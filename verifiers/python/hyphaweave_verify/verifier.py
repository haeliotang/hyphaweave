# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Per-record verification pipeline and the verification context.

This is the orchestration layer that applies the deterministic check order of
CONTRACT §14.6/spec §14.3 per record:

1. parse + canonical form, 2. envelope structure, 3. signature presence/format,
4. key availability, 5. Ed25519 verification, 6. kind body schema, 7. kind
semantic rules, 8. actor/authorisation, 9. labels, 10. reference resolution.

Cross-record dependencies (key declarations, grants, references) are resolved
against a :class:`Context` that is iterated to a fixed point: every pass rebuilds
key/grant state from the records that verified in the previous pass, then
re-attempts every record. The iteration is bounded and deterministic, so the
same container bytes always produce the same report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from . import ed25519, encoding, envelope as envelope_module, erase, kinds, labels, refs
from . import grammar
from .errors import UsageError, WeaveError
from .grants import (
    GrantRecord,
    GrantRevocationRecord,
    GrantState,
    check_agent_authorization,
    check_grant_semantics,
)
from .keys import (
    KeyDeclaration,
    KeyRevocation,
    KeyRotation,
    KeyState,
    RevocationContext,
    check_declared_semantics,
    check_revoked_semantics,
    check_rotated_semantics,
    decode_public_key_material,
)
from .report import record_verdict
from .times import is_valid_timestamp  # noqa: F401  (imported for type checkers)

#: Maximum size of one record file (spec §13).
MAX_RECORD_BYTES = 1_048_576

#: Kinds whose signer requirements are kind-specific: a missing required signer is
#: their own registry code, not the generic ``E_SIG_REQUIRED``.
SPECIFIC_SIGNER_KINDS = frozenset(
    {kinds.KIND_DECLARED, kinds.KIND_ROTATED, kinds.KIND_REVOKED}
)


@dataclass
class LoadedRecord:
    """A parsed record file ready for verification."""

    raw: bytes
    value: dict[str, Any] | None
    digest: str | None
    source: str  # "keyset" or "container"
    container_path: str | None = None


def load_record_bytes(raw: bytes, *, source: str, size_code: str = "E_JSON_SIZE") -> LoadedRecord:
    """Parse a canonical record file and compute its record digest."""
    from .canonical import parse_file_bytes

    value = parse_file_bytes(
        raw, max_bytes=MAX_RECORD_BYTES, require_object=True, size_code=size_code
    )
    digest = encoding.record_digest(value)
    return LoadedRecord(raw=raw, value=value, digest=digest, source=source)


@dataclass
class RecordView:
    """Mutable per-record verification state used by the pipeline and reports."""

    loaded: LoadedRecord
    digest: str | None = None
    envelope: envelope_module.Envelope | None = None
    placeholder: erase.Placeholder | None = None
    verdict: str | None = None
    errors: list[str] = field(default_factory=list)
    notices: list[str] = field(default_factory=list)
    refs: list[dict[str, Any]] = field(default_factory=list)
    sigs: list[dict[str, Any]] = field(default_factory=list)
    attestation: dict[str, Any] | None = None
    verified_keys: frozenset[str] = frozenset()
    key_declaration: KeyDeclaration | None = None
    key_rotation: KeyRotation | None = None
    key_revocation: KeyRevocation | None = None
    grant_record: GrantRecord | None = None
    grant_revocation: GrantRevocationRecord | None = None

    # -- derived facts ----------------------------------------------------

    @property
    def subject_key(self) -> tuple[str, str, str] | None:
        if self.placeholder is not None:
            origin = self.placeholder.origin
            return (origin.project, origin.instance, self.placeholder.record_id)
        if self.envelope is not None:
            origin = self.envelope.origin
            return (origin.project, origin.instance, self.envelope.record_id)
        return None

    @property
    def kind(self) -> str | None:
        if self.placeholder is not None:
            return kinds.KIND_ERASED
        if self.envelope is not None:
            return self.envelope.kind
        return None

    def state_signature(self) -> tuple[Any, ...]:
        """Deterministic snapshot used to detect fixed-point convergence."""
        return (
            self.verdict,
            tuple(self.errors),
            tuple(sorted(set(self.notices))),
            tuple(
                (entry.get("index"), entry.get("rel"), entry.get("state")) for entry in self.refs
            ),
            tuple((entry.get("key"), entry.get("state")) for entry in self.sigs),
            None if self.attestation is None else tuple(sorted(self.attestation.items())),
        )


# ---------------------------------------------------------------------------
# Verification context
# ---------------------------------------------------------------------------


class Context:
    """The record set against which a target is verified.

    Implements :class:`refs.ResolutionContext` and the state accessors used by
    the grant and label checks. ``rebuild()`` recomputes key/grant state from the
    records that currently have verdict ``valid``.
    """

    def __init__(self, *, verified_timestamps: tuple[Any, ...] = ()) -> None:
        self.views: list[RecordView] = []
        self.key_state = KeyState()
        self.grant_state = GrantState()
        self.verified_timestamps = tuple(verified_timestamps)
        self.pending_touched = False
        self._index: dict[tuple[str, str, str], list[RecordView]] = {}

    # -- registration -----------------------------------------------------

    def register(self, view: RecordView) -> None:
        self.views.append(view)
        key = view.subject_key
        if key is not None:
            self._index.setdefault(key, []).append(view)

    def rebuild(self) -> None:
        """Recompute lifecycle state from records whose current verdict is valid."""
        self.key_state = KeyState()
        self.grant_state = GrantState()
        for view in self.views:
            if view.verdict == "valid":
                self._apply_state(view)

    def _apply_state(self, view: RecordView) -> None:
        if view.key_declaration is not None:
            self.key_state.add_declaration(view.key_declaration)
        if view.key_rotation is not None:
            self.key_state.add_rotation(view.key_rotation)
        if view.key_revocation is not None:
            self.key_state.add_revocation(view.key_revocation)
        if view.grant_record is not None:
            self.grant_state.add(view.grant_record)
        if view.grant_revocation is not None:
            self.grant_state.add_revocation(view.grant_revocation)

    # -- resolution -------------------------------------------------------

    def find_records(self, origin: refs.Origin, record_id: str) -> tuple[refs.TargetView, ...]:
        candidates = self._index.get((origin.project, origin.instance, record_id), ())
        targets: list[refs.TargetView] = []
        for view in candidates:
            if view.verdict is None:
                self.pending_touched = True
            targets.append(_target_view(view))
        return tuple(targets)

    def resolve(self, reference: refs.Reference) -> refs.Resolution:
        return refs.resolve_reference(reference, self)


def _target_view(view: RecordView) -> refs.TargetView:
    if view.placeholder is not None:
        return refs.TargetView(
            origin=view.placeholder.origin,
            id=view.placeholder.record_id,
            kind=kinds.KIND_ERASED,
            verdict=view.verdict or "unverifiable",
            computed_digest=view.digest,
            payload_digest=view.placeholder.digest,
            is_placeholder=True,
            record=view,
        )
    assert view.envelope is not None
    return refs.TargetView(
        origin=view.envelope.origin,
        id=view.envelope.record_id,
        kind=view.envelope.kind,
        verdict=view.verdict or "unverifiable",
        computed_digest=view.digest,
        payload_digest=None,
        is_placeholder=False,
        record=view,
    )


# ---------------------------------------------------------------------------
# Signature verification (steps 3-5)
# ---------------------------------------------------------------------------


def _verify_signatures(view: RecordView, envelope: envelope_module.Envelope, context: Context) -> None:
    digest = view.digest or ""
    message = encoding.record_sig_message(digest)
    states: list[dict[str, Any]] = view.sigs
    verified: set[str] = set()
    try:
        for signature in envelope.sigs:
            material, from_context, is_declared = _resolve_signing_key(
                signature.key, envelope, context
            )
            if material is None:
                states.append({"key": signature.key, "state": "unverified"})
                view.notices.append("N_KEY_UNDECLARED")
                raise WeaveError(
                    "E_KEY_UNKNOWN", "signing key is not declared in the context"
                )
            if from_context:
                if "N_KEY_TOFU" not in view.notices:
                    view.notices.append("N_KEY_TOFU")
                context.key_state.check_signature_effects(
                    signature.key,
                    envelope.recorded_at,
                    verified_timestamps=context.verified_timestamps,  # type: ignore[arg-type]
                    skip_revocations=(envelope.kind == kinds.KIND_REVOKED),
                )
            try:
                ed25519.verify_signature(material, message, signature.raw)
            except WeaveError:
                states.append({"key": signature.key, "state": "invalid"})
                raise
            states.append({"key": signature.key, "state": "valid"})
            verified.add(signature.key)
    finally:
        for signature in envelope.sigs[len(states) :]:
            states.append({"key": signature.key, "state": "unverified"})
        view.verified_keys = frozenset(verified)


def _resolve_signing_key(
    key: str,
    envelope: envelope_module.Envelope,
    context: Context,
) -> tuple[bytes | None, bool, bool]:
    """Resolve signer key material: ``(material, from_context, from_declaration)``.

    Key-lifecycle records supply their own key material in the body so that the
    first declaration in a fresh context is verifiable without any prior trust
    (spec §9.5): a declaration carries the declared key, a rotation carries the
    old/new public keys.
    """
    body = envelope.body
    if envelope.kind == kinds.KIND_DECLARED and body.get("key") == key:
        return (decode_public_key_material(body.get("public_key")), False, True)
    if envelope.kind == kinds.KIND_ROTATED:
        if body.get("new_key") == key and "new_public_key" in body:
            return (decode_public_key_material(body["new_public_key"]), False, False)
        if body.get("old_key") == key and body.get("old_public_key") is not None:
            return (decode_public_key_material(body["old_public_key"]), False, False)
    material = context.key_state.public_key(key)
    if material is not None:
        return (material, True, context.key_state.is_declared(key))
    return (None, False, False)


# ---------------------------------------------------------------------------
# Kind semantics (step 7)
# ---------------------------------------------------------------------------


def _check_kind_semantics(
    view: RecordView,
    envelope: envelope_module.Envelope,
    context: Context,
) -> None:
    digest = view.digest or ""
    kind = envelope.kind
    if kind == kinds.KIND_DECLARED:
        view.key_declaration = check_declared_semantics(
            body=envelope.body,
            actor_key=envelope.actor_key,
            actor_type=envelope.actor_type,
            verified_signature_keys=view.verified_keys,
            recorded_at=envelope.recorded_at,
            record_digest=digest,
        )
    elif kind == kinds.KIND_ROTATED:
        view.key_rotation = check_rotated_semantics(
            body=envelope.body,
            actor_key=envelope.actor_key,
            verified_signature_keys=view.verified_keys,
            recorded_at=envelope.recorded_at,
            record_digest=digest,
        )
    elif kind == kinds.KIND_REVOKED:
        revocation_context = RevocationContext(
            frozenset(signature.key for signature in envelope.sigs),
            context.key_state,
        )
        view.key_revocation = check_revoked_semantics(
            body=envelope.body,
            recorded_at=envelope.recorded_at,
            record_digest=digest,
            verification_context=revocation_context,
        )
    elif kind == kinds.KIND_GRANT:
        state = check_grant_semantics(envelope, digest, context)
        if isinstance(state, GrantRecord):
            view.grant_record = state
        else:
            view.grant_revocation = state
    elif kind == kinds.KIND_CONSENT_GRANTED:
        if envelope.actor_type not in ("human", "organization"):
            raise WeaveError(
                "E_KIND_BODY_SCHEMA",
                "consent.granted actor.type must be human or organization",
            )
        valid_until = envelope.body["valid_until"]
        if valid_until is not None and is_valid_timestamp(valid_until):
            from .times import timestamp_sort_key

            if timestamp_sort_key(envelope.body["valid_from"]) > timestamp_sort_key(valid_until):
                raise WeaveError(
                    "E_CONSENT_VALIDITY", "consent valid_from is after valid_until"
                )
    elif kind == kinds.KIND_CONSENT_REVOKED:
        if envelope.actor_type not in ("human", "organization"):
            raise WeaveError(
                "E_KIND_BODY_SCHEMA",
                "consent.revoked actor.type must be human or organization",
            )
        reference = refs.validate_reference(envelope.body["revokes"])
        resolution = context.resolve(reference)
        if resolution.state != refs.FOUND:
            raise WeaveError(
                "E_CONSENT_REVOKE_REF", "revokes does not resolve to a consent grant"
            )
        if refs.kind_claim_mismatch(reference, resolution):
            raise WeaveError(
                "E_REF_KIND_MISMATCH", "revokes kind claim contradicts the target kind"
            )
        target = resolution.target
        assert target is not None
        if target.kind != kinds.KIND_CONSENT_GRANTED:
            raise WeaveError(
                "E_CONSENT_REVOKE_REF", "revokes does not resolve to a consent grant"
            )
    elif kind == kinds.KIND_ERASURE:
        if envelope.actor_type != "human":
            raise WeaveError("E_ERASE_ACTOR", "erasure actor must be human")


# ---------------------------------------------------------------------------
# Actor compatibility and authorisation (step 8)
# ---------------------------------------------------------------------------


def _check_actor_and_authorization(
    view: RecordView,
    envelope: envelope_module.Envelope,
    context: Context,
) -> None:
    if envelope.kind in kinds.KEY_LIFECYCLE_KINDS:
        # The kind pages for the three key-lifecycle kinds carry their own
        # signer-class rules (including human/organization co-signatures and a
        # human-signed compromise revocation), so the generic rules do not apply.
        return
    for signature in envelope.sigs:
        key_class = context.key_state.key_type(signature.key)
        if key_class is None:
            continue  # undeclared or rotation-supplied key: TOFU, no class check
        if signature.key == envelope.actor_key:
            if key_class != envelope.actor_type:
                raise WeaveError(
                    "E_ACTOR_KEY_TYPE_MISMATCH",
                    "actor.key class is incompatible with actor.type",
                )
        else:
            if key_class in ("human", "organization") and envelope.actor_type not in (
                "human",
                "organization",
            ):
                raise WeaveError(
                    "E_ACTOR_HUMAN_KEY",
                    "human/organization key co-signed a non-human record",
                )
            if key_class != envelope.actor_type:
                raise WeaveError(
                    "E_ACTOR_KEY_TYPE_MISMATCH",
                    "a signing key's class is incompatible with actor.type",
                )
    if envelope.actor_type == "agent" and envelope.kind != kinds.KIND_GRANT:
        # Delegated weave.grant records are governed by the delegation rules in
        # the kind semantics; every other agent record needs grant coverage
        # (spec §5.4, Q10).
        check_agent_authorization(envelope, context)


# ---------------------------------------------------------------------------
# Labels (step 9) and references (step 10)
# ---------------------------------------------------------------------------


def _check_labels(
    view: RecordView, envelope: envelope_module.Envelope, context: Context
) -> None:
    view.notices.extend(labels.check_label_propagation(envelope, context))
    view.notices.extend(labels.check_consent_reference(envelope, context))


def _check_references(
    view: RecordView, envelope: envelope_module.Envelope, context: Context
) -> None:
    states: list[dict[str, Any]] = []
    notice_set: set[str] = set()
    mismatched = False
    for index, entry in enumerate(envelope.refs):
        resolution = context.resolve(entry.ref)
        states.append({"index": index, "rel": entry.rel, "state": resolution.state})
        if resolution.notice is not None:
            notice_set.add(resolution.notice)
        if refs.kind_claim_mismatch(entry.ref, resolution):
            mismatched = True
    view.refs = states
    view.notices.extend(sorted(notice_set))
    if mismatched:
        raise WeaveError("E_REF_KIND_MISMATCH", "a reference kind claim contradicts its target")


# ---------------------------------------------------------------------------
# One record
# ---------------------------------------------------------------------------


def attempt_record(view: RecordView, context: Context) -> None:
    """Re-run the full record pipeline, replacing the view's current result."""
    view.digest = view.loaded.digest
    view.envelope = None
    view.placeholder = None
    view.verdict = None
    view.errors = []
    view.notices = []
    view.refs = []
    view.sigs = []
    view.attestation = None
    view.verified_keys = frozenset()
    view.key_declaration = None
    view.key_rotation = None
    view.key_revocation = None
    view.grant_record = None
    view.grant_revocation = None
    try:
        value = view.loaded.value
        if erase.looks_like_placeholder(value):
            placeholder = erase.validate_placeholder(value)
            view.placeholder = placeholder
            resolution = context.resolve(placeholder.attestation)
            view.attestation = {
                "digest": placeholder.attestation.digest,
                "state": resolution.state,
            }
            if resolution.notice is not None:
                view.notices.append(resolution.notice)
            view.verdict = "erased"
            return
        envelope = envelope_module.validate_envelope(value)
        view.envelope = envelope
        _check_signature_presence(envelope)
        _verify_signatures(view, envelope, context)
        kinds.validate_body_schema(envelope.kind, envelope.body)
        _check_kind_semantics(view, envelope, context)
        _check_actor_and_authorization(view, envelope, context)
        _check_labels(view, envelope, context)
        _check_references(view, envelope, context)
        if not envelope.kind_known:
            view.notices.append("N_KIND_UNKNOWN_OPAQUE")
        view.verdict = "valid"
    except WeaveError as error:
        view.errors.append(error.code)
        view.verdict = record_verdict(view.errors)


def _check_signature_presence(envelope: envelope_module.Envelope) -> None:
    required = envelope_module.signing_required(envelope.kind, envelope.stage)
    if not required:
        return
    if not envelope.sigs:
        raise WeaveError("E_SIG_REQUIRED", "record requires a per-record signature")
    if envelope.kind in SPECIFIC_SIGNER_KINDS:
        return  # the kind's own semantic rules check its required signers
    if not envelope_module.has_signature_by(envelope.sigs, envelope.actor_key):
        raise WeaveError(
            "E_SIG_REQUIRED", "record requires a signature by actor.key"
        )


# ---------------------------------------------------------------------------
# Fixed-point verification of a record set
# ---------------------------------------------------------------------------


def verify_record_set(
    loaded: Iterable[LoadedRecord],
    *,
    verified_timestamps: tuple[Any, ...] = (),
    context_views: Iterable[RecordView] = (),
) -> list[RecordView]:
    """Verify every record of a set (a container or an external keyset).

    The set is iterated to a deterministic fixed point: a record's verdict may
    depend on another record's verdict (keys, grants, references), so each pass
    rebuilds key/grant state from the previous pass's valid records and
    re-attempts every record until the results stop changing or the pass budget
    is exhausted (then the last results are final).
    """
    views = [RecordView(loaded=record) for record in loaded]
    fixed_context_views = list(context_views)
    max_passes = 2 * len(views) + 3
    previous: tuple[Any, ...] | None = None
    for _ in range(max_passes):
        context = Context(verified_timestamps=verified_timestamps)
        for view in fixed_context_views:
            context.register(view)
        for view in views:
            context.register(view)
        context.rebuild()
        for view in views:
            attempt_record(view, context)
        snapshot = tuple(view.state_signature() for view in views)
        if snapshot == previous:
            break
        previous = snapshot
    return views


def verify_single_record(
    target: LoadedRecord,
    context_records: Iterable[LoadedRecord] = (),
    *,
    verified_timestamps: tuple[Any, ...] = (),
) -> tuple[RecordView, list[RecordView]]:
    """Verify one record target against an external context (the ``--keys`` keyset)."""
    resolved_context = verify_record_set(
        context_records, verified_timestamps=verified_timestamps
    )
    context = Context(verified_timestamps=verified_timestamps)
    for view in resolved_context:
        context.register(view)
    context.rebuild()
    target_view = RecordView(loaded=target)
    attempt_record(target_view, context)
    return target_view, resolved_context


# ---------------------------------------------------------------------------
# Keyset loading (``--keys <dir>``)
# ---------------------------------------------------------------------------


def load_keyset_directory(path: Path) -> list[LoadedRecord]:
    """Load top-level ``*.json`` files of a keyset directory.

    Per the CLI contract, files are parsed and structurally validated as
    records; anything else is a usage error (exit 2). A record that parses and is
    structurally valid but fails its semantic or cryptographic checks does not
    establish trust; that is not a usage error.
    """
    if not path.exists() or not path.is_dir():
        raise UsageError("keyset path is not a directory")
    loaded: list[LoadedRecord] = []
    for entry in sorted(path.iterdir(), key=lambda item: item.name):
        if not entry.is_file() or entry.suffix != ".json":
            continue
        try:
            raw = entry.read_bytes()
        except OSError as error:
            raise UsageError("could not read a keyset file") from error
        try:
            record = load_record_bytes(raw, source="keyset")
            if erase.looks_like_placeholder(record.value):
                raise WeaveError("E_JSON_INVALID", "keyset file is not a normal record")
            envelope_module.validate_envelope(record.value)
        except WeaveError as error:
            raise UsageError("keyset file is not a valid record: %s" % error.code) from error
        loaded.append(record)
    return loaded
