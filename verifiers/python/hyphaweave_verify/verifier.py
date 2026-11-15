# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Per-record verification pipeline and the verification context.

The per-record check order is fixed (decision #34): parse/canonical form →
envelope structure → signature presence/format → key availability → Ed25519
verification → kind body schema → kind semantics → actor/authorisation → labels
→ references. The first failing check decides the record's single primary error.

Unknown-algorithm signature entries are validated structurally and then ignored
(Q13); if a record requires per-record signing but no verifiable required
signature of a known algorithm exists, the record is ``unverifiable`` with
``E_SIG_UNVERIFIABLE`` instead of invalid.

Cross-record dependencies (key declarations, grants, references) are resolved
against a :class:`Context` iterated to a deterministic fixed point.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from . import ed25519, encoding, envelope as envelope_module, erase, grammar, kinds, labels, refs
from . import keys as keys_module
from . import operator_input
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
    VerifiedTimestamp,
    check_declared_semantics,
    check_revoked_semantics,
    check_rotated_material,
    check_rotated_semantics,
    decode_public_key_material,
)
from .report import record_verdict
from .times import timestamp_sort_key  # U3/T9 deterministic revocation order

MAX_RECORD_BYTES = 1_048_576

#: Kinds whose signer requirements are kind-specific: a missing required signer is
#: their own registry code, not the generic ``E_SIG_REQUIRED``.
SPECIFIC_SIGNER_KINDS = frozenset(kinds.MUST_SIGN_KINDS)


@dataclass
class LoadedRecord:
    """A parsed record file ready for verification."""

    raw: bytes
    value: dict[str, Any] | None
    digest: str | None
    source: str  # "keyset" or "container"
    #: U4: cached §14.1 structural parse for governing-class determination. It is
    #: computed from the loaded value only, so class governance is stable from the
    #: first verification pass and never depends on transient verdicts.
    structural_checked: bool = False
    structural_envelope: Any = None
    structural_key_type: str | None = None
    container_path: str | None = None
    #: S2/F60: the record file failed parsing with a size violation (nesting
    #: above MAX_JSON_DEPTH), reported by the records-listing phase.
    size_violation: bool = False


def load_record_bytes(raw: bytes, *, source: str, size_code: str = "E_JSON_SIZE") -> LoadedRecord:
    """Parse a canonical record file and compute its record digest."""
    from .canonical import parse_file_bytes

    value = parse_file_bytes(
        raw, max_bytes=MAX_RECORD_BYTES, require_object=True, size_code=size_code
    )
    digest = encoding.record_digest(value)
    return LoadedRecord(raw=raw, value=value, digest=digest, source=source)


@dataclass(frozen=True)
class ConsentRevocation:
    """A valid ``weave.consent.revoked`` record, as used by consent checks."""

    digest: str
    target_digest: str
    effective_at: str


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
    signature_algs_by_key: dict[str, frozenset[str]] = field(default_factory=dict)
    key_declaration: KeyDeclaration | None = None
    key_rotation: KeyRotation | None = None
    key_revocation: KeyRevocation | None = None
    grant_record: GrantRecord | None = None
    grant_revocation: GrantRevocationRecord | None = None
    consent_revocation: ConsentRevocation | None = None
    #: S2/F38/F61-1: the key-lifecycle facts of a ``weave.key.declared`` or
    #: ``weave.key.rotated`` record whose checks pass when the §9.4 effects on
    #: the signature of the record's *subject key* (``body.key`` of a
    #: declaration, ``body.new_key`` of a rotation) are left out. §9.4 judges
    #: every signature of the record for its reported verdict, but whether the
    #: record supplies key material, governs a window or enters the trusted set
    #: (§5.3) is decided without that one effect, so a declaration of a
    #: compromised key keeps the key's lifecycle attached to every signature it
    #: makes. A cosignature or a rotation's old-key signature must pass §9.4
    #: for the record to be admitted at all (S2-FIX1 T1, Q2).
    admitted_declaration: KeyDeclaration | None = None
    admitted_rotation: KeyRotation | None = None

    @property
    def subject_key(self) -> tuple[str, str, str] | None:
        if self.placeholder is not None:
            origin = self.placeholder.origin
            return (origin.project, origin.instance, self.placeholder.record_id)
        if self.envelope is not None:
            origin = self.envelope.origin
            return (origin.project, origin.instance, self.envelope.record_id)
        identity = self.raw_identity
        if identity is not None:
            return (identity[0].project, identity[0].instance, identity[1])
        return None

    @property
    def raw_identity(self) -> tuple[refs.Origin, str] | None:
        """S2/F44 (§6.3): the identity of a record that failed its structure.

        A record that parsed but failed a later structure check is still
        *present* for reference resolution when its own ``origin`` and ``id``
        are well formed (§4.1 grammar): a reference to it is ``unverifiable``
        ("present but … itself not valid"), not ``missing``. A record whose
        ``origin`` or ``id`` is itself malformed has no identity and is never a
        resolution candidate.
        """
        value = self.loaded.value
        if self.envelope is not None or self.placeholder is not None:
            return None
        if not isinstance(value, dict) or "origin" not in value or "id" not in value:
            return None
        try:
            origin = refs.validate_origin(value["origin"])
        except WeaveError:
            return None
        record_id = value["id"]
        if not grammar.is_valid_id(record_id):
            return None
        return origin, record_id

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
            self.admitted_declaration is not None,
            self.admitted_rotation is not None,
        )


# ---------------------------------------------------------------------------
# Verification context
# ---------------------------------------------------------------------------


class Context:
    """The record set against which a target is verified."""

    def __init__(
        self,
        *,
        verified_timestamps: tuple[VerifiedTimestamp, ...] = (),
        timestamp_evidence_present: bool = False,
    ) -> None:
        self.views: list[RecordView] = []
        self.key_state = KeyState()
        self.grant_state = GrantState()
        self.consent_revocations: dict[str, list[ConsentRevocation]] = {}
        self.verified_timestamps = tuple(verified_timestamps)
        self.timestamp_evidence_present = timestamp_evidence_present
        self._trusted_human_org: frozenset[str] = frozenset()
        self.pending_touched = False
        self._index: dict[tuple[str, str, str], list[RecordView]] = {}
        self._declared_material: dict[str, tuple[bytes, str]] = {}
        #: Where a key's governing declaration material came from: ``"keyset"``
        #: or ``"context"`` (S8.10: N_KEY_TOFU covers context declarations only).
        self._material_source: dict[str, str] = {}
        #: U4: class governance is computed from the §14.1 structural group only
        #: (canonical form + envelope structure + sigs presence/format +
        #: registered-kind body schema), independently of semantic validity and
        #: of the trust closure. ``governing_class`` reads the derived map below.
        self._structural_declarations: dict[
            str, list[tuple[tuple[tuple[int, ...], str], str, str, str]]
        ] = {}
        self._governing_classes: dict[str, str] = {}

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
        self.consent_revocations = {}
        self._declared_material = {}
        trusted: set[str] = set()
        self._material_source = {}
        self._rebuild_governing_classes()
        for view in self.views:
            self._register_declared_material(view)
            source = "keyset" if view.loaded.source == "keyset" else "context"
            if view.verdict != "valid":
                # S2/F38: a declaration or rotation that fails only through the
                # §9.4 effects on its own signatures still supplies its facts.
                if view.admitted_declaration is not None:
                    self.key_state.add_declaration(view.admitted_declaration)
                    declaration = view.admitted_declaration
                    _record_source(self._material_source, declaration.key_id, source)
                    if declaration.key_type in ("human", "organization"):
                        trusted.add(declaration.key_id)
                if view.admitted_rotation is not None:
                    self.key_state.add_rotation(view.admitted_rotation)
                    rotation = view.admitted_rotation
                    _record_source(self._material_source, rotation.new_key, source)
                    if rotation.old_public_key is not None:
                        _record_source(self._material_source, rotation.old_key, source)
                continue
            self._apply_state(view)
            declaration = view.key_declaration
            if declaration is not None:
                _record_source(self._material_source, declaration.key_id, source)
                if declaration.key_type in ("human", "organization"):
                    trusted.add(declaration.key_id)
            rotation = view.key_rotation
            if rotation is not None:
                _record_source(self._material_source, rotation.new_key, source)
                if rotation.old_public_key is not None:
                    _record_source(self._material_source, rotation.old_key, source)
        self._trusted_human_org = frozenset(trusted)

    def _register_declared_material(self, view: RecordView) -> None:
        """Owner lookup material: any structurally usable declaration, valid or not."""
        envelope = view.envelope
        if envelope is None or envelope.kind != kinds.KIND_DECLARED:
            return
        body = envelope.body
        key_id = body.get("key")
        key_type = body.get("key_type")
        if not isinstance(key_id, str) or key_id in self._declared_material:
            return
        if key_type not in ("human", "organization", "agent", "program", "device"):
            return
        try:
            public_key = decode_public_key_material(body.get("public_key"))
        except WeaveError:
            return
        if encoding.key_id_from_public_key(public_key) != key_id:
            return
        self._declared_material[key_id] = (public_key, key_type)

    def declaration_material(self, key_id: str) -> tuple[bytes, str] | None:
        return self._declared_material.get(key_id)

    def is_declared_key(self, key_id: str) -> bool:
        return self.key_state.is_declared(key_id)

    def trusted_human_org(self) -> frozenset[str]:
        """Human/organization keys trusted via the keyset and its closure."""
        return self._trusted_human_org

    def material_source(self, key_id: str) -> str | None:
        """``"keyset"``/``"context"`` for a key's governing material (S8.10)."""
        return self._material_source.get(key_id)

    def governing_class(self, key_id: str, exclude_digest: str) -> str | None:
        """The governing class of a key id (U4/§5.3), verdict-independent.

        The governing class is derived from the §14.1 structural group only:
        a keyset declaration wins when the local keyset has one; otherwise the
        declaration with the smallest ``(recorded_at, record digest)`` among all
        structurally valid declarations in the verification context governs.
        Trust closure and semantic validity are computed afterwards and cannot
        change it. ``exclude_digest`` is kept for interface stability; the set is
        already independent of the record being judged, and a declaration cannot
        conflict with itself.
        """
        del exclude_digest  # U4: the structural set includes the record itself.
        return self._governing_classes.get(key_id)

    def _rebuild_governing_classes(self) -> None:
        """Compute the U4 governing classes from the §14.1 structural group."""
        structural: dict[str, list[tuple[tuple[tuple[int, ...], str], str, str, str]]] = {}
        for view in self.views:
            declaration = _structural_declaration_class(view)
            if declaration is None:
                continue
            key_id, key_type, order, digest = declaration
            source = "keyset" if view.loaded.source == "keyset" else "context"
            structural.setdefault(key_id, []).append((order, key_type, digest, source))
        self._structural_declarations = structural
        governing: dict[str, str] = {}
        for key_id, declarations in structural.items():
            keyset_declarations = [
                declaration for declaration in declarations if declaration[3] == "keyset"
            ]
            candidates = keyset_declarations or declarations
            # Keyset conflicts are a usage error (T4), so every keyset entry for
            # one key id carries the same class; the earliest order breaks ties
            # deterministically.
            candidates.sort(key=lambda declaration: (declaration[0], declaration[2]))
            governing[key_id] = candidates[0][1]
        self._governing_classes = governing

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
        if view.consent_revocation is not None:
            self.consent_revocations.setdefault(
                view.consent_revocation.target_digest, []
            ).append(view.consent_revocation)

    # -- consent ----------------------------------------------------------

    def consent_revoked_as_of(self, consent_digest: str, recorded_at: str) -> ConsentRevocation | None:
        from .times import timestamp_sort_key

        for revocation in self.consent_revocations.get(consent_digest, ()):
            if timestamp_sort_key(revocation.effective_at) <= timestamp_sort_key(recorded_at):
                return revocation
        return None

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


def _structural_declaration_class(
    view: RecordView,
) -> tuple[str, str, tuple[tuple[int, ...], str], str] | None:
    """Return ``(key_id, key_type, order, digest)`` for the §14.1 structural group.

    U4: a declaration participates in governing-class determination iff it passes
    the §14.1 structural group — canonical form (implicit: it has a parsed
    value), envelope structure, signature presence/format and the registered-kind
    body schema. Signature *validity*, trust and kind semantics are deliberately
    not part of this check, and neither is the current verdict: the parse is
    cached on the loaded record so class governance is identical in every pass.
    """
    loaded = view.loaded
    if not loaded.structural_checked:
        loaded.structural_checked = True
        value = loaded.value
        if isinstance(value, dict) and not erase.looks_like_placeholder(value):
            try:
                envelope = envelope_module.validate_envelope(value)
            except WeaveError:
                envelope = None
            if envelope is not None and envelope.kind == kinds.KIND_DECLARED:
                structurally_ok = not (
                    envelope_module.signing_required(envelope.kind, envelope.stage)
                    and not envelope.sigs
                )
                if structurally_ok:
                    try:
                        kinds.validate_body_schema(envelope.kind, envelope.body)
                    except WeaveError:
                        structurally_ok = False
                if structurally_ok:
                    # V5/M2: public_key encoding is a *structural* property
                    # (§14.1 structural group): a missing/invalid base64url or
                    # non-32-byte public key keeps the declaration out of class
                    # governance. Key-id correspondence and point validity stay
                    # semantic checks with their own codes (E_SIG_INVALID etc.).
                    body = envelope.body
                    try:
                        keys_module.decode_public_key_material(body.get("public_key"))
                    except WeaveError:
                        structurally_ok = False
                if structurally_ok:
                    body = envelope.body
                    key_id = body.get("key")
                    key_type = body.get("key_type")
                    if isinstance(key_id, str) and isinstance(key_type, str):
                        loaded.structural_envelope = envelope
                        loaded.structural_key_type = key_type
    envelope = loaded.structural_envelope
    key_type = loaded.structural_key_type
    if envelope is None or key_type is None:
        return None
    body = envelope.body
    key_id = body.get("key")
    if not isinstance(key_id, str):
        return None
    digest = view.digest or ""
    order = (timestamp_sort_key(envelope.recorded_at), digest)
    return key_id, key_type, order, digest


def _record_source(sources: dict[str, str], key_id: str, source: str) -> None:
    """Record a key's material source; keyset declarations are authoritative."""
    current = sources.get(key_id)
    if current is None or (current == "context" and source == "keyset"):
        sources[key_id] = source


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
    if view.envelope is None:
        identity = view.raw_identity
        assert identity is not None
        raw_kind = view.loaded.value.get("kind") if isinstance(view.loaded.value, dict) else None
        return refs.TargetView(
            origin=identity[0],
            id=identity[1],
            kind=raw_kind if kinds.is_kind_syntax(raw_kind) else None,
            verdict=view.verdict or "unverifiable",
            computed_digest=view.digest,
            payload_digest=None,
            is_placeholder=False,
            record=view,
        )
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
# Signature presence (step 3) and verification (steps 4-5)
# ---------------------------------------------------------------------------


def _signature_entries_by_key(
    envelope: envelope_module.Envelope,
) -> dict[str, frozenset[str]]:
    entries: dict[str, set[str]] = {}
    for signature in envelope.sigs:
        entries.setdefault(signature.key, set()).add(signature.alg)
    return {key: frozenset(algs) for key, algs in entries.items()}


def _check_signature_presence(
    view: RecordView, envelope: envelope_module.Envelope
) -> None:
    """Step 3: missing/empty sigs on a record that requires per-record signing."""
    if not envelope_module.signing_required(envelope.kind, envelope.stage):
        return
    if not envelope.sigs:
        raise WeaveError("E_SIG_REQUIRED", "record requires a per-record signature")


def _declared_anywhere(
    key: str, envelope: envelope_module.Envelope, context: "Context"
) -> bool:
    """§4.4 step 5: whether a ``sigs`` key is declared in the verification context.

    A key is declared by a ``weave.key.declared`` record anywhere in the context
    (including the record under verification) or by the explicit key material
    of a ``weave.key.rotated`` record (§9.2 rule 5: those members are explicit
    declarations of the two keys).
    """
    if context.is_declared_key(key) or context.declaration_material(key) is not None:
        return True
    body = envelope.body if isinstance(envelope.body, dict) else {}
    if envelope.kind == kinds.KIND_DECLARED and body.get("key") == key:
        return True
    if envelope.kind == kinds.KIND_ROTATED:
        if body.get("new_key") == key and "new_public_key" in body:
            return True
        if body.get("old_key") == key and body.get("old_public_key") is not None:
            return True
    return False


def signer_obligation_error(
    view: RecordView,
    envelope: envelope_module.Envelope,
    context: "Context",
    code: str,
    required: Iterable[str] | None = None,
) -> WeaveError:
    """§4.4 steps 4-5 when the required signer has no verified signature (S2/F46).

    Step 4: some known-algorithm signature by a declared key verified (every
    ``ed25519`` entry has been verified by step (5)), so the record carries
    the dedicated signer *code*. Step 5: no such signature exists at all; the
    record is ``unverifiable``: ``E_KEY_UNKNOWN`` when no required signer key
    (``required``, default ``actor.key``) is declared anywhere in the context,
    otherwise ``E_SIG_UNVERIFIABLE``. The undeclared key of an unknown-algorithm
    entry that is not a required signer does not decide the code (pinned by
    ``sig/unknown-alg``).
    """
    if view.verified_keys:
        return WeaveError(code, "no valid signature by the required signer")
    required_keys = [envelope.actor_key] if required is None else list(required)
    if not any(_declared_anywhere(key, envelope, context) for key in required_keys):
        return WeaveError("E_KEY_UNKNOWN", "the required signing key is not declared")
    return WeaveError(
        "E_SIG_UNVERIFIABLE",
        "no known-algorithm signature by a declared key exists",
    )


def _unknown_algorithm_error(
    view: RecordView, context: "Context", key: str, fallback_code: str
) -> WeaveError:
    """Q13 / §4.4 steps 4-5 for the required signer ``key``."""
    assert view.envelope is not None
    return signer_obligation_error(view, view.envelope, context, fallback_code, (key,))


def _check_required_signers(
    view: RecordView, envelope: envelope_module.Envelope, context: "Context"
) -> None:
    """Required-signer existence after signature verification (decision #34 A)."""
    if not envelope_module.signing_required(envelope.kind, envelope.stage):
        return
    if envelope.kind in SPECIFIC_SIGNER_KINDS:
        return  # kind semantics decide their dedicated signer code
    actor_key = envelope.actor_key
    if actor_key in view.verified_keys:
        return
    raise signer_obligation_error(view, envelope, context, "E_SIG_REQUIRED")


def _verify_signatures(
    view: RecordView,
    envelope: envelope_module.Envelope,
    context: Context,
    *,
    own_effects: bool = True,
) -> None:
    """Steps 4-5: key availability, lifecycle effects and Ed25519 verification."""
    digest = view.digest or ""
    message = encoding.record_sig_message(digest)
    states: list[dict[str, Any]] = view.sigs
    verified: set[str] = set()
    entries_by_key = _signature_entries_by_key(envelope)
    view.signature_algs_by_key = entries_by_key
    # T9: for a weave.key.revoked record the deterministic evaluation order is
    # (recorded_at, record digest); signatures by the key being revoked are the
    # self-revocation exemption, every other signer is judged against the key
    # state produced by strictly earlier revocations.
    revocation_prior_order: tuple[tuple[int, ...], str] | None = None
    if envelope.kind == kinds.KIND_REVOKED:
        # U3/§9.5: every signature of a revocation record is judged against the
        # key state produced by strictly earlier revocations. The record's own
        # effect is excluded by construction (its order is not < itself), so no
        # separate self-revocation exemption is needed.
        revocation_prior_order = (
            timestamp_sort_key(envelope.recorded_at),
            digest,
        )
    # S2 (§14.5 steps (4)-(5), §4.4 step 2, §14.6): step (4) resolves the key
    # of every ed25519 entry before any cryptography, and every resolved entry
    # is then judged in array order, first by the §3.4 equation and then by the
    # §9.4 effects, and reports its own state. S2-FIX1 T2 ("invalid beats
    # unverifiable", §4.4 step 2): the first entry with an invalid outcome
    # decides the record's code even when another entry's key cannot be
    # resolved; only without one is the record unverifiable, E_KEY_UNKNOWN for
    # an unresolved key before any unverifiable §9.4 outcome.
    subject_key = _lifecycle_subject_key(envelope)
    resolved: list[tuple[Any, bytes | None, bool]] = []
    for signature in envelope.sigs:
        if not signature.is_ed25519:
            resolved.append((signature, None, False))
            continue
        material, from_context = _resolve_signing_key(signature.key, envelope, context)
        resolved.append((signature, material, from_context))
    unknown_key = any(
        signature.is_ed25519 and material is None for signature, material, _ in resolved
    )
    first_invalid: WeaveError | None = None
    first_unverifiable: WeaveError | None = None
    for signature, material, from_context in resolved:
        if not signature.is_ed25519:
            # Q13: unknown algorithms are ignored, never invalidating.
            states.append({"key": signature.key, "state": "ignored"})
            continue
        if material is None:
            states.append({"key": signature.key, "state": "unverified"})
            if "N_KEY_UNDECLARED" not in view.notices:
                view.notices.append("N_KEY_UNDECLARED")
            continue
        if from_context:
            # S8.10/F12.2: TOFU covers material admitted through context
            # declarations, not material supplied by the local keyset. §14.6:
            # the check counts once the context material is used, "even if
            # that signature or the record then fails" (S2/F42), so the
            # notice is decided before the equation.
            if (
                context.material_source(signature.key) == "context"
                and "N_KEY_TOFU" not in view.notices
            ):
                view.notices.append("N_KEY_TOFU")
        # S8.11/§14.5: the Ed25519 cryptographic steps (§3.4) run before the
        # §9.4 lifecycle/semantic effects, so a flipped signature on a
        # compromised/expired/revoked key reports E_SIG_INVALID.
        try:
            ed25519.verify_signature(material, message, signature.raw or b"")
        except WeaveError as error:
            states.append({"key": signature.key, "state": "invalid"})
            first_invalid = first_invalid or error
            continue
        if from_context or own_effects or signature.key != subject_key:
            # §9.4 judges every signature by its key's lifecycle, including
            # the signatures of a declaration or rotation whose material
            # the record itself supplies (S2/F38/F61-1): a declaration of a
            # compromised key is rescued only by a verified trusted
            # receipt, exactly like any other record the key signed.
            # The admission pass (own_effects=False, §5.3) leaves out only
            # the §9.4 effects on the signature of the key the record
            # states (its subject key); a cosignature or a rotation's
            # old-key signature that fails §9.4 gives the record's subject
            # key neither material nor trust (S2-FIX1 T1, Q2).
            try:
                context.key_state.check_signature_effects(
                    signature.key,
                    envelope.recorded_at,
                    verified_timestamps=context.verified_timestamps,
                    timestamp_evidence_present=context.timestamp_evidence_present,
                    prior_order=(
                        revocation_prior_order
                        if envelope.kind == kinds.KIND_REVOKED
                        else None
                    ),
                )
            except WeaveError as error:
                # §14.6 (S8.10/F12, F52): the equation passed but the key
                # state fails a §9.4 rule, so the signature is unverified.
                states.append({"key": signature.key, "state": "unverified"})
                if record_verdict([error.code]) == "invalid":
                    first_invalid = first_invalid or error
                else:
                    first_unverifiable = first_unverifiable or error
                continue
        states.append({"key": signature.key, "state": "valid"})
        verified.add(signature.key)
    view.verified_keys = frozenset(verified)
    if first_invalid is not None:
        raise first_invalid
    if unknown_key:
        raise WeaveError("E_KEY_UNKNOWN", "signing key is not declared in the context")
    if first_unverifiable is not None:
        raise first_unverifiable


def _lifecycle_subject_key(envelope: envelope_module.Envelope) -> object:
    """The key a declaration or rotation states for itself (§5.3, S2-FIX1 Q2).

    ``body.key`` of a ``weave.key.declared`` record and ``body.new_key`` of a
    ``weave.key.rotated`` record; ``None`` for every other kind. Only that
    key's own signature is left out of §9.4 when the record's admission is
    decided (:func:`attempt_record`).
    """
    body = envelope.body if isinstance(envelope.body, dict) else {}
    if envelope.kind == kinds.KIND_DECLARED:
        return body.get("key")
    if envelope.kind == kinds.KIND_ROTATED:
        return body.get("new_key")
    return None


def _resolve_signing_key(
    key: str,
    envelope: envelope_module.Envelope,
    context: Context,
) -> tuple[bytes | None, bool]:
    """Resolve signer key material: ``(material, from_context)``.

    Key-lifecycle records supply their own key material in the body so the first
    declaration in a fresh context is verifiable without prior trust. No
    ``old_key -> new_key`` inference is performed (M-12): only explicitly listed
    public keys (declaration body, rotation body fields) are used.

    For a ``weave.key.declared`` record, signatures by keys that are declared
    anywhere in the context are verified against that declaration's structural
    public key: the declaration's own trust/validity is decided by the kind
    semantics, not by the fact that a cosignature could be located.
    ``from_context`` is only true for keys whose declaration is itself valid
    (those signatures are subject to TOFU/lifecycle effects); structurally
    resolved keys are reported as ``False`` because the declaration semantics
    owns the trust decision.
    """
    body = envelope.body
    if envelope.kind == kinds.KIND_DECLARED:
        if body.get("key") == key:
            return (decode_public_key_material(body.get("public_key")), False)
        declared_material = context.declaration_material(key)
        if declared_material is not None:
            return (declared_material[0], False)
    if envelope.kind == kinds.KIND_ROTATED:
        if body.get("new_key") == key and "new_public_key" in body:
            return (decode_public_key_material(body["new_public_key"]), False)
        if body.get("old_key") == key and body.get("old_public_key") is not None:
            return (decode_public_key_material(body["old_public_key"]), False)
    material = context.key_state.public_key(key)
    if material is not None:
        return (material, True)
    return (None, False)


def _require_valid_signer(
    view: RecordView, context: Context, key: str, code: str
) -> None:
    """Require a valid signature by ``key`` for a kind-specific rule (Q13 aware).

    A missing signature uses the kind's dedicated code; a present but
    unverifiable one (unknown algorithm only) is unverifiable: E_KEY_UNKNOWN
    when the key is undeclared, E_SIG_UNVERIFIABLE otherwise.
    """
    if key in view.verified_keys:
        return
    raise signer_obligation_error(view, view.envelope, context, code, (key,))


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
        declaration = check_declared_semantics(
            body=envelope.body,
            actor_key=envelope.actor_key,
            actor_type=envelope.actor_type,
            verified_signature_keys=view.verified_keys,
            signature_entries_by_key=view.signature_algs_by_key,
            recorded_at=envelope.recorded_at,
            record_digest=digest,
            context=context,
            source=view.loaded.source,
            signer_error=lambda code: signer_obligation_error(
                view, envelope, context, code, (envelope.body.get("key"),)
            ),
        )
        view.key_declaration = declaration
    elif kind == kinds.KIND_ROTATED:
        view.key_rotation = check_rotated_semantics(
            body=envelope.body,
            actor_key=envelope.actor_key,
            verified_signature_keys=view.verified_keys,
            signature_entries_by_key=view.signature_algs_by_key,
            recorded_at=envelope.recorded_at,
            record_digest=digest,
        )
        _require_valid_signer(view, context, view.key_rotation.old_key, "E_KEY_ROTATION_SIGS")
        _require_valid_signer(view, context, view.key_rotation.new_key, "E_KEY_ROTATION_SIGS")
    elif kind == kinds.KIND_REVOKED:
        revocation_context = RevocationContext(
            frozenset(signature.key for signature in envelope.sigs),
            view.verified_keys,
            context.key_state,
            view.signature_algs_by_key,
        )
        view.key_revocation = check_revoked_semantics(
            body=envelope.body,
            recorded_at=envelope.recorded_at,
            record_digest=digest,
            verification_context=revocation_context,
            signer_error=lambda code: signer_obligation_error(view, envelope, context, code),
        )
    elif kind == kinds.KIND_GRANT:
        state = check_grant_semantics(
            envelope, digest, context, view.verified_keys,
            signer_error=lambda code: signer_obligation_error(view, envelope, context, code),
        )
        if isinstance(state, GrantRecord):
            _require_valid_signer(view, context, envelope.actor_key, "E_GRANT_GRANTER")
            view.grant_record = state
        else:
            view.grant_revocation = state
    elif kind == kinds.KIND_CONSENT_GRANTED:
        if envelope.actor_type not in ("human", "organization"):
            raise WeaveError(
                "E_ACTOR_KEY_TYPE_MISMATCH",
                "consent.granted actor.type must be human or organization",
            )
        _require_valid_signer(view, context, envelope.actor_key, "E_ACTOR_KEY_TYPE_MISMATCH")
        from .times import timestamp_sort_key

        valid_until = envelope.body["valid_until"]
        if valid_until is not None and timestamp_sort_key(
            envelope.body["valid_from"]
        ) > timestamp_sort_key(valid_until):
            raise WeaveError("E_CONSENT_VALIDITY", "consent valid_from is after valid_until")
    elif kind == kinds.KIND_CONSENT_REVOKED:
        if envelope.actor_type not in ("human", "organization"):
            raise WeaveError(
                "E_ACTOR_KEY_TYPE_MISMATCH",
                "consent.revoked actor.type must be human or organization",
            )
        _require_valid_signer(view, context, envelope.actor_key, "E_ACTOR_KEY_TYPE_MISMATCH")
        reference = refs.validate_reference(envelope.body["revokes"])
        resolution = context.resolve(reference)
        if resolution.state != refs.FOUND or resolution.target is None:
            raise WeaveError(
                "E_CONSENT_REVOKE_REF", "revokes does not resolve to a consent grant"
            )
        if refs.kind_claim_mismatch(reference, resolution):
            raise WeaveError(
                "E_REF_KIND_MISMATCH", "revokes kind claim contradicts the target kind"
            )
        target = resolution.target
        if target.kind != kinds.KIND_CONSENT_GRANTED:
            raise WeaveError(
                "E_CONSENT_REVOKE_REF", "revokes does not resolve to a consent grant"
            )
        view.consent_revocation = ConsentRevocation(
            digest=digest,
            target_digest=target.computed_digest or "",
            effective_at=envelope.body["effective_at"],
        )
    elif kind == kinds.KIND_ERASURE:
        _check_erasure_actor(envelope, context)
        _require_valid_signer(view, context, envelope.actor_key, "E_ERASE_ACTOR")


def _check_erasure_actor(envelope: envelope_module.Envelope, context: Context) -> None:
    """Erasure signer rules (M-10): human/organization, or granted agent/program."""
    actor_type = envelope.actor_type
    if actor_type in ("human", "organization"):
        return
    if actor_type == "agent":
        if envelope.actor_grant is None:
            raise WeaveError("E_ERASE_ACTOR", "agent erasure requires a grant")
        try:
            check_agent_authorization(envelope, context)
        except WeaveError as error:
            raise WeaveError(
                "E_ERASE_ACTOR", "agent erasure is not covered by an erase grant"
            ) from error
        grant = context.resolve(envelope.actor_grant)
        if grant.target is not None:
            target_envelope = getattr(grant.target.record, "envelope", None)
            if target_envelope is not None:
                grant_body = target_envelope.body.get("grant", {})
                if "erase" not in grant_body.get("actions", ()):
                    raise WeaveError("E_ERASE_ACTOR", "grant does not allow erase")
        return
    # program/device: body.basis must reference a valid grant covering the actor
    # key with the erase action.
    basis = envelope.body.get("basis")
    if basis is None:
        raise WeaveError("E_ERASE_ACTOR", "program/device erasure requires a basis grant")
    reference = refs.validate_reference(basis)
    resolution = context.resolve(reference)
    if resolution.state != refs.FOUND or resolution.target is None:
        raise WeaveError("E_ERASE_ACTOR", "basis grant cannot be resolved")
    target = resolution.target
    if target.kind != kinds.KIND_GRANT:
        raise WeaveError("E_ERASE_ACTOR", "basis does not reference a grant")
    target_envelope = getattr(target.record, "envelope", None)
    if target_envelope is None or target_envelope.body.get("action") != "grant":
        raise WeaveError("E_ERASE_ACTOR", "basis does not reference an authorising grant")
    grant = target_envelope.body["grant"]
    if grant["grantee"]["key"] != envelope.actor_key:
        raise WeaveError("E_ERASE_ACTOR", "basis grant is not for this actor")
    if "erase" not in grant["actions"] or "weave.erasure" not in grant["kinds"]:
        raise WeaveError("E_ERASE_ACTOR", "basis grant does not allow erase")


# ---------------------------------------------------------------------------
# Actor compatibility and authorisation (step 8)
# ---------------------------------------------------------------------------


def _check_actor_and_authorization(
    view: RecordView,
    envelope: envelope_module.Envelope,
    context: Context,
) -> None:
    if envelope.kind in kinds.KEY_LIFECYCLE_KINDS:
        # The kind pages carry their own signer-class rules (including
        # human/organization co-signatures), so the generic rules do not apply.
        return
    for signature in envelope.sigs:
        if not signature.is_ed25519:
            continue
        key_class = context.key_state.key_type(signature.key)
        if key_class is None:
            continue  # undeclared or rotation-supplied key: no class check
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
        # Delegated weave.grant records are governed by the delegation rules;
        # every other agent record (any stage) needs grant coverage (M-3).
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
    """Re-run the full record pipeline, replacing the view's current result.

    For ``weave.key.declared`` and ``weave.key.rotated`` the pipeline runs a
    second time with the §9.4 effects on the subject key's own signature left
    out (:func:`_lifecycle_subject_key`); when that pass is valid its facts are
    *admitted* to the key state even if the reported verdict fails a §9.4 rule
    (S2/F38). Every other signature, cosignatures and a rotation's old-key
    signature included, keeps its §9.4 effects in that pass (S2-FIX1 Q2).
    """
    _attempt_record_pass(view, context, own_effects=True)
    view.admitted_declaration = None
    view.admitted_rotation = None
    if view.verdict == "valid" or view.envelope is None:
        return
    if view.envelope.kind not in (kinds.KIND_DECLARED, kinds.KIND_ROTATED):
        return
    probe = RecordView(loaded=view.loaded)
    _attempt_record_pass(probe, context, own_effects=False)
    if probe.verdict == "valid":
        view.admitted_declaration = probe.key_declaration
        view.admitted_rotation = probe.key_rotation


def _attempt_record_pass(view: RecordView, context: Context, *, own_effects: bool) -> None:
    """One run of the record pipeline (see :func:`attempt_record`)."""
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
    view.signature_algs_by_key = {}
    view.key_declaration = None
    view.key_rotation = None
    view.key_revocation = None
    view.grant_record = None
    view.grant_revocation = None
    view.consent_revocation = None
    try:
        value = view.loaded.value
        if value is None:
            raise WeaveError("E_JSON_INVALID", "record file is not canonical JSON")
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
        _check_signature_presence(view, envelope)
        if envelope.kind == kinds.KIND_DECLARED:
            # T1/§9.1 rule 1 (S2/F39/F50): a missing or malformed
            # ``body.public_key`` is decided before key resolution (step (4)):
            # the declared key's own material is what the self-signature would
            # resolve to, so no signature check runs (``sigs`` stays ``[]``)
            # and no other body defect (``body.key`` included) can precede it.
            decode_public_key_material(envelope.body.get("public_key"))
        if envelope.kind == kinds.KIND_ROTATED:
            # T13: the declared key-material structure (strict base64url, 32
            # bytes, key-id derivation) is a body/kind check that runs before the
            # signature pass; curve-point decoding stays with the §3.4 crypto.
            check_rotated_material(envelope.body)
        _verify_signatures(view, envelope, context, own_effects=own_effects)
        _check_required_signers(view, envelope, context)
        kinds.validate_body_schema(envelope.kind, envelope.body)
        _check_kind_semantics(view, envelope, context)
        _check_actor_and_authorization(view, envelope, context)
        _check_labels(view, envelope, context)
        _check_references(view, envelope, context)
        if not envelope.kind_known:
            view.notices.append("N_KIND_UNKNOWN_OPAQUE")
        if envelope.stage == "accepted" and not _has_human_signature(view, context):
            view.notices.append("N_NO_HUMAN_SIGNATURE")
        view.verdict = "valid"
    except WeaveError as error:
        view.errors.append(error.code)
        if error.notice is not None:
            view.notices.append(error.notice)
        view.verdict = record_verdict(view.errors)


def _has_human_signature(view: RecordView, context: Context) -> bool:
    """Whether some valid signature was made by a declared human key."""
    for key in view.verified_keys:
        if context.key_state.key_type(key) == "human":
            return True
    return False


# ---------------------------------------------------------------------------
# Fixed-point verification of a record set
# ---------------------------------------------------------------------------


def verify_record_set(
    loaded: Iterable[LoadedRecord],
    *,
    verified_timestamps: tuple[VerifiedTimestamp, ...] = (),
    timestamp_evidence_present: bool = False,
    context_views: Iterable[RecordView] = (),
) -> list[RecordView]:
    """Verify every record of a set (a container or an external keyset)."""
    views = [RecordView(loaded=record) for record in loaded]
    fixed_context_views = list(context_views)
    max_passes = 2 * len(views) + 3
    previous: tuple[Any, ...] | None = None
    for _ in range(max_passes):
        context = Context(
            verified_timestamps=verified_timestamps,
            timestamp_evidence_present=timestamp_evidence_present,
        )
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
    verified_timestamps: tuple[VerifiedTimestamp, ...] = (),
    timestamp_evidence_present: bool = False,
) -> tuple[RecordView, list[RecordView]]:
    """Verify one record target against an external context (the ``--keys`` keyset)."""
    resolved_context = verify_record_set(
        context_records,
        verified_timestamps=verified_timestamps,
        timestamp_evidence_present=timestamp_evidence_present,
    )
    context = Context(
        verified_timestamps=verified_timestamps,
        timestamp_evidence_present=timestamp_evidence_present,
    )
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

    Files are parsed and structurally validated as records; anything else is a
    usage error (exit 2). A record that parses and is structurally valid but
    fails its semantic or cryptographic checks does not establish trust; that is
    not a usage error.
    """
    # X3: lstat before listing; only a directory is accepted.
    operator_input.path_kind(path, "--keys", allowed=(operator_input.DIRECTORY,))
    loaded: list[LoadedRecord] = []
    try:
        entries = sorted(path.iterdir(), key=lambda item: item.name)
    except OSError as error:
        raise UsageError(
            "--keys %s cannot be listed: %s" % (path, error.strerror or error)
        ) from error
    for entry in entries:
        # W10/L6 (§14.1): every top-level entry whose name ends in ".json" is a
        # keyset file, including names that begin with "."; one that does not
        # resolve to a regular file (a directory, a dangling symbolic link, a
        # special file) is an operator error, never silently skipped.
        if not entry.name.endswith(".json"):
            continue
        # X3: lstat before opening (a FIFO entry never blocks the verifier).
        try:
            operator_input.path_kind(entry, "--keys entry", allowed=(operator_input.FILE,))
        except UsageError as error:
            raise UsageError(
                "--keys %s: entry %s is not a regular file" % (path, entry.name)
            ) from error
        try:
            descriptor = os.open(entry, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
            with os.fdopen(descriptor, "rb") as handle:
                if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                    raise UsageError(
                        "--keys %s: entry %s is not a regular file" % (path, entry.name)
                    )
                # §13: one keyset file is one record; read at most one byte past
                # MAX_RECORD_BYTES so an oversize file is rejected without a
                # full read (it then fails as E_JSON_SIZE below).
                raw = handle.read(MAX_RECORD_BYTES + 1)
        except OSError as error:
            raise UsageError(
                "--keys %s: entry %s cannot be read: %s"
                % (path, entry.name, error.strerror or error)
            ) from error
        try:
            record = load_record_bytes(raw, source="keyset")
            if record.value is None or erase.looks_like_placeholder(record.value):
                raise WeaveError("E_JSON_INVALID", "keyset file is not a normal record")
            envelope = envelope_module.validate_envelope(record.value)
            # S8.9/§14.1: the structural side of the boundary includes the
            # registered-kind body *schema*; a semantic, lifecycle, actor,
            # authorisation or cryptographic failure is not a usage error and
            # simply establishes no trust.
            kinds.validate_body_schema(envelope.kind, envelope.body)
            # V5/M2: the declared/rotated key material encoding is part of the
            # structural group. A keyset that carries a structurally invalid
            # declaration is an operator error (exit 2), not a silently ignored
            # file.
            _check_keyset_material_structure(envelope.kind, envelope.body)
        except WeaveError as error:
            raise UsageError(
                "--keys %s: entry %s is not a valid record: %s" % (path, entry.name, error.code)
            ) from error
        loaded.append(record)
    _check_keyset_declaration_conflicts(loaded)
    return loaded


def _check_keyset_material_structure(kind: str, body: dict[str, Any]) -> None:
    """V5/§14.1: structurally validate the key material of a keyset record.

    ``public_key``/``new_public_key``/``old_public_key`` must be strictly-encoded
    base64url decoding to exactly 32 bytes; otherwise the declaration is not in
    the structural group and the keyset is a usage error.
    """
    if kind == kinds.KIND_DECLARED:
        keys_module.decode_public_key_material(body.get("public_key"))
    elif kind == kinds.KIND_ROTATED:
        keys_module.decode_public_key_material(body.get("new_public_key"))
        if body.get("old_public_key") is not None:
            keys_module.decode_public_key_material(body["old_public_key"])


def _check_keyset_declaration_conflicts(records: list[LoadedRecord]) -> None:
    """T4/§14.1: conflicting keyset declarations of one key id are a usage error.

    Two structurally valid ``weave.key.declared`` records for the same key id
    with a different class, or a different validity window (present versus absent
    counts as different), are an operator error: exit 2, no report. The
    deterministic "earlier" order (recorded_at, record digest) only applies when
    the declarations agree.
    """
    seen: dict[str, tuple[str, str | None, str | None]] = {}
    for record in records:
        value = record.value
        if not isinstance(value, dict) or value.get("kind") != kinds.KIND_DECLARED:
            continue
        body = value.get("body")
        if not isinstance(body, dict):
            continue
        key_id = body.get("key")
        key_type = body.get("key_type")
        if not isinstance(key_id, str) or not isinstance(key_type, str):
            continue
        window = (key_type, body.get("valid_from"), body.get("valid_until"))
        existing = seen.get(key_id)
        if existing is None:
            seen[key_id] = window
            continue
        if existing != window:
            raise UsageError(
                "conflicting keyset declarations for key id %s" % key_id
            )
