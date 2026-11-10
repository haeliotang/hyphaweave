# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Labels, consent references and strictest-label propagation (spec §8).

Labels are claims on a signed record (H1): the verifier checks their syntax, the
strictest-wins propagation along ``derived_from`` references (H2) and the
``local-only`` export refusal. It does not verify that a claim is true.
"""

from __future__ import annotations

from typing import Protocol

from . import kinds, refs
from .envelope import Envelope
from .errors import WeaveError


class LabelContext(Protocol):
    """What label checking needs from the verifier's live context."""

    def resolve(self, reference: refs.Reference) -> refs.Resolution:
        ...


def check_label_propagation(envelope: Envelope, context: LabelContext) -> list[str]:
    """Check strictest-label propagation; return notices to attach.

    ``E_LABEL_DOWNGRADE`` is raised for a resolved ``derived_from`` input whose
    sensitivity rank exceeds the referring record's rank, including when the
    referring record has no sensitivity and the input is not public (conservative
    reading, Q16). Unresolved inputs leave propagation unchecked
    (``N_LABEL_PROPAGATION_UNCHECKED``).
    """
    notices: list[str] = []
    for entry in envelope.refs:
        if entry.rel != "derived_from":
            continue
        resolution = context.resolve(entry.ref)
        if resolution.state != refs.FOUND or resolution.target is None:
            notices.append("N_LABEL_PROPAGATION_UNCHECKED")
            continue
        target = resolution.target
        target_envelope = getattr(target.record, "envelope", None)
        if target_envelope is None:  # pragma: no cover - found implies a record view
            notices.append("N_LABEL_PROPAGATION_UNCHECKED")
            continue
        target_rank = target_envelope.sensitivity_rank
        record_rank = envelope.sensitivity_rank
        if record_rank < 0:
            if target_rank > 0:
                raise WeaveError(
                    "E_LABEL_DOWNGRADE",
                    "derived record has no sensitivity while its input is not public",
                )
        elif record_rank < target_rank:
            raise WeaveError(
                "E_LABEL_DOWNGRADE", "derived record is less sensitive than its input"
            )
    return sorted(set(notices))


def check_consent_reference(envelope: Envelope, context: LabelContext) -> list[str]:
    """Check ``labels.consent`` (spec §8.6); return notices to attach."""
    if envelope.consent is None:
        return []
    resolution = context.resolve(envelope.consent)
    if resolution.state != refs.FOUND or resolution.target is None:
        # An erased or mismatched target is a contradiction of the claim; a
        # missing/unverifiable reference is only a notice (record verdict
        # unchanged, spec §8.6).
        if resolution.state == refs.ERASED:
            raise WeaveError(
                "E_REF_KIND_MISMATCH", "consent reference resolves to an erased record"
            )
        return ["N_CONSENT_UNRESOLVED"]
    target = resolution.target
    if refs.kind_claim_mismatch(envelope.consent, resolution):
        raise WeaveError(
            "E_REF_KIND_MISMATCH", "consent kind claim contradicts the target kind"
        )
    if target.kind not in (kinds.KIND_CONSENT_GRANTED, kinds.KIND_CONSENT_REVOKED):
        raise WeaveError(
            "E_REF_KIND_MISMATCH", "consent reference resolves to a non-consent kind"
        )
    return []


def is_local_only(envelope: Envelope) -> bool:
    """Whether the record carries the ``local-only`` sensitivity."""
    return envelope.sensitivity == "local-only"
