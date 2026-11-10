# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Deterministic report construction and serialization (spec §14.2).

The report shape is stable and versioned (``report_version: "1"``). Records are
emitted in manifest order (or the single input record); errors and notices are
sorted and de-duplicated; limitations are stable English strings. Input paths,
usernames, hostnames, the clock, the locale, the timezone and the environment
never appear in a report.

Serialization: ``json.dumps(sort_keys=True, ensure_ascii=True, indent=2)`` plus
exactly one trailing LF.
"""

from __future__ import annotations

import json
from typing import Any, Iterable

from . import VERIFIER_NAME, __version__
from .errors import ERROR_CODES, EFFECT_INVALID, EFFECT_UNVERIFIABLE

REPORT_VERSION = "1"
SPEC = "weave-record/1"

#: Stable limitation strings. A report lists only the ones that apply.
LIMITATION_OFFLINE_CONTEXT = (
    "Offline verification: only this container's records and the supplied keyset are in the "
    "verification context; references to records outside the context resolve as missing."
)
LIMITATION_CHAIN_CLAIM = (
    "The internal hash chain of a claimed L1/L2 container cannot be recomputed offline: "
    "chain.status is unverified and level_verified is reported as L0."
)
LIMITATION_TOFU = (
    "Key trust is trust-on-first-use from key-lifecycle records in the context; no certificate "
    "authority, network lookup or pinned local trust store was consulted."
)
LIMITATION_TSA_TRUST = (
    "No matching TSA trust anchor was available: timestamps are present-unverified and the "
    "container cannot be reported valid."
)
LIMITATION_PREVIOUS_SIG = (
    "The embedded previous manifest's own signature was not re-verified; only its digest was "
    "checked against previous_manifest.digest."
)
LIMITATION_ERASED_PLACEHOLDER = (
    "A weave.erased placeholder has no content: its integrity rests on the signed attestation, "
    "the retained original digest and the manifest entry, not on a hash of the deleted record."
)
LIMITATION_ERASED_STANDALONE = (
    "A standalone weave.erased placeholder has no container context, so the attestation "
    "resolution is reported but the container cross-checks of the erasure rules cannot be applied."
)
LIMITATION_LABELS_ARE_CLAIMS = (
    "Labels, consent coverage and licences are claims checked for consistency only; their truth "
    "is not established offline."
)
LIMITATION_UNKNOWN_KIND = (
    "An unregistered kind is transported and integrity-checked but its body is never interpreted "
    "(K3 forward compatibility)."
)
LIMITATION_UNRESOLVED_LABEL_PROPAGATION = (
    "Label propagation was not checked for unresolved derived_from references."
)


def record_verdict(errors: Iterable[str]) -> str:
    """Compute a record verdict from its error codes (effect column of the registry)."""
    codes = list(errors)
    if any(ERROR_CODES.get(code) == EFFECT_INVALID for code in codes):
        return "invalid"
    if any(ERROR_CODES.get(code) == EFFECT_UNVERIFIABLE for code in codes):
        return "unverifiable"
    return "valid"


def container_verdict(
    *,
    errors: Iterable[str],
    record_verdicts: Iterable[str],
) -> str:
    """Compute a container verdict (spec §14.3)."""
    all_errors = list(errors)
    verdicts = list(record_verdicts)
    if any(ERROR_CODES.get(code) == EFFECT_INVALID for code in all_errors):
        return "invalid"
    if "invalid" in verdicts:
        return "invalid"
    if any(ERROR_CODES.get(code) == EFFECT_UNVERIFIABLE for code in all_errors):
        return "unverifiable"
    if "unverifiable" in verdicts:
        return "unverifiable"
    return "valid"


def record_entry(
    *,
    digest: str | None,
    record_id: str | None,
    kind: str | None,
    stage: str | None,
    origin: dict[str, str] | None,
    kind_known: bool,
    verdict: str,
    errors: Iterable[str],
    notices: Iterable[str],
    refs: list[dict[str, Any]],
    sigs: list[dict[str, Any]],
    attestation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one ``records[]`` report entry."""
    entry: dict[str, Any] = {
        "digest": digest,
        "errors": sorted(set(errors)),
        "id": record_id,
        "kind": kind,
        "kind_known": kind_known,
        "notices": sorted(set(notices)),
        "origin": origin,
        "refs": refs,
        "sigs": sigs,
        "stage": stage,
        "verdict": verdict,
    }
    if attestation is not None:
        entry["attestation"] = attestation
    return entry


def build_report(
    *,
    target: str,
    verdict: str,
    input_sha256: str,
    input_size: int,
    records: list[dict[str, Any]],
    checks_disabled: Iterable[str] = (),
    container: dict[str, Any] | None = None,
    limitations: Iterable[str] = (),
    errors: Iterable[str] = (),
    notices: Iterable[str] = (),
) -> dict[str, Any]:
    """Assemble the report object (spec §14.2)."""
    summary = {"erased": 0, "invalid": 0, "unverifiable": 0, "valid": 0}
    for entry in records:
        summary[entry["verdict"]] = summary.get(entry["verdict"], 0) + 1
    report: dict[str, Any] = {
        "checks_disabled": sorted(set(checks_disabled)),
        "input": {"sha256": input_sha256, "size": input_size},
        "limitations": list(limitations),
        "summary": summary,
        "records": records,
        "report_version": REPORT_VERSION,
        "spec": SPEC,
        "target": target,
        "verdict": verdict,
        "verifier": {"name": VERIFIER_NAME, "version": __version__},
    }
    if container is not None:
        report["container"] = container
    return report


def serialize(report: dict[str, Any]) -> bytes:
    """Serialize a report deterministically: sorted keys, ASCII, 2-space indent, one LF."""
    text = json.dumps(report, sort_keys=True, ensure_ascii=True, indent=2)
    return (text + "\n").encode("utf-8")
