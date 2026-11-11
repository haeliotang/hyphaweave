# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Deterministic report construction and serialization (spec §14.2/§14.6).

The report shape is stable and versioned (``report_version: "1"``). Records are
emitted in manifest order (or the single input record); errors and notices are
sorted and de-duplicated; ``limitations`` is a sorted, unique array of the
closed identifier set of spec §14.9 (no free prose, S12). Input paths,
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

#: Closed set of limitation identifiers (spec §14.9, S12). A report lists only
#: the ones that apply, sorted and unique; no prose is ever emitted.
LIMITATION_OFFLINE_CONTEXT = "L_OFFLINE_CONTEXT"
LIMITATION_CHAIN_CLAIM = "L_CHAIN_CLAIM_UNVERIFIED"
LIMITATION_TOFU = "L_KEY_TRUST_TOFU"
LIMITATION_TSA_TRUST = "L_TSA_TRUST_UNVERIFIED"
LIMITATION_PREVIOUS_SIG = "L_PREVIOUS_SIG_UNVERIFIED"
LIMITATION_PREVIOUS_CONTENT = "L_PREVIOUS_CONTENT_UNVERIFIED"
LIMITATION_ERASED_PLACEHOLDER = "L_ERASED_PLACEHOLDER"
LIMITATION_ERASED_STANDALONE = "L_ERASED_STANDALONE"
LIMITATION_LABELS_ARE_CLAIMS = "L_LABELS_ARE_CLAIMS"
LIMITATION_UNKNOWN_KIND = "L_UNKNOWN_KIND_OPAQUE"
LIMITATION_UNRESOLVED_LABEL_PROPAGATION = "L_LABEL_PROPAGATION_UNCHECKED"

#: Every identifier the verifier may emit (used by tests and the vectors gate).
LIMITATION_IDENTIFIERS: frozenset[str] = frozenset(
    {
        LIMITATION_OFFLINE_CONTEXT,
        LIMITATION_CHAIN_CLAIM,
        LIMITATION_TOFU,
        LIMITATION_TSA_TRUST,
        LIMITATION_PREVIOUS_SIG,
        LIMITATION_PREVIOUS_CONTENT,
        LIMITATION_ERASED_PLACEHOLDER,
        LIMITATION_ERASED_STANDALONE,
        LIMITATION_LABELS_ARE_CLAIMS,
        LIMITATION_UNKNOWN_KIND,
        LIMITATION_UNRESOLVED_LABEL_PROPAGATION,
    }
)


def limitation_list(values: Iterable[str]) -> list[str]:
    """Return the sorted, unique limitation identifiers (spec §14.9)."""
    return sorted(set(values))


def record_limitations(
    *,
    notices: Iterable[str],
    verdict: str,
    kind_known: bool,
    placeholder: bool,
    has_labels: bool,
    standalone: bool = False,
) -> list[str]:
    """Limitation identifiers that apply to one record's report entry.

    The same construction is used for a standalone record target, for a
    container's records and for the container aggregate (S12/F12.3): the opaque
    kind limitation is reported only when the record verdict is ``valid``.
    """
    notice_set = set(notices)
    result: list[str] = []
    if "N_KEY_TOFU" in notice_set:
        result.append(LIMITATION_TOFU)
    if not kind_known and verdict == "valid":
        result.append(LIMITATION_UNKNOWN_KIND)
    if placeholder:
        result.append(LIMITATION_ERASED_PLACEHOLDER)
        if standalone:
            result.append(LIMITATION_ERASED_STANDALONE)
    if has_labels:
        result.append(LIMITATION_LABELS_ARE_CLAIMS)
    if "N_LABEL_PROPAGATION_UNCHECKED" in notice_set:
        result.append(LIMITATION_UNRESOLVED_LABEL_PROPAGATION)
    return limitation_list(result)



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
    kind_known: bool | None,
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
    input_sha256: str | None,
    input_size: int | None,
    records: list[dict[str, Any]],
    checks_disabled: Iterable[str] = (),
    container: dict[str, Any] | None = None,
    limitations: Iterable[str] = (),
    errors: Iterable[str] = (),
    notices: Iterable[str] = (),
) -> dict[str, Any]:
    """Assemble the report object (spec §14.6)."""
    summary = {"erased": 0, "invalid": 0, "unverifiable": 0, "valid": 0}
    for entry in records:
        summary[entry["verdict"]] = summary.get(entry["verdict"], 0) + 1
    report: dict[str, Any] = {
        "checks_disabled": sorted(set(checks_disabled)),
        "input": {"sha256": input_sha256, "size": input_size},
        "limitations": limitation_list(limitations),
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
