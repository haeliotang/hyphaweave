# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Conformance-vector runner (spec §14.10 and §16).

Every case directory contains an ``expected.json`` describing the target, the
input, optional CLI-style arguments and the expected result. This runner
executes each case in-process (no shelling out) and compares:

* ``verdict`` exactly;
* ``errors`` as a set against the aggregated errors (container errors plus every
  record's errors);
* ``notices`` expected subset of the aggregated notices;
* ``expected_digest`` against the record digest (a record target is one record;
  a container case succeeds if any listed record carries that digest);
* ``expected_resolution`` against the record's ``refs[].state`` in order (a
  standalone erased placeholder uses its ``attestation.state``);
* ``expected_container`` as a recursive subset of ``report.container``;
* ``records`` as per-record subsets matched by ``id``.

Argument tokens follow the contract: ``@keyset`` is the suite's
``keys/keyset`` directory, ``@case`` is the case directory, anything else is a
path relative to the case directory.

The runner is deterministic: cases are executed in sorted order and the result
objects never contain absolute paths, the clock or environment values.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from . import container as container_module
from . import report as report_module
from . import verifier
from .errors import CheckSkipper, UsageError, WeaveError
from .report import record_verdict

TARGETS = ("record", "container")


# ---------------------------------------------------------------------------
# Suite discovery
# ---------------------------------------------------------------------------


def _discover_cases(root: Path) -> list[Path]:
    """Discover cases in the documented ``<category>/<case-id>`` layout.

    Exactly two levels below the given root, so a source suite and a frozen
    suite rooted at ``vectors/frozen/v0.1`` never overlap:
    ``root/<category>/<case-id>/expected.json``.
    """
    cases = [path.parent for path in root.glob("*/*/expected.json") if path.is_file()]
    return sorted(cases, key=lambda path: path.as_posix())


def _find_suite_root(case_dir: Path) -> Path | None:
    candidates = [case_dir, *case_dir.parents]
    for candidate in candidates:
        if (candidate / "keys" / "keyset").is_dir():
            return candidate
    return None


def _case_id(expected: dict[str, Any], case_dir: Path) -> str:
    identifier = expected.get("id")
    if isinstance(identifier, str) and identifier:
        return identifier
    return case_dir.name


# ---------------------------------------------------------------------------
# Case execution
# ---------------------------------------------------------------------------


def _resolve_token(token: str, case_dir: Path, suite_root: Path | None) -> Path:
    if token == "@keyset":
        if suite_root is None:
            raise UsageError("vector suite has no keys/keyset directory")
        return suite_root / "keys" / "keyset"
    if token == "@case":
        return case_dir
    if token.startswith("@"):
        raise UsageError("unknown argument token %r" % token)
    path = Path(token)
    if path.is_absolute():
        return path
    return case_dir / token


class _CaseArguments:
    __slots__ = ("keys", "tsa_trust", "previous")

    def __init__(self) -> None:
        self.keys: Path | None = None
        self.tsa_trust: Path | None = None
        self.previous: Path | None = None


def _parse_case_arguments(
    arguments: Any, case_dir: Path, suite_root: Path | None
) -> _CaseArguments:
    resolved = _CaseArguments()
    if arguments is None:
        return resolved
    if not isinstance(arguments, list):
        raise UsageError("expected.json args must be an array")
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if token == "--keys":
            if index + 1 >= len(arguments):
                raise UsageError("--keys requires a value")
            resolved.keys = _resolve_token(str(arguments[index + 1]), case_dir, suite_root)
            index += 2
        elif token == "--tsa-trust":
            if index + 1 >= len(arguments):
                raise UsageError("--tsa-trust requires a value")
            resolved.tsa_trust = _resolve_token(
                str(arguments[index + 1]), case_dir, suite_root
            )
            index += 2
        elif token == "--previous":
            if index + 1 >= len(arguments):
                raise UsageError("--previous requires a value")
            resolved.previous = _resolve_token(str(arguments[index + 1]), case_dir, suite_root)
            index += 2
        elif token in ("--json",):
            index += 1
        else:
            raise UsageError("unsupported vector case argument %r" % token)
    return resolved


_KEYSET_CACHE: dict[str, tuple[list[verifier.LoadedRecord], list[verifier.RecordView]]] = {}


def _load_keyset(case_arguments: _CaseArguments) -> tuple[list[verifier.LoadedRecord], list[verifier.RecordView]]:
    """Load and verify a keyset directory once per process (deterministic cache)."""
    if case_arguments.keys is None:
        return [], []
    cache_key = str(case_arguments.keys)
    cached = _KEYSET_CACHE.get(cache_key)
    if cached is not None:
        return cached
    loaded = verifier.load_keyset_directory(case_arguments.keys)
    views = verifier.verify_record_set(loaded)
    _KEYSET_CACHE[cache_key] = (loaded, views)
    return loaded, views


def _case_input_path(case_dir: Path, expected: dict[str, Any]) -> Path:
    input_name = expected.get("input")
    if not isinstance(input_name, str) or not input_name:
        raise UsageError("expected.json input must be a non-empty string")
    return case_dir / input_name


def _run_case(
    case_dir: Path,
    expected: dict[str, Any],
    suite_root: Path | None,
    default_tsa_trust: bytes | None,
    skipper: CheckSkipper,
) -> dict[str, Any]:
    target = expected.get("target")
    if target not in TARGETS:
        raise UsageError("expected.json target must be record or container")
    case_arguments = _parse_case_arguments(expected.get("args"), case_dir, suite_root)
    keyset_loaded, keyset_views = _load_keyset(case_arguments)
    tsa_trust = default_tsa_trust
    if case_arguments.tsa_trust is not None:
        tsa_trust = case_arguments.tsa_trust.read_bytes()
    input_path = _case_input_path(case_dir, expected)

    if target == "record":
        actual = _run_record_case(input_path, keyset_loaded, skipper)
    else:
        verification = container_module.verify_container(
            input_path,
            keyset_records=keyset_loaded,
            keyset_views=keyset_views,
            tsa_trust=tsa_trust,
            previous_container=case_arguments.previous,
            skipper=skipper,
        )
        actual = _actual_from_container_report(verification.report)
    mismatches = _compare(expected, actual, target)
    return {
        "id": _case_id(expected, case_dir),
        "mismatches": mismatches,
        "ok": not mismatches,
        "verdict": actual["verdict"],
    }


def _run_record_case(
    input_path: Path,
    keyset_loaded: list[verifier.LoadedRecord],
    skipper: CheckSkipper,
) -> dict[str, Any]:
    raw = input_path.read_bytes()
    try:
        loaded = verifier.load_record_bytes(raw, source="record")
    except WeaveError as error:
        filtered = [code for code in [error.code] if not skipper.skip_error(code)]
        entry = report_module.record_entry(
            digest=None,
            record_id=None,
            kind=None,
            stage=None,
            origin=None,
            kind_known=False,
            verdict=record_verdict(filtered) if filtered else "valid",
            errors=filtered,
            notices=[],
            refs=[],
            sigs=[],
        )
        return {
            "verdict": entry["verdict"],
            "errors": entry["errors"],
            "notices": [],
            "records": [entry],
        }
    target_view, _ = verifier.verify_single_record(loaded, keyset_loaded, verified_timestamps=())
    entry = container_module._record_report_entry(target_view)
    filtered_errors = [code for code in entry["errors"] if not skipper.skip_error(code)]
    entry["errors"] = sorted(set(filtered_errors))
    if target_view.placeholder is None:
        entry["verdict"] = record_verdict(filtered_errors)
    return {
        "verdict": entry["verdict"],
        "errors": entry["errors"],
        "notices": entry["notices"],
        "records": [entry],
    }


def _actual_from_container_report(report: dict[str, Any]) -> dict[str, Any]:
    container = report.get("container", {})
    errors: set[str] = set(container.get("errors", []))
    notices: set[str] = set(container.get("notices", []))
    records = report.get("records", [])
    for entry in records:
        errors.update(entry.get("errors", []))
        notices.update(entry.get("notices", []))
    return {
        "verdict": report["verdict"],
        "errors": sorted(errors),
        "notices": sorted(notices),
        "records": records,
        "container": container,
    }


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------


def _recursive_subset(expected: Any, actual: Any) -> bool:
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return False
        for key, expected_value in expected.items():
            if key not in actual:
                return False
            if not _recursive_subset(expected_value, actual[key]):
                return False
        return True
    if isinstance(expected, list):
        if not isinstance(actual, list) or len(expected) != len(actual):
            return False
        return all(
            _recursive_subset(expected_item, actual_item)
            for expected_item, actual_item in zip(expected, actual)
        )
    return expected == actual


def _resolution_states(actual: dict[str, Any], target: str, records: list[dict[str, Any]]) -> list[str]:
    if target == "record":
        if not records:
            return []
        entry = records[0]
        if entry.get("attestation") is not None and not entry.get("refs"):
            return [entry["attestation"]["state"]]
        return [item["state"] for item in entry.get("refs", [])]
    states: list[str] = []
    for entry in records:
        states.extend(item["state"] for item in entry.get("refs", []))
        if entry.get("attestation") is not None and not entry.get("refs"):
            states.append(entry["attestation"]["state"])
    return states


def _compare(expected: dict[str, Any], actual: dict[str, Any], target: str) -> list[str]:
    mismatches: list[str] = []
    expected_verdict = expected.get("verdict")
    if expected_verdict != actual["verdict"]:
        mismatches.append(
            "verdict: expected %r, got %r" % (expected_verdict, actual["verdict"])
        )
    expected_errors = set(expected.get("errors", []))
    actual_errors = set(actual["errors"])
    if expected_errors != actual_errors:
        mismatches.append(
            "errors: expected %s, got %s"
            % (sorted(expected_errors), sorted(actual_errors))
        )
    expected_notices = set(expected.get("notices", []))
    if not expected_notices <= set(actual["notices"]):
        mismatches.append(
            "notices: expected subset %s, got %s"
            % (sorted(expected_notices), sorted(actual["notices"]))
        )
    if "expected_digest" in expected:
        expected_digest = expected["expected_digest"]
        records = actual["records"]
        if target == "record":
            got = records[0].get("digest") if records else None
            matched = got == expected_digest
        else:
            matched = any(entry.get("digest") == expected_digest for entry in records)
        if not matched:
            mismatches.append(
                "expected_digest: expected %r, got %r"
                % (expected_digest, [entry.get("digest") for entry in records])
            )
    if "expected_resolution" in expected:
        expected_resolution = expected["expected_resolution"]
        states = _resolution_states(actual, target, actual["records"])
        if list(expected_resolution) != states:
            mismatches.append(
                "expected_resolution: expected %s, got %s"
                % (list(expected_resolution), states)
            )
    if "expected_container" in expected:
        if not _recursive_subset(expected["expected_container"], actual.get("container")):
            mismatches.append("expected_container: subset mismatch")
    for expected_record in expected.get("records", []):
        if not isinstance(expected_record, dict):
            mismatches.append("records: malformed expected record entry")
            continue
        record_id = expected_record.get("id")
        match = None
        for entry in actual["records"]:
            if entry.get("id") == record_id:
                match = entry
                break
        if match is None:
            mismatches.append("records: no record with id %r" % (record_id,))
            continue
        if not _recursive_subset(expected_record, match):
            mismatches.append("records: subset mismatch for id %r" % (record_id,))
    return mismatches


# ---------------------------------------------------------------------------
# Suite
# ---------------------------------------------------------------------------


def run_vectors(root: Path, *, default_tsa_trust: bytes | None = None) -> dict[str, Any]:
    """Run every case under ``root``; return a deterministic vectors report."""
    if not root.exists() or not root.is_dir():
        raise UsageError("vector suite directory does not exist")
    cases = _discover_cases(root)
    if not cases:
        raise UsageError("no expected.json files found in the vector suite")
    skipper = CheckSkipper.from_env()
    case_results: list[dict[str, Any]] = []
    input_hasher = hashlib.sha256()
    input_hasher.update(b"weave-vectors/1\n")
    input_size = 0
    for case_dir in cases:
        expected_path = case_dir / "expected.json"
        expected_bytes = expected_path.read_bytes()
        input_hasher.update(case_dir.name.encode("utf-8", "surrogatepass"))
        input_hasher.update(b"\0")
        input_hasher.update(hashlib.sha256(expected_bytes).digest())
        input_size += len(expected_bytes)
        try:
            expected = json.loads(expected_bytes.decode("utf-8"))
            if not isinstance(expected, dict):
                raise UsageError("expected.json must be an object")
            suite_root = _find_suite_root(case_dir)
            result = _run_case(case_dir, expected, suite_root, default_tsa_trust, skipper)
        except (UsageError, OSError, ValueError) as error:
            result = {
                "id": case_dir.name,
                "mismatches": ["case error: %s" % error],
                "ok": False,
                "verdict": None,
            }
        case_results.append(result)
    matched = sum(1 for result in case_results if result["ok"])
    total = len(case_results)
    verdict = "valid" if matched == total else "invalid"
    report = report_module.build_report(
        target="vectors",
        verdict=verdict,
        input_sha256="sha256:" + input_hasher.hexdigest(),
        input_size=input_size,
        records=[],
        checks_disabled=skipper.tokens,
        limitations=[],
    )
    # Vectors report summary is case-based (decision #34 / FIX1 §3):
    # {"case_count", "matched", "mismatched"} instead of record-verdict counts.
    report["summary"] = {
        "case_count": total,
        "matched": matched,
        "mismatched": total - matched,
    }
    report["cases"] = case_results
    return report
