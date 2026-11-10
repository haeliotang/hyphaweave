#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0
"""Gate 3: compare the Python and Rust verifier reports case by case.

This is a repository gate tool, not part of the verifier. It runs the two
implementations as black boxes over every conformance case, normalizes only the
`verifier` identity object of §14.6, and then compares the report bytes.

Rules this script implements (H1 workstream contract):

* The Python reference verifier is only executed through its documented command
  line (``python -m hyphaweave_verify.cli`` or an equivalent ``--python-cli``).
  Its source is never read by this script, and the verifier is never imported.
* Neither verifier nor the vectors are modified.
* Gate 3 may only run after the Rust verifier passes every committed vector, so
  the script first runs the Rust ``vectors`` runner over each selected set and
  aborts without touching the Python implementation if that fails.
* The only normalization is §14.6's ``verifier`` member: its ``name`` and
  ``version`` values are replaced in place with the constant ``"normalized"``.
  Every other byte of the report must match, including key order, escaping,
  indentation and the trailing LF.
* A difference may only be accepted through an explicit entry in
  ``gate3_known_differences.json`` (checked into this directory). The script
  exits 0 only when every difference is listed and no listed entry is stale.

Case reproduction follows ``vectors/README.md``: ``expected.json`` carries
``target`` (``record`` or ``container``), ``input`` (relative to the case
directory) and optional ``args`` tokens (``@keyset`` -> the enclosing set's
``keys/keyset`` directory, ``@case`` -> the case directory, other non-flag
tokens -> paths relative to the case directory). The same argv is given to both
implementations.

Exit codes: 0 = every case identical (or every difference allow-listed),
1 = at least one unlisted or stale difference, 2 = gate/environment error.
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parents[3]
ALLOW_LIST_PATH = SCRIPT_PATH.parent / "gate3_known_differences.json"
FROZEN_SET = "vectors/frozen/v0.1-candidate"
CLASSIFICATIONS = (
    "spec-unique-answer-Rust-bug",
    "spec-unique-answer-Python-bug",
    "spec-ambiguous",
)
NORMALIZED_LITERAL = '"normalized"'
FLAGS_WITH_PATH_VALUE = ("--keys", "--tsa-trust", "--previous")
_WS = " \t\r\n"


class GateError(Exception):
    """Fatal gate/environment problem (exit 2)."""


class ScanError(Exception):
    """Internal JSON scanner failure."""


# ---------------------------------------------------------------------------
# In-place normalization of the report's `verifier` identity object
# ---------------------------------------------------------------------------


def _skip_ws(text: str, index: int) -> int:
    length = len(text)
    while index < length and text[index] in _WS:
        index += 1
    return index


def _scan_string(text: str, index: int) -> int:
    """Return the index just past the JSON string starting at ``index``."""
    length = len(text)
    if index >= length or text[index] != '"':
        raise ScanError("expected a string")
    index += 1
    while index < length:
        char = text[index]
        if char == '"':
            return index + 1
        if char == "\\":
            index += 1
            if index >= length:
                raise ScanError("truncated escape")
            escape = text[index]
            if escape == "u":
                if index + 4 >= length:
                    raise ScanError("truncated unicode escape")
                for offset in range(1, 5):
                    if text[index + offset] not in "0123456789abcdefABCDEF":
                        raise ScanError("bad unicode escape")
                index += 5
            elif escape in '"\\/bfnrt':
                index += 1
            else:
                raise ScanError("bad escape")
        elif ord(char) < 0x20:
            raise ScanError("control character in string")
        else:
            index += 1
    raise ScanError("unterminated string")


def _scan_value(text: str, index: int) -> int:
    """Return the index just past the JSON value starting at ``index``."""
    index = _skip_ws(text, index)
    length = len(text)
    if index >= length:
        raise ScanError("truncated value")
    char = text[index]
    if char == '"':
        return _scan_string(text, index)
    if char == "{":
        index += 1
        index = _skip_ws(text, index)
        if index < length and text[index] == "}":
            return index + 1
        while True:
            index = _skip_ws(text, index)
            if index >= length or text[index] != '"':
                raise ScanError("expected an object member name")
            index = _scan_string(text, index)
            index = _skip_ws(text, index)
            if index >= length or text[index] != ":":
                raise ScanError("expected ':'")
            index += 1
            index = _scan_value(text, index)
            index = _skip_ws(text, index)
            if index < length and text[index] == ",":
                index += 1
                continue
            if index < length and text[index] == "}":
                return index + 1
            raise ScanError("expected ',' or '}'")
    if char == "[":
        index += 1
        index = _skip_ws(text, index)
        if index < length and text[index] == "]":
            return index + 1
        while True:
            index = _scan_value(text, index)
            index = _skip_ws(text, index)
            if index < length and text[index] == ",":
                index += 1
                continue
            if index < length and text[index] == "]":
                return index + 1
            raise ScanError("expected ',' or ']'")
    length = len(text)
    start = index
    while index < length and text[index] not in ",]} \t\r\n":
        index += 1
    if index == start:
        raise ScanError("expected a value")
    return index


def _object_members(text: str, index: int) -> tuple[dict[str, tuple[int, int]], int]:
    """Return ``{key: (value_start, value_end)}`` and the object end index."""
    if index >= len(text) or text[index] != "{":
        raise ScanError("expected an object")
    members: dict[str, tuple[int, int]] = {}
    index += 1
    index = _skip_ws(text, index)
    if index < len(text) and text[index] == "}":
        return members, index + 1
    while True:
        index = _skip_ws(text, index)
        if index >= len(text) or text[index] != '"':
            raise ScanError("expected an object member name")
        key_start = index
        key_end = _scan_string(text, index)
        try:
            key = json.loads(text[key_start:key_end])
        except ValueError as error:  # pragma: no cover - guarded by scanner
            raise ScanError(str(error)) from error
        index = _skip_ws(text, key_end)
        if index >= len(text) or text[index] != ":":
            raise ScanError("expected ':'")
        value_start = _skip_ws(text, index + 1)
        value_end = _scan_value(text, value_start)
        if key in members:
            raise ScanError(f"duplicate member {key!r}")
        members[key] = (value_start, value_end)
        index = _skip_ws(text, value_end)
        if index < len(text) and text[index] == ",":
            index += 1
            continue
        if index < len(text) and text[index] == "}":
            return members, index + 1
        raise ScanError("expected ',' or '}'")


def normalize_verifier(raw: bytes) -> tuple[bytes | None, str]:
    """Normalize the report's ``verifier.name``/``verifier.version`` values.

    Only the two values are replaced, in place: every other byte of the report
    is preserved. Returns ``(normalized_bytes, "")`` on success and
    ``(None, reason)`` when the report is not a §14.6 report object with the
    expected identity member.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None, "stdout is not valid UTF-8"
    try:
        index = _skip_ws(text, 0)
        if index >= len(text) or text[index] != "{":
            return None, "stdout is not one JSON object"
        root, root_end = _object_members(text, index)
        if _skip_ws(text, root_end) != len(text):
            return None, "stdout has bytes after the report object"
    except ScanError as error:
        return None, f"stdout is not a parseable JSON object: {error}"
    if "verifier" not in root:
        return None, "report has no top-level 'verifier' member"
    value_start, _ = root["verifier"]
    try:
        verifier_index = _skip_ws(text, value_start)
        if verifier_index >= len(text) or text[verifier_index] != "{":
            return None, "top-level 'verifier' is not an object"
        members, _ = _object_members(text, verifier_index)
    except ScanError as error:
        return None, f"'verifier' is not a parseable object: {error}"
    replacements: list[tuple[int, int]] = []
    for field in ("name", "version"):
        if field not in members:
            return None, f"'verifier' has no {field!r} member"
        start, end = members[field]
        token = _skip_ws(text, start)
        if token >= len(text) or text[token] != '"':
            return None, f"'verifier.{field}' is not a string"
        replacements.append((start, end))
    normalized = text
    for start, end in sorted(replacements, reverse=True):
        normalized = normalized[:start] + NORMALIZED_LITERAL + normalized[end:]
    return normalized.encode("utf-8"), ""


# ---------------------------------------------------------------------------
# Independent check of one report against the case's expected conclusions
# ---------------------------------------------------------------------------


def _as_str_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _report_errors(report: dict) -> set[str]:
    errors: set[str] = set()
    container = report.get("container")
    if isinstance(container, dict):
        errors.update(_as_str_list(container.get("errors")))
    records = report.get("records")
    if isinstance(records, list):
        for record in records:
            if isinstance(record, dict):
                errors.update(_as_str_list(record.get("errors")))
    return errors


def _report_notices(report: dict) -> set[str]:
    notices: set[str] = set()
    container = report.get("container")
    if isinstance(container, dict):
        notices.update(_as_str_list(container.get("notices")))
    records = report.get("records")
    if isinstance(records, list):
        for record in records:
            if isinstance(record, dict):
                notices.update(_as_str_list(record.get("notices")))
    return notices


def _subset_mismatches(expected: object, actual: object, where: str) -> list[str]:
    """vectors/README.md subset match: nested objects recursive, arrays exact."""
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return [f"{where}: expected an object"]
        problems: list[str] = []
        for key, expected_value in expected.items():
            if key not in actual:
                problems.append(f"{where}.{key}: missing in report")
            else:
                problems.extend(
                    _subset_mismatches(expected_value, actual[key], f"{where}.{key}")
                )
        return problems
    if isinstance(expected, list):
        if not isinstance(actual, list) or expected != actual:
            return [f"{where}: expected {expected!r}, got {actual!r}"]
        return []
    if expected != actual:
        return [f"{where}: expected {expected!r}, got {actual!r}"]
    return []


def report_matches_expected(expected: dict, report: dict) -> tuple[bool, list[str]]:
    """Check one implementation report against the case's expected conclusions.

    This mirrors the matching rules documented in ``vectors/README.md``:
    verdict exact, errors as a set over the container and all record errors,
    notices a subset, ``expected_digest``/``expected_resolution``/
    ``expected_container``/``records`` as documented. It is used only to
    classify a byte difference; it never modifies the vectors.
    """
    problems: list[str] = []
    if report.get("verdict") != expected.get("verdict"):
        problems.append(
            f"verdict: expected {expected.get('verdict')!r}, got {report.get('verdict')!r}"
        )
    expected_errors = set(_as_str_list(expected.get("errors")))
    actual_errors = _report_errors(report)
    if actual_errors != expected_errors:
        problems.append(
            f"errors: expected {sorted(expected_errors)!r}, got {sorted(actual_errors)!r}"
        )
    missing_notices = set(_as_str_list(expected.get("notices"))) - _report_notices(report)
    if missing_notices:
        problems.append(f"notices: missing {sorted(missing_notices)!r}")
    records = report.get("records")
    if "expected_digest" in expected:
        if not isinstance(records, list) or not records or not isinstance(records[0], dict):
            problems.append("expected_digest: report has no records[0]")
        elif records[0].get("digest") != expected["expected_digest"]:
            problems.append(
                f"digest: expected {expected['expected_digest']!r}, "
                f"got {records[0].get('digest')!r}"
            )
    if "expected_resolution" in expected:
        expected_resolution = expected["expected_resolution"]
        if not isinstance(expected_resolution, dict):
            problems.append("expected_resolution: case expectation is not an object")
        else:
            refs: list = []
            if isinstance(records, list) and records and isinstance(records[0], dict):
                candidate_refs = records[0].get("refs")
                if isinstance(candidate_refs, list):
                    refs = candidate_refs
            actual_resolution: dict[str, str] = {}
            for ref in refs:
                if isinstance(ref, dict) and "index" in ref:
                    actual_resolution[str(ref["index"])] = ref.get("state")
            for index, state in expected_resolution.items():
                if actual_resolution.get(str(index)) != state:
                    problems.append(
                        f"refs[{index}]: expected {state!r}, "
                        f"got {actual_resolution.get(str(index))!r}"
                    )
    if "expected_container" in expected:
        problems.extend(
            _subset_mismatches(expected["expected_container"], report.get("container"), "container")
        )
    if "records" in expected:
        expected_records = expected["records"]
        if not isinstance(expected_records, list):
            problems.append("records: case expectation is not an array")
        else:
            actual_records = records if isinstance(records, list) else []
            by_id = {
                record.get("id"): record
                for record in actual_records
                if isinstance(record, dict)
            }
            for expected_record in expected_records:
                if not isinstance(expected_record, dict):
                    problems.append("records: case expectation entry is not an object")
                    continue
                record_id = expected_record.get("id")
                actual_record = by_id.get(record_id)
                if actual_record is None:
                    problems.append(f"records[{record_id!r}]: missing in report")
                else:
                    problems.extend(
                        _subset_mismatches(expected_record, actual_record, f"records[{record_id!r}]")
                    )
    return not problems, problems


def _parse_report(raw: bytes) -> dict | None:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


# ---------------------------------------------------------------------------
# Case discovery and argv reproduction
# ---------------------------------------------------------------------------


class Case:
    """One conformance case."""

    def __init__(self, set_name: str, set_root: Path, case_dir: Path, expected: dict):
        self.set_name = set_name
        self.set_root = set_root
        self.case_dir = case_dir
        self.expected = expected
        self.case_id = str(expected.get("id", case_dir.parent.name + "/" + case_dir.name))

    def __repr__(self) -> str:
        return f"Case({self.set_name}:{self.case_id})"


def discover_cases(set_name: str, set_root: Path) -> list[Case]:
    cases: list[Case] = []
    for expected_path in sorted(set_root.glob("*/*/expected.json")):
        try:
            expected = json.loads(expected_path.read_bytes().decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as error:
            raise GateError(f"{expected_path}: not parseable JSON: {error}") from error
        if not isinstance(expected, dict):
            raise GateError(f"{expected_path}: expected.json is not an object")
        cases.append(Case(set_name, set_root, expected_path.parent, expected))
    if not cases:
        raise GateError(f"{set_root}: no <category>/<case>/expected.json cases found")
    cases.sort(key=lambda case: (case.set_name, case.case_id))
    return cases


def find_keyset(set_root: Path) -> Path:
    directory = set_root.resolve()
    while True:
        candidate = directory / "keys" / "keyset"
        if candidate.is_dir():
            return candidate
        if directory.parent == directory:
            raise GateError(
                f"cannot locate keys/keyset by walking up from {set_root}; "
                "check the vectors layout"
            )
        directory = directory.parent


def reproduce_argv(case: Case) -> list[str]:
    """Reproduce the case's documented verifier arguments (§vectors/README.md)."""
    target = case.expected.get("target")
    if target not in ("record", "container"):
        raise GateError(f"{case.case_id}: unsupported target {target!r}")
    input_rel = case.expected.get("input")
    if not isinstance(input_rel, str):
        raise GateError(f"{case.case_id}: expected.json has no string 'input'")
    input_path = case.case_dir / input_rel
    if not input_path.exists():
        raise GateError(f"{case.case_id}: input {input_path} does not exist")
    keyset = find_keyset(case.set_root)
    argv = [target, str(input_path)]
    tokens = case.expected.get("args", [])
    if not isinstance(tokens, list):
        raise GateError(f"{case.case_id}: 'args' is not an array")
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not isinstance(token, str):
            raise GateError(f"{case.case_id}: non-string token in 'args'")
        if token in FLAGS_WITH_PATH_VALUE:
            argv.append(token)
            index += 1
            if index >= len(tokens):
                raise GateError(f"{case.case_id}: {token} has no value")
            value = tokens[index]
            if value == "@keyset":
                argv.append(str(keyset))
            elif value == "@case":
                argv.append(str(case.case_dir))
            else:
                value_path = Path(value)
                argv.append(str(value_path if value_path.is_absolute() else case.case_dir / value))
        elif token == "@keyset":
            argv.append(str(keyset))
        elif token == "@case":
            argv.append(str(case.case_dir))
        elif token.startswith("-"):
            argv.append(token)
        else:
            argv.append(str(case.case_dir / token))
        index += 1
    return argv


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------


def _child_env() -> dict[str, str]:
    env = dict(os.environ)
    # The test-only ablation hook must not influence a comparison run.
    env.pop("WEAVE_VERIFY_SKIP_CHECKS", None)
    # Do not leave __pycache__ directories in the checkout.
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def run_process(command: list[str], timeout: float) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            command,
            cwd=str(REPO_ROOT),
            env=_child_env(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as error:
        raise GateError(f"cannot execute {command[0]!r}: {error}") from error
    except OSError as error:
        raise GateError(f"cannot execute {command[0]!r}: {error}") from error
    except subprocess.TimeoutExpired as error:
        raise GateError(
            f"{command[0]!r} timed out after {timeout:g}s on {' '.join(command)}"
        ) from error


def first_line(data: bytes) -> str:
    text = data.decode("utf-8", "replace").strip()
    if not text:
        return ""
    line = text.splitlines()[0]
    return line if len(line) <= 400 else line[:397] + "..."


def _executable(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


def find_rust_binary(override: str | None) -> Path:
    if override:
        path = Path(override)
        if not path.is_absolute():
            path = (REPO_ROOT / path).resolve()
        if not _executable(path):
            raise GateError(f"Rust verifier binary is not executable: {path}")
        return path
    candidates = [
        REPO_ROOT / "verifiers/rust/target/debug/hyphaweave-verify-rs",
        REPO_ROOT / "target/debug/hyphaweave-verify-rs",
        REPO_ROOT / "verifiers/rust/target/release/hyphaweave-verify-rs",
    ]
    for candidate in candidates:
        if _executable(candidate):
            return candidate
    raise GateError(
        "Rust verifier binary not found; build it first with\n"
        "    cargo build --manifest-path verifiers/rust/Cargo.toml\n"
        "or pass --rust-binary <path>"
    )


def resolve_python_command(override: str | None) -> list[str]:
    """Return the complete Python black-box command prefix.

    The prefix is followed directly by the verifier argv, so it must already
    select the verifier CLI. The default is ``<python> -m hyphaweave_verify.cli``
    using the checkout's virtual environment when present.
    """
    if override:
        command = shlex.split(override)
        if not command:
            raise GateError("--python-cli is empty")
        return command
    environment_python = REPO_ROOT / ".venv" / "bin" / "python"
    python = str(environment_python) if _executable(environment_python) else sys.executable
    return [python, "-m", "hyphaweave_verify.cli"]


# ---------------------------------------------------------------------------
# Allow list
# ---------------------------------------------------------------------------


def load_allow_list(path: Path) -> list[dict]:
    if not path.is_file():
        raise GateError(f"allow-list file not found: {path}")
    try:
        document = json.loads(path.read_bytes().decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise GateError(f"{path}: not parseable JSON: {error}") from error
    if not isinstance(document, dict) or not isinstance(document.get("allowed_differences"), list):
        raise GateError(f"{path}: expected an object with an 'allowed_differences' array")
    entries: list[dict] = []
    seen: set[str] = set()
    for entry in document["allowed_differences"]:
        if not isinstance(entry, dict):
            raise GateError(f"{path}: allow-list entry is not an object: {entry!r}")
        case_id = entry.get("case")
        reason = entry.get("reason")
        if not isinstance(case_id, str) or not case_id:
            raise GateError(f"{path}: allow-list entry has no string 'case'")
        if not isinstance(reason, str) or not reason.strip():
            raise GateError(f"{path}: allow-list entry for {case_id} has no 'reason'")
        classification = entry.get("classification")
        if classification is not None and classification not in CLASSIFICATIONS:
            raise GateError(
                f"{path}: allow-list entry for {case_id} has unknown classification "
                f"{classification!r}; expected one of {list(CLASSIFICATIONS)}"
            )
        if case_id in seen:
            raise GateError(f"{path}: duplicate allow-list entry for {case_id}")
        seen.add(case_id)
        entries.append(entry)
    return entries


# ---------------------------------------------------------------------------
# Diff rendering
# ---------------------------------------------------------------------------


def render_diff(python_raw: bytes, rust_raw: bytes, limit: int) -> list[str]:
    python_text = python_raw.decode("utf-8", "replace").splitlines(keepends=True)
    rust_text = rust_raw.decode("utf-8", "replace").splitlines(keepends=True)
    diff = difflib.unified_diff(
        python_text,
        rust_text,
        fromfile="python (normalized)",
        tofile="rust (normalized)",
        n=1,
    )
    lines: list[str] = []
    for line in diff:
        lines.append(line.rstrip("\n"))
        if len(lines) >= limit:
            lines.append("    ... diff truncated")
            break
    return lines


def describe_abnormal(result: subprocess.CompletedProcess) -> str:
    if result.stdout:
        return f"exit {result.returncode}"
    stderr = first_line(result.stderr)
    return f"exit {result.returncode}, no report on stdout" + (f"; stderr: {stderr}" if stderr else "")


# ---------------------------------------------------------------------------
# Main gate
# ---------------------------------------------------------------------------


def parse_arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Gate 3: compare Python and Rust verifier report bytes case by case.",
    )
    parser.add_argument(
        "--vectors",
        action="append",
        default=None,
        metavar="DIR",
        help="vectors set root(s) to compare (default: vectors/); repeatable",
    )
    parser.add_argument(
        "--include-frozen",
        action="store_true",
        help=f"also compare the candidate regression set {FROZEN_SET}/",
    )
    parser.add_argument(
        "--case",
        action="append",
        default=None,
        metavar="ID",
        help="only compare the case(s) with this id; repeatable (debugging aid)",
    )
    parser.add_argument(
        "--rust-binary",
        default=None,
        help="path to the Rust verifier binary (default: auto-detect the cargo target)",
    )
    parser.add_argument(
        "--python-cli",
        default=None,
        metavar="COMMAND",
        help=(
            "Python black-box command prefix (default: .venv/bin/python when present, "
            "otherwise the running interpreter; the script appends "
            "`-m hyphaweave_verify.cli`)"
        ),
    )
    parser.add_argument(
        "--allow-list",
        default=str(ALLOW_LIST_PATH),
        help=f"known-differences allow list (default: {ALLOW_LIST_PATH.name})",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=180.0,
        metavar="SECONDS",
        help="per-process timeout (default: 180)",
    )
    parser.add_argument(
        "--max-diff-lines",
        type=int,
        default=24,
        help="maximum diff lines printed per differing case (default: 24)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="print one line for every identical case",
    )
    return parser.parse_args(argv)


def selected_sets(arguments: argparse.Namespace) -> list[tuple[str, Path]]:
    if arguments.vectors:
        roots = [Path(item) for item in arguments.vectors]
    else:
        roots = [REPO_ROOT / "vectors"]
    if arguments.include_frozen:
        roots.append(REPO_ROOT / FROZEN_SET)
    selected: list[tuple[str, Path]] = []
    seen: set[Path] = set()
    for root in roots:
        path = root if root.is_absolute() else (REPO_ROOT / root)
        path = path.resolve()
        if path in seen:
            continue
        seen.add(path)
        if not path.is_dir():
            raise GateError(f"vectors set does not exist: {path}")
        name = path.name
        if path == (REPO_ROOT / "vectors").resolve():
            name = "vectors"
        selected.append((name, path))
    return selected


def run_rust_vectors_preflight(
    rust_binary: Path, sets: list[tuple[str, Path]], timeout: float
) -> None:
    """Gate ordering rule: the Rust verifier must pass every vector first."""
    for set_name, set_root in sets:
        result = run_process([str(rust_binary), "vectors", str(set_root)], timeout)
        if result.returncode != 0:
            report_tail = first_line(result.stdout)
            stderr_tail = first_line(result.stderr)
            raise GateError(
                "refusing to run the Python black box: the Rust verifier does not pass "
                f"its own vectors for {set_name} ({set_root}): "
                f"exit {result.returncode}"
                + (f"; stdout: {report_tail}" if report_tail else "")
                + (f"; stderr: {stderr_tail}" if stderr_tail else "")
            )
        print(f"  Rust vectors preflight: {set_name} OK")


def main(argv: list[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    sets = selected_sets(arguments)
    rust_binary = find_rust_binary(arguments.rust_binary)
    python_command = resolve_python_command(arguments.python_cli)
    allow_entries = load_allow_list(Path(arguments.allow_list))

    cases: list[Case] = []
    for set_name, set_root in sets:
        cases.extend(discover_cases(set_name, set_root))
    if arguments.case:
        wanted = set(arguments.case)
        unknown = wanted - {case.case_id for case in cases}
        if unknown:
            raise GateError(f"--case id(s) not found in the selected sets: {sorted(unknown)}")
        cases = [case for case in cases if case.case_id in wanted]
        # A focused debugging run compares a subset: allow-list entries for
        # cases outside the selection are simply not part of this run.
        compared_ids = {case.case_id for case in cases}
        allow_entries = [entry for entry in allow_entries if entry["case"] in compared_ids]
    if not cases:
        raise GateError("no cases selected")
    allow_cases = {entry["case"] for entry in allow_entries}

    print("Gate 3: Python reference verifier vs Rust verifier (report bytes)")
    print(f"  Rust binary: {rust_binary}")
    print(f"  Python CLI:  {' '.join(python_command)}")
    print(f"  Sets:        {', '.join(name for name, _ in sets)}")
    print(f"  Cases:       {len(cases)}")

    # Ordering rule: never run the Python black box before the Rust verifier
    # has passed every vector of the selected sets.
    run_rust_vectors_preflight(rust_binary, sets, arguments.timeout)
    version_probe = run_process(python_command + ["--version"], arguments.timeout)
    if version_probe.returncode != 0:
        raise GateError(
            f"the Python black-box command is not usable (exit "
            f"{version_probe.returncode}): {' '.join(python_command)} --version"
            + (
                f"; stderr: {first_line(version_probe.stderr)}"
                if version_probe.stderr
                else ""
            )
            + "; install the reference verifier with "
            "`python -m pip install -e verifiers/python` or pass --python-cli"
        )

    identical = 0
    differences: list[tuple[Case, list[str], str]] = []
    classification_counts = {name: 0 for name in CLASSIFICATIONS}
    for case in cases:
        case_argv = reproduce_argv(case)
        python_result = run_process(python_command + case_argv, arguments.timeout)
        rust_result = run_process([str(rust_binary)] + case_argv, arguments.timeout)
        python_normalized, python_problem = normalize_verifier(python_result.stdout)
        rust_normalized, rust_problem = normalize_verifier(rust_result.stdout)
        same_bytes = (
            python_normalized is not None
            and rust_normalized is not None
            and python_normalized == rust_normalized
        )
        same_exit = python_result.returncode == rust_result.returncode
        if same_bytes and same_exit:
            identical += 1
            if arguments.verbose:
                print(f"  IDENTICAL {case.case_id}")
            continue

        python_report = _parse_report(python_result.stdout)
        rust_report = _parse_report(rust_result.stdout)
        if python_report is not None and rust_report is not None:
            python_matches, python_problems = report_matches_expected(case.expected, python_report)
            rust_matches, rust_problems = report_matches_expected(case.expected, rust_report)
        else:
            python_matches = rust_matches = False
            python_problems = ["no parseable report"]
            rust_problems = ["no parseable report"]
        if python_matches and not rust_matches:
            classification = "spec-unique-answer-Rust-bug"
            detail = "; ".join(rust_problems[:3])
        elif rust_matches and not python_matches:
            classification = "spec-unique-answer-Python-bug"
            detail = "; ".join(python_problems[:3])
        elif python_matches and rust_matches:
            classification = "spec-ambiguous"
            detail = "both reports match expected.json; difference is outside the vector conclusions"
        else:
            classification = "spec-ambiguous"
            detail = (
                "neither report matches expected.json "
                f"(python: {'; '.join(python_problems[:2]) or 'no parseable report'}; "
                f"rust: {'; '.join(rust_problems[:2]) or 'no parseable report'})"
            )
        classification_counts[classification] += 1
        notes: list[str] = []
        if python_normalized is None:
            notes.append(f"python: {python_problem} ({describe_abnormal(python_result)})")
        if rust_normalized is None:
            notes.append(f"rust: {rust_problem} ({describe_abnormal(rust_result)})")
        if same_bytes and not same_exit:
            notes.append(
                f"identical report bytes but different exit codes "
                f"(python {python_result.returncode}, rust {rust_result.returncode})"
            )
        if python_normalized is not None and rust_normalized is not None:
            notes.extend(
                "  " + line
                for line in render_diff(python_normalized, rust_normalized, arguments.max_diff_lines)
            )
        differences.append((case, notes, classification))
        print(f"DIFFERENT {case.case_id} [{classification}] {detail}")
        for note in notes:
            print(f"    {note}")

    differing_cases = [case.case_id for case, _, _ in differences]
    gate_problems: list[str] = []
    unlisted = [case_id for case_id in differing_cases if case_id not in allow_cases]
    if unlisted:
        gate_problems.append(f"difference(s) not in the allow list: {', '.join(unlisted)}")
    discovered_ids = {case.case_id for case in cases}
    unknown_allowed = sorted(allow_cases - discovered_ids)
    if unknown_allowed:
        gate_problems.append(
            f"allow-list entr(y/ies) name case(s) not among the compared cases: "
            f"{', '.join(unknown_allowed)}"
        )
    stale_allowed = sorted((allow_cases & discovered_ids) - set(differing_cases))
    if stale_allowed:
        gate_problems.append(
            f"allow-list entr(y/ies) are stale (case reports now identical): "
            f"{', '.join(stale_allowed)}"
        )
    if identical != len(cases) - len(allow_cases & discovered_ids):
        gate_problems.append(
            "identical count does not match total-minus-allowlisted: "
            f"total={len(cases)} identical={identical} allowlisted={len(allow_cases & discovered_ids)}"
        )

    print("")
    if classification_counts:
        print(
            "  Differences by classification: "
            + ", ".join(f"{name}={count}" for name, count in classification_counts.items())
        )
    print(
        f"Gate 3 summary: total={len(cases)} identical={identical} "
        f"differing={len(differences)} allowlisted={len(allow_entries)}"
    )
    if gate_problems:
        print("Gate 3 result: FAIL")
        for problem in gate_problems:
            print(f"  - {problem}")
        return 1
    if differences:
        print(
            "Gate 3 result: PASS (all differing cases are allow-listed; "
            "every other report is byte-identical after verifier normalization)"
        )
    else:
        print("Gate 3 result: PASS (every report byte-identical after verifier normalization)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except GateError as error:
        print(f"gate3: error: {error}", file=sys.stderr)
        sys.exit(2)
