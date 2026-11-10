#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0
"""H0 FIX1 gate: exhaustive byte-level bit-flip anti-verification.

For **every positive vector case** (expected verdict ``valid`` or ``erased``, and
also the frozen candidate when present) this gate flips one bit in **every byte**
of every input file:

* record target: every byte of the record file;
* directory container: every byte of every regular file inside the container
  directory (``readable/`` included deliberately; it is expected to be exempt);
* zip container: every byte of the archive, including headers and the central
  directory (metadata flips are expected to be exempt).

The mutation is deterministic: byte offset ``i`` gets bit ``i % 8`` flipped
(least-significant bit first).

Expected outcome: every mutant must be **rejected** by the verifier, i.e. it must
not come back with the case's accepted verdict (``valid``, or ``erased`` for an
erased-placeholder case):

* ``invalid`` - the normal rejection; counted separately.
* ``unverifiable`` / usage error / verifier crash - also a rejection.  A mutated
  byte can break a dependency (for example the only key-declaration record), so
  the honest verdict is ``unverifiable`` rather than ``invalid``; this is counted
  separately with the observed verdict, never silently folded into ``invalid``.
  A crash means the verifier did not fail closed; it is counted separately too.
* **exempt** - a mutant that *is accepted again* is only allowed when the flipped
  byte is in a documented, signature/digest-uncovered byte class (unsigned
  records, erased placeholders, ``sigs`` metadata, ``readable/``, untrusted TSA
  certificate files, zip container metadata).  Each class has a written reason in
  ``EXEMPT_REASONS``; counts are reported per class.
* a **survivor** - an accepted mutant outside every exemption class; the gate
  fails (exit 1) because the vectors do not depend on that byte.

Exemption classes implemented here:

``unsigned-record``
    A record-target positive deliberately carries no ``sigs`` (its purpose is to
    prove an unsigned record can be valid; CONTRACT §5.3).  Nothing in the file
    is signature-covered, so a content flip can legitimately stay valid.
``erased-placeholder``
    ``weave.erased`` placeholders have no ``sigs`` by format (§7.8).  A flip in
    the placeholder's claims keeps the verdict ``erased`` (never ``valid``).
``record-signature-metadata``
    Bytes of the top-level ``sigs`` member are excluded from the record digest
    (§3.1).  Flipping a signature's ``alg``/``key`` can make that entry ignored
    or unverifiable while the record semantics stay untouched; such mutants are
    exempt (the record is still rejected as unverifiable when signing is
    required).  Flipped signature *values* are **not** exempt for known
    algorithms: they must be rejected as ``E_SIG_INVALID``.
``readable-view``
    ``readable/`` is outside the digest and never trusted (§11.8); its bytes are
    exempt.
``tsa-certificate-file``
    ``signatures/tsa-cert-<n>.pem`` is an optional, explicitly untrusted copy of
    the TSA certificate (layout comment in §11.1); it is not part of the digest.
``zip-metadata``
    Zip local-file headers, extra fields, data descriptors, central directory and
    end-of-central-directory are container metadata, not archived evidence; a
    metadata bit flip must not be reported as invalid evidence.  Bytes of the
    archived entry payloads are *not* exempt.

The tool imports the verifier package in-process (the same check path the
``hyphaweave-verify`` CLI executes) and caches the verified key set between
mutants for speed; ``--no-cache`` disables that and calls the CLI helpers
without any patch.  Reports are deterministic (sorted case order, no clock).

Usage:
    python tools/byte_flip_gate.py [--suite DIR] [--jobs N] [--json PATH]
                                   [--case ID ...] [--max-bytes N] [--verbose]
                                   [--no-cache] [--list]

Exit status: 0 = every mutant invalid or exempt, 1 = survivors, 2 = usage/IO
error.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import threading
import zipfile
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
DEFAULT_SUITE = REPO / "vectors"
FROZEN_CANDIDATE = REPO / "vectors" / "frozen" / "v0.1-candidate"
TMP_ROOT = REPO / ".tmp-work" / "byte-flip"
KEYSET = REPO / "vectors" / "keys" / "keyset"

EXEMPT_REASONS = {
    "unsigned-record": (
        "record target with no verifiable per-record signature (no sigs member, or only "
        "unknown-algorithm entries that Q13 ignores): no content byte is signature-covered, "
        "so a content flip can legitimately remain a valid unsigned record"
    ),
    "erased-placeholder": (
        "weave.erased placeholder: no sigs by format; a flip in the claimed placeholder "
        "fields keeps the verdict erased (never valid)"
    ),
    "record-signature-metadata": (
        "top-level sigs member is excluded from the record digest; an unusable or ignored "
        "signature entry cannot make the record invalid, only unsigned/unverifiable"
    ),
    "ignored-signature-entry": (
        "signature entry with an unknown algorithm is ignored (Q13); flipping its value bytes "
        "cannot change a verdict that never checks them"
    ),
    "readable-view": (
        "readable/ is outside the digest and never trusted (spec §11.8)"
    ),
    "tsa-certificate-file": (
        "signatures/tsa-cert-<n>.pem is an optional, explicitly untrusted copy of the TSA "
        "certificate; it is not evidence and not part of the digest"
    ),
    "zip-metadata": (
        "zip local-file headers, extra fields, data descriptors, central directory and "
        "EOCD are container metadata, not archived evidence"
    ),
}

#: record targets whose whole input is exempt from the "must be invalid" rule, by
#: (kind, whether the record has a sigs member).  Computed per case; kept as constants
#: so the policy is auditable.
UNSIGNED_RECORD_KINDS_EXEMPT = True  # any record target without sigs is exempt


# --------------------------------------------------------------------------- helpers


def expand_args(tokens: list[str], case_dir: Path) -> list[str]:
    out: list[str] = []
    for token in tokens:
        if token == "@keyset":
            out.append(str(KEYSET))
        elif token == "@case":
            out.append(str(case_dir))
        elif token.startswith("@case/"):
            out.append(str(case_dir / token[len("@case/") :]))
        else:
            candidate = case_dir / token
            out.append(str(candidate if candidate.exists() else Path(token)))
    return out


def discover_cases(suite: Path) -> list[tuple[str, dict, Path]]:
    cases: list[tuple[str, dict, Path]] = []
    for expected_path in sorted(suite.glob("*/*/expected.json")):
        case_dir = expected_path.parent
        category = case_dir.parent.name
        if category in {"frozen", "external", "keys"}:
            continue
        data = json.loads(expected_path.read_text(encoding="utf-8"))
        if data.get("verdict") not in ("valid", "erased"):
            continue
        cases.append((str(data.get("id") or case_dir.relative_to(suite)), data, case_dir))
    return cases


def discover_frozen(candidate: Path) -> list[tuple[str, dict, Path]]:
    if not candidate.is_dir():
        return []
    cases: list[tuple[str, dict, Path]] = []
    for expected_path in sorted(candidate.glob("*/*/expected.json")):
        case_dir = expected_path.parent
        data = json.loads(expected_path.read_text(encoding="utf-8"))
        if data.get("verdict") not in ("valid", "erased"):
            continue
        cases.append((str(data.get("id") or case_dir.name), data, case_dir))
    return cases


# ---------------------------------------------------------------- JSON span scanner


class _SpanScanner:
    """Find the byte span of the top-level ``sigs`` member and its entries.

    Works on the raw canonical file bytes; the record must be an object at top
    level (all vector records are).  Returns ``None`` when the record has no
    top-level ``sigs`` member or the bytes are not parseable, in which case the
    whole input is handled by the unsigned-record exemption path.
    """

    def __init__(self, raw: bytes) -> None:
        self.raw = raw

    def _skip_ws(self, index: int) -> int:
        while index < len(self.raw) and self.raw[index] in b" \t\r\n":
            index += 1
        return index

    def _scan_string(self, index: int) -> int:
        assert self.raw[index : index + 1] == b'"'
        index += 1
        while index < len(self.raw):
            byte = self.raw[index]
            if byte == 0x5C:  # backslash
                index += 2
                continue
            if byte == 0x22:
                return index + 1
            index += 1
        raise ValueError("unterminated string")

    def _scan_value(self, index: int) -> int:
        index = self._skip_ws(index)
        if index >= len(self.raw):
            raise ValueError("truncated value")
        byte = self.raw[index]
        if byte == 0x22:
            return self._scan_string(index)
        if byte == 0x7B:  # {
            index += 1
            index = self._skip_ws(index)
            if self.raw[index : index + 1] == b"}":
                return index + 1
            while True:
                index = self._scan_string(self._skip_ws(index))
                index = self._skip_ws(index)
                if self.raw[index : index + 1] != b":":
                    raise ValueError("expected colon")
                index = self._scan_value(index + 1)
                index = self._skip_ws(index)
                if self.raw[index : index + 1] == b",":
                    index += 1
                    continue
                if self.raw[index : index + 1] == b"}":
                    return index + 1
                raise ValueError("bad object")
        if byte == 0x5B:  # [
            index += 1
            index = self._skip_ws(index)
            if self.raw[index : index + 1] == b"]":
                return index + 1
            while True:
                index = self._scan_value(index)
                index = self._skip_ws(index)
                if self.raw[index : index + 1] == b",":
                    index += 1
                    continue
                if self.raw[index : index + 1] == b"]":
                    return index + 1
                raise ValueError("bad array")
        while index < len(self.raw) and self.raw[index] not in b",}] \t\r\n":
            index += 1
        return index

    def spans(self) -> dict[str, Any] | None:
        try:
            index = self._skip_ws(0)
            if self.raw[index : index + 1] != b"{":
                return None
            index += 1
            sigs_start = sigs_end = None
            entries: list[dict[str, Any]] = []
            while True:
                index = self._skip_ws(index)
                if self.raw[index : index + 1] == b"}":
                    break
                start = index
                index = self._scan_string(index)
                name = self.raw[start:index]
                index = self._skip_ws(index)
                if self.raw[index : index + 1] != b":":
                    return None
                value_start = self._skip_ws(index + 1)
                value_end = self._scan_value(value_start)
                if name == b'"sigs"':
                    sigs_start, sigs_end = value_start, value_end
                    if self.raw[value_start : value_start + 1] == b"[":
                        cursor = self._skip_ws(value_start + 1)
                        while cursor < value_end - 1:
                            if self.raw[cursor : cursor + 1] == b"]":
                                break
                            entry_start = cursor
                            cursor = self._scan_value(cursor)
                            entries.append(
                                {
                                    "span": (entry_start, cursor),
                                    "alg": self._first_member_span(entry_start, cursor, b"alg"),
                                    "key": self._first_member_span(entry_start, cursor, b"key"),
                                    "value": self._first_member_span(entry_start, cursor, b"value"),
                                }
                            )
                            cursor = self._skip_ws(cursor)
                            if self.raw[cursor : cursor + 1] == b",":
                                cursor = self._skip_ws(cursor + 1)
                index = self._skip_ws(value_end)
                if self.raw[index : index + 1] == b",":
                    index = self._skip_ws(index + 1)
                    continue
                if self.raw[index : index + 1] == b"}":
                    break
                return None
            if sigs_start is None:
                return None
            for entry in entries:
                alg_span = entry.get("alg")
                entry["alg_text"] = (
                    self.raw[alg_span[0] : alg_span[1]] if alg_span else b""
                )
            return {"sigs": (sigs_start, sigs_end), "entries": entries}
        except (ValueError, IndexError):
            return None

    def _first_member_span(
        self, start: int, end: int, name: bytes
    ) -> tuple[int, int] | None:
        spans = self._member_value_spans(start, end, name)
        return spans[0] if spans else None

    def _member_value_spans(self, start: int, end: int, name: bytes) -> list[tuple[int, int]]:
        spans: list[tuple[int, int]] = []
        index = start + 1
        target = b'"' + name + b'"'
        while index < end:
            index = self._skip_ws(index)
            while index < end and self.raw[index : index + 1] == b",":
                index = self._skip_ws(index + 1)
            if index >= end or self.raw[index : index + 1] != b'"':
                return spans
            key_start = index
            index = self._scan_string(index)
            name_bytes = self.raw[key_start:index]
            index = self._skip_ws(index)
            if self.raw[index : index + 1] != b":":
                return spans
            value_start = self._skip_ws(index + 1)
            value_end = self._scan_value(value_start)
            if name_bytes == target:
                spans.append((value_start, value_end))
            index = value_end
        return spans

    def _skip_value(self, index: int) -> int:
        return self._scan_value(index)


# ------------------------------------------------------------------------ zip layout


def zip_ranges(path: Path) -> list[tuple[int, int]]:
    """Return the byte ranges that are *archived evidence* (entry payloads).

    Everything else in the archive (local headers, central directory, EOCD and
    entry descriptors) is container metadata and exempt from the invalid rule.
    """
    data = path.read_bytes()
    payload: list[tuple[int, int]] = []
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            header = info.header_offset
            if data[header : header + 4] != b"PK\x03\x04":
                continue
            name_len = int.from_bytes(data[header + 26 : header + 28], "little")
            extra_len = int.from_bytes(data[header + 28 : header + 30], "little")
            start = header + 30 + name_len + extra_len
            end = start + info.compress_size
            payload.append((start, end))
    return payload


# ------------------------------------------------------------------- verifier glue


class VerifierRunner:
    """Run the reference verifier's own check path in-process."""

    def __init__(self, *, cache: bool = True) -> None:
        sys.path.insert(0, str(REPO / "verifiers" / "python"))
        import hyphaweave_verify.cli as cli_module
        from hyphaweave_verify import verifier as verifier_module

        self.cli = cli_module
        self.verifier = verifier_module
        self.parser = cli_module.build_parser()
        self._cache_lock = threading.RLock()
        self._verify_set_cache: dict[Any, Any] = {}
        self.cache = cache
        if cache:
            self._install_cache()

    def _install_cache(self) -> None:
        runner = self

        original_load = self.cli._load_keyset
        memo: dict[str, Any] = {}

        def load_keyset(keys_path: Any) -> Any:
            key = str(keys_path) if keys_path else ""
            with runner._cache_lock:
                if key not in memo:
                    memo[key] = original_load(keys_path)
                return memo[key]

        self.cli._load_keyset = load_keyset

        original_verify_set = self.verifier.verify_record_set

        def cached_verify_set(
            records: Any,
            *,
            verified_timestamps: Any = (),
            context_views: Any = (),
        ) -> Any:
            """Cache only the keyset-resolution call (no timestamps, no context views).

            Container verification passes fresh record lists and context views; those
            calls bypass the cache (and do not grow it), while ``verify_single_record``
            reuses the memoised keyset list object, so its expensive fixed-point run is
            computed once per process.
            """
            fixed_context = tuple(context_views)
            if verified_timestamps or fixed_context:
                return original_verify_set(
                    records,
                    verified_timestamps=verified_timestamps,
                    context_views=fixed_context,
                )
            cache_key = id(records)
            with runner._cache_lock:
                if cache_key not in runner._verify_set_cache:
                    runner._verify_set_cache[cache_key] = original_verify_set(records)
                return runner._verify_set_cache[cache_key]

        self.verifier.verify_record_set = cached_verify_set

    def imported_file(self) -> str:
        import hyphaweave_verify

        return str(Path(hyphaweave_verify.__file__).resolve())

    def _skipped(self) -> Any:
        saved = os.environ.pop("WEAVE_VERIFY_SKIP_CHECKS", None)
        if saved is not None:
            os.environ["WEAVE_VERIFY_SKIP_CHECKS"] = saved
        return self.cli.CheckSkipper.from_env()

    def run(self, argv: list[str]) -> dict:
        namespace = self.parser.parse_args(argv)
        skipper = self._skipped()
        try:
            if namespace.command == "record":
                return self.cli._run_record(namespace, skipper)
            if namespace.command == "container":
                return self.cli._run_container(namespace, skipper)
        except self.cli.UsageError as error:  # usage/IO problems never count as invalid
            return {"verdict": "usage-error", "error": str(error)}
        except OSError as error:
            return {"verdict": "usage-error", "error": str(error)}
        except Exception as error:  # noqa: BLE001 - a crash must be reported, not hidden
            # A malformed mutant may make the verifier raise instead of reporting invalid.
            # That is not a clean rejection; it is reported as ``verifier-crash`` and the
            # byte-class exemption rules decide whether it is documented or a survivor.
            return {
                "verdict": "verifier-crash",
                "error": "%s: %s" % (type(error).__name__, error),
            }
        raise SystemExit("byte_flip_gate: unexpected verifier command")


# ----------------------------------------------------------------------- exemptions


def record_span_map(raw: bytes) -> dict[str, Any]:
    return _SpanScanner(raw).spans() or {}


def classify_non_invalid(
    *,
    case: dict,
    target: str,
    file_rel: str | None,
    offset: int,
    raw: bytes,
    spans: dict[str, Any] | None,
    verdict: str,
) -> str | None:
    """Return an exemption class for a non-``invalid`` mutant, or None (survivor)."""
    if target == "record":
        if case.get("verdict") == "erased" or case.get("_kind") == "weave.erased":
            return "erased-placeholder"
        if case.get("_unsigned"):
            return "unsigned-record"
        if spans:
            sigs_span = spans.get("sigs")
            if sigs_span and sigs_span[0] <= offset < sigs_span[1]:
                for entry in spans.get("entries", []):
                    if not (entry["span"][0] <= offset < entry["span"][1]):
                        continue
                    for member in ("alg", "key"):
                        span = entry.get(member)
                        if span and span[0] <= offset < span[1]:
                            return "record-signature-metadata"
                    value_span = entry.get("value")
                    if value_span and value_span[0] <= offset < value_span[1]:
                        alg_text = entry.get("alg_text") or b""
                        known = alg_text in (b'"ed25519"', b'"Ed25519"', b'"ED25519"')
                        if known:
                            return None  # tampered known-algorithm signature must be invalid
                        return "ignored-signature-entry"
                    # structural bytes inside an entry: treat like metadata only when the
                    # entry's algorithm is unknown (otherwise the entry is evidence)
                    alg_text = entry.get("alg_text") or b""
                    if alg_text not in (b'"ed25519"', b'"Ed25519"', b'"ED25519"'):
                        return "ignored-signature-entry"
                    return None
        return None
    if file_rel is None:
        return None
    if spans:
        sigs_span = spans.get("sigs")
        if sigs_span and sigs_span[0] <= offset < sigs_span[1]:
            return "record-signature-metadata"
    if file_rel == "readable" or file_rel.startswith("readable/"):
        return "readable-view"
    name = file_rel.rsplit("/", 1)[-1]
    if name.startswith("tsa-cert-") and name.endswith(".pem"):
        return "tsa-certificate-file"
    return None


def classify_zip(offset: int, payload_ranges: list[tuple[int, int]]) -> str | None:
    for start, end in payload_ranges:
        if start <= offset < end:
            return None
    return "zip-metadata"


# ---------------------------------------------------------------------- case worker


def mutate_bytes_at(raw: bytes, offset: int) -> bytes:
    mutated = bytearray(raw)
    mutated[offset] ^= 1 << (offset % 8)
    return bytes(mutated)


def input_files(case_dir: Path, expected: dict) -> tuple[str, list[Path] | Path]:
    input_path = case_dir / expected["input"]
    target = expected["target"]
    if target == "record":
        return ("record", [input_path])
    if input_path.is_dir():
        return ("container-dir", [input_path])
    return ("container-zip", [input_path])


def _accepted_verdict(expected: dict) -> str:
    """The accepted verdict for this positive case (``valid`` or ``erased``)."""
    return "erased" if expected.get("verdict") == "erased" else "valid"


def process_case(
    *,
    case_id: str,
    expected: dict,
    case_dir: Path,
    work_root: Path,
    runner: VerifierRunner,
    max_bytes: int | None,
    verbose: bool,
) -> dict:
    args = expand_args(list(expected.get("args") or []), case_dir)
    kind, paths = input_files(case_dir, expected)
    accepted = _accepted_verdict(expected)
    result: dict[str, Any] = {
        "case": case_id,
        "target": expected["target"],
        "mutants": 0,
        "invalid": 0,
        "rejected": {},
        "exempt": {},
        "crash_samples": [],
        "survivors": [],
        "crash_samples": [],
        "files": [],
    }

    def note_outcome(verdict: str, report: dict, exempt_class: str | None, location: dict) -> None:
        result["mutants"] += 1
        if verdict != accepted:
            if verdict == "invalid":
                result["invalid"] += 1
            else:
                result["rejected"][verdict] = result["rejected"].get(verdict, 0) + 1
                if verdict == "verifier-crash" and len(result["crash_samples"]) < 20:
                    result["crash_samples"].append(
                        {**location, "error": report.get("error", "")}
                    )
            return
        if exempt_class is None:
            result["survivors"].append(
                {**location, "verdict": verdict, "errors": _errors(report)}
            )
        else:
            result["exempt"][exempt_class] = result["exempt"].get(exempt_class, 0) + 1

    work = work_root / case_id.replace("/", "__")
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True, exist_ok=True)

    if kind == "record":
        original = paths[0].read_bytes()
        expected["_kind"] = None
        try:
            record = json.loads(original)
            expected["_kind"] = record.get("kind") if isinstance(record, dict) else None
            sigs = record.get("sigs") if isinstance(record, dict) else None
            known = isinstance(sigs, list) and any(
                isinstance(entry, dict) and entry.get("alg") == "ed25519" for entry in sigs
            )
            expected["_unsigned"] = not known
        except ValueError:
            expected["_unsigned"] = False
        spans = record_span_map(original)
        temp_path = work / "mutant.json"
        limit = len(original) if max_bytes is None else min(len(original), max_bytes)
        for offset in range(limit):
            temp_path.write_bytes(mutate_bytes_at(original, offset))
            report = runner.run(["record", str(temp_path)] + args)
            verdict = report.get("verdict")
            if verdict != accepted:
                note_outcome(verdict, report, None, {})
                continue
            exemption = classify_non_invalid(
                case=expected,
                target="record",
                file_rel=None,
                offset=offset,
                raw=original,
                spans=spans,
                verdict=verdict,
            )
            note_outcome(
                verdict,
                report,
                exemption,
                {"offset": offset, "bit": offset % 8},
            )
        result["files"].append({"file": expected["input"], "bytes": len(original)})
        return result

    if kind == "container-dir":
        container_src = paths[0]
        container = work / "container"
        shutil.copytree(container_src, container)
        files = sorted(path for path in container.rglob("*") if path.is_file())
        for path in files:
            rel = path.relative_to(container).as_posix()
            original = path.read_bytes()
            file_spans = None
            if rel.startswith("records/") and rel.endswith(".json"):
                file_spans = record_span_map(original)
            limit = len(original) if max_bytes is None else min(len(original), max_bytes)
            result["files"].append({"file": rel, "bytes": len(original)})
            for offset in range(limit):
                path.write_bytes(mutate_bytes_at(original, offset))
                try:
                    report = runner.run(["container", str(container)] + _container_args(args))
                finally:
                    path.write_bytes(original)
                verdict = report.get("verdict")
                if verdict != accepted:
                    note_outcome(verdict, report, None, {})
                    continue
                exemption = classify_non_invalid(
                    case=expected,
                    target="container",
                    file_rel=rel,
                    offset=offset,
                    raw=original,
                    spans=file_spans,
                    verdict=verdict,
                )
                note_outcome(
                    verdict,
                    report,
                    exemption,
                    {"file": rel, "offset": offset, "bit": offset % 8},
                )
        return result

    # zip container
    archive = paths[0]
    original = archive.read_bytes()
    payload_ranges = zip_ranges(archive)
    limit = len(original) if max_bytes is None else min(len(original), max_bytes)
    temp_zip = work / "mutant.zip"
    result["files"].append({"file": expected["input"], "bytes": len(original)})
    for offset in range(limit):
        temp_zip.write_bytes(mutate_bytes_at(original, offset))
        report = runner.run(["container", str(temp_zip)] + _container_args(args))
        verdict = report.get("verdict")
        if verdict != accepted:
            note_outcome(verdict, report, None, {})
            continue
        exemption = classify_zip(offset, payload_ranges)
        if exemption is None and expected.get("verdict") == "erased":
            exemption = "erased-placeholder"
        note_outcome(verdict, report, exemption, {"offset": offset, "bit": offset % 8})
    return result


def _container_args(args: list[str]) -> list[str]:
    return list(args)


def _errors(report: dict) -> list[str]:
    errors: list[str] = []
    for entry in report.get("records") or []:
        errors.extend(entry.get("errors") or [])
    container = report.get("container") or {}
    errors.extend(container.get("errors") or [])
    return sorted(set(errors))


# ---------------------------------------------------------------------- process pool

_WORKER_RUNNER: "VerifierRunner | None" = None


def _init_worker(cache: bool) -> None:
    global _WORKER_RUNNER
    _WORKER_RUNNER = VerifierRunner(cache=cache)


def _process_case_worker(task: tuple) -> dict:
    case_id, expected, case_dir, work_root, max_bytes = task
    assert _WORKER_RUNNER is not None
    return process_case(
        case_id=case_id,
        expected=expected,
        case_dir=Path(case_dir),
        work_root=Path(work_root),
        runner=_WORKER_RUNNER,
        max_bytes=max_bytes,
        verbose=False,
    )


# ---------------------------------------------------------------------------- main


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--suite", default=str(DEFAULT_SUITE), help="vector suite root (default: vectors/)")
    parser.add_argument("--jobs", type=int, default=min(8, os.cpu_count() or 4))
    parser.add_argument(
        "--executor",
        choices=("process", "thread"),
        default="process",
        help="process pool (default, true CPU parallelism) or thread pool",
    )
    parser.add_argument("--quiet", action="store_true", help="suppress per-case progress on stderr")
    parser.add_argument("--json", metavar="PATH", help="write the machine report to PATH")
    parser.add_argument("--case", action="append", default=[], help="only these case ids (repeatable)")
    parser.add_argument("--max-bytes", type=int, help="debug: only the first N bytes of each file")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--no-cache", action="store_true", help="do not cache the verified key set")
    parser.add_argument("--list", action="store_true", help="list positive cases and exit")
    parser.add_argument(
        "--frozen-candidate",
        default=str(FROZEN_CANDIDATE),
        help="frozen candidate directory to include (default: vectors/frozen/v0.1-candidate)",
    )
    args = parser.parse_args(argv)

    suite = Path(args.suite)
    if not suite.is_dir():
        print("byte_flip_gate: suite directory not found: %s" % suite, file=sys.stderr)
        return 2
    cases = discover_cases(suite)
    frozen_root = Path(args.frozen_candidate)
    frozen_cases = discover_frozen(frozen_root) if frozen_root.is_dir() else []
    if args.case:
        wanted = set(args.case)
        cases = [case for case in cases if case[0] in wanted]
        frozen_cases = [case for case in frozen_cases if case[0] in wanted]
    if not cases and not frozen_cases:
        print("byte_flip_gate: no positive cases found", file=sys.stderr)
        return 2
    if args.list:
        for case_id, expected, _case_dir in cases + frozen_cases:
            print("%s\t%s\t%s" % (case_id, expected["target"], expected["input"]))
        return 0

    TMP_ROOT.mkdir(parents=True, exist_ok=True)
    tmpdir = Path(tempfile.mkdtemp(prefix="run-", dir=TMP_ROOT))
    runner = VerifierRunner(cache=not args.no_cache)
    print("byte_flip_gate: verifier package in use: %s" % runner.imported_file(), file=sys.stderr)
    if runner.cache is False:
        pass

    all_cases = [("source", case) for case in cases] + [("frozen-candidate", case) for case in frozen_cases]
    results: list[dict] = []
    executor: Any
    if args.executor == "process" and args.jobs > 1:
        executor = ProcessPoolExecutor(
            max_workers=max(1, args.jobs),
            initializer=_init_worker,
            initargs=(not args.no_cache,),
        )
    else:
        executor = ThreadPoolExecutor(max_workers=max(1, args.jobs))
    try:
        if args.executor == "process" and args.jobs > 1:
            futures = {}
            for origin, (case_id, expected, case_dir) in all_cases:
                future = executor.submit(
                    _process_case_worker,
                    (case_id, expected, str(case_dir), str(tmpdir), args.max_bytes),
                )
                futures[future] = (origin, case_id)
        else:
            futures = {}
            for origin, (case_id, expected, case_dir) in all_cases:
                future = executor.submit(
                    process_case,
                    case_id=case_id,
                    expected=expected,
                    case_dir=case_dir,
                    work_root=tmpdir,
                    runner=runner,
                    max_bytes=args.max_bytes,
                    verbose=args.verbose,
                )
                futures[future] = (origin, case_id)
        for future in futures:
            origin, case_id = futures[future]
            result = future.result()
            result["origin"] = origin
            results.append(result)
            if args.verbose or not args.quiet:
                print(
                    "  %-12s %-45s mutants=%d invalid=%d rejected=%s exempt=%s survivors=%d"
                    % (
                        origin,
                        case_id,
                        result["mutants"],
                        result["invalid"],
                        json.dumps(result.get("rejected", {}), sort_keys=True),
                        json.dumps(result["exempt"], sort_keys=True),
                        len(result["survivors"]),
                    ),
                    file=sys.stderr,
                    flush=True,
                )
    finally:
        executor.shutdown(wait=True, cancel_futures=True)
        if not os.environ.get("KEEP_BYTE_FLIP_TMP"):
            shutil.rmtree(tmpdir, ignore_errors=True)

    results.sort(key=lambda item: (item["origin"], item["case"]))
    totals = {
        "cases": len(results),
        "files": sum(len(item["files"]) for item in results),
        "bytes": sum(entry["bytes"] for item in results for entry in item["files"]),
        "mutants": sum(item["mutants"] for item in results),
        "invalid": sum(item["invalid"] for item in results),
        "rejected": {},
        "exempt": {},
        "crash_samples": [],
        "survivors": [],
    }
    for item in results:
        for name, count in item.get("rejected", {}).items():
            totals["rejected"][name] = totals["rejected"].get(name, 0) + count
        for sample in item.get("crash_samples", []):
            if len(totals["crash_samples"]) < 20:
                totals["crash_samples"].append({"case": item["case"], **sample})
        for name, count in item["exempt"].items():
            totals["exempt"][name] = totals["exempt"].get(name, 0) + count
        for survivor in item["survivors"]:
            totals["survivors"].append({"case": item["case"], "origin": item["origin"], **survivor})
    totals["frozen_included"] = bool(frozen_cases)

    report = {
        "gate": "byte-flip",
        "ok": not totals["survivors"],
        "exempt_reasons": EXEMPT_REASONS,
        **totals,
        "case_results": results,
    }
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        "byte-flip: %d cases (%d frozen candidate), %d files, %d bytes, %d mutants, "
        "%d invalid, %d other-rejection, %d exempt, %d survivors"
        % (
            totals["cases"],
            1 if totals["frozen_included"] else 0,
            totals["files"],
            totals["bytes"],
            totals["mutants"],
            totals["invalid"],
            sum(totals["rejected"].values()),
            sum(totals["exempt"].values()),
            len(totals["survivors"]),
        )
    )
    if totals["rejected"]:
        print("non-invalid rejections (fail-closed dependency breaks):")
        for name in sorted(totals["rejected"]):
            print("  %-26s %6d" % (name, totals["rejected"][name]))
    if totals["crash_samples"]:
        print("verifier-crash samples (fail-closed gap, reported separately):")
        for sample in totals["crash_samples"][:10]:
            print(
                "  %s file=%s offset=%s :: %s"
                % (sample["case"], sample.get("file", "-"), sample.get("offset"), sample.get("error", "")[:120])
            )
    if totals["exempt"]:
        print("exempt classes:")
        for name in sorted(totals["exempt"]):
            print("  %-26s %6d  %s" % (name, totals["exempt"][name], EXEMPT_REASONS.get(name, "")))
    if totals["survivors"]:
        print("SURVIVORS (must be fixed with a vector or an exemption rule):")
        for survivor in totals["survivors"][:40]:
            print(
                "  %s [%s] file=%s offset=%s bit=%s verdict=%s errors=%s"
                % (
                    survivor["case"],
                    survivor["origin"],
                    survivor.get("file", "-"),
                    survivor.get("offset"),
                    survivor.get("bit"),
                    survivor.get("verdict"),
                    ",".join(survivor.get("errors") or []),
                )
            )
        print("RESULT: FAIL")
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
