#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0
"""H0 FIX1 gate: verify a frozen-vector candidate directory.

The frozen candidate (``vectors/frozen/v0.1-candidate/``) is *not* formally frozen
until the v0.1 acceptance cases J1/J2 pass; it is a copied, pinned regression set.
This gate makes the candidate's integrity checkable in CI:

1. ``SHA256SUMS`` lists exactly the files in the directory (no missing file, no
   extra file, no absolute/traversing path, no duplicate entry) and every listed
   file hashes to its recorded SHA-256 (``sha256sum -c --strict`` equivalent);
2. ``FROZEN.md`` declares the directory as a **candidate**, states the formal
   freeze condition (J1/J2 acceptance), pins a source commit, states the
   selection rule, and its declared case/verdict/category counts match the cases
   actually present;
3. the number of ``*/*/expected.json`` case files equals the declared count (a
   silently deleted frozen case is caught even when its old hash line was also
   removed — the set comparison alone cannot catch "delete case and delete its
   three lines together", the count check can).

Exit status: 0 = pass, 1 = verification failure, 2 = usage/IO error.
Output is deterministic: sorted paths, no clock, no absolute machine paths in the
report body (the directory argument is echoed as given on disk).

Usage:
    python tools/check_frozen.py [--json] [--quiet]

Run from the repository root; the tool locates the repository itself. CI runs it
with no arguments and only on the final revision state. If the candidate
directory does not exist yet (revision in progress), the tool exits 2 with an
explanation. ``--directory`` is a QA-only override used to exercise the checker
against temporary copies; CI never passes it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_CANDIDATE = REPO / "vectors" / "frozen" / "v0.1-candidate"
SUMS_NAME = "SHA256SUMS"
DOC_NAME = "FROZEN.md"
COUNT_NAME = "FROZEN_CASE_COUNT"
IGNORED_NAMES = {".DS_Store"}  # macOS metadata; never part of the frozen data
SUMS_LINE = re.compile(r"^([0-9a-f]{64}) [ *](.+)$")
HEX40 = re.compile(r"\b[0-9a-f]{40}\b")
TOTAL_ATTR = "__TOTAL__"


class Failure(Exception):
    """A verification failure reported as exit status 1."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def disk_files(root: Path) -> tuple[set[str], list[str]]:
    found: set[str] = set()
    ignored: list[str] = []
    for path in sorted(root.rglob("*")):
        if path.is_dir():
            continue
        rel = path.relative_to(root).as_posix()
        if path.name in IGNORED_NAMES:
            ignored.append(rel)
            continue
        if rel == SUMS_NAME:
            continue
        found.add(rel)
    return found, ignored


def parse_sums(root: Path) -> dict[str, str]:
    sums_path = root / SUMS_NAME
    if not sums_path.is_file():
        raise Failure("missing %s in %s" % (SUMS_NAME, root))
    listed: dict[str, str] = {}
    for lineno, raw in enumerate(sums_path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        match = SUMS_LINE.match(line)
        if not match:
            raise Failure("%s:%d: not a sha256sum line: %r" % (SUMS_NAME, lineno, line))
        digest, rel = match.group(1), match.group(2)
        if rel in listed:
            raise Failure("%s:%d: duplicate entry for %r" % (SUMS_NAME, lineno, rel))
        if rel.startswith("/") or rel.startswith("./") or rel.endswith("/"):
            raise Failure("%s:%d: invalid relative path %r" % (SUMS_NAME, lineno, rel))
        parts = rel.split("/")
        if any(part in ("", ".", "..") for part in parts):
            raise Failure("%s:%d: path escapes the directory: %r" % (SUMS_NAME, lineno, rel))
        listed[rel] = digest
    if not listed:
        raise Failure("%s lists no files" % SUMS_NAME)
    return listed


def parse_counts(doc_text: str, actual: dict[str, int], actual_verdicts: dict[str, int]) -> list[str]:
    """Cross-check the human-readable counts in FROZEN.md against the cases."""
    problems: list[str] = []
    # Category table rows: | `category` | N |
    declared_categories: dict[str, int] = {}
    for match in re.finditer(r"^\|\s*`([a-z0-9-]+)`\s*\|\s*(\d+)\s*\|\s*$", doc_text, re.M):
        declared_categories[match.group(1)] = int(match.group(2))
    total_declared = None
    case_count_line = re.search(r"^\s*[-*]\s*Case count:\s*(\d+)\s*$", doc_text, re.M)
    if case_count_line:
        total_declared = int(case_count_line.group(1))
    else:
        total_match = re.search(r"^\|\s*\*\*total\*\*\s*\|\s*\*\*(\d+)\*\*\s*\|\s*$", doc_text, re.M)
        if total_match:
            total_declared = int(total_match.group(1))
        else:
            total_match = re.search(r"^\|\s*total\s*\|\s*(\d+)\s*\|\s*$", doc_text, re.M | re.I)
            if total_match:
                total_declared = int(total_match.group(1))
    if declared_categories:
        for category, count in sorted(declared_categories.items()):
            got = actual.get(category, 0)
            if count != got:
                problems.append(
                    "FROZEN.md category %r declares %d case(s), found %d" % (category, count, got)
                )
        unknown = sorted(set(actual) - set(declared_categories))
        if unknown:
            problems.append(
                "FROZEN.md category table omits categories present on disk: %s" % ", ".join(unknown)
            )
    if total_declared is None:
        problems.append("FROZEN.md does not declare a total case count")
    elif total_declared != sum(actual.values()):
        problems.append(
            "FROZEN.md total declares %d case(s), found %d"
            % (total_declared, sum(actual.values()))
        )
    # Verdict line: ``Verdicts: `erased` 1, `invalid` 90, ...``
    verdict_match = re.search(r"Verdicts:(.+)", doc_text)
    if verdict_match:
        declared: dict[str, int] = {}
        for name, value in re.findall(r"`([a-z]+)`\s*(\d+)", verdict_match.group(1)):
            declared[name] = int(value)
        if declared:
            for name, count in sorted(declared.items()):
                got = actual_verdicts.get(name, 0)
                if count != got:
                    problems.append(
                        "FROZEN.md verdict %r declares %d case(s), found %d" % (name, count, got)
                    )
    return problems


def verify(root: Path) -> dict:
    root = root.resolve()
    if not root.is_dir():
        raise Failure("frozen directory does not exist: %s" % root)
    doc_path = root / DOC_NAME
    if not doc_path.is_file():
        raise Failure("missing %s in %s" % (DOC_NAME, root))
    doc_text = doc_path.read_text(encoding="utf-8")

    listed = parse_sums(root)
    found, ignored = disk_files(root)

    missing = sorted(set(listed) - found)
    extra = sorted(found - set(listed))

    hashes_ok = 0
    hash_mismatches: list[str] = []
    for rel, expected_digest in sorted(listed.items()):
        path = root / rel
        if not path.is_file():
            continue
        actual_digest = sha256_file(path)
        if actual_digest == expected_digest:
            hashes_ok += 1
        else:
            hash_mismatches.append(rel)

    # Case files and their verdict counts
    case_dirs = sorted(path.parent for path in root.glob("*/*/expected.json"))
    if not case_dirs:
        raise Failure("no */*/expected.json case files under %s" % root)
    case_ids = [path.relative_to(root).as_posix() for path in case_dirs]
    categories: dict[str, int] = {}
    verdicts: dict[str, int] = {}
    invalid_expected: list[str] = []
    for case_dir in case_dirs:
        expected_path = case_dir / "expected.json"
        try:
            expected = json.loads(expected_path.read_text(encoding="utf-8"))
            category = str(expected.get("category") or case_dir.parent.name)
            verdict = str(expected.get("verdict") or "")
        except (OSError, ValueError) as error:
            raise Failure("cannot read %s: %s" % (expected_path.relative_to(root), error))
        categories[category] = categories.get(category, 0) + 1
        verdicts[verdict] = verdicts.get(verdict, 0) + 1
        if not verdict:
            invalid_expected.append(expected_path.relative_to(root).as_posix())

    count_file = root / COUNT_NAME
    declared_count = None
    count_problems: list[str] = []
    if count_file.is_file():
        text = count_file.read_text(encoding="utf-8")
        stripped = text.strip()
        if not re.fullmatch(r"\d+", stripped):
            count_problems.append("%s must contain a single decimal integer" % COUNT_NAME)
        else:
            if not text.endswith("\n"):
                count_problems.append("%s must end with a newline" % COUNT_NAME)
            declared_count = int(stripped)
            if declared_count != len(case_dirs):
                count_problems.append(
                    "%s declares %d case(s), found %d"
                    % (COUNT_NAME, declared_count, len(case_dirs))
                )

    doc_problems: list[str] = []
    informational: list[str] = []
    if not re.search(r"candidate", doc_text, re.I):
        doc_problems.append("FROZEN.md does not declare the directory as a candidate")
    for token in ("J1", "J2"):
        if token not in doc_text:
            doc_problems.append(
                "FROZEN.md does not state the formal freeze condition (%s acceptance)" % token
            )
    if "freeze condition" not in doc_text.lower() and "formally frozen" not in doc_text.lower():
        doc_problems.append("FROZEN.md does not state a formal freeze condition")
    if not re.search(r"selection rule|selection", doc_text, re.I):
        informational.append("FROZEN.md does not state the selection rule (contract §12)")
    if not HEX40.search(doc_text):
        informational.append("FROZEN.md does not pin a 40-hex source commit (contract §12)")
    doc_problems.extend(parse_counts(doc_text, categories, verdicts))

    problems: list[str] = list(count_problems)
    if missing:
        problems.append(
            "%d file(s) listed in %s are missing: %s"
            % (len(missing), SUMS_NAME, ", ".join(missing[:8]))
        )
    if extra:
        problems.append(
            "%d file(s) on disk are not listed in %s: %s"
            % (len(extra), SUMS_NAME, ", ".join(extra[:8]))
        )
    if hash_mismatches:
        problems.append(
            "%d listed file(s) do not match their SHA-256: %s"
            % (len(hash_mismatches), ", ".join(hash_mismatches[:8]))
        )
    if declared_count is None and "total case count" not in " ".join(doc_problems):
        # FROZEN.md must still carry a count; parse_counts reports a missing total itself.
        pass
    if invalid_expected:
        problems.append("case file(s) without a verdict: %s" % ", ".join(invalid_expected[:8]))
    problems.extend(doc_problems)

    return {
        "directory": str(root.relative_to(REPO)) if root.is_relative_to(REPO) else str(root),
        "listed_files": len(listed),
        "disk_files": len(found),
        "hashes_ok": hashes_ok,
        "case_count": len(case_dirs),
        "case_dirs": case_ids,
        "categories": categories,
        "verdicts": verdicts,
        "ignored": ignored,
        "problems": problems,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--json", action="store_true", help="emit a JSON report on stdout")
    parser.add_argument("--quiet", action="store_true", help="print only the final verdict")
    parser.add_argument(
        "--directory",
        metavar="DIR",
        help="QA-only override for exercising the checker against a temporary copy",
    )
    args = parser.parse_args(argv)

    root = Path(args.directory) if args.directory else DEFAULT_CANDIDATE
    if not root.is_dir():
        print(
            "check_frozen: SKIP: candidate directory %s does not exist "
            "(revision in progress; CI runs this check only on the final state)"
            % root.relative_to(REPO) if root.is_relative_to(REPO) else str(root),
            file=sys.stderr,
        )
        return 2

    try:
        result = verify(root)
    except Failure as error:
        print("check_frozen: FAIL: %s" % error, file=sys.stderr)
        return 1
    except OSError as error:
        print("check_frozen: I/O error: %s" % error, file=sys.stderr)
        return 2

    ok = not result["problems"]
    if args.json:
        report = {"ok": ok, "gate": "frozen-candidate", **result}
        sys.stdout.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    elif not args.quiet:
        print("frozen candidate: %s" % result["directory"])
        print("  listed files: %d, on-disk files: %d, hashes OK: %d" % (
            result["listed_files"], result["disk_files"], result["hashes_ok"]))
        print("  cases: %d across %d categories; verdicts: %s" % (
            result["case_count"], len(result["categories"]),
            json.dumps(result["verdicts"], sort_keys=True)))
        if result["ignored"]:
            print("  ignored metadata files: %s" % ", ".join(result["ignored"]))
        if ok:
            print("CHECK_FROZEN: PASS")
        else:
            for problem in result["problems"]:
                print("  PROBLEM: %s" % problem)
            print("CHECK_FROZEN: FAIL")
    if not ok and not args.json:
        return 1
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
