# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""The ``hyphaweave-verify`` command line interface (spec §14.1).

``hyphaweave-verify record <file>``, ``container <dir|zip>``, ``vectors <dir>``,
``--help`` and ``--version``. stdout carries exactly one deterministic JSON
report per verification run; usage and IO errors go to stderr and exit 2.
Exit codes: 0 = valid (or all vector cases matched), 1 = invalid/unverifiable or
a vector mismatch, 2 = usage/IO error.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path
from typing import Sequence

from . import __version__, canonical
from . import container as container_module
from . import report as report_module
from . import verifier
from .errors import CheckSkipper, UsageError, WeaveError
from .report import LIMITATION_ERASED_PLACEHOLDER, LIMITATION_OFFLINE_CONTEXT, LIMITATION_TOFU
from .report import LIMITATION_UNKNOWN_KIND, LIMITATION_LABELS_ARE_CLAIMS, record_verdict

PROGRAM = "hyphaweave-verify"
EXIT_VALID = 0
EXIT_MISMATCH = 1
EXIT_USAGE = 2


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description="Reference verifier for the weave-record/1 exchange format (H0 draft).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%s %s (report_version 1)" % (PROGRAM, __version__),
    )
    subparsers = parser.add_subparsers(dest="command", metavar="command")

    record = subparsers.add_parser("record", help="verify one record file")
    record.add_argument("file", help="path to the record JSON file")
    record.add_argument("--keys", metavar="DIR", help="directory of key-lifecycle records")
    record.add_argument("--json", action="store_true", help="emit JSON (the default)")

    container = subparsers.add_parser("container", help="verify a container directory or zip")
    container.add_argument("path", help="container directory or zip file")
    container.add_argument("--keys", metavar="DIR", help="directory of key-lifecycle records")
    container.add_argument("--tsa-trust", metavar="PEM", help="TSA trust anchors (PEM bundle)")
    container.add_argument("--previous", metavar="DIR", help="previous container")
    container.add_argument("--json", action="store_true", help="emit JSON (the default)")

    vectors = subparsers.add_parser("vectors", help="run every vector case under a directory")
    vectors.add_argument("directory", help="vector suite root")
    vectors.add_argument("--tsa-trust", metavar="PEM", help="default TSA trust anchors")
    vectors.add_argument("--json", action="store_true", help="emit JSON (the default)")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point; returns the process exit code."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    try:
        namespace = parser.parse_args(arguments)
    except SystemExit as exit_signal:  # argparse already printed help/usage
        return int(exit_signal.code) if exit_signal.code is not None else EXIT_VALID
    if namespace.command is None:
        parser.print_usage(sys.stderr)
        return EXIT_USAGE
    skipper = CheckSkipper.from_env()
    try:
        if namespace.command == "record":
            report = _run_record(namespace, skipper)
        elif namespace.command == "container":
            report = _run_container(namespace, skipper)
        else:
            report = _run_vectors(namespace)
    except UsageError as error:
        print("%s: %s" % (PROGRAM, error), file=sys.stderr)
        return EXIT_USAGE
    except OSError as error:
        print("%s: I/O error: %s" % (PROGRAM, error.strerror or error), file=sys.stderr)
        return EXIT_USAGE
    output = report_module.serialize(report)
    sys.stdout.buffer.write(output)
    sys.stdout.buffer.flush()
    return EXIT_VALID if report["verdict"] in ("valid", "erased") else EXIT_MISMATCH


# ---------------------------------------------------------------------------
# record
# ---------------------------------------------------------------------------


def _run_record(namespace: argparse.Namespace, skipper: CheckSkipper) -> dict:
    path = Path(namespace.file)
    raw = path.read_bytes()
    input_sha = "sha256:" + hashlib.sha256(raw).hexdigest()
    keyset_loaded, keyset_views = _load_keyset(namespace.keys)

    limitations = [LIMITATION_OFFLINE_CONTEXT]
    try:
        loaded = verifier.load_record_bytes(raw, source="record")
    except WeaveError as error:
        return _record_report_for_error(error.code, input_sha, len(raw), skipper, limitations)

    target_view, _context_views = verifier.verify_single_record(
        loaded, keyset_loaded, verified_timestamps=()
    )
    entry = _record_entry(target_view, skipper)
    verdict = entry["verdict"]
    limitations = _record_limitations(target_view, limitations)
    report = report_module.build_report(
        target="record",
        verdict=verdict,
        input_sha256=input_sha,
        input_size=len(raw),
        records=[entry],
        checks_disabled=skipper.tokens,
        limitations=limitations,
    )
    return report


def _record_entry(view: verifier.RecordView, skipper: CheckSkipper) -> dict:
    entry = container_module._record_report_entry(view)
    filtered_errors = [code for code in entry["errors"] if not skipper.skip_error(code)]
    entry["errors"] = sorted(set(filtered_errors))
    if view.placeholder is None:
        entry["verdict"] = record_verdict(filtered_errors)
    return entry


def _record_report_for_error(
    code: str, input_sha: str, size: int, skipper: CheckSkipper, limitations: list[str]
) -> dict:
    filtered = [candidate for candidate in [code] if not skipper.skip_error(candidate)]
    verdict = record_verdict(filtered) if filtered else "valid"
    entry = report_module.record_entry(
        digest=None,
        record_id=None,
        kind=None,
        stage=None,
        origin=None,
        kind_known=False,
        verdict=verdict,
        errors=filtered,
        notices=[],
        refs=[],
        sigs=[],
    )
    return report_module.build_report(
        target="record",
        verdict=verdict,
        input_sha256=input_sha,
        input_size=size,
        records=[entry],
        checks_disabled=skipper.tokens,
        limitations=limitations,
    )


def _record_limitations(view: verifier.RecordView, limitations: list[str]) -> list[str]:
    result = list(limitations)
    if "N_KEY_TOFU" in view.notices:
        result.append(LIMITATION_TOFU)
    if view.envelope is not None and not view.envelope.kind_known:
        result.append(LIMITATION_UNKNOWN_KIND)
    if view.placeholder is not None:
        result.append(LIMITATION_ERASED_PLACEHOLDER)
    if view.envelope is not None and view.envelope.labels is not None:
        result.append(LIMITATION_LABELS_ARE_CLAIMS)
    deduped: list[str] = []
    for item in result:
        if item not in deduped:
            deduped.append(item)
    return deduped


def _load_keyset(
    keys_path: str | None,
) -> tuple[list[verifier.LoadedRecord], list[verifier.RecordView]]:
    if not keys_path:
        return [], []
    loaded = verifier.load_keyset_directory(Path(keys_path))
    views = verifier.verify_record_set(loaded)
    return loaded, views


# ---------------------------------------------------------------------------
# container
# ---------------------------------------------------------------------------


def _run_container(namespace: argparse.Namespace, skipper: CheckSkipper) -> dict:
    path = Path(namespace.path)
    if not path.exists():
        raise UsageError("container path does not exist")
    keyset_loaded, keyset_views = _load_keyset(namespace.keys)
    tsa_trust = None
    if namespace.tsa_trust:
        tsa_trust = Path(namespace.tsa_trust).read_bytes()
    previous = Path(namespace.previous) if namespace.previous else None
    verification = container_module.verify_container(
        path,
        keyset_records=keyset_loaded,
        keyset_views=keyset_views,
        tsa_trust=tsa_trust,
        previous_container=previous,
        skipper=skipper,
    )
    return verification.report


# ---------------------------------------------------------------------------
# vectors
# ---------------------------------------------------------------------------


def _run_vectors(namespace: argparse.Namespace) -> dict:
    from . import vectors_runner

    default_tsa_trust = None
    if namespace.tsa_trust:
        default_tsa_trust = Path(namespace.tsa_trust).read_bytes()
    return vectors_runner.run_vectors(Path(namespace.directory), default_tsa_trust=default_tsa_trust)


if __name__ == "__main__":  # pragma: no cover - exercised by python -m
    sys.exit(main())
