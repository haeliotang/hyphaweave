#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0
"""Standing crash-fuzz gate for the Rust verifier CLI (H1-FIX1).

A deterministic mutator derives hostile inputs from the committed conformance
vectors (record files, container directories, zip containers and RFC 3161
receipts), runs the Rust CLI on each one with the case's own arguments, and
fails when any run

* is killed by a signal or exits with a code outside {0, 1, 2, 3} (§14.8),
* prints a Rust panic or a stack-overflow message,
* exceeds the per-run timeout, or
* exits 0, 1 or 3 without exactly one JSON object on standard output.

The verdicts themselves are not judged here (the vectors and the differential
comparison do that). The mutator is seeded and never grows its inputs
exponentially: every mutant is derived from an original input by a bounded
number of edits. Only the Rust CLI is executed.

Usage:
  crash_fuzz.py [--binary PATH] [--count N] [--seed S] [--jobs J] [--timeout T]
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
VECTORS = REPO / "vectors"
DEFAULT_BINARY = REPO / "verifiers" / "rust" / "target" / "release" / "hyphaweave-verify-rs"
ALLOWED_EXIT = {0, 1, 2, 3}
CRASH_MARKERS = ("panicked at", "stack overflow", "RUST_BACKTRACE", "fatal runtime error")
MAX_EDITS = 4


def load_cases() -> list[dict]:
    cases = []
    for expected_path in sorted(VECTORS.glob("*/*/expected.json")):
        if expected_path.parts[-3] == "frozen":
            continue
        expected = json.loads(expected_path.read_text(encoding="utf-8"))
        expected["_dir"] = expected_path.parent
        cases.append(expected)
    return cases


def resolve_args(case: dict, case_dir: Path, workdir: Path) -> list[str]:
    out: list[str] = []
    for token in case.get("args", []):
        if token == "@keyset":
            out.append(str(VECTORS / "keys" / "keyset"))
        elif token == "@case":
            out.append(str(case_dir))
        elif token.startswith("--"):
            out.append(token)
        else:
            out.append(str(case_dir / token))
    return out


def mutate_bytes(rng: random.Random, data: bytes) -> bytes:
    """A bounded number of edits: bit flips, byte sets, deletions, insertions,
    truncation and duplication of a short slice."""
    buffer = bytearray(data)
    for _ in range(rng.randint(1, MAX_EDITS)):
        choice = rng.randrange(7)
        if not buffer:
            buffer.extend(rng.randbytes(rng.randint(1, 8)))
            continue
        position = rng.randrange(len(buffer))
        if choice == 0:
            buffer[position] ^= 1 << rng.randrange(8)
        elif choice == 1:
            buffer[position] = rng.choice([0x00, 0xFF, 0x7F, 0x80, ord("{"), ord('"'), ord("[")])
        elif choice == 2:
            del buffer[position : position + rng.randint(1, 16)]
        elif choice == 3:
            buffer[position:position] = rng.randbytes(rng.randint(1, 16))
        elif choice == 4:
            del buffer[position:]
        elif choice == 5:
            length = rng.randint(1, 64)
            buffer[position:position] = buffer[position : position + length]
        else:
            # Deep nesting / long numbers in JSON-like inputs.
            buffer[position:position] = rng.choice([b"[" * 64, b"{\"a\":" * 40, b"9" * 40, b"(" * 40])
    return bytes(buffer)


def prepare(case: dict, rng: random.Random, workdir: Path) -> tuple[list[str], str]:
    """Copies the case input into `workdir`, mutates one file, returns the CLI
    argument list and a short description."""
    case_dir: Path = case["_dir"]
    target = case["target"]
    source = case_dir / case["input"]
    mutated_dir = workdir / "case"
    shutil.copytree(case_dir, mutated_dir, symlinks=True)
    input_path = mutated_dir / case["input"]
    if input_path.is_dir():
        files = sorted(
            path
            for path in input_path.rglob("*")
            if path.is_file() and not path.is_symlink()
        )
        if not files:
            return [], "empty"
        victim = rng.choice(files)
    else:
        victim = input_path
    original = victim.read_bytes()
    victim.write_bytes(mutate_bytes(rng, original))
    args = resolve_args(case, mutated_dir, workdir)
    description = f"{case['id']} :: {victim.relative_to(mutated_dir)}"
    _ = source
    return [target, str(input_path), *args], description


def run_one(binary: Path, case: dict, seed: int, timeout: float) -> tuple[bool, str]:
    rng = random.Random(seed)
    with tempfile.TemporaryDirectory(prefix="h1-crash-fuzz-") as raw:
        workdir = Path(raw)
        argv, description = prepare(case, rng, workdir)
        if not argv:
            return True, ""
        try:
            completed = subprocess.run(
                [str(binary), *argv],
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return False, f"TIMEOUT seed={seed} {description}"
        stderr = completed.stderr.decode("utf-8", "replace")
        if completed.returncode not in ALLOWED_EXIT:
            return False, f"EXIT {completed.returncode} seed={seed} {description}: {stderr[:200]}"
        if any(marker in stderr for marker in CRASH_MARKERS):
            return False, f"PANIC seed={seed} {description}: {stderr[:200]}"
        if completed.returncode in (0, 1, 3):
            try:
                report = json.loads(completed.stdout)
            except ValueError:
                return False, f"NO-REPORT seed={seed} {description}"
            if not isinstance(report, dict):
                return False, f"NO-REPORT seed={seed} {description}"
        elif completed.stdout:
            return False, f"REPORT-ON-EXIT-2 seed={seed} {description}"
    return True, ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--count", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=20261114)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=30.0)
    options = parser.parse_args()
    if not options.binary.is_file():
        print(f"crash_fuzz: binary not found: {options.binary}", file=sys.stderr)
        return 2
    cases = load_cases()
    master = random.Random(options.seed)
    plan = [(master.choice(cases), master.randrange(1 << 62)) for _ in range(options.count)]
    failures: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(options.jobs, 2))) as pool:
        futures = [
            pool.submit(run_one, options.binary, case, seed, options.timeout) for case, seed in plan
        ]
        for future in futures:
            ok, message = future.result()
            if not ok:
                failures.append(message)
    print(f"crash_fuzz: {options.count} mutants, {len(failures)} failures (seed {options.seed})")
    for message in failures[:50]:
        print(f"  {message}")
    return 1 if failures else 0


if __name__ == "__main__":
    os.environ.setdefault("RUST_BACKTRACE", "0")
    sys.exit(main())
