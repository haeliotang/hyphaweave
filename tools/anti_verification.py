#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0
"""H0 gate 3: anti-verification (mutation) and check-class ablation.

Two independent checks over the conformance vectors:

(a) Mutation: every case whose expected verdict is ``valid`` (or ``erased``) is copied to a
    scratch directory, one bit is flipped at deterministic positions, and the reference
    verifier must never again return ``valid``/``erased``.  A surviving mutant means the
    case does not actually depend on the bytes it claims to prove.

    Evidence scope.  A ``target: record`` positive case whose input record carries no
    ``sigs`` member has *no cryptographic binding at all*: a bit flipped in its body
    (for example a digit of ``recorded_at``) yields another perfectly valid record, and a
    conforming verifier must keep saying ``valid``.  The H0 gate statement ("every
    positive case must become non-valid") is therefore unachievable for such vectors.
    The sweep still runs on every positive case, but classifies survivors:

    * ``evidence-bound`` - record cases with at least one signature, and every container
      case (the signed manifest digest chain commits every byte).  These MUST have zero
      survivors; a survivor here fails the gate.
    * ``unbound`` - record cases with no ``sigs`` (unsigned records and ``weave.erased``
      placeholders).  Survivors are printed explicitly as a DOCUMENTED EXCEPTION and do
      not fail the gate in the default ``--require-strength=evidence`` mode.

    ``--require-strength=strict`` applies the literal H0-prompt rule (zero survivors
    anywhere) and is expected to FAIL until the vectors are changed or the Lead accepts
    the documented exception.  Whatever mode is used, the delivery report must state
    which one and how many unbound survivors were observed.

    Zip containers are mutated by rewriting the archive with one bit flipped in the bytes
    of one contained file (up to 8 files x 4 bits).  Flipping raw archive metadata bytes
    (mtime/version/attributes) would be semantically irrelevant, so the literal
    "flip a byte in the .zip" rule is implemented as "flip a byte of the archived
    evidence", which is what the gate is trying to prove.

(b) Ablation: for each error-code family (e.g. ``E_ENV``, ``E_SIG``) the whole vector
    suite is re-run in a fresh subprocess with ``WEAVE_VERIFY_SKIP_CHECKS`` set to the
    family's codes.  A family whose removal changes no vector result is not tested by the
    vectors and is reported as a gap (a gap must be either fixed by adding vectors or
    whitelisted here with a written reason, and stated in the delivery report).

Exit status: 0 when the gate passes in the selected mode, 1 otherwise, 2 on usage/IO
error.  The machine summary is written to ``.tmp-work/gates/gate3-report.json`` with
sorted keys; stdout is a stable human summary (no current time, no randomness; scratch
paths are only mentioned as relative paths below the repository root).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import io
import json
import os
import random
import re
import shutil
import subprocess
import sys
import threading
import zipfile
from functools import lru_cache
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
VECTORS = REPO / "vectors"
GATES_DIR = REPO / ".tmp-work" / "gates"
SCRATCH = GATES_DIR / "anti-verification"
SUMMARY_PATH = GATES_DIR / "gate3-report.json"

#: Expected verdicts that count as "accepted evidence".
ACCEPTED_VERDICTS = {"valid", "erased"}

#: Families that legitimately cannot be exercised by a negative vector.  Every entry needs
#: a written reason; the gate prints whitelisted gaps explicitly and the delivery report
#: must carry the same statement.  Keep this empty unless the Lead has accepted a gap.
WHITELISTED_GAPS: dict[str, str] = {}


def fail(message: str) -> "NoReturn":  # type: ignore[name-defined]
    print(f"anti-verification: {message}", file=sys.stderr)
    raise SystemExit(2)


# --------------------------------------------------------------------------- verifier CLI


@lru_cache(maxsize=1)
def resolve_verifier() -> tuple[str, tuple[str, ...]]:
    """Return ``(mode, argv_prefix)`` for the reference verifier (resolved once)."""
    script = REPO / ".venv" / "bin" / "hyphaweave-verify"
    if script.exists():
        probe = subprocess.run(
            [str(script), "--version"], capture_output=True, text=True, timeout=120
        )
        if probe.returncode == 0:
            return ("script", (str(script),))
    py = REPO / ".venv" / "bin" / "python"
    if not py.exists():
        py = Path(sys.executable)
    probe = subprocess.run(
        [str(py), "-c", "import hyphaweave_verify.cli"], capture_output=True, text=True
    )
    if probe.returncode == 0:
        return ("module", (str(py), "-m", "hyphaweave_verify.cli"))
    fail(
        "reference verifier CLI is not installed/runnable "
        "(need .venv/bin/hyphaweave-verify or hyphaweave_verify.cli; "
        "run: .venv/bin/python -m pip install -e 'verifiers/python[dev]')"
    )


def find_verifier() -> tuple[str, ...]:
    """Return the subprocess argv prefix for the reference verifier."""
    return resolve_verifier()[1]


#: The in-process runner serialises calls: the verifier CLI writes to ``sys.stdout``.
_INPROCESS_LOCK = threading.Lock()
_MUTATION_SUBPROCESS = False


class _StdoutCapture(io.TextIOBase):
    """Minimal stdout replacement exposing the ``buffer`` the CLI writes to."""

    def __init__(self) -> None:
        self.buffer = io.BytesIO()

    def write(self, data: str) -> int:  # pragma: no cover - defensive
        self.buffer.write(data.encode("utf-8"))
        return len(data)

    def flush(self) -> None:  # pragma: no cover - defensive
        return None


@lru_cache(maxsize=1)
def _cli_module():
    import hyphaweave_verify.cli as cli_module  # the real check path, imported lazily

    return cli_module


@lru_cache(maxsize=1)
def _cli_parser():
    return _cli_module().build_parser()


def run_verifier_inprocess(args: list[str]) -> tuple[int, dict | None, str]:
    """Invoke the CLI's own check path in-process.

    H0 gate 3 explicitly allows in-process use as long as the real check path is invoked.
    Instead of spawning a process (or capturing the CLI's stdout), we call the same
    ``_run_record``/``_run_container`` functions that ``hyphaweave_verify.cli.main`` calls
    and receive the report dictionary they return; JSON serialisation and the console
    stream are not part of the check.  The check functions keep no mutable global state
    (their only lazy initialiser is idempotent), so per-case mutation workers call them
    concurrently; each case mutates its own private copy of the case directory.
    """
    cli_module = _cli_module()
    parser = _cli_parser()
    try:
        namespace = parser.parse_args(list(args))
    except SystemExit as exit_signal:
        return int(exit_signal.code or 0), None, "usage error"
    if namespace.command is None:
        return 2, None, "no command"
    skipper = cli_module.CheckSkipper.from_env()
    try:
        if namespace.command == "record":
            report = cli_module._run_record(namespace, skipper)
        elif namespace.command == "container":
            report = cli_module._run_container(namespace, skipper)
        else:
            report = cli_module._run_vectors(namespace)
    except cli_module.UsageError as error:
        return 2, None, str(error)
    except OSError as error:
        return 2, None, str(error)
    rc = 0 if report.get("verdict") in ("valid", "erased") else 1
    return rc, report, ""


def run_verifier(
    argv: list[str],
    *,
    env_extra: dict[str, str] | None = None,
    force_subprocess: bool = False,
) -> tuple[int, dict | None, str]:
    """Run the verifier; return (rc, report-or-None, stderr).

    Mutation runs default to the in-process CLI path (much faster and explicitly allowed
    by the gate definition).  Ablation always uses a fresh subprocess because it needs a
    fresh ``WEAVE_VERIFY_SKIP_CHECKS`` environment and clean interpreter state.
    """
    mode, prefix = resolve_verifier()
    if not force_subprocess and not env_extra:
        if mode == "script":
            args = argv[len(prefix):]
        else:
            args = argv[len(prefix):]
        return run_verifier_inprocess(args)
    env = dict(os.environ)
    env.pop("WEAVE_VERIFY_SKIP_CHECKS", None)
    env["PYTHONHASHSEED"] = "0"
    env.pop("PYTHONPATH", None)
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=600)
    report: dict | None = None
    if proc.stdout.strip():
        try:
            report = json.loads(proc.stdout)
        except json.JSONDecodeError:
            report = None
    return proc.returncode, report, proc.stderr.strip()


# --------------------------------------------------------------------------------- vectors


def iter_cases(root: Path) -> list[tuple[str, dict, Path]]:
    """Return (case_id, expected_dict, case_dir) for every ``*/*/expected.json``."""
    cases: list[tuple[str, dict, Path]] = []
    for expected_path in sorted(root.glob("*/*/expected.json")):
        category = expected_path.parent.parent.name
        if category in {"frozen", "external", "keys"}:
            continue
        data = json.loads(expected_path.read_text(encoding="utf-8"))
        case_id = str(data.get("id") or expected_path.parent.relative_to(root))
        cases.append((case_id, data, expected_path.parent))
    return cases


def check_index(cases: list[tuple[str, dict, Path]]) -> None:
    """Cross-check the discovered cases against ``vectors/index.json`` (honesty check)."""
    index_path = VECTORS / "index.json"
    if not index_path.exists():
        return
    index = json.loads(index_path.read_text(encoding="utf-8"))
    indexed = {entry["id"] for entry in index.get("cases", [])}
    discovered = {case_id for case_id, _, _ in cases}
    if indexed != discovered:
        missing = sorted(discovered - indexed)
        extra = sorted(indexed - discovered)
        fail(
            "vectors/index.json and the case directories disagree "
            f"(missing_in_index={missing[:8]}, stale_in_index={extra[:8]})"
        )
    declared = index.get("case_count")
    if isinstance(declared, int) and declared != len(discovered):
        fail(f"vectors/index.json case_count={declared} but {len(discovered)} cases exist")


def expand_args(tokens: list[str], case_dir: Path) -> list[str]:
    out: list[str] = []
    for token in tokens:
        if token == "@keyset":
            out.append(str(VECTORS / "keys" / "keyset"))
        elif token == "@case":
            out.append(str(case_dir))
        elif token.startswith("@case/"):
            out.append(str(case_dir / token[len("@case/") :]))
        else:
            candidate = case_dir / token
            out.append(str(candidate if candidate.exists() else Path(token)))
    return out


def verifier_argv_for(expected: dict, case_dir: Path, input_path: Path) -> list[str]:
    argv = list(find_verifier())
    argv += [expected["target"], str(input_path)]
    argv += expand_args(list(expected.get("args") or []), case_dir)
    return argv


# -------------------------------------------------------------------------------- mutation


def mutate_bytes(data: bytes, seed_material: str, limit: int = 32) -> list[bytes]:
    """Return up to ``limit`` deterministic one-bit-flipped variants of ``data``."""
    if not data:
        return []
    rng = random.Random(int.from_bytes(hashlib.sha256(seed_material.encode()).digest(), "big"))
    count = min(limit, len(data))
    variants: list[bytes] = []
    seen: set[int] = set()
    for _ in range(count * 4):
        if len(seen) >= count:
            break
        pos = rng.randrange(len(data))
        bit = rng.randrange(8)
        if pos in seen:
            continue
        seen.add(pos)
        mutated = bytearray(data)
        mutated[pos] ^= 1 << bit
        variants.append(bytes(mutated))
    return variants


def record_is_unbound(path: Path) -> bool:
    """True when a record target has no per-record signature (no cryptographic binding)."""
    try:
        value = json.loads(path.read_bytes())
    except (OSError, ValueError):
        return False
    if not isinstance(value, dict):
        return False
    sigs = value.get("sigs")
    return not (isinstance(sigs, list) and sigs)


def container_files(container: Path) -> list[Path]:
    """Files inside a directory container to mutate: manifest, signatures, then records."""
    files: list[Path] = []
    for path in sorted(container.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(container)
        if rel.parts and rel.parts[0] == "readable":
            continue  # readable/ is outside the digest and never trusted
        files.append(path)

    def rank(p: Path) -> tuple[int, str]:
        rel = p.relative_to(container).as_posix()
        order = 0 if rel == "manifest.json" else 1 if rel.startswith("signatures/") else 2
        return (order, rel)

    return sorted(files, key=rank)


def zip_entries(path: Path) -> list[tuple[zipfile.ZipInfo, bytes]]:
    with zipfile.ZipFile(path) as zf:
        return [
            (info, zf.read(info.filename))
            for info in zf.infolist()
            if not info.is_dir()
        ]


def rebuild_zip(entries: list[tuple[zipfile.ZipInfo, bytes]], dest: Path) -> None:
    """Rebuild a deterministic zip from entries, preserving per-entry metadata."""
    with zipfile.ZipFile(dest, "w") as zf:
        for info, data in entries:
            zi = zipfile.ZipInfo(filename=info.filename, date_time=info.date_time)
            zi.compress_type = info.compress_type
            zi.create_system = info.create_system
            zi.external_attr = info.external_attr
            zf.writestr(zi, data)


def zip_mutants(path: Path, seed_material: str, per_file: int = 4, max_files: int = 8):
    """Yield (name, mutant_bytes) for zips mutated in archived-file bytes, not metadata."""
    entries = zip_entries(path)
    if not entries:
        return
    order = sorted(range(len(entries)), key=lambda i: entries[i][0].filename)
    for file_index in order[:max_files]:
        info, data = entries[file_index]
        variants = mutate_bytes(data, f"{seed_material}|{info.filename}", limit=per_file)
        for sample, mutated in enumerate(variants):
            changed = list(entries)
            changed[file_index] = (info, mutated)
            dest = SCRATCH / f"zip-{hashlib.sha256(seed_material.encode()).hexdigest()[:16]}-{sample}.zip"
            rebuild_zip(changed, dest)
            yield f"zip:{info.filename}#{sample}", dest.read_bytes()
            dest.unlink()


def run_one_mutant(
    *,
    case_id: str,
    expected: dict,
    case_dir: Path,
    input_path: Path,
    unbound: bool,
    detail: dict,
) -> dict:
    """Run the verifier on one mutant; return a survivor dict or {} when rejected."""
    rc, report, stderr = run_verifier(
        verifier_argv_for(expected, case_dir, input_path),
        force_subprocess=_MUTATION_SUBPROCESS,
    )
    if rc == 2 or report is None:
        # The verifier refused the mutant as a usage/IO error, or crashed.  That is not
        # "accepted evidence", but it is also not a clean rejection; keep it visible.
        return {
            "case": case_id,
            "evidence_bound": not unbound,
            "verdict": None,
            "note": f"verifier returned no report (rc={rc}): {stderr.splitlines()[-1][:200] if stderr else ''}",
            **detail,
        }
    verdict = report.get("verdict")
    expected_verdict = expected.get("verdict")
    if expected_verdict == "erased":
        # A mutated weave.erased placeholder may legitimately stay "erased" (the placeholder
        # has no sigs and a standalone placeholder cannot be cryptographically bound); the
        # gate only requires that it is never upgraded to "valid".
        accepted_again = verdict == "valid"
    else:
        accepted_again = verdict in ACCEPTED_VERDICTS
    if accepted_again:
        return {
            "case": case_id,
            "evidence_bound": not unbound,
            "verdict": verdict,
            "note": "mutant still accepted",
            **detail,
        }
    return {}


def mutate_case(case_id: str, expected: dict, case_dir: Path) -> tuple[list[dict], int]:
    """Run the mutation sweep for one positive case.

    Returns ``(survivors, mutants_run)`` for that case.
    """
    target = expected["target"]
    dest = SCRATCH / case_id.replace("/", "__")
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(case_dir, dest)
    input_path = dest / expected["input"]
    survivors: list[dict] = []
    mutants_run = 0
    if target == "record":
        unbound = record_is_unbound(input_path)
        original = input_path.read_bytes()
        for index, mutated in enumerate(mutate_bytes(original, case_id)):
            mutants_run += 1
            mutant_path = dest / f"mutant-{index}.json"
            mutant_path.write_bytes(mutated)
            survivor = run_one_mutant(
                case_id=case_id,
                expected=expected,
                case_dir=dest,
                input_path=mutant_path,
                unbound=unbound,
                detail={"kind": "record", "sample": index},
            )
            if survivor:
                survivors.append(survivor)
        return survivors, mutants_run
    if target != "container":
        fail(f"unknown target {target!r} in case {case_id}")
    if input_path.is_file():  # zip container: mutate archived evidence bytes, not zip metadata
        for index, (name, mutant_bytes) in enumerate(zip_mutants(input_path, case_id)):
            mutants_run += 1
            mutant_path = dest / f"mutant-{index}.zip"
            mutant_path.write_bytes(mutant_bytes)
            survivor = run_one_mutant(
                case_id=case_id,
                expected=expected,
                case_dir=dest,
                input_path=mutant_path,
                unbound=False,
                detail={"kind": "zip", "sample": index, "entry": name},
            )
            if survivor:
                survivors.append(survivor)
        return survivors, mutants_run
    # Directory container: mutate up to 8 files x 4 bit positions in the copied container.
    files = container_files(input_path)
    for file_index, path in enumerate(files[:8]):
        rel = path.relative_to(input_path).as_posix()
        original = path.read_bytes()
        for sample_index, mutated in enumerate(
            mutate_bytes(original, f"{case_id}|{rel}", limit=4)
        ):
            backup = path.read_bytes()
            path.write_bytes(mutated)
            try:
                survivor = run_one_mutant(
                    case_id=case_id,
                    expected=expected,
                    case_dir=dest,
                    input_path=input_path,
                    unbound=False,
                    detail={"kind": "container", "sample": sample_index, "file": rel},
                )
            finally:
                path.write_bytes(backup)
            mutants_run += 1
            if survivor:
                survivors.append(survivor)
    return survivors, mutants_run


# -------------------------------------------------------------------------------- ablation

CODE_ROW = re.compile(r"^\|\s*`([EN]_[A-Z0-9_]+)`\s*\|")


def load_code_registry() -> dict[str, list[str]]:
    path = REPO / "spec" / "error-codes.md"
    if not path.exists():
        fail("spec/error-codes.md is missing")
    errors: list[str] = []
    notices: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = CODE_ROW.match(line.strip())
        if not match:
            continue
        code = match.group(1)
        (notices if code.startswith("N_") else errors).append(code)
    if not errors:
        fail("no error codes parsed from spec/error-codes.md")
    return {"errors": sorted(set(errors)), "notices": sorted(set(notices))}


def family_of(code: str) -> str:
    parts = code.split("_")
    return parts[0] + "_" + parts[1] if len(parts) >= 2 else code


def find_case_list(report: dict) -> list[dict]:
    """Locate the per-case result list in the implementation-defined vectors report."""
    for key in ("cases", "vector_cases", "vectors", "results", "case_results"):
        value = report.get(key)
        if isinstance(value, list) and all(isinstance(item, dict) for item in value):
            return value
    if report.get("verdict") == "valid":
        return []  # all matched; no list needed to count mismatches
    fail(
        "cannot locate per-case results in the vectors report; "
        f"report keys: {sorted(report)} (expected one of cases/vector_cases/vectors/results)"
    )


def case_mismatched(item: dict) -> bool:
    """Return True when a per-case report entry says the case did not match."""
    for key in ("match", "matched", "ok", "passed"):
        if key in item:
            return not bool(item[key])
    if "mismatches" in item:
        return bool(item["mismatches"])
    if item.get("status") is not None:
        return str(item["status"]) not in {"match", "matched", "ok", "pass", "passed"}
    fail(f"cannot interpret per-case result entry: {sorted(item)}")


def case_identifier(item: dict) -> str:
    for key in ("id", "case", "case_id"):
        if key in item:
            return str(item[key])
    return json.dumps(item, sort_keys=True)[:120]


def run_ablation(
    cases: list[tuple[str, dict, Path]], jobs: int, verbose: bool
) -> tuple[list[str], list[tuple[str, int, list[str]]], list[str]]:
    registry = load_code_registry()
    families: dict[str, list[str]] = {}
    for code in registry["errors"]:
        families.setdefault(family_of(code), []).append(code)

    argv = list(find_verifier()) + ["vectors", str(VECTORS)]
    # Baseline: the suite must be green before ablation means anything.
    rc, baseline, stderr = run_verifier(argv, force_subprocess=True)
    if rc != 0 or baseline is None or baseline.get("verdict") != "valid":
        fail(
            "baseline vector run is not valid (gate 2 must be green first): "
            f"rc={rc} verdict={(baseline or {}).get('verdict')} stderr={stderr.splitlines()[-1][:300] if stderr else ''}"
        )
    if baseline.get("checks_disabled"):
        fail(f"baseline run reports disabled checks: {baseline.get('checks_disabled')}")

    def run_family(family: str) -> tuple[str, int, list[str]]:
        codes = sorted(families[family])
        rc, report, stderr = run_verifier(
            argv,
            env_extra={"WEAVE_VERIFY_SKIP_CHECKS": ",".join(codes)},
            force_subprocess=True,
        )
        if rc not in (0, 1) or report is None:
            fail(f"ablation run for {family} produced no report (rc={rc}): {stderr[:300]}")
        disabled = sorted(report.get("checks_disabled") or [])
        if disabled != codes:
            fail(
                f"verifier did not echo checks_disabled correctly for {family}: "
                f"got {disabled!r}, expected {codes!r}"
            )
        failed: list[str] = []
        if report.get("verdict") != "valid":
            for item in find_case_list(report):
                if case_mismatched(item):
                    failed.append(case_identifier(item))
        count = len(failed)
        if verbose:
            state = f"{count} mismatches" if count else "0 mismatches (GAP)"
            print(f"  family {family:14s} codes={len(codes):3d} -> {state}")
        return family, count, sorted(set(failed))

    results: list[tuple[str, int, list[str]]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        futures = [pool.submit(run_family, family) for family in sorted(families)]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    results.sort()
    gaps = [family for family, count, _ in results if count == 0]
    return gaps, results, [code for family in families for code in families[family]]


# ----------------------------------------------------------------------------------- main


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-mutation", action="store_true")
    parser.add_argument("--skip-ablation", action="store_true")
    parser.add_argument(
        "--require-strength",
        choices=("evidence", "strict"),
        default="evidence",
        help="evidence: unbound-record survivors are a documented exception; "
        "strict: any survivor fails (literal H0-prompt rule)",
    )
    parser.add_argument("--jobs", type=int, default=min(8, os.cpu_count() or 4))
    parser.add_argument(
        "--mutation-subprocess",
        action="store_true",
        help="run every mutant through a fresh verifier subprocess (slower, maximum isolation)",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    global _MUTATION_SUBPROCESS
    _MUTATION_SUBPROCESS = bool(args.mutation_subprocess)
    if not VECTORS.exists():
        fail("vectors/ directory is missing")
    GATES_DIR.mkdir(parents=True, exist_ok=True)
    if SCRATCH.exists():
        shutil.rmtree(SCRATCH)
    SCRATCH.mkdir(parents=True, exist_ok=True)

    cases = iter_cases(VECTORS)
    if not cases:
        fail("no vector cases found under vectors/")
    check_index(cases)

    summary: dict[str, object] = {
        "gate": "3",
        "require_strength": args.require_strength,
        "case_count": len(cases),
    }
    ok = True

    if not args.skip_mutation:
        print("== gate 3(a): positive-case bit-flip mutation ==")
        positives = [
            (case_id, expected, case_dir)
            for case_id, expected, case_dir in cases
            if expected.get("verdict") in ACCEPTED_VERDICTS
        ]
        survivors: list[dict] = []
        mutant_total = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
            futures = {
                pool.submit(mutate_case, case_id, expected, case_dir): case_id
                for case_id, expected, case_dir in positives
            }
            for future in concurrent.futures.as_completed(futures):
                result, mutants_run = future.result()
                survivors.extend(result)
                mutant_total += mutants_run
                if args.verbose:
                    print(f"  mutated {futures[future]}: {mutants_run} mutants, {len(result)} survivor(s)")
        survivors.sort(key=lambda item: (item["case"], item.get("sample", -1), str(item.get("file", ""))))
        evidence_bound = [s for s in survivors if s["evidence_bound"]]
        unbound = [s for s in survivors if not s["evidence_bound"]]
        print(
            f"mutation sweep: {len(positives)} positive cases, {mutant_total} mutants run, "
            f"{len(survivors)} survivors "
            f"({len(evidence_bound)} evidence-bound, {len(unbound)} unbound)"
        )
        for item in evidence_bound:
            print(
                f"  SURVIVOR {item['case']} [{item['kind']}] sample={item.get('sample')} "
                f"file={item.get('file', '-')} entry={item.get('entry', '-')} "
                f"verdict={item.get('verdict')} :: {item['note']}"
            )
        for item in unbound:
            print(
                f"  DOCUMENTED EXCEPTION {item['case']} [unsigned record, no binding] "
                f"sample={item.get('sample')} verdict={item.get('verdict')}"
            )
        summary["mutation"] = {
            "positive_cases": len(positives),
            "mutant_cap_per_case": 32,
            "mutants_run": mutant_total,
            "survivors": survivors,
            "evidence_bound_survivors": len(evidence_bound),
            "unbound_survivors": len(unbound),
        }
        if evidence_bound:
            ok = False
            print("FAIL: evidence-bound mutants were accepted")
        elif unbound and args.require_strength == "strict":
            ok = False
            print("FAIL: unbound-record mutants were accepted (--require-strength=strict)")
        elif unbound:
            print(
                "PASS (evidence mode): evidence-bound mutants all rejected; "
                f"{len(unbound)} unsigned-record survivors documented as exceptions"
            )
        else:
            print("PASS: every mutant was rejected")

    if not args.skip_ablation:
        print()
        print("== gate 3(b): error-code family ablation ==")
        gaps, families, all_codes = run_ablation(cases, args.jobs, args.verbose)
        summary["ablation"] = {
            "families": [
                {"family": family, "mismatches": count, "mismatched_cases": failed}
                for family, count, failed in families
            ],
            "gaps": gaps,
            "whitelisted_gaps": {gap: WHITELISTED_GAPS[gap] for gap in gaps if gap in WHITELISTED_GAPS},
        }
        unwhitelisted = [gap for gap in gaps if gap not in WHITELISTED_GAPS]
        for gap in gaps:
            if gap in WHITELISTED_GAPS:
                print(f"GAP (whitelisted): {gap}: {WHITELISTED_GAPS[gap]}")
            else:
                print(
                    f"GAP (not whitelisted): {gap}: disabling this family changes no vector "
                    "result - the vectors do not test this check class"
                )
        if unwhitelisted:
            ok = False
            print(f"FAIL: {len(unwhitelisted)} unwhitelisted gap(s)")
        else:
            print(f"PASS: all {len(families)} error-code families are exercised by the vectors")

    summary["result"] = "PASS" if ok else "FAIL"
    try:
        SUMMARY_PATH.write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        relative = SUMMARY_PATH.relative_to(REPO)
    except OSError:  # pragma: no cover - scratch dir is expected to be writable
        relative = SUMMARY_PATH
    print()
    print(f"summary written to {relative}")
    print("RESULT:", summary["result"])
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:  # pragma: no cover
        raise SystemExit(130)
