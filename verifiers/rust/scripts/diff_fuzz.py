#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0
"""Differential fuzzing of the two weave-record/1 verifiers (H1-FIX1 gate 4).

Mutants are derived from the committed conformance vectors. Mutations that
must survive the signature layer are re-signed with the published test seeds
(`vectors/keys/*.seed`), and container mutations rewrite the record file
names, the manifest entries, the manifest digest and the manifest signatures,
so the mutant reaches the deeper checks. Both verifiers run as black boxes on
every mutant with the case's own arguments; the script never imports or reads
either implementation.

Mutation classes (the H1 review A classes): bitflip, member_delete,
member_dup, number, base64, time, refs, sigs, container, zip.

Output: one JSON line per mutant in `--out` (class, case, seed, both
conclusions and exit codes, whether the normalized report bytes are equal),
and a summary on standard output.

Exit status: 1 when any mutant's conclusions differ (verdict, error codes,
notices or exit code of the two runs), 0 otherwise. Report-detail differences
with equal conclusions do not change the exit status; they are counted in
the summary (`mutants` minus `same_bytes`) and listed in `--out`.

Requires the `cryptography` package (Ed25519 signing of the test seeds only).
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import io
import json
import random
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

REPO = Path(__file__).resolve().parents[3]
VECTORS = REPO / "vectors"
CLASSES = [
    "bitflip",
    "member_delete",
    "member_dup",
    "number",
    "base64",
    "time",
    "refs",
    "sigs",
    "container",
    "zip",
]

# ---------------------------------------------------------------------------
# WR-CJ (written from §1 of the specification) and the §2 constructions
# ---------------------------------------------------------------------------


def _utf16_key(text: str) -> list[int]:
    return list(text.encode("utf-16-be"))


def _string(text: str) -> str:
    out = ['"']
    for character in text:
        code = ord(character)
        if character == '"':
            out.append('\\"')
        elif character == "\\":
            out.append("\\\\")
        elif character == "\b":
            out.append("\\b")
        elif character == "\t":
            out.append("\\t")
        elif character == "\n":
            out.append("\\n")
        elif character == "\f":
            out.append("\\f")
        elif character == "\r":
            out.append("\\r")
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(character)
    out.append('"')
    return "".join(out)


def canonical(value: object) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, list):
        return "[" + ",".join(canonical(item) for item in value) + "]"
    if isinstance(value, dict):
        members = sorted(value.items(), key=lambda item: _utf16_key(item[0]))
        return "{" + ",".join(_string(name) + ":" + canonical(item) for name, item in members) + "}"
    raise TypeError(type(value))


def canonical_bytes(value: object) -> bytes:
    return canonical(value).encode("utf-8")


def record_digest(record: dict) -> str:
    without = {name: value for name, value in record.items() if name != "sigs"}
    return "sha256:" + hashlib.sha256(b"weave-record/1/digest\n" + canonical_bytes(without)).hexdigest()


def manifest_digest(manifest: dict) -> str:
    return "sha256:" + hashlib.sha256(
        b"weave-record/1/manifest-digest\n" + canonical_bytes(manifest)
    ).hexdigest()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def load_signers() -> dict[str, Ed25519PrivateKey]:
    signers: dict[str, Ed25519PrivateKey] = {}
    for seed_path in sorted((VECTORS / "keys").glob("*.seed")):
        seed = bytes.fromhex(seed_path.read_text(encoding="ascii").strip())
        key = Ed25519PrivateKey.from_private_bytes(seed)
        public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        key_id = "ed25519:" + hashlib.sha256(public).hexdigest()[:32]
        signers[key_id] = key
    return signers


SIGNERS: dict[str, Ed25519PrivateKey] = {}


def resign_record(record: dict) -> dict:
    sigs = record.get("sigs")
    if not isinstance(sigs, list):
        return record
    message = ("weave-record/1/sig\n" + record_digest(record)).encode("ascii")
    for entry in sigs:
        if isinstance(entry, dict) and entry.get("alg") == "ed25519" and entry.get("key") in SIGNERS:
            entry["value"] = b64url(SIGNERS[entry["key"]].sign(message))
    return record


def resign_attestation(attestation: dict, digest_string: str) -> dict:
    attestation["digest"] = digest_string
    message = ("weave-record/1/manifest\n" + digest_string).encode("ascii")
    for entry in attestation.get("signatures", []):
        if isinstance(entry, dict) and entry.get("alg") == "ed25519" and entry.get("key") in SIGNERS:
            entry["value"] = b64url(SIGNERS[entry["key"]].sign(message))
    return attestation


# ---------------------------------------------------------------------------
# JSON-level mutations
# ---------------------------------------------------------------------------


def paths(value: object, prefix: tuple = ()) -> list[tuple]:
    out = [prefix]
    if isinstance(value, dict):
        for name, item in value.items():
            out.extend(paths(item, prefix + (name,)))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            out.extend(paths(item, prefix + (index,)))
    return out


def get_at(value: object, path: tuple) -> object:
    for part in path:
        value = value[part]  # type: ignore[index]
    return value


def set_at(value: object, path: tuple, new: object) -> None:
    parent = get_at(value, path[:-1])
    parent[path[-1]] = new  # type: ignore[index]


def delete_at(value: object, path: tuple) -> None:
    parent = get_at(value, path[:-1])
    del parent[path[-1]]  # type: ignore[arg-type]


def leaves(value: object, predicate) -> list[tuple]:
    return [path for path in paths(value) if path and predicate(get_at(value, path))]


TIME_VALUES = [
    "2026-11-01T00:00:00.000Z",
    "2026-10-31T23:59:59.999Z",
    "1970-01-01T00:00:00.000Z",
    "9999-12-31T23:59:59.999Z",
    "2026-11-01T00:00:00.001Z",
    "2027-01-01T00:00:00.000Z",
    "2026-02-29T00:00:00.000Z",
    "2026-11-01T00:00:60.000Z",
    "2026-11-01T00:00:00Z",
]

NUMBER_VALUES = [0, 1, -1, 2, 9007199254740991, -9007199254740991, 255, 1000, 100000]


def is_time(value: object) -> bool:
    return isinstance(value, str) and len(value) == 24 and value.endswith("Z") and value[4] == "-"


def is_b64(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) >= 16
        and all(character.isalnum() or character in "-_" for character in value)
        and not value.startswith("ed25519")
    )


def mutate_object(rng: random.Random, klass: str, record: dict) -> tuple[dict, bool]:
    """Returns the mutated object and whether to re-sign it."""
    if klass == "member_delete":
        candidates = [path for path in paths(record) if path]
        path = rng.choice(candidates)
        delete_at(record, path)
        return record, rng.random() < 0.8
    if klass == "number":
        candidates = leaves(record, lambda value: isinstance(value, int) and not isinstance(value, bool))
        if not candidates:
            candidates = [path for path in paths(record) if path]
            set_at(record, rng.choice(candidates), rng.choice(NUMBER_VALUES))
        else:
            set_at(record, rng.choice(candidates), rng.choice(NUMBER_VALUES))
        return record, True
    if klass == "base64":
        candidates = leaves(record, is_b64)
        if candidates:
            path = rng.choice(candidates)
            text = get_at(record, path)
            choice = rng.randrange(4)
            if choice == 0:
                text = text[:-1]
            elif choice == 1:
                text = text + rng.choice("AQgw")
            elif choice == 2:
                text = text + "="
            else:
                position = rng.randrange(len(text))
                text = text[:position] + rng.choice("A-_+/9") + text[position + 1 :]
            set_at(record, path, text)
        return record, True
    if klass == "time":
        candidates = leaves(record, is_time)
        if candidates:
            set_at(record, rng.choice(candidates), rng.choice(TIME_VALUES))
        return record, True
    if klass == "refs":
        refs = record.get("refs")
        choice = rng.randrange(6)
        if isinstance(refs, list) and refs:
            entry = rng.choice(refs)
            if choice == 0:
                entry["rel"] = rng.choice(["derived_from", "supersedes", "erases", "receipt_of", "x"])
            elif choice == 1 and isinstance(entry.get("ref"), dict):
                entry["ref"]["digest"] = "sha256:" + "0" * 64
            elif choice == 2 and isinstance(entry.get("ref"), dict):
                entry["ref"]["id"] = entry["ref"].get("id", "x") + "-x"
            elif choice == 3:
                refs.append(json.loads(json.dumps(entry)))
            elif choice == 4:
                refs.clear()
            elif isinstance(entry.get("ref"), dict):
                entry["ref"]["kind"] = "weave.grant"
        else:
            record["refs"] = [
                {
                    "rel": "derived_from",
                    "ref": {
                        "origin": record.get("origin", {"project": "example", "instance": "ed25519:" + "0" * 32}),
                        "id": "missing",
                        "digest": "sha256:" + "1" * 64,
                    },
                }
            ]
        return record, True
    if klass == "sigs":
        sigs = record.get("sigs")
        choice = rng.randrange(7)
        if not isinstance(sigs, list):
            record["sigs"] = []
            return record, False
        if choice == 0 and len(sigs) >= 2:
            sigs[0], sigs[1] = sigs[1], sigs[0]
            return record, False
        if choice == 1 and sigs:
            sigs.append(json.loads(json.dumps(sigs[0])))
            return record, False
        if choice == 2 and sigs:
            del sigs[rng.randrange(len(sigs))]
            return record, False
        if choice == 3:
            record["sigs"] = []
            return record, False
        if choice == 4:
            other = rng.choice(sorted(SIGNERS))
            if sigs:
                sigs[0]["key"] = other
            else:
                sigs.append({"alg": "ed25519", "key": other, "value": ""})
            sigs.sort(key=lambda entry: entry.get("key", ""))
            return record, True
        if choice == 5:
            sigs.append({"alg": "example-sig", "key": "example-sig:abcd", "value": b64url(b"x" * 32)})
            sigs.sort(key=lambda entry: entry.get("key", ""))
            return record, rng.random() < 0.5
        if sigs:
            sigs[0]["alg"] = rng.choice(["ed25518", "rsa", "Ed25519", "ed25519-x"])
        return record, False
    raise ValueError(klass)


def member_dup(rng: random.Random, data: bytes) -> bytes:
    """Inserts a duplicate member name at the text level (canonical position
    is not preserved; the parser classifies first violation in byte order)."""
    text = data.decode("utf-8", "replace")
    positions = [index for index, character in enumerate(text) if character == "{"]
    if not positions:
        return data
    position = rng.choice(positions)
    end = text.find(":", position)
    if end < 0:
        return data
    name = text[position + 1 : end]
    if not name.startswith('"'):
        return data
    insertion = name + ":" + rng.choice(["1", '"x"', "null", "1.5", "-0"]) + ","
    return (text[: position + 1] + insertion + text[position + 1 :]).encode("utf-8")


def bitflip(rng: random.Random, data: bytes) -> bytes:
    buffer = bytearray(data)
    if not buffer:
        return data
    for _ in range(rng.randint(1, 3)):
        position = rng.randrange(len(buffer))
        buffer[position] ^= 1 << rng.randrange(8)
    return bytes(buffer)


def mutate_record_bytes(rng: random.Random, klass: str, data: bytes) -> bytes:
    if klass == "bitflip":
        return bitflip(rng, data)
    if klass == "member_dup":
        return member_dup(rng, data)
    try:
        record = json.loads(data)
        if not isinstance(record, dict):
            return bitflip(rng, data)
        record, resign = mutate_object(rng, klass, record)
        if resign:
            record = resign_record(record)
        return canonical_bytes(record) + b"\n"
    except (ValueError, TypeError, KeyError, IndexError, RecursionError):
        # Inputs outside WR-CJ (floats, deep nesting): byte-level edit instead.
        return bitflip(rng, data)


# ---------------------------------------------------------------------------
# Container rewriting
# ---------------------------------------------------------------------------


def rewrite_container(directory: Path, record_edits: dict[str, bytes], resign: bool = True) -> None:
    """Applies record-file edits and rewrites names, manifest and attestation."""
    manifest_path = directory / "manifest.json"
    sig_path = directory / "signatures" / "manifest.sig.json"
    try:
        manifest = json.loads(manifest_path.read_bytes())
    except (OSError, ValueError):
        manifest = None
    renames: dict[str, str] = {}
    for relative, new_bytes in record_edits.items():
        old_path = directory / relative
        if old_path.exists():
            old_path.unlink()
        try:
            new_record = json.loads(new_bytes)
            new_digest = record_digest(new_record) if isinstance(new_record, dict) else None
        except ValueError:
            new_digest = None
        if new_digest is None:
            (directory / relative).write_bytes(new_bytes)
            continue
        new_relative = "records/" + new_digest.split(":", 1)[1] + ".json"
        (directory / new_relative).write_bytes(new_bytes)
        renames[relative] = (new_relative, new_digest, new_record)  # type: ignore[assignment]
    if not isinstance(manifest, dict) or not resign:
        return
    records = manifest.get("records")
    if isinstance(records, list):
        for entry in records:
            if not isinstance(entry, dict):
                continue
            old_relative = "records/" + str(entry.get("digest", "")).split(":", 1)[-1] + ".json"
            if old_relative in renames:
                new_relative, new_digest, new_record = renames[old_relative]  # type: ignore[misc]
                entry["digest"] = new_digest
                if isinstance(new_record.get("id"), str):
                    entry["id"] = new_record["id"]
                if isinstance(new_record.get("kind"), str):
                    entry["kind"] = new_record["kind"]
        records.sort(key=lambda entry: entry.get("digest", "") if isinstance(entry, dict) else "")
    write_manifest(directory, manifest, sig_path)


def write_manifest(directory: Path, manifest: dict, sig_path: Path) -> None:
    (directory / "manifest.json").write_bytes(canonical_bytes(manifest) + b"\n")
    try:
        attestation = json.loads(sig_path.read_bytes())
    except (OSError, ValueError):
        return
    if isinstance(attestation, dict):
        resign_attestation(attestation, manifest_digest(manifest))
        sig_path.write_bytes(canonical_bytes(attestation) + b"\n")


def container_mutation(rng: random.Random, directory: Path) -> str:
    files = sorted(path for path in directory.rglob("*") if path.is_file() and not path.is_symlink())
    choice = rng.randrange(6)
    if choice == 0 and files:
        victim = rng.choice(files)
        victim.unlink()
        return f"delete {victim.relative_to(directory)}"
    if choice == 1:
        name = rng.choice(["records/extra.json", "blobs/sha256/" + "a" * 64, "unknown.txt", "readable/x.txt", "signatures/timestamp-9.tsr", "previous/manifest.json"])
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"{}\n")
        return f"add {name}"
    if choice == 2 and files:
        victim = rng.choice(files)
        new = victim.with_name(victim.name.upper())
        victim.rename(new)
        return f"rename {victim.relative_to(directory)}"
    manifest_path = directory / "manifest.json"
    sig_path = directory / "signatures" / "manifest.sig.json"
    try:
        manifest = json.loads(manifest_path.read_bytes())
    except (OSError, ValueError):
        return "noop"
    if not isinstance(manifest, dict):
        return "noop"
    if choice == 3:
        manifest["level"] = rng.choice(["L0", "L1", "L2", "L3"])
    elif choice == 4 and isinstance(manifest.get("records"), list) and manifest["records"]:
        entry = rng.choice(manifest["records"])
        if isinstance(entry, dict):
            entry[rng.choice(["id", "kind", "chain_index"])] = rng.choice(["x", 0, "weave.grant"])
    else:
        manifest["created_at"] = rng.choice(TIME_VALUES)
    write_manifest(directory, manifest, sig_path)
    return "manifest edit"


def zip_variant(rng: random.Random, directory: Path) -> bytes:
    """Builds a zip of the container directory with one of several framing
    variations."""
    files = sorted(path for path in directory.rglob("*") if path.is_file())
    buffer = io.BytesIO()
    choice = rng.randrange(10)
    compression = zipfile.ZIP_DEFLATED if choice % 2 else zipfile.ZIP_STORED
    with zipfile.ZipFile(buffer, "w", compression=compression, allowZip64=choice == 9) as archive:
        if choice == 3:
            archive.writestr("records/", b"")
        for path in files:
            name = path.relative_to(directory).as_posix()
            if choice == 4:
                name = "./" + name
            archive.writestr(name, path.read_bytes())
        if choice == 5 and files:
            archive.writestr(files[0].relative_to(directory).as_posix() + "x", b"")
        if choice == 6:
            archive.comment = b"comment"
    data = buffer.getvalue()
    if choice == 7:
        data = b"PREFIX" + data
    if choice == 8:
        data = data + b"\0" * rng.randint(1, 8)
    return data


# ---------------------------------------------------------------------------
# Running
# ---------------------------------------------------------------------------


def load_cases() -> list[dict]:
    cases = []
    for expected_path in sorted(VECTORS.glob("*/*/expected.json")):
        if expected_path.parts[-3] in ("frozen", "external", "keys"):
            continue
        expected = json.loads(expected_path.read_text(encoding="utf-8"))
        expected["_dir"] = str(expected_path.parent)
        cases.append(expected)
    return cases


def resolve_args(case: dict, case_dir: Path) -> list[str]:
    out = []
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


def conclusion(stdout: bytes) -> dict | None:
    try:
        report = json.loads(stdout)
    except ValueError:
        return None
    if not isinstance(report, dict):
        return None
    errors = set(report.get("container", {}).get("errors", []) if isinstance(report.get("container"), dict) else [])
    notices = set(report.get("container", {}).get("notices", []) if isinstance(report.get("container"), dict) else [])
    for record in report.get("records", []):
        errors.update(record.get("errors", []))
        notices.update(record.get("notices", []))
    report.pop("verifier", None)
    return {
        "verdict": report.get("verdict"),
        "errors": sorted(errors),
        "notices": sorted(notices),
        "limitations": report.get("limitations"),
        "normalized": json.dumps(report, sort_keys=True),
    }


def make_mutant(case: dict, klass: str, seed: int, workdir: Path) -> tuple[list[str], str] | None:
    rng = random.Random(seed)
    case_dir = Path(case["_dir"])
    mutated = workdir / "case"
    shutil.copytree(case_dir, mutated, symlinks=True)
    input_path = mutated / case["input"]
    args = resolve_args(case, mutated)
    target = case["target"]
    if target == "record":
        if klass in ("container", "zip"):
            return None
        input_path.write_bytes(mutate_record_bytes(rng, klass, input_path.read_bytes()))
        return [target, str(input_path), *args], klass
    # Container cases.
    if input_path.is_file():
        # A zip input: byte-level mutations only.
        if klass not in ("bitflip", "zip"):
            return None
        data = input_path.read_bytes()
        input_path.write_bytes(bitflip(rng, data) if klass == "bitflip" else data[:-1] if rng.random() < 0.5 else b"X" + data)
        return [target, str(input_path), *args], klass
    if klass == "container":
        description = container_mutation(rng, input_path)
        return [target, str(input_path), *args], f"container: {description}"
    if klass == "zip":
        zip_path = workdir / "container.zip"
        zip_path.write_bytes(zip_variant(rng, input_path))
        return [target, str(zip_path), *args], "zip"
    record_files = sorted((input_path / "records").glob("*.json")) if (input_path / "records").is_dir() else []
    if not record_files:
        return None
    victim = rng.choice(record_files)
    relative = victim.relative_to(input_path).as_posix()
    new_bytes = mutate_record_bytes(rng, klass, victim.read_bytes())
    if klass in ("bitflip", "member_dup"):
        victim.write_bytes(new_bytes)
        # Keep the manifest consistent only for re-signed classes.
    else:
        rewrite_container(input_path, {relative: new_bytes})
    return [target, str(input_path), *args], f"{klass}: {relative}"


def run_both(case: dict, klass: str, seed: int, rust: Path, python: list[str], timeout: float) -> dict | None:
    with tempfile.TemporaryDirectory(prefix="h1-diff-fuzz-") as raw:
        workdir = Path(raw)
        try:
            made = make_mutant(case, klass, seed, workdir)
        except (ValueError, TypeError, KeyError, IndexError, RecursionError, OSError):
            made = None
        if made is None:
            return None
        argv, description = made
        results = {}
        for name, command in (("rust", [str(rust)]), ("python", python)):
            try:
                completed = subprocess.run(command + argv, capture_output=True, timeout=timeout, check=False)
                results[name] = {
                    "exit": completed.returncode,
                    "conclusion": conclusion(completed.stdout),
                    "stderr": completed.stderr.decode("utf-8", "replace")[-300:],
                }
            except subprocess.TimeoutExpired:
                results[name] = {"exit": "timeout", "conclusion": None, "stderr": ""}
        # Keep the mutant bytes of a disagreement for reproduction.
        rust_c = results["rust"]["conclusion"]
        python_c = results["python"]["conclusion"]
        same_conclusion = (
            rust_c is not None
            and python_c is not None
            and (rust_c["verdict"], rust_c["errors"], rust_c["notices"])
            == (python_c["verdict"], python_c["errors"], python_c["notices"])
            and results["rust"]["exit"] == results["python"]["exit"]
        )
        same_bytes = rust_c is not None and python_c is not None and rust_c["normalized"] == python_c["normalized"]
        return {
            "case": case["id"],
            "class": klass,
            "seed": seed,
            "description": description,
            "rust": {key: value for key, value in results["rust"].items() if key != "conclusion"}
            | {"conclusion": {k: v for k, v in (rust_c or {}).items() if k != "normalized"}},
            "python": {key: value for key, value in results["python"].items() if key != "conclusion"}
            | {"conclusion": {k: v for k, v in (python_c or {}).items() if k != "normalized"}},
            "same_conclusion": same_conclusion,
            "same_bytes": same_bytes,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument("--python", required=True, help="Python CLI command prefix, e.g. '/venv/bin/hyphaweave-verify'")
    parser.add_argument("--per-class", type=int, default=400)
    parser.add_argument("--seed", type=int, default=20261114)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--out", type=Path, required=True)
    options = parser.parse_args()
    SIGNERS.update(load_signers())
    cases = load_cases()
    master = random.Random(options.seed)
    plan = []
    for klass in CLASSES:
        produced = 0
        attempts = 0
        while produced < options.per_class and attempts < options.per_class * 20:
            attempts += 1
            case = master.choice(cases)
            if klass in ("container", "zip") and case["target"] != "container":
                continue
            plan.append((case, klass, master.randrange(1 << 62)))
            produced += 1
    python_command = options.python.split()
    totals = {"mutants": 0, "same_conclusion": 0, "same_bytes": 0, "skipped": 0}
    with options.out.open("w", encoding="utf-8") as out, concurrent.futures.ThreadPoolExecutor(
        max_workers=max(1, min(options.jobs, 2))
    ) as pool:
        futures = [
            pool.submit(run_both, case, klass, seed, options.rust, python_command, options.timeout)
            for case, klass, seed in plan
        ]
        for future in futures:
            result = future.result()
            if result is None:
                totals["skipped"] += 1
                continue
            totals["mutants"] += 1
            totals["same_conclusion"] += int(result["same_conclusion"])
            totals["same_bytes"] += int(result["same_bytes"])
            out.write(json.dumps(result, sort_keys=True) + "\n")
    print(json.dumps(totals))
    return 1 if totals["same_conclusion"] != totals["mutants"] else 0


if __name__ == "__main__":
    sys.exit(main())
