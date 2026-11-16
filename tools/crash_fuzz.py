#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0
"""Crash-fuzz gate: deterministic crash fuzzing of the Python verifier.

The gate feeds the verifier a fixed batch of malformed inputs and requires that
**every** mutant is rejected *cleanly*: the process exit code must be one of
``0``/``1``/``2`` and nothing may be written to stderr that contains a
``Traceback``. Exit code ``3`` belongs to the §14.7 test-only check hook, which
is only active behind ``--test-hooks``; the gate never passes that switch, so a
``3`` here is a failure (S2, the same accepted set as the Rust crash-fuzz gate). An escaping exception is a crash and makes the gate fail; a crash
is never an accepted rejection (spec S1-FIX3 V2d).

Input classes (each ``--count`` >= 300 deterministic mutants that actually change
the input; the CI seed is ``20261111``, and ``--seed S`` runs another
deterministic batch, so a crash found with any seed is reproducible with that
seed):

* ``container-dir`` - a directory-form container with a mutated member;
* ``container-zip`` - a zip-form container with mutated bytes/zip fields;
* ``previous``     - a supplied ``--previous`` container (stored and deflate zip
  and directory forms) with a mutated member;
* ``tsa``          - a ``.tsr`` receipt mutated and its (unsigned) attestation
  digest re-pointed, so the mutation reaches strict DER parsing;
* ``keyset``       - a local keyset whose files are mutated;
* ``record``       - a single record target mutated byte-wise or structurally.

Mutation operations are deterministic in ``(seed, class, index)``: byte
set/flip/truncate/insert/delete/duplicate, JSON structure mutations
(delete/replace/add member, type change, deep nesting, duplicate key) and zip
header-field mutations. A **no-op mutant** — one whose files, after the mutation,
are byte-for-byte identical to the base case (for example a DER ``NULL`` written
over an existing ``05 00``) — is not run and not counted (S1-FIX4 W11): further
indices of the same class are drawn, in order, until ``--count`` effective mutants
exist, so the batch stays deterministic.

Every mutant is executed through the **real CLI process** (``python -m
hyphaweave_verify.cli``): the gate observes the process exit code and stderr, so
a crash is exactly what a user would see. The criterion is the S1-FIX3 V8 rule:
the exit code must be in ``{0, 1, 2}`` and stderr must not contain
``Traceback``; anything else (including a timeout or a signal) is a crash and
fails the gate. A crash is never an accepted rejection.

The committed regression corpus under ``tools/crash_corpus/`` holds the 145
crash inputs found by the S1-FIX2 recheck (6 ``previous`` + 139 ``tsa``) and the
``--tsa-trust`` PEM with an invalid certificate version found by the S1-FIX3
recheck with seed 777 (S1-FIX4 W4), plus the eight record-body crash inputs of the
H1 findings F51, F61-2 and F67 (S2; the committed ``key-lifecycle/crash-*`` vectors
replayed as-is), and the two keyset files with ``"sigs": []`` of S2-FIX1 T5 (a
usage error, replayed through a private keyset copy, ``keyset_overlay``); every run
replays it first and requires zero crashes. ``index.json`` records the original seed/category/index for
traceability.

Load: every worker runs one CLI subprocess at a time. When this gate runs next
to the other gates on one machine, use ``--jobs 2`` (see ``tools/README.md``).

Usage:
    python tools/crash_fuzz.py [--classes a,b,...] [--count N] [--seed S]
                               [--jsonl PATH] [--jobs N] [--corpus-only]
                               [--no-corpus] [--keep]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing
import os
import random
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
VECTORS = REPO / "vectors"
KEYSET = VECTORS / "keys" / "keyset"
CORPUS = REPO / "tools" / "crash_corpus"
TMP_ROOT = REPO / ".tmp-work" / "crash-fuzz"

DEFAULT_SEED = 20261111
DEFAULT_COUNT = 300
#: §14.8: 0 valid, 1 invalid/unverifiable, 2 usage error. 3 is the §14.7 test-only
#: hook, reachable only with ``--test-hooks``, which this gate never passes (S2).
ACCEPTED_EXIT_CODES = (0, 1, 2)

#: Fixed base cases per class (all committed conformance vectors).
BASE_CASES: dict[str, list[str]] = {
    "container-dir": [
        "actor/agent-accepted-valid",
        "container/chain-valid",
        "key-lifecycle/mixed-revocation-compromise-then-retired",
        "integrity-levels/l2-valid",
        "key-lifecycle/rotation-declares-new-key-valid",
    ],
    "container-zip": [
        "container/zip-valid",
        "container/zip64-valid",
        "container/zip-data-descriptor-valid",
        "container/readable-declared-size-excluded",
    ],
    "previous": [
        "container/previous-zip-valid",
        "container/previous-zip-deflate-valid",
        "container/previous-ignores-extra-directory-file",
    ],
    "tsa": [
        "integrity-levels/l2-valid",
        "integrity-levels/l2-renewal-chain-valid",
        "integrity-levels/l2-submillisecond-rescue",
        "key-lifecycle/compromise-rescued-by-timestamp",
        "key-lifecycle/mixed-revocation-compromise-then-retired",
    ],
    "keyset": [
        "actor/agent-accepted-valid",
        "integrity-levels/l2-valid",
        "container/zip-valid",
    ],
    "record": [
        "actor/device-valid",
        "actor/human-valid",
        "key-lifecycle/declared-valid",
    ],
}


# ---------------------------------------------------------------------------
# Case helpers
# ---------------------------------------------------------------------------


def load_case(case_id: str) -> dict:
    return json.loads((VECTORS / case_id / "expected.json").read_text(encoding="utf-8"))


def expand_args(expected: dict, case_dir: Path, keyset: Path) -> list[str]:
    argv: list[str] = [expected["target"], str(case_dir / expected["input"])]
    args = expected.get("args") or []
    for index in range(0, len(args), 2):
        token, value = args[index], args[index + 1]
        resolved = str(keyset) if value == "@keyset" else str(case_dir / value)
        argv += [token, resolved]
    return argv


def copy_case(case_id: str, destination: Path) -> Path:
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(VECTORS / case_id, destination, symlinks=True)
    return destination


# ---------------------------------------------------------------------------
# Mutation primitives (deterministic from the caller's rng)
# ---------------------------------------------------------------------------

JSON_REPLACEMENTS = [
    None,
    True,
    False,
    0,
    -1,
    1.5,
    2**64,
    -(2**63) - 1,
    "",
    "x",
    "\u0000",
    [],
    {},
    "sha256:" + "0" * 64,
    "2026-13-45T99:99:99Z",
    "A" * 5000,
]


def byte_mutation(data: bytes, rng: random.Random, region: tuple[int, int] | None = None) -> tuple[bytes, str]:
    b = bytearray(data)
    lo, hi = region if region else (0, len(b))
    hi = max(lo, min(hi, len(b)))
    op = rng.choice(["set", "set", "flip", "multi", "truncate", "insert", "delete", "dup"])
    if not b:
        return bytes([rng.randrange(256)]), "empty-insert"
    if op == "set":
        i = rng.randrange(lo, max(lo + 1, hi))
        b[i] = rng.randrange(256)
        return bytes(b), "set@%d" % i
    if op == "flip":
        i = rng.randrange(lo, max(lo + 1, hi))
        b[i] ^= 1 << rng.randrange(8)
        return bytes(b), "flip@%d" % i
    if op == "multi":
        k = rng.randint(2, 8)
        for _ in range(k):
            i = rng.randrange(lo, max(lo + 1, hi))
            b[i] = rng.choice([0, 0xFF, rng.randrange(256)])
        return bytes(b), "multi%d" % k
    if op == "truncate":
        i = rng.randrange(0, len(b))
        return bytes(b[:i]), "truncate@%d" % i
    if op == "insert":
        i = rng.randrange(0, len(b) + 1)
        ins = bytes(rng.randrange(256) for _ in range(rng.randint(1, 16)))
        return bytes(b[:i] + ins + b[i:]), "insert@%d" % i
    if op == "delete":
        i = rng.randrange(0, len(b))
        j = min(len(b), i + rng.randint(1, 16))
        return bytes(b[:i] + b[j:]), "delete@%d" % i
    i = rng.randrange(0, len(b))
    j = min(len(b), i + rng.randint(1, 64))
    return bytes(b[:j] + b[i:j] + b[j:]), "dup@%d" % i


def _walk_json(value, path=()):
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _walk_json(child, path + (key,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_json(child, path + (index,))


def json_mutation(data: bytes, rng: random.Random) -> tuple[bytes, str] | None:
    try:
        value = json.loads(data)
    except ValueError:
        return None
    nodes = list(_walk_json(value))
    path, node = rng.choice(nodes)
    op = rng.choice(["replace", "replace", "replace", "delete", "add", "wrap", "deep", "dupkey"])

    def set_at(root, at, new):
        if not at:
            return new
        current = root
        for key in at[:-1]:
            current = current[key]
        current[at[-1]] = new
        return root

    if op == "replace":
        replacement = rng.choice(JSON_REPLACEMENTS)
        value = set_at(value, path, replacement)
        desc = "replace %s" % (list(path),)
    elif op == "delete" and path:
        current = value
        for key in path[:-1]:
            current = current[key]
        del current[path[-1]]
        desc = "delete %s" % (list(path),)
    elif op == "add" and isinstance(node, dict):
        node[rng.choice(["zz", "sigs", "kind", "timestamps", "digest", "a"])] = rng.choice(
            JSON_REPLACEMENTS
        )
        desc = "add-key %s" % (list(path),)
    elif op == "wrap":
        value = set_at(value, path, rng.choice([[node], {"v": node}]))
        desc = "wrap %s" % (list(path),)
    elif op == "deep":
        deep = 0
        for _ in range(rng.choice([40, 200, 5000])):
            deep = [deep]
        value = set_at(value, path, deep)
        desc = "deep %s" % (list(path),)
    else:
        text = json.dumps(value, ensure_ascii=False)
        if text.startswith("{") and len(text) > 2 and isinstance(value, dict) and value:
            first_key = next(iter(value))
            text = "{" + json.dumps(first_key) + ":1," + text[1:]
            return text.encode("utf-8"), "dupkey"
        desc = "noop"
    out = json.dumps(value, separators=(",", ":"), ensure_ascii=False, sort_keys=True)
    return out.encode("utf-8"), desc


def zip_fields(data: bytes) -> list[tuple[int, int, str]]:
    fields: list[tuple[int, int, str]] = []
    i = 0
    while True:
        j = data.find(b"PK", i)
        if j < 0 or j + 4 > len(data):
            break
        signature = data[j : j + 4]
        if signature == b"PK\x03\x04":
            for off, width, name in (
                (4, 2, "ver"),
                (6, 2, "flags"),
                (8, 2, "method"),
                (14, 4, "crc"),
                (18, 4, "csize"),
                (22, 4, "usize"),
                (26, 2, "namelen"),
                (28, 2, "extralen"),
            ):
                fields.append((j + off, width, "local." + name))
        elif signature == b"PK\x01\x02":
            for off, width, name in (
                (4, 2, "vermade"),
                (6, 2, "ver"),
                (8, 2, "flags"),
                (10, 2, "method"),
                (16, 4, "crc"),
                (20, 4, "csize"),
                (24, 4, "usize"),
                (28, 2, "namelen"),
                (30, 2, "extralen"),
                (32, 2, "commentlen"),
                (34, 2, "disk"),
                (38, 4, "extattr"),
                (42, 4, "lho"),
            ):
                fields.append((j + off, width, "central." + name))
        elif signature == b"PK\x05\x06":
            for off, width, name in (
                (4, 2, "disk"),
                (6, 2, "cddisk"),
                (8, 2, "ndisk"),
                (10, 2, "ntotal"),
                (12, 4, "cdsize"),
                (16, 4, "cdoff"),
                (20, 2, "commentlen"),
            ):
                fields.append((j + off, width, "eocd." + name))
        elif signature == b"PK\x06\x06":
            for off, width, name in (
                (4, 8, "size"),
                (12, 2, "vermade"),
                (14, 2, "ver"),
                (16, 4, "disk"),
                (20, 4, "cddisk"),
                (24, 8, "ndisk"),
                (32, 8, "ntotal"),
                (40, 8, "cdsize"),
                (48, 8, "cdoff"),
            ):
                fields.append((j + off, width, "z64eocd." + name))
        elif signature == b"PK\x06\x07":
            for off, width, name in ((4, 4, "disk"), (8, 8, "off"), (16, 4, "ndisks")):
                fields.append((j + off, width, "z64loc." + name))
        elif signature == b"PK\x07\x08":
            for off, width, name in ((4, 4, "crc"), (8, 4, "csize"), (12, 4, "usize")):
                fields.append((j + off, width, "dd." + name))
        i = j + 2
    return [field for field in fields if field[0] + field[1] <= len(data)]


INTERESTING_INTS = [0, 1, 2, 0x7F, 0x80, 0xFF, 0xFFFF, 0xFFFE, 0x7FFFFFFF, 0xFFFFFFFF]


def zip_mutation(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    fields = zip_fields(data)
    if fields and rng.random() < 0.7:
        off, width, name = rng.choice(fields)
        current = int.from_bytes(data[off : off + width], "little")
        mask = (1 << (8 * width)) - 1
        new = rng.choice(
            INTERESTING_INTS
            + [current + 1, current - 1, current + 30, current * 2, rng.randrange(mask + 1)]
        ) & mask
        mutated = bytearray(data)
        mutated[off : off + width] = new.to_bytes(width, "little")
        return bytes(mutated), "%s@%d %d->%d" % (name, off, current, new)
    return byte_mutation(data, rng)


def der_nodes(data: bytes, start=0, end=None, depth=0, out=None):
    if out is None:
        out = []
    end = len(data) if end is None else end
    i = start
    while i < end and depth < 40:
        tag_off = i
        tag = data[i]
        i += 1
        if tag & 0x1F == 0x1F:
            while i < end and data[i] & 0x80:
                i += 1
            i += 1
        if i >= end:
            break
        len_off = i
        first = data[i]
        i += 1
        if first & 0x80:
            count = first & 0x7F
            if count == 0 or count > 4 or i + count > end:
                break
            length = int.from_bytes(data[i : i + count], "big")
            i += count
        else:
            length = first
        if i + length > end:
            break
        constructed = bool(tag & 0x20)
        out.append((tag_off, len_off, i, i + length, constructed))
        if constructed:
            der_nodes(data, i, i + length, depth + 1, out)
        elif tag == 0x04 and length > 2 and data[i] in (0x30, 0x31):
            der_nodes(data, i, i + length, depth + 1, out)
        i += length
    return out


def der_mutation(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    nodes = der_nodes(data)
    if not nodes or rng.random() < 0.25:
        return byte_mutation(data, rng)
    tag_off, len_off, content_start, content_end, _constructed = rng.choice(nodes)
    mutated = bytearray(data)
    op = rng.choice(
        ["tag", "len", "len_long", "content", "empty", "truncate_content", "indef", "null_tag"]
    )
    if op == "tag":
        mutated[tag_off] = rng.choice(
            [0x02, 0x04, 0x05, 0x06, 0x0C, 0x13, 0x17, 0x18, 0x30, 0x31, 0xA0, 0xA3, 0x80,
             rng.randrange(256)]
        )
        return bytes(mutated), "der-tag@%d" % tag_off
    if op == "len":
        if mutated[len_off] < 0x80:
            mutated[len_off] = max(0, min(0x7F, mutated[len_off] + rng.choice([-2, -1, 1, 2])))
        else:
            count = mutated[len_off] & 0x7F
            value = int.from_bytes(mutated[len_off + 1 : len_off + 1 + count], "big")
            value = max(0, min((1 << (8 * count)) - 1, value + rng.choice([-1, 1])))
            mutated[len_off + 1 : len_off + 1 + count] = value.to_bytes(count, "big")
        return bytes(mutated), "der-len@%d" % len_off
    if op == "len_long":
        new = bytes([0x84, 0xFF, 0xFF, 0xFF, 0xF0])
        return bytes(mutated[:len_off] + new + mutated[content_start:]), "der-len-huge@%d" % len_off
    if op == "indef":
        return bytes(mutated[:len_off] + b"\x80" + mutated[content_start:]), "der-indef@%d" % len_off
    if op == "content" and content_end > content_start:
        point = rng.randrange(content_start, content_end)
        mutated[point] = rng.randrange(256)
        return bytes(mutated), "der-content@%d" % point
    if op == "empty":
        return bytes(mutated[:len_off] + b"\x00" + mutated[content_end:]), "der-empty@%d" % tag_off
    if op == "truncate_content" and content_end > content_start:
        return bytes(mutated[: content_start + (content_end - content_start) // 2]), "der-trunc@%d" % content_start
    return bytes(mutated[:tag_off] + b"\x05\x00" + mutated[content_end:]), "der-null@%d" % tag_off


def pem_mutation(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    import base64

    text = data.decode("ascii", "replace")
    blocks = text.split("-----BEGIN CERTIFICATE-----")
    if len(blocks) < 2 or rng.random() < 0.2:
        return byte_mutation(data, rng)
    index = rng.randrange(1, len(blocks))
    body, _, rest = blocks[index].partition("-----END CERTIFICATE-----")
    try:
        der = base64.b64decode("".join(body.split()))
    except ValueError:
        return byte_mutation(data, rng)
    mutated, desc = der_mutation(der, rng)
    encoded = base64.encodebytes(mutated).decode()
    blocks[index] = "\n" + encoded + "-----END CERTIFICATE-----" + rest
    return "-----BEGIN CERTIFICATE-----".join(blocks).encode(), "pem:" + desc


def filesystem_mutation(root: Path, rng: random.Random) -> str:
    files = sorted(path for path in root.rglob("*") if path.is_file())
    target = rng.choice(files)
    op = rng.choice(["to_dir", "delete", "empty", "symlink_missing", "extra_file", "extra_dir"])
    relative = target.relative_to(root)
    if op == "to_dir":
        target.unlink()
        target.mkdir()
        (target / "x.json").write_text("{}")
    elif op == "delete":
        target.unlink()
    elif op == "empty":
        target.write_bytes(b"")
    elif op == "symlink_missing":
        target.unlink()
        target.symlink_to(root / "does-not-exist")
    elif op == "extra_file":
        (target.parent / rng.choice(["zz.json", "x.tsr", ".hidden", "a b.json"])).write_bytes(
            rng.choice([b"{}", b"\x00\xff", b"[]", b"null", b'{"kind":1}'])
        )
    else:
        (target.parent / "subdir").mkdir(exist_ok=True)
        (target.parent / "subdir" / "y.json").write_text("{}")
    return "%s %s" % (op, relative)


# ---------------------------------------------------------------------------
# Job construction
# ---------------------------------------------------------------------------


def _rng(category: str, index: int, seed: int) -> random.Random:
    return random.Random("%d-%s-%d" % (seed, category, index))


def _mutate_json_or_bytes(path: Path, rng: random.Random) -> str:
    original = path.read_bytes()
    result = json_mutation(original, rng) if rng.random() < 0.75 else None
    mutated, desc = result if result else byte_mutation(original, rng)
    path.write_bytes(mutated)
    return desc


def _tree_fingerprint(root: Path) -> str:
    """Digest of a directory tree: relative paths, entry types, bytes, link targets."""
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix().encode("utf-8", "surrogateescape")
        if path.is_symlink():
            digest.update(b"L" + relative + b"\0" + os.readlink(path).encode("utf-8", "surrogateescape"))
        elif path.is_dir():
            digest.update(b"D" + relative)
        elif path.is_file():
            digest.update(b"F" + relative + b"\0" + hashlib.sha256(path.read_bytes()).digest())
        else:
            digest.update(b"O" + relative)
        digest.update(b"\n")
    return digest.hexdigest()


def build_job(category: str, index: int, seed: int, work_root: Path) -> dict:
    rng = _rng(category, index, seed)
    bases = BASE_CASES[category]
    base_case = rng.choice(bases)
    job_dir = work_root / "jobs" / category / ("%05d" % index)
    copy_case(base_case, job_dir)
    expected = load_case(base_case)
    keyset = KEYSET
    desc = base_case
    if category == "keyset":
        # The keyset class mutates a private copy; fingerprint it with the case.
        private_keyset = job_dir / "_keyset"
        if private_keyset.exists():
            shutil.rmtree(private_keyset)
        shutil.copytree(KEYSET, private_keyset)
    before = _tree_fingerprint(job_dir)

    if category == "container-dir":
        container = job_dir / expected["input"]
        if rng.random() < 0.2:
            desc += " | " + filesystem_mutation(container, rng)
        else:
            files = sorted(path for path in container.rglob("*") if path.is_file())
            target = rng.choice(files)
            desc += " | %s %s" % (target.relative_to(container), _mutate_json_or_bytes(target, rng))
    elif category == "container-zip":
        archive = job_dir / expected["input"]
        mutated, desc_op = zip_mutation(archive.read_bytes(), rng)
        archive.write_bytes(mutated)
        desc += " | " + desc_op
    elif category == "previous":
        previous_value = expected["args"][expected["args"].index("--previous") + 1]
        previous = job_dir / previous_value
        if previous.is_dir():
            desc += " | " + filesystem_mutation(previous, rng) if rng.random() < 0.3 else " | " + _mutate_previous_dir(previous, rng)
        else:
            mutated, desc_op = zip_mutation(previous.read_bytes(), rng)
            previous.write_bytes(mutated)
            desc += " | " + desc_op
    elif category == "tsa":
        container = job_dir / expected["input"]
        receipts = sorted(container.rglob("*.tsr"))
        trust_path = job_dir / expected["args"][expected["args"].index("--tsa-trust") + 1]
        if rng.random() < 0.2:
            mutated, desc_op = pem_mutation(trust_path.read_bytes(), rng)
            trust_path.write_bytes(mutated)
            desc += " | pem " + desc_op
        else:
            receipt = rng.choice(receipts)
            mutated, desc_op = der_mutation(receipt.read_bytes(), rng)
            receipt.write_bytes(mutated)
            desc += " | %s %s" % (receipt.name, desc_op)
            attestation = container / "signatures" / "manifest.sig.json"
            if attestation.is_file():
                _sync_attestation_digest(attestation, str(receipt.relative_to(container)), mutated)
                desc += " +redigest"
    elif category == "keyset":
        keyset = job_dir / "_keyset"
        if rng.random() < 0.2:
            desc += " | " + filesystem_mutation(keyset, rng)
        else:
            target = rng.choice(sorted(path for path in keyset.iterdir() if path.is_file()))
            desc += " | %s %s" % (target.name, _mutate_json_or_bytes(target, rng))
    elif category == "record":
        record_path = job_dir / expected["input"]
        if record_path.is_dir():
            files = sorted(path for path in record_path.rglob("*") if path.is_file())
            record_path = rng.choice(files)
        desc += " | %s %s" % (record_path.name, _mutate_json_or_bytes(record_path, rng))
    else:  # pragma: no cover - argparse limits the classes
        raise SystemExit("unknown crash_fuzz class: %s" % category)

    argv = expand_args(expected, job_dir, keyset)
    return {
        "category": category,
        "index": index,
        "desc": desc,
        "base_case": base_case,
        "argv": argv,
        "dir": str(job_dir),
        # W11: a mutation that left every byte unchanged is not a mutant.
        "noop": _tree_fingerprint(job_dir) == before,
    }


def _mutate_previous_dir(previous: Path, rng: random.Random) -> str:
    members = sorted(
        [previous / "manifest.json", previous / "signatures" / "manifest.sig.json"]
    )
    target = rng.choice(members)
    return "%s %s" % (target.relative_to(previous), _mutate_json_or_bytes(target, rng))


def _sync_attestation_digest(attestation: Path, relative: str, receipt_bytes: bytes) -> None:
    """V2c: re-point the (unsigned) attestation digest so DER parsing is reached."""
    from hyphaweave_verify import canonical

    value = json.loads(attestation.read_bytes())
    for entry in value.get("timestamps") or ():
        if isinstance(entry, dict) and entry.get("path") == relative:
            entry["digest"] = "sha256:" + hashlib.sha256(receipt_bytes).hexdigest()
    attestation.write_bytes(canonical.canonicalize(value))


# ---------------------------------------------------------------------------
# Running one mutant through the real CLI process
# ---------------------------------------------------------------------------

CLI_ARGV = [sys.executable, "-m", "hyphaweave_verify.cli"]
#: One mutant may not block the gate: a timeout (or a signal) counts as a crash.
MUTANT_TIMEOUT_SECONDS = 60
MAX_STDERR_DETAIL = 400


def _extract_errors(report: dict | None) -> list[str] | None:
    if not isinstance(report, dict):
        return None
    errors = set(report.get("errors") or ())
    container = report.get("container") or {}
    errors.update(container.get("errors") or ())
    for entry in report.get("records") or ():
        errors.update(entry.get("errors") or ())
    return sorted(errors)


def run_cli(argv: list[str]) -> dict:
    """Run one mutant through the real CLI subprocess (V8: exit code + stderr)."""
    try:
        completed = subprocess.run(
            CLI_ARGV + list(argv),
            capture_output=True,
            timeout=MUTANT_TIMEOUT_SECONDS,
            cwd=str(REPO),
        )
    except subprocess.TimeoutExpired:
        return {
            "rc": None,
            "verdict": None,
            "errors": None,
            "crash": True,
            "stderr_has_traceback": False,
            "detail": "timeout after %d s" % MUTANT_TIMEOUT_SECONDS,
        }
    stdout = completed.stdout.decode("utf-8", "replace")
    stderr = completed.stderr.decode("utf-8", "replace")
    report = None
    if stdout.strip():
        try:
            report = json.loads(stdout)
        except ValueError:
            report = None
    stderr_has_traceback = "Traceback" in stderr
    rc = completed.returncode
    crashed = rc not in ACCEPTED_EXIT_CODES or stderr_has_traceback
    detail = ""
    if crashed:
        last_stderr = stderr.strip().splitlines()[-1] if stderr.strip() else ""
        detail = "rc=%r stderr=%r" % (rc, last_stderr[:MAX_STDERR_DETAIL])
    return {
        "rc": rc,
        "verdict": (report or {}).get("verdict") if isinstance(report, dict) else None,
        "errors": _extract_errors(report),
        "crash": crashed,
        "stderr_has_traceback": stderr_has_traceback,
        "detail": detail,
    }


def run_live_job(task: tuple[str, int, int, str]) -> dict:
    category, index, seed, work_root = task
    work = Path(work_root)
    try:
        job = build_job(category, index, seed, work)
        desc = job["desc"]
        if job["noop"]:
            shutil.rmtree(job["dir"], ignore_errors=True)
            return {
                "id": "%s-%05d" % (category, index),
                "category": category,
                "index": index,
                "desc": desc,
                "noop": True,
            }
        outcome = run_cli(job["argv"])
        shutil.rmtree(job["dir"], ignore_errors=True)
    except Exception as error:  # noqa: BLE001 - a fuzz-tool failure is a gate failure
        outcome = {
            "rc": None,
            "verdict": None,
            "errors": None,
            "crash": True,
            "stderr_has_traceback": False,
            "detail": "crash_fuzz could not build/run the mutant: %s: %s"
            % (type(error).__name__, error),
        }
        desc = category
    outcome.update(
        {
            "id": "%s-%05d" % (category, index),
            "category": category,
            "index": index,
            "desc": desc,
            "noop": False,
        }
    )
    return outcome


def run_live_batch(classes: list[str], count: int, seed: int, work_root: Path, jobs: int) -> tuple[list[dict], int]:
    """W11: ``count`` effective (non-no-op) mutants per class, deterministically.

    Indices are drawn in order 0, 1, 2, ...; no-op indices are skipped and the
    next indices are drawn in further rounds until every class has ``count``
    effective mutants. Returns the effective results and the number of skipped
    no-op indices.
    """
    effective: dict[str, list[dict]] = {category: [] for category in classes}
    next_index = {category: 0 for category in classes}
    skipped = 0
    with multiprocessing.Pool(processes=max(1, jobs), initializer=_worker_init) as pool:
        while True:
            tasks = []
            for category in classes:
                missing = count - len(effective[category])
                for offset in range(missing):
                    tasks.append((category, next_index[category] + offset, seed, str(work_root)))
                next_index[category] += max(0, missing)
            if not tasks:
                break
            for item in pool.map(run_live_job, tasks):
                if item.get("noop"):
                    skipped += 1
                    continue
                effective[item["category"]].append(item)
    results = [item for category in classes for item in effective[category]]
    return results, skipped


# ---------------------------------------------------------------------------
# Committed crash-corpus replay
# ---------------------------------------------------------------------------


def load_corpus() -> list[dict]:
    index_path = CORPUS / "index.json"
    if not index_path.is_file():
        return []
    return json.loads(index_path.read_text(encoding="utf-8")).get("cases") or []


def materialize_corpus_case(case: dict, work_root: Path) -> tuple[Path, list[str]]:
    case_dir = copy_case(case["base_case"], work_root / "corpus" / case["file_id"])
    for relative in case.get("overlay") or ():
        source = CORPUS / case["file_id"] / relative
        destination = case_dir / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    for relative in case.get("deleted") or ():
        target = case_dir / relative
        if target.exists():
            target.unlink()
    keyset = KEYSET
    if case.get("keyset_overlay"):
        # S2-FIX1 T5: a corpus input may replace files of a private keyset copy
        # (stored under <file_id>/_keyset/ in the corpus), replayed as --keys.
        keyset = case_dir / "_keyset"
        shutil.copytree(KEYSET, keyset)
        for relative in case["keyset_overlay"]:
            shutil.copyfile(CORPUS / case["file_id"] / "_keyset" / relative, keyset / relative)
    expected = load_case(case["base_case"])
    return case_dir, expand_args(expected, case_dir, keyset)


def run_corpus_job(task: tuple[dict, str]) -> dict:
    case, work_root = task
    try:
        case_dir, argv = materialize_corpus_case(case, Path(work_root))
        outcome = run_cli(argv)
        shutil.rmtree(case_dir, ignore_errors=True)
    except Exception as error:  # noqa: BLE001 - a fuzz-tool failure is a gate failure
        outcome = {
            "rc": None,
            "verdict": None,
            "errors": None,
            "crash": True,
            "stderr_has_traceback": False,
            "detail": "crash_fuzz could not materialize/run the corpus case: %s: %s"
            % (type(error).__name__, error),
        }
    outcome.update(
        {
            "id": "corpus/" + case["file_id"],
            "category": "corpus",
            "index": case["index"],
            "desc": case["desc"],
        }
    )
    return outcome


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def _worker_init() -> None:  # pragma: no cover - multiprocessing hook
    """Pool initializer; the mutant timeout is enforced by subprocess.run."""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--classes", default=",".join(BASE_CASES), help="comma-separated classes to fuzz")
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT, help="mutants per class (>= 300 for gates)")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="deterministic mutation seed")
    parser.add_argument("--jsonl", metavar="PATH", help="write one JSON line per mutant (3.12/3.14 parity)")
    parser.add_argument("--jobs", type=int, default=min(8, os.cpu_count() or 4))
    parser.add_argument("--corpus-only", action="store_true", help="replay only the committed crash corpus")
    parser.add_argument("--no-corpus", action="store_true", help="skip the committed crash-corpus replay")
    parser.add_argument("--keep", action="store_true", help="keep the temporary work directory")
    args = parser.parse_args(argv)

    classes = [name.strip() for name in args.classes.split(",") if name.strip()]
    unknown = [name for name in classes if name not in BASE_CASES]
    if unknown:
        print("crash_fuzz: unknown class(es): %s" % ", ".join(unknown), file=sys.stderr)
        return 2
    if args.count < 1:
        print("crash_fuzz: --count must be positive", file=sys.stderr)
        return 2

    TMP_ROOT.mkdir(parents=True, exist_ok=True)
    work_root = Path(tempfile.mkdtemp(prefix="run-", dir=TMP_ROOT))
    results: list[dict] = []
    failures = 0
    try:
        corpus_cases = [] if args.no_corpus else load_corpus()
        if corpus_cases and not args.corpus_only:
            print("crash_fuzz: replaying %d committed crash inputs ..." % len(corpus_cases), file=sys.stderr)
        if corpus_cases:
            with multiprocessing.Pool(
                processes=max(1, args.jobs), initializer=_worker_init
            ) as pool:
                corpus_results = pool.map(
                    run_corpus_job,
                    [(case, str(work_root)) for case in corpus_cases],
                )
            crashes = [item for item in corpus_results if item["crash"]]
            failures += len(crashes)
            results.extend(corpus_results)
            print(
                "crash-corpus: %d inputs, %d crashes" % (len(corpus_results), len(crashes)),
                file=sys.stderr,
            )
            for item in crashes[:10]:
                print("  CRASH %s :: %s" % (item["id"], item.get("detail", "")), file=sys.stderr)

        if not args.corpus_only:
            live_results, skipped_noops = run_live_batch(
                classes, args.count, args.seed, work_root, args.jobs
            )
            crashes = [item for item in live_results if item["crash"]]
            failures += len(crashes)
            results.extend(live_results)
            per_class: dict[str, int] = {category: 0 for category in classes}
            for item in live_results:
                per_class[item["category"]] += 1
            print(
                "crash-fuzz: %d effective mutants (seed %d) across %s; %d no-op mutation(s) skipped"
                % (
                    len(live_results),
                    args.seed,
                    ", ".join("%s=%d" % (name, per_class[name]) for name in classes),
                    skipped_noops,
                ),
                file=sys.stderr,
            )
            for item in crashes[:10]:
                print(
                    "  CRASH %s (reproduce with --seed %d) :: %s"
                    % (item["id"], args.seed, item.get("detail", "")),
                    file=sys.stderr,
                )
    finally:
        if not args.keep:
            shutil.rmtree(work_root, ignore_errors=True)

    results.sort(key=lambda item: (str(item["category"]), int(item["index"])))
    if args.jsonl:
        path = Path(args.jsonl)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            for item in results:
                handle.write(
                    json.dumps(
                        {
                            "id": item["id"],
                            "category": item["category"],
                            "index": item["index"],
                            "desc": item["desc"],
                            "rc": item["rc"],
                            "verdict": item["verdict"],
                            "errors": item["errors"],
                            "crash": item["crash"],
                            "stderr_has_traceback": item["stderr_has_traceback"],
                        },
                        sort_keys=True,
                    )
                    + "\n"
                )
    total = len(results)
    print(
        "crash-fuzz: %d mutants, %d crashes, %d clean rejections, %d accepted"
        % (
            total,
            sum(1 for item in results if item["crash"]),
            sum(1 for item in results if not item["crash"] and item["rc"] in (1, 2)),
            sum(1 for item in results if not item["crash"] and item["rc"] == 0),
        )
    )
    if failures:
        print(
            "RESULT: FAIL (%d crash(es) with seed %d; a crash is never an accepted rejection)"
            % (failures, args.seed)
        )
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
