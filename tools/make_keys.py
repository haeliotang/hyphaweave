#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Generate the synthetic test-key inventory under ``vectors/keys/``.

Everything produced here is **public test material**, deterministically
derived from public names, and must never be confused with a real key:

    seed = SHA-256(b"weave-record/1/test-key/" + <ascii name>)[:32]

The script is re-runnable and idempotent: it rewrites the named-key artifacts
byte-identically, regenerates the ``weave.key.declared`` keyset records
(self-signature plus owner counter-signature, strictly increasing
``recorded_at`` so that ``human-1`` is the deterministic self-attested root),
writes the deterministic edge-point public-key material used by the Ed25519
boundary vectors, and regenerates the RFC 3161 test TSA key/certificate.  The
TSA key is RSA-2048 and therefore generated once on first run and then reused
from ``tsa.key.pem`` (an RSA key cannot be derived from a seed
deterministically); the certificate is re-generated deterministically from
that key, fixed validity and a fixed serial number.

Usage::

    ./.venv/bin/python tools/make_keys.py [--check]

``--check`` verifies only: any difference on disk makes the command fail with
exit code 1 (used to prove determinism by re-running).
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

_TOOLS_DIR = Path(__file__).resolve().parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

import keyutil
import recordlib

try:
    import edcraft
except ImportError:  # pragma: no cover - edcraft is committed with the tools
    edcraft = None  # type: ignore[assignment]

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

REPO_ROOT = _TOOLS_DIR.parent
KEYS_DIR = REPO_ROOT / "vectors" / "keys"
KEYSET_DIR = KEYS_DIR / "keyset"
EDGE_POINTS_DIR = KEYS_DIR / "edge-points"
TSA_DIR = KEYS_DIR / "tsa"

SEED_DOMAIN = b"weave-record/1/test-key/"

# Required key names and their declared key classes (all are test keys).
KEY_NAMES: tuple[tuple[str, str], ...] = (
    ("human-1", "human"),
    ("human-2", "human"),
    ("agent-1", "agent"),
    ("agent-2", "agent"),
    ("program-1", "program"),
    ("device-1", "device"),
    ("org-1", "organization"),
    ("key-old", "human"),
    ("key-new", "human"),
    ("key-compromised", "human"),
)

# Keyset declarations: strictly increasing recorded_at (human-1 is the
# earliest valid human/organization declaration and therefore the
# self-attested root); every later declaration carries body.owner and the
# owner/previous-key counter-signature.  key-new is owned and co-signed by
# key-old (the previous key of the rotation pair).
KEY_DECLARATION_BASE = "2026-11-01T00:00:00.000Z"
KEY_DECLARATION_PLAN: tuple[dict[str, Any], ...] = (
    {"name": "human-1", "offset_ms": 0, "owner": None, "cosigners": ()},
    {"name": "human-2", "offset_ms": 1, "owner": "human-1", "cosigners": ("human-1",)},
    {"name": "org-1", "offset_ms": 2, "owner": "human-1", "cosigners": ("human-1",)},
    {"name": "key-old", "offset_ms": 3, "owner": "human-1", "cosigners": ("human-1",)},
    {"name": "key-new", "offset_ms": 4, "owner": "key-old", "cosigners": ("key-old",)},
    {
        "name": "key-compromised",
        "offset_ms": 5,
        "owner": "human-1",
        "cosigners": ("human-1",),
    },
    {"name": "agent-1", "offset_ms": 6, "owner": "human-1", "cosigners": ("human-1",)},
    {"name": "agent-2", "offset_ms": 7, "owner": "human-1", "cosigners": ("human-1",)},
    {"name": "program-1", "offset_ms": 8, "owner": "human-1", "cosigners": ("human-1",)},
    {"name": "device-1", "offset_ms": 9, "owner": "human-1", "cosigners": ("human-1",)},
)

# Deterministic edge-point public-key material for the Ed25519 boundary
# vectors.  These are encodings, not usable signing keys (no private part is
# published or derivable from them).
SMALL_ORDER_ENCODINGS: tuple[str, ...] = (
    "00" * 32,  # y = 0 point, canonical encoding (order 4)
    "00" * 31 + "80",  # y = 0 point, sign bit set (order 4)
    "01" + "00" * 31,  # identity point (order 1)
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",  # order 8
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",  # order 8
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",  # order 8
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",  # order 8
    "ec" + "ff" * 30 + "7f",  # y = p - 1 point (order 2)
)

X0_SIGN_BIT_ENCODING = "01" + "00" * 30 + "80"
NONCANONICAL_Y_P_ENCODING = "ed" + "ff" * 30 + "7f"

MIXED_ORDER_SEED = hashlib.sha256(
    b"weave-record/1/test-key/mixed-order-a"
).digest()

EDGE_POINTS: tuple[dict[str, str], ...] = tuple(
    {
        "name": "small-order-%02d" % index,
        "encoding": encoding,
        "class": "small-order",
        "note": "canonical encoding of a point whose order divides 8; "
        "8*P == identity",
    }
    for index, encoding in enumerate(SMALL_ORDER_ENCODINGS)
) + (
    {
        "name": "x0-sign-bit",
        "encoding": X0_SIGN_BIT_ENCODING,
        "class": "x0-sign-bit",
        "note": "y = 1 (identity) encoding with the RFC 8032 sign bit set: "
        "decoding must fail (x = 0 with sign bit 1)",
    },
    {
        "name": "noncanonical-y-p",
        "encoding": NONCANONICAL_Y_P_ENCODING,
        "class": "noncanonical",
        "note": "y = p encoding: y is not reduced modulo p, decoding must fail",
    },
)

TSA_COMMON_NAME = "Hyphaweave H0 test TSA (test only)"
TSA_SERIAL = 0x5754_4553_5401
TSA_NOT_BEFORE = datetime.datetime(2026, 1, 1, 0, 0, 0)
TSA_NOT_AFTER = datetime.datetime(2126, 1, 1, 0, 0, 0)


def derive_seed(name: str) -> bytes:
    return hashlib.sha256(SEED_DOMAIN + name.encode("ascii")).digest()


def declaration_timestamp(offset_ms: int) -> str:
    """``KEY_DECLARATION_BASE`` plus *offset_ms* milliseconds (0..999)."""
    prefix, _, _suffix = KEY_DECLARATION_BASE.rpartition(".")
    return "%s.%03dZ" % (prefix, offset_ms)


def _write_if_changed(path: Path, data: bytes, *, mode: int | None = None) -> bool:
    """Write *data* unless the file already contains exactly those bytes."""
    if path.is_file() and path.read_bytes() == data:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if mode is not None:
        path.chmod(mode)
    return True


def _key_json(name: str, key_type: str, key_id: str) -> dict[str, Any]:
    return {
        "name": name,
        "key_id": key_id,
        "key_type": key_type,
        "seed_file": name + ".seed",
        "pub_bin_file": name + ".pub.bin",
        "pub_pem_file": name + ".pub.pem",
        "note": (
            "SYNTHETIC PUBLIC TEST KEY - not a secret, not for any real use. "
            "seed = sha256('weave-record/1/test-key/' + name)[:32]"
        ),
    }


def generate_named_keys(*, check: bool) -> tuple[dict[str, str], list[str]]:
    problems: list[str] = []
    key_ids: dict[str, str] = {}
    for name, key_type in KEY_NAMES:
        seed = derive_seed(name)
        private = keyutil.private_from_seed(seed)
        public_raw = keyutil.public_bytes(private)
        derived_id = keyutil.key_id(public_raw)
        key_ids[name] = derived_id

        artifacts = {
            name + ".seed": seed.hex().encode("ascii") + b"\n",
            name + ".pub.bin": public_raw,
            name + ".pub.pem": keyutil.spki_pem(private),
            name + ".json": (
                json.dumps(
                    _key_json(name, key_type, derived_id), indent=2, ensure_ascii=True
                )
                + "\n"
            ).encode("utf-8"),
        }
        for filename, data in artifacts.items():
            path = KEYS_DIR / filename
            if check:
                if not path.is_file():
                    problems.append("missing %s" % path)
                elif path.read_bytes() != data:
                    problems.append("content mismatch %s" % path)
            else:
                _write_if_changed(path, data)
        if not check:
            meta = json.loads((KEYS_DIR / (name + ".json")).read_text(encoding="utf-8"))
            if meta.get("key_id") != derived_id:
                problems.append(
                    "key id mismatch for %s: %r != %r"
                    % (name, meta.get("key_id"), derived_id)
                )
    return key_ids, problems


def generate_keyset(*, check: bool, key_ids: dict[str, str]) -> list[str]:
    problems: list[str] = []
    files: dict[str, bytes] = {}
    for plan in KEY_DECLARATION_PLAN:
        name = plan["name"]
        record = recordlib.key_declaration(
            name,
            recorded_at=declaration_timestamp(plan["offset_ms"]),
            owner=plan["owner"],
            cosigners=plan["cosigners"],
        )
        record_id = "key-declared-" + name
        if record["id"] != record_id:
            problems.append("keyset record id mismatch for %s" % name)
        if record["body"]["key"] != key_ids[name]:
            problems.append("keyset record declares wrong key id for %s" % name)
        if plan["owner"] is not None:
            if record["body"].get("owner") != key_ids[plan["owner"]]:
                problems.append("keyset record wrong owner for %s" % name)
            if len(record["sigs"]) != 1 + len(plan["cosigners"]):
                problems.append("keyset record missing counter-signature for %s" % name)
        elif len(record["sigs"]) != 1:
            problems.append("self-attested keyset record must have one signature for %s" % name)
        sig_keys = [entry["key"] for entry in record["sigs"]]
        if sig_keys != sorted(sig_keys) or len(set(sig_keys)) != len(sig_keys):
            problems.append("keyset record signatures unsorted for %s" % name)
        files[record_id + ".json"] = recordlib.canonical_file(record)
    for filename, data in files.items():
        path = KEYSET_DIR / filename
        if check:
            if not path.is_file():
                problems.append("missing %s" % path)
            elif path.read_bytes() != data:
                problems.append("content mismatch %s" % path)
        else:
            _write_if_changed(path, data)
    return problems


def generate_edge_points(*, check: bool) -> tuple[list[dict[str, str]], list[str]]:
    """Write the deterministic edge-point public-key material.

    Returns the index rows (with derived key ids) and any problems.
    """
    problems: list[str] = []
    rows: list[dict[str, str]] = []
    files: dict[str, bytes] = {}
    for point in EDGE_POINTS:
        raw = bytes.fromhex(point["encoding"])
        if len(raw) != 32:
            problems.append("edge point %s is not 32 bytes" % point["name"])
            continue
        key_id = keyutil.key_id(raw)
        row = {
            "name": point["name"],
            "encoding": point["encoding"],
            "key_id": key_id,
            "class": point["class"],
            "note": point["note"],
        }
        rows.append(row)
        files[point["name"] + ".pub.bin"] = raw
    if edcraft is None:
        problems.append("tools/edcraft.py is missing; cannot derive mixed-order-a")
    else:
        mixed_public = edcraft.mixed_order_public(MIXED_ORDER_SEED)
        if len(mixed_public) != 32:
            problems.append("mixed-order-a public key is not 32 bytes")
        else:
            mixed_id = keyutil.key_id(mixed_public)
            rows.append(
                {
                    "name": "mixed-order-a",
                    "encoding": mixed_public.hex(),
                    "key_id": mixed_id,
                    "class": "mixed-order",
                    "note": (
                        "public key A = [a]B + T with T of order 8 and "
                        "a = edcraft.private_scalar(sha256("
                        "'weave-record/1/test-key/mixed-order-a')); "
                        "cofactorless-valid signatures exist via "
                        "edcraft.mixed_order_key_and_signature(seed, message)"
                    ),
                }
            )
            files["mixed-order-a.pub.bin"] = mixed_public
            files["mixed-order-a.seed"] = MIXED_ORDER_SEED.hex().encode("ascii") + b"\n"
    files["index.json"] = json.dumps(
        {
            "format": "weave-record-edge-points/1",
            "note": (
                "SYNTHETIC TEST MATERIAL - these public points are deliberately "
                "hostile/small-order/mixed-order and must never be used as real "
                "keys. Private crafting material exists only for mixed-order-a."
            ),
            "points": rows,
        },
        indent=2,
        ensure_ascii=True,
        sort_keys=True,
    ).encode("utf-8") + b"\n"
    for filename, data in files.items():
        path = EDGE_POINTS_DIR / filename
        if check:
            if not path.is_file():
                problems.append("missing %s" % path)
            elif path.read_bytes() != data:
                problems.append("content mismatch %s" % path)
        else:
            _write_if_changed(path, data)
    return rows, problems


def _tsa_private_key(*, check: bool) -> tuple[rsa.RSAPrivateKey | None, list[str]]:
    key_path = TSA_DIR / "tsa.key.pem"
    if key_path.is_file():
        try:
            loaded = serialization.load_pem_private_key(
                key_path.read_bytes(), password=None
            )
        except ValueError as exc:  # pragma: no cover - defensive
            return None, ["cannot load %s: %s" % (key_path, exc)]
        if not isinstance(loaded, rsa.RSAPrivateKey):
            return None, ["%s is not an RSA private key" % key_path]
        return loaded, []
    if check:
        return None, ["missing %s" % key_path]
    TSA_DIR.mkdir(parents=True, exist_ok=True)
    generated = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = generated.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path.write_bytes(pem)
    key_path.chmod(0o644)  # public test material: no secrecy claimed
    return generated, []


def generate_tsa(*, check: bool) -> list[str]:
    problems: list[str] = []
    private_key, load_problems = _tsa_private_key(check=check)
    problems.extend(load_problems)
    if private_key is None:
        return problems
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, TSA_COMMON_NAME)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(TSA_SERIAL)
        .not_valid_before(TSA_NOT_BEFORE)
        .not_valid_after(TSA_NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True
        )
        .sign(private_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    artifacts = {
        "tsa.crt.pem": cert_pem,
        "tsa.cnf": _tsa_config_text().encode("utf-8"),
        "serial.txt": b"01\n",
    }
    for filename, data in artifacts.items():
        path = TSA_DIR / filename
        if check:
            if not path.is_file():
                problems.append("missing %s" % path)
            elif path.read_bytes() != data:
                problems.append("content mismatch %s" % path)
        else:
            _write_if_changed(path, data)
    return problems


def _tsa_config_text() -> str:
    # Paths are relative to the directory the openssl ts command runs in.
    return """\
# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0
#
# Local RFC 3161 test TSA configuration (OpenSSL `openssl ts`).
# Never a real timestamp authority.
[ tsa ]
default_tsa = tsa_config1

[ tsa_config1 ]
crypto_device = builtin
serial = ./serial.txt
signer_cert = ./tsa.crt.pem
certs = ./tsa.crt.pem
signer_key = ./tsa.key.pem
signer_digest = sha256
default_policy = 1.2.3.4.1
other_policies = 1.2.3.4.5
digests = sha256
accuracy = secs:1
ordering = no
tsa_name = yes
ess_cert_id_chain = no
ess_cert_id_alg = sha256
"""


def _readme_text(
    key_ids: dict[str, str],
    edge_rows: list[dict[str, str]],
    tsa_fingerprint: str,
    tsa_fingerprint_colons: str,
) -> str:
    key_types = dict(KEY_NAMES)
    plan_by_name = {plan["name"]: plan for plan in KEY_DECLARATION_PLAN}
    rows = "\n".join(
        "| `%s` | %s | `%s` | %s | %s |"
        % (
            plan["name"],
            key_types[plan["name"]],
            key_ids[plan["name"]],
            "`%s`" % plan["owner"] if plan["owner"] else "*(root)*",
            ", ".join("`%s`" % item for item in plan["cosigners"]) or "-",
        )
        for plan in KEY_DECLARATION_PLAN
    )
    edge_rows_text = "\n".join(
        "| `%s` | `%s` | %s | `%s` |"
        % (row["name"], row["encoding"], row["class"], row["key_id"])
        for row in edge_rows
    )
    return f"""\
<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Hyphaweave test keys

**These are synthetic public test keys. They are deliberately published and
must never be used for anything real.** Every private seed is derived
deterministically from a public name:

```
seed = SHA-256(b"weave-record/1/test-key/" + <ascii name>)[:32]
```

Regenerate the whole inventory (the output is byte-identical on every run
except the one-time RSA TSA key, which is generated on first run and then
reused):

```
./.venv/bin/python tools/make_keys.py            # create/refresh
./.venv/bin/python tools/make_keys.py --check    # verify, exit 1 on drift
```

Each key has four files: `<name>.seed` (64 lowercase hex characters = the
32-byte Ed25519 seed), `<name>.pub.bin` (32 raw public-key bytes),
`<name>.pub.pem` (SPKI PEM, for `openssl pkeyutl`) and `<name>.json` (name,
key id, key class, file names, warning note). Key ids are
`ed25519:<sha256(raw public key)[:32 hex]>`.

## keyset/

`keyset/*.json` are valid `weave.key.declared` records (one per test key),
used as `--keys @keyset` for record-level vectors:

| key name | declared class | key id | `body.owner` | counter-signature by |
|---|---|---|---|---|
{rows}

The declarations carry strictly increasing `recorded_at` values, starting with
`human-1` at `{KEY_DECLARATION_BASE}` (then `human-2`, `org-1`, `key-old`,
`key-new`, `key-compromised`, `agent-1`, `agent-2`, `program-1`, `device-1`,
each one millisecond later). Root-key rule: the earliest valid
human/organization declaration is the self-attested root and may carry only
its self-signature; the verifier reports `N_SELF_ATTESTED_ROOT_KEY` when it
accepts such a root. Every later declaration carries the owner/previous-key
counter-signature (sorted with the self-signature by key id): `human-2`,
`org-1`, `key-old`, `key-compromised`, `agent-*`, `program-*` and `device-*`
are owned and counter-signed by `human-1`; `key-new` is owned and
counter-signed by `key-old` (the previous key of the rotation pair).
`agent`, `program` and `device` declarations require `body.owner`; for those
kinds the owner is a declared human/organization key.

## edge-points/

Deterministic public-key material for the Ed25519 boundary vectors (no private
part exists for these points, and none is derivable from this directory):

| name | encoding | class | derived key id |
|---|---|---|---|
{edge_rows_text}

`index.json` carries the same table in machine-readable form. The eight
`small-order-*` encodings are the canonical encodings of points whose order
divides 8; `x0-sign-bit` is the identity encoding with the RFC 8032 sign bit
set (decoding must fail); `noncanonical-y-p` is the `y = p` encoding
(decoding must fail). See `tools/edcraft.py` for the crafted signatures that
go with them.

## tsa/

Local RFC 3161 test TSA material, used **only** to sign the committed L2 test
timestamp replies (the generation procedure lives in
`vectors/integrity-levels/README.md`; this directory is read-only input for it):

- `tsa.key.pem` - RSA-2048 test key (generated once on the first
  `make_keys.py` run and then reused byte-for-byte; public test material, no
  secrecy claimed);
- `tsa.crt.pem` - self-signed certificate, CN `{TSA_COMMON_NAME}`,
  validity 2026-01-01 through 2126-01-01, critical timeStamping EKU;
  DER-encoded certificate SHA-256:
  `{tsa_fingerprint}` (OpenSSL x509 fingerprint
  `{tsa_fingerprint_colons}`);
- `tsa.cnf`, `serial.txt` - configuration for the local `openssl ts` test TSA.

The TSA certificate is a **test trust anchor** for `--tsa-trust` in the
integrity-level vectors only; it is not trusted by anything else. The contents
of this directory are frozen: do not regenerate them once timestamp replies
exist.
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the files on disk instead of writing (exit 1 on drift)",
    )
    arguments = parser.parse_args(argv)

    key_ids, problems = generate_named_keys(check=arguments.check)
    recordlib._KEY_CACHE.clear()
    problems.extend(generate_keyset(check=arguments.check, key_ids=key_ids or {}))
    edge_rows, edge_problems = generate_edge_points(check=arguments.check)
    problems.extend(edge_problems)
    problems.extend(generate_tsa(check=arguments.check))

    tsa_cert = TSA_DIR / "tsa.crt.pem"
    if tsa_cert.is_file():
        der = x509.load_pem_x509_certificate(tsa_cert.read_bytes()).public_bytes(
            serialization.Encoding.DER
        )
        digest = hashlib.sha256(der).hexdigest()
        tsa_fingerprint = digest
        tsa_fingerprint_colons = ":".join(
            digest[index : index + 2] for index in range(0, len(digest), 2)
        ).upper()
    else:
        tsa_fingerprint = "(missing)"
        tsa_fingerprint_colons = "(missing)"
    if key_ids:
        readme = _readme_text(
            key_ids, edge_rows, tsa_fingerprint, tsa_fingerprint_colons
        )
        readme_path = KEYS_DIR / "README.md"
        if arguments.check:
            if (
                not readme_path.is_file()
                or readme_path.read_text(encoding="utf-8") != readme
            ):
                problems.append("content mismatch %s" % readme_path)
        else:
            _write_if_changed(readme_path, readme.encode("utf-8"))

    if problems:
        for problem in problems:
            print("FAIL: %s" % problem, file=sys.stderr)
        return 1
    if arguments.check:
        print(
            "ok: test-key inventory is up to date (%d named keys, %d keyset "
            "declarations, %d edge points)"
            % (len(KEY_NAMES), len(KEY_DECLARATION_PLAN), len(edge_rows))
        )
    else:
        print(
            "generated %d named test keys, %d keyset declarations, %d edge points, "
            "TSA key/cert -> %s"
            % (
                len(KEY_NAMES),
                len(KEY_DECLARATION_PLAN),
                len(edge_rows),
                KEYS_DIR,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
