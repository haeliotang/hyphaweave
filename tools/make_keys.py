#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Generate the synthetic test-key inventory under ``vectors/keys/``.

Everything produced here is **public test material**, deterministically
derived from public names, and must never be confused with a real key:

    seed = SHA-256(b"weave-record/1/test-key/" + <ascii name>)[:32]

The script is re-runnable and idempotent: it rewrites the named-key artifacts
byte-identically, regenerates the self-signed ``weave.key.declared`` keyset
records and the RFC 3161 test TSA key/certificate, and verifies each derived
key id against ``<name>.json``.  The TSA key is RSA-2048 and therefore
generated once on first run and then reused from ``tsa.key.pem`` (an RSA key
cannot be derived from a seed deterministically); the certificate is
re-generated deterministically from that key, fixed validity and a fixed
serial number.

Usage::

    ./.venv/bin/python tools/make_keys.py [--check]

``--check`` verifies only: any difference on disk makes the command fail with
exit code 1 (used to prove determinism by re-running).
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path
from typing import Any

_TOOLS_DIR = Path(__file__).resolve().parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

import keyutil
import recordlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

REPO_ROOT = _TOOLS_DIR.parent
KEYS_DIR = REPO_ROOT / "vectors" / "keys"
KEYSET_DIR = KEYS_DIR / "keyset"
TSA_DIR = KEYS_DIR / "tsa"

SEED_DOMAIN = b"weave-record/1/test-key/"

# Requirement of CONTRACT §16.3 (at minimum); all are test keys.
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

TSA_COMMON_NAME = "Hyphaweave H0 test TSA (test only)"
TSA_SERIAL = 0x5754_4553_5401
TSA_NOT_BEFORE = datetime.datetime(2026, 1, 1, 0, 0, 0)
TSA_NOT_AFTER = datetime.datetime(2126, 1, 1, 0, 0, 0)


def derive_seed(name: str) -> bytes:
    import hashlib

    return hashlib.sha256(SEED_DOMAIN + name.encode("ascii")).digest()


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


def generate_named_keys(*, check: bool) -> list[str]:
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
            # A re-run must not have changed the derived id: the generated
            # metadata is the single source of truth for key ids.
            meta = json.loads((KEYS_DIR / (name + ".json")).read_text(encoding="utf-8"))
            if meta.get("key_id") != derived_id:
                problems.append(
                    "key id mismatch for %s: %r != %r"
                    % (name, meta.get("key_id"), derived_id)
                )
    return key_ids, problems  # type: ignore[return-value]


def generate_keyset(*, check: bool, key_ids: dict[str, str]) -> list[str]:
    problems: list[str] = []
    files: dict[str, bytes] = {}
    for name, _key_type in KEY_NAMES:
        record = recordlib.key_declaration(name)
        record_id = "key-declared-" + name
        if record["id"] != record_id:
            problems.append("keyset record id mismatch for %s" % name)
        if record["body"]["key"] != key_ids[name]:
            problems.append("keyset record declares wrong key id for %s" % name)
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
    # Paths are relative to the directory the openssl ts command runs in
    # (tools/make_test_tsr.sh runs inside vectors/keys/tsa/).
    return """\
# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0
#
# Local RFC 3161 test TSA configuration (OpenSSL `openssl ts`).
# Used only to generate the committed test timestamp replies under
# vectors/keys/tsa/fixtures/; never a real timestamp authority.
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
    key_ids: dict[str, str], tsa_fingerprint: str, tsa_fingerprint_colons: str
) -> str:
    rows = "\n".join(
        "| `%s` | %s | `%s` |" % (name, key_type, key_ids[name])
        for name, key_type in KEY_NAMES
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

| key name | declared key class | key id |
|---|---|---|
{rows}

## keyset/

`keyset/*.json` are self-signed `weave.key.declared` records (one per test
key), used as `--keys @keyset` for record-level vectors. They are generated by
`tools/make_keys.py` from the same deterministic seeds.

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
    problems.extend(generate_tsa(check=arguments.check))

    tsa_cert = TSA_DIR / "tsa.crt.pem"
    if tsa_cert.is_file():
        import hashlib

        from cryptography import x509 as _x509

        der = _x509.load_pem_x509_certificate(tsa_cert.read_bytes()).public_bytes(
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
        readme = _readme_text(key_ids, tsa_fingerprint, tsa_fingerprint_colons)
        readme_path = KEYS_DIR / "README.md"
        if arguments.check:
            if not readme_path.is_file() or readme_path.read_text(encoding="utf-8") != readme:
                problems.append("content mismatch %s" % readme_path)
        else:
            _write_if_changed(readme_path, readme.encode("utf-8"))

    if problems:
        for problem in problems:
            print("FAIL: %s" % problem, file=sys.stderr)
        return 1
    if arguments.check:
        print("ok: test-key inventory is up to date (%d named keys)" % len(KEY_NAMES))
    else:
        print(
            "generated %d named test keys, %d keyset records, TSA key/cert -> %s"
            % (len(KEY_NAMES), len(KEY_NAMES), KEYS_DIR)
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
