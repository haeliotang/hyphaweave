#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Generate the second half of the ``weave-record/1`` conformance vectors.

This generator owns the ``erasure``, ``grant``, ``key-lifecycle``, ``container``
and ``integrity-levels`` categories.  The first half (``jcs``, ``digest``,
``sig``, ``ref``, ``stage``, ``actor``, ``labels``) is produced by
``tools/gen_vectors.py``; both write the same case format and are catalogued by
``tools/gen_index.py``.

Design rules (`vectors/README.md`):

* Every case's expected verdict and error codes are **hand-authored** in the
  table below from the contract text.  The generator never imports, runs or
  otherwise consults the reference verifier; the files are built with the
  independent helpers in :mod:`wcj`, :mod:`keyutil` and :mod:`recordlib` (own
  WR-CJ, own digests, own Ed25519 signing through ``cryptography``).
* A case directory contains either ``record.json`` (record target), a
  ``container/`` tree (container target) or ``container.zip`` (zip container
  target), plus exactly one canonical ``expected.json``.
* Containers under ``integrity-levels/`` with a claimed L2 level carry RFC 3161
  ``.tsr`` replies crafted deterministically from the published local test TSA
  key (``vectors/keys/tsa/``) with fixed genTime/signing time and RSA PKCS#1 v1.5
  signatures, so regeneration reproduces the committed bytes exactly; no
  OpenSSL, wall clock or network is involved.  The construction and the case
  matrix are documented in ``vectors/integrity-levels/README.md``.

Usage (from the repository root)::

    ./.venv/bin/python tools/gen_vectors_extra.py             # write cases
    ./.venv/bin/python tools/gen_vectors_extra.py --check     # verify on disk
    ./.venv/bin/python tools/gen_vectors_extra.py --only container
    ./.venv/bin/python tools/gen_vectors_extra.py --freeze --frozen-source-commit <sha>
                                              # copy the gate-7 frozen set
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import io
import shutil
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence

_TOOLS_DIR = Path(__file__).resolve().parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

import keyutil
import recordlib
import wcj

from asn1crypto import cms as asn1_cms, tsp as asn1_tsp, x509 as asn1_x509
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import padding as crypto_padding

REPO_ROOT = _TOOLS_DIR.parent
VECTORS_DIR = REPO_ROOT / "vectors"
TSA_DIR = VECTORS_DIR / "keys" / "tsa"
TSA_CERT_NAME = "tsa.crt.pem"

FORMAT = recordlib.FORMAT
PROJECT = recordlib.PROJECT


# ---------------------------------------------------------------------------
# Case model
# ---------------------------------------------------------------------------


@dataclass
class Case:
    category: str
    name: str
    target: str
    input: str
    verdict: str
    build: Callable[[Path], dict[str, bytes]]
    errors: tuple[str, ...] = ()
    notices: tuple[str, ...] = ()
    args: tuple[str, ...] = ()
    notes: str = ""
    expected_digest: bool = False
    expected_resolution: tuple[str, ...] | None = None
    expected_container: dict[str, Any] | None = None
    records: tuple[dict[str, Any], ...] | None = None

    @property
    def id(self) -> str:
        return "%s/%s" % (self.category, self.name)

    @property
    def case_dir(self) -> Path:
        return VECTORS_DIR / self.category / self.name


CASES: list[Case] = []
_CURRENT_CONTEXT: dict[str, Any] = {}


def declare(
    category: str,
    name: str,
    target: str,
    input_value: str,
    verdict: str,
    *,
    build: Callable[[Path], dict[str, bytes]],
    **kwargs: Any,
) -> None:
    cases_append = Case(
        category=category,
        name=name,
        target=target,
        input=input_value,
        verdict=verdict,
        build=build,
        **kwargs,
    )
    CASES.append(cases_append)


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def canonical(value: Any) -> bytes:
    """Canonical file bytes of a value (WR-CJ bytes plus one trailing LF)."""
    return wcj.dump_canonical_file(value)


def parse(data: bytes) -> Any:
    return wcj.parse_strict(data)


def note(record_id: str, **kwargs: Any) -> dict[str, Any]:
    return recordlib.note(record_id, **kwargs)


def key(name: str) -> keyutil.KeyMaterial:
    return recordlib.key(name)


def kid(name: str) -> str:
    return recordlib.kid(name)


def ktype(name: str) -> str:
    return recordlib.ktype(name)


def digest_of(record: dict[str, Any]) -> str:
    return recordlib.record_digest(record)


def as_zip(files: dict[str, bytes]) -> bytes:
    """Deterministic STORED zip of a container file map."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for path in sorted(files):
            info = zipfile.ZipInfo(path, date_time=(2026, 11, 10, 0, 0, 0))
            info.external_attr = 0o644 << 16
            info.create_system = 3
            archive.writestr(info, files[path])
    return buffer.getvalue()


def wrap(files: dict[str, bytes]) -> dict[str, bytes]:
    """Wrap internal container paths under the case-relative ``container/`` dir."""
    return {"container/" + path: data for path, data in files.items()}


def zip_wrap(files: dict[str, bytes]) -> dict[str, bytes]:
    return {"container.zip": as_zip(files)}


def container(records: Sequence[dict[str, Any]], **kwargs: Any) -> dict[str, bytes]:
    """Build a container from records and wrap it under ``container/``."""
    return wrap(recordlib.build_container(records, **kwargs))


def mutate(
    files: dict[str, bytes],
    mutator: Callable[[dict[str, Any]], dict[str, Any]],
    *,
    resign_with: Sequence[str] | None = ("human-1",),
) -> dict[str, bytes]:
    """Apply *mutator* to the container's manifest (optionally re-sealing)."""
    working = dict(files)
    return recordlib.mutate_manifest(working, mutator, resign_with=resign_with)


def mutate_sigfile(
    files: dict[str, bytes], mutator: Callable[[dict[str, Any]], dict[str, Any]]
) -> dict[str, bytes]:
    working = dict(files)
    recordlib.mutate_sigfile(working, mutator)
    return working


def replace(files: dict[str, bytes], path: str, data: bytes) -> dict[str, bytes]:
    working = dict(files)
    working[path] = data
    return working


def drop(files: dict[str, bytes], path: str) -> dict[str, bytes]:
    working = dict(files)
    del working[path]
    return working


RECORD_FILES = "records/"


def record_path(files: dict[str, bytes]) -> str:
    for path in sorted(files):
        if path.startswith(RECORD_FILES) and path.endswith(".json"):
            return path
    raise SystemExit("container has no records/ file")


# ---------------------------------------------------------------------------
# Crafted RFC 3161 timestamp replies (local test TSA, deterministic)
# ---------------------------------------------------------------------------
# Every L2 case timestamp is crafted here from the committed test TSA private
# key with asn1crypto + cryptography.  The construction is fully deterministic
# (fixed genTime, fixed signingTime, fixed serial numbers, fixed certificate
# hashes and RSA PKCS#1 v1.5 signatures), so regenerating the vectors reproduces
# the committed `.tsr` bytes exactly: no wall clock, no OpenSSL, no network and
# no `--bootstrap` step.  The test TSA key and certificates under
# `vectors/keys/tsa/` are deliberately published test material.

FIXED_GEN_TIME = datetime.datetime(2026, 11, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
FIXED_SIGNING_TIME = datetime.datetime(
    2026, 11, 10, 9, 52, 40, tzinfo=datetime.timezone.utc
)
TSA_POLICY = "1.2.3.4.1"

_CRAFTED_CERTS: dict[str, tuple[bytes, bytes]] = {}
_TSA_KEY: Any = None
_TSA_CERT_DER: bytes | None = None


def _sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _tsa_private_key() -> Any:
    global _TSA_KEY
    if _TSA_KEY is None:
        _TSA_KEY = crypto_serialization.load_pem_private_key(
            (TSA_DIR / "tsa.key.pem").read_bytes(), password=None
        )
    return _TSA_KEY


def _tsa_certificate_der() -> bytes:
    """DER bytes of the committed test TSA certificate (the normal signer)."""
    global _TSA_CERT_DER
    if _TSA_CERT_DER is None:
        _TSA_CERT_DER = crypto_x509.load_pem_x509_certificate(
            (TSA_DIR / TSA_CERT_NAME).read_bytes()
        ).public_bytes(crypto_serialization.Encoding.DER)
    return _TSA_CERT_DER


def _crafted_certificate(variant: str) -> tuple[bytes, bytes]:
    """A deterministic self-signed certificate for the test TSA key.

    Variants (all reuse the committed TSA public key, so tokens signed with the
    TSA private key verify against them):

    * ``no-eku``: no extendedKeyUsage extension at all;
    * ``expired``: validity window in the past (2020-2021);
    * ``wrong-anchor``: a valid timeStamping certificate that is not the leaf
      certificate used by the normal tokens (for anchor-mismatch cases).
    """
    cached = _CRAFTED_CERTS.get(variant)
    if cached is not None:
        return cached
    specifications: dict[str, tuple[str, int, tuple[int, int, int], tuple[int, int, int], bool]] = {
        "no-eku": (
            "Hyphaweave H0 test TSA (no EKU)",
            7001,
            (2026, 1, 1),
            (2126, 1, 1),
            False,
        ),
        "expired": (
            "Hyphaweave H0 test TSA (expired)",
            7002,
            (2020, 1, 1),
            (2021, 1, 1),
            True,
        ),
        "wrong-anchor": (
            "Hyphaweave H0 test TSA (wrong anchor)",
            7003,
            (2026, 1, 1),
            (2126, 1, 1),
            True,
        ),
        "ku-without-digital": (
            "Hyphaweave H0 test TSA (no digitalSignature)",
            7004,
            (2026, 1, 1),
            (2126, 1, 1),
            True,
        ),
        "eku-wrong": (
            "Hyphaweave H0 test TSA (wrong EKU)",
            7005,
            (2026, 1, 1),
            (2126, 1, 1),
            True,
        ),
    }
    common_name, serial, not_before, not_after, with_eku = specifications[variant]
    base = asn1_x509.Certificate.load(_tsa_certificate_der())
    subject_public_key_info = base["tbs_certificate"]["subject_public_key_info"]

    def time_value(year_month_day: tuple[int, int, int]) -> Any:
        year, month, day = year_month_day
        moment = datetime.datetime(year, month, day, tzinfo=datetime.timezone.utc)
        key = "utc_time" if 1950 <= year <= 2049 else "general_time"
        return asn1_x509.Time({key: moment})

    extensions = [
        asn1_x509.Extension(
            {
                "extn_id": "basic_constraints",
                "critical": True,
                "extn_value": asn1_x509.BasicConstraints({"ca": False}),
            }
        ),
        asn1_x509.Extension(
            {
                "extn_id": "key_usage",
                "critical": True,
                "extn_value": asn1_x509.KeyUsage(
                    {"key_encipherment"}
                    if variant == "ku-without-digital"
                    else {"digital_signature"}
                ),
            }
        ),
    ]
    if with_eku:
        extensions.append(
            asn1_x509.Extension(
                {
                    "extn_id": "extended_key_usage",
                    "critical": True,
                    "extn_value": asn1_x509.ExtKeyUsageSyntax(
                        ["code_signing"]
                        if variant == "eku-wrong"
                        else ["time_stamping"]
                    ),
                }
            )
        )
    name = asn1_x509.Name.build({"common_name": common_name})
    tbs = asn1_x509.TbsCertificate()
    tbs["version"] = "v3"
    tbs["serial_number"] = serial
    tbs["signature"] = {"algorithm": "sha256_rsa"}
    tbs["issuer"] = name
    validity = asn1_x509.Validity()
    validity["not_before"] = time_value(not_before)
    validity["not_after"] = time_value(not_after)
    tbs["validity"] = validity
    tbs["subject"] = name
    tbs["subject_public_key_info"] = subject_public_key_info
    tbs["extensions"] = extensions
    signature = _tsa_private_key().sign(
        tbs.dump(), crypto_padding.PKCS1v15(), crypto_hashes.SHA256()
    )
    certificate = asn1_x509.Certificate()
    certificate["tbs_certificate"] = tbs
    certificate["signature_algorithm"] = {"algorithm": "sha256_rsa"}
    certificate["signature_value"] = signature
    der = certificate.dump()
    pem = crypto_x509.load_der_x509_certificate(der).public_bytes(
        crypto_serialization.Encoding.PEM
    )
    _CRAFTED_CERTS[variant] = (der, pem)
    return der, pem


def _tst_info(
    imprint: bytes,
    *,
    hash_algorithm: str = "sha256",
    gen_time: datetime.datetime = FIXED_GEN_TIME,
    accuracy: tuple[int, int, int] | None = None,
) -> Any:
    """The TSTInfo payload of one crafted timestamp token.

    *accuracy* is ``(seconds, millis, micros)``; ``None`` omits the Accuracy
    member entirely, which the profile treats as zero (revision-2 R3).
    """
    tst = asn1_tsp.TSTInfo()
    tst["version"] = "v1"
    tst["policy"] = TSA_POLICY
    tst["message_imprint"] = asn1_tsp.MessageImprint(
        {
            "hash_algorithm": {"algorithm": hash_algorithm},
            "hashed_message": imprint,
        }
    )
    tst["serial_number"] = 2
    tst["gen_time"] = gen_time
    if accuracy is not None:
        seconds, millis, micros = accuracy
        tst["accuracy"] = {
            "seconds": seconds,
            "millis": millis if millis else None,
            "micros": micros if micros else None,
        }
    tst["ordering"] = False
    return tst


def _signed_attributes(
    tst_der: bytes,
    certificate_der: bytes,
    *,
    ess: str = "v2",
    message_digest_override: bytes | None = None,
    content_type_value: str = "tst_info",
) -> Any:
    """CMS signed attributes for one token; *ess* picks the ESS variant."""
    attributes = asn1_cms.CMSAttributes()
    attributes.append(
        asn1_cms.CMSAttribute(
            {"type": "content_type", "values": [content_type_value]}
        )
    )
    attributes.append(
        asn1_cms.CMSAttribute(
            {
                "type": "signing_time",
                "values": [asn1_cms.Time({"utc_time": FIXED_SIGNING_TIME})],
            }
        )
    )
    message_digest = (
        message_digest_override
        if message_digest_override is not None
        else _sha256_bytes(tst_der)
    )
    attributes.append(
        asn1_cms.CMSAttribute(
            {"type": "message_digest", "values": [message_digest]}
        )
    )
    if ess == "v2":
        attributes.append(
            asn1_cms.CMSAttribute(
                {
                    "type": "signing_certificate_v2",
                    "values": [
                        asn1_tsp.SigningCertificateV2(
                            {
                                "certs": [
                                    asn1_tsp.ESSCertIDv2(
                                        {
                                            "hash_algorithm": {"algorithm": "sha256"},
                                            "cert_hash": _sha256_bytes(certificate_der),
                                        }
                                    )
                                ]
                            }
                        )
                    ],
                }
            )
        )
    elif ess == "v1":
        attributes.append(
            asn1_cms.CMSAttribute(
                {
                    "type": "signing_certificate",
                    "values": [
                        asn1_tsp.SigningCertificate(
                            {
                                "certs": [
                                    asn1_tsp.ESSCertID(
                                        {
                                            "cert_hash": hashlib.sha1(
                                                certificate_der
                                            ).digest()
                                        }
                                    )
                                ]
                            }
                        )
                    ],
                }
            )
        )
    elif ess != "none":
        raise SystemExit("unknown ESS variant %r" % (ess,))
    return attributes


def _crafted_tsr(
    imprint: bytes,
    *,
    certificate_der: bytes | None = None,
    ess: str = "v2",
    include_certificate: bool = True,
    message_digest_override: bytes | None = None,
    tamper_signature: bool = False,
    status: int = 0,
    imprint_algorithm: str = "sha256",
    imprint_bytes: bytes | None = None,
    encap_content_type: str = "tst_info",
    attribute_content_type: str = "tst_info",
    signer_digest_algorithm: str = "sha256",
    certificates_override: Sequence[bytes] | None = None,
    accuracy: tuple[int, int, int] | None = None,
) -> bytes:
    """Build one DER TimeStampResp deterministically (see module section note)."""
    signer_der = certificate_der if certificate_der is not None else _tsa_certificate_der()
    signer_certificate = asn1_x509.Certificate.load(signer_der)
    tst = _tst_info(
        imprint_bytes if imprint_bytes is not None else imprint,
        hash_algorithm=imprint_algorithm,
        accuracy=accuracy,
    )
    attributes = _signed_attributes(
        tst.dump(),
        signer_der,
        ess=ess,
        message_digest_override=message_digest_override,
        content_type_value=attribute_content_type,
    )
    _digest_classes = {
        "sha256": crypto_hashes.SHA256,
        "sha384": crypto_hashes.SHA384,
        "sha512": crypto_hashes.SHA512,
    }
    signature = _tsa_private_key().sign(
        attributes.untag().dump(),
        crypto_padding.PKCS1v15(),
        _digest_classes[signer_digest_algorithm](),
    )
    if tamper_signature:
        signature = bytes([signature[0] ^ 0x01]) + signature[1:]
    signer_info = asn1_cms.SignerInfo()
    signer_info["version"] = "v1"
    signer_info["sid"] = asn1_cms.SignerIdentifier(
        {
            "issuer_and_serial_number": asn1_cms.IssuerAndSerialNumber(
                {
                    "issuer": signer_certificate.issuer,
                    "serial_number": signer_certificate.serial_number,
                }
            )
        }
    )
    signer_info["digest_algorithm"] = {"algorithm": signer_digest_algorithm}
    signer_info["signed_attrs"] = attributes
    signer_info["signature_algorithm"] = {"algorithm": "rsassa_pkcs1v15"}
    signer_info["signature"] = signature
    encapsulated = asn1_cms.EncapsulatedContentInfo(
        {
            "content_type": encap_content_type,
            "content": asn1_cms.ParsableOctetString(parsed=tst)
            if encap_content_type == "tst_info"
            else asn1_cms.ParsableOctetString(tst.dump()),
        }
    )
    signed_data = asn1_cms.SignedData()
    signed_data["version"] = "v3"
    signed_data["digest_algorithms"] = [{"algorithm": "sha256"}]
    signed_data["encap_content_info"] = encapsulated
    if certificates_override is not None:
        signed_data["certificates"] = [
            asn1_cms.CertificateChoices(
                {"certificate": asn1_x509.Certificate.load(der)}
            )
            for der in certificates_override
        ]
    elif include_certificate:
        signed_data["certificates"] = [
            asn1_cms.CertificateChoices({"certificate": signer_certificate})
        ]
    signed_data["signer_infos"] = [signer_info]
    token = asn1_cms.ContentInfo(
        {"content_type": "signed_data", "content": signed_data}
    )
    response = asn1_tsp.TimeStampResp()
    status_info = asn1_tsp.PKIStatusInfo()
    status_info["status"] = status
    response["status"] = status_info
    response["time_stamp_token"] = token
    return response.dump()


# Manifest attestation with the timestamp chain (spec §12; renewals included).


def _seal_with_timestamps(
    files: dict[str, bytes],
    manifest_value: dict[str, Any],
    entries: Sequence[tuple[str, bytes, str | None]],
) -> tuple[dict[str, bytes], str]:
    """Write manifest.json and signatures/manifest.sig.json with a TSR chain.

    *entries* is ``(relative path, tsr bytes, renews)`` in path order; the
    ``renews`` member points at the previous reply of the single chain (or is
    ``None`` for the chain head).
    """
    files["manifest.json"] = canonical(manifest_value)
    manifest_digest_value = recordlib.manifest_digest(files["manifest.json"])
    base_sigfile = recordlib.manifest_sigfile(manifest_digest_value, ("human-1",))
    timestamps = []
    for relative, data, renews in sorted(entries):
        files[relative] = data
        timestamps.append(
            {
                "path": relative,
                "digest": wcj.sha256_digest(data),
                "renews": renews,
            }
        )
    sigfile = {
        "digest": manifest_digest_value,
        "format": FORMAT,
        "signatures": base_sigfile["signatures"],
        "timestamps": timestamps,
    }
    files["signatures/manifest.sig.json"] = canonical(sigfile)
    return files, manifest_digest_value


def _build_timestamped_container(
    records: Sequence[dict[str, Any]],
    timestamp_builder: Callable[[bytes], Sequence[tuple[str, bytes, str | None]]],
    *,
    level: str = "L2",
    created_at: str = recordlib.T0,
    manifest_signers: Sequence[str] = ("human-1",),
) -> dict[str, bytes]:
    """Build a container and add the given timestamp chain to its sig file."""
    files = recordlib.build_container(
        records,
        level=level,
        created_at=created_at,
        manifest_signers=manifest_signers,
    )
    manifest_value = parse(files["manifest.json"])
    manifest_bytes = canonical(manifest_value)
    manifest_digest_value = recordlib.manifest_digest(manifest_bytes)
    imprint = bytes.fromhex(manifest_digest_value[len("sha256:") :])
    return _seal_with_timestamps(files, manifest_value, timestamp_builder(imprint))[0]


def _tampered_signature_value(value: str) -> bytes:
    """Decode one 64-byte base64url signature and flip its first bit."""
    raw = keyutil.b64url_decode(value, expected_len=64)
    return bytes([raw[0] ^ 0x01]) + raw[1:]


def _zip_with_traversal(files: dict[str, bytes]) -> bytes:
    """Deterministic STORED zip that also contains one path-escaping entry."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for path in sorted(files):
            info = zipfile.ZipInfo(path, date_time=(2026, 11, 10, 0, 0, 0))
            info.external_attr = 0o644 << 16
            info.create_system = 3
            archive.writestr(info, files[path])
        info = zipfile.ZipInfo("../escape.json", date_time=(2026, 11, 10, 0, 0, 0))
        info.external_attr = 0o644 << 16
        info.create_system = 3
        archive.writestr(info, b"{}\n")
    return buffer.getvalue()


def _previous_manifest_bytes(*, origin_instance: str | None = None) -> bytes:
    """Manifest bytes of a tiny valid L0 container (used as previous/)."""
    return recordlib.build_container(
        [recordlib.key_declaration("human-2")],
        level="L0",
        created_at=recordlib.EARLY,
        manifest_signers=("human-2",),
        origin_value=(
            None
            if origin_instance is None
            else recordlib.origin(origin_instance)
        ),
    )["manifest.json"]


def _chain_previous_digest() -> str:
    return recordlib.manifest_digest(_previous_manifest_bytes())


def _chain_container(
    case_dir: Path, *, mismatch: bool, origin_mismatch: bool = False
) -> dict[str, bytes]:
    """Build container c2 that embeds the previous manifest bytes.

    ``origin_mismatch`` makes the embedded previous manifest come from another
    origin (different instance key) while its digest still matches, which is
    the manifest-chain same-origin defect.
    """
    previous_bytes = _previous_manifest_bytes(
        origin_instance=(
            recordlib.kid("human-2") if origin_mismatch else None
        )
    )
    previous_digest = recordlib.manifest_digest(previous_bytes)
    if mismatch:
        previous_digest = "sha256:" + "22" * 32
    files = recordlib.build_container(
        [recordlib.key_declaration("human-1")],
        level="L0",
        created_at=recordlib.T1,
        manifest_signers=("human-1",),
        previous_manifest={"digest": previous_digest},
        previous_manifest_bytes=previous_bytes,
    )
    return wrap(files)


def _l0_with_chain_files() -> dict[str, bytes]:
    """L0 container whose manifest nevertheless claims a chain head."""
    built = recordlib.build_container(SIMPLE_RECORDS(), level="L0")

    def mutator(manifest: dict[str, Any]) -> dict[str, Any]:
        result = dict(manifest)
        result["chain"] = {"algorithm": "sha256", "head": "sha256:" + "77" * 32}
        return result

    return recordlib.mutate_manifest(built, mutator, resign_with=("human-1",))


def _previous_external_mismatch_files() -> dict[str, bytes]:
    """Chain-valid c2 plus a --previous container whose manifest differs."""
    files = _chain_container(Path("."), mismatch=False)
    # A genuinely different previous container: same origin, different contents
    # (different created_at), so its manifest digest differs from the embedded
    # previous/manifest.json that c2 commits to.
    other_bytes = recordlib.build_container(
        [recordlib.key_declaration("human-2")],
        level="L0",
        created_at=recordlib.T5,
        manifest_signers=("human-2",),
    )["manifest.json"]
    files["previous-container/manifest.json"] = other_bytes
    return files


def _previous_external_mismatch_files_checked() -> dict[str, bytes]:
    return _previous_external_mismatch_files()


def _manifest_sig_record_prefix_files() -> dict[str, bytes]:
    """A container whose manifest signature is made over the record domain."""
    files = recordlib.build_container(SIMPLE_RECORDS())
    sigfile = wcj.parse_strict(files["signatures/manifest.sig.json"])
    message = keyutil.SIG_DOMAIN + sigfile["digest"].encode("ascii")
    signature = recordlib.key("human-1").sign(message)
    sigfile["signatures"] = [
        {
            "alg": "ed25519",
            "key": recordlib.kid("human-1"),
            "value": keyutil.b64url_encode(signature),
        }
    ]
    files["signatures/manifest.sig.json"] = canonical(sigfile)
    return files


# ---------------------------------------------------------------------------
# container cases: layout, manifest, records/ blobs/, chain
# ---------------------------------------------------------------------------

# A single valid self-signed key declaration is enough for the container-level
# cases: the manifest checks must fail before any record verdict is produced.
SIMPLE_RECORDS = lambda: [recordlib.key_declaration("human-1")]  # noqa: E731


def _two_records() -> list[dict[str, Any]]:
    return [
        recordlib.key_declaration("human-1"),
        recordlib.signed(note("container-note-2"), "human-1"),
    ]


declare(
    "container",
    "l0-minimal",
    "container",
    "container",
    "valid",
    build=lambda case_dir: container(SIMPLE_RECORDS()),
    args=("--keys", "@keyset"),
    expected_container={
        "level_claimed": "L0",
        "level_verified": "L0",
        "chain": {"status": "absent"},
        "previous_manifest_digest": None,
        "record_count": 1,
    },
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    notes="SPECIAL CASE: the worked example of spec/offline-verification.md. One "
    "weave.key.declared record signed by its own key, an L0 manifest signed by "
    "that key, every byte canonical, nothing else. The byte-level manual "
    "sha256sum/openssl procedure still walks it end to end; record trust comes "
    "from the local trust input (--keys @keyset, revision-2 R2): without it the "
    "same bytes are unverifiable (see container/self-attested-root-untrusted).",
)

declare(
    "container",
    "manifest-unsigned",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_UNSIGNED",),
    build=lambda case_dir: mutate_sigfile(
        recordlib.build_container(SIMPLE_RECORDS()),
        lambda sigfile: {**sigfile, "signatures": []},
    ),
    notes="manifest attestation lists no signatures: a manifest MUST be signed "
    "(§11.3, I2); digest is correct and the container is otherwise sound.",
)

declare(
    "container",
    "manifest-sig-invalid",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_SIG_INVALID",),
    build=lambda case_dir: mutate_sigfile(
        recordlib.build_container(SIMPLE_RECORDS()),
        lambda sigfile: {
            **sigfile,
            "signatures": [
                {
                    **sigfile["signatures"][0],
                    "value": keyutil.b64url_encode(
                        _tampered_signature_value(sigfile["signatures"][0]["value"])
                    ),
                }
            ],
        },
    ),
    notes="A genuine manifest signature with one raw byte flipped must fail "
    "E_MANIFEST_SIG_INVALID (§2.4/§11.3).",
)

declare(
    "container",
    "manifest-digest-wrong",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_DIGEST",),
    build=lambda case_dir: mutate_sigfile(
        recordlib.build_container(SIMPLE_RECORDS()),
        lambda sigfile: {**sigfile, "digest": "sha256:" + "11" * 32},
    ),
    notes="signatures/manifest.sig.json.digest does not equal the §2.4 manifest "
    "digest; the digest check precedes signature verification (§14.5).",
)

declare(
    "container",
    "manifest-format-wrong",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_FORMAT",),
    build=lambda case_dir: mutate(
        recordlib.build_container(SIMPLE_RECORDS()),
        lambda manifest: {**manifest, "format": "weave-record/2"},
    ),
    notes="manifest.format is not weave-record/1; re-sealed so the digest and "
    "signature are internally consistent and only the format check fails.",
)

declare(
    "container",
    "manifest-version-unsupported",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_VERSION",),
    build=lambda case_dir: mutate(
        recordlib.build_container(SIMPLE_RECORDS()),
        lambda manifest: {**manifest, "manifest_version": 2},
    ),
    notes="H0 supports only manifest_version 1; an unknown integer version is "
    "unsupported (E_MANIFEST_VERSION), never silently accepted (K3).",
)

declare(
    "container",
    "record-extra",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_RECORD_EXTRA",),
    build=lambda case_dir: _record_extra_files(),
    notes="records/ contains a well-formed file that the manifest does not list "
    "(§11.6): every record file must be listed exactly once.",
)

declare(
    "container",
    "manifest-id-kind-mismatch",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_RECORDS",),
    build=lambda case_dir: _manifest_id_kind_mismatch_files(),
    notes="manifest.records[] entries claim the id and kind of the record they "
    "list; here the kind claim (weave.key.revoked) contradicts the envelope kind "
    "(weave.key.declared) inside records/<digest>.json while the digest is still "
    "correct. The manifest/records listing is inconsistent: E_MANIFEST_RECORDS "
    "(§11.2/§11.6). Re-sealed so only the cross-check fails.",
)

declare(
    "container",
    "record-missing",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_RECORD_MISSING",),
    build=lambda case_dir: drop(
        recordlib.build_container(SIMPLE_RECORDS()), record_path(
            recordlib.build_container(SIMPLE_RECORDS())
        )
    ),
    args=("--keys", "@keyset"),
    notes="A digest listed in manifest.records has no files/records/<hex>.json "
    "file (§11.6).",
)

declare(
    "container",
    "record-digest-mismatch",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_RECORD_DIGEST",),
    build=lambda case_dir: (
        lambda files: replace(
            files,
            record_path(files),
            canonical(note("container-tampered", body={"tampered": True})),
        )
    )(recordlib.build_container(SIMPLE_RECORDS())),
    args=("--keys", "@keyset"),
    notes="The records/ file content no longer hashes to its filename/manifest "
    "digest (§11.6).",
)

declare(
    "container",
    "manifest-records-unsorted",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_RECORDS",),
    build=lambda case_dir: mutate(
        recordlib.build_container(_two_records()),
        lambda manifest: {
            **manifest,
            "records": list(reversed(manifest["records"])),
        },
    ),
    notes="manifest.records must be sorted by digest ascending with unique "
    "digests (§11.2); two genuinely sorted entries are reversed here.",
)

declare(
    "container",
    "unknown-top-level-entry",
    "container",
    "container",
    "invalid",
    errors=("E_CONTAINER_ENTRY",),
    build=lambda case_dir: replace(
        recordlib.build_container(SIMPLE_RECORDS()), "notes.txt", b"not listed\n"
    ),
    notes="A file outside the closed container layout is E_CONTAINER_ENTRY "
    "(§11.1); the check runs during entry enumeration, before manifest checks.",
)

declare(
    "container",
    "zip-valid",
    "container",
    "container.zip",
    "valid",
    build=lambda case_dir: zip_wrap(recordlib.build_container(SIMPLE_RECORDS())),
    args=("--keys", "@keyset"),
    expected_container={"level_claimed": "L0", "level_verified": "L0"},
    notes="Positive zip form (§11.9): the same layout, STORED entries, POSIX "
    "relative paths; must verify like the directory form.",
)

declare(
    "container",
    "zip-traversal",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_ENTRY",),
    build=lambda case_dir: {
        "container.zip": _zip_with_traversal(
            recordlib.build_container(SIMPLE_RECORDS())
        )
    },
    notes="A zip entry whose path escapes the container root must be rejected "
    "during safe entry enumeration (§11.1/§11.9), before any manifest parsing.",
)

declare(
    "container",
    "blobs-mismatch",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_BLOB",),
    build=lambda case_dir: _blobs_mismatch_files(),
    args=("--keys", "@keyset"),
    notes="blobs/sha256/<hex> content must hash to the manifest.blobs entry and "
    "match its size (§11.6); the bytes are altered after the manifest is sealed.",
)

declare(
    "container",
    "readable-ignored",
    "container",
    "container",
    "valid",
    build=lambda case_dir: replace(
        recordlib.build_container(SIMPLE_RECORDS()),
        "readable/notes.txt",
        b"human readable view, never hashed and never trusted\n",
    ),
    args=("--keys", "@keyset"),
    expected_container={"level_claimed": "L0", "level_verified": "L0"},
    notes="readable/ is an optional human view outside the digest (§11.8, I1): "
    "arbitrary bytes there must not change validity (N_READABLE_PRESENT is an "
    "optional notice, so it is not required here).",
)

declare(
    "container",
    "chain-valid",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _chain_container(case_dir, mismatch=False),
    args=("--keys", "@keyset"),
    expected_container={
        "level_claimed": "L0",
        "level_verified": "L0",
        "previous_manifest_digest": _chain_previous_digest(),
    },
    notes="Container c2 embeds c1's manifest under previous/manifest.json and "
    "commits previous_manifest.digest == manifest-digest(c1 bytes) (§11.5, D1). "
    "The previous manifest's own signature is not re-verified (N_PREVIOUS_SIG_"
    "UNVERIFIED is optional, not required).",
)

declare(
    "container",
    "chain-digest-mismatch",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_CHAIN",),
    build=lambda case_dir: _chain_container(case_dir, mismatch=True),
    args=("--keys", "@keyset"),
    notes="previous_manifest.digest does not equal the digest of the embedded "
    "previous/manifest.json bytes (§11.5).",
)

declare(
    "container",
    "chain-missing",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_CHAIN_MISSING",),
    build=lambda case_dir: drop(
        _chain_container(case_dir, mismatch=False),
        "container/previous/manifest.json",
    ),
    args=("--keys", "@keyset"),
    notes="previous_manifest is non-null but previous/manifest.json is absent "
    "(§11.5, E_MANIFEST_CHAIN_MISSING).",
)

declare(
    "container",
    "chain-unexpected-file",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_CHAIN_UNEXPECTED",),
    build=lambda case_dir: replace(
        recordlib.build_container(SIMPLE_RECORDS()),
        "previous/manifest.json",
        _previous_manifest_bytes(),
    ),
    args=("--keys", "@keyset"),
    notes="previous_manifest is null but previous/ contains a manifest: an "
    "unexpected previous container is rejected (§11.5).",
)

declare(
    "container",
    "chain-origin-mismatch",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_CHAIN",),
    build=lambda case_dir: _chain_container(case_dir, mismatch=False, origin_mismatch=True),
    args=("--keys", "@keyset"),
    notes="previous_manifest.digest matches the embedded previous/manifest.json bytes, "
    "but that previous manifest belongs to a different origin. The manifest chain "
    "must stay within the same publisher origin (E_MANIFEST_CHAIN, D1).",
)

declare(
    "container",
    "l0-with-chain",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_LEVEL",),
    build=lambda case_dir: _l0_with_chain_files(),
    notes="A manifest claiming L0 with a non-null chain head: L0 is the level "
    "without an internal chain claim, so this level/contents contradiction is "
    "E_MANIFEST_LEVEL.",
)

declare(
    "container",
    "previous-external-mismatch",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_CHAIN",),
    build=lambda case_dir: _previous_external_mismatch_files_checked(),
    args=("--keys", "@keyset", "--previous", "previous-container"),
    notes="The embedded previous/manifest.json matches previous_manifest.digest, "
    "but the explicitly supplied --previous container has a different manifest "
    "digest: the external chain comparison fails (E_MANIFEST_CHAIN, D1/D2).",
)

declare(
    "container",
    "manifest-sig-record-prefix",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_SIG_INVALID",),
    build=lambda case_dir: _manifest_sig_record_prefix_files(),
    notes="The manifest signature is computed over the record domain prefix "
    "(weave-record/1/sig) instead of the manifest domain. A signature made for one "
    "purpose must never verify for the other (E_MANIFEST_SIG_INVALID, C4).",
)

declare(
    "container",
    "manifest-missing",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_MISSING",),
    build=lambda case_dir: drop(
        wrap(recordlib.build_container(SIMPLE_RECORDS())), "container/manifest.json"
    ),
    notes="A container directory without manifest.json is E_MANIFEST_MISSING "
    "(§11.1), not "
    "a generic parse error.",
)



# ---------------------------------------------------------------------------
# erasure cases (§10, G3)
# ---------------------------------------------------------------------------


def erased_original(record_id: str = "erasure-original-1") -> dict[str, Any]:
    """The live record that is about to be erased (never exported)."""
    return note(record_id, body={"text": "sensitive original body"})


def erasure_record(
    original: dict[str, Any],
    *,
    record_id: str = "erasure-attestation-1",
    reason: str = "data-subject-request",
    signer: str = "human-1",
    actor_type: str | None = None,
    actor_override: dict[str, Any] | None = None,
    basis: dict[str, Any] | None = None,
    erased_digest: str | None = None,
    with_signature: bool = True,
) -> dict[str, Any]:
    original_digest = recordlib.record_digest(original)
    body = {
        "erased": recordlib.make_ref(
            original["origin"]["instance"],
            original["id"],
            erased_digest if erased_digest is not None else original_digest,
            kind=original["kind"],
        ),
        "reason": reason,
        "reason_note": None,
        "basis": basis,
    }
    record = recordlib.build_record(
        kind="weave.erasure",
        id=record_id,
        actor=(
            actor_override
            if actor_override is not None
            else recordlib.actor(signer, actor_type=actor_type)
        ),
        body=body,
        stage="accepted",
        recorded_at=recordlib.T4,
        origin_instance=kid(signer),
    )
    return recordlib.signed(record, signer) if with_signature else record


def erased_placeholder(
    original: dict[str, Any],
    attestation: dict[str, Any],
    *,
    digest: str | None = None,
) -> dict[str, Any]:
    """The replacement object for an erased record (exact §4.5 shape)."""
    return {
        "format": FORMAT,
        "kind": "weave.erased",
        "origin": original["origin"],
        "id": original["id"],
        "digest": digest if digest is not None else recordlib.record_digest(original),
        "attestation": recordlib.make_ref(
            attestation["origin"]["instance"],
            attestation["id"],
            recordlib.record_digest(attestation),
            kind="weave.erasure",
        ),
    }


def _erasure_valid_files() -> dict[str, bytes]:
    original = erased_original()
    attestation = erasure_record(original)
    placeholder = erased_placeholder(original, attestation)
    return container([placeholder, attestation])


ERASURE_ARGS = ("--keys", "@keyset")

declare(
    "erasure",
    "valid-container",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _erasure_valid_files(),
    args=ERASURE_ARGS,
    records=(
        {"id": "erasure-attestation-1", "verdict": "valid", "errors": []},
        {
            "id": "erasure-original-1",
            "verdict": "erased",
            "errors": [],
        },
    ),
    notes="Positive: the live record is replaced by a weaver.erased placeholder whose "
    "digest is the original record digest and whose attestation resolves to the "
    "signed weave.erasure record; the placeholder's own verdict is 'erased', the "
    "erasure record is valid, and both cross-checks hold (§10.2/§10.3, G3a/G3b).",
)

declare(
    "erasure",
    "unsigned",
    "record",
    "record.json",
    "invalid",
    errors=("E_SIG_REQUIRED",),
    build=lambda case_dir: {
        "record.json": canonical(
            erasure_record(
                erased_original(), record_id="erasure-unsigned-1", with_signature=False
            )
        )
    },
    args=ERASURE_ARGS,
    notes="A weave.erasure record MUST be per-record signed (§4.4); without sigs it "
    "is E_SIG_REQUIRED before any body/ref check.",
)

declare(
    "erasure",
    "reason-invalid",
    "record",
    "record.json",
    "invalid",
    errors=("E_KIND_BODY_SCHEMA",),
    build=lambda case_dir: {
        "record.json": canonical(
            erasure_record(erased_original(), reason="because-i-said-so")
        )
    },
    args=ERASURE_ARGS,
    notes="The erasure reason is a closed enum (§10.2); an unknown value is a kind "
    "body schema failure. Genuinely signed so the check is reached.",
)

declare(
    "erasure",
    "digest-mismatch",
    "container",
    "container",
    "invalid",
    errors=("E_ERASE_DIGEST_MISMATCH",),
    build=lambda case_dir: (
        lambda original, attestation: container(
            [
                erased_placeholder(
                    original,
                    attestation,
                    digest=recordlib.record_digest(original),
                ),
                attestation,
            ]
        )
    )(
        erased_original(),
        erasure_record(
            erased_original(), erased_digest="sha256:" + "33" * 32
        ),
    ),
    args=ERASURE_ARGS,
    notes="The erasure record's erased reference names a different digest than the "
    "placeholder it attests (§10.3): E_ERASE_DIGEST_MISMATCH.",
)

declare(
    "erasure",
    "attestation-missing",
    "container",
    "container",
    "invalid",
    errors=("E_ERASE_ATTESTATION",),
    build=lambda case_dir: container(
        [
            {
                "format": FORMAT,
                "kind": "weave.erased",
                "origin": recordlib.origin(kid("human-1")),
                "id": "erasure-orphan-1",
                "digest": "sha256:" + "44" * 32,
                "attestation": recordlib.make_ref(
                    kid("human-1"),
                    "no-such-erasure",
                    "sha256:" + "55" * 32,
                    kind="weave.erasure",
                ),
            }
        ]
    ),
    args=ERASURE_ARGS,
    notes="A placeholder whose attestation reference resolves to nothing is "
    "E_ERASE_ATTESTATION (§4.5/§10.3): an erasure claim without its attestation is not "
    "acceptable evidence.",
)

declare(
    "erasure",
    "contradiction",
    "container",
    "container",
    "invalid",
    errors=("E_ERASE_CONTRADICTION",),
    build=lambda case_dir: (
        lambda original, attestation: container(
            [original, erased_placeholder(original, attestation), attestation]
        )
    )(erased_original(), erasure_record(erased_original())),
    args=ERASURE_ARGS,
    notes="The same origin+id appears both as the live record and as an erased "
    "placeholder: erasure must replace the record, never coexist with it (§10.1, "
    "G3e: withdrawn records are appended, only erasure replaces).",
)

declare(
    "erasure",
    "actor-program-without-grant",
    "record",
    "record.json",
    "invalid",
    errors=("E_ERASE_ACTOR",),
    build=lambda case_dir: {
        "record.json": canonical(
            erasure_record(
                erased_original(),
                record_id="erasure-program-1",
                signer="program-1",
                actor_type="program",
            )
        )
    },
    args=ERASURE_ARGS,
    notes="Only a human may execute an erasure (§10.2, G3a): a program actor is "
    "E_ERASE_ACTOR invalid (the record is correctly signed by its own key, so the "
    "actor rule is the defect).",
)


# ---------------------------------------------------------------------------
# grant cases (§5.4/§5.5; principle "agents only propose unless granted")
# ---------------------------------------------------------------------------

GRANT_ARGS = ("--keys", "@keyset")
GRANT_ACTIONS = ["propose", "accept", "reject", "withdraw", "supersede", "erase", "grant"]


def parent_ref(grant: dict[str, Any]) -> dict[str, Any]:
    return recordlib.make_ref(
        grant["origin"]["instance"],
        grant["id"],
        recordlib.record_digest(grant),
        kind="weave.grant",
    )


def root_grant(
    *,
    record_id: str = "grant-root-1",
    granter: str = "human-1",
    grantee: str = "agent-1",
    kinds: Sequence[str] = ("example.note",),
    actions: Sequence[str] = ("propose", "accept"),
    scope: Sequence[str] = ("example",),
    valid_from: str = recordlib.T0,
    valid_until: str | None = recordlib.T9,
    transferable: bool = True,
    revocation: Sequence[str] | None = None,
) -> dict[str, Any]:
    """A root weave.grant issued by a human key (spec §5.5)."""
    body = {
        "action": "grant",
        "grant": {
            "grantee": {"key": kid(grantee)},
            "kinds": list(kinds),
            "actions": list(actions),
            "scope": list(scope),
            "valid_from": valid_from,
            "valid_until": valid_until,
            "transferable": transferable,
            "evidence": None,
            "remedy": None,
        },
    }
    if revocation is not None:
        body["grant"]["revocation"] = [kid(name) for name in revocation]
    record = recordlib.build_record(
        kind="weave.grant",
        id=record_id,
        actor=recordlib.actor(granter),
        body=body,
        stage="accepted",
        recorded_at=valid_from,
        origin_instance=kid(granter),
    )
    return recordlib.signed(record, granter)


def delegated_grant(
    parent: dict[str, Any],
    *,
    record_id: str = "grant-sub-1",
    sub_granter: str = "agent-1",
    grantee: str = "agent-2",
    kinds: Sequence[str] = ("example.note",),
    actions: Sequence[str] = ("propose",),
    scope: Sequence[str] = ("example",),
    valid_from: str = recordlib.T1,
    valid_until: str | None = recordlib.T8,
    transferable: bool = False,
    recorded_at: str | None = None,
) -> dict[str, Any]:
    """A delegated sub-grant signed by an agent under a parent grant."""
    body = {
        "action": "grant",
        "grant": {
            "grantee": {"key": kid(grantee)},
            "kinds": list(kinds),
            "actions": list(actions),
            "scope": list(scope),
            "valid_from": valid_from,
            "valid_until": valid_until,
            "transferable": transferable,
            "evidence": None,
            "remedy": None,
        },
    }
    actor = recordlib.actor(
        sub_granter,
        model="example/model@1.2.3",
        on_behalf_of=kid("human-1"),
        grant=parent_ref(parent),
        idempotency_key="idem-" + record_id,
    )
    record = recordlib.build_record(
        kind="weave.grant",
        id=record_id,
        actor=actor,
        body=body,
        stage="accepted",
        recorded_at=recorded_at if recorded_at is not None else valid_from,
        origin_instance=kid(sub_granter),
    )
    return recordlib.signed(record, sub_granter)


def _agent_grant_without_parent() -> dict[str, Any]:
    """An agent-signed weave.grant whose actor.grant resolves to nothing."""
    body = {
        "action": "grant",
        "grant": {
            "grantee": {"key": kid("agent-2")},
            "kinds": ["example.note"],
            "actions": ["propose"],
            "scope": ["example"],
            "valid_from": recordlib.T1,
            "valid_until": recordlib.T8,
            "transferable": False,
            "evidence": None,
            "remedy": None,
        },
    }
    actor = recordlib.actor(
        "agent-1",
        model="example/model@1.2.3",
        on_behalf_of=kid("human-1"),
        grant=recordlib.make_ref(
            kid("human-1"), "no-such-parent-grant", "sha256:" + "77" * 32, kind="weave.grant"
        ),
        idempotency_key="idem-agent-grant-no-parent",
    )
    record = recordlib.build_record(
        kind="weave.grant",
        id="grant-agent-no-parent",
        actor=actor,
        body=body,
        stage="accepted",
        recorded_at=recordlib.T1,
        origin_instance=kid("agent-1"),
    )
    return recordlib.signed(record, "agent-1")


def grant_revocation(
    grant: dict[str, Any],
    *,
    record_id: str = "grant-revoke-1",
    signer: str = "human-1",
    effective_at: str = recordlib.T3,
    revokes_digest: str | None = None,
    revokes_ref: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body = {
        "action": "revoke",
        "revoke": {
            "revokes": revokes_ref
            if revokes_ref is not None
            else recordlib.make_ref(
                grant["origin"]["instance"],
                grant["id"],
                revokes_digest
                if revokes_digest is not None
                else recordlib.record_digest(grant),
                kind="weave.grant",
            ),
            "effective_at": effective_at,
            "reason": None,
        },
    }
    record = recordlib.build_record(
        kind="weave.grant",
        id=record_id,
        actor=recordlib.actor(signer),
        body=body,
        stage="accepted",
        recorded_at=effective_at,
        origin_instance=kid(signer),
    )
    return recordlib.signed(record, signer)


def agent_action(
    grant: dict[str, Any],
    *,
    record_id: str = "agent-action-1",
    key_name: str = "agent-1",
    kind: str = "example.note",
    stage: str = "accepted",
    recorded_at: str = recordlib.T2,
) -> dict[str, Any]:
    """A record authored by an agent citing the given grant (§5.4)."""
    actor = recordlib.actor(
        key_name,
        model="example/model@1.2.3",
        on_behalf_of=kid("human-1"),
        grant=parent_ref(grant),
        idempotency_key="idem-" + record_id,
    )
    record = recordlib.build_record(
        kind=kind,
        id=record_id,
        actor=actor,
        body={"text": "agent action"},
        stage=stage,
        recorded_at=recorded_at,
    )
    return recordlib.signed(record, key_name)


declare(
    "grant",
    "valid-root",
    "record",
    "record.json",
    "valid",
    build=lambda case_dir: {
        "record.json": canonical(
            root_grant(
                kinds=("example.note", "example.receipt"),
                actions=("propose", "accept"),
            )
        )
    },
    args=GRANT_ARGS,
    expected_digest=True,
    notes="Baseline root grant: a human key issues kind, action, scope, validity "
    "and transferability for one agent; signed by the granter's key (§5.5).",
)

declare(
    "grant",
    "agent-grant-without-parent",
    "record",
    "record.json",
    "unverifiable",
    errors=("E_GRANT_UNRESOLVED",),
    build=lambda case_dir: {
        "record.json": canonical(
            _agent_grant_without_parent()
        )
    },
    args=GRANT_ARGS,
    notes="An agent-signed weave.grant is a delegated sub-grant. Its actor.grant "
    "reference is absent from the verification context, so the delegation cannot "
    "be checked: unverifiable E_GRANT_UNRESOLVED (§5.4/§5.5, registry distinction: "
    "E_GRANT_GRANTER is only for a parent that is resolvable but does not permit "
    "issuing grants — see grant/parent-not-authorising).",
)

declare(
    "grant",
    "parent-not-authorising",
    "container",
    "container",
    "invalid",
    errors=("E_GRANT_GRANTER",),
    build=lambda case_dir: (
        lambda parent: container(
            [
                parent,
                delegated_grant(parent, record_id="grant-sub-parent-not-authorising"),
            ]
        )
    )(
        root_grant(
            record_id="grant-root-not-authorising",
            kinds=("example.note",),
            actions=("propose", "accept", "grant"),
            transferable=True,
        )
    ),
    args=GRANT_ARGS,
    records=(
        {"id": "grant-root-not-authorising", "verdict": "valid", "errors": []},
        {
            "id": "grant-sub-parent-not-authorising",
            "verdict": "invalid",
            "errors": ["E_GRANT_GRANTER"],
        },
    ),
    notes="The parent grant IS resolvable and transferable, but its kinds list does "
    "not contain weave.grant (it only allows example.note) and therefore does not "
    "authorise issuing further grants. A resolvable parent that does not permit "
    "granting is invalid E_GRANT_GRANTER (§5.5) — the companion case to "
    "agent-grant-without-parent (unresolvable => unverifiable).",
)

declare(
    "grant",
    "sub-grant-parent-not-transferable",
    "container",
    "container",
    "invalid",
    errors=("E_GRANT_NOT_TRANSFERABLE",),
    build=lambda case_dir: (
        lambda parent: container(
            [parent, delegated_grant(parent, record_id="grant-sub-notransfer")]
        )
    )(
        root_grant(
            record_id="grant-root-notransfer",
            kinds=("weave.grant", "example.note"),
            actions=("grant", "propose", "accept"),
            transferable=False,
        )
    ),
    args=GRANT_ARGS,
    records=(
        {"id": "grant-root-notransfer", "verdict": "valid", "errors": []},
        {
            "id": "grant-sub-notransfer",
            "verdict": "invalid",
            "errors": ["E_GRANT_NOT_TRANSFERABLE"],
        },
    ),
    notes="A delegated sub-grant may only exist under a parent whose "
    "transferable=true (§5.5); a parent grant defaults to non-transferable in the "
    "decision draft, and delegation of a non-transferable grant is invalid.",
)

declare(
    "grant",
    "sub-grant-expands-kinds",
    "container",
    "container",
    "invalid",
    errors=("E_GRANT_DELEGATION_EXCEEDS",),
    build=lambda case_dir: (
        lambda parent: container(
            [
                parent,
                delegated_grant(
                    parent,
                    record_id="grant-sub-exceeds",
                    kinds=("example.note", "example.receipt"),
                ),
            ]
        )
    )(
        root_grant(
            record_id="grant-root-exceeds",
            kinds=("weave.grant", "example.note"),
            actions=("grant", "propose", "accept"),
            transferable=True,
        )
    ),
    args=GRANT_ARGS,
    notes="A sub-grant's kinds must be a subset of its parent's kinds and its "
    "validity window must be inside the parent's (§5.5): granting example.receipt "
    "under a parent that only allows example.note exceeds the delegation.",
)

declare(
    "grant",
    "kind-not-covered",
    "container",
    "container",
    "invalid",
    errors=("E_GRANT_NOT_APPLICABLE",),
    build=lambda case_dir: (
        lambda grant: container(
            [grant, agent_action(grant, record_id="agent-kind-not-covered", kind="example.receipt")]
        )
    )(
        root_grant(
            record_id="grant-root-kind",
            kinds=("example.note",),
            actions=("propose", "accept"),
        )
    ),
    args=GRANT_ARGS,
    notes="An agent record whose kind is not listed in the cited grant is invalid "
    "(§5.4, E_GRANT_NOT_APPLICABLE): the authorization must cover the kind.",
)

declare(
    "grant",
    "grantee-mismatch",
    "container",
    "container",
    "invalid",
    errors=("E_GRANT_GRANTEE_MISMATCH",),
    build=lambda case_dir: (
        lambda grant: container(
            [grant, agent_action(grant, record_id="agent-grantee-mismatch")]
        )
    )(
        root_grant(
            record_id="grant-root-grantee",
            grantee="agent-2",
            kinds=("example.note",),
            actions=("propose", "accept"),
        )
    ),
    args=GRANT_ARGS,
    notes="The cited grant is issued to agent-2 but the record is authored by "
    "agent-1: agent.key must equal grantee.key (§5.4, E_GRANT_GRANTEE_MISMATCH).",
)

declare(
    "grant",
    "expired",
    "container",
    "container",
    "unverifiable",
    errors=("E_GRANT_EXPIRED",),
    build=lambda case_dir: (
        lambda grant: container([grant, agent_action(grant, record_id="agent-expired", recorded_at=recordlib.T2)])
    )(
        root_grant(
            record_id="grant-root-expired",
            valid_from=recordlib.T0,
            valid_until=recordlib.T1,
        )
    ),
    args=GRANT_ARGS,
    notes="The cited grant expired before the record's claimed recorded_at: the "
    "authorization cannot be checked, so the record and container are "
    "unverifiable, not invalid (§5.4, E_GRANT_EXPIRED).",
)

declare(
    "grant",
    "revoked",
    "container",
    "container",
    "unverifiable",
    errors=("E_GRANT_REVOKED",),
    build=lambda case_dir: (
        lambda grant, revocation: container(
            [
                grant,
                revocation,
                agent_action(grant, record_id="agent-revoked", recorded_at=recordlib.T4),
            ]
        )
    )(
        root_grant(record_id="grant-root-revoked"),
        grant_revocation(
            root_grant(record_id="grant-root-revoked"),
            record_id="grant-revoke-effective",
            effective_at=recordlib.T3,
        ),
    ),
    args=GRANT_ARGS,
    notes="A revocation record is effective at T3; the later agent record (T4) "
    "cites the revoked grant, so it is unverifiable E_GRANT_REVOKED (§5.5/§9.6), "
    "not invalid. Records at or before effective_at would be unaffected.",
)

declare(
    "grant",
    "revoke-ref-not-grant",
    "container",
    "container",
    "invalid",
    errors=("E_GRANT_REVOKE_REF",),
    build=lambda case_dir: (
        lambda grant, first: container(
            [
                grant,
                first,
                grant_revocation(
                    grant,
                    record_id="grant-revoke-targets-revocation",
                    revokes_ref=parent_ref(first),
                ),
            ]
        )
    )(
        root_grant(record_id="grant-root-revoke-ref"),
        grant_revocation(
            root_grant(record_id="grant-root-revoke-ref"),
            record_id="grant-revoke-first",
            effective_at=recordlib.T3,
        ),
    ),
    args=GRANT_ARGS,
    notes="The revocation's revokes reference does resolve to a record of kind "
    "weave.grant, but that record is itself a revoke record (action != grant), so it "
    "is not an authorising grant: E_GRANT_REVOKE_REF invalid. This distinguishes "
    "the reference-resolution check from the authorising-action check.",
)

declare(
    "grant",
    "revocation-default-granter-valid",
    "container",
    "container",
    "valid",
    build=lambda case_dir: (
        lambda grant: container(
            [
                grant,
                grant_revocation(
                    grant, record_id="grant-revoke-default", signer="human-1"
                ),
            ]
        )
    )(
        root_grant(record_id="grant-root-default-granter")
    ),
    args=GRANT_ARGS,
    records=(
        {"id": "grant-root-default-granter", "verdict": "valid", "errors": []},
        {"id": "grant-revoke-default", "verdict": "valid", "errors": []},
    ),
    notes="Positive default revocation authority (Q10): with no explicit "
    "revocation list, the granter's own key may revoke the grant; the revokes "
    "reference resolves to an authorising grant and the revocation is valid.",
)

declare(
    "grant",
    "revoke-signer-not-qualified",
    "container",
    "container",
    "invalid",
    errors=("E_GRANT_REVOKE_SIGNER",),
    build=lambda case_dir: (
        lambda grant: container(
            [
                grant,
                grant_revocation(
                    grant, record_id="grant-revoke-program", signer="program-1"
                ),
            ]
        )
    )(
        root_grant(record_id="grant-root-revoke-signer")
    ),
    args=GRANT_ARGS,
    records=(
        {"id": "grant-root-revoke-signer", "verdict": "valid", "errors": []},
        {
            "id": "grant-revoke-program",
            "verdict": "invalid",
            "errors": ["E_GRANT_REVOKE_SIGNER"],
        },
    ),
    notes="A grant revocation must be signed by the original granter's key or by a "
    "declared human/organization key (§5.5). A program-key-signed revocation of a "
    "human-issued grant is E_GRANT_REVOKE_SIGNER invalid, even though the revokes "
    "reference itself resolves.",
)

declare(
    "grant",
    "agent-accepted-with-grant",
    "container",
    "container",
    "valid",
    build=lambda case_dir: (
        lambda grant: container(
            [grant, agent_action(grant, record_id="agent-covered-accepted")]
        )
    )(
        root_grant(
            record_id="grant-root-covered",
            kinds=("example.note",),
            actions=("propose", "accept"),
        )
    ),
    args=GRANT_ARGS,
    notices=("N_NO_HUMAN_SIGNATURE",),
    records=(
        {"id": "grant-root-covered", "verdict": "valid", "errors": []},
        {"id": "agent-covered-accepted", "verdict": "valid", "errors": []},
    ),
    notes="Positive agent authorization (§5.4): the grant lists example.note and "
    "the accept action, the grantee key equals actor.key, the record's recorded_at "
    "is inside the grant window and the grant is not revoked.",
)


# ---------------------------------------------------------------------------
# key-lifecycle cases (§9)
# ---------------------------------------------------------------------------


def record_signed_by(
    key_name: str,
    record_id: str,
    *,
    recorded_at: str = recordlib.T4,
    kind: str = "example.note",
    stage: str = "proposed",
) -> dict[str, Any]:
    record = recordlib.build_record(
        kind=kind,
        id=record_id,
        actor=recordlib.actor(key_name),
        body={"text": "signed after the key event"},
        stage=stage,
        recorded_at=recorded_at,
    )
    return recordlib.signed(record, key_name)


def key_rotation(
    *,
    record_id: str = "key-rotated-1",
    old_name: str = "key-old",
    new_name: str = "key-new",
    signers: Sequence[str] = ("key-old", "key-new"),
    recorded_at: str = recordlib.T2,
) -> dict[str, Any]:
    """A weave.key.rotated record signed by both the old and the new key (§9.2)."""
    body = {
        "new_key": kid(new_name),
        "new_public_key": key(new_name).public_b64url(),
        "old_key": kid(old_name),
        "old_public_key": key(old_name).public_b64url(),
        "reason": "scheduled rotation",
    }
    record = recordlib.build_record(
        kind="weave.key.rotated",
        id=record_id,
        actor=recordlib.actor(old_name),
        body=body,
        stage="accepted",
        recorded_at=recorded_at,
        origin_instance=kid(old_name),
    )
    return recordlib.signed(record, list(signers))


def undeclared_key_record() -> dict[str, Any]:
    """A record signed by a key that is deliberately not declared anywhere."""
    seed = hashlib.sha256(b"weave-record/1/test-key/undeclared-extra").digest()
    private = keyutil.private_from_seed(seed)
    public = keyutil.public_bytes(private)
    undeclared_id = keyutil.key_id(public)
    record = recordlib.build_record(
        kind="example.note",
        id="key-unknown-1",
        actor={"type": "human", "key": undeclared_id},
        body={"text": "whose key is this?"},
        stage="proposed",
        recorded_at=recordlib.T2,
        origin_instance=undeclared_id,
    )
    digest = recordlib.record_digest(record)
    signature = private.sign(keyutil.SIG_DOMAIN + digest.encode("ascii"))
    record["sigs"] = [
        {
            "alg": "ed25519",
            "key": undeclared_id,
            "value": keyutil.b64url_encode(signature),
        }
    ]
    return record


def declaration_with_mismatched_id() -> dict[str, Any]:
    """A declaration whose body.key contradicts its own public_key.

    The record is signed by the key whose raw bytes it publishes (human-1), so
    the signature verifies through the declaration's bootstrap key material and
    the first failing rule is the §2.5 derivation vs body.key (E_KEY_ID_-
    MISMATCH), not the signature.
    """
    body = {
        "algorithm": "ed25519",
        "key": kid("human-2"),
        "key_type": "human",
        "public_key": key("human-1").public_b64url(),
    }
    record = recordlib.build_record(
        kind="weave.key.declared",
        id="key-declared-id-mismatch",
        actor=recordlib.actor("human-2"),
        body=body,
        stage="accepted",
        recorded_at=recordlib.T0,
        origin_instance=kid("human-2"),
    )
    return recordlib.signed(record, "human-1")


def derived_key(name: str):
    """Deterministic synthetic key material not present in vectors/keys/."""
    seed = hashlib.sha256(b"weave-record/1/test-key/" + name.encode("ascii")).digest()
    private = keyutil.private_from_seed(seed)
    public = keyutil.public_bytes(private)
    return private, public, keyutil.key_id(public)


def _derived_signature(private, key_id: str, record: dict[str, Any]) -> dict[str, str]:
    digest = recordlib.record_digest(record)
    signature = private.sign(keyutil.SIG_DOMAIN + digest.encode("ascii"))
    return {
        "alg": "ed25519",
        "key": key_id,
        "value": keyutil.b64url_encode(signature),
    }


def declaration_with_validity(
    *, record_id: str, valid_until: str, valid_from: str = recordlib.T0
) -> dict[str, Any]:
    """A self-signed key declaration for a fresh key, with a validity window."""
    private, public, key_id = derived_key("expiring-key")
    body = {
        "algorithm": "ed25519",
        "key": key_id,
        "key_type": "human",
        "public_key": keyutil.b64url_encode(public),
        "valid_from": valid_from,
        "valid_until": valid_until,
    }
    record = recordlib.build_record(
        kind="weave.key.declared",
        id=record_id,
        actor={"type": "human", "key": key_id},
        body=body,
        stage="accepted",
        recorded_at=recordlib.T0,
        origin_instance=key_id,
    )
    # A non-root human declaration needs an established human/organization
    # cosignature (Q33); the keyset's self-attested root human-1 provides it.
    signatures = [_derived_signature(private, key_id, record)]
    signatures.append(recordlib.sig_entry(record, "human-1"))
    signatures.sort(key=lambda entry: entry["key"])
    record["sigs"] = signatures
    return record


def record_signed_by_derived(*, record_id: str, recorded_at: str) -> dict[str, Any]:
    private, _public, key_id = derived_key("expiring-key")
    record = recordlib.build_record(
        kind="example.note",
        id=record_id,
        actor={"type": "human", "key": key_id},
        body={"text": "signed with an expiring key"},
        stage="proposed",
        recorded_at=recorded_at,
        origin_instance=key_id,
    )
    record["sigs"] = [_derived_signature(private, key_id, record)]
    return record


LIFECYCLE_ARGS = ("--keys", "@keyset")

declare(
    "key-lifecycle",
    "declared-valid",
    "record",
    "record.json",
    "valid",
    build=lambda case_dir: {
        "record.json": canonical(
            recordlib.key_declaration(
                "human-2", owner="human-1", cosigners=("human-1",)
            )
        )
    },
    args=LIFECYCLE_ARGS,
    expected_digest=True,
    notes="Baseline weave.key.declared: the key publishes its own raw public key, "
    "the key id is the derivation, the declaration is self-signed and an already "
    "established human key cosigns it (Q33; non-root keys need a cosignature).",
)

declare(
    "key-lifecycle",
    "key-id-mismatch",
    "record",
    "record.json",
    "invalid",
    errors=("E_KEY_ID_MISMATCH",),
    build=lambda case_dir: {
        "record.json": canonical(declaration_with_mismatched_id())
    },
    args=LIFECYCLE_ARGS,
    notes="The declared key id is not the §2.5 derivation of the declared public "
    "key: key ids are claims until a declaration supplies the public key and the "
    "verifier recomputes the id (§2.5/§9.1, E_KEY_ID_MISMATCH). The record is "
    "signed by the key whose raw bytes it publishes, so the signature verifies "
    "and the key-id derivation is the first failing rule.",
)

declare(
    "key-lifecycle",
    "declared-not-self-signed",
    "record",
    "record.json",
    "invalid",
    errors=("E_KEY_DECLARED_NOT_SELF_SIGNED",),
    build=lambda case_dir: {
        "record.json": canonical(
            recordlib.key_declaration("human-1", signed_by="human-2")
        )
    },
    args=LIFECYCLE_ARGS,
    notes="A declaration MUST carry a signature by the declared key (§9.1). Here it "
    "carries only the owner's (human-2) signature over it: E_KEY_DECLARED_NOT_"
    "SELF_SIGNED. Note the generic §4.4 signature-presence rule is satisfied (the "
    "sigs array is non-empty and verifies), so this is the specific kind rule.",
)

declare(
    "key-lifecycle",
    "rotated-valid",
    "record",
    "record.json",
    "valid",
    build=lambda case_dir: {"record.json": canonical(key_rotation())},
    args=LIFECYCLE_ARGS,
    expected_digest=True,
    notes="Positive weave.key.rotated (§9.2): old and new public keys match their "
    "key ids, the actor is the old key, and the record is signed by both keys "
    "(rotation is a two-party statement).",
)

declare(
    "key-lifecycle",
    "rotation-missing-new-sig",
    "record",
    "record.json",
    "invalid",
    errors=("E_KEY_ROTATION_SIGS",),
    build=lambda case_dir: {
        "record.json": canonical(
            key_rotation(record_id="key-rotated-missing-new", signers=("key-old",))
        )
    },
    args=LIFECYCLE_ARGS,
    notes="A rotation is only valid when signed by BOTH the old and the new key "
    "(§9.2, E_KEY_ROTATION_SIGS); the old-key signature alone cannot authorize a "
    "new key.",
)

declare(
    "key-lifecycle",
    "retired-then-signed-after",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_REVOKED",),
    build=lambda case_dir: container(
        [
            recordlib.key_revocation(
                "key-old",
                reason="retired",
                effective_at=recordlib.T3,
                recorded_at=recordlib.T3,
                signer_name="human-1",
                record_id="key-revoked-key-old-retired",
            ),
            record_signed_by(
                "key-old", "record-after-retirement", recorded_at=recordlib.T4
            ),
        ]
    ),
    args=LIFECYCLE_ARGS,
    notes="A 'retired' revocation is not retroactive (§9.4): a signature made "
    "after effective_at is E_KEY_REVOKED invalid. The revocation record is signed "
    "by a human key, which the retiral rule allows.",
)

declare(
    "key-lifecycle",
    "compromise-retroactive",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_COMPROMISED",),
    build=lambda case_dir: container(
        [
            recordlib.key_revocation(
                "key-compromised",
                reason="key-compromise",
                effective_at=recordlib.T3,
                recorded_at=recordlib.T3,
                signer_name="human-1",
                record_id="key-revoked-key-compromised",
            ),
            record_signed_by(
                "key-compromised", "record-after-compromise", recorded_at=recordlib.T4
            ),
        ]
    ),
    args=LIFECYCLE_ARGS,
    notes="A key-compromise revocation is retroactive (§9.4): signatures after "
    "effective_at are E_KEY_COMPROMISED unless an earlier verified timestamp rescues "
    "them. Here there is no timestamp.",
)

declare(
    "key-lifecycle",
    "compromise-rescued-by-timestamp",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _compromise_rescue_files(case_dir),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container={
        "level_claimed": "L2",
        "level_verified": "L0",
        "anchor_verified": True,
    },
    records=(
        {"id": "key-revoked-key-compromised", "verdict": "valid", "errors": []},
        {"id": "record-before-compromise", "verdict": "valid", "errors": []},
    ),
    notes="Positive retroactive-compromise rescue (§9.4, E5): the record claims a "
    "recorded_at after effective_at, but the container has a verified L2 RFC 3161 "
    "timestamp whose genTime is at/before effective_at, proving the record existed "
    "before the compromise; it stays valid. effective_at is chosen after the "
    "committed TSR generation time (see vectors/integrity-levels/README.md).",
)

declare(
    "key-lifecycle",
    "unknown-key",
    "record",
    "record.json",
    "unverifiable",
    errors=("E_KEY_UNKNOWN",),
    build=lambda case_dir: {"record.json": canonical(undeclared_key_record())},
    notes="A signature by a key with no declaration anywhere in the context cannot "
    "be checked: the record is unverifiable E_KEY_UNKNOWN, not invalid (§9.4/§5.3); "
    "trust is TOFU but the key must be published first (§5.3).",
)


declare(
    "key-lifecycle",
    "key-expired",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_EXPIRED",),
    build=lambda case_dir: container(
        [
            declaration_with_validity(
                record_id="key-declared-expiring", valid_until=recordlib.T2
            ),
            record_signed_by_derived(
                record_id="record-after-key-expiry", recorded_at=recordlib.T4
            ),
        ]
    ),
    args=LIFECYCLE_ARGS,
    records=(
        {"id": "key-declared-expiring", "verdict": "valid", "errors": []},
        {
            "id": "record-after-key-expiry",
            "verdict": "invalid",
            "errors": ["E_KEY_EXPIRED"],
        },
    ),
    notes="A declared key with valid_until T2 signs a record whose claimed "
    "recorded_at is T4 > valid_until: the signature is E_KEY_EXPIRED invalid "
    "(§9.4). The declaration itself is valid and is published in the container.",
)

declare(
    "key-lifecycle",
    "public-key-invalid",
    "record",
    "record.json",
    "invalid",
    errors=("E_KEY_PUBLIC_KEY",),
    build=lambda case_dir: {
        "record.json": canonical(
            recordlib.key_declaration(
                "human-1",
                public_key_b64=keyutil.b64url_encode(b"\x00" * 31),
                signed_by="human-2",
            )
        )
    },
    args=LIFECYCLE_ARGS,
    notes="A declaration whose public_key is not strict unpadded base64url of "
    "exactly 32 bytes (here 31 bytes) is E_KEY_PUBLIC_KEY invalid (§2.6/§9.1): a "
    "key declaration must publish a canonical 32-byte point. The record is signed "
    "by an owner key (human-2) rather than treated as its own bootstrap key, so the "
    "declaration body check is the first failing rule.",
)

declare(
    "key-lifecycle",
    "rotation-same-key",
    "record",
    "record.json",
    "invalid",
    errors=("E_KEY_ROTATION_KEYS",),
    build=lambda case_dir: {
        "record.json": canonical(
            key_rotation(
                record_id="key-rotated-same",
                old_name="key-old",
                new_name="key-old",
                signers=("key-old",),
            )
        )
    },
    args=LIFECYCLE_ARGS,
    notes="A rotation must actually change the key; old_key == new_key is "
    "E_KEY_ROTATION_KEYS invalid (§9.2).",
)



# ---------------------------------------------------------------------------
# Revision-1 helpers: declared-key cosignatures, rotations, grant chains
# ---------------------------------------------------------------------------


def derived_declaration(
    *,
    record_id: str,
    key_name: str,
    key_type: str = "human",
    owner: str | None = None,
    owner_key_id: str | None = None,
    cosigners: Sequence[str] = ("human-1",),
    valid_from: str | None = None,
    valid_until: str | None = None,
    recorded_at: str = recordlib.T0,
) -> dict[str, Any]:
    """A declaration for fresh deterministic key material (not in vectors/keys)."""
    private, public, key_id = derived_key(key_name)
    body: dict[str, Any] = {
        "algorithm": "ed25519",
        "key": key_id,
        "key_type": key_type,
        "public_key": keyutil.b64url_encode(public),
    }
    if owner_key_id is not None:
        body["owner"] = owner_key_id
    elif owner is not None:
        body["owner"] = kid(owner)
    if valid_from is not None:
        body["valid_from"] = valid_from
    if valid_until is not None:
        body["valid_until"] = valid_until
    record = recordlib.build_record(
        kind="weave.key.declared",
        id=record_id,
        actor={"type": key_type, "key": key_id},
        body=body,
        stage="accepted",
        recorded_at=recorded_at,
        origin_instance=key_id,
    )
    signatures = [_derived_signature(private, key_id, record)]
    for cosigner in cosigners:
        signatures.append(recordlib.sig_entry(record, cosigner))
    signatures.sort(key=lambda entry: entry["key"])
    record["sigs"] = signatures
    return record


def derived_record(
    *, record_id: str, key_name: str, recorded_at: str, stage: str = "proposed"
) -> dict[str, Any]:
    private, _public, key_id = derived_key(key_name)
    record = recordlib.build_record(
        kind="example.note",
        id=record_id,
        actor={"type": "human", "key": key_id},
        body={"text": "signed by a derived key"},
        stage=stage,
        recorded_at=recorded_at,
        origin_instance=key_id,
    )
    record["sigs"] = [_derived_signature(private, key_id, record)]
    return record


def rotation_with_derived_new_key(
    *,
    record_id: str,
    old_name: str = "human-1",
    derived_name: str = "undeclared-rotation-key",
    recorded_at: str = recordlib.T2,
) -> dict[str, Any]:
    """Rotation whose new key is declared only by the rotation record itself."""
    private, public, key_id = derived_key(derived_name)
    body = {
        "new_key": key_id,
        "new_public_key": keyutil.b64url_encode(public),
        "old_key": kid(old_name),
        "old_public_key": key(old_name).public_b64url(),
    }
    record = recordlib.build_record(
        kind="weave.key.rotated",
        id=record_id,
        actor=recordlib.actor(old_name),
        body=body,
        stage="accepted",
        recorded_at=recorded_at,
        origin_instance=kid(old_name),
    )
    signatures = [
        recordlib.sig_entry(record, old_name),
        _derived_signature(private, key_id, record),
    ]
    signatures.sort(key=lambda entry: entry["key"])
    record["sigs"] = signatures
    return record


def rotation_pubkey_contradiction(*, record_id: str = "key-rotated-contradiction") -> dict[str, Any]:
    """Rotation whose new_public_key derives a different key id than new_key."""
    body = {
        "new_key": kid("human-2"),
        "new_public_key": key("key-new").public_b64url(),
        "old_key": kid("key-old"),
        "old_public_key": key("key-old").public_b64url(),
    }
    record = recordlib.build_record(
        kind="weave.key.rotated",
        id=record_id,
        actor=recordlib.actor("key-old"),
        body=body,
        stage="accepted",
        recorded_at=recordlib.T2,
        origin_instance=kid("key-old"),
    )
    return recordlib.signed(record, ["key-old", "key-new"])


# ---- grant-chain cases (delegated sub-grants and revocations) -------------

grant_parent_args = dict(
    kinds=("weave.grant", "example.note"),
    actions=("propose", "accept", "grant"),
    transferable=True,
)

declare(
    "grant",
    "sub-grant-expands-actions",
    "container",
    "container",
    "invalid",
    errors=("E_GRANT_DELEGATION_EXCEEDS",),
    build=lambda case_dir: (
        lambda parent: container(
            [
                parent,
                delegated_grant(
                    parent,
                    record_id="grant-sub-actions",
                    actions=("propose", "accept", "reject"),
                ),
            ]
        )
    )(
        root_grant(record_id="grant-root-actions", **grant_parent_args)
    ),
    args=GRANT_ARGS,
    notes="A sub-grant's actions must be a subset of the parent's actions; adding "
    "'reject' is an authority expansion (E_GRANT_DELEGATION_EXCEEDS, S3).",
)

declare(
    "grant",
    "sub-grant-window-starts-before-parent",
    "container",
    "container",
    "invalid",
    errors=("E_GRANT_DELEGATION_EXCEEDS",),
    build=lambda case_dir: (
        lambda parent: container(
            [
                parent,
                delegated_grant(
                    parent,
                    record_id="grant-sub-window-start",
                    valid_from=recordlib.T1,
                    valid_until=recordlib.T8,
                ),
            ]
        )
    )(
        root_grant(
            record_id="grant-root-window-start",
            valid_from=recordlib.T2,
            valid_until=recordlib.T9,
            **grant_parent_args
        )
    ),
    args=GRANT_ARGS,
    notes="The sub-grant starts before the parent grant: its validity window must "
    "be inside the parent's (E_GRANT_DELEGATION_EXCEEDS, S3).",
)

declare(
    "grant",
    "sub-grant-window-ends-after-parent",
    "container",
    "container",
    "invalid",
    errors=("E_GRANT_DELEGATION_EXCEEDS",),
    build=lambda case_dir: (
        lambda parent: container(
            [
                parent,
                delegated_grant(
                    parent,
                    record_id="grant-sub-window-end",
                    valid_from=recordlib.T1,
                    valid_until=recordlib.T9,
                ),
            ]
        )
    )(
        root_grant(
            record_id="grant-root-window-end",
            valid_from=recordlib.T0,
            valid_until=recordlib.T8,
            **grant_parent_args
        )
    ),
    args=GRANT_ARGS,
    notes="The sub-grant ends after the parent grant: its validity window must be "
    "inside the parent's (E_GRANT_DELEGATION_EXCEEDS, S3).",
)

declare(
    "grant",
    "sub-grant-scope-expands",
    "container",
    "container",
    "invalid",
    errors=("E_GRANT_DELEGATION_EXCEEDS",),
    build=lambda case_dir: (
        lambda parent: container(
            [
                parent,
                delegated_grant(
                    parent,
                    record_id="grant-sub-scope",
                    scope=("example", "another-scope"),
                ),
            ]
        )
    )(
        root_grant(record_id="grant-root-scope", scope=("example",), **grant_parent_args)
    ),
    args=GRANT_ARGS,
    notes="The sub-grant names a scope outside the parent's scope list; scope is "
    "compared as a string set for delegation purposes (E_GRANT_DELEGATION_EXCEEDS).",
)

declare(
    "grant",
    "parent-revoked",
    "container",
    "container",
    "unverifiable",
    errors=("E_GRANT_REVOKED",),
    build=lambda case_dir: (
        lambda parent, revocation: container(
            [
                parent,
                revocation,
                delegated_grant(
                    parent,
                    record_id="grant-sub-parent-revoked",
                    valid_from=recordlib.T4,
                    valid_until=recordlib.T8,
                    recorded_at=recordlib.T4,
                ),
            ]
        )
    )(
        root_grant(record_id="grant-root-parent-revoked", **grant_parent_args),
        grant_revocation(
            root_grant(record_id="grant-root-parent-revoked", **grant_parent_args),
            record_id="grant-revoke-parent",
            effective_at=recordlib.T3,
        ),
    ),
    args=GRANT_ARGS,
    notes="The parent grant was revoked at T3; the delegated sub-grant is recorded "
    "at T4. A revoked link anywhere in the chain makes the delegation action "
    "unverifiable E_GRANT_REVOKED (S3/§6).",
)

declare(
    "grant",
    "parent-expired",
    "container",
    "container",
    "unverifiable",
    errors=("E_GRANT_EXPIRED",),
    build=lambda case_dir: (
        lambda parent: container(
            [
                parent,
                delegated_grant(
                    parent,
                    record_id="grant-sub-parent-expired",
                    valid_from=recordlib.T0,
                    valid_until=recordlib.T3,
                    recorded_at=recordlib.T4,
                ),
            ]
        )
    )(
        root_grant(
            record_id="grant-root-parent-expired",
            valid_from=recordlib.T0,
            valid_until=recordlib.T3,
            **grant_parent_args
        )
    ),
    args=GRANT_ARGS,
    notes="The parent grant expired at T3 and the sub-grant is recorded at T4: the "
    "delegating authority is outside its validity window (unverifiable "
    "E_GRANT_EXPIRED).",
)

declare(
    "grant",
    "sub-grant-granter-mismatch",
    "container",
    "container",
    "invalid",
    errors=("E_GRANT_GRANTER",),
    build=lambda case_dir: (
        lambda parent: container(
            [
                parent,
                delegated_grant(parent, record_id="grant-sub-granter-mismatch"),
            ]
        )
    )(
        root_grant(
            record_id="grant-root-granter-mismatch",
            grantee="agent-2",
            **grant_parent_args
        )
    ),
    args=GRANT_ARGS,
    notes="The parent grant names agent-2 as grantee but the sub-grant is signed "
    "by agent-1: the parent does not authorise this sub-granter (E_GRANT_GRANTER).",
)

declare(
    "grant",
    "sub-grant-parent-lacks-grant-action",
    "container",
    "container",
    "invalid",
    errors=("E_GRANT_GRANTER",),
    build=lambda case_dir: (
        lambda parent: container(
            [
                parent,
                delegated_grant(parent, record_id="grant-sub-lacks-grant-action"),
            ]
        )
    )(
        root_grant(
            record_id="grant-root-lacks-grant-action",
            kinds=("weave.grant", "example.note"),
            actions=("propose", "accept"),
            transferable=True,
        )
    ),
    args=GRANT_ARGS,
    notes="The parent grant lists weave.grant in kinds but does not list the grant "
    "action in actions: it cannot authorise issuing further grants "
    "(E_GRANT_GRANTER).",
)

declare(
    "grant",
    "revoke-record-as-authority",
    "container",
    "container",
    "invalid",
    errors=("E_GRANT_GRANTER",),
    build=lambda case_dir: (
        lambda grant, revocation: container(
            [
                grant,
                revocation,
                _agent_action_citing(
                    revocation,
                    record_id="agent-cites-revocation",
                    recorded_at=recordlib.T4,
                ),
            ]
        )
    )(
        root_grant(record_id="grant-root-as-authority"),
        grant_revocation(
            root_grant(record_id="grant-root-as-authority"),
            record_id="grant-revoke-as-authority",
            effective_at=recordlib.T3,
        ),
    ),
    args=GRANT_ARGS,
    notes="An agent record cites a grant-revocation record as its authorisation: "
    "the cited record's action is not 'grant', so it does not authorise anything "
    "(E_GRANT_GRANTER).",
)

declare(
    "grant",
    "revocation-listed-key-valid",
    "container",
    "container",
    "valid",
    build=lambda case_dir: (
        lambda grant: container(
            [
                grant,
                grant_revocation(
                    grant, record_id="grant-revoke-listed", signer="program-1"
                ),
            ]
        )
    )(
        root_grant(record_id="grant-root-listed", revocation=("program-1",))
    ),
    args=GRANT_ARGS,
    records=(
        {"id": "grant-root-listed", "verdict": "valid", "errors": []},
        {"id": "grant-revoke-listed", "verdict": "valid", "errors": []},
    ),
    notes="Positive: the grant names program-1 in its revocation list, so a "
    "revocation signed by program-1 is authorised even though program-1 is not "
    "the granter (Q10 revocation officers).",
)

declare(
    "grant",
    "revocation-unlisted-human",
    "container",
    "container",
    "invalid",
    errors=("E_GRANT_REVOKE_SIGNER",),
    build=lambda case_dir: (
        lambda grant: container(
            [
                grant,
                grant_revocation(
                    grant, record_id="grant-revoke-unlisted", signer="human-2"
                ),
            ]
        )
    )(
        root_grant(record_id="grant-root-unlisted")
    ),
    args=GRANT_ARGS,
    notes="No longer may any human key revoke any grant (M-5): the revocation is "
    "signed by an unlisted key that is neither the granter nor its rotation "
    "successor, so it is E_GRANT_REVOKE_SIGNER.",
)

declare(
    "grant",
    "revocation-rotation-successor-valid",
    "container",
    "container",
    "valid",
    build=lambda case_dir: (
        lambda grant, rotation: container(
            [
                grant,
                rotation,
                grant_revocation(
                    grant, record_id="grant-revoke-successor", signer="key-new"
                ),
            ]
        )
    )(
        root_grant(record_id="grant-root-successor"),
        key_rotation(
            record_id="grant-granter-rotation",
            old_name="human-1",
            new_name="key-new",
            signers=("human-1", "key-new"),
            recorded_at=recordlib.T2,
        ),
    ),
    args=GRANT_ARGS,
    records=(
        {"id": "grant-root-successor", "verdict": "valid", "errors": []},
        {"id": "grant-granter-rotation", "verdict": "valid", "errors": []},
        {"id": "grant-revoke-successor", "verdict": "valid", "errors": []},
    ),
    notes="Positive: the revocation is signed by key-new, which an explicit "
    "weave.key.rotated record makes the rotation successor of the granter human-1; "
    "the default revocation officers include the granter's rotation successors.",
)

declare(
    "grant",
    "revoked-boundary-equal",
    "container",
    "container",
    "unverifiable",
    errors=("E_GRANT_REVOKED",),
    build=lambda case_dir: (
        lambda grant, revocation: container(
            [
                grant,
                revocation,
                agent_action(
                    grant, record_id="agent-boundary-equal", recorded_at=recordlib.T3
                ),
            ]
        )
    )(
        root_grant(record_id="grant-root-boundary"),
        grant_revocation(
            root_grant(record_id="grant-root-boundary"),
            record_id="grant-revoke-boundary",
            effective_at=recordlib.T3,
        ),
    ),
    args=GRANT_ARGS,
    notes="Equality belongs to revocation (Q11/M-2): a record whose recorded_at "
    "equals the revocation's effective_at is already revoked, so it is "
    "unverifiable E_GRANT_REVOKED.",
)


def _agent_action_citing(
    cited: dict[str, Any],
    *,
    record_id: str,
    recorded_at: str,
    kind: str = "example.note",
    stage: str = "accepted",
) -> dict[str, Any]:
    """An agent record whose actor.grant cites *cited* as its authorisation."""
    actor = recordlib.actor(
        "agent-1",
        model="example/model@1.2.3",
        on_behalf_of=kid("human-1"),
        grant=parent_ref(cited),
        idempotency_key="idem-" + record_id,
    )
    record = recordlib.build_record(
        kind=kind,
        id=record_id,
        actor=actor,
        body={"text": "agent action"},
        stage=stage,
        recorded_at=recorded_at,
    )
    return recordlib.signed(record, "agent-1")



# ---------------------------------------------------------------------------
# Revision-1 key-lifecycle edges (Q20/Q33/S2, M-2/M-4/M-11/M-12)
# ---------------------------------------------------------------------------

declare(
    "key-lifecycle",
    "declared-agent-without-owner",
    "record",
    "record.json",
    "invalid",
    errors=("E_KEY_OWNER_MISSING",),
    build=lambda case_dir: {
        "record.json": canonical(
            derived_declaration(
                record_id="key-declared-agent-no-owner",
                key_name="agent-no-owner",
                key_type="agent",
                owner=None,
            )
        )
    },
    args=LIFECYCLE_ARGS,
    notes="An agent key declaration without body.owner is E_KEY_OWNER_MISSING "
    "(Q33/S4): automated keys must be bound to an owning human/organization.",
)

declare(
    "key-lifecycle",
    "declared-agent-not-cosigned",
    "record",
    "record.json",
    "invalid",
    errors=("E_KEY_DECLARED_NOT_COSIGNED",),
    build=lambda case_dir: {
        "record.json": canonical(
            derived_declaration(
                record_id="key-declared-agent-not-cosigned",
                key_name="agent-not-cosigned",
                key_type="agent",
                owner="human-1",
                cosigners=(),
            )
        )
    },
    args=LIFECYCLE_ARGS,
    notes="An agent key declaration names an owner but carries only the self "
    "signature: the owner's cosignature is mandatory (E_KEY_DECLARED_NOT_COSIGNED, "
    "Q33/S4).",
)

declare(
    "key-lifecycle",
    "declared-agent-cosigned-valid",
    "record",
    "record.json",
    "valid",
    build=lambda case_dir: {
        "record.json": canonical(
            derived_declaration(
                record_id="key-declared-agent-cosigned",
                key_name="agent-cosigned",
                key_type="agent",
                owner="human-1",
                cosigners=("human-1",),
            )
        )
    },
    args=LIFECYCLE_ARGS,
    expected_digest=True,
    notes="Positive: an agent key declaration with owner=human-1 and the owner's "
    "cosignature (self-signature plus cosignature in sigs, sorted by key).",
)

declare(
    "key-lifecycle",
    "declared-human-owner-cosigned-valid",
    "record",
    "record.json",
    "valid",
    build=lambda case_dir: {
        "record.json": canonical(
            derived_declaration(
                record_id="key-declared-human-cosigned",
                key_name="human-cosigned",
                key_type="human",
                owner="human-1",
                cosigners=("human-1",),
            )
        )
    },
    args=LIFECYCLE_ARGS,
    expected_digest=True,
    notes="Positive: a human key declaration cosigned by the established root "
    "human key; non-root human/organization declarations need such a cosignature.",
)

declare(
    "key-lifecycle",
    "declared-human-self-attested-valid",
    "record",
    "record.json",
    "unverifiable",
    errors=("E_KEY_UNTRUSTED",),
    build=lambda case_dir: {
        "record.json": canonical(
            derived_declaration(
                record_id="key-declared-self-attested-human",
                key_name="self-attested-human",
                key_type="human",
                cosigners=(),
            )
        )
    },
    args=LIFECYCLE_ARGS,
    expected_digest=True,
    notices=("N_SELF_ATTESTED_ROOT_KEY",),
    notes="Revision-2 R2: a root key can only come from the verifier's local trust "
    "input (--keys). A self-signed human declaration that is not in the keyset and "
    "has no cosignature tracing to a trusted human/organization key is "
    "UNVERIFIABLE E_KEY_UNTRUSTED, with N_SELF_ATTESTED_ROOT_KEY because its only "
    "signature is its own; it can never become a root by claiming an early "
    "recorded_at.",
)

declare(
    "key-lifecycle",
    "compromise-backdated-forgery",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_COMPROMISED",),
    build=lambda case_dir: container(
        [
            recordlib.key_revocation(
                "key-compromised",
                reason="key-compromise",
                effective_at=recordlib.T3,
                recorded_at=recordlib.T3,
                signer_name="human-1",
                record_id="key-revoked-compromise-backdated",
            ),
            record_signed_by(
                "key-compromised", "record-backdated-forgery", recorded_at=recordlib.T1
            ),
        ]
    ),
    args=LIFECYCLE_ARGS,
    notes="S2: after a key-compromise revocation a signature by that key is only "
    "valid when a verified timestamp proves it existed at/before effective_at. Here "
    "the record backdates recorded_at to T1 (< T3) but has no timestamp, so it is "
    "still E_KEY_COMPROMISED invalid: recorded_at is only a claim.",
)

declare(
    "key-lifecycle",
    "retired-boundary-equal",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_REVOKED",),
    build=lambda case_dir: container(
        [
            recordlib.key_revocation(
                "key-old",
                reason="retired",
                effective_at=recordlib.T3,
                recorded_at=recordlib.T3,
                signer_name="human-1",
                record_id="key-revoked-retired-equal",
            ),
            record_signed_by(
                "key-old", "record-retired-boundary", recorded_at=recordlib.T3
            ),
        ]
    ),
    args=LIFECYCLE_ARGS,
    notes="Boundary Q11/M-2: recorded_at == effective_at belongs to the revocation, "
    "so the signature is E_KEY_REVOKED invalid.",
)

declare(
    "key-lifecycle",
    "retired-before-effective",
    "container",
    "container",
    "valid",
    build=lambda case_dir: container(
        [
            recordlib.key_revocation(
                "key-old",
                reason="retired",
                effective_at=recordlib.T3,
                recorded_at=recordlib.T3,
                signer_name="human-1",
                record_id="key-revoked-retired-before",
            ),
            record_signed_by(
                "key-old", "record-before-retirement", recorded_at=recordlib.T2
            ),
        ]
    ),
    args=LIFECYCLE_ARGS,
    records=(
        {"id": "key-revoked-retired-before", "verdict": "valid", "errors": []},
        {"id": "record-before-retirement", "verdict": "valid", "errors": []},
    ),
    notes="Positive boundary: a signature made before effective_at (T2 < T3) is "
    "unaffected by a retired revocation.",
)

declare(
    "key-lifecycle",
    "sign-before-valid-from",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_EXPIRED",),
    build=lambda case_dir: container(
        [
            derived_declaration(
                record_id="key-declared-valid-from",
                key_name="valid-from-key",
                valid_from=recordlib.T3,
            ),
            derived_record(
                record_id="record-before-valid-from",
                key_name="valid-from-key",
                recorded_at=recordlib.T1,
            ),
        ]
    ),
    args=LIFECYCLE_ARGS,
    notes="M-4/Q20: a signature made before the declared valid_from is "
    "E_KEY_EXPIRED invalid, symmetric with valid_until.",
)

declare(
    "key-lifecycle",
    "declaration-duplicate-earliest",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_EXPIRED",),
    build=lambda case_dir: container(
        [
            derived_declaration(
                record_id="key-declared-earliest-1",
                key_name="duplicate-key",
                recorded_at=recordlib.T0,
                valid_until=recordlib.T2,
            ),
            derived_declaration(
                record_id="key-declared-earliest-2",
                key_name="duplicate-key",
                recorded_at=recordlib.T1,
                valid_until=recordlib.T9,
            ),
            derived_record(
                record_id="record-duplicate-declaration",
                key_name="duplicate-key",
                recorded_at=recordlib.T4,
            ),
        ]
    ),
    args=LIFECYCLE_ARGS,
    notes="Q12: with two valid declarations for one key id the earliest claimed "
    "recorded_at governs (no pinning in H0). The first declaration's valid_until "
    "T2 makes the T4 signature E_KEY_EXPIRED.",
)

declare(
    "key-lifecycle",
    "rotation-pubkey-contradicts-id",
    "record",
    "record.json",
    "invalid",
    errors=("E_KEY_ROTATION_KEYS",),
    build=lambda case_dir: {
        "record.json": canonical(rotation_pubkey_contradiction())
    },
    args=LIFECYCLE_ARGS,
    notes="M-11: a rotation whose new_public_key derives a different key id than "
    "new_key is E_KEY_ROTATION_KEYS invalid; both required signatures verify, so "
    "the contradiction is the defect.",
)

declare(
    "key-lifecycle",
    "rotation-declares-new-key-valid",
    "container",
    "container",
    "valid",
    build=lambda case_dir: container(
        [
            rotation_with_derived_new_key(record_id="rotation-to-new-key"),
            derived_record(
                record_id="record-signed-by-rotation-key",
                key_name="undeclared-rotation-key",
                recorded_at=recordlib.T2,
            ),
        ]
    ),
    args=LIFECYCLE_ARGS,
    records=(
        {"id": "rotation-to-new-key", "verdict": "valid", "errors": []},
        {
            "id": "record-signed-by-rotation-key",
            "verdict": "valid",
            "errors": [],
        },
    ),
    notes="M-12 wording: a signing key must be declared either by a key "
    "declaration record OR by the rotation record itself. This rotation explicitly "
    "lists new_public_key, so that material is an explicit declaration and the "
    "later record signed by it is valid. H0 only forbids inferring keys that never "
    "appear in any record's material (rotation-chain following is allowed for the "
    "revocation-authority rule only); a fully undeclared signer is covered by the "
    "core key-lifecycle/unknown-key vector.",
)

declare(
    "key-lifecycle",
    "rotation-cycle-revocation",
    "container",
    "container",
    "invalid",
    errors=("E_GRANT_REVOKE_SIGNER",),
    build=lambda case_dir: (
        lambda grant, rotation_one, rotation_two: container(
            [
                grant,
                rotation_one,
                rotation_two,
                grant_revocation(
                    grant, record_id="grant-revoke-cycle", signer="key-new"
                ),
            ]
        )
    )(
        root_grant(record_id="grant-root-cycle"),
        key_rotation(
            record_id="rotation-cycle-a",
            old_name="human-1",
            new_name="key-old",
            signers=("human-1", "key-old"),
            recorded_at=recordlib.T2,
        ),
        key_rotation(
            record_id="rotation-cycle-b",
            old_name="key-old",
            new_name="human-1",
            signers=("key-old", "human-1"),
            recorded_at=recordlib.T3,
        ),
    ),
    args=GRANT_ARGS,
    notes="Q26 cycle case: the only possible reference graph cycle in this format "
    "is the key-id rotation graph. The two rotations form human-1 -> key-old -> "
    "human-1; a revocation signed by an unrelated key can never be shown to be a "
    "rotation successor, the traversal MUST terminate deterministically and the "
    "revocation is E_GRANT_REVOKE_SIGNER (not unverifiable, no hang).",
)


# ---------------------------------------------------------------------------
# Revision-1 erasure actors (M-10): organization, program-with-basis, agent
# ---------------------------------------------------------------------------

ERASURE_REVISION_ARGS = ("--keys", "@keyset")


def _erasure_actor_files(
    *,
    erasure_signer: str,
    actor_override: dict[str, Any] | None = None,
    actor_type: str | None = None,
    grant_grantee: str | None = None,
    use_basis: bool = False,
    basis_actions: Sequence[str] = ("erase",),
    reason: str = "data-subject-request",
) -> dict[str, bytes]:
    """Placeholder+attestation container for an organization/program/agent erasure."""
    original = erased_original("erasure-revision-original")
    records: list[dict[str, Any]] = []
    basis: dict[str, Any] | None = None
    if grant_grantee is not None:
        grant = root_grant(
            record_id="erasure-basis-grant",
            grantee=grant_grantee,
            kinds=("weave.erasure",),
            actions=tuple(basis_actions),
            scope=("example",),
        )
        records.append(grant)
        basis = parent_ref(grant)
    attestation = erasure_record(
        original,
        record_id="erasure-revision-attestation",
        reason=reason,
        signer=erasure_signer,
        actor_type=actor_type,
        actor_override=actor_override,
        basis=basis if use_basis else None,
    )
    placeholder = erased_placeholder(original, attestation)
    records.extend([placeholder, attestation])
    return container(records)


declare(
    "erasure",
    "actor-organization-valid",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _erasure_actor_files(
        erasure_signer="org-1", actor_type="organization"
    ),
    args=ERASURE_REVISION_ARGS,
    records=(
        {"id": "erasure-revision-attestation", "verdict": "valid", "errors": []},
        {"id": "erasure-revision-original", "verdict": "erased", "errors": []},
    ),
    notes="Positive M-10: an organization may execute an erasure (the previous rule "
    "limited the actor to human). The placeholder/attestation cross-checks hold.",
)

declare(
    "erasure",
    "actor-program-with-grant-valid",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _erasure_actor_files(
        erasure_signer="program-1",
        grant_grantee="program-1",
        use_basis=True,
        reason="retention-expired",
    ),
    args=ERASURE_REVISION_ARGS,
    notices=("N_NO_HUMAN_SIGNATURE",),
    records=(
        {"id": "erasure-revision-attestation", "verdict": "valid", "errors": []},
        {"id": "erasure-revision-original", "verdict": "erased", "errors": []},
    ),
    notes="Positive M-10: a program may execute an automatic retention-expiry "
    "erasure when body.basis references a resolvable grant that names the program "
    "key and the erase action. The accepted attestation has no human signature, so "
    "the N_NO_HUMAN_SIGNATURE notice is reported.",
)

declare(
    "erasure",
    "actor-agent-with-grant-valid",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _erasure_agent_files(),
    args=ERASURE_REVISION_ARGS,
    notices=("N_NO_HUMAN_SIGNATURE",),
    records=(
        {"id": "erasure-revision-attestation", "verdict": "valid", "errors": []},
        {"id": "erasure-revision-original", "verdict": "erased", "errors": []},
    ),
    notes="Positive M-10: an agent may execute an erasure (for example on behalf "
    "of a data subject) when its actor.grant covers kind weave.erasure and action "
    "erase; the accepted attestation lacks a human signature, so "
    "N_NO_HUMAN_SIGNATURE is reported.",
)


def _erasure_agent_files() -> dict[str, bytes]:
    original = erased_original("erasure-revision-original")
    grant = root_grant(
        record_id="erasure-basis-grant",
        grantee="agent-1",
        kinds=("weave.erasure",),
        # Accepted agent records need the generic "accept" action as well as the
        # kind-specific "erase" action (spec §5.4 + erasure kind page).
        actions=("accept", "erase"),
        scope=("example",),
    )
    actor = recordlib.actor(
        "agent-1",
        model="example/model@1.2.3",
        on_behalf_of=recordlib.kid("human-1"),
        grant=parent_ref(grant),
        idempotency_key="idem-erasure-agent",
    )
    attestation = erasure_record(
        original,
        record_id="erasure-revision-attestation",
        reason="data-subject-request",
        signer="agent-1",
        actor_override=actor,
    )
    placeholder = erased_placeholder(original, attestation)
    return container([grant, placeholder, attestation])



# ---------------------------------------------------------------------------
# integrity-levels cases (L0/L1/L2 and the RFC 3161 verification profile)
# ---------------------------------------------------------------------------

LEVEL_ARGS = ("--keys", "@keyset")
TSA_CERT = lambda: (TSA_DIR / TSA_CERT_NAME).read_bytes()  # noqa: E731
L2_ANCHOR = {"level_verified": "L0", "anchor_verified": True}
L2_NO_ANCHOR = {"level_verified": "L0", "anchor_verified": False}


def _with_certificate(variant: str, **kwargs: Any) -> Callable[[bytes], bytes]:
    """TSR factory whose signer certificate is a crafted TSA certificate variant."""
    certificate_der, _pem = _crafted_certificate(variant)
    return lambda imprint: _crafted_tsr(imprint, certificate_der=certificate_der, **kwargs)


def _crafted_l2_files(
    case_dir: Path,
    *,
    tsr_factory: Callable[[bytes], bytes] | None = None,
    cert_variant: str | None = None,
    trust_name: str | None = TSA_CERT_NAME,
    level: str = "L2",
) -> dict[str, bytes]:
    """Files of an L2 case with one crafted TSR and (optionally) a trust anchor."""
    factory = tsr_factory if tsr_factory is not None else _crafted_tsr

    def builder(imprint: bytes) -> list[tuple[str, bytes, str | None]]:
        return [("signatures/timestamp-1.tsr", factory(imprint), None)]

    files = _build_timestamped_container(SIMPLE_RECORDS(), builder, level=level)
    result = wrap(files)
    if trust_name is not None:
        if cert_variant is None:
            result[trust_name] = TSA_CERT()
        else:
            _der, pem = _crafted_certificate(cert_variant)
            result[trust_name] = pem
    return result


def _l2_ts_file_digest_files(case_dir: Path) -> dict[str, bytes]:
    """L2 files whose sig file lists a timestamp digest the TSR does not have."""
    def builder(imprint: bytes) -> list[tuple[str, bytes, str | None]]:
        return [("signatures/timestamp-1.tsr", _crafted_tsr(imprint), None)]

    files = _build_timestamped_container(SIMPLE_RECORDS(), builder, level="L2")
    files = mutate_sigfile(
        files,
        lambda sigfile: {
            **sigfile,
            "timestamps": [
                {**entry, "digest": "sha256:" + "99" * 32}
                for entry in sigfile["timestamps"]
            ],
        },
    )
    return {**wrap(files), TSA_CERT_NAME: TSA_CERT()}


def _l2_renewal_files(
    case_dir: Path,
    *,
    renews: str = "signatures/timestamp-1.tsr",
    renewal_imprint: str = "chain",
) -> dict[str, bytes]:
    """L2 files with a two-reply timestamp renewal chain.

    ``renewal_imprint="chain"`` gives the valid imprint
    ``SHA-256(previous .tsr bytes || manifest digest)``; ``"previous-only"``
    drops the manifest digest (an imprint mismatch).
    """

    def builder(imprint: bytes) -> list[tuple[str, bytes, str | None]]:
        first = _crafted_tsr(imprint)
        if renewal_imprint == "chain":
            second_imprint = _sha256_bytes(first + imprint)
        elif renewal_imprint == "previous-only":
            second_imprint = _sha256_bytes(first)
        else:  # pragma: no cover - defensive
            raise SystemExit("unknown renewal imprint mode %r" % (renewal_imprint,))
        second = _crafted_tsr(second_imprint)
        return [
            ("signatures/timestamp-1.tsr", first, None),
            ("signatures/timestamp-2.tsr", second, renews),
        ]

    files = _build_timestamped_container(SIMPLE_RECORDS(), builder, level="L2")
    return {**wrap(files), TSA_CERT_NAME: TSA_CERT()}


def _compromise_rescue_files(case_dir: Path) -> dict[str, bytes]:
    """L2 container where a verified timestamp rescues a compromised-key signature."""
    # The crafted TSR genTime is 2026-11-01T00:00:00Z; S2 requires genTime <=
    # effective_at, so the compromise takes effect after the proof of existence.
    effective_at = "2026-12-01T00:00:00.000Z"
    recorded_at = "2027-01-01T00:00:00.000Z"
    records = [
        recordlib.key_revocation(
            "key-compromised",
            reason="key-compromise",
            effective_at=effective_at,
            recorded_at=effective_at,
            signer_name="human-1",
            record_id="key-revoked-key-compromised",
        ),
        record_signed_by(
            "key-compromised", "record-before-compromise", recorded_at=recorded_at
        ),
    ]

    def builder(imprint: bytes) -> list[tuple[str, bytes, str | None]]:
        return [("signatures/timestamp-1.tsr", _crafted_tsr(imprint), None)]

    files = _build_timestamped_container(records, builder, level="L2")
    return {**wrap(files), TSA_CERT_NAME: TSA_CERT()}


declare(
    "integrity-levels",
    "l0-valid",
    "container",
    "container",
    "valid",
    build=lambda case_dir: container(SIMPLE_RECORDS(), level="L0"),
    args=LEVEL_ARGS,
    expected_container={
        "level_claimed": "L0",
        "level_verified": "L0",
        "chain": {"status": "absent"},
    },
    notes="L0 positive: only the export-time container signature, no internal chain "
    "claim and no timestamp; level_verified is L0 and chain.status is 'absent'.",
)

declare(
    "integrity-levels",
    "l1-valid",
    "container",
    "container",
    "valid",
    build=lambda case_dir: container(SIMPLE_RECORDS(), level="L1"),
    args=LEVEL_ARGS,
    notices=("N_CHAIN_CLAIM_UNVERIFIED",),
    expected_container={
        "level_claimed": "L1",
        "level_verified": "L0",
        "chain": {"status": "unverified"},
    },
    notes="L1 positive: chain head plus chain_index on every record is structurally "
    "complete, but an offline verifier cannot recompute an exported internal chain, "
    "so it must report level_verified=L0 and the notice N_CHAIN_CLAIM_UNVERIFIED "
    "instead of claiming the chain was verified.",
)

declare(
    "integrity-levels",
    "l1-no-head",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_L1_NO_HEAD",),
    build=lambda case_dir: _l1_without_chain(),
    args=LEVEL_ARGS,
    notes="A manifest claiming L1 without manifest.chain is structurally incomplete "
    "(E_MANIFEST_L1_NO_HEAD); the manifest digest and signature are valid.",
)

declare(
    "integrity-levels",
    "l1-no-position",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_L1_NO_POSITION",),
    build=lambda case_dir: _l1_without_position(),
    args=LEVEL_ARGS,
    notes="A manifest claiming L1 with chain present but a records[] entry lacking "
    "chain_index is incomplete (E_MANIFEST_L1_NO_POSITION).",
)

declare(
    "integrity-levels",
    "l2-valid",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _crafted_l2_files(case_dir),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container=dict(level_claimed="L2", **L2_ANCHOR),
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    notes="L2 positive: one crafted DER TimeStampResp whose messageImprint is "
    "{sha256, raw 32-byte manifest digest}, CMS signature verified against the "
    "committed test TSA certificate, genTime inside the certificate validity "
    "window; with --tsa-trust the timestamp verifies, anchor_verified is true and "
    "level_verified stays L0 (L2 = L0 + verified anchor, never a hash-chain claim).",
)

declare(
    "integrity-levels",
    "l2-no-timestamp",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_L2_NO_TIMESTAMP",),
    build=lambda case_dir: container(SIMPLE_RECORDS(), level="L2"),
    args=LEVEL_ARGS,
    expected_container=dict(level_claimed="L2", **L2_NO_ANCHOR),
    notes="A manifest claiming L2 must list at least one RFC 3161 timestamp "
    "(E_MANIFEST_L2_NO_TIMESTAMP); existing .tsr files are not implied.",
)

declare(
    "integrity-levels",
    "l2-without-trust",
    "container",
    "container",
    "unverifiable",
    errors=("E_TS_UNTRUSTED",),
    build=lambda case_dir: _crafted_l2_files(case_dir, trust_name=None),
    args=LEVEL_ARGS,
    expected_container=dict(level_claimed="L2", **L2_NO_ANCHOR),
    notes="Same L2 container without --tsa-trust: the timestamp is "
    "'present-unverified' and the container MUST be unverifiable E_TS_UNTRUSTED, "
    "never valid, even though the TSR parses.",
)

declare(
    "integrity-levels",
    "l2-imprint-mismatch",
    "container",
    "container",
    "invalid",
    errors=("E_TS_IMPRINT",),
    build=lambda case_dir: _crafted_l2_files(
        case_dir,
        tsr_factory=lambda imprint: _crafted_tsr(_sha256_bytes(b"wrong imprint")),
    ),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container=dict(level_claimed="L2", **L2_NO_ANCHOR),
    notes="The timestamp token's messageImprint.hashedMessage is not the raw 32-byte "
    "manifest digest (E_TS_IMPRINT); a timestamp over another document proves "
    "nothing about this manifest.",
)

declare(
    "integrity-levels",
    "l2-ts-file-digest",
    "container",
    "container",
    "invalid",
    errors=("E_TS_FILE",),
    build=lambda case_dir: _l2_ts_file_digest_files(case_dir),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container=dict(level_claimed="L2", **L2_NO_ANCHOR),
    notes="The signature file lists a timestamp digest that the committed .tsr "
    "bytes do not hash to (E_TS_FILE).",
)

declare(
    "integrity-levels",
    "l0-with-timestamp",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_LEVEL",),
    build=lambda case_dir: _crafted_l2_files(case_dir, level="L0", trust_name=None),
    args=LEVEL_ARGS,
    expected_container=dict(level_claimed="L0", level_verified="L0", anchor_verified=False),
    notes="L0 must not carry timestamps (E_MANIFEST_LEVEL); timestamps are only "
    "meaningful for a claimed L2.",
)

declare(
    "integrity-levels",
    "l2-cms-tampered",
    "container",
    "container",
    "invalid",
    errors=("E_TS_CMS",),
    build=lambda case_dir: _crafted_l2_files(
        case_dir, tsr_factory=lambda imprint: _crafted_tsr(imprint, tamper_signature=True)
    ),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container=dict(level_claimed="L2", **L2_NO_ANCHOR),
    notes="The CMS signature bytes are altered after signing: the signed attributes "
    "no longer verify (E_TS_CMS). A timestamp whose signature does not verify is "
    "invalid, never merely present-unverified.",
)

declare(
    "integrity-levels",
    "l2-ess-v1-only",
    "container",
    "container",
    "invalid",
    errors=("E_TS_CMS",),
    build=lambda case_dir: _crafted_l2_files(
        case_dir, tsr_factory=lambda imprint: _crafted_tsr(imprint, ess="v1")
    ),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container=dict(level_claimed="L2", **L2_NO_ANCHOR),
    notes="The token carries only the legacy ESS signingCertificate (v1, SHA-1) "
    "attribute instead of signingCertificateV2: E_TS_CMS. The archive profile "
    "requires ESS v2 so the signer certificate is bound under SHA-256.",
)

declare(
    "integrity-levels",
    "l2-ess-missing",
    "container",
    "container",
    "invalid",
    errors=("E_TS_CMS",),
    build=lambda case_dir: _crafted_l2_files(
        case_dir, tsr_factory=lambda imprint: _crafted_tsr(imprint, ess="none")
    ),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container=dict(level_claimed="L2", **L2_NO_ANCHOR),
    notes="The token has no ESS signing-certificate attribute at all (E_TS_CMS): "
    "without it the signer certificate is not bound to the signed attributes.",
)

declare(
    "integrity-levels",
    "l2-message-digest-wrong",
    "container",
    "container",
    "invalid",
    errors=("E_TS_CMS",),
    build=lambda case_dir: _crafted_l2_files(
        case_dir,
        tsr_factory=lambda imprint: _crafted_tsr(
            imprint, message_digest_override=_sha256_bytes(b"wrong digest")
        ),
    ),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container=dict(level_claimed="L2", **L2_NO_ANCHOR),
    notes="The signed messageDigest attribute does not equal SHA-256 of the "
    "eContent TSTInfo (E_TS_CMS), so the signature does not actually cover the "
    "timestamp statement (e.g. the genTime could have been swapped).",
)

declare(
    "integrity-levels",
    "l2-cert-not-in-token",
    "container",
    "container",
    "invalid",
    errors=("E_TS_CMS",),
    build=lambda case_dir: _crafted_l2_files(
        case_dir,
        tsr_factory=lambda imprint: _crafted_tsr(imprint, include_certificate=False),
    ),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container=dict(level_claimed="L2", **L2_NO_ANCHOR),
    notes="The signer certificate must be carried inside the token's certificates "
    "set; --tsa-trust does not substitute for it (E_TS_CMS).",
)

declare(
    "integrity-levels",
    "l2-eku-missing",
    "container",
    "container",
    "invalid",
    errors=("E_TS_CERT",),
    build=lambda case_dir: _crafted_l2_files(
        case_dir,
        tsr_factory=_with_certificate("no-eku"),
        cert_variant="no-eku",
        trust_name="tsa-crafted.pem",
    ),
    args=("--keys", "@keyset", "--tsa-trust", "tsa-crafted.pem"),
    expected_container=dict(level_claimed="L2", **L2_NO_ANCHOR),
    notes="The timestamp signer certificate has no id-kp-timeStamping extended key "
    "usage: E_TS_CERT. The certificate is supplied as the trust anchor so the "
    "failure is the EKU check, not the fingerprint comparison.",
)

declare(
    "integrity-levels",
    "l2-cert-expired",
    "container",
    "container",
    "invalid",
    errors=("E_TS_CERT",),
    build=lambda case_dir: _crafted_l2_files(
        case_dir,
        tsr_factory=_with_certificate("expired"),
        cert_variant="expired",
        trust_name="tsa-crafted.pem",
    ),
    args=("--keys", "@keyset", "--tsa-trust", "tsa-crafted.pem"),
    expected_container=dict(level_claimed="L2", **L2_NO_ANCHOR),
    notes="The signer certificate expired in 2021 while genTime is 2026: the "
    "certificate validity window must contain genTime (E_TS_CERT), independent of "
    "the wall clock.",
)

declare(
    "integrity-levels",
    "l2-digest-algorithm-unsupported",
    "container",
    "container",
    "invalid",
    errors=("E_TS_SCHEMA",),
    build=lambda case_dir: _crafted_l2_files(
        case_dir,
        tsr_factory=lambda imprint: _crafted_tsr(
            imprint,
            imprint_algorithm="sha1",
            imprint_bytes=_sha256_bytes(b"sha1 imprint")[:20],
        ),
    ),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container=dict(level_claimed="L2", **L2_NO_ANCHOR),
    notes="messageImprint.hashAlgorithm is sha1; the archive profile requires "
    "sha256 (E_TS_SCHEMA). The token itself is correctly signed, so only the "
    "algorithm restriction fails.",
)

declare(
    "integrity-levels",
    "l2-status-not-granted",
    "container",
    "container",
    "invalid",
    errors=("E_TS_SCHEMA",),
    build=lambda case_dir: _crafted_l2_files(
        case_dir, tsr_factory=lambda imprint: _crafted_tsr(imprint, status=1)
    ),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container=dict(level_claimed="L2", **L2_NO_ANCHOR),
    notes="PKIStatusInfo.status is grantedWithMods (1) instead of granted (0): "
    "E_TS_SCHEMA. Only an unmodified granted status is accepted.",
)

declare(
    "integrity-levels",
    "l2-anchor-mismatch",
    "container",
    "container",
    "unverifiable",
    errors=("E_TS_UNTRUSTED",),
    build=lambda case_dir: _crafted_l2_files(
        case_dir,
        cert_variant="wrong-anchor",
        trust_name="tsa-crafted.pem",
    ),
    args=("--keys", "@keyset", "--tsa-trust", "tsa-crafted.pem"),
    expected_container=dict(level_claimed="L2", **L2_NO_ANCHOR),
    notes="The supplied trust anchor's DER SHA-256 does not match the signer leaf "
    "certificate: the timestamp stays present-unverified and the container is "
    "unverifiable E_TS_UNTRUSTED.",
)

declare(
    "integrity-levels",
    "l2-renewal-chain-valid",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _l2_renewal_files(case_dir),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container=dict(level_claimed="L2", **L2_ANCHOR),
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    notes="Positive renewal chain: reply 1 timestamps the manifest digest "
    "(renews=null); reply 2 timestamps SHA-256(reply-1 bytes || manifest digest) "
    "and points renews at reply 1. The chain is structurally complete, every "
    "imprint verifies and the anchor matches: anchor_verified is true.",
)

declare(
    "integrity-levels",
    "l2-renewal-broken",
    "container",
    "container",
    "invalid",
    errors=("E_TS_RENEWAL",),
    build=lambda case_dir: _l2_renewal_files(
        case_dir, renews="signatures/timestamp-3.tsr"
    ),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container=dict(level_claimed="L2", **L2_NO_ANCHOR),
    notes="The second reply's renews member points at a reply that is not listed "
    "in the signature file: the renewal chain is broken (E_TS_RENEWAL), not a "
    "chain of one.",
)

declare(
    "integrity-levels",
    "l2-renewal-imprint-mismatch",
    "container",
    "container",
    "invalid",
    errors=("E_TS_IMPRINT",),
    build=lambda case_dir: _l2_renewal_files(case_dir, renewal_imprint="previous-only"),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container=dict(level_claimed="L2", **L2_NO_ANCHOR),
    notes="The second reply's imprint covers only the previous .tsr bytes instead of "
    "SHA-256(previous .tsr bytes || manifest digest): E_TS_IMPRINT. The renewal "
    "link itself is structurally present.",
)


# ---------------------------------------------------------------------------
# Ablation-closure vectors (each makes one otherwise-unpinned check the first
# failing check; expected codes are handwritten from the registry/spec)
# ---------------------------------------------------------------------------


def _chain_unexpected_zip_files() -> dict[str, bytes]:
    """A zip container whose manifest has no previous but carries previous/manifest.json.

    A zip without explicit directory entries has no ``previous/`` entry in the
    container's directory set, so only the first unexpected-previous branch (the
    embedded manifest file itself) can reject it.
    """
    files = recordlib.build_container(SIMPLE_RECORDS())
    files["previous/manifest.json"] = _previous_manifest_bytes()
    return {"container.zip": as_zip(files)}


def _blobs_extra_unlisted_files() -> dict[str, bytes]:
    """A container with a listed blob plus one extra blob file not in the manifest."""
    files = recordlib.build_container(
        SIMPLE_RECORDS(), blobs=[(b"listed blob data\n", b"")]
    )
    files["blobs/sha256/%s" % ("ab" * 32)] = b"unlisted blob\n"
    return files


def _chain_depth_grant_files() -> dict[str, bytes]:
    """A delegated grant chain deeper than the maximum depth (8)."""
    records: list[dict[str, Any]] = []
    parent = root_grant(
        record_id="grant-depth-root",
        kinds=("weave.grant", "example.note"),
        actions=("grant", "propose", "accept"),
        transferable=True,
    )
    records.append(parent)
    grantee = "agent-2"
    for index in range(9):
        sub_granter = "agent-1" if index % 2 == 0 else "agent-2"
        child = delegated_grant(
            parent,
            record_id="grant-depth-%d" % (index + 1),
            sub_granter=sub_granter,
            grantee=grantee,
            kinds=("weave.grant", "example.note"),
            actions=("grant", "propose", "accept"),
            valid_from=recordlib.T0,
            valid_until=recordlib.T9,
            transferable=True,
        )
        records.append(child)
        parent = child
        grantee = "agent-1" if index % 2 == 0 else "agent-2"
    return container(records)


declare(
    "container",
    "blobs-extra-unlisted",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_BLOB",),
    build=lambda case_dir: _blobs_extra_unlisted_files(),
    args=("--keys", "@keyset"),
    notes="blobs/ contains a content-addressed file that manifest.blobs does not "
    "list: the blobs directory and the manifest must agree exactly, so this is "
    "E_MANIFEST_BLOB (the blob tree is closed).",
)

declare(
    "grant",
    "chain-depth-exceeded",
    "container",
    "container",
    "unverifiable",
    errors=("E_GRANT_UNRESOLVED",),
    build=lambda case_dir: _chain_depth_grant_files(),
    args=GRANT_ARGS,
    notes="A delegated-authorisation chain longer than the maximum depth (8) cannot "
    "be checked to a fixed point, so the deepest sub-grant is unverifiable "
    "E_GRANT_UNRESOLVED. The chain is built from distinct records (no digest "
    "cycles, which are impossible by construction).",
)

declare(
    "key-lifecycle",
    "declared-nonroot-human-not-cosigned",
    "record",
    "record.json",
    "unverifiable",
    errors=("E_KEY_UNTRUSTED",),
    build=lambda case_dir: {
        "record.json": canonical(
            derived_declaration(
                record_id="key-declared-nonroot-human",
                key_name="nonroot-human",
                key_type="human",
                recorded_at=recordlib.T1,
                cosigners=(),
            )
        )
    },
    args=LIFECYCLE_ARGS,
    notices=("N_SELF_ATTESTED_ROOT_KEY",),
    notes="Revision-2 R2: a non-root human declaration with only its own signature "
    "and no cosignature tracing to a trusted keyset root is UNVERIFIABLE "
    "E_KEY_UNTRUSTED (it is not a root, and roots come only from --keys), with "
    "N_SELF_ATTESTED_ROOT_KEY. The old revision-1 expectation (invalid "
    "E_KEY_DECLARED_NOT_COSIGNED) came from the record-time root-selection rule "
    "that R2 removes.",
)

declare(
    "key-lifecycle",
    "declared-validity-inverted",
    "record",
    "record.json",
    "invalid",
    errors=("E_KEY_VALIDITY",),
    build=lambda case_dir: {
        "record.json": canonical(
            derived_declaration(
                record_id="key-declared-inverted-window",
                key_name="inverted-window-key",
                key_type="human",
                valid_from=recordlib.T3,
                valid_until=recordlib.T2,
                cosigners=("human-1",),
            )
        )
    },
    args=LIFECYCLE_ARGS,
    notes="A declaration whose valid_from is later than its valid_until is "
    "E_KEY_VALIDITY invalid; self-signature and cosignature are both valid, so the "
    "window check is the failing rule.",
)

declare(
    "key-lifecycle",
    "revoke-effective-after-recorded",
    "record",
    "record.json",
    "invalid",
    errors=("E_KEY_REVOKE_EFFECTIVE",),
    build=lambda case_dir: {
        "record.json": canonical(
            recordlib.key_revocation(
                "key-old",
                reason="retired",
                effective_at=recordlib.T4,
                recorded_at=recordlib.T3,
                signer_name="human-1",
                record_id="key-revoked-effective-late",
            )
        )
    },
    args=LIFECYCLE_ARGS,
    notes="A revocation may not take effect after it was recorded: "
    "effective_at > recorded_at is E_KEY_REVOKE_EFFECTIVE invalid.",
)

declare(
    "key-lifecycle",
    "revoke-signer-unqualified",
    "record",
    "record.json",
    "invalid",
    errors=("E_KEY_REVOKE_SIGNER",),
    build=lambda case_dir: {
        "record.json": canonical(
            recordlib.key_revocation(
                "key-old",
                reason="key-compromise",
                effective_at=recordlib.T3,
                recorded_at=recordlib.T3,
                signer_name="program-1",
                record_id="key-revoked-unqualified-signer",
            )
        )
    },
    args=LIFECYCLE_ARGS,
    notes="A key-compromise revocation requires a human or organization signature; "
    "a program-key signature is E_KEY_REVOKE_SIGNER invalid.",
)

declare(
    "erasure",
    "actor-program-basis-lacks-erase",
    "container",
    "container",
    "invalid",
    errors=("E_ERASE_ACTOR",),
    build=lambda case_dir: _erasure_actor_files(
        erasure_signer="program-1",
        grant_grantee="program-1",
        use_basis=True,
        basis_actions=("accept",),
        reason="retention-expired",
    ),
    args=ERASURE_REVISION_ARGS,
    notes="A program/device erasure is only authorised when body.basis resolves to a "
    "grant that allows the erase action; a basis grant without 'erase' is "
    "E_ERASE_ACTOR invalid.",
)

declare(
    "integrity-levels",
    "l2-content-type-wrong",
    "container",
    "container",
    "invalid",
    errors=("E_TS_SCHEMA",),
    build=lambda case_dir: _crafted_l2_files(
        case_dir,
        tsr_factory=lambda imprint: _crafted_tsr(imprint, encap_content_type="data"),
    ),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container=dict(level_claimed="L2", **L2_NO_ANCHOR),
    notes="The CMS SignedData encapsulates content type id-data instead of "
    "id-ct-TSTInfo: the token is not a timestamp token (E_TS_SCHEMA).",
)

declare(
    "integrity-levels",
    "l2-signed-attrs-content-type-wrong",
    "container",
    "container",
    "invalid",
    errors=("E_TS_CMS",),
    build=lambda case_dir: _crafted_l2_files(
        case_dir,
        tsr_factory=lambda imprint: _crafted_tsr(
            imprint, attribute_content_type="data"
        ),
    ),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container=dict(level_claimed="L2", **L2_NO_ANCHOR),
    notes="The signed content_type attribute names id-data instead of id-ct-TSTInfo, "
    "so the signed attributes do not describe the encapsulated content "
    "(E_TS_CMS).",
)

declare(
    "integrity-levels",
    "l2-signer-digest-algorithm-unsupported",
    "container",
    "container",
    "invalid",
    errors=("E_TS_SCHEMA",),
    build=lambda case_dir: _crafted_l2_files(
        case_dir,
        tsr_factory=lambda imprint: _crafted_tsr(
            imprint, signer_digest_algorithm="sha384"
        ),
    ),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container=dict(level_claimed="L2", **L2_NO_ANCHOR),
    notes="signerInfo.digestAlgorithm is sha384; the archive profile requires sha256 "
    "for the signer digest algorithm (E_TS_SCHEMA).",
)

declare(
    "integrity-levels",
    "l2-key-usage-missing",
    "container",
    "container",
    "invalid",
    errors=("E_TS_CERT",),
    build=lambda case_dir: _crafted_l2_files(
        case_dir,
        tsr_factory=_with_certificate("ku-without-digital"),
        cert_variant="ku-without-digital",
        trust_name="tsa-crafted.pem",
    ),
    args=("--keys", "@keyset", "--tsa-trust", "tsa-crafted.pem"),
    expected_container=dict(level_claimed="L2", **L2_NO_ANCHOR),
    notes="The signer certificate carries a KeyUsage extension without "
    "digitalSignature: E_TS_CERT. An absent KeyUsage is tolerated, but a present "
    "one must allow digital signatures.",
)



declare(
    "container",
    "chain-unexpected-first",
    "container",
    "container.zip",
    "invalid",
    errors=("E_MANIFEST_CHAIN_UNEXPECTED",),
    build=lambda case_dir: _chain_unexpected_zip_files(),
    args=("--keys", "@keyset"),
    notes="Zip form of the unexpected-previous manifest: previous_manifest is null "
    "but the archive carries previous/manifest.json. With no explicit previous/ "
    "directory entry, only the embedded-file branch can reject this, which pins "
    "that first branch (E_MANIFEST_CHAIN_UNEXPECTED).",
)

declare(
    "integrity-levels",
    "l2-cert-not-matching-token",
    "container",
    "container",
    "invalid",
    errors=("E_TS_CMS",),
    build=lambda case_dir: _crafted_l2_files(
        case_dir,
        tsr_factory=lambda imprint: _crafted_tsr(
            imprint,
            certificates_override=[_crafted_certificate("wrong-anchor")[0]],
        ),
    ),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container=dict(level_claimed="L2", **L2_NO_ANCHOR),
    notes="The token carries a certificate set, but none of its certificates is the "
    "signer certificate named by signerInfo.sid: the signer certificate MUST be "
    "carried inside the token (E_TS_CMS), regardless of --tsa-trust.",
)

declare(
    "integrity-levels",
    "l2-eku-wrong-usage",
    "container",
    "container",
    "invalid",
    errors=("E_TS_CERT",),
    build=lambda case_dir: _crafted_l2_files(
        case_dir,
        tsr_factory=_with_certificate("eku-wrong"),
        cert_variant="eku-wrong",
        trust_name="tsa-crafted.pem",
    ),
    args=("--keys", "@keyset", "--tsa-trust", "tsa-crafted.pem"),
    expected_container=dict(level_claimed="L2", **L2_NO_ANCHOR),
    notes="The signer certificate has an extendedKeyUsage extension, but it does "
    "not include id-kp-timeStamping: E_TS_CERT. This pins the timestamping-profile "
    "branch separately from the missing-EKU branch.",
)


# ---------------------------------------------------------------------------
# Revision-2 vectors (决定 #42 R1-R5): ancestor revocation, local trust roots,
# timestamp accuracy and untrusted receipts
# ---------------------------------------------------------------------------


def _self_attested_human_declaration(
    *, record_id: str, key_name: str, recorded_at: str = recordlib.T0
) -> dict[str, Any]:
    """A human declaration carrying only its own signature (no cosignature)."""
    return derived_declaration(
        record_id=record_id,
        key_name=key_name,
        key_type="human",
        cosigners=(),
        recorded_at=recorded_at,
    )


def _agent_declaration_with_derived_owner(
    *,
    record_id: str,
    agent_key_name: str,
    owner_key_name: str,
    cosign: bool = True,
    recorded_at: str = recordlib.T0,
) -> dict[str, Any]:
    """An agent declaration whose owner is fresh (container-only) human material."""
    owner_private, _owner_public, owner_id = derived_key(owner_key_name)
    agent_private, agent_public, agent_id = derived_key(agent_key_name)
    body = {
        "algorithm": "ed25519",
        "key": agent_id,
        "key_type": "agent",
        "public_key": keyutil.b64url_encode(agent_public),
        "owner": owner_id,
    }
    record = recordlib.build_record(
        kind="weave.key.declared",
        id=record_id,
        actor={"type": "agent", "key": agent_id},
        body=body,
        stage="accepted",
        recorded_at=recorded_at,
        origin_instance=agent_id,
    )
    signatures = [_derived_signature(agent_private, agent_id, record)]
    if cosign:
        signatures.append(_derived_signature(owner_private, owner_id, record))
    signatures.sort(key=lambda entry: entry["key"])
    record["sigs"] = signatures
    return record


def _ancestor_revoked_files(*, note_recorded_at: str) -> dict[str, bytes]:
    """Root grant + delegated sub-grant + root revocation + a record citing the sub-grant.

    Revision-2 R1: the whole grant chain is evaluated at the record's own claimed
    recorded_at -- including ancestors. With the root revoked at T4, a note written
    at T5 is unverifiable E_GRANT_REVOKED; a note written at T3 (control) is valid.
    """
    root = root_grant(
        record_id="grant-ancestor-root",
        kinds=("weave.grant", "example.note"),
        actions=("propose", "accept", "grant"),
        transferable=True,
        valid_from=recordlib.T0,
        valid_until=recordlib.T9,
    )
    sub = delegated_grant(
        root,
        record_id="grant-ancestor-sub",
        sub_granter="agent-1",
        grantee="agent-2",
        kinds=("example.note",),
        actions=("propose", "accept"),
        valid_from=recordlib.T1,
        valid_until=recordlib.T8,
        transferable=False,
        recorded_at=recordlib.T1,
    )
    revocation = grant_revocation(
        root,
        record_id="grant-ancestor-revoke",
        effective_at=recordlib.T4,
    )
    note_by_agent = agent_action(
        sub,
        record_id="agent-ancestor-note",
        key_name="agent-2",
        stage="proposed",
        recorded_at=note_recorded_at,
    )
    return container([root, sub, revocation, note_by_agent])


def _compromise_accuracy_files(
    case_dir: Path,
    *,
    accuracy: tuple[int, int, int],
    effective_at: str,
) -> dict[str, bytes]:
    """L2 container whose only receipt has the given accuracy (R3 boundary)."""
    records = [
        recordlib.key_revocation(
            "key-compromised",
            reason="key-compromise",
            effective_at=effective_at,
            recorded_at=effective_at,
            signer_name="human-1",
            record_id="key-revoked-compromise-accuracy",
        ),
        record_signed_by(
            "key-compromised",
            "record-compromise-accuracy",
            recorded_at="2027-01-01T00:00:00.000Z",
        ),
    ]

    def builder(imprint: bytes) -> list[tuple[str, bytes, str | None]]:
        return [
            (
                "signatures/timestamp-1.tsr",
                _crafted_tsr(imprint, accuracy=accuracy),
                None,
            )
        ]

    files = _build_timestamped_container(records, builder, level="L2")
    return {**wrap(files), TSA_CERT_NAME: TSA_CERT()}


def _compromise_untrusted_timestamp_files(case_dir: Path) -> dict[str, bytes]:
    """L2 container with a receipt but no trust anchor (R4 untrusted receipt)."""
    effective_at = "2026-12-01T00:00:00.000Z"
    records = [
        recordlib.key_revocation(
            "key-compromised",
            reason="key-compromise",
            effective_at=effective_at,
            recorded_at=effective_at,
            signer_name="human-1",
            record_id="key-revoked-compromise-untrusted",
        ),
        record_signed_by(
            "key-compromised",
            "record-before-compromise-untrusted",
            recorded_at="2027-01-01T00:00:00.000Z",
        ),
    ]

    def builder(imprint: bytes) -> list[tuple[str, bytes, str | None]]:
        return [("signatures/timestamp-1.tsr", _crafted_tsr(imprint), None)]

    files = _build_timestamped_container(records, builder, level="L2")
    return wrap(files)


declare(
    "container",
    "self-attested-root-untrusted",
    "container",
    "container",
    "unverifiable",
    errors=("E_KEY_UNTRUSTED",),
    build=lambda case_dir: container(SIMPLE_RECORDS()),
    notices=("N_SELF_ATTESTED_ROOT_KEY",),
    records=(
        {
            "id": "key-declared-human-1",
            "verdict": "unverifiable",
            "errors": ["E_KEY_UNTRUSTED"],
        },
    ),
    notes="Revision-2 R2, same bytes as container/l0-minimal but WITHOUT the local "
    "trust input: a root may only come from the verifier's keyset, never from a "
    "container record that merely self-signs, so the declaration is unverifiable "
    "E_KEY_UNTRUSTED with N_SELF_ATTESTED_ROOT_KEY. Byte-level checks still pass.",
)

declare(
    "grant",
    "ancestor-revoked-before-record",
    "container",
    "container",
    "unverifiable",
    errors=("E_GRANT_REVOKED",),
    build=lambda case_dir: _ancestor_revoked_files(note_recorded_at=recordlib.T5),
    args=GRANT_ARGS,
    records=(
        {
            "id": "agent-ancestor-note",
            "verdict": "unverifiable",
            "errors": ["E_GRANT_REVOKED"],
        },
    ),
    notes="Revision-2 R1: the whole authorisation chain is checked at the record's "
    "own claimed recorded_at, ancestors included. The root grant was revoked at "
    "T4 (11-05); the sub-grant was issued at T1 while the root was live, but the "
    "agent note is written at T5, so the chain is revoked as of T5 and the note is "
    "unverifiable E_GRANT_REVOKED (a second implementation evaluating ancestors at "
    "the sub-grant's time would wrongly accept it).",
)

declare(
    "grant",
    "ancestor-revoked-control-before-effective",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _ancestor_revoked_files(note_recorded_at=recordlib.T3),
    args=GRANT_ARGS,
    records=(
        {"id": "grant-ancestor-root", "verdict": "valid", "errors": []},
        {"id": "grant-ancestor-sub", "verdict": "valid", "errors": []},
        {"id": "grant-ancestor-revoke", "verdict": "valid", "errors": []},
        {"id": "agent-ancestor-note", "verdict": "valid", "errors": []},
    ),
    notes="Revision-2 R1 control: the same chain and revocation, but the note is "
    "written at T3, before the root's revocation took effect at T4; every record "
    "is valid and the container is valid.",
)

declare(
    "key-lifecycle",
    "backdated-container-root",
    "record",
    "record.json",
    "unverifiable",
    errors=("E_KEY_UNTRUSTED",),
    build=lambda case_dir: {
        "record.json": canonical(
            _self_attested_human_declaration(
                record_id="key-declared-backdated-container-root",
                key_name="backdated-container-human",
                recorded_at="2020-01-01T00:00:00.000Z",
            )
        )
    },
    args=LIFECYCLE_ARGS,
    notes="Revision-2 R2 (anti-verification b pin): backdating the claimed "
    "recorded_at to 2020 does not turn a container/target self-signed human "
    "declaration into a root. Roots come only from the local keyset, so this "
    "declaration is unverifiable E_KEY_UNTRUSTED with N_SELF_ATTESTED_ROOT_KEY "
    "rather than accepted by an earliest-recorded_at root election.",
)

declare(
    "key-lifecycle",
    "keyset-root-not-invalidated",
    "container",
    "container",
    "unverifiable",
    errors=("E_KEY_UNTRUSTED", "E_KEY_UNKNOWN"),
    build=lambda case_dir: container(
        [
            _self_attested_human_declaration(
                record_id="key-declared-attacker-backdated",
                key_name="backdated-attacker",
                recorded_at="2020-01-01T00:00:00.000Z",
            ),
            recordlib.signed(note("keyset-root-note"), "human-1"),
            derived_record(
                record_id="attacker-signed-note",
                key_name="backdated-attacker",
                recorded_at=recordlib.T2,
            ),
        ]
    ),
    args=LIFECYCLE_ARGS,
    records=(
        {"id": "keyset-root-note", "verdict": "valid", "errors": []},
        {
            "id": "key-declared-attacker-backdated",
            "verdict": "unverifiable",
            "errors": ["E_KEY_UNTRUSTED"],
        },
        {
            "id": "attacker-signed-note",
            "verdict": "unverifiable",
            "errors": ["E_KEY_UNKNOWN"],
        },
    ),
    notes="Revision-2 R2: an attacker's backdated self-signed human declaration in "
    "the container is unverifiable and must not invalidate the local keyset root -- "
    "the human-1 notes stay valid, only the attacker's own records are unverifiable "
    "(its signing key never enters the key state, so its note is E_KEY_UNKNOWN). "
    "The container verdict is unverifiable, never invalid.",
)

declare(
    "key-lifecycle",
    "declared-owner-wrong-class",
    "record",
    "record.json",
    "invalid",
    errors=("E_KEY_OWNER_MISSING",),
    build=lambda case_dir: {
        "record.json": canonical(
            derived_declaration(
                record_id="key-declared-owner-wrong-class",
                key_name="owner-wrong-class-agent",
                key_type="agent",
                owner="agent-1",
                cosigners=("agent-1",),
            )
        )
    },
    args=LIFECYCLE_ARGS,
    notes="Revision-2 R5: body.owner must resolve to a human or organization "
    "declaration; an owner whose declared class is agent is invalid "
    "E_KEY_OWNER_MISSING (the owner is resolvable and has cosigned, but its class "
    "is wrong).",
)

declare(
    "key-lifecycle",
    "untrusted-owner-cosign",
    "container",
    "container",
    "unverifiable",
    errors=("E_KEY_UNTRUSTED",),
    build=lambda case_dir: container(
        [
            _self_attested_human_declaration(
                record_id="key-declared-container-owner",
                key_name="container-only-owner",
                recorded_at=recordlib.T0,
            ),
            _agent_declaration_with_derived_owner(
                record_id="key-declared-untrusted-owner-agent",
                agent_key_name="untrusted-owner-agent",
                owner_key_name="container-only-owner",
                cosign=True,
                recorded_at=recordlib.T1,
            ),
        ]
    ),
    args=LIFECYCLE_ARGS,
    expected_container={"level_claimed": "L0", "level_verified": "L0"},
    records=(
        {
            "id": "key-declared-container-owner",
            "verdict": "unverifiable",
            "errors": ["E_KEY_UNTRUSTED"],
        },
        {
            "id": "key-declared-untrusted-owner-agent",
            "verdict": "unverifiable",
            "errors": ["E_KEY_UNTRUSTED"],
        },
    ),
    notices=("N_SELF_ATTESTED_ROOT_KEY",),
    notes="Revision-2 R2: an agent declaration is cosigned by its owner, but that "
    "owner is only a container self-signed human declaration that cannot trace to "
    "the local keyset root. The owner is untrusted, so the agent declaration is "
    "unverifiable E_KEY_UNTRUSTED (not invalid): the cosignature is there but the "
    "owner is not trusted.",
)

declare(
    "key-lifecycle",
    "compromise-accuracy-equality",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_COMPROMISED",),
    build=lambda case_dir: _compromise_accuracy_files(
        case_dir,
        accuracy=(1, 0, 0),
        effective_at="2026-11-01T00:00:01.000Z",
    ),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container={
        "level_claimed": "L2",
        "level_verified": "L0",
        "anchor_verified": True,
    },
    records=(
        {
            "id": "record-compromise-accuracy",
            "verdict": "invalid",
            "errors": ["E_KEY_COMPROMISED"],
        },
    ),
    notes="Revision-2 R3 equality boundary: the receipt's genTime is "
    "2026-11-01T00:00:00.000Z with accuracy 1 second, so genTime+accuracy equals "
    "the compromise effective_at T exactly; the rescue requires genTime+accuracy "
    "STRICTLY before T, so the compromised-key signature is invalid "
    "E_KEY_COMPROMISED.",
)

declare(
    "key-lifecycle",
    "compromise-accuracy-crossing",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_COMPROMISED",),
    build=lambda case_dir: _compromise_accuracy_files(
        case_dir,
        accuracy=(1, 0, 0),
        effective_at="2026-11-01T00:00:00.500Z",
    ),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container={
        "level_claimed": "L2",
        "level_verified": "L0",
        "anchor_verified": True,
    },
    records=(
        {
            "id": "record-compromise-accuracy",
            "verdict": "invalid",
            "errors": ["E_KEY_COMPROMISED"],
        },
    ),
    notes="Revision-2 R3 accuracy crossing: genTime (00:00:00.000) is earlier than "
    "T (00:00:00.500), but adding the receipt's 1-second accuracy crosses T, so the "
    "true timestamp is not provably before the compromise and the signature is "
    "invalid E_KEY_COMPROMISED. Accuracy must be taken into account.",
)

declare(
    "key-lifecycle",
    "compromise-untrusted-timestamp",
    "container",
    "container",
    "unverifiable",
    errors=("E_TS_UNTRUSTED",),
    build=lambda case_dir: _compromise_untrusted_timestamp_files(case_dir),
    args=("--keys", "@keyset"),
    expected_container={
        "level_claimed": "L2",
        "level_verified": "L0",
        "anchor_verified": False,
    },
    records=(
        {
            "id": "record-before-compromise-untrusted",
            "verdict": "unverifiable",
            "errors": ["E_TS_UNTRUSTED"],
        },
    ),
    notes="Revision-2 R4: the container carries a timestamp receipt but the "
    "verifier was given no --tsa-trust, so the rescue evidence exists yet cannot "
    "be trusted. Missing information yields unverifiable E_TS_UNTRUSTED for the "
    "compromised-key record and the container, never invalid. Without any receipt "
    "at all the record is invalid E_KEY_COMPROMISED (L0 cases).",
)

# === END CASE SECTIONS ===


# ---------------------------------------------------------------------------
# Case writing / checking
# ---------------------------------------------------------------------------


def _manifest_id_kind_mismatch_files() -> dict[str, bytes]:
    """A container whose manifest entry kind contradicts its record envelope."""
    built = recordlib.build_container(SIMPLE_RECORDS())

    def mutator(manifest: dict[str, Any]) -> dict[str, Any]:
        result = dict(manifest)
        entries = [dict(entry) for entry in result["records"]]
        entries[0]["kind"] = "weave.key.revoked"
        result["records"] = entries
        return result

    return recordlib.mutate_manifest(built, mutator, resign_with=("human-1",))


def _record_extra_files() -> dict[str, bytes]:
    """A container with one extra records/ file that the manifest does not list."""
    extra = note("container-extra")
    files = recordlib.build_container(SIMPLE_RECORDS())
    files["records/%s.json" % recordlib.record_digest(extra)[len("sha256:") :]] = canonical(
        extra
    )
    return files


def _blobs_mismatch_files() -> dict[str, bytes]:
    """A container whose blob bytes no longer match manifest.blobs."""
    files = recordlib.build_container(
        SIMPLE_RECORDS(), blobs=[(b"blob data\n", b"")]
    )
    blob_path = [path for path in files if path.startswith("blobs/sha256/")][0]
    files[blob_path] = b"tampered blob bytes\n"
    return files



def _l1_without_chain() -> dict[str, bytes]:
    """Internal container files of an L1 manifest that claims no chain at all."""
    records = SIMPLE_RECORDS()
    files: dict[str, bytes] = {}
    for record in records:
        digest_hex = recordlib.record_digest(record)[len("sha256:") :]
        files["records/%s.json" % digest_hex] = canonical(record)
    manifest_value = recordlib.build_manifest(
        records, level="L1", chain=None, chain_indices=[0]
    )
    recordlib.seal_container(files, manifest_value, manifest_signers=("human-1",))
    return files


def _l1_without_position() -> dict[str, bytes]:
    """Internal container files of an L1 manifest with one record missing chain_index."""
    built = recordlib.build_container(SIMPLE_RECORDS(), level="L1")

    def mutator(manifest: dict[str, Any]) -> dict[str, Any]:
        result = dict(manifest)
        entries = [dict(entry) for entry in result["records"]]
        entries[0].pop("chain_index", None)
        result["records"] = entries
        return result

    return recordlib.mutate_manifest(built, mutator, resign_with=("human-1",))


def build_expected(case: Case, files: dict[str, bytes]) -> dict[str, Any]:
    expected: dict[str, Any] = {
        "id": case.id,
        "category": case.category,
        "target": case.target,
        "input": case.input,
        "verdict": case.verdict,
        "errors": list(case.errors),
    }
    if case.notices:
        expected["notices"] = list(case.notices)
    if case.args:
        expected["args"] = list(case.args)
    if case.expected_digest:
        if case.target != "record":
            raise SystemExit("%s: expected_digest is only for record targets" % case.id)
        record = parse(files[case.input])
        expected["expected_digest"] = recordlib.record_digest(record)
    if case.expected_resolution is not None:
        expected["expected_resolution"] = list(case.expected_resolution)
    if case.expected_container is not None:
        expected["expected_container"] = case.expected_container
    if case.records is not None:
        expected["records"] = list(case.records)
    if case.notes:
        expected["notes"] = case.notes
    return expected


def validate_case(case: Case, files: dict[str, bytes]) -> None:
    if case.verdict not in {"valid", "invalid", "unverifiable", "erased"}:
        raise SystemExit("%s: invalid verdict %r" % (case.id, case.verdict))
    if case.verdict == "invalid" and not case.errors:
        raise SystemExit("%s: invalid case must name expected error codes" % case.id)
    if case.verdict == "valid" and case.errors:
        raise SystemExit("%s: valid case may not expect error codes" % case.id)
    if case.target not in {"record", "container"}:
        raise SystemExit("%s: invalid target %r" % (case.id, case.target))
    if case.target == "record":
        if case.input not in files:
            raise SystemExit(
                "%s: input %r not among built files %s"
                % (case.id, case.input, sorted(files))
            )
    elif case.input == "container":
        if "container/manifest.json" not in files and "E_MANIFEST_MISSING" not in case.errors:
            raise SystemExit("%s: container case has no container/manifest.json" % case.id)
    elif case.input == "container.zip":
        if "container.zip" not in files:
            raise SystemExit("%s: zip case has no container.zip" % case.id)
    else:
        raise SystemExit("%s: container input must be container/container.zip" % case.id)
    for path in files:
        relative = Path(path)
        if relative.is_absolute() or ".." in relative.parts:
            raise SystemExit("%s: unsafe case file path %r" % (case.id, path))


def write_all(*, check: bool, only: str | None = None) -> list[str]:
    problems: list[str] = []
    selected = [case for case in CASES if only is None or case.category == only]
    # Remove case directories that no longer exist in the table (renamed or
    # dropped cases); the five categories below are owned entirely by this
    # generator, so no unrelated data lives under their category directories.
    for category in sorted({case.category for case in CASES}):
        if only is not None and category != only:
            continue
        category_dir = VECTORS_DIR / category
        if not category_dir.is_dir():
            continue
        wanted = {case.name for case in CASES if case.category == category}
        for child in sorted(category_dir.iterdir()):
            if child.is_dir() and child.name not in wanted:
                shutil.rmtree(child)
    seen: set[str] = set()
    for case in selected:
        if case.id in seen:
            raise SystemExit("duplicate case id %r" % case.id)
        seen.add(case.id)
        files = case.build(case.case_dir)
        # Builders may return internal container paths (manifest.json, records/...);
        # wrap those under the case-relative container/ dir that the runner reads.
        if (
            case.target == "container"
            and case.input == "container"
            and "manifest.json" in files
        ):
            files = wrap(files)
        validate_case(case, files)
        expected = build_expected(case, files)
        target_files = dict(files)
        target_files["expected.json"] = canonical(expected)
        case_dir = case.case_dir
        if check:
            if not case_dir.is_dir():
                problems.append("missing case dir %s" % case_dir)
                continue
            existing = {
                str(path.relative_to(case_dir)): path.read_bytes()
                for path in case_dir.rglob("*")
                if path.is_file()
            }
            for name, data in sorted(target_files.items()):
                if name not in existing:
                    problems.append("missing %s/%s" % (case_dir, name))
                elif existing[name] != data:
                    problems.append("content mismatch %s/%s" % (case_dir, name))
            for name in sorted(existing):
                if name not in target_files:
                    problems.append("unexpected file %s/%s" % (case_dir, name))
            continue
        if case_dir.exists():
            for path in sorted(case_dir.rglob("*"), reverse=True):
                if path.is_file() or path.is_symlink():
                    path.unlink()
                elif path.is_dir():
                    path.rmdir()
        case_dir.mkdir(parents=True, exist_ok=True)
        for name, data in target_files.items():
            destination = case_dir / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
    return problems



# ---------------------------------------------------------------------------
# Frozen regression set (`vectors/README.md`, gate 7)
# ---------------------------------------------------------------------------

FREEZE_VERSION = "v0.1-candidate"


def _all_case_expected() -> list[dict[str, Any]]:
    """Every generated case under vectors/<category>/<case-id>/ (frozen excluded)."""
    rows: list[dict[str, Any]] = []
    for expected_path in sorted(VECTORS_DIR.glob("*/*/expected.json")):
        if "frozen" in expected_path.parts:
            continue
        expected = wcj.parse_strict(expected_path.read_bytes())
        rows.append(
            {
                "id": expected["id"],
                "category": expected["category"],
                "case_dir": expected_path.parent,
                "expected": expected,
            }
        )
    return rows


def select_frozen_cases(rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """All positive cases plus one deterministic negative per error code family."""
    selected: dict[str, dict[str, Any]] = {}
    for row in rows:
        if row["expected"]["verdict"] in ("valid", "erased"):
            selected[row["id"]] = row
    by_code: dict[str, dict[str, Any]] = {}
    for row in rows:
        for code in row["expected"].get("errors", []):
            by_code.setdefault(code, row)
    for code in sorted(by_code):
        selected.setdefault(by_code[code]["id"], by_code[code])
    return [selected[case_id] for case_id in sorted(selected)]


def freeze_cases(*, source_commit: str, freeze_date: str) -> int:
    """Copy the representative set verbatim into vectors/frozen/<version>/."""
    rows = _all_case_expected()
    selected = select_frozen_cases(rows)
    destination = VECTORS_DIR / "frozen" / FREEZE_VERSION
    if destination.exists():
        for path in sorted(destination.rglob("*"), reverse=True):
            if path.is_file() or path.is_symlink():
                path.unlink()
            elif path.is_dir():
                path.rmdir()
    destination.mkdir(parents=True, exist_ok=True)

    category_counts: dict[str, int] = {}
    verdict_counts: dict[str, int] = {}
    for row in selected:
        case_dir: Path = row["case_dir"]
        target = destination / row["category"] / case_dir.name
        target.mkdir(parents=True, exist_ok=True)
        for source in case_dir.rglob("*"):
            if not source.is_file():
                continue
            relative = source.relative_to(case_dir)
            destination_file = target / relative
            destination_file.parent.mkdir(parents=True, exist_ok=True)
            destination_file.write_bytes(source.read_bytes())
        category_counts[row["category"]] = category_counts.get(row["category"], 0) + 1
        verdict = row["expected"]["verdict"]
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1

    lines = [
        "<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->",
        "<!-- SPDX-License-Identifier: Apache-2.0 -->",
        "",
        "# Candidate frozen conformance vectors, %s" % FREEZE_VERSION,
        "",
        "> **Status: CANDIDATE — not yet formally frozen.** The conclusions in this",
        "> directory are the candidate v0.1 regression set. They become formally",
        "> frozen (and must never change afterwards, K3) only when v0.1 is accepted",
        "> by the J1 and J2 round trips (decision draft §10). Until then the set may",
        "> be regenerated by the vector generators, but changes must be reviewed like",
        "> any other vector change. A later implementation or profile change adds new",
        "> vectors; the frozen/candidate cases are copied verbatim from a gated state",
        "> of the repository and keep their expected verdicts, error codes, notices,",
        "> digests and container bytes.",
        "",
        "- Freeze date: %s" % freeze_date,
        "- Source repository state: commit `%s`" % source_commit,
        "- Generated by: `tools/gen_vectors_extra.py --freeze` (only the copy step;",
        "  the cases themselves were generated by the independent generators).",
        "- Selection rule: **every positive case** (`valid`/`erased`) plus, for each",
        "  error code that appears in any case, the lexicographically first case that",
        "  expects it. This keeps at least one negative per registered error code",
        "  while remaining deterministic.",
        "",
        "- Case count: %d" % len(selected),
        "",
        "| Category | Cases |",
        "|---|---:|",
    ]
    for category in sorted(category_counts):
        lines.append("| `%s` | %d |" % (category, category_counts[category]))
    lines.extend(
        [
            "| **total** | **%d** |" % len(selected),
            "",
            "Verdicts: "
            + ", ".join(
                "`%s` %d" % (verdict, verdict_counts[verdict])
                for verdict in sorted(verdict_counts)
            )
            + ".",
            "",
            "Run the candidate regression set with:",
            "",
            "```bash",
            "hyphaweave-verify vectors vectors/frozen/%s" % FREEZE_VERSION,
            "```",
            "",
            "`SHA256SUMS` lists the SHA-256 of every file in this directory (except",
            "itself); `--check`-style verification of the inputs against it proves the",
            "frozen bytes were not edited.",
            "",
        ]
    )
    lines.extend(
        [
            "",
            "Formal-freeze condition: **J1 and J2 acceptance round trips** (decision",
            "draft §10) must have passed; only then may this candidate be renamed to",
            "the final frozen set and its conclusions become permanently stable.",
            "",
        ]
    )
    (destination / "FROZEN.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (destination / "FROZEN_CASE_COUNT").write_text(
        "%d\n" % len(selected), encoding="utf-8"
    )

    digest_lines = []
    for path in sorted(destination.rglob("*")):
        if not path.is_file() or path.name == "SHA256SUMS":
            continue
        digest_lines.append(
            "%s  %s" % (hashlib.sha256(path.read_bytes()).hexdigest(), path.relative_to(destination).as_posix())
        )
    (destination / "SHA256SUMS").write_text("\n".join(digest_lines) + "\n", encoding="utf-8")
    try:
        destination_label = destination.resolve().relative_to(REPO_ROOT)
    except ValueError:  # pragma: no cover - sandbox/QA override path
        destination_label = destination
    print(
        "wrote %d frozen case(s) under %s (%d categories)"
        % (len(selected), destination_label, len(category_counts))
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare regenerated output with the files on disk (exit 1 on drift)",
    )
    parser.add_argument(
        "--only",
        metavar="CATEGORY",
        help="regenerate one category only (erasure|grant|key-lifecycle|container|"
        "integrity-levels)",
    )
    parser.add_argument(
        "--freeze",
        action="store_true",
        help="copy the representative case set into vectors/frozen/v0.1 (gate 7)",
    )
    parser.add_argument(
        "--frozen-source-commit",
        metavar="SHA",
        help="source repository commit recorded in FROZEN.md (required with --freeze)",
    )
    parser.add_argument(
        "--freeze-date",
        metavar="YYYY-MM-DD",
        help="freeze date recorded in FROZEN.md (default: today, UTC)",
    )
    arguments = parser.parse_args(argv)
    if arguments.freeze:
        if not arguments.frozen_source_commit:
            print("--freeze requires --frozen-source-commit SHA", file=sys.stderr)
            return 2
        import datetime

        freeze_date = arguments.freeze_date or datetime.datetime.now(
            datetime.timezone.utc
        ).strftime("%Y-%m-%d")
        return freeze_cases(
            source_commit=arguments.frozen_source_commit, freeze_date=freeze_date
        )
    problems = write_all(check=arguments.check, only=arguments.only)
    if "hyphaweave_verify" in sys.modules:
        raise SystemExit("vector generator imported the reference verifier")
    if problems:
        for problem in problems:
            print("FAIL: %s" % problem, file=sys.stderr)
        return 1
    count = len([case for case in CASES if arguments.only in (None, case.category)])
    if arguments.check:
        print("ok: %d extra vector case(s) match the generator" % count)
    else:
        print("wrote %d extra vector case(s) under vectors/" % count)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
