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
import os
import shutil
import struct
import sys
import zipfile
import zlib
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
    expected_input: dict[str, Any] | None = None
    limitations: tuple[str, ...] | None = None
    notices_absent: tuple[str, ...] | None = None
    records: tuple[dict[str, Any], ...] | None = None
    symlinks: tuple[tuple[str, str], ...] = ()

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

    *accuracy* is ``(seconds, millis, micros)``; a component that is ``None`` is
    omitted, while an explicit integer (including 0) is written into the token.
    ``accuracy=None`` omits the Accuracy member entirely, which the profile
    treats as zero (revision-2 R3). T3 needs to express an explicit
    ``milliseconds = 0`` / ``microseconds = 0`` to exercise the "present
    component outside 1-999 is a format error" rule.
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
        components: dict[str, int] = {}
        if seconds is not None:
            components["seconds"] = seconds
        if millis is not None:
            components["millis"] = millis
        if micros is not None:
            components["micros"] = micros
        tst["accuracy"] = components
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
    accuracy: tuple[int | None, int | None, int | None] | None = None,
    gen_time: datetime.datetime | None = None,
) -> bytes:
    """Build one DER TimeStampResp deterministically (see module section note)."""
    signer_der = certificate_der if certificate_der is not None else _tsa_certificate_der()
    signer_certificate = asn1_x509.Certificate.load(signer_der)
    tst = _tst_info(
        imprint_bytes if imprint_bytes is not None else imprint,
        hash_algorithm=imprint_algorithm,
        accuracy=accuracy,
        gen_time=gen_time if gen_time is not None else FIXED_GEN_TIME,
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
    limitations=("L_OFFLINE_CONTEXT",),
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
    notices=("N_READABLE_PRESENT",),
    notes="readable/ is a human view outside the digest (§11.8, I1): arbitrary "
    "bytes there must not change validity, and the entries are never "
    "decompressed or CRC-checked. The container contains a readable/ entry, so "
    "the report MUST carry N_READABLE_PRESENT (it is no longer optional).",
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
    notices=("N_PREVIOUS_SIG_UNVERIFIED",),
    limitations=("L_OFFLINE_CONTEXT", "L_PREVIOUS_SIG_UNVERIFIED"),
    notes="Container c2 embeds c1's manifest under previous/manifest.json and "
    "commits previous_manifest.digest == manifest-digest(c1 bytes) (§11.5, D1). "
    "The previous manifest's own signature is not re-verified, so the report "
    "MUST carry N_PREVIOUS_SIG_UNVERIFIED and the L_PREVIOUS_SIG_UNVERIFIED "
    "limitation identifier.",
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
    expected_input={"sha256": None, "size": None},
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
    limitations=("L_ERASED_PLACEHOLDER", "L_OFFLINE_CONTEXT"),
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
    recorded_at: str | None = None,
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
        recorded_at=recorded_at if recorded_at is not None else valid_from,
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
    for index in range(10):
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
    records=(
        {"id": "grant-depth-9", "verdict": "valid", "errors": []},
        {
            "id": "grant-depth-10",
            "verdict": "unverifiable",
            "errors": ["E_GRANT_UNRESOLVED"],
        },
    ),
    notes="A delegated-authorisation chain longer than the maximum depth is "
    "unverifiable. T8 counts parent links from the cited grant to the root, so "
    "grant-depth-10 (citing depth-9) has a nine-link chain and is unverifiable "
    "E_GRANT_UNRESOLVED, while grant-depth-9 (citing depth-8, eight links) is "
    "still valid. The chain is built from distinct records (no digest cycles, "
    "which are impossible by construction).",
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
        accuracy=(1, None, None),
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
        accuracy=(1, None, None),
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

# ---------------------------------------------------------------------------
# S1 revision: keyset trust, revocation merging, ZIP64/zip edges, --previous,
# the differential-fuzz Python defects, ambiguity rulings, future grants, grant
# chain depth, TSA accuracy and limitation identifiers (decisions 2026-11-11
# #2; rulings S1/S2/S5/S6/S7/S8/S9/S10/S11/S12/S14).
# ---------------------------------------------------------------------------


def _keyset_copy(name: str) -> bytes:
    """Bytes of one committed keyset declaration (from vectors/keys/keyset)."""
    return (recordlib.KEYS_DIR / "keyset" / name).read_bytes()


def _wrap_internal(files: dict[str, bytes]) -> dict[str, bytes]:
    return {"container/" + path: data for path, data in files.items()}


def _manifest_signature_tampered(files: dict[str, bytes]) -> dict[str, bytes]:
    """Replace the manifest signature value with a bit-flipped copy."""

    def mutator(sigfile: dict[str, Any]) -> dict[str, Any]:
        entry = dict(sigfile["signatures"][0])
        entry["value"] = keyutil.b64url_encode(
            _tampered_signature_value(entry["value"])
        )
        return {**sigfile, "signatures": [entry]}

    return mutate_sigfile(files, mutator)


# -- S5: ZIP64 and archive edges -------------------------------------------------


_ZIP_EOCD_SIG = 0x06054B50
_ZIP64_EOCD_SIG = 0x06064B50
_ZIP64_LOCATOR_SIG = 0x07064B50
_ARCHIVE_PREFIX = b"WEAVE-ZIP-PREFIX-0123456789abcd\x00"
assert len(_ARCHIVE_PREFIX) == 32


def _zip_entries(
    files: dict[str, bytes],
    extra: Sequence[tuple[str, bytes, int, int]] = (),
) -> bytes:
    """Deterministic STORED zip; *extra* adds ``(name, data, create_system, attr)``."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for path in sorted(files):
            info = zipfile.ZipInfo(path, date_time=(2026, 11, 10, 0, 0, 0))
            info.external_attr = 0o644 << 16
            info.create_system = 3
            archive.writestr(info, files[path])
        for name, data, create_system, external_attr in extra:
            info = zipfile.ZipInfo(name, date_time=(2026, 11, 10, 0, 0, 0))
            info.create_system = create_system
            info.external_attr = external_attr
            archive.writestr(info, data)
    return buffer.getvalue()


def _patch_zip64(archive: bytes) -> bytes:
    """Rewrite a small STORED archive in ZIP64 form, keeping the real entries.

    The end-of-central-directory record's 16-bit entry counts are replaced by
    ``0xFFFF`` and a ZIP64 EOCD record plus locator (carrying the real small
    counts and the unchanged central-directory offset) are inserted directly
    before it. A reader that follows the ZIP64 path accepts the archive; the
    archived bytes are unchanged.
    """
    if len(archive) < 22:
        raise SystemExit("zip64 patch: archive too short")
    eocd_offset = len(archive) - 22
    signature, = struct.unpack_from("<I", archive, eocd_offset)
    if signature != _ZIP_EOCD_SIG:
        raise SystemExit("zip64 patch: no end-of-central-directory record")
    disk, cd_disk, entries_disk, entries_total, cd_size, cd_offset, comment = (
        struct.unpack_from("<HHHHIIH", archive, eocd_offset + 4)
    )
    if comment != 0:
        raise SystemExit("zip64 patch: archive comment not expected")
    if entries_total != entries_disk:
        raise SystemExit("zip64 patch: single-disk archive expected")
    zip64_eocd = (
        struct.pack("<I", _ZIP64_EOCD_SIG)
        + struct.pack("<Q", 44)  # size of the remainder of this record
        + struct.pack("<H", 45)  # version made by (4.5)
        + struct.pack("<H", 45)  # version needed (4.5)
        + struct.pack("<I", 0)  # this disk
        + struct.pack("<I", 0)  # disk with the central directory
        + struct.pack("<Q", entries_disk)
        + struct.pack("<Q", entries_total)
        + struct.pack("<Q", cd_size)
        + struct.pack("<Q", cd_offset)
    )
    locator = struct.pack("<IIQI", _ZIP64_LOCATOR_SIG, 0, eocd_offset, 1)
    eocd = bytearray(archive[eocd_offset:])
    struct.pack_into("<HH", eocd, 8, 0xFFFF, 0xFFFF)
    return archive[:eocd_offset] + zip64_eocd + locator + bytes(eocd)


def _zip64_files() -> dict[str, bytes]:
    """A valid container zip in ZIP64 form, with a zero-data directory entry."""
    internal = recordlib.build_container(SIMPLE_RECORDS())
    archive = _zip_entries(
        internal,
        extra=(("readable/", b"", 3, (0o40755 << 16) | 0x10),),
    )
    return {"container.zip": _patch_zip64(archive)}


def _zip_with_prefix() -> dict[str, bytes]:
    internal = recordlib.build_container(SIMPLE_RECORDS())
    return {"container.zip": _ARCHIVE_PREFIX + _zip_entries(internal)}


def _zip_with_trailing_bytes() -> dict[str, bytes]:
    internal = recordlib.build_container(SIMPLE_RECORDS())
    return {
        "container.zip": _zip_entries(internal)
        + b"TRAILING-BYTES-0123456789abcdef\x00"[:32]
    }


def _zip_dos_directory_attribute_with_data() -> dict[str, bytes]:
    internal = recordlib.build_container(SIMPLE_RECORDS())
    archive = _zip_entries(
        internal,
        extra=(
            ("readable/dir-entry", b"directory-attribute-but-has-data", 0, 0x10),
        ),
    )
    return {"container.zip": archive}


declare(
    "container",
    "zip64-valid",
    "container",
    "container.zip",
    "valid",
    build=lambda case_dir: _zip64_files(),
    args=("--keys", "@keyset"),
    expected_container={
        "level_claimed": "L0",
        "level_verified": "L0",
        "record_count": 1,
    },
    limitations=("L_OFFLINE_CONTEXT",),
    notes="S5/§11.9: ZIP64 MUST be accepted. The fixture is the ordinary "
    "deterministic STORED container zip rewritten in ZIP64 form (EOCD entry "
    "counts 0xFFFF, ZIP64 EOCD record + locator carrying the real small counts, "
    "central directory unchanged) and additionally contains a zero-data "
    "directory entry, which is ignored.",
)

declare(
    "container",
    "zip-prefix",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_ZIP",),
    build=lambda case_dir: _zip_with_prefix(),
    notes="S5/§11.9: the archive MUST start at byte 0 with a local file header; "
    "32 deterministic bytes before the first local header are E_CONTAINER_ZIP "
    "(the conservative reading).",
)

declare(
    "container",
    "zip-trailing",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_ZIP",),
    build=lambda case_dir: _zip_with_trailing_bytes(),
    notes="S5/§11.9: the end-of-central-directory record MUST end exactly at the "
    "last input byte; 32 trailing bytes are E_CONTAINER_ZIP.",
)

declare(
    "container",
    "zip-dos-directory-attribute-with-data",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_ZIP",),
    build=lambda case_dir: _zip_dos_directory_attribute_with_data(),
    notes="S5/§11.9: an entry carrying the DOS directory attribute but non-zero "
    "data is not a directory entry and is E_CONTAINER_ZIP; zero-length "
    "directory entries are ignored instead.",
)

# -- S6: --previous with an absent chain ----------------------------------------


def _previous_without_chain_files() -> dict[str, bytes]:
    current = _wrap_internal(recordlib.build_container(SIMPLE_RECORDS()))
    previous = _wrap_internal(recordlib.build_container(SIMPLE_RECORDS()))
    result = dict(current)
    for path, data in previous.items():
        result["previous-container/" + path[len("container/") :]] = data
    return result


declare(
    "container",
    "previous-without-chain",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_CHAIN",),
    build=lambda case_dir: _previous_without_chain_files(),
    args=("--keys", "@keyset", "--previous", "previous-container"),
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    notes="S6/§11.5: the container has `previous_manifest: null`, but the caller "
    "supplies a previous container. A supplied --previous requires a non-null "
    "chain whose digest matches, so this is E_MANIFEST_CHAIN invalid (this is "
    "how a receiver detects a silently restarted chain). The previous-manifest "
    "chain is container step (10), after the record phase, so the container's "
    "record has already been processed and is reported valid; the invalid "
    "container error does not erase its verdict.",
)

# -- S7/S8: manifest signature continuation, listing multi-error, missing files --


def _manifest_signature_unverifiable_continues_files() -> dict[str, bytes]:
    files = _manifest_signature_tampered(recordlib.build_container(SIMPLE_RECORDS()))
    record_rel = record_path(files)
    original = files[record_rel]
    files[record_rel] = bytes([original[0] ^ 0x01]) + original[1:]
    return _wrap_internal(files)


def _record_extra_and_missing_files() -> dict[str, bytes]:
    files = recordlib.build_container(SIMPLE_RECORDS())
    record_rel = record_path(files)
    files["records/" + "ab" * 32 + ".json"] = files.pop(record_rel)
    return _wrap_internal(files)


def _manifest_sigfile_missing_files() -> dict[str, bytes]:
    return drop(
        _wrap_internal(recordlib.build_container(SIMPLE_RECORDS())),
        "container/signatures/manifest.sig.json",
    )


def _manifest_unknown_member_files() -> dict[str, bytes]:
    built = recordlib.build_container(SIMPLE_RECORDS())
    return _wrap_internal(
        recordlib.mutate_manifest(
            built, lambda manifest: {**manifest, "extra": 1}, resign_with=("human-1",)
        )
    )


def _attestation_unknown_member_files() -> dict[str, bytes]:
    return _wrap_internal(
        mutate_sigfile(
            recordlib.build_container(SIMPLE_RECORDS()),
            lambda sigfile: {**sigfile, "extra": 1},
        )
    )


declare(
    "container",
    "manifest-sig-unverifiable-continues",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_UNKNOWN", "E_MANIFEST_RECORD_DIGEST"),
    build=lambda case_dir: _manifest_signature_unverifiable_continues_files(),
    records=[],
    expected_container={"record_count": 1},
    notes="S7(2)/§14.5: an unverifiable manifest signature (here: no keyset, so "
    "the signing key is not available, E_KEY_UNKNOWN) MUST NOT stop record "
    "processing. The records-listing phase then finds a record file whose bytes "
    "do not match its digest (E_MANIFEST_RECORD_DIGEST), so both container "
    "errors are reported and no record verdicts are produced.",
)

declare(
    "container",
    "manifest-record-extra-and-missing",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_RECORD_EXTRA", "E_MANIFEST_RECORD_MISSING"),
    build=lambda case_dir: _record_extra_and_missing_files(),
    records=[],
    expected_container={"record_count": 1},
    notes="S8(1)/§11.6: the records-listing phase reports every independent "
    "defect it detects. The manifest lists a record file that was renamed, so "
    "that file is missing and the renamed file is extra (its name is "
    "well-formed but unlisted); the complete sorted set is reported.",
)

declare(
    "container",
    "manifest-unsigned-missing-sigfile",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_UNSIGNED",),
    build=lambda case_dir: _manifest_sigfile_missing_files(),
    records=[],
    notes="S8(2)/§11.1: the required attestation file signatures/manifest.sig.json "
    "is absent. The registry assigns the no-signatures condition to "
    "E_MANIFEST_UNSIGNED, not to a manifest schema error.",
)

declare(
    "container",
    "manifest-unknown-member",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_SCHEMA",),
    build=lambda case_dir: _manifest_unknown_member_files(),
    records=[],
    notes="F2/S8(6): the manifest is a closed object owned by §11.2; an unknown "
    "member is E_MANIFEST_SCHEMA (not the envelope-level E_ENV_UNKNOWN_FIELD).",
)

declare(
    "container",
    "attestation-unknown-member",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_SCHEMA",),
    build=lambda case_dir: _attestation_unknown_member_files(),
    records=[],
    notes="F2/S8(6): the attestation file is a closed object owned by §11.3; an "
    "unknown member is E_MANIFEST_SCHEMA.",
)

# -- S7(3): erasure crash regression and S7(4)/S8(3) declarations -----------------


def _erasure_missing_target() -> dict[str, Any]:
    attestation = erasure_record(erased_original())
    body = dict(attestation["body"])
    del body["erased"]
    mutated = {name: value for name, value in attestation.items() if name != "sigs"}
    mutated["body"] = body
    return recordlib.signed(mutated, "human-1")


declare(
    "erasure",
    "missing-target",
    "record",
    "record.json",
    "invalid",
    errors=("E_KIND_BODY_SCHEMA",),
    build=lambda case_dir: {"record.json": canonical(_erasure_missing_target())},
    args=ERASURE_ARGS,
    notes="S7(3): a weave.erasure body without the required `erased` reference is "
    "a kind body schema error (E_KIND_BODY_SCHEMA); the reference verifier used "
    "to crash on this input. The record is otherwise genuinely signed.",
)


def _declaration_without_public_key() -> dict[str, Any]:
    body = {
        "algorithm": "ed25519",
        "key": kid("human-2"),
        "key_type": "human",
    }
    record = recordlib.build_record(
        kind="weave.key.declared",
        id="key-declared-missing-public-key",
        actor=recordlib.actor("human-2"),
        body=body,
        stage="accepted",
        recorded_at=recordlib.T0,
        origin_instance=kid("human-2"),
    )
    return recordlib.signed(record, "human-2")


def _declared_unknown_alg_selfsig() -> dict[str, Any]:
    name = "agent-unknown-alg-selfsig"
    record = derived_declaration(
        record_id="key-declared-unknown-alg-selfsig",
        key_name=name,
        key_type="agent",
        owner="human-1",
        cosigners=("human-1",),
    )
    _private, _public, self_id = derived_key(name)
    for entry in record["sigs"]:
        if entry["key"] == self_id:
            entry["alg"] = "ed25518"
    return record


declare(
    "key-lifecycle",
    "declared-missing-public-key",
    "record",
    "record.json",
    "invalid",
    errors=("E_KEY_PUBLIC_KEY",),
    build=lambda case_dir: {
        "record.json": canonical(_declaration_without_public_key())
    },
    args=("--keys", "@keyset"),
    notes="S8(3): a weave.key.declared without body.public_key is invalid "
    "E_KEY_PUBLIC_KEY. The structure error precedes the trust judgement, and "
    "invalid is more conservative than unverifiable.",
)

declare(
    "key-lifecycle",
    "declared-unknown-alg-selfsig",
    "record",
    "record.json",
    "invalid",
    errors=("E_KEY_DECLARED_NOT_SELF_SIGNED",),
    build=lambda case_dir: {
        "record.json": canonical(_declared_unknown_alg_selfsig())
    },
    args=("--keys", "@keyset"),
    notes="S7(4): the declaration's self-signature entry uses an unknown "
    "algorithm and is ignored (§3.6), while the owner cosignature is a valid "
    "known-algorithm signature. A known-algorithm declared-key signature exists "
    "but not by the required signer, so the dedicated kind code "
    "E_KEY_DECLARED_NOT_SELF_SIGNED applies (not E_KEY_UNKNOWN).",
)

# -- S1: governing keyset class and window --------------------------------------


def _class_declaration(
    key_name: str, claimed_type: str, record_id: str, recorded_at: str
) -> dict[str, Any]:
    material = key(key_name)
    body = {
        "algorithm": "ed25519",
        "key": kid(key_name),
        "key_type": claimed_type,
        "public_key": material.public_b64url(),
    }
    record = recordlib.build_record(
        kind="weave.key.declared",
        id=record_id,
        actor={"type": claimed_type, "key": kid(key_name)},
        body=body,
        stage="accepted",
        recorded_at=recorded_at,
        origin_instance=kid(key_name),
    )
    return recordlib.signed(record, key_name)


def _human_act_note(
    key_name: str, record_id: str, recorded_at: str
) -> dict[str, Any]:
    record = recordlib.build_record(
        kind="example.note",
        id=record_id,
        actor={"type": "human", "key": kid(key_name)},
        body={"text": "human act"},
        stage="accepted",
        recorded_at=recorded_at,
        origin_instance=kid(key_name),
    )
    return recordlib.signed(record, key_name)


def _class_conflict_files(*, attack: bool) -> dict[str, bytes]:
    records: list[dict[str, Any]] = []
    if attack:
        records.append(
            _class_declaration(
                "agent-1",
                "human",
                "key-class-conflict-declaration",
                recordlib.EARLY,
            )
        )
    records.append(
        _human_act_note("agent-1", "key-class-conflict-note", recordlib.T4)
    )
    return _wrap_internal(recordlib.build_container(records))


def _windowed_human2_keyset() -> dict[str, bytes]:
    windowed = recordlib.key_declaration(
        "human-2",
        record_id="key-declared-human-2-windowed",
        valid_until=recordlib.T2,
    )
    return {
        "keyset/key-declared-human-1.json": _keyset_copy("key-declared-human-1.json"),
        "keyset/key-declared-human-2.json": canonical(windowed),
    }


def _window_attack_files() -> dict[str, bytes]:
    redeclared = recordlib.key_declaration(
        "human-2",
        record_id="key-declared-human-2-window-attack",
        recorded_at=recordlib.EARLY,
        valid_from=recordlib.EARLY,
        valid_until=recordlib.LATE,
    )
    note = _human_act_note("human-2", "key-window-attack-note", recordlib.T4)
    files = _windowed_human2_keyset()
    files.update(_wrap_internal(recordlib.build_container([redeclared, note])))
    return files


def _window_control_files() -> dict[str, bytes]:
    redeclared = recordlib.key_declaration(
        "human-2",
        record_id="key-declared-human-2-redeclaration-control",
        recorded_at=recordlib.EARLY,
    )
    note = _human_act_note("human-2", "key-window-control-note", recordlib.T4)
    return _wrap_internal(recordlib.build_container([redeclared, note]))


declare(
    "key-lifecycle",
    "redeclare-class-conflict",
    "container",
    "container",
    "invalid",
    errors=("E_ACTOR_KEY_TYPE_MISMATCH", "E_KEY_CLASS_CONFLICT"),
    build=lambda case_dir: _class_conflict_files(attack=True),
    args=("--keys", "@keyset"),
    records=(
        {
            "id": "key-class-conflict-declaration",
            "verdict": "invalid",
            "errors": ["E_KEY_CLASS_CONFLICT"],
        },
        {
            "id": "key-class-conflict-note",
            "verdict": "invalid",
            "errors": ["E_ACTOR_KEY_TYPE_MISMATCH"],
        },
    ),
    notes="S1/§5.3: `agent-1` is trusted from the local keyset as an agent, so a "
    "backdated self-signed re-declaration claiming `human` cannot reclassify it: "
    "the declaration is invalid E_KEY_CLASS_CONFLICT and the human-act record "
    "signed by that key stays E_ACTOR_KEY_TYPE_MISMATCH.",
)

declare(
    "key-lifecycle",
    "redeclare-class-conflict-control",
    "container",
    "container",
    "invalid",
    errors=("E_ACTOR_KEY_TYPE_MISMATCH",),
    build=lambda case_dir: _class_conflict_files(attack=False),
    args=("--keys", "@keyset"),
    records=(
        {
            "id": "key-class-conflict-note",
            "verdict": "invalid",
            "errors": ["E_ACTOR_KEY_TYPE_MISMATCH"],
        },
    ),
    notes="S1 control group: the same container without the malicious "
    "re-declaration has only the human-act mismatch, proving that the "
    "E_KEY_CLASS_CONFLICT vector's declaration is what drives the attack.",
)

declare(
    "key-lifecycle",
    "redeclare-window-attack",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_EXPIRED",),
    build=lambda case_dir: _window_attack_files(),
    args=("--keys", "keyset"),
    records=(
        {
            "id": "key-declared-human-2-window-attack",
            "verdict": "valid",
            "errors": [],
        },
        {
            "id": "key-window-attack-note",
            "verdict": "invalid",
            "errors": ["E_KEY_EXPIRED"],
        },
    ),
    notes="S1/§5.3: the local keyset declares human-2 with valid_until=T2. A "
    "backdated container re-declaration widening the window is same-class and "
    "therefore valid, but it MUST NOT override the keyset's class or window: "
    "the note signed by human-2 at T4 is E_KEY_EXPIRED.",
)

declare(
    "key-lifecycle",
    "redeclare-window-control",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _window_control_files(),
    args=("--keys", "@keyset"),
    records=(
        {
            "id": "key-declared-human-2-redeclaration-control",
            "verdict": "valid",
            "errors": [],
        },
        {"id": "key-window-control-note", "verdict": "valid", "errors": []},
    ),
    notes="S1 control: a same-class re-declaration that does not change the "
    "window is valid and leaves the trusted key usable, so the container is "
    "valid.",
)

# -- S2: order-independent revocations and keyset revocations --------------------


def _key_multi_revocation_files(order: str) -> dict[str, bytes]:
    note = _human_act_note("human-2", "key-multi-revocation-note", recordlib.T4)
    early = recordlib.key_revocation(
        "human-2",
        reason="retired",
        effective_at=recordlib.T2,
        recorded_at=recordlib.T3,
        record_id="key-revoked-human-2-early",
    )
    early_digest = recordlib.record_digest(early)
    for index in range(256):
        late = recordlib.key_revocation(
            "human-2",
            reason="retired",
            effective_at=recordlib.T6,
            recorded_at=recordlib.T7,
            record_id="key-revoked-human-2-late-%d" % index,
        )
        early_first = early_digest < recordlib.record_digest(late)
        if early_first == (order == "early-first"):
            return _wrap_internal(
                recordlib.build_container([note, early, late])
            )
    raise SystemExit("no deterministic revocation record id gives the requested order")


def _keyset_revocation_files() -> dict[str, bytes]:
    revocation = recordlib.key_revocation(
        "human-2",
        reason="retired",
        effective_at=recordlib.T2,
        recorded_at=recordlib.T3,
        record_id="key-revoked-human-2-keyset",
        signer_name="human-1",
    )
    note = _human_act_note("human-2", "key-keyset-revocation-note", recordlib.T4)
    files = {
        "keyset/key-declared-human-1.json": _keyset_copy(
            "key-declared-human-1.json"
        ),
        "keyset/key-declared-human-2.json": _keyset_copy(
            "key-declared-human-2.json"
        ),
        "keyset/key-revoked-human-2-keyset.json": canonical(revocation),
    }
    files.update(_wrap_internal(recordlib.build_container([note])))
    return files


declare(
    "key-lifecycle",
    "multi-revocation-order-a",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_REVOKED",),
    build=lambda case_dir: _key_multi_revocation_files("early-first"),
    args=("--keys", "@keyset"),
    records=(
        {
            "id": "key-multi-revocation-note",
            "verdict": "invalid",
            "errors": ["E_KEY_REVOKED"],
        },
    ),
    notes="S2/§9.4: two retired revocations of human-2 with different "
    "effective_at (T2 applies to the note at T4, T6 does not). This case has the "
    "revocation set in one numeric-digest order; the conclusion must be the "
    "same regardless of order.",
)

declare(
    "key-lifecycle",
    "multi-revocation-order-b",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_REVOKED",),
    build=lambda case_dir: _key_multi_revocation_files("late-first"),
    args=("--keys", "@keyset"),
    records=(
        {
            "id": "key-multi-revocation-note",
            "verdict": "invalid",
            "errors": ["E_KEY_REVOKED"],
        },
    ),
    notes="S2/§9.4: the same revocation set as multi-revocation-order-a, with "
    "record bytes chosen so the numeric digests (and therefore the manifest "
    "order) are reversed; the note is E_KEY_REVOKED in both orders because every "
    "effective revocation in the context counts.",
)

declare(
    "key-lifecycle",
    "keyset-revocation",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_REVOKED",),
    build=lambda case_dir: _keyset_revocation_files(),
    args=("--keys", "keyset"),
    records=(
        {
            "id": "key-keyset-revocation-note",
            "verdict": "invalid",
            "errors": ["E_KEY_REVOKED"],
        },
    ),
    notes="S2/§14.1: revocations supplied by the local keyset take part in key "
    "state exactly like container records. human-2 is revoked (retired, "
    "effective T2) in the keyset, so the note signed at T4 is E_KEY_REVOKED.",
)


_COMPROMISE_EARLY = "2026-10-31T00:00:00.000Z"
_COMPROMISE_LATE = "2026-11-02T00:00:00.000Z"


def _compromise_multi_revocation_files(order: str) -> dict[str, bytes]:
    note = record_signed_by(
        "key-compromised",
        "key-compromise-earliest-note",
        recorded_at=recordlib.T4,
        stage="accepted",
    )
    early = recordlib.key_revocation(
        "key-compromised",
        reason="key-compromise",
        effective_at=_COMPROMISE_EARLY,
        recorded_at=recordlib.T8,
        record_id="key-revoked-compromise-earliest",
    )
    early_digest = recordlib.record_digest(early)
    for index in range(256):
        late = recordlib.key_revocation(
            "key-compromised",
            reason="key-compromise",
            effective_at=_COMPROMISE_LATE,
            recorded_at=recordlib.T8,
            record_id="key-revoked-compromise-later-%d" % index,
        )
        early_first = early_digest < recordlib.record_digest(late)
        if early_first == (order == "early-first"):

            def builder(imprint: bytes):
                return [
                    ("signatures/timestamp-1.tsr", _crafted_tsr(imprint), None)
                ]

            files = _build_timestamped_container(
                [note, early, late], builder, level="L2"
            )
            return {**wrap(files), TSA_CERT_NAME: TSA_CERT()}
    raise SystemExit("no deterministic revocation record id gives the requested order")


declare(
    "key-lifecycle",
    "compromise-earliest-revocation-a",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_COMPROMISED",),
    build=lambda case_dir: _compromise_multi_revocation_files("early-first"),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    records=(
        {
            "id": "key-compromise-earliest-note",
            "verdict": "invalid",
            "errors": ["E_KEY_COMPROMISED"],
        },
    ),
    expected_container={
        "level_claimed": "L2",
        "level_verified": "L0",
        "anchor_verified": True,
    },
    notes="S2/§9.4: with two key-compromise revocations the rescue bound uses the "
    "earliest effective_at (2026-10-31). The trusted receipt's genTime "
    "(2026-11-01) is not before it, so the signature is not rescued: "
    "E_KEY_COMPROMISED. The revocation set is in one numeric-digest order.",
)

declare(
    "key-lifecycle",
    "compromise-earliest-revocation-b",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_COMPROMISED",),
    build=lambda case_dir: _compromise_multi_revocation_files("late-first"),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    records=(
        {
            "id": "key-compromise-earliest-note",
            "verdict": "invalid",
            "errors": ["E_KEY_COMPROMISED"],
        },
    ),
    expected_container={
        "level_claimed": "L2",
        "level_verified": "L0",
        "anchor_verified": True,
    },
    notes="S2/§9.4: same compromise revocation set as "
    "compromise-earliest-revocation-a in the reversed numeric-digest order; the "
    "earliest effective_at governs, so the conclusion does not depend on order.",
)

# -- S9: grants issued for future effect ---------------------------------------


def _preissued_grant() -> dict[str, Any]:
    return root_grant(
        record_id="grant-preissued-root",
        kinds=("example.note",),
        actions=("propose", "accept"),
        valid_from=recordlib.T1,
        valid_until=recordlib.T9,
        recorded_at=recordlib.T0,
    )


def _preissued_grant_covered_files() -> dict[str, bytes]:
    grant = _preissued_grant()
    note = agent_action(
        grant,
        record_id="grant-preissued-covered-note",
        recorded_at=recordlib.T2,
        stage="accepted",
    )
    return _wrap_internal(recordlib.build_container([grant, note]))


def _preissued_grant_before_valid_from_files() -> dict[str, bytes]:
    grant = _preissued_grant()
    note = agent_action(
        grant,
        record_id="grant-preissued-early-note",
        recorded_at=recordlib.T0,
        stage="accepted",
    )
    return _wrap_internal(recordlib.build_container([grant, note]))


declare(
    "grant",
    "root-valid-from-after-recorded",
    "record",
    "record.json",
    "valid",
    build=lambda case_dir: {
        "record.json": canonical(_preissued_grant())
    },
    args=GRANT_ARGS,
    limitations=("L_OFFLINE_CONTEXT",),
    notes="S9/§5.5.2: a grant may be issued for future effect. The grant record's "
    "own validity window is not compared with its own recorded_at, so this "
    "pre-issued root grant (recorded_at T0, valid_from T1) is valid.",
)

declare(
    "grant",
    "pre-issued-grant-covers-record",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _preissued_grant_covered_files(),
    args=GRANT_ARGS,
    records=(
        {"id": "grant-preissued-root", "verdict": "valid", "errors": []},
        {"id": "grant-preissued-covered-note", "verdict": "valid", "errors": []},
    ),
    notes="S9/§5.4: the grant covers other records at each covered record's own "
    "recorded_at; the agent note at T2 is inside the grant's T1..T9 window.",
)

declare(
    "grant",
    "record-before-grant-valid-from",
    "container",
    "container",
    "unverifiable",
    errors=("E_GRANT_EXPIRED",),
    build=lambda case_dir: _preissued_grant_before_valid_from_files(),
    args=GRANT_ARGS,
    records=(
        {
            "id": "grant-preissued-early-note",
            "verdict": "unverifiable",
            "errors": ["E_GRANT_EXPIRED"],
        },
    ),
    notes="S9/§5.4: a record covered by the pre-issued grant is judged at its own "
    "recorded_at; before valid_from the grant is not yet valid, so the note is "
    "unverifiable E_GRANT_EXPIRED.",
)

# -- S10: invalid revocations do not revoke; chain depth boundary ----------------


def _invalid_grant_revocation_ineffective_files() -> dict[str, bytes]:
    grant = root_grant(
        record_id="grant-invalid-revocation-target",
        kinds=("example.note",),
        actions=("propose", "accept"),
        valid_from=recordlib.T0,
        valid_until=recordlib.T9,
    )
    revocation = grant_revocation(
        grant,
        record_id="grant-invalid-revocation-record",
        signer="org-1",
        effective_at=recordlib.T2,
    )
    note = agent_action(
        grant,
        record_id="grant-invalid-revocation-note",
        recorded_at=recordlib.T4,
        stage="accepted",
    )
    return _wrap_internal(recordlib.build_container([grant, revocation, note]))


def _grant_chain_records(
    links: int,
) -> tuple[list[dict[str, Any]], dict[str, Any], str]:
    root = root_grant(
        record_id="grant-depth-root",
        kinds=("weave.grant", "example.note"),
        actions=("grant", "propose", "accept"),
        valid_from=recordlib.T0,
        valid_until=recordlib.T9,
        transferable=True,
    )
    records = [root]
    parent = root
    grantee = "agent-2"
    final_grantee = grantee
    for index in range(links):
        final_grantee = grantee
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
    return records, parent, final_grantee


def _grant_chain_files(links: int, *, note_id: str) -> dict[str, bytes]:
    records, deepest, final_grantee = _grant_chain_records(links)
    note = agent_action(
        deepest,
        record_id=note_id,
        key_name=final_grantee,
        recorded_at=recordlib.T4,
        stage="accepted",
    )
    return _wrap_internal(recordlib.build_container(records + [note]))


declare(
    "grant",
    "invalid-revocation-ineffective",
    "container",
    "container",
    "invalid",
    errors=("E_GRANT_REVOKE_SIGNER",),
    build=lambda case_dir: _invalid_grant_revocation_ineffective_files(),
    args=GRANT_ARGS,
    records=(
        {
            "id": "grant-invalid-revocation-target",
            "verdict": "valid",
            "errors": [],
        },
        {
            "id": "grant-invalid-revocation-record",
            "verdict": "invalid",
            "errors": ["E_GRANT_REVOKE_SIGNER"],
        },
        {
            "id": "grant-invalid-revocation-note",
            "verdict": "valid",
            "errors": [],
        },
    ),
    notes="S10(a)/§5.5.4: a grant revocation signed by an unauthorised key is "
    "invalid and does not revoke the target grant, so the agent note recorded "
    "after its effective_at stays valid; the container is invalid because of the "
    "bad revocation record itself.",
)

declare(
    "grant",
    "chain-depth-8-valid",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _grant_chain_files(8, note_id="grant-depth-8-note"),
    args=GRANT_ARGS,
    notes="S10/§5.5.2 step 7: the depth bound is an inclusive endpoint. Eight "
    "parent links (nine grants) from the deepest grant to the root are supported, "
    "so the chain and the record citing its deepest grant are valid.",
)

declare(
    "grant",
    "chain-depth-9-links",
    "container",
    "container",
    "unverifiable",
    errors=("E_GRANT_UNRESOLVED",),
    build=lambda case_dir: _grant_chain_files(9, note_id="grant-depth-9-note"),
    args=GRANT_ARGS,
    records=(
        {
            "id": "grant-depth-9",
            "verdict": "valid",
            "errors": [],
        },
        {
            "id": "grant-depth-9-note",
            "verdict": "unverifiable",
            "errors": ["E_GRANT_UNRESOLVED"],
        },
    ),
    notes="S10/T8/§5.5.2 step 7: the bound counts parent links from the cited "
    "grant to the root. The depth-9 grant record itself cites the depth-8 grant "
    "(eight links) and is valid; the note citing the depth-9 grant has nine "
    "links, so it is unverifiable E_GRANT_UNRESOLVED and the container is "
    "unverifiable.",
)

# -- S11/S12: TSA accuracy bound and limitation identifiers ---------------------






declare(
    "integrity-levels",
    "l2-without-trust-limitations",
    "container",
    "container",
    "unverifiable",
    errors=("E_TS_UNTRUSTED",),
    build=lambda case_dir: _crafted_l2_files(case_dir, trust_name=None),
    args=LEVEL_ARGS,
    expected_container={"level_claimed": "L2", "anchor_verified": False},
    limitations=(
        "L_CHAIN_CLAIM_UNVERIFIED",
        "L_OFFLINE_CONTEXT",
        "L_TSA_TRUST_UNVERIFIED",
    ),
    notes="S12/§14.9: the report lists limitation identifiers only. Timestamps "
    "are present but no matching anchor was supplied, so the container is "
    "unverifiable (E_TS_UNTRUSTED) and the report carries L_TSA_TRUST_UNVERIFIED "
    "plus the always-present L_OFFLINE_CONTEXT.",
)


def _context_trusted_tofu_files() -> dict[str, bytes]:
    private, public, key_id = derived_key("context-trusted-human")
    body = {
        "algorithm": "ed25519",
        "key": key_id,
        "key_type": "human",
        "public_key": keyutil.b64url_encode(public),
    }
    declaration = recordlib.build_record(
        kind="weave.key.declared",
        id="key-declared-context-trusted",
        actor={"type": "human", "key": key_id},
        body=body,
        stage="accepted",
        recorded_at=recordlib.T0,
        origin_instance=key_id,
    )
    signatures = [
        _derived_signature(private, key_id, declaration),
        recordlib.sig_entry(declaration, "human-1"),
    ]
    signatures.sort(key=lambda entry: entry["key"])
    declaration["sigs"] = signatures
    consent_body = {
        "purpose": "vector test consent",
        "scope": ["test-scope"],
        "valid_from": recordlib.T0,
        "valid_until": None,
        "data_subject": None,
        "terms": None,
    }
    consent = recordlib.build_record(
        kind="weave.consent.granted",
        id="consent-context-trusted",
        actor={"type": "human", "key": key_id},
        body=consent_body,
        stage="accepted",
        recorded_at=recordlib.T0,
        origin_instance=key_id,
    )
    consent["sigs"] = [_derived_signature(private, key_id, consent)]
    return _wrap_internal(recordlib.build_container([declaration, consent]))


declare(
    "key-lifecycle",
    "context-trusted-tofu-limitations",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _context_trusted_tofu_files(),
    args=("--keys", "@keyset"),
    notices=("N_KEY_TOFU",),
    limitations=("L_KEY_TRUST_TOFU", "L_OFFLINE_CONTEXT"),
    records=(
        {"id": "key-declared-context-trusted", "verdict": "valid", "errors": []},
        {"id": "consent-context-trusted", "verdict": "valid", "errors": []},
    ),
    notes="S12/§14.9: a fresh human key is declared in the container and trusted "
    "through the keyset root's cosignature. The signature material came from a "
    "context declaration, so the report carries N_KEY_TOFU and the limitation "
    "identifiers L_KEY_TRUST_TOFU and L_OFFLINE_CONTEXT.",
)

# -- S8(11): check-order precedence (crypto before lifecycle, file before renewal) --


def _compromise_sig_invalid_precedence_files() -> dict[str, bytes]:
    revocation = recordlib.key_revocation(
        "key-compromised",
        reason="key-compromise",
        effective_at=recordlib.T2,
        recorded_at=recordlib.T3,
        record_id="key-revoked-compromise-precedence",
    )
    note = record_signed_by(
        "key-compromised",
        "key-compromise-precedence-note",
        recorded_at=recordlib.T4,
        stage="accepted",
    )
    entries = [dict(entry) for entry in note["sigs"]]
    raw = keyutil.b64url_decode(entries[0]["value"], expected_len=64)
    entries[0]["value"] = keyutil.b64url_encode(bytes([raw[0] ^ 0x01]) + raw[1:])
    note["sigs"] = entries
    return _wrap_internal(recordlib.build_container([revocation, note]))


declare(
    "key-lifecycle",
    "compromise-sig-invalid-precedence",
    "container",
    "container",
    "invalid",
    errors=("E_SIG_INVALID",),
    build=lambda case_dir: _compromise_sig_invalid_precedence_files(),
    args=("--keys", "@keyset"),
    records=(
        {
            "id": "key-compromise-precedence-note",
            "verdict": "invalid",
            "errors": ["E_SIG_INVALID"],
        },
    ),
    notes="S8(11)/§14.5: the Ed25519 cryptographic steps run before the "
    "lifecycle checks. This record is signed by a key-compromise-revoked key "
    "AND its signature value is tampered, so the first failing check is the "
    "cryptographic one: E_SIG_INVALID, not E_KEY_COMPROMISED.",
)


def _l2_ts_file_before_renewal_files() -> dict[str, bytes]:
    def builder(imprint: bytes):
        first = _crafted_tsr(imprint)
        second = _crafted_tsr(_sha256_bytes(first + imprint))
        return [
            ("signatures/timestamp-1.tsr", first, None),
            (
                "signatures/timestamp-2.tsr",
                second,
                "signatures/timestamp-1.tsr",
            ),
        ]

    files = _build_timestamped_container(SIMPLE_RECORDS(), builder, level="L2")

    def mutator(sigfile: dict[str, Any]) -> dict[str, Any]:
        timestamps = [dict(entry) for entry in sigfile["timestamps"]]
        timestamps[0]["digest"] = "sha256:" + "99" * 32
        timestamps[1]["renews"] = "signatures/timestamp-3.tsr"
        return {**sigfile, "timestamps": timestamps}

    files = mutate_sigfile(files, mutator)
    return {**wrap(files), TSA_CERT_NAME: TSA_CERT()}


declare(
    "integrity-levels",
    "l2-ts-file-before-renewal",
    "container",
    "container",
    "invalid",
    errors=("E_TS_FILE",),
    build=lambda case_dir: _l2_ts_file_before_renewal_files(),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container={
        "level_claimed": "L2",
        "level_verified": "L0",
        "anchor_verified": False,
    },
    notes="S8(11)/§12.2: a listed receipt whose bytes do not match its listed "
    "digest (E_TS_FILE) is reported before the broken renewal chain "
    "(E_TS_RENEWAL): the listed checks run in order and report the first "
    "failing check. The receipt file itself is intact; only its listed digest "
    "is wrong.",
)


# ---------------------------------------------------------------------------
# S1-FIX1 T6: zip structure rules (decision 2026-11-11 #5 T6; spec §11.9)
# ---------------------------------------------------------------------------

_ZIP_LOCAL_SIG = 0x04034B50
_ZIP_CENTRAL_SIG = 0x02014B50
_ZIP_EOCD_SIG = 0x06054B50
_ZIP_DESCRIPTOR_SIG = 0x08074B50
_ZIP_UTF8_FLAG = 0x0800


def _zip_raw(
    entries: Sequence[tuple[str, bytes, int, int]],
    *,
    data_descriptor: bool = False,
    gaps: dict[int, int] | None = None,
    gap_before_central: int = 0,
    local_names: dict[int, bytes] | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Deterministic STORED zip writer over raw entries.

    ``entries`` is a sequence of ``(name, data, create_system, external_attr)``.
    Returns ``(archive_bytes, meta)``; *meta* carries the local-header and EOCD
    offsets so individual structural fields can be patched deterministically.
    ``gaps`` maps an entry index to zero bytes inserted before its local header;
    ``local_names`` overrides the local-header filename bytes only (the central
    directory keeps the real name).
    """
    gaps = gaps or {}
    local_names = local_names or {}
    output = bytearray()
    central = bytearray()
    local_meta: list[dict[str, Any]] = []
    for index, (name, data, create_system, external_attr) in enumerate(entries):
        output += b"\x00" * gaps.get(index, 0)
        name_bytes = name.encode("utf-8")
        header_name = local_names.get(index, name_bytes)
        local_offset = len(output)
        crc = zlib.crc32(data) & 0xFFFFFFFF
        if data_descriptor:
            flags = _ZIP_UTF8_FLAG | 0x0008
            local_crc = local_comp = local_uncomp = 0
        else:
            flags = _ZIP_UTF8_FLAG
            local_crc, local_comp, local_uncomp = crc, len(data), len(data)
        output += struct.pack(
            "<IHHHHHIIIHH",
            _ZIP_LOCAL_SIG,
            20,
            flags,
            0,  # compression method: stored
            0,
            0,
            local_crc,
            local_comp,
            local_uncomp,
            len(header_name),
            0,
        )
        output += header_name
        output += data
        if data_descriptor:
            output += struct.pack(
                "<IIII", _ZIP_DESCRIPTOR_SIG, crc, len(data), len(data)
            )
        central += struct.pack(
            "<IHHHHHHIIIHHHHHII",
            _ZIP_CENTRAL_SIG,
            (create_system << 8) | 20,
            20,
            flags,
            0,
            0,
            0,
            crc,
            len(data),
            len(data),
            len(name_bytes),
            0,
            0,
            0,
            0,
            external_attr,
            local_offset,
        )
        central += name_bytes
        local_meta.append(
            {
                "name": name,
                "offset": local_offset,
                "name_offset": local_offset + 30,
                "data_offset": local_offset + 30 + len(header_name),
            }
        )
    central_offset = len(output) + gap_before_central
    output += b"\x00" * gap_before_central
    output += central
    eocd_offset = len(output)
    output += struct.pack(
        "<IHHHHIIH",
        _ZIP_EOCD_SIG,
        0,
        0,
        len(entries),
        len(entries),
        len(central),
        central_offset,
        0,
    )
    meta = {
        "locals": local_meta,
        "central_offset": central_offset,
        "eocd_offset": eocd_offset,
        "entry_count": len(entries),
    }
    return bytes(output), meta


def _zip_patch(data: bytes, offset: int, fmt: str, *values: Any) -> bytes:
    result = bytearray(data)
    struct.pack_into(fmt, result, offset, *values)
    return bytes(result)


_STANDARD_ATTR = 0o100644 << 16
_SYMLINK_ATTR = 0o120777 << 16


def _zip_standard_entries(
    extra: Sequence[tuple[str, bytes, int, int]] = (),
) -> list[tuple[str, bytes, int, int]]:
    """Sorted standard container entries (raw zip entries) plus *extra*."""
    internal = recordlib.build_container(SIMPLE_RECORDS())
    entries = [(name, internal[name], 3, _STANDARD_ATTR) for name in sorted(internal)]
    return entries + list(extra)


def _zip_standard(
    **kwargs: Any,
) -> tuple[bytes, dict[str, Any]]:
    extra = kwargs.pop("extra", ())
    return _zip_raw(_zip_standard_entries(extra), **kwargs)


def _zip_local_field(
    archive: bytes, meta: dict[str, Any], field_name: str
) -> tuple[int, str]:
    positions = {
        "method": (8, "<H"),
        "crc": (14, "<I"),
        "compressed": (18, "<I"),
        "uncompressed": (22, "<I"),
    }
    relative, fmt = positions[field_name]
    return meta["locals"][0]["offset"] + relative, fmt


def _zip_local_mismatch(field_name: str, *, value: Any) -> dict[str, bytes]:
    archive, meta = _zip_standard()
    offset, fmt = _zip_local_field(archive, meta, field_name)
    if value is None:
        value = struct.unpack_from(fmt, archive, offset)[0] + 1
    return {"container.zip": _zip_patch(archive, offset, fmt, value)}


def _zip_local_name_mismatch() -> dict[str, bytes]:
    archive, _meta = _zip_standard(local_names={0: b"manifest.jsoN"})
    return {"container.zip": archive}


def _zip_gap_between_entries() -> dict[str, bytes]:
    archive, _meta = _zip_standard(gaps={1: 8})
    return {"container.zip": archive}


def _zip_gap_before_central() -> dict[str, bytes]:
    archive, _meta = _zip_standard(gap_before_central=8)
    return {"container.zip": archive}


def _zip_eocd_count(delta: int) -> dict[str, bytes]:
    archive, meta = _zip_standard()
    count = meta["entry_count"] + delta
    patched = _zip_patch(archive, meta["eocd_offset"] + 8, "<H", count)
    return {"container.zip": _zip_patch(patched, meta["eocd_offset"] + 10, "<H", count)}


def _zip64_eocd(archive: bytes, meta: dict[str, Any]) -> tuple[bytes, int]:
    """Patch the standard archive into ZIP64 form; return (zip64_bytes, eocd_offset)."""
    eocd_offset = meta["eocd_offset"]
    return _patch_zip64(archive), eocd_offset


def _zip64_eocd_count_mismatch() -> dict[str, bytes]:
    archive, meta = _zip_standard()
    patched, eocd_offset = _zip64_eocd(archive, meta)
    count = meta["entry_count"] + 1
    # ZIP64 EOCD record: sig(4) size(8) version(2+2) disk(4+4) counts(8+8)...
    patched = _zip_patch(patched, eocd_offset + 24, "<Q", count)
    return {"container.zip": _zip_patch(patched, eocd_offset + 32, "<Q", count)}


def _zip64_locator_offset_corrupt() -> dict[str, bytes]:
    archive, meta = _zip_standard()
    patched, eocd_offset = _zip64_eocd(archive, meta)
    # locator follows the 56-byte ZIP64 EOCD record: sig(4) disk(4) offset(8)...
    locator = eocd_offset + 56
    return {
        "container.zip": _zip_patch(patched, locator + 8, "<Q", eocd_offset + 1)
    }


def _zip_entry_data_overlap() -> dict[str, bytes]:
    """Entry 0's declared data range overlaps the next entry's local header."""
    archive, meta = _zip_standard()
    first = meta["locals"][0]
    actual_compressed = struct.unpack_from("<I", archive, first["offset"] + 18)[0]
    local_offset = first["offset"] + 18
    central_offset = meta["central_offset"] + 20
    patched = _zip_patch(archive, local_offset, "<I", actual_compressed + 8)
    return {
        "container.zip": _zip_patch(
            patched, central_offset, "<I", actual_compressed + 8
        )
    }


def _zip_readable_extra(name: str, data: bytes = b"x", attr: int = _STANDARD_ATTR):
    return _zip_standard(extra=((name, data, 3, attr),))[0]


def _zip_readable_dotdot() -> dict[str, bytes]:
    return {"container.zip": _zip_readable_extra("readable/../escape")}


def _zip_readable_absolute() -> dict[str, bytes]:
    return {"container.zip": _zip_readable_extra("/readable/x")}


def _zip_readable_symlink() -> dict[str, bytes]:
    return {"container.zip": _zip_readable_extra("readable/link", attr=_SYMLINK_ATTR)}


def _zip_readable_duplicate() -> dict[str, bytes]:
    archive, _meta = _zip_standard(
        extra=(
            ("readable/x", b"a", 3, _STANDARD_ATTR),
            ("readable/x", b"b", 3, _STANDARD_ATTR),
        )
    )
    return {"container.zip": archive}


def _zip_data_descriptor_valid() -> dict[str, bytes]:
    archive, _meta = _zip_standard(data_descriptor=True)
    return {"container.zip": archive}


declare(
    "container",
    "zip-local-central-uncompressed-size-mismatch",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_ZIP",),
    build=lambda case_dir: _zip_local_mismatch("uncompressed", value=None),
    records=[],
    notes="T6/§11.9 rule 1: the local file header and the central directory "
    "must agree on the uncompressed size. The local header claims one byte "
    "more than the central directory, so the archive is E_CONTAINER_ZIP.",
)

declare(
    "container",
    "zip-local-central-crc-mismatch",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_ZIP",),
    build=lambda case_dir: _zip_local_mismatch("crc", value=None),
    records=[],
    notes="T6/§11.9 rule 1: the local header CRC-32 must equal the central "
    "directory CRC-32; a mismatch is E_CONTAINER_ZIP.",
)

declare(
    "container",
    "zip-local-central-method-mismatch",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_ZIP",),
    build=lambda case_dir: _zip_local_mismatch("method", value=8),
    records=[],
    notes="T6/§11.9 rule 1: the local header compression method (deflate) "
    "contradicts the central directory (stored); the archive is "
    "E_CONTAINER_ZIP before any decompression.",
)

declare(
    "container",
    "zip-local-central-name-mismatch",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_ZIP",),
    build=lambda case_dir: _zip_local_name_mismatch(),
    records=[],
    notes="T6/§11.9 rule 1: the raw filename bytes must agree between the "
    "local header and the central directory; a one-byte name difference is "
    "E_CONTAINER_ZIP.",
)

declare(
    "container",
    "zip-entry-data-overlap",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_ZIP",),
    build=lambda case_dir: _zip_entry_data_overlap(),
    records=[],
    notes="T6/§11.9 rule 2: every byte must have exactly one home. The first "
    "entry's declared compressed size is extended by 8 bytes in both the local "
    "header and the central directory, so its data range overlaps the next "
    "entry's local header. The field pair agrees (rule 1) but the layout "
    "overlaps, so the archive is E_CONTAINER_ZIP.",
)

declare(
    "container",
    "zip-gap-between-entries",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_ZIP",),
    build=lambda case_dir: _zip_gap_between_entries(),
    records=[],
    notes="T6/§11.9 rule 2: every byte must have a home. Eight zero bytes "
    "between the first entry's data and the next local header are a gap, so "
    "the archive is E_CONTAINER_ZIP (all central-directory offsets are "
    "correct; only the byte layout is wrong).",
)

declare(
    "container",
    "zip-gap-before-central-directory",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_ZIP",),
    build=lambda case_dir: _zip_gap_before_central(),
    records=[],
    notes="T6/§11.9 rule 2: the central directory must begin immediately "
    "after the last entry. Eight zero bytes before it are a gap, so the "
    "archive is E_CONTAINER_ZIP.",
)

declare(
    "container",
    "zip-eocd-count-plus-three",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_ZIP",),
    build=lambda case_dir: _zip_eocd_count(3),
    records=[],
    notes="T6/§11.9 rule 3: the end-of-central-directory entry count must "
    "equal the actual parsed entry count; +3 is E_CONTAINER_ZIP.",
)

declare(
    "container",
    "zip-eocd-count-minus-one",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_ZIP",),
    build=lambda case_dir: _zip_eocd_count(-1),
    records=[],
    notes="T6/§11.9 rule 3: an EOCD count one lower than the actual entry "
    "count would make a counting parser miss an entry; it is "
    "E_CONTAINER_ZIP.",
)

declare(
    "container",
    "zip64-eocd-count-mismatch",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_ZIP",),
    build=lambda case_dir: _zip64_eocd_count_mismatch(),
    records=[],
    notes="T6/§11.9 rule 3: for a ZIP64 archive the ZIP64 EOCD entry count "
    "must equal the actual parsed count; +1 is E_CONTAINER_ZIP.",
)

declare(
    "container",
    "zip64-locator-corrupt-offset",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_ZIP",),
    build=lambda case_dir: _zip64_locator_offset_corrupt(),
    records=[],
    notes="T6/§11.9 rule 3: the ZIP64 EOCD locator's offset must point at "
    "the ZIP64 EOCD record; a corrupted offset is E_CONTAINER_ZIP. This pins "
    "the version-independent (3.12/3.14) parsing required by T6.",
)

declare(
    "container",
    "readable-dotdot-entry",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_ENTRY",),
    build=lambda case_dir: _zip_readable_dotdot(),
    records=[],
    notes="T6/§11.9 rule 4: a readable/ entry still goes through the path "
    "safety checks; a `..` segment is E_CONTAINER_ENTRY even though "
    "readable/ is never decompressed.",
)

declare(
    "container",
    "readable-absolute-path-entry",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_ENTRY",),
    build=lambda case_dir: _zip_readable_absolute(),
    records=[],
    notes="T6/§11.9 rule 4: an absolute path under readable/ is "
    "E_CONTAINER_ENTRY (path safety applies to every entry).",
)

declare(
    "container",
    "readable-symlink-entry",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_ENTRY",),
    build=lambda case_dir: _zip_readable_symlink(),
    records=[],
    notes="T6/§11.9 rule 4: a readable/ entry with the Unix symlink file type "
    "is E_CONTAINER_ENTRY; skipping decompression and CRC checking does not "
    "skip the entry-type check.",
)

declare(
    "container",
    "readable-duplicate-name",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_ENTRY",),
    build=lambda case_dir: _zip_readable_duplicate(),
    records=[],
    notes="T6/§11.9 rule 4: duplicate entry names are E_CONTAINER_ENTRY even "
    "under readable/.",
)

declare(
    "container",
    "zip-data-descriptor-valid",
    "container",
    "container.zip",
    "valid",
    build=lambda case_dir: _zip_data_descriptor_valid(),
    args=("--keys", "@keyset"),
    expected_container={
        "level_claimed": "L0",
        "level_verified": "L0",
        "record_count": 1,
    },
    limitations=("L_OFFLINE_CONTEXT",),
    notes="T6/§11.9 rule 1 positive: a streaming archive whose entries set "
    "general-purpose flag bit 3 (data descriptor) and carry zero local "
    "sizes. The descriptor values equal the central directory, so the archive "
    "is accepted.",
)

# ---------------------------------------------------------------------------
# S1-FIX1 T13: rotated key material is checked before the signature equation
# ---------------------------------------------------------------------------


def _rotation_malformed_old_public_key() -> dict[str, bytes]:
    record = key_rotation(record_id="key-rotated-old-public-key-malformed")
    body = dict(record["body"])
    body["old_public_key"] = keyutil.b64url_encode(b"short")
    mutated = {name: value for name, value in record.items() if name != "sigs"}
    mutated["body"] = body
    return {"record.json": canonical(recordlib.signed(mutated, ["key-old", "key-new"]))}


declare(
    "key-lifecycle",
    "rotation-old-public-key-malformed",
    "record",
    "record.json",
    "invalid",
    errors=("E_KEY_ROTATION_KEYS",),
    build=lambda case_dir: _rotation_malformed_old_public_key(),
    args=("--keys", "@keyset"),
    notes="T13/§9.2: the declared old_public_key is not a strict unpadded "
    "base64url of exactly 32 bytes. Structural key-material validation runs "
    "before the signature equation, so the record is invalid "
    "E_KEY_ROTATION_KEYS (not E_SIG_NONCANONICAL_A).",
)

# ---------------------------------------------------------------------------
# S1-FIX1 T2: retired and compromise revocations are independent
# (decision 2026-11-11 #5 T2; spec §9.4)
# ---------------------------------------------------------------------------

# The crafted receipt genTime is 2026-11-01T00:00:00.000Z (fixed test TSA).
# A compromise effective time strictly after it is rescuable by a trusted
# receipt; a retired effective time at or before the note's recorded_at bites.
_MIXED_COMPROMISE_EARLY = "2026-11-01T00:00:01.000Z"
_MIXED_COMPROMISE_LATE = recordlib.T8
_MIXED_RETIRED_EARLY = recordlib.T2
_MIXED_RETIRED_LATE = recordlib.T9


def _mixed_revocation_files(scenario: str, *, trusted: bool) -> dict[str, bytes]:
    """L2 container with a retired and a compromise revocation of one key.

    *scenario* selects the effective-time relation; the record is always signed
    by the compromised key at T4 and the receipt is the fixed test-TSA token.
    """
    retired_effective: str
    compromise_effective: str
    if scenario == "retired-then-compromise":
        retired_effective = _MIXED_RETIRED_EARLY
        compromise_effective = _MIXED_COMPROMISE_LATE
    elif scenario == "compromise-then-retired":
        retired_effective = _MIXED_RETIRED_LATE
        compromise_effective = _MIXED_COMPROMISE_EARLY
    elif scenario == "rescue-but-retired":
        retired_effective = _MIXED_RETIRED_EARLY
        compromise_effective = _MIXED_COMPROMISE_EARLY
    else:  # pragma: no cover - defensive
        raise SystemExit("unknown mixed-revocation scenario %r" % (scenario,))
    records = [
        recordlib.key_revocation(
            "key-compromised",
            reason="retired",
            effective_at=retired_effective,
            recorded_at=retired_effective,
            record_id="mixed-revocation-retired",
        ),
        recordlib.key_revocation(
            "key-compromised",
            reason="key-compromise",
            effective_at=compromise_effective,
            recorded_at=compromise_effective,
            record_id="mixed-revocation-compromise",
        ),
        record_signed_by(
            "key-compromised",
            "mixed-revocation-note",
            recorded_at=recordlib.T4,
            stage="accepted",
        ),
    ]

    def builder(imprint: bytes) -> list[tuple[str, bytes, str | None]]:
        return [("signatures/timestamp-1.tsr", _crafted_tsr(imprint), None)]

    files = _build_timestamped_container(records, builder, level="L2")
    result = wrap(files)
    if trusted:
        result[TSA_CERT_NAME] = TSA_CERT()
    return result


_MIXED_CASES: tuple[tuple[str, bool, str, tuple[str, ...], bool], ...] = (
    # (scenario, trusted, container verdict, aggregated errors, anchor_verified)
    ("retired-then-compromise", True, "invalid", ("E_KEY_REVOKED",), True),
    (
        "retired-then-compromise",
        False,
        "invalid",
        ("E_KEY_REVOKED", "E_TS_UNTRUSTED"),
        False,
    ),
    ("compromise-then-retired", True, "valid", (), True),
    ("compromise-then-retired", False, "unverifiable", ("E_TS_UNTRUSTED",), False),
    ("rescue-but-retired", True, "invalid", ("E_KEY_REVOKED",), True),
    (
        "rescue-but-retired",
        False,
        "invalid",
        ("E_KEY_REVOKED", "E_TS_UNTRUSTED"),
        False,
    ),
)

for _scenario, _trusted, _verdict, _errors, _anchor in _MIXED_CASES:
    _name = "mixed-revocation-%s%s" % (
        _scenario,
        "" if _trusted else "-no-anchor",
    )
    if _verdict == "invalid":
        _note_verdict = "invalid"
        _note_errors = ("E_KEY_REVOKED",) if _scenario != "compromise-then-retired" else ()
    elif _verdict == "unverifiable":
        _note_verdict = "unverifiable"
        _note_errors = ("E_TS_UNTRUSTED",)
    else:
        _note_verdict = "valid"
        _note_errors = ()
    if _scenario == "retired-then-compromise":
        _notes = (
            "T2/§9.4: two revocations of the same key are evaluated independently. "
            "The retired revocation (effective T2) bites the T4 signature and can "
            "never be timestamp-rescued; the compromise revocation does not "
            "override it. The retired family produces invalid E_KEY_REVOKED; "
            "without an anchor the container also reports the untrusted-receipt "
            "condition E_TS_UNTRUSTED."
        )
    elif _scenario == "compromise-then-retired":
        _notes = (
            "T2/§9.4: the retired revocation (effective T9) does not bite the T4 "
            "signature, so only the compromise family applies; the trusted receipt "
            "predates the compromise effective time and rescues the signature. "
            "Without an anchor the outcome is unverifiable E_TS_UNTRUSTED."
        )
    else:
        _notes = (
            "T2/§9.4: the compromise family alone would rescue the signature with "
            "the trusted receipt, but the retired family also bites the T4 "
            "signature; the stricter invalid E_KEY_REVOKED wins in both variants."
        )
    declare(
        "key-lifecycle",
        _name,
        "container",
        "container",
        _verdict,
        errors=_errors,
        build=lambda case_dir, s=_scenario, t=_trusted: _mixed_revocation_files(
            s, trusted=t
        ),
        args=(
            ("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME)
            if _trusted
            else ("--keys", "@keyset")
        ),
        expected_container={
            "level_claimed": "L2",
            "level_verified": "L0",
            "anchor_verified": _anchor,
            "record_count": 3,
        },
        records=(
            {"id": "mixed-revocation-retired", "verdict": "valid", "errors": []},
            {"id": "mixed-revocation-compromise", "verdict": "valid", "errors": []},
            {
                "id": "mixed-revocation-note",
                "verdict": _note_verdict,
                "errors": list(_note_errors),
            },
        ),
        notes=_notes,
    )


# ---------------------------------------------------------------------------
# S1-FIX1 T3: TSA accuracy range vs unusable accuracy (decision 2026-11-11 #5)
# ---------------------------------------------------------------------------


def _accuracy_l2_files(
    case_dir: Path,
    accuracy: tuple[int | None, int | None, int | None] | None,
    *,
    tamper_signature: bool = False,
) -> dict[str, bytes]:
    """L2 container whose single crafted receipt carries *accuracy*."""
    return _crafted_l2_files(
        case_dir,
        tsr_factory=lambda imprint: _crafted_tsr(
            imprint,
            accuracy=accuracy,
            tamper_signature=tamper_signature,
        ),
    )


_ACCURACY_RECORD = {"id": "key-declared-human-1", "verdict": "valid", "errors": []}


declare(
    "integrity-levels",
    "l2-accuracy-millis-out-of-range",
    "container",
    "container",
    "invalid",
    errors=("E_TS_SCHEMA",),
    build=lambda case_dir: _accuracy_l2_files(case_dir, (None, 1000, None)),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container={
        "level_claimed": "L2",
        "level_verified": "L0",
        "anchor_verified": False,
    },
    records=(_ACCURACY_RECORD,),
    notes="T3(1)/§12.2 check 13: a present accuracy.milliseconds outside 1-999 "
    "is a malformed token component, not an unusable-but-valid receipt: "
    "E_TS_SCHEMA, container invalid.",
)

declare(
    "integrity-levels",
    "l2-accuracy-micros-zero-explicit",
    "container",
    "container",
    "invalid",
    errors=("E_TS_SCHEMA",),
    build=lambda case_dir: _accuracy_l2_files(case_dir, (None, None, 0)),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container={
        "level_claimed": "L2",
        "level_verified": "L0",
        "anchor_verified": False,
    },
    records=(_ACCURACY_RECORD,),
    notes="T3(1)/§12.2 check 13: an explicitly written accuracy.microseconds = 0 "
    "is a present component outside 1-999 (an absent component would count as "
    "0, but a written 0 is malformed): E_TS_SCHEMA, container invalid.",
)

declare(
    "integrity-levels",
    "l2-accuracy-over-limit",
    "container",
    "container",
    "unverifiable",
    errors=("E_TS_UNTRUSTED",),
    build=lambda case_dir: _accuracy_l2_files(case_dir, (86_401, None, None)),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container={
        "level_claimed": "L2",
        "level_verified": "L0",
        "anchor_verified": False,
        "timestamps": [{"state": "present-unverified"}],
    },
    records=(_ACCURACY_RECORD,),
    limitations=(
        "L_CHAIN_CLAIM_UNVERIFIED",
        "L_OFFLINE_CONTEXT",
        "L_TSA_TRUST_UNVERIFIED",
    ),
    notes="T3(2)/§12.2 check 13: an accuracy above MAX_TS_ACCURACY is not a "
    "format error. The receipt cannot support the L2 claim, so the container is "
    "unverifiable E_TS_UNTRUSTED (never invalid); the record itself is still "
    "processed and valid. (Revision 3 reported this input as invalid "
    "E_TS_SCHEMA; S1-FIX1 changes the conclusion.)",
)

declare(
    "integrity-levels",
    "l2-accuracy-overflow",
    "container",
    "container",
    "unverifiable",
    errors=("E_TS_UNTRUSTED",),
    build=lambda case_dir: _accuracy_l2_files(case_dir, (10**13, None, None)),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container={
        "level_claimed": "L2",
        "level_verified": "L0",
        "anchor_verified": False,
        "timestamps": [{"state": "present-unverified"}],
    },
    records=(_ACCURACY_RECORD,),
    limitations=(
        "L_CHAIN_CLAIM_UNVERIFIED",
        "L_OFFLINE_CONTEXT",
        "L_TSA_TRUST_UNVERIFIED",
    ),
    notes="T3(2)/§12.2 check 13: converting accuracy.seconds = 10^13 to "
    "microseconds overflows; the token is well formed but the accuracy is "
    "unusable, so the container is unverifiable E_TS_UNTRUSTED without "
    "crashing or claiming L2. (Revision 3 reported invalid E_TS_SCHEMA.)",
)

declare(
    "integrity-levels",
    "l2-accuracy-over-limit-tampered-cms",
    "container",
    "container",
    "invalid",
    errors=("E_TS_CMS",),
    build=lambda case_dir: _accuracy_l2_files(
        case_dir, (86_401, None, None), tamper_signature=True
    ),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container={
        "level_claimed": "L2",
        "level_verified": "L0",
        "anchor_verified": False,
    },
    records=(_ACCURACY_RECORD,),
    notes="T3(3)/§12.2: the checks run in numbered order and the first failing "
    "check decides. The CMS signature is tampered AND the accuracy is over the "
    "limit; CMS checks (rows 5-12) come before accuracy (row 13), so the "
    "container is invalid E_TS_CMS, not E_TS_SCHEMA/E_TS_UNTRUSTED.",
)

declare(
    "integrity-levels",
    "l2-submillisecond-rescue",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _submillisecond_rescue_files(),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container={
        "level_claimed": "L2",
        "level_verified": "L0",
        "anchor_verified": True,
        "record_count": 2,
    },
    records=(
        {"id": "submillisecond-compromise-revocation", "verdict": "valid", "errors": []},
        {"id": "submillisecond-rescued-note", "verdict": "valid", "errors": []},
    ),
    notes="T3(4)/§9.4: the rescue comparison truncates genTime to integer "
    "milliseconds first: genTime = T-0.5 ms becomes T-1 ms in the comparison, "
    "and 500 us of accuracy keeps genTime_ms*1000 + accuracy_us < T_ms*1000. "
    "The compromised-key signature is rescued, so the record and container are "
    "valid even though the raw genTime is only half a millisecond before T.",
)


def _submillisecond_rescue_files() -> dict[str, bytes]:
    """L2 container rescued by a sub-millisecond-precision receipt."""
    effective_at = "2026-11-01T00:00:00.001Z"
    records = [
        recordlib.key_revocation(
            "key-compromised",
            reason="key-compromise",
            effective_at=effective_at,
            recorded_at="2026-11-01T00:00:01.000Z",
            record_id="submillisecond-compromise-revocation",
        ),
        record_signed_by(
            "key-compromised",
            "submillisecond-rescued-note",
            recorded_at=recordlib.T4,
            stage="accepted",
        ),
    ]

    def builder(imprint: bytes) -> list[tuple[str, bytes, str | None]]:
        return [
            (
                "signatures/timestamp-1.tsr",
                _crafted_tsr(
                    imprint,
                    gen_time=datetime.datetime(
                        2026, 11, 1, 0, 0, 0, 500,
                        tzinfo=datetime.timezone.utc,
                    ),
                    accuracy=(None, None, 500),
                ),
                None,
            )
        ]

    files = _build_timestamped_container(records, builder, level="L2")
    return {**wrap(files), TSA_CERT_NAME: TSA_CERT()}

# ---------------------------------------------------------------------------
# S1-FIX1 T4: equal recorded_at declarations are ordered by record digest
# (decision 2026-11-11 #5 T4; spec §5.3/§9.1)
# ---------------------------------------------------------------------------

_TIE_KEY_NAME = "equal-time-declaration-key"


def _equal_time_declaration(
    private: Any,
    public: bytes,
    key_id: str,
    key_type: str,
    record_id: str,
) -> dict[str, Any]:
    body = {
        "algorithm": "ed25519",
        "key": key_id,
        "key_type": key_type,
        "public_key": keyutil.b64url_encode(public),
    }
    record = recordlib.build_record(
        kind="weave.key.declared",
        id=record_id,
        actor={"type": key_type, "key": key_id},
        body=body,
        stage="accepted",
        recorded_at=recordlib.T1,
        origin_instance=key_id,
    )
    signatures = [
        _derived_signature(private, key_id, record),
        recordlib.sig_entry(record, "human-1"),
    ]
    signatures.sort(key=lambda entry: entry["key"])
    record["sigs"] = signatures
    return record


_TIE_CACHE: dict[bool, tuple[dict[str, Any], dict[str, Any], Any, str]] = {}


def _equal_time_pair(
    *, human_first: bool
) -> tuple[dict[str, Any], dict[str, Any], Any, str]:
    """Human and organization declarations for one fresh key at the same time.

    The human declaration's record id is fixed; organization ids are searched so
    that the numeric record-digest order matches *human_first*. Both twins are
    fully deterministic.
    """
    cached = _TIE_CACHE.get(human_first)
    if cached is not None:
        return cached
    private, public, key_id = derived_key(_TIE_KEY_NAME)
    human = _equal_time_declaration(
        private, public, key_id, "human", "key-declared-equal-time-human"
    )
    human_digest = recordlib.record_digest(human)
    for index in range(512):
        organization = _equal_time_declaration(
            private,
            public,
            key_id,
            "organization",
            "key-declared-equal-time-organization-%d" % index,
        )
        organization_digest = recordlib.record_digest(organization)
        matches = (
            human_digest < organization_digest
            if human_first
            else organization_digest < human_digest
        )
        if matches:
            _TIE_CACHE[human_first] = (human, organization, private, key_id)
            return _TIE_CACHE[human_first]
    raise SystemExit("no deterministic organization id gives the requested order")


def _equal_time_note(private: Any, key_id: str) -> dict[str, Any]:
    record = recordlib.build_record(
        kind="example.note",
        id="key-declared-equal-time-note",
        actor={"type": "human", "key": key_id},
        body={"text": "human act by the tied key"},
        stage="accepted",
        recorded_at=recordlib.T4,
        origin_instance=key_id,
    )
    record["sigs"] = [_derived_signature(private, key_id, record)]
    return record


def _equal_time_files(*, human_first: bool) -> dict[str, bytes]:
    human, organization, private, key_id = _equal_time_pair(human_first=human_first)
    return _wrap_internal(
        recordlib.build_container(
            [human, organization, _equal_time_note(private, key_id)]
        )
    )


_HUMAN_FIRST_IDS = _equal_time_pair(human_first=True)[:2]
_ORGANIZATION_FIRST_IDS = _equal_time_pair(human_first=False)[:2]

declare(
    "key-lifecycle",
    "equal-time-declaration-digest-order-human-first",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_CLASS_CONFLICT",),
    build=lambda case_dir: _equal_time_files(human_first=True),
    args=("--keys", "@keyset"),
    records=(
        {
            "id": _HUMAN_FIRST_IDS[0]["id"],
            "verdict": "valid",
            "errors": [],
        },
        {
            "id": _HUMAN_FIRST_IDS[1]["id"],
            "verdict": "invalid",
            "errors": ["E_KEY_CLASS_CONFLICT"],
        },
        {"id": "key-declared-equal-time-note", "verdict": "valid", "errors": []},
    ),
    notes="T4(3)/§5.3: two context declarations for the same key id share a "
    "recorded_at, so the deterministic order is the record digest (smallest "
    "first). This twin has the human declaration's digest first: it governs the "
    "key's class and is valid, the organization declaration is invalid "
    "E_KEY_CLASS_CONFLICT, and the human-act note is valid.",
)

declare(
    "key-lifecycle",
    "equal-time-declaration-digest-order-organization-first",
    "container",
    "container",
    "invalid",
    errors=("E_ACTOR_KEY_TYPE_MISMATCH", "E_KEY_CLASS_CONFLICT"),
    build=lambda case_dir: _equal_time_files(human_first=False),
    args=("--keys", "@keyset"),
    records=(
        {
            "id": _ORGANIZATION_FIRST_IDS[0]["id"],
            "verdict": "invalid",
            "errors": ["E_KEY_CLASS_CONFLICT"],
        },
        {
            "id": _ORGANIZATION_FIRST_IDS[1]["id"],
            "verdict": "valid",
            "errors": [],
        },
        {
            "id": "key-declared-equal-time-note",
            "verdict": "invalid",
            "errors": ["E_ACTOR_KEY_TYPE_MISMATCH"],
        },
    ),
    notes="T4(3)/§5.3: the mirrored twin of the human-first case, where the "
    "organization declaration's digest is the smaller one. The organization "
    "class governs, the human declaration is invalid E_KEY_CLASS_CONFLICT, and "
    "the human-act note is invalid E_ACTOR_KEY_TYPE_MISMATCH. Together the two "
    "twins pin the digest tie-break independently of input order.",
)

# ---------------------------------------------------------------------------
# S1-FIX1 T9: a revocation signed by an already-revoked key is ineffective
# (decision 2026-11-11 #5 T9; spec §9.5)
# ---------------------------------------------------------------------------


def _revocation_by_retired_signer_files() -> dict[str, bytes]:
    retired_human_1 = recordlib.key_revocation(
        "human-1",
        reason="retired",
        effective_at=recordlib.T1,
        recorded_at=recordlib.T1,
        signer_name="human-2",
        record_id="key-revoked-human-1-retired",
    )
    ineffective = recordlib.key_revocation(
        "human-2",
        reason="retired",
        effective_at=recordlib.T3,
        recorded_at=recordlib.T3,
        signer_name="human-1",
        record_id="key-revoked-human-2-by-retired-signer",
    )
    note = recordlib.build_record(
        kind="example.note",
        id="revocation-target-note",
        actor=recordlib.actor("human-2"),
        body={"text": "the target key is not revoked"},
        stage="accepted",
        recorded_at=recordlib.T4,
    )
    note = recordlib.signed(note, "human-2")
    return _wrap_internal(
        recordlib.build_container([retired_human_1, ineffective, note])
    )


declare(
    "key-lifecycle",
    "revocation-signed-by-retired-key",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_REVOKED",),
    build=lambda case_dir: _revocation_by_retired_signer_files(),
    args=("--keys", "@keyset"),
    records=(
        {"id": "key-revoked-human-1-retired", "verdict": "valid", "errors": []},
        {
            "id": "key-revoked-human-2-by-retired-signer",
            "verdict": "invalid",
            "errors": ["E_KEY_REVOKED"],
        },
        {"id": "revocation-target-note", "verdict": "valid", "errors": []},
    ),
    notes="T9/§9.5: the revocation of human-2 is signed by human-1, but human-1 "
    "was already retired at T1. A revocation record must itself be valid to take "
    "effect, so this one is invalid E_KEY_REVOKED and revokes nothing; human-2's "
    "note stays valid and the container is invalid because of the bad "
    "revocation record.",
)


_MUTUAL_REVOCATION_CACHE: dict[bool, dict[str, Any]] = {}


def _mutual_revocation_records(*, human1_earlier: bool) -> dict[str, Any]:
    """The two mutual revocation records in the requested digest order."""
    cached = _MUTUAL_REVOCATION_CACHE.get(human1_earlier)
    if cached is not None:
        return cached
    by_human_1 = recordlib.key_revocation(
        "human-2",
        reason="retired",
        effective_at=recordlib.T2,
        recorded_at=recordlib.T2,
        signer_name="human-1",
        record_id="mutual-revocation-by-human-1",
    )
    by_human_1_digest = recordlib.record_digest(by_human_1)
    other = None
    for index in range(256):
        candidate = recordlib.key_revocation(
            "human-1",
            reason="retired",
            effective_at=recordlib.T2,
            recorded_at=recordlib.T2,
            signer_name="human-2",
            record_id="mutual-revocation-by-human-2-%d" % index,
        )
        candidate_first = recordlib.record_digest(candidate) < by_human_1_digest
        if candidate_first == (not human1_earlier):
            other = candidate
            break
    if other is None:
        raise SystemExit("no deterministic id gives the requested mutual order")
    cached = {"by_human_1": by_human_1, "by_human_2": other}
    _MUTUAL_REVOCATION_CACHE[human1_earlier] = cached
    return cached


def _mutual_revocation_files(*, human1_earlier: bool) -> dict[str, bytes]:
    records = _mutual_revocation_records(human1_earlier=human1_earlier)
    by_human_1 = records["by_human_1"]
    other = records["by_human_2"]
    note_human_1 = recordlib.build_record(
        kind="example.note",
        id="mutual-revocation-note-human-1",
        actor=recordlib.actor("human-1"),
        body={"text": "signed by human-1"},
        stage="accepted",
        recorded_at=recordlib.T4,
    )
    note_human_1 = recordlib.signed(note_human_1, "human-1")
    note_human_2 = recordlib.build_record(
        kind="example.note",
        id="mutual-revocation-note-human-2",
        actor=recordlib.actor("human-2"),
        body={"text": "signed by human-2"},
        stage="accepted",
        recorded_at=recordlib.T4,
    )
    note_human_2 = recordlib.signed(note_human_2, "human-2")
    return _wrap_internal(
        recordlib.build_container(
            [by_human_1, other, note_human_1, note_human_2]
        )
    )


declare(
    "key-lifecycle",
    "mutual-revocation-order-a",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_REVOKED",),
    build=lambda case_dir: _mutual_revocation_files(human1_earlier=True),
    args=("--keys", "@keyset"),
    records=(
        {
            "id": "mutual-revocation-by-human-1",
            "verdict": "valid",
            "errors": [],
        },
        {
            "id": _mutual_revocation_records(human1_earlier=True)["by_human_2"]["id"],
            "verdict": "invalid",
            "errors": ["E_KEY_REVOKED"],
        },
        {"id": "mutual-revocation-note-human-1", "verdict": "valid", "errors": []},
        {
            "id": "mutual-revocation-note-human-2",
            "verdict": "invalid",
            "errors": ["E_KEY_REVOKED"],
        },
    ),
    notes="T9/§9.5: two revocations with the same recorded_at are ordered by "
    "record digest. The human-1-signed revocation (smaller digest) is valid and "
    "revokes human-2; the later human-2-signed revocation is then signed by an "
    "already-revoked key, is invalid E_KEY_REVOKED and revokes nothing.",
)

declare(
    "key-lifecycle",
    "mutual-revocation-order-b",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_REVOKED",),
    build=lambda case_dir: _mutual_revocation_files(human1_earlier=False),
    args=("--keys", "@keyset"),
    records=(
        {
            "id": "mutual-revocation-by-human-1",
            "verdict": "invalid",
            "errors": ["E_KEY_REVOKED"],
        },
        {
            "id": _mutual_revocation_records(human1_earlier=False)["by_human_2"]["id"],
            "verdict": "valid",
            "errors": [],
        },
        {
            "id": "mutual-revocation-note-human-1",
            "verdict": "invalid",
            "errors": ["E_KEY_REVOKED"],
        },
        {"id": "mutual-revocation-note-human-2", "verdict": "valid", "errors": []},
    ),
    notes="T9/§9.5: the mirrored mutual-revocation twin. The human-2-signed "
    "revocation has the smaller digest, is valid and revokes human-1; the later "
    "human-1-signed revocation is invalid E_KEY_REVOKED. Together the twins pin "
    "the deterministic (recorded_at, digest) evaluation order.",
)

# ---------------------------------------------------------------------------
# S1-FIX1 T10: one TOFU criterion, including the manifest signature
# (decision 2026-11-11 #5 T10; spec §14.6/§14.9)
# ---------------------------------------------------------------------------


def _manifest_context_trusted_tofu_files() -> dict[str, bytes]:
    """J1-like container: the manifest is signed by a context-declared key."""
    private, public, key_id = derived_key("j1-manifest-device-key")
    body = {
        "algorithm": "ed25519",
        "key": key_id,
        "key_type": "device",
        "owner": recordlib.kid("human-1"),
        "public_key": keyutil.b64url_encode(public),
    }
    declaration = recordlib.build_record(
        kind="weave.key.declared",
        id="key-declared-j1-manifest-device",
        actor={"type": "device", "key": key_id},
        body=body,
        stage="accepted",
        recorded_at=recordlib.T0,
        origin_instance=key_id,
    )
    signatures = [
        _derived_signature(private, key_id, declaration),
        recordlib.sig_entry(declaration, "human-1"),
    ]
    signatures.sort(key=lambda entry: entry["key"])
    declaration["sigs"] = signatures
    files = recordlib.build_container([declaration], manifest_signers=("human-1",))
    manifest_digest_value = recordlib.manifest_digest(files["manifest.json"])
    signature = private.sign(
        recordlib.sig_message_for_manifest(manifest_digest_value)
    )
    files["signatures/manifest.sig.json"] = canonical(
        {
            "digest": manifest_digest_value,
            "format": FORMAT,
            "signatures": [
                {
                    "alg": "ed25519",
                    "key": key_id,
                    "value": keyutil.b64url_encode(signature),
                }
            ],
            "timestamps": [],
        }
    )
    return _wrap_internal(files)


declare(
    "container",
    "manifest-context-trusted-tofu",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _manifest_context_trusted_tofu_files(),
    args=("--keys", "@keyset"),
    notices_absent=("N_KEY_TOFU",),
    limitations=("L_KEY_TRUST_TOFU", "L_OFFLINE_CONTEXT"),
    records=(
        {"id": "key-declared-j1-manifest-device", "verdict": "valid", "errors": []},
    ),
    notes="T10/§14.9: the manifest is signed by a device key declared in the "
    "container and trusted through the keyset root's cosignature (the J1 shape). "
    "The manifest signature check used context-trusted material, so the report "
    "carries L_KEY_TRUST_TOFU; no record signature used context material, so no "
    "record carries N_KEY_TOFU.",
)

# ---------------------------------------------------------------------------
# S1-FIX1 T12: readable/ and previous-manifest notices after early failures
# (decision 2026-11-11 #5 T12)
# ---------------------------------------------------------------------------


def _readable_after_manifest_failure_files() -> dict[str, bytes]:
    files = recordlib.build_container(SIMPLE_RECORDS())
    files["readable/notes.txt"] = b"human readable view\n"
    manifest = parse(files["manifest.json"])
    manifest["extra"] = 1
    files["manifest.json"] = canonical(manifest)
    return _wrap_internal(files)


declare(
    "container",
    "readable-present-after-manifest-failure",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_SCHEMA",),
    build=lambda case_dir: _readable_after_manifest_failure_files(),
    args=("--keys", "@keyset"),
    notices=("N_READABLE_PRESENT",),
    records=[],
    notes="T12/§11.8: entry enumeration saw readable/ before the manifest "
    "structure check failed, so N_READABLE_PRESENT MUST still be reported even "
    "though the container is invalid E_MANIFEST_SCHEMA.",
)


def _previous_unverified_after_early_failure_files() -> dict[str, bytes]:
    files = _chain_container(Path("."), mismatch=False)
    manifest_path = "container/manifest.json"
    manifest = parse(files[manifest_path])
    manifest["extra"] = 1
    files[manifest_path] = canonical(manifest)
    return files


declare(
    "container",
    "previous-unverified-after-early-failure",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_SCHEMA",),
    build=lambda case_dir: _previous_unverified_after_early_failure_files(),
    args=("--keys", "@keyset"),
    notices=("N_PREVIOUS_SIG_UNVERIFIED",),
    limitations=("L_OFFLINE_CONTEXT", "L_PREVIOUS_SIG_UNVERIFIED"),
    records=[],
    notes="T12/§14.6: previous_manifest is non-null and the previous manifest's "
    "signature is not re-verified, so N_PREVIOUS_SIG_UNVERIFIED and "
    "L_PREVIOUS_SIG_UNVERIFIED are reported even though the manifest structure "
    "check later fails (E_MANIFEST_SCHEMA).",
)

# ---------------------------------------------------------------------------
# S1-FIX1 T16: oversize record file report shape (decision 2026-11-11 #5 T16)
# ---------------------------------------------------------------------------

_T16_RECORD_LIMIT = 1_048_576
_T16_OVERSIZE = _T16_RECORD_LIMIT + 1


def _t16_manifest_identity() -> dict[str, Any]:
    internal = recordlib.build_container([recordlib.key_declaration("human-1")])
    manifest_bytes = internal["manifest.json"]
    return {
        "sha256": recordlib.manifest_digest(manifest_bytes),
        "size": len(manifest_bytes),
    }


def _oversize_record_file_files() -> dict[str, bytes]:
    internal = recordlib.build_container([recordlib.key_declaration("human-1")])
    path = record_path(internal)
    original = internal[path]
    internal[path] = original + b" " * (_T16_OVERSIZE - len(original))
    return _wrap_internal(internal)


declare(
    "container",
    "oversize-record-file",
    "container",
    "container",
    "invalid",
    errors=("E_JSON_SIZE",),
    build=lambda case_dir: _oversize_record_file_files(),
    args=("--keys", "@keyset"),
    expected_input=_t16_manifest_identity(),
    expected_container={
        "created_at": recordlib.T0,
        "manifest_digest": _t16_manifest_identity()["sha256"],
        "level_claimed": "L0",
        "level_verified": "L0",
        "anchor_verified": False,
        "chain": {"status": "absent"},
        "previous_manifest_digest": None,
        "record_count": 1,
        "timestamps": [],
    },
    records=[],
    notes="T16/§14.6: a records/ file exceeds MAX_RECORD_BYTES (1,048,576) but "
    "the manifest itself is readable and structurally valid, so the failure is "
    "found at the records-listing stage: container invalid E_JSON_SIZE, "
    "records [], manifest-derived fields filled (record_count 1, "
    "manifest_digest set) and input identifies the raw manifest bytes (the "
    "two-tier rule). The oversize file is 1,048,577 bytes.",
)

# ---------------------------------------------------------------------------
# S1-FIX1 T17: previous non-zip path and backdated grants
# (decision 2026-11-11 #5 T17; review A L9/L4)
# ---------------------------------------------------------------------------


def _previous_non_zip_file_files() -> dict[str, bytes]:
    files = _wrap_internal(recordlib.build_container(SIMPLE_RECORDS()))
    files["previous.txt"] = b"this path exists and is readable but is not a zip\n"
    return files


declare(
    "container",
    "previous-non-zip-file",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_CHAIN",),
    build=lambda case_dir: _previous_non_zip_file_files(),
    args=("--keys", "@keyset", "--previous", "previous.txt"),
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    notes="T17/A-L9 + S1-FIX2 U1 + S1-FIX3 V7/L1/§11.5: a --previous path that "
    "exists and is readable but is not a usable container (here: a plain text "
    "file) is E_MANIFEST_CHAIN invalid. The previous-manifest chain is "
    "container step (10), after the record phase, so the container's record is "
    "processed and valid. This branch is pinned by the ablation mutation "
    "`previous-non-container-mapping` (the real catalogue id, not the earlier "
    "`previous-not-a-container` typo); per S1-FIX3 V7/L1 the mutation must "
    "weaken the check semantically (treat the unusable previous as an absent/"
    "valid link) so the vector turns red, not merely remap the code.",
)


def _backdated_grant_files() -> dict[str, bytes]:
    grant = root_grant(
        record_id="grant-backdated-root",
        kinds=("example.note",),
        actions=("propose", "accept"),
        valid_from=recordlib.T0,
        valid_until=recordlib.T1,
        recorded_at=recordlib.T3,
        transferable=True,
    )
    note = agent_action(
        grant,
        record_id="grant-backdated-covered-note",
        recorded_at=recordlib.T1,
        stage="accepted",
    )
    return _wrap_internal(recordlib.build_container([grant, note]))


declare(
    "grant",
    "backdated-grant-covers-record",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _backdated_grant_files(),
    args=GRANT_ARGS,
    records=(
        {"id": "grant-backdated-root", "verdict": "valid", "errors": []},
        {"id": "grant-backdated-covered-note", "verdict": "valid", "errors": []},
    ),
    notes="T17/review A L4/S9: a grant recorded after its own validity window is "
    "accepted (only covered records' recorded_at decides their authorisation). "
    "The grant is recorded at T3 with window T0..T1 and covers the agent note "
    "recorded at T1, so both are valid.",
)


# ---------------------------------------------------------------------------
# S1-FIX2 U1: a supplied --previous container may be given as a zip
# (decision 2026-11-11 #12 U1; spec §11.5)
# ---------------------------------------------------------------------------


def _previous_container_internal() -> dict[str, bytes]:
    """Internal files of the previous container c1 (same bytes as `previous/`)."""
    return recordlib.build_container(
        [recordlib.key_declaration("human-2")],
        level="L0",
        created_at=recordlib.EARLY,
        manifest_signers=("human-2",),
    )


def _previous_container_zip(*, defective: bool) -> bytes:
    internal = _previous_container_internal()
    if not defective:
        return as_zip(internal)
    entries = [
        (name, internal[name], 3, _STANDARD_ATTR) for name in sorted(internal)
    ]
    archive, _meta = _zip_raw(entries, gaps={1: 8})
    return archive


def _previous_zip_files(*, defective: bool) -> dict[str, bytes]:
    files = _chain_container(Path("."), mismatch=False)
    files["previous-container.zip"] = _previous_container_zip(defective=defective)
    return files


declare(
    "container",
    "previous-zip-valid",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _previous_zip_files(defective=False),
    args=("--keys", "@keyset", "--previous", "previous-container.zip"),
    expected_container={
        "level_claimed": "L0",
        "level_verified": "L0",
        "previous_manifest_digest": _chain_previous_digest(),
    },
    limitations=("L_OFFLINE_CONTEXT", "L_PREVIOUS_CONTENT_UNVERIFIED"),
    notices_absent=("N_PREVIOUS_SIG_UNVERIFIED",),
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    notes="U1 + S1-FIX3 V3/§11.5: the caller supplies the previous container in "
    "zip form. Only manifest.json and signatures/manifest.sig.json are read "
    "from it, its manifest digest matches previous_manifest.digest and its "
    "manifest signature verifies with the supplied keyset, so the link "
    "succeeds, the container is valid and L_PREVIOUS_CONTENT_UNVERIFIED is "
    "reported. Because the supplied previous signature was verified, "
    "N_PREVIOUS_SIG_UNVERIFIED/L_PREVIOUS_SIG_UNVERIFIED are not reported.",
)

declare(
    "container",
    "previous-zip-invalid",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_CHAIN",),
    build=lambda case_dir: _previous_zip_files(defective=True),
    args=("--keys", "@keyset", "--previous", "previous-container.zip"),
    expected_container={
        "level_claimed": "L0",
        "level_verified": "L0",
        "previous_manifest_digest": _chain_previous_digest(),
    },
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    notes="U1 + S1-FIX3 V1/V3/§11.5: the supplied previous container is a zip "
    "with a structural defect (eight zero bytes between two local headers). The "
    "previous path parses the zip only for structure, framing and the §13 "
    "limits; any read/structural failure of the supplied previous is "
    "E_MANIFEST_CHAIN invalid (never E_CONTAINER_ZIP) and must not crash. The "
    "previous-manifest chain is container step (10), after the record phase, so "
    "the record is processed and valid.",
)

# ---------------------------------------------------------------------------
# S1-FIX2 U2: §13 limits in the zip form
# (decision 2026-11-11 #12 U2; spec §11.9/§13)
# ---------------------------------------------------------------------------

_TWO_BLOB_SIZES = (600_000_000, 600_000_000)  # each < MAX_BLOB_BYTES, sum > 1 GiB
_READABLE_BIG_DECLARED = 1_073_741_825  # 1 GiB + 1: excluded from the total


def _deflated_tiny_payload() -> bytes:
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    return compressor.compress(b"x") + compressor.flush()


def _zip_declared_entries(
    entries: Sequence[tuple[str, bytes, int, int, int, int]],
    *,
    gaps: dict[int, int] | None = None,
) -> bytes:
    """Deterministic zip over (name, payload, method, usize, crc, attr) tuples.

    The declared uncompressed size is caller-controlled (the payload stays
    small), which is how the §13 declared-total and readable-exclusion rules are
    exercised without multi-gigabyte fixtures. ``gaps`` inserts that many zero
    bytes after the local entry with the given index (S1-FIX3 V7).
    """
    output = bytearray()
    central = bytearray()
    gap_after = gaps or {}
    for index, (name, payload, method, declared_size, crc, attr) in enumerate(entries):
        name_bytes = name.encode("utf-8")
        flags = _ZIP_UTF8_FLAG
        offset = len(output)
        output += struct.pack(
            "<IHHHHHIIIHH",
            _ZIP_LOCAL_SIG,
            20,
            flags,
            method,
            0,
            0,
            crc,
            len(payload),
            declared_size,
            len(name_bytes),
            0,
        )
        output += name_bytes
        output += payload
        central += struct.pack(
            "<IHHHHHHIIIHHHHHII",
            _ZIP_CENTRAL_SIG,
            (3 << 8) | 20,
            20,
            flags,
            method,
            0,
            0,
            crc,
            len(payload),
            declared_size,
            len(name_bytes),
            0,
            0,
            0,
            0,
            attr,
            offset,
        )
        central += name_bytes
        if index in gap_after:
            output += b"\x00" * gap_after[index]
    central_offset = len(output)
    output += central
    count = len(entries)
    output += struct.pack(
        "<IHHHHIIH",
        _ZIP_EOCD_SIG,
        0,
        0,
        count,
        count,
        len(central),
        central_offset,
        0,
    )
    return bytes(output)


def _zip_declared_standard_entries() -> list[tuple[str, bytes, int, int, int, int]]:
    entries = []
    for name, data, _create_system, attr in _zip_standard_entries():
        entries.append((name, data, 0, len(data), zlib.crc32(data) & 0xFFFFFFFF, attr))
    return entries


def _zip_declared_total_over_limit() -> dict[str, bytes]:
    entries = _zip_declared_standard_entries()
    payload = _deflated_tiny_payload()
    for label, declared in zip(("a", "b"), _TWO_BLOB_SIZES):
        entries.append(
            (
                "blobs/sha256/" + label * 64,
                payload,
                8,
                declared,
                0,
                _STANDARD_ATTR,
            )
        )
    return {"container.zip": _zip_declared_entries(entries)}


def _readable_declared_size_excluded() -> dict[str, bytes]:
    entries = _zip_declared_standard_entries()
    entries.append(
        (
            "readable/big.txt",
            _deflated_tiny_payload(),
            8,
            _READABLE_BIG_DECLARED,
            0,
            _STANDARD_ATTR,
        )
    )
    return {"container.zip": _zip_declared_entries(entries)}


declare(
    "container",
    "zip-declared-total-over-limit",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_SIZE",),
    build=lambda case_dir: _zip_declared_total_over_limit(),
    records=[],
    notes="U2/§13: two zip entries declare 600,000,000 uncompressed bytes each "
    "(each below MAX_BLOB_BYTES, sum over MAX_CONTAINER_UNCOMPRESSED_BYTES = "
    "1 GiB). The declared-size total is checked on the archive before entry "
    "processing, so this is invalid E_CONTAINER_SIZE (not E_CONTAINER_ZIP) "
    "with no per-record verdicts.",
)

declare(
    "container",
    "readable-declared-size-excluded",
    "container",
    "container.zip",
    "valid",
    build=lambda case_dir: _readable_declared_size_excluded(),
    args=("--keys", "@keyset"),
    expected_container={"level_claimed": "L0", "level_verified": "L0", "record_count": 1},
    notices=("N_READABLE_PRESENT",),
    limitations=("L_OFFLINE_CONTEXT",),
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    notes="U2/§11.9/§13: the archive also has a readable/big.txt entry that "
    "declares 1 GiB + 1 uncompressed bytes (its payload is a few deflated "
    "bytes). readable/** is never decompressed and is excluded from the "
    "declared-size total, so the archive stays valid and the entry count and "
    "record are unaffected.",
)

# ---------------------------------------------------------------------------
# S1-FIX2 U9: single-volume archives only — every disk field is checked
# (decision 2026-11-11 #12 U9; spec §11.9 rule 3)
# ---------------------------------------------------------------------------


def _zip_eocd_disk_number() -> dict[str, bytes]:
    archive, meta = _zip_standard()
    return {"container.zip": _zip_patch(archive, meta["eocd_offset"] + 4, "<H", 1)}


def _zip64_locator_total_disks() -> dict[str, bytes]:
    archive, meta = _zip_standard()
    patched = _patch_zip64(archive)
    locator = meta["eocd_offset"] + 56
    # locator: sig(4) disk-with-zip64-eocd(4) offset(8) total-disks(4)
    return {"container.zip": _zip_patch(patched, locator + 16, "<I", 2)}


declare(
    "container",
    "zip-disk-number-nonzero",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_ZIP",),
    build=lambda case_dir: _zip_eocd_disk_number(),
    records=[],
    notes="U9/§11.9 rule 3: only single-volume archives are supported. The "
    "EOCD's \"number of this disk\" field is 1, not 0, so the archive is "
    "E_CONTAINER_ZIP.",
)

declare(
    "container",
    "zip64-locator-total-disks",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_ZIP",),
    build=lambda case_dir: _zip64_locator_total_disks(),
    records=[],
    notes="U9/§11.9 rule 3: the ZIP64 EOCD locator's \"total number of disks\" "
    "field is 2 (a single-volume archive must have 1), so the archive is "
    "E_CONTAINER_ZIP.",
)

# ---------------------------------------------------------------------------
# S1-FIX2 U12: low zip findings L1/L2/L4/L5/L6
# (decision 2026-11-11 #12 U12; spec §11.9)
# ---------------------------------------------------------------------------


def _zip_data_descriptor_nonzero_local() -> dict[str, bytes]:
    archive, meta = _zip_standard(data_descriptor=True)
    offset = meta["locals"][0]["offset"]
    patched = _zip_patch(archive, offset + 14, "<I", 1)  # CRC
    patched = _zip_patch(patched, offset + 18, "<I", 1)  # compressed size
    patched = _zip_patch(patched, offset + 22, "<I", 1)  # uncompressed size
    return {"container.zip": patched}


def _zip_readable_local_central_crc_mismatch() -> dict[str, bytes]:
    extra_name = "readable/notes.txt"
    archive, meta = _zip_standard(
        extra=((extra_name, b"readable payload", 3, _STANDARD_ATTR),)
    )
    index = len(_zip_standard_entries())
    offset = meta["locals"][index]["offset"] + 14
    local_crc = struct.unpack_from("<I", archive, offset)[0]
    return {"container.zip": _zip_patch(archive, offset, "<I", local_crc + 1)}


def _zip_eocd_per_disk_count() -> dict[str, bytes]:
    archive, meta = _zip_standard()
    count = struct.unpack_from("<H", archive, meta["eocd_offset"] + 8)[0]
    return {
        "container.zip": _zip_patch(
            archive, meta["eocd_offset"] + 8, "<H", count + 1
        )
    }


def _zip64_sentinel_without_zip64() -> dict[str, bytes]:
    archive, meta = _zip_standard()
    return {
        "container.zip": _zip_patch(
            archive, meta["eocd_offset"] + 8, "<HH", 0xFFFF, 0xFFFF
        )
    }


def _zip_slash_name_with_data() -> dict[str, bytes]:
    archive, _meta = _zip_standard(
        extra=(("readable/dir/", b"data", 3, _STANDARD_ATTR),)
    )
    return {"container.zip": archive}


declare(
    "container",
    "zip-data-descriptor-nonzero-local-header",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_ZIP",),
    build=lambda case_dir: _zip_data_descriptor_nonzero_local(),
    records=[],
    notes="U12/L1/§11.9 rule 1: with general-purpose flag bit 3 set (data "
    "descriptor), the local header's CRC and sizes MUST be zero (APPNOTE "
    "4.4.4). This local header carries non-zero values, so the archive is "
    "E_CONTAINER_ZIP.",
)

declare(
    "container",
    "readable-local-central-crc-mismatch",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_ZIP",),
    build=lambda case_dir: _zip_readable_local_central_crc_mismatch(),
    records=[],
    notes="U12/L2/§11.9 rule 5: skipping decompression and CRC-over-data checks "
    "for readable/ entries does not skip rule 1 — the local header CRC must "
    "still equal the central-directory CRC. They differ here, so the archive "
    "is E_CONTAINER_ZIP.",
)

declare(
    "container",
    "zip-eocd-per-disk-count",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_ZIP",),
    build=lambda case_dir: _zip_eocd_per_disk_count(),
    records=[],
    notes="U12/L4/§11.9 rule 3: the EOCD has two entry-count fields (entries on "
    "this disk, total entries); both must equal the actual entry count. Only "
    "the per-disk field is wrong here, so the archive is E_CONTAINER_ZIP.",
)

declare(
    "container",
    "zip64-sentinel-without-zip64",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_ZIP",),
    build=lambda case_dir: _zip64_sentinel_without_zip64(),
    records=[],
    notes="U12/L5/§11.9 rule 3: the 0xFFFF entry-count sentinel is only valid "
    "when a ZIP64 EOCD record carries the true counts. This archive uses the "
    "sentinel with no ZIP64 EOCD/locator, so it is E_CONTAINER_ZIP.",
)

declare(
    "container",
    "zip-slash-name-with-data",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_ZIP",),
    build=lambda case_dir: _zip_slash_name_with_data(),
    records=[],
    notes="U12/L6/§11.9 rule 4: an entry whose name ends with `/` is a "
    "directory entry and must carry no data; this readable/ entry has data and "
    "no DOS directory attribute, so the archive is E_CONTAINER_ZIP.",
)

# ---------------------------------------------------------------------------
# S1-FIX2 U3: the self-revocation exemption only covers a revocation's own
# validity, never prior revocations of the signing key
# (decision 2026-11-11 #12 U3; spec §9.5)
# ---------------------------------------------------------------------------


def _self_revocation_after_retirement_files() -> dict[str, bytes]:
    retired = recordlib.key_revocation(
        "key-compromised",
        reason="retired",
        effective_at=recordlib.T1,
        recorded_at=recordlib.T1,
        signer_name="human-1",
        record_id="retired-key-compromised-by-human-1",
    )
    self_revocation = recordlib.key_revocation(
        "key-compromised",
        reason="retired",
        effective_at=recordlib.T3,
        recorded_at=recordlib.T3,
        signer_name="key-compromised",
        record_id="self-revocation-after-retirement",
    )
    note = record_signed_by(
        "key-compromised",
        "note-after-retirement",
        recorded_at=recordlib.T4,
        stage="accepted",
    )
    return _wrap_internal(
        recordlib.build_container([retired, self_revocation, note])
    )


declare(
    "key-lifecycle",
    "self-revocation-after-retirement",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_REVOKED",),
    build=lambda case_dir: _self_revocation_after_retirement_files(),
    args=("--keys", "@keyset"),
    records=(
        {
            "id": "retired-key-compromised-by-human-1",
            "verdict": "valid",
            "errors": [],
        },
        {
            "id": "self-revocation-after-retirement",
            "verdict": "invalid",
            "errors": ["E_KEY_REVOKED"],
        },
        {
            "id": "note-after-retirement",
            "verdict": "invalid",
            "errors": ["E_KEY_REVOKED"],
        },
    ),
    notes="U3/§9.5: the key is already validly retired at T1, so its later "
    "self-signed revocation (recorded T3) is judged with the prior revocation "
    "applied: the self-revocation exemption only excludes R's own revocation "
    "effect, not earlier revocations of the same key. R is invalid "
    "E_KEY_REVOKED and revokes nothing; the original retirement stays "
    "effective, so the T4 note is invalid E_KEY_REVOKED too.",
)


def _backdated_self_compromise_ineffective_files() -> dict[str, bytes]:
    retired = recordlib.key_revocation(
        "key-compromised",
        reason="retired",
        effective_at=recordlib.T1,
        recorded_at=recordlib.T1,
        signer_name="human-1",
        record_id="retired-key-compromised-before-backdate",
    )
    honest_note = record_signed_by(
        "key-compromised",
        "honest-note-before-retirement",
        recorded_at="2026-11-01T12:00:00.000Z",
        stage="accepted",
    )
    backdated_compromise = recordlib.key_revocation(
        "key-compromised",
        reason="key-compromise",
        effective_at=recordlib.EARLY,
        recorded_at=recordlib.T3,
        signer_name="key-compromised",
        record_id="backdated-self-compromise-after-retirement",
    )
    return _wrap_internal(
        recordlib.build_container([retired, honest_note, backdated_compromise])
    )


declare(
    "key-lifecycle",
    "backdated-self-compromise-ineffective",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_REVOKED",),
    build=lambda case_dir: _backdated_self_compromise_ineffective_files(),
    args=("--keys", "@keyset"),
    records=(
        {
            "id": "retired-key-compromised-before-backdate",
            "verdict": "valid",
            "errors": [],
        },
        {
            "id": "honest-note-before-retirement",
            "verdict": "valid",
            "errors": [],
        },
        {
            "id": "backdated-self-compromise-after-retirement",
            "verdict": "invalid",
            "errors": ["E_KEY_REVOKED"],
        },
    ),
    notes="U3/§9.5: after the valid retirement at T1 the key self-signs a "
    "key-compromise revocation recorded at T3 whose effective_at is backdated "
    "before the retirement. The revocation record itself is judged with the "
    "prior retirement applied, so it is invalid E_KEY_REVOKED and has no "
    "effect. The honest note recorded before the retirement stays valid, which "
    "shows the backdated compromise did not reach back.",
)

# ---------------------------------------------------------------------------
# S1-FIX2 U4: the governing class is computed before and independently of the
# trust closure (decision 2026-11-11 #12 U4; spec §5.3)
# ---------------------------------------------------------------------------


def _keyset_without(*filenames: str) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for path in sorted((recordlib.KEYS_DIR / "keyset").iterdir()):
        if path.name in filenames:
            continue
        files["keyset/" + path.name] = path.read_bytes()
    return files


def _nonmonotonic_closure_files() -> dict[str, bytes]:
    declaration_org = recordlib.key_declaration(
        "org-1",
        record_id="K-as-org-T0",
        recorded_at=recordlib.T0,
        key_type="organization",
        cosigners=("human-2",),
    )
    declaration_human = recordlib.key_declaration(
        "org-1",
        record_id="K-as-human-T1",
        recorded_at=recordlib.T1,
        key_type="human",
        cosigners=("human-1",),
    )
    declaration_younger = recordlib.key_declaration(
        "human-2",
        record_id="Y-human-T2",
        recorded_at=recordlib.T2,
        key_type="human",
        cosigners=("org-1",),
    )
    files = _wrap_internal(
        recordlib.build_container(
            [declaration_org, declaration_human, declaration_younger]
        )
    )
    files.update(
        _keyset_without(
            "key-declared-org-1.json", "key-declared-human-2.json"
        )
    )
    return files


declare(
    "key-lifecycle",
    "nonmonotonic-closure-class-conflict",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_CLASS_CONFLICT", "E_KEY_UNTRUSTED"),
    build=lambda case_dir: _nonmonotonic_closure_files(),
    args=("--keys", "keyset"),
    records=(
        {
            "id": "K-as-org-T0",
            "verdict": "unverifiable",
            "errors": ["E_KEY_UNTRUSTED"],
        },
        {
            "id": "K-as-human-T1",
            "verdict": "invalid",
            "errors": ["E_KEY_CLASS_CONFLICT"],
        },
        {
            "id": "Y-human-T2",
            "verdict": "unverifiable",
            "errors": ["E_KEY_UNTRUSTED"],
        },
    ),
    notes="U4/§5.3 non-monotone closure example. Keyset omits the org-1 and "
    "human-2 declarations; the container carries three context declarations: "
    "D_o = org-1 as organization @T0 cosigned by human-2, D_h = org-1 as human "
    "@T1 cosigned by the keyset root human-1, D_y = human-2 as human @T2 "
    "cosigned by org-1. Derivation per U4: (1) governing class comes from "
    "structurally valid declarations before/independently of trust, keyset "
    "first else smallest (recorded_at, record digest); org-1's earliest "
    "declaration is D_o @T0, so organization governs. (2) D_h claims human and "
    "is invalid E_KEY_CLASS_CONFLICT. (3) The closure runs afterwards and "
    "invalid declarations establish no trust: D_o's cosigner human-2 and D_y's "
    "cosigner org-1 have no trusted source (the dependency is circular), so "
    "D_o and D_y are unverifiable E_KEY_UNTRUSTED. Container invalid; no "
    "fixed point selects a different class.",
)

# ---------------------------------------------------------------------------
# S1-FIX2 U5: a keyset declaration of any class pins the governing class
# (decision 2026-11-11 #12 U5; spec §9.1)
# ---------------------------------------------------------------------------


def _keyset_device_class_pins_files() -> dict[str, bytes]:
    declaration = recordlib.key_declaration(
        "device-1",
        record_id="device-1-as-human",
        recorded_at=recordlib.T2,
        key_type="human",
        cosigners=("human-1",),
    )
    return _wrap_internal(recordlib.build_container([declaration]))


declare(
    "key-lifecycle",
    "keyset-device-class-pins",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_CLASS_CONFLICT",),
    build=lambda case_dir: _keyset_device_class_pins_files(),
    args=("--keys", "@keyset"),
    records=(
        {"id": "device-1-as-human", "verdict": "invalid", "errors": ["E_KEY_CLASS_CONFLICT"]},
    ),
    notes="U5/§5.3/§9.1: the local keyset declares device-1 as `device`, so "
    "device-1's governing class is device even though a device declaration "
    "does not establish a trust root. The container's later re-declaration of "
    "device-1 as `human` (even cosigned by the keyset root human-1) is invalid "
    "E_KEY_CLASS_CONFLICT.",
)

# ---------------------------------------------------------------------------
# S1-FIX2 U6: rotated key material counts as context-trusted for TOFU
# (decision 2026-11-11 #12 U6; spec §14.9)
# ---------------------------------------------------------------------------


def _rotated_material_tofu_files() -> dict[str, bytes]:
    rotation = key_rotation()
    note = record_signed_by(
        "key-new",
        "note-by-rotated-key",
        recorded_at=recordlib.T4,
        stage="accepted",
    )
    files = _wrap_internal(recordlib.build_container([rotation, note]))
    files.update(_keyset_without("key-declared-key-new.json"))
    return files


declare(
    "key-lifecycle",
    "rotated-material-tofu",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _rotated_material_tofu_files(),
    args=("--keys", "keyset"),
    notices=("N_KEY_TOFU",),
    limitations=(
        "L_KEY_TRUST_TOFU",
        "L_OFFLINE_CONTEXT",
        "L_UNKNOWN_KIND_OPAQUE",
    ),
    records=(
        {"id": "key-rotated-1", "verdict": "valid", "errors": []},
        {
            "id": "note-by-rotated-key",
            "verdict": "valid",
            "errors": [],
        },
    ),
    notes="U6/§14.9: the local keyset omits key-new's declaration. The note is "
    "signed by key-new and its material comes from the explicit new_public_key "
    "of the weave.key.rotated record in the container, which the single TOFU "
    "criterion counts as context-trusted: the record is valid, carries "
    "N_KEY_TOFU, and the report carries L_KEY_TRUST_TOFU (plus the "
    "always-present offline limitation and the opaque-kind limitation for the "
    "unregistered note kind).",
)

# ---------------------------------------------------------------------------
# S1-FIX2 U7: L_TSA_TRUST_UNVERIFIED requires a present-unverified receipt
# (decision 2026-11-11 #12 U7; spec §14.9)
# ---------------------------------------------------------------------------


declare(
    "integrity-levels",
    "l2-invalid-receipt-no-tsa-limitation",
    "container",
    "container",
    "invalid",
    errors=("E_TS_CMS",),
    build=lambda case_dir: _crafted_l2_files(
        case_dir,
        tsr_factory=lambda imprint: _crafted_tsr(
            imprint, tamper_signature=True
        ),
    ),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container={
        "level_claimed": "L2",
        "level_verified": "L0",
        "anchor_verified": False,
    },
    limitations=("L_CHAIN_CLAIM_UNVERIFIED", "L_OFFLINE_CONTEXT"),
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    notes="U7/§14.9: the receipt's CMS signature is tampered, so the receipt is "
    "rejected by a structural/CMS check with E_TS_CMS even though a matching "
    "anchor is supplied. L_TSA_TRUST_UNVERIFIED is reported only for a "
    "present-unverified receipt (structure/CMS fine but untrusted), so the "
    "exact limitations list is [L_CHAIN_CLAIM_UNVERIFIED, L_OFFLINE_CONTEXT] "
    "and does not contain L_TSA_TRUST_UNVERIFIED.",
)

# ---------------------------------------------------------------------------
# S1-FIX2 U8: an oversize record combines with MISSING/EXTRA
# (decision 2026-11-11 #12 U8; spec §14.5)
# ---------------------------------------------------------------------------


def _oversize_combination_internal(*, extra: bool) -> dict[str, bytes]:
    records = [
        recordlib.key_declaration("human-1"),
        recordlib.key_declaration(
            "human-2", recorded_at=recordlib.T1, cosigners=("human-1",)
        ),
    ]
    internal = recordlib.build_container(records)
    record_paths = sorted(
        path for path in internal if path.startswith("records/")
    )
    first = internal[record_paths[0]]
    internal[record_paths[0]] = first + b" " * (1_048_577 - len(first))
    if extra:
        internal["records/" + "0" * 64 + ".json"] = canonical(
            recordlib.key_declaration(
                "human-2", recorded_at=recordlib.T1, cosigners=("human-1",)
            )
        )
    else:
        del internal[record_paths[1]]
    return internal


def _oversize_combination_identity(*, extra: bool) -> dict[str, Any]:
    internal = _oversize_combination_internal(extra=extra)
    manifest_bytes = internal["manifest.json"]
    return {
        "sha256": recordlib.manifest_digest(manifest_bytes),
        "size": len(manifest_bytes),
    }


declare(
    "container",
    "oversize-record-with-missing",
    "container",
    "container",
    "invalid",
    errors=("E_JSON_SIZE", "E_MANIFEST_RECORD_MISSING"),
    build=lambda case_dir: _wrap_internal(
        _oversize_combination_internal(extra=False)
    ),
    args=("--keys", "@keyset"),
    expected_input=_oversize_combination_identity(extra=False),
    expected_container={
        "created_at": recordlib.T0,
        "manifest_digest": _oversize_combination_identity(extra=False)["sha256"],
        "level_claimed": "L0",
        "level_verified": "L0",
        "anchor_verified": False,
        "chain": {"status": "absent"},
        "previous_manifest_digest": None,
        "record_count": 2,
        "timestamps": [],
    },
    records=[],
    notes="U8/§14.5: the records-listing phase reports every independent "
    "violation it detects, sorted. One records/ file is 1,048,577 bytes "
    "(E_JSON_SIZE) and one manifest-listed record file is missing "
    "(E_MANIFEST_RECORD_MISSING), so container.errors is the sorted pair and "
    "no per-record verdicts are produced; the manifest-derived report fields "
    "stay filled and input identifies the raw manifest bytes.",
)

declare(
    "container",
    "oversize-record-with-extra",
    "container",
    "container",
    "invalid",
    errors=("E_JSON_SIZE", "E_MANIFEST_RECORD_EXTRA"),
    build=lambda case_dir: _wrap_internal(
        _oversize_combination_internal(extra=True)
    ),
    args=("--keys", "@keyset"),
    expected_input=_oversize_combination_identity(extra=True),
    expected_container={
        "created_at": recordlib.T0,
        "manifest_digest": _oversize_combination_identity(extra=True)["sha256"],
        "level_claimed": "L0",
        "level_verified": "L0",
        "anchor_verified": False,
        "chain": {"status": "absent"},
        "previous_manifest_digest": None,
        "record_count": 2,
        "timestamps": [],
    },
    records=[],
    notes="U8/§14.5: the same oversize record file (E_JSON_SIZE) together with "
    "an unlisted extra records/ file (E_MANIFEST_RECORD_EXTRA). The "
    "records-listing phase reports both independent violations, sorted; "
    "records is empty and the manifest-derived report fields stay filled.",
)

# ---------------------------------------------------------------------------
# S1-FIX3 V1/V3: a supplied --previous container is used only to link the
# chain (decision 2026-11-11 #14 V1/V3; spec §11.5)
# ---------------------------------------------------------------------------

V3_VALID_LIMITATIONS = ("L_OFFLINE_CONTEXT", "L_PREVIOUS_CONTENT_UNVERIFIED")
V3_NO_NOTICES = ("N_PREVIOUS_SIG_UNVERIFIED",)


def _stored_deflate(data: bytes) -> bytes:
    """Deterministic raw DEFLATE stream built only from stored blocks.

    Using our own stored-block framing (instead of ``zlib.compress``) keeps the
    committed bytes independent of the zlib version; corrupting such a stream
    (reserved block type) still makes the decoder raise ``zlib.error`` (V1).
    """
    chunks = [data[index : index + 65535] for index in range(0, len(data), 65535)]
    if not chunks:
        chunks = [b""]
    out = bytearray()
    for index, chunk in enumerate(chunks):
        out.append(0x01 if index == len(chunks) - 1 else 0x00)
        length = len(chunk)
        out += struct.pack("<HH", length, length ^ 0xFFFF)
        out += chunk
    return bytes(out)


def _stored_entry(name: str, data: bytes) -> tuple[str, bytes, int, int, int, int]:
    return (name, data, 0, len(data), zlib.crc32(data) & 0xFFFFFFFF, _STANDARD_ATTR)


def _stored_zip_entries(
    files: dict[str, bytes],
    extra: Sequence[tuple[str, bytes, int, int, int, int]] = (),
) -> list[tuple[str, bytes, int, int, int, int]]:
    entries = [_stored_entry(name, files[name]) for name in sorted(files)]
    entries.extend(extra)
    return entries


def _deflated_zip(files: dict[str, bytes]) -> bytes:
    entries = []
    for name in sorted(files):
        data = files[name]
        entries.append(
            (name, _stored_deflate(data), 8, len(data), zlib.crc32(data) & 0xFFFFFFFF, _STANDARD_ATTR)
        )
    return _zip_declared_entries(entries)


def _chain_files_for_previous(previous_internal: dict[str, bytes]) -> dict[str, bytes]:
    previous_bytes = previous_internal["manifest.json"]
    previous_digest = recordlib.manifest_digest(previous_bytes)
    files = recordlib.build_container(
        [recordlib.key_declaration("human-1")],
        level="L0",
        created_at=recordlib.T1,
        manifest_signers=("human-1",),
        previous_manifest={"digest": previous_digest},
        previous_manifest_bytes=previous_bytes,
    )
    return wrap(files)


def _prepend_previous_directory(
    files: dict[str, bytes], previous_internal: dict[str, bytes]
) -> dict[str, bytes]:
    result = dict(files)
    result.update(
        {"previous-container/" + path: data for path, data in previous_internal.items()}
    )
    return result


def _v3_expected_container(previous_internal: dict[str, bytes]) -> dict[str, Any]:
    return {
        "level_claimed": "L0",
        "level_verified": "L0",
        "previous_manifest_digest": recordlib.manifest_digest(
            previous_internal["manifest.json"]
        ),
    }


def _previous_ignores_record_corruption_files() -> dict[str, bytes]:
    previous = _previous_container_internal()
    record_paths = sorted(path for path in previous if path.startswith("records/"))
    data = previous[record_paths[0]]
    previous[record_paths[0]] = data[: len(data) // 2] + b"\x00"
    return _prepend_previous_directory(
        _chain_files_for_previous(previous), previous
    )


declare(
    "container",
    "previous-ignores-record-corruption",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _previous_ignores_record_corruption_files(),
    args=("--keys", "@keyset", "--previous", "previous-container"),
    expected_container=_v3_expected_container(_previous_container_internal()),
    limitations=V3_VALID_LIMITATIONS,
    notices_absent=V3_NO_NOTICES,
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    notes="S1-FIX3 V3/§11.5: the supplied previous container is read only for "
    "its manifest.json and signatures/manifest.sig.json; one record file inside "
    "it has a changed byte (its CRC/digest no longer match). The previous "
    "content is not verified, so the link still succeeds, the container is "
    "valid and L_PREVIOUS_CONTENT_UNVERIFIED is reported. N_PREVIOUS_SIG_UNVERIFIED "
    "is not reported: the supplied previous manifest's signature was verified.",
)


def _previous_ignores_duplicate_manifest_files() -> dict[str, bytes]:
    previous = _previous_container_internal()
    entries = _stored_zip_entries(
        previous, extra=(_stored_entry("manifest.json", b"{}\n"),)
    )
    files = _chain_files_for_previous(previous)
    files["previous-container.zip"] = _zip_declared_entries(entries)
    return files


declare(
    "container",
    "previous-ignores-duplicate-manifest",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_CHAIN",),
    build=lambda case_dir: _previous_ignores_duplicate_manifest_files(),
    args=("--keys", "@keyset", "--previous", "previous-container.zip"),
    expected_container=_v3_expected_container(_previous_container_internal()),
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    notes="S1-FIX3 V3/§11.5: a zip previous must contain exactly one "
    "non-directory manifest.json member. This archive has two (the first is the "
    "valid one); the duplicate makes the link unreadable, so the container is "
    "invalid E_MANIFEST_CHAIN. The rest of the archive is ignored, but the two "
    "read members are not optional.",
)


def _previous_ignores_evil_path_files() -> dict[str, bytes]:
    previous = _previous_container_internal()
    entries = _stored_zip_entries(
        previous, extra=(_stored_entry("../evil.json", b"{}\n"),)
    )
    files = _chain_files_for_previous(previous)
    files["previous-container.zip"] = _zip_declared_entries(entries)
    return files


declare(
    "container",
    "previous-ignores-evil-path",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _previous_ignores_evil_path_files(),
    args=("--keys", "@keyset", "--previous", "previous-container.zip"),
    expected_container=_v3_expected_container(_previous_container_internal()),
    limitations=V3_VALID_LIMITATIONS,
    notices_absent=V3_NO_NOTICES,
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    notes="S1-FIX3 V3/§11.5: the zip previous contains an extra ../evil.json "
    "member. Only structure, framing and the §13 limits are applied to a zip "
    "previous; entry-name safety and duplicate-name rules are not applied to "
    "the ignored members, so the link still succeeds and the container is "
    "valid with L_PREVIOUS_CONTENT_UNVERIFIED.",
)


def _previous_ignores_extra_zip_file_files() -> dict[str, bytes]:
    previous = _previous_container_internal()
    entries = _stored_zip_entries(
        previous, extra=(_stored_entry("junk.txt", b"junk\n"),)
    )
    files = _chain_files_for_previous(previous)
    files["previous-container.zip"] = _zip_declared_entries(entries)
    return files


declare(
    "container",
    "previous-ignores-extra-zip-file",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _previous_ignores_extra_zip_file_files(),
    args=("--keys", "@keyset", "--previous", "previous-container.zip"),
    expected_container=_v3_expected_container(_previous_container_internal()),
    limitations=V3_VALID_LIMITATIONS,
    notices_absent=V3_NO_NOTICES,
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    notes="S1-FIX3 V3/§11.5: the zip previous contains an extra top-level "
    "junk.txt member that no manifest lists. Extra members of a supplied "
    "previous are ignored (only manifest.json and signatures/manifest.sig.json "
    "are read), so the container is valid with L_PREVIOUS_CONTENT_UNVERIFIED.",
)


def _previous_ignores_extra_directory_file_files() -> dict[str, bytes]:
    previous = _previous_container_internal()
    previous["junk.txt"] = b"junk\n"
    return _prepend_previous_directory(
        _chain_files_for_previous(_previous_container_internal()), previous
    )


declare(
    "container",
    "previous-ignores-extra-directory-file",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _previous_ignores_extra_directory_file_files(),
    args=("--keys", "@keyset", "--previous", "previous-container"),
    expected_container=_v3_expected_container(_previous_container_internal()),
    limitations=V3_VALID_LIMITATIONS,
    notices_absent=V3_NO_NOTICES,
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    notes="S1-FIX3 V3/§11.5: the directory previous contains an extra junk.txt "
    "file. Extra files in a supplied previous are ignored (only manifest.json "
    "and signatures/manifest.sig.json are read as regular files), so the "
    "container is valid with L_PREVIOUS_CONTENT_UNVERIFIED.",
)


def _previous_ignores_record_symlink_files() -> dict[str, bytes]:
    previous = _previous_container_internal()
    return _prepend_previous_directory(
        _chain_files_for_previous(previous), previous
    )


declare(
    "container",
    "previous-ignores-record-symlink",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _previous_ignores_record_symlink_files(),
    args=("--keys", "@keyset", "--previous", "previous-container"),
    expected_container=_v3_expected_container(_previous_container_internal()),
    limitations=V3_VALID_LIMITATIONS,
    notices_absent=V3_NO_NOTICES,
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    symlinks=(("previous-container/records/evil.json", "../manifest.json"),),
    notes="S1-FIX3 V3/§11.5: inside the directory previous, records/evil.json "
    "is a symbolic link. Only manifest.json and signatures/manifest.sig.json "
    "are read from a supplied previous and they must be regular files; record "
    "entries are not read at all, so the link succeeds and the container is "
    "valid with L_PREVIOUS_CONTENT_UNVERIFIED.",
)


def _previous_ignores_missing_record_files() -> dict[str, bytes]:
    previous = _previous_container_internal()
    record_paths = sorted(path for path in previous if path.startswith("records/"))
    for path in record_paths:
        del previous[path]
    return _prepend_previous_directory(
        _chain_files_for_previous(previous), previous
    )


declare(
    "container",
    "previous-ignores-missing-record",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _previous_ignores_missing_record_files(),
    args=("--keys", "@keyset", "--previous", "previous-container"),
    expected_container=_v3_expected_container(_previous_container_internal()),
    limitations=V3_VALID_LIMITATIONS,
    notices_absent=V3_NO_NOTICES,
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    notes="S1-FIX3 V3/§11.5: the directory previous is missing its record "
    "file (the manifest still lists it). The previous content is not verified "
    "— only manifest.json and signatures/manifest.sig.json are read — so the "
    "link succeeds and the container is valid with L_PREVIOUS_CONTENT_UNVERIFIED.",
)


def _previous_bad_manifest_attestation_files() -> dict[str, bytes]:
    previous = _previous_container_internal()
    previous["signatures/manifest.sig.json"] = b"this is not a manifest attestation\n"
    return _prepend_previous_directory(
        _chain_files_for_previous(previous), previous
    )


declare(
    "container",
    "previous-ignores-bad-attestation",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_CHAIN",),
    build=lambda case_dir: _previous_bad_manifest_attestation_files(),
    args=("--keys", "@keyset", "--previous", "previous-container"),
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    notes="S1-FIX3 V3/§11.5 (recheck2 X3 row rewritten): the supplied "
    "previous's signatures/manifest.sig.json is not valid JSON. That file is "
    "one of the two members the verifier must read to verify the previous "
    "manifest signature, so the link cannot be established and the container "
    "is invalid E_MANIFEST_CHAIN (the old behaviour silently accepted it).",
)


def _timestamped_previous_internal() -> dict[str, bytes]:
    def builder(imprint: bytes) -> list[tuple[str, bytes, str | None]]:
        return [("signatures/timestamp-1.tsr", _crafted_tsr(imprint), None)]

    return _build_timestamped_container(
        [recordlib.key_declaration("human-2")],
        builder,
        level="L2",
        created_at=recordlib.EARLY,
        manifest_signers=("human-2",),
    )


def _previous_corrupt_timestamp_content_files() -> dict[str, bytes]:
    previous = _timestamped_previous_internal()
    tsr_path = "signatures/timestamp-1.tsr"
    previous[tsr_path] = b"\x30\x00corrupted timestamp content"
    return _prepend_previous_directory(
        _chain_files_for_previous(previous), previous
    )


declare(
    "container",
    "previous-ignores-corrupt-timestamp-content",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _previous_corrupt_timestamp_content_files(),
    args=("--keys", "@keyset", "--previous", "previous-container"),
    expected_container={
        "level_claimed": "L0",
        "level_verified": "L0",
        "previous_manifest_digest": recordlib.manifest_digest(
            _timestamped_previous_internal()["manifest.json"]
        ),
    },
    limitations=V3_VALID_LIMITATIONS,
    notices_absent=V3_NO_NOTICES,
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    notes="S1-FIX3 V3/§11.5: the supplied directory previous has a readable "
    "manifest.json and a valid, signature-checked "
    "signatures/manifest.sig.json, but the timestamp reply content "
    "(signatures/timestamp-1.tsr) is corrupted. Attestation timestamp contents "
    "are not verified when the container is used as a previous, so the link "
    "succeeds and the container is valid with L_PREVIOUS_CONTENT_UNVERIFIED.",
)


def _previous_zip_deflate_files(*, corrupt: bool) -> dict[str, bytes]:
    previous = _previous_container_internal()
    entries = []
    for name in sorted(previous):
        data = previous[name]
        compressed = _stored_deflate(data)
        if corrupt and name == "manifest.json":
            compressed = b"\xff" + compressed[1:]
        entries.append(
            (
                name,
                compressed,
                8,
                len(data),
                zlib.crc32(data) & 0xFFFFFFFF,
                _STANDARD_ATTR,
            )
        )
    files = _chain_files_for_previous(previous)
    files["previous-container.zip"] = _zip_declared_entries(entries)
    return files


declare(
    "container",
    "previous-zip-deflate-valid",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _previous_zip_deflate_files(corrupt=False),
    args=("--keys", "@keyset", "--previous", "previous-container.zip"),
    expected_container=_v3_expected_container(_previous_container_internal()),
    limitations=V3_VALID_LIMITATIONS,
    notices_absent=V3_NO_NOTICES,
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    notes="S1-FIX3 V1/§11.5: the supplied previous container is a zip whose "
    "members are DEFLATE-compressed (stored-block streams). The two read "
    "members decompress correctly, so the link succeeds and the container is "
    "valid with L_PREVIOUS_CONTENT_UNVERIFIED; the previous signature is "
    "verified, so N_PREVIOUS_SIG_UNVERIFIED is not reported.",
)

declare(
    "container",
    "previous-zip-deflate-corrupt",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_CHAIN",),
    build=lambda case_dir: _previous_zip_deflate_files(corrupt=True),
    args=("--keys", "@keyset", "--previous", "previous-container.zip"),
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    notes="S1-FIX3 V1/§11.5 (recheck2 X1): the manifest.json member of the "
    "DEFLATE-compressed previous zip has a corrupted compressed stream; the "
    "decoder raises zlib.error, which zipread maps to ZipStructureError and the "
    "previous path maps to E_MANIFEST_CHAIN. The process must not crash. The "
    "previous identity is not established, so no L_PREVIOUS_CONTENT_UNVERIFIED "
    "and no previous_manifest_digest are reported; the target record is still "
    "processed and valid.",
)

# ---------------------------------------------------------------------------
# S1-FIX3 V6: zip version-needed and per-entry disk number start
# (decision 2026-11-11 #14 V6; spec §11.9 rule 1/3)
# ---------------------------------------------------------------------------


def _zip_version_needed_too_high() -> dict[str, bytes]:
    archive, meta = _zip_standard()
    return {"container.zip": _zip_patch(archive, meta["central_offset"] + 6, "<H", 64)}


def _zip_entry_disk_start_nonzero() -> dict[str, bytes]:
    archive, meta = _zip_standard()
    return {"container.zip": _zip_patch(archive, meta["central_offset"] + 34, "<H", 1)}


declare(
    "container",
    "zip-version-needed-too-high",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_ZIP",),
    build=lambda case_dir: _zip_version_needed_too_high(),
    records=[],
    notes="S1-FIX3 V6/§11.9 rule 1: the central-directory \"version needed to "
    "extract\" is 64 while the accepted range is 20..63 (the local-header "
    "version field is not constrained). The archive is E_CONTAINER_ZIP.",
)

declare(
    "container",
    "zip-entry-disk-start-nonzero",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_ZIP",),
    build=lambda case_dir: _zip_entry_disk_start_nonzero(),
    records=[],
    notes="S1-FIX3 V6/§11.9 rule 3: only single-volume archives are supported; "
    "every per-entry central-directory \"disk number start\" field must be 0. "
    "This entry's field is 1, so the archive is E_CONTAINER_ZIP.",
)

# ---------------------------------------------------------------------------
# S1-FIX3 V7: §13 limits are checked before the remaining zip structure rules
# (decision 2026-11-11 #14 V7/L7; spec §11.9/§13)
# ---------------------------------------------------------------------------


def _zip_over_limit_and_structure_violation() -> dict[str, bytes]:
    entries = _zip_declared_standard_entries()
    payload = _deflated_tiny_payload()
    for label, declared in zip(("a", "b"), _TWO_BLOB_SIZES):
        entries.append(
            ("blobs/sha256/" + label * 64, payload, 8, declared, 0, _STANDARD_ATTR)
        )
    # Eight zero bytes between the first and the second local entry: the
    # archive is over the declared-size limit AND structurally invalid.
    return {"container.zip": _zip_declared_entries(entries, gaps={0: 8})}


declare(
    "container",
    "zip-over-limit-and-structure-violation",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_SIZE",),
    build=lambda case_dir: _zip_over_limit_and_structure_violation(),
    records=[],
    notes="S1-FIX3 V7/L7/§11.9/§13: the archive both exceeds the declared "
    "uncompressed total (two 600,000,000-byte declarations) and has an 8-byte "
    "gap between local entries. The §13 entry-count/declared-total limits are "
    "checked before the remaining zip structure rules, so the container is "
    "invalid E_CONTAINER_SIZE only; the structural violation is not reported.",
)

# ---------------------------------------------------------------------------
# S1-FIX3 V2: strict DER for timestamp replies (recomputed attestation digests)
# (decision 2026-11-11 #14 V2; spec §12.2 check 1)
# ---------------------------------------------------------------------------


class _DerNode:
    __slots__ = ("tag", "content", "children", "force_long")

    def __init__(
        self, tag: int, content: bytes | None, children: list["_DerNode"] | None
    ) -> None:
        self.tag = tag
        self.content = content
        self.children = children
        self.force_long = False


def _der_read_length(data: bytes, position: int) -> tuple[int, int]:
    first = data[position]
    position += 1
    if first < 0x80:
        return first, position
    count = first & 0x7F
    if count == 0:
        raise ValueError("indefinite-length DER is not supported")
    length = int.from_bytes(data[position : position + count], "big")
    return length, position + count


def _der_parse_node(data: bytes, position: int) -> tuple[_DerNode, int]:
    tag = data[position]
    position += 1
    length, position = _der_read_length(data, position)
    end = position + length
    if end > len(data):
        raise ValueError("DER node exceeds the buffer")
    if tag & 0x20:
        children: list[_DerNode] = []
        child_position = position
        while child_position < end:
            child, child_position = _der_parse_node(data, child_position)
            children.append(child)
        if child_position != end:
            raise ValueError("DER children do not fill their parent")
        return _DerNode(tag, None, children), end
    return _DerNode(tag, data[position:end], None), end


def _der_tree(data: bytes) -> _DerNode:
    node, end = _der_parse_node(data, 0)
    if end != len(data):
        raise ValueError("trailing data after the top-level DER object")
    return node


def _der_encode_length(length: int, *, force_long: bool) -> bytes:
    if length < 0x80 and not force_long:
        return bytes([length])
    raw = length.to_bytes(max(1, (length.bit_length() + 7) // 8), "big")
    return bytes([0x80 | len(raw)]) + raw


def _der_encode(node: _DerNode) -> bytes:
    if node.children is None:
        body = node.content if node.content is not None else b""
    else:
        body = b"".join(_der_encode(child) for child in node.children)
    # A node built by hand may carry a multi-octet identifier (high tag number).
    identifier = node.tag if isinstance(node.tag, bytes) else bytes([node.tag])
    return (
        identifier
        + _der_encode_length(len(body), force_long=node.force_long)
        + body
    )


def _der_nonminimal_length(data: bytes) -> bytes:
    """Re-encode PKIStatusInfo with a long-form length for a short body."""
    tree = _der_tree(data)
    tree.children[0].force_long = True
    return _der_encode(tree)


def _der_signed_data_version_18(data: bytes) -> bytes:
    """Change SignedData.version from 3 to 18 (same one-byte encoding)."""
    tree = _der_tree(data)
    signed_data = tree.children[1].children[1].children[0]
    version = signed_data.children[0]
    if version.tag != 0x02 or version.content != b"\x03":
        raise SystemExit("unexpected SignedData version encoding")
    version.content = b"\x12"
    return _der_encode(tree)


def _der_truncated(data: bytes) -> bytes:
    """Drop the tail so strict whole-file DER decoding fails."""
    return data[:-20]


def _der_mutated_l2_files(
    case_dir: Path, mutation: Callable[[bytes], bytes]
) -> dict[str, bytes]:
    return _crafted_l2_files(
        case_dir, tsr_factory=lambda imprint: mutation(_crafted_tsr(imprint))
    )


for _name, _mutation, _why in (
    (
        "l2-ts-der-nonminimal-length",
        _der_nonminimal_length,
        "the PKIStatusInfo length is re-encoded in long form (30 81 03) for a "
        "three-byte body: BER-valid but not minimal DER (recheck2 M3 probe shape)",
    ),
    (
        "l2-ts-der-version-invalid",
        _der_signed_data_version_18,
        "SignedData.version is 18 instead of the required 3 (recheck2 fuzz "
        "tsa#363 shape); the field is outside the CMS signature coverage",
    ),
    (
        "l2-ts-der-truncated-with-digest",
        _der_truncated,
        "the receipt bytes are truncated, so the whole file is not one complete "
        "DER TimeStampResp",
    ),
):
    declare(
        "integrity-levels",
        _name,
        "container",
        "container",
        "invalid",
        errors=("E_TS_SCHEMA",),
        build=lambda case_dir, _mutation=_mutation: _der_mutated_l2_files(
            case_dir, _mutation
        ),
        args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
        expected_container=dict(level_claimed="L2", **L2_NO_ANCHOR),
        limitations=("L_CHAIN_CLAIM_UNVERIFIED", "L_OFFLINE_CONTEXT"),
        records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
        notes="S1-FIX3 V2/§12.2 check 1: "
        + _why
        + ". The attestation timestamp digest is recomputed over the mutated "
        "bytes, so the mutation reaches DER parsing instead of stopping at "
        "E_TS_FILE. Check 1 runs before the CMS checks: the receipt is rejected "
        "with E_TS_SCHEMA at the timestamp phase (step 11), after the records "
        "were processed. An invalid receipt is not present-unverified, so "
        "L_TSA_TRUST_UNVERIFIED is not reported; the exact limitations list is "
        "[L_CHAIN_CLAIM_UNVERIFIED, L_OFFLINE_CONTEXT].",
    )

# ---------------------------------------------------------------------------
# S1-FIX3 V5: a bad public_key is structural and never governs the class
# (decision 2026-11-11 #14 V5; spec §5.3/§14.1)
# ---------------------------------------------------------------------------


def _bad_public_key_does_not_govern_files() -> dict[str, bytes]:
    files = _wrap_internal(
        recordlib.build_container(
            [
                recordlib.key_declaration(
                    "org-1",
                    record_id="org1-bad-pk-human-T0",
                    recorded_at=recordlib.T0,
                    key_type="human",
                    public_key_b64="AAAA",
                    cosigners=("human-1",),
                ),
                recordlib.key_declaration(
                    "org-1",
                    record_id="org1-org-T1",
                    recorded_at=recordlib.T1,
                    key_type="organization",
                    cosigners=("human-1",),
                ),
            ]
        )
    )
    files.update(_keyset_without("key-declared-org-1.json"))
    return files


declare(
    "key-lifecycle",
    "bad-public-key-does-not-govern",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_PUBLIC_KEY",),
    build=lambda case_dir: _bad_public_key_does_not_govern_files(),
    args=("--keys", "keyset"),
    records=(
        {
            "id": "org1-bad-pk-human-T0",
            "verdict": "invalid",
            "errors": ["E_KEY_PUBLIC_KEY"],
        },
        {"id": "org1-org-T1", "verdict": "valid", "errors": []},
    ),
    notes="S1-FIX3 V5/§5.3/§14.1 (recheck2 M2/n4): the local keyset omits "
    "org-1's declaration. The earliest context declaration (T0) claims org-1 as "
    "human but its public_key is not 32-byte base64url: public_key is a "
    "structural property, so that declaration is not structurally valid, is "
    "invalid E_KEY_PUBLIC_KEY, and never governs the class. The later T1 "
    "organization declaration (cosigned by the keyset root human-1) is "
    "structurally valid, is the governing declaration, and is valid; there is "
    "no E_KEY_CLASS_CONFLICT. A declaration with a bad public_key inside a "
    "keyset is a usage error (exit 2), which the committed vector format "
    "cannot express; it is covered by a unit test and noted in vectors/README.md.",
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


# ---------------------------------------------------------------------------
# S1-FIX4 (Inceptless decision 2026-11-11 #16, W1-W11). Every expected
# conclusion below is hand-written from the specification text it cites; the
# generator never imports a verifier.
# ---------------------------------------------------------------------------

FIX4_PREVIOUS_ARGS = ("--keys", "@keyset", "--previous", "previous-container")
FIX4_LINKED = ("L_KEY_TRUST_TOFU", "L_OFFLINE_CONTEXT", "L_PREVIOUS_CONTENT_UNVERIFIED")
FIX4_UNLINKED = ("L_OFFLINE_CONTEXT", "L_PREVIOUS_SIG_UNVERIFIED")
FIX4_UNLINKED_TOFU = ("L_KEY_TRUST_TOFU", "L_OFFLINE_CONTEXT", "L_PREVIOUS_SIG_UNVERIFIED")


def _w1_sign_manifest_with_derived(files: dict[str, bytes], key_name: str) -> dict[str, bytes]:
    """Replace the manifest attestation signatures by one derived-key signature."""
    private, _public, key_id = derived_key(key_name)
    digest = recordlib.manifest_digest(files["manifest.json"])
    sigfile = parse(files["signatures/manifest.sig.json"])
    sigfile["signatures"] = [
        {
            "alg": "ed25519",
            "key": key_id,
            "value": keyutil.b64url_encode(
                private.sign(recordlib.sig_message_for_manifest(digest))
            ),
        }
    ]
    files["signatures/manifest.sig.json"] = canonical(sigfile)
    return files


def _w1_build(
    records: Sequence[dict[str, Any]],
    signer: tuple[str, str],
    *,
    created_at: str,
    previous_internal: dict[str, bytes] | None = None,
) -> dict[str, bytes]:
    """Internal files of one container signed by a keyset or a derived key."""
    kind_of_signer, name = signer
    kwargs: dict[str, Any] = {}
    if previous_internal is not None:
        previous_bytes = previous_internal["manifest.json"]
        kwargs["previous_manifest"] = {
            "digest": recordlib.manifest_digest(previous_bytes)
        }
        kwargs["previous_manifest_bytes"] = previous_bytes
    files = recordlib.build_container(
        records,
        created_at=created_at,
        manifest_signers=(name,) if kind_of_signer == "keyset" else ("human-1",),
        **kwargs,
    )
    if kind_of_signer == "derived":
        _w1_sign_manifest_with_derived(files, name)
    return files


def _w1_device_declaration(
    key_name: str, record_id: str, *, recorded_at: str = recordlib.T0
) -> dict[str, Any]:
    """A device declaration owned and cosigned by the keyset root human-1 (J1 shape)."""
    return derived_declaration(
        record_id=record_id,
        key_name=key_name,
        key_type="device",
        owner="human-1",
        cosigners=("human-1",),
        recorded_at=recorded_at,
    )


def _w1_device_with_derived_owner(
    key_name: str, owner_key_name: str, record_id: str
) -> dict[str, Any]:
    """A device declaration whose owner is container-only (untrusted) human material."""
    owner_private, _owner_public, owner_id = derived_key(owner_key_name)
    private, public, key_id = derived_key(key_name)
    record = recordlib.build_record(
        kind="weave.key.declared",
        id=record_id,
        actor={"type": "device", "key": key_id},
        body={
            "algorithm": "ed25519",
            "key": key_id,
            "key_type": "device",
            "owner": owner_id,
            "public_key": keyutil.b64url_encode(public),
        },
        stage="accepted",
        recorded_at=recordlib.T0,
        origin_instance=key_id,
    )
    signatures = [
        _derived_signature(private, key_id, record),
        _derived_signature(owner_private, owner_id, record),
    ]
    signatures.sort(key=lambda entry: entry["key"])
    record["sigs"] = signatures
    return record


def _w1_device_rotation(
    old_name: str, new_name: str, record_id: str, *, recorded_at: str = recordlib.T2
) -> dict[str, Any]:
    """A rotation between two derived device keys, listing both public keys."""
    old_private, old_public, old_id = derived_key(old_name)
    new_private, new_public, new_id = derived_key(new_name)
    record = recordlib.build_record(
        kind="weave.key.rotated",
        id=record_id,
        actor={"type": "device", "key": old_id},
        body={
            "new_key": new_id,
            "new_public_key": keyutil.b64url_encode(new_public),
            "old_key": old_id,
            "old_public_key": keyutil.b64url_encode(old_public),
            "reason": "scheduled rotation",
        },
        stage="accepted",
        recorded_at=recorded_at,
        origin_instance=old_id,
    )
    signatures = [
        _derived_signature(old_private, old_id, record),
        _derived_signature(new_private, new_id, record),
    ]
    signatures.sort(key=lambda entry: entry["key"])
    record["sigs"] = signatures
    return record


def _w1_revocation(
    key_name: str, *, reason: str, effective_at: str, record_id: str
) -> dict[str, Any]:
    """A revocation of a derived key, signed by the keyset root human-1."""
    _private, _public, key_id = derived_key(key_name)
    record = recordlib.build_record(
        kind="weave.key.revoked",
        id=record_id,
        actor=recordlib.actor("human-1"),
        body={"effective_at": effective_at, "key": key_id, "reason": reason},
        stage="accepted",
        recorded_at=effective_at,
        origin_instance=key_id,
    )
    return recordlib.signed(record, "human-1")


def _w1_pair_files(
    previous: dict[str, bytes], target: dict[str, bytes]
) -> dict[str, bytes]:
    return _prepend_previous_directory(wrap(target), previous)


_W1_DEVICE = "w1-device-key"
_W1_DEVICE_ID = "key-declared-w1-device"


def _w1_j1_shape_files() -> dict[str, bytes]:
    declaration = _w1_device_declaration(_W1_DEVICE, _W1_DEVICE_ID)
    previous = _w1_build([declaration], ("derived", _W1_DEVICE), created_at=recordlib.T1)
    target = _w1_build(
        [declaration], ("derived", _W1_DEVICE), created_at=recordlib.T5,
        previous_internal=previous,
    )
    return _w1_pair_files(previous, target)


declare(
    "container",
    "previous-device-key-target-context",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _w1_j1_shape_files(),
    args=FIX4_PREVIOUS_ARGS,
    limitations=FIX4_LINKED,
    notices_absent=("N_PREVIOUS_SIG_UNVERIFIED", "N_KEY_TOFU"),
    records=({"id": _W1_DEVICE_ID, "verdict": "valid", "errors": []},),
    notes="S1-FIX4 W1/§11.5 (the Koinoweave J1 shape): both manifests are signed by "
    "a device key that the keyset does not declare; the keyset holds only its owner "
    "(human-1). The device declaration, owner-cosigned, is in the target container, "
    "so the device key is a required key of the target verification context and is "
    "trusted in the target's closure: the supplied previous's signature verifies, "
    "the link holds and the container is valid with L_PREVIOUS_CONTENT_UNVERIFIED. "
    "Both signature checks used context material (L_KEY_TRUST_TOFU); no record "
    "signature did (no N_KEY_TOFU).",
)


def _w1_declared_only_in_previous_files() -> dict[str, bytes]:
    declaration = _w1_device_declaration(_W1_DEVICE, _W1_DEVICE_ID)
    previous = _w1_build([declaration], ("derived", _W1_DEVICE), created_at=recordlib.T1)
    target = _w1_build(
        [recordlib.key_declaration("human-1")], ("keyset", "human-1"),
        created_at=recordlib.T5, previous_internal=previous,
    )
    return _w1_pair_files(previous, target)


declare(
    "container",
    "previous-key-declared-only-in-previous",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_CHAIN",),
    build=lambda case_dir: _w1_declared_only_in_previous_files(),
    args=FIX4_PREVIOUS_ARGS,
    notices=("N_PREVIOUS_SIG_UNVERIFIED",),
    limitations=FIX4_UNLINKED,
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    notes="S1-FIX4 W1/§11.5 rule 1: the previous manifest is signed by a device key "
    "whose declaration exists only inside the previous container. The previous "
    "container's own records are never part of the verification context, so the "
    "key is not a required key of the target context and the link fails: invalid "
    "E_MANIFEST_CHAIN. The previous signature was not re-verified, so "
    "N_PREVIOUS_SIG_UNVERIFIED/L_PREVIOUS_SIG_UNVERIFIED are reported and "
    "L_PREVIOUS_CONTENT_UNVERIFIED is not.",
)

_W1_UNTRUSTED_OWNER = "w1-untrusted-owner"
_W1_UNTRUSTED_DEVICE = "w1-untrusted-device"


def _w1_untrusted_files() -> dict[str, bytes]:
    owner = _self_attested_human_declaration(
        record_id="key-declared-w1-untrusted-owner", key_name=_W1_UNTRUSTED_OWNER
    )
    device = _w1_device_with_derived_owner(
        _W1_UNTRUSTED_DEVICE, _W1_UNTRUSTED_OWNER, "key-declared-w1-untrusted-device"
    )
    previous = _w1_build([device], ("derived", _W1_UNTRUSTED_DEVICE), created_at=recordlib.T1)
    target = _w1_build(
        [owner, device], ("keyset", "human-1"), created_at=recordlib.T5,
        previous_internal=previous,
    )
    return _w1_pair_files(previous, target)


declare(
    "container",
    "previous-key-not-trusted-in-target",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_UNTRUSTED", "E_MANIFEST_CHAIN"),
    build=lambda case_dir: _w1_untrusted_files(),
    args=FIX4_PREVIOUS_ARGS,
    notices=("N_PREVIOUS_SIG_UNVERIFIED", "N_SELF_ATTESTED_ROOT_KEY"),
    limitations=FIX4_UNLINKED_TOFU,
    records=(
        {"id": "key-declared-w1-untrusted-device", "verdict": "unverifiable", "errors": ["E_KEY_UNTRUSTED"]},
        {"id": "key-declared-w1-untrusted-owner", "verdict": "unverifiable", "errors": ["E_KEY_UNTRUSTED"]},
    ),
    notes="S1-FIX4 W1/§11.5 rule 2: the previous manifest's signing key is declared "
    "in the target container, so its signature equation verifies with context "
    "material (L_KEY_TRUST_TOFU), but the declaration's owner is a self-attested "
    "human key outside the keyset: both declarations are unverifiable "
    "E_KEY_UNTRUSTED and the signing key is not trusted in the target's final "
    "trust closure, so the link fails with E_MANIFEST_CHAIN (invalid wins).",
)

_W1_OLD = "w1-rotated-old-device"
_W1_NEW = "w1-rotated-new-device"


def _w1_rotated_files() -> dict[str, bytes]:
    old_declaration = _w1_device_declaration(_W1_OLD, "key-declared-w1-old-device")
    previous = _w1_build([old_declaration], ("derived", _W1_OLD), created_at=recordlib.T1)
    new_declaration = _w1_device_declaration(
        _W1_NEW, "key-declared-w1-new-device", recorded_at=recordlib.T2
    )
    rotation = _w1_device_rotation(_W1_OLD, _W1_NEW, "key-rotated-w1-device", recorded_at=recordlib.T3)
    target = _w1_build(
        [new_declaration, rotation], ("derived", _W1_NEW), created_at=recordlib.T5,
        previous_internal=previous,
    )
    return _w1_pair_files(previous, target)


declare(
    "container",
    "previous-rotated-old-key-links",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _w1_rotated_files(),
    args=FIX4_PREVIOUS_ARGS,
    limitations=FIX4_LINKED,
    notices_absent=("N_PREVIOUS_SIG_UNVERIFIED",),
    records=(
        {"id": "key-declared-w1-new-device", "verdict": "valid", "errors": []},
        {"id": "key-rotated-w1-device", "verdict": "valid", "errors": []},
    ),
    notes="S1-FIX4 W1/§11.5 rules 1-2: the previous manifest was signed by an old "
    "device key that has since been rotated. The target no longer carries the old "
    "key's declaration; its rotation record lists old_public_key, so the old key is "
    "a §11.3 required key of the target context, and the rotation's new key has a "
    "valid owner-cosigned declaration, so the old key is trusted in the target's "
    "closure. The link holds: valid with L_PREVIOUS_CONTENT_UNVERIFIED and "
    "L_KEY_TRUST_TOFU.",
)

_W1_ROT_X = "w1-rotation-only-x"
_W1_ROT_Y = "w1-rotation-only-y"


def _w1_rotation_material_untrusted_files() -> dict[str, bytes]:
    previous = _w1_build(
        [recordlib.key_declaration("human-2")], ("derived", _W1_ROT_X), created_at=recordlib.T1
    )
    rotation = _w1_device_rotation(_W1_ROT_X, _W1_ROT_Y, "key-rotated-w1-untrusted", recorded_at=recordlib.T3)
    target = _w1_build(
        [recordlib.key_declaration("human-1"), rotation], ("keyset", "human-1"),
        created_at=recordlib.T5, previous_internal=previous,
    )
    return _w1_pair_files(previous, target)


declare(
    "container",
    "previous-rotation-material-untrusted",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_CHAIN",),
    build=lambda case_dir: _w1_rotation_material_untrusted_files(),
    args=FIX4_PREVIOUS_ARGS,
    notices=("N_PREVIOUS_SIG_UNVERIFIED",),
    limitations=FIX4_UNLINKED_TOFU,
    records=(
        {"id": "key-declared-human-1", "verdict": "valid", "errors": []},
        {"id": "key-rotated-w1-untrusted", "verdict": "valid", "errors": []},
    ),
    notes="S1-FIX4 W1/§11.5 rule 2 (docs/open-questions.md §6 entry 24): the "
    "previous manifest is signed by key X, which the target supplies only as the "
    "old_public_key of a valid rotation X->Y. Neither X nor Y has a declaration, so "
    "the rotation's new key is not trusted and explicit rotation material alone "
    "does not make X trusted: the equation verifies with context material "
    "(L_KEY_TRUST_TOFU) but the link fails with E_MANIFEST_CHAIN.",
)

_W1_INVALID_ROT_X = "x5-invalid-rotation-x"
_W1_INVALID_ROT_Y = "x5-invalid-rotation-y"


def _x5_invalid_rotation_files() -> dict[str, bytes]:
    """Previous signed by X; the target's only X material is an invalid rotation X->Y."""
    previous = _w1_build(
        [recordlib.key_declaration("human-2")], ("derived", _W1_INVALID_ROT_X),
        created_at=recordlib.T1,
    )
    rotation = _w1_device_rotation(
        _W1_INVALID_ROT_X, _W1_INVALID_ROT_Y, "key-rotated-x5-invalid", recorded_at=recordlib.T3
    )
    _old_private, _old_public, old_id = derived_key(_W1_INVALID_ROT_X)
    # Drop the old key's signature: only the new key signs (§9.2, E_KEY_ROTATION_SIGS).
    rotation["sigs"] = [entry for entry in rotation["sigs"] if entry["key"] != old_id]
    target = _w1_build(
        [recordlib.key_declaration("human-1"), rotation], ("keyset", "human-1"),
        created_at=recordlib.T5, previous_internal=previous,
    )
    return _w1_pair_files(previous, target)


declare(
    "container",
    "previous-invalid-rotation-supplies-no-material",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_ROTATION_SIGS", "E_MANIFEST_CHAIN"),
    build=lambda case_dir: _x5_invalid_rotation_files(),
    args=FIX4_PREVIOUS_ARGS,
    notices=("N_PREVIOUS_SIG_UNVERIFIED",),
    limitations=FIX4_UNLINKED,
    records=(
        {"id": "key-declared-human-1", "verdict": "valid", "errors": []},
        {"id": "key-rotated-x5-invalid", "verdict": "invalid", "errors": ["E_KEY_ROTATION_SIGS"]},
    ),
    notes="S1-FIX5 X5 (§11.5 rule 1, §5.3; decision 2026-11-12 #1): the previous "
    "manifest is signed by key X, and the only record of the target that lists X's "
    "public key is a rotation X->Y signed by Y alone, which is invalid "
    "(E_KEY_ROTATION_SIGS). An invalid rotation record supplies no key material, so X "
    "is not a required key of the target context: the link fails with "
    "E_MANIFEST_CHAIN, and since no equation was verified with context material "
    "there is no L_KEY_TRUST_TOFU (the target manifest itself is signed by the "
    "keyset root human-1).",
)


_W1_REVOKED = "w1-retired-device"


def _w1_retired_files(*, effective_at: str) -> dict[str, bytes]:
    declaration = _w1_device_declaration(_W1_REVOKED, "key-declared-w1-retired-device")
    previous = _w1_build([declaration], ("derived", _W1_REVOKED), created_at=recordlib.T3)
    revocation = _w1_revocation(
        _W1_REVOKED, reason="retired", effective_at=effective_at,
        record_id="key-revoked-w1-retired-device",
    )
    target = _w1_build(
        [declaration, revocation], ("keyset", "human-1"), created_at=recordlib.T5,
        previous_internal=previous,
    )
    return _w1_pair_files(previous, target)


declare(
    "container",
    "previous-signing-key-retired-before-previous",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_CHAIN",),
    build=lambda case_dir: _w1_retired_files(effective_at=recordlib.T2),
    args=FIX4_PREVIOUS_ARGS,
    notices=("N_PREVIOUS_SIG_UNVERIFIED",),
    limitations=FIX4_UNLINKED_TOFU,
    records=(
        {"id": "key-declared-w1-retired-device", "verdict": "valid", "errors": []},
        {"id": "key-revoked-w1-retired-device", "verdict": "valid", "errors": []},
    ),
    notes="S1-FIX4 W1/§11.5 rule 3: the target carries a valid retired revocation of "
    "the previous manifest's signing key effective at T2, and the previous manifest "
    "claims created_at T3 (after the revocation took effect). Under §9.4, evaluated "
    "at the previous created_at, the signature is revoked, so the link fails with "
    "E_MANIFEST_CHAIN (the equation itself verified with context material: "
    "L_KEY_TRUST_TOFU).",
)

declare(
    "container",
    "previous-signing-key-retired-after-previous",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _w1_retired_files(effective_at=recordlib.T4),
    args=FIX4_PREVIOUS_ARGS,
    limitations=FIX4_LINKED,
    notices_absent=("N_PREVIOUS_SIG_UNVERIFIED",),
    records=(
        {"id": "key-declared-w1-retired-device", "verdict": "valid", "errors": []},
        {"id": "key-revoked-w1-retired-device", "verdict": "valid", "errors": []},
    ),
    notes="S1-FIX4 W1/§11.5 rule 3 (control): the same retired revocation takes "
    "effect at T4, after the previous manifest's created_at T3. A revocation that "
    "takes effect later does not affect the historical link: valid with "
    "L_PREVIOUS_CONTENT_UNVERIFIED.",
)

_W1_COMPROMISED = "w1-compromised-device"


def _w1_compromised_files(*, previous_created_at: str = recordlib.EARLY) -> dict[str, bytes]:
    """Target L2 (receipt genTime T0 rescues the device key); compromise at T1.

    Only the previous manifest's ``created_at`` varies between the X2 cases.
    """
    declaration = _w1_device_declaration(_W1_COMPROMISED, "key-declared-w1-compromised-device")
    previous = _w1_build(
        [declaration], ("derived", _W1_COMPROMISED), created_at=previous_created_at
    )
    revocation = _w1_revocation(
        _W1_COMPROMISED, reason="key-compromise", effective_at=recordlib.T1,
        record_id="key-revoked-w1-compromised-device",
    )
    previous_bytes = previous["manifest.json"]
    files = recordlib.build_container(
        [declaration, revocation],
        level="L2",
        created_at=recordlib.T5,
        manifest_signers=("human-1",),
        previous_manifest={"digest": recordlib.manifest_digest(previous_bytes)},
        previous_manifest_bytes=previous_bytes,
    )
    manifest_value = parse(files["manifest.json"])
    imprint = bytes.fromhex(
        recordlib.manifest_digest(files["manifest.json"])[len("sha256:"):]
    )
    files, _digest = _seal_with_timestamps(
        files, manifest_value, [("signatures/timestamp-1.tsr", _crafted_tsr(imprint), None)]
    )
    result = _w1_pair_files(previous, files)
    result[TSA_CERT_NAME] = TSA_CERT()
    return result


_X2_RECORDS = (
    {"id": "key-declared-w1-compromised-device", "verdict": "valid", "errors": []},
    {"id": "key-revoked-w1-compromised-device", "verdict": "valid", "errors": []},
)

declare(
    "container",
    "previous-signing-key-compromised-after-previous",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _w1_compromised_files(),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME, "--previous", "previous-container"),
    notices_absent=("N_PREVIOUS_SIG_UNVERIFIED",),
    limitations=(
        "L_CHAIN_CLAIM_UNVERIFIED", "L_KEY_TRUST_TOFU", "L_OFFLINE_CONTEXT",
        "L_PREVIOUS_CONTENT_UNVERIFIED",
    ),
    expected_container=dict(level_claimed="L2", **L2_ANCHOR),
    records=_X2_RECORDS,
    notes="S1-FIX4 W1 / S1-FIX5 X2 (§11.5 rule 3; docs/open-questions.md §6 entry 24, "
    "decision 2026-11-12 #1): the target is an L2 container whose trusted receipt "
    "(genTime T0) rescues the device declaration from a key-compromise revocation "
    "effective at T1, so both records are valid. The previous manifest, signed by the "
    "compromised key, has created_at 2025-01-01, before T1. On the previous link a "
    "key-compromise revocation is judged like a retired one, against the previous "
    "created_at: its digest is already pinned by the target's trusted signature, so a "
    "compromise that takes effect later does not reach back into the link. The link "
    "holds (L_PREVIOUS_CONTENT_UNVERIFIED; the equation used context material, "
    "L_KEY_TRUST_TOFU), the timestamp phase runs and the receipt is verified: valid (a claimed L2 chain is never recomputed offline: L_CHAIN_CLAIM_UNVERIFIED).",
)

for _name, _created_at, _relation in (
    ("previous-signing-key-compromised-at-previous", recordlib.T1,
     "equals the compromise time T1"),
    ("previous-signing-key-compromised-before-previous", recordlib.T2,
     "is T2, after the compromise time T1"),
):
    declare(
        "container",
        _name,
        "container",
        "container",
        "invalid",
        errors=("E_MANIFEST_CHAIN",),
        build=lambda case_dir, _created_at=_created_at: _w1_compromised_files(
            previous_created_at=_created_at
        ),
        args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME, "--previous", "previous-container"),
        notices=("N_PREVIOUS_SIG_UNVERIFIED",),
        limitations=("L_CHAIN_CLAIM_UNVERIFIED", "L_KEY_TRUST_TOFU", "L_OFFLINE_CONTEXT", "L_PREVIOUS_SIG_UNVERIFIED"),
        expected_container={"level_claimed": "L2", "anchor_verified": False, "timestamps": []},
        records=_X2_RECORDS,
        notes="S1-FIX5 X2 (§11.5 rule 3; docs/open-questions.md §6 entry 24, decision "
        "2026-11-12 #1): the same target as previous-signing-key-compromised-after-"
        "previous (its receipt rescues both records), but the previous manifest's "
        "created_at " + _relation + ". On the previous link a key-compromise "
        "revocation is judged against the previous created_at exactly like a retired "
        "one: created_at >= T breaks the link, E_MANIFEST_CHAIN (the equation itself "
        "verified with context material: L_KEY_TRUST_TOFU). The pipeline stops at step "
        "(10): container.timestamps is [] and anchor_verified is false.",
    )


# ---------------------------------------------------------------------------
# S1-FIX4 W2: §11.9 rule 4 applies to every entry of a supplied previous zip
# ---------------------------------------------------------------------------


def _w2_central_offsets(archive: bytes) -> list[int]:
    """Offsets of the central-directory records of a plain (non-ZIP64) archive."""
    eocd = len(archive) - 22
    count = struct.unpack_from("<H", archive, eocd + 10)[0]
    position = struct.unpack_from("<I", archive, eocd + 16)[0]
    offsets = []
    for _ in range(count):
        offsets.append(position)
        name_length, extra_length, comment_length = struct.unpack_from(
            "<HHH", archive, position + 28
        )
        position += 46 + name_length + extra_length + comment_length
    return offsets


def _w2_previous_zip(variant: str) -> bytes:
    internal = _previous_container_internal()
    names = sorted(internal)
    record_index = next(index for index, name in enumerate(names) if name.startswith("records/"))
    entries = [_stored_entry(name, internal[name]) for name in names]
    if variant == "directory-with-data":
        data = b"xy"
        entries.append(
            ("previous/", data, 0, len(data), zlib.crc32(data) & 0xFFFFFFFF, _STANDARD_ATTR)
        )
        return _zip_declared_entries(entries)
    archive = bytearray(_zip_declared_entries(entries))
    central = _w2_central_offsets(bytes(archive))[record_index]
    if variant == "dos-directory-attribute":
        attr = struct.unpack_from("<I", archive, central + 38)[0]
        struct.pack_into("<I", archive, central + 38, attr | 0x10)
    elif variant == "encrypted":
        local = struct.unpack_from("<I", archive, central + 42)[0]
        flags = struct.unpack_from("<H", archive, central + 8)[0]
        struct.pack_into("<H", archive, central + 8, flags | 0x0001)
        struct.pack_into("<H", archive, local + 6, flags | 0x0001)
    else:  # pragma: no cover - defensive
        raise SystemExit("unknown W2 variant %r" % (variant,))
    return bytes(archive)


for _variant, _what in (
    ("directory-with-data", "an extra entry named previous/ (a directory name) that carries two data bytes"),
    ("dos-directory-attribute", "the records/ entry carries the DOS directory attribute in the central directory while holding data"),
    ("encrypted", "the records/ entry has the encryption flag set in both its local header and the central directory"),
):
    declare(
        "container",
        "previous-zip-rule4-" + _variant,
        "container",
        "container",
        "invalid",
        errors=("E_MANIFEST_CHAIN",),
        build=lambda case_dir, _variant=_variant: {
            **_chain_files_for_previous(_previous_container_internal()),
            "previous-container.zip": _w2_previous_zip(_variant),
        },
        args=("--keys", "@keyset", "--previous", "previous-container.zip"),
        notices=("N_PREVIOUS_SIG_UNVERIFIED",),
        limitations=FIX4_UNLINKED,
        records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
        notes="S1-FIX4 W2/§11.5/§11.9 rule 4: in the supplied previous zip, "
        + _what
        + ". That entry is not one of the two read members, but rules 1-4 of §11.9 "
        "apply to the framing of the whole archive, every entry included, so the "
        "previous is not a usable link: invalid E_MANIFEST_CHAIN (the same archive "
        "as a target container would be E_CONTAINER_ZIP).",
    )

# ---------------------------------------------------------------------------
# S1-FIX4 W5: the container pipeline stops at the failing stage
# ---------------------------------------------------------------------------


def _w5_target_with_previous(mutator: Callable[[dict[str, bytes]], None] | None = None,
                             previous: dict[str, bytes] | None = None) -> dict[str, bytes]:
    previous_internal = previous if previous is not None else _previous_container_internal()
    target = recordlib.build_container(
        [recordlib.key_declaration("human-1")],
        created_at=recordlib.T1,
        manifest_signers=("human-1",),
        previous_manifest={"digest": recordlib.manifest_digest(_previous_container_internal()["manifest.json"])},
        previous_manifest_bytes=_previous_container_internal()["manifest.json"],
    )
    if mutator is not None:
        mutator(target)
    return _prepend_previous_directory(wrap(target), previous_internal)


def _w5_drop_record(files: dict[str, bytes]) -> None:
    for path in [path for path in files if path.startswith("records/")]:
        del files[path]


_W5_EXTRA_BLOB = b"an unlisted blob\n"


def _w5_extra_blob(files: dict[str, bytes]) -> None:
    files["blobs/sha256/" + hashlib.sha256(_W5_EXTRA_BLOB).hexdigest()] = _W5_EXTRA_BLOB


def _w5_bad_signature_previous() -> dict[str, bytes]:
    previous = _previous_container_internal()
    sigfile = parse(previous["signatures/manifest.sig.json"])
    entry = sigfile["signatures"][0]
    entry["value"] = keyutil.b64url_encode(_tampered_signature_value(entry["value"]))
    previous["signatures/manifest.sig.json"] = canonical(sigfile)
    return previous


def _w5_embedded_mismatch(files: dict[str, bytes]) -> None:
    other = recordlib.build_container(
        [recordlib.key_declaration("human-2")],
        created_at=recordlib.T6,
        manifest_signers=("human-2",),
    )["manifest.json"]
    files["previous/manifest.json"] = other


declare(
    "container",
    "previous-not-read-after-listing-failure",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_RECORD_MISSING",),
    build=lambda case_dir: _w5_target_with_previous(_w5_drop_record),
    args=FIX4_PREVIOUS_ARGS,
    notices=("N_PREVIOUS_SIG_UNVERIFIED",),
    limitations=FIX4_UNLINKED,
    records=[],
    notes="S1-FIX4 W5/§14.5: the target's only record file is missing, an invalid "
    "error at step (7). The pipeline stops there: step (10) never runs, the valid "
    "supplied previous is never read, so L_PREVIOUS_CONTENT_UNVERIFIED is not "
    "reported and the previous signature counts as not re-verified "
    "(N_PREVIOUS_SIG_UNVERIFIED, L_PREVIOUS_SIG_UNVERIFIED).",
)

declare(
    "container",
    "previous-not-read-after-blob-failure",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_BLOB",),
    build=lambda case_dir: _w5_target_with_previous(_w5_extra_blob),
    args=FIX4_PREVIOUS_ARGS,
    notices=("N_PREVIOUS_SIG_UNVERIFIED",),
    limitations=FIX4_UNLINKED,
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    notes="S1-FIX4 W5/§14.5: the target carries an unlisted blob file, an invalid "
    "error at step (9). The record phase already ran (its verdict is reported), but "
    "the pipeline stops at step (9): the valid supplied previous is never read, so "
    "L_PREVIOUS_CONTENT_UNVERIFIED is not reported.",
)

declare(
    "container",
    "previous-bad-signature-after-blob-failure",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_BLOB",),
    build=lambda case_dir: _w5_target_with_previous(
        _w5_extra_blob, previous=_w5_bad_signature_previous()
    ),
    args=FIX4_PREVIOUS_ARGS,
    notices=("N_PREVIOUS_SIG_UNVERIFIED",),
    limitations=FIX4_UNLINKED,
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    notes="S1-FIX4 W5/§14.5: as previous-not-read-after-blob-failure, but the "
    "supplied previous's manifest signature is also broken. Step (10) does not run "
    "after the step-(9) error, so only E_MANIFEST_BLOB is reported, never "
    "E_MANIFEST_CHAIN.",
)

declare(
    "container",
    "previous-embedded-mismatch-supplied-verified",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_CHAIN",),
    build=lambda case_dir: _w5_target_with_previous(_w5_embedded_mismatch),
    args=FIX4_PREVIOUS_ARGS,
    limitations=("L_OFFLINE_CONTEXT", "L_PREVIOUS_CONTENT_UNVERIFIED"),
    notices_absent=("N_PREVIOUS_SIG_UNVERIFIED",),
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    notes="S1-FIX4 W5/§11.5 (order inside step (10)): the embedded "
    "previous/manifest.json is another manifest whose digest does not match "
    "previous_manifest.digest, while the supplied previous is the right one with a "
    "valid signature. Step (10) reads and verifies the supplied previous first, so "
    "L_PREVIOUS_CONTENT_UNVERIFIED is reported (one criterion) and the "
    "*_PREVIOUS_SIG_UNVERIFIED pair is not; the stage then reports its first "
    "failing check, the embedded digest mismatch: E_MANIFEST_CHAIN.",
)


def _w5_l2_blob_failure_files(case_dir: Path) -> dict[str, bytes]:
    files = _crafted_l2_files(case_dir, trust_name=None)
    files["container/blobs/sha256/" + hashlib.sha256(_W5_EXTRA_BLOB).hexdigest()] = _W5_EXTRA_BLOB
    return files


declare(
    "container",
    "timestamps-not-run-after-blob-failure",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_BLOB",),
    build=_w5_l2_blob_failure_files,
    args=("--keys", "@keyset"),
    expected_container={"level_claimed": "L2", "anchor_verified": False, "timestamps": []},
    limitations=("L_CHAIN_CLAIM_UNVERIFIED", "L_OFFLINE_CONTEXT"),
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    notes="S1-FIX4 W5/§14.5/§14.6: an L2 container with one well-formed receipt and "
    "no --tsa-trust (which alone would be E_TS_UNTRUSTED with "
    "L_TSA_TRUST_UNVERIFIED) also carries an unlisted blob, an invalid error at "
    "step (9). The timestamp phase (step 11) does not run: no E_TS_UNTRUSTED, no "
    "L_TSA_TRUST_UNVERIFIED, container.timestamps is [] and anchor_verified false.",
)

# ---------------------------------------------------------------------------
# S1-FIX4 W7: the zip check order (locate, parse, limits, remaining rules)
# ---------------------------------------------------------------------------


def _w7_over_limit_entries(*, directory_with_data: bool = False) -> list[tuple[str, bytes, int, int, int, int]]:
    entries = _zip_declared_standard_entries()
    payload = _deflated_tiny_payload()
    for label, declared in zip(("a", "b"), _TWO_BLOB_SIZES):
        entries.append(("blobs/sha256/" + label * 64, payload, 8, declared, 0, _STANDARD_ATTR))
    if directory_with_data:
        data = b"xy"
        entries.append(("readable/", data, 0, len(data), zlib.crc32(data) & 0xFFFFFFFF, _STANDARD_ATTR))
    return entries


def _w7_archive(variant: str) -> bytes:
    if variant == "directory-with-data":
        return _zip_declared_entries(_w7_over_limit_entries(directory_with_data=True))
    archive = bytearray(_zip_declared_entries(_w7_over_limit_entries()))
    first_central = _w2_central_offsets(bytes(archive))[0]
    if variant == "version-needed":
        struct.pack_into("<H", archive, first_central + 6, 64)
    elif variant == "disk-start":
        struct.pack_into("<H", archive, first_central + 34, 1)
    elif variant == "method":
        struct.pack_into("<H", archive, first_central + 10, 99)
    elif variant == "comment":
        comment = b"an archive comment"
        struct.pack_into("<H", archive, len(archive) - 2, len(comment))
        archive += comment
    elif variant == "prefix":
        # One leading byte with every offset shifted to match (the shape of a
        # self-extracting stub): the central directory still parses, so only
        # the phase-1 rule "a non-empty archive starts with a local header at
        # offset 0" rejects it.
        for central in _w2_central_offsets(bytes(archive)):
            local = struct.unpack_from("<I", archive, central + 42)[0]
            struct.pack_into("<I", archive, central + 42, local + 1)
        cd_offset = struct.unpack_from("<I", archive, len(archive) - 6)[0]
        struct.pack_into("<I", archive, len(archive) - 6, cd_offset + 1)
        archive = bytearray(b"\x00") + archive
    else:  # pragma: no cover - defensive
        raise SystemExit("unknown W7 variant %r" % (variant,))
    return bytes(archive)


for _variant, _code, _what in (
    ("version-needed", "E_CONTAINER_SIZE", "the first central-directory record's version needed to extract is 64 (a phase-4 rule)"),
    ("disk-start", "E_CONTAINER_SIZE", "the first central-directory record's disk number start is 1 (a phase-4 rule)"),
    ("method", "E_CONTAINER_SIZE", "the first central-directory record names compression method 99 (a phase-4 rule)"),
    ("comment", "E_CONTAINER_SIZE", "the end-of-central-directory record carries a non-empty archive comment (a phase-4 rule)"),
    ("directory-with-data", "E_CONTAINER_SIZE", "an entry named readable/ (a directory name) carries data (rule 4, a phase-4 rule)"),
    ("prefix", "E_CONTAINER_ZIP", "one byte precedes the first local file header while every offset is shifted to match, so the central directory parses but the archive fails phase 1 (a non-empty archive starts with a local header at offset 0) before the limits are reached"),
):
    declare(
        "container",
        "zip-over-limit-and-" + _variant,
        "container",
        "container.zip",
        "invalid",
        errors=(_code,),
        build=lambda case_dir, _variant=_variant: {"container.zip": _w7_archive(_variant)},
        records=[],
        notes="S1-FIX4 W7/§11.9 (order of the zip checks): the archive declares two "
        "600,000,000-byte blobs, above MAX_CONTAINER_UNCOMPRESSED_BYTES, and "
        + _what
        + ". Phases run locate -> parse central directory -> §13 limits -> remaining "
        "rules, so the container is invalid "
        + _code
        + " only.",
    )

# ---------------------------------------------------------------------------
# S1-FIX4 W9: the supplied-previous core checks pinned by vectors
# ---------------------------------------------------------------------------


def _w9_previous(variant: str) -> dict[str, bytes]:
    previous = _previous_container_internal()
    if variant == "signature-invalid":
        return _w5_bad_signature_previous()
    if variant == "attestation-digest-mismatch":
        sigfile = parse(previous["signatures/manifest.sig.json"])
        sigfile["digest"] = "sha256:" + "5a" * 32
        previous["signatures/manifest.sig.json"] = canonical(sigfile)
        return previous
    if variant == "attestation-symlink":
        previous["signatures/attestation-copy.json"] = previous.pop(
            "signatures/manifest.sig.json"
        )
        return previous
    raise SystemExit("unknown W9 variant %r" % (variant,))  # pragma: no cover


for _variant, _what, _links in (
    ("signature-invalid", "the attestation's ed25519 signature value is altered (one bit), so it does not verify over the previous manifest digest", ()),
    ("attestation-digest-mismatch", "the attestation's digest member names another manifest digest, while the signature still verifies over the real one", ()),
    ("attestation-symlink", "signatures/manifest.sig.json is a symbolic link to a valid attestation file in the same directory, not a regular file", (("previous-container/signatures/manifest.sig.json", "attestation-copy.json"),)),
):
    declare(
        "container",
        "previous-" + _variant,
        "container",
        "container",
        "invalid",
        errors=("E_MANIFEST_CHAIN",),
        build=lambda case_dir, _variant=_variant: _prepend_previous_directory(
            _chain_files_for_previous(_previous_container_internal()), _w9_previous(_variant)
        ),
        args=FIX4_PREVIOUS_ARGS,
        notices=("N_PREVIOUS_SIG_UNVERIFIED",),
        limitations=FIX4_UNLINKED,
        records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
        symlinks=_links,
        notes="S1-FIX4 W9/§11.5: in the supplied directory previous, "
        + _what
        + ". The link fails: invalid E_MANIFEST_CHAIN, the records are processed as "
        "usual and the previous signature counts as not re-verified.",
    )

# ---------------------------------------------------------------------------
# S1-FIX4 W3/W6: check 1 is a real DER check; the complete check order
# ---------------------------------------------------------------------------


def _w3_signed_data(tree: _DerNode) -> _DerNode:
    return tree.children[1].children[1].children[0]


def _w3_signer_info(tree: _DerNode) -> _DerNode:
    signed_data = _w3_signed_data(tree)
    return signed_data.children[-1].children[0]


def _w3_certificates(tree: _DerNode) -> _DerNode:
    for child in _w3_signed_data(tree).children:
        if child.tag == 0xA0:
            return child
    raise SystemExit("token has no certificates")


def _w3_node(tag: int, *, content: bytes | None = None, children: list[_DerNode] | None = None) -> _DerNode:
    return _DerNode(tag, content, children)


def _w3_oid(dotted: str) -> _DerNode:
    parts = [int(part) for part in dotted.split(".")]
    body = bytearray([40 * parts[0] + parts[1]])
    for value in parts[2:]:
        groups = []
        while True:
            groups.append(value & 0x7F)
            value >>= 7
            if not value:
                break
        for index, group in enumerate(reversed(groups)):
            body.append(group | (0x80 if index < len(groups) - 1 else 0))
    return _w3_node(0x06, content=bytes(body))


def _w3_int(value: int) -> _DerNode:
    return _w3_node(0x02, content=value.to_bytes(1, "big"))


def _w3_attribute(oid: str, values: list[_DerNode]) -> _DerNode:
    return _w3_node(0x30, children=[_w3_oid(oid), _w3_node(0x31, children=values)])


def _w3_sorted(nodes: list[_DerNode], *, reverse: bool) -> list[_DerNode]:
    ordered = sorted(nodes, key=_der_encode)
    if _der_encode(ordered[0]) == _der_encode(ordered[-1]):
        raise SystemExit("W3 SET OF fixture needs distinct components")
    return list(reversed(ordered)) if reverse else ordered


def _w3_digest_algorithms(tree: _DerNode, *, reverse: bool) -> None:
    algorithms = _w3_signed_data(tree).children[1]
    sha256 = algorithms.children[0]
    sha512 = _der_tree(_der_encode(sha256))
    oid = sha512.children[0]
    oid.content = oid.content[:-1] + b"\x03"
    algorithms.children = _w3_sorted([sha256, sha512], reverse=reverse)


def _w3_certificate_set(tree: _DerNode, *, reverse: bool) -> None:
    certificates = _w3_certificates(tree)
    extra = _der_tree(_crafted_certificate("wrong-anchor")[0])
    certificates.children = _w3_sorted(certificates.children + [extra], reverse=reverse)


def _w3_crls(tree: _DerNode, *, reverse: bool) -> None:
    signed_data = _w3_signed_data(tree)
    others = [
        _w3_node(0xA1, children=[_w3_oid("1.2.3.4.7.%d" % index), _w3_node(0x05, content=b"")])
        for index in (1, 2)
    ]
    crls = _w3_node(0xA1, children=_w3_sorted(others, reverse=reverse))
    position = next(index for index, child in enumerate(signed_data.children) if child.tag == 0xA0)
    signed_data.children.insert(position + 1, crls)


def _w3_unsigned_attrs(tree: _DerNode, attributes: list[_DerNode]) -> None:
    _w3_signer_info(tree).children.append(_w3_node(0xA1, children=attributes))


def _w3_two_unsigned(tree: _DerNode, *, reverse: bool) -> None:
    attributes = [_w3_attribute("1.2.3.4.8.%d" % index, [_w3_int(index)]) for index in (1, 2)]
    _w3_unsigned_attrs(tree, _w3_sorted(attributes, reverse=reverse))


def _w3_attr_values(tree: _DerNode, *, reverse: bool) -> None:
    values = _w3_sorted([_w3_int(1), _w3_int(2)], reverse=reverse)
    _w3_unsigned_attrs(tree, [_w3_attribute("1.2.3.4.8.3", values)])


def _w3_opaque_set(tree: _DerNode, *, reverse: bool) -> None:
    inner = _w3_node(0x31, children=_w3_sorted([_w3_int(1), _w3_int(2)], reverse=reverse))
    _w3_unsigned_attrs(tree, [_w3_attribute("1.2.3.4.8.4", [inner])])


def _w3_signed_attrs_unsorted(tree: _DerNode) -> None:
    signed_attrs = next(child for child in _w3_signer_info(tree).children if child.tag == 0xA0)
    signed_attrs.children = _w3_sorted(signed_attrs.children, reverse=True)


def _w3_rdn_certificate(*, reverse: bool) -> _DerNode:
    """The wrong-anchor certificate with a two-attribute subject RDN (never verified)."""
    certificate = _der_tree(_crafted_certificate("wrong-anchor")[0])
    tbs = certificate.children[0]
    subject = tbs.children[5]
    rdn = subject.children[0]
    organisation = _w3_node(
        0x30,
        children=[_w3_oid("2.5.4.10"), _w3_node(0x0C, content=b"Hyphaweave test")],
    )
    rdn.children = _w3_sorted(rdn.children + [organisation], reverse=reverse)
    return certificate


def _w3_rdn(tree: _DerNode, *, reverse: bool) -> None:
    certificates = _w3_certificates(tree)
    certificates.children = _w3_sorted(
        certificates.children + [_w3_rdn_certificate(reverse=reverse)], reverse=False
    )


def _w3_tst_info_edit(tree: _DerNode, edit: Callable[[_DerNode], None]) -> None:
    encapsulated = _w3_signed_data(tree).children[2]
    octets = encapsulated.children[1].children[0]
    tst_info = _der_tree(octets.content)
    edit(tst_info)
    octets.content = _der_encode(tst_info)


def _w3_tst_insert_ordering(value: bytes) -> Callable[[_DerNode], None]:
    def edit(tst_info: _DerNode) -> None:
        # TSTInfo: version, policy, messageImprint, serialNumber, genTime, ...
        tst_info.children.insert(5, _w3_node(0x01, content=value))

    return edit


def _w3_tst_serial_nonminimal(tst_info: _DerNode) -> None:
    serial = tst_info.children[3]
    if serial.tag != 0x02 or serial.content[0] >= 0x80:
        raise SystemExit("unexpected TSTInfo serialNumber encoding")
    serial.content = b"\x00" + serial.content


def _w3_tst_accuracy_millis_nonminimal(tst_info: _DerNode) -> None:
    accuracy = tst_info.children[5]
    if accuracy.tag != 0x30:
        raise SystemExit("unexpected TSTInfo accuracy position")
    millis = next(child for child in accuracy.children if child.tag == 0x80)
    millis.content = b"\x00" + millis.content


def _w3_indefinite(data: bytes) -> bytes:
    """Re-encode the outer TimeStampResp SEQUENCE with the BER indefinite form."""
    tree = _der_tree(data)
    body = b"".join(_der_encode(child) for child in tree.children)
    return b"\x30\x80" + body + b"\x00\x00"


def _w3_tree_mutation(mutate_tree: Callable[[_DerNode], None]) -> Callable[[bytes], bytes]:
    def mutation(data: bytes) -> bytes:
        tree = _der_tree(data)
        mutate_tree(tree)
        return _der_encode(tree)

    return mutation


def _w3_signer_info_version_2(tree: _DerNode) -> None:
    version = _w3_signer_info(tree).children[0]
    if version.content != b"\x01":
        raise SystemExit("unexpected SignerInfo version encoding")
    version.content = b"\x02"


def _x7_signer_certificate(tree: _DerNode) -> _DerNode:
    """The signer certificate of a crafted receipt (its only certificate)."""
    certificates = _w3_certificates(tree)
    if len(certificates.children) != 1:
        raise SystemExit("expected exactly the signer certificate")
    return certificates.children[0]


def _x7_signer_certificate_version_74(tree: _DerNode) -> None:
    """X7/M3: the signer certificate's TBSCertificate version is 74 (1e)."""
    version = _x7_signer_certificate(tree).children[0].children[0].children[0]
    if version.tag != 0x02 or version.content != b"\x02":
        raise SystemExit("unexpected certificate version encoding")
    version.content = b"\x4a"


def _x7_signer_extension_value_nonminimal(tree: _DerNode) -> None:
    """X7/M3: the signer certificate's basicConstraints value uses a long-form length."""
    tbs = _x7_signer_certificate(tree).children[0]
    extensions = next(child for child in tbs.children if child.tag == 0xA3).children[0]
    value = extensions.children[0].children[-1]
    if value.tag != 0x04:
        raise SystemExit("unexpected extension value encoding")
    inner = _der_tree(value.content)
    inner.force_long = True
    value.content = _der_encode(inner)


_W3_SCHEMA_EXPECTED = dict(
    errors=("E_TS_SCHEMA",),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container={
        "level_claimed": "L2",
        "level_verified": "L0",
        "anchor_verified": False,
        "timestamps": [
            {"index": 0, "path": "signatures/timestamp-1.tsr", "state": "invalid", "gen_time": None}
        ],
    },
    limitations=("L_CHAIN_CLAIM_UNVERIFIED", "L_OFFLINE_CONTEXT"),
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
)

_W3_WRONG_IMPRINT = b"\x5a" * 32

for _name, _mutation, _factory_kwargs, _why in (
    ("l2-ts-der-setof-digest-algorithms-unsorted",
     _w3_tree_mutation(lambda tree: _w3_digest_algorithms(tree, reverse=True)), {},
     "SignedData.digestAlgorithms (a universal SET OF) lists sha512 before sha256, which is not DER order (1a and 1c)"),
    ("l2-ts-der-setof-certificates-unsorted",
     _w3_tree_mutation(lambda tree: _w3_certificate_set(tree, reverse=True)), {},
     "SignedData.certificates ([0] IMPLICIT SET OF) carries the signer certificate and a second certificate out of DER order; only the schema re-encoding (1c) can see this implicitly tagged SET OF"),
    ("l2-ts-der-setof-crls-unsorted",
     _w3_tree_mutation(lambda tree: _w3_crls(tree, reverse=True)), {},
     "SignedData.crls ([1] IMPLICIT SET OF) carries two otherRevocationInfo entries out of DER order (1c)"),
    ("l2-ts-der-setof-signed-attrs-unsorted",
     _w3_tree_mutation(_w3_signed_attrs_unsorted), {},
     "SignerInfo.signedAttrs ([0] IMPLICIT SET OF) lists its attributes in descending instead of ascending DER order (1c)"),
    ("l2-ts-der-setof-unsigned-attrs-unsorted",
     _w3_tree_mutation(lambda tree: _w3_two_unsigned(tree, reverse=True)), {},
     "SignerInfo.unsignedAttrs ([1] IMPLICIT SET OF, outside the CMS signature) lists two attributes out of DER order (1c)"),
    ("l2-ts-der-setof-attr-values-unsorted",
     _w3_tree_mutation(lambda tree: _w3_attr_values(tree, reverse=True)), {},
     "an unsigned attribute's attrValues SET OF lists INTEGER 2 before INTEGER 1 (1a and 1c)"),
    ("l2-ts-der-setof-rdn-unsorted",
     _w3_tree_mutation(lambda tree: _w3_rdn(tree, reverse=True)), {},
     "a second, non-signer certificate's subject RelativeDistinguishedName (a SET OF AttributeTypeAndValue) is out of DER order"),
    ("l2-ts-der-setof-opaque-unsorted",
     _w3_tree_mutation(lambda tree: _w3_opaque_set(tree, reverse=True)), {},
     "the value of an unregistered unsigned attribute (type unknown to the verifier) is a universal SET whose INTEGER components are out of DER order; only the universal-rule scan (1a) can see inside a value of unknown type"),
    ("l2-ts-der-indefinite-length",
     _w3_indefinite, {},
     "the outer TimeStampResp SEQUENCE uses the BER indefinite length form (30 80 ... 00 00)"),
    ("l2-ts-der-trailing-byte",
     lambda data: data + b"\x00", {},
     "one byte follows the complete TimeStampResp, so the file is not exactly one DER object"),
    ("l2-ts-der-boolean-not-ff",
     _w3_tree_mutation(lambda tree: _w3_tst_info_edit(tree, _w3_tst_insert_ordering(b"\x01"))), {},
     "the TSTInfo carries ordering TRUE encoded as 0x01 instead of 0xFF (check 2 applies 1a-1c to the TSTInfo)"),
    ("l2-ts-der-integer-nonminimal",
     _w3_tree_mutation(lambda tree: _w3_tst_info_edit(tree, _w3_tst_serial_nonminimal)), {},
     "the TSTInfo serialNumber INTEGER carries a redundant leading 0x00 octet"),
    ("l2-ts-der-default-encoded",
     _w3_tree_mutation(lambda tree: _w3_tst_info_edit(tree, _w3_tst_insert_ordering(b"\x00"))), {},
     "the TSTInfo explicitly encodes ordering FALSE, its DEFAULT value, which DER omits; only the schema re-encoding of the TSTInfo (check 2 / 1c) can see this"),
    ("l2-ts-der-implicit-integer-nonminimal",
     _w3_tree_mutation(lambda tree: _w3_tst_info_edit(tree, _w3_tst_accuracy_millis_nonminimal)), {"accuracy": (1, 5, None)},
     "the TSTInfo accuracy.millis ([0] IMPLICIT INTEGER) is encoded with a redundant leading 0x00 octet; the context tag hides the INTEGER from the universal scan, the schema re-encoding (1c) rebuilds it"),
    ("l2-ts-signer-info-version-and-imprint",
     _w3_tree_mutation(_w3_signer_info_version_2), {"imprint_bytes": _W3_WRONG_IMPRINT},
     "SignerInfo.version is 2 (check 1) and messageImprint.hashedMessage is also wrong (check 4); W6: only the first failing check is reported, E_TS_SCHEMA, never E_TS_IMPRINT"),
    ("l2-ts-certificate-undecodable",
     _w3_tree_mutation(_x7_signer_certificate_version_74), {"imprint_bytes": _W3_WRONG_IMPRINT},
     "the signer certificate has TBSCertificate version 74, which does not decode as an X.509 certificate (1e; since S1-FIX5 X7/M3 1e decodes the signer certificate only), and the imprint is also wrong; W6: check 1 precedes check 4, so E_TS_SCHEMA"),
):
    declare(
        "integrity-levels",
        _name,
        "container",
        "container",
        "invalid",
        build=lambda case_dir, _mutation=_mutation, _factory_kwargs=_factory_kwargs: _crafted_l2_files(
            case_dir,
            tsr_factory=lambda imprint: _mutation(_crafted_tsr(imprint, **_factory_kwargs)),
        ),
        notes="S1-FIX4 W3/W6/§12.2 check 1: "
        + _why
        + ". The attestation digest is computed over the mutated bytes, so the "
        "receipt reaches decoding; check 1 completes before any later check, so the "
        "receipt is invalid with E_TS_SCHEMA and gen_time null, after the records "
        "were processed.",
        **_W3_SCHEMA_EXPECTED,
    )


def _w3_sorted_control(tree: _DerNode) -> None:
    _w3_digest_algorithms(tree, reverse=False)
    _w3_certificate_set(tree, reverse=False)
    _w3_crls(tree, reverse=False)
    attributes = [_w3_attribute("1.2.3.4.8.%d" % index, [_w3_int(index)]) for index in (1, 2)]
    attributes.append(_w3_attribute("1.2.3.4.8.3", _w3_sorted([_w3_int(1), _w3_int(2)], reverse=False)))
    attributes.append(
        _w3_attribute(
            "1.2.3.4.8.4",
            [_w3_node(0x31, children=_w3_sorted([_w3_int(1), _w3_int(2)], reverse=False))],
        )
    )
    _w3_unsigned_attrs(tree, _w3_sorted(attributes, reverse=False))


declare(
    "integrity-levels",
    "l2-ts-der-setof-sorted-control",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _crafted_l2_files(
        case_dir,
        tsr_factory=lambda imprint: _w3_tree_mutation(_w3_sorted_control)(_crafted_tsr(imprint)),
    ),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container=dict(level_claimed="L2", **L2_ANCHOR),
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    notes="S1-FIX4 W3/§12.2 check 1 (control): the receipt carries two digest "
    "algorithms, two certificates, two otherRevocationInfo entries and four "
    "unregistered unsigned attributes (one with two values, one whose value is a "
    "universal SET of unknown type), every SET OF in ascending DER order. Strict "
    "DER accepts it: the receipt verifies against the anchor, anchor_verified is "
    "true and the container is valid.",
)


def _w6_renewal_broken_with_schema_files(case_dir: Path) -> dict[str, bytes]:
    def builder(imprint: bytes) -> list[tuple[str, bytes, str | None]]:
        first = _crafted_tsr(imprint)
        second = _der_signed_data_version_18(_crafted_tsr(_sha256_bytes(first + imprint)))
        return [
            ("signatures/timestamp-1.tsr", first, None),
            ("signatures/timestamp-2.tsr", second, "signatures/timestamp-9.tsr"),
        ]

    files = _build_timestamped_container(SIMPLE_RECORDS(), builder, level="L2")
    return {**wrap(files), TSA_CERT_NAME: TSA_CERT()}


declare(
    "integrity-levels",
    "l2-renewal-broken-with-schema-receipt",
    "container",
    "container",
    "invalid",
    errors=("E_TS_RENEWAL",),
    build=_w6_renewal_broken_with_schema_files,
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container={
        "level_claimed": "L2",
        "anchor_verified": False,
        "timestamps": [
            {"index": 0, "path": "signatures/timestamp-1.tsr", "state": "invalid", "gen_time": None},
            {"index": 1, "path": "signatures/timestamp-2.tsr", "state": "invalid", "gen_time": None},
        ],
    },
    limitations=("L_CHAIN_CLAIM_UNVERIFIED", "L_OFFLINE_CONTEXT"),
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    notes="S1-FIX4 W6/§12.2 (complete check order, docs/open-questions.md §6 entry "
    "26): the second receipt's renews names an unlisted path (a broken chain, check "
    "14) and that receipt also has SignedData.version 18 (a check-1 failure). The "
    "chain shape is decided before any receipt is decoded, so only E_TS_RENEWAL is "
    "reported and every receipt is invalid with gen_time null.",
)


# S1-FIX4 W3/W5/W6: further pins (eContent scan, extension values, key type,
# cross-record stop).


def _w3_tst_opaque(tst_info: _DerNode) -> None:
    """Append TSTInfo.tsa = otherName whose value (an open type) is an unsorted SET."""
    value = _w3_node(0x31, children=_w3_sorted([_w3_int(1), _w3_int(2)], reverse=True))
    other_name = _w3_node(
        0xA0, children=[_w3_oid("1.2.3.4.9.1"), _w3_node(0xA0, children=[value])]
    )
    tst_info.children.append(_w3_node(0xA0, children=[other_name]))


for _name, _mutation, _why in (
    ("l2-ts-der-tstinfo-opaque-unsorted",
     _w3_tree_mutation(lambda tree: _w3_tst_info_edit(tree, _w3_tst_opaque)),
     "the TSTInfo carries a tsa name of the otherName form whose value (an open type unknown to the verifier) is a universal SET with its INTEGER components out of DER order; only the universal-rule scan of the TSTInfo (check 2, 1a) can see it"),
    ("l2-ts-der-extension-value-nonminimal",
     _w3_tree_mutation(_x7_signer_extension_value_nonminimal),
     "the signer certificate's basicConstraints extnValue holds its SEQUENCE with a long-form length for a short body (30 81 ..); an extension value is itself DER (1e, signer certificate only since S1-FIX5 X7/M3), although its OCTET STRING hides it from the receipt-level scan"),
):
    declare(
        "integrity-levels",
        _name,
        "container",
        "container",
        "invalid",
        build=lambda case_dir, _mutation=_mutation: _crafted_l2_files(
            case_dir, tsr_factory=lambda imprint: _mutation(_crafted_tsr(imprint))
        ),
        notes="S1-FIX4 W3/§12.2 check 1: "
        + _why
        + ". The receipt is invalid with E_TS_SCHEMA and gen_time null.",
        **_W3_SCHEMA_EXPECTED,
    )

# ---------------------------------------------------------------------------
# S1-FIX5 X1: check 1c follows X.690 and the module definitions only
# (decision 2026-11-12 #1). Every positive receipt here is fully re-signed with
# the published test TSA key: messageDigest is recomputed over the (possibly
# edited) eContent and the signature over DER(SET OF signedAttrs) is renewed.
# ---------------------------------------------------------------------------

_X1_MESSAGE_DIGEST_OID = _w3_oid("1.2.840.113549.1.9.4").content
_X1_SIGNING_CERTIFICATE_V2_OID = _w3_oid("1.2.840.113549.1.9.16.2.47").content


def _x1_resign(tree: _DerNode, sign: Callable[[bytes], bytes] | None = None) -> None:
    """Recompute messageDigest and re-sign the signed attributes in place.

    ``sign`` defaults to the test TSA's RSA PKCS#1 v1.5 SHA-256 signature.
    """
    signed_data = _w3_signed_data(tree)
    econtent = signed_data.children[2].children[1].children[0]
    signer_info = _w3_signer_info(tree)
    position = next(
        index for index, child in enumerate(signer_info.children) if child.tag == 0xA0
    )
    signed_attrs = signer_info.children[position]
    for attribute in signed_attrs.children:
        if attribute.children[0].content == _X1_MESSAGE_DIGEST_OID:
            attribute.children[1].children[0].content = _sha256_bytes(econtent.content)
    signed_attrs.children = sorted(signed_attrs.children, key=_der_encode)
    to_be_signed = _der_encode(_DerNode(0x31, None, signed_attrs.children))
    signature = next(
        child for child in signer_info.children[position + 1 :] if child.tag == 0x04
    )
    signature.content = (
        sign(to_be_signed)
        if sign is not None
        else _tsa_private_key().sign(
            to_be_signed, crypto_padding.PKCS1v15(), crypto_hashes.SHA256()
        )
    )


def _x1_resigned(mutate_tree: Callable[[_DerNode], None]) -> Callable[[bytes], bytes]:
    def mutation(data: bytes) -> bytes:
        tree = _der_tree(data)
        mutate_tree(tree)
        _x1_resign(tree)
        return _der_encode(tree)

    return mutation


def _x1_ess_hash_algorithm(with_null: bool) -> Callable[[_DerNode], None]:
    """Write ESSCertIDv2.hashAlgorithm explicitly: {sha256, NULL} or {sha256}."""

    def edit(tree: _DerNode) -> None:
        signed_attrs = next(
            child for child in _w3_signer_info(tree).children if child.tag == 0xA0
        )
        attribute = next(
            child
            for child in signed_attrs.children
            if child.children[0].content == _X1_SIGNING_CERTIFICATE_V2_OID
        )
        ess_cert_id = attribute.children[1].children[0].children[0].children[0]
        if ess_cert_id.children[0].tag != 0x04:
            raise SystemExit("ESSCertIDv2 already carries a hashAlgorithm")
        algorithm = [_w3_oid("2.16.840.1.101.3.4.2.1")]
        if with_null:
            algorithm.append(_w3_node(0x05, content=b""))
        ess_cert_id.children.insert(0, _w3_node(0x30, children=algorithm))

    return edit


def _x1_gen_time(text: bytes) -> Callable[[_DerNode], None]:
    def edit(tree: _DerNode) -> None:
        def set_gen_time(tst_info: _DerNode) -> None:
            gen_time = tst_info.children[4]
            if gen_time.tag != 0x18 or gen_time.content != b"20261101000000Z":
                raise SystemExit("unexpected TSTInfo genTime encoding")
            gen_time.content = text

        _w3_tst_info_edit(tree, set_gen_time)

    return edit


def _x1_unsigned_value(identifier: bytes, content: bytes) -> Callable[[_DerNode], None]:
    """One unregistered unsigned attribute whose single value has this identifier."""

    def edit(tree: _DerNode) -> None:
        value = _DerNode(identifier, content, None)
        _w3_unsigned_attrs(tree, [_w3_attribute("1.2.3.4.8.5", [value])])

    return edit


_X1_VALID_EXPECTED = dict(
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
)

for _name, _edit, _gen_time, _why in (
    ("l2-ts-der-ess-hash-algorithm-sha256-null", _x1_ess_hash_algorithm(True),
     "2026-11-01T00:00:00.000Z",
     "the ESS signingCertificateV2 ESSCertIDv2 writes hashAlgorithm {id-sha256, NULL} "
     "explicitly. The DEFAULT of that component (RFC 5035) is {algorithm id-sha256} "
     "with no parameters, encoded 30 0b 06 09 60 86 48 01 65 03 04 02 01; "
     "{id-sha256, NULL} is a different value, so DER must encode it"),
    ("l2-ts-der-unsigned-attr-context-tag-value", _x1_unsigned_value(b"\x80", b"\x01"),
     "2026-11-01T00:00:00.000Z",
     "an unregistered unsigned attribute carries one value encoded 80 01 01 (a "
     "context-specific [0] primitive). The value of an attribute type the verifier "
     "does not decode is an open type: only its TLV framing is judged (1a), it is "
     "never handed to a type decoder"),
    ("l2-ts-der-unsigned-attr-application-200-value",
     _x1_unsigned_value(b"\x5f\x81\x48", b"\x01"),
     "2026-11-01T00:00:00.000Z",
     "an unregistered unsigned attribute carries one value encoded 5f 81 48 01 01 "
     "([APPLICATION 200], high-tag-number form). The open-type value is judged by "
     "its TLV framing only"),
    ("l2-ts-der-high-tag-number-inner-zero-group",
     _x1_unsigned_value(b"\x5f\x81\x80\x00", b"\x01"),
     "2026-11-01T00:00:00.000Z",
     "an unregistered unsigned attribute carries one value encoded 5f 81 80 00 01 01: "
     "[APPLICATION 16384] in its minimal high-tag-number form. X.690 §8.1.2.4 only "
     "forbids 0x80 as the first subsequent octet; the inner 0x80 and 0x00 groups are "
     "part of the minimal base-128 form"),
    ("l2-ts-der-gentime-seven-fraction-digits", _x1_gen_time(b"20261101000000.1234567Z"),
     "2026-11-01T00:00:00.123Z",
     "the TSTInfo genTime is 20261101000000.1234567Z. X.690 §11.7 limits neither "
     "the number of fractional digits nor requires fewer; the time is compared as its "
     "raw DER form, never through a time object. gen_time floors to milliseconds "
     "(check 13): 00.123"),
):
    declare(
        "integrity-levels",
        _name,
        "container",
        "container",
        "valid",
        build=lambda case_dir, _edit=_edit: _crafted_l2_files(
            case_dir, tsr_factory=lambda imprint: _x1_resigned(_edit)(_crafted_tsr(imprint))
        ),
        expected_container={
            "level_claimed": "L2",
            "level_verified": "L0",
            "anchor_verified": True,
            "timestamps": [
                {
                    "index": 0,
                    "path": "signatures/timestamp-1.tsr",
                    "state": "verified",
                    "gen_time": _gen_time,
                }
            ],
        },
        notes="S1-FIX5 X1/§12.2 check 1c: "
        + _why
        + ". The receipt is fully re-signed with the test TSA key (messageDigest "
        "recomputed, signature over the signed attributes renewed), so it is strict "
        "DER, the CMS signature verifies and the container is valid.",
        **_X1_VALID_EXPECTED,
    )

for _name, _edit, _why in (
    ("l2-ts-der-ess-hash-algorithm-default-encoded", _x1_ess_hash_algorithm(False),
     "the ESSCertIDv2 writes hashAlgorithm {algorithm id-sha256} explicitly, which is "
     "exactly its DEFAULT value (RFC 5035), so DER omits it (X.690 §11.5)"),
    ("l2-ts-der-gentime-fraction-trailing-zero", _x1_gen_time(b"20261101000000.1230Z"),
     "the TSTInfo genTime is 20261101000000.1230Z; X.690 §11.7.3 omits trailing "
     "fractional zeros"),
    ("l2-ts-der-high-tag-number-nonminimal",
     _x1_unsigned_value(b"\x5f\x80\x81\x48", b"\x01"),
     "an unregistered unsigned attribute carries a value whose identifier 5f 80 81 48 "
     "starts its high-tag-number form with the octet 0x80, which X.690 §8.1.2.4.2 "
     "forbids (a non-minimal tag number)"),
):
    declare(
        "integrity-levels",
        _name,
        "container",
        "container",
        "invalid",
        build=lambda case_dir, _edit=_edit: _crafted_l2_files(
            case_dir, tsr_factory=lambda imprint: _x1_resigned(_edit)(_crafted_tsr(imprint))
        ),
        notes="S1-FIX5 X1/§12.2 check 1: "
        + _why
        + ". The receipt is otherwise fully re-signed with the test TSA key, so the "
        "only defect is the DER rule: invalid with E_TS_SCHEMA and gen_time null.",
        **_W3_SCHEMA_EXPECTED,
    )


_W6_EC_CERT: dict[str, bytes] = {}


def _w6_ec_certificate() -> bytes:
    """A timeStamping certificate carrying an EC P-256 key (test material only)."""
    cached = _W6_EC_CERT.get("der")
    if cached is not None:
        return cached
    from cryptography.hazmat.primitives.asymmetric import ec as crypto_ec

    private = crypto_ec.derive_private_key(
        int.from_bytes(hashlib.sha256(b"weave-record/1/test-tsa-ec").digest(), "big")
        % (2**255),
        crypto_ec.SECP256R1(),
    )
    spki = asn1_x509.PublicKeyInfo.load(
        private.public_key().public_bytes(
            crypto_serialization.Encoding.DER,
            crypto_serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    name = asn1_x509.Name.build({"common_name": "Hyphaweave H0 test TSA (EC key)"})
    tbs = asn1_x509.TbsCertificate()
    tbs["version"] = "v3"
    tbs["serial_number"] = 7006
    tbs["signature"] = {"algorithm": "sha256_rsa"}
    tbs["issuer"] = name
    validity = asn1_x509.Validity()
    validity["not_before"] = asn1_x509.Time({"utc_time": datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)})
    validity["not_after"] = asn1_x509.Time({"general_time": datetime.datetime(2126, 1, 1, tzinfo=datetime.timezone.utc)})
    tbs["validity"] = validity
    tbs["subject"] = name
    tbs["subject_public_key_info"] = spki
    tbs["extensions"] = [
        asn1_x509.Extension({"extn_id": "key_usage", "critical": True, "extn_value": asn1_x509.KeyUsage({"digital_signature"})}),
        asn1_x509.Extension({"extn_id": "extended_key_usage", "critical": True, "extn_value": asn1_x509.ExtKeyUsageSyntax(["time_stamping"])}),
    ]
    signature = _tsa_private_key().sign(tbs.dump(), crypto_padding.PKCS1v15(), crypto_hashes.SHA256())
    certificate = asn1_x509.Certificate()
    certificate["tbs_certificate"] = tbs
    certificate["signature_algorithm"] = {"algorithm": "sha256_rsa"}
    certificate["signature_value"] = signature
    _W6_EC_CERT["der"] = certificate.dump()
    return _W6_EC_CERT["der"]


declare(
    "integrity-levels",
    "l2-ts-signature-key-type-mismatch",
    "container",
    "container",
    "invalid",
    errors=("E_TS_CMS",),
    build=lambda case_dir: _crafted_l2_files(
        case_dir,
        tsr_factory=lambda imprint: _crafted_tsr(imprint, certificate_der=_w6_ec_certificate()),
    ),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container={
        "level_claimed": "L2",
        "level_verified": "L0",
        "anchor_verified": False,
        "timestamps": [
            {"index": 0, "path": "signatures/timestamp-1.tsr", "state": "invalid", "gen_time": "2026-11-01T00:00:00.000Z"}
        ],
    },
    limitations=("L_CHAIN_CLAIM_UNVERIFIED", "L_OFFLINE_CONTEXT"),
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    notes="S1-FIX4 W6/§12.2 (complete check order): the signer certificate carries an "
    "EC P-256 key while signerInfo.signatureAlgorithm is the allowlisted RSA PKCS#1 "
    "v1.5 identifier. Check 6 (allowlist) passes; the RSA algorithm cannot use the EC "
    "key, so the CMS signature does not verify: check 10, E_TS_CMS (not E_TS_CERT). "
    "Checks 1-4 passed, so gen_time is reported.",
)


# ---------------------------------------------------------------------------
# S1-FIX5 X6 (decision 2026-11-12 #2): the parameters of the signer's
# digestAlgorithm and signatureAlgorithm have a fixed form per algorithm
# (RFC 5754 §2, RFC 3370 §3.2, RFC 4055/8017, RFC 5758 §3.2). Every receipt is
# fully re-signed (RSA with the test TSA key; ECDSA deterministically, RFC 6979,
# with the test EC key of _w6_ec_certificate).
# ---------------------------------------------------------------------------


def _x6_ec_private_key() -> Any:
    """The private key of _w6_ec_certificate (same derivation, test material only)."""
    from cryptography.hazmat.primitives.asymmetric import ec as crypto_ec

    return crypto_ec.derive_private_key(
        int.from_bytes(hashlib.sha256(b"weave-record/1/test-tsa-ec").digest(), "big")
        % (2**255),
        crypto_ec.SECP256R1(),
    )


def _x6_ec_sign(data: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric import ec as crypto_ec

    return _x6_ec_private_key().sign(
        data, crypto_ec.ECDSA(crypto_hashes.SHA256(), deterministic_signing=True)
    )


_X6_NULL = b"null"
_X6_ABSENT = b"absent"
_X6_OTHER = b"other"  # an empty OCTET STRING: well framed, neither absent nor NULL


def _x6_algorithm(which: str, oid: str, parameters: bytes) -> Callable[[_DerNode], None]:
    """Rewrite the signer's digestAlgorithm or signatureAlgorithm."""

    def edit(tree: _DerNode) -> None:
        signer_info = _w3_signer_info(tree)
        if which == "digest":
            algorithm = signer_info.children[2]
        else:
            position = next(
                index for index, child in enumerate(signer_info.children) if child.tag == 0xA0
            )
            algorithm = signer_info.children[position + 1]
        if algorithm.tag != 0x30:
            raise SystemExit("unexpected SignerInfo algorithm position")
        children = [_w3_oid(oid)]
        if parameters == _X6_NULL:
            children.append(_w3_node(0x05, content=b""))
        elif parameters == _X6_OTHER:
            children.append(_w3_node(0x04, content=b""))
        algorithm.children = children

    return edit


def _x6_ec_pem() -> bytes:
    return crypto_x509.load_der_x509_certificate(_w6_ec_certificate()).public_bytes(
        crypto_serialization.Encoding.PEM
    )


def _x6_files(case_dir: Path, edit: Callable[[_DerNode], None], *, ec: bool) -> dict[str, bytes]:
    def factory(imprint: bytes) -> bytes:
        if not ec:
            return _x1_resigned(edit)(_crafted_tsr(imprint))
        tree = _der_tree(_crafted_tsr(imprint, certificate_der=_w6_ec_certificate()))
        edit(tree)
        _x1_resign(tree, _x6_ec_sign)
        return _der_encode(tree)

    files = _crafted_l2_files(case_dir, tsr_factory=factory)
    if ec:
        files[TSA_CERT_NAME] = _x6_ec_pem()
    return files


_X6_SHA256 = "2.16.840.1.101.3.4.2.1"
_X6_RSA = "1.2.840.113549.1.1.1"
_X6_SHA256_RSA = "1.2.840.113549.1.1.11"
_X6_ECDSA_SHA256 = "1.2.840.10045.4.3.2"

for _name, _edit, _ec, _why in (
    ("l2-ts-signer-digest-params-absent", _x6_algorithm("digest", _X6_SHA256, _X6_ABSENT), False,
     "signerInfo.digestAlgorithm is {id-sha256} with the parameters absent; RFC 5754 §2 "
     "requires accepting both the absent and the NULL form for SHA-2"),
    ("l2-ts-signer-digest-params-null", _x6_algorithm("digest", _X6_SHA256, _X6_NULL), False,
     "signerInfo.digestAlgorithm is {id-sha256, NULL} (the other RFC 5754 §2 form) and "
     "signatureAlgorithm is {rsaEncryption, NULL} (RFC 3370 §3.2)"),
    ("l2-ts-signer-sha256-rsa-params-null", _x6_algorithm("signature", _X6_SHA256_RSA, _X6_NULL), False,
     "signerInfo.signatureAlgorithm is {sha256WithRSAEncryption, NULL}; RFC 4055 §5 / "
     "RFC 5754 §3.2 make NULL the parameters a signer writes (absent is accepted too, X7)"),
    ("l2-ts-signer-ecdsa-params-absent", _x6_algorithm("signature", _X6_ECDSA_SHA256, _X6_ABSENT), True,
     "the receipt is signed with ECDSA P-256 (deterministic, RFC 6979) and "
     "signerInfo.signatureAlgorithm is {ecdsa-with-SHA256} with the parameters absent, as "
     "RFC 5758 §3.2 requires; the trust anchor is the EC test certificate"),
):
    declare(
        "integrity-levels",
        _name,
        "container",
        "container",
        "valid",
        build=lambda case_dir, _edit=_edit, _ec=_ec: _x6_files(case_dir, _edit, ec=_ec),
        expected_container={
            "level_claimed": "L2",
            "level_verified": "L0",
            "anchor_verified": True,
            "timestamps": [
                {
                    "index": 0,
                    "path": "signatures/timestamp-1.tsr",
                    "state": "verified",
                    "gen_time": "2026-11-01T00:00:00.000Z",
                }
            ],
        },
        notes="S1-FIX5 X6/§12.2 check 1c (decision 2026-11-12 #2): "
        + _why
        + ". The receipt is fully re-signed, so it is strict DER, its signer algorithm "
        "parameters have the permitted form, the CMS signature verifies and the container "
        "is valid.",
        **_X1_VALID_EXPECTED,
    )

for _name, _edit, _ec, _why in (
    ("l2-ts-signer-digest-params-other", _x6_algorithm("digest", _X6_SHA256, _X6_OTHER), False,
     "signerInfo.digestAlgorithm is {id-sha256} with an empty OCTET STRING as parameters; "
     "SHA-2 parameters must be absent or NULL (RFC 5754 §2)"),
    ("l2-ts-signer-rsa-params-absent", _x6_algorithm("signature", _X6_RSA, _X6_ABSENT), False,
     "signerInfo.signatureAlgorithm is {rsaEncryption} with the parameters absent; they "
     "must be NULL (RFC 3370 §3.2)"),
    ("l2-ts-signer-rsa-params-other", _x6_algorithm("signature", _X6_RSA, _X6_OTHER), False,
     "signerInfo.signatureAlgorithm is {rsaEncryption} with an empty OCTET STRING as "
     "parameters; they must be NULL (RFC 3370 §3.2)"),
    ("l2-ts-signer-ecdsa-params-null", _x6_algorithm("signature", _X6_ECDSA_SHA256, _X6_NULL), True,
     "the ECDSA-signed receipt writes signatureAlgorithm {ecdsa-with-SHA256, NULL}; the "
     "parameters must be absent (RFC 5758 §3.2)"),
    ("l2-ts-signer-ecdsa-params-other", _x6_algorithm("signature", _X6_ECDSA_SHA256, _X6_OTHER), True,
     "the ECDSA-signed receipt writes an empty OCTET STRING as signatureAlgorithm "
     "parameters; they must be absent (RFC 5758 §3.2)"),
):
    declare(
        "integrity-levels",
        _name,
        "container",
        "container",
        "invalid",
        build=lambda case_dir, _edit=_edit, _ec=_ec: _x6_files(case_dir, _edit, ec=_ec),
        notes="S1-FIX5 X6/§12.2 check 1 (decision 2026-11-12 #2): "
        + _why
        + ". The receipt is otherwise fully re-signed, so the only defect is the "
        "parameters form, a check-1 structure rule: invalid with E_TS_SCHEMA and "
        "gen_time null.",
        **_W3_SCHEMA_EXPECTED,
    )


# ---------------------------------------------------------------------------
# S1-FIX5 X7 (decision 2026-11-12 #3): time forms matched as whole strings (H1),
# sha*WithRSAEncryption parameters absent or NULL (M1), exactly one SignerInfo
# (M2), 1e decodes the signer certificate only (M3). Every receipt is fully
# re-signed with the test TSA key.
# ---------------------------------------------------------------------------


def _x7_second_signer_info(tree: _DerNode) -> None:
    """Add a second SignerInfo (a copy with another signature value), in DER order."""
    signer_infos = _w3_signed_data(tree).children[-1]
    copy = _der_tree(_der_encode(signer_infos.children[0]))
    copy.children[-1].content = b"\x00" * len(copy.children[-1].content)
    if copy.children[-1].tag != 0x04:
        raise SystemExit("unexpected SignerInfo layout")
    signer_infos.children = _w3_sorted(signer_infos.children + [copy], reverse=False)


def _x7_signer_info_version_3(tree: _DerNode) -> None:
    version = _w3_signer_info(tree).children[0]
    if version.tag != 0x02 or version.content != b"\x01":
        raise SystemExit("unexpected SignerInfo version encoding")
    version.content = b"\x03"


def _x7_non_signer(edit: Callable[[_DerNode], None]) -> Callable[[_DerNode], None]:
    """Add a second, non-signer certificate (the wrong-anchor test certificate), edited."""

    def mutate(tree: _DerNode) -> None:
        certificate = _der_tree(_crafted_certificate("wrong-anchor")[0])
        edit(certificate)
        certificates = _w3_certificates(tree)
        certificates.children = _w3_sorted(certificates.children + [certificate], reverse=False)

    return mutate


def _x7_outer_algorithm_params_octets(certificate: _DerNode) -> None:
    algorithm = certificate.children[1]
    if algorithm.tag != 0x30 or len(algorithm.children) != 2 or algorithm.children[1].tag != 0x05:
        raise SystemExit("unexpected certificate signatureAlgorithm encoding")
    algorithm.children[1] = _w3_node(0x04, content=b"")


def _x7_version_74(certificate: _DerNode) -> None:
    version = certificate.children[0].children[0].children[0]
    if version.tag != 0x02 or version.content != b"\x02":
        raise SystemExit("unexpected certificate version encoding")
    version.content = b"\x4a"


def _x7_extension_value_long_form(certificate: _DerNode) -> None:
    tbs = certificate.children[0]
    extensions = next(child for child in tbs.children if child.tag == 0xA3).children[0]
    value = extensions.children[0].children[-1]
    inner = _der_tree(value.content)
    inner.force_long = True
    value.content = _der_encode(inner)


for _name, _edit, _why in (
    ("l2-ts-signer-sha256-rsa-params-absent", _x6_algorithm("signature", _X6_SHA256_RSA, _X6_ABSENT),
     "signerInfo.signatureAlgorithm is {sha256WithRSAEncryption} with the parameters absent; "
     "RFC 4055 §5 and RFC 5754 §3.2 require accepting the absent form as well as NULL "
     "(X7/M1 corrects the X6 table)"),
    ("l2-ts-non-signer-certificate-params-octet-string", _x7_non_signer(_x7_outer_algorithm_params_octets),
     "a second, non-signer certificate writes its outer signatureAlgorithm parameters as 04 00 "
     "(an empty OCTET STRING). Since X7/M3 every component of SignedData.certificates other "
     "than the signer certificate is an open type, judged by its TLV framing only and never "
     "handed to a certificate decoder"),
    ("l2-ts-non-signer-certificate-undecodable", _x7_non_signer(_x7_version_74),
     "a second, non-signer certificate has TBSCertificate version 74; it is an open type "
     "(X7/M3), so only its framing is judged"),
    ("l2-ts-non-signer-extension-value-nonminimal", _x7_non_signer(_x7_extension_value_long_form),
     "a second, non-signer certificate's basicConstraints extnValue uses a long-form length; "
     "1e reads the signer certificate's extension values only (X7/M3), and the OCTET STRING "
     "content of an open type is not decoded"),
):
    declare(
        "integrity-levels",
        _name,
        "container",
        "container",
        "valid",
        build=lambda case_dir, _edit=_edit: _crafted_l2_files(
            case_dir, tsr_factory=lambda imprint: _x1_resigned(_edit)(_crafted_tsr(imprint))
        ),
        expected_container={
            "level_claimed": "L2",
            "level_verified": "L0",
            "anchor_verified": True,
            "timestamps": [
                {
                    "index": 0,
                    "path": "signatures/timestamp-1.tsr",
                    "state": "verified",
                    "gen_time": "2026-11-01T00:00:00.000Z",
                }
            ],
        },
        notes="S1-FIX5 X7/§12.2 check 1 (decision 2026-11-12 #3): "
        + _why
        + ". The receipt is fully re-signed with the test TSA key, so the CMS signature "
        "verifies and the container is valid.",
        **_X1_VALID_EXPECTED,
    )

for _name, _edit, _why in (
    ("l2-ts-der-unsigned-attr-utctime-trailing-newline",
     _x1_unsigned_value(b"\x17", b"260101000000Z\n"),
     "an unregistered unsigned attribute carries the UTCTime 260101000000Z followed by a line "
     "feed (17 0e .. 5a 0a); 1a requires exactly YYMMDDHHMMSSZ, matched against the whole "
     "content (X7/H1)"),
    ("l2-ts-der-unsigned-attr-gentime-trailing-newline",
     _x1_unsigned_value(b"\x18", b"20260101000000Z\n"),
     "an unregistered unsigned attribute carries the GeneralizedTime 20260101000000Z followed "
     "by a line feed; 1a matches the DER form against the whole content (X7/H1)"),
    ("l2-ts-der-gentime-trailing-newline", _x1_gen_time(b"20261101000000Z\n"),
     "the TSTInfo genTime is 20261101000000Z followed by a line feed; 1a and 1c match the DER "
     "form against the whole content (X7/H1)"),
    ("l2-ts-signer-sha256-rsa-params-other", _x6_algorithm("signature", _X6_SHA256_RSA, _X6_OTHER),
     "signerInfo.signatureAlgorithm is {sha256WithRSAEncryption} with an empty OCTET STRING as "
     "parameters; they must be absent or NULL (RFC 4055 §5, RFC 5754 §3.2)"),
    ("l2-ts-signer-info-version-3-with-issuer-serial", _x7_signer_info_version_3,
     "SignerInfo.version is 3 while its sid is issuerAndSerialNumber; RFC 5652 §5.3 requires "
     "version 1 for that sid form (X7, docs/open-questions.md §6 entry 35)"),
    ("l2-ts-signer-info-count-two", _x7_second_signer_info,
     "SignedData.signerInfos carries a second SignerInfo (a copy with another signature value, "
     "outside every signature) in DER order; RFC 3161 §2.4.2 allows no signature other than "
     "the TSA's, so check 1d requires exactly one SignerInfo (X7/M2)"),
):
    declare(
        "integrity-levels",
        _name,
        "container",
        "container",
        "invalid",
        build=lambda case_dir, _edit=_edit: _crafted_l2_files(
            case_dir, tsr_factory=lambda imprint: _x1_resigned(_edit)(_crafted_tsr(imprint))
        ),
        notes="S1-FIX5 X7/§12.2 check 1 (decision 2026-11-12 #3): "
        + _why
        + ". The receipt is otherwise fully re-signed with the test TSA key, so the only "
        "defect is that check-1 rule: invalid with E_TS_SCHEMA and gen_time null.",
        **_W3_SCHEMA_EXPECTED,
    )


def _w5_cross_record_stop_files() -> dict[str, bytes]:
    files = recordlib.build_container(
        [
            recordlib.note(
                "w5-local-only-note",
                labels={"sensitivity": "local-only"},
                salt=keyutil.b64url_encode(bytes(range(16))),
            )
        ]
    )
    files["blobs/sha256/" + hashlib.sha256(_W5_EXTRA_BLOB).hexdigest()] = _W5_EXTRA_BLOB
    return wrap(files)


declare(
    "container",
    "cross-record-failure-stops-pipeline",
    "container",
    "container",
    "invalid",
    errors=("E_LABEL_LOCAL_ONLY_EXPORTED",),
    build=lambda case_dir: _w5_cross_record_stop_files(),
    args=("--keys", "@keyset"),
    limitations=("L_LABELS_ARE_CLAIMS", "L_OFFLINE_CONTEXT", "L_UNKNOWN_KIND_OPAQUE"),
    records=({"id": "w5-local-only-note", "verdict": "valid", "errors": []},),
    notes="S1-FIX4 W5/§14.5: the container exports a local-only record (an invalid "
    "cross-record error at step (8)) and also carries an unlisted blob (step 9). The "
    "pipeline stops at step (8): E_MANIFEST_BLOB is not reported; the record verdict "
    "already produced is reported as usual.",
)


# ---------------------------------------------------------------------------
# S2 (decision 2026-11-15 #8): the H1 findings F38-F69 closed in the
# specification. Every expected conclusion below is hand-written from the
# specification text; positive receipts are fully re-signed with the test TSA
# key (the P-384 receipts with a deterministic RFC 6979 ECDSA key).
# ---------------------------------------------------------------------------

_S2_ARGS = ("--keys", "@keyset")
_S2_L2_ARGS = ("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME)


def _s2_declaration(
    name: str,
    *,
    record_id: str,
    key_type: str = "device",
    owner: str = "human-1",
    recorded_at: str = recordlib.T0,
    valid_from: str | None = None,
    cosigners: Sequence[str] = ("human-1",),
) -> dict[str, Any]:
    """A declaration of a derived key, self-signed and cosigned by *cosigners*."""
    private, public, key_id = derived_key(name)
    body: dict[str, Any] = {
        "algorithm": "ed25519",
        "key": key_id,
        "key_type": key_type,
        "public_key": keyutil.b64url_encode(public),
    }
    if owner is not None:
        body["owner"] = kid(owner)
    if valid_from is not None:
        body["valid_from"] = valid_from
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
    signatures += [recordlib.sig_entry(record, cosigner) for cosigner in cosigners]
    return {**record, "sigs": sorted(signatures, key=lambda entry: entry["key"])}


def _s2_revocation(
    revoked_key_id: str,
    *,
    reason: str,
    effective_at: str,
    record_id: str,
    signer: str = "human-1",
) -> dict[str, Any]:
    record = recordlib.build_record(
        kind="weave.key.revoked",
        id=record_id,
        actor=recordlib.actor(signer),
        body={"effective_at": effective_at, "key": revoked_key_id, "reason": reason},
        stage="accepted",
        recorded_at=effective_at,
        origin_instance=revoked_key_id,
    )
    return recordlib.signed(record, signer)


def _s2_derived_note(name: str, record_id: str, recorded_at: str, key_type: str = "device") -> dict[str, Any]:
    private, _public, key_id = derived_key(name)
    record = recordlib.build_record(
        kind="example.note",
        id=record_id,
        actor={"type": key_type, "key": key_id},
        body={"text": "signed by a derived key"},
        recorded_at=recorded_at,
        origin_instance=key_id,
    )
    return {**record, "sigs": [_derived_signature(private, key_id, record)]}


def _s2_sigs(record: dict[str, Any], states: dict[str, str]) -> list[dict[str, str]]:
    """The expected ``sigs`` report of *record*: its entries in order, with states."""
    return [{"key": entry["key"], "state": states[entry["key"]]} for entry in record["sigs"]]


# -- A1: F61-1/F38: a declaration of a compromised key is rescued only by a
#    verified, trusted, usable receipt (§9.4) ------------------------------------

_S2_COMPROMISED = "s2-compromised-device"


def _s2_compromised_records(*, effective_at: str = recordlib.T1) -> list[dict[str, Any]]:
    declaration = _s2_declaration(_S2_COMPROMISED, record_id="key-declared-s2-compromised-device")
    revocation = _s2_revocation(
        derived_key(_S2_COMPROMISED)[2],
        reason="key-compromise",
        effective_at=effective_at,
        record_id="key-revoked-s2-compromised-device",
    )
    return [declaration, revocation]


def _s2_compromised_files(
    *,
    tsr: Callable[[bytes], bytes] | None = None,
    anchor: bytes | None = None,
    level: str = "L2",
    effective_at: str = recordlib.T1,
    sigfile_edit: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
) -> dict[str, bytes]:
    records = _s2_compromised_records(effective_at=effective_at)
    if level != "L2":
        return container(records, level=level)
    factory = tsr if tsr is not None else _crafted_tsr
    files = _build_timestamped_container(
        records, lambda imprint: [("signatures/timestamp-1.tsr", factory(imprint), None)]
    )
    if sigfile_edit is not None:
        files = mutate_sigfile(files, sigfile_edit)
    result = wrap(files)
    if anchor is not None:
        result[TSA_CERT_NAME] = anchor
    return result


def _s2_declaration_expected(verdict: str, errors: Sequence[str], self_state: str) -> dict[str, Any]:
    declaration = _s2_compromised_records()[0]
    states = {kid("human-1"): "valid", derived_key(_S2_COMPROMISED)[2]: self_state}
    return {
        "id": "key-declared-s2-compromised-device",
        "verdict": verdict,
        "errors": list(errors),
        "sigs": _s2_sigs(declaration, states),
    }


_S2_REVOCATION_VALID = {"id": "key-revoked-s2-compromised-device", "verdict": "valid", "errors": []}

declare(
    "key-lifecycle",
    "declaration-compromised-rescued",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _s2_compromised_files(anchor=TSA_CERT()),
    args=_S2_L2_ARGS,
    records=(_s2_declaration_expected("valid", (), "valid"), _S2_REVOCATION_VALID),
    notes="S2/F38/F61-1 control (§9.4 case 1): a device declaration recorded at T0 is "
    "self-signed by a key with a valid key-compromise revocation effective at T1. §9.4 "
    "judges every signature by the key, the declaration's own self-signature included; "
    "the container's verified, trusted receipt (genTime T0, no accuracy) is strictly "
    "before T1, so the self-signature is rescued and the declaration is valid.",
)

for _name, _tsr, _anchor, _container_errors, _verdict, _why in (
    ("declaration-compromised-receipt-trailing-byte",
     lambda imprint: _crafted_tsr(imprint) + b"\x00", True, ("E_TS_SCHEMA",), "invalid",
     "the only receipt carries one byte after its TimeStampResp (check 1, E_TS_SCHEMA)"),
    ("declaration-compromised-receipt-signature-tampered",
     lambda imprint: _crafted_tsr(imprint, tamper_signature=True), True, ("E_TS_CMS",), "invalid",
     "the only receipt's CMS signature is tampered (check 10, E_TS_CMS)"),
    ("declaration-compromised-receipt-imprint-mismatch",
     lambda imprint: _crafted_tsr(imprint, imprint_bytes=b"\x11" * 32), True, ("E_TS_IMPRINT",),
     "invalid", "the only receipt time-stamps another imprint (check 4, E_TS_IMPRINT)"),
    ("declaration-compromised-receipt-no-anchor",
     None, False, ("E_TS_UNTRUSTED",), "unverifiable",
     "no --tsa-trust anchor is supplied, so the receipt is present but untrusted (check 15)"),
    ("declaration-compromised-receipt-unusable-accuracy",
     lambda imprint: _crafted_tsr(imprint, accuracy=(86_401, None, None)), True,
     ("E_TS_UNTRUSTED",), "unverifiable",
     "the only receipt's accuracy is 86,401 s, above MAX_TS_ACCURACY: unusable evidence "
     "(check 13, T3)"),
):
    declare(
        "key-lifecycle",
        _name,
        "container",
        "container",
        _verdict,
        errors=tuple(sorted(set(_container_errors) | {"E_TS_UNTRUSTED"})),
        build=lambda case_dir, _tsr=_tsr, _anchor=_anchor: _s2_compromised_files(
            tsr=_tsr, anchor=TSA_CERT() if _anchor else None
        ),
        args=_S2_L2_ARGS if _anchor else _S2_ARGS,
        records=(
            _s2_declaration_expected("unverifiable", ("E_TS_UNTRUSTED",), "unverified"),
            _S2_REVOCATION_VALID,
        ),
        notes="S2/F61-1 (security; §9.4 case 2): the same container as "
        "declaration-compromised-rescued, but "
        + _why
        + ". Receipts are present and none is verified, trusted and usable, so the "
        "declaration's self-signature by the compromised key is unverifiable "
        "E_TS_UNTRUSTED (sigs state unverified, §14.6): a receipt that fails cannot rescue "
        "a declaration any more than any other record the key signed.",
    )

declare(
    "key-lifecycle",
    "declaration-compromised-receipt-after-compromise",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_COMPROMISED",),
    build=lambda case_dir: _s2_compromised_files(
        anchor=TSA_CERT(), effective_at="2026-10-31T00:00:00.000Z"
    ),
    args=_S2_L2_ARGS,
    records=(
        {
            "id": "key-declared-s2-compromised-device",
            "verdict": "invalid",
            "errors": ["E_KEY_COMPROMISED"],
        },
        _S2_REVOCATION_VALID,
    ),
    notes="S2/F38 (§9.4 case 3): the compromise takes effect on 2026-10-31, before the "
    "only receipt's genTime (2026-11-01). The receipt is verified, trusted and usable but "
    "does not place the declaration strictly before the compromise, so the declaration's "
    "self-signature is invalid E_KEY_COMPROMISED.",
)

declare(
    "key-lifecycle",
    "declaration-compromised-l0",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_COMPROMISED",),
    build=lambda case_dir: _s2_compromised_files(level="L0"),
    args=_S2_ARGS,
    records=(
        _s2_declaration_expected("invalid", ("E_KEY_COMPROMISED",), "unverified"),
        _S2_REVOCATION_VALID,
    ),
    notes="S2/F38 (§9.4 case 3): an L0 container has no timestamp evidence, so the "
    "declaration's self-signature by a key with a valid key-compromise revocation is "
    "invalid E_KEY_COMPROMISED.",
)


def _s2_window_files() -> dict[str, bytes]:
    declaration = _s2_declaration(
        "s2-window-device",
        record_id="key-declared-s2-window-device",
        recorded_at=recordlib.T1,
        valid_from=recordlib.T2,
    )
    note_record = _s2_derived_note("s2-window-device", "s2-window-note", recordlib.T3)
    return container([declaration, note_record])


declare(
    "key-lifecycle",
    "declaration-before-own-valid-from",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_EXPIRED",),
    build=lambda case_dir: _s2_window_files(),
    args=_S2_ARGS,
    records=(
        {"id": "key-declared-s2-window-device", "verdict": "invalid", "errors": ["E_KEY_EXPIRED"]},
        {"id": "s2-window-note", "verdict": "valid", "errors": []},
    ),
    notes="S2/F38 (§9.4 validity windows, §9.1 rule 6): the declaration is recorded at T1 "
    "and declares valid_from T2, so its own self-signature is outside the window: the "
    "declaration is invalid E_KEY_EXPIRED. The §9.4 judgement of the declaration's own "
    "signatures decides its verdict only; the declaration still supplies the key's "
    "material, class and window (§5.3), so a note signed by the key at T3 is valid.",
)


def _s2_cosigner_retired_files() -> dict[str, bytes]:
    revocation = recordlib.key_revocation(
        "human-2", reason="retired", effective_at=recordlib.T1, signer_name="human-1",
        record_id="key-revoked-s2-human-2",
    )
    declaration = _s2_declaration(
        "s2-cosigned-device",
        record_id="key-declared-s2-cosigned-device",
        owner="human-2",
        recorded_at=recordlib.T2,
        cosigners=("human-2",),
    )
    return container([revocation, declaration])


declare(
    "key-lifecycle",
    "declaration-cosigner-retired",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_REVOKED",),
    build=lambda case_dir: _s2_cosigner_retired_files(),
    args=_S2_ARGS,
    records=(
        {"id": "key-declared-s2-cosigned-device", "verdict": "invalid", "errors": ["E_KEY_REVOKED"]},
        {"id": "key-revoked-s2-human-2", "verdict": "valid", "errors": []},
    ),
    notes="S2/F38 (§9.4): the owner cosignature of a device declaration recorded at T2 is "
    "made by human-2, retired at T1. §9.4 judges every signature of the declaration, so the "
    "declaration is invalid E_KEY_REVOKED. (Whether such a declaration still establishes "
    "trust for its key is an open question for the founder; this case pins the "
    "declaration's own verdict only.)",
)


def _s2_rotation_old_retired_files() -> dict[str, bytes]:
    old_private, old_public, old_id = derived_key("s2-rotation-old")
    new_private, new_public, new_id = derived_key("s2-rotation-new")
    declaration = _s2_declaration("s2-rotation-old", record_id="key-declared-s2-rotation-old")
    revocation = _s2_revocation(
        old_id, reason="retired", effective_at=recordlib.T1,
        record_id="key-revoked-s2-rotation-old",
    )
    rotation = recordlib.build_record(
        kind="weave.key.rotated",
        id="key-rotated-s2-after-retirement",
        actor={"type": "device", "key": old_id},
        body={
            "new_key": new_id,
            "new_public_key": keyutil.b64url_encode(new_public),
            "old_key": old_id,
            "old_public_key": keyutil.b64url_encode(old_public),
        },
        stage="accepted",
        recorded_at=recordlib.T2,
        origin_instance=old_id,
    )
    rotation = {
        **rotation,
        "sigs": sorted(
            [
                _derived_signature(old_private, old_id, rotation),
                _derived_signature(new_private, new_id, rotation),
            ],
            key=lambda entry: entry["key"],
        ),
    }
    return container([declaration, revocation, rotation])


declare(
    "key-lifecycle",
    "rotation-old-key-retired",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_REVOKED",),
    build=lambda case_dir: _s2_rotation_old_retired_files(),
    args=_S2_ARGS,
    records=(
        {"id": "key-rotated-s2-after-retirement", "verdict": "invalid", "errors": ["E_KEY_REVOKED"]},
        {"id": "key-revoked-s2-rotation-old", "verdict": "valid", "errors": []},
    ),
    notes="S2/F38 (§9.4): a rotation recorded at T2 is signed by its old key, retired at "
    "T1. The old-key signature is verified against the rotation's own old_public_key, and "
    "§9.4 still judges it: the rotation is invalid E_KEY_REVOKED.",
)



# -- §14.5 steps (4)-(5) across entries: every entry is judged ----------------


def _s2_two_signer_files(*, unknown_second: bool) -> dict[str, bytes]:
    first_private, _first_public, first_id = derived_key("s2-two-signer-a")
    second_name = "s2-two-signer-undeclared" if unknown_second else "s2-two-signer-b"
    second_private, _second_public, second_id = derived_key(second_name)
    declarations = [_s2_declaration("s2-two-signer-a", record_id="key-declared-s2-two-signer-a")]
    if not unknown_second:
        declarations.append(
            _s2_declaration("s2-two-signer-b", record_id="key-declared-s2-two-signer-b")
        )
    record = recordlib.build_record(
        kind="example.note",
        id="s2-two-signer-note",
        actor={"type": "device", "key": first_id},
        body={"text": "two signers"},
        recorded_at=recordlib.T1,
        origin_instance=first_id,
    )
    entries = {
        first_id: _derived_signature(first_private, first_id, record),
        second_id: _derived_signature(second_private, second_id, record),
    }
    tampered = dict(entries[first_id])
    raw = bytearray(keyutil.b64url_decode(tampered["value"], expected_len=64))
    raw[32] ^= 0x01  # the low bit of S: R stays canonical and S stays below L
    tampered["value"] = keyutil.b64url_encode(bytes(raw))
    entries[first_id] = tampered
    if not first_id < second_id:
        raise SystemExit("the tampered entry must come first in key order")
    record = {**record, "sigs": [entries[first_id], entries[second_id]]}
    return container(declarations + [record])


declare(
    "key-lifecycle",
    "signature-entries-all-judged",
    "container",
    "container",
    "invalid",
    errors=("E_SIG_INVALID",),
    build=lambda case_dir: _s2_two_signer_files(unknown_second=False),
    args=_S2_ARGS,
    records=(
        {
            "id": "s2-two-signer-note",
            "verdict": "invalid",
            "errors": ["E_SIG_INVALID"],
            "sigs": [
                {"key": derived_key("s2-two-signer-a")[2], "state": "invalid"},
                {"key": derived_key("s2-two-signer-b")[2], "state": "valid"},
            ],
        },
    ),
    notes="S2 (§4.4 step 2: every ed25519 entry is verified; §14.6): the note's first "
    "entry fails the equation and its second entry is a good signature by a declared key. "
    "Every entry is judged and reports its own state (invalid, valid); the first failing "
    "entry decides the record's code, E_SIG_INVALID.",
)

declare(
    "key-lifecycle",
    "signature-key-resolution-before-equation",
    "container",
    "container",
    "invalid",
    errors=("E_SIG_INVALID",),
    build=lambda case_dir: _s2_two_signer_files(unknown_second=True),
    args=_S2_ARGS,
    records=(
        {
            "id": "s2-two-signer-note",
            "verdict": "invalid",
            "errors": ["E_SIG_INVALID"],
            "sigs": [
                {"key": derived_key("s2-two-signer-a")[2], "state": "invalid"},
                {"key": derived_key("s2-two-signer-undeclared")[2], "state": "unverified"},
            ],
        },
    ),
    notes="S2 (§14.5 steps (4) and (5)), expectation corrected by S2-FIX1 T2 (decision "
    "2026-11-15 #13; §4.4 step 2): the note's first entry is by a declared key and fails "
    "the equation; its second entry names a key that nothing declares. Key resolution "
    "(step (4)) covers every entry and every resolved entry is verified, and an invalid "
    "outcome beats an unverifiable one: a known-key signature that fails the equation makes "
    "the record invalid E_SIG_INVALID, and an entry by an undeclared key cannot lower it to "
    "unverifiable E_KEY_UNKNOWN. Every entry still reports its state (invalid, unverified).",
)

# -- F51 / F61-2 / F67: crash sites of the candidate key state ------------------


def _s2_body_variant(record: dict[str, Any], signers: Sequence[Any], edit: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    body = dict(record["body"])
    edit(body)
    unsigned = {name: value for name, value in record.items() if name != "sigs"}
    unsigned["body"] = body
    signatures = []
    for signer in signers:
        if isinstance(signer, str):
            signatures.append(recordlib.sig_entry(unsigned, signer))
        else:
            private, key_id = signer
            signatures.append(_derived_signature(private, key_id, unsigned))
    return {**unsigned, "sigs": sorted(signatures, key=lambda entry: entry["key"])}


def _s2_crash_files(target: str, edit: Callable[[dict[str, Any]], None]) -> dict[str, bytes]:
    private, _public, key_id = derived_key("s2-crash-device")
    declaration = _s2_declaration("s2-crash-device", record_id="key-declared-s2-crash-device")
    # A revocation of the declaration-target cases is "retired" at T1, after the
    # declaration's T0 signatures, so §9.4 does not decide them before step (6).
    revocation = _s2_revocation(
        key_id, reason="key-compromise" if target == "revocation" else "retired",
        effective_at=recordlib.T1,
        record_id="key-revoked-s2-crash-device",
    )
    if target == "declaration":
        declaration = _s2_body_variant(declaration, [(private, key_id), "human-1"], edit)
    else:
        revocation = _s2_body_variant(revocation, ["human-1"], edit)
    return container([declaration, revocation])


def _s2_set(member: str, value: Any) -> Callable[[dict[str, Any]], None]:
    return lambda body: body.__setitem__(member, value)


def _s2_drop(member: str) -> Callable[[dict[str, Any]], None]:
    return lambda body: body.pop(member)


for _name, _target, _edit, _record_id, _verdict, _errors, _why in (
    ("crash-declaration-without-key", "declaration", _s2_drop("key"),
     "key-declared-s2-crash-device", "unverifiable", ("E_KEY_UNKNOWN",),
     "F51: the declaration has no body.key. Its self-signature names a key that nothing "
     "in the context declares, so key resolution (step (4)) makes it unverifiable "
     "E_KEY_UNKNOWN"),
    ("crash-declaration-without-key-type", "declaration", _s2_drop("key_type"),
     "key-declared-s2-crash-device", "invalid", ("E_KIND_BODY_SCHEMA",),
     "F67: the declaration has no body.key_type: E_KIND_BODY_SCHEMA"),
    ("crash-revocation-without-key", "revocation", _s2_drop("key"),
     "key-revoked-s2-crash-device", "invalid", ("E_KIND_BODY_SCHEMA",),
     "F51: the revocation has no body.key: E_KIND_BODY_SCHEMA"),
    ("crash-revocation-without-effective-at", "revocation", _s2_drop("effective_at"),
     "key-revoked-s2-crash-device", "invalid", ("E_KIND_BODY_SCHEMA",),
     "F67: the revocation has no body.effective_at: E_KIND_BODY_SCHEMA"),
    ("crash-revocation-effective-at-space", "revocation",
     _s2_set("effective_at", "2026-11-02 03:04:05.678Z"),
     "key-revoked-s2-crash-device", "invalid", ("E_KIND_BODY_SCHEMA",),
     "F61-2: body.effective_at has a space instead of T (§2.8): E_KIND_BODY_SCHEMA"),
    ("crash-revocation-effective-at-no-fraction", "revocation",
     _s2_set("effective_at", "2026-11-02T03:04:05Z"),
     "key-revoked-s2-crash-device", "invalid", ("E_KIND_BODY_SCHEMA",),
     "F67: body.effective_at has no fractional seconds (§2.8 requires exactly three): "
     "E_KIND_BODY_SCHEMA"),
    ("crash-revocation-effective-at-day-31", "revocation",
     _s2_set("effective_at", "2026-11-31T03:04:05.678Z"),
     "key-revoked-s2-crash-device", "invalid", ("E_KIND_BODY_SCHEMA",),
     "F67: body.effective_at names 31 November, not a calendar date (§2.8): "
     "E_KIND_BODY_SCHEMA"),
    ("crash-revocation-effective-at-second-60", "revocation",
     _s2_set("effective_at", "2026-11-02T03:04:60.000Z"),
     "key-revoked-s2-crash-device", "invalid", ("E_KIND_BODY_SCHEMA",),
     "F67: body.effective_at has second 60, which §2.8 does not permit: "
     "E_KIND_BODY_SCHEMA"),
):
    declare(
        "key-lifecycle",
        _name,
        "container",
        "container",
        _verdict,
        errors=_errors,
        build=lambda case_dir, _target=_target, _edit=_edit: _s2_crash_files(_target, _edit),
        args=_S2_ARGS,
        records=({"id": _record_id, "verdict": _verdict, "errors": list(_errors)},),
        notes="S2 (§13, §15: a verifier reports, it never crashes): "
        + _why
        + ". The record sits in a container next to a declaration and a key-compromise "
        "revocation of the same key, so the input reaches every stage that reads lifecycle "
        "bodies before their kind schema is checked.",
    )


# -- F61-3: rotation key-id grammar -------------------------------------------


def _s2_rotation_key_id_files(edit: Callable[[dict[str, Any]], None]) -> dict[str, bytes]:
    rotation = key_rotation(record_id="key-rotated-s2-key-id", old_name="human-1", new_name="key-new",
                            signers=("human-1", "key-new"))
    rotation = _s2_body_variant(rotation, ["human-1", "key-new"], edit)
    return container([rotation])


for _name, _edit, _why in (
    ("rotation-old-key-malformed", _s2_set("old_key", "ed25519:XYZ"),
     "body.old_key is a string that is not a key id"),
    ("rotation-new-key-wrong-type", _s2_set("new_key", 7),
     "body.new_key is a number"),
):
    declare(
        "key-lifecycle",
        _name,
        "container",
        "container",
        "invalid",
        errors=("E_KIND_BODY_SCHEMA",),
        build=lambda case_dir, _edit=_edit: _s2_rotation_key_id_files(_edit),
        args=_S2_ARGS,
        records=(
            {"id": "key-rotated-s2-key-id", "verdict": "invalid", "errors": ["E_KIND_BODY_SCHEMA"],
             "sigs": []},
        ),
        notes="S2/F61-3 (§9.2 rule 2, §14.5): "
        + _why
        + ". new_key and old_key are key ids of the body table; their grammar is part "
        "of the structural body check that runs before signature verification (T13) and "
        "precedes the key-material rule, which compares a public key with a well-formed "
        "key id: E_KIND_BODY_SCHEMA, not E_KEY_ROTATION_KEYS or a key-resolution outcome; "
        "no signature check runs (sigs []).",
    )


# -- F46 / F39 / F50 -------------------------------------------------------------


def _s2_unknown_alg_declaration() -> dict[str, Any]:
    declaration = recordlib.key_declaration("human-2", cosigners=("human-1",))
    return {**declaration, "sigs": [{**entry, "alg": "ed25519-x"} for entry in declaration["sigs"]]}


declare(
    "key-lifecycle",
    "declared-only-unknown-algorithm-entries",
    "record",
    "record.json",
    "unverifiable",
    errors=("E_SIG_UNVERIFIABLE",),
    build=lambda case_dir: {"record.json": canonical(_s2_unknown_alg_declaration())},
    args=_S2_ARGS,
    records=(
        {"id": "key-declared-human-2", "verdict": "unverifiable", "errors": ["E_SIG_UNVERIFIABLE"]},
    ),
    notes="S2/F46 (§4.4 step 5): every sigs entry of the declaration uses the unknown "
    "algorithm ed25519-x, so no known-algorithm signature by a declared key exists at all. "
    "Step 5 applies, not the dedicated code of step 4: the required signer (the declared "
    "key) is declared, so the record is unverifiable E_SIG_UNVERIFIABLE.",
)


def _s2_bad_public_key_and_key_files() -> dict[str, bytes]:
    declaration = recordlib.key_declaration(
        "human-2", record_id="key-declared-s2-bad-pk", public_key_b64="AAAA",
        cosigners=("human-1",),
    )
    declaration = _s2_body_variant(declaration, ["human-2", "human-1"], _s2_set("key", 9007199254740991))
    return container([declaration])


declare(
    "key-lifecycle",
    "declared-public-key-before-body-key",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_PUBLIC_KEY",),
    build=lambda case_dir: _s2_bad_public_key_and_key_files(),
    args=_S2_ARGS,
    records=(
        {"id": "key-declared-s2-bad-pk", "verdict": "invalid", "errors": ["E_KEY_PUBLIC_KEY"],
         "sigs": []},
    ),
    notes="S2/F50/F39 (§9.1 rule 1, T1, §14.5): the declaration's public_key is the "
    "malformed AAAA and its body.key is a number. A malformed public_key is decided before "
    "E_KIND_BODY_SCHEMA and before key resolution (step (4)), so it wins over the body.key "
    "defect, and no signature check runs: sigs is [] (§14.6).",
)


# -- F42: N_KEY_TOFU when the equation fails ----------------------------------


def _s2_tofu_failed_equation_files() -> dict[str, bytes]:
    declaration = _s2_declaration("s2-tofu-device", record_id="key-declared-s2-tofu-device")
    note_record = _s2_derived_note("s2-tofu-device", "s2-tofu-note", recordlib.T1)
    signature = dict(note_record["sigs"][0])
    signature["value"] = keyutil.b64url_encode(_tampered_signature_value(signature["value"]))
    note_record = {**note_record, "sigs": [signature]}
    return container([declaration, note_record])


declare(
    "key-lifecycle",
    "tofu-on-failed-equation",
    "container",
    "container",
    "invalid",
    errors=("E_SIG_INVALID",),
    build=lambda case_dir: _s2_tofu_failed_equation_files(),
    args=_S2_ARGS,
    records=(
        {"id": "s2-tofu-note", "verdict": "invalid", "errors": ["E_SIG_INVALID"],
         "notices": ["N_KEY_TOFU"]},
    ),
    notes="S2/F42 (§14.6 N_KEY_TOFU): the note's only signature is verified with key "
    "material from a container declaration (context material) and fails the equation. "
    "The check was context-trusted, so the record carries N_KEY_TOFU \"even if that "
    "signature or the record then fails\".",
)



def _s2_manifest_tofu_failed_files() -> dict[str, bytes]:
    files = _manifest_context_trusted_tofu_files()
    path = "container/signatures/manifest.sig.json"
    sigfile = parse(files[path])
    entry = dict(sigfile["signatures"][0])
    raw = bytearray(keyutil.b64url_decode(entry["value"], expected_len=64))
    raw[32] ^= 0x01
    entry["value"] = keyutil.b64url_encode(bytes(raw))
    sigfile["signatures"] = [entry] + list(sigfile["signatures"][1:])
    return {**files, path: canonical(sigfile)}


declare(
    "container",
    "manifest-tofu-failed-equation",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_SIG_INVALID",),
    build=lambda case_dir: _s2_manifest_tofu_failed_files(),
    args=_S2_ARGS,
    limitations=("L_OFFLINE_CONTEXT",),
    records=[],
    notes="S2/F42 (§11.5, §14.9 TOFU predicate): the manifest of "
    "container/manifest-context-trusted-tofu, signed by a container-declared device key, "
    "with its signature value altered. A manifest signature contributes to "
    "L_KEY_TRUST_TOFU only when the context material verified its equation; the failed "
    "equation is E_MANIFEST_SIG_INVALID, the pipeline stops at step (5) and the report "
    "carries no L_KEY_TRUST_TOFU.",
)

# -- F44: a present but structurally invalid reference target --------------------


def _s2_reference_target_files(target_edit: Callable[[dict[str, Any]], None]) -> dict[str, bytes]:
    target = note("s2-ref-target", body={"text": "target"})
    target_edit(target)
    source = note(
        "s2-ref-source",
        refs=[{"rel": "derived_from", "ref": recordlib.make_ref(
            kid("human-1"), "s2-ref-target", recordlib.record_digest(target)
        )}],
    )
    return container([target, source])


for _name, _edit, _target_error, _state, _notice, _why in (
    ("reference-to-structurally-invalid-target", lambda record: record["actor"].pop("key"),
     "E_ENV_ACTOR_KEY", "unverifiable", "N_REF_UNVERIFIABLE",
     "the target keeps a well-formed origin and id but fails its envelope (actor.key "
     "missing). A record with that origin and id is present but is itself not valid: "
     "unverifiable (§6.3)"),
    ("reference-to-target-with-malformed-origin",
     lambda record: record["origin"].__setitem__("instance", "ed25519:zz"),
     "E_ENV_ORIGIN", "missing", "N_REF_MISSING",
     "the target's own origin is malformed, so it has no identity: no record with the "
     "referenced origin and id exists, missing (§6.3, S2 sentence for tier b)"),
):
    declare(
        "container",
        _name,
        "container",
        "container",
        "invalid",
        errors=(_target_error,),
        build=lambda case_dir, _edit=_edit: _s2_reference_target_files(_edit),
        args=_S2_ARGS,
        notices=(_notice,),
        records=(
            {"id": "s2-ref-source", "verdict": "valid", "errors": [],
             "refs": [{"index": 0, "rel": "derived_from", "state": _state}]},
        ),
        notes="S2/F44: the source record references a target by its (well-formed) origin, "
        "id and the target's digest; " + _why + ". The container is invalid because of the "
        "target record itself.",
    )


# -- container-level findings: F40, F49, F54, F55, F56, F60 ----------------------

_S2_PREFIX_ARCHIVE = _zip_with_prefix()["container.zip"]

declare(
    "container",
    "zip-prefix-input-identity",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_ZIP",),
    build=lambda case_dir: {"container.zip": _S2_PREFIX_ARCHIVE},
    expected_input={
        "sha256": "sha256:" + hashlib.sha256(_S2_PREFIX_ARCHIVE).hexdigest(),
        "size": len(_S2_PREFIX_ARCHIVE),
    },
    records=[],
    notes="S2/F40 (§14.6 input): for a zip container the input identity is the archive "
    "bytes, without exception: an archive that does not start with a local file header "
    "(32 prefix bytes, §11.9 phase 1, E_CONTAINER_ZIP) still reports the SHA-256 and size "
    "of the whole file.",
)


def _s2_entry_and_crc_archive() -> bytes:
    archive = bytearray(_zip_readable_extra("readable/../escape"))
    position = archive.find(b'{"actor"')
    if position < 0:
        raise SystemExit("record member data not found in the stored archive")
    archive[position + 20] ^= 0x01
    return bytes(archive)


declare(
    "container",
    "zip-entry-check-before-crc",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_ENTRY",),
    build=lambda case_dir: {"container.zip": _s2_entry_and_crc_archive()},
    args=_S2_ARGS,
    records=[],
    notes="S2/F49 (§11.9 W7): the archive has a readable/../escape entry and one byte of a "
    "record member's stored data is flipped (its CRC no longer matches). Entry paths are "
    "judged for every entry before any content is decompressed or CRC-checked, so the "
    "container is E_CONTAINER_ENTRY, not E_CONTAINER_ZIP.",
)


def _s2_unlisted_receipt_l0_files() -> dict[str, bytes]:
    files = container(SIMPLE_RECORDS())
    files["container/signatures/timestamp-1.tsr"] = b""
    return files


declare(
    "container",
    "unlisted-receipt-file-l0",
    "container",
    "container",
    "invalid",
    errors=("E_TS_FILE",),
    build=lambda case_dir: _s2_unlisted_receipt_l0_files(),
    args=_S2_ARGS,
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    notes="S2/F54 (§11.3: every .tsr file in signatures/ MUST appear in timestamps): an L0 "
    "container whose attestation lists no receipt carries an empty "
    "signatures/timestamp-1.tsr. An unlisted receipt file is a file-check failure of the "
    "timestamp phase (§12.2 W6 step 1), E_TS_FILE, whatever the claimed level.",
)


def _s2_unlisted_receipt_l2_files(case_dir: Path) -> dict[str, bytes]:
    files = _crafted_l2_files(case_dir)
    files["container/signatures/timestamp-2.tsr"] = files["container/signatures/timestamp-1.tsr"]
    return files


declare(
    "integrity-levels",
    "l2-unlisted-receipt-file",
    "container",
    "container",
    "invalid",
    errors=("E_TS_FILE",),
    build=_s2_unlisted_receipt_l2_files,
    args=_S2_L2_ARGS,
    expected_container={
        "level_claimed": "L2",
        "anchor_verified": False,
        "timestamps": [
            {"index": 0, "path": "signatures/timestamp-1.tsr", "state": "invalid", "gen_time": None}
        ],
    },
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    notes="S2/F54 (§11.3, §12.2 W6 step 1): a valid L2 container carries a second, unlisted "
    "copy of its receipt as signatures/timestamp-2.tsr. The file checks fail (E_TS_FILE), "
    "so every listed receipt is invalid with gen_time null and nothing below runs.",
)


def _s2_l1_with_timestamp_files() -> dict[str, bytes]:
    files = _build_timestamped_container(
        SIMPLE_RECORDS(),
        lambda imprint: [("signatures/timestamp-1.tsr", _crafted_tsr(imprint), None)],
        level="L1",
    )
    return {**wrap(files), TSA_CERT_NAME: TSA_CERT()}


declare(
    "integrity-levels",
    "l1-lists-timestamp",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_LEVEL",),
    build=lambda case_dir: _s2_l1_with_timestamp_files(),
    args=_S2_L2_ARGS,
    records=[],
    notes="S2/F56 (§11.3: timestamps is empty for L0/L1, E_MANIFEST_LEVEL otherwise): an L1 "
    "manifest whose attestation lists a receipt fails the level/chain completeness step "
    "(§14.5 step (6)), before any record is verified.",
)


def _s2_misnamed_oversize_files() -> dict[str, bytes]:
    internal = recordlib.build_container(SIMPLE_RECORDS())
    internal["records/" + "AB" * 32 + ".json"] = b"{" + b" " * (_T16_OVERSIZE - 2) + b"}"
    return _wrap_internal(internal)


declare(
    "container",
    "oversize-record-file-misnamed",
    "container",
    "container",
    "invalid",
    errors=("E_JSON_SIZE", "E_MANIFEST_RECORD_EXTRA"),
    build=lambda case_dir: _s2_misnamed_oversize_files(),
    args=_S2_ARGS,
    records=[],
    notes="S2/F55 (§11.6 item 5, §13, §14.5 U8): records/ holds an unlisted file with an "
    "upper-case (so misnamed) hex name and 1,048,577 bytes. A records/ file is subject to "
    "MAX_RECORD_BYTES whether or not it is listed, so the records-listing phase reports "
    "both independent violations: E_MANIFEST_RECORD_EXTRA and E_JSON_SIZE.",
)


def _s2_deep_record_files() -> dict[str, bytes]:
    """A listed record nested 33 levels deep (MAX_JSON_DEPTH is 32).

    The record object is depth 1, ``body`` depth 2 and 31 nested arrays reach 33.
    The bytes are written by hand (JCS of ASCII strings and arrays is the
    sorted, separator-free JSON form); the digest is §2.2 over them.
    """
    deep = "[" * 31 + "]" * 31
    unsigned = (
        '{"actor":{"key":"%s","type":"human"},"body":{"deep":%s,"text":"deep"},'
        '"format":"weave-record/1","id":"s2-deep-record","kind":"example.note",'
        '"origin":{"instance":"%s","project":"example"},"recorded_at":"%s",'
        '"stage":"proposed"}' % (kid("human-1"), deep, kid("human-1"), recordlib.T0)
    ).encode("ascii")
    digest = "sha256:" + hashlib.sha256(keyutil.DIGEST_DOMAIN + unsigned).hexdigest()
    files = recordlib.build_container(SIMPLE_RECORDS())
    manifest = parse(files["manifest.json"])
    manifest["records"] = sorted(
        manifest["records"] + [{"digest": digest, "id": "s2-deep-record", "kind": "example.note"}],
        key=lambda entry: entry["digest"],
    )
    files["records/%s.json" % digest[len("sha256:"):]] = unsigned + b"\n"
    recordlib.seal_container(files, manifest)
    return _wrap_internal(files)


declare(
    "container",
    "record-nesting-above-limit",
    "container",
    "container",
    "invalid",
    errors=("E_JSON_SIZE",),
    build=lambda case_dir: _s2_deep_record_files(),
    args=_S2_ARGS,
    records=[],
    notes="S2/F60 (§1.9, §14.5 U8): a listed records/ file nests 33 levels deep. A depth "
    "above MAX_JSON_DEPTH is E_JSON_SIZE and, like any size violation of a records/ file, "
    "it is reported by the records-listing phase as E_JSON_SIZE (not as an unconfirmable "
    "digest, E_MANIFEST_RECORD_DIGEST); records [].",
)


# -- F44: present but structurally invalid targets are defined above; F58 (Y1):
#    identity is (origin.project, origin.instance, id) ---------------------------


def _s2_identity_reference_files() -> dict[str, bytes]:
    other_instance = note("s2-y1-target", key_name="human-2", body={"text": "human-2 copy"})
    wanted = note("s2-y1-target", body={"text": "the human-1 record that is not exported"})
    source = note(
        "s2-y1-source",
        refs=[{"rel": "derived_from", "ref": recordlib.make_ref(
            kid("human-1"), "s2-y1-target", recordlib.record_digest(wanted)
        )}],
    )
    return container([other_instance, source])


declare(
    "container",
    "reference-identity-includes-instance",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _s2_identity_reference_files(),
    args=_S2_ARGS,
    notices=("N_REF_MISSING",),
    records=(
        {"id": "s2-y1-source", "verdict": "valid", "errors": [],
         "refs": [{"index": 0, "rel": "derived_from", "state": "missing"}]},
    ),
    notes="S2/F58 (Y1; §4.1, §6.3): a record's identity is (origin.project, "
    "origin.instance, id). The reference names instance human-1 and id s2-y1-target; the "
    "context only has a record with that id under instance human-2 (another digest). No "
    "record with the referenced origin and id exists: missing, N_REF_MISSING (not "
    "unverifiable).",
)


def _s2_placeholder_other_instance_files() -> dict[str, bytes]:
    original = erased_original("s2-y1-erased")
    attestation = erasure_record(original, record_id="s2-y1-erasure")
    placeholder = erased_placeholder(original, attestation)
    placeholder = {**placeholder, "origin": recordlib.origin(kid("human-2"))}
    return container([placeholder, attestation])


declare(
    "erasure",
    "placeholder-of-another-instance",
    "container",
    "container",
    "invalid",
    errors=("E_ERASE_DIGEST_MISMATCH",),
    build=lambda case_dir: _s2_placeholder_other_instance_files(),
    args=ERASURE_ARGS,
    notes="S2/F58 (Y1; §10.3 rule 1): the erasure record erases (example, human-1, "
    "s2-y1-erased), but the only placeholder carries origin.instance human-2 (its digest is "
    "still the erased digest, which does not cover the placeholder's own origin). There is "
    "no placeholder with the erased record's identity: an origin/id mismatch, "
    "E_ERASE_DIGEST_MISMATCH.",
)


def _s2_two_instance_placeholders_files() -> dict[str, bytes]:
    records: list[dict[str, Any]] = []
    for signer in ("human-1", "human-2"):
        original = note("s2-y1-same-id", key_name=signer, body={"text": "erased by " + signer})
        attestation = erasure_record(original, record_id="s2-y1-erasure-" + signer, signer=signer)
        records += [erased_placeholder(original, attestation), attestation]
    return container(records)


declare(
    "erasure",
    "placeholders-same-id-two-instances",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _s2_two_instance_placeholders_files(),
    args=ERASURE_ARGS,
    notes="S2/F58 (Y1; §10.3 rule 3): two placeholders share project and id but have "
    "different instances (human-1 and human-2), each with its own signed erasure record. "
    "They are placeholders for two different targets, so there is no contradiction: valid, "
    "no E_ERASE_CONTRADICTION.",
)



def _s2_erasure_two_rules_files() -> dict[str, bytes]:
    original = erased_original("s2-f48-erased")
    attestation = erasure_record(original, record_id="s2-f48-erasure")
    placeholder = erased_placeholder(original, attestation, digest="sha256:" + "77" * 32)
    placeholder["attestation"] = {**placeholder["attestation"], "digest": "sha256:" + "66" * 32}
    return container([placeholder, attestation])


declare(
    "erasure",
    "cross-checks-reported-independently",
    "container",
    "container",
    "invalid",
    errors=("E_ERASE_ATTESTATION", "E_ERASE_DIGEST_MISMATCH"),
    build=lambda case_dir: _s2_erasure_two_rules_files(),
    args=ERASURE_ARGS,
    notes="S2/F48 (§10.3, §14.5: the failing stage reports every violation it finds): the "
    "placeholder's digest is not the erased digest (rule 1, E_ERASE_DIGEST_MISMATCH) and "
    "its attestation reference names another digest (rule 2, E_ERASE_ATTESTATION). Each "
    "rule is evaluated independently, so both codes are reported.",
)

# -- F68 (Z1): §5.5.2 step 6 walks the whole chain before the depth bound -------

_S2_LATE = "2026-11-11T00:00:00.000Z"


def _s2_deep_chain_files(
    *,
    note_at: str = recordlib.T4,
    revoke_root: bool = False,
    tenth_grant: bool = False,
) -> dict[str, bytes]:
    records, deepest, final_grantee = _grant_chain_records(9)
    if tenth_grant:
        other = "agent-2" if final_grantee == "agent-1" else "agent-1"
        records.append(
            delegated_grant(
                deepest,
                record_id="grant-depth-10",
                sub_granter=final_grantee,
                grantee=other,
                kinds=("weave.grant", "example.note"),
                actions=("grant", "propose", "accept"),
                valid_from=recordlib.T0,
                valid_until=recordlib.T9,
                transferable=True,
                recorded_at=note_at,
            )
        )
    else:
        records.append(
            agent_action(
                deepest, record_id="grant-depth-9-note", key_name=final_grantee,
                recorded_at=note_at, stage="accepted",
            )
        )
    if revoke_root:
        records.append(
            grant_revocation(records[0], record_id="grant-depth-root-revoked",
                             effective_at=recordlib.T2)
        )
    return _wrap_internal(recordlib.build_container(records))


for _name, _kwargs, _subject, _code, _why in (
    ("chain-depth-9-root-revoked", dict(revoke_root=True), "grant-depth-9-note",
     "E_GRANT_REVOKED",
     "the note citing the depth-9 grant (nine parent links, one beyond the bound) is "
     "recorded at T4, and the root grant is revoked by a valid revocation effective at T2. "
     "Step 6 judges the cited grant and every ancestor, so the revoked root, which lies "
     "beyond the depth bound, is found before step 7"),
    ("chain-depth-9-expired", dict(note_at=_S2_LATE), "grant-depth-9-note", "E_GRANT_EXPIRED",
     "the note citing the depth-9 grant is recorded after every grant's valid_until (T9). "
     "Step 6 (validity) precedes step 7 (depth)"),
    ("chain-depth-10-grant-root-revoked", dict(revoke_root=True, tenth_grant=True),
     "grant-depth-10", "E_GRANT_REVOKED",
     "a grant record cites the depth-9 grant, so its own parent chain has nine links; it is "
     "recorded at T4 and the root grant is revoked at T2. A grant record's ancestors are "
     "judged at its recorded_at by the same walk"),
    ("chain-depth-10-grant-expired", dict(note_at=_S2_LATE, tenth_grant=True),
     "grant-depth-10", "E_GRANT_EXPIRED",
     "a grant record citing the depth-9 grant is recorded after every ancestor's valid_until"),
):
    declare(
        "grant",
        _name,
        "container",
        "container",
        "unverifiable",
        errors=(_code,),
        build=lambda case_dir, _kwargs=_kwargs: _s2_deep_chain_files(**_kwargs),
        args=GRANT_ARGS,
        records=({"id": _subject, "verdict": "unverifiable", "errors": [_code]},),
        notes="S2/F68 (Z1; §5.5.2: the chain is evaluated in the listed order and the first "
        "failing check decides): " + _why + ", so the record is unverifiable " + _code
        + ", not E_GRANT_UNRESOLVED.",
    )


# -- F57 / F66: the universal rules of 1a inside an open type -------------------

_S2_VALID_L2 = dict(
    args=_S2_L2_ARGS,
    expected_container={
        "level_claimed": "L2",
        "level_verified": "L0",
        "anchor_verified": True,
        "timestamps": [
            {"index": 0, "path": "signatures/timestamp-1.tsr", "state": "verified",
             "gen_time": "2026-11-01T00:00:00.000Z"}
        ],
    },
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
)

for _name, _identifier, _content, _verdict, _why in (
    ("l2-ts-der-universal-tag-zero", b"\x00", b"", "invalid",
     "the value is 00 00: universal tag number 0 (end-of-contents), which X.690 reserves "
     "for the indefinite form; DER never contains it"),
    ("l2-ts-der-universal-tag-zero-nested", b"\x30", b"\x00\x00", "invalid",
     "the value is 30 02 00 00: a SEQUENCE holding universal tag 0"),
    ("l2-ts-der-enumerated-nonminimal", b"\x0a", b"\x00\x01", "invalid",
     "the value is 0a 02 00 01: an ENUMERATED with a redundant leading zero octet; "
     "ENUMERATED is encoded as an INTEGER (X.690 §8.4), so the INTEGER rule applies"),
    ("l2-ts-der-enumerated-minimal", b"\x0a", b"\x01", "valid",
     "the value is 0a 01 01, a minimal ENUMERATED (control)"),
    ("l2-ts-der-external-primitive", b"\x08", b"\x00", "invalid",
     "the value is 08 01 00: EXTERNAL in the primitive form; EXTERNAL is SEQUENCE-based "
     "and constructed-only (X.690 §8.18)"),
    ("l2-ts-der-embedded-pdv-primitive", b"\x0b", b"\x00", "invalid",
     "the value is 0b 01 00: EMBEDDED PDV in the primitive form (constructed-only, "
     "X.690 §8.19)"),
    ("l2-ts-der-character-string-primitive", b"\x1d", b"\x00", "invalid",
     "the value is 1d 01 00: the unrestricted CHARACTER STRING in the primitive form "
     "(constructed-only, X.690 §8.21)"),
    ("l2-ts-der-external-constructed", b"\x28", b"\x02\x01\x01", "valid",
     "the value is 28 03 02 01 01: EXTERNAL in the constructed form, judged by its "
     "framing only (control)"),
    ("l2-ts-der-embedded-pdv-constructed", b"\x2b", b"\x02\x01\x01", "valid",
     "the value is 2b 03 02 01 01: EMBEDDED PDV in the constructed form (control)"),
    ("l2-ts-der-character-string-constructed", b"\x3d", b"\x02\x01\x01", "valid",
     "the value is 3d 03 02 01 01: CHARACTER STRING in the constructed form (control)"),
):
    _expected = _S2_VALID_L2 if _verdict == "valid" else _W3_SCHEMA_EXPECTED
    declare(
        "integrity-levels",
        _name,
        "container",
        "container",
        _verdict,
        build=lambda case_dir, _identifier=_identifier, _content=_content: _crafted_l2_files(
            case_dir,
            tsr_factory=lambda imprint: _x1_resigned(_x1_unsigned_value(_identifier, _content))(
                _crafted_tsr(imprint)
            ),
        ),
        notes="S2/F57/F66 (§12.2 1a, decided by principle as X.690 in full for the universal "
        "types it names): the receipt gains one unregistered unsigned attribute (an open "
        "type, judged by its framing and the universal rules of 1a only); "
        + _why
        + ". The receipt is otherwise fully re-signed with the test TSA key.",
        **_expected,
    )


# -- F62 / F63 / F59: the signer certificate under 1e ---------------------------


def _s2_pem(der: bytes) -> bytes:
    """PEM text of DER bytes, written directly (no certificate decoder involved)."""
    import base64

    text = base64.b64encode(der).decode("ascii")
    lines = [text[index:index + 64] for index in range(0, len(text), 64)]
    return ("-----BEGIN CERTIFICATE-----\n" + "\n".join(lines)
            + "\n-----END CERTIFICATE-----\n").encode("ascii")


def _s2_signer_certificate(edit: Callable[[_DerNode], None]) -> bytes:
    """The committed TSA certificate, edited and its TBSCertificate re-signed."""
    certificate = _der_tree(_tsa_certificate_der())
    edit(certificate)
    signature = _tsa_private_key().sign(
        _der_encode(certificate.children[0]), crypto_padding.PKCS1v15(), crypto_hashes.SHA256()
    )
    certificate.children[2].content = b"\x00" + signature
    return _der_encode(certificate)


def _s2_tbs(certificate: _DerNode) -> _DerNode:
    return certificate.children[0]


def _s2_drop_version(certificate: _DerNode) -> None:
    tbs = _s2_tbs(certificate)
    if tbs.children[0].tag != 0xA0:
        raise SystemExit("TSA certificate has no explicit version")
    tbs.children.pop(0)


def _s2_set_version(value: int) -> Callable[[_DerNode], None]:
    def edit(certificate: _DerNode) -> None:
        _s2_tbs(certificate).children[0].children[0].content = bytes([value])

    return edit


def _s2_drop_extensions(certificate: _DerNode) -> None:
    tbs = _s2_tbs(certificate)
    tbs.children = [child for child in tbs.children if child.tag != 0xA3]


def _s2_add_issuer_unique_id(certificate: _DerNode) -> None:
    _s2_tbs(certificate).children.append(_w3_node(0x81, content=b"\x00\x5a"))


def _s2_chain(*edits: Callable[[_DerNode], None]) -> Callable[[_DerNode], None]:
    def edit(certificate: _DerNode) -> None:
        for step in edits:
            step(certificate)

    return edit


def _s2_subject_printable(text: bytes) -> Callable[[_DerNode], None]:
    def edit(certificate: _DerNode) -> None:
        tbs = _s2_tbs(certificate)
        subject_index = 5 if tbs.children[0].tag == 0xA0 else 4
        tbs.children[subject_index] = _w3_node(0x30, children=[_w3_node(0x31, children=[
            _w3_node(0x30, children=[_w3_oid("2.5.4.3"), _w3_node(0x13, content=text)])
        ])])

    return edit


def _s2_tbs_signature_params_octets(certificate: _DerNode) -> None:
    algorithm = _s2_tbs(certificate).children[2]
    if algorithm.tag != 0x30 or algorithm.children[1].tag != 0x05:
        raise SystemExit("unexpected TBSCertificate.signature encoding")
    algorithm.children[1] = _w3_node(0x04, content=b"")


def _s2_explicit_critical_false(certificate: _DerNode) -> None:
    extensions = next(child for child in _s2_tbs(certificate).children if child.tag == 0xA3)
    extension = extensions.children[0].children[0]
    extension.children[1] = _w3_node(0x01, content=b"\x00")


def _s2_certificate_files(
    case_dir: Path, certificate_der: bytes, *, anchor_is_signer: bool
) -> dict[str, bytes]:
    """L2 files whose receipt is signed under *certificate_der*.

    The trust anchor is that certificate when it is itself a well-formed anchor;
    otherwise the committed TSA certificate (a malformed anchor would be a usage
    error, §14.1, and a vector cannot express one).
    """
    files = _crafted_l2_files(
        case_dir,
        tsr_factory=lambda imprint: _crafted_tsr(imprint, certificate_der=certificate_der),
        trust_name=None,
    )
    files[TSA_CERT_NAME] = _s2_pem(certificate_der) if anchor_is_signer else TSA_CERT()
    return files


for _name, _edit, _verdict, _errors, _why in (
    ("l2-ts-signer-cert-v1-with-extensions", _s2_drop_version, "invalid", ("E_TS_SCHEMA",),
     "the signer certificate omits version (v1) but carries extensions; RFC 5280 "
     "§4.1.2.1/§4.1.2.9: extensions require v3"),
    ("l2-ts-signer-cert-v1-with-issuer-unique-id",
     _s2_chain(_s2_drop_version, _s2_drop_extensions, _s2_add_issuer_unique_id),
     "invalid", ("E_TS_SCHEMA",),
     "the signer certificate is v1 (version absent, no extensions) and carries "
     "issuerUniqueID; RFC 5280 §4.1.2.8: the unique identifiers require v2 or v3"),
    ("l2-ts-signer-cert-v2-with-issuer-unique-id",
     _s2_chain(_s2_set_version(1), _s2_drop_extensions, _s2_add_issuer_unique_id),
     "invalid", ("E_TS_CERT",),
     "the signer certificate is v2 with issuerUniqueID and no extensions: a well-formed "
     "X.509 certificate, so check 1 passes; without extensions it has no timeStamping EKU, "
     "so check 11 fails (E_TS_CERT)"),
    ("l2-ts-signer-cert-version-v4", _s2_set_version(3), "invalid", ("E_TS_SCHEMA",),
     "the signer certificate's version is 3 (v4), outside v1..v3"),
    ("l2-ts-signer-cert-subject-printable-at-star", _s2_subject_printable(b"a@b*"), "valid", (),
     "the signer certificate's subject CN is the PrintableString a@b*, whose characters "
     "are outside the PrintableString set; AttributeTypeAndValue.value is an open type "
     "(1c), judged by its framing only, so the certificate decodes and verifies"),
    ("l2-ts-signer-cert-tbs-signature-params-octets", _s2_tbs_signature_params_octets,
     "valid", (),
     "the signer certificate's TBSCertificate.signature parameters are 04 00; "
     "AlgorithmIdentifier.parameters is an open type outside the signer's SignerInfo "
     "algorithms (1c)"),
    ("l2-ts-signer-cert-outer-signature-params-octets", _x7_outer_algorithm_params_octets,
     "valid", (),
     "the signer certificate's outer signatureAlgorithm parameters are 04 00 (an open type, "
     "1c)"),
    ("l2-ts-signer-cert-extension-critical-false", _s2_explicit_critical_false,
     "invalid", ("E_TS_SCHEMA",),
     "the signer certificate's basicConstraints extension writes critical FALSE explicitly; "
     "Extension.critical is BOOLEAN DEFAULT FALSE (1c DEFAULT table), so the encoded "
     "default is a DER violation"),
):
    _certificate_expected: dict[str, Any] = dict(
        args=_S2_L2_ARGS,
        records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    )
    if _verdict == "valid":
        _certificate_expected["expected_container"] = {"anchor_verified": True}
    declare(
        "integrity-levels",
        _name,
        "container",
        "container",
        _verdict,
        errors=_errors,
        build=lambda case_dir, _edit=_edit, _anchor=(_errors != ("E_TS_SCHEMA",)): (
            _s2_certificate_files(case_dir, _s2_signer_certificate(_edit), anchor_is_signer=_anchor)
        ),
        notes="S2/F62/F63/F59 (§12.2 1e, decided by principle: the RFC 5280 module "
        "definition and its version constraints, never a parsing library's habits): "
        + _why
        + ". The certificate is re-signed with the test TSA key and the receipt carries it "
        "as signer certificate (ESS signingCertificateV2 updated). The case's trust anchor "
        "is that certificate when it is a well-formed X.509 certificate, otherwise the "
        "committed test TSA certificate (a malformed anchor is a usage error, §14.1).",
        **_certificate_expected,
    )


# -- F59 (Y2): TSTInfo extension critical FALSE and a non-null chain-head renews --


def _s2_tst_extension(critical: bytes | None) -> Callable[[_DerNode], None]:
    def edit(tree: _DerNode) -> None:
        def add(tst_info: _DerNode) -> None:
            parts = [_w3_oid("1.2.3.4.9.1")]
            if critical is not None:
                parts.append(_w3_node(0x01, content=critical))
            parts.append(_w3_node(0x04, content=b"\x05\x00"))
            tst_info.children.append(
                _w3_node(0xA1, children=[_w3_node(0x30, children=parts)])
            )

        _w3_tst_info_edit(tree, add)

    return edit


for _name, _critical, _verdict, _why in (
    ("l2-ts-tst-extension-critical-false", b"\x00", "invalid",
     "TSTInfo carries one extension that writes critical FALSE explicitly; "
     "Extension.critical is BOOLEAN DEFAULT FALSE for TSTInfo extensions too (1c DEFAULT "
     "table)"),
    ("l2-ts-tst-extension-critical-absent", None, "valid",
     "TSTInfo carries one extension with critical absent (control)"),
):
    declare(
        "integrity-levels",
        _name,
        "container",
        "container",
        _verdict,
        build=lambda case_dir, _critical=_critical: _crafted_l2_files(
            case_dir,
            tsr_factory=lambda imprint: _x1_resigned(_s2_tst_extension(_critical))(
                _crafted_tsr(imprint)
            ),
        ),
        notes="S2/F59 (Y2; §12.2 1c): " + _why + ". The edited TSTInfo is re-signed with "
        "the test TSA key (messageDigest recomputed).",
        **(_S2_VALID_L2 if _verdict == "valid" else _W3_SCHEMA_EXPECTED),
    )


def _s2_chain_head_renews_files(case_dir: Path, renews: str) -> dict[str, bytes]:
    files = _build_timestamped_container(
        SIMPLE_RECORDS(),
        lambda imprint: [("signatures/timestamp-1.tsr", _crafted_tsr(imprint), renews)],
    )
    return {**wrap(files), TSA_CERT_NAME: TSA_CERT()}


for _name, _renews, _why in (
    ("l2-ts-chain-head-renews-itself", "signatures/timestamp-1.tsr",
     "the single receipt's renews names its own path"),
    ("l2-ts-chain-head-renews-unlisted", "signatures/timestamp-7.tsr",
     "the single receipt's renews names a path that is not listed"),
):
    declare(
        "integrity-levels",
        _name,
        "container",
        "container",
        "invalid",
        errors=("E_TS_RENEWAL",),
        build=lambda case_dir, _renews=_renews: _s2_chain_head_renews_files(case_dir, _renews),
        args=_S2_L2_ARGS,
        records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
        notes="S2/F59 (Y2; §11.3, §12.4, §12.2 check 14): " + _why + ". renews is null for "
        "the first receipt of the chain and the chain has exactly one receipt with renews "
        "null, so the chain shape fails: E_TS_RENEWAL.",
    )


# -- F65: a P-384 ECDSA timestamp signer -------------------------------------

_S2_P384_ORDER = int(
    "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"
    "581a0db248b0a77aecec196accc52973",
    16,
)
_S2_P384: dict[str, Any] = {}


def _s2_p384_key() -> Any:
    from cryptography.hazmat.primitives.asymmetric import ec as crypto_ec

    if "key" not in _S2_P384:
        scalar = int.from_bytes(
            hashlib.sha384(b"weave-record/1/test-tsa-p384").digest(), "big"
        ) % (_S2_P384_ORDER - 1) + 1
        _S2_P384["key"] = crypto_ec.derive_private_key(scalar, crypto_ec.SECP384R1())
    return _S2_P384["key"]


def _s2_p384_sign(message: bytes, digest: str) -> bytes:
    from cryptography.hazmat.primitives.asymmetric import ec as crypto_ec

    algorithm = crypto_hashes.SHA384() if digest == "sha384" else crypto_hashes.SHA256()
    return _s2_p384_key().sign(message, crypto_ec.ECDSA(algorithm, deterministic_signing=True))


def _s2_p384_certificate() -> bytes:
    """A deterministic self-signed P-384 timeStamping certificate (ECDSA, RFC 6979)."""
    if "certificate" in _S2_P384:
        return _S2_P384["certificate"]
    spki = _s2_p384_key().public_key().public_bytes(
        crypto_serialization.Encoding.DER,
        crypto_serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    name = asn1_x509.Name.build({"common_name": "Hyphaweave S2 test TSA P-384 (test only)"})
    tbs = asn1_x509.TbsCertificate()
    tbs["version"] = "v3"
    tbs["serial_number"] = 7384
    tbs["signature"] = {"algorithm": "sha384_ecdsa"}
    tbs["issuer"] = name
    validity = asn1_x509.Validity()
    validity["not_before"] = asn1_x509.Time(
        {"utc_time": datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)}
    )
    validity["not_after"] = asn1_x509.Time(
        {"general_time": datetime.datetime(2126, 1, 1, tzinfo=datetime.timezone.utc)}
    )
    tbs["validity"] = validity
    tbs["subject"] = name
    tbs["subject_public_key_info"] = asn1_x509.PublicKeyInfo.load(spki)
    tbs["extensions"] = [
        asn1_x509.Extension({"extn_id": "key_usage", "critical": True,
                             "extn_value": asn1_x509.KeyUsage({"digital_signature"})}),
        asn1_x509.Extension({"extn_id": "extended_key_usage", "critical": True,
                             "extn_value": asn1_x509.ExtKeyUsageSyntax(["time_stamping"])}),
    ]
    certificate = asn1_x509.Certificate()
    certificate["tbs_certificate"] = tbs
    certificate["signature_algorithm"] = {"algorithm": "sha384_ecdsa"}
    certificate["signature_value"] = _s2_p384_sign(tbs.dump(), "sha384")
    _S2_P384["certificate"] = certificate.dump()
    return _S2_P384["certificate"]


_S2_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
_S2_ECDSA_SHA384 = "1.2.840.10045.4.3.3"
_S2_SHA256_RSA = "1.2.840.113549.1.1.11"


def _s2_p384_tsr(
    algorithm: str, *, with_null: bool = False, digest: str = "sha384", tamper: bool = False,
) -> Callable[[bytes], bytes]:
    def factory(imprint: bytes) -> bytes:
        tree = _der_tree(_crafted_tsr(imprint, certificate_der=_s2_p384_certificate()))
        signer_info = _w3_signer_info(tree)
        position = next(
            index for index, child in enumerate(signer_info.children) if child.tag == 0xA0
        )
        parts = [_w3_oid(algorithm)]
        if with_null:
            parts.append(_w3_node(0x05, content=b""))
        signer_info.children[position + 1] = _w3_node(0x30, children=parts)
        if algorithm == _S2_SHA256_RSA:
            _x1_resign(tree)
        else:
            _x1_resign(tree, sign=lambda message: _s2_p384_sign(message, digest))
        if tamper:
            signature = signer_info.children[position + 2]
            signature.content = signature.content[:-1] + bytes([signature.content[-1] ^ 0x01])
        return _der_encode(tree)

    return factory


def _s2_p384_files(case_dir: Path, factory: Callable[[bytes], bytes]) -> dict[str, bytes]:
    files = _crafted_l2_files(case_dir, tsr_factory=factory, trust_name=None)
    files[TSA_CERT_NAME] = _s2_pem(_s2_p384_certificate())
    return files


for _name, _factory, _verdict, _errors, _why in (
    ("l2-ts-signer-p384-sha384", _s2_p384_tsr(_S2_ECDSA_SHA384), "valid", (),
     "ecdsa-with-SHA384 with the parameters absent (RFC 5758 §3.2)"),
    ("l2-ts-signer-p384-sha256", _s2_p384_tsr(_S2_ECDSA_SHA256, digest="sha256"), "valid", (),
     "ecdsa-with-SHA256 with a P-384 key (the curve does not fix the hash)"),
    ("l2-ts-signer-p384-sha384-params-null", _s2_p384_tsr(_S2_ECDSA_SHA384, with_null=True),
     "invalid", ("E_TS_SCHEMA",),
     "ecdsa-with-SHA384 with NULL parameters; for ECDSA the parameters MUST be absent "
     "(§12.2 1c X6 table)"),
    ("l2-ts-signer-p384-signature-tampered", _s2_p384_tsr(_S2_ECDSA_SHA384, tamper=True),
     "invalid", ("E_TS_CMS",),
     "ecdsa-with-SHA384 whose signature's last octet is flipped after signing (check 10)"),
    ("l2-ts-signer-p384-with-rsa-algorithm", _s2_p384_tsr(_S2_SHA256_RSA, with_null=True),
     "invalid", ("E_TS_CMS",),
     "sha256WithRSAEncryption with the P-384 signer key: a key the allowlisted algorithm "
     "cannot use fails check 10 (E_TS_CMS), not check 6"),
):
    _p384_expected: dict[str, Any] = dict(
        args=_S2_L2_ARGS,
        records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    )
    if _verdict == "valid":
        _p384_expected["expected_container"] = {"anchor_verified": True}
    declare(
        "integrity-levels",
        _name,
        "container",
        "container",
        _verdict,
        errors=_errors,
        build=lambda case_dir, _factory=_factory: _s2_p384_files(case_dir, _factory),
        notes="S2/F65 (§12.2 checks 1c, 6, 10): the receipt's signer is a deterministic "
        "P-384 test certificate (self-signed, timeStamping EKU), and the receipt is signed "
        "with that key using RFC 6979 deterministic ECDSA; the case's trust anchor is that "
        "certificate. The SignerInfo uses " + _why + ".",
        **_p384_expected,
    )


# ---------------------------------------------------------------------------
# S2-FIX1 (decision 2026-11-15 #13): the founder's rulings Q1-Q5 and the
# review items T1-T8 of the S2 round. Every expected conclusion below is
# hand-written from the specification text.
# ---------------------------------------------------------------------------

# -- T1 / Q2: a signature that fails §9.4 gives no other key material or trust.
#    Only the signature of the key the record states for itself (a declaration's
#    body.key, a rotation's new_key) is left out when admission is decided (§5.3).


def _fix1_rotation_records(
    *, compromised: str, recorded_at: str = recordlib.T0
) -> list[dict[str, Any]]:
    """A device key declared at T0, rotated at *recorded_at*; *compromised* is
    ``"old"`` or ``"new"``: that key has a key-compromise revocation at T1."""
    old_private, old_public, old_id = derived_key("fix1-rotation-old")
    new_private, new_public, new_id = derived_key("fix1-rotation-new")
    declaration = _s2_declaration("fix1-rotation-old", record_id="key-declared-fix1-rotation-old")
    revocation = _s2_revocation(
        old_id if compromised == "old" else new_id,
        reason="key-compromise",
        effective_at=recordlib.T1,
        record_id="key-revoked-fix1-rotation",
    )
    rotation = recordlib.build_record(
        kind="weave.key.rotated",
        id="key-rotated-fix1",
        actor={"type": "device", "key": old_id},
        body={
            "new_key": new_id,
            "new_public_key": keyutil.b64url_encode(new_public),
            "old_key": old_id,
            "old_public_key": keyutil.b64url_encode(old_public),
        },
        stage="accepted",
        recorded_at=recorded_at,
        origin_instance=old_id,
    )
    rotation = {
        **rotation,
        "sigs": sorted(
            [
                _derived_signature(old_private, old_id, rotation),
                _derived_signature(new_private, new_id, rotation),
            ],
            key=lambda entry: entry["key"],
        ),
    }
    note_record = _s2_derived_note("fix1-rotation-new", "fix1-note-by-new-key", recordlib.T3)
    return [declaration, revocation, rotation, note_record]


def _fix1_rotation_expected(compromised: str) -> tuple[dict[str, Any], ...]:
    records = _fix1_rotation_records(compromised=compromised)
    rotation, note_record = records[2], records[3]
    old_id = derived_key("fix1-rotation-old")[2]
    new_id = derived_key("fix1-rotation-new")[2]
    if compromised == "old":
        rotation_states = {old_id: "unverified", new_id: "valid"}
        note_expected = {
            "id": "fix1-note-by-new-key",
            "verdict": "unverifiable",
            "errors": ["E_KEY_UNKNOWN"],
            "sigs": _s2_sigs(note_record, {new_id: "unverified"}),
        }
    else:
        rotation_states = {old_id: "valid", new_id: "unverified"}
        note_expected = {
            "id": "fix1-note-by-new-key",
            "verdict": "invalid",
            "errors": ["E_KEY_COMPROMISED"],
            "sigs": _s2_sigs(note_record, {new_id: "unverified"}),
        }
    declaration_expected: dict[str, Any] = {
        "id": "key-declared-fix1-rotation-old", "verdict": "valid", "errors": [],
    }
    if compromised == "old":
        # A1 (§9.4 case 3): the old key's own declaration (T0) is self-signed by a key
        # with a key-compromise revocation and the L0 container has no evidence.
        declaration_expected = {
            "id": "key-declared-fix1-rotation-old",
            "verdict": "invalid",
            "errors": ["E_KEY_COMPROMISED"],
            "sigs": _s2_sigs(records[0], {old_id: "unverified", kid("human-1"): "valid"}),
        }
    return (
        declaration_expected,
        {"id": "key-revoked-fix1-rotation", "verdict": "valid", "errors": []},
        {
            "id": "key-rotated-fix1",
            "verdict": "invalid",
            "errors": ["E_KEY_COMPROMISED"],
            "sigs": _s2_sigs(rotation, rotation_states),
        },
        note_expected,
    )


declare(
    "key-lifecycle",
    "rotation-old-key-compromised-backdated-note-by-new-key",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_COMPROMISED", "E_KEY_UNKNOWN"),
    build=lambda case_dir: container(_fix1_rotation_records(compromised="old"), level="L0"),
    args=_S2_ARGS,
    records=_fix1_rotation_expected("old"),
    notes="S2-FIX1 T1 (Q2; §5.3, §9.4 case 3): a device key has a valid key-compromise "
    "revocation effective at T1; a rotation from that old key to a new key claims T0, "
    "before the compromise, and the L0 container has no timestamp evidence at all (so "
    "the old key's own declaration is invalid E_KEY_COMPROMISED as well, A1). The "
    "rotation's old-key signature fails §9.4 (invalid E_KEY_COMPROMISED), and a signature "
    "that fails §9.4 gives another key neither material nor trust: the rotation supplies "
    "no new-key material, so a note signed by the new key at T3 is unverifiable "
    "E_KEY_UNKNOWN (sigs state unverified). Without this a thief holding the old key "
    "could backdate a rotation to a key of their own and sign valid records with it.",
)

declare(
    "key-lifecycle",
    "rotation-new-key-compromised-note-by-new-key",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_COMPROMISED",),
    build=lambda case_dir: container(_fix1_rotation_records(compromised="new"), level="L0"),
    args=_S2_ARGS,
    records=_fix1_rotation_expected("new"),
    notes="S2-FIX1 T1 (Q2; §5.3, §9.4 case 3): the same L0 container, but the key-compromise "
    "revocation names the new key. The rotation's new-key signature fails §9.4, so the "
    "rotation is invalid E_KEY_COMPROMISED; that is the signature of the key the rotation "
    "states for itself, the one signature left out when admission is decided (§5.3), so "
    "the rotation still supplies the new key's material and the note signed by the new "
    "key at T3 is judged under the new key's own lifecycle: invalid E_KEY_COMPROMISED, "
    "not unverifiable E_KEY_UNKNOWN.",
)


def _fix1_with_note(files_records: list[dict[str, Any]], name: str, note_id: str) -> dict[str, bytes]:
    return container(files_records + [_s2_derived_note(name, note_id, recordlib.T3)])


def _fix1_rotation_retired_records() -> list[dict[str, Any]]:
    files = _s2_rotation_old_retired_files()
    return [parse(data) for path, data in sorted(files.items()) if path.startswith("container/records/")]


def _fix1_cosigner_retired_records() -> list[dict[str, Any]]:
    files = _s2_cosigner_retired_files()
    return [parse(data) for path, data in sorted(files.items()) if path.startswith("container/records/")]


declare(
    "key-lifecycle",
    "rotation-old-key-retired-note-by-new-key",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_REVOKED", "E_KEY_UNKNOWN"),
    build=lambda case_dir: _fix1_with_note(
        _fix1_rotation_retired_records(), "s2-rotation-new", "fix1-note-by-rotated-in-key"
    ),
    args=_S2_ARGS,
    records=(
        {"id": "key-rotated-s2-after-retirement", "verdict": "invalid", "errors": ["E_KEY_REVOKED"]},
        {
            "id": "fix1-note-by-rotated-in-key",
            "verdict": "unverifiable",
            "errors": ["E_KEY_UNKNOWN"],
            "sigs": [{"key": derived_key("s2-rotation-new")[2], "state": "unverified"}],
        },
    ),
    notes="S2-FIX1 T1 (Q2; §5.3, §9.4): key-lifecycle/rotation-old-key-retired (a rotation "
    "recorded at T2 whose old key was retired at T1, invalid E_KEY_REVOKED) plus a note "
    "signed by the rotated-in key at T3. The old-key signature fails §9.4, so the "
    "rotation supplies no new-key material: the note is unverifiable E_KEY_UNKNOWN.",
)

declare(
    "key-lifecycle",
    "declaration-cosigner-retired-note-by-device",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_REVOKED", "E_KEY_UNKNOWN"),
    build=lambda case_dir: _fix1_with_note(
        _fix1_cosigner_retired_records(), "s2-cosigned-device", "fix1-note-by-cosigned-device"
    ),
    args=_S2_ARGS,
    records=(
        {"id": "key-declared-s2-cosigned-device", "verdict": "invalid", "errors": ["E_KEY_REVOKED"]},
        {
            "id": "fix1-note-by-cosigned-device",
            "verdict": "unverifiable",
            "errors": ["E_KEY_UNKNOWN"],
            "sigs": [{"key": derived_key("s2-cosigned-device")[2], "state": "unverified"}],
        },
    ),
    notes="S2-FIX1 T1 (Q2; §5.3, §9.4): key-lifecycle/declaration-cosigner-retired (a device "
    "declaration recorded at T2 whose owner cosignature is by human-2, retired at T1, "
    "invalid E_KEY_REVOKED) plus a note signed by the device key at T3. The owner "
    "cosignature fails §9.4, so the declaration gives the device key neither material nor "
    "trust: the note is unverifiable E_KEY_UNKNOWN.",
)


def _fix1_owner_compromised_records() -> list[dict[str, Any]]:
    revocation = recordlib.key_revocation(
        "human-2", reason="key-compromise", effective_at=recordlib.T1, signer_name="human-1",
        record_id="key-revoked-fix1-human-2",
    )
    declaration = _s2_declaration(
        "fix1-owner-compromised-device",
        record_id="key-declared-fix1-owner-compromised-device",
        owner="human-2",
        recorded_at=recordlib.T0,
        cosigners=("human-2",),
    )
    return [revocation, declaration]


declare(
    "key-lifecycle",
    "declaration-cosigner-compromised-note-by-device",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_COMPROMISED", "E_KEY_UNKNOWN"),
    build=lambda case_dir: _fix1_with_note(
        _fix1_owner_compromised_records(), "fix1-owner-compromised-device",
        "fix1-note-by-owner-compromised-device",
    ),
    args=_S2_ARGS,
    records=(
        {"id": "key-revoked-fix1-human-2", "verdict": "valid", "errors": []},
        {
            "id": "key-declared-fix1-owner-compromised-device",
            "verdict": "invalid",
            "errors": ["E_KEY_COMPROMISED"],
            "sigs": _s2_sigs(
                _fix1_owner_compromised_records()[1],
                {derived_key("fix1-owner-compromised-device")[2]: "valid",
                 kid("human-2"): "unverified"},
            ),
        },
        {
            "id": "fix1-note-by-owner-compromised-device",
            "verdict": "unverifiable",
            "errors": ["E_KEY_UNKNOWN"],
            "sigs": [{"key": derived_key("fix1-owner-compromised-device")[2], "state": "unverified"}],
        },
    ),
    notes="S2-FIX1 T1 (Q2; §5.3, §9.4 case 3): human-2 has a valid key-compromise "
    "revocation effective at T1. A new device declaration owned by human-2 claims T0 and "
    "carries human-2's owner cosignature; the L0 container has no timestamp evidence. The "
    "cosignature fails §9.4 (invalid E_KEY_COMPROMISED), so the declaration gives the "
    "device key neither material nor trust, and a note signed by the device at T3 is "
    "unverifiable E_KEY_UNKNOWN. Without this a thief holding human-2's key could "
    "backdate a declaration of a device key of their own.",
)


# -- T2: invalid beats unverifiable across signature entries (§4.4 step 2, §14.5) --


def _fix1_revoked_entry_and_unknown_key_files() -> dict[str, bytes]:
    first_private, _first_public, first_id = derived_key("fix1-retired-signer")
    second_private, _second_public, second_id = derived_key("fix1-undeclared-signer")
    declaration = _s2_declaration("fix1-retired-signer", record_id="key-declared-fix1-retired-signer")
    revocation = _s2_revocation(
        first_id, reason="retired", effective_at=recordlib.T1,
        record_id="key-revoked-fix1-retired-signer",
    )
    record = recordlib.build_record(
        kind="example.note",
        id="fix1-retired-and-undeclared-note",
        actor={"type": "device", "key": first_id},
        body={"text": "a retired signer and an undeclared signer"},
        recorded_at=recordlib.T2,
        origin_instance=first_id,
    )
    record = {
        **record,
        "sigs": sorted(
            [
                _derived_signature(first_private, first_id, record),
                _derived_signature(second_private, second_id, record),
            ],
            key=lambda entry: entry["key"],
        ),
    }
    return container([declaration, revocation, record])


def _fix1_revoked_entry_expected() -> dict[str, Any]:
    files = _fix1_revoked_entry_and_unknown_key_files()
    record = next(
        parse(data) for path, data in files.items()
        if path.startswith("container/records/")
        and parse(data).get("id") == "fix1-retired-and-undeclared-note"
    )
    return {
        "id": "fix1-retired-and-undeclared-note",
        "verdict": "invalid",
        "errors": ["E_KEY_REVOKED"],
        "sigs": _s2_sigs(
            record,
            {derived_key("fix1-retired-signer")[2]: "unverified",
             derived_key("fix1-undeclared-signer")[2]: "unverified"},
        ),
    }


declare(
    "key-lifecycle",
    "signature-revoked-entry-beats-unknown-key",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_REVOKED",),
    build=lambda case_dir: _fix1_revoked_entry_and_unknown_key_files(),
    args=_S2_ARGS,
    records=(_fix1_revoked_entry_expected(),),
    notes="S2-FIX1 T2 (§14.5 steps (4)-(5), §9.4; invalid beats unverifiable): a note "
    "recorded at T2 carries a good signature by a device key retired at T1 and a good "
    "signature by a key that nothing declares. The retired key's signature is invalid "
    "E_KEY_REVOKED under §9.4 (sigs state unverified) and the other entry's key cannot be "
    "resolved (unverified). The invalid outcome decides the record's code: invalid "
    "E_KEY_REVOKED, not unverifiable E_KEY_UNKNOWN.",
)


# -- Q1 (F47): an erasure's authorising grant. Present but itself invalid ->
#    E_ERASE_ACTOR (invalid); absent, outside its window or revoked ->
#    the grant codes (unverifiable, "cannot be established").


def _fix1_erasure_agent_files(
    *,
    grant_kwargs: dict[str, Any] | None = None,
    include_grant: bool = True,
    revoke_at: str | None = None,
    actions: Sequence[str] = ("accept", "erase"),
) -> dict[str, bytes]:
    original = erased_original("erasure-revision-original")
    grant = root_grant(
        record_id="erasure-basis-grant",
        grantee="agent-1",
        kinds=("weave.erasure",),
        actions=tuple(actions),
        scope=("example",),
        **(grant_kwargs or {}),
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
    records: list[dict[str, Any]] = []
    if include_grant:
        records.append(grant)
    if revoke_at is not None:
        records.append(
            grant_revocation(grant, record_id="erasure-basis-grant-revoked", effective_at=revoke_at)
        )
    return container(records + [placeholder, attestation])


def _fix1_erasure_program_files(*, include_grant: bool, invalid_grant: bool = False) -> dict[str, bytes]:
    original = erased_original("erasure-revision-original")
    grant = root_grant(
        record_id="erasure-basis-grant",
        grantee="program-1",
        kinds=("weave.erasure",),
        actions=("erase",),
        scope=("example",),
        **(dict(valid_from=recordlib.T9, valid_until=recordlib.T0) if invalid_grant else {}),
    )
    attestation = erasure_record(
        original,
        record_id="erasure-revision-attestation",
        reason="retention-expired",
        signer="program-1",
        basis=parent_ref(grant),
    )
    placeholder = erased_placeholder(original, attestation)
    return container(([grant] if include_grant else []) + [placeholder, attestation])


_FIX1_BAD_WINDOW = dict(valid_from=recordlib.T9, valid_until=recordlib.T0)

for _name, _build, _verdict, _attestation_errors, _other, _why in (
    ("actor-agent-grant-present-invalid",
     lambda case_dir: _fix1_erasure_agent_files(grant_kwargs=_FIX1_BAD_WINDOW),
     "invalid", ("E_ERASE_ACTOR",),
     ({"id": "erasure-basis-grant", "verdict": "invalid", "errors": ["E_KEY_VALIDITY"]},),
     "the agent's actor.grant resolves to a grant record that is present but itself invalid "
     "(its valid_from T9 is after its valid_until T0, E_KEY_VALIDITY). A present grant that "
     "is invalid is a disallowed signer basis: E_ERASE_ACTOR (invalid)"),
    ("actor-agent-grant-absent",
     lambda case_dir: _fix1_erasure_agent_files(include_grant=False),
     "unverifiable", ("E_GRANT_UNRESOLVED",), (),
     "the agent's actor.grant names a grant that is not in the container. The authorising "
     "grant cannot be established: E_GRANT_UNRESOLVED (unverifiable)"),
    ("actor-agent-grant-expired",
     lambda case_dir: _fix1_erasure_agent_files(grant_kwargs=dict(valid_until=recordlib.T3)),
     "unverifiable", ("E_GRANT_EXPIRED",),
     ({"id": "erasure-basis-grant", "verdict": "valid", "errors": []},),
     "the agent's grant is valid but its window ends at T3, before the erasure's recorded_at "
     "T4: E_GRANT_EXPIRED (unverifiable)"),
    ("actor-agent-grant-revoked",
     lambda case_dir: _fix1_erasure_agent_files(revoke_at=recordlib.T3),
     "unverifiable", ("E_GRANT_REVOKED",),
     ({"id": "erasure-basis-grant", "verdict": "valid", "errors": []},
      {"id": "erasure-basis-grant-revoked", "verdict": "valid", "errors": []}),
     "the agent's grant is revoked by its granter effective T3, before the erasure's "
     "recorded_at T4: E_GRANT_REVOKED (unverifiable)"),
    ("actor-agent-grant-expired-and-lacks-erase",
     lambda case_dir: _fix1_erasure_agent_files(
         grant_kwargs=dict(valid_until=recordlib.T3), actions=("accept",)
     ),
     "invalid", ("E_ERASE_ACTOR",),
     ({"id": "erasure-basis-grant", "verdict": "valid", "errors": []},),
     "the agent's grant does not allow the erase action (invalid) and its window also ends "
     "before the erasure (unverifiable). Invalid beats unverifiable: E_ERASE_ACTOR"),
    ("actor-program-basis-absent",
     lambda case_dir: _fix1_erasure_program_files(include_grant=False),
     "unverifiable", ("E_GRANT_UNRESOLVED",), (),
     "a program erasure's body.basis names a grant that is not in the container: the "
     "authorising grant cannot be established, E_GRANT_UNRESOLVED (unverifiable)"),
    ("actor-program-basis-present-invalid",
     lambda case_dir: _fix1_erasure_program_files(include_grant=True, invalid_grant=True),
     "invalid", ("E_ERASE_ACTOR",),
     ({"id": "erasure-basis-grant", "verdict": "invalid", "errors": ["E_KEY_VALIDITY"]},),
     "a program erasure's body.basis resolves to a grant record that is present but itself "
     "invalid (E_KEY_VALIDITY): E_ERASE_ACTOR (invalid)"),
):
    _attestation = {
        "id": "erasure-revision-attestation",
        "verdict": _verdict,
        "errors": list(_attestation_errors),
    }
    declare(
        "erasure",
        _name,
        "container",
        "container",
        "invalid" if _verdict == "invalid" or any(r["verdict"] == "invalid" for r in _other) else _verdict,
        errors=tuple(sorted(set(_attestation_errors) | {e for r in _other for e in r["errors"]})),
        build=_build,
        args=ERASURE_REVISION_ARGS,
        records=(_attestation,) + tuple(_other),
        notes="S2-FIX1 Q1 (F47; weave.erasure signer rules, error table): " + _why + ".",
    )


# -- Q3 (F69-1, F55 first part): the §4.4 step-5 outcome after the other rules of
#    step (7); the dedicated signer code of step 4 before the rules that consult
#    other records.


def _fix1_resign(record: dict[str, Any], signers: Sequence[str], *, unknown_alg: bool = False) -> dict[str, Any]:
    unsigned = {name: value for name, value in record.items() if name != "sigs"}
    result = recordlib.signed(unsigned, list(signers))
    if unknown_alg:
        result = {**result, "sigs": [{**entry, "alg": "ed25519-x"} for entry in result["sigs"]]}
    return result


def _fix1_expanding_sub_grant_files(signers: Sequence[str], *, unknown_alg: bool) -> dict[str, bytes]:
    parent = root_grant(
        record_id="grant-root-exceeds",
        kinds=("weave.grant", "example.note"),
        actions=("grant", "propose", "accept"),
        transferable=True,
    )
    child = delegated_grant(
        parent, record_id="grant-sub-exceeds", kinds=("example.note", "example.receipt")
    )
    return container([parent, _fix1_resign(child, signers, unknown_alg=unknown_alg)])


def _fix1_parent_expired_files() -> dict[str, bytes]:
    parent = root_grant(
        record_id="grant-root-parent-expired",
        valid_from=recordlib.T0,
        valid_until=recordlib.T3,
        kinds=("weave.grant", "example.note"),
        actions=("grant", "propose"),
        transferable=True,
    )
    child = delegated_grant(
        parent,
        record_id="grant-sub-parent-expired",
        valid_from=recordlib.T0,
        valid_until=recordlib.T3,
        recorded_at=recordlib.T4,
    )
    return container([parent, _fix1_resign(child, ["agent-1"], unknown_alg=True)])


declare(
    "grant",
    "sub-grant-expands-kinds-step5-outcome-last",
    "container",
    "container",
    "invalid",
    errors=("E_GRANT_DELEGATION_EXCEEDS",),
    build=lambda case_dir: _fix1_expanding_sub_grant_files(["agent-1"], unknown_alg=True),
    args=GRANT_ARGS,
    records=(
        {"id": "grant-sub-exceeds", "verdict": "invalid", "errors": ["E_GRANT_DELEGATION_EXCEEDS"]},
    ),
    notes="S2-FIX1 Q3 (F69-1; §4.4 step 5, §14.5): grant/sub-grant-expands-kinds whose only "
    "sigs entry (by agent-1, the sub-granter) uses the unknown algorithm ed25519-x. §4.4 "
    "step 5 applies (unverifiable E_SIG_UNVERIFIABLE), but that outcome is reported only "
    "after every other rule of step (7) has passed; the delegation check fails, so the "
    "record is invalid E_GRANT_DELEGATION_EXCEEDS.",
)

declare(
    "grant",
    "parent-expired-step5-outcome-last",
    "container",
    "container",
    "unverifiable",
    errors=("E_GRANT_EXPIRED",),
    build=lambda case_dir: _fix1_parent_expired_files(),
    args=GRANT_ARGS,
    records=(
        {"id": "grant-sub-parent-expired", "verdict": "unverifiable", "errors": ["E_GRANT_EXPIRED"]},
    ),
    notes="S2-FIX1 Q3 (F69-1): grant/parent-expired whose sub-grant's only sigs entry uses "
    "the unknown algorithm ed25519-x. The parent expired at T3 and the sub-grant is recorded "
    "at T4; the step-(7) chain rule fails (E_GRANT_EXPIRED) before the step-5 outcome "
    "(E_SIG_UNVERIFIABLE) would be reported, so the record is unverifiable E_GRANT_EXPIRED.",
)

declare(
    "grant",
    "sub-grant-granter-signer-before-delegation",
    "container",
    "container",
    "invalid",
    errors=("E_GRANT_GRANTER",),
    build=lambda case_dir: _fix1_expanding_sub_grant_files(["agent-2"], unknown_alg=False),
    args=GRANT_ARGS,
    records=(
        {"id": "grant-sub-exceeds", "verdict": "invalid", "errors": ["E_GRANT_GRANTER"]},
    ),
    notes="S2-FIX1 Q3 (F55 first part, first item; §14.5 step (7)): the expanding sub-grant "
    "of grant/sub-grant-expands-kinds is signed only by agent-2, a declared key that is not "
    "the sub-granter (agent-1), so §4.4 step 4 gives the dedicated signer code. The signer "
    "rule precedes the rules that consult other records (the delegated-chain checks), so "
    "the record is invalid E_GRANT_GRANTER, not E_GRANT_DELEGATION_EXCEEDS.",
)


def _fix1_class_conflict_unknown_alg_declaration() -> dict[str, Any]:
    material = key("device-1")
    body = {
        "algorithm": "ed25519",
        "key": material.key_id,
        "key_type": "program",
        "owner": kid("human-1"),
        "public_key": material.public_b64url(),
    }
    record = recordlib.build_record(
        kind="weave.key.declared",
        id="key-declared-fix1-device-1-as-program",
        actor={"type": "program", "key": material.key_id},
        body=body,
        stage="accepted",
        recorded_at=recordlib.T1,
        origin_instance=material.key_id,
    )
    return _fix1_resign(record, ["device-1", "human-1"], unknown_alg=True)


declare(
    "key-lifecycle",
    "declaration-class-conflict-before-step5-outcome",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_CLASS_CONFLICT",),
    build=lambda case_dir: container([_fix1_class_conflict_unknown_alg_declaration()]),
    args=_S2_ARGS,
    records=(
        {
            "id": "key-declared-fix1-device-1-as-program",
            "verdict": "invalid",
            "errors": ["E_KEY_CLASS_CONFLICT"],
        },
    ),
    notes="S2-FIX1 Q3 (F69-1; §4.4 step 5, §5.3): a container declaration re-declares the "
    "keyset's device-1 key as a program key; its two sigs entries (device-1 and the owner "
    "human-1) use the unknown algorithm ed25519-x, so §4.4 step 5 applies (unverifiable "
    "E_SIG_UNVERIFIABLE). That outcome waits until the other step-(7) rules have passed; "
    "the governing class (device, from the keyset) conflicts, so the record is invalid "
    "E_KEY_CLASS_CONFLICT.",
)


def _fix1_erasure_wrong_signer_files() -> dict[str, bytes]:
    original = erased_original("erasure-revision-original")
    grant = root_grant(
        record_id="erasure-basis-grant", grantee="program-1", kinds=("weave.erasure",),
        actions=("erase",), scope=("example",),
    )
    attestation = erasure_record(
        original,
        record_id="erasure-revision-attestation",
        reason="retention-expired",
        signer="program-1",
        basis=parent_ref(grant),
    )
    attestation = _fix1_resign(attestation, ["device-1"])
    placeholder = erased_placeholder(original, attestation)
    return container([placeholder, attestation])


declare(
    "erasure",
    "actor-program-signer-rule-before-basis-lookup",
    "container",
    "container",
    "invalid",
    errors=("E_ERASE_ACTOR",),
    build=lambda case_dir: _fix1_erasure_wrong_signer_files(),
    args=ERASURE_REVISION_ARGS,
    records=(
        {"id": "erasure-revision-attestation", "verdict": "invalid", "errors": ["E_ERASE_ACTOR"]},
    ),
    notes="S2-FIX1 Q1/Q3 (§14.5 step (7), weave.erasure signer rules): a program erasure "
    "whose body.basis names a grant that is not in the container (that alone is "
    "unverifiable E_GRANT_UNRESOLVED) is signed only by device-1, a declared key that is "
    "not the actor's (§4.4 step 4: the dedicated signer code E_ERASE_ACTOR). The signer "
    "rule precedes the lookup of the authorising grant, so the record is invalid "
    "E_ERASE_ACTOR.",
)


# -- Q5 (F68 open point): steps 1-5 of §5.5.2 are walked beyond the depth bound.
#    Step 1 needs every resolved parent to be a valid record, so a step-2..5
#    failure on a link reaches the records above it as step 1 (cascade).


def _fix1_deep_chain_bad_root_files(**root_kwargs: Any) -> dict[str, bytes]:
    root_args: dict[str, Any] = dict(
        record_id="grant-depth-root",
        kinds=("weave.grant", "example.note"),
        actions=("grant", "propose", "accept"),
        valid_from=recordlib.T0,
        valid_until=recordlib.T9,
        transferable=True,
    )
    root_args.update(root_kwargs)
    root = root_grant(**root_args)
    records = [root]
    parent = root
    grantee = "agent-2"
    final_grantee = grantee
    for index in range(9):
        final_grantee = grantee
        child = delegated_grant(
            parent,
            record_id="grant-depth-%d" % (index + 1),
            sub_granter="agent-1" if index % 2 == 0 else "agent-2",
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
    records.append(
        agent_action(
            parent, record_id="grant-depth-9-note", key_name=final_grantee,
            recorded_at=recordlib.T4, stage="accepted",
        )
    )
    return _wrap_internal(recordlib.build_container(records))


for _name, _root_kwargs, _code, _why in (
    ("chain-depth-9-root-not-transferable", dict(transferable=False), "E_GRANT_NOT_TRANSFERABLE",
     "the root grant is not transferable, so the ninth link (grant-depth-1 to the root, "
     "beyond the depth bound for the note) fails step 3"),
    ("chain-depth-9-first-link-exceeds", dict(kinds=("weave.grant",)), "E_GRANT_DELEGATION_EXCEEDS",
     "the root grant covers only weave.grant, so the ninth link (grant-depth-1 to the root, "
     "beyond the depth bound for the note) fails step 5 (example.note is not in the parent)"),
):
    declare(
        "grant",
        _name,
        "container",
        "container",
        "invalid",
        errors=(_code, "E_GRANT_UNRESOLVED"),
        build=lambda case_dir, _root_kwargs=_root_kwargs: _fix1_deep_chain_bad_root_files(
            **_root_kwargs
        ),
        args=GRANT_ARGS,
        records=(
            {"id": "grant-depth-1", "verdict": "invalid", "errors": [_code]},
            {"id": "grant-depth-2", "verdict": "unverifiable", "errors": ["E_GRANT_UNRESOLVED"]},
            {"id": "grant-depth-9", "verdict": "unverifiable", "errors": ["E_GRANT_UNRESOLVED"]},
            {"id": "grant-depth-9-note", "verdict": "unverifiable", "errors": ["E_GRANT_UNRESOLVED"]},
        ),
        notes="S2-FIX1 Q5 (F68 open point; §5.5.2): grant/chain-depth-9-links (a note citing "
        "the depth-9 grant, nine parent links, one beyond the bound) where " + _why + ". "
        "Steps 1-5 are walked beyond the bound as well, and step 1 requires each resolved "
        "parent to be a valid record: grant-depth-1 is itself invalid (" + _code + "), every "
        "grant above it fails step 1 (unverifiable E_GRANT_UNRESOLVED), and so does the note, "
        "whose walk stops at its first link. A failure beyond the bound is therefore never "
        "hidden behind step 7, and it reaches the note as step 1.",
    )


# -- T3: the §12.2 1a table, one universal tag number at a time (X.690) ---------

for _name, _identifier, _content, _verdict, _why in (
    # 7 ObjectDescriptor: a GraphicString (X.680), primitive only (§10.2), ISO 2022 (§11.4).
    ("l2-ts-der-1a-object-descriptor-primitive", b"\x07", b"A", "valid",
     "07 01 41: an ObjectDescriptor in the primitive form (control)"),
    ("l2-ts-der-1a-object-descriptor-constructed", b"\x27", b"\x07\x01A", "invalid",
     "27 03 07 01 41: an ObjectDescriptor in the constructed form; it is a restricted "
     "character string type, primitive only in DER (X.690 §10.2)"),
    ("l2-ts-der-1a-object-descriptor-escape", b"\x07", b"\x1b(B", "invalid",
     "07 03 1b 28 42: an ObjectDescriptor carrying an ISO 2022 escape sequence; 1a judges "
     "X.690 §11.4 conservatively (no ESC octet in an ISO 2022 register type)"),
    # 9 REAL: §8.5, §11.3.
    ("l2-ts-der-1a-real-plus-zero", b"\x09", b"", "valid",
     "09 00: the REAL plus zero, no contents octets (X.690 §8.5.2; control)"),
    ("l2-ts-der-1a-real-binary-one", b"\x09", b"\x80\x00\x01", "valid",
     "09 03 80 00 01: the REAL 1 in binary form, base 2, F = 0, a one-octet exponent 0 and "
     "the odd mantissa 1 (X.690 §8.5.7, §11.3.1; control)"),
    ("l2-ts-der-1a-real-decimal-nr3", b"\x09", b"\x0315.E-1", "valid",
     "09 07 03 31 35 2e 45 2d 31: the REAL 1.5 as NR3 '15.E-1' (X.690 §11.3.2; control)"),
    ("l2-ts-der-1a-real-minus-zero", b"\x09", b"\x43", "valid",
     "09 01 43: the REAL minus zero (X.690 §8.5.9; control)"),
    ("l2-ts-der-1a-real-constructed", b"\x29", b"\x09\x00", "invalid",
     "29 02 09 00: a REAL in the constructed form (X.690 §8.5.1: primitive)"),
    ("l2-ts-der-1a-real-base-8", b"\x09", b"\x90\x00\x01", "invalid",
     "09 03 90 00 01: a binary REAL with base 8; DER uses base 2 (X.690 §11.3.1)"),
    ("l2-ts-der-1a-real-scaling-factor", b"\x09", b"\x84\x00\x01", "invalid",
     "09 03 84 00 01: a binary REAL with scaling factor F = 1; DER requires F = 0 "
     "(X.690 §11.3.1)"),
    ("l2-ts-der-1a-real-even-mantissa", b"\x09", b"\x80\x00\x02", "invalid",
     "09 03 80 00 02: a binary REAL whose mantissa 2 is even; DER chooses M odd "
     "(X.690 §11.3.1)"),
    ("l2-ts-der-1a-real-mantissa-leading-zero", b"\x09", b"\x80\x00\x00\x01", "invalid",
     "09 04 80 00 00 01: the mantissa 1 written in two octets; M in the fewest octets "
     "(X.690 §11.3.1)"),
    ("l2-ts-der-1a-real-exponent-nonminimal", b"\x09", b"\x81\x00\x00\x01", "invalid",
     "09 04 81 00 00 01: the exponent 0 written in two octets (format 01); E in the fewest "
     "octets (X.690 §11.3.1)"),
    ("l2-ts-der-1a-real-long-exponent-format", b"\x09", b"\x83\x01\x00\x01", "invalid",
     "09 04 83 01 00 01: the exponent 0 in the long format 11 with one octet; the fewest "
     "octets use format 00 (X.690 §8.5.7.4, §11.3.1)"),
    ("l2-ts-der-1a-real-decimal-nr1", b"\x09", b"\x011", "invalid",
     "09 02 01 31: a decimal REAL in the NR1 form; DER uses NR3 (X.690 §11.3.2.1)"),
    ("l2-ts-der-1a-real-decimal-trailing-zero", b"\x09", b"\x0310.E+0", "invalid",
     "09 07 03 31 30 2e 45 2b 30: NR3 '10.E+0', whose mantissa ends in 0 "
     "(X.690 §11.3.2.4)"),
    ("l2-ts-der-1a-real-decimal-plus-exponent", b"\x09", b"\x031.E+1", "invalid",
     "09 06 03 31 2e 45 2b 31: NR3 '1.E+1', a non-zero exponent with a PLUS SIGN "
     "(X.690 §11.3.2.6)"),
    ("l2-ts-der-1a-real-special-reserved", b"\x09", b"\x44", "invalid",
     "09 01 44: a special REAL octet that X.690 §8.5.9 reserves"),
    # 10 ENUMERATED: primitive only (§8.4).
    ("l2-ts-der-1a-enumerated-constructed", b"\x2a", b"\x0a\x01\x01", "invalid",
     "2a 03 0a 01 01: an ENUMERATED in the constructed form (X.690 §8.4: primitive)"),
    # 13 RELATIVE-OID: §8.20.
    ("l2-ts-der-1a-relative-oid-minimal", b"\x0d", b"\x81\x00\x03", "valid",
     "0d 03 81 00 03: the RELATIVE-OID {128 3}, each sub-identifier minimal (control)"),
    ("l2-ts-der-1a-relative-oid-nonminimal", b"\x0d", b"\x80\x01", "invalid",
     "0d 02 80 01: a RELATIVE-OID sub-identifier with a leading 0x80 octet; sub-identifiers "
     "use the fewest octets (X.690 §8.20.2)"),
    ("l2-ts-der-1a-relative-oid-truncated", b"\x0d", b"\x81", "invalid",
     "0d 01 81: a RELATIVE-OID whose last sub-identifier octet has bit 8 set "
     "(X.690 §8.20.2)"),
    ("l2-ts-der-1a-relative-oid-empty", b"\x0d", b"", "invalid",
     "0d 00: a RELATIVE-OID with no sub-identifier"),
    ("l2-ts-der-1a-relative-oid-constructed", b"\x2d", b"\x0d\x01\x01", "invalid",
     "2d 03 0d 01 01: a RELATIVE-OID in the constructed form (X.690 §8.20.1: primitive)"),
    # 14 TIME and 34 DURATION: rejected (§11.9 canonical form not judged).
    ("l2-ts-der-1a-time-rejected", b"\x0e", b"2026-11-15", "invalid",
     "0e 0a '2026-11-15': a TIME value; its DER canonical form (X.690 §11.9) needs an "
     "ISO 8601 parser this profile does not define, so 1a rejects TIME values"),
    ("l2-ts-der-1a-time-constructed", b"\x2e", b"\x0e\x01A", "invalid",
     "2e 03 0e 01 41: a TIME in the constructed form (X.690 §8.26.1.1: primitive)"),
    ("l2-ts-der-1a-duration-rejected", b"\x1f\x22", b"P1D", "invalid",
     "1f 22 03 'P1D': a DURATION value (universal 34), rejected like TIME"),
    # 31-33, 35, 36: primitive, UTF-8 contents (§8.21, §8.22, §8.26).
    ("l2-ts-der-1a-date-utf8", b"\x1f\x1f", b"2026-11-15", "valid",
     "1f 1f 0a '2026-11-15': a DATE (universal 31) whose contents are UTF-8 (control)"),
    ("l2-ts-der-1a-date-not-utf8", b"\x1f\x1f", b"\xff", "invalid",
     "1f 1f 01 ff: a DATE whose contents are not UTF-8 (X.690 §8.26.2.2)"),
    ("l2-ts-der-1a-date-time-constructed", b"\x3f\x21", b"\x0c\x01A", "invalid",
     "3f 21 03 0c 01 41: a DATE-TIME (universal 33) in the constructed form "
     "(X.690 §8.26.4.1: primitive)"),
    ("l2-ts-der-1a-oid-iri-utf8", b"\x1f\x23", b"/a", "valid",
     "1f 23 02 '/a': an OID-IRI (universal 35) whose contents are UTF-8 (control)"),
    ("l2-ts-der-1a-relative-oid-iri-not-utf8", b"\x1f\x24", b"\xc0\x80", "invalid",
     "1f 24 02 c0 80: a RELATIVE-OID-IRI (universal 36) whose contents are an overlong, "
     "hence not UTF-8, sequence (X.690 §8.22.2)"),
    # 28 UniversalString, 30 BMPString: whole code units (§8.23.7, §8.23.8).
    ("l2-ts-der-1a-universal-string-units", b"\x1c", b"\x00\x00\x00A", "valid",
     "1c 04 00 00 00 41: a UniversalString of one 4-octet unit (control)"),
    ("l2-ts-der-1a-universal-string-partial-unit", b"\x1c", b"\x00\x00A", "invalid",
     "1c 03 00 00 41: a UniversalString that is not whole 4-octet units (X.690 §8.23.7)"),
    ("l2-ts-der-1a-bmp-string-units", b"\x1e", b"\x00A", "valid",
     "1e 02 00 41: a BMPString of one 2-octet unit (control)"),
    ("l2-ts-der-1a-bmp-string-partial-unit", b"\x1e", b"A", "invalid",
     "1e 01 41: a BMPString that is not whole 2-octet units (X.690 §8.23.8)"),
    # ISO 2022 register types (§11.4).
    ("l2-ts-der-1a-teletex-string-plain", b"\x14", b"A", "valid",
     "14 01 41: a TeletexString without escape sequences (control)"),
    ("l2-ts-der-1a-general-string-escape", b"\x1b", b"\x1b(B", "invalid",
     "1b 03 1b 28 42: a GeneralString with an escape sequence; 1a judges X.690 §11.4 "
     "conservatively (no ESC octet)"),
):
    _expected = _S2_VALID_L2 if _verdict == "valid" else _W3_SCHEMA_EXPECTED
    declare(
        "integrity-levels",
        _name,
        "container",
        "container",
        _verdict,
        build=lambda case_dir, _identifier=_identifier, _content=_content: _crafted_l2_files(
            case_dir,
            tsr_factory=lambda imprint: _x1_resigned(_x1_unsigned_value(_identifier, _content))(
                _crafted_tsr(imprint)
            ),
        ),
        notes="S2-FIX1 T3 (§12.2 1a table, X.690 per universal tag number): the receipt gains "
        "one unregistered unsigned attribute (an open type, judged by its framing and the "
        "universal rules of 1a only) whose value is " + _why + ". The receipt is otherwise "
        "fully re-signed with the test TSA key.",
        **_expected,
    )


# -- Q4 (F64): the check-10 key and signature-encoding bounds ---------------------
#    RSA modulus 2048-8192 bits; public exponent odd, 65537 <= e < 2^256; ECDSA
#    Ecdsa-Sig-Value a DER SEQUENCE of two minimal positive INTEGERs in [1, n-1].

_FIX1_RSA: dict[tuple[int, int], Any] = {}
_FIX1_SMALL_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71)


def _fix1_probable_prime(candidate: int) -> bool:
    """Deterministic Miller-Rabin with the first twenty primes as bases."""
    for prime in _FIX1_SMALL_PRIMES:
        if candidate % prime == 0:
            return candidate == prime
    exponent, rounds = candidate - 1, 0
    while exponent % 2 == 0:
        exponent //= 2
        rounds += 1
    for base in _FIX1_SMALL_PRIMES:
        value = pow(base, exponent, candidate)
        if value in (1, candidate - 1):
            continue
        for _ in range(rounds - 1):
            value = value * value % candidate
            if value == candidate - 1:
                break
        else:
            return False
    return True


def _fix1_prime(label: bytes, bits: int, public_exponent: int) -> int:
    """A deterministic prime of exactly *bits* bits from SHA-512 expansion of *label*."""
    counter = 0
    while True:
        stream = b""
        block = 0
        while len(stream) * 8 < bits:
            stream += hashlib.sha512(label + counter.to_bytes(4, "big") + bytes([block])).digest()
            block += 1
        candidate = int.from_bytes(stream, "big") >> (len(stream) * 8 - bits)
        candidate |= (3 << (bits - 2)) | 1
        while True:
            if _fix1_probable_prime(candidate):
                if _gcd(candidate - 1, public_exponent) == 1:
                    return candidate
                break
            candidate += 2
            if candidate.bit_length() != bits:
                break
        counter += 1


def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def _fix1_rsa_key(bits: int, public_exponent: int) -> Any:
    from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa

    cached = _FIX1_RSA.get((bits, public_exponent))
    if cached is not None:
        return cached
    label = b"weave-record/1/test-tsa-rsa/%d/%d/" % (bits, public_exponent)
    p = _fix1_prime(label + b"p", bits // 2, public_exponent)
    q = _fix1_prime(label + b"q", bits // 2, public_exponent)
    if p < q:
        p, q = q, p
    phi = (p - 1) * (q - 1)
    d = pow(public_exponent, -1, phi // _gcd(p - 1, q - 1))
    key = crypto_rsa.RSAPrivateNumbers(
        p=p, q=q, d=d, dmp1=d % (p - 1), dmq1=d % (q - 1), iqmp=pow(q, -1, p),
        public_numbers=crypto_rsa.RSAPublicNumbers(public_exponent, p * q),
    ).private_key(unsafe_skip_rsa_key_validation=True)
    _FIX1_RSA[(bits, public_exponent)] = key
    return key


def _fix1_rsa_sign(key: Any, message: bytes) -> bytes:
    return key.sign(message, crypto_padding.PKCS1v15(), crypto_hashes.SHA256())


_FIX1_RSA_CERTIFICATES: dict[tuple[int, int], bytes] = {}


def _fix1_rsa_certificate(bits: int, public_exponent: int) -> bytes:
    """A deterministic self-signed timeStamping certificate for that RSA key."""
    cached = _FIX1_RSA_CERTIFICATES.get((bits, public_exponent))
    if cached is not None:
        return cached
    key = _fix1_rsa_key(bits, public_exponent)
    spki = key.public_key().public_bytes(
        crypto_serialization.Encoding.DER,
        crypto_serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    name = asn1_x509.Name.build(
        {"common_name": "Hyphaweave S2-FIX1 test TSA RSA-%d e=%d (test only)" % (bits, public_exponent)}
    )
    tbs = asn1_x509.TbsCertificate()
    tbs["version"] = "v3"
    tbs["serial_number"] = 8000 + bits % 1000
    tbs["signature"] = {"algorithm": "sha256_rsa", "parameters": None}
    tbs["issuer"] = name
    validity = asn1_x509.Validity()
    validity["not_before"] = asn1_x509.Time(
        {"utc_time": datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)}
    )
    validity["not_after"] = asn1_x509.Time(
        {"general_time": datetime.datetime(2126, 1, 1, tzinfo=datetime.timezone.utc)}
    )
    tbs["validity"] = validity
    tbs["subject"] = name
    tbs["subject_public_key_info"] = asn1_x509.PublicKeyInfo.load(spki)
    tbs["extensions"] = [
        asn1_x509.Extension({"extn_id": "key_usage", "critical": True,
                             "extn_value": asn1_x509.KeyUsage({"digital_signature"})}),
        asn1_x509.Extension({"extn_id": "extended_key_usage", "critical": True,
                             "extn_value": asn1_x509.ExtKeyUsageSyntax(["time_stamping"])}),
    ]
    certificate = asn1_x509.Certificate()
    certificate["tbs_certificate"] = tbs
    certificate["signature_algorithm"] = {"algorithm": "sha256_rsa", "parameters": None}
    certificate["signature_value"] = _fix1_rsa_sign(key, tbs.dump())
    _FIX1_RSA_CERTIFICATES[(bits, public_exponent)] = certificate.dump()
    return _FIX1_RSA_CERTIFICATES[(bits, public_exponent)]


def _fix1_rsa_files(case_dir: Path, bits: int, public_exponent: int) -> dict[str, bytes]:
    certificate = _fix1_rsa_certificate(bits, public_exponent)
    key = _fix1_rsa_key(bits, public_exponent)

    def factory(imprint: bytes) -> bytes:
        tree = _der_tree(_crafted_tsr(imprint, certificate_der=certificate))
        _x1_resign(tree, sign=lambda message: _fix1_rsa_sign(key, message))
        return _der_encode(tree)

    files = _crafted_l2_files(case_dir, tsr_factory=factory, trust_name=None)
    files[TSA_CERT_NAME] = _s2_pem(certificate)
    return files


def _fix1_ecdsa_signature_edit(edit: Callable[[bytes], bytes]) -> Callable[[bytes], bytes]:
    """The P-384 receipt (ecdsa-with-SHA384) with its Ecdsa-Sig-Value re-encoded."""

    def factory(imprint: bytes) -> bytes:
        tree = _der_tree(_s2_p384_tsr(_S2_ECDSA_SHA384)(imprint))
        signer_info = _w3_signer_info(tree)
        position = next(
            index for index, child in enumerate(signer_info.children) if child.tag == 0xA0
        )
        signature = next(
            child for child in signer_info.children[position + 1 :] if child.tag == 0x04
        )
        signature.content = edit(signature.content)
        return _der_encode(tree)

    return factory


def _fix1_ecdsa_components(value: bytes) -> tuple[bytes, bytes]:
    if value[0] != 0x30 or value[1] & 0x80:
        raise SystemExit("unexpected Ecdsa-Sig-Value shape")
    body = value[2:]
    r_length = body[1]
    r = body[2 : 2 + r_length]
    rest = body[2 + r_length :]
    s = rest[2 : 2 + rest[1]]
    return r, s


def _fix1_ecdsa_encode(r: bytes, s: bytes) -> bytes:
    body = b"\x02" + bytes([len(r)]) + r + b"\x02" + bytes([len(s)]) + s
    return b"\x30" + bytes([len(body)]) + body


def _fix1_ecdsa_r_padded(value: bytes) -> bytes:
    r, s = _fix1_ecdsa_components(value)
    return _fix1_ecdsa_encode(b"\x00" + r, s)


def _fix1_ecdsa_trailing(value: bytes) -> bytes:
    return value + b"\x00"


def _fix1_ecdsa_s_plus_order(value: bytes) -> bytes:
    r, s = _fix1_ecdsa_components(value)
    shifted = int.from_bytes(s, "big") + _S2_P384_ORDER
    content = shifted.to_bytes((shifted.bit_length() + 8) // 8, "big")
    return _fix1_ecdsa_encode(r, content)


for _name, _bits, _exponent, _verdict, _why in (
    ("l2-ts-check10-rsa-1024", 1024, 65537, "invalid",
     "a 1024-bit RSA modulus, below the 2048-bit lower bound"),
    ("l2-ts-check10-rsa-exponent-3", 2048, 3, "invalid",
     "a 2048-bit RSA key with public exponent 3, below 65537"),
    ("l2-ts-check10-rsa-exponent-2-pow-256-plus-1", 2048, (1 << 256) + 1, "invalid",
     "a 2048-bit RSA key with public exponent 2^256 + 1, at or above the 2^256 limit"),
    ("l2-ts-check10-rsa-exponent-65539", 2048, 65539, "valid",
     "a 2048-bit RSA key with public exponent 65539 (odd, inside the bounds; control)"),
):
    _expected: dict[str, Any] = dict(
        args=_S2_L2_ARGS,
        records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    )
    if _verdict == "valid":
        _expected["expected_container"] = {"anchor_verified": True}
    declare(
        "integrity-levels",
        _name,
        "container",
        "container",
        _verdict,
        errors=() if _verdict == "valid" else ("E_TS_CMS",),
        build=lambda case_dir, _bits=_bits, _exponent=_exponent: _fix1_rsa_files(
            case_dir, _bits, _exponent
        ),
        notes="S2-FIX1 Q4 (F64; §12.2 check 10): the receipt's signer is a deterministic "
        "self-signed timeStamping certificate for " + _why + "; the receipt is "
        "signed with that key (sha256WithRSAEncryption, RSA PKCS#1 v1.5, a valid "
        "signature) and the case's trust anchor is that certificate. Check 10 accepts RSA "
        "moduli of 2048 to 8192 bits and odd public exponents with 65537 <= e < 2^256; "
        "outside them the signature does not count (E_TS_CMS).",
        **_expected,
    )

for _name, _edit, _why in (
    ("l2-ts-check10-ecdsa-r-nonminimal", _fix1_ecdsa_r_padded,
     "r is re-encoded with a redundant leading 0x00 octet (not the shortest INTEGER)"),
    ("l2-ts-check10-ecdsa-trailing-octet", _fix1_ecdsa_trailing,
     "one 0x00 octet follows the Ecdsa-Sig-Value SEQUENCE"),
    ("l2-ts-check10-ecdsa-s-plus-order", _fix1_ecdsa_s_plus_order,
     "s is replaced by s + n (the same value modulo the P-384 order n, outside [1, n - 1])"),
):
    declare(
        "integrity-levels",
        _name,
        "container",
        "container",
        "invalid",
        errors=("E_TS_CMS",),
        build=lambda case_dir, _edit=_edit: _s2_p384_files(
            case_dir, _fix1_ecdsa_signature_edit(_edit)
        ),
        args=_S2_L2_ARGS,
        records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
        notes="S2-FIX1 Q4 (F64; §12.2 check 10): integrity-levels/l2-ts-signer-p384-sha384 "
        "(a valid ecdsa-with-SHA384 receipt by the deterministic P-384 test TSA) whose "
        "signature value is changed after signing: " + _why + ". The Ecdsa-Sig-Value must "
        "be a DER SEQUENCE of two shortest positive INTEGERs r, s in [1, n - 1] with no "
        "trailing octets (E_TS_CMS).",
    )


# -- T8 / review A low-1: readable/ and the limitations when the pipeline stops ---


def _fix1_readable_root_file(zip_form: bool) -> dict[str, bytes]:
    files = dict(recordlib.build_container(SIMPLE_RECORDS()))
    files["readable"] = b"a regular file named readable at the container root\n"
    if zip_form:
        return {"container.zip": as_zip(files)}
    return _wrap_internal(files)


for _name, _zip_form in (("readable-root-regular-file", False), ("readable-root-regular-file-zip", True)):
    declare(
        "container",
        _name,
        "container",
        "container.zip" if _zip_form else "container",
        "invalid",
        errors=("E_CONTAINER_ENTRY",),
        build=lambda case_dir, _zip_form=_zip_form: _fix1_readable_root_file(_zip_form),
        args=("--keys", "@keyset"),
        records=[],
        notices_absent=("N_READABLE_PRESENT",),
        notes="S2-FIX1 T8 (§11.1, §11.8): the container root holds a regular file named "
        "`readable`. `readable/` is a directory of the layout; a regular file of that name is "
        "not a readable/ entry but an entry outside the layout: E_CONTAINER_ENTRY (invalid), "
        "and no N_READABLE_PRESENT (" + ("zip form" if _zip_form else "directory form") + ").",
    )


def _fix1_readable_then_crc_mismatch() -> bytes:
    archive = bytearray(_zip_readable_extra("readable/notes.txt"))
    position = archive.find(b'{"actor"')
    if position < 0:
        raise SystemExit("record member data not found in the stored archive")
    archive[position + 20] ^= 0x01
    return bytes(archive)


declare(
    "container",
    "readable-not-reported-after-zip-structure-failure",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_ZIP",),
    build=lambda case_dir: {"container.zip": _fix1_readable_then_crc_mismatch()},
    args=("--keys", "@keyset"),
    records=[],
    notices_absent=("N_READABLE_PRESENT",),
    notes="S2-FIX1 (review A low-1; §11.8, §11.9, §14.5): the archive has a well-formed "
    "readable/notes.txt entry and one byte of a record member's stored data is flipped, so "
    "its CRC fails (§11.9 rule 5): E_CONTAINER_ZIP. An archive whose zip structure fails "
    "has no enumerated entries and the later checks are not run, so N_READABLE_PRESENT is "
    "not reported.",
)

declare(
    "container",
    "readable-reported-after-entry-check-failure",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_ENTRY",),
    build=lambda case_dir: {
        "container.zip": _zip_standard(
            extra=(
                ("readable/notes.txt", b"x", 3, _STANDARD_ATTR),
                ("records/link.json", b"x", 3, _SYMLINK_ATTR),
            )
        )[0]
    },
    args=("--keys", "@keyset"),
    records=[],
    notices=("N_READABLE_PRESENT",),
    notes="S2-FIX1 (review A low-1; §11.8, T6/F32): the archive's zip structure holds; its "
    "readable/notes.txt entry passes its own entry checks and a records/link.json entry has "
    "the Unix symlink type (E_CONTAINER_ENTRY). The entries were enumerated and the "
    "readable/ entry was observed, so N_READABLE_PRESENT is reported (control for "
    "readable-not-reported-after-zip-structure-failure).",
)


def _fix1_listing_failure(records: list[dict[str, Any]], corrupt_id: str) -> dict[str, bytes]:
    files = dict(recordlib.build_container(records))
    target = next(record for record in records if record.get("id") == corrupt_id)
    path = "records/%s.json" % recordlib.record_digest(target)[len("sha256:"):]
    files[path] = files[path].replace(b'"accepted"', b'"proposed"', 1)
    return _wrap_internal(files)


def _fix1_erasure_listing_failure() -> dict[str, bytes]:
    original = erased_original()
    attestation = erasure_record(original)
    placeholder = erased_placeholder(original, attestation)
    return _fix1_listing_failure([placeholder, attestation], attestation["id"])


def _fix1_labels_listing_failure() -> dict[str, bytes]:
    labelled = recordlib.note(
        "fix1-labelled-note", stage="accepted", labels={"sensitivity": "internal"}
    )
    other = recordlib.note("fix1-plain-note", stage="accepted")
    return _fix1_listing_failure(
        [recordlib.signed(labelled, "human-1"), recordlib.signed(other, "human-1")],
        "fix1-plain-note",
    )


for _name, _build, _what in (
    ("erased-placeholder-limitation-not-reported-after-listing-failure",
     _fix1_erasure_listing_failure,
     "a weave.erased placeholder and its erasure record; the erasure record's file is "
     "changed after sealing (its digest no longer matches the manifest). "
     "L_ERASED_PLACEHOLDER"),
    ("labels-limitation-not-reported-after-listing-failure",
     _fix1_labels_listing_failure,
     "a note carrying labels and a plain note; the plain note's file is changed after "
     "sealing. L_LABELS_ARE_CLAIMS"),
):
    declare(
        "container",
        _name,
        "container",
        "container",
        "invalid",
        errors=("E_MANIFEST_RECORD_DIGEST",),
        build=lambda case_dir, _build=_build: _build(),
        args=("--keys", "@keyset"),
        records=[],
        limitations=("L_OFFLINE_CONTEXT",),
        notes="S2-FIX1 (review A low-1; §14.5, §14.9): the container holds " + _what
        + " describes the records that are verified; the records-listing phase stops the "
        "container with E_MANIFEST_RECORD_DIGEST and records: [], no record is verified "
        "and the later checks are not run, so it is not reported.",
    )


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
    if case.expected_input is not None:
        expected["expected_input"] = case.expected_input
    if case.limitations is not None:
        expected["limitations"] = list(case.limitations)
    if case.notices_absent is not None:
        expected["notices_absent"] = list(case.notices_absent)
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
        expected_links = dict(case.symlinks)
        if check:
            if not case_dir.is_dir():
                problems.append("missing case dir %s" % case_dir)
                continue
            existing: dict[str, bytes] = {}
            existing_links: dict[str, str] = {}
            for path in case_dir.rglob("*"):
                relative = str(path.relative_to(case_dir))
                if path.is_symlink():
                    existing_links[relative] = os.readlink(path)
                elif path.is_file():
                    existing[relative] = path.read_bytes()
            for name, data in sorted(target_files.items()):
                if name not in existing:
                    problems.append("missing %s/%s" % (case_dir, name))
                elif existing[name] != data:
                    problems.append("content mismatch %s/%s" % (case_dir, name))
            for name in sorted(existing):
                if name not in target_files:
                    problems.append("unexpected file %s/%s" % (case_dir, name))
            for name, link_target in sorted(expected_links.items()):
                if name not in existing_links:
                    problems.append("missing symlink %s/%s" % (case_dir, name))
                elif existing_links[name] != link_target:
                    problems.append("symlink mismatch %s/%s" % (case_dir, name))
            for name in sorted(existing_links):
                if name not in expected_links:
                    problems.append("unexpected symlink %s/%s" % (case_dir, name))
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
        for name, link_target in sorted(expected_links.items()):
            destination = case_dir / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.symlink_to(link_target)
    return problems



# ---------------------------------------------------------------------------
# Frozen regression set (`vectors/README.md`, gate 7)
# ---------------------------------------------------------------------------

FREEZE_VERSION = "v0.1-candidate"

# S1-FIX1 T7: the revision-3 regeneration dropped these twelve representative
# cases although their conclusions were unchanged (the selection rule had picked
# lexicographically earlier cases instead). Candidate sets only grow until the
# formal freeze, so they are restored here and the freeze step keeps every case
# that is already in the candidate.
RESTORED_REPRESENTATIVES: tuple[str, ...] = (
    "container/record-digest-mismatch",
    "container/record-extra",
    "container/record-missing",
    "erasure/reason-invalid",
    "grant/revocation-unlisted-human",
    "integrity-levels/l2-content-type-wrong",
    "integrity-levels/l2-ts-file-digest",
    "key-lifecycle/keyset-root-not-invalidated",
    "key-lifecycle/public-key-invalid",
    "key-lifecycle/retired-boundary-equal",
    "ref/bad-hint-scheme",
    "sig/invalid-value",
)


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


def freeze_cases(
    *,
    source_commit: str,
    freeze_date: str,
    delta_markdown: str | None = None,
    preserve_existing: bool = False,
    selection_rule: str | None = None,
) -> int:
    """Copy the representative set verbatim into vectors/frozen/<version>/.

    ``delta_markdown`` is an optional reviewed "what changed in this
    regeneration" section appended to ``FROZEN.md`` before the checksums are
    computed (S17 requires every changed case to be listed with its old and new
    conclusion and the ruling it belongs to). The delta text is review
    documentation for one regeneration and is not committed separately, so a
    later ``--freeze`` run must supply the text for that regeneration itself.

    ``preserve_existing`` applies the "the candidate set only grows" policy: the
    cases already present in the destination are kept (copied from the current
    main corpus) and the ``RESTORED_REPRESENTATIVES`` are added on top, instead
    of recomputing the selection rule over the whole corpus. ``selection_rule``
    overrides the selection-rule sentence written into ``FROZEN.md``.
    """
    rows = _all_case_expected()
    destination = VECTORS_DIR / "frozen" / FREEZE_VERSION
    if preserve_existing:
        existing_ids: set[str] = set()
        if destination.is_dir():
            for expected_path in destination.glob("*/*/expected.json"):
                existing_ids.add(wcj.parse_strict(expected_path.read_bytes())["id"])
        by_id = {row["id"]: row for row in rows}
        selected_ids = existing_ids | set(RESTORED_REPRESENTATIVES)
        missing = sorted(selected_ids - set(by_id))
        if missing:
            raise SystemExit(
                "preserved/restored frozen cases missing from the main corpus: %s"
                % ", ".join(missing)
            )
        selected = [by_id[case_id] for case_id in sorted(selected_ids)]
    else:
        selected = select_frozen_cases(rows)
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
        "- Selection rule: "
        + (
            selection_rule
            or "**every positive case** (`valid`/`erased`) plus, for each error "
            "code that appears in any case, the lexicographically first case that "
            "expects it. This keeps at least one negative per registered error "
            "code while remaining deterministic."
        ),
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
    if delta_markdown:
        lines.append(delta_markdown.rstrip("\n"))
        lines.append("")
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
    parser.add_argument(
        "--frozen-delta",
        metavar="PATH",
        help="reviewed delta section appended to FROZEN.md (S17 regeneration "
        "documentation; read before the checksums are computed)",
    )
    parser.add_argument(
        "--preserve-existing",
        action="store_true",
        help="keep every case already in the frozen candidate and add the "
        "RESTORED_REPRESENTATIVES on top (candidate set only grows)",
    )
    parser.add_argument(
        "--selection-rule",
        metavar="TEXT",
        help="override the selection-rule sentence written into FROZEN.md",
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
        delta_markdown = None
        if arguments.frozen_delta:
            delta_markdown = Path(arguments.frozen_delta).read_text(encoding="utf-8")
        return freeze_cases(
            source_commit=arguments.frozen_source_commit,
            freeze_date=freeze_date,
            delta_markdown=delta_markdown,
            preserve_existing=arguments.preserve_existing,
            selection_rule=arguments.selection_rule,
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
