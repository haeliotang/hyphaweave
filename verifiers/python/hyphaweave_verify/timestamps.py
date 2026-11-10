# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""L2 external anchors: RFC 3161 ``TimeStampResp`` verification (spec §12).

The verification is deliberately honest about what it can establish offline:

* the response must be DER ``TimeStampResp`` with a granted token and a
  well-formed ``TSTInfo`` (``E_TS_SCHEMA``);
* the token's ``messageImprint`` must be ``{sha256, raw 32-byte manifest digest}``
  (``E_TS_IMPRINT``);
* the CMS signature over the DER-encoded signed attributes, the ESS
  ``messageDigest``/``signingCertificateV2`` attributes and the signer
  certificate resolution must verify (``E_TS_CMS``);
* the signer certificate must be valid at ``genTime`` and carry a timestamping
  key usage (``E_TS_CERT``);
* trust requires an explicit anchor whose SHA-256 fingerprint matches the signer
  certificate. Without a matching anchor the timestamp is
  ``present-unverified`` and the container must not be ``valid``
  (``E_TS_UNTRUSTED``).

No network access, no wall clock, no trust store discovery: anchors are supplied
by the caller (``--tsa-trust``).
"""

from __future__ import annotations

import datetime as _datetime
import hashlib
from dataclasses import dataclass

from asn1crypto import cms, tsp
from cryptography import x509 as cryptography_x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from .errors import ERROR_CODES, WeaveError

MAX_TIMESTAMP_BYTES = 1_048_576

#: Timestamp states reported in the report's ``container.timestamps[].state``.
STATE_VERIFIED = "verified"
STATE_PRESENT_UNVERIFIED = "present-unverified"
STATE_INVALID = "invalid"


@dataclass(frozen=True)
class TimestampResult:
    """The verification outcome for one listed TSR file."""

    digest: str
    path: str
    state: str
    gen_time: str | None
    error: str | None

    def to_report(self, index: int) -> dict[str, object]:
        return {
            "gen_time": self.gen_time,
            "index": index,
            "state": self.state,
        }


def parse_trust_anchors(pem_bytes: bytes) -> frozenset[bytes]:
    """Parse a PEM bundle of trust-anchor certificates into DER SHA-256 fingerprints."""
    try:
        certificates = cryptography_x509.load_pem_x509_certificates(pem_bytes)
    except ValueError as error:
        raise WeaveError("E_TS_UNTRUSTED", "TSA trust file is not a PEM certificate bundle") from error
    return frozenset(hashlib.sha256(cert.public_bytes(_encoding())).digest() for cert in certificates)


def _encoding():
    from cryptography.hazmat.primitives.serialization import Encoding

    return Encoding.DER


def verify_timestamp_file(
    *,
    tsr_bytes: bytes,
    listed_digest: str,
    path: str,
    manifest_digest: str,
    trust_anchor_fingerprints: frozenset[bytes] | None,
) -> TimestampResult:
    """Verify one exported TSR against the manifest digest and the trust anchors."""
    if len(tsr_bytes) > MAX_TIMESTAMP_BYTES:
        return _invalid(listed_digest, path, "E_JSON_SIZE")
    try:
        gen_time, signer_certificate_der = _verify_token(tsr_bytes, manifest_digest)
    except WeaveError as error:
        return _invalid(listed_digest, path, error.code)
    if trust_anchor_fingerprints is None or not trust_anchor_fingerprints:
        return TimestampResult(
            digest=listed_digest,
            path=path,
            state=STATE_PRESENT_UNVERIFIED,
            gen_time=gen_time,
            error="E_TS_UNTRUSTED",
        )
    fingerprint = hashlib.sha256(signer_certificate_der).digest()
    if fingerprint not in trust_anchor_fingerprints:
        return TimestampResult(
            digest=listed_digest,
            path=path,
            state=STATE_PRESENT_UNVERIFIED,
            gen_time=gen_time,
            error="E_TS_UNTRUSTED",
        )
    return TimestampResult(
        digest=listed_digest,
        path=path,
        state=STATE_VERIFIED,
        gen_time=gen_time,
        error=None,
    )


def _invalid(listed_digest: str, path: str, code: str) -> TimestampResult:
    assert ERROR_CODES[code] == "invalid"
    return TimestampResult(
        digest=listed_digest,
        path=path,
        state=STATE_INVALID,
        gen_time=None,
        error=code,
    )


# ---------------------------------------------------------------------------
# DER / CMS verification
# ---------------------------------------------------------------------------


def _verify_token(tsr_bytes: bytes, manifest_digest: str) -> tuple[str, bytes]:
    """Verify the TSR's structure, imprint and CMS evidence; return (genTime, cert DER)."""
    try:
        response = tsp.TimeStampResp.load(tsr_bytes)
    except Exception as error:  # asn1crypto raises ValueError subtypes
        raise WeaveError("E_TS_SCHEMA", "not a DER TimeStampResp") from error
    try:
        status = response["status"]["status"].native
    except Exception as error:
        raise WeaveError("E_TS_SCHEMA", "TimeStampResp has no readable status") from error
    if status != "granted":
        raise WeaveError("E_TS_SCHEMA", "TimeStampResp status is not granted")
    token = response["time_stamp_token"]
    if token["content_type"].native != "signed_data":
        raise WeaveError("E_TS_SCHEMA", "timestamp token is not CMS signed data")
    signed_data = token["content"]

    encap = signed_data["encap_content_info"]
    if encap["content_type"].native != "tst_info":
        raise WeaveError("E_TS_SCHEMA", "timestamp token does not encapsulate TSTInfo")
    content = encap["content"]
    try:
        raw_content = content.contents
        tst_info = tsp.TSTInfo.load(raw_content)
    except Exception as error:
        raise WeaveError("E_TS_SCHEMA", "malformed TSTInfo") from error

    try:
        imprint = tst_info["message_imprint"]
        algorithm = imprint["hash_algorithm"]["algorithm"].native
        hashed_message = imprint["hashed_message"].native
    except Exception as error:
        raise WeaveError("E_TS_SCHEMA", "TSTInfo has no readable messageImprint") from error
    raw_manifest_digest = _parse_digest_bytes(manifest_digest)
    if algorithm != "sha256" or hashed_message != raw_manifest_digest:
        raise WeaveError("E_TS_IMPRINT", "messageImprint does not match the manifest digest")

    try:
        gen_time_value = tst_info["gen_time"].native
    except Exception as error:
        raise WeaveError("E_TS_SCHEMA", "TSTInfo has no readable genTime") from error
    gen_time = _format_gen_time(gen_time_value)

    signer_info, signer_certificate_der = _verify_cms_signature(signed_data, raw_content)
    _check_signer_certificate(signer_certificate_der, gen_time_value)
    return gen_time, signer_certificate_der


def _parse_digest_bytes(manifest_digest: str) -> bytes:
    """Accept ``sha256:<64hex>`` or bare 64 lowercase hex; reject anything else."""
    hex_value = manifest_digest
    if hex_value.startswith("sha256:"):
        hex_value = hex_value[len("sha256:"):]
    if len(hex_value) != 64 or any(character not in "0123456789abcdef" for character in hex_value):
        raise WeaveError("E_TS_IMPRINT", "manifest digest is not a sha256 digest string")
    return bytes.fromhex(hex_value)


def _format_gen_time(value: object) -> str:
    if not isinstance(value, _datetime.datetime):
        raise WeaveError("E_TS_SCHEMA", "genTime is not a timestamp")
    if value.tzinfo is None:
        value = value.replace(tzinfo=_datetime.timezone.utc)
    utc = value.astimezone(_datetime.timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (utc.microsecond // 1000)


def _verify_cms_signature(signed_data: cms.SignedData, raw_content: bytes):
    signer_infos = signed_data["signer_infos"]
    if len(signer_infos) < 1:
        raise WeaveError("E_TS_CMS", "timestamp token has no signerInfo")
    signer_info = signer_infos[0]
    if signer_info["digest_algorithm"]["algorithm"].native != "sha256":
        raise WeaveError("E_TS_CMS", "unsupported timestamp digest algorithm")
    signed_attrs = signer_info["signed_attrs"]
    if signed_attrs.native is None or len(signed_attrs) == 0:
        raise WeaveError("E_TS_CMS", "timestamp token has no signed attributes")
    try:
        signed_attrs_der = signed_attrs.untag().dump()
    except Exception as error:
        raise WeaveError("E_TS_CMS", "signed attributes cannot be encoded") from error

    signer_certificate_der = _find_signer_certificate(signed_data, signer_info)
    certificate = cryptography_x509.load_der_x509_certificate(signer_certificate_der)

    # Signed attributes: content type, message digest, ESS signing certificate v2.
    digest_algorithm = hashes.SHA256()
    message_digest = hashlib.sha256(raw_content).digest()
    content_type_ok = False
    message_digest_ok = False
    signing_certificate_seen = False
    for attribute in signed_attrs:
        attribute_type = attribute["type"].native
        values = attribute["values"]
        if attribute_type == "content_type":
            if len(values) != 1 or values[0].native != "tst_info":
                raise WeaveError("E_TS_CMS", "content_type attribute is not TSTInfo")
            content_type_ok = True
        elif attribute_type == "message_digest":
            if len(values) != 1 or values[0].native != message_digest:
                raise WeaveError("E_TS_CMS", "ESS messageDigest does not match the token content")
            message_digest_ok = True
        elif attribute_type == "signing_certificate_v2":
            signing_certificate_seen = True
            _check_ess_signing_certificate(values, signer_certificate_der)
    if not content_type_ok or not message_digest_ok:
        raise WeaveError("E_TS_CMS", "required signed attributes are missing")
    if not signing_certificate_seen:
        raise WeaveError("E_TS_CMS", "ESS signingCertificateV2 attribute is missing")

    signature = signer_info["signature"].native
    signature_algorithm = signer_info["signature_algorithm"]["algorithm"].native
    public_key = certificate.public_key()
    try:
        if signature_algorithm in ("rsassa_pkcs1v15", "sha256_rsa", "rsa"):
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise WeaveError("E_TS_CERT", "signature algorithm does not match the key")
            public_key.verify(signature, signed_attrs_der, padding.PKCS1v15(), hashes.SHA256())
        elif signature_algorithm in ("ecdsa", "sha256_ecdsa"):
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise WeaveError("E_TS_CERT", "signature algorithm does not match the key")
            public_key.verify(signature, signed_attrs_der, ec.ECDSA(hashes.SHA256()))
        else:
            raise WeaveError(
                "E_TS_CERT", "unsupported timestamp signature algorithm"
            )
    except WeaveError:
        raise
    except (InvalidSignature, UnsupportedAlgorithm) as error:
        raise WeaveError("E_TS_CMS", "CMS signature does not verify") from error
    except Exception as error:  # pragma: no cover - defensive: provider errors
        raise WeaveError("E_TS_CMS", "CMS signature does not verify") from error
    return signer_info, signer_certificate_der


def _find_signer_certificate(signed_data: cms.SignedData, signer_info) -> bytes:
    certificates = signed_data["certificates"]
    if certificates.native is None or len(certificates) == 0:
        raise WeaveError("E_TS_CMS", "timestamp token carries no signer certificate")
    sid = signer_info["sid"]
    chosen = sid.chosen
    for index in range(len(certificates)):
        certificate_choice = certificates[index]
        if certificate_choice.name != "certificate":
            continue
        certificate = certificate_choice.chosen
        if sid.name == "issuer_and_serial_number":
            if (
                certificate.serial_number == chosen["serial_number"].native
                and certificate.issuer.dump() == chosen["issuer"].dump()
            ):
                return certificate.dump()
        elif sid.name == "subject_key_identifier":
            try:
                extension = certificate.key_identifier_value
            except Exception:
                extension = None
            if extension is not None and extension == chosen.native:
                return certificate.dump()
    raise WeaveError("E_TS_CMS", "signer certificate not found in the token")


def _check_ess_signing_certificate(values, signer_certificate_der: bytes) -> None:
    if len(values) != 1:
        raise WeaveError("E_TS_CMS", "malformed ESS signingCertificateV2")
    signing_certificate_v2 = values[0]
    certs = signing_certificate_v2["certs"]
    if len(certs) == 0:
        raise WeaveError("E_TS_CMS", "empty ESS signingCertificateV2")
    first = certs[0]
    hash_algorithm = first["hash_algorithm"]["algorithm"].native
    try:
        digest = hashes.Hash(_hash_algorithm(hash_algorithm))
    except (ValueError, UnsupportedAlgorithm) as error:
        raise WeaveError("E_TS_CMS", "unsupported ESS certificate hash algorithm") from error
    digest.update(signer_certificate_der)
    if digest.finalize() != first["cert_hash"].native:
        raise WeaveError("E_TS_CMS", "ESS signingCertificateV2 does not match the signer certificate")


def _hash_algorithm(name: str):
    mapping = {
        "sha256": hashes.SHA256(),
        "sha384": hashes.SHA384(),
        "sha512": hashes.SHA512(),
    }
    try:
        return mapping[name]
    except KeyError as error:  # pragma: no cover - mapped to WeaveError by caller
        raise ValueError(name) from error


def _check_signer_certificate(certificate_der: bytes, gen_time_value: object) -> None:
    certificate = cryptography_x509.load_der_x509_certificate(certificate_der)
    if not isinstance(gen_time_value, _datetime.datetime):
        raise WeaveError("E_TS_SCHEMA", "genTime is not a timestamp")
    gen_time = gen_time_value
    if gen_time.tzinfo is None:
        gen_time = gen_time.replace(tzinfo=_datetime.timezone.utc)
    if certificate.not_valid_before_utc > gen_time or certificate.not_valid_after_utc < gen_time:
        raise WeaveError("E_TS_CERT", "signer certificate is not valid at genTime")
    try:
        extended_key_usage = certificate.extensions.get_extension_for_class(
            cryptography_x509.ExtendedKeyUsage
        ).value
    except cryptography_x509.ExtensionNotFound:
        raise WeaveError("E_TS_CERT", "signer certificate has no timeStamping EKU")
    if cryptography_x509.oid.ExtendedKeyUsageOID.TIME_STAMPING not in extended_key_usage:
        raise WeaveError("E_TS_CERT", "signer certificate is not a timestamping certificate")
    try:
        key_usage = certificate.extensions.get_extension_for_class(
            cryptography_x509.KeyUsage
        ).value
    except cryptography_x509.ExtensionNotFound:
        return
    if not key_usage.digital_signature:
        raise WeaveError("E_TS_CERT", "signer certificate key usage lacks digitalSignature")
