# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""L2 external anchors: the RFC 3161 verification profile (decision #34 / S5).

The profile is a fixed MUST list; each failing check maps to one registry code
and the first failing check of a token decides that token's state:

1. DER ``TimeStampResp`` with ``PKIStatusInfo.status == 0`` (granted) —
   ``E_TS_SCHEMA`` (grantedWithMods and every other status fail);
2. CMS ``SignedData`` encapsulating ``id-ct-TSTInfo``, TSTInfo version 1 —
   ``E_TS_SCHEMA``;
3. ``messageImprint.hashAlgorithm == sha256`` — ``E_TS_SCHEMA``;
4. ``messageImprint.hashedMessage`` equals the manifest digest for the chain
   head, or ``SHA-256(previous TSR bytes || manifest digest)`` for a renewal —
   ``E_TS_IMPRINT``;
5. ``signerInfo.digestAlgorithm == sha256`` — ``E_TS_SCHEMA``;
6. signature algorithm allowlist (RSA PKCS#1 v1.5 SHA-256/384/512, ECDSA
   SHA-256/384; RSA-PSS and everything else) — ``E_TS_CERT``;
7. the signer certificate MUST be carried inside the token — ``E_TS_CMS``;
8. ESS ``signingCertificateV2`` MUST be present and match the signer
   certificate (v1-only or missing fails) — ``E_TS_CMS``;
9. the signed-attributes ``messageDigest`` equals ``SHA-256(eContent)`` —
   ``E_TS_CMS``;
10. the CMS signature over ``DER(SET OF signedAttrs)`` verifies under the signer
    certificate — ``E_TS_CMS``;
11. EKU ``id-kp-timeStamping`` and (when present) KeyUsage
    ``digitalSignature`` — ``E_TS_CERT``;
12. the certificate validity window covers ``genTime`` — ``E_TS_CERT``;
13. trust anchor: a ``--tsa-trust`` certificate whose DER SHA-256 equals the
    signer leaf certificate; otherwise the timestamp is ``present-unverified``
    with ``E_TS_UNTRUSTED`` (the container may not be valid);
14. ``genTime`` normalised to integer milliseconds (fraction beyond ms floored);
15. renewal chain structure is a single chain rooted at ``renews = null``,
    ordered by path index — ``E_TS_RENEWAL``.

No network access, no wall clock, no trust-store discovery: anchors are supplied
by the caller (``--tsa-trust``).
"""

from __future__ import annotations

import calendar
import datetime as _datetime
import hashlib
from dataclasses import dataclass, field

from asn1crypto import tsp
from cryptography import x509 as cryptography_x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from .errors import WeaveError

MAX_TIMESTAMP_BYTES = 1_048_576

STATE_VERIFIED = "verified"
STATE_PRESENT_UNVERIFIED = "present-unverified"
STATE_INVALID = "invalid"

#: RDNSequence OIDs (dotted) of the accepted CMS signature algorithms.
_RSA_PKCS1V15_OIDS = {
    # `openssl ts` emits the generic rsaEncryption OID and carries the digest
    # algorithm in signerInfo.digestAlgorithm (which MUST be sha256, check 5).
    "1.2.840.113549.1.1.1": hashes.SHA256,
    "1.2.840.113549.1.1.11": hashes.SHA256,
    "1.2.840.113549.1.1.12": hashes.SHA384,
    "1.2.840.113549.1.1.13": hashes.SHA512,
}
_ECDSA_OIDS = {
    "1.2.840.10045.4.3.2": hashes.SHA256,
    "1.2.840.10045.4.3.3": hashes.SHA384,
}
_SHA256_OID = "2.16.840.1.101.3.4.2.1"


@dataclass(frozen=True)
class TimestampResult:
    """The verification outcome for one listed TSR.

    ``gen_time_us`` is genTime in integer microseconds; ``accuracy_us`` is the
    TSTInfo accuracy normalised to microseconds (absent fields count as 0).
    Compromise rescue uses ``gen_time_us + accuracy_us < effective_at_us``.
    """

    path: str
    digest: str
    state: str
    gen_time: str | None
    gen_time_ms: int | None
    error: str | None
    gen_time_us: int | None = None
    accuracy_us: int = 0

    def to_report(self, index: int) -> dict[str, object]:
        return {
            "gen_time": self.gen_time,
            "index": index,
            "path": self.path,
            "state": self.state,
        }


@dataclass
class TimestampArchive:
    """The outcome of verifying a container's timestamp archive (all listed TSRs)."""

    results: list[TimestampResult] = field(default_factory=list)
    chain_paths: tuple[str, ...] = ()
    errors: list[str] = field(default_factory=list)
    anchor_verified: bool = False

    @property
    def earliest_verified_gen_time_ms(self) -> int | None:
        values = [
            result.gen_time_ms
            for result in self.results
            if result.state == STATE_VERIFIED and result.gen_time_ms is not None
        ]
        return min(values) if values else None

    def verified_results(self) -> list[TimestampResult]:
        """Every individually verified receipt (used for compromise rescue evidence)."""
        return [result for result in self.results if result.state == STATE_VERIFIED]


def parse_trust_anchors(pem_bytes: bytes) -> frozenset[bytes]:
    """Parse a PEM bundle of trust-anchor certificates into DER SHA-256 fingerprints."""
    try:
        certificates = cryptography_x509.load_pem_x509_certificates(pem_bytes)
    except ValueError as error:
        raise WeaveError(
            "E_TS_UNTRUSTED", "TSA trust file is not a PEM certificate bundle"
        ) from error
    from cryptography.hazmat.primitives.serialization import Encoding

    return frozenset(
        hashlib.sha256(certificate.public_bytes(Encoding.DER)).digest()
        for certificate in certificates
    )


# ---------------------------------------------------------------------------
# Archive-level verification (renewal chain + per-token checks)
# ---------------------------------------------------------------------------


def verify_timestamp_archive(
    *,
    listed: list[dict],
    files: dict[str, bytes],
    manifest_digest: str,
    trust_anchor_fingerprints: frozenset[bytes] | None,
) -> TimestampArchive:
    """Verify every listed TSR of a container, including the renewal chain."""
    archive = TimestampArchive()
    manifest_raw_digest = _parse_digest_bytes(manifest_digest)
    entries: dict[str, dict] = {}
    for entry in listed:
        entries[entry["path"]] = entry
    if not entries:
        return archive
    chain, structure_error = _build_renewal_chain(entries)
    if structure_error is not None:
        archive.errors.append("E_TS_RENEWAL")
        archive.results = [
            TimestampResult(
                path=path,
                digest=str(entries[path].get("digest", "")),
                state=STATE_INVALID,
                gen_time=None,
                gen_time_ms=None,
                error="E_TS_RENEWAL",
            )
            for path in sorted(entries)
        ]
        return archive
    archive.chain_paths = tuple(chain)
    previous_bytes: bytes | None = None
    for path in chain:
        entry = entries[path]
        listed_digest = str(entry.get("digest", ""))
        data = files.get(path)
        if data is None or len(data) > MAX_TIMESTAMP_BYTES:
            archive.results.append(
                TimestampResult(path, listed_digest, STATE_INVALID, None, None, "E_TS_FILE")
            )
            archive.errors.append("E_TS_FILE")
            previous_bytes = None
            continue
        if "sha256:" + hashlib.sha256(data).hexdigest() != listed_digest:
            archive.results.append(
                TimestampResult(path, listed_digest, STATE_INVALID, None, None, "E_TS_FILE")
            )
            archive.errors.append("E_TS_FILE")
            previous_bytes = data
            continue
        expected_imprint = (
            manifest_raw_digest
            if previous_bytes is None
            else hashlib.sha256(previous_bytes + manifest_raw_digest).digest()
        )
        result = verify_timestamp_token(
            tsr_bytes=data,
            expected_imprint=expected_imprint,
            listed_digest=listed_digest,
            path=path,
            trust_anchor_fingerprints=trust_anchor_fingerprints,
        )
        archive.results.append(result)
        if result.state == STATE_INVALID and result.error is not None:
            archive.errors.append(result.error)
        previous_bytes = data
    _aggregate_archive(archive)
    return archive


def _build_renewal_chain(entries: dict[str, dict]) -> tuple[list[str], str | None]:
    """Derive the single renewal chain (oldest -> newest) or a structure error."""
    heads = [path for path, entry in entries.items() if entry.get("renews") is None]
    if len(heads) != 1:
        return [], "expected exactly one renews=null entry"
    successor: dict[str, str] = {}
    for path, entry in entries.items():
        renews = entry.get("renews")
        if renews is None:
            continue
        if renews not in entries:
            return [], "renews points to an unlisted timestamp"
        if renews in successor:
            return [], "a timestamp is renewed by more than one entry"
        successor[renews] = path
    chain = [heads[0]]
    seen = {heads[0]}
    while chain[-1] in successor:
        next_path = successor[chain[-1]]
        if next_path in seen:
            return [], "renewal chain contains a cycle"
        chain.append(next_path)
        seen.add(next_path)
    if len(chain) != len(entries):
        return [], "renewal chain does not cover every listed timestamp"
    order = [_timestamp_path_index(path) for path in chain]
    if order != sorted(order):
        return [], "renewal chain order does not follow the path index"
    return chain, None


def _timestamp_path_index(path: str) -> int:
    prefix = "signatures/timestamp-"
    if path.startswith(prefix) and path.endswith(".tsr"):
        value = path[len(prefix):-4]
        if value.isdigit():
            return int(value)
    return 1 << 30


def _aggregate_archive(archive: TimestampArchive) -> None:
    states = [result.state for result in archive.results]
    if STATE_INVALID in states:
        return  # invalid tokens already added their specific error
    if states and all(state == STATE_VERIFIED for state in states):
        archive.anchor_verified = True
        return
    # Anything not verified is present-unverified: trust anchor missing/mismatch.
    if any(state == STATE_PRESENT_UNVERIFIED for state in states):
        if "E_TS_UNTRUSTED" not in archive.errors:
            archive.errors.append("E_TS_UNTRUSTED")


# ---------------------------------------------------------------------------
# Per-token verification (checks 1-13)
# ---------------------------------------------------------------------------


def verify_timestamp_token(
    *,
    tsr_bytes: bytes,
    expected_imprint: bytes,
    listed_digest: str,
    path: str,
    trust_anchor_fingerprints: frozenset[bytes] | None,
) -> TimestampResult:
    """Verify one TSR token; the first failing check decides the error code."""
    state = STATE_INVALID
    gen_time: str | None = None
    gen_time_ms: int | None = None
    gen_time_us: int | None = None
    accuracy_us = 0
    try:
        parsed = _parse_tst_info(tsr_bytes)
    except WeaveError as error:
        return TimestampResult(
            path, listed_digest, state, gen_time, gen_time_ms, error.code, gen_time_us, accuracy_us
        )
    signed_data, tst_info, raw_content = parsed
    try:
        # Checks 3-4: hash algorithm and message imprint.
        imprint = tst_info["message_imprint"]
        if _oid(imprint["hash_algorithm"]["algorithm"]) != _SHA256_OID:
            raise WeaveError("E_TS_SCHEMA", "messageImprint hash algorithm is not sha256")
        if imprint["hashed_message"].native != expected_imprint:
            raise WeaveError("E_TS_IMPRINT", "messageImprint does not match the manifest/anchor")
        gen_time_value = tst_info["gen_time"].native
        gen_time_ms = _gen_time_to_ms(gen_time_value)
        gen_time = _format_ms(gen_time_ms)
        gen_time_us = _gen_time_to_us(gen_time_value)
        accuracy_us = _accuracy_to_us(tst_info)

        signer_info, signer_certificate_der = _verify_cms(signed_data, raw_content, gen_time_value)
        fingerprint = hashlib.sha256(signer_certificate_der).digest()
        _check_signer_certificate(signer_certificate_der, gen_time_value)
        if trust_anchor_fingerprints is None or not trust_anchor_fingerprints:
            return TimestampResult(
                path, listed_digest, STATE_PRESENT_UNVERIFIED, gen_time, gen_time_ms,
                "E_TS_UNTRUSTED", gen_time_us, accuracy_us,
            )
        if fingerprint not in trust_anchor_fingerprints:
            return TimestampResult(
                path, listed_digest, STATE_PRESENT_UNVERIFIED, gen_time, gen_time_ms,
                "E_TS_UNTRUSTED", gen_time_us, accuracy_us,
            )
    except WeaveError as error:
        return TimestampResult(
            path, listed_digest, state, gen_time, gen_time_ms, error.code, gen_time_us, accuracy_us
        )
    return TimestampResult(
        path, listed_digest, STATE_VERIFIED, gen_time, gen_time_ms, None,
        gen_time_us, accuracy_us,
    )


def _parse_tst_info(tsr_bytes: bytes):
    """Checks 1-2: DER TimeStampResp, granted status, TSTInfo version 1."""
    try:
        response = tsp.TimeStampResp.load(tsr_bytes)
    except Exception as error:
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
        version = tst_info["version"].native
    except Exception as error:
        raise WeaveError("E_TS_SCHEMA", "TSTInfo has no readable version") from error
    if version != "v1":
        raise WeaveError("E_TS_SCHEMA", "unsupported TSTInfo version")
    return signed_data, tst_info, raw_content


def _verify_cms(signed_data, raw_content: bytes, gen_time_value):
    """Checks 5-10: CMS signature, ESS v2, messageDigest."""
    signer_infos = signed_data["signer_infos"]
    if len(signer_infos) < 1:
        raise WeaveError("E_TS_CMS", "timestamp token has no signerInfo")
    signer_info = signer_infos[0]
    # Check 5: signer digest algorithm.
    if _oid(signer_info["digest_algorithm"]["algorithm"]) != _SHA256_OID:
        raise WeaveError("E_TS_SCHEMA", "signerInfo digest algorithm is not sha256")
    # Check 6: signature algorithm allowlist (RSA-PSS and others are rejected).
    signature_algorithm_oid = _oid(signer_info["signature_algorithm"]["algorithm"])
    if signature_algorithm_oid not in _RSA_PKCS1V15_OIDS and signature_algorithm_oid not in _ECDSA_OIDS:
        raise WeaveError("E_TS_CERT", "unsupported timestamp signature algorithm")
    signed_attrs = signer_info["signed_attrs"]
    if signed_attrs.native is None or len(signed_attrs) == 0:
        raise WeaveError("E_TS_CMS", "timestamp token has no signed attributes")
    try:
        signed_attrs_der = signed_attrs.untag().dump()
    except Exception as error:
        raise WeaveError("E_TS_CMS", "signed attributes cannot be encoded") from error
    # Check 7: the signer certificate must be carried inside the token.
    signer_certificate_der = _find_signer_certificate(signed_data, signer_info)
    certificate = cryptography_x509.load_der_x509_certificate(signer_certificate_der)

    message_digest = hashlib.sha256(raw_content).digest()
    content_type_ok = False
    message_digest_ok = False
    signing_certificate_v2 = False
    signing_certificate_v1 = False
    for attribute in signed_attrs:
        attribute_type = attribute["type"].native
        values = attribute["values"]
        if attribute_type == "content_type":
            if len(values) != 1 or values[0].native != "tst_info":
                raise WeaveError("E_TS_CMS", "content_type attribute is not TSTInfo")
            content_type_ok = True
        elif attribute_type == "message_digest":
            if len(values) != 1 or values[0].native != message_digest:
                raise WeaveError("E_TS_CMS", "signed messageDigest does not match the eContent")
            message_digest_ok = True
        elif attribute_type == "signing_certificate_v2":
            signing_certificate_v2 = True
            _check_ess_signing_certificate_v2(values, signer_certificate_der)
        elif attribute_type == "signing_certificate":
            signing_certificate_v1 = True
    if not content_type_ok or not message_digest_ok:
        raise WeaveError("E_TS_CMS", "required signed attributes are missing")
    # Check 8: ESS signingCertificateV2 is required (v1-only is not accepted).
    if not signing_certificate_v2:
        if signing_certificate_v1:
            raise WeaveError("E_TS_CMS", "only ESS signingCertificate v1 is present")
        raise WeaveError("E_TS_CMS", "ESS signingCertificateV2 attribute is missing")

    # Check 10: the CMS signature over DER(SET OF signedAttrs).
    signature = signer_info["signature"].native
    public_key = certificate.public_key()
    try:
        if signature_algorithm_oid in _RSA_PKCS1V15_OIDS:
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise WeaveError("E_TS_CERT", "signature algorithm does not match the key")
            digest_class = _RSA_PKCS1V15_OIDS[signature_algorithm_oid]
            public_key.verify(signature, signed_attrs_der, padding.PKCS1v15(), digest_class())
        else:
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise WeaveError("E_TS_CERT", "signature algorithm does not match the key")
            digest_class = _ECDSA_OIDS[signature_algorithm_oid]
            public_key.verify(signature, signed_attrs_der, ec.ECDSA(digest_class()))
    except WeaveError:
        raise
    except (InvalidSignature, UnsupportedAlgorithm) as error:
        raise WeaveError("E_TS_CMS", "CMS signature does not verify") from error
    except Exception as error:  # pragma: no cover - defensive provider errors
        raise WeaveError("E_TS_CMS", "CMS signature does not verify") from error
    return signer_info, signer_certificate_der


def _find_signer_certificate(signed_data, signer_info) -> bytes:
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


def _check_ess_signing_certificate_v2(values, signer_certificate_der: bytes) -> None:
    if len(values) != 1:
        raise WeaveError("E_TS_CMS", "malformed ESS signingCertificateV2")
    certs = values[0]["certs"]
    if len(certs) == 0:
        raise WeaveError("E_TS_CMS", "empty ESS signingCertificateV2")
    first = certs[0]
    hash_algorithm_oid = _oid(first["hash_algorithm"]["algorithm"])
    try:
        digest_algorithm = _HASH_OIDS[hash_algorithm_oid]
    except KeyError as error:
        raise WeaveError("E_TS_CMS", "unsupported ESS certificate hash algorithm") from error
    digest = hashes.Hash(digest_algorithm())
    digest.update(signer_certificate_der)
    if digest.finalize() != first["cert_hash"].native:
        raise WeaveError("E_TS_CMS", "ESS signingCertificateV2 does not match the signer certificate")


_HASH_OIDS = {
    "2.16.840.1.101.3.4.2.1": hashes.SHA256,
    "2.16.840.1.101.3.4.2.2": hashes.SHA384,
    "2.16.840.1.101.3.4.2.3": hashes.SHA512,
}


def _check_signer_certificate(certificate_der: bytes, gen_time_value: object) -> None:
    """Checks 11-12: timestamping EKU / key usage / validity at genTime."""
    certificate = cryptography_x509.load_der_x509_certificate(certificate_der)
    gen_time = _to_aware_datetime(gen_time_value)
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
        key_usage = None
    if key_usage is not None and not key_usage.digital_signature:
        raise WeaveError("E_TS_CERT", "signer certificate key usage lacks digitalSignature")
    if certificate.not_valid_before_utc > gen_time or certificate.not_valid_after_utc < gen_time:
        raise WeaveError("E_TS_CERT", "signer certificate is not valid at genTime")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _oid(value) -> str:
    return value.dotted if hasattr(value, "dotted") else str(value)


def _parse_digest_bytes(manifest_digest: str) -> bytes:
    hex_value = manifest_digest
    if hex_value.startswith("sha256:"):
        hex_value = hex_value[len("sha256:"):]
    if len(hex_value) != 64 or any(character not in "0123456789abcdef" for character in hex_value):
        raise WeaveError("E_TS_IMPRINT", "manifest digest is not a sha256 digest string")
    return bytes.fromhex(hex_value)


def _to_aware_datetime(value: object) -> _datetime.datetime:
    if not isinstance(value, _datetime.datetime):
        raise WeaveError("E_TS_SCHEMA", "genTime is not a timestamp")
    if value.tzinfo is None:
        return value.replace(tzinfo=_datetime.timezone.utc)
    return value


def _gen_time_to_ms(value: object) -> int:
    """Normalise genTime to integer milliseconds (fraction beyond ms is floored)."""
    utc = _to_aware_datetime(value).astimezone(_datetime.timezone.utc)
    return calendar.timegm(utc.utctimetuple()) * 1000 + utc.microsecond // 1000


def _gen_time_to_us(value: object) -> int:
    """Normalise genTime to integer microseconds (sub-microsecond truncation)."""
    utc = _to_aware_datetime(value).astimezone(_datetime.timezone.utc)
    return calendar.timegm(utc.utctimetuple()) * 1_000_000 + utc.microsecond


def _accuracy_to_us(tst_info) -> int:
    """Normalise TSTInfo accuracy (seconds/millis/micros) to microseconds.

    RFC 3161 ``Accuracy`` carries at most one of seconds, millis and micros; an
    absent field counts as 0 (an absent accuracy is treated as exact).
    """
    try:
        accuracy = tst_info["accuracy"]
    except Exception:  # pragma: no cover - defensive
        return 0
    if accuracy is None or accuracy.native is None:
        return 0
    native = accuracy.native
    seconds = native.get("seconds") or 0
    millis = native.get("millis") or 0
    micros = native.get("micros") or 0
    return int(seconds) * 1_000_000 + int(millis) * 1000 + int(micros)


def _format_ms(epoch_ms: int) -> str:
    """Format integer milliseconds as a TS literal (``YYYY-MM-DDTHH:MM:SS.mmmZ``)."""
    seconds, milliseconds = divmod(epoch_ms, 1000)
    value = _datetime.datetime.fromtimestamp(seconds, tz=_datetime.timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % milliseconds
