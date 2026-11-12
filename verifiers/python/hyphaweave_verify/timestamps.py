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
import re
import warnings
from dataclasses import dataclass, field
from pathlib import Path

from asn1crypto import tsp
from cryptography import x509 as cryptography_x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from . import der_schema, operator_input
from .errors import UsageError, WeaveError

MAX_TIMESTAMP_BYTES = 1_048_576

#: Internal strict-DER violation marker (check 1a scan and the 1b/1c walk).
_DerViolation = der_schema.DerViolation

#: U1 exception audit: asn1crypto DER parsing/access on untrusted bytes raises
#: these built-in exception types only (no bare ``Exception`` catch remains).
_DER_ACCESS_ERRORS = (
    ValueError,
    TypeError,
    KeyError,
    IndexError,
    OverflowError,
    UnicodeError,
)

#: V2/X2: the per-receipt boundary also catches the parsing-class exceptions the
#: DER/X.509 libraries raise for structures that parse far enough to be handed to
#: them (cryptography's InvalidVersion for a malformed certificate version), plus
#: AttributeError from asn1crypto's lazy objects for an unexpected tag type. The
#: specification says any DER decoding or receipt-structure failure, wherever
#: discovered, is check 1's E_TS_SCHEMA.
_RECEIPT_PARSE_ERRORS = _DER_ACCESS_ERRORS + (
    cryptography_x509.InvalidVersion,
    AttributeError,
)

#: S11/§13: total accuracy of one receipt, in seconds. A receipt whose
#: normalised accuracy exceeds this (or whose conversion overflows a signed
#: 64-bit microsecond value) is invalid with ``E_TS_SCHEMA`` and can never
#: rescue a compromised-key signature.
MAX_TS_ACCURACY_SECONDS = 86_400
MAX_TS_ACCURACY_US = MAX_TS_ACCURACY_SECONDS * 1_000_000

#: Signed 64-bit bound used by the rescue arithmetic (§9.4/S11).
INT64_MAX = (1 << 63) - 1

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
    #: T3: the receipt's accuracy is above MAX_TS_ACCURACY (or its conversion
    #: overflows). It is *unusable evidence*, not a format error: the receipt is
    #: present-unverified with E_TS_UNTRUSTED and can neither rescue a
    #: compromised-key signature nor support an L2 claim.
    unusable: bool = False

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


#: W4/§14.1: the exception types the trust-anchor PEM loader can raise for a
#: malformed operator file. ``load_pem_x509_certificates`` raises ``ValueError``
#: for a missing/garbled PEM block or undecodable DER and
#: ``cryptography.x509.InvalidVersion`` (not a ``ValueError``) for a certificate
#: whose version field is out of range (recheck3 H4, crash_fuzz seed 777);
#: ``UnsupportedAlgorithm`` and ``TypeError``/``OverflowError``/``UnicodeError``
#: are the remaining parsing-class types of the cryptography API surface used
#: here. Every one of them is a usage error (exit 2), never a crash.
TRUST_ANCHOR_PARSE_ERRORS = (
    ValueError,
    TypeError,
    OverflowError,
    UnicodeError,
    cryptography_x509.InvalidVersion,
    UnsupportedAlgorithm,
)


def parse_trust_anchors(pem_bytes: bytes) -> frozenset[bytes]:
    """Parse a PEM bundle of trust-anchor certificates into DER SHA-256 fingerprints.

    W4/§14.1: ``--tsa-trust`` is operator input exactly like ``--keys``. A file
    that is not a bundle of one or more well-formed PEM certificates is a usage
    error (:class:`UsageError`, exit 2, no report); it is never silently treated
    as an empty anchor set.
    """
    from cryptography.hazmat.primitives.serialization import Encoding

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            certificates = cryptography_x509.load_pem_x509_certificates(pem_bytes)
        fingerprints = frozenset(
            hashlib.sha256(certificate.public_bytes(Encoding.DER)).digest()
            for certificate in certificates
        )
    except TRUST_ANCHOR_PARSE_ERRORS as error:
        raise UsageError(
            "TSA trust file is not a bundle of well-formed PEM certificates (%s)"
            % type(error).__name__
        ) from error
    if not fingerprints:
        raise UsageError("TSA trust file contains no certificate")
    return fingerprints


def load_trust_anchor_file(path: Path) -> bytes:
    """Read and validate a ``--tsa-trust`` file; usage error names the file (W4).

    X3/§14.1: the path must be a regular file (``lstat`` before opening, so a
    FIFO never blocks the verifier) and is read with the bound
    ``MAX_TIMESTAMP_BYTES``; anything else is a usage error.
    """
    data = operator_input.read_bounded_file(path, "--tsa-trust", MAX_TIMESTAMP_BYTES)
    try:
        parse_trust_anchors(data)
    except UsageError as error:
        raise UsageError("--tsa-trust %s: %s" % (path, error)) from error
    return data


# ---------------------------------------------------------------------------
# Archive-level verification (renewal chain + per-token checks)
# ---------------------------------------------------------------------------


def verify_timestamp_archive(
    *,
    listed: list[dict],
    files: dict[str, bytes],
    manifest_digest: str,
    trust_anchor_fingerprints: frozenset[bytes] | None,
    oversized: frozenset[str] = frozenset(),
) -> TimestampArchive:
    """Verify every listed TSR of a container.

    Order (S8.11): the listed ``.tsr`` files are materialised and their listed
    digests checked first (``E_TS_FILE``; an oversized file is ``E_JSON_SIZE``),
    then the renewal-chain structure (``E_TS_RENEWAL``), then every token's
    checks 1-13.

    ``oversized`` names listed ``.tsr`` files whose byte size exceeded the
    ``MAX_TIMESTAMP_BYTES`` class limit while reading (S4): they are invalid
    with ``E_JSON_SIZE`` and cannot be parsed.
    """
    archive = TimestampArchive()
    manifest_raw_digest = _parse_digest_bytes(manifest_digest)
    entries: dict[str, dict] = {}
    for entry in listed:
        entries[entry["path"]] = entry
    if not entries:
        return archive
    # Phase 1: every listed TSR must exist, be within the class limit and hash
    # to the digest the attestation lists (§11.3 file-level checks).
    file_errors: list[str] = []
    file_data: dict[str, bytes] = {}
    for path in sorted(entries):
        listed_digest = str(entries[path].get("digest", ""))
        if path in oversized:
            archive.results.append(
                TimestampResult(path, listed_digest, STATE_INVALID, None, None, "E_JSON_SIZE")
            )
            if "E_JSON_SIZE" not in file_errors:
                file_errors.append("E_JSON_SIZE")
            continue
        data = files.get(path)
        if data is None:
            archive.results.append(
                TimestampResult(path, listed_digest, STATE_INVALID, None, None, "E_TS_FILE")
            )
            if "E_TS_FILE" not in file_errors:
                file_errors.append("E_TS_FILE")
            continue
        if "sha256:" + hashlib.sha256(data).hexdigest() != listed_digest:
            archive.results.append(
                TimestampResult(path, listed_digest, STATE_INVALID, None, None, "E_TS_FILE")
            )
            if "E_TS_FILE" not in file_errors:
                file_errors.append("E_TS_FILE")
            continue
        file_data[path] = data
    if file_errors:
        # A broken file chain stops the archive check before the renewal
        # structure is judged; every listed receipt is invalid.
        archive.errors.extend(file_errors)
        invalid_code = "E_JSON_SIZE" if "E_JSON_SIZE" in file_errors else "E_TS_FILE"
        archive.results = [
            TimestampResult(
                path=path,
                digest=str(entries[path].get("digest", "")),
                state=STATE_INVALID,
                gen_time=None,
                gen_time_ms=None,
                error=invalid_code,
            )
            for path in sorted(entries)
        ]
        return archive
    # Phase 2: renewal-chain structure (§12.2 row 14).
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
        data = file_data[path]
        entry = entries[path]
        listed_digest = str(entry.get("digest", ""))
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
    """Verify one TSR token; the first failing check decides the error code.

    V2/X2: one receipt's whole processing is wrapped in a boundary that catches
    only parsing-class exceptions (asn1crypto lazy DER decode/access errors:
    ``ValueError``/``TypeError``/``KeyError``/``IndexError``/``UnicodeError``
    and friends). The specification says any DER decoding or receipt-structure
    failure, wherever discovered, is check 1's ``E_TS_SCHEMA``; a malformed
    receipt must never escape as a crash.
    """
    try:
        return _verify_timestamp_token_checks(
            tsr_bytes=tsr_bytes,
            expected_imprint=expected_imprint,
            listed_digest=listed_digest,
            path=path,
            trust_anchor_fingerprints=trust_anchor_fingerprints,
        )
    except _RECEIPT_PARSE_ERRORS:
        return TimestampResult(
            path, listed_digest, STATE_INVALID, None, None, "E_TS_SCHEMA"
        )


def _verify_timestamp_token_checks(
    *,
    tsr_bytes: bytes,
    expected_imprint: bytes,
    listed_digest: str,
    path: str,
    trust_anchor_fingerprints: frozenset[bytes] | None,
) -> TimestampResult:

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
    signed_data, tst_info, raw_content, located_signer_certificate = parsed
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
        # Keep the token's microsecond genTime for reporting; the T3(4)
        # rescue comparison truncates to milliseconds (VerifiedTimestamp).
        gen_time_us = _gen_time_to_us(gen_time_value)
        # T3(3)/§12.2 first failing check: CMS and certificate checks (5-12) run
        # before the accuracy checks (13).
        signer_info, signer_certificate_der = _verify_cms(
            signed_data, raw_content, gen_time_value, located_signer_certificate
        )
        fingerprint = hashlib.sha256(signer_certificate_der).digest()
        _check_signer_certificate(signer_certificate_der, gen_time_value)
        accuracy_value = _accuracy_to_us(tst_info)
        if accuracy_value is None:
            # T3(2): unusable evidence, not a format error. Present-unverified with
            # E_TS_UNTRUSTED; never rescues, never supports L2, never invalid.
            return TimestampResult(
                path, listed_digest, STATE_PRESENT_UNVERIFIED, gen_time, gen_time_ms,
                "E_TS_UNTRUSTED", gen_time_us, 0, unusable=True,
            )
        accuracy_us = accuracy_value
        if gen_time_us + accuracy_us > INT64_MAX:
            return TimestampResult(
                path, listed_digest, STATE_PRESENT_UNVERIFIED, gen_time, gen_time_ms,
                "E_TS_UNTRUSTED", gen_time_us, accuracy_us, unusable=True,
            )
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
    """Checks 1-2 of §12.2, in the fixed W6 order.

    Check 1 (``E_TS_SCHEMA``) decodes **everything** before any later check
    runs, so a DER/structure failure anywhere in the receipt is never reported
    as a later check's code (W6, recheck3 M2):

    1a. the linear strict-DER scan of the whole file (exactly one TLV, no
        trailing data, definite minimal lengths, minimal high tag numbers,
        canonical universal primitives, sorted universal SET OF);
    1b/1c. the walk of :mod:`.der_schema`: the whole file decodes against the
        hand-written RFC 3161 / 5652 / 5280 / 5035 module definitions, and its
        DER re-encoding (SET OF sorted, no DEFAULT encoded, typed primitives
        rebuilt by X.690, open types re-emitted as decoded) equals the input;
        no parsing library takes part in this judgement (S1-FIX5 X1);
    1d. ``PKIStatusInfo.status`` is granted; the token is CMS ``SignedData``;
        ``SignedData.version`` is 3; every ``SignerInfo.version`` is 1 or 3;
    1e. every certificate carried in ``SignedData.certificates`` decodes as an
        X.509 certificate, and every extension value in it is one TLV obeying the
        universal DER rules of 1a.

    Check 2: the encapsulated content type is ``id-ct-TSTInfo`` and the
    TSTInfo bytes pass 1a-1c on their own with ``version == 1``.
    """
    # Check 1a.
    _validate_strict_der(tsr_bytes)
    # Checks 1b and 1c: schema decode and DER re-encoding (X1).
    walk = _require_der_reencoding(der_schema.TIME_STAMP_RESP, tsr_bytes, "TimeStampResp")
    # The values read by the later checks come from asn1crypto; it is only a
    # reader here (the DER judgement above did not consult it).
    try:
        response = tsp.TimeStampResp.load(tsr_bytes, strict=True)
    except _DER_ACCESS_ERRORS as error:
        raise WeaveError("E_TS_SCHEMA", "not a DER TimeStampResp") from error
    # Check 1d.
    try:
        status = response["status"]["status"].native
    except _DER_ACCESS_ERRORS as error:
        raise WeaveError("E_TS_SCHEMA", "TimeStampResp has no readable status") from error
    if status != "granted":
        raise WeaveError("E_TS_SCHEMA", "TimeStampResp status is not granted")
    token = response["time_stamp_token"]
    if token["content_type"].native != "signed_data":
        raise WeaveError("E_TS_SCHEMA", "timestamp token is not CMS signed data")
    signed_data = token["content"]
    try:
        signed_data_version = signed_data["version"].native
    except _DER_ACCESS_ERRORS as error:
        raise WeaveError("E_TS_SCHEMA", "SignedData has no readable version") from error
    if signed_data_version != "v3":
        raise WeaveError("E_TS_SCHEMA", "SignedData version is not 3")
    # X7/M2 (RFC 3161 §2.4.2: no signature other than the TSA's): exactly one
    # SignerInfo. Counted on the 1b/1c walk, not by a parsing library.
    if len(walk.signer_identifiers) != 1:
        raise WeaveError("E_TS_SCHEMA", "SignedData does not carry exactly one signerInfo")
    for signer_info in signed_data["signer_infos"]:
        try:
            signer_info_version = signer_info["version"].native
        except _DER_ACCESS_ERRORS as error:
            raise WeaveError("E_TS_SCHEMA", "signerInfo has no readable version") from error
        if signer_info_version not in ("v1", "v3"):
            raise WeaveError("E_TS_SCHEMA", "signerInfo version is not 1 or 3")
    # Check 1e (X7/M3): only the signer certificate is decoded. The other
    # components of SignedData.certificates are open types (framing only, 1a).
    # The signer certificate is located by its sid on the raw TLVs, walked with
    # the RFC 5280 module definition (1b/1c rules), decoded as an X.509
    # certificate, and its extension values obey the universal rules of 1a.
    signer_certificate_der = der_schema.signer_certificate(walk)
    if signer_certificate_der is not None:
        certificate_walk = _require_der_reencoding(
            der_schema.CERTIFICATE, signer_certificate_der, "signer certificate"
        )
        _load_der_certificate(signer_certificate_der)
        for extension_value in certificate_walk.certificate_extension_values:
            _validate_strict_der(extension_value)
    # Check 2.
    encap = signed_data["encap_content_info"]
    if encap["content_type"].native != "tst_info":
        raise WeaveError("E_TS_SCHEMA", "timestamp token does not encapsulate TSTInfo")
    content = encap["content"]
    try:
        raw_content = content.contents
        _validate_strict_der(raw_content)
    except WeaveError:
        raise
    except _DER_ACCESS_ERRORS as error:
        raise WeaveError("E_TS_SCHEMA", "malformed TSTInfo") from error
    _require_der_reencoding(der_schema.TST_INFO, raw_content, "TSTInfo")
    try:
        tst_info = tsp.TSTInfo.load(raw_content, strict=True)
    except _DER_ACCESS_ERRORS as error:
        raise WeaveError("E_TS_SCHEMA", "malformed TSTInfo") from error
    try:
        version = tst_info["version"].native
    except _DER_ACCESS_ERRORS as error:
        raise WeaveError("E_TS_SCHEMA", "TSTInfo has no readable version") from error
    if version != "v1":
        raise WeaveError("E_TS_SCHEMA", "unsupported TSTInfo version")
    return signed_data, tst_info, raw_content, signer_certificate_der


def _load_der_certificate(der: bytes):
    """Decode one X.509 certificate without writing library warnings to stderr.

    §14.1: standard error carries usage and I/O errors only; cryptography emits
    a deprecation warning for some decodable-but-unusual certificates (for
    example a non-positive serial number), which must not reach the stream.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return cryptography_x509.load_der_x509_certificate(der)


def _require_der_reencoding(schema, data: bytes, label: str) -> der_schema.WalkContext:
    """§12.2 checks 1b/1c: decode against the module definitions, re-encode, compare.

    The walk (:mod:`.der_schema`) uses only X.690 and the RFC 3161 / 5652 / 5280
    / 5035 module definitions -- no parsing library: SET OF components are
    re-emitted in DER order, a component equal to its DEFAULT (the encodings in
    ``der_schema.DEFAULTS``) is a violation, typed primitives are rebuilt from
    their content octets by the X.690 rules for their type, time values are
    compared as their raw DER form, and open-type values are re-emitted as
    decoded. Any difference from the input is check 1's ``E_TS_SCHEMA``.
    """
    try:
        encoded, context = der_schema.reencode(schema, data)
    except der_schema.DerViolation as error:
        raise WeaveError(
            "E_TS_SCHEMA", "%s is not DER: %s" % (label, error)
        ) from error
    if encoded != data:
        raise WeaveError(
            "E_TS_SCHEMA", "%s is not in DER canonical form (re-encoding differs)" % label
        )
    return context


# ---------------------------------------------------------------------------
# Strict DER enforcement (V2/M3, §12.2 check 1)
# ---------------------------------------------------------------------------

#: Universal tag numbers whose DER encoding is always primitive (SEQUENCE/SET and
#: the rarely-used EXTERNAL/EMBEDDED PDV/CHARACTER STRING are constructed).
_DER_PRIMITIVE_UNIVERSAL = frozenset(
    {1, 2, 3, 4, 5, 6, 9, 10, 12, 13, 14, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 30}
)
_DER_GENERALIZED_TIME = re.compile(r"^(?:[0-9]{14}|[0-9]{14}\.[0-9]*[1-9])Z$")
_DER_UTC_TIME = re.compile(r"^[0-9]{12}Z$")


def _validate_strict_der(data: bytes) -> None:
    """Check 1a: the schema-independent DER rules, as a linear scan (V2, W3).

    This is the *first* half of check 1 only: it rejects trailing data,
    indefinite and non-minimal lengths, non-minimal high tag numbers,
    constructed encodings of primitive universal types, non-canonical BOOLEAN /
    INTEGER / BIT STRING / NULL / OID / time encodings, and a universal SET
    whose components are not in ascending DER order (every universal SET in the
    TimeStampResp, CMS and X.509 schemas is a SET OF, X.690 §11.6). It is cheap,
    so most malformed receipts stop here. It is **not** a substitute for the
    re-encoding of check 1c (:func:`_require_der_reencoding`), which knows the
    schema (implicitly tagged SET OF such as ``certificates``/``signedAttrs``,
    DEFAULT values) and is always run afterwards.
    """
    try:
        _scan_der(data, 0, len(data), 0)
    except _DerViolation as error:
        raise WeaveError("E_TS_SCHEMA", "receipt is not strict DER: %s" % error) from error
    if not data:
        raise WeaveError("E_TS_SCHEMA", "receipt is empty")
    first_end = _scan_tlv_end(data, 0, len(data))
    if first_end != len(data):
        raise WeaveError("E_TS_SCHEMA", "receipt carries data after its TimeStampResp")


def _scan_tlv_end(data: bytes, position: int, end: int) -> int:
    """End offset of the (already validated) TLV at ``position``."""
    try:
        return _scan_tlv(data, position, end, 0)
    except _DerViolation as error:  # pragma: no cover - validated just before
        raise WeaveError("E_TS_SCHEMA", "receipt is not strict DER: %s" % error) from error



def _scan_der(data: bytes, start: int, end: int, depth: int) -> None:
    if depth > 64:
        raise _DerViolation("nesting is too deep")
    position = start
    while position < end:
        position = _scan_tlv(data, position, end, depth)


def _scan_tlv(data: bytes, position: int, end: int, depth: int) -> int:
    first = data[position]
    position += 1
    tag_class = first >> 6
    constructed = bool(first & 0x20)
    tag_number = first & 0x1F
    if tag_number == 0x1F:
        # X.690 §8.1.2.4: base 128, bit 8 set on every subsequent octet but the
        # last, and bits 7-1 of the *first* subsequent octet not all zero. Only
        # the first subsequent octet can make the form non-minimal; a zero group
        # later on (5f 81 80 00 = 16384) is part of a minimal encoding.
        tag_number = 0
        count = 0
        while True:
            if position >= end:
                raise _DerViolation("truncated high-tag-number form")
            byte = data[position]
            position += 1
            count += 1
            if count == 1 and byte == 0x80:
                raise _DerViolation("non-minimal high-tag-number form")
            if count <= 5:
                # Bounded accumulation: only "below 31" and the universal type
                # numbers matter here, and two or more octets are always >= 128.
                tag_number = (tag_number << 7) | (byte & 0x7F)
            if not byte & 0x80:
                break
        if tag_number < 0x1F:
            # X.690 §8.1.2.2/8.1.2.4: tag numbers 0-30 use the single-octet form.
            raise _DerViolation("high-tag-number form for a low tag")
    if position >= end:
        raise _DerViolation("missing length")
    first_length = data[position]
    position += 1
    if first_length & 0x80:
        length_octets = first_length & 0x7F
        if length_octets == 0:
            raise _DerViolation("indefinite length is not DER")
        if length_octets > 4:
            raise _DerViolation("length uses too many octets")
        if position + length_octets > end:
            raise _DerViolation("truncated length")
        if data[position] == 0:
            raise _DerViolation("length has a leading zero")
        length = int.from_bytes(data[position : position + length_octets], "big")
        if length < 0x80:
            raise _DerViolation("non-minimal long-form length")
        position += length_octets
    else:
        length = first_length
    content_end = position + length
    if content_end > end:
        raise _DerViolation("content runs past its container")
    if tag_class == 0:
        if tag_number in (16, 17):
            if not constructed:
                raise _DerViolation("SEQUENCE/SET must be constructed")
        elif constructed and tag_number in _DER_PRIMITIVE_UNIVERSAL:
            raise _DerViolation("primitive universal type is constructed")
        if tag_number == 1:
            if length != 1 or data[position] not in (0x00, 0xFF):
                raise _DerViolation("BOOLEAN is not canonical DER")
        elif tag_number == 2:
            _check_der_integer(data, position, content_end)
        elif tag_number == 3:
            if length < 1:
                raise _DerViolation("BIT STRING has no unused-bits octet")
            unused = data[position]
            if unused > 7:
                raise _DerViolation("BIT STRING unused-bit count is invalid")
            if length == 1 and unused != 0:
                raise _DerViolation("empty BIT STRING has unused bits")
            if unused and (data[content_end - 1] & ((1 << unused) - 1)):
                raise _DerViolation("BIT STRING has non-zero unused bits")
        elif tag_number == 5 and length != 0:
            raise _DerViolation("NULL is not empty")
        elif tag_number == 6:
            _check_der_oid(data, position, content_end)
        elif tag_number in (23, 24):
            text = data[position:content_end].decode("ascii", "replace")
            pattern = _DER_UTC_TIME if tag_number == 23 else _DER_GENERALIZED_TIME
            if not pattern.fullmatch(text):
                raise _DerViolation("time value is not canonical DER")
        elif tag_number == 12:
            try:
                data[position:content_end].decode("utf-8")
            except UnicodeDecodeError as error:
                raise _DerViolation("UTF8String is not valid UTF-8") from error
    if constructed:
        if tag_class == 0 and tag_number == 17:
            _scan_set_of(data, position, content_end, depth + 1)
        else:
            _scan_der(data, position, content_end, depth + 1)
    return content_end


def _scan_set_of(data: bytes, start: int, end: int, depth: int) -> None:
    """A universal SET: components valid and in ascending DER order (X.690 §11.6)."""
    if depth > 64:
        raise _DerViolation("nesting is too deep")
    previous: bytes | None = None
    position = start
    while position < end:
        component_end = _scan_tlv(data, position, end, depth)
        component = data[position:component_end]
        if previous is not None and component < previous:
            raise _DerViolation("SET OF components are not in DER order")
        previous = component
        position = component_end


def _check_der_integer(data: bytes, start: int, end: int) -> None:
    if end <= start:
        raise _DerViolation("INTEGER is empty")
    if end - start > 1:
        if data[start] == 0x00 and data[start + 1] < 0x80:
            raise _DerViolation("INTEGER has a redundant leading zero")
        if data[start] == 0xFF and data[start + 1] >= 0x80:
            raise _DerViolation("INTEGER has a redundant leading 0xFF")


def _check_der_oid(data: bytes, start: int, end: int) -> None:
    if end <= start:
        raise _DerViolation("OBJECT IDENTIFIER is empty")
    component_start = True
    position = start
    while position < end:
        byte = data[position]
        if component_start and byte == 0x80:
            raise _DerViolation("OBJECT IDENTIFIER is not minimally encoded")
        component_start = not byte & 0x80
        if not component_start and position == end - 1:
            raise _DerViolation("OBJECT IDENTIFIER is truncated")
        position += 1


def _verify_cms(
    signed_data, raw_content: bytes, gen_time_value, signer_certificate_der: bytes | None
):
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
    # Check 1 already proved the whole receipt is DER, so the stored signed
    # attributes are their own DER encoding; the CMS signature input is that
    # SET OF with the universal SET tag (RFC 5652 §5.4).
    signed_attrs_der = signed_attrs.untag().dump()
    # Check 7: the signer certificate must be carried inside the token.
    if signer_certificate_der is None:
        raise WeaveError("E_TS_CMS", "signer certificate not found in the token")
    certificate = _load_der_certificate(signer_certificate_der)

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
                # W6: a key the allowlisted algorithm cannot use means the
                # signature does not verify (check 10), not a check-6 failure.
                raise WeaveError("E_TS_CMS", "signature algorithm does not match the key")
            digest_class = _RSA_PKCS1V15_OIDS[signature_algorithm_oid]
            public_key.verify(signature, signed_attrs_der, padding.PKCS1v15(), digest_class())
        else:
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise WeaveError("E_TS_CMS", "signature algorithm does not match the key")
            digest_class = _ECDSA_OIDS[signature_algorithm_oid]
            public_key.verify(signature, signed_attrs_der, ec.ECDSA(digest_class()))
    except WeaveError:
        raise
    except (InvalidSignature, UnsupportedAlgorithm, ValueError, TypeError) as error:
        # U1 exception audit: cryptography's verify() raises InvalidSignature for
        # a failing signature, UnsupportedAlgorithm for an unusable key/curve and
        # ValueError/TypeError for malformed key material.
        raise WeaveError("E_TS_CMS", "CMS signature does not verify") from error
    return signer_info, signer_certificate_der


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
    certificate = _load_der_certificate(certificate_der)
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


def _accuracy_to_us(tst_info) -> int | None:
    """Normalise TSTInfo accuracy (seconds/millis/micros) to microseconds (T3).

    Format errors raise ``E_TS_SCHEMA`` (invalid receipt): malformed/absent-type
    components, negative or non-integer values, and a *present*
    ``milliseconds``/``microseconds`` component outside 1–999 (an explicit 0 is
    out of range too). An absent component counts as 0 and an absent accuracy
    field is exact.

    Returns ``None`` for **unusable evidence**, which is not a format error: the
    converted total exceeds ``MAX_TS_ACCURACY`` or a signed 64-bit microsecond
    value overflows. The receipt is then present-unverified with
    ``E_TS_UNTRUSTED`` and can neither rescue nor support L2 (T3).
    """
    try:
        accuracy = tst_info["accuracy"]
    except (KeyError, ValueError, TypeError):
        return 0
    if accuracy is None or accuracy.native is None:
        return 0
    native = accuracy.native
    if not isinstance(native, dict):
        raise WeaveError("E_TS_SCHEMA", "accuracy is not a sequence")
    seconds = native.get("seconds")
    millis = native.get("millis")
    micros = native.get("micros")
    for component in (seconds, millis, micros):
        if component is not None and (
            isinstance(component, bool) or not isinstance(component, int)
        ):
            raise WeaveError("E_TS_SCHEMA", "accuracy components are not integers")
    if seconds is None:
        seconds = 0
    if millis is not None and not 1 <= millis <= 999:
        raise WeaveError(
            "E_TS_SCHEMA", "accuracy.milliseconds is outside 1-999"
        )
    if micros is not None and not 1 <= micros <= 999:
        raise WeaveError(
            "E_TS_SCHEMA", "accuracy.microseconds is outside 1-999"
        )
    if seconds < 0:
        raise WeaveError("E_TS_SCHEMA", "accuracy components are negative")
    total = (
        seconds * 1_000_000
        + (millis or 0) * 1000
        + (micros or 0)
    )
    if total > INT64_MAX:
        return None
    if total > MAX_TS_ACCURACY_US:
        return None
    return total


def _format_ms(epoch_ms: int) -> str:
    """Format integer milliseconds as a TS literal (``YYYY-MM-DDTHH:MM:SS.mmmZ``)."""
    seconds, milliseconds = divmod(epoch_ms, 1000)
    value = _datetime.datetime.fromtimestamp(seconds, tz=_datetime.timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % milliseconds
