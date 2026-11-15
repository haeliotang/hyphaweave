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
from cryptography.hazmat.primitives import hashes, serialization
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


_PEM_BLOCK = re.compile(
    rb"-----BEGIN CERTIFICATE-----\r?\n(.*?)-----END CERTIFICATE-----", re.DOTALL
)
_PEM_BASE64_LINE = re.compile(rb"^[A-Za-z0-9+/]*={0,2}$")


def parse_trust_anchors(pem_bytes: bytes) -> frozenset[bytes]:
    """Parse a PEM bundle of trust-anchor certificates into DER SHA-256 fingerprints.

    W4/§14.1: ``--tsa-trust`` is operator input exactly like ``--keys``. A file
    that is not a bundle of one or more well-formed PEM certificates is a usage
    error (:class:`UsageError`, exit 2, no report); it is never silently treated
    as an empty anchor set.

    S2/F62/F63 (§14.1): each certificate "decodes as an X.509 certificate"
    under the rules of §12.2 1e -- the RFC 5280 module walk with the 1b/1c
    rules, the version constraints and the 1a rules for every extension value
    -- and under no parsing library's habits.
    """
    import base64
    import binascii

    blocks = _PEM_BLOCK.findall(pem_bytes)
    if b"-----BEGIN" in _PEM_BLOCK.sub(b"", pem_bytes):
        raise UsageError("TSA trust file has a PEM block that is not a certificate")
    fingerprints: set[bytes] = set()
    for block in blocks:
        lines = [line.strip() for line in block.splitlines() if line.strip()]
        if not lines or any(not _PEM_BASE64_LINE.fullmatch(line) for line in lines):
            raise UsageError("TSA trust file has a malformed PEM certificate block")
        try:
            der = base64.b64decode(b"".join(lines), validate=True)
        except (binascii.Error, ValueError) as error:
            raise UsageError("TSA trust file has a malformed PEM certificate block") from error
        try:
            check_certificate_1e(der, "trust anchor")
        except WeaveError as error:
            raise UsageError(
                "TSA trust file holds a certificate that does not decode under §12.2 1e"
            ) from error
        fingerprints.add(hashlib.sha256(der).digest())
    if not fingerprints:
        raise UsageError("TSA trust file contains no certificate")
    return frozenset(fingerprints)


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
    present: frozenset[str] = frozenset(),
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
    # Phase 1: every listed TSR must exist, be within the class limit and hash
    # to the digest the attestation lists (§11.3 file-level checks), and every
    # ``.tsr`` file present in ``signatures/`` must be listed (S2/F54: an
    # unlisted receipt file is a file-check failure, ``E_TS_FILE``, whatever
    # the claimed level; every listed receipt is then invalid).
    file_errors: list[str] = []
    file_data: dict[str, bytes] = {}
    if any(path not in entries for path in present):
        file_errors.append("E_TS_FILE")
    if not entries and not file_errors:
        return archive
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
        # RFC 5652 §5.3: version 1 with issuerAndSerialNumber, 3 with
        # subjectKeyIdentifier (the sid's first identifier octet decides).
        expected_version = "v1" if walk.signer_identifiers[0][0] == 0x30 else "v3"
        if signer_info_version != expected_version:
            raise WeaveError("E_TS_SCHEMA", "signerInfo version does not match its sid")
    # Check 1e (X7/M3): only the signer certificate is decoded. The other
    # components of SignedData.certificates are open types (framing only, 1a).
    # The signer certificate is located by its sid on the raw TLVs, walked with
    # the RFC 5280 module definition (1b/1c rules), decoded as an X.509
    # certificate, and its extension values obey the universal rules of 1a.
    signer_certificate_der = der_schema.signer_certificate(walk)
    if signer_certificate_der is not None:
        check_certificate_1e(signer_certificate_der, "signer certificate")
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


def check_certificate_1e(certificate_der: bytes, label: str) -> der_schema.CertificateFacts:
    """§12.2 1e for one certificate: walk, re-encode, version rules, extension values.

    S2/F62/F63: the certificate is judged by the RFC 5280 module definition and
    X.690 only (1b/1c rules, the version constraints of the module, every
    ``extnValue`` one TLV under 1a); no parsing library decides whether it
    "decodes as an X.509 certificate". ``--tsa-trust`` anchors are judged by
    the same function (§14.1).
    """
    certificate_walk = _require_der_reencoding(der_schema.CERTIFICATE, certificate_der, label)
    try:
        facts = der_schema.certificate_facts(certificate_der)
        der_schema.check_certificate_version(facts)
    except (der_schema.DerViolation, IndexError) as error:
        raise WeaveError("E_TS_SCHEMA", "%s: %s" % (label, error)) from error
    for extension_value in certificate_walk.certificate_extension_values:
        _validate_strict_der(extension_value)
    return facts


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

#: Universal tag numbers whose DER encoding is always primitive (S2-FIX1 T3, the
#: §12.2 1a table): BOOLEAN, INTEGER, BIT STRING, OCTET STRING, NULL, OBJECT
#: IDENTIFIER, ObjectDescriptor (a GraphicString, X.690 §10.2), REAL (§8.5.1),
#: ENUMERATED (§8.4), UTF8String, RELATIVE-OID (§8.20.1), TIME (§8.26.1.1), the
#: restricted character string types (§10.2), UTCTime, GeneralizedTime, and DATE,
#: TIME-OF-DAY, DATE-TIME, DURATION (§8.26), OID-IRI and RELATIVE-OID-IRI (§8.21,
#: §8.22). SEQUENCE/SET and EXTERNAL/EMBEDDED PDV/CHARACTER STRING are constructed.
_DER_PRIMITIVE_UNIVERSAL = frozenset(
    {1, 2, 3, 4, 5, 6, 7, 9, 10, 12, 13, 14, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
     30, 31, 32, 33, 34, 35, 36}
)
#: S2-FIX1 T3: contents defined as UTF-8 by X.690 (UTF8String §8.23.10). DATE,
#: TIME-OF-DAY, DATE-TIME, OID-IRI and RELATIVE-OID-IRI are rejected instead
#: (S2-FIX2 U4).
_DER_UTF8_UNIVERSAL = frozenset({12})
#: S2-FIX2 U4: the types that carry no explicit escape sequence: NumericString,
#: PrintableString, IA5String, VisibleString (X.690 §8.23.5.3, Table 3 "No") and
#: UTF8String (§8.23.10). Their content contains no ESC (0x1B) octet.
_DER_NO_ESCAPE_UNIVERSAL = frozenset({12, 18, 19, 22, 26})
#: S2-FIX1 T3: the ISO 2022 register types under X.690 §11.4 (ObjectDescriptor,
#: TeletexString, VideotexString, GraphicString, GeneralString). S2-FIX2 U4: their
#: escape sequences are judged by §11.4 and §8.23.5.4 as far as the octets fix
#: them (:func:`_check_der_iso2022`), no longer rejected as a whole.
_DER_ISO2022_UNIVERSAL = frozenset({7, 20, 21, 25, 27})
#: S2-FIX1 T3: TIME (14) and DURATION (34): the §11.9 canonical form needs an
#: ISO 8601 interval/duration parser this profile does not define; 1a rejects them
#: (conservative; no module of check 1 uses them). S2-FIX2 U4: DATE (31),
#: TIME-OF-DAY (32), DATE-TIME (33), OID-IRI (35) and RELATIVE-OID-IRI (36) are
#: rejected on the same footing (their value notations are not judged either).
_DER_REJECTED_UNIVERSAL = frozenset({14, 31, 32, 33, 34, 35, 36})
#: S2-FIX2 U4: the default designations of X.690 Table 3 (§8.23.5.2) per ISO 2022
#: register type, as (set class, final octets) of the G0, C0 and C1 sets.
_ISO2022_DEFAULTS: dict[int, dict[str, tuple[str, bytes]]] = {
    7: {"G0": ("94", b"B")},  # ObjectDescriptor is a GraphicString
    20: {"G0": ("94", b"u"), "C0": ("C0", b"E"), "C1": ("C1", b"H")},  # TeletexString
    21: {"G0": ("94", b"u"), "C0": ("C0", b"@"), "C1": ("C1", b"A")},  # VideotexString
    25: {"G0": ("94", b"B")},  # GraphicString
    27: {"G0": ("94", b"B"), "C0": ("C0", b"@")},  # GeneralString
}
#: ISO/IEC 2022 designation intermediates: the G set they designate into and the
#: class of the designated set (94 or 96 graphic characters).
_ISO2022_G_SINGLE = {0x28: ("G0", "94"), 0x29: ("G1", "94"), 0x2A: ("G2", "94"),
                     0x2B: ("G3", "94"), 0x2D: ("G1", "96"), 0x2E: ("G2", "96"),
                     0x2F: ("G3", "96")}
#: The smallest numbered G set for which a designating escape sequence exists, per
#: set class (§11.4: "into the smallest numbered G or C set"): a 94-character set
#: has a G0 sequence, a 96-character set none (its smallest is G1).
_ISO2022_SMALLEST_G = {"94": "G0", "96": "G1", "94n": "G0", "96n": "G1"}
_DER_REAL_NR3 = re.compile(rb"-?[1-9](?:[0-9]*[1-9])?\.E(?:\+0|-?[1-9][0-9]*)")
#: S2/F66: EXTERNAL (8, X.690 §8.18), EMBEDDED PDV (11, §8.19) and the
#: unrestricted CHARACTER STRING (29, §8.21) are SEQUENCE-based and always use
#: the constructed form; their primitive form is a 1a violation.
_DER_CONSTRUCTED_ONLY_UNIVERSAL = frozenset({8, 11, 29})
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
        if tag_number == 0:
            # S2/F57 (X.690 §8.1.5, §8.3): universal tag number 0 is reserved
            # for the end-of-contents octets of the indefinite form, which DER
            # forbids; it never occurs, whatever its length.
            raise _DerViolation("universal tag number 0")
        if tag_number in (16, 17) or tag_number in _DER_CONSTRUCTED_ONLY_UNIVERSAL:
            if not constructed:
                raise _DerViolation("constructed-only universal type is primitive")
        elif constructed and tag_number in _DER_PRIMITIVE_UNIVERSAL:
            raise _DerViolation("primitive universal type is constructed")
        if tag_number == 1:
            if length != 1 or data[position] not in (0x00, 0xFF):
                raise _DerViolation("BOOLEAN is not canonical DER")
        elif tag_number in (2, 10):
            # S2/F57: ENUMERATED is encoded as an INTEGER (X.690 §8.4).
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
        elif tag_number in _DER_UTF8_UNIVERSAL:
            try:
                data[position:content_end].decode("utf-8")
            except UnicodeDecodeError as error:
                raise _DerViolation("UTF-8 content is not valid UTF-8") from error
            if 0x1B in data[position:content_end]:
                raise _DerViolation("an escape sequence in a UTF8String (X.690 §8.23.10)")
        elif tag_number in _DER_NO_ESCAPE_UNIVERSAL and 0x1B in data[position:content_end]:
            raise _DerViolation("an escape sequence in a string type that allows none")
        elif tag_number == 9:
            _check_der_real(data, position, content_end)
        elif tag_number == 13:
            _check_der_oid(data, position, content_end, "RELATIVE-OID")
        elif tag_number in _DER_REJECTED_UNIVERSAL:
            raise _DerViolation(
                "TIME, DURATION, DATE, TIME-OF-DAY, DATE-TIME, OID-IRI and "
                "RELATIVE-OID-IRI values are not accepted (§12.2 1a)"
            )
        elif tag_number == 28 and length % 4:
            raise _DerViolation("UniversalString is not whole 4-octet units")
        elif tag_number == 30 and length % 2:
            raise _DerViolation("BMPString is not whole 2-octet units")
        elif tag_number in _DER_ISO2022_UNIVERSAL and 0x1B in data[position:content_end]:
            _check_der_iso2022(tag_number, data[position:content_end])
    if constructed:
        if tag_class == 0 and tag_number == 17:
            _scan_set_of(data, position, content_end, depth + 1)
        else:
            _scan_der(data, position, content_end, depth + 1)
    return content_end


def _iso2022_designation(sequence: bytes) -> tuple[str, str, bytes] | None:
    """Return ``(set, class, entry)`` when *sequence* (``ESC I... F``) designates.

    ISO/IEC 2022 designations: ``ESC 2/8..2/11 [I] F`` (94-set into G0..G3),
    ``ESC 2/13..2/15 [I] F`` (96-set into G1..G3), ``ESC 2/4 F`` with F in
    4/0..4/2 (94^n-set into G0), ``ESC 2/4 2/8..2/11 [I] F`` and
    ``ESC 2/4 2/13..2/15 [I] F`` (94^n / 96^n), ``ESC 2/1 F`` (C0) and
    ``ESC 2/2 F`` (C1). ``entry`` identifies the register entry: the octets
    after the set-selecting intermediate, the final octet included.
    """
    intermediates = sequence[1:]
    first = intermediates[0]
    if first == 0x21:
        return "C0", "C0", intermediates[1:]
    if first == 0x22:
        return "C1", "C1", intermediates[1:]
    if first in _ISO2022_G_SINGLE:
        target, size = _ISO2022_G_SINGLE[first]
        return target, size, intermediates[1:]
    if first == 0x24:
        if len(intermediates) == 2:
            return "G0", "94n", intermediates[1:]
        second = intermediates[1]
        if second in _ISO2022_G_SINGLE:
            target, size = _ISO2022_G_SINGLE[second]
            return target, size + "n", intermediates[2:]
    return None


def _check_der_iso2022(tag_number: int, content: bytes) -> None:
    """S2-FIX2 U4: the escape sequences of an ISO 2022 register type.

    Judged from the octets alone, starting from the Table 3 defaults
    (§8.23.5.2): every ESC (0x1B) begins a complete escape sequence (ISO/IEC
    2022: zero or more intermediates 2/0..2/15, then one final octet 3/0..7/14); no announcer
    (``ESC 2/0 F``, §8.23.5.4); a designation never names a register entry that
    is already designated as G0, G1, G2, G3, C0 or C1, and it designates into the
    smallest numbered G set that has an escape sequence for the entry's class
    (§11.4). Other escape sequences (invocations, for example) are not judged:
    whether one is needed depends on the characters, which 1a does not map.
    """
    designated: dict[str, tuple[str, bytes]] = dict(_ISO2022_DEFAULTS[tag_number])
    position = 0
    while True:
        position = content.find(b"\x1b", position)
        if position < 0:
            return
        cursor = position + 1
        while cursor < len(content) and 0x20 <= content[cursor] <= 0x2F:
            cursor += 1
        if cursor >= len(content) or not 0x30 <= content[cursor] <= 0x7E:
            raise _DerViolation("an incomplete ISO 2022 escape sequence")
        sequence = content[position : cursor + 1]
        position = cursor + 1
        if sequence[1] == 0x20:
            raise _DerViolation("an ISO 2022 announcer (X.690 §8.23.5.4)")
        designation = _iso2022_designation(sequence)
        if designation is None:
            continue
        target, size, entry = designation
        if (size, entry) in designated.values():
            raise _DerViolation("an ISO 2022 designation of an entry already designated (§11.4)")
        if target.startswith("G") and target != _ISO2022_SMALLEST_G[size]:
            raise _DerViolation("an ISO 2022 designation not into the smallest G set (§11.4)")
        designated[target] = (size, entry)


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


def _check_der_oid(
    data: bytes, start: int, end: int, name: str = "OBJECT IDENTIFIER"
) -> None:
    """X.690 §8.19.2 / §8.20.2: non-empty, every (sub-)identifier minimal and complete."""
    if end <= start:
        raise _DerViolation("%s is empty" % name)
    component_start = True
    position = start
    while position < end:
        byte = data[position]
        if component_start and byte == 0x80:
            raise _DerViolation("%s is not minimally encoded" % name)
        component_start = not byte & 0x80
        if not component_start and position == end - 1:
            raise _DerViolation("%s is truncated" % name)
        position += 1


def _check_der_real(data: bytes, start: int, end: int) -> None:
    """S2-FIX1 T3: a REAL under X.690 §8.5 and the DER restrictions of §11.3.

    Plus zero has no contents octets (§8.5.2). Binary form (§8.5.7, §11.3.1):
    base 2, scaling factor 0, the exponent in the fewest octets (formats 00/01/10
    for one to three octets; the long format 11 only for four or more, its first
    nine bits not all zeros or all ones), the mantissa N non-zero, odd and without
    a leading zero octet. Decimal form (§8.5.8, §11.3.2): NR3 only, written
    ``-?D...D.E`` with neither the first nor the last mantissa digit 0 and the
    exponent ``+0`` or without a plus sign or leading zero. Special values
    (§8.5.9): exactly one octet 0x40-0x43.
    """
    if end == start:
        return
    first = data[start]
    if first & 0x80:
        if first & 0x30:
            raise _DerViolation("REAL binary encoding does not use base 2")
        if first & 0x0C:
            raise _DerViolation("REAL binary scaling factor is not zero")
        exponent_format = first & 0x03
        position = start + 1
        if exponent_format < 3:
            exponent_length = exponent_format + 1
        else:
            if position >= end:
                raise _DerViolation("REAL exponent length octet is missing")
            exponent_length = data[position]
            position += 1
            if exponent_length < 4:
                raise _DerViolation("REAL long exponent format for a short exponent")
        if position + exponent_length > end:
            raise _DerViolation("REAL exponent is truncated")
        exponent = data[position : position + exponent_length]
        if exponent_length > 1 and (
            (exponent[0] == 0x00 and exponent[1] < 0x80)
            or (exponent[0] == 0xFF and exponent[1] >= 0x80)
        ):
            raise _DerViolation("REAL exponent is not in the fewest octets")
        mantissa = data[position + exponent_length : end]
        if not mantissa or mantissa[0] == 0x00:
            raise _DerViolation("REAL mantissa is empty or not in the fewest octets")
        if not mantissa[-1] & 0x01:
            raise _DerViolation("REAL mantissa is not odd")
        return
    if first & 0x40:
        if end - start != 1 or first > 0x43:
            raise _DerViolation("REAL special value is not one of the four defined octets")
        return
    if first != 0x03:
        raise _DerViolation("REAL decimal encoding is not the NR3 form")
    if not _DER_REAL_NR3.fullmatch(data[start + 1 : end]):
        raise _DerViolation("REAL NR3 text is not in the DER form of X.690 §11.3.2")


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
    certificate_facts = der_schema.certificate_facts(signer_certificate_der)

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
    try:
        # Check 10 is the only place a library reads the certificate: the
        # subjectPublicKeyInfo is handed to the key loader (F64).
        public_key = serialization.load_der_public_key(
            certificate_facts.subject_public_key_info
        )
        if signature_algorithm_oid in _RSA_PKCS1V15_OIDS:
            if not isinstance(public_key, rsa.RSAPublicKey):
                # W6: a key the allowlisted algorithm cannot use means the
                # signature does not verify (check 10), not a check-6 failure.
                raise WeaveError("E_TS_CMS", "signature algorithm does not match the key")
            _check_rsa_key_bounds(public_key)
            digest_class = _RSA_PKCS1V15_OIDS[signature_algorithm_oid]
            public_key.verify(signature, signed_attrs_der, padding.PKCS1v15(), digest_class())
        else:
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise WeaveError("E_TS_CMS", "signature algorithm does not match the key")
            _check_ecdsa_signature_encoding(signature, public_key)
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


#: S2-FIX1 Q4 (§12.2 check 10): the RSA bounds written into the profile.
_RSA_MIN_MODULUS_BITS = 2048
_RSA_MAX_MODULUS_BITS = 8192
_RSA_MIN_EXPONENT = 65537
_RSA_EXPONENT_LIMIT = 1 << 256
#: Group orders n of the curves whose bound Python checks itself; for any other
#: curve the library's verification rejects r or s outside [1, n-1] (FIPS 186-5).
_EC_ORDERS = {
    "secp256r1": int(
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
    ),
    "secp384r1": int(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF"
        "581A0DB248B0A77AECEC196ACCC52973",
        16,
    ),
    "secp521r1": int(
        "01FF" + "FFFFFFFF" * 7 + "FFFFFFFA"
        "51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
        16,
    ),
}


def _check_rsa_key_bounds(public_key: "rsa.RSAPublicKey") -> None:
    """S2-FIX1 Q4: modulus 2048-8192 bits; public exponent odd, 65537 <= e < 2^256."""
    if not _RSA_MIN_MODULUS_BITS <= public_key.key_size <= _RSA_MAX_MODULUS_BITS:
        raise WeaveError("E_TS_CMS", "RSA modulus size is outside 2048-8192 bits")
    exponent = public_key.public_numbers().e
    if exponent % 2 == 0 or not _RSA_MIN_EXPONENT <= exponent < _RSA_EXPONENT_LIMIT:
        raise WeaveError("E_TS_CMS", "RSA public exponent is outside the profile bounds")


def _check_ecdsa_signature_encoding(signature: bytes, public_key) -> None:
    """S2-FIX1 Q4: ``Ecdsa-Sig-Value`` is a DER SEQUENCE of two minimal positive
    INTEGERs r and s, each in [1, n - 1], with no trailing octets."""

    def read_tlv(data: bytes, position: int, expected_tag: int) -> tuple[bytes, int]:
        if position + 2 > len(data) or data[position] != expected_tag:
            raise WeaveError("E_TS_CMS", "ECDSA signature is not a DER Ecdsa-Sig-Value")
        length = data[position + 1]
        position += 2
        if length & 0x80:
            count = length & 0x7F
            if count == 0 or count > 2 or position + count > len(data) or data[position] == 0:
                raise WeaveError("E_TS_CMS", "ECDSA signature length is not DER")
            length = int.from_bytes(data[position : position + count], "big")
            if length < 0x80:
                raise WeaveError("E_TS_CMS", "ECDSA signature length is not DER")
            position += count
        if position + length > len(data):
            raise WeaveError("E_TS_CMS", "ECDSA signature is truncated")
        return data[position : position + length], position + length

    body, end = read_tlv(signature, 0, 0x30)
    if end != len(signature):
        raise WeaveError("E_TS_CMS", "ECDSA signature carries trailing octets")
    order = _EC_ORDERS.get(public_key.curve.name)
    position = 0
    for _name in ("r", "s"):
        content, position = read_tlv(body, position, 0x02)
        if not content or content[0] & 0x80:
            raise WeaveError("E_TS_CMS", "ECDSA %s is not a positive INTEGER" % _name)
        if len(content) > 1 and content[0] == 0x00 and content[1] < 0x80:
            raise WeaveError("E_TS_CMS", "ECDSA %s is not minimally encoded" % _name)
        value = int.from_bytes(content, "big")
        if value < 1 or (order is not None and value >= order):
            raise WeaveError("E_TS_CMS", "ECDSA %s is outside [1, n - 1]" % _name)
    if position != len(body):
        raise WeaveError("E_TS_CMS", "ECDSA signature has more than two components")


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
    """Checks 11-12: timestamping EKU / key usage / validity at genTime.

    Read from the certificate walked by 1e (:func:`der_schema.certificate_facts`),
    not through a parsing library (S2/F63).
    """
    facts = der_schema.certificate_facts(certificate_der)
    gen_time = _to_aware_datetime(gen_time_value)
    extensions = {oid: value for oid, _critical, value in reversed(facts.extensions)}
    extended_key_usage = extensions.get(_ID_CE_EXT_KEY_USAGE)
    if extended_key_usage is None:
        raise WeaveError("E_TS_CERT", "signer certificate has no timeStamping EKU")
    try:
        purposes = der_schema.sequence_of_oids(extended_key_usage)
    except der_schema.DerViolation as error:
        raise WeaveError("E_TS_CERT", "signer certificate EKU is malformed") from error
    if _ID_KP_TIME_STAMPING not in purposes:
        raise WeaveError("E_TS_CERT", "signer certificate is not a timestamping certificate")
    key_usage = extensions.get(_ID_CE_KEY_USAGE)
    if key_usage is not None:
        try:
            bits = der_schema.bit_string_content(key_usage)
        except der_schema.DerViolation as error:
            raise WeaveError("E_TS_CERT", "signer certificate key usage is malformed") from error
        # digitalSignature is bit 0: the most significant bit of the first
        # content octet after the unused-bits octet.
        if len(bits) < 2 or not bits[1] & 0x80:
            raise WeaveError("E_TS_CERT", "signer certificate key usage lacks digitalSignature")
    not_before = _certificate_time(facts.not_before)
    not_after = _certificate_time(facts.not_after)
    if not_before > gen_time or not_after < gen_time:
        raise WeaveError("E_TS_CERT", "signer certificate is not valid at genTime")


_ID_CE_EXT_KEY_USAGE = der_schema.oid_content("2.5.29.37")
_ID_CE_KEY_USAGE = der_schema.oid_content("2.5.29.15")
_ID_KP_TIME_STAMPING = der_schema.oid_content("1.3.6.1.5.5.7.3.8")


def _certificate_time(value: tuple[int, bytes]) -> _datetime.datetime:
    """A certificate validity time (RFC 5280 §4.1.2.5) as an aware datetime.

    UTCTime ``YYMMDDHHMMSSZ`` (YY >= 50 is 19YY, otherwise 20YY) or
    GeneralizedTime ``YYYYMMDDHHMMSS[.f]Z``; 1a already fixed the DER form.
    """
    tag, content = value
    text = content.decode("ascii")
    try:
        if tag == 23:
            year = int(text[0:2])
            year += 1900 if year >= 50 else 2000
            rest = text[2:12]
            fraction = ""
        else:
            year = int(text[0:4])
            rest = text[4:14]
            fraction = text[15:-1] if "." in text else ""
        result = _datetime.datetime(
            year,
            int(rest[0:2]),
            int(rest[2:4]),
            int(rest[4:6]),
            int(rest[6:8]),
            int(rest[8:10]),
            int((fraction + "000000")[:6]) if fraction else 0,
            tzinfo=_datetime.timezone.utc,
        )
    except ValueError as error:
        raise WeaveError("E_TS_CERT", "signer certificate validity is not a valid time") from error
    return result


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
