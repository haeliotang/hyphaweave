# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""§12.2 checks 1b/1c: the receipt schema and its DER re-encoding (S1-FIX5 X1).

Every rule in this module comes from X.690 (DER) and from the ASN.1 module
definitions of RFC 3161, RFC 5652, RFC 5280 and RFC 5035/5816. No parsing
library is consulted: the input bytes are walked directly against a small,
hand-written copy of the module definitions below, and each value is
re-encoded from what was decoded:

* a ``SEQUENCE`` re-emits its components in schema order and **omits a
  component whose encoding equals its DEFAULT** (X.690 §11.5); the DEFAULT
  encodings are written out from the module definitions in :data:`DEFAULTS`;
* a ``SET OF`` re-emits its components in ascending order of their encodings
  (X.690 §11.6);
* a typed primitive is rebuilt from its content octets by the X.690 rules for
  its type, whether universally or implicitly tagged: INTEGER minimal (§8.3.2),
  BOOLEAN ``00``/``FF`` (§11.1), NULL empty (§8.8), OBJECT IDENTIFIER
  sub-identifiers minimal (§8.19.2), BIT STRING unused bits zero (§11.2.1) and,
  for a named bit list, no trailing zero bit (§11.2.2), the time types in their
  DER form compared as their raw content (§11.7, §11.8: no time-object round
  trip, so any number of fractional digits is kept), strings and OCTET STRING
  content as decoded and always in the primitive form (§10.2);
* the ``parameters`` of the signer's ``digestAlgorithm`` and
  ``signatureAlgorithm`` have the form fixed per algorithm in
  :data:`SIGNER_DIGEST_PARAMETERS` / :data:`SIGNER_SIGNATURE_PARAMETERS` (X6);
* a value of an **open type** (``ANY`` / ``ANY DEFINED BY`` with a type this
  profile does not decode — see :data:`KNOWN_ATTRIBUTES` and the ``ANY``
  fields below) is re-emitted as its own TLV, untouched. Only its framing (tag,
  length and nesting, plus the universal rules) is judged, by the check-1a scan
  that runs over every byte of the file before this walk.

Every header is rebuilt with the minimal definite length. The caller compares
the re-encoding with the input; equality is check 1c.
"""

from __future__ import annotations

import re
from typing import Callable

__all__ = [
    "DerViolation",
    "WalkContext",
    "reencode",
    "TIME_STAMP_RESP",
    "TST_INFO",
    "SIGNER_DIGEST_PARAMETERS",
    "SIGNER_SIGNATURE_PARAMETERS",
    "DEFAULTS",
    "KNOWN_ATTRIBUTES",
]


class DerViolation(ValueError):
    """The bytes do not decode under the schema, or are not DER."""


# ---------------------------------------------------------------------------
# TLV framing (X.690 §8.1)
# ---------------------------------------------------------------------------

_UNIVERSAL, _APPLICATION, _CONTEXT, _PRIVATE = 0, 1, 2, 3
#: Tag numbers above this are irrelevant to the schema (it only uses small
#: tags); a longer base-128 form keeps being read but no longer accumulated.
_TAG_ACCUMULATION_LIMIT = 1 << 32


def _read_header(data: bytes, position: int, end: int) -> tuple[int, bool, int, int, int]:
    """``(class, constructed, number, content_start, content_end)`` at ``position``."""
    if position >= end:
        raise DerViolation("a required component is missing")
    first = data[position]
    position += 1
    tag_class = first >> 6
    constructed = bool(first & 0x20)
    number = first & 0x1F
    if number == 0x1F:
        # X.690 §8.1.2.4: base 128, high bit set on every octet but the last;
        # bits 7-1 of the first subsequent octet are not all zero.
        number = 0
        first_subsequent = True
        while True:
            if position >= end:
                raise DerViolation("truncated high-tag-number form")
            octet = data[position]
            position += 1
            if first_subsequent and octet == 0x80:
                raise DerViolation("non-minimal high-tag-number form")
            first_subsequent = False
            if number < _TAG_ACCUMULATION_LIMIT:
                number = (number << 7) | (octet & 0x7F)
            if not octet & 0x80:
                break
    if position >= end:
        raise DerViolation("missing length")
    length = data[position]
    position += 1
    if length & 0x80:
        count = length & 0x7F
        if count == 0:
            raise DerViolation("indefinite length is not DER")
        if position + count > end:
            raise DerViolation("truncated length")
        length = int.from_bytes(data[position : position + count], "big")
        position += count
    content_end = position + length
    if content_end > end:
        raise DerViolation("content runs past its container")
    return tag_class, constructed, number, position, content_end


def _identifier(tag_class: int, constructed: bool, number: int) -> bytes:
    first = (tag_class << 6) | (0x20 if constructed else 0)
    if number < 31:
        return bytes([first | number])
    groups = []
    while True:
        groups.append(number & 0x7F)
        number >>= 7
        if not number:
            break
    tail = [group | 0x80 for group in reversed(groups[1:])] + [groups[0]]
    return bytes([first | 0x1F]) + bytes(tail)


def _length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag_class: int, constructed: bool, number: int, content: bytes) -> bytes:
    return _identifier(tag_class, constructed, number) + _length(len(content)) + content


class WalkContext:
    """Facts the walk hands to the later sub-steps (checks 1d and 1e)."""

    __slots__ = ("certificate_extension_values", "certificates", "signer_identifiers")

    def __init__(self) -> None:
        #: The ``extnValue`` contents of the extensions of the certificate walked
        #: with :data:`CERTIFICATE` (1e: the signer certificate only).
        self.certificate_extension_values: list[bytes] = []
        #: Every component of ``SignedData.certificates``, as its raw TLV.
        self.certificates: list[bytes] = []
        #: The raw ``sid`` TLV of every ``SignerInfo``, in input order.
        self.signer_identifiers: list[bytes] = []


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------


class _Type:
    """A schema type. ``tag`` is ``(class, number)``; ``None`` for CHOICE/ANY."""

    tag: tuple[int, int] | None = None
    constructed = False

    def accepts(self, tag_class: int, number: int) -> bool:
        return self.tag == (tag_class, number)

    def content(self, data: bytes, start: int, end: int, context: WalkContext) -> bytes:
        raise NotImplementedError

    def decode(
        self, data: bytes, position: int, end: int, context: WalkContext
    ) -> tuple[bytes, int]:
        """Decode one value at ``position``; return ``(re-encoding, next position)``."""
        tag_class, constructed, number, start, content_end = _read_header(data, position, end)
        if (tag_class, number) != self.tag:
            raise DerViolation("unexpected tag for %s" % type(self).__name__)
        if constructed != self.constructed:
            raise DerViolation("wrong primitive/constructed form for %s" % type(self).__name__)
        content = self.content(data, start, content_end, context)
        return _tlv(tag_class, constructed, number, content), content_end


_GENERALIZED_TIME_DER = re.compile(rb"^[0-9]{14}(?:\.[0-9]*[1-9])?Z$")
_UTC_TIME_DER = re.compile(rb"^[0-9]{12}Z$")


def _canonical_integer(content: bytes) -> bytes:
    """X.690 §8.3.2: the shortest two's-complement form of the decoded value."""
    if not content:
        raise DerViolation("INTEGER is empty")
    index = 0
    while index + 1 < len(content) and (
        (content[index] == 0x00 and content[index + 1] < 0x80)
        or (content[index] == 0xFF and content[index + 1] >= 0x80)
    ):
        index += 1
    return content[index:]


def _canonical_boolean(content: bytes) -> bytes:
    """X.690 §8.2.1 decodes one octet; §11.1 encodes TRUE as ``FF``."""
    if len(content) != 1:
        raise DerViolation("BOOLEAN is not one octet")
    return b"\xff" if content[0] else b"\x00"


def _canonical_null(content: bytes) -> bytes:
    if content:
        raise DerViolation("NULL has content octets")
    return b""


def _canonical_oid(content: bytes) -> bytes:
    """X.690 §8.19.2: each sub-identifier in the fewest possible octets."""
    if not content:
        raise DerViolation("OBJECT IDENTIFIER is empty")
    if content[-1] & 0x80:
        raise DerViolation("OBJECT IDENTIFIER is truncated")
    rebuilt = bytearray()
    at_start = True
    for octet in content:
        if at_start and octet == 0x80:
            continue  # a leading zero group: dropped by the minimal form
        rebuilt.append(octet)
        at_start = not octet & 0x80
    return bytes(rebuilt)


def _canonical_bit_string(content: bytes, *, named_bits: bool) -> bytes:
    """X.690 §8.6.2 / §11.2: unused bits zero; named bit lists without trailing 0s."""
    if not content:
        raise DerViolation("BIT STRING has no unused-bits octet")
    unused = content[0]
    if unused > 7 or (len(content) == 1 and unused):
        raise DerViolation("BIT STRING unused-bit count is invalid")
    if len(content) == 1:
        return content
    body = bytearray(content[1:])
    body[-1] &= (0xFF << unused) & 0xFF
    if not named_bits:
        return bytes([unused]) + bytes(body)
    while body and body[-1] == 0:
        body.pop()
    if not body:
        return b"\x00"
    last = body[-1]
    trailing = (last & -last).bit_length() - 1
    return bytes([trailing]) + bytes(body)


class _Primitive(_Type):
    def __init__(self, number: int, kind: str) -> None:
        self.tag = (_UNIVERSAL, number)
        self.kind = kind

    def content(self, data: bytes, start: int, end: int, context: WalkContext) -> bytes:
        raw = data[start:end]
        kind = self.kind
        if kind == "integer":
            return _canonical_integer(raw)
        if kind == "boolean":
            return _canonical_boolean(raw)
        if kind == "null":
            return _canonical_null(raw)
        if kind == "oid":
            return _canonical_oid(raw)
        if kind == "bits":
            return _canonical_bit_string(raw, named_bits=False)
        if kind == "named-bits":
            return _canonical_bit_string(raw, named_bits=True)
        if kind == "generalized-time":
            # X.690 §11.7 checked on the raw content; never a time-object round trip.
            if not _GENERALIZED_TIME_DER.fullmatch(raw):
                raise DerViolation("GeneralizedTime is not in its DER form")
            return raw
        if kind == "utc-time":
            if not _UTC_TIME_DER.fullmatch(raw):
                raise DerViolation("UTCTime is not in its DER form")
            return raw
        # OCTET STRING and the character string types: content as decoded.
        return raw


class _Implicit(_Type):
    """``[class number] IMPLICIT inner``: the inner type's content under a new tag."""

    def __init__(self, tag_class: int, number: int, inner: _Type) -> None:
        if inner.tag is None:
            raise TypeError("IMPLICIT tagging needs a tagged inner type")
        self.tag = (tag_class, number)
        self.constructed = inner.constructed
        self.inner = inner

    def content(self, data: bytes, start: int, end: int, context: WalkContext) -> bytes:
        return self.inner.content(data, start, end, context)


class _Explicit(_Type):
    """``[class number] EXPLICIT inner``: exactly one inner value inside the tag."""

    constructed = True

    def __init__(self, tag_class: int, number: int, inner: _Type) -> None:
        self.tag = (tag_class, number)
        self.inner = inner

    def content(self, data: bytes, start: int, end: int, context: WalkContext) -> bytes:
        encoded, position = self.inner.decode(data, start, end, context)
        if position != end:
            raise DerViolation("data after the value of an explicit tag")
        return encoded


class _Any(_Type):
    """An open type: one TLV, re-emitted as decoded (its framing is check 1a's)."""

    def accepts(self, tag_class: int, number: int) -> bool:
        return True

    def decode(
        self, data: bytes, position: int, end: int, context: WalkContext
    ) -> tuple[bytes, int]:
        _tag_class, _constructed, _number, _start, content_end = _read_header(
            data, position, end
        )
        return data[position:content_end], content_end


class _Opaque(_Type):
    """A tagged alternative whose inner type this profile does not decode."""

    def __init__(self, tag_class: int, number: int, constructed: bool) -> None:
        self.tag = (tag_class, number)
        self.constructed = constructed

    def content(self, data: bytes, start: int, end: int, context: WalkContext) -> bytes:
        return data[start:end]


class _Collected(_Any):
    """An open type whose raw TLV is also recorded in the walk context."""

    def __init__(self, slot: str) -> None:
        self.slot = slot

    def decode(
        self, data: bytes, position: int, end: int, context: WalkContext
    ) -> tuple[bytes, int]:
        encoded, content_end = super().decode(data, position, end, context)
        getattr(context, self.slot).append(encoded)
        return encoded, content_end


class _Choice(_Type):
    def __init__(self, *alternatives: _Type) -> None:
        self.alternatives = alternatives

    def accepts(self, tag_class: int, number: int) -> bool:
        return any(alternative.accepts(tag_class, number) for alternative in self.alternatives)

    def decode(
        self, data: bytes, position: int, end: int, context: WalkContext
    ) -> tuple[bytes, int]:
        tag_class, _constructed, number, _start, _end = _read_header(data, position, end)
        for alternative in self.alternatives:
            if alternative.accepts(tag_class, number):
                return alternative.decode(data, position, end, context)
        raise DerViolation("no CHOICE alternative has this tag")


class _SequenceOf(_Type):
    constructed = True

    def __init__(self, element: _Type, *, is_set: bool = False) -> None:
        self.tag = (_UNIVERSAL, 17 if is_set else 16)
        self.element = element
        self.is_set = is_set

    def content(self, data: bytes, start: int, end: int, context: WalkContext) -> bytes:
        components = []
        position = start
        while position < end:
            encoded, position = self.element.decode(data, position, end, context)
            components.append(encoded)
        if self.is_set:
            # X.690 §11.6: SET OF components in ascending order of their encodings.
            components.sort()
        return b"".join(components)


def _set_of(element: _Type) -> _SequenceOf:
    return _SequenceOf(element, is_set=True)


class _Field:
    __slots__ = ("name", "type", "optional", "default", "selector")

    def __init__(
        self,
        name: str,
        field_type: _Type | None,
        *,
        optional: bool = False,
        default: bytes | None = None,
        selector: Callable[[dict[str, bytes]], _Type] | None = None,
    ) -> None:
        self.name = name
        self.type = field_type
        self.optional = optional
        self.default = default
        self.selector = selector


class _Sequence(_Type):
    constructed = True
    tag = (_UNIVERSAL, 16)

    def __init__(self, *fields: _Field, collect_extension_value: bool = False) -> None:
        self.fields = fields
        self.collect_extension_value = collect_extension_value

    def content(self, data: bytes, start: int, end: int, context: WalkContext) -> bytes:
        parts = []
        #: Raw content octets of the components decoded so far (for ANY DEFINED BY).
        seen: dict[str, bytes] = {}
        position = start
        for field in self.fields:
            field_type = field.selector(seen) if field.selector is not None else field.type
            present = False
            if position < end:
                tag_class, _constructed, number, content_start, content_end = _read_header(
                    data, position, end
                )
                present = field_type.accepts(tag_class, number)
            if not present:
                if field.optional or field.default is not None:
                    continue
                raise DerViolation("required component %s is missing" % field.name)
            seen[field.name] = data[content_start:content_end]
            encoded, position = field_type.decode(data, position, end, context)
            if field.default is not None and encoded == field.default:
                # X.690 §11.5: a component equal to its DEFAULT is never encoded.
                raise DerViolation("component %s encodes its DEFAULT value" % field.name)
            parts.append(encoded)
        if position != end:
            raise DerViolation("unexpected component after the last field")
        if self.collect_extension_value:
            context.certificate_extension_values.append(seen["extnValue"])
        return b"".join(parts)


# ---------------------------------------------------------------------------
# The module definitions (RFC 3161, RFC 5652, RFC 5280, RFC 5035/5816)
# ---------------------------------------------------------------------------


def _oid_content(dotted: str) -> bytes:
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
    return bytes(body)


INTEGER = _Primitive(2, "integer")
BOOLEAN = _Primitive(1, "boolean")
BIT_STRING = _Primitive(3, "bits")
NAMED_BIT_STRING = _Primitive(3, "named-bits")
OCTET_STRING = _Primitive(4, "octets")
NULL = _Primitive(5, "null")
OBJECT_IDENTIFIER = _Primitive(6, "oid")
UTF8_STRING = _Primitive(12, "string")
PRINTABLE_STRING = _Primitive(19, "string")
TELETEX_STRING = _Primitive(20, "string")
IA5_STRING = _Primitive(22, "string")
UTC_TIME = _Primitive(23, "utc-time")
GENERALIZED_TIME = _Primitive(24, "generalized-time")
UNIVERSAL_STRING = _Primitive(28, "string")
BMP_STRING = _Primitive(30, "string")
ANY = _Any()

#: Every DEFAULT component in the schema, with the DER encoding of its default
#: value as written in the module definition (tag included). A component whose
#: re-encoding equals this is a DER violation; any other value is encoded.
DEFAULTS: dict[str, bytes] = {
    # RFC 5280 TBSCertificate: version [0] EXPLICIT Version DEFAULT v1
    "TBSCertificate.version": bytes.fromhex("a003020100"),
    # RFC 5280 Extension: critical BOOLEAN DEFAULT FALSE
    "Extension.critical": bytes.fromhex("010100"),
    # RFC 3161 TSTInfo: ordering BOOLEAN DEFAULT FALSE
    "TSTInfo.ordering": bytes.fromhex("010100"),
    # RFC 5035 (RFC 5816) ESSCertIDv2: hashAlgorithm AlgorithmIdentifier
    # DEFAULT {algorithm id-sha256} -- no parameters component.
    "ESSCertIDv2.hashAlgorithm": bytes.fromhex("300b0609608648016503040201"),
}

ALGORITHM_IDENTIFIER = _Sequence(
    _Field("algorithm", OBJECT_IDENTIFIER),
    _Field("parameters", ANY, optional=True),
)
#: X6 (decision 2026-11-12 #2): the permitted form of the ``parameters`` of the
#: signer's ``digestAlgorithm`` and ``signatureAlgorithm``, by algorithm.
#: "absent-or-null": RFC 5754 §2 (SHA-2 digests) and RFC 4055 §5 / RFC 5754
#: §3.2 (sha*WithRSAEncryption: "MUST accept the parameters being absent as
#: well as present"); "null": RFC 3370 §3.2 (rsaEncryption); "absent": RFC 5758
#: §3.2 (ECDSA). X7/M1 (decision 2026-11-12 #3) corrected the sha*WithRSA rows. An algorithm not listed keeps the open-type
#: rule (framing only); checks 5 and 6 reject it afterwards.
SIGNER_DIGEST_PARAMETERS: dict[bytes, str] = {
    _oid_content("2.16.840.1.101.3.4.2.4"): "absent-or-null",  # sha224
    _oid_content("2.16.840.1.101.3.4.2.1"): "absent-or-null",  # sha256
    _oid_content("2.16.840.1.101.3.4.2.2"): "absent-or-null",  # sha384
    _oid_content("2.16.840.1.101.3.4.2.3"): "absent-or-null",  # sha512
}
SIGNER_SIGNATURE_PARAMETERS: dict[bytes, str] = {
    _oid_content("1.2.840.113549.1.1.1"): "null",  # rsaEncryption
    _oid_content("1.2.840.113549.1.1.14"): "absent-or-null",  # sha224WithRSAEncryption
    _oid_content("1.2.840.113549.1.1.11"): "absent-or-null",  # sha256WithRSAEncryption
    _oid_content("1.2.840.113549.1.1.12"): "absent-or-null",  # sha384WithRSAEncryption
    _oid_content("1.2.840.113549.1.1.13"): "absent-or-null",  # sha512WithRSAEncryption
    _oid_content("1.2.840.10045.4.3.1"): "absent",  # ecdsa-with-SHA224
    _oid_content("1.2.840.10045.4.3.2"): "absent",  # ecdsa-with-SHA256
    _oid_content("1.2.840.10045.4.3.3"): "absent",  # ecdsa-with-SHA384
    _oid_content("1.2.840.10045.4.3.4"): "absent",  # ecdsa-with-SHA512
}
_NULL_ENCODING = b"\x05\x00"


class _SignerAlgorithm(_Sequence):
    """An AlgorithmIdentifier whose parameters form is fixed per algorithm (X6)."""

    def __init__(self, rules: dict[bytes, str]) -> None:
        super().__init__(
            _Field("algorithm", OBJECT_IDENTIFIER),
            _Field("parameters", ANY, optional=True),
        )
        self.rules = rules

    def content(self, data: bytes, start: int, end: int, context: WalkContext) -> bytes:
        encoded = super().content(data, start, end, context)
        _class, _constructed, _number, oid_start, oid_end = _read_header(encoded, 0, len(encoded))
        rule = self.rules.get(encoded[oid_start:oid_end])
        parameters = encoded[oid_end:]
        if rule == "absent-or-null" and parameters not in (b"", _NULL_ENCODING):
            raise DerViolation("algorithm parameters are neither absent nor NULL")
        if rule == "null" and parameters != _NULL_ENCODING:
            raise DerViolation("rsaEncryption parameters are not NULL")
        if rule == "absent" and parameters:
            raise DerViolation("ECDSA algorithm parameters are not absent")
        return encoded


_ATTRIBUTE_TYPE_AND_VALUE = _Sequence(
    _Field("type", OBJECT_IDENTIFIER),
    _Field("value", ANY),
)
_NAME = _SequenceOf(_set_of(_ATTRIBUTE_TYPE_AND_VALUE))  # Name ::= CHOICE { rdnSequence }
_TIME = _Choice(UTC_TIME, GENERALIZED_TIME)


def _extension(*, collect: bool) -> _Sequence:
    return _Sequence(
        _Field("extnID", OBJECT_IDENTIFIER),
        _Field("critical", BOOLEAN, default=DEFAULTS["Extension.critical"]),
        _Field("extnValue", OCTET_STRING),
        collect_extension_value=collect,
    )


_EXTENSIONS = _SequenceOf(_extension(collect=False))
_CERTIFICATE_EXTENSIONS = _SequenceOf(_extension(collect=True))

_TBS_CERTIFICATE = _Sequence(
    _Field(
        "version",
        _Explicit(_CONTEXT, 0, INTEGER),
        default=DEFAULTS["TBSCertificate.version"],
    ),
    _Field("serialNumber", INTEGER),
    _Field("signature", ALGORITHM_IDENTIFIER),
    _Field("issuer", _NAME),
    _Field("validity", _Sequence(_Field("notBefore", _TIME), _Field("notAfter", _TIME))),
    _Field("subject", _NAME),
    _Field(
        "subjectPublicKeyInfo",
        _Sequence(
            _Field("algorithm", ALGORITHM_IDENTIFIER),
            _Field("subjectPublicKey", BIT_STRING),
        ),
    ),
    _Field("issuerUniqueID", _Implicit(_CONTEXT, 1, BIT_STRING), optional=True),
    _Field("subjectUniqueID", _Implicit(_CONTEXT, 2, BIT_STRING), optional=True),
    _Field("extensions", _Explicit(_CONTEXT, 3, _CERTIFICATE_EXTENSIONS), optional=True),
)
CERTIFICATE = _Sequence(
    _Field("tbsCertificate", _TBS_CERTIFICATE),
    _Field("signatureAlgorithm", ALGORITHM_IDENTIFIER),
    _Field("signatureValue", BIT_STRING),
)

_TBS_CERT_LIST = _Sequence(
    _Field("version", INTEGER, optional=True),
    _Field("signature", ALGORITHM_IDENTIFIER),
    _Field("issuer", _NAME),
    _Field("thisUpdate", _TIME),
    _Field("nextUpdate", _TIME, optional=True),
    _Field(
        "revokedCertificates",
        _SequenceOf(
            _Sequence(
                _Field("userCertificate", INTEGER),
                _Field("revocationDate", _TIME),
                _Field("crlEntryExtensions", _EXTENSIONS, optional=True),
            )
        ),
        optional=True,
    ),
    _Field("crlExtensions", _Explicit(_CONTEXT, 0, _EXTENSIONS), optional=True),
)
_CERTIFICATE_LIST = _Sequence(
    _Field("tbsCertList", _TBS_CERT_LIST),
    _Field("signatureAlgorithm", ALGORITHM_IDENTIFIER),
    _Field("signatureValue", BIT_STRING),
)

_REVOCATION_INFO_CHOICE = _Choice(
    _CERTIFICATE_LIST,
    _Implicit(  # other OtherRevocationInfoFormat
        _CONTEXT,
        1,
        _Sequence(_Field("otherRevInfoFormat", OBJECT_IDENTIFIER), _Field("otherRevInfo", ANY)),
    ),
)

_DIRECTORY_STRING = _Choice(
    TELETEX_STRING, PRINTABLE_STRING, UNIVERSAL_STRING, UTF8_STRING, BMP_STRING
)
# RFC 5280 GeneralName (module PKIX1Implicit88, IMPLICIT TAGS; a tagged CHOICE
# or ANY is explicit). x400Address (ORAddress) is not decoded.
_GENERAL_NAME = _Choice(
    _Implicit(
        _CONTEXT,
        0,
        _Sequence(
            _Field("type-id", OBJECT_IDENTIFIER),
            _Field("value", _Explicit(_CONTEXT, 0, ANY)),
        ),
    ),
    _Implicit(_CONTEXT, 1, IA5_STRING),
    _Implicit(_CONTEXT, 2, IA5_STRING),
    _Opaque(_CONTEXT, 3, True),
    _Explicit(_CONTEXT, 4, _NAME),
    _Implicit(
        _CONTEXT,
        5,
        _Sequence(
            _Field("nameAssigner", _Explicit(_CONTEXT, 0, _DIRECTORY_STRING), optional=True),
            _Field("partyName", _Explicit(_CONTEXT, 1, _DIRECTORY_STRING)),
        ),
    ),
    _Implicit(_CONTEXT, 6, IA5_STRING),
    _Implicit(_CONTEXT, 7, OCTET_STRING),
    _Implicit(_CONTEXT, 8, OBJECT_IDENTIFIER),
)
_GENERAL_NAMES = _SequenceOf(_GENERAL_NAME)

# RFC 5035 / RFC 5816 (ESS).
_ISSUER_SERIAL = _Sequence(
    _Field("issuer", _GENERAL_NAMES),
    _Field("serialNumber", INTEGER),
)
_POLICY_INFORMATION = _Sequence(
    _Field("policyIdentifier", OBJECT_IDENTIFIER),
    _Field(
        "policyQualifiers",
        _SequenceOf(
            _Sequence(_Field("policyQualifierId", OBJECT_IDENTIFIER), _Field("qualifier", ANY))
        ),
        optional=True,
    ),
)
_ESS_CERT_ID_V2 = _Sequence(
    _Field(
        "hashAlgorithm",
        ALGORITHM_IDENTIFIER,
        default=DEFAULTS["ESSCertIDv2.hashAlgorithm"],
    ),
    _Field("certHash", OCTET_STRING),
    _Field("issuerSerial", _ISSUER_SERIAL, optional=True),
)
_SIGNING_CERTIFICATE_V2 = _Sequence(
    _Field("certs", _SequenceOf(_ESS_CERT_ID_V2)),
    _Field("policies", _SequenceOf(_POLICY_INFORMATION), optional=True),
)

#: The attribute types whose values this profile decodes (by OID content
#: octets). The value of every other attribute type is an open type.
KNOWN_ATTRIBUTES: dict[bytes, _Type] = {
    _oid_content("1.2.840.113549.1.9.3"): OBJECT_IDENTIFIER,  # contentType
    _oid_content("1.2.840.113549.1.9.4"): OCTET_STRING,  # messageDigest
    _oid_content("1.2.840.113549.1.9.16.2.47"): _SIGNING_CERTIFICATE_V2,
}


def _attribute_values(seen: dict[str, bytes]) -> _Type:
    return _set_of(KNOWN_ATTRIBUTES.get(seen["attrType"], ANY))


_ATTRIBUTE = _Sequence(
    _Field("attrType", OBJECT_IDENTIFIER),
    _Field("attrValues", None, selector=_attribute_values),
)

class _SignerIdentifier(_Choice):
    """``SignerIdentifier``; the raw TLV is recorded for locating the signer (1e)."""

    def decode(
        self, data: bytes, position: int, end: int, context: WalkContext
    ) -> tuple[bytes, int]:
        encoded, content_end = super().decode(data, position, end, context)
        context.signer_identifiers.append(data[position:content_end])
        return encoded, content_end


_SIGNER_INFO = _Sequence(
    _Field("version", INTEGER),
    _Field(
        "sid",
        _SignerIdentifier(
            _Sequence(_Field("issuer", _NAME), _Field("serialNumber", INTEGER)),
            _Implicit(_CONTEXT, 0, OCTET_STRING),  # subjectKeyIdentifier
        ),
    ),
    _Field("digestAlgorithm", _SignerAlgorithm(SIGNER_DIGEST_PARAMETERS)),
    _Field("signedAttrs", _Implicit(_CONTEXT, 0, _set_of(_ATTRIBUTE)), optional=True),
    _Field("signatureAlgorithm", _SignerAlgorithm(SIGNER_SIGNATURE_PARAMETERS)),
    _Field("signature", OCTET_STRING),
    _Field("unsignedAttrs", _Implicit(_CONTEXT, 1, _set_of(_ATTRIBUTE)), optional=True),
)
_SIGNED_DATA = _Sequence(
    _Field("version", INTEGER),
    _Field("digestAlgorithms", _set_of(ALGORITHM_IDENTIFIER)),
    _Field(
        "encapContentInfo",
        _Sequence(
            _Field("eContentType", OBJECT_IDENTIFIER),
            _Field("eContent", _Explicit(_CONTEXT, 0, OCTET_STRING), optional=True),
        ),
    ),
    # X7/M3: every CertificateChoices component is an open type here; only the
    # signer certificate is decoded, by 1e (:func:`signer_certificate`).
    _Field("certificates", _Implicit(_CONTEXT, 0, _set_of(_Collected("certificates"))), optional=True),
    _Field("crls", _Implicit(_CONTEXT, 1, _set_of(_REVOCATION_INFO_CHOICE)), optional=True),
    _Field("signerInfos", _set_of(_SIGNER_INFO)),
)
_ID_SIGNED_DATA = _oid_content("1.2.840.113549.1.7.2")


def _content_info_content(seen: dict[str, bytes]) -> _Type:
    # content [0] EXPLICIT ANY DEFINED BY contentType: SignedData is decoded;
    # any other content type is open (check 1d rejects it afterwards).
    if seen["contentType"] == _ID_SIGNED_DATA:
        return _Explicit(_CONTEXT, 0, _SIGNED_DATA)
    return _Explicit(_CONTEXT, 0, ANY)


_CONTENT_INFO = _Sequence(
    _Field("contentType", OBJECT_IDENTIFIER),
    _Field("content", None, selector=_content_info_content),
)

# RFC 3161.
TIME_STAMP_RESP = _Sequence(
    _Field(
        "status",
        _Sequence(
            _Field("status", INTEGER),
            _Field("statusString", _SequenceOf(UTF8_STRING), optional=True),
            _Field("failInfo", NAMED_BIT_STRING, optional=True),
        ),
    ),
    _Field("timeStampToken", _CONTENT_INFO, optional=True),
)
TST_INFO = _Sequence(
    _Field("version", INTEGER),
    _Field("policy", OBJECT_IDENTIFIER),
    _Field(
        "messageImprint",
        _Sequence(
            _Field("hashAlgorithm", ALGORITHM_IDENTIFIER),
            _Field("hashedMessage", OCTET_STRING),
        ),
    ),
    _Field("serialNumber", INTEGER),
    _Field("genTime", GENERALIZED_TIME),
    _Field(
        "accuracy",
        _Sequence(
            _Field("seconds", INTEGER, optional=True),
            _Field("millis", _Implicit(_CONTEXT, 0, INTEGER), optional=True),
            _Field("micros", _Implicit(_CONTEXT, 1, INTEGER), optional=True),
        ),
        optional=True,
    ),
    _Field("ordering", BOOLEAN, default=DEFAULTS["TSTInfo.ordering"]),
    _Field("nonce", INTEGER, optional=True),
    _Field("tsa", _Explicit(_CONTEXT, 0, _GENERAL_NAME), optional=True),
    _Field("extensions", _Implicit(_CONTEXT, 1, _EXTENSIONS), optional=True),
)


def reencode(schema: _Type, data: bytes) -> tuple[bytes, WalkContext]:
    """Decode ``data`` as exactly one value of ``schema``; return its DER re-encoding."""
    context = WalkContext()
    encoded, position = schema.decode(data, 0, len(data), context)
    if position != len(data):
        raise DerViolation("data after the top-level value")
    return encoded, context


# ---------------------------------------------------------------------------
# 1e: locating the signer certificate among the open certificate components
# ---------------------------------------------------------------------------

_ID_SUBJECT_KEY_IDENTIFIER = _oid_content("2.5.29.14")


def _children(data: bytes, start: int, end: int) -> list[tuple[int, int, int, int, int]]:
    """``(class, number, tlv_start, content_start, content_end)`` of each child TLV."""
    out = []
    position = start
    while position < end:
        tag_class, _constructed, number, content_start, content_end = _read_header(
            data, position, end
        )
        out.append((tag_class, number, position, content_start, content_end))
        position = content_end
    return out


def _certificate_identity(certificate: bytes) -> tuple[bytes, bytes, bytes | None]:
    """``(issuer TLV, serial content, subjectKeyIdentifier or None)`` of a certificate.

    Read by position from the raw TLVs (RFC 5280 TBSCertificate); raises
    :class:`DerViolation` when the component does not have that shape.
    """
    outer = _children(certificate, 0, len(certificate))
    if len(outer) != 1 or (outer[0][0], outer[0][1]) != (_UNIVERSAL, 16):
        raise DerViolation("not a certificate")
    certificate_fields = _children(certificate, outer[0][3], outer[0][4])
    if not certificate_fields:
        raise DerViolation("not a certificate")
    tbs = _children(certificate, certificate_fields[0][3], certificate_fields[0][4])
    if tbs and (tbs[0][0], tbs[0][1]) == (_CONTEXT, 0):
        tbs = tbs[1:]  # version
    if len(tbs) < 6:
        raise DerViolation("not a certificate")
    serial = certificate[tbs[0][3] : tbs[0][4]]
    issuer = certificate[tbs[2][2] : tbs[2][4]]
    key_identifier = None
    for tag_class, number, _start, content_start, content_end in tbs[6:]:
        if (tag_class, number) != (_CONTEXT, 3):
            continue
        for extensions in _children(certificate, content_start, content_end)[:1]:
            for extension in _children(certificate, extensions[3], extensions[4]):
                parts = _children(certificate, extension[3], extension[4])
                if parts and certificate[parts[0][3] : parts[0][4]] == _ID_SUBJECT_KEY_IDENTIFIER:
                    value = certificate[parts[-1][3] : parts[-1][4]]
                    inner = _children(value, 0, len(value))
                    if len(inner) == 1 and (inner[0][0], inner[0][1]) == (_UNIVERSAL, 4):
                        key_identifier = value[inner[0][3] : inner[0][4]]
    return issuer, serial, key_identifier


def signer_certificate(context: WalkContext) -> bytes | None:
    """1e: the carried certificate that the (single) SignerInfo's ``sid`` names.

    ``issuerAndSerialNumber`` matches the certificate whose issuer TLV and serial
    number content octets are equal; ``[0] subjectKeyIdentifier`` matches the
    certificate whose subjectKeyIdentifier extension carries the same octets.
    The first matching component wins; a component that does not have the
    shape of a certificate is skipped (it is an open type, X7/M3).
    """
    if not context.signer_identifiers:
        return None
    sid = context.signer_identifiers[0]
    sid_class, _constructed, sid_number, sid_start, sid_end = _read_header(sid, 0, len(sid))
    by_key_identifier = (sid_class, sid_number) == (_CONTEXT, 0)
    if not by_key_identifier:
        parts = _children(sid, sid_start, sid_end)
        wanted_issuer = sid[parts[0][2] : parts[0][4]]
        wanted_serial = sid[parts[1][3] : parts[1][4]]
    for certificate in context.certificates:
        try:
            issuer, serial, key_identifier = _certificate_identity(certificate)
        except (DerViolation, IndexError):
            continue
        if by_key_identifier:
            if key_identifier is not None and key_identifier == sid[sid_start:sid_end]:
                return certificate
        elif issuer == wanted_issuer and serial == wanted_serial:
            return certificate
    return None
