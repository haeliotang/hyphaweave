#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""WR-CJ v1 canonical JSON and the strict canonical-bytes parser.

This is the *independent* canonicalization implementation used by the vector
generators (``tools/make_keys.py``, ``tools/gen_vectors.py``).  It is written
from the specification text only and deliberately does not import
``hyphaweave_verify``: the conformance vectors must not be produced by the
reference verifier.

WR-CJ v1:

* UTF-8 output, no BOM, no insignificant whitespace, no trailing newline;
* object members sorted by the UTF-16 code-unit sequence of their names;
* ECMAScript ``JSON.stringify`` escaping (``\\" \\\\ \\b \\t \\n \\f \\r``,
  other U+0000-U+001F as lowercase ``\\u00xx``, everything else literal
  UTF-8); U+007F, U+2028 and U+2029 are emitted literally;
* integers only, in ``[-(2**53-1), +(2**53-1)]``; no floats, no exponents,
  no ``-0``; zero is serialized as ``0``;
* duplicate object member names are a parse error;
* lone surrogate escapes are a parse error;
* a *file* that this format digests or signs must contain exactly the WR-CJ
  bytes of its value, optionally followed by exactly one LF; digests and
  signatures are computed over the canonical bytes without that LF.

The parser is a hand-written **single-pass** recursive-descent parser: it
reports the first violation in input byte order, as required for the JCS
error-code rules (for example ``{"a":1,"a":1.5}`` reports the duplicate key,
while ``{"a":1.5,"a":1}`` reports the float).  ``+1``, ``01`` and ``.5`` are
not JSON grammar and report ``E_JSON_INVALID``; a well-formed float/exponent
reports ``E_JSON_NUMBER_NOT_INTEGER``; a well-formed out-of-range integer
reports ``E_JSON_NUMBER_RANGE``; ``-0`` is valid JSON but non-canonical.
"""

from __future__ import annotations

import hashlib
from typing import Any

__all__ = [
    "MAX_INT",
    "MIN_INT",
    "WcjError",
    "canonical_sha256",
    "canonicalize",
    "canonicalize_text",
    "dump_canonical_file",
    "parse_strict",
    "sha256_digest",
]

# WR-CJ v1: integers must be exactly representable as IEEE-754 doubles.
MAX_INT = (1 << 53) - 1
MIN_INT = -((1 << 53) - 1)

_MAX_RECORD_BYTES = 1_048_576

_STRING_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}

_ESCAPE_VALUES = {
    '"': '"',
    "\\": "\\",
    "/": "/",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
}

_JSON_WHITESPACE = " \t\n\r"
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_DIGITS = frozenset("0123456789")


class WcjError(ValueError):
    """A JSON document cannot be represented or parsed under WR-CJ v1."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__("%s: %s" % (code, message))
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def _utf16_sort_key(name: str) -> bytes:
    return name.encode("utf-16-be", "surrogatepass")


def _escape_string(value: str) -> str:
    chunks = ['"']
    for character in value:
        escaped = _STRING_ESCAPES.get(character)
        if escaped is not None:
            chunks.append(escaped)
            continue
        code_point = ord(character)
        if code_point < 0x20:
            chunks.append("\\u%04x" % code_point)
        elif 0xD800 <= code_point <= 0xDFFF:
            raise WcjError(
                "E_JSON_LONE_SURROGATE",
                "string contains lone surrogate U+%04X" % code_point,
            )
        else:
            chunks.append(character)
    chunks.append('"')
    return "".join(chunks)


def _render_integer(value: int) -> str:
    if value < MIN_INT or value > MAX_INT:
        raise WcjError(
            "E_JSON_NUMBER_RANGE",
            "integer %d outside WR-CJ range [%d, %d]" % (value, MIN_INT, MAX_INT),
        )
    return str(value)


def _emit(value: Any, chunks: list[str]) -> None:
    if value is None:
        chunks.append("null")
        return
    if value is True:
        chunks.append("true")
        return
    if value is False:
        chunks.append("false")
        return
    if isinstance(value, str):
        chunks.append(_escape_string(value))
        return
    if isinstance(value, float):
        raise WcjError(
            "E_JSON_NUMBER_NOT_INTEGER",
            "floating-point numbers are not representable in WR-CJ v1",
        )
    if isinstance(value, int):
        chunks.append(_render_integer(value))
        return
    if isinstance(value, list):
        chunks.append("[")
        for index, item in enumerate(value):
            if index:
                chunks.append(",")
            _emit(item, chunks)
        chunks.append("]")
        return
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise WcjError(
                    "E_JSON_NOT_CANONICAL",
                    "object member names must be strings, got %s"
                    % type(key).__name__,
                )
        chunks.append("{")
        for index, key in enumerate(sorted(value, key=_utf16_sort_key)):
            if index:
                chunks.append(",")
            chunks.append(_escape_string(key))
            chunks.append(":")
            _emit(value[key], chunks)
        chunks.append("}")
        return
    raise WcjError(
        "E_JSON_NOT_CANONICAL",
        "unsupported JSON value type: %s" % type(value).__name__,
    )


def canonicalize_text(value: Any) -> str:
    """Return the WR-CJ v1 canonical string for a JSON value."""
    chunks: list[str] = []
    _emit(value, chunks)
    return "".join(chunks)


def canonicalize(value: Any) -> bytes:
    """Return the WR-CJ v1 canonical UTF-8 bytes for a JSON value."""
    return canonicalize_text(value).encode("utf-8")


def sha256_digest(data: bytes) -> str:
    """Return ``sha256:<lowercase hex>`` for arbitrary bytes."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical_sha256(value: Any) -> str:
    """Return the ``sha256:<hex>`` digest of the canonical bytes of *value*."""
    return sha256_digest(canonicalize(value))


def dump_canonical_file(value: Any, trailing_lf: bool = True) -> bytes:
    """Serialize a value as canonical file bytes (canonical bytes + one LF)."""
    data = canonicalize(value)
    return data + b"\n" if trailing_lf else data


# ---------------------------------------------------------------------------
# Single-pass strict parser
# ---------------------------------------------------------------------------


class _Parser:
    """Recursive-descent JSON parser with WR-CJ error classification."""

    __slots__ = ("text", "length", "position")

    def __init__(self, text: str) -> None:
        self.text = text
        self.length = len(text)
        self.position = 0

    # -- low-level helpers -------------------------------------------------

    def _error(self, code: str, message: str) -> WcjError:
        return WcjError(code, message)

    def _skip_whitespace(self) -> None:
        text = self.text
        length = self.length
        position = self.position
        while position < length and text[position] in _JSON_WHITESPACE:
            position += 1
        self.position = position

    def _peek(self) -> str:
        return self.text[self.position] if self.position < self.length else ""

    def _expect(self, character: str) -> None:
        if self._peek() != character:
            raise self._error(
                "E_JSON_INVALID",
                "expected %r at offset %d" % (character, self.position),
            )
        self.position += 1

    # -- grammar -----------------------------------------------------------

    def parse(self) -> Any:
        self._skip_whitespace()
        if self.position >= self.length:
            raise self._error("E_JSON_INVALID", "empty input")
        value = self._parse_value()
        self._skip_whitespace()
        if self.position != self.length:
            raise self._error(
                "E_JSON_INVALID",
                "trailing content at offset %d" % self.position,
            )
        return value

    def _parse_value(self) -> Any:
        character = self._peek()
        if character == "{":
            return self._parse_object()
        if character == "[":
            return self._parse_array()
        if character == '"':
            return self._parse_string()
        if character == "-" or character in _DIGITS:
            return self._parse_number()
        if character == "t":
            self._expect_literal("true")
            return True
        if character == "f":
            self._expect_literal("false")
            return False
        if character == "n":
            self._expect_literal("null")
            return None
        raise self._error(
            "E_JSON_INVALID", "unexpected value at offset %d" % self.position
        )

    def _expect_literal(self, literal: str) -> None:
        end = self.position + len(literal)
        if self.text[self.position : end] != literal:
            raise self._error(
                "E_JSON_INVALID", "invalid literal at offset %d" % self.position
            )
        self.position = end

    def _parse_object(self) -> dict[str, Any]:
        self._expect("{")
        members: dict[str, Any] = {}
        self._skip_whitespace()
        if self._peek() == "}":
            self.position += 1
            return members
        while True:
            self._skip_whitespace()
            if self._peek() != '"':
                raise self._error(
                    "E_JSON_INVALID",
                    "object member name must be a string at offset %d" % self.position,
                )
            name = self._parse_string()
            # Duplicate detection happens as soon as the name is read, i.e.
            # before the value token, so the reported code follows byte order.
            if name in members:
                raise self._error(
                    "E_JSON_DUPLICATE_KEY", "duplicate object member %r" % (name,)
                )
            self._skip_whitespace()
            self._expect(":")
            self._skip_whitespace()
            members[name] = self._parse_value()
            self._skip_whitespace()
            character = self._peek()
            if character == ",":
                self.position += 1
                continue
            if character == "}":
                self.position += 1
                return members
            raise self._error(
                "E_JSON_INVALID",
                "expected ',' or '}' at offset %d" % self.position,
            )

    def _parse_array(self) -> list[Any]:
        self._expect("[")
        items: list[Any] = []
        self._skip_whitespace()
        if self._peek() == "]":
            self.position += 1
            return items
        while True:
            self._skip_whitespace()
            items.append(self._parse_value())
            self._skip_whitespace()
            character = self._peek()
            if character == ",":
                self.position += 1
                continue
            if character == "]":
                self.position += 1
                return items
            raise self._error(
                "E_JSON_INVALID",
                "expected ',' or ']' at offset %d" % self.position,
            )

    def _parse_string(self) -> str:
        self._expect('"')
        text = self.text
        length = self.length
        position = self.position
        chunks: list[str] = []
        while True:
            if position >= length:
                raise self._error("E_JSON_INVALID", "unterminated string")
            character = text[position]
            if character == '"':
                self.position = position + 1
                return "".join(chunks)
            if character == "\\":
                position += 1
                if position >= length:
                    raise self._error("E_JSON_INVALID", "unterminated escape")
                escape = text[position]
                if escape in _ESCAPE_VALUES:
                    chunks.append(_ESCAPE_VALUES[escape])
                    position += 1
                    continue
                if escape != "u":
                    raise self._error(
                        "E_JSON_INVALID",
                        "invalid escape \\%s at offset %d" % (escape, position - 1),
                    )
                if position + 4 >= length:
                    raise self._error("E_JSON_INVALID", "truncated \\u escape")
                hex_digits = text[position + 1 : position + 5]
                if any(digit not in _HEX_DIGITS for digit in hex_digits):
                    raise self._error(
                        "E_JSON_INVALID",
                        "invalid \\u escape at offset %d" % (position - 1),
                    )
                code_point = int(hex_digits, 16)
                position += 5
                if 0xD800 <= code_point <= 0xDBFF:
                    # A high surrogate must be followed by a low surrogate
                    # escape; anything else is a lone surrogate.
                    if (
                        position + 1 < length
                        and text[position] == "\\"
                        and text[position + 1] == "u"
                    ):
                        if position + 5 >= length:
                            raise self._error(
                                "E_JSON_INVALID", "truncated surrogate pair"
                            )
                        low_digits = text[position + 2 : position + 6]
                        if any(digit not in _HEX_DIGITS for digit in low_digits):
                            raise self._error(
                                "E_JSON_INVALID",
                                "invalid surrogate pair escape at offset %d" % position,
                            )
                        low = int(low_digits, 16)
                        if 0xDC00 <= low <= 0xDFFF:
                            combined = (
                                0x10000
                                + ((code_point - 0xD800) << 10)
                                + (low - 0xDC00)
                            )
                            chunks.append(chr(combined))
                            position += 6
                            continue
                    raise self._error(
                        "E_JSON_LONE_SURROGATE",
                        "lone high surrogate escape at offset %d" % (position - 5),
                    )
                if 0xDC00 <= code_point <= 0xDFFF:
                    raise self._error(
                        "E_JSON_LONE_SURROGATE",
                        "lone low surrogate escape at offset %d" % (position - 5),
                    )
                chunks.append(chr(code_point))
                continue
            if character < " ":
                raise self._error(
                    "E_JSON_INVALID",
                    "unescaped control character U+%04X in string"
                    % ord(character),
                )
            chunks.append(character)
            position += 1

    def _parse_number(self) -> int:
        text = self.text
        length = self.length
        start = self.position
        position = start
        if text[position] == "-":
            position += 1
            if position >= length or text[position] not in _DIGITS:
                raise self._error(
                    "E_JSON_INVALID", "invalid number at offset %d" % start
                )
        if text[position] == "0":
            position += 1
            if position < length and text[position] in _DIGITS:
                # "01" is not JSON (a leading zero is not permitted there).
                raise self._error(
                    "E_JSON_INVALID", "number with leading zero at offset %d" % start
                )
        else:
            while position < length and text[position] in _DIGITS:
                position += 1
        is_fractional = False
        if position < length and text[position] == ".":
            is_fractional = True
            position += 1
            if position >= length or text[position] not in _DIGITS:
                raise self._error(
                    "E_JSON_INVALID", "invalid fraction at offset %d" % start
                )
            while position < length and text[position] in _DIGITS:
                position += 1
        if position < length and text[position] in "eE":
            is_fractional = True
            position += 1
            if position < length and text[position] in "+-":
                position += 1
            if position >= length or text[position] not in _DIGITS:
                raise self._error(
                    "E_JSON_INVALID", "invalid exponent at offset %d" % start
                )
            while position < length and text[position] in _DIGITS:
                position += 1
        self.position = position
        token = text[start:position]
        if is_fractional:
            raise self._error(
                "E_JSON_NUMBER_NOT_INTEGER",
                "number %r is not an integer (integers only)" % token,
            )
        value = int(token)
        if value < MIN_INT or value > MAX_INT:
            raise self._error(
                "E_JSON_NUMBER_RANGE",
                "integer %s outside WR-CJ range [%d, %d]" % (token, MIN_INT, MAX_INT),
            )
        return value


def parse_strict(
    data: bytes,
    *,
    max_bytes: int | None = _MAX_RECORD_BYTES,
    require_canonical: bool = True,
    allow_trailing_lf: bool = True,
) -> Any:
    """Parse canonical JSON file bytes under the WR-CJ v1 rules.

    Raises :class:`WcjError` with the H0 error code of the *first* violation in
    input byte order: duplicate member names, lone surrogates, invalid JSON
    syntax, floats/exponents, out-of-range integers, and (when
    *require_canonical*) any deviation from the canonical-form rule.
    """
    if max_bytes is not None and len(data) > max_bytes:
        raise WcjError(
            "E_JSON_SIZE",
            "document is %d bytes (limit %d)" % (len(data), max_bytes),
        )
    if data.startswith(b"\xef\xbb\xbf"):
        raise WcjError("E_JSON_INVALID", "byte-order mark is not permitted")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WcjError("E_JSON_INVALID", "input is not valid UTF-8: %s" % exc) from exc
    value = _Parser(text).parse()
    if require_canonical:
        candidate = data[: -1] if (allow_trailing_lf and data.endswith(b"\n")) else data
        expected = canonicalize(value)
        if candidate != expected:
            raise WcjError(
                "E_JSON_NOT_CANONICAL",
                "file bytes are not the canonical form of the value",
            )
    return value
