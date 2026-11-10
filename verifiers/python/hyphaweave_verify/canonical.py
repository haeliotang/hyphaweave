# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""WR-CJ v1 — the canonical JSON profile of ``weave-record/1``.

This module implements RFC 8785 (JCS) restricted by decisions C1/C2/C3/C5:

* UTF-8 output, no BOM, no insignificant whitespace, no trailing newline;
* non-ASCII characters are emitted as literal UTF-8; a byte-order mark, invalid
  UTF-8 and lone surrogate escapes are rejected;
* object members are sorted by the UTF-16 code-unit sequence of their names
  (RFC 8785 §3.2.3); no Unicode normalization is performed anywhere;
* duplicate member names are rejected during parsing, at any nesting depth;
* strings use ECMAScript ``JSON.stringify`` escaping exactly (see ``_ESCAPES``);
* numbers must be integers in ``[-(2**53-1), +(2**53-1)]``; floats, exponents,
  ``1.0``, ``-0`` and out-of-range integers are rejected
  (``E_JSON_NUMBER_NOT_INTEGER`` / ``E_JSON_NUMBER_RANGE`` /
  ``E_JSON_NOT_CANONICAL``);
* a canonical *file* is the WR-CJ bytes optionally followed by exactly one LF;
  digests and signatures are always computed over the bytes without that LF.

The serializer is used for signature and digest payloads, so it raises
:class:`~hyphaweave_verify.errors.WeaveError` with a registry code instead of a
bare exception: callers must not accidentally downgrade a canonicalization
failure into a generic error.
"""

from __future__ import annotations

from typing import Any

from .errors import CheckSkipper, NO_SKIP, WeaveError

#: Largest integer magnitude representable exactly as an IEEE-754 double.
MAX_SAFE_INTEGER = 2**53 - 1

#: The ECMAScript ``JSON.stringify`` short escapes.
_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}

_JSON_WHITESPACE = " \t\n\r"


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def _utf16_code_unit_key(name: str) -> bytes:
    """Sort key giving RFC 8785 object-member order.

    UTF-16 big-endian encodes each code unit as two bytes, so lexicographic
    byte comparison of the encodings is exactly the UTF-16 code-unit order the
    profile requires. ``surrogatepass`` keeps the function total for names
    containing lone surrogates; :func:`_emit_string` rejects those with
    ``E_JSON_LONE_SURROGATE`` when the value is emitted.
    """
    return name.encode("utf-16-be", "surrogatepass")


def _emit_string(value: str, chunks: list[str]) -> None:
    chunks.append('"')
    for character in value:
        escaped = _ESCAPES.get(character)
        if escaped is not None:
            chunks.append(escaped)
            continue
        code_point = ord(character)
        if code_point < 0x20:
            chunks.append("\\u%04x" % code_point)
        elif 0xD800 <= code_point <= 0xDFFF:
            raise WeaveError(
                "E_JSON_LONE_SURROGATE",
                "string contains a lone Unicode surrogate U+%04X" % code_point,
            )
        else:
            chunks.append(character)
    chunks.append('"')


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
        _emit_string(value, chunks)
        return
    if isinstance(value, float):
        raise WeaveError(
            "E_JSON_NUMBER_NOT_INTEGER",
            "floating-point numbers are not permitted (integers only): %r" % (value,),
        )
    if isinstance(value, int):
        if value < -MAX_SAFE_INTEGER or value > MAX_SAFE_INTEGER:
            raise WeaveError(
                "E_JSON_NUMBER_RANGE",
                "integer %d is outside [%d, %d]" % (value, -MAX_SAFE_INTEGER, MAX_SAFE_INTEGER),
            )
        chunks.append(str(value))
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
                raise WeaveError("E_JSON_INVALID", "object member names must be strings")
        chunks.append("{")
        for index, key in enumerate(sorted(value, key=_utf16_code_unit_key)):
            if index:
                chunks.append(",")
            _emit_string(key, chunks)
            chunks.append(":")
            _emit(value[key], chunks)
        chunks.append("}")
        return
    raise WeaveError(
        "E_JSON_INVALID",
        "unsupported JSON value type: %s" % type(value).__name__,
    )


def canonicalize(value: Any) -> bytes:
    """Return the WR-CJ v1 UTF-8 bytes of an already parsed JSON value.

    This is the public API used by the repository's cross-check tooling. It
    raises :class:`WeaveError` carrying a registry ``.code`` for values outside
    the profile (floats, out-of-range integers, lone surrogates, non-string
    object member names).
    """
    chunks: list[str] = []
    _emit(value, chunks)
    return "".join(chunks).encode("utf-8")


# Alias used internally where the input came from JSON parsing.
dumps = canonicalize


# ---------------------------------------------------------------------------
# Strict parser
# ---------------------------------------------------------------------------


class _Parser:
    """A strict JSON parser with WR-CJ error attribution.

    Whitespace is *accepted* here (it is legal JSON) so that the canonical-form
    comparison below reports ``E_JSON_NOT_CANONICAL`` for pretty-printed files
    rather than a parse error. Structural JSON violations are
    ``E_JSON_INVALID``; number-profile violations, duplicate members and lone
    surrogate escapes get their own registry codes.
    """

    __slots__ = ("text", "length", "pos", "skipper")

    def __init__(self, text: str, skipper: CheckSkipper) -> None:
        self.text = text
        self.length = len(text)
        self.pos = 0
        self.skipper = skipper

    # -- helpers ----------------------------------------------------------

    def _fail(self, code: str, detail: str) -> None:
        raise WeaveError(code, detail)

    def _peek(self) -> str:
        if self.pos >= self.length:
            self._fail("E_JSON_INVALID", "unexpected end of input")
        return self.text[self.pos]

    def _skip_whitespace(self) -> None:
        text = self.text
        pos = self.pos
        length = self.length
        while pos < length and text[pos] in _JSON_WHITESPACE:
            pos += 1
        self.pos = pos

    def _expect(self, character: str) -> None:
        if self.pos >= self.length or self.text[self.pos] != character:
            self._fail("E_JSON_INVALID", "expected %r" % character)
        self.pos += 1

    # -- entry point ------------------------------------------------------

    def parse(self) -> Any:
        self._skip_whitespace()
        value = self._parse_value()
        self._skip_whitespace()
        if self.pos != self.length:
            self._fail("E_JSON_INVALID", "trailing non-whitespace content")
        return value

    # -- values -----------------------------------------------------------

    def _parse_value(self) -> Any:
        if self.pos >= self.length:
            self._fail("E_JSON_INVALID", "unexpected end of input")
        character = self.text[self.pos]
        if character == "{":
            return self._parse_object()
        if character == "[":
            return self._parse_array()
        if character == '"':
            return self._parse_string()
        if character == "t":
            self._parse_literal("true")
            return True
        if character == "f":
            self._parse_literal("false")
            return False
        if character == "n":
            self._parse_literal("null")
            return None
        if character == "-" or "0" <= character <= "9":
            return self._parse_number()
        if character == "." and self.pos + 1 < self.length and "0" <= self.text[self.pos + 1] <= "9":
            # The registry attributes JSON "float-looking" literals to this code.
            self._fail("E_JSON_NUMBER_NOT_INTEGER", "number literal is not an integer")
        if character == "+" and self.pos + 1 < self.length and "0" <= self.text[self.pos + 1] <= "9":
            self._fail("E_JSON_NUMBER_RANGE", "number literal has a leading '+'")
        self._fail("E_JSON_INVALID", "unexpected character %r" % character)
        raise AssertionError("unreachable")  # pragma: no cover

    def _parse_literal(self, literal: str) -> None:
        end = self.pos + len(literal)
        if self.text[self.pos : end] != literal:
            self._fail("E_JSON_INVALID", "invalid literal")
        self.pos = end

    def _parse_object(self) -> dict[str, Any]:
        self.pos += 1  # '{'
        result: dict[str, Any] = {}
        self._skip_whitespace()
        if self.pos < self.length and self.text[self.pos] == "}":
            self.pos += 1
            return result
        while True:
            self._skip_whitespace()
            if self.pos >= self.length or self.text[self.pos] != '"':
                self._fail("E_JSON_INVALID", "object member name must be a string")
            key = self._parse_string()
            if key in result:
                self._fail("E_JSON_DUPLICATE_KEY", "duplicate object member name")
            self._skip_whitespace()
            self._expect(":")
            self._skip_whitespace()
            result[key] = self._parse_value()
            self._skip_whitespace()
            if self.pos >= self.length:
                self._fail("E_JSON_INVALID", "unterminated object")
            character = self.text[self.pos]
            if character == ",":
                self.pos += 1
                continue
            if character == "}":
                self.pos += 1
                return result
            self._fail("E_JSON_INVALID", "expected ',' or '}' in object")

    def _parse_array(self) -> list[Any]:
        self.pos += 1  # '['
        result: list[Any] = []
        self._skip_whitespace()
        if self.pos < self.length and self.text[self.pos] == "]":
            self.pos += 1
            return result
        while True:
            self._skip_whitespace()
            result.append(self._parse_value())
            self._skip_whitespace()
            if self.pos >= self.length:
                self._fail("E_JSON_INVALID", "unterminated array")
            character = self.text[self.pos]
            if character == ",":
                self.pos += 1
                continue
            if character == "]":
                self.pos += 1
                return result
            self._fail("E_JSON_INVALID", "expected ',' or ']' in array")

    def _parse_string(self) -> str:
        self.pos += 1  # opening quote
        chunks: list[str] = []
        text = self.text
        length = self.length
        pos = self.pos
        while True:
            if pos >= length:
                self.pos = pos
                self._fail("E_JSON_INVALID", "unterminated string")
            character = text[pos]
            if character == '"':
                pos += 1
                self.pos = pos
                return "".join(chunks)
            if character == "\\":
                pos += 1
                if pos >= length:
                    self.pos = pos
                    self._fail("E_JSON_INVALID", "unterminated escape")
                escape = text[pos]
                pos += 1
                if escape == '"':
                    chunks.append('"')
                elif escape == "\\":
                    chunks.append("\\")
                elif escape == "/":
                    chunks.append("/")
                elif escape == "b":
                    chunks.append("\b")
                elif escape == "f":
                    chunks.append("\f")
                elif escape == "n":
                    chunks.append("\n")
                elif escape == "r":
                    chunks.append("\r")
                elif escape == "t":
                    chunks.append("\t")
                elif escape == "u":
                    self.pos = pos
                    code_point = self._parse_hex4()
                    pos = self.pos
                    if 0xD800 <= code_point <= 0xDBFF:
                        if text[pos : pos + 2] != "\\u":
                            self._fail("E_JSON_LONE_SURROGATE", "high surrogate escape is not followed by a low surrogate")
                        self.pos = pos + 2
                        low = self._parse_hex4()
                        if not 0xDC00 <= low <= 0xDFFF:
                            self._fail("E_JSON_LONE_SURROGATE", "high surrogate escape is not followed by a low surrogate")
                        pos = self.pos
                        chunks.append(chr(0x10000 + ((code_point - 0xD800) << 10) + (low - 0xDC00)))
                    elif 0xDC00 <= code_point <= 0xDFFF:
                        self._fail("E_JSON_LONE_SURROGATE", "lone low surrogate escape")
                    else:
                        chunks.append(chr(code_point))
                else:
                    self.pos = pos
                    self._fail("E_JSON_INVALID", "invalid escape sequence")
                continue
            if character < "\x20":
                self.pos = pos
                self._fail("E_JSON_INVALID", "unescaped control character in string")
            # Raw text is already valid UTF-8-decoded text; surrogate code
            # points cannot appear here because the UTF-8 decode rejects the
            # surrogate byte sequences.
            chunks.append(character)
            pos += 1

    def _parse_hex4(self) -> int:
        end = self.pos + 4
        if end > self.length:
            self._fail("E_JSON_INVALID", "truncated \\u escape")
        digits = self.text[self.pos : end]
        try:
            value = int(digits, 16)
        except ValueError:
            self._fail("E_JSON_INVALID", "invalid \\u escape")
            raise AssertionError("unreachable")  # pragma: no cover
        if any(character not in "0123456789abcdefABCDEF" for character in digits):
            self._fail("E_JSON_INVALID", "invalid \\u escape")
        self.pos = end
        return value

    def _parse_number(self) -> int:
        text = self.text
        length = self.length
        start = self.pos
        pos = start
        if text[pos] == "-":
            pos += 1
            if pos >= length:
                self.pos = pos
                self._fail("E_JSON_INVALID", "truncated number")
        character = text[pos]
        if character == "0":
            pos += 1
            if pos < length and "0" <= text[pos] <= "9":
                self.pos = pos
                self._fail("E_JSON_NUMBER_RANGE", "integer literal has a leading zero")
        elif "1" <= character <= "9":
            pos += 1
            while pos < length and "0" <= text[pos] <= "9":
                pos += 1
        else:
            self.pos = pos
            self._fail("E_JSON_INVALID", "invalid number")
            raise AssertionError("unreachable")  # pragma: no cover
        if pos < length and text[pos] == ".":
            self.pos = pos
            self._fail("E_JSON_NUMBER_NOT_INTEGER", "number literal has a fraction")
        if pos < length and text[pos] in "eE":
            self.pos = pos
            self._fail("E_JSON_NUMBER_NOT_INTEGER", "number literal has an exponent")
        self.pos = pos
        value = int(text[start:pos])
        if value < -MAX_SAFE_INTEGER or value > MAX_SAFE_INTEGER:
            self._fail("E_JSON_NUMBER_RANGE", "integer outside the safe range")
        return value


def parse_text(text: str, *, require_object: bool = False, skipper: CheckSkipper = NO_SKIP) -> Any:
    """Parse ``text`` strictly and return the value.

    Trailing non-whitespace content is ``E_JSON_INVALID``. This function does
    not perform the canonical-file byte comparison; use :func:`parse_file_bytes`
    for files that are digested or signed.
    """
    value = _Parser(text, skipper).parse()
    if require_object and not isinstance(value, dict):
        raise WeaveError("E_JSON_INVALID", "top-level JSON value must be an object")
    return value


def parse_file_bytes(
    data: bytes,
    *,
    max_bytes: int | None = None,
    require_object: bool = False,
    size_code: str = "E_JSON_SIZE",
    skipper: CheckSkipper = NO_SKIP,
) -> Any:
    """Parse a canonical JSON *file* and return its value.

    Enforces the canonical-form rule of CONTRACT §2.8: the file must be exactly
    the WR-CJ bytes of its value, optionally followed by one LF. Size limits are
    enforced first (``E_JSON_SIZE`` by default).
    """
    if max_bytes is not None and len(data) > max_bytes:
        raise WeaveError(size_code, "file exceeds the size limit")
    if data.startswith(b"\xef\xbb\xbf"):
        raise WeaveError("E_JSON_INVALID", "byte-order mark is not permitted")
    body = data
    if body.endswith(b"\n"):
        body = body[:-1]
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WeaveError("E_JSON_INVALID", "input is not valid UTF-8") from exc
    value = parse_text(text, require_object=require_object, skipper=skipper)
    if canonicalize(value) != body:
        raise WeaveError(
            "E_JSON_NOT_CANONICAL",
            "file bytes are not the canonical serialization of the parsed value",
        )
    return value


def canonical_file_bytes(value: Any) -> bytes:
    """Return the bytes a canonical JSON file may contain (without the LF)."""
    return canonicalize(value)
