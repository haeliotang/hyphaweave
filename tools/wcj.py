#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""WR-CJ v1 canonical JSON and the strict canonical-bytes parser.

This is the *independent* canonicalization implementation used by the vector
generators (``tools/make_keys.py``, ``tools/gen_vectors.py``).  It is written
from the specification text only and deliberately does not import
``hyphaweave_verify``: the conformance vectors must not be produced by the
reference verifier.

WR-CJ v1 (see the normative spec, `spec/weave-record-1.md` §1):

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

``parse_strict`` is the only supported way to read a canonical JSON file; it
raises :class:`WcjError` carrying the H0 error code so that negative vector
cases can assert the exact expected class.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

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

# WR-CJ v1 §2.6: integers must be exactly representable as IEEE-754 doubles.
MAX_INT = (1 << 53) - 1
MIN_INT = -((1 << 53) - 1)

_MAX_RECORD_BYTES = 1_048_576  # MAX_RECORD_BYTES, spec §13

_STRING_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}


class WcjError(ValueError):
    """A JSON document cannot be represented or parsed under WR-CJ v1."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__("%s: %s" % (code, message))
        self.code = code
        self.message = message


def _utf16_sort_key(name: str) -> bytes:
    """UTF-16 big-endian encoding of a member name, for byte-order sorting."""
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


def parse_strict(
    data: bytes,
    *,
    max_bytes: int | None = _MAX_RECORD_BYTES,
    require_canonical: bool = True,
    allow_trailing_lf: bool = True,
) -> Any:
    """Parse canonical JSON file bytes under the WR-CJ v1 rules.

    Raises :class:`WcjError` with the H0 error code of the first violated
    rule: duplicate member names, lone surrogates, non-integer/out-of-range
    numbers, invalid UTF-8/JSON, and (when *require_canonical*) any deviation
    from the canonical-form rule of §2.8.
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

    def _pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for name, value in pairs:
            if name in result:
                raise WcjError(
                    "E_JSON_DUPLICATE_KEY", "duplicate object member %r" % (name,)
                )
            result[name] = value
        return result

    def _reject_constant(token: str) -> Any:
        raise WcjError("E_JSON_INVALID", "non-JSON constant %r" % token)

    def _reject_float(token: str) -> Any:
        raise WcjError(
            "E_JSON_NUMBER_NOT_INTEGER",
            "number %r is not an integer (integers only, WR-CJ §2.6)" % token,
        )

    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs_hook,
            parse_constant=_reject_constant,
            parse_float=_reject_float,
        )
    except WcjError:
        raise
    except json.JSONDecodeError as exc:
        raise WcjError("E_JSON_INVALID", "invalid JSON: %s" % exc) from exc

    _validate_parsed(value)

    if require_canonical:
        candidate = data[: -1] if (allow_trailing_lf and data.endswith(b"\n")) else data
        expected = canonicalize(value)
        if candidate != expected:
            raise WcjError(
                "E_JSON_NOT_CANONICAL",
                "file bytes are not the canonical form of the value",
            )
    return value


def _validate_parsed(value: Any) -> None:
    """Reject ranges/surrogates that the JSON parser let through."""
    stack: list[Any] = [value]
    while stack:
        item = stack.pop()
        if item is None or item is True or item is False:
            continue
        if isinstance(item, str):
            for character in item:
                if 0xD800 <= ord(character) <= 0xDFFF:
                    raise WcjError(
                        "E_JSON_LONE_SURROGATE",
                        "string contains lone surrogate U+%04X" % ord(character),
                    )
            continue
        if isinstance(item, int):
            _render_integer(item)
            continue
        if isinstance(item, list):
            stack.extend(item)
            continue
        if isinstance(item, dict):
            for name, member in item.items():
                stack.append(name)
                stack.append(member)
            continue
        raise WcjError(
            "E_JSON_INVALID", "unexpected parsed value type %s" % type(item).__name__
        )


def parse_batch(data: bytes, *, max_bytes: int | None = None) -> Any:
    """Convenience alias used by helper scripts."""
    return parse_strict(data, max_bytes=max_bytes)


def canonical_join(values: Iterable[Any]) -> list[str]:
    """Return canonical strings for each value (helper for digests)."""
    return [canonicalize_text(value) for value in values]
