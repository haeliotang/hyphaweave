# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Small deterministic grammar checks shared by the envelope and kind validators.

Kept separate from :mod:`hyphaweave_verify.envelope` so that kind body validators
can use the same primitives without a circular import. Nothing here depends on
the clock, the network, the environment or the filesystem.
"""

from __future__ import annotations

import re

PROJECT_SLUG_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
MODEL_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*"
    r"@[A-Za-z0-9][A-Za-z0-9._+-]*$"
)
HINT_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s]+$")

MAX_ORIGIN_PROJECT_BYTES = 64
MAX_ID_SCALARS = 256
MAX_HINT_BYTES = 2048
MAX_REFS = 256
MAX_HINTS = 8
MAX_SIGS = 16
MAX_SALT_BYTES = 16

#: Closed ``rel`` vocabulary (Q7: the eight Inceptless relations plus
#: ``supersedes`` and ``correction_of``; erasure/revocation use body references).
RELS = (
    "derived_from",
    "handed_off_to",
    "receipt_of",
    "executed_as",
    "assessed_by",
    "compensated_by",
    "migrated_from",
    "reshaped_from",
    "supersedes",
    "correction_of",
)

#: Relations that propagate labels (M/L: all derivation relations).
DERIVATION_RELS = frozenset(
    {"derived_from", "reshaped_from", "migrated_from", "correction_of"}
)

#: Algorithm-name grammar used by ``sigs[].alg`` (spec §4.3 / Q13).
ALGORITHM_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
ALGORITHM_MAX_BYTES = 32

#: Generic key-id shape for signatures whose algorithm is not ed25519.
GENERIC_KEY_ID_PATTERN = re.compile(
    r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*:[0-9a-f]{1,128}$"
)


def is_algorithm_name(value: object) -> bool:
    """Whether ``value`` is a well-formed signature algorithm name."""
    if not isinstance(value, str):
        return False
    if len(value.encode("utf-8")) > ALGORITHM_MAX_BYTES:
        return False
    return ALGORITHM_PATTERN.match(value) is not None


def is_generic_key_id(value: object) -> bool:
    """The ``<alg>:<lowercase hex>`` key-id shape for non-ed25519 algorithms."""
    return isinstance(value, str) and GENERIC_KEY_ID_PATTERN.match(value) is not None


def is_valid_project_slug(value: object) -> bool:
    """A project slug: lowercase hyphen-separated words, at most 64 bytes."""
    if not isinstance(value, str):
        return False
    if len(value.encode("utf-8")) > MAX_ORIGIN_PROJECT_BYTES:
        return False
    return PROJECT_SLUG_PATTERN.match(value) is not None


def has_control_characters(value: str) -> bool:
    """C0, DEL and C1 control characters, as excluded by the id grammar."""
    for character in value:
        code_point = ord(character)
        if code_point < 0x20 or code_point == 0x7F or 0x80 <= code_point <= 0x9F:
            return True
    return False


def is_valid_id(value: object) -> bool:
    """Envelope/ref id: 1-256 Unicode scalar values, no control chars, no edge spaces."""
    if not isinstance(value, str) or not value:
        return False
    if len(value) > MAX_ID_SCALARS:
        return False
    if value.startswith(" ") or value.endswith(" "):
        return False
    return not has_control_characters(value)


def is_valid_model(value: object) -> bool:
    """The ``provider/model@version`` grammar for agent models (ASCII, 1-256 bytes)."""
    if not isinstance(value, str):
        return False
    if not 1 <= len(value.encode("utf-8")) <= 256:
        return False
    return MODEL_PATTERN.match(value) is not None


def is_valid_scope_string(value: object) -> bool:
    """A grant/consent scope item: 1-256 Unicode scalar values."""
    return isinstance(value, str) and 1 <= len(value) <= 256


def is_valid_text(value: object, minimum: int, maximum: int) -> bool:
    """A free-form string with a Unicode scalar-value length bound."""
    return isinstance(value, str) and minimum <= len(value) <= maximum


def is_valid_hint(value: object) -> bool:
    """A hint URI string: scheme-prefixed, no whitespace, at most 2048 UTF-8 bytes."""
    if not isinstance(value, str):
        return False
    if len(value.encode("utf-8")) > MAX_HINT_BYTES:
        return False
    return HINT_PATTERN.match(value) is not None


# ---------------------------------------------------------------------------
# SPDX licence expression syntax (spec §8.7)
# ---------------------------------------------------------------------------


def _tokenize_spdx(value: str) -> list[str] | None:
    tokens: list[str] = []
    index = 0
    length = len(value)
    while index < length:
        character = value[index]
        if character.isspace():
            index += 1
            continue
        if character in "()":
            tokens.append(character)
            index += 1
            continue
        start = index
        while index < length and not value[index].isspace() and value[index] not in "()":
            index += 1
        token = value[start:index]
        for token_character in token:
            if not (
                "A" <= token_character <= "Z"
                or "a" <= token_character <= "z"
                or "0" <= token_character <= "9"
                or token_character in ".+-"
            ):
                return None
        tokens.append(token)
    return tokens


def _spdx_is_identifier(token: str) -> bool:
    return token not in ("AND", "OR", "WITH")


def _parse_spdx_simple(tokens: list[str], index: int) -> int:
    token = tokens[index]
    if token == "(":
        index = _parse_spdx_or(tokens, index + 1)
        if index >= len(tokens) or tokens[index] != ")":
            raise ValueError("unbalanced parentheses")
        return index + 1
    if not _spdx_is_identifier(token):
        raise ValueError("expected an identifier")
    index += 1
    if index < len(tokens) and tokens[index] == "WITH":
        if index + 1 >= len(tokens) or not _spdx_is_identifier(tokens[index + 1]):
            raise ValueError("WITH must be followed by an exception identifier")
        index += 2
    return index


def _parse_spdx_and(tokens: list[str], index: int) -> int:
    index = _parse_spdx_simple(tokens, index)
    while index < len(tokens) and tokens[index] == "AND":
        index = _parse_spdx_simple(tokens, index + 1)
    return index


def _parse_spdx_or(tokens: list[str], index: int) -> int:
    index = _parse_spdx_and(tokens, index)
    while index < len(tokens) and tokens[index] == "OR":
        index = _parse_spdx_and(tokens, index + 1)
    return index


def is_valid_spdx_expression(value: object) -> bool:
    """Syntax-only SPDX expression check (membership is never checked, Q14)."""
    if not isinstance(value, str) or not value.strip():
        return False
    tokens = _tokenize_spdx(value)
    if tokens is None:
        return False
    try:
        index = _parse_spdx_or(tokens, 0)
    except (ValueError, IndexError):
        return False
    return index == len(tokens)
