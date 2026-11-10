# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""WR-CJ v1: serialization order, escaping, number rules and file canonicality."""

from __future__ import annotations

import pytest

from hyphaweave_verify import canonical
from hyphaweave_verify.errors import WeaveError


def test_serialize_basic_shapes() -> None:
    assert canonical.canonicalize({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
    assert canonical.canonicalize([True, False, None]) == b"[true,false,null]"
    assert canonical.canonicalize("plain") == b'"plain"'
    assert canonical.canonicalize(0) == b"0"
    assert canonical.canonicalize(-1) == b"-1"


def test_member_order_is_utf16_code_unit_order() -> None:
    # Astral-plane key U+10000 is UTF-16 D800 DC00; it sorts before U+E000
    # (UTF-16 E000) even though its scalar value is larger.
    value = {"\ue000": 2, "\U00010000": 1}
    assert canonical.canonicalize(value) == '{"\U00010000":1,"\ue000":2}'.encode("utf-8")
    # BMP ordering: shorter prefix before longer key.
    assert canonical.canonicalize({"ab": 2, "a": 1}) == b'{"a":1,"ab":2}'
    # Printable ASCII is identical in UTF-16 and code-point order.
    assert canonical.canonicalize({"Z": 1, "a": 2, "_": 3}) == b'{"Z":1,"_":3,"a":2}'


def test_string_escaping_matches_ecmascript() -> None:
    assert canonical.canonicalize('"\\') == b'"\\"\\\\"'
    assert canonical.canonicalize("\b\t\n\f\r") == b'"\\b\\t\\n\\f\\r"'
    assert canonical.canonicalize("\x00\x01\x1f") == b'"\\u0000\\u0001\\u001f"'
    # Lowercase hex, no uppercase escapes, slash not escaped.
    assert canonical.canonicalize("\x0b") == b'"\\u000b"'
    assert canonical.canonicalize("/") == b'"/"'
    # Non-ASCII is literal UTF-8, and DEL is not escaped.
    assert canonical.canonicalize("é\u20ac\x7f") == '"é\u20ac\x7f"'.encode("utf-8")


def test_non_ascii_roundtrip() -> None:
    value = {"key": "café \u20ac \U0001f600"}
    assert canonical.parse_text(canonical.canonicalize(value).decode("utf-8")) == value


def test_lone_surrogate_rejected_on_serialize() -> None:
    with pytest.raises(WeaveError) as raised:
        canonical.canonicalize("bad\ud800")
    assert raised.value.code == "E_JSON_LONE_SURROGATE"


def test_number_rules_on_serialize() -> None:
    with pytest.raises(WeaveError) as raised:
        canonical.canonicalize(1.5)
    assert raised.value.code == "E_JSON_NUMBER_NOT_INTEGER"
    with pytest.raises(WeaveError) as raised:
        canonical.canonicalize(2**53)
    assert raised.value.code == "E_JSON_NUMBER_RANGE"
    with pytest.raises(WeaveError):
        canonical.canonicalize(-(2**53))
    # The inclusive bounds are accepted.
    assert canonical.canonicalize(2**53 - 1) == str(2**53 - 1).encode()
    assert canonical.canonicalize(-(2**53 - 1)) == str(-(2**53 - 1)).encode()
    # Booleans are never rendered as integers.
    assert canonical.canonicalize(True) == b"true"


@pytest.mark.parametrize(
    ("payload", "code"),
    [
        (b"", "E_JSON_INVALID"),
        (b"   ", "E_JSON_INVALID"),
        (b"\xef\xbb\xbf{}", "E_JSON_INVALID"),
        (b'{"a":1} {"b":2}', "E_JSON_INVALID"),
        (b'{"a":1,}', "E_JSON_INVALID"),
        (b'{"a":}', "E_JSON_INVALID"),
        (b'[1,2', "E_JSON_INVALID"),
        (b'"\\x"', "E_JSON_INVALID"),
        (b"not json", "E_JSON_INVALID"),
        (b"\xff\xfe", "E_JSON_INVALID"),
        (b'{"a":1,"a":2}', "E_JSON_DUPLICATE_KEY"),
        (b'{"a":{"b":1,"b":2}}', "E_JSON_DUPLICATE_KEY"),
        (b'{"a":1.0}', "E_JSON_NUMBER_NOT_INTEGER"),
        (b'{"a":1e3}', "E_JSON_NUMBER_NOT_INTEGER"),
        (b'{"a":.5}', "E_JSON_NUMBER_NOT_INTEGER"),
        (b'{"a":9007199254740992}', "E_JSON_NUMBER_RANGE"),
        (b'{"a":01}', "E_JSON_NUMBER_RANGE"),
        (b'{"a":+1}', "E_JSON_NUMBER_RANGE"),
        (b'{"a":"\\ud800"}', "E_JSON_LONE_SURROGATE"),
        (b'{"a":"\\udc00"}', "E_JSON_LONE_SURROGATE"),
    ],
)
def test_parse_rejects_with_expected_code(payload: bytes, code: str) -> None:
    with pytest.raises(WeaveError) as raised:
        canonical.parse_file_bytes(payload, require_object=True)
    assert raised.value.code == code


def test_minus_zero_is_not_canonical() -> None:
    with pytest.raises(WeaveError) as raised:
        canonical.parse_file_bytes(b'{"a":-0}')
    assert raised.value.code == "E_JSON_NOT_CANONICAL"


@pytest.mark.parametrize(
    "payload",
    [
        b'{"b":1,"a":2}',  # wrong member order
        b'{ "a" : 1 }',  # insignificant whitespace
        b'{"a":"\\u0061"}',  # non-canonical escape choice
        b'{"a":"\\/"}',  # escaped slash
        b'{"a":1}\r\n',  # CR
        b'{"a":1}\n\n',  # two trailing LFs
        b'{"a":1}\n ',  # byte after the LF
    ],
)
def test_non_canonical_files_rejected(payload: bytes) -> None:
    with pytest.raises(WeaveError) as raised:
        canonical.parse_file_bytes(payload)
    assert raised.value.code == "E_JSON_NOT_CANONICAL"


def test_optional_trailing_lf_tolerated() -> None:
    value = canonical.parse_file_bytes(b'{"a":1}')
    assert value == {"a": 1}
    assert canonical.parse_file_bytes(b'{"a":1}\n') == {"a": 1}
    assert canonical.canonicalize(value) == b'{"a":1}'


def test_surrogate_pair_escape_is_canonical_literal_utf8() -> None:
    # "\\ud83d\\ude00" is the JSON escape for U+1F600; canonical form is literal UTF-8.
    with pytest.raises(WeaveError) as raised:
        canonical.parse_file_bytes('{"a":"\\ud83d\\ude00"}'.encode())
    assert raised.value.code == "E_JSON_NOT_CANONICAL"
    assert canonical.parse_text('"\\ud83d\\ude00"') == "\U0001f600"


def test_top_level_object_required() -> None:
    with pytest.raises(WeaveError) as raised:
        canonical.parse_file_bytes(b"[1]", require_object=True)
    assert raised.value.code == "E_JSON_INVALID"
