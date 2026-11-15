# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0
"""S2 (decision 2026-11-15 #8): ``--tsa-trust`` anchors are judged under §12.2 1e.

A malformed anchor is a usage error (§14.1), which a conformance vector cannot
express, so the F62/F63 anchor shapes are pinned here. The certificates are
built by editing the committed test TSA certificate at the DER level; 1e does
not verify a certificate's own signature, so no private key is needed.
"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from hyphaweave_verify import timestamps
from hyphaweave_verify.errors import UsageError

REPO = Path(__file__).resolve().parents[3]
TSA_PEM = REPO / "vectors" / "keys" / "tsa" / "tsa.crt.pem"


class _Node:
    def __init__(self, tag: int, content: bytes | None, children: list["_Node"] | None) -> None:
        self.tag = tag
        self.content = content
        self.children = children


def _parse(data: bytes, position: int = 0) -> tuple[_Node, int]:
    tag = data[position]
    position += 1
    first = data[position]
    position += 1
    if first & 0x80:
        count = first & 0x7F
        length = int.from_bytes(data[position : position + count], "big")
        position += count
    else:
        length = first
    end = position + length
    if tag & 0x20:
        children = []
        child_position = position
        while child_position < end:
            child, child_position = _parse(data, child_position)
            children.append(child)
        return _Node(tag, None, children), end
    return _Node(tag, data[position:end], None), end


def _encode(node: _Node) -> bytes:
    body = node.content if node.children is None else b"".join(_encode(c) for c in node.children)
    if len(body) < 0x80:
        length = bytes([len(body)])
    else:
        raw = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([node.tag]) + length + body


def _tsa_der() -> bytes:
    text = TSA_PEM.read_text(encoding="ascii")
    body = "".join(line for line in text.splitlines() if not line.startswith("-----"))
    return base64.b64decode(body)


def _pem(der: bytes) -> bytes:
    text = base64.b64encode(der).decode("ascii")
    lines = [text[index : index + 64] for index in range(0, len(text), 64)]
    return ("-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n").encode()


def _edited(edit) -> bytes:
    certificate, _end = _parse(_tsa_der())
    edit(certificate.children[0])
    return _pem(_encode(certificate))


def _drop_version(tbs: _Node) -> None:
    assert tbs.children[0].tag == 0xA0
    tbs.children.pop(0)


def _drop_extensions(tbs: _Node) -> None:
    tbs.children = [child for child in tbs.children if child.tag != 0xA3]


def _issuer_unique_id(tbs: _Node) -> None:
    tbs.children.append(_Node(0x81, b"\x00\x5a", None))


def _version(value: int):
    def edit(tbs: _Node) -> None:
        tbs.children[0].children[0].content = bytes([value])

    return edit


def _extension_value_long_form(tbs: _Node) -> None:
    extensions = next(child for child in tbs.children if child.tag == 0xA3).children[0]
    value = extensions.children[0].children[-1]
    inner, _end = _parse(value.content)
    body = inner.content if inner.children is None else b"".join(_encode(c) for c in inner.children)
    value.content = bytes([inner.tag, 0x81, len(body)]) + body


def _subject_printable(tbs: _Node) -> None:
    oid = _Node(0x06, bytes([0x55, 0x04, 0x03]), None)
    value = _Node(0x13, b"a@b*", None)
    tbs.children[5] = _Node(0x30, None, [_Node(0x31, None, [_Node(0x30, None, [oid, value])])])


def _chain(*edits):
    def edit(tbs: _Node) -> None:
        for step in edits:
            step(tbs)

    return edit


def test_committed_anchor_is_accepted() -> None:
    assert len(timestamps.parse_trust_anchors(TSA_PEM.read_bytes())) == 1


@pytest.mark.parametrize(
    "edit",
    [
        pytest.param(_drop_version, id="F62-v1-with-extensions"),
        pytest.param(_chain(_drop_version, _drop_extensions, _issuer_unique_id), id="F62-v1-with-unique-id"),
        pytest.param(_version(3), id="F62-version-v4"),
        pytest.param(_extension_value_long_form, id="F63-extension-value-nonminimal"),
    ],
)
def test_anchor_outside_1e_is_a_usage_error(edit) -> None:
    """§14.1/§12.2 1e (S2/F62/F63): the anchor is rejected, exit 2, no report."""
    with pytest.raises(UsageError):
        timestamps.parse_trust_anchors(_edited(edit))


@pytest.mark.parametrize(
    "edit",
    [
        pytest.param(_chain(_version(1), _drop_extensions, _issuer_unique_id), id="F62-v2-with-unique-id"),
        pytest.param(_subject_printable, id="F63-printable-string-outside-its-set"),
    ],
)
def test_anchor_inside_1e_is_accepted(edit) -> None:
    """A well-formed X.509 certificate under the module rules is an anchor."""
    assert len(timestamps.parse_trust_anchors(_edited(edit))) == 1


def test_anchor_reverting_the_1e_judgement_turns_the_negatives_green(monkeypatch) -> None:
    """Anti-verification of the wiring: without the 1e walk the negatives pass."""
    monkeypatch.setattr(timestamps, "check_certificate_1e", lambda der, label: None)
    assert len(timestamps.parse_trust_anchors(_edited(_drop_version))) == 1
