# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0
"""S2-FIX3 (decision 2026-11-16 #1): the shapes a conformance vector cannot express.

* F72: a declaration never keeps itself trusted through its own earlier verdict
  (defence in depth beside the material rule the vectors pin);
* F71: an anchor's typed primitives follow the 1c canonical-content rules (a malformed
  anchor is a usage error, exit 2, which a vector cannot express);
* F78: entry names compare exactly (``Manifest.json`` is not ``manifest.json``, which
  only a case-insensitive file system can confuse), and the record-target limitations
  of the ``record`` command follow the records as parsed (the vectors pin the runner's
  copy of the rule).
"""

from __future__ import annotations

import base64
import json
import shutil
from pathlib import Path

import pytest

from conftest import VECTORS, run_cli
from hyphaweave_verify import keys, timestamps
from hyphaweave_verify.errors import UsageError, WeaveError

REPO = Path(__file__).resolve().parents[3]
TSA_PEM = REPO / "vectors" / "keys" / "tsa" / "tsa.crt.pem"


# --------------------------------------------------------------------------- F72


class _SelfTrustedContext:
    """A context whose only trust source for the key is the record being judged."""

    def __init__(self, key_id: str, own: tuple[str, str]) -> None:
        self._key_id = key_id
        self._own = own

    def declaration_material(self, key_id: str):
        return None

    def owner_declaration(self, key_id: str):
        return None

    def trusted_human_org(self) -> frozenset[str]:
        return frozenset({self._key_id})

    def trusted_by_another_record(self, key_id: str, record_digest: str, source: str) -> bool:
        own = ("keyset" if source == "keyset" else "context", record_digest)
        return key_id == self._key_id and own != self._own

    def is_declared_key(self, key_id: str) -> bool:
        return False

    def governing_class(self, key_id: str, exclude_digest: str) -> str | None:
        return None


def _human_body() -> dict:
    raw = bytes([7]) * 32
    from hyphaweave_verify import encoding

    key_id = encoding.key_id_from_public_key(raw)
    return {
        "key": key_id,
        "key_type": "human",
        "algorithm": "ed25519",
        "public_key": encoding.encode_base64url(raw),
    }


def test_a_declaration_never_keeps_itself_trusted() -> None:
    """§5.3 (S2-FIX3 F72): "already trusted" comes from a record other than this one."""
    body = _human_body()
    digest = "sha256:" + "07" * 32
    context = _SelfTrustedContext(body["key"], ("context", digest))
    with pytest.raises(WeaveError) as raised:
        keys.check_declared_semantics(
            body=body,
            actor_key=body["key"],
            actor_type="human",
            verified_signature_keys=frozenset({body["key"]}),
            signature_entries_by_key={},
            recorded_at="2026-11-02T00:00:00.000Z",
            record_digest=digest,
            context=context,
            source="container",
        )
    assert raised.value.code == "E_KEY_UNTRUSTED"


def test_a_container_copy_of_a_keyset_declaration_stays_trusted() -> None:
    """The same digest in the keyset is another record: the container copy is trusted."""
    body = _human_body()
    digest = "sha256:" + "08" * 32
    context = _SelfTrustedContext(body["key"], ("keyset-elsewhere", digest))
    declaration = keys.check_declared_semantics(
        body=body,
        actor_key=body["key"],
        actor_type="human",
        verified_signature_keys=frozenset({body["key"]}),
        signature_entries_by_key={},
        recorded_at="2026-11-02T00:00:00.000Z",
        record_digest=digest,
        context=context,
        source="container",
    )
    assert declaration.key_id == body["key"]


# --------------------------------------------------------------------------- F71


class _Node:
    def __init__(self, tag: int, content: bytes | None, children: list["_Node"] | None) -> None:
        self.tag = tag
        self.content = content
        self.children = children


def _parse(data: bytes, position: int = 0) -> tuple[_Node, int]:
    tag = data[position]
    first = data[position + 1]
    position += 2
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


def _edited_anchor(edit) -> bytes:
    text = TSA_PEM.read_text(encoding="ascii")
    der = base64.b64decode("".join(line for line in text.splitlines() if not line.startswith("-----")))
    certificate, _end = _parse(der)
    edit(certificate.children[0])
    encoded = base64.b64encode(_encode(certificate)).decode("ascii")
    lines = [encoded[index : index + 64] for index in range(0, len(encoded), 64)]
    return ("-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n").encode()


def _offset(tbs: _Node) -> int:
    return 1 if tbs.children[0].tag == 0xA0 else 0


def _serial_not_minimal(tbs: _Node) -> None:
    serial = tbs.children[_offset(tbs)]
    assert serial.tag == 0x02
    serial.content = (b"\x00" if serial.content[0] < 0x80 else b"\x00\x00") + serial.content


def _public_key_unused_bits(tbs: _Node) -> None:
    bit_string = tbs.children[_offset(tbs) + 5].children[1]
    assert bit_string.tag == 0x03
    bit_string.content = b"\x01" + bit_string.content[1:]


def _critical_not_ff(tbs: _Node) -> None:
    extensions = next(child for child in tbs.children if child.tag == 0xA3).children[0]
    for extension in extensions.children:
        if len(extension.children) == 3 and extension.children[1].tag == 0x01:
            extension.children[1].content = b"\x01"
            return
    raise AssertionError("the committed anchor has no critical extension")


@pytest.mark.parametrize(
    "edit",
    [
        pytest.param(_serial_not_minimal, id="serial-number-not-minimal"),
        pytest.param(_public_key_unused_bits, id="public-key-bit-string-unused-bits"),
        pytest.param(_critical_not_ff, id="critical-boolean-0x01"),
    ],
)
def test_anchor_typed_primitives_follow_1c(edit) -> None:
    """§14.1 (S2-FIX3 F71): a non-canonical typed primitive makes the anchor a usage error."""
    with pytest.raises(UsageError):
        timestamps.parse_trust_anchors(_edited_anchor(edit))


# --------------------------------------------------------------------------- F78


def test_manifest_name_compares_exactly(tmp_path) -> None:
    """§14.6 S14 (S2-FIX3 F78): a root ``Manifest.json`` leaves the manifest absent."""
    destination = tmp_path / "container"
    shutil.copytree(VECTORS / "container" / "l0-minimal" / "container", destination)
    (destination / "manifest.json").rename(destination / "Manifest.json")
    result = run_cli("container", str(destination), "--keys", str(VECTORS / "keys" / "keyset"))
    report = json.loads(result.stdout)
    assert report["input"] == {"sha256": None, "size": None}
    assert report["container"]["errors"] == ["E_CONTAINER_ENTRY"]


def test_record_target_limitations_follow_the_parsed_record(tmp_path) -> None:
    """§14.9 (S2-FIX3 F78): the record command reports labels a failing envelope carries."""
    case = VECTORS / "labels" / "labels-on-record-failing-envelope"
    result = run_cli("record", str(case / "record.json"))
    report = json.loads(result.stdout)
    assert "L_LABELS_ARE_CLAIMS" in report["limitations"]
    placeholder = VECTORS / "erasure" / "placeholder-malformed-record-target" / "record.json"
    result = run_cli("record", str(placeholder))
    report = json.loads(result.stdout)
    assert {"L_ERASED_PLACEHOLDER", "L_ERASED_STANDALONE"} <= set(report["limitations"])
