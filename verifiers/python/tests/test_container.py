# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Container-level checks: layout, manifest, records, chain, blobs and levels."""

from __future__ import annotations

import io
import json
import zipfile

import pytest

from hyphaweave_verify import container as container_module
from hyphaweave_verify import manifest as manifest_module
from hyphaweave_verify import verifier
from conftest import KEYSET, VECTORS


@pytest.fixture(scope="module")
def keyset():
    loaded = verifier.load_keyset_directory(KEYSET)
    views = verifier.verify_record_set(loaded)
    return loaded, views


_DEFAULT_KEYSET_CACHE: tuple | None = None


def default_keyset():
    """Revision 2: container trust roots come from the local --keys keyset."""
    global _DEFAULT_KEYSET_CACHE
    if _DEFAULT_KEYSET_CACHE is None:
        loaded = verifier.load_keyset_directory(KEYSET)
        views = verifier.verify_record_set(loaded)
        _DEFAULT_KEYSET_CACHE = (loaded, views)
    return _DEFAULT_KEYSET_CACHE


def verify(path, keyset_pair=None, **kwargs):
    if keyset_pair is None:
        keyset_pair = default_keyset()
    keyset_loaded, keyset_views = keyset_pair
    return container_module.verify_container(
        path,
        keyset_records=keyset_loaded,
        keyset_views=keyset_views,
        **kwargs,
    )


def test_l0_minimal_container(keyset) -> None:
    result = verify(VECTORS / "container" / "l0-minimal" / "container")
    report = result.report
    assert report["verdict"] == "valid"
    assert report["container"]["level_claimed"] == "L0"
    assert report["container"]["level_verified"] == "L0"
    assert report["container"]["chain"] == {"status": "absent"}
    assert report["container"]["previous_manifest_digest"] is None
    assert report["container"]["created_at"] == "2026-11-01T00:00:00.000Z"
    assert report["container"]["manifest_digest"].startswith("sha256:")
    assert report["container"]["errors"] == []
    assert report["records"][0]["verdict"] == "valid"


def test_manifest_digest_excludes_trailing_lf(keyset) -> None:
    """The digest is over canonical bytes without the tolerated trailing LF."""
    from hyphaweave_verify import canonical, encoding

    manifest_path = VECTORS / "container" / "l0-minimal" / "container" / "manifest.json"
    raw = manifest_path.read_bytes()
    assert raw.endswith(b"\n")
    value = canonical.parse_file_bytes(raw)
    digest_without_lf = encoding.manifest_digest(canonical.canonicalize(value))
    import hashlib

    digest_with_lf = "sha256:" + hashlib.sha256(
        b"weave-record/1/manifest-digest\n" + raw
    ).hexdigest()
    assert digest_without_lf != digest_with_lf
    result = verify(VECTORS / "container" / "l0-minimal" / "container")
    assert result.report["container"]["manifest_digest"] == digest_without_lf


def test_zip_container_matches_directory(keyset, tmp_path) -> None:
    directory = VECTORS / "container" / "l0-minimal" / "container"
    zip_path = VECTORS / "container" / "zip-valid" / "container.zip"
    direct = verify(directory)
    archived = verify(zip_path)
    assert archived.report["verdict"] == "valid"
    # Same content tree, different input identity (archive vs manifest digest).
    assert archived.report["container"]["manifest_digest"] == direct.report["container"][
        "manifest_digest"
    ]


def test_l1_claim_is_valid_but_chain_is_unverified() -> None:
    result = verify(VECTORS / "integrity-levels" / "l1-valid" / "container")
    report = result.report
    assert report["verdict"] == "valid"
    assert report["container"]["chain"] == {"status": "unverified"}
    assert report["container"]["level_verified"] == "L0"
    assert "N_CHAIN_CLAIM_UNVERIFIED" in report["container"]["notices"]


def test_l2_verified_with_trust_anchor(keyset) -> None:
    case = VECTORS / "integrity-levels" / "l2-valid"
    trust = (case / "tsa.crt.pem").read_bytes()
    result = verify(case / "container", keyset, tsa_trust=trust)
    report = result.report
    assert report["verdict"] == "valid"
    assert report["container"]["level_claimed"] == "L2"
    # S5/低3: L2 is reported as "L0 + verified anchor"; the CLI never claims L1/L2.
    assert report["container"]["level_verified"] == "L0"
    assert report["container"]["anchor_verified"] is True
    assert report["container"]["timestamps"][0]["state"] == "verified"
    assert report["container"]["timestamps"][0]["path"] == "signatures/timestamp-1.tsr"
    assert report["container"]["timestamps"][0]["gen_time"].endswith("Z")


def test_l2_without_trust_is_present_unverified(keyset) -> None:
    case = VECTORS / "integrity-levels" / "l2-without-trust"
    result = verify(case / "container", keyset)
    report = result.report
    assert report["verdict"] == "unverifiable"
    assert "E_TS_UNTRUSTED" in report["container"]["errors"]
    assert report["container"]["level_verified"] == "L0"
    assert report["container"]["anchor_verified"] is False
    assert report["container"]["timestamps"][0]["state"] == "present-unverified"


def test_l2_imprint_mismatch_is_invalid(keyset) -> None:
    case = VECTORS / "integrity-levels" / "l2-imprint-mismatch"
    trust = (case / "tsa.crt.pem").read_bytes()
    result = verify(case / "container", keyset, tsa_trust=trust)
    assert result.report["verdict"] == "invalid"
    assert "E_TS_IMPRINT" in result.report["container"]["errors"]


@pytest.mark.parametrize(
    ("category", "case", "expected_code"),
    [
        ("container", "manifest-missing", "E_MANIFEST_MISSING"),
        ("container", "manifest-digest-wrong", "E_MANIFEST_DIGEST"),
        ("container", "manifest-format-wrong", "E_MANIFEST_FORMAT"),
        ("container", "manifest-version-unsupported", "E_MANIFEST_VERSION"),
        ("container", "manifest-records-unsorted", "E_MANIFEST_RECORDS"),
        ("container", "manifest-unsigned", "E_MANIFEST_UNSIGNED"),
        ("container", "manifest-sig-invalid", "E_MANIFEST_SIG_INVALID"),
        ("container", "record-missing", "E_MANIFEST_RECORD_MISSING"),
        ("container", "record-extra", "E_MANIFEST_RECORD_EXTRA"),
        ("container", "record-digest-mismatch", "E_MANIFEST_RECORD_DIGEST"),
        ("container", "manifest-id-kind-mismatch", "E_MANIFEST_RECORDS"),
        ("container", "unknown-top-level-entry", "E_CONTAINER_ENTRY"),
        ("container", "zip-traversal", "E_CONTAINER_ENTRY"),
        ("container", "blobs-mismatch", "E_MANIFEST_BLOB"),
        ("container", "chain-missing", "E_MANIFEST_CHAIN_MISSING"),
        ("container", "chain-unexpected-file", "E_MANIFEST_CHAIN_UNEXPECTED"),
        ("container", "chain-digest-mismatch", "E_MANIFEST_CHAIN"),
        ("integrity-levels", "l0-with-timestamp", "E_MANIFEST_LEVEL"),
        ("integrity-levels", "l1-no-head", "E_MANIFEST_L1_NO_HEAD"),
        ("integrity-levels", "l1-no-position", "E_MANIFEST_L1_NO_POSITION"),
        ("integrity-levels", "l2-no-timestamp", "E_MANIFEST_L2_NO_TIMESTAMP"),
    ],
)
def test_container_error_classes(category: str, case: str, expected_code: str, keyset) -> None:
    case_dir = VECTORS / category / case
    if not case_dir.exists():  # pragma: no cover - fixtures are committed
        pytest.skip("vector case is not present")
    input_path = case_dir / "container"
    if (case_dir / "container.zip").exists():
        input_path = case_dir / "container.zip"
    result = verify(input_path, keyset)
    report = result.report
    assert report["verdict"] == "invalid"
    assert report["container"]["errors"] == [expected_code]


def test_container_errors_and_notices_sorted() -> None:
    result = verify(VECTORS / "container" / "manifest-unsigned" / "container")
    container = result.report["container"]
    assert container["errors"] == sorted(set(container["errors"]))
    assert container["notices"] == sorted(set(container["notices"]))


def test_readable_directory_is_ignored() -> None:
    result = verify(VECTORS / "container" / "readable-ignored" / "container")
    report = result.report
    assert report["verdict"] == "valid"
    assert "N_READABLE_PRESENT" in report["container"]["notices"]


def test_previous_chain_valid() -> None:
    result = verify(VECTORS / "container" / "chain-valid" / "container")
    report = result.report
    assert report["verdict"] == "valid"
    assert report["container"]["previous_manifest_digest"].startswith("sha256:")
    assert "N_PREVIOUS_SIG_UNVERIFIED" in report["container"]["notices"]


def test_local_only_export_refused(keyset) -> None:
    result = verify(VECTORS / "labels" / "local-only-exported" / "container", keyset)
    report = result.report
    assert report["verdict"] == "invalid"
    assert report["container"]["errors"] == ["E_LABEL_LOCAL_ONLY_EXPORTED"]


def test_erasure_container_is_valid(keyset) -> None:
    result = verify(VECTORS / "erasure" / "valid-container" / "container", keyset)
    report = result.report
    assert report["verdict"] == "valid"
    verdicts = {entry["id"]: entry["verdict"] for entry in report["records"]}
    assert "erased" in verdicts.values()


# ---------------------------------------------------------------------------
# Corrupted zip robustness: malformed archives must never raise a traceback.
# ---------------------------------------------------------------------------


def _zip_from_directory(source, destination, *, compression=zipfile.ZIP_DEFLATED):
    import zipfile

    with zipfile.ZipFile(destination, "w", compression=compression) as archive:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(source).as_posix())
    return destination


@pytest.fixture()
def valid_zip(tmp_path):
    return _zip_from_directory(
        VECTORS / "container" / "l0-minimal" / "container", tmp_path / "container.zip"
    )


def _expect_container_zip(path, keyset_pair=None):
    result = verify(path, keyset_pair)
    assert result.report["verdict"] == "invalid"
    assert "E_CONTAINER_ZIP" in result.report["container"]["errors"]
    assert result.report["records"] == []


def test_truncated_zip_is_container_zip(valid_zip) -> None:
    data = valid_zip.read_bytes()
    truncated = valid_zip.parent / "truncated.zip"
    truncated.write_bytes(data[: len(data) // 2])
    _expect_container_zip(truncated)


def test_corrupt_zip_header_is_container_zip(valid_zip) -> None:
    data = bytearray(valid_zip.read_bytes())
    data[0:4] = b"\x00\x00\x00\x00"
    corrupted = valid_zip.parent / "corrupt-header.zip"
    corrupted.write_bytes(bytes(data))
    _expect_container_zip(corrupted)


def test_corrupt_deflate_stream_is_container_zip(valid_zip) -> None:
    import struct
    import zipfile

    data = bytearray(valid_zip.read_bytes())
    with zipfile.ZipFile(io.BytesIO(bytes(data))) as archive:
        info = archive.infolist()[0]
        name_length = struct.unpack("<H", bytes(data[info.header_offset + 26 : info.header_offset + 28]))[0]
        extra_length = struct.unpack("<H", bytes(data[info.header_offset + 28 : info.header_offset + 30]))[0]
        data_offset = info.header_offset + 30 + name_length + extra_length
    # Corrupt a byte inside the deflate payload.
    data[data_offset + 2] ^= 0xFF
    corrupted = valid_zip.parent / "corrupt-deflate.zip"
    corrupted.write_bytes(bytes(data))
    _expect_container_zip(corrupted)


def test_random_zip_bytes_is_container_zip(tmp_path) -> None:
    bogus = tmp_path / "bogus.zip"
    bogus.write_bytes(b"PK\x03\x04not actually a zip archive")
    _expect_container_zip(bogus)


def test_zip_reader_structure_error_maps_to_container_zip(valid_zip, monkeypatch) -> None:
    """A structure error raised by the byte parser is E_CONTAINER_ZIP."""

    def raising_read(handle, entry):
        raise container_module.zipread.ZipStructureError("ablation: decoder failure")

    monkeypatch.setattr(container_module.zipread, "read_entry_data", raising_read)
    _expect_container_zip(valid_zip)


def test_zip_reader_decode_exception_maps_to_container_zip(valid_zip, monkeypatch) -> None:
    import zlib

    def raising_digest(handle, entry):
        raise zlib.error("bad deflate stream")

    monkeypatch.setattr(container_module.zipread, "digest_entry", raising_digest)
    monkeypatch.setattr(container_module.zipread, "read_entry_data", raising_digest)
    _expect_container_zip(valid_zip)


# ---------------------------------------------------------------------------
# S4/S5/S14: bounded reads, zip raw-byte rules, streamed blobs and identity
# ---------------------------------------------------------------------------


def _copy_container(tmp_path, name: str = "container"):
    import shutil

    destination = tmp_path / name
    shutil.copytree(VECTORS / "container" / "l0-minimal" / "container", destination)
    return destination


def test_zip_prefix_bytes_are_rejected(valid_zip) -> None:
    prefixed = valid_zip.parent / "prefixed.zip"
    prefixed.write_bytes(b"\x00" * 32 + valid_zip.read_bytes())
    _expect_container_zip(prefixed)


def test_zip_trailing_bytes_are_rejected(valid_zip) -> None:
    trailing = valid_zip.parent / "trailing.zip"
    trailing.write_bytes(valid_zip.read_bytes() + b"trailing")
    _expect_container_zip(trailing)


def test_zip_archive_comment_is_rejected(valid_zip) -> None:
    data = bytearray(valid_zip.read_bytes())
    eocd = data.rfind(b"PK\x05\x06")
    assert eocd >= 0
    comment = b"comment"
    data[eocd + 20 : eocd + 22] = len(comment).to_bytes(2, "little")
    commented = valid_zip.parent / "commented.zip"
    commented.write_bytes(bytes(data) + comment)
    _expect_container_zip(commented)


def test_zip_directory_entries_are_ignored(valid_zip) -> None:
    import zipfile

    directory_entry = zipfile.ZipInfo("records/")
    directory_entry.external_attr = (0o40755 << 16) | 0x10
    with zipfile.ZipFile(valid_zip, "a") as archive:
        archive.writestr(directory_entry, b"")
    result = verify(valid_zip)
    assert result.report["verdict"] == "valid"


def test_zip_dos_directory_attribute_with_data_is_container_zip(valid_zip) -> None:
    import zipfile

    entry = zipfile.ZipInfo("readable/not-a-directory")
    entry.external_attr = 0x10  # DOS directory attribute
    with zipfile.ZipFile(valid_zip, "a") as archive:
        archive.writestr(entry, b"payload")
    _expect_container_zip(valid_zip)


def test_readable_entries_are_never_read(tmp_path) -> None:
    container = _copy_container(tmp_path)
    readable = container / "readable"
    readable.mkdir()
    payload = readable / "payload.bin"
    payload.write_bytes(b"x" * (2 << 20))
    payload.chmod(0o000)  # an attempt to open this file would fail
    try:
        container_input = container_module.read_container(container)
    finally:
        payload.chmod(0o644)
    assert container_input.error is None
    assert container_input.readable_present is True
    assert not any(name.startswith("readable/") for name in container_input.files)
    result = verify(container)
    assert result.report["verdict"] == "valid"
    assert "N_READABLE_PRESENT" in result.report["container"]["notices"]


def test_blobs_are_streamed_not_materialised(tmp_path) -> None:
    container = _copy_container(tmp_path)
    blobs = container / "blobs" / "sha256"
    blobs.mkdir(parents=True)
    name = "ab" * 32
    (blobs / name).write_bytes(b"\0" * (4 << 20))
    container_input = container_module.read_container(container)
    assert container_input.error is None
    assert container_input.blobs["blobs/sha256/" + name][1] == 4 << 20
    assert "blobs/sha256/" + name not in container_input.files


def test_oversized_record_file_is_json_size(tmp_path) -> None:
    import hashlib

    container = _copy_container(tmp_path)
    manifest_bytes = (container / "manifest.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    oversized = container / "records" / ("ff" * 32 + ".json")
    oversized.write_bytes(b"{" + b" " * (2 << 20) + b"}")
    result = verify(container)
    report = result.report
    assert report["verdict"] == "invalid"
    # S2/F55: the oversize file is not listed, so the records-listing phase also
    # reports it as an extra file (§11.6 item 5, §13, §14.5 U8).
    assert report["container"]["errors"] == ["E_JSON_SIZE", "E_MANIFEST_RECORD_EXTRA"]
    assert report["records"] == []
    # T16: the manifest-derived container fields stay filled and the report shape
    # is the records-listing failure shape.
    assert report["container"]["record_count"] == len(manifest["records"])
    assert report["container"]["manifest_digest"] is not None
    assert report["container"]["level_claimed"] == "L0"
    assert report["container"]["level_verified"] == "L0"
    assert report["container"]["timestamps"] == []
    assert report["summary"] == {"erased": 0, "invalid": 0, "unverifiable": 0, "valid": 0}
    # S14/§14.6: a directory container's identity is the manifest digest once the
    # manifest parses; a *different* oversized file does not change it.
    assert report["input"] == {
        "sha256": report["container"]["manifest_digest"],
        "size": len(manifest_bytes),
    }
    assert report["input"]["sha256"] != "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()


def test_oversized_manifest_has_null_input_identity(tmp_path) -> None:
    container = _copy_container(tmp_path)
    (container / "manifest.json").write_bytes(b"{" + b" " * (5 << 20) + b"}")
    result = verify(container)
    assert result.report["verdict"] == "invalid"
    assert result.report["container"]["errors"] == ["E_JSON_SIZE"]
    assert result.report["input"] == {"sha256": None, "size": None}


def test_previous_with_a_null_chain_is_manifest_chain(keyset, tmp_path) -> None:
    previous = VECTORS / "container" / "l0-minimal" / "container"
    result = verify(
        VECTORS / "container" / "l0-minimal" / "container",
        keyset,
        previous_container=previous,
    )
    assert result.report["verdict"] == "invalid"
    assert result.report["container"]["errors"] == ["E_MANIFEST_CHAIN"]


def test_missing_previous_path_is_a_usage_error(keyset, tmp_path) -> None:
    from hyphaweave_verify.errors import UsageError

    with pytest.raises(UsageError):
        verify(
            VECTORS / "container" / "l0-minimal" / "container",
            keyset,
            previous_container=tmp_path / "does-not-exist",
        )


def test_erasure_cross_checks_tolerate_a_missing_body_erased() -> None:
    from types import SimpleNamespace

    from hyphaweave_verify import kinds

    fake_view = SimpleNamespace(
        verdict="invalid",
        digest="sha256:" + "aa" * 32,
        placeholder=None,
        envelope=SimpleNamespace(kind=kinds.KIND_ERASURE, body={}, origin=None),
    )
    # S7.3: an invalid erasure record must never crash the cross-record phase.
    assert container_module._erasure_cross_checks([fake_view]) is None


# ---------------------------------------------------------------------------
# S1-FIX1 T15/T17/A: directory total cap, previous-manifest precedence and the
# manifest signer's trust state
# ---------------------------------------------------------------------------


def test_directory_total_uncompressed_cap(tmp_path, monkeypatch) -> None:
    """T15: MAX_CONTAINER_UNCOMPRESSED_BYTES applies to directory containers."""
    container = _copy_container(tmp_path)
    monkeypatch.setattr(container_module, "MAX_CONTAINER_UNCOMPRESSED_BYTES", 32)
    result = verify(container)
    assert result.report["verdict"] == "invalid"
    assert "E_CONTAINER_SIZE" in result.report["container"]["errors"]


def test_oversized_embedded_previous_manifest_is_json_size(tmp_path) -> None:
    """A-L7: previous/manifest.json above MAX_MANIFEST_BYTES is E_JSON_SIZE; the
    record pass still runs (step 10), unlike a parse error (E_MANIFEST_CHAIN)."""
    import shutil

    container = tmp_path / "container"
    shutil.copytree(VECTORS / "container" / "chain-valid" / "container", container)
    (container / "previous" / "manifest.json").write_bytes(
        b"{" + b" " * (manifest_module.MAX_MANIFEST_BYTES + 1) + b"}"
    )
    result = verify(container)
    report = result.report
    assert report["verdict"] == "invalid"
    assert report["container"]["errors"] == ["E_JSON_SIZE"]
    assert report["records"], "records must still be processed before step 10"
    assert all(entry["verdict"] == "valid" for entry in report["records"])


def test_unparseable_embedded_previous_manifest_is_manifest_chain(tmp_path) -> None:
    import shutil

    container = tmp_path / "container"
    shutil.copytree(VECTORS / "container" / "chain-valid" / "container", container)
    (container / "previous" / "manifest.json").write_bytes(b"[" * 33 + b"]" * 33)
    result = verify(container)
    assert result.report["verdict"] == "invalid"
    assert result.report["container"]["errors"] == ["E_MANIFEST_CHAIN"]
    assert result.report["records"]


def test_manifest_signer_trust_is_not_part_of_the_crypto_check() -> None:
    """A-L8: a declared-but-untrusted manifest key does not add E_KEY_UNKNOWN."""
    case = VECTORS / "container" / "manifest-context-trusted-tofu" / "container"
    # Without a keyset the device declaration establishes no trust, but the
    # manifest signature equation still verifies against the declared material.
    result = verify(case, keyset_pair=([], []))
    report = result.report
    assert "E_KEY_UNKNOWN" not in report["container"]["errors"]


def test_previous_directory_without_manifest_is_manifest_chain(tmp_path) -> None:
    """A-L9/B-L7: a readable but unusable --previous path is E_MANIFEST_CHAIN."""
    previous = tmp_path / "previous"
    previous.mkdir()
    result = verify(
        VECTORS / "container" / "chain-valid" / "container",
        previous_container=previous,
    )
    assert result.report["verdict"] == "invalid"
    assert result.report["container"]["errors"] == ["E_MANIFEST_CHAIN"]


def test_previous_readable_non_zip_file_is_manifest_chain(tmp_path) -> None:
    previous = tmp_path / "previous.bin"
    previous.write_bytes(b"not a container and not a manifest\n")
    result = verify(
        VECTORS / "container" / "chain-valid" / "container",
        previous_container=previous,
    )
    assert result.report["verdict"] == "invalid"
    assert result.report["container"]["errors"] == ["E_MANIFEST_CHAIN"]


# ---------------------------------------------------------------------------
# S1-FIX2: previous containers (U1), zip limits (U2), disk numbers (U9) and the
# §11.9 rule-level behaviours (U12 L1/L2/L4/L5/L6).
# ---------------------------------------------------------------------------


def test_previous_zip_valid_and_invalid() -> None:
    """U1: a supplied previous container may be a zip, parsed by zipread."""
    valid_dir = VECTORS / "container" / "previous-zip-valid"
    valid_expected = json.loads((valid_dir / "expected.json").read_text(encoding="utf-8"))
    valid = verify(
        valid_dir / valid_expected["input"],
        previous_container=valid_dir / "previous-container.zip",
    )
    assert valid.report["verdict"] == "valid"

    invalid_dir = VECTORS / "container" / "previous-zip-invalid"
    invalid_expected = json.loads((invalid_dir / "expected.json").read_text(encoding="utf-8"))
    invalid = verify(
        invalid_dir / invalid_expected["input"],
        previous_container=invalid_dir / "previous-container.zip",
    )
    assert invalid.report["verdict"] == "invalid"
    assert invalid.report["container"]["errors"] == ["E_MANIFEST_CHAIN"]


def test_previous_zip_structural_failure_never_maps_to_container_zip() -> None:
    from hyphaweave_verify import container as container_module
    from hyphaweave_verify.errors import WeaveError

    case_dir = VECTORS / "container" / "previous-zip-invalid"
    with pytest.raises(WeaveError) as raised:
        container_module._read_previous_identity(
            case_dir / "previous-container.zip", []
        )
    assert raised.value.code == "E_MANIFEST_CHAIN"


def test_zip_entry_count_limit_in_memory(tmp_path) -> None:
    """U2: more than MAX_CONTAINER_ENTRIES zip entries is E_CONTAINER_SIZE.

    The 200,001-entry fixture would be ~16 MiB, so it is built in memory here
    instead of being committed (the reason is recorded in the report).
    """
    import struct

    entries = 200_001
    name = b"a/"
    local_size = 30 + len(name)
    local = struct.pack(
        "<IHHHHHIIIHH", 0x04034B50, 20, 0, 0, 0, 0, 0, 0, 0, len(name), 0
    ) + name
    central_header = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50,
        20,
        20,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        len(name),
        0,
        0,
        0,
        0,
        0x10,
        0,
    )
    central_entries = b"".join(
        central_header[:42]
        + struct.pack("<I", index * local_size)
        + name
        for index in range(entries)
    )
    central_offset = entries * local_size
    central_size_total = len(central_entries)
    zip64_eocd_offset = central_offset + central_size_total
    zip64_eocd = (
        struct.pack("<I", 0x06064B50)
        + struct.pack("<Q", 44)
        + struct.pack("<H", 45)
        + struct.pack("<H", 45)
        + struct.pack("<I", 0)
        + struct.pack("<I", 0)
        + struct.pack("<Q", entries)
        + struct.pack("<Q", entries)
        + struct.pack("<Q", central_size_total)
        + struct.pack("<Q", central_offset)
    )
    locator = struct.pack("<IIQI", 0x07064B50, 0, zip64_eocd_offset, 1)
    eocd_offset = zip64_eocd_offset + len(zip64_eocd) + len(locator)
    eocd = struct.pack(
        "<IHHHHIIH", 0x06054B50, 0, 0, 0xFFFF, 0xFFFF, central_size_total, central_offset, 0
    )
    archive_path = tmp_path / "entries.zip"
    archive_path.write_bytes(
        local * entries + central_entries + zip64_eocd + locator + eocd
    )
    result = verify(archive_path)
    assert result.report["verdict"] == "invalid"
    assert result.report["container"]["errors"] == ["E_CONTAINER_SIZE"]
    assert eocd_offset == archive_path.stat().st_size - 22


def test_zip_declared_total_over_limit_is_container_size() -> None:
    """U2: declared uncompressed total over 1 GiB is E_CONTAINER_SIZE, not ZIP."""
    case_dir = VECTORS / "container" / "zip-declared-total-over-limit"
    expected = json.loads((case_dir / "expected.json").read_text(encoding="utf-8"))
    result = verify(case_dir / expected["input"])
    assert result.report["verdict"] == "invalid"
    assert result.report["container"]["errors"] == ["E_CONTAINER_SIZE"]


def test_readable_declared_size_is_excluded_from_the_total() -> None:
    """U2: a huge declared readable/ entry is neither counted nor decompressed."""
    case_dir = VECTORS / "container" / "readable-declared-size-excluded"
    expected = json.loads((case_dir / "expected.json").read_text(encoding="utf-8"))
    result = verify(case_dir / expected["input"], default_keyset())
    assert result.report["verdict"] == "valid"


def test_zip_disk_numbers_are_single_volume_only() -> None:
    """U9: non-zero EOCD/locator disk numbers are E_CONTAINER_ZIP."""
    from hyphaweave_verify import zipread

    for case in ("zip-disk-number-nonzero", "zip64-locator-total-disks"):
        case_dir = VECTORS / "container" / case
        expected = json.loads((case_dir / "expected.json").read_text(encoding="utf-8"))
        with pytest.raises(zipread.ZipStructureError):
            with (case_dir / expected["input"]).open("rb") as handle:
                zipread.parse_zip(handle)


def test_zip_rule_level_structural_violations() -> None:
    """U12 L1/L2/L4/L5: the parser rejects each documented rule violation."""
    from hyphaweave_verify import zipread

    for case in (
        "zip-data-descriptor-nonzero-local-header",  # L1
        "readable-local-central-crc-mismatch",  # L2
        "zip-eocd-per-disk-count",  # L4
        "zip64-sentinel-without-zip64",  # L5
    ):
        case_dir = VECTORS / "container" / case
        expected = json.loads((case_dir / "expected.json").read_text(encoding="utf-8"))
        with pytest.raises(zipread.ZipStructureError):
            with (case_dir / expected["input"]).open("rb") as handle:
                zipread.parse_zip(handle)


def test_slash_name_with_data_is_container_zip() -> None:
    """U12 L6: a directory-style name carrying data is E_CONTAINER_ZIP."""
    case_dir = VECTORS / "container" / "zip-slash-name-with-data"
    expected = json.loads((case_dir / "expected.json").read_text(encoding="utf-8"))
    result = verify(case_dir / expected["input"])
    assert result.report["verdict"] == "invalid"
    assert result.report["container"]["errors"] == ["E_CONTAINER_ZIP"]


def test_oversize_record_listing_combines_independent_violations() -> None:
    """U8: E_JSON_SIZE joins MISSING/EXTRA in the records-listing phase."""
    for case, expected_codes in (
        ("oversize-record-file", ["E_JSON_SIZE"]),
        (
            "oversize-record-with-missing",
            ["E_JSON_SIZE", "E_MANIFEST_RECORD_MISSING"],
        ),
        (
            "oversize-record-with-extra",
            ["E_JSON_SIZE", "E_MANIFEST_RECORD_EXTRA"],
        ),
    ):
        case_dir = VECTORS / "container" / case
        expected = json.loads((case_dir / "expected.json").read_text(encoding="utf-8"))
        result = verify(case_dir / expected["input"])
        assert result.report["verdict"] == "invalid"
        assert sorted(result.report["container"]["errors"]) == expected_codes
        assert result.report["records"] == []


def test_zip64_eocd_disk_numbers_are_single_volume(tmp_path) -> None:
    """U9: non-zero disk fields in the ZIP64 EOCD record are E_CONTAINER_ZIP."""
    import struct

    from hyphaweave_verify import zipread

    source = VECTORS / "container" / "zip64-valid" / "container.zip"
    data = bytearray(source.read_bytes())
    locator = data.rfind(b"PK\x06\x07")
    zip64_offset = struct.unpack_from("<Q", data, locator + 8)[0]
    struct.pack_into("<I", data, zip64_offset + 16, 1)  # "number of this disk"
    archive_path = tmp_path / "disk.zip"
    archive_path.write_bytes(bytes(data))
    with pytest.raises(zipread.ZipStructureError):
        with archive_path.open("rb") as handle:
            zipread.parse_zip(handle)


def test_zip64_sentinel_rule_is_enforced_specifically() -> None:
    """U12 L5: sentinel counts without a ZIP64 locator are rejected by the
    sentinel rule itself (the redundantly matching CD-size checks would otherwise
    hide the specific rule behind the same error code)."""
    from hyphaweave_verify import zipread

    case_dir = VECTORS / "container" / "zip64-sentinel-without-zip64"
    expected = json.loads((case_dir / "expected.json").read_text(encoding="utf-8"))
    with pytest.raises(zipread.ZipStructureError) as raised:
        with (case_dir / expected["input"]).open("rb") as handle:
            zipread.parse_zip(handle)
    assert "ZIP64 sentinel" in str(raised.value)
