# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Container-level checks: layout, manifest, records, chain, blobs and levels."""

from __future__ import annotations

import pytest

from hyphaweave_verify import container as container_module
from hyphaweave_verify import verifier
from hyphaweave_verify.errors import WeaveError

from conftest import KEYSET, VECTORS


@pytest.fixture(scope="module")
def keyset():
    loaded = verifier.load_keyset_directory(KEYSET)
    views = verifier.verify_record_set(loaded)
    return loaded, views


def verify(path, keyset_pair=None, **kwargs):
    keyset_loaded, keyset_views = keyset_pair or ([], [])
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
        ("container", "chain-unexpected", "E_MANIFEST_CHAIN_UNEXPECTED"),
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
