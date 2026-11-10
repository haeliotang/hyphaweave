# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""CLI contract: JSON on stdout, stderr for usage, exit codes 0/1/2."""

from __future__ import annotations

import json

import pytest

from conftest import REPO_ROOT, VECTORS, run_cli


def _json_output(result) -> dict:
    assert result.stdout, result.stderr.decode("utf-8", "replace")
    return json.loads(result.stdout.decode("utf-8"))


def test_version() -> None:
    result = run_cli("--version")
    assert result.returncode == 0
    text = result.stdout.decode("utf-8")
    assert text.startswith("hyphaweave-verify 0.1.0")
    assert "report_version 1" in text


def test_help() -> None:
    result = run_cli("--help")
    assert result.returncode == 0
    text = result.stdout.decode("utf-8")
    for command in ("record", "container", "vectors"):
        assert command in text


def test_no_command_is_usage_error() -> None:
    result = run_cli()
    assert result.returncode == 2
    assert result.stdout == b""
    assert result.stderr


def test_record_valid() -> None:
    result = run_cli(
        "record",
        str(VECTORS / "stage" / "accepted-signed" / "record.json"),
        "--keys",
        str(VECTORS / "keys" / "keyset"),
    )
    assert result.returncode == 0
    report = _json_output(result)
    assert report["target"] == "record"
    assert report["verdict"] == "valid"
    assert report["report_version"] == "1"
    assert report["spec"] == "weave-record/1"
    assert report["checks_disabled"] == []
    assert report["verifier"] == {"name": "hyphaweave-verify-python", "version": "0.1.0"}
    assert report["records"][0]["kind"] == "example.note"


def test_record_invalid_exit_code() -> None:
    result = run_cli("record", str(VECTORS / "stage" / "bad-format" / "record.json"))
    assert result.returncode == 1
    report = _json_output(result)
    assert report["verdict"] == "invalid"
    assert report["records"][0]["errors"] == ["E_ENV_FORMAT"]


def test_record_unverifiable_exit_code() -> None:
    result = run_cli("record", str(VECTORS / "sig" / "undeclared-key" / "record.json"))
    assert result.returncode == 1
    report = _json_output(result)
    assert report["verdict"] == "unverifiable"
    assert report["records"][0]["errors"] == ["E_KEY_UNKNOWN"]


def test_erased_placeholder_is_success() -> None:
    result = run_cli(
        "record", str(VECTORS / "digest" / "record-erased-placeholder" / "record.json")
    )
    assert result.returncode == 0
    report = _json_output(result)
    assert report["verdict"] == "erased"
    entry = report["records"][0]
    assert entry["kind"] == "weave.erased"
    assert entry["verdict"] == "erased"
    assert entry["refs"] == []
    assert entry["attestation"]["state"] == "missing"
    assert entry["digest"].startswith("sha256:")


def test_container_valid() -> None:
    result = run_cli("container", str(VECTORS / "container" / "l0-minimal" / "container"))
    assert result.returncode == 0
    report = _json_output(result)
    assert report["verdict"] == "valid"
    assert report["container"]["level_claimed"] == "L0"
    assert report["container"]["level_verified"] == "L0"
    assert report["container"]["chain"] == {"status": "absent"}
    assert report["container"]["record_count"] == 1
    assert report["summary"]["valid"] == 1


def test_container_zip() -> None:
    result = run_cli(
        "container", str(VECTORS / "container" / "zip-valid" / "container.zip")
    )
    assert result.returncode == 0
    assert _json_output(result)["verdict"] == "valid"


def test_container_invalid_exit_code() -> None:
    result = run_cli(
        "container", str(VECTORS / "container" / "manifest-digest-wrong" / "container")
    )
    assert result.returncode == 1
    report = _json_output(result)
    assert report["verdict"] == "invalid"
    assert report["container"]["errors"] == ["E_MANIFEST_DIGEST"]
    assert report["records"] == []


def test_usage_error_on_missing_file() -> None:
    result = run_cli("record", str(REPO_ROOT / "does-not-exist.json"))
    assert result.returncode == 2
    assert result.stdout == b""
    assert result.stderr


def test_usage_error_on_bad_keyset(tmp_path) -> None:
    bad_keyset = tmp_path / "keyset"
    bad_keyset.mkdir()
    (bad_keyset / "bad.json").write_text('{"not":"a record"}', encoding="utf-8")
    result = run_cli(
        "record",
        str(VECTORS / "stage" / "accepted-signed" / "record.json"),
        "--keys",
        str(bad_keyset),
    )
    assert result.returncode == 2
    assert result.stdout == b""


def test_json_flag_is_accepted() -> None:
    result = run_cli("record", str(VECTORS / "stage" / "bad-format" / "record.json"), "--json")
    assert result.returncode == 1
    assert _json_output(result)["target"] == "record"


def test_report_contains_no_paths_or_environment() -> None:
    result = run_cli("container", str(VECTORS / "container" / "l0-minimal" / "container"))
    text = result.stdout.decode("utf-8")
    assert str(REPO_ROOT) not in text
    assert "/Users/" not in text
    assert ".venv" not in text
    assert "\t" not in text
    assert text.endswith("\n")
    assert not text.endswith("\n\n")


@pytest.mark.parametrize(
    "arguments",
    [
        ("container", str(VECTORS / "integrity-levels" / "l2-without-trust" / "container"),
         "--keys", str(VECTORS / "keys" / "keyset")),
    ],
)
def test_untrusted_timestamp_is_unverifiable(arguments) -> None:
    result = run_cli(*arguments)
    assert result.returncode == 1
    report = _json_output(result)
    assert report["verdict"] == "unverifiable"
    assert "E_TS_UNTRUSTED" in report["container"]["errors"]
