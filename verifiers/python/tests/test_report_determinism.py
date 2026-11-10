# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Reports must be byte-identical regardless of wall clock, TZ, locale or cwd."""

from __future__ import annotations

import json

from conftest import REPO_ROOT, VECTORS, load_bytes, run_cli

L0_CONTAINER = VECTORS / "container" / "l0-minimal" / "container"
RECORD = VECTORS / "stage" / "accepted-signed" / "record.json"
KEYSET = VECTORS / "keys" / "keyset"


def test_container_report_is_deterministic() -> None:
    first = run_cli("container", str(L0_CONTAINER), "--keys", str(KEYSET))
    second = run_cli(
        "container",
        str(L0_CONTAINER),
        "--keys",
        str(KEYSET),
        extra_env={"TZ": "Pacific/Kiritimati", "LANG": "C", "LC_ALL": "C"},
        cwd=REPO_ROOT,
    )
    assert first.returncode == second.returncode == 0
    assert first.stdout == second.stdout


def test_container_report_independent_of_cwd_timezone_locale(tmp_path) -> None:
    first = run_cli("container", str(L0_CONTAINER), "--keys", str(KEYSET), cwd=tmp_path)
    second = run_cli(
        "container",
        str(L0_CONTAINER),
        "--keys",
        str(KEYSET),
        cwd="/",
        extra_env={
            "TZ": "America/New_York",
            "LANG": "ja_JP.UTF-8",
            "LC_ALL": "ja_JP.UTF-8",
            "HOME": str(tmp_path),
        },
    )
    assert first.stdout == second.stdout
    assert first.stderr == second.stderr == b""


def test_record_report_is_deterministic() -> None:
    first = run_cli("record", str(RECORD), "--keys", str(KEYSET))
    second = run_cli(
        "record",
        str(RECORD),
        "--keys",
        str(KEYSET),
        extra_env={"TZ": "Asia/Tokyo", "LANG": "de_DE.UTF-8"},
        cwd="/",
    )
    assert first.stdout == second.stdout


def test_report_serialization_shape() -> None:
    result = run_cli("record", str(RECORD), "--keys", str(KEYSET))
    text = result.stdout.decode("utf-8")
    report = json.loads(text)
    # sort_keys=True: the first key is lexicographically smallest.
    keys = list(report)
    assert keys == sorted(keys)
    # Two-space indent and ASCII escaping.
    assert '\n  "checks_disabled": [],' in text
    # Every array of codes is sorted and unique.
    for entry in report["records"]:
        assert entry["errors"] == sorted(set(entry["errors"]))
        assert entry["notices"] == sorted(set(entry["notices"]))


def test_input_identity_uses_manifest_digest_for_directories() -> None:
    result = run_cli("container", str(L0_CONTAINER), "--keys", str(KEYSET))
    report = json.loads(result.stdout.decode("utf-8"))
    assert report["input"]["sha256"] == report["container"]["manifest_digest"]
    assert report["input"]["size"] > 0
    # The zip form identifies the archive itself.
    zip_result = run_cli(
        "container",
        str(VECTORS / "container" / "zip-valid" / "container.zip"),
        "--keys",
        str(KEYSET),
    )
    zip_report = json.loads(zip_result.stdout.decode("utf-8"))
    assert zip_report["input"]["sha256"].startswith("sha256:")
    assert zip_report["input"]["size"] == len(
        load_bytes("container", "zip-valid", "container.zip")
    )
