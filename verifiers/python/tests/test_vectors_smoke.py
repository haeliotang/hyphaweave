# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Smoke test: the CLI oracle matches every committed conformance vector."""

from __future__ import annotations

import pytest

from hyphaweave_verify import vectors_runner

from conftest import VECTORS


def _suite_available() -> bool:
    return (VECTORS / "index.json").exists()


@pytest.mark.skipif(not _suite_available(), reason="vector suite is not generated")
def test_all_vectors_match() -> None:
    report = vectors_runner.run_vectors(VECTORS)
    failures = [case for case in report["cases"] if not case["ok"]]
    assert report["verdict"] == "valid", failures
    assert report["summary"]["mismatched"] == 0
    assert report["summary"]["matched"] == report["summary"]["case_count"]
    assert report["summary"]["case_count"] >= 100
    assert report["target"] == "vectors"
    assert report["report_version"] == "1"


@pytest.mark.skipif(not _suite_available(), reason="vector suite is not generated")
def test_vectors_report_shape_is_deterministic() -> None:
    first = vectors_runner.run_vectors(VECTORS)
    second = vectors_runner.run_vectors(VECTORS)
    from hyphaweave_verify import report as report_module

    assert report_module.serialize(first) == report_module.serialize(second)
    assert [case["id"] for case in first["cases"]] == [
        case["id"] for case in second["cases"]
    ]


@pytest.mark.skipif(not _suite_available(), reason="vector suite is not generated")
def test_frozen_vectors_when_present() -> None:
    frozen = VECTORS / "frozen" / "v0.1-candidate"
    if not frozen.is_dir():
        pytest.skip("candidate frozen vector set is not committed yet")
    revision_two_marker = frozen / "container" / "self-attested-root-untrusted"
    if not revision_two_marker.is_dir():
        pytest.skip("candidate frozen set predates revision 2 and will be regenerated")
    report = vectors_runner.run_vectors(frozen)
    assert report["verdict"] == "valid", [
        case for case in report["cases"] if not case["ok"]
    ]
