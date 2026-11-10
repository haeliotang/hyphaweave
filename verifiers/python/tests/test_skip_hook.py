# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""The test-only WEAVE_VERIFY_SKIP_CHECKS hook (spec §14.7 / Q18)."""

from __future__ import annotations

import json

from conftest import VECTORS, run_cli

UNDECLARED = VECTORS / "sig" / "undeclared-key" / "record.json"
INVALID_SIG = VECTORS / "sig" / "invalid-value" / "record.json"
KEYSET = VECTORS / "keys" / "keyset"


def _report(result) -> dict:
    return json.loads(result.stdout.decode("utf-8"))


def test_hook_is_off_by_default() -> None:
    result = run_cli("record", str(UNDECLARED))
    assert result.returncode == 1
    report = _report(result)
    assert report["checks_disabled"] == []
    assert report["verdict"] == "unverifiable"


def test_exact_code_is_skipped_and_echoed() -> None:
    result = run_cli(
        "record", str(UNDECLARED), extra_env={"WEAVE_VERIFY_SKIP_CHECKS": "E_KEY_UNKNOWN"}
    )
    report = _report(result)
    assert report["checks_disabled"] == ["E_KEY_UNKNOWN"]
    # The suppressed check is treated as passed: no error, verdict valid.
    assert report["records"][0]["errors"] == []
    assert report["verdict"] == "valid"
    assert result.returncode == 0


def test_family_prefix_is_skipped() -> None:
    normal = run_cli(
        "record", str(INVALID_SIG), "--keys", str(KEYSET)
    )
    assert _report(normal)["records"][0]["errors"] == ["E_SIG_INVALID"]
    skipped = run_cli(
        "record",
        str(INVALID_SIG),
        "--keys",
        str(KEYSET),
        extra_env={"WEAVE_VERIFY_SKIP_CHECKS": "E_SIG"},
    )
    report = _report(skipped)
    assert report["checks_disabled"] == ["E_SIG"]
    assert report["records"][0]["errors"] == []
    assert report["verdict"] == "valid"


def test_multiple_tokens_sorted_unique() -> None:
    result = run_cli(
        "record",
        str(UNDECLARED),
        extra_env={"WEAVE_VERIFY_SKIP_CHECKS": "E_SIG,E_KEY_UNKNOWN,E_SIG,,"},
    )
    report = _report(result)
    assert report["checks_disabled"] == ["E_KEY_UNKNOWN", "E_SIG"]


def test_unknown_token_has_no_effect() -> None:
    result = run_cli(
        "record", str(UNDECLARED), extra_env={"WEAVE_VERIFY_SKIP_CHECKS": "E_NOT_A_CODE"}
    )
    report = _report(result)
    assert report["checks_disabled"] == ["E_NOT_A_CODE"]
    assert report["records"][0]["errors"] == ["E_KEY_UNKNOWN"]


def test_hook_applies_to_vectors_command() -> None:
    result = run_cli("vectors", str(VECTORS), extra_env={"WEAVE_VERIFY_SKIP_CHECKS": "E_JSON"})
    report = _report(result)
    assert report["checks_disabled"] == ["E_JSON"]
    # Suppressing parse errors breaks the parse-negative cases, which proves the
    # family is exercised: the suite must no longer fully match.
    assert report["verdict"] == "invalid"
    assert report["matched_count"] < report["case_count"]
