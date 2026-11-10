# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""The test-only check-skip hook and exit code 3 (spec §14.7/§14.8, S13)."""

from __future__ import annotations

import json

from conftest import VECTORS, run_cli

UNDECLARED = VECTORS / "sig" / "undeclared-key" / "record.json"
INVALID_SIG = VECTORS / "sig" / "invalid-value" / "record.json"
KEYSET = VECTORS / "keys" / "keyset"


def _report(result) -> dict:
    return json.loads(result.stdout.decode("utf-8"))


def test_hook_ignores_environment_without_the_flag() -> None:
    result = run_cli(
        "record", str(UNDECLARED), extra_env={"WEAVE_VERIFY_SKIP_CHECKS": "E_KEY_UNKNOWN"}
    )
    assert result.returncode == 1
    report = _report(result)
    assert report["checks_disabled"] == []
    assert report["verdict"] == "unverifiable"


def test_exact_code_is_skipped_echoed_and_exit_3() -> None:
    result = run_cli(
        "--test-hooks",
        "record",
        str(UNDECLARED),
        extra_env={"WEAVE_VERIFY_SKIP_CHECKS": "E_KEY_UNKNOWN"},
    )
    report = _report(result)
    assert report["checks_disabled"] == ["E_KEY_UNKNOWN"]
    # The suppressed check is treated as passed: no error, verdict valid; the
    # exit code still distinguishes the degraded run from an ordinary valid one.
    assert report["records"][0]["errors"] == []
    assert report["verdict"] == "valid"
    assert result.returncode == 3


def test_family_and_wildcard_tokens_are_usage_errors() -> None:
    for token in ("E_SIG", "E_SIG_*"):
        result = run_cli(
            "--test-hooks",
            "record",
            str(INVALID_SIG),
            "--keys",
            str(KEYSET),
            extra_env={"WEAVE_VERIFY_SKIP_CHECKS": token},
        )
        assert result.returncode == 2
        assert result.stdout == b""
        assert token.encode() in result.stderr


def test_multiple_tokens_sorted_unique_and_exit_3() -> None:
    result = run_cli(
        "--test-hooks",
        "record",
        str(UNDECLARED),
        extra_env={"WEAVE_VERIFY_SKIP_CHECKS": "E_SIG_INVALID,E_KEY_UNKNOWN,E_SIG_INVALID,,"},
    )
    report = _report(result)
    assert report["checks_disabled"] == ["E_KEY_UNKNOWN", "E_SIG_INVALID"]
    assert result.returncode == 3


def test_unknown_token_is_a_usage_error() -> None:
    result = run_cli(
        "--test-hooks",
        "record",
        str(UNDECLARED),
        extra_env={"WEAVE_VERIFY_SKIP_CHECKS": "E_NOT_A_CODE"},
    )
    assert result.returncode == 2
    assert result.stdout == b""
    assert b"E_NOT_A_CODE" in result.stderr


def test_hook_applies_to_vectors_command() -> None:
    result = run_cli(
        "--test-hooks",
        "vectors",
        str(VECTORS),
        extra_env={"WEAVE_VERIFY_SKIP_CHECKS": "E_JSON_SIZE"},
    )
    report = _report(result)
    assert report["checks_disabled"] == ["E_JSON_SIZE"]
    # Suppressing the JSON-size check breaks the parse-negative cases, which
    # proves the family is exercised; the degraded run exits 3.
    assert report["verdict"] == "invalid"
    assert report["summary"]["matched"] < report["summary"]["case_count"]
    assert result.returncode == 3
