# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""The verifier's code registry must equal ``spec/error-codes.md`` exactly."""

from __future__ import annotations

import pathlib
import re

from hyphaweave_verify import errors

SPEC = pathlib.Path(__file__).resolve().parents[3] / "spec" / "error-codes.md"
ERROR_ROW = re.compile(r"^\| `(E_[A-Z0-9_]+)` \| (invalid|unverifiable)\b[^|]*\|")
NOTICE_ROW = re.compile(r"^\| `(N_[A-Z0-9_]+)` \|")

SOURCE_DIR = pathlib.Path(__file__).resolve().parents[1] / "hyphaweave_verify"


def _parse_registry() -> tuple[dict[str, str], set[str]]:
    text = SPEC.read_text(encoding="utf-8")
    errors_table: dict[str, str] = {}
    notices: set[str] = set()
    for line in text.splitlines():
        error_match = ERROR_ROW.match(line)
        if error_match:
            effect = error_match.group(2)
            errors_table[error_match.group(1)] = effect
            continue
        notice_match = NOTICE_ROW.match(line)
        if notice_match:
            notices.add(notice_match.group(1))
    return errors_table, notices


def test_error_code_set_matches_spec() -> None:
    spec_errors, spec_notices = _parse_registry()
    assert spec_errors, "could not parse the error table of spec/error-codes.md"
    assert set(spec_errors) == set(errors.ERROR_CODES)


def test_error_effects_match_spec() -> None:
    spec_errors, _ = _parse_registry()
    mismatches = {
        code: (spec_errors[code], errors.ERROR_CODES[code])
        for code in spec_errors
        if code in errors.ERROR_CODES and spec_errors[code] != errors.ERROR_CODES[code]
    }
    assert mismatches == {}


def test_notice_set_matches_spec() -> None:
    _, spec_notices = _parse_registry()
    assert spec_notices == set(errors.NOTICES)


def test_source_uses_only_registered_codes() -> None:
    """No source file may mention an error/notice code outside the registry."""
    offenders: list[str] = []
    pattern = re.compile(r'"(E_[A-Z0-9_]+|N_[A-Z0-9_]+)"')
    for path in sorted(SOURCE_DIR.glob("*.py")):
        for code in pattern.findall(path.read_text(encoding="utf-8")):
            if code not in errors.ALL_CODES:
                offenders.append("%s: %s" % (path.name, code))
    assert offenders == []


def test_weave_error_requires_registry_code() -> None:
    error = errors.WeaveError("E_SIG_INVALID")
    assert error.code == "E_SIG_INVALID"
    assert error.effect == "invalid"
    assert errors.WeaveError("E_KEY_UNKNOWN").effect == "unverifiable"
    try:
        errors.WeaveError("E_NOT_A_CODE")
    except KeyError:
        pass
    else:  # pragma: no cover - the registry is closed
        raise AssertionError("unknown code accepted")


def test_skip_checker_accepts_registered_error_codes_only() -> None:
    skipper = errors.CheckSkipper(["E_SIG_INVALID", "E_KEY_UNKNOWN", "E_SIG_INVALID"])
    assert skipper.tokens == ("E_KEY_UNKNOWN", "E_SIG_INVALID")
    assert skipper.skip_error("E_SIG_INVALID")
    assert skipper.skip_error("E_KEY_UNKNOWN")
    assert not skipper.skip_error("E_SIG_SMALL_ORDER_A")
    assert not skipper.skip_error("E_ENV_FORMAT")
    assert not skipper.skip_error("N_KEY_TOFU")
    # S13: family prefixes, wildcards, notice codes and unknown tokens are not
    # accepted; an unknown token is a usage error (the CLI exits 2).
    for bad in (["E_SIG"], ["E_ENV_*"], ["N_KEY_TOFU"], ["E_NOT_A_CODE"]):
        try:
            errors.CheckSkipper(bad)
        except errors.UsageError:
            pass
        else:  # pragma: no cover - the registry is closed
            raise AssertionError("bad skip token accepted: %r" % (bad,))
    # The environment variable is read only when the explicit hook is enabled.
    assert errors.CheckSkipper.from_env(False, {"WEAVE_VERIFY_SKIP_CHECKS": "E_SIG_INVALID"}).tokens == ()
    assert errors.CheckSkipper.from_env(True, {"WEAVE_VERIFY_SKIP_CHECKS": "E_SIG_INVALID"}).tokens == (
        "E_SIG_INVALID",
    )
