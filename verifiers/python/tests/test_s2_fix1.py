# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0
"""S2-FIX1 (decision 2026-11-15 #13): rules that a conformance vector cannot express.

Usage errors (exit 2, no report) have no place in the vector expectation schema, so
the S2-FIX1 shapes that end in a usage error are pinned here.
"""

from __future__ import annotations

import json
import shutil

import pytest

from conftest import VECTORS, run_cli

KEYSET = VECTORS / "keys" / "keyset"
TARGET = VECTORS / "stage" / "accepted-signed" / "record.json"


def _canonical_file(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("utf-8")


@pytest.mark.parametrize(
    "name", ["key-declared-human-2.json", "key-declared-key-new.json", "key-declared-human-1.json"]
)
def test_keyset_declaration_with_empty_sigs_is_a_usage_error(tmp_path, name) -> None:
    """T5 (§14.1): `sigs: []` on a keyset record that must be signed is exit 2.

    §14.1 lists "sigs presence and format (§4.3, including a record that requires
    per-record signatures but has sigs absent or empty)" in the structural group whose
    failure in a keyset file is a usage error. Review A's differential fuzz found the
    reference verifier accepting such a keyset (mutants keyset-00013, keyset-00217).
    """
    keyset = tmp_path / "keyset"
    shutil.copytree(KEYSET, keyset)
    path = keyset / name
    record = json.loads(path.read_bytes())
    record["sigs"] = []
    path.write_bytes(_canonical_file(record))
    result = run_cli("record", str(TARGET), "--keys", str(keyset))
    assert result.returncode == 2, result.stdout
    assert result.stdout == b""
    assert b"E_SIG_REQUIRED" in result.stderr


def test_keyset_declaration_without_sigs_member_is_a_usage_error(tmp_path) -> None:
    """T5: an absent `sigs` on a keyset declaration is the same usage error."""
    keyset = tmp_path / "keyset"
    shutil.copytree(KEYSET, keyset)
    path = keyset / "key-declared-human-2.json"
    record = json.loads(path.read_bytes())
    del record["sigs"]
    path.write_bytes(_canonical_file(record))
    result = run_cli("record", str(TARGET), "--keys", str(keyset))
    assert result.returncode == 2, result.stdout
    assert result.stdout == b""


def test_unmodified_keyset_still_verifies() -> None:
    """Control for T5: the committed keyset is accepted."""
    result = run_cli("record", str(TARGET), "--keys", str(KEYSET))
    assert result.returncode in (0, 1)
    assert json.loads(result.stdout)["verdict"] == "valid"
