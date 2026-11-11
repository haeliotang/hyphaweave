# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for the S1-FIX2 rulings (U1–U9) not already covered by the
container-level tests: non-monotonic class closure (U4), rotated-material TOFU
(U6) and the L_TSA_TRUST_UNVERIFIED iff rule (U7)."""

from __future__ import annotations

import json
import shutil

from conftest import VECTORS, run_cli


def _cli_report(*arguments: str) -> dict:
    result = run_cli(*arguments)
    return json.loads(result.stdout.decode("utf-8"))


def _case_arguments(case_dir) -> list[str]:
    expected = json.loads((case_dir / "expected.json").read_text(encoding="utf-8"))
    resolved: list[str] = []
    for token in expected.get("args") or ():
        if token in ("--keys", "--previous", "--tsa-trust"):
            resolved.append(token)
        elif token == "@keyset":
            for parent in (case_dir, *case_dir.parents):
                candidate = parent / "keys" / "keyset"
                if candidate.is_dir():
                    resolved.append(str(candidate))
                    break
            else:  # pragma: no cover - the suite always ships keys/keyset
                raise AssertionError("vector suite has no keys/keyset directory")
        else:
            resolved.append(str(case_dir / token))
    return resolved


def test_nonmonotonic_class_closure_is_not_trust_seeded() -> None:
    """U4: class governance precedes the trust closure; invalid declarations build
    no trust, so the D_o <-> D_y cosignature cycle has no trusted source."""
    case_dir = VECTORS / "key-lifecycle" / "nonmonotonic-closure-class-conflict"
    report = _cli_report(
        "container",
        str(case_dir / "container"),
        *_case_arguments(case_dir),
    )
    assert report["verdict"] == "invalid"
    verdicts = {entry["id"]: entry["verdict"] for entry in report["records"]}
    assert verdicts == {
        "K-as-org-T0": "unverifiable",
        "K-as-human-T1": "invalid",
        "Y-human-T2": "unverifiable",
    }
    aggregated = set(report["container"]["errors"])
    for entry in report["records"]:
        aggregated.update(entry["errors"])
    assert aggregated == {"E_KEY_CLASS_CONFLICT", "E_KEY_UNTRUSTED"}


def test_rotated_material_counts_as_context_trusted() -> None:
    """U6: material obtained from a context weave.key.rotated record is TOFU."""
    case_dir = VECTORS / "key-lifecycle" / "rotated-material-tofu"
    report = _cli_report(
        "container", str(case_dir / "container"), *_case_arguments(case_dir)
    )
    assert report["verdict"] == "valid"
    assert "L_KEY_TRUST_TOFU" in report["limitations"]
    notes = [entry for entry in report["records"] if entry["id"] == "note-by-rotated-key"]
    assert notes and "N_KEY_TOFU" in notes[0]["notices"]


def test_keyset_rotated_material_is_not_context_trusted(tmp_path) -> None:
    """U6: the TOFU predicate never covers local-keyset material, rotated or not."""
    case_dir = VECTORS / "key-lifecycle" / "rotated-material-tofu"
    keyset = tmp_path / "keyset"
    shutil.copytree(case_dir / "keyset", keyset)
    # Move the container's rotated record into the keyset: the material now comes
    # from the local keyset, so no N_KEY_TOFU / L_KEY_TRUST_TOFU may be reported.
    container = case_dir / "container"
    rotated_path = None
    for record_path in sorted((container / "records").iterdir()):
        value = json.loads(record_path.read_text(encoding="utf-8"))
        if value.get("kind") == "weave.key.rotated":
            rotated_path = record_path
            break
    assert rotated_path is not None
    (keyset / "zz-rotated.json").write_bytes(rotated_path.read_bytes())
    report = _cli_report(
        "container",
        str(container),
        "--keys",
        str(keyset),
    )
    assert "L_KEY_TRUST_TOFU" not in report["limitations"]
    notes = [entry for entry in report["records"] if entry["id"] == "note-by-rotated-key"]
    assert notes and "N_KEY_TOFU" not in notes[0]["notices"]


def test_tsa_limitation_only_for_present_unverified_receipts() -> None:
    """U7: an invalid receipt reports its code and does not trigger L_TSA."""
    invalid_dir = VECTORS / "integrity-levels" / "l2-invalid-receipt-no-tsa-limitation"
    invalid = _cli_report(
        "container", str(invalid_dir / "container"), *_case_arguments(invalid_dir)
    )
    assert "L_TSA_TRUST_UNVERIFIED" not in invalid["limitations"]
    assert invalid["container"]["errors"] == ["E_TS_CMS"]

    # Positive coverage: a receipt that passes structure/CMS but has no anchor is
    # present-unverified and does trigger the identifier.
    trusted_dir = VECTORS / "integrity-levels" / "l2-without-trust-limitations"
    without_trust = _cli_report(
        "container", str(trusted_dir / "container"), *_case_arguments(trusted_dir)
    )
    assert "L_TSA_TRUST_UNVERIFIED" in without_trust["limitations"]
