# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Pinned gate: every complete JSON example in the specification must verify.

The check lives in ``tools/check_spec_examples.py`` (owned by the vector tooling);
this test pins the gate so a specification/verifier drift cannot pass unnoticed.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

import pytest

from conftest import REPO_ROOT

TOOL = REPO_ROOT / "tools" / "check_spec_examples.py"


@pytest.mark.skipif(not TOOL.exists(), reason="spec-example gate tool is not present")
def test_spec_examples_verify() -> None:
    result = subprocess.run(
        [sys.executable, str(TOOL)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
