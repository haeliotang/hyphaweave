# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Shared pytest fixtures for the reference verifier's test suite."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
PACKAGE_ROOT = REPO_ROOT / "verifiers" / "python"
VECTORS = REPO_ROOT / "vectors"
KEYS = VECTORS / "keys"
KEYSET = KEYS / "keyset"
SPEC_ERROR_CODES = REPO_ROOT / "spec" / "error-codes.md"


def cli_environment(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ)
    env.pop("WEAVE_VERIFY_SKIP_CHECKS", None)
    if extra:
        env.update(extra)
    return env


def run_cli(
    *arguments: str,
    extra_env: dict[str, str] | None = None,
    cwd: pathlib.Path | None = None,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "hyphaweave_verify.cli", *arguments],
        capture_output=True,
        cwd=str(cwd if cwd is not None else REPO_ROOT),
        env=cli_environment(extra_env),
        check=False,
    )


@pytest.fixture(scope="session")
def repo_root() -> pathlib.Path:
    return REPO_ROOT


@pytest.fixture(scope="session")
def vectors_dir() -> pathlib.Path:
    return VECTORS


@pytest.fixture(scope="session")
def vectors_available() -> bool:
    return (VECTORS / "index.json").exists()


@pytest.fixture(scope="session")
def keyset_records():
    from hyphaweave_verify import verifier

    return verifier.load_keyset_directory(KEYSET)


@pytest.fixture(scope="session")
def keyset_views(keyset_records):
    from hyphaweave_verify import verifier

    return verifier.verify_record_set(keyset_records)


def load_expected(*parts: str) -> dict:
    path = VECTORS.joinpath(*parts)
    return json.loads(path.read_text(encoding="utf-8"))


def load_bytes(*parts: str) -> bytes:
    return VECTORS.joinpath(*parts).read_bytes()
