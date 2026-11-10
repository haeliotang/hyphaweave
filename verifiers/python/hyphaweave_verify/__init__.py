# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Reference verifier for the ``weave-record/1`` exchange format (H0 draft).

This is the Python reference implementation. It is deliberately small,
offline and deterministic: it never touches the network, never reads the wall
clock, and always emits the same report bytes for the same input bytes.

Public modules used by external tooling (for example the repository's
independent cross-check scripts) are ``canonical`` and ``ed25519``; the CLI is
``hyphaweave_verify.cli:main`` installed as ``hyphaweave-verify``.

Reading order for a new maintainer is documented in ``README.md``.
"""

from __future__ import annotations

__version__ = "0.1.0"

#: Name reported in the ``verifier.name`` report field.
VERIFIER_NAME = "hyphaweave-verify-python"

__all__ = ["VERIFIER_NAME", "__version__"]
