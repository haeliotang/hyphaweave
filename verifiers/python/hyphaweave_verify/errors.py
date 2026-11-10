# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Closed registry of verifier error codes and notices.

This module is the single source of truth inside the verifier for the closed
registry defined by ``spec/error-codes.md`` (the specification is the
authority; ``tests/test_registry.py`` parses that Markdown table and asserts
that this module exposes exactly the same set of codes with the same effects).

Every code is either an *error* (``E_*``) with an effect of ``invalid`` or
``unverifiable``, or a *notice* (``N_*``) that never changes a verdict by
itself. Check functions raise :class:`WeaveError` with a registry code; the
enclosing unit (record, manifest, container) converts it to a verdict.
"""

from __future__ import annotations

# Effect values used by spec/error-codes.md.
EFFECT_INVALID = "invalid"
EFFECT_UNVERIFIABLE = "unverifiable"

#: Error code -> effect. Sorted by code in the source for easy review.
ERROR_CODES: dict[str, str] = {
    "E_ACTOR_HUMAN_KEY": EFFECT_INVALID,
    "E_ACTOR_KEY_TYPE_MISMATCH": EFFECT_INVALID,
    "E_CONSENT_REVOKED": EFFECT_INVALID,
    "E_CONSENT_REVOKE_REF": EFFECT_INVALID,
    "E_CONSENT_VALIDITY": EFFECT_INVALID,
    "E_CONTAINER_ENTRY": EFFECT_INVALID,
    "E_CONTAINER_SIZE": EFFECT_INVALID,
    "E_CONTAINER_ZIP": EFFECT_INVALID,
    "E_ENV_ACTOR": EFFECT_INVALID,
    "E_ENV_ACTOR_GRANT_MISSING": EFFECT_INVALID,
    "E_ENV_ACTOR_IDEMPOTENCY": EFFECT_INVALID,
    "E_ENV_ACTOR_IDEMPOTENCY_MISSING": EFFECT_INVALID,
    "E_ENV_ACTOR_KEY": EFFECT_INVALID,
    "E_ENV_ACTOR_MODEL": EFFECT_INVALID,
    "E_ENV_ACTOR_MODEL_MISSING": EFFECT_INVALID,
    "E_ENV_ACTOR_ON_BEHALF": EFFECT_INVALID,
    "E_ENV_ACTOR_ON_BEHALF_MISSING": EFFECT_INVALID,
    "E_ENV_ACTOR_TYPE": EFFECT_INVALID,
    "E_ENV_BODY": EFFECT_INVALID,
    "E_ENV_FORMAT": EFFECT_INVALID,
    "E_ENV_ID": EFFECT_INVALID,
    "E_ENV_KIND_SYNTAX": EFFECT_INVALID,
    "E_ENV_LABELS": EFFECT_INVALID,
    "E_ENV_LICENCE": EFFECT_INVALID,
    "E_ENV_MISSING_FIELD": EFFECT_INVALID,
    "E_ENV_ORIGIN": EFFECT_INVALID,
    "E_ENV_REFS": EFFECT_INVALID,
    "E_ENV_SALT": EFFECT_INVALID,
    "E_ENV_SALT_MISSING": EFFECT_INVALID,
    "E_ENV_SENSITIVITY": EFFECT_INVALID,
    "E_ENV_SIG_ALG": EFFECT_INVALID,
    "E_ENV_SIG_KEY": EFFECT_INVALID,
    "E_ENV_SIG_VALUE": EFFECT_INVALID,
    "E_ENV_SIGS": EFFECT_INVALID,
    "E_ENV_STAGE": EFFECT_INVALID,
    "E_ENV_TIME": EFFECT_INVALID,
    "E_ENV_UNKNOWN_FIELD": EFFECT_INVALID,
    "E_ERASE_ACTOR": EFFECT_INVALID,
    "E_ERASE_ATTESTATION": EFFECT_INVALID,
    "E_ERASE_CONTRADICTION": EFFECT_INVALID,
    "E_ERASE_DIGEST_MISMATCH": EFFECT_INVALID,
    "E_GRANT_DELEGATION_EXCEEDS": EFFECT_INVALID,
    "E_GRANT_EXPIRED": EFFECT_UNVERIFIABLE,
    "E_GRANT_GRANTER": EFFECT_INVALID,
    "E_GRANT_GRANTEE_MISMATCH": EFFECT_INVALID,
    "E_GRANT_NOT_APPLICABLE": EFFECT_INVALID,
    "E_GRANT_NOT_TRANSFERABLE": EFFECT_INVALID,
    "E_GRANT_REVOKE_REF": EFFECT_INVALID,
    "E_GRANT_REVOKE_SIGNER": EFFECT_INVALID,
    "E_GRANT_REVOKED": EFFECT_UNVERIFIABLE,
    "E_GRANT_SCHEMA": EFFECT_INVALID,
    "E_GRANT_UNRESOLVED": EFFECT_UNVERIFIABLE,
    "E_JSON_DUPLICATE_KEY": EFFECT_INVALID,
    "E_JSON_INVALID": EFFECT_INVALID,
    "E_JSON_LONE_SURROGATE": EFFECT_INVALID,
    "E_JSON_NOT_CANONICAL": EFFECT_INVALID,
    "E_JSON_NUMBER_NOT_INTEGER": EFFECT_INVALID,
    "E_JSON_NUMBER_RANGE": EFFECT_INVALID,
    "E_JSON_SIZE": EFFECT_INVALID,
    "E_KEY_COMPROMISED": EFFECT_INVALID,
    "E_KEY_DECLARED_NOT_COSIGNED": EFFECT_INVALID,
    "E_KEY_DECLARED_NOT_SELF_SIGNED": EFFECT_INVALID,
    "E_KEY_EXPIRED": EFFECT_INVALID,
    "E_KEY_ID_MISMATCH": EFFECT_INVALID,
    "E_KEY_OWNER_MISSING": EFFECT_INVALID,
    "E_KEY_PUBLIC_KEY": EFFECT_INVALID,
    "E_KEY_REVOKE_EFFECTIVE": EFFECT_INVALID,
    "E_KEY_REVOKE_SIGNER": EFFECT_INVALID,
    "E_KEY_REVOKED": EFFECT_INVALID,
    "E_KEY_ROTATION_KEYS": EFFECT_INVALID,
    "E_KEY_ROTATION_SIGS": EFFECT_INVALID,
    "E_KEY_UNKNOWN": EFFECT_UNVERIFIABLE,
    "E_KEY_VALIDITY": EFFECT_INVALID,
    "E_KIND_BODY_SCHEMA": EFFECT_INVALID,
    "E_LABEL_DOWNGRADE": EFFECT_INVALID,
    "E_LABEL_LOCAL_ONLY_EXPORTED": EFFECT_INVALID,
    "E_MANIFEST_BLOB": EFFECT_INVALID,
    "E_MANIFEST_CHAIN": EFFECT_INVALID,
    "E_MANIFEST_CHAIN_MISSING": EFFECT_INVALID,
    "E_MANIFEST_CHAIN_UNEXPECTED": EFFECT_INVALID,
    "E_MANIFEST_DIGEST": EFFECT_INVALID,
    "E_MANIFEST_FORMAT": EFFECT_INVALID,
    "E_MANIFEST_LEVEL": EFFECT_INVALID,
    "E_MANIFEST_L1_NO_HEAD": EFFECT_INVALID,
    "E_MANIFEST_L1_NO_POSITION": EFFECT_INVALID,
    "E_MANIFEST_L2_NO_TIMESTAMP": EFFECT_INVALID,
    "E_MANIFEST_MISSING": EFFECT_INVALID,
    "E_MANIFEST_RECORD_DIGEST": EFFECT_INVALID,
    "E_MANIFEST_RECORD_EXTRA": EFFECT_INVALID,
    "E_MANIFEST_RECORD_MISSING": EFFECT_INVALID,
    "E_MANIFEST_RECORDS": EFFECT_INVALID,
    "E_MANIFEST_SCHEMA": EFFECT_INVALID,
    "E_MANIFEST_SIG_INVALID": EFFECT_INVALID,
    "E_MANIFEST_UNSIGNED": EFFECT_INVALID,
    "E_MANIFEST_VERSION": EFFECT_INVALID,
    "E_REF_KIND_MISMATCH": EFFECT_INVALID,
    "E_SIG_INVALID": EFFECT_INVALID,
    "E_SIG_MIXED_ORDER_A": EFFECT_INVALID,
    "E_SIG_NONCANONICAL_A": EFFECT_INVALID,
    "E_SIG_NONCANONICAL_R": EFFECT_INVALID,
    "E_SIG_REQUIRED": EFFECT_INVALID,
    "E_SIG_SMALL_ORDER_A": EFFECT_INVALID,
    "E_SIG_SMALL_ORDER_R": EFFECT_INVALID,
    "E_SIG_S_OUT_OF_RANGE": EFFECT_INVALID,
    "E_SIG_UNVERIFIABLE": EFFECT_UNVERIFIABLE,
    "E_TS_CERT": EFFECT_INVALID,
    "E_TS_CMS": EFFECT_INVALID,
    "E_TS_FILE": EFFECT_INVALID,
    "E_TS_IMPRINT": EFFECT_INVALID,
    "E_TS_RENEWAL": EFFECT_INVALID,
    "E_TS_SCHEMA": EFFECT_INVALID,
    "E_TS_UNTRUSTED": EFFECT_UNVERIFIABLE,
}

#: Notice codes. Notices never change a verdict by themselves.
NOTICES: frozenset[str] = frozenset(
    {
        "N_CHAIN_CLAIM_UNVERIFIED",
        "N_CONSENT_UNRESOLVED",
        "N_IDEMPOTENCY_DUPLICATE",
        "N_KEY_TOFU",
        "N_KEY_UNDECLARED",
        "N_KIND_UNKNOWN_OPAQUE",
        "N_LABEL_PROPAGATION_UNCHECKED",
        "N_NO_HUMAN_SIGNATURE",
        "N_PREVIOUS_SIG_UNVERIFIED",
        "N_READABLE_PRESENT",
        "N_REF_MISSING",
        "N_REF_MOVED",
        "N_REF_UNVERIFIABLE",
        "N_SELF_ATTESTED_ROOT_KEY",
    }
)

ALL_CODES: frozenset[str] = frozenset(ERROR_CODES) | NOTICES


class UsageError(Exception):
    """A usage or IO problem: the CLI exits 2 and writes no report to stdout."""


class WeaveError(ValueError):
    """A verifier check failed with a code from the closed registry.

    ``code`` is always a registry error code (``E_*``); notices are never
    raised. ``detail`` is a human-readable explanation used only for
    debugging/tests and never appears in a report.
    """

    def __init__(self, code: str, detail: str | None = None) -> None:
        if code not in ERROR_CODES:
            raise KeyError(f"{code!r} is not a registered error code")
        super().__init__(detail or code)
        self.code = code
        self.detail = detail

    @property
    def effect(self) -> str:
        """``invalid`` or ``unverifiable`` (see spec/error-codes.md)."""
        return ERROR_CODES[self.code]

    def __reduce__(self):  # pragma: no cover - convenience for pickle/deepcopy
        return (self.__class__, (self.code, self.detail))


def is_registered(code: str) -> bool:
    """Return whether ``code`` is a registered error or notice code."""
    return code in ALL_CODES


# ---------------------------------------------------------------------------
# Test hook: WEAVE_VERIFY_SKIP_CHECKS (CONTRACT §14.5 / Q18)
# ---------------------------------------------------------------------------

ENV_SKIP_CHECKS = "WEAVE_VERIFY_SKIP_CHECKS"


class CheckSkipper:
    """A test-only control that pretends selected checks passed.

    The hook exists solely so the repository's anti-verification gate can prove
    that each error-code family is actually exercised by the vectors. It is
    documented in the verifier README as test-only.

    A token may be an exact code (``E_SIG_INVALID``), a family prefix
    (``E_SIG``, matching every ``E_SIG_*`` code) or a wildcard form
    (``E_SIG_*``). The raw tokens are echoed, sorted and unique, in the report
    field ``checks_disabled`` so a report is never silently degraded.
    """

    __slots__ = ("_tokens",)

    def __init__(self, tokens: list[str] | tuple[str, ...] | None = None) -> None:
        cleaned: set[str] = set()
        for raw in tokens or ():
            token = raw.strip()
            if not token:
                continue
            cleaned.add(token)
        self._tokens = tuple(sorted(cleaned))

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> "CheckSkipper":
        import os

        env = os.environ if environ is None else environ
        raw = env.get(ENV_SKIP_CHECKS, "")
        return cls(raw.split(","))

    @property
    def tokens(self) -> tuple[str, ...]:
        """Sorted unique tokens as supplied by the environment."""
        return self._tokens

    def is_skipped(self, code: str) -> bool:
        """Return whether ``code`` should be treated as passed."""
        for token in self._tokens:
            if token == code:
                return True
            if token.endswith("*") and code.startswith(token[:-1]):
                return True
            # Area family form: E_SIG matches E_SIG_INVALID but not E_SIGS.
            if code.startswith(token + "_") and token.startswith(("E_", "N_")):
                return True
        return False

    def skip_error(self, code: str) -> bool:
        """Return whether a failing check with ``code`` should be suppressed.

        Only error codes can be skipped; a token naming an unknown code or a
        notice never suppresses anything.
        """
        return code in ERROR_CODES and self.is_skipped(code)


#: The default (empty) skipper used when the environment variable is unset.
NO_SKIP = CheckSkipper()


def skipped_code_allowed(code: str) -> bool:
    """Validate a token supplied to :class:`CheckSkipper` (used by tests)."""
    if code in ALL_CODES:
        return True
    family = code.rstrip("*")
    return any(code_name.startswith(family + "_") for code_name in ERROR_CODES)
