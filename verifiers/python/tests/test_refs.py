# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Five-state reference resolution (spec §6.3)."""

from __future__ import annotations

import pytest

from hyphaweave_verify import refs
from hyphaweave_verify.errors import WeaveError

ORIGIN = refs.Origin(project="example", instance="ed25519:" + "a" * 32)
DIGEST_A = "sha256:" + "aa" * 32
DIGEST_B = "sha256:" + "bb" * 32


def reference(digest: str = DIGEST_A, kind: str | None = None) -> refs.Reference:
    return refs.Reference(origin=ORIGIN, id="target-1", digest=digest, kind=kind)


class FakeContext:
    def __init__(self, targets: list[refs.TargetView]) -> None:
        self.targets = targets

    def find_records(self, origin: refs.Origin, record_id: str):
        return tuple(
            target
            for target in self.targets
            if target.origin == origin and target.id == record_id
        )


def target(
    *,
    digest: str = DIGEST_A,
    verdict: str = "valid",
    kind: str = "example.note",
    payload_digest: str | None = None,
    placeholder: bool = False,
) -> refs.TargetView:
    return refs.TargetView(
        origin=ORIGIN,
        id="target-1",
        kind=kind,
        verdict=verdict,
        computed_digest=digest,
        payload_digest=payload_digest,
        is_placeholder=placeholder,
        record=None,
    )


def test_found() -> None:
    resolution = refs.resolve_reference(reference(), FakeContext([target()]))
    assert resolution.state == refs.FOUND
    assert resolution.notice is None


def test_digest_mismatch_is_unverifiable_not_moved() -> None:
    """M-1: an offline verifier never emits ``moved``; a digest mismatch cannot be verified."""
    resolution = refs.resolve_reference(
        reference(), FakeContext([target(digest=DIGEST_B)])
    )
    assert resolution.state == refs.UNVERIFIABLE
    assert resolution.notice == "N_REF_UNVERIFIABLE"


def test_missing() -> None:
    resolution = refs.resolve_reference(reference(), FakeContext([]))
    assert resolution.state == refs.MISSING
    assert resolution.notice == "N_REF_MISSING"


def test_unverifiable_target_invalid() -> None:
    resolution = refs.resolve_reference(
        reference(), FakeContext([target(verdict="invalid")])
    )
    assert resolution.state == refs.UNVERIFIABLE
    assert resolution.notice == "N_REF_UNVERIFIABLE"


def test_erased_placeholder_matches_original_digest() -> None:
    placeholder = target(
        digest=DIGEST_B,
        payload_digest=DIGEST_A,
        placeholder=True,
        kind="weave.erased",
        verdict="erased",
    )
    resolution = refs.resolve_reference(reference(), FakeContext([placeholder]))
    assert resolution.state == refs.ERASED
    assert resolution.target is placeholder
    assert resolution.notice is None


def test_placeholder_with_different_original_digest_is_unverifiable() -> None:
    placeholder = target(
        digest=DIGEST_B,
        payload_digest=DIGEST_B,
        placeholder=True,
        kind="weave.erased",
        verdict="erased",
    )
    resolution = refs.resolve_reference(reference(), FakeContext([placeholder]))
    assert resolution.state == refs.UNVERIFIABLE


def test_unknown_digest_algorithm_is_unverifiable() -> None:
    unsupported = refs.Reference(
        origin=ORIGIN, id="target-1", digest="sha3-256:" + "ab" * 32
    )
    resolution = refs.resolve_reference(unsupported, FakeContext([target()]))
    assert resolution.state == refs.UNVERIFIABLE
    assert resolution.notice == "N_REF_UNVERIFIABLE"


def test_kind_claim_mismatch() -> None:
    found = refs.resolve_reference(reference(kind="other.kind"), FakeContext([target()]))
    assert refs.kind_claim_mismatch(reference(kind="other.kind"), found)
    assert not refs.kind_claim_mismatch(reference(kind="example.note"), found)
    assert not refs.kind_claim_mismatch(reference(), found)
    missing = refs.resolve_reference(reference(), FakeContext([]))
    assert not refs.kind_claim_mismatch(reference(kind="anything.kind"), missing)


def test_erased_kind_claim_is_checked_against_placeholder_kind() -> None:
    placeholder = target(
        digest=DIGEST_B,
        payload_digest=DIGEST_A,
        placeholder=True,
        kind="weave.erased",
        verdict="erased",
    )
    resolution = refs.resolve_reference(reference(), FakeContext([placeholder]))
    assert refs.kind_claim_mismatch(reference(kind="example.note"), resolution)
    assert not refs.kind_claim_mismatch(reference(kind="weave.erased"), resolution)


def test_validate_reference_rejects_bad_shapes() -> None:
    with pytest.raises(WeaveError) as raised:
        refs.validate_reference({"origin": ORIGIN.to_json(), "id": "x"})
    assert raised.value.code == "E_ENV_REFS"
    with pytest.raises(WeaveError):
        refs.validate_reference(
            {"origin": ORIGIN.to_json(), "id": "x", "digest": "not-a-digest"}
        )
    with pytest.raises(WeaveError):
        refs.validate_reference(
            {
                "origin": ORIGIN.to_json(),
                "id": "x",
                "digest": DIGEST_A,
                "hints": ["https://example.invalid/" + "x" * 3000],
            }
        )
    parsed = refs.validate_reference(
        {
            "origin": ORIGIN.to_json(),
            "id": "x",
            "digest": DIGEST_A,
            "kind": "example.note",
            "hints": ["https://example.invalid/record", "inceptless://node/1"],
        }
    )
    assert parsed.kind == "example.note"
    assert parsed.hints == ("https://example.invalid/record", "inceptless://node/1")
