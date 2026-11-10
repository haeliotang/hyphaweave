#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0
"""H0 FIX1 gate 3(a): true source-level mutation ablation of the verifier.

This replaces the old "check family ablation" (which only filtered already-produced
error codes out of reports and was therefore a tautology - see review-a H-3).  Here
each mutation really changes the verifier source:

1. the ``hyphaweave_verify`` package is copied to ``.tmp-work/mutants/<id>/``;
2. exactly one anchored textual change is applied to one module; anchors are
   regular expressions that must match the expected number of sites exactly (a
   stale anchor is a hard failure, never a silent skip);
3. ``python -m hyphaweave_verify.cli vectors <vectors>`` is run in a fresh process
   with ``PYTHONPATH`` pointing at the mutated copy; the process first prints
   ``hyphaweave_verify.__file__`` so the log proves the mutated copy was imported;
4. the mutation is **killed** iff that run no longer matches every vector
   (non-zero exit / ``verdict != "valid"``).  A survivor means the vectors do not
   pin down that check and the gate fails (exit 1).

The catalogue is a curated list of mutations covering every verifier check class,
including each of the 24 survivors reported by review-a (cross-purpose signature
domains in both directions, x=0 sign-bit A/R, mixed-order A, negative integer lower
bound, revoke-record-as-grant, delegated granter identity, parent grant
revoked/expired, sub-grant valid_from/valid_until bounds, erasure digest
cross-check, erasure attestation back-reference, chain-unexpected first branch,
``--previous`` comparison, L0-with-chain, TSA certificate validity, EKU, ESS,
``messageDigest``, and the remaining classes listed in ``CATALOGUE``).

Every mutation names the vector(s) expected to pin it (``pinned_by``) and the
review-a survivor it corresponds to where applicable, so the final report can show
"survivor X is now pinned by vector Y".

Usage:
    python tools/anti_verification.py [--list] [--json PATH] [--jobs N]
                                      [--only ID[,ID...]] [--self-test] [--verbose]
                                      [--suite DIR] [--pytest-survivors]

Exit status: 0 = every mutation killed, 1 = survivor(s), 2 = usage/IO/setup error
(baseline vectors not green, stale catalogue anchor, mutant package shadowing).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PACKAGE_DIR = REPO / "verifiers" / "python" / "hyphaweave_verify"
DEFAULT_SUITE = REPO / "vectors"
MUTANT_ROOT = REPO / ".tmp-work" / "mutants"
REPORT_PATH = REPO / ".tmp-work" / "gates" / "fix1-ablation-report.json"
PYTHON = str(Path(sys.executable))


# --------------------------------------------------------------------------- catalogue


@dataclass(frozen=True)
class Mutation:
    """One anchored source mutation."""

    id: str
    module: str
    description: str
    check: str
    #: regular expression anchoring exactly one (or ``occurrences``) source site(s)
    anchor: str
    #: replacement template (``re.sub`` syntax; backreferences allowed)
    replacement: str
    pinned_by: tuple[str, ...] = ()
    review_a_survivor: bool = False
    #: expected number of occurrences of ``anchor`` (default exactly one)
    occurrences: int = 1
    replace_all: bool = False
    #: non-empty when the mutation is an *equivalent mutant*: removing the check cannot
    #: change any observable verdict because another layer produces the same result.
    #: Equivalent mutants are reported separately (they cannot be killed by a vector);
    #: the gate fails only on survivors that are not documented equivalents.
    equivalent_reason: str = ""


@dataclass
class MutationResult:
    mutation: Mutation
    status: str  # "killed" | "survivor" | "error"
    detail: str = ""
    imported_file: str = ""
    pytest_caught: str = ""  # "yes" | "no" | "not-run"
    exit_code: int | None = None
    report_verdict: str | None = None
    mismatched_cases: int = 0


#: Curated mutation catalogue.  ``check`` groups mutations by verifier check class;
#: ``review_a_survivor`` marks the 24 survivors from review-a (they MUST all be killed
#: by vectors once the FIX1 vectors land).
CATALOGUE: list[Mutation] = []


def _add(*mutations: Mutation) -> None:
    CATALOGUE.extend(mutations)


def _m(
    mid: str,
    module: str,
    check: str,
    description: str,
    anchor: str,
    replacement: str,
    pinned_by: tuple[str, ...] = (),
    review_a_survivor: bool = False,
    occurrences: int = 1,
    replace_all: bool = False,
    equivalent_reason: str = "",
) -> Mutation:
    return Mutation(
        id=mid,
        module=module,
        description=description,
        check=check,
        anchor=anchor,
        replacement=replacement,
        pinned_by=pinned_by,
        review_a_survivor=review_a_survivor,
        occurrences=occurrences,
        replace_all=replace_all,
        equivalent_reason=equivalent_reason,
    )


def _build_catalogue() -> None:
    """Populate :data:`CATALOGUE` (kept in one place for auditability)."""
    _add(
        # ------------------------------------------------------------------ canonical JSON
        _m("canonical-duplicate-key", "canonical.py", "canonical.duplicate-key",
           "stop rejecting duplicate object member names",
           r'self\._fail\("E_JSON_DUPLICATE_KEY", "duplicate object member name"\)',
           'pass  # ablation: duplicate-key check disabled',
           ("jcs/duplicate-top-level-key", "jcs/duplicate-nested-key")),
        _m("canonical-number-not-integer", "canonical.py", "canonical.number-not-integer",
           "accept well-formed floats/exponents as integers",
           r'self\._fail\("E_JSON_NUMBER_NOT_INTEGER", "number literal is not an integer"\)',
           'pass  # ablation: float/exponent rejection disabled',
           ("jcs/float-number", "jcs/exponent-number")),
        _m("canonical-negative-zero", "canonical.py", "canonical.negative-zero",
           "accept the non-canonical integer literal -0",
           r'self\._fail\("E_JSON_NOT_CANONICAL", "negative zero is not canonical"\)',
           'pass  # ablation: -0 rejection disabled',
           ("jcs/minus-zero",),
           equivalent_reason="the canonical-file byte comparison rejects the same -0 file as "
           "E_JSON_NOT_CANONICAL, so removing the token-level check cannot change any verdict"),
        _m("canonical-integer-lower-bound", "canonical.py", "canonical.integer-range",
           "drop the negative integer lower bound -(2^53-1)",
           r'if value < -MAX_SAFE_INTEGER or value > MAX_SAFE_INTEGER:',
           'if value > MAX_SAFE_INTEGER:  # ablation: lower bound dropped',
           ("jcs/integer-below-min",), review_a_survivor=True,
           occurrences=2, replace_all=True),
        _m("canonical-integer-upper-bound", "canonical.py", "canonical.integer-range",
           "drop the positive integer upper bound +(2^53-1)",
           r'if value < -MAX_SAFE_INTEGER or value > MAX_SAFE_INTEGER:',
           'if value < -MAX_SAFE_INTEGER:  # ablation: upper bound dropped',
           ("jcs/integer-out-of-range",), occurrences=2, replace_all=True),
        _m("canonical-not-canonical-bytes", "canonical.py", "canonical.canonical-file-form",
           "skip the canonical-file byte comparison",
           r'raise WeaveError\(\s*"E_JSON_NOT_CANONICAL",[^)]*\)',
           'pass  # ablation: canonical-file byte comparison disabled',
           ("jcs/pretty-printed", "jcs/member-order", "jcs/crlf")),
        _m("canonical-lone-surrogate", "canonical.py", "canonical.lone-surrogate",
           "stop rejecting unpaired surrogate escapes in the parser",
           r'self\._fail\("E_JSON_LONE_SURROGATE",[^)]*\)',
           'pass  # ablation: parser lone-surrogate rejection disabled',
           ("jcs/lone-surrogate-escape",), occurrences=3, replace_all=True),
        _m("canonical-lone-surrogate-emit", "canonical.py", "canonical.lone-surrogate",
           "stop rejecting unpaired surrogates when serialising strings",
           r'raise WeaveError\(\n\s*"E_JSON_LONE_SURROGATE",\n\s*"string contains a lone Unicode surrogate U\+%04X" % code_point,\n\s*\)',
           'pass  # ablation: emitter lone-surrogate rejection disabled',
           ("jcs/lone-surrogate-escape",),
           equivalent_reason="the parser rejects a lone surrogate escape before serialisation "
           "is reached, so removing the emitter guard cannot change any accepted input"),
        # ----------------------------------------------------------------------- ed25519
        _m("ed25519-x0-sign-bit", "ed25519.py", "ed25519.decode.x0-sign-bit",
           "accept x == 0 point encodings with the sign bit set",
           r'if sign:\n\s*# RFC 8032[^\n]*\n\s*raise WeaveError\(noncanonical_code, "x == 0 with the sign bit set"\)',
           'if False:  # ablation: x==0 sign-bit rejection disabled',
           ("sig/x0-sign-bit-A", "sig/x0-sign-bit-R"), review_a_survivor=True),
        _m("ed25519-small-order-A", "ed25519.py", "ed25519.small-order-A",
           "accept small-order public keys",
           r'if order_class == "small":',
           'if False:  # ablation: small-order A rejection disabled',
           ("sig/small-order-A-00", "sig/small-order-A-identity")),
        _m("ed25519-mixed-order-A", "ed25519.py", "ed25519.mixed-order-A",
           "accept mixed-order public keys (not in the prime-order subgroup)",
           r'if order_class == "mixed":',
           'if False:  # ablation: mixed-order A rejection disabled',
           ("sig/mixed-order-A",), review_a_survivor=True),
        _m("ed25519-small-order-R", "ed25519.py", "ed25519.small-order-R",
           "accept small-order R values",
           r'if _is_small_order\(r_point\):',
           'if False:  # ablation: small-order R rejection disabled',
           ("sig/small-order-R",)),
        _m("ed25519-s-out-of-range", "ed25519.py", "ed25519.s-out-of-range",
           "accept S >= L (non-canonical scalar)",
           r'if s >= L:',
           'if False:  # ablation: S range check disabled',
           ("sig/S-equals-L", "sig/S-L-plus-1"), occurrences=2, replace_all=True),
        _m("ed25519-signature-length", "ed25519.py", "ed25519.signature-length",
           "drop the 64-byte signature length check",
           r'if len\(signature\) != 64:',
           'if False:  # ablation: signature length check disabled',
           ("sig/signature-short",),
           equivalent_reason="the envelope validates ed25519 signature entries as strict 64-byte "
           "base64url (E_ENV_SIG_VALUE), so this defence-in-depth check is unreachable"),
        _m("ed25519-public-key-length", "ed25519.py", "ed25519.public-key-length",
           "drop the 32-byte public key length check",
           r'if len\(public_key\) != 32:',
           'if False:  # ablation: public key length check disabled',
           ("sig/noncanonical-public-key",),
           equivalent_reason="declared/rotated key material is decoded to exactly 32 bytes before "
           "verification (E_KEY_PUBLIC_KEY/E_KEY_ROTATION_KEYS), so a wrong-length key never "
           "reaches this defence-in-depth check"),
        _m("ed25519-equation", "ed25519.py", "ed25519.equation",
           "skip the cofactorless verification equation",
           r'try:\n\s*from cryptography\.hazmat\.primitives\.asymmetric\.ed25519 import Ed25519PublicKey\n\n\s*Ed25519PublicKey\.from_public_bytes\(public_key\)\.verify\(signature, message\)\n\s*except Exception as error:\n\s*raise WeaveError\(\n\s*"E_SIG_INVALID", "Ed25519 verification equation does not hold"\n\s*\) from error',
           'return  # ablation: cofactorless equation not verified',
           ("sig/invalid-value", "sig/wrong-key-value")),
        # ---------------------------------------------------------------------- envelope
        _m("envelope-stage-accepted", "envelope.py", "envelope.stage-accepted-kinds",
           "allow the special kinds to use a non-accepted stage",
           r'raise WeaveError\("E_ENV_STAGE", "this kind requires stage accepted"\)',
           'pass  # ablation: accepted-stage requirement disabled',
           ("stage/key-declared-not-accepted",)),
        _m("envelope-unknown-field", "envelope.py", "envelope.closed-top-level",
           "stop rejecting unknown top-level members",
           r'raise WeaveError\("E_ENV_UNKNOWN_FIELD", "unknown top-level member %r" % member\)',
           'pass  # ablation: closed-top-level check disabled',
           ("stage/unknown-envelope-member",)),
        _m("envelope-salt-missing", "envelope.py", "envelope.salt-required",
           "allow personal/local-only labels without a salt",
           r'raise WeaveError\("E_ENV_SALT_MISSING", "salt is required for this sensitivity"\)',
           'pass  # ablation: salt requirement disabled',
           ("labels/personal-missing-salt",)),
        _m("envelope-agent-grant-missing", "envelope.py", "envelope.agent-grant-required",
           "allow an agent record without actor.grant",
           r'raise WeaveError\("E_ENV_ACTOR_GRANT_MISSING", "agent actor requires grant"\)',
           'pass  # ablation: agent grant requirement disabled',
           ("actor/agent-missing-grant",),
           equivalent_reason="the agent-authorisation layer raises the same "
           "E_ENV_ACTOR_GRANT_MISSING for a missing grant, so the envelope check is redundant"),
        _m("envelope-sigs-order", "envelope.py", "envelope.sigs-order",
           "stop enforcing sorted/unique signature entries",
           r'raise WeaveError\("E_ENV_SIGS", "sigs must be sorted by key and have unique keys"\)',
           'pass  # ablation: sigs sorted/unique check disabled',
           ("sig/unsorted-sigs", "sig/duplicate-sigs")),
        _m("envelope-kind-syntax", "envelope.py", "envelope.kind-syntax",
           "stop rejecting malformed kind names",
           r'raise WeaveError\("E_ENV_KIND_SYNTAX", "kind is not a well-formed kind name"\)',
           'pass  # ablation: kind-name syntax check disabled',
           ("stage/kind-syntax",)),
        _m("envelope-id-grammar", "envelope.py", "envelope.id-grammar",
           "stop validating the record id grammar",
           r'raise WeaveError\("E_ENV_ID", "id violates the id grammar"\)',
           'pass  # ablation: id grammar check disabled',
           ("stage/bad-id",)),
        # ------------------------------------------------------- record signature pipeline
        _m("record-required-signature", "verifier.py", "verifier.sig.required",
           "allow a record that requires per-record signing to have no sigs",
           r'raise WeaveError\("E_SIG_REQUIRED", "record requires a per-record signature"\)',
           'pass  # ablation: required-signature presence check disabled',
           ("sig/missing-required-signature", "erasure/unsigned")),
        _m("record-sig-unverifiable", "verifier.py", "verifier.sig.unverifiable",
           "report invalid instead of unverifiable when the required signature only has unknown-alg entries",
           r'"E_SIG_UNVERIFIABLE",\n\s*"the required signature only has unknown-algorithm entries",',
           '"E_SIG_INVALID",\n            "ablation: unknown-alg required signature treated as invalid",',
           ("sig/unknown-alg",)),
        _m("record-sig-unknown-alg-ignored", "verifier.py", "verifier.sig.q13-unknown-alg",
           "treat unknown-algorithm signature entries as invalid instead of ignored",
           r'if not signature\.is_ed25519:\n\s*# Q13: unknown algorithms are ignored, never invalidating\.\n\s*states\.append\(\{"key": signature\.key, "state": "ignored"\}\)\n\s*continue',
           'if not signature.is_ed25519:\n                raise WeaveError("E_SIG_INVALID", "ablation: unknown algorithm rejected")\n                continue',
           ("sig/unknown-alg-with-known-valid", "sig/unknown-alg-optional")),
        _m("record-sig-cross-purpose-domain", "verifier.py", "verifier.sig.domain-separation",
           "accept a record signature made over the manifest domain prefix",
           r'            try:\n                ed25519\.verify_signature\(material, message, signature\.raw or b""\)\n            except WeaveError:\n                states\.append\(\{"key": signature\.key, "state": "invalid"\}\)\n                raise',
           '            try:\n                ed25519.verify_signature(material, message, signature.raw or b"")\n            except WeaveError:\n                try:\n                    ed25519.verify_signature(\n                        material, encoding.manifest_sig_message(digest), signature.raw or b""\n                    )\n                except WeaveError:\n                    states.append({"key": signature.key, "state": "invalid"})\n                    raise',
           ("sig/manifest-prefix-in-record",), review_a_survivor=True),
        _m("record-ref-kind-mismatch", "verifier.py", "verifier.refs.kind-mismatch",
           "ignore contradicting kind claims on references",
           r'if refs\.kind_claim_mismatch\(entry\.ref, resolution\):\n\s*mismatched = True',
           'if False:  # ablation: ref kind mismatch ignored\n                mismatched = True',
           ("ref/kind-mismatch", "labels/consent-kind-mismatch")),
        _m("record-consent-validity", "verifier.py", "verifier.consent.validity",
           "accept consent records whose valid_from is after valid_until",
           r'raise WeaveError\("E_CONSENT_VALIDITY", "consent valid_from is after valid_until"\)',
           'pass  # ablation: consent validity check disabled',
           ("labels/consent-validity",)),
        _m("record-erase-actor-agent", "verifier.py", "verifier.erasure.signer",
           "allow an agent erasure without actor.grant",
           r'raise WeaveError\("E_ERASE_ACTOR", "agent erasure requires a grant"\)',
           'pass  # ablation: erasure actor grant requirement disabled',
           ("erasure/actor-agent-without-grant",),
           equivalent_reason="the fallback path catches the authorisation error and re-raises the "
           "same E_ERASE_ACTOR, so removing the first branch cannot change the verdict"),
        _m("record-erase-actor-basis", "verifier.py", "verifier.erasure.signer",
           "allow a program/device erasure whose basis grant lacks the erase action",
           r'raise WeaveError\("E_ERASE_ACTOR", "basis grant does not allow erase"\)',
           'pass  # ablation: erasure basis grant action check disabled',
           ("erasure/actor-program-without-grant",)),
        _m("record-human-key-class", "verifier.py", "verifier.actor.key-class",
           "allow a human/organization key to co-sign a non-human record",
           r'raise WeaveError\(\s*"E_ACTOR_HUMAN_KEY",\n\s*"human/organization key co-signed a non-human record",?\n\s*\)',
           'pass  # ablation: human-key co-signature class check disabled',
           ("actor/agent-extra-human-signature", "actor/program-human-signature")),
        _m("record-actor-key-class", "verifier.py", "verifier.actor.key-class",
           "allow actor.type to disagree with a signing key class",
           r'raise WeaveError\(\s*"E_ACTOR_KEY_TYPE_MISMATCH",\n\s*"actor\.key class is incompatible with actor\.type",?\n\s*\)',
           'pass  # ablation: actor/signing-key class match disabled',
           ("actor/agent-with-human-key",)),
        _m("record-human-signature-notice", "verifier.py", "verifier.notice.human-signature",
           "stop emitting N_NO_HUMAN_SIGNATURE on accepted records",
           r'if envelope\.stage == "accepted" and not _has_human_signature\(view, context\):\n\s*view\.notices\.append\("N_NO_HUMAN_SIGNATURE"\)',
           'if False:  # ablation: human-signature notice disabled\n            pass',
           ("actor/agent-accepted-valid",)),
        _m("record-self-attested-root-notice", "verifier.py", "verifier.notice.self-attested-root",
           "stop emitting N_SELF_ATTESTED_ROOT_KEY for bootstrap root keys",
           r'view\.notices\.append\("N_SELF_ATTESTED_ROOT_KEY"\)',
           'pass  # ablation: self-attested root notice disabled',
           ("key-lifecycle/declared-human-self-attested-valid",)),
        # ------------------------------------------------------------------------ grants
        _m("grant-revoke-as-authority", "grants.py", "grants.parent.action",
           "accept a weave.grant revoke record as an authorising grant",
           r'if envelope\.kind != kinds\.KIND_GRANT or envelope\.body\.get\("action"\) != "grant":\n\s*raise WeaveError\("E_GRANT_GRANTER", "reference does not resolve to an authorising grant"\)',
           'if False:  # ablation: revoke record accepted as authorising grant\n        pass',
           ("grant/revoke-grant-as-authority",), review_a_survivor=True),
        _m("grant-delegation-parent-action", "grants.py", "grants.delegation.parent-capabilities",
           "allow a parent grant that does not authorise granting",
           r'if "weave\.grant" not in parent\.kind_names or "grant" not in parent\.actions:',
           'if False:  # ablation: parent capability check disabled',
           ("grant/sub-grant-parent-lacks-grant-action",)),
        _m("grant-delegation-transferable", "grants.py", "grants.delegation.transferable",
           "allow delegation from a non-transferable parent grant",
           r'if not parent\.transferable:',
           'if False:  # ablation: transferable check disabled',
           ("grant/sub-grant-not-transferable",)),
        _m("grant-delegation-granter", "grants.py", "grants.delegation.granter-identity",
           "stop checking that the parent grantee is the sub-granting key",
           r'if parent\.grantee_key != child\.actor_key:',
           'if False:  # ablation: delegated granter identity check disabled',
           ("grant/sub-grant-granter-mismatch",), review_a_survivor=True),
        _m("grant-delegation-kinds", "grants.py", "grants.delegation.kinds",
           "allow a sub-grant to expand the kinds of its parent",
           r'if not set\(child\.kind_names\)\.issubset\(set\(parent\.kind_names\)\):',
           'if False:  # ablation: delegation kinds subset check disabled',
           ("grant/sub-grant-expands-kinds",)),
        _m("grant-delegation-actions", "grants.py", "grants.delegation.actions",
           "allow a sub-grant to expand the actions of its parent",
           r'if not set\(child\.actions\)\.issubset\(set\(parent\.actions\)\):',
           'if False:  # ablation: delegation actions subset check disabled',
           ("grant/sub-grant-expands-actions",)),
        _m("grant-delegation-scope", "grants.py", "grants.delegation.scope",
           "allow a sub-grant to expand the scope of its parent",
           r'if not set\(child\.scopes\)\.issubset\(set\(parent\.scopes\)\):',
           'if False:  # ablation: delegation scope subset check disabled',
           ("grant/sub-grant-scope-expands",)),
        _m("grant-delegation-valid-from", "grants.py", "grants.delegation.window",
           "allow a sub-grant to start before its parent",
           r'if timestamp_sort_key\(child\.valid_from\) < timestamp_sort_key\(parent\.valid_from\):',
           'if False:  # ablation: delegation valid_from bound disabled',
           ("grant/sub-grant-outside-window",), review_a_survivor=True),
        _m("grant-delegation-valid-until", "grants.py", "grants.delegation.window",
           "allow a sub-grant to end after its parent",
           r'if parent_until is not None and \(\n\s*child\.valid_until is None\n\s*or timestamp_sort_key\(child\.valid_until\) > parent_until\n\s*\):',
           'if False:  # ablation: delegation valid_until bound disabled',
           ("grant/sub-grant-outside-window",), review_a_survivor=True),
        _m("grant-parent-revoked", "grants.py", "grants.delegation.parent-revoked",
           "ignore revocation of the parent grant",
           r'if context\.grant_state\.revocation_as_of\(parent\.digest, at_time\) is not None:',
           'if False:  # ablation: parent grant revocation check disabled',
           ("grant/sub-grant-parent-revoked",), review_a_survivor=True),
        _m("grant-parent-expired", "grants.py", "grants.delegation.parent-window",
           "ignore that the parent grant is not yet valid",
           r'if timestamp_sort_key\(at_time\) < timestamp_sort_key\(parent\.valid_from\):',
           'if False:  # ablation: parent grant lower-window check disabled',
           ("grant/sub-grant-parent-expired",), review_a_survivor=True),
        _m("grant-chain-depth", "grants.py", "grants.chain.depth",
           "remove the grant chain depth guard",
           r'if depth > MAX_CHAIN_DEPTH or grant\.digest in seen:',
           'if grant.digest in seen:  # ablation: chain depth guard removed',
           ("grant/chain-depth",)),
        _m("grant-chain-cycle", "grants.py", "grants.chain.cycle",
           "remove the grant chain cycle guard",
           r'if depth > MAX_CHAIN_DEPTH or grant\.digest in seen:',
           'if depth > MAX_CHAIN_DEPTH:  # ablation: chain cycle guard removed',
           (),
           equivalent_reason="a grant-chain cycle is unconstructible in an authenticated "
           "content-addressed DAG (chain references point at already-signed grant digests); "
           "the guard is defensive only, and rotation-cycle coverage is provided by the "
           "keyset/lifecycle vectors"),
        _m("grant-agent-grantee", "grants.py", "grants.agent.grantee",
           "allow an agent record whose actor.key is not the grant's grantee",
           r'if grant\.grantee_key != envelope\.actor_key:',
           'if False:  # ablation: grantee mismatch check disabled',
           ("actor/agent-accepted-grantee-mismatch",)),
        _m("grant-agent-kind", "grants.py", "grants.agent.kind-coverage",
           "allow an agent record whose kind is not covered by its grant",
           r'if envelope\.kind not in grant\.kind_names:',
           'if False:  # ablation: grant kind coverage disabled',
           ("actor/agent-accepted-kind-not-granted",)),
        _m("grant-agent-action", "grants.py", "grants.agent.action-coverage",
           "allow an agent record whose stage action is not covered by its grant",
           r'if action not in grant\.actions:',
           'if False:  # ablation: grant action coverage disabled',
           ("actor/agent-accepted-action-not-granted",)),
        _m("grant-revoke-ref", "grants.py", "grants.revocation.ref",
           "accept a grant-revocation reference that does not resolve to an authorising grant",
           r'raise WeaveError\("E_GRANT_REVOKE_REF", "revoked target is not an authorising grant"\)',
           'pass  # ablation: grant revocation reference check disabled',
           ("grant/revoke-bad-ref",)),
        # ------------------------------------------------------------------------ labels
        _m("label-downgrade-absent", "labels.py", "labels.propagation.absent",
           "allow a derived record with no sensitivity when its input is not public",
           r'raise WeaveError\(\s*"E_LABEL_DOWNGRADE",\n\s*"derived record has no sensitivity while its input is not public",?\n\s*\)',
           'pass  # ablation: absent-sensitivity downgrade check disabled',
           ("labels/downgrade-absent-sensitivity",)),
        _m("label-downgrade-rank", "labels.py", "labels.propagation.rank",
           "allow a derived record less sensitive than its input",
           r'raise WeaveError\(\n\s*"E_LABEL_DOWNGRADE", "derived record is less sensitive than its input"\n\s*\)',
           'pass  # ablation: label rank comparison disabled',
           ("labels/downgrade",)),
        _m("label-consent-revoked", "labels.py", "labels.consent.revoked",
           "allow a record citing a consent withdrawn before recorded_at",
           r'raise WeaveError\(\s*"E_CONSENT_REVOKED",\n\s*"the cited consent was withdrawn at or before the record\'s recorded_at",?\n\s*\)',
           'pass  # ablation: consent withdrawal check disabled',
           ("labels/consent-revoked-referenced",)),
        _m("label-local-only-export", "container.py", "labels.local-only",
           "allow local-only records in an export container",
           r'errors\.append\("E_LABEL_LOCAL_ONLY_EXPORTED"\)',
           'pass  # ablation: local-only export refusal disabled',
           ("labels/local-only-exported",)),
        # -------------------------------------------------------------------------- keys
        _m("key-expired-before-valid-from", "keys.py", "keys.validity.lower",
           "ignore declarations' valid_from lower window",
           r'raise WeaveError\("E_KEY_EXPIRED", "signature made before valid_from"\)',
           'pass  # ablation: valid_from check disabled',
           ("key-lifecycle/sign-before-valid-from",), review_a_survivor=False),
        _m("key-expired-after-valid-until", "keys.py", "keys.validity.upper",
           "ignore declarations' valid_until upper window",
           r'raise WeaveError\("E_KEY_EXPIRED", "signature made after valid_until"\)',
           'pass  # ablation: valid_until check disabled',
           ("key-lifecycle/expired-then-signed",)),
        _m("key-retired-boundary", "keys.py", "keys.revocation.retired",
           "ignore retired-key revocations",
           r'raise WeaveError\("E_KEY_REVOKED", "signature made at or after a retired revocation"\)',
           'pass  # ablation: retired revocation effect disabled',
           ("key-lifecycle/retired-then-signed-after",)),
        _m("key-compromise-never-rescued", "keys.py", "keys.revocation.compromise-rescue",
           "never rescue compromise signatures with an earlier verified timestamp",
           r'rescued = any\(\n\s*timestamp\.gen_time_ms <= revocation\.effective_at_ms\n\s*for timestamp in verified_timestamps\n\s*\)',
           'rescued = False  # ablation: compromise rescue disabled',
           ("key-lifecycle/compromise-rescued-by-timestamp",)),
        _m("key-compromise-always-rescued", "keys.py", "keys.revocation.compromise",
           "always rescue compromise signatures (never fail closed)",
           r'if rescued:\n\s*continue',
           'if True:  # ablation: every compromise signature rescued\n                continue',
           ("key-lifecycle/compromise-backdated-forgery", "key-lifecycle/compromise-retroactive"),
           review_a_survivor=True),
        _m("key-owner-missing", "keys.py", "keys.declaration.owner",
           "allow agents/programs/devices without a declared owner",
           r'raise WeaveError\("E_KEY_OWNER_MISSING", "missing owner"\)',
           'pass  # ablation: owner requirement disabled',
           ("key-lifecycle/declared-agent-without-owner",)),
        _m("key-id-mismatch", "keys.py", "keys.declaration.key-id",
           "stop deriving the key id from the declared public key",
           r'raise WeaveError\("E_KEY_ID_MISMATCH", "declared key id does not derive from public_key"\)',
           'pass  # ablation: key id derivation check disabled',
           ("key-lifecycle/key-id-mismatch",)),
        _m("key-validity-window", "keys.py", "keys.declaration.validity",
           "accept declarations with valid_from after valid_until",
           r'raise WeaveError\("E_KEY_VALIDITY", "valid_from is after valid_until"\)',
           'pass  # ablation: declaration validity window check disabled',
           ("key-lifecycle/declared-validity",)),
        _m("key-rotation-keys", "keys.py", "keys.rotation.keys",
           "accept a rotation using the same key as old and new",
           r'raise WeaveError\("E_KEY_ROTATION_KEYS", "old_key and new_key are the same key"\)',
           'pass  # ablation: rotation old/new distinctness disabled',
           ("key-lifecycle/rotation-same-key",)),
        _m("key-rotation-signatures", "verifier.py", "keys.rotation.signatures",
           "accept a rotation not signed by both old and new keys",
           r'_require_valid_signer\(view, context, view\.key_rotation\.(?:old|new)_key, "E_KEY_ROTATION_SIGS"\)',
           'pass  # ablation: rotation dual-signature check disabled',
           ("key-lifecycle/rotation-missing-new-sig",), occurrences=2, replace_all=True),
        _m("key-revoke-effective", "keys.py", "keys.revocation.effective-at",
           "accept revocations whose effective_at is after recorded_at",
           r'raise WeaveError\("E_KEY_REVOKE_EFFECTIVE", "effective_at is after recorded_at"\)',
           'pass  # ablation: revocation effective_at check disabled',
           ("key-lifecycle/revoke-effective-after-record",)),
        _m("key-revoke-signer", "keys.py", "keys.revocation.signer",
           "accept revocations from any signature",
           r'raise WeaveError\("E_KEY_REVOKE_SIGNER", "revocation lacks an acceptable signer"\)',
           'pass  # ablation: revocation signer rule disabled',
           ("key-lifecycle/revoke-bad-signer",)),
        _m("key-declared-not-self-signed", "keys.py", "keys.declaration.self-signature",
           "accept a declaration with no valid signature by the declared key",
           r'raise WeaveError\(\n\s*"E_KEY_DECLARED_NOT_SELF_SIGNED",\n\s*"no valid signature by the declared key",?\n\s*\)',
           'pass  # ablation: self-signature requirement disabled',
           ("key-lifecycle/declared-not-self-signed",)),
        _m("key-agent-not-cosigned", "keys.py", "keys.declaration.cosignature",
           "accept an agent/program/device declaration without the owner cosignature",
           r'raise WeaveError\(\n\s*"E_KEY_DECLARED_NOT_COSIGNED",\n\s*"agent/program/device key declaration lacks the owner\'s cosignature",?\n\s*\)',
           'pass  # ablation: owner cosignature requirement disabled',
           ("key-lifecycle/declared-agent-not-cosigned",)),
        _m("key-human-not-cosigned", "keys.py", "keys.declaration.cosignature",
           "accept a human/organization declaration without a cosignature",
           r'raise WeaveError\(\n\s*"E_KEY_DECLARED_NOT_COSIGNED",\n\s*"human/organization key declaration lacks a cosignature",?\n\s*\)',
           'pass  # ablation: human cosignature requirement disabled',
           ("key-lifecycle/declared-human-not-cosigned",)),
        # ---------------------------------------------------------------------- container
        _m("container-manifest-digest", "container.py", "container.manifest.digest",
           "accept a manifest attestation whose digest does not match the manifest",
           r'if attestation\.digest != manifest_digest:',
           'if False:  # ablation: manifest digest comparison disabled',
           ("container/manifest-digest-wrong",)),
        _m("container-manifest-unsigned", "container.py", "container.manifest.unsigned",
           "accept an unsigned manifest attestation",
           r'raise WeaveError\("E_MANIFEST_UNSIGNED", "manifest attestation has no signatures"\)',
           'pass  # ablation: non-empty manifest signature requirement disabled',
           ("container/manifest-unsigned",)),
        _m("container-manifest-signature", "container.py", "container.manifest.signature",
           "accept a manifest signature that does not verify",
           r'raise WeaveError\(\n\s*"E_MANIFEST_SIG_INVALID", "manifest signature does not verify"\n\s*\) from error',
           'pass  # ablation: manifest signature verification disabled',
           ("container/manifest-sig-invalid",)),
        _m("container-manifest-cross-purpose-domain", "container.py", "container.manifest.domain-separation",
           "accept a manifest signature made over the record domain prefix",
           r'        try:\n            from \. import ed25519\n\n            ed25519\.verify_signature\(material, message, signature\.raw\)\n        except WeaveError as error:',
           '        try:\n            from . import ed25519\n\n            try:\n                ed25519.verify_signature(material, message, signature.raw)\n            except WeaveError:\n                ed25519.verify_signature(\n                    material, encoding.record_sig_message(manifest_digest), signature.raw\n                )\n        except WeaveError as error:',
           ("container/manifest-sig-record-prefix",), review_a_survivor=True),
        _m("container-previous-origin", "container.py", "container.chain.origin",
           "accept a previous manifest from a different origin",
           r'raise WeaveError\(\n\s*"E_MANIFEST_CHAIN", "previous manifest origin differs from the manifest origin"\n\s*\)',
           'pass  # ablation: previous-manifest origin check disabled',
           ("container/chain-origin-mismatch",)),
        _m("container-previous-digest", "container.py", "container.chain.digest",
           "accept an embedded previous manifest whose digest does not match",
           r'raise WeaveError\(\n\s*"E_MANIFEST_CHAIN", "embedded previous manifest digest does not match"\n\s*\)',
           'pass  # ablation: embedded previous digest check disabled',
           ("container/chain-digest-mismatch",)),
        _m("container-previous-external", "container.py", "container.chain.previous-flag",
           "ignore the --previous container comparison",
           r'raise WeaveError\(\n\s*"E_MANIFEST_CHAIN", "--previous manifest digest does not match"\n\s*\)',
           'pass  # ablation: --previous comparison disabled',
           ("container/previous-external-mismatch",), review_a_survivor=True),
        _m("container-chain-unexpected-first", "container.py", "container.chain.unexpected",
           "ignore the first unexpected-previous branch (previous/manifest.json present)",
           r'if embedded is not None:\n\s*raise WeaveError\(\n\s*"E_MANIFEST_CHAIN_UNEXPECTED",\n\s*"previous_manifest is null but previous/manifest\.json is present",\n\s*\)',
           'if False:  # ablation: first unexpected-previous branch disabled\n            pass',
           ("container/chain-unexpected",), review_a_survivor=True),
        _m("container-record-digest-name", "container.py", "container.records.digest",
           "accept a record file whose name does not match its computed digest",
           r'if match\.group\(1\) != record\.digest\.partition\(":"\)\[2\]:',
           'if False:  # ablation: record digest/filename check disabled',
           ("container/record-digest-mismatch",)),
        _m("container-record-id-kind", "container.py", "container.records.metadata",
           "accept a manifest entry whose id/kind disagrees with the record content",
           r'if record_entry\.id != record_id or record_entry\.kind != record_kind:',
           'if False:  # ablation: manifest id/kind cross-check disabled (Q22)',
           ("container/manifest-id-kind-mismatch",)),
        _m("container-blobs-extra", "container.py", "container.blobs.set",
           "accept blobs/ files that are not listed in the manifest",
           r'if blob_files:\n\s*raise WeaveError\("E_MANIFEST_BLOB", "blobs/ contains a file not listed in the manifest"\)',
           'if False:  # ablation: extra-blob check disabled\n        pass',
           ("container/blobs-mismatch",)),
        _m("container-anchor-verified", "container.py", "container.l2.anchor",
           "report anchor_verified for a claimed L2 even when the timestamp chain is not anchored",
           r'container\["anchor_verified"\] = bool\(\n\s*manifest\.level == "L2" and archive\.anchor_verified\n\s*\)',
           'container["anchor_verified"] = manifest.level == "L2"  # ablation: anchor verification assumed',
           ("integrity-levels/l2-without-trust",)),
        _m("container-level-verified", "container.py", "container.report.level",
           "claim level_verified L2 without an anchor (report wide claim)",
           r'"level_verified": "L0",',
           '"level_verified": "L2",  # ablation: claim L2 without verification',
           ("integrity-levels/l1-valid", "integrity-levels/l2-without-trust"),
           occurrences=2, replace_all=True),
        _m("container-erase-digest", "container.py", "container.erasure.digest-cross-check",
           "skip the erasure/placeholder digest cross-check",
           r'return "E_ERASE_DIGEST_MISMATCH"',
           'return None  # ablation: erasure digest cross-check disabled',
           ("erasure/digest-mismatch",), review_a_survivor=True,
           occurrences=3, replace_all=True),
        _m("container-erase-attestation", "container.py", "container.erasure.attestation-backref",
           "skip the placeholder attestation back-reference check",
           r'return "E_ERASE_ATTESTATION"',
           'return None  # ablation: attestation back-reference check disabled',
           ("erasure/attestation-missing",), review_a_survivor=True,
           occurrences=4, replace_all=True),
        _m("container-erase-contradiction", "container.py", "container.erasure.contradiction",
           "skip live-record/placeholder contradiction detection",
           r'return "E_ERASE_CONTRADICTION"',
           'return None  # ablation: erasure contradiction check disabled',
           ("erasure/contradiction",), occurrences=2, replace_all=True),
        # -------------------------------------------------------------------- timestamps
        _m("ts-status-granted", "timestamps.py", "timestamps.status",
           "accept a TimeStampResp whose PKIStatus is not granted",
           r'raise WeaveError\("E_TS_SCHEMA", "TimeStampResp status is not granted"\)',
           'pass  # ablation: granted-status check disabled',
           ("integrity-levels/l2-status-not-granted",), review_a_survivor=True),
        _m("ts-digest-algorithm", "timestamps.py", "timestamps.digest-algorithm",
           "accept a signerInfo digest algorithm other than sha256",
           r'raise WeaveError\("E_TS_SCHEMA", "signerInfo digest algorithm is not sha256"\)',
           'pass  # ablation: sha256 digest-algorithm requirement disabled',
           ("integrity-levels/l2-digest-alg-unsupported",)),
        _m("ts-imprint", "timestamps.py", "timestamps.imprint",
           "accept a messageImprint that does not match the manifest/anchor",
           r'raise WeaveError\("E_TS_IMPRINT", "messageImprint does not match the manifest/anchor"\)',
           'pass  # ablation: messageImprint comparison disabled',
           ("integrity-levels/l2-imprint-mismatch",), review_a_survivor=False),
        _m("ts-message-digest", "timestamps.py", "timestamps.message-digest",
           "accept signed attributes whose messageDigest does not match the eContent",
           r'raise WeaveError\("E_TS_CMS", "signed messageDigest does not match the eContent"\)',
           'pass  # ablation: signed messageDigest comparison disabled',
           ("integrity-levels/l2-message-digest-wrong",), review_a_survivor=True),
        _m("ts-content-type", "timestamps.py", "timestamps.content-type",
           "accept signed attributes whose content_type is not TSTInfo",
           r'raise WeaveError\("E_TS_CMS", "content_type attribute is not TSTInfo"\)',
           'pass  # ablation: content_type attribute check disabled',
           ("integrity-levels/l2-content-type-wrong",)),
        _m("ts-ess-signing-certificate-v2", "timestamps.py", "timestamps.ess-v2",
           "accept a token without ESS signingCertificateV2",
           r'if not signing_certificate_v2:\n\s*if signing_certificate_v1:\n\s*raise WeaveError\("E_TS_CMS", "only ESS signingCertificate v1 is present"\)\n\s*raise WeaveError\("E_TS_CMS", "ESS signingCertificateV2 attribute is missing"\)',
           'if False:  # ablation: ESS signingCertificateV2 requirement disabled\n        pass',
           ("integrity-levels/l2-ess-missing", "integrity-levels/l2-ess-v1-only"),
           review_a_survivor=True),
        _m("ts-certificate-in-token", "timestamps.py", "timestamps.certificate-in-token",
           "accept a signer certificate that is not carried in the token",
           r'raise WeaveError\("E_TS_CMS", "signer certificate not found in the token"\)',
           'pass  # ablation: in-token certificate requirement disabled',
           ("integrity-levels/l2-cert-not-in-token",), review_a_survivor=True),
        _m("ts-cms-signature", "timestamps.py", "timestamps.cms-signature",
           "skip the CMS signature verification",
           r'raise WeaveError\("E_TS_CMS", "CMS signature does not verify"\)',
           'pass  # ablation: CMS signature verification disabled',
           ("integrity-levels/l2-cms-tampered",), review_a_survivor=True,
           occurrences=2, replace_all=True),
        _m("ts-eku", "timestamps.py", "timestamps.eku",
           "accept a signer certificate without the timeStamping EKU",
           r'raise WeaveError\("E_TS_CERT", "signer certificate has no timeStamping EKU"\)',
           'pass  # ablation: timeStamping EKU requirement disabled',
           ("integrity-levels/l2-eku-missing",), review_a_survivor=True),
        _m("ts-eku-profile", "timestamps.py", "timestamps.eku",
           "accept a signer certificate that is not a timestamping certificate",
           r'raise WeaveError\("E_TS_CERT", "signer certificate is not a timestamping certificate"\)',
           'pass  # ablation: timestamping certificate profile check disabled',
           ("integrity-levels/l2-eku-missing",)),
        _m("ts-key-usage", "timestamps.py", "timestamps.key-usage",
           "accept a signer certificate whose key usage lacks digitalSignature",
           r'raise WeaveError\("E_TS_CERT", "signer certificate key usage lacks digitalSignature"\)',
           'pass  # ablation: digitalSignature key-usage check disabled',
           ("integrity-levels/l2-ku-missing",)),
        _m("ts-certificate-validity", "timestamps.py", "timestamps.certificate-validity",
           "accept a signer certificate that is not valid at genTime",
           r'raise WeaveError\("E_TS_CERT", "signer certificate is not valid at genTime"\)',
           'pass  # ablation: certificate validity-at-genTime check disabled',
           ("integrity-levels/l2-cert-expired",), review_a_survivor=True),
        _m("ts-trust-anchor", "timestamps.py", "timestamps.trust-anchor",
           "accept any TSA certificate as trusted",
           r'if fingerprint not in trust_anchor_fingerprints:',
           'if False:  # ablation: trust-anchor fingerprint comparison disabled',
           ("integrity-levels/l2-anchor-mismatch",)),
        _m("ts-file-digest", "timestamps.py", "timestamps.archive.file-digest",
           "accept a listed timestamp file whose bytes do not hash to its listed digest",
           r'archive\.errors\.append\("E_TS_FILE"\)',
           'pass  # ablation: timestamp file digest check disabled',
           ("integrity-levels/l2-ts-file-digest",),
           occurrences=2, replace_all=True),
        _m("ts-renewal-chain", "timestamps.py", "timestamps.renewal-chain",
           "accept a broken timestamp renewal chain",
           r'archive\.errors\.append\("E_TS_RENEWAL"\)',
           'pass  # ablation: renewal chain check disabled',
           ("integrity-levels/l2-renewal-broken",)),
        # ------------------------------------------------------------------- manifest level
        _m("manifest-l0-with-chain", "manifest.py", "manifest.level.l0-chain",
           "accept an L0 manifest carrying a chain head",
           r'_fail\("E_MANIFEST_LEVEL", "an L0 manifest must not carry a chain"\)',
           'pass  # ablation: L0-must-not-carry-chain check disabled',
           ("container/l0-with-chain",), review_a_survivor=True),
        _m("manifest-l1-no-head", "manifest.py", "manifest.level.l1-head",
           "accept a claimed L1 manifest without a chain head",
           r'_fail\("E_MANIFEST_L1_NO_HEAD", "an L1/L2 manifest requires chain"\)',
           'pass  # ablation: L1 chain-head requirement disabled',
           ("integrity-levels/l1-no-head",)),
        _m("manifest-l1-no-position", "manifest.py", "manifest.level.l1-position",
           "accept an L1 manifest whose records lack chain_index",
           r'_fail\(\n\s*"E_MANIFEST_L1_NO_POSITION",\n\s*"every L1/L2 record entry requires a unique chain_index",\n\s*\)',
           'pass  # ablation: L1 chain-position requirement disabled',
           ("integrity-levels/l1-no-position",)),
        _m("manifest-l2-no-timestamp", "manifest.py", "manifest.level.l2-timestamp",
           "accept a claimed L2 manifest without any timestamp",
           r'_fail\("E_MANIFEST_L2_NO_TIMESTAMP", "an L2 manifest must list a timestamp"\)',
           'pass  # ablation: L2 timestamp-listing requirement disabled',
           ("integrity-levels/l2-no-timestamp",)),
        # -------------------------------------------------------------------- refs resolution
        _m("refs-kind-claim", "refs.py", "refs.kind-claim",
           "never report a contradicting kind claim on a reference",
           r'return target_kind is not None and target_kind != reference\.kind',
           'return False  # ablation: reference kind claim mismatch disabled',
           ("ref/kind-mismatch",)),
    )


_build_catalogue()


# ----------------------------------------------------------------------------- runner


def fail(message: str) -> "NoReturn":  # type: ignore[name-defined]
    print("anti_verification: %s" % message, file=sys.stderr)
    raise SystemExit(2)


def check_baseline(suite: Path) -> dict:
    """Gate 2 must be green before ablation means anything."""
    argv = [PYTHON, "-m", "hyphaweave_verify.cli", "vectors", str(suite)]
    env = dict(os.environ)
    env.pop("WEAVE_VERIFY_SKIP_CHECKS", None)
    env["PYTHONHASHSEED"] = "0"
    proc = subprocess.run(argv, capture_output=True, text=True, cwd=str(REPO), env=env)
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError:
        fail("baseline vector run produced no JSON (rc=%d): %s" % (proc.returncode, proc.stderr[-800:]))
    if proc.returncode != 0 or report.get("verdict") != "valid":
        fail(
            "baseline vector suite is not green (rc=%d, verdict=%r); gate 3 requires gate 2 first"
            % (proc.returncode, report.get("verdict"))
        )
    return report


def copy_package(destination: Path) -> Path:
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    target = destination / "hyphaweave_verify"
    shutil.copytree(
        PACKAGE_DIR,
        target,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    return target


def apply_mutation(mutation: Mutation, package_copy: Path) -> Path:
    source_path = package_copy / mutation.module
    if not source_path.is_file():
        raise RuntimeError("module %r missing from the package copy" % mutation.module)
    text = source_path.read_text(encoding="utf-8")
    matches = list(re.finditer(mutation.anchor, text, re.MULTILINE))
    if len(matches) != mutation.occurrences:
        raise RuntimeError(
            "stale catalogue: anchor regex for %s matches %d site(s) in %s, expected %d"
            % (mutation.id, len(matches), mutation.module, mutation.occurrences)
        )
    if mutation.replace_all:
        mutated = re.sub(mutation.anchor, mutation.replacement, text, flags=re.MULTILINE)
    else:
        mutated = re.sub(mutation.anchor, mutation.replacement, text, count=1, flags=re.MULTILINE)
    if mutated == text:
        raise RuntimeError("mutation %s did not change the source" % mutation.id)
    source_path.write_text(mutated, encoding="utf-8")
    return source_path


def mutant_env(mutant_dir: Path) -> dict[str, str]:
    env = dict(os.environ)
    env.pop("WEAVE_VERIFY_SKIP_CHECKS", None)
    env["PYTHONHASHSEED"] = "0"
    previous = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(mutant_dir) if not previous else str(mutant_dir) + os.pathsep + previous
    return env


def imported_file(env: dict[str, str]) -> str:
    proc = subprocess.run(
        [PYTHON, "-c", "import hyphaweave_verify; print(hyphaweave_verify.__file__)"],
        capture_output=True,
        text=True,
        cwd=str(REPO),
        env=env,
    )
    if proc.returncode != 0:
        raise RuntimeError("mutant package import probe failed: %s" % proc.stderr[-500:])
    return proc.stdout.strip()


def run_mutation(mutation: Mutation, suite: Path) -> MutationResult:
    mutant_dir = MUTANT_ROOT / mutation.id
    try:
        package_copy = copy_package(mutant_dir)
        apply_mutation(mutation, package_copy)
        env = mutant_env(mutant_dir)
        resolved = imported_file(env)
        if not str(mutant_dir.resolve()) in resolved:
            raise RuntimeError(
                "mutant package was not imported: __file__=%r expected under %r"
                % (resolved, str(mutant_dir))
            )
        argv = [PYTHON, "-m", "hyphaweave_verify.cli", "vectors", str(suite)]
        proc = subprocess.run(argv, capture_output=True, text=True, cwd=str(REPO), env=env)
        report = None
        if proc.stdout.strip():
            try:
                report = json.loads(proc.stdout)
            except json.JSONDecodeError:
                report = None
        mismatched = 0
        if report is not None:
            mismatched = sum(1 for case in report.get("cases") or [] if not case.get("ok"))
        killed = proc.returncode != 0 or (report is not None and report.get("verdict") != "valid")
        if killed:
            detail = "vectors no longer match (rc=%d, %d mismatched case(s))" % (
                proc.returncode,
                mismatched,
            )
            return MutationResult(
                mutation,
                "killed",
                detail=detail,
                imported_file=resolved,
                exit_code=proc.returncode,
                report_verdict=(report or {}).get("verdict"),
                mismatched_cases=mismatched,
            )
        return MutationResult(
            mutation,
            "survivor",
            detail="all vectors still valid; this check is not pinned by any vector",
            imported_file=resolved,
            exit_code=proc.returncode,
            report_verdict=(report or {}).get("verdict"),
            mismatched_cases=0,
        )
    except RuntimeError as error:
        return MutationResult(mutation, "error", detail=str(error))
    finally:
        # Keep the mutant only on failure/mismatch for debugging; successful runs are
        # cleaned up immediately so a full sweep stays small.
        pass


def pytest_on_survivor(result: MutationResult) -> str:
    mutant_dir = MUTANT_ROOT / result.mutation.id
    env = mutant_env(mutant_dir)
    proc = subprocess.run(
        [PYTHON, "-m", "pytest", "verifiers/python/tests", "-q"],
        capture_output=True,
        text=True,
        cwd=str(REPO),
        env=env,
    )
    return "no" if proc.returncode == 0 else "yes"


# -------------------------------------------------------------------------------- main


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--list", action="store_true", help="list the mutation catalogue and exit")
    parser.add_argument("--json", metavar="PATH", default=str(REPORT_PATH))
    parser.add_argument("--jobs", type=int, default=min(8, os.cpu_count() or 4))
    parser.add_argument("--only", default="", help="comma separated mutation ids")
    parser.add_argument("--suite", default=str(DEFAULT_SUITE))
    parser.add_argument("--self-test", action="store_true", help="validate anchors without running")
    parser.add_argument("--pytest-survivors", action="store_true", help="run pytest on survivors")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--keep", action="store_true", help="keep mutant directories on success")
    args = parser.parse_args(argv)

    if not PACKAGE_DIR.is_dir():
        fail("verifier package not found at %s" % PACKAGE_DIR)
    suite = Path(args.suite)
    if not suite.is_dir():
        fail("vector suite directory not found: %s" % suite)
    selected = [item for item in CATALOGUE if not args.only or item.id in set(args.only.split(","))]
    if not selected:
        fail("no mutations selected (catalogue size %d)" % len(CATALOGUE))

    if args.list:
        for item in selected:
            print("%-38s %-18s %-14s %s" % (item.id, item.module, item.check, item.description))
        return 0

    if args.self_test:
        problems: list[str] = []
        for item in selected:
            path = PACKAGE_DIR / item.module
            if not path.is_file():
                problems.append("%s: module %s missing" % (item.id, item.module))
                continue
            text = path.read_text(encoding="utf-8")
            count = len(re.findall(item.anchor, text, re.MULTILINE))
            if count != item.occurrences:
                problems.append(
                    "%s: anchor occurs %d time(s) in %s, expected %d"
                    % (item.id, count, item.module, item.occurrences)
                )
        for problem in problems:
            print("STALE: %s" % problem)
        print("catalogue: %d mutation(s), %d stale anchor problem(s)" % (len(selected), len(problems)))
        return 0 if not problems else 1

    print("anti_verification: baseline vector run ...")
    baseline = check_baseline(suite)
    summary = baseline.get("summary") or {}
    print(
        "anti_verification: baseline green (%d cases, verdict=%s)"
        % (summary.get("case_count", len(baseline.get("cases") or [])), baseline.get("verdict"))
    )
    MUTANT_ROOT.mkdir(parents=True, exist_ok=True)
    for item in selected:
        if (MUTANT_ROOT / item.id).exists():
            shutil.rmtree(MUTANT_ROOT / item.id)
    results: list[MutationResult] = []
    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        futures = {
            pool.submit(run_mutation, item, suite): item for item in selected
        }
        for future in futures:
            result = future.result()
            results.append(result)
            if args.verbose:
                print(
                    "  %-38s %-8s %s"
                    % (result.mutation.id, result.status, result.detail)
                )
    results.sort(key=lambda item: item.mutation.id)
    if args.pytest_survivors:
        for result in results:
            if result.status == "survivor":
                result.pytest_caught = pytest_on_survivor(result)
    survivors = [item for item in results if item.status == "survivor"]
    unpinned = [item for item in survivors if not item.mutation.equivalent_reason]
    equivalents = [item for item in survivors if item.mutation.equivalent_reason]
    errors = [item for item in results if item.status == "error"]
    killed = [item for item in results if item.status == "killed"]

    if not args.keep:
        for item in results:
            if item.status == "killed":
                shutil.rmtree(MUTANT_ROOT / item.mutation.id, ignore_errors=True)

    report = {
        "gate": "3a-source-ablation",
        "ok": not unpinned and not errors,
        "catalogue_size": len(selected),
        "killed": len(killed),
        "survivors": len(survivors),
        "unpinned_survivors": len(unpinned),
        "equivalent_mutants": len(equivalents),
        "errors": len(errors),
        "mutations": [
            {
                "id": item.mutation.id,
                "module": item.mutation.module,
                "check": item.mutation.check,
                "description": item.mutation.description,
                "pinned_by": list(item.mutation.pinned_by),
                "review_a_survivor": item.mutation.review_a_survivor,
                "equivalent_reason": item.mutation.equivalent_reason,
                "status": item.status,
                "detail": item.detail,
                "imported_file": item.imported_file,
                "exit_code": item.exit_code,
                "report_verdict": item.report_verdict,
                "mismatched_cases": item.mismatched_cases,
                "pytest_caught": item.pytest_caught,
            }
            for item in results
        ],
    }
    report_path = Path(args.json)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print()
    print(
        "source ablation: %d mutations, %d killed, %d survivors (%d unpinned, %d documented equivalent), "
        "%d catalogue errors"
        % (len(selected), len(killed), len(survivors), len(unpinned), len(equivalents), len(errors))
    )
    for item in errors:
        print("  CATALOGUE ERROR %s: %s" % (item.mutation.id, item.detail))
    for item in equivalents:
        print("  EQUIVALENT (documented): %s :: %s" % (item.mutation.id, item.mutation.equivalent_reason))
    if unpinned:
        print("SURVIVORS (checks not pinned by any vector):")
        for item in unpinned:
            survivor_tag = " [review-a survivor]" if item.mutation.review_a_survivor else ""
            pytest_tag = " pytest_caught=%s" % item.pytest_caught if args.pytest_survivors else ""
            print("  %s%s%s :: %s" % (item.mutation.id, survivor_tag, pytest_tag, item.mutation.description))
        print("RESULT: FAIL")
        return 1
    if errors:
        print("RESULT: FAIL (stale mutation catalogue)")
        return 1
    print("summary written to %s" % report_path.relative_to(REPO))
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
