#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0
"""H0 revision-1 gate 3(a): true source-level mutation ablation of the verifier.

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
from dataclasses import dataclass
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
    #: further (module, anchor-regex, replacement) patches that implement the same
    #: semantic elsewhere.  When the single-site mutation survives, the harness applies
    #: this site *and* the co-sites together and requires the vectors to go red; that
    #: proves the semantic is pinned even though one redundant site is invisible alone.
    co_mutations: tuple[tuple[str, str, str], ...] = ()


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
    mismatched_case_ids: tuple[str, ...] = ()
    kill_kind: str = ""  # "mismatch" only: a crash is a catalogue error (V2d)


#: Curated mutation catalogue.  ``check`` groups mutations by verifier check class;
#: ``review_a_survivor`` marks the 24 survivors from review-a (they MUST all be killed
#: by vectors once the revision-1 vectors land).
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
    co_mutations: tuple[tuple[str, str, str], ...] = (),
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
        co_mutations=co_mutations,
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
        _m("ed25519-x0-sign-bit", "ed25519.py", "ed25519.decode.x0-sign",
           "accept x == 0 with the sign bit set",
           r'if sign:\n\s*# RFC 8032[^\n]*\n\s*raise WeaveError\(noncanonical_code, "x == 0 with the sign bit set"\)',
           'pass  # ablation: x==0 sign-bit rejection disabled',
           ("sig/x0-sign-bit-A", "sig/x0-sign-bit-R"),
        ),
        _m("ed25519-small-order-A", "ed25519.py", "ed25519.small-order-A",
           "accept small-order public keys",
           r'if order_class == "small":',
           'if False:  # ablation: small-order A rejection disabled',
           ("sig/small-order-A-00", "sig/small-order-A-01")),
        _m("ed25519-mixed-order-A", "ed25519.py", "ed25519.mixed-order-A",
           "accept mixed-order public keys (not in the prime-order subgroup)",
           r'if order_class == "mixed":',
           'if False:  # ablation: mixed-order A rejection disabled',
           ("sig/mixed-order-A",), review_a_survivor=True),
        _m("ed25519-small-order-R", "ed25519.py", "ed25519.small-order-R",
           "accept small-order R values",
           r'if _is_small_order\(r_point\):',
           'if False:  # ablation: small-order R rejection disabled',
           ("sig/small-order-R-00",)),
        _m("ed25519-s-out-of-range", "ed25519.py", "ed25519.s-out-of-range",
           "accept S >= L (non-canonical scalar)",
           r'if s >= L:',
           'if False:  # ablation: S range check disabled',
           ("sig/S-equals-L", "sig/S-L-plus-1"), occurrences=2, replace_all=True),
        _m("ed25519-signature-length", "ed25519.py", "ed25519.signature-length",
           "drop the 64-byte signature length check",
           r'if len\(signature\) != 64:',
           'if False:  # ablation: signature length check disabled',
           (),
           equivalent_reason="the envelope validates ed25519 signature entries as strict 64-byte "
           "base64url (E_ENV_SIG_VALUE), so this defence-in-depth check is unreachable"),
        _m("ed25519-public-key-length", "ed25519.py", "ed25519.public-key-length",
           "drop the 32-byte public key length check",
           r'if len\(public_key\) != 32:',
           'if False:  # ablation: public key length check disabled',
           (),
           equivalent_reason="declared/rotated key material is decoded to exactly 32 bytes before "
           "verification (E_KEY_PUBLIC_KEY/E_KEY_ROTATION_KEYS), so a wrong-length key never "
           "reaches this defence-in-depth check"),
        _m("ed25519-equation", "ed25519.py", "ed25519.equation",
           "skip the cofactorless verification equation",
           r'try:\n\s*Ed25519PublicKey\.from_public_bytes\(public_key\)\.verify\(signature, message\)\n\s*except \(InvalidSignature, ValueError, TypeError\) as error:\n\s*# U1 exception audit:[\s\S]*?\n\s*\) from error',
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
           ("erasure/actor-program-without-grant",),
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
        _m("record-self-attested-root-notice", "keys.py", "verifier.notice.self-attested-root",
           "stop emitting N_SELF_ATTESTED_ROOT_KEY for untrusted self-attested container roots",
           r'notice="N_SELF_ATTESTED_ROOT_KEY" if self_signed_only else None,',
           'notice=None,  # ablation: self-attested-root notice suppressed',
           ("key-lifecycle/backdated-container-root",
            "container/self-attested-root-untrusted",
            "key-lifecycle/declared-human-self-attested-valid")),
        # ------------------------------------------------------------------------ grants
        _m("grant-revoke-as-authority", "grants.py", "grants.parent.action",
           "accept a weave.grant revoke record as an authorising grant",
           r'if envelope\.kind != kinds\.KIND_GRANT or envelope\.body\.get\("action"\) != "grant":\n\s*raise WeaveError\("E_GRANT_GRANTER", "reference does not resolve to an authorising grant"\)',
           'if False:  # ablation: revoke record accepted as authorising grant\n        pass',
           ("grant/revoke-record-as-authority",), review_a_survivor=True,
           equivalent_reason="reviewed-equivalent: the cited-authority action is checked twice with the "
           "same E_GRANT_GRANTER (grants.py _as_grant and check_agent_authorization), and removing both "
           "still cannot accept a revoke record: grant_record_from_envelope reinterprets the body and "
           "fails because body.grant is absent; grant/revoke-record-as-authority pins the "
           "E_GRANT_GRANTER outcome"),
        _m("grant-delegation-parent-action", "grants.py", "grants.delegation.parent-capabilities",
           "allow a parent grant that does not authorise granting",
           r'if "weave\.grant" not in parent\.kind_names or "grant" not in parent\.actions:',
           'if False:  # ablation: parent capability check disabled',
           ("grant/sub-grant-parent-lacks-grant-action",)),
        _m("grant-delegation-transferable", "grants.py", "grants.delegation.transferable",
           "allow delegation from a non-transferable parent grant",
           r'if not parent\.transferable:',
           'if False:  # ablation: transferable check disabled',
           ("grant/sub-grant-parent-not-transferable",)),
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
           ("grant/sub-grant-window-starts-before-parent",), review_a_survivor=True),
        _m("grant-delegation-valid-until", "grants.py", "grants.delegation.window",
           "allow a sub-grant to end after its parent",
           r'if parent_until is not None and \(\n\s*child\.valid_until is None\n\s*or timestamp_sort_key\(child\.valid_until\) > parent_until\n\s*\):',
           'if False:  # ablation: delegation valid_until bound disabled',
           ("grant/sub-grant-window-ends-after-parent",), review_a_survivor=True),
        _m("grant-parent-revoked", "grants.py", "grants.delegation.parent-revoked",
           "ignore revocation of the parent grant",
           r'if context\.grant_state\.revocation_as_of\(parent\.digest, at_time\) is not None:',
           'if False:  # ablation: parent grant revocation check disabled',
           ("grant/parent-revoked",), review_a_survivor=True,
           equivalent_reason="reviewed-equivalent: the delegation-layer revocation check is mirrored by "
           "validate_grant_chain's own revocation guard (same E_GRANT_REVOKED) and by the "
           "agent-authorisation path that resolves the same cited grant; non-agent sub-grants are "
           "unconstructible (the envelope forbids actor.grant on non-agent actors), so the "
           "E_GRANT_REVOKED outcome is pinned by grant/parent-revoked, grant/revoked and "
           "grant/revoked-boundary-equal"),
        _m("grant-parent-expired", "grants.py", "grants.delegation.parent-window",
           "ignore that the parent grant is not yet valid",
           r'if timestamp_sort_key\(at_time\) < timestamp_sort_key\(parent\.valid_from\):',
           'if False:  # ablation: parent grant lower-window check disabled',
           ("grant/parent-expired",), review_a_survivor=True,
           equivalent_reason="reviewed-equivalent: the delegation-layer validity check is mirrored by "
           "_check_window during the recursive parent-chain validation (same E_GRANT_EXPIRED, covering "
           "both not-yet-valid and expired parents), and the delegating record is necessarily an agent "
           "record whose actor.grant goes through the same agent-authorisation path; the vectors "
           "grant/parent-expired and grant/sub-grant-parent-expired pin the E_GRANT_EXPIRED outcome"),
        # FIX2 recheck counterexample (R1): literal old §5.5.2 step 6 - ancestors judged at
        # the descendant grant's claimed recorded_at instead of the verified record's.
        # FIX2 recheck counterexample (R1): literal old §5.5.2 step 6 - every ancestor is
        # evaluated at the direct descendant grant's recorded_at instead of the verified
        # record's recorded_at.  grants.py funnels both consumers through ``ancestor_time``
        # so this is a genuine single-line mutation.
        _m("grant-ancestor-evaluated-at-descendant-time", "grants.py", "grants.chain.ancestor-time",
           "evaluate ancestor grants at the descendant grant's recorded_at (literal old step 6)",
           r'ancestor_time = at_time',
           'ancestor_time = grant.recorded_at  # ablation: literal old step-6 semantics',
           ("grant/ancestor-revoked-before-record",)),
        _m("grant-chain-depth", "grants.py", "grants.chain.depth",
           "remove the grant chain depth guard",
           r'if depth > MAX_CHAIN_DEPTH or grant\.digest in seen:',
           'if grant.digest in seen:  # ablation: chain depth guard removed',
           ("grant/chain-depth-9-links", "grant/chain-depth-exceeded",)),
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
        _m("grant-revoke-ref", "grants.py", "grants.revoke-ref",
           "report the wrong code for a non-authorising grant reference (ablation of the check)",
           r'if target_envelope is None or target_envelope\.body\.get\("action"\) != "grant":\n\s*raise WeaveError\("E_GRANT_REVOKE_REF", "revoked target is not an authorising grant"\)',
           'if target_envelope is None or target_envelope.body.get("action") != "grant":\n            raise WeaveError("E_REF_KIND_MISMATCH", "ablation: non-authorising grant reference accepted")',
           ("grant/revoke-ref-not-grant", "grant/revoke-record-as-authority"),
        ),
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
           ("key-lifecycle/key-expired",)),
        _m("key-retired-boundary", "keys.py", "keys.revocation.retired",
           "ignore the retired/other revocation family (T2)",
           r'if timestamp_sort_key\(recorded_at\) >= timestamp_sort_key\(revocation\.effective_at\):',
           'if False:  # ablation: retired revocation effect disabled',
           ("key-lifecycle/retired-then-signed-after",
            "key-lifecycle/mixed-revocation-retired-then-compromise",
            "key-lifecycle/mixed-revocation-compromise-then-retired",
            "key-lifecycle/mixed-revocation-rescue-but-retired")),
        _m("key-compromise-never-rescued", "keys.py", "keys.revocation.compromise-rescue",
           "never rescue compromise signatures with an earlier verified timestamp",
           r'rescued = any\(\n\s*timestamp\.covered_until_us < effective_at_us\n\s*for timestamp in verified_timestamps\n\s*\)',
           'rescued = False  # ablation: compromise rescue disabled',
           ("key-lifecycle/compromise-rescued-by-timestamp",)),
        _m("key-compromise-always-rescued", "keys.py", "keys.revocation.compromise",
           "always rescue compromise signatures (never fail closed)",
           r'if rescued:\n            return',
           'if True:  # ablation: every compromise signature rescued\n            return',
           ("key-lifecycle/compromise-backdated-forgery", "key-lifecycle/compromise-retroactive"),
           review_a_survivor=True),
        # FIX2 recheck counterexample (R2): roots may only come from the verifier's local
        # keyset; disabling that gate lets container self-signed human/org declarations act
        # as trust roots (backdating then creates roots).
        _m("keyset-root-gate-always-true", "keys.py", "keys.declaration.root-source",
           "treat every human/organization declaration source as a trusted local root",
           r'if source == "keyset":',
           'if True:  # ablation: any declaration source treated as a local trust root',
           ("key-lifecycle/backdated-container-root",
            "key-lifecycle/keyset-root-not-invalidated",
            "container/self-attested-root-untrusted")),
        _m("key-owner-missing", "keys.py", "keys.declaration.owner",
           "allow agents/programs/devices without a declared owner "
           "(primary check; the second guard is unreachable dead code)",
           r'raise WeaveError\(\n\s*"E_KEY_OWNER_MISSING",\n\s*"agent/program/device key declarations require body\.owner",?\n\s*\)',
           'pass  # ablation: primary owner requirement disabled',
           ("key-lifecycle/declared-agent-without-owner",),
           co_mutations=(
               ("keys.py",
                r'raise WeaveError\("E_KEY_OWNER_MISSING", "missing owner"\)',
                'pass  # co-ablation: fallback owner guard disabled'),
           )),
        _m("key-id-mismatch", "keys.py", "keys.declaration.key-id",
           "stop deriving the key id from the declared public key",
           r'raise WeaveError\("E_KEY_ID_MISMATCH", "declared key id does not derive from public_key"\)',
           'pass  # ablation: key id derivation check disabled',
           ("key-lifecycle/key-id-mismatch",)),
        _m("key-validity-window", "keys.py", "keys.declaration.validity",
           "accept declarations with valid_from after valid_until",
           r'raise WeaveError\("E_KEY_VALIDITY", "valid_from is after valid_until"\)',
           'pass  # ablation: declaration validity window check disabled',
           ("key-lifecycle/declared-validity-inverted",)),
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
           ("key-lifecycle/revoke-effective-after-recorded",)),
        _m("key-revoke-signer", "keys.py", "keys.revocation.signer",
           "accept revocations from any signature",
           r'raise WeaveError\("E_KEY_REVOKE_SIGNER", "revocation lacks an acceptable signer"\)',
           'pass  # ablation: revocation signer rule disabled',
           ("key-lifecycle/revoke-signer-unqualified",)),
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
        _m("key-container-declaration-untrusted", "keys.py", "keys.declaration.container-trust",
           "accept a container declaration without a keyset trust root",
           r'raise WeaveError\(\n\s*"E_KEY_UNTRUSTED",\n\s*"container declaration cannot be chained to a keyset trust root",\n\s*notice="N_SELF_ATTESTED_ROOT_KEY" if self_signed_only else None,\n\s*\)',
           'pass  # ablation: untrusted container declaration accepted',
           ("key-lifecycle/declared-human-self-attested-valid", "key-lifecycle/untrusted-owner-cosign"),
        ),
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
           ("container/previous-external-mismatch",), review_a_survivor=True,
           equivalent_reason="the committed mismatch vector is already rejected by the embedded "
           "previous/manifest.json digest check before the supplied --previous comparison runs; the "
           "supplied-digest comparison remains defence in depth for a chain whose embedded manifest "
           "matches but --previous differs"),
        _m("container-chain-unexpected-first", "container.py", "container.chain.unexpected",
           "ignore the first unexpected-previous branch (previous/manifest.json present)",
           r'if embedded is not None:\n\s*raise WeaveError\(\n\s*"E_MANIFEST_CHAIN_UNEXPECTED",\n\s*"previous_manifest is null but previous/manifest\.json is present",\n\s*\)',
           'if False:  # ablation: first unexpected-previous branch disabled\n            pass',
           ("container/chain-unexpected-first",), review_a_survivor=True,
           co_mutations=(
               ("container.py",
                r'raise WeaveError\(\n\s*"E_MANIFEST_CHAIN_UNEXPECTED",\n\s*"previous_manifest is null but previous/ contains a manifest",?\n\s*\)',
                'pass  # co-ablation: second unexpected-previous branch disabled'),
           )),
        _m("container-record-digest-name", "container.py", "container.records.digest",
           "accept a record file whose name does not match its computed digest",
           r'if match\.group\(1\) != record\.digest\.partition\(":"\)\[2\]:',
           'if False:  # ablation: record digest/filename check disabled',
           ("container/record-digest-mismatch",),
           equivalent_reason="the filename-vs-digest rule and the immediately following "
           "manifest-lookup fallback report the same E_MANIFEST_RECORD_DIGEST for every "
           "committed case (the tampered record's computed digest is not listed under any "
           "name), so removing this single site cannot change an observable verdict; the "
           "semantic is pinned by container/record-digest-mismatch through the fallback "
           "with the same code"),
        _m("container-record-id-kind", "container.py", "container.records.metadata",
           "accept a manifest entry whose id/kind disagrees with the record content",
           r'if record_entry\.id != value\.get\("id"\) or record_entry\.kind != value\.get\("kind"\):',
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
           ("integrity-levels/l2-signer-digest-algorithm-unsupported",)),
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
           'return signed_data["certificates"][0].chosen.dump()  # ablation: fall back to the first token certificate',
           ("integrity-levels/l2-cert-not-in-token",), review_a_survivor=True,
           equivalent_reason="the signer certificate is consumed by the ESS signingCertificateV2 binding "
           "and by CMS signature verification, which fail with the same E_TS_CMS when the token does not "
           "carry the matching certificate; falling back to another token certificate is rejected by those "
           "checks, so the vector pins the outcome but no single site is individually observable"),
        _m("ts-cms-signature", "timestamps.py", "timestamps.cms-signature",
           "skip the CMS signature verification",
           r'\n        raise WeaveError\("E_TS_CMS", "CMS signature does not verify"\) from error',
           '\n        pass  # ablation: CMS signature verification disabled',
           ("integrity-levels/l2-cms-tampered",), review_a_survivor=True),
        _m("ts-eku", "timestamps.py", "timestamps.eku",
           "accept a signer certificate without the timeStamping EKU",
           r'raise WeaveError\("E_TS_CERT", "signer certificate has no timeStamping EKU"\)',
           'extended_key_usage = [cryptography_x509.oid.ExtendedKeyUsageOID.TIME_STAMPING]  # ablation: EKU requirement disabled',
           ("integrity-levels/l2-eku-missing",), review_a_survivor=True),
        _m("ts-eku-profile", "timestamps.py", "timestamps.eku",
           "accept a signer certificate that is not a timestamping certificate",
           r'raise WeaveError\("E_TS_CERT", "signer certificate is not a timestamping certificate"\)',
           'pass  # ablation: timestamping certificate profile check disabled',
           ("integrity-levels/l2-eku-missing",),
           co_mutations=(
               ("timestamps.py",
                r'raise WeaveError\("E_TS_CERT", "signer certificate has no timeStamping EKU"\)',
                'pass  # co-ablation: missing-EKU-extension check disabled'),
           )),
        _m("ts-key-usage", "timestamps.py", "timestamps.key-usage",
           "accept a signer certificate whose key usage lacks digitalSignature",
           r'raise WeaveError\("E_TS_CERT", "signer certificate key usage lacks digitalSignature"\)',
           'pass  # ablation: digitalSignature key-usage check disabled',
           ("integrity-levels/l2-key-usage-missing",)),
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
           r'if "sha256:" \+ hashlib\.sha256\(data\)\.hexdigest\(\) != listed_digest:',
           'if False:  # ablation: timestamp file digest check disabled',
           ("integrity-levels/l2-ts-file-digest",)),
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

        # ------------------------------------------------------------------- S1 revision (S1-S14)
        _m("json-max-depth", "canonical.py", "canonical.depth.limit",
           "accept JSON nesting deeper than MAX_JSON_DEPTH",
           r'if self\.depth > MAX_JSON_DEPTH:',
           'if False:  # ablation: JSON nesting-depth limit disabled',
           ("jcs/depth-limit-plus-one",)),
        _m("licence-nesting-limit", "grammar.py", "grammar.licence.nesting",
           "accept an SPDX licence expression nested deeper than MAX_LICENCE_NESTING",
           r'if depth > MAX_LICENCE_NESTING:',
           'if False:  # ablation: licence nesting-depth limit disabled',
           ("labels/licence-nesting-plus-one",)),
        _m("zip64-accepted", "zipread.py", "container.zip.zip64",
           "reject a ZIP64 archive (T6 requires accepting it)",
           r'    end_record = _read_end_records\(handle, eocd_offset\)',
           '    end_record = _read_end_records(handle, eocd_offset)\n    if end_record.has_zip64:  # ablation: ZIP64 archive rejected\n        raise ZipStructureError("ablation: ZIP64 archive rejected")',
           ("container/zip64-valid",)),
        _m("zip-prefix-bytes", "container.py", "container.zip.prefix",
           "accept an archive with bytes before the first local file header",
           r'    return head in \(\n        zipread\.LOCAL_HEADER,\n        zipread\.END_OF_CENTRAL_DIRECTORY,\n        zipread\.ZIP64_END_OF_CENTRAL_DIRECTORY,\n    \)',
           '    return True  # ablation: zip signature probe disabled',
           ("container/zip-prefix",),
           co_mutations=(
               ("zipread.py",
                r'    if end_record\.count_total and end_record\.cd_offset != 0:',
                '    return  # co-ablation: the archive-prefix rule is disabled\n    if end_record.count_total and end_record.cd_offset != 0:'),
               ("zipread.py",
                r'        if entry\.local_offset != expected:',
                '        if False:  # co-ablation: gaps/overlaps tolerated'),
           )),
        _m("zip-trailing-bytes", "zipread.py", "container.zip.trailing",
           "accept trailing bytes after the end-of-central-directory record",
           r'            if position \+ _EOCD_SIZE \+ comment_length == len\(tail\):\n                return size - window \+ position, comment_length',
           '            if True:  # ablation: the EOCD need not end at EOF (trailing bytes accepted)\n                return size - window + position, comment_length',
           ("container/zip-trailing",)),
        _m("zip-dos-directory-data", "zipread.py", "container.zip.dos-directory",
           "accept a DOS-directory-attribute entry that carries data (rule 4, every entry, W2)",
           r'    if entry\.external_attr & 0x10 and entry\.uncompressed_size:',
           '    if False:  # ablation: DOS directory attribute on a data entry accepted',
           ("container/zip-dos-directory-attribute-with-data",
            "container/previous-zip-rule4-dos-directory-attribute")),
        _m("previous-null-chain", "container.py", "container.chain.previous-null",
           "accept --previous when previous_manifest is null",
           r'raise WeaveError\(\n\s*"E_MANIFEST_CHAIN",\n\s*"a previous container was supplied but previous_manifest is null",\n\s*\)',
           'return  # ablation: a supplied previous container with a null chain is ignored',
           ("container/previous-without-chain",)),
        _m("sigs-empty-required", "verifier.py", "verifier.sigs.empty",
           "treat an empty sigs array as satisfying a required-signature record",
           r'if not envelope\.sigs:\n\s*raise WeaveError\("E_SIG_REQUIRED", "record requires a per-record signature"\)',
           'if False:  # ablation: empty sigs treated as satisfying the required signature\n        raise WeaveError("E_SIG_REQUIRED", "record requires a per-record signature")',
           ("sig/required-empty-sigs",)),
        _m("manifest-sig-unverifiable-continues", "container.py", "container.manifest.signature-unverifiable",
           "stop record processing after an unverifiable manifest signature",
           r'if error\.code in \("E_KEY_UNKNOWN", "E_SIG_UNVERIFIABLE"\) or active_skipper\.skip_error\(\n            error\.code\n        \):',
           'if False:  # ablation: an unverifiable manifest signature stops the pipeline',
           ("container/manifest-sig-unverifiable-continues",)),
        _m("manifest-listing-multi-error", "container.py", "container.records.multi-error",
           "report only the first records-listing defect",
           r'    return sorted\(errors\)\n',
           '    return sorted(errors)[:1]  # ablation: only the first records-listing defect is reported\n',
           ("container/manifest-record-extra-and-missing",)),
        _m("manifest-unsigned-missing-sigfile", "container.py", "container.manifest.unsigned",
           "report a missing attestation file as a schema error",
           r'raise WeaveError\("E_MANIFEST_UNSIGNED", "container has no manifest attestation file"\)',
           'raise WeaveError("E_MANIFEST_SCHEMA", "container has no manifest attestation file")',
           ("container/manifest-unsigned-missing-sigfile",)),
        _m("declared-missing-public-key", "verifier.py", "verifier.declared.public-key",
           "verify a declaration's self-signature against a placeholder key when body.public_key is absent",
           r'    if envelope\.kind == kinds\.KIND_DECLARED:\n        if body\.get\("key"\) == key:\n            return \(decode_public_key_material\(body\.get\("public_key"\)\), False\)',
           '    if envelope.kind == kinds.KIND_DECLARED:\n        if body.get("key") == key:\n            return (decode_public_key_material(body["public_key"]) if "public_key" in body else bytes(32), False)  # ablation',
           ("key-lifecycle/declared-missing-public-key",)),
        _m("key-class-conflict", "keys.py", "keys.declared.class-conflict",
           "accept a container declaration that reclassifies a trusted key",
           r'if governing_class is not None and governing_class != key_type:',
           'if False:  # ablation: key-class conflict accepted',
           ("key-lifecycle/redeclare-class-conflict",)),
        _m("keyset-window-authority", "keys.py", "keys.declaration.keyset-authority",
           "allow a backdated in-context declaration to override the keyset window",
           r'if current_from_keyset and not new_from_keyset:\n\s*return',
           'if False:  # ablation: in-context re-declaration may override the keyset window\n            return',
           ("key-lifecycle/redeclare-window-attack",)),
        _m("keyset-revocations", "verifier.py", "verifier.context.keyset-revocations",
           "ignore revocations supplied by the local keyset",
           r'if view\.key_revocation is not None:\n\s*self\.key_state\.add_revocation\(view\.key_revocation\)',
           'if view.key_revocation is not None and view.loaded.source != "keyset":  # ablation: keyset revocations ignored\n            self.key_state.add_revocation(view.key_revocation)',
           ("key-lifecycle/keyset-revocation",)),
        _m("revocations-all-effective", "keys.py", "keys.revocations.all",
           "consider only one revocation record instead of every effective revocation",
           r'        revocations = list\(self\.revocations\.get\(key_id, \(\)\)\)',
           '        revocations = list(self.revocations.get(key_id, ()))[-1:]  # ablation: only one revocation considered',
           ("key-lifecycle/multi-revocation-order-a", "key-lifecycle/multi-revocation-order-b",
            "key-lifecycle/mixed-revocation-retired-then-compromise",
            "key-lifecycle/mixed-revocation-compromise-then-retired")),
        _m("compromise-earliest", "keys.py", "keys.compromise.earliest",
           "use the latest instead of the earliest key-compromise revocation for the rescue bound",
           r'        effective_at_us = compromises\[0\]\.effective_at_ms \* 1000',
           '        effective_at_us = compromises[-1].effective_at_ms * 1000  # ablation: latest compromise used',
           ("key-lifecycle/compromise-earliest-revocation-a", "key-lifecycle/compromise-earliest-revocation-b")),
        _m("grant-self-window", "grants.py", "grants.self-window",
           "judge a grant record against its own validity window at its own recorded_at",
           r'if envelope\.actor_type in \("human", "organization"\):\n\s*return grant  # root grant',
           'if envelope.actor_type in ("human", "organization"):\n        _check_window(grant, envelope.recorded_at)  # ablation: grant judged against its own window\n        return grant',
           ("grant/root-valid-from-after-recorded",)),
        _m("grant-revocation-signer", "grants.py", "grants.revocation.signer",
           "accept a grant revocation signed by an unauthorised key",
           r'    if not allowed & verified_signature_keys:',
           '    if False:  # ablation: grant-revocation signer authorisation disabled',
           ("grant/invalid-revocation-ineffective",)),
        _m("grant-chain-depth-endpoint", "grants.py", "grants.chain.depth",
           "accept one more grant-chain link than the inclusive depth bound",
           r'if depth > MAX_CHAIN_DEPTH or grant\.digest in seen:',
           'if depth > MAX_CHAIN_DEPTH + 1 or grant.digest in seen:  # ablation: off-by-one depth bound',
           ("grant/chain-depth-9-links",)),
        _m("ts-accuracy-bound", "timestamps.py", "timestamps.accuracy.bound",
           "accept a receipt whose accuracy exceeds MAX_TS_ACCURACY",
           r'if total > MAX_TS_ACCURACY_US:',
           'if False:  # ablation: MAX_TS_ACCURACY bound disabled',
           ("integrity-levels/l2-accuracy-over-limit", "integrity-levels/l2-accuracy-overflow")),
        _m("ts-file-before-renewal", "timestamps.py", "timestamps.archive.file-first",
           "judge renewal-chain structure before the listed TSR file digests",
           r'    # Phase 1: every listed TSR must exist, be within the class limit and hash\n    # to the digest the attestation lists \(§11\.3 file-level checks\)\.',
           '    _abl_chain, _abl_error = _build_renewal_chain(entries)  # ablation: renewal structure judged first\n    if _abl_error is not None:\n        archive.errors.append("E_TS_RENEWAL")\n        archive.results = [\n            TimestampResult(path, str(entries[path].get("digest", "")), STATE_INVALID, None, None, "E_TS_RENEWAL")\n            for path in sorted(entries)\n        ]\n        return archive\n    # Phase 1: every listed TSR must exist, be within the class limit and hash\n    # to the digest the attestation lists (§11.3 file-level checks).',
           ("integrity-levels/l2-ts-file-before-renewal",)),
        _m("crypto-before-lifecycle", "verifier.py", "verifier.crypto.order",
           "run lifecycle effects before the cryptographic check",
           r'try:\n\s*ed25519\.verify_signature\(material, message, signature\.raw or b""\)',
           'if from_context:  # ablation: lifecycle effects before the crypto check\n                context.key_state.check_signature_effects(\n                    signature.key,\n                    envelope.recorded_at,\n                    verified_timestamps=context.verified_timestamps,\n                    timestamp_evidence_present=context.timestamp_evidence_present,\n                )\n            try:\n                ed25519.verify_signature(material, message, signature.raw or b"")',
           ("sig/invalid-value", "sig/wrong-key-value"),
        ),
        _m("limitations-identifiers", "report.py", "report.limitations.identifiers",
           "emit a free-form sentence in the limitations array",
           r'    return sorted\(set\(values\)\)',
           '    return sorted(set(values)) + ["free-form prose is not an identifier"]  # ablation',
           ("container/l0-minimal", "jcs/depth-limit-32", "grant/root-valid-from-after-recorded")),
        _m("container-input-null", "container.py", "container.report.input-null",
           "report a directory-snapshot input identity when the manifest is missing",
           r'    if "manifest\.json" not in container_input\.files:\n\s*errors\.append\("E_MANIFEST_MISSING"\)',
           '    if "manifest.json" not in container_input.files:\n        errors.append("E_MANIFEST_MISSING")\n        container_input.input_sha256 = "sha256:" + "0" * 64  # ablation: undocumented snapshot identity\n        container_input.input_size = 0',
           ("container/manifest-missing",)),
        _m("envelope-suborder", "envelope.py", "envelope.structure.order",
           "check top-level closedness before the required members (reverses §14.5 sub-order)",
           r'    for member in REQUIRED_MEMBERS:\n        if member not in record:\n            raise WeaveError\("E_ENV_MISSING_FIELD", "missing required member %r" % member\)\n    for member in record:\n        if member not in ENVELOPE_MEMBERS:\n            raise WeaveError\("E_ENV_UNKNOWN_FIELD", "unknown top-level member %r" % member\)',
           '    for member in record:  # ablation: closedness before the required-member checks\n        if member not in ENVELOPE_MEMBERS:\n            raise WeaveError("E_ENV_UNKNOWN_FIELD", "unknown top-level member %r" % member)\n    for member in REQUIRED_MEMBERS:\n        if member not in record:\n            raise WeaveError("E_ENV_MISSING_FIELD", "missing required member %r" % member)',
           ("stage/multi-defect-envelope",)),
        _m("env-sensitivity-code", "envelope.py", "envelope.labels.sensitivity-code",
           "report a wrong labels.sensitivity value with the labels code",
           r'raise WeaveError\(\n            "E_ENV_SENSITIVITY", "labels\.sensitivity is not one of the closed values"\n        \)',
           'raise WeaveError(\n            "E_ENV_LABELS", "labels.sensitivity is not one of the closed values"\n        )',
           ("labels/sensitivity-wrong-type",)),
        _m("env-sig-key-code", "envelope.py", "envelope.sigs.key-type-code",
           "report a non-string sigs[].key with the key-id code",
           r'raise WeaveError\("E_ENV_SIGS", "signature key must be a string"\)',
           'raise WeaveError("E_ENV_SIG_KEY", "signature key must be a string")',
           ("sig/key-not-string",)),
        _m("env-actor-grant-code", "envelope.py", "envelope.actor.grant-code",
           "report a malformed actor.grant reference with the actor code",
           r'raise WeaveError\(\n                    "E_ENV_REFS", "actor\.grant is not a valid reference"\n                \) from error',
           'raise WeaveError(\n                    "E_ENV_ACTOR", "actor.grant is not a valid reference"\n                ) from error',
           ("actor/grant-malformed-reference",)),
        _m("refs-invalid-target", "refs.py", "refs.resolve.invalid-target",
           "resolve an individually invalid target as missing instead of unverifiable",
           r'return Resolution\(UNVERIFIABLE, candidate\)',
           'return Resolution(MISSING, candidate)  # ablation: invalid target reported missing',
           ("ref/invalid-target",),
           occurrences=2, replace_all=True),
        _m("blocking-condition-terminal", "verifier.py", "verifier.blocking.terminal",
           "make the undeclared-signing-key blocking condition non-terminal",
           r'raise WeaveError\(\n                    "E_KEY_UNKNOWN", "signing key is not declared in the context"\n                \)',
           'view.errors.append("E_KEY_UNKNOWN")  # ablation: blocking condition downgraded\n                continue',
           ("sig/unknown-key-terminal",)),
        _m("no-human-signature-notice", "verifier.py", "verifier.notice.no-human-signature",
           "report N_NO_HUMAN_SIGNATURE on a record that a blocking condition made unverifiable",
           r'    except WeaveError as error:\n        view\.errors\.append\(error\.code\)',
           '    except WeaveError as error:\n        if getattr(view.envelope, "stage", None) == "accepted":\n            view.notices.append("N_NO_HUMAN_SIGNATURE")  # ablation: notice precedence broken\n        view.errors.append(error.code)',
           ("sig/unknown-alg",)),

        # ------------------------------------------------------- S1-FIX1 T2/T3/T9/T10/T12/T13/T14/T15/T16
        _m("key-revocation-prior-order", "keys.py", "keys.revocation.deterministic-order",
           "ignore the deterministic prior-revocation order for a key.revoked record's signatures",
           r'        if prior_order is not None:',
           '        if False:  # ablation: revocation order filter disabled',
           ("key-lifecycle/mutual-revocation-order-a", "key-lifecycle/mutual-revocation-order-b")),
        _m("key-revocation-prior-order-record", "verifier.py", "verifier.revocation.prior-order",
           "judge a key.revoked record's signatures without the prior-revocation order (U3)",
           r'                    prior_order=\(\n                        revocation_prior_order\n                        if envelope\.kind == kinds\.KIND_REVOKED\n                        else None\n                    \),',
           '                    prior_order=None,  # ablation: no prior-revocation order for revocation records',
           ("key-lifecycle/self-revocation-after-retirement",
            "key-lifecycle/backdated-self-compromise-ineffective",
            "key-lifecycle/revocation-signed-by-retired-key")),
        _m("grant-record-depth", "grants.py", "grants.chain.depth-record",
           "count a grant record's own link in its parent-chain depth (T8)",
           r'validate_grant_chain\(parent, context, envelope\.recorded_at, depth=0, seen=frozenset\(\{digest\}\)\)',
           'validate_grant_chain(parent, context, envelope.recorded_at, depth=1, seen=frozenset({digest}))  # ablation: own link counted',
           ("grant/chain-depth-9-links",)),
        _m("manifest-tofu-limitation", "container.py", "container.limitations.manifest-tofu",
           "omit the TOFU limitation for a manifest signed with context-declaration material",
           r'        manifest_context_trusted = any\(',
           '        manifest_context_trusted = False; _unused_sources = any(  # ablation: manifest TOFU not tracked',
           ("container/manifest-context-trusted-tofu",)),
        _m("limitation-chain-claim", "container.py", "container.limitations.chain-claim",
           "omit L_CHAIN_CLAIM_UNVERIFIED for a claimed L1/L2 level",
           r'    if container\.get\("level_claimed"\) in \("L1", "L2"\):',
           '    if False:  # ablation: chain-claim limitation disabled',
           ("integrity-levels/l2-without-trust-limitations",)),
        _m("limitation-tsa-trust", "container.py", "container.limitations.tsa-trust",
           "omit L_TSA_TRUST_UNVERIFIED for a present-unverified receipt (U7)",
           r'    if any\(\n        entry\.get\("state"\) == STATE_PRESENT_UNVERIFIED\n        for entry in container\.get\("timestamps"\) or \(\)\n    \):',
           '    if False:  # ablation: TSA-trust limitation disabled',
           ("integrity-levels/l2-without-trust-limitations",)),
        _m("limitation-tsa-trust-invalid-receipt", "container.py", "container.limitations.tsa-trust-invalid",
           "report L_TSA_TRUST_UNVERIFIED for a receipt rejected by a structural/CMS check (U7)",
           r'    if any\(\n        entry\.get\("state"\) == STATE_PRESENT_UNVERIFIED\n        for entry in container\.get\("timestamps"\) or \(\)\n    \):',
           '    if container.get("timestamps"):  # ablation: any receipt triggers the limitation',
           ("integrity-levels/l2-invalid-receipt-no-tsa-limitation",)),
        _m("limitation-previous-sig", "container.py", "container.limitations.previous-signature",
           "keep reporting an unverified previous signature after the supplied previous was re-verified (V3)",
           r'    if not previous_signature_verified and \(\n        previous_manifest_declared or container\.get\("previous_manifest_digest"\) is not None\n    \):',
           '    if previous_manifest_declared or container.get("previous_manifest_digest") is not None:  # ablation: suppression disabled',
           ("container/previous-zip-valid", "container/previous-ignores-record-corruption"),
        ),
        _m("limitation-readable-notice", "container.py", "container.notices.readable",
           "omit N_READABLE_PRESENT for an enumerated readable/ entry",
           r'    if container_input\.readable_present:\n        notices\.append\("N_READABLE_PRESENT"\)',
           '    if False:  # ablation: readable notice disabled\n        notices.append("N_READABLE_PRESENT")',
           ("container/readable-ignored", "container/readable-present-after-manifest-failure")),
        _m("limitation-labels-claims", "container.py", "container.limitations.labels",
           "omit L_LABELS_ARE_CLAIMS when a record carries labels",
           r'    if labels_seen:\n        limitations\.append\(LIMITATION_LABELS_ARE_CLAIMS\)',
           '    if False:  # ablation: labels limitation disabled\n        limitations.append(LIMITATION_LABELS_ARE_CLAIMS)',
           ("labels/labels-claims-limitation",),
           co_mutations=(
               ("report.py",
                r'    if has_labels:\n        result\.append\(LIMITATION_LABELS_ARE_CLAIMS\)',
                '    if False:  # co-ablation: record-level labels limitation disabled\n        result.append(LIMITATION_LABELS_ARE_CLAIMS)'),
           )),
        _m("limitation-erased-placeholder", "container.py", "container.limitations.erased",
           "omit L_ERASED_PLACEHOLDER for a container that contains a placeholder",
           r'    if placeholder_seen:\n        limitations\.append\(LIMITATION_ERASED_PLACEHOLDER\)',
           '    if False:  # ablation: erased-placeholder limitation disabled\n        limitations.append(LIMITATION_ERASED_PLACEHOLDER)',
           ("erasure/valid-container", "digest/record-erased-placeholder"),
           co_mutations=(
               ("report.py",
                r'    if placeholder:\n        result\.append\(LIMITATION_ERASED_PLACEHOLDER\)',
                '    if False:  # co-ablation: record-level erased limitation disabled\n        result.append(LIMITATION_ERASED_PLACEHOLDER)'),
           )),
        _m("limitation-unknown-kind", "report.py", "report.limitations.unknown-kind",
           "omit L_UNKNOWN_KIND_OPAQUE for a valid unregistered-kind record",
           r'    if not kind_known and verdict == "valid":',
           '    if False:  # ablation: unknown-kind limitation disabled',
           ("stage/unknown-kind-opaque",)),
        _m("limitation-label-propagation", "report.py", "report.limitations.label-propagation",
           "omit L_LABEL_PROPAGATION_UNCHECKED when a derivation reference did not resolve",
           r'    if "N_LABEL_PROPAGATION_UNCHECKED" in notice_set:',
           '    if False:  # ablation: label-propagation limitation disabled',
           ("labels/propagation-unchecked",)),
        _m("rotated-material-first", "verifier.py", "verifier.rotated.material-first",
           "defer rotated key-material validation until after the signature pass (T13)",
           r'            check_rotated_material\(envelope\.body\)',
           '            pass  # ablation: rotated material checked only in kind semantics',
           ("key-lifecycle/rotation-old-public-key-malformed",)),
        _m("canonical-utf16-order", "canonical.py", "canonical.member-order",
           "sort object members by Unicode code point instead of UTF-16 code units (T14)",
           r'    return name\.encode\("utf-16-be", "surrogatepass"\)',
           '    return name  # ablation: code-point member order',
           ("jcs/supplementary-plane-member-order",)),
        _m("container-directory-total", "container.py", "container.size.directory-total",
           "disable the MAX_CONTAINER_UNCOMPRESSED_BYTES total cap for directory containers (T15)",
           r'            if total > MAX_CONTAINER_UNCOMPRESSED_BYTES:',
           '            if False:  # ablation: directory total cap disabled',
           occurrences=2, replace_all=True,
           equivalent_reason="T15 has no committed vector: a directory container above 1 GiB "
           "cannot be committed as a fixture. The cap is pinned by the unit test and gate 5 "
           "(the task book explicitly keeps the multi-GB resource check out of the vectors)."),
        _m("keyset-conflict-detection", "verifier.py", "verifier.keyset.conflict",
           "accept conflicting keyset declarations of one key id (T4 usage error)",
           r'    _check_keyset_declaration_conflicts\(loaded\)',
           '    pass  # ablation: keyset declaration conflicts accepted',
           equivalent_reason="a usage error (exit 2, no report) cannot be expressed in the "
           "vector expectation schema; the check is pinned by the unit test "
           "test_keyset_conflicting_declarations_is_usage_error"),
        _m("zip-local-uncompressed", "zipread.py", "container.zip.local-uncompressed",
           "accept a local header whose uncompressed size contradicts the central directory",
           r'            if local_uncompressed != entry\.uncompressed_size:',
           '            if False:  # ablation: local uncompressed-size comparison disabled',
           ("container/zip-local-central-uncompressed-size-mismatch",)),
        _m("zip-local-crc", "zipread.py", "container.zip.local-crc",
           "accept a local header whose CRC contradicts the central directory",
           r'            if crc != entry\.crc:',
           '            if False:  # ablation: local CRC comparison disabled',
           ("container/zip-local-central-crc-mismatch",
            "container/readable-local-central-crc-mismatch")),
        _m("zip-local-method", "zipread.py", "container.zip.local-method",
           "accept a local header whose method contradicts the central directory",
           r'        if method != entry\.method:',
           '        if False:  # ablation: local method comparison disabled',
           ("container/zip-local-central-method-mismatch",)),
        _m("zip-local-name", "zipread.py", "container.zip.local-name",
           "accept a local header whose filename contradicts the central directory",
           r'        if raw_name != entry\.raw_name:',
           '        if False:  # ablation: local filename comparison disabled',
           ("container/zip-local-central-name-mismatch",)),
        _m("zip-coverage-contiguity", "zipread.py", "container.zip.coverage-contiguity",
           "accept gaps or overlaps between zip entries",
           r'        if entry\.local_offset != expected:',
           '        if False:  # ablation: entry contiguity disabled',
           ("container/zip-gap-between-entries", "container/zip-entry-data-overlap")),
        _m("zip-coverage-final", "zipread.py", "container.zip.coverage-final",
           "accept a central directory that does not immediately follow the last entry",
           r'    if expected != boundary:',
           '    if False:  # ablation: final byte-coverage check disabled',
           ("container/zip-gap-before-central-directory",)),
        _m("zip-eocd-count", "zipread.py", "container.zip.eocd-count",
           "ignore the declared EOCD/ZIP64 entry count and parse by directory size",
           r'    for _ in range\(count\):',
           '    while position < end:  # ablation: declared entry count ignored',
           ("container/zip-eocd-count-plus-three", "container/zip-eocd-count-minus-one",
            "container/zip64-eocd-count-mismatch")),
        _m("zip64-locator-offset", "zipread.py", "container.zip.zip64-locator",
           "ignore the ZIP64 locator's EOCD offset and assume the record is adjacent",
           r'    zip64_eocd_offset = struct\.unpack_from\("<Q", locator, 8\)\[0\]',
           '    zip64_eocd_offset = locator_offset - _ZIP64_EOCD_MIN_SIZE  # ablation: locator offset ignored',
           ("container/zip64-locator-corrupt-offset",)),
        _m("zip-readable-duplicate", "container.py", "container.zip.readable-duplicate",
           "accept duplicate zip entry names under readable/",
           r'                if name in seen_names:',
           '                if False:  # ablation: duplicate-name check disabled',
           ("container/readable-duplicate-name",)),
        _m("oversized-record-shape", "container.py", "container.report.oversized-record",
           "let an oversized record file fall through the records-listing checks (T16)",
           r'    if oversized_records:',
           '    if False:  # ablation: oversized-record stage error disabled',
           ("container/oversize-record-file",)),
        _m("ts-accuracy-millis-range", "timestamps.py", "timestamps.accuracy.millis-range",
           "accept accuracy.milliseconds outside 1-999",
           r'    if millis is not None and not 1 <= millis <= 999:',
           '    if False:  # ablation: millisecond range check disabled',
           ("integrity-levels/l2-accuracy-millis-out-of-range",)),
        _m("ts-accuracy-micros-range", "timestamps.py", "timestamps.accuracy.micros-range",
           "accept accuracy.microseconds outside 1-999 (including an explicit 0)",
           r'    if micros is not None and not 1 <= micros <= 999:',
           '    if False:  # ablation: microsecond range check disabled',
           ("integrity-levels/l2-accuracy-micros-zero-explicit",)),
        _m("ts-accuracy-unusable", "timestamps.py", "timestamps.accuracy.unusable",
           "treat an over-limit accuracy as a format error instead of unusable evidence",
           r'    if total > MAX_TS_ACCURACY_US:\n        return None',
           '    if total > MAX_TS_ACCURACY_US:\n        raise WeaveError("E_TS_SCHEMA", "ablation: over-limit accuracy as format error")',
           ("integrity-levels/l2-accuracy-over-limit", "integrity-levels/l2-accuracy-overflow")),
        _m("ts-accuracy-order", "timestamps.py", "timestamps.accuracy.order",
           "check the accuracy limit before the CMS/certificate checks",
           r'        signer_info, signer_certificate_der = _verify_cms\(\n',
           '        _early_accuracy = _accuracy_to_us(tst_info)\n        if _early_accuracy is None:  # ablation: accuracy checked before the CMS\n            return TimestampResult(\n                path, listed_digest, STATE_PRESENT_UNVERIFIED, gen_time, gen_time_ms,\n                "E_TS_UNTRUSTED", gen_time_us, 0, unusable=True,\n            )\n        signer_info, signer_certificate_der = _verify_cms(\n',
           ("integrity-levels/l2-accuracy-over-limit-tampered-cms",)),
        _m("ts-rescue-truncation", "keys.py", "keys.compromise.ms-truncation",
           "use microsecond genTime in the rescue comparison instead of truncated milliseconds",
           r'        return self\.gen_time_ms \* 1000 \+ self\.accuracy_us',
           '        return self.gen_time_us + self.accuracy_us  # ablation: microsecond rescue comparison',
           ("integrity-levels/l2-submillisecond-rescue",)),

        # ------------------------------------------------- S1-FIX2 (U1/U2/U3/U4/U6/U8/U9/U12)
        _m("previous-non-container-mapping", "container.py", "container.previous.supplied-link",
           "ignore a supplied previous container entirely (semantic weakening, V7/L1)",
           r'    if supplied_error is not None:\n        raise supplied_error\n    if previous_container is not None and supplied_digest != manifest\.previous_manifest_digest:',
           '    if False:  # ablation: the supplied previous link is ignored\n        raise supplied_error\n    if False and supplied_digest != manifest.previous_manifest_digest:',
           ("container/previous-non-zip-file", "container/previous-zip-invalid", "container/previous-zip-valid"),
        ),
        _m("previous-map-to-chain", "container.py", "container.previous.error-mapping",
           "let a previous-container failure keep its container-level code instead of E_MANIFEST_CHAIN",
           r'    except WeaveError as error:\n        if error\.code == "E_MANIFEST_CHAIN":\n            raise\n        raise WeaveError\(\n            "E_MANIFEST_CHAIN", "--previous container is not a usable chain link"\n        \) from error',
           '    except WeaveError:\n        raise  # ablation: previous failures keep their container-level codes',
           ("container/previous-zip-invalid", "container/previous-zip-deflate-corrupt"),
        ),
        _m("zip-entry-count-limit", "zipread.py", "container.zip.entry-limit",
           "disable only the zip entry-count limit (V7/L7, split from the declared-total check)",
           r'    if max_entries is not None and directory\.count > max_entries:',
           '    if False:  # ablation: zip entry-count limit disabled',
           (),
           equivalent_reason="V7/L2: no committed 200,001-entry fixture (about 16 MiB); the count limit is pinned by the in-memory unit test test_zip_entry_count_limit_in_memory and by gate 5, and is deliberately independent of the declared-total mutation",
        ),
        _m("zip-declared-total-limit", "zipread.py", "container.zip.declared-total",
           "disable only the zip declared uncompressed-total limit (V7/L7)",
           r'    if \(\n        max_declared_total is not None\n        and directory\.declared_total > max_declared_total\n    \):',
           '    if False:  # ablation: declared uncompressed-total limit disabled',
           ("container/zip-declared-total-over-limit",),
        ),
        _m("zip-readable-excluded", "zipread.py", "container.zip.readable-excluded",
           "count readable/ entries in the declared uncompressed total (U2)",
           r'        if not is_directory and not _is_readable_entry\(name\):',
           '        if not is_directory:  # ablation: readable/ counted in the total',
           ("container/readable-declared-size-excluded",)),
        _m("class-governance-valid-only", "verifier.py", "class.governance.valid-only",
           "determine the governing class from semantically valid declarations only (U4)",
           r'            declaration = _structural_declaration_class\(view\)',
           '            declaration = (\n                _structural_declaration_class(view) if view.verdict == "valid" else None\n            )',
           ("key-lifecycle/nonmonotonic-closure-class-conflict",)),
        _m("class-governance-keyset-authority", "verifier.py", "class.governance.keyset",
           "ignore the keyset's class authority (U4 rule 1a)",
           r'            keyset_declarations = \[\n                declaration for declaration in declarations if declaration\[3\] == "keyset"\n            \]',
           '            keyset_declarations = []  # ablation: keyset class authority ignored',
           ("key-lifecycle/redeclare-class-conflict",
            "key-lifecycle/redeclare-class-conflict-control")),
        _m("rotated-material-tofu", "verifier.py", "verifier.tofu.rotated",
           "do not treat rotated old/new key material as context-trusted (U6)",
           r'                _record_source\(self\._material_source, rotation\.new_key, source\)\n                if rotation\.old_public_key is not None:\n                    _record_source\(self\._material_source, rotation\.old_key, source\)',
           '                pass  # ablation: rotated material not registered as context-trusted',
           ("key-lifecycle/rotated-material-tofu",)),
        _m("listing-oversize-json-size", "container.py", "container.listing.oversize",
           "drop E_JSON_SIZE from the records-listing multi-error set (U8)",
           r'        listing_errors = sorted\(\n            set\(listing_errors\)\n            \| \{container_input\.oversized\[path\] for path in oversized_records\}\n        \)',
           '        pass  # ablation: oversize record files do not join the listing errors',
           ("container/oversize-record-file",
            "container/oversize-record-with-missing",
            "container/oversize-record-with-extra")),
        _m("zip-eocd-disk-number", "zipread.py", "container.zip.eocd-disk",
           "accept a non-zero EOCD disk number (U9)",
           r'    if this_disk != 0 or central_directory_disk != 0:',
           '    if False:  # ablation: EOCD disk numbers ignored',
           ("container/zip-disk-number-nonzero",)),
        _m("zip64-locator-total-disks", "zipread.py", "container.zip.locator-disks",
           "accept a ZIP64 locator that is not single-volume (U9)",
           r'    if total_disks != 1:',
           '    if False:  # ablation: locator total-disks ignored',
           ("container/zip64-locator-total-disks",)),
        _m("zip64-eocd-disk-numbers", "zipread.py", "container.zip.zip64-eocd-disks",
           "accept a ZIP64 EOCD with non-zero disk numbers (U9)",
           r'    if disk != 0 or cd_disk != 0:',
           '    if False:  # ablation: ZIP64 EOCD disk numbers ignored',
           equivalent_reason="no committed vector isolates the ZIP64 EOCD disk fields; the "
           "check is pinned by the in-memory unit test "
           "test_zip64_eocd_disk_numbers_are_single_volume"),
        _m("zip-descriptor-local-nonzero", "zipread.py", "container.zip.descriptor-local",
           "accept non-zero local CRC/sizes when the data-descriptor flag is set (U12 L1)",
           r'            if \(crc, local_compressed, local_uncompressed\) != \(0, 0, 0\):',
           '            if False:  # ablation: data-descriptor local-header rule disabled',
           ("container/zip-data-descriptor-nonzero-local-header",)),
        _m("zip-eocd-per-disk-count", "zipread.py", "container.zip.eocd-per-disk-count",
           "accept an EOCD whose per-disk and total entry counts differ (U12 L4)",
           r'        if count_disk != count_total:',
           '        if False:  # ablation: EOCD per-disk count comparison disabled',
           ("container/zip-eocd-per-disk-count",)),
        _m("zip64-sentinel", "zipread.py", "container.zip.zip64-sentinel",
           "accept ZIP64 sentinel values without a ZIP64 locator/record (U12 L5)",
           r'        if needs_zip64:\n            raise ZipStructureError\("ZIP64 sentinel without a ZIP64 locator"\)',
           '        if False:  # ablation: ZIP64 sentinel rule disabled\n            raise ZipStructureError("ZIP64 sentinel without a ZIP64 locator")',
           ("container/zip64-sentinel-without-zip64",),
           equivalent_reason="the committed fixture also violates the central-directory "
           "size/count consistency rules, so removing the sentinel rule alone still yields "
           "E_CONTAINER_ZIP; the specific rule is pinned by the unit test "
           "test_zip64_sentinel_rule_is_enforced_specifically"),
        _m("zip-slash-name-with-data", "zipread.py", "container.zip.slash-name-data",
           "accept a directory-style zip entry that carries data (U12 L6; rule 4, every entry, W2)",
           r'    if entry\.is_directory and \(entry\.uncompressed_size or entry\.compressed_size\):',
           '    if False:  # ablation: slash-name-with-data rule disabled',
           ("container/zip-slash-name-with-data",
            "container/previous-zip-rule4-directory-with-data")),
        _m("zip-encrypted-entry", "zipread.py", "container.zip.encrypted",
           "accept an encrypted entry that is never decompressed (rule 4, every entry, W2)",
           r'    if entry\.flags & FLAG_ENCRYPTED:\n        raise ZipStructureError\("encrypted entries are not supported"\)\n(    if entry\.method not in \(METHOD_STORED, METHOD_DEFLATED\):\n        raise ZipStructureError\("unsupported compression method"\)\n    if entry\.is_directory)',
           '    if False:  # ablation: encrypted entries accepted unless decompressed\n        raise ZipStructureError("encrypted entries are not supported")\n\\1',
           ("container/previous-zip-rule4-encrypted",)),
        # ------------------------------------------------- S1-FIX3 (V1/V2/V3/V5/V6/V7)
        _m("previous-identity-signature", "container.py", "container.previous.signature",
           "skip the supplied previous manifest signature verification (V3)",
           r'            signer_keys = _verify_manifest_signatures\(\n                attestation\.signatures, digest, link_context\.candidates\n            \)',
           '            signer_keys = tuple(  # ablation: previous manifest signature not verified\n                entry.key for entry in attestation.signatures if entry.is_ed25519\n            )',
           ("container/previous-signature-invalid",)),
        _m("previous-attestation-digest", "container.py", "container.previous.attestation-digest",
           "skip the previous attestation digest equality check (V3)",
           r'        if attestation\.digest != digest:',
           '        if False:  # ablation: previous attestation digest not compared',
           ("container/previous-attestation-digest-mismatch",)),
        _m("previous-regular-file", "container.py", "container.previous.regular-member",
           "accept a symlinked or non-regular previous member (V3)",
           r'    if stat\.S_ISLNK\(member_stat\.st_mode\) or not stat\.S_ISREG\(member_stat\.st_mode\):',
           '    if False:  # ablation: previous members need not be regular files',
           ("container/previous-attestation-symlink",)),
        _m("previous-exactly-one-member", "container.py", "container.previous.single-member",
           "accept duplicate previous zip members (V3)",
           r'    if len\(matches\) != 1:',
           '    if len(matches) == 0:  # ablation: duplicate previous members accepted',
           ("container/previous-ignores-duplicate-manifest",)),
        _m("previous-ignores-other-members", "container.py", "container.previous.other-members",
           "validate every member of the supplied previous zip instead of the two read members (V3)",
           r'        manifest_entry = _exactly_one_previous_member\(',
           '        for _candidate in archive.entries:  # ablation: all previous members are checked\n'
           '            if not _is_safe_relative_path(_candidate.name):\n'
           '                raise WeaveError("E_MANIFEST_CHAIN", "ablation: other previous members are checked")\n'
           '        manifest_entry = _exactly_one_previous_member(',
           ("container/previous-ignores-evil-path",)),
        _m("previous-content-limitation", "container.py", "container.limitations.previous-content",
           "omit L_PREVIOUS_CONTENT_UNVERIFIED for a verified supplied previous (V3)",
           r'    finish_flags\["previous_content_unverified"\] = True',
           '    pass  # ablation: previous-content limitation not emitted',
           ("container/previous-zip-valid", "container/previous-ignores-record-corruption")),
        _m("ts-strict-der-scan", "timestamps.py", "timestamps.der.strict-scan",
           "disable the strict-DER scan of the whole receipt (V2/M3)",
           r'    _validate_strict_der\(tsr_bytes\)',
           '    pass  # ablation: strict DER scan disabled',
           ("integrity-levels/l2-ts-der-nonminimal-length",)),
        _m("ts-econtent-strict-der", "timestamps.py", "timestamps.der.econtent",
           "disable the strict-DER scan of the TSTInfo eContent (V2/M3)",
           r'        _validate_strict_der\(raw_content\)',
           '        pass  # ablation: eContent strict DER scan disabled',
           ("integrity-levels/l2-ts-der-tstinfo-opaque-unsorted",)),
        _m("ts-signed-data-version", "timestamps.py", "timestamps.der.signed-data-version",
           "accept a SignedData version other than 3 (V2/M3)",
           r'    if signed_data_version != "v3":',
           '    if False:  # ablation: SignedData version not checked',
           ("integrity-levels/l2-ts-der-version-invalid",)),
        _m("ts-signer-info-version", "timestamps.py", "timestamps.der.signer-info-version",
           "accept a signerInfo version outside {1, 3} (V2/M3)",
           r'        if signer_info_version not in \("v1", "v3"\):',
           '        if False:  # ablation: signerInfo version not checked',
           ("integrity-levels/l2-ts-signer-info-version-and-imprint",)),
        _m("class-governance-public-key", "verifier.py", "class.governance.public-key",
           "let a declaration with an invalid public_key govern the class (V5/M2)",
           r'                    try:\n                        keys_module\.decode_public_key_material\(body\.get\("public_key"\)\)\n                    except WeaveError:\n                        structurally_ok = False',
           '                    pass  # ablation: public_key encoding is not structural',
           ("key-lifecycle/bad-public-key-does-not-govern",)),
        _m("keyset-public-key-usage", "verifier.py", "verifier.keyset.public-key",
           "silently ignore a structurally invalid keyset declaration (V5)",
           r'            _check_keyset_material_structure\(envelope\.kind, envelope\.body\)',
           '            pass  # ablation: invalid keyset key material silently ignored',
           (),
           equivalent_reason="a keyset usage error (exit 2) cannot be expressed in the vector "
           "expectation schema; pinned by the unit test test_keyset_bad_public_key_is_usage_error"),
        _m("zip-version-needed", "zipread.py", "container.zip.version-needed",
           "accept a central-directory version-needed above 63 (V6)",
           r'    if entry\.version_needed > 63:',
           '    if False:  # ablation: version-needed not checked',
           ("container/zip-version-needed-too-high",)),
        _m("zip-entry-disk-start", "zipread.py", "container.zip.entry-disk-start",
           "accept a central-directory entry with a non-zero disk start (V6)",
           r'    if entry\.disk_number_start != 0:',
           '    if False:  # ablation: entry disk number not checked',
           ("container/zip-entry-disk-start-nonzero",)),
        _m("record-count-after-manifest", "container.py", "container.report.record-count",
           "reset record_count to 0 after the manifest structure stage (V7/L5)",
           r'            "record_count": len\(manifest\.records\),',
           '            "record_count": 0,  # ablation: record_count reset after manifest structure',
           ("container/manifest-record-extra-and-missing",)),
        _m("dir-entry-count-manifest", "container.py", "container.size.directory-count",
           "exclude the already-read manifest.json from the directory entry count (V7/L6)",
           r'            if relative_path == "manifest.json" and manifest_preloaded:\n                # L6/§13: the entry count covers all files, including the\n                # already-read manifest.json.\n                count \+= 1\n                if count > MAX_CONTAINER_ENTRIES:\n                    error = error or "E_CONTAINER_SIZE"\n                    break\n                continue',
           '            if relative_path == "manifest.json" and manifest_preloaded:\n                continue  # ablation: manifest.json not counted',
           (),
           equivalent_reason="the entry count differs by one only at the 200,000 boundary; pinned by "
           "the boundary unit test test_directory_entry_count_includes_manifest"),
        _m("zip-limits-order", "zipread.py", "container.zip.limits-order",
           "run the remaining zip structural rules before the §13 limits (V7/L7, W7)",
           r'    # Phase 3: the §13 limits, before every remaining structural rule \(V7/W7\)\.\n',
           '    # ablation: every remaining structural rule runs before the limits\n'
           '    if comment_length != 0:\n        raise ZipStructureError("a non-empty archive comment is not accepted")\n'
           '    if end_record.deferred:\n        raise ZipStructureError(end_record.deferred[0])\n'
           '    for _entry in directory.entries:\n        _check_entry_rules(_entry)\n'
           '    _validate_byte_coverage(\n        _validate_local_headers(handle, directory.entries, end_record.cd_offset),\n        end_record,\n    )\n',
           ("container/zip-over-limit-and-structure-violation",
            "container/zip-over-limit-and-version-needed",
            "container/zip-over-limit-and-disk-start",
            "container/zip-over-limit-and-method",
            "container/zip-over-limit-and-comment",
            "container/zip-over-limit-and-directory-with-data")),

        # ------------------------------------------------- S1-FIX4 (W1-W9, W10/L6)
        _m("previous-target-context", "container.py", "container.previous.target-context",
           "verify the supplied previous signature with keyset material only (W1)",
           r'        candidates, sources = _candidate_manifest_keys\(\n            \[record for record in container_records if id\(record\) not in invalid_rotations\],\n',
           '        candidates, sources = _candidate_manifest_keys(  # ablation: keyset only\n            [],\n',
           ("container/previous-device-key-target-context",
            "container/previous-rotated-old-key-links")),
        _m("previous-trust-closure", "container.py", "container.previous.trust",
           "accept a previous signing key that is not trusted in the target closure (W1)",
           r'            if key not in link_context\.trusted:',
           '            if False:  # ablation: previous signing key need not be trusted',
           ("container/previous-key-not-trusted-in-target",
            "container/previous-rotation-material-untrusted")),
        _m("previous-rotated-old-trust", "container.py", "container.previous.rotated-old",
           "do not trust the old key of a rotation whose new key is declared (W1)",
           r'            trusted=declared \| rotated_old,',
           '            trusted=declared,  # ablation: rotated-away keys never trusted',
           ("container/previous-rotated-old-key-links",)),
        _m("previous-key-state", "container.py", "container.previous.key-state",
           "skip the §9.4 key-state rules at the previous created_at (W1)",
           r'                link_context\.key_state\.check_signature_effects\(\n                    key,\n                    previous_manifest\.created_at,',
           '                (lambda *_a, **_k: None)(  # ablation: previous key state not checked\n                    key,\n                    previous_manifest.created_at,',
           ("container/previous-signing-key-retired-before-previous",
            "container/previous-signing-key-compromised-at-previous",
            "container/previous-signing-key-compromised-before-previous")),
        _m("previous-tofu", "container.py", "container.limitations.previous-tofu",
           "do not count the previous signature for the TOFU predicate (W1/§14.9)",
           r'            finish_flags\["previous_context_trusted"\] = True',
           '            pass  # ablation: previous signature never TOFU',
           ("container/previous-rotation-material-untrusted",
            "container/previous-signing-key-retired-after-previous")),
        _m("previous-supplied-first", "container.py", "container.previous.order",
           "evaluate the supplied previous only after the embedded checks pass (W5)",
           r'    if digest != manifest\.previous_manifest_digest:\n        raise WeaveError\(\n            "E_MANIFEST_CHAIN", "embedded previous manifest digest does not match"\n        \)',
           '    if digest != manifest.previous_manifest_digest:\n'
           '        finish_flags.pop("previous_signature_verified", None)  # ablation\n'
           '        finish_flags.pop("previous_content_unverified", None)  # ablation\n'
           '        raise WeaveError(\n            "E_MANIFEST_CHAIN", "embedded previous manifest digest does not match"\n        )',
           ("container/previous-embedded-mismatch-supplied-verified",)),
        _m("stage-8-stops", "container.py", "container.pipeline.stage-8",
           "keep running the later stages after an invalid cross-record error (W5)",
           r'        if _stops\(container_errors_from_state\):\n            return _finish_after_records\(\)',
           '        pass  # ablation: step (8) does not stop the pipeline',
           ("container/cross-record-failure-stops-pipeline",)),
        _m("stage-9-stops", "container.py", "container.pipeline.stage-9",
           "keep running the later stages after an invalid blob error (W5)",
           r'        _check_blobs\(manifest, container_input\)\n    except WeaveError as error:\n        errors\.append\(error\.code\)\n        if _stops\(\[error\.code\]\):\n            return _finish_after_records\(\)',
           '        _check_blobs(manifest, container_input)\n    except WeaveError as error:\n        errors.append(error.code)  # ablation: step (9) does not stop the pipeline',
           ("container/previous-not-read-after-blob-failure",
            "container/previous-bad-signature-after-blob-failure",
            "container/timestamps-not-run-after-blob-failure")),
        _m("stage-10-stops", "container.py", "container.pipeline.stage-10",
           "report the timestamp stage after an invalid previous-chain error (W5)",
           r'            finish_flags,\n        \)\n    except WeaveError as error:\n        errors\.append\(error\.code\)\n        if _stops\(\[error\.code\]\):\n            return _finish_after_records\(\)',
           '            finish_flags,\n        )\n    except WeaveError as error:\n        errors.append(error.code)  # ablation: step (10) does not stop the pipeline',
           ("container/previous-signing-key-compromised-at-previous",
            "container/previous-signing-key-compromised-before-previous")),
        _m("ts-der-reencode-response", "timestamps.py", "timestamps.der.reencode",
           "skip the DER re-encoding comparison of the whole TimeStampResp (W3, check 1c)",
           r'    walk = _require_der_reencoding\(der_schema\.TIME_STAMP_RESP, tsr_bytes, "TimeStampResp"\)',
           '    try:  # ablation: TimeStampResp re-encoding not compared\n'
           '        walk = der_schema.reencode(der_schema.TIME_STAMP_RESP, tsr_bytes)[1]\n'
           '    except der_schema.DerViolation:\n'
           '        walk = der_schema.WalkContext()',
           ("integrity-levels/l2-ts-der-setof-certificates-unsorted",
            "integrity-levels/l2-ts-der-setof-crls-unsorted",
            "integrity-levels/l2-ts-der-setof-signed-attrs-unsorted",
            "integrity-levels/l2-ts-der-setof-unsigned-attrs-unsorted")),
        _m("ts-der-reencode-setof-sort", "der_schema.py", "timestamps.der.reencode-setof",
           "re-encode a SET OF in input order instead of DER order (W3, check 1c)",
           r'        if self\.is_set:\n',
           '        if False:  # ablation: SET OF not sorted by the re-encoding\n',
           ("integrity-levels/l2-ts-der-setof-certificates-unsorted",
            "integrity-levels/l2-ts-der-setof-unsigned-attrs-unsorted")),
        _m("ts-der-reencode-tstinfo", "timestamps.py", "timestamps.der.reencode-tstinfo",
           "skip the DER re-encoding comparison of the TSTInfo (W3, check 2)",
           r'    _require_der_reencoding\(der_schema\.TST_INFO, raw_content, "TSTInfo"\)',
           '    pass  # ablation: TSTInfo re-encoding not compared',
           ("integrity-levels/l2-ts-der-default-encoded",
            "integrity-levels/l2-ts-der-implicit-integer-nonminimal")),
        _m("ts-der-set-order-scan", "timestamps.py", "timestamps.der.set-order-scan",
           "do not check universal SET order in the universal-rule scan (W3, check 1a)",
           r'            _scan_set_of\(data, position, content_end, depth \+ 1\)',
           '            _scan_der(data, position, content_end, depth + 1)  # ablation: SET order not scanned',
           ("integrity-levels/l2-ts-der-setof-opaque-unsorted",
            "integrity-levels/l2-ts-der-tstinfo-opaque-unsorted")),
        _m("ts-certificates-decode", "timestamps.py", "timestamps.der.certificates",
           "do not decode the carried certificates in check 1 (W3/W6, check 1e)",
           r'        _load_der_certificate\(signer_certificate_der\)\n',
           '        pass  # ablation: the signer certificate is not decoded in check 1\n',
           ("integrity-levels/l2-ts-certificate-undecodable",)),
        _m("ts-extension-value-der", "timestamps.py", "timestamps.der.extension-values",
           "do not scan certificate extension values (W3, check 1e)",
           r'            _validate_strict_der\(extension_value\)\n',
           '            pass  # ablation: extension values not scanned\n',
           ("integrity-levels/l2-ts-der-extension-value-nonminimal",)),
        _m("ts-key-type-check10", "timestamps.py", "timestamps.cms.key-type",
           "report an algorithm/key-type mismatch as E_TS_CERT instead of check 10 (W6)",
           r'                raise WeaveError\("E_TS_CMS", "signature algorithm does not match the key"\)\n            digest_class = _RSA_PKCS1V15_OIDS',
           '                raise WeaveError("E_TS_CERT", "ablation: key-type mismatch as check 6")\n            digest_class = _RSA_PKCS1V15_OIDS',
           ("integrity-levels/l2-ts-signature-key-type-mismatch",)),
        _m("zip-prefix-phase-1", "zipread.py", "container.zip.prefix-phase",
           "judge bytes before the first local header after the §13 limits (W7 phase 1)",
           r'    _check_prefix\(handle, size, eocd_offset, end_record\)\n',
           '    pass  # ablation: the leading-byte rule is not part of phase 1\n',
           ("container/zip-over-limit-and-prefix",),
           co_mutations=(
               # The container reader's signature probe also refuses a file that
               # does not start with a zip signature; both are phase 1.
               ("container.py",
                r'    return head in \(',
                '    return True or head in (  # co-ablation: signature probe disabled'),
           )),
        _m("tsa-trust-usage-error", "container.py", "container.operator.tsa-trust",
           "treat a malformed --tsa-trust file as an empty anchor set (W4)",
           r'        timestamps_module\.parse_trust_anchors\(tsa_trust\)\n',
           '        pass  # ablation: anchors not validated up front\n',
           (),
           equivalent_reason="a usage error (exit 2, no report) cannot be expressed in the vector "
           "expectation schema, and the later parse still raises the same usage error, so this "
           "site is redundant for valid anchors; the operator-input rule is pinned by the unit "
           "tests test_tsa_trust_malformed_is_usage_error and test_tsa_trust_invalid_version_is_usage_error"),
        _m("keyset-non-regular-entry", "verifier.py", "verifier.keyset.non-regular",
           "silently skip a keyset *.json entry that is not a regular file (W10/L6)",
           r'        except UsageError as error:\n            raise UsageError\(\n                "--keys %s: entry %s is not a regular file" % \(path, entry\.name\)\n            \) from error\n',
           '        except UsageError:\n            continue  # ablation: non-regular keyset entries skipped\n',
           (),
           equivalent_reason="a keyset usage error (exit 2) cannot be expressed in the vector "
           "expectation schema; pinned by the unit tests test_keyset_non_regular_json_entry_is_usage_error "
           "and test_keyset_fifo_entry_is_usage_error_without_blocking"),

        # ------------------------------------------------- S1-FIX5 (X1-X3)
        _m("der-default-omitted", "der_schema.py", "timestamps.der.default",
           "accept a component that encodes its DEFAULT value (X1, check 1c)",
           r'                raise DerViolation\("component %s encodes its DEFAULT value" % field\.name\)',
           '                pass  # ablation: DEFAULT values may be encoded',
           ("integrity-levels/l2-ts-der-default-encoded",
            "integrity-levels/l2-ts-der-ess-hash-algorithm-default-encoded")),
        _m("der-default-ess-library-value", "der_schema.py", "timestamps.der.default-table",
           "take the ESSCertIDv2 DEFAULT as {sha256, NULL} (a parsing library's value) (X1)",
           r'    "ESSCertIDv2\.hashAlgorithm": bytes\.fromhex\("300b0609608648016503040201"\),',
           '    "ESSCertIDv2.hashAlgorithm": bytes.fromhex("300d06096086480165030402010500"),  # ablation',
           ("integrity-levels/l2-ts-der-ess-hash-algorithm-sha256-null",
            "integrity-levels/l2-ts-der-ess-hash-algorithm-default-encoded")),
        _m("der-open-type-decoded", "der_schema.py", "timestamps.der.open-type",
           "hand an open-type value to a type decoder that knows universal tags only (X1)",
           r'        _tag_class, _constructed, _number, _start, content_end = _read_header\(\n            data, position, end\n        \)\n',
           '        _tag_class, _constructed, _number, _start, content_end = _read_header(\n            data, position, end\n        )\n'
           '        if _tag_class != 0:  # ablation: open types decoded by a universal-only decoder\n'
           '            raise DerViolation("unknown element class")\n',
           ("integrity-levels/l2-ts-der-unsigned-attr-context-tag-value",
            "integrity-levels/l2-ts-der-unsigned-attr-application-200-value")),
        _m("der-time-object-round-trip", "der_schema.py", "timestamps.der.time-raw",
           "rebuild GeneralizedTime through a microsecond time object (X1)",
           r'                raise DerViolation\("GeneralizedTime is not in its DER form"\)\n            return raw\n',
           '                raise DerViolation("GeneralizedTime is not in its DER form")\n'
           '            return re.sub(rb"(\\.[0-9]{6})[0-9]+Z$", rb"\\\\1Z", raw)  # ablation: microseconds\n',
           ("integrity-levels/l2-ts-der-gentime-seven-fraction-digits",)),
        _m("der-time-form", "der_schema.py", "timestamps.der.time-form",
           "accept a GeneralizedTime that is not in its DER form (X1, 1c; co-site 1a)",
           r'            if not _GENERALIZED_TIME_DER\.fullmatch\(raw\):\n',
           '            if False:  # ablation: GeneralizedTime form not checked by 1c\n',
           ("integrity-levels/l2-ts-der-gentime-fraction-trailing-zero",),
           co_mutations=(
               ("timestamps.py",
                r'            if not pattern\.fullmatch\(text\):\n',
                '            if False:  # co-ablation: time form not checked by 1a\n'),
           )),
        _m("der-high-tag-first-octet", "timestamps.py", "timestamps.der.high-tag",
           "accept 0x80 as the first subsequent octet of a high tag number (X1, 1a; co-site 1c)",
           r'            if count == 1 and byte == 0x80:\n',
           '            if False:  # ablation: non-minimal high tag number accepted by 1a\n',
           ("integrity-levels/l2-ts-der-high-tag-number-nonminimal",),
           co_mutations=(
               ("der_schema.py",
                r'            if first_subsequent and octet == 0x80:\n',
                '            if False:  # co-ablation: non-minimal high tag number accepted by 1c\n'),
           )),
        _m("der-high-tag-inner-zero", "timestamps.py", "timestamps.der.high-tag-inner",
           "reject a 0x80 group after the first subsequent octet (the pre-X1 1a rule)",
           r'            if count == 1 and byte == 0x80:\n',
           '            if (count == 1 and byte == 0x80) or (count > 1 and data[position - 2] == 0x80):  # ablation\n',
           ("integrity-levels/l2-ts-der-high-tag-number-inner-zero-group",)),
        _m("previous-compromise-created-at", "container.py", "container.previous.compromise",
           "judge a key-compromise revocation on the previous link by \u00a79.4 case 3 (X2)",
           r'                    compromise_at_recorded_time=True,\n',
           '                    # ablation: compromise breaks every link\n',
           ("container/previous-signing-key-compromised-after-previous",)),
        _m("previous-compromise-boundary", "keys.py", "container.previous.compromise-boundary",
           "let a link whose created_at equals the compromise time stand (X2)",
           r'            if timestamp_sort_key\(recorded_at\) >= timestamp_sort_key\(\n                compromises\[0\]\.effective_at\n            \):',
           '            if timestamp_sort_key(recorded_at) > timestamp_sort_key(  # ablation: > instead of >=\n                compromises[0].effective_at\n            ):',
           ("container/previous-signing-key-compromised-at-previous",)),
        _m("previous-invalid-rotation-material", "container.py", "container.previous.rotation-material",
           "let an invalid rotation record supply key material for the previous link (X5)",
           r'            \[record for record in container_records if id\(record\) not in invalid_rotations\],\n',
           '            container_records,  # ablation: invalid rotations supply material\n',
           ("container/previous-invalid-rotation-supplies-no-material",)),
        _m("der-signer-digest-params", "der_schema.py", "timestamps.der.signer-digest-params",
           "accept any well-framed parameters of the signer digestAlgorithm (X6)",
           r'        if rule == "absent-or-null" and parameters not in \(b"", _NULL_ENCODING\):\n',
           '        if False:  # ablation: SHA-2 parameters form not checked\n',
           ("integrity-levels/l2-ts-signer-digest-params-other",)),
        _m("der-signer-digest-params-null-only", "der_schema.py", "timestamps.der.signer-digest-absent",
           "require NULL SHA-2 parameters, rejecting the absent form RFC 5754 permits (X6)",
           r'        if rule == "absent-or-null" and parameters not in \(b"", _NULL_ENCODING\):\n',
           '        if rule == "absent-or-null" and parameters != _NULL_ENCODING:  # ablation\n',
           ("integrity-levels/l2-ts-signer-digest-params-absent",)),
        _m("der-signer-rsa-params", "der_schema.py", "timestamps.der.signer-rsa-params",
           "accept RSA PKCS#1 v1.5 parameters other than NULL (X6)",
           r'        if rule == "null" and parameters != _NULL_ENCODING:\n',
           '        if False:  # ablation: RSA parameters form not checked\n',
           ("integrity-levels/l2-ts-signer-rsa-params-absent",
            "integrity-levels/l2-ts-signer-rsa-params-other")),
        _m("der-signer-ecdsa-params", "der_schema.py", "timestamps.der.signer-ecdsa-params",
           "accept present ECDSA parameters (X6)",
           r'        if rule == "absent" and parameters:\n',
           '        if False:  # ablation: ECDSA parameters form not checked\n',
           ("integrity-levels/l2-ts-signer-ecdsa-params-null",
            "integrity-levels/l2-ts-signer-ecdsa-params-other")),
        # ------------------------------------------------- S1-FIX5 X7
        _m("der-time-anchor-1a", "timestamps.py", "timestamps.der.time-anchor",
           "match the 1a time forms with a $ anchor that admits a trailing line feed (X7/H1)",
           r'            if not pattern\.fullmatch\(text\):\n',
           '            if not pattern.match(text):  # ablation: $ admits a trailing \\n\n',
           ("integrity-levels/l2-ts-der-unsigned-attr-utctime-trailing-newline",
            "integrity-levels/l2-ts-der-unsigned-attr-gentime-trailing-newline")),
        _m("der-time-anchor-1c", "der_schema.py", "timestamps.der.time-anchor-1c",
           "match the 1c GeneralizedTime form with a $ anchor (X7/H1; co-site 1a)",
           r'            if not _GENERALIZED_TIME_DER\.fullmatch\(raw\):\n',
           '            if not _GENERALIZED_TIME_DER.match(raw):  # ablation: $ admits \\n\n',
           ("integrity-levels/l2-ts-der-gentime-trailing-newline",),
           co_mutations=(
               ("timestamps.py",
                r'            if not pattern\.fullmatch\(text\):\n',
                '            if not pattern.match(text):  # co-ablation\n'),
           )),
        _m("der-signer-sha2-rsa-absent", "der_schema.py", "timestamps.der.signer-sha2-rsa",
           "require NULL parameters for sha256WithRSAEncryption (the corrected X6 row, X7/M1)",
           r'    _oid_content\("1\.2\.840\.113549\.1\.1\.11"\): "absent-or-null",',
           '    _oid_content("1.2.840.113549.1.1.11"): "null",  # ablation',
           ("integrity-levels/l2-ts-signer-sha256-rsa-params-absent",)),
        _m("signer-info-count", "timestamps.py", "timestamps.der.signer-info-count",
           "accept more than one SignerInfo (X7/M2)",
           r'    if len\(walk\.signer_identifiers\) != 1:\n',
           '    if False:  # ablation: SignerInfo count not checked\n',
           ("integrity-levels/l2-ts-signer-info-count-two",)),
        _m("non-signer-certificates-decoded", "timestamps.py", "timestamps.der.non-signer-open",
           "decode every carried certificate as X.509, not only the signer's (X7/M3)",
           r'    signer_certificate_der = der_schema\.signer_certificate\(walk\)\n',
           '    for _component in walk.certificates:  # ablation: every certificate decoded\n'
           '        _load_der_certificate(_component)\n'
           '    signer_certificate_der = der_schema.signer_certificate(walk)\n',
           ("integrity-levels/l2-ts-non-signer-certificate-params-octet-string",
            "integrity-levels/l2-ts-non-signer-certificate-undecodable")),
        _m("signer-certificate-walk", "timestamps.py", "timestamps.der.signer-certificate-walk",
           "skip the 1b/1c walk of the signer certificate (X7/M3)",
           r'        certificate_walk = _require_der_reencoding\(\n            der_schema\.CERTIFICATE, signer_certificate_der, "signer certificate"\n        \)\n',
           '        certificate_walk = der_schema.WalkContext()  # ablation: no typed walk\n',
           ("integrity-levels/l2-ts-der-extension-value-nonminimal",)),
        _m("operator-path-kind", "operator_input.py", "operator.path-kind",
           "open operator paths without examining their kind first (X3)",
           r'    if stat\.S_ISREG\(status\.st_mode\):\n        kind = FILE\n    elif stat\.S_ISDIR\(status\.st_mode\):\n        kind = DIRECTORY\n    else:\n',
           '    if not stat.S_ISDIR(status.st_mode):  # ablation: every non-directory counts as a file\n        kind = FILE\n    elif stat.S_ISDIR(status.st_mode):\n        kind = DIRECTORY\n    else:\n',
           (),
           equivalent_reason="a usage error (exit 2, no report) cannot be expressed in the vector "
           "expectation schema; pinned by the unit tests test_tsa_trust_fifo_is_usage_error_without_blocking, "
           "test_previous_fifo_is_usage_error_without_blocking, test_device_file_is_usage_error and "
           "test_socket_is_usage_error"),
        _m("tsa-trust-read-bound", "operator_input.py", "operator.read-bound",
           "read a --tsa-trust file without a bound (X3)",
           r'    if len\(data\) > limit:\n',
           '    if False:  # ablation: no read bound\n',
           (),
           equivalent_reason="a usage error (exit 2, no report) cannot be expressed in the vector "
           "expectation schema; pinned by the unit test test_tsa_trust_above_the_read_bound_is_usage_error"),
    )


_build_catalogue()


# ----------------------------------------------------------------------------- runner


def fail(message: str):
    print("anti_verification: %s" % message, file=sys.stderr)
    raise SystemExit(2)


def pinned_by_problems(selected: list[Mutation], suite: Path) -> list[str]:
    """W10/L2: every ``pinned_by`` is a tuple of vector ids that exist in the suite."""
    index_path = suite / "index.json"
    known: set[str] = set()
    if index_path.is_file():
        index = json.loads(index_path.read_text(encoding="utf-8"))
        rows = index.get("cases", index) if isinstance(index, dict) else index
        for row in rows:
            if isinstance(row, dict) and isinstance(row.get("id"), str):
                known.add(row["id"])
    problems: list[str] = []
    for item in selected:
        if not isinstance(item.pinned_by, tuple):
            problems.append(
                "%s: pinned_by is a %s, not a tuple of vector ids"
                % (item.id, type(item.pinned_by).__name__)
            )
            continue
        for case_id in item.pinned_by:
            if case_id not in known:
                problems.append("%s: pinned_by names an unknown vector %r" % (item.id, case_id))
        if not item.pinned_by and not item.equivalent_reason:
            problems.append("%s: no pinned_by vector and no documented equivalent reason" % item.id)
    return problems


def check_baseline(suite: Path) -> dict:
    """Gate 2 must be green before ablation means anything."""
    argv = [PYTHON, "-m", "hyphaweave_verify.cli", "--test-hooks", "vectors", str(suite)]
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


def apply_patch(
    package_copy: Path,
    module: str,
    anchor: str,
    replacement: str,
    *,
    occurrences: int = 1,
    replace_all: bool = False,
    label: str = "mutation",
) -> Path:
    source_path = package_copy / module
    if not source_path.is_file():
        raise RuntimeError("module %r missing from the package copy" % module)
    text = source_path.read_text(encoding="utf-8")
    matches = list(re.finditer(anchor, text, re.MULTILINE))
    if len(matches) != occurrences:
        raise RuntimeError(
            "stale catalogue: anchor regex for %s matches %d site(s) in %s, expected %d"
            % (label, len(matches), module, occurrences)
        )
    if replace_all:
        mutated = re.sub(anchor, replacement, text, flags=re.MULTILINE)
    else:
        mutated = re.sub(anchor, replacement, text, count=1, flags=re.MULTILINE)
    if mutated == text:
        raise RuntimeError("%s did not change the source" % label)
    source_path.write_text(mutated, encoding="utf-8")
    return source_path


def apply_mutation(mutation: Mutation, package_copy: Path) -> Path:
    return apply_patch(
        package_copy,
        mutation.module,
        mutation.anchor,
        mutation.replacement,
        occurrences=mutation.occurrences,
        replace_all=mutation.replace_all,
        label="mutation %s" % mutation.id,
    )


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
        argv = [PYTHON, "-m", "hyphaweave_verify.cli", "--test-hooks", "vectors", str(suite)]
        proc = subprocess.run(argv, capture_output=True, text=True, cwd=str(REPO), env=env)
        report = None
        if proc.stdout.strip():
            try:
                report = json.loads(proc.stdout)
            except json.JSONDecodeError:
                report = None
        mismatched = 0
        mismatch_ids: list[str] = []
        if report is not None:
            for case in report.get("cases") or []:
                if not case.get("ok"):
                    mismatched += 1
                    if len(mismatch_ids) < 5:
                        mismatch_ids.append(str(case.get("id")))
        # V2d: no gate counts a crash as a rejection or a kill. A mutation that
        # aborts without a report, exits outside {0,1,2,3}, or writes a traceback
        # is a catalogue error (gate failure), not a "killed by crash" mutation.
        traceback_on_stderr = "Traceback" in proc.stderr
        if report is None or traceback_on_stderr or proc.returncode not in (0, 1, 2, 3):
            return MutationResult(
                mutation,
                "error",
                detail="mutant crashed/aborted instead of reporting: rc=%d%s"
                % (
                    proc.returncode,
                    " (traceback on stderr)" if traceback_on_stderr else "",
                ),
                imported_file=resolved,
                exit_code=proc.returncode,
            )
        killed = proc.returncode != 0 or report.get("verdict") != "valid"
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
                mismatched_case_ids=tuple(mismatch_ids),
                kill_kind="mismatch",
            )
        if mutation.co_mutations:
            combined = _run_combined(mutation, suite)
            if combined is not None:
                return combined
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


def _run_combined(mutation: Mutation, suite: Path) -> MutationResult | None:
    """Disable this site plus its co-sites; return a ``redundant`` result when vectors go red."""
    combined_dir = MUTANT_ROOT / (mutation.id + "__combined")
    try:
        package_copy = copy_package(combined_dir)
        apply_mutation(mutation, package_copy)
        for index, (module, anchor, replacement) in enumerate(mutation.co_mutations):
            apply_patch(
                package_copy,
                module,
                anchor,
                replacement,
                label="%s co-site %d" % (mutation.id, index),
            )
        env = mutant_env(combined_dir)
        resolved = imported_file(env)
        argv = [PYTHON, "-m", "hyphaweave_verify.cli", "--test-hooks", "vectors", str(suite)]
        proc = subprocess.run(argv, capture_output=True, text=True, cwd=str(REPO), env=env)
        report = None
        if proc.stdout.strip():
            try:
                report = json.loads(proc.stdout)
            except json.JSONDecodeError:
                report = None
        if report is None or "Traceback" in proc.stderr or proc.returncode not in (0, 1, 2, 3):
            # V2d: a crash in the combined mutant is a catalogue error, not a
            # documented-redundant result.
            raise RuntimeError("combined mutant crashed/aborted: rc=%d" % proc.returncode)
        if proc.returncode != 0 or report.get("verdict") != "valid":
            mismatched = 0
            mismatch_ids: list[str] = []
            if report is not None:
                for case in report.get("cases") or []:
                    if not case.get("ok"):
                        mismatched += 1
                        if len(mismatch_ids) < 5:
                            mismatch_ids.append(str(case.get("id")))
            return MutationResult(
                mutation,
                "redundant",
                detail=(
                    "single-site removal is invisible because the same semantic is enforced "
                    "at %d co-site(s); disabling the site AND the co-sites makes the vectors "
                    "red (%d mismatched case(s)), so the semantic is pinned"
                    % (len(mutation.co_mutations), mismatched)
                ),
                imported_file=resolved,
                exit_code=proc.returncode,
                report_verdict=(report or {}).get("verdict"),
                mismatched_cases=mismatched,
                mismatched_case_ids=tuple(mismatch_ids),
            )
        return None
    except RuntimeError:
        return None


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

    pin_problems = pinned_by_problems(selected, suite)
    if args.self_test:
        problems: list[str] = list(pin_problems)
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
        print(
            "catalogue: %d mutation(s), %d stale anchor or pinned_by problem(s)"
            % (len(selected), len(problems))
        )
        return 0 if not problems else 1
    if pin_problems:
        # W10/L2: a pinned_by entry must be a tuple of real vector ids; a
        # string (a missing comma) or a stale id is a catalogue error.
        for problem in pin_problems:
            print("CATALOGUE ERROR: %s" % problem, file=sys.stderr)
        fail("%d pinned_by problem(s) in the mutation catalogue" % len(pin_problems))

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
    redundant = [item for item in results if item.status == "redundant"]
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
        "killed_by_mismatch": len([item for item in killed if item.kill_kind == "mismatch"]),
        "killed_by_crash": 0,  # V2d: a crash is a catalogue error, never a kill
        "survivors": len(survivors),
        "unpinned_survivors": len(unpinned),
        "documented_redundant": len(redundant),
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
                "co_mutations": len(item.mutation.co_mutations),
                "status": item.status,
                "detail": item.detail,
                "imported_file": item.imported_file,
                "exit_code": item.exit_code,
                "report_verdict": item.report_verdict,
                "mismatched_cases": item.mismatched_cases,
                "mismatched_case_ids": list(item.mismatched_case_ids),
                "kill_kind": item.kill_kind,
                "pytest_caught": item.pytest_caught,
            }
            for item in results
        ],
    }
    report_path = Path(args.json)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print()
    killed_clean = [item for item in killed if item.kill_kind == "mismatch"]
    print(
        "source ablation: %d mutations, %d killed (%d by mismatch; crashes are catalogue errors), %d survivors "
        "(%d unpinned, %d documented equivalent), %d documented redundant, %d catalogue errors"
        % (
            len(selected), len(killed), len(killed_clean), len(survivors),
            len(unpinned), len(equivalents), len(redundant), len(errors),
        )
    )
    for item in errors:
        print("  CATALOGUE ERROR %s: %s" % (item.mutation.id, item.detail))
    for item in equivalents:
        print("  EQUIVALENT (documented): %s :: %s" % (item.mutation.id, item.mutation.equivalent_reason))
    for item in redundant:
        print("  REDUNDANT (documented): %s :: %s" % (item.mutation.id, item.detail))
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
    try:
        shown_path = report_path.resolve().relative_to(REPO.resolve())
    except ValueError:
        shown_path = report_path
    print("summary written to %s" % shown_path)
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
