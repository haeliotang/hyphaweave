<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# `weave.key.revoked` — announce key revocation

**Kind:** `weave.key.revoked` · **Stage:** `accepted` only · **Per-record signature:** REQUIRED
· **Decision tags:** [E5] [D3] · **Normative parent:** `spec/weave-record-1.md` §9.3, §9.4, §4.4.

## Purpose

Announces that a key must no longer be trusted after a claimed effective time, and why. The
reason matters: `key-compromise` revocations apply **retroactively** — signatures made after
the compromise are invalid unless the record/signature provably existed before the
effective time through a verified external timestamp — whereas `retired` (and `other`,
which is treated as `retired`) apply only going forward [E5][D3].

## Envelope requirements

- `kind` is exactly `weave.key.revoked`; `stage` **MUST** be `accepted`
  (`E_ENV_STAGE`) [E5][§4].
- `sigs` **MUST** be present [§4]. `actor.key` **MUST** be one of the signing keys; its
  declared class with `actor.type` obeys the signer-class rules below. If `sigs` is
  non-empty but no signature satisfies the required signer rule below,
  `E_KEY_REVOKE_SIGNER` is reported (not `E_SIG_REQUIRED`); `E_SIG_REQUIRED` is used only
  when `sigs` is absent or empty (§4.4 precedence, Q31). `actor.type` here
  names the class of the signing or revoked key the record is about, not a delegated
  actor: the four agent-only envelope members are **NOT required** for this kind even when
  the class is `agent` (parent specification §4.2 exception, PROVISIONAL Q28).
- Signer requirements:
  - `reason == "key-compromise"`: at least one valid signature by a key declared `human` or
    `organization` (`E_KEY_REVOKE_SIGNER`). The compromised key itself need not (and
    normally cannot safely) sign.
  - `reason == "retired"` or `"other"`: at least one valid signature by the revoked key
    itself **or** by a key declared `human` or `organization`
    (`E_KEY_REVOKE_SIGNER`).
- For this kind, the signer-class rules of this page are authoritative (Q30, accepted
  during H0 integration): the generic human-key prohibition for agent records does not
  override an explicitly required human/organization signature, and additionally the
  revoked key itself may sign a `retired`/`other` revocation even when its class differs
  from a human co-signer. The three key-lifecycle kinds are excluded from the registry's
  `E_ACTOR_HUMAN_KEY` condition for extra signatures.

## Body

| member | required | type | rule |
|---|---|---|---|
| `effective_at` | yes | TS | claimed instant from which the revocation applies |
| `key` | yes | key id | the revoked key id |
| `reason` | yes | string | one of `key-compromise`, `retired`, `other` |
| `note` | no | string | free-form note (not interpreted) |

## Semantic rules

1. **Effective time.** `effective_at` **MUST** be less than or equal to `recorded_at`;
   otherwise `E_KEY_REVOKE_EFFECTIVE` (invalid) [E5].
2. **Revocation is retroactive only for compromise.** For `retired`/`other`: any
   record or manifest signature by the revoked key whose claimed time is later than
   `effective_at` is invalid (`E_KEY_REVOKED`); earlier signatures are unaffected. For
   `key-compromise`: a signature whose claimed time is later than `effective_at` is invalid
   (`E_KEY_COMPROMISED`), **unless** the signature is covered by a verified L2 timestamp
   with `genTime <= effective_at`, in which case the content provably existed before the
   compromise and remains valid [E5][D3]. A single-record target has no timestamp evidence,
   so the compromise exception cannot be applied there.
3. **Self-evidencing.** A revocation of the key that signed this record does not invalidate
   this record; it is the revocation itself (§9.5 of the parent specification).
4. **Revocation is not proof of compromise time.** `effective_at` is a claim by the
   revoker; H0 does not attempt to establish when a compromise actually happened. The
   retroactive rule is a policy that limits the damage of undated post-compromise
   signatures [E5].
5. **Revoking an already-revoked key** is permitted; multiple revocations are separate
   claims and H0 does not merge them (limitation: the earliest-effective reason should be
   used by policy, not by the verifier).

## Error codes

| code | verdict | condition |
|---|---|---|
| `E_ENV_STAGE` | invalid | stage is not `accepted` |
| `E_KEY_REVOKE_EFFECTIVE` | invalid | `effective_at > recorded_at` |
| `E_KEY_REVOKE_SIGNER` | invalid | no signature by an allowed signer (per reason) |
| `E_SIG_REQUIRED` | invalid | `sigs` is absent or an empty array (per-record signing required) |
| `E_KIND_BODY_SCHEMA` | invalid | body shape, reason vocabulary or code grammar violation |
| `E_KEY_REVOKED` | invalid | later retired-key signature |
| `E_KEY_COMPROMISED` | invalid | later compromised-key signature without pre-compromise timestamp |
| `E_KEY_UNKNOWN` | unverifiable | signer's key is not available in context |
| `N_KEY_TOFU`, `N_KEY_UNDECLARED` | notice | trust-on-first-use reporting |

## Canonical JSON example

A human key revokes an agent key after a compromise:

```json
{"actor":{"key":"ed25519:3333333333333333333333333333333333333333333333333333333333333333","type":"human"},"body":{"effective_at":"2026-11-07T15:00:00.000Z","key":"ed25519:4444444444444444444444444444444444444444444444444444444444444444","note":"laptop lost","reason":"key-compromise"},"format":"weave-record/1","id":"revoke-agent-1","kind":"weave.key.revoked","origin":{"instance":"ed25519:3333333333333333333333333333333333333333333333333333333333333333","project":"example"},"recorded_at":"2026-11-07T16:30:00.000Z","sigs":[{"alg":"ed25519","key":"ed25519:3333333333333333333333333333333333333333333333333333333333333333","value":"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"}],"stage":"accepted"}
```

## Why this kind exists

Keys get lost, stolen, retired or compromised; the format must let any holder of the
container learn this offline. Publishing revocation as a signed record keeps trust local
and CA-free, and the retroactive compromise rule limits the value of signatures made after a
theft without depending on a central notary [E5][E4][D3].
