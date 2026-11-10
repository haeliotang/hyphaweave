<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# `weave.consent.revoked` — withdraw a consent grant

**Kind:** `weave.consent.revoked` · **Stage:** `accepted` only · **Per-record signature:**
REQUIRED · **Decision tags:** [H3] · **Normative parent:** `spec/weave-record-1.md` §8.6,
§4.4.

## Purpose

Withdraws a previously granted consent. Withdrawal takes effect immediately and is the
reference basis for subsequent records: after a revocation exists in the context, a record
that cites the revoked consent can be judged by policy (and by a later verifier) as no
longer covered [H3]. Modelled as a separate kind rather than an edit of the grant, because
the format is append-only: evidence is never rewritten in place.

## Envelope requirements

- `kind` is exactly `weave.consent.revoked`; `stage` **MUST** be `accepted`
  (`E_ENV_STAGE`) [H3][§7.2].
- `actor.type` **MUST** be `human` or `organization`; any other actor type is a kind-body
  violation (`E_KIND_BODY_SCHEMA`; PROVISIONAL gap-filling choice of code — the decision
  draft does not name one).
- `sigs` **MUST** be present and include a valid signature by `actor.key` [§4]. If `sigs`
  is non-empty but no signature satisfies the required human/organization signer rule, the
  kind code `E_ACTOR_KEY_TYPE_MISMATCH` is reported (not `E_SIG_REQUIRED`, §4.4 precedence,
  Q31); `E_SIG_REQUIRED` is used only when `sigs` is absent or empty.
- `salt`, `refs` and `labels` follow the parent specification.

## Body

| member | required | type | rule |
|---|---|---|---|
| `revokes` | yes | reference object | the `weave.consent.granted` record being withdrawn |
| `effective_at` | yes | TS | claimed instant from which the consent is withdrawn |
| `reason` | yes | string or `null` | free-form reason (not interpreted) |

## Semantic rules

1. **Reference target.** `revokes` **MUST** resolve to a record whose kind is
   `weave.consent.granted`; otherwise `E_CONSENT_REVOKE_REF` (invalid) [H3]. If the
   reference's optional `kind` claim contradicts the resolved target's kind, that is
   `E_REF_KIND_MISMATCH` (invalid).
2. **Immediate effect.** The revocation is effective from `effective_at`; it is visible in
   any container that includes the record, with no propagation delay [H3]. H0 does not
   evaluate the effect of a revocation on records that cite the consent (a declared
   limitation): the verifier establishes that the revocation exists and what it references,
   and policy decides coverage.
3. **Revoker identity.** H0 does not require the revocation to be signed by the same party
   that signed the grant (the decision draft only constrains `actor.type`); a human or
   organization key may record a withdrawal. This is a gap-filling reading; it should be
   tightened in a later version so that only the consent holder or an authorised fiduciary
   can withdraw.
4. **Revocation of a revocation.** There is no "un-revoke" record in H0; a new consent grant
   is appended instead, with a new id and digest.
5. **`effective_at` relation to `recorded_at`.** The decision draft does not constrain
   `effective_at` relative to `recorded_at`; a future `effective_at` is a scheduled
   withdrawal. H0 records the claim and does not enforce a relation.

## Error codes

| code | verdict | condition |
|---|---|---|
| `E_ENV_STAGE` | invalid | stage is not `accepted` |
| `E_CONSENT_REVOKE_REF` | invalid | `revokes` does not resolve to a `weave.consent.granted` |
| `E_REF_KIND_MISMATCH` | invalid | reference kind claim contradicts the resolved target kind |
| `E_KIND_BODY_SCHEMA` | invalid | body shape, grammar or actor-type violation |
| `E_SIG_REQUIRED` | invalid | `sigs` is absent or an empty array (per-record signing required) |
| `E_KEY_UNKNOWN` | unverifiable | signer's key is not available in context |
| `N_KEY_TOFU`, `N_KEY_UNDECLARED` | notice | trust-on-first-use reporting |

## Canonical JSON example

```json
{"actor":{"key":"ed25519:7777777777777777777777777777777777777777777777777777777777777777","type":"human"},"body":{"effective_at":"2026-12-01T00:00:00.000Z","reason":"project ended","revokes":{"digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","id":"consent-1","kind":"weave.consent.granted","origin":{"instance":"ed25519:7777777777777777777777777777777777777777777777777777777777777777","project":"example"}}},"format":"weave-record/1","id":"consent-1-revoke","kind":"weave.consent.revoked","origin":{"instance":"ed25519:7777777777777777777777777777777777777777777777777777777777777777","project":"example"},"recorded_at":"2026-12-01T09:00:00.000Z","sigs":[{"alg":"ed25519","key":"ed25519:7777777777777777777777777777777777777777777777777777777777777777","value":"GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG"}],"stage":"accepted"}
```

## Why this kind exists

Consent that cannot be withdrawn is not consent. Withdrawal must be as durable and
verifiable as the grant, and it must not rewrite history: the grant stays, the withdrawal is
appended, and both are visible offline [H3].
