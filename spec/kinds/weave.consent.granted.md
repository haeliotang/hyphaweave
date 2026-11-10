<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# `weave.consent.granted` — record informed consent

**Kind:** `weave.consent.granted` · **Stage:** `accepted` only · **Per-record signature:**
REQUIRED · **Decision tags:** [H1] [H3] · **Normative parent:** `spec/weave-record-1.md`
§8.6, §4.4.

## Purpose

Consent is evidence, not a checkbox: it is a signed record stating who consented, for what
purpose, over what scope, for how long, and on what terms [H3]. Records that process a
person's data reference such a consent record through `labels.consent`; a later
`weave.consent.revoked` record withdraws it. Because consent is itself a record in the same
signed container, it can be verified offline together with the records that rely on it
[H3][H1].

## Envelope requirements

- `kind` is exactly `weave.consent.granted`; `stage` **MUST** be `accepted`
  (`E_ENV_STAGE`) [H3][§7.2].
- `actor.type` **MUST** be `human` or `organization`; any other actor type is a kind-body
  violation (`E_KIND_BODY_SCHEMA`; the decision draft does not name a dedicated code for
  this case — PROVISIONAL gap-filling choice).
- `sigs` **MUST** be present and include a valid signature by `actor.key` [§4]. If `sigs`
  is non-empty but no signature satisfies the required human/organization signer rule, the
  kind code `E_ACTOR_KEY_TYPE_MISMATCH` is reported (not `E_SIG_REQUIRED`, §4.4 precedence,
  Q31); `E_SIG_REQUIRED` is used only when `sigs` is absent or empty.
- `salt` is optional; a consent record is not necessarily `personal` data itself. `refs`
  and `labels` follow the parent specification.

## Body

| member | required | type | rule |
|---|---|---|---|
| `purpose` | yes | string | 1–1024 Unicode scalar values; what the consent is for |
| `scope` | yes | array | 1–32 strings, each 1–256 Unicode scalar values; the data/activities covered |
| `valid_from` | yes | TS | start of the claimed consent window |
| `valid_until` | yes | TS or `null` | end of the window; `null` means no stated end |
| `data_subject` | yes | reference object or `null` | the subject whose data is covered, when a record exists for them |
| `terms` | yes | string or `null` | the consent terms text or a reference-like description (audit text, not machine-checked) |

## Semantic rules

1. **Validity window ordering.** When `valid_until` is not `null`, `valid_from` **MUST** be
   less than or equal to `valid_until`; otherwise `E_CONSENT_VALIDITY` (invalid) [H3].
2. **Signed claim.** The consent is a claim by the signing actor that the described consent
   was given. The verifier checks consistency, signatures and time grammar; it does not
   prove that a real person was informed, nor that the terms are lawful (claims, not truth,
   parent specification §8.8).
3. **Reference from records.** Records reference a consent record through
   `labels.consent`; the referenced kind must be `weave.consent.granted` or
   `weave.consent.revoked` (§8.6 of the parent specification). If the target is a
   `weave.consent.revoked`, the consent has been withdrawn; H0 verification records the
   claim and does not re-evaluate whether the citing record's purpose is still covered
   (declared limitation).
4. **Revocation.** Withdrawal is a separate `weave.consent.revoked` record that references
   this grant; see that kind page [H3].
5. **Consent is not transferred.** A consent record's authority is not delegable; there is
   no transfer member. A project needing proxy consent records the proxy as an actor with
   its own grant chain (project-level policy).
6. **No automatic expiry enforcement on citing records.** In H0 the verifier does not
   evaluate whether a citing record falls inside `valid_from`/`valid_until`; the times are
   claims available to policy on top of verification.

## Error codes

| code | verdict | condition |
|---|---|---|
| `E_ENV_STAGE` | invalid | stage is not `accepted` |
| `E_CONSENT_VALIDITY` | invalid | `valid_from > valid_until` |
| `E_KIND_BODY_SCHEMA` | invalid | body shape, vocabulary, string length or actor-type violation |
| `E_SIG_REQUIRED` | invalid | `sigs` is absent or an empty array (per-record signing required) |
| `E_ACTOR_KEY_TYPE_MISMATCH` | invalid | signer key class incompatible with the human/organization actor |
| `E_KEY_UNKNOWN` | unverifiable | signer's key is not available in context |
| `N_KEY_TOFU`, `N_KEY_UNDECLARED` | notice | trust-on-first-use reporting |

## Canonical JSON example

```json
{"actor":{"key":"ed25519:7777777777777777777777777777777777777777777777777777777777777777","type":"human"},"body":{"data_subject":null,"purpose":"operational energy reporting","scope":["electricity meter readings at site A"],"terms":null,"valid_from":"2026-11-01T00:00:00.000Z","valid_until":"2027-11-01T00:00:00.000Z"},"format":"weave-record/1","id":"consent-1","kind":"weave.consent.granted","origin":{"instance":"ed25519:7777777777777777777777777777777777777777777777777777777777777777","project":"example"},"recorded_at":"2026-11-01T12:00:00.000Z","sigs":[{"alg":"ed25519","key":"ed25519:7777777777777777777777777777777777777777777777777777777777777777","value":"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"}],"stage":"accepted"}
```

## Why this kind exists

Data use needs a verifiable basis, and "the person consented" must survive offline and
independent of any service. Consent as a signed record with purpose, scope and time makes
the basis explicit, reviewable and referenceable from the records that rely on it [H1][H3].
