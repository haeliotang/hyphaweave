<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# `weave.consent.granted` — record informed consent

**Kind:** `weave.consent.granted` · **Stage:** `accepted` only · **Per-record signature:**
REQUIRED · **Decision tags:** [H1] [H3] · **Normative parent:** `spec/weave-record-1.md`
§8.6. Every normative rule below is `decided (Inceptless decision 2026-11-10 #34)` where it
implements rulings H3/M-7.

## Purpose

Consent is evidence, not a checkbox: a signed record stating who consented, for what
purpose, over what scope, for how long, and on what terms [H3]. Records that process a
person's data reference such a consent through `labels.consent`; a later
`weave.consent.revoked` withdraws it, immediately and with the effect defined in §8.6 of the
parent specification.

## Envelope requirements

- `kind` is exactly `weave.consent.granted`; `stage` **MUST** be `accepted`
  (`E_ENV_STAGE`).
- `actor.type` **MUST** be `human` or `organization`; a non-human/organization signer is
  `E_ACTOR_KEY_TYPE_MISMATCH` (the kind's signer rule; parent specification §5.1/Q30).
- `sigs` **MUST** be present. If `sigs` is non-empty but the required human/organization
  signer is missing or wrong, `E_ACTOR_KEY_TYPE_MISMATCH` is reported instead of
  `E_SIG_REQUIRED`; `E_SIG_REQUIRED` is used only when `sigs` is absent or empty.
- `salt` is optional; `refs` and `labels` follow the parent specification.

## Body

| member | required | type | rule |
|---|---|---|---|
| `purpose` | yes | string | 1–1024 Unicode scalar values |
| `scope` | yes | array | 1–32 strings, each 1–256 Unicode scalar values |
| `valid_from` | yes | TS | start of the claimed consent window |
| `valid_until` | yes | TS or `null` | end of the window; `null` means no stated end |
| `data_subject` | yes | reference object or `null` | the subject whose data is covered, when a record exists for them |
| `terms` | yes | string or `null` | consent terms text or description (audit text, not machine-checked) |

## Semantic rules

1. **Validity window ordering.** When `valid_until` is not `null`, `valid_from` MUST be less
   than or equal to `valid_until`; otherwise `E_CONSENT_VALIDITY` (invalid) [H3].
2. **Signed claim.** The consent is a claim by the signing actor that the described consent
   was given. The verifier checks consistency, signatures and grammar; it does not prove that
   a real person was informed, nor that the terms are lawful (parent specification §8.8).
3. **Reference from records.** Records cite this consent through `labels.consent`; the cited
   kind must be `weave.consent.granted` or `weave.consent.revoked`. If the cited consent has
   been revoked, a citing record with claimed `recorded_at >= effective_at` is invalid with
   `E_CONSENT_REVOKED` (parent specification §8.6) [M-7] decided (Inceptless decision
   2026-11-10 #34; M-7).
4. **Withdrawal.** Withdrawal is a separate `weave.consent.revoked` record; a consent record
   is never edited in place.
5. **Consent is not transferable.** There is no delegation member; proxy consent is recorded
   by the proxy as an actor with its own grant chain under project policy.

## Error codes

| code | verdict | condition |
|---|---|---|
| `E_ENV_STAGE` | invalid | stage is not `accepted` |
| `E_CONSENT_VALIDITY` | invalid | `valid_from > valid_until` |
| `E_KIND_BODY_SCHEMA` | invalid | body shape, vocabulary or string length violation |
| `E_ACTOR_KEY_TYPE_MISMATCH` | invalid | actor/signing key is not human or organization |
| `E_SIG_REQUIRED`, `E_SIG_UNVERIFIABLE`, `E_SIG_INVALID` | invalid / unverifiable | per parent specification §4.4 |
| `E_KEY_UNKNOWN` | unverifiable | signer's key is not available in context |
| `N_KEY_TOFU`, `N_KEY_UNDECLARED`, `N_NO_HUMAN_SIGNATURE` | notice | reporting |

## Canonical JSON example

<!-- spec-example: standalone-record -->
```json
{"actor":{"key":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","type":"human"},"body":{"data_subject":null,"purpose":"operational energy reporting","scope":["electricity meter readings at site A"],"terms":null,"valid_from":"2026-11-01T00:00:00.000Z","valid_until":"2027-11-01T00:00:00.000Z"},"format":"weave-record/1","id":"consent-1","kind":"weave.consent.granted","origin":{"instance":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","project":"example"},"recorded_at":"2026-11-02T02:00:00.000Z","sigs":[{"alg":"ed25519","key":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","value":"ARf3HW3X_FdUEO5OZ9kpCz5UE8jVj9-H7e8Xy2j8qnUvrIR5N9vc4lhiQI1yjCTZXjJ5t8IvQxl2JUWJf8IIDg"}],"stage":"accepted"}
```

## Why this kind exists

Data use needs a verifiable basis, and "the person consented" must survive offline and
independent of any service. Consent as a signed record with purpose, scope, validity and
subject makes the basis explicit and referenceable from the records that rely on it; making
withdrawal immediate closes the gap between "can be revoked" and "is revoked" [H1][H3].

(Per §14.10 of the parent specification and the marker convention: `standalone-record`
examples must pass the verifier as-is; `container-context` examples need surrounding
records; `illustrative` examples are shapes.)
