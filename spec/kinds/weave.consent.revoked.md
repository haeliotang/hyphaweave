<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# `weave.consent.revoked` — withdraw a consent grant

**Kind:** `weave.consent.revoked` · **Stage:** `accepted` only · **Per-record signature:**
REQUIRED · **Decision tags:** [H3] · **Normative parent:** `spec/weave-record-1.md` §8.6.
Every normative rule below is `decided (Inceptless decision 2026-11-10 #34)` where it
implements ruling M-7.

## Purpose

Withdraws a previously granted consent, immediately. The withdrawal is a new signed record;
the original grant is never edited, because the format is append-only. Records that cite the
revoked consent at or after the revocation's effective time are invalid
(`E_CONSENT_REVOKED`) [H3][M-7] decided (Inceptless decision 2026-11-10 #34; M-7).

## Envelope requirements

- `kind` is exactly `weave.consent.revoked`; `stage` **MUST** be `accepted`
  (`E_ENV_STAGE`).
- `actor.type` **MUST** be `human` or `organization`; a non-human/organization signer is
  `E_ACTOR_KEY_TYPE_MISMATCH` (parent specification §5.1/Q30). If `sigs` is non-empty but the
  required human/organization signer is missing or wrong, that code is reported instead of
  `E_SIG_REQUIRED`.
- `sigs` **MUST** be present unless... (it is required: `stage == accepted`); missing or
  empty `sigs` is `E_SIG_REQUIRED`.
- `salt`, `refs` and `labels` follow the parent specification.

## Body

| member | required | type | rule |
|---|---|---|---|
| `revokes` | yes | reference object | the `weave.consent.granted` record being withdrawn |
| `effective_at` | yes | TS | claimed instant from which the consent is withdrawn |
| `reason` | yes | string or `null` | free-form reason (not interpreted) |

## Semantic rules

1. **Reference target.** `revokes` MUST resolve to a record whose kind is
   `weave.consent.granted`; otherwise `E_CONSENT_REVOKE_REF` (invalid). A reference `kind`
   claim that contradicts the resolved target kind is `E_REF_KIND_MISMATCH`.
2. **Immediate effect.** The withdrawal takes effect at `effective_at`. A record that cites
   this consent (through `labels.consent`) is invalid with `E_CONSENT_REVOKED` when its
   claimed `recorded_at >= effective_at`; a record with `recorded_at < effective_at` is
   unaffected. The boundary belongs to revocation (equality counts as revoked) [M-7]
   decided (Inceptless decision 2026-11-10 #34; M-7).
3. **Revoker identity.** H0 requires an `actor.type` of `human` or `organization`; it does
   not bind the revoker to the original consent holder. A project MAY apply a stricter policy
   on top of verification; the wire format records the claim and the signature.
4. **No un-revoke.** There is no record that cancels a withdrawal; a new consent grant is
   appended instead, with a new id and digest.
5. **`effective_at` relation to `recorded_at`.** H0 does not constrain the relation; a
   future `effective_at` is a scheduled withdrawal.

## Error codes

| code | verdict | condition |
|---|---|---|
| `E_ENV_STAGE` | invalid | stage is not `accepted` |
| `E_CONSENT_REVOKE_REF` | invalid | `revokes` does not resolve to a `weave.consent.granted` |
| `E_CONSENT_REVOKED` | invalid | on a *citing record*: cited consent revoked at or before its `recorded_at` |
| `E_REF_KIND_MISMATCH` | invalid | reference kind claim contradicts the resolved target kind |
| `E_KIND_BODY_SCHEMA` | invalid | body shape or grammar violation |
| `E_ACTOR_KEY_TYPE_MISMATCH` | invalid | actor/signing key is not human or organization |
| `E_SIG_REQUIRED`, `E_SIG_UNVERIFIABLE`, `E_SIG_INVALID` | invalid / unverifiable | per parent specification §4.4 |
| `E_KEY_UNKNOWN` | unverifiable | signer's key is not available in context |
| `N_KEY_TOFU`, `N_KEY_UNDECLARED`, `N_NO_HUMAN_SIGNATURE` | notice | reporting |

## Canonical JSON example

A withdrawal record always needs its target `weave.consent.granted` record in the
verification context, so this complete record is marked `container-context`; it would be
verified inside a container that carries both records.

<!-- spec-example: container-context -->
```json
{"actor":{"key":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","type":"human"},"body":{"effective_at":"2026-12-01T00:00:00.000Z","reason":"project ended","revokes":{"digest":"sha256:4444444444444444444444444444444444444444444444444444444444444444","id":"consent-1","kind":"weave.consent.granted","origin":{"instance":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","project":"example"}}},"format":"weave-record/1","id":"consent-1-revoke","kind":"weave.consent.revoked","origin":{"instance":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","project":"example"},"recorded_at":"2026-12-01T00:00:00.000Z","sigs":[{"alg":"ed25519","key":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","value":"aryl2tmini5qSen5f7ZFF4ln88hefZGdHOAEj5nMH0fdfikYQ5YyAU4Du04VyE85b44O-1tg7msv5rzRJwZoCA"}],"stage":"accepted"}
```

## Why this kind exists

Consent that cannot be withdrawn is not consent; withdrawal must be as durable and
verifiable as the grant and must not rewrite history. Making a citation of a withdrawn
consent invalid — not merely noticed — gives the withdrawal wire-level effect [H3][M-7]
decided (Inceptless decision 2026-11-10 #34; M-7).
