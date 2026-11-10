<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# `weave.key.revoked` — announce key revocation

**Kind:** `weave.key.revoked` · **Stage:** `accepted` only · **Per-record signature:** REQUIRED
· **Decision tags:** [E5] [D3] · **Normative parent:** `spec/weave-record-1.md` §9.3 and
§9.4. Every normative rule below is `decided (Inceptless decision 2026-11-10 #34; S2/Q11/
Q20)` where it implements those rulings.

## Purpose

Announces that a key must no longer be trusted, and why. The reason is load-bearing:

- `key-compromise` is **retroactive without relying on claimed time**: any signature by the
  compromised key is valid only when a verified RFC 3161 timestamp proves the signed
  manifest existed at or before the revocation's effective time. A thief cannot backdate
  `recorded_at` to evade the revocation.
- `retired` (and `other`, treated as retired) applies only to signatures claimed after the
  effective time.

## Envelope requirements

- `kind` is exactly `weave.key.revoked`; `stage` **MUST** be `accepted`
  (`E_ENV_STAGE`).
- `sigs` **MUST** be present. The key-lifecycle exception of parent specification §4.2
  applies (the four agent-only envelope members are not required).
- Signer requirements:
  - `reason == "key-compromise"`: at least one valid signature by a key declared `human`
    or `organization` (`E_KEY_REVOKE_SIGNER`). The compromised key itself need not and
    normally cannot safely sign.
  - `reason == "retired"` or `"other"`: at least one valid signature by the revoked key
    itself, or by a key declared `human` or `organization` (`E_KEY_REVOKE_SIGNER`).
- For this kind the signer rules above are authoritative for counter-signatures (parent
  specification §5.1, Q30).

## Body

| member | required | type | rule |
|---|---|---|---|
| `effective_at` | yes | TS | claimed instant from which the revocation applies |
| `key` | yes | key id | the revoked key id |
| `reason` | yes | string | one of `key-compromise`, `retired`, `other` |
| `note` | no | string | free-form note (not interpreted) |

## Semantic rules

1. **Effective time.** `effective_at` **MUST** be less than or equal to `recorded_at`
   (`E_KEY_REVOKE_EFFECTIVE`, invalid) [E5].
2. **Retired / other.** A signature by the revoked key whose claimed `recorded_at` is at or
   after `effective_at` is invalid (`E_KEY_REVOKED`); a signature claimed earlier is
   unaffected. The boundary belongs to revocation (equality counts as revoked) [Q11][M-2]
   decided (Inceptless decision 2026-11-10 #34; Q11).
3. **Compromise (S2).** After a `key-compromise` revocation with effective time `T`, **every**
   signature by the revoked key is invalid (`E_KEY_COMPROMISED`) unless the signed record is
   covered by a verified RFC 3161 timestamp whose `genTime` is at or before `T` (`genTime`
   converted to integer milliseconds, parent specification §12.2). The claimed
   `recorded_at` is **not** evidence: it is attacker-controlled. For a manifest signature
   the same test uses the manifest's timestamp chain; a single-record target has no
   timestamp evidence and is invalid [S2] decided (Inceptless decision 2026-11-10 #34; S2).
4. **Self-evidencing.** A revocation of the key that signed this record does not invalidate
   this record; it is the revocation itself (parent specification §9.5).
5. **Revocation is a claim.** `effective_at` is a claim by the revoker; H0 does not
   establish when a compromise actually happened beyond the timestamp rule of rule 3.

## Error codes

| code | verdict | condition |
|---|---|---|
| `E_ENV_STAGE` | invalid | stage is not `accepted` |
| `E_KEY_REVOKE_EFFECTIVE` | invalid | `effective_at > recorded_at` |
| `E_KEY_REVOKE_SIGNER` | invalid | no signature by an allowed signer (per reason) |
| `E_SIG_REQUIRED` | invalid | `sigs` is absent or an empty array |
| `E_KIND_BODY_SCHEMA` | invalid | body shape, reason vocabulary or code grammar violation |
| `E_KEY_REVOKED` | invalid | a retired-key signature at or after `effective_at` |
| `E_KEY_COMPROMISED` | invalid | a compromised-key signature without pre-compromise verified timestamp |
| `E_KEY_UNKNOWN` | unverifiable | a signer's key is not available in context |
| `N_KEY_TOFU`, `N_KEY_UNDECLARED` | notice | trust-on-first-use reporting |

## Canonical JSON example

The root human key retires the rotated-out `key-old`; verified as a standalone record with
`--keys vectors/keys/keyset`:

<!-- spec-example: standalone-record -->
```json
{"actor":{"key":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","type":"human"},"body":{"effective_at":"2026-11-03T12:00:00.000Z","key":"ed25519:f6a2edbfb48098da6eb9018c5ee78673","note":"example: old key retired after rotation","reason":"retired"},"format":"weave-record/1","id":"key-revoked-key-old","kind":"weave.key.revoked","origin":{"instance":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","project":"example"},"recorded_at":"2026-11-04T00:00:00.000Z","sigs":[{"alg":"ed25519","key":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","value":"4VbqPHcUa2BNOVXCFvVbVF8ifOm4vNbCvo9uQr9NkhGfSLrPASUbr-lJ0bAbM4-su61s1BxyWtXjU0jKM5w0Cg"}],"stage":"accepted"}
```

## Why this kind exists

Keys get lost, stolen, retired or compromised; the format must let any holder of the
container learn this offline. Publishing revocation as a signed record keeps trust local and
CA-free, and the S2 rule — timestamp-only evidence for compromises — is the only treatment
that cannot be defeated by backdating a claimed time [E5][S2] decided (Inceptless decision
2026-11-10 #34; S2).
