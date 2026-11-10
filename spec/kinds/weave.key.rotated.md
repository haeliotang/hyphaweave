<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# `weave.key.rotated` — bind an old key to a new key

**Kind:** `weave.key.rotated` · **Stage:** `accepted` only · **Per-record signature:** REQUIRED
· **Decision tags:** [E5] · **Normative parent:** `spec/weave-record-1.md` §9.2, §4.4.

## Purpose

Records the replacement of an old key by a new key. Both keys sign, so the rotation is
evidence that the old key authorised the new key: verifiers can follow the chain of key
history without a CA. Rotation is not revocation: the old key remains usable for existing
records and must be revoked separately (usually with reason `retired`) if it should stop
signing [E5].

## Envelope requirements

- `kind` is exactly `weave.key.rotated`; `stage` **MUST** be `accepted`
  (`E_ENV_STAGE`) [E5][§4].
- `actor.key` **MUST** equal `body.old_key`; `actor.type` names the old key's declared
  class (when the old key is declared; otherwise TOFU rules apply and the declaration may
  arrive later). `actor.type` here describes the key the record is about, not a delegated
  actor: the four agent-only envelope members are **NOT required** for this kind even when
  the class is `agent` (parent specification §4.2 exception, PROVISIONAL Q28). Normal
  actor-key compatibility rules apply to `actor.key` [E5][§5.1].
- `sigs` **MUST** be present and **MUST** contain a valid signature by the old key and a
  valid signature by the new key (`E_KEY_ROTATION_SIGS`) [E5]. If `sigs` is non-empty but
  either required signature is missing or wrong, `E_KEY_ROTATION_SIGS` is reported (not
  `E_SIG_REQUIRED`); `E_SIG_REQUIRED` is used only when `sigs` is absent or empty (§4.4
  precedence, Q31).
- The new key's signature is verified against `body.new_public_key` (required), so the new
  key need not yet be declared in the context; `body.old_public_key`, when present, permits
  verifying the old-key signature even if the old declaration is absent. When a public key
  member is present its key id **MUST** equal the corresponding id member
  (`E_KEY_ID_MISMATCH`).
- A rotation to a key of a different class (for example human to agent) is not supported by
  H0: the new key's signature must be compatible with `actor.type` under §5.1, which makes
  a cross-class rotation invalid. Use a separate declaration and revocation instead.

## Body

| member | required | type | rule |
|---|---|---|---|
| `new_key` | yes | key id | the successor key id |
| `new_public_key` | yes | string | 32 raw bytes of the successor key, unpadded base64url |
| `old_key` | yes | key id | the predecessor key id; equals `actor.key` |
| `old_public_key` | no | string | 32 raw bytes of the predecessor key, unpadded base64url |
| `reason` | no | string | free-form note (not interpreted) |

## Semantic rules

1. **Distinct keys.** `old_key != new_key`; otherwise `E_KEY_ROTATION_KEYS` (invalid) [E5].
2. **Bound public keys.** When `old_public_key` is present, `"ed25519:" + first 32 hex of
   SHA-256(raw old_public_key)` **MUST** equal `old_key`; the same for `new_public_key` and
   `new_key`. A mismatch is `E_KEY_ID_MISMATCH` (invalid) [E3][correction v0.1.1].
3. **Both signatures.** At least one valid signature by `old_key` and at least one valid
   signature by `new_key` **MUST** be present; otherwise `E_KEY_ROTATION_SIGS` (invalid)
   [E5]. If the old-key signature must be verified and neither a declaration nor
   `old_public_key` supplies the old key, the record is `unverifiable` (`E_KEY_UNKNOWN`).
4. **Effect.** The rotation is evidence of succession; it does not by itself revoke the old
   key, and it does not by itself give the new key a class — that comes from a
   `weave.key.declared` record. Verifiers may follow `old_key → new_key` links when a
   signature's key is not declared but an old key chain is available in context.
5. A second rotation from the same old key to a different new key is not prevented by the
   format; that would be conflicting evidence, and H0 does not attempt to resolve it
   automatically (limitation).

## Error codes

| code | verdict | condition |
|---|---|---|
| `E_ENV_STAGE` | invalid | stage is not `accepted` |
| `E_KEY_ROTATION_KEYS` | invalid | `old_key == new_key` |
| `E_KEY_PUBLIC_KEY` | invalid | `new_public_key`/`old_public_key` is not strict unpadded base64url of 32 bytes or is not a canonical point encoding |
| `E_KEY_ROTATION_KEYS` | invalid | a supplied public key contradicts its id (per the closed registry; `E_KEY_ID_MISMATCH` is reserved for declarations) |
| `E_KEY_ROTATION_SIGS` | invalid | missing a valid signature by the old or by the new key |
| `E_ACTOR_KEY_TYPE_MISMATCH` | invalid | signing-key class incompatible with `actor.type` |
| `E_SIG_REQUIRED` | invalid | `sigs` is absent or an empty array (per-record signing required) |
| `E_KIND_BODY_SCHEMA` | invalid | body shape or known-member grammar violation |
| `E_KEY_UNKNOWN` | unverifiable | old key material is not available in context |
| `N_KEY_TOFU`, `N_KEY_UNDECLARED` | notice | trust-on-first-use reporting |

## Canonical JSON example

```json
{"actor":{"key":"ed25519:1111111111111111111111111111111111111111111111111111111111111111","type":"human"},"body":{"new_key":"ed25519:2222222222222222222222222222222222222222222222222222222222222222","new_public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","old_key":"ed25519:1111111111111111111111111111111111111111111111111111111111111111","old_public_key":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","reason":"annual rotation"},"format":"weave-record/1","id":"rotation-1","kind":"weave.key.rotated","origin":{"instance":"ed25519:1111111111111111111111111111111111111111111111111111111111111111","project":"example"},"recorded_at":"2026-11-07T16:30:00.000Z","sigs":[{"alg":"ed25519","key":"ed25519:1111111111111111111111111111111111111111111111111111111111111111","value":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},{"alg":"ed25519","key":"ed25519:2222222222222222222222222222222222222222222222222222222222222222","value":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}],"stage":"accepted"}
```

## Why this kind exists

Keys must be replaceable over decades. A CA is not available offline and must not be
required; instead the old key explicitly authorises its successor by signing the same
rotation record as the new key [E5]. This keeps the key history verifiable with only the
container and its records [E5][E4].
