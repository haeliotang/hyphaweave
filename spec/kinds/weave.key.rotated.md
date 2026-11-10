<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# `weave.key.rotated` — bind an old key to a new key

**Kind:** `weave.key.rotated` · **Stage:** `accepted` only · **Per-record signature:**
REQUIRED · **Decision tags:** [E5] · **Normative parent:** `spec/weave-record-1.md` §9.2
and §9.4. Every normative rule below is `decided (Inceptless decision 2026-11-10 #34; M-11/
M-12/Q20)` where it implements those rulings.

## Purpose

Records the replacement of an old key by a new key. Both keys sign, so the rotation is
evidence that the old key authorised the new one. Rotation is not revocation: the old key
remains usable for existing records and must be revoked separately (usually with reason
`retired`) if it should stop signing [E5].

## Envelope requirements

- `kind` is exactly `weave.key.rotated`; `stage` **MUST** be `accepted` (`E_ENV_STAGE`).
- `actor.key` **MUST** equal `body.old_key`; `actor.type` names the old key's class. The
  key-lifecycle exception of parent specification §4.2 applies: the agent-only envelope
  members are not required for this kind.
- `sigs` **MUST** be present and MUST contain a valid signature by the old key and a valid
  signature by the new key (`E_KEY_ROTATION_SIGS`). If `sigs` is present but one of the two
  required signatures is missing or wrong, `E_KEY_ROTATION_SIGS` is reported (not
  `E_SIG_REQUIRED`); `E_SIG_REQUIRED` is used only when `sigs` is absent or empty.

## Body

| member | required | type | rule |
|---|---|---|---|
| `new_key` | yes | key id | the successor key id |
| `new_public_key` | yes | string | 32 raw bytes of the successor key, strict unpadded base64url |
| `old_key` | yes | key id | the predecessor key id; equals `actor.key` |
| `old_public_key` | no | string | 32 raw bytes of the predecessor key, strict unpadded base64url |
| `reason` | no | string | free-form note (not interpreted) |

## Semantic rules

1. **Distinct keys.** `old_key != new_key`; otherwise `E_KEY_ROTATION_KEYS` (invalid) [E5].
2. **Bound public keys.** A public key, when present, MUST be strict unpadded base64url of
   exactly 32 bytes, and its key-id derivation MUST equal the corresponding id member. A
   malformed value or a contradiction is `E_KEY_ROTATION_KEYS` (invalid). This kind
   deliberately uses `E_KEY_ROTATION_KEYS`, not `E_KEY_PUBLIC_KEY` or
   `E_KEY_ID_MISMATCH` [M-11] decided (Inceptless decision 2026-11-10 #34; M-11).
3. **Both signatures.** At least one valid signature by `old_key` and at least one valid
   signature by `new_key` MUST be present (`E_KEY_ROTATION_SIGS`). The new-key signature is
   verified against `body.new_public_key`; the old-key signature is verified against
   `body.old_public_key` when present, otherwise against the old key's declaration in
   context. If the needed key material is absent the record is `unverifiable`
   (`E_KEY_UNKNOWN`).
4. **Effect.** The rotation is evidence of succession; it does not revoke the old key and
   does not by itself give the new key a class (a separate declaration publishes that).
   A rotation to a key of a different class is not supported: the new key's signature must
   be compatible with `actor.type` under the parent specification §5.1, so a cross-class
   rotation is invalid.
5. **Explicit key material, no chain inference.** `old_public_key` and `new_public_key`
   are explicit declarations of those two keys: they verify this rotation record and serve
   as material for other records signed by those keys (parent specification §5.3). A
   verifier never needs to traverse a rotation chain to verify a signature. What is
   forbidden is inferring a key that no declaration and no rotation record states, by
   following `old_key → new_key` links. Rotation chains are traversed only by the
   revocation-authority rule of the `weave.grant` kind [M-12] decided (Inceptless decision
   2026-11-10 #34; M-12).
6. **No duplicate-successor resolution.** Two rotations from the same old key to different
   new keys are conflicting evidence; H0 does not merge them. A verifier reports each
   rotation on its own terms.

## Error codes

| code | verdict | condition |
|---|---|---|
| `E_ENV_STAGE` | invalid | stage is not `accepted` |
| `E_KEY_ROTATION_KEYS` | invalid | `old_key == new_key`, a public-key value is malformed, or a public key contradicts its key id |
| `E_KEY_ROTATION_SIGS` | invalid | missing a valid signature by the old or by the new key |
| `E_ACTOR_KEY_TYPE_MISMATCH` | invalid | a signing-key class is incompatible with `actor.type` |
| `E_SIG_REQUIRED` | invalid | `sigs` is absent or an empty array |
| `E_KIND_BODY_SCHEMA` | invalid | body shape or known-member grammar violation |
| `E_KEY_UNKNOWN` | unverifiable | the old key's material is not available in context |
| `N_KEY_TOFU`, `N_KEY_UNDECLARED` | notice | trust-on-first-use reporting |

## Canonical JSON example

Rotation of the test key `key-old` to `key-new`, signed by both keys; verified as a
standalone record with `--keys vectors/keys/keyset`:

<!-- spec-example: standalone-record -->
```json
{"actor":{"key":"ed25519:f6a2edbfb48098da6eb9018c5ee78673","type":"human"},"body":{"new_key":"ed25519:bbecfa632505e9d2df3c49b3e70e613f","new_public_key":"beDOLrXdg6ohy3CIfhIG_B5LNa_Av2xD3cwQHC6Je7E","old_key":"ed25519:f6a2edbfb48098da6eb9018c5ee78673","old_public_key":"gSBP0Jm78fwrwEQDLfar292wPqjUxqq1lAY4oCPfkOY","reason":"example: scheduled rotation"},"format":"weave-record/1","id":"key-rotated-old-to-new","kind":"weave.key.rotated","origin":{"instance":"ed25519:f6a2edbfb48098da6eb9018c5ee78673","project":"example"},"recorded_at":"2026-11-03T00:00:00.000Z","sigs":[{"alg":"ed25519","key":"ed25519:bbecfa632505e9d2df3c49b3e70e613f","value":"WJjT0VNSQ0NZvfrkj6MHOKbb7z_vKyD0iIKV41kjClUUZk7IT_3AabP8offwBdOom00dc9WyMJ7ZxJJcG_LXBQ"},{"alg":"ed25519","key":"ed25519:f6a2edbfb48098da6eb9018c5ee78673","value":"yWelWk5nenXycKR6wjAPgliKmo-0222T-BI1-xV187TXtymAryfC_xnM39fDKGsxWoUBDO95Tha4p2rxLMIlAA"}],"stage":"accepted"}
```

## Why this kind exists

Keys must be replaceable over decades without a CA: instead of delegating trust to a
central authority, the old key explicitly authorises its successor by signing the same
rotation record as the new key [E5]. H0 deliberately does not turn that evidence into an
automatic key-following shortcut, because a rotation chain is only evidence of succession,
not a substitute for an explicit declaration [M-12] decided (Inceptless decision
2026-11-10 #34; M-12).
