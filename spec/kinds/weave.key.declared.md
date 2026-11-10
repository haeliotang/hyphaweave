<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# `weave.key.declared` — declare a public key

**Kind:** `weave.key.declared` · **Stage:** `accepted` only · **Per-record signature:** REQUIRED
· **Decision tags:** [E3] [E4] [E5] · **Normative parent:** `spec/weave-record-1.md` §9.1.
Every normative rule below is `decided (Inceptless decision 2026-11-10 #34)` where it
implements rulings S1, S4, Q12, Q20, Q28 or Q33.

## Purpose

Publishes a public key and binds it to its class and (for automated keys) its owner, so that
later records signed by it can be verified without a certificate authority. Key lifecycle is
itself made of records [E5]: a key comes into existence by publishing its raw public key,
its class and its owner, self-signed and cosigned under the rules below. Trust is
trust-on-first-use: the first valid declaration seen in a context is accepted, and the
report marks it as TOFU [E4][Q12] decided (Inceptless decision 2026-11-10 #34; Q12).

## Envelope requirements

- `kind` is exactly `weave.key.declared`.
- `stage` **MUST** be `accepted` (any other stage is `E_ENV_STAGE`).
- `actor.key` **MUST** equal `body.key`; `actor.type` **MUST** equal `body.key_type`
  (`E_ENV_ACTOR*`, `E_ACTOR_KEY_TYPE_MISMATCH`). This kind is a key self-description: the
  four agent-only envelope members (`model`, `on_behalf_of`, `grant`, `idempotency_key`)
  are **NOT required** even when the class is `agent` [Q28] decided (Inceptless decision
  2026-11-10 #34; Q28).
- `sigs` **MUST** be present and MUST include the self-signature and the cosignature
  described below (`E_KEY_DECLARED_NOT_SELF_SIGNED`, `E_KEY_DECLARED_NOT_COSIGNED`).
- `salt` is optional; `refs` and `labels` follow the parent specification.

## Body

`body` is a closed object for its known members; additional unknown body members are
permitted (additive evolution, K3, parent specification §7.5).

| member | required | type | rule |
|---|---|---|---|
| `algorithm` | yes | string | exactly `"ed25519"` |
| `key` | yes | key id | the declared key: `ed25519:` + 32 lowercase hex |
| `key_type` | yes | string | one of `human`, `agent`, `program`, `device`, `organization` |
| `public_key` | yes | string | 32 raw Ed25519 public-key bytes, strict unpadded base64url (43 characters) |
| `owner` | conditional | key id | the owning human/organization key; **REQUIRED** when `key_type` is `agent`, `program` or `device` (`E_KEY_OWNER_MISSING`); optional for `human`/`organization` |
| `valid_from` | no | TS | start of the claimed validity window |
| `valid_until` | no | TS | end of the claimed validity window |
| `note` | no | string | free-form note (not interpreted) |

## Semantic rules

1. **Key-id derivation.** `body.key` **MUST** equal the key-id derivation of the raw
   `public_key` bytes (`ed25519:` + first 32 lowercase hex of SHA-256 of the 32 raw bytes);
   otherwise `E_KEY_ID_MISMATCH` (invalid). A `public_key` that is not strict unpadded
   base64url of exactly 32 bytes is `E_KEY_PUBLIC_KEY` (invalid). **No point check happens
   here**: whether the 32 bytes decode to a canonical curve point, or whether that point is
   small-order or mixed-order, is checked only when a signature is verified (parent
   specification §2.5 and §3.4) [S1][M-11] decided (Inceptless decision 2026-11-10 #34;
   S1/M-11).
2. **Self-signature.** At least one `sigs` entry **MUST** be a valid signature by the
   declared key; otherwise `E_KEY_DECLARED_NOT_SELF_SIGNED` (invalid) [E5][S4] decided
   (Inceptless decision 2026-11-10 #34; S4).
3. **Owner binding.** For `key_type` in `agent`, `program`, `device`, `body.owner` **MUST**
   be present (`E_KEY_OWNER_MISSING`). The owner **MUST** resolve to a declaration in the
   verification context, and that declaration's class **MUST** be `human` or `organization`;
   the owner declaration itself does not have to be valid (it only identifies the owning
   principal). An owner that cannot be resolved makes the declaration `unverifiable` with
   `E_KEY_UNKNOWN`.
4. **Cosignature.** A declaration MUST be cosigned:
   - for `agent`/`program`/`device`: at least one valid signature by the key whose id equals
     `body.owner`, declared `human` or `organization`;
   - for `human`/`organization`: the declaration takes part in the deterministic root
     procedure of parent specification §9.1 rule 4. In short: declarations are processed in
     ascending claimed `recorded_at` (ties broken by lexicographically smallest record
     digest); a declaration cosigned by an already-established human/organization key is
     valid and joins the established set; otherwise, if the set is empty, the declaration is
     the **root** and may be self-signed only, with the notice `N_SELF_ATTESTED_ROOT_KEY`;
     any other declaration without a valid human/organization cosignature is
     `E_KEY_DECLARED_NOT_COSIGNED` (invalid) [S4][Q33] decided (Inceptless decision
     2026-11-10 #34; S4/Q33).
   The self-signature and the cosignature are both carried in `sigs`, sorted by `key`
   ascending.
5. **Validity window.** When both `valid_from` and `valid_until` are present, `valid_from`
   MUST be less than or equal to `valid_until`; otherwise `E_KEY_VALIDITY` (invalid). A
   signature made outside the declared window (either before `valid_from` or after
   `valid_until`) is `E_KEY_EXPIRED` (invalid) [Q20] decided (Inceptless decision
   2026-11-10 #34; Q20).
6. **Multiple declarations.** When a context contains several valid declarations for one
   key id, the earliest claimed `recorded_at` (tie: lexicographically smallest record
   digest) governs [Q12] decided (Inceptless decision 2026-11-10 #34; Q12).
7. **No point claims.** A declaration does not prove that the key belongs to a particular
   real-world party, only that its holder published it [E4].

## Error codes

| code | verdict | condition |
|---|---|---|
| `E_ENV_STAGE` | invalid | stage is not `accepted` |
| `E_ACTOR_KEY_TYPE_MISMATCH` | invalid | `actor.type != body.key_type` (or a signing class is incompatible) |
| `E_KEY_PUBLIC_KEY` | invalid | `public_key` is not 32 raw bytes in strict unpadded base64url |
| `E_KEY_ID_MISMATCH` | invalid | `body.key` does not match the key-id derivation |
| `E_KEY_OWNER_MISSING` | invalid | `key_type` is `agent`/`program`/`device` and `body.owner` is absent |
| `E_KEY_DECLARED_NOT_SELF_SIGNED` | invalid | no valid signature by the declared key |
| `E_KEY_DECLARED_NOT_COSIGNED` | invalid | no acceptable cosignature (owner for automated keys; an established human/organization key for non-root human/organization keys) |
| `E_KEY_VALIDITY` | invalid | `valid_from > valid_until` |
| `E_KEY_UNKNOWN` | unverifiable | the owner key, or a cosigner key, has no declaration in the context |
| `E_KEY_EXPIRED` | invalid | a signature made outside the declared validity window |
| `E_SIG_REQUIRED`, `E_SIG_UNVERIFIABLE`, `E_SIG_INVALID` | invalid / unverifiable | per parent specification §4.4 and §3.4 |
| `N_SELF_ATTESTED_ROOT_KEY` | notice | human/organization root bootstrap with only a self-signature |
| `N_KEY_TOFU` | notice | key accepted via in-context declaration |
| `N_KEY_UNDECLARED` | notice | signature key not declared when a compatibility check was needed |

## Canonical JSON examples

A human key owned by the root key (self-signature by human-2, cosignature by human-1);
verified as a standalone record with `--keys vectors/keys/keyset`:

<!-- spec-example: standalone-record -->
```json
{"actor":{"key":"ed25519:928a1e1dbe45a5d298ce5f6b5ce2eabe","type":"human"},"body":{"algorithm":"ed25519","key":"ed25519:928a1e1dbe45a5d298ce5f6b5ce2eabe","key_type":"human","note":"example: human key owned by the root key","owner":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","public_key":"YT1Qy4_h1RAkRXOnFdTXbr63odSK4ASJYBA14TVGiLA"},"format":"weave-record/1","id":"key-declared-human-2","kind":"weave.key.declared","origin":{"instance":"ed25519:928a1e1dbe45a5d298ce5f6b5ce2eabe","project":"example"},"recorded_at":"2026-11-02T00:00:00.000Z","sigs":[{"alg":"ed25519","key":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","value":"9q5jW7z5f4aeYOYzWWJiW3gF4sejIx1slHtW_mBGh1ORj7XVqRhHCnJAUKYMgp7P-S2q8I8DL6Nj6FkTXBRSCA"},{"alg":"ed25519","key":"ed25519:928a1e1dbe45a5d298ce5f6b5ce2eabe","value":"5FfvXmL6cC-NlvYAZU-_l06ethaP6RbMLXj0WExs_i-gbNzEZe65G7w6X2wISt41FTy4U0Lq8udYVLWY1GTWBQ"}],"stage":"accepted"}
```

An agent-class key owned by the root key (self-signature by agent-1, owner cosignature by
human-1); note that the agent-only envelope members are not required for this kind:

<!-- spec-example: standalone-record -->
```json
{"actor":{"key":"ed25519:b6190071e4bbc7c82afc702fa9ffa6f5","type":"agent"},"body":{"algorithm":"ed25519","key":"ed25519:b6190071e4bbc7c82afc702fa9ffa6f5","key_type":"agent","note":"example: agent key owned by the root key","owner":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","public_key":"YU2BJvrHfOrZQorPEopwttQOPlmXqv9KaU108gO1WZU"},"format":"weave-record/1","id":"key-declared-agent-1","kind":"weave.key.declared","origin":{"instance":"ed25519:b6190071e4bbc7c82afc702fa9ffa6f5","project":"example"},"recorded_at":"2026-11-02T01:00:00.000Z","sigs":[{"alg":"ed25519","key":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","value":"lDWLylAyu9YASvIIsxHc4ZPAXRV0L7fejn2xdY45Y41VoRxLvgSstS7ZWHgyTVuJygVIkFEyYea1_II0-BAdBg"},{"alg":"ed25519","key":"ed25519:b6190071e4bbc7c82afc702fa9ffa6f5","value":"PSby3UAd82Wt2MUNFFm34Gn_wrCRvxeYe17fuYoTVA5AkBC10QKpopFQsqgovDUGeVd6eiCnf9FeuYVBVOT4Dw"}],"stage":"accepted"}
```

A root `human` or `organization` declaration with only its self-signature is valid when it
is the root bootstrap; the report then carries `N_SELF_ATTESTED_ROOT_KEY`. No complete
example is shown here because a root example would duplicate the keyset's own root
declaration; the rule is in the parent specification §9.1.

## Why this kind exists

Keys must be exchangeable, revocable and replaceable over decades without a central CA;
key-material publication is itself evidence and must be signed and transportable in the
same container as the records it verifies [E3][E4][E5]. The self-signature bootstraps
verification and the owner cosignature binds automated keys to a human/organization
principal; the root exception exists because the very first human key has no earlier key to
sign it [S4][Q33] decided (Inceptless decision 2026-11-10 #34; S4/Q33).
