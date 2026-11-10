<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# `weave.key.declared` — declare a public key

**Kind:** `weave.key.declared` · **Stage:** `accepted` only · **Per-record signature:** REQUIRED
· **Decision tags:** [E3] [E4] [E5] [R2] [R5] · **Normative parent:** `spec/weave-record-1.md`
§9.1. Every normative rule below is `decided` where it implements rulings S1, S4, Q12, Q20,
Q28 or Q33 of decision 2026-11-10 #34, or R2/R5 of decision 2026-11-10 #42.

## Purpose

Publishes a public key and binds it to its class and (for automated keys) its owner, so that
later records signed by it can be verified without a certificate authority. Key lifecycle is
itself made of records [E5]: a key comes into existence by publishing its raw public key,
its class and its owner, self-signed and cosigned under the rules below. Trust roots are a
**local keyset input**: the verifier's `--keys` directory supplies self-signed
human/organization declarations that it already trusts, and container declarations can only
extend that trust through cosignatures [E4][Q12][R2] decided (Inceptless decision
2026-11-10 #42; R2).

## Envelope requirements

- `kind` is exactly `weave.key.declared`.
- `stage` **MUST** be `accepted` (any other stage is `E_ENV_STAGE`).
- `actor.key` **MUST** equal `body.key`; `actor.type` **MUST** equal `body.key_type`
  (`E_ENV_ACTOR*`, `E_ACTOR_KEY_TYPE_MISMATCH`). This kind is a key self-description: the
  four agent-only envelope members (`model`, `on_behalf_of`, `grant`, `idempotency_key`)
  are **NOT required** even when the class is `agent` [Q28] decided (Inceptless decision
  2026-11-10 #34; Q28).
- `sigs` **MUST** be present and MUST include the self-signature described below
  (`E_KEY_DECLARED_NOT_SELF_SIGNED`); `agent`/`program`/`device` declarations MUST also
  include the owner cosignature (`E_KEY_DECLARED_NOT_COSIGNED`).
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
   verification context and that declaration's class **MUST** be `human` or `organization`
   (a resolving owner of any other class is also `E_KEY_OWNER_MISSING`, invalid — R5). The
   owner declaration itself does not have to be otherwise valid (it only identifies the
   owning principal), but the owner key **MUST** be in the trusted set: an owner that
   resolves but is untrusted makes the declaration `unverifiable` with `E_KEY_UNTRUSTED`.
   An owner that cannot be resolved makes the declaration `unverifiable` with
   `E_KEY_UNKNOWN`.
4. **Cosignature and trust roots.** Trust roots come only from the verifier's local keyset
   (`--keys`), never from a container:
   - a keyset `weave.key.declared` of class `human`/`organization` that passes its own
     checks is a trusted root; it needs no cosignature and produces no
     `N_SELF_ATTESTED_ROOT_KEY` (the keyset is the local trust statement);
   - a container/target declaration of class `human`/`organization` is valid when its key is
     already trusted (for example the same key is trusted from the keyset) or when it
     carries a valid cosignature by a trusted human/organization key; otherwise it is
     `unverifiable` with `E_KEY_UNTRUSTED`, plus `N_SELF_ATTESTED_ROOT_KEY` when its only
     signature is its own. An untrusted declaration must not make any other declaration
     invalid and never becomes trusted;
   - for `agent`/`program`/`device`, at least one valid signature by the key whose id equals
     `body.owner` is required; a missing or invalid owner cosignature is
     `E_KEY_DECLARED_NOT_COSIGNED` (invalid), and an owner that is not trusted makes the
     declaration `unverifiable` with `E_KEY_UNTRUSTED`.
   There is no time-ordered root selection: claimed `recorded_at` values never decide which
   declaration is a root, so a backdated self-signed declaration cannot become one
   [S4][Q33][R2] decided (Inceptless decision 2026-11-10 #42; R2). The self-signature and
   any cosignature are both carried in `sigs`, sorted by `key` ascending.
5. **Validity window.** When both `valid_from` and `valid_until` are present, `valid_from`
   MUST be less than or equal to `valid_until`; otherwise `E_KEY_VALIDITY` (invalid). A
   signature made outside the declared window (either before `valid_from` or after
   `valid_until`) is `E_KEY_EXPIRED` (invalid) [Q20] decided (Inceptless decision
   2026-11-10 #34; Q20).
6. **Multiple declarations.** When a context contains several valid declarations for one
   key id, the earliest claimed `recorded_at` (tie: lexicographically smallest record
   digest) governs; this is declaration resolution, not root selection [Q12] decided
   (Inceptless decision 2026-11-10 #34; Q12).
7. **No point claims.** A declaration does not prove that the key belongs to a particular
   real-world party, only that its holder published it or that the verifier trusted it from
   the local keyset [E4].

## Error codes

| code | verdict | condition |
|---|---|---|
| `E_ENV_STAGE` | invalid | stage is not `accepted` |
| `E_ACTOR_KEY_TYPE_MISMATCH` | invalid | `actor.type != body.key_type` (or a signing class is incompatible) |
| `E_KEY_PUBLIC_KEY` | invalid | `public_key` is not 32 raw bytes in strict unpadded base64url |
| `E_KEY_ID_MISMATCH` | invalid | `body.key` does not match the key-id derivation |
| `E_KEY_OWNER_MISSING` | invalid | `key_type` is `agent`/`program`/`device` and `body.owner` is absent, or the resolving owner's declaration class is not `human`/`organization` (R5) |
| `E_KEY_DECLARED_NOT_SELF_SIGNED` | invalid | no valid signature by the declared key |
| `E_KEY_DECLARED_NOT_COSIGNED` | invalid | an `agent`/`program`/`device` declaration has no valid owner cosignature |
| `E_KEY_UNTRUSTED` | unverifiable | a container/target human/organization declaration cannot be chained to the local keyset roots, or an automated declaration's owner is not trusted (R2) |
| `E_KEY_VALIDITY` | invalid | `valid_from > valid_until` |
| `E_KEY_UNKNOWN` | unverifiable | the owner key, or a cosigner key, has no declaration in the context |
| `E_KEY_EXPIRED` | invalid | a signature made outside the declared validity window |
| `E_SIG_REQUIRED`, `E_SIG_UNVERIFIABLE`, `E_SIG_INVALID` | invalid / unverifiable | per parent specification §4.4 and §3.4 |
| `N_SELF_ATTESTED_ROOT_KEY` | notice | a container/target human/organization declaration is self-signed only and untrusted (it is not a root) |
| `N_KEY_TOFU` | notice | key accepted via in-context declaration |
| `N_KEY_UNDECLARED` | notice | signature key not declared when a compatibility check was needed |

## Canonical JSON examples

A human key owned by human-1 (self-signature by human-2, cosignature by human-1, which the
local keyset already trusts as a human root); verified as a standalone record with `--keys
vectors/keys/keyset`:

<!-- spec-example: standalone-record -->
```json
{"actor":{"key":"ed25519:928a1e1dbe45a5d298ce5f6b5ce2eabe","type":"human"},"body":{"algorithm":"ed25519","key":"ed25519:928a1e1dbe45a5d298ce5f6b5ce2eabe","key_type":"human","note":"example: human key owned by the root key","owner":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","public_key":"YT1Qy4_h1RAkRXOnFdTXbr63odSK4ASJYBA14TVGiLA"},"format":"weave-record/1","id":"key-declared-human-2","kind":"weave.key.declared","origin":{"instance":"ed25519:928a1e1dbe45a5d298ce5f6b5ce2eabe","project":"example"},"recorded_at":"2026-11-02T00:00:00.000Z","sigs":[{"alg":"ed25519","key":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","value":"9q5jW7z5f4aeYOYzWWJiW3gF4sejIx1slHtW_mBGh1ORj7XVqRhHCnJAUKYMgp7P-S2q8I8DL6Nj6FkTXBRSCA"},{"alg":"ed25519","key":"ed25519:928a1e1dbe45a5d298ce5f6b5ce2eabe","value":"5FfvXmL6cC-NlvYAZU-_l06ethaP6RbMLXj0WExs_i-gbNzEZe65G7w6X2wISt41FTy4U0Lq8udYVLWY1GTWBQ"}],"stage":"accepted"}
```

An agent-class key owned by human-1 (self-signature by agent-1, owner cosignature by human-1,
a trusted keyset root); note that the agent-only envelope members are not required for this
kind:

<!-- spec-example: standalone-record -->
```json
{"actor":{"key":"ed25519:b6190071e4bbc7c82afc702fa9ffa6f5","type":"agent"},"body":{"algorithm":"ed25519","key":"ed25519:b6190071e4bbc7c82afc702fa9ffa6f5","key_type":"agent","note":"example: agent key owned by the root key","owner":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","public_key":"YU2BJvrHfOrZQorPEopwttQOPlmXqv9KaU108gO1WZU"},"format":"weave-record/1","id":"key-declared-agent-1","kind":"weave.key.declared","origin":{"instance":"ed25519:b6190071e4bbc7c82afc702fa9ffa6f5","project":"example"},"recorded_at":"2026-11-02T01:00:00.000Z","sigs":[{"alg":"ed25519","key":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","value":"lDWLylAyu9YASvIIsxHc4ZPAXRV0L7fejn2xdY45Y41VoRxLvgSstS7ZWHgyTVuJygVIkFEyYea1_II0-BAdBg"},{"alg":"ed25519","key":"ed25519:b6190071e4bbc7c82afc702fa9ffa6f5","value":"PSby3UAd82Wt2MUNFFm34Gn_wrCRvxeYe17fuYoTVA5AkBC10QKpopFQsqgovDUGeVd6eiCnf9FeuYVBVOT4Dw"}],"stage":"accepted"}
```

A `human` or `organization` declaration that is only self-signed is **not** valid inside a
container or as a standalone record: without a local keyset root it is `unverifiable` with
`E_KEY_UNTRUSTED` and carries `N_SELF_ATTESTED_ROOT_KEY`; with the local keyset that trusts
the same key it is valid (the declaration is a duplicate of a trusted key). Trust roots are
a local keyset input, never a container claim (R2); the rule is in the parent specification
§5.3 and §9.1.

## Why this kind exists

Keys must be exchangeable, revocable and replaceable over decades without a central CA;
key-material publication is itself evidence and must be signed and transportable in the
same container as the records it verifies [E3][E4][E5]. The self-signature bootstraps
verification and the owner cosignature binds automated keys to a human/organization
principal. A container cannot supply its own root: trust roots come only from the verifier's
local keyset, so a self-signed declaration inside a container is evidence of a claim, not a
trust anchor (R2) [S4][Q33][R2] decided (Inceptless decision 2026-11-10 #42; R2).
