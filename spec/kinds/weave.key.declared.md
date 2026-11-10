<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# `weave.key.declared` — declare a public key

**Kind:** `weave.key.declared` · **Stage:** `accepted` only · **Per-record signature:** REQUIRED
· **Decision tags:** [E3] [E4] [E5] · **Normative parent:** `spec/weave-record-1.md` §9.1, §4.4.

## Purpose

Publishes a public key so that later records signed by it can be verified without a
certificate authority. Key lifecycle is itself made of records [E5]: a key comes into
existence by publishing its raw public key and its class (human, agent, program, device,
organization), self-signed by the declared key. Trust is trust-on-first-use: the first
valid declaration seen in a context is accepted, and the report marks it as TOFU [E4].

## Envelope requirements

- `kind` is exactly `weave.key.declared`.
- `stage` **MUST** be `accepted` (any other stage is `E_ENV_STAGE`) [E5][§4].
- `actor.key` **MUST** equal `body.key`; `actor.type` **MUST** equal `body.key_type`
  (`E_ENV_ACTOR*`, `E_ACTOR_KEY_TYPE_MISMATCH`). `actor.type` here names the declared
  key's class only (see the key-lifecycle exception above).
- `sigs` **MUST** be present (per-record signing is mandatory [§4]) and **MUST** include a
  valid signature by the declared key itself (`E_KEY_DECLARED_NOT_SELF_SIGNED`) [E5]. If
  `sigs` is non-empty but the declared-key self-signature is missing or wrong, the kind code
  `E_KEY_DECLARED_NOT_SELF_SIGNED` is reported (not `E_SIG_REQUIRED`); `E_SIG_REQUIRED` is
  used only when `sigs` is absent or empty (§4.4 precedence, Q31).
- If `body.key_type` is `agent`, the four agent-only envelope members (`model`,
  `on_behalf_of`, `grant`, `idempotency_key`) are **NOT required** and a verifier **MUST
  NOT** require them: this kind is a key self-description, not a delegated action
  (parent specification §4.2 exception, PROVISIONAL Q28). They remain forbidden for
  non-agent actors.
- `salt` is optional (no sensitivity requirement); `refs` and `labels` follow the parent
  specification. Owner or previous-key counter-signatures MAY be appended; the signer-class
  rules of this kind (and of `weave.key.rotated`/`weave.key.revoked`) govern them, so a
  human owner co-signature on an agent-class key declaration is permitted by this kind even
  though ordinary agent records cannot be human-signed (Q30, accepted during H0
  integration; the closed registry's `E_ACTOR_HUMAN_KEY` condition excludes the three
  key-lifecycle kinds).

## Body

`body` is an object; the known members are fixed, additional unknown members are permitted
(additive evolution, K3).

| member | required | type | rule |
|---|---|---|---|
| `algorithm` | yes | string | exactly `"ed25519"` |
| `key` | yes | key id | the declared key: `ed25519:` + 32 lowercase hex (§2.5) |
| `key_type` | yes | string | one of `human`, `agent`, `program`, `device`, `organization` |
| `public_key` | yes | string | 32 raw Ed25519 public-key bytes, unpadded base64url (43 characters) |
| `valid_from` | no | TS | start of the claimed validity window |
| `valid_until` | no | TS | end of the claimed validity window |
| `note` | no | string | free-form note (not interpreted) |

`algorithm` other than `ed25519` is `E_KIND_BODY_SCHEMA` (unknown algorithms are future
work; `sigs[].alg` is the signature-agility interface [E1]).

## Semantic rules

1. **Key-id derivation.** `body.key` **MUST** equal `"ed25519:" + first 32 lowercase hex
   characters of SHA-256(<32 raw public-key bytes>)`; the raw bytes are the base64url
   decoding of `body.public_key`. A mismatch is `E_KEY_ID_MISMATCH` (invalid). A wrong
   `public_key` encoding (bad base64url, padding, wrong length) is `E_KEY_PUBLIC_KEY`
   (invalid) [E3][correction v0.1.1].
2. **Self-signature.** At least one `sigs` entry **MUST** have `key == body.key` and a
   signature that verifies over the record signature message (§2.3) with `body.public_key`;
   otherwise `E_KEY_DECLARED_NOT_SELF_SIGNED` (invalid) [E5].
3. **Validity window.** When both `valid_from` and `valid_until` are present, `valid_from`
   **MUST** be less than or equal to `valid_until`; otherwise `E_KEY_VALIDITY` (invalid)
   [E5][Q20].
4. **Effects on other records.** Once the declaration is valid in context, signatures by the
   declared key can be verified; if the declaration has `valid_until`, a signature made
   with a claimed `recorded_at` after it is `E_KEY_EXPIRED` (invalid) [E5][Q20]. With no
   declaration anywhere in context, a signature by that key makes the record
   `unverifiable` (`E_KEY_UNKNOWN`) [E4][Q12].
5. **First use is trust.** A valid declaration is accepted without any CA; the verifier
   reports `N_KEY_TOFU`. A declaration does not prove the key belongs to any particular
   real-world party, only that its holder published it [E4].
6. Multiple declarations for the same key are permitted; they are claims about the same key
   id. Conflicting `key_type` claims are not resolved automatically in H0 (limitation).

## Error codes

| code | verdict | condition |
|---|---|---|
| `E_ENV_STAGE` | invalid | stage is not `accepted` |
| `E_ACTOR_KEY_TYPE_MISMATCH` | invalid | `actor.type != body.key_type` or signer classes incompatible |
| `E_KEY_PUBLIC_KEY` | invalid | `public_key` is not 32 raw bytes in strict unpadded base64url |
| `E_KEY_ID_MISMATCH` | invalid | `body.key` does not match the §2.5 derivation |
| `E_KEY_DECLARED_NOT_SELF_SIGNED` | invalid | no valid signature by `body.key` |
| `E_KEY_VALIDITY` | invalid | `valid_from > valid_until` |
| `E_SIG_REQUIRED` | invalid | `sigs` is absent or an empty array (per-record signing required) |
| `E_KIND_BODY_SCHEMA` | invalid | body shape or known-member grammar violation |
| `E_KEY_UNKNOWN` | unverifiable | another signature's key has no declaration in context |
| `N_KEY_TOFU` | notice | key accepted via in-context declaration |
| `N_KEY_UNDECLARED` | notice | signature key not declared when a compatibility check was needed |

## Canonical JSON example

A human key declaring itself (illustrative; key ids and signature are fake):

```json
{"actor":{"key":"ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","type":"human"},"body":{"algorithm":"ed25519","key":"ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","key_type":"human","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},"format":"weave-record/1","id":"key-human-2","kind":"weave.key.declared","origin":{"instance":"ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","project":"example"},"recorded_at":"2026-11-07T16:30:00.000Z","sigs":[{"alg":"ed25519","key":"ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","value":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}],"stage":"accepted"}
```

## Why this kind exists

Keys must be exchangeable, revocable and replaceable over decades without a central CA;
key-material publication is itself evidence and must be signed and transportable in the
same container as the records it verifies [E3][E4][E5]. The self-signature bootstraps
verification: the declaration carries exactly the bytes needed to check its own signature
and key id, so the first record in a fresh context can be verified offline [E5][Q12].
