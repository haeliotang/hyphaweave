<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Verifier error-code registry (`weave-record/1`, H0)

> **Status: `DRAFT` — provisional.** This registry is closed for `weave-record/1` v0.1.
> A verifier MUST NOT report a code that is not listed here, and MUST NOT silently reuse a
> code for a different condition. Additions follow the change process (`K4`): a written
> proposal, founder approval, decision-log entry, and new test vectors. Codes are never
> removed or renumbered; an implementation that stops performing a check must keep
> recognizing the code for older vectors (K3).
>
> Every code is a fixed ASCII identifier. Human-readable messages are not part of the
> format and MUST NOT be used for machine decisions (they may change without a format
> change). Error codes are compared as a set; order is not meaningful. Notices (`N_*`) do
> not by themselves change a verdict.

## Check-order rules

A verifier evaluates a **record** in this order and stops at the first failing check:
canonical bytes → envelope → signature presence/format → key availability → signature
verification → kind body → kind semantics → actor/authorization → labels → references.
A **container** is evaluated in this order: safe entry enumeration → manifest bytes →
manifest structure → manifest digest → manifest signature → level/chain completeness →
records listing and per-record evaluation → cross-record state → blobs → previous manifest
chain → timestamps → aggregation. A container-level failure before record evaluation means
no record verdicts are reported. This makes each defect yield one primary code.

## Error codes (`E_*`)

Effect column: `invalid` = the enclosing unit (record, manifest, container) fails;
`unverifiable` = the claimed evidence cannot be checked, and the unit must not be reported
as `valid`.

| Code | Effect | Condition |
|---|---|---|
| `E_JSON_INVALID` | invalid | Input is not UTF-8 JSON, has a BOM, is truncated, has trailing non-whitespace content, or is not a JSON object where an object is required. |
| `E_JSON_DUPLICATE_KEY` | invalid | An object member name appears twice at any nesting depth. |
| `E_JSON_NOT_CANONICAL` | invalid | The file's bytes are not exactly the WR-CJ canonical serialization plus at most one trailing LF (wrong key order, whitespace, non-canonical escaping or number spelling, `-0`, CRLF, extra bytes). |
| `E_JSON_NUMBER_NOT_INTEGER` | invalid | A number literal is a float or has an exponent (`1.0`, `1e3`, `.5`). |
| `E_JSON_NUMBER_RANGE` | invalid | An integer is outside `[-(2^53−1), +(2^53−1)]`, or an integer literal has a leading zero or leading `+`. |
| `E_JSON_LONE_SURROGATE` | invalid | A string contains an unpaired surrogate escape (e.g. `"\ud800"`). |
| `E_JSON_SIZE` | invalid | A record, manifest, signature file or timestamp file exceeds its size limit (spec §size limits). |
| `E_ENV_MISSING_FIELD` | invalid | A required envelope member is absent. |
| `E_ENV_UNKNOWN_FIELD` | invalid | A member not defined for the envelope (or a closed nested object: `origin`, `actor`, `labels`, reference, manifest, attestation file) is present. |
| `E_ENV_FORMAT` | invalid | `format` is not exactly `"weave-record/1"`. |
| `E_ENV_KIND_SYNTAX` | invalid | `kind` does not satisfy the kind-name grammar or exceeds the length limit. |
| `E_ENV_ORIGIN` | invalid | `origin` is not an object with a valid project slug and instance key id. |
| `E_ENV_ID` | invalid | `id` is not a string, is empty, exceeds 256 scalar values, contains control characters, or has leading/trailing U+0020. |
| `E_ENV_STAGE` | invalid | `stage` is not one of the five closed values, or a kind requiring `accepted` uses another stage. |
| `E_ENV_ACTOR` | invalid | `actor` is not an object, or contains members that are forbidden for its type (e.g. agent-only members on a human actor), or is otherwise structurally invalid. |
| `E_ENV_ACTOR_TYPE` | invalid | `actor.type` is not one of the five closed values. |
| `E_ENV_ACTOR_KEY` | invalid | `actor.key` is not a valid key id (`ed25519:` + 32 lowercase hex). |
| `E_ENV_ACTOR_MODEL_MISSING` | invalid | `actor.type` is `agent` and `actor.model` is absent. |
| `E_ENV_ACTOR_MODEL` | invalid | `actor.model` is present but does not match `provider/model@version` or exceeds 256 bytes. |
| `E_ENV_ACTOR_ON_BEHALF_MISSING` | invalid | `actor.type` is `agent` and `actor.on_behalf_of` is absent. |
| `E_ENV_ACTOR_ON_BEHALF` | invalid | `actor.on_behalf_of` is present but is not a valid key id. |
| `E_ENV_ACTOR_GRANT_MISSING` | invalid | `actor.type` is `agent` and `actor.grant` is absent (or, per §8, a non-`proposed` agent record cites no resolvable authorization where the field itself is absent). |
| `E_ENV_ACTOR_IDEMPOTENCY_MISSING` | invalid | `actor.type` is `agent` and `actor.idempotency_key` is absent. |
| `E_ENV_ACTOR_IDEMPOTENCY` | invalid | `actor.idempotency_key` is not a valid string (empty, control characters, >256 scalar values). |
| `E_ENV_TIME` | invalid | `recorded_at`/`occurred_at`/other TS field is not RFC 3339 UTC with exactly three fractional digits and trailing `Z` (or uses second `60`). |
| `E_ENV_REFS` | invalid | `refs` is not an array of `{rel, ref}` with a registered `rel`, exceeds 256 entries, or repeats an identical `(rel, ref)` pair. |
| `E_ENV_LABELS` | invalid | `labels` is not a closed object with the defined members (unknown member, wrong type, `sensitivity` present but not in the closed vocabulary). `labels` may carry only `licence` and/or `consent`; missing `sensitivity` is not a structural error, but a derived record without it is subject to `E_LABEL_DOWNGRADE` when a resolved input ranks above `public`. |
| `E_ENV_SENSITIVITY` | invalid | `labels.sensitivity` is not one of `public`, `internal`, `personal`, `local-only`. |
| `E_ENV_LICENCE` | invalid | `labels.licence` is not a syntactically valid SPDX license expression. |
| `E_ENV_SALT` | invalid | `salt` is present but is not strict unpadded base64url of exactly 16 bytes. |
| `E_ENV_SALT_MISSING` | invalid | `labels.sensitivity` is `personal` or `local-only` and `salt` is absent. |
| `E_ENV_SIGS` | invalid | `sigs` is not an array of 1–16 signature objects sorted by `key` ascending with unique keys. |
| `E_ENV_SIG_ALG` | invalid | A signature `alg` is not `ed25519`. |
| `E_ENV_SIG_KEY` | invalid | A signature `key` is not a valid key id. |
| `E_ENV_SIG_VALUE` | invalid | A signature `value` is not strict unpadded base64url of exactly 64 bytes. |
| `E_ENV_BODY` | invalid | `body` is absent or is not a JSON object. |
| `E_ACTOR_KEY_TYPE_MISMATCH` | invalid | `actor.type` is incompatible with the class of a declared signing key (for example an `agent` record signed by a key declared `human`, or a `weave.erasure` actor that is not `human` when the signing key declares another class). |
| `E_ACTOR_HUMAN_KEY` | invalid | A non-human record outside the key-lifecycle kinds carries an additional signature made by a key declared `human` or `organization` (human/organization keys only sign human/organization acts, §8.3; key-lifecycle kinds may require or allow such counter-signatures, §5.1 exception / Q30). |
| `E_SIG_INVALID` | invalid | The Ed25519 verification equation does not hold for the signed bytes. |
| `E_SIG_REQUIRED` | invalid | The record is required to be per-record signed (spec §5.3 / kind rules) and has no `sigs` or no signature by `actor.key`. |
| `E_SIG_NONCANONICAL_A` | invalid | The public key is not a canonically encoded point of the curve (length, `y >= p`, or not on the curve). |
| `E_SIG_NONCANONICAL_R` | invalid | The signature `R` is not a canonically encoded point. |
| `E_SIG_SMALL_ORDER_A` | invalid | The public key decodes to one of the eight small-order points (includes the identity-key forgery). |
| `E_SIG_SMALL_ORDER_R` | invalid | The signature `R` decodes to one of the eight small-order points. |
| `E_SIG_S_OUT_OF_RANGE` | invalid | The signature scalar `S` is not canonical (`S >= L`). |
| `E_KIND_BODY_SCHEMA` | invalid | The body of a registered kind does not satisfy its registered schema. |
| `E_KEY_PUBLIC_KEY` | invalid | A declared public key is not strict unpadded base64url of 32 bytes, or is not a canonical point encoding. |
| `E_KEY_ID_MISMATCH` | invalid | A declared key id is not the key-id derivation of its declared public key. |
| `E_KEY_DECLARED_NOT_SELF_SIGNED` | invalid | A `weave.key.declared` record has no valid signature by the declared key. |
| `E_KEY_VALIDITY` | invalid | A key declaration's or a `weave.grant`'s validity window is inverted (`valid_from` > `valid_until`). Consent windows use `E_CONSENT_VALIDITY`; key rotation has no window. |
| `E_KEY_ROTATION_KEYS` | invalid | `weave.key.rotated` uses the same key as old and new, or a declared public key contradicts its id. |
| `E_KEY_ROTATION_SIGS` | invalid | `weave.key.rotated` is not signed by both the old and the new key. |
| `E_KEY_REVOKE_EFFECTIVE` | invalid | `weave.key.revoked.effective_at` is later than the revocation record's `recorded_at`. |
| `E_KEY_REVOKE_SIGNER` | invalid | A `weave.key.revoked` record lacks an acceptable signer (compromise requires a human/organization key; retired/other require the revoked key or a human/organization key). |
| `E_KEY_UNKNOWN` | unverifiable | A signature or actor names a key that is not declared anywhere in the verification context (container + external keyset); the signature cannot be checked. |
| `E_KEY_EXPIRED` | invalid | A signature was made after the signing key's declared `valid_until` (claimed `recorded_at`). |
| `E_KEY_REVOKED` | invalid | A signature was made after a `retired`/`other` revocation's `effective_at` (claimed `recorded_at`). |
| `E_KEY_COMPROMISED` | invalid | A signature was made after a `key-compromise` revocation's `effective_at` and is not protected by a verified RFC 3161 timestamp whose `genTime` is at or before `effective_at`. |
| `E_GRANT_SCHEMA` | invalid | A `weave.grant` body does not match its registered schema (wrong action variant, missing/extra variant members, invalid lists). |
| `E_GRANT_GRANTER` | invalid | The actor/signing-key class does not permit issuing this grant given the resolved context (e.g. a `program`/`device` actor, or an agent-signed grant whose resolved parent grant does not cover kind `weave.grant`/action `grant`). An unresolvable parent grant is `E_GRANT_UNRESOLVED` (unverifiable), not this code. |
| `E_GRANT_NOT_TRANSFERABLE` | invalid | A delegated sub-grant cites a parent grant whose `transferable` is false. |
| `E_GRANT_DELEGATION_EXCEEDS` | invalid | A delegated sub-grant grants kinds or a validity window that exceeds its parent grant. |
| `E_GRANT_REVOKE_SIGNER` | invalid | A grant-revocation record is not signed by the original granter's key or by a human/organization key. |
| `E_GRANT_REVOKE_REF` | invalid | A grant-revocation record's `revokes` reference does not resolve to a `weave.grant` record with matching digest. |
| `E_GRANT_UNRESOLVED` | unverifiable | An agent-authored record cites an authorization that cannot be resolved in the verification context. |
| `E_GRANT_REVOKED` | unverifiable | An agent-authored record cites an authorization revoked with `effective_at` at or before the record's claimed `recorded_at`. |
| `E_GRANT_EXPIRED` | unverifiable | An agent-authored record's claimed `recorded_at` is outside its cited authorization's validity window. |
| `E_GRANT_GRANTEE_MISMATCH` | invalid | An agent-authored record's `actor.key` is not the `grantee.key` of its cited authorization. |
| `E_GRANT_NOT_APPLICABLE` | invalid | An agent-authored record's kind or stage action is not covered by its cited authorization. |
| `E_CONSENT_VALIDITY` | invalid | A `weave.consent.granted` record has `valid_from` > `valid_until`. |
| `E_CONSENT_REVOKE_REF` | invalid | A `weave.consent.revoked` record's `revokes` reference does not resolve to a `weave.consent.granted` record. |
| `E_ERASE_ACTOR` | invalid | A `weave.erasure` record's actor is not human. |
| `E_ERASE_DIGEST_MISMATCH` | invalid | A `weave.erasure` record's `erased` reference does not match its target erased placeholder (`origin`, `id`, `digest`), or a placeholder's `digest` contradicts the attestation. |
| `E_ERASE_ATTESTATION` | invalid | An erased placeholder's `attestation` reference does not resolve to the corresponding `weave.erasure` record. |
| `E_ERASE_CONTRADICTION` | invalid | A container contains both a live record and an erased placeholder for the same `origin` + `id`, or two placeholders for the same target. |
| `E_LABEL_DOWNGRADE` | invalid | A derived record's sensitivity rank is lower than a resolved `derived_from` input's rank, or is absent while a resolved input ranks above `public`. |
| `E_LABEL_LOCAL_ONLY_EXPORTED` | invalid | A record carrying `labels.sensitivity = "local-only"` appears in an export container. |
| `E_REF_KIND_MISMATCH` | invalid | A reference's claimed `kind` (or a link target's required kind) contradicts the resolved target's actual kind. |
| `E_MANIFEST_MISSING` | invalid | The container has no `manifest.json`. |
| `E_MANIFEST_FORMAT` | invalid | `manifest.format` is not `"weave-record/1"`. |
| `E_MANIFEST_VERSION` | invalid | `manifest.manifest_version` is not a supported integer (H0: only `1`). |
| `E_MANIFEST_SCHEMA` | invalid | The manifest object or attestation file is not a closed object with the defined members and types. |
| `E_MANIFEST_DIGEST` | invalid | `signatures/manifest.sig.json.digest` does not equal the manifest digest computed per the spec. |
| `E_MANIFEST_UNSIGNED` | invalid | The manifest attestation file has no signatures. |
| `E_MANIFEST_SIG_INVALID` | invalid | A manifest signature does not verify against the manifest signature message. |
| `E_MANIFEST_RECORDS` | invalid | `manifest.records` is not an array of 1–100000 well-formed entries, is not sorted by digest ascending, or repeats a digest. |
| `E_MANIFEST_RECORD_MISSING` | invalid | A record listed in the manifest has no file in `records/`. |
| `E_MANIFEST_RECORD_EXTRA` | invalid | `records/` contains a file not listed in the manifest, or a malformed filename. |
| `E_MANIFEST_RECORD_DIGEST` | invalid | A record file's computed digest does not match its filename and/or manifest entry. |
| `E_MANIFEST_BLOB` | invalid | `blobs/` contents and `manifest.blobs` disagree (missing, extra, wrong digest/size), or the blobs directory exists while no blobs are listed. |
| `E_MANIFEST_LEVEL` | invalid | `level` is not `L0`/`L1`/`L2`, or the level-specific completeness rules are violated (e.g. timestamps under L0/L1). |
| `E_MANIFEST_L1_NO_HEAD` | invalid | The claimed level is `L1`/`L2` but `manifest.chain` is absent. |
| `E_MANIFEST_L1_NO_POSITION` | invalid | The claimed level is `L1`/`L2` but a `records[]` entry lacks a unique non-negative `chain_index`. |
| `E_MANIFEST_L2_NO_TIMESTAMP` | invalid | The claimed level is `L2` but the manifest attestation lists no RFC 3161 timestamp. |
| `E_MANIFEST_CHAIN` | invalid | `previous_manifest.digest` does not equal the digest of the embedded `previous/manifest.json`, or `--previous` disagrees with the embedded manifest. |
| `E_MANIFEST_CHAIN_MISSING` | invalid | `previous_manifest` is non-null but `previous/manifest.json` is absent. |
| `E_MANIFEST_CHAIN_UNEXPECTED` | invalid | `previous_manifest` is null but `previous/` contains a manifest. |
| `E_CONTAINER_ENTRY` | invalid | The container contains an entry outside the allowed layout, a path that escapes the root, a duplicate entry name, a symlink or other unsupported entry type, or an unknown file in `signatures/`/`previous/`. |
| `E_CONTAINER_SIZE` | invalid | Entry count or uncompressed total bytes exceed the container limits (zip-bomb protection). |
| `E_CONTAINER_ZIP` | invalid | The zip cannot be read as a zip (corrupt archive, unsupported compression, encrypted entries). |
| `E_TS_FILE` | invalid | A listed timestamp file is missing or does not hash to the listed digest. |
| `E_TS_SCHEMA` | invalid | A timestamp is not a DER TimeStampResp with a `granted` token and well-formed TSTInfo. |
| `E_TS_IMPRINT` | invalid | The token's `messageImprint` is not `{sha256, raw 32-byte manifest digest}`. |
| `E_TS_CMS` | invalid | The CMS signature, signed attributes or ESS `messageDigest` of the timestamp token do not verify. |
| `E_TS_UNTRUSTED` | unverifiable | No trust anchor was supplied for the timestamp's signer certificate, so the timestamp is reported `present-unverified`; the container must not be reported `valid`. |
| `E_TS_CERT` | invalid | The signer certificate is not valid at the token's `genTime`, lacks an acceptable key usage, or its signature-algorithm is unsupported. |

## Notices (`N_*`, non-fatal unless stated)

| Code | Condition |
|---|---|
| `N_KIND_UNKNOWN_OPAQUE` | The record's kind is well-formed but not registered; the body was not interpreted (must never be treated as understood). |
| `N_KEY_UNDECLARED` | A signing key has no declaration in the verification context; the signature could not be checked (paired with `E_KEY_UNKNOWN` when it makes the unit unverifiable). |
| `N_KEY_TOFU` | A declared key was accepted on first use (no trust anchor, no CA) — informational for the human reader. |
| `N_REF_MISSING` | A reference resolved to `missing`. |
| `N_REF_MOVED` | A reference resolved to `moved` (same origin+id, different digest). |
| `N_REF_UNVERIFIABLE` | A reference resolved to `unverifiable` (target present but not valid, or unsupported digest algorithm). |
| `N_LABEL_PROPAGATION_UNCHECKED` | A `derived_from` reference could not be resolved, so strictest-label propagation could not be checked. |
| `N_CHAIN_CLAIM_UNVERIFIED` | An L1/L2 chain head is an internal-chain claim that an offline verifier cannot recompute; `level_verified` is reported as `L0`. |
| `N_CONSENT_UNRESOLVED` | `labels.consent` is a reference that could not be resolved. |
| `N_PREVIOUS_SIG_UNVERIFIED` | The embedded previous manifest's own signature was not re-verified. |
| `N_IDEMPOTENCY_DUPLICATE` | A container contains two records with the same `origin` and `actor.idempotency_key` (claimed as the same action). |
| `N_READABLE_PRESENT` | The container has a `readable/` view; it is unsigned and was not used. |
