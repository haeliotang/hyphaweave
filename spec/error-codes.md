<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Verifier error-code registry (`weave-record/1`, H0)

> **Status: closed for `weave-record/1` v0.1 (revision 3).** This registry is closed: a
> verifier MUST NOT report a code that is not listed here, and MUST NOT silently reuse a
> code for a different condition. Additions follow the change process (K4): a written
> proposal, decision-log entry, and new test vectors. Codes are never removed or
> renumbered; an implementation that stops performing a check must keep recognizing the
> code for older vectors (K3). No code is retired from this registry in revision 1; one
> code (`E_ENV_SIG_ALG`) is retained but is no longer emitted by an H0 verifier, because
> unknown signature algorithms are now ignored instead of rejected. Every condition below
> is normative for the check named by its code.
>
> Revision 3 (Inceptless decision 2026-11-11 #2) adds `E_KEY_CLASS_CONFLICT` (S1), sharpens
> the `E_ENV_MISSING_FIELD`/`E_ENV_UNKNOWN_FIELD` scope (F2), extends `E_JSON_SIZE`,
> `E_ENV_LICENCE`, `E_TS_SCHEMA`, `E_MANIFEST_UNSIGNED`, `E_MANIFEST_CHAIN`,
> `E_CONTAINER_ZIP` and the `E_ENV_SIGS` bounds, pins the notice conditions, and adds the
> closed `L_*` limitation-identifier list (S12).

> Every code is a fixed ASCII identifier. Human-readable messages are not part of the
> format and MUST NOT be used for machine decisions (they may change without a format
> change). Error codes are compared as a set; order is not meaningful. Notices (`N_*`) do
> not by themselves change a verdict unless the registry says so.

## Check-order rules

A verifier evaluates a **record** in this order and stops at the first failing check, which
is the only code reported for that record: canonical bytes (§1.9 of the specification) →
envelope → signature presence/format → key availability → signature verification → kind
body → kind semantics → actor/authorisation → labels → references. Within the envelope
stage the sub-order is required top-level members → top-level closedness → per-member
grammar; a nested closed object repeats presence → closedness → grammar inside itself and
reports its own dedicated code (F2, F3). Within signature verification the Ed25519 steps
have their own fixed order (specification §3.4); the cryptography of §3.4 runs before the
key-lifecycle effects of §9.4, so a signature that fails the equation reports `E_SIG_INVALID`
even when its key is expired, revoked or compromised. An unverifiable condition listed in
specification §14.4 is terminal for the record exactly like an error (F7). In the timestamp
phase a listed receipt's file digest failure (`E_TS_FILE`) is reported before the
renewal-chain shape (`E_TS_RENEWAL`).

A **container** is evaluated in this order: safe entry enumeration → manifest bytes →
manifest structure → manifest digest → manifest signature → level/chain completeness →
records listing and per-record evaluation → cross-record state → blobs → previous manifest
chain → timestamps → aggregation. A container-level invalid error stops the container
pipeline at the stage where it is found: record listing/evaluation does not run for an
invalid error found before it, and the report carries `records: []`. The failing stage
reports every independent violation it found in that stage (sorted, unique in
`container.errors`); the records-listing stage in particular reports all of its
`E_MANIFEST_RECORD_*`/`E_MANIFEST_RECORDS`/`E_JSON_SIZE` violations together. An
unverifiable container condition does not stop record processing and its code is retained in
`container.errors` (S8①). Each record defect still yields one primary code.

## Error codes (`E_*`)

Effect column: `invalid` = the enclosing unit (record, manifest, container) fails;
`unverifiable` = the claimed evidence cannot be checked, and the unit must not be reported
as `valid`.

| Code | Effect | Condition |
|---|---|---|
| `E_JSON_INVALID` | invalid | Input is not UTF-8 JSON, has a BOM, is truncated, has trailing non-whitespace content, is not an object where an object is required, or uses a numeric literal that is not valid JSON (`+1`, `01`, `.5`, `1.`) or any other JSON syntax error. Where several violations exist, report the first one in input byte order (specification §1.9). |
| `E_JSON_DUPLICATE_KEY` | invalid | An object member name appears twice at any nesting depth (first violation in input byte order). |
| `E_JSON_NOT_CANONICAL` | invalid | The file's bytes are not exactly the WR-CJ canonical serialization plus at most one trailing LF (wrong key order, whitespace, non-canonical escaping or number spelling, `-0`, CRLF, more than one trailing LF, extra bytes). The `-0` number spelling is classified at its number token during the syntax/number pass; other canonical-form deviations are classified after a syntactically valid parse (specification §1.9). |
| `E_JSON_NUMBER_NOT_INTEGER` | invalid | A syntactically valid JSON number literal is a float or has an exponent (`1.0`, `1e3`). |
| `E_JSON_NUMBER_RANGE` | invalid | A syntactically valid JSON integer is outside `[-(2^53−1), +(2^53−1)]`. |
| `E_JSON_LONE_SURROGATE` | invalid | A string contains an unpaired surrogate escape (e.g. `"\ud800"`). |
| `E_JSON_SIZE` | invalid | A record, manifest, signature-attestation file or timestamp receipt file exceeds its size limit, or a JSON document's **value nesting depth** exceeds `MAX_JSON_DEPTH` (specification §1.9, §13). |
| `E_ENV_MISSING_FIELD` | invalid | A required **top-level** envelope member is absent. A missing member of a closed nested object reports that object's dedicated code (F2). |
| `E_ENV_UNKNOWN_FIELD` | invalid | A member not defined for the **top-level** envelope is present. An unknown member of a closed nested object reports that object's dedicated code: `E_ENV_ORIGIN`, `E_ENV_ACTOR*`, `E_ENV_REFS`, `E_ENV_LABELS`, `E_ENV_SIGS`, `E_MANIFEST_SCHEMA`, or `E_KIND_BODY_SCHEMA` for the `weave.erased` placeholder (F2). |
| `E_ENV_FORMAT` | invalid | `format` is not exactly `"weave-record/1"`. |
| `E_ENV_KIND_SYNTAX` | invalid | `kind` does not satisfy the kind-name grammar or exceeds the length limit. |
| `E_ENV_ORIGIN` | invalid | `origin` is not a closed object with exactly the members `project` (valid slug) and `instance` (key id): a missing member, an unknown member, a wrong type or a malformed value. |
| `E_ENV_ID` | invalid | `id` is not a string, is empty, exceeds 256 scalar values, contains control characters, or has leading/trailing U+0020. |
| `E_ENV_STAGE` | invalid | `stage` is not one of the five closed values, or a kind requiring `accepted` uses another stage. |
| `E_ENV_ACTOR` | invalid | `actor` is not an object, or contains members that are forbidden for its type (e.g. agent-only members on a human actor), or is otherwise structurally invalid; the key-lifecycle exception (agent-only members not required for `weave.key.declared`/`weave.key.rotated`/`weave.key.revoked`) is part of the rule. |
| `E_ENV_ACTOR_TYPE` | invalid | `actor.type` is not one of the five closed values. |
| `E_ENV_ACTOR_KEY` | invalid | `actor.key` is not a valid key id (`ed25519:` + 32 lowercase hex). |
| `E_ENV_ACTOR_MODEL_MISSING` | invalid | `actor.type` is `agent` and `actor.model` is absent. |
| `E_ENV_ACTOR_MODEL` | invalid | `actor.model` is present but does not match `provider/model@version` or exceeds 256 bytes. |
| `E_ENV_ACTOR_ON_BEHALF_MISSING` | invalid | `actor.type` is `agent` and `actor.on_behalf_of` is absent. |
| `E_ENV_ACTOR_ON_BEHALF` | invalid | `actor.on_behalf_of` is present but is not a valid key id. |
| `E_ENV_ACTOR_GRANT_MISSING` | invalid | `actor.type` is `agent` and `actor.grant` is absent (the field itself is absent; a present but unresolvable grant is `E_GRANT_UNRESOLVED`). |
| `E_ENV_ACTOR_IDEMPOTENCY_MISSING` | invalid | `actor.type` is `agent` and `actor.idempotency_key` is absent. |
| `E_ENV_ACTOR_IDEMPOTENCY` | invalid | `actor.idempotency_key` is not a valid string (empty, control characters, >256 scalar values). |
| `E_ENV_TIME` | invalid | `recorded_at`/`occurred_at`/another TS field is not RFC 3339 UTC with exactly three fractional digits and trailing `Z` (or uses second `60`). |
| `E_ENV_REFS` | invalid | `refs` is not an array of `{rel, ref}` with a registered `rel`, exceeds 256 entries, repeats an identical `(rel, ref)` pair, or a `refs` entry or nested reference object is closed and has a missing or unknown member or a malformed member value. |
| `E_ENV_LABELS` | invalid | `labels` is not a closed object with the defined members (unknown member or wrong type). `sensitivity` is optional; a missing `sensitivity` is not a structural error (it is handled by `E_LABEL_DOWNGRADE` when a derivation input ranks above `public`). |
| `E_ENV_SENSITIVITY` | invalid | `labels.sensitivity` is not one of `public`, `internal`, `personal`, `local-only`. |
| `E_ENV_LICENCE` | invalid | `labels.licence` is not a syntactically valid SPDX license expression, or its parenthesis nesting depth exceeds `MAX_LICENCE_NESTING` (specification §8.7, §13). |
| `E_ENV_SALT` | invalid | `salt` is present but is not strict unpadded base64url of exactly 16 bytes. |
| `E_ENV_SALT_MISSING` | invalid | `labels.sensitivity` is `personal` or `local-only` and `salt` is absent. |
| `E_ENV_SIGS` | invalid | `sigs` is not an array of 0–16 signature objects sorted by `key` ascending with unique keys; or an entry is not a closed `{alg,key,value}` object or a member has the wrong JSON type; or an `alg` does not match the algorithm-name grammar; or the `key`/`value` grammar of that algorithm (specification §4.3) is violated in a way not covered by `E_ENV_SIG_KEY`/`E_ENV_SIG_VALUE`. An empty array is structurally valid; whether the record must be signed is `E_SIG_REQUIRED`. |
| `E_ENV_SIG_ALG` | invalid (no longer emitted) | **Retained for older vectors; an H0 verifier does not emit it.** Unknown algorithms are structurally validated and ignored. |
| `E_ENV_SIG_KEY` | invalid | An `ed25519` signature entry's `key` is not a valid ed25519 key id (`ed25519:` + 32 lowercase hex). |
| `E_ENV_SIG_VALUE` | invalid | An `ed25519` signature entry's `value` is not strict unpadded base64url of exactly 64 bytes. |
| `E_ENV_BODY` | invalid | `body` is absent or is not a JSON object. |
| `E_ACTOR_KEY_TYPE_MISMATCH` | invalid | `actor.type` is incompatible with the class of `actor.key` or of a declared signing key (for example an `agent` record signed by a key declared `human`), or the record's kind requires a human/organization signer class by its signer rules while `actor.type` (or the only available signer) is not `human`/`organization` (for example a `weave.consent.*` record with an agent or program actor). |
| `E_ACTOR_HUMAN_KEY` | invalid | A non-human record outside the three key-lifecycle kinds carries an additional signature made by a key declared `human` or `organization` (human/organization keys only sign human/organization acts; key-lifecycle kinds may require or allow such counter-signatures). |
| `E_SIG_INVALID` | invalid | The Ed25519 verification equation does not hold for the signed bytes, or a known-algorithm signature fails a cryptographic step (the first failing step of specification §3.4 determines the code). |
| `E_SIG_REQUIRED` | invalid | A record that needs a per-record signature has `sigs` absent or empty, or has a non-empty `sigs` for an ordinary kind whose required signer has no valid known-algorithm signature. Not used when a dedicated signer code applies or when no known-algorithm signature exists at all. |
| `E_SIG_NONCANONICAL_A` | invalid | The public key does not pass the complete RFC 8032 §5.1.3 point decoding (length not 32, `y >= p`, no square root / not on the curve, or the non-canonical `x = 0` with sign bit 1). |
| `E_SIG_NONCANONICAL_R` | invalid | The signature `R` does not pass the complete RFC 8032 §5.1.3 point decoding (the non-canonical `x = 0` with sign bit 1 included). |
| `E_SIG_SMALL_ORDER_A` | invalid | The decoded public key is small-order: `[8]A` is the identity. Includes the identity-key forgery. |
| `E_SIG_SMALL_ORDER_R` | invalid | The decoded signature `R` is small-order: `[8]R` is the identity. |
| `E_SIG_S_OUT_OF_RANGE` | invalid | The signature scalar `S` is not canonical (`S >= L`). |
| `E_SIG_MIXED_ORDER_A` | invalid | The public key decodes, is not small-order, but is not in the prime-order subgroup (`[L]A != identity`). Mixed-order public keys are rejected. |
| `E_SIG_UNVERIFIABLE` | unverifiable | A record that needs a per-record signature, or a manifest attestation, has a non-empty signature list, but no entry has both a known algorithm and a declared key, so no required signature can be checked. Unknown-algorithm entries are ignored; when the failure is caused by an undeclared signature key the code is `E_KEY_UNKNOWN` instead. |
| `E_KIND_BODY_SCHEMA` | invalid | The body of a registered kind does not satisfy its registered schema; for the special `weave.erased` shape this code also covers every structural violation of the placeholder itself (missing/unknown member, wrong type, malformed `digest` or `attestation`), because `weave.erased` is not a normal envelope. |
| `E_KEY_PUBLIC_KEY` | invalid | A declaration's `public_key` is **missing**, or is not strict unpadded base64url of exactly 32 bytes. The missing-member case is decided before the generic `E_KIND_BODY_SCHEMA` and before any trust judgement (T1). Point validity (canonical encoding, small order, subgroup membership) is not checked at declaration; those checks belong to signature verification and use `E_SIG_*`. |
| `E_KEY_ID_MISMATCH` | invalid | A declared key id is not the key-id derivation of its declared public key. |
| `E_KEY_CLASS_CONFLICT` | invalid | A `weave.key.declared` in a container or record target names a key id that already has a governing class — from the local keyset or from an earlier valid context declaration — and claims a different class (S1, T4). Same-class declarations are valid but do not override the governing class or validity window. (Conflicting keyset declarations for one key id are a usage error, not this code.) |
| `E_KEY_DECLARED_NOT_SELF_SIGNED` | invalid | A `weave.key.declared` record has no valid signature by the declared key. |
| `E_KEY_OWNER_MISSING` | invalid | A `weave.key.declared` record with `key_type` in `agent`, `program`, `device` has no `body.owner`, or the owner resolves but its declaration's class is not `human`/`organization`. |
| `E_KEY_DECLARED_NOT_COSIGNED` | invalid | An `agent`/`program`/`device` key declaration has no valid cosignature by the key named in `body.owner`. Human/organization declarations are never invalid for lack of a cosignature; when they cannot be chained to a trusted root they are `unverifiable` (`E_KEY_UNTRUSTED`). |
| `E_KEY_VALIDITY` | invalid | A key declaration's or a `weave.grant`'s validity window is inverted (`valid_from` > `valid_until`). Consent windows use `E_CONSENT_VALIDITY`; key rotation has no window. |
| `E_KEY_ROTATION_KEYS` | invalid | `weave.key.rotated` uses the same key as old and new, or a public-key value is malformed or contradicts its key id. |
| `E_KEY_ROTATION_SIGS` | invalid | `weave.key.rotated` is not signed by both the old and the new key. |
| `E_KEY_REVOKE_EFFECTIVE` | invalid | `weave.key.revoked.effective_at` is later than the revocation record's `recorded_at`. |
| `E_KEY_REVOKE_SIGNER` | invalid | A `weave.key.revoked` record lacks an acceptable signer (compromise requires a human/organization key; retired/other require the revoked key or a human/organization key). |
| `E_KEY_UNKNOWN` | unverifiable | A signature or actor names a key that is not declared anywhere in the verification context (container plus external keyset); the signature cannot be checked. |
| `E_KEY_UNTRUSTED` | unverifiable | A `human`/`organization` declaration in a container or record target cannot be chained to a trusted root supplied by the local keyset (`--keys`): its key is not already trusted and it has no valid cosignature by a trusted human/organization key. Also used when an `agent`/`program`/`device` declaration's owner resolves but is not in the trusted set. An untrusted declaration never invalidates other declarations and never becomes trusted; with no `--keys` input every container/target human/organization declaration is untrusted. |
| `E_KEY_EXPIRED` | invalid | A signature's claimed `recorded_at` is outside the signing key's declared validity window: later than `valid_until`, or earlier than `valid_from`. |
| `E_KEY_REVOKED` | invalid | A signature was made after a `retired`/`other` revocation's `effective_at` (claimed `recorded_at`; equality counts as revoked). The `retired`/`other` family and the `key-compromise` family are independent: when this code applies it is the record's outcome and **no timestamp evidence can rescue it**, even if a compromise revocation also exists (T2). |
| `E_KEY_COMPROMISED` | invalid | A signature by a `key-compromise`-revoked key cannot be rescued: either there is **no timestamp evidence at all** (single record target, no listed receipts, claimed level below L2), or verified trusted receipt evidence exists but none satisfies the strict `genTime + accuracy < T` bound. If receipts are present but none is verified, trusted and usable (for example no matching `--tsa-trust` anchor, or every receipt has an unusable accuracy per T3), the outcome is `unverifiable` with `E_TS_UNTRUSTED`, not this code. The claimed `recorded_at` is never evidence. |
| `E_GRANT_SCHEMA` | invalid | A `weave.grant` body does not match its registered schema (wrong action variant, missing/extra variant members, invalid lists, duplicate list elements). |
| `E_GRANT_GRANTER` | invalid | The granter is not permitted to issue this grant given the resolved context: the resolved parent grant is not an authorising `weave.grant` covering kind `weave.grant`/action `grant`, its `grantee.key` is not the sub-granter's `actor.key`, the parent is outside its validity window or revoked at the evaluated time, the actor/signing-key class does not permit issuing a grant, or (for a `weave.grant` record with `action == "grant"` and non-empty `sigs`) the required granter signature is missing/wrong. An unresolvable parent is `E_GRANT_UNRESOLVED`. |
| `E_GRANT_NOT_TRANSFERABLE` | invalid | A delegated sub-grant cites a parent grant whose `transferable` is false. |
| `E_GRANT_DELEGATION_EXCEEDS` | invalid | A delegated sub-grant exceeds its parent: `kinds`, `actions` or `scope` is not a subset, or its validity window extends outside the parent's. |
| `E_GRANT_REVOKE_SIGNER` | invalid | A grant-revocation record is not signed by a key authorised to revoke: neither in the target grant's `grant.revocation` list (when present) nor the original granter's `actor.key` nor an explicit rotation successor of that key (a cycle in the key-id graph counts as no match). |
| `E_GRANT_REVOKE_REF` | invalid | A grant-revocation record's `revokes` reference does not resolve to a `weave.grant` record with matching digest. |
| `E_GRANT_UNRESOLVED` | unverifiable | A grant's parent, or a record's cited authorisation, cannot be resolved or checked in the verification context (including a chain deeper than the supported bound and a `program`/`device` grant record that cannot carry `actor.grant`). |
| `E_GRANT_REVOKED` | unverifiable | A record or grant cites an authorisation that was revoked at the evaluated time (`effective_at <= recorded_at`; equality counts as revoked). |
| `E_GRANT_EXPIRED` | unverifiable | A record or grant cites an authorisation that is outside its validity window at the evaluated time (expired or not yet valid). |
| `E_GRANT_GRANTEE_MISMATCH` | invalid | A record's `actor.key` is not the `grantee.key` of the grant it cites for authorisation. |
| `E_GRANT_NOT_APPLICABLE` | invalid | A record's kind or stage action is not covered by its cited authorisation. |
| `E_CONSENT_VALIDITY` | invalid | A `weave.consent.granted` record has `valid_from` > `valid_until`. |
| `E_CONSENT_REVOKE_REF` | invalid | A `weave.consent.revoked` record's `revokes` reference does not resolve to a `weave.consent.granted` record. |
| `E_CONSENT_REVOKED` | invalid | A record cites a consent that has been revoked, and the record's claimed `recorded_at` is greater than or equal to the revocation's `effective_at` (equality counts as revoked). |
| `E_ERASE_ACTOR` | invalid | A `weave.erasure` record's actor may not execute an erasure: `human`/`organization` are always allowed; an `agent` requires a covering grant for kind `weave.erasure`/action `erase`; a `program`/`device` requires a resolving, valid `body.basis` grant covering the actor's key with action `erase`. |
| `E_ERASE_DIGEST_MISMATCH` | invalid | A `weave.erasure` record's `erased` reference does not match its target erased placeholder (`origin`, `id`, `digest`), or a placeholder's `digest` contradicts the attestation. |
| `E_ERASE_ATTESTATION` | invalid | An erased placeholder's `attestation` reference does not resolve to the corresponding `weave.erasure` record. |
| `E_ERASE_CONTRADICTION` | invalid | A container contains both a live record and an erased placeholder for the same `origin` + `id`, or two placeholders for the same target. |
| `E_LABEL_DOWNGRADE` | invalid | A derived record's sensitivity rank is lower than a resolved derivation input's rank (`derived_from`, `reshaped_from`, `migrated_from`, `correction_of`), or is absent while a resolved input ranks above `public`. |
| `E_LABEL_LOCAL_ONLY_EXPORTED` | invalid | A record carrying `labels.sensitivity = "local-only"` appears in an export container. |
| `E_REF_KIND_MISMATCH` | invalid | A reference's claimed `kind` (or a link target's required kind) contradicts the resolved target's actual kind. A reference resolved to `erased` is not kind-checked. |
| `E_MANIFEST_MISSING` | invalid | The container has no `manifest.json`. |
| `E_MANIFEST_FORMAT` | invalid | `manifest.format` is not `"weave-record/1"`. |
| `E_MANIFEST_VERSION` | invalid | `manifest.manifest_version` is not a supported integer (H0: only `1`). |
| `E_MANIFEST_SCHEMA` | invalid | The manifest object or attestation file is not a closed object with the defined members and types. |
| `E_MANIFEST_DIGEST` | invalid | `signatures/manifest.sig.json.digest` does not equal the manifest digest computed per the specification. |
| `E_MANIFEST_UNSIGNED` | invalid | The attestation file `signatures/manifest.sig.json` is absent, or its `signatures` array is empty. A non-empty list with no verifiable required signature is `unverifiable` (`E_KEY_UNKNOWN` or `E_SIG_UNVERIFIABLE`). |
| `E_MANIFEST_SIG_INVALID` | invalid | A known-algorithm manifest signature does not verify against the manifest signature message. Unknown-algorithm entries are ignored. |
| `E_MANIFEST_RECORDS` | invalid | `manifest.records` is not an array of 1–100000 well-formed entries, is not sorted by digest ascending, repeats a digest, or an entry's `id`/`kind` does not equal the record file's `id`/`kind`. |
| `E_MANIFEST_RECORD_MISSING` | invalid | A record listed in the manifest has no file in `records/`. |
| `E_MANIFEST_RECORD_EXTRA` | invalid | `records/` contains a file not listed in the manifest, or a malformed filename. |
| `E_MANIFEST_RECORD_DIGEST` | invalid | A record file's computed digest does not match its filename and/or manifest entry. |
| `E_MANIFEST_BLOB` | invalid | `blobs/` contents and `manifest.blobs` disagree (missing, extra, wrong digest/size, unsupported digest algorithm), or the blobs directory exists while no blobs are listed. |
| `E_MANIFEST_LEVEL` | invalid | `level` is not `L0`/`L1`/`L2`, or the level-specific completeness rules are violated (e.g. timestamps under L0/L1, non-null `chain` under L0). |
| `E_MANIFEST_L1_NO_HEAD` | invalid | The claimed level is `L1`/`L2` but `manifest.chain` is absent or null. |
| `E_MANIFEST_L1_NO_POSITION` | invalid | The claimed level is `L1`/`L2` but a `records[]` entry lacks a unique non-negative `chain_index`. |
| `E_MANIFEST_L2_NO_TIMESTAMP` | invalid | The claimed level is `L2` but the manifest attestation lists no RFC 3161 timestamp. |
| `E_MANIFEST_CHAIN` | invalid | `previous_manifest.digest` does not equal the digest of the embedded `previous/manifest.json`; or the embedded previous manifest's `origin` differs from the current manifest's `origin`; or `--previous` is supplied while `previous_manifest` is `null`; or the supplied `--previous` container's manifest is unreadable/invalid or its digest disagrees with the embedded manifest. A missing or unreadable `--previous` path is a usage/I/O error (exit 2). |
| `E_MANIFEST_CHAIN_MISSING` | invalid | `previous_manifest` is non-null but `previous/manifest.json` is absent. |
| `E_MANIFEST_CHAIN_UNEXPECTED` | invalid | `previous_manifest` is null but `previous/` contains a manifest. |
| `E_CONTAINER_ENTRY` | invalid | The container contains an entry outside the allowed layout, a path that escapes the root, a duplicate entry name, a symlink or other unsupported entry type, or an unknown file in `signatures/`/`previous/`. These checks also apply to `readable/` entries, even though they are never decompressed or CRC-checked (T6). |
| `E_CONTAINER_SIZE` | invalid | Entry count or uncompressed total bytes exceed the container limits (zip-bomb protection). |
| `E_CONTAINER_ZIP` | invalid | The zip cannot be read as a zip (corrupt archive, unsupported compression, encrypted entries), or a structural zip rule of specification §11.9 is violated: bytes before the first local file header or after the end-of-central-directory record; a non-empty archive comment; a gap, pad byte or overlap between entries or before the central directory; a local file header that disagrees with the central directory on name, flags, method, CRC or sizes (or, with a data descriptor, descriptor values that disagree); an EOCD or ZIP64 EOCD entry count or central-directory size/offset that disagrees with the parsed values; or an entry with the DOS directory attribute carrying data. ZIP64 archives are accepted and are not an error by themselves. |
| `E_TS_FILE` | invalid | A listed timestamp receipt file is missing or does not hash to the listed digest. |
| `E_TS_SCHEMA` | invalid | A receipt is not a DER `TimeStampResp` with a `granted` token and a well-formed TSTInfo: `PKIStatus` not `granted`, wrong content type, TSTInfo version not 1, `messageImprint`/`signerInfo` hash algorithm not sha256, an invalid `genTime`, or a malformed `accuracy` component — a present `milliseconds`/`microseconds` outside 1–999 (an explicit `0` included), or a negative/non-integer component. An accuracy total above `MAX_TS_ACCURACY` or a conversion overflow is **not** this code: it makes the receipt unusable evidence (`E_TS_UNTRUSTED`, container unverifiable). |
| `E_TS_IMPRINT` | invalid | The token's `messageImprint.hashedMessage` does not equal the expected imprint (the raw 32-byte manifest digest for the first receipt, or `SHA-256(previous receipt bytes ‖ raw manifest digest)` for a renewal receipt). |
| `E_TS_CMS` | invalid | The token's CMS evidence fails: the signer certificate is not carried in the token, the ESS `signingCertificateV2` attribute is missing or mismatched, the signed attributes' `messageDigest` is wrong, or the CMS signature does not verify. |
| `E_TS_CERT` | invalid | The signer certificate or its signature algorithm is unacceptable: a signature algorithm outside the allowlist (RSA PKCS#1 v1.5 with SHA-256/384/512 or ECDSA with SHA-256/384), missing `id-kp-timeStamping` EKU, KeyUsage without `digitalSignature` when the extension is present, or a validity window that does not contain `genTime`. |
| `E_TS_UNTRUSTED` | unverifiable | No trust anchor was supplied that matches the timestamp signer's leaf certificate, so the receipt is reported `present-unverified`; the container must not be reported `valid`. The same code and state apply when the receipt's accuracy is **unusable evidence**: the converted `accuracy` total exceeds `MAX_TS_ACCURACY` or the conversion overflows (T3). Such a receipt cannot support an L2 claim (the container is unverifiable) and cannot rescue; a signature by a `key-compromise`-revoked key with only such receipts is `unverifiable` (missing usable information), never `E_KEY_COMPROMISED`. |
| `E_TS_RENEWAL` | invalid | The timestamp receipts do not form exactly one renewal chain: no receipt with `renews == null`, a `renews` link that is dangling or not earlier in the chain, duplicate paths or digests, more than one chain, or a receipt listed out of chain order. |

## Notices (`N_*`, non-fatal unless stated)

| Code | Condition |
|---|---|
| `N_KIND_UNKNOWN_OPAQUE` | The record's kind is well-formed but not registered and the record's final verdict is `valid`; the body was not interpreted (must never be treated as understood). `kind_known` is `false` for unregistered kinds regardless of the verdict (F12 item 3). |
| `N_KEY_UNDECLARED` | A signing key has no declaration in the verification context; the signature could not be checked (paired with `E_KEY_UNKNOWN` when it makes the unit unverifiable). |
| `N_KEY_TOFU` | Per-record form of the TOFU predicate (specification §14.9): at least one of this record's signature checks was context-trusted — the verifying key material came from a context `weave.key.declared` declaration rather than the local keyset — even if that signature or the record later fails. For the three key-lifecycle kinds only the actor-key signature counts. The manifest signature never produces this notice (it contributes to `L_KEY_TRUST_TOFU`) (T10). |
| `N_SELF_ATTESTED_ROOT_KEY` | A `human`/`organization` declaration in a container or record target is self-signed only and cannot be chained to a trusted root supplied by the local keyset; it is `unverifiable` (`E_KEY_UNTRUSTED`) and is never a root. Keyset declarations never produce this notice. |
| `N_NO_HUMAN_SIGNATURE` | An `accepted` record whose verdict is `valid` has no valid signature made by a key declared `human` in the verification context. The notice is not reported on a record made `unverifiable` by the required-signature check or invalid for another reason (F6). |
| `N_REF_MISSING` | A reference resolved to `missing`. |
| `N_REF_MOVED` | A reference resolved to `moved` (the object was located through hints with a matching digest). An offline verifier without hint resolution never emits this. |
| `N_REF_UNVERIFIABLE` | A reference resolved to `unverifiable` (target present but not valid, digest mismatch, unsupported digest algorithm, or an undecidable non-digest dependency). |
| `N_LABEL_PROPAGATION_UNCHECKED` | A derivation reference could not be resolved, so strictest-label propagation could not be checked. |
| `N_CHAIN_CLAIM_UNVERIFIED` | An L1/L2 chain head is an internal-chain claim that an offline verifier cannot recompute; `level_verified` is reported as `L0`. |
| `N_CONSENT_UNRESOLVED` | `labels.consent` is a reference that could not be resolved. |
| `N_PREVIOUS_SIG_UNVERIFIED` | The embedded previous manifest's own signature was not re-verified; reported if and only if `previous_manifest` is non-null and the signature was not re-verified, including when a later container check fails. Not reported when the manifest cannot be parsed and the previous manifest is not reachable (T12). |
| `N_IDEMPOTENCY_DUPLICATE` | A container contains two records with the same `origin` and `actor.idempotency_key` (claimed as the same action). |
| `N_READABLE_PRESENT` | The container has a `readable/` view; it is unsigned and was not used. Reported if and only if an enumerated container contains a `readable/` entry, including when a later container check fails; not reported when entry enumeration fails before the entry is observed (T12). |

## Limitation identifiers (`L_*`, closed list, report `limitations` only)

`limitations` in a report is a sorted, unique array of these identifiers and nothing else.
The full emission conditions are in specification §14.9; no free prose is permitted (S12).

| Identifier | Meaning |
|---|---|
| `L_OFFLINE_CONTEXT` | The verification context is the container/target plus the supplied keyset; references to records outside it resolve as `missing`. Always emitted for record and container targets. |
| `L_CHAIN_CLAIM_UNVERIFIED` | A claimed L1/L2 internal chain cannot be recomputed offline; `level_verified` is `L0`. |
| `L_KEY_TRUST_TOFU` | At least one signature check in the report — a record signature or the manifest signature — was context-trusted per the TOFU predicate of specification §14.9. |
| `L_PREVIOUS_SIG_UNVERIFIED` | An embedded previous manifest exists and its own signature was not re-verified. |
| `L_TSA_TRUST_UNVERIFIED` | Timestamps are present but no matching TSA anchor was supplied; they are `present-unverified`. |
| `L_ERASED_PLACEHOLDER` | The verified input contains a `weave.erased` placeholder. |
| `L_ERASED_STANDALONE` | A standalone placeholder was verified with no container context, so the erasure cross-checks could not be applied. |
| `L_LABELS_ARE_CLAIMS` | Labels, consent coverage or licence claims were checked for consistency only. |
| `L_UNKNOWN_KIND_OPAQUE` | An unregistered kind body was transported but not interpreted, and the record's verdict is `valid`. |
| `L_LABEL_PROPAGATION_UNCHECKED` | A derivation reference could not be resolved, so strictest-label propagation could not be checked. |
