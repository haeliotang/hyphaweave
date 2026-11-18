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
> closed `L_*` limitation-identifier list (S12). Revision 4 (Inceptless decision
> 2026-11-11 #14) adds `L_PREVIOUS_CONTENT_UNVERIFIED` (V3) and sharpens `E_TS_SCHEMA`
> (strict DER), `E_KEY_PUBLIC_KEY` (structural classification, V5) and
> `E_CONTAINER_ZIP` (version-needed and per-entry disk start, V6). Revision 5 (Inceptless
> decision 2026-11-11 #16) adds no code; it sharpens `E_MANIFEST_CHAIN` (a supplied
> previous's signature is verified in the target context, W1; the whole previous zip obeys
> §11.9 rules 1–4, W2), `E_TS_SCHEMA` (check 1 is a real DER re-encoding check, W3),
> `E_TS_CMS` (an algorithm/key-type mismatch is check 10, W6), `E_CONTAINER_ZIP` /
> `E_CONTAINER_SIZE` (the zip check order, W7), the timestamp and container check orders
> (W5, W6), the usage-error rule for operator inputs (W4) and the
> `L_PREVIOUS_CONTENT_UNVERIFIED` / `L_KEY_TRUST_TOFU` conditions (W1, W5). Revision 6
> (Inceptless decision 2026-11-12 #1) adds no code; it sharpens `E_TS_SCHEMA` (check 1's
> DER rules come from X.690 and the module definitions only, X1) and `E_MANIFEST_CHAIN`
> (a `key-compromise` revocation is judged against the previous `created_at`, X2; an
> invalid rotation record supplies no key material for the link, X5); decision
> 2026-11-12 #2 adds the fixed form of the signer algorithm parameters to `E_TS_SCHEMA` (X6);
> decision 2026-11-12 #3 (X7) adds whole-content time forms and exactly one `SignerInfo`,
> corrects the sha*WithRSAEncryption parameters to absent or `NULL`, and limits certificate
> decoding to the signer certificate. Revision 7 (Inceptless decision 2026-11-15 #8, the S2
> round of specification revision 3) adds no code; it sharpens `E_KEY_EXPIRED`,
> `E_KEY_REVOKED`, `E_KEY_COMPROMISED` and `E_TS_UNTRUSTED` (every signature of a
> key-lifecycle record is judged under §9.4, F38/F61-1), `E_KEY_UNKNOWN` /
> `E_SIG_UNVERIFIABLE` (step (4) covers every entry — the code is chosen invalid-first since S2-FIX1 T2; §4.4 step 5 is decided by the required
> signer key, F46), `E_ENV_SIGS` (member JSON types before grammar, F67), `E_KEY_PUBLIC_KEY`
> (before key resolution, F39/F50), `E_KIND_BODY_SCHEMA` (rotation key ids, F61-3),
> `E_JSON_SIZE` (an unlisted or too-deep `records/` file, F55/F60), `E_TS_FILE` (an unlisted
> `.tsr`, F54), `E_MANIFEST_LEVEL` (L1 with timestamps, F56), `E_TS_SCHEMA` (universal tag 0,
> ENUMERATED, constructed-only types, certificate versions and open types in 1e, F57, F62,
> F63, F66) and the §10.3 erasure codes (reported independently, F48). Decisions
> 2026-11-15 #18 (S2-FIX1) and #22 (S2-FIX2) revise the S2 round and are folded into
> revision 7; S2-FIX2 adds no code and sharpens `E_GRANT_GRANTER` / `E_GRANT_UNRESOLVED`
> (a parent or cited grant record that is present but itself invalid is `E_GRANT_GRANTER`,
> Q6/U2), `E_ERASE_ACTOR` (a program's or device's basis chain is judged like an agent's,
> U1), `E_MANIFEST_SIG_INVALID` / `E_KEY_UNKNOWN` (manifest signature entries are judged
> invalid-first, U5), `E_TS_SCHEMA` (the 1a escape-sequence rules of the string types and
> the rejection of DATE, TIME-OF-DAY, DATE-TIME, OID-IRI and RELATIVE-OID-IRI, U4) and
> `N_READABLE_PRESENT` (member-level zip failures, U7). Decision 2026-11-16 #1 (S2-FIX3,
> the third revision of the S2 round) is folded into revision 7 as well; it adds no code
> and sharpens `E_ENV_REFS` (duplicates compare whole reference values, F76),
> `E_ACTOR_KEY_TYPE_MISMATCH` (no verified signature needed, F77; the consent signer is
> `actor.key`, F81), `E_KEY_UNKNOWN` (an owner resolves only through a structurally valid
> declaration, F73; a declaration with a cosignature that does not pass supplies no
> material, F72), `E_KEY_ROTATION_KEYS` (a missing `new_public_key`, F74),
> `E_CONTAINER_ENTRY` / `E_CONTAINER_ZIP` (reported together in step (1), F75), the §10.3
> erasure codes (F80, F82 and the `sigs`-absent erasure record) and `L_LABELS_ARE_CLAIMS` /
> `L_ERASED_*` (facts about the records as parsed, F78). Decision 2026-11-16 #13 (S2-FIX6)
> is folded into revision 7 too; it adds no code, removes from `E_GRANT_GRANTER` the
> parent outside its window or revoked (those are `E_GRANT_EXPIRED` / `E_GRANT_REVOKED`,
> §5.5.2 step 6) and sharpens `E_GRANT_REVOKED` (revocation is judged over the whole chain
> before any window). Revision 8 (Inceptless decision 2026-11-16 #44, the S3 round of
> specification revision 3, decided by principle) adds no code; it splits the blob
> violations between `E_MANIFEST_SCHEMA` (a malformed `manifest.blobs`, more than
> `MAX_BLOBS` entries included, B1/B2) and `E_MANIFEST_BLOB` (a well-formed listing with
> another digest than `sha256:<64 lowercase hex>` or out of order, and every disagreement
> with the files, B1/B3), names every file in `blobs/` or `blobs/sha256/` that is not a
> listed blob an extra file whatever its name (B3), and sharpens `E_CONTAINER_ENTRY` (a
> file below a directory inside `blobs/` other than `blobs/sha256/`, B4). Its revision
> round (FIX1, Inceptless decision 2026-11-17 #5, decided by principle) adds no code
> either: a zero-data zip directory entry takes no part in the layout or in whether
> `blobs/` is present, but its path is checked like every entry's (`E_CONTAINER_ENTRY`);
> `N_IDEMPOTENCY_DUPLICATE` compares the origin and the idempotency key only, over every
> record whose envelope structure passes; and the digest-string grammar of §2.7 is
> applied whole wherever a digest string is read (`E_ENV_REFS`, `E_KIND_BODY_SCHEMA`).
> Its second revision (FIX2, Inceptless decision 2026-11-18 #2, decided by principle) adds
> no code: only a name ending `/` makes a zip directory entry, and the DOS directory
> attribute matters only to `E_CONTAINER_ZIP` for an entry that carries data (a non-zero
> compressed or uncompressed size); and `N_READABLE_PRESENT` after the zip entry checks
> does not depend on the order of the central directory (decision 2026-11-18 #3).

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
specification §14.4 is terminal for the record exactly like an error (F7). The timestamp
phase runs in the complete order of specification §12.2 (W6): the file checks of every
listed receipt (`E_TS_FILE`, `E_JSON_SIZE`), then the renewal-chain shape (`E_TS_RENEWAL`),
then, per receipt in chain order, checks 1–13 and 15, the first failing check being that
receipt's only code. A zip is checked in the order of specification §11.9 (W7): locate the
end-of-central-directory record (bytes before the first local header or after the record
fail here, `E_CONTAINER_ZIP`) → parse the central directory (`E_CONTAINER_ZIP`) → the §13
entry-count and declared-total limits (`E_CONTAINER_SIZE`, nothing later is checked) →
every remaining structural rule (`E_CONTAINER_ZIP`).

A **container** is evaluated in this order: safe entry enumeration → manifest bytes →
manifest structure → manifest digest → manifest signature → level/chain completeness →
records listing and per-record evaluation → cross-record state → blobs → previous manifest
chain → timestamps → aggregation. A container-level invalid error stops the container
pipeline at the stage where it is found: record listing/evaluation does not run for an
invalid error found before it, and the report carries `records: []`; an invalid error at
the cross-record, blob or previous-manifest-chain stage means the later stages report
nothing — no code, notice, limitation or timestamp entry — while the records already
evaluated keep their verdicts (W5). The failing stage
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
| `E_JSON_SIZE` | invalid | A record, manifest, signature-attestation file or timestamp receipt file exceeds its size limit, or a JSON document's **value nesting depth** exceeds `MAX_JSON_DEPTH` (specification §1.9, §13). A `records/` file is subject to `MAX_RECORD_BYTES` and `MAX_JSON_DEPTH` whether or not it is listed; the records-listing phase reports such a file as `E_JSON_SIZE` (with `E_MANIFEST_RECORD_EXTRA` when it is unlisted or misnamed), never as `E_MANIFEST_RECORD_DIGEST` (S2/F55/F60). |
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
| `E_ENV_REFS` | invalid | `refs` is not an array of `{rel, ref}` with a registered `rel`, exceeds 256 entries, repeats an identical `(rel, ref)` pair (the same `rel` and reference objects equal as JSON values, `kind` and `hints` included; entries that differ only in `kind` or `hints` are not duplicates, S2-FIX3 F76), or a `refs` entry or nested reference object is closed and has a missing or unknown member or a malformed member value — a `digest` that breaks the digest-string grammar of specification §2.7 included (the algorithm-name pattern and its 32-byte bound, 1–128 lowercase hexadecimal digits; FIX1). |
| `E_ENV_LABELS` | invalid | `labels` is not a closed object with the defined members (unknown member or wrong type). `sensitivity` is optional; a missing `sensitivity` is not a structural error (it is handled by `E_LABEL_DOWNGRADE` when a derivation input ranks above `public`). |
| `E_ENV_SENSITIVITY` | invalid | `labels.sensitivity` is not one of `public`, `internal`, `personal`, `local-only`. |
| `E_ENV_LICENCE` | invalid | `labels.licence` is not a syntactically valid SPDX license expression, or its parenthesis nesting depth exceeds `MAX_LICENCE_NESTING` (specification §8.7, §13). |
| `E_ENV_SALT` | invalid | `salt` is present but is not strict unpadded base64url of exactly 16 bytes. |
| `E_ENV_SALT_MISSING` | invalid | `labels.sensitivity` is `personal` or `local-only` and `salt` is absent. |
| `E_ENV_SIGS` | invalid | `sigs` is not an array of 0–16 signature objects sorted by `key` ascending with unique keys; or an entry is not a closed `{alg,key,value}` object or a member has the wrong JSON type (judged before any member's grammar, so a non-string `value` is `E_ENV_SIGS`, not `E_ENV_SIG_VALUE`, S2/F67); or an `alg` does not match the algorithm-name grammar; or the `key`/`value` grammar of that algorithm (specification §4.3) is violated in a way not covered by `E_ENV_SIG_KEY`/`E_ENV_SIG_VALUE`. An empty array is structurally valid; whether the record must be signed is `E_SIG_REQUIRED`. |
| `E_ENV_SIG_ALG` | invalid (no longer emitted) | **Retained for older vectors; an H0 verifier does not emit it.** Unknown algorithms are structurally validated and ignored. |
| `E_ENV_SIG_KEY` | invalid | An `ed25519` signature entry's `key` is not a valid ed25519 key id (`ed25519:` + 32 lowercase hex). |
| `E_ENV_SIG_VALUE` | invalid | An `ed25519` signature entry's `value` is a string that is not strict unpadded base64url of exactly 64 bytes. |
| `E_ENV_BODY` | invalid | `body` is absent or is not a JSON object. |
| `E_ACTOR_KEY_TYPE_MISMATCH` | invalid | `actor.type` is incompatible with the class of `actor.key` or of a declared signing key (for example an `agent` record signed by a key declared `human`), or the record's kind requires a human/organization signer class by its signer rules while `actor.type` (or the only available signer) is not `human`/`organization` (for example a `weave.consent.*` record with an agent or program actor). The comparison with the class of `actor.key` needs no verified signature by it and precedes an agent record's grant coverage (S2-FIX3 F77); the required signer of a `weave.consent.*` record is `actor.key`, so a consent signed only by another human key is this code (S2-FIX3 F81). |
| `E_ACTOR_HUMAN_KEY` | invalid | A non-human record outside the three key-lifecycle kinds carries an additional signature made by a key declared `human` or `organization` (human/organization keys only sign human/organization acts; key-lifecycle kinds may require or allow such counter-signatures). |
| `E_SIG_INVALID` | invalid | The Ed25519 verification equation does not hold for the signed bytes, or a known-algorithm signature fails a cryptographic step (the first failing step of specification §3.4 determines the code). |
| `E_SIG_REQUIRED` | invalid | A record that needs a per-record signature has `sigs` absent or empty, or has a non-empty `sigs` for an ordinary kind whose required signer has no valid known-algorithm signature. Not used when a dedicated signer code applies or when no known-algorithm signature exists at all. |
| `E_SIG_NONCANONICAL_A` | invalid | The public key does not pass the complete RFC 8032 §5.1.3 point decoding (length not 32, `y >= p`, no square root / not on the curve, or the non-canonical `x = 0` with sign bit 1). |
| `E_SIG_NONCANONICAL_R` | invalid | The signature `R` does not pass the complete RFC 8032 §5.1.3 point decoding (the non-canonical `x = 0` with sign bit 1 included). |
| `E_SIG_SMALL_ORDER_A` | invalid | The decoded public key is small-order: `[8]A` is the identity. Includes the identity-key forgery. |
| `E_SIG_SMALL_ORDER_R` | invalid | The decoded signature `R` is small-order: `[8]R` is the identity. |
| `E_SIG_S_OUT_OF_RANGE` | invalid | The signature scalar `S` is not canonical (`S >= L`). |
| `E_SIG_MIXED_ORDER_A` | invalid | The public key decodes, is not small-order, but is not in the prime-order subgroup (`[L]A != identity`). Mixed-order public keys are rejected. |
| `E_SIG_UNVERIFIABLE` | unverifiable | A record that needs a per-record signature, or a manifest attestation, has a non-empty signature list, but no entry has both a known algorithm and a declared key, so no required signature can be checked. Unknown-algorithm entries are ignored; when no required signer key is declared anywhere in the verification context the code is `E_KEY_UNKNOWN` instead (specification §4.4 step 5, S2/F46). This applies to the seven signer-constrained kinds too: their dedicated signer code needs some verified known-algorithm signature. |
| `E_KIND_BODY_SCHEMA` | invalid | The body of a registered kind does not satisfy its registered schema; for the special `weave.erased` shape this code also covers every structural violation of the placeholder itself (missing/unknown member, wrong type, malformed `digest` or `attestation`), because `weave.erased` is not a normal envelope. |
| `E_KEY_PUBLIC_KEY` | invalid | A declaration's `public_key` is **missing**, or is not strict unpadded base64url of exactly 32 bytes. This is a **structural** error (specification §14.1, V5): such a declaration never governs a class; the missing-member case is decided before the generic `E_KIND_BODY_SCHEMA` and before any trust judgement (T1). In the keyset a file carrying it is a usage error (exit 2), not silently ignored. Point validity (canonical encoding, small order, subgroup membership) is not checked at declaration; those checks belong to signature verification and use `E_SIG_*`. |
| `E_KEY_ID_MISMATCH` | invalid | A declared key id is not the key-id derivation of its declared public key. |
| `E_KEY_CLASS_CONFLICT` | invalid | A `weave.key.declared` in a container or record target names a key id whose **governing class** — defined in specification §5.3 and determined before, and independently of, the trust closure from structurally valid declarations (keyset declaration first, otherwise smallest `(recorded_at, record digest)`) — differs from the declaration's `key_type` (S1, T4, U4). Same-class declarations are valid but do not override the governing class or validity window. (Conflicting keyset declarations for one key id are a usage error, not this code.) |
| `E_KEY_DECLARED_NOT_SELF_SIGNED` | invalid | A `weave.key.declared` record has no valid signature by the declared key. |
| `E_KEY_OWNER_MISSING` | invalid | A `weave.key.declared` record with `key_type` in `agent`, `program`, `device` has no `body.owner`, or the owner resolves but its declaration's class is not `human`/`organization`. |
| `E_KEY_DECLARED_NOT_COSIGNED` | invalid | An `agent`/`program`/`device` key declaration has no valid cosignature by the key named in `body.owner`. Human/organization declarations are never invalid for lack of a cosignature; when they cannot be chained to a trusted root they are `unverifiable` (`E_KEY_UNTRUSTED`). |
| `E_KEY_VALIDITY` | invalid | A key declaration's or a `weave.grant`'s validity window is inverted (`valid_from` > `valid_until`). Consent windows use `E_CONSENT_VALIDITY`; key rotation has no window. |
| `E_KEY_ROTATION_KEYS` | invalid | `weave.key.rotated` uses the same key as old and new, or a public-key value is malformed or contradicts its key id, or the required `new_public_key` is missing (decided before key resolution; `sigs` is `[]`, S2-FIX3 F74). |
| `E_KEY_ROTATION_SIGS` | invalid | `weave.key.rotated` is not signed by both the old and the new key. |
| `E_KEY_REVOKE_EFFECTIVE` | invalid | `weave.key.revoked.effective_at` is later than the revocation record's `recorded_at`. |
| `E_KEY_REVOKE_SIGNER` | invalid | A `weave.key.revoked` record lacks an acceptable signer (compromise requires a human/organization key; retired/other require the revoked key or a human/organization key). |
| `E_KEY_UNKNOWN` | unverifiable | A signature or actor names a key that is not declared anywhere in the verification context (container plus external keyset); the signature cannot be checked. Key resolution covers every `ed25519` entry before any equation, but an entry that fails its equation, or another entry's invalid §9.4 outcome, makes the record invalid instead: `E_KEY_UNKNOWN` is the record's code only when no entry is invalid (specification §14.5, S2; invalid first, S2-FIX1 T2); the same holds for the entries of a manifest signature, for a failed equation and for an invalid §9.4 outcome alike (§11.3, S2-FIX2 U5; the §9.4 half by decision 2026-11-15 #32). It is also the code of a `weave.key.declared` record whose owner cannot be resolved: an owner resolves only through a declaration that passes the §14.1 structural group (S2-FIX3 F73), and a declaration with another signature that does not pass supplies no material of any kind (S2-FIX3 F72). |
| `E_KEY_UNTRUSTED` | unverifiable | A `human`/`organization` declaration in a container or record target cannot be chained to a trusted root supplied by the local keyset (`--keys`): its key is not already trusted and it has no valid cosignature by a trusted human/organization key. Also used when an `agent`/`program`/`device` declaration's owner resolves but is not in the trusted set, also for a declaration signed only with unknown algorithms (it wins over the §4.4 step-5 `E_SIG_UNVERIFIABLE`, FIX1 R2). An untrusted declaration never invalidates other declarations and never becomes trusted; with no `--keys` input every container/target human/organization declaration is untrusted. |
| `E_KEY_EXPIRED` | invalid | A signature's claimed `recorded_at` is outside the signing key's declared validity window: later than `valid_until`, or earlier than `valid_from`. This includes the signatures of a `weave.key.declared` or `weave.key.rotated` record itself (§9.4, S2/F38). |
| `E_KEY_REVOKED` | invalid | A signature was made after a `retired`/`other` revocation's `effective_at` (claimed `recorded_at`; equality counts as revoked). The `retired`/`other` family and the `key-compromise` family are independent: when this code applies it is the record's outcome and **no timestamp evidence can rescue it**, even if a compromise revocation also exists (T2). |
| `E_KEY_COMPROMISED` | invalid | A signature by a `key-compromise`-revoked key cannot be rescued: either there is **no timestamp evidence at all** (single record target, no listed receipts, claimed level below L2), or verified trusted receipt evidence exists but none satisfies the strict `genTime + accuracy < T` bound. If receipts are present but none is verified, trusted and usable (for example no matching `--tsa-trust` anchor, or every receipt has an unusable accuracy per T3), the outcome is `unverifiable` with `E_TS_UNTRUSTED`, not this code. The claimed `recorded_at` is never evidence. |
| `E_GRANT_SCHEMA` | invalid | A `weave.grant` body does not match its registered schema (wrong action variant, missing/extra variant members, invalid lists, duplicate list elements). |
| `E_GRANT_GRANTER` | invalid | The granter is not permitted to issue this grant given the resolved context: the parent grant record is present but its own verdict is invalid (specification §5.5.2 step 1, first tier; likewise a record's cited grant, §5.4; S2-FIX2 U2), the resolved parent grant is not an authorising `weave.grant` covering kind `weave.grant`/action `grant`, its `grantee.key` is not the sub-granter's `actor.key`, the actor/signing-key class does not permit issuing a grant, or (for a `weave.grant` record with `action == "grant"` and non-empty `sigs`) the required granter signature is missing/wrong. An unresolvable parent is `E_GRANT_UNRESOLVED`. |
| `E_GRANT_NOT_TRANSFERABLE` | invalid | A delegated sub-grant cites a parent grant whose `transferable` is false. |
| `E_GRANT_DELEGATION_EXCEEDS` | invalid | A delegated sub-grant exceeds its parent: `kinds`, `actions` or `scope` is not a subset, or its validity window extends outside the parent's. |
| `E_GRANT_REVOKE_SIGNER` | invalid | A grant-revocation record is not signed by a key authorised to revoke: neither in the target grant's `grant.revocation` list (when present) nor the original granter's `actor.key` nor an explicit rotation successor of that key (a cycle in the key-id graph counts as no match). |
| `E_GRANT_REVOKE_REF` | invalid | A grant-revocation record's `revokes` reference does not resolve to a `weave.grant` record with matching digest. |
| `E_GRANT_UNRESOLVED` | unverifiable | A grant's parent, or a record's cited authorisation, cannot be resolved or checked in the verification context: absent, or present but not valid for a reason other than an invalid verdict (an invalid one is `E_GRANT_GRANTER`, S2-FIX2 U2) (including a chain deeper than the supported bound and a `program`/`device` grant record that cannot carry `actor.grant`). |
| `E_GRANT_REVOKED` | unverifiable | A record or grant cites an authorisation that was revoked at the evaluated time (`effective_at <= recorded_at`; equality counts as revoked). A revoked link anywhere in the chain gives this code even when a nearer link is outside its window (specification §5.5.2 step 6; S2-FIX6). |
| `E_GRANT_EXPIRED` | unverifiable | A record or grant cites an authorisation that is outside its validity window at the evaluated time (expired or not yet valid). |
| `E_GRANT_GRANTEE_MISMATCH` | invalid | A record's `actor.key` is not the `grantee.key` of the grant it cites for authorisation. |
| `E_GRANT_NOT_APPLICABLE` | invalid | A record's kind or stage action is not covered by its cited authorisation. |
| `E_CONSENT_VALIDITY` | invalid | A `weave.consent.granted` record has `valid_from` > `valid_until`. |
| `E_CONSENT_REVOKE_REF` | invalid | A `weave.consent.revoked` record's `revokes` reference does not resolve to a `weave.consent.granted` record. |
| `E_CONSENT_REVOKED` | invalid | A record cites a consent that has been revoked, and the record's claimed `recorded_at` is greater than or equal to the revocation's `effective_at` (equality counts as revoked). |
| `E_ERASE_ACTOR` | invalid | A `weave.erasure` record's actor may not execute an erasure: `human`/`organization` are always allowed; an `agent` requires a covering grant for kind `weave.erasure`/action `erase`; a `program`/`device` requires a resolving, valid `body.basis` grant covering the actor's key with action `erase`. An authorising grant record (the agent's `actor.grant`, the `body.basis`) that is **present but itself invalid** is `E_ERASE_ACTOR`; one that cannot be established — absent, present but not valid for another reason, outside its window, revoked or beyond the chain-depth bound — gives `E_GRANT_UNRESOLVED`, `E_GRANT_EXPIRED` or `E_GRANT_REVOKED` (unverifiable) (S2-FIX1 Q1); the window, revocation and chain of a program's or device's `body.basis` are judged at the erasure's `recorded_at` exactly as an agent's `actor.grant` (S2-FIX2 U1). |
| `E_ERASE_DIGEST_MISMATCH` | invalid | A `weave.erasure` record's `erased` reference does not match its target erased placeholder (`origin`, `id`, `digest`), or a placeholder's `digest` contradicts the attestation. The three §10.3 rules are evaluated independently and reported together (S2/F48). A valid erasure record whose erased identity has no placeholder that passes §4.5 (none, or only a malformed one) is this code, and so is an erasure record named by a placeholder whose own `origin`/`id` differ from its `erased` reference, whatever that record's verdict (S2-FIX3 F80, F82). |
| `E_ERASE_ATTESTATION` | invalid | An erased placeholder's `attestation` reference does not resolve to the corresponding `weave.erasure` record. A `weave.erasure` record that fails the §14.1 structural group (for example one whose `sigs` is absent) is not an erasure record for this check (S2-FIX3). |
| `E_ERASE_CONTRADICTION` | invalid | A container contains both a live record and an erased placeholder for the same `origin` + `id`, or two placeholders for the same target. |
| `E_LABEL_DOWNGRADE` | invalid | A derived record's sensitivity rank is lower than a resolved derivation input's rank (`derived_from`, `reshaped_from`, `migrated_from`, `correction_of`), or is absent while a resolved input ranks above `public`. |
| `E_LABEL_LOCAL_ONLY_EXPORTED` | invalid | A record carrying `labels.sensitivity = "local-only"` appears in an export container: every record whose envelope structure passes counts, whatever its verdict, a record whose `sigs` fail included (specification §8.5; FIX1). |
| `E_REF_KIND_MISMATCH` | invalid | A reference's claimed `kind` (or a link target's required kind) contradicts the resolved target's actual kind. A reference resolved to `erased` is not kind-checked. |
| `E_MANIFEST_MISSING` | invalid | The container has no `manifest.json`. |
| `E_MANIFEST_FORMAT` | invalid | `manifest.format` is not `"weave-record/1"`. |
| `E_MANIFEST_VERSION` | invalid | `manifest.manifest_version` is not a supported integer (H0: only `1`). |
| `E_MANIFEST_SCHEMA` | invalid | The manifest object or attestation file is not a closed object with the defined members and types. This includes a malformed `manifest.blobs` (specification §11.7 rule 1): not an array, more than `MAX_BLOBS` entries, an entry that is not a closed `{digest,size}` object, a digest without the digest-string grammar of §2.7 (uppercase hexadecimal digits included), or a size that is not a non-negative integer (S3 B1, B2). |
| `E_MANIFEST_DIGEST` | invalid | `signatures/manifest.sig.json.digest` does not equal the manifest digest computed per the specification. |
| `E_MANIFEST_UNSIGNED` | invalid | The attestation file `signatures/manifest.sig.json` is absent, or its `signatures` array is empty. A non-empty list with no verifiable required signature is `unverifiable` (`E_KEY_UNKNOWN` or `E_SIG_UNVERIFIABLE`). |
| `E_MANIFEST_SIG_INVALID` | invalid | A known-algorithm manifest signature does not verify against the manifest signature message. Unknown-algorithm entries are ignored. Every `ed25519` entry is judged: one entry of a required key that fails the equation decides this code even when another entry's key is undeclared, whatever the entry order (S2-FIX2 U5). |
| `E_MANIFEST_RECORDS` | invalid | `manifest.records` is not an array of 1–100000 well-formed entries, is not sorted by digest ascending, repeats a digest, or an entry's `id`/`kind` does not equal the record file's `id`/`kind`. |
| `E_MANIFEST_RECORD_MISSING` | invalid | A record listed in the manifest has no file in `records/`. |
| `E_MANIFEST_RECORD_EXTRA` | invalid | `records/` contains a file not listed in the manifest, or a malformed filename. |
| `E_MANIFEST_RECORD_DIGEST` | invalid | A record file's computed digest does not match its filename and/or manifest entry. |
| `E_MANIFEST_BLOB` | invalid | A well-formed `manifest.blobs` names a digest other than `sha256:<64 lowercase hex>` (an unsupported digest algorithm included) or is not strictly ascending by digest (a repeated digest included) (specification §11.7 rule 2); or `blobs/` contents and `manifest.blobs` disagree: a listed blob missing, a wrong digest or size, a blob above `MAX_BLOB_BYTES`, or an extra file — any file in `blobs/` or `blobs/sha256/` that is not a listed blob, whatever its name — or the blobs directory exists while no blobs are listed (absent or empty listing; in the zip form `blobs/` exists when a file entry lies in it, a zero-data directory entry does not count, FIX1; a zero-data entry such as `blobs/sha256` whose name does not end with `/` is a file and counts, with or without the DOS directory attribute, FIX2) (§11.7 rule 3; S3 B1, B3). |
| `E_MANIFEST_LEVEL` | invalid | `level` is not `L0`/`L1`/`L2`, or the level-specific completeness rules are violated (e.g. timestamps under L0/L1, non-null `chain` under L0). |
| `E_MANIFEST_L1_NO_HEAD` | invalid | The claimed level is `L1`/`L2` but `manifest.chain` is absent or null. |
| `E_MANIFEST_L1_NO_POSITION` | invalid | The claimed level is `L1`/`L2` but a `records[]` entry lacks a unique non-negative `chain_index`. |
| `E_MANIFEST_L2_NO_TIMESTAMP` | invalid | The claimed level is `L2` but the manifest attestation lists no RFC 3161 timestamp. |
| `E_MANIFEST_CHAIN` | invalid | `previous_manifest.digest` does not equal the digest of the embedded `previous/manifest.json`; or the embedded previous manifest's `origin` differs from the current manifest's `origin`; or `--previous` is supplied while `previous_manifest` is `null`; or the supplied `--previous` container's manifest is unreadable/invalid or its digest disagrees with the embedded manifest; or the supplied previous's manifest attestation does not verify **in the target container's verification context** — an `ed25519` entry by a key that is not a required key of the target context, that does not verify, that is not trusted in the target's final trust closure, or whose §9.4 validity window or revocation state at the previous manifest's `created_at` fails — a `retired`, `other` or `key-compromise` revocation fails iff `created_at >= T` (W1, X2; on this link a compromise is not judged by §9.4 case 3) — key material counting only from the keyset and from valid records (an invalid rotation record supplies none, X5); or the supplied previous zip violates a §11.9 rule 1–4 in any entry, read or not (W2). A missing or unopenable `--previous` path is a usage/I/O error (exit 2). |
| `E_MANIFEST_CHAIN_MISSING` | invalid | `previous_manifest` is non-null but `previous/manifest.json` is absent. |
| `E_MANIFEST_CHAIN_UNEXPECTED` | invalid | `previous_manifest` is null but `previous/` contains a manifest. |
| `E_CONTAINER_ENTRY` | invalid | The container contains an entry outside the allowed layout, a path that escapes the root, a duplicate entry name, a symlink or other unsupported entry type, or an unknown file in `signatures/`/`previous/`. A file below a directory inside `blobs/` other than `blobs/sha256/`, or below a directory inside `blobs/sha256/`, is outside the layout in the directory and the zip form alike; a misnamed file directly in `blobs/` or `blobs/sha256/` is `E_MANIFEST_BLOB` instead (S3 B4). A zero-data directory entry of the zip form — a name ending `/` — is ignored for the layout (specification §11.9 rule 4: a zip whose only extra entry is `foo/` or `blobs/sha512/` is not outside the layout; a zero-data entry `foo` is a file outside the layout even with the DOS directory attribute, FIX2), but its path, its type and its name are checked like every entry's: `../x/` or `/abs/` is this code (FIX1). These checks also apply to `readable/` entries, even though they are never decompressed or CRC-checked (T6). An entry outside the layout and a member that then fails as it is read are independent violations of container step (1) and are reported together with `E_CONTAINER_ZIP` (S2-FIX3 F75); a root file `Manifest.json` is not `manifest.json` (names compare exactly, F78). |
| `E_CONTAINER_SIZE` | invalid | Entry count or uncompressed total bytes exceed the container limits (zip-bomb protection). In the zip form this is phase 3 of the §11.9 check order: it is reported only when the end-of-central-directory record was located and the central directory parsed, and it wins over every remaining structural rule (W7). |
| `E_CONTAINER_ZIP` | invalid | The zip cannot be read as a zip (corrupt archive, unsupported compression, encrypted entries), or a structural zip rule of specification §11.9 is violated: bytes before the first local file header or after the end-of-central-directory record; a non-empty archive comment; a gap, pad byte or overlap between entries or before the central directory; a local file header that disagrees with the central directory on name, flags, method, CRC or sizes (or, with a data descriptor, descriptor values that disagree); an EOCD or ZIP64 EOCD entry count or central-directory size/offset that disagrees with the parsed values; a disk-number field in the EOCD, ZIP64 EOCD or ZIP64 locator that is not that of a single-volume archive (including a locator total-disk count other than 1, and any per-entry central-directory "disk number start" other than 0); a central-directory "version needed to extract" above 63 (the local-header version field is unconstrained); an entry whose name ends with `/` but carries data, or an entry with the DOS directory attribute carrying data (an entry carries data when its compressed or uncompressed size is not zero, so a deflated empty member with the attribute is this code; without data the attribute does not make a directory entry, FIX2). ZIP64 archives are accepted and are not an error by themselves. |
| `E_TS_FILE` | invalid | A listed timestamp receipt file is missing or does not hash to the listed digest, or a `.tsr` file in `signatures/` is not listed (whatever the claimed level, S2/F54). |
| `E_TS_SCHEMA` | invalid | A receipt is not strict, canonical DER, or its structure is invalid: not exactly one `TimeStampResp` (trailing data), non-minimal length forms, a universal DER rule violated anywhere in the file (including inside values of unknown type; the §12.2 1a rules by universal tag number, among them the escape-sequence rules of the string types and the rejection of TIME, DURATION, DATE, TIME-OF-DAY, DATE-TIME, OID-IRI and RELATIVE-OID-IRI values, S2-FIX1 T3, S2-FIX2 U4), re-encoding the parsed object differs from the input — in particular any SET OF at any level not in DER order (`digestAlgorithms`, `certificates`, `crls`, `signedAttrs`, `unsignedAttrs`, `attrValues`, RDNs) or a component equal to its DEFAULT encoded, judged by the DEFAULT encodings of the module definitions listed in §12.2 1c (W3, X1), or signer `digestAlgorithm`/`signatureAlgorithm` parameters outside the form fixed per algorithm in §12.2 1c (X6, X7), or a UTCTime/GeneralizedTime whose whole content is not in its DER form (a trailing line feed included, X7) — `SignedData.version` not 3, not exactly one `SignerInfo` (X7), a `SignerInfo.version` not in {1, 3} or not matching its `sid` (RFC 5652 §5.3, X7), a signer certificate that does not decode (X7: only the signer certificate is decoded), a DER decoding failure **anywhere** in receipt processing — these are all check 1's code, decided before any later check (V2, W3, W6). Also: `PKIStatus` not `granted`, wrong content type, TSTInfo version not 1, `messageImprint`/`signerInfo` hash algorithm not sha256, an invalid `genTime`, or a malformed `accuracy` component — a present `milliseconds`/`microseconds` outside 1–999 (an explicit `0` included), or a negative/non-integer component. An accuracy total above `MAX_TS_ACCURACY` or a conversion overflow is **not** this code: it makes the receipt unusable evidence (`E_TS_UNTRUSTED`, container unverifiable). |
| `E_TS_IMPRINT` | invalid | The token's `messageImprint.hashedMessage` does not equal the expected imprint (the raw 32-byte manifest digest for the first receipt, or `SHA-256(previous receipt bytes ‖ raw manifest digest)` for a renewal receipt). |
| `E_TS_CMS` | invalid | The token's CMS evidence fails: the token carries no `signerInfo`, the signer certificate is not carried in the token, the signed attributes are absent or lack the content-type/`messageDigest` attributes, the ESS `signingCertificateV2` attribute is missing or mismatched, the signed attributes' `messageDigest` is wrong, or the CMS signature does not verify — including a signer public key that the allowlisted algorithm cannot use (W6), an RSA modulus outside 2,048–8,192 bits or a public exponent that is even, below 65,537 or at least 2^256, and an ECDSA `Ecdsa-Sig-Value` that is not a DER SEQUENCE of two shortest positive INTEGERs `r`, `s` in [1, n − 1] with no trailing octets (S2-FIX1 Q4). |
| `E_TS_CERT` | invalid | The signer certificate or the signature algorithm identifier is unacceptable: a signature algorithm outside the allowlist (RSA PKCS#1 v1.5 with SHA-256/384/512 or ECDSA with SHA-256/384), missing `id-kp-timeStamping` EKU, KeyUsage without `digitalSignature` when the extension is present, or a validity window that does not contain `genTime`. |
| `E_TS_UNTRUSTED` | unverifiable | No trust anchor was supplied that matches the timestamp signer's leaf certificate, so the receipt is reported `present-unverified`; the container must not be reported `valid`. The same code and state apply when the receipt's accuracy is **unusable evidence**: the converted `accuracy` total exceeds `MAX_TS_ACCURACY` or the conversion overflows (T3). Such a receipt cannot support an L2 claim (the container is unverifiable) and cannot rescue; a signature by a `key-compromise`-revoked key with only such receipts is `unverifiable` (missing usable information), never `E_KEY_COMPROMISED`. |
| `E_TS_RENEWAL` | invalid | The timestamp receipts do not form exactly one renewal chain: no receipt with `renews == null`, a `renews` link that is dangling or not earlier in the chain, duplicate paths or digests, more than one chain, or a receipt listed out of chain order. |

## Notices (`N_*`, non-fatal unless stated)

| Code | Condition |
|---|---|
| `N_KIND_UNKNOWN_OPAQUE` | The record's kind is well-formed but not registered and the record's final verdict is `valid`; the body was not interpreted (must never be treated as understood). `kind_known` is `false` for unregistered kinds regardless of the verdict (F12 item 3). |
| `N_KEY_UNDECLARED` | A signing key has no declaration in the verification context; the signature could not be checked (paired with `E_KEY_UNKNOWN` when it makes the unit unverifiable). |
| `N_KEY_TOFU` | Per-record form of the TOFU predicate (specification §14.9): at least one of this record's signature checks was context-trusted — the verifying key material came from a context `weave.key.declared` declaration **or** from the explicit `old_public_key`/`new_public_key` of a context `weave.key.rotated` record, rather than from the local keyset — even if that signature or the record later fails. For the three key-lifecycle kinds only the actor-key signature counts. The manifest signature never produces this notice (it contributes to `L_KEY_TRUST_TOFU`) (T10, U6). |
| `N_SELF_ATTESTED_ROOT_KEY` | A `human`/`organization` declaration in a container or record target is self-signed only and cannot be chained to a trusted root supplied by the local keyset; it is `unverifiable` (`E_KEY_UNTRUSTED`) and is never a root. Keyset declarations never produce this notice. |
| `N_NO_HUMAN_SIGNATURE` | An `accepted` record whose verdict is `valid` has no valid signature made by a key declared `human` in the verification context. The notice is not reported on a record made `unverifiable` by the required-signature check or invalid for another reason (F6). |
| `N_REF_MISSING` | A reference resolved to `missing`. |
| `N_REF_MOVED` | A reference resolved to `moved` (the object was located through hints with a matching digest). An offline verifier without hint resolution never emits this. |
| `N_REF_UNVERIFIABLE` | A reference resolved to `unverifiable` (target present but not valid, digest mismatch, unsupported digest algorithm, or an undecidable non-digest dependency). |
| `N_LABEL_PROPAGATION_UNCHECKED` | A derivation reference could not be resolved, so strictest-label propagation could not be checked. Not reported for a record that fails another check of step (9) (S2-FIX1 Q3). |
| `N_CHAIN_CLAIM_UNVERIFIED` | An L1/L2 chain head is an internal-chain claim that an offline verifier cannot recompute; `level_verified` is reported as `L0`. |
| `N_CONSENT_UNRESOLVED` | `labels.consent` is a reference that could not be resolved. |
| `N_PREVIOUS_SIG_UNVERIFIED` | The embedded previous manifest's own signature was not re-verified; reported if and only if `previous_manifest` is non-null and the signature was not re-verified, including when a later container check fails. Not reported when the manifest cannot be parsed and the previous manifest is not reachable; also not reported when a supplied `--previous` container's manifest signature verifies, because that previous manifest's signature then counts as re-verified (`L_PREVIOUS_CONTENT_UNVERIFIED` is reported instead) (T12, V3). |
| `N_IDEMPOTENCY_DUPLICATE` | A container contains two records with the same `origin` and `actor.idempotency_key` (claimed as the same action). Nothing else is compared (not `actor.key`), and every record whose envelope structure passes takes part, whatever its verdict, a record whose `sigs` fail included (specification §5.4; FIX1 R1). |
| `N_READABLE_PRESENT` | The container has a `readable/` view; it is unsigned and was not used. Reported if and only if an enumerated container contains a `readable/` entry, including when a later container check fails; not reported when entry enumeration fails before the entry is observed (T12), in particular when the archive fails in phases 1–4 of the §11.9 zip check order (no entry is enumerated, S2-FIX1); reported when a member fails after the entries were enumerated (CRC-32, decompression, the actual-size total; S2-FIX2 U7); reported when a `readable/` entry passed its own entry checks while another entry fails them, before or after it in the central directory (the order does not matter, S3-FIX2 N2); a regular file named `readable` at the root is not a `readable/` entry (`E_CONTAINER_ENTRY`, S2-FIX1 T8). |

## Limitation identifiers (`L_*`, closed list, report `limitations` only)

`limitations` in a report is a sorted, unique array of these identifiers and nothing else.
The full emission conditions are in specification §14.9; no free prose is permitted (S12).

| Identifier | Meaning |
|---|---|
| `L_OFFLINE_CONTEXT` | The verification context is the container/target plus the supplied keyset; references to records outside it resolve as `missing`. Always emitted for record and container targets. |
| `L_CHAIN_CLAIM_UNVERIFIED` | A claimed L1/L2 internal chain cannot be recomputed offline; `level_verified` is `L0`. |
| `L_KEY_TRUST_TOFU` | At least one signature check in the report — a record signature, the manifest signature, or a supplied previous container's manifest signature (W1) — was context-trusted per the TOFU predicate of specification §14.9 (declared or rotated context key material; U6). |
| `L_PREVIOUS_CONTENT_UNVERIFIED` | One criterion (W5): `--previous` was supplied, the previous-manifest-chain stage ran, and the supplied previous's manifest signature verified in the target container's verification context (W1); the rest of the previous container's content was not verified. Reported whether or not a later check of that stage then fails; not reported when no previous was supplied, when the container pipeline stopped before that stage, or when the previous could not be read/verified (V3, W5). |
| `L_PREVIOUS_SIG_UNVERIFIED` | An embedded previous manifest exists and its own signature was not re-verified. When a supplied `--previous` container's manifest signature verifies, that previous manifest's signature counts as re-verified, so this identifier is not reported for it (`L_PREVIOUS_CONTENT_UNVERIFIED` is reported instead) (V3). |
| `L_TSA_TRUST_UNVERIFIED` | At least one listed receipt is `present-unverified`: its structure and CMS signature pass but it is not verified-and-trusted (no matching anchor, or its accuracy is unusable evidence). A receipt rejected by a structural, format or CMS check reports its error code and does not by itself trigger this identifier (U7). |
| `L_ERASED_PLACEHOLDER` | The verified input contains a `weave.erased` placeholder (for a container: among the records that are verified; not reported when the pipeline stops before the per-record checks). A record whose `kind` is `weave.erased` counts, whether or not it passes §4.5 (S2-FIX3 F78). |
| `L_ERASED_STANDALONE` | A standalone placeholder was verified with no container context, so the erasure cross-checks could not be applied. A record whose `kind` is `weave.erased` counts, whether or not it passes §4.5 (S2-FIX3 F78). |
| `L_LABELS_ARE_CLAIMS` | Labels, consent coverage or licence claims were checked for consistency only. Emitted for a record (target, or verified record of a container) that is a JSON object with a top-level `labels` member, whether or not its envelope passes (S2-FIX3 F78). |
| `L_UNKNOWN_KIND_OPAQUE` | An unregistered kind body was transported but not interpreted, and the record's verdict is `valid`. |
| `L_LABEL_PROPAGATION_UNCHECKED` | A derivation reference could not be resolved, so strictest-label propagation could not be checked. |
