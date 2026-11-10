<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Open questions and provisional choices

> **Status: `DRAFT`.** This file records the gaps that the `weave-record/1` decision draft
> (`DECISIONS.md` v0.1 + correction v0.1.1) leaves open, the most conservative choice H0
> made for each, and the choice's rationale. H0 must not silently settle decisions that
> belong to the founder: every item below is marked `PROVISIONAL` in the normative spec
> (`spec/weave-record-1.md`) and is listed here with a recommendation.
>
> Where an item is a format rule, the H0 reference verifier and the test vectors implement
> the provisional choice. Changing a choice after v0.1 requires a new decision (`K4`), and
> — for anything observable on the wire — new test vectors plus a new frozen regression set;
> the existing frozen vectors (`vectors/frozen/v0.1/`) must keep their conclusions forever
> (`K3`).

## 1. Format gaps filled provisionally in H0

### Q1. Ed25519 verification profile

- **Question.** Which exact verification rules must every implementation share, so that two
  independent verifiers reach byte-identical conclusions? RFC 8032 permits cofactored and
  cofactorless verification; libraries differ on small-order keys.
- **H0 choice.** PureEdDSA, single-message, no context, **strict**: canonical point
  encodings for `R` and `A` (`y < 2^255−19`), the eight small-order points rejected for
  both `A` and `R`, `S < L`, cofactorless equation `[S]B = R + [k]A`, no batch
  verification. The identity-key forgery (identity public key, `R = identity`, `S = 0`) is
  rejected — OpenSSL's raw verifier accepts it, so the pre-checks are mandatory.
- **Recommendation.** Keep. Cross-implementation agreement is the whole point of the
  vectors (`I4`); "strictest" is the only profile that can be tested identically everywhere.
  Consequence for the external cross-check: Wycheproof's `acceptable` class is resolved
  per case — small-order public keys/`R` are rejected, mixed-order public keys are accepted
  because the exact cofactorless equation verifies and the key id commits to those bytes.
  Subgroup-membership (`[L]A == identity`) is deliberately not part of the profile: honest
  keys are prime-order, RFC 8032 does not require the check, and it would add a scalar
  multiplication to every verifier for a case Wycheproof itself marks "acceptable". The
  per-case table is in `vectors/external/wycheproof/PROVENANCE.md` and is checked by
  `tools/check_external.py`.
- **Affects.** `spec/weave-record-1.md` §signatures; `vectors/sig/`; `vectors/external/`;
  `verifiers/python`.

### Q2. base64url encoding

- **Question.** Is padding allowed, and how strict is decoding?
- **H0 choice.** Unpadded base64url (RFC 4648 §5), no `=`, strict decoding: reject
  whitespace/`+`/`/`, reject non-zero unused trailing bits. Fixed lengths per field
  (16 bytes salt, 32 bytes public key, 64 bytes signature).
- **Recommendation.** Keep. Padding variants and non-zero trailing bits are the classic
  source of "same signature, different bytes" disagreement; rejecting them is cheap.
- **Affects.** `spec/weave-record-1.md` §encodings; `vectors/jcs/`, `vectors/sig/`.

### Q3. `salt` encoding, length and obligation

- **Question.** What exactly must `salt` be, and when is it required?
- **H0 choice.** Exactly 16 random bytes, unpadded base64url (22 chars), **required** when
  `labels.sensitivity` is `personal` or `local-only`, optional otherwise, participates in
  the record digest like any other field (`G3c`). A verifier can check encoding and length,
  never randomness.
- **Recommendation.** Keep. The salt's only job is to make an erased record's digest
  non-enumerable; 16 bytes of CSPRNG output is the smallest conventional choice.
- **Affects.** `spec/weave-record-1.md` §envelope/§erasure; `vectors/labels/`,
  `vectors/erasure/`.

### Q4. Unicode normalization

- **Question.** Are strings normalized (NFC/NFKC) before comparison, signing or label
  checks?
- **H0 choice.** No normalization anywhere. Strings are compared as Unicode scalar values;
  JCS/WR-CJ emit literal UTF-8; a lone surrogate escape is invalid.
- **Recommendation.** Keep. Normalization depends on Unicode-versioned tables; applying it
  silently changes the bytes a person signed, and two implementations on different Unicode
  versions would disagree. Byte-level identity is the decades-long property (`C1`, `C5`).
- **Affects.** `spec/weave-record-1.md` §canonical JSON; `vectors/jcs/`.

### Q5. Size limits

- **Question.** The decision draft says nothing about maximum sizes; a format without limits
  invites resource-exhaustion bugs.
- **H0 choice.** Record ≤ 1 MiB; manifest ≤ 4 MiB; signature/timestamp file ≤ 1 MiB;
  ≤100,000 records per container; ≤200,000 container entries; ≤1 GiB uncompressed container
  bytes; ≤10,000 blobs; ≤256 refs; ≤16 sigs; ≤8 hints per ref. Violations are hard errors
  (fail closed; `E_JSON_SIZE`/`E_CONTAINER_SIZE`), checked before/while reading.
- **Recommendation.** Keep, then revisit after the J1/J2 round-trips produce real data; if
  any project legitimately exceeds a limit, raise the number in a patch (the vectors only
  assert the boundary behavior, not the exact magnitude).
- **Affects.** `spec/weave-record-1.md` §limits; `vectors/jcs/`, `vectors/container/`.

### Q6. Timestamp grammar and leap seconds

- **Question.** Exact syntax of time fields; how are leap seconds represented?
- **H0 choice.** RFC 3339, UTC only, millisecond precision, exactly three fractional digits,
  trailing `Z`, seconds `00`–`59`. A leap second (`:60`) is invalid; the event is attributed
  to the following second. Times are claims (`F1`, `F2`), never trusted.
- **Recommendation.** Keep. `:60` appears in reality only twice a year and no current
  producer emits it here; rejecting is safer than an untestable mapping rule. A future
  decision can add an explicit leap-second rule if the J1/J2 round-trips ever need it.
- **Affects.** `spec/weave-record-1.md` §envelope; `vectors/actor/`, `vectors/container/`.

### Q7. `refs[].rel` closed vocabulary

- **Question.** Which relation words are in the closed vocabulary? The decision says "closed
  vocabulary, based on Inceptless's `provenance_edge`".
- **H0 choice.** The eight Inceptless relations (`derived_from`, `handed_off_to`,
  `receipt_of`, `executed_as`, `assessed_by`, `compensated_by`, `migrated_from`,
  `reshaped_from`) plus four needed by this format's own rules: `supersedes`,
  `correction_of`, `erases`, `revokes`.
- **Recommendation.** Keep minimal. Any project needing another word must propose it (`K4`)
  with the semantics and a vector; a generic `references` catch-all is deliberately not
  included, because a generic word is not machine-readable.
- **Affects.** `spec/weave-record-1.md` §references; `vectors/ref/`, `vectors/erasure/`.

### Q8. Manifest field set and manifest signature placement

- **Question.** `D1`/`I2` mandate a manifest digest, a previous-manifest digest and a
  manifest signature, but not the exact JSON shape.
- **H0 choice.** `manifest.json` is pure data (`format`, `manifest_version`, `origin`,
  `created_at`, `level`, `records`, `previous_manifest`, `chain`, optional `blobs`) and never
  contains its own digest. The digest and signatures live in
  `signatures/manifest.sig.json`; the manifest digest uses its own domain prefix
  (`weave-record/1/manifest-digest\n`); the previous container's exact `manifest.json` bytes
  are embedded at `previous/manifest.json` so the chain is offline-checkable.
- **Recommendation.** Keep. It keeps the digest constructive from a plain file (no
  self-reference, no JSON surgery) which is what makes the offline L0 procedure possible
  with `sha256sum` alone (`I4`, `offline-verification.md`).
- **Affects.** `spec/weave-record-1.md` §container; `schemas/manifest.json`;
  `vectors/container/`, `vectors/integrity-levels/`.

### Q9. L1 chain head cannot be re-verified offline

- **Question.** `A1c` requires L1 to add the internal hash-chain head and each record's
  position, but an exporter cannot export the internal chain preimages (they use each
  project's own framing, `A2`).
- **H0 choice.** The verifier checks that the L1/L2 claim is structurally complete (head
  present, every record has a unique `chain_index`) and reports
  `chain.status = "unverified"`, `level_verified = "L0"`, notice `N_CHAIN_CLAIM_UNVERIFIED`.
  It must never claim the internal chain was verified.
- **Recommendation.** Keep honest labeling for v0.1; consider an additive export of chain
  links in a later milestone (it would let third parties verify L1 offline, at a cost each
  project pays in its adapter). This is a founder decision.
- **Affects.** `spec/weave-record-1.md` §integrity-levels; `vectors/integrity-levels/`.

### Q10. Grant revocation shape and delegation

- **Question.** The H0 kind list names eight `weave.*` kinds and does not include a
  `weave.grant.revoked`; `§8.2` says grants are issued by a person's or organization's key,
  while the required vector "sub-grant of a non-transferable grant" implies sub-grants.
- **H0 choice.** Revocation is a `weave.grant` record with `action: "revoke"` (one registered
  kind, two action variants). Root grants are signed by `human`/`organization` actors.
  A grant signed by an `agent`/`program`/`device` actor is a delegated sub-grant and needs a
  parent grant with `transferable: true` that covers kind `weave.grant` and action `grant`;
  the sub-grant must stay within the parent's kinds and validity window.
- **Recommendation.** Keep for v0.2 review: if the Axioweave adapter (J2) prefers a separate
  kind, add `weave.grant.revoked` then (additive, K3) rather than reshaping `weave.grant`.
  The delegation interpretation is the narrowest reading that makes §8.2 and §8.5 coexist.
- **Affects.** `spec/kinds/weave.grant.md`; `vectors/grant/`; `verifiers/python`.

### Q11. Verdict semantics for authorization failures

- **Question.** When an agent's authorization is missing, expired, revoked, or too narrow, is
  the record `invalid` or `unverifiable`?
- **H0 choice.** Envelope-level absence → `invalid` (`E_ENV_ACTOR_GRANT_MISSING`); grantee/
  kind/action mismatch → `invalid` (the agent exceeded its explicit authority); authorization
  that cannot be checked or no longer holds at the claimed time (unresolvable, revoked,
  expired) → `unverifiable` (`E_GRANT_UNRESOLVED`/`E_GRANT_REVOKED`/`E_GRANT_EXPIRED`),
  mirroring §8.5's explicit rule for revocation.
- **Recommendation.** Keep. `unverifiable` is the honest verdict for "I cannot tell"; it
  still refuses `valid`, so it cannot be used to smuggle unauthorized records through.
- **Affects.** `spec/weave-record-1.md` §agent rules; `vectors/stage/`, `vectors/grant/`.

### Q12. Key trust model (TOFU) and undeclared keys

- **Question.** How can an offline verifier obtain public keys, and what does it do when a
  signature names a key it has never seen?
- **H0 choice.** TOFU: a valid `weave.key.declared` record in the container or an external
  keyset supplies the key; no CA, no network. An undeclared key makes the affected signature
  unverifiable (`E_KEY_UNKNOWN` + `N_KEY_UNDECLARED`), and therefore the unit
  `unverifiable`, never `valid`. A local pinning/trust store remains an implementation
  concern outside the H0 verifier.
- **Recommendation.** Keep; note in the spec that a "declared key" is a claim, and that
  TOFU is a usability/security trade the founder accepted in `E4`.
- **Affects.** `spec/weave-record-1.md` §signatures/§keys; all signatures vectors.

### Q13. Unknown digest algorithms

- **Question.** `B3` says the algorithm name is the agility interface; what if a reference
  carries `sha3-256:…` before any implementation supports it?
- **H0 choice.** Structurally valid; resolution state `unverifiable` (not an error of the
  record), and a manifest listing an unsupported digest algorithm is invalid
  (`E_MANIFEST_RECORDS`) because the manifest's own integrity depends on it.
- **Recommendation.** Keep. A verifier must be able to say "not understood, not verified",
  and must not break forward compatibility (`K3`) by rejecting documents merely because a
  newer algorithm name appears.
- **Affects.** `spec/weave-record-1.md` §digests/§references; `vectors/ref/`.

### Q14. SPDX license expression checking

- **Question.** How much SPDX validation is required offline?
- **H0 choice.** Syntax only (identifiers `[A-Za-z0-9.+-]+`, `AND`/`OR`/`WITH`,
  parentheses, `+` suffix). License-list membership needs the SPDX list; the verifier is
  offline and version-pinned, so membership is not checked.
- **Recommendation.** Keep; if the founder wants list membership checked, ship the SPDX
  license list as versioned data in a later milestone (additive; old verifiers continue to
  work).
- **Affects.** `spec/weave-record-1.md` §labels; `vectors/labels/`.

### Q15. `weave.erased` is not an envelope

- **Question.** `§7` gives the erased replacement shape explicitly, and it has no
  `stage`/`actor`/`sigs`. Is it an envelope record or a special document?
- **H0 choice.** A special document, exactly the shape `§7` writes. Its own record digest is
  computed like any record (no sigs to remove); its `digest` field carries the **original**
  record digest. Verdict `erased`; integrity rests on the attestation record, the original
  digest, and the container's manifest/chain position (`G3b`).
- **Recommendation.** Keep exactly as decided; do not add envelope fields to it.
- **Affects.** `spec/kinds/weave.erased.md`; `schemas/kinds/weave.erased.json`;
  `vectors/erasure/`.

### Q16. Label propagation when a derived record has no labels

- **Question.** `H2` says a derived record's sensitivity must not be lower than any input.
  Does an absent `labels.sensitivity` count as `public` (0) or as unknown?
- **H0 choice.** As a downgrade error (`E_LABEL_DOWNGRADE`) whenever a resolved
  `derived_from` input ranks above `public`: absence cannot prove "not lower". If all
  resolved inputs are `public` (or there are none), absence is fine.
- **Recommendation.** Keep (conservative). The alternative would let a careless exporter
  drop personal data by omitting a field.
- **Affects.** `spec/weave-record-1.md` §labels; `vectors/labels/`.

### Q17. Idempotency-key duplicates

- **Question.** `§2` says records with the same origin and idempotency key are the same
  action. Should a container containing both be invalid?
- **H0 choice.** Notice `N_IDEMPOTENCY_DUPLICATE`, not an error. Duplicate *content* would
  already collapse into one digest; two different records claiming the same action key is an
  advisory inconsistency, not proof of tampering.
- **Recommendation.** Keep as a notice until the founder defines dedupe semantics for
  importers (that is an adapter concern, `A1a`).
- **Affects.** `spec/weave-record-1.md` §envelope; `vectors/container/`.

### Q18. Test-only check-disable hook in the reference verifier

- **Question.** H0 gate 3 requires proving that vectors test each check class; that needs a
  controlled way to disable one check family.
- **H0 choice.** `WEAVE_VERIFY_SKIP_CHECKS` (comma-separated error codes), honoured only by
  the Python reference verifier, echoed in `report.checks_disabled`, documented as
  test-only. It is not part of the format and MUST NOT be used to claim verification.
- **Recommendation.** Keep in the reference implementation; do not add it to the conformance
  surface for third-party verifiers.
- **Affects.** `verifiers/python/`; `tools/anti_verification.py`; delivery report.

### Q19. `readable/` handling

- **Question.** `I1` says `readable/` is an optional human view and does not participate in
  the digest. Does a verifier ignore it entirely?
- **H0 choice.** Yes: ignored, unhashed, never trusted; its presence gets the informational
  notice `N_READABLE_PRESENT`. An exporter must not put anything machine-significant there.
- **Recommendation.** Keep.
- **Affects.** `spec/weave-record-1.md` §container; `vectors/container/`.

### Q20. `valid_until` on key declarations

- **Question.** `E5` defines declared/rotated/revoked but does not mention declared key
  validity windows; the envelope needs a rule if a declaration carries one.
- **H0 choice.** Optional `valid_from`/`valid_until` on `weave.key.declared`; a signature
  made (claimed `recorded_at`) after `valid_until` is `E_KEY_EXPIRED` (invalid).
- **Recommendation.** Keep; if this proves unnecessary in practice (rotation + revocation
  cover it), deprecate the fields additively rather than removing them.
- **Affects.** `spec/kinds/weave.key.declared.md`; `vectors/key-lifecycle/`.

### Q21. `signatures/manifest.sig.json` `timestamps` member

- **Question.** Must the attestation file always carry a `timestamps` array, or may the
  member be absent for L0/L1?
- **H0 choice.** Required member; MAY be an empty array for L0/L1 and MUST be non-empty for
  L2. Closed-object treatment avoids a hidden "absent vs empty" distinction in a signed
  file.
- **Recommendation.** Keep; revisit only if a future level changes the attestation shape.
- **Affects.** `spec/weave-record-1.md` §11.3; `schemas/manifest.json`.

### Q22. `manifest.records[]` metadata vs record content

- **Question.** Are the manifest's `id`/`kind` per record merely hints, or claims that must
  match the record bytes?
- **H0 choice.** They MUST equal the listed record's actual `id` and `kind`; a mismatch is
  `E_MANIFEST_RECORDS` (invalid). The manifest is signed evidence, so metadata contradicting
  the record it lists is an inconsistency, not a hint.
- **Recommendation.** Keep; a manifest that only listed digests would lose searchability and
  the contradiction would stay undetectable.
- **Affects.** `spec/weave-record-1.md` §11.2; verifier container checks.

### Q23. Blob digest algorithms and errors

- **Question.** Which digest algorithms may `manifest.blobs` use, and which code covers
  problems?
- **H0 choice.** Only `sha256` (the path is `blobs/sha256/<hex>`); an unsupported algorithm,
  a size mismatch or set mismatch is `E_MANIFEST_BLOB` (invalid).
- **Recommendation.** Keep; blobs are content-addressed attachments with no need for
  agility in H0.
- **Affects.** `spec/weave-record-1.md` §11.7; `vectors/container/`.

### Q24. Error-code mapping for size limits

- **Question.** The decision draft mentions size limits but not which code fires.
- **H0 choice.** Settled by the closed registry: single-file JSON limit → `E_JSON_SIZE`;
  container aggregate → `E_CONTAINER_SIZE`; record count → `E_MANIFEST_RECORDS`; blob limits
  → `E_MANIFEST_BLOB`/`E_MANIFEST_SCHEMA`; oversized zip streams → `E_CONTAINER_SIZE`.
- **Recommendation.** Keep (deterministic negative vectors need one fixed mapping).
- **Affects.** `spec/error-codes.md`; `vectors/jcs/`, `vectors/container/`.

### Q25. Error-code split for zip violations

- **Question.** One `E_CONTAINER_*` code for every zip problem, or a split?
- **H0 choice.** Split by nature: path escapes, duplicate entry names, symlinks, unsupported
  entry types and unknown files in `signatures/`/`previous/` → `E_CONTAINER_ENTRY`;
  corrupt archive, unsupported compression or encryption → `E_CONTAINER_ZIP`; content layout
  → `E_MANIFEST_*`.
- **Recommendation.** Keep; a nested vector that is refused for the wrong reason is a test
  failure (H0 prompt rule 4).
- **Affects.** `spec/error-codes.md`; `vectors/container/`.

### Q26. Evaluation model for cross-record dependencies and cycles

- **Question.** Records reference each other (key declarations, grants, consents, erasure
  attestations, label propagation). How must a verifier evaluate them deterministically
  without loops?
- **H0 choice.** Evaluate dependencies in a deterministic order with memoisation; a cycle
  that prevents deciding a condition makes the dependent unit `unverifiable` with
  `N_REF_UNVERIFIABLE` (never `valid`, never a crash).
- **Recommendation.** Keep; H0 containers are small, so the memoised traversal is enough,
  and a future revision can define an explicit partial order if adapters need one.
- **Affects.** `spec/weave-record-1.md` §6.4/§14.5; verifier.

### Q27. Report `input` for directory containers; `vectors` target report shape

- **Question.** A directory has no single content digest; what identifies the input in a
  deterministic report? How are per-case results shaped?
- **H0 choice.** Directory container: `input.sha256` = manifest digest, `input.size` =
  manifest byte size (the manifest is the container's content-addressed identity); zip:
  hash/size of the archive. The `vectors` target's report shape is
  implementation-defined but deterministic and path-free. The H1 independence requirement
  concerns record/container verification, not the test-runner report.
- **Recommendation.** Keep; if H1 needs a byte-identical `vectors` report, define a
  `vectors-report/1` shape in a patch.
- **Affects.** `spec/weave-record-1.md` §14.6.

### Q28. Agent-only envelope members on key-lifecycle records

- **Question.** `actor.type == "agent"` normally requires `model`, `on_behalf_of`, `grant`
  and `idempotency_key`. But `weave.key.declared` requires `actor.type == body.key_type`,
  so an agent-class key declaring itself could never satisfy both.
- **H0 choice.** The four agent-only members are not required for `weave.key.declared`,
  `weave.key.rotated` and `weave.key.revoked`: those records describe keys, they are not
  delegated actions. Delegated `weave.grant` and all other agent records keep the full
  obligations. This was found during H0 integration and is marked PROVISIONAL because it
  refines `§8`'s universal phrasing.
- **Recommendation.** Keep; a self-declared agent key is the only way TOFU can bootstrap an
  agent identity offline.
- **Affects.** `spec/weave-record-1.md` §4.2/§5.1; `schemas/envelope.json`; verifier.

### Q29. `labels` present without `sensitivity`

- **Question.** Is `labels.sensitivity` required whenever the `labels` object exists?
- **H0 choice.** **No** (adjudicated during integration). `labels` may carry only `licence`
  and/or `consent`; a missing `sensitivity` is not a structural error. When it matters — a
  derived record whose resolved `derived_from` input ranks above `public` — absence is
  `E_LABEL_DOWNGRADE` (Q16). `E_ENV_LABELS` covers only structural problems.
- **Recommendation.** Keep; the decision draft (`H1`) does not require the field and
  licence-only labels are meaningful.
- **Affects.** `spec/weave-record-1.md` §8.1; `schemas/envelope.json`; `vectors/labels/`.

### Q30. Signer-class scope for the special kinds

- **Question.** The generic rule "a human key only signs human acts" would forbid
  counter-signatures that some kinds explicitly require (both keys on a rotation, a
  human/organization signer on a compromise revocation, an owner co-signature on a declared
  key).
- **H0 choice.** For `weave.key.*`, `weave.grant`, `weave.consent.*` and `weave.erasure`,
  the kind page's explicit signer requirements are authoritative. `E_ACTOR_HUMAN_KEY`
  applies only to non-human records outside the key-lifecycle kinds; `actor.key` must still
  match its declared class (`E_ACTOR_KEY_TYPE_MISMATCH`).
- **Recommendation.** Keep; otherwise an owner-approved agent key or a human-signed
  compromise revocation would be unconstructible.
- **Affects.** `spec/weave-record-1.md` §5.1–§5.2 and the kind pages; verifier.

### Q31. Required-signature error precedence for the special kinds

- **Question.** For the seven kinds with explicit signer rules, a non-empty `sigs` array may
  satisfy the generic "at least one signature by `actor.key`" rule yet lack the *required*
  signer (e.g. a `weave.key.declared` signed only by the owner, not by the declared key).
  Which code wins?
- **H0 choice.** The kind-specific code wins: `E_KEY_DECLARED_NOT_SELF_SIGNED`,
  `E_KEY_ROTATION_SIGS`, `E_KEY_REVOKE_SIGNER`, `E_GRANT_GRANTER`/`E_GRANT_REVOKE_SIGNER`,
  `E_ACTOR_KEY_TYPE_MISMATCH`, `E_ERASE_ACTOR`. `E_SIG_REQUIRED` is reserved for an
  absent/empty `sigs` array where signing is required, and for kinds without explicit
  signer rules where no signature by `actor.key` is present.
- **Recommendation.** Keep; it makes negative vectors unambiguous and keeps the most
  specific diagnosis.
- **Affects.** `spec/weave-record-1.md` §4.4/§14.5; verifier; `vectors/key-lifecycle/`,
  `vectors/grant/`.

### Q32. Erased-reference cross-checks and the two erasure error codes

- **Question.** When a reference resolves to a `weave.erased` placeholder, may its `kind`
  claim (the kind of the record that was erased) contradict anything? And which code covers
  which erasure inconsistency?
- **H0 choice.** No contradiction check for erased resolution: the placeholder does not
  carry the original kind, so the claim cannot be checked (G3 semantics: the reference still
  means the erased record). Code split: `E_ERASE_DIGEST_MISMATCH` when the erasure record's
  `erased.digest`/origin/id disagrees with the placeholder (or the placeholder's `digest`
  contradicts the attestation); `E_ERASE_ATTESTATION` only when the placeholder's
  `attestation` reference cannot be resolved to the corresponding `weave.erasure` record.
- **Recommendation.** Keep; it avoids misreporting legitimate erased references and keeps
  negative vectors deterministic.
- **Affects.** `spec/weave-record-1.md` §6.3/§10.3; verifier `refs.py`/`erase.py`;
  `vectors/erasure/`.

## 2. Founder decisions still pending (outside H0 scope)

These come from `POSITIONING.md` §11 and the licensing decision `2026-11-10 #20`; H0 does
not settle them:

1. **Publication timing** of this repository (the H0 deliverable is a private local repo;
   nothing is pushed).
2. **When and under which license** the offline transport package is extracted from
   Koinoweave (it is not part of H0).
3. **Human keys in Inceptless** (`ADR 0026`) — the precondition for §8.3 and for `H0`'s
   "human keys only sign human acts" rule to be meaningful with real keys; until then all
   `accepted` records produced without a human signature should be treated as claims.
4. **Governance** after publication (`K4` is founder approval + decision log for now;
   a written interim charter may be needed once external contributors arrive).
5. **CLIA legal review** of `CLA.md` (copied verbatim, still DRAFT, not in force).
6. **Whether to publish the license/CLA split** as `LICENSING.md` describes (H0 implements
   the `2026-11-10 #20` decision: Apache-2.0 code/schemas/vectors, CC-BY-4.0 spec/docs).
