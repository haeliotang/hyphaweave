<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Decided questions and remaining provisional choices

> **Status: DRAFT (revision 3).** This file records the questions that the
> `weave-record/1` decision draft v0.1 (with correction v0.1.1) left open and how
> H0 resolved them.
>
> **Q1–Q32 are decided** by Inceptless decision **2026-11-10 #34**; **Q33 is
> decided** by Inceptless decision **2026-11-10 #42**. Revision 3 records the
> rulings S1–S17 of Inceptless decision **2026-11-11 #2**: the ambiguity classes
> that S8 left to the reviser are listed, with their readings and rationale, in
> §6 under `decided by principle (Inceptless decision 2026-11-11 #2)`; §6
> entries 15–19 record the five further principle decisions of decision 2026-11-11 #5;
> entries 20–23 record the S1-FIX2/S1-FIX3 principle decisions (decisions 2026-11-11 #12
> and #14). Each
> entry in §1 carries its decision status; its normative form is in
> [`../spec/`](../spec/), and this page only records the question, the decision
> and the reasoning. A small number of *implementation-shape* details were not
> decided by #34, #42 or #2; they are listed as `PROVISIONAL` in §3. P1 and P2
> were resolved by #42, and P3/P10 by #2, and are no longer listed.
>
> Nothing in this file overrides the specification. Where this page and
> [`../spec/weave-record-1.md`](../spec/weave-record-1.md) disagree, the
> specification wins.
>
> Earlier revisions of this file attributed some choices to integration decisions
> that did not exist and presented them as final. Those attributions are gone;
> §4 and §5 list what changed in revisions 2 and 1 respectively.

## 1. Decided questions (Q1–Q33)

Each entry has five parts: the decision status, the question, the decision, the
reasoning, and where the rule lives (specification section, vectors and verifier).
All statuses are `decided (Inceptless decision 2026-11-10 #34)` unless stated
otherwise.

### Q1. Ed25519 verification profile

- **Status:** `decided (Inceptless decision 2026-11-10 #34)`.
- **Question.** Which exact verification rules must every implementation share so
  that two independent verifiers reach identical conclusions? RFC 8032 permits
  cofactored and cofactorless verification, and libraries differ on small-order
  and mixed-order keys.
- **Decision.** PureEdDSA, single message, no context string, no pre-hash, strict
  and cofactorless, with a fixed check order: signature length, `S < L`, full
  RFC 8032 §5.1.3 decoding of `A` (including "x = 0 and sign bit 1 is a decoding
  failure"), `[8]A == identity` → `E_SIG_SMALL_ORDER_A`, `[L]A != identity` →
  `E_SIG_MIXED_ORDER_A` (new), full decoding of `R`, `[8]R == identity` →
  `E_SIG_SMALL_ORDER_R`, then the equation `[S]B = R + [k]A` or `E_SIG_INVALID`.
  Each step has its own error code and the first failing step is reported.
  Identity-key forgeries are rejected. Wycheproof `valid` cases are accepted,
  `invalid` cases rejected, and **all** `acceptable` cases rejected — including
  small-order and mixed-order public keys.
- **Reasoning.** Cross-implementation agreement is the point of the vectors; "when
  unsure, reject" is the conservative reading, and a library-permitted permissive
  variant is exactly where two honest implementations would diverge. Mixed-order
  public keys are rejected because accepting them would need a second, different
  rule to stay consistent across implementations.
- **Where.** `spec/weave-record-1.md` §3; `spec/error-codes.md`;
  `vectors/sig/`, `vectors/external/`; verifier `ed25519.py`.

### Q2. base64url encoding

- **Status:** `decided (Inceptless decision 2026-11-10 #34)`.
- **Question.** Is padding allowed, and how strict is decoding?
- **Decision.** Unpadded base64url (RFC 4648 §5), no `=`, strict decoding:
  reject whitespace, `+` and `/`, and non-zero unused trailing bits. Fixed byte
  lengths per field: 16 bytes salt, 32 bytes public key, 64 bytes signature.
- **Reasoning.** Padding variants and non-zero trailing bits are the classic
  source of "same value, different bytes" disagreement; rejecting them is cheap
  and canonical.
- **Where.** `spec/weave-record-1.md` §2.6; `vectors/jcs/`, `vectors/sig/`;
  verifier `encoding.py`.

### Q3. `salt` encoding, length and obligation

- **Status:** `decided (Inceptless decision 2026-11-10 #34)`.
- **Question.** What exactly must `salt` be, and when is it required?
- **Decision.** Exactly 16 random bytes, unpadded base64url (22 characters),
  required when `labels.sensitivity` is `personal` or `local-only`, optional
  otherwise, and covered by the record digest like any other member. A verifier
  checks encoding and length, never randomness.
- **Reasoning.** The salt's job is to make an erased record's digest
  non-enumerable; 16 bytes is the smallest conventional choice. Randomness cannot
  be verified offline, and the specification says so.
- **Where.** `spec/weave-record-1.md` §4.1, §8.3; `vectors/labels/`,
  `vectors/erasure/`; verifier `envelope.py`.

### Q4. Unicode normalization

- **Status:** `decided (Inceptless decision 2026-11-10 #34)`.
- **Question.** Are strings normalized (NFC/NFKC) before comparison, signing or
  label checks?
- **Decision.** No normalization anywhere. Strings are compared as Unicode scalar
  values; WR-CJ emits literal UTF-8; a lone surrogate escape is invalid.
- **Reasoning.** Normalization depends on Unicode-versioned tables; applying it
  silently changes the bytes a person signed, and two implementations on
  different Unicode versions would disagree. Byte-level identity is the
  decades-long property.
- **Where.** `spec/weave-record-1.md` §1; `vectors/jcs/`; verifier
  `canonical.py`.

### Q5. Size limits

- **Status:** `decided (Inceptless decision 2026-11-10 #34)`.
- **Question.** The decision draft says nothing about maximum sizes; a format
  without limits invites resource-exhaustion bugs.
- **Decision.** The limits of `spec/weave-record-1.md` §13 (for example: record
  ≤ 1 MiB, manifest ≤ 4 MiB, ≤ 100,000 records per container, ≤ 200,000 container
  entries, ≤ 1 GiB uncompressed container bytes). Violations are hard errors
  checked before or while reading, never a crash.
- **Reasoning.** Generous but bounded; the exact magnitudes can be revisited once
  J1/J2 produce operational data, because the vectors test the boundary behaviour
  rather than the specific number.
- **Where.** `spec/weave-record-1.md` §13; `spec/error-codes.md`;
  `vectors/jcs/`, `vectors/container/`; verifier `canonical.py`, `container.py`.

### Q6. Timestamp grammar and leap seconds

- **Status:** `decided (Inceptless decision 2026-11-10 #34)`.
- **Question.** What is the exact syntax of time fields, and how are leap seconds
  represented?
- **Decision.** RFC 3339, UTC only, exactly three fractional digits (milliseconds),
  literal trailing `Z`, seconds `00`–`59`, years 0000–9999. A leap second (`:60`)
  is invalid; the event is attributed to the following second. Times are claims,
  never trusted.
- **Reasoning.** `:60` appears only rarely and no producer in this scope emits it;
  rejecting is safer than an untestable mapping rule. A future decision can add an
  explicit leap-second rule if a round trip ever needs it.
- **Where.** `spec/weave-record-1.md` §2.8; `vectors/actor/`,
  `vectors/container/`; verifier `grammar.py`.

### Q7. `refs[].rel` closed vocabulary

- **Status:** `decided (Inceptless decision 2026-11-10 #34)`.
- **Question.** Which relation words are in the closed vocabulary?
- **Decision.** The eight Inceptless relations (`derived_from`, `handed_off_to`,
  `receipt_of`, `executed_as`, `assessed_by`, `compensated_by`, `migrated_from`,
  `reshaped_from`) plus `supersedes` and `correction_of`. `erases` and `revokes`
  are **not** in the vocabulary: revocation and erasure are expressed through
  body references, and no rule uses those two relation words.
- **Reasoning.** Minimal, auditable and every word is used by a rule or by the
  stage vocabulary. Additions require a written proposal.
- **Where.** `spec/weave-record-1.md` §6.2; `schemas/envelope.json`;
  `vectors/ref/`; verifier `refs.py`.

### Q8. Manifest field set and manifest signature placement

- **Status:** `decided (Inceptless decision 2026-11-10 #34)`.
- **Question.** The decisions mandate a manifest digest, a previous-manifest
  digest and a manifest signature, but not the exact JSON shape.
- **Decision.** `manifest.json` is pure data (`format`, `manifest_version`,
  `origin`, `created_at`, `level`, `records`, `previous_manifest`, optional
  `chain` and `blobs`) and never contains its own digest. The digest and
  signatures live in `signatures/manifest.sig.json`; the manifest digest uses its
  own domain prefix (`weave-record/1/manifest-digest\n`); the exact bytes of the
  previous container's `manifest.json` are embedded at `previous/manifest.json`.
  This is explicitly a reading of D1 ("the manifest must carry a manifest
  digest"): the digest is carried next to the manifest, not inside it.
- **Reasoning.** Keeps the digest constructive from plain file bytes with no
  self-reference, which is what makes the offline L0 procedure possible with
  `sha256sum` alone.
- **Where.** `spec/weave-record-1.md` §2.4, §11; `schemas/manifest.json`;
  `vectors/container/`, `vectors/integrity-levels/`; verifier `manifest.py`.

### Q9. L1 chain head and honest integrity reporting

- **Status:** `decided (Inceptless decision 2026-11-10 #34)`.
- **Question.** L1 requires the internal hash-chain head and each record's chain
  position, but an exporter cannot export the internal chain preimages (they use
  each project's own framing). Can an offline verifier claim L1 or L2?
- **Decision.** The verifier checks structural completeness of the claim (head
  present, every record has a unique `chain_index`, L2 has a timestamp chain) but
  reports `chain.status = "unverified"`, `level_verified = "L0"` always, and
  notice `N_CHAIN_CLAIM_UNVERIFIED`. L2 is reported as "L0 plus a verified
  external anchor" through the separate `anchor_verified` field; the verifier must
  never claim the internal chain was verified.
- **Reasoning.** Honest labelling: v0.1 cannot re-verify a project's internal
  chain offline. Exporting chain links is possible in a later additive milestone.
- **Where.** `spec/weave-record-1.md` §11.4, §12; `vectors/integrity-levels/`;
  verifier `manifest.py`, `container.py`.

### Q10. Grant revocation and delegation

- **Status:** `decided (Inceptless decision 2026-11-10 #34)`.
- **Question.** The H0 kind list names exactly eight `weave.*` kinds and has no
  separate `weave.grant.revoked`; how is revocation modelled, how is delegation
  constrained, and who may revoke?
- **Decision.** Revocation is a `weave.grant` record with `action: "revoke"`.
  A grant (`action: "grant"`) carries an optional `revocation` array of 1–8 unique
  key ids that lists which keys may revoke it; when absent, the granter's
  `actor.key` **and** its rotation successors found by explicitly walking
  `weave.key.rotated` records (depth ≤ 8) may revoke. No arbitrary declared
  human/organization key may revoke someone else's grant. A delegated sub-grant
  must be a subset of its parent: kinds, actions and scope must not grow, its
  validity window must lie inside the parent's, the parent must be transferable,
  must cover kind `weave.grant` and action `grant`, and the parent's
  `grant.grantee.key` must equal the sub-granter's `actor.key`. The delegation
  chain depth is at most 8; a cycle or an unresolvable parent makes the dependent
  record `unverifiable`.
- **Reasoning.** The eight-kind list stays closed and additive evolution remains
  possible; the subset rule closes the privilege-escalation path where a grantee
  could widen its own actions.
- **Where.** `spec/weave-record-1.md` §5.5; `spec/kinds/weave.grant.md`;
  `schemas/kinds/weave.grant.json`; `vectors/grant/`; verifier `grants.py`.

### Q11. Verdict semantics for authorization failures

- **Status:** `decided (Inceptless decision 2026-11-10 #34)`.
- **Question.** When an agent's authorization is missing, expired, revoked or too
  narrow, is the record `invalid` or `unverifiable`?
- **Decision.** Envelope-level absence of `actor.grant` is `invalid`
  (`E_ENV_ACTOR_GRANT_MISSING`). Grantee, kind or action mismatch is `invalid`
  (the agent exceeded its explicit authority). An authorization that cannot be
  checked or no longer holds at the claimed `recorded_at` is `unverifiable`
  (`E_GRANT_UNRESOLVED`, `E_GRANT_REVOKED`, `E_GRANT_EXPIRED`). The revocation
  boundary is `recorded_at >= effective_at` → revoked; records with
  `recorded_at < effective_at` are unaffected. Every stage requires grant
  coverage, including `proposed`; a not-yet-valid grant is `E_GRANT_EXPIRED`.
- **Reasoning.** "I cannot tell" is not the same as "definitely wrong"; reporting
  `unverifiable` still refuses `valid`, so it cannot smuggle unauthorized records
  through.
- **Where.** `spec/weave-record-1.md` §5.4, §9.6; `vectors/stage/`,
  `vectors/grant/`; verifier `grants.py`.

### Q12. Key trust (TOFU), pinning and duplicate declarations

- **Status:** `decided (Inceptless decision 2026-11-10 #34)`.
- **Question.** How does an offline verifier obtain public keys, what does it do
  with an undeclared key, and which declaration wins if the same key id is
  declared more than once?
- **Decision.** Trust on first use: a valid `weave.key.declared` record in the
  container or a supplied keyset provides the key; no CA, no network. **H0 does
  not implement pinning**; a local trust store is an implementation concern
  outside the H0 verifier. An undeclared key makes the affected signature
  `unverifiable` (`E_KEY_UNKNOWN` + `N_KEY_UNDECLARED`). When the same key id
  appears in multiple declarations, the **earliest valid declaration by claimed
  `recorded_at`** wins; equal `recorded_at` breaks the tie by the
  lexicographically smallest record digest.
- **Reasoning.** Fits the offline, CA-less design; the earliest-declaration rule
  is deterministic without needing a mutable trust database.
- **Where.** `spec/weave-record-1.md` §5.3, §9.5; all signature vectors;
  verifier `keys.py`.

### Q13. Unknown algorithms

- **Status:** `decided (Inceptless decision 2026-11-10 #34)`.
- **Question.** Algorithm names are the agility interface. What happens before an
  implementation supports a newer digest or signature algorithm?
- **Decision.** For references, an unknown digest algorithm is structurally
  valid and resolves to `unverifiable` (not a record error); a manifest record
  entry with an unknown digest algorithm is `invalid` (`E_MANIFEST_RECORDS`)
  because the manifest's own integrity depends on it. For signatures, entries
  with an unknown `alg` are **ignored** (`sigs[].state = "ignored"`); a record
  that requires per-record signing is satisfied by at least one known-algorithm
  signature by a required key, and is `unverifiable` (`E_SIG_UNVERIFIABLE`) when
  its signatures exist but no verifiable required signature does.
- **Reasoning.** Algorithm agility must not turn a future mixed-signature record
  into an invalid document for older verifiers. This mirrors the digest rule and
  keeps forward compatibility.
- **Where.** `spec/weave-record-1.md` §2.7, §4.3, §6.3; `schemas/envelope.json`;
  `vectors/ref/`, `vectors/sig/`; verifier `refs.py`, `envelope.py`.

### Q14. SPDX license expression checking

- **Status:** `decided (Inceptless decision 2026-11-10 #34)`.
- **Question.** How much SPDX validation is required offline?
- **Decision.** Syntax only (identifiers `[A-Za-z0-9.+-]+`, `AND`/`OR`/`WITH`,
  parentheses, optional `+` suffix). License-list membership is not checked.
- **Reasoning.** Offline verification cannot consult the SPDX list, and a
  version-pinned verifier must not reject a valid future identifier.
- **Where.** `spec/weave-record-1.md` §8.7; `vectors/labels/`; verifier
  `labels.py`.

### Q15. `weave.erased` is not an envelope

- **Status:** `decided (Inceptless decision 2026-11-10 #34)`.
- **Question.** The erasure rule gives the replacement shape explicitly, and it
  has no `stage`/`actor`/`sigs`. Is it an envelope record or a special document?
- **Decision.** A special document with exactly the decided six-member shape. Its
  own record digest is computed like any record (there are no signatures to
  remove); its `digest` member carries the **original** record digest. The verdict
  for such a file is `erased`, and integrity rests on the attestation record, the
  original digest and the container's manifest/chain position.
- **Reasoning.** The substitution shape is the decided erasure design; adding
  envelope fields would change what a reference to the erased record means.
- **Where.** `spec/weave-record-1.md` §4.5, §10; `spec/kinds/weave.erased.md`;
  `schemas/kinds/weave.erased.json`; `vectors/erasure/`; verifier `erase.py`.

### Q16. Label propagation across derived relations and absent sensitivity

- **Status:** `decided (Inceptless decision 2026-11-10 #34)`.
- **Question.** Which relations propagate sensitivity, and does an absent
  `sensitivity` count as `public` or as unknown?
- **Decision.** Strictest-value propagation applies along every derived relation:
  `derived_from`, `reshaped_from`, `migrated_from` and `correction_of`. An absent
  `labels.sensitivity` on a record with a resolved derived input ranked above
  `public` is `E_LABEL_DOWNGRADE`; absence cannot prove "not lower". If all
  resolved inputs are public (or there are none), absence is allowed.
- **Reasoning.** Conservative: the alternative would let a careless exporter drop
  personal data by omitting a field. Covering every derived relation closes the
  bypass where a different derivative word escapes the check.
- **Where.** `spec/weave-record-1.md` §8.4; `vectors/labels/`; verifier
  `labels.py`.

### Q17. Idempotency-key duplicates

- **Status:** `decided (Inceptless decision 2026-11-10 #34)`.
- **Question.** The decision draft says records with the same origin and
  idempotency key are the same action. Is a container containing both invalid?
- **Decision.** Notice `N_IDEMPOTENCY_DUPLICATE`, not an error. Identical content
  would already collapse into one digest; two different records claiming the same
  action key is an advisory inconsistency, not proof of tampering.
- **Reasoning.** Dedupe semantics are an importer concern; the verifier reports
  the condition without inventing an invalidity rule.
- **Where.** `spec/weave-record-1.md` §4.1; `vectors/container/`; verifier
  `container.py`.

### Q18. Test-only check-disable hook in the reference verifier

- **Status:** `decided (Inceptless decision 2026-11-10 #34)`.
- **Question.** The H0 gates need to prove that vectors exercise each check
  class. How can the Python reference verifier be manipulated for that without
  affecting normal use?
- **Decision.** `WEAVE_VERIFY_SKIP_CHECKS` (comma-separated error codes) is
  honoured only by the Python reference verifier for conformance testing and is
  echoed in `report.checks_disabled`. It is not part of the format and MUST NOT be
  used to claim verification. Revision 1 additionally uses true source-level
  mutation (copying and editing the verifier) as the primary ablation gate; the
  hook remains for reproducing individual checks.
- **Reasoning.** A report must never be silently degraded, so disabled checks are
  always visible. The hook is test-only; an independent implementation does not
  need it to be conformant.
- **Where.** `spec/weave-record-1.md` §14.7; `verifiers/python/`;
  `tools/anti_verification.py`.

### Q19. `readable/` handling

- **Status:** `decided (Inceptless decision 2026-11-10 #34)`.
- **Question.** The container decision says `readable/` is an optional human view
  that does not participate in the digest. Does a verifier ignore it entirely?
- **Decision.** Yes: ignored, unharshed and never trusted; its presence may
  produce the informational notice `N_READABLE_PRESENT`. An exporter must not put
  anything machine-significant there.
- **Reasoning.** It does not participate in the digest by decision, and hashing
  or parsing it would invent a rule the format does not have.
- **Where.** `spec/weave-record-1.md` §11.8; `vectors/container/`; verifier
  `container.py`.

### Q20. Key validity windows

- **Status:** `decided (Inceptless decision 2026-11-10 #34)`.
- **Question.** The decisions define declared, rotated and revoked keys but say
  nothing about a declared key's validity window.
- **Decision.** Optional `valid_from` and `valid_until` on
  `weave.key.declared`. A signature whose claimed `recorded_at` is after
  `valid_until` **or** before `valid_from` is `E_KEY_EXPIRED` (invalid).
- **Reasoning.** Conservative reading of claimed validity windows; both bounds
  are checked so a key cannot be used before its declared start either.
- **Where.** `spec/weave-record-1.md` §9.4; `spec/kinds/weave.key.declared.md`;
  `vectors/key-lifecycle/`; verifier `keys.py`.

### Q21. `signatures/manifest.sig.json` `timestamps` member

- **Status:** `decided (Inceptless decision 2026-11-10 #34)`.
- **Question.** Must the attestation file always carry a `timestamps` array, or
  may it be absent for L0/L1?
- **Decision.** Required member; it MAY be an empty array for L0/L1 and MUST be
  non-empty for L2. Each entry carries `path`, `digest` and `renews`; the array is
  sorted by path and forms one renewal chain.
- **Reasoning.** Closed-object treatment avoids a hidden "absent versus empty"
  distinction in a signed file.
- **Where.** `spec/weave-record-1.md` §11.3, §12; `schemas/manifest.json`;
  `vectors/integrity-levels/`; verifier `timestamps.py`.

### Q22. `manifest.records[]` metadata versus record content

- **Status:** `decided (Inceptless decision 2026-11-10 #34)`.
- **Question.** Are the manifest's per-record `id`/`kind` hints, or claims that
  must match the record bytes?
- **Decision.** They MUST equal the listed record's actual `id` and `kind`; a
  mismatch is `E_MANIFEST_RECORDS` (invalid).
- **Reasoning.** The manifest is signed evidence; metadata that contradicts the
  record it lists is an inconsistency, not a hint.
- **Where.** `spec/weave-record-1.md` §11.2, §11.6; `vectors/container/`;
  verifier `container.py`.

### Q23. Blob digest algorithms and errors

- **Status:** `decided (Inceptless decision 2026-11-10 #34)`.
- **Question.** Which algorithms may `manifest.blobs` use, and which code covers
  problems?
- **Decision.** Only `sha256` (the path is `blobs/sha256/<hex>`); an unsupported
  algorithm, a size mismatch or a set mismatch is `E_MANIFEST_BLOB` (invalid).
- **Reasoning.** Blobs are content-addressed attachments; H0 needs no agility
  there, and one code keeps negative vectors deterministic.
- **Where.** `spec/weave-record-1.md` §11.7; `vectors/container/`; verifier
  `container.py`.

### Q24. Error-code mapping for size limits

- **Status:** `decided (Inceptless decision 2026-11-10 #34)`.
- **Question.** The decisions mention size limits but not which code fires.
- **Decision.** The closed registry fixes one mapping: single-file JSON limit →
  `E_JSON_SIZE`; container aggregate → `E_CONTAINER_SIZE`; record count →
  `E_MANIFEST_RECORDS`; blob limits → `E_MANIFEST_BLOB`/`E_MANIFEST_SCHEMA`;
  oversized zip streams → `E_CONTAINER_SIZE`.
- **Reasoning.** Deterministic negative vectors need exactly one code per defect.
- **Where.** `spec/error-codes.md`; `vectors/jcs/`, `vectors/container/`;
  verifier `canonical.py`, `container.py`.

### Q25. Error-code split for zip violations

- **Status:** `decided (Inceptless decision 2026-11-10 #34)`.
- **Question.** One `E_CONTAINER_*` code for every zip problem, or a split?
- **Decision.** Split by nature: path escapes, duplicate entry names, symlinks,
  unsupported entry types and unknown files in `signatures/`/`previous/` →
  `E_CONTAINER_ENTRY`; corrupt archive, unsupported compression or encryption →
  `E_CONTAINER_ZIP`; content layout problems → `E_MANIFEST_*`.
- **Reasoning.** A nested vector refused for the wrong reason is a test failure;
  the split makes the cause explicit.
- **Where.** `spec/error-codes.md`; `vectors/container/`; verifier
  `container.py`.

### Q26. Evaluation model for cross-record dependencies and cycles

- **Status:** `decided (Inceptless decision 2026-11-10 #34)`.
- **Question.** Records reference each other (key declarations, grants, consents,
  erasure attestations, label propagation). How must a verifier evaluate them
  deterministically without loops?
- **Decision.** Deterministic dependency-ordered evaluation with memoisation. A
  cycle that prevents deciding a condition makes the dependent unit
  `unverifiable` with `N_REF_UNVERIFIABLE`; it is never `valid` and never a crash.
  A dedicated cycle vector pins the first error code that a cycle produces.
- **Reasoning.** The format must terminate deterministically on adversarial
  input; H0 containers are small, so memoised traversal is sufficient.
- **Where.** `spec/weave-record-1.md` §6.4, §14.5; `vectors/ref/`; verifier
  `refs.py`, `verifier.py`.

### Q27. Report `input` for directory containers and the `vectors` report shape

- **Status:** `decided (Inceptless decision 2026-11-10 #34)`.
- **Question.** A directory has no single content digest. What identifies the
  input in a deterministic report, and how are per-case results shaped?
- **Decision.** For a directory container, `input.sha256` is the manifest digest
  and `input.size` is the manifest byte size (the manifest is the container's only
  content-addressed identity); for a zip, the hash and size of the archive. The
  `vectors` target report shape is implementation-defined but deterministic and
  path-free; revision 1 uses `{"case_count", "matched", "mismatched"}` for its
  summary and does not reuse record-verdict counts.
- **Reasoning.** The identity must be derivable from the bytes actually received.
  H1 independence concerns record and container verification, not the test-runner
  report shape.
- **Where.** `spec/weave-record-1.md` §14.6; verifier `report.py`, `cli.py`.

### Q28. Agent-only envelope members on key-lifecycle records

- **Status:** `decided (Inceptless decision 2026-11-10 #34)`.
- **Question.** `actor.type == "agent"` normally requires `model`,
  `on_behalf_of`, `grant` and `idempotency_key`. But `weave.key.declared`
  requires `actor.type == body.key_type`, so an agent-class key declaring itself
  could never satisfy both.
- **Decision.** The four agent-only members are not required on
  `weave.key.declared`, `weave.key.rotated` and `weave.key.revoked`: those records
  describe keys and are not delegated actions. Delegated `weave.grant` records and
  all other agent records keep the full obligations.
- **Reasoning.** A self-declared agent key is the only way TOFU can bootstrap an
  agent identity offline; the exception is limited to the three key-lifecycle
  kinds.
- **Where.** `spec/weave-record-1.md` §4.2, §5.1; `schemas/envelope.json`;
  verifier `envelope.py`.

### Q29. `labels` present without `sensitivity`

- **Status:** `decided (Inceptless decision 2026-11-10 #34)`.
- **Question.** Is `labels.sensitivity` required whenever the `labels` object
  exists?
- **Decision.** No. `labels` may carry only `licence` and/or `consent`; a missing
  `sensitivity` is not a structural error. When it matters — a derived record
  whose resolved input ranks above `public` — absence is `E_LABEL_DOWNGRADE`
  (Q16). `E_ENV_LABELS` covers structural problems only.
- **Reasoning.** The decisions do not require the field, and licence-only or
  consent-only labels are meaningful.
- **Where.** `spec/weave-record-1.md` §8.1; `schemas/envelope.json`;
  `vectors/labels/`; verifier `envelope.py`.

### Q30. Signer-class scope for the special kinds

- **Status:** `decided (Inceptless decision 2026-11-10 #34)`.
- **Question.** The generic rule "a human key only signs human acts" would forbid
  counter-signatures that some kinds explicitly require (both keys on a rotation,
  an owner co-signature on a declared key).
- **Decision.** For the seven signer-constrained kinds (`weave.key.*`,
  `weave.grant`, `weave.consent.*`, `weave.erasure`), the kind page's explicit
  signer requirements are authoritative for additional signatures.
  `E_ACTOR_HUMAN_KEY` applies only outside the three key-lifecycle kinds, to
  records whose `actor.type` is not `human`/`organization`; `actor.key` must still
  match its declared class (`E_ACTOR_KEY_TYPE_MISMATCH`).
- **Reasoning.** Otherwise an owner-approved agent key or a human-signed
  compromise revocation would be unconstructible.
- **Where.** `spec/weave-record-1.md` §5.1–§5.2 and the kind pages; verifier
  `keys.py`.

### Q31. Required-signature error precedence

- **Status:** `decided (Inceptless decision 2026-11-10 #34)`.
- **Question.** For the seven kinds with explicit signer rules, a non-empty `sigs`
  array may satisfy the generic "at least one signature by `actor.key`" rule yet
  lack the required signer. Which code wins?
- **Decision.** The kind-specific code wins: `E_KEY_DECLARED_NOT_SELF_SIGNED`,
  `E_KEY_DECLARED_NOT_COSIGNED`, `E_KEY_ROTATION_SIGS`, `E_KEY_REVOKE_SIGNER`,
  `E_GRANT_GRANTER`, `E_GRANT_REVOKE_SIGNER`, `E_ACTOR_KEY_TYPE_MISMATCH`,
  `E_ERASE_ACTOR`. `E_SIG_REQUIRED` is reserved for an absent or empty `sigs`
  array where signing is required, and for ordinary kinds with non-empty `sigs`
  but no valid `actor.key` signature. `E_SIG_UNVERIFIABLE` (Q13) is reported when
  signatures exist but none is verifiable for a required signer.
- **Reasoning.** One primary code per defect, and the most specific diagnosis wins.
- **Where.** `spec/weave-record-1.md` §4.4, §14.5; `spec/error-codes.md`;
  `vectors/key-lifecycle/`, `vectors/grant/`; verifier `envelope.py`, `kinds.py`.

### Q32. Erased references, erasure signers and the two erasure error codes

- **Status:** `decided (Inceptless decision 2026-11-10 #34)`.
- **Question.** When a reference resolves to a `weave.erased` placeholder, may its
  `kind` claim contradict anything? Which code covers which erasure
  inconsistency? Who may execute an erasure?
- **Decision.** A reference resolved to `erased` is not kind-checked: the
  placeholder does not carry the original kind, so the claim cannot be checked.
  `E_ERASE_DIGEST_MISMATCH` covers an erasure record whose `erased` reference
  disagrees with the placeholder (or a placeholder whose `digest` contradicts the
  attestation); `E_ERASE_ATTESTATION` covers only a placeholder `attestation`
  reference that does not resolve to the matching erasure record. Erasure executors
  may be `human` or `organization` directly; `agent` needs an `actor.grant`
  covering kind `weave.erasure` and action `erase`; `program`/`device` need a
  `body.basis` reference to a valid grant covering `actor.key` with action
  `erase`. Otherwise `E_ERASE_ACTOR`.
- **Reasoning.** Avoids misreporting legitimate erased references and keeps
  negative vectors deterministic; the signer rules keep the decision-draft
  commitment that human keys sign human acts while allowing automated
  retention-expired erasure with an explicit grant.
- **Where.** `spec/weave-record-1.md` §6.3, §10; `spec/kinds/weave.erasure.md`;
  `vectors/erasure/`; verifier `refs.py`, `erase.py`.

### Q33. Root of trust and key bootstrap

- **Status:** `decided (Inceptless decision 2026-11-10 #42)`.
- **Question.** Every key declaration must be self-signed and counter-signed by
  its owner or the previous key. The first `human`/`organization` key has neither
  an owner nor a previous key, yet a verification context needs a starting point
  for trust. How is that root established without trusting attacker-controlled
  data?
- **Decision.** Roots come **only from the locally supplied keyset** (the
  `--keys` directory) — the verifier's own local trust input under E4. A keyset
  `weave.key.declared` record whose `key_type` is `human` or `organization` and
  which is self-signed and passes its own declaration checks is a root: it enters
  the trusted set, needs no counter-signature, and produces **no**
  `N_SELF_ATTESTED_ROOT_KEY`. Declarations in the container or target must chain
  to that local trust: either the same key id is already trusted from the keyset,
  or at least one valid counter-signature was made by a trusted
  `human`/`organization` key. A declaration that cannot chain is **unverifiable
  `E_KEY_UNTRUSTED`**; when its verified signatures are only its own, the verifier
  also reports `N_SELF_ATTESTED_ROOT_KEY`. The keyset is evaluated **before** the
  container/target declarations and its roots seed the trusted set; container
  declarations may extend the set by iteration to a fixed point. There is **no
  time-ordered root selection**: a claimed `recorded_at` cannot create a root, so
  backdating a self-signed container declaration does not make it trusted.
  An untrusted container declaration must not invalidate other declarations and
  must never demote a keyset root; Q12's earliest-declaration rule remains a
  declaration-resolution rule, not root selection. Without `--keys`, the trusted
  set is empty: container/target `human`/`organization` declarations are
  unverifiable with the notice, and agent/program/device declarations whose owner
  is not trusted are unverifiable `E_KEY_UNTRUSTED`.
- **Reasoning.** An attacker controls the claimed time inside a container, so a
  time-based root selection can be backdated. The locally supplied keyset is what
  the verifier was explicitly given, is evaluated offline, and lets two honest
  implementations compute the same trust set. Missing local trust is
  `unverifiable`, not `invalid`, because the information rather than the record is
  lacking — and it must never silently upgrade other records.
- **Where.** `spec/weave-record-1.md` §5.3, §9.1; `spec/error-codes.md`
  (`E_KEY_UNTRUSTED`); `spec/kinds/weave.key.declared.md`;
  `vectors/key-lifecycle/`; verifier `keys.py`.

## 2. Founder decisions still pending (outside the H0 specification)

These are outside the format rules Q1–Q33. H0 does not settle them. Publication
timing was originally listed here and is now resolved: the repository is public.

1. **Offline transport extraction**: when and under which license the transport
   component is extracted from its source project. It is not part of H0 and is
   deferred until after J1.
2. **Human keys in Inceptless**: the human-key foundation is the precondition for
   the agent rules to be meaningful with real keys. Revision 1 reports `accepted`
   records without a declared-human signature via `N_NO_HUMAN_SIGNATURE`, but a
   notice is not a substitute for real human keys.
3. **Governance after publication**: today changes are founder-approved and
   recorded in the decision log (K4); an interim written charter may be needed
   once external contributors arrive.
4. **Formal v0.1 freeze**: the candidate regression set becomes a frozen set only
   after J1 and J2 acceptance. Until then, conclusions in
   `vectors/frozen/v0.1-candidate/` may still change with a new decision.

Already resolved and therefore not open questions: publication timing (the
repository is public now), the CLA v1.0 review and signing channel (decisions
2026-11-10 #27/#28, see `CLA.md` and `CONTRIBUTING.md`), and the licensing split
(decision K2 plus 2026-11-10 #20, see `LICENSING.md`).

## 3. Remaining PROVISIONAL implementation-shape choices

Decision **2026-11-10 #42** resolved P1 and P2. Root selection no longer uses
claimed time, so there is no deterministic root ordering to choose and no
root tie-break; those entries were removed from the specification's Appendix A
and are not listed below. Decision **2026-11-11 #2** resolved P3 (delegation-chain
depth, now fixed by S10) and P10 (`N_NO_HUMAN_SIGNATURE` precedence, now fixed by
F6/S8⑭), and narrowed P7. The remaining implementation-shape choices keep the
specification's identifiers **P4–P6, P9, P11, P12**; they are marked
`PROVISIONAL` and may change additively without changing the decided behaviours
above.

- **P4 — Revocation-authority walk order.** Walking `weave.key.rotated` records
  to find a grant granter's successor for revocation authority is bounded at 8
  rotation steps (fixed by S10); the walk order within that bound is
  implementation shape.
- **P5 — Grant-chain error-code precedence.** The delegation checks and the code
  each step reports are fixed, in this order:
  `E_GRANT_UNRESOLVED` → `E_GRANT_GRANTER` (parent not a grant) →
  `E_GRANT_NOT_TRANSFERABLE` → `E_GRANT_GRANTER` (granter identity mismatch) →
  `E_GRANT_DELEGATION_EXCEEDS` → `E_GRANT_REVOKED`/`E_GRANT_EXPIRED`. The
  precedence among several simultaneously failing steps is an implementation-shape
  choice pending J1/J2 experience. `E_GRANT_GRANTEE_MISMATCH` is not a
  delegation-chain step code: it reports a record whose `actor.key` differs from
  the grantee of the grant it references.
- **P6 — Timestamp renewal-chain representation.** The renewal chain is the
  `timestamps[]` array of `signatures/manifest.sig.json`: each entry has `path`,
  `digest` and `renews`; entries are sorted by path; the first entry's imprint is
  the raw manifest digest, and each later entry's imprint is
  `SHA-256(previous .tsr file bytes || manifest digest raw bytes)`.
- **P7 — `vectors`-target report layout.** The record/container report field
  shapes are now normative in specification §14.6. What remains implementation
  shape is only the `vectors` target: its per-case result array layout and the
  representation of the `input` identity are implementation-defined, deterministic
  and path-free, and are not compared across implementations (F5/S8⑬).
- **P9 — Scope subset comparison.** Delegation subset checks compare `scope` as
  sets of strings; `scope` does not participate in record-level machine checks
  beyond the subset relation.
- **P11 — Specification-example classification markers.** The examples that
  `tools/check_spec_examples.py` validates are annotated as
  `standalone-record`, `container-context` or `illustrative`; the marking
  convention is a non-normative tooling convention.
- **P12 — Delegated-granter actor classes.** Delegation is reachable only for
  `agent` granters: a `program`/`device` grant record that would be a delegated
  sub-grant is `unverifiable` (`E_GRANT_UNRESOLVED`) because the envelope forbids
  `actor.grant` on those actor types, so the parent grant cannot be expressed. The
  handling of that unreachable shape is an implementation-shape choice; the
  restriction itself follows from the envelope rules.

Q27's report-shape part is updated by revision 3: the `vectors` target's
`summary` is normative and conformance is `mismatched == 0`, while the per-case
layout and the `vectors` input identity are explicitly implementation-defined
(F5/S8⑬); the directory-container `input` rule is refined by S14 and decisions
§4.7 (`null` when the manifest identity cannot be read within the limits).

One further candidate implementation shape was resolved by decision #34 rather
than left provisional: structural errors of the special `weave.erased` shape are
reported with `E_KIND_BODY_SCHEMA`, while
`E_ENV_MISSING_FIELD`/`E_ENV_UNKNOWN_FIELD` apply only to normal envelopes.

## 4. What changed in revision 2 of this file

Revision 2 implements Inceptless decision **2026-11-10 #42** (focused
re-verification):

- Q33 was rewritten as `decided (Inceptless decision 2026-11-10 #42)`: trust
  roots come only from the locally supplied keyset; a container/target
  `human`/`organization` declaration that cannot chain to that local trust is
  `unverifiable E_KEY_UNTRUSTED` (with `N_SELF_ATTESTED_ROOT_KEY` when only
  self-signed); there is no time-ordered root selection; backdating cannot create
  a root; the keyset is evaluated before the container/target declarations; and an
  untrusted container declaration must not invalidate other declarations.
- P1 (deterministic root ordering) and P2 (root tie-break) were resolved by
  decision #42 and removed from the PROVISIONAL list; the remaining identifiers
  keep their numbering P3–P12.
- P8 now states the strict `genTime + accuracy < effective_at` comparison for the
  compromise-revocation rescue.
- The pre-publication status text was updated separately: the repository is
  public, while the format remains a draft.

## 5. What changed in revision 1 of this file

- Q1–Q33 are now marked `decided (Inceptless decision 2026-11-10 #34)`. The
  previous revision presented several of them as PROVISIONAL choices and cited
  decisions that did not exist; those references were removed.
- Q7 vocabulary changed: `erases` and `revokes` removed; `supersedes` and
  `correction_of` kept.
- Q10 gained the `revocation` field, the default granter-plus-rotation-successor
  revocation authority, and the subset rules for delegated grants.
- Q12 now says H0 does not implement pinning and specifies the earliest-declaration
  rule.
- Q13 now covers unknown-algorithm **signatures** as well as digest algorithms.
- Q16 now propagates along all four derived relations.
- Q20 now covers `valid_from` as well as `valid_until`.
- Q33 (root-key bootstrap) was added.
- The CLA status was corrected: CLA v1.0 is in force (decisions 2026-11-10
  #27/#28); the old "DRAFT / not in force" text and its typo were removed.
- The frozen regression set is now a **candidate** set
  (`vectors/frozen/v0.1-candidate/`); the official freeze begins after J1/J2
  acceptance.
- §3 was added for the implementation-shape choices that decision #34 did not
  decide.

## 6. What changed in revision 3 of this file

Revision 3 implements Inceptless decision **2026-11-11 #2** and the H1/J1a review
dispositions. Ruling S8 fixed four ambiguity classes outright (manifest multi-error
reporting, missing attestation file, missing `body.public_key`, `-0` versus a later
float) and left the rest to the reviser with the instruction to take the more
conservative reading, pin it in the specification and record it here. Every entry in this
section carries the status `decided by principle (Inceptless decision 2026-11-11 #2)`; each
gives the two readings, the chosen one and why it is the conservative or the deterministic
one. **The entry numbers 1–14 below are the numbers used by the specification's
`[S8①]`–`[S8⑭]` labels**; entries 15–19 record five further principle decisions added
in revision 1 of the S1-FIX1 round (T11), entry 20 records the S1-FIX2 (`decision
2026-11-11 #12`) deterministic-order trade-off (U12/L8), and entries 21–23 record the
S1-FIX3 (`decision 2026-11-11 #14`) principle decisions V3, V2 and V7/L5, and entries
24–29 record the S1-FIX4 (`decision 2026-11-11 #16`) principle decisions W1, W5, W6,
W10/L5, W10/L6 and W3. The S1-FIX5 round (`decision 2026-11-12 #1`) rewrote entries 24,
26 and 29 and added entries 30–31 (principle decisions X1 and X3) and 32–33 (two
questions left open for a later round); decisions 2026-11-12 #2 and #3 (X6, X7)
amended entry 30 and added entry 34.

1. **Several independent manifest defects (S8①).** Reading A: the one-error rule of
   the old §14.5 applies to the whole container, so one code. Reading B: the one-error
   rule is per record (and per container stage), and the §11.6 records-listing phase
   reports every inconsistency it detects. **Chosen B** — the input is invalid either
   way, but reporting the complete set hides no defect and matches the replacement stop
   rule; the container carries all detected codes in `container.errors` with
   `records: []`. More conservative: the receiver sees every problem rather than
   whichever check happened to run first.
2. **Missing `signatures/manifest.sig.json` (S8②).** Readings: `E_MANIFEST_SCHEMA`
   (the file is part of the layout) or `E_MANIFEST_UNSIGNED` (no signature evidence).
   **Chosen `E_MANIFEST_UNSIGNED`**: the registry assigns "no signatures" to that code
   and the manifest is unsigned either way; naming the missing signature is the single
   informative reading.
3. **`weave.key.declared` without `body.public_key` (S8③).** Readings:
   `E_KEY_UNKNOWN` (the key cannot be established) or `E_KEY_PUBLIC_KEY` (the body is
   structurally wrong). **Chosen invalid `E_KEY_PUBLIC_KEY`**: a structure error
   precedes the trust judgement, and invalid is more conservative than unverifiable.
4. **`-0` versus a later float (S8④).** Readings: classify canonical-form deviations
   only after the parse, or classify `-0` at its number token. **Chosen**: number
   classes are examined in input byte order, so `-0` is classified at its token as
   `E_JSON_NOT_CANONICAL`; `{"a":-0,"b":1.5}` yields `E_JSON_NOT_CANONICAL` and the
   reverse order yields `E_JSON_NUMBER_NOT_INTEGER`. The general canonical byte
   comparison still runs after a syntactically valid parse. More deterministic: one
   input, one code, without a cross-class ordering promise implementations would have
   to guess.
5. **Envelope sub-order (F3).** Readings: required-member presence first, or
   closedness first. **Chosen** presence → closedness → per-member grammar in table
   order, repeated inside every closed nested object. **Deterministic** (not a
   conservative-vs-permissive axis): it makes "one error per record" deterministic; the
   alternative lets two conforming verifiers report different codes for one record.
6. **Nested closed-object codes (F2).** Readings: the envelope-level codes cover every
   closed object, or the object's owning section names the code. **Chosen** the owning
   section's dedicated code; `E_ENV_MISSING_FIELD`/`E_ENV_UNKNOWN_FIELD` are top-level
   only. **Deterministic**: the more specific owning-section code is the only reading that
   matches the explicit §4.5 and §11.2 statements that the envelope codes do not apply to
   those objects.
7. **Reference to an individually invalid record.** Readings: `found` because origin,
   id and digest match, or `unverifiable`. **Chosen `unverifiable`**
   (`N_REF_UNVERIFIABLE`), as §6.3 already states: a record that is not itself valid is
   not evidence a reference can rely on. No text change was needed; the vector was
   added.
8. **Zip edge details (S5/S4/S8⑧).** Readings: tolerate a zip prefix, archive comment
   or trailing bytes (common in self-extracting archives), or reject. **Chosen**
   reject (`E_CONTAINER_ZIP`), with ZIP64 accepted and `readable/` never decompressed
   or CRC-checked. More conservative: the container framing is part of the bytes the
   verifier examined; accepting unexamined bytes weakens "the received bytes are the
   evidence".
9. **Keyset structural/semantic boundary (F10, S8⑨).** Readings: any keyset error is a
   usage error (exit 2), or only structural failures are. **Chosen**: canonical form,
   envelope structure, `sigs` presence/format and registered-kind body schema are usage
   errors; kind-semantic, lifecycle, actor, authorisation and cryptographic failures
   establish no trust and are not usage errors. More conservative: a malformed keyset
   input fails closed as a usage error, while a merely untrusted record is ignored
   instead of silently upgrading trust. The silently ignored keyset record is invisible to
   the operator in the report; that is accepted because the alternative (a report warning)
   would need a notice code and the file establishes nothing either way.
10. **Report construction details (F12, S8⑩).** Readings: leave them
    implementation-defined (byte comparisons then cannot be meaningful) or pin them.
    **Chosen** pin them normatively in §14.6: `N_KEY_TOFU` placement, unknown-kind
    notice only on a valid record, `sigs[].state`, partial `refs[]`,
    `timestamps[].gen_time`, broken-renewal states, container defaults for undetermined
    values, and the serializer micro-decisions (including `\u007f` escaping).
    **Deterministic**: the report becomes reproducible and no implementation must copy
    another implementation's output to conform.
11. **Check-order precedence (S8⑪).** **Chosen** the §14.5 stage order: cryptographic
    checks before lifecycle/semantic ones, and `E_TS_FILE` before `E_TS_RENEWAL`.
    **Deterministic**: a single code per defect; the order is the logical one (a signature
    can only be attributed to a key once it verifies), so no implementation needs another
    implementation's behaviour to reach it.
12. **`verifier` identity (F1, S8⑫).** **Chosen**: informational, excluded from
    cross-implementation comparison; conformance is defined by §14.10. Avoids claiming
    byte identity that cannot exist and fixes no false shared name.
13. **`vectors` report layout (F5, S8⑬).** **Chosen**: `summary` is normative and
    per-case layout and `vectors` input identity are implementation-defined,
    deterministic and path-free. **Deterministic**: no implementer has to copy an
    unobservable shape, and conformance is `mismatched == 0`.
14. **`N_NO_HUMAN_SIGNATURE` precedence (F6, S8⑭).** Readings: the notice also appears
    on the unverifiable signature branches, or only on a valid accepted record.
    **Chosen** only on a `valid` accepted record: reporting a human-signature
    conclusion on a record whose signatures could not be checked would state something
    the verifier did not establish.

Entries 15–19 record five further principle decisions added by revision 1 of the S1-FIX1
round (T11); they carry the status
`decided by principle (Inceptless decision 2026-11-11 #5; T11)`.

15. **`stage` value semantics (§4.1.1).** Readings: the five stage words are opaque closed
    values whose meaning is left to projects, or they have fixed envelope meanings. **Chosen**
    fixed meanings: `proposed` = the actor asserts the claim without having adopted it (not
    "awaiting receiver approval"), `accepted` = the actor adopts it as its current position,
    and similarly `rejected`/`withdrawn`/`superseded`. Reason: a closed vocabulary with no
    meaning cannot support the signer/authorisation rules that key off `accepted`, and the
    alternative lets two implementations disagree on what a `proposed` record asserts. The
    negative clarification ("not awaiting approval") prevents a receiver from reading the
    stage as a workflow state the format does not define.
16. **Registration does not retroactively abandon records (§7.6).** Readings: registering a
    kind re-judges all older records of that kind against the new body rules, or the frozen
    set pins old conclusions and a registration must accept previously exportable bodies.
    **Chosen** the second: a kind page must accept the body shapes its project exported while
    the kind was opaque, and a registration that cannot do so is a breaking change under
    §0.3. Reason: §7.5's additive evolution exists precisely so a verifier never abandons
    older records (K3); the frozen regression set makes the commitment checkable.
17. **Manifest signing key need not be `manifest.origin.instance` (§11.3).** Readings: the
    manifest signature must be by the key named in the manifest origin (publisher binding),
    or the signature only proves which declared key signed the manifest bytes. **Chosen** the
    second, as a documented limitation (T17/A-L8): the verifier checks the equation
    against declared material, the report does not claim a publisher binding, and a consumer
    that needs the binding must pin the key id out of band. Reason: H0 has no ruling that
    establishes the binding, and inventing one would reject valid containers produced by
    systems whose manifest signer is a delegated key. The limitation is stated in §15 so the
    gap is not silent.
18. **Oversized `.tsr` is a container-level `E_JSON_SIZE` (§13).** Readings: an oversized
    timestamp receipt file is an invalid receipt (`E_TS_*` inside the timestamp phase) or a
    container-level size-limit failure. **Chosen** container-level `E_JSON_SIZE`, reported by
    the timestamp phase, with the record verdicts kept. Reason: every §13 limit maps to one
    deterministic code (Q24); the size limit is checked before parsing the file, so calling it
    a receipt format error would report a different check than the one that failed, and the
    timestamp phase runs after the record phase so the already-processed records remain
    reportable (T16).
19. **Retention of `N_READABLE_PRESENT` / `N_PREVIOUS_SIG_UNVERIFIED` after an early
    failure (§14.6).** Readings: notices are reported only from completed stages, or a
    notice about a condition the verifier already observed is kept even if a later check
    fails. **Chosen** the second, and the identical if-and-only-if rule for the limitation
    identifiers. Reason: deterministic information-preserving reporting — the condition is a
    fact of the input, not a passed check, so dropping it after a later failure would make
    the report depend on check ordering and hide a condition the verifier did establish.
    When the condition cannot be determined (for example entry enumeration fails before a
    `readable/` entry is observed), it is not reported.

20. **`(recorded_at, record digest)` order for revocation validity (§9.5, U12/L8).**
    Readings: judge whether a revocation record is valid using revocations ordered by
    `effective_at`, or by the record's own `(recorded_at, record digest)`. **Chosen** the
    recorded order: when judging R, only a revocation ordered strictly before R by
    `(recorded_at, record digest)` participates. Reason: mutual revocations need a
    deterministic fixed point, and ordering by `effective_at` gives none (two revocations
    effective in the same instant would each be invalidated by the other). The trade-off is
    explicit: a revocation recorded later but effective earlier cannot invalidate an
    earlier-recorded revocation. Marked `decided by principle (Inceptless decision
    2026-11-11 #12; U12/L8)`; the specification and the verifier implement this order.

21. **A supplied previous container links the chain only (V3).** Readings: parse the
    supplied previous container exactly like a target container (full evidence), or read only
    the manifest and its attestation file and verify the link. **Chosen** the second: the
    chain needs only the manifest digest and its signature, and narrowing the checked
    surface removes the places where two implementations could disagree; the report states
    the narrowing explicitly with `L_PREVIOUS_CONTENT_UNVERIFIED`, and a party that wants
    the previous container verified runs it as a target. Marked `decided by principle
    (Inceptless decision 2026-11-11 #14; V3)`.
22. **TSA receipts must be strict canonical DER (V2).** Readings: accept lenient/BER-ish
    receipt encodings and only fail later checks, or require strict canonical DER at check
    1. **Chosen** strict DER: exactly one `TimeStampResp` with no trailing data, canonical
    minimal length forms, re-encoding equal to the input, and the fixed version values
    (`SignedData.version` = 3, `SignerInfo.version` ∈ {1, 3}, `TSTInfo.version` = 1); any
    DER decoding or structure failure anywhere in receipt processing is `E_TS_SCHEMA`.
    Reason: the attestation digest of a `.tsr` is not covered by the manifest signature, so
    receipts are attacker-supplied input; one strict profile gives a single deterministic
    code and cannot depend on a parser's tolerance. Marked `decided by principle
    (Inceptless decision 2026-11-11 #14; V2)`.
23. **`record_count` keeps the manifest count (V7/L5).** Readings: reset `record_count` to
    0 when a later container stage fails, or keep the manifest's record count once the
    manifest has parsed and its structure checks have passed. **Chosen** keep it: the count
    is a fact established at the manifest stage, resetting it loses information and made
    implementations disagree on report shape for the same input. It stays 0 only for a
    failure before the manifest structure stage. Marked `decided by principle (Inceptless
    decision 2026-11-11 #14; V7/L5)`.
24. **Which keys and which trust link a supplied previous container (W1).** The ruling
    fixed the context (the target's keyset plus target records, never the previous
    container's own declarations), the key material (the §11.3 required-key definition)
    and the time rule (§9.4 at the previous `created_at`). Two details were left to
    principle. *Trust:* reading A — any key that resolves in the target's final key state,
    including key material that only a self-consistent rotation record supplies; reading B —
    a key with a valid declaration in the target context, or the `old_key` of a valid
    rotation whose `new_key` has a valid declaration. **Chosen B**: a rotation record is
    valid without any trust, so under A two fresh keys could rotate into each other and
    link any previous manifest; under B the successor key's own trusted declaration vouches
    for the predecessor, which is exactly the rotated-key case the ruling names.
    *Compromise:* reading A — judge a `key-compromise` revocation like a retired one,
    against the previous `created_at`: `created_at` before the compromise time `T` links,
    `created_at` at or after `T` is `E_MANIFEST_CHAIN`; reading B — apply §9.4 case 3 as
    for a target manifest signature: a compromised key needs timestamp evidence, the
    previous container's receipts are not read, so every such link breaks. S1-FIX4 chose B
    by principle. **The founder decided A** (Inceptless decision 2026-11-12 #1, X2): the
    previous manifest's digest is already pinned by the target's trusted signature
    (`previous_manifest.digest`), so a key reported compromised later cannot be used to
    substitute that history, while B made every honest exporter's chain break permanently
    from the moment one of its device keys was reported compromised. §11.5 rule 3 now states
    one comparison for every revocation reason, and the sentence that let a compromise
    "always" break the link was removed. *Material:* §11.5 rule 1 also states that a
    rotation record that is not valid supplies no key material for the link (as §5.3 says
    for material in general; X5). The trust part remains `decided by principle (Inceptless
    decision 2026-11-11 #16; W1)`; the compromise part is `decided (Inceptless decision
    2026-11-12 #1; X2)`.
25. **Order inside the previous-manifest-chain stage (W5).** Readings: check the embedded
    previous manifest first and read the supplied previous only when the embedded one
    passes (the limitation then depends on unrelated embedded defects), or read and verify
    the supplied previous first whenever the stage runs. **Chosen** the second for the
    limitation and the suppressed `*_PREVIOUS_SIG_UNVERIFIED` pair, so that
    `L_PREVIOUS_CONTENT_UNVERIFIED` has one criterion; the reported code is still the first
    failing check of a fixed order (embedded size, null-versus-present, embedded manifest,
    supplied previous, digest comparison), which keeps the existing codes. Marked
    `decided by principle (Inceptless decision 2026-11-11 #16; W5)`.
26. **Renewal-chain shape before the per-receipt checks (W6).** The previous text said
    checks 1–13 run before check 14 "over the receipts that passed them". Readings: decode
    every receipt first, or decide the chain shape from the `renews` links first.
    **Chosen** the chain shape first: the expected imprint of a renewal receipt (check 4)
    is defined by its place in the chain, so per-receipt checks cannot be completed before
    the chain is known; the chain shape is decided from the attestation array
    alone. A broken chain therefore reports only `E_TS_RENEWAL`. This is a deterministic
    choice, not a more conservative one (both readings make the container invalid). Marked
    `decided by principle (Inceptless decision 2026-11-11 #16; W6)`. *Note (X5):* this
    rewrote the wording "checks 1–13 run before check 14" that S8⑪ (entry 11) and T3 had
    fixed; the behaviour did not change — the vector
    `integrity-levels/l2-renewal-broken-with-schema-receipt` reported only `E_TS_RENEWAL`
    under the earlier text as well, and no existing vector changed. The wording change is
    kept and recorded here for the founder (Inceptless decision 2026-11-12 #1).
27. **Several `ed25519` entries in one attestation file (W10/L5).** §11.3 said the
    signature is unverifiable when "no entry is a verifiable signature by a declared
    required key" and did not say what happens when one entry verifies and another does
    not. Readings: one verifying entry suffices, or every `ed25519` entry must be by a
    required key and verify. **Chosen** every entry: an extra entry by an undeclared key
    keeps the manifest signature `unverifiable` (`E_KEY_UNKNOWN`), a failing entry is
    `E_MANIFEST_SIG_INVALID`, and a supplied previous attestation follows the same rule
    (`E_MANIFEST_CHAIN`). This is the more conservative reading and the one existing
    verifiers already apply. Marked `decided by principle (Inceptless decision 2026-11-11
    #16; W10/L5)`.
28. **Keyset directory entries (W10/L6).** §14.1 said "the top-level `*.json` files".
    Readings: skip hidden names and non-files silently, or treat every top-level name
    ending in `.json` as a keyset file and reject one that is not a regular file.
    **Chosen** the second: a keyset is the operator's trust statement, and a silently
    skipped entry (a dangling link, a directory named `*.json`) would change which roots
    exist without any signal. A hidden name is read like any other. Marked `decided by
    principle (Inceptless decision 2026-11-11 #16; W10/L6)`.
29. **DER of values whose type is unknown, and of OCTET STRING contents (W3).** Readings:
    exempt values of unknown type from DER checking, or apply the universal DER rules to
    them. **Chosen** apply them, and check a universal SET of unknown type as a SET OF
    (every universal SET in the `TimeStampResp`, CMS and X.509 schemas is one; a SET with
    mixed constructed/primitive context tags would be the only false rejection, and none
    is defined there). The content octets of OCTET STRINGs and BIT STRINGs (certificate
    extension values, signature values) are not re-decoded by check 1; the TSTInfo inside
    `eContent` is checked on its own by check 2. Marked `decided by principle (Inceptless
    decision 2026-11-11 #16; W3)`. *Amended by X1 (decision 2026-11-12 #1):* a value of
    an open type is judged by its TLV framing only (1a) and is never handed to a type
    decoder; its tag class does not matter (`80 01 01` and `5f 81 48 01 01` are valid
    values of an unregistered attribute). See entry 30 for the list of open types.
30. **Which types check 1c decodes (X1).** The ruling fixed that 1c's rules come from
    X.690 and the module definitions only, that DEFAULT values are judged against the
    module definitions, that open types are judged by their framing only and that time
    values are compared raw. It did not list which `ANY DEFINED BY` values the profile
    decodes. Readings: decode every attribute, algorithm-parameter and certificate type
    some library knows (signingTime, counterSignature, RSASSA-PSS parameters, attribute
    certificates…), or decode exactly the types the profile reads. **Chosen** the second:
    the decoded attribute types are `id-contentType`, `id-messageDigest` and
    `id-aa-signingCertificateV2`; `AlgorithmIdentifier.parameters` and every other
    `ANY`/`ANY DEFINED BY` value, the non-`certificate` `CertificateChoices`
    alternatives and the `x400Address` name form are open types (§12.2 1c lists them). A
    list fixed by the specification is the only one two independent implementations can
    agree on; "whatever my library knows" is exactly the dependency X1 removed, and every
    extra decoded type is a further source of false rejections (for example the
    RSASSA-PSS-params DEFAULTs). Marked `decided by principle (Inceptless decision
    2026-11-12 #1; X1)`. *Follow-up, decided (Inceptless decision 2026-11-12 #2; X6):*
    treated as an open type, the `parameters` of the signer's `digestAlgorithm` and
    `signatureAlgorithm` were judged by their framing only, so a receipt whose
    `rsaEncryption` parameters were not `NULL` would have been accepted. The more
    conservative reading was taken: those parameters now have the form fixed per
    algorithm (SHA-2 absent or `NULL`, RFC 5754 §2; `rsaEncryption` `NULL`, RFC 3370
    §3.2; ECDSA absent, RFC 5758 §3.2), listed in §12.2 1c; any other form is
    `E_TS_SCHEMA`. No byte-flip exemption is needed for them. *Corrected (Inceptless
    decision 2026-11-12 #3; X7/M1):* X6 first required `NULL` for sha*WithRSAEncryption
    as well, contrary to RFC 4055 §5 and RFC 5754 §3.2 ("MUST accept the parameters being
    absent as well as present"); those rows are now "absent or `NULL`".
34. **Known open type: `SignedData.digestAlgorithms` parameters (recheck5 L1).** The
    parameters of the algorithm identifiers in `SignedData.digestAlgorithms` are outside
    the signature and read by no check; under X1 they are an open type, judged by their
    framing only, and the byte-flip gate exempts them (`tsr-digest-algorithms`). The
    reason given for X6 (outside the signature, changeable by anyone) applies to them as
    well, but they are deliberately **not** fixed: no check reads them, so two
    implementations following the specification cannot disagree on a verdict. Recorded as
    a known open type (Inceptless decision 2026-11-12 #3).
35. **`SignerInfo.version` must match its `sid` (X7, found by the byte-flip gate).** The
    profile accepted version 1 or 3 with either `sid` form. After X7 the gate found that
    flipping version 1 to 3 in a receipt whose `sid` is `issuerAndSerialNumber` left the
    receipt valid: the field is outside the signature and read only as "1 or 3". Readings:
    exempt that octet in the byte-flip gate, or apply RFC 5652 §5.3 ("If the
    SignerIdentifier is issuerAndSerialNumber, then the version MUST be 1 … if
    subjectKeyIdentifier, then the version MUST be 3"). **Chosen** the second, the more
    conservative reading (the precedent of X6, decision 2026-11-12 #2, which preferred a
    fixed form to a byte-flip exemption): a mismatch is `E_TS_SCHEMA` (check 1d). Marked
    `decided by principle (Inceptless decision 2026-11-12 #3; X7)`; the coordinator may
    reverse it.
31. **Symbolic links among operator paths (X3).** The ruling says the kind of each
    operator path is established with `lstat` before opening. Readings: reject every
    symbolic link (`lstat` alone), or resolve a link and judge its target the same way.
    **Chosen** the second: operator paths are routinely links (a keyset directory kept
    elsewhere), the hazard the ruling addresses is the blocking open of a FIFO or a device,
    and a link to one is rejected as well; a dangling link is a usage error, as it already
    was for keyset entries (entry 28). Marked `decided by principle (Inceptless decision
    2026-11-12 #1; X3)`.
32. **Open: the target manifest signature is judged more leniently than the previous one
    (recheck4 L7).** Since W1 the previous manifest's signing key must be trusted in the
    target's closure, while the target manifest signature itself only needs a required key
    and records a TOFU limitation: a self-made rotation between two fresh keys can carry a
    target manifest signature to `valid` with `L_KEY_TRUST_TOFU` only. Whether the target
    signature should meet the same trust bar is **not decided**; it is left for a later
    round (Inceptless decision 2026-11-12 #1).
33. **Open: §9.4 last paragraph versus §11.3 (recheck4 L7).** §9.4 ends by saying that a
    signature by a key whose declaration is untrusted is `E_KEY_UNKNOWN` and that "this
    applies to manifest signatures as well", while §11.3 says that "a declared but
    untrusted signing key … does not make the manifest signature unverifiable". The
    current implementations follow §11.3. Which sentence governs is **not decided**; it is
    left for a later round (Inceptless decision 2026-11-12 #1).

Status updates in this revision:

- **Q27** (report `input` identity) is refined by S14 and T16: a directory container's
  `input` is the §2.4 manifest digest and byte size once the manifest has parsed and its
  structure validated; before that (structurally invalid manifest or a stop before the
  manifest structure stage) it is the raw `manifest.json` bytes' SHA-256 and size; it is
  `null` for both when the manifest is absent, unreadable or above
  `MAX_MANIFEST_BYTES`, and for a standalone record above `MAX_RECORD_BYTES` (the whole
  file is never read). The `vectors` target report shape is implementation-defined
  (F5/S8⑬).
- **P3** (delegation-chain depth) and **P10** (human-signature notice precedence) are
  resolved and removed from §3; **P7** is narrowed to the `vectors`-target layout
  (F5).
- **F4/F12** limitation prose is replaced by the closed identifier list of §14.9;
  reports carry identifiers only.
- **F13** is a property of the byte constructions (the bytes of `sigs[].alg` are not
  covered by the record digest or signature), not an ambiguity; it is recorded as a
  note in specification §4.3.
- **F17** matcher semantics are stated normatively in specification §14.10 and in
  `vectors/README.md` (the vectors area).

### F1–F17 disposition (ruling S16)

All seventeen findings are adopted; none is silently dropped. The normative locations
are in the specification; the table records the disposition and, where a finding needed
no text change, the reason (specification §14.10 and the kind pages carry the detail).

| finding | disposition | normative location |
|---|---|---|
| F1 | adopted: `verifier` is an informational implementation identity, excluded from cross-implementation comparison | spec §0.2, §14.6 |
| F2 | adopted (mandatory): registry rows shrink to envelope-level; closed nested objects use their owning section's code | spec §4, §4.2, registry `E_ENV_MISSING_FIELD`/`E_ENV_UNKNOWN_FIELD` |
| F3 | adopted: envelope sub-order presence → closedness → grammar, repeated inside nested closed objects | spec §4, §14.5 |
| F4 | adopted via S12: `limitations` is a closed identifier list, not prose | spec §14.6, §14.9, registry `L_*` |
| F5 | adopted: `summary` normative, per-case layout and `vectors` input identity implementation-defined; P7 narrowed | spec §14.6, §14.10; this file §3 P7 |
| F6 | adopted: `N_NO_HUMAN_SIGNATURE` only for a valid `accepted` record; P10 resolved | spec §4.4, §14.5, §14.6 |
| F7 | adopted: a §14.4 blocking condition is terminal for the record, like an error | spec §14.4, §14.5 |
| F8 | adopted: timestamp verification may run before the record stage; reporting/stopping order unchanged | spec §14.5 |
| F9 | adopted: scalar/object fields `null`, list fields `[]`, conditional fields omitted | spec §14.6 |
| F10 | adopted: explicit keyset structural/semantic boundary | spec §14.1 |
| F11 | adopted via S14: `input` is `null` when the manifest identity cannot be read within the limits | spec §14.6 |
| F12 | adopted: report-construction details pinned normatively (TOFU placement, unknown-kind notice, `sigs[].state`, partial `refs[]`, `gen_time`, container defaults, broken-renewal states, serializer micro-decisions) | spec §14.6 |
| F13 | no format change: a property of the byte constructions (`sigs[].alg` bytes are outside the record digest and signature); recorded as a note | spec §4.3, Appendix A |
| F14 | superseded by S13: unknown skip-token is a usage error, not silently ignored | spec §14.1, §14.7 |
| F15 | adopted: `vectors --tsa-trust` default anchor; `--previous` accepts a directory or zip; `--keys`/`--previous` not accepted on `vectors` | spec §14.1 |
| F16 | adopted: a container invalid error stops with `records: []`; manifest signature verification is the cryptographic equation only | spec §14.5, §11.3 |
| F17 | adopted: exact matcher semantics stated normatively | spec §14.10 and `vectors/README.md` |

## 7. The S2 round of revision 3 (decision 2026-11-15 #8)

The S2 round closes the findings of the second implementation recorded in
`docs/h1-findings.md` (F38–F69). Every entry below carries the status `decided by
principle (Inceptless decision 2026-11-15 #8)`: it gives the readings, the chosen one and
why it is the more conservative (or, where neither is more conservative, the one the text
supports). Section 7.2 lists the questions the principle does not settle; they stay open
for the founder and the specification text is unchanged for them.

### 7.1 Decided by principle

1. **§9.4 and the signatures of a key-lifecycle record (F38, F61-1).** Reading A: a
   declaration's self-signature only proves possession and, like a grant judged against
   its own window (S9), is exempt from §9.4. Reading B: §9.4 applies to "signatures made by
   that key", every one. **Chosen B** for the record's own verdict: under A a declaration of
   a compromised key, recorded before the compromise, is valid even when the only receipt
   that could rescue it fails (F61-1, a security defect: a record-level `valid` on a stolen
   key). The cosignatures and a rotation's two signatures are judged the same way. The
   judgement does not remove the record's key facts (§5.3): without them every signature by
   the key would fall to `E_KEY_UNKNOWN` (unverifiable) instead of being judged under the
   key's own lifecycle (`E_KEY_COMPROMISED`, invalid), which is the less conservative
   outcome. Vectors `key-lifecycle/declaration-compromised-*`,
   `declaration-before-own-valid-from`, `declaration-cosigner-retired`,
   `rotation-old-key-retired`.
2. **`sigs[]` when `E_KEY_PUBLIC_KEY` precedes signature verification (F39, F50).**
   Reading A: the malformed `public_key` is found at step (6) as a body defect, after the
   signatures were checked, so `sigs` lists their states. Reading B: T1 places it "before
   any trust judgement", i.e. before step (4). **Chosen B**: the declared key's own material
   is what its self-signature would resolve to, so key resolution cannot run without it;
   no signature check runs and `sigs` is `[]`, and the code wins over every other body
   defect (`body.key` included, F50). Vector `key-lifecycle/declared-public-key-before-body-key`.
3. **TOFU and failed equations (F42).** Records: §14.6 already says "even if that signature
   or the record then fails"; the reference verifier did not count a failed equation and is
   corrected (vector `key-lifecycle/tofu-on-failed-equation`). Manifest and previous
   signatures: §11.5 counts material "that verified the equation". **Chosen**: the literal
   text — a failed manifest equation adds no `L_KEY_TRUST_TOFU`; the container is invalid
   (`E_MANIFEST_SIG_INVALID`) and the failure itself is reported. Both implementations agree.
4. **A structurally invalid reference target (F44).** Tier (a), the target keeps a
   well-formed `origin` and `id`: §6.3 already gives `unverifiable` ("present but … itself
   not valid"). Tier (b), the target's own `origin` or `id` is malformed: reading A, still
   present (`unverifiable`); reading B, it has no identity (`missing`). **Chosen B**: identity
   is the well-formed triple of §4.1/F58; a record without one cannot be "a record with that
   `origin` and `id`". Vectors `container/reference-to-structurally-invalid-target`,
   `container/reference-to-target-with-malformed-origin`.
5. **Presence of the agent-only actor members (F45, F67).** Presence → closedness → grammar
   applies inside `actor`; the agent-only members are required members of an agent actor, so
   their absence is a presence defect reported before any member's grammar. The reference
   verifier checked them member by member and is corrected. Vectors
   `actor/agent-missing-*-before-*`.
6. **§4.4 step 5 for the signer-constrained kinds and the meaning of "declared" (F46,
   F69-4).** §4.4 step 5 says "if any `sigs` entry names a key that is not declared". The
   committed (frozen) vector `sig/unknown-alg` expects `E_SIG_UNVERIFIABLE` for an entry whose
   own key is undeclared while `actor.key` is declared, so the text is reworded to what the
   vectors pin: the required signer key decides. A key named with public material by a
   `weave.key.rotated` record is declared (§9.2 rule 5 calls those members "explicit
   declarations"), the more conservative reading (step 4's invalid dedicated code rather
   than step 5's unverifiable). Vector `key-lifecycle/declared-only-unknown-algorithm-entries`.
7. **Signature entries across steps (4) and (5).** Reading A: each entry is resolved,
   verified and judged before the next, and the first failure stops the layer. Reading B:
   steps (4) and (5) are steps of the record (§14.5) and §4.4 step 2 verifies "every"
   entry. **Chosen B**: an unresolvable key anywhere makes the record `E_KEY_UNKNOWN`; every
   entry is judged and reports its own state; the first failing entry (equation, then
   §9.4) decides the code. Vectors `key-lifecycle/signature-entries-all-judged`,
   `key-lifecycle/signature-key-resolution-before-equation`.
8. **§10.3 when the erasure record and the placeholder do not pair (F48).** Reading A: the
   first failing rule decides. Reading B: the three rules are independent and the stage
   reports every violation (§14.5). **Chosen B**, the more complete report. A placeholder that
   fails §4.5 is an invalid record, not a placeholder (F69). Vector
   `erasure/cross-checks-reported-independently`.
9. **An unlisted `.tsr` (F54) and timestamps under L1 (F56).** §11.3 is explicit for both;
   the reference verifier ignored them and is corrected. The unlisted file is a file-check
   failure of the timestamp phase whatever the level. Vectors `container/unlisted-receipt-file-l0`,
   `integrity-levels/l2-unlisted-receipt-file`, `integrity-levels/l1-lists-timestamp`.
10. **Unlisted, misnamed or too-deep `records/` files (F55 second part, F60).** Reading A for
    depth: the file cannot be parsed, so its digest cannot be confirmed
    (`E_MANIFEST_RECORD_DIGEST`). Reading B: §1.9 makes depth a size violation "like any size
    violation" (`E_JSON_SIZE`). **Chosen B**, the literal §1.9. An oversize file is subject to
    the limit whether or not it is listed (§11.6 item 5, §13, U8). Vectors
    `container/oversize-record-file-misnamed`, `container/record-nesting-above-limit`.
11. **1a: X.690 in full or the list it names (F57, F66).** Reading A: 1a means X.690 for
    every universal TLV (universal tag 0 never occurs; ENUMERATED is an INTEGER;
    EXTERNAL, EMBEDDED PDV and CHARACTER STRING are constructed-only). Reading B: 1a is the
    list it enumerates. **Chosen A** for those three rules, the more conservative (a receipt
    one implementation accepted is rejected), with the list of 1a rules then closed: the
    content of REAL and RELATIVE-OID and the character repertoire of string types stay
    outside 1a, as both implementations already treat them. Vectors `integrity-levels/l2-ts-der-*`.
12. **Rotation key-id grammar (F61-3).** Reading A: a malformed `new_key`/`old_key` is a
    "contradiction" with its public key, `E_KEY_ROTATION_KEYS`. Reading B: the key ids are
    body-table members, `E_KIND_BODY_SCHEMA`. **Chosen B**, decided in the pre-signature
    structural check (so never the unverifiable `E_KEY_UNKNOWN` that key resolution would give).
    Vectors `key-lifecycle/rotation-old-key-malformed`, `rotation-new-key-wrong-type`.
13. **Certificate versions and "decodes as an X.509 certificate" (F62, F63).** Reading A: a
    parsing library decides. Reading B: the RFC 5280 module and X.690 only (X1). **Chosen B**:
    the 1b/1c walk plus the module's version constraints (extensions need v3, unique
    identifiers v2 or v3; versions above v3 are rejected, the conservative side of RFC
    5280's "SHOULD be prepared to accept any version"); open types stay open. The same rule
    judges `--tsa-trust` anchors (the strict side of the anchor-strictness question). Vectors
    `integrity-levels/l2-ts-signer-cert-*`; anchor shapes in the reference verifier's tests.
14. **§5.5.2 step 6 beyond the depth bound (F68).** Step 6 judges "the cited grant and every
    ancestor"; it covers links beyond the bound and precedes step 7. Vectors
    `grant/chain-depth-9-*`, `grant/chain-depth-10-grant-*`.
15. **§5.4 bullet order (F69-3).** Reading A: the list is not an order. Reading B: it is.
    **Chosen B**: the invalid mismatches (grantee, kind/action) precede the unverifiable
    window and revocation state, so a defect that makes the record invalid is never hidden
    behind an unverifiable outcome.
16. **How this round is numbered.** §0.3 now states the rule the history already followed:
    a revision is opened by one decision's rulings and later decisions are rounds of it, so
    the specification stays "revision 3"; the registry counts its own revisions per decision
    (this round is its revision 7).

### 7.2 Open for the founder (not decided; text unchanged)

Each was handed to the founder with both readings, their consequences and a
recommendation; the specification keeps its current text for each until the founder rules
in a later decision.

- **F47** — an erasure whose authorising grant is present but invalid: `E_ERASE_ACTOR`
  (invalid, the reference verifier) or the grant codes (unverifiable, the second verifier).
- **Cosignature and old-key trust after §9.4 (from entry 1)** — whether a declaration whose
  owner cosignature, or a rotation whose old-key signature, fails §9.4 still extends trust
  or supplies material.
- **F69-1, F69-2, F55 first part** — where the §4.4 step-5 outcome and the consent signer
  rule sit inside step (7), and the consent checks against label propagation in step (9).
- **F64** — the key-size and signature-encoding bounds of check 10.
- **F68 open point** — whether steps 1–5 of §5.5.2 are walked beyond the depth bound.
