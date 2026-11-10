<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Decided questions and remaining provisional choices

> **Status: DRAFT (revision 2).** This file records the questions that the
> `weave-record/1` decision draft v0.1 (with correction v0.1.1) left open and how
> H0 resolved them.
>
> **Q1–Q32 are decided** by Inceptless decision **2026-11-10 #34**; **Q33 is
> decided** by Inceptless decision **2026-11-10 #42**. Each entry in §1 carries its
> decision status; its normative form is in [`../spec/`](../spec/), and this page
> only records the question, the decision and the reasoning. A small number of
> *implementation-shape* details were not decided by #34 or #42; they are listed as
> `PROVISIONAL` in §3. P1 and P2 were resolved by #42 and are no longer listed.
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
and are not listed below. The remaining implementation-shape choices keep the
specification's identifiers **P3–P12**; they are marked `PROVISIONAL` and may
change additively without changing the decided behaviours above.

- **P3 — Delegation-chain depth.** The maximum grant delegation depth is 8. A
  grant chain cannot contain a cycle: digest references form a DAG. The depth
  bound applies to the delegation chain only.
- **P4 — Revocation-authority walk depth.** Walking `weave.key.rotated` records
  to find a grant granter's successor for revocation authority stops at depth 8;
  the walk order is implementation shape.
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
- **P7 — Report field shapes.** `container.level_verified` is always `"L0"`,
  `container.anchor_verified` is a boolean for L2, `timestamps[]` entries carry
  `index`, `path`, `state` and `gen_time`, and the `vectors` target summary and
  per-case layout are the shapes described in the specification.
- **P8 — Compromise-revocation rescue comparison.** The S2 rescue requires an
  external timestamp receipt whose `genTime + accuracy` is **strictly before** the
  revocation's `effective_at` (a receipt without an `accuracy` field counts as
  zero; comparison at microsecond precision, with `genTime` reduced to
  milliseconds per the timestamp profile). The rescue exists if at least one
  verified receipt satisfies that strict comparison; the qualifying receipt with
  the smallest `genTime + accuracy` supplies the evidence. The mechanics of that
  comparison are implementation shape.
- **P9 — Scope subset comparison.** Delegation subset checks compare `scope` as
  sets of strings; `scope` does not participate in record-level machine checks
  beyond the subset relation.
- **P10 — Human-signature notice and unverifiable-signature precedence.**
  `N_NO_HUMAN_SIGNATURE` is reported when an `accepted` record has no valid
  signature by a declared human key; its precedence relative to
  `E_SIG_UNVERIFIABLE` is implementation shape.
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
