<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# H1 findings: specification ambiguities and implementation-shape choices

**Status: DRAFT, living document for milestone H1.** This file records the points
where an independent implementation of `weave-record/1` could not determine a
unique answer from the specification text and the committed vectors, together
with the reading H1 adopted and a proposed wording change. It is documentation,
not a ruling: where this file and [`spec/`](../spec/) disagree, the specification
wins, and none of the ambiguities below is silently resolved inside the verifier.

## Purpose

H1 exists to test whether `weave-record/1` is implementable from the
specification and the conformance vectors alone. The Rust verifier was written
under the independence rules in
[`verifiers/rust/ARCHITECTURE.md`](../verifiers/rust/ARCHITECTURE.md): it never
reads the Python reference implementation or the vector generators. Every time
the specification and vectors did not pin one answer, that gap was recorded here
instead of being turned into an implicit convention.

The document has three jobs:

1. list the ambiguities that are **visible from the specification text alone**, so
   maintainers can decide whether to fix the text before v0.1 is accepted;
2. record the **chosen reading** so a later reviewer can audit the Rust verifier
   against a stated interpretation instead of guessing;
3. be the place where the **gate-3 black-box comparison** adds the differences
   that come from the two implementations resolving an ambiguity differently.

## How findings were collected

1. **Implementation from the specification and vectors only.** The Rust
   workstreams implemented the format from [`spec/`](../spec/),
   [`schemas/`](../schemas/) and [`vectors/`](../vectors/), with the independence
   exclusions above. A question that the text did not answer was written down in
   the workstream report and collected here.
2. **Cross-check against the committed vectors.** Each finding states whether a
   committed `vectors/<category>/<case>/expected.json` pins one reading. A vector
   that expects one specific error code for one specific defect pins that case,
   but a vector with a single defect cannot pin the precedence between two
   simultaneous defects.
3. **Gate 3 (two-implementation report comparison).** Only after the Rust
   verifier passes every committed vector, `verifiers/rust/scripts/compare_reports.py`
   runs both implementations as black boxes over every case, normalizes only the
   §14.6 `verifier` identity object, and compares the remaining report bytes. Any
   difference is then classified as a defect in one implementation or as a
   specification ambiguity. Gate 3 ran on 2026-11-11; its result is summarized
   under [Gate-3 observations](#gate-3-observations), and each finding's
   **Python black-box agreement** field states the observed outcome or why the
   committed cases do not exercise it.
4. **Findings from other workstreams.** A workstream that hits an ambiguity sends
   it to the documentation workstream; it is added below and, if it belongs to a
   module, linked from the `registry-notes` scratch section.

A finding is **not** a licence to deviate silently. The Rust verifier follows the
chosen reading; if the reading is later ruled out, the verifier and this
document change together, and a new conformance vector should pin the ruling.

## Reading key

Each finding below has the same fields:

- **Where** — the specification chapter and the exact paragraphs or rows involved.
- **Text** — what the normative text says (short quotes).
- **Possible readings** — the candidate answers an honest implementer could reach.
- **Chosen reading and why** — the reading H1 adopted and the argument for it. The
  Rust verifier implements this reading.
- **Vector pinning** — whether and how a committed vector pins an answer.
- **Python black-box agreement** — the observed gate-3 outcome for this finding,
  or the reason the committed comparison cases do not exercise it.
- **Proposed wording change** — the smallest change that would remove the
  ambiguity. Proposals are suggestions to the maintainers, not edits made by H1.

## Specification-text findings

### F1 — The report carries implementation identity, so reports cannot be byte-identical across implementations

- **Where.** §14.6 "Report format" (the example report object and the report
  rules), §0.2 (the term *verifier* names the H0 Python verifier
  `hyphaweave-verify`), §14 (implementation conformance), §14.10 (conformance is
  defined by the vectors).
- **Text.** The §14.6 example contains
  `"verifier": {"name": "hyphaweave-verify-python", "version": "0.1.0"}`. No
  report rule defines the `verifier` member: it is not listed as required, its
  shape is not stated, and its relation to conformance is not stated. The name in
  the example (`hyphaweave-verify-python`) also differs from the name in §0.2
  (`hyphaweave-verify`). §14 says independent implementations "must agree on
  every vector", and §14.10 defines conformance as matching each case's expected
  verdict/errors/resolution — it does not require byte-identical reports.
- **Possible readings.**
  (a) The `verifier` object is required and its values are implementation-defined;
  therefore two conforming implementations can never print identical bytes and any
  literal report comparison must normalize this member.
  (b) The `verifier` member is part of the illustrative example only, so an
  implementation may omit it; a report with it and a report without are then both
  conforming, with the same consequence for byte comparison.
  (c) Reports must be byte-identical across implementations at the §14.6
  serialization level, which is impossible with (a) or (b) unless the member is
  fixed by the specification.
- **Chosen reading and why.** (a) for the member's presence: H1 prints
  `"verifier": {"name": "hyphaweave-verify-rs", "version": "<crate version>"}`,
  using stable constants (`VERIFIER_NAME`, `VERIFIER_VERSION` in the library), so
  the report is self-describing and deterministic per implementation. For
  conformance, H1 follows §14.10: a verifier conforms by matching the vectors'
  conclusions, not by matching another implementation's report bytes. The gate-3
  comparison therefore compares report bytes **only after** replacing
  `verifier.name` and `verifier.version` with the constant `"normalized"`.
  Reason: the member is needed for a human-readable report and for reproducing
  which implementation produced a report; fixing its value cross-implementation
  would be a lie about implementation identity, and dropping it would contradict
  the §14.6 example.
- **Vector pinning.** No committed vector pins the `verifier` member or any other
  report byte: expected conclusions are verdicts, error/notice sets, digests,
  reference resolutions, container subsets and per-record subsets. The
  `vectors` target does not compare report prose. Not pinned.
- **Python black-box agreement.** Observed in gate 3: after normalizing
  `verifier.name`/`verifier.version`, every non-F11 report was byte-identical;
  without the normalization the reports differ exactly on those identity values
  (that is why the gate normalizes them).
- **Proposed wording change.** Add a report rule to §14.6: "The `verifier` object
  identifies the implementation: `name` is a stable identifier for the
  implementation and `version` its version. It is informational and is outside
  cross-implementation comparison; a comparison of two implementations' reports
  normalizes `verifier.name` and `verifier.version`. Byte-identical reports are
  not a conformance requirement; conformance is defined by §14.10." Also align the
  example name with §0.2 (either rename the example to `hyphaweave-verify` or state
  that `hyphaweave-verify-python` is the report identity).

### F2 — `E_ENV_UNKNOWN_FIELD` versus the dedicated closed-object codes, including a registry/spec contradiction

- **Where.** §4 (envelope closedness), §4.1 (top-level member table), §4.2
  (`actor`), §4.5 (`weave.erased` special shape), §6.1 (reference object), §8.1
  (`labels`), §11.2 (`manifest.json`), §11.3 (attestation file), and the
  `E_ENV_MISSING_FIELD`/`E_ENV_UNKNOWN_FIELD`/`E_ENV_ORIGIN`/`E_ENV_ACTOR`/
  `E_ENV_LABELS`/`E_ENV_REFS` rows of [`spec/error-codes.md`](../spec/error-codes.md).
- **Text.** §4: "Its top-level members are **closed**: a member not listed in the
  table below is `E_ENV_UNKNOWN_FIELD` ... Unknown members inside `body` are
  permitted ...; unknown members inside `origin`, `actor`, `labels`, reference
  objects and `sigs` entries are errors, because those objects are closed." The
  per-object sections assign their own codes: `origin` "otherwise
  `E_ENV_ORIGIN`" (§4.1), `actor` errors `E_ENV_ACTOR*` (§4.2), `labels`
  "otherwise `E_ENV_LABELS`" and "Unknown members of `labels` are
  `E_ENV_LABELS`" (§4.1, §8.1), `refs` "otherwise `E_ENV_REFS`" (§4.1, §6.1).
  §4.5: "every structural violation of the placeholder is `E_KIND_BODY_SCHEMA` —
  missing member, unknown extra member, wrong member type ... `E_ENV_MISSING_FIELD`
  and `E_ENV_UNKNOWN_FIELD` apply to the normal envelope only and are not used for
  `weave.erased`". §11.2: manifest "unknown members are `E_MANIFEST_SCHEMA`".
  However the registry row for `E_ENV_UNKNOWN_FIELD` says it covers "a closed
  nested object: origin, actor, labels, reference, **manifestation entry,
  attestation file**, `weave.erased` placeholder" — directly contradicting §4.5
  and §11.2/§11.3 — and the `E_ENV_MISSING_FIELD` row says it also covers "a
  required member of a closed nested object with envelope-level codes". A related
  sub-case: a *missing* member inside a closed nested object has no obvious code
  either (`actor` missing `key` is `E_ENV_ACTOR_KEY` or `E_ENV_MISSING_FIELD`?),
  and a malformed reference object nested in `actor.grant` can be `E_ENV_REFS`
  (reference-object grammar) or `E_ENV_ACTOR` (actor structure).
- **Possible readings.**
  (a) The section that owns the object assigns the code; `E_ENV_UNKNOWN_FIELD` is
  only for unknown *top-level* envelope members and for nested objects that have
  no dedicated code, and `E_ENV_MISSING_FIELD` likewise only for top-level
  required members (per-object "missing" codes such as
  `E_ENV_ACTOR_MODEL_MISSING` support this).
  (b) The registry rows win: any unknown member anywhere in a closed object is
  `E_ENV_UNKNOWN_FIELD`, including the placeholder, manifest entries and the
  attestation file.
  (c) The registry list is illustrative and the per-object codes apply, except
  that the placeholder/manifest/attestation mentions are mistakes that should be
  removed; either way the text must be reconciled.
- **Chosen reading and why.** (a)+(c): the enclosing section's dedicated code
  wins; `E_ENV_UNKNOWN_FIELD`/`E_ENV_MISSING_FIELD` are envelope-level codes for
  the normal envelope, and nested closed objects report their own code
  (`E_ENV_ORIGIN`, `E_ENV_ACTOR*`, `E_ENV_REFS`, `E_ENV_LABELS`, and
  `E_KIND_BODY_SCHEMA` for the placeholder; `E_MANIFEST_SCHEMA` for manifest and
  attestation-file members). Reason: the dedicated codes carry more information,
  the closedness requirement is identical either way, the most specific sections
  (§4.5, §11.2) state the rule for the object they own, and the committed vectors
  already follow this reading where they exist: `labels/unknown-label-member`
  expects `E_ENV_LABELS`, `actor/human-with-agent-members` expects
  `E_ENV_ACTOR`, `stage/unknown-envelope-member` expects `E_ENV_UNKNOWN_FIELD` for
  the top-level case, `stage/bad-origin` expects `E_ENV_ORIGIN`. The malformed
  reference nested in `actor.grant` follows the reference-object grammar, so H1
  reports `E_ENV_REFS` there.
- **Vector pinning.** Partially pinned. Pinned: unknown top-level member
  (`stage/unknown-envelope-member`), unknown `labels` member
  (`labels/unknown-label-member`), forbidden `actor` member
  (`actor/human-with-agent-members`), malformed `origin` (`stage/bad-origin`),
  reference-object grammar and list defects (`ref/bad-rel`,
  `ref/bad-hint-scheme`, `ref/too-many-hints`, `ref/duplicate-refs` pin
  `E_ENV_REFS` for reference defects, but not the unknown-member sub-case).
  Not pinned: unknown member inside `origin`, reference object, `weave.erased`
  placeholder, manifest entry or attestation file; a missing member inside a
  closed nested object; the malformed-`actor.grant` code.
- **Python black-box agreement.** Observed in gate 3: no difference on the
  committed corpus. Only the vector-pinned subset is represented there, so the
  comparison does not exercise the unpinned nested-object combinations.
- **Proposed wording change.** Rewrite the two registry rows: `E_ENV_UNKNOWN_FIELD`
  = "a member not defined for the top-level envelope is present" (delete the
  parenthetical list), `E_ENV_MISSING_FIELD` = "a required top-level envelope
  member is absent" (delete "or a required member of a closed nested object").
  Add one sentence to §4: "Inside a closed nested object, a missing or unknown
  member reports that object's code from the section that defines it
  (§4.1, §4.2, §6.1, §8.1, §11.2, §11.3; §4.5 for `weave.erased`)." Add a
  sentence to §4.2 for the `actor.grant` reference object: "a malformed
  reference object in `actor.grant` is `E_ENV_REFS`."

### F3 — Envelope-structure sub-check order is not fixed, so a record with two defects has no determinable code

- **Where.** §14.5 "Deterministic check order" (per-record step (2) "envelope
  structure"; "report at most one error per record: the first failing check in
  the order below (later checks are not run for that record)"), §4.1 member
  table, [`spec/error-codes.md`](../spec/error-codes.md) "Check-order rules" (the
  per-record order is enumerated but "envelope" is one stage) and the note "Error
  codes are compared as a set; order is not meaningful".
- **Text.** The per-record order fixes ten stages, but envelope structure is one
  stage inside which several checks happen: required top-level members present,
  top-level closedness, then per-member grammar. The report carries exactly one
  error per record (§14.5), so the order *inside* the stage decides the code. The
  registry note that codes are "compared as a set" concerns comparing reported
  codes with expectations, not choosing which single code to report.
- **Possible readings.**
  (a) Check required members first (missing → `E_ENV_MISSING_FIELD`), then
  closedness (unknown → `E_ENV_UNKNOWN_FIELD`), then each present member in
  §4.1 table order.
  (b) Check closedness first (unknown member wins over a missing member).
  (c) Report the code of whichever check happens to run first in an
  implementation; both are conforming because the order is not stated.
  (c) cannot be right in practice: the vector contract compares the exact error
  set, so two conforming verifiers would disagree on such a record.
- **Chosen reading and why.** (a). H1's envelope parser performs the required-member
  presence loop over the §4.1 table order first, then the unknown-member check,
  then the per-member grammar checks in §4.1 table order; nested closed objects do
  the same within themselves (presence, closedness, then their member order). A
  record missing `stage` and carrying `extra` therefore reports
  `E_ENV_MISSING_FIELD`. Reason: required-member absence is the coarsest defect,
  the table lists the required members before the per-member rules, and this is
  the only order that makes "at most one error per record" deterministic without
  inventing a per-case rule. The same reasoning fixes missing-versus-unknown inside
  a closed nested object once F2 decides the code family.
- **Vector pinning.** Not pinned for multi-defect records. The committed vectors
  pin each single-defect outcome only: `stage/missing-stage` (missing member),
  `stage/unknown-envelope-member` (unknown member), `stage/bad-origin` (grammar),
  `actor/invalid-actor-type`, etc. No committed vector carries two simultaneous
  envelope defects, and the Rust source carries a comment recording exactly that
  gap for the missing/unknown pair.
- **Python black-box agreement.** Not exercised in gate 3: every committed case
  has a single envelope defect, so no comparison pair distinguishes the readings.
- **Proposed wording change.** Extend §14.5 step (2): "Within envelope structure:
  required top-level members first in the §4.1 table order
  (`E_ENV_MISSING_FIELD`), then top-level closedness (`E_ENV_UNKNOWN_FIELD`), then
  each present member's grammar in the §4.1 table order; a closed nested object
  applies the same presence-then-closedness-then-grammar order inside itself and
  reports its own code." Add a multi-defect vector (for example a record missing
  `stage` and carrying an unknown top-level member) once the ruling is made.

### F4 — `limitations` prose is not fixed, so even semantically equal reports can differ in bytes

- **Where.** §14.6 (the example's `"limitations": ["..."]` and the report rules),
  §14.9 "Limitations reporting", §14.4 (report the gap in `limitations`).
- **Text.** §14.9: "Every report lists what was not verified. At minimum, when
  applicable: an unverified L1 chain claim; an unverified or absent L2 timestamp
  trust; keys trusted only through context declarations rather than the local
  keyset; untrusted self-attested declarations; unresolved authorisation or
  consent; unknown kinds not understood; continuous multi-container chains out of
  scope. A verifier MUST NOT phrase a limitation as a passed check." No wording,
  ordering, deduplication, casing or per-record versus per-report placement is
  fixed, and §14.6 does not restrict the member's content beyond the
  no-environment-values rule.
- **Possible readings.**
  (a) `limitations` is human-readable prose with an implementation-defined
  vocabulary; it is not part of cross-implementation comparison.
  (b) The "at minimum" list is a closed set of sentences whose wording must be
  derived from the list itself, so two implementations must produce the same
  strings.
- **Chosen reading and why.** (a): the prose is implementation-defined and not
  part of the format's conformance surface. The specification fixes *what must be
  disclosed* (§14.9's minimum categories), not *how it is written*; a closed
  vocabulary would be a new normative surface and should be decided deliberately.
  In practice H1 aligned its `limitations` strings and ordering to the reference
  verifier during gate-3 integration so that the byte comparison is meaningful
  (the concrete alignment is recorded in F12 item 1); that is an empirical
  choice, not a specification ruling. Gate 3 still normalizes only `verifier`
  (F1), so a future wording change on either side would surface as a case
  difference and have to be classified and allow-listed.
- **Vector pinning.** Not pinned. The vector matcher does not look at
  `limitations` at all (`vectors/README.md` lists the matched fields). No
  committed vector asserts a limitation string.
- **Python black-box agreement.** Observed in gate 3: zero differences on the
  committed corpus after the alignment in F12 item 1; the two allow-listed
  differences are F11 identity cases, not limitation prose.
- **Proposed wording change.** Add one sentence to §14.9: "The `limitations` array
  is implementation-defined human-readable prose; its content is not part of
  cross-implementation comparison, and it MUST remain deterministic and free of
  paths, times, environment values and claims that a check passed." If a fixed
  vocabulary is wanted instead, define the sentence set and its ordering here.

### F5 — P7: the `vectors` report layout and its `input` identity are explicitly PROVISIONAL

- **Where.** §14.6 (the `vectors` target bullet: summary shape fixed, "the exact
  field layout of that array is an implementation shape (PROVISIONAL, Appendix A
  P7)"), §14.6 `input` bullet (record / zip / directory only), Appendix A P7,
  [`docs/open-questions.md`](../docs/open-questions.md) §3 P7, Q27.
- **Text.** "For the `vectors` target, `summary` is `{"case_count": N, "matched":
  n, "mismatched": m}` and per-case results are listed in a deterministic,
  path-free array; the exact field layout of that array is an implementation
  shape (PROVISIONAL, Appendix A P7)." The `input.sha256`/`input.size` rule is
  stated only for record, zip and directory targets; it does not say what a
  `vectors` report's input identity commits to.
- **Possible readings.**
  (a) The vectors report is semantically comparable only through `summary` and
  the top-level verdict; per-case layout, discovery rules and the vectors input
  identity are implementation-defined.
  (b) The layout is fixed by the H0 Python implementation's output, and an
  independent implementation must copy it; but that output is not available to an
  implementer who follows the independence rules, so this reading is
  unenforceable.
  (c) The runner must at least agree on what counts as one case and on the
  directory depth at which cases are discovered, because `case_count` is part of
  the report and different discovery would run a different set of cases.
- **Chosen reading and why.** (a)+(c). H1's provisional vectors report uses
  `cases: [{"id", "matched", "expected", "actual"}]` in sorted case-id order and a
  path-free, deterministic input identity: `input.sha256` is the SHA-256 digest
  string of the sorted `expected.json` `id` list joined with a single `\n` (no
  trailing newline), and `input.size` is that byte length. Discovery is exactly
  `<category>/<case>/expected.json` two directory levels below the directory
  argument, in sorted relative-path order, so the main corpus is 294 cases and
  the frozen candidate set is a **separate** run (179 cases), never a nested part
  of the main run. The library documents the report shape as PROVISIONAL.
  Consequence for gate 3: the gate compares **per-case** `record`/`container`
  reports, whose §14.6 shape is stable, not the two implementations' `vectors`
  reports; the latter may legitimately differ in layout and input identity. This
  finding was contributed by the CLI workstream (which owns the vectors runner)
  and checked by the documentation workstream against `vectors/index.json`
  (`case_count` 294) and `vectors/frozen/v0.1-candidate/FROZEN_CASE_COUNT` (179).
- **Vector pinning.** No committed vector pins the `vectors` report shape or the
  input identity. The *discovery sets* are pinned indirectly: `vectors/index.json`
  lists all 294 main-corpus cases, and the frozen candidate set has its case count
  plus a SHA-256 manifest over every file, so adding or removing a case turns
  those checks red.
- **Python black-box agreement.** Not applicable by design: gate 3 compares only
  per-case `record`/`container` reports, so the two implementations' `vectors`
  reports were never compared byte-for-byte (their layouts are free).
- **Proposed wording change.** Replace the P7 sentence in §14.6 with: "For the
  `vectors` target, `summary` is normative. The per-case array layout and the
  `input` identity representation are implementation-defined and MUST be
  deterministic and path-free; they are not compared across implementations.
  Conformance for this target is `mismatched == 0`." Update P7 in Appendix A and
  `docs/open-questions.md` accordingly, and either move the vectors input identity
  out of P7 or state the Q27 ruling for it.

### F6 — P10: `N_NO_HUMAN_SIGNATURE` versus `E_SIG_UNVERIFIABLE`

- **Where.** §4.4 "Required-signature error precedence" and "Human-signature
  notice"; §14.5 last paragraph of the per-record order; Appendix A P10.
- **Text.** §4.4: "An `accepted` record that has no valid signature made by a key
  declared `human` in the verification context is still valid and MUST carry the
  notice `N_NO_HUMAN_SIGNATURE` ... The exact interaction of this notice with step
  5 above is an implementation-shape detail (PROVISIONAL, Appendix A P10)." Step
  5 is the branch where no verifiable required signature exists: the record is
  `unverifiable` with `E_KEY_UNKNOWN` or `E_SIG_UNVERIFIABLE`.
- **Possible readings.**
  (a) The notice is reported only when the record is otherwise valid (the
  "is still valid" condition in §4.4 is read as a precondition).
  (b) The notice is reported whenever an `accepted` record has no valid human
  signature, including records that become `unverifiable` for signature reasons;
  the record has both a notice and the `E_SIG_UNVERIFIABLE`/`E_KEY_UNKNOWN` code.
  (c) The notice is suppressed when signature verification cannot complete at all,
  because no signature state (and therefore no human-signature conclusion) can be
  established.
- **Chosen reading and why.** (a)/(c): H1 reports `N_NO_HUMAN_SIGNATURE` only for
  a record that is `accepted` and otherwise valid, and does not report it on the
  step-5 branches where the record is already `unverifiable` (`E_KEY_UNKNOWN` or
  `E_SIG_UNVERIFIABLE`). Reason: the notice is the report-side counterpart of a
  valid human act; §4.4 frames it with "is still valid", and reporting a
  human-signature conclusion on a record whose signatures could not be checked
  would state something the verifier did not establish. The registry note that
  notices do not by themselves change a verdict does not decide this, which is
  why it is PROVISIONAL.
- **Vector pinning.** Partially pinned for the positive direction: the container
  cases `actor/agent-accepted-valid` and `erasure/actor-program-with-grant-valid`
  require `N_NO_HUMAN_SIGNATURE` on valid accepted agent/program records
  (notices are matched as a subset). The negative interaction is not pinned:
  `sig/unknown-alg` expects `E_SIG_UNVERIFIABLE` but does not assert the absence
  of the notice, because notices matching is subset-only.
- **Python black-box agreement.** Observed in gate 3: the committed positive
  notice cases agreed; the unpinned negative interaction is not asserted by any
  fixture, so the comparison cannot distinguish the readings.
- **Proposed wording change.** Resolve P10 in §4.4: "The notice is reported only
  for a record that is `accepted` and whose verdict is `valid`; when the required
  signature check makes the record `unverifiable`, that outcome is reported
  instead and the notice is not." Add a vector for the negative interaction with
  the expected notice set (the matcher is subset-only today, so this needs an
  "exact notices" option or a case-level `notices_absent` clause).

### F7 — Do §14.4 blocking conditions stop later per-record checks?

- **Where.** §14.5 (per-record order and "at most one error per record: the first
  failing check ... later checks are not run"), §14.3 (verdict precedence
  `invalid` over `unverifiable`), §14.4 (blocking conditions that force
  `unverifiable`), §14.5 container rule ("an `unverifiable` container condition
  does not stop record processing").
- **Text.** §14.5 says later checks are not run after the first failing check, but
  the §14.4 blocking conditions are described as conditions that "MUST NOT lead to
  `valid`", not as errors. §14.3 says a record is "`invalid` if any error; else
  `unverifiable` if a blocking condition of §14.4 is present; else `valid`". The
  container rule explicitly says an unverifiable container condition does not stop
  record processing; there is no corresponding statement for a record.
- **Possible readings.**
  (a) A blocking condition is terminal exactly like an error: the record pipeline
  stops at it, that code is reported (in `records[].errors`, as the vectors do),
  and no later check runs. A record with an unknown key and a later invalid kind
  body is `unverifiable`, not `invalid`.
  (b) A blocking condition is not a "failing check": the pipeline continues, later
  errors are found, and `invalid` wins by §14.3; possibly both the blocking code
  and the later error are reported (which conflicts with "at most one error per
  record" unless the blocking code is not counted as an error).
- **Chosen reading and why.** (a). H1 stops the record pipeline at the first
  outcome, whether it is an error code or a §14.4 blocking code, and reports one
  code. Reason: §14.5's "later checks are not run for that record" is explicit and
  makes the promise "at most one error per record" implementable; the container
  sentence is a deliberate, explicit exception that would be unnecessary if the
  default were to continue. Reading (b) would make a record's report depend on
  defects that the specified order says are never examined.
- **Vector pinning.** Not pinned for the combined case. Every committed negative
  vector either carries an error or an unverifiable blocking condition, not both;
  a vector that expects only `E_KEY_UNKNOWN` and contains a later kind-body defect
  would pin (a). The single-defect unverifiable vectors (`sig/undeclared-key`,
  `sig/unknown-alg`, `actor/agent-grant-unresolved`) are consistent with (a) but
  do not distinguish the readings.
- **Python black-box agreement.** Not exercised in gate 3: no committed case
  combines a blocking condition with a later error, so the comparison cannot
  distinguish the readings.
- **Proposed wording change.** Add to §14.4 (or §14.5): "A condition in this
  section is terminal for the record exactly like an error: the verifier reports
  that code, stops the record's remaining checks, and reports no later error; the
  record is `unverifiable`. The codes in this section are carried in
  `records[].errors` and count as the record's single reported code." Add a
  multi-defect vector once the ruling is made.

### F8 — The container check order puts timestamp verification after the record checks that depend on it

- **Where.** §14.5 (container order steps (7) records and (11) timestamps), §9.4
  (key-compromise rescue needs verified trusted timestamp evidence), §12.5
  (timestamp outcomes and the container verdict), §14.4.
- **Text.** §14.5 fixes the container order as "(7) records listing and
  per-record verification; (8) cross-record state rules; (9) blobs; (10)
  previous-manifest chain; (11) timestamps; (12) aggregation" and says a
  container-level invalid error before check (7) stops record processing while an
  unverifiable container condition does not. §9.4 requires a **verified, trusted**
  RFC 3161 receipt (`genTime + accuracy < T`) to rescue a signature by a
  `key-compromise`-revoked key, and §12.5 defines when receipts are verified and
  trusted.
- **Possible readings.**
  (a) Timestamps are verified before per-record evaluation as a data dependency,
  because record outcomes (§9.4) cannot be decided without them; the reported
  container-level check order and the stop rules are unchanged (the timestamp
  evidence is computed early, its errors are carried in `container.errors` and do
  not stop record processing).
  (b) The literal order is followed: records are decided first without the
  timestamp evidence, so a compromised-key record in a container is judged as if
  no receipt were available (invalid `E_KEY_COMPROMISED`) or the record checks are
  deferred/re-evaluated after (11).
  (c) The order text is a mistake and should be changed to put timestamps before
  records.
- **Chosen reading and why.** (a), which is also the H1 architecture contract:
  verify the timestamp chain early (it is needed as input), then evaluate records,
  and report container errors/notices in the §14.5 order. Reason: reading (b)
  contradicts §9.4 and the committed vectors — for example
  `key-lifecycle/compromise-rescued-by-timestamp` requires the record to be
  `valid` because of a verified timestamp, and
  `key-lifecycle/compromise-untrusted-timestamp` requires the record to be
  `unverifiable` with `E_TS_UNTRUSTED`; neither outcome can be produced by a
  verifier that does not know the timestamp result at record-evaluation time.
  Reading (a) also preserves the stated report behaviour (the timestamp failure is
  a container error, and an unverifiable container condition does not stop record
  processing).
- **Vector pinning.** Effectively pinned by the joint expectations of
  `key-lifecycle/compromise-rescued-by-timestamp`,
  `key-lifecycle/compromise-untrusted-timestamp` and the
  `integrity-levels/l2-*` cases: they pin the record verdicts that depend on
  timestamp evidence, though they do not pin the wording of the order.
- **Python black-box agreement.** Observed in gate 3: the joint timestamp /
  compromise cases agreed (after the Rust timestamp-report fixes recorded in the
  gate-3 section); a difference here would have been a spec-unique-answer bug in
  one implementation.
- **Proposed wording change.** Add a note to §14.5 after the container order:
  "Timestamp verification may be performed before step (7) because §9.4 uses the
  verified receipt chain as evidence for record outcomes; a timestamp failure is
  still reported as a container-level error and does not stop record processing.
  The listed order governs reporting and stopping, not the internal computation
  order." Alternatively move timestamps to step (7) and records to step (8) in the
  list, keeping the container-error semantics explicit.

### F9 — Undetermined report fields: `null`, empty array/object, or omitted?

- **Where.** §14.6 report rules ("A field whose value cannot be determined because
  the input failed earlier in the check order is reported as JSON `null`; a report
  never invents a value and never omits a `records[]` entry that the container
  manifest or the target requires"), the §14.6 example report object, §14.6
  bullets that make `container` present only for containers and the placeholder's
  `attestation` optional.
- **Text.** The rule says "a field ... is reported as JSON `null`", but the
  example types several fields as arrays (`refs`, `sigs`, `errors`, `notices`,
  `limitations`) and makes one object conditional (`container` only for container
  targets); the placeholder's `attestation` is explicitly optional. For a record
  target whose bytes fail canonical parsing (§14.5 step (1)), `records` must still
  hold one entry, but the type of each undetermined field is not stated: is
  `refs` `null` (one "unknown" value) or `[]` (type-stable, ambiguously "no
  refs")? Does `kind_known` become `null`? Are `container`/`attestation` omitted
  or `null`?
- **Possible readings.**
  (a) Type-stable: every field present with its example type; undetermined
  scalars/objects are `null`, undetermined list fields are `[]`; only fields the
  specification marks optional are omitted.
  (b) Undetermined means `null`, even for list fields (so `refs: null`).
  (c) Omit any undetermined field (contradicts "reported as JSON `null`" and the
  stable report shape).
- **Chosen reading and why.** (a), for H1: scalar and object fields render
  `null` when undetermined (`digest`, `id`, `kind`, `stage`, `origin`,
  `kind_known`, `created_at`, `manifest_digest`, `level_claimed`,
  `level_verified`, `anchor_verified`, `chain`, `previous_manifest_digest`,
  `record_count`), list fields render `[]` (`errors`, `notices`, `refs`, `sigs`,
  `timestamps`, `limitations`, `cases`), `container` appears only for a container
  target, and `attestation` appears only when a placeholder carries one. Reason:
  it keeps the report schema stable for consumers (the §14.6 example fixes the
  array/object types), avoids inventing values for scalars, and follows the only
  two explicit presence rules in §14.6. The `refs: []` choice is semantically
  "unknown" only for records that failed before reference parsing, which the
  record's `verdict`/`errors` already communicate.
- **Vector pinning.** Not pinned. The vector matcher checks verdict, error sets,
  notices, digest, resolution, container subset and per-record subsets; it never
  asserts `null` versus `[]` versus omission, and no committed vector snapshot
  records report bytes.
- **Python black-box agreement.** Observed in gate 3: the early-failed record
  entries (`jcs/*` canonical-form failures and envelope failures) agreed on the
  null/empty/omission shape; the container-report default details are in F12
  item 7. Only the two F11 identity cases differ.
- **Proposed wording change.** Add a rule to §14.6: "A field whose value could not
  be determined because the input failed earlier in the check order is `null` for
  scalar and object fields and `[]` for list fields; a field is omitted only where
  this section says it is conditional (`container` for non-container targets,
  `attestation` for non-placeholder records, `cases` for non-`vectors` targets).
  The report's field set and types are stable." Add a report-shape snapshot (or a
  few explicit cases) to the vectors once the rule is fixed.

### F10 — §14.1 keyset: which defects are a usage error (exit 2) and which merely fail to establish trust?

- **Where.** §14.1 `--keys <dir>` bullet, §14.8 exit codes, §9.4/§5.3 trust
  rules.
- **Text.** "Each file MUST be a structurally valid record under this
  specification (canonical bytes, envelope, signatures where present, kind body
  and the kind's self-consistency rules); a file that is not such a record is a
  usage error (exit 2). A record that parses and is structurally valid but fails
  semantic or cryptographic checks does not establish trust; that is not a usage
  error."
- **Possible readings.**
  (a) "Structurally valid" means the code categories up to and including shape
  checks: canonical JSON, envelope structure/grammar, `sigs` presence/format,
  registered-kind body schema. A keyset file that fails one of those is exit 2;
  a file whose first failure is semantic (kind semantics, key lifecycle state,
  authorisation) or cryptographic (signature verification, key trust) is
  structurally valid but unusable as trust input, so it is ignored rather than
  fatal.
  (b) Any error in a keyset record is a usage error (exit 2), because the text
  lists "signatures where present, kind body and the kind's self-consistency
  rules".
  (c) Only unreadable/non-JSON files are usage errors; all record-level errors
  are ignored.
- **Chosen reading and why.** (a). H1's keyset loader runs each keyset file
  through the same §14.5 pipeline; if the record's first reported code is one of
  the parse/canonical/envelope/`sigs`-grammar/kind-schema group, the keyset is a
  usage error (exit 2); if the first failure is kind semantics, key lifecycle,
  actor, authorisation or signature verification, the file is treated as a record
  that does not establish trust and its keys are not usable (no exit 2). This is
  the reading the implementation records as its interpretation; the boundary is
  not exercised by committed vectors, so it should be confirmed with maintainers
  before it is relied on. Reason: the parenthetical in §14.1 mixes structural
  words ("signatures where present") with semantic ones ("kind's
  self-consistency rules"), so a line must be drawn; the "fails semantic or
  cryptographic checks ... is not a usage error" sentence puts semantic and
  cryptographic failures explicitly on the non-fatal side, and the structural
  side is naturally the code families that describe shape.
- **Vector pinning.** Not pinned: every committed case's `@keyset` points at the
  valid committed keyset, so no vector exercises an invalid keyset file. Gate 3
  uses the same committed cases, so it will not exercise this either.
- **Python black-box agreement.** Not exercised: every gate-3 comparison case
  uses the committed (valid) keyset, so the invalid-keyset boundary was never
  compared. It is recorded here so the boundary is a deliberate choice; a
  dedicated test would be needed to compare behaviour.
- **Proposed wording change.** Replace the parenthetical with an explicit
  boundary: "A keyset file whose canonical form, envelope structure, `sigs`
  format, or registered-kind body *schema* is invalid is a usage error (exit 2).
  A keyset record that is structurally valid but fails a kind semantic rule, a
  key-lifecycle, actor, authorisation or cryptographic check does not establish
  trust and is ignored; it is not a usage error." List the code families that
  count as structural (or, better, define them as the failures of checks (1)–(3)
  and (6) of §14.5). Add tests for both sides of the boundary.


### F11 — A directory container's `input` identity is undefined when the manifest is missing or unreadable

- **Where.** §14.6 report rules (`input.sha256`/`input.size`), Q27 decision.
  The specification says that for a directory container `input` identifies "the
  manifest digest and manifest byte size" (Q27 decided (Inceptless decision
  2026-11-10 #34; Q27)).
- **Text.** The same paragraph requires that "a field whose value cannot be
  determined because the input failed earlier in the check order is reported as
  JSON `null`". When `manifest.json` is absent (`E_MANIFEST_MISSING`) or cannot
  be read, the rule's subject does not exist.
- **Possible readings.** (a) `input` is `null`/zero; (b) `input` identifies the
  raw `manifest.json` bytes when any exist and is arbitrary implementation
  detail otherwise; (c) `input` identifies a deterministic snapshot of the
  directory (relative paths and file digests); (d) it is a usage error.
- **Chosen reading.** H1 reports the SHA-256 and byte length of the **raw
  `manifest.json` bytes** whenever the file exists (even when its structure
  fails, e.g. `E_MANIFEST_SCHEMA`/`E_MANIFEST_VERSION`) because that is the only
  reading compatible with the decided rule. When the manifest file is absent
  H1 uses a deterministic fallback over the materialised file map
  (`SHA-256` over `relative-path \0 content` in sorted path order, size = total
  file bytes) so the report is still reproducible and path-free.
- **Vector pinning.** No committed vector states `input.sha256`/`input.size`, so
  no vector pins either reading.
- **Python black-box agreement.** The reference verifier uses the raw-manifest
  rule when the manifest exists (confirmed for `E_MANIFEST_SCHEMA`,
  `E_MANIFEST_VERSION`, `E_MANIFEST_LEVEL`, records-listing failures), but for a
  missing manifest it reports an undocumented snapshot hash that this
  implementation could not reproduce from its output alone (probes: empty
  directory → `sha256:25908dcb…`, size 0; one file `x` = `abc` →
  `sha256:07f01384…`, size 3; and similarly content/name-dependent values).
  Gate 3 therefore allow-lists exactly `container/manifest-missing` and
  `container/unknown-top-level-entry` as `spec-ambiguous`; these are the two
  entries in `verifiers/rust/scripts/gate3_known_differences.json` (written by
  the Lead when the gate was integrated).
- **Proposed wording change.** Add one sentence to §14.6: "When
  `manifest.json` is absent or unreadable, `input` must identify the raw bytes
  that would have been the manifest: if no such bytes exist, it is `null`."
  Alternatively define the fallback snapshot serialization exactly.

### F12 — Report details that the specification leaves free but that a byte comparison exposes

- **Where.** §14.6 report format and the individual rules it references; §9.4,
  §7.3, §12.5.
- **Text.** The report format fixes the member names and the verdict/error/notice
  registries, but several *placement* and *value* choices are either not stated
  or stated only loosely. Because the H1 task compares the two implementations'
  reports byte-for-byte, every such choice has to be pinned empirically against
  the reference black box. The following are the observed choices; H1 mirrors
  them so that gate 3 is meaningful, and none of them is asserted by the vectors:
  1. `limitations` prose — see F4; H1 reproduces the reference strings/order.
  2. `N_KEY_TOFU` (Q12) — the specification does not say on which record the
     notice is reported, nor whether it covers keyset-established material. The
     reference reports it on a record when a signature was checked using
     material from context declarations (any signature for ordinary/registered
     kinds; only the actor-key signature for the three key-lifecycle kinds), even
     when the signature or key state then fails. H1 mirrors this.
  3. `N_KIND_UNKNOWN_OPAQUE` — §7.3 says an unknown kind must report
     `kind_known: false` and the notice; the reference only adds the notice when
     the record's final verdict is `valid` (it reports `kind_known: false` for
     invalid records without the notice). H1 mirrors; the vectors match notices
     as a subset, so the vocabulary requirement is not exercised for invalid
     records.
  4. `sigs[].state` — §14.6 lists `valid|invalid|unverified|ignored` without
     saying which condition is `unverified`. The reference maps a
     cryptographically valid signature whose key state fails the §9.4 rules
     (expired/revoked/compromised) to `unverified`, and a crypto failure to
     `invalid`; H1 mirrors.
  5. `refs[]` when check (10) fails — §14.6 does not say whether the
     references resolved so far are reported when the reference check reports an
     error. The reference reports them; H1 mirrors (e.g. `ref/kind-mismatch`).
  6. `container.timestamps[].gen_time` for invalid receipts — the reference
     fills `gen_time` whenever the token parsed far enough (checks 1–4 pass),
     even if a later §12.2 check fails, and leaves it `null` for
     `E_TS_FILE`/unparseable tokens. H1 mirrors (§12.2 check 13 data
     availability is not the same as receipt validity).
  7. Container report defaults and stop rules — the reference always reports
     `level_verified: "L0"`, `anchor_verified: false`, `chain: {"status":
     "absent"}`, `record_count: 0` and `timestamps: []` when they cannot be
     determined, whereas §14.6's "report `null`" sentence suggests `null`; it
     also reports `records: []` (and zero summary counts) for any
     records-listing failure, and `manifest_digest` only after the manifest
     structure checks pass. H1 mirrors.
  8. A timestamp renewal chain failing check 14 — the reference reports every
     receipt as `invalid` with no `gen_time`; H1 mirrors (and this also removes
     spurious §9.4 rescue evidence from a structurally broken chain).
  9. §14.6 serializer micro-decisions — the specification fixes only "sorted
     keys, two spaces of indentation, `ensure_ascii` true and exactly one trailing
     LF", not the remaining escaping choices. H1's serializer targets Python
     `json.dumps(..., sort_keys=True, indent=2, ensure_ascii=True) + "\n"` and
     matches it on every corpus-exercised shape: empty `[]`/`{}` inline, `": "` separator, one item per line with
     two-space indentation, `\b\t\n\f\r` shorthands, other C0 controls as
     lower-case `\u00xx`, every scalar >= U+0080 as lower-case `\uXXXX`
     including surrogate pairs (so U+2028/U+2029 are escaped), `/` never escaped.
     `Option::None` values render `null` and are never omitted, except for the
     explicitly conditional `container`/`cases` members and the placeholder
     `attestation` (F9). One latent divergence was found while documenting this:
     Python's `ensure_ascii` escapes U+007F (DEL) as `\u007f`, while the Rust
     serializer emits DEL literally; no committed input can carry DEL into a
     report string (report strings come from closed grammars or are
     implementation-chosen ASCII prose), so gate 3 is not affected, but the
     byte-equality claim is only exact if DEL is escaped the same way or declared
     free. This list was contributed by the CLI workstream (which owns
     `report_json.rs` and its byte-exact tests).
- **Chosen reading.** Mirror the reference report behaviour for these
  non-conformance details, because the report is the only output a byte-level
  cross-implementation gate can compare; each choice is recorded here so a later
  specification revision can either fix it or explicitly declare it free.
- **Vector pinning.** None of these choices is pinned by a committed vector
  (verdicts, error sets and notice subsets are unaffected).
- **Python black-box agreement.** Observed in gate 3: byte-identical after
  verifier-identity normalization on 292/294 main-corpus and 177/179 frozen cases;
  the only differences are the two F11 identity cases (allow-listed).
- **Proposed wording change.** Add an explicit "report construction" paragraph
  to §14.6 covering: limitations ordering/content, the TOFU notice placement,
  opaque-kind notice condition, `sigs[].state` mapping, reporting partial
  reference resolutions on failure, `gen_time` availability, container defaults
  for undetermined values, records-listing stop behaviour, and broken-renewal
  receipt states.

### F13 — Gate 5(a) exemption class: `sigs[].alg` bytes are semantically inert (Q13)

- **Where.** §2.2 (record digest excludes `sigs`), §2.3 (record signature is over
  the record digest), §3.6 and Q13 (unknown-algorithm signature entries are
  ignored), §4.3 (`sigs` entry grammar); gate 5(a) of the H1 task (the byte-flip
  gate; the H0 equivalent is gate 3(a) in `vectors/GATE-3-EXCEPTIONS.md`).
- **Text.** `record_digest = SHA-256("weave-record/1/digest\n" || WR-CJ(R with its
  top-level member "sigs" removed))` (§2.2) and the record signature signs
  `ASCII("weave-record/1/sig\n" + record_digest)` (§2.3), so no byte inside
  `sigs` is covered by the record digest or by the signature over it. §3.6/Q13: a
  signature entry whose `alg` is well-formed but unknown is structurally validated
  and then *ignored*. §4.3 gives the algorithm-name grammar
  `^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`, at most 32 bytes.
- **Possible readings.** (a) No exemption: every one-bit flip of a positive
  record's bytes must change the terminal verdict. That is false for
  `sigs[].alg`: flipping one bit of `"ed25519"` can yield another grammar-valid
  name (for example `"dd25519"`), the entry becomes ignored per Q13, and if the
  record's required evidence is still satisfied (a `proposed` record, or another
  valid required signature) the verdict legitimately stays `valid`; a strict gate
  would then force a choice between a red gate and changing the verifier away
  from Q13. (b) Exempt all `sigs` bytes: too broad — it would mask key/value/
  structural coverage (`sigs[].key` flips are caught by key resolution, `value`
  flips by Ed25519, structural bytes by JSON and envelope checks). (c) Exempt
  exactly the flips inside a `sigs[].alg` value whose mutated text is a
  grammar-valid algorithm name other than `ed25519`; keep every other byte strict.
- **Chosen reading and why.** (c). The H1 gate harness (`tests/gates.rs`, owned by
  the Lead) scans each positive record's raw bytes for the `sigs[].alg` value
  ranges, re-validates the mutated name against the §4.3 grammar in the gate
  itself, counts these flips as documented exemptions and prints them; a flip
  outside that class (including one that breaks the name grammar) is still a
  violation. The same range logic applies to the attestation file's
  `signatures[].alg` bytes in the container byte-flip gate, because the manifest
  digest excludes the attestation file (§2.4). Reason: Q13 explicitly decided that
  unknown algorithms are ignored, so these bytes are semantically inert by
  specification, not uncovered by an implementation bug; exempting exactly that
  class keeps the gate strict for every byte that is cryptographically or
  structurally load-bearing.
- **Vector pinning.** No committed vector pins gate accounting (vectors declare
  conclusions, not exemptions). The *behaviour* that creates the class is pinned
  by the Q13 vectors (`sig/unknown-alg*`) and by the §3.6/§4.3 tests. The CLI
  workstream's scan provides the accounting: across all 71 positive record-target
  cases, 309 `sigs[].alg` value bytes were flipped; 235 flips leave a terminal
  verdict and all 235 produce a grammar-valid unknown algorithm name, so none
  falls outside the exemption rule (18 of those 235 sit inside the three
  whole-case-exempt `sig/unknown-alg*` cases and are counted under the case-level
  exemption first). The CLI workstream's independent replica of the fixed gate
  (built outside the repository) reports 23,493 flips, 22,594 rejected and 899
  documented exemptions (450 case-level + 217 Q13 `sigs[].alg` + 232 `weave.erased`
  placeholder) with 0 violations; the Lead's own harness run remains
  authoritative.
- **Python black-box agreement.** Not applicable: this is a single-implementation
  gate; gate 3 only compares report bytes and never counts byte flips.
- **Proposed wording change.** None for the format: Q13 is already decided. This
  is a gate-tooling note. For H0's equivalent gate (3(a)) the same class applies
  because the Q13 behaviour is revision-1 semantics; `vectors/` is protected by
  the H1 zero-byte-diff rule, so the class is documented here and in the gate
  harness output rather than added to `vectors/GATE-3-EXCEPTIONS.md`.

### F14 — §14.7/Q18: which environment tokens may appear in `checks_disabled`

- **Where.** §14.7 "Test-only check hook" and Q18; §14.6 `checks_disabled`;
  §14.2 rule 7 (only registry codes in reports).
- **Text.** `WEAVE_VERIFY_SKIP_CHECKS` is "a comma-separated list of error codes
  whose checks are treated as passed. Unset or empty means normal operation. The
  report MUST echo the sorted list in `checks_disabled` so a report can never be
  silently degraded."
- **Possible readings.** (a) Echo every comma-separated token verbatim (sorted,
  unique), including tokens that are not registry codes; (b) treat a non-code
  token as a usage error; (c) echo only tokens that are registered `E_*` codes,
  silently dropping anything else.
- **Chosen reading and why.** (c): `checks_disabled` contains only registered
  codes, sorted lexicographically and unique; unset/empty gives `[]`; a token that
  is not a registry code disables nothing and is silently dropped, not a usage
  error. Reason: §14.2 forbids a report from carrying codes outside the closed
  registry, the report field is typed as a list of codes, and the hook is
  documented as test-only "for conformance testing only"; aborting a run because
  of an unknown token would turn a test-only convenience into a production
  failure mode. Contributed by the CLI workstream.
- **Vector pinning.** No committed vector covers the hook. The H1 ablation
  procedure uses only registered codes (for example
  `WEAVE_VERIFY_SKIP_CHECKS=E_SIG_INVALID` must echo exactly `["E_SIG_INVALID"]`
  and turn the corpus red); that is a gate procedure, not a vector.
- **Python black-box agreement.** Not compared: `compare_reports.py` clears
  `WEAVE_VERIFY_SKIP_CHECKS` for both children so gate 3 never exercises the
  hook, and §14.7 notes that an independent implementation is not required to
  implement the hook for format conformance.
- **Proposed wording change.** Add: "`checks_disabled` lists only registered error
  codes, sorted lexicographically and unique; unset or empty means no checks are
  disabled. A token that is not a registered code is ignored."

### F15 — §14.1 command-surface details: global trust flags on `vectors`, and the `--previous` input form

- **Where.** §14.1 command surface; §11.5 previous-manifest chain;
  `vectors/README.md` case `args`.
- **Text.** The surface lists `vectors <dir> [--tsa-trust <pem>]` but not what the
  flag does, while per-case `expected.json` `args` independently name
  `--keys`/`--tsa-trust`/`--previous`. `--previous <dir>` is described as a
  directory, while `container` accepts `<dir|zip>`.
- **Possible readings.** (a) The global `--tsa-trust` on `vectors` is ignored;
  (b) it is rejected as not applicable; (c) it supplies default anchors for every
  case, with a case's own `args` replacing that input for itself; (d) a case
  without `args` must ignore caller input. For `--previous`: directory only, or
  directory-or-zip.
- **Chosen reading and why.** (c) with per-case replacement: caller options are
  the base for every case; a case whose `args` name `--keys`, `--tsa-trust` or
  `--previous` replaces that input for itself; a case without `args` keeps the
  caller's inputs (so the committed corpus, designed to pass with no global trust
  options, runs every no-args case with no local trust input). `--keys` and
  `--previous` remain rejected on `vectors`, matching the §14.1 surface.
  `--previous` accepts a directory (the vector form) and tolerates a file/zip by
  treating its bytes as a zip, because the previous container is a container input
  like any other and the superset cannot change committed-vector behaviour.
  Reason: the committed per-case conclusions are stated relative to the case's own
  `args` (for example a container case with no `args` documents an unverifiable
  outcome that would change if a global keyset were silently injected), and
  §14.1 is the only text. Contributed by the CLI workstream.
- **Vector pinning.** No vector passes a global trust flag on `vectors`, so the
  global-default behaviour is unpinned. The per-case `args` mechanism is pinned by
  210 of the 294 main-corpus cases and 131 of the 179 frozen cases, and the
  directory form of `--previous` by `container/previous-external-mismatch`; the
  zip form is unpinned.
- **Python black-box agreement.** Directory-form `--previous` and per-case `args`
  were exercised by gate 3 (both implementations ran each case's CLI with its
  reproduced arguments and agreed after identity normalization); the `vectors`
  runner's global-flag behaviour was not compared (the gate does not run the
  `vectors` target) and the zip form is unexercised.
- **Proposed wording change.** §14.1: "On `vectors`, `--tsa-trust` supplies a
  default trust anchor for cases that do not name `--tsa-trust`; `--keys` and
  `--previous` are not accepted. `--previous <path>` accepts a container directory
  or its zip, exactly like `container`."

### F16 — §14.5 container order versus §11.2: an invalid L0 chain claim stops before the manifest signature is evaluated

- **Where.** §14.5 (container steps (2)-(6), one container error, `records: []`),
  §11.2 (`chain` row), §11.3 (manifest signature), §11.4 (levels).
- **Text.** §11.2: `level == "L0"` with a non-null `chain` is `E_MANIFEST_LEVEL`;
  §11.3: a non-empty signature list with no verifiable signature by a declared
  required key is unverifiable (`E_KEY_UNKNOWN`/`E_SIG_UNVERIFIABLE`), and
  `E_MANIFEST_SIG_INVALID` is the crypto failure; §14.5: a container-level invalid
  error before the records check yields `records: []` and exactly one error in
  `container.errors`.
- **Possible readings.** (a) Report the structural `E_MANIFEST_LEVEL` *and* the
  unfavourable signature/trust condition (for example `E_KEY_UNKNOWN` when no
  local keyset is supplied) - two container errors for one input; (b) the manifest
  structure check runs before the manifest signature check, so the structural
  error wins and stops the container pipeline, and manifest signature verification
  establishes the cryptographic equation against the declared key material
  independently of local trust.
- **Chosen reading and why.** (b). Reason: §14.5 fixes the stage order and the
  one-error/stop rule, and local-root trust is evaluated where declarations are
  established, not in the manifest signature equation (the same split the vectors
  use for record signatures: `E_KEY_UNKNOWN` is a key-availability outcome, not a
  signature-format one).
- **Vector pinning.** Pinned by `container/l0-with-chain`, which expects exactly
  `{E_MANIFEST_LEVEL}` and no records without a keyset. Also pinned by
  `container/manifest-sig-invalid` and `container/manifest-sig-record-prefix`: a
  container with an invalid manifest signature and no `--keys` must be
  `E_MANIFEST_SIG_INVALID` (the crypto check against container-declared key
  material), not a trust error.
- **Python black-box agreement.** Observed in gate 3: all three cases agreed
  byte-for-byte after identity normalization.
- **Proposed wording change.** Add to §14.5: "A container-level invalid error
  before the records check stops the pipeline: report exactly that one error and
  `records: []`. Manifest signature verification establishes the cryptographic
  equation only; whether the signing declaration is trusted is evaluated at the
  key/record layer."

### F17 — `vectors/README.md` matcher details that the runner must fix

- **Where.** [`vectors/README.md`](../vectors/README.md) "Case format" and "Runner
  rules"; §14.10.
- **Text.** The README fixes the field set of `expected.json`, but leaves the exact
  comparison semantics of three fields partly open: `expected_resolution` is
  described as a "map of reference index -> state" although JSON stores it as an
  array; `records` is a "per-id subset match (`verdict`/`errors` when present)";
  `expected_container` is "recursive subset match ... (nested objects recursive,
  arrays/values exact)".
- **Possible readings.** (a) `expected_resolution` keys are indices into
  `records[0].refs` and are matched as a prefix; `records` is an id lookup where
  `verdict` and `errors` are exact and any other expected member is a recursive
  subset; `expected_container` objects are recursive while arrays compare
  element-by-element recursively (so array order matters but object member order
  does not, which pure value equality would get wrong for an array of objects).
  (b) `expected_resolution` keys are `refs[].index` values from the report;
  `records` compares whole entries; `expected_container` compares arrays
  literally.
- **Chosen reading and why.** (a). It is what the H0 corpus's own shape implies
  (every committed `expected_resolution` lists every reference; `records`
  expectations carry only the fields they mean to assert), it is what the CLI
  runner implements, and both verifiers pass all committed vectors with it. No
  committed expectation contains an array inside `expected_container`, so the
  array rule is chosen rather than pinned. Contributed by the CLI workstream.
- **Vector pinning.** Partially: the fields are exercised by
  `ref/missing`, `ref/two-missing`, `ref/hints-valid`,
  `labels/propagation-unchecked`, `stage/unknown-kind-opaque`,
  `container/l0-minimal`, and others, so the basic semantics are pinned by the
  passing corpus; the array-inside-`expected_container` case and the prefix form
  of `expected_resolution` are unpinned.
- **Python black-box agreement.** Not directly comparable: gate 3 invokes the
  CLIs per case, not the two vectors runners; agreement is indirect - both
  implementations pass 294/294 main and 179/179 frozen, so the runner
  interpretations agree on every committed expectation shape.
- **Proposed wording change.** Replace the runner-rules sentence with the exact
  semantics: "`expected_resolution` is matched as a map from the position in
  `records[0].refs` to state (all listed entries must match); `records` matches by
  `id`, with `verdict` and `errors` exact and other listed members recursive
  subsets; `expected_container` recursively matches objects and matches arrays
  element by element, recursively, comparing scalars and null exactly."

## Other PROVISIONAL implementation shapes

These are explicitly acknowledged as implementation shapes by Appendix A.2 and
[`docs/open-questions.md`](../docs/open-questions.md) §3. They are not recorded as
findings because the specification already labels them PROVISIONAL; H1 follows the
shape stated in the specification and this table records any residual risk.

| id | item | H1 resolution | residual risk |
|---|---|---|---|
| P3 | grant delegation depth bound 8 | followed literally (§5.5.2, §13) | none, bound is fixed |
| P4 | revocation-authority walk depth 8 | followed literally (§5.5.4) | walk order still implementation-defined within the same depth |
| P5 | precedence among simultaneously failing grant-chain steps | follows the step order stated in §5.5.2 | a chain with two independent failures in the same step can still yield either code; no vector combines them |
| P6 | renewal-chain representation (`timestamps[].renews`, imprint formula, single chain) | followed literally (§11.3, §12.4) | none, formula fixed |
| P7 | report field shapes | per-case report shape fixed; `vectors` layout, discovery and input identity documented as PROVISIONAL in F5 (extended by the CLI workstream); `timestamps[]` entries carry `index`/`path`/`state`/`gen_time` | cross-implementation `vectors` reports and byte equality are not comparable by design |
| P9 | `scope` compared as a set of strings | followed literally (§5.5.2) | none, rule fixed |
| P10 | `N_NO_HUMAN_SIGNATURE` determination/precedence | resolved by F6 above | the specification does not decide it; see F6 |
| P11 | specification-example markers | tooling convention, not used by the verifier | none for verifier conformance |
| P12 | delegation unreachable for `program`/`device` granters | followed literally: `E_GRANT_UNRESOLVED` (§5.4, §5.5.2) | none, envelope makes it unreachable |

P1/P2 (time-ordered root selection) and P8 (compromise-rescue comparison) are
resolved by decision 2026-11-10 #42 (R2, R3) and are not open.

## Gate-3 observations

Gate 3 was run on 2026-11-11 after the Rust verifier passed every committed
vector (294/294 main and 179/179 frozen) and after the F1–F12 alignment work.
The comparison normalizes **only** the §14.6 `verifier` identity object (F1) and
then compares every remaining report byte.

Method: `./.venv/bin/python verifiers/rust/scripts/compare_reports.py`
(main corpus) and `... --include-frozen`. The reference verifier was executed as a
black box through its documented CLI; its source was never read.

Local gate environment: the `rustup` toolchains in this sandbox do not ship the
`clippy`/`rustfmt` components, so the local gate runs used the Homebrew Rust
toolchain (1.94.0) with its `cargo`; CI installs both components through
`dtolnay/rust-toolchain` in `.github/workflows/ci.yml`.

| run | cases | identical after identity normalization | allow-listed (spec-ambiguous) | other differences |
|---|---|---|---|---|
| main corpus | 294 | 292 | 2 | 0 |
| frozen candidate | 179 | 177 | 2 | 0 |

Allow-listed differences (both are the F11 fallback): `container/manifest-missing`,
`container/unknown-top-level-entry` — the reference's directory-snapshot
`input.sha256`/`size` when no manifest exists is undocumented (F11).

Differences found during the run and resolved **in the Rust implementation**
(specification has a unique answer; the Rust report was wrong before the fix):
manifest-signature key material may come from a declared (not necessarily
trusted) key (§11.3); the §4.2 key-lifecycle actor exemption; §9.4 case-2
unverifiable codes surviving signature aggregation; grant-revocation reference
order and authorising-action requirement (§5.5.4); erasure cross-check identity
vs digest agreement (§10.3); container records-listing stop rules and report
defaults (§14.5/§14.6); timestamp `genTime` recovery for invalid receipts
(§12.2); record-report details in F12. No difference was classified
`spec-unique-answer-Python-bug`: every case where the two implementations
disagreed on a conclusion was already caught by the vectors and fixed in Rust
before gate 3.

The CLI workstream's command-surface and report/runner notes (F13-F17) were
written up after this run; they record choices that were already in force and do
not change the comparison result (the only differences remain the two F11 cases).

## Registry notes from other workstreams

Scratch list of implementation notes that other H1 workstreams reported; they
are recorded here as provenance and are promoted to a numbered finding only
where they concern specification text.

- **Ed25519 (§3):** §3.4 step 1 ownership between caller and crypto layer; §3.7
  "acceptable with another defect → first failing §3.4 step" is unexercised by
  the corpus; §3.2's internal failure order is not observable through §3.4's
  one-code-per-point model; the mixed-order predicate is implemented as
  `[L]A != identity` alone (equivalent after step 5's small-order check);
  Wycheproof tcId 210 is flagged MixedOrder but is an `invalid` (not
  `acceptable`) case and is rejected with `E_SIG_MIXED_ORDER_A`; the signing
  scalar is the clamped scalar reduced mod L (reproduces the RFC 8032 §7.1
  signatures exactly).
- **L2 / RFC 3161 (§12):** outer ContentInfo vs inner encapsulated content
  type (only the inner is pinned by a vector); fractional `genTime` seconds
  (row 13's "floor sub-millisecond digits" implies fractional input must be
  accepted; unpinned); `accuracy` component bounds (1–999, absent = 0;
  unpinned); check 12 vs check 13 ordering for malformed `genTime` (unpinned);
  renewal-chain array order equals chain order; signed `contentType` attribute
  required by RFC 3161 but not listed in the §12.2 table; exactly one
  SignerInfo; ESS v2 DEFAULT hash algorithm; algorithm-allowlist pairings
  (ECDSA and combined OIDs implemented but unexercised); defensive `E_TS_FILE`
  re-check inside the timestamp layer.
- **Kinds (§5.5, §7, §9, §10):** kind↔envelope consistency codes that the kind
  pages leave unnamed (declaration `actor.key`/`actor.type` equality, rotation
  `actor.key` equality; H1 chose `E_ENV_ACTOR`/`E_ACTOR_KEY_TYPE_MISMATCH`);
  malformed optional declaration `owner` → `E_KIND_BODY_SCHEMA`; wrong-JSON-type
  public-key members use the dedicated key codes; body-root additive evolution
  accepted for kinds whose prose calls the body "closed"; grant window inversion
  is `E_KEY_VALIDITY` (not `E_GRANT_SCHEMA`); consent `scope` has no uniqueness
  rule; no committed vector pins `E_GRANT_SCHEMA`, and
  declaration/rotation actor-equality rules are unpinned.
- **Container (§11):** records-listing failures stop before per-record
  evaluation (records `[]`) because the exact expected error sets would
  otherwise gain key-trust errors; zip archive metadata bytes are not part of
  the format's cryptographic binding (the byte-flip gate exercises materialised
  entry contents instead); directory-container identity fallback is F11.
- **Record pipeline (§14.5):** the fixed order was interpreted as the first
  failing check wins even where §14.4 calls the outcome unverifiable; the
  envelope sub-order (required member presence → unknown member → per-member
  grammar) is unpinned when two envelope defects coexist (F3).
- **CLI (§14 command surface, report bytes, vectors runner):** promoted to
  findings - the `vectors` target/discovery and input identity (F5, extended), the
  skip-hook report form (F14), the `vectors`/`--previous` command-surface details
  (F15), the §14.5-versus-§11.2 chain-ordering pin (F16), the §14.6 serializer
  micro-decisions (F12 item 9, including the latent DEL-escaping divergence), and
  the `vectors/README.md` matcher details (F17).

## Change log of this document

- **2026-11-11** — initial version for the H1 hand-off: purpose, collection
  method, findings F1–F10 visible from the specification text alone, the
  PROVISIONAL-shape table, and the empty gate-3 and registry-note sections.
- **2026-11-11 (integration)** — added F11 (directory-container `input` identity
  when the manifest is missing) and F12 (report details left free by §14.6),
  filled the gate-3 observations table (292/294 and 177/179 identical after
  identity normalization; two F11 allow-listed cases), and recorded the
  workstream registry notes.
- **2026-11-11 (final documentation pass)** — replaced every *pending gate 3*
  field with the observed 292/294 + 177/179 result or the reason a finding is not
  exercised; aligned F4/F11/F12 with the integrated report behaviour and the two
  allow-listed identity cases; added F13 (byte-flip gate 5(a) Q13 `alg`-byte
  exemption class), F14 (§14.7 skip-hook report form), F15 (§14.1 command-surface
  details), F16 (§14.5-versus-§11.2 pinned ordering) and F17
  (`vectors/README.md` matcher details); extended F5 with the CLI workstream's
  discovery/input-identity notes; recorded the local gate environment (Homebrew
  Rust toolchain because the rustup toolchains here lack clippy/rustfmt).
