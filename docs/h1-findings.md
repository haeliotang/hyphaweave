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

## H1-FIX1 (2026-11-14): status of F1–F17 after specification revision 3

Decision 2026-11-11 #2 (S16) adopted every finding F1–F17; the S1 rounds wrote
the rulings into the specification, and H1-FIX1 implemented them in the Rust
verifier. The **Python black-box agreement** column is the result of the
H1-FIX1 gate-3 comparison (498 main + 202 frozen committed cases) and of the
H1-FIX1 differential fuzzing (gate 4), recorded under
[H1-FIX1 gate results](#h1-fix1-gate-results).

| finding | specification now | Rust (H1-FIX1) | Python black-box agreement |
|---|---|---|---|
| F1 report identity | §0.2/§14.6: `verifier` is informational, outside comparison | unchanged (`hyphaweave-verify-rs`) | normalized away by gate 3, as §14.6 says |
| F2 nested closed-object codes | §4, §4.2, registry rows rewritten (S8⑤⑥) | nested objects report their own code; an `actor` missing member reports its member code; a malformed `actor.grant` and a malformed `origin` inside a reference object are `E_ENV_REFS`; `labels.sensitivity` of a wrong JSON type is `E_ENV_SENSITIVITY` | **Corrected.** The H1 hand-off said "no difference"; review A's fuzzing showed the black box choosing the other reading on unpinned sub-cases (`E_ENV_ACTOR` vs `E_ENV_ACTOR_TYPE`, `E_ENV_SIGS` vs `E_ENV_SIG_KEY`, `E_ENV_LABELS` vs `E_ENV_SENSITIVITY`). After revision 3: gate 4 (4,063 mutants) has no conclusion difference attributable to a nested-object code. |
| F3 envelope sub-order | §14.5 step (2): presence → closedness → grammar, nested objects alike | implemented for the envelope and inside `actor` (presence of the agent-only members first) | **Corrected.** The H1 hand-off said "not exercised"; review A observed the black box choosing a different order on multi-defect records. After revision 3: gate 4 (4,063 mutants) has one sub-order difference, an agent-only actor member against another member's grammar (F45, classified as a reference-verifier deviation). |
| F4 limitations prose | closed `L_*` identifiers (S12) | identifiers from if-and-only-if facts (`src/limitations.rs`); no prose | conclusions agree on every committed case (gate 3) |
| F5 `vectors` layout | implementation-defined (S8⑬) | unchanged | not compared, by design |
| F6 `N_NO_HUMAN_SIGNATURE` | only on a `valid` record (S16/F6) | unchanged | conclusions agree on every committed case (gate 3) |
| F7 §14.4 terminal | terminal like an error (S8⑪) | unchanged | conclusions agree on every committed case (gate 3) |
| F8 timestamp order | computed early, reported at step (11) | reported only when the pipeline reaches (11) (W5) | conclusions agree on every committed case (gate 3) |
| F9 undetermined fields | `null` / `[]`; `kind_known` `null` before parse | `kind_known` is now `null` for an unparsed record | conclusions agree on every committed case (gate 3) |
| F10 keyset usage errors | structural group fixed (§14.1, V5) | only structural failures are usage errors; semantic failures establish no trust | usage errors are not representable as vectors |
| F11 manifest-less identity | `null`/`null` (S14) | identity tiers (a)/(b)/(c) of §14.6 | the four former allow-list entries were removed; gate 3 now matches all four byte for byte. |
| F12 report details | §14.6 byte rule, `kind_known`, TOFU, `sigs[].state`, `refs[]` prefix | implemented from the text (UTF-16 key order, U+007F as `\u007f`) | conclusions agree on every committed case (gate 3) |
| F13 `sigs[].alg` not covered | stated in §4.3 (S16/F13) | unchanged | n/a |
| F14 skip-hook tokens | §14.7 tokens, exit 3, `--test-hooks` (S13) | implemented; the library hook exists only with the `test-hooks` cargo feature (R3) | n/a (test hook) |
| F15 command surface | §14.1 (`--previous <dir|zip>`, `vectors` defaults) | implemented | conclusions agree on every committed case (gate 3) |
| F16 chain claim before signature | unchanged | unchanged | conclusions agree on every committed case (gate 3) |
| F17 matcher details | §14.10 | the runner implements `expected_input`, `limitations`, `notices_absent`, an explicit empty `records`, and the position-map `expected_resolution` | n/a |

## H1-FIX1 additions: review items missing from the H1 hand-off (R7)

The H1 reviews listed ambiguities that the H1 hand-off did not record. Each is
now decided by the specification; they are listed so the audit trail is
complete.

### F18 — Nesting depth of JSON values and of SPDX licence expressions (review B H1/H2, review A M-4)

- **Where.** §1.9, §8.7, §13 (`MAX_JSON_DEPTH`, `MAX_LICENCE_NESTING`).
- **Readings before revision 3.** Unbounded except by the record size, versus an
  implementation-chosen bound. H1 had chosen 1,024 levels and `E_JSON_INVALID`;
  its recursive parsers overflowed a 64–512 KiB stack (review A, review B).
- **Now decided.** Depth above 32 is `E_JSON_SIZE`; licence nesting above 16 is
  `E_ENV_LICENCE`; implementations MUST NOT crash (S3).
- **Rust.** The parser checks the depth before descending (recursion is bounded
  by 32); the SPDX parser checks its counter before descending; the DER walker of
  §12.2 is iterative. `tests/small_stack.rs` verifies the limit, limit + 1, a
  1,023-level and a 400,000-level JSON input and a 400,000-pair licence on a
  64 KiB stack (R6).
- **Vectors.** `jcs/depth-limit-32`, `jcs/depth-limit-plus-one`,
  `labels/licence-nesting-limit-16`, `labels/licence-nesting-plus-one`.
- **Python black-box agreement.** Conclusions agree on every committed case (gate 3). The 1,023-level replay input:
  both report `invalid` `E_JSON_SIZE`, no crash (Rust peak RSS 2.3 MB; the 400,000-level input 3.2 MB).

### F19 — Several revocations of one key, and revocations in the keyset (review B H3)

- **Where.** §9.4, §9.5, §14.1.
- **Readings before revision 3.** The first valid revocation in manifest order
  (H1) versus every valid revocation (black box); keyset revocations ignored (H1)
  versus effective (black box).
- **Now decided.** Every valid revocation of the context counts, keyset
  included; the retired/other and compromise families are independent, each with
  its earliest `effective_at` (S2, T2); a revocation record is judged against the
  valid revocations ordered strictly before it (T9, U3).
- **Rust.** `context::World::key_revocation_state` with a
  `(recorded_at, digest)` cutoff for revocation records.
- **Vectors.** `key-lifecycle/multi-revocation-order-{a,b}`, `keyset-revocation`,
  `mixed-revocation-*`, `mutual-revocation-order-{a,b}`,
  `revocation-signed-by-retired-key`, `self-revocation-after-retirement`.
- **Python black-box agreement.** Conclusions agree on every committed case (gate 3). Replay: `multi-revocation-order-a`/`-b` and `keyset-revocation` give `E_KEY_REVOKED` in both.

### F20 — "Already in trusted": redeclaring a trusted key (review B H4)

- **Where.** §5.3, §9.1 rule 4.
- **Readings before revision 3.** Any trusted key (H1: an agent key could
  redeclare itself `human` in a container and be accepted) versus a key trusted
  as the same class (black box).
- **Now decided.** The governing class is decided before and independently of
  the trust closure; a declaration of a different class is
  `E_KEY_CLASS_CONFLICT`; the keyset governs class and window; conflicting keyset
  declarations are a usage error (S1, T4, U4, V5).
- **Rust.** `context::World::build_trust` (structural candidates, keyset pins,
  governing class, closure, governing window).
- **Vectors.** `key-lifecycle/redeclare-class-conflict(-control)`,
  `redeclare-window-attack`, `redeclare-window-control`,
  `nonmonotonic-closure-class-conflict`, `equal-time-declaration-digest-order-*`,
  `keyset-device-class-pins`, `bad-public-key-does-not-govern`.
- **Python black-box agreement.** Conclusions agree on every committed case (gate 3). Replay: the review's human upgrade gives `E_ACTOR_KEY_TYPE_MISMATCH` and `E_KEY_CLASS_CONFLICT` in both.

### F21 — A grant judged against its own window; grant-revocation validity; depth (review B M4/M5)

- **Where.** §5.5.2 steps 6–7, §5.5.4, §9.6.
- **Now decided.** A grant record is not judged against its own window or
  revocation (S9); a grant revocation takes effect only when it is valid and
  targets an authorising grant (S10, T17); the bounds are 8 links and 8 rotation
  steps inclusive, and a grant record's own link is not counted (S10, T8).
- **Rust.** `check_grant_record_chain` starts the window/revocation walk at the
  parent; `grant_revoked_at` requires a valid revocation (keyset records
  included); `authorised_revoker_keys` walks at most 8 steps through valid
  rotation records only.
- **Vectors.** `grant/backdated-grant-covers-record`, `grant/chain-depth-9-links`,
  `grant/chain-depth-exceeded`.
- **Python black-box agreement.** Conclusions agree on every committed case (gate 3). Replays: a pre-issued root grant and a root grant whose `valid_from` follows its own `recorded_at` are `valid` in both; a grant revocation by a successor 8 rotation steps away is `valid` and 9 steps away `E_GRANT_REVOKE_SIGNER` in both.

### F22 — `-0` before a later float (review B L1)

- **Now decided.** `-0` is classified at its number token (S8④). **Rust.**
  `json.rs` reports `E_JSON_NOT_CANONICAL` at the `-0` token. **Vectors.**
  `jcs/minus-zero-before-float`, `jcs/float-before-minus-zero`. **Python.**
  Conclusions agree on every committed case (gate 3).

### F23 — ZIP64, prefix and trailing bytes, `readable/` in the zip form, DOS directory entries (review A M-1, review B M3/L6)

- **Now decided.** ZIP64 is accepted; prefix bytes, a comment and trailing bytes
  are `E_CONTAINER_ZIP`; the structural rules and their order are normative (S5,
  T6, U9, V6, W7); `readable/` entries are never decompressed or CRC-checked but
  keep rule 1 and the entry checks (U12/L2).
- **Rust.** `zip.rs` rewritten: the four W7 phases, ZIP64 records and extra
  fields, lazy bounded decompression, `readable/` never decompressed.
- **Vectors.** `container/zip64-valid`, `container/zip-prefix`,
  `container/zip-trailing` and the other `container/zip*` cases.
- **Python black-box agreement.** Conclusions agree on every committed case (gate 3). Replays: a plain zip `valid`, prefix and trailing bytes `E_CONTAINER_ZIP`, and a ZIP64 archive of 70,000 entries `valid` in both.

### F24 — "Enforce the limits while reading" (review A M-3, review B M1)

- **Now decided.** Per-class probes bounded by the class limit plus one byte, the
  directory total accumulated while reading, the zip central directory checked
  before decompression (S4, T15, U2).
- **Rust.** `container.rs` reads every file through a bounded probe and hashes
  blobs while streaming; the CLI reads a record target to at most
  `MAX_RECORD_BYTES + 1` bytes (`operator::read_record_target`). Measured peak
  RSS: a 300 MiB `manifest.json` 9.3 MB (`E_JSON_SIZE`), a 300 MiB unlisted file in `records/` 4.2 MB (directory) and 3.5 MB (zip), a 300 MiB `readable/` zip entry 3.5 MB (`valid`, never decompressed), a zip declaring 2 GiB 4.9 MB (`E_CONTAINER_SIZE`), a ZIP64 archive of 70,000 entries 29 MB; the reference verifier used 37–89 MB on the same inputs.

### F25 — TSA accuracy overflow and bound (review B M2)

- **Now decided.** Checked fixed-width arithmetic; a total above
  `MAX_TS_ACCURACY` (86,400 s) or an overflow is unusable evidence,
  `E_TS_UNTRUSTED` (S11, T3).
- **Rust.** `timestamp::accuracy_micros`, `ChainEvidence::rescue`.
- **Vectors.** `integrity-levels/l2-accuracy-*`. **Python.** Conclusions agree on every committed case (gate 3).

### F26 — The differential-fuzz classes of review A M-2

| class | decided by | Rust (H1-FIX1) |
|---|---|---|
| `sigs: []` on a record that must be signed | §4.3/§4.4 (S7①): `E_SIG_REQUIRED` | `E_SIG_REQUIRED`; `[]` is structurally valid otherwise |
| unverifiable manifest signature followed by a listing error | §14.5 (S7②): processing continues | listing runs; the unverifiable code is kept |
| unknown-algorithm self-signature entry plus a valid cosignature | §4.4/§9.1 rule 2 (S7④): `E_KEY_DECLARED_NOT_SELF_SIGNED` | unchanged |
| several listing violations at once | §14.5 (S8①, U8): all reported | all reported |
| missing `signatures/manifest.sig.json` | §11.1 (S8②): `E_MANIFEST_UNSIGNED` | changed from `E_MANIFEST_SCHEMA` |
| `weave.key.declared` without `public_key` | §9.1 rule 1 (S8③, T1): `E_KEY_PUBLIC_KEY`, before any trust judgement | checked before key resolution |
| grant `valid_from` after its own `recorded_at` | §5.5.2 (S9): valid | own window not judged |
| zip prefix/trailing bytes | §11.9 (S5): `E_CONTAINER_ZIP` | unchanged |
| manifest signer not bound to `origin.instance` | §11.3, §15 item 15 (T11): not required | unchanged |

### F27 — Remaining low items (review A L-2/L-4, review B L2–L7)

- ECDSA receipts (review A L-2): P-256 is pinned by the X6 vectors
  `integrity-levels/l2-ts-signer-ecdsa-params-{absent,null,other}`; P-384 has no
  committed receipt, so a unit test (`timestamp::tests::ecdsa_signer_signatures_p256_and_p384`)
  checks both curves on fixed fixtures, with wrong-message, wrong-digest,
  wrong-curve and flipped-signature negatives.
- The manifest signer is not bound to `origin.instance` (review A L-4): §11.3
  and §15 item 15 (T11) now say it is not required (F26 table); the code is
  unchanged.
- `E_ENV_SIG_ALG` (review B L2) is still never emitted (§3.6).
- The `expect` in the context builder (review B L3) is gone, and the library has
  `#![forbid(unsafe_code)]`.
- Reference lookup by `(project, id)` (review B L4): **changed in H1-FIX2
  (Y1, commit `ce3e75e`)**. The H1-FIX1 reason given here ("the digest binds
  `instance`") was wrong: it only holds for a live record whose digest matches;
  a placeholder's own `origin` is not covered by the digest it carries, and a
  record of another instance with a different digest turned `missing` into
  `unverifiable`. See F58.
- Linear `Object::get` (review B L5) is unchanged; no measured bottleneck.
- DEL escaping (review B L7) is normative in §14.6 (S8⑩/F12).

## H1-FIX1: new findings from implementing revision 3

### F28 — §4.5 names both `E_ENV_UNKNOWN_FIELD` and `E_KIND_BODY_SCHEMA` for an extra placeholder member

- **Where.** §4.5, first and last paragraphs; the §4 introduction; the registry.
- **Text.** §4.5 opens with "any extra member is `E_ENV_UNKNOWN_FIELD`; a missing
  member is `E_ENV_MISSING_FIELD`", and closes with "every structural violation
  of the placeholder is `E_KIND_BODY_SCHEMA` … `E_ENV_MISSING_FIELD` and
  `E_ENV_UNKNOWN_FIELD` … are not used for `weave.erased`".
- **Chosen reading.** `E_KIND_BODY_SCHEMA` (the later sentence, §4 and the
  registry agree). **Proposed wording.** Delete the codes from the opening
  sentence. **Python.** Same answer from the reference verifier on a black-box probe..

### F29 — Decoding a zip entry name without general-purpose bit 11

- **Where.** §11.9 check order, phase 2 ("a decodable name").
- **Readings.** (a) UTF-8 only; (b) UTF-8 with bit 11, otherwise the APPNOTE
  default code page, which always decodes.
- **Chosen reading.** (b): a non-UTF-8 name with bit 11 set is phase-2
  `E_CONTAINER_ZIP`; any other non-ASCII name decodes and then fails the layout
  (`E_CONTAINER_ENTRY`) unless it is under `readable/`. **Proposed wording.** Name
  the decoding rule in phase 2. **Python.** Same answer from the reference verifier on a black-box probe..

### F30 — The stage of a member decompression failure in a target zip

- **Where.** §11.9 ("decompression … reported as `E_CONTAINER_ZIP`"), §14.5.
- **Readings.** (a) step (1): decompression follows the entry checks of §11.9;
  (b) the stage that reads the member (step (7) for a record file).
- **Chosen reading.** (a): every non-`readable/` member is decompressed at step
  (1), after the entry checks, under its class cap; the report has `records: []`.
  **Proposed wording.** State the stage. **Python.** Same answer from the reference verifier on a black-box probe..

### F31 — Do `readable/` files count toward `MAX_CONTAINER_ENTRIES` in the directory form?

- **Where.** §13 ("every file in the directory container, including
  `manifest.json`") versus §11.8 ("in a directory container its bytes are never
  read, stat-ed or counted toward the container total").
- **Chosen reading.** Not counted: counting them needs an enumeration of the
  directory that §11.8 says is never stat-ed. **Proposed wording.** Add
  "excluding `readable/**`" to the directory-form entry count, or require the
  enumeration explicitly. No committed vector reaches 200,000 files.

### F32 — When is a `readable/` entry "observed" in a zip whose structure fails?

- **Where.** §11.8, §14.6 (`N_READABLE_PRESENT`: "if entry enumeration itself
  fails before a `readable/` entry is observed, the notice is not reported").
- **Chosen reading.** The entries of a zip are enumerated once phases 1–4 pass; a
  structural failure reports no `N_READABLE_PRESENT`; an entry-check failure
  (`E_CONTAINER_ENTRY`) after the phases keeps it. **Python.** Same answer from the reference verifier on a black-box probe..

### F33 — Is a container declaration's own self-signature "context-trusted"?

- **Where.** §14.9 TOFU predicate, §14.6 `N_KEY_TOFU`.
- **Readings.** (a) yes: the verifying material comes from a context
  `weave.key.declared` (the record itself); (b) no: material that the record
  under verification supplies for itself is not context material.
- **Chosen reading.** (b). It is pinned by `container/manifest-context-trusted-tofu`
  (`notices_absent: ["N_KEY_TOFU"]` on a container-declared device declaration);
  H1-FIX1 first implemented (a) and that vector failed. **Proposed wording.** Say
  that the record under verification does not count as context material for its
  own signatures. **Python.** Same (pinned).

### F34 — A file in `records/` whose name is not `<hex>.json`

- **Where.** §11.1 ("an extra file in `records/` is `E_MANIFEST_RECORD_EXTRA`"),
  §14.5 (records listing).
- **Chosen reading.** Every file in `records/` that is not a listed record is an
  extra file, reported by the records listing at step (7) together with the
  other listing violations (U8), whatever its name; likewise an extra file in
  `blobs/` is `E_MANIFEST_BLOB` at step (9). **Python.** Same answer from the reference verifier on a black-box probe..

### F35 — A malformed `labels.consent`: `E_ENV_LABELS` (§8.1) or `E_ENV_REFS` (§4)?

- **Where.** §8.1 ("malformed is `E_ENV_LABELS`") versus the §4 introduction
  ("inside a reference object `E_ENV_REFS`").
- **Chosen reading.** `E_ENV_LABELS`, the owning section's code. **Python.** Same answer from the reference verifier on a black-box probe..

### F36 — Where "a member forbidden for the actor type" sits in the actor sub-order

- **Where.** §4.2, §14.5 step (2).
- **Chosen reading.** At that member's grammar position in the table order,
  after `type` and `key`; so `type: "robot"` with a `model` member reports
  `E_ENV_ACTOR_TYPE`. **Python.** Same answer from the reference verifier on a black-box probe..

### F37 — Limitation facts about records that failed their own structure, or were not reported

- **Where.** §14.9 (`L_LABELS_ARE_CLAIMS`, `L_ERASED_PLACEHOLDER`,
  `L_ERASED_STANDALONE`).
- **Chosen reading.** The facts concern the reported records: with
  `records: []` none of the three is reported. `L_LABELS_ARE_CLAIMS` needs a
  `labels` member in an envelope that passed its structure checks (a record that
  is `E_ENV_LABELS` or `E_ENV_SENSITIVITY` does not "carry" labels);
  `L_ERASED_*` count every `weave.erased` record, well formed or not.
  H1-FIX1 first read "carries a `labels` member" literally; gate 3 showed the
  reference reading on `labels/invalid-sensitivity` and seven other committed
  cases, and H1-FIX1 follows it. **Proposed wording.** Say "a record whose
  envelope passed with a `labels` member".

### F38 — A declaration's own self-signature against its own validity window and revocations

- **Where.** §9.1 rule 5 ("a signature made outside the declared window … is
  `E_KEY_EXPIRED`"), §9.4, §9.5 (self-declaration bootstrap).
- **Readings.** (a) every signature made by the key, the declaration's own
  self-signature included, is judged against the window and the revocations;
  (b) the declaration's self-signature only proves possession and is exempt, as
  a grant is exempt from its own window (S9).
- **Chosen reading.** (a), the literal text and the more conservative outcome: a
  declaration recorded before its own `valid_from` is `E_KEY_EXPIRED`, and a
  declaration of a compromised key without a rescuing receipt follows §9.4.
- **Vectors.** `key-lifecycle/sign-before-valid-from` expects the aggregated
  error set `{E_KEY_EXPIRED}`, which both readings produce.
- **Python black-box agreement.** Different: the reference exempts the
  self-signature (that committed case differs at record level and is
  allow-listed as spec-ambiguous). **Proposed wording.** Say whether §9.1 rule 5
  applies to the declaration's own self-signature.
- **Minimal reproduction.** `scripts/diff_fuzz.py` mutant of
  `key-lifecycle/sign-before-valid-from`, class `number`, seed
  `2685454045068581988`: H1 `{E_ENV_SIGS, E_KEY_EXPIRED}`, the reference
  `{E_ENV_SIGS}`.

### F39 — `sigs[]` when `E_KEY_PUBLIC_KEY` precedes signature verification

- **Where.** §14.5 (T1: decided before any key resolution), §14.6 (an
  undetermined list field is `[]`; `sigs[].state`).
- **Chosen reading.** The signature checks did not run, so `sigs` is `[]`.
- **Python black-box agreement.** Different: the reference lists signature
  states (5 committed cases, allow-listed as spec-ambiguous:
  `key-lifecycle/bad-public-key-does-not-govern`, `declared-missing-public-key`,
  `public-key-invalid`, the last two also in the frozen set). **Proposed
  wording.** State whether `sigs[]` reports checks that were not reached.

### F40 — Input identity of a zip target whose archive structure fails

- **Where.** §14.6 (`input`: "for a zip container, the archive bytes").
- **Chosen reading.** The archive bytes, always.
- **Python black-box agreement.** Different, **Python suspected wrong**: the
  reference reports `null`/`null` when the archive has prefix bytes
  (`container/zip-prefix`, `container/zip-over-limit-and-prefix`). Minimal
  reproduction: `hyphaweave-verify container vectors/container/zip-prefix/container.zip --keys vectors/keys/keyset`.

### F41 — Which declarations supply key material for a manifest signature and for a cosignature

- **Where.** §11.3 ("a required key … resolves … through a
  `weave.key.declared` or `weave.key.rotated` record"), §4.4 step 5 ("declared").
- **Readings.** (a) any `weave.key.declared` record carrying the material; (b)
  only structurally valid declarations (as for the governing class); (c) a
  declaration whose envelope and `sigs` format passed, whatever its body rules.
- **Chosen reading.** (c), which is what the black box does; (b) was the first
  H1-FIX1 reading and the differential fuzzing showed the difference
  (`E_KEY_UNKNOWN` versus a verified or `E_MANIFEST_SIG_INVALID` signature).
  **Proposed wording.** Define "resolves" for key material.

### F42 — Does a failed signature equation count for the TOFU predicate?

- **Where.** §14.6 (`N_KEY_TOFU`: "even if that signature or the record then
  fails"), §11.5 ("when the material that verified the equation … came from the
  context"), §14.9.
- **Chosen reading.** For record signatures the context material counts even
  when the equation fails (§14.6); for the manifest and previous signatures it
  counts when it verified the equation (§11.5, "like a target manifest
  signature").
- **Python black-box agreement.** The reference does not count a failed record
  equation (fuzz: no `N_KEY_TOFU` on a record whose context-declared key failed
  the equation; H1 reports it). Minimal reproduction: a
  `key-lifecycle/declaration-duplicate-earliest` record whose signature value is
  altered.
- **Classification (H1-FIX2 Y9, review B).** Two parts. **Record signatures:
  Python suspected wrong** — §14.6 gives a unique answer, `N_KEY_TOFU` is
  reported when a check was context-trusted "even if that signature or the
  record then fails". **Manifest and previous-manifest signatures:
  spec-ambiguous** — §11.5 counts the material "that verified the equation",
  and whether a failed manifest equation contributes `L_KEY_TRUST_TOFU` is not
  said. **Proposed wording.** One sentence in §11.5 stating whether a failed
  manifest or previous-manifest equation counts.

### F43 — Placeholder `origin`/`id` defects

- **Where.** §4.5 ("every structural violation of the placeholder is
  `E_KIND_BODY_SCHEMA`"; "`origin` and `id` have the same grammar … as in a
  normal envelope").
- **Chosen reading.** `E_KIND_BODY_SCHEMA` for an `origin`/`id` defect inside a
  placeholder (H1 had used `E_ENV_ORIGIN`/`E_ENV_ID`); `format` keeps
  `E_ENV_FORMAT`. Matches the black box after the change.

### F44 — A reference to a record that is present but structurally invalid: `missing` or `unverifiable`?

- **Where.** §6.3 (`unverifiable` covers "target present but not valid").
- **Chosen reading.** `unverifiable` (the record is present). The erasure
  cross-checks of §10.3 then match the attestation by identity and digest.
- **Python black-box agreement.** Different: the reference treats a record that
  fails its envelope or `sigs` structure as absent (`N_REF_MISSING`, and
  `E_ERASE_ATTESTATION` for a placeholder whose erasure record is malformed).
  Minimal reproduction: `labels/downgrade` with an `actor.key` removed from the
  target record.
- **Classification (H1-FIX2 Y9, review B), in two tiers.** (a) The target's
  `origin` and `id` are intact (as in the reproduction): §6.3 gives a unique
  answer — `unverifiable` is "a record with that `origin` and `id` is present
  but … it is itself not valid" — so this tier is **Python suspected wrong**.
  (b) The target's `origin` or `id` is itself malformed, so its identity cannot
  be established: **spec-ambiguous** (absent, or present-but-invalid).
  **Proposed wording.** One sentence in §6.3 for tier (b).

### F45 — Agent-only actor members: presence before the grammar of other members

- **Where.** §4.2, §14.5 step (2) (presence → closedness → grammar).
- **Chosen reading.** A missing `idempotency_key` (`E_ENV_ACTOR_IDEMPOTENCY_MISSING`)
  wins over a malformed `on_behalf_of`. **Python suspected wrong**: the
  reference reports `E_ENV_ACTOR_ON_BEHALF`. Minimal reproduction:
  `actor/agent-bad-on-behalf` with `actor.idempotency_key` removed.

### F46 — §4.4 step 5 for signer-constrained kinds whose only entry has an unknown algorithm

- **Chosen reading.** §4.4 step 5 applies: no known-algorithm signature →
  `E_SIG_UNVERIFIABLE` (or `E_KEY_UNKNOWN`), not the dedicated signer code.
  **Python suspected wrong**: the reference reports
  `E_KEY_DECLARED_NOT_SELF_SIGNED` / `E_GRANT_REVOKE_SIGNER`. Minimal
  reproduction: `key-lifecycle/declared-valid` with the only `sigs[].alg`
  changed to `ed25519-x`.

### F47 — An erasure whose authorising grant cannot be established

- **Where.** `spec/kinds/weave.erasure.md` (`E_GRANT_UNRESOLVED`/`E_GRANT_REVOKED`/
  `E_GRANT_EXPIRED` are unverifiable "the authorising grant cannot be
  established") versus "any other combination is `E_ERASE_ACTOR`".
- **Chosen reading.** The grant codes; the reference reports `E_ERASE_ACTOR`.
  Minimal reproduction: `erasure/actor-agent-with-grant-valid` with a required
  member removed from the grant record.
- **Classification (H1-FIX2 Y9, review B): spec-ambiguous** (H1-FIX1 had
  "Python suspected wrong"). The grant record is present but invalid, and both
  sentences of the kind page apply: the agent's `actor.grant` "MUST resolve to a
  valid `weave.grant`", otherwise "any other combination is `E_ERASE_ACTOR`"
  (invalid), versus the error table's "the authorising grant cannot be
  established" (`E_GRANT_UNRESOLVED`, unverifiable). The more conservative
  answer is the reference's `E_ERASE_ACTOR` (invalid rather than
  unverifiable). **Proposed wording.** State which code applies when the
  authorising grant is present but invalid.

### F48 — §10.3 cross-checks when the erasure record and the placeholder do not pair

- **Where.** §10.3 ("When both the placeholder and its erasure record are
  present").
- **Chosen reading.** Every rule is evaluated independently, so a container can
  report `E_ERASE_DIGEST_MISMATCH`, `E_ERASE_ATTESTATION` and
  `E_ERASE_CONTRADICTION` together. The reference reports a subset.
  **Spec-ambiguous.**
  Minimal reproduction: `scripts/diff_fuzz.py` mutant of
  `erasure/valid-container`, class `base64`, seed `4271959529863204925`: H1
  `{E_ERASE_ATTESTATION, E_ERASE_DIGEST_MISMATCH}`, the reference
  `{E_ERASE_DIGEST_MISMATCH}`.

### F49 — Entry checks before content CRC in a zip

- **Chosen reading.** §11.9 (W7): entry paths, symbolic links and duplicates are
  judged before any content is decompressed, so a `readable/../x` entry is
  `E_CONTAINER_ENTRY` even if another member's data fails its CRC. **Python
  suspected wrong**: `E_CONTAINER_ZIP`. Minimal reproduction:
  `container/readable-dotdot-entry` with one byte of a record member's data
  flipped.

### F50 — A malformed `public_key` together with another body-schema defect

- **Chosen reading.** §14.5: `E_KEY_PUBLIC_KEY` instead of `E_KIND_BODY_SCHEMA`.
  **Python suspected wrong**: `E_KIND_BODY_SCHEMA`.
  Minimal reproduction: `scripts/diff_fuzz.py` mutant of
  `key-lifecycle/bad-public-key-does-not-govern`, class `number`, seed
  `3843386067220390351`.
- **Reproduction made explicit (H1-FIX2 Y9).** Review A tried three other
  second defects (an extra body member, `algorithm` `rsa`, a missing
  `key_type`) and both verifiers agreed on all three. The seed above rebuilds,
  and still diverges on the H1-FIX2 head: in that case's declaration
  `org1-bad-pk-human-T0` (whose `public_key` is the malformed `"AAAA"`),
  `body.key` is replaced by the integer `9007199254740991`, the record is
  re-signed with both of its signers (`human-1` and `org-1`) and the
  container rewritten (file name, manifest entry, manifest signature). H1:
  `E_KEY_PUBLIC_KEY` on that record; the reference: `E_KIND_BODY_SCHEMA` (and
  lists the record's signatures, both `valid`). So the divergence is specific
  to a second defect in `body.key` itself, the member that names the key
  whose material is malformed.
- **Correction (H1-FIX2B Z4, narrow re-check low-4).** The H1-FIX2 text said
  "re-signed with `human-1`" only. Re-signed that way, the `org-1` signature
  keeps its old value and the reference reports `E_SIG_INVALID` instead of
  `E_KIND_BODY_SCHEMA` (H1 still `E_KEY_PUBLIC_KEY`); the divergence above
  needs both signatures re-signed.

### F51 — Reference verifier crashes

- **Python bug.** The reference exits with a Python traceback (`KeyError: 'key'`)
  when a `weave.key.declared` or `weave.key.revoked` record in a container lacks
  `body.key`; §13/§15 require a report, never a crash. Minimal reproduction:
  `container/l0-minimal` with `body.key` removed from its declaration (and the
  manifest re-signed). The Rust verifier reports `E_KIND_BODY_SCHEMA`.

### F52 — `sigs[].state` for a signature whose key state fails §9.4

- **Where.** §14.6 (S8⑩): `unverified` when the key state fails (expired,
  revoked, compromised).
- **Python suspected wrong**: the reference reports `valid` (29 committed cases
  differ only in this field; allow-listed).

### F53 — The target of a grant revocation must "resolve"

- **Where.** §5.5.4 ("The reference MUST resolve to a `weave.grant` record …").
- **Chosen reading.** §6.3 resolution (`found`: present, matching digest,
  valid); a revocation of an invalid or unverifiable grant record is
  `E_GRANT_REVOKE_REF`. H1 had matched by identity and digest only; changed
  after the differential fuzzing (the black box does the same).

### F54 — Unlisted `.tsr` files, and which stage reports them

- **Where.** §11.3 ("every `.tsr` file in `signatures/` MUST appear in
  `timestamps`, … `E_TS_FILE`"), §12.2 W6 (file checks).
- **Chosen reading.** An unlisted receipt file is a file-check failure of the
  timestamp phase: `E_TS_FILE`, every listed receipt invalid, nothing below
  runs (so §9.4 sees no usable receipt). **Python suspected wrong** for
  ignoring an unlisted `.tsr` altogether. Minimal reproduction:
  `labels/propagation-reshaped_from-downgrade` plus an empty
  `signatures/timestamp-9.tsr`.

### F55 — Order inside steps (7)–(9) that the vectors do not reach

- The required-signer code versus the delegation checks of a sub-grant (H1:
  `E_GRANT_GRANTER` first; the reference: `E_GRANT_DELEGATION_EXCEEDS`), the
  actor-key class check versus agent grant coverage (H1:
  `E_ACTOR_KEY_TYPE_MISMATCH`; the reference: `E_GRANT_UNRESOLVED`), the consent
  checks versus label propagation inside step (9) (the reference reports
  `N_LABEL_PROPAGATION_UNCHECKED` on a record that then fails its consent kind
  check; H1 stops first). **Spec-ambiguous**; each needs one sentence in
  §14.5.
  Minimal reproductions (`scripts/diff_fuzz.py`): `actor/agent-with-human-key`,
  class `sigs`, seed `860462574772497619` (H1 `E_ACTOR_KEY_TYPE_MISMATCH`, the
  reference `E_GRANT_UNRESOLVED`); `labels/consent-kind-mismatch`, class
  `refs`, seed `4136374855248767585` (same error, the reference adds
  `N_LABEL_PROPAGATION_UNCHECKED`).
- An unlisted file in `records/` above `MAX_RECORD_BYTES`. The gate-4 run and
  the 300 MiB replays found H1 reporting only `E_MANIFEST_RECORD_EXTRA` and the
  reference only `E_JSON_SIZE`. §14.5 lists `E_JSON_SIZE` "for record files
  above `MAX_RECORD_BYTES`" among the independent violations of the
  records-listing phase without restricting it to listed files, so H1 now
  reports both (`tests/probes.rs`,
  `unlisted_oversize_record_file_reports_both_listing_violations`). The
  committed `oversize-record-*` vectors only have listed oversize files.
  Minimal reproduction: `scripts/diff_fuzz.py` mutant of
  `container/oversize-record-with-missing`, class `container`, seed
  `617063513226618884` (the oversize file renamed): H1 now
  `{E_JSON_SIZE, E_MANIFEST_RECORD_EXTRA, E_MANIFEST_RECORD_MISSING}`, the
  reference `{E_JSON_SIZE, E_MANIFEST_RECORD_MISSING}`.
  **Correction (H1-FIX2).** The sentence above was not true on the H1-FIX1
  head: that mutant renames the file to an upper-case, hence misnamed, name,
  and the H1-FIX1 change only measured unlisted files with a `<hex>.json`
  name, so H1 reported `{E_MANIFEST_RECORD_EXTRA, E_MANIFEST_RECORD_MISSING}`
  (no `E_JSON_SIZE`). The H1-FIX2 gate-5 rerun of seed 20261114 found it;
  commit `17e78a1` measures misnamed `records/` files too, and the sentence
  now holds (probe
  `misnamed_oversize_record_file_reports_both_listing_violations`).
  **How it is measured (H1-FIX2B Z2, narrow re-check low-1).** `17e78a1`
  took the directory form's size from the filesystem
  (`symlink_metadata().len()`), against §13's "MUST NOT rely on
  filesystem-reported sizes"; the directory form now reads such a file
  through a probe bounded by `MAX_RECORD_BYTES` plus one byte (counted toward
  the container total, as every read is) and keeps only the size. The zip
  form keeps the central directory's declared size (the member is not
  decompressed); a zip-form test now covers it
  (`misnamed_oversize_record_member_in_zip_reports_both_listing_violations`).
  **Classification (H1-FIX2 Y9, review B): Python suspected wrong** (H1-FIX1
  had "spec-ambiguous"). §11.6 item 5 reports an unlisted file as
  `E_MANIFEST_RECORD_EXTRA` without condition; §13 names "an oversized
  `records/` file" without restricting it to listed files and reads each file
  through a probe bounded by its class limit; §14.5 has the records-listing
  phase report "every independent violation it detects together", naming both
  codes. The only gap is the word "detects". **Proposed wording** (after §11.6
  item 5, or after the U8 sentence of §14.5): "A file in `records/` is subject
  to `MAX_RECORD_BYTES` whether or not it is listed; an unlisted or misnamed
  file above that limit reports both `E_MANIFEST_RECORD_EXTRA` and
  `E_JSON_SIZE`."
- The first part of this finding (the order inside steps (7)–(9)) stays
  **spec-ambiguous**.

### F56 — Timestamps listed under L0/L1

- **Where.** §11.3 ("It is empty for L0/L1 (`E_MANIFEST_LEVEL` otherwise)").
- **Rust.** `E_MANIFEST_LEVEL` at step (6). **Python suspected wrong**: the
  reference accepts an L1 manifest whose attestation lists receipts and reports
  later-stage codes. Minimal reproduction: `integrity-levels/l2-valid` with the
  manifest level changed to `L1` and the manifest re-signed.

## H1-FIX2 (2026-11-15): findings from the two re-reviews

Recorded for decision 2026-11-15 #3 (rulings Y1–Y10). Each item below either
records a Rust change made in this revision or a question for the
specification and the reference verifier. "Both CLIs" means the H1-FIX2 Rust
binary and the reference verifier installed non-editable from
`git archive origin/main` (`5474cf7`), run as black boxes.

### F57 — §12.2 1a: universal tag 0 and a non-minimal ENUMERATED inside an open type

- **Where.** §12.2 check 1, sub-step 1a (the universal DER rules applied to
  every TLV) and 1c (an open type: "only its framing … is judged").
- **Possible readings.** (a) 1a means **all of X.690 (DER)** for every
  universal TLV: universal tag number 0 is reserved for the encoding rules
  (end-of-contents only occurs in the indefinite form, which DER forbids), and
  ENUMERATED is encoded as an INTEGER (X.690 §8.4), so it must be minimal. (b)
  1a is the **list it enumerates**: "tag numbers 0–30 use the single-octet
  identifier" admits tag 0 as an identifier, and the type rules name INTEGER but
  not ENUMERATED, so neither is a violation inside an open type.
- **Chosen reading.** (a), X.690 throughout; the Rust code is unchanged (Y3).
- **Python black-box agreement.** Different — a judgement-level split (one
  side `valid`, the other `invalid`). Minimal reproduction (review A,
  reproduced on the H1-FIX2 head): `integrity-levels/l2-valid` whose receipt
  gains one unknown unsigned attribute (outside the signature) whose value is
  the open-type TLV below, the receipt digest in the attestation file updated:

  | attribute value | H1 | reference |
  |---|---|---|
  | `00 00` (universal 0, definite length) | `invalid` `E_TS_SCHEMA` | `valid` |
  | `30 02 00 00` | `invalid` `E_TS_SCHEMA` | `valid` |
  | `00 01 00` | `invalid` `E_TS_SCHEMA` | `valid` |
  | `0a 02 00 01` (ENUMERATED, non-minimal) | `invalid` `E_TS_SCHEMA` | `valid` |

  A minimal ENUMERATED (`0a 01 01`) is `valid` on both. Review A also saw
  the split with `00 00` as a non-signer certificate, and its fuzzing hit it
  three times naturally (a signer certificate overwritten with zero bytes: H1
  `E_TS_SCHEMA`, the reference `E_TS_CMS`).
- **Vector pinning.** None.
- **Proposed wording** (§12.2 1a, one sentence): "Universal tag number 0 never
  occurs, and ENUMERATED follows the INTEGER rules (X.690 §8.4)" — or, if
  reading (b) is intended, "1a lists all universal rules; any other universal
  tag is judged on its framing only". Either way, a vector pair (`00 00` and
  `0a 02 00 01` as an unsigned attribute value) should pin it.

### F58 — Record identity is `(origin.project, origin.instance, id)` (Y1)

- **Where.** §4.1 (`origin` is `{project, instance}`), §6.3 (resolution by
  "that `origin` and `id`"), §10.3 rules 1 and 3.
- **Rust change.** H1-FIX1 indexed the context by `(project, id)` (review B
  L4, kept in F27 with a wrong reason). H1-FIX2 keys references, the §10.3
  placeholder match and the contradiction count by the full identity (commit
  `ce3e75e`). Three cases, each a `verify_container` test in
  `verifiers/rust/hyphaweave-verify/tests/identity.rs`; reverting the key to
  `(project, id)` turns all three red:
  1. A reference to `(example, human-1, ref-target, D)` where the context only
     has `(example, human-2, ref-target)` with another digest: **`missing`**
     (§6.3: "no record with that `origin` and `id`"), not `unverifiable`.
  2. `erasure/valid-container` with the placeholder's `origin.instance` changed
     to `human-2` (its `digest` still the erased digest):
     **`E_ERASE_DIGEST_MISMATCH`**, container invalid (§10.3 rule 1: "an
     `origin`/`id` mismatch"). The old key accepted it as valid: a placeholder's
     own `origin` is not covered by the digest it carries.
  3. Two placeholders with the same project and `id` but instances `human-1`
     and `human-2`, each with its own signed erasure record: **valid**, no
     `E_ERASE_CONTRADICTION` (rule 3: "two placeholders for the same target").
- **Python black-box agreement.** Same as the new H1 on all three (built as
  directory containers, both CLIs): `missing` + `N_REF_MISSING`;
  `E_ERASE_DIGEST_MISMATCH`; valid.
- **Vector pinning.** None. **Request to the specification side (S2):** add
  the three cases as vectors; both implementations already agree.

### F59 — Two L2 checks that no vector reaches (Y2)

- **Where.** §12.2 1c DEFAULT table, row `Extension.critical` ("certificate,
  CRL, CRL-entry and TSTInfo extensions", `01 01 00`); §11.3/§12.4 ("`renews` is
  `null` for the first receipt of the timestamp chain").
- **Finding (review A M-2).** Disabling either check left all 700 vectors and
  the whole `cargo test` green; a single-receipt `l2-valid` whose `renews`
  names itself then verified `valid`.
- **Rust change.** Tests only (commit `dc1e902`,
  `tests/l2_probes.rs`): a TSTInfo extension with `critical` explicitly FALSE
  (receipt rebuilt, `messageDigest` recomputed, SignerInfo re-signed with the
  test TSA key) is `E_TS_SCHEMA`, while the twins with `critical` absent or
  TRUE are valid; `renews` set to the receipt's own path or to an unlisted path
  is `E_TS_RENEWAL`. Disabling either check turns its test red (the defective
  container then verifies valid).
- **Python black-box agreement.** Same on all five inputs (critical
  absent/TRUE valid, FALSE `E_TS_SCHEMA`; both `renews` variants
  `E_TS_RENEWAL`).
- **Request to S2.** Vectors for the explicit `critical FALSE` (TSTInfo, and
  preferably also a signer-certificate and a CRL extension) and for a non-null
  chain-head `renews`.

### F60 — Nesting above `MAX_JSON_DEPTH` inside a container record (review A L-1)

- **Where.** §1.9 ("A depth above `MAX_JSON_DEPTH` is `E_JSON_SIZE` and, like
  any size violation …"); §14.5 records-listing phase ("`E_JSON_SIZE` for record
  files above `MAX_RECORD_BYTES`"); §11.6 item 2 (no dedicated code for a record
  file whose digest cannot be computed).
- **Possible readings.** (a) A too-deep record file is a size violation of the
  listing phase: container-level `E_JSON_SIZE` (H1). (b) The record file cannot
  be parsed, so its listed digest cannot be confirmed:
  `E_MANIFEST_RECORD_DIGEST` (the reference).
- **Python black-box agreement.** Different. Minimal reproduction (re-run on
  the H1-FIX2 head): `container/l0-minimal` whose record gains a top-level
  member holding 32 nested arrays (depth 33, the record object counting as 1),
  re-signed, container rewritten: H1 `invalid`, container `[E_JSON_SIZE]`, no
  record reported; the reference `invalid`, container
  `[E_MANIFEST_RECORD_DIGEST]`. At depth 32 both report the record's own
  `E_ENV_UNKNOWN_FIELD`. Review A: a truncated record or a duplicate key is
  `E_MANIFEST_RECORD_DIGEST` on both; 35 fuzz mutants hit this split.
  **Spec-ambiguous.**
- **Proposed wording.** §14.5: state that a record file deeper than
  `MAX_JSON_DEPTH` is reported in the listing phase as `E_JSON_SIZE` (or as
  `E_MANIFEST_RECORD_DIGEST`).

### F61 — Reference-verifier deviations found by review A's fuzzing (review A L-2)

Reported by review A on the H1-FIX1 head (seed 151115); not rebuilt one by one
in H1-FIX2 (the H1-FIX2 gate-5 rerun of the same seed is summarised under
"H1-FIX2 gate results").

1. **A compromised key rescued by an invalid receipt** (security relevant).
   When the container's receipt fails check 1 or the CMS checks
   (`E_TS_SCHEMA`/`E_TS_CMS`), a record signed with a key that was later
   reported compromised can only be rescued by that receipt. §9.4 case 2:
   "receipts are present, but none of them is verified … `E_TS_UNTRUSTED`". H1
   reports the record `unverifiable` `E_TS_UNTRUSTED`; the reference reports
   the record **`valid`**. The container verdict is `invalid` on both (the
   receipt error). Base case: `container/previous-signing-key-compromised-after-previous`
   with its receipt damaged (23 mutants). **Python suspected wrong.**
2. **A crash.** `weave.key.revoked` with `effective_at` written with a space
   instead of `T` (`2026-11-01 00:00:00.000Z`): the reference exits with a
   Python traceback (`ValueError: time data … does not match format`); H1
   reports `E_KIND_BODY_SCHEMA`. §13/§15 require a report. A different crash
   site from F51. **Python bug.**
3. **Key-id syntax in `weave.key.rotated`.** `old_key`/`new_key` malformed or
   of another type: H1 `E_KIND_BODY_SCHEMA` (the key-id grammar of the body
   table, §14.5 step 6), the reference `E_KEY_ROTATION_KEYS` or
   `E_KEY_UNKNOWN`. `E_KEY_ROTATION_KEYS` covers the public-key structure and
   contradictions of a rotation, not the key-id syntax. Same family as F50.
   **Python suspected wrong**; one sentence in the kind page would remove the
   doubt.

### F62 — Signer certificate `version` (Y5, review B L-4)

- **Where.** §12.2 1e ("decodes as an X.509 certificate"), 1c DEFAULT table
  (`TBSCertificate.version`, `a0 03 02 01 00`); RFC 5280 §4.1: `version [0]
  EXPLICIT Version DEFAULT v1`, `Version ::= INTEGER { v1(0), v2(1), v3(2) }`,
  and the module comments "If present, version MUST be v2 or v3" (unique
  identifiers) and "If present, version MUST be v3" (extensions).
- **Reading (Y5).** The specification adds no version rule, so the RFC 5280
  module is the criterion: v1 is the absent field (an explicit v1 is a DEFAULT
  value encoded, already rejected by the DEFAULT row), v2 and v3 are encoded;
  a version outside v1..v3 is rejected; extensions require v3 and unique
  identifiers v2 or v3. H1-FIX1 accepted only explicit v2/v3 (or the absent
  field) and did not enforce the two module constraints; H1-FIX2 adds them
  (commit `ae3ab58`, unit test `timestamp::tests::certificate_versions`).
  The same walk decodes `--tsa-trust` anchors.
- **Open point.** RFC 5280 also says implementations "SHOULD be prepared to
  accept any version certificate"; the named-number list is not a value
  constraint in ASN.1. Whether a version above v3 is "decodes as an X.509
  certificate" is not said. **Proposed wording** (§12.2 1e): "The signer
  certificate's `version` is v1 (absent), v2 or v3, with the RFC 5280 module
  constraints on `extensions` and the unique identifiers."
- **Python black-box agreement.** Not exercised by the committed cases.
  The H1-FIX2 narrow re-check (low-3) exercised it as a `--tsa-trust` anchor
  (the same certificate walk as 1e), with `container/l2-valid`'s
  `tsa.crt.pem` rebuilt in six version shapes. Three of them diverge:

  | anchor | H1 | reference |
  |---|---|---|
  | v3 rebuilt unchanged | exit 0, `valid` | exit 0, `valid` |
  | v1 (version absent) + `extensions` | **exit 2** (anchor rejected) | exit 1, `E_TS_UNTRUSTED` (accepted as an anchor) |
  | v2 + `extensions` | exit 2 | exit 2 |
  | v4 + `extensions` | exit 2 | exit 2 |
  | v1 + `issuerUniqueID` | **exit 2** | exit 1 (accepted) |
  | v2 + `issuerUniqueID` | exit 1 (accepted) | **exit 2** (appears to reject every v2) |

  H1 follows the RFC 5280 text (§4.1.2.1 "When extensions are used … version
  MUST be 3", §4.1.2.8 unique identifiers "MUST only appear if the version
  is 2 or 3", §4.1.2.9 extensions "MUST only appear if the version is 3");
  the reference looks like it accepts v1 and v3 only and does not check the
  two module constraints. **Python suspected wrong** on all three rows.
  **Request to S2:** vectors for v1 + `extensions`, v1 + `issuerUniqueID` and
  v2 + `issuerUniqueID`, as the signer certificate (1e) and as a
  `--tsa-trust` anchor, together with the proposed wording above.

### F63 — Open types inside the signer certificate; `--tsa-trust` strictness (review A L-3)

Reported by review A from its re-signed probes; not rebuilt in H1-FIX2.

- **Signer-certificate open types: Python suspected wrong.** §12.2 1c lists
  `AlgorithmIdentifier.parameters` (other than the signer's own digest and
  signature algorithms) and `AttributeTypeAndValue.value` as open types. A
  signer certificate whose subject CN is a PrintableString with `@` or `*`, or
  whose TBS or outer `signatureAlgorithm` parameters are `04 00`: H1 passes
  check 1 (and verifies when that certificate is the anchor); the reference
  reports `E_TS_SCHEMA`, or exits 2 when the same certificate is given as
  `--tsa-trust`. Review A: 4 of its 161 unique-answer probes, and 6 replays of
  S1's `string-printable-bad-charset`.
- **`--tsa-trust` decoding strictness: spec-ambiguous.** §14.1 makes a trust
  file that "does not decode as an X.509 certificate" a usage error, without
  saying how strict the decoding is. A certificate whose `extnValue` holds a
  non-minimal length or trailing bytes: H1 rejects it as an anchor (exit 2,
  same strict walk as 1e); the reference accepts it. **Proposed wording.**
  "decodes under the rules of §12.2 1e" (or name the looser rule).

### F64 — Check 10 results that the cryptographic libraries decide (Y8, review B L-2)

- **Where.** §12.2 check 10 (the CMS signature verifies with the signer
  certificate's public key); the specification has no key-size, exponent or
  signature-encoding rule.
- **What decides today.** Check 1 never uses a parsing library. Check 10 does:
  - RSA: `rsa` 0.10 `PublicKey` (`src/public_key.rs`) accepts a modulus of
    1,024 to 8,192 bits and a public exponent from 2 to 2^33 − 1; any other key
    makes H1's check 10 fail (`E_TS_CMS`).
  - ECDSA: the strictness of the DER `Ecdsa-Sig-Value` decoding is that of
    `ecdsa` 0.17 `Signature::from_der` (P-256/P-384).
- **Severity.** Low: the receipt bytes are fixed by the attestation digest, so
  signature malleability has no security consequence; but this is the "a
  library's habit as a criterion" that X1 excluded for check 1.
- **Request to S2.** Either write the bounds into §12.2 check 10 (for example
  "RSA moduli of 2,048 to 8,192 bits, public exponent 3 to 2^33 − 1;
  `Ecdsa-Sig-Value` in DER") or declare them implementation-defined.

### F65 — P-384 has no committed vector (review A L-6)

- Review A ran a new P-384 key and self-signed certificate end to end: SHA-384
  with parameters absent `valid`, with `NULL` `E_TS_SCHEMA`, P-384 with SHA-256
  `valid`, a wrong signature `E_TS_CMS`, an EC key with an RSA algorithm
  `E_TS_CMS`. Both verifiers agreed on all of them; H1 also has the unit test of
  F27. **Request to S2:** turn these five into vectors.

### F66 — EXTERNAL, EMBEDDED PDV and CHARACTER STRING are constructed-only (Y4, review B L-3)

- **Where.** §12.2 1a ("the string … types" are primitive-only) and X.690
  §8.18 (EXTERNAL, 8), §8.19 (EMBEDDED PDV, 11), §8.21.1 (CHARACTER STRING, the
  unrestricted character string type, 29).
- **Rust change.** H1-FIX1 listed 29 as primitive-only and let the primitive
  form of 8, 11 and 29 pass. H1-FIX2 (commit `152e597`) follows X.690: their
  constructed form passes framing, their primitive form is a 1a violation.
- **Python black-box agreement.** Different for the primitive form. A valid
  receipt with one unknown unsigned attribute (outside the signature) whose
  value is the TLV below, attestation digest updated:

  | value | H1 | reference |
  |---|---|---|
  | `08 01 00`, `0b 01 00`, `1d 01 00` (primitive) | `invalid` `E_TS_SCHEMA` | `valid` |
  | `28 03 02 01 01`, `2b 03 02 01 01`, `3d 03 02 01 01` (constructed) | `valid` | `valid` |

  Same family as F57 (whether 1a is X.690 in full or the list it names).
- **Proposed wording.** Add to 1a: "EXTERNAL, EMBEDDED PDV and CHARACTER
  STRING use the constructed form only (X.690 §8.18, §8.19, §8.21)", and a
  vector pair.

### F67 — More reference-verifier deviations from the H1-FIX2 fuzzing

- **A `sigs` entry member of the wrong JSON type.** §4.3: "Structural errors
  of the array or of an entry's closed shape are `E_ENV_SIGS`, including a
  member of an entry that is present with the wrong JSON type"; the
  per-member codes apply "when the member is a string". An `ed25519` entry
  whose `value` is the number `2`: H1 `E_ENV_SIGS`, the reference
  `E_ENV_SIG_VALUE`. Reproduction: `scripts/diff_fuzz.py`,
  `key-lifecycle/context-trusted-tofu-limitations`, class `number`, seed
  `1615007253324860239`. **Python suspected wrong.**
- **More crash sites** (besides F51 and F61-2). Inputs on which the
  reference exits with a Python traceback instead of a report (§13/§15):
  a declaration without `body.key_type` (`KeyError: 'key_type'`), a
  revocation without `body.effective_at` (`KeyError: 'effective_at'`), a
  timestamp without fractional seconds (`2026-11-01T00:00:00Z`), or with
  day 31 of a 30-day month or second 60 (`ValueError`). H1 reports a §14.5
  code for each (mostly `E_KIND_BODY_SCHEMA`). **Python bug.** Counts in
  "H1-FIX2 gate results".
- **Agent presence before grammar, two more shapes** (F45 family):
  `actor/agent-missing-grant` with `on_behalf_of` a number (H1
  `E_ENV_ACTOR_GRANT_MISSING`, the reference `E_ENV_ACTOR_ON_BEHALF`) and
  `actor/agent-missing-on-behalf` with `actor.key` a number (H1
  `E_ENV_ACTOR_ON_BEHALF_MISSING`, the reference `E_ENV_ACTOR_KEY`). §14.5
  step (2): presence, then closedness, then grammar. **Python suspected
  wrong.**

### F68 — §5.5.2: chain validity (step 6) before the depth bound (step 7) — Rust changed

- **Where.** §5.5.2: "The parent chain is evaluated in the following order,
  and the first failing check determines the error"; Appendix A P5 marks the
  precedence among the chain codes as a PROVISIONAL shape that "a verifier
  MUST follow".
- **Rust change.** H1-FIX1 checked the step-7 depth bound during the
  structural walk (steps 1–5) and the step-6 window and revocation state
  afterwards. A note citing `grant/chain-depth-9-links`' depth-9 grant, with
  its `recorded_at` after every grant's window, was therefore
  `E_GRANT_UNRESOLVED` (H1) against `E_GRANT_EXPIRED` (the reference). The
  stated order gives `E_GRANT_EXPIRED`, so H1 was wrong. Found by the H1-FIX2
  gate-5 run of seed 151115 (`grant/chain-depth-9-links`, class `time`, seed
  `1563098227896494338`); fixed in commit `f7e3df9`, pinned by
  `tests/precedence.rs`. Both verdicts were `unverifiable`.
- **Completed (H1-FIX2B Z1, narrow re-check medium-1).** `f7e3df9` moved
  step 7 after step 6 but the step-6 walk itself still stopped at the depth
  bound, so a failure on a link beyond the bound was not seen: with
  `grant-depth-root` (the tenth grant walked for the note) revoked by
  `human-1` before the note's `recorded_at`, H1 still reported
  `E_GRANT_UNRESOLVED` and the reference `E_GRANT_REVOKED`. Step 6 now walks
  the entire chain ("the cited grant and every ancestor"), stopped only by a
  cycle; step 7 is decided afterwards. Both call sites (a cited grant, and a
  `weave.grant` record whose own ancestors are judged at its `recorded_at`)
  share that walk and are pinned by `tests/precedence.rs`:
  `grant_chain_validity_covers_links_past_the_depth_bound` (root revoked →
  `E_GRANT_REVOKED`) and `grant_record_chain_validity_is_judged_before_depth`
  (a `grant-depth-10` record: alone `E_GRANT_UNRESOLVED`, recorded after
  every window `E_GRANT_EXPIRED`, root revoked `E_GRANT_REVOKED`). Reverting
  either call site to the old order, or restoring the bound in the walk,
  turns them red.
- **Open point.** Steps 1–5 on links beyond the depth bound are not walked
  (the structural walk stops at the bound; step 6 now covers them); whether a
  step-2 to step-5 failure on a 10th link should outrank step 7 is not said.
  **Request to S2:** vectors for the expired-and-too-deep case and for a
  revoked root beyond the bound (the note of `grant/chain-depth-9-links` plus
  a revocation of `grant-depth-root`), both call sites.

### F69 — Order questions inside steps (7) and (8) found by the H1-FIX2 fuzzing

All four are **spec-ambiguous**; in each, H1 and the reference pick different
first failures and the text does not order them. Reproductions are
`scripts/diff_fuzz.py` mutants (case, class, seed).

1. **Where the §4.4 step-5 outcome sits for the signer-constrained kinds.**
   §14.5 says the dedicated signer code is "emitted at step (7)" and, "when
   there is no known-algorithm declared-key signature at all", the record is
   `E_KEY_UNKNOWN` or `E_SIG_UNVERIFIABLE`, without a step. H1 decides it with
   the signer obligation, after the kind's body (including the consent window
   rule) and before the grant-chain checks; the reference reports grant-chain
   codes first and the signature outcome before the consent window. Examples:
   `grant/parent-expired`, `sigs`, `3154292035054101878` (H1
   `E_SIG_UNVERIFIABLE`, the reference `E_GRANT_EXPIRED`);
   `grant/sub-grant-expands-kinds`, `sigs`, `4136488168248786250` (H1
   `E_SIG_UNVERIFIABLE`, the reference `E_GRANT_DELEGATION_EXCEEDS`);
   `grant/parent-not-authorising`, `sigs`, `755171691454986662` (H1
   `E_SIG_UNVERIFIABLE`, the reference `E_GRANT_GRANTER`);
   `labels/consent-validity`, `sigs`, `2929257818963171381` (H1
   `E_CONSENT_VALIDITY`, the reference `E_SIG_UNVERIFIABLE`).
2. **Consent window versus the consent signer rule**, both step (7):
   `labels/consent-validity`, `sigs`, `1740247710176792193` (H1
   `E_CONSENT_VALIDITY`, the reference `E_ACTOR_KEY_TYPE_MISMATCH`).
3. **§5.4 bullet order**, grantee versus window: `grant/grantee-mismatch`,
   `time`, `4197516580675169878` (H1 `E_GRANT_EXPIRED`, the reference
   `E_GRANT_GRANTEE_MISMATCH`). §5.4 lists the grantee rule before the window
   rule but does not say the list is an order.
4. **Is a key named only by the rotation itself "declared" for §4.4 step 4?**
   `container/previous-rotation-material-untrusted`, `sigs`,
   `3286669199506339158`: the new key's entry gets an unknown `alg`, the old
   key's entry verifies with the rotation's `old_public_key`, and neither key
   has a declaration. H1 treats the old key as a required, resolvable key
   (§11.3's "resolves … through a `weave.key.declared` or `weave.key.rotated`
   record") and reports `E_KEY_ROTATION_SIGS` (step 4); the reference reports
   `E_KEY_UNKNOWN` (step 5). Same family as F41.

**Proposed wording.** One sentence each in §14.5 (where the step-5 outcome
sits), the consent kind page, §5.4 ("in this order") and §4.4 (whether a
rotation's own key material counts as declared).

- **F48, one more shape.** A structurally invalid placeholder (`refs` added,
  `E_KIND_BODY_SCHEMA`) as the target of an erasure record: H1 reports
  `E_ERASE_DIGEST_MISMATCH` (no usable placeholder), the reference no
  container error. `erasure/actor-program-basis-lacks-erase`, `refs`,
  `4170755898233117835`. Spec-ambiguous (whether a malformed placeholder is
  "present" for §10.3).

### Not changed in H1-FIX2

- **The CLI always carries the test hooks** (review A L-5). The
  `hyphaweave-verify-rs` crate enables the library's `test-hooks` feature; the
  hook is read only behind the explicit `--test-hooks` switch and then exits 3,
  as §14.7 and ruling R3 require. Review A's runs confirm the hook is inert
  without the switch.

## S2 dispositions (decision 2026-11-15 #8)

The S2 round of specification revision 3 settled the findings below in the
specification (rules tagged `[S2]`, `docs/open-questions.md` §7) and in the Python
reference verifier. "Python corrected" means the reference verifier was wrong
against the text and now follows it; "spec sentence" means the text admitted two
readings and the more conservative one was written; "Rust to follow" names what the
H1 follow-up has to change. Every row has a vector unless it says otherwise.

| finding | disposition | Rust to follow |
|---|---|---|
| F38, F61-1 | spec sentence (§9.4, §5.3): every signature of a declaration or rotation is judged under §9.4 for its verdict; Python corrected (the self-signature exemption was the F61-1 security defect) | none (already this reading) |
| F39 | spec sentence: `E_KEY_PUBLIC_KEY` precedes step (4), `sigs` is `[]`; Python corrected | none |
| F40 | Python corrected (§14.6 was unique) | none |
| F42 | records: Python corrected; manifest: spec sentence (a failed equation adds no TOFU, both agree) | none |
| F44 | tier a: Python corrected; tier b: spec sentence (no identity, `missing`) | none observed |
| F45, F67 (actor) | Python corrected | none |
| F46 | Python corrected; §4.4 step 5 reworded to the required signer (frozen `sig/unknown-alg`) | none |
| F47 | open for the founder (text unchanged) | — |
| F48 | spec sentence: the §10.3 rules are independent; Python corrected | none |
| F49, F50, F51, F52, F54, F56 | Python corrected | none |
| F55 | second part: spec sentence (U8), Python corrected; first part (orders in steps (7)–(9)): open for the founder | — |
| F57, F66 | spec sentence (1a: tag 0, ENUMERATED, constructed-only; list closed); Python corrected | none |
| F58 | vectors (both already agreed) | none |
| F59 | vectors (`Extension.critical` FALSE in the signer certificate and in TSTInfo; chain-head `renews`) | none |
| F60 | spec sentence (`E_JSON_SIZE` in the listing phase); Python corrected | none |
| F61-2, F67 (crashes) | Python corrected; inputs in the crash corpus | none |
| F61-3 | spec sentence (a new rule decided by principle): key ids are checked as body schema **before** the key-material rule and before key resolution | **yes**: the Rust verifier already reports `E_KIND_BODY_SCHEMA`, but after the signature layer, so its `sigs` lists the two signatures; to follow: decide it before step (4), `sigs` `[]` (`key-lifecycle/rotation-old-key-malformed`, `rotation-new-key-wrong-type`; corrected by S2-FIX1 T4) |
| F62, F63 | spec sentence (1e and `--tsa-trust` by the module rules); Python corrected | none |
| F64 | open for the founder (check-10 bounds) | — |
| F65 | vectors (P-384) | none |
| F67 (`sigs` member type) | Python corrected | none |
| F68 | spec sentence (step 6 covers the whole chain before step 7); open point (steps 1–5 beyond the bound) for the founder | none for the decided part |
| F69-1, F69-2 | open for the founder | — |
| F69-3 | spec sentence (a new rule decided by principle; the order Python already had) | **yes**: grantee before window (`grant/grantee-mismatch-before-window`, added by S2-FIX1 T4) |
| F69-4 | spec sentence: a rotation's key material declares its keys (§4.4) | none |
| signature entries | spec sentence: step (4) over every entry, every entry judged (the Rust reading); Python corrected | none |

### S2-FIX1 dispositions (decision 2026-11-15 #13)

| finding | disposition | Rust to follow |
|---|---|---|
| F47 | founder ruling Q1: a present but invalid grant is `E_ERASE_ACTOR`; a grant that cannot be established keeps the grant codes | **yes**: `erasure/actor-agent-grant-present-invalid`, `actor-program-basis-present-invalid`, `actor-agent-grant-expired-and-lacks-erase` |
| F38 trust half (Q2) | founder ruling Q2: a cosignature or old-key signature that fails §9.4 supplies no material and no trust | **yes** for the cosignature half and for the new-key half (`key-lifecycle/declaration-cosigner-*-note-by-device`, `rotation-new-key-compromised-note-by-new-key`); the old-key half already agrees |
| F55 first part, F69-1, F69-2 | founder ruling Q3: step-5 outcome last in step (7); record-local rules, signer rule, cross-record rules; no step-(9) notice on a failed record | **yes**: `grant/*-step5-outcome-last`, `key-lifecycle/declaration-class-conflict-before-step5-outcome` |
| F64 | founder ruling Q4: RSA 2,048–8,192 bits, 65,537 ≤ `e` < 2^256 odd; strict ECDSA DER | **yes**: `integrity-levels/l2-ts-check10-rsa-1024`, `l2-ts-check10-rsa-exponent-3` |
| F68 open point | founder ruling Q5: steps 1–5 walked beyond the bound (observable only through step 1) | none observed (`grant/chain-depth-9-root-not-transferable`, `chain-depth-9-first-link-exceeds` pass) |
| signature entries | S2-FIX1 T2: invalid first | **yes**: `key-lifecycle/signature-key-resolution-before-equation`, `signature-revoked-entry-beats-unknown-key` |
| F57, F66 (1a list) | S2-FIX1 T3: X.690 tag by tag | **yes**: 21 of the `integrity-levels/l2-ts-der-1a-*` cases |
| F59 (CRL) | vectors `integrity-levels/l2-ts-crl-extension-critical-*` | none |
| F69-4 | vector `key-lifecycle/rotation-own-material-declares-its-keys` | none |

Gate 3 after S2: the 37 allow-listed differences are gone (both reports are
byte-identical on every committed case the Rust verifier passes), so the allow
list in `verifiers/rust/scripts/gate3_known_differences.json` is stale and fails
the gate until the H1 follow-up empties it.

## H1-S2 follow-up (decision 2026-11-15 #20)

The Rust verifier follows every "Rust to follow" row of the two tables above, and the
three deviations that review A (low-1) found by differential fuzzing without a vector.
Each row names where the rule now lives.

| item | rule | Rust change |
|---|---|---|
| F61-3 | §9.2 rule 2, §14.5 | `kinds::key_material_structural_error`: `new_key`/`old_key` key-id syntax first, `E_KIND_BODY_SCHEMA` before the signature layer, `sigs` `[]` |
| Q2 (F38 trust half) | §5.3, §9.4, kind pages | `World::declaration_admitted` checks every non-subject signature of a declaration under §9.4 (only those, so the subject key's own lifecycle never decides admission); `admitted_trusted` / `admitted_declared_material` give no material from a declaration that fails it. `World::rotation_admitted` re-evaluates an invalid rotation once with only its new-key signature exempt from §9.4 |
| T2 | §4.4 step 2, §14.5 | `record::evaluate_normalized`: the first invalid entry decides before `E_KEY_UNKNOWN`; `N_KEY_UNDECLARED` is reported whenever an entry's key is undeclared (the registry row states a fact about the entry; the reference verifier agrees) |
| Q1 (F47) | erasure kind page | erasure check: actor member, signer rule, `World::reference_target_invalid` (present but invalid → `E_ERASE_ACTOR`), `grant_resolve`, coverage, then `grant_usable_at` |
| Q3 (F55-1, F69-1/2) | §4.4 step 5, §14.5 | step 5 deferred for grant (delegated chain first), declaration (`decl_issue_without_signatures`: owner, class), consent revocation (target) and erasure |
| F69-3 | §5.4 | `check_actor`: `grant_resolve`, grantee, kind/action, then `grant_usable_at` |
| Q4 (F64) | §12.2 check 10 | `rsa_key_within_bounds`, `ecdsa_signature_within_bounds`: explicit checks on the decoded `RSAPublicKey` and `Ecdsa-Sig-Value`, before the `rsa`/`p256`/`p384` crates are called; unit tests at each bound |
| T3 (F57, F66) | §12.2 1a | `der::check_primitive_content` by tag number: REAL (`check_real`), RELATIVE-OID, TIME/DURATION, ESC in 7/20/21/25/27, UniversalString/BMPString units, UTF-8 for 31–33/35/36 |
| T8 (`readable`) | §11.8 | zip enumeration: no `N_READABLE_PRESENT` when the step-(1) codes include `E_CONTAINER_ZIP` |
| anchor bundle (review A medium-1 ②) | §14.1, §12.2 1e | `load_trust_anchors`: framing (`der::check_framing`) instead of 1a over the whole certificate; the walk applies the 1c canonical-content rules to its typed primitives (`der::check_typed_content`) and 1a to every `extnValue` |
| review A low-1, 33-level array | §1.9, §13 | `json::parse_object` judges "top-level value not an object" after the value, so the depth violation is reported (`tests/s2_followup.rs`) |
| review A low-1, top-level 2^64 | §1.6, §1.9 | the same change: `E_JSON_NUMBER_RANGE` at the token (`tests/s2_followup.rs`) |
| review A low-1, keyset | §14.1 | `declared_material`: a keyset declaration whose trust outcome is not `None` is ignored; keyset declarations are preferred as the material source, so a context declaration used instead is TOFU material (`tests/s2_followup.rs`) |
| gate 3 | — | allow list emptied |

### F70 — Where "top-level value not an object" sits in the byte order (§1.9)

§1.9 lists "top-level value not an object where an object is required" among the
`E_JSON_INVALID` classes of the stage-one pass, which reports the first violation in
byte order, but does not say at which position that violation is. Read at the first
byte, `[[…]]` (33 levels) would be `E_JSON_INVALID`; read as a property of the whole
value, it is `E_JSON_SIZE`, and `18446744073709551616` is `E_JSON_NUMBER_RANGE`. The
reference verifier takes the second reading, the brief of H1-S2 adopts it, and the Rust
verifier now follows. A sentence in §1.9 would settle it; no vector pins it.

### F71 — An anchor's typed primitives (§14.1, §12.2 1e)

§14.1 judges a `--tsa-trust` certificate by "the module walk with the 1b/1c rules, the
version constraints, and the 1a rules for every `extnValue`". The Rust verifier reads
"1c rules" as including 1c's canonical content of every typed primitive (a non-minimal
`serialNumber`, a BIT STRING with non-zero unused bits, a `critical` BOOLEAN `0x01`
fail), while open types (`AttributeTypeAndValue.value`, `parameters`) get framing only.
No vector has a non-canonical typed primitive in an anchor, and the reference verifier
was not probed on one; a vector would pin the reading.

### F72 — Trust handed on by a declaration that supplies no material (§5.3, Q2) — reference verifier deviates

Q2 says a declaration in which a signature other than its subject key's fails §9.4
"supplies no key material (neither the subject key's nor any other key's), governs no
window and establishes no trust" (§5.3). The trust closure itself runs before any record is
evaluated (its §9.4 inputs — valid revocations and timestamp evidence — need evaluation),
so the Rust verifier applies Q2 where material is used: a key trusted only through such a
declaration has no material, and a declaration whose cosignature is made by such a key is
not admitted either.

Reproduction (`tests/s2_followup.rs`,
`trust_is_not_handed_on_through_a_declaration_that_supplies_no_material`; set
`H1_S2_DUMP_DIR` to write the container out): keyset = human-1's declaration only; an L0
container with a `retired` revocation of human-1 effective T1 (signed by human-1), a
`human` declaration of human-2 at T2 cosigned by human-1, a `human` declaration of key-old
at T3 cosigned by human-2, and a note signed by key-old at T4.

| record | Rust | reference verifier |
|---|---|---|
| retirement of human-1 | valid | valid |
| human-2 declaration | invalid `E_KEY_REVOKED` (human-1 cosignature `unverified`) | the same |
| key-old declaration | unverifiable `E_KEY_UNKNOWN` (human-2's signature has no material) | **valid** (human-2's signature `valid`) |
| note by key-old | unverifiable `E_KEY_UNKNOWN` | **valid**, `N_KEY_TOFU` |

The reference verifier still uses human-2's material from a declaration that §5.3 says
supplies none; its Q2 vectors only cover owner cosignatures of automated keys. Spec
reading: unique (the §5.3 sentence names "a declaration's owner cosignature or other
cosignatures"); the Rust verifier follows it. No vector pins it; it belongs on the S2
list.

### F73–F78 — Differences found by the H1-S2 differential fuzzing

`scripts/diff_fuzz.py`, seeds 151115 and 777001, on the H1-S2 code before the two
fixes below. Every row is reproducible with the script from (case, class, mutant seed),
the seed being the `seed` of the JSONL line.

| # | shape (example: case, class, seed) | reference | Rust | reading |
|---|---|---|---|---|
| fixed | erasure record with no placeholder of its erased identity, or only a malformed one (`erasure/actor-agent-grant-absent`, `member_delete`, 326222880947857115) | no §10.3 code | was `E_ERASE_DIGEST_MISMATCH` | **Rust was wrong**: §10.3 applies "when both … are present" and a malformed placeholder is not one (S2/F48); now rule 1 without a placeholder fires only when a placeholder attests the erasure (`erasure/placeholder-of-another-instance` keeps its code) |
| fixed | placeholder whose `format` is a number (`erasure/placeholder-of-another-instance`, `number`, 4247991127229048556) | `E_KIND_BODY_SCHEMA` | was `E_ENV_FORMAT` | **Rust was wrong**: §4.5 "wrong member type" of the placeholder is `E_KIND_BODY_SCHEMA`; a wrong `format` string keeps `E_ENV_FORMAT` |
| F73 | an automated declaration whose owner's declaration has no `sigs` (`container/previous-key-not-trusted-in-target`, `member_delete`, 2466068138702282238) | `E_KEY_UNTRUSTED` | `E_KEY_UNKNOWN` | spec-ambiguous: §9.1 rule 3 lets the owner declaration be "not otherwise valid", while §5.3 takes the class only from structurally valid declarations (the structural group includes `sigs` presence) |
| F74 | a rotation without `new_public_key`, or with it renamed (`key-lifecycle/rotation-pubkey-contradicts-id`, `bitflip`, 1206337844626379176; `grant/revocation-rotation-successor-valid`, `member_delete`, 232162857186555824) | `E_KEY_ROTATION_KEYS`, `sigs` `[]` | the signature-layer code, or `E_KIND_BODY_SCHEMA` at check (6) | reference suspected wrong: rule 2 judges a public key "when present", §14.1 makes the *encoding and length* (not the presence) of the rotation keys structural, and a missing required member is the body-schema code |
| F75 | zip whose root `readable` file and members fail (`container/readable-root-regular-file-zip`, `bitflip`, 4433355601911133336) | `E_CONTAINER_ZIP` | `E_CONTAINER_ENTRY` + `E_CONTAINER_ZIP` | spec-ambiguous: §11.9 orders entry judgement before decompression but does not say whether a layout failure and a member CRC failure of the same step are reported together; to be re-run after S2-FIX2 U7 |
| F76 | `refs` with two entries equal but for the reference `kind` (`ref/duplicate-refs`, `refs`, 3196356845985137547) | `E_ENV_REFS` | valid | reference suspected wrong: §6.1 duplicates "repeat an identical `(rel, ref)` pair" |
| F77 | a proposed agent record whose `actor.key` is declared `human`, signed only with an unknown algorithm (`actor/agent-with-human-key`, `sigs`, 4478745140622538270) | `E_GRANT_UNRESOLVED` | `E_ACTOR_KEY_TYPE_MISMATCH` | reference suspected wrong: §5.1 compares `actor.type` with the class of `actor.key`, which needs no verified signature, and invalid beats unverifiable |
| F78 | report detail: the input identity of a directory container whose `manifest.json` was renamed (`input` `null` by S14 in Rust, a digest in the reference); `L_LABELS_ARE_CLAIMS` for records failing check (2) or (3), and `L_ERASED_*` for a malformed placeholder (F37) | — | — | S14 is unique (Rust); for the limitations the reference changed its F37 reading after S2 (it now counts a container record that fails check (2) with a `labels` member, not a record target that fails check (3), and no malformed placeholder); spec-ambiguous, a sentence in §14.9 would settle it |
| also | an erasure whose attesting placeholder is fine but the erasure record fails its `sigs` format (`erasure/actor-agent-grant-present-invalid`, `number`, 2971139823131269709) | adds `E_ERASE_ATTESTATION` | identity+digest match, no code | spec-ambiguous (whether a structurally failed record is "the `weave.erasure` record" of §10.3 rule 2) |

The S2-FIX2 rows (the DATE / OID-IRI types, `N_READABLE_PRESENT` after a member CRC
failure) differed only because the Rust verifier already followed S2-FIX2.

## H1-FIX2B gate results

Recorded 2026-11-15 on branch `h1/rust-verifier`, code at `97f56df`
(rulings Z1–Z3; the documentation commit that adds this section changes no
code). The reference verifier ran only as a black box (installed
non-editable from `git archive origin/main`, `5474cf7`).

| gate | result |
|---|---|
| 1. CI rust job, verbatim from the repository root | every step exit 0 (`CARGO_TARGET_DIR` outside the repository, so the crash-fuzz `--binary` follows it and gate 3 gets `--rust-binary`/`--python-cli`): fmt; clippy all-targets; clippy library without test hooks; `cargo test … --workspace` 99 passed, 0 failed, 3 ignored; the two `vectors` runs; `cargo deny check`; `cargo audit` (67 dependencies); crash fuzz 2,000 mutants, 0 failures; gate 3 PASS. The first gate-3 run, before the allow list was rewritten to indexed paths, failed on exactly the 35 rewritten entries (each new path collapses to its old `[*]` path); fmt and clippy were not rerun under rustup stable this time |
| 2. vectors | 498/498 main and 202/202 frozen cases match `expected.json` |
| 3. two-implementation comparison | 700 cases, 663 byte-identical, 37 allow-listed with exactly their (now indexed) fields and vector basis. Red checks: the narrow re-check's probe (the first signature of `key-declared-valid-from` in `key-lifecycle/sign-before-valid-from` turned `invalid` in the Rust report) fails the gate with `not allow-listed: ['records[0].sigs[0].state']`, exit 1, where the H1-FIX2 script passed it; an extra top-level member fails it too |
| 4. Z1 and Z2 red checks | reverting the cited-grant call site to "depth before validity", the grant-record call site likewise, or restoring the depth bound in the step-6 walk each turns `tests/precedence.rs` red; disabling the zip-form or the directory-form size check turns its probe red |
| 5. differential fuzzing | `scripts/diff_fuzz.py`, 10 classes × 400, with the d0af4f4 Rust binary run beside the new one on every mutant: seed **151115** 3,695 mutants, 3,296 byte-identical, 89 conclusion differences; seed **20261114** 3,696 mutants, 3,299 byte-identical, 114 conclusion differences. The new Rust report equals the d0af4f4 report, byte for byte and in exit code, on all 7,391 mutants, so the H1-FIX2 classification of every difference carries over: **Rust wrong 0**. Rust: 0 panics, 0 timeouts, exit codes 0 and 1 only. Neither seed builds the Z1 shape (it needs an added record) |
| 6. other workstreams untouched | `git diff --stat origin/main..h1/rust-verifier -- spec schemas vectors verifiers/python tools` is empty |

## H1-FIX2 gate results

Recorded 2026-11-15 on branch `h1/rust-verifier`, head `f7e3df9` for the code
(the documentation commit that adds this section changes no code). The
reference verifier ran only as a black box (installed non-editable from
`git archive origin/main`, `5474cf7`).

| gate | result |
|---|---|
| 1. CI rust job, verbatim from the repository root | every step exit 0 (`CARGO_TARGET_DIR` outside the repository, so the crash-fuzz `--binary` follows it and gate 3 gets `--rust-binary`/`--python-cli`): `cargo fmt … --all --check`; `cargo clippy … --all-targets -- -D warnings`; `cargo clippy … -p hyphaweave-verify --lib -- -D warnings`; `cargo test … --workspace` 96 passed, 0 failed, 3 ignored (the gate runs); the two `vectors` runs; `cargo deny check`; `cargo audit` (67 dependencies); the crash-fuzz step (2,000 mutants, 0 failures, exit codes 0–2 only); gate 3 PASS. fmt and both clippy steps also exit 0 under rustup stable 1.99.1 |
| 2. vectors | 498/498 main and 202/202 frozen cases match `expected.json` |
| 3. two-implementation comparison | 700 cases, 663 byte-identical, 37 allow-listed with exactly their listed fields and vector basis (29 `records[*].sigs[*].state`, 5 `records[*].sigs`, 2 `input.sha256`+`input.size`, 1 F38 set); vector basis `both-match-expected` for all 37; classifications 31 `spec-unique-answer-Python-bug`, 6 `spec-ambiguous`. Red checks: one more field difference injected into an allow-listed case, a wrong basis, and a listed field that no longer differs each fail the gate (exit 1); a `spec-unique-answer-Rust-bug` entry is a gate error (exit 2) |
| 4. red checks for Y1, Y2, Y4 | each change reverted on the final head turns its tests red: Y1 (identity key without the instance) 3 of 3; Y2 `critical` DEFAULT row and chain-head `renews` 1 each; Y4 three variants |
| 5. differential fuzzing | `scripts/diff_fuzz.py`, 10 classes × 400. A first pass on the Y1–Y10 head found two Rust defects (F55 misnamed oversize file, F68 grant-chain order), fixed in `17e78a1` and `f7e3df9`. Final pass on `f7e3df9`: seed **151115** (review A's): 3,695 mutants, 3,296 byte-identical, 89 conclusion differences — **Rust wrong 0**, reference suspected wrong 68, F44 8, spec-ambiguous 13; seed **20261114** (H1-FIX1's): 3,696 mutants, 3,299 byte-identical, 114 conclusion differences — **Rust wrong 0**, reference suspected wrong 86, F44 6, spec-ambiguous 22. Rust: 0 panics, 0 timeouts, exit codes 0 and 1 only. Of the 14 F44 rows, 10 keep the target's `origin` and `id` (tier a, reference suspected wrong), 1 deletes the target's `id` (tier b, ambiguous), 3 were not attributed |
| 6. other workstreams untouched | `git diff --stat origin/main..h1/rust-verifier -- spec schemas vectors verifiers/python tools` is empty |

The reference-verifier classes in gate 5: F46 54, Python crashes 47 (F51
`KeyError: 'key'` 23, and the F67 crash sites: `key_type` 15, `second must
be in 0..59` 3, `day is out of range` 4, `effective_at` 1, time without
fraction 1), F54 16, F56 11, F42 (record part) 9, F61-1 6, F49 3, F45 3, F50
2, F55 (oversize) 2, F67 (`sigs` member type) 1. Spec-ambiguous: F47 8, F38 6,
F48 7, F69 9, F55 (orders) 5.

## H1-FIX1 gate results

Recorded 2026-11-14 on branch `h1/rust-verifier` (after merging `origin/main`
`5474cf7`: specification revision 3 with S1-FIX1 to S1-FIX5, X6 and X7; 498 main
cases and 202 frozen cases). The Python reference verifier was run only as a
black box, installed non-editable from `git archive origin/main`.

| gate | result |
|---|---|
| 1. CI rust job, verbatim from the repository root | every step exit 0: `cargo fmt … --all --check`; `cargo clippy … --all-targets -- -D warnings`; `cargo clippy … -p hyphaweave-verify --lib -- -D warnings` (default features, no `test-hooks`); `cargo test … --workspace` 85 passed, 0 failed, 3 ignored (the gate runs); the two `vectors` runs; `cargo deny check`; `cargo audit` (67 dependencies, no vulnerability); the crash-fuzz step (2,000 mutants, 0 failures, seed 20261114); the gate-3 comparison (PASS) |
| 2. vectors | 498/498 main and 202/202 frozen cases match `expected.json` (0 mismatches) |
| 3. two-implementation comparison | 700 cases; 663 byte-identical reports after removing only the `verifier` object; the 37 others have identical conclusions (verdict, errors, notices, limitations) and differ in report detail. Classified in `verifiers/rust/scripts/gate3_known_differences.json`: 29 `sigs[].state` (F52) and 2 zip-prefix input identities (F40) as reference-verifier deviations from a unique answer in §14.6; 5 `sigs[]` lists after `E_KEY_PUBLIC_KEY` (F39) and 1 self-signature window (F38) as spec-ambiguous. The four manifest-less cases of F11 are now identical. |
| 4. differential fuzzing | 4,063 mutants (bit flips 439, member deletion 398, member duplication 396, numbers 394, base64 403, times 402, `refs` 408, `sigs` order 397, container edits 386, zip variants 440); 3,647 byte-identical reports; 98 conclusion differences: **Rust wrong 0**, reference suspected wrong 73 (F46 28, F51 crash 24, F47 8, F54 6, F56 3, F49 2, F45 1, F50 1), spec-ambiguous 25 (F44 8, F38 6, F42 3, F48 3, F55 5). Each class has a minimal reproduction above (`scripts/diff_fuzz.py`, rebuilt from case, class and seed). Rust exit codes only 0 and 1, no panic, no timeout. One Rust defect found by an earlier exploratory run (an empty `blobs/` directory accepted, §11.7) was fixed before this run and has a regression test; the F55 oversize-unlisted reading was changed after it (see F55). |
| 5. review reproduction inputs | every input of reviews A and B was re-run on both CLIs; the conclusions are listed in F18–F25 above. Both agree on all of them except the 300 MiB unlisted `records/` file (F55: H1 `E_JSON_SIZE` + `E_MANIFEST_RECORD_EXTRA`, the reference `E_JSON_SIZE`). No crash. |
| 6. 64 KiB stack (R6) | `tests/small_stack.rs` passes (depth 32/33, 1,023 and 400,000 JSON levels; licence nesting 16/17 and 400,000 pairs) |
| 7. resources (`/usr/bin/time -l`, peak RSS of the Rust CLI) | see F24: 2.3–9.3 MB for the 300 MiB, 2 GiB-declared and deep inputs, 29 MB for 70,000 ZIP64 entries |
| 8. ablation (`cargo test --release -p hyphaweave-verify --test gates ablation_every_code_turns_corpus_red -- --include-ignored`) | 114 registered error codes; 112 killed by the committed corpus; 2 survivors: `E_GRANT_SCHEMA`, pinned by `tests/probes.rs` (default `cargo test`, R4), and `E_ENV_SIG_ALG`, never emitted (§3.6, Q13). The probes for `E_JSON_SIZE`, `E_MANIFEST_SCHEMA`, `E_CONTAINER_ZIP` and `E_CONTAINER_SIZE` stay in the default run although the larger corpus now kills those codes too. Run on commit `217d641` (849 s); the later F55 change adds no code. |
| 9. supply chain | `cargo deny check`: advisories ok, bans ok, licenses ok, sources ok; `cargo audit`: no vulnerabilities, no `--ignore`; `cargo check -p hyphaweave-verify --target aarch64-linux-android`: exit 0, no warnings; `reuse lint`: compliant |
| 10. other workstreams untouched | `git diff --stat origin/main..h1/rust-verifier -- spec schemas vectors verifiers/python tools` is empty |

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
- **2026-11-14 (H1-FIX1)** — recorded the status of F1–F17 after specification
  revision 3 with the Python black-box agreement of each (F2 and F3 corrected);
  added F18–F27, the review items missing from the H1 hand-off (R7), and
  F28–F56, the ambiguities and reference-verifier deviations found while
  implementing revision 3 and by the H1-FIX1 differential fuzzing, each with a
  minimal reproduction; added the H1-FIX1 gate results.
- **2026-11-15 (H1-FIX2)** — added F57–F69 (the two re-reviews of H1-FIX1
  and the H1-FIX2 differential fuzzing), reclassified F42, F44, F47 and F55,
  made F50's reproduction explicit, corrected F55's H1-FIX1 reproduction
  claim, recorded the Y1 change in F27, and added the H1-FIX2 gate results.
- **2026-11-15 (H1-FIX2B)** — completed F68 (step 6 walks the whole chain,
  past the depth bound), recorded how F55's misnamed file is measured,
  added the three diverging certificate-version shapes to F62, corrected
  F50's reproduction (both signers re-sign), and added the H1-FIX2B gate
  results.
- **2026-11-15 (H1-S2)** — added the H1-S2 follow-up table, F70–F72, and
  the H1-S2 gate results.
