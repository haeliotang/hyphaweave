<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# H1 gate scripts

These scripts are repository gate tooling for the H1 Rust verifier, not part of
the verifier or its library API. They run the Python reference verifier only as
a black box through its documented command line, and they never read its source.

## Gate 3 — two-implementation report comparison

`compare_reports.py` runs both implementations over every committed conformance
case, reproduces the case's documented arguments, normalizes only the §14.6
`verifier` identity object (`name`/`version` become `"normalized"`), and compares
every remaining report byte. It also requires the Rust verifier to pass the
vector set before it runs the Python black box at all (the H1 ordering rule: gate
3 comes after the vector gates).

Preconditions:

```bash
# from the repository root
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_HOME="$PWD/.tmp-work/cargo-home"

# 1. the Rust verifier must build and pass every vector (this script checks it)
cargo build --manifest-path verifiers/rust/Cargo.toml

# 2. the Python reference verifier must be importable by the selected interpreter
./.venv/bin/python -m pip show hyphaweave_verify >/dev/null || \
    ./.venv/bin/python -m pip install -e "verifiers/python[dev]"
```

Run the gate:

```bash
# main vector set (default)
./.venv/bin/python verifiers/rust/scripts/compare_reports.py

# main set plus the v0.1 candidate regression set
./.venv/bin/python verifiers/rust/scripts/compare_reports.py --include-frozen

# one case while triaging a difference
./.venv/bin/python verifiers/rust/scripts/compare_reports.py \
    --case sig/unknown-alg --verbose
```

Useful options: `--vectors DIR` (repeatable; default `vectors/`), `--case ID`
(repeatable), `--rust-binary PATH` (default: auto-detected cargo target),
`--python-cli "CMD ..."` (complete command prefix, e.g.
`"./.venv/bin/hyphaweave-verify"`), `--allow-list PATH`, `--timeout SECONDS`,
`--max-diff-lines N`, `--verbose`. Cases are identified by their
`expected.json` `id`. The main corpus uses that id unchanged
(`sig/unknown-alg`); a different set whose ids repeat the main corpus (such as
`--include-frozen`, which compares a copy of the same cases) is prefixed with the
set name (`v0.1-candidate/sig/unknown-alg`) so allow-list entries and `--case`
selections are unambiguous. `--case` accepts either spelling.

Each difference is printed with the script's vector basis (which report
matches the case's `expected.json`), the allow-list classification (or
`not allow-listed`), the differing `fields`, and a short diff. The
classifications an allow-list entry may carry are:

- `spec-unique-answer-Rust-bug` — the spec/vector pins one answer, the Rust
  report does not match it and Python does (never allow-listed: fix Rust);
- `spec-unique-answer-Python-bug` — the reverse, or the specification text
  (cited in the entry's `reason`) pins an answer outside the vector
  conclusions that the Rust report follows;
- `spec-ambiguous` — the specification does not give one answer for the
  differing fields (for example a PROVISIONAL report field shape).

Exit code `0` means every report byte was identical after the identity
normalization, or every difference is listed in
`gate3_known_differences.json` and no listed entry is stale. Exit code `1`
means at least one unlisted (or stale) difference. Exit code `2` means the gate
could not run (missing binary, unusable Python command, Rust vector failure).

### Allow-list policy

`gate3_known_differences.json` starts empty. Add an entry only after the
difference has been traced to a documented specification ambiguity (a section in
`docs/h1-findings.md`) or to an agreed implementation-shape choice; each entry
needs the exact case id (with the set prefix for non-default sets), a `reason`,
and one of the three classifications above.
Never add an entry to paper over a difference where the specification and the
vectors give a unique answer — that is a defect in one of the implementations.
Removing or fixing the underlying issue must also remove the entry, because a
stale entry fails the gate.

Since H1-FIX2 (Y10) an entry accepts named fields, not a whole case:

- `fields` — the sorted report paths that differ, with `[*]` for array
  positions (`records[*].sigs[*].state`, `input.sha256`); `<exit-code>`,
  `<report>` (no parseable report on one side) and `<report-bytes>` (equal
  parsed values, different bytes) name differences outside the JSON tree. The
  script prints the computed `fields` of every differing case; they must equal
  the listed ones exactly, so a further field difference in an allow-listed
  case, or a listed field that no longer differs, fails the gate.
- `vector_basis` — the script's own reading of the case's `expected.json`:
  `rust-only-matches-expected`, `both-match-expected`,
  `python-only-matches-expected` or `neither-matches-expected`. It must equal
  what the script computes. The `classification` must be consistent with it:
  `rust-only-matches-expected` requires `spec-unique-answer-Python-bug`;
  `both-match-expected` (the difference is outside the vector conclusions)
  allows `spec-unique-answer-Python-bug`, with the specification text cited in
  `reason`, or `spec-ambiguous`; `neither-matches-expected` allows only
  `spec-ambiguous`; `python-only-matches-expected` is a Rust defect and can
  never be listed.
