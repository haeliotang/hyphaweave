<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# H0 build-contract cross-reference (non-normative)

During H0 the specification, schemas, vectors and verifier were built in parallel against an
internal engineering contract (a temporary scaffold, not part of this repository). Some source
comments and docstrings still cite it as `CONTRACT §N`; this page maps those historical
coordinates to the normative documents that are actually delivered, so no reader has to
guess. **The normative source is `spec/weave-record-1.md` and its companion pages; where this
page and the specification differ, the specification wins.**

| historical reference | normative location |
| --- | --- |
| `CONTRACT §0` concepts and terms | `spec/weave-record-1.md` §0 |
| `CONTRACT §2`, `§2.8` — canonical JSON | `spec/weave-record-1.md` §1, §1.8 |
| `CONTRACT §3` — byte constructions | `spec/weave-record-1.md` §2 |
| `CONTRACT §3.1` — record digest | `spec/weave-record-1.md` §2.2 |
| `CONTRACT §3.2` — record signature | `spec/weave-record-1.md` §2.3 |
| `CONTRACT §3.3` — manifest digest and signature | `spec/weave-record-1.md` §2.4 |
| `CONTRACT §3.4` — key ids | `spec/weave-record-1.md` §2.5 |
| `CONTRACT §3.5` — base64url | `spec/weave-record-1.md` §2.6 |
| `CONTRACT §3.6` — digest strings | `spec/weave-record-1.md` §2.7 |
| `CONTRACT §4` — Ed25519 verification profile | `spec/weave-record-1.md` §3 |
| `CONTRACT §5` — record envelope | `spec/weave-record-1.md` §4 |
| `CONTRACT §5.1` — `actor` | `spec/weave-record-1.md` §4.2 |
| `CONTRACT §5.2` — `sigs` entries | `spec/weave-record-1.md` §4.3 |
| `CONTRACT §5.3` — records that must be per-record signed | `spec/weave-record-1.md` §4.4 |
| `CONTRACT §6`, `§6.3` — references, `rel`, resolution states | `spec/weave-record-1.md` §6 |
| `CONTRACT §7` — registered kinds | `spec/weave-record-1.md` §7 |
| `CONTRACT §7.1`–`§7.3` — key lifecycle kinds | `spec/weave-record-1.md` §9.1–§9.3, `spec/kinds/weave.key.*.md` |
| `CONTRACT §7.4` — `weave.grant` | `spec/weave-record-1.md` §5.5, `spec/kinds/weave.grant.md` |
| `CONTRACT §7.5`–`§7.6` — consent kinds | `spec/weave-record-1.md` §8.6, `spec/kinds/weave.consent.*.md` |
| `CONTRACT §7.7`–`§7.8` — erasure and the erased placeholder | `spec/weave-record-1.md` §10.2, §4.5, `spec/kinds/weave.erasure.md`, `spec/kinds/weave.erased.md` |
| `CONTRACT §8` — actors, agents, grants, authorisation | `spec/weave-record-1.md` §5 |
| `CONTRACT §9` — labels, consent, licence | `spec/weave-record-1.md` §8 |
| `CONTRACT §10` — key lifecycle effects | `spec/weave-record-1.md` §9 |
| `CONTRACT §11`, `§11.2`, `§11.3` — container, manifest, attestation file | `spec/weave-record-1.md` §11 |
| `CONTRACT §12` — integrity levels and RFC 3161 | `spec/weave-record-1.md` §11.4, §12 |
| `CONTRACT §13` — size and resource limits | `spec/weave-record-1.md` §13 |
| `CONTRACT §14` — verifier conformance | `spec/weave-record-1.md` §14 |
| `CONTRACT §14.2` — report shape | `spec/weave-record-1.md` §14.6 |
| `CONTRACT §14.5` — test-only check hook | `spec/weave-record-1.md` §14.7 |
| `CONTRACT §14.6` — deterministic check order | `spec/weave-record-1.md` §14.5 |
| `CONTRACT §15` — error codes | `spec/error-codes.md` |
| `CONTRACT §16`, `§16.2` — vector layout and case format | `vectors/README.md`, `spec/weave-record-1.md` §16 |
| `CONTRACT §16.3` — test keys | `vectors/keys/README.md` |
| `CONTRACT §17` — JSON Schemas | `schemas/README.md` |
| `CONTRACT §18` — verifier module layout | `verifiers/python/README.md` |
| `CONTRACT §19` — H0 gates | H0 task prompt §5 (external delivery input) |
| `CONTRACT §20`–`§21` — delivery report and commits | delivery report (delivered separately, not in this repository) |
| `CONTRACT §22` — PROVISIONAL items | `spec/weave-record-1.md` Appendix A, `docs/open-questions.md` |
