<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Licensing

Hyphaweave is licensed in layers. The specification is meant to be read,
implemented and quoted by anyone; the code, schemas and conformance vectors are
meant to be embedded in any tool, including proprietary ones.

This follows decision **K2** of the `weave-record/1` decision draft (specification
text under CC BY 4.0, code and test vectors under Apache-2.0) and decision
**2026-11-10 #20**, which keeps Hyphaweave permissive and adds a reserved
license for brand assets. No file in this repository is offered under AGPL or
any other copyleft license.

| Material | License | Why |
| --- | --- | --- |
| Code (`verifiers/`, `tools/`, CI workflow) | `Apache-2.0` | Patent grant; safe to embed in any implementation, including closed-source ones. |
| JSON Schemas (`schemas/`) | `Apache-2.0` | Machine-readable part of the format; should be vendorable without friction. |
| Conformance vectors and test data (`vectors/`, including frozen vectors and public test keys) | `Apache-2.0` | Test data that must be copyable into every implementation's test suite. |
| Specification and prose documentation (`spec/`, `docs/`, root Markdown files) | `CC-BY-4.0` | Prose should be quotable and translatable with attribution; a software license is a poor fit for text. |
| Brand assets (wordmarks, logos) | `LicenseRef-Inceptless-Brand`, all rights reserved | **None are present in this repository.** If brand assets are ever added, they are explicitly outside the licenses above and are not licensed for reuse or modification. |
| External data under `vectors/external/` | The upstream license recorded for each source | This repository redistributes unmodified official test data; each directory carries `SOURCE.json` / `PROVENANCE.md` with the source URL, commit, SHA-256 and license. Those terms continue to apply to those bytes. |

Two of the three external sources are Apache-2.0. The RFC 8032 text is an IETF
document under the IETF Trust Legal Provisions (BCP 78), which have no SPDX
license identifier; it is annotated with the local reference
`LicenseRef-IETF-Trust`, whose file in `LICENSES/` points to the authoritative
terms and to the copyright notice carried inside the retained RFC text.

The split is applied at the file level. A Markdown page under `spec/`, `docs/`
or the repository root is prose (CC-BY-4.0). A JSON file is code-adjacent data
(Apache-2.0) even when its content is a test case. README pages that live inside
a code, schema or vector directory follow that directory's license
(Apache-2.0); their inline SPDX header is authoritative.

## File-by-file SPDX information

Every file in the repository carries SPDX information under the
[REUSE](https://reuse.software/) convention:

- Markdown files start with two HTML comment lines: one carrying the
  `SPDX-FileCopyrightText` tag (`2026 Inceptless <support@inceptless.com>`) and
  one carrying the `SPDX-License-Identifier` tag (`CC-BY-4.0`).
- Python files start with the same two tags as `#` comments.
- YAML files start with the same two tags as `#` comments.
- Files that cannot carry comments (JSON, binary test keys, PEM files) are
  covered by `REUSE.toml` annotations.
- `CLA.md` is copied byte-for-byte from the Inceptless CLA source, so it cannot
  carry an inline header; it is declared as CC-BY-4.0 prose in `REUSE.toml`.
- The root `LICENSE` and the files in `LICENSES/` are the license texts
  themselves. `REUSE.toml` records them for completeness, naming the license
  steward as the copyright holder; REUSE treats these files as licensing
  information rather than as content to be licensed, so those entries are a
  provenance note, not a relicensing of Creative Commons' or the Apache
  Software Foundation's words.

Check the result with:

```bash
reuse lint
```

(at the repository root, with `reuse` 5.0.2 installed — see `CONTRIBUTING.md`).

## License texts: official sources and integrity

The license texts were downloaded from the official sources below on
2026-11-10 and are stored unmodified. The root `LICENSE` is a byte-identical
copy of `LICENSES/Apache-2.0.txt`.

| File | Source URL | SHA-256 |
| --- | --- | --- |
| `LICENSES/Apache-2.0.txt`, `LICENSE` | https://www.apache.org/licenses/LICENSE-2.0.txt | `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30` |
| `LICENSES/CC-BY-4.0.txt` | https://creativecommons.org/licenses/by/4.0/legalcode.txt | `9ba9550ad48438d0836ddab3da480b3b69ffa0aac7b7878b5a0039e7ab429411` |

## Contributions and the CLA

Before any contribution can be merged, the contributor must accept the
Inceptless Contributor License Agreement (`CLA.md`), which allows Inceptless to
offer the projects under other terms while keeping every accepted contribution
available under its open-source license. The CLA is currently a **draft, version
1.0, not yet in force**, and no external contribution is merged until it is
finalized — see `CONTRIBUTING.md`. There is no DCO sign-off in this repository.

## What this license does not promise

The code is provided "as is", without warranties or conditions of any kind. A
valid signature proves which key signed a record and that the bytes have not
changed; it does not prove that the claims in a record are true. See
`SECURITY.md` for what is and is not a security issue, and `docs/positioning.md`
for what the project deliberately does not do.

## Contact

Licensing questions: support@inceptless.com (the only contact address used by
this repository).
