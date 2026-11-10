<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Security policy

## Status of this repository

Hyphaweave is at milestone **H0 revision 2** (decisions 2026-11-10 #34 and
#42): a draft specification (`weave-record/1` v0.1), JSON Schemas, conformance
vectors and one Python reference verifier. The repository is **public**, but the
format is **not stable** and the project is not yet accepted (J1/J2), and nothing
here runs as a network service. There is no warranty (see `LICENSING.md`).

## Reporting a vulnerability

Send reports to **support@inceptless.com** — the only contact address for this
project. Do not open a public issue for a security report: the repository is
public now, and a public issue would disclose the problem before a fix exists.
Please report privately so we can coordinate disclosure.

Please include, when possible:

- what you observed and what you expected;
- the affected file(s) or component (specification text, schema, vector,
  verifier, or tooling);
- exact reproduction steps, and the commands and environment used;
- whether the issue is already public anywhere.

We will acknowledge the report, investigate it, and agree with you on a
disclosure date before any details are published. Please give us reasonable
time to fix the issue first. There is no bug bounty, and we cannot offer a
reward.

## In scope

- **Specification text** (`spec/`): a rule that is ambiguous, contradictory or
  wrong in a way that lets two honest independent implementations reach
  different conclusions, or that weakens the signature/digest construction.
- **Reference verifier** (`verifiers/python/`):
  - accepting a record, container or vector that the specification says must be
    rejected (false accept), or rejecting one the specification says is valid
    (false reject);
  - canonical JSON parsing, Ed25519 profile enforcement, digest and domain
    separator handling, base64url strictness, size/resource-limit bypass;
  - crashes, hangs or unbounded resource use caused by crafted inputs
    (for example zip bombs or deeply nested JSON);
  - non-deterministic or environment-dependent reports;
  - a report that marks data as verified when a check was skipped or not
    possible (for example claiming L1 chain verification or L2 timestamp trust
    without the required evidence).
- **Schemas** (`schemas/`): structural validation gaps that disagree with the
  specification.
- **Conformance vectors** (`vectors/`): a vector whose input and
  `expected.json` disagree with the specification, a positive case that is
  actually invalid, a negative case that does not fail for the stated reason,
  or external data redistributed with the wrong license or provenance.
- **Tooling and CI** (`tools/`, `.github/workflows/ci.yml`): a gate that can
  report success without actually checking anything.

## Out of scope (not vulnerabilities)

- The draft, not-stable status of `weave-record/1` v0.1 or any API shown as
  draft; the specification is expected to change before v1.0.
- The fact that there is currently only one implementation, so the format does
  not yet have independent implementations. This is documented, expected at
  H0, and tracked as the H1 milestone.
- Documentation typos, wording preferences and non-security bugs.
- The absence of a network service, account system, storage service or sync
  layer: the project deliberately has none.
- L2 timestamps reported as `present-unverified` when no `--tsa-trust` anchor is
  supplied, and L1 chain heads reported as `unverified`: this is the honest,
  specified behavior, not a bypass.
- **Unknown-algorithm signature entries being ignored.** Signatures whose `alg`
  is not understood are reported with state `ignored` and ignored for
  verification (Q13). A record that requires a signature is still rejected or
  reported unverifiable when no verifiable required signature remains; that is
  the decided forward-compatibility rule, not a verification bypass.
- **`level_verified` being always `"L0"` and `anchor_verified` being a separate
  field.** The internal L1/L2 hash chain cannot be re-verified offline, so the
  report never claims more than it can prove (decision 2026-11-10 #34).
- **The public test keys under `vectors/keys/`.** They are deliberately
  published synthetic test material, not secrets. A key that is public by
  design is not a leaked key. Never use them for real records, and never treat
  a signature made with them as evidence of anything.
- The trust model: TOFU without a central CA, no revocation distribution beyond
  records in the verification context, and the fact that a signature proves
  which key signed bytes, not that the signed claims are true.
- Reports against `vectors/external/` upstream data that should go to the
  upstream project instead.
- Anything requiring a live service or network interaction, because the
  verifier is offline by design.

## Handling of your report

We will keep the report confidential until the agreed disclosure date, credit
you in the fix if you want, and publish the fix (and a note on the impact) in
the repository's history and release notes once it is safe to do so.

## Contact

support@inceptless.com — only this address is used for security reports.
