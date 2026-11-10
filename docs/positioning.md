<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Hyphaweave: positioning (draft, non-normative)

| Field | Value |
| --- | --- |
| Document status | `DRAFT` — candidate; not reviewed, not adopted |
| Version | 0.1 (English adaptation of the 2026-11-09 positioning draft) |
| Date | 2026-11-10 |
| Basis | `weave-record/1` decision draft v0.1 (2026-11-07) and correction v0.1.1 |
| Normativity | **Non-normative.** This document does not modify any project's protocol, gates or storage, and it is not an authorization to build, publish or implement anything. |
| Decision owner | The founder. The project name is decided; the recommendations below are not. |

> This is a positioning draft, not an architecture decision record and not a
> specification. The record format itself is defined by the `weave-record/1`
> decision draft and, in this repository, by [`../spec/weave-record-1.md`](../spec/weave-record-1.md).
> If the two disagree, the decision draft wins.

## 1. One line

**Hyphaweave — the common thread between independent systems.**

The name joins two images: *hyphae*, the filaments that connect a forest
underground without owning a single tree, and *weave*, the making of cloth.
Hyphaweave does the same for records: it lets independent projects reference
and verify each other's records, while each project keeps its own interior.

## 2. Core proposition

Several independent projects have each built an append-only, auditable ledger.
They all separate "claims" from "evidence", but that promise has no carrier
across project boundaries: evidence inside one project can be neither
referenced nor verified by another.

Hyphaweave does not unify them. It defines only the **exchange and reference**
layer: records are exported into one common format, accepted verbatim, and every
cross-project reference is "origin + id + digest".

Two principles run through everything:

1. **Built for decades.** Files must stay readable and verifiable without any
   particular software; algorithms and keys must be replaceable, revocable and
   re-timestampable; identity and references are based on digests, and URLs are
   only hints.
2. **Agent-heavy operations.** Every record states *who acted, on whose behalf,
   and under what authorization*; agent output is a proposal by default.

## 3. Scope: three parts

| Part | Content | Status at H0 |
| --- | --- | --- |
| **Records** — `weave-record/1` | Specification and schemas for the envelope, references, containers, erasure and authorization; conformance vectors; offline manual verification steps; two independent reference verifiers (Python and Rust) | Draft v0.1 decided 2026-11-07; **Python reference verifier implemented in this repository; Rust is a later milestone; J1/J2 acceptance has not happened** |
| **Keys and consent** | Record kinds `weave.key.declared / rotated / revoked`, `weave.consent.granted / revoked`, `weave.grant`; local trust rules (trust on first use, no central CA) | Kinds decided; the human-key foundation is still a dependency and is not provided by this repository |
| **Offline transport** | A shared component (framing, fragment reassembly, deduplication, TTL relay queue, QR text packages) that carries arbitrary `weave-record/1` containers | **Not part of H0.** It is not extracted or shipped here yet |

Records are the core; the other two depend on them. Keys and consent are
themselves records, and transport only moves record containers.

## 4. Responsibility boundaries

| Actor | Responsible for | Not responsible for |
| --- | --- | --- |
| **Hyphaweave** | Specification, schemas, conformance vectors, reference verifiers, the shared transport component | Writing any project's export/import adapters; touching any project's internal storage |
| **Each adopting project** | Its own export and import adapters; its internal format; its own gates | Replacing a received original with a re-hash |
| **Inceptless** | Making human keys real, which is the prerequisite for the agent rules | Owning the format because it provides a reference implementation |
| **Future evidence projects** | Carrying external reproduction results in Hyphaweave attestation records | Defining the record format |

## 5. Non-goals

- **Not an identity provider.** It does not decide who is a human, issue
  credentials or provide login. A key identifier is a public-key fingerprint;
  DIDs and URLs are only hints.
- **Not a blockchain, and not a transparency log.** Time anchoring uses RFC 3161
  timestamps, and a record may carry timestamps from several services.
- **Not a sync service or a network.** The transport component moves files; it
  provides no server, relay network or discovery mechanism.
- **Does not unify storage.** Each project keeps its own internal storage.
- **Does not prove facts are true.** Signatures prove which key signed and that
  the content has not changed.
- **Does not guarantee global deletion.** Erasure constrains exported artifacts
  and references; copies that have already spread elsewhere are not promised to
  be deleted.
- **No exception channel for agents.** Strictest-label propagation and the
  `local-only` export refusal apply to agents exactly as they do to humans.

## 6. First milestone

Following the decision draft's implementation order:

1. **Prerequisite.** Inceptless makes human keys real (outside this
   repository); the agent rules depend on it.
2. **H0 (this repository).** The five-part specification, schemas and
   conformance vectors, plus the Python reference verifier.
3. **J1.** A first project pair round-trips records through `weave-record/1`:
   one exports receipts and events, the other accepts them verbatim and
   verifies them.
4. **J2.** A second project pair round-trips authorizations through
   `weave.grant`, with the receiving project referencing back.
5. **H1.** The Rust verifier passes the same vectors. Only then is
   `weave-record/1` v1.0 announced.

J1 and J2 both passing is what makes v0.1 valid. The offline transport
component is not part of this milestone; it is extracted only after J1 works,
so that the format and the transport are not changed at the same time.

## 7. Evaluation metrics

- Two independent verifiers reach **the same conclusion, case by case**, on
  every conformance vector.
- An outsider can manually verify a container using only the specification and
  no implementation (target: yes; `spec/offline-verification.md` is the guide,
  and an independent reviewer executed it against the L0 example during H0
  review).
- How many lines of adapter code and how much internal change a project needs
  to adopt the format (the "smallest internal change" promise is tested here).
- A container written a decade ago still verifies with the current verifier
  (the "never abandon old versions" promise, tested with the v0.1 candidate
  regression vector set).
- The number of accepted records produced by agents without an authorization
  (target: 0, and the verifier rejects them).

## 8. Design principles

1. Use only mature public standards: RFC 8785 JCS, Ed25519, SHA-256, RFC 3161,
   SPDX.
2. Everything is a plain file; no database or runtime is required.
3. The algorithm name is the interface for replacing algorithms; timestamps and
   signatures are renewed before they expire.
4. The verifier never abandons old versions.
5. Agents may only propose by default; human keys sign only human acts.
6. Labels propagate along derivation, taking the strictest; `local-only` never
   leaves the machine.
7. Received originals are preserved verbatim.
8. The specification is independent of any implementation and can be read on
   its own.

## 9. Licensing

Following decision K2 and the 2026-11-10 licensing decision: specification and
documentation prose are CC-BY-4.0; code, schemas and conformance vectors are
Apache-2.0; brand assets, if any are ever added, are reserved under
`LicenseRef-Inceptless-Brand`. The Apache-2.0 patent grant matters for a format
that wants others to implement it independently and confidently. See
[`../LICENSING.md`](../LICENSING.md). Contributions require the Inceptless CLA
(see [`../CONTRIBUTING.md`](../CONTRIBUTING.md)).

## 10. Risks

| Risk | Mitigation |
| --- | --- |
| The specification exists but no project actually adopts it | J1 and J2 are acceptance conditions; without round trips, v0.1 is not valid |
| A single maintainer, so "independent implementation" would be a hollow claim | The second verifier is written by a different implementer, preferably an outsider, from the specification and vectors only; the README states honestly who implemented what |
| Human keys are delayed and the agent rules stay theoretical | The human-key foundation is a prerequisite; revision 1 reports `accepted` records that carry no signature from a declared human key with the `N_NO_HUMAN_SIGNATURE` notice (a notice, not a rejection) |
| Scope creep into an identity system or a sync network | The non-goals are fixed; new parts require a written proposal |
| Renaming the project changes the format name in already-written records | Project name and format identifier are separate: the project is Hyphaweave, the format identifier is always `weave-record/1` |

## 11. Open questions

The concrete open questions for this milestone — in particular the
implementation-shape choices that remain `PROVISIONAL` in the specification —
are tracked in [`open-questions.md`](open-questions.md). When the two documents
differ, that file and the decision log govern.

The repository is public now, so publication timing is no longer an open
question; this positioning draft did not decide it.

## 12. Adoption flow

1. The founder resolves the open questions that block adoption.
2. An independent reviewer checks this document and the decision draft against
   each other.
3. A separate adoption record is entered in the decision log.
4. Adoption is not the same as building the repository; building is a separate
   decision.
