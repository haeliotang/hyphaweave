<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# `weave.erasure` — attest the erasure of a record

**Kind:** `weave.erasure` · **Stage:** `accepted` only · **Per-record signature:** REQUIRED
· **Decision tags:** [G3a] [G3b] [G3d] [G3e] [A1b] · **Normative parent:**
`spec/weave-record-1.md` §10. Every normative rule below is `decided (Inceptless decision
2026-11-10 #34)` where it implements ruling M-10.

## Purpose

The erasure attestation is the evidence that a record was deliberately erased, when, why,
by whom, and on what basis. It is referenced from the `weave.erased` placeholder that
replaces the erased record in an export, and it keeps the erased entry auditable after its
content is gone. Erasure exists for data-subject requests, legal obligations, safety,
mistaken inclusion, retention expiry and similar reasons; it is not a way to change a
judgement (withdrawal appends a new record and never triggers erasure) [G3a][G3e].

## Envelope requirements

- `kind` is exactly `weave.erasure`; `stage` **MUST** be `accepted`.
- `actor.type` and the signing keys are constrained by the signer rules below
  (`E_ERASE_ACTOR` on violation).
- `sigs` **MUST** be present (per-record signing mandatory). If `sigs` is non-empty but no
  required signer pattern is satisfied, `E_ERASE_ACTOR` is reported instead of
  `E_SIG_REQUIRED`; `E_SIG_REQUIRED` is used only when `sigs` is absent or empty.
- `salt` is optional; `refs` and `labels` follow the parent specification.

## Signer rules (widened by M-10)

The erasure attestation may be executed by:

| actor type | requirement |
|---|---|
| `human`, `organization` | allowed directly; the signature is by the actor's key |
| `agent` | `actor.grant` MUST resolve to a valid `weave.grant` covering kind `weave.erasure` and **both** actions `accept` (generic stage coverage for an accepted record) and `erase` (kind-specific); the chain is checked at the record's `recorded_at` (parent specification §5.4) |
| `program`, `device` | `body.basis` MUST resolve to a valid `weave.grant` covering the actor's key with action `erase`; this is the intended route for automatic `retention-expired` erasure |

Any other combination is `E_ERASE_ACTOR` (invalid). Human keys remain bound by the rule
that human keys sign human acts: an automated erasure is signed by the automated actor and
authorised by a grant, never by a human key acting as the automation [G3a][G3d][M-10]
decided (Inceptless decision 2026-11-10 #34; M-10).

## Body

| member | required | type | rule |
|---|---|---|---|
| `erased` | yes | reference object | the erased record: origin, id and the **original record digest** |
| `reason` | yes | string | one of `data-subject-request`, `legal`, `safety`, `mistaken-inclusion`, `retention-expired`, `other` |
| `reason_note` | yes | string or `null` | free-form note about the reason |
| `basis` | yes | reference object or `null` | authorisation basis for the erasure (for `program`/`device` it is required and must resolve to an `erase` grant) |
| `executed_at` | no | TS | claimed time when the erasure was executed |

`erased.kind`, when present, SHOULD name the original erased record's kind (it describes the
record that was erased, not the placeholder); a reference that resolves to `erased` is not
kind-checked (parent specification §6.3).

## Semantic rules

1. **The reference carries the original digest.** `erased.digest` MUST be the original
   record digest computed before erasure (sigs removed, salt included). It is the digest
   that existing references carry and the `digest` member of the placeholder [G3][G3b].
2. **Container cross-checks.** When this record and the placeholder are both in a container:
   the placeholder exists with `placeholder.digest == erased.digest`
   (`E_ERASE_DIGEST_MISMATCH`); its `attestation` reference resolves back to this record
   (`E_ERASE_ATTESTATION`); and the original live record is not also present
   (`E_ERASE_CONTRADICTION`). These rules make the erase assertion self-consistent and
   prevent a container from carrying both the data and a claim that it was erased (parent
   specification §10.3).
3. **Attestation is a claim, not proof of deletion.** A signed attestation is the format's
   best available evidence that an erasure happened; there is no cryptographic proof of
   absence. The verifier reports the erased entry with its attestation integrity
   established; it does not claim the content never existed elsewhere [G3b].
4. **Withdrawal is not erasure.** Changing a judgement appends a record and never creates an
   erasure attestation [G3e].
5. **Scope.** Erasure constrains exports and references. Projects may really delete content
   internally, but the minimum they keep is the digest plus the attestation record [A1b].
6. **`executed_at` is a claim** and has no ordering rule relative to `recorded_at`.

## Error codes

| code | verdict | condition |
|---|---|---|
| `E_ENV_STAGE` | invalid | stage is not `accepted` |
| `E_ERASE_ACTOR` | invalid | the actor/signer is not permitted by the signer table above |
| `E_ERASE_DIGEST_MISMATCH` | invalid | in a container: placeholder missing or `digest` disagreement |
| `E_ERASE_ATTESTATION` | invalid | the placeholder's `attestation` does not resolve back to this record |
| `E_ERASE_CONTRADICTION` | invalid | the original live record is also present |
| `E_REF_KIND_MISMATCH` | invalid | a reference kind claim contradicts a live target kind |
| `E_KIND_BODY_SCHEMA` | invalid | body shape, reason vocabulary or reference grammar violation |
| `E_GRANT_UNRESOLVED`, `E_GRANT_REVOKED`, `E_GRANT_EXPIRED` | unverifiable | the authorising grant cannot be established |
| `E_SIG_REQUIRED`, `E_SIG_UNVERIFIABLE`, `E_SIG_INVALID` | invalid / unverifiable | per parent specification §4.4 |
| `E_KEY_UNKNOWN` | unverifiable | a signer's key is not available in context |
| `N_REF_MISSING`, `N_REF_UNVERIFIABLE` | notice | `basis` or `erased` reference not resolvable in a record-only target |
| `N_KEY_TOFU`, `N_KEY_UNDECLARED` | notice | reporting |

## Canonical JSON example

A human-executed erasure attestation. As a standalone record target it is valid: the
container cross-checks of rule 2 are container-level and are not applied without a container
(parent specification §10.3).

<!-- spec-example: standalone-record -->
```json
{"actor":{"key":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","type":"human"},"body":{"basis":null,"erased":{"digest":"sha256:8566b341bb0be9de245d2dba29a3b80a4f023d481ecaa79c967c5e87051927b0","id":"example-note-7","kind":"example.note","origin":{"instance":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","project":"example"}},"executed_at":"2026-11-04T23:00:00.000Z","reason":"data-subject-request","reason_note":"example: data-subject request reference DS-2026-0042"},"format":"weave-record/1","id":"erasure-1","kind":"weave.erasure","origin":{"instance":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","project":"example"},"recorded_at":"2026-11-05T00:00:00.000Z","sigs":[{"alg":"ed25519","key":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","value":"1zt0nCGg6CW0khWjNfANlDilwqOYXrm-gkQssLoZw7F4SJT7MnEyc7E9whqTmXb2_ZYO3ZVLwAm9w4s4-wmrBg"}],"stage":"accepted"}
```

An agent- or program-executed erasure needs its authorising grant in the context and is
therefore not a complete standalone example; the signer table above specifies the rule.

## Why this kind exists

Deleting data must be a recorded, signed, authorised act, not a silent disappearance. The
attestation record plus the retained original digest plus the manifest and chain position is
what makes an erased entry integrable into an otherwise verifiable container. Widening the
signer set to authorised automated actors is what makes retention-expiry erasure
expressible without pretending a human performed it [G3a][G3b][G3d][M-10] decided
(Inceptless decision 2026-11-10 #34; M-10).
