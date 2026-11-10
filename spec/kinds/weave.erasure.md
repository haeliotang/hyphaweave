<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# `weave.erasure` — attest the erasure of a record

**Kind:** `weave.erasure` · **Stage:** `accepted` only · **Per-record signature:** REQUIRED
· **Decision tags:** [G3a] [G3b] [G3e] [A1b] · **Normative parent:**
`spec/weave-record-1.md` §10, §4.4.

## Purpose

The erasure attestation is the evidence that a record was deliberately erased, when, why,
by whom, and on what basis. It is referenced from the `weave.erased` placeholder that
replaces the erased record in an export (§10 of the parent specification), and it is what
keeps the erased entry auditable after its content is gone. Erasure exists for
data-subject requests, legal obligations, safety, mistaken inclusion, retention expiry and
similar reasons; it is not a way to change a judgement. Withdrawing a claim only appends a
new record and never triggers erasure [G3a][G3e].

## Envelope requirements

- `kind` is exactly `weave.erasure`; `stage` **MUST** be `accepted` (any other stage is
  `E_ENV_STAGE`) [G3a][§7.7].
- `actor.type` **MUST** be `human` (`E_ERASE_ACTOR`). Erasure is a human decision; agent
  and program records cannot attest erasure [G3a][§7.7].
- `sigs` **MUST** be present and include a valid signature by `actor.key` (per-record
  signing is mandatory) [G3a][§4]. If `sigs` is non-empty but no required human signer is
  present, `E_ERASE_ACTOR` is reported (not `E_SIG_REQUIRED`, §4.4 precedence, Q31);
  `E_SIG_REQUIRED` is used only when `sigs` is absent or empty.
- `salt` is optional; `refs` and `labels` follow the parent specification.

## Body

| member | required | type | rule |
|---|---|---|---|
| `erased` | yes | reference object | the record being erased: origin, id and the **original record digest** (§2.2, before erasure) |
| `reason` | yes | string | one of `data-subject-request`, `legal`, `safety`, `mistaken-inclusion`, `retention-expired`, `other` |
| `reason_note` | yes | string or `null` | free-form note about the reason (not interpreted) |
| `basis` | yes | reference object or `null` | authorisation basis for the erasure (for example a consent revocation, a legal order record, or a data-subject request record) |
| `executed_at` | no | TS | claimed time when the erasure was executed |

The known members are fixed; additional unknown body members are permitted (K3 evolution).
`erased.kind`, when present, SHOULD name the **original erased record's kind** (it describes
the record that was erased, not the placeholder that replaces it), or be omitted. A
reference that resolves to `erased` cannot be kind-checked, because the placeholder carries
no original kind; therefore the original kind here is not a contradiction and is **not**
`E_REF_KIND_MISMATCH` (specification §6.3, erased exception). Only the placeholder's
`attestation` reference — which targets a live `weave.erasure` record — is kind-checked.

## Semantic rules

1. **The reference carries the original digest.** `erased.digest` **MUST** be the original
   record digest computed before erasure (sigs removed, salt included, §2.2). It is the
   digest that existing references to the erased record carry, and it is the `digest`
   member of the placeholder [G3][G3b].
2. **Container cross-checks [G3a][G3b].** When this record and the placeholder are both in
   a container: the referenced placeholder **MUST** exist with `placeholder.digest ==
   erased.digest` (`E_ERASE_DIGEST_MISMATCH`); its `attestation` reference **MUST** resolve
   back to this erasure record (`E_ERASE_ATTESTATION`); and the original live record
   **MUST NOT** also be present (`E_ERASE_CONTRADICTION`). These rules make the erase
   assertion self-consistent and prevent a container from carrying both the data and a
   claim that the data was erased [§10.3].
3. **Attestation is a claim, not proof of deletion.** A signed attestation by a human is the
   format's best available evidence that an erasure happened; there is no cryptographic
   proof of absence. A verifier reports the erasure as an erased entry with its attestation
   integrity established; it does not claim the content never existed elsewhere [G3b].
4. **Withdrawal is not erasure.** Changing a judgement (`stage: withdrawn`) appends a record
   and never creates an erasure attestation [G3e].
5. **Scope.** Erasure constrains exports and references. Projects may really delete content
   internally, but the minimum they keep is the digest plus the attestation record, so the
   audit trail of "what was erased and on what basis" remains [A1b].
6. **The `basis` reference is audit information in H0.** It is resolved as a reference for
   reporting (so a missing basis shows up in the refs list) but H0 does not require a
   particular basis kind. A future version may constrain it (for example to
   `weave.consent.revoked` for data-subject requests).
7. **`executed_at` is a claim** and has no ordering rule relative to `recorded_at`;
   `recorded_at` is the signing time.

## Error codes

| code | verdict | condition |
|---|---|---|
| `E_ENV_STAGE` | invalid | stage is not `accepted` |
| `E_ERASE_ACTOR` | invalid | `actor.type` is not `human` |
| `E_ERASE_DIGEST_MISMATCH` | invalid | referenced placeholder missing, or `placeholder.digest != erased.digest` |
| `E_ERASE_ATTESTATION` | invalid | placeholder's `attestation` does not resolve back to this record |
| `E_ERASE_CONTRADICTION` | invalid | the original live record is also present in the container |
| `E_KIND_BODY_SCHEMA` | invalid | body shape, reason vocabulary or reference grammar violation |
| `E_SIG_REQUIRED` | invalid | `sigs` is absent or an empty array (per-record signing required) |
| `E_ACTOR_KEY_TYPE_MISMATCH` | invalid | signing key class is not `human` |
| `E_KEY_UNKNOWN` | unverifiable | signer's key is not available in context |
| `N_REF_MISSING`, `N_REF_UNVERIFIABLE` | notice | `basis` reference not resolvable (record verdict unchanged by the notice alone) |
| `N_KEY_TOFU`, `N_KEY_UNDECLARED` | notice | trust-on-first-use reporting |

## Canonical JSON example

```json
{"actor":{"key":"ed25519:8888888888888888888888888888888888888888888888888888888888888888","type":"human"},"body":{"basis":null,"erased":{"digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","id":"receipt-7","kind":"weave.erased","origin":{"instance":"ed25519:9999999999999999999999999999999999999999999999999999999999999999","project":"example"}},"executed_at":"2026-11-07T16:00:00.000Z","reason":"data-subject-request","reason_note":"request reference DS-2026-0042"},"format":"weave-record/1","id":"erasure-1","kind":"weave.erasure","origin":{"instance":"ed25519:8888888888888888888888888888888888888888888888888888888888888888","project":"example"},"recorded_at":"2026-11-07T16:30:00.000Z","sigs":[{"alg":"ed25519","key":"ed25519:8888888888888888888888888888888888888888888888888888888888888888","value":"HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH"}],"stage":"accepted"}
```

## Why this kind exists

Deleting data must be a recorded, signed human act, not a silent disappearance. The
attestation record plus the retained original digest plus the manifest and chain position
is what makes an erased entry integrable into an otherwise verifiable container [G3a][G3b].
