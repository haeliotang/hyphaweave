<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# `weave.erased` — placeholder for an erased record

**Kind:** `weave.erased` · **Stage:** none (special shape) · **Per-record signature:** none
(no `sigs` member) · **Decision tags:** [G3] [G3b] [G3c] · **Normative parent:**
`spec/weave-record-1.md` §4.5 and §10. Every normative rule below is `decided (Inceptless
decision 2026-11-10 #34)` where it implements rulings Q15/Q32.

## Purpose

When a record is erased, its place in the export is taken by this placeholder, and every
reference to the erased record resolves to the state `erased` instead of `missing` or
`found`. The placeholder preserves the erased record's `origin` and `id` and its **original
digest**, so references and the digest chain keep their meaning, while no content and no salt
remain that could be used to reconstruct the data [G3][G3b][G3c].

## Shape (not a normal envelope)

The placeholder is exactly this closed object. It has no `stage`, no `actor`, no `sigs`, no
`body`, no `refs`, no `labels` and no `salt`.

| member | required | type | rule |
|---|---|---|---|
| `format` | yes | string | exactly `"weave-record/1"` (`E_ENV_FORMAT`) |
| `kind` | yes | string | exactly `"weave.erased"` |
| `origin` | yes | origin object | same grammar as a normal envelope (`E_ENV_ORIGIN`) |
| `id` | yes | string | same grammar as a normal envelope (`E_ENV_ID`) |
| `digest` | yes | digest string | the **original record digest** of the erased record |
| `attestation` | yes | reference object | a reference to the `weave.erasure` record attesting this erasure |

Because this is a special shape rather than a normal envelope, **every structural violation
of the placeholder is `E_KIND_BODY_SCHEMA`**: a missing member, an unknown extra member, a
wrong member type, or a malformed `digest`/`attestation` format. `E_ENV_MISSING_FIELD` and
`E_ENV_UNKNOWN_FIELD` apply to the normal envelope only and are not used for
`weave.erased` [Q15] decided (Inceptless decision 2026-11-10 #34; Q15).

## Semantic rules

1. **The digest member is the original digest.** It equals the record digest that existing
   references to the erased record carry. It is **not** the placeholder's own record
   digest; the placeholder's own record digest (used for its file name and manifest entry)
   is computed over the placeholder object itself and is a different value [G3].
2. **Verdict.** A structurally sound placeholder has verdict `erased`, never `valid`. For a
   single-record target the top-level verdict is `erased` and the exit code is 0: the
   attestation of an erasure is a successful structural verification even though the content
   is gone.
3. **Attestation resolution.**
   - In a container context, the `attestation` reference MUST resolve to a
     `weave.erasure` record whose `erased` reference carries the same `digest`; otherwise
     `E_ERASE_ATTESTATION` (invalid). The erasure record's `erased` reference must resolve
     back to this placeholder with a matching `digest`, otherwise
     `E_ERASE_DIGEST_MISMATCH`.
   - For a standalone placeholder target there is no context, so these cross-checks cannot
     be applied; the verdict remains `erased`, the unresolved attestation is reported as a
     reference state with the normal notice, and the report states the limitation [Q15].
4. **No duplicate live record.** The original live record with the same `origin`, `id` and
   original digest MUST NOT also be present in the container (`E_ERASE_CONTRADICTION`). Two
   placeholders for the same target are also `E_ERASE_CONTRADICTION`.
5. **Integrity argument (G3b).** The erased entry's integrity no longer depends on its own
   content hash. It is proven by: (a) the signed erasure attestation; (b) the retained
   original digest; (c) the signed container manifest listing the placeholder's own digest
   (and, for L1/L2, its chain position claim). Each is checkable offline, so a later
   substitution or removal of the placeholder is detectable like any other tampering [G3b].
6. **Salt is gone.** The original record's `salt` was part of its digest but is not carried
   by the placeholder and must be deleted together with the content. Without the salt, the
   original digest does not permit brute-force reconstruction of the deleted content [G3c].
7. **Kind claims are not checkable.** A `kind` claim on a reference that resolves to
   `erased` is not a contradiction: the placeholder does not record the original kind
   (parent specification §6.3) [Q32] decided (Inceptless decision 2026-11-10 #34; Q32).
8. **The placeholder is a record.** It is listed in `manifest.records` with its own digest
   and file name; it is not exempt from the container's digest/signature/manifest checks.

## Error codes

| code | verdict | condition |
|---|---|---|
| `E_KIND_BODY_SCHEMA` | invalid | any structural violation of the placeholder: missing/unknown member, wrong member type, malformed `digest` or `attestation` |
| `E_ENV_FORMAT` | invalid | `format` is not `weave-record/1` |
| `E_ENV_ORIGIN`, `E_ENV_ID` | invalid | origin/id grammar violation (the shared members keep the envelope grammar) |
| `E_ERASE_ATTESTATION` | invalid | in a container: attestation does not resolve to the matching `weave.erasure` |
| `E_ERASE_DIGEST_MISMATCH` | invalid | in a container: the erasure record's `erased` digest does not match |
| `E_ERASE_CONTRADICTION` | invalid | in a container: the original live record is also present, or two placeholders |
| `N_REF_UNVERIFIABLE`, `N_REF_MISSING` | notice | standalone placeholder: attestation not resolvable (verdict stays `erased`) |

## Canonical JSON example

A standalone placeholder; the expected verdict is `erased` (exit code 0):

<!-- spec-example: standalone-record -->
```json
{"attestation":{"digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","id":"erasure-1","kind":"weave.erasure","origin":{"instance":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","project":"example"}},"digest":"sha256:8566b341bb0be9de245d2dba29a3b80a4f023d481ecaa79c967c5e87051927b0","format":"weave-record/1","id":"example-note-7","kind":"weave.erased","origin":{"instance":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","project":"example"}}
```

## Why this kind exists

Erasure must be visible without destroying the referential graph. Replacing the record with
a digest-bearing placeholder keeps every existing reference meaningful (state `erased`),
keeps the container self-consistent (signed manifest plus placeholder digest), and removes
the content and salt so privacy is preserved [G3][G3b][G3c][Q15] decided (Inceptless
decision 2026-11-10 #34; Q15).
