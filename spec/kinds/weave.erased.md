<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# `weave.erased` — placeholder for an erased record

**Kind:** `weave.erased` · **Stage:** none (special shape) · **Per-record signature:** none
(no `sigs` member) · **Decision tags:** [G3] [G3b] [G3c] [Q15] · **Normative parent:**
`spec/weave-record-1.md` §4.5, §10.

## Purpose

When a record is erased, its place in the export is taken by this placeholder, and every
reference to the erased record resolves to the state `erased` instead of `missing` or
`found`. The placeholder preserves the erased record's `origin` and `id` and its **original
digest**, so that references and the digest chain keep their meaning, while no content and
no salt remain that could be used to reconstruct the data [G3][G3b][G3c].

## Shape (not a normal envelope)

The placeholder is exactly this closed object. It has no `stage`, no `actor`, no `sigs`, no
`body`, no `refs`, no `labels` and no `salt`.

| member | required | type | rule |
|---|---|---|---|
| `format` | yes | string | exactly `"weave-record/1"` (`E_ENV_FORMAT`) |
| `kind` | yes | string | exactly `"weave.erased"` (`E_ENV_KIND_SYNTAX`/`E_ENV_UNKNOWN_FIELD` shape rules) |
| `origin` | yes | origin object | same grammar as a normal envelope (`E_ENV_ORIGIN`) |
| `id` | yes | string | same grammar as a normal envelope (`E_ENV_ID`) |
| `digest` | yes | digest string | the **original record digest** of the erased record; must be a §2.7 digest string |
| `attestation` | yes | reference object | a reference to the `weave.erasure` record attesting this erasure |

A missing member is `E_ENV_MISSING_FIELD`; an extra member is `E_ENV_UNKNOWN_FIELD`.
A malformed `digest`/`attestation` member is `E_KIND_BODY_SCHEMA` (PROVISIONAL gap-filling
choice of code; the decision draft names no dedicated code — the special shape is settled by
Q15 but the error-code mapping is not).

## Semantic rules

1. **The digest member is the original digest.** It equals the record digest that existing
   references to the erased record carry. It is **not** the placeholder's own record
   digest; the placeholder's own record digest (used for its file name and manifest entry,
   §2.2) is computed over the placeholder object itself and is a different value [G3].
2. **Verdict.** A structurally sound placeholder has verdict `erased`, never `valid`. For a
   single-record target the top-level verdict is `erased` and the exit code is 0: the
   attestation of an erasure is a successful structural verification even though the
   content is gone [Q15].
3. **Attestation resolution.**
   - In a container context, the `attestation` reference **MUST** resolve to a
     `weave.erasure` record whose `erased` reference carries the same `digest`; otherwise
     `E_ERASE_ATTESTATION` (invalid). The erasure record's `erased` reference must resolve
     back to this placeholder with a matching `digest`, otherwise `E_ERASE_DIGEST_MISMATCH`.
   - For a standalone placeholder target there is no context, so these cross-checks cannot
     be applied; the verdict remains `erased` and the unresolved attestation is reported as
     a reference state with the normal notice and with the limitation stated in the report
     [Q15].
4. **No duplicate live record.** The original live record with the same `origin`, `id` and
   original digest **MUST NOT** also be present in the container
   (`E_ERASE_CONTRADICTION`). The container must not carry both the data and a claim that
   the data was erased [G3].
5. **Integrity argument (G3b).** The erased entry's integrity no longer depends on its own
   content hash. It is proven by: (a) the signed erasure attestation; (b) the retained
   original digest; (c) the signed container manifest listing the placeholder's own digest
   (and, for L1/L2, its chain position claim). Each of these is checkable offline, so a
   later substitution or removal of the placeholder is detectable like any other
   tampering [G3b].
6. **Salt is gone.** The original record's `salt` was part of its digest but is not carried
   by the placeholder and must be deleted together with the content in the erased export.
   Without the salt, the original digest does not permit brute-force reconstruction of the
   deleted content [G3c].
7. **The placeholder is a record.** It is listed in `manifest.records` with its own digest
   and file name; it is not exempt from the container's digest/signature/manifest checks.
   References resolve to `erased` when the placeholder's `digest` member equals the
   reference digest (§6.3 of the parent specification) [G3][G3b].
8. **Kind claims on references to this placeholder are not checkable.** The placeholder does
   not record the original kind, so a reference that resolves to `erased` and carries a
   `kind` claim (normally the original record's kind) is not a contradiction and is not
   `E_REF_KIND_MISMATCH`; see specification §6.3, erased exception.

## Error codes

| code | verdict | condition |
|---|---|---|
| `E_ENV_MISSING_FIELD` | invalid | one of the six members is absent |
| `E_ENV_UNKNOWN_FIELD` | invalid | an extra member is present |
| `E_ENV_FORMAT` | invalid | `format` is not `weave-record/1` |
| `E_ENV_ORIGIN`, `E_ENV_ID` | invalid | origin/id grammar violation |
| `E_KIND_BODY_SCHEMA` | invalid | malformed `digest` or `attestation` member (PROVISIONAL code choice) |
| `E_ERASE_ATTESTATION` | invalid | in a container: attestation does not resolve to a matching `weave.erasure` |
| `E_ERASE_DIGEST_MISMATCH` | invalid | in a container: erasure record's `erased` digest does not match |
| `E_ERASE_CONTRADICTION` | invalid | in a container: the original live record is also present |
| `N_REF_UNVERIFIABLE` / `N_REF_MISSING` | notice | standalone placeholder: attestation not resolvable (verdict stays `erased`) |

## Canonical JSON example

```json
{"attestation":{"digest":"sha256:3333333333333333333333333333333333333333333333333333333333333333","id":"erasure-1","kind":"weave.erasure","origin":{"instance":"ed25519:8888888888888888888888888888888888888888888888888888888888888888","project":"example"}},"digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","format":"weave-record/1","id":"receipt-7","kind":"weave.erased","origin":{"instance":"ed25519:9999999999999999999999999999999999999999999999999999999999999999","project":"example"}}
```

(Canonical member order: `attestation`, `digest`, `format`, `id`, `kind`, `origin`.)

## Why this kind exists

Erasure must be visible without destroying the referential graph. Replacing the record with
a digest-bearing placeholder keeps every existing reference meaningful (state `erased`),
keeps the container self-consistent (signed manifest + placeholder digest), and removes the
content and salt so privacy is preserved [G3][G3b][G3c][Q15].
