<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# weave-record/1 — exchange and reference format for records

**Status:** draft v0.1 (milestone H0). Not yet stabilised: `weave-record/1` v0.1 has not
passed the J1 and J2 round-trip acceptance cases, and only one independent verifier
implementation exists. This document is the normative specification of the draft.
**Version:** `weave-record/1`.
**Revision:** draft v0.1, revision 3 (Inceptless decision 2026-11-11 #2). Revision 3
implements rulings S1–S17 of decision 2026-11-11 #2 and the finding dispositions of
H1/J1a: it closes the trust, revocation, resource-limit and report-shape gaps found by the
second independent implementation. Revision 2 (Inceptless decision 2026-11-10 #42) made key
trust roots a local keyset input (R2), fixed the grant-chain verification time (R1), the
compromise-rescue accuracy bound (R3) and its unverifiable/invalid split (R4), the owner
class error code (R5), and the `genTime` cross-reference (R6). Revision 3 carries the S1
rounds (Inceptless decisions 2026-11-11 #5 to 2026-11-12 #3) and the **S2 round**
(Inceptless decision 2026-11-15 #8), which closes the findings of the second
implementation (H1 findings F38–F69) by the rules marked `[S2]`, together with its first
revision (Inceptless decision 2026-11-15 #18, the founder's rulings Q1–Q5 and the review
items of the S2 round, marked `[S2-FIX1]`); like the S1 rounds, it implements rulings of a
later decision inside revision 3 (§0.3).
**Editors:** Inceptless.
**Licence:** this specification text is licensed CC BY 4.0; code and test vectors for the
format are licensed Apache-2.0.

This document is normative for the `weave-record/1` exchange format. It is the English
rendering of the public-record-format decision draft v0.1 (2026-11-07) plus correction
v0.1.1 (2026-11-10), and of the rulings recorded in Inceptless decision 2026-11-10 #34.
Where this document and the decision draft disagree, the decision draft wins; such
disagreements are recorded as open questions.

**Ruling tags.** Normative content that is fixed by a ruling of Inceptless decision
2026-11-10 #34 is tagged `decided (Inceptless decision 2026-11-10 #34)` together with the
ruling identifier, for example `[S1]` or `[Q1]`; content fixed by a later decision is
tagged with that decision's date and number. Revision 2 of this document implements rulings
[R1]–[R6] of Inceptless decision 2026-11-10 #42; revision 3 implements rulings S1–S17 of
Inceptless decision 2026-11-11 #2 and tags them `decided (Inceptless decision 2026-11-11
#2; <ruling>)`, for example `[S3]`. No decision may be invented: a statement
that no ruling covers is labelled PROVISIONAL [S8] decided (Inceptless decision
2026-11-10 #34; S8). Content that no ruling covers is marked
**PROVISIONAL** and recorded as an open question; PROVISIONAL items are listed in
Appendix A. Ruling identifiers S1–S8 and Q1–Q33 are those of the decision 2026-11-10 #34 ruling
document, R1–R6 those of decision 2026-11-10 #42, and S1–S17 those of decision 2026-11-11 #2.
Decision-draft identifiers (`[C1]`, `[B3]`, `[E6]`, `[G3a]`, `[I2]`, `[K3]`, …) tie
paragraphs back to the decision draft. `[§8.1]`-style tags cite a section of the decision
draft, not of this document. Cross-references to this document are written as `§1.8` and
refer to this document's own numbering.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**,
**SHOULD NOT**, **RECOMMENDED**, **MAY** and **OPTIONAL** in this document are to be
interpreted as described in RFC 2119 and RFC 8174, but only when they appear in capitals.

## 0. Scope and terms

### 0.1 What the format is

`weave-record/1` is an **exchange and reference** format. Independent systems keep their own
internal formats and storage; when they export, they write records in this format and place
them in a signed container. Cross-system references are always "(origin, id, digest)". This
specification defines five things: the record envelope, the container, references,
signatures (including key lifecycle), and erasure [A1][§0].

This specification does **not** define: identity provision, credential issuance, a network,
a synchronisation service, a database, a blockchain or transparency log, or any project's
internal storage [A1][K1]. It also does not define encryption; see §11.10 for the
sign-then-encrypt rule [I3].

### 0.2 Terms

- **record** — one `weave-record/1` JSON document, either a normal envelope (§4) or the
  special `weave.erased` placeholder (§4.5).
- **canonical bytes** — the byte sequence produced by WR-CJ, the canonical JSON profile of
  §1.
- **digest string** — `<alg>:<lowercase hex>`, for example `sha256:ab…` (§2.7).
- **record digest** — the digest string of a record, computed per §2.2.
- **key id** — `ed25519:<32 lowercase hex>` computed per §2.5.
- **origin** — the pair `{project, instance}` that names the system and the specific key
  instance that created a record (§4.1, §6).
- **timestamp literal (TS)** — the timestamp grammar of §2.8.
- **container** — a directory, or its zip, with the layout of §11.
- **manifest** — `manifest.json` at the root of a container (§11.2).
- **attestation file** — `signatures/manifest.sig.json` (§11.3).
- **verification context** — the set of records against which a target is verified: the
  container's records (if the target is a container), plus records supplied externally (a
  keyset). Continuous chains across *multiple* containers are outside H0 (§9.8).
- **verifier** — an implementation that implements §14. The H0 Python verifier's command is
  named `hyphaweave-verify`; its report identity (`verifier.name` of §14.6) is
  `hyphaweave-verify-python` [S16/F1] decided (Inceptless decision 2026-11-11 #2; S16/F1).
- **export** — writing a container for consumption by another system. **Import** — taking
  delivery of records from another system. This format constrains exports and references;
  it does not constrain a project's internal storage [A1b].

### 0.3 Versions and change control

`format: "weave-record/1"` changes only on a breaking change, in which case the major
version rises; kinds evolve additively (new optional members, new kinds). A verifier
**MUST NOT** ever stop verifying an older version of the format; that commitment is the
core of the multi-decade goal [K3]. Changes to this specification are made by written
proposal and, at H0, are approved through the decision log; when governance is transferred
to multiple parties, a charter will be added to the repository [K4]. New algorithms are
introduced through the algorithm-name field of digest strings (§2.7) and signature `alg`
values (§4.3), never by silently changing the meaning of existing names [B3][E1].
A **revision** of this document is the set of rulings of the one decision that opens it
(revision 2: decision 2026-11-10 #42; revision 3: decision 2026-11-11 #2); later decisions
that close findings against the open revision are recorded as **rounds** of that revision
(the S1 rounds and the S2 round of revision 3), with their rulings tagged and listed in
Appendix A. The error-code registry (`spec/error-codes.md`) numbers its own revisions by
its own convention: a decision that opens a specification revision or a round opens a
registry revision, and later decisions that only revise that round are folded into the same
registry revision (registry revision 6 carries decisions 2026-11-12 #1, #2 and #3; registry
revision 7 carries decisions 2026-11-15 #8, #18 and #22). Neither changes the `format`
identifier [S2] decided by principle (Inceptless decision 2026-11-15 #8; S2); the
registry-numbering sentence is corrected to the registry's own history [S2-FIX1/T7] decided
by principle (Inceptless decision 2026-11-15 #18).

### 0.4 Normative references

- RFC 2119 / RFC 8174 — requirement keywords.
- RFC 8785 — JSON Canonicalization Scheme (JCS), used as the base of WR-CJ [C1].
- RFC 4648 §5 — base64url alphabet, used without padding [Q2].
- RFC 8032 — EdDSA/Ed25519, used through the strict profile of §3 [E1][Q1].
- RFC 3339 — timestamp grammar, restricted by §2.8 [F1][Q6].
- RFC 3161 — Time-Stamp Protocol, used for external time anchors [D3].
- RFC 4998 — evidence-record renewal, the model for the timestamp renewal chain (§12.4).
- RFC 5280 / RFC 6960-style certificate handling is not required by this document: the
  timestamp profile below names exactly the certificate checks a verifier performs.
- SPDX License List — licence expression syntax [H1][Q14].

### 0.5 Out of scope

- Transport (offline bundles, QR framing, relay queues) — not part of `weave-record/1`.
- Encrypted containers — only the rule that signatures are applied before encryption
  (§11.10).
- Trust in signer identity or truth of content — a signature proves which key signed which
  bytes, not that the content is true (§15).
- Guaranteed deletion of copies already distributed — erasure constrains exports and
  references (§10).
- Project-specific kinds not registered under the `weave.` namespace (§7.6).

## 1. Canonical JSON — WR-CJ v1

### 1.1 Profile

**WR-CJ v1** is the canonical JSON profile of this format. It is RFC 8785 JCS restricted as
follows [C1][C2][C3][C5]. WR-CJ is used for every record, every manifest, and anything else
this specification digests or signs. An implementation **MUST** implement WR-CJ itself (or
verify a library's behaviour against the vectors); it **MUST NOT** assume that a
general-purpose JSON library serialises canonically. Where this document says "canonical
JSON" it means WR-CJ v1.

### 1.2 Encoding and encoding form

1. Output **MUST** be UTF-8 with no byte-order mark, no insignificant whitespace, and no
   trailing newline [C1][C5].
2. Non-ASCII characters **MUST** be emitted as literal UTF-8; they **MUST NOT** be emitted
   as `\u` escapes. A lone surrogate escape (`\uD800`–`\uDFFF` not part of a valid
   surrogate pair) **MUST** be rejected with `E_JSON_LONE_SURROGATE` [C1].
3. No Unicode normalisation is performed anywhere: member names and string values are
   compared and serialised as the exact code points given, byte for byte after UTF-8
   encoding. A verifier **MUST NOT** normalise, case-fold or otherwise transform strings
   [Q4] decided (Inceptless decision 2026-11-10 #34).

### 1.3 Member order

Object members **MUST** be sorted ascending by the **UTF-16 code-unit sequence** of the
member name (clause 3.2.3 of RFC 8785). This ordering is normative and is not the same as
UTF-8 byte order for supplementary code points; implementations **MUST** sort by UTF-16
code units. Member names are compared by code-unit value only; no locale-dependent
comparison is allowed [C1][Q4].

### 1.4 Duplicate member names

Duplicate member names **MUST** be rejected during parsing, at any nesting depth, with
`E_JSON_DUPLICATE_KEY` [C3]. Last-value-wins semantics are forbidden at every level,
including inside `body` [C3].

### 1.5 Strings and escaping

Strings **MUST** follow ECMAScript `JSON.stringify` escaping exactly [C1]:

- `"` **MUST** be emitted as `\"`; `\` **MUST** be emitted as `\\`;
- U+0008 **MUST** be emitted as `\b`, U+0009 as `\t`, U+000A as `\n`, U+000C as `\f`,
  U+000D as `\r`;
- every other code point U+0000–U+001F **MUST** be emitted as `\u00xx` with **lowercase**
  hexadecimal digits;
- every other code point **MUST** be emitted as literal UTF-8;
- `/` **MUST NOT** be escaped.

### 1.6 Numbers

Numbers **MUST** be integers in the inclusive interval `[-(2^53-1), +(2^53-1)]` [C2].
Numbers **MUST** be serialised in base 10 with no leading zero, no `+` sign and no `-0`
(the canonical form of zero is `0`). Floats, exponent notation, `1.0` and `-0` **MUST** be
rejected; a format that needs fractional or physical quantities **MUST** encode them as
strings with units, for example `"12.50 kWh"` or `{"value":"12.50","unit":"kWh"}` [C2].

Input classification is fixed by the rulings, in a single left-to-right pass over the input
bytes (§1.9): a numeric literal that is not valid JSON (`+1`, `01`, `.5`, `1.`) is a JSON
syntax error (`E_JSON_INVALID`); a syntactically valid JSON number that is a float or has an
exponent (`1.0`, `1e3`) is `E_JSON_NUMBER_NOT_INTEGER`; a syntactically valid JSON integer
outside the interval is `E_JSON_NUMBER_RANGE`; the literal `-0` is
`E_JSON_NOT_CANONICAL` (valid JSON but not WR-CJ canonical). The number classes are
classified at the token where the number occurs, in input byte order: for example
`{"a":-0,"b":1.5}` reports `E_JSON_NOT_CANONICAL` because the `-0` token — a canonical-form
deviation in a number spelling — is reached before the later float, while
`{"b":1.5,"a":-0}` reports `E_JSON_NUMBER_NOT_INTEGER`. The canonical-form byte comparison
of §1.8 still runs after the syntax pass, as §1.9 describes; `-0` is the one canonical-form
deviation that is classified at its number token during that pass
[Q5][Q6][M-14][S8④] decided (Inceptless decision 2026-11-11 #2; S8).

### 1.7 Booleans, nulls, arrays, objects

`true`, `false`, `null`, arrays and nested objects follow RFC 8785 [C1]. No other JSON
extensions are permitted.

### 1.8 Canonical file form

Every JSON file that this format digests or signs — record files, `manifest.json`,
`previous/manifest.json`, and `signatures/manifest.sig.json` — **MUST** contain exactly the
WR-CJ bytes of its value, optionally followed by exactly one LF byte (`0x0A`) at end of
file [C5]. A single trailing LF is tolerated; any other deviation (whitespace, member order,
escape choice, number spelling, CR bytes, extra bytes, more than one trailing LF) **MUST**
be rejected with `E_JSON_NOT_CANONICAL`. Digests and signatures are always computed over
the canonical bytes **without** the optional trailing LF. A receiving implementation
**MUST** re-canonicalise the parsed value and fail if the file does not satisfy this rule;
it **MUST NOT** verify a signature over re-serialised bytes that differ from the bytes
received [C5].

The attestation file `signatures/manifest.sig.json` is not itself digested or signed, but
its bytes are part of the container evidence and therefore also follow the canonical file
form. Everything under `readable/` is exempt: it is never parsed or hashed (§11.8).

### 1.9 Error precedence for malformed JSON

A verifier classifies the input in **two fixed stages** and reports one code: stage one is a
single left-to-right syntax/number pass, which reports the first violation in input byte
order among the syntax, duplicate-member, number and lone-surrogate classes, and classifies
the `-0` number spelling at its token position; stage two is the canonical-form byte
comparison, which runs only after the input has parsed successfully and reports
`E_JSON_NOT_CANONICAL` for the first deviation in byte order (the code is the same for
every canonical-form deviation). A verifier **MUST NOT** build a full document tree first
and then report syntax-class violations in some other order
[M-14][S8④] decided (Inceptless decision 2026-11-11 #2; S8). The classes are:

| first violation encountered | code |
|---|---|
| the file exceeds its size limit (checked on the input length before parsing) or the JSON **value nesting depth** exceeds `MAX_JSON_DEPTH` (checked while parsing, §13) | `E_JSON_SIZE` |
| not UTF-8; BOM; truncated input; trailing non-whitespace content; `+1`, `01`, `.5`, `1.`, trailing comma, comment, or any other JSON syntax error; top-level value not an object where an object is required | `E_JSON_INVALID` |
| a duplicate member name at any nesting depth | `E_JSON_DUPLICATE_KEY` |
| a syntactically valid JSON number that is a float or has an exponent | `E_JSON_NUMBER_NOT_INTEGER` |
| a syntactically valid JSON integer outside `[-(2^53-1), +(2^53-1)]` | `E_JSON_NUMBER_RANGE` |
| a lone surrogate escape | `E_JSON_LONE_SURROGATE` |
| the `-0` number spelling, at its number token in the stage-one pass | `E_JSON_NOT_CANONICAL` |
| after a syntactically valid parse, byte form not WR-CJ canonical (for example wrong member order, non-shortest escaping, insignificant whitespace, CR bytes, more than one trailing LF, extra bytes) | `E_JSON_NOT_CANONICAL` |

`-0` is a canonical-form deviation in a number spelling; it is classified at its number
token because the number classes are examined in input byte order, and this is what makes
the examples below deterministic. The other canonical-form deviations are byte comparisons
and are detected after the syntax pass; among several of them the first one in byte order
is not separately distinguished (the code is the same). For example, `{"a":1,"a":1.5}`
reports `E_JSON_DUPLICATE_KEY`: the duplicate is encountered before the float;
`{"a":1.5,"a":1}` reports `E_JSON_NUMBER_NOT_INTEGER` for the same reason;
`{"a":-0,"b":1.5}` reports `E_JSON_NOT_CANONICAL` for the `-0` token, while
`{"b":1.5,"a":-0}` reports `E_JSON_NUMBER_NOT_INTEGER`. The examples in this paragraph are
illustrative; the vectors are normative.

The size limit is checked on the input length before parsing: an input larger than its
applicable limit is `E_JSON_SIZE` regardless of any defect below that row. JSON **value
nesting depth** is counted while parsing so that a hostile input cannot overflow the stack:
the top-level value is depth 1, every member value and every array element is one level
deeper than the value that contains it, and a scalar is a leaf value at its own depth. A
depth above `MAX_JSON_DEPTH` is `E_JSON_SIZE` and, like any size violation, is an invalid
outcome, never a crash [S3] decided (Inceptless decision 2026-11-11 #2; S3).

**UTF-8 validity is a whole-input precondition.** An input that is not valid UTF-8 is
`E_JSON_INVALID` regardless of any structural violation (for example a depth violation) at a
lower byte offset: UTF-8 decoding precedes the per-position classification of the table
above (T17/A-L6). This is the only exception to the byte-order reading of this section.

### 1.10 Size

See §13 for size limits; a WR-CJ document larger than its limit is `E_JSON_SIZE`.

## 2. Byte constructions and encodings

This section is normative and byte-exact. All domain prefixes are ASCII strings and each
ends with exactly one LF byte. "‖" denotes byte concatenation.

### 2.1 Domain-separation prefixes [C4]

| purpose | prefix (ASCII, includes the final LF) |
|---|---|
| record digest | `weave-record/1/digest\n` |
| record signature | `weave-record/1/sig\n` |
| manifest digest | `weave-record/1/manifest-digest\n` |
| manifest signature | `weave-record/1/manifest\n` |

No other prefix is defined by `weave-record/1`. A signature made over one purpose's bytes
**MUST NOT** be accepted for another purpose. Cross-purpose acceptance is a defect, and the
vectors contain both directions (a record signature carrying the manifest prefix and a
manifest signature carrying the record prefix) [C4] decided (Inceptless decision
2026-11-10 #34; S1).

### 2.2 Record digest [C4][B3][E6]

The record digest of a record `R` is:

```
record_digest = "sha256:" + lowercase_hex( SHA-256(
    "weave-record/1/digest\n" || WR-CJ(R with its top-level member "sigs" removed) ) )
```

If `sigs` is absent, WR-CJ is computed over the record as it is. The digest covers every
other member, including `body`, `labels`, `salt`, `refs`, `actor`, `stage`, `origin`, `id`,
`kind`, `format`, `recorded_at` and `occurred_at`. The record digest is **never** stored
inside the normal record envelope; it is computed on demand and published in container
manifests and references [C4][E6]. For `weave.erased` placeholders, which have no `sigs`
member, the same construction applies unchanged (§4.5).

### 2.3 Record signature [E6][C4]

The bytes signed by a record signature are:

```
sig_message = ASCII( "weave-record/1/sig\n" + record_digest )     # record_digest is the ASCII digest string
signature   = Ed25519_sign(private_key, sig_message)              # 64 bytes
```

The signature value is carried in base64url in the `value` member of a `sigs` entry (§4.3).
Verification decodes `value` and verifies Ed25519 over exactly `sig_message` with the public
key identified by the `sigs[].key` key id, under the profile of §3. Implementations
**MUST NOT** sign or verify any serialisation of the record other than `sig_message`; in
particular they **MUST NOT** sign the record object, its field order, or the record file
bytes [E6].

### 2.4 Manifest digest and manifest signature [I2][D1]

```
manifest_digest = "sha256:" + lowercase_hex( SHA-256(
    "weave-record/1/manifest-digest\n" || <canonical file bytes of manifest.json, without the optional trailing LF> ) )

manifest_sig_message = ASCII( "weave-record/1/manifest\n" + manifest_digest )
manifest_signature   = Ed25519_sign(private_key, manifest_sig_message)      # 64 bytes
```

The manifest digest therefore binds the exact bytes of the manifest file; it is stored in
the attestation file as `digest`, never inside `manifest.json`. Placing the manifest digest
outside the manifest is the H0 reading of the decision draft's requirement that a manifest
must carry its own digest: the signed manifest stays free of signature bytes, so manual
verification needs no byte surgery on signed content [I2][D1][Q8] decided (Inceptless
decision 2026-11-10 #34; Q8). The manifest digest is also the RFC 3161
`messageImprint.hashedMessage` of the first timestamp (§12.2) and the target of
`previous_manifest.digest` in the next container (§11.5).

### 2.5 Key ids [E3][correction v0.1.1]

```
key_id = "ed25519:" + first 32 lowercase hex characters of SHA-256(<32-byte raw Ed25519 public key>)
```

The 32-byte raw public key is exactly the RFC 8032 public-key encoding (compressed Edwards
point). The hash input is the 32 raw bytes, **not** the hexadecimal text of the key. Hashes
of the hex text are **not** this format's key id, and a verifier **MUST NOT** compute key
ids that way [E3][correction v0.1.1].

A declared key's point validity (canonical encoding, small order, subgroup membership) is
**not** checked when the key is declared; a declaration only requires 32 bytes and the key
id derivation. Point and order checks happen when a signature is verified (§3.4)
[Q1][Q20] decided (Inceptless decision 2026-11-10 #34; S1/M-11). Key ids are claims until a
`weave.key.declared` record supplies the public key; a verifier **MUST** recompute the key
id from the declared public key and **MUST** reject a mismatch with `E_KEY_ID_MISMATCH`
(§9.1). DID strings and URLs are hints only and never identifiers [E3].

### 2.6 base64url [Q2]

`public_key`, `sigs[].value` and `salt` use unpadded base64url: RFC 4648 §5 alphabet
`A–Z a–z 0–9 - _`, **no `=` padding** [Q2] decided (Inceptless decision 2026-11-10 #34).
Decoding **MUST** be strict: padding, whitespace, `+` or `/` characters, and any non-zero
unused trailing bits **MUST** be rejected. Expected encoded lengths: 16 bytes → 22
characters, 32 bytes → 43 characters, 64 bytes → 86 characters.

Error codes: a malformed ed25519 `sigs[].value` is `E_ENV_SIG_VALUE`; a malformed `salt` is
`E_ENV_SALT`; a malformed `public_key` is `E_KEY_PUBLIC_KEY` (in `weave.key.declared`) or
`E_KEY_ROTATION_KEYS` (in `weave.key.rotated`, §9.2). A padded input is always an error; it
is never accepted by removing the padding.

### 2.7 Digest strings and algorithm agility [B3][Q13]

A digest string is `<alg>:<lowercase hex>`. For H0 the only defined algorithm is `sha256`:
`sha256:` followed by exactly 64 lowercase hexadecimal characters. An algorithm name is an
ASCII token matching `^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`, at most 32 bytes; its hexadecimal
part is one or more lowercase hexadecimal characters (at most 128). The algorithm name is
the algorithm-agility interface; new names (`sha3-256:`, …) may be added by proposal
[B3][K4].

A digest string whose algorithm is structurally valid but not implemented is **not** a
malformed value: it is *structurally valid but unsupported*. A reference with an unknown
digest algorithm resolves to `unverifiable` (§6.3), which is not a record or container
error; a `manifest.records[]` entry with an unknown algorithm is `E_MANIFEST_RECORDS`
(invalid) because a container must list records in a form the format can verify [B3][Q13]
decided (Inceptless decision 2026-11-10 #34; Q13). Implementations **MUST NOT** silently
treat an unknown algorithm as `sha256`.

### 2.8 Timestamp literal (TS) [F1][F2][Q6]

A timestamp literal is exactly:

```
TS = YYYY "-" MM "-" DD "T" HH ":" MM ":" SS "." sss "Z"
```

- UTC only, literal `Z`; no other offset and no `+00:00` form;
- years `0000`–`9999`; months, days, hours and minutes are two digits and must be a valid
  calendar date-time in the proleptic Gregorian calendar (for example `2026-02-29` is
  invalid);
- seconds `00`–`59`; the value `60` (leap second) is **not** permitted; a leap second is
  attributed to the following second;
- exactly three fractional digits (milliseconds), which may be `000`.

All times in this format (`recorded_at`, `occurred_at`, `created_at`, `valid_from`,
`valid_until`, `effective_at`, `executed_at`) are **claimed** times, not trusted times
[F1][F2][F4]. `recorded_at` and `occurred_at` have no ordering requirement relative to each
other. A malformed timestamp is `E_ENV_TIME` in the envelope; in kind bodies and manifests
the error code is the one listed by the kind page or `E_MANIFEST_SCHEMA` respectively;
`genTime` of an RFC 3161 token is converted per §12.2 check 13. The canonical serialisation of a TS
value is exactly its 24 ASCII bytes. The grammar is fixed by the ruling [Q6] decided
(Inceptless decision 2026-11-10 #34).

## 3. Ed25519 signature profile

### 3.1 Algorithm

The only signature algorithm defined by `weave-record/1` is Ed25519 (PureEdDSA over
Curve25519, RFC 8032). HMAC signatures and other symmetric proofs are valid only inside the
originating system; they are **not** exchange-layer proofs and **MUST NOT** be represented
as `sigs` entries [E1]. Signature values are 64 bytes (`R ‖ S`); public keys are 32 bytes.
Other asymmetric algorithms may be added by proposal. A `sigs` entry whose `alg` is not
`ed25519` is structurally validated (§4.3) and then **ignored** by an H0 verifier: an
unknown algorithm never makes a record invalid by itself, and a future mixed-algorithm
record can still be verified for its ed25519 evidence [E1][Q13] decided (Inceptless
decision 2026-11-10 #34; Q13).

### 3.2 Decoding a compressed Edwards point

The profile uses the complete clause 5.1.3 of RFC 8032 decoding procedure. A verifier **MUST** decode
`A` and `R` with all of the following steps, in this order, and **MUST NOT** substitute a
library call whose failure classification it has not checked [S1][Q1] decided (Inceptless
decision 2026-11-10 #34; S1).

Input: 32 octets `o[0..31]`. Let `p = 2^255 − 19` and
`d = −121665 / 121666 mod p`.

1. Interpret `o` as a little-endian integer; let `x_0` be bit 255 (the most significant
   bit) and let `y` be the integer obtained by clearing bit 255.
2. If `y >= p`, decoding fails (non-canonical `y`).
3. Let `u = y² − 1 mod p` and `v = d·y² + 1 mod p`. Compute a candidate
   `x = (u/v)^((p+3)/8) mod p` as in clause 5.1.3 of RFC 8032: if `v·x² = u` the candidate is
   valid; else if `v·x² = −u`, replace `x` by `x·2^((p−1)/4) mod p`; otherwise decoding
   fails (no square root: the encoded point is not on the curve).
4. If `x = 0` and `x_0 = 1`, decoding fails: the only canonical encoding of a point with
   `x = 0` has sign bit 0. This rule is mandatory; omitting it makes the identity-point
   forgery below possible.
5. If `x ≠ 0` and `x mod 2 ≠ x_0`, set `x = p − x`.
6. The decoded point is `(x, y)`.

The canonical encoding of a point `(x, y)` is the 32-octet little-endian encoding of `y`
with bit 255 set to `x mod 2`.

### 3.3 Point predicates used by verification

- The **identity** is the point `(0, 1)`.
- A decoded point `P` is **small-order** if and only if `[8]P` is the identity. This is a
  predicate on the decoded point, not on a list of encodings; the eight canonical
  32-byte encodings of the small-order points are still useful as test values, but a
  verifier **MUST NOT** implement the check as an encoding-list comparison [S1] decided
  (Inceptless decision 2026-11-10 #34; S1).
- A decoded point `A` is **mixed-order** if it is not small-order and `[L]A` is not the
  identity, where `L = 2^252 + 27742317777372353535851937790883648493` is the prime order
  of the Ed25519 base point. In other words, `A` is not in the prime-order subgroup.
- The base point `B` is the standard Ed25519 base point of RFC 8032.

### 3.4 Fixed verification order and error codes

Verification of one signature over one message `M` (the `sig_message` of §2.3 or §2.4) is
single-message, strict and cofactorless. The checks are performed in **exactly this
order**; the first failing check determines the reported code [S1][Q1] decided (Inceptless
decision 2026-11-10 #34; S1).

| step | check | code on failure |
|---|---|---|
| 1 | the signature `value` decoded from strict unpadded base64url is exactly 64 octets (this is a structural check of the envelope/attestation, performed before crypto) | `E_ENV_SIG_VALUE` (record signature, §4.3) / `E_MANIFEST_SCHEMA` (manifest signature, §11.3) |
| 2 | the public-key octets are exactly 32 | `E_SIG_NONCANONICAL_A` |
| 3 | interpret signature octets 32–63 as a little-endian integer `S`; require `S < L` | `E_SIG_S_OUT_OF_RANGE` |
| 4 | decode `A` (the public key) per §3.2 | `E_SIG_NONCANONICAL_A` |
| 5 | require `[8]A != identity` | `E_SIG_SMALL_ORDER_A` |
| 6 | require `[L]A == identity` (reject mixed-order public keys) | `E_SIG_MIXED_ORDER_A` |
| 7 | decode `R` (signature octets 0–31) per §3.2 | `E_SIG_NONCANONICAL_R` |
| 8 | require `[8]R != identity` | `E_SIG_SMALL_ORDER_R` |
| 9 | let `k = SHA-512(R ‖ A ‖ M) mod L`; accept iff `[S]B = R + [k]A` (cofactorless equation) | `E_SIG_INVALID` |

No batch verification, no context string, no pre-hash and no cofactored variant is
permitted. The identity-key forgery (a small-order `A`) and the `x = 0, x_0 = 1`
non-canonical encodings **MUST NOT** be accepted; step 5 and step 4 of §3.2 are the two
checks that block them. Accepting an invalid signature at any step is a defect; a verifier
**MUST NOT** rely on its cryptographic library to classify these conditions.

### 3.5 Signing

Signing is RFC 8032 PureEdDSA: derive the secret scalar and nonce prefix from the seed with
SHA-512, compute `r = SHA-512(prefix ‖ M) mod L`, `R = [r]B`, `S = (r + SHA-512(R ‖ A ‖ M)·s)
mod L`, and emit `R ‖ S`. Seed generation, storage and protection are out of scope (§15).

### 3.6 Signature aggregation and unknown algorithms [E1][Q13]

A record's `sigs` array is a set of independent signatures over the same `sig_message`.
Every entry whose `alg` is `ed25519` and whose signature verifies is evidence; an entry with
a known algorithm and an invalid signature makes the unit invalid (`E_SIG_INVALID` in the
table above). Entries with an unknown `alg` are validated structurally (§4.3) and then
ignored: they do not make the record invalid, and a report lists their state as `ignored`.
Whether a record's required per-record signing obligation is satisfied is decided only from
known-algorithm signatures (§4.4) [Q13] decided (Inceptless decision 2026-11-10 #34; Q13).

An `ed25519` entry whose key is not declared anywhere in the verification context — and is
not supplied explicitly by the record itself or by a declaration/rotation record in the
context (as a `weave.key.declared` self-signature or an `old_public_key`/
`new_public_key` member does) — cannot be checked: the record is `unverifiable` with
`E_KEY_UNKNOWN`. Such an entry is **not** ignored; an attacker could
otherwise add an unverifiable signature to an otherwise valid record. The same applies to
manifest attestation signatures (§11.3).

### 3.7 External test-vector mapping [Q1]

For the Wycheproof Ed25519 test vectors, the expected outcome of this profile is:

- `valid` cases → accept;
- `invalid` cases → reject;
- `acceptable` cases → **reject** for both classes present in the corpus: small-order
  public keys (`E_SIG_SMALL_ORDER_A`) and mixed-order public keys
  (`E_SIG_MIXED_ORDER_A`). Cases whose `acceptable` verdict comes from another defect are
  rejected with the code of the first failing check in §3.4.

The ruling chooses rejection for every `acceptable` case: across decades and independent
implementations, agreement on one strict profile matters more than compatibility with
individual library defaults, and "when in doubt, reject" is the stated principle [Q1]
decided (Inceptless decision 2026-11-10 #34; Q1). For clause 7.1 of RFC 8032 vectors, all signatures
MUST verify and the derived public keys MUST equal the published ones. The per-case outcome
table and the provenance of the external data are recorded under `vectors/`.

## 4. Record envelope — normal kinds

A normal record is a canonical JSON object. Its top-level members are **closed**: a member
not listed in the table below is `E_ENV_UNKNOWN_FIELD` (invalid), and a missing required
member is `E_ENV_MISSING_FIELD` (invalid). `E_ENV_MISSING_FIELD` and `E_ENV_UNKNOWN_FIELD`
are envelope-level codes and apply only to the top-level envelope object. Unknown members
inside `body` are permitted and are governed by the kind rules (§7.5).

Nested closed objects report the code of the section that defines them, not the
envelope-level codes: a defect inside `origin` is `E_ENV_ORIGIN`, inside `actor` the
`E_ENV_ACTOR*` code of the failing rule, inside a reference object `E_ENV_REFS` (including a
reference object nested in `actor.grant`), inside `labels` the `E_ENV_LABELS` /
`E_ENV_SENSITIVITY` / `E_ENV_LICENCE` code of the failing rule, inside a `sigs` entry
`E_ENV_SIGS` or that entry's per-member code (§4.3), inside the manifest or the attestation
file `E_MANIFEST_SCHEMA`, and inside the `weave.erased` placeholder `E_KIND_BODY_SCHEMA`
(§4.5). Inside a closed nested object the check order is required members, then closedness,
then per-member grammar, in the order the owning section lists them; the first failing rule
of that section is reported [S8⑤⑥][F2][F3] decided (Inceptless decision 2026-11-11 #2;
S8/F2/F3).

### 4.1 Top-level members

| member | required | rule |
|---|---|---|
| `format` | yes | exactly the string `"weave-record/1"`; otherwise `E_ENV_FORMAT` |
| `kind` | yes | kind name, syntax in §7.1; `weave.` names reserved to this specification; otherwise `E_ENV_KIND_SYNTAX` [§2] |
| `origin` | yes | closed object `{"project":<slug>,"instance":<key id>}`; `project` matches `^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$` and is at most 64 bytes; `instance` is a key id (§2.5); otherwise `E_ENV_ORIGIN` [B1][B2] |
| `id` | yes | 1–256 Unicode scalar values; no C0 control characters (U+0000–U+001F), no C1 control characters (U+0080–U+009F) and no U+007F (DEL); no leading or trailing U+0020 space; otherwise `E_ENV_ID` [B1] |
| `stage` | yes | one of the five closed values defined in §4.1.1; otherwise `E_ENV_STAGE` [G1] |
| `actor` | yes | closed object (§4.2); errors `E_ENV_ACTOR*` [E2] |
| `recorded_at` | yes | TS grammar of §2.8; otherwise `E_ENV_TIME` [F1][F4] |
| `occurred_at` | no | TS grammar; claimed; no ordering rule relative to `recorded_at`; otherwise `E_ENV_TIME` [F1][F2] |
| `refs` | no | array of at most 256 reference entries `{"rel":<rel>,"ref":<reference object>}`; see §6; duplicate entries rejected; otherwise `E_ENV_REFS` [F3] |
| `labels` | no | closed object; see §8.1; otherwise `E_ENV_LABELS` [H1] |
| `salt` | conditional | 16 random bytes in base64url (§2.6). **REQUIRED** if `labels.sensitivity` is `personal` or `local-only` (`E_ENV_SALT_MISSING`); a malformed value is `E_ENV_SALT`; optional in every other case [G3c][Q3] decided (Inceptless decision 2026-11-10 #34; Q3) |
| `body` | yes | a JSON object; absent or non-object is `E_ENV_BODY`; body semantics are the kind's (§7) |
| `sigs` | conditional | array of 0–16 signature entries (§4.3), sorted by `key` ascending, unique keys; whether a record MUST carry signatures is decided by §4.4; errors `E_ENV_SIGS`, `E_ENV_SIG_KEY`, `E_ENV_SIG_VALUE`, and `E_SIG_REQUIRED` when signing is required but the array is absent or empty [E1][E6][S7①] |

`id` is unique only within its `origin`; cross-system identity is by digest, never by
`id` alone [B1]. The member `salt` is included in the record digest; it is deleted together
with the content on erasure (§10) so that the original digest cannot be brute-forced after
erasure, while before erasure a third party can still verify the record [G3c].

#### 4.1.1 `stage` values and time fields

The five `stage` values name the acting system's relation to the claim:

| value | meaning |
|---|---|
| `proposed` | the actor asserts the claim without having adopted it; it does **not** mean "awaiting receiver approval" |
| `accepted` | the actor adopts the claim as its current position |
| `rejected` | the actor rejects the claim |
| `withdrawn` | the actor withdraws a claim it previously asserted |
| `superseded` | the actor declares this claim replaced by a later record; the later record carries the `supersedes` reference (§6.2) |

Stage is an envelope value and a claim like any other; a `proposed` record is not an approval
workflow item, and projects that need finer sub-states put them in `body`
[T11; `docs/open-questions.md` §6 entry 15] decided by principle (Inceptless decision 2026-11-11 #5; T11).

`recorded_at` is the time the source system wrote this record into its own storage.
`occurred_at`, when present, is the claimed time at which the event described by the record
happened. Both are claimed times (§2.8) with no ordering requirement between them: an event
may be recorded long after it happened, and a record may describe an event scheduled for the
future [S15①] decided (Inceptless decision 2026-11-11 #2; S15).

### 4.2 `actor` (closed object)

`actor` describes who acted. Its members are closed.

| member | required | rule |
|---|---|---|
| `type` | yes | one of `human`, `agent`, `program`, `device`, `organization`; otherwise `E_ENV_ACTOR_TYPE` [E2] |
| `key` | yes | a key id (§2.5); otherwise `E_ENV_ACTOR_KEY` |
| `model` | iff `type == "agent"` | `provider/model@version`, ASCII, 1–256 bytes, matching `^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*@[A-Za-z0-9][A-Za-z0-9._+-]*$`; missing when required `E_ENV_ACTOR_MODEL_MISSING`; malformed `E_ENV_ACTOR_MODEL` [§8][E2] |
| `on_behalf_of` | iff `type == "agent"` | a key id; the principal the agent acts for; missing when required `E_ENV_ACTOR_ON_BEHALF_MISSING`; malformed `E_ENV_ACTOR_ON_BEHALF` [§8] |
| `grant` | iff `type == "agent"` | a reference object (§6.1) whose target kind SHOULD be `weave.grant`; missing when required `E_ENV_ACTOR_GRANT_MISSING` [§8] |
| `idempotency_key` | iff `type == "agent"` | 1–256 Unicode scalar values, no control characters; missing when required `E_ENV_ACTOR_IDEMPOTENCY_MISSING`; malformed `E_ENV_ACTOR_IDEMPOTENCY` [§8] |

A missing required member of `actor` reports its member code from the table (`type` →
`E_ENV_ACTOR_TYPE`, `key` → `E_ENV_ACTOR_KEY`, and so on); a non-object `actor`, a member
forbidden for the actor type, or an otherwise structurally invalid actor object is
`E_ENV_ACTOR` [S8⑥/F2] decided (Inceptless decision 2026-11-11 #2; S8/F2). A malformed
reference object in `actor.grant` is `E_ENV_REFS`, not an actor code: the reference grammar
is owned by §6.1.

`model`, `on_behalf_of`, `grant` and `idempotency_key` **MUST** be absent for non-agent
actors (`E_ENV_ACTOR`). The `agent` type is the only type with these extra obligations
because agent reasoning is the least trustworthy writer in the system; `program` and
`device` actors are non-human automated writers but they still must obey the human-key rule
(§5.2) [E2][§8].

**Exception — key-lifecycle records.** For the three kinds `weave.key.declared`,
`weave.key.rotated` and `weave.key.revoked`, `actor.type` merely names the class of the key
the record is about (`body.key_type` for a declaration, the old key's class for a rotation,
the signing or revoked key's class for a revocation): these records are key
self-descriptions and key-state assertions, not delegated actions. For these three kinds the
four agent-only members (`model`, `on_behalf_of`, `grant`, `idempotency_key`) are **NOT
required**, and a verifier **MUST NOT** require them; a record of one of these kinds whose
`actor.type` is `agent` is valid without them. They remain forbidden for non-agent actors
by the rule above. Delegated `weave.grant` records and all other agent-authored records keep
the full obligations [Q28] decided (Inceptless decision 2026-11-10 #34; Q28).

### 4.3 `sigs` entries (closed object)

Each entry is exactly `{"alg":<algorithm name>,"key":<key id>,"value":<base64url>}`. `sigs`
is an array of 0–16 entries; it **MUST** be sorted ascending by the `key` string (UTF-16
code-unit order; the key id is ASCII so byte order is identical) and keys **MUST** be
unique. An empty array is structurally valid; whether a record **must** carry signatures is
decided by §4.4, not by this structural rule [S7①] decided (Inceptless decision 2026-11-11
#2; S7). Structural errors of the array or of an entry's closed shape are `E_ENV_SIGS`,
including a member of an entry that is present with the wrong JSON type. The JSON types of
the three members are part of the entry's structure and are judged, in every entry, before
the grammar of any member, so an entry whose `value` is a number reports `E_ENV_SIGS` even
when its `key` is also malformed [S2/F67] decided by principle (Inceptless decision 2026-11-15 #8; S2). Per-member grammar
when the member is a string is:

- `alg` **MUST** match `^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$` and be at most 32 bytes.
- When `alg == "ed25519"`: `key` **MUST** be `ed25519:` followed by exactly 32 lowercase
  hexadecimal characters (`E_ENV_SIG_KEY` when malformed), and `value` **MUST** be strict
  unpadded base64url of exactly 64 bytes (`E_ENV_SIG_VALUE`).
- When `alg` is another well-formed algorithm name: `key` **MUST** match
  `^[a-z][a-z0-9]*(?:-[a-z0-9]+)*:[0-9a-f]{1,128}$` and `value` **MUST** be strict
  unpadded base64url of 1–2048 bytes; both are structural only and the entry is ignored
  for verification (§3.6). A structural violation is `E_ENV_SIGS`.

`E_ENV_SIG_ALG` is **not emitted by an H0 verifier**; it is retained in the closed registry
for older vectors and for future algorithms that may want a stricter profile [E1][Q13]
decided (Inceptless decision 2026-11-10 #34; Q13).

Because the record digest and the record signature are computed with `sigs` removed (§2.2,
§2.3), no byte inside a `sigs` entry is covered by the record digest or by the signature
over it; in particular a mutated `sigs[].alg` value that is still a well-formed algorithm
name cannot change a signature conclusion. This is a property of the byte constructions, not
a licence to skip the structural rules of this section [S16/F13] decided (Inceptless
decision 2026-11-11 #2; S16/F13).

### 4.4 Records that MUST be signed per record

The container signature (§11.3) covers every record by digest, but certain records must also
carry their own signatures so that they remain verifiable after being extracted from their
container. A record **MUST** carry `sigs` when **any** of the following holds:

1. `stage == "accepted"` (any kind);
2. `kind` is one of `weave.key.declared`, `weave.key.rotated`, `weave.key.revoked`,
   `weave.grant`, `weave.consent.granted`, `weave.consent.revoked`, `weave.erasure`;
   these seven kinds also **MUST** use `stage == "accepted"` (any other stage is
   `E_ENV_STAGE`) [§4][Q7] decided (Inceptless decision 2026-11-10 #34);
3. the kind's own rules require per-record signing (none of the eight registered kinds
   adds a requirement beyond 1 and 2; future kinds may).

Otherwise `sigs` **MAY** be absent; such records are covered by the container signature only
[§4]. This split exists because agent-generated records can be numerous: they may be
container-signed as a batch, but authorisation, key, consent and erasure records may not
[§4][§8.4].

**Required-signature error precedence.** The following order is fixed
[Q31][Q13][Q30][S7①] decided (Inceptless decision 2026-11-11 #2; S7):

1. If a record is required to be per-record signed (above) and its `sigs` member is absent
   or an empty array, the record is invalid with `E_SIG_REQUIRED`.
2. Every `ed25519` signature entry is verified per §3.4; a known-key signature that fails
   the equation (or any other crypto step) makes the record invalid with the corresponding
   `E_SIG_*` code. This holds even when another entry names a key that cannot be resolved
   (§14.5 step (4)): an invalid outcome of one entry is never lowered to `unverifiable`
   `E_KEY_UNKNOWN` by another entry [S2-FIX1/T2] decided by principle (Inceptless decision
   2026-11-15 #18; invalid beats unverifiable).
3. If at least one `ed25519` signature by the required signer verifies, the obligation is
   satisfied (additional valid signatures are evidence, not errors).
4. Otherwise, if at least one **known-algorithm** signature exists whose key is declared
   (i.e. there is a verifiable signature, just not by the required signer), then:
   - for the seven signer-constrained kinds, the kind's dedicated signer code is reported
     (§9, §5.5, kind pages);
   - for every other kind, `E_SIG_REQUIRED` is reported.
5. Otherwise (no entry has a known algorithm and a declared key):
   - if **no** required signer key — `actor.key` for an ordinary kind; for a
     signer-constrained kind the key or keys its signer rule names (the declared key, the
     rotation's old or new key, the revocation or grant signer) — is declared anywhere in the
     verification context, the record is `unverifiable` with `E_KEY_UNKNOWN`;
   - otherwise the record is `unverifiable` with `E_SIG_UNVERIFIABLE`.
   A key is declared when a `weave.key.declared` record in the context (including the record
   being verified) declares it, or when a `weave.key.rotated` record lists its public key
   (§9.2 rule 5). The key of an unknown-algorithm entry that is not a required signer does
   not decide between the two codes (vector `sig/unknown-alg`). Step 5 applies to the seven
   signer-constrained kinds exactly as to every other kind: when no known-algorithm
   declared-key signature exists at all, the dedicated signer code of step 4 is **not**
   reported [S2/F46] decided by principle (Inceptless decision 2026-11-15 #8; S2).
   Step 5 is reached only after §14.5 step (4): an `ed25519` entry whose key is not declared
   has already made the record `unverifiable` `E_KEY_UNKNOWN` there (unless an entry is
   invalid, step 2), so at step 5 every remaining entry has an unknown algorithm, and the
   `E_KEY_UNKNOWN` of step 5 is about the required signer key, not about an entry's key
   [S2-FIX1/T7] decided by principle (Inceptless decision 2026-11-15 #18). For the seven
   signer-constrained kinds the step-5 outcome is reported only after every other rule of
   that kind's step (7) has passed: an invalid outcome of the kind's other rules (or an
   `unverifiable` one, such as a grant-chain code) is reported instead, and the step-5 code
   only when none applies. The dedicated signer code of step 4 (invalid) stays where the
   kind's signer rule sits (§14.5) [S2-FIX1/Q3] decided (Inceptless decision 2026-11-15 #18;
   Q3).

The seven dedicated signer codes are: `E_KEY_DECLARED_NOT_SELF_SIGNED` (declared),
`E_KEY_ROTATION_SIGS` (rotated), `E_KEY_REVOKE_SIGNER` (revoked), `E_GRANT_GRANTER`
(`weave.grant` with `action == "grant"`), `E_GRANT_REVOKE_SIGNER` (`weave.grant` with
`action == "revoke"`), `E_ACTOR_KEY_TYPE_MISMATCH` (`weave.consent.granted` and
`weave.consent.revoked` with a non-human/organization signer), and `E_ERASE_ACTOR`
(`weave.erasure` with a disallowed signer).

Unknown-algorithm signature entries are ignored when deciding which of the steps above
applies (§3.6): an entry with an unknown `alg` is not a "known-algorithm signature", even
when the same `key` also has a verifiable signature elsewhere. A required-signature
obligation is satisfied only by an `ed25519` entry that verifies and whose signer satisfies
the kind's signer rule [S7④][Q13] decided (Inceptless decision 2026-11-11 #2; S7).

**Human-signature notice.** An `accepted` record that has no valid signature made by a key
declared `human` in the verification context is still valid and MUST carry the notice
`N_NO_HUMAN_SIGNATURE`; this is the report-side counterpart of the principle that human
keys sign human acts (§5.2) [M-15] decided (Inceptless decision 2026-11-10 #34; M-15②).
The notice is reported only for a record whose final verdict is `valid`: when the
required-signature check makes the record `unverifiable` (`E_KEY_UNKNOWN` or
`E_SIG_UNVERIFIABLE`, step 5) or when the record is invalid for any other reason, that
outcome is reported instead and the notice is not [S8⑭][S16/F6] decided (Inceptless
decision 2026-11-11 #2; S8/F6).

### 4.5 `weave.erased` placeholder — special shape

The `weave.erased` object is **not** a normal envelope. It is exactly:

```text
{"format":"weave-record/1","kind":"weave.erased","origin":{…},"id":"…","digest":"sha256:…","attestation":{…}}
```

The object has exactly the six members `format`, `kind`, `origin`, `id`, `digest` and
`attestation`, all required; it has no `stage`, no `actor`, no `sigs` and no `body`, and any
extra member is `E_ENV_UNKNOWN_FIELD`; a missing member is `E_ENV_MISSING_FIELD`. `origin`
and `id` have the same grammar and meaning as in a normal envelope. `digest` is the
**original record digest** of the erased record; it is a digest string (§2.7).
`attestation` is a reference object (§6.1) to a `weave.erasure` record.

The placeholder's own record digest — the value used for its file name and manifest entry —
is computed per §2.2 over the placeholder object itself; it is different from the `digest`
member it contains. The verdict for a placeholder record is `erased`, not `valid` [G3][Q15]
decided (Inceptless decision 2026-11-10 #34; Q15). Because this is a special shape rather
than a normal envelope, **every structural violation of the placeholder is
`E_KIND_BODY_SCHEMA`** — missing member, unknown extra member, wrong member type, or a
malformed `digest`/`attestation` format. `E_ENV_MISSING_FIELD` and `E_ENV_UNKNOWN_FIELD`
apply to the normal envelope only and are not used for `weave.erased` [Q15] decided
(Inceptless decision 2026-11-10 #34; Q15).

## 5. Actors, keys and authorisation

### 5.1 Key classes and actor compatibility

`weave.key.declared.body.key_type` is the key's class and is one of `human`, `agent`,
`program`, `device`, `organization`. `actor.type` **MUST** be compatible with the class of
`actor.key`: a key declared `human` may only be the actor key of records with `actor.type ==
"human"`, an `organization` key only of `organization` records, an `agent` key only of
`agent` records, and `program`/`device` likewise. A violation is
`E_ACTOR_KEY_TYPE_MISMATCH` (invalid) [E2][§8].

For ordinary (non-special) kinds, `actor.type` **MUST** additionally be compatible with
every signing key declared in the verification context, again with
`E_ACTOR_KEY_TYPE_MISMATCH`. For the seven kinds whose signer classes are constrained by
their kind pages (§7.2), additional signatures beyond `actor.key` are governed by the kind
page's explicit signer requirements: a kind page may explicitly permit or require a
counter-signature by a different key class (an owner co-signature on a key declaration, the
old and new key on a rotation, a human/organization signer on a revocation or erasure). The
kind page's explicit signer rules are authoritative for those signatures [Q30] decided
(Inceptless decision 2026-11-10 #34; Q30).

### 5.2 Human keys only sign human acts

Agent, program and device records **MUST NOT** be signed by a key declared `human` or
`organization`. In other words, a human key may only sign acceptance, authorisation,
consent and erasure acts performed as a human [§8.3]. For ordinary (non-special) records
this is implied by §5.1; it is additionally checked for every extra signature: a signature
by a human or organization key on a record whose `actor.type` is not `human` or
`organization` is `E_ACTOR_HUMAN_KEY` (invalid). The exception are the three key-lifecycle
kinds `weave.key.declared`, `weave.key.rotated` and `weave.key.revoked`: they are key
self-descriptions, and their kind pages permit owner/previous-key co-signatures, so an extra
human/organization signature on them is **not** `E_ACTOR_HUMAN_KEY` [Q30] decided
(Inceptless decision 2026-11-10 #34; Q30).

### 5.3 Key trust: roots come only from the local keyset

There is no certificate authority, no network lookup and no revocation distribution beyond
records in the verification context. Trust roots are supplied **only by the verifier's local
keyset input** (`--keys <dir>`, the E4 "local trust"): a `weave.key.declared` record in the
keyset whose `key_type` is `human` or `organization`, and which passes its own structural,
self-signature and validity checks, establishes that key as a **trusted human/organization
root**. Keyset declarations do not need a cosignature and never produce
`N_SELF_ATTESTED_ROOT_KEY`; the keyset **is** the local trust statement [E4][Q12][R2] decided
(Inceptless decision 2026-11-10 #42; R2). A keyset `weave.key.declared` record, **whatever
its `key_type`**, governs the class and validity window of its key id (see the
governing-class and governing-window definitions below); only the `human`/`organization`
ones establish trust roots, while an `agent`/`program`/`device` keyset declaration only
pins that key id's class and window (it does not make the key trusted) (T4).

**Governing class.** The **governing class** of a key id is decided **before** the trust
closure of this section and **independently of it**, from *structurally valid* declarations
only (the structural group of §14.1: canonical form, envelope structure, `sigs`
presence/format and registered-kind body schema — including a `weave.key.declared`
`body.public_key` that is present as strictly-encoded base64url decoding to exactly 32
bytes (V5); trust, self-signature verification and other semantic checks are not part of
it):

1. if the keyset contains a declaration for the key id, that declaration's `key_type` is the
   governing class (conflicting keyset declarations are a usage error, T4);
2. otherwise the structurally valid declaration with the smallest `(recorded_at, §2.2
   record digest)` pair among all declarations in the verification context governs — the
   deterministic declaration-resolution order defined below.

A declaration whose `body.public_key` is missing or is not strictly-encoded base64url
decoding to exactly 32 bytes is **not structurally valid** (V5): it never takes part in
class determination, so it cannot govern a class, and in a container or record target it is
reported invalid with `E_KEY_PUBLIC_KEY` (in the keyset a structurally invalid file is a
usage error, §14.1). Every structurally valid declaration for that key id whose `key_type`
differs from the governing class is invalid with `E_KEY_CLASS_CONFLICT`. Class determination does not depend
on which declarations become trusted, and an untrusted but structurally valid declaration can
still govern the class; the trust closure below then runs afterwards and independently, and
invalid declarations establish no trust (T4/U4).

**Example — class is not decided by closure order.** The keyset declares neither `org-1` nor
`human-2`, and the container carries three declarations: `D_o` declares `org-1` as
`organization` at T0, cosigned by `human-2`; `D_h` declares `org-1` as `human` at T1,
cosigned by `human-1` (a keyset root); `D_y` declares `human-2` as `human` at T2, cosigned
by `org-1`. A trust-closure-first reading would make `D_h` trusted first (its cosigner is a
root), then `D_y`, and only then would `D_o`'s cosignature become checkable — and which
declaration "wins" could depend on iteration order. Under this section `D_o` is the earliest
structurally valid declaration, so it governs: `org-1`'s governing class is `organization`,
`D_h` is invalid with `E_KEY_CLASS_CONFLICT` even though its cosignature becomes checkable
first, and `D_y` is class-consistent (it is handled by the trust closure like any other
declaration). The two readings differ on *which* record is invalid, not on whether a conflict
exists.

The `trusted` set is context-level state built from the keyset first and then closed over the
container/target declarations (an iterative fixed point, so a declaration may be trusted
through a chain of co-signatures). A keyset declaration that fails its own checks (bad
self-signature, inverted window, ...) establishes no trust, but it is not a usage error:
only a keyset file that is not a structurally valid record is one (§14.1). **Two
structurally valid keyset declarations for the same key id with a different `key_type` or a
different `(valid_from, valid_until)` pair — absent means unbounded, and present-versus-absent
counts as different — are a usage error (exit 2):** the operator must fix the keyset, and
no report is produced. When there is no such conflict, the keyset declaration is authoritative for the key's class
and window; context declarations never override it. A declaration in the container or in a record target is a
trust root only if its key is already in `trusted`:

- a `human`/`organization` declaration in the container/target is **valid** only when its
  key id is already trusted **with the same class** (`human` or `organization`), or when it
  carries at least one valid cosignature made by a `trusted` human/organization key; a valid
  declaration adds its key id to `trusted`. A declaration for a key id whose **governing
  class** (defined above) differs from the declaration's `key_type` is invalid with
  `E_KEY_CLASS_CONFLICT`. Same-class
  declarations of an already-trusted key are valid but never override the governing class
  or validity window: for a keyset key the keyset declaration governs, and a container
  declaration cannot extend the window or displace the keyset with a backdated
  `recorded_at` [S1] decided (Inceptless decision 2026-11-11 #2; S1);
- otherwise it is `unverifiable` with `E_KEY_UNTRUSTED`, and when its only signature is its
  own it also carries the notice `N_SELF_ATTESTED_ROOT_KEY`. An untrusted declaration
  **MUST NOT** make any other declaration invalid and MUST NOT become trusted;
- `agent`/`program`/`device` declarations require their owner to be in `trusted`
  (§9.1 rules 3–4); an owner that resolves but is not trusted makes the declaration
  `unverifiable` with `E_KEY_UNTRUSTED`.

With no `--keys` input there are no roots: every human/organization declaration in a
container or record target is untrusted (`E_KEY_UNTRUSTED`; plus
`N_SELF_ATTESTED_ROOT_KEY` when only self-signed), and an automated declaration whose owner
resolves but is not trusted is `E_KEY_UNTRUSTED` (an owner that cannot be resolved makes the
declaration `unverifiable` with `E_KEY_UNKNOWN`, §9.1 rule 3). There is **no** time-ordered root
selection: claimed `recorded_at` values never decide which declaration is a root; a backdated
self-signed declaration cannot become one [R2] decided (Inceptless decision 2026-11-10 #42;
R2). This closes the self-attested-root attack where a container could nominate its own root
by claiming an early time.

A public key can also be supplied as verification material by a valid `weave.key.rotated`
record in the context that explicitly lists it in `old_public_key`/`new_public_key`; that is
material, not a trust root. What is forbidden is inferring a key that no record states, by
walking an `old_key → new_key` chain (§9.2 rule 5) [M-12] decided (Inceptless decision
2026-11-10 #34; M-12). H0 does **not** implement pinning beyond the keyset input; the
verifier MUST NOT require any other local trust store. The verifier reports `N_KEY_TOFU` for
keys accepted through declarations in the context, so a human reader can see that trust came
from the context rather than from the local keyset [Q12] decided (Inceptless decision
2026-11-10 #34; Q12).

**Governing window and declaration resolution.** The validity window of a key id is
governed by the keyset declaration if the keyset declares the key id; otherwise by the
semantically valid context declaration with the smallest **declaration-resolution order**
pair `(claimed recorded_at, record digest)`. The same declaration-resolution order decides
which single declaration governs when several are eligible: smallest claimed `recorded_at`
first, ties broken by the lexicographically smallest §2.2 record digest. That order is
defined here once; §9.1, the kind pages and the registry refer to it. A keyset declaration
is never displaced by a container or record-target declaration, however early the latter's
claimed `recorded_at`: for a keyset key the keyset declaration governs the class and the
validity window, and context declarations cannot change either [S1] decided (Inceptless
decision 2026-11-11 #2; S1; T4). Declarations that are not themselves semantically valid
never govern the window or establish trust. For this purpose, and for the key material a
`weave.key.declared` or `weave.key.rotated` record supplies, a record is semantically valid
when it passes every check **other than** the §9.4 effects on the signature of its
**subject key** — the key the record states for itself: `body.key` of a declaration,
`body.new_key` of a rotation. §9.4 judges that signature for the record's own verdict
(§9.4, "Signatures of key-lifecycle records"), but a declaration of a key that is later
compromised, retired or outside its window still states that key's material, class and
window, so every signature the key makes is judged under that key's lifecycle rather than
becoming `E_KEY_UNKNOWN` [S2/F38] decided by principle (Inceptless decision 2026-11-15 #8;
S2). The exemption covers **only** that one signature. Every other signature of the record
— a declaration's owner cosignature or other cosignatures, a rotation's old-key signature —
counts only when it passes §9.4: a record in which such a signature fails §9.4 is not
semantically valid in this sense, so it supplies no key material (neither the subject key's
nor any other key's), governs no window and establishes no trust, and a signature by its
subject key is `unverifiable` `E_KEY_UNKNOWN` unless another record supplies that key. A key
whose signature does not pass §9.4 therefore never hands material or trust to another key;
in particular a rotation whose old-key signature fails §9.4 never supplies key material
(the previous-manifest link of §11.5 applies the stricter verdict rule of X5) [S2-FIX1/Q2] decided (Inceptless decision 2026-11-15 #18;
Q2). This is declaration resolution, not root selection [Q12] decided (Inceptless decision
2026-11-10 #34; Q12).

### 5.4 Agent authorisation: every agent record needs a covering grant

An agent's output is never self-authorised. Every record whose `actor.type` is `agent`
**MUST** cite a grant in `actor.grant` and that grant MUST cover the record, for **every**
stage, including `proposed` (decided (Inceptless decision 2026-11-10 #34; M-3): the decision
draft requires an agent to state "on whose behalf and under what authority" even for a
proposal). The envelope presence requirements are in §4.2; the semantic coverage checks are
evaluated in the order of this list, and the first failing check decides the code, so a
grantee or kind/action mismatch (invalid) is reported before the grant's window or
revocation state (unverifiable) [S2/F69] decided by principle (Inceptless decision 2026-11-15 #8; S2):

- `actor.grant` MUST resolve to a valid `weave.grant` record with `action == "grant"`
  (`E_GRANT_UNRESOLVED` → unverifiable when the target is not in the context; if it
  resolves to a record with `action == "revoke"` the code is `E_GRANT_GRANTER`, invalid).
  The two tiers of §5.5.2 step 1 apply to the cited grant: a cited grant record that is
  present but whose own verdict is invalid is `E_GRANT_GRANTER` (invalid); one that is
  present but not valid for any other reason is `E_GRANT_UNRESOLVED` (unverifiable)
  [S2-FIX2/U2] decided (Inceptless decision 2026-11-15 #22; Q6);
- the grant's `grant.grantee.key` MUST equal `actor.key` (`E_GRANT_GRANTEE_MISMATCH`,
  invalid);
- the grant's `grant.kinds` MUST contain the record's `kind`, and its `grant.actions` MUST
  contain the action mapped from the record's stage — `proposed → propose`,
  `accepted → accept`, `rejected → reject`, `withdrawn → withdraw`,
  `superseded → supersede`; otherwise `E_GRANT_NOT_APPLICABLE`, invalid;
- at the record's claimed `recorded_at` the grant MUST be inside its validity window
  (`valid_from <= recorded_at <= valid_until`, `null` meaning unbounded); otherwise
  `E_GRANT_EXPIRED` (unverifiable, including the not-yet-valid case);
- at that time the grant MUST NOT be revoked: a `weave.grant` revocation of this grant with
  `effective_at <= recorded_at` gives `E_GRANT_REVOKED` (unverifiable); the boundary
  belongs to revocation (equal counts as revoked);
- the whole grant chain, including all ancestors, is judged at the claimed `recorded_at`
  of the record being verified (and, when the record being verified is itself a
  `weave.grant`, at that grant's own claimed `recorded_at`), per §5.5.2 step 6
  [S3][M-3][Q11][Q13][R1] decided (Inceptless decision 2026-11-10 #34; #42/R1). The grant
  record being verified is not itself judged against its own validity window or its own
  revocation at that time — only its ancestors are — so an authorisation may be issued for
  future effect; a record covered by it is judged at that record's own `recorded_at`
  [S9] decided (Inceptless decision 2026-11-11 #2; S9).

A missing `actor.grant` member is an envelope error (`E_ENV_ACTOR_GRANT_MISSING`); a grant
that is present but unresolvable is `unverifiable`, a grant that is resolvable but wrong is
invalid. The not-yet-valid case and the split between invalid and unverifiable are part of
the ruling [Q11] decided (Inceptless decision 2026-11-10 #34; Q11).

**Idempotency.** `actor.idempotency_key` lets importers deduplicate agent actions: two
records with the same `origin` and the same `actor.idempotency_key` are claimed to be the
same action. A container containing such a pair is still valid, but the report carries the
notice `N_IDEMPOTENCY_DUPLICATE`; H0 does not define replay or deduplication semantics
beyond the notice [Q17] decided (Inceptless decision 2026-11-10 #34; Q17).

**Only agents carry delegated authority.** The envelope forbids `actor.grant` on
`human`, `program` and `device` actors (§4.2). The delegated-authority rules of this section
therefore apply exactly to `agent` actors; `program` and `device` records are not
grant-authorised through the envelope (their specific kinds may define their own
authorisation references, such as the erasure `basis` of `weave.erasure`).

### 5.5 Grants

A `weave.grant` record authorises a grantee key for a set of kinds and actions within a
validity window and a scope, and may be revoked. A grant is either a **root grant** (issued
by a human or organization key) or a **delegated sub-grant** (issued by an agent, program or
device key under a parent grant) [§8.2].

#### 5.5.1 `action: "grant"` body

The `grant` object is closed and has exactly these members:

| member | required | type | rule |
|---|---|---|---|
| `grantee` | yes | object | closed `{"key": <key id>}`; the authorised key |
| `kinds` | yes | array | 1–64 kind names (§7.1), unique |
| `actions` | yes | array | 1–7 unique strings from `propose`, `accept`, `reject`, `withdraw`, `supersede`, `erase`, `grant` |
| `scope` | yes | array | 1–32 strings, each 1–256 Unicode scalar values, unique; audit scope; compared as a set only for delegation subsetting (§5.5.2) |
| `valid_from` | yes | TS | start of the grant's validity window |
| `valid_until` | yes | TS or `null` | end of the window; `null` means unbounded |
| `transferable` | yes | boolean | whether the grantee may delegate this grant further; default policy is not transferable |
| `evidence` | yes | reference object or `null` | audit evidence; not machine-checked for authorisation |
| `remedy` | yes | string or `null` | audit remedy clause; not machine-checked for authorisation |
| `revocation` | no | array | 1–8 unique key ids allowed to revoke this grant; absent means the granter's `actor.key` and its explicit rotation successors (§5.5.4) |

`valid_from` MUST be less than or equal to `valid_until` when `valid_until` is not `null`
(`E_KEY_VALIDITY`, invalid). Unknown members inside the `grant` object are
`E_GRANT_SCHEMA`; unknown members at the `body` level are permitted (additive evolution,
§7.5). A `body` with `action` missing, with an unknown `action`, or with the wrong variant
member present or absent is `E_GRANT_SCHEMA` [Q10] decided (Inceptless decision
2026-11-10 #34; Q10).

The `revocation` field is the machine-readable "how to revoke" statement required by the
decision draft: the H0 mechanism is an explicit list of authorised revoker keys, defaulting
to the granter's own key (and its explicit rotation successors). No arbitrary
human/organization key can revoke someone else's grant [Q10][§8.2] decided (Inceptless
decision 2026-11-10 #34; Q10).

#### 5.5.2 Delegated sub-grant chain

A grant whose `actor.type` is `agent` is a delegated sub-grant; it MUST have
`actor.grant` referencing a parent grant. For a delegated `weave.grant` record the
parent-chain requirements of this subsection are the coverage requirement: the generic
agent stage/action coverage rule of §5.4 is not additionally applied, because a grant
record's own act is granting, not accepting [Q10] decided (Inceptless decision 2026-11-10
#34; Q10). A grant record whose `actor.type` is `program` or
`device` cannot be a delegated sub-grant: the envelope forbids `actor.grant` on those actor
types (§4.2), so such a grant can never cite a parent and is `unverifiable` with
`E_GRANT_UNRESOLVED`. This conservative reading of the envelope/delegation interaction is
PROVISIONAL (Appendix A P12). The parent chain is evaluated in the following order, and the
first failing check determines the error [S3][Q10] decided (Inceptless decision 2026-11-10
#34; S3/Q10); the exact precedence between the chain codes is an implementation shape
(PROVISIONAL, Appendix A P5):

1. **Resolve.** Step 1 has two tiers. If the parent reference resolves to a record that is
   **present but whose own verdict is invalid**, the parent is not an authorising grant: the
   sub-grant is invalid with `E_GRANT_GRANTER` (step 1 has no code of its own for this tier,
   so it takes the code of step 2, in the same shape as the two tiers of an erasure's
   authorising grant, [S2-FIX1/Q1]). If the parent reference cannot be resolved in the
   context, or resolves to a record whose own verdict is not `valid` for any other reason
   (for example `unverifiable`), the parent cannot be established: the sub-grant is
   `unverifiable` with `E_GRANT_UNRESOLVED` (T17/A-L5) [S2-FIX2/U2] decided (Inceptless decision 2026-11-15 #22; Q6).
2. **Authorising action and capability.** If the resolved parent's `action` is not `grant`
   (for example it is a revocation record), or its `kinds` does not contain `weave.grant`,
   or its `actions` does not contain `grant`, the parent does not authorise delegation of
   granting; the sub-grant is invalid with `E_GRANT_GRANTER`.
3. **Transferability.** If the parent's `transferable` is not `true`, the sub-grant is
   invalid with `E_GRANT_NOT_TRANSFERABLE`.
4. **Granter identity.** If the parent's `grant.grantee.key` is not the sub-grant's
   `actor.key`, the sub-grant is invalid with `E_GRANT_GRANTER`.
5. **No expansion.** The sub-grant MUST be a subset of the parent:
   - `kinds` of the child are a subset of the parent's `kinds`;
   - `actions` of the child are a subset of the parent's `actions` (this closes the
     privilege-escalation hole where a sub-grant could add `accept` or `erase`);
   - `scope` of the child is a subset of the parent's `scope`, compared as sets of strings;
   - the child's `valid_from` is greater than or equal to the parent's `valid_from`, and the
     child's `valid_until` is less than or equal to the parent's `valid_until` (`null` on
     the parent means unbounded; a `null` child under a bounded parent exceeds it).
   Any violation is `E_GRANT_DELEGATION_EXCEEDS` (invalid). The `scope` set-comparison is an
   implementation shape (PROVISIONAL, Appendix A P9).
6. **Chain validity at the verification time.** The entire chain — the cited grant and
   every ancestor — is judged at the claimed `recorded_at` of the record currently being
   verified. When the record being verified is itself a `weave.grant`, the chain is judged
   at that grant's own claimed `recorded_at` (it is the record being verified). At that
   time: a grant or ancestor revoked with `effective_at <= recorded_at` makes the chain
   `unverifiable` with `E_GRANT_REVOKED`; a grant or ancestor outside its validity window
   makes it `unverifiable` with `E_GRANT_EXPIRED`; the equality boundaries count as
   revoked. Any such failure anywhere in the chain makes the whole chain unverifiable.
   This rule replaces the earlier per-link evaluation time: there is one time for the whole
   chain, the verification time of the record, which is exactly the same time used for the
   directly cited grant [R1] decided (Inceptless decision 2026-11-10 #42; R1). Step 6 covers
   the entire chain up to its root, links beyond the depth bound of step 7 included, and it
   is decided before step 7: a chain that is both too deep and expired, or too deep with a
   revoked ancestor beyond the bound, reports `E_GRANT_EXPIRED` or `E_GRANT_REVOKED`, not
   `E_GRANT_UNRESOLVED`; this holds for a cited grant and for the ancestors of a grant record
   being verified [S2/F68] decided by principle (Inceptless decision 2026-11-15 #8; S2).
   Steps 1–5 are walked over the entire chain as well, links beyond the depth bound
   included: the walk goes from the cited grant up to its root, stopped only by cycle
   detection (a cycle is `E_GRANT_UNRESOLVED`), and step 7 is decided after it, so an
   invalid outcome of steps 2–5 on any link, or an unverifiable outcome of step 1 or 6, is
   reported instead of the depth code. The length of the walk is bounded by the number of
   records in the verification context (each grant is visited once). A step-2 to step-5
   failure on a link makes that link's child record itself invalid, and by the first tier of
   step 1 every record above it is then invalid `E_GRANT_GRANTER` (its parent is present but
   itself invalid); a failure beyond the bound therefore reaches a record that cites the
   chain as an invalid outcome at its first link, before the depth code of step 7, so an
   invalid link beyond the bound is never reported as the unverifiable `E_GRANT_UNRESOLVED`
   [S2-FIX1/Q5] decided (Inceptless decision 2026-11-15 #18; Q5) [S2-FIX2/U2] decided
   (Inceptless decision 2026-11-15 #22; Q6).

   When the record being verified is itself a `weave.grant`, its **own** validity window and
   its own revocation are not compared against its own `recorded_at`: the grant is the
   record being verified, its existence does not depend on the window it grants, and an
   authorisation may legitimately be issued for future effect. Only its ancestors are judged
   at that time. Records covered by the grant are judged at each covered record's own
   `recorded_at`, so a covered record before the grant's `valid_from` is still
   `E_GRANT_EXPIRED`. A grant **recorded after** its own validity window (a late-recorded or
   "backdated" grant) is likewise accepted: the grant record itself is judged only through
   its ancestors, and each covered record is judged at its own `recorded_at`, so a covered
   record after the grant's `valid_until` is `E_GRANT_EXPIRED` (T17/A-L4)
   [S9] decided (Inceptless decision 2026-11-11 #2; S9).
7. **Depth.** H0 does not support chains with more than 8 **links** (edges) from the grant
   used by a record up to its root: a chain of 9 or more links is `unverifiable` with
   `E_GRANT_UNRESOLVED`. The bound is inclusive of 8 links — the cited grant plus at most 8
   parent links — and it counts links, not records. When the record being verified is
   **itself** a `weave.grant`, its own link is not part of the chain: the record cites a
   parent P, and the chain counted is P → … → root. A delegated grant record that cites a
   depth-8 grant (8 links from P to the root) is therefore valid; a record whose cited
   grant needs a 9th link is `E_GRANT_UNRESOLVED` (T8). A
   cycle cannot occur in a conforming grant chain: each grant record is identified by a
   digest that covers its `actor.grant` reference, so mutual parent references are not
   constructible (the record-reference graph is a DAG). The bound is fixed by the ruling
   [S10] decided (Inceptless decision 2026-11-11 #2; S10).

#### 5.5.3 Record authorisation by a grant

The checks for a record whose `actor.type` is `agent` (and for any record that cites an
`actor.grant`) are in §5.4. `scope` is an audit and delegation-subset field; H0 does not
evaluate it for machine authorisation of an individual record (§5.6).

#### 5.5.4 `action: "revoke"` body and revocation authority

The `revoke` object is closed: `{"revokes": <reference object>, "effective_at": <TS>,
"reason": <string or null>}`. The reference MUST resolve to a `weave.grant` record with a
matching digest **and `action == "grant"`**; a target that is not an authorising grant (for
example another revocation record) is `E_GRANT_REVOKE_REF` (invalid). `effective_at <= recorded_at` is not
imposed on grant revocations; a future `effective_at` is a scheduled revocation.

The revocation record MUST be signed by an authorised revoker:

- if the target grant's `grant.revocation` list is present, by a key whose id is in that
  list;
- otherwise by the original granter's `actor.key`, or by an explicit rotation successor of
  that key (followed only through `weave.key.rotated` records that name the successor key
  explicitly, never by automatic inference, at most 8 rotation steps). The key-id graph can
  contain a cycle; a cycle means the signature cannot be proven to come from a rotation
  successor, and the revocation is invalid with `E_GRANT_REVOKE_SIGNER`. The walk is bounded
  and terminates; a successor reachable only through 9 or more rotation steps does not
  match [S10] decided (Inceptless decision 2026-11-11 #2; S10).

Otherwise `E_GRANT_REVOKE_SIGNER` (invalid). A revoker key that is not declared in the
context makes the revocation `unverifiable` with `E_KEY_UNKNOWN` rather than invalid. The
rotation-successor walk order within the bound is an implementation shape (PROVISIONAL,
Appendix A P4) [Q10][M-5][M-12] decided (Inceptless decision 2026-11-10 #34; Q10).

A grant-revocation record takes effect only if the revocation record is **itself valid**
(its verdict is `valid`): an invalid or unverifiable revocation record revokes nothing. This
is the conservative reading of the self-evidencing revocation model (§9.5): a broken
revocation cannot be used to disable an authorisation, and the broken record itself is
already reported [S10] decided (Inceptless decision 2026-11-11 #2; S10).

The revocation takes effect from `effective_at`; a record that uses the grant with
`recorded_at >= effective_at` is `unverifiable` (`E_GRANT_REVOKED`); with
`recorded_at < effective_at` it is unaffected. The boundary belongs to revocation [Q11][M-2]
decided (Inceptless decision 2026-11-10 #34; Q11).

### 5.6 What grants do not prove

Grants are claims by their signers; they authorise actions with respect to a specific
grantee key, kind and action set, within a window, and with a stated revocation path. The
verifier checks consistency and authorisation coverage, not the wisdom or truthfulness of
the grant. `scope`, `evidence` and `remedy` are recorded for audit and are not evaluated for
record-level authorisation in H0; `scope` participates only in the delegation subset check
of §5.5.2.

## 6. References

### 6.1 Reference object

Causality and provenance are expressed only through explicit references [F3]. A reference
object is a closed JSON object:

| member | required | rule |
|---|---|---|
| `origin` | yes | an origin object (§4.1); malformed → `E_ENV_REFS` |
| `id` | yes | same grammar and length as the envelope `id` (§4.1) |
| `digest` | yes | a digest string (§2.7) of the referenced record [B4] |
| `kind` | no | a kind name (§7.1); when present it is a claim about the referenced record's kind |
| `hints` | no | array of at most 8 URI strings, each at most 2048 UTF-8 bytes, each matching `^[A-Za-z][A-Za-z0-9+.-]*:[^\s]+$`; hints are never fetched and never carry identity [B2] |

A reference **MUST** carry the digest of the referenced record [B4]. A source system that
does not have a digest for an existing internal reference must compute one when exporting
(the export adapter's job) [B4][A1a]. Unknown members in a reference object are
`E_ENV_REFS`. URLs are only hints, never identity [B2].

In `refs[]` entries, the entry object is exactly `{"rel":<rel>,"ref":<reference object>}`;
duplicate entries are rejected (`E_ENV_REFS`). Two entries are duplicates when they repeat
an identical `(rel, ref)` pair.

### 6.2 `rel` — closed vocabulary

The `rel` member is one of the following closed set of ten relation words [Q7] decided
(Inceptless decision 2026-11-10 #34; Q7):

```
derived_from  handed_off_to  receipt_of    executed_as    assessed_by
compensated_by  migrated_from  reshaped_from  supersedes   correction_of
```

The first eight are the base vocabulary from Inceptless `provenance_edge`; `supersedes` and
`correction_of` are additions that correspond to the `stage` vocabulary (a superseding
record and a correction record). `erases` and `revokes` are **not** in the vocabulary:
erasure is expressed by the placeholder plus erasure attestation (§10), and revocation by
the kind bodies (key revocation and grant revocation), not by a relation word. Any other
`rel` value, including `erases` or `revokes`, is `E_ENV_REFS` (invalid). Additions require
the proposal process of §7.6 [K4].

**Direction.** Each `rel` word has a fixed direction: if record **A**'s `refs` array
contains `{"rel": R, "ref": <B>}`, the relation reads **"A R B"** — A is the subject and B
is the object. The direction is part of the meaning; putting the same two records on the
other side of the relation claims something different. The ten words read:

| rel | reading of "A rel B" |
|---|---|
| `derived_from` | A was derived from B |
| `handed_off_to` | A is the hand-off record and B is the record it hands the work over to |
| `receipt_of` | A is a receipt of B |
| `executed_as` | A is the record describing the execution, and B is the record it was executed as |
| `assessed_by` | A was assessed by B |
| `compensated_by` | A was compensated by B |
| `migrated_from` | A was migrated from B |
| `reshaped_from` | A was reshaped from B |
| `supersedes` | A supersedes B |
| `correction_of` | A corrects B |

For example a receipt record names its authorisation with `receipt_of` on the receipt side,
and a corrected record names the original with `correction_of` on the correcting record
[S15②] decided (Inceptless decision 2026-11-11 #2; S15).

**`stage: superseded` has no outbound relation.** The record that has been superseded does
not point at its successor with a `rel`; the **successor** record carries the
`supersedes` reference targeting the superseded record. The stage value records the
claimant's position, the `supersedes` reference records the link (T17/B-L6).

### 6.3 Resolution states — five states

Each reference is resolved against the verification context; the result is exactly one of:

| state | meaning |
|---|---|
| `found` | a record with the same `origin` and `id` and a matching `digest` is present and itself valid |
| `moved` | the referenced object was located at another location through its `hints` and its record digest matches the reference |
| `missing` | no record with that `origin` and `id` exists in the context |
| `erased` | a `weave.erased` placeholder with that `origin` and `id` exists whose `digest` member equals the reference digest |
| `unverifiable` | a record with that `origin` and `id` is present but its digest does not match the reference, or it is itself not valid, or the reference digest algorithm is unsupported, or the target record digest cannot be computed |

A record's identity is the triple `(origin.project, origin.instance, id)`. A record in the
context that parsed as JSON but failed a later check of its own (its envelope or its
`sigs`, for example) is still **present** when its own `origin` and `id` are well formed
(§4.1): a reference to it is `unverifiable` ("itself not valid"), not `missing`. A record
whose own `origin` or `id` is malformed has no identity, so it is never a candidate for any
reference: a reference whose target exists only in such a form is `missing`
[S2/F44/F58] decided by principle (Inceptless decision 2026-11-15 #8; S2).

The first four states follow Inceptless ADR 0026; the fifth is new [B5]. `moved` has the
decision-draft meaning: **location migration**, established through hints with a matching
digest. An offline verifier that does not fetch hints cannot establish a location migration,
so it MUST NOT report `moved`; a same-`origin`+`id` record whose digest differs from the
reference is `unverifiable` (with the notice `N_REF_UNVERIFIABLE`), never `moved`. `moved`
remains part of the format vocabulary for a context in which a hint resolves [B5][M-1]
decided (Inceptless decision 2026-11-10 #34; M-1).

`unverifiable` is not an error by itself: unresolved references are notices only
(`N_REF_MISSING`, `N_REF_MOVED`, `N_REF_UNVERIFIABLE`) and do **not** by themselves
invalidate a record, except where authorisation, consent or erasure rules say otherwise
(§5, §8, §10). A present `kind` that contradicts the resolved target's kind is
`E_REF_KIND_MISMATCH` (invalid) [B5].

**Exception — references resolved to `erased`.** A `weave.erased` placeholder does not
carry the erased record's original kind, so a `kind` claim on a reference that resolves to
`erased` cannot be checked: it is **not** a contradiction and is not reported as
`E_REF_KIND_MISMATCH`. This covers `refs[]` entries and the `weave.erasure.body.erased`
reference, whose `kind` SHOULD name the original erased record's kind (or be absent). Only
references to live records — including the placeholder's `attestation` reference, which
targets a live `weave.erasure` record — are checked for kind contradiction [Q32] decided
(Inceptless decision 2026-11-10 #34; Q32).

### 6.4 Deterministic resolution and dependencies

Reference resolution needs the target record's individual verdict, which can itself depend
on other records. The record-reference graph is acyclic **by construction**: a reference
carries the digest of its target, the digest covers the reference, and a digest-preimage
cycle cannot be produced. A conforming input therefore cannot contain a reference cycle; a
verifier does not need cycle-breaking for digest references [Q26] decided (Inceptless
decision 2026-11-10 #34; Q26).

A verifier **MUST** evaluate record dependencies deterministically and in bounded time: a
target that is individually invalid or unverifiable makes the reference `unverifiable`; for
a non-digest identity dependency that cannot be decided (the only H0 case is the key-id
graph of the revocation-successor rule, §5.5.4), the condition is `unverifiable` with
`N_REF_UNVERIFIABLE` where the rule does not give a more specific verdict. Any
deterministic terminating strategy is conforming — for example dependency-ordered
evaluation with memoisation, or a bounded fixed-point iteration that rebuilds key/grant
state from the records verified so far and re-attempts the rest — provided it produces the
same verdicts on the vectors. Container records are processed in manifest order, sorted by
digest (§11.2); a verifier MUST NOT make its verdict depend on filesystem enumeration order.

### 6.5 Reference digest algorithm agility

A reference digest with an unsupported algorithm resolves to `unverifiable`; it is not a
record error [B3][Q13] decided (Inceptless decision 2026-11-10 #34; Q13). Containers, by
contrast, must list record digests with an algorithm the format can verify (§11.2).

## 7. Registered kinds, the kind registry and unknown kinds

### 7.1 Kind name syntax

A kind name matches `^[a-z][a-z0-9]*(?:[.-][a-z][a-z0-9]*)*$`, is at most 128 bytes, and
is written as `<project>.<kind>` (for example `koinoweave.receipt`). A malformed kind name
is `E_ENV_KIND_SYNTAX`. The `weave.` namespace is reserved for kinds defined by this
specification; project kinds use their own namespace. A kind without a dot is syntactically
invalid (a kind name must have a project segment) [§2][§7].

### 7.2 The eight kinds registered by H0

Exactly these eight kinds are registered by version 0.1 of this specification; each has a
normative kind page in `spec/kinds/` and a JSON Schema in `schemas/kinds/`:

| kind | purpose | stage constraint |
|---|---|---|
| `weave.key.declared` | publish a public key, its class and its owner [E5] | `accepted` only |
| `weave.key.rotated` | bind an old key to a new key [E5] | `accepted` only |
| `weave.key.revoked` | announce key revocation and its effective time [E5] | `accepted` only |
| `weave.grant` | authorise a grantee key, or revoke a grant [§8.2][Q10] | `accepted` only |
| `weave.consent.granted` | record informed consent with purpose, scope and validity [H3] | `accepted` only |
| `weave.consent.revoked` | revoke a consent record [H3] | `accepted` only |
| `weave.erasure` | attest the erasure of a record, with reason and basis [G3a] | `accepted` only |
| `weave.erased` | placeholder standing in for an erased record (§4.5) [G3] | no stage; special shape |

All seven normal kinds in this table MUST use `stage == "accepted"` (other stages
`E_ENV_STAGE`) and MUST be signed per record (§4.4) [§4] decided (Inceptless decision
2026-11-10 #34). `weave.erased`
is the special non-envelope shape of §4.5 [G3][Q15]. Project-specific kinds (for example
`koinoweave.receipt`) are **not** registered by H0 [§2][A1a].

### 7.3 Unknown kinds are opaque but not understood

Any syntactically valid kind not registered in the version of this specification that a
verifier implements is **opaque but not understood** [K3]. For such a record a verifier:

1. **MUST** verify the envelope structure, references, signatures, labels and
   authorisation rules exactly as for a known kind;
2. **MUST NOT** validate the `body` and **MUST NOT** claim to understand it;
3. **MUST** report `kind_known: false`, and **MUST** report the notice
   `N_KIND_UNKNOWN_OPAQUE` when the record's final verdict is `valid` (the notice informs
   the reader about an accepted opaque record; a record that fails another check reports
   its errors instead) [S8⑩][S16/F12] decided (Inceptless decision 2026-11-11 #2; S8/F12);
4. **MUST NOT** mark the record invalid merely because the kind is unregistered.

An unknown kind is therefore verified for integrity and authorisation, not for meaning, and
it is never dropped from a container: it stays in the manifest, is digested, and is
transported verbatim [K3].

### 7.4 Reserved symbols and closed known members

Symbols reserved by a registered kind (for example the meaning of `weave.grant.action`) are
fixed by the kind page. Known members of each registered kind are closed as stated by the
kind page: an unknown value in a known-member position is the kind's body error. A verifier
**MUST** ignore body members it does not know and **MUST NOT** reject a record merely
because of an unknown body member at the `body` root (§7.5).

### 7.5 Body evolution is additive

`body` objects of registered kinds accept additional unknown members (additive evolution,
[K3]). Each known member has a fixed grammar and meaning; a verifier validates only the
known members it implements and is silent about unknown ones. This is the mechanism by which
the format lasts: a verifier never abandons older records [K3].

### 7.6 Kind registration process

A new kind (whether in the `weave.` namespace or a project namespace) is introduced by a
written proposal that specifies: the kind name; purpose; envelope constraints (stage, actor
type, mandatory signing); the `body` member table with types, closed vocabularies and error
codes; semantic rules (especially any cross-record rules); security considerations; a JSON
Schema; and test vectors. The proposal is approved under the change process of §0.3 [K4].
Kinds are registered by the specification repository, not by individual exporters;
exporters in project repositories may emit their own kinds before registration only as
opaque, namespace-owned kinds, and adapters remain the projects' responsibility [A1a][K4].

Registration is never retroactive in a way that abandons existing records: a kind page MUST
accept the body shapes that its project exported while the kind was opaque, because §7.5's
additive evolution is the mechanism by which old records stay verifiable [K3]. A change that
cannot meet that is a breaking change under §0.3, not a registration. The frozen regression
set (§16) pins the commitment: registering a kind MUST NOT change a conclusion fixed there
[T11; `docs/open-questions.md` §6 entry 16] decided by principle (Inceptless decision 2026-11-11 #5; T11).

### 7.7 Per-kind pages are normative

The normative rules for each registered kind — purpose, envelope requirements, body
members, semantic rules, error codes, canonical JSON examples and rationale — are in its
kind page under `spec/kinds/`. Those pages are part of this specification. This section
states only the registry-level rules that apply to all kinds. A record whose body violates
its kind's rules is `E_KIND_BODY_SCHEMA` unless the kind page names a more specific error
code.

## 8. Labels, consent and licence

### 8.1 `labels` (closed object)

`labels` is an optional, closed object:

| member | required | rule |
|---|---|---|
| `sensitivity` | no | one of `public`, `internal`, `personal`, `local-only`; any other value is `E_ENV_SENSITIVITY` [H1] |
| `licence` | no | an SPDX licence expression (syntax only, §8.7); malformed is `E_ENV_LICENCE` [H1][Q14] |
| `consent` | no | a reference object (§6.1) to a `weave.consent.*` record; malformed is `E_ENV_LABELS` [H1][H3] |

Unknown members of `labels` are `E_ENV_LABELS`. The absence of `sensitivity` is **not** a
structural error: `labels` may legitimately carry only `licence` or `consent` [Q29] decided
(Inceptless decision 2026-11-10 #34; Q29). Project-specific labels (a permission lattice,
markings, …) belong in `body` and **MUST** be mapped by the project to one of the four
sensitivity ranks; they never replace the four-rank vocabulary [H1].

### 8.2 Sensitivity rank

Sensitivity ranks are ordered `public` 0 < `internal` 1 < `personal` 2 < `local-only` 3.
`personal` includes any record containing personal data; `local-only` means the record
**MUST NOT** leave the machine or project boundary that created it.

### 8.3 Salt

A record whose `labels.sensitivity` is `personal` or `local-only` **MUST** carry a `salt`
member: exactly 16 random bytes in unpadded base64url (22 characters). The salt is included
in the record digest (§2.2) but is not otherwise interpreted by the verifier; the verifier
**MUST NOT** attempt to test randomness (impossible offline) and **MUST NOT** require a salt
for other records. The salt makes the original digest non-brute-forceable after the content
and salt are deleted on erasure [G3c][Q3] decided (Inceptless decision 2026-11-10 #34; Q3).

The salt is part of the record: the same record exported again **MUST** carry the same salt,
because a different salt is a different record with a different digest and would break every
existing reference to it. Persisting the salt per record and reusing it on every export is an
exporter requirement; a verifier cannot check it [S15③] decided (Inceptless decision
2026-11-11 #2; S15).

### 8.4 Label propagation — strictest wins

Labels propagate along every derivation relation and the strictest wins. For each resolved
reference whose `rel` is one of `derived_from`, `reshaped_from`, `migrated_from` or
`correction_of`, the referring record's sensitivity rank **MUST** be greater than or equal
to the target's sensitivity rank. If the referring record has no `labels.sensitivity` while
a resolved derivation input has a rank greater than 0, that is `E_LABEL_DOWNGRADE`
(invalid): absence cannot prove non-downgrade. A derivation reference that cannot be
resolved leaves propagation unchecked and is reported as the notice
`N_LABEL_PROPAGATION_UNCHECKED` (the record's verdict is unchanged by that notice alone).
The four-relation propagation set is fixed by the ruling [Q16][M-15] decided (Inceptless
decision 2026-11-10 #34; low-2). A missing sensitivity label on a record with **known
public** inputs is acceptable.

### 8.5 `local-only` must not be exported

A container is an export. Any record in a container whose sensitivity is `local-only` makes
the container invalid with `E_LABEL_LOCAL_ONLY_EXPORTED` (export refused); there is no
exception for agent-generated records and no override flag [H2]. A `local-only` record
verified as a **single record** (not inside a container) is not an export and does not
trigger this error; the export refusal applies to containers. Implementations should model
this after the "assert export may leave" check of the source projects.

### 8.6 Consent references and revocation

`labels.consent` is a reference to a consent record. The referenced record's kind **MUST**
be `weave.consent.granted` or `weave.consent.revoked`; resolving to any other kind is
`E_REF_KIND_MISMATCH` (invalid). An unresolvable consent reference produces the notice
`N_CONSENT_UNRESOLVED` and does not by itself change the record verdict [H1][H3].

A `weave.consent.granted` record whose `valid_until` is not `null` MUST satisfy
`valid_from <= valid_until` (`E_CONSENT_VALIDITY`, invalid). A `weave.consent.revoked`
record's `revokes` reference MUST resolve to a `weave.consent.granted` record;
otherwise it is `E_CONSENT_REVOKE_REF` (invalid) [H3].

Withdrawal is immediate [H3]: if the consent referred to by a record is revoked, then any
record whose claimed `recorded_at` is greater than or equal to the revocation's
`effective_at` is invalid with `E_CONSENT_REVOKED`. A record with
`recorded_at < effective_at` is unaffected (the boundary belongs to revocation). Revocation
is found both when the `consent` reference points directly at a `weave.consent.revoked`
record and when a `weave.consent.revoked` record in the context revokes the referenced
`weave.consent.granted` record [M-7] decided (Inceptless decision 2026-11-10 #34; M-7).
The revocation record's signer rules are in §8.6's kind page.

### 8.7 Licence expressions

`labels.licence` is an SPDX licence expression. Only syntax is checked offline; membership
in the SPDX License List is **not** checked and a verifier **MUST NOT** reject an unknown
identifier on membership grounds [Q14] decided (Inceptless decision 2026-11-10 #34; Q14).
The accepted syntax is the following grammar, with tokens separated by optional ASCII
whitespace:

```
expression := or_expression
or_expression := and_expression ( "OR" and_expression )*
and_expression := simple ( "AND" simple )*
simple := identifier ( "WITH" identifier )? | "(" expression ")"
identifier := [A-Za-z0-9][A-Za-z0-9.+-]*      # a trailing "+" suffix is part of the identifier
```

- identifiers begin with an ASCII letter or digit and continue with letters, digits, `.`,
  `+` or `-`; a trailing `+` suffix denotes "or later versions" as in SPDX;
- operators are the uppercase words `AND`, `OR`, `WITH`; lowercase operators are not
  accepted;
- `WITH` **MUST** appear only between two identifiers (a licence and an exception);
- parentheses **MAY** nest up to `MAX_LICENCE_NESTING` levels (§13), where the nesting depth
  is the number of `(` tokens on the deepest path through the expression (an expression
  without parentheses has depth 0); a deeper expression is `E_ENV_LICENCE`;
- the expression must be non-empty and fully consumed by the grammar;
- the verifier **MUST NOT** check that a licence or exception actually exists in the SPDX
  list; a syntax violation is `E_ENV_LICENCE`.

### 8.8 Labels are claims

Labels are claims attached to a signed record. A verifier checks consistency of the claims
(propagation, export refusal, consent revocation, syntax), not their truth: it cannot know
whether data really is personal, or whether a licence claim is legally correct. Reporting
must not imply otherwise [H1].

## 9. Key lifecycle and authorisation state

Key lifecycle is carried by records, so that keys can be exchanged, revoked and replaced
without a central CA [E4][E5]. The verifier builds state from records in the verification
context: key declarations (key id → class, owner, validity window), revocations (key id →
reason, effective time), rotations, grants, grant revocations, consents and erasures.

### 9.1 `weave.key.declared`

Publishes a key and binds it to its class and (for automated keys) its owner. `body` has
exactly these known members:

| member | required | type | rule |
|---|---|---|---|
| `algorithm` | yes | string | exactly `"ed25519"` |
| `key` | yes | key id | the declared key: `ed25519:` + 32 lowercase hex (§2.5) |
| `key_type` | yes | string | one of `human`, `agent`, `program`, `device`, `organization` |
| `public_key` | yes | string | 32 raw Ed25519 public-key bytes, strict unpadded base64url (43 characters) |
| `owner` | conditional | key id | the human/organization key that owns this key; **REQUIRED** when `key_type` is `agent`, `program` or `device`; optional otherwise |
| `valid_from` | no | TS | start of the claimed validity window |
| `valid_until` | no | TS | end of the claimed validity window |
| `note` | no | string | free-form note (not interpreted) |

Envelope: `actor.key` MUST equal `body.key`; `actor.type` MUST equal `body.key_type`
(§4.2, with the key-lifecycle exception for agent-only members). `sigs` MUST be present
(§4.4).

Semantic rules:

1. **Key-id derivation.** `body.key` MUST equal the §2.5 derivation from `public_key`; a
   mismatch is `E_KEY_ID_MISMATCH` (invalid). A `public_key` that is **missing** or is not
   strict unpadded base64url of exactly 32 bytes is `E_KEY_PUBLIC_KEY` (invalid). The
   missing-member case reports `E_KEY_PUBLIC_KEY`, not the generic body-schema code, and it
   is decided **before** `E_KIND_BODY_SCHEMA` and before any trust judgement
   [S8③] decided (Inceptless decision 2026-11-11 #2; S8③). A declaration does not
   check whether the 32 bytes decode to a curve point or whether the point is small-order
   or mixed-order: those checks happen at signature verification (§2.5, §3.4) [E3][S1]
   decided (Inceptless decision 2026-11-10 #34; S1/M-11).
2. **Self-signature.** At least one `sigs` entry MUST be a valid signature by the declared
   key over the record signature message; otherwise `E_KEY_DECLARED_NOT_SELF_SIGNED`
   (invalid) [E5]. Entries with an unknown algorithm are ignored for this obligation
   (§3.6); when a known-algorithm declared-key signature exists but is not by the declared
   key, the dedicated code `E_KEY_DECLARED_NOT_SELF_SIGNED` applies through the precedence
   of §4.4, not an availability code [S7④] decided (Inceptless decision 2026-11-11 #2; S7).
3. **Owner binding.** For `key_type` in `agent`, `program`, `device`, `body.owner` MUST be
   present and its declaration MUST resolve in the verification context, and that
   declaration's class MUST be `human` or `organization`. A missing owner is
   `E_KEY_OWNER_MISSING` (invalid); a resolving owner whose declaration class is not
   `human`/`organization` is also `E_KEY_OWNER_MISSING` (invalid) [R5] decided (Inceptless
   decision 2026-11-10 #42; R5); an owner that cannot be resolved makes the declaration
   `unverifiable` with `E_KEY_UNKNOWN`. The owner declaration itself does not have to be
   otherwise valid (it only identifies the owning principal), but the owner key must be in
   the trusted set (rule 4): an owner that resolves but is not trusted makes the declaration
   `unverifiable` with `E_KEY_UNTRUSTED` [R2] decided (Inceptless decision 2026-11-10 #42;
   R2).
4. **Cosignature and trust roots.** A declaration is trusted as follows:
   - **Keyset declarations (local trust input).** A `weave.key.declared` record supplied
     through `--keys` whose `key_type` is `human` or `organization` and which passes its own
     structural, self-signature and validity checks establishes its key as a trusted
     human/organization root. Keyset declarations need no cosignature and never produce
     `N_SELF_ATTESTED_ROOT_KEY`: the keyset is the verifier's local trust statement
     [E4][R2] decided (Inceptless decision 2026-11-10 #42; R2). Any keyset declaration,
     whatever its `key_type`, governs its key id's class and validity window; an
     `agent`/`program`/`device` keyset declaration only pins the class/window and does not
     establish trust (T4).
   - **Container/target human/organization declarations.** A declaration of class
     `human`/`organization` in a container or record target is valid only when its key id is
     already trusted **as the same class**, or when it carries at least one valid
     cosignature by a trusted human/organization key; a valid declaration adds its key id to
     the trusted set. A declaration whose key id already has a **governing class**
     (defined in §5.3, before and independently of this trust closure) that differs from the
     declaration's `key_type` is invalid with `E_KEY_CLASS_CONFLICT`; same-class
     declarations are valid but do not override the governing class or validity window.
     Otherwise it is `unverifiable`
     with `E_KEY_UNTRUSTED`, and when its only signature is its own it also carries
     `N_SELF_ATTESTED_ROOT_KEY`. An untrusted declaration MUST NOT make any other declaration
     invalid and MUST NOT become trusted. With no keyset there are no roots, so every
     container/target human/organization declaration is untrusted in this way
     [S1][R2] decided (Inceptless decision 2026-11-11 #2; S1; 2026-11-10 #42; R2).
   - **Automated declarations (`agent`, `program`, `device`).** At least one valid signature
     by the key named in `body.owner` is required; a missing or invalid owner cosignature is
     `E_KEY_DECLARED_NOT_COSIGNED` (invalid). The owner must be in the trusted set, else the
     declaration is `unverifiable` with `E_KEY_UNTRUSTED` [S4][Q33][R2] decided
     (Inceptless decision 2026-11-10 #42; R2).
   The trusted set is context-level state (keyset first, then an iterative closure over the
   container/target declarations); container declarations that are untrusted never remove a
   keyset root. The keyset is authoritative for the class and validity window of a key it
   declares, whatever the declaration's class: no container/target declaration can override
   either, and a backdated
   `recorded_at` never wins [S1] decided (Inceptless decision 2026-11-11 #2; S1). Two
   structurally valid keyset declarations for one key id with a different class or a
   different `(valid_from, valid_until)` pair are a usage error (exit 2, §14.1) (T4). Root
   selection is never time-ordered: claimed `recorded_at` values do not
   decide which declaration is a root, so a backdated self-signed declaration cannot become
   one [R2] decided (Inceptless decision 2026-11-10 #42; R2).
5. **Validity window.** When both `valid_from` and `valid_until` are present,
   `valid_from` MUST be less than or equal to `valid_until`; otherwise `E_KEY_VALIDITY`
   (invalid) [E5][Q20] decided (Inceptless decision 2026-11-10 #34; Q20).
6. **Effects.** Once a declaration is trusted, signatures by the declared key can be
   verified within its declaration's validity rules (§9.4). The governing class and the
   governing validity window of a key id, and the declaration-resolution order that picks
   among multiple declarations, are defined once in §5.3 (smallest claimed `recorded_at`,
   ties by the lexicographically smallest §2.2 record digest); that is declaration
   resolution, not root selection [Q12] decided (Inceptless decision 2026-11-10 #34; Q12;
   T4/U5/U12-L10).

A declaration is never a trust anchor by itself: roots come only from the verifier's local
keyset input, and a container-only declaration can at most extend existing local trust
(§5.3).

### 9.2 `weave.key.rotated`

Binds an old key to a new key; both keys sign, so the rotation is evidence that the old key
authorised the new one. `body` is closed: `new_key` (key id, required), `new_public_key`
(32 raw bytes base64url, required), `old_key` (key id, required), `old_public_key` (32 raw
bytes base64url, optional), `reason` (string, optional). Envelope: `actor.key` MUST equal
`body.old_key`; `actor.type` names the old key's class; `sigs` MUST contain valid
signatures by both the old and the new key (§4.4).

Semantic rules:

1. `old_key != new_key`; otherwise `E_KEY_ROTATION_KEYS` (invalid).
2. `new_public_key` and `old_public_key` MUST be strict unpadded base64url of exactly 32
   bytes, and a public key, when present, MUST match its key id (`"ed25519:" + first 32 hex
   of SHA-256(raw)`); a contradiction or malformed value is `E_KEY_ROTATION_KEYS`
   (invalid; this kind uses that code, not `E_KEY_PUBLIC_KEY`) [M-11] decided
   (Inceptless decision 2026-11-10 #34; M-11). This **structural** validation is part of
   the kind body check and runs before signature verification, so it wins over an `E_SIG_*`
   outcome (T13). Curve-point decoding failures during an actual signature check remain the
   §3.4 codes.
3. The new-key signature is verified against `body.new_public_key`; the old-key signature
   is verified against `body.old_public_key` when present, otherwise against the old key's
   declaration in context. If the needed key material is absent, the record is
   `unverifiable` (`E_KEY_UNKNOWN`). Missing either required signature is
   `E_KEY_ROTATION_SIGS` (invalid) [E5].
4. A rotation does not revoke the old key and does not automatically change the class of
   the new key; a separate declaration publishes the new key's class. A rotation to a key
   of a different class is not supported: the new key's signature must be compatible with
   `actor.type` under §5.1, so a cross-class rotation is invalid.
5. **Explicit key material, no chain inference.** The `old_public_key` and
   `new_public_key` members of a rotation record are **explicit declarations** of those two
   keys: they supply verification material for the rotation record itself and, as a material
   source, for any other record signed by those keys (§5.3). A verifier therefore never
   needs to traverse a rotation chain in order to verify a signature. What is forbidden is
   inferring a key that appears in no declaration and in no rotation record — for example
   following `old_key → new_key` links to fill in material for a key that is nowhere listed.
   Rotation-chain traversal is permitted only for the revocation-authority rule of §5.5.4
   [M-12] decided (Inceptless decision 2026-11-10 #34; M-12).

### 9.3 `weave.key.revoked`

Announces key revocation. `body` is closed: `effective_at` (TS, required), `key` (key id,
required), `reason` (one of `key-compromise`, `retired`, `other`, required), `note`
(string, optional). Envelope: `stage` MUST be `accepted`; `sigs` MUST be present; signer
requirements:

- `reason == "key-compromise"`: at least one valid signature by a key declared `human` or
  `organization` (`E_KEY_REVOKE_SIGNER` otherwise). The compromised key itself need not
  sign, and normally cannot safely sign.
- `reason == "retired"` or `"other"`: at least one valid signature by the revoked key
  itself, or by a key declared `human` or `organization` (`E_KEY_REVOKE_SIGNER`
  otherwise).

`effective_at` MUST be less than or equal to the revocation record's `recorded_at`
(`E_KEY_REVOKE_EFFECTIVE`, invalid) [E5]. The kind page's signer rules are authoritative
for counter-signatures (§5.1) [Q30] decided (Inceptless decision 2026-11-10 #34; Q30).

### 9.4 Effects of declarations and revocations

The verifier collects **every** valid revocation in the verification context, including
`weave.key.revoked` records supplied through the `--keys` keyset and records inside the
container. The effect is independent of record order and of whether a revocation sits in the
keyset or in the container [S2] decided (Inceptless decision 2026-11-11 #2; S2). The
`retired`/`other` family and the `key-compromise` family are evaluated **independently**;
neither overrides the other (T2):

1. **Retired/other family.** The signature is revoked if **any** valid `retired` or `other`
   revocation of the signing key has the **signature's claimed** `recorded_at` at or after
   the revocation's `effective_at` (`recorded_at >= effective_at`). The outcome is invalid
   `E_KEY_REVOKED`, and timestamp evidence **cannot** rescue it.
2. **Compromise family.** If **any** valid `key-compromise` revocation exists, the
   compromise rescue rule below applies with `T` = the **earliest** `effective_at` among the
   valid compromise revocations (the most conservative choice for rescue).
3. **Combination.** If the retired/other family applies, the result is invalid
   `E_KEY_REVOKED`; otherwise the compromise family outcome applies. The deterministic
   "stricter result" rule is: invalid beats unverifiable beats valid.

**Signatures of key-lifecycle records.** These effects apply to **every** signature, the
signatures of `weave.key.declared` and `weave.key.rotated` records included: a
declaration's self-signature and its cosignatures, and a rotation's old-key and new-key
signatures, are judged exactly like the signatures of any other record, although their key
material comes from the record's own body. So a declaration recorded before its own
`valid_from` is `E_KEY_EXPIRED`; a declaration whose owner cosignature is made by a key
retired at or before its `recorded_at` is `E_KEY_REVOKED`; and a declaration self-signed by
a key with a valid `key-compromise` revocation is rescued only by a verified, trusted and
usable receipt under the three cases below — a receipt that fails any check of §12.2, or
that is untrusted or unusable, cannot rescue it (case 2, `E_TS_UNTRUSTED`). This judgement
decides the record's verdict [S2/F38/F61-1] decided by principle (Inceptless decision
2026-11-15 #8; S2). Whether the record supplies key material, a class, a window and trust
is decided by §5.3: without the §9.4 effects on the subject key's own signature only, and
with them on every other signature, so a cosignature or an old-key signature that fails
§9.4 leaves the record without any of those [S2-FIX1/Q2] decided (Inceptless decision
2026-11-15 #18; Q2).

Let `T` be the claimed `effective_at` of a revocation of a key. Effects on signatures made
by that key (the signature's claimed `recorded_at`; for a manifest signature the manifest's
claimed `created_at`):

| reason | signature condition | outcome |
|---|---|---|
| `retired` (and `other`, treated as retired) | `recorded_at >= T` | invalid (`E_KEY_REVOKED`) |
| `retired` / `other` | `recorded_at < T` | unaffected |
| `key-compromise` | **always** | see the three cases below |

The `key-compromise` rule deliberately ignores `recorded_at`: claims of time are not
evidence, and a thief who holds the key can backdate a record. Only an external timestamp
over the manifest that contains the record, verified under §12, can establish that the
record existed before the compromise. For a signature by a compromised key there are
exactly three outcomes [S2][R3][R4] decided (Inceptless decision 2026-11-10 #42; R3/R4):

1. **Rescued (valid).** There exists at least one **verified, trusted** receipt (a receipt
   that passes every check of §12.2, including check 15 with a matching `--tsa-trust`
   anchor) for the manifest that contains the signature, whose timestamp plus accuracy is
   **strictly before** `T`:
   `genTime + accuracy < T`, evaluated at microsecond precision: microseconds are the unit
   of the comparison while `genTime` itself is only known to whole milliseconds. The
   comparison is
   `genTime_ms * 1000 + accuracy_us < T_ms * 1000`, where `genTime_ms` is the integer
   millisecond conversion of §12.2 check 13 — `genTime` is **truncated to whole
   milliseconds** before the comparison, and its sub-millisecond digits never affect it —
   and
   `accuracy_us` is the receipt's accuracy
   converted to integer microseconds (seconds × 10⁶ + milliseconds × 10³ + microseconds;
   an absent `accuracy` field means 0). Both conversions use checked fixed-width
   arithmetic. If a conversion overflows or the accuracy total exceeds `MAX_TS_ACCURACY`
   (§13), the receipt is **unusable evidence**, not a format error: it cannot rescue and
   cannot support an L2 claim, and case 2 applies (unverifiable `E_TS_UNTRUSTED`)
   [T3] decided (Inceptless decision 2026-11-11 #5; T3). Equality
   does **not** rescue: a receipt exactly at
   `T` (or later) proves only that the record existed at `T`, not before it.
2. **Present but untrusted or unusable (unverifiable).** Timestamp receipts are present,
   but none of them is verified, trusted and usable (for example the verifier was given no
   `--tsa-trust` anchor, or every receipt's accuracy is unusable per case 1). The missing
   information makes the record `unverifiable` with
   `E_TS_UNTRUSTED`; it is not reported as invalid. The same applies to a manifest
   signature judged on the manifest's timestamp chain, and to an L2 claim that relies on
   unusable receipts (§12.5).
3. **No rescue possible (invalid).** Either there is no timestamp evidence at all for the
   signature — a single-record target (no container and therefore no timestamp chain), a
   container that lists no receipts, or a claimed level below L2 — or the available
   evidence positively fails to rescue it: at least one receipt is verified, trusted and
   usable, and no verified trusted usable receipt satisfies `genTime + accuracy < T` (all of
   them place the signature at `T` or later). The record is invalid with `E_KEY_COMPROMISED`.
   If some receipts are trusted (failing the bound) and some are untrusted or unusable, the
   trusted usable evidence decides: the record is invalid.

A renewal chain does not weaken the rule: if any receipt in the chain satisfies the strict
`genTime + accuracy < T` bound under a trusted chain, the signature is rescued; otherwise
the outcome is case 2 or 3 as above. For a manifest signature the same test uses the
manifest's timestamp chain [S2] decided (Inceptless decision 2026-11-10 #34; S2).

Validity windows of declarations:

- a signature whose claimed `recorded_at` is later than the declared `valid_until` is
  `E_KEY_EXPIRED` (invalid);
- a signature whose claimed `recorded_at` is earlier than the declared `valid_from` is
  `E_KEY_EXPIRED` (invalid).

Both directions are one rule: a signature outside the declared window is invalid
[Q20][M-4] decided (Inceptless decision 2026-11-10 #34; Q20).

A signature by a key with no **trusted** declaration and no explicit rotation-record
material anywhere in the verification context is `unverifiable` (`E_KEY_UNKNOWN`): only
trusted declarations enter key state, so a declaration that exists but is untrusted does
not make its key usable, and signatures by it stay in the "key cannot be established"
bucket rather than becoming invalid; this applies to manifest signatures as well. The two
codes have different subjects: an untrusted **declaration** is itself `unverifiable` with
`E_KEY_UNTRUSTED`, while a **signature** by the key of an untrusted declaration is
`unverifiable` with `E_KEY_UNKNOWN` [E4][Q12][M-12][R2] decided (Inceptless decision
2026-11-10 #42; R2).
Multiple declarations for one key id are resolved as in §5.3 [Q12] decided (Inceptless
decision 2026-11-10 #34; Q12).

### 9.5 Revocation record validity and self-evidencing

A `weave.key.revoked` record takes effect only if it is **itself valid** (the same
principle as S10 for grant revocations). In particular, a revocation signed by a key that
was already revoked does not take effect (T9):

- When deciding whether a revocation record **R** is valid, evaluate its signatures against
  the key state produced by **prior** valid revocations, i.e. those ordered strictly before
  R by ascending `(recorded_at, record digest)`. R's own effect, and the effect of later
  records, is ignored for this judgement.
- A signature by a key already revoked at R's `recorded_at` is invalid (the §9.4 outcome,
  normally `E_KEY_REVOKED`), so **R is invalid and revokes nothing**; R still appears as an
  invalid record in the container, which makes the container invalid, while the key state it
  tried to change is unaffected.
- **Self-revocation exemption (limited).** The record revoking the very key that signed it
  is not invalidated by its **own** revocation, but that exemption only removes R's own
  effect from the prior set used to judge R: prior valid revocations of the signing key
  still apply. A key already revoked by an earlier-ordered valid revocation therefore
  cannot emit a new valid self-revocation — R's signature is itself revoked under §9.4, R
  is invalid, and R revokes nothing (U3).
- **Mutual revocations** therefore resolve deterministically: the earlier
  `(recorded_at, record digest)` revocation is valid and takes effect, the later one is
  invalid.

Likewise, a `weave.key.declared` record
that supplies its own key is verifiable from its own `public_key` even though it may be the
first time the key is seen in the context (self-declaration bootstrap) [E5][Q12]. A
revocation is a claim by the revoker; H0 does not attempt to establish when a compromise
actually happened beyond the timestamp evidence rule of §9.4 [T9] decided (Inceptless
decision 2026-11-11 #5; T9).

### 9.6 Grant revocation effects

A record that uses `actor.grant` G at claimed `recorded_at`, where a `weave.grant`
revocation record R revokes G with `R.revokes` resolving to G, `R.effective_at <=
recorded_at` and **R is itself valid**, is `unverifiable` (`E_GRANT_REVOKED`). An invalid or
unverifiable revocation record revokes nothing (§5.5.4), so it cannot disable the grant.
Records before `effective_at` are unaffected; the boundary belongs to revocation (equal
counts as revoked). A revoked or
expired grant therefore makes a new record unverifiable rather than invalid; a grantee,
kind or action mismatch is invalid [Q11][M-2][S10] decided (Inceptless decision 2026-11-11
#2; S10; 2026-11-10 #34; Q11).

### 9.7 Grant chains across records

Grants may delegate (root grant → delegated sub-grant → records using the sub-grant). The
verifier evaluates the chain as specified in §5.5.2 and §5.4: one verification time for the
whole chain, the claimed `recorded_at` of the record being verified (or of the grant itself
when a grant record is verified). When the verified record is itself a grant, its own window
and revocation are not compared against its own `recorded_at`; only its ancestors are
(§5.5.2 step 6, §9.4) [S9] decided (Inceptless decision 2026-11-11 #2; S9). An unresolvable
or invalid parent link makes the dependent grant unusable, and records using it
`unverifiable` (`E_GRANT_UNRESOLVED` or the specific chain error of §5.5.2). Grants are only
usable within their validity windows, and revocation as of the verification time makes them
unusable [R1] decided (Inceptless decision 2026-11-10 #42; R1).

### 9.8 Continuous chains are out of scope for H0

Continuous verification across a chain of many containers is outside H0. A verifier verifies
one container plus the immediately previous manifest bytes embedded in it (§11.5). Rollback
and truncation are detected only by the manifest chain plus external anchors (§11.5, §12),
and only to the extent the previous manifest is supplied [D2]. This is a declared
limitation, not a claim of complete history verification.

## 10. Erasure

### 10.1 The replacement shape

Erasure in an export works by replacing the erased record with the placeholder of §4.5.
References to the erased record resolve to `erased` when the placeholder's `digest` member
equals the reference's digest (§6.3). The placeholder keeps `origin` and `id` (so the
identity is still known) and keeps the **original record digest** (so references and the
digest chain remain meaningful), but no content, no salt and no signature of the original
record [G3]. The placeholder itself is digested and listed in the container manifest like
any record [G3].

### 10.2 The attestation record `weave.erasure`

The placeholder's `attestation` reference points to a `weave.erasure` record. `body` is
closed: `erased` (reference object, required), `reason` (required, one of
`data-subject-request`, `legal`, `safety`, `mistaken-inclusion`, `retention-expired`,
`other`), `reason_note` (string or `null`, required), `basis` (reference object or `null`,
required), `executed_at` (TS, optional). The record MUST be signed per record (§4.4) and
MUST use `stage == "accepted"`.

**Signer rules.** The erasure attestation may be executed by:

- a `human` or `organization` actor directly;
- an `agent` actor, only when `actor.grant` resolves to a valid grant covering kind
  `weave.erasure` and **both** actions `accept` (the generic agent stage action for an
  accepted record, §5.4) and `erase` (the kind-specific action);
- a `program` or `device` actor, only when `body.basis` resolves to a valid `weave.grant`
  covering the actor's key with action `erase`; automatic retention-expiry erasure
  (`reason == "retention-expired"`) is the intended case.

Any other combination is `E_ERASE_ACTOR` (invalid). Human keys remain bound by §5.2: a
human key signs human acts, not automated erasure. The widened signer set makes the
Tacitweave retention-expiry case (automatic discard recorded as an erasure) expressible
[G3a][G3d][M-10] decided (Inceptless decision 2026-11-10 #34; M-10).

### 10.3 Cross-checks in a container

When both the placeholder and its erasure record are present in a container, the three
rules below are evaluated independently and every violation is reported together, so a
container can carry `E_ERASE_DIGEST_MISMATCH`, `E_ERASE_ATTESTATION` and
`E_ERASE_CONTRADICTION` at once (§14.5: the failing stage reports every violation it finds).
A placeholder that fails its own §4.5 structure is an invalid record, not a placeholder, for
these rules [S2/F48] decided by principle (Inceptless decision 2026-11-15 #8; S2):

1. the erasure record's `erased` reference MUST resolve to a `weave.erased` placeholder in
   the same container with the same `origin` and `id` whose `digest` member equals
   `erasure.body.erased.digest`; a missing placeholder, an `origin`/`id` mismatch or a
   digest mismatch is `E_ERASE_DIGEST_MISMATCH`;
2. the placeholder's `attestation` reference MUST resolve to this erasure record; a
   missing or different target is `E_ERASE_ATTESTATION`;
3. the original live record MUST NOT also be present in the container; if a record with
   the same `origin` and `id` and computed digest equal to the placeholder's `digest` is
   present, that is `E_ERASE_CONTRADICTION`. Two placeholders for the same target are also
   `E_ERASE_CONTRADICTION` [G3][Q32] decided (Inceptless decision 2026-11-10 #34; Q32).

For a standalone `weave.erased` record target there is no container context: the verdict is
`erased` (exit code 0), the attestation reference is reported as unresolved (its state will
normally be `missing`), and the cross-checks of this subsection are not applied because
their inputs are absent; the verifier reports that limitation [G3][Q15] decided (Inceptless
decision 2026-11-10 #34; Q15).

### 10.4 Integrity argument for the erased entry (G3b)

The erased entry's integrity does **not** depend on the hash of the deleted content (there
is no content left to hash). It is proven by the combination of:

1. the **attestation record** — signed, stating the erasure and the original digest;
2. the **original digest** retained in the placeholder — so all existing references still
   resolve to `erased` and cannot be repurposed for different content;
3. the **container manifest and chain position** — the placeholder's own digest is listed
   in the signed manifest with its position claim, so a later substitution or deletion of
   the placeholder is detectable exactly like tampering with any other record.

A verifier **MUST NOT** require the deleted content, or a hash of it, to be present; it
**MUST** treat a correctly attested erased entry as an integrated part of the container. A
verifier **MUST NOT** report an erased record as invalid merely because its content is
absent [G3b].

### 10.5 Withdrawal is not erasure

Withdrawing a claim (changing one's judgement) only appends a new record; it never triggers
erasure. Erasure is for data that must stop being present (data-subject requests, legal
requirements, safety, mistaken inclusion, retention expiry), not for changing a position
[G3e].

### 10.6 Scope and limits of erasure

Erasure rules constrain **exports and references**. A project's internal storage may really
delete content; the minimum internal change is to retain "digest plus attestation record":
content can be deleted, the audit trail remains [A1b]. This specification does **not**
promise that already distributed copies can be recalled or deleted; it promises that an
erased record is visibly erased, references resolve to `erased`, and a container that
contains the live record plus a claim of erasure is rejected (§10.3) [A1b][G3].

### 10.7 Project guidance encoded as requirements on exporters

- Before deleting content for retention/limit reasons, an exporter MUST record the digest
  and append an erasure attestation with reason `retention-expired`; data must not silently
  disappear (the Tacitweave lesson) [G3d].
- A system that previously stored a digest of a record it now erases MUST replace the
  content with the digest-plus-placeholder form rather than removing the entry entirely
  [G4].

These are requirements on export adapters (project repositories), not on the verifier; the
verifier enforces the resulting shapes in containers.

## 11. Container format

### 11.1 Layout

A container is a directory, or the zip of that directory, with exactly this layout:

```
manifest.json
signatures/manifest.sig.json
signatures/timestamp-<n>.tsr          # L2 only; n is a decimal integer >= 1 with no leading zero
signatures/tsa-cert-<n>.pem           # optional; NEVER trusted on its own; same <n> form
previous/manifest.json                # required iff manifest.previous_manifest != null
records/<64 lowercase hex>.json
blobs/sha256/<64 lowercase hex>
readable/                             # optional; ignored entirely
```

All entries are ordinary files; the format depends on no database and no runtime [I1]. A
container with no `manifest.json` is `E_MANIFEST_MISSING` (invalid); a container with no
`signatures/manifest.sig.json` is `E_MANIFEST_UNSIGNED` (invalid) — the manifest signature
is required evidence, and its absence is the registry's "no signatures" condition
[S8②] decided (Inceptless decision 2026-11-11 #2; S8). Directories not listed
here, or unknown files inside a listed directory, are `E_CONTAINER_ENTRY` — with two special
cases: an extra file in `records/` is `E_MANIFEST_RECORD_EXTRA`, and an extra file in
`blobs/` is `E_MANIFEST_BLOB`. The `readable/` directory and anything below it is ignored
entirely: it is never parsed, never hashed, never decompressed in the zip form, its CRC is
never checked, it is never trusted, and it is never part of the manifest
[Q19][S16/F4] decided (Inceptless decision 2026-11-11 #2; S16/F4; 2026-11-10 #34; Q19). All
digested JSON files use the canonical file form (§1.8) and all files obey the size limits of
§13.

### 11.2 `manifest.json` (closed object)

The manifest is a canonical JSON object with these members; unknown members are
`E_MANIFEST_SCHEMA`:

| member | required | rule |
|---|---|---|
| `format` | yes | exactly `"weave-record/1"`; otherwise `E_MANIFEST_FORMAT` |
| `manifest_version` | yes | the integer `1`. A newer integer means a newer, unsupported manifest version (`E_MANIFEST_VERSION`); a future verifier must still accept version 1 [K3] |
| `origin` | yes | origin object (§4.1) of the **publisher of this container**; malformed → `E_MANIFEST_SCHEMA` |
| `created_at` | yes | TS (§2.8) of container creation; malformed → `E_MANIFEST_SCHEMA` |
| `level` | yes | `"L0"`, `"L1"` or `"L2"`; any other value → `E_MANIFEST_LEVEL` |
| `records` | yes | array of 1–100000 entries (§11.2.1), sorted by `digest` ascending, unique digests; violations `E_MANIFEST_RECORDS` |
| `previous_manifest` | yes | `null`, or exactly `{"digest":<digest string>}` (closed); malformed `E_MANIFEST_SCHEMA` |
| `chain` | conditional | for L0: absent or `null`; a non-null `chain` with `level == "L0"` is `E_MANIFEST_LEVEL` (invalid); for L1/L2: required exactly `{"algorithm":"sha256","head":<digest string>}`; missing or null → `E_MANIFEST_L1_NO_HEAD` |
| `blobs` | no | array of blobs (§11.7); absent means no blobs; malformed `E_MANIFEST_SCHEMA` |

The manifest's `origin` is the publisher of the container; records inside the container may
carry other origins (a container may transport records received from other systems), and
there is no requirement that record origins equal the manifest origin. The `chain` head and
positions are an internal-chain **claim** that an offline verifier cannot recompute (§11.4).

#### 11.2.1 `manifest.records[]` entries

Each entry is a closed object `{"id":<string>, "kind":<kind name>, "digest":<digest
string>, "chain_index":<integer>=0 optional}`:

- `id` and `kind` MUST have the same grammar as the envelope's `id` and `kind` (§4.1,
  §7.1), and MUST equal the values inside the record file they describe
  (`E_MANIFEST_RECORDS` on mismatch) [Q22] decided (Inceptless decision 2026-11-10 #34;
  Q22).
- `digest` MUST be the record digest of the referenced record (§2.2). For H0 it MUST be
  `sha256:<64 lowercase hex>`; an unsupported algorithm is `E_MANIFEST_RECORDS` (a
  container must list verifiable digests).
- entries MUST be sorted ascending by the `digest` string (UTF-16 code-unit order) and
  digests MUST be unique.
- `chain_index` is an integer greater than or equal to zero. It is required for L1/L2 and
  MUST be unique among entries there (missing/duplicate → `E_MANIFEST_L1_NO_POSITION`).
  For L0 entries it is optional and ignored when present.

There are 1–100,000 entries (`E_MANIFEST_RECORDS`). `manifest.records` order (sorted by
digest) is the deterministic order in which records are reported and processed.

### 11.3 `signatures/manifest.sig.json` (attestation file, closed object)

The manifest signature and timestamp inventory is a canonical JSON object with exactly these
members:

```text
{"digest":<digest string>, "format":"weave-record/1",
 "signatures":[{"alg":"ed25519","key":<key id>,"value":<base64url 64 bytes>}],
 "timestamps":[{"digest":<digest string>,"path":"signatures/timestamp-<n>.tsr","renews":<path>|null}]}
```

- `digest` MUST equal the §2.4 manifest digest of `manifest.json` (`E_MANIFEST_DIGEST`).
- `format` MUST be `"weave-record/1"` (`E_MANIFEST_SCHEMA`).
- `signatures` MUST contain 1–16 entries, sorted ascending by `key`, unique keys; each
  entry uses the `sigs` entry grammar of §4.3. Entries with an unknown `alg` are ignored
  for the manifest signature obligation, exactly as for record signatures, and an
  `ed25519` signature that does not verify is `E_MANIFEST_SIG_INVALID`. An empty array is
  `E_MANIFEST_UNSIGNED`; so is an absent attestation file (§11.1). If the array is non-empty
  but no entry is a verifiable signature by a declared required key, the manifest signature
  is `unverifiable`: `E_KEY_UNKNOWN`
  when the failure is caused by an undeclared signature key, otherwise
  `E_SIG_UNVERIFIABLE` [Q13][S8②] decided (Inceptless decision 2026-11-11 #2; S8;
  2026-11-10 #34; Q13). **Every** `ed25519` entry is checked, not only one: when several
  `ed25519` entries are present, an entry whose key is not a required key makes the manifest
  signature `unverifiable` (`E_KEY_UNKNOWN`) even if another entry verifies, and an entry
  that fails the equation is `E_MANIFEST_SIG_INVALID` even if another entry verifies
  [W10/L5; `docs/open-questions.md` §6 entry 27] decided by principle (Inceptless decision
  2026-11-11 #16; W10). Invalid beats unverifiable across the entries: every `ed25519`
  entry is judged, and the manifest signature is invalid when any entry of a required key
  is invalid, whatever the array order and even when another entry's key is undeclared —
  `E_MANIFEST_SIG_INVALID` when the entry fails the equation (step (5) decides this before
  any §9.4 effect), otherwise the §9.4 code (`E_KEY_REVOKED`, `E_KEY_COMPROMISED`,
  `E_KEY_EXPIRED`) when the §9.4 outcome of the entry's key at the manifest's `created_at`
  is invalid, reported where a single-entry manifest signature reports it; `E_KEY_UNKNOWN`
  is reported only when no entry is invalid in either way, and an entry whose §9.4 outcome
  is `unverifiable` (`E_TS_UNTRUSTED`) leaves `E_KEY_UNKNOWN` as the code. The
  first-failing-entry rule of W10 is withdrawn, so an invented key id that sorts first
  cannot turn a forged signature, or a signature by a retired or compromised key, into an
  unverifiable one [S2-FIX2/U5] decided by principle (Inceptless decision 2026-11-15 #22;
  as S2-FIX1 T2 for record signatures; the §9.4 half by Inceptless decision 2026-11-15
  #32). A **required key** for the manifest signature is a key that resolves
  in the verification context through a `weave.key.declared` or `weave.key.rotated` record;
  it does not have to be trusted for the cryptographic equation, which is evaluated before
  trust (§9.4). A **declared but untrusted** signing key therefore does not make the
  manifest signature unverifiable: only absent key material or an **undeclared** signature
  key produces `E_KEY_UNKNOWN`; the declaration's trust state is evaluated as for any other
  signature (§9.4, T17/A-L8). H0 does not additionally require the manifest signing key to equal
  `manifest.origin.instance`; that binding is a security consideration (§15) and the
  verification of that claim is left to the consumer [T11; `docs/open-questions.md` §6 entry 17] decided by
  principle (Inceptless decision 2026-11-11 #5; T11).
- `timestamps` MUST be present (possibly empty) [Q21] decided (Inceptless decision
  2026-11-10 #34; Q21). It is empty for L0/L1 (`E_MANIFEST_LEVEL` otherwise) and MUST
  contain at least one entry for L2 (`E_MANIFEST_L2_NO_TIMESTAMP`).
  Entries are closed objects, sorted ascending by `path`, with unique `path` values and
  unique `digest` values. Each `path` matches `signatures/timestamp-<n>.tsr` with `n` a decimal integer >= 1 and no leading zero; each
  `digest` is `sha256:<64 lowercase hex>` of the raw `.tsr` bytes. `renews` is `null` for
  the first receipt of the timestamp chain and otherwise the `path` of the immediately
  preceding receipt in the same chain (§12.4).

`signatures/manifest.sig.json` is not itself digested or signed, but follows the canonical
file form (§1.8) and the manifest signature is what makes the manifest digest and the
timestamp list trustworthy. Optional `tsa-cert-<n>.pem` files in `signatures/` are allowed
and are never trusted on their own (§12.3); every `.tsr` file in `signatures/` MUST appear
in `timestamps`, and every listed `.tsr` MUST exist and hash to its listed digest
(`E_TS_FILE`, invalid). An unlisted `.tsr` file is a failure of the file checks of the
timestamp phase (§12.2, complete check order, step 1), whatever the claimed level: the
container reports `E_TS_FILE`, every listed receipt (if any) is `invalid` with `gen_time`
`null`, and no receipt is decoded, so §9.4 sees no verified receipt
[S2/F54] decided by principle (Inceptless decision 2026-11-15 #8; S2).

### 11.4 Integrity levels and their reporting

The manifest MUST state its level [A1c]:

- **L0** — only the container signature taken at export time, intended for source systems
  with no internal hash chain. An L0 container proves that the manifest was signed by the
  holder of the signing key, that every listed record file has the listed digest, and that
  the records are consistent with the manifest at signing time.
- **L1** — L0 plus the head of the source system's internal hash chain and each record's
  position on that chain (`chain.head`, `chain_index`). L1 is a claim: an offline verifier
  cannot recompute an internal chain from exported records.
- **L2** — L0 plus a **renewal timestamp chain** over the manifest digest (§12). It is not
  a stronger form of L1: the internal chain head remains an unverified claim.

Report semantics: `level_claimed` reports the
manifest's claim; `level_verified` is **always** `"L0"` for H0 — no verifier may claim to
have verified L1 or L2 — and a separate boolean `anchor_verified` is true only when
`level_claimed == "L2"` and the whole timestamp chain verified with at least one trusted
anchor. `chain.status` is `"absent"` for L0 and `"unverified"` for L1/L2, with the notice
`N_CHAIN_CLAIM_UNVERIFIED`; a verifier MUST NOT claim to have verified the internal chain.
The record and container report field shapes are normative in §14.6; only the `vectors`
target per-case layout remains implementation-defined (Appendix A P7)
[S5][Q9] decided (Inceptless decision 2026-11-10 #34; S5/Q9).

### 11.5 Manifest chain continuity

- If `manifest.previous_manifest` is non-null, `previous/manifest.json` MUST exist. Its
  bytes MUST satisfy the canonical file form (§1.8) and parse as a manifest, its §2.4
  manifest digest MUST equal `previous_manifest.digest`, and its `format`/
  `manifest_version` MUST be supported. The file being missing is
  `E_MANIFEST_CHAIN_MISSING`; a non-canonical, unparseable, unsupported-version,
  depth-violating or digest-mismatching embedded manifest is `E_MANIFEST_CHAIN`. An
  embedded previous manifest **above `MAX_MANIFEST_BYTES`** is instead a container-level
  `E_JSON_SIZE` (invalid) detected at the previous-manifest-chain stage, with the
  already-processed record verdicts reported as usual (§13, §14.5, T16); it is a
  size-limit failure of a manifest-class file, not a chain inconsistency (T17/A-L7).
- The previous manifest's `origin` MUST equal the current manifest's `origin`: the chain
  records the history of one publisher. A different origin is `E_MANIFEST_CHAIN` (invalid)
  [M-8] decided (Inceptless decision 2026-11-10 #34; M-8).
- If `manifest.previous_manifest` is null, `previous/` MUST be absent or empty
  (`E_MANIFEST_CHAIN_UNEXPECTED`).
- The previous manifest's own signature is not re-verified by default: the chain is a chain
  over manifest digests. A verifier MAY additionally verify the previous signature when the
  keys are available and MUST report `N_PREVIOUS_SIG_UNVERIFIED` when it does not; the
  notice and the matching limitation (§14.9) are reported if and only if
  `previous_manifest` is non-null and the previous signature was not re-verified, including
  when a later container check fails; when the manifest cannot be parsed and the previous
  manifest is not reachable, neither is reported. **When a supplied `--previous` container's
  manifest signature verifies (§11.5), that previous manifest's signature counts as
  re-verified**, so neither `N_PREVIOUS_SIG_UNVERIFIED` nor `L_PREVIOUS_SIG_UNVERIFIED` is
  reported for it; the report carries `L_PREVIOUS_CONTENT_UNVERIFIED` instead (V3
  clarification) [D1] decided (Inceptless decision
  2026-11-11 #2; report-construction rule; T12; 2026-11-11 #14; V3).
- The `--previous <path>` command option accepts a container directory or its zip. A
  supplied previous container is used **only to link the chain**, not as further evidence:
  the verifier reads exactly two members from it — `manifest.json` and the manifest
  attestation file `signatures/manifest.sig.json` — each bounded by
  `MAX_MANIFEST_BYTES`, and verifies only what the link needs (V3). Everything else in the
  supplied previous container (records, blobs, `readable/`, extra files) is **not
  verified**; to verify a previous container as evidence, run it as a target container.
  Specifically:
  - the read manifest bytes MUST satisfy the canonical file form (§1.8) and parse as a
    manifest with a supported `format`/`manifest_version`, and its §2.4 manifest digest
    MUST equal the `digest` member of that attestation file;
  - **the previous manifest signature is verified in the target container's verification
    context (W1).** That context is the supplied keyset plus the records of the **target**
    container; the previous container's own records are never part of it and cannot supply
    key material or trust. The attestation file's `signatures` are judged exactly like the
    target manifest's (§11.3): `alg` values other than `ed25519` are ignored, at least one
    `ed25519` entry MUST be present, and **every** `ed25519` entry MUST satisfy all of:
    1. its key is a **required key** of the target verification context in the §11.3 sense
       (it resolves through a `weave.key.declared` or `weave.key.rotated` record of the
       keyset or of the target container), and the signature verifies over the §2.4
       manifest signature message with that key material — so a key rotated away since the
       previous container was exported still links when the target carries the rotation or
       the old declaration. The record verdicts are known at this step, and here the
       rotation's **verdict** decides: a `weave.key.rotated` record whose verdict is not
       `valid` supplies **no** key material, neither its `old_public_key` nor its
       `new_public_key` counts here [X5; decision 2026-11-12 #1]. This is stricter than the
       key-material rule of §5.3, which leaves out the §9.4 effects on the subject key's own
       signature (so a rotation that is invalid only through the §9.4 effects on its
       `new_key`'s signature still supplies material for the target's records, but not for
       this link); the wording is
       aligned with §5.3 without changing the rule [S2-FIX2/U6] decided by principle
       (Inceptless decision 2026-11-15 #22);
    2. its key is **trusted in the target's final trust closure** (§5.3): it has a valid
       `weave.key.declared` record in the target verification context (a keyset root; an
       `agent`/`program`/`device` declaration of the keyset that is trusted through its
       owner; or a context declaration admitted by the closure — for an
       `agent`/`program`/`device` key, one whose owner is trusted), or it is the `old_key`
       of a valid `weave.key.rotated` record of the target context that lists
       `old_public_key` and whose `new_key` has such a valid declaration. Explicit rotation
       material alone, without that trusted successor, does not make a key trusted here.
       Consequence: with no `--keys` input there is no trusted key, so a supplied
       `--previous` can never pass this rule and the container is `invalid`
       (`E_MANIFEST_CHAIN`), although the same container without `--previous` is only
       `unverifiable` for want of a trust root. This is kept deliberately: the operator asked
       for a link to be proved and it cannot be. A recipient that checks chain continuity
       should supply its keyset, and should supply as `--previous` only a container it has
       itself received and accepted earlier, never one taken from the same untrusted source
       as the target [S2-FIX1/T8] decided by principle (Inceptless decision 2026-11-15 #18);
    3. its key passes the §9.4 validity-window and revocation rules **at the previous
       manifest's claimed `created_at`**, evaluated with the target context's valid
       declarations and revocations: a validity window that excludes that instant breaks the
       link, and so does a revocation of the signing key — `retired`, `other` **or
       `key-compromise`** — whose effective time `T` is at or before it (`created_at >= T`;
       for several revocations of one family, the earliest `T`). A revocation whose `T` is
       after `created_at` does not affect the link. On this link a `key-compromise`
       revocation is judged by that same comparison, not by §9.4 case 3: the previous
       container's timestamp receipts are not read, but the previous manifest's digest is
       already pinned by the target's trusted manifest signature
       (`previous_manifest.digest`), so a compromise reported later cannot reach back into
       the history that signature pins [X2; `docs/open-questions.md` §6 entry 24] decided
       (Inceptless decision 2026-11-12 #1; X2).
    Any entry failing 1–3 is `E_MANIFEST_CHAIN` [W1; `docs/open-questions.md` §6 entry 24]
    decided (Inceptless decision 2026-11-11 #16; W1). When the material that verified the
    equation of an entry came from the context rather than the keyset, the check counts for
    the TOFU predicate of §14.9 like a target manifest signature, even if the entry then
    fails rule 2 or 3;
  - when comparing, the supplied previous manifest's §2.4 manifest digest MUST equal the
    current manifest's `previous_manifest.digest`;
  - in a **directory** previous, both member paths MUST be regular files: a symbolic link,
    a non-regular file or a missing member is `E_MANIFEST_CHAIN`; in a **zip** previous the
    archive MUST contain exactly one non-directory entry for each of the two paths, and a
    duplicate or missing member is `E_MANIFEST_CHAIN`. **Rules 1–4 of §11.9 and the §13
    limits apply to the framing of the whole previous archive, in the §11.9 order, exactly
    as for a target zip** (W2): local headers against the central directory, byte coverage,
    counts and single volume, and the entry classes of rule 4 (a directory entry or a DOS
    directory-attribute entry carrying data, an encrypted entry, an unsupported compression
    method) are checked for **every** entry, read or not. Only these rules are **not**
    applied to the members other than the two read ones, because those members are not
    verified: entry-name safety, duplicate names, CRC (the other members are never
    decompressed) and the `readable/` rules (V1, W2) decided (Inceptless decision
    2026-11-11 #16; W2);
  - a read, parse, canonical-form, digest, signature or structure/limit failure of the two
    members — including a `signatures/manifest.sig.json` that is not valid JSON or cannot be
    parsed — a `--previous` given when `previous_manifest` is `null`, and a supplied
    previous manifest digest that does not match are all `E_MANIFEST_CHAIN` (invalid), and
    the target container's record verdicts are reported as usual. A missing or unreadable
    supplied path is a usage or I/O error (exit 2, no report). A path that exists and is
    readable but is **not a usable container** — a non-zip plain file, or a directory
    without `manifest.json` — is `E_MANIFEST_CHAIN` as well (T17/A-L9).
  **Order inside the previous-manifest-chain stage (W5).** The stage runs only when the
  container pipeline reaches step (10) of §14.5; a container-level invalid error at an
  earlier stage stops the pipeline and the supplied previous is never read. When the stage
  runs and `--previous` was supplied, the supplied previous's identity is read and its
  signatures are verified **first**, whatever else fails in the stage; that outcome alone
  decides `L_PREVIOUS_CONTENT_UNVERIFIED` and the suppression of the
  `*_PREVIOUS_SIG_UNVERIFIED` pair. The stage then reports the **first** failing check of
  this order, and only that one: (a) an embedded `previous/manifest.json` above
  `MAX_MANIFEST_BYTES` (`E_JSON_SIZE`); (b) with `previous_manifest` null: an embedded
  previous manifest (`E_MANIFEST_CHAIN_UNEXPECTED`), then a supplied `--previous`
  (`E_MANIFEST_CHAIN`); (c) with `previous_manifest` non-null: a missing embedded manifest
  (`E_MANIFEST_CHAIN_MISSING`), then the embedded manifest's form, version, origin and
  digest (`E_MANIFEST_CHAIN`); (d) the supplied previous's own read, structure, digest or
  signature failure (`E_MANIFEST_CHAIN`); (e) the supplied digest comparison
  (`E_MANIFEST_CHAIN`) [W5; `docs/open-questions.md` §6 entry 25] decided (Inceptless
  decision 2026-11-11 #16; W5).
  **`L_PREVIOUS_CONTENT_UNVERIFIED` has one criterion (W5):** it is reported if and only if
  `--previous` was supplied, the stage ran, and the supplied previous's manifest signature
  was verified under the rules above; it is reported whether or not a later check of the
  stage (the digest comparison, the embedded manifest) then fails, and it is not reported
  when the stage did not run or the previous could not be read or verified
  ([S6][S16/F15][V3][W5] decided (Inceptless decision 2026-11-11 #2; S6/F15;
  2026-11-11 #14; V3; 2026-11-11 #16; W5)). A receipt side needs this check to detect an
  exporter silently restarting its chain.

The chain makes tampering with one container detectable in the next; it does not by itself
detect rollback or truncation — that requires an external anchor (§12) or the latest
container digest from an independent source [D2].

### 11.6 `records/` consistency

For every `manifest.records[]` entry:

1. the file `records/<hex>.json` MUST exist, where `<hex>` is the 64 lowercase hex
   characters of the entry digest (`E_MANIFEST_RECORD_MISSING`);
2. its bytes MUST satisfy the canonical file form (§1.8);
3. its §2.2 record digest MUST equal the digest in the entry and in the file name
   (`E_MANIFEST_RECORD_DIGEST`);
4. the record's `id` and `kind` MUST equal the entry's `id` and `kind`
   (`E_MANIFEST_RECORDS`) [Q22] decided (Inceptless decision 2026-11-10 #34; Q22);
5. every file in `records/` MUST be listed by an entry, and every file name MUST be
   `<64 lowercase hex>.json`; a file that is unlisted or has a malformed name is
   `E_MANIFEST_RECORD_EXTRA`.

The records are then verified per §14; a record that is individually invalid does not make
the container structurally inconsistent, but a container manifest listing a record whose
file is absent or whose digest mismatches is invalid.

### 11.7 Blobs

Attachments are content-addressed as `blobs/sha256/<64 lowercase hex>`. `manifest.blobs`,
when present, is an array of closed objects `{"digest":<digest string>,"size":<integer>=0}`,
sorted ascending by `digest`, unique digests. For H0 every blob digest MUST be
`sha256:<64 lowercase hex>` (the path convention only defines sha256) and every blob's
`size` MUST equal its byte length, at most `MAX_BLOB_BYTES`; at most 10,000 blobs. Every
`blobs/sha256/<hex>` file MUST be listed with matching sha256 and size, every listed blob
MUST exist, and a present `blobs/` directory MUST have a non-empty `manifest.blobs`
listing; all violations (including an unsupported blob digest algorithm) are
`E_MANIFEST_BLOB` [Q23] decided (Inceptless decision 2026-11-10 #34; Q23). Blob files are
not JSON and are not canonicalised; they are hashed as raw bytes.

### 11.8 `readable/`

`readable/` is an optional human-readable rendering directory. It is ignored entirely: not
parsed, not hashed, not decompressed in the zip form, its CRC is not checked, not trusted,
not listed in the manifest; it is never decompressed or CRC-checked in the zip form; in a
directory container its bytes are never read, stat-ed or counted toward the container total,
and in the zip form its **declared** uncompressed sizes are excluded from the declared-size
total (§13). Its presence or content never changes a
verdict; a verifier
MUST report the informational notice `N_READABLE_PRESENT` if and only if an enumerated
container contains a `readable/` entry, including when a later container check fails; if
entry enumeration itself fails before a `readable/` entry is observed, the notice is not
reported [Q19] decided (Inceptless decision 2026-11-11 #2; S16 report-construction rule;
2026-11-10 #34; Q19; T12). A zip archive that fails in phases 1–4 of the §11.9 check
order (its end-of-central-directory record or central directory cannot be read, a §13
limit, or another structural rule: `E_CONTAINER_ZIP` or `E_CONTAINER_SIZE`) has no
enumerated entries, because entries are enumerated by the entry checks that follow those
phases: the notice is not reported even when a `readable/` entry was listed in its central
directory. Once the phases have passed and the entries have been enumerated, the notice
follows the `readable/` entries that passed their own checks (T6), whatever fails
afterwards: an archive whose entry checks fail (`E_CONTAINER_ENTRY`), or one in which a
member then fails as it is read (a CRC-32 mismatch, a decompression failure, the
actual-size total of §13), still reports it. This narrows S2-FIX1's reading, under which
every `E_CONTAINER_ZIP` (a member CRC included) suppressed the notice [S2-FIX2/U7] decided
by principle (Inceptless decision 2026-11-15 #22). `readable` is a **directory** of the
layout: a regular file named `readable` at the container root (directory or zip form) is
not a `readable/` entry but an entry outside the layout, `E_CONTAINER_ENTRY` (invalid), and
it does not trigger the notice [S2-FIX1/T8] decided by principle (Inceptless decision
2026-11-15 #18).

### 11.9 Zip form

The zip form of a container contains exactly the same relative paths as the directory form,
with `/` separators. It MUST NOT contain absolute paths, `..` segments, duplicate entry
names, symbolic links, or entries that escape the root; per the closed registry these are
`E_CONTAINER_ENTRY` (layout and entry-safety violations), as are unknown files under
`signatures/` or `previous/`. Content layout problems keep their content codes
(`E_MANIFEST_*`).

The verifier parses the archive structure itself from the bytes; the verdict MUST NOT depend
on the behaviour of a standard-library zip reader, which differs between library versions.
The following structural rules are normative, and any violation is `E_CONTAINER_ZIP` unless
stated otherwise (T6):

1. **Local header versus central directory.** For each entry the local file header and the
   central-directory record MUST agree on the raw file-name bytes, the whole
   general-purpose flags word, the compression method, the CRC-32, the compressed size and
   the uncompressed size. When general-purpose flag bit 3 (data descriptor) is set, the
   local header's CRC-32 and both size fields **MUST be zero** (U12/L1), and the values in
   the data descriptor — which MAY be prefixed with the signature `PK\x07\x08` — MUST equal
   the central directory's values instead. Each entry's central-directory "version needed
   to extract" MUST be at most 63; the local-header version field is not constrained
   (V6).
2. **Every byte has a home.** The first local file header starts at offset 0; each entry's
   data followed by its data descriptor (when present) ends exactly where the next local
   file header begins, "next" meaning **physical offset order**; the central-directory order
   is free and need not match the physical order. The central directory begins immediately
   after the last entry in physical order. Gaps, pad bytes and overlapping ranges are
   rejected (U12/L3).
3. **Counts, framing and single volume.** The end-of-central-directory record carries
   **two** entry counts — "number of entries on this disk" and "total number of entries" —
   and both MUST equal the actually parsed entry count (U12/L4). When a ZIP64
   end-of-central-directory record is present, its entry counts MUST equal the actual count
   and the 16-bit EOCD count fields MAY be either the `0xFFFF` sentinel or the true count,
   accepted only when consistent with the ZIP64 record and the actual count; without a
   ZIP64 end-of-central-directory record the `0xFFFF` sentinel is `E_CONTAINER_ZIP` (the
   true count would not fit and a ZIP64 record is required), and any wrong non-sentinel
   value is `E_CONTAINER_ZIP` (U12/L5). The central directory's size and offset MUST equal
   the actually parsed values. Only **single-volume** archives are supported: the EOCD
   "number of this disk" and "number of the disk with the start of the central directory"
   MUST be 0; the ZIP64 EOCD's two disk-number fields MUST be 0; the ZIP64 locator's
   "number of the disk with the start of the ZIP64 EOCD" MUST be 0 and its "total number of
   disks" MUST be 1. Every per-entry central-directory "disk number start" field MUST be 0
   as well. Anything else is `E_CONTAINER_ZIP` (U9, V6). The end-of-central-directory
   record MUST have a zero-length comment and MUST end exactly at the last input byte; bytes
   before the first local header, a non-empty archive comment, and bytes after the record
   are rejected. ZIP64 archives MUST be accepted, including ZIP64 end-of-central-directory
   records, locators and extra fields; entry counts and declared sizes remain subject to
   §13 [S5].
4. **Entry classes.** Entries MAY be stored or deflated; directory entries (names ending
   `/`) with zero data are ignored. An entry whose name ends with `/` but carries data is
   `E_CONTAINER_ZIP`, with or without the DOS directory attribute; an entry carrying the DOS
   directory attribute but non-zero data is likewise `E_CONTAINER_ZIP` (U12/L6). Encrypted
   entries and unsupported compression methods are rejected [Q25]. This rule is checked for
   every entry, including `readable/` entries and the unread members of a supplied previous
   zip (W2).
5. **`readable/` entries.** They are not decompressed and the CRC over their data is not
   checked, but rule 1 still applies to them (the local header and the central directory
   must agree on name, flags, method, CRC-32 and sizes), and they still pass the
   path-safety, symbolic-link and duplicate-name checks of this section; a rule-1 violation
   is `E_CONTAINER_ZIP`, a path/type/duplicate violation is `E_CONTAINER_ENTRY` like any
   other entry (U12/L2, §11.8).

**Order of the zip checks (W7).** The archive is checked in exactly this order, and the
first phase that fails decides the code:

1. **Locate the end-of-central-directory record.** An EOCD record whose comment-length
   field makes it end exactly at the last input byte MUST exist (so bytes after the record
   fail here); when the EOCD uses a ZIP64 sentinel, the ZIP64 locator MUST be present and
   point at a well-formed ZIP64 EOCD record that ends exactly at the locator; the central
   directory MUST lie inside the file; and a non-empty archive MUST start with a local file
   header at offset 0 (so bytes before the first local header fail here). Failure:
   `E_CONTAINER_ZIP`.
2. **Parse the central directory.** Every central-directory record is framed: its
   signature, its fixed and variable-length parts inside the declared directory, the ZIP64
   extended-information field needed to read its sizes, a decodable name, and the records
   filling the declared directory size exactly (so the EOCD total entry count used for
   parsing equals the number of parsed records). Failure: `E_CONTAINER_ZIP`.
3. **The §13 limits.** The number of parsed entries above `MAX_CONTAINER_ENTRIES`
   (`readable/**` included) or the sum of the declared uncompressed sizes above
   `MAX_CONTAINER_UNCOMPRESSED_BYTES` (`readable/**` and directory entries excluded) is
   `E_CONTAINER_SIZE`, and **nothing after this phase is checked**.
4. **Every remaining structural rule** of this section: a non-empty archive comment; the
   single-volume disk-number fields, the second EOCD count and the EOCD/ZIP64 consistency
   of rule 3; per entry the "version needed to extract", the "disk number start", the
   compression method and the entry classes of rule 4; the local headers and data
   descriptors of rule 1; and the byte coverage of rule 2. Failure: `E_CONTAINER_ZIP`.

Only after these phases are entry paths, symbolic links and duplicate names judged
(`E_CONTAINER_ENTRY`) and is any content decompressed [W7] decided (Inceptless decision
2026-11-11 #16; W7). Rules 1–4 and this order apply to **every** entry of the archive and
to a supplied previous zip exactly as to a target zip (§11.5, W2). Each entry is then
decompressed under a bounded output cap; decompressed output MUST NOT exceed the declared
uncompressed size. **Decompression is a structural operation that never
crashes:** any failure while decompressing a member (a corrupt or malformed DEFLATE stream,
an unexpected end of stream, a decompressed size that contradicts the declared size) is a
structural failure of the container, reported as `E_CONTAINER_ZIP` for a target container
and as `E_MANIFEST_CHAIN` for a supplied previous container (§11.5), never as a process
crash. The target-container path and the previous-container path use the **same** member
reading and decompression rule (V1). The archive entry count above
`MAX_CONTAINER_ENTRIES` (`readable/**` included) and the declared-size total above
`MAX_CONTAINER_UNCOMPRESSED_BYTES` (`readable/**` excluded) are both invalid
`E_CONTAINER_SIZE`, never `E_CONTAINER_ZIP` [S4][T15][U2] decided (Inceptless decision
2026-11-11 #2; S4; 2026-11-11 #12; U2). These two limits are phase 3 of the order above:
an archive that is over a limit and violates a phase-4 rule reports `E_CONTAINER_SIZE`
only, while an archive whose EOCD cannot be located or whose central directory cannot be
parsed (phases 1–2, including bytes before the first local header or after the EOCD
record) reports `E_CONTAINER_ZIP` whatever its declared sizes (V7/L7, W7). A zip bomb is
bounded by the §13 limits (`E_CONTAINER_SIZE`), never a crash.

### 11.10 Encrypted export

Encryption, if used, MUST be applied after signing: the container is signed, then the whole
container is encrypted by an envelope defined outside this format. The receiver decrypts and
verifies the plaintext container exactly as in §11.1. An encryption envelope is not part of
`weave-record/1`; this specification defines no encrypted format [I3].

### 11.11 Import preserves received bytes

An importing system MUST store the received `weave-record/1` bytes unchanged. It MAY project
them into its own internal format for use, but it MUST NOT replace the original with a
re-hashed or re-serialised copy; the received bytes are the evidence [D4][A1d]. This is a
requirement on importers (project adapters), not on the verifier.

## 12. Integrity levels and RFC 3161 timestamps

### 12.1 Levels and report semantics

The manifest's `level` is a claim (§11.4). L0 and L1 need no external data. L2 requires a
complete, verified RFC 3161 timestamp chain over the manifest digest. A verifier MUST NOT
claim a level it did not verify and MUST NOT claim L2 solely because `.tsr` files exist
[A1c][D3][S5]. For L2 the report states the honest outcome: `level_verified` remains
`"L0"` and `anchor_verified` reports whether the timestamp chain verified against a
supplied trust anchor (§12.5) [S5] decided (Inceptless decision 2026-11-10 #34; S5).

### 12.2 RFC 3161 timestamp verification profile

Each listed receipt is verified against the following MUST table; the code of the first
failing check is reported [S5] decided (Inceptless decision 2026-11-10 #34; S5). **Any DER
decoding or receipt-structure failure, wherever it is discovered** — including a failure
while re-encoding `signed_attrs` for signature verification — is reported as check 1's
`E_TS_SCHEMA`, never as a crash and never as a later check's code (V2).

| # | check | code on failure |
|---|---|---|
| 1 | The file is **exactly one** strict-DER-encoded RFC 3161 `TimeStampResp` with no trailing data, decoded completely before any later check (sub-steps 1a–1e below): the whole file decodes as one `TimeStampResp`, the encoding uses canonical minimal length forms (no BER indefinite form) and **re-encoding the parsed object yields the input bytes exactly** — every SET OF at every level in DER order, no DEFAULT value encoded. `PKIStatusInfo.status` is `0` (`granted`); `grantedWithMods` (1) and every other status are rejected. The token is CMS `SignedData`; `SignedData.version` is 3, it carries **exactly one** `SignerInfo`, and its `SignerInfo.version` is 1 or 3; any other version is rejected. The signer certificate carried in `SignedData.certificates` decodes as an X.509 certificate. | `E_TS_SCHEMA` |
| 2 | The `SignedData` content type is `id-ct-TSTInfo`, and the encapsulated TSTInfo parses as DER with `version == 1` (TSTInfo version is exactly 1; any other value is `E_TS_SCHEMA`). | `E_TS_SCHEMA` |
| 3 | `messageImprint.hashAlgorithm` is `sha256`; any other algorithm is a schema failure. | `E_TS_SCHEMA` |
| 4 | `messageImprint.hashedMessage` equals the expected imprint (§12.4): the raw 32 bytes of the manifest digest for the first receipt, or `SHA-256(<previous receipt bytes> ‖ <raw manifest digest>)` for a renewal receipt. | `E_TS_IMPRINT` |
| 5 | `signerInfo.digestAlgorithm` is `sha256`. | `E_TS_SCHEMA` |
| 6 | The signature algorithm is on the allowlist: RSA PKCS#1 v1.5 with SHA-256, SHA-384 or SHA-512, or ECDSA with SHA-256 or SHA-384. RSA-PSS and every other algorithm are rejected. | `E_TS_CERT` |
| 7 | The signer certificate is included in the token's `SignedData.certificates` (a receipt whose token does not carry its signer certificate is rejected even if `--tsa-trust` contains that certificate). | `E_TS_CMS` |
| 8 | The signed attributes carry ESS `signingCertificateV2` matching the signer certificate. A v1-only `signingCertificate` or a missing ESS attribute is rejected. | `E_TS_CMS` |
| 9 | The signed attributes' `messageDigest` equals `SHA-256(eContent)`. | `E_TS_CMS` |
| 10 | The CMS signature verifies over `DER(SET OF SignedAttributes)` with the signer certificate's public key, within these bounds: an RSA key has a modulus of 2,048 to 8,192 bits and an odd public exponent `e` with 65,537 ≤ `e` < 2^256; an ECDSA signature value (`Ecdsa-Sig-Value`, RFC 5480 / RFC 5758) is one DER SEQUENCE of exactly two INTEGERs `r` and `s`, each positive and in its shortest encoding, each in [1, `n` − 1] for the order `n` of the key's curve, with no octet after the SEQUENCE. A key or signature outside these bounds fails the check like a signature that does not verify [S2-FIX1/Q4] decided (Inceptless decision 2026-11-15 #18; Q4). | `E_TS_CMS` |
| 11 | The signer certificate has the `id-kp-timeStamping` extended key usage; if a KeyUsage extension is present it contains `digitalSignature`. | `E_TS_CERT` |
| 12 | The signer certificate's validity window contains `genTime` (not the current wall clock). | `E_TS_CERT` |
| 13 | `genTime` is a valid GeneralizedTime and is converted to an integer number of milliseconds since the Unix epoch by truncating (flooring) any sub-millisecond digits. If the TSTInfo carries an `accuracy` field: `seconds`, when present, is a non-negative integer; `milliseconds` and `microseconds`, when present and explicitly encoded, are integers in 1–999; an absent component counts as 0. Malformed DER, a present component outside 1–999 (an explicit `0` included), negative or non-integer components are **format errors** → `E_TS_SCHEMA`. The components are converted to integer microseconds (`seconds × 10⁶ + milliseconds × 10³ + microseconds`) with **checked fixed-width arithmetic**; an absent `accuracy` field means `accuracy_us = 0`. A total above `MAX_TS_ACCURACY` (§13) or an arithmetic overflow in the conversion is **not** a format error: the receipt is **unusable evidence** (see below). Both values are retained for the §9.4 compromise rule. | `E_TS_SCHEMA` (format errors) / `E_TS_UNTRUSTED` (unusable-accuracy sub-case, unverifiable) |
| 14 | The `timestamps[]` array of the attestation file forms exactly one renewal chain (§12.4): exactly one receipt with `renews == null`; every other `renews` names a listed, earlier receipt; no duplicate paths, no gaps, no second chain. | `E_TS_RENEWAL` |
| 15 | The receipt is trusted under §12.3. | `E_TS_UNTRUSTED` (unverifiable) |

**Check 1 in detail (W3).** Check 1 is evaluated as five sub-steps, all reporting
`E_TS_SCHEMA`, and every one of them completes before check 2 starts, so a decoding or
structure failure anywhere in the receipt is never reported under a later check's code:

- **1a — universal DER rules.** The bytes are one TLV with no trailing data; every length
  is definite and minimal; tag numbers 0–30 use the single-octet identifier and larger ones
  the high-tag-number form of X.690 §8.1.2.4, read in base 128, whose **first** subsequent
  octet is not `0x80` (later subsequent octets may be `0x80` or `0x00`: `5f 81 80 00` is
  the minimal form of `[APPLICATION 16384]`; the number of subsequent octets is not
  limited); no universal primitive type
  (BOOLEAN, INTEGER, BIT STRING, OCTET STRING, NULL, OBJECT IDENTIFIER, the string and
  time types) uses the constructed form; BOOLEAN is `0x00` or `0xFF`; INTEGER has no
  redundant leading `0x00`/`0xFF` octet; a BIT STRING's unused-bit count is 0–7 (0 when
  it has no content octets) and its unused bits are zero; NULL is empty; OBJECT IDENTIFIER sub-identifiers are minimal; a UTF8String is
  well-formed UTF-8 without an escape sequence; UTCTime is `YYMMDDHHMMSSZ` and GeneralizedTime is `YYYYMMDDHHMMSS`,
  optionally followed by `.` and one or more fractional digits whose last digit is not `0`,
  then `Z` (X.690 §11.7–§11.8: any number of fractional digits, no trailing zero, no empty
  fraction), each form matched against the **whole** content octets, so a trailing line
  feed or any other octet after the `Z` is a violation [X7] decided (Inceptless decision
  2026-11-12 #3; X7/H1); and the components
  of every universal SET are in ascending DER order (X.690 §11.6). These rules apply to
  every TLV of the file, including values whose type is not known to the verifier (an
  unregistered attribute's value, for example): every universal SET in the
  `TimeStampResp`, CMS and X.509 schemas is a SET OF, so a universal SET of unknown type is
  checked as a SET OF [W3; `docs/open-questions.md` §6 entry 29]. Three further X.690 rules
  apply to every TLV in the same way: universal tag number 0 never occurs (it is reserved
  for the end-of-contents octets of the indefinite form, X.690 §8.1.5, which DER forbids),
  whatever its length; ENUMERATED is encoded as an INTEGER (X.690 §8.4), so it has no
  redundant leading `0x00`/`0xFF` octet; and EXTERNAL (8), EMBEDDED PDV (11) and the
  unrestricted CHARACTER STRING (29) are SEQUENCE-based types that use the constructed form
  only (X.690 §8.18, §8.17, §8.24; the S2 text cited §8.19 and §8.21, corrected by S2-FIX1), so their primitive form is a violation while their
  constructed form is judged by its framing [S2/F57/F66] decided by principle (Inceptless
  decision 2026-11-15 #8; S2). The list is **not** closed: 1a is X.690 (clauses 8, 10 and
  11) for every universal tag number, as the registry's `E_TS_SCHEMA` row says ("a universal
  DER rule violated anywhere in the file"). By universal tag number:
  - **0** — never occurs (§8.1.5).
  - **1 BOOLEAN** — primitive; one content octet, `0x00` or `0xFF` (§8.2, §11.1).
  - **2 INTEGER, 10 ENUMERATED** — primitive; at least one content octet, two's complement
    in the fewest octets (§8.3, §8.4).
  - **3 BIT STRING** — primitive (§10.2); the unused-bit rules above (§8.6.2, §11.2).
  - **4 OCTET STRING** — primitive (§10.2).
  - **5 NULL** — primitive; no content octets (§8.8).
  - **6 OBJECT IDENTIFIER** — primitive; at least one sub-identifier, each in the fewest
    octets (leading octet not `0x80`) and complete (its last octet has bit 8 clear)
    (§8.19).
  - **7 ObjectDescriptor** — a GraphicString: primitive (§10.2) and an ISO 2022 register
    type (see 20 below).
  - **8 EXTERNAL, 11 EMBEDDED PDV, 29 CHARACTER STRING** — constructed only; framing
    (§8.18, §8.17, §8.24).
  - **9 REAL** — primitive (§8.5.1). Plus zero has no content octets (§8.5.2). The first
    content octet selects the form (§8.5.6). Binary (bit 8 set): base 2 (bits 6–5 `00`),
    scaling factor 0 (bits 4–3 `00`), and the exponent and the mantissa each in the fewest
    octets (§11.3.1): the exponent is two's complement without a redundant leading `0x00`
    or `0xFF` octet, written with format `00`, `01` or `10` for one to three octets and
    with format `11` (a length octet, §8.5.7.4 d) only for four or more octets; the
    mantissa N is non-empty, has no leading `0x00` octet and is odd. Decimal (bits 8–7
    `00`): only the NR3 form (bits 6–1 `000011`, §11.3.2.1), its text matching
    `-?[1-9]([0-9]*[1-9])?.E(+0|-?[1-9][0-9]*)` — no SPACE, a MINUS SIGN only for a negative
    value, neither the first nor the last mantissa digit `0`, the mantissa immediately
    followed by `.E`, the exponent `+0` or without PLUS SIGN or leading zero (§11.3.2.2–6).
    Special values (bits 8–7 `01`): exactly one content octet, `0x40`–`0x43` (§8.5.9);
    the other values are reserved.
  - **12 UTF8String** — primitive (§10.2); well-formed UTF-8 that contains no ESC (`0x1B`)
    octet: §8.23.10 allows no escape sequence in a UTF8String.
  - **13 RELATIVE-OID** — primitive; at least one sub-identifier, each in the fewest octets
    and complete, as for 6 (§8.20).
  - **14 TIME, 34 DURATION, 31 DATE, 32 TIME-OF-DAY, 33 DATE-TIME, 35 OID-IRI,
    36 RELATIVE-OID-IRI** — rejected wherever they occur. The DER form of TIME and DURATION
    is the canonical value notation of §11.9, which needs an ISO 8601 interval and duration
    parser that this profile does not define; the contents of DATE, TIME-OF-DAY and
    DATE-TIME (§8.26) and of OID-IRI and RELATIVE-OID-IRI (§8.21.2, §8.22.2) are the UTF-8
    encoding of a value notation that this profile does not judge either. None of these
    types occurs in the RFC 3161, RFC 5652 or RFC 5280 modules, so the profile rejects them
    as a class. This is stricter than X.690, which admits their well-formed values; it is a
    conservative reading decided by principle, not an X.690 rule [S2-FIX2/U4] decided by
    principle (Inceptless decision 2026-11-15 #22).
  - **18 NumericString, 19 PrintableString, 22 IA5String, 26 VisibleString** — primitive
    (§10.2); the content contains no ESC (`0x1B`) octet: these types allow no explicit
    escape sequence (§8.23.5.3, Table 3).
  - **20 TeletexString, 21 VideotexString, 25 GraphicString, 27 GeneralString** (and 7) —
    primitive (§10.2); these are defined by reference to the ISO 2022 register and allow
    escape sequences (Table 3). 1a judges what §11.4 and §8.23.5.4 fix in the octets,
    starting from the designations Table 3 assumes for the type (§8.23.5.2; G0 6 for
    ObjectDescriptor, GraphicString and GeneralString, G0 102 for TeletexString and
    VideotexString, and their C0/C1 entries): every ESC octet begins a complete ISO/IEC 2022
    escape sequence (zero or more intermediate octets `0x20`–`0x2F`, then one final octet
    `0x30`–`0x7E`); no announcer (`ESC 2/0 F`, §8.23.5.4); and a designating escape
    sequence (`ESC 2/8`–`2/11`, `2/13`–`2/15`, `ESC 2/4 …`, `ESC 2/1`, `ESC 2/2`) neither
    names a register entry that is currently designated as G0, G1, G2, G3, C0 or C1 — a
    re-designation of an entry already in force is a violation — nor designates into a G set
    other than the smallest numbered one that has an escape sequence for the entry's class
    (G0 for a 94-character set, G1 for a 96-character set) (§11.4). Whether a designation or
    another escape sequence (an invocation, for example) is needed for the characters that
    follow, and whether its register entry is among those the type is defined by
    (§8.23.5.1), depends on the register entries and is not judged by 1a. S2-FIX1's reading,
    which rejected every ESC octet in these types, is withdrawn: a necessary designation
    (for example registration 6 into G0 of a TeletexString) is valid [S2-FIX2/U4] decided by
    principle (Inceptless decision 2026-11-15 #22).
  - **23 UTCTime, 24 GeneralizedTime** — primitive; the whole-content forms above (§11.7,
    §11.8).
  - **28 UniversalString** — primitive; whole 4-octet units (§8.23.7). **30 BMPString** —
    primitive; whole 2-octet units (§8.23.8).
  - **31 DATE, 32 TIME-OF-DAY, 33 DATE-TIME, 35 OID-IRI, 36 RELATIVE-OID-IRI** — primitive
    (§10.2), and rejected with 14 and 34 above.
  - **16 SEQUENCE, 17 SET** — constructed only; a universal SET is a SET OF in DER order, as
    above.
  - **15 and 37 or more** — reserved by X.680 for later editions; no DER rule exists for
    them, so only the framing rules apply, as for a type the verifier does not know (X1).
  Which characters a restricted string type admits (X.680 §41) is a property of the abstract
  value, not an X.690 encoding rule, and is not judged by 1a beyond the rules listed above
  (the escape-sequence rules of 12, 18, 19, 22 and 26 and of the ISO 2022 register types are
  X.690 encoding rules, §8.23.5 and §8.23.10, and are judged)
  [S2-FIX1/T3] decided by principle (Inceptless decision 2026-11-15 #18; X.690 in full).
- **1b — schema decoding.** The file decodes as an RFC 3161 `TimeStampResp` against the
  module definitions of RFC 3161, RFC 5652, RFC 5280 and RFC 5035/RFC 5816 (ESS), with the
  open types listed under 1c.
- **1c — re-encoding.** Re-encoding the decoded `TimeStampResp` yields the input bytes
  exactly. The re-encoding is defined by X.690 (DER) and those module definitions
  **only**: no parsing library's value model, default object or time type is a criterion
  [X1] decided (Inceptless decision 2026-11-12 #1; X1). In detail:
  - every SET OF — including the implicitly tagged ones, which 1a cannot recognise — is
    emitted with its components in ascending DER order: `SignedData.digestAlgorithms`,
    `SignedData.certificates`, `SignedData.crls`, `SignerInfo.signedAttrs`,
    `SignerInfo.unsignedAttrs`, every `Attribute.attrValues`, every
    `RelativeDistinguishedName` and `SignedData.signerInfos`;
  - a component equal to its DEFAULT value is omitted (X.690 §11.5). Equality is equality
    of the value the module definition gives, so it is decided on DER encodings: a
    component is "equal to its DEFAULT" exactly when its encoding equals the encoding of
    the default below, and every other value is encoded. In particular the ESSCertIDv2
    default is `{algorithm id-sha256}` with the `parameters` component absent; an explicit
    `{id-sha256, NULL}` is a different value and is encoded, while an explicit
    `{id-sha256}` is the default and is a violation. The DEFAULT components of this schema
    are exactly:

    | component | module | definition | DER encoding of the default |
    |---|---|---|---|
    | `TBSCertificate.version` | RFC 5280 | `version [0] EXPLICIT Version DEFAULT v1` | `a0 03 02 01 00` |
    | `Extension.critical` (certificate, CRL, CRL-entry and TSTInfo extensions) | RFC 5280 | `critical BOOLEAN DEFAULT FALSE` | `01 01 00` |
    | `TSTInfo.ordering` | RFC 3161 | `ordering BOOLEAN DEFAULT FALSE` | `01 01 00` |
    | `ESSCertIDv2.hashAlgorithm` | RFC 5035 (RFC 5816) | `hashAlgorithm AlgorithmIdentifier DEFAULT {algorithm id-sha256}` | `30 0b 06 09 60 86 48 01 65 03 04 02 01` |

  - every typed primitive, universally or implicitly tagged, is rebuilt from its content
    octets by the X.690 rules for its type, so implicitly tagged primitives obey the same
    canonical-content rules as in 1a: INTEGER in its shortest two's-complement form,
    BOOLEAN as `0xFF`/`0x00`, NULL empty, OBJECT IDENTIFIER sub-identifiers minimal, BIT
    STRING with zero unused bits and, for the named bit list `PKIStatusInfo.failInfo`, no
    trailing zero bit (X.690 §11.2.2); every primitive is in the primitive form;
  - the content octets of an OCTET STRING, a BIT STRING or a character string are
    re-emitted as decoded (their inner encoding is not part of this sub-step: the TSTInfo
    inside `eContent` is checked on its own by check 2 and certificate extension values by
    1e);
  - UTCTime and GeneralizedTime values are compared as their **raw content** in the DER
    form of 1a, never through a time value: any number of fractional digits is kept as
    encoded;
  - the `parameters` of the signer's `SignerInfo.digestAlgorithm` and
    `SignerInfo.signatureAlgorithm` have exactly the form fixed for the algorithm; any other
    form (including another well-framed value) is a violation of this check (`E_TS_SCHEMA`)
    [X6] decided (Inceptless decision 2026-11-12 #2; X6):

    | field | algorithms (OBJECT IDENTIFIER) | permitted `parameters` | source |
    |---|---|---|---|
    | `digestAlgorithm` | SHA-2: `id-sha224` (2.16.840.1.101.3.4.2.4), `id-sha256` (…2.1), `id-sha384` (…2.2), `id-sha512` (…2.3) | absent, or `NULL` (`05 00`) | RFC 5754 §2 |
    | `signatureAlgorithm` | `rsaEncryption` (1.2.840.113549.1.1.1) | `NULL` (`05 00`) only | RFC 3370 §3.2 |
    | `signatureAlgorithm` | `sha224WithRSAEncryption` (1.2.840.113549.1.1.14), `sha256WithRSAEncryption` (…1.11), `sha384WithRSAEncryption` (…1.12), `sha512WithRSAEncryption` (…1.13) | absent, or `NULL` (`05 00`) | RFC 4055 §5 and RFC 5754 §3.2 ("MUST accept the parameters being absent as well as present") |
    | `signatureAlgorithm` | ECDSA: `ecdsa-with-SHA224` (1.2.840.10045.4.3.1), `ecdsa-with-SHA256` (…3.2), `ecdsa-with-SHA384` (…3.3), `ecdsa-with-SHA512` (…3.4) | absent only | RFC 5758 §3.2 |

    The parameters of an algorithm not in this table are an open type (below); checks 5
    and 6 then reject such an algorithm;
  - a value of an **open type** is re-emitted exactly as decoded: only its framing — tag,
    length and nesting, with the universal rules of 1a — is judged, and it is never handed
    to a type decoder, whatever its tag class. The open types of this schema are
    `AlgorithmIdentifier.parameters` (except those of the signer's `digestAlgorithm` and
    `signatureAlgorithm` for an algorithm of the table above); `AttributeTypeAndValue.value`; the values of every
    attribute (signed or unsigned) whose type is not `id-contentType`
    (1.2.840.113549.1.9.3, decoded as an OBJECT IDENTIFIER), `id-messageDigest`
    (1.2.840.113549.1.9.4, an OCTET STRING) or `id-aa-signingCertificateV2`
    (1.2.840.113549.1.9.16.2.47, a `SigningCertificateV2`); `ContentInfo.content` when
    the content type is not `id-signedData` (check 1d then rejects it); **every component
    of `SignedData.certificates`** as a whole value (the signer certificate among them is
    decoded by 1e, X7/M3);
    `OtherRevocationInfoFormat.otherRevInfo`; the `x400Address` alternative of
    `GeneralName` and `AnotherName.value`; and `PolicyQualifierInfo.qualifier`.
- **1d — status and versions.** `PKIStatusInfo.status` is `granted`; the token's content
  type is `id-signedData`; `SignedData.version` is 3; `SignedData.signerInfos` holds
  **exactly one** `SignerInfo` (RFC 3161 §2.4.2: the token carries no signature other than
  the TSA's), whose `version` is 1 or 3 [X7/M2] decided (Inceptless decision 2026-11-12 #3;
  X7) and matches its `sid` as RFC 5652 §5.3 requires: 1 for `issuerAndSerialNumber`, 3
  for `subjectKeyIdentifier` [X7; `docs/open-questions.md` §6 entry 35] decided by
  principle (Inceptless decision 2026-11-12 #3; X7).
- **1e — the signer certificate.** The signer certificate is the first component of
  `SignedData.certificates` that the `SignerInfo`'s `sid` names: for
  `issuerAndSerialNumber`, the component whose TBSCertificate `issuer` encoding and
  `serialNumber` content octets are equal to the `sid`'s; for `subjectKeyIdentifier`, the
  component whose subjectKeyIdentifier extension carries the same octets. That certificate
  is walked under the RFC 5280 `Certificate` definition with the rules of 1b and 1c (its
  DEFAULT components included), decodes as an X.509 certificate, and every `extnValue` of
  its extensions — itself the DER encoding of the extension value (RFC 5280 §4.1) — is
  exactly one TLV obeying the universal rules of 1a. **Every other component is an open
  type** (1c): only its framing is judged, and it is never handed to a certificate decoder.
  When no component matches, 1e decodes nothing and check 7 fails [X7/M3] decided
  (Inceptless decision 2026-11-12 #3; X7).
  "Decodes as an X.509 certificate" means exactly this walk plus the version constraints of
  the RFC 5280 module, and no parsing library's habits: `version` is v1 (absent; an
  explicit v1 is an encoded DEFAULT, a 1c violation), v2 or v3, and any other value is not
  an X.509 certificate; `extensions` require v3 (RFC 5280 §4.1.2.1, §4.1.2.9) and
  `issuerUniqueID`/`subjectUniqueID` require v2 or v3 (§4.1.2.8). The open types of 1c stay
  open inside the signer certificate: a subject `AttributeTypeAndValue.value` whose
  PrintableString holds characters outside that type's set, or `AlgorithmIdentifier`
  parameters written as another well-framed value, do not make the certificate fail 1e.
  Checks 11 and 12 read the extended key usage, key usage and validity of the walked
  certificate; only check 10 hands its `subjectPublicKeyInfo` to a key decoder
  [S2/F62/F63] decided by principle (Inceptless decision 2026-11-15 #8; S2).

Check 2 applies 1a–1c to the encapsulated `TSTInfo` bytes on their own before reading
`TSTInfo.version` [W3] decided (Inceptless decision 2026-11-11 #16; W3).

**Complete check order (W6).** The timestamp phase of a container runs in exactly this
order:

1. **File checks, for every listed receipt:** the listed `.tsr` exists, is within
   `MAX_TIMESTAMP_BYTES` and hashes to its listed digest (`E_TS_FILE`, or `E_JSON_SIZE` for
   an oversize file); and every `.tsr` file in `signatures/` is listed (`E_TS_FILE`, §11.3). If any listed receipt fails, every listed receipt is `invalid` with
   `gen_time` `null` and nothing below runs.
2. **Check 14 (chain shape)** over the `timestamps[]` array of the attestation file. It is
   decided from the array alone (the `renews` links), before any receipt is decoded,
   because the imprint of a renewal receipt (check 4) is defined by its place in the chain.
   If it fails, every listed receipt is `invalid` with `gen_time` `null`, only
   `E_TS_RENEWAL` is reported, and nothing below runs.
3. **Per receipt, in chain order:** checks 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 and
   then 15, in that numeric order. The **first** failing check is the only code reported for
   that receipt. Within checks 7–10 the sub-steps are: the token carries a `signerInfo`
   whose signer certificate is present in `SignedData.certificates` (7); the signed
   attributes are present, carry the content-type and `messageDigest` attributes and the
   ESS `signingCertificateV2` (8, 9); the CMS signature verifies (10). A signer
   public key that the allowlisted signature algorithm cannot use (for example an EC key
   with an RSA algorithm) is a failure of check 10 (`E_TS_CMS`), not of check 6. Every
   receipt of the chain is checked; the timestamp phase reports the codes of all failing
   receipts together.

So a receipt with both an out-of-profile `SignerInfo.version` and a wrong imprint reports
only `E_TS_SCHEMA` (check 1 precedes check 4), and a broken renewal chain reports only
`E_TS_RENEWAL` even when a listed receipt would also fail check 1 [W6;
`docs/open-questions.md` §6 entry 26] decided (Inceptless decision 2026-11-11 #16; W6).

Checks 1–14 are structural or cryptographic and make the container **invalid** when they
fail, with one exception: the **unusable-accuracy** case of check 13 (a total above
`MAX_TS_ACCURACY` or a conversion overflow) is not a format error. Such a receipt keeps its
structural state, is reported `present-unverified`, and the container is **unverifiable**
(`E_TS_UNTRUSTED`), never invalid; it cannot rescue a compromised-key signature and cannot
support an L2 claim (T3). Within the timestamp phase the order is the complete check order
above: `E_TS_FILE` precedes `E_TS_RENEWAL`, which precedes every per-receipt code, and the
structural/CMS checks 5–12 precede the accuracy check 13
[S8⑪][T3][W6] decided (Inceptless decision 2026-11-11 #5; T3; 2026-11-11 #2; S8;
2026-11-11 #16; W6). Check 15 is a
trust decision: without a matching anchor the receipt is reported
`present-unverified` and the container cannot be `valid` (`unverifiable`,
`E_TS_UNTRUSTED`). An untrusted receipt also cannot rescue a signature by a compromised key
(§9.4 case 2): the missing information makes that record `unverifiable` with
`E_TS_UNTRUSTED`, not invalid [R3][R4] decided (Inceptless decision 2026-11-10 #42;
R3/R4).

### 12.3 Trust anchors

Verifying an RFC 3161 token does not by itself prove *when* it was issued: the signer
certificate must be trusted. Verification therefore requires an explicit trust anchor
(`--tsa-trust <pem>`, a file of one or more PEM certificates): a receipt is trusted if and
only if the SHA-256 digest of the **signer leaf certificate's DER encoding** equals the
SHA-256 digest of one of the anchor certificates. Certificate-chain building is not
performed in H0; the anchor is compared against the leaf certificate exactly. A
`tsa-cert-<n>.pem` inside the container is never trusted on its own; it is a transport
convenience only. Without a matching anchor, the receipt is `present-unverified` and the
container verdict is `unverifiable` (never `valid`) [D3][S5] decided (Inceptless decision
2026-11-10 #34; S5).

### 12.4 Renewal timestamp chain

Timestamps expire together with their certificates and algorithms. To keep evidence
verifiable over decades, a manifest may carry a **renewal chain**: the first receipt
timestamps the manifest digest; each later receipt timestamps the previous receipt bytes
together with the same manifest digest, in order. The attestation file represents this as a
single `timestamps[]` array sorted by `path`, where each entry carries `renews`, the `path`
of the previous receipt (or `null` for the first). The chain MUST be single and complete
(§12.2 row 14).

The imprint of a receipt with `renews == null` is the raw 32 bytes of the manifest digest.
The imprint of a receipt whose `renews` names a receipt with bytes `B` is:

```
expected_imprint = SHA-256( B ‖ <raw 32-byte manifest digest> )
```

The whole chain is verified link by link. This representation and imprint formula are
implementation shapes (PROVISIONAL, Appendix A P6) that the ruling fixes as the H0 answer
to the decision draft's renewal requirement [D3][S5] decided (Inceptless decision
2026-11-10 #34; S5).

### 12.5 Timestamp outcomes and the container verdict

- A claimed L2 MUST list at least one receipt (`E_MANIFEST_L2_NO_TIMESTAMP`), and L0/L1
  MUST list none (`E_MANIFEST_LEVEL`).
- If any listed receipt fails checks 1–14 of §12.2 as a **format or cryptographic failure**,
  the container is **invalid**.
- Otherwise, if the chain is complete and every receipt is verified (including check 15,
  with a matching anchor) and every receipt's accuracy is **usable**, `anchor_verified` is
  true and the L2 claim is verified at the
  report level described in §11.4.
- Otherwise each unverified-or-unusable receipt is `present-unverified` and the container is
  **unverifiable** (`E_TS_UNTRUSTED`), never `valid`. The unusable-accuracy case of
  §12.2 check 13 belongs here, not to the invalid branch (T3).

A verifier MUST NOT claim L2 merely because `.tsr` files exist, and MUST NOT accept a
receipt whose CMS signature, imprint, certificate constraints, ESS attribute or
`messageDigest` fails.

### 12.6 Timestamps prove anchoring, not truth

A verified timestamp proves that a timestamp authority signed an imprint at some time (and
that the stated constraints held); it does not prove the content is true. It is the only
evidence that a record or a manifest existed before a claimed time, and it is therefore the
evidence used by the `key-compromise` rule of §9.4. That rule requires a **trusted** receipt
whose `genTime + accuracy` is **strictly before** the revocation's effective time `T`
(§9.4 case 1); a receipt that is present but untrusted leaves the record `unverifiable` with
`E_TS_UNTRUSTED` (§9.4 case 2), and the absence of any timestamp evidence makes it invalid
with `E_KEY_COMPROMISED` (§9.4 case 3) [D3][A1c][S2][R3][R4] decided (Inceptless decision
2026-11-10 #42; R3/R4).

## 13. Size and resource limits

A conforming verifier MUST enforce at least these limits, before or while reading inputs.
Exceeding a limit is an error, never a crash or an unbounded read [Q5] decided (Inceptless
decision 2026-11-10 #34; Q5). The limit-to-code mapping in the table is fixed [Q24] decided
(Inceptless decision 2026-11-10 #34; Q24).

| constant | value | applies to | violation code |
|---|---|---|---|
| `MAX_RECORD_BYTES` | 1,048,576 (1 MiB) | one record file / one standalone record | `E_JSON_SIZE` |
| `MAX_MANIFEST_BYTES` | 4,194,304 (4 MiB) | `manifest.json`, `previous/manifest.json` | `E_JSON_SIZE` |
| `MAX_SIGFILE_BYTES` | 1,048,576 (1 MiB) | `signatures/manifest.sig.json` | `E_JSON_SIZE` |
| `MAX_TIMESTAMP_BYTES` | 1,048,576 (1 MiB) | one `.tsr` file | `E_JSON_SIZE` |
| `MAX_RECORDS` | 100,000 | `manifest.records` entries | `E_MANIFEST_RECORDS` |
| `MAX_CONTAINER_ENTRIES` | 200,000 | zip form: **all** archive entries (including `readable/**`); directory form: every file in the directory container, **including `manifest.json`** | `E_CONTAINER_SIZE` |
| `MAX_CONTAINER_UNCOMPRESSED_BYTES` | 1,073,741,824 (1 GiB) | zip form: the sum of the **declared** uncompressed sizes, excluding `readable/**`; directory form: the summed bytes of the files the verifier actually reads (`readable/**` never read or counted, `tsa-cert-*` presence-only and not counted) | `E_CONTAINER_SIZE` |
| `MAX_BLOB_BYTES` | 1,073,741,824 (1 GiB) | one blob | `E_MANIFEST_BLOB` |
| `MAX_BLOBS` | 10,000 | `manifest.blobs` entries | `E_MANIFEST_SCHEMA` |
| `MAX_REFS` | 256 | `refs` entries | `E_ENV_REFS` |
| `MAX_SIGS` | 16 | `sigs` entries | `E_ENV_SIGS` |
| `MAX_HINTS` | 8 | one reference's `hints` entries | `E_ENV_REFS` |
| `MAX_SIG_VALUE_BYTES` | 2,048 | decoded bytes of a non-ed25519 signature `value` | `E_ENV_SIGS` |
| `MAX_GRANT_CHAIN` | 8 | grant-chain links (§5.5.2) and rotation steps of the revocation-authority walk (§5.5.4) | `E_GRANT_UNRESOLVED` / `E_GRANT_REVOKE_SIGNER` |
| `MAX_JSON_DEPTH` | 32 | JSON **value nesting depth**: the top-level value is depth 1; every member value and every array element is one level deeper than the value that contains it; a scalar is a leaf value at its own depth | `E_JSON_SIZE` |
| `MAX_LICENCE_NESTING` | 16 | parenthesis nesting depth of an SPDX licence expression (§8.7) | `E_ENV_LICENCE` |
| `MAX_TS_ACCURACY` | 86,400 (seconds) | total `accuracy` of one RFC 3161 receipt (§12.2 check 13); exceeding it makes the receipt unusable evidence, not a format error | `E_TS_UNTRUSTED` (unverifiable) |

Limits are checked on the streamed bytes, not on a fully materialised decompression, and
both container forms use the same error code: exceeding any container limit is
`E_CONTAINER_SIZE` (invalid). In the **zip form** the verifier checks, before decompressing
anything, the total number of archive entries (`MAX_CONTAINER_ENTRIES`, `readable/**`
included) and the sum of the **declared** uncompressed sizes of all entries except
`readable/**` (`MAX_CONTAINER_UNCOMPRESSED_BYTES`); a declared-size total above the limit is
`E_CONTAINER_SIZE`, never `E_CONTAINER_ZIP`. In the **directory form** the same limits count
the entries and the bytes the verifier actually reads (record, manifest, attestation,
timestamp and blob files); the entry count is every file in the directory container, while
`readable/**` is never read or counted toward the byte total and `tsa-cert-*` files are
presence-only and not counted (T15). In the zip form the entry-count and declared-size
limits are phase 3 of the §11.9 check order: after the EOCD has been located and the
central directory parsed, before every remaining structural zip rule, so an over-limit
archive with a phase-4 violation reports `E_CONTAINER_SIZE` only (V7/L7, W7). Implementations MUST
NOT rely on filesystem-reported sizes for these checks;
they MUST enforce them while reading: each file of a directory container is read through a
probe bounded by its class limit plus one byte, the container total is accumulated while
reading, and the zip central directory is inspected before any entry is decompressed
[S4] decided (Inceptless decision 2026-11-11 #2; S4).

An in-container file above its class limit is a container-level `E_JSON_SIZE` (invalid). The
report shape follows the §14.5 stage in which the failure is detected (T16): a
`manifest.json` above `MAX_MANIFEST_BYTES` (manifest stage) yields the container defaults
and `records: []`; an oversized `signatures/manifest.sig.json` (step 5) and an oversized
`records/` file (records listing, step 7) fill the manifest-derived fields and report
`records: []`; an embedded `previous/manifest.json` above `MAX_MANIFEST_BYTES` (step 10,
after the record phase) and a `.tsr` above `MAX_TIMESTAMP_BYTES` (step 11) report
`E_JSON_SIZE` while the record verdicts are reported as usual (`E_MANIFEST_CHAIN` for a
depth/parse failure of the previous manifest keeps the same stage and shape, T17/A-L7). A
standalone record
target larger than `MAX_RECORD_BYTES` is read to at most `MAX_RECORD_BYTES + 1` bytes and
reported as `E_JSON_SIZE` (invalid); its `input.sha256`/`input.size` are `null`, and an
implementation MUST NOT read or hash the whole oversize file just to fill the report
(§14.6, T16). Implementations MUST NOT
crash because of nesting depth; the reference approach is non-recursive or
bounded-recursion parsing and serialisation with an explicit depth counter checked before
recursing [S3] decided (Inceptless decision 2026-11-11 #2; S3).

## 14. Verifier conformance

A conforming verifier reads records and containers with no network, no wall clock and no
locale/TZ/path dependence, and produces a deterministic report [I4]. Independent
implementations must agree on every vector [I4].

### 14.1 Command surface

The H0 Python verifier exposes these commands (names are normative for that CLI; an
independent implementation MUST provide equivalent behaviour):

```
hyphaweave-verify [--test-hooks] record <file> [--keys <dir>] [--json]
hyphaweave-verify [--test-hooks] container <dir|zip> [--keys <dir>] [--tsa-trust <pem>] [--previous <dir|zip>]
hyphaweave-verify [--test-hooks] vectors <dir> [--tsa-trust <pem>]
hyphaweave-verify --help | --version
```

`--test-hooks` is a global option that precedes the subcommand. It is the explicit test
switch of §14.7 and takes effect only for the test-only check-skip hook.

- **Operator inputs are checked before verification (W4).** `--keys`, `--tsa-trust` and
  `--previous` are inputs supplied by the operator, not evidence under verification. Before
  any stage of the target's pipeline runs, the verifier reads and checks the keyset and the
  trust-anchor file and checks that the `--previous` path exists and can be opened; a
  failure of any of these is a usage or I/O error: exit code 2, a message on standard
  error that names the offending option and file, and no report. Any failure while reading
  or decoding these inputs — whatever the decoding library reports — is such a usage error,
  never a crash and never an empty input. The content of an openable `--previous` is
  evidence for the chain link and is judged by §11.5 (`E_MANIFEST_CHAIN`), not by this rule
  [W4] decided (Inceptless decision 2026-11-11 #16; W4). **The kind of every operator path
  is established before it is opened (X3):** the `--keys` directory, each of its `*.json`
  entries, the `--tsa-trust` file and the `--previous` path are examined with `lstat`; a
  symbolic link is resolved and its target judged the same way. `--keys` must be a
  directory, a keyset entry and `--tsa-trust` a regular file, `--previous` a directory or a
  regular file; a FIFO, a character or block device, a socket, a dangling link or any other
  kind is a usage error (exit 2) without opening it, so a FIFO can never block the
  verifier. The `--tsa-trust` file is read with the bound `MAX_TIMESTAMP_BYTES` (§13); a
  larger file is a usage error (exit 2) [X3; `docs/open-questions.md` §6 entry 31] decided
  (Inceptless decision 2026-11-12 #1; X3).
- `--keys <dir>` supplies the verifier's **local trust input**: every top-level entry of
  the directory whose name ends in `.json`, names beginning with `.` included; an entry
  with such a name that does not resolve to a regular file (a directory, a dangling
  symbolic link, a special file) is a usage error (exit 2), and entries with other names
  are ignored [W10/L6; `docs/open-questions.md` §6 entry 28]. Each file MUST be a
  structurally valid record under this specification; a file whose first failing check belongs to the structural group is a
  usage error (exit 2). The structural group is: JSON classification and canonical form
  (§1.9), envelope structure (§4.1–§4.5), `sigs` presence and format (§4.3, including a
  record that requires per-record signatures but has `sigs` absent or empty), and the
  registered-kind body **schema** (the shape grammar of the kind page). For
  `weave.key.declared` the presence and encoding of `body.public_key` (strictly-encoded
  base64url decoding to exactly 32 bytes, §9.1) is **structural**; for `weave.key.rotated`
  the encoding and length of `old_public_key`/`new_public_key` (§9.2) are **structural**
  (V5). A file that is
  structurally valid but whose first failing check is a kind semantic rule, a key-lifecycle
  rule, an actor or authorisation rule, or a cryptographic rule does not establish trust and
  is ignored; it is not a usage error. **Two structurally valid keyset declarations for the
  same key id whose `key_type` differs, or whose `(valid_from, valid_until)` pair differs
  (absent = unbounded; present-versus-absent counts as different), are a usage error
  (exit 2):** the ambiguity must be fixed by the operator, so no report is produced. When
  there is no conflict, the §5.3 definitions apply: the **governing class** is determined
  from structurally valid declarations (keyset declaration first, otherwise the smallest
  `(recorded_at, record digest)` among structurally valid declarations) and the governing
  validity window from
  semantically valid declarations, both independently of the trust closure; any keyset
  declaration — whatever its class — governs its key id's class and window (T4, V4). The keyset is verified first; each valid
  `weave.key.declared` of class `human`/`organization` in it is a trusted root, with no
  cosignature needed and no self-attestation notice (§5.3). Other keyset records
  participate in the verification context like container records: in particular
  `weave.key.revoked` records in the keyset are effective revocations (§9.4). Container and
  record-target declarations can extend this local trust but can never create a root
  [R2] decided (Inceptless decision 2026-11-11 #2; S8⑨/F10; 2026-11-10 #42; R2).
- `--tsa-trust <pem>` supplies L2 trust anchors (§12.3): a file of one or more PEM
  certificates. A file that cannot be read, contains no certificate, or contains a PEM block
  that does not decode as an X.509 certificate is a usage error (exit 2, no report,
  standard error names the file); it is never treated as an empty anchor set (W4). An
  anchor "decodes as an X.509 certificate" under exactly the rules of §12.2 1e — the module
  walk with the 1b/1c rules, the version constraints, and the 1a rules for every
  `extnValue` — so a certificate that 1e would reject as a signer certificate is also
  rejected as an anchor, and one that 1e accepts is accepted [S2/F62/F63] decided by principle (Inceptless decision 2026-11-15 #8; S2). On
  `container` it supplies the anchors for that container. On `vectors` it supplies a default anchor for every case that
  does not name its own `--tsa-trust` in its `expected.json` `args`; per-case arguments
  replace the caller-supplied value for that case. `--keys` and `--previous` are not
  accepted on `vectors`, and a case without `args` sees no local trust input
  [S16/F15] decided (Inceptless decision 2026-11-11 #2; S16/F15).
- `--previous <dir|zip>` supplies the previous container in the chain, as a directory or
  its zip. It is **not** verified like a `container` target: only its `manifest.json` and
  `signatures/manifest.sig.json` are read, its manifest signature is verified in the
  target container's verification context, and its manifest digest must equal
  `previous_manifest.digest`; everything else in it is not verified
  (`L_PREVIOUS_CONTENT_UNVERIFIED`). The rules and failure conditions are in §11.5
  [S6][S16/F15][V3][W1] decided (Inceptless decision 2026-11-11 #2; S6/F15;
  2026-11-11 #14; V3; 2026-11-11 #16; W1).
- `--json` is accepted and is the default (compatibility flag). No colour, no progress
  output. Standard output carries exactly one JSON report per run; standard error carries
  usage and I/O errors only.
- No network access. No reading of external test data at runtime. Input file bytes are read
  once, under the §13 limits, and verified from those bytes.

### 14.2 What a verifier MUST accept and reject

A verifier MUST accept a record or container that satisfies every applicable requirement of
this specification, and MUST reject as invalid, or mark unverifiable, every record or
container for which a required check fails, per §14.3. In particular it:

1. accepts records whose canonical bytes, envelope, signatures, kind rules, actor rules,
   labels and references satisfy this specification;
2. accepts containers whose layout, manifest, manifest signature, level completeness,
   records consistency, cross-record state, blobs, previous-manifest chain and timestamps
   satisfy this specification;
3. rejects any JSON that is not WR-CJ canonical form where required, or that violates the
   WR-CJ input restrictions, with the first-violation classification of §1.9;
4. rejects any record that lacks a required per-record signature (per §4.4), any
   `ed25519` signature that does not verify under §3.4, and any record or container
   violating a MUST of this specification;
5. marks a record or container `unverifiable` — never `valid` — when a required
   authorisation, key, signature or trust condition cannot be established from the input,
   as listed in §14.4;
6. reports `erased` for a `weave.erased` placeholder and for containers containing such
   placeholders among otherwise valid records;
7. MUST NOT add, invent or accept error or notice codes outside the closed registry of
   `spec/error-codes.md`.

Unknown kinds are handled per §7.3: verify integrity and authorisation, do not validate
the body, report `kind_known: false` and `N_KIND_UNKNOWN_OPAQUE`, and never reject because
a kind is unregistered [K3].

### 14.3 Verdicts

Exactly four verdicts exist for a record:

| verdict | meaning |
|---|---|
| `valid` | every applicable check passed |
| `invalid` | at least one error was found in this record (or in the container structure, for a container target) |
| `unverifiable` | no error, but an authorisation, key, signature or trust condition cannot be established from the input |
| `erased` | this record is a `weave.erased` placeholder (§4.5) and its structure is sound |

For a record target: `invalid` if any error; else `unverifiable` if a blocking condition of
§14.4 is present; else `valid` (or `erased` for a placeholder). For a container target:
`invalid` if any container, manifest or record error exists; else `unverifiable` if a
manifest or record key, an authorisation condition or timestamp trust is unverifiable, or
any record is `unverifiable`; else `valid` (erased placeholders are allowed and yield
`erased` record verdicts). For the `vectors` target: `valid` if and only if every case
matches its `expected.json`.

Verdict precedence is `invalid` over `unverifiable` over `valid`; `erased` is a record-level
verdict and, at the top level of a record target, replaces `valid` for a placeholder. The
top-level verdict of a container is never `erased`.

### 14.4 Blocking conditions that force `unverifiable`

The following conditions MUST NOT lead to `valid`: `E_KEY_UNKNOWN`, `E_KEY_UNTRUSTED`,
`E_SIG_UNVERIFIABLE`, `E_GRANT_UNRESOLVED`, `E_GRANT_REVOKED`, `E_GRANT_EXPIRED`,
`E_TS_UNTRUSTED`, and the notice `N_KEY_UNDECLARED` when a signature cannot be checked at
all because no key material is available. A claimed L2 without a matching trust anchor is `unverifiable` (§12.5). Any
`unverifiable` record makes the container `unverifiable` (not invalid). A verifier MUST NOT
silently pass a check it could not perform; it reports the gap in `limitations`.

A condition in this section is terminal for the record exactly like an error: the verifier
reports that code, stops the record's remaining checks, and reports no later error. The
code is carried in `records[].errors` and counts as the record's single reported code; the
verdict is `unverifiable`. This does not apply to container conditions: an `unverifiable`
container condition does not stop record processing (§14.5)
[S8⑪][S16/F7] decided (Inceptless decision 2026-11-11 #2; S8/F7).

### 14.5 Deterministic check order

A verifier MUST apply checks in a deterministic order and MUST report at most one error per
record: the first failing check in the order below (later checks are not run for that
record). Containers apply the container order below.

Per record: (1) parse and canonical form (§1.9), (2) envelope structure, (3) `sigs`
presence/format (§4.3), (4) key resolution (unknown key → unverifiable, stop crypto),
(5) Ed25519 verification (§3.4), (6) kind body schema, (7) kind semantic rules,
(8) actor/authorisation, (9) labels, (10) reference resolution and kind mismatch. Within the
signature layer the Ed25519 cryptography of §3.4 runs before the key-lifecycle effects of
§9.4: a signature that fails the equation reports the §3.4 code (`E_SIG_INVALID` or the
applicable `E_SIG_*` code) even when its key is expired, revoked or compromised
[S8⑪] decided (Inceptless decision 2026-11-11 #2; S8). Steps (4) and (5) are steps of the
record, not of one entry: step (4) resolves the key of **every** `ed25519` entry before any
equation is evaluated, and then every entry whose key resolved is judged in array order,
each by its §3.4 equation and then by §9.4; every entry reports its state (§14.6)
[S2] decided by principle (Inceptless decision 2026-11-15 #8; S2). The record's code is
then chosen invalid-first: the first entry, in array order, with an invalid outcome (a
§3.4 failure, or an invalid §9.4 outcome such as `E_KEY_REVOKED`, `E_KEY_EXPIRED` or
`E_KEY_COMPROMISED`) decides it; only when no entry is invalid does an unresolved key give
`unverifiable` `E_KEY_UNKNOWN`, and only then the first unverifiable §9.4 outcome (for
example `E_TS_UNTRUSTED`). A known-key signature that fails its equation therefore makes
the record invalid `E_SIG_INVALID` even when another entry's key cannot be resolved (§4.4
step 2) [S2-FIX1/T2] decided by principle (Inceptless decision 2026-11-15 #18; invalid beats
unverifiable).

Two documented ordering exceptions live inside the kind checks:

- for `weave.key.declared`, a **missing** or malformed `body.public_key` reports
  `E_KEY_PUBLIC_KEY` instead of the generic `E_KIND_BODY_SCHEMA` from step (6), and it is
  decided before any trust judgement (§9.1 rule 1, T1) — that is, immediately after step
  (3) and before the key resolution of step (4), because the declared key's own material is
  what its self-signature would resolve to. No signature check runs (`sigs` is `[]`), and no
  other body defect, `body.key` included, can precede it [S2/F39/F50] decided by principle (Inceptless decision 2026-11-15 #8; S2);
- for `weave.key.rotated`, the **structural** validation of `old_public_key` /
  `new_public_key` (`E_KEY_ROTATION_KEYS`) is part of the kind body check and runs before
  signature verification, so a structural error wins over an `E_SIG_*` outcome (§9.2
  rule 2, T13). That structural check first requires `new_key` and `old_key` to be present
  key ids (§2.5): a missing or malformed key id, or one of another JSON type, is
  `E_KIND_BODY_SCHEMA`, decided before the key-material rule (which compares a public key
  with a well-formed key id) and before key resolution [S2/F61-3] decided by principle (Inceptless decision 2026-11-15 #8; S2). Curve-point decoding failures during an actual signature check remain
  `E_SIG_*` (§3.4).

Within step (2) the envelope sub-order is: required top-level members in §4.1 table order
(`E_ENV_MISSING_FIELD`), then top-level closedness (`E_ENV_UNKNOWN_FIELD`), then each present
member's grammar in §4.1 table order. A closed nested object applies the same
presence → closedness → grammar order inside itself and reports the dedicated code of the
section that defines it (§4). Inside `actor`, the four agent-only members are required
members when `type` is the string `"agent"` (outside the key-lifecycle exception), so their
presence is decided in the presence phase, in table order, before closedness and before
the grammar of any member, `key` included; a `type` that is not one of the closed values
creates no such obligation and is reported by the grammar phase [S2/F45/F67] decided by principle (Inceptless decision 2026-11-15 #8; S2). A record missing `stage` while also carrying an unknown
top-level member therefore reports `E_ENV_MISSING_FIELD`
[S8⑤][S16/F3] decided (Inceptless decision 2026-11-11 #2; S8/F3).

Required-signature errors follow the precedence of §4.4: an absent or empty `sigs` array on
a record that needs a per-record signature is `E_SIG_REQUIRED` at step (3); a record that
does not need signing may carry an empty `sigs` array. For ordinary kinds, a non-empty
`sigs` with verifiable signatures but no required signer is `E_SIG_REQUIRED` immediately
after step (5); for the seven signer-constrained kinds the dedicated kind code is emitted at
step (7) when verifiable entries exist but the required signer is missing/wrong; when there
is no known-algorithm declared-key signature at all the record is `E_KEY_UNKNOWN` or
`E_SIG_UNVERIFIABLE` as specified in §4.4. The notice `N_NO_HUMAN_SIGNATURE` is reported
only for an `accepted` record whose verdict is `valid`; the unverifiable branches report
only their outcome (§4.4) [S7①][S8⑭][Q31][Q13] decided (Inceptless decision 2026-11-11 #2;
S7/S8/F6; 2026-11-10 #34; Q13/Q31).

**Order inside steps (7) and (9).** Inside step (7) of a signer-constrained kind the rules
run in this order: first the kind's rules that read only the record itself, in the order of
its kind page (for example `actor.type`, the consent window `E_CONSENT_VALIDITY`, a grant
variant's window `E_KEY_VALIDITY`, a declaration's `body.key`/`public_key` agreement); then
the kind's signer rule, which reports the dedicated code of §4.4 step 4 (invalid); then the
rules that consult other records (a declaration's governing class and owner, the
delegated-grant chain of §5.5.2, an erasure's authorising grant, a consent revocation's
target). A signer rule whose signers are defined by another record follows the lookup of
that record: a grant revocation's allowed revokers (§5.5.4), a revocation's human or
organization signers, a declaration's owner cosignature and its trust (§5.3, §9.1). When
§4.4 step 5 applies — no known-algorithm signature by a declared key exists at all — the
signer rules, and the rules that need a verified signature (trust through a cosignature),
are not evaluated: their outcome is the step-5 code, and it is reported only when every
other rule of the kind's step (7) passes, so an invalid outcome (or an `unverifiable`
grant-chain or trust outcome) of another rule is reported instead. A record that fails a
check of step (9) reports only that outcome: the notice `N_LABEL_PROPAGATION_UNCHECKED` of
the same step is not reported for it, as for any check that is not run after the first
failure [S2-FIX1/Q3] decided (Inceptless decision 2026-11-15 #18; Q3).

Per container: (1) entry enumeration/safety; (2) manifest parse/canonical form;
(3) manifest structure; (4) manifest digest; (5) manifest signature; (6) level/chain
structure completeness; (7) records listing and per-record verification; (8) cross-record
state rules (key lifecycle, grants, consents, erasure, label propagation); (9) blobs;
(10) previous-manifest chain; (11) timestamps; (12) aggregation and report.

Timestamp verification may be performed before step (7) because §9.4 uses the verified
receipt chain as evidence for record outcomes; a timestamp failure is still reported as a
container-level error and does not stop record processing. The listed order governs
reporting and stopping, not the internal computation order
[S16/F8] decided (Inceptless decision 2026-11-11 #2; S16/F8).

A container-level **invalid** error stops the container pipeline at the stage where it is
detected: later container stages are not run, and record processing does not run for an
invalid error found before the per-record checks, so the report carries `records: []`.
This holds for every stage, steps (8)–(11) included: an invalid cross-record (8), blob (9)
or previous-manifest-chain (10) error means that the later stages are not run and report
nothing — no error code, no notice, no limitation and no `container.timestamps` entry of
a later stage — while the record verdicts already produced are reported as usual (W5).
Record-level errors are not container-level errors: an invalid record does not stop the
container pipeline [W5] decided (Inceptless decision 2026-11-11 #16; W5).
`container.errors` carries every violation found in the failing stage, sorted
lexicographically and unique; an earlier stage that produced only `unverifiable` conditions
keeps those codes, so `container.errors` can carry both kinds. In particular the
records-listing and consistency phase (§11.6) reports every independent violation it detects
together — `E_MANIFEST_RECORD_MISSING`, `E_MANIFEST_RECORD_EXTRA`,
`E_MANIFEST_RECORD_DIGEST`, `E_MANIFEST_RECORDS`, and `E_JSON_SIZE` for record files above
`MAX_RECORD_BYTES` (U8). A file in `records/` is subject to `MAX_RECORD_BYTES` whether or
not it is listed; an unlisted or misnamed file above that limit reports both
`E_MANIFEST_RECORD_EXTRA` and `E_JSON_SIZE`. A `records/` file nested deeper than
`MAX_JSON_DEPTH` is a size violation like any other (§1.9): this phase reports it as
`E_JSON_SIZE`, not as an unconfirmable digest (`E_MANIFEST_RECORD_DIGEST`)
[S2/F55/F60] decided by principle (Inceptless decision 2026-11-15 #8; S2). An in-container file above its §13 class
limit is a container-level `E_JSON_SIZE`, and the report shape follows the stage where it is
detected (T16): `manifest.json` at the manifest stage → container fields default/`null` and
`records: []`; the attestation file at step (5) and a `records/` file at step (7) →
manifest-derived container fields filled and `records: []`; an embedded
`previous/manifest.json` at step (10) and a `.tsr` at step (11) → the already-processed
record verdicts are reported as usual. The reader MUST NOT abort the record phase for an
oversize file that belongs to a later stage. An `unverifiable` container condition does
not stop record processing and its code is retained in `container.errors`; in particular an
unverifiable manifest signature (for example `E_KEY_UNKNOWN` with no keyset) does not stop
the records listing or the per-record checks. Manifest signature verification establishes
the cryptographic equation only; whether the signing declaration is trusted is evaluated at
the key/record layer [S8①][S7②][S16/F16] decided (Inceptless decision 2026-11-11 #2;
S8/S7/F16; T16).

Checks (7)–(10) of a record may need other records; they are evaluated with the
deterministic resolution model of §6.4.

### 14.6 Report format

The report is one JSON object on standard output, UTF-8. The exact byte rule is: object
member names sorted ascending by UTF-16 code-unit order, two spaces of indentation, one
item per line, empty arrays and objects inline as `[]`/`{}`, the `": "` name separator,
`\\`, `\"`, `\b`, `\t`, `\n`, `\f` and `\r` shorthands, every other C0 control, every
non-ASCII code point (including U+007F) and surrogate pairs emitted as lowercase `\uXXXX`,
`/` never escaped, and exactly one trailing LF byte. The report contains no absolute
paths, usernames, hostnames, current times,
randomness or environment values. The stable report version is `report_version: "1"`
[S8⑩][S16/F12] decided (Inceptless decision 2026-11-11 #2; S8/F12):

```json
{
  "checks_disabled": [],
  "report_version": "1",
  "spec": "weave-record/1",
  "target": "record|container|vectors",
  "verdict": "valid|invalid|unverifiable|erased",
  "input": {"sha256": "sha256:...", "size": 1234},
  "records": [{
    "digest": "sha256:...", "id": "...", "kind": "...", "stage": "...",
    "origin": {"project": "...", "instance": "ed25519:..."},
    "kind_known": true,
    "verdict": "valid|invalid|unverifiable|erased",
    "errors": ["E_..."], "notices": ["N_..."],
    "refs": [{"index": 0, "rel": "derived_from", "state": "found|moved|missing|erased|unverifiable"}],
    "sigs": [{"key": "ed25519:...", "state": "valid|invalid|unverified|ignored"}]
  }],
  "container": {
    "created_at": "...", "manifest_digest": "sha256:...",
    "level_claimed": "L0|L1|L2", "level_verified": "L0",
    "anchor_verified": false,
    "chain": {"status": "absent|unverified"},
    "previous_manifest_digest": null,
    "record_count": 1,
    "errors": ["E_..."], "notices": ["N_..."],
    "timestamps": [{"index": 0, "path": "signatures/timestamp-1.tsr", "state": "verified|present-unverified|invalid", "gen_time": "..."}]
  },
  "summary": {"valid": 1, "invalid": 0, "unverifiable": 0, "erased": 0},
  "limitations": ["L_OFFLINE_CONTEXT"],
  "verifier": {"name": "hyphaweave-verify-python", "version": "0.1.0"}
}
```

Report rules:

- The `verifier` object identifies the implementation: `name` is a stable identifier and
  `version` its version. It is informational, outside cross-implementation comparison, and
  two conforming implementations are not required to emit byte-identical reports;
  conformance is defined by §14.10. §0.2 names the H0 Python verifier's report identity
  [S8⑫][S16/F1] decided (Inceptless decision 2026-11-11 #2; S8/F1).
- The `container` object is present only for a container target. `level_verified` is always
  `"L0"` in H0; `anchor_verified` is true only for a fully verified L2 timestamp chain with
  a matching anchor (§11.4, §12.5). When a container value cannot be determined because the
  input failed earlier in the check order, the container defaults are: `level_verified`
  `"L0"`, `anchor_verified` `false`, `chain` `{"status":"absent"}`, `record_count` `0`,
  `timestamps` `[]`; `created_at` and `manifest_digest` are `null` until their checks pass,
  and `manifest_digest` is reported only after the manifest structure checks pass. A
  failure before per-record evaluation reports `records: []` and all-zero `summary` counts;
  a failure at a later stage (for example the previous-manifest chain at step (10) or the
  timestamp phase at step (11)) keeps the record verdicts it already produced. When the
  pipeline stops before step (11), the timestamp phase did not run: `timestamps` is `[]`
  and `anchor_verified` is `false`, even though receipts may have been evaluated
  internally for the §9.4 rescue (W5). For an
  in-container file above its §13 class limit the shape follows the stage where it is
  detected (§14.5, T16): a `manifest.json` oversize leaves the container fields at their
  defaults/`null`; an attestation-file or `records/` file oversize fills the manifest-derived
  fields (`created_at`, `manifest_digest`, `level_claimed`, `level_verified`, `chain`,
  `previous_manifest_digest`, `record_count`, `timestamps: []`) while `records` and
  `summary` stay empty; a previous-manifest or `.tsr` oversize reports `E_JSON_SIZE` with
  the processed records and their `summary` counts
  [S8⑩][S16/F12][T16] decided (Inceptless decision 2026-11-11 #5; T16; 2026-11-11 #2;
  S8/F12). **`record_count` rule (V7/L5):** once the manifest has parsed **and its
  structure checks have passed**, `record_count` is the number of records listed in
  `manifest.records` for every later failure — records listing/consistency, blobs, the
  previous-manifest chain, timestamps, aggregation — and is never reset to 0 by a later
  failure. It is 0 only when the failure occurs before the manifest structure stage
  (absent, unreadable, oversize, unparseable or structurally invalid manifest).
- `records` holds one entry for a record target and the manifest-ordered entries for a
  container target. For a `weave.erased` entry, `records[].digest` is the §2.2 record
  digest computed over the placeholder object itself (not the placeholder's original-digest
  member); the entry optionally carries
  `"attestation": {"digest": <digest string>, "state": "found|moved|missing|erased|unverifiable"}`;
  its `refs` array is empty.
- `kind_known` is `false` for an unregistered kind; the notice `N_KIND_UNKNOWN_OPAQUE` is
  reported only when that record's final verdict is `valid` (§7.3)
  [S8⑩][S16/F12] decided (Inceptless decision 2026-11-11 #2; S8/F12).
- `N_KEY_TOFU` is the per-record form of the TOFU predicate of §14.9: it is reported on a
  record if and only if at least one of that record's signature checks was context-trusted
  (the verifying key material came from a context `weave.key.declared` declaration or from
  the explicit key material of a context `weave.key.rotated` record, rather than from the
  local keyset), even if that signature or the record then fails (§5.3, U6). For the three
  key-lifecycle kinds only the actor-key signature counts. The manifest signature never
  produces a record notice; it contributes to `L_KEY_TRUST_TOFU` instead. A J1-style
  container illustrates the split: a container-declared device key (owner-cosigned by a
  keyset root) signs the manifest while no record signature uses context material — the
  report carries `L_KEY_TRUST_TOFU` and no record carries `N_KEY_TOFU`
  [S8⑩][S16/F12][T10] decided (Inceptless decision 2026-11-11 #5; T10; 2026-11-11 #2;
  S8/F12).
- `sigs[].state` is `ignored` for an unknown algorithm (§3.6), `invalid` when the
  cryptographic equation fails, `unverified` when the key state fails a §9.4 rule
  (expired, revoked, compromised) or when the key material is unavailable, and `valid` when
  the signature and its key state both pass. Every entry is judged and reports its own state,
  also after an earlier entry failed (§4.4 step 2, §14.5); an entry whose key cannot be
  resolved is `unverified`. When the record stops
  before the signature layer — at steps (1)–(3), or at the `E_KEY_PUBLIC_KEY` decision that
  precedes step (4) for a declaration — no signature check ran and `sigs` is `[]`
  [S2/F39/F52] decided by principle (Inceptless decision 2026-11-15 #8; S2) [S8⑩][S16/F12] decided (Inceptless decision
  2026-11-11 #2; S8/F12).
- `refs[]` reports the reference resolutions established so far when a later reference or
  kind check then fails; the resolved prefix is information, not a passed check
  [S8⑩][S16/F12] decided (Inceptless decision 2026-11-11 #2; S8/F12).
- `container.timestamps[]` entries carry `index`, `path`, `state` and `gen_time`;
  `gen_time` is filled whenever §12.2 checks 1–4 passed, even if a later check fails, and
  is `null` for `E_TS_FILE` or an unparseable token. A receipt whose DER or structure
  cannot be decoded anywhere in its processing reports `E_TS_SCHEMA` (reported in the
  timestamp phase as a container-level `E_TS_SCHEMA`) and its `gen_time` is `null` (V2).
  When the renewal chain itself is
  broken (§12.2 check 14), every receipt is reported `invalid` with `gen_time` `null`
  [S8⑩][S16/F12] decided (Inceptless decision 2026-11-11 #2; S8/F12; 2026-11-11 #14; V2).
- Container-level errors and notices (manifest, level/chain, blob, timestamp and container
  structure problems) live in `container.errors` / `container.notices` (sorted,
  lexicographically unique, registry codes only). An invalid container stage reports every
  violation it found (`container.errors` may hold several codes, §14.5); an unverifiable
  container condition keeps its code and does not stop record processing. For test-vector
  comparison, a container case's aggregated errors are the set union
  `container.errors ∪ every records[i].errors`, and its aggregated notices are the
  corresponding union [S8①][S7②] decided (Inceptless decision 2026-11-11 #2; S8/S7).
- `N_READABLE_PRESENT` is reported whenever an enumerated container contains a
  `readable/` entry; `N_PREVIOUS_SIG_UNVERIFIED` is reported whenever
  `previous_manifest` is non-null and the previous signature was not re-verified. Both are
  retained even when an earlier container check failed: they describe conditions the
  verifier already detected, and hiding them would make the report lose information. When
  the condition cannot be determined (for example entry enumeration failed before a
  `readable/` entry was observed), the notice is not reported
  [S12][T12] decided (Inceptless decision 2026-11-11 #5; T12).
- Errors and notices are sorted lexicographically and unique; they come only from the
  closed registry. `checks_disabled` is sorted, unique and contains only registered `E_*`
  codes; it is `[]` unless the test hook of §14.7 is active.
- A report never invents a value and never omits a `records[]` entry that the container
  manifest or the target requires. The report's field set and types are stable: a
  scalar or object field whose value cannot be determined because the input failed earlier
  in the check order is `null`, a list field whose elements are not determined is `[]`, and
  a field is omitted only where this section says it is conditional (`container` for
  non-container targets, `attestation` for non-placeholder records, `cases` for
  non-`vectors` targets) [S16/F9] decided (Inceptless decision 2026-11-11 #2; S16/F9).
- `input.sha256`/`input.size` identify the target input:
  - for a record target, the record file bytes. If the file is larger than
    `MAX_RECORD_BYTES`, at most `MAX_RECORD_BYTES + 1` bytes are read (the whole file is
    never read or streamed just to fill the report), the record is `E_JSON_SIZE`, and both
    `input` fields are `null`;
  - for a zip container, the archive bytes (whose identity may be streamed from the archive
    file, which is read anyway);
  - for a directory container, the identity is two-tier. **(a)** Once `manifest.json` has
    parsed and its structure has been validated (§11.2), `input.sha256` is the §2.4
    **manifest digest** and `input.size` is the manifest byte size [Q27]. **(b)** When the
    raw `manifest.json` bytes were read within `MAX_MANIFEST_BYTES`, but the manifest is not
    a canonical, structurally valid manifest, or verification stopped before the manifest
    structure stage (for example an entry-enumeration failure), `input.sha256` is the
    SHA-256 of the **raw `manifest.json`
    bytes** and `input.size` is their byte size. A later failure (for example an oversized
    record file, or an oversize `.tsr`) is not tier (b): once the manifest is valid the
    identity is tier (a), and the §14.5/T16 report shape applies. **(c)** When
    `manifest.json` is absent,
    unreadable, or above `MAX_MANIFEST_BYTES`, both are `null`; a directory-snapshot hash is
    never reported.
  The general undetermined-field rule of this section applies to `input` in exactly the
  `null` cases [S14][S16/F11][T16] decided (Inceptless decision 2026-11-11 #2; S14/F11;
  2026-11-11 #5; T16).
- For the `vectors` target, `summary` is `{"case_count": N, "matched": n,
  "mismatched": m}` and conformance for this target is `mismatched == 0`. The per-case
  result array layout and the representation of the `input` identity are
  implementation-defined, deterministic and path-free; they are not compared across
  implementations [S8⑬][S16/F5] decided (Inceptless decision 2026-11-11 #2; S8/F5).
- `limitations` is a sorted, unique array of closed limitation **identifiers** — never
  free prose — drawn from the registry list in `spec/error-codes.md`: `L_OFFLINE_CONTEXT`,
  `L_CHAIN_CLAIM_UNVERIFIED`, `L_KEY_TRUST_TOFU`, `L_PREVIOUS_CONTENT_UNVERIFIED`,
  `L_PREVIOUS_SIG_UNVERIFIED`, `L_TSA_TRUST_UNVERIFIED`, `L_ERASED_PLACEHOLDER`,
  `L_ERASED_STANDALONE`, `L_LABELS_ARE_CLAIMS`, `L_UNKNOWN_KIND_OPAQUE`,
  `L_LABEL_PROPAGATION_UNCHECKED`. The
  conditions under which each identifier is emitted are normative in §14.9; a verifier MUST
  NOT emit an identifier outside this list and MUST NOT phrase a limitation as a passed
  check [S12] decided (Inceptless decision 2026-11-11 #2; S12).
- A report is never silently degraded: skipped checks appear in `checks_disabled` (§14.7)
  and make the exit code `3` (§14.8).

### 14.7 Test-only check hook

For conformance testing only, the H0 verifier exposes a check-skip hook. It is
reachable only through the explicit global CLI switch `--test-hooks` (§14.1): the
environment variable `WEAVE_VERIFY_SKIP_CHECKS` is read **only** when `--test-hooks` is
present and is ignored entirely otherwise (no `checks_disabled` entry and no change to the
report or the exit code). When active, the variable is a comma-separated list of registered
error codes whose checks are treated as passed; unset or empty means normal operation.
`checks_disabled` echoes the sorted, unique registered codes. Token parsing is fixed:
split on ASCII commas, trim ASCII whitespace around each token, ignore empty tokens, match
registered error codes case-sensitively and exactly, and collapse duplicates. A token that
is not a
registered `E_*` code is a usage error: exit code 2, a message on standard error naming the
sorted unknown tokens, and no report on standard output. The exit code is `3` whenever
`checks_disabled` is non-empty, even if every reported verdict is `valid` and even when the
verdict is `invalid` (§14.8). The hook
is documented as test-only and MUST NOT be used as a production configuration. An
independent implementation is not required to implement this hook to be conformant to the
record format; it is required only for reproducing the H0 test-gate procedure
[S13][Q18] decided (Inceptless decision 2026-11-11 #2; S13).

### 14.8 Exit codes

| exit code | meaning |
|---|---|
| `0` | valid: the record/container is `valid` (or `erased` for a placeholder record), or every vector case matched |
| `1` | invalid, unverifiable, or at least one vector case mismatched |
| `2` | usage or I/O error; no report on standard output |
| `3` | a report was produced but the test-only check hook disabled at least one check (`checks_disabled` non-empty); this takes precedence over `0` and `1` and below `2` |

`record` on a `weave.erased` placeholder returns verdict `erased` and exit code 0: a
structurally sound attestation of an erasure is a successful verification. Exit code `3`
means the report is present and must be read together with `checks_disabled`; it is never
the "all valid" code [S13] decided (Inceptless decision 2026-11-11 #2; S13).

### 14.9 Limitations reporting

Every report lists what was **not** verified, using the closed identifier list of the
registry (`spec/error-codes.md`): a sorted, unique array of identifiers only, never free
prose. A verifier MUST NOT emit an identifier outside the list, MUST NOT invent a
limitation, and MUST NOT phrase a limitation as a passed check
[S12] decided (Inceptless decision 2026-11-11 #2; S12). The emission conditions below are
**if-and-only-if** conditions on decidable facts; when a condition cannot be determined, the
identifier (and the corresponding notice) is **not** reported (T12).

**TOFU predicate (single definition).** A signature check was **context-trusted** when the
key material used to verify it came from the verification context (container or target
records) rather than from the local keyset (`--keys`), where context material means either

- a `weave.key.declared` declaration in the context, or
- the explicit `old_public_key` / `new_public_key` of a `weave.key.rotated` record in the
  context.

Rotated key material therefore counts as TOFU exactly like declared material: the check
emits `N_KEY_TOFU` on the record and makes the report carry `L_KEY_TRUST_TOFU` (T10 rules
otherwise unchanged). Manifest-signature checks and record-signature checks both use this
one definition [T10][U6] decided (Inceptless decision 2026-11-11 #5; T10; 2026-11-11 #12;
U6). Example: the keyset omits the new key, a context `weave.key.rotated` record supplies
its `new_public_key`, and a note signed by that key is verified — the note carries
`N_KEY_TOFU` and the report carries `L_KEY_TRUST_TOFU`. A **record** signature check is
context-trusted as soon as context material is used for it, even when its equation then
fails (§14.6). A **manifest** or supplied previous-manifest signature check contributes to
`L_KEY_TRUST_TOFU` only when the context material verified its equation (§11.5): a failed
manifest equation is reported as `E_MANIFEST_SIG_INVALID` (or `E_MANIFEST_CHAIN`) and adds no
limitation [S2/F42] decided by principle (Inceptless decision 2026-11-15 #8; S2).

| identifier | emitted if and only if |
|---|---|
| `L_OFFLINE_CONTEXT` | the target is a record or a container (not `vectors`): the verification context is the target plus the supplied keyset, and references outside it resolve as `missing` |
| `L_CHAIN_CLAIM_UNVERIFIED` | `level_claimed` is `L1` or `L2` (the internal-chain claim cannot be recomputed), regardless of later failures |
| `L_KEY_TRUST_TOFU` | at least one signature check in the report — a record signature, the manifest signature, or a supplied previous container's manifest signature verified at step (10) (§11.5, W1) — was context-trusted per the TOFU predicate above |
| `L_PREVIOUS_CONTENT_UNVERIFIED` | `--previous` was supplied, the previous-manifest-chain stage (§14.5 step (10)) ran, and the supplied previous's manifest signature verified under §11.5 (in the target container's verification context). This is the only criterion: it does not depend on the later checks of that stage (embedded manifest, digest comparison); it is not reported when no `--previous` was supplied, when the container pipeline stopped before step (10), or when the previous could not be read or verified (V3, W5) |
| `L_PREVIOUS_SIG_UNVERIFIED` | `previous_manifest` is non-null and the embedded previous manifest's own signature was not re-verified; this is reported even when a later container check fails, and is not reported when the manifest could not be parsed so that the previous manifest is not reachable. When a supplied `--previous` container's manifest signature verifies, that previous manifest's signature counts as re-verified and this identifier is **not** reported for it; `L_PREVIOUS_CONTENT_UNVERIFIED` is reported instead (V3) |
| `L_TSA_TRUST_UNVERIFIED` | at least one listed receipt is `present-unverified`: its structure and CMS signature pass, but it is not verified-and-trusted (no matching anchor, or its accuracy is unusable evidence per §12.2 check 13). A receipt rejected by a structural, format or CMS check reports its error code and does not by itself trigger this identifier (U7) |
| `L_ERASED_PLACEHOLDER` | the verified input (container or record target) contains a `weave.erased` placeholder; for a container, among the records that are verified — when the container pipeline stops before the per-record checks (`records: []`), no record is verified and it is not reported (S2-FIX1, §14.5) |
| `L_ERASED_STANDALONE` | the target is a single `weave.erased` record with no container context, so the §10.3 cross-checks could not be applied |
| `L_LABELS_ARE_CLAIMS` | the record target, or at least one record of the container, carries a `labels` member; for a container, among the records that are verified, as for `L_ERASED_PLACEHOLDER` (S2-FIX1) |
| `L_UNKNOWN_KIND_OPAQUE` | at least one record has an unregistered kind and final verdict `valid` (the same condition as `N_KIND_UNKNOWN_OPAQUE`) |
| `L_LABEL_PROPAGATION_UNCHECKED` | at least one derivation reference could not be resolved (the same condition as `N_LABEL_PROPAGATION_UNCHECKED`) |

A `vectors`-target report carries `limitations: []`: it verifies no record or container,
so none of the conditions above applies. The two notices that describe container-level
undetermined or retained state are reported
under the same if-and-only-if discipline: `N_READABLE_PRESENT` is emitted exactly when an
enumerated container contains a `readable/` entry (if entry enumeration fails before a
`readable/` entry is observed, it is not reported), and `N_PREVIOUS_SIG_UNVERIFIED` is
emitted exactly when `previous_manifest` is non-null and the previous signature was not
re-verified, including after a later container failure [T12] decided (Inceptless decision
2026-11-11 #5; T12).

### 14.10 Independence and vectors

Conformance is defined by the test vectors: every case declares its expected verdict,
errors and (where applicable) reference resolution, and an implementation conforms when it
matches all of them. Vector generation is independent of any verifier and expected outcomes
are authored separately; negative cases name the expected code. A second independent
implementation must pass the same vectors before version 1.0 [I4].

The `vectors` target compares each case's report against `expected.json` with exactly these
semantics (also stated in `vectors/README.md`):

- `verdict` compares exactly; `errors` and `notices` compare as sets (order is not
  meaningful).
- The `records` member is a per-`id` subset match: every listed record
  id must appear in the report, its `verdict` and `errors` compare exactly, and any other
  listed member is a recursive subset match. A list value in a subset match compares
  element by element and must have the same length as the report's list. An explicit empty
  `records` array asserts that the report carries **no** record entries at all, which is
  only correct for a failure in the pre-record container phase; a case whose failing check
  happens after record processing must expect the processed records instead.
- `expected_resolution` is matched as a map from the position in `records[0].refs` to the
  resolution state: every listed position must match the report's entry at that position,
  and the report may carry additional entries.
- `expected_container` is a recursive subset match against the report's `container`
  object: objects match by member (the report may carry more), arrays compare element by
  element recursively with the same length, and scalars and `null` compare exactly.
- `expected_input` is a recursive subset match against the report's top-level `input`
  object: objects match by member, scalars compare exactly, and an expected `null` matches
  only an actual `null`.
- `limitations`, when present, must equal the report's `limitations` array exactly.
  `notices_absent`, when present, lists notice codes that MUST NOT appear in the aggregated
  report: `container.notices` plus every `records[].notices`.
- For the `vectors` target, conformance is `mismatched == 0` and the report's `input`
  identity and per-case layout are implementation-defined (§14.6).

S16/F5, S16/F17 and the S14 `expected_input` extension fix these semantics; the case file
layout itself is specified in `vectors/README.md` [S16/F5][S16/F17][S14] decided
(Inceptless decision 2026-11-11 #2; S16/F5, S16/F17, S14).

Specification examples are additionally checked: every complete standalone JSON record
example in this specification and in the kind pages MUST pass `record <example> --keys
vectors/keys/keyset`; context-dependent examples are marked as such and container examples
are verified as containers; purely illustrative snippets are marked and skipped. The three
example markers and their handling are a non-normative tooling convention (PROVISIONAL,
Appendix A P11).

## 15. Security considerations

This section is informative except where it states a MUST.

1. **Canonicalisation is a security boundary.** Implementations MUST implement WR-CJ
   exactly (§1) and MUST NOT delegate the decision to a general JSON library without
   cross-checks. Duplicate-member rejection, the integer-only rule and the left-to-right
   first-violation classification of §1.9 are security requirements [C1][C2][C3][M-14].
2. **Signature domain separation.** The four domain prefixes (§2.1) prevent replay of a
   signature across object types and purposes; cross-purpose acceptance is a defect and is
   tested in both directions [C4][E6][S1].
3. **Ed25519 edge cases.** The complete decode procedure (§3.2), the point-based
   small-order predicate (§3.3), mixed-order rejection and the fixed order of §3.4 are
   mandatory. Omitting the `x = 0, x_0 = 1` rule or the small-order check enables the
   identity-key forgery; relying on a library that accepts mixed-order keys causes
   cross-implementation divergence [S1][Q1].
4. **Trust roots are local input.** Roots come only from the verifier's keyset
   (`--keys`), never from the container: a container that supplies its own self-signed
   human/organization declaration is `unverifiable` (`E_KEY_UNTRUSTED`) and cannot promote
   itself to a trust root, no matter what `recorded_at` it claims. In-context declarations
   can extend existing local trust through co-signatures but can never create it, and a
   declaration for an already-trusted key can never change its class or validity window
   (§5.3, §9.1): a different class is invalid with `E_KEY_CLASS_CONFLICT`. This is
   the structural defence against the self-attested-root attack; users should pin key ids
   out of band for high-value evidence, and reports mark context-accepted keys and
   untrusted self-attested declarations [E4][Q12][S1][R2].
5. **Compromise is not cured by backdating.** The `key-compromise` rule (§9.4) deliberately
   ignores claimed time; without a verified pre-compromise timestamp, a signature by a
   compromised key is invalid. This is the only honest offline treatment [E5][S2].
6. **Key lifecycle is evidence, not authority.** A revocation only helps if it is in the
   verification context; a rotation chain is never a shortcut to trust [E5][M-12].
7. **Rollback and truncation.** A single container proves only its own integrity; the
   previous-manifest chain detects modification of linked containers, while rollback or
   omission of newer containers is detectable only with an external anchor or an
   independently obtained latest digest [D1][D2].
8. **Replay and duplicate actions.** `actor.idempotency_key` lets importers deduplicate the
   same agent action; duplicates are reported with `N_IDEMPOTENCY_DUPLICATE` and are not
   invalid [Q17]. Records without such a key are not deduplicated by the verifier.
9. **Erasure is not global deletion.** An erased record remains referenceable by digest,
   and copies distributed before erasure cannot be recalled. The salt rule (§8.3) prevents
   brute-forcing deleted personal content from its digest when the salt is deleted with it
   [G3c].
10. **Local-only data.** The export refusal of §8.5 is a check, not a guarantee; a
    malicious exporter can produce a container that simply omits the `local-only` record.
    Importers should apply policy on top of verification [H2].
11. **Agent authorisation is only as good as the context.** A grant chain proves coverage
    with respect to presented records; a compromised agent key or a forged inclusion can
    extend apparent authority. Human keys signing human acts (§5.2), the every-stage grant
    requirement (§5.4) and the subset rule for delegation (§5.5.2) are the load-bearing
    rules [§8][S3].
12. **Timestamps prove anchoring, not truth.** A verified RFC 3161 token proves a TSA
    signed an imprint under the stated constraints; it does not prove content truth. Trust
    in the TSA is a local policy decision via `--tsa-trust` [D3][S5].
13. **Denial of service.** Size and resource limits (§13) bound hostile containers; a
    verifier MUST NOT crash or unboundedly decompress on a zip bomb, and MUST NOT overflow
    the stack on deeply nested JSON or deeply nested SPDX licence expressions
    (`MAX_JSON_DEPTH`, `MAX_LICENCE_NESTING`, §13). The timestamp accuracy rules keep
    rescuing comparisons inside fixed-width arithmetic and make an over-bound receipt
    unusable evidence (unverifiable), never a silently accepted rescue [S3][S11][T3].
14. **Plain files only.** Containers are ordinary files with no executable content; a
    verifier MUST NOT execute or follow hints, URLs or `readable/` content.
15. **Manifest signer binding is not established offline.** A manifest signature proves
    which key signed the manifest bytes; H0 does not require that key to be the key named by
    `manifest.origin.instance` (§11.3). A consumer that needs the publisher identity to be
    the origin instance must check the binding itself, against a key id pinned out of band
    [T11; `docs/open-questions.md` §6 entry 17] decided by principle (Inceptless decision 2026-11-11 #5; T11).

## 16. Governance, repository and implementation requirements

- **Repository and identity**: the specification repository is `haeliotang/hyphaweave`; the
  format identifier remains `weave-record/1` independently of the project name [K1].
- **Licences**: specification prose CC BY 4.0; code, schemas and test vectors Apache-2.0
  [K2].
- **Adapters live in project repositories**; this repository contains only the
  specification, schemas, test vectors and reference verifiers [A1a].
- **Two independent implementations**: the H0 Python verifier and a second
  independent verifier must both pass the same test vectors before version 1.0 [I4].
- **Acceptance cases**: `weave-record/1` v0.1 is accepted only when the J1
  (Koinoweave → Traceweave) and J2 (Axioweave → Koinoweave) round trips pass with the
  receiving side verifying the container; adapters live in the projects' repositories
  [J1][J2][A1a].
- **Never abandon old versions**: a verifier MUST continue to verify older versions of the
  format and older registered kinds; frozen regression vectors encode this commitment [K3].
- **Offline verification**: this repository also provides a manual verification procedure
  using only common tools (`sha256sum`, OpenSSL 3.x, a JSON viewer), performed on a sample
  L0 container [I4].
- **Change control**: new algorithms, relations and kinds go through the written proposal
  and approval process of §0.3 and §7.6 [K4].
- **Frozen regression set and conformance tooling**: the candidate frozen vector set is
  `vectors/frozen/v0.1-candidate/` and becomes final only after the J1/J2 acceptance cases
  pass; conformance gates use real source-level check ablation and per-byte bit flips
  [S6][S7] decided (Inceptless decision 2026-11-10 #34; S6/S7). These obligations concern
  the vector and tooling areas of the repository, not this document's normative rules.

## Appendix A — Rulings and PROVISIONAL items

### A.1 Rulings implemented by this specification

Every entry below is normative and is tagged `decided (Inceptless decision 2026-11-10 #34)`
at its location in the body of this document.

| ruling | topic | normative location |
|---|---|---|
| S1 | complete clause 5.1.3 of RFC 8032 decoding, point-based small-order test, mixed-order rejection, fixed verification order and per-step codes | §2.5, §3.2–§3.4 |
| S2 | compromise revocation: a signature by a compromised key is valid only with a verified trusted timestamp whose `genTime + accuracy` is strictly before the effective time; untrusted receipts make it unverifiable, no timestamp evidence makes it invalid | §9.4, §12.5–§12.6 |
| S3 | delegated sub-grants must be subsets of their parent (kinds, actions, scope, window); no privilege escalation | §5.5.2 |
| S4 | key declarations must be self-signed; automated keys need the owner's cosignature; human/organization declarations are trusted only through the local keyset or a trusted cosignature chain (revision 2 refines the root rule) | §5.3, §9.1 |
| S5 | the RFC 3161 verification profile is a fixed MUST table; L2 is reported as L0 plus a verified anchor | §11.4, §12 |
| S6 | the frozen set becomes `vectors/frozen/v0.1-candidate/` pending J1/J2 acceptance | outside this document (vectors) |
| S7 | gate 3 uses real source ablation and per-byte bit flips | outside this document (tooling) |
| S8 | no invented decisions: rulings are tagged, everything else is PROVISIONAL or absent | whole document |
| Q1 | strict Ed25519 profile; mixed-order public keys rejected; Wycheproof `acceptable` rejected | §3.4, §3.7 |
| Q2 | base64url unpadded, strict decoding | §2.6 |
| Q3 | salt: 16 random bytes, required for personal/local-only, randomness not testable | §4.1, §8.3 |
| Q4 | no Unicode normalisation | §1.2–§1.3 |
| Q5 | size and resource limits | §13 |
| Q6 | timestamp literal grammar | §2.8 |
| Q7 | closed `rel` vocabulary: eight Inceptless words plus `supersedes` and `correction_of` | §6.2 |
| Q8 | manifest digest lives in the attestation file, outside the signed manifest | §2.4, §11.3 |
| Q9 | L1 chain head is an unverified claim; `level_verified` stays L0 | §11.4 |
| Q10 | grant revocation field, default revocation authority, no arbitrary human/organization revocation | §5.5.1, §5.5.4 |
| Q11 | revoked/expired → unverifiable, wrong-grantee/kind/action → invalid; `effective_at <= recorded_at` is revoked | §5.4, §5.5.4, §9.6 |
| Q12 | trust on first use, no pinning, earliest valid declaration governs | §5.3 |
| Q13 | unknown signature algorithms ignored; no verifiable required signature → unverifiable | §2.7, §3.6, §4.3–§4.4, §6.5, §11.3 |
| Q14 | SPDX expressions syntax-checked only | §8.7 |
| Q15 | `weave.erased` special shape and standalone verdict `erased` | §4.5, §10 |
| Q16 | strictest label propagation; absent sensitivity on derived data is a downgrade | §8.4 |
| Q17 | idempotency duplicates are a notice | §5.4 |
| Q18 | test-only `WEAVE_VERIFY_SKIP_CHECKS` hook, echoed in the report | §14.7 |
| Q19 | `readable/` ignored and unhashed | §11.8 |
| Q20 | declared validity windows checked in both directions (`valid_from`, `valid_until`) | §9.4 |
| Q21 | attestation file always carries `timestamps` (possibly empty) | §11.3 |
| Q22 | manifest entry `id`/`kind` must equal the record content | §11.2.1, §11.6 |
| Q23 | blobs are sha256-only; blob problems are `E_MANIFEST_BLOB` | §11.7 |
| Q24 | deterministic size-limit → error-code mapping | §13 |
| Q25 | deterministic split between `E_CONTAINER_ENTRY` and `E_CONTAINER_ZIP` | §11.9 |
| Q26 | deterministic dependency resolution; digest references are acyclic by construction | §6.4 |
| Q27 | report input identity for directory containers and the vectors target | §14.6 |
| Q28 | key-lifecycle records are exempt from the agent-only envelope members | §4.2 |
| Q29 | `labels.sensitivity` is optional | §8.1 |
| Q30 | explicit kind-page signer rules are authoritative for the seven signer-constrained kinds | §5.1–§5.2 |
| Q31 | kind-specific signer codes take precedence over `E_SIG_REQUIRED` when a known-signature exists but the required signer is wrong | §4.4, §14.5 |
| Q32 | erased references are not kind-checked; erasure digest/attestation code split | §4.5, §6.3, §10.3 |
| Q33 | trust roots come only from the local keyset (`--keys`); a container/target self-signed human/organization declaration is `unverifiable` (`E_KEY_UNTRUSTED`) with `N_SELF_ATTESTED_ROOT_KEY` and is never a root; no time-ordered root selection | §5.3, §9.1 |
| R1 | the whole grant chain is judged at the verified record's claimed `recorded_at` (a grant record itself uses its own) | §5.4, §5.5.2 step 6, §9.7 |
| R2 | roots come only from the local keyset; container/target declarations are `E_KEY_UNTRUSTED` unless chained to a trusted root; keyset roots are never invalidated by container declarations | §5.3, §9.1, kinds/weave.key.declared |
| R3 | compromise rescue requires `genTime + accuracy < T` (strict; accuracy in microseconds, absent = 0) | §9.4, §12.2 check 13 |
| R4 | receipts present but untrusted → `unverifiable` `E_TS_UNTRUSTED`; no timestamp evidence → invalid `E_KEY_COMPROMISED` | §9.4, §12.5 |
| R5 | an owner whose class is not human/organization → invalid `E_KEY_OWNER_MISSING` | §9.1 rule 3 |
| R6 | `genTime` conversion cross-reference fixed; vector inventory updated | §2.8, §12.2 |

The following rows are fixed by Inceptless decision **2026-11-11 #2** and are normative at
the locations given.

| ruling | topic | normative location |
|---|---|---|
| S1 | a keyset-trusted key's class and validity window cannot be overridden by a container/target redeclaration; a different class is invalid with `E_KEY_CLASS_CONFLICT` | §5.3, §9.1, registry |
| S2 | revocation effects are order-independent and include keyset records; the retired/other and compromise families are independent (a retired/other hit is invalid `E_KEY_REVOKED` and never rescuable); the compromise family uses the earliest `T` for rescue | §9.4, §14.1 |
| S3 | nesting limits: `MAX_JSON_DEPTH` → `E_JSON_SIZE`, `MAX_LICENCE_NESTING` → `E_ENV_LICENCE`, no stack crash | §1.9, §8.7, §13 |
| S4 | bounded reads: per-class read limits, central directory before decompression, `readable/` never decompressed or CRC-checked | §11.1, §11.8, §11.9, §13 |
| S5 | ZIP64 MUST be accepted; prefix bytes, archive comments and trailing bytes are `E_CONTAINER_ZIP` | §11.9 |
| S6 | `--previous` requires a non-null `previous_manifest`; null/mismatch is `E_MANIFEST_CHAIN` | §11.5 |
| S7 | the differential-fuzz defect classes: empty `sigs` on a required record, unverifiable manifest signature continuation, unknown-algorithm self-signature handling | §4.3, §4.4, §9.1, §14.5 |
| S8 | the fourteen ambiguity rulings listed in `docs/open-questions.md` (envelope order, nested codes, `-0`, manifest multi-error, report construction, keyset boundary, P10, etc.) | §1.6, §1.9, §4, §4.2, §4.4, §7.3, §11.9, §14.1, §14.4–§14.6, §14.9 |
| S9 | a grant may be issued for future effect: a grant record is not judged against its own window/revocation at its own `recorded_at` | §5.4, §5.5.2, §9.7 |
| S10 | a grant-revocation record must itself be valid; grant-chain and rotation-step bounds are inclusive (8 links / 8 steps) | §5.5.2, §5.5.4, §9.6, §13 |
| S11 | timestamp accuracy bound `MAX_TS_ACCURACY` and checked arithmetic; overflow is `E_TS_SCHEMA` | §9.4, §12.2, §13 |
| S12 | limitations are a closed identifier list; report-construction details (including serializer micro-decisions) are pinned in §14.6 | §14.6, §14.9, registry |
| S13 | test hook reachable only through `--test-hooks`; unknown token is a usage error; exit code 3 for disabled checks | §14.1, §14.7, §14.8 |
| S14 | directory-container `input` is the raw manifest identity, and `null` when the manifest is absent/unreadable/oversized | §14.6 |
| S15 | `recorded_at`/`occurred_at` definitions, `rel` direction with examples, salt stability | §2.8, §4.1.1, §6.2, §8.3 |
| S16 | the F1–F17 dispositions (all adopted; F2 mandatory) — per-finding disposition table in `docs/open-questions.md` §6 | whole document; `docs/open-questions.md` §6 |
| S17 | frozen candidate-set regeneration stays in the vectors area | outside this document (vectors) |

The following rows are fixed by Inceptless decision **2026-11-11 #5** (S1-FIX1, T1–T17)
and are normative at the locations given.

| ruling | topic | normative location |
|---|---|---|
| T1 | a missing or malformed `body.public_key` is invalid `E_KEY_PUBLIC_KEY`, before `E_KIND_BODY_SCHEMA` and any trust judgement | §9.1, §14.5, `weave.key.declared.md` |
| T2 | retired/other and compromise revocations are evaluated independently; the stricter result wins; a retired/other hit is `E_KEY_REVOKED` and never rescuable | §9.4, `weave.key.revoked.md` |
| T3 | TSA accuracy: component range is a format error `E_TS_SCHEMA`; over-bound/overflow accuracy makes a receipt unusable evidence (`E_TS_UNTRUSTED`, container unverifiable, never rescuing); structure/CMS checks precede the accuracy cap; `genTime` truncated to ms for rescue | §9.4, §12.2, §12.5, §13 |
| T4 | any-class keyset declaration governs class and window (only human/organization establish roots); conflicting keyset declarations are a usage error; deterministic earlier = `(recorded_at, record digest)` | §5.3, §9.1, §14.1 |
| T5 | record `sigs` is structurally 0–16 entries; required signing is §4.4's rule | §4.1, §4.3 |
| T6 | the verifier parses the zip structure itself: local/central field agreement (including data descriptors), no gaps or overlaps, EOCD/ZIP64 counts and framing, `readable/` path/type checks | §11.9, registry |
| T7 | the frozen candidate set only grows (vectors area) | outside this document (vectors) |
| T8 | depth counting when the verified record is itself a grant: its own link is not part of the chain | §5.5.2 step 7 |
| T9 | a revocation record takes effect only if it is itself valid; deterministic `(recorded_at, record digest)` order; self-revocation exempt | §9.5, `weave.key.revoked.md` |
| T10 | one TOFU predicate shared by `N_KEY_TOFU` and `L_KEY_TRUST_TOFU`; the manifest signature counts for the limitation | §14.6, §14.9, registry |
| T11 | the five principle decisions recorded in `docs/open-questions.md` §6 entries 15–19; internal-document references removed | whole document |
| T12 | limitation and notice emission is if-and-only-if; `N_READABLE_PRESENT`/`N_PREVIOUS_SIG_UNVERIFIED` retention and "undetermined means not reported" | §14.9, §11.5, §11.8 |
| T13 | rotated key-material structural errors (`E_KEY_ROTATION_KEYS`) precede signature verification | §9.2, §14.5 |
| T14 | member ordering is UTF-16 code-unit order only | §14.6 |
| T15 | the directory-container total byte cap counts only the files actually read | §13, §11.8, §11.9 |
| T16 | container report shape for an oversize in-container file follows the §14.5 stage in which it is detected; `records: []` only before step (7) | §14.5, §14.6 |
| T17 | the remaining review items (grant-revocation target action, late-recorded grants, unverifiable cited grant, UTF-8 precondition, previous-manifest size mapping, manifest signer trust, `--previous` path semantics, token parsing, relation direction, Appendix C/D) | §1.9, §5.5.2, §5.5.4, §6.2, §11.3, §11.5, §13, §14.6, §14.7, Appendix C |

The following rows are fixed by Inceptless decision **2026-11-11 #12** (S1-FIX2, U1–U12)
and are normative at the locations given.

| ruling | topic | normative location |
|---|---|---|
| U1 | a supplied previous container (directory or zip) is parsed exactly like a `container` input; any read/structural failure of it is `E_MANIFEST_CHAIN`, not `E_CONTAINER_ZIP` | §11.5 |
| U2 | container limits by form: zip declared uncompressed total excluding `readable/**`, entry count including all entries; directory read bytes; over-limit is `E_CONTAINER_SIZE` | §13, §11.8, §11.9 |
| U3 | the self-revocation exemption only removes the revocation's own effect; prior valid revocations still apply, so an already-revoked key cannot emit a valid new self-revocation | §9.5, `weave.key.revoked.md` |
| U4 | the governing class is determined before and independently of the trust closure: keyset declaration first, otherwise the structurally valid declaration with the smallest `(recorded_at, record digest)`; different class is `E_KEY_CLASS_CONFLICT`; non-monotonic-closure example | §5.3 |
| U5 | "governing class" is the one term used in §5.3, §9.1, the kind page and the registry | §5.3, §9.1, `weave.key.declared.md`, registry |
| U6 | the TOFU predicate includes key material from a context `weave.key.rotated` record; `N_KEY_TOFU`/`L_KEY_TRUST_TOFU` follow it | §14.9, §14.6, registry |
| U7 | `L_TSA_TRUST_UNVERIFIED` iff at least one listed receipt is `present-unverified`; a receipt invalid by structure/CMS does not by itself trigger it | §14.9 |
| U8 | the records-listing phase reports all independent violations together, including `E_JSON_SIZE` for an oversize record file | §14.5 |
| U9 | single-volume archives only: EOCD/ZIP64 disk-number fields and the locator total-disk count are validated | §11.9 rule 3 |
| U10 | the `docs/open-questions.md` references point to §6 entries 15–19 (no §7) | whole document |
| U11 | H1-FIX1 hand-off corrections (kind pages, §4.1.1, corrected vector id) | report/hand-off; §7.7 makes kind pages normative |
| U12 | the low-item wording decisions: data-descriptor local fields, `readable/` rule-1 applicability, physical offset order, two EOCD counts, ZIP64 sentinel rules, slash-name-with-data, directory/zip limit wording, revocation-order principle entry, "signature's claimed `recorded_at`", unified declaration-resolution sentence | §11.9, §13, §9.4, §5.3, §9.1, `weave.key.declared.md`, `docs/open-questions.md` §6 entry 20 |

The following rows are fixed by Inceptless decision **2026-11-11 #14** (S1-FIX3, V1–V8)
and are normative at the locations given.

| ruling | topic | normative location |
|---|---|---|
| V1 | a member's decompression failure is a structural failure, never a crash; target and previous containers use the same member-reading rule; a previous-container failure is `E_MANIFEST_CHAIN` | §11.9, §11.5 |
| V2 | any DER decoding or receipt-structure failure, wherever discovered (including signed-attributes re-encoding), is `E_TS_SCHEMA` (check 1); strict canonical DER and the version rules | §12.2, §14.6, registry |
| V3 | a supplied previous container links the chain only: the two read members, regular-file/unique-member rules, everything else unverified, `L_PREVIOUS_CONTENT_UNVERIFIED` (the keyset-only signature verification of V3 is superseded by W1) | §11.5, §14.6, §14.9, registry |
| V4 | the governing class is determined from structurally valid declarations per §5.3 (no "semantically valid declarations govern class" wording remains) | §14.1, Appendix D |
| V5 | `public_key` presence/encoding is structural; a declaration without a valid `public_key` never governs a class; in a keyset it is a usage error; rotated key-material encoding/length is structural too | §5.3, §14.1, `weave.key.declared.md`, `weave.key.rotated.md`, registry |
| V6 | central-directory "version needed to extract" ≤ 63 (local-header version unconstrained); every per-entry central-directory disk start = 0; else `E_CONTAINER_ZIP` | §11.9 rules 1/3 |
| V7 | directory entry count includes `manifest.json`; entry-count/declared-total limits are checked before the remaining zip structural rules (over-limit wins); `record_count` keeps the manifest count after the manifest structure stage | §13, §11.9, §14.6 |
| V8 | the permanent crash-fuzz gate is tooling/CI, not a format rule | outside this document (tools, CI) |

The following rows are fixed by Inceptless decision **2026-11-11 #16** (S1-FIX4, W1–W11)
and are normative at the locations given.

| ruling | topic | normative location |
|---|---|---|
| W1 | a supplied previous container's manifest signature is verified in the **target** container's verification context: §11.3 required-key material of the target, the key trusted in the target's final trust closure, §9.4 key state at the previous `created_at` (a compromise judged by its time against `created_at`, X2); the previous container's own declarations never count | §11.5, §14.1, §14.9, registry |
| W2 | §11.9 rules 1–4 and the §13 limits apply to the framing of the whole zip, every entry, for a supplied previous zip as for a target zip; only name safety, duplicate names, CRC and `readable/` rules are not applied to the unread previous members | §11.5, §11.9 rule 4 |
| W3 | check 1 is a real DER check: universal DER rules over every TLV (1a), schema decoding (1b), re-encoding equal to the input with every SET OF sorted and no DEFAULT encoded (1c), versions (1d), certificate decoding (1e); the TSTInfo gets 1a–1c on its own | §12.2, registry |
| W4 | `--keys`, `--tsa-trust` and the `--previous` path are operator inputs checked before verification; any read/decode failure is a usage error (exit 2) naming the file | §14.1, registry |
| W5 | a container-level invalid error at steps (8)–(10) stops the pipeline (no later code, notice, limitation or timestamp entry); the order inside step (10); `L_PREVIOUS_CONTENT_UNVERIFIED` has one criterion | §11.5, §14.5, §14.6, §14.9 |
| W6 | the complete timestamp check order: file checks, then chain shape (check 14), then checks 1–13 and 15 per receipt in chain order; one code per receipt; an algorithm/key-type mismatch is check 10 | §12.2, registry |
| W7 | the zip check order: locate the EOCD (prefix/trailing bytes) → parse the central directory → §13 limits (`E_CONTAINER_SIZE`, stop) → every remaining structural rule | §11.9, §13, registry |
| W8, W9, W11 | gate and vector coverage (byte-flip `.tsr` exemptions, V3 core checks pinned by vectors, crash-fuzz seeds) are tooling, not format rules | outside this document (tools, vectors) |
| W10 | every `ed25519` attestation entry is judged (multi-signature attestation); keyset entry names and non-regular entries; wording of `--previous` | §11.3, §14.1 |

The following rows are fixed by Inceptless decision **2026-11-12 #1** (S1-FIX5, X1–X5;
row X6 by decision 2026-11-12 #2, row X7 by decision 2026-11-12 #3)
and are normative at the locations given. They amend the W1 and W3 rows above where they
differ.

| ruling | topic | normative location |
|---|---|---|
| X1 | check 1's DER rules come from X.690 and the ASN.1 module definitions only: the DEFAULT components and their encodings are listed (ESSCertIDv2's default is `{id-sha256}` without parameters, so `{id-sha256, NULL}` is encoded); open-type values are judged by their TLV framing only; time values are compared as their raw DER form; the high-tag-number form follows X.690 §8.1.2.4 | §12.2, registry |
| X2 | on the previous link a `key-compromise` revocation is judged like a retired one, against the previous `created_at`: `created_at >= T` breaks the link, an earlier `created_at` links | §11.5, registry |
| X3 | operator paths are examined with `lstat` before opening; a FIFO, device or socket is a usage error; `--tsa-trust` is read with the bound `MAX_TIMESTAMP_BYTES` | §14.1 |
| X4 | gate coverage (the independent DER judge) is tooling, not a format rule | outside this document (tools) |
| X5 | §11.5 rules 1–2 wording (an invalid rotation record supplies no key material; keyset declarations trusted through their owner); documentation | §11.5 |
| X6 | the `parameters` of the signer's `digestAlgorithm` (SHA-2: absent or `NULL`) and `signatureAlgorithm` (`rsaEncryption`: `NULL`; sha*WithRSAEncryption: absent or `NULL`, as corrected by X7; ECDSA: absent) have a fixed form; any other form is `E_TS_SCHEMA` (decision 2026-11-12 #2) | §12.2, registry |
| X7 | time forms matched against the whole content (a trailing line feed is a violation); sha*WithRSAEncryption parameters absent or `NULL`; exactly one `SignerInfo`; 1e decodes the signer certificate only, every other certificate is an open type (decision 2026-11-12 #3) | §12.2, registry |

The following rows are fixed by Inceptless decision **2026-11-15 #8** (the S2 round of
revision 3). Each closes an H1 finding (`docs/h1-findings.md`) and is **decided by
principle**: where the text admitted two readings, the more conservative one was taken, and
the two readings, the choice and the reason are recorded in `docs/open-questions.md` §7.
Questions the principle does not settle are listed there as open, for the founder.

| ruling | topic | normative location |
|---|---|---|
| S2/F38, F61-1 | §9.4 judges every signature of a `weave.key.declared` or `weave.key.rotated` record (window, retired revocations, compromise rescue); a declaration of a compromised key is rescued only by a verified, trusted, usable receipt; the record's key facts are still supplied for §5.3 | §5.3, §9.4, `weave.key.declared.md`, registry |
| S2/F39, F50 | a malformed declared `public_key` is decided before key resolution: `sigs` is `[]`, and it wins over every other body defect | §14.5, §14.6 |
| S2/F42 | a record signature check is context-trusted even if its equation fails; a failed manifest or previous-manifest equation adds no `L_KEY_TRUST_TOFU` | §14.9 |
| S2/F44, F58 | record identity is `(origin.project, origin.instance, id)`; a structurally failed record with a well-formed `origin` and `id` is present (`unverifiable`), one with a malformed `origin` or `id` has no identity (`missing`) | §6.3 |
| S2/F45, F67 | the agent-only actor members are decided in the presence phase; a `sigs` member of the wrong JSON type is `E_ENV_SIGS`, before any member's grammar | §4.3, §14.5 |
| S2/F46, F69 | §4.4 step 5 is decided by the required signer key and applies to the signer-constrained kinds; a rotation's explicit key material declares its keys | §4.4, registry |
| S2 (signature entries) | step (4) resolves every entry before any equation; every entry is judged and reports its state (the code choice was corrected by S2-FIX1 T2: invalid first) | §14.5, §14.6, registry |
| S2/F48 | the §10.3 rules are evaluated independently and reported together; a malformed placeholder is not a placeholder | §10.3, registry |
| S2/F54 | an unlisted `.tsr` in `signatures/` is `E_TS_FILE`, whatever the level | §11.3, §12.2, registry |
| S2/F55, F60 | a `records/` file is subject to `MAX_RECORD_BYTES` and `MAX_JSON_DEPTH` whether or not it is listed; both are `E_JSON_SIZE` in the listing phase | §14.5, registry |
| S2/F57, F66 | 1a: universal tag 0 never occurs, ENUMERATED follows INTEGER, EXTERNAL/EMBEDDED PDV/CHARACTER STRING are constructed-only (the "list of 1a rules is closed" sentence was withdrawn by S2-FIX1 T3) | §12.2 |
| S2/F61-3 | rotation key ids are body-schema members checked before the key-material rule | §14.5, `weave.key.rotated.md` |
| S2/F62, F63 | 1e is the module walk plus the RFC 5280 version constraints; open types stay open in the signer certificate; `--tsa-trust` anchors are judged by 1e | §12.2, §14.1 |
| S2/F68 | §5.5.2 step 6 covers the whole chain, links beyond the depth bound included, before step 7 | §5.5.2 |
| S2/F69 | the §5.4 coverage list is the evaluation order | §5.4 |

The following rows are fixed by Inceptless decision **2026-11-15 #18** (S2-FIX1, the first
revision of the S2 round): the founder's rulings Q1–Q5 on the questions §7.2 of
`docs/open-questions.md` left open (**decided**), and the review items T1–T8, each
**decided by principle** ("invalid beats unverifiable", or the more conservative reading)
and recorded in `docs/open-questions.md` §7.3.

| ruling | topic | normative location |
|---|---|---|
| S2-FIX1/Q1 | an erasure's authorising grant present but itself invalid is `E_ERASE_ACTOR`; absent, outside its window, revoked or too deep gives the grant codes (unverifiable); order inside step (7) | `weave.erasure.md`, registry |
| S2-FIX1/Q2 (T1) | only the subject key's own signature (a declaration's `body.key`, a rotation's `new_key`) is exempt from §9.4 when a key-lifecycle record's admission is decided; a cosignature or old-key signature that fails §9.4 leaves the record without material and trust | §5.3, §9.4, `weave.key.declared.md`, `weave.key.rotated.md` |
| S2-FIX1/Q3 | inside step (7): the kind's record-local rules, the signer rule, then the rules that consult other records; the §4.4 step-5 outcome only after every other step-(7) rule; no `N_LABEL_PROPAGATION_UNCHECKED` on a record that fails step (9) | §4.4, §14.5, kind pages, registry |
| S2-FIX1/Q4 | check 10: RSA modulus 2,048–8,192 bits, odd `e` with 65,537 ≤ `e` < 2^256; ECDSA `Ecdsa-Sig-Value` strict DER, `r`, `s` in [1, `n` − 1] | §12.2, registry |
| S2-FIX1/Q5 | §5.5.2 steps 1–5 are walked beyond the depth bound too; the walk is limited only by cycle detection | §5.5.2, `weave.grant.md` |
| S2-FIX1/T2 | across signature entries an invalid outcome decides before an unresolved key's `E_KEY_UNKNOWN` | §4.4, §14.5 |
| S2-FIX1/T3 | 1a is X.690 for every universal tag number, listed tag by tag (REAL, RELATIVE-OID, primitive-only and constructed-only types, string units, §11.4 conservatively, TIME and DURATION rejected; the string and date rules revised by S2-FIX2/U4) | §12.2, registry |
| S2-FIX1/T7 | §0.3 registry numbering follows the registry's own history; §4.4 step 5 is reached only after §14.5 step (4) | §0.3, §4.4 |
| S2-FIX1/T8 | a root regular file named `readable` is `E_CONTAINER_ENTRY`; no `N_READABLE_PRESENT` after a zip-structure failure (narrowed by S2-FIX2/U7); `L_ERASED_PLACEHOLDER` and `L_LABELS_ARE_CLAIMS` only for verified records; §11.5 W1 rule 2 with no trust root keeps `E_MANIFEST_CHAIN`, with advice to recipients | §11.5, §11.8, §14.9, registry |

The following rows are fixed by Inceptless decision **2026-11-15 #22** (S2-FIX2, the second
revision of the S2 round): the founder's ruling Q6 (**decided**) and the narrow review's
items U1 and U3–U7, each **decided by principle** (U1 completes Q1; U5 applies the T2
principle to the manifest signature; U4 and U7 correct S2-FIX1's T3 and T8 readings; U6
changes wording only). The founder can overturn the items decided by principle.

| ruling | topic | normative location |
|---|---|---|
| S2-FIX2/U1 | a program's or device's `body.basis` grant chain is judged at the erasure's `recorded_at`, like an agent's `actor.grant` (expired/revoked → the grant codes) | `weave.erasure.md`, registry |
| S2-FIX2/U2 (Q6) | §5.5.2 step 1 in two tiers: a parent or cited grant present but itself invalid → `E_GRANT_GRANTER` (invalid); absent or present but not valid otherwise → `E_GRANT_UNRESOLVED`; an invalid link beyond the depth bound now reaches the citing record as invalid | §5.4, §5.5.2, `weave.grant.md`, registry |
| S2-FIX2/U4 | 1a: no ESC in NumericString, PrintableString, IA5String, VisibleString, UTF8String; the ISO 2022 register types judged by §11.4 and §8.23.5.4 from the Table 3 defaults instead of rejecting every ESC; DATE, TIME-OF-DAY, DATE-TIME, OID-IRI, RELATIVE-OID-IRI rejected with TIME and DURATION (stricter than X.690) | §12.2, registry |
| S2-FIX2/U5 | every manifest signature entry is judged; an entry of a required key that fails the equation decides `E_MANIFEST_SIG_INVALID` before an undeclared key's `E_KEY_UNKNOWN`, whatever the order; so does an invalid §9.4 outcome of a verified entry's key (its §9.4 code; decision 2026-11-15 #32) | §11.3, registry |
| S2-FIX2/U6 | §11.5 W1 rule 1 states the verdict rule of X5 as stricter than §5.3 instead of "as in §5.3" (no change of behaviour) | §5.3, §11.5 |
| S2-FIX2/U7 | `N_READABLE_PRESENT` is withheld only when the archive fails in phases 1–4 of the zip check order; a member-level failure after the entries were enumerated still reports it | §11.8, registry |

### A.2 PROVISIONAL implementation shapes

The following are implementation shapes rather than wire-format rulings. The rule text is
normative in this document, but the shape itself was not decided by the ruling document and
is recorded as PROVISIONAL in `docs/open-questions.md`. A verifier MUST follow the shape
stated here; a later ruling may change it.

P1 and P2 (time-ordered root selection and its tie-break) are **resolved by decision
2026-11-10 #42 (R2)** and are no longer provisional: roots come only from the local keyset
and no time-ordered root selection exists. P8 (the "earliest verified `genTime`" rescue
comparison) is **resolved by decision 2026-11-10 #42 (R3)**: the rescue rule is now the
strict `genTime + accuracy < T` comparison of §9.4. P3 (delegation-chain depth) is
**resolved by decision 2026-11-11 #2 (S10)** — the bound of 8 links is now fixed in §5.5.2
and §13, not provisional. P10 (the human-signature notice precedence) is **resolved by
decision 2026-11-11 #2 (S16/F6)** — §4.4 and §14.5 state the rule. P7 is narrowed: the
record/container report field shapes are now normative in §14.6, while the `vectors` target
per-case layout and input identity are explicitly implementation-defined (S8⑬/F5).

| id | item | normative location |
|---|---|---|
| P4 | revocation-authority walk over explicit rotation successors: the walk order within the fixed bound of 8 rotation steps (§5.5.4) | §5.5.4 |
| P5 | exact precedence order among the delegation-chain error codes | §5.5.2 |
| P6 | renewal-chain representation (`timestamps[].renews`, the `SHA-256(previous receipt ‖ manifest digest)` imprint formula, single chain) | §11.3, §12.4 |
| P7 | `vectors`-target per-case layout and input-identity representation (implementation-defined, deterministic, path-free; not compared across implementations) | §14.6, §14.10 |
| P9 | `scope` compared as a set of strings for delegation subsetting | §5.5.2 |
| P11 | example-classification annotations used by the specification-example checker (non-normative tooling convention) | §14.10 |
| P12 | delegation is reachable only for `agent` granters: a `program`/`device` grant record is `unverifiable` because the envelope forbids `actor.grant` on those actor types | §5.4, §5.5.2 |

## Appendix B — Decision-draft coverage map

| decision | where specified in this document |
|---|---|
| C1 | §1.1–§1.7 |
| C2 | §1.6 |
| C3 | §1.4 |
| C4 | §2.1–§2.3 |
| C5 | §1.8 |
| B1 | §4.1 (`id`), §2.7 |
| B2 | §4.1 (`origin`), §6.1 |
| B3 | §2.7 |
| B4 | §6.1 |
| B5 | §6.3 |
| E1 | §3, §4.3, §15 |
| E2 | §4.2, §5.1 |
| E3 | §2.5 |
| E4 | §5.3, §9 |
| E5 | §9, §5.5 |
| E6 | §2.2, §2.3, §4.4 |
| F1, F2, F4 | §2.8, §4.1 |
| F3 | §6 |
| G1 | §4.1 (`stage`) |
| G3, G3a–G3e, G4 | §4.5, §10 |
| H1 | §8.1, §8.7 |
| H2 | §8.4, §8.5 |
| H3 | §8.6, kind pages for consent |
| I1 | §11.1, §11.6–§11.9 |
| I2 | §2.4, §11.3 |
| I3 | §11.10 |
| I4 | §14, §16 |
| A1, A1a–A1d | §0.1, §10.6, §11.11, §16 |
| A1c | §11.4, §12 |
| D1, D2 | §11.5 |
| D3 | §12 |
| D4 | §11.11 |
| K1, K2 | §16 |
| K3 | §0.3, §7.3–§7.5, §11.2, §16 |
| K4 | §0.3, §7.6 |
| J1, J2 | acceptance cases outside this document; referenced in the status block and §16 |
| correction v0.1.1 | §2.5 |

## Appendix C — Closed vocabularies (normative summary)

| vocabulary | values | where |
|---|---|---|
| `format` | `weave-record/1` | §4.1, §11.2 |
| `stage` | `proposed`, `accepted`, `rejected`, `withdrawn`, `superseded` | §4.1 |
| `actor.type` | `human`, `agent`, `program`, `device`, `organization` | §4.2 |
| `origin.project` | `^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`, ≤64 bytes | §4.1 |
| kind name | `^[a-z][a-z0-9]*(?:[.-][a-z][a-z0-9]*)*$`, ≤128 bytes | §7.1 |
| registered kinds | the eight `weave.*` kinds of §7.2 | §7.2 |
| `rel` | `derived_from`, `handed_off_to`, `receipt_of`, `executed_as`, `assessed_by`, `compensated_by`, `migrated_from`, `reshaped_from`, `supersedes`, `correction_of` | §6.2 |
| resolution state | `found`, `moved`, `missing`, `erased`, `unverifiable` | §6.3 |
| signature `alg` | `^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`, ≤32 bytes; `ed25519` defined by H0 | §4.3 |
| `labels.sensitivity` | `public`, `internal`, `personal`, `local-only` | §8.1 |
| `labels.consent` target kind | `weave.consent.granted`, `weave.consent.revoked` | §8.6 |
| `weave.key.revoked.reason` | `key-compromise`, `retired`, `other` | §9.3 |
| `weave.grant.action` | `grant`, `revoke` | §5.5 |
| `weave.grant.actions[]` | `propose`, `accept`, `reject`, `withdraw`, `supersede`, `erase`, `grant` | §5.5.1 |
| `weave.key.declared.key_type` | `human`, `agent`, `program`, `device`, `organization` | §9.1 |
| `weave.erasure.reason` | `data-subject-request`, `legal`, `safety`, `mistaken-inclusion`, `retention-expired`, `other` | §10.2 |
| `manifest.level` | `L0`, `L1`, `L2` | §11.2 |
| `chain.algorithm` | `sha256` | §11.2 |
| digest algorithm | `sha256` (H0) | §2.7 |
| limitation identifiers | the eleven closed `L_*` identifiers of §14.9 (registry: `spec/error-codes.md`) | §14.9, §14.6 |
| resource limits | the `MAX_*` constants of §13 (including `MAX_JSON_DEPTH`, `MAX_LICENCE_NESTING`, `MAX_TS_ACCURACY`) | §13 |
| exit codes | `0`, `1`, `2`, `3` | §14.8 |
| error/notice codes | closed registry in `spec/error-codes.md` | §14.2 |

## Appendix D — Conformance summary

**Accept (valid)** — a record or container in which: JSON is WR-CJ canonical; every required
member is present and well-formed; every known-algorithm signature verifies under §3.4 and
is authorised by an available declared key; a signature is present per record where §4.4
requires it; kind rules, actor rules, labels, references and cross-record state all pass;
the manifest digest and signature verify; manifest records match the record files; the
claimed level is labelled honestly (`level_verified` L0, L1 chain claim unverified, L2
anchor verified); the previous-manifest chain matches and is same-origin; blobs are
consistent; the timestamp chain verifies under a supplied trust anchor.

**Reject as invalid** — any violation of a MUST whose consequence is an `E_` code, in
particular: non-canonical JSON bytes; duplicate keys; invalid numeric literals or
out-of-range integers; JSON value nesting depth above `MAX_JSON_DEPTH`; a non-verifying
signature; a
missing required per-record signature where `sigs` is absent/empty; a kind body violating
its known members; an actor/signing-key class mismatch; a key redeclaration that changes the
governing class of a key id, independent of trust (`E_KEY_CLASS_CONFLICT`); a human key signing a
non-human record (outside the key-lifecycle exception); a missing salt for
`personal`/`local-only`; a label downgrade; licence nesting above `MAX_LICENCE_NESTING`;
`local-only` in a container; a `rel` or kind not matching its grammar; a reference kind
mismatch; a grant delegation that expands authority or a revocation by an unauthorised
signer; a missing/mismatched erasure attestation or an erasure contradiction; a missing
attestation file (`E_MANIFEST_UNSIGNED`); a `--previous` supplied against a null chain
(`E_MANIFEST_CHAIN`); a manifest digest/signature/records/blobs/level/chain violation; a
zip/entry violation including prefix, comment or trailing bytes (`E_CONTAINER_ZIP`); a
container file above its §13 class limit (`E_JSON_SIZE`); an invalid timestamp receipt
including an over-bound accuracy; a manifest-record digest or metadata mismatch.

**Report as unverifiable (never valid)** — a signature whose key is not declared anywhere
in the context (`E_KEY_UNKNOWN`); no verifiable required signature
(`E_SIG_UNVERIFIABLE`); an unresolvable, revoked or expired grant for an agent's record;
a claimed L2 without a trusted, complete timestamp chain; a signature by a compromised key
without pre-compromise timestamp evidence; any authorisation or key condition that cannot
be established from the input. These conditions are terminal for the record and are
reported as the record's single code (§14.4, §14.5); an unverifiable **container** condition
does not stop record processing.

**Report as erased** — a structurally sound `weave.erased` placeholder (record target:
verdict `erased`, exit 0; in a container: record verdict `erased`, container may still be
valid).

**Report limitations as identifiers** — every report carries the applicable `L_*`
identifiers of §14.9, sorted and unique, and never free prose. A report whose
`checks_disabled` is non-empty exits with code `3`, never `0`.

## Appendix E — Canonical examples

These examples are checked by the specification-example tooling as described in §14.10.
Each block is annotated with its example class: `standalone-record` examples are complete
records that MUST pass `record <file> --keys vectors/keys/keyset`; `container-context`
examples need a surrounding container; `illustrative` examples are shape sketches and are
not executable. All key ids are 32-hex; all example public keys are valid curve points.

### E.1 Minimal proposed record (standalone)

<!-- spec-example: standalone-record -->
```json
{"actor":{"key":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","type":"human"},"body":{},"format":"weave-record/1","id":"example-1","kind":"example.note","origin":{"instance":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","project":"example"},"recorded_at":"2026-11-01T00:00:00.000Z","stage":"proposed"}
```

A proposed record of an unregistered kind needs no signature (its stage is not `accepted`
and the kind is not one of the seven signer-constrained kinds), so the record is a valid
record target on its own; the report carries `N_KIND_UNKNOWN_OPAQUE`.

### E.2 Proposed record with a reference (standalone)

<!-- spec-example: standalone-record -->
```json
{"actor":{"key":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","type":"human"},"body":{},"format":"weave-record/1","id":"example-2","kind":"example.note","origin":{"instance":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","project":"example"},"recorded_at":"2026-11-01T00:00:00.000Z","refs":[{"ref":{"digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","id":"example-0","origin":{"instance":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","project":"example"}},"rel":"derived_from"}],"stage":"proposed"}
```

The referenced record is not in the verification context, so the reference is `missing`
(notice `N_REF_MISSING`) and label propagation is unchecked
(`N_LABEL_PROPAGATION_UNCHECKED`); the record itself remains valid.

### E.3 Erased placeholder (standalone)

<!-- spec-example: standalone-record -->
```json
{"attestation":{"digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","id":"erasure-1","kind":"weave.erasure","origin":{"instance":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","project":"example"}},"digest":"sha256:3333333333333333333333333333333333333333333333333333333333333333","format":"weave-record/1","id":"example-3","kind":"weave.erased","origin":{"instance":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","project":"example"}}
```

A standalone placeholder has verdict `erased` and exit code 0: its structure is sound even
though its attestation cannot be resolved without a container context (§10.3).
