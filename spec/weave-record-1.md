<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# weave-record/1 — exchange and reference format for records

**Status:** draft v0.1 (milestone H0). Not yet stabilised: `weave-record/1` v0.1 has not
passed the J1 and J2 round-trip acceptance cases, and only one independent verifier
implementation exists. This document is the normative specification of the draft.
**Version:** `weave-record/1`.
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
ruling identifier, for example `[S1]` or `[Q1]`. No decision may be invented: a statement
that no ruling covers is labelled PROVISIONAL [S8] decided (Inceptless decision
2026-11-10 #34; S8). Content that no ruling covers is marked
**PROVISIONAL** and recorded as an open question; PROVISIONAL items are listed in
Appendix A. Ruling identifiers S1–S8 and Q1–Q33 are those of the ruling document.
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
- **verifier** — an implementation that implements §14. The H0 Python verifier is named
  `hyphaweave-verify`.
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

Input classification is fixed by the rulings, in a single left-to-right parse of the input
bytes (§1.9): a numeric literal that is not valid JSON (`+1`, `01`, `.5`, `1.`) is a JSON
syntax error (`E_JSON_INVALID`); a syntactically valid JSON number that is a float or has an
exponent (`1.0`, `1e3`) is `E_JSON_NUMBER_NOT_INTEGER`; a syntactically valid JSON integer
outside the interval is `E_JSON_NUMBER_RANGE`; the literal `-0` is
`E_JSON_NOT_CANONICAL` (valid JSON but not WR-CJ canonical). The classification is applied
in input byte order (§1.9) [Q5][Q6][M-14] decided (Inceptless decision 2026-11-10 #34;
M-14).

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

A verifier parses the input bytes in **one left-to-right pass** and reports the **first**
violation in input byte order; it **MUST NOT** build a full document tree first and then
report violations in some other order [M-14] decided (Inceptless decision 2026-11-10 #34).
The classification is:

| first violation encountered | code |
|---|---|
| not UTF-8; BOM; truncated input; trailing non-whitespace content; `+1`, `01`, `.5`, `1.`, trailing comma, comment, or any other JSON syntax error; top-level value not an object where an object is required | `E_JSON_INVALID` |
| a duplicate member name at any nesting depth | `E_JSON_DUPLICATE_KEY` |
| a syntactically valid JSON number that is a float or has an exponent | `E_JSON_NUMBER_NOT_INTEGER` |
| a syntactically valid JSON integer outside `[-(2^53-1), +(2^53-1)]` | `E_JSON_NUMBER_RANGE` |
| a lone surrogate escape | `E_JSON_LONE_SURROGATE` |
| byte form not WR-CJ canonical (only detectable after a syntactically valid parse) | `E_JSON_NOT_CANONICAL` |
| file exceeds its size limit | `E_JSON_SIZE` |

Canonical-form violations are detected after the syntax pass because they concern the byte
spelling, not the parse; among several canonical-form deviations the first one in byte order
is not separately distinguished (the code is the same). For example, `{"a":1,"a":1.5}`
reports `E_JSON_DUPLICATE_KEY`: the duplicate is encountered before the float. `{"a":1.5,
"a":1}` reports `E_JSON_NUMBER_NOT_INTEGER` for the same reason. The examples in this
paragraph are illustrative; the vectors are normative.

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
`genTime` of an RFC 3161 token is converted per §12.3. The canonical serialisation of a TS
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
member is `E_ENV_MISSING_FIELD` (invalid). Unknown members inside `body` are permitted and
are governed by the kind rules (§7.5); unknown members inside `origin`, `actor`, `labels`,
reference objects and `sigs` entries are errors, because those objects are closed (§4.2,
§6.1, §8.1, §4.3).

### 4.1 Top-level members

| member | required | rule |
|---|---|---|
| `format` | yes | exactly the string `"weave-record/1"`; otherwise `E_ENV_FORMAT` |
| `kind` | yes | kind name, syntax in §7.1; `weave.` names reserved to this specification; otherwise `E_ENV_KIND_SYNTAX` [§2] |
| `origin` | yes | closed object `{"project":<slug>,"instance":<key id>}`; `project` matches `^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$` and is at most 64 bytes; `instance` is a key id (§2.5); otherwise `E_ENV_ORIGIN` [B1][B2] |
| `id` | yes | 1–256 Unicode scalar values; no C0 control characters (U+0000–U+001F), no C1 control characters (U+0080–U+009F) and no U+007F (DEL); no leading or trailing U+0020 space; otherwise `E_ENV_ID` [B1] |
| `stage` | yes | one of `proposed`, `accepted`, `rejected`, `withdrawn`, `superseded`; otherwise `E_ENV_STAGE` [G1] |
| `actor` | yes | closed object (§4.2); errors `E_ENV_ACTOR*` [E2] |
| `recorded_at` | yes | TS grammar of §2.8; otherwise `E_ENV_TIME` [F1][F4] |
| `occurred_at` | no | TS grammar; claimed; no ordering rule relative to `recorded_at`; otherwise `E_ENV_TIME` [F1][F2] |
| `refs` | no | array of at most 256 reference entries `{"rel":<rel>,"ref":<reference object>}`; see §6; duplicate entries rejected; otherwise `E_ENV_REFS` [F3] |
| `labels` | no | closed object; see §8.1; otherwise `E_ENV_LABELS` [H1] |
| `salt` | conditional | 16 random bytes in base64url (§2.6). **REQUIRED** if `labels.sensitivity` is `personal` or `local-only` (`E_ENV_SALT_MISSING`); a malformed value is `E_ENV_SALT`; optional in every other case [G3c][Q3] decided (Inceptless decision 2026-11-10 #34; Q3) |
| `body` | yes | a JSON object; absent or non-object is `E_ENV_BODY`; body semantics are the kind's (§7) |
| `sigs` | conditional | array of 1–16 signature entries (§4.3), sorted by `key` ascending, unique keys; required by §4.4; errors `E_ENV_SIGS`, `E_ENV_SIG_KEY`, `E_ENV_SIG_VALUE` [E1][E6] |

`id` is unique only within its `origin`; cross-system identity is by digest, never by
`id` alone [B1]. The member `salt` is included in the record digest; it is deleted together
with the content on erasure (§10) so that the original digest cannot be brute-forced after
erasure, while before erasure a third party can still verify the record [G3c].

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
is an array of 1–16 entries; it **MUST** be sorted ascending by the `key` string (UTF-16
code-unit order; the key id is ASCII so byte order is identical) and keys **MUST** be
unique. Structural errors are `E_ENV_SIGS`; per-member grammar is:

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

**Required-signature error precedence.** The following order is fixed [Q31][Q13][Q30]
decided (Inceptless decision 2026-11-10 #34; Q31/Q13), except for the report-shape detail
listed in Appendix A P10:

1. If a record is required to be per-record signed (above) and its `sigs` member is absent
   or an empty array, the record is invalid with `E_SIG_REQUIRED`.
2. Every `ed25519` signature entry is verified per §3.4; a known-key signature that fails
   the equation (or any other crypto step) makes the record invalid with the corresponding
   `E_SIG_*` code.
3. If at least one `ed25519` signature by the required signer verifies, the obligation is
   satisfied (additional valid signatures are evidence, not errors).
4. Otherwise, if at least one **known-algorithm** signature exists whose key is declared
   (i.e. there is a verifiable signature, just not by the required signer), then:
   - for the seven signer-constrained kinds, the kind's dedicated signer code is reported
     (§9, §5.5, kind pages);
   - for every other kind, `E_SIG_REQUIRED` is reported.
5. Otherwise (no entry has a known algorithm and a declared key):
   - if any `sigs` entry names a key that is not declared anywhere in the verification
     context, the record is `unverifiable` with `E_KEY_UNKNOWN`;
   - otherwise the record is `unverifiable` with `E_SIG_UNVERIFIABLE`.

The seven dedicated signer codes are: `E_KEY_DECLARED_NOT_SELF_SIGNED` (declared),
`E_KEY_ROTATION_SIGS` (rotated), `E_KEY_REVOKE_SIGNER` (revoked), `E_GRANT_GRANTER`
(`weave.grant` with `action == "grant"`), `E_GRANT_REVOKE_SIGNER` (`weave.grant` with
`action == "revoke"`), `E_ACTOR_KEY_TYPE_MISMATCH` (`weave.consent.granted` and
`weave.consent.revoked` with a non-human/organization signer), and `E_ERASE_ACTOR`
(`weave.erasure` with a disallowed signer).

**Human-signature notice.** An `accepted` record that has no valid signature made by a key
declared `human` in the verification context is still valid and MUST carry the notice
`N_NO_HUMAN_SIGNATURE`; this is the report-side counterpart of the principle that human
keys sign human acts (§5.2) [M-15] decided (Inceptless decision 2026-11-10 #34; M-15②).
The exact interaction of this notice with step 5 above is an implementation-shape detail
(PROVISIONAL, Appendix A P10).

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

### 5.3 Key trust: trust on first use, no pinning

The verifier accepts a public key when a valid `weave.key.declared` record for it exists in
the verification context or in the externally supplied keyset, or when a valid
`weave.key.rotated` record in the context explicitly lists the key in its
`old_public_key`/`new_public_key` member. A rotation record's explicit public-key members
are declarations of those two keys: they are verification material for the rotation record
and for other records signed by those keys. What is forbidden is inferring a key that no
record states, by walking an `old_key → new_key` chain (§9.2 rule 5). There is no
certificate authority, no network lookup and no revocation distribution beyond records in
context; the local decision is trust-on-first-use [E4][M-12] decided (Inceptless decision
2026-11-10 #34; M-12). H0 does **not** implement pinning: there is no
pinned-trust input beyond the keyset, and the verifier MUST NOT require one. The verifier
reports the notice `N_KEY_TOFU` for keys accepted this way, so a human reader can see that
trust came from the context itself rather than from a pre-existing local trust store [Q12]
decided (Inceptless decision 2026-11-10 #34; Q12).

When the verification context contains more than one valid declaration for the same key id,
the declaration whose claimed `recorded_at` is **earliest** governs, and when two tie the
declaration whose record digest is lexicographically smallest governs. Declarations that are
not themselves valid (for any reason) never establish or govern a key [Q12] decided
(Inceptless decision 2026-11-10 #34; Q12). The tie-break rule is an implementation-shape
detail (PROVISIONAL, Appendix A P2).

### 5.4 Agent authorisation: every agent record needs a covering grant

An agent's output is never self-authorised. Every record whose `actor.type` is `agent`
**MUST** cite a grant in `actor.grant` and that grant MUST cover the record, for **every**
stage, including `proposed` (decided (Inceptless decision 2026-11-10 #34; M-3): the decision
draft requires an agent to state "on whose behalf and under what authority" even for a
proposal). The envelope presence requirements are in §4.2; the semantic coverage checks are:

- `actor.grant` MUST resolve to a valid `weave.grant` record with `action == "grant"`
  (`E_GRANT_UNRESOLVED` → unverifiable when the target is not in the context; if it
  resolves to a record with `action == "revoke"` the code is `E_GRANT_GRANTER`, invalid);
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
- the whole grant chain, including ancestors, is checked at the record's claimed
  `recorded_at`, per §5.5 [S3][M-3][Q11][Q13] decided (Inceptless decision 2026-11-10 #34).

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

1. **Resolve.** If the parent reference cannot be resolved in the context, or resolves to a
   record whose own verdict is invalid, the sub-grant is `unverifiable` with
   `E_GRANT_UNRESOLVED`.
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
6. **Ancestor validity.** Each ancestor link is evaluated at the claimed `recorded_at` of
   the descendant grant that used it: an ancestor revoked at that time
   (`effective_at <= recorded_at`) makes the chain `unverifiable` with `E_GRANT_REVOKED`;
   an ancestor outside its validity window at that time makes it `unverifiable` with
   `E_GRANT_EXPIRED`; any such failure anywhere in the chain makes the whole chain
   unverifiable (decided (Inceptless decision 2026-11-10 #34; M-2/S3)).
7. **Depth.** H0 does not support chains with more than 8 links from the grant used by a
   record up to its root: a deeper chain is `unverifiable` with `E_GRANT_UNRESOLVED`. A
   cycle cannot occur in a conforming grant chain: each grant record is identified by a
   digest that covers its `actor.grant` reference, so mutual parent references are not
   constructible (the record-reference graph is a DAG). The depth bound is an
   implementation shape (PROVISIONAL, Appendix A P3).

#### 5.5.3 Record authorisation by a grant

The checks for a record whose `actor.type` is `agent` (and for any record that cites an
`actor.grant`) are in §5.4. `scope` is an audit and delegation-subset field; H0 does not
evaluate it for machine authorisation of an individual record (§5.6).

#### 5.5.4 `action: "revoke"` body and revocation authority

The `revoke` object is closed: `{"revokes": <reference object>, "effective_at": <TS>,
"reason": <string or null>}`. The reference MUST resolve to a `weave.grant` record with a
matching digest (`E_GRANT_REVOKE_REF`, invalid). `effective_at <= recorded_at` is not
imposed on grant revocations; a future `effective_at` is a scheduled revocation.

The revocation record MUST be signed by an authorised revoker:

- if the target grant's `grant.revocation` list is present, by a key whose id is in that
  list;
- otherwise by the original granter's `actor.key`, or by an explicit rotation successor of
  that key (followed only through `weave.key.rotated` records that name the successor key
  explicitly, never by automatic inference, depth at most 8). The key-id graph can contain
  a cycle; a cycle means the signature cannot be proven to come from a rotation successor,
  and the revocation is invalid with `E_GRANT_REVOKE_SIGNER`. The walk is bounded and
  terminates.

Otherwise `E_GRANT_REVOKE_SIGNER` (invalid). A revoker key that is not declared in the
context makes the revocation `unverifiable` with `E_KEY_UNKNOWN` rather than invalid. The
rotation-successor walk and its depth bound are implementation shapes (PROVISIONAL,
Appendix A P4) [Q10][M-5][M-12] decided (Inceptless decision 2026-11-10 #34; Q10).

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

### 6.3 Resolution states — five states

Each reference is resolved against the verification context; the result is exactly one of:

| state | meaning |
|---|---|
| `found` | a record with the same `origin` and `id` and a matching `digest` is present and itself valid |
| `moved` | the referenced object was located at another location through its `hints` and its record digest matches the reference |
| `missing` | no record with that `origin` and `id` exists in the context |
| `erased` | a `weave.erased` placeholder with that `origin` and `id` exists whose `digest` member equals the reference digest |
| `unverifiable` | a record with that `origin` and `id` is present but its digest does not match the reference, or it is itself not valid, or the reference digest algorithm is unsupported, or the target record digest cannot be computed |

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
3. **MUST** report `kind_known: false` and the notice `N_KIND_UNKNOWN_OPAQUE`;
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
- parentheses **MAY** nest, bounded only by the record size limit;
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
   mismatch is `E_KEY_ID_MISMATCH` (invalid). A `public_key` that is not strict unpadded
   base64url of exactly 32 bytes is `E_KEY_PUBLIC_KEY` (invalid). A declaration does not
   check whether the 32 bytes decode to a curve point or whether the point is small-order
   or mixed-order: those checks happen at signature verification (§2.5, §3.4) [E3][S1]
   decided (Inceptless decision 2026-11-10 #34; S1/M-11).
2. **Self-signature.** At least one `sigs` entry MUST be a valid signature by the declared
   key over the record signature message; otherwise `E_KEY_DECLARED_NOT_SELF_SIGNED`
   (invalid) [E5].
3. **Owner binding.** For `key_type` in `agent`, `program`, `device`, `body.owner` MUST be
   present; a missing owner is `E_KEY_OWNER_MISSING` (invalid). The owner MUST resolve to a
   declaration in the verification context, and that declaration's class MUST be `human` or
   `organization`; the owner declaration itself does **not** have to be valid (it only
   identifies the owning principal). An owner that cannot be resolved makes the declaration
   `unverifiable` with `E_KEY_UNKNOWN` (invalid evidence, not a structural error).
4. **Cosignature.** A key declaration MUST be cosigned as follows:
   - for `agent`, `program` and `device`: at least one valid signature by a key declared
     with class `human` or `organization` and key id equal to `body.owner`;
   - for `human` and `organization`: the declaration is processed as part of the set of
     human/organization declarations in the context, in ascending order of claimed
     `recorded_at` (ties broken by lexicographically smallest record digest). A declaration
     with a valid cosignature by a key already in the established human/organization set is
     valid and is added to that set; otherwise, if the established set is empty, the
     declaration is a **root** and may be self-signed only, and the verifier MUST emit
     `N_SELF_ATTESTED_ROOT_KEY`; otherwise the declaration is invalid with
     `E_KEY_DECLARED_NOT_COSIGNED`.
   The cosignature requirement is [S4][Q33] decided (Inceptless decision 2026-11-10 #34;
   S4/Q33). The root-determination order is an implementation shape (PROVISIONAL,
   Appendix A P1); the tie-break between equal `recorded_at` values is a further
   implementation shape (PROVISIONAL, Appendix A P2).
5. **Validity window.** When both `valid_from` and `valid_until` are present,
   `valid_from` MUST be less than or equal to `valid_until`; otherwise `E_KEY_VALIDITY`
   (invalid) [E5][Q20] decided (Inceptless decision 2026-11-10 #34; Q20).
6. **Effects.** Once a declaration is valid in context, signatures by the declared key can
   be verified within its declaration's validity rules (§9.4). Multiple declarations for
   the same key id are resolved per §5.3 [Q12] decided (Inceptless decision 2026-11-10
   #34; Q12).

The declaration itself is not a trust anchor; trust remains trust-on-first-use (§5.3).

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
   (Inceptless decision 2026-11-10 #34; M-11).
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

Let `T` be the claimed `effective_at` of a revocation of a key. Effects on signatures made
by that key (the signature's claimed `recorded_at`; for a manifest signature the manifest's
claimed `created_at`):

| reason | signature condition | outcome |
|---|---|---|
| `retired` (and `other`, treated as retired) | `recorded_at >= T` | invalid (`E_KEY_REVOKED`) |
| `retired` / `other` | `recorded_at < T` | unaffected |
| `key-compromise` | **always** | valid **only if** the record is covered by a verified RFC 3161 timestamp whose `genTime` is at or before `T`; otherwise invalid (`E_KEY_COMPROMISED`) |

The `key-compromise` rule deliberately ignores `recorded_at`: claims of time are not
evidence, and a thief who holds the key can backdate a record. Only an external timestamp
over the manifest that contains the record, verified under §12, can establish that the
record existed before the compromise. The timestamp used for this comparison is the
earliest `genTime` among the verified receipts of the manifest's timestamp chain; when a
renewal chain is present the earliest verified link is the evidence of age. A
single-record target has no timestamp evidence, so a signature by a compromised key is
invalid there. For a manifest signature the same test uses the manifest's timestamp chain
[S2] decided (Inceptless decision 2026-11-10 #34; S2). The choice of "earliest verified
`genTime`" as the comparison value is an implementation shape (PROVISIONAL, Appendix A P8).

Validity windows of declarations:

- a signature whose claimed `recorded_at` is later than the declared `valid_until` is
  `E_KEY_EXPIRED` (invalid);
- a signature whose claimed `recorded_at` is earlier than the declared `valid_from` is
  `E_KEY_EXPIRED` (invalid).

Both directions are one rule: a signature outside the declared window is invalid
[Q20][M-4] decided (Inceptless decision 2026-11-10 #34; Q20).

A signature by a key with no declaration and no explicit rotation-record material anywhere
in the verification context is `unverifiable` (`E_KEY_UNKNOWN`); this applies to manifest
signatures as well [E4][Q12][M-12] decided (Inceptless decision 2026-11-10 #34; M-12).
Multiple declarations for one key id are resolved as in §5.3 [Q12] decided (Inceptless
decision 2026-11-10 #34; Q12).

### 9.5 Revocation records are self-evidencing

The revocation of the key that signed a `weave.key.revoked` record does not invalidate that
revocation record; it is the revocation itself. Likewise, a `weave.key.declared` record
that supplies its own key is verifiable from its own `public_key` even though it may be the
first time the key is seen in the context (self-declaration bootstrap) [E5][Q12]. A
revocation is a claim by the revoker; H0 does not attempt to establish when a compromise
actually happened beyond the timestamp evidence rule of §9.4.

### 9.6 Grant revocation effects

A record that uses `actor.grant` G at claimed `recorded_at`, where a `weave.grant`
revocation record R revokes G with `R.revokes` resolving to G and `R.effective_at <=
recorded_at`, is `unverifiable` (`E_GRANT_REVOKED`). Records before `effective_at` are
unaffected; the boundary belongs to revocation (equal counts as revoked). A revoked or
expired grant therefore makes a new record unverifiable rather than invalid; a grantee,
kind or action mismatch is invalid [Q11][M-2] decided (Inceptless decision 2026-11-10 #34;
Q11).

### 9.7 Grant chains across records

Grants may delegate (root grant → delegated sub-grant → records using the sub-grant). The
verifier evaluates the chain as specified in §5.5.2 and §5.4. An unresolvable or invalid
parent link makes the dependent grant unusable, and records using it `unverifiable`
(`E_GRANT_UNRESOLVED` or the specific chain error of §5.5.2). Grants are only usable within
their validity windows, and revocation at the usage time makes them unusable.

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

When both the placeholder and its erasure record are present in a container:

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
container with no `manifest.json` is `E_MANIFEST_MISSING` (invalid). Directories not listed
here, or unknown files inside a listed directory, are `E_CONTAINER_ENTRY` — with two special
cases: an extra file in `records/` is `E_MANIFEST_RECORD_EXTRA`, and an extra file in
`blobs/` is `E_MANIFEST_BLOB`. The `readable/` directory and anything below it is ignored
entirely: it is never parsed, never hashed, never trusted, and never part of the manifest
[Q19] decided (Inceptless decision 2026-11-10 #34; Q19). All digested JSON files use the
canonical file form (§1.8) and all files obey the size limits of §13.

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
  `E_MANIFEST_UNSIGNED`. If the array is non-empty but no entry is a verifiable signature
  by a declared required key, the manifest signature is `unverifiable`: `E_KEY_UNKNOWN`
  when the failure is caused by an undeclared signature key, otherwise
  `E_SIG_UNVERIFIABLE` [Q13] decided (Inceptless decision 2026-11-10 #34; Q13).
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
(`E_TS_FILE`, invalid).

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

Report semantics (the shape is PROVISIONAL, Appendix A P7): `level_claimed` reports the
manifest's claim; `level_verified` is **always** `"L0"` for H0 — no verifier may claim to
have verified L1 or L2 — and a separate boolean `anchor_verified` is true only when
`level_claimed == "L2"` and the whole timestamp chain verified with at least one trusted
anchor. `chain.status` is `"absent"` for L0 and `"unverified"` for L1/L2, with the notice
`N_CHAIN_CLAIM_UNVERIFIED`; a verifier MUST NOT claim to have verified the internal chain
[S5][Q9] decided (Inceptless decision 2026-11-10 #34; S5/Q9).

### 11.5 Manifest chain continuity

- If `manifest.previous_manifest` is non-null, `previous/manifest.json` MUST exist. Its
  bytes MUST satisfy the canonical file form (§1.8) and parse as a manifest, its §2.4
  manifest digest MUST equal `previous_manifest.digest`, and its `format`/
  `manifest_version` MUST be supported. The file being missing is
  `E_MANIFEST_CHAIN_MISSING`; a non-canonical, unparseable, unsupported-version or
  digest-mismatching embedded manifest is `E_MANIFEST_CHAIN`.
- The previous manifest's `origin` MUST equal the current manifest's `origin`: the chain
  records the history of one publisher. A different origin is `E_MANIFEST_CHAIN` (invalid)
  [M-8] decided (Inceptless decision 2026-11-10 #34; M-8).
- If `manifest.previous_manifest` is null, `previous/` MUST be absent or empty
  (`E_MANIFEST_CHAIN_UNEXPECTED`).
- The previous manifest's own signature is not re-verified by default: the chain is a chain
  over manifest digests. A verifier MAY additionally verify the previous signature when the
  keys are available and MUST report `N_PREVIOUS_SIG_UNVERIFIED` when it does not [D1].
- The `--previous <dir>` command option additionally requires the supplied previous
  container's manifest digest to equal `previous_manifest.digest`; a mismatch is
  `E_MANIFEST_CHAIN`.

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
parsed, not hashed, not trusted, not listed in the manifest. Its presence or content never
changes a verdict; a verifier MAY report the informational notice `N_READABLE_PRESENT`
[Q19] decided (Inceptless decision 2026-11-10 #34; Q19).

### 11.9 Zip form

The zip form of a container contains exactly the same relative paths as the directory form,
with `/` separators. It MUST NOT contain absolute paths, `..` segments, duplicate entry
names, symbolic links, or entries that escape the root; per the closed registry these are
`E_CONTAINER_ENTRY` (layout and entry-safety violations), as are unknown files under
`signatures/` or `previous/`. Encrypted entries, unsupported compression and an archive
that cannot be read as a zip are `E_CONTAINER_ZIP` [Q25] decided (Inceptless decision
2026-11-10 #34; Q25). Entries MAY be stored or deflated;
directory entries are ignored. Content layout problems keep their content codes
(`E_MANIFEST_*`). Limits apply to uncompressed sizes and to entry counts (§13) and are
checked during streaming; a zip bomb is bounded by those limits (`E_CONTAINER_SIZE`), never
a crash.

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
failing check is reported [S5] decided (Inceptless decision 2026-11-10 #34; S5).

| # | check | code on failure |
|---|---|---|
| 1 | The file is a DER-encoded RFC 3161 `TimeStampResp` whose `PKIStatusInfo.status` is `0` (`granted`); `grantedWithMods` (1) and every other status are rejected. | `E_TS_SCHEMA` |
| 2 | The `SignedData` content type is `id-ct-TSTInfo`, and the encapsulated TSTInfo parses as DER with `version == 1`. | `E_TS_SCHEMA` |
| 3 | `messageImprint.hashAlgorithm` is `sha256`; any other algorithm is a schema failure. | `E_TS_SCHEMA` |
| 4 | `messageImprint.hashedMessage` equals the expected imprint (§12.4): the raw 32 bytes of the manifest digest for the first receipt, or `SHA-256(<previous receipt bytes> ‖ <raw manifest digest>)` for a renewal receipt. | `E_TS_IMPRINT` |
| 5 | `signerInfo.digestAlgorithm` is `sha256`. | `E_TS_SCHEMA` |
| 6 | The signature algorithm is on the allowlist: RSA PKCS#1 v1.5 with SHA-256, SHA-384 or SHA-512, or ECDSA with SHA-256 or SHA-384. RSA-PSS and every other algorithm are rejected. | `E_TS_CERT` |
| 7 | The signer certificate is included in the token's `SignedData.certificates` (a receipt whose token does not carry its signer certificate is rejected even if `--tsa-trust` contains that certificate). | `E_TS_CMS` |
| 8 | The signed attributes carry ESS `signingCertificateV2` matching the signer certificate. A v1-only `signingCertificate` or a missing ESS attribute is rejected. | `E_TS_CMS` |
| 9 | The signed attributes' `messageDigest` equals `SHA-256(eContent)`. | `E_TS_CMS` |
| 10 | The CMS signature verifies over `DER(SET OF SignedAttributes)` with the signer certificate's public key. | `E_TS_CMS` |
| 11 | The signer certificate has the `id-kp-timeStamping` extended key usage; if a KeyUsage extension is present it contains `digitalSignature`. | `E_TS_CERT` |
| 12 | The signer certificate's validity window contains `genTime` (not the current wall clock). | `E_TS_CERT` |
| 13 | `genTime` is a valid GeneralizedTime and is converted to an integer number of milliseconds since the Unix epoch by truncating (flooring) any sub-millisecond digits; all comparisons in §12 use that integer. | `E_TS_SCHEMA` |
| 14 | The `timestamps[]` array of the attestation file forms exactly one renewal chain (§12.4): exactly one receipt with `renews == null`; every other `renews` names a listed, earlier receipt; no duplicate paths, no gaps, no second chain. | `E_TS_RENEWAL` |
| 15 | The receipt is trusted under §12.3. | `E_TS_UNTRUSTED` (unverifiable) |

Checks 1–14 are structural or cryptographic and make the container **invalid** when they
fail. Check 15 is a trust decision: without a matching anchor the receipt is reported
`present-unverified` and the container cannot be `valid` (`unverifiable`,
`E_TS_UNTRUSTED`).

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
- If any listed receipt fails checks 1–14 of §12.2, the container is **invalid**.
- Otherwise, if the chain is complete and every receipt is verified (including check 15,
  with a matching anchor), `anchor_verified` is true and the L2 claim is verified at the
  report level described in §11.4.
- Otherwise each unverified receipt is `present-unverified` and the container is
  **unverifiable** (`E_TS_UNTRUSTED`), never `valid`.

A verifier MUST NOT claim L2 merely because `.tsr` files exist, and MUST NOT accept a
receipt whose CMS signature, imprint, certificate constraints, ESS attribute or
`messageDigest` fails.

### 12.6 Timestamps prove anchoring, not truth

A verified timestamp proves that a timestamp authority signed an imprint at some time (and
that the stated constraints held); it does not prove the content is true. It is the only
evidence that a record or a manifest existed before a claimed time, and it is therefore the
evidence used by the `key-compromise` rule of §9.4. The exact "earliest verified `genTime`"
selection for that rule is an implementation shape (PROVISIONAL, Appendix A P8)
[D3][A1c][S2] decided (Inceptless decision 2026-11-10 #34; S2).

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
| `MAX_CONTAINER_ENTRIES` | 200,000 | all zip entries / all files in a directory container | `E_CONTAINER_SIZE` |
| `MAX_CONTAINER_UNCOMPRESSED_BYTES` | 1,073,741,824 (1 GiB) | total uncompressed bytes of a zip container | `E_CONTAINER_SIZE` |
| `MAX_BLOB_BYTES` | 1,073,741,824 (1 GiB) | one blob | `E_MANIFEST_BLOB` |
| `MAX_BLOBS` | 10,000 | `manifest.blobs` entries | `E_MANIFEST_SCHEMA` |
| `MAX_REFS` | 256 | `refs` entries | `E_ENV_REFS` |
| `MAX_SIGS` | 16 | `sigs` entries | `E_ENV_SIGS` |
| `MAX_HINTS` | 8 | one reference's `hints` entries | `E_ENV_REFS` |
| `MAX_SIG_VALUE_BYTES` | 2,048 | decoded bytes of a non-ed25519 signature `value` | `E_ENV_SIGS` |
| `MAX_GRANT_CHAIN` | 8 | delegated grant chain depth (§5.5.2) | `E_GRANT_UNRESOLVED` |

Limits are checked on the streamed bytes, not on a fully materialised decompression. A zip
whose decompression would exceed the uncompressed-byte limit is `E_CONTAINER_SIZE`
(invalid). Implementations MUST NOT rely on filesystem-reported sizes for these checks;
they MUST enforce them while reading.

## 14. Verifier conformance

A conforming verifier reads records and containers with no network, no wall clock and no
locale/TZ/path dependence, and produces a deterministic report [I4]. Independent
implementations must agree on every vector [I4].

### 14.1 Command surface

The H0 Python verifier exposes these commands (names are normative for that CLI; an
independent implementation MUST provide equivalent behaviour):

```
hyphaweave-verify record <file> [--keys <dir>] [--json]
hyphaweave-verify container <dir|zip> [--keys <dir>] [--tsa-trust <pem>] [--previous <dir>]
hyphaweave-verify vectors <dir> [--tsa-trust <pem>]
hyphaweave-verify --help | --version
```

- `--keys <dir>` supplies external key-lifecycle records: the top-level `*.json` files in
  the directory. Each file MUST be a structurally valid record under this specification
  (canonical bytes, envelope, signatures where present, kind body and the kind's
  self-consistency rules); a file that is not such a record is a usage error (exit 2). A
  record that parses and is structurally valid but fails semantic or cryptographic checks
  does not establish trust; that is not a usage error. Keyset records are key material and
  lifecycle context, not part of a container.
- `--tsa-trust <pem>` supplies L2 trust anchors (§12.3).
- `--previous <dir>` additionally requires the supplied previous container's manifest
  digest to equal `previous_manifest.digest` (§11.5).
- `--json` is accepted and is the default (compatibility flag). No colour, no progress
  output. Standard output carries exactly one JSON report per run; standard error carries
  usage and I/O errors only.
- No network access. No reading of external test data at runtime. Input file bytes are read
  once and verified from those bytes.

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

The following conditions MUST NOT lead to `valid`: `E_KEY_UNKNOWN`, `E_SIG_UNVERIFIABLE`,
`E_GRANT_UNRESOLVED`, `E_GRANT_REVOKED`, `E_GRANT_EXPIRED`, `E_TS_UNTRUSTED`, and the
notice `N_KEY_UNDECLARED` when a signature cannot be checked at all because no key material
is available. A claimed L2 without a matching trust anchor is `unverifiable` (§12.5). Any
`unverifiable` record makes the container `unverifiable` (not invalid). A verifier MUST NOT
silently pass a check it could not perform; it reports the gap in `limitations`.

### 14.5 Deterministic check order

A verifier MUST apply checks in a deterministic order and MUST report at most one error per
record: the first failing check in the order below (later checks are not run for that
record). Containers apply the container order below.

Per record: (1) parse and canonical form (§1.9), (2) envelope structure, (3) `sigs`
presence/format (§4.3), (4) key resolution (unknown key → unverifiable, stop crypto),
(5) Ed25519 verification (§3.4), (6) kind body schema, (7) kind semantic rules,
(8) actor/authorisation, (9) labels, (10) reference resolution and kind mismatch.

Required-signature errors follow the precedence of §4.4: an absent/empty `sigs` array on a
record that needs a per-record signature is `E_SIG_REQUIRED` at step (3); for ordinary kinds,
a non-empty `sigs` with verifiable signatures but no required signer is `E_SIG_REQUIRED`
immediately after step (5); for the seven signer-constrained kinds the dedicated kind code
is emitted at step (7) when verifiable entries exist but the required signer is
missing/wrong; when there is no known-algorithm declared-key signature at all the record is
`E_KEY_UNKNOWN` or `E_SIG_UNVERIFIABLE` as specified in §4.4. The precedence between
`N_NO_HUMAN_SIGNATURE` and the `E_SIG_UNVERIFIABLE` outcome is an implementation shape
(PROVISIONAL, Appendix A P10) [Q31][Q13] decided (Inceptless decision 2026-11-10 #34).

Per container: (1) entry enumeration/safety; (2) manifest parse/canonical form;
(3) manifest structure; (4) manifest digest; (5) manifest signature; (6) level/chain
structure completeness; (7) records listing and per-record verification; (8) cross-record
state rules (key lifecycle, grants, consents, erasure, label propagation); (9) blobs;
(10) previous-manifest chain; (11) timestamps; (12) aggregation and report.

A container-level invalid error before check (7) stops record processing (`records: []` and
exactly one error recorded in `container.errors`); an `unverifiable` container condition
does not stop record processing. Checks (7)–(10) of a record may need other records; they
are evaluated with the deterministic resolution model of §6.4.

### 14.6 Report format

The report is one JSON object on standard output, UTF-8, serialised with sorted keys, two
spaces of indentation, `ensure_ascii` true and exactly one trailing LF; it contains no
absolute paths, usernames, hostnames, current times, randomness or environment values. The
stable report version is `report_version: "1"`:

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
  "limitations": ["..."],
  "verifier": {"name": "hyphaweave-verify-python", "version": "0.1.0"}
}
```

Report rules:

- The `container` object is present only for a container target. `level_verified` is always
  `"L0"` in H0; `anchor_verified` is true only for a fully verified L2 timestamp chain with
  a matching anchor (§11.4, §12.5).
- `records` holds one entry for a record target and the manifest-ordered entries for a
  container target. For a `weave.erased` entry, `records[].digest` is the §2.2 record
  digest computed over the placeholder object itself (not the placeholder's original-digest
  member); the entry optionally carries
  `"attestation": {"digest": <digest string>, "state": "found|moved|missing|erased|unverifiable"}`;
  its `refs` array is empty.
- `sigs[].state` is `valid`, `invalid`, `unverified` (key not available) or `ignored`
  (unknown algorithm, §3.6).
- Container-level errors and notices (manifest, level/chain, blob, timestamp and container
  structure problems) live in `container.errors` / `container.notices` (sorted,
  lexicographically unique, registry codes only). A container-level invalid failure before
  the records check yields `records: []` and exactly one error in `container.errors`. For
  test-vector comparison, a container case's aggregated errors are the set union
  `container.errors ∪ every records[i].errors`.
- Errors and notices are sorted lexicographically and unique; they come only from the
  closed registry.
- A field whose value cannot be determined because the input failed earlier in the check
  order is reported as JSON `null`; a report never invents a value and never omits a
  `records[]` entry that the container manifest or the target requires.
- `input.sha256`/`input.size` identify the target input: for a record target, the record
  file bytes; for a zip container, the archive bytes; for a directory container, the
  manifest digest and manifest byte size [Q27] decided (Inceptless decision 2026-11-10
  #34; Q27).
- For the `vectors` target, `summary` is `{"case_count": N, "matched": n,
  "mismatched": m}` and per-case results are listed in a deterministic, path-free array;
  the exact field layout of that array is an implementation shape (PROVISIONAL, Appendix A
  P7) [Q27] decided (Inceptless decision 2026-11-10 #34; Q27).
- A report is never silently degraded: skipped checks appear in `checks_disabled` (§14.7).

### 14.7 Test-only check hook

For conformance testing only, the reference verifier honours the environment variable
`WEAVE_VERIFY_SKIP_CHECKS`: a comma-separated list of error codes whose checks are treated
as passed. Unset or empty means normal operation. The report MUST echo the sorted list in
`checks_disabled` so a report can never be silently degraded. The hook is documented as
test-only and MUST NOT be used as a production configuration [Q18] decided (Inceptless
decision 2026-11-10 #34; Q18). An independent implementation is not required to implement
this hook to be conformant to the record format; it is required only for reproducing the
H0 test-gate procedure.

### 14.8 Exit codes

| exit code | meaning |
|---|---|
| `0` | valid: the record/container is `valid` (or `erased` for a placeholder record), or every vector case matched |
| `1` | invalid, unverifiable, or at least one vector case mismatched |
| `2` | usage or I/O error; no report on standard output |

`record` on a `weave.erased` placeholder returns verdict `erased` and exit code 0: a
structurally sound attestation of an erasure is a successful verification.

### 14.9 Limitations reporting

Every report lists what was not verified. At minimum, when applicable: an unverified L1
chain claim; an unverified or absent L2 timestamp trust; TOFU keys; unresolved
authorisation or consent; unknown kinds not understood; continuous multi-container chains
out of scope. A verifier MUST NOT phrase a limitation as a passed check.

### 14.10 Independence and vectors

Conformance is defined by the test vectors: every case declares its expected verdict,
errors and (where applicable) reference resolution, and an implementation conforms when it
matches all of them. Vector generation is independent of any verifier and expected outcomes
are authored separately; negative cases name the expected code. A second independent
implementation must pass the same vectors before version 1.0 [I4]. Specification examples
are additionally checked: every complete standalone JSON record example in this
specification and in the kind pages MUST pass `record <example> --keys
vectors/keys/keyset`; context-dependent examples are marked as such and container examples
are verified as containers; purely illustrative snippets are marked and skipped. The three
example markers and their handling are a non-normative tooling convention (PROVISIONAL,
Appendix A P11).

## 15. Security considerations

This section is informative except where it states a MUST.

1. **Canonicalisation is a security boundary.** Implementations MUST implement WR-CJ
   exactly (§1) and MUST NOT delegate the decision to a general JSON library without
   cross-checks. Duplicate-member rejection, the integer-only rule and the right-to-left
   first-violation classification of §1.9 are security requirements [C1][C2][C3][M-14].
2. **Signature domain separation.** The four domain prefixes (§2.1) prevent replay of a
   signature across object types and purposes; cross-purpose acceptance is a defect and is
   tested in both directions [C4][E6][S1].
3. **Ed25519 edge cases.** The complete decode procedure (§3.2), the point-based
   small-order predicate (§3.3), mixed-order rejection and the fixed order of §3.4 are
   mandatory. Omitting the `x = 0, x_0 = 1` rule or the small-order check enables the
   identity-key forgery; relying on a library that accepts mixed-order keys causes
   cross-implementation divergence [S1][Q1].
4. **Trust on first use.** In-context key declarations are trusted on first use; an
   attacker who can inject a declaration and a matching key into the context can make
   records appear valid. This is inherent in a CA-less design; users should pin key ids out
   of band for high-value evidence, and reports mark TOFU-accepted keys [E4][Q12].
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
    verifier MUST NOT crash or unboundedly decompress on a zip bomb.
14. **Plain files only.** Containers are ordinary files with no executable content; a
    verifier MUST NOT execute or follow hints, URLs or `readable/` content.

## 16. Governance, repository and implementation requirements

- **Repository and identity**: the specification repository is `haeliotang/hyphaweave`; the
  format identifier remains `weave-record/1` independently of the project name [K1].
- **Licences**: specification prose CC BY 4.0; code, schemas and test vectors Apache-2.0
  [K2].
- **Adapters live in project repositories**; this repository contains only the
  specification, schemas, test vectors and reference verifiers [A1a].
- **Two independent implementations**: the Python reference verifier and a second
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
| S2 | compromise revocation: a signature by a compromised key is valid only with a verified timestamp at or before the effective time | §9.4, §12.5–§12.6 |
| S3 | delegated sub-grants must be subsets of their parent (kinds, actions, scope, window); no privilege escalation | §5.5.2 |
| S4 | key declarations must be self-signed and cosigned (owner or previous key); only the root bootstrap is exempt | §9.1 |
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
| Q33 | root human/organization key bootstrap: first key may be self-attested, with `N_SELF_ATTESTED_ROOT_KEY` | §9.1 |

### A.2 PROVISIONAL implementation shapes

The following are implementation shapes rather than wire-format rulings. The rule text is
normative in this document, but the shape itself was not decided by the ruling document and
is recorded as PROVISIONAL in `docs/open-questions.md`. A verifier MUST follow the shape
stated here; a later ruling may change it.

| id | item | normative location |
|---|---|---|
| P1 | deterministic root-declaration ordering algorithm for Q33 (process human/organization declarations by claimed `recorded_at`, maintaining the established-key set) | §9.1 |
| P2 | tie-break between declarations with the same claimed `recorded_at`: lexicographically smallest record digest | §5.3, §9.1 |
| P3 | delegated-grant chain depth bound of 8 | §5.5.2, §13 |
| P4 | revocation-authority walk over explicit rotation successors, depth bound 8 | §5.5.4 |
| P5 | exact precedence order among the delegation-chain error codes | §5.5.2 |
| P6 | renewal-chain representation (`timestamps[].renews`, the `SHA-256(previous receipt ‖ manifest digest)` imprint formula, single chain) | §11.3, §12.4 |
| P7 | report field shapes: `level_verified` always `L0`, `anchor_verified`, `timestamps[]` entries, `vectors` summary and per-case layout | §11.4, §14.6 |
| P8 | the S2 rescue comparison uses the earliest verified `genTime_ms` of the manifest's timestamp chain | §9.4, §12.6 |
| P9 | `scope` compared as a set of strings for delegation subsetting | §5.5.2 |
| P10 | `N_NO_HUMAN_SIGNATURE` determination and its precedence relative to `E_SIG_UNVERIFIABLE` | §4.4, §14.5 |
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
out-of-range integers; a non-verifying signature; a missing required per-record signature
where `sigs` is absent/empty; a kind body violating its known members; an
actor/signing-key class mismatch; a human key signing a non-human record (outside the
key-lifecycle exception); a missing salt for `personal`/`local-only`; a label downgrade;
`local-only` in a container; a `rel` or kind not matching its grammar; a reference kind
mismatch; a grant delegation that expands authority or a revocation by an unauthorised
signer; a missing/mismatched erasure attestation or an erasure contradiction; a manifest
digest/signature/records/blobs/level/chain violation; a zip or entry violation; an invalid
timestamp receipt; a manifest-record digest or metadata mismatch.

**Report as unverifiable (never valid)** — a signature whose key is not declared anywhere
in the context (`E_KEY_UNKNOWN`); no verifiable required signature
(`E_SIG_UNVERIFIABLE`); an unresolvable, revoked or expired grant for an agent's record;
a claimed L2 without a trusted, complete timestamp chain; a signature by a compromised key
without pre-compromise timestamp evidence; any authorisation or key condition that cannot
be established from the input.

**Report as erased** — a structurally sound `weave.erased` placeholder (record target:
verdict `erased`, exit 0; in a container: record verdict `erased`, container may still be
valid).

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
