<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# weave-record/1 — exchange and reference format for records

**Status:** draft v0.1 (milestone H0). Not yet stabilised: `weave-record/1` v0.1 has not
passed the J1 and J2 round-trip acceptance cases, and only one independent verifier
implementation exists (Python). This document therefore describes a *draft* format.
**Version:** `weave-record/1` (the format identifier is the string `weave-record/1` and does
not follow the repository name).
**Editors:** Inceptless.
**Licence:** this specification text is licensed CC BY 4.0; code and test vectors for the
format are licensed Apache-2.0 [K2].

This document is normative for the `weave-record/1` exchange format. It is the English
rendering of decision draft v0.1 (2026-11-07) plus correction v0.1.1 (2026-11-10)
(collectively "the decision draft"), and of the H0 internal engineering contract. Where this
document, the decision draft and the H0 contract disagree, the decision draft wins; such
disagreements are recorded as open questions. Decision identifiers in square brackets (for
example `[C1]`, `[B3]`, `[E6]`, `[G3a]`, `[I2]`, `[K3]`) tie every normative paragraph back
to the decision draft; `[§8.1]`-style tags cite the correspondingly numbered section of the
decision draft, and `[Q1]`–`[Q32]` refer to the provisional items of Appendix A.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**,
**SHOULD NOT**, **RECOMMENDED**, **MAY** and **OPTIONAL** in this document are to be
interpreted as described in RFC 2119 and RFC 8174, but only when they appear in capitals.

## 0. Scope and terms

### 0.1 What the format is

`weave-record/1` is an **exchange and reference** format. Independent systems keep their own
internal formats and storage; when they export, they write records in this format and place
them in a signed container. Cross-system references are always
"(origin, id, digest)". This specification defines five things: the record envelope, the
container, references, signatures (including key lifecycle), and erasure [A1][§0].

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
- **verification context** — the set of records against which a target is verified: the
  container's records (if the target is a container) or a supplied external key/lifecycle
  set, plus a supplied external record set. Continuous chains across *multiple* containers
  are outside H0 (§9.8).
- **verifier** — an implementation that implements §14. The reference implementation is
  named `hyphaweave-verify`.
- **export** — writing a container for consumption by another system. **Import** — taking
  delivery of records from another system. This format constrains exports and references;
  it does not constrain a project's internal storage [A1b].

### 0.3 Versions and change control

`format: "weave-record/1"` changes only on a breaking change, in which case the major
version rises; kinds evolve additively (new optional members, new kinds). A verifier
**MUST NOT** ever stop verifying an older version of the format; that commitment is the
core of the multi-decade goal [K3]. Changes to this specification are made by written
proposal and, at H0, are approved by the founder and recorded in the decision log; when
governance is transferred to multiple parties, a charter will be added to the repository
[K4]. New algorithms are introduced through the algorithm-name field of digest strings
(§2.7) and signature `alg` values (§4.3), never by silently changing the meaning of
existing names [B3][E1].

### 0.4 Normative references

- RFC 2119 / RFC 8174 — requirement keywords.
- RFC 8785 — JSON Canonicalization Scheme (JCS), used as the base of WR-CJ [C1].
- RFC 4648 §5 — base64url alphabet, used without padding [Q2].
- RFC 8032 — EdDSA/Ed25519, used through the strict profile of §3 [E1][Q1].
- RFC 3339 — timestamp grammar, restricted by §2.8 [F1][Q6].
- RFC 3161 — Time-Stamp Protocol, used for external time anchors [D3].
- RFC 4998 — evidence-record renewal, cited as the model for timestamp renewal [D3].
- SPDX License List — licence expression syntax [H1][Q14].

### 0.5 Out of scope for this specification

- Transport (offline bundles, QR framing, relay queues) — not part of `weave-record/1`.
- Encrypted containers — only the rule that signatures are applied before encryption (§11.10).
- Trust in signer identity or truth of content — a signature proves which key signed which
  bytes, not that the content is true (§15).
- Guaranteed deletion of copies already distributed — erasure constrains exports and
  references (§10).
- Project-specific kinds not registered under the `weave.` namespace (§7.6).

## 1. Canonical JSON — WR-CJ v1

### 1.1 Profile

**WR-CJ v1** is the canonical JSON profile of this format. It is RFC 8785 JCS
(`https://www.rfc-editor.org/rfc/rfc8785`) restricted as follows [C1][C2][C3][C5]. WR-CJ is
used for every record, every manifest, and anything else this specification digests or
signs. An implementation **MUST** implement WR-CJ itself (or verify a library's behaviour
against the vectors); it **MUST NOT** assume that a general-purpose JSON library serialises
canonically. Where this document says "canonical JSON" it means WR-CJ v1.

### 1.2 Encoding and encoding form

1. Output **MUST** be UTF-8 with no byte-order mark, no insignificant whitespace, and no
   trailing newline [C1][C5].
2. Non-ASCII characters **MUST** be emitted as literal UTF-8; they **MUST NOT** be emitted
   as `\u` escapes. Input that is not valid UTF-8, is truncated, has trailing
   non-whitespace content, or is not an object where an object is required **MUST** be
   rejected with `E_JSON_INVALID`; an input byte-order mark **MUST** be rejected. A lone
   surrogate escape (`\uD800`–`\uDFFF` not part of a valid surrogate pair) **MUST** be
   rejected with `E_JSON_LONE_SURROGATE` [C1].
3. No Unicode normalisation is performed anywhere: member names and string values are
   compared and serialised as the exact code points given, byte for byte after UTF-8
   encoding [Q4] (**PROVISIONAL**, Appendix A). A verifier **MUST NOT** normalise, case-fold
   or otherwise transform strings [Q4].

### 1.3 Member order

Object members **MUST** be sorted ascending by the **UTF-16 code-unit sequence** of the
member name (clause 3.2.3 of RFC 8785). This ordering is normative and is not the same as UTF-8 byte
order for supplementary code points; implementations **MUST** sort by UTF-16 code units.
Member names are compared by code unit value only; no locale-dependent comparison is
allowed [C1][Q4].

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
(the canonical form of zero is `0`). Floats, exponent notation, `1.0`, `-0`, and integers
outside the interval **MUST** be rejected with `E_JSON_NUMBER_NOT_INTEGER`,
`E_JSON_NUMBER_RANGE`, or `E_JSON_NOT_CANONICAL` as applicable [C2]. A format that needs
fractional or physical quantities **MUST** encode them as strings with units, for example
`"12.50 kWh"` or `{"value":"12.50","unit":"kWh"}` [C2].

### 1.7 Booleans, nulls, arrays, objects

`true`, `false`, `null`, arrays and nested objects follow RFC 8785 [C1]. No other JSON
extensions are permitted.

### 1.8 Canonical file form

Every JSON file that this format digests or signs — record files, `manifest.json`,
`previous/manifest.json` — **MUST** contain exactly the WR-CJ bytes of its value,
optionally followed by exactly one LF byte (`0x0A`) at end of file [C5]. A single trailing
LF is tolerated; any other deviation (whitespace, member order, escape choice, number
spelling, CR bytes, extra bytes, BOM) **MUST** be rejected with `E_JSON_NOT_CANONICAL`.
Digests and signatures are always computed over the canonical bytes **without** the
optional trailing LF. A receiving implementation **MUST** re-canonicalise the parsed value
and fail if the file does not satisfy this rule; it **MUST NOT** verify a signature over
re-serialised bytes that differ from the bytes received [C5].

The canonical file form does **not** apply to files that this format neither digests nor
signs — specifically `signatures/manifest.sig.json` (see §11.3) and everything under
`readable/`. Those files **MUST** nevertheless be parsed under the input restrictions of
§1.2–§1.6 (valid UTF-8, no duplicate members, integer numbers only, no lone surrogates), and
a violation there is an error of that file's own domain (§11.3). Implementations **SHOULD**
require `signatures/manifest.sig.json` to be WR-CJ as well, for determinism, but a
container **MUST NOT** be rejected solely for a non-canonical byte spelling of a JSON file
that is neither digested nor signed, provided that file parses under the rules above.

### 1.9 Size

See §13 for size limits; a WR-CJ document larger than its limit **MUST** be rejected with
`E_JSON_SIZE` [Q5].

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
**MUST NOT** be accepted for another purpose [C4].

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
`signatures/manifest.sig.json` as `digest`, never inside `manifest.json` [I2][D1]. The
manifest digest is also the RFC 3161 `messageImprint.hashedMessage` (its raw 32 bytes,
§12.2) and the target of `previous_manifest.digest` in the next container (§11.5).

### 2.5 Key ids [E3][correction v0.1.1]

```
key_id = "ed25519:" + first 32 lowercase hex characters of SHA-256(<32-byte raw Ed25519 public key>)
```

The 32-byte raw public key is exactly the RFC 8032 public-key encoding (compressed Edwards
point). The hash input is the 32 raw bytes, **not** the hexadecimal text of the key. Hashes
of the hex text (such as the Inceptless `humanFingerprint` behaviour at the time of writing)
are **not** this format's key id, and a verifier **MUST NOT** compute key ids that way
[E3][correction v0.1.1].

Key ids are claims until a `weave.key.declared` record supplies the public key. A verifier
**MUST** recompute the key id from the declared public key and **MUST** reject any mismatch
with `E_KEY_ID_MISMATCH` (§9.1). DID strings and URLs are hints only and never
identifiers [E3].

### 2.6 base64url [Q2]

`public_key`, `sigs[].value` and `salt` use unpadded base64url: RFC 4648 §5 alphabet
`A–Z a–z 0–9 - _`, **no `=` padding** [Q2] (**PROVISIONAL**, Appendix A). Decoding **MUST**
be strict: padding, whitespace, `+` or `/` characters, and any non-zero unused trailing bits
**MUST** be rejected. Expected encoded lengths: 16 bytes → 22 characters, 32 bytes → 43
characters, 64 bytes → 86 characters.

Error codes: a malformed `sigs[].value` is `E_ENV_SIG_VALUE`; a malformed `salt` is
`E_ENV_SALT`; a malformed `public_key` is `E_KEY_PUBLIC_KEY` (in `weave.key.declared` or
`weave.key.rotated`) or the kind's body-schema error where the kind page says so. A padded
input is always an error; it is never accepted by removing the padding.

### 2.7 Digest strings and algorithm agility [B3][Q13]

A digest string is `<alg>:<lowercase hex>`. For H0 the only defined algorithm is `sha256`:
`sha256:` followed by exactly 64 lowercase hexadecimal characters. An algorithm name is an
ASCII token matching `^[a-z][a-z0-9-]*$` (lowercase letters, digits and hyphens), and its
hexadecimal part is one or more lowercase hexadecimal characters. The algorithm name is the
algorithm-agility interface; new names (`sha3-256:`, …) may be added by proposal
[B3][K4].

A digest string whose algorithm is structurally valid but not implemented is **not** a
malformed value: it is *structurally valid but unsupported*. A reference with an unknown
digest algorithm resolves to `unverifiable` (§6.3), which is not a record or container
error; a `manifest.records[]` entry with an unknown algorithm is `E_MANIFEST_RECORDS`
(invalid) because a container must list records in a form the format can verify [B3][Q13]
(**PROVISIONAL** as to the exact classification of unknown algorithms, Appendix A).
Implementations **MUST NOT** silently treat an unknown algorithm as `sha256`.

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
the error code is the one listed by the kind page or `E_MANIFEST_SCHEMA` respectively.
Future versions may extend the grammar; a verifier **MUST NOT** accept timestamps that do
not match this grammar [Q6] (**PROVISIONAL**, Appendix A). The canonical serialisation of
a TS value is exactly its 24 ASCII bytes.

## 3. Ed25519 signature profile [E1][Q1]

### 3.1 Algorithm

The only signature algorithm defined by `weave-record/1` is Ed25519 (PureEdDSA over
Curve25519, RFC 8032). HMAC signatures and other symmetric proofs are valid only inside the
originating system; they are **not** exchange-layer proofs and **MUST NOT** be represented
as `sigs` entries [E1]. The `sigs[].alg` value is the ASCII string `ed25519`; other
algorithms may be added by proposal and are unsupported for H0 (`E_ENV_SIG_ALG`).
Signature values are 64 bytes (`R ‖ S`); public keys are 32 bytes.

### 3.2 Verification steps (normative)

Verification is **single-message, strict and cofactorless**. An implementation **MUST**
perform the following checks, in this order or with equivalent short-circuit results, and
**MUST NOT** skip checks 2–3 because its underlying library "probably" rejects those cases
[Q1] (**PROVISIONAL**, Appendix A):

1. **Lengths.** Reject unless `len(public_key) == 32` and `len(signature) == 64`. Errors:
   `E_SIG_NONCANONICAL_A` (bad public key length in a signature context),
   `E_ENV_SIG_VALUE` / `E_SIG_INVALID` (bad signature value length).
2. **Point decoding of `A` (public key) and `R`.** Interpret each 32-byte value as
   little-endian `y` with the top bit as the sign of `x`. Reject if `y >= p` where
   `p = 2^255 − 19` (`E_SIG_NONCANONICAL_A`, `E_SIG_NONCANONICAL_R`); reject if no `x`
   exists (the encoded point is not on the curve) with the same code. `S` is interpreted as
   a little-endian integer.
3. **Small-order points.** Reject the eight canonical small-order encodings listed in
   §3.3: `E_SIG_SMALL_ORDER_A` when `A` is one of them, `E_SIG_SMALL_ORDER_R` when `R` is
   one of them. Compute `k = SHA-512(R ‖ A ‖ M) mod L` as an integer, where `L =
   2^252 + 27742317777372353535851937790883648493`, and reject `S >= L` with
   `E_SIG_S_OUT_OF_RANGE`.
4. **Equation.** Accept if and only if `[S]B = R + [k]A` holds, where `B` is the Ed25519
   base point; otherwise `E_SIG_INVALID`.

No batch verification, no context string, no pre-hash, no cofactored variant is permitted.
An implementation **MUST NOT** accept the identity-key forgery: an implementation of
OpenSSL's raw Ed25519 verifier has been observed to accept signatures with a small-order
`A`, so step 3 is mandatory and not optional [E1][Q1].

### 3.3 Complete canonical small-order point set

The eight canonical 32-byte encodings, lowercase hex, are the complete set of small-order
points that must be rejected in step 3:

```
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000080
0100000000000000000000000000000000000000000000000000000000000000
26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05
26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85
c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a
c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa
ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
```

The identity point `0100…00` and the all-zero encoding are both in this set; accepting them
allows an attacker to forge signatures for any message without any private key.

### 3.4 Signing

Signing is RFC 8032 PureEdDSA: `SHA-512` of the seed to derive the secret scalar and
prefix, `r = SHA-512(prefix ‖ M) mod L`, `R = [r]B`, `S = (r + SHA-512(R ‖ A ‖ M) · s) mod
L`, signature `R ‖ S`. Seed handling (generation, storage, protection) is out of scope for
this specification; see §15.

### 3.5 Aggregate signature rules

Every `sigs` entry present in a record **MUST** verify; a record with any invalid signature
is invalid. For records that require per-record signing (§4.4) at least one signature
**MUST** be by `actor.key`; missing such a signature is `E_SIG_REQUIRED` (invalid). A
signature by a key whose public key is not available in the verification context makes the
record `unverifiable` with `E_KEY_UNKNOWN` (§9.5) unless the record is the
`weave.key.declared` record that supplies that key itself (§9.1).

### 3.6 Wycheproof mapping [Q1]

For the Wycheproof Ed25519 test vectors (external cross-check data), the outcome is
prescribed **per case class**, not globally:

- `valid` cases → this profile MUST accept.
- `invalid` cases → this profile MUST reject.
- `acceptable` cases:
  - **small-order cases** — `SmallOrderPublicKey`, small-order `R`, and any other case
    where `A` or `R` decodes to one of the eight small-order points — this profile MUST
    **reject** (step 3 of §3.2);
  - **`MixedOrderPublicKey` cases** — public key with a non-zero torsion component plus a
    valid large-order component — this profile MUST **accept**. The cofactorless equation
    `[S]B = R + [k]A` verifies exactly for these vectors, and the key id commits to the
    exact public-key bytes; Wycheproof marks them `acceptable` precisely because both
    accepting and rejecting policies are considered correct.
  - any other `acceptable` case follows the same rule: reject if and only if a check of
    §3.2 requires rejection, otherwise accept.

**Deliberately not part of this profile:** a subgroup-membership check
(`[L]A == identity`). The decision-draft verdict (see `docs/open-questions.md` Q1 and the H0
contract) keeps the profile at the §3.2 checks. Rationale: RFC 8032 does not mandate a
subgroup check; an honestly generated Ed25519 public key is always prime-order; rejecting
mixed-order keys is a library-specific hardening policy; and adding `[L]A == identity`
would cost an extra scalar multiplication in every verifier without a cross-implementation
agreement benefit. The exact per-case outcome table (including the eight reject rows among
the `acceptable` set) is recorded in `vectors/external/wycheproof/PROVENANCE.md` and checked
by `tools/check_external.py` [Q1].

For RFC 8032 §7.1 vectors, all signatures MUST verify and the derived public keys MUST equal
the published ones [Q1].

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
| `format` | yes | exactly the string `"weave-record/1"`; otherwise `E_ENV_FORMAT` [A1] |
| `kind` | yes | kind name, syntax in §7.1; `weave.` names reserved to this specification; otherwise `E_ENV_KIND_SYNTAX` [§2] |
| `origin` | yes | closed object `{"project":<slug>,"instance":<key id>}`; `project` matches `^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$` and is at most 64 bytes; `instance` is a key id (§2.5); otherwise `E_ENV_ORIGIN` [B1][B2] |
| `id` | yes | 1–256 Unicode scalar values; no C0 control characters (U+0000–U+001F), no C1 control characters (U+0080–U+009F) and no U+007F (DEL); no leading or trailing U+0020 space; otherwise `E_ENV_ID` [B1] |
| `stage` | yes | one of `proposed`, `accepted`, `rejected`, `withdrawn`, `superseded`; otherwise `E_ENV_STAGE` [G1] |
| `actor` | yes | closed object (§4.2); errors `E_ENV_ACTOR*` [E2] |
| `recorded_at` | yes | TS grammar of §2.8; otherwise `E_ENV_TIME` [F1][F4] |
| `occurred_at` | no | TS grammar; claimed; no ordering rule relative to `recorded_at`; otherwise `E_ENV_TIME` [F1][F2] |
| `refs` | no | array of at most 256 reference entries `{"rel":<rel>,"ref":<reference object>}`; see §6; duplicate entries rejected; otherwise `E_ENV_REFS` [F3] |
| `labels` | no | closed object; see §8.1; otherwise `E_ENV_LABELS` [H1] |
| `salt` | conditional | 16 random bytes in base64url (§2.6). **REQUIRED** if `labels.sensitivity` is `personal` or `local-only` (`E_ENV_SALT_MISSING`); a malformed value is `E_ENV_SALT`; optional in every other case [G3c][Q3] |
| `body` | yes | a JSON object; absent or non-object is `E_ENV_BODY` (per the closed registry); body semantics are the kind's (§7) |
| `sigs` | conditional | array of 1–16 signature entries (§4.3), sorted by `key` ascending, unique keys; required by §4.4; errors `E_ENV_SIGS`, `E_ENV_SIG_ALG`, `E_ENV_SIG_KEY`, `E_ENV_SIG_VALUE` [E1][E6] |

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
(§5.3) [E2][§8].

**Exception — key-lifecycle records (PROVISIONAL, integration gap-fill).** For the three
kinds `weave.key.declared`, `weave.key.rotated` and `weave.key.revoked`, `actor.type`
merely names the class of the key the record is about (`body.key_type` for a declaration,
the old key's class for a rotation, the signing or revoked key's class for a revocation):
these records are key self-descriptions and key-state assertions, not delegated actions.
For these three kinds the four agent-only members (`model`, `on_behalf_of`, `grant`,
`idempotency_key`) are **NOT required**, and a verifier **MUST NOT** require them; a record
of one of these kinds whose `actor.type` is `agent` is valid without them. They remain
forbidden for non-agent actors by the rule above. Delegated `weave.grant` records and all
other agent-authored records keep the full obligations. Reason: a `weave.key.declared`
record for an agent-class key (required by the test keyset, which contains one declaration
per key) is self-signed by the agent key itself and has no principal to name at bootstrap
time; requiring delegation fields there would make the bootstrap declarations
unconstructible [E5][Q12] (**PROVISIONAL**, Appendix A Q28).

### 4.3 `sigs` entries (closed object)

Each entry is exactly `{"alg":"ed25519","key":<key id>,"value":<base64url 64 bytes>}`.
`sigs` is an array of 1–16 entries; it **MUST** be sorted ascending by the `key` string
(UTF-16 code-unit order; key ids are ASCII so byte order is identical) and keys **MUST** be
unique. Errors: `E_ENV_SIGS` (shape, count, order, duplicates), `E_ENV_SIG_ALG` (algorithm
not `ed25519`), `E_ENV_SIG_KEY` (malformed key id), `E_ENV_SIG_VALUE` (malformed base64url
or wrong length) [E1][E6].

### 4.4 Records and kinds that MUST be signed per record [§4][E1][E6]

The container signature (§11.3) covers every record by digest, but certain kinds must also
carry their own signatures so that they remain verifiable after being extracted from their
container. A record **MUST** carry a valid `sigs` array with at least one signature by
`actor.key` when **any** of the following holds:

1. `stage == "accepted"` (any kind);
2. `kind` is one of `weave.key.declared`, `weave.key.rotated`, `weave.key.revoked`,
   `weave.grant`, `weave.consent.granted`, `weave.consent.revoked`, `weave.erasure`.
   These kinds also **MUST** use `stage == "accepted"`; any other stage is `E_ENV_STAGE`.
3. the kind's own rules require per-record signing (none of the eight registered kinds
   adds a requirement beyond 1 and 2; future kinds may).

Otherwise `sigs` **MAY** be absent; such records are covered by the container signature
only [§4]. This split exists because agent-generated records can be numerous: they may be
container-signed as a batch, but authorisation, key, consent and erasure records may not
[§4][§8.4].

**Error precedence for required signatures (accepted during H0 integration; PROVISIONAL
Q31).** `E_SIG_REQUIRED` is emitted only in these two cases:

- (a) a record needs a per-record signature (rule 1, 2 or 3 above) and its `sigs` member is
  absent or an empty array — the presence check fails before any signature can be examined;
- (b) a record of a kind **without** a dedicated signer rule is required to be signed and,
  although `sigs` is non-empty and its signatures verify, it contains no valid signature by
  `actor.key`.

When `sigs` is non-empty but the required signer is missing or wrong for one of the seven
signer-constrained kinds, the kind's own error code is reported instead of
`E_SIG_REQUIRED`:

| kind | code for a missing/wrong required signer (with non-empty `sigs`) |
|---|---|
| `weave.key.declared` | `E_KEY_DECLARED_NOT_SELF_SIGNED` |
| `weave.key.rotated` | `E_KEY_ROTATION_SIGS` |
| `weave.key.revoked` | `E_KEY_REVOKE_SIGNER` |
| `weave.grant` (`action == "grant"`) | `E_GRANT_GRANTER` |
| `weave.grant` (`action == "revoke"`) | `E_GRANT_REVOKE_SIGNER` |
| `weave.consent.granted`, `weave.consent.revoked` | `E_ACTOR_KEY_TYPE_MISMATCH` |
| `weave.erasure` | `E_ERASE_ACTOR` |

The dedicated codes are determined at the kind-semantic check (§14.5 step 7), i.e. **after**
signature verification of the signatures that *are* present: a cryptographically invalid
present signature is `E_SIG_INVALID`, not a signer-mismatch code [E6][Q31].

### 4.5 `weave.erased` placeholder — special shape [G3][Q15]

The `weave.erased` object is **not** a normal envelope. It is exactly:

```json
{"format":"weave-record/1","kind":"weave.erased","origin":{…},"id":"…","digest":"sha256:…","attestation":{…}}
```

The object has exactly the six members `format`, `kind`, `origin`, `id`, `digest` and
`attestation`, all required; it has no `stage`, no `actor`, no `sigs` and no `body`, and any
extra member is `E_ENV_UNKNOWN_FIELD`. `origin` and `id` have the same grammar and meaning
as in a normal envelope. `digest` is the **original record digest** of the erased record;
it is a digest string (§2.7) and its `sha256` value is the original record digest computed
before erasure. `attestation` is a reference object (§6.1) to a `weave.erasure` record.

The placeholder's own record digest — the value used for its file name and manifest entry —
is computed per §2.2 over the placeholder object itself; it is different from the `digest`
member it contains. The verdict for a placeholder record is `erased`, not `valid` [G3][Q15]
(**PROVISIONAL**: the placeholder shape is settled but the error-code mapping for a
malformed `digest`/`attestation` member is a gap-filling choice, see Appendix A and
`docs/open-questions.md`). Erasure semantics, cross-checks and the integrity argument are in
§10.

## 5. Actors, keys and authorisation [E2][E4][E5][§8]

### 5.1 Key classes and actor compatibility

`weave.key.declared.body.key_type` is the key's class and is one of `human`, `agent`,
`program`, `device`, `organization`. `actor.type` **MUST** be compatible with the class of
`actor.key`: a key declared `human` may only be the actor key of records with `actor.type ==
"human"`, an `organization` key only of `organization` records, an `agent` key only of
`agent` records, and `program`/`device` likewise. A violation is
`E_ACTOR_KEY_TYPE_MISMATCH` (invalid) [E2][§8].

For **ordinary** (non-special) kinds, `actor.type` **MUST** additionally be compatible with
every signing key declared in the verification context, again with
`E_ACTOR_KEY_TYPE_MISMATCH`. For the seven kinds whose signer classes are constrained by
their kind pages (§7.2: the `weave.key.*`, `weave.grant`, `weave.consent.*` and
`weave.erasure` kinds), additional signatures beyond `actor.key` are governed by the kind
page's explicit signer requirements: a kind page may explicitly permit or require a
counter-signature by a different key class (for example an owner co-signature on a key
declaration, or the old and new key on a rotation). This scope is PROVISIONAL Q30, accepted
during H0 integration; see Appendix A [E2][§8][Q30].

### 5.2 Human keys only sign human acts [§8.3]

Agent, program and device records **MUST NOT** be signed by a key declared `human` or
`organization`. In other words, a human key may only sign acceptance, authorisation,
consent and erasure acts performed as a human [§8.3]. For ordinary (non-special) records
this is implied by §5.1; it is additionally checked for every extra signature: a signature
by a human or organization key on a record whose `actor.type` is not
`human`/`organization` is `E_ACTOR_HUMAN_KEY` (invalid). The exception accepted during H0
integration (Q30) is the three key-lifecycle kinds `weave.key.declared`,
`weave.key.rotated` and `weave.key.revoked`: they are key self-descriptions, and their
kind pages permit owner/previous-key co-signatures, so an extra human/organization
signature on them is **not** `E_ACTOR_HUMAN_KEY`. The closed registry's
`E_ACTOR_HUMAN_KEY` condition is narrowed accordingly [§8.3][Q30].

### 5.3 Key trust is TOFU [E4][Q12]

The verifier accepts a public key when a valid `weave.key.declared` record for it exists in
the verification context or in the externally supplied keyset. There is no certificate
authority, no network lookup, and no revocation distribution beyond records in context; the
local decision is trust-on-first-use plus pinning [E4] (**PROVISIONAL**, Appendix A). The
verifier reports the notice `N_KEY_TOFU` for keys accepted in this way, so a human reader
can see that trust came from the context itself rather than from a pre-existing local trust
store. A local trust store is an implementation concern outside `weave-record/1`; H0 has no
pinned-trust input beyond the keyset [Q12].

### 5.4 Agent records default to proposal only [§8.1]

An agent's output may only be a proposal unless a grant explicitly allows more. Formally:
`actor.type == "agent"` and `stage != "proposed"` requires `actor.grant` to resolve to a
valid `weave.grant` record with `action == "grant"` that, at the record's claimed
`recorded_at`:

- is not expired (`valid_until` absent/null, or `recorded_at <= valid_until`);
- is not revoked as of that time (§5.5, §9.7);
- has `grant.grantee.key == actor.key`;
- lists the record's `kind` in `grant.kinds`;
- lists the stage's action in `grant.actions`, using the mapping
  `proposed→propose`, `accepted→accept`, `rejected→reject`, `withdrawn→withdraw`,
  `superseded→supersede`.

For `stage == "proposed"` the same grant coverage is required: a proposal needs a grant
naming the kind and the `propose` action. Envelope errors are as in §4.2; the semantic
outcomes are: grant unresolvable → `unverifiable` (`E_GRANT_UNRESOLVED`); grant revoked →
`unverifiable` (`E_GRANT_REVOKED`); grant expired → `unverifiable` (`E_GRANT_EXPIRED`);
grantee mismatch → invalid (`E_GRANT_GRANTEE_MISMATCH`); kind or action not covered →
invalid (`E_GRANT_NOT_APPLICABLE`). A grant whose `valid_from` is later than the record's
`recorded_at` is outside its validity window and is treated like an expired grant
(`unverifiable`, `E_GRANT_EXPIRED`) — this not-yet-valid case is a PROVISIONAL
gap-filling reading (Appendix A) [§8.1][Q11] (**PROVISIONAL**, Appendix A).

The interaction between this generic stage/action rule and the special signer rules of
`weave.key.*` and `weave.grant` is only partly settled: key-lifecycle records
(`weave.key.declared`, `weave.key.rotated`, `weave.key.revoked`) are not delegated actions
at all, and the envelope exception of §4.2 (PROVISIONAL Q28) applies to them; they are
governed by their own §9 signer rules. A delegated `weave.grant` record authored by an
agent is governed by the delegation rules of §5.5, and the question whether the generic
stage/action mapping of this subsection additionally applies to it is a PROVISIONAL
reading (Appendix A Q10): the delegation rules are authoritative for grant records; a
parent grant used to authorise a delegated grant must contain `weave.grant` in `kinds` and
`grant` in `actions`, and requiring the stage-mapped `accept` action as well is not
applied, because a grant record's own act is granting, not accepting [§8.1][E5][Q10].

### 5.5 Grants [§8.2][Q10]

A `weave.grant` record (kind page `spec/kinds/weave.grant.md`) is either a **root grant** or
a **delegated sub-grant**:

- A grant whose `actor.type` is `human` or `organization` is a **root grant** [§8.2].
- A grant whose `actor.type` is `agent`, `program` or `device` is a **delegated sub-grant**.
  It **MUST** have `actor.grant` resolving to a parent `weave.grant` record that permits
  issuing grants; the checks are applied in this order:
  1. **resolve and cover.** An unresolvable parent is `unverifiable` (`E_GRANT_UNRESOLVED`):
     the claimed delegating authorisation cannot be checked. A resolved parent that is not
     a `weave.grant` with `action == "grant"`, or whose `kinds` do not contain
     `weave.grant`/`actions` do not contain `grant`, is `E_GRANT_GRANTER` (invalid): the
     context is resolvable but the granter is not permitted to issue this grant.
  2. **transferable.** The parent's `transferable` **MUST** be `true`; otherwise
     `E_GRANT_NOT_TRANSFERABLE`.
  3. **granter identity.** The parent's `grantee.key` **MUST** equal the sub-granter's
     `actor.key`; otherwise `E_GRANT_GRANTER`.
  4. **parent validity.** The parent **MUST** be inside its validity window at the
     sub-grant's claimed `recorded_at` and **MUST NOT** be revoked as of that time;
     otherwise `E_GRANT_GRANTER`.
  5. **no expansion.** The sub-grant's `kinds` **MUST** be a subset of the parent's
     `kinds`; its `valid_from` **MUST** be greater than or equal to the parent's
     `valid_from`; its `valid_until` **MUST** be less than or equal to the parent's
     `valid_until` (null means unbounded; a null child under a bounded parent exceeds it).
     Violations are `E_GRANT_DELEGATION_EXCEEDS`.

  (For a *record* authorised by a grant — not for the grant record itself — coverage
  failures are `E_GRANT_NOT_APPLICABLE`; see §5.4.) The ordering above is the deterministic
  precedence used by the reference implementation: the first failing check is the record's
  single error [Q10].

Revocation is modelled inside `weave.grant` with `action == "revoke"` rather than as a ninth
`weave.*` kind, because the H0 kind list names exactly eight kinds; this may be revisited in
v0.2 [Q10]. A revocation record's signer **MUST** be the original granter's `actor.key` or a
key declared `human`/`organization` (`E_GRANT_REVOKE_SIGNER`); `revoke.revokes.kind` SHOULD
be `weave.grant`; its digest **MUST** match a grant resolvable in the context
(`E_GRANT_REVOKE_REF`) [Q10].

### 5.6 What grants do not prove

Grants are claims by their signers; they authorise actions with respect to a specific
grantee key, kind and action set. The verifier checks consistency and authorisation
coverage, not the wisdom or truthfulness of the grant. `scope`, `evidence` and `remedy` are
recorded for audit and are not evaluated for authorisation in H0 [§8.2].

## 6. References [B2][B4][B5][F3]

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
`E_ENV_REFS`. URLs (`https://…`, `inceptless://…`, …) are only hints, never identity [B2].

In `refs[]` entries, the entry object is exactly `{"rel":<rel>,"ref":<reference object>}`;
duplicate entries are rejected (`E_ENV_REFS`). Two entries are duplicates when they repeat
an identical `(rel, ref)` pair: the same `rel` and the same complete reference object
(same `origin`, `id`, `digest`, and — when present — the same `kind` and `hints`). This
matches the closed registry's condition ("repeats an identical `(rel, ref)` pair") [F3].

### 6.2 `rel` — closed vocabulary [B2][B4][F3][Q7]

The `rel` member is one of the following closed set of twelve relation words:

```
derived_from  handed_off_to  receipt_of    executed_as    assessed_by   compensated_by
migrated_from reshaped_from  supersedes    correction_of  erases        revokes
```

The first eight are the base vocabulary from Inceptless `provenance_edge`; `supersedes`,
`correction_of`, `erases` and `revokes` are additions [Q7] (**PROVISIONAL**, Appendix A).
Any other `rel` value is `E_ENV_REFS` (invalid). Additions require the proposal process of
§7.6 [K4][Q7].

### 6.3 Resolution states — five states [B5]

Each reference is resolved against the verification context; the result is exactly one of:

| state | meaning |
|---|---|
| `found` | a record with the same `origin` and `id` and a matching `digest` is present and itself valid |
| `moved` | a record with the same `origin` and `id` exists, but its digest differs from the reference digest |
| `missing` | no record with that `origin` and `id` exists in the context |
| `erased` | a `weave.erased` placeholder with that `origin` and `id` exists whose `digest` member equals the reference digest (the referenced record was erased; its digest can still be checked, §10) |
| `unverifiable` | the target is present with a matching digest but is itself not valid; or the reference's digest algorithm is unsupported; or the target record's digest cannot be computed |

The first four states follow Inceptless ADR 0026; the fifth is new [B5][Q13]
(**PROVISIONAL** for unknown digest algorithms, Appendix A). `unverifiable` is not an error
by itself: unresolved references are notices only (`N_REF_MISSING`, `N_REF_MOVED`,
`N_REF_UNVERIFIABLE`) and do **not** by themselves invalidate a record, except where
authorisation, consent or erasure rules say otherwise (§5, §8, §10). A present `kind` that
contradicts the resolved target's kind is `E_REF_KIND_MISMATCH` (invalid) [B5].

H0 verification is offline and single-container: a reference whose target is not in the
context is `missing` even if a network copy might exist. Continuous chains across containers
are out of scope (§9.8, §11.5).

### 6.4 Deterministic resolution with dependencies

Reference resolution needs the target record's individual verdict, which can itself depend
on other records. A verifier **MUST** evaluate record dependencies deterministically and
without unbounded looping: a target that is individually invalid or unverifiable makes the
reference `unverifiable`; a dependency cycle that cannot be decided **MUST** be reported as
`unverifiable` (and `N_REF_UNVERIFIABLE`) rather than crashing or looping. Any deterministic
terminating strategy that yields these verdicts is conforming — for example
dependency-ordered evaluation with memoisation, or a bounded fixed-point iteration that
rebuilds key/grant state from the records verified so far and re-attempts the rest. A
verifier **MUST NOT** make its verdict depend on filesystem enumeration order; container
records are processed in manifest order, sorted by digest (§11.2) (PROVISIONAL gap-filling
model detail, Appendix A).

### 6.5 Reference digest algorithm agility

A reference digest with an unsupported algorithm resolves to `unverifiable`; it is not a
record error [B3][Q13] (**PROVISIONAL**, Appendix A). Containers, by contrast, must list
record digests with an algorithm the format can verify (§11.2) [B3].

## 7. Registered kinds, the kind registry and unknown kinds

### 7.1 Kind name syntax

A kind name matches `^[a-z][a-z0-9]*(?:[.-][a-z][a-z0-9]*)*$`, is at most 128 bytes, and
is written as `<project>.<kind>` (for example `koinoweave.receipt`) [§2]. A malformed kind
name is `E_ENV_KIND_SYNTAX`. The `weave.` namespace is reserved for kinds defined by this
specification; project kinds use their own namespace. A kind without a dot is syntactically
invalid (a kind name must have a project segment) [§2][7.6].

### 7.2 The eight kinds registered by H0

Exactly these eight kinds are registered by version 0.1 of this specification; each has a
normative kind page in `spec/kinds/` and a JSON Schema in `schemas/kinds/`:

| kind | purpose | stage constraint |
|---|---|---|
| `weave.key.declared` | publish a public key and its class [E5] | `accepted` only |
| `weave.key.rotated` | bind an old key to a new key [E5] | `accepted` only |
| `weave.key.revoked` | announce key revocation and its effective time [E5] | `accepted` only |
| `weave.grant` | authorise a grantee key for kinds/actions/scope, or revoke a grant [§8.2][Q10] | `accepted` only |
| `weave.consent.granted` | record informed consent with purpose, scope and validity [H3] | `accepted` only |
| `weave.consent.revoked` | revoke a consent record [H3] | `accepted` only |
| `weave.erasure` | attest the erasure of a record, with reason and basis [G3a] | `accepted` only |
| `weave.erased` | placeholder standing in for an erased record (§4.5) [G3] | no stage; special shape |

All seven normal kinds in this table **MUST** be signed per record (§4.4); all except
`weave.erased` also **MUST** use `stage == "accepted"` (other stages `E_ENV_STAGE`)
[E5][H3][G3a]. `weave.erased` is the special non-envelope shape of §4.5 [G3][Q15].
Project-specific kinds (for example `koinoweave.receipt`) are **not** registered by H0
[§2][A1a].

### 7.3 Unknown kinds are opaque but not understood [§2][K3]

Any syntactically valid kind not registered in the version of this specification that a
verifier implements is **opaque but not understood** [K3]. For such a record a verifier:

1. **MUST** verify the envelope structure, references, signatures, labels and
   authorisation rules exactly as for a known kind;
2. **MUST NOT** validate the `body` and **MUST NOT** claim to understand it;
3. **MUST** report `kind_known: false` and the notice `N_KIND_UNKNOWN_OPAQUE`;
4. **MUST NOT** mark the record invalid merely because the kind is unregistered.

An unknown kind is therefore verified for integrity and authorisation, not for meaning. A
verifier that *does* understand a later kind (because it is newer) verifies it under its
own rules; a verifier that does not, keeps the container acceptable. This forward
compatibility is the reason unknown kinds must never be treated as understood, and never be
dropped from a container either: they stay in the manifest, are digested, and are
transported verbatim [K3].

### 7.4 Reserved symbols and closed known members

Symbols reserved by a registered kind (for example the meaning of `weave.grant.action`) are
fixed by the kind page. New members may be added to a registered kind's body in later
versions (additive evolution) [K3][7.5]; a verifier **MUST** ignore body members it does
not know and **MUST NOT** reject a record because of an unknown body member, unless the
kind page says the body members are closed. The known members of each registered kind are
closed: an unknown value in a known-member position is the kind's body error.

### 7.5 Body evolution is additive [K3]

`body` objects of registered kinds accept additional unknown members (additive evolution).
The body object itself is not closed: future versions may add members. Each **known** member
has a fixed grammar and meaning; a verifier validates only the known members it implements
and is silent about unknown ones. This is the mechanism by which the format lasts: a
verifier never abandons older records [K3].

### 7.6 Kind registration process [K4][A1a]

A new kind (whether in the `weave.` namespace or a project namespace) is introduced by a
written proposal that specifies: the kind name; purpose; envelope constraints (stage,
actor type, mandatory signing); the `body` member table with types, closed vocabularies and
error codes; semantic rules (especially any cross-record rules); security considerations; a
JSON Schema; and test vectors. The proposal is approved under the change process of §0.3
(founder approval and decision-log entry at H0; multi-party charter later) [K4]. Kinds are
registered by the specification repository, not by individual exporters; exporters in
project repositories may emit their own kinds before registration only as opaque,
namespace-owned kinds, and adapters remain the projects' responsibility [A1a][K4].

### 7.7 Per-kind pages are normative

The normative rules for each registered kind — purpose, envelope requirements, body
members, semantic rules, error codes and canonical JSON examples — are in its kind page
under `spec/kinds/`. Those pages are part of this specification. This section states only
the registry-level rules that apply to all kinds. A record whose body violates its kind's
rules is `E_KIND_BODY_SCHEMA` unless the kind page names a more specific error code.

## 8. Labels, consent and licence [H1][H2][H3]

### 8.1 `labels` (closed object)

`labels` is an optional, closed object:

| member | required | rule |
|---|---|---|
| `sensitivity` | no | one of `public`, `internal`, `personal`, `local-only`; any other value is `E_ENV_SENSITIVITY` [H1] |
| `licence` | no | an SPDX licence expression (syntax only, §8.7); malformed is `E_ENV_LICENCE` [H1][Q14] |
| `consent` | no | a reference object (§6.1) to a `weave.consent.*` record; malformed is `E_ENV_LABELS` [H1][H3] |

`labels` is a closed object: unknown members, wrong member types and a `sensitivity` value
outside the closed set are `E_ENV_LABELS`/`E_ENV_SENSITIVITY`. The absence of
`sensitivity` is **not** a structural error: `labels` may legitimately carry only
`licence` or `consent` (Lead ruling during H0 integration, reversing the earlier
registry wording). Missing sensitivity is handled semantically, not structurally: a
derived record with no `labels.sensitivity` while a resolved `derived_from` input ranks
above `public` is `E_LABEL_DOWNGRADE` (§8.4), and `personal`/`local-only` records must
carry a salt (§8.3). Project-specific labels (a permission lattice, markings, …) belong
in `body` and **MUST** be mapped by the project to one of the four sensitivity ranks;
they never replace the four-rank vocabulary [H1].

### 8.2 Sensitivity rank [H2]

Sensitivity ranks are ordered `public` 0 < `internal` 1 < `personal` 2 < `local-only` 3.
`personal` includes any record containing personal data; `local-only` means the record
**MUST NOT** leave the machine or project boundary that created it.

### 8.3 Salt [G3c][Q3]

A record whose `labels.sensitivity` is `personal` or `local-only` **MUST** carry a `salt`
member: exactly 16 random bytes in unpadded base64url (22 characters). The salt is included
in the record digest (§2.2) but is not otherwise interpreted by the verifier; the verifier
**MUST NOT** attempt to test randomness (impossible offline) and **MUST NOT** require a salt
for other records. The salt makes the original digest non-brute-forceable after the content
and salt are deleted on erasure [G3c] (**PROVISIONAL**, Appendix A).

### 8.4 Label propagation — strictest wins [H2][Q16]

Labels propagate along derivation and the strictest wins: for each resolved reference with
`rel == "derived_from"`, the referring record's sensitivity rank **MUST** be greater than or
equal to the target's sensitivity rank. If the referring record has no
`labels.sensitivity` while a resolved `derived_from` input has a rank greater than 0, that
is `E_LABEL_DOWNGRADE` (invalid): absence cannot prove non-downgrade, so the conservative
reading rejects it [H2] (**PROVISIONAL**, Appendix A). A reference that cannot be resolved
leaves propagation unchecked, reported as the notice `N_LABEL_PROPAGATION_UNCHECKED`
(record verdict unchanged by that notice alone) [H2].

A missing sensitivity label on a record with **known public** inputs is acceptable; a
missing label is only an error when a resolved input ranks above 0. Guidance: exporters
SHOULD always write an explicit sensitivity label when the record is not public, because
absence is easy to misread.

### 8.5 `local-only` must not be exported [H2]

A container is an export. Any record in a container whose sensitivity is `local-only` makes
the container invalid with `E_LABEL_LOCAL_ONLY_EXPORTED` (export refused); there is no
exemption for agent-generated records and no override flag [H2]. The reference implementation
models this after the "assert export may leave" check of the source projects. A
`local-only` record verified as a **single record** (not inside a container) is not an
export and does not trigger this error; the export refusal applies to containers.

### 8.6 Consent references and revocation [H3]

`labels.consent` is a reference to a consent record. The referenced record's kind **MUST**
be `weave.consent.granted` or `weave.consent.revoked`; resolving to any other kind is
`E_REF_KIND_MISMATCH` (invalid); an unresolvable consent reference produces the notice
`N_CONSENT_UNRESOLVED` and does not by itself change the record verdict [H1][H3]. The fact
that a referenced consent has since been revoked is a semantic question about whether the
record's purpose is still covered; H0 verification records consent as a claim and does not
re-evaluate consent coverage (limitation, §14.9). Consent conditions (purpose, scope,
validity) are authoring obligations for exporters, not mechanically checkable claims in H0.

### 8.7 Licence expressions [H1][Q14]

`labels.licence` is an SPDX licence expression [H1][Q14]. Only syntax is checked offline;
membership in the SPDX License List is **not** checked and a verifier **MUST NOT** reject an
unknown identifier on membership grounds (**PROVISIONAL**, Appendix A). The accepted
syntax is the following grammar, with tokens separated by optional ASCII whitespace:

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
- the verifier **MUST NOT** evaluate operator precedence semantics or check that a licence
  and exception actually exist in the SPDX list; it reports a syntactic violation only as
  `E_ENV_LICENCE`.

The rule is deliberately permissive on membership and strict on structure.

### 8.8 Labels are claims [H1]

Labels are claims attached to a signed record. A verifier checks consistency of the claims
(propagation, export refusal, syntax), not their truth: it cannot know whether data really
is personal, or whether a licence claim is legally correct. Reporting must not imply
otherwise [H1].

## 9. Key lifecycle and authorisation state [E5][Q20]

Key lifecycle is carried by records, so that keys can be exchanged, revoked and replaced
without a central CA [E4][E5]. The verifier builds state from records in the verification
context: key declarations (key id → class, validity window), revocations (key id → reason,
effective time), grants, grant revocations, consents and erasures [E5].

### 9.1 `weave.key.declared`

Publishes a key: `body.key` is the declared key id, `body.public_key` the 32 raw bytes in
base64url, `body.key_type` the key class, optional `valid_from`/`valid_until` and an
optional `note`; `actor.type` **MUST** equal `body.key_type`, `actor.key` **MUST** equal
`body.key`, the declared key id **MUST** equal the §2.5 derivation from `public_key`
(`E_KEY_ID_MISMATCH`), the record **MUST** include a signature by the declared key
(`E_KEY_DECLARED_NOT_SELF_SIGNED`), and `valid_from` **MUST** be less than or equal to
`valid_until` when both are present (`E_KEY_VALIDITY`; per the closed registry this code
covers the validity-window inversion of `weave.key.declared` and of `weave.grant`, while
`weave.consent.granted` uses `E_CONSENT_VALIDITY`). Signatures by other keys (owner,
previous key) MAY be appended. Because `actor.type` here only names the declared key's
class, the agent-only envelope members are not required for this kind even when
`body.key_type` is `agent` (§4.2 exception, PROVISIONAL Q28). Full rules in
`spec/kinds/weave.key.declared.md` [E5].

### 9.2 `weave.key.rotated`

Binds an old key to a new key: both keys signed the rotation; `old_key != new_key`; public
keys, when present, must match their ids; a public-key/id contradiction in a rotation is
`E_KEY_ROTATION_KEYS` (per the closed registry; `E_KEY_ID_MISMATCH` is reserved for
declarations). `actor.key` is the old key; `actor.type` names the old key's class (and does
not trigger the agent-only envelope obligations of §4.2, per the key-lifecycle exception
there, PROVISIONAL Q28). Full rules in `spec/kinds/weave.key.rotated.md` [E5].

### 9.3 `weave.key.revoked`

Announces revocation with `effective_at` and reason `key-compromise`, `retired` or `other`;
`effective_at <= recorded_at` (`E_KEY_REVOKE_EFFECTIVE`). A `key-compromise` revocation
requires a signature by a key declared `human` or `organization`
(`E_KEY_REVOKE_SIGNER`); `retired`/`other` require a signature by the revoked key itself or
by a human/organization key. Revocation is retroactive only for `key-compromise` (§9.4).
`actor.type` names the class of the signing or revoked key described by the record; the
agent-only envelope obligations of §4.2 are not required for this kind (key-lifecycle
exception, PROVISIONAL Q28). Full rules in `spec/kinds/weave.key.revoked.md` [E5].

### 9.4 Effects of revocations and validity windows [E5][Q20]

Let the revoked key have a revocation with claimed `effective_at == T`, and let a signature
carry the claimed `recorded_at` of its record (`created_at` for a manifest signature):

| reason | signature time | outcome |
|---|---|---|
| `retired` (or `other`, treated as retired) | `recorded_at > T` | invalid (`E_KEY_REVOKED`) |
| `key-compromise` | `recorded_at > T`, record covered by a verified L2 timestamp with `genTime <= T` | valid (the record provably existed before the compromise) |
| `key-compromise` | `recorded_at > T`, no such timestamp | invalid (`E_KEY_COMPROMISED`) |
| any reason | `recorded_at <= T` | unaffected by this revocation |

"Covered by a verified L2 timestamp" means: the record is listed in a container whose
manifest carries a verified RFC 3161 timestamp (§12.2) with `genTime <= T`. A single-record
target has no timestamp evidence, so the compromise exception cannot be applied there; such
a signature is invalid after a compromise revocation. The same rule applies to manifest
signatures using the manifest timestamp set [E5][D3].

A signature by a declared key whose `valid_until` is present and whose claimed
`recorded_at > valid_until` is `E_KEY_EXPIRED` (invalid) [E5][Q20] (**PROVISIONAL**: a
signature made **before** a declared `valid_from` is treated as outside the validity window
and is also `E_KEY_EXPIRED`, Appendix A). A signature by a key with no declaration anywhere
in the context is `unverifiable` (`E_KEY_UNKNOWN`); this applies to manifest signatures as
well [E4][Q12].

### 9.5 Revocation records are self-evidencing [E5]

The revocation of the key that signed a `weave.key.revoked` record does not invalidate that
revocation record; it is the revocation itself. Likewise, a `weave.key.declared` record that
supplies its own key is verifiable from its own `public_key` even though it may be the first
time the key is seen in the context (self-declaration bootstrap) [E5][Q12].

### 9.6 Grant revocation effects [Q11]

A record that uses `actor.grant` G at claimed `recorded_at`, where a `weave.grant`
revocation record R revokes G with `R.revokes` resolving to G and `R.effective_at <=
recorded_at`, is `unverifiable` (`E_GRANT_REVOKED`). Records at or before `effective_at` are
unaffected. A revoked or expired grant therefore makes a new record unverifiable rather
than invalid; a grantee, kind or action mismatch is invalid. This split is deliberate: the
signed content is intact, but the authorisation state cannot be established [Q11]
(**PROVISIONAL**, Appendix A).

### 9.7 Grant chains across records

Grants may delegate (root grant → delegated sub-grant → records using the sub-grant). The
verifier evaluates the chain in dependency order; an unresolvable or invalid parent link
makes the dependent grant unusable, and records using it `unverifiable` (`E_GRANT_UNRESOLVED`
or the specific parent error). Grants are only valid within their validity windows; see
§5.4 and `spec/kinds/weave.grant.md`.

### 9.8 Continuous chains are out of scope for H0

Continuous verification across a chain of many containers is outside H0. A verifier verifies
one container plus the immediately previous manifest bytes embedded in it (§11.5). Rollback
and truncation are detected only by the manifest chain plus external anchors (§11.5, §12),
and only to the extent the previous manifest is supplied [D2]. This is a declared limitation,
not a claim of complete history verification.

## 10. Erasure [G3][Q15][Q16]

### 10.1 The replacement shape

Erasure in an export works by replacing the erased record with the placeholder of §4.5.
References to the erased record resolve to `erased` when the placeholder's `digest` member
equals the reference's digest (§6.3). The placeholder keeps `origin` and `id` (so the
identity is still known) and keeps the **original record digest** (so references and the
digest chain remain meaningful), but no content, no salt and no signature of the original
record [G3]. The placeholder itself is digested and listed in the container manifest like
any record [G3].

### 10.2 The attestation record `weave.erasure`

The placeholder's `attestation` reference points to a `weave.erasure` record (kind page
`spec/kinds/weave.erasure.md`). That record is signed per record (§4.4), must have
`actor.type == "human"` (`E_ERASE_ACTOR`), and carries: the reference to the erased record
(including its original digest), a closed-vocabulary reason (`data-subject-request`,
`legal`, `safety`, `mistaken-inclusion`, `retention-expired`, `other`), an optional note, an
optional basis reference (authorisation for the erasure, for example a consent revocation
or a legal order), and an optional `executed_at` time [G3a]. The attestation is what makes
the erasure auditable: who attested to erasing what, when, and why.

### 10.3 Cross-checks in a container [G3][G3a]

When both the placeholder and its erasure record are present in a container:

1. the erasure record's `erased` reference **MUST** resolve to a `weave.erased`
   placeholder in the same container with the same `origin` and `id` whose `digest`
   member equals `erasure.body.erased.digest`; a missing placeholder, an `origin`/`id`
   mismatch or a digest mismatch is `E_ERASE_DIGEST_MISMATCH`;
2. the placeholder's `attestation` reference **MUST** resolve to this erasure record
   (`E_ERASE_ATTESTATION`);
3. the original live record **MUST NOT** also be present in the container; if a record with
   the same `origin` and `id` and computed digest equal to the placeholder's `digest` is
   present, that is `E_ERASE_CONTRADICTION` (the erasure is contradicted). Two placeholders
   for the same target are also `E_ERASE_CONTRADICTION` [G3].

For a standalone `weave.erased` record target there is no container context: the verdict is
`erased` (exit code 0), the attestation reference is reported as unresolved (its state will
normally be `missing`), and the cross-checks of this subsection are not applied because
their inputs are absent; the verifier reports that limitation [G3][Q15].

### 10.4 Integrity argument for the erased entry (G3b) [G3b]

The erased entry's integrity does **not** depend on the hash of the deleted content (there
is no content left to hash). It is proven by the combination of:

1. the **attestation record** — signed, stating the erasure and the original digest;
2. the **original digest** retained in the placeholder — so all existing references still
   resolve to `erased` and cannot be repurposed for different content;
3. the **container manifest and chain position** — the placeholder's own digest is listed
   in the signed manifest with its position claims, so a later substitution or deletion of
   the placeholder is detectable exactly like tampering with any other record.

A verifier **MUST NOT** require the deleted content, or a hash of it, to be present; it
**MUST** treat a correctly attested erased entry as an integrated part of the container. A
verifier **MUST NOT** report an erased record as invalid merely because its content is
absent [G3b].

### 10.5 Withdrawal is not erasure [G3e]

Withdrawing a claim (changing one's judgement) only appends a new record; it never triggers
erasure. Erasure is for data that must stop being present (data-subject requests, legal
requirements, safety, mistaken inclusion, retention expiry), not for changing a position
[G3e].

### 10.6 Scope and limits of erasure [A1b]

Erasure rules constrain **exports and references**. A project's internal storage may really
delete content; the minimum internal change is to retain "digest plus attestation record"
content can be deleted, the audit trail remains [A1b]. This specification does **not**
promise that already distributed copies can be recalled or deleted; it promises that an
erased record is visibly erased, references resolve to `erased`, and a container that
contains the live record plus a claim of erasure is rejected (§10.3) [A1b][G3].

### 10.7 Project guidance encoded as requirements on exporters [G3d][G4]

- Before deleting content for retention/limit reasons, an exporter **MUST** record the
  digest and append an erasure attestation with reason `retention-expired`; data must not
  silently disappear (the Tacitweave lesson) [G3d].
- A system that previously stored a digest of a record it now erases (the Teloweave
  `erase` path) **MUST** replace the content with the digest-plus-placeholder form rather
  than removing the entry entirely [G4].

These are requirements on export adapters (project repositories), not on the verifier; the
verifier enforces the resulting shapes in containers.

## 11. Container format [I1][I2][D1][D2][Q8][Q19]

### 11.1 Layout

A container is a directory, or the zip of that directory, with exactly this layout:

```
manifest.json
signatures/manifest.sig.json
signatures/timestamp-<n>.tsr          # L2 only; n is a decimal integer >= 1
signatures/tsa-cert-<n>.pem           # optional; NOT trusted
previous/manifest.json                # required iff manifest.previous_manifest != null
records/<64 lowercase hex>.json
blobs/sha256/<64 lowercase hex>
readable/                             # optional; ignored entirely
```

All entries are ordinary files; the format depends on no database and no runtime [I1]. A
container with no `manifest.json` is `E_MANIFEST_MISSING` (invalid). Directories not listed
here, or unknown files inside a listed directory, are `E_CONTAINER_ENTRY` — with two special cases: an extra file in `records/` is
`E_MANIFEST_RECORD_EXTRA`, and an extra file in `blobs/` is `E_MANIFEST_BLOB`. The
`readable/` directory and anything below it is ignored entirely: it is never parsed, never
hashed, never trusted, and never part of the manifest [Q19] (**PROVISIONAL**, Appendix A).
All JSON files that are digested use the canonical file form (§1.8) and all files obey the
size limits of §13.

### 11.2 `manifest.json` (closed object)

The manifest is a canonical JSON object with these members; unknown members are
`E_MANIFEST_SCHEMA`. The manifest field set, the separate attestation file
(`signatures/manifest.sig.json`), the distinct `manifest-digest` domain prefix and the
embedded `previous/manifest.json` are the PROVISIONAL field-design choices of Q8
(Appendix A) [Q8]: they keep the signed manifest free of signature bytes so that manual
verification needs no JSON surgery on signed content.

| member | required | rule |
|---|---|---|
| `format` | yes | exactly `"weave-record/1"`; otherwise `E_MANIFEST_FORMAT` |
| `manifest_version` | yes | the integer `1`. An integer greater than 1 means a newer, unsupported manifest version → `E_MANIFEST_VERSION`. A future verifier must still accept version 1 (never abandon older versions) [K3] |
| `origin` | yes | origin object (§4.1) of the **publisher of this container**; malformed → `E_MANIFEST_SCHEMA` |
| `created_at` | yes | TS (§2.8) of container creation; malformed → `E_MANIFEST_SCHEMA` |
| `level` | yes | `"L0"`, `"L1"` or `"L2"`; any other value → `E_MANIFEST_LEVEL` |
| `records` | yes | array of 1–100000 entries (§11.2.1), sorted by `digest` ascending, unique digests; violations `E_MANIFEST_RECORDS` |
| `previous_manifest` | yes | `null`, or exactly `{"digest":<digest string>}` (closed); malformed `E_MANIFEST_SCHEMA` |
| `chain` | conditional | for L0: absent or `null` (a non-null `chain` for L0 → `E_MANIFEST_LEVEL`); for L1/L2: required exactly `{"algorithm":"sha256","head":<digest string>}` (missing or null → `E_MANIFEST_L1_NO_HEAD`) |
| `blobs` | no | array of blobs (§11.7); absent means no blobs; malformed `E_MANIFEST_SCHEMA` |

The manifest's `origin` is the publisher of the container; records inside the container may
carry other origins (a container may transport records received from other systems) and
there is no requirement that record origins equal the manifest origin.

#### 11.2.1 `manifest.records[]` entries

Each entry is a closed object:

```
{"id":<string>, "kind":<kind name>, "digest":<digest string>, "chain_index":<integer>=0 (optional)}
```

- `id` and `kind` **MUST** have the same grammar as the envelope's `id` and `kind`
  (§4.1, §7.1), and **MUST** equal the values inside the record file they describe
  (PROVISIONAL gap-filling cross-check, §11.6; a mismatch is `E_MANIFEST_RECORDS`).
- `digest` **MUST** be the record digest of the referenced record (§2.2). For H0 it
  **MUST** be `sha256:<64 lowercase hex>`; an unsupported algorithm is
  `E_MANIFEST_RECORDS` (a container must list verifiable digests) [B3][Q13].
- entries **MUST** be sorted ascending by the `digest` string (UTF-16 code-unit order) and
  digests **MUST** be unique.
- `chain_index` is an integer greater than or equal to zero. It is required for L1/L2 and
  MUST be unique among entries there (missing/duplicate → `E_MANIFEST_L1_NO_POSITION`).
  For L0 entries it is optional; when present at L0 it is ignored (it is only a position
  claim for the internal chain of L1/L2).

The number of entries is bounded: at least 1, at most 100,000 (`E_MANIFEST_RECORDS`).
`manifest.records` order (sorted by digest) is the deterministic order in which records are
reported and processed.

### 11.3 `signatures/manifest.sig.json` (closed object)

The manifest signature and timestamp inventory is a JSON object with exactly these members:

```json
{"digest":<digest string>, "format":"weave-record/1",
 "signatures":[{"alg":"ed25519","key":<key id>,"value":<base64url 64 bytes>}],
 "timestamps":[{"digest":<digest string>,"path":"signatures/timestamp-<n>.tsr"}]}
```

- `digest` **MUST** equal the §2.4 manifest digest of `manifest.json`
  (`E_MANIFEST_DIGEST`).
- `format` **MUST** be `"weave-record/1"` (`E_MANIFEST_SCHEMA`).
- `signatures` **MUST** contain 1–16 entries, sorted ascending by `key`, with unique keys,
  each entry closed with exactly `alg`/`key`/`value`; malformed shape is
  `E_MANIFEST_SCHEMA`; empty is `E_MANIFEST_UNSIGNED`; every signature **MUST** verify
  against the manifest signature message (§2.4) (`E_MANIFEST_SIG_INVALID`; a signature by
  an unknown key is `unverifiable`, `E_KEY_UNKNOWN`). At least one signature is required
  [I2].
- `timestamps` **MUST** be present; it **MAY** be an empty array (for L0/L1). Its entries
  are closed objects, sorted ascending by `path`, unique paths; each `path` **MUST** match
  `signatures/timestamp-<n>.tsr`; each `digest` **MUST** be `sha256:<64 lowercase hex>` of
  the `.tsr` bytes (otherwise `E_TS_FILE`/`E_MANIFEST_SCHEMA`). For L0 and L1 it **MUST**
  be empty; for L2 it **MUST** contain at least one entry (`E_MANIFEST_L2_NO_TIMESTAMP`);
  a list inconsistent with `level` is `E_MANIFEST_LEVEL`.

`signatures/manifest.sig.json` is neither digested nor signed by this format; it is
nevertheless parsed under the input restrictions of §1 (see §1.8). Its `signatures` array
is the container signature required by [I2]. Optional `tsa-cert-<n>.pem` files are allowed
in `signatures/` and are never trusted (§12.3); every `.tsr` file in `signatures/`
**MUST** appear in `timestamps` and every listed `.tsr` **MUST** exist.

### 11.4 Integrity levels [A1c][D2][Q9]

The manifest **MUST** state its level [A1c]:

- **L0** — only the container signature taken at export time. Intended for source systems
  with no internal hash chain. An L0 container proves: the manifest was signed by the
  holder of the signing key; every listed record has the listed digest; the records are
  consistent with the manifest at the time of signing. It proves nothing about the order or
  existence of records before export beyond what signatures and timestamps in the records
  themselves show.
- **L1** — L0 plus the head of the source system's internal hash chain and each record's
  position on that chain (`chain.head` and `chain_index`). L1 is a **claim**: an offline
  verifier cannot recompute an internal chain from exported records. For an L1 container a
  verifier **MUST** report `chain.status = "unverified"`, `level_verified = "L0"`, and the
  notice `N_CHAIN_CLAIM_UNVERIFIED`; it **MUST NOT** claim to have verified the internal
  chain [Q9] (**PROVISIONAL**, Appendix A).
- **L2** — L1 plus at least one external time anchor, recommended RFC 3161, over the
  manifest digest (§12). L2 is verified only under the rules of §12; mere presence of
  `.tsr` files is never enough.

The claimed `level` is a claim; `level_verified` reports what was actually verified. A
container whose claimed level cannot be verified must not be reported as valid at that
level (§12, §14).

### 11.5 Manifest chain continuity [D1][D2]

- If `manifest.previous_manifest` is non-null, `previous/manifest.json` **MUST** exist. Its
  bytes **MUST** satisfy the canonical file form (§1.8) and its §2.4 manifest digest
  **MUST** equal `previous_manifest.digest` (`E_MANIFEST_CHAIN_MISSING` when the file is
  missing, `E_MANIFEST_CHAIN` when the digest mismatches or the previous manifest's
  `format`/`manifest_version` are unsupported).
- If `manifest.previous_manifest` is null, `previous/` **MUST** be absent or empty
  (`E_MANIFEST_CHAIN_UNEXPECTED`).
- The previous manifest's **own signature is not re-verified** by default: the chain is a
  chain over manifest digests, mirroring the source project's `previousManifestHash`. A
  verifier **MAY** additionally verify the previous signature when its keys are available
  and **MUST** report `N_PREVIOUS_SIG_UNVERIFIED` when it does not [D1].

The chain makes tampering with one container detectable in the next; it does not, by
itself, detect rollback or truncation — that requires an external anchor (§12) or the
latest container digest from an independent source [D2]. The `--previous <dir>` command
option additionally requires the supplied previous container's manifest digest to equal
`previous_manifest.digest` (otherwise `E_MANIFEST_CHAIN`).

### 11.6 `records/` consistency [I1]

For every `manifest.records[]` entry:

1. the file `records/<hex>.json` **MUST** exist, where `<hex>` is the 64 lowercase hex
   characters of the entry digest (`E_MANIFEST_RECORD_MISSING`);
2. its bytes **MUST** satisfy the canonical file form (§1.8);
3. its §2.2 record digest **MUST** equal the digest in the entry and in the file name
   (`E_MANIFEST_RECORD_DIGEST`);
4. the record's `id` and `kind` **MUST** equal the entry's `id` and `kind`
   (`E_MANIFEST_RECORDS`; PROVISIONAL gap-filling cross-check, Appendix A);
5. every file in `records/` **MUST** be listed by an entry, and every file name **MUST**
   be `<64 lowercase hex>.json`; a file that is unlisted **or** has a malformed name is
   `E_MANIFEST_RECORD_EXTRA` (per the closed registry).

The records are then verified per §14; a record that is individually invalid does not make
the container structurally inconsistent (the report distinguishes record errors from
container errors), but a container manifest listing a record whose file is absent or whose
digest mismatches is invalid.

### 11.7 Blobs [I1]

Attachments are content-addressed as `blobs/sha256/<64 lowercase hex>`. `manifest.blobs`,
when present, is an array of closed objects `{"digest":<digest string>,"size":<integer>=0}`,
sorted ascending by `digest`, unique digests. For H0 every blob digest **MUST** be
`sha256:<64 lowercase hex>` (the path convention only defines sha256) and every blob's
`size` **MUST** equal its byte length, at most `MAX_BLOB_BYTES`; at most 10,000 blobs.
Every `blobs/sha256/<hex>` file **MUST** be listed with matching sha256 and size, every
listed blob **MUST** exist, and a present `blobs/` directory **MUST** have a non-empty
`manifest.blobs` listing; all violations (including an unsupported blob digest algorithm
and a missing/extra/wrong-size blob) are `E_MANIFEST_BLOB`.
Blob files are not JSON and are not canonicalised; they are hashed as raw bytes.
`readable/` is not blobs and is never hashed.

### 11.8 `readable/` [I1][Q19]

`readable/` is an optional human-readable rendering directory. It is ignored entirely: not
parsed, not hashed, not trusted, not listed in the manifest. Its presence or content never
changes a verdict; a verifier **MAY** report the informational notice `N_READABLE_PRESENT`
[Q19] (**PROVISIONAL**, Appendix A).

### 11.9 Zip form [I1]

The zip form of a container contains exactly the same relative paths as the directory form,
with `/` separators. It **MUST NOT** contain absolute paths, `..` segments, duplicate entry
names, symbolic links, or entries that escape the root; per the closed registry these are
`E_CONTAINER_ENTRY` (layout/entry-safety violations), as are unknown files under
`signatures/` or `previous/`. Encrypted entries, unsupported compression and an archive
that cannot be read as a zip are `E_CONTAINER_ZIP`. Entries **MAY** be stored or deflated;
directory entries are ignored. Content layout problems keep their content codes
(`E_MANIFEST_*`). Limits apply to uncompressed sizes and to entry counts (§13) and are
checked during streaming; a zip bomb is bounded by those limits (`E_CONTAINER_SIZE`), never
a crash.

### 11.10 Encrypted export [I3]

Encryption, if used, **MUST** be applied after signing: the container is signed, then the
whole container is encrypted by an envelope defined outside this format. The receiver
decrypts and verifies the plaintext container exactly as in §11.1. An encryption envelope
is **not** part of `weave-record/1`; this specification defines no encrypted format [I3].

### 11.11 Import preserves received bytes [D4]

An importing system **MUST** store the received `weave-record/1` bytes unchanged. It **MAY**
project them into its own internal format for use, but it **MUST NOT** replace the
original with a re-hashed or re-serialised copy; the received bytes are the evidence
[D4][A1d]. This is a requirement on importers (project adapters), not on the verifier.

## 12. Integrity levels and RFC 3161 timestamps [A1c][D3]

### 12.1 Level claims

The manifest's `level` is a claim (§11.4). L0 and L1 need no external data. L2 requires at
least one external time anchor. A verifier **MUST NOT** claim a level it did not verify and
**MUST NOT** claim L2 solely because `.tsr` files exist [A1c][D3].

### 12.2 L2 timestamp validation

For each `timestamps[]` entry of `signatures/manifest.sig.json`, the referenced
`signatures/timestamp-<n>.tsr` file **MUST**:

1. exist and hash to the listed digest (`E_TS_FILE`);
2. be a DER-encoded RFC 3161 `TimeStampResp` containing a `granted` token (`E_TS_SCHEMA`);
3. contain a `TSTInfo` whose `messageImprint` is exactly
   `{hashAlgorithm: sha256, hashedMessage: <the raw 32 bytes of the manifest digest>}`
   (`E_TS_IMPRINT`);
4. carry a CMS signature over the token's signed attributes that verifies (`E_TS_CMS`).

The timestamp's `genTime` is the claimed time of anchoring. Timestamp validation is
independent of the container's other checks; an invalid timestamp makes the container
invalid (`E_TS_*`), not merely unverifiable [D3].

### 12.3 Trust anchors

Verifying an RFC 3161 token does not by itself prove *when* it was issued: the signer
certificate must be trusted. Verification therefore requires an explicit trust anchor
(`--tsa-trust <pem>`, a file of one or more PEM certificates): the timestamp signer
certificate must match the SHA-256 fingerprint of one anchor (`E_TS_UNTRUSTED`), its
validity window must contain `genTime` (`E_TS_CERT`), and the ESS `messageDigest` signed
attributes must verify as part of the CMS signature (`E_TS_CMS`). Without an anchor, a
timestamp is reported `present-unverified`: the container verdict **MUST** be
`unverifiable` (`E_TS_UNTRUSTED`) and **MUST NOT** be `valid`; the report lists the missing
trust as a limitation/gap [D3]. `tsa-cert-<n>.pem` files in the container are **never**
trusted on their own; they are transport conveniences only [D3].

### 12.4 Multiple timestamps

Multiple timestamps are allowed, including from different timestamp authorities. A container
is L2-verified if and only if at least one listed timestamp verifies under §12.3 and all
listed timestamps are individually either valid or `present-unverified`. An individually
invalid timestamp entry makes the container invalid, even if another timestamp verifies.

### 12.5 Renewal before expiry [D3]

Algorithms and timestamp certificates expire. Before expiry, an evidence owner SHOULD obtain
a new timestamp over the old timestamp together with the manifest (the evidence
renewal model of RFC 4998), forming a renewal chain, so that the evidence remains verifiable
decades later. This specification defines only the per-container L2 format; renewal chains
are a future extension [D3].

### 12.6 Verification of an untrusted timestamp is not a time proof

An unverified timestamp gives no trusted time; a verified timestamp proves only that the
timestamp authority signed an imprint at some time (and, under the trust anchor's
assumptions, no later than that). It does not prove the content is true. See §15
[D3][A1c].

## 13. Size and resource limits [Q5]

A conforming verifier **MUST** enforce at least these limits, before or while reading
inputs. Exceeding a limit is an error, never a crash or an unbounded read [Q5]
(**PROVISIONAL**, Appendix A).

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

Limits are checked on the streamed bytes, not on a fully materialised decompression. A zip
whose decompression would exceed the uncompressed-byte limit is `E_CONTAINER_SIZE`
(invalid). Implementations **MUST NOT** rely on filesystem-reported sizes for these checks;
they **MUST** enforce them while reading. The limit-to-code mapping in the table follows the
closed registry of `spec/error-codes.md` (a single-file JSON size violation is
`E_JSON_SIZE`; container aggregate limits are `E_CONTAINER_SIZE`; per-domain limits use the
domain's structural code).

## 14. Verifier conformance

A conforming verifier is an implementation of H0 that reads records and containers with no
network, no wall clock and no locale/TZ/path dependence, and produces a deterministic report
[I4][H0 §4]. Independent implementations must agree on every vector [I4]; the reference
implementation is Python, and a second independent implementation (Rust) must pass the same
vectors before `weave-record/1` may be called v1.0 [I4][K3]. This section specifies what a
verifier MUST accept and reject, and the stable report/exit-code surface.

### 14.1 Command surface

The reference verifier exposes (names are normative for the reference CLI; an independent
implementation may expose equivalent features under its own names, but for the H0
conformance run it MUST provide equivalent behaviour):

```
hyphaweave-verify record <file> [--keys <dir>] [--json]
hyphaweave-verify container <dir|zip> [--keys <dir>] [--tsa-trust <pem>] [--previous <dir>]
hyphaweave-verify vectors <dir> [--tsa-trust <pem>]
hyphaweave-verify --help | --version
```

- `--keys <dir>` supplies external key-lifecycle records: the top-level `*.json` files in
  the directory. Each file MUST be a structurally valid, self-consistent record under this
  specification (canonical bytes, envelope, signatures, kind body and the kind's
  self-consistency rules such as self-signature and key-id derivation); a file that is not
  such a record is a usage error (exit 2). A keyset file is key material and lifecycle
  context, not part of a container; its broader authorisation status (for example an agent
  grant gate that would apply to a delegated action) is not re-evaluated for the purpose of
  supplying keys — in particular `weave.key.*` records are key self-descriptions and
  therefore do not need grants (§5.4, §4.2 exception).
- `--tsa-trust <pem>` supplies L2 trust anchors (§12.3).
- `--previous <dir>` additionally requires the supplied previous container's manifest
  digest to equal `previous_manifest.digest` (§11.5).
- `--json` is accepted and is the default (compatibility flag). No colour, no progress
  output. Standard output carries exactly one JSON report per run; standard error carries
  usage and I/O errors only.
- No network access. No reading of `vectors/external/` at runtime. Input file bytes are
  read once and verified from those bytes.

### 14.2 What a verifier MUST accept and reject

A verifier **MUST** accept a record or container that satisfies every applicable
requirement of this specification with every check passing, and **MUST** reject (invalid)
or mark unverifiable every record or container for which a required check fails, per the
tables of §14.3. Specifically, a conforming verifier:

1. accepts records whose canonical bytes, envelope, signatures, kind rules, actor rules,
   labels and references satisfy this specification;
2. accepts containers whose layout, manifest, manifest signature, level completeness,
   records consistency, cross-record state, blobs, previous-manifest chain and timestamps
   satisfy this specification;
3. rejects any JSON that is not WR-CJ canonical form where required, or that violates the
   WR-CJ input restrictions;
4. rejects any record that lacks a required per-record signature, any signature that does
   not verify under the §3 profile, and any record or container violating a MUST of this
   specification;
5. marks a record or container `unverifiable` — never `valid` — when a required
   authorisation, key or trust condition cannot be established from the input, as listed in
   §14.4;
6. reports `erased` for a `weave.erased` placeholder and for containers containing only
   such placeholders among otherwise valid records;
7. **MUST NOT** add, invent or accept error or notice codes outside the closed registry of
   `spec/error-codes.md`; the registry is the single source for codes.

Unknown kinds are handled per §7.3: verify integrity and authorisation, do not validate
the body, report `kind_known: false` and `N_KIND_UNKNOWN_OPAQUE`, and never reject because
a kind is unregistered [K3].

### 14.3 Verdicts

Exactly four verdicts exist for a record:

| verdict | meaning |
|---|---|
| `valid` | every applicable check passed |
| `invalid` | at least one error was found in this record, or in the container structure for a container target |
| `unverifiable` | no error, but an authorisation, key or trust condition cannot be established from the input |
| `erased` | this record is a `weave.erased` placeholder (§4.5) and its structure is sound |

For a record target: `invalid` if any error; else `unverifiable` if an unresolved
authorisation/key condition or blocking condition of §14.4 is present; else `valid` (or
`erased` for a placeholder). For a container target: `invalid` if any container, manifest or
record error exists or any timestamp entry is invalid; else `unverifiable` if a manifest or
record key, an authorisation condition, or timestamp trust is unverifiable, or any record is
`unverifiable`; else `valid` (erased placeholders are allowed and yield `erased` record
verdicts). A container with a valid L2 is `valid` at `level_verified "L2"`. For the
`vectors` target: `valid` if and only if every case matches its `expected.json`.

Verdict precedence is `invalid` over `unverifiable` over `valid`; `erased` is a record-level
verdict and, at the top level of a record target, replaces `valid` for a placeholder. The
top-level verdict of a container is **never** `erased` [I4][Q11].

### 14.4 Blocking conditions that force `unverifiable`

The following conditions **MUST NOT** lead to `valid`; they make the affected record (and
therefore the container) `unverifiable` unless another check has already made it `invalid`:
`E_KEY_UNKNOWN`, `E_GRANT_UNRESOLVED`, `E_GRANT_REVOKED`, `E_GRANT_EXPIRED`,
`E_TS_UNTRUSTED`, and the notice `N_KEY_UNDECLARED` when a signature cannot be checked at
all because no key material is available. A claimed L2 without `--tsa-trust` is
`unverifiable` (§12.3). Any `unverifiable` record makes the container `unverifiable` (not
invalid). A verifier **MUST NOT** silently "pass" a check it could not perform; it reports
the gap in `limitations` and uses `unverifiable`.

### 14.5 Deterministic check order

A verifier **MUST** apply checks in a deterministic order and **MUST** report at most one
error per record: the first failing check in the order below (later checks are not run for
that record). Containers apply the container order below; a container-level invalid error
before check (7) stops record processing (`records: []` and exactly one error recorded in
`container.errors`, §14.6), while an `unverifiable` container condition does not stop record
processing.

Per record: (1) parse + canonical form; (2) envelope structure; (3) `sigs`
presence/format; (4) key resolution (unknown key → unverifiable, stop crypto); (5) Ed25519
verification (§3); (6) kind body schema; (7) kind semantic rules; (8) actor/authorisation;
(9) labels; (10) reference resolution and kind mismatch.

Required-signature errors follow the precedence of §4.4: an absent/empty `sigs` array on a
record that needs a per-record signature is `E_SIG_REQUIRED` at step (3); for an ordinary
kind, a non-empty `sigs` with no valid `actor.key` signature is `E_SIG_REQUIRED` immediately
after step (5); for the seven signer-constrained kinds the dedicated kind code is emitted at
step (7) when `sigs` is non-empty but the required signer is missing/wrong, so it takes
precedence over `E_SIG_REQUIRED` (which is not emitted for those kinds in that situation).

Per container: (1) entry enumeration/safety; (2) manifest parse/canonical form;
(3) manifest structure; (4) manifest digest; (5) manifest signature; (6) level/chain
structure completeness; (7) records listing and per-record verification; (8) cross-record
state rules (key lifecycle, grants, consents, erasure, label propagation); (9) blobs;
(10) previous-manifest chain; (11) timestamps; (12) aggregation and report.

Checks (7)–(10) of a record may need other records; they are evaluated with the
deterministic dependency model of §6.4 and the report assigns the first failing check per
record after all dependencies are resolved. A container whose manifest lists records in
sorted-by-digest order yields deterministic per-record report order.

### 14.6 Report format

The report is one JSON object on standard output, UTF-8, serialised with sorted keys, two
spaces of indentation, `ensure_ascii` true and exactly one trailing LF; it contains no
absolute paths, usernames, hostnames, current times, randomness or environment values
[H0 §2.6]. The stable report version is `report_version: "1"`:

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
    "sigs": [{"key": "ed25519:...", "state": "valid|invalid|unverified"}]
  }],
  "container": {
    "created_at": "...", "manifest_digest": "sha256:...",
    "level_claimed": "L0|L1|L2", "level_verified": "L0|L2",
    "chain": {"status": "absent|unverified"},
    "previous_manifest_digest": null,
    "record_count": 3,
    "errors": ["E_..."], "notices": ["N_..."],
    "timestamps": [{"index": 0, "state": "verified|present-unverified|invalid", "gen_time": "..."}]
  },
  "summary": {"valid": 3, "invalid": 0, "unverifiable": 0, "erased": 0},
  "limitations": ["..."],
  "verifier": {"name": "hyphaweave-verify-python", "version": "0.1.0"}
}
```

- `target` selects which keys are present: `container` only for a container target; the
  `records` array contains one entry for a record target and the manifest-ordered entries
  for a container target; for a `weave.erased` record target the top-level verdict is
  `erased` and `records[0].verdict` is `erased`.
- For a `weave.erased` entry, `records[].digest` is the §2.2 record digest computed over the
  placeholder object itself (it is **not** the placeholder's `digest` member, which is the
  original record digest), and the entry additionally carries the optional member
  `"attestation": {"digest": <digest string>, "state": "found|moved|missing|erased|unverifiable"}`,
  the resolution of the placeholder's `attestation` reference. The placeholder has no
  `refs` member, so its `refs` array is empty (`[]`); it is never represented by a
  `rel`-less pseudo-entry.
- Container-level errors and notices (manifest, level/chain, blob, timestamp and container
  structure problems) live in `container.errors` / `container.notices` (sorted,
  lexicographically unique, registry codes only). A container-level invalid failure before
  the records check (§14.5) yields `records: []` and exactly one error in
  `container.errors`. For test-vector comparison, a container case's aggregated errors are
  the set union `container.errors ∪ every records[i].errors`; `expected.errors` is compared
  against that aggregate as a set.
- `errors` and `notices` are sorted lexicographically and unique; they come only from the
  closed registry of `spec/error-codes.md`.
- A field whose value cannot be determined because the input failed earlier in the check
  order is reported as JSON `null` (for example `records[].digest`, `.id`, `.kind`,
  `.stage` and `.origin` for an unparseable record); a report never invents a value and
  never omits a `records[]` entry that the container manifest or the target requires.
- `summary` counts record verdicts; `limitations` contains stable English strings about what
  was not verified (for example the internal chain claim, absent TSA trust, TOFU keys,
  consent coverage).
- `input.sha256` and `input.size` identify the target input: for a record target, the hash
  and size of the record file bytes; for a zip container, the hash and size of the zip
  file; for a directory container, `input.sha256` is the manifest digest (the only
  content-addressed identity a directory has) and `input.size` is the manifest byte size
  (PROVISIONAL gap-filling choice, Appendix A).
- A report is never silently degraded: skipped checks appear in `checks_disabled` (§14.7).
  The exact `vectors`-target report shape (how per-case results are listed) is
  implementation-defined but must be deterministic and must not contain absolute paths; the
  H1 independence requirement is about record and container verification, not about the
  test-runner report shape.

### 14.7 Test-only check hook [Q18]

For conformance-testing only, the reference verifier honours the environment variable
`WEAVE_VERIFY_SKIP_CHECKS`: a comma-separated list of error codes whose checks are treated
as passed (not recorded, not raised). Unset or empty means normal operation. The report
**MUST** echo the sorted list of disabled codes in `checks_disabled` so a report can never
be silently degraded. The hook exists only to prove that each vector actually exercises its
check class; it is documented as test-only in the verifier documentation and **MUST NOT**
be used as a production configuration [Q18] (**PROVISIONAL**, Appendix A). An independent
implementation is not required to implement this hook to be conformant to the record
format; it is required only for reproducing the H0 test-gate procedure [Q18].

### 14.8 Exit codes

| exit code | meaning |
|---|---|
| `0` | valid: the record/container is `valid` (or `erased` for a placeholder record), or every vector case matched |
| `1` | invalid, unverifiable, or at least one vector case mismatched |
| `2` | usage or I/O error; no report on standard output |

`hyphaweave-verify record` on a `weave.erased` placeholder returns verdict `erased` and exit
code 0: a structurally sound attestation of an erasure is a successful verification, even
though the content is gone, and the report still resolves the attestation reference as far
as the context allows [G3][Q15].

### 14.9 Limitations reporting

Every report lists what was not verified. At minimum, when applicable: an unverified L1
chain claim; an unverified or absent L2 timestamp trust; TOFU keys; unresolved
authorisation/consent; unknown kinds not understood; consent coverage not re-evaluated;
continuous multi-container chains out of scope. A verifier **MUST NOT** phrase a limitation
as a passed check.

### 14.10 Independence and vectors

Conformance is defined by the test vectors: every vector case declares its expected
verdict, errors and (where applicable) ref resolution, and an implementation conforms when
it matches all of them [H0 §2.3][I4]. Vector generation is independent of any verifier, and
expected outcomes are authored separately from the verifier implementation; vectors include
negative cases that fail for the named reason [H0 §2.4]. A second, independent
implementation (Rust) must pass the same vectors before version 1.0 [I4].

## 15. Security considerations

This section is informative except where it states a MUST.

1. **Canonicalisation is a security boundary.** If two implementations serialise the same
   value differently, a valid record can be rejected or, worse, a signature can be made
   over different bytes than were reviewed. Implementations **MUST** implement WR-CJ
   exactly (§1) and **MUST NOT** delegate the decision to a general JSON library without
   cross-checks. Duplicate-member rejection and the integer-only rule are security
   requirements, not style choices [C1][C2][C3].
2. **Signature domain separation.** The four domain prefixes (§2.1) prevent replay of a
   signature across object types and across digest/signature purposes. A verifier that
   verifies a record signature over any other byte sequence is not conformant [C4][E6].
3. **Small-order and non-canonical points.** Without the checks of §3.2, the identity-key
   forgery allows forging signatures for arbitrary content, and non-canonical encodings
   allow signature malleability. The strict profile is mandatory; libraries **MUST NOT** be
   trusted to reject these cases [Q1].
4. **TOFU trust.** In-context key declarations are trusted on first use; an attacker who
   can inject a declaration and a matching signature key into the context can make records
   appear valid. This is inherent in a CA-less design. Users should pin key ids out of band
   for high-value evidence, and reports mark TOFU-accepted keys [E4][Q12].
5. **Key lifecycle is evidence, not authority.** A revocation record only helps if it is in
   the verification context. For a compromise revocation, the retroactive rule depends on
   verified timestamps (§9.4); without them, signatures after the compromise are invalid and
   signatures before it cannot be distinguished from forgeries created later [E5][D3].
6. **Rollback and truncation.** A single container proves only its own integrity. The
   previous-manifest chain detects modification of linked containers, but rollback or
   omission of newer containers is detectable only with an external anchor or an
   independently obtained latest digest [D1][D2].
7. **Replay and duplicate actions.** `actor.idempotency_key` lets importers deduplicate the
   same agent action; duplicates are reported with `N_IDEMPOTENCY_DUPLICATE` and are not
   invalid [Q17] (**PROVISIONAL**, Appendix A). Records without such a key are not
   deduplicated by the verifier.
8. **Erasure is not global deletion.** An erased record remains referenceable by digest,
   and copies distributed before erasure cannot be recalled. The salt rule (§8.3) prevents
   brute-forcing deleted personal content from its digest when the salt is deleted with it;
   a record whose salt is *not* deleted is a privacy risk [G3c].
9. **Local-only data.** The export refusal of §8.5 is a check, not a guarantee; a malicious
   exporter can produce a container that simply omits the `local-only` record (and its
   false claim cannot be detected offline). Importers should apply policy on top of
   verification [H2].
10. **Agent authorisation is only as good as the context.** A grant chain proves coverage
    with respect to presented records; a compromised agent key or a forged inclusion can
    extend apparent authority. Human keys signing human acts (§5.2) is the load-bearing
    rule [§8].
11. **Timestamps prove anchoring, not truth.** A verified RFC 3161 token proves a TSA
    signed an imprint; it does not prove content truth. Trust in the TSA is a local policy
    decision via `--tsa-trust` [D3].
12. **Denial-of-service.** Size and resource limits (§13) bound hostile containers; a
    verifier **MUST NOT** crash or unboundedly decompress on a zip bomb.
13. **Plain files only.** Containers are ordinary files with no executable content; a
    verifier **MUST NOT** execute or follow hints, URLs or `readable/` content.

## 16. Governance, repository and implementation requirements

- **Repository and identity**: the specification repository is `haeliotang/hyphaweave`; the
  format identifier remains `weave-record/1` independently of the project name [K1].
- **Licences**: specification prose CC BY 4.0; code, schemas and test vectors Apache-2.0
  [K2].
- **Adapters live in project repositories** (each project knows its own internal format);
  this repository contains only the specification, schemas, test vectors and reference
  verifiers [A1a].
- **Two independent implementations**: the Python reference verifier and a second
  independent verifier (Rust) must both pass the same test vectors before version 1.0;
  independence is guaranteed by the second implementer working from specification and
  vectors only [I4].
- **Never abandon old versions**: a verifier MUST continue to verify older versions of the
  format and older registered kinds; frozen regression vectors encode this commitment [K3].
- **Acceptance**: `weave-record/1` v0.1 is accepted only when the J1
  (Koinoweave → Traceweave) and J2 (Axioweave → Koinoweave) round-trip cases pass, with the
  receiving side verifying the container; adapters live in the projects' repositories
  [J1][J2][A1a].
- **Offline verification**: this repository also provides a manual verification procedure
  using only common tools (`sha256sum`, `openssl`, a JSON viewer), which must be actually
  performed on a sample L0 container [I4].
- **Change control**: new algorithms, relations and kinds go through the written proposal
  and approval process of §0.3 and §7.6 [K4].

## Appendix A — PROVISIONAL items

Every item below is a gap-filling choice; the decision draft leaves the point open and H0
chooses the most conservative reading, marked PROVISIONAL. Each corresponds to an entry of
`docs/open-questions.md`; Q1–Q20 are the items enumerated by the H0 engineering contract,
and Q21–Q32 are additional gaps identified while writing this specification (some were
settled during H0 integration and are retained here for traceability).

| id | item | chosen reading | reason |
|---|---|---|---|
| Q1 | Ed25519 verification profile (§3) | strict, cofactorless, reject S ≥ L, reject non-canonical A/R, reject the eight small-order points; **no** subgroup-membership check (`[L]A == identity`); Wycheproof `valid` accepted, `invalid` rejected, `acceptable` decided per case class (small-order → reject, `MixedOrderPublicKey` → accept) | two independent implementations only agree if the profile is exact; RFC 8032 permits both strict and cofactored readings and does not mandate a subgroup check; the identity-key attack makes the strict small-order checks mandatory; a subgroup check would add a scalar multiplication per verification without cross-implementation benefit |
| Q2 | base64url padding (§2.6) | unpadded only; strict decoding; reject padding, whitespace, `+`/`/`, non-zero unused bits | canonical and unambiguous; padded input is always an error |
| Q3 | `salt` (§4.1, §8.3) | exactly 16 random bytes in base64url; required for `personal`/`local-only`; not otherwise constrained; randomness is not testable offline | prevents brute-forcing erased personal digests; verifier cannot test randomness |
| Q4 | Unicode normalisation (§1) | none anywhere; byte/code-unit comparison only | normalisation is version- and locale-dependent and would silently change signer intent |
| Q5 | size limits (§13) | the table of §13 | generous but bounded; revisit after J1/J2 operational data |
| Q6 | timestamp grammar (§2.8) | RFC 3339 UTC, exactly milliseconds, literal `Z`, no leap second `60`, years 0000–9999 | leap seconds are attributed to the following second; a single grammar is reproducible |
| Q7 | `rel` closed vocabulary (§6.2) | the eight Inceptless relations plus `supersedes`, `correction_of`, `erases`, `revokes`; any other word is invalid | minimal, auditable; additions require K4 proposal |
| Q8 | manifest field set, separate signature file, manifest-digest domain, embedded previous manifest (§11) | as §11.2–§11.5 | makes manual L0 verification possible without modifying the signed manifest |
| Q9 | L1 chain head not re-verifiable offline (§11.4) | report `chain.status = "unverified"`, `level_verified = "L0"`, `N_CHAIN_CLAIM_UNVERIFIED` | honest labelling; consider exporting chain links in a later milestone |
| Q10 | grant revocation modelled inside `weave.grant`; delegation (§5.5) | `action:"revoke"` inside `weave.grant`; agent-signed grants allowed only under a transferable parent grant with matching constraints | the H0 kind list names exactly eight kinds; revisit in v0.2 |
| Q11 | verdict semantics for grants (§5.4, §9.6) | expired/revoked grant → `unverifiable`; grantee/kind/action mismatch → `invalid`; not-yet-valid grant → `unverifiable` (`E_GRANT_EXPIRED`) | signed content intact but authorisation state undecidable vs authorisation definitely wrong |
| Q12 | TOFU key trust (§5.3) | accept keys declared in context; report `N_KEY_TOFU`; no CA, no network; a local trust store is out of scope for H0 | fits the offline, CA-less design |
| Q13 | unknown digest algorithms (§2.7, §6.3, §11.2) | reference → resolution `unverifiable`; manifest record entry → `E_MANIFEST_RECORDS`; algorithm names are the agility interface | algorithm agility without silently accepting unknown algorithms |
| Q14 | SPDX licence checking (§8.7) | syntax checked only; membership not checked; permissive on identifiers, strict on structure | offline verification cannot consult the SPDX list; unknown identifiers are not an offline error |
| Q15 | `weave.erased` special shape (§4.5, §10) | exactly the decided six-member object; verdict `erased`; standalone verdict `erased` exit 0, container cross-checks in §10.3 | the substitution shape is the decided erasure design |
| Q16 | label propagation with absent sensitivity (§8.4) | absent `sensitivity` with a resolved `derived_from` input ranked above 0 → `E_LABEL_DOWNGRADE` | conservative: absence cannot prove non-downgrade |
| Q17 | idempotency duplicates (`N_IDEMPOTENCY_DUPLICATE`) | notice, not invalid; "same origin + same key = same action" for importers | dedupe semantics are not yet defined; verifier reports duplicates only |
| Q18 | test hook `WEAVE_VERIFY_SKIP_CHECKS` (§14.7) | test-only environment variable; report echoes `checks_disabled` | needed to prove vector coverage; never a production setting |
| Q19 | `readable/` (§11.8) | ignored entirely; not hashed; never trusted; optional informational `N_READABLE_PRESENT` | it does not participate in the digest, by decision |
| Q20 | key validity windows (§9.4) | `valid_until` expiry makes later signatures `E_KEY_EXPIRED` invalid; a signature before `valid_from` is treated the same way | conservative reading of claimed validity windows |
| Q21 | `signatures/manifest.sig.json` `timestamps` requiredness (§11.3) | settled: required member, MAY be an empty array for L0/L1 (registry, manifest schema and §11.3 agree) | closed-object treatment of the signature file; avoids a hidden absent-vs-empty distinction |
| Q22 | `manifest.records[]` `id`/`kind` vs record content (§11.2.1, §11.6) | MUST equal the record's values; mismatch is `E_MANIFEST_RECORDS` | a manifest whose metadata contradicts the record it lists is inconsistent evidence |
| Q23 | blob digest algorithms and codes (§11.7) | only `sha256` for H0; unsupported algorithm is `E_MANIFEST_BLOB`; size mismatch `E_MANIFEST_BLOB` | the `blobs/sha256/` path only defines sha256 |
| Q24 | error-code mapping for size limits (§13) | settled by the closed registry of `spec/error-codes.md`: single-file JSON size limits → `E_JSON_SIZE`; container aggregate → `E_CONTAINER_SIZE`; record count → `E_MANIFEST_RECORDS`; blob limits → `E_MANIFEST_BLOB`/`E_MANIFEST_SCHEMA` | the decision draft lists possible codes; the final registry fixes one deterministic mapping (retained here only for traceability) |
| Q25 | error-code split for zip violations (§11.9) | settled by the closed registry: path escapes, duplicate entry names, symlinks and unknown signature/previous files → `E_CONTAINER_ENTRY`; corrupt archive, unsupported compression, encrypted entries → `E_CONTAINER_ZIP`; content layout → `E_MANIFEST_*` | needed for deterministic negative vectors |
| Q26 | verification model for cross-record dependencies and cycles (§6.4, §14.5) | deterministic dependency-ordered evaluation with memoisation; cycles → `unverifiable` + `N_REF_UNVERIFIABLE` | the check order requires deterministic, terminating resolution |
| Q27 | report `input` for directory containers and the `vectors` target (§14.6) | directory container: `input.sha256` = manifest digest, `input.size` = manifest byte size; vectors-run report shape implementation-defined but deterministic | a directory has no single content digest; the manifest digest is its only content-addressed identity |
| Q28 | agent-only envelope members on key-lifecycle records (§4.2 exception) | not required for `weave.key.declared`/`weave.key.rotated`/`weave.key.revoked`; still required for delegated `weave.grant` and all other agent records | those kinds are key self-descriptions, not delegated actions; a self-declaration of an agent-class key would otherwise be unconstructible (found during H0 integration) |
| Q29 | `labels` present but `sensitivity` absent (§8.1) | **Lead ruling: allowed.** `labels` is a closed object but `sensitivity` may be absent (a licence-only or consent-only labels object is valid); `E_ENV_LABELS` covers structural problems only; missing sensitivity is handled by `E_LABEL_DOWNGRADE` (§8.4) and the salt rule (§8.3) | keeps `labels` useful for licence/consent-only tagging; the earlier registry wording was reversed during H0 integration |
| Q30 | signer-class scope for the seven special kinds (§5.1–§5.2) | **accepted by the Lead**: for the seven signer-constrained kinds the kind page's explicit signer requirements are authoritative for additional signatures; `E_ACTOR_HUMAN_KEY` applies only outside the three key-lifecycle kinds, to records whose `actor.type` is not `human`/`organization` | required to make owner co-signatures on key declarations and multi-key rotations constructible; discovered while writing the kind pages |
| Q31 | error precedence: kind-specific signer code vs `E_SIG_REQUIRED` (§4.4, §14.5) | **accepted during H0 integration**: `E_SIG_REQUIRED` only for absent/empty `sigs` (required records) or for ordinary kinds with non-empty `sigs` but no valid `actor.key` signature; the seven signer-constrained kinds report their dedicated code for a missing/wrong required signer | makes `key-lifecycle/declared-not-self-signed` report `E_KEY_DECLARED_NOT_SELF_SIGNED` (not `E_SIG_REQUIRED`) and keeps one primary code per defect |
| Q32 | erased references and erasure cross-check codes (§6.3, §10.3) | **accepted by the Lead**: a reference resolved to `erased` is not kind-checked (the placeholder carries no original kind); `E_ERASE_DIGEST_MISMATCH` covers an `erased` reference whose placeholder is missing or whose digest member disagrees, while `E_ERASE_ATTESTATION` covers only a placeholder `attestation` reference that does not resolve to the matching erasure record | the vectors carry the original kind on `erasure.body.erased` and expect `valid`; the two erasure codes test distinct relationships |

## Appendix B — Decision coverage map

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
| E1 | §3, §4.3, §15 (subgroup-check exclusion: §3.6) |
| E2 | §4.2, §5.1 |
| E3 | §2.5 |
| E4 | §5.3, §9 |
| E5 | §9, §5.5, §4.2 exception (Q28) |
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
| K3 | §0.3, §7.3, §7.5, §11.2, §16 |
| K4 | §0.3, §7.6 |
| J1, J2 | acceptance cases outside this document; referenced in the status block |
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
| `rel` | `derived_from`, `handed_off_to`, `receipt_of`, `executed_as`, `assessed_by`, `compensated_by`, `migrated_from`, `reshaped_from`, `supersedes`, `correction_of`, `erases`, `revokes` | §6.2 |
| resolution state | `found`, `moved`, `missing`, `erased`, `unverifiable` | §6.3 |
| `sigs[].alg` | `ed25519` (H0) | §3.1, §4.3 |
| `labels.sensitivity` | `public`, `internal`, `personal`, `local-only` | §8.1 |
| `weave.key.revoked.reason` | `key-compromise`, `retired`, `other` | §9.3 |
| `weave.grant.action` | `grant`, `revoke` | §5.5 |
| `weave.grant.actions[]` | `propose`, `accept`, `reject`, `withdraw`, `supersede`, `erase`, `grant` | kind page |
| `weave.erasure.reason` | `data-subject-request`, `legal`, `safety`, `mistaken-inclusion`, `retention-expired`, `other` | §10.2 |
| `manifest.level` | `L0`, `L1`, `L2` | §11.4 |
| `chain.algorithm` | `sha256` | §11.2 |
| digest algorithm | `sha256` (H0) | §2.7 |
| error/notice codes | closed registry in `spec/error-codes.md` | §14.2 |

## Appendix D — Conformance summary (what a verifier MUST accept/reject)

**Accept (valid)** — a record or container in which: JSON is WR-CJ canonical (where
required); every required member is present and well-formed; every signature verifies under
§3 and is authorised by an available declared key; a signature is present per record where
§4.4 requires it; kind rules, actor rules, labels, references and cross-record state all
pass; the manifest digest and signature verify; the manifest records match the record files;
the claimed level is verified at least to L0 (L1/L2 labelled honestly); the previous-manifest
chain matches; blobs are consistent; L2 timestamps verify under a supplied trust anchor.

**Reject as invalid** — any violation of a MUST whose consequence is an `E_` code, in
particular: non-canonical JSON bytes; duplicate keys; floats or out-of-range integers; a
non-verifying signature; a missing required per-record signature; a body violating its
kind's closed members; an actor/signing-key class mismatch; a human key signing a non-human
record; a missing salt for `personal`/`local-only`; a label downgrade; `local-only` in a
container; a `rel` or kind not matching its grammar; a reference kind mismatch; a broken
grant delegation; a malformed grant revocation; a missing/mismatched erasure attestation or
an erasure contradiction; a manifest digest/signature/records/blobs/level/chain violation;
a zip/entry violation; an invalid L2 timestamp; a manifest-record digest mismatch.

**Report as unverifiable (never valid)** — a signature whose key is not declared anywhere in
the context (`E_KEY_UNKNOWN`); an unresolvable, revoked or expired grant for an agent's
non-proposal record; a claimed L2 without a trusted timestamp; any authorisation or key
condition that cannot be established from the input; a record whose reference target exists
but is itself not valid when the reference matters for authorisation.

**Report as erased** — a structurally sound `weave.erased` placeholder (record target:
verdict `erased`, exit 0; in a container: record verdict `erased`, container may still be
valid).

## Appendix E — Minimal canonical examples

These examples are illustrative, not test vectors; the normative vectors are in `vectors/`.
They show the exact canonical serialisation shape (single line, sorted members).

A minimal proposed record (unsigned, container-signed):

```json
{"actor":{"key":"ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","type":"human"},"body":{},"format":"weave-record/1","id":"example-1","kind":"example.note","origin":{"instance":"ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","project":"example"},"recorded_at":"2026-11-07T16:30:00.000Z","stage":"proposed"}
```

The same record with a `refs` member added (canonical order: `actor`, `body`, `format`,
`id`, `kind`, `origin`, `recorded_at`, `refs`, `stage`):

```json
{"actor":{"key":"ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","type":"human"},"body":{},"format":"weave-record/1","id":"example-2","kind":"example.note","origin":{"instance":"ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","project":"example"},"recorded_at":"2026-11-07T16:30:00.000Z","refs":[{"ref":{"digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","id":"example-1","origin":{"instance":"ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","project":"example"}},"rel":"derived_from"}],"stage":"proposed"}
```

An erased placeholder:

```json
{"attestation":{"digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","id":"erasure-1","origin":{"instance":"ed25519:2222222222222222222222222222222222222222222222222222222222222222","project":"example"}},"digest":"sha256:3333333333333333333333333333333333333333333333333333333333333333","format":"weave-record/1","id":"example-2","kind":"weave.erased","origin":{"instance":"ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","project":"example"}}
```
