<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Gate 3(a) exceptions: positive cases without a full cryptographic binding

Gate 3(a) (revision-1 gates) flips one seeded bit in the input of every positive
vector and requires that the verifier never again returns `valid`/`erased`. For
most positives that holds because the record or container carries a
cryptographic binding:

* record-target positives are signed by the record's `actor.key`; any change to
  the canonical record bytes changes the record digest and invalidates the
  signature (a flip inside the `sigs` array keeps the digest but breaks the
  signature);
* container-target positives are bound by the Ed25519 manifest signature over
  the manifest digest, which commits every manifest/record/signature/timestamp
  byte through the container checks.

There are exactly three deliberate exceptions whose *purpose* is to prove that
an unsigned record can still be valid (a container signature covers it), and one
structural class (`weave.erased`) that cannot be signed by design:

| exception | why |
|---|---|
| `vectors/digest/record-unsigned` | Exists to exercise the record-digest construction without any signature material. A flipped body byte yields another perfectly valid record. |
| `vectors/stage/valid-proposed-unsigned` | Exists to prove that a `proposed` record may rely on the container signature only. Same unboundness. |
| `vectors/sig/proposed-empty-sigs` | Spec §4.4/S7(1): a `proposed` ordinary record is not required to be signed, so an explicit `sigs: []` is valid; no byte in the file is signature-covered, so flips can keep it valid. |
| `vectors/sig/unknown-alg-optional` | A `proposed` record that is not required to be signed and whose only signature entry uses an unknown algorithm (ignored by Q13): effectively unsigned, so body flips need not change the verdict. |
| `weave.erased` placeholders (e.g. `vectors/digest/record-erased-placeholder`) | The placeholder shape has no `sigs` by specification. A flip that keeps the placeholder structurally valid still yields `erased`, never `valid`; the QA harness lists such mutants as documented exceptions. |

## Q13 unknown-algorithm signature entries (byte-flip exemption)

Revision 1 treats signatures of unknown algorithms as **ignored** (Q13): they
are syntactically validated but never verified and never interpreted. Their
`value` bytes (and, to a large extent, the `alg`/`key` strings) are therefore
semantically inert for the record's verdict. The byte-flip gate must exempt
the bytes of an ignored signature entry, because flipping them can leave a
still-valid record:

| case | reason |
|---|---|
| `vectors/sig/unknown-alg-optional` | The record is not required to be signed; its only signature entry is ignored, so flips inside that entry do not change the verdict. |
| `vectors/sig/unknown-alg-with-known-valid` | The ignored entry is not authenticated; flips inside it leave the valid Ed25519 signature and the verdict unchanged. |
| `vectors/sig/unknown-alg` | The record is unverifiable either way (`E_SIG_UNVERIFIABLE`); only flips that break the entry's structural validity change the reported code. |

The byte-flip gate should keep this list as its documented exempt set; any
survivor outside these cases and the three exceptions above fails gate 3(a).

## readable/ bytes are outside the evidence (both container forms)

`readable/**` is an unsigned human view outside the digest (§11.8/§11.9): it is
never decompressed and its CRC is never checked. Every byte of a `readable/`
entry is therefore semantically inert, in the directory form and in the zip
form alike: the byte-flip gate exempts directory `readable/**` bytes
(`readable-view` class) and must exempt the payload bytes of archived entries
whose path starts with `readable/` too (`zip-readable-payload` class). This is
required by `vectors/container/readable-declared-size-excluded`, whose
`readable/big.txt` entry declares 1 GiB+1 uncompressed bytes while carrying a
three-byte deflate payload: a flip inside those three bytes cannot change the
verdict.

## What is *not* an exception

`unverifiable` negatives (for example `sig/unknown-alg` or
`actor/agent-grant-unresolved`) are not "positive cases": the verifier never
reports them as `valid` by construction. Negatives are covered by the true
source-ablation gate and by their exact expected error codes.
