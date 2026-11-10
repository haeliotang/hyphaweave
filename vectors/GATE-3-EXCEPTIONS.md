<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Gate 3(a) exceptions: positive cases without a per-record signature

Gate 3(a) (CONTRACT §19.3) flips one seeded bit in the input of every positive
vector and requires that the verifier never again returns `valid`. For
record-target positives that only works if the record carries a **cryptographic
binding**: with a valid `sigs` entry, any change to the canonical record bytes
changes the record digest and invalidates the signature (a flip inside the
`sigs` array itself keeps the digest but breaks the signature).

Every record-target positive under `vectors/{jcs,digest,sig,ref,stage,actor,
labels}/` is therefore signed by the record's `actor.key` — with exactly two
deliberate exceptions, whose *purpose* is to prove that an unsigned record can
still be valid (a container signature covers it, CONTRACT §5.3):

| case | why it is unsigned |
|---|---|
| `vectors/digest/record-unsigned` | Exists to exercise the record-digest construction (§3.1) and the digest-excludes-`sigs` rule without any signature material. |
| `vectors/stage/valid-proposed-unsigned` | Exists to prove that a `proposed` record may rely on the container signature only (§5.3: "otherwise `sigs` may be absent"). |

No signed exception is needed for the container-target positives: they are
bound by the (Ed25519) manifest signature over the manifest digest; a bit flip
in any manifest/record/signature/timestamp byte makes the container invalid or
unverifiable, so the manifest-level binding is the cryptographic anchor.

`unverifiable` negatives (e.g. `actor/agent-grant-unresolved`,
`sig/undeclared-key`) are not "positive cases" for gate 3(a): the verifier never
reports them as `valid` by construction.

## `weave.erased` placeholders (no signature is possible)

`weave.erased` placeholders have **no `sigs` by format** (§7.8), so no
cryptographic binding can be attached. Gate 3(a) still holds because the
verifier can never report a mutated placeholder as `valid`:

* a flip that breaks the canonical bytes or the closed placeholder shape makes
  the input invalid;
* a flip that keeps the placeholder structurally valid (for example one hex
  digit of `digest` or a character of `id`) leaves the verdict **`erased`**,
  which is not `valid`. The QA gate-3 harness treats such a post-mutation
  `erased` verdict as a **documented exception**, exactly as it treats the two
  unsigned record cases above.

This is why no `weave.erased` case is listed in the table above: it cannot be
signed, and the harness exemption is the agreed handling for it.

The exceptions above are reported by the anti-verification gate as documented
exceptions rather than as survivors of gate 3(a).
