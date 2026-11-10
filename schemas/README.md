<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# weave-record/1 JSON Schemas

Draft 2020-12 JSON Schemas for the `weave-record/1` format. These files describe the
*shape* of records and containers; they are not a verifier. Every rule that cannot
be expressed in JSON Schema (canonical bytes, Ed25519, key-id derivation,
reference resolution, container consistency, ...) is listed in
[What JSON Schema does not enforce](#what-json-schema-does-not-enforce) and belongs
to the reference verifier.

Status: H0 draft (revision 1). `weave-record/1` v0.1 has not yet been accepted by the
J1/J2 round-trip tests.

## What is registered

| File | Describes |
|---|---|
| `envelope.json` | a normal `weave-record/1` record envelope: closed top-level members, closed `origin`, `actor`, `labels`, `refs` entries, `sigs` entries, `salt`, timestamp grammar, conditional requirements |
| `ref.json` | a reference object: `origin`, `id`, `digest`, optional `kind`, up to 8 `hints` |
| `manifest.json` | a container `manifest.json`, including the shared `$defs` and `$defs.manifest_attestation` for `signatures/manifest.sig.json` |
| `kinds/weave.key.declared.json` | `weave.key.declared` record (key publication, optional `owner`) |
| `kinds/weave.key.rotated.json` | `weave.key.rotated` record |
| `kinds/weave.key.revoked.json` | `weave.key.revoked` record |
| `kinds/weave.grant.json` | `weave.grant` record: `action=grant` / `action=revoke` bodies, optional `grant.revocation` key list |
| `kinds/weave.consent.granted.json` | `weave.consent.granted` record |
| `kinds/weave.consent.revoked.json` | `weave.consent.revoked` record |
| `kinds/weave.erasure.json` | `weave.erasure` record |
| `kinds/weave.erased.json` | the exact `weave.erased` placeholder object; not a normal envelope |

`manifest.json` is the home of the reusable definitions (`$defs.origin`,
`$defs.key_id`, `$defs.digest`, `$defs.timestamp`, `$defs.kind_name`,
`$defs.record_id`, `$defs.public_key`, `$defs.signature_value`,
`$defs.algorithm_name`, `$defs.generic_key_id`, `$defs.generic_signature_value`,
`$defs.signature`, `$defs.signatures`, `$defs.timestamp_path`, and the manifest
entries/attestation definitions); the other files `$ref` them by relative path.
That keeps one definition of key ids, digests and timestamps instead of eleven copies.

Revision 1 additions to the shape: the closed `rel` vocabulary is the eight base
provenance relations plus `supersedes` and `correction_of` (erasure and revocation
are body references, not `rel` values); signature entries are algorithm-agile
(`alg` pattern plus the ed25519/generic condition); `weave.key.declared` accepts an
optional `owner`; `weave.grant` accepts an optional `grant.revocation` list of
1-8 unique ed25519 key ids; manifest timestamp entries carry `renews`, the
re-stamping chain link.

## Identifiers and resolution

- `$id` = `https://inceptless.com/hyphaweave/schemas/v1/<relative path>`, for
  example `.../v1/envelope.json` and `.../v1/kinds/weave.grant.json`.
- Cross-file references are relative (`ref.json`, `manifest.json#/$defs/origin`,
  `../envelope.json`) and are resolved offline through a local resource registry;
  no network access is ever needed or performed.
- Registered kind schemas are an `allOf` of `$ref: "../envelope.json"` plus the
  kind `const`, the required `stage` and the constrained `body` (body-level unknown
  members are allowed for additive evolution; known members are fixed).
  `weave.erased.json` is standalone because the placeholder is not a normal
  envelope (no `stage`, `actor` or `sigs`).
- A record whose `kind` is not one of the eight registered kinds is *opaque but
  not invalid*: validate it against `envelope.json`. Project kinds
  (`koinoweave.*`, ...) are not registered in H0.

## Offline validation

The CI gate is the schema self-check, which requires the vector tree:

```sh
./.venv/bin/python tools/check_schemas.py
# exit 0 = every schema is valid Draft 2020-12, every positive vector input
# validates, every structural-negative vector is rejected, and expected.json /
# vectors/index.json are well formed.  --schemas/--vectors point at other trees.
```

`tools/check_schemas.py` must run with the pinned environment
(`jsonschema==4.23.0`, Python >= 3.11); it builds the registry from
`schemas/**/*.json` itself. A single document can be checked with the same
registry:

```sh
./.venv/bin/python - <<'PY'
import json, pathlib
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

schemas = {}
for path in sorted(pathlib.Path("schemas").rglob("*.json")):
    document = json.loads(path.read_text())
    schemas[document["$id"]] = document
registry = Registry().with_resources(
    [(uri, Resource.from_contents(doc, default_specification=DRAFT202012))
     for uri, doc in schemas.items()])
validator = Draft202012Validator(
    schemas["https://inceptless.com/hyphaweave/schemas/v1/envelope.json"],
    registry=registry)
instance = json.loads(pathlib.Path("record.json").read_text())
for error in validator.iter_errors(instance):
    print(list(error.absolute_path), error.message)
PY
```

## Registering a new kind

`weave.*` is reserved by this specification. A project registers its own kinds by
written proposal (the change process of the specification; a new kind is
registered by the specification repository, not by individual exporters). The
normative registration process is section "Kind registration process" of
`spec/weave-record-1.md`. A registration adds:

1. a schema file `schemas/kinds/<kind>.json` — `allOf` of `$ref: "../envelope.json"`,
   `{"const": "<kind>"}`, any `stage`/`actor` restriction, and a body schema
   (`additionalProperties: true`, known members fixed);
2. a kind page under `spec/kinds/`;
3. conformance vectors and, in this repository, one entry in the `KIND_SCHEMA_FILES`
   table of `tools/check_schemas.py` so the self-check validates it;
4. no edit to `v1` `$id`s. Kind schemas only grow additively; a breaking change is a
   new format version and a new `$id` base.

## Algorithm agility and unknown algorithms

Signatures and digest strings are algorithm-agile interfaces. The schema encodes the
structure; the verifier decides what it can verify.

- A signature entry is `{"alg", "key", "value"}`. `alg` is a lowercase algorithm-name
  token (at most 32 bytes). For `alg == "ed25519"`, `key` is an ed25519 key id
  (`ed25519:` + 32 lowercase hex) and `value` is strict unpadded base64url of exactly
  64 bytes. For any other algorithm name, `key` has the generic key-id shape
  (algorithm token, colon, 1-128 lowercase hex) and `value` is strict unpadded
  base64url of 1-2048 bytes.
- Unknown-algorithm signatures are **structurally valid but semantically ignored**:
  H0 verifiers do not reject a record just because one signature entry names an
  algorithm they do not implement, and they report that entry as ignored. This is the
  forward-compatibility slot for future algorithms (for example post-quantum
  signatures).
- A structural violation of the signature condition above is `E_ENV_SIGS` (not a
  separate algorithm error). In H0 `E_ENV_SIG_ALG` is never emitted but is still
  recognised.
- If a record requires a per-record signature and every available signature entry is
  either unverifiable (unknown algorithm) or by a key that is not the required key,
  the record becomes `unverifiable` (`E_SIG_UNVERIFIABLE`), never silently valid.
- Reference digest strings follow the same idea: a syntactically well-formed
  `<algorithm>:<lowercase hex>` digest with an algorithm the verifier does not
  implement resolves to `unverifiable` and is not a record error. Container
  positions (`manifest.records[].digest`, `previous_manifest`, `chain.head`,
  `blobs`, attestation `digest`) require `sha256` in H0.

## What JSON Schema does not enforce

Approximations and rules deliberately left to the verifier. Keep this list in sync
when the schemas or the specification change. Rules that the specification states
but JSON Schema cannot reach are *unreachable semantic rules*: this gate never
enforces them, and they must be implemented and tested by the verifier and the
vectors.

1. **Canonical bytes.** Duplicate member names, number spelling/range, escaping, BOM
   and trailing-LF rules are parser/profile rules, not schema rules.
2. **Unicode details.** `id`/`model`/... lengths count Unicode code points in JSON
   Schema, while the specification states Unicode scalar values and UTF-8 bytes in
   places; lone surrogates cannot be rejected. This only differs for exotic strings
   that the canonical-bytes/UTF-8 handling rejects earlier.
3. **Timestamp calendar validity.** The pattern pins exactly
   `YYYY-MM-DDTHH:MM:SS.sssZ`, years 0000-9999, seconds 00-59, but not month/day
   combinations (e.g. `2026-02-30...` matches the pattern).
4. **Ordering and uniqueness across array entries.** JSON Schema cannot sort array
   items or compare fields between items. Enforced by supplementary predicates in
   `tools/check_schemas.py`: duplicate `refs` entries (same `rel` and target
   `origin`/`id`/`digest`), `sigs` and manifest `signatures` sorted by key with
   unique keys, the per-entry signature geometry condition, `manifest.records`
   sorted by digest with unique digests and unique `chain_index` for L1/L2,
   `manifest.records[].id`/`kind` equal to the listed `records/<digest>.json`,
   `manifest.blobs` sorted by digest with unique digests, `weave.grant`'s
   `grant.revocation` with unique ed25519 key ids, and manifest `timestamps` sorted
   by path with unique paths plus the single acyclic renewal chain (exactly one
   `renews=null` head, every `renews` path listed, no receipt renewed twice).
   Everything else is verifier territory.
5. **Cross-field equality, derivation and lifecycle.** `actor.key == body.key` and
   `actor.type == body.key_type` for `weave.key.declared`, the old key for a
   rotation, `old_key != new_key`, key ids recomputed from `public_key`,
   `valid_from <= valid_until`, `effective_at <= recorded_at` for
   `weave.key.revoked`, and the signature-class/`owner`/countersignature rules of
   key declarations (including the root-key bootstrap algorithm and its notice) are
   verifier rules. The schema accepts an optional `owner` member but does not require
   it by `body.key_type`; `E_KEY_OWNER_MISSING` and
   `E_KEY_DECLARED_NOT_COSIGNED` are unreachable semantic rules for this gate.
6. **Authorization, consent, erasure, labels and container semantics.**
   Grant chain evaluation (delegation subsetting of kinds/actions/scope and validity
   windows, transferability, grantee/granter identity, depth and cycles), revocation
   signer rules (including `grant.revocation` lists and rotation successors),
   consent/erasure reference targets, erasure executor classes and basis grants,
   `weave.erased` cross-checks, label propagation, `local-only` export refusal,
   manifest/records/blob consistency, the previous-manifest chain (including the
   same-origin rule), timestamp archive verification and the level/timestamp
   cross-file rule are not expressible in JSON Schema. In particular `labels` may
   omit `sensitivity`; that is not a structural error (the propagation rule reports
   the downgrade when a resolved derivation input is non-public).
7. **base64url strictness.** Unused trailing bits are constrained by the final
   character of `salt` (16 bytes), `public_key` (32 bytes) and ed25519 signature
   `value` (64 bytes); the generic signature value constraints select the valid
   character-count classes and their unused-bit final characters. Full strict
   decoding (no `=`, no whitespace, correct lengths, zero unused bits) is a
   verifier/encoding rule.
8. **SPDX licence expressions.** `labels.licence` accepts a bounded approximation:
   identifiers `[A-Za-z0-9][A-Za-z0-9.+-]*`, uppercase `AND`/`OR`/`WITH` operators
   and parentheses nested at most two levels. Operator precedence, exception
   identifiers and licence-list membership are not checked offline ("syntax only,
   no membership").
9. **Kind name grammar and the project segment.** `$defs.kind_name` follows the
   published regex, which permits names without a dot. The specification additionally
   requires a project segment (`<project>.<kind>`), so a dotless synthetic kind is a
   syntax error; that verifier rule is not encoded here.
10. **Byte-size limits.** Element-count limits are in the schemas (`refs` 256,
    `sigs` 16, `hints` 8, manifest `records` 100000, grant `kinds` 64, `actions` 7,
    `scope` 32, `blobs` 10000). Record, manifest, signature-file, timestamp and
    container byte limits are enforced by the verifier before or while reading.
11. **Agent obligations have a kind exception.** `model`, `on_behalf_of`, `grant`
    and `idempotency_key` are required when `actor.type == "agent"` *except* for
    `weave.key.declared`, `weave.key.rotated` and `weave.key.revoked` (key
    self-descriptions, not delegated actions). They stay forbidden for non-agent
    actors. The conditional lives at the record root because it needs the sibling
    `kind`.
12. **Per-record signature requirement.** The envelope requires a non-empty `sigs`
    array for `stage == "accepted"` and for the seven registered kinds that must be
    accepted-and-signed. The verifier additionally requires at least one *known
    algorithm* signature by `actor.key`, applies the key-kind-specific signer rules
    and emits the human-signature notice; a present but cryptographically invalid
    signature is a verifier error. Which signatures are required and what "ignored"
    means is semantic (see the algorithm agility section).
13. **Exact kind bodies.** `weave.grant` bodies use `oneOf` so exactly the body
    matching `action` is present. The `grant`/`revoke`/`grantee` nested objects are
    closed (nullable members are present as null), while the body object itself stays
    open for additive evolution. Similar closed nested shapes apply where the
    specification lists exact members.
14. **Manifest attestation `timestamps`.** `$defs.manifest_attestation` requires the
    `timestamps` array: empty for L0/L1, a single renewal chain for L2. Whether the
    list matches `manifest.level`, the RFC 3161 archive (status, imprint including
    the renewed-bytes construction, CMS/ESS/EKU/certificate checks) and trust-anchor
    handling are verifier rules; the schema only constrains each entry
    (`digest`, `path`, `renews`) and the chain structure described above.
