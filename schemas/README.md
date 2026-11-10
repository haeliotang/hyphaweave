<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# weave-record/1 JSON Schemas

Draft 2020-12 JSON Schemas for the H0 `weave-record/1` format. These files describe
the *shape* of records and containers; they are not a verifier. Every rule that
cannot be expressed in JSON Schema (canonical bytes, Ed25519, key-id derivation,
reference resolution, container consistency, ...) is listed in
[What JSON Schema does not enforce](#what-json-schema-does-not-enforce) and
belongs to the reference verifier.

Status: H0 draft. `weave-record/1` v0.1 has not yet been accepted by the J1/J2
round-trip tests.

## What is registered

| File | Describes |
|---|---|
| `envelope.json` | a normal `weave-record/1` record envelope (CONTRACT §5): closed top-level members, closed `origin`, `actor`, `labels`, `refs` entries, `sigs` entries, `salt`, timestamp grammar, conditional requirements |
| `ref.json` | a reference object (CONTRACT §6; DECISIONS B2/B4/B5): `origin`, `id`, `digest`, optional `kind`, up to 8 `hints` |
| `manifest.json` | a container `manifest.json` (CONTRACT §11.2), including the shared `$defs` and `$defs.manifest_attestation` for `signatures/manifest.sig.json` (CONTRACT §11.3) |
| `kinds/weave.key.declared.json` | `weave.key.declared` record (CONTRACT §7.1) |
| `kinds/weave.key.rotated.json` | `weave.key.rotated` record (CONTRACT §7.2) |
| `kinds/weave.key.revoked.json` | `weave.key.revoked` record (CONTRACT §7.3) |
| `kinds/weave.grant.json` | `weave.grant` record (CONTRACT §7.4): `action=grant` / `action=revoke` bodies |
| `kinds/weave.consent.granted.json` | `weave.consent.granted` record (CONTRACT §7.5) |
| `kinds/weave.consent.revoked.json` | `weave.consent.revoked` record (CONTRACT §7.6) |
| `kinds/weave.erasure.json` | `weave.erasure` record (CONTRACT §7.7) |
| `kinds/weave.erased.json` | the exact `weave.erased` placeholder object (CONTRACT §7.8); not a normal envelope |

`manifest.json` is the home of the reusable definitions (`$defs.origin`,
`$defs.key_id`, `$defs.digest`, `$defs.timestamp`, `$defs.kind_name`,
`$defs.record_id`, `$defs.public_key`, `$defs.signature_value`, `$defs.signature`,
`$defs.signatures`, and the manifest entries/attestation definitions); the other
files `$ref` them by relative path. That keeps one definition of key ids, digests
and timestamps instead of eleven copies.

## Identifiers and resolution

- `$id` = `https://inceptless.com/hyphaweave/schemas/v1/<relative path>`, for
  example `.../v1/envelope.json` and `.../v1/kinds/weave.grant.json`.
- Cross-file references are relative (`ref.json`, `manifest.json#/$defs/origin`,
  `../envelope.json`) and are resolved offline through a local resource registry;
  no network access is ever needed or performed.
- Registered kind schemas are an `allOf` of `$ref: "../envelope.json"` plus the
  kind `const`, the required `stage` and the constrained `body` (body-level
  unknown members are allowed for additive evolution, K3; known members are
  fixed). `weave.erased.json` is standalone because the placeholder is not a
  normal envelope (no `stage`, `actor` or `sigs`).
- A record whose `kind` is not one of the eight registered kinds is *opaque but
  not invalid* (K3): validate it against `envelope.json`. Project kinds
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

## Registering a new kind (K4)

`weave.*` is reserved by this specification. A project registers its own kinds by
written proposal (K4 in `DECISIONS.md`; until the governance charter exists the
founder approves proposals and the decision log records them); the registration
process is normative text in `spec/weave-record-1.md` §7.6. A registration adds:

1. a schema file `schemas/kinds/<kind>.json` — `allOf` of `$ref: "../envelope.json"`,
   `{"const": "<kind>"}`, any `stage`/`actor` restriction, and a body schema
   (`additionalProperties: true`, known members fixed);
2. a kind page under `spec/kinds/`;
3. conformance vectors and, in this repository, one entry in the `KIND_SCHEMA_FILES`
   table of `tools/check_schemas.py` so the self-check validates it;
4. no edit to `v1` `$id`s. Kind schemas only grow additively (K3); a breaking
   change is a new format version and a new `$id` base.

## What JSON Schema does not enforce

Approximations and rules deliberately left to the verifier. Keep this list in
sync when the schemas or the contract change.

1. **Canonical bytes (WR-CJ).** Duplicate member names, number spelling/range,
   escaping, BOM and trailing-LF rules are parse/profile rules, not schema rules.
2. **Unicode details.** `id`/`model`/... lengths count Unicode code points in
   JSON Schema, while CONTRACT states Unicode scalar values and UTF-8 bytes in
   places; lone surrogates cannot be rejected. This only differs for exotic
   strings that WR-CJ/UTF-8 handling rejects earlier.
3. **Timestamp calendar validity.** The pattern pins exactly
   `YYYY-MM-DDTHH:MM:SS.sssZ`, years 0000-9999, seconds 00-59, but not
   month/day combinations (e.g. `2026-02-30...` matches the pattern).
4. **Ordering and uniqueness across array entries.** JSON Schema cannot sort
   array items or compare fields between items. Enforced by supplementary
   predicates in `tools/check_schemas.py`: duplicate `refs` entries (same `rel`
   and target `origin`/`id`/`digest`), `sigs` sorted by key with unique keys,
   `manifest.records` sorted by digest with unique digests, unique
   `chain_index` for L1/L2, `manifest.blobs` sorted by digest with unique
   digests, manifest `signatures` sorted by key with unique keys, and
   `timestamps` sorted by path with unique paths. It also cross-checks every
   `manifest.records[]` entry's `id` and `kind` against the record file it lists
   (`records/<digest>.json`, CONTRACT §11.2.1/§11.6; a missing file belongs to
   `E_MANIFEST_RECORD_MISSING`, a different family). Everything else is
   verifier territory.
5. **Cross-field equality and derivation.** `actor.key == body.key` and
   `actor.type == body.key_type` for `weave.key.declared`, the old key for a
   rotation, `old_key != new_key`, key ids recomputed from `public_key`,
   `valid_from <= valid_until`, `effective_at <= recorded_at` for
   `weave.key.revoked`, and "a signature by `actor.key`/the declared key/both
   rotation keys" — all verifier rules.
6. **Authorization, consent, erasure, labels and container semantics.**
   Grant/delegation containment and transferability, revocation signer classes,
   consent/erasure reference targets, `weave.erased` cross-checks, label
   propagation, `local-only` export refusal, manifest/records/blob consistency,
   the previous-manifest chain, and the level/timestamp cross-file rule are not
   expressible in JSON Schema. In particular `labels` may omit `sensitivity`
   (Lead ruling: that is not a structural error; when a resolved `derived_from`
   input is non-public the propagation rule reports `E_LABEL_DOWNGRADE`).
7. **base64url strictness.** The unused trailing bits of unpadded base64url are
   approximated by constraining the final character of `salt` (16 bytes),
   `public_key` (32 bytes) and signature `value` (64 bytes) to the letters whose
   unused bits are zero. Full strict decoding (no `=`, no whitespace, correct
   lengths, zero unused bits) is a verifier/encoding rule.
8. **SPDX licence expressions.** `labels.licence` accepts a bounded
   approximation: identifiers `[A-Za-z0-9][A-Za-z0-9.+-]*`, uppercase
   `AND`/`OR`/`WITH` operators and parentheses nested at most two levels.
   Operator precedence, exception identifiers and licence-list membership are
   not checked offline (DECISIONS H1 says syntax only, no membership).
9. **Reference digest algorithm agility.** `ref.json` intentionally accepts any
   syntactically well-formed `<alg>:<lowercase hex>` digest when the algorithm
   is not `sha256`; CONTRACT §3.6 says an unknown algorithm in a *reference* is
   structurally valid but resolves to `unverifiable` (not a record error;
   DECISIONS B3). The algorithm token follows the spec §2.7 grammar
   (`^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`, at most 32 bytes). A `sha256:` reference
   digest must be exactly 64 lowercase hex characters. Manifest positions
   (`records[].digest`, `previous_manifest`, `chain.head`, `blobs`, attestation
   `digest`) are strict `sha256`.
10. **Kind name grammar and the project segment.** `$defs.kind_name` follows
    CONTRACT §7's published regex, which permits names without a dot. DECISIONS
    §2 and spec §7.1 additionally require a project segment (`<project>.<kind>`,
    so a dotless synthetic kind such as `note` is `E_ENV_KIND_SYNTAX`); that
    verifier rule is not encoded here because the contract's published grammar
    does not state it.
11. **Byte-size limits.** Element-count limits are in the schemas
    (`refs` 256, `sigs` 16, `hints` 8, manifest `records` 100000, grant `kinds`
    64, `actions` 7, `scope` 32, `blobs` 10000). The byte limits of CONTRACT §13
    (1 MiB record, 4 MiB manifest, ...) are enforced by the verifier before or
    while reading.
12. **Agent obligations have a kind exception.** `model`, `on_behalf_of`,
    `grant` and `idempotency_key` are required when `actor.type == "agent"`
    *except* for `weave.key.declared`, `weave.key.rotated` and
    `weave.key.revoked` (CONTRACT §5.1 exception: those are key self-descriptions,
    not delegated actions). They stay forbidden for non-agent actors. The
    conditional lives at the record root because it needs the sibling `kind`.
13. **Per-record signature requirement.** The envelope requires a non-empty
    `sigs` array for `stage == "accepted"` and for the seven registered kinds
    that must be accepted-and-signed. The verifier additionally requires at
    least one signature by `actor.key` (and the key-kind-specific signer rules);
    a present but cryptographically invalid signature is a verifier error.
14. **Exact kind bodies.** `weave.grant` bodies use `oneOf` so exactly the body
    matching `action` is present. The `grant`/`revoke`/`grantee` nested objects
    are closed (their members are listed exactly in CONTRACT §7.4; nullable
    members are required-but-nullable there), while the body object itself stays
    open for additive evolution. Similar closed nested shapes apply where the
    contract lists exact members.
15. **Manifest attestation `timestamps`.** `$defs.manifest_attestation` requires
    the `timestamps` array (CONTRACT §11.3): it is empty for L0/L1 and has at
    least one entry for L2. Whether the list matches `manifest.level` is a
    cross-file rule the verifier checks; the schema only constrains each entry
    (`digest`, `path: signatures/timestamp-<n>.tsr`) and their order.
