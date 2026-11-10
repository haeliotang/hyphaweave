<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# `weave.grant` — authorise a grantee, and revoke grants

**Kind:** `weave.grant` · **Stage:** `accepted` only · **Per-record signature:** REQUIRED
· **Decision tags:** [§8.1] [§8.2] [§8.5] · **Normative parent:**
`spec/weave-record-1.md` §5.4–§5.6, §9.6. Every normative rule below is `decided
(Inceptless decision 2026-11-10 #34; S3/Q10/Q11/Q13)` where it implements those rulings.

## Purpose

A grant authorises a grantee key for a set of record kinds and actions within a scope and a
validity window, says whether it may be delegated, and names who may revoke it. It is the
machine-readable answer to "who did it, on behalf of whom, under what authority" that makes
an agent's default output a proposal (§8.1). A grant is either a **root grant**, issued by a
human or organization key, or a **delegated sub-grant**, issued by an agent/program/device
key under a transferable parent grant [§8.2].

Grant revocation is part of this kind (`action: "revoke"`) rather than a separate kind; the
H0 registry has exactly eight kinds.

## Envelope requirements

- `kind` is exactly `weave.grant`; `stage` **MUST** be `accepted` (`E_ENV_STAGE`).
- `sigs` **MUST** be present. If `sigs` is present but the required signer is missing or
  wrong, the kind code is reported instead of `E_SIG_REQUIRED`: `E_GRANT_GRANTER` for
  `action == "grant"`, `E_GRANT_REVOKE_SIGNER` for `action == "revoke"`; `E_SIG_REQUIRED`
  is used only when `sigs` is absent or empty (parent specification §4.4).
- `actor`:
  - root grant — `actor.type` is `human` or `organization`;
  - delegated sub-grant — `actor.type` is `agent`; the normal agent envelope obligations
    apply and `actor.grant` references the parent grant. `program`/`device` actors cannot
    carry `actor.grant` (parent specification §4.2), so a grant record signed by such an
    actor can never cite a parent and is `unverifiable` with `E_GRANT_UNRESOLVED`
    (PROVISIONAL, parent specification Appendix A P12).
- `salt` is optional; `refs`/`labels` follow the parent specification.

## Body

`body` carries `action` and exactly one of `grant` / `revoke`; that variant structure and
the known members are fixed. Additional unknown **body** members are permitted by additive
evolution (K3); unknown members inside the `grant`/`revoke` variant objects are
`E_GRANT_SCHEMA`.

| member | required | type | rule |
|---|---|---|---|
| `action` | yes | string | `"grant"` or `"revoke"` |
| `grant` | iff action is `grant` | object | variant object below |
| `revoke` | iff action is `revoke` | object | variant object below |

### `grant` variant object (closed)

| member | required | type | rule |
|---|---|---|---|
| `grantee` | yes | object | closed `{"key": <key id>}` |
| `kinds` | yes | array | 1–64 kind names, unique |
| `actions` | yes | array | 1–7 unique strings from `propose`, `accept`, `reject`, `withdraw`, `supersede`, `erase`, `grant` |
| `scope` | yes | array | 1–32 strings (each 1–256 Unicode scalar values), unique; audit scope, compared as a set only for delegation subsetting |
| `valid_from` | yes | TS | start of validity window |
| `valid_until` | yes | TS or `null` | end of window; `null` means unbounded |
| `transferable` | yes | boolean | whether the grantee may delegate further (default policy: no) |
| `evidence` | yes | reference object or `null` | audit evidence; not machine-checked |
| `remedy` | yes | string or `null` | audit remedy clause; not machine-checked |
| `revocation` | no | array | 1–8 unique key ids allowed to revoke this grant; absent means the granter's `actor.key` and its explicit rotation successors |

`valid_from <= valid_until` when `valid_until` is not `null`, otherwise `E_KEY_VALIDITY`.

### `revoke` variant object (closed)

| member | required | type | rule |
|---|---|---|---|
| `revokes` | yes | reference object | the grant being revoked (origin, id, digest) |
| `effective_at` | yes | TS | claimed instant from which the grant is revoked |
| `reason` | yes | string or `null` | free-form (not interpreted) |

A wrong action/variant pairing, a missing variant member or an extra variant member is
`E_GRANT_SCHEMA`.

## Semantic rules

### Root grant

A grant record whose `actor.type` is `human` or `organization` is a root grant; its
authority comes from the signer and no parent grant is required (§8.2).

### Delegated sub-grant chain

Checks on a delegated sub-grant, in fixed order (the first failure is the record's single
error; the exact code precedence is PROVISIONAL, see the parent specification Appendix A):

1. **Resolve.** Parent reference unresolvable, or parent verdict invalid → `E_GRANT_UNRESOLVED`
   (unverifiable).
2. **Authorising action and capability.** Parent `action` is not `grant`, or parent `kinds`
   lacks `weave.grant`, or parent `actions` lacks `grant` → `E_GRANT_GRANTER` (invalid).
3. **Transferable.** Parent `transferable` is not `true` → `E_GRANT_NOT_TRANSFERABLE`.
4. **Granter identity.** Parent `grant.grantee.key` is not this record's `actor.key` →
   `E_GRANT_GRANTER`.
5. **No expansion.** Child `kinds` ⊆ parent `kinds`, child `actions` ⊆ parent `actions`
   (this closes the privilege-escalation hole where a sub-grant adds `accept` or `erase`),
   child `scope` ⊆ parent `scope` as a set of strings, child `valid_from` >= parent
   `valid_from`, child `valid_until` <= parent `valid_until` (`null` = unbounded; a `null`
   child under a bounded parent exceeds it) → otherwise `E_GRANT_DELEGATION_EXCEEDS`.
6. **Chain validity at the verification time.** The whole chain — the cited grant and every
   ancestor — is judged at the claimed `recorded_at` of the record being verified; when the
   record being verified is itself a `weave.grant`, that grant's own `recorded_at` is used.
   At that time: a grant or ancestor revoked (`effective_at <= recorded_at`, equality
   counts) → `E_GRANT_REVOKED` (unverifiable); a grant or ancestor outside its validity
   window → `E_GRANT_EXPIRED` (unverifiable). Any failing link makes the whole chain
   unverifiable (R1).
7. **Depth.** Up to 8 links from the grant used by a record to its root; deeper chains are
   `unverifiable` (`E_GRANT_UNRESOLVED`). A cycle is not constructible for digest
   references; the key-id rotation graph used by the revocation rule is bounded separately.

### Authorisation of a record

A record whose actor is an agent MUST cite an `actor.grant` covering the record for **every**
stage (including `proposed`): the grant must be an `action == "grant"` grant whose
`grantee.key` equals `actor.key`, whose `kinds` contains the record's kind, whose `actions`
contains the stage's action (`propose`/`accept`/`reject`/`withdraw`/`supersede`), and which
is inside its validity window and not revoked at the record's claimed `recorded_at`; the
whole chain is evaluated at that same time, the single verification time (R1). Outcomes: unresolvable → `E_GRANT_UNRESOLVED`
(unverifiable); revoked → `E_GRANT_REVOKED` (unverifiable); outside window →
`E_GRANT_EXPIRED` (unverifiable); grantee mismatch → `E_GRANT_GRANTEE_MISMATCH` (invalid);
kind/action not covered → `E_GRANT_NOT_APPLICABLE` (invalid). A grant reference to a
`action == "revoke"` record is `E_GRANT_GRANTER` (invalid).

`scope` is not machine-evaluated for an individual record; it is used only for delegation
subsetting above.

### Revocation authority

For `action == "revoke"`, `revokes` MUST resolve to a `weave.grant` record with a matching
digest (`E_GRANT_REVOKE_REF`). The revocation MUST be signed by:

- a key in the target grant's `grant.revocation` list when that list is present; or
- otherwise the original granter's `actor.key`, or an explicit rotation successor of that
  key (walking only `weave.key.rotated` records that name the successor, never by inference;
  depth at most 8; a cycle in the key-id graph means no successor can be proven and the
  revocation is invalid).

Otherwise `E_GRANT_REVOKE_SIGNER` (invalid). A revoker key with no declaration in context
makes the revocation `unverifiable` (`E_KEY_UNKNOWN`), not invalid. No arbitrary
human/organization key may revoke someone else's grant [Q10/M-5] decided (Inceptless
decision 2026-11-10 #34; Q10).

A record using the grant with `recorded_at >= effective_at` is `unverifiable`
(`E_GRANT_REVOKED`); earlier records are unaffected (equality counts as revoked).

### Unknown-algorithm signatures

Entries with an unknown `alg` are ignored (parent specification §3.6). A grant's signing
obligation is satisfied by a valid known-algorithm signature of the required signer; if no
such signature exists the record is `unverifiable` (`E_SIG_UNVERIFIABLE`) or invalid per
§4.4 of the parent specification [Q13] decided (Inceptless decision 2026-11-10 #34; Q13).

## Error codes

| code | verdict | condition |
|---|---|---|
| `E_ENV_STAGE` | invalid | stage is not `accepted` |
| `E_GRANT_SCHEMA` | invalid | body shape, variant pairing, member grammar, duplicate list elements |
| `E_KEY_VALIDITY` | invalid | `valid_from > valid_until` in the `grant` variant |
| `E_GRANT_GRANTER` | invalid | granter not permitted: parent not an authorising `weave.grant` covering `weave.grant`/`grant`, parent grantee not the sub-granter, parent outside window or revoked at evaluated time, or (non-empty `sigs`) required granter signature missing/wrong |
| `E_GRANT_NOT_TRANSFERABLE` | invalid | parent `transferable` is false |
| `E_GRANT_DELEGATION_EXCEEDS` | invalid | child `kinds`/`actions`/`scope` not a subset, or window outside the parent |
| `E_GRANT_REVOKE_SIGNER` | invalid | revocation signer not in the `revocation` list, not the granter, and not a provable rotation successor |
| `E_GRANT_REVOKE_REF` | invalid | `revokes` does not resolve to a `weave.grant` with matching digest |
| `E_GRANT_GRANTEE_MISMATCH` | invalid | a record's `actor.key` is not the cited grant's grantee |
| `E_GRANT_NOT_APPLICABLE` | invalid | a record's kind or stage action is not covered |
| `E_REF_KIND_MISMATCH` | invalid | a reference kind claim contradicts the resolved target kind |
| `E_GRANT_UNRESOLVED` | unverifiable | parent/authorisation unresolvable, parent invalid, or chain too deep |
| `E_GRANT_REVOKED` | unverifiable | grant/ancestor revoked at the evaluated time |
| `E_GRANT_EXPIRED` | unverifiable | grant/ancestor outside its window at the evaluated time |
| `E_ENV_ACTOR_GRANT_MISSING` | invalid | agent actor lacks `actor.grant` (envelope) |
| `E_SIG_REQUIRED`, `E_SIG_UNVERIFIABLE`, `E_SIG_INVALID` | invalid / unverifiable | per parent specification §4.4 |
| `E_KEY_UNKNOWN` | unverifiable | signer/revoker key not available in context |
| `N_KEY_TOFU`, `N_KEY_UNDECLARED`, `N_NO_HUMAN_SIGNATURE` | notice | reporting |

## Canonical JSON examples

A root grant from the root human key to the agent key, covering the `example.note` kind with
the `propose` and `accept` actions, and naming the root and the other human key as revokers
(the new `revocation` field); verified as a standalone record with
`--keys vectors/keys/keyset`:

<!-- spec-example: standalone-record -->
```json
{"actor":{"key":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","type":"human"},"body":{"action":"grant","grant":{"actions":["propose","accept"],"evidence":null,"grantee":{"key":"ed25519:b6190071e4bbc7c82afc702fa9ffa6f5"},"kinds":["example.note"],"remedy":null,"revocation":["ed25519:333f90d1d9dfb653b78df977b9b13ff2","ed25519:928a1e1dbe45a5d298ce5f6b5ce2eabe"],"scope":["site A receipts"],"transferable":false,"valid_from":"2026-11-01T00:00:00.000Z","valid_until":"2027-11-01T00:00:00.000Z"}},"format":"weave-record/1","id":"grant-root-1","kind":"weave.grant","origin":{"instance":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","project":"example"},"recorded_at":"2026-11-02T00:00:00.000Z","sigs":[{"alg":"ed25519","key":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","value":"AXswcvufHWzSm5WPcVPnnvwb9jKv8PWyiXf9uZQYyikhiVCpRdwomyw_OgceH4GpMxdF33dSsbFDVCLcGl7TCA"}],"stage":"accepted"}
```

A revocation record needs its target grant in the verification context, so it is shown as a
container-context example: this record revokes `grant-root-1` (digest placeholder) and is
signed by the root human key, which is authorised to revoke it.

<!-- spec-example: container-context -->
```json
{"actor":{"key":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","type":"human"},"body":{"action":"revoke","revoke":{"effective_at":"2026-12-01T00:00:00.000Z","reason":"engagement ended","revokes":{"digest":"sha256:5555555555555555555555555555555555555555555555555555555555555555","id":"grant-root-1","kind":"weave.grant","origin":{"instance":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","project":"example"}}}},"format":"weave-record/1","id":"grant-root-1-revoke","kind":"weave.grant","origin":{"instance":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","project":"example"},"recorded_at":"2026-12-01T01:00:00.000Z","sigs":[{"alg":"ed25519","key":"ed25519:333f90d1d9dfb653b78df977b9b13ff2","value":"HGfRzrYblzLJBIIEBhKO_H4O2vIO5kMp5K7ORvHYpGUi3yU4vZna4oPd_dcd5jR_IG-i9iXSx2FYUDnbTcmNAw"}],"stage":"accepted"}
```

## Why this kind exists

The founding principle is that agents act for people at scale; every agent record must say
who acted, on whose behalf, and under what authority. A machine-readable grant with kinds,
actions, scope, validity, transferability and a revocation path makes "no grant ⇒ proposal
only" enforceable offline, and the subset rule makes delegation unable to expand authority
[§8.1][§8.2][S3] decided (Inceptless decision 2026-11-10 #34; S3).
