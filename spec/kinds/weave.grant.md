<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# `weave.grant` — authorise an agent, and revoke grants

**Kind:** `weave.grant` · **Stage:** `accepted` only · **Per-record signature:** REQUIRED
· **Decision tags:** [§8.1] [§8.2] [§8.5] [Q10] [Q11] · **Normative parent:**
`spec/weave-record-1.md` §5.4–§5.6, §9.6, §4.4.

## Purpose

A grant is the authorisation record that lets an agent act, and defines exactly how far
that authority goes: which agent key, which record kinds, which actions, which scope, for
how long, whether it can be sub-delegated, and how it is revoked. It is signed by a human or
organization key for a root grant, or by a delegated agent under a transferable parent grant
for sub-grants [§8.2][Q10]. Grants make the "who did it, on behalf of whom, under what
authority" question answerable offline, and they are what keeps an agent's default output a
proposal [§8.1][§8.2].

Grant revocation is modelled as `action: "revoke"` in this same kind rather than a ninth
`weave.*` kind, because H0 registers exactly eight kinds; this may be revisited in v0.2
[Q10].

## Envelope requirements

- `kind` is exactly `weave.grant`; `stage` **MUST** be `accepted` (`E_ENV_STAGE`)
  [§7.4][§4].
- `sigs` **MUST** be present and include a valid signature by `actor.key` [§4]. If `sigs`
  is non-empty but the required signer is missing or wrong, the kind code is reported
  instead of `E_SIG_REQUIRED`: `E_GRANT_GRANTER` for `action == "grant"`,
  `E_GRANT_REVOKE_SIGNER` for `action == "revoke"` (§4.4 precedence, Q31);
  `E_SIG_REQUIRED` is used only when `sigs` is absent or empty.
- `actor`:
  - **root grant** — `actor.type` is `human` or `organization`;
  - **delegated sub-grant** — `actor.type` is `agent`, `program` or `device`, and
    `actor.grant` (envelope) references the parent grant; for `agent` the normal agent
    envelope obligations apply [§8.2].
- `salt` is optional. `refs`/`labels` follow the parent specification.

## Body

`body` carries `action` and exactly one of `grant` / `revoke`; that variant structure and
the known members are fixed. Additional unknown **body** members are permitted by additive
evolution (K3); unknown members inside the `grant`/`revoke` variant objects are structurally
rejected (`E_GRANT_SCHEMA`).

| member | required | type | rule |
|---|---|---|---|
| `action` | yes | string | `"grant"` or `"revoke"`; any other value `E_GRANT_SCHEMA` |
| `grant` | iff `action == "grant"` | object | present exactly when `action` is `grant`; present with revoke → `E_GRANT_SCHEMA` |
| `revoke` | iff `action == "revoke"` | object | present exactly when `action` is `revoke`; absent → `E_GRANT_SCHEMA` |

### `grant` object (closed)

| member | required | type | rule |
|---|---|---|---|
| `grantee` | yes | object | closed `{"key": <key id>}`; the authorised key |
| `kinds` | yes | array | 1–64 kind names (valid kind name syntax, §7.1), unique |
| `actions` | yes | array | 1–7 unique strings from `propose`, `accept`, `reject`, `withdraw`, `supersede`, `erase`, `grant` |
| `scope` | yes | array | 1–32 strings, each 1–256 Unicode scalar values; audit scope (not machine-checked for authorisation in H0) |
| `valid_from` | yes | TS | start of the grant's validity window |
| `valid_until` | yes | TS or `null` | end of the window; `null` means unbounded |
| `transferable` | yes | boolean | whether the grantee may delegate this grant further |
| `evidence` | yes | reference object or `null` | audit evidence for the grant (not machine-checked in H0) |
| `remedy` | yes | string or `null` | audit remedy clause (not machine-checked in H0) |

`valid_from` **MUST** be less than or equal to `valid_until` when `valid_until` is not
`null`; otherwise `E_KEY_VALIDITY` (the closed registry assigns the validity-window
ordering condition of `weave.grant` to that code). The `scope`, `evidence` and `remedy` members
implement the four elements of authorisation, evidence, scope and remedy from the source
project; H0 records them for audit and does not evaluate them for authorisation [§8.2].

### `revoke` object (closed)

| member | required | type | rule |
|---|---|---|---|
| `revokes` | yes | reference object | the grant being revoked; digest, origin, id per §6.1 |
| `effective_at` | yes | TS | claimed instant from which the grant is revoked |
| `reason` | yes | string or `null` | free-form reason (not interpreted) |

## Semantic rules

### Root grant

A grant record whose `actor.type` is `human` or `organization` is a root grant. Its
authority comes from the signer; no parent grant is required [§8.2].

### Delegated sub-grant

A grant record whose `actor.type` is `agent`, `program` or `device` **MUST** have
`actor.grant` resolve to a parent `weave.grant` record that permits issuing grants, checked
in this order:

1. **resolve and cover:** an unresolvable parent is `unverifiable` (`E_GRANT_UNRESOLVED`);
   a resolved parent that is not an `action == "grant"` `weave.grant` whose `kinds`
   contain `weave.grant` and whose `actions` contain `grant` is `E_GRANT_GRANTER`
   (invalid);
2. has `transferable == true` — otherwise `E_GRANT_NOT_TRANSFERABLE` (invalid);
3. has `grant.grantee.key` equal to the sub-granter's `actor.key` — otherwise
   `E_GRANT_GRANTER` (invalid);
4. is inside its validity window at the sub-grant's `recorded_at` and is not revoked as of
   that time — otherwise `E_GRANT_GRANTER` (invalid).

The sub-grant's fields **MUST** stay within the parent's authority: its `kinds` **MUST** be
a subset of the parent's `kinds`; its `valid_from` **MUST** be greater than or equal to the
parent's `valid_from`; its `valid_until` **MUST** be less than or equal to the parent's
`valid_until` (`null` on the parent means unbounded; a `null` child under a bounded parent
exceeds it). Any violation is `E_GRANT_DELEGATION_EXCEEDS` (invalid). The five checks of
the parent (resolve/cover, transferable, granter identity, parent validity, no expansion)
are applied in that order; the first failing check is the record's single error [Q10].

### Authorisation of a record by a grant

A record that uses `actor.grant` G (or a record whose actor is an agent and therefore needs
a grant, §5.4) is authorised when G is a valid `weave.grant` with `action == "grant"` and,
at the record's claimed `recorded_at`:

- G is inside its validity window (`valid_from <= recorded_at <= valid_until` when
  `valid_until` is not null); outside → `unverifiable` (`E_GRANT_EXPIRED`);
- G is not revoked as of that time (§ below); revoked → `unverifiable`
  (`E_GRANT_REVOKED`);
- `G.grant.grantee.key == record.actor.key` — else `E_GRANT_GRANTEE_MISMATCH` (invalid);
- `G.grant.kinds` contains the record's `kind` and `G.grant.actions` contains the action
  mapped from the record's stage (`propose`, `accept`, `reject`, `withdraw`, `supersede`) —
  else `E_GRANT_NOT_APPLICABLE` (invalid).

The not-yet-valid case and the verdict split (`unverifiable` for revoked/expired,
`invalid` for grantee/kind/action mismatches) are PROVISIONAL readings of Q11 (parent
specification Appendix A).

### Revocation records

For `action == "revoke"`:

1. `revoke.revokes` **MUST** resolve to a `weave.grant` record in the context;
   otherwise `E_GRANT_REVOKE_REF` (invalid). `revoke.revokes.kind`, when present, SHOULD be
   `weave.grant`; a contradicting kind claim is `E_REF_KIND_MISMATCH` (invalid).
2. The revoking record **MUST** be signed by the original granter's `actor.key` of the
   revoked grant, **or** by a key declared `human`/`organization`; otherwise
   `E_GRANT_REVOKE_SIGNER` (invalid) [§8.5].
3. Effect: a record that uses the revoked grant at a claimed `recorded_at >=
   effective_at` is `unverifiable` (`E_GRANT_REVOKED`); records at or before
   `effective_at` are unaffected. Revocation is immediately visible offline; there is no
   propagation delay to model [§8.5][Q11].
4. `effective_at` is a claim and is not constrained relative to `recorded_at` by H0; a
   revocation with a future `effective_at` is a scheduled revocation and applies from that
   time.

### What a grant does not prove

A grant proves that the named granter authorised the named grantee key for the listed kinds
and actions within the window. It does not prove the grantee's conduct was wise, nor that
the grant's scope was respected (scope is an audit obligation in H0). Delegation cannot
expand authority (§ above) [§8.2][Q10].

## Error codes

| code | verdict | condition |
|---|---|---|
| `E_ENV_STAGE` | invalid | stage is not `accepted` |
| `E_GRANT_SCHEMA` | invalid | body shape, action/member pairing, vocabulary, kinds/actions/scope grammar |
| `E_KEY_VALIDITY` | invalid | `valid_from > valid_until` in the `grant` object |
| `E_GRANT_NOT_TRANSFERABLE` | invalid | parent grant is not transferable |
| `E_GRANT_DELEGATION_EXCEEDS` | invalid | sub-grant exceeds parent kinds or window |
| `E_GRANT_REVOKE_SIGNER` | invalid | revocation not signed by original granter key or human/org key |
| `E_GRANT_REVOKE_REF` | invalid | revoked grant not resolvable in context |
| `E_GRANT_GRANTEE_MISMATCH` | invalid | a record's `actor.key` is not the `grantee.key` of the grant it cites for authorisation |
| `E_GRANT_NOT_APPLICABLE` | invalid | record's kind/action not covered by the grant |
| `E_REF_KIND_MISMATCH` | invalid | a reference kind claim contradicts the target kind |
| `E_GRANT_GRANTER` | invalid | the granter is not permitted to issue this grant: parent resolved but not an authorising `weave.grant` covering `weave.grant`/`grant`, parent `grantee.key` is not the sub-granter's key, parent outside its validity window or revoked at the sub-grant's `recorded_at`, or (with non-empty `sigs`) the required granter signature is missing/wrong for `action == "grant"` |
| `E_GRANT_UNRESOLVED` | unverifiable | a grant's parent or a record's cited authorisation cannot be resolved/checked |
| `E_GRANT_EXPIRED` | unverifiable | a record's cited grant is outside its validity window at record time (incl. not yet valid) |
| `E_GRANT_REVOKED` | unverifiable | grant revoked as of record time |
| `E_ENV_ACTOR_GRANT_MISSING` | invalid | agent actor lacks `actor.grant` (envelope) |
| `E_SIG_REQUIRED` | invalid | `sigs` is absent or an empty array (per-record signing required) |
| `E_KEY_UNKNOWN` | unverifiable | signer's key is not available in context |
| `N_KEY_TOFU`, `N_KEY_UNDECLARED` | notice | trust-on-first-use reporting |

## Canonical JSON examples

A root grant authorising an agent to propose and accept receipts in a scope (illustrative;
the `evidence` reference is null):

```json
{"actor":{"key":"ed25519:5555555555555555555555555555555555555555555555555555555555555555","type":"human"},"body":{"action":"grant","grant":{"actions":["propose","accept"],"evidence":null,"grantee":{"key":"ed25519:6666666666666666666666666666666666666666666666666666666666666666"},"kinds":["koinoweave.receipt"],"remedy":null,"scope":["receipts for mill site A"],"transferable":false,"valid_from":"2026-11-01T00:00:00.000Z","valid_until":"2027-11-01T00:00:00.000Z"}},"format":"weave-record/1","id":"grant-1","kind":"weave.grant","origin":{"instance":"ed25519:5555555555555555555555555555555555555555555555555555555555555555","project":"example"},"recorded_at":"2026-11-01T12:00:00.000Z","sigs":[{"alg":"ed25519","key":"ed25519:5555555555555555555555555555555555555555555555555555555555555555","value":"DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"}],"stage":"accepted"}
```

A revocation of that grant:

```json
{"actor":{"key":"ed25519:5555555555555555555555555555555555555555555555555555555555555555","type":"human"},"body":{"action":"revoke","revoke":{"effective_at":"2026-12-01T00:00:00.000Z","reason":"engagement ended","revokes":{"digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","id":"grant-1","kind":"weave.grant","origin":{"instance":"ed25519:5555555555555555555555555555555555555555555555555555555555555555","project":"example"}}}},"format":"weave-record/1","id":"grant-1-revoke","kind":"weave.grant","origin":{"instance":"ed25519:5555555555555555555555555555555555555555555555555555555555555555","project":"example"},"recorded_at":"2026-12-01T00:00:00.000Z","sigs":[{"alg":"ed25519","key":"ed25519:5555555555555555555555555555555555555555555555555555555555555555","value":"EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"}],"stage":"accepted"}
```

## Why this kind exists

The second founding principle is that agents act for people at scale; every agent record
must say who acted, on whose behalf, and under what authority. A machine-readable,
closed-vocabulary grant is what makes "no grant ⇒ proposal only" enforceable offline
[§8.1][§8.2]. Modelling revocation inside the same kind keeps the H0 vocabulary at exactly
eight kinds while still making revocation visible immediately and retroactively scoped
[Q10][Q11][§8.5].
