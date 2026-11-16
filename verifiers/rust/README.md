<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# `hyphaweave-verify-rs` — independent Rust verifier for `weave-record/1`

This workspace is milestone H1: a second, independent verifier for
`weave-record/1`, written in Rust. It implements the record envelope, references,
labels and consent, key lifecycle and grants, erasure, the L0/L1/L2 container
format including RFC 3161 timestamp verification, and the deterministic report
format of §14.

**The implementation was written from the specification (`spec/`) and the
conformance vectors (`vectors/`) only.** It never reads the Python reference
verifier or the vector generators. The Python verifier is executed only as a
black box by the gate-3 comparison script, after the Rust verifier passes every
committed vector; even that script never reads the Python source.

**Review status.** H1 was reviewed by two independent reviewers on 2026-11-11;
H1-FIX1 (2026-11-14) brings the verifier up to specification revision 3 (the
S1 rounds, decision 2026-11-11 #2 and its follow-ups) and handles every review
item; H1-FIX2 and H1-FIX2B follow the two re-reviews, and H1-S2 (2026-11-15,
decision 2026-11-15 #20) follows the S2 round of revision 3, its revisions
S2-FIX1, S2-FIX2 and S2-FIX3 and the supplement S2-FIX2b (decisions 2026-11-15
#8, #18, #22 and #32, 2026-11-16 #1), so both implementations now follow
revision 3 including S2; H1-S3 (decision 2026-11-16 #10) follows S2-FIX4 and
S2-FIX5 (decisions 2026-11-16 #4 and #9), and H1-S4 (decision 2026-11-16 #13) fixes
what the pre-merge reviews of H1-S2 and H1-S3 found. H1-S4 has not itself been
reviewed yet. The format
`weave-record/1` v0.1 is still a draft and has not passed J1/J2 acceptance, so
the candidate regression set in `vectors/frozen/v0.1-candidate/` is not frozen
yet. Nothing in this file claims that a CI run or a gate has passed; run the
commands below on your checkout.

## Workspace layout

```
verifiers/rust/
  Cargo.toml                     workspace (resolver 2), shared metadata and deps
  hyphaweave-verify/             library crate: the verifier
    src/lib.rs                   public API (three entry points + report constants)
    src/options.rs               VerifyOptions, ContainerInput, UsageError
    src/report.rs                Report model (§14.6)
    src/report_json.rs           deterministic report bytes (§14.6)
    src/envelope.rs              record envelope, sigs grammar, refs and labels
    src/record.rs                single-record pipeline (§14.5)
    src/context.rs               trust/key/grant state and cross-record checks
    src/container.rs             container pipeline (§11), report assembly
    src/zip.rs                   zip structure parser (§11.9 phases, ZIP64, bounded DEFLATE)
    src/vectors.rs               conformance-vector runner (§14.10)
    src/ed25519.rs               strict Ed25519 profile (§3, RFC 8032)
    src/timestamp.rs             RFC 3161 / CMS / X.509 profile (§12), schema walk of check 1
    src/der.rs                   strict DER reader written from X.690 (§12.2 1a)
    src/operator.rs              operator inputs: --keys, --tsa-trust, --previous (§14.1)
    src/limitations.rs           closed L_* limitation identifiers (§14.9)
    src/kinds.rs                 registered-kind body schemas and obligations (§7)
    src/json.rs, src/value.rs    WR-CJ parser/writer (§1)
    src/digest.rs, src/b64.rs    byte constructions and encodings (§2)
    src/time.rs, src/patterns.rs TS literals and shared grammars (§2.8)
    src/limits.rs                §13 size and nesting limits
    src/labels.rs                SPDX licence expression syntax (§8.7)
    src/error_codes.rs           closed error/notice registry
  hyphaweave-verify-rs/          command-line front end (§14.1)
  tests in hyphaweave-verify/tests/   external-vector and report-byte integration tests
  deny.toml                      cargo-deny policy (licences, bans, sources, advisories)
  scripts/                       gate 3 comparison, crash-fuzz gate, differential fuzzing
                                 (tooling, not part of the verifier)
```

The library crate and the CLI are in one Cargo workspace. The library has no
I/O of its own: `record` targets are raw bytes and containers are a directory,
zip bytes or an already-materialised file map. A directory container is read
by the library through bounded probes (§13); the `operator` module offers the
bounded, `lstat`-first readers that the CLI uses for operator inputs and
targets. The CLI is the only place that reads the environment.

## Building

The crate needs a stable Rust toolchain (MSRV `1.87`). From the repository root:

```bash
cargo build --manifest-path verifiers/rust/Cargo.toml
cargo build --manifest-path verifiers/rust/Cargo.toml --release
```

The local development sandbox used during H1 keeps the cargo registry cache
inside the repository (the directory is already ignored). This is a sandbox
workaround only; CI and normal checkouts do not need it:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_HOME="$PWD/.tmp-work/cargo-home"
```

## Running the CLI

The command surface is the §14.1 surface of an independent implementation:

```
hyphaweave-verify-rs [--test-hooks] record <file> [--keys <dir>] [--json]
hyphaweave-verify-rs [--test-hooks] container <dir|zip> [--keys <dir>] [--tsa-trust <pem>] [--previous <dir|zip>] [--json]
hyphaweave-verify-rs [--test-hooks] vectors <dir> [--tsa-trust <pem>] [--json]
hyphaweave-verify-rs --help | --version
```

`--json` is accepted and is the default. A run prints exactly one deterministic
JSON report to standard output; usage and I/O errors go to standard error and
exit code `2`. Operator inputs (`--keys`, `--tsa-trust`, `--previous`) are
checked before verification: their kind is established with `lstat`, reads are
bounded, and any failure is exit `2` naming the option and file (§14.1).

The test-only check-skip hook of §14.7 is reachable only through the global
`--test-hooks` switch: `WEAVE_VERIFY_SKIP_CHECKS` is read only when that switch
is present, an unregistered token is a usage error, and a report with a
non-empty `checks_disabled` exits with `3`. Never use it in production.

Exit codes (§14.8): `0` valid (or `erased` for a placeholder record, or every
vector case matched), `1` invalid, unverifiable or a vector mismatch, `2` usage
or I/O error (no report), `3` a report was produced with checks disabled by the
test hook.

Examples from the repository root:

```bash
# one record target, with the public synthetic test keyset as context
cargo run --manifest-path verifiers/rust/Cargo.toml -p hyphaweave-verify-rs -- \
    record vectors/digest/record-unsigned/record.json --keys vectors/keys/keyset

# one L0 container target
cargo run --manifest-path verifiers/rust/Cargo.toml -p hyphaweave-verify-rs -- \
    container vectors/container/l0-minimal/container --keys vectors/keys/keyset

# an L2 container with the test TSA anchor
cargo run --manifest-path verifiers/rust/Cargo.toml -p hyphaweave-verify-rs -- \
    container vectors/integrity-levels/l2-valid/container \
    --keys vectors/keys/keyset \
    --tsa-trust vectors/integrity-levels/l2-valid/tsa.crt.pem

# every committed conformance case
cargo run --manifest-path verifiers/rust/Cargo.toml -p hyphaweave-verify-rs -- \
    vectors vectors
cargo run --manifest-path verifiers/rust/Cargo.toml -p hyphaweave-verify-rs -- \
    vectors vectors/frozen/v0.1-candidate
```

All key material under `vectors/keys/` is synthetic, deliberately public test
material; never trust it outside this repository's tests.

## Library API

The public surface is deliberately small: three entry points that take input
plus `VerifyOptions` and return a `Report` (or a `UsageError` for I/O and usage
problems), and the report serializer.

```rust
use hyphaweave_verify::{report_json, verify_record, VerifyOptions};

let record_bytes = std::fs::read("record.json").unwrap();
let report = verify_record(&record_bytes, &VerifyOptions::new()).unwrap();
let bytes = report_json::to_bytes(&report);       // deterministic §14.6 bytes
std::io::stdout().write_all(&bytes).unwrap();
```

`verify_container` accepts `ContainerInput::Directory`, `ContainerInput::Zip`
and `ContainerInput::Files`; `verify_vectors` runs a conformance directory.
`VerifyOptions` carries the local keyset bytes (`--keys`), TSA trust anchors
(`--tsa-trust`) and an optional previous container (`--previous`). The
test-only skip set (`VerifyOptions::skip_checks`) exists only when the crate is
built with the `test-hooks` cargo feature; a default build has no such field.
`report.input.sha256`/`size` are `Option`s (`null` for an oversize record
target or a directory container without a readable manifest, §14.6).
`operator::{load_keyset, read_tsa_trust, open_previous, open_container,
read_record_target}` are the bounded readers the CLI uses. Reports are
deterministic: no clock, locale, time zone, environment or filesystem-order
dependence, and `report_json::to_bytes` implements the §14.6 byte rule
(UTF-16 member order, two-space indent, ASCII output with lowercase `\uXXXX`
escapes, one trailing LF) without a JSON serialization dependency.

## Dependencies

The direct dependencies and their purposes are listed below; the versions are
the ones pinned in `Cargo.lock`. `Cargo.lock` pins 65 third-party packages
(67 with the two workspace crates); a host build compiles 53 of them,
the rest are optional or target-specific. All are permissive and all come from
crates.io. `cargo tree` and `cargo metadata` are the authoritative sources:

```bash
cargo tree --manifest-path verifiers/rust/Cargo.toml --workspace
```

H1-FIX1 (R2) removed `der`, `cms`, `x509-cert`, `spki` and `const-oid` as
direct dependencies: RFC 3161 receipts, CMS `SignedData` and X.509 certificates
are walked by the verifier's own strict DER module (`src/der.rs`), whose rules
come from X.690 and the ASN.1 modules, not from a parsing library. Some of those
crates remain in the tree only as internals of `rsa`/`p256`/`p384`, where they
decode the signer's `SubjectPublicKeyInfo` after the verifier has checked its
DER itself.

### Direct dependencies

| crate | version | purpose | licence |
|---|---|---|---|
| `sha2` | 0.10.9 | SHA-256 for the byte constructions and digests (§2.2–§2.5) | MIT OR Apache-2.0 |
| `curve25519-dalek` | 4.1.3 | Edwards point/scalar arithmetic for the strict §3 profile (not its convenience verifier) | BSD-3-Clause |
| `miniz_oxide` | 0.8.9 | raw DEFLATE decoding for zip-form containers (§11.9); the zip structure itself is parsed by the verifier | MIT OR Zlib OR Apache-2.0 |
| `rsa` | 0.10.0 | RSA PKCS#1 v1.5 signature verification for timestamp signers (§12.2, X6) | MIT OR Apache-2.0 |
| `p256` | 0.14.0 | ECDSA P-256 verification for timestamp signers (§12.2, X6) | Apache-2.0 OR MIT |
| `p384` | 0.14.0 | ECDSA P-384 verification for timestamp signers (§12.2, X6) | Apache-2.0 OR MIT |
| `signature` | 3.0.0 | signature-trait glue between the verifier and `rsa`/`ecdsa` | Apache-2.0 OR MIT |

### Transitive dependencies

These crates are not used directly by the verifier; their purpose is the
support role named here. Licence expressions are taken verbatim from the
crates' metadata and every one is accepted by `deny.toml`.

| crate | version | role | licence |
|---|---|---|---|
| `adler2` | 2.0.1 | DEFLATE checksum (`miniz_oxide`) | 0BSD OR MIT OR Apache-2.0 |
| `autocfg` | 1.5.1 | build-script compiler probe | Apache-2.0 OR MIT |
| `base16ct` | 1.0.0 | RustCrypto hex encoding | Apache-2.0 OR MIT |
| `base64ct` | 1.8.3 | RustCrypto base64 encoding (key decoding inside `rsa`/`spki`) | Apache-2.0 OR MIT |
| `block-buffer` | 0.10.4 | hashing trait support | MIT OR Apache-2.0 |
| `block-buffer` | 0.12.1 | hashing trait support | MIT OR Apache-2.0 |
| `cfg-if` | 1.0.5 | compile-time platform selection | MIT OR Apache-2.0 |
| `cmov` | 0.5.4 | constant-time conditional moves (`ctutils`) | Apache-2.0 OR MIT |
| `const-oid` | 0.10.3 | OID types inside `spki`/`pkcs1`/`pkcs8` (the verifier keeps its own OID table) | Apache-2.0 OR MIT |
| `cpubits` | 0.1.1 | word-size selection for `crypto-bigint` | MIT OR Apache-2.0 |
| `cpufeatures` | 0.2.17 | runtime CPU feature detection | MIT OR Apache-2.0 |
| `cpufeatures` | 0.3.1 | runtime CPU feature detection | MIT OR Apache-2.0 |
| `crypto-bigint` | 0.7.11 | big-integer arithmetic for RSA/ECDSA verification | Apache-2.0 OR MIT |
| `crypto-common` | 0.1.6 | RustCrypto trait glue | MIT OR Apache-2.0 |
| `crypto-common` | 0.2.2 | RustCrypto trait glue | MIT OR Apache-2.0 |
| `crypto-primes` | 0.7.2 | prime support pulled in by `rsa` (key generation, unused by the verifier) | Apache-2.0 OR MIT |
| `ctutils` | 0.4.8 | constant-time helpers for `crypto-bigint` | Apache-2.0 OR MIT |
| `curve25519-dalek-derive` | 0.1.1 | derive support for `curve25519-dalek` (SIMD backends, not built on the host) | MIT/Apache-2.0 |
| `der` | 0.8.3 | DER decoding of `SubjectPublicKeyInfo` inside `rsa`/`spki` only; receipts and certificates are walked by the verifier's own `der` module | Apache-2.0 OR MIT |
| `digest` | 0.10.7 | hashing trait layer | MIT OR Apache-2.0 |
| `digest` | 0.11.3 | hashing trait layer | MIT OR Apache-2.0 |
| `ecdsa` | 0.17.0 | ECDSA verification plumbing | Apache-2.0 OR MIT |
| `elliptic-curve` | 0.14.3 | elliptic-curve arithmetic plumbing | Apache-2.0 OR MIT |
| `ff` | 0.14.0 | finite-field trait layer | MIT/Apache-2.0 |
| `fiat-crypto` | 0.2.9 | generated field arithmetic (`curve25519-dalek` fiat backend; not built on the host) | MIT OR Apache-2.0 OR BSD-1-Clause |
| `fiat-crypto` | 0.3.0 | generated field arithmetic (`curve25519-dalek` fiat backend; not built on the host) | MIT OR Apache-2.0 OR BSD-1-Clause |
| `generic-array` | 0.14.9 | fixed-size array types (`sha2` 0.10) | MIT |
| `group` | 0.14.0 | group trait layer | MIT/Apache-2.0 |
| `hmac` | 0.13.0 | HMAC for RFC 6979 deterministic nonces (signing only, unused) | MIT OR Apache-2.0 |
| `hybrid-array` | 0.4.15 | fixed-size array types (RustCrypto 0.11+) | MIT OR Apache-2.0 |
| `libc` | 0.2.191 | platform shim | MIT OR Apache-2.0 |
| `num-traits` | 0.2.19 | numeric trait layer | MIT OR Apache-2.0 |
| `pem-rfc7468` | 1.0.0 | PEM support inside `spki`/`pkcs8` (trust anchors are decoded by the verifier itself) | Apache-2.0 OR MIT |
| `pkcs1` | 0.8.0 | PKCS#1 key types for `rsa` | Apache-2.0 OR MIT |
| `pkcs8` | 0.11.0 | PKCS#8 key encoding support | Apache-2.0 OR MIT |
| `primefield` | 0.14.0 | prime-field arithmetic (`p256`, `p384`) | Apache-2.0 OR MIT |
| `primeorder` | 0.14.0 | prime-order curve arithmetic (`p256`, `p384`) | Apache-2.0 OR MIT |
| `proc-macro2` | 1.0.107 | procedural-macro support (optional derives; not built on the host) | MIT OR Apache-2.0 |
| `quote` | 1.0.47 | procedural-macro support (not built on the host) | MIT OR Apache-2.0 |
| `rand_core` | 0.10.1 | RNG trait layer (no RNG is used at verification time) | MIT OR Apache-2.0 |
| `rfc6979` | 0.6.0 | deterministic nonce helper in `ecdsa` (signing only) | Apache-2.0 OR MIT |
| `rustc_version` | 0.4.1 | build-script compiler probe | MIT OR Apache-2.0 |
| `sec1` | 0.8.1 | EC point encoding support | Apache-2.0 OR MIT |
| `semver` | 1.0.28 | build-script version parsing | MIT OR Apache-2.0 |
| `serde` | 1.0.229 | optional serialisation in RustCrypto (not built on the host) | MIT OR Apache-2.0 |
| `serde_core` | 1.0.229 | optional serialisation (not built on the host) | MIT OR Apache-2.0 |
| `serde_derive` | 1.0.229 | optional serialisation (not built on the host) | MIT OR Apache-2.0 |
| `serdect` | 0.4.3 | optional constant-time serialisation (not built on the host) | Apache-2.0 OR MIT |
| `sha2` | 0.11.1 | SHA-2 (0.10 for the verifier; 0.11 inside `rsa`/`ecdsa` digests) | MIT OR Apache-2.0 |
| `spki` | 0.8.1 | `SubjectPublicKeyInfo` decoding inside `rsa`/`p256`/`p384` | Apache-2.0 OR MIT |
| `subtle` | 2.6.1 | constant-time comparison helpers | BSD-3-Clause |
| `syn` | 2.0.119 | procedural-macro parser (not built on the host) | MIT OR Apache-2.0 |
| `syn` | 3.0.10 | procedural-macro parser (not built on the host) | MIT OR Apache-2.0 |
| `typenum` | 1.20.1 | type-level integers | MIT OR Apache-2.0 |
| `unicode-ident` | 1.0.27 | identifier parsing for `syn` (not built on the host) | (MIT OR Apache-2.0) AND Unicode-3.0 |
| `version_check` | 0.9.5 | build-script compiler probe | MIT/Apache-2.0 |
| `wnaf` | 0.14.1 | windowed scalar multiplication (`p256`, `p384`) | Apache-2.0 OR MIT |
| `zeroize` | 1.9.1 | zeroing support in RustCrypto types | Apache-2.0 OR MIT |

### Supply-chain policy

`deny.toml` is enforced with `cargo deny check` (licences, bans, sources and
advisories). It allows exactly the licence identifiers that at least one crate
in the locked tree requires: Apache-2.0, MIT, BSD-3-Clause and Unicode-3.0.
Other identifiers appear only as alternatives inside OR expressions (0BSD,
BSD-1-Clause, Zlib) and are resolved by an allowed branch; add one to the allow list with a comment if a
future dependency requires it outright. crates.io is the only allowed source:
unknown registries and git dependencies are denied.

The advisory check ignores nothing. H1-FIX1 (R2) moved to `rsa` 0.10 and
`p256`/`p384` 0.14, which removed RUSTSEC-2023-0071 (`rsa` 0.9) and
RUSTSEC-2026-0387 (`crypto-bigint` 0.5) from the tree; `cargo audit` runs
without `--ignore`.

## Tests and gates

```bash
# from the repository root
cargo fmt --manifest-path verifiers/rust/Cargo.toml --all --check
cargo clippy --manifest-path verifiers/rust/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path verifiers/rust/Cargo.toml --workspace

# conformance vectors (exit 0 = every case matched)
cargo run --manifest-path verifiers/rust/Cargo.toml -p hyphaweave-verify-rs -- vectors vectors
cargo run --manifest-path verifiers/rust/Cargo.toml -p hyphaweave-verify-rs -- \
    vectors vectors/frozen/v0.1-candidate

# supply chain (run from verifiers/rust/)
( cd verifiers/rust && cargo deny check )
( cd verifiers/rust && cargo audit )

# crash-fuzz gate (deterministic mutants of the vectors; Rust CLI only)
cargo build --release --manifest-path verifiers/rust/Cargo.toml -p hyphaweave-verify-rs
python3 verifiers/rust/scripts/crash_fuzz.py --count 2000 --jobs 2

# gate 3: two-implementation report comparison (only after the vectors pass)
./.venv/bin/python verifiers/rust/scripts/compare_reports.py --include-frozen
```

The test suite has three layers:

1. **Unit tests** in the modules themselves, covering the WR-CJ parser, the
   fixed Ed25519 verification order, TS arithmetic, label propagation, grant
   subsets, limits and report serialization.
2. **Integration tests** in `hyphaweave-verify/tests/`: the RFC 8032 and
   Wycheproof Ed25519 vectors, the RFC 8785-derived canonical-JSON material,
   the report byte format, the committed L2 timestamp cases, the targeted
   probes that pin the checks the vectors do not reach (`tests/probes.rs`, R4;
   `tests/identity.rs`, the full record identity of §6.3/§10.3; and
   `tests/l2_probes.rs`, the `Extension.critical` DEFAULT row and the
   chain-head `renews` rule on a re-signed receipt; `tests/precedence.rs`,
   a §5.5.2 check-order case, H1-FIX2) and the small-stack nesting test
   (`tests/small_stack.rs`, R6: the whole verifier on a 128 KiB stack, the
   JSON parser, writer, `Clone` and `Drop` on a 32 KiB stack). The slow
   corpus-wide ablation and byte-flip gates in `tests/gates.rs` are `#[ignore]`d
   and run with `--release --include-ignored`.
3. **The conformance runner** (`vectors <dir>`) over every case in `vectors/`
   and the candidate regression set, which is also what CI runs.

The full gate list, including the Python job, is in
[`CONTRIBUTING.md`](../../CONTRIBUTING.md) and
[`.github/workflows/ci.yml`](../../.github/workflows/ci.yml). The Rust job in
that workflow builds this workspace, runs the commands above and then runs the
gate-3 comparison script; it does not claim a particular run passed.

## Licence

Code in this directory is Apache-2.0. Specification prose and the rest of the
repository prose are CC-BY-4.0. See [`LICENSING.md`](../../LICENSING.md) for the
file-level split and [`SECURITY.md`](../../SECURITY.md) for what a valid
signature does and does not prove.
