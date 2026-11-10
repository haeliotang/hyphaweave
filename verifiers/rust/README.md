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

**Review status: H1 has not yet been externally reviewed.** The format
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
    src/zip.rs                   minimal zip reader (stored + DEFLATE, §11.9)
    src/vectors.rs               conformance-vector runner (§14.10)
    src/ed25519.rs               strict Ed25519 profile (§3, RFC 8032)
    src/timestamp.rs             RFC 3161 / CMS / X.509 profile (§12)
    src/kinds.rs                 registered-kind body schemas and obligations (§7)
    src/json.rs, src/value.rs    WR-CJ parser/writer (§1)
    src/digest.rs, src/b64.rs    byte constructions and encodings (§2)
    src/time.rs, src/patterns.rs TS literals and shared grammars (§2.8)
    src/limits.rs                §13 size limits
    src/labels.rs                SPDX licence expression syntax (§8.7)
    src/error_codes.rs           closed error/notice registry
  hyphaweave-verify-rs/          command-line front end (§14.1)
  tests in hyphaweave-verify/tests/   external-vector and report-byte integration tests
  deny.toml                      cargo-deny policy (licences, bans, sources, advisories)
  scripts/                       gate-3 report comparison (not part of the verifier)
```

The library crate and the CLI are in one Cargo workspace. The library has no
I/O of its own: `record` targets are raw bytes and containers are a directory,
zip bytes or an already-materialised file map, so an embedder controls all
reads. The CLI is the only place that touches the filesystem and environment.

## Building

The crate needs a stable Rust toolchain (MSRV `1.85`). From the repository root:

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
hyphaweave-verify-rs record <file> [--keys <dir>] [--json]
hyphaweave-verify-rs container <dir|zip> [--keys <dir>] [--tsa-trust <pem>] [--previous <dir>] [--json]
hyphaweave-verify-rs vectors <dir> [--tsa-trust <pem>] [--json]
hyphaweave-verify-rs --help | --version
```

`--json` is accepted and is the default. A run prints exactly one deterministic
JSON report to standard output; usage and I/O errors go to standard error and
exit code `2`. The test-only `WEAVE_VERIFY_SKIP_CHECKS` environment variable
(§14.7) is honoured by the CLI only; the library never reads the environment.
Exit codes are `0` (valid, or `erased` for a placeholder record, or every
vector case matched), `1` (invalid, unverifiable or a vector mismatch) and `2`
(usage/IO; no report on stdout).

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
(`--tsa-trust`), an optional previous container (`--previous`) and the test-only
skip set. Reports are deterministic: no clock, locale, time zone, environment
or filesystem-order dependence, and `report_json::to_bytes` reproduces the
§14.6 serialisation (sorted keys, two-space indent, `ensure_ascii`, one trailing
LF) without a JSON serialization dependency.

## Dependencies

The direct dependencies and their purposes are listed below; the versions are
the ones pinned in `Cargo.lock`. The full locked tree is 68 packages; all are
permissive and all come from crates.io. `cargo tree` and `cargo metadata` are
the authoritative sources:

```bash
cargo tree --manifest-path verifiers/rust/Cargo.toml --workspace
```

### Direct dependencies

| crate | version | purpose | licence |
|---|---|---|---|
| `sha2` | 0.10.9 | SHA-256 for the byte constructions and digests (§2.2–§2.5) | MIT OR Apache-2.0 |
| `curve25519-dalek` | 4.1.3 | Edwards point/scalar arithmetic for the strict §3 profile (not its convenience verifier) | BSD-3-Clause |
| `miniz_oxide` | 0.8.9 | DEFLATE decoding for zip-form containers (§11.9) | MIT OR Zlib OR Apache-2.0 |
| `der` | 0.7.10 | DER decoding for CMS, X.509 and timestamp structures (§12) | Apache-2.0 OR MIT |
| `cms` | 0.2.3 | CMS `SignedData` parsing (§12.2) | Apache-2.0 OR MIT |
| `x509-cert` | 0.2.5 | X.509 certificate parsing for timestamp signers (§12.2) | Apache-2.0 OR MIT |
| `spki` | 0.7.3 | `SubjectPublicKeyInfo` decoding (§12.2) | Apache-2.0 OR MIT |
| `const-oid` | 0.9.6 | OID constants for the §12.2 profile | Apache-2.0 OR MIT |
| `rsa` | 0.9.10 | RSA PKCS#1 v1.5 signature verification for TSA certificates | MIT OR Apache-2.0 |
| `p256` | 0.13.2 | ECDSA P-256 signature verification for TSA certificates | Apache-2.0 OR MIT |
| `p384` | 0.13.1 | ECDSA P-384 signature verification for TSA certificates | Apache-2.0 OR MIT |
| `signature` | 2.2.0 | signature-trait glue between the verifier and `rsa`/`ecdsa` | Apache-2.0 OR MIT |

### Transitive dependencies

These crates are not used directly by the verifier; their purpose is the
support role named here. Licence expressions are taken verbatim from the
crates' metadata and every one is accepted by `deny.toml`.

| crate | version | role | licence |
|---|---|---|---|
| `adler2` | 2.0.1 | DEFLATE checksum (`miniz_oxide`) | 0BSD OR MIT OR Apache-2.0 |
| `autocfg` | 1.5.1 | build-script/compiler probes | Apache-2.0 OR MIT |
| `base16ct` | 0.2.0 | RustCrypto hex encoding | Apache-2.0 OR MIT |
| `base64ct` | 1.8.3 | RustCrypto base64 encoding | Apache-2.0 OR MIT |
| `block-buffer` | 0.10.4 | hashing trait support | MIT OR Apache-2.0 |
| `cfg-if` | 1.0.5 | compile-time platform selection | MIT OR Apache-2.0 |
| `cpufeatures` | 0.2.17 | runtime CPU feature detection | MIT OR Apache-2.0 |
| `crypto-bigint` | 0.5.5 | big-integer arithmetic for ECDSA/RSA verification | Apache-2.0 OR MIT |
| `crypto-common` | 0.1.6 | RustCrypto trait glue | MIT OR Apache-2.0 |
| `curve25519-dalek-derive` | 0.1.1 | derive support for `curve25519-dalek` | MIT/Apache-2.0 |
| `der_derive` | 0.7.3 | derive support for `der` | Apache-2.0 OR MIT |
| `digest` | 0.10.7 | hashing trait layer | MIT OR Apache-2.0 |
| `ecdsa` | 0.16.9 | ECDSA verification plumbing | Apache-2.0 OR MIT |
| `elliptic-curve` | 0.13.8 | elliptic-curve arithmetic plumbing | Apache-2.0 OR MIT |
| `ff` | 0.13.1 | finite-field trait layer | MIT/Apache-2.0 |
| `fiat-crypto` | 0.2.9 | generated field arithmetic | MIT OR Apache-2.0 OR BSD-1-Clause |
| `flagset` | 0.4.7 | flagset support used by `cms`/`x509-cert` | Apache-2.0 |
| `generic-array` | 0.14.9 | fixed-size array types | MIT |
| `getrandom` | 0.2.17 | RNG plumbing in `crypto-bigint` (unused at runtime) | MIT OR Apache-2.0 |
| `group` | 0.13.0 | group trait layer | MIT/Apache-2.0 |
| `hmac` | 0.12.1 | HMAC for RFC 6979 deterministic nonces | MIT OR Apache-2.0 |
| `lazy_static` | 1.5.1 | lazily initialised tables (`curve25519-dalek`) | MIT OR Apache-2.0 |
| `libc` | 0.2.191 | platform shim | MIT OR Apache-2.0 |
| `libm` | 0.2.16 | portable floating-point math | MIT |
| `num-bigint-dig` | 0.8.6 | big-integer arithmetic for `rsa` | MIT/Apache-2.0 |
| `num-integer` | 0.1.47 | integer arithmetic support | MIT OR Apache-2.0 |
| `num-iter` | 0.1.46 | integer iterator support | MIT OR Apache-2.0 |
| `num-traits` | 0.2.19 | numeric trait layer | MIT OR Apache-2.0 |
| `pem-rfc7468` | 0.7.0 | PEM decoding for trust anchors and timestamp files | Apache-2.0 OR MIT |
| `pkcs1` | 0.7.5 | PKCS#1 key/signature types for `rsa` | Apache-2.0 OR MIT |
| `pkcs8` | 0.10.2 | PKCS#8 key encoding support | Apache-2.0 OR MIT |
| `ppv-lite86` | 0.2.21 | SIMD support for `rand_chacha` | MIT OR Apache-2.0 |
| `primeorder` | 0.13.6 | prime-order curve arithmetic (`p256`, `p384`) | Apache-2.0 OR MIT |
| `proc-macro2` | 1.0.107 | procedural-macro support | MIT OR Apache-2.0 |
| `quote` | 1.0.47 | procedural-macro support | MIT OR Apache-2.0 |
| `rand` | 0.8.8 | RNG plumbing in `rsa`/`crypto-bigint` (unused at runtime) | MIT OR Apache-2.0 |
| `rand_chacha` | 0.3.1 | RNG plumbing in `rsa` (unused at runtime) | MIT OR Apache-2.0 |
| `rand_core` | 0.6.4 | RNG trait layer | MIT OR Apache-2.0 |
| `rfc6979` | 0.4.0 | deterministic nonce helper in `ecdsa` | Apache-2.0 OR MIT |
| `rustc_version` | 0.4.1 | build-script compiler probe | MIT OR Apache-2.0 |
| `sec1` | 0.7.3 | EC point encoding support | Apache-2.0 OR MIT |
| `semver` | 1.0.28 | build-script version parsing | MIT OR Apache-2.0 |
| `smallvec` | 1.16.5 | small-vector support in `der` | MIT OR Apache-2.0 |
| `spin` | 0.9.9 | no-std synchronisation shim | MIT |
| `subtle` | 2.6.1 | constant-time comparison helpers | BSD-3-Clause |
| `syn` | 2.0.119 | procedural-macro parser | MIT OR Apache-2.0 |
| `tls_codec` | 0.4.2 | TLS codec support used by `cms` | Apache-2.0 OR MIT |
| `tls_codec_derive` | 0.4.2 | derive support for `tls_codec` | Apache-2.0 OR MIT |
| `typenum` | 1.20.1 | type-level integers for `generic-array` | MIT OR Apache-2.0 |
| `unicode-ident` | 1.0.27 | identifier parsing for `syn` | (MIT OR Apache-2.0) AND Unicode-3.0 |
| `version_check` | 0.9.5 | build-script compiler probe | MIT/Apache-2.0 |
| `wasi` | 0.11.1+wasi-snapshot-preview1 | WASI platform shim (`getrandom`, non-host targets) | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| `zerocopy` | 0.8.63 | zero-copy byte views in RustCrypto | BSD-2-Clause OR Apache-2.0 OR MIT |
| `zerocopy-derive` | 0.8.63 | derive support for `zerocopy` | BSD-2-Clause OR Apache-2.0 OR MIT |
| `zeroize` | 1.9.1 | zeroing support in RustCrypto types | Apache-2.0 OR MIT |
| `zeroize_derive` | 1.5.0 | derive support for `zeroize` | Apache-2.0 OR MIT |

### Supply-chain policy

`deny.toml` is enforced with `cargo deny check` (licences, bans, sources and
advisories). It allows exactly the licence identifiers that at least one crate
in the locked tree requires: Apache-2.0, MIT, BSD-3-Clause and Unicode-3.0.
Other identifiers appear only as alternatives inside OR expressions (0BSD,
BSD-1-Clause, BSD-2-Clause, Zlib, `Apache-2.0 WITH LLVM-exception`) and are
resolved by an allowed branch; add one to the allow list with a comment if a
future dependency requires it outright. crates.io is the only allowed source:
unknown registries and git dependencies are denied.

The advisory check ignores two timing-side-channel advisories that concern
operations this verifier does not perform:

| advisory | crate | why it does not apply |
|---|---|---|
| `RUSTSEC-2023-0071` | `rsa 0.9.x` | "Marvin Attack" concerns RSA *private-key* operations; the verifier only verifies signatures with public keys and never handles a private key. |
| `RUSTSEC-2026-0387` | `crypto-bigint 0.5.x` | Secret-dependent branches in constant-time primitives; reached only through ECDSA *verification*, which operates on public values (signature, public key, digest) and handles no secret scalar. |

Both ignores must be removed when the respective dependency families are
upgraded; each entry carries the same note in `deny.toml`.

## Tests and gates

```bash
# from the repository root
cargo fmt --manifest-path verifiers/rust/Cargo.toml --check
cargo clippy --manifest-path verifiers/rust/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path verifiers/rust/Cargo.toml --workspace

# conformance vectors (exit 0 = every case matched)
cargo run --manifest-path verifiers/rust/Cargo.toml -p hyphaweave-verify-rs -- vectors vectors
cargo run --manifest-path verifiers/rust/Cargo.toml -p hyphaweave-verify-rs -- \
    vectors vectors/frozen/v0.1-candidate

# supply chain (run from verifiers/rust/)
( cd verifiers/rust && cargo deny check )
( cd verifiers/rust && cargo audit --ignore RUSTSEC-2023-0071 --ignore RUSTSEC-2026-0387 )

# gate 3: two-implementation report comparison (only after the vectors pass)
./.venv/bin/python verifiers/rust/scripts/compare_reports.py --include-frozen
```

The test suite has three layers:

1. **Unit tests** in the modules themselves, covering the WR-CJ parser, the
   fixed Ed25519 verification order, TS arithmetic, label propagation, grant
   subsets, limits and report serialization.
2. **Integration tests** in `hyphaweave-verify/tests/`: the RFC 8032 and
   Wycheproof Ed25519 vectors, the RFC 8785-derived canonical-JSON material,
   the report byte format, and the committed L2 timestamp cases.
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
