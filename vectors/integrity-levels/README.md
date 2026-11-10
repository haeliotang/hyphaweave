<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# L2 integrity-level vectors: local RFC 3161 test TSA

This directory contains the `integrity-levels` conformance cases (L0/L1/L2). The L2
cases use a **local, test-only RFC 3161 timestamp authority**: the RSA-2048 key and
self-signed certificate under `vectors/keys/tsa/`. Nothing here is a real TSA and
nothing here is trusted by anything outside these vectors.

## Test TSA material (owned by the test-key inventory, frozen)

| File | Purpose |
|---|---|
| `vectors/keys/tsa/tsa.key.pem` | RSA-2048 private key, deliberately published test material |
| `vectors/keys/tsa/tsa.crt.pem` | self-signed certificate, CN `Hyphaweave H0 test TSA (test only)`, validity 2026-01-01 → 2126-01-01, critical `timeStamping` EKU and `digitalSignature` key usage |
| `vectors/keys/tsa/tsa.cnf` | `openssl ts` configuration used to sign replies |
| `vectors/keys/tsa/serial.txt` | starting serial number for that configuration |

Certificate fingerprint (SHA-256 of the DER certificate, the value a verifier uses
for the `--tsa-trust` anchor comparison):

```
2cd592e2ecd4c9f3ba4271eeeb446e7d1248704d3cd65cd8d033b2cf2c64300c
```

## What the `.tsr` files are

Each committed `container/signatures/timestamp-1.tsr` is a DER-encoded
`TimeStampResp` with a `granted` token whose `TSTInfo.messageImprint` is
`{hashAlgorithm: sha256, hashedMessage: <raw 32-byte manifest digest>}`, signed by
the test TSA certificate. The manifest digest is the §3.3 construction:

```
sha256( "weave-record/1/manifest-digest\n" || <canonical manifest bytes without the
        optional trailing LF> )
```

The `.tsr` files are committed fixtures. They are **not** byte-reproducible (the
token embeds generation time, serial number and nonce), so a normal regeneration
reuses them and `tools/gen_vectors_extra.py --check` stays byte-stable. Only
`--bootstrap` creates missing fixtures.

## Fixtures and why each exists

| Case | Imprint | Why |
|---|---|---|
| `integrity-levels/l2-valid` | the manifest digest | positive L2: verified with `--tsa-trust tsa.crt.pem` |
| `integrity-levels/l2-without-trust` | the manifest digest | same shape, no trust anchor: must be `unverifiable` `E_TS_UNTRUSTED`, never `valid` |
| `integrity-levels/l2-imprint-mismatch` | `sha256("wrong imprint")` | token is genuine but signs another document: `E_TS_IMPRINT` |
| `integrity-levels/l2-ts-file-digest` | the manifest digest | the sig file lists a wrong digest for the file: `E_TS_FILE` |
| `integrity-levels/l0-with-timestamp` | `sha256("l0-with-timestamp fixture")` | an L0 claim that carries a timestamp: `E_MANIFEST_LEVEL` |
| `key-lifecycle/compromise-rescued-by-timestamp` | the manifest digest | the L2 timestamp must prove the record existed before a `key-compromise` `effective_at`; `effective_at` is set to 2026-12-01, after the fixture's `genTime` (2026-11-10) and before the record's claimed `recorded_at` (2027-01-01). Regenerating that fixture **after** the `effective_at` would make the rescue case fail; keep the committed bytes. |

## Requirements for regeneration

**Normal use needs no OpenSSL at all.** The committed `.tsr` fixtures are reused,
so `tools/gen_vectors_extra.py` (write) and `--check` are pure Python and do not
invoke OpenSSL. Only creating a *new* fixture (`--bootstrap`, or deliberately
re-creating one) needs an **OpenSSL 3.x binary that includes the `ts` command**
(`openssl ts`; LibreSSL, the macOS system `openssl`, does not have it).

Resolution order in `tools/gen_vectors_extra.py`: the `OPENSSL` environment
variable, else `/opt/homebrew/opt/openssl@3/bin/openssl` when it exists (macOS
development default), else `openssl` from `PATH` (Linux/CI, e.g. Ubuntu's
OpenSSL 3). Check the tool first:

```bash
OPENSSL="${OPENSSL:-$(command -v openssl)}"
"$OPENSSL" version          # must print OpenSSL 3.x, not LibreSSL
"$OPENSSL" ts -help >/dev/null 2>&1 && echo "ts available"
```

On macOS with Homebrew: `export OPENSSL=/opt/homebrew/opt/openssl@3/bin/openssl`.
On a Debian/Ubuntu CI image, plain `openssl` (3.x) is normally sufficient.

## Regeneration (only when fixtures are intentionally re-created)

The commands below are portable: they run from a clean checkout with any
OpenSSL 3.x that has `ts` (`OPENSSL=/path/to/openssl` may be set first; the
examples use `$OPENSSL`). From the repository root:

```bash
: "${OPENSSL:=/opt/homebrew/opt/openssl@3/bin/openssl}"   # or e.g. "$(command -v openssl)"
work=.tmp-work/tsa-regen
rm -rf "$work" && mkdir -p "$work"
cp vectors/keys/tsa/tsa.cnf vectors/keys/tsa/tsa.crt.pem vectors/keys/tsa/tsa.key.pem "$work"/
printf '01\n' > "$work/serial.txt"
cd "$work"

# 1. The raw 32-byte manifest digest, hex without the "sha256:" prefix.
#    Example for integrity-levels/l2-valid (replace <IMPRINT-HEX> with the actual
#    value computed from that case's container/manifest.json):
IMPRINT_HEX=<IMPRINT-HEX>

# 2. RFC 3161 query for that message imprint and a signed reply (DER TimeStampResp).
"$OPENSSL" ts -query -digest "$IMPRINT_HEX" -sha256 -cert -out query.tsq
"$OPENSSL" ts -reply -config tsa.cnf -section tsa_config1 \
    -queryfile query.tsq -out response.tsr

# 3. Copy the reply over the committed fixture, then verify the case again.
cp response.tsr ../../vectors/integrity-levels/l2-valid/container/signatures/timestamp-1.tsr
```

The routine path is instead:

```bash
./.venv/bin/python tools/gen_vectors_extra.py --bootstrap   # only if a .tsr is missing
./.venv/bin/python tools/gen_vectors_extra.py --check       # byte-stable verification
```

## How the verifier is expected to use these cases

- Record-level cases use `--keys @keyset`.
- L2 positive/mismatch cases expect the argument token resolution rule of
  CONTRACT §16.2: `tsa.crt.pem` is a path relative to the **case directory**, and
  each L2 case directory contains a copy of the test TSA certificate
  (`DER SHA-256 = 2cd5…300c`).
- The trust anchor is supplied only through `--tsa-trust`; without it the timestamp
  is `present-unverified` and the container verdict MUST be `unverifiable`
  (`E_TS_UNTRUSTED`). A verifier must not claim L2 merely because `.tsr` files exist.
- L1 cases must report `chain.status = "unverified"`, `level_verified = "L0"` and the
  notice `N_CHAIN_CLAIM_UNVERIFIED`: an offline verifier cannot recompute an
  exported internal hash chain.

## Digest/byte note for manual verification

Every digested/signed JSON file in these cases is WR-CJ canonical bytes **plus
exactly one trailing LF**, and every digest/signature is computed over the
canonical bytes **without** that trailing LF (CONTRACT §2.8). When verifying by
hand, strip at most one final `0x0a` before hashing or signing — do not strip all
trailing whitespace and do not re-serialize the JSON.
