<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# L2 integrity-level vectors: local, deterministic RFC 3161 test TSA

This directory contains the `integrity-levels` conformance cases (L0/L1/L2) and the L2
timestamp-profile negative vectors. Every timestamp reply is crafted by
`tools/gen_vectors_extra.py` from the **local, test-only** RSA-2048 TSA key under
`vectors/keys/tsa/`. Nothing here is a real timestamp authority and nothing here is trusted
by anything outside these vectors.

## Test TSA material (deliberately published test material)

| File | Purpose |
|---|---|
| `vectors/keys/tsa/tsa.key.pem` | RSA-2048 private key, publicly published test material |
| `vectors/keys/tsa/tsa.crt.pem` | self-signed certificate (the normal signer/anchor), CN `Hyphaweave H0 test TSA (test only)`, validity 2026-01-01 → 2126-01-01, critical `timeStamping` EKU and `digitalSignature` key usage |
| `vectors/keys/tsa/tsa.cnf`, `vectors/keys/tsa/serial.txt` | kept from v0.1 for reference; the revision-1 generator does not use OpenSSL |

Certificate fingerprint (SHA-256 of the DER certificate; this is what a verifier compares
against for a `--tsa-trust` anchor):

```
2cd592e2ecd4c9f3ba4271eeeb446e7d1248704d3cd65cd8d033b2cf2c64300c
```

## How the `.tsr` files are generated (deterministic, no OpenSSL)

Each `container/signatures/timestamp-N.tsr` is a DER `TimeStampResp` built with
`asn1crypto` and signed by the test TSA key with RSA PKCS#1 v1.5 / SHA-256. The construction
is fully deterministic:

- fixed `genTime` **2026-11-01T00:00:00.000Z** for every crafted token (a claimed external
  time, recorded in the token; it does not come from the wall clock);
- fixed CMS `signingTime` **2026-11-10T09:52:40Z**, fixed serial numbers, fixed nonce-free
  minimal `TSTInfo`, fixed certificate hashes;
- `signerInfo.digestAlgorithm = sha256`, `signatureAlgorithm = rsaEncryption` (RSA PKCS#1
  v1.5), ESS `signingCertificateV2` over the signer certificate, `messageDigest` over the
  TSTInfo DER;
- exactly one signer certificate is carried inside the token's `certificates` set.

Because PKCS#1 v1.5 signatures and certificates are deterministic, re-running
`tools/gen_vectors_extra.py` reproduces the committed `.tsr` bytes exactly:
`--check` verifies this byte-for-byte. **No wall clock, no OpenSSL, no network and no
absolute path influence the timestamp bytes**, and verification of these committed vectors
needs nothing but the repository.

Regenerate and verify:

```bash
./.venv/bin/python tools/gen_vectors_extra.py --only integrity-levels
./.venv/bin/python tools/gen_vectors_extra.py --check
```

## Timestamp verification profile exercised by these vectors

The spec's RFC 3161 archive profile is exercised one defect at a time, with the exact
expected code handwritten in `expected.json`:

| Case | Crafted variation | Expected |
|---|---|---|
| `l2-valid` | valid token over the raw 32-byte manifest digest, anchor supplied | valid, `anchor_verified: true` |
| `l2-without-trust` | same token, no `--tsa-trust` | unverifiable `E_TS_UNTRUSTED` |
| `l2-imprint-mismatch` | imprint over another document | invalid `E_TS_IMPRINT` |
| `l2-ts-file-digest` | sig file lists a digest the `.tsr` does not have | invalid `E_TS_FILE` |
| `l2-cms-tampered` | one bit flipped in the CMS signature | invalid `E_TS_CMS` |
| `l2-ess-v1-only` | legacy ESS `signingCertificate` (SHA-1) instead of v2 | invalid `E_TS_CMS` |
| `l2-ess-missing` | no ESS signing-certificate attribute | invalid `E_TS_CMS` |
| `l2-message-digest-wrong` | signed `messageDigest` does not match the TSTInfo | invalid `E_TS_CMS` |
| `l2-cert-not-in-token` | signer certificate omitted from the token | invalid `E_TS_CMS` |
| `l2-eku-missing` | crafted signer certificate without `timeStamping` EKU | invalid `E_TS_CERT` |
| `l2-cert-expired` | crafted signer certificate valid 2020–2021 only | invalid `E_TS_CERT` |
| `l2-digest-alg-unsupported` | `messageImprint.hashAlgorithm` is sha1 | invalid `E_TS_SCHEMA` |
| `l2-status-not-granted` | `PKIStatusInfo.status = grantedWithMods` | invalid `E_TS_SCHEMA` |
| `l2-anchor-mismatch` | `--tsa-trust` points at a different certificate | unverifiable `E_TS_UNTRUSTED` |
| `l2-renewal-chain-valid` | reply 2 imprints `SHA-256(reply-1 bytes \|\| manifest digest)` and `renews` reply 1 | valid, `anchor_verified: true` |
| `l2-renewal-broken` | `renews` points at an unlisted reply | invalid `E_TS_RENEWAL` |
| `l2-renewal-imprint-mismatch` | reply 2 imprints only the previous `.tsr` bytes | invalid `E_TS_IMPRINT` |
| `l0-with-timestamp` | L0 manifest carrying a timestamp | invalid `E_MANIFEST_LEVEL` |

The `eku-missing`/`expired` cases write the crafted certificate into the case directory as
`tsa-crafted.pem` and pass it via `--tsa-trust`, so the failing check is the certificate
profile, not the anchor-fingerprint comparison.

Case files for the crafted certificates are deterministic too: serial numbers, subject
names, validity windows, extensions and the self-signature are fixed constants.

## Renewal chain representation

`signatures/manifest.sig.json`'s `timestamps[]` entries are `{path, digest, renews}` sorted
by path and form a single chain: exactly one `renews: null` head, every other entry points
at the previous reply of the chain. The imprint of a renewal reply is

```
SHA-256(previous reply .tsr file bytes || raw 32-byte manifest digest)
```

while the chain head imprints the raw manifest digest itself (spec §12.4). The renewal
battery above covers the valid chain as well as a broken link and a wrong renewal imprint.

## Report expectations

For a claimed L2 container the report carries `level_claimed: "L2"`,
`level_verified: "L0"` (an offline verifier never claims the internal hash chain) and
`anchor_verified: true` only when the whole timestamp chain verifies with at least one
matching anchor; otherwise `anchor_verified` is `false` and the container is at best
`unverifiable`. The `expected_container` blocks of these cases assert exactly that.
