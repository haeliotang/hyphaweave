<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Hyphaweave test keys

**These are synthetic public test keys. They are deliberately published and
must never be used for anything real.** Every private seed is derived
deterministically from a public name:

```
seed = SHA-256(b"weave-record/1/test-key/" + <ascii name>)[:32]
```

Regenerate the whole inventory (the output is byte-identical on every run
except the one-time RSA TSA key, which is generated on first run and then
reused):

```
./.venv/bin/python tools/make_keys.py            # create/refresh
./.venv/bin/python tools/make_keys.py --check    # verify, exit 1 on drift
```

Each key has four files: `<name>.seed` (64 lowercase hex characters = the
32-byte Ed25519 seed), `<name>.pub.bin` (32 raw public-key bytes),
`<name>.pub.pem` (SPKI PEM, for `openssl pkeyutl`) and `<name>.json` (name,
key id, key class, file names, warning note). Key ids are
`ed25519:<sha256(raw public key)[:32 hex]>`.

## keyset/

`keyset/*.json` are valid `weave.key.declared` records (one per test key),
used as `--keys @keyset` for record-level vectors:

| key name | declared class | key id | `body.owner` | counter-signature by |
|---|---|---|---|---|
| `human-1` | human | `ed25519:333f90d1d9dfb653b78df977b9b13ff2` | *(root)* | - |
| `human-2` | human | `ed25519:928a1e1dbe45a5d298ce5f6b5ce2eabe` | `human-1` | `human-1` |
| `org-1` | organization | `ed25519:34b835597028e3382ae0ee25dbe7e3e6` | `human-1` | `human-1` |
| `key-old` | human | `ed25519:f6a2edbfb48098da6eb9018c5ee78673` | `human-1` | `human-1` |
| `key-new` | human | `ed25519:bbecfa632505e9d2df3c49b3e70e613f` | `key-old` | `key-old` |
| `key-compromised` | human | `ed25519:d27f41bd9e715d0bf9b66ef71d09aa45` | `human-1` | `human-1` |
| `agent-1` | agent | `ed25519:b6190071e4bbc7c82afc702fa9ffa6f5` | `human-1` | `human-1` |
| `agent-2` | agent | `ed25519:b5598e3317d83ed2ca322be01a8f3560` | `human-1` | `human-1` |
| `program-1` | program | `ed25519:43a1178e89cdbd81a024c9e60369d4a7` | `human-1` | `human-1` |
| `device-1` | device | `ed25519:68abd4908f12bb09ced21e963235955a` | `human-1` | `human-1` |

The declarations carry strictly increasing `recorded_at` values, starting with
`human-1` at `2026-11-01T00:00:00.000Z` (then `human-2`, `org-1`, `key-old`,
`key-new`, `key-compromised`, `agent-1`, `agent-2`, `program-1`, `device-1`,
each one millisecond later). Root-key rule: the earliest valid
human/organization declaration is the self-attested root and may carry only
its self-signature; the verifier reports `N_SELF_ATTESTED_ROOT_KEY` when it
accepts such a root. Every later declaration carries the owner/previous-key
counter-signature (sorted with the self-signature by key id): `human-2`,
`org-1`, `key-old`, `key-compromised`, `agent-*`, `program-*` and `device-*`
are owned and counter-signed by `human-1`; `key-new` is owned and
counter-signed by `key-old` (the previous key of the rotation pair).
`agent`, `program` and `device` declarations require `body.owner`; for those
kinds the owner is a declared human/organization key.

## edge-points/

Deterministic public-key material for the Ed25519 boundary vectors (no private
part exists for these points, and none is derivable from this directory):

| name | encoding | class | derived key id |
|---|---|---|---|
| `small-order-00` | `0000000000000000000000000000000000000000000000000000000000000000` | small-order | `ed25519:66687aadf862bd776c8fc18b8e9f8e20` |
| `small-order-01` | `0000000000000000000000000000000000000000000000000000000000000080` | small-order | `ed25519:63794a3bf8875ac2c32ba6238d27e7e1` |
| `small-order-02` | `0100000000000000000000000000000000000000000000000000000000000000` | small-order | `ed25519:01d0fabd251fcbbe2b93b4b927b26ad2` |
| `small-order-03` | `26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05` | small-order | `ed25519:0d34fd0d99957c53e4dc954ddaae5934` |
| `small-order-04` | `26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85` | small-order | `ed25519:5204010488ca3338ed6c56bb34a9e26c` |
| `small-order-05` | `c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a` | small-order | `ed25519:1381231a2021f331f1b9b69d2f5ff04a` |
| `small-order-06` | `c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa` | small-order | `ed25519:ea4d97c02b411d7bc6e52582295463fe` |
| `small-order-07` | `ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f` | small-order | `ed25519:ffe1ea08f3af443b5a2d6497c9b7c5a7` |
| `x0-sign-bit` | `0100000000000000000000000000000000000000000000000000000000000080` | x0-sign-bit | `ed25519:05e33a7a25dc39ab258dacfea5a955d0` |
| `noncanonical-y-p` | `edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f` | noncanonical | `ed25519:bd6174a7c16e1af07272966a9c071c8a` |
| `mixed-order-a` | `95bdb6042e891155f3f55a3336f7d8b08fd2b5d61bfb79bf59f662bb36c3a288` | mixed-order | `ed25519:54a1a2759b77ab093fcf0dad8f740c36` |

`index.json` carries the same table in machine-readable form. The eight
`small-order-*` encodings are the canonical encodings of points whose order
divides 8; `x0-sign-bit` is the identity encoding with the RFC 8032 sign bit
set (decoding must fail); `noncanonical-y-p` is the `y = p` encoding
(decoding must fail). See `tools/edcraft.py` for the crafted signatures that
go with them.

## tsa/

Local RFC 3161 test TSA material, used **only** to sign the committed L2 test
timestamp replies (the generation procedure lives in
`vectors/integrity-levels/README.md`; this directory is read-only input for it):

- `tsa.key.pem` - RSA-2048 test key (generated once on the first
  `make_keys.py` run and then reused byte-for-byte; public test material, no
  secrecy claimed);
- `tsa.crt.pem` - self-signed certificate, CN `Hyphaweave H0 test TSA (test only)`,
  validity 2026-01-01 through 2126-01-01, critical timeStamping EKU;
  DER-encoded certificate SHA-256:
  `2cd592e2ecd4c9f3ba4271eeeb446e7d1248704d3cd65cd8d033b2cf2c64300c` (OpenSSL x509 fingerprint
  `2C:D5:92:E2:EC:D4:C9:F3:BA:42:71:EE:EB:44:6E:7D:12:48:70:4D:3C:D6:5C:D8:D0:33:B2:CF:2C:64:30:0C`);
- `tsa.cnf`, `serial.txt` - configuration for the local `openssl ts` test TSA.

The TSA certificate is a **test trust anchor** for `--tsa-trust` in the
integrity-level vectors only; it is not trusted by anything else. The contents
of this directory are frozen: do not regenerate them once timestamp replies
exist.
