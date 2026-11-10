<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Offline verification of a `weave-record/1` L0 container

**Status:** normative companion to `spec/weave-record-1.md`, revision 1. This document
describes how a person can verify a signed **L0** container by hand, offline, with nothing
but common tools. It relies only on the byte-level rules of the specification; it does not
use the reference verifier and does not need this repository. The worked example in §9 has
been executed on `vectors/container/l0-minimal/` and its real output is pasted there. The
manual procedure deliberately does not cover L2 timestamps or the L1 chain claim; those are
declared limitations in §8.

**Decision tags:** [A1c] [C4] [C5] [D1] [D2] [E5] [I1] [I2] [I4] [Q8].

## 0. What you need

- A shell (bash or zsh; the commands below are POSIX-ish bash), because verification is a
  sequence of small readable steps.
- `sha256sum` — any implementation (GNU coreutils, or the macOS/Darwin build).
- **OpenSSL 3.x** for Ed25519 raw-signature verification. The macOS system `openssl` is
  LibreSSL and cannot do `pkeyutl -rawin`; on such a machine set
  `OSSL=/opt/homebrew/opt/openssl@3/bin/openssl` (or point it at any OpenSSL 3.x binary).
  The examples use `${OSSL:-openssl}` and abort with a clear error if the selected binary
  is not OpenSSL 3.x.
- A JSON viewer. The examples use `jq` (a common JSON viewer/processor) to pick values out
  of JSON; any viewer works — you can read a value on screen and paste it into a shell
  variable instead. Verdicts never depend on the viewer.
- `xxd`, `printf`, `cat`, `head`, `tail`, `wc`, `od`, `tr`, `cut`, `cmp` are ordinary base
  utilities used to move bytes around. No verifier, no library, no network.

This procedure verifies an **L0** container: a directory (or an unzipped zip) with
`manifest.json`, `signatures/manifest.sig.json` and `records/*.json`. Such a container may
additionally carry `previous/manifest.json` (the manifest chain, §7), `blobs/sha256/<hex>`
attachments (§11.7 of the specification) and `readable/` (ignored). L1 chain claims and L2
RFC 3161 timestamps are not verified here; see §8.

## 1. Prepare a scratch area and the byte helpers

Never write inside the container: the bytes you hash must be the bytes you received. Create
the intermediate files elsewhere (for example under `$TMPDIR`), and define the helpers once
in your shell.

```bash
# Run from the repository root; adjust C if your container is elsewhere.
C=vectors/container/l0-minimal/container

# OpenSSL 3.x is required (Ed25519 raw verify). LibreSSL (the macOS system `openssl`)
# cannot do `pkeyutl -rawin`, so override $OSSL explicitly on such a machine:
#   OSSL=/opt/homebrew/opt/openssl@3/bin/openssl
# On a system whose `openssl` is already OpenSSL 3.x, the default below works.
OSSL=${OSSL:-openssl}
if ! "$OSSL" version 2>/dev/null | grep -q '^OpenSSL 3\.'; then
  echo "error: \$OSSL must be OpenSSL 3.x (LibreSSL cannot verify Ed25519 raw signatures)" >&2
  "$OSSL" version >&2 2>/dev/null || true
  exit 2
fi
echo "using: $("$OSSL" version)"

W=$(mktemp -d "${TMPDIR:-/tmp}/weave-l0.XXXXXX")
echo "work directory: $W"

# remove at most one trailing LF (the optional canonical file-form LF) -> $2
strip_lf() {
  n=$(wc -c < "$1")
  if [ "$n" -gt 0 ] && [ "$(tail -c 1 "$1" | od -An -tx1 | tr -d ' \n')" = "0a" ]; then
    n=$((n - 1))
  fi
  head -c "$n" "$1" > "$2"
}

# decode strict unpadded base64url $1 -> raw bytes $2
b64url_decode() {
  s=$1
  case "$s" in
    *[!A-Za-z0-9_-]*) echo "not base64url: $s" >&2; return 1 ;;
  esac
  b64=$(printf '%s' "$s" | tr '_-' '/+')
  case $(( ${#b64} % 4 )) in
    2) b64="${b64}==" ;;
    3) b64="${b64}=" ;;
    0) : ;;
    *) echo "bad base64url length: $s" >&2; return 1 ;;
  esac
  printf '%s' "$b64" | "$OSSL" base64 -d -A -out "$2"
}

# wrap a 32-byte raw Ed25519 public key $1 into a PEM file $2 (Ed25519 SPKI prefix)
raw_to_pem() {
  printf '302a300506032b6570032100' | xxd -r -p > "$W/pub.der"
  cat "$1" >> "$W/pub.der"
  "$OSSL" pkey -pubin -inform DER -in "$W/pub.der" -out "$2"
}

# key id of a raw 32-byte public key: "ed25519:" + first 32 hex of SHA-256(raw bytes)
keyid_of_raw() {
  printf 'ed25519:%s' "$(sha256sum "$1" | cut -c1-32)"
}

# sha256 of "weave-record/1/<purpose>\n" || file bytes $2, printed as a digest string
digest_with_prefix() {
  { printf 'weave-record/1/%s\n' "$1"; cat "$2"; } | sha256sum | cut -d' ' -f1 | sed 's/^/sha256:/'
}
```

Why the trailing-LF stripping matters: the canonical file form allows exactly one trailing
LF after the canonical JSON bytes, and digests are computed **without** it
(specification §1.8). `strip_lf` removes exactly one LF, never more, so a file with two
trailing LFs (which is invalid) will still hash differently from the manifest entry and the
check will fail — correctly.

## 2. Step 1 — check the layout

An L0 container contains `manifest.json`, `signatures/manifest.sig.json` and
`records/<64 lowercase hex>.json` files. Directories/files not in the layout are an error,
**except** `readable/`, which is ignored entirely and never trusted.

```bash
(cd "$C" && find . -type f | sort)
```

Expect only `./manifest.json`, `./signatures/manifest.sig.json` and `./records/*.json`
(plus the optional `./previous/manifest.json`, `./blobs/sha256/<hex>` and `./readable/...`,
which you may ignore or check separately). Anything else — extra JSON in `records/`,
unknown files in `signatures/`, a missing manifest — means the container is not
structurally conformant. If the container is a zip, unzip it to an empty scratch directory
first; the zip must contain the same relative paths, no absolute paths, no `..`, no
symlinks and no encrypted entries. Zip-level checks are not covered by this manual
procedure in detail, but you can inspect the entry list before extracting:

```bash
unzip -l container.zip        # entry names; there must be no absolute paths, no "..", no symlinks
```

## 3. Step 2 — derive key ids from the declared keys

Every public key used by the container must be declared in a `weave.key.declared` record
(specification §9.1). The key id is **not** the SHA-256 of the key's text; it is
`"ed25519:" + first 32 lowercase hex characters of SHA-256(32 raw public-key bytes)`
(specification §2.5, correction v0.1.1). Anyone can derive it:

```bash
: > "$W/keys.tsv"     # key_id <TAB> path-to-pem

for f in "$C"/records/*.json; do
  [ "$(jq -r '.kind // empty' "$f")" = "weave.key.declared" ] || continue
  keyid=$(jq -r '.body.key' "$f")
  pub=$(jq -r '.body.public_key' "$f")
  b64url_decode "$pub" "$W/key.raw" || continue
  computed=$(keyid_of_raw "$W/key.raw")
  raw_to_pem "$W/key.raw" "$W/pub.pem"
  printf '%s\t%s\n' "$keyid" "$W/pub.pem" >> "$W/keys.tsv"
  printf 'record %s\n  declared: %s\n  computed: %s\n  %s\n' \
    "$(basename "$f")" "$keyid" "$computed" \
    "$( [ "$keyid" = "$computed" ] && echo MATCH || echo 'MISMATCH -> invalid (E_KEY_ID_MISMATCH)')"
done
cat "$W/keys.tsv"
```

The `records/*.json` files are already in content-addressed names; this step is read-only.

If the test-key inventory from this repository is available, cross-check the derivation
against the published raw public-key files (these bytes are exactly what the convention
above hashes):

```bash
for bin in vectors/keys/*.pub.bin; do
  base=${bin%.pub.bin}
  want=$(jq -r '.key_id' "$base.json")
  got=$(keyid_of_raw "$bin")
  printf '%-40s %s  %s\n' "$(basename "$bin")" "$got" \
    "$( [ "$got" = "$want" ] && echo MATCH || echo MISMATCH )"
done
```

The vectors' test keys are deliberately published; they are test material only.

## 4. Step 3 — the manifest digest

The manifest digest binds the exact bytes of `manifest.json` (specification §2.4):

```
manifest_digest = "sha256:" + hex( SHA-256( "weave-record/1/manifest-digest\n" || canonical manifest bytes ) )
```

Compute it and compare with the `digest` member of `signatures/manifest.sig.json`:

```bash
strip_lf "$C/manifest.json" "$W/manifest.canon"
MANIFEST_DIGEST=$(digest_with_prefix manifest-digest "$W/manifest.canon")
echo "computed manifest digest: $MANIFEST_DIGEST"

declare_sig_digest=$(jq -r '.digest' "$C/signatures/manifest.sig.json")
echo "declared in signatures/manifest.sig.json: $declare_sig_digest"
[ "$MANIFEST_DIGEST" = "$declare_sig_digest" ] \
  && echo "manifest digest MATCH" \
  || echo "manifest digest MISMATCH -> invalid (E_MANIFEST_DIGEST)"
```

Also inspect the manifest itself with your eyes: `format` must be `weave-record/1`,
`manifest_version` must be `1`, `level` must be `L0` (for this procedure), `records` must be
sorted by digest with unique digests, `previous_manifest` is `null` or a digest,
`chain` must be absent or `null` for L0, and `blobs` (if present) lists each blob with
digest and size:

```bash
jq '{format, manifest_version, level, created_at, origin,
     previous_manifest, chain, record_count: (.records|length),
     sorted_by_digest: ([.records[].digest] == ([.records[].digest]|sort)),
     unique_digests: (([.records[].digest]|unique|length) == (.records|length)),
     blobs: (.blobs // [])}' "$C/manifest.json"
```

## 5. Step 4 — the manifest signature

The manifest signature message is ASCII `weave-record/1/manifest\n` followed by the
**digest string** (including the `sha256:` prefix) — not the raw 32 hash bytes
(specification §2.4). The signature is base64url 64 bytes and lives in
`signatures/manifest.sig.json.signatures[]`; the entry names the signer key id.

```bash
{ printf 'weave-record/1/manifest\n'; printf '%s' "$MANIFEST_DIGEST"; } > "$W/manifest.msg"

n_sigs=$(jq '.signatures | length' "$C/signatures/manifest.sig.json")
echo "manifest signatures: $n_sigs"
if [ "$n_sigs" -gt 0 ]; then
for i in $(seq 0 $((n_sigs - 1))); do
  key=$(jq -r ".signatures[$i].key" "$C/signatures/manifest.sig.json")
  value=$(jq -r ".signatures[$i].value" "$C/signatures/manifest.sig.json")
  pem=$(awk -F '\t' -v k="$key" '$1==k {print $2; found=1} END {exit !found}' "$W/keys.tsv") || {
    echo "signer $key: no declaration found in the container (unverifiable: E_KEY_UNKNOWN)"; continue; }
  b64url_decode "$value" "$W/manifest.sig.bin" || continue
  printf 'signer %s: ' "$key"
  "$OSSL" pkeyutl -verify -pubin -inkey "$pem" -rawin \
    -in "$W/manifest.msg" -sigfile "$W/manifest.sig.bin" \
    && echo "SIGNATURE VALID" || echo "SIGNATURE INVALID -> invalid (E_MANIFEST_SIG_INVALID)"
done
fi
```

`openssl pkeyutl -verify` prints `Signature Verified Successfully` and exits 0 on success;
the shell `&&`/`||` turns that into the verdict word above.

The signature list must be non-empty (1–16 entries), sorted by `key` and unique; an empty
list means the container is unsigned (invalid, `E_MANIFEST_UNSIGNED`). Check the ordering
quickly:

```bash
jq -r '[.signatures[].key] == ([.signatures[].key]|sort)' "$C/signatures/manifest.sig.json"
jq -r '[.signatures[].key] | length == (unique | length)' "$C/signatures/manifest.sig.json"
```

## 6. Step 5 — every record: file name, digest, and signature

For every entry in `manifest.records`, the file `records/<hex>.json` must exist, must be in
canonical form, and its **record digest** must equal both the entry digest and the file
name (specification §2.2, §11.6). The record digest is computed over the canonical JSON
with the **top-level `sigs` member removed** — signatures never cover themselves. For a
`weave.erased` placeholder there is no `sigs` member, so it is hashed as it stands.

Two helper commands:

```bash
# canonical bytes of record $1 without the top-level sigs member -> file $2
record_signing_bytes() {
  strip_lf "$1" "$W/rec.raw"
  if jq -e 'has("sigs")' "$1" >/dev/null 2>&1; then
    jq -cS 'del(.sigs)' "$1" > "$W/rec.nosigs"
    strip_lf "$W/rec.nosigs" "$2"
  else
    cp "$W/rec.raw" "$2"
  fi
}

# record digest of record file $1 -> prints digest string
record_digest() {
  record_signing_bytes "$1" "$W/rec.signing"
  digest_with_prefix digest "$W/rec.signing"
}
```

`jq -cS` writes compact JSON with keys sorted and no whitespace: that is the WR-CJ byte form
for records whose member names are ASCII (as all envelope member names are) and whose known
values contain no characters needing different escaping. If a body uses exotic member names
there is a small theoretical difference in UTF-16-vs-UTF-8 key ordering; the digest
comparison below then fails loudly instead of passing silently, and you should defer to a
conforming verifier rather than trusting a hand-edited value. A record that does not hash to
its manifest entry is not evidence that the record was tampered with *by itself* — it may
also mean your JSON tool re-serialised differently; re-check with a different canonicalising
tool before drawing a conclusion.

Now the loop. It also verifies each record signature against the declared key, using the
same message construction as §2.3:

```bash
while IFS=$'\t' read -r digest id kind; do
  hex=${digest#sha256:}
  f="$C/records/$hex.json"
  [ -f "$f" ] || { echo "MISSING record file: $hex.json -> invalid (E_MANIFEST_RECORD_MISSING)"; continue; }
  computed=$(record_digest "$f")
  if [ "$computed" = "$digest" ]; then digest_ok=MATCH; else digest_ok=MISMATCH; fi

  # optional canonical-form sanity check: the file text must be the canonical bytes (+1 LF)
  jq -cS . "$f" > "$W/rec.canon"
  strip_lf "$W/rec.canon" "$W/rec.canon.raw"
  strip_lf "$f" "$W/rec.file.raw"
  cmp -s "$W/rec.file.raw" "$W/rec.canon.raw" && canon_ok=canonical || canon_ok="NOT-CANONICAL -> invalid (E_JSON_NOT_CANONICAL)"

  echo "record $id ($kind)"
  echo "  file: records/$hex.json"
  echo "  digest $computed"
  echo "  manifest entry $digest -> $digest_ok"
  echo "  file form: $canon_ok"

  # record signatures (per-record signing is required for accepted records and for the
  # authorisation/key/consent/erasure kinds; other records may be container-signed only)
  n_sigs=$(jq '.sigs | length // 0' "$f")
  if [ "$n_sigs" -eq 0 ]; then
    echo "  sigs: none (container signature covers this record; required only if accepted)"
    continue
  fi
  { printf 'weave-record/1/sig\n'; printf '%s' "$computed"; } > "$W/record.msg"
  for i in $(seq 0 $((n_sigs - 1))); do
    rkey=$(jq -r ".sigs[$i].key" "$f")
    rvalue=$(jq -r ".sigs[$i].value" "$f")
    rpem=$(awk -F '\t' -v k="$rkey" '$1==k {print $2; found=1} END {exit !found}' "$W/keys.tsv") || {
      echo "  sig[$i] $rkey: no declaration found (unverifiable: E_KEY_UNKNOWN)"; continue; }
    b64url_decode "$rvalue" "$W/record.sig.bin" || continue
    printf '  sig[%s] %s: ' "$i" "$rkey"
    "$OSSL" pkeyutl -verify -pubin -inkey "$rpem" -rawin \
      -in "$W/record.msg" -sigfile "$W/record.sig.bin" \
      && echo "SIGNATURE VALID" || echo "SIGNATURE INVALID -> invalid (E_SIG_INVALID)"
  done
done < <(jq -r '.records[] | [.digest, .id, .kind] | @tsv' "$C/manifest.json")
```

Notes for reading the output:

- A record whose `kind` is `weave.erased` is a placeholder; its verdict is `erased`, not
  `valid`, and its `digest` member is the **original** record digest, not its own. Its
  `attestation` reference should point at the `weave.erasure` record; if that record is in
  this container, its `body.erased.digest` must equal the placeholder's `digest` member and
  its own digest must be the placeholder's `attestation.digest` (specification §10.3).
- `sigs` must be sorted by key id ascending and unique; a quick check per record:
  `jq -r '[.sigs[].key] == ([.sigs[].key]|sort)' "$f"`.
- Every listed record file must exist and every file in `records/` must be listed. Check the
  directory listing against the manifest digests:

```bash
comm -3 \
  <(jq -r '.records[].digest' "$C/manifest.json" | sed 's/^sha256://' | sort) \
  <(cd "$C/records" && ls *.json | sed 's/\.json$//' | sort)
```

An empty output means the manifest and the `records/` directory agree exactly.

## 7. Step 6 — the previous-manifest chain

If `manifest.previous_manifest` is `null`, `previous/` must be absent or empty. If it is
not null, `previous/manifest.json` must exist, must be canonical, and its manifest digest
(hash of `"weave-record/1/manifest-digest\n" || canonical bytes`) must equal
`previous_manifest.digest` (specification §11.5):

```bash
prev=$(jq -r '.previous_manifest.digest // "null"' "$C/manifest.json")
echo "previous_manifest: $prev"
if [ "$prev" = "null" ]; then
  if [ -d "$C/previous" ] && [ -n "$(ls -A "$C/previous" 2>/dev/null)" ]; then
    echo "previous/ present although previous_manifest is null -> invalid (E_MANIFEST_CHAIN_UNEXPECTED)"
  else
    echo "no previous manifest (first container in the chain)"
  fi
else
  if [ ! -f "$C/previous/manifest.json" ]; then
    echo "previous/manifest.json missing -> invalid (E_MANIFEST_CHAIN_MISSING)"
  else
    strip_lf "$C/previous/manifest.json" "$W/prev.canon"
    PREV=$(digest_with_prefix manifest-digest "$W/prev.canon")
    echo "computed previous manifest digest: $PREV"
    [ "$PREV" = "$prev" ] && echo "chain MATCH" || echo "chain MISMATCH -> invalid (E_MANIFEST_CHAIN)"
  fi
fi
```

The chain is a chain over manifest **digests**; this procedure does not re-verify the
previous manifest's signature (that is allowed, and it is reported as
`N_PREVIOUS_SIG_UNVERIFIED` when a verifier does not). If the previous container is
available, repeat steps 3–5 on it to check its signature too.

## 8. What an L0 container proves, and what it does not

**It proves** (given the checks above pass):

1. `manifest.json` has exactly the bytes signed by a holder of the manifest signing key;
   the signature message binds the manifest digest, and the manifest digest binds every
   byte of the manifest.
2. Each record file in `records/` hashes to the digest listed in that signed manifest, so
   the record bytes have not changed since the manifest was signed (assuming no SHA-256
   collision).
3. For records that carry their own signatures: those signatures verify over the record
   digest. For records required to be per-record signed (accepted records; key, grant,
   consent and erasure records), the absence of a valid signature is a defect.
4. Declared keys have self-consistent key ids: the id is the SHA-256 of the raw 32-byte
   public key (first 32 hex), and the self-signature verifies.

**It does not prove** (these are the honest limits, also reported as `limitations` by a
verifier):

1. **Identity.** A signature proves possession of the private key behind a key id. Key
   declarations are self-asserted (trust on first use); nothing says the key belongs to a
   particular human or organisation. There is no CA here.
2. **Time.** `created_at`, `recorded_at` and `occurred_at` are claims. L0 has no external
   timestamp, so "this container was signed no later than X" cannot be proven. A verifier
   must not treat claimed times as trusted.
3. **Existence before export / completeness.** L0 has no internal chain head. Records could
   have been omitted before signing, and no offline check can show that the manifest lists
   every record the source system ever had. Rollback and truncation of a chain of containers
   are only detectable via `previous_manifest` links plus external anchors (L1/L2).
4. **Deletion.** A record that was deleted before export leaves no trace; erasure is only
   visible when it is done through the placeholder+attestation mechanism.
5. **Truth.** Signatures prove who signed which bytes, not that the content is true.
6. **Key validity at signing time.** Revocations or expiry windows only constrain a
   signature if the relevant key-lifecycle records are in the verification context and the
   claimed times are used as claims. A compromised key's signatures might be forgeries;
   detecting that needs timestamp evidence (L2).
7. **Strict Ed25519 profile.** The `openssl pkeyutl` verification used here performs the
   RFC 8032 equation but is not guaranteed to reject small-order public keys or
   non-canonical points the way the `weave-record/1` profile requires (§3 of the
   specification). Manual verification is therefore *necessary but not sufficient* for the
   strict profile; use a conforming verifier for the strict checks, or verify the public
   keys' provenance out of band.
8. **L1/L2 claims.** An L0 container has no chain head and no timestamp. If the manifest
   claims L1 or L2, this procedure does not verify those claims; at most, L1 chain head and
   chain positions are claims, and L2 timestamps require RFC 3161 + a trust anchor.
9. **Agent authorisation beyond context.** Whether an agent was authorised is only as good
   as the `weave.grant` records and key declarations present in the verification context.

## 9. Worked example on `vectors/container/l0-minimal/`

The case `vectors/container/l0-minimal/` contains `expected.json` (the vector's expected
verdict: `valid`, one record, `level_verified: "L0"`) and a `container/` directory that is
the export itself. Its complete file inventory is:

| file (relative to the case dir) | bytes |
|---|---|
| `expected.json` | 635 |
| `container/manifest.json` | 365 |
| `container/records/e08150ddc301c6ebd26f577a4e71a060b5a575ff287a6fe25bbbc62da664379d.json` | 634 |
| `container/signatures/manifest.sig.json` | 306 |

The container is self-contained: the only record is the `weave.key.declared` record of the
signing key (human-1, key id `ed25519:333f90d1d9dfb653b78df977b9b13ff2`), so the manual
procedure needs no external keyset and no verifier. Every JSON file ends with exactly one
LF, which is what makes the trailing-LF rule of §1.8 matter for the worked example.

The worked example runs the procedure above end to end with a single shell script, so the
command/actual-output pairing is unambiguous. The script defines the same helpers as §1 and
performs steps 1–7 on `C=vectors/container/l0-minimal/container`, printing one line per check and
exiting nonzero if any check fails.

```bash
#!/usr/bin/env bash
# Manual L0 verification transcript for weave-record/1.
# Run from the repository root.
# Uses only sha256sum, OpenSSL 3.x, jq (JSON viewer) and POSIX base utilities.
set -u
C=vectors/container/l0-minimal/container
OSSL=${OSSL:-openssl}
if ! "$OSSL" version 2>/dev/null | grep -q '^OpenSSL 3\.'; then
  echo "error: \$OSSL must be OpenSSL 3.x (LibreSSL cannot verify Ed25519 raw signatures)" >&2
  exit 2
fi
echo "using: $("$OSSL" version)"
W=$(mktemp -d "${TMPDIR:-/tmp}/weave-l0.XXXXXX")
rc=0

fail() { echo "FAIL: $*"; rc=1; }

strip_lf() {
  n=$(wc -c < "$1")
  if [ "$n" -gt 0 ] && [ "$(tail -c 1 "$1" | od -An -tx1 | tr -d ' \n')" = "0a" ]; then n=$((n-1)); fi
  head -c "$n" "$1" > "$2"
}
b64url_decode() {
  s=$1
  case "$s" in *[!A-Za-z0-9_-]*) return 1;; esac
  b64=$(printf '%s' "$s" | tr '_-' '/+')
  case $(( ${#b64} % 4 )) in 2) b64="${b64}==";; 3) b64="${b64}=";; 0) :;; *) return 1;; esac
  printf '%s' "$b64" | "$OSSL" base64 -d -A -out "$2"
}
raw_to_pem() {
  printf '302a300506032b6570032100' | xxd -r -p > "$W/pub.der"
  cat "$1" >> "$W/pub.der"
  "$OSSL" pkey -pubin -inform DER -in "$W/pub.der" -out "$2"
}
keyid_of_raw() { printf 'ed25519:%s' "$(sha256sum "$1" | cut -c1-32)"; }
digest_with_prefix() {
  { printf 'weave-record/1/%s\n' "$1"; cat "$2"; } | sha256sum | cut -d' ' -f1 | sed 's/^/sha256:/'
}
record_signing_bytes() {
  strip_lf "$1" "$W/rec.raw"
  if jq -e 'has("sigs")' "$1" >/dev/null 2>&1; then
    jq -cS 'del(.sigs)' "$1" > "$W/rec.nosigs"
    strip_lf "$W/rec.nosigs" "$2"
  else
    cp "$W/rec.raw" "$2"
  fi
}
record_digest() {
  record_signing_bytes "$1" "$W/rec.signing"
  digest_with_prefix digest "$W/rec.signing"
}

echo "== 1. layout =="
(cd "$C" && find . -type f | sort) | tee "$W/layout.txt"

echo "== 2. declared keys and key ids =="
: > "$W/keys.tsv"
for f in "$C"/records/*.json; do
  [ "$(jq -r '.kind // empty' "$f")" = "weave.key.declared" ] || continue
  keyid=$(jq -r '.body.key' "$f")
  b64url_decode "$(jq -r '.body.public_key' "$f")" "$W/key.raw" || { fail "bad public_key in $f"; continue; }
  computed=$(keyid_of_raw "$W/key.raw")
  raw_to_pem "$W/key.raw" "$W/pub.pem"
  printf '%s\t%s\n' "$keyid" "$W/pub.pem" >> "$W/keys.tsv"
  echo "declared=$keyid computed=$computed $([ "$keyid" = "$computed" ] && echo MATCH || { fail "key id mismatch"; echo MISMATCH; })"
done
if compgen -G "vectors/keys/*.pub.bin" >/dev/null; then
  for bin in vectors/keys/*.pub.bin; do
    base=${bin%.pub.bin}
    want=$(jq -r '.key_id' "$base.json"); got=$(keyid_of_raw "$bin")
    echo "$(basename "$bin"): $got $([ "$got" = "$want" ] && echo MATCH || { fail "test-key id mismatch"; echo MISMATCH; })"
  done
fi

echo "== 3. manifest digest =="
strip_lf "$C/manifest.json" "$W/manifest.canon"
MANIFEST_DIGEST=$(digest_with_prefix manifest-digest "$W/manifest.canon")
DECLARED_MANIFEST_DIGEST=$(jq -r '.digest' "$C/signatures/manifest.sig.json")
echo "computed=$MANIFEST_DIGEST"
echo "declared=$DECLARED_MANIFEST_DIGEST"
[ "$MANIFEST_DIGEST" = "$DECLARED_MANIFEST_DIGEST" ] && echo "manifest digest MATCH" || fail "E_MANIFEST_DIGEST"

echo "== 4. manifest signature =="
{ printf 'weave-record/1/manifest\n'; printf '%s' "$MANIFEST_DIGEST"; } > "$W/manifest.msg"
n_sigs=$(jq '.signatures | length' "$C/signatures/manifest.sig.json")
echo "signatures=$n_sigs"
[ "$n_sigs" -ge 1 ] || fail "E_MANIFEST_UNSIGNED"
if [ "$n_sigs" -gt 0 ]; then
for i in $(seq 0 $((n_sigs - 1))); do
  key=$(jq -r ".signatures[$i].key" "$C/signatures/manifest.sig.json")
  value=$(jq -r ".signatures[$i].value" "$C/signatures/manifest.sig.json")
  pem=$(awk -F '\t' -v k="$key" '$1==k {print $2; found=1} END {exit !found}' "$W/keys.tsv") || { fail "E_KEY_UNKNOWN $key"; continue; }
  b64url_decode "$value" "$W/manifest.sig.bin" || { fail "E_MANIFEST_SCHEMA signature value"; continue; }
  if "$OSSL" pkeyutl -verify -pubin -inkey "$pem" -rawin -in "$W/manifest.msg" -sigfile "$W/manifest.sig.bin" >/dev/null 2>&1; then
    echo "signer=$key SIGNATURE VALID"
  else
    fail "E_MANIFEST_SIG_INVALID $key"
  fi
done
fi

echo "== 5. records =="
while IFS=$'\t' read -r digest id kind; do
  hex=${digest#sha256:}; f="$C/records/$hex.json"
  [ -f "$f" ] || { echo "record $id: MISSING $hex.json"; echo "FAIL: E_MANIFEST_RECORD_MISSING"; continue; }
  computed=$(record_digest "$f")
  jq -cS . "$f" > "$W/rec.canon"; strip_lf "$W/rec.canon" "$W/rec.canon.raw"; strip_lf "$f" "$W/rec.file.raw"
  canon=canonical; cmp -s "$W/rec.file.raw" "$W/rec.canon.raw" || canon="NOT-CANONICAL"
  digest_check=$([ "$computed" = "$digest" ] && echo MATCH || echo MISMATCH)
  echo "record id=$id kind=$kind file=records/$hex.json digest=$digest computed=$computed $digest_check form=$canon"
  [ "$digest_check" = MATCH ] || echo "FAIL: E_MANIFEST_RECORD_DIGEST $id"
  [ "$canon" = canonical ] || echo "FAIL: E_JSON_NOT_CANONICAL $id"
  n_sigs=$(jq '(.sigs // []) | length' "$f")
  if [ "$n_sigs" -gt 0 ]; then
    { printf 'weave-record/1/sig\n'; printf '%s' "$computed"; } > "$W/record.msg"
    for i in $(seq 0 $((n_sigs - 1))); do
      rkey=$(jq -r ".sigs[$i].key" "$f"); rvalue=$(jq -r ".sigs[$i].value" "$f")
      rpem=$(awk -F '\t' -v k="$rkey" '$1==k {print $2; found=1} END {exit !found}' "$W/keys.tsv") || { echo "record $id sig[$i] $rkey: E_KEY_UNKNOWN"; continue; }
      b64url_decode "$rvalue" "$W/record.sig.bin" || { echo "FAIL: E_ENV_SIG_VALUE $id"; continue; }
      if "$OSSL" pkeyutl -verify -pubin -inkey "$rpem" -rawin -in "$W/record.msg" -sigfile "$W/record.sig.bin" >/dev/null 2>&1; then
        echo "  record $id sig[$i] $rkey SIGNATURE VALID"
      else
        echo "  record $id sig[$i] $rkey SIGNATURE INVALID"; fail "E_SIG_INVALID $id"
      fi
    done
  fi
done < <(jq -r '.records[] | [.digest, .id, .kind] | @tsv' "$C/manifest.json")

echo "== 5b. manifest vs records/ directory =="
diff=$(comm -3 \
  <(jq -r '.records[].digest' "$C/manifest.json" | sed 's/^sha256://' | sort) \
  <(cd "$C/records" && ls *.json 2>/dev/null | sed 's/\.json$//' | sort))
if [ -z "$diff" ]; then echo "manifest and records/ agree exactly"; else echo "$diff"; echo "FAIL: E_MANIFEST_RECORD_EXTRA/MISSING"; fi
echo "== 5c. manifest ordering =="
jq -r '([.records[].digest] == ([.records[].digest]|sort))' "$C/manifest.json"
jq -r '([.records[].digest]|length) == ([.records[].digest]|unique|length)' "$C/manifest.json"

echo "== 6. previous manifest chain =="
prev=$(jq -r '.previous_manifest.digest // "null"' "$C/manifest.json")
echo "previous_manifest=$prev"
if [ "$prev" = "null" ]; then
  if [ -d "$C/previous" ] && [ -n "$(ls -A "$C/previous" 2>/dev/null)" ]; then fail "E_MANIFEST_CHAIN_UNEXPECTED"; else echo "first container: no previous manifest"; fi
else
  if [ ! -f "$C/previous/manifest.json" ]; then fail "E_MANIFEST_CHAIN_MISSING"
  else
    strip_lf "$C/previous/manifest.json" "$W/prev.canon"
    PREV=$(digest_with_prefix manifest-digest "$W/prev.canon")
    echo "computed=$PREV declared=$prev"
    [ "$PREV" = "$prev" ] && echo "chain MATCH" || fail "E_MANIFEST_CHAIN"
  fi
fi

echo "== result: $([ "$rc" -eq 0 ] && echo 'ALL CHECKS PASSED' || echo 'CHECKS FAILED') =="
rm -rf "$W"
exit "$rc"
```

### Worked-example output (actually executed)

The script above was saved to a scratch file (`verify-l0.sh`) and executed from the
repository root as
`OSSL=/opt/homebrew/opt/openssl@3/bin/openssl bash verify-l0.sh` (the macOS system
`openssl` is LibreSSL, which the version guard rejects). Its standard output and exit code
are reproduced verbatim below, followed by what each step demonstrated. The run is
deterministic: no network, no current time, no locale.

```text
$ OSSL=/opt/homebrew/opt/openssl@3/bin/openssl bash verify-l0.sh
using: OpenSSL 3.6.2 7 Apr 2026 (Library: OpenSSL 3.6.2 7 Apr 2026)
== 1. layout ==
./manifest.json
./records/e08150ddc301c6ebd26f577a4e71a060b5a575ff287a6fe25bbbc62da664379d.json
./signatures/manifest.sig.json
== 2. declared keys and key ids ==
declared=ed25519:333f90d1d9dfb653b78df977b9b13ff2 computed=ed25519:333f90d1d9dfb653b78df977b9b13ff2 MATCH
agent-1.pub.bin: ed25519:b6190071e4bbc7c82afc702fa9ffa6f5 MATCH
agent-2.pub.bin: ed25519:b5598e3317d83ed2ca322be01a8f3560 MATCH
device-1.pub.bin: ed25519:68abd4908f12bb09ced21e963235955a MATCH
human-1.pub.bin: ed25519:333f90d1d9dfb653b78df977b9b13ff2 MATCH
human-2.pub.bin: ed25519:928a1e1dbe45a5d298ce5f6b5ce2eabe MATCH
key-compromised.pub.bin: ed25519:d27f41bd9e715d0bf9b66ef71d09aa45 MATCH
key-new.pub.bin: ed25519:bbecfa632505e9d2df3c49b3e70e613f MATCH
key-old.pub.bin: ed25519:f6a2edbfb48098da6eb9018c5ee78673 MATCH
org-1.pub.bin: ed25519:34b835597028e3382ae0ee25dbe7e3e6 MATCH
program-1.pub.bin: ed25519:43a1178e89cdbd81a024c9e60369d4a7 MATCH
== 3. manifest digest ==
computed=sha256:d3ddf34c3b7371a3a4b4e29473590c5688124e6362b384f3911509b4494b09a3
declared=sha256:d3ddf34c3b7371a3a4b4e29473590c5688124e6362b384f3911509b4494b09a3
manifest digest MATCH
== 4. manifest signature ==
signatures=1
signer=ed25519:333f90d1d9dfb653b78df977b9b13ff2 SIGNATURE VALID
== 5. records ==
record id=key-declared-human-1 kind=weave.key.declared file=records/e08150ddc301c6ebd26f577a4e71a060b5a575ff287a6fe25bbbc62da664379d.json digest=sha256:e08150ddc301c6ebd26f577a4e71a060b5a575ff287a6fe25bbbc62da664379d computed=sha256:e08150ddc301c6ebd26f577a4e71a060b5a575ff287a6fe25bbbc62da664379d MATCH form=canonical
  record key-declared-human-1 sig[0] ed25519:333f90d1d9dfb653b78df977b9b13ff2 SIGNATURE VALID
== 5b. manifest vs records/ directory ==
manifest and records/ agree exactly
== 5c. manifest ordering ==
true
true
== 6. previous manifest chain ==
previous_manifest=null
first container: no previous manifest
== result: ALL CHECKS PASSED ==
```

**Exit code 0** — every check passed, agreeing with the vector's `expected.json`
(`verdict: "valid"`, `level_verified: "L0"`, `record_count: 1`,
`previous_manifest_digest: null`).

### What the worked example demonstrates

- **Step 2 — key ids from raw bytes.** The key id of the record's declared key is derived
  from the raw 32-byte public key (`SHA-256(raw)` first 32 hex) and matches
  `ed25519:333f90d1d9dfb653b78df977b9b13ff2`. The same derivation reproduces all ten
  published test-key ids in `vectors/keys/` (`*.pub.bin`), which are exactly the bytes the
  rule hashes.
- **Step 3 — manifest digest and the trailing LF.** The manifest digest is computed over
  the canonical manifest bytes with the optional single trailing LF removed, producing
  `sha256:d3ddf34c3b7371a3a4b4e29473590c5688124e6362b384f3911509b4494b09a3`, which equals
  the `digest` in `signatures/manifest.sig.json`. Hashing the file including its LF would
  give a different value and a digest mismatch.
- **Step 4 — manifest signature.** The Ed25519 signature verifies over the ASCII string
  `weave-record/1/manifest\n` followed by that digest string, using the public key from the
  in-container declaration (`Signature Verified Successfully`).
- **Step 5 — record digest and record signature.** The record's digest is computed over the
  parsed record with its top-level `sigs` member removed and then canonicalised; it equals
  `sha256:e08150ddc301c6ebd26f577a4e71a060b5a575ff287a6fe25bbbc62da664379d`, matching the
  manifest entry and the file name. The record is canonical on disk, and its self-signature
  verifies over `weave-record/1/sig\n` plus that digest.
- **Steps 5b/5c — manifest/records consistency.** The `records/` directory and
  `manifest.records` agree exactly (no missing or extra files), and the entries are sorted
  by digest and unique.
- **Step 6 — previous-manifest chain.** `previous_manifest` is `null` and `previous/` is
  absent, so this container is presented as the first in its chain; nothing further is
  claimed.
