#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Gate 4: cross-check the reference verifier against official external data.

This tool is **not** a vector generator and it does not use the repository's own
vectors.  It reads the unmodified third-party data under ``vectors/external/``
and checks that the reference verifier agrees with it, using the documented
stricter-profile mapping:

* RFC 8785 (JCS): the six official input/output pairs from
  ``cyberphone/json-canonicalization``.  The four integer-only documents must
  canonicalize to the official output bytes; the two documents containing
  floating-point numbers must be **rejected** (``E_JSON_NUMBER_NOT_INTEGER``)
  because ``weave-record/1`` only represents integers.
* RFC 8032 §7.1: all five Ed25519 test vectors must verify.
* Project Wycheproof Ed25519: ``valid`` -> accept, ``invalid`` -> reject, and
  ``acceptable`` is split by class (documented decision Q1): small-order public
  keys are rejected by the strict profile's small-order pre-checks, while
  mixed-order public keys whose signatures satisfy the cofactorless equation
  exactly are accepted (no subgroup-membership rule is part of the profile).

It also re-hashes every retrieved external file against the ``SOURCE.json`` /
``SHA256SUMS`` provenance committed with the data, so the cross-check cannot
silently run against different bytes.

Expected verifier API (``from hyphaweave_verify import canonical, ed25519``)::

    canonical.canonicalize(value) -> bytes
        Canonicalize an already-parsed JSON value under WR-CJ v1.  Must raise an
        exception carrying ``.code == "E_JSON_NUMBER_NOT_INTEGER"`` for a float
        (and ``E_JSON_NUMBER_RANGE`` for an out-of-range integer).

    ed25519.verify(public_key: bytes, message: bytes, signature: bytes) -> bool
        Verify a single-message, strict, cofactorless Ed25519 signature.  Any
        rejection (including the strict-profile pre-checks) returns ``False``;
        a raised exception carrying an ``E_SIG_*``/``E_KEY_*``/``E_ENV_SIG*``
        ``.code`` is also treated as rejection.

The verifier package may be importable or live under ``verifiers/python/`` (the
tool adds that directory to ``sys.path`` as a fallback; gate commands run from
the repository root with ``./.venv/bin/python tools/check_external.py``).

Exit status: 0 = all cross-checks passed; 1 = at least one mismatch; 2 = usage
or I/O error (missing data, verifier not importable, unsupported API).
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
EXTERNAL = REPO / "vectors" / "external"

REJECTION_CODE_PREFIXES = ("E_SIG_", "E_KEY_", "E_ENV_SIG")

# Hand-authored mapping from the RFC 8785 test-data README/PROVENANCE: which
# documents WR-CJ v1 accepts and which it must reject, and with which code.
RFC8785_PLAN: dict[str, str] = {
    "arrays": "canonical",
    "french": "canonical",
    "structures": "reject",
    "unicode": "canonical",
    "values": "reject",
    "weird": "canonical",
}
RFC8785_REJECT_CODES: dict[str, str] = {
    "structures": "E_JSON_NUMBER_NOT_INTEGER",
    "values": "E_JSON_NUMBER_NOT_INTEGER",
}

# The pinned Wycheproof file has exactly these outcome counts (recorded in
# PROVENANCE.md); a different count means the committed data changed.
WYCHEPROOF_EXPECTED_COUNTS = {
    "valid": 117,
    "invalid": 64,
    "acceptable/mixed-order": 21,
    "acceptable/small-order": 8,
}
# Documented stricter-profile decision (Q1, 2026-11-10): mixed-order public keys
# are NOT rejected; their signatures satisfy the cofactorless equation exactly,
# and the H0 profile does not add a prime-order-subgroup membership rule.  The
# small-order public keys are rejected by the mandatory eight-point pre-check.
WYCHEPROOF_ACCEPTABLE_ACCEPT_FLAGS = {"MixedOrderPublicKey"}

RFC8032_EXPECTED_TESTS = {"1", "2", "3", "1024", "SHA(abc)"}

_MISMATCHES: list[str] = []
_CHECKS: list[str] = []


class CheckFailure(Exception):
    """A cross-check could not run (usage/data problem, not a mismatch)."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def mismatch(message: str) -> None:
    _MISMATCHES.append(message)


def passed(message: str) -> None:
    _CHECKS.append(message)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CheckFailure("cannot read JSON %s: %s" % (path, exc)) from exc


# ---------------------------------------------------------------------------
# 1. External-data provenance integrity
# ---------------------------------------------------------------------------


def check_external_data() -> None:
    """Re-hash every retrieved official file and the SOURCE.json manifests."""
    if not EXTERNAL.is_dir():
        raise CheckFailure("missing external data directory: %s" % EXTERNAL)
    source_dirs = sorted(path for path in EXTERNAL.iterdir() if path.is_dir())
    if not source_dirs:
        raise CheckFailure("no external data sources under %s" % EXTERNAL)
    for source_dir in source_dirs:
        source_json = source_dir / "SOURCE.json"
        sums_file = source_dir / "SHA256SUMS"
        if not source_json.is_file() or not sums_file.is_file():
            mismatch("%s: missing SOURCE.json or SHA256SUMS" % source_dir.name)
            continue
        source = load_json(source_json)
        for key in ("name", "url", "commit", "sha256", "license", "retrieved_at"):
            if not isinstance(source.get(key), str) or not source[key]:
                mismatch(
                    "%s: SOURCE.json member %r missing or not a string"
                    % (source_dir.name, key)
                )
        files = source.get("files")
        if not isinstance(files, dict) or not files:
            mismatch("%s: SOURCE.json files map missing/empty" % source_dir.name)
            continue
        # Every listed file must exist and hash correctly.
        failed = 0
        for rel_path, expected in sorted(files.items()):
            path = source_dir / rel_path
            if not path.is_file():
                mismatch("%s: listed file missing: %s" % (source_dir.name, rel_path))
                failed += 1
                continue
            actual = sha256_file(path)
            if actual != expected:
                mismatch(
                    "%s: %s sha256 %s != recorded %s"
                    % (source_dir.name, rel_path, actual, expected)
                )
                failed += 1
        # The committed SHA256SUMS must equal the files map, and SOURCE.sha256
        # must be the hash of those manifest bytes.
        expected_sums = "".join(
            "%s  %s\n" % (files[rel], rel) for rel in sorted(files)
        )
        try:
            actual_sums = sums_file.read_text(encoding="utf-8")
        except OSError as exc:
            raise CheckFailure("cannot read %s: %s" % (sums_file, exc)) from exc
        if actual_sums != expected_sums:
            mismatch("%s: SHA256SUMS does not match SOURCE.json files" % source_dir.name)
            failed += 1
        actual_manifest_hash = sha256_hex(sums_file.read_bytes())
        if actual_manifest_hash != source.get("sha256"):
            mismatch(
                "%s: SOURCE.json sha256 %s != SHA256SUMS sha256 %s"
                % (source_dir.name, source.get("sha256"), actual_manifest_hash)
            )
            failed += 1
        if not failed:
            passed(
                "%s: %d file(s) hash-verified (commit %s)"
                % (source_dir.name, len(files), source.get("commit"))
            )


# ---------------------------------------------------------------------------
# 2. Verifier import and API adaptation
# ---------------------------------------------------------------------------


def import_verifier() -> tuple[Any, Any]:
    """Import ``hyphaweave_verify.canonical`` and ``.ed25519``.

    The package is imported from the environment when installed, else the
    in-repository package directory is added to ``sys.path``.
    """
    try:
        import hyphaweave_verify  # noqa: F401
    except ImportError:
        candidate = REPO / "verifiers" / "python"
        if candidate.is_dir() and str(candidate) not in sys.path:
            sys.path.insert(0, str(candidate))
        try:
            import hyphaweave_verify  # noqa: F401
        except ImportError as exc:
            raise CheckFailure(
                "cannot import hyphaweave_verify (install it or run from the "
                "repository root so verifiers/python is found): %s" % exc
            ) from exc
    try:
        from hyphaweave_verify import canonical, ed25519
    except ImportError as exc:
        raise CheckFailure(
            "hyphaweave_verify must expose the modules 'canonical' and "
            "'ed25519': %s" % exc
        ) from exc
    return canonical, ed25519


def resolve_canonicalize(canonical: Any):
    for name in (
        "canonicalize",
        "canonicalize_bytes",
        "canonical_bytes",
        "dumps_canonical",
    ):
        candidate = getattr(canonical, name, None)
        if callable(candidate):
            return candidate
    raise CheckFailure(
        "hyphaweave_verify.canonical must expose a value->bytes canonicalize "
        "function (expected 'canonicalize'); found: %s"
        % ", ".join(sorted(name for name in dir(canonical) if not name.startswith("_")))
    )


def error_code(exc: BaseException) -> str | None:
    code = getattr(exc, "code", None)
    return code if isinstance(code, str) else None


def to_bytes(result: Any) -> bytes:
    if isinstance(result, (bytes, bytearray)):
        return bytes(result)
    if isinstance(result, str):
        return result.encode("utf-8")
    raise CheckFailure(
        "canonicalize() returned %s, expected bytes or str" % type(result).__name__
    )


def canonicalize_value(fn, value: Any) -> tuple[bytes | None, str | None]:
    """Return (bytes, None) or (None, error code) for canonicalization."""
    try:
        return to_bytes(fn(value)), None
    except Exception as exc:  # noqa: BLE001 - the code is the classifier
        code = error_code(exc)
        if code is not None:
            return None, code
        raise CheckFailure(
            "canonicalize() raised an unsupported exception without .code: %r" % (exc,)
        ) from exc


def resolve_verify(ed25519: Any):
    for name in ("verify", "verify_signature", "verify_strict"):
        candidate = getattr(ed25519, name, None)
        if callable(candidate):
            return candidate
    raise CheckFailure(
        "hyphaweave_verify.ed25519 must expose verify(public_key, message, "
        "signature); found: %s"
        % ", ".join(sorted(name for name in dir(ed25519) if not name.startswith("_")))
    )


def verify_signature(fn, public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Call the strict verifier; ``False`` for any profile rejection."""
    try:
        result = fn(public_key, message, signature)
    except Exception as exc:  # noqa: BLE001 - mapped by code prefix
        code = error_code(exc)
        if code is not None and code.startswith(REJECTION_CODE_PREFIXES):
            return False
        raise CheckFailure(
            "ed25519.verify() raised an unsupported exception: %r" % (exc,)
        ) from exc
    if isinstance(result, bool):
        return result
    if isinstance(result, tuple) and result and isinstance(result[0], bool):
        return result[0]
    raise CheckFailure(
        "ed25519.verify() must return bool, got %s" % type(result).__name__
    )


# ---------------------------------------------------------------------------
# 3. RFC 8785 JCS pairs
# ---------------------------------------------------------------------------


def check_rfc8785(canonicalize) -> None:
    root = EXTERNAL / "rfc8785-jcs" / "testdata"
    inputs = root / "input"
    outputs = root / "output"
    outhexes = root / "outhex"
    if not inputs.is_dir() or not outputs.is_dir() or not outhexes.is_dir():
        raise CheckFailure("missing RFC 8785 testdata under %s" % root)
    names = sorted(RFC8785_PLAN)
    failures = 0
    for name in names:
        in_path = inputs / (name + ".json")
        out_path = outputs / (name + ".json")
        hex_path = outhexes / (name + ".txt")
        if not (in_path.is_file() and out_path.is_file() and hex_path.is_file()):
            mismatch("RFC8785 %s: missing input/output/outhex file" % name)
            failures += 1
            continue
        expected_bytes = out_path.read_bytes()
        # The outhex form must be the same expected canonical bytes.
        hex_tokens = hex_path.read_text(encoding="utf-8").split()
        try:
            hex_bytes = bytes(int(token, 16) for token in hex_tokens)
        except ValueError:
            mismatch("RFC8785 %s: outhex file is not hexadecimal" % name)
            failures += 1
            continue
        if hex_bytes != expected_bytes:
            mismatch(
                "RFC8785 %s: outhex bytes differ from output file bytes" % name
            )
            failures += 1
        # Parse the non-canonical input with the standard library; the value is
        # the input to the canonicalization function, not a canonical file.
        try:
            value = json.loads(in_path.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise CheckFailure("RFC8785 %s: input is not JSON: %s" % (name, exc)) from exc
        got, code = canonicalize_value(canonicalize, value)
        plan = RFC8785_PLAN[name]
        if plan == "canonical":
            if got is None:
                mismatch(
                    "RFC8785 %s: expected canonicalization, got rejection %s"
                    % (name, code)
                )
                failures += 1
            elif got != expected_bytes:
                mismatch(
                    "RFC8785 %s: canonical bytes differ from official output "
                    "(ours %d bytes, official %d bytes)"
                    % (name, len(got), len(expected_bytes))
                )
                failures += 1
        else:
            expected_code = RFC8785_REJECT_CODES[name]
            if got is not None:
                mismatch(
                    "RFC8785 %s: expected rejection %s, but the document was "
                    "canonicalized (%d bytes)" % (name, expected_code, len(got))
                )
                failures += 1
            elif code != expected_code:
                mismatch(
                    "RFC8785 %s: expected rejection code %s, got %s"
                    % (name, expected_code, code)
                )
                failures += 1
    if not failures:
        accepted = sum(1 for plan in RFC8785_PLAN.values() if plan == "canonical")
        passed(
            "RFC 8785 JCS pairs: %d/%d documents match (%d canonicalized exactly, "
            "%d rejected with E_JSON_NUMBER_NOT_INTEGER as documented)"
            % (len(names), len(names), accepted, len(names) - accepted)
        )


# ---------------------------------------------------------------------------
# 4. RFC 8032 §7.1 test vectors
# ---------------------------------------------------------------------------

_HEX_LINE = re.compile(r"^[0-9a-fA-F]+$")
_MESSAGE_LENGTH = re.compile(r"MESSAGE \(length (\d+) bytes?\)")


def _hex_lines(lines: list[str]) -> str:
    """Join the hexadecimal continuation lines of an RFC test-vector block."""
    text = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if _HEX_LINE.match(stripped):
            text.append(stripped)
        # Anything else is RFC page furniture (headers, footers, form feeds).
    return "".join(text).lower()


def parse_rfc8032_ed25519_vectors(text: str) -> list[dict[str, Any]]:
    start = re.search(r"^7\.1\.  Test Vectors for Ed25519\s*$", text, re.MULTILINE)
    end = re.search(r"^7\.2\.  Test Vectors for Ed25519ctx\s*$", text, re.MULTILINE)
    if start is None or end is None:
        raise CheckFailure(
            "RFC 8032 text: cannot locate §7.1 (Ed25519 test vectors) and §7.2"
        )
    section = text[start.end() : end.start()]
    chunks = re.split(r"-----TEST ", section)[1:]
    if not chunks:
        raise CheckFailure("RFC 8032 text: §7.1 contains no '-----TEST' blocks")
    vectors: list[dict[str, Any]] = []
    for chunk in chunks:
        title, _, body = chunk.partition("\n")
        title = title.strip()
        lines = body.split("\n")
        labels: dict[str, int] = {}
        message_index: int | None = None
        for index, line in enumerate(lines):
            stripped = line.strip()
            for label in ("ALGORITHM:", "SECRET KEY:", "PUBLIC KEY:", "SIGNATURE:"):
                if stripped.startswith(label):
                    labels.setdefault(label, index)
            if stripped.startswith("MESSAGE (length"):
                message_index = index if message_index is None else message_index
        needed = ("SECRET KEY:", "PUBLIC KEY:", "SIGNATURE:")
        if message_index is None or any(label not in labels for label in needed):
            raise CheckFailure(
                "RFC 8032 text: TEST %s is missing a labelled block" % title
            )
        if not (
            labels["SECRET KEY:"]
            < labels["PUBLIC KEY:"]
            < message_index
            < labels["SIGNATURE:"]
        ):
            raise CheckFailure(
                "RFC 8032 text: TEST %s blocks are out of order" % title
            )
        secret_hex = _hex_lines(lines[labels["SECRET KEY:"] + 1 : labels["PUBLIC KEY:"]])
        public_hex = _hex_lines(lines[labels["PUBLIC KEY:"] + 1 : message_index])
        message_hex = _hex_lines(lines[message_index + 1 : labels["SIGNATURE:"]])
        signature_hex = _hex_lines(lines[labels["SIGNATURE:"] + 1 :])
        declared = _MESSAGE_LENGTH.search(body)
        vector = {
            "name": title,
            "secret_key": bytes.fromhex(secret_hex),
            "public_key": bytes.fromhex(public_hex),
            "message": bytes.fromhex(message_hex),
            "signature": bytes.fromhex(signature_hex),
            "declared_message_length": int(declared.group(1)) if declared else None,
        }
        if len(vector["secret_key"]) != 32 or len(vector["public_key"]) != 32:
            raise CheckFailure(
                "RFC 8032 text: TEST %s key material is not 32 bytes" % title
            )
        if len(vector["signature"]) != 64:
            raise CheckFailure(
                "RFC 8032 text: TEST %s signature is not 64 bytes" % title
            )
        if vector["declared_message_length"] != len(vector["message"]):
            raise CheckFailure(
                "RFC 8032 text: TEST %s message length %d != declared %s"
                % (title, len(vector["message"]), vector["declared_message_length"])
            )
        vectors.append(vector)
    names = {vector["name"] for vector in vectors}
    if names != RFC8032_EXPECTED_TESTS:
        raise CheckFailure(
            "RFC 8032 text: expected test names %s, found %s"
            % (sorted(RFC8032_EXPECTED_TESTS), sorted(names))
        )
    return vectors


def check_rfc8032(verify) -> None:
    path = EXTERNAL / "rfc8032" / "rfc8032.txt"
    if not path.is_file():
        raise CheckFailure("missing RFC 8032 text: %s" % path)
    vectors = parse_rfc8032_ed25519_vectors(path.read_text(encoding="utf-8"))
    failures = 0
    for vector in vectors:
        if not verify_signature(
            verify, vector["public_key"], vector["message"], vector["signature"]
        ):
            mismatch("RFC8032 TEST %s: signature was rejected" % vector["name"])
            failures += 1
    if not failures:
        passed("RFC 8032 §7.1: %d/%d Ed25519 signatures verify" % (len(vectors), len(vectors)))


# ---------------------------------------------------------------------------
# 5. Project Wycheproof Ed25519 vectors
# ---------------------------------------------------------------------------


def _wycheproof_bucket(result: str, flags: set[str]) -> str:
    """Classify one Wycheproof test into the documented outcome class."""
    if result in ("valid", "invalid"):
        return result
    if result == "acceptable":
        if "MixedOrderPublicKey" in flags:
            return "acceptable/mixed-order"
        if "SmallOrderPublicKey" in flags:
            return "acceptable/small-order"
        return "acceptable/other"
    return "unknown"


def _wycheproof_expected_accept(result: str, flags: set[str]) -> bool | None:
    """Expected accept/reject for one test under the documented mapping."""
    if result == "valid":
        return True
    if result == "invalid":
        return False
    if result == "acceptable":
        return bool(flags & WYCHEPROOF_ACCEPTABLE_ACCEPT_FLAGS)
    return None


def check_wycheproof(verify) -> None:
    path = EXTERNAL / "wycheproof" / "testvectors_v1" / "ed25519_test.json"
    if not path.is_file():
        raise CheckFailure("missing Wycheproof file: %s" % path)
    document = load_json(path)
    if document.get("algorithm") != "EDDSA":
        mismatch(
            "Wycheproof: expected algorithm EDDSA, got %r" % document.get("algorithm")
        )
    groups = document.get("testGroups")
    if not isinstance(groups, list):
        raise CheckFailure("Wycheproof: testGroups missing")
    counts: dict[str, int] = {}
    computed_outcomes: dict[int, str] = {}
    total = 0
    failures = 0
    for group in groups:
        try:
            public_key = bytes.fromhex(group["publicKey"]["pk"])
            tests = group["tests"]
        except (KeyError, TypeError, ValueError) as exc:
            raise CheckFailure("Wycheproof: malformed test group: %s" % exc) from exc
        for test in tests:
            total += 1
            try:
                result = test["result"]
                message = bytes.fromhex(test["msg"])
                signature = bytes.fromhex(test["sig"])
                test_id = test["tcId"]
            except (KeyError, TypeError, ValueError) as exc:
                raise CheckFailure(
                    "Wycheproof: malformed test near tcId %r: %s"
                    % (test.get("tcId") if isinstance(test, dict) else None, exc)
                ) from exc
            flags = set(test.get("flags") or ())
            bucket = _wycheproof_bucket(result, flags)
            counts[bucket] = counts.get(bucket, 0) + 1
            accepted = verify_signature(verify, public_key, message, signature)
            expected_accept = _wycheproof_expected_accept(result, flags)
            if expected_accept is not None:
                computed_outcomes[test_id] = "accept" if expected_accept else "reject"
            if expected_accept is None:
                mismatch(
                    "Wycheproof tcId %s: unclassified result %r flags %r"
                    % (test_id, result, sorted(flags))
                )
                failures += 1
                continue
            if accepted != expected_accept:
                mismatch(
                    "Wycheproof tcId %s: result %r expected %s, verifier %s"
                    % (
                        test_id,
                        result,
                        "accept" if expected_accept else "reject",
                        "accepted" if accepted else "rejected",
                    )
                )
                failures += 1
    if counts != WYCHEPROOF_EXPECTED_COUNTS:
        mismatch(
            "Wycheproof: outcome counts %s != pinned %s"
            % (counts, WYCHEPROOF_EXPECTED_COUNTS)
        )
        failures += 1
    if document.get("numberOfTests") != total:
        mismatch(
            "Wycheproof: numberOfTests %r != %d read"
            % (document.get("numberOfTests"), total)
        )
        failures += 1
    # The committed per-vector outcome table must agree with the rule above.
    outcomes_path = path.parent.parent / "EXPECTED_OUTCOMES.json"
    try:
        table = load_json(outcomes_path)
    except CheckFailure:
        mismatch("Wycheproof: missing expected-outcome table %s" % outcomes_path.name)
        failures += 1
        table = None
    if table is not None:
        rows = table.get("outcomes")
        if not isinstance(rows, list) or len(rows) != total:
            mismatch(
                "Wycheproof: expected-outcome table has %s rows, data has %d tests"
                % (len(rows) if isinstance(rows, list) else "?", total)
            )
            failures += 1
        else:
            table_outcomes: dict[int, str] = {}
            for row in rows:
                try:
                    table_outcomes[row["tcId"]] = row["expected"]
                except (KeyError, TypeError):
                    mismatch("Wycheproof: malformed expected-outcome row %r" % (row,))
                    failures += 1
                    continue
            for test_id, expected in sorted(computed_outcomes.items()):
                if table_outcomes.get(test_id) != expected:
                    mismatch(
                        "Wycheproof tcId %s: expected-outcome table says %r, rule "
                        "says %r" % (test_id, table_outcomes.get(test_id), expected)
                    )
                    failures += 1
            if set(table_outcomes) != set(computed_outcomes):
                mismatch(
                    "Wycheproof: expected-outcome table tcIds do not match the data"
                )
                failures += 1
    if not failures:
        passed(
            "Wycheproof Ed25519: %d/%d outcomes match (%d valid accepted, %d "
            "acceptable/mixed-order accepted, %d invalid rejected, %d "
            "acceptable/small-order rejected)"
            % (
                total,
                total,
                counts.get("valid", 0),
                counts.get("acceptable/mixed-order", 0),
                counts.get("invalid", 0),
                counts.get("acceptable/small-order", 0),
            )
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] in ("-h", "--help"):
        print(__doc__.strip())
        return 0
    if argv:
        print("usage: tools/check_external.py", file=sys.stderr)
        return 2
    try:
        check_external_data()
        canonical, ed25519 = import_verifier()
        canonicalize = resolve_canonicalize(canonical)
        verify = resolve_verify(ed25519)
        check_rfc8785(canonicalize)
        check_rfc8032(verify)
        check_wycheproof(verify)
    except CheckFailure as exc:
        print("check_external: ERROR: %s" % exc, file=sys.stderr)
        return 2
    for line in _CHECKS:
        print("ok   " + line)
    if _MISMATCHES:
        for line in _MISMATCHES:
            print("FAIL " + line)
        print(
            "check_external: FAIL (%d mismatch(es), %d check(s) passed)"
            % (len(_MISMATCHES), len(_CHECKS))
        )
        return 1
    print("check_external: PASS (%d checks)" % len(_CHECKS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
