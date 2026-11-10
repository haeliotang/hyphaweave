#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Validate the JSON examples embedded in the specification (CI gate).

The specification is the authority for H1 implementers, so every *complete*
record example in it must actually verify, and every manifest/reference example
must satisfy its JSON Schema.  This tool extracts the fenced ```` ```json ````
blocks from ``spec/weave-record-1.md`` and ``spec/kinds/*.md`` and classifies
each block:

* ``standalone-record`` (default for a complete record envelope) -- must pass
  ``hyphaweave-verify record <file> --keys vectors/keys/keyset``:
  verdict ``valid`` (or ``erased`` for a ``weave.erased`` placeholder) and
  exit code 0.  The block bytes are handed to the verifier unchanged, so a
  pretty-printed or non-canonical example is rejected with
  ``E_JSON_NOT_CANONICAL``; examples must be flush-left single-value JSON.
* ``manifest`` -- a ``manifest.json`` value validated against
  ``schemas/manifest.json``; an attestation-shaped block (``digest`` +
  ``format`` + ``signatures``) is validated against
  ``schemas/manifest.json#/$defs/manifest_attestation``.
* ``reference`` -- a reference object validated against ``schemas/ref.json``.
* ``container-context`` -- depends on other records (e.g. a grant-revocation
  or consent-revocation record, or an erasure cross-check).  Skipped and
  counted; the reason is printed once in the summary.
* ``illustrative`` -- shape-only fragment; skipped and counted.

Classification is explicit when a marker comment is present::

    <!-- spec-example: standalone-record -->
    ```json
    {...}
    ```

Accepted markers: ``standalone-record``, ``manifest``, ``reference``,
``container-context``, ``illustrative``.  The marker must be the last non-blank
line before the opening fence.  A block without a marker is classified from its
shape (complete record envelope / manifest / attestation / reference), and any
other unmarked block is treated as ``illustrative`` and skipped.

The verification command is resolved from ``WEAVE_VERIFY_CMD`` when set, then
``.venv/bin/hyphaweave-verify`` and ``hyphaweave-verify`` on ``PATH``, and
finally ``python -m hyphaweave_verify.cli``.  The verifier is never imported,
so this gate keeps working while the implementation is revised.

Usage::

    ./.venv/bin/python tools/check_spec_examples.py

Exit code 0 means every example passed (or was explicitly skipped as
non-executable); 1 means at least one example failed or a block could not be
classified.  Output is deterministic: no temporary paths, no wall clock.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
SPEC_MAIN = REPO_ROOT / "spec" / "weave-record-1.md"
KINDS_DIR = REPO_ROOT / "spec" / "kinds"
SCHEMAS_DIR = REPO_ROOT / "schemas"
KEYSET_DIR = REPO_ROOT / "vectors" / "keys" / "keyset"

FENCE_OPEN_RE = re.compile(r"^\s*```json\s*$")
FENCE_CLOSE_RE = re.compile(r"^\s*```\s*$")
MARKER_RE = re.compile(r"^<!--\s*spec-example:\s*([a-z][a-z0-9-]*)\s*-->\s*$")

KNOWN_MARKERS = (
    "standalone-record",
    "manifest",
    "reference",
    "container-context",
    "illustrative",
)

# Fixed textual order for the deterministic summary.
CATEGORY_ORDER = (
    "standalone-record",
    "manifest",
    "reference",
    "container-context",
    "illustrative",
)

MAX_VERIFIER_SECONDS = 120


class Block:
    """One fenced JSON block found in a specification markdown file."""

    def __init__(self, path: Path, line: int, content: str, marker: str | None):
        self.path = path
        self.line = line  # 1-based line number of the opening fence
        self.content = content
        self.marker = marker
        self.category = "illustrative"
        self.value: Any = None
        self.parse_error: str | None = None
        self.status = "pending"
        self.detail = ""
        self.marker_error: str | None = None

    @property
    def where(self) -> str:
        try:
            shown = self.path.relative_to(REPO_ROOT).as_posix()
        except ValueError:
            shown = self.path.name
        return "%s:%d" % (shown, self.line)


def _read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def _find_marker(lines: list[str], fence_index: int) -> str | None:
    """Return the marker on the last non-blank line before the fence, if any."""
    index = fence_index - 1
    while index >= 0 and lines[index].strip() == "":
        index -= 1
    if index < 0:
        return None
    match = MARKER_RE.match(lines[index].strip())
    return match.group(1) if match else None


def extract_blocks(path: Path) -> list[Block]:
    """Extract every fenced ```json block from *path* in document order."""
    lines = _read_lines(path)
    blocks: list[Block] = []
    index = 0
    while index < len(lines):
        if not FENCE_OPEN_RE.match(lines[index]):
            index += 1
            continue
        marker = _find_marker(lines, index)
        content_lines: list[str] = []
        cursor = index + 1
        while cursor < len(lines):
            if FENCE_CLOSE_RE.match(lines[cursor]):
                break
            content_lines.append(lines[cursor])
            cursor += 1
        content = "\n".join(content_lines) + "\n"
        blocks.append(Block(path, index + 1, content, marker))
        index = cursor + 1
    return blocks


def _has_keys(value: Any, keys: tuple[str, ...]) -> bool:
    return isinstance(value, dict) and all(name in value for name in keys)


def _looks_like_record(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and value.get("format") == "weave-record/1"
        and "kind" in value
        and "id" in value
        and "origin" in value
    )


def _looks_like_manifest(value: Any) -> bool:
    return isinstance(value, dict) and "manifest_version" in value


def _looks_like_attestation(value: Any) -> bool:
    # The revision-1 attestation always carries ``timestamps`` (possibly empty); a
    # block missing it is still routed to the attestation schema so the schema
    # reports the missing member instead of silently treating it as illustrative.
    return _has_keys(value, ("digest", "format", "signatures"))


def _looks_like_reference(value: Any) -> bool:
    return (
        _has_keys(value, ("origin", "id", "digest"))
        and "format" not in value
        and "manifest_version" not in value
    )


def classify(block: Block) -> None:
    """Decide how *block* is validated and record structural problems."""
    try:
        block.value = json.loads(block.content)
    except json.JSONDecodeError as error:
        block.parse_error = (
            "not a single JSON value (%s at line %d, column %d)"
            % (error.msg, error.lineno, error.colno)
        )
        block.value = None

    if block.marker is not None:
        if block.marker not in KNOWN_MARKERS:
            block.category = "illustrative"
            block.marker_error = "unknown marker %r (accepted: %s)" % (
                block.marker,
                ", ".join(KNOWN_MARKERS),
            )
            return
        block.category = block.marker
        if block.parse_error is not None:
            return
        # Cross-check that the marker agrees with the block shape.
        if block.category == "standalone-record" and not _looks_like_record(block.value):
            block.parse_error = (
                "marked standalone-record but the block is not a complete record "
                "envelope (needs format, kind, id, origin)"
            )
        elif block.category == "manifest" and not (
            _looks_like_manifest(block.value) or _looks_like_attestation(block.value)
        ):
            block.parse_error = (
                "marked manifest but the block is neither a manifest object nor a "
                "manifest attestation (digest/format/signatures/timestamps)"
            )
        elif block.category == "reference" and not _looks_like_reference(block.value):
            block.parse_error = (
                "marked reference but the block is not a reference object "
                "(origin, id, digest)"
            )
        return

    # No marker: infer from shape.  Anything else is an illustrative fragment.
    if block.parse_error is not None:
        block.category = "illustrative"
    elif _looks_like_record(block.value):
        block.category = "standalone-record"
    elif _looks_like_manifest(block.value):
        block.category = "manifest"
    elif _looks_like_attestation(block.value):
        block.category = "manifest"
    elif _looks_like_reference(block.value):
        block.category = "reference"
    else:
        block.category = "illustrative"


# ---------------------------------------------------------------------------
# Schema validation (local, network-free registry)
# ---------------------------------------------------------------------------


class SchemaSet:
    """The checked-in schemas plus a local registry resolving relative $refs."""

    def __init__(self, schemas_dir: Path) -> None:
        self.schemas_dir = schemas_dir
        self.problems: list[str] = []
        self.registry: Any = None
        self._validators: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        try:
            from jsonschema import Draft202012Validator
            from referencing import Registry, Resource
            from referencing.jsonschema import DRAFT202012
        except Exception as error:  # pragma: no cover - environment issue
            self.problems.append(
                "cannot import jsonschema/referencing (%s); required for manifest/"
                "reference example validation" % error
            )
            return
        if not self.schemas_dir.is_dir():
            self.problems.append("schemas directory not found: schemas/")
            return
        resources = []
        for path in sorted(self.schemas_dir.rglob("*.json")):
            if not path.is_file():
                continue
            try:
                schema = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                self.problems.append(
                    "schemas/%s is not valid JSON: %s"
                    % (path.relative_to(self.schemas_dir).as_posix(), error)
                )
                continue
            schema_id = schema.get("$id")
            if not isinstance(schema_id, str):
                self.problems.append(
                    "schemas/%s has no $id"
                    % path.relative_to(self.schemas_dir).as_posix()
                )
                continue
            resources.append(
                (schema_id, Resource.from_contents(schema, default_specification=DRAFT202012))
            )
        if self.problems:
            return
        self.registry = Registry().with_resources(resources)
        self._validator_factory = Draft202012Validator

    def validator(self, name: str) -> Any:
        """Validator for the top-level schema *name* (e.g. ``manifest.json``)."""
        if self.registry is None:
            raise RuntimeError("schema registry is unavailable")
        if name not in self._validators:
            path = self.schemas_dir / name
            if not path.is_file():
                raise RuntimeError("schema file schemas/%s not found" % name)
            schema = json.loads(path.read_text(encoding="utf-8"))
            self._validators[name] = self._validator_factory(schema, registry=self.registry)
        return self._validators[name]

    def attestation_validator(self) -> Any:
        if self.registry is None:
            raise RuntimeError("schema registry is unavailable")
        if "attestation" not in self._validators:
            manifest = json.loads(
                (self.schemas_dir / "manifest.json").read_text(encoding="utf-8")
            )
            manifest_id = manifest.get("$id", "")
            if not isinstance(manifest_id, str):
                raise RuntimeError("schemas/manifest.json has no $id")
            reference = {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$ref": manifest_id + "#/$defs/manifest_attestation",
            }
            self._validators["attestation"] = self._validator_factory(
                reference, registry=self.registry
            )
        return self._validators["attestation"]

    def validate(self, name: str, value: Any, *, attestation: bool = False) -> list[str]:
        try:
            if attestation:
                validator = self.attestation_validator()
            else:
                validator = self.validator(name)
            errors = sorted(validator.iter_errors(value), key=lambda error: list(error.path))
        except RuntimeError as error:
            return [str(error)]
        except Exception as error:  # pragma: no cover - defensive
            return ["schema validation error: %s" % error]
        messages = []
        for error in errors[:5]:
            location = "/".join(str(part) for part in error.absolute_path) or "<root>"
            messages.append("%s: %s" % (location, error.message))
        if len(errors) > 5:
            messages.append("... %d more schema error(s)" % (len(errors) - 5))
        return messages


# ---------------------------------------------------------------------------
# Record verification (subprocess only; the verifier is never imported)
# ---------------------------------------------------------------------------


def resolve_verifier() -> list[str]:
    override = os.environ.get("WEAVE_VERIFY_CMD", "").strip()
    if override:
        return shlex.split(override)
    venv_bin = REPO_ROOT / ".venv" / "bin" / "hyphaweave-verify"
    if venv_bin.is_file():
        return [str(venv_bin)]
    found = shutil.which("hyphaweave-verify")
    if found:
        return [found]
    return [sys.executable, "-m", "hyphaweave_verify.cli"]


class RecordVerifier:
    """Runs the reference CLI on one record; caches the resolved command."""

    def __init__(self, keyset: Path) -> None:
        self.keyset = keyset
        self.command: list[str] | None = None
        self.environment_problem: str | None = None

    def _prepare(self) -> bool:
        if self.command is not None:
            return True
        if not self.keyset.is_dir():
            self.environment_problem = "keyset directory vectors/keys/keyset not found"
            return False
        command = resolve_verifier()
        try:
            probe = subprocess.run(
                command + ["--version"],
                cwd=str(REPO_ROOT),
                capture_output=True,
                text=True,
                timeout=MAX_VERIFIER_SECONDS,
            )
        except (OSError, subprocess.SubprocessError) as error:
            self.environment_problem = (
                "cannot run the reference verifier (%s); build the verifier or set "
                "WEAVE_VERIFY_CMD" % error
            )
            return False
        if probe.returncode != 0:
            self.environment_problem = (
                "reference verifier is not usable (--version exit %d): %s"
                % (probe.returncode, _excerpt(probe.stderr))
            )
            return False
        self.command = command
        return True

    def verify(self, content: str) -> tuple[str | None, list[str], str | None]:
        """Return (verdict, errors, problem) for one record example."""
        if not self._prepare():
            return None, [], self.environment_problem
        assert self.command is not None
        temporary = tempfile.mkdtemp(prefix="weave-spec-example-")
        try:
            example_path = Path(temporary) / "example.json"
            example_path.write_bytes(content.encode("utf-8"))
            completed = subprocess.run(
                self.command
                + ["record", str(example_path), "--keys", str(self.keyset), "--json"],
                cwd=str(REPO_ROOT),
                capture_output=True,
                text=True,
                timeout=MAX_VERIFIER_SECONDS,
            )
        except (OSError, subprocess.SubprocessError) as error:
            return None, [], "cannot run the reference verifier (%s)" % error
        finally:
            shutil.rmtree(temporary, ignore_errors=True)

        report: dict[str, Any] | None = None
        try:
            report = json.loads(completed.stdout)
        except json.JSONDecodeError:
            report = None
        if completed.returncode == 2 or report is None:
            problem = completed.stderr.strip() or completed.stdout.strip()
            return (
                None,
                [],
                "usage/IO error from the reference verifier (exit %d): %s"
                % (completed.returncode, _excerpt(problem)),
            )
        records = report.get("records") or [{}]
        errors = [
            code
            for record in records
            for code in (record.get("errors") or [])
        ] + list(report.get("errors") or [])
        verdict = report.get("verdict")
        return verdict, sorted(set(errors)), None


def _excerpt(text: str, limit: int = 300) -> str:
    text = " ".join(text.split())
    text = text.replace(str(REPO_ROOT) + "/", "").replace(str(REPO_ROOT), ".")
    text = re.sub(r"/tmp/weave-spec-example-[A-Za-z0-9_]+", "<tmp>", text)
    return text[:limit] + ("..." if len(text) > limit else "")


def process_block(block: Block, schemas: SchemaSet, verifier: RecordVerifier) -> None:
    classify(block)

    if block.marker_error is not None:
        block.status = "failed"
        block.detail = block.marker_error
        return

    if block.category in ("illustrative", "container-context"):
        if block.category == "illustrative" and block.marker is None and block.parse_error:
            # An unmarked, non-JSON fragment could hide a broken example; require
            # either valid JSON or an explicit marker/text fence.
            block.status = "failed"
            block.detail = block.parse_error + (
                " [hint: use a ```text fence for pseudo-JSON, or mark the block "
                "<!-- spec-example: illustrative -->]"
            )
            return
        block.status = "skipped"
        block.detail = (
            "illustrative fragment; not executable"
            if block.category == "illustrative"
            else "depends on other records in a container (cross-record context); "
            "not executed here"
        )
        return

    if block.parse_error is not None:
        block.status = "failed"
        block.detail = block.parse_error
        return

    assert block.value is not None
    if block.category == "standalone-record":
        verdict, errors, problem = verifier.verify(block.content)
        if problem is not None:
            block.status = "failed"
            block.detail = (
                "reference verifier unavailable (see environment failure above)"
                if verifier.environment_problem == problem
                else problem
            )
            return
        kind = block.value.get("kind") if isinstance(block.value, dict) else None
        expected_verdict = "erased" if kind == "weave.erased" else "valid"
        if verdict != expected_verdict:
            block.status = "failed"
            block.detail = "expected verdict %r, got %r%s" % (
                expected_verdict,
                verdict,
                (" (errors: %s)" % ", ".join(errors)) if errors else "",
            )
            if errors and "E_JSON_NOT_CANONICAL" in errors:
                block.detail += (
                    " [hint: examples must be flush-left WR-CJ canonical bytes: "
                    "sorted keys, no insignificant whitespace, at most one trailing LF]"
                )
            return
        block.status = "verified"
        block.detail = "verdict %s" % verdict
        return

    if block.category == "manifest":
        is_attestation = not _looks_like_manifest(block.value)
        problems = schemas.validate(
            "manifest.json", block.value, attestation=is_attestation
        )
        if problems:
            block.status = "failed"
            block.detail = "schema error(s): " + "; ".join(problems)
        else:
            block.status = "verified"
            block.detail = (
                "manifest attestation schema"
                if is_attestation
                else "manifest schema"
            )
        return

    if block.category == "reference":
        problems = schemas.validate("ref.json", block.value)
        if problems:
            block.status = "failed"
            block.detail = "schema error(s): " + "; ".join(problems)
        else:
            block.status = "verified"
            block.detail = "reference schema"
        return

    block.status = "failed"
    block.detail = "internal error: unhandled category %r" % block.category


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def spec_files() -> list[Path]:
    files: list[Path] = []
    if SPEC_MAIN.is_file():
        files.append(SPEC_MAIN)
    if KINDS_DIR.is_dir():
        files.extend(sorted(KINDS_DIR.glob("*.md")))
    return files


def main(argv: list[str]) -> int:
    arguments = [argument for argument in argv if argument]
    if any(argument in ("-h", "--help") for argument in arguments):
        sys.stdout.write(
            "usage: python tools/check_spec_examples.py [--verbose]\n"
            "Validates fenced json examples in spec/weave-record-1.md and "
            "spec/kinds/*.md.\n"
        )
        return 0
    verbose = "--verbose" in arguments
    unexpected = [argument for argument in arguments if argument != "--verbose"]
    if unexpected:
        sys.stderr.write("unexpected argument(s): %s\n" % " ".join(unexpected))
        return 1

    schemas = SchemaSet(SCHEMAS_DIR)
    verifier = RecordVerifier(KEYSET_DIR)
    files = spec_files()
    blocks: list[Block] = []
    for path in files:
        blocks.extend(extract_blocks(path))

    environment_problems: list[str] = []
    if not files:
        environment_problems.append(
            "no specification files found (spec/weave-record-1.md and spec/kinds/*.md)"
        )
    for problem in schemas.problems:
        environment_problems.append(problem)
    if not KEYSET_DIR.is_dir():
        environment_problems.append(
            "keyset directory vectors/keys/keyset not found"
        )
    if not blocks and files:
        environment_problems.append(
            "no fenced json blocks found; the extraction gate would be vacuous"
        )

    for block in blocks:
        process_block(block, schemas, verifier)
    if verifier.environment_problem and verifier.environment_problem not in environment_problems:
        environment_problems.append(verifier.environment_problem)

    failures = [block for block in blocks if block.status == "failed"]
    verified = [block for block in blocks if block.status == "verified"]
    skipped = [block for block in blocks if block.status == "skipped"]
    counts = {category: 0 for category in CATEGORY_ORDER}
    for block in blocks:
        counts[block.category] = counts.get(block.category, 0) + 1

    lines: list[str] = []
    lines.append(
        "spec examples: %d file(s), %d json block(s)" % (len(files), len(blocks))
    )
    lines.append(
        "  categories: "
        + ", ".join(
            "%s=%d" % (category, counts[category]) for category in CATEGORY_ORDER
        )
    )
    lines.append(
        "  verified: %d (record=%d erased=%d manifest=%d reference=%d)"
        % (
            len(verified),
            sum(
                1
                for block in verified
                if block.category == "standalone-record"
                and block.detail == "verdict valid"
            ),
            sum(
                1
                for block in verified
                if block.category == "standalone-record"
                and block.detail == "verdict erased"
            ),
            sum(1 for block in verified if block.category == "manifest"),
            sum(1 for block in verified if block.category == "reference"),
        )
    )
    lines.append(
        "  skipped: %d (container-context=%d illustrative=%d)"
        % (
            len(skipped),
            counts.get("container-context", 0),
            counts.get("illustrative", 0),
        )
    )
    lines.append("  failures: %d" % (len(failures) + len(environment_problems)))
    for problem in environment_problems:
        lines.append("FAIL environment: " + problem)
    for block in failures:
        lines.append(
            "FAIL %s %s: %s" % (block.where, block.category, block.detail)
        )
    if verbose:
        for block in blocks:
            lines.append(
                "  %s %s [%s] %s: %s"
                % (
                    block.status.upper(),
                    block.where,
                    block.category,
                    block.marker or "auto",
                    block.detail,
                )
            )
    lines.append(
        "result: %s" % ("OK" if not failures and not environment_problems else "FAILED")
    )

    sys.stdout.write("\n".join(lines) + "\n")
    return 0 if not failures and not environment_problems else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
