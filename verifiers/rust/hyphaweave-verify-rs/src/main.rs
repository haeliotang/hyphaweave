// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! `hyphaweave-verify-rs`: command-line front end for the independent
//! `weave-record/1` verifier (§14.1, §14.8).
//!
//! The binary is deliberately small: it parses the command surface, performs
//! the I/O the library does not do (file and directory reads, the test-only
//! `WEAVE_VERIFY_SKIP_CHECKS` hook), prints exactly one report on standard
//! output and maps the report verdict to the §14.8 exit codes. Usage and I/O
//! errors go to standard error with exit code 2 and print no report.

use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use hyphaweave_verify::{
    report_json, verify_container, verify_record, verify_vectors, ContainerInput, Report,
    UsageError, VerifyOptions, VERIFIER_VERSION,
};

const USAGE: &str = "\
hyphaweave-verify-rs -- independent verifier for weave-record/1

Usage:
  hyphaweave-verify-rs record <file> [--keys <dir>] [--json]
  hyphaweave-verify-rs container <dir|zip> [--keys <dir>] [--tsa-trust <pem>] [--previous <dir>] [--json]
  hyphaweave-verify-rs vectors <dir> [--tsa-trust <pem>] [--json]
  hyphaweave-verify-rs --help | --version

Options:
  --keys <dir>        local trust input: top-level *.json key-declaration records
  --tsa-trust <pem>   L2 RFC 3161 trust anchors (PEM certificates); for the
                      vectors command these are defaults for every case and a
                      case's own --tsa-trust argument overrides them
  --previous <dir>    additionally require the previous container's manifest digest
  --json              accepted for compatibility; JSON is the default and only output

Environment:
  WEAVE_VERIFY_SKIP_CHECKS   test-only, comma-separated error codes whose checks
                             are treated as passed; echoed in the report

Exit codes:
  0  valid (or erased for a placeholder record), or every vector case matched
  1  invalid, unverifiable, or at least one vector case mismatched
  2  usage or I/O error (no report on standard output)
";

const SKIP_CHECKS_ENV: &str = "WEAVE_VERIFY_SKIP_CHECKS";

enum Command {
    Record(PathBuf),
    Container(PathBuf),
    Vectors(PathBuf),
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(UsageError(message)) => {
            eprintln!("hyphaweave-verify-rs: {message}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode, UsageError> {
    let mut argv = env::args_os().skip(1);
    let Some(first) = argv.next() else {
        return Err(UsageError("missing command (try --help)".to_owned()));
    };
    if first == "--help" || first == "-h" {
        print_stdout(USAGE.as_bytes())?;
        return Ok(ExitCode::SUCCESS);
    }
    if first == "--version" || first == "-V" {
        print_stdout(format!("hyphaweave-verify-rs {VERIFIER_VERSION}\n").as_bytes())?;
        return Ok(ExitCode::SUCCESS);
    }
    let command_name = first
        .to_str()
        .ok_or_else(|| UsageError("command name is not valid UTF-8".to_owned()))?;
    let mut positionals: Vec<PathBuf> = Vec::new();
    let mut keys: Option<PathBuf> = None;
    let mut tsa_trust: Option<PathBuf> = None;
    let mut previous: Option<PathBuf> = None;
    let tokens: Vec<OsString> = argv.collect();
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index]
            .to_str()
            .ok_or_else(|| UsageError("argument is not valid UTF-8".to_owned()))?;
        match token {
            "--json" => index += 1,
            "--keys" | "--tsa-trust" | "--previous" => {
                let value = tokens
                    .get(index + 1)
                    .ok_or_else(|| UsageError(format!("{token} requires a value")))?;
                let value = PathBuf::from(value);
                match token {
                    "--keys" => keys = Some(value),
                    "--tsa-trust" => tsa_trust = Some(value),
                    _ => previous = Some(value),
                }
                index += 2;
            }
            other if other.starts_with('-') => {
                return Err(UsageError(format!("unknown option {other}")));
            }
            other => {
                positionals.push(PathBuf::from(other));
                index += 1;
            }
        }
    }
    let command = match command_name {
        "record" => {
            reject_options(
                "record",
                &[("--tsa-trust", &tsa_trust), ("--previous", &previous)],
            )?;
            Command::Record(single_target("record", &positionals)?)
        }
        "container" => Command::Container(single_target("container", &positionals)?),
        "vectors" => {
            reject_options("vectors", &[("--keys", &keys), ("--previous", &previous)])?;
            Command::Vectors(single_target("vectors", &positionals)?)
        }
        other => return Err(UsageError(format!("unknown command {other} (try --help)"))),
    };
    let mut options = VerifyOptions {
        skip_checks: skip_checks()?,
        ..VerifyOptions::new()
    };
    let report = match command {
        Command::Record(file) => {
            if let Some(directory) = &keys {
                options.keyset = load_keyset(directory)?;
            }
            let bytes = read_bytes(&file)?;
            verify_record(&bytes, &options)?
        }
        Command::Container(target) => {
            if let Some(directory) = &keys {
                options.keyset = load_keyset(directory)?;
            }
            if let Some(anchors) = &tsa_trust {
                options.tsa_trust = vec![read_bytes(anchors)?];
            }
            if let Some(previous) = &previous {
                options.previous = Some(container_input(previous)?);
            }
            verify_container(container_input(&target)?, &options)?
        }
        Command::Vectors(directory) => {
            if let Some(anchors) = &tsa_trust {
                options.tsa_trust = vec![read_bytes(anchors)?];
            }
            verify_vectors(&directory, &options)?
        }
    };
    print_stdout(&report_json::to_bytes(&report))?;
    Ok(exit_code(&report))
}

/// §14.8: `valid` and `erased` are success; everything else is failure. For the
/// `vectors` target the top-level verdict is `valid` exactly when every case
/// matched.
fn exit_code(report: &Report) -> ExitCode {
    match report.verdict.as_str() {
        "valid" | "erased" => ExitCode::SUCCESS,
        _ => ExitCode::from(1),
    }
}

fn single_target(command: &str, positionals: &[PathBuf]) -> Result<PathBuf, UsageError> {
    match positionals {
        [target] => Ok(target.clone()),
        [] => Err(UsageError(format!("{command} requires a target"))),
        _ => Err(UsageError(format!("{command} takes exactly one target"))),
    }
}

fn reject_options(command: &str, options: &[(&str, &Option<PathBuf>)]) -> Result<(), UsageError> {
    for (name, value) in options {
        if value.is_some() {
            return Err(UsageError(format!("{command} does not accept {name}")));
        }
    }
    Ok(())
}

/// True when the path is a container directory; any other path is read as zip
/// bytes (§14.1 `container <dir|zip>`).
fn container_input(path: &Path) -> Result<ContainerInput, UsageError> {
    if path.is_dir() {
        Ok(ContainerInput::Directory(path.to_path_buf()))
    } else {
        Ok(ContainerInput::Zip(read_bytes(path)?))
    }
}

fn read_bytes(path: &Path) -> Result<Vec<u8>, UsageError> {
    fs::read(path).map_err(|error| UsageError(format!("{}: {error}", path.display())))
}

/// Loads the top-level `*.json` files of `directory` in sorted file-name order
/// (§14.1 local trust input).
fn load_keyset(directory: &Path) -> Result<Vec<Vec<u8>>, UsageError> {
    let entries = fs::read_dir(directory)
        .map_err(|error| UsageError(format!("{}: {error}", directory.display())))?;
    let mut files: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let entry =
            entry.map_err(|error| UsageError(format!("{}: {error}", directory.display())))?;
        let path = entry.path();
        if path.is_file() && path.extension() == Some(std::ffi::OsStr::new("json")) {
            files.push(path);
        }
    }
    files.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
    let mut records = Vec::with_capacity(files.len());
    for path in files {
        records.push(read_bytes(&path)?);
    }
    Ok(records)
}

/// Reads the test-only §14.7 skip hook. Unset or empty means normal operation;
/// tokens are trimmed and empty tokens are ignored.
fn skip_checks() -> Result<BTreeSet<String>, UsageError> {
    match env::var(SKIP_CHECKS_ENV) {
        Ok(value) => Ok(value
            .split(',')
            .map(str::trim)
            .filter(|token| !token.is_empty())
            .map(ToOwned::to_owned)
            .collect()),
        Err(env::VarError::NotPresent) => Ok(BTreeSet::new()),
        Err(env::VarError::NotUnicode(_)) => Err(UsageError(format!(
            "{SKIP_CHECKS_ENV} is not valid Unicode"
        ))),
    }
}

fn print_stdout(bytes: &[u8]) -> Result<(), UsageError> {
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(bytes)
        .and_then(|()| stdout.flush())
        .map_err(|error| UsageError(format!("cannot write standard output: {error}")))
}
