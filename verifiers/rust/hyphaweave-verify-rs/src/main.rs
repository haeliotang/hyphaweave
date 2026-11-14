// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! `hyphaweave-verify-rs`: command-line front end for the independent
//! `weave-record/1` verifier (§14.1, §14.7, §14.8).
//!
//! The binary parses the command surface, reads the operator inputs through
//! the library's bounded, `lstat`-first readers (§14.1, W4, X3), prints
//! exactly one report on standard output and maps it to the §14.8 exit codes.
//! Usage and I/O errors go to standard error with exit code 2 and print no
//! report. The test-only check-skip hook (§14.7) is reachable only through the
//! explicit global `--test-hooks` switch: `WEAVE_VERIFY_SKIP_CHECKS` is read
//! only when that switch is present.

use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use hyphaweave_verify::error_codes::is_error_code;
use hyphaweave_verify::{
    operator, report_json, verify_container, verify_record, verify_vectors, Report, UsageError,
    VerifyOptions, VERIFIER_VERSION,
};

const USAGE: &str = "\
hyphaweave-verify-rs -- independent verifier for weave-record/1

Usage:
  hyphaweave-verify-rs [--test-hooks] record <file> [--keys <dir>] [--json]
  hyphaweave-verify-rs [--test-hooks] container <dir|zip> [--keys <dir>] [--tsa-trust <pem>] [--previous <dir|zip>] [--json]
  hyphaweave-verify-rs [--test-hooks] vectors <dir> [--tsa-trust <pem>] [--json]
  hyphaweave-verify-rs --help | --version

Options:
  --test-hooks          enable the test-only check-skip hook (reads
                        WEAVE_VERIFY_SKIP_CHECKS); never a production setting
  --keys <dir>          local trust input: top-level *.json records
  --tsa-trust <pem>     L2 RFC 3161 trust anchors (PEM certificates); for the
                        vectors command a default for cases without their own
  --previous <dir|zip>  the previous container in the chain (only its manifest
                        and attestation are read)
  --json                accepted for compatibility; JSON is the only output

Exit codes:
  0  valid (or erased for a placeholder record), or every vector case matched
  1  invalid, unverifiable, or at least one vector case mismatched
  2  usage or I/O error (no report on standard output)
  3  a report was produced but the test hook disabled at least one check
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
    let mut argv: Vec<OsString> = env::args_os().skip(1).collect();
    // `--test-hooks` is a global option that precedes the subcommand (§14.1).
    let test_hooks = argv.first().is_some_and(|first| first == "--test-hooks");
    if test_hooks {
        argv.remove(0);
    }
    let Some(first) = argv.first().cloned() else {
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
        .ok_or_else(|| UsageError("command name is not valid UTF-8".to_owned()))?
        .to_owned();
    let mut positionals: Vec<PathBuf> = Vec::new();
    let mut keys: Option<PathBuf> = None;
    let mut tsa_trust: Option<PathBuf> = None;
    let mut previous: Option<PathBuf> = None;
    let tokens = &argv[1..];
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
                let slot = match token {
                    "--keys" => &mut keys,
                    "--tsa-trust" => &mut tsa_trust,
                    _ => &mut previous,
                };
                if slot.is_some() {
                    return Err(UsageError(format!("{token} given more than once")));
                }
                *slot = Some(PathBuf::from(value));
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
    let command = match command_name.as_str() {
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
    let mut options = VerifyOptions::new();
    if test_hooks {
        options.skip_checks = skip_checks()?;
    }
    // §14.1 (W4): operator inputs are read and checked before verification.
    if let Some(directory) = &keys {
        options.keyset = operator::load_keyset(directory)?;
    }
    if let Some(anchors) = &tsa_trust {
        options.tsa_trust = vec![operator::read_tsa_trust(anchors)?];
    }
    if let Some(previous) = &previous {
        options.previous = Some(operator::open_previous(previous)?);
    }
    let report = match command {
        Command::Record(file) => {
            let bytes = operator::read_record_target(&file)?;
            verify_record(&bytes, &options)?
        }
        Command::Container(target) => {
            let input = operator::open_container(&target)?;
            verify_container(input, &options)?
        }
        Command::Vectors(directory) => verify_vectors(&directory, &options)?,
    };
    print_stdout(&report_json::to_bytes(&report))?;
    Ok(exit_code(&report))
}

/// §14.8: `3` when the test hook disabled a check (above `0`/`1`, below `2`);
/// otherwise `valid`/`erased` is `0` and everything else `1`.
fn exit_code(report: &Report) -> ExitCode {
    if !report.checks_disabled.is_empty() {
        return ExitCode::from(3);
    }
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

/// §14.7 token parsing: split on ASCII commas, trim ASCII whitespace, ignore
/// empty tokens, match registered `E_*` codes exactly, collapse duplicates. An
/// unregistered token is a usage error naming the sorted unknown tokens.
fn skip_checks() -> Result<BTreeSet<String>, UsageError> {
    let value = match env::var(SKIP_CHECKS_ENV) {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => return Ok(BTreeSet::new()),
        Err(env::VarError::NotUnicode(_)) => {
            return Err(UsageError(format!(
                "{SKIP_CHECKS_ENV} is not valid Unicode"
            )))
        }
    };
    let tokens: BTreeSet<String> = value
        .split(',')
        .map(|token| token.trim_matches(|character: char| character.is_ascii_whitespace()))
        .filter(|token| !token.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    let unknown: Vec<&str> = tokens
        .iter()
        .map(String::as_str)
        .filter(|token| !(token.starts_with("E_") && is_error_code(token)))
        .collect();
    if !unknown.is_empty() {
        return Err(UsageError(format!(
            "{SKIP_CHECKS_ENV}: unknown check codes: {}",
            unknown.join(", ")
        )));
    }
    Ok(tokens)
}

fn print_stdout(bytes: &[u8]) -> Result<(), UsageError> {
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(bytes)
        .and_then(|()| stdout.flush())
        .map_err(|error| UsageError(format!("cannot write standard output: {error}")))
}
