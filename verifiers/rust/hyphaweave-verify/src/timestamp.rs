// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! RFC 3161 timestamp receipts and the renewal chain of §12.
//!
//! This module is implemented from the specification only (§12.2 check table,
//! §12.3 trust anchors, §12.4 renewal chain, §9.4 compromise rescue). It parses
//! DER `TimeStampResp` / CMS `SignedData` / X.509 structures with the pure-Rust
//! RustCrypto crates and verifies the CMS signature under the fixed algorithm
//! allowlist. No network access and no certificate-chain building (H0 compares
//! the leaf certificate against the supplied anchors exactly).

use std::collections::BTreeMap;

use crate::error_codes::Code;
use crate::options::UsageError;
use crate::time::Timestamp;

/// State of one timestamp receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptState {
    /// Checks 1–15 of §12.2 passed (including a matching trust anchor).
    Verified,
    /// Checks 1–14 passed but check 15 (trust anchor) did not match.
    PresentUnverified,
    /// At least one of checks 1–14 failed.
    Invalid,
}

/// Outcome of verifying one receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptOutcome {
    /// Receipt state.
    pub state: ReceiptState,
    /// `genTime` converted to a timestamp literal (millisecond precision).
    pub gen_time: Option<Timestamp>,
    /// `accuracy` converted to integer microseconds (absent = 0).
    pub accuracy_us: i64,
    /// First failing §12.2 check, when [`ReceiptState::Invalid`].
    pub error: Option<Code>,
}

/// One `timestamps[]` entry of the attestation file (§11.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationTimestamp {
    /// `sha256:<hex>` of the raw receipt bytes.
    pub digest: String,
    /// Container-relative receipt path.
    pub path: String,
    /// Path of the previous receipt in the renewal chain, or `None` for the
    /// first receipt.
    pub renews: Option<String>,
}

/// Result of verifying the whole renewal chain of one manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainEvidence {
    /// One outcome per `timestamps[]` entry, in attestation order.
    pub receipts: Vec<ReceiptOutcome>,
    /// First failing §12.2 check 14 (renewal-chain structure), when present.
    pub chain_error: Option<Code>,
    /// True only when every receipt is verified and the chain is complete.
    pub anchor_verified: bool,
}

impl ChainEvidence {
    /// Empty evidence, used when a target has no timestamp chain (record target,
    /// L0/L1 container).
    #[must_use]
    pub fn none() -> Self {
        Self {
            receipts: Vec::new(),
            chain_error: None,
            anchor_verified: false,
        }
    }

    /// True when any receipt is present (for the §9.4 case-2/case-3 split).
    #[must_use]
    pub fn has_receipts(&self) -> bool {
        !self.receipts.is_empty()
    }

    /// The `genTime + accuracy` bound in integer microseconds for every
    /// verified-and-trusted receipt (§9.4 case 1). A signature by a compromised
    /// key is rescued when one bound is strictly below `T`.
    #[must_use]
    pub fn rescue_bounds_us(&self) -> Vec<i64> {
        self.receipts
            .iter()
            .filter(|receipt| receipt.state == ReceiptState::Verified)
            .filter_map(|receipt| receipt.gen_time.map(|time| time.to_unix_millis() * 1_000 + receipt.accuracy_us))
            .collect()
    }
}

/// Verifies the renewal chain (§12.4) over one manifest digest.
///
/// `files` maps container-relative paths to file bytes; the caller has already
/// checked that every listed `.tsr` exists and matches its listed digest.
/// `trust_anchors` holds the SHA-256 digests of the DER encodings of the
/// `--tsa-trust` certificates.
#[must_use]
pub fn verify_chain(
    _entries: &[AttestationTimestamp],
    _manifest_digest: &[u8; 32],
    _files: &BTreeMap<String, Vec<u8>>,
    _trust_anchors: &[[u8; 32]],
) -> ChainEvidence {
    todo!("timestamp chain: implemented by the L2 workstream")
}

/// Maps a receipt error to the §12.5 container effect:
/// checks 1–14 are invalid; check 15 is unverifiable.
#[must_use]
pub fn receipt_effect(_error: Code) -> &'static str {
    todo!("timestamp chain: implemented by the L2 workstream")
}

/// Loads `--tsa-trust` anchors: one or more PEM certificates, or raw DER.
/// Returns the SHA-256 digests of the DER encodings (§12.3).
pub fn load_trust_anchors(_file_contents: &[Vec<u8>]) -> Result<Vec<[u8; 32]>, UsageError> {
    todo!("timestamp anchors: implemented by the L2 workstream")
}
