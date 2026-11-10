// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Ed25519 verification under the fixed strict profile of §3.
//!
//! This module is implemented from the specification only (RFC 8032 plus the
//! §3 rulings). It MUST NOT call a library convenience verifier: every step of
//! §3.4 has its own error code and the order of checks is normative.
//!
//! Interface contract (see ARCHITECTURE.md):
//! - [`verify`] performs exactly the checks 2–9 of §3.4 (check 1, the structural
//!   length check, belongs to the envelope/attestation layer) and returns the
//!   [`crate::error_codes::Code`] of the first failing check.
//! - [`public_key_from_seed`] and [`sign`] implement §3.5 and exist so the
//!   RFC 8032 §7.1 cross-check can derive and sign exactly as the specification
//!   says; the verifier itself never signs.

use crate::error_codes::Code;

/// Verifies one Ed25519 signature over one message under §3.4 steps 2–9.
///
/// `public_key` must be the 32 raw public-key octets and `signature` the 64
/// `R ‖ S` octets; the caller performs the structural base64url/length checks
/// first (§3.4 step 1) and maps those to `E_ENV_SIG_VALUE` /
/// `E_MANIFEST_SCHEMA`.
///
/// # Errors
/// Returns the code of the first failing §3.4 step: `E_SIG_NONCANONICAL_A`,
/// `E_SIG_S_OUT_OF_RANGE`, `E_SIG_SMALL_ORDER_A`, `E_SIG_MIXED_ORDER_A`,
/// `E_SIG_NONCANONICAL_R`, `E_SIG_SMALL_ORDER_R` or `E_SIG_INVALID`.
pub fn verify(_public_key: &[u8], _signature: &[u8], _message: &[u8]) -> Result<(), Code> {
    todo!("ed25519 profile: implemented by the crypto workstream")
}

/// Derives the 32-byte public key from a 32-byte Ed25519 seed (§3.5).
#[must_use]
pub fn public_key_from_seed(_seed: &[u8; 32]) -> [u8; 32] {
    todo!("ed25519 profile: implemented by the crypto workstream")
}

/// Produces an Ed25519 signature over `message` from a 32-byte seed (§3.5).
#[must_use]
pub fn sign(_seed: &[u8; 32], _message: &[u8]) -> [u8; 64] {
    todo!("ed25519 profile: implemented by the crypto workstream")
}
