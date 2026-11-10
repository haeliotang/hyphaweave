// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Registered-kind body schemas and per-kind facts (§7.2, kind pages).
//!
//! This module performs check (6) of §14.5 — the kind body schema — and derives
//! from each body the structured facts that later checks (kind semantics,
//! authorisation, container state) need. It is deliberately *context-free*:
//! facts that require other records (owner trust, grant chains, consent
//! revocation, erasure cross-checks) are evaluated by [`crate::context`].
//!
//! Unknown kinds are opaque (§7.3): the body is never validated and the record
//! must not be rejected for unknown body members. Additional unknown members at
//! the `body` root of a registered kind are permitted (additive evolution,
//! §7.5); unknown members inside closed variant objects are errors.

use crate::envelope::RecordFile;
use crate::error_codes::Code;
use crate::time::Timestamp;

/// `weave.key.revoked.body.reason` closed vocabulary (§9.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevokeReason {
    /// Retroactive; rescue only via verified pre-compromise timestamp.
    Compromise,
    /// Retired key.
    Retired,
    /// Treated as retired.
    Other,
}

/// `weave.grant.body.action` (§5.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantActionKind {
    /// `action: "grant"`.
    Grant,
    /// `action: "revoke"`.
    Revoke,
}

/// Body of `weave.key.declared` (§9.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyDeclaredBody {
    /// Declared key id.
    pub key: String,
    /// Declared key class.
    pub key_type: String,
    /// 32 raw public-key bytes.
    pub public_key: Vec<u8>,
    /// Owner key id for automated classes.
    pub owner: Option<String>,
    /// Claimed validity window start.
    pub valid_from: Option<Timestamp>,
    /// Claimed validity window end.
    pub valid_until: Option<Timestamp>,
}

/// Body of `weave.key.rotated` (§9.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRotatedBody {
    /// Predecessor key id.
    pub old_key: String,
    /// Successor key id.
    pub new_key: String,
    /// Predecessor public key, when explicitly supplied.
    pub old_public_key: Option<Vec<u8>>,
    /// Successor public key.
    pub new_public_key: Vec<u8>,
}

/// Body of `weave.key.revoked` (§9.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRevokedBody {
    /// Revoked key id.
    pub key: String,
    /// Reason (load-bearing).
    pub reason: RevokeReason,
    /// Claimed effective instant.
    pub effective_at: Timestamp,
}

/// The `grant` variant object (§5.5.1), closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantSpec {
    /// Authorised grantee key id.
    pub grantee_key: String,
    /// Authorised kinds (1–64, unique).
    pub kinds: Vec<String>,
    /// Authorised actions (1–7, unique, closed vocabulary).
    pub actions: Vec<String>,
    /// Audit scope (1–32 strings, unique).
    pub scope: Vec<String>,
    /// Start of validity window.
    pub valid_from: Timestamp,
    /// End of validity window; `None` means unbounded.
    pub valid_until: Option<Timestamp>,
    /// Whether the grantee may delegate further.
    pub transferable: bool,
    /// Explicit revoker list, when present.
    pub revocation: Option<Vec<String>>,
}

/// The `revoke` variant object (§5.5.4), closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevokeSpec {
    /// Reference to the grant being revoked.
    pub revokes: crate::envelope::RefObject,
    /// Claimed effective instant.
    pub effective_at: Timestamp,
}

/// Body of `weave.grant` (§5.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantBody {
    /// Variant discriminator.
    pub action: GrantActionKind,
    /// Present exactly when `action == "grant"`.
    pub grant: Option<GrantSpec>,
    /// Present exactly when `action == "revoke"`.
    pub revoke: Option<RevokeSpec>,
}

/// Body of `weave.consent.granted`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentGrantedBody {
    /// Start of the claimed consent window.
    pub valid_from: Timestamp,
    /// End of the window; `None` means no stated end.
    pub valid_until: Option<Timestamp>,
}

/// Body of `weave.consent.revoked`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentRevokedBody {
    /// Reference to the consent being withdrawn.
    pub revokes: crate::envelope::RefObject,
    /// Claimed effective instant.
    pub effective_at: Timestamp,
}

/// Body of `weave.erasure` (§10.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErasureBody {
    /// Reference to the erased record.
    pub erased: crate::envelope::RefObject,
    /// Reason vocabulary value.
    pub reason: String,
    /// Authorisation basis, when supplied.
    pub basis: Option<crate::envelope::RefObject>,
    /// Claimed execution instant.
    pub executed_at: Option<Timestamp>,
}

/// Structured kind body; `Opaque` for unknown kinds (§7.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KindBody {
    /// `weave.key.declared` body.
    KeyDeclared(KeyDeclaredBody),
    /// `weave.key.rotated` body.
    KeyRotated(KeyRotatedBody),
    /// `weave.key.revoked` body.
    KeyRevoked(KeyRevokedBody),
    /// `weave.grant` body.
    Grant(GrantBody),
    /// `weave.consent.granted` body.
    ConsentGranted(ConsentGrantedBody),
    /// `weave.consent.revoked` body.
    ConsentRevoked(ConsentRevokedBody),
    /// `weave.erasure` body.
    Erasure(ErasureBody),
    /// Unknown kind: not interpreted.
    Opaque,
}

/// The per-record signing obligation of §4.4, used to decide whether a valid
/// required signature exists. Evaluation against the verification context is
/// the record pipeline's job; this type only names the requirement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Obligation {
    /// No per-record signature is required.
    None,
    /// A signature by `actor.key` is required.
    ActorKey,
    /// `weave.key.declared`: self-signature by the declared key; automated
    /// classes additionally need the owner cosignature.
    DeclaredKey {
        /// Declared key id.
        declared_key: String,
        /// Owner key id for automated classes.
        owner_key: Option<String>,
    },
    /// `weave.key.rotated`: signatures by both keys.
    RotationBoth {
        /// Predecessor key id.
        old_key: String,
        /// Successor key id.
        new_key: String,
    },
    /// `weave.key.revoked`: signer rule depends on the reason.
    RevokedKey {
        /// Revoked key id.
        revoked_key: String,
        /// Revocation reason.
        reason: RevokeReason,
    },
    /// `weave.grant`: granter/revoker signature required.
    Grant {
        /// Variant discriminator.
        action: GrantActionKind,
    },
    /// `weave.consent.*`: a declared human/organization key must sign.
    Consent,
    /// `weave.erasure`: actor signature plus signer-table constraints.
    Erasure,
}

impl Obligation {
    /// Dedicated signer code of the seven signer-constrained kinds (§4.4), used
    /// when verifiable signatures exist but the required signer is missing.
    #[must_use]
    pub fn dedicated_code(&self) -> Option<Code> {
        match self {
            Self::None | Self::ActorKey => None,
            Self::DeclaredKey { .. } => Some(crate::error_codes::e::KEY_DECLARED_NOT_SELF_SIGNED),
            Self::RotationBoth { .. } => Some(crate::error_codes::e::KEY_ROTATION_SIGS),
            Self::RevokedKey { .. } => Some(crate::error_codes::e::KEY_REVOKE_SIGNER),
            Self::Grant { action } => Some(match action {
                GrantActionKind::Grant => crate::error_codes::e::GRANT_GRANTER,
                GrantActionKind::Revoke => crate::error_codes::e::GRANT_REVOKE_SIGNER,
            }),
            Self::Consent => Some(crate::error_codes::e::ACTOR_KEY_TYPE_MISMATCH),
            Self::Erasure => Some(crate::error_codes::e::ERASE_ACTOR),
        }
    }
}

/// Check (6) of §14.5: validates the kind body schema and derives facts.
///
/// # Errors
/// Returns the kind's schema/semantic error code (`E_KIND_BODY_SCHEMA`,
/// `E_GRANT_SCHEMA`, `E_KEY_VALIDITY`, `E_KEY_ROTATION_KEYS`,
/// `E_KEY_PUBLIC_KEY`, `E_KEY_ID_MISMATCH`, `E_KEY_OWNER_MISSING`,
/// `E_CONSENT_VALIDITY`, ...).
pub fn parse_body(_record: &RecordFile) -> Result<KindBody, Code> {
    todo!("kind bodies: implemented by the kinds workstream")
}

/// Derives the §4.4 signing obligation from the parsed record and body.
#[must_use]
pub fn obligation(_record: &RecordFile, _body: &KindBody) -> Obligation {
    todo!("kind bodies: implemented by the kinds workstream")
}
