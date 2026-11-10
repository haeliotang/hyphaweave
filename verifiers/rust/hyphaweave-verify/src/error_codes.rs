// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Closed registry of verifier error codes (`E_*`) and notices (`N_*`).
//!
//! The registry is defined by `spec/error-codes.md` and is closed: this crate
//! must not report any identifier outside these lists. Codes are represented as
//! `&'static str` so that reports, the test-only skip hook and the vector
//! matcher all compare the same bytes as the specification.
//!
//! Constants are grouped by prefix: [`e`] for error codes, [`n`] for notices.

/// A closed-registry error code or notice identifier.
pub type Code = &'static str;

/// Error codes (`E_*`). Every entry is a fixed ASCII identifier.
#[allow(dead_code)]
pub mod e {
    use super::Code;
    pub const JSON_INVALID: Code = "E_JSON_INVALID";
    pub const JSON_DUPLICATE_KEY: Code = "E_JSON_DUPLICATE_KEY";
    pub const JSON_NOT_CANONICAL: Code = "E_JSON_NOT_CANONICAL";
    pub const JSON_NUMBER_NOT_INTEGER: Code = "E_JSON_NUMBER_NOT_INTEGER";
    pub const JSON_NUMBER_RANGE: Code = "E_JSON_NUMBER_RANGE";
    pub const JSON_LONE_SURROGATE: Code = "E_JSON_LONE_SURROGATE";
    pub const JSON_SIZE: Code = "E_JSON_SIZE";
    pub const ENV_MISSING_FIELD: Code = "E_ENV_MISSING_FIELD";
    pub const ENV_UNKNOWN_FIELD: Code = "E_ENV_UNKNOWN_FIELD";
    pub const ENV_FORMAT: Code = "E_ENV_FORMAT";
    pub const ENV_KIND_SYNTAX: Code = "E_ENV_KIND_SYNTAX";
    pub const ENV_ORIGIN: Code = "E_ENV_ORIGIN";
    pub const ENV_ID: Code = "E_ENV_ID";
    pub const ENV_STAGE: Code = "E_ENV_STAGE";
    pub const ENV_ACTOR: Code = "E_ENV_ACTOR";
    pub const ENV_ACTOR_TYPE: Code = "E_ENV_ACTOR_TYPE";
    pub const ENV_ACTOR_KEY: Code = "E_ENV_ACTOR_KEY";
    pub const ENV_ACTOR_MODEL_MISSING: Code = "E_ENV_ACTOR_MODEL_MISSING";
    pub const ENV_ACTOR_MODEL: Code = "E_ENV_ACTOR_MODEL";
    pub const ENV_ACTOR_ON_BEHALF_MISSING: Code = "E_ENV_ACTOR_ON_BEHALF_MISSING";
    pub const ENV_ACTOR_ON_BEHALF: Code = "E_ENV_ACTOR_ON_BEHALF";
    pub const ENV_ACTOR_GRANT_MISSING: Code = "E_ENV_ACTOR_GRANT_MISSING";
    pub const ENV_ACTOR_IDEMPOTENCY_MISSING: Code = "E_ENV_ACTOR_IDEMPOTENCY_MISSING";
    pub const ENV_ACTOR_IDEMPOTENCY: Code = "E_ENV_ACTOR_IDEMPOTENCY";
    pub const ENV_TIME: Code = "E_ENV_TIME";
    pub const ENV_REFS: Code = "E_ENV_REFS";
    pub const ENV_LABELS: Code = "E_ENV_LABELS";
    pub const ENV_SENSITIVITY: Code = "E_ENV_SENSITIVITY";
    pub const ENV_LICENCE: Code = "E_ENV_LICENCE";
    pub const ENV_SALT: Code = "E_ENV_SALT";
    pub const ENV_SALT_MISSING: Code = "E_ENV_SALT_MISSING";
    pub const ENV_SIGS: Code = "E_ENV_SIGS";
    pub const ENV_SIG_ALG: Code = "E_ENV_SIG_ALG";
    pub const ENV_SIG_KEY: Code = "E_ENV_SIG_KEY";
    pub const ENV_SIG_VALUE: Code = "E_ENV_SIG_VALUE";
    pub const ENV_BODY: Code = "E_ENV_BODY";
    pub const ACTOR_KEY_TYPE_MISMATCH: Code = "E_ACTOR_KEY_TYPE_MISMATCH";
    pub const ACTOR_HUMAN_KEY: Code = "E_ACTOR_HUMAN_KEY";
    pub const SIG_INVALID: Code = "E_SIG_INVALID";
    pub const SIG_REQUIRED: Code = "E_SIG_REQUIRED";
    pub const SIG_NONCANONICAL_A: Code = "E_SIG_NONCANONICAL_A";
    pub const SIG_NONCANONICAL_R: Code = "E_SIG_NONCANONICAL_R";
    pub const SIG_SMALL_ORDER_A: Code = "E_SIG_SMALL_ORDER_A";
    pub const SIG_SMALL_ORDER_R: Code = "E_SIG_SMALL_ORDER_R";
    pub const SIG_S_OUT_OF_RANGE: Code = "E_SIG_S_OUT_OF_RANGE";
    pub const SIG_MIXED_ORDER_A: Code = "E_SIG_MIXED_ORDER_A";
    pub const SIG_UNVERIFIABLE: Code = "E_SIG_UNVERIFIABLE";
    pub const KIND_BODY_SCHEMA: Code = "E_KIND_BODY_SCHEMA";
    pub const KEY_PUBLIC_KEY: Code = "E_KEY_PUBLIC_KEY";
    pub const KEY_ID_MISMATCH: Code = "E_KEY_ID_MISMATCH";
    pub const KEY_DECLARED_NOT_SELF_SIGNED: Code = "E_KEY_DECLARED_NOT_SELF_SIGNED";
    pub const KEY_OWNER_MISSING: Code = "E_KEY_OWNER_MISSING";
    pub const KEY_DECLARED_NOT_COSIGNED: Code = "E_KEY_DECLARED_NOT_COSIGNED";
    pub const KEY_VALIDITY: Code = "E_KEY_VALIDITY";
    pub const KEY_ROTATION_KEYS: Code = "E_KEY_ROTATION_KEYS";
    pub const KEY_ROTATION_SIGS: Code = "E_KEY_ROTATION_SIGS";
    pub const KEY_REVOKE_EFFECTIVE: Code = "E_KEY_REVOKE_EFFECTIVE";
    pub const KEY_REVOKE_SIGNER: Code = "E_KEY_REVOKE_SIGNER";
    pub const KEY_UNKNOWN: Code = "E_KEY_UNKNOWN";
    pub const KEY_UNTRUSTED: Code = "E_KEY_UNTRUSTED";
    pub const KEY_EXPIRED: Code = "E_KEY_EXPIRED";
    pub const KEY_REVOKED: Code = "E_KEY_REVOKED";
    pub const KEY_COMPROMISED: Code = "E_KEY_COMPROMISED";
    pub const GRANT_SCHEMA: Code = "E_GRANT_SCHEMA";
    pub const GRANT_GRANTER: Code = "E_GRANT_GRANTER";
    pub const GRANT_NOT_TRANSFERABLE: Code = "E_GRANT_NOT_TRANSFERABLE";
    pub const GRANT_DELEGATION_EXCEEDS: Code = "E_GRANT_DELEGATION_EXCEEDS";
    pub const GRANT_REVOKE_SIGNER: Code = "E_GRANT_REVOKE_SIGNER";
    pub const GRANT_REVOKE_REF: Code = "E_GRANT_REVOKE_REF";
    pub const GRANT_UNRESOLVED: Code = "E_GRANT_UNRESOLVED";
    pub const GRANT_REVOKED: Code = "E_GRANT_REVOKED";
    pub const GRANT_EXPIRED: Code = "E_GRANT_EXPIRED";
    pub const GRANT_GRANTEE_MISMATCH: Code = "E_GRANT_GRANTEE_MISMATCH";
    pub const GRANT_NOT_APPLICABLE: Code = "E_GRANT_NOT_APPLICABLE";
    pub const CONSENT_VALIDITY: Code = "E_CONSENT_VALIDITY";
    pub const CONSENT_REVOKE_REF: Code = "E_CONSENT_REVOKE_REF";
    pub const CONSENT_REVOKED: Code = "E_CONSENT_REVOKED";
    pub const ERASE_ACTOR: Code = "E_ERASE_ACTOR";
    pub const ERASE_DIGEST_MISMATCH: Code = "E_ERASE_DIGEST_MISMATCH";
    pub const ERASE_ATTESTATION: Code = "E_ERASE_ATTESTATION";
    pub const ERASE_CONTRADICTION: Code = "E_ERASE_CONTRADICTION";
    pub const LABEL_DOWNGRADE: Code = "E_LABEL_DOWNGRADE";
    pub const LABEL_LOCAL_ONLY_EXPORTED: Code = "E_LABEL_LOCAL_ONLY_EXPORTED";
    pub const REF_KIND_MISMATCH: Code = "E_REF_KIND_MISMATCH";
    pub const MANIFEST_MISSING: Code = "E_MANIFEST_MISSING";
    pub const MANIFEST_FORMAT: Code = "E_MANIFEST_FORMAT";
    pub const MANIFEST_VERSION: Code = "E_MANIFEST_VERSION";
    pub const MANIFEST_SCHEMA: Code = "E_MANIFEST_SCHEMA";
    pub const MANIFEST_DIGEST: Code = "E_MANIFEST_DIGEST";
    pub const MANIFEST_UNSIGNED: Code = "E_MANIFEST_UNSIGNED";
    pub const MANIFEST_SIG_INVALID: Code = "E_MANIFEST_SIG_INVALID";
    pub const MANIFEST_RECORDS: Code = "E_MANIFEST_RECORDS";
    pub const MANIFEST_RECORD_MISSING: Code = "E_MANIFEST_RECORD_MISSING";
    pub const MANIFEST_RECORD_EXTRA: Code = "E_MANIFEST_RECORD_EXTRA";
    pub const MANIFEST_RECORD_DIGEST: Code = "E_MANIFEST_RECORD_DIGEST";
    pub const MANIFEST_BLOB: Code = "E_MANIFEST_BLOB";
    pub const MANIFEST_LEVEL: Code = "E_MANIFEST_LEVEL";
    pub const MANIFEST_L1_NO_HEAD: Code = "E_MANIFEST_L1_NO_HEAD";
    pub const MANIFEST_L1_NO_POSITION: Code = "E_MANIFEST_L1_NO_POSITION";
    pub const MANIFEST_L2_NO_TIMESTAMP: Code = "E_MANIFEST_L2_NO_TIMESTAMP";
    pub const MANIFEST_CHAIN: Code = "E_MANIFEST_CHAIN";
    pub const MANIFEST_CHAIN_MISSING: Code = "E_MANIFEST_CHAIN_MISSING";
    pub const MANIFEST_CHAIN_UNEXPECTED: Code = "E_MANIFEST_CHAIN_UNEXPECTED";
    pub const CONTAINER_ENTRY: Code = "E_CONTAINER_ENTRY";
    pub const CONTAINER_SIZE: Code = "E_CONTAINER_SIZE";
    pub const CONTAINER_ZIP: Code = "E_CONTAINER_ZIP";
    pub const TS_FILE: Code = "E_TS_FILE";
    pub const TS_SCHEMA: Code = "E_TS_SCHEMA";
    pub const TS_IMPRINT: Code = "E_TS_IMPRINT";
    pub const TS_CMS: Code = "E_TS_CMS";
    pub const TS_CERT: Code = "E_TS_CERT";
    pub const TS_UNTRUSTED: Code = "E_TS_UNTRUSTED";
    pub const TS_RENEWAL: Code = "E_TS_RENEWAL";
}

/// Notices (`N_*`), non-fatal unless the specification says otherwise.
#[allow(dead_code)]
pub mod n {
    use super::Code;

    pub const KIND_UNKNOWN_OPAQUE: Code = "N_KIND_UNKNOWN_OPAQUE";
    pub const KEY_UNDECLARED: Code = "N_KEY_UNDECLARED";
    pub const KEY_TOFU: Code = "N_KEY_TOFU";
    pub const SELF_ATTESTED_ROOT_KEY: Code = "N_SELF_ATTESTED_ROOT_KEY";
    pub const NO_HUMAN_SIGNATURE: Code = "N_NO_HUMAN_SIGNATURE";
    pub const REF_MISSING: Code = "N_REF_MISSING";
    pub const REF_MOVED: Code = "N_REF_MOVED";
    pub const REF_UNVERIFIABLE: Code = "N_REF_UNVERIFIABLE";
    pub const LABEL_PROPAGATION_UNCHECKED: Code = "N_LABEL_PROPAGATION_UNCHECKED";
    pub const CHAIN_CLAIM_UNVERIFIED: Code = "N_CHAIN_CLAIM_UNVERIFIED";
    pub const CONSENT_UNRESOLVED: Code = "N_CONSENT_UNRESOLVED";
    pub const PREVIOUS_SIG_UNVERIFIED: Code = "N_PREVIOUS_SIG_UNVERIFIED";
    pub const IDEMPOTENCY_DUPLICATE: Code = "N_IDEMPOTENCY_DUPLICATE";
    pub const READABLE_PRESENT: Code = "N_READABLE_PRESENT";
}

/// Every error code in the closed registry, in registry order.
pub const ALL_ERROR_CODES: &[Code] = &[
    "E_JSON_INVALID",
    "E_JSON_DUPLICATE_KEY",
    "E_JSON_NOT_CANONICAL",
    "E_JSON_NUMBER_NOT_INTEGER",
    "E_JSON_NUMBER_RANGE",
    "E_JSON_LONE_SURROGATE",
    "E_JSON_SIZE",
    "E_ENV_MISSING_FIELD",
    "E_ENV_UNKNOWN_FIELD",
    "E_ENV_FORMAT",
    "E_ENV_KIND_SYNTAX",
    "E_ENV_ORIGIN",
    "E_ENV_ID",
    "E_ENV_STAGE",
    "E_ENV_ACTOR",
    "E_ENV_ACTOR_TYPE",
    "E_ENV_ACTOR_KEY",
    "E_ENV_ACTOR_MODEL_MISSING",
    "E_ENV_ACTOR_MODEL",
    "E_ENV_ACTOR_ON_BEHALF_MISSING",
    "E_ENV_ACTOR_ON_BEHALF",
    "E_ENV_ACTOR_GRANT_MISSING",
    "E_ENV_ACTOR_IDEMPOTENCY_MISSING",
    "E_ENV_ACTOR_IDEMPOTENCY",
    "E_ENV_TIME",
    "E_ENV_REFS",
    "E_ENV_LABELS",
    "E_ENV_SENSITIVITY",
    "E_ENV_LICENCE",
    "E_ENV_SALT",
    "E_ENV_SALT_MISSING",
    "E_ENV_SIGS",
    "E_ENV_SIG_ALG",
    "E_ENV_SIG_KEY",
    "E_ENV_SIG_VALUE",
    "E_ENV_BODY",
    "E_ACTOR_KEY_TYPE_MISMATCH",
    "E_ACTOR_HUMAN_KEY",
    "E_SIG_INVALID",
    "E_SIG_REQUIRED",
    "E_SIG_NONCANONICAL_A",
    "E_SIG_NONCANONICAL_R",
    "E_SIG_SMALL_ORDER_A",
    "E_SIG_SMALL_ORDER_R",
    "E_SIG_S_OUT_OF_RANGE",
    "E_SIG_MIXED_ORDER_A",
    "E_SIG_UNVERIFIABLE",
    "E_KIND_BODY_SCHEMA",
    "E_KEY_PUBLIC_KEY",
    "E_KEY_ID_MISMATCH",
    "E_KEY_DECLARED_NOT_SELF_SIGNED",
    "E_KEY_OWNER_MISSING",
    "E_KEY_DECLARED_NOT_COSIGNED",
    "E_KEY_VALIDITY",
    "E_KEY_ROTATION_KEYS",
    "E_KEY_ROTATION_SIGS",
    "E_KEY_REVOKE_EFFECTIVE",
    "E_KEY_REVOKE_SIGNER",
    "E_KEY_UNKNOWN",
    "E_KEY_UNTRUSTED",
    "E_KEY_EXPIRED",
    "E_KEY_REVOKED",
    "E_KEY_COMPROMISED",
    "E_GRANT_SCHEMA",
    "E_GRANT_GRANTER",
    "E_GRANT_NOT_TRANSFERABLE",
    "E_GRANT_DELEGATION_EXCEEDS",
    "E_GRANT_REVOKE_SIGNER",
    "E_GRANT_REVOKE_REF",
    "E_GRANT_UNRESOLVED",
    "E_GRANT_REVOKED",
    "E_GRANT_EXPIRED",
    "E_GRANT_GRANTEE_MISMATCH",
    "E_GRANT_NOT_APPLICABLE",
    "E_CONSENT_VALIDITY",
    "E_CONSENT_REVOKE_REF",
    "E_CONSENT_REVOKED",
    "E_ERASE_ACTOR",
    "E_ERASE_DIGEST_MISMATCH",
    "E_ERASE_ATTESTATION",
    "E_ERASE_CONTRADICTION",
    "E_LABEL_DOWNGRADE",
    "E_LABEL_LOCAL_ONLY_EXPORTED",
    "E_REF_KIND_MISMATCH",
    "E_MANIFEST_MISSING",
    "E_MANIFEST_FORMAT",
    "E_MANIFEST_VERSION",
    "E_MANIFEST_SCHEMA",
    "E_MANIFEST_DIGEST",
    "E_MANIFEST_UNSIGNED",
    "E_MANIFEST_SIG_INVALID",
    "E_MANIFEST_RECORDS",
    "E_MANIFEST_RECORD_MISSING",
    "E_MANIFEST_RECORD_EXTRA",
    "E_MANIFEST_RECORD_DIGEST",
    "E_MANIFEST_BLOB",
    "E_MANIFEST_LEVEL",
    "E_MANIFEST_L1_NO_HEAD",
    "E_MANIFEST_L1_NO_POSITION",
    "E_MANIFEST_L2_NO_TIMESTAMP",
    "E_MANIFEST_CHAIN",
    "E_MANIFEST_CHAIN_MISSING",
    "E_MANIFEST_CHAIN_UNEXPECTED",
    "E_CONTAINER_ENTRY",
    "E_CONTAINER_SIZE",
    "E_CONTAINER_ZIP",
    "E_TS_FILE",
    "E_TS_SCHEMA",
    "E_TS_IMPRINT",
    "E_TS_CMS",
    "E_TS_CERT",
    "E_TS_UNTRUSTED",
    "E_TS_RENEWAL",
];

/// Every notice in the closed registry, in registry order.
pub const ALL_NOTICES: &[Code] = &[
    "N_KIND_UNKNOWN_OPAQUE",
    "N_KEY_UNDECLARED",
    "N_KEY_TOFU",
    "N_SELF_ATTESTED_ROOT_KEY",
    "N_NO_HUMAN_SIGNATURE",
    "N_REF_MISSING",
    "N_REF_MOVED",
    "N_REF_UNVERIFIABLE",
    "N_LABEL_PROPAGATION_UNCHECKED",
    "N_CHAIN_CLAIM_UNVERIFIED",
    "N_CONSENT_UNRESOLVED",
    "N_PREVIOUS_SIG_UNVERIFIED",
    "N_IDEMPOTENCY_DUPLICATE",
    "N_READABLE_PRESENT",
];

/// True when `code` is a registered error code.
#[must_use]
pub fn is_error_code(code: &str) -> bool {
    ALL_ERROR_CODES.contains(&code)
}

/// True when `code` is a registered notice.
#[must_use]
pub fn is_notice(code: &str) -> bool {
    ALL_NOTICES.contains(&code)
}
