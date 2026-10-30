// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! Error codes. Each variant maps 1:1 to a code of spec §7.2 (grants) or §8.3 (registry); the
//! `as_str()` strings are stable and are what the broker writes to its audit log. They are
//! broker-facing only: the workload receives the generic `grant_denied` (spec §7.4).

use std::fmt;

/// Broker-facing grant error codes, spec §7.2. Declared in procedure order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GrantError {
    /// Step 0.
    Missing,
    /// Steps 1a, 1c.
    TooLarge,
    /// Step 1b.
    EncodingInvalid,
    /// Step 2.
    Malformed,
    /// Step 3.
    HeaderInvalid,
    /// Step 4a.
    UnknownKid,
    /// Step 4b.
    AlgMismatch,
    /// Step 4c.
    KeyRevoked,
    /// Step 4d.
    KeyInactive,
    /// Step 5.
    SignatureInvalid,
    /// Step 6.
    PayloadMalformed,
    /// Step 7a.
    VersionUnsupported,
    /// Step 7b.
    PayloadInvalid,
    /// Step 8a.
    IssuerMismatch,
    /// Step 8b.
    TimeInvalid,
    /// Step 8c.
    TtlExceeded,
    /// Step 8d.
    NotYetValid,
    /// Step 8e.
    Expired,
    /// Step 9a.
    AudienceMismatch,
    /// Step 9b.
    WorkloadMismatch,
    /// Step 9c.
    TenantMismatch,
    /// Step W11a; R11a/R11b/R11d.
    OpMismatch,
    /// Step W11b; R11a/R11c.
    KindMismatch,
    /// Step W11c; R11a.
    OpvUnsupported,
    /// Step W11d.
    ConfirmationRequired,
    /// Step W12a.
    OpSchemaInvalid,
    /// Step W12b.
    ResourceMismatch,
    /// Step W12c (exact, or bounded with a non-uint request value).
    ConstraintMismatch,
    /// Step W12c (bounded).
    BoundExceeded,
    /// Step W10 (produced by the broker's replay store: same `(iss, jti)`, different hash).
    Replayed,
    /// Steps W13 / R13.
    Revoked,
}

impl GrantError {
    /// Every code, in procedure order.
    pub const ALL: [GrantError; 31] = [
        Self::Missing,
        Self::TooLarge,
        Self::EncodingInvalid,
        Self::Malformed,
        Self::HeaderInvalid,
        Self::UnknownKid,
        Self::AlgMismatch,
        Self::KeyRevoked,
        Self::KeyInactive,
        Self::SignatureInvalid,
        Self::PayloadMalformed,
        Self::VersionUnsupported,
        Self::PayloadInvalid,
        Self::IssuerMismatch,
        Self::TimeInvalid,
        Self::TtlExceeded,
        Self::NotYetValid,
        Self::Expired,
        Self::AudienceMismatch,
        Self::WorkloadMismatch,
        Self::TenantMismatch,
        Self::OpMismatch,
        Self::KindMismatch,
        Self::OpvUnsupported,
        Self::ConfirmationRequired,
        Self::OpSchemaInvalid,
        Self::ResourceMismatch,
        Self::ConstraintMismatch,
        Self::BoundExceeded,
        Self::Replayed,
        Self::Revoked,
    ];

    /// The spec's error code string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "grant_missing",
            Self::TooLarge => "grant_too_large",
            Self::EncodingInvalid => "grant_encoding_invalid",
            Self::Malformed => "grant_malformed",
            Self::HeaderInvalid => "grant_header_invalid",
            Self::UnknownKid => "grant_unknown_kid",
            Self::AlgMismatch => "grant_alg_mismatch",
            Self::KeyRevoked => "grant_key_revoked",
            Self::KeyInactive => "grant_key_inactive",
            Self::SignatureInvalid => "grant_signature_invalid",
            Self::PayloadMalformed => "grant_payload_malformed",
            Self::VersionUnsupported => "grant_version_unsupported",
            Self::PayloadInvalid => "grant_payload_invalid",
            Self::IssuerMismatch => "grant_issuer_mismatch",
            Self::TimeInvalid => "grant_time_invalid",
            Self::TtlExceeded => "grant_ttl_exceeded",
            Self::NotYetValid => "grant_not_yet_valid",
            Self::Expired => "grant_expired",
            Self::AudienceMismatch => "grant_audience_mismatch",
            Self::WorkloadMismatch => "grant_workload_mismatch",
            Self::TenantMismatch => "grant_tenant_mismatch",
            Self::OpMismatch => "grant_op_mismatch",
            Self::KindMismatch => "grant_kind_mismatch",
            Self::OpvUnsupported => "grant_opv_unsupported",
            Self::ConfirmationRequired => "grant_confirmation_required",
            Self::OpSchemaInvalid => "grant_op_schema_invalid",
            Self::ResourceMismatch => "grant_resource_mismatch",
            Self::ConstraintMismatch => "grant_constraint_mismatch",
            Self::BoundExceeded => "grant_bound_exceeded",
            Self::Replayed => "grant_replayed",
            Self::Revoked => "grant_revoked",
        }
    }

    /// The only code the workload may see (spec §7.4).
    pub const CLIENT_FACING: &'static str = "grant_denied";
}

impl fmt::Display for GrantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for GrantError {}

/// Key registry load error codes, spec §8.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegistryErrorCode {
    EntryInvalid,
    KeyInvalid,
    KeyWeak,
    KidMismatch,
    DuplicateKey,
}

impl RegistryErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EntryInvalid => "registry_entry_invalid",
            Self::KeyInvalid => "registry_key_invalid",
            Self::KeyWeak => "registry_key_weak",
            Self::KidMismatch => "registry_kid_mismatch",
            Self::DuplicateKey => "registry_duplicate_key",
        }
    }
}

/// A registry load failure: the code and, when the failure is in one entry, its 0-based index in
/// `keys`. The broker must refuse to start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryError {
    pub code: RegistryErrorCode,
    pub entry: Option<usize>,
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.entry {
            Some(i) => write!(f, "{} (keys[{i}])", self.code.as_str()),
            None => f.write_str(self.code.as_str()),
        }
    }
}

impl std::error::Error for RegistryError {}

/// Invalid operation declarations (spec §6.3): the broker must refuse to start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclarationError {
    detail: String,
}

impl DeclarationError {
    pub(crate) fn new(detail: String) -> Self {
        DeclarationError { detail }
    }
    /// The spec's code, `ops_declaration_invalid`.
    pub const fn as_str(&self) -> &'static str {
        "ops_declaration_invalid"
    }
    /// Human-readable detail for the operator log.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for DeclarationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ops_declaration_invalid: {}", self.detail)
    }
}

impl std::error::Error for DeclarationError {}

/// A request that does not match its operation's declaration (spec §6.2, §7.1). This is a
/// request-parser rejection (the broker's `invalid_argument`), not a grant decision: nothing is
/// verified, consumed or recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestError {
    UnknownOperation,
    UnknownParameter(String),
    MissingParameter(String),
    InvalidValue(String),
    /// Internal: the request could not be encoded for hashing (unreachable for valid input).
    Encoding,
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownOperation => f.write_str("unknown operation"),
            Self::UnknownParameter(n) => write!(f, "unknown parameter {n}"),
            Self::MissingParameter(n) => write!(f, "missing parameter {n}"),
            Self::InvalidValue(n) => write!(f, "invalid value for {n}"),
            Self::Encoding => f.write_str("request encoding failed"),
        }
    }
}

impl std::error::Error for RequestError {}

/// The issuer refused to sign: the grant would not conform to the spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildError(pub &'static str);

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cannot issue grant: {}", self.0)
    }
}

impl std::error::Error for BuildError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_unique_and_prefixed() {
        let mut seen = std::collections::HashSet::new();
        for e in GrantError::ALL {
            assert!(e.as_str().starts_with("grant_"));
            assert!(seen.insert(e.as_str()));
        }
    }
}
