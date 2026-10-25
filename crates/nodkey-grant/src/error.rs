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
    /// Step 10a (write), 10a/10c/10d (read).
    OpMismatch,
    /// Step 10b (write), 10b/10c (read).
    KindMismatch,
    /// Step 10c (write), 10e (read).
    OpvUnsupported,
    /// Step 10d (write), 10f (read).
    IssuerNotPermitted,
    /// Step 10e (write).
    ConfirmationRequired,
    /// Step 11a.
    OpSchemaInvalid,
    /// Step 11b.
    ResourceMismatch,
    /// Step 11c (exact).
    ConstraintMismatch,
    /// Step 11c (bounded).
    BoundExceeded,
    /// Step 12 (produced by the broker's replay store, not by this crate's `verify`).
    Replayed,
    /// Step 13 (produced by the broker's revocation check, see `GrantIdentity::is_revoked`).
    Revoked,
}

impl GrantError {
    /// Every code, in procedure order.
    pub const ALL: [GrantError; 32] = [
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
        Self::IssuerNotPermitted,
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
            Self::IssuerNotPermitted => "grant_issuer_not_permitted",
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

/// Invalid operation declarations (spec §6): the broker must refuse to start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclarationError(pub String);

impl fmt::Display for DeclarationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid operation declaration: {}", self.0)
    }
}

impl std::error::Error for DeclarationError {}

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
