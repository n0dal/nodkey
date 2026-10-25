//! Nodkey-Grant v1: strict verifier and canonical issuer for `docs/specs/grant-v1.md`.
//!
//! - [`Registry::load`] — key registry (spec §8) with every load-time check.
//! - [`decode_transport`] — spec §2 / steps 0–1c (base64url text to grant bytes).
//! - [`verify`] — spec §7.2 steps 1c–11. Consumption (step 12) and revocation (step 13) belong to
//!   the broker's transaction; [`VerifiedGrant`], [`Rejection::verified`], [`request_hash`] and
//!   [`GrantIdentity::is_revoked`] give it what it needs.
//! - [`GrantBuilder`] — issuer side (spec §9).
//!
//! Error codes are broker-facing (audit log only); the workload sees `grant_denied` (spec §7.4).
//! A valid grant is a necessary condition for an effect, never a sufficient one (SI-04).

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

mod cbor;
mod error;
mod issue;
mod ops;
mod payload;
mod registry;
mod text;
mod transport;
mod verify;

pub use error::{BuildError, DeclarationError, GrantError, RegistryError, RegistryErrorCode};
pub use issue::GrantBuilder;
pub use ops::{
    Authority, Binding, OpKind, OperationDecl, Operations, ParamDecl, ParamType, ParamValue,
    Params, TextRule,
};
pub use payload::GrantKind;
pub use registry::{ALG_ED25519, KeyEntry, KeyStatus, Registry, Role, derive_kid};
pub use transport::{decode_transport, encode_transport};
pub use verify::{
    GrantIdentity, Rejection, RevocationScope, RevokedBefore, Skew, VerifiedGrant, VerifyContext,
    request_hash, verify,
};

/// Re-export so issuers and tests use the same key type as `GrantBuilder::sign`.
pub use ed25519_dalek::SigningKey;

/// Protected header `typ` (spec §3.2).
pub const TYP: &str = "application/nodkey-grant+cbor";
/// `external_aad` domain tag (spec §3.4).
pub const AAD_TAG: &str = "nodkey.grant.v1";
/// kid derivation label (spec §8.1).
pub const KID_LABEL: &str = "nodkey.kid.v1";
/// Maximum grant size in bytes (spec §3.1).
pub const MAX_GRANT_BYTES: usize = 2048;
/// Maximum transport text length, ceil(2048 * 4 / 3) (spec §2).
pub const MAX_TRANSPORT_CHARS: usize = 2731;
/// Broker-wide maximum `exp - nbf` in seconds (spec §7.1, D-6).
pub const MAX_TTL: u64 = 30;
/// Maximum clock skew in seconds (spec §7.1).
pub const MAX_SKEW: u64 = 5;
/// Largest time value, 2^53 - 1 (spec §5.1).
pub const MAX_TIME: u64 = (1 << 53) - 1;
