//! nodkey-broker library: protocol v1 (Demo 1 only) and protocol v2
//! (`docs/specs/effect-protocol-v2.md`, propose → confirm → execute).
//!
//! PROTOTYPE. Not for production use.

#![forbid(unsafe_code)]

pub mod config;
pub mod ledger;
pub mod protocol;
pub mod server;
pub mod strict_json;
pub mod v2;
