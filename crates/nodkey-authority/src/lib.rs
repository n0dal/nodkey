// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! Nodkey authority (effect-protocol-v2 Draft 2, ADR-0011 Amendment 1).
//!
//! The only grant signer. No network: it listens on socket I for the gateway (`approve`,
//! `read_grant`) and is a client of the broker's socket A (`config.digest`, `pending.get`,
//! `grant.deliver`). A write grant needs two independent inputs: a gateway approval and a broker
//! record that agree on digest and subject. Issuance is recorded durably before delivery, with
//! `jti = pending_id`, so at most one grant per pending effect is ever signed and delivered.
//!
//! PROTOTYPE. Not suitable for production use.

#![forbid(unsafe_code)]

pub mod broker_client;
pub mod config;
pub mod digest;
pub mod key;
pub mod log;
pub mod server;
pub mod store;
pub mod wire;

/// The effective uid of this process, read without `unsafe` via `SO_PEERCRED` on a socket pair.
/// Must be called inside a Tokio runtime.
pub fn own_uid() -> std::io::Result<u32> {
    let (a, _b) = tokio::net::UnixStream::pair()?;
    Ok(a.peer_cred()?.uid())
}
