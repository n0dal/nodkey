//! Protocol v2 (effect protocol v2 Draft 2): pending effects, approval via the authority, and
//! execution of verified write grants in one transaction.
//!
//! - [`ids`]: pending and receipt identifiers (canonical base64url), hex.
//! - [`digest`]: the normative pending-effect digest (spec §3.2).
//! - [`config`]: the v2 broker configuration and start-up refusals (spec §1.2, §2.1, §2.4).
//! - [`decls`]: the operation declarations this broker implements (spec §5).
//! - [`db`]: a small bounded PostgreSQL connection pool.
//! - [`service`]: method semantics for sockets W, G and A, execution and recovery (spec §2–§4).
//! - [`server`]: Unix-socket listeners, framing, `SO_PEERCRED` checks.
//! - [`limits`]: per-workload rate limiting.

pub mod adapter;
pub mod config;
pub mod db;
pub mod decls;
pub mod digest;
pub mod ids;
pub mod limits;
pub mod payments;
pub mod server;
pub mod service;
pub mod wire;
