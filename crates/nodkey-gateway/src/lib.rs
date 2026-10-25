//! Nodkey gateway (prototype, Phase 3): the only public HTTP listener and part of the TCB.
//!
//! - **App origin**: reverse proxy to the untrusted app web server with request/response header
//!   allowlists (ADR-0003 Phase 3 profile item 2), read-grant delivery (`Nodkey-Grant`), and the
//!   reserved `/.nodkey/` paths for the app-session hand-off.
//! - **Auth origin**: sessions, login (test login only, `test-login` feature + config flag), and the
//!   confirmation page of `docs/specs/effect-protocol-v2.md` §7.
//!
//! The gateway holds no signing key. It talks to the broker on socket G (`pending.render`,
//! `pending.deny`) and to the authority on socket I (`approve`, `read_grant`).

#![forbid(unsafe_code)]

pub mod app;
pub mod auth;
pub mod config;
pub mod digest;
pub mod html;
pub mod http;
pub mod ipc;
pub mod json;
pub mod server;
pub mod store;
pub mod util;

/// Whether this build contains the test login.
pub const TEST_LOGIN_COMPILED: bool = cfg!(feature = "test-login");
