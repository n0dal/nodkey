//! Nodkey per-agent MCP front (agent-interface-v1 Draft 2 §2). **Prototype.**
//!
//! The front is **outside the TCB** and holds no secret: it translates MCP tool calls into
//! effect-protocol-v2 calls on the agent's own broker socket W, which identifies the agent. The
//! broker, authority, gateway and payments adapter make every decision; nothing here is a control
//! except the peer-uid check on `mcp.sock` (AI-11), which limits who *is* the agent.

#![forbid(unsafe_code)]

pub mod broker;
pub mod config;
pub mod json;
pub mod mcp;
pub mod server;
pub mod shim;
