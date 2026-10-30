// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! `nodkey-mcp --config <path>`: the per-agent MCP front.

use std::path::PathBuf;
use std::sync::Arc;

use nodkey_mcp_front::config::FrontConfig;
use nodkey_mcp_front::mcp::{Front, Timing};
use nodkey_mcp_front::server;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = match args.as_slice() {
        [_, flag, p] if flag == "--config" => PathBuf::from(p),
        _ => {
            eprintln!("usage: nodkey-mcp --config <path>");
            std::process::exit(2);
        }
    };
    let cfg = match FrontConfig::load(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("nodkey-mcp: configuration refused: {}", e.0);
            std::process::exit(2);
        }
    };
    let listener = match server::bind(&cfg.listen_socket) {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "nodkey-mcp: cannot bind {}: {e}",
                cfg.listen_socket.display()
            );
            std::process::exit(2);
        }
    };
    let agent_uid = cfg.agent_uid;
    let front = Arc::new(Front::new(cfg, Timing::default()));
    tokio::select! {
        _ = server::serve(front, listener, agent_uid) => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}
