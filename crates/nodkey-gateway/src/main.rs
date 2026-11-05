// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! `nodkey-gateway --config <path>`

use std::path::PathBuf;
use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!("usage: nodkey-gateway --config <path>");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let path = match args.as_slice() {
        [flag, p] if flag == "--config" => PathBuf::from(p),
        _ => return usage(),
    };
    let cfg = match nodkey_gateway::config::load(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("nodkey-gateway: refusing to start: {e}");
            return ExitCode::FAILURE;
        }
    };
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("nodkey-gateway: runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    rt.block_on(async {
        let running = match nodkey_gateway::server::start(cfg).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("nodkey-gateway: refusing to start: {e}");
                return ExitCode::FAILURE;
            }
        };
        eprintln!("nodkey-gateway: listening on {}", running.addr);
        let _ = tokio::signal::ctrl_c().await;
        running.task.abort();
        ExitCode::SUCCESS
    })
}
