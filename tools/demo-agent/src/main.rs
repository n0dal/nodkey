// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! `demo-agent`: the Demo A scripted support agent (agent-interface-v1 Draft 2 §5).

use std::io::Write;
use std::path::PathBuf;
use std::process::Stdio;

use demo_agent::{Client, RunOptions, run, script, select};
use tokio::io::BufReader;

const USAGE: &str = "usage: demo-agent --ticket <file> (--mcp-command <program> [--mcp-arg <arg>]... | --mcp-socket <path>)
                  [--steps <S0p,S0,S1,...>] [--decision-wait-s <0..3600>] [--record <file>]

  Deterministic scripted agent for Nodkey Demo A. It reads the whole ticket, then obeys every
  instruction in it (a fully prompt-injected stand-in) by calling MCP tools in the order
  S0', S0, S1 ... S12, and records every tool result as JSON lines.

  --mcp-command       MCP server program speaking stdio, normally the shim:
                      --mcp-command nodkey-mcp-stdio --mcp-arg /run/nodkey/agent/<name>/mcp.sock
  --mcp-socket        connect to mcp.sock directly (MCP stdio framing over the socket)
  --steps             subset, in the given order (S9 = S9a,S9b; S12 = S12a,S12b). Default: all.
                      S12 expects the principal to have revoked the mandate first.
  --decision-wait-s   per step, how long to poll nodkey.effect_status while the effect is
                      pending (default 60)
  --record            output file (default: stdout)

  Optional model mode (--model): NOT IMPLEMENTED in this prototype and never required. No paid
  API path exists. Demo A runs entirely with this scripted agent.";

fn fail(m: &str) -> ! {
    eprintln!("demo-agent: {m}\n\n{USAGE}");
    std::process::exit(2);
}

#[tokio::main]
async fn main() {
    let mut ticket: Option<PathBuf> = None;
    let mut command: Option<String> = None;
    let mut command_args: Vec<String> = Vec::new();
    let mut socket: Option<PathBuf> = None;
    let mut steps = script();
    let mut decision_wait_s = 60u64;
    let mut record: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = || {
            args.next()
                .unwrap_or_else(|| fail(&format!("{a} needs a value")))
        };
        match a.as_str() {
            "--ticket" => ticket = Some(val().into()),
            "--mcp-command" => command = Some(val()),
            "--mcp-arg" => command_args.push(val()),
            "--mcp-socket" => socket = Some(val().into()),
            "--steps" => steps = select(&val()).unwrap_or_else(|e| fail(&e)),
            "--decision-wait-s" => {
                decision_wait_s = val()
                    .parse()
                    .ok()
                    .filter(|n| *n <= 3600)
                    .unwrap_or_else(|| fail("--decision-wait-s needs 0..3600"))
            }
            "--record" => record = Some(val().into()),
            "--model" => fail(
                "the optional model mode is not implemented in this prototype (AT-27 NOT TESTED); \
                 Demo A uses the scripted agent only",
            ),
            "-h" | "--help" => {
                println!("{USAGE}");
                return;
            }
            _ => fail(&format!("unknown argument {a}")),
        }
    }
    let ticket = ticket.unwrap_or_else(|| fail("--ticket is required"));
    let text = std::fs::read_to_string(&ticket)
        .unwrap_or_else(|e| fail(&format!("cannot read {}: {e}", ticket.display())));
    let mut out: Box<dyn Write> = match &record {
        Some(p) => Box::new(
            std::fs::File::create(p).unwrap_or_else(|e| fail(&format!("{}: {e}", p.display()))),
        ),
        None => Box::new(std::io::stdout()),
    };
    let mut emit = |v: serde_json::Value| {
        let _ = writeln!(out, "{v}");
        let _ = out.flush();
    };
    let opts = RunOptions {
        steps,
        decision_wait_s,
    };
    let result = match (command, socket) {
        (Some(cmd), None) => {
            let mut child = tokio::process::Command::new(&cmd)
                .args(&command_args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .unwrap_or_else(|e| fail(&format!("cannot start {cmd}: {e}")));
            let (Some(w), Some(r)) = (child.stdin.take(), child.stdout.take()) else {
                fail("no stdio pipes");
            };
            let mut c = Client::new(BufReader::new(r), w);
            run(&mut c, &text, &opts, &mut emit).await
        }
        (None, Some(path)) => {
            let s = tokio::net::UnixStream::connect(&path)
                .await
                .unwrap_or_else(|e| fail(&format!("cannot connect {}: {e}", path.display())));
            let (r, w) = s.into_split();
            let mut c = Client::new(BufReader::new(r), w);
            run(&mut c, &text, &opts, &mut emit).await
        }
        _ => fail("exactly one of --mcp-command and --mcp-socket is required"),
    };
    if let Err(e) = result {
        emit(serde_json::json!({"event": "error", "detail": format!("{e:?}")}));
        std::process::exit(1);
    }
    emit(serde_json::json!({"event": "done"}));
}
