//! `nodkey-mcp-stdio <mcp.sock path>`: the no-secret byte-copying shim (agent-interface-v1 §2.2).

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, path] = args.as_slice() else {
        eprintln!("usage: nodkey-mcp-stdio <path to mcp.sock>");
        std::process::exit(2);
    };
    let code = nodkey_mcp_front::shim::run(
        std::path::Path::new(path),
        tokio::io::stdin(),
        tokio::io::stdout(),
    )
    .await;
    std::process::exit(code);
}
