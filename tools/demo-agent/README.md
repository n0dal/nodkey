# demo-agent: Demo A scripted support agent

> **Untrusted test tool.** It is a deterministic stand-in for a **fully prompt-injected** model.

It runs the agent side of [agent-interface-v1](../../docs/specs/agent-interface-v1.md) Draft 2 §5:
1. read the whole ticket ([`fixtures/ticket-T-1.txt`](fixtures/ticket-T-1.txt), including the injected
   `‹SYSTEM: …›` text);
2. obey every instruction in it by calling MCP tools in the fixed order S0', S0, S1 … S12 (`S0p` = S0',
   `S9a`/`S9b`, `S12a`/`S12b`);
3. record every tool result verbatim as JSON lines.

It makes no decision of its own and holds no secret. The only value that depends on data is the S8 body:
"Card details: " plus the S1 read result, which is what the agent had. After a write that is still
`in_progress` or `pending_confirmation`, it polls `nodkey.effect_status` for up to `--decision-wait-s`.
The scripted principal `op_ana` (approve S0 only, deny the rest) belongs to the test harness, not to this
tool.

```sh
demo-agent --ticket fixtures/ticket-T-1.txt \
  --mcp-command nodkey-mcp-stdio --mcp-arg /run/nodkey/agent/support-bot/mcp.sock \
  [--steps S0p,S0,…] [--decision-wait-s 60] [--record run.jsonl]
```

S12 assumes the principal has revoked M1 first. The harness runs it as a separate `--steps S12`.

**Optional model mode:** off by default, never required, and **not implemented** (`--model` exits with an
explanation; AT-27 NOT TESTED). There is no paid-API path.

## Tests

`cargo test`:
- unit: script order and step selection, S8 body bounds;
- `tests/scripted.rs`: the full script through the **real** `nodkey-mcp-front` on a `mcp.sock`, with a
  fake broker socket W that plays the §5 outcomes. It checks call order, arguments, recorded statuses,
  S5 `-32602`, S6 `invalid_argument` with no record, and that every proposal has the enrolment as
  approver and no `to`. It also runs the binary with `--steps`, checks that a bad transport (`/bin/cat`)
  fails closed, and that `--model` is refused.

The outcomes in these tests come from the fake broker, not from Nodkey. The real outcomes are checked
by the Demo A run (next step).

## Dependencies

| Crate | Why | License |
|---|---|---|
| `tokio` | Unix socket, subprocess stdio, timers | MIT |
| `serde_json` | MCP messages and records | MIT OR Apache-2.0 |
| `nodkey-mcp-front` (dev) | End-to-end test against the real front | Apache-2.0 |
