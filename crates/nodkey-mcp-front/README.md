# nodkey-mcp-front

> **PROTOTYPE.** Not suitable for production use.

The per-agent MCP front `nodkey-mcp` and the stdio shim `nodkey-mcp-stdio` of
[agent-interface-v1](../../docs/specs/agent-interface-v1.md) **Draft 2** §2 (ADR-0013 rev. 1).

**Outside the TCB; holds no secret.** It translates MCP tool calls into effect-protocol-v2 calls on
the agent's own broker socket W, which is what identifies the agent. Every decision is the broker's,
authority's, gateway's and payments adapter's. Its strict parsing only improves error messages; the
broker re-applies every rule. The one control here is the **peer-uid check on `mcp.sock`** (AI-11):
any process that can open `mcp.sock` or socket W *is* the agent.

## Commands

```sh
nodkey-mcp --config <front.json>          # listens on listen_socket (mode 0660)
nodkey-mcp-stdio <path to mcp.sock>       # stdin → mcp.sock → stdout, byte for byte
```

Configuration (`nodkey.mcp-front.v1`, strict JSON, every member required, nothing secret):
`listen_socket`, `agent_uid`, `broker_socket`, `broker_uid`, `operations_path` (the grant-v1 §6.1
operations file the broker loads), `write_ops`, `read_ops`, `approver {ten, sub}` (the enrolment),
`auth_origin` (`https://host[:port]`). Start-up refuses: unknown or missing members, an op not declared
or declared with the other kind, duplicates, a tool named `nodkey.effect_status`, an approver outside
the ID grammar, a non-`https` origin, an unknown parameter type, and a socket directory with "other"
permission bits.

## MCP subset (revision 2026-07-28 only)

Facts from the MCP `schema/2026-07-28/schema.ts` (fetched 2026-10-28):
- every request's `params._meta` must carry `io.modelcontextprotocol/protocolVersion` = `2026-07-28` and
  `io.modelcontextprotocol/clientCapabilities` (an object); another version gets `-32022` with
  `data {supported, requested}`, and a missing one gets `-32602`;
- `server/discover`: `{supportedVersions, capabilities: {tools: {listChanged: false}}, ttlMs: 0,
  cacheScope: "private", _meta.serverInfo}`. `tools/list`: the static catalogue, `ttlMs: 0`, `cacheScope:
  "private"`, no pagination (any `cursor` gets `-32602`). Every result carries `resultType: "complete"`;
- `tools/call`: an unknown tool gets `-32602`. Tool failures are results with `isError: true`, and
  `structuredContent` = `{error: <code>}` with the same JSON as one text item;
- notifications are not answered. Every other method gets `-32601`.

Tool catalogue (§2.3): one tool per configured operation, in operations-file order, then
`nodkey.effect_status{pending_id, wait_s 0..20}`. The input schemas follow §2.3:
`additionalProperties: false`, every parameter required, and broker-resolved parameters omitted. The front
keeps its own copy of the broker's `resolved_by_broker` table.

Parsing (§2.4) uses its own strict JSON parser (`src/json.rs`). It keeps the source text of each number
and rejects duplicate names at any depth, lone surrogates and nesting deeper than 32. `serde_json` is not
used for input: it keeps the last duplicate and loses the source form of numbers. Its
`arbitrary_precision` mode has a magic-key ambiguity.

Call mapping (§2.5):
- write: `effect.propose{op, params, approver}`, then `effect.status` every 250 ms for up to 3 s,
  stopping at the first status other than `in_progress`;
- `nodkey.effect_status`: every 1 s until the status is neither `in_progress` nor
  `pending_confirmation`, or `wait_s` runs out;
- read: the method with the checked arguments; the result object is passed through, and a number that is
  not a `uint` is `unavailable`.

The state table follows §2.5. `confirm_url` is formed by the front as `<auth_origin>/confirm/<pending_id>`,
so no broker text reaches the agent. Broker error codes outside effect-protocol-v2 §2.6 become
`unavailable`, and broker messages are dropped.

Transport: one broker connection per call, with the broker's listener uid checked. Limits: 8
connections, 8 requests in flight per connection, 64 KiB per line. An oversize line gets one `-32600`
and the connection is closed. The shim forwards nothing past the cap and exits with a non-zero status.

## Spec gaps found

| # | Gap | Reading used |
|---|---|---|
| MF-1 | §2.1 lists `ping`, but the 2026-07-28 schema has no `ping` request | Served (empty result) as the spec says; MCP clients will not send it |
| MF-2 | The 2026-07-28 schema makes `clientCapabilities` required in `_meta`; §2.4 names only the version | Required (`-32602` if missing or not an object) |
| MF-3 | `effect.status` has no `confirm_url`, but §2.5 wants it for `nodkey.effect_status` | Formed from the configured `auth_origin` (same format as effect-protocol-v2 §2.3) for every `pending_confirmation` |
| MF-4 | The operations file does not mark `resolved_by_broker` parameters | Front copy of the broker's table; drift only changes the advertised schema |
| MF-5 | §2.4 gives no codes for a missing version, bad `id`, batch or duplicate names | `-32602`, `-32600`, `-32600`, `-32700` |
| MF-6 | §2.5 poll stop conditions | Write: stop at any status other than `in_progress`; `effect_status`: stop when neither `in_progress` nor `pending_confirmation` |
| MF-7 | `effect.status` `PENDING` without `awaiting`, unknown states, or a `FAILED` class other than `failed`/`denied` | Unknown shape → `unavailable` (write calls then report `in_progress` with the `pending_id`); other classes → `failed` |

## Tests

```sh
cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check
```

| Suite | Covers |
|---|---|
| unit | Parser (duplicates, number forms, surrogates, depth), broker reply parsing, shim cap |
| `tests/conformance.rs` | discover/ping/ids; static `tools/list` with resolved parameters omitted; version and `_meta` rules; AT-04 envelope and argument rejections and AT-05 forbidden members (nothing reaches the broker); the §2.5 state table; broker codes only; `effect_status` waiting; reads; config refusals |
| `tests/socket.rs` | real `mcp.sock`: mode 0660, concurrent requests on one connection, notifications, oversize line, **foreign peer uid gets no response**, wrong broker uid, shim subprocess end to end and oversize, bind refusals |

Limits: tests run as one uid (the foreign-uid case is simulated by configuring another expected uid).
macOS only so far (`getpeereid`); Linux `SO_PEERCRED` is not tested.

## Dependencies

| Crate | Why | License |
|---|---|---|
| `tokio` | Unix sockets, `peer_cred`, timers, stdio | MIT |
| `serde_json` | Building output messages only (input uses `src/json.rs`) | MIT OR Apache-2.0 |
