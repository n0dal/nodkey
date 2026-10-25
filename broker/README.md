# nodkey-broker

> [!WARNING]
> **Prototype.** Part of the Nodkey containment demo (Phase 2). Not for production use.

The broker is the trusted process that executes protected effects on behalf of untrusted
workloads. It holds the database credential; workloads never do.

- **Identity:** one Unix socket per configured workload. The socket a request arrives on
  identifies the workload; the peer's uid (`SO_PEERCRED`) must also match the configured uid.
- **Interface:** newline-delimited JSON, protocol version 1, at most 16 KiB per request. Parsing is
  strict: duplicate keys (including keys equal after unescaping), unknown fields, wrong types and
  missing fields are rejected.
- **Operations:** a closed set — `ledger.get_balance` and `ledger.transfer`. Each workload has an
  allowlist of operations and a per-call amount limit. Anything else is denied.
- **Transfers:** both account rows are locked in a fixed order inside one transaction. A required
  `idempotency_key` makes retries safe: the same key with the same arguments returns the original
  result without a second effect; with different arguments it is denied.
- **Failure reporting:** a failure before any write is `unavailable` (nothing happened); a failure
  at or after the first write — including timeouts around `COMMIT` — is `outcome_unknown`, and the
  client must retry with the same key rather than assume failure.
- **Logging:** one JSON line per decision on stdout, with a correlation id. Container logs are not
  an audit trail (see the demo's known limitations).

## Build and test

```sh
cargo test                                   # unit tests (any platform)
docker build -t nodkey/broker:dev .        # Linux image (base images pinned by digest)
```

End-to-end tests live in `tests/containment/run.sh` and `tests/integration/idempotency.sh` at the
repository root.

## Dependencies

Direct dependencies only; versions are locked in `Cargo.lock`.

| Crate | Locked | License | Why it is needed |
|---|---|---|---|
| `tokio` | 1.54.1 | MIT | Async runtime, Unix sockets, timeouts. Default features off; only the features used are enabled. |
| `serde` | 1.0.229 | MIT OR Apache-2.0 | Typed deserialization of requests and configuration. |
| `serde_json` | 1.0.154 | MIT OR Apache-2.0 | JSON parsing. Duplicate-key rejection is implemented separately in `src/strict_json.rs` because `serde_json` accepts duplicates. |
| `tokio-postgres` | 0.7.18 | MIT OR Apache-2.0 | PostgreSQL client with SCRAM authentication. TLS is not used inside the internal network in this demo. |

A full transitive license inventory and SBOM are planned for the supply-chain phase.
