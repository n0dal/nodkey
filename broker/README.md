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

## Protocol v2 (Phase 3, `docs/specs/effect-protocol-v2.md` Draft 2)

Selected by a configuration with `"format": "nodkey.broker.v2"` (run with
`--mounts-verified-externally`; the broker has no deployment-manifest reader, so it refuses to start
without the flag). A v2 configuration cannot describe a v1 socket and vice versa; a v1 and a v2 broker
never share a database (`broker_claim` row; v1 refuses to start if the table is missing). Protocol v1
runs only with an explicit `"profile": "demo1"` in its configuration.

| Socket | Methods |
|---|---|
| W (per workload) | `effect.propose`, `effect.status`, `ledger.get_balance` (authority read grant); `payments.*` declared, denied `operation_not_permitted` (not implemented in Phase 3) |
| G (gateway) | `pending.render`, `pending.deny`, in the gateway's shapes (`crates/nodkey-gateway` README, GW-1) |
| A (authority) | `config.digest`, `pending.get`, `grant.deliver`, in the authority's shapes (`crates/nodkey-authority` README, AU-1/AU-2) |

- Pending records, consumption (`consumed_grant`), revocation, clock mark and ownership tables:
  `examples/php-ledger/docker/postgres/initdb/02-effects-v2.sh` (triggers enforce immutability and
  the §3.3 state machine; the broker role can update only mutable columns and cannot delete).
- Execution: on `grant.deliver` acceptance and in a 5 s recovery loop, one transaction does lock →
  window check → verify → W10 consume → savepoint → W11–W13 → W14 (ownership, funds under row locks)
  → effect + `SUCCEEDED`, or rollback to savepoint + `FAILED/denied`. Any failure before commit leaves
  the record `APPROVED` with nothing consumed.
- Availability (review BR-01): socket W uses its own pool (`db_pool_size`). Each workload is
  capped at `limits.db_conns_per_wid` concurrent connections (default 2) and rate limits for
  proposals, status and reads (`reads_per_min`, default 600). Sockets G and A, execution and
  recovery use a separate control pool (`db_control_pool_size`, default 4) that workloads cannot reach.
- Sockets are mode 0660; the peer connects through the socket's group. At start-up each socket
  directory must be a real directory owned by the broker or the peer, with no "other" bits. Socket
  directories must not nest. A workload socket that cannot be bound disables only that workload.
  `SO_PEERCRED` remains the primary control.
- Operator obligations:
  - prune final `pending_effect` rows after a retention period;
  - prune `consumed_grant` rows only after `exp + skew + margin` (grant-v1 §7.6).

  The broker role cannot delete. `effect.propose` may return `unavailable` even though a `PENDING`
  record was committed (the commit outcome was lost). The record is harmless, and it counts toward
  the limits until it expires.
- `config.digest` requires `authority_workloads_path`: the authority's `nodkey.workloads.v1`
  file, which must describe exactly this broker's workloads.

## Payments (Demo P, `docs/specs/payments-adapter-v1.md` Draft 3.2)

Enabled by a `payments` section in the v2 configuration:

```json
{"adapter_socket": "...", "adapter_uid": 0, "R_max_s": 43200, "max_resends": 5, "adapter_total_ms": 10000,
 "budget": {"max_count_per_day": 3, "limits_minor": {"USD": 20000}}}
```

It also needs the effect-protocol-v2 Draft 3.1 `payments.refund` declaration, which includes
`charge_id`. The legacy 3-parameter declaration still loads but is never executable.

- Schema: `examples/php-ledger/docker/postgres/initdb/03-payments.sh`. Schema `nodkey` holds:
  - `orders` (operator-written; the broker has `SELECT` only);
  - `charge_refund_state` (per-charge lock and counters, checked at commit);
  - `payment_effect`, `refund_budget`, `refund_denial`.

  Every broker statement is schema-qualified, every function pins its `search_path`, and no Nodkey
  role can create objects in any schema or database (`CREATE`/`TEMPORARY` revoked). Each role's default
  `search_path` is empty, but that is defence in depth only: a role can change its own session defaults.
- Settlement: `pending` rows are polled with `refund.get`; `succeeded` rows stay under a lookup-only
  post-success watch until `dispatched_at + payments.settlement_watch_s` (default 30 days). A later
  `failed` is recorded with anomaly `settlement_reversed` and an alarm; the amount stays encumbered.
- Propose resolves `charge_id` from `orders` (or `unresolved`) into the record.
- T1 runs consumption, the ordered W14 checks, the budget, encumbrance and `RESERVED` in one
  transaction.
- T2/T3: `refund.create` on socket P under a row lease, followed by a confirming `refund.get`.
- The reconciler looks up first. It resends with the same key only inside the gate, and only the
  lease holder calls the adapter. Before every call the broker waits (bounded) for a call slot and
  then re-asserts the row's lease.
- Every call on P carries the row's `idem_kid`. `adapter.hello` is re-run before every dispatch,
  reconciliation round and payments tick; payment processing is refused while a non-final row
  carries another kid, or while the adapter's `deadline_ms` is not below `adapter_total_ms + 2 s`.
- Payments recovery and reconciliation run in their own loop (`v2::server::payments_loop`), at most
  4 rows at a time, with per-row error isolation; the effect-protocol-v2 recovery loop never waits
  for the adapter.
- Workloads see only the §8 reason enum.

The pg_hba lines for the adapter role (§1) belong to the deployment; they are not set here.

## Build and test

```sh
cargo test                                   # unit tests, feature guard (any platform)
tests/run-pg-integration.sh                  # PostgreSQL integration tests (Docker; pinned image)
docker build -f broker/Dockerfile -t nodkey/broker:dev .   # from the REPOSITORY ROOT
```

The Docker build context is now the repository root (path dependency on `crates/nodkey-grant`);
`examples/php-ledger/compose.protected.yaml` must be updated accordingly
(`context: ../..`, `dockerfile: broker/Dockerfile`).

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
| `nodkey-grant` | path | Apache-2.0 | Grant verification (grant-v1). Its test-only feature `conformance-unvalidated-requests` must never be enabled; `tests/feature_guard.rs` fails if it is. |
| `sha2` | 0.11.0 | MIT OR Apache-2.0 | Pending-effect digest (§3.2) and `config.digest`. Already in the tree through `nodkey-grant`. |

Dev-only: `nodkey-authority` and `nodkey-gateway` (path), used by the integration tests to drive
sockets A and G with the peers' own clients.

A full transitive license inventory and SBOM are planned for the supply-chain phase.
