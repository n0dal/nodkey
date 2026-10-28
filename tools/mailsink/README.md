# mailsink: a SIMULATED mail sink

> [!WARNING]
> **mailsink delivers no mail.** It is a local test tool for Nodkey Demo A. Never expose it on a
> public network. Every response carries `Mailsink-Simulator: SIMULATED mail sink - delivers no mail`,
> every JSON body carries `"simulator": true`, and every log line starts with `[mailsink SIMULATOR]`.

`messages.send` (agent-interface-v1 Draft 2 §3) is an internal broker effect: one row in the broker-owned
`public.outbox(message_id, ten, to, body, created_at)`. mailsink polls that table read-only. It keeps the
rows it has seen in memory (deduplicated, at most 10,000) and lists them on a local admin endpoint for
tests.

**Trust:** none. Nodkey never reads anything back from mailsink. It is not part of any TCB.

## Running

```sh
MAILSINK_DATABASE='host=db user=mailsink dbname=ledger password=…' \
  mailsink [--admin 127.0.0.1:12121] [--poll-ms 500] [--container-bind]
```

- `GET /messages` returns `{simulator, label, messages: [{message_id (hex), ten, to, body, created_at}],
  not_stored}`.
- `GET /healthz` returns `{simulator, label, polls_ok, last_error}`.
- Anything else gets 404, 405 or 400.
- The bind policy is the same as simpay's: loopback and private addresses only, the unspecified address
  only with `--container-bind`, never a public address.
- The poll runs in a `READ ONLY` session, ordered by `(created_at, message_id)` with a bytewise cursor
  (`COLLATE "C"`). It reconnects every 1 s after a failure.

**Deployment gap (next step):** `04-mandates.sh` has no mailsink role. Demo A needs a role with `SELECT`
on `public.outbox` only, plus a `pg_hba` line for the sink's address.

## Tests

`cargo test`: the admin endpoint over loopback TCP (listing, labels, 404/405/400), deduplication, cursor
order, the memory cap, and the bind policy. **NOT TESTED:** the PostgreSQL poll (`poll_outbox`,
`POLL_SQL`). It needs a database and is covered by the Demo A run.

## Dependencies

| Crate | Why | License |
|---|---|---|
| `tokio` | TCP listener, timers | MIT |
| `tokio-postgres` | Reading `public.outbox` (already used by the broker) | MIT OR Apache-2.0 |
| `serde_json` | JSON bodies | MIT OR Apache-2.0 |
| `httparse` | Request-head parsing (already used by simpay) | MIT OR Apache-2.0 |
