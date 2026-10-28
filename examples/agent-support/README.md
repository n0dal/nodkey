# Demo A: an AI support agent under Nodkey

> [!WARNING]
> **LOCAL TEST STACK ONLY. Never expose it to a network.** The gateway runs the **test login**, which
> asks for no credential. simpay is a **simulated** payment provider and mailsink is a **simulated**
> mail sink that delivers no mail. The Demo P shop (`POST /debug/eval`, which is **intentionally
> vulnerable** to remote code execution) is kept unchanged as the gateway's app upstream. The only
> published port is `127.0.0.1:8443`.

This stack implements the Demo A scenario of [agent-interface-v1](../../docs/specs/agent-interface-v1.md)
Draft 2 §5 ([ADR-0013](../../docs/decisions/0013-agent-interface-and-mandates.md)). It needs no model, API
key or account.

## What runs

| Service | Role | Network | Holds |
|---|---|---|---|
| `agent` | [`tools/demo-agent`](../../tools/demo-agent/README.md): a deterministic stand-in for a **fully prompt-injected** model. It reads ticket T-1 and obeys every instruction in it, including the injected ones | none; uid 10011; only `mcp.sock` mounted, read-only | nothing |
| `mcp-front` | [`nodkey-mcp`](../../crates/nodkey-mcp-front/README.md) for `support-bot`. It translates MCP into protocol v2 on the agent's socket W and is outside the TCB | none; runs as the agent's registered uid | nothing |
| `broker`, `authority`, `gateway`, `adapter`, `db` | as in Demo P ([`examples/confirmed-refund`](../confirmed-refund/compose.yaml)), plus `04-mandates.sh` | as in Demo P | as in Demo P |
| `simpay` | simulated provider (TLS, test-only CA) | `pay-egress`, `harness` | its fixture |
| `mailsink` | simulated mail sink. It reads `public.outbox` through a role that can only `SELECT` that table, and lists the rows on `GET /messages` | `data` 172.30.20.30, `harness` 172.30.40.40 | its DB password (compose secret) |

Principals and data ([`config/demo-data.json`](config/demo-data.json); every one is a test user):
- tenant `shop1`;
- **Carol (support)** (`staff:carol`), the agent's enrolled principal and the only support principal;
- **Dave** (`staff:dave`), staff but not a support principal;
- customers `c42` (`alice@customer.test`) and `c9` (`bob@customer.test`), with orders 101 (c42, €35.00),
  102 (c42, €30.00) and 777 (c9, €40.00);
- further customers and orders, used only as fixed inputs for single conformance rows.

The spec's principal `op_ana` is played by Carol, under the same rule: she approves only what concerns
the ticket's visible sender c42 and denies everything else. The demo agent's hard-coded ids (c42, c9,
101, 102, 777) are used unchanged.

## Configuration

- `config/operations.json`: Demo P's two operations plus the four agent operations (§3), in the order
  `tools/list` shows them.
- `config/workloads.json` (authority) and `config/broker.json`: the shop (`named`) and `support-bot`
  (`enrolled` to `shop1`/`staff:carol`). The workloads file also sets `support_principals` and the
  `mandate.support_ticket` template, with ceilings of 5 refunds, 10 messages and €100.00 (broker README
  MD-1/MD-2).
- `config/adapter.json`: `support.wids` = the agent, with the same support principals (payments-adapter
  §16).
- `config/front.json`: the front's socket paths and uids, its tools, the enrolment it sends as `approver`,
  and the auth origin.
- `broker.json` sets the daily refund budget to 20 refunds per customer and currency. Demo P uses 3. With
  20, S10 is refused because of the remaining refundable amount, as §5 intends, and not because of the
  budget.

## Running

Use only [`tests/demoa/run.sh`](../../tests/demoa/run.sh). It generates every secret, key and test
certificate into `var/demoa/` (Git-ignored). Then it runs the script twice, each time on a fresh stack
(AT-26), followed by the conformance rows. Results go to `var/demoa/results.json`. Findings are in
[`tests/demoa/FINDINGS.md`](../../tests/demoa/FINDINGS.md).

Every image is pinned by digest, either directly or through its Dockerfile's base images.
