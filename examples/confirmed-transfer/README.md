# confirmed-transfer — Demo 2 (propose → confirm → execute)

> [!CAUTION]
> **Intentionally vulnerable, local only.** The PHP app exposes `POST /debug/eval` (remote code
> execution) to model an attacker with code execution inside the workload (threat actor C). The
> gateway is built and run with the credential-less **TEST LOGIN**. The only published port is
> bound to `127.0.0.1`. Never expose this stack to a network.

Demonstrates effect-protocol-v2 Draft 2 (ADR-0011): a compromised application can *propose* a
consequential effect but cannot hold, redirect, replay or alter an approved grant. A transfer is
executed only after the user approves the exact values on the auth origin, and exactly once.

## Topology

- **gateway** (TCB): the only service with a published port (`127.0.0.1:8443`); dev self-signed
  TLS; test login enabled. `gateway-port` is a dev-only loopback TCP relay (see
  `tests/demo2/FINDINGS.md` DEMO2-F01).
- **app trust domain** (untrusted): `web` (nginx, `network_mode: none`, Unix socket to the gateway
  only) + `app` (php-fpm, `network_mode: none`, P0 hardening, broker socket **W** only). `app2` is
  a second workload (tenant globex) used by the harness.
- **broker** (TCB): the only service on the DB network; listens on W, W2, G, A, each socket in its
  own volume mounted only where the spec allows.
- **authority** (TCB): `network_mode: none`; signing key `0400` in its own volume; sockets I and A.
- **db**: `pg_hba` accepts only the broker role from the broker's fixed address.

## Run

Requires Docker with Compose v2 (on macOS, a Linux VM such as Colima).

```sh
tests/demo2/run.sh            # generates secrets + authority key + registry, builds, runs, tears down
tests/demo2/run.sh --keep     # leave the stack running afterwards
```

The runner calls `nodkey-authority keygen` to create the signing key and the broker's key
registry, drives the legit flow and attack groups 1–12 (`tests/demo2/harness.py`), writes
`var/demo2/results.json` (Git-ignored) and prints a table. It exits non-zero on any FAIL.
