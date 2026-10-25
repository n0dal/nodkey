# Architecture

> [!IMPORTANT]
> Status: **DRAFT v0.3** (2026-10-25), revised after the
> [architecture review](reviews/2026-10-24-architecture-review.md) and the
> [ADR-0003/0009 review](reviews/2026-10-25-adr-0003-0009-review.md). Reflects ADR-0001…0009 (see
> [index](decisions/README.md) for status). Nothing is implemented or tested. The project name is
> **Nodkey** (owner decision, 2026-10-24; replaces the provisional name, OQ-02 resolved).

Nodkey is privilege separation for application effects, in the lineage of OpenSSH privsep, the Chromium
broker, and BeyondProd end-user context tickets ([research 01](research/01-prior-art.md)). The
untrusted workload computes; a broker holds credentials and executes typed operations only when a
grant, policy, and current trusted state all agree.

## 1. Components

| Component | Trust | Role | ADR |
|---|---|---|---|
| **Gateway edge** (Rust) | TCB | Only public listener; routes on `Host`. App origin: sessions, fetch-metadata checks, strict JSON/urlencoded parsing, route map → ≤ 1 write grant + ≤ 1 read grant, request/cookie allowlists, response policy (`no-store`, `nosniff`, Set-Cookie allowlist, SW rejection), pending-effect store. Auth origin: login code flow (built-in passkeys or delegated OIDC IdP), enrollment, recovery, confirmation pages | 0001, 0003 |
| **Gateway proxy** (Rust) | **Outside TCB**, no secrets | Strict HTTP/1.1 to the workload over UDS, one request per connection; returns a length-prefixed structure to the edge | 0003 |
| **Authority** (Rust) | TCB | Signs grants for the edge only; no network; no workload traffic | 0003, 0004 |
| **Workload**: PHP-FPM (+ optional nginx) + PHP SDK | **Untrusted** | Business logic; receives grant; submits `{grant, params}` | 0001, 0008 |
| **Broker** (Rust) | TCB | Per-workload UDS; strict verification; typed validation; read ops filtered by grant subject; Cedar; locked budgets; consumption; workflow state machine (Phase 5: `derived` transitions); audit rows | 0002, 0004–0007, 0009 |
| **DB** (Postgres) | Protected | Broker role only | 0001, 0006 |

Outside the TCB: the gateway proxy, the workload (PHP, extensions, Composer packages, SDK, nginx), browser code,
workflow orchestrators, container logs (never audit evidence), `verify` tooling.

## 2. Diagram

```mermaid
flowchart LR
  U[Browser<br/>untrusted] -->|HTTPS app origin| ED[Gateway edge<br/>sessions, route map,<br/>pending effects]
  U -->|HTTPS auth origin<br/>login, confirm| ED
  ED -->|UDS: scope to sign| AU[Authority<br/>signing key, no network]
  AU -->|grant| ED
  ED <-->|UDS: allowlisted request + grant /<br/>structured response| PX[Gateway proxy<br/>no secrets, untrusted]
  PX <-->|HTTP/1.1 over UDS| APP[Workload: nginx? + PHP-FPM<br/>network_mode none<br/>UNTRUSTED]
  APP -->|per-workload UDS<br/>grant + params| BR[Broker<br/>Rust, DB creds]
  ED -->|revoke-only UDS| BR
  BR -->|internal net, broker role| DB[(Postgres)]
  classDef untrusted fill:#fde2e2,stroke:#c00;
  classDef trusted fill:#e2f0fd,stroke:#036;
  class U,APP,PX untrusted;
  class ED,AU,BR,DB trusted;
```

## 3. Request flow: "refund $25 on order 9821"

**T** = trusted fact. **U** = untrusted (a request, never a fact).

1. Earlier: the user logged in with a user-verifying passkey on `auth.<domain>` through the bound code
   flow (ADR-0003 §2); the edge set a fresh `__Host-nodkey_session` on the app host (**T**).
2. Browser → edge: `POST /orders/9821/refund`, body `{"amount_cents":2500}`, cookie,
   `Sec-Fetch-Site: same-origin`. (**U**)
3. Edge: provenance check (SI-21); session lookup → `sub=u-17`, `ten=acme` (**T**); strict parse;
   route map → `ledger.refund`, `res={order:9821}` from `request:path`, `amount_cents ==2500` from
   `request:body:/amount_cents`, `currency` as a `state:` check (broker requires the order's currency)
   (**T**, derived from the request the browser sent — not necessarily the user's intent).
4. Gateway → authority: the derived scope; authority signs `{iss, aud=broker, wid=shop-php, ten, sub,
   op, opv, res, con, iat, nbf, exp=+30 s, jti}` (**T**).
5. Edge → proxy → workload: canonical path, exact query, allowlisted headers, app-owned cookies, the
   same body bytes it parsed, and `Nodkey-Grant` (plus a read grant if the route declares reads).
   (**U** from here.)
6. Workload → broker: `{grant, params:{order:9821, amount_cents:2500}}`. (**U**)
7. Broker: socket → `wid` + `SO_PEERCRED` (**T**); verify grant (ADR-0004); `sub`/`ten` sourced from
   it; params must equal `con`.
8. Broker transaction (ADR-0006): lock budget rows `(acme,u-17,day)`, `(acme,day)` → lock order row
   `WHERE tenant_id='acme' AND id=9821` → check `revoked_before`, pending UNKNOWN → Cedar on facts →
   insert `consumed_grant` → guarded writes (refund, budgets) → audit row → `COMMIT`. A deny after
   verification records `DENIED` for the `jti`.
9. Broker → workload: unsigned outcome + audit row id (evidence only).

After issue, a compromised workload cannot change the amount, order, user, tenant, or workload, or
reuse the grant. It can drop or delay the request (≤ 30 s), lie to the user, leak data, or — while the
user's tab is open — make the browser send *different* real requests, which are bound just as exactly
(THREAT_MODEL R-3). Only `confirm` routes bind intent.

**Confirmed variant** (`ledger.transfer` above the threshold, ADR-0003 §6): at step 3 the edge stores
a pending effect instead of forwarding, and redirects to `auth.<domain>/confirm/<pid>`. The user
approves the gateway-rendered summary with a passkey assertion committing to the exact values. The
browser returns to `/.nodkey/continue/<pid>`, where the edge signs the grant and forwards the stored
request.

## 4. Deployment profile P0

Containers: `gateway-edge`, `gateway-proxy` (untrusted side, P0 workload hardening, no network),
`authority`, `app` (PHP-FPM; nginx optional as a second untrusted container), `broker`, `db`. This
supersedes research 03 §8's four-container minimum. Recommended: the app origin on its own registrable
domain (THREAT_MODEL R-18).

**Phase 3 scope:** no grantless effects. The Demo 1 operations migrate: `ledger.transfer` becomes a
`user_grant` write (`from` = the subject's account, `to` exact, `confirm` above a threshold);
`ledger.get_balance` becomes a `read` operation filtered by owner = subject (ADR-0009).

- Workload: `network_mode: none`, read-only rootfs, `cap_drop: [ALL]`, `no-new-privileges`, default
  seccomp/LSM, private IPC/PID, distinct non-root UID, empty env, pids/memory limits, log driver
  `max-size`/`max-file`. Every writable mount — including the gateway↔app and app-internal FastCGI
  socket volumes — is tmpfs with `noexec,nosuid,nodev` and a size cap. Broker socket mounted read-only.
- Gateway edge: `edge` network only; no route to `data`. Gateway proxy: no network; UDS to the edge and
  to the workload only.
- Authority: no network; one UDS shared with the gateway only.
- Broker: `data` network; no egress or metadata access.
- DB: internal only, no published ports, `pg_hba` broker-only; storage on a filesystem the workload
  cannot fill.
- `verify` probes per research 03 §7, plus: exec from each writable mount (expect EACCES), file
  persistence across recreate (expect absent), `Service-Worker` request rejected, gateway-prefixed
  and non-allowlisted `Set-Cookie` dropped, duplicate gateway-named cookies rejected, non-allowlisted
  request headers absent at the app, `no-store`/`nosniff` on every app response, write grant refused for
  `GET`, cross-site, same-site-sibling, and header-less requests, login callback refused without the
  matching login cookie, upgrade/1xx/trailer responses refused by the proxy.

**P1** = P0 + gVisor for workload containers. WASI is a research track.

## 5. Invariant enforcement map

| SI | Enforced by | Verified by (planned) |
|---|---|---|
| SI-01 | P0 workload config | N-01..08, F-02, C-01..07 |
| SI-02 | Secrets only in TCB containers; gateway allowlist; auth origin | F-01; header-allowlist probes |
| SI-03 | `pg_hba` + role | D-01 |
| SI-04 | No authority conditioned on signatures | Review |
| SI-05 | Key only in authority | F-04; forged-grant vectors |
| SI-06 | Broker verifier; parameter classification and binding sources; read-op ownership filter | Vectors 12, 18, 19; unclassified-param startup test; read-grant-on-write and cross-owner read tests |
| SI-07 | No attenuation; params == / ≤ `con` | Vector 19 |
| SI-08 | Strict decoder; Cedar adapter | Vectors 1–17; B-01 |
| SI-09 | Consumption in effect transaction; DENIED recording | Vectors 21–23; **not claimed** across restore/clock rollback until ADR-0006 §8–9 tested |
| SI-10 | Grant-sourced `sub`/`ten`; DB facts | ID-substitution tests |
| SI-11 | Explicit locks, fixed order; guarded writes; locked budget counters | N = 64 cross-resource budget tests |
| SI-12 | Broker-owned workflow state; unsigned outcomes | Outcome-replay tests |
| SI-13 | Config not mounted in workload | F-03, F-04 |
| SI-14 | Deployment-only administration (v0 note) | NOT TESTED |
| SI-15 | Fail-closed handling; UNKNOWN state + precondition | Fault injection |
| SI-16 | Operation registry | B-01; review |
| SI-17 | Docs process; `verify` result classes | Doc review |
| SI-18 | Edge: auth origin, bound code flow, cookie rules, SW rejection, cache policy | Gateway probes above; browser spike (Chromium, Firefox, WebKit) |
| SI-19 | Authority classes; startup check; config-enforced tenancy; Phase 3: none | Grantless-op tests |
| SI-20 | Edge pending effects; auth-origin confirm page; WebAuthn challenge over the values | Confirm-bypass and value-substitution tests |
| SI-21 | Edge provenance checks | Forgery probes above |

## 6. Adoption modes

**Legacy Containment** (no SDK, no route map): network/OS isolation and evidence; credential removal
for allowlisted egress needs an egress proxy not in v0. No per-user or per-effect authorization. An app
that keeps its own DB credential, **or its own login form**, is not contained for those channels. Under
strict P0 an unmodified app that needs its own DB does not run; Legacy Containment needs its own,
not-yet-written profile.

**Native Effect Authorization** (gateway login, route map, typed operations, SDK): the flow in §3.
Limits: THREAT_MODEL R-2..R-7 and R-16..R-18, especially in-page abuse while a user is active, bounded
by budgets except on `confirm` routes. Not supported in v1: multipart bodies on mapped routes,
app-side destination resolution, multi-effect writes per request, batches, wizards whose final POST
carries no values, service workers. Migration from Legacy is route by route; login moves to the auth
origin first.

**Comparison baseline:** for internal-DB-only effects, P0 isolation + PostgREST RPC-only + RLS with a
gateway-signed JWT provides essentially the same guarantees with less new code (ADR-0002, AR-14).
Nodkey's distinct value is the gateway binding, external-effect handling, and multi-workload identity;
OQ-01 remains open until that baseline is tested.
