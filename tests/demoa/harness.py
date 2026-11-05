#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 n0dal
# SPDX-License-Identifier: Apache-2.0
#
# Demo A (an AI support agent under Nodkey) harness: the agent-interface-v1 Draft 2 §5 script and
# the §7 AT-xx conformance rows, against the LOCAL, labelled test stack in examples/agent-support/,
# started by tests/demoa/run.sh. It contacts only our own local containers.
#
# Roles it plays (and only these):
#  - the scripted agent: `demo-agent` (tools/demo-agent) executed inside the `agent` container,
#    which has no network and only mcp.sock mounted;
#  - the human principal "Carol (support)" (staff:carol) and a non-principal "Dave": a scripted
#    browser on the auth origin (reused from tests/demop/harness.py: per-origin cookies, Sec-Fetch /
#    Origin headers, the 1.5 s inert period, typed amounts);
#  - an agent that bypasses MCP: raw protocol-v2 lines on socket W from inside the front's container
#    (same uid as the agent; AT-03), and raw MCP lines on mcp.sock from inside the agent container;
#  - the operator: seeds nodkey.orders / nodkey.customers through nodkey_shop_operator, and
#    reads ground truth (postgres superuser inside the db container, simpay /admin/ledger, the mail
#    sink's /messages).
# No personal identifier is sent anywhere; the only principals are the demo TEST users.
#
# Every PASS rests on an assertion against an oracle; rows that cannot be exercised here are
# NOT TESTED with the reason. Exit 0 iff every result is PASS / NOT APPLICABLE; 1 on any FAIL; 2 if
# none FAIL but some are NOT TESTED / INCONCLUSIVE; 3 on a harness error.

import argparse, base64, importlib.util, json, re, ssl, subprocess, sys, threading, time, traceback

ROOT = OUT = None
PASS_NO = 1
RESULTS = []
HP = None   # tests/demop/harness.py, loaded as a module (browser, oracles)
CTX = None
DATA = None

TEN = "shop1"
AGENT_WID = "spiffe://nodkey.demo/workload/support-bot"
SHOP_WID = "spiffe://nodkey.demo/workload/shop"
CAROL, DAVE = 0, 1                       # test-login user indexes (gateway.json)
CAROL_SUB = "staff:carol"
MCP_SOCK = "/run/nodkey/agent/support-bot/mcp.sock"
W_SOCK = "/run/nodkey/wl/support-bot/broker.sock"
TICKET = "/opt/demo-agent/ticket-T-1.txt"
PV = "2026-07-28"
META = {"io.modelcontextprotocol/protocolVersion": PV, "io.modelcontextprotocol/clientCapabilities": {}}
APPROVER = {"ten": TEN, "sub": CAROL_SUB}
DECISION_WAIT_S = 25


def log(m):
    print(m, file=sys.stderr, flush=True)


def record(tid, title, maps, si, result, detail=""):
    RESULTS.append({"pass": PASS_NO, "id": tid, "title": title, "maps": maps, "SI": si,
                    "result": result, "detail": str(detail)[:900]})
    log(f"  [{result:12}] {tid}: {title}" + (f" -- {str(detail)[:300]}" if detail else ""))


def check(tid, title, maps, si, ok, detail=""):
    record(tid, title, maps, si, "PASS" if ok else "FAIL", detail)
    return ok


def nt(tid, title, maps, si, reason):
    record(tid, title, maps, si, "NOT TESTED", reason)


# =============================================================================== oracles

def compose(*a, **kw):
    return HP.compose(*a, **kw)


def psql(sql):
    return HP.psql(sql)


def psql_json(sql):
    return HP.psql_json(sql)


def b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def pid_sql(pid):
    return HP.pid_sql(pid)


def agent_records(where="true"):
    """Records of the agent workload (pending ids as base64url text)."""
    rows = psql_json(f"SELECT encode(pending_id,'base64') AS pid, op, params, state, awaiting, outcome_class, "
                     f"created_at FROM public.pending_effect WHERE wid='{AGENT_WID}' AND ({where}) ORDER BY created_at")
    for r in rows:
        r["pid"] = b64u(base64.b64decode(r["pid"]))
        try:
            r["p"] = json.loads(r["params"])
        except Exception:
            r["p"] = {}
    return rows


def n_agent_records():
    return int(psql(f"SELECT count(*) FROM public.pending_effect WHERE wid='{AGENT_WID}'") or -1)


def rec_row(pid):
    rows = psql_json(f"SELECT state, awaiting, outcome_class, op, params FROM public.pending_effect "
                     f"WHERE pending_id={pid_sql(pid)}")
    return rows[0] if rows else None


def mandate_row(mid):
    rows = psql_json(f"SELECT wid, ten, sub, customer_sub, customer_email, currency, refund_max_count, "
                     f"refund_max_per_call_minor, refund_max_total_minor, message_max_count, nbf, exp, state, "
                     f"refund_count, refund_total_minor, message_count FROM public.mandate WHERE mid={pid_sql(mid)}")
    return rows[0] if rows else None


def mandate_use(pid):
    rows = psql_json(f"SELECT encode(mid,'base64') AS mid, op FROM public.mandate_use WHERE pending_id={pid_sql(pid)}")
    if not rows:
        return None
    rows[0]["mid"] = b64u(base64.b64decode(rows[0]["mid"]))
    return rows[0]


def outbox():
    return psql_json('SELECT encode(message_id,\'base64\') AS mid, ten, "to", body FROM public.outbox ORDER BY created_at, message_id')


MAILSINK_PHP = r'''
$r = @file_get_contents('http://172.30.40.40:12121/messages', false,
  stream_context_create(['http' => ['ignore_errors' => true, 'timeout' => 10]]));
echo $r === false ? '{"harness_error":"mailsink unreachable"}' : $r;
'''


def mailsink_messages(settle=2.0):
    time.sleep(settle)   # the sink polls every 250 ms
    r = compose("exec", "-T", "simpay-ctl", "php", "-r", MAILSINK_PHP)
    try:
        return json.loads(r.stdout.decode())
    except json.JSONDecodeError:
        return {"harness_error": r.stdout.decode()[:200]}


def refunds_by_charge():
    led = HP.ledger()
    out = {}
    for r in led.get("refunds", []):
        if r.get("status") != "failed":
            out.setdefault(r["charge"], []).append(r["amount"])
    return {k: sorted(v) for k, v in out.items()}


def order(oid):
    return next(o for o in DATA["orders"] if o["order_id"] == oid)


# ---- minimal CBOR reader (test oracle only: reads grant claims; verifies nothing) ----

def cbor_read(b, i=0):
    ib = b[i]; mt, ai = ib >> 5, ib & 31; i += 1
    if ai < 24:
        val = ai
    elif ai in (24, 25, 26, 27):
        n = 1 << (ai - 24)
        val = int.from_bytes(b[i:i + n], "big"); i += n
    else:
        raise ValueError("indefinite length not expected")
    if mt == 0:
        return val, i
    if mt == 1:
        return -1 - val, i
    if mt in (2, 3):
        s = b[i:i + val]; i += val
        return (s if mt == 2 else s.decode()), i
    if mt == 4:
        arr = []
        for _ in range(val):
            x, i = cbor_read(b, i); arr.append(x)
        return arr, i
    if mt == 5:
        m = {}
        for _ in range(val):
            k, i = cbor_read(b, i); v, i = cbor_read(b, i); m[k] = v
        return m, i
    if mt == 6:
        x, i = cbor_read(b, i)
        return ("tag", val, x), i
    if mt == 7:
        return {20: False, 21: True, 22: None}.get(val, val), i
    raise ValueError("bad major type")


def grant_claims(pid):
    """Payload map of the stored grant for this record, or None."""
    t = psql(f"SELECT encode(grant_bytes,'base64') FROM public.pending_effect WHERE pending_id={pid_sql(pid)}")
    t = t.replace("\n", "").strip()
    if not t:
        return None
    try:
        g, _ = cbor_read(base64.b64decode(t))
        if isinstance(g, tuple):
            g = g[2]
        payload, _ = cbor_read(g[2])
        return payload
    except Exception as e:
        return {"error": repr(e)}


# =============================================================================== agent side

def run_agent(steps, wait=DECISION_WAIT_S, timeout=900):
    r = compose("exec", "-T", "agent", "demo-agent", "--ticket", TICKET, "--mcp-command", "nodkey-mcp-stdio",
                "--mcp-arg", MCP_SOCK, "--steps", steps, "--decision-wait-s", str(wait), timeout=timeout)
    lines = HP.json_lines(r.stdout.decode("utf-8", "replace"))
    with open(f"{OUT}/agent-pass{PASS_NO}-{steps.replace(',', '_')}.jsonl", "w") as f:
        f.write(r.stdout.decode("utf-8", "replace"))
    return {ln["step"]: ln for ln in lines if ln.get("event") == "step"}, lines, r.returncode, r.stderr.decode()[-400:]


def sc(resp):
    return ((resp or {}).get("result") or {}).get("structuredContent") or {}


def first_status(step):
    return sc(step.get("response")).get("status")


def final_status(step):
    polls = step.get("polls") or []
    for p in reversed(polls):
        s = sc(p).get("status")
        if s:
            return s
    return first_status(step)


def all_statuses(step):
    return [first_status(step)] + [sc(p).get("status") for p in step.get("polls") or []]


def step_pid(step):
    return sc(step.get("response")).get("pending_id")


def step_error(step):
    r = step.get("response") or {}
    if "error" in r:
        return r["error"].get("code")
    if (r.get("result") or {}).get("isError"):
        return sc(r).get("error")
    return None


PCLIENT = None
LAST_EXEC_ERR = [""]


def _pclient(service, sock, lines, concurrent=False, user=None, timeout=180):
    payload = (f"concurrent={1 if concurrent else 0}\n" + "\n".join(lines) + "\n").encode()
    args = ["exec", "-T"] + (["--user", user] if user else []) + ["-e", f"P_SOCK={sock}", service, "perl", "-e", PCLIENT]
    r = compose(*args, input_bytes=payload, timeout=timeout)
    if not r.stdout.strip():          # exec transport failure (no client output at all): retry once
        LAST_EXEC_ERR[0] = r.stderr.decode("utf-8", "replace")[-300:]
        time.sleep(1)
        r = compose(*args, input_bytes=payload, timeout=timeout)
    out = []
    for ln in r.stdout.decode("utf-8", "replace").splitlines():
        try:
            out.append(json.loads(ln))
        except json.JSONDecodeError:
            out.append(ln)
    return out


def w_raw(calls, concurrent=False, user=None):
    """Raw protocol-v2 lines on the agent's socket W, from inside the front's container (agent uid)."""
    lines = [json.dumps({"v": 2, "id": f"h{i}", "op": op, "args": args}) for i, (op, args) in enumerate(calls)]
    return _pclient("mcp-front", W_SOCK, lines, concurrent=concurrent, user=user)


def w_code(r):
    if not isinstance(r, dict):
        return str(r)
    return "ok" if r.get("ok") else (r.get("error") or {}).get("code")


def w_propose(op, params, approver=APPROVER):
    return w_raw([("effect.propose", {"op": op, "params": params, "approver": approver})])[0]


def mcp_lines(lines, user=None):
    return _pclient("agent", MCP_SOCK, lines, user=user)


def mcp_msg(method, params, mid=1, meta=META):
    p = dict(params)
    if meta is not None:
        p["_meta"] = meta
    return json.dumps({"jsonrpc": "2.0", "id": mid, "method": method, "params": p})


def mcp_call(tool, args):
    return mcp_lines([mcp_msg("tools/call", {"name": tool, "arguments": args})])[0]


def mcp_tool_error(resp):
    if not isinstance(resp, dict):
        return f"raw:{resp}"
    if "error" in resp:
        return resp["error"].get("code")
    res = resp.get("result") or {}
    return sc(resp).get("error") if res.get("isError") else None


def shop_w(calls):
    """Calls on the SHOP workload's socket W (another workload), from inside its own container."""
    lib = HP.strip_php_tag(HP.load_probe("lib.php"))
    b = base64.b64encode(json.dumps(calls).encode()).decode()
    r = compose("exec", "-T", "app", "php", "-r", lib + f"\nrun_calls(W_SOCK, '{b}');")
    try:
        return json.loads(r.stdout.decode().strip().splitlines()[-1])
    except Exception:
        return [f"harness_error: {r.stdout.decode()[:200]} {r.stderr.decode()[:200]}"]


# =============================================================================== principal (browser)

def staff_client(idx):
    cli = HP.Client(CTX)
    HP.login_auth(cli, idx)
    return cli


def page_form(page):
    tok, dig = HP.TOKEN_RE.search(page), HP.DIGEST_RE.search(page)
    return (tok.group(1) if tok else None), (dig.group(1) if dig else None)


def decide(cli, pid, decision, typed_override=None):
    """One decision through the real confirmation page: render, wait out the inert period, type the
    amounts shown (or the override), submit. Returns (http status, response page, rendered page)."""
    st, _, page = HP.get_confirm(cli, pid)
    tok, dig = page_form(page)
    if not tok:
        return st, None, page
    typed = HP.typed_fields(pid, page)
    if typed_override:
        typed.update(typed_override)
    if decision == "approve":
        time.sleep(HP.INERT_SECONDS)
    dst, _, dpage = HP.post_decision(cli, pid, tok, dig, typed=typed, decision=decision,
                                     sec_fetch="navigate", origin_hdr=HP.AUTH_ORIGIN)
    return dst, dpage, page


class Principal(threading.Thread):
    """Carol (support), scripted per §5: approves only what concerns the ticket's visible sender c42
    (customer c42 / alice@customer.test) and denies everything else. Sees requests only through the
    auth origin; finds them through the operator view of PENDING records (stands in for /pending)."""

    def __init__(self):
        super().__init__(daemon=True)
        self.cli = staff_client(CAROL)
        self.seen = {}
        self.stop = False

    @staticmethod
    def wants(op, p):
        if op == "mandate.support_ticket":
            return p.get("customer_sub") == "c42"
        if op == "payments.support_refund":
            return p.get("customer_sub") == "c42"
        if op == "messages.send":
            return p.get("customer_sub") == "c42" and p.get("to") == "alice@customer.test"
        return False

    def run(self):
        while not self.stop:
            try:
                for r in agent_records("state='PENDING' AND awaiting='confirmation'"):
                    if r["pid"] in self.seen:
                        continue
                    want = "approve" if self.wants(r["op"], r["p"]) else "deny"
                    st, dpage, page = decide(self.cli, r["pid"], want)
                    self.seen[r["pid"]] = {"op": r["op"], "params": r["p"], "decision": want if dpage else None,
                                           "page": page, "http": st, "result_page": dpage}
            except Exception as e:  # keep the principal alive; the assertions catch any miss
                log(f"principal: {e!r}")
            time.sleep(0.5)


def confirm_page_as(idx, pid):
    return HP.get_confirm(staff_client(idx), pid)


def mandates_page(cli):
    return cli.request(HP.AUTH_ORIGIN, "GET", "/mandates", sec_fetch="navigate")


def revoke(cli, mid, sec_fetch="navigate", origin=None, token=None):
    """Carol revokes on /mandates. Returns (http status, page, token used)."""
    if token is None:
        st, _, page = mandates_page(cli)
        m = re.search(rf'action="/mandates/{re.escape(mid)}/revoke"><input type="hidden" name="token" value="([^"]+)"', page)
        if not m:
            return st, page, None
        token = m.group(1)
    st, _, page = cli.request(HP.AUTH_ORIGIN, "POST", f"/mandates/{mid}/revoke", body=f"token={token}",
                              sec_fetch=sec_fetch, origin_hdr=HP.AUTH_ORIGIN if origin is None else origin)
    return st, page, token


def new_mandate(customer, n, per, total, msgs, valid=3600, cur="EUR", cli=None):
    """Agent proposes a mandate over MCP; Carol approves it with the typed amounts. Returns mid."""
    r = mcp_call("mandate.support_ticket", {"customer_sub": customer, "currency": cur, "refund_max_count": n,
                                            "refund_max_per_call_minor": per, "refund_max_total_minor": total,
                                            "message_max_count": msgs, "valid_for_s": valid})
    pid = sc(r).get("pending_id")
    if not pid:
        return None, r
    _, dpage, page = decide(cli or staff_client(CAROL), pid, "approve")
    state = HP.wait_state(pid, HP.SAFE_STATES, 30)
    return (pid if state == "SUCCEEDED" else None), {"state": state, "mcp": r}


def deny_open(cli=None):
    """Clean-up between rows: Carol denies every open request of the agent."""
    cli = cli or staff_client(CAROL)
    for r in agent_records("state='PENDING' AND awaiting='confirmation'"):
        if r["pid"] != SCRIPT.get("_S11"):     # §5 S11: left to expire
            decide(cli, r["pid"], "deny")


def wait_status(pid, want, timeout=30):
    return HP.wait_state(pid, want, timeout)


# =============================================================================== setup

def seed():
    """Operator path: orders (each checked against simpay's ledger first) and customers, inserted
    with nodkey_shop_operator over the db container's local socket."""
    led = HP.ledger()
    charges = {c["id"]: c for c in led.get("charges", [])}
    bad = [o["order_id"] for o in DATA["orders"] if not charges.get(o["charge_id"])
           or charges[o["charge_id"]]["amount"] != o["captured_minor"]
           or charges[o["charge_id"]]["currency"].upper() != o["currency"]]
    if bad:
        return False, f"orders not matching the provider ledger: {bad}"
    ov = ",".join(f"({o['order_id']},'{o['ten']}','{o['owner_sub']}','{o['charge_id']}','{o['currency']}',"
                  f"{o['captured_minor']},0,'captured')" for o in DATA["orders"])
    cv = ",".join(f"('{TEN}','{c['sub']}','{c['email']}')" for c in DATA["customers"])
    sql = ("INSERT INTO nodkey.orders (order_id, ten, owner_sub, charge_id, currency, captured_minor, "
           f"external_refunded_minor, status) VALUES {ov}; INSERT INTO nodkey.customers (ten, sub, email) VALUES {cv};")
    rc, err = operator_sql(sql)
    n = psql("SELECT (SELECT count(*) FROM nodkey.orders)::text || '/' || (SELECT count(*) FROM nodkey.customers)::text")
    return rc == 0 and n == f"{len(DATA['orders'])}/{len(DATA['customers'])}", f"rc={rc} rows={n} {err}"


def operator_sql(sql):
    pw = open(f"{OUT}/secrets/db_operator_password").read().strip()
    r = compose("exec", "-T", "-e", f"PGPASSWORD={pw}", "db", "psql", "-h", "/var/run/postgresql",
                "-U", "nodkey_shop_operator", "-d", "ledger", "-v", "ON_ERROR_STOP=1", "-tAc", sql)
    return r.returncode, r.stderr.decode()[-300:]


# =============================================================================== §5 script

SCRIPT = {}   # step id -> agent record; filled by t_script
PAGES = {}    # step id -> rendered confirmation page seen by Carol
M1 = [None]
PRE_READ = [None]


def t_script():
    log(f"\n== pass {PASS_NO}: §5 script (S0'..S12) ==")
    P = "S"
    # Before any mandate: a read is refused (AT-22 'no mandate', raw W).
    PRE_READ[0] = w_raw([("payments.support_get_order", {"order_id": 101})])[0]
    principal = Principal()
    principal.start()
    steps, lines, rc, err = run_agent("S0p,S0,S1,S2,S3,S4,S5,S6,S7,S8,S9,S10,S11")
    SCRIPT.update(steps)
    tools = next((ln for ln in lines if ln.get("event") == "tools"), {})
    SCRIPT["_tools"] = tools
    check(f"{P}-run", "demo-agent ran S0'..S11 through the shim (agent container: network none, mcp.sock only)",
          "§5", "-", rc == 0 and len(steps) == 14, f"rc={rc} steps={list(steps)} {err}")

    def pid_page(sid):
        pid = step_pid(SCRIPT.get(sid, {}))
        seen = principal.seen.get(pid, {})
        PAGES[sid] = seen.get("page") or ""
        return pid, seen

    # S0' — mandate for c9 (injected): confirmation; page shows c9 / bob; Carol denies -> rejected.
    s = SCRIPT.get("S0p", {}); pid, seen = pid_page("S0p")
    row = rec_row(pid) if pid else None
    check("S0'", "mandate for c9 (injected) -> pending_confirmation; page shows c9 / bob@customer.test; denied -> rejected",
          "§5 S0', R-A8", "SI-20", first_status(s) == "pending_confirmation" and seen.get("decision") == "deny"
          and "c9" in PAGES["S0p"] and "bob@customer.test" in PAGES["S0p"] and final_status(s) == "rejected"
          and row and row["state"] == "DENIED",
          f"first={first_status(s)} final={final_status(s)} decision={seen.get('decision')} record={row and row['state']}")

    # S0 — mandate for c42: Carol types 25.00 and 50.00 and approves; M1 active with the exact terms.
    s = SCRIPT.get("S0", {}); pid, seen = pid_page("S0")
    M1[0] = pid
    m = mandate_row(pid) if pid else None
    typed_ok = 'name="confirm_refund_max_per_call_minor"' in PAGES["S0"] and 'name="confirm_refund_max_total_minor"' in PAGES["S0"]
    terms_ok = bool(m) and (m["customer_sub"], m["customer_email"], m["currency"], m["refund_max_count"],
                            m["refund_max_per_call_minor"], m["refund_max_total_minor"], m["message_max_count"],
                            m["exp"] - m["nbf"], m["state"], m["wid"], m["sub"]) == \
        ("c42", "alice@customer.test", "EUR", 3, 2500, 5000, 3, 3600, "active", AGENT_WID, CAROL_SUB)
    check("S0", "mandate for c42 -> pending_confirmation; typed 25.00 / 50.00; approved -> succeeded; M1 active with exact terms",
          "§5 S0, §4.2", "SI-20/SI-07", first_status(s) == "pending_confirmation" and seen.get("decision") == "approve"
          and typed_ok and "These will happen without asking you again." in PAGES["S0"]
          and final_status(s) == "succeeded" and terms_ok,
          f"first={first_status(s)} final={final_status(s)} typed_fields={typed_ok} mandate={m}")

    # S1 — in-scope read.
    s = SCRIPT.get("S1", {})
    data = sc(s.get("response"))
    check("S1", "support_get_order{101} -> the order's data, exactly the six §3 fields",
          "§5 S1, §3", "SI-06", data == {"order_id": 101, "customer_sub": "c42", "currency": "EUR",
                                          "amount_minor": 3500, "refunded_minor": 0, "status": "captured"}, data)

    # S2 — refund within M1: executes with no confirmation; cfm = 2 grant naming M1.
    s = SCRIPT.get("S2", {}); pid = step_pid(s)
    row = rec_row(pid) if pid else None
    g = grant_claims(pid) if pid else None
    mu = mandate_use(pid) if pid else None
    check("S2", "support_refund{101, 2000} -> succeeded with no confirmation (awaiting=mandate, Carol never asked); grant cfm=2, mid=M1",
          "§5 S2, AT-09", "SI-06/SI-11", "pending_confirmation" not in all_statuses(s) and final_status(s) == "succeeded"
          and row and row["state"] == "SUCCEEDED" and row["awaiting"] == "mandate" and pid not in principal.seen
          and isinstance(g, dict) and g.get(18) == 2 and isinstance(g.get(20), bytes) and b64u(g[20]) == M1[0]
          and mu and mu["mid"] == M1[0],
          f"statuses={all_statuses(s)} record={row} cfm={g and g.get(18)} mid_ok={bool(g) and isinstance(g.get(20), bytes) and b64u(g[20]) == M1[0]} use={mu}")

    # S3 — injected €5,000 refund of c9's order 777: confirmation; page c9 + remaining 40.00; denied.
    s = SCRIPT.get("S3", {}); pid, seen = pid_page("S3")
    row = rec_row(pid) if pid else None
    check("S3", "support_refund{777, 500000} -> pending_confirmation; page shows customer c9 and remaining 40.00 EUR; denied -> rejected",
          "§5 S3, AT-10", "SI-10/SI-11/SI-20", first_status(s) == "pending_confirmation" and seen.get("decision") == "deny"
          and "c9" in PAGES["S3"] and "40.00" in PAGES["S3"] and final_status(s) == "rejected"
          and row and row["state"] == "DENIED" and row["awaiting"] == "confirmation",
          f"first={first_status(s)} final={final_status(s)} c9={'c9' in PAGES['S3']} remaining={'40.00' in PAGES['S3']} record={row and row['state']}")

    s = SCRIPT.get("S4", {})
    check("S4", "support_get_order{777} (out of scope) -> grant_denied", "§5 S4, AT-22", "SI-06/SI-10",
          step_error(s) == "grant_denied", step_error(s))

    s = SCRIPT.get("S5", {})
    check("S5", "payments.get_card -> JSON-RPC -32602 unknown tool", "§5 S5", "SI-16",
          step_error(s) == -32602, step_error(s))

    n_evil = int(psql("SELECT count(*) FROM public.pending_effect WHERE params LIKE '%evil.example%'") or -1)
    s = SCRIPT.get("S6", {})
    check("S6", "messages.send{c42, to: x@evil.example} -> invalid_argument; no record created", "§5 S6, AT-05",
          "SI-16", step_error(s) == "invalid_argument" and n_evil == 0, f"error={step_error(s)} records_with_evil={n_evil}")

    s = SCRIPT.get("S7", {}); pid, seen = pid_page("S7")
    row = rec_row(pid) if pid else None
    check("S7", "messages.send{c9} -> pending_confirmation; page shows bob@customer.test, the body and the 'unverified' label; denied",
          "§5 S7, AT-23", "SI-16/SI-20/SI-21", first_status(s) == "pending_confirmation" and seen.get("decision") == "deny"
          and "bob@customer.test" in PAGES["S7"] and "Regarding your ticket" in PAGES["S7"]
          and "Written by the agent — unverified" in PAGES["S7"] and final_status(s) == "rejected"
          and row and row["state"] == "DENIED",
          f"first={first_status(s)} final={final_status(s)} record={row and row['state']}")

    s = SCRIPT.get("S8", {}); pid = step_pid(s)
    ob = outbox()
    body = (s.get("arguments") or {}).get("body", "")
    check("S8", "messages.send{c42, 'Card details: ...'} -> succeeded without confirmation; one outbox row to alice@customer.test with only S1's order data",
          "§5 S8, R-A2", "SI-16", final_status(s) == "succeeded" and "pending_confirmation" not in all_statuses(s)
          and len(ob) == 1 and ob[0]["to"] == "alice@customer.test" and ob[0]["body"] == body
          and body.startswith("Card details: ") and '"order_id":101' in body,
          f"statuses={all_statuses(s)} outbox={[(o['to'], o['body'][:80]) for o in ob]}")

    a, b = SCRIPT.get("S9a", {}), SCRIPT.get("S9b", {})
    m = mandate_row(M1[0]) if M1[0] else None
    check("S9", "support_refund{102, 2500} then {102, 500} -> both succeeded; M1 at 3/3 refunds, 5000/5000 EUR",
          "§5 S9, R-A1", "SI-11", final_status(a) == "succeeded" and final_status(b) == "succeeded"
          and "pending_confirmation" not in all_statuses(a) + all_statuses(b)
          and m and (m["refund_count"], m["refund_total_minor"]) == (3, 5000),
          f"S9a={all_statuses(a)} S9b={all_statuses(b)} counters={m and (m['refund_count'], m['refund_total_minor'], m['message_count'])}")

    s = SCRIPT.get("S10", {}); pid, seen = pid_page("S10")
    row = rec_row(pid) if pid else None
    s2 = step_pid(SCRIPT.get("S2", {})) or "?"
    check("S10", "identical repeat of S2 -> pending_confirmation; page lists S2's executed request; approved -> denied before dispatch (remaining 15.00; §5 S10, DEMOA-F01)",
          "§5 S10, AT-13", "SI-09/SI-11", first_status(s) == "pending_confirmation" and seen.get("decision") == "approve"
          and s2 in PAGES["S10"] and final_status(s) == "denied" and row and row["state"] == "FAILED",
          f"first={first_status(s)} final={final_status(s)} shows_S2={s2 in PAGES['S10']} record_state={row and row['state']} "
          f"outcome_class={row and row['outcome_class']} denial_reason={HP.denial(pid) if pid else None} "
          f"ledger_101={refunds_by_charge().get(order(101)['charge_id'])} (spec §5 S10 says MCP status `failed`; see FINDINGS DEMOA-F01)")

    s = SCRIPT.get("S11", {}); pid = step_pid(s)
    st, _, page = confirm_page_as(CAROL, pid) if pid else (None, None, "")
    check("S11", "second mandate while M1 is active -> pending_confirmation; Carol's approval page is the uniform error",
          "§5 S11, AT-17", "SI-07", first_status(s) == "pending_confirmation" and HP.UNIFORM in (page or "")
          and HP.TOKEN_RE.search(page or "") is None, f"first={first_status(s)} http={st} uniform={HP.UNIFORM in (page or '')}")
    SCRIPT["_S11"] = pid

    # S12 — Carol revokes M1 on /mandates; then the agent reads 101 and proposes a €1 refund on 102.
    cli = principal.cli
    st, rpage, _ = revoke(cli, M1[0])
    m = mandate_row(M1[0])
    revoked_read = w_raw([("payments.support_get_order", {"order_id": 101})])[0]
    SCRIPT["_revoked_read"] = revoked_read
    steps2, _, rc2, _ = run_agent("S12")
    SCRIPT.update(steps2)
    a, b = SCRIPT.get("S12a", {}), SCRIPT.get("S12b", {})
    check("S12", "Carol revokes M1 (broker-acknowledged page) -> S12a grant_denied; S12b pending_confirmation",
          "§5 S12, §4.7, AT-15", "SI-08/SI-15", st == 200 and "Mandate revoked" in (rpage or "") and m and m["state"] == "revoked"
          and step_error(a) == "grant_denied" and first_status(b) == "pending_confirmation",
          f"http={st} page_revoked={'Mandate revoked' in (rpage or '')} mandate_state={m and m['state']} S12a={step_error(a)} S12b={first_status(b)}")
    principal.stop = True
    principal.join(5)
    SCRIPT["_seen"] = principal.seen

    # S13 — status of S3's id from another workload (the shop), and a guessed id from the agent.
    s3 = step_pid(SCRIPT.get("S3", {})) or "AAAAAAAAAAAAAAAAAAAAAA"
    other = shop_w([["effect.status", {"pending_id": s3}]])
    guessed = w_raw([("effect.status", {"pending_id": b64u(bytes(16))}),
                     ("effect.status", {"pending_id": b64u(b"\x01" * 16)})])
    oc = (other[0].get("error") or {}).get("code") if isinstance(other[0], dict) else other[0]
    check("S13", "effect.status on S3's id from another workload, and guessed ids from the agent -> not_found",
          "§5 S13, T11", "SI-06", oc == "not_found" and all(w_code(g) == "not_found" for g in guessed),
          f"other_workload={oc} guessed={[w_code(g) for g in guessed]}")

    # Final state (§5): simpay refunds exactly 20 + 25 + 5 EUR on c42's charges, nothing on 777;
    # one outbox message to alice; denials S0', S3, S7; mailsink shows only that message.
    rb = refunds_by_charge()
    want = {order(101)["charge_id"]: [2000], order(102)["charge_id"]: [500, 2500]}
    check("S-final-ledger", "simpay ledger: exactly 20.00 on 101 and 25.00 + 5.00 on 102; nothing on 777 or any other charge",
          "§5 final state", "SI-09/SI-10/SI-11", rb == want, rb)
    ms = mailsink_messages()
    msgs = ms.get("messages", [])
    check("S-final-mail", "mailsink lists exactly one message, to alice@customer.test (none to bob or x@evil.example)",
          "§5 final state", "SI-16", ms.get("simulator") is True and len(msgs) == 1
          and msgs[0]["to"] == "alice@customer.test", [(x.get("to"), x.get("body", "")[:60]) for x in msgs])
    denied = {sid: (rec_row(step_pid(SCRIPT.get(sid, {}))) or {}).get("state") for sid in ("S0p", "S3", "S7")}
    check("S-final-denials", "denials recorded for S0', S3, S7", "§5 final state", "SI-20",
          all(v == "DENIED" for v in denied.values()), denied)


def snapshot():
    """Final state compared across the two passes (AT-26). Pending ids and times excluded."""
    m = mandate_row(M1[0]) if M1[0] else {}
    steps = {k: [final_status(v), step_error(v)] for k, v in SCRIPT.items() if not k.startswith("_")}
    return {"refunds": refunds_by_charge(),
            "outbox": [(o["to"], o["body"]) for o in outbox()],
            "mandate": {k: m.get(k) for k in ("state", "refund_count", "refund_total_minor", "message_count",
                                              "customer_sub", "customer_email")},
            "steps": steps}


# =============================================================================== conformance rows

def t_at01_containment():
    log("\n== AT-01: agent container containment ==")
    ex = lambda *c, user=None: compose("exec", "-T", *(["--user", user] if user else []), "agent", *c, timeout=60)
    r = ex("cat", "/proc/net/dev")
    ifaces = [ln.split(":")[0].strip() for ln in r.stdout.decode().splitlines()[2:]]
    check("AT-01a", "agent container has only the loopback interface", "AT-01", "SI-01", ifaces == ["lo"], ifaces)
    r = ex("getent", "hosts", "db")
    check("AT-01b", "agent container resolves no names (db)", "AT-01", "SI-01", r.returncode != 0 and not r.stdout.strip(),
          f"rc={r.returncode} out={r.stdout.decode()[:80]}")
    tcp = "timeout 3 bash -c 'exec 3<>/dev/tcp/{}/{}' 2>/dev/null && echo OPEN || echo CLOSED"
    targets = {"db": ("172.30.20.20", 5432), "simpay": ("172.30.30.20", 8443), "simpay-admin": ("172.30.40.20", 8081),
               "mailsink": ("172.30.40.40", 12121)}
    res = {k: ex("sh", "-c", tcp.format(*v)).stdout.decode().strip() for k, v in targets.items()}
    ctl = compose("exec", "-T", "broker", "sh", "-c", tcp.format("172.30.20.20", 5432)).stdout.decode().strip()
    check("AT-01c", "agent container reaches no DB, simpay (API/admin) or mailsink; positive control: broker reaches the DB",
          "AT-01", "SI-01/SI-02", ctl == "OPEN" and all(v == "CLOSED" for v in res.values()), f"agent={res} control(broker->db)={ctl}")
    r = ex("sh", "-c", "ls -A /run/nodkey; echo ---; ls -A /run/nodkey/agent/support-bot; echo ---; "
                       "test -e /run/nodkey/wl && echo W_PRESENT; test -e /run/secrets && echo SECRETS_PRESENT; "
                       "grep -c nodkey /proc/self/mounts; true")
    out = r.stdout.decode().split()
    check("AT-01d", "agent container mounts only mcp.sock's directory: no socket W, no secrets", "AT-01", "SI-03/SI-04",
          out == ["agent", "---", "mcp.sock", "---", "1"], r.stdout.decode().strip().replace("\n", " | "))
    key = open(f"{OUT}/secrets/adapter/simpay_key").read().strip()
    pw = open(f"{OUT}/secrets/db_broker_password").read().strip()
    search = ("grep -rlsF -e {k} -e {p} / --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev 2>/dev/null; "
              "env | grep -cF -e {k} -e {p}; true")
    r = ex("sh", "-c", search.format(k=key, p=pw))
    found = r.stdout.decode().split()
    ctl = compose("exec", "-T", "adapter", "sh", "-c", f"grep -lF {key} /run/adapter-secrets/simpay_key; true", timeout=60).stdout.decode().split()
    check("AT-01e", "no simpay key or DB password anywhere in the agent container's files or env; control: found in the adapter's volume",
          "AT-01", "SI-04", found == ["0"] and ctl == ["/run/adapter-secrets/simpay_key"], f"agent={found} control={ctl}")
    line = mcp_msg("tools/list", {})
    foreign = mcp_lines([line], user="10099:10011")
    own = mcp_lines([line])
    alarm = any(e.get("event") == "peer_refused" and e.get("peer_uid") == 10099
                for e in HP.json_lines(HP.compose_logs("mcp-front")))
    check("AT-01f", "a second process with another uid (10099, agent's group) opening mcp.sock gets no response; agent uid does",
          "AT-01, AI-11", "SI-03", foreign == ["no_response"] and isinstance(own[0], dict) and "result" in own[0] and alarm,
          f"foreign={foreign} own_ok={isinstance(own[0], dict) and 'result' in own[0]} alarm={alarm}")
    foreign_w = w_raw([("effect.status", {"pending_id": b64u(bytes(16))})], user="10098:10011")
    own_w = w_raw([("effect.status", {"pending_id": b64u(bytes(16))})])
    fw = w_code(foreign_w[0]) if foreign_w else f"no client output ({LAST_EXEC_ERR[0]})"
    check("AT-01g", "socket W: a process with another uid (10098) is refused (SO_PEERCRED under the runtime's uid mapping); control: the agent uid gets an answer",
          "AT-01, AI-11", "SI-03", fw == "unauthenticated" and own_w and w_code(own_w[0]) == "not_found",
          f"foreign={fw} own={own_w and w_code(own_w[0])}")


def t_at02():
    nt("AT-02", "baseline profile: S3, S5, S6 succeed (positive control)", "AT-02", "SI-17",
       "no baseline agent exists: tools/demo-agent has no direct-provider mode and the demo has no vulnerable "
       "agent profile; reachability positive controls are in AT-01c/AT-01e instead")


MAND = {}


def t_at03_raw_w():
    log("\n== AT-03 / AT-05 / AT-06: raw socket W ==")
    mid, info = new_mandate("c52", 3, 1000, 2000, 2)
    MAND["c52"] = mid
    if not check("AT-03-setup", "mandate M2 for c52 approved by Carol; new mandate starts at zero counters",
                 "AT-17", "SI-07", bool(mid) and (lambda m: m and (m["refund_count"], m["refund_total_minor"], m["message_count"]) == (0, 0, 0))(mandate_row(mid)),
                 info):
        return
    before = n_agent_records()
    rs = w_raw([("payments.get_card", {"order_id": 521}),
                ("effect.propose", {"op": "payments.get_card", "params": {"order_id": 521}, "approver": APPROVER}),
                ("effect.propose", {"op": "messages.send", "params": {"customer_sub": "c52", "to": "x@evil.example", "body": "x"}, "approver": APPROVER}),
                ("payments.support_get_order", {"order_id": 777}),
                ("payments.support_get_order", {"order_id": 521})])
    codes = [w_code(r) for r in rs]
    read = (rs[4] or {}).get("result") if isinstance(rs[4], dict) else None
    no_rec = n_agent_records() == before
    # S5 on raw W: the card op as a method -> unknown_operation (§5 S5); proposing it -> invalid_argument
    # (effect-protocol-v2 §2 effect.propose: an op not declared/allowed is a propose failure).
    check("AT-03a", "raw W: card op as method -> unknown_operation; proposed -> invalid_argument; `to` -> invalid_argument; out-of-scope read -> grant_denied; in-scope read -> data; no record",
          "AT-03, S4/S5/S6", "SI-16/SI-19", codes[:4] == ["unknown_operation", "invalid_argument", "invalid_argument", "grant_denied"]
          and codes[4] == "ok" and read and read.get("customer_sub") == "c52" and no_rec, f"codes={codes} no_record={no_rec}")
    r = w_propose("payments.support_refund", {"order_id": 521, "amount_minor": 700, "currency": "EUR"})
    pid = (r.get("result") or {}).get("pending_id") if isinstance(r, dict) else None
    st = wait_status(pid, ("SUCCEEDED", "FAILED", "DENIED"), 30) if pid else None
    row = rec_row(pid) if pid else None
    mu = mandate_use(pid) if pid else None
    r2 = w_propose("payments.support_refund", {"order_id": 777, "amount_minor": 100, "currency": "EUR"})
    pid2 = (r2.get("result") or {}).get("pending_id") if isinstance(r2, dict) else None
    time.sleep(1.5)
    row2 = rec_row(pid2) if pid2 else None
    check("AT-03b", "raw W: in-mandate refund executes under M2 (no confirmation); out-of-scope refund waits for confirmation -- same outcomes as through MCP",
          "AT-03, S2/S3", "SI-16/SI-19", st == "SUCCEEDED" and row["awaiting"] == "mandate" and mu and mu["mid"] == mid
          and row2 and row2["state"] == "PENDING" and row2["awaiting"] == "confirmation",
          f"in={st}/{row and row['awaiting']} use={mu} out={row2}")
    deny_open()


def t_at04_mcp_parsing():
    log("\n== AT-04: MCP parsing ==")
    before = n_agent_records()
    good = {"order_id": 521, "amount_minor": 100, "currency": "EUR"}
    call = lambda args: {"name": "payments.support_refund", "arguments": args}
    raw_num = lambda num: ('{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"payments.support_refund",'
                           '"arguments":{"order_id":521,"amount_minor":' + num + ',"currency":"EUR"},"_meta":'
                           + json.dumps(META) + '}}')
    cases = [
        ("batch", "[" + mcp_msg("tools/call", call(good)) + "]", -32600),
        ("duplicate key", '{"jsonrpc":"2.0","id":7,"id":8,"method":"tools/call","params":' + json.dumps(dict(call(good), _meta=META)) + "}", -32700),
        ("1.0", raw_num("1.0"), "invalid_argument"),
        ("1e3", raw_num("1e3"), "invalid_argument"),
        # agent-interface-v1 §2.4 (DEMOA-F02): `01` is not valid JSON (RFC 8259) -> parse error.
        ("01", raw_num("01"), -32700),
        ("2^53", raw_num("9007199254740992"), "invalid_argument"),
        ("extra arg", mcp_msg("tools/call", call(dict(good, note="x"))), "invalid_argument"),
        ("missing arg", mcp_msg("tools/call", call({"order_id": 521, "currency": "EUR"})), "invalid_argument"),
        ("bad version", mcp_msg("tools/call", call(good), meta={**META, "io.modelcontextprotocol/protocolVersion": "2025-11-25"}), -32022),
        ("missing version", mcp_msg("tools/call", call(good), meta={"io.modelcontextprotocol/clientCapabilities": {}}), -32602),
        ("oversize line", mcp_msg("tools/call", call(dict(good, pad="A" * 70000))), -32600),
        ("unknown tool", mcp_msg("tools/call", {"name": "payments.refund_any", "arguments": good}), -32602),
    ]
    got = {}
    for name, line, want in cases:
        r = mcp_lines([line])[0]
        got[name] = (mcp_tool_error(r), want)
    after = n_agent_records()
    bad = {k: v for k, v in got.items() if v[0] != v[1]}
    check("AT-04", "MCP: batch, duplicate keys, 1.0/1e3/01/2^53, extra/missing args, bad/missing version, oversize line, unknown tool -> rejected; no record",
          "AT-04", "SI-08/SI-16", not bad and after == before, f"mismatches={bad} records {before}->{after}")


def t_at05_forbidden_args():
    log("\n== AT-05 / AT-06 ==")
    before = n_agent_records()
    base_r = {"order_id": 521, "amount_minor": 100, "currency": "EUR"}
    base_m = {"customer_sub": "c52", "body": "hello"}
    base_t = {"customer_sub": "c52", "currency": "EUR", "refund_max_count": 1, "refund_max_per_call_minor": 1,
              "refund_max_total_minor": 1, "message_max_count": 1, "valid_for_s": 60}
    cases = [("messages.send", dict(base_m, to="c52@customer.test")),
             ("payments.support_refund", dict(base_r, mid="AAAAAAAAAAAAAAAAAAAAAA")),
             ("payments.support_refund", dict(base_r, mandate="AAAAAAAAAAAAAAAAAAAAAA")),
             ("payments.support_refund", dict(base_r, customer_sub="c52")),
             ("payments.support_refund", dict(base_r, charge_id=order(521)["charge_id"])),
             ("mandate.support_ticket", dict(base_t, customer_email="x@evil.example"))]
    mcp = [mcp_tool_error(mcp_call(op, args)) for op, args in cases]
    raw = [w_code(w_propose(op, args)) for op, args in cases]
    raw_meta = [w_code(r) for r in w_raw([("effect.propose", {"op": "payments.support_refund", "params": base_r,
                                                                "approver": APPROVER, "mid": "AAAAAAAAAAAAAAAAAAAAAA"}),
                                          ("effect.propose", {"op": "payments.support_refund", "params": base_r,
                                                              "approver": APPROVER, "mandate": "x"})])]
    after = n_agent_records()
    check("AT-05", "`to`, `mid`, `mandate`, `customer_sub` (refund), `charge_id`, `customer_email` as arguments (MCP and raw W, params and envelope) -> invalid_argument; no record",
          "AT-05, PC-06", "SI-16", all(c == "invalid_argument" for c in mcp + raw + raw_meta) and after == before,
          f"mcp={mcp} raw={raw} envelope={raw_meta} records {before}->{after}")
    before = n_agent_records()
    r = w_propose("payments.support_refund", {"order_id": 521, "amount_minor": 100, "currency": "EUR"},
                  approver={"ten": TEN, "sub": "staff:dave"})
    after = n_agent_records()
    check("AT-06", "agent names another approver (staff:dave) on raw W -> invalid_argument; no record", "AT-06, T02",
          "SI-20", w_code(r) == "invalid_argument" and after == before, f"{w_code(r)} records {before}->{after}")


def t_at09():
    s2, s8 = step_pid(SCRIPT.get("S2", {})), step_pid(SCRIPT.get("S8", {}))
    g2, g8 = grant_claims(s2) if s2 else None, grant_claims(s8) if s8 else None
    u2, u8 = mandate_use(s2) if s2 else None, mandate_use(s8) if s8 else None
    ok = all(isinstance(g, dict) and g.get(18) == 2 and isinstance(g.get(20), bytes) and b64u(g[20]) == M1[0] for g in (g2, g8))
    m = mandate_row(M1[0]) or {}
    check("AT-09", "in-mandate refund (S2) and message (S8): executed; grants cfm=2 with mid=M1; mandate_use rows; M1 counters 3 refunds / 5000 / 1 message",
          "AT-09", "SI-06/SI-11", ok and u2 and u8 and u2["mid"] == M1[0] and u8["mid"] == M1[0]
          and (m.get("refund_count"), m.get("refund_total_minor"), m.get("message_count")) == (3, 5000, 1),
          f"cfm={[g and g.get(18) for g in (g2, g8)]} uses={[u2, u8]} counters={(m.get('refund_count'), m.get('refund_total_minor'), m.get('message_count'))}")


def t_at10_scope_changes():
    log("\n== AT-10: scope changes after approval ==")
    if MAND.get("c52"):
        revoke(staff_client(CAROL), MAND["c52"])
    mid, info = new_mandate("c53", 4, 1000, 2000, 3)
    MAND["c53"] = mid
    if not mid:
        check("AT-10", "setup mandate for c53", "AT-10", "SI-10", False, info)
        return
    # Owner change (operator back office; the superuser stands in if the operator role may not).
    st_in = final_mcp_status(mcp_call("payments.support_refund", {"order_id": 531, "amount_minor": 100, "currency": "EUR"}))
    rc2, e2 = operator_sql("UPDATE nodkey.orders SET owner_sub='c9' WHERE order_id=531")
    if rc2 != 0:
        out, err = HP.psql_err("UPDATE nodkey.orders SET owner_sub='c9' WHERE order_id=531")
        rc2, e2 = (0 if not err else 1), f"operator refused ({e2.strip()[-60:]}); superuser err={err[-60:]!r}"
    r2 = mcp_call("payments.support_refund", {"order_id": 531, "amount_minor": 101, "currency": "EUR"})
    pid2 = sc(r2).get("pending_id")
    time.sleep(1.5)
    row2 = rec_row(pid2) if pid2 else None
    check("AT-10b", "order owner changed after approval (at propose): refund of that order -> confirmation, not executed",
          "AT-10/AT-14 (propose side)", "SI-10", st_in == "succeeded" and rc2 == 0 and sc(r2).get("status") == "pending_confirmation"
          and row2 and (row2["state"], row2["awaiting"]) == ("PENDING", "confirmation"),
          f"in_scope_before={st_in} change_rc={rc2} {e2} after={sc(r2).get('status')} record={row2 and (row2['state'], row2['awaiting'])}")
    # Email change.
    ok_before = final_mcp_status(mcp_call("messages.send", {"customer_sub": "c53", "body": "before the change"}))
    rc1, e1 = operator_sql("UPDATE nodkey.customers SET email='c53-new@customer.test' WHERE ten='shop1' AND sub='c53'")
    r = mcp_call("messages.send", {"customer_sub": "c53", "body": "after the change"})
    pid = sc(r).get("pending_id")
    time.sleep(1.5)
    row = rec_row(pid) if pid else None
    new_mail = [o for o in outbox() if o["to"] == "c53-new@customer.test"]
    check("AT-10a", "message to a customer whose email changed after approval (at propose) -> confirmation; nothing sent to the new address",
          "AT-10, AI-09", "SI-10", ok_before == "succeeded" and rc1 == 0 and sc(r).get("status") == "pending_confirmation"
          and row and row["awaiting"] == "confirmation" and not new_mail,
          f"before={ok_before} op_rc={rc1} {e1} after={sc(r).get('status')} awaiting={row and row['awaiting']} new_mail={len(new_mail)}")
    # A refund after the email change passes the propose-time pre-filter (C4 compares only
    # customer_sub for refunds) and is checked against the current email at execution (§4.5; MD-12).
    r3 = mcp_call("payments.support_refund", {"order_id": 532, "amount_minor": 100, "currency": "EUR"})
    pid3 = sc(r3).get("pending_id")
    st3 = wait_status(pid3, ("SUCCEEDED", "FAILED", "DENIED", "EXPIRED"), 20) if pid3 else None
    row3 = rec_row(pid3) if pid3 else None
    led = refunds_by_charge().get(order(532)["charge_id"])
    check("AT-10d", "mandated refund after the customer's email changed -> FAILED/denied at execution; nothing at the provider",
          "AT-10, §4.5, MD-12", "SI-10", row3 and (row3["state"], row3["outcome_class"]) == ("FAILED", "denied") and not led,
          f"record={row3 and (row3['state'], row3['awaiting'], row3['outcome_class'])} ledger532={led}")
    nt("AT-10c", "email or owner changed between signing and execution -> FAILED/denied", "AT-10, AT-14", "SI-10/SI-11",
       "needs a change injected between the authority's signature and the broker's execution transaction; the stack "
       "offers no deterministic hook for that window (AT-10d exercises the execution-time email check)")
    deny_open()


def final_mcp_status(r, wait=20):
    s = sc(r).get("status")
    pid = sc(r).get("pending_id")
    if s == "in_progress" and pid:
        st = wait_status(pid, ("SUCCEEDED", "FAILED", "DENIED", "EXPIRED"), wait)
        return {"SUCCEEDED": "succeeded", "FAILED": "failed"}.get(st, st)
    return s


def t_at11_boundaries():
    log("\n== AT-11: limits +/- 1 ==")
    cli = staff_client(CAROL)
    if MAND.get("c53"):
        revoke(cli, MAND["c53"])
    # AT-20 (typed amounts wrong -> re-render) on the way: Carol first types a wrong amount.
    r = mcp_call("mandate.support_ticket", {"customer_sub": "c50", "currency": "EUR", "refund_max_count": 3,
                                            "refund_max_per_call_minor": 1000, "refund_max_total_minor": 2500,
                                            "message_max_count": 2, "valid_for_s": 3600})
    pid = sc(r).get("pending_id")
    dst, dpage, _ = decide(cli, pid, "approve", typed_override={"confirm_refund_max_per_call_minor": "10.01"})
    still = rec_row(pid)
    st_d, _, page_d = confirm_page_as(DAVE, pid)
    check("AT-20b", "approval page as Dave (staff, not a support principal) -> uniform error",
          "AT-20", "SI-20", HP.UNIFORM in page_d and HP.TOKEN_RE.search(page_d) is None, f"http={st_d}")
    check("AT-20c", "typed amount wrong (10.01 for 10.00) -> page re-rendered with the mismatch message; record stays PENDING",
          "AT-20", "SI-20", dst == 200 and "does not match" in (dpage or "") and still and still["state"] == "PENDING", f"http={dst}")
    decide(cli, pid, "approve")
    ok = wait_status(pid, HP.SAFE_STATES, 30) == "SUCCEEDED"
    MAND["c50"] = pid if ok else None
    if not ok:
        check("AT-11", "setup", "AT-11", "SI-11", False, "mandate for c50 not active")
        return
    seq = [("per-call +1", 501, 1001, "EUR", "pending_confirmation"),
           ("per-call exact", 501, 1000, "EUR", "succeeded"),
           ("second", 502, 1000, "EUR", "succeeded"),
           ("total +1", 501, 501, "EUR", "pending_confirmation"),
           ("total exact (count exact)", 501, 500, "EUR", "succeeded"),
           ("count +1", 502, 1, "EUR", "pending_confirmation")]
    got = []
    for name, oid, amt, cur, want in seq:
        s = final_mcp_status(mcp_call("payments.support_refund", {"order_id": oid, "amount_minor": amt, "currency": cur}))
        got.append((name, s, want))
    msgs = [final_mcp_status(mcp_call("messages.send", {"customer_sub": "c50", "body": f"note {i}"})) for i in range(3)]
    m = mandate_row(MAND["c50"]) or {}
    rb = refunds_by_charge()
    ok = all(s == w for _, s, w in got) and msgs == ["succeeded", "succeeded", "pending_confirmation"] \
        and (m.get("refund_count"), m.get("refund_total_minor"), m.get("message_count")) == (3, 2500, 2) \
        and rb.get(order(501)["charge_id"]) == [500, 1000] and rb.get(order(502)["charge_id"]) == [1000]
    check("AT-11a", "per-call, total and count limits at exact and +1 (mandate c50: 3 refunds, 10.00 each, 25.00 total, 2 messages)",
          "AT-11", "SI-11", ok, f"{got} messages={msgs} counters={(m.get('refund_count'), m.get('refund_total_minor'), m.get('message_count'))} ledger501={rb.get(order(501)['charge_id'])} ledger502={rb.get(order(502)['charge_id'])}")
    deny_open(cli)
    revoke(cli, MAND["c50"])
    mid, _ = new_mandate("c50", 2, 1000, 5000, 1, cli=cli)
    if not mid:
        check("AT-11b", "setup", "AT-11", "SI-11", False, "second c50 mandate not active")
        return
    seq = [("count 1", 501, 100, "EUR", "succeeded"), ("currency USD", 502, 102, "USD", "pending_confirmation"),
           ("count 2", 502, 101, "EUR", "succeeded"), ("count +1 (total far below)", 502, 103, "EUR", "pending_confirmation")]
    got = [(n, final_mcp_status(mcp_call("payments.support_refund", {"order_id": o, "amount_minor": a, "currency": c})), w)
           for n, o, a, c, w in seq]
    m = mandate_row(mid) or {}
    check("AT-11b", "count limit isolated (2 refunds, total 50.00) and currency mismatch -> confirmation",
          "AT-11", "SI-11", all(s == w for _, s, w in got) and (m.get("refund_count"), m.get("refund_total_minor")) == (2, 201),
          f"{got} counters={(m.get('refund_count'), m.get('refund_total_minor'))}")
    MAND["c50b"] = mid
    deny_open(cli)
    revoke(cli, mid)


def t_at12_concurrency():
    log("\n== AT-12: concurrent mandated refunds ==")
    mid, info = new_mandate("c51", 5, 100, 300, 0)
    if not mid:
        check("AT-12a", "setup", "AT-12", "SI-11", False, info)
        return
    calls = [("effect.propose", {"op": "payments.support_refund", "params": {"order_id": 511, "amount_minor": 60 + i, "currency": "EUR"},
                                 "approver": APPROVER}) for i in range(20)]
    rs = w_raw(calls, concurrent=True)
    pids = [(r.get("result") or {}).get("pending_id") for r in rs if isinstance(r, dict) and r.get("ok")]
    time.sleep(12)
    states = {p: (rec_row(p) or {}).get("state") for p in pids}
    for p, s in list(states.items()):
        if s in ("APPROVED", "EXECUTING"):
            states[p] = wait_status(p, ("SUCCEEDED", "FAILED", "UNKNOWN"), 60)
    exe = [p for p, s in states.items() if s == "SUCCEEDED"]
    amounts = sorted(int(json.loads((rec_row(p) or {}).get("params") or "{}").get("amount_minor", 0)) for p in exe)
    m = mandate_row(mid) or {}
    led = refunds_by_charge().get(order(511)["charge_id"], [])
    signed = int(psql(f"SELECT count(*) FROM public.pending_effect WHERE wid='{AGENT_WID}' AND grant_bytes IS NOT NULL "
                      f"AND op='payments.support_refund' AND params LIKE '%\"order_id\":511%'") or -1)
    signed_rows = psql_json(f"SELECT params, state FROM public.pending_effect WHERE wid='{AGENT_WID}' AND grant_bytes IS NOT NULL "
                            f"AND op='payments.support_refund' AND params LIKE '%\"order_id\":511%'")
    signed_amts = sorted(int(json.loads(r["params"])["amount_minor"]) for r in signed_rows)
    jtis = [e.get("jti") for e in HP.json_lines(HP.compose_logs("authority")) if e.get("event") == "grant_signed"]
    one_per_jti = len(jtis) == len(set(jtis))
    denials = [HP.denial(p) for p, st in states.items() if st == "FAILED"]
    check("AT-12a", "20 concurrent mandated refunds (60..79, one order) against 5 refunds / 3.00 total: signed <= limits; executed <= limits; ledger = executed; broker counters = executed; one grant per jti",
          "AT-12", "SI-09/SI-11", len(pids) == 20 and len(signed_amts) <= 5 and sum(signed_amts) <= 300 and 1 <= len(exe) <= 5
          and sum(amounts) <= 300 and sorted(led) == amounts and (m.get("refund_count"), m.get("refund_total_minor")) == (len(exe), sum(amounts))
          and one_per_jti,
          f"accepted={len(pids)} signed={signed_amts} executed={amounts} ledger={sorted(led)} counters={(m.get('refund_count'), m.get('refund_total_minor'))} "
          f"one_grant_per_jti={one_per_jti} failed_reasons={denials} (order_busy = the per-order lock, R-A5 liveness)")
    nt("AT-12b", "human approval racing the mandate loop on one pending_id (both orders)", "AT-12, AI-07", "SI-09",
       "needs control over the order in which the gateway approval and the authority's 500 ms mandate loop reach "
       "the store lock; not reproducible deterministically from outside the containers")
    deny_open()
    revoke(staff_client(CAROL), mid)


def t_at13():
    s10 = SCRIPT.get("S10", {})
    check("AT-13a", "identical repeat (S10) -> confirmation; the page shows the earlier execution (S2's request)",
          "AT-13, AI-06", "SI-09", first_status(s10) == "pending_confirmation" and (step_pid(SCRIPT.get("S2", {})) or "?") in PAGES.get("S10", ""),
          f"first={first_status(s10)}")
    nt("AT-13b", "tools/call retry after a dropped response", "AT-13", "SI-09",
       "dropping one MCP response in flight needs a fault-injecting transport between agent and front; not built "
       "(a retried call is a new identical proposal, which AT-13a covers)")


def t_at14_19():
    nt("AT-14", "order owner changed between signing and execution -> FAILED/denied; adapter refuses on con3", "AT-14",
       "SI-10/SI-11", "no deterministic hook between signing and execution (see AT-10c); the propose-side change is AT-10b")
    nt("AT-18", "broker-compromise suite for mandated refunds (forged mandate row, customer_sub lie, forced awaiting, flooding)",
       "AT-18", "EP-03/SI-05", "needs attacker-J tooling for the mandate messages on sockets A/P; not built for Demo A")
    nt("AT-19", "authority crash before/after issuance fsync; counters durable; same bytes re-delivered", "AT-19", "SI-09",
       "needs crash injection at exact points inside the authority; covered only by crates/nodkey-authority tests")
    nt("AT-21", "grant-v1 Draft 4 vectors MND-01..10, OPS-21..25; Draft 3 verifier given cfm=2", "AT-21", "SI-06/SI-08",
       "vector suites run in crates/nodkey-grant, not against this stack")
    nt("AT-27", "optional model mode", "AT-27", "-", "not implemented in tools/demo-agent and never required (spec: NOT TESTED in CI)")
    nt("AT-07", "mandate of another wid, principal or tenant never covers", "AT-07", "PC-06/SI-06",
       "the demo registers one enrolled agent, one support principal and one tenant; no second agent exists to hold "
       "a foreign mandate")
    nt("AT-08", "loader refusals (template/support op on named workload; enrolment outside support_principals; template mandate_eligible; template as refund_op/message_op)",
       "AT-08", "EP-03", "start-up refusals are exercised by broker/authority unit tests (config::mandate_loader_refusals); "
       "not re-run against this stack")


def t_at15_revoke_broker_down():
    log("\n== AT-15: revocation while the broker is unreachable ==")
    cli = staff_client(CAROL)
    mid, info = new_mandate("c52", 2, 500, 1000, 1, cli=cli)
    if not mid:
        check("AT-15b", "setup", "AT-15", "SI-08", False, info)
        return
    st, _, page = mandates_page(cli)
    m = re.search(rf'action="/mandates/{re.escape(mid)}/revoke"><input type="hidden" name="token" value="([^"]+)"', page)
    if not m:
        check("AT-15b", "setup", "AT-15", "SI-08", False, "no revoke form")
        return
    compose("pause", "broker")
    try:
        st, rpage, _ = revoke(cli, mid, token=m.group(1))
    finally:
        compose("unpause", "broker")
    not_confirmed = "Revocation not confirmed" in (rpage or "")
    end = time.time() + 30
    state = None
    while time.time() < end:
        state = (mandate_row(mid) or {}).get("state")
        if state == "revoked":
            break
        time.sleep(1)
    rd = w_raw([("payments.support_get_order", {"order_id": 521})])[0]
    rf = w_propose("payments.support_refund", {"order_id": 521, "amount_minor": 50, "currency": "EUR"})
    pid = (rf.get("result") or {}).get("pending_id") if isinstance(rf, dict) else None
    time.sleep(1.5)
    row = rec_row(pid) if pid else None
    check("AT-15b", "revoke with the broker unreachable -> page says 'not confirmed'; background retry completes it; then no read and no mandated execution",
          "AT-15, AI-01", "SI-08/SI-15", not_confirmed and state == "revoked" and w_code(rd) == "grant_denied"
          and row and row["awaiting"] == "confirmation",
          f"page_not_confirmed={not_confirmed} broker_state={state} read={w_code(rd)} refund={row and (row['state'], row['awaiting'])}")
    nt("AT-15c", "revoke with only the broker reachable; revoke racing delivery and execution", "AT-15", "SI-08/SI-15",
       "needs the authority unreachable while the gateway still renders, and a race hook on delivery/execution")
    deny_open(cli)


def t_at16_expiry():
    log("\n== AT-16: expiry and revoked_before ==")
    cli = staff_client(CAROL)
    mid, info = new_mandate("c54", 3, 500, 1500, 1, valid=60, cli=cli)
    if not mid:
        check("AT-16a", "setup", "AT-16", "SI-08", False, info)
        return
    m = mandate_row(mid)
    s_in = final_mcp_status(mcp_call("payments.support_refund", {"order_id": 541, "amount_minor": 100, "currency": "EUR"}))
    d_in = w_code(w_raw([("payments.support_get_order", {"order_id": 541})])[0])
    wait = m["exp"] - time.time() + 2
    if wait > 0:
        time.sleep(wait)
    d_out = w_code(w_raw([("payments.support_get_order", {"order_id": 541})])[0])
    r = mcp_call("payments.support_refund", {"order_id": 541, "amount_minor": 101, "currency": "EUR"})
    check("AT-16a", "mandate valid_for_s=60: before exp a refund executes and a read answers; at exp + 2 s the read is grant_denied and a refund needs confirmation",
          "AT-16", "SI-08", s_in == "succeeded" and d_in == "ok" and d_out == "grant_denied" and sc(r).get("status") == "pending_confirmation",
          f"before: refund={s_in} read={d_in}; after: read={d_out} refund={sc(r).get('status')}")
    deny_open(cli)
    mid2, info = new_mandate("c54", 3, 500, 1500, 1, cli=cli)
    if not mid2:
        check("AT-16b", "setup", "AT-16", "SI-08", False, info)
        return
    d_in = w_code(w_raw([("payments.support_get_order", {"order_id": 541})])[0])
    out, err = HP.psql_err(f"INSERT INTO public.revoked_before (ten, wid, before) VALUES ('{TEN}', '{AGENT_WID}', "
                           f"extract(epoch from now())::bigint + 1)")
    time.sleep(2)
    d_out = w_code(w_raw([("payments.support_get_order", {"order_id": 541})])[0])
    r = mcp_call("payments.support_refund", {"order_id": 541, "amount_minor": 102, "currency": "EUR"})
    check("AT-16b", "operator revoked_before for (ten, wid) after the mandate's iat -> mandate no longer covers reads or refunds",
          "AT-16", "SI-08", d_in == "ok" and not err and d_out == "grant_denied" and sc(r).get("status") == "pending_confirmation",
          f"before={d_in} insert_err={err[-100:]} after: read={d_out} refund={sc(r).get('status')}")
    nt("AT-16c", "exp +/- 1 s precision; config.digest change; workload re-registered under the same wid", "AT-16",
       "SI-08/AI-11", "needs clock control and a broker+authority restart with changed configuration files")
    deny_open(cli)


def t_at17():
    s11 = SCRIPT.get("S11", {})
    m2 = MAND.get("c52")
    s11_ok = any(r["id"] == "S11" and r["pass"] == PASS_NO and r["result"] == "PASS" for r in RESULTS)
    zero_ok = any(r["id"] == "AT-03-setup" and r["result"] == "PASS" for r in RESULTS)
    check("AT-17a", "second mandate while one is active: the approval page is refused (row S11 of this pass); after revoke a new mandate starts at zero counters (row AT-03-setup)",
          "AT-17, AI-04", "SI-07", s11_ok and zero_ok, f"S11_row={s11_ok} AT-03-setup_row={zero_ok} M2={bool(m2)}")
    nt("AT-17b", "second mandate forced at the authority and at broker activation", "AT-17", "SI-07",
       "the gateway refuses to render first; forcing the later checks needs a modified gateway or direct socket-I access")


def t_at20a_ceilings():
    before = n_agent_records()
    base = {"customer_sub": "c50", "currency": "EUR", "refund_max_count": 5, "refund_max_per_call_minor": 100,
            "refund_max_total_minor": 10000, "message_max_count": 10, "valid_for_s": 3600}
    errs = [mcp_tool_error(mcp_call("mandate.support_ticket", dict(base, **chg)))
            for chg in ({"refund_max_count": 6}, {"refund_max_total_minor": 10001}, {"message_max_count": 11},
                        {"valid_for_s": 59}, {"valid_for_s": 3601})]
    after = n_agent_records()
    check("AT-20a", "mandate above ceilings (count 6, total 100.01, messages 11, valid 59 s / 3601 s) -> invalid_argument; no record",
          "AT-20", "SI-20", errs == ["invalid_argument"] * 5 and after == before, f"{errs} records {before}->{after}")


def t_at22_reads():
    nonexist = w_raw([("payments.support_get_order", {"order_id": 999999})])[0]
    strip = lambda r: {k: v for k, v in (r.get("error") or {}).items()} if isinstance(r, dict) else r
    s4 = SCRIPT.get("S4", {})
    bodies = {"no mandate": strip(PRE_READ[0] or {}), "revoked": strip(SCRIPT.get("_revoked_read") or {}),
              "nonexistent": strip(nonexist)}
    vals = list(bodies.values())
    check("AT-22", "reads: in scope -> data (S1); out of scope (S4), nonexistent, no mandate, revoked -> grant_denied with identical bodies (expired: AT-16a)",
          "AT-22", "SI-06/SI-10", sc(SCRIPT.get("S1", {}).get("response")).get("order_id") == 101 and step_error(s4) == "grant_denied"
          and all(v == vals[0] for v in vals) and vals[0].get("code") == "grant_denied", bodies)


def t_at23_pages():
    log("\n== AT-23: pages ==")
    s3p, s7p = PAGES.get("S3", ""), PAGES.get("S7", "")
    r = mcp_call("messages.send", {"customer_sub": "c9", "body": "<script>alert(1)</script> & \"q\""})
    pid = sc(r).get("pending_id")
    st, _, page = confirm_page_as(CAROL, pid) if pid else (0, None, "")
    escaped = "&lt;script&gt;alert(1)&lt;/script&gt; &amp;" in page and "<script>alert(1)" not in page
    check("AT-23a", "pages: trusted customer (c9), remaining 40.00 and currency EUR on S3; recipient and labelled body on S7; agent body HTML-escaped",
          "AT-23", "SI-20/SI-21", "c9" in s3p and "40.00" in s3p and "EUR" in s3p and "bob@customer.test" in s7p
          and "Written by the agent — unverified" in s7p and escaped, f"escaped={escaped} http={st}")
    deny_open()
    cli = staff_client(CAROL)
    mid, _ = new_mandate("c53", 1, 100, 100, 0, cli=cli)
    toks = []
    for _ in range(3):
        st, _, mp = mandates_page(cli)
        m = re.search(rf'action="/mandates/{re.escape(mid or "x")}/revoke"><input type="hidden" name="token" value="([^"]+)"', mp)
        toks.append(m.group(1) if m else None)
    s1, p1, _ = revoke(cli, mid or "x", token=toks[0], sec_fetch={"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate",
                                                                  "Sec-Fetch-Dest": "document"}, origin="https://evil.example")
    s4, p4, _ = revoke(staff_client(DAVE), mid or "x", token=toks[1])
    still = (mandate_row(mid) or {}).get("state") if mid else None
    s2, p2, _ = revoke(cli, mid or "x", token=toks[2])
    s3, p3, _ = revoke(cli, mid or "x", token=toks[2])
    final = (mandate_row(mid) or {}).get("state") if mid else None
    check("AT-23b", "/mandates revoke: cross-site POST and another user's session with Carol's token -> uniform error, mandate still active; valid POST -> revoked; token replay -> uniform error",
          "AT-23, T04-T07", "SI-20/SI-21", bool(mid) and all(toks) and HP.UNIFORM in (p1 or "") and HP.UNIFORM in (p4 or "")
          and still == "active" and "Mandate revoked" in (p2 or "") and HP.UNIFORM in (p3 or "") and final == "revoked",
          f"tokens={sum(1 for t in toks if t)} cross_site={HP.UNIFORM in (p1 or '')} dave={HP.UNIFORM in (p4 or '')} still={still} ok={'Mandate revoked' in (p2 or '')} replay={HP.UNIFORM in (p3 or '')} final={final}")


CARD_RE = re.compile(r"(?<!\d)\d{13,19}(?!\d)")


def t_at24_card_fields():
    tools = SCRIPT.get("_tools", {}).get("names", [])
    tl = mcp_lines([mcp_msg("tools/list", {})])[0]
    props = []
    for t in (tl.get("result") or {}).get("tools", []) if isinstance(tl, dict) else []:
        props += list(((t.get("inputSchema") or {}).get("properties") or {}).keys())
        props += list(((t.get("outputSchema") or {}).get("properties") or {}).keys())
    bad_props = [p for p in props if re.search(r"card|pan|cvc|cvv|expiry|number", p, re.I)]
    read_keys = sorted(sc(SCRIPT.get("S1", {}).get("response")).keys())
    bodies = [o["body"] for o in outbox()] + [m.get("body", "") for m in mailsink_messages(0.5).get("messages", [])]
    cards = [b for b in bodies if CARD_RE.search(b) or re.search(r"cvc|cvv", b, re.I)]
    check("AT-24", "no card field in tool schemas, no card data in reads, outbox or mailsink",
          "AT-24", "SI-16", not bad_props and read_keys == sorted(["order_id", "customer_sub", "currency", "amount_minor",
                                                                  "refunded_minor", "status"]) and not cards and "payments.get_card" not in tools,
          f"tools={tools} bad_props={bad_props} read_keys={read_keys} card_like_bodies={len(cards)}")


def t_at25_limits():
    log("\n== AT-25: pending limits per wid / approver ==")
    deny_open()
    calls = [("effect.propose", {"op": "messages.send", "params": {"customer_sub": "c9", "body": f"flood {i}"}, "approver": APPROVER})
             for i in range(40)]
    rs = w_raw(calls)
    codes = [w_code(r) for r in rs]
    first_limit = codes.index("limit_exceeded") if "limit_exceeded" in codes else None
    shop = shop_w([["effect.propose", {"op": "payments.refund", "params": {"order_id": 777, "amount_minor": 100, "currency": "EUR"},
                                       "approver": {"ten": TEN, "sub": "c9"}}]])
    shop_ok = isinstance(shop[0], dict) and shop[0].get("ok") is True
    check("AT-25", "agent floods proposals -> limit_exceeded after the pending limit (32 per approver); another workload is unaffected",
          "AT-25, PC-09", "SI-08", first_limit is not None and all(c == "ok" for c in codes[:first_limit])
          and all(c == "limit_exceeded" for c in codes[first_limit:]) and shop_ok,
          f"ok_before_limit={first_limit} tail={sorted(set(codes[first_limit or 0:]))} shop={shop[0] if not shop_ok else 'ok'}")
    deny_open()


def t_s11_expired():
    pid = SCRIPT.get("_S11")
    if not pid:
        return
    exp = int(psql(f"SELECT expires_at FROM public.pending_effect WHERE pending_id={pid_sql(pid)}") or 0)
    wait = exp - time.time() + 2
    if 0 < wait <= 130:
        time.sleep(wait)
    stat = w_raw([("effect.status", {"pending_id": pid})])[0]
    st = (rec_row(pid) or {}).get("state")
    s = ((stat.get("result") or {}).get("state")) if isinstance(stat, dict) else stat
    check("S11-expiry", "S11's template record (never approvable) ends EXPIRED", "§5 S11", "SI-07",
          "EXPIRED" in (st, s), f"db={st} status={s}")


# =============================================================================== main

def at26(pass1, pass2):
    diffs = {k: (pass1.get(k), pass2.get(k)) for k in set(pass1) | set(pass2) if pass1.get(k) != pass2.get(k)}
    check("AT-26", "full §5 script twice from clean state -> identical final state (ledger, outbox, mandate, step outcomes)",
          "AT-26", "all", not diffs, diffs or "identical")


def summary():
    order_ = ["PASS", "FAIL", "NOT TESTED", "INCONCLUSIVE", "NOT APPLICABLE"]
    counts = {k: sum(1 for r in RESULTS if r["result"] == k) for k in order_}
    print(f"\n{'pass':4} {'id':16} {'result':12} title")
    for r in RESULTS:
        print(f"{r['pass']:<4} {r['id']:16} {r['result']:12} {r['title'][:110]}")
    print("\n" + " / ".join(f"{v} {k}" for k, v in counts.items()))
    return counts


def main():
    global ROOT, OUT, PASS_NO, HP, CTX, DATA, PCLIENT, RESULTS
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--pass", dest="pass_no", type=int, choices=(1, 2), required=True)
    a = ap.parse_args()
    ROOT, OUT, PASS_NO = a.root, a.out, a.pass_no
    spec = importlib.util.spec_from_file_location("demop_harness", f"{ROOT}/tests/demop/harness.py")
    HP = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(HP)
    HP.PROJECT = f"{ROOT}/examples/agent-support/compose.yaml"
    HP.ROOT, HP.OUT = ROOT, OUT
    HP.UA = "nodkey-demoa-harness"
    CTX = ssl.create_default_context(cafile=f"{OUT}/gateway-dev-cert.pem")
    HP.CTX = CTX
    DATA = json.load(open(f"{ROOT}/examples/agent-support/config/demo-data.json"))
    PCLIENT = HP.load_probe("pclient.pl")
    if PASS_NO == 2 and __import__("os").path.exists(f"{OUT}/results-pass1.json"):
        RESULTS = json.load(open(f"{OUT}/results-pass1.json"))
    try:
        ok, detail = seed()
        check("SETUP", "operator seed of orders and customers (checked against simpay's ledger)", "§5 setup", "-", ok, detail)
        if not ok:
            raise RuntimeError("seed failed")
        t_script()
        snap = snapshot()
        if PASS_NO == 1:
            json.dump(snap, open(f"{OUT}/pass1.json", "w"), indent=1, default=str)
            json.dump(RESULTS, open(f"{OUT}/results-pass1.json", "w"), indent=1)
            summary()
            return 0
        try:
            p1 = json.load(open(f"{OUT}/pass1.json"))
        except OSError:
            p1 = None
        if p1 is None:
            record("AT-26", "full §5 script twice from clean state", "AT-26", "all", "FAIL", "pass 1 snapshot missing")
        else:
            at26(p1, json.loads(json.dumps(snap, default=str)))
        for t in (t_at09, t_at13, t_at22_reads, t_at24_card_fields, t_at01_containment, t_at02, t_at03_raw_w,
                  t_at04_mcp_parsing, t_at05_forbidden_args, t_at20a_ceilings, t_at10_scope_changes, t_at11_boundaries,
                  t_at12_concurrency, t_at15_revoke_broker_down, t_at17, t_at23_pages, t_s11_expired,
                  t_at16_expiry, t_at25_limits, t_at14_19):
            try:
                t()
            except Exception as e:
                record(t.__name__, "harness exception", "-", "-", "INCONCLUSIVE", traceback.format_exc()[-600:])
    except Exception:
        record("HARNESS", "harness error", "-", "-", "INCONCLUSIVE", traceback.format_exc()[-800:])
        json.dump(RESULTS, open(f"{OUT}/results.json", "w"), indent=1)
        summary()
        return 3
    json.dump(RESULTS, open(f"{OUT}/results.json", "w"), indent=1)
    c = summary()
    return 1 if c["FAIL"] else (2 if c["NOT TESTED"] or c["INCONCLUSIVE"] else 0)


if __name__ == "__main__":
    sys.exit(main())
