#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Henry Cuevas
# SPDX-License-Identifier: Apache-2.0
#
# Demo P (confirmed refunds via the SIMULATED provider simpay) end-to-end + attack harness. Runs
# against the LOCAL, INTENTIONALLY VULNERABLE stack in examples/confirmed-refund/, started by
# tests/demop/run.sh.
#
# Roles it plays (and only these):
#  - a scripted browser (tiny HTTP/1.1 client over the gateway's dev TLS, per-origin cookie jars,
#    the Sec-Fetch-* / Origin headers a real browser sends) for the demo TEST users;
#  - attacker C through the shop's /debug/eval RCE endpoint (or `docker compose exec app`, same
#    namespaces, uid and mounts) — threat actor C;
#  - attacker J (broker compromise) for the PT-29 / R_max cases: code running as the broker uid
#    inside the broker container, talking to socket P directly;
#  - attacker G: simpay fault and malicious-provider rules, through simpay's admin listener
#    (reached only from the harness-only `simpay-ctl` container);
#  - the operator: seeds nodkey.orders through nodkey_shop_operator after asserting each row
#    against simpay's admin ledger, and reads ground truth (postgres superuser in the db container,
#    simpay /admin/ledger).
# It never sends the owner's email or any personal identifier anywhere (the only principals are the
# demo test users; the User-Agent is generic).
#
# Output: var/demop/results.json and a table on stdout. Exit 0 iff every result is PASS or
# NOT APPLICABLE; 1 on any FAIL; 2 if none FAIL but some INCONCLUSIVE / NOT TESTED.

import argparse, base64, hashlib, json, re, socket, ssl, subprocess, sys, threading, time

GW = ("127.0.0.1", 8443)
APP = "app.localhost:8443"
AUTH = "auth.localhost:8443"
APP_ORIGIN = "https://" + APP
AUTH_ORIGIN = "https://" + AUTH
PROJECT = None  # set in main
ROOT = OUT = None
UA = "nodkey-demop-harness"

RESULTS = []
EXPONENT = {"USD": 2, "EUR": 2, "GBP": 2, "JPY": 0}
SAFE_STATES = ("SUCCEEDED", "FAILED", "UNKNOWN", "DENIED", "EXPIRED")


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def record(gid, tid, title, maps, si, result, detail=""):
    RESULTS.append({"group": gid, "id": tid, "title": title, "maps": maps, "SI": si,
                    "result": result, "detail": str(detail)[:600]})
    log(f"  [{result:12}] {tid}: {title}" + (f" -- {detail}" if detail else ""))


def verdict(ok, inconclusive=False):
    return "PASS" if ok else ("INCONCLUSIVE" if inconclusive else "FAIL")


# =============================================================================== browser

class Client:
    """One scripted browser: per-origin cookie jars, manual redirects."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.jars = {APP: {}, AUTH: {}}

    def request(self, origin, method, path, headers=None, body=b"", sec_fetch=None, origin_hdr=None,
                timeout=30):
        host = APP if origin == APP_ORIGIN else AUTH
        hdrs = {"Host": host, "Connection": "close", "User-Agent": UA, "Accept": "text/html"}
        if sec_fetch == "navigate":
            hdrs.update({"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate",
                         "Sec-Fetch-Dest": "document", "Sec-Fetch-User": "?1"})
        elif isinstance(sec_fetch, dict):
            hdrs.update(sec_fetch)
        if origin_hdr is not None:
            hdrs["Origin"] = origin_hdr
        jar = self.jars[host]
        if jar:
            hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in jar.items())
        if isinstance(body, str):
            body = body.encode()
        if body:
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
            hdrs["Content-Length"] = str(len(body))
        if headers:
            hdrs.update(headers)
        req = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
        raw = socket.create_connection(GW, timeout=timeout)
        s = self.ctx.wrap_socket(raw, server_hostname=host.split(":")[0])
        s.sendall(req.encode() + body)
        buf = b""
        while True:
            try:
                chunk = s.recv(65536)
            except (ssl.SSLError, ConnectionResetError):
                break
            if not chunk:
                break
            buf += chunk
        s.close()
        head, _, rbody = buf.partition(b"\r\n\r\n")
        lines = head.decode("latin1").split("\r\n")
        status = int(lines[0].split()[1]) if lines and len(lines[0].split()) > 1 else 0
        rheaders = []
        for ln in lines[1:]:
            k, _, v = ln.partition(":")
            rheaders.append((k.strip().lower(), v.strip()))
        for k, v in rheaders:
            if k == "set-cookie":
                self._store_cookie(host, v)
        return status, rheaders, rbody.decode("utf-8", "replace")

    def _store_cookie(self, host, sc):
        name, _, val = sc.split(";")[0].partition("=")
        attrs = sc.lower()
        if "max-age=0" in attrs or ("expires=" in attrs and "1970" in attrs):
            self.jars[host].pop(name.strip(), None)
        else:
            self.jars[host][name.strip()] = val.strip()

    @staticmethod
    def header(rheaders, name):
        return [v for k, v in rheaders if k == name.lower()]


# =============================================================================== operator oracles

def compose(*args, check=False, input_bytes=None, timeout=180):
    return subprocess.run(["docker", "compose", "-f", PROJECT, *args], capture_output=True,
                          input=input_bytes, check=check, timeout=timeout)


def psql(sql, user_flags=()):
    r = compose("exec", "-T", "--user", "postgres", "db", "psql", "-U", "postgres", "-d", "ledger",
                "-tAc", sql)
    return r.stdout.decode().strip()


def psql_err(sql):
    """Runs SQL as superuser; returns (stdout, stderr) so expected refusals can be inspected."""
    r = compose("exec", "-T", "--user", "postgres", "db", "psql", "-U", "postgres", "-d", "ledger",
                "-v", "ON_ERROR_STOP=1", "-tAc", sql)
    return r.stdout.decode().strip(), r.stderr.decode().strip()


def psql_json(sql):
    out = psql(f"SELECT coalesce(json_agg(t), '[]') FROM ({sql}) t")
    try:
        return json.loads(out or "[]")
    except json.JSONDecodeError:
        return []


ADMIN_PHP = r'''
$m = $argv[1]; $p = $argv[2]; $b = $argv[3] ?? '';
$ctx = stream_context_create(['http' => ['method' => $m, 'header' => "Content-Type: application/json\r\n",
  'content' => $b, 'ignore_errors' => true, 'timeout' => 15]]);
$r = @file_get_contents('http://172.30.40.20:8081' . $p, false, $ctx);
echo $r === false ? '{"harness_error":"admin unreachable"}' : $r;
'''


def admin(method, path, body=None):
    r = compose("exec", "-T", "simpay-ctl", "php", "-r", ADMIN_PHP, method, path,
                json.dumps(body) if body is not None else "")
    try:
        return json.loads(r.stdout.decode())
    except json.JSONDecodeError:
        return {"harness_error": r.stdout.decode()[:200] + r.stderr.decode()[:200]}


def ledger():
    return admin("GET", "/admin/ledger")


def ledger_charge(charge):
    led = ledger()
    c = next((c for c in led.get("charges", []) if c["id"] == charge), None)
    refunds = [r for r in led.get("refunds", []) if r.get("charge") == charge]
    return c, refunds


def set_faults(rules):
    return admin("PUT", "/admin/faults", {"rules": rules})


def clear_faults():
    return admin("DELETE", "/admin/faults")


def set_malicious(on):
    return admin("PUT", "/admin/malicious", {"enabled": bool(on)})


def compose_logs(service):
    r = compose("logs", "--no-color", "--no-log-prefix", service, timeout=60)
    return r.stdout.decode("utf-8", "replace")


def json_lines(text):
    out = []
    for ln in text.splitlines():
        ln = ln.strip()
        if ln.startswith("{"):
            try:
                out.append(json.loads(ln))
            except json.JSONDecodeError:
                pass
    return out


def adapter_events():
    return json_lines(compose_logs("adapter"))


def creates_sent(jti):
    """refund.create requests for this jti that reached the provider (adapter audit log)."""
    return [e for e in adapter_events() if e.get("event") == "p_request" and e.get("op") == "refund.create"
            and e.get("jti") == jti and e.get("provider_request_started")]


def adapter_calls(jti):
    return [e for e in adapter_events() if e.get("event") == "p_request" and e.get("jti") == jti]


# =============================================================================== records

def _pid_b64(pid):
    s = pid.replace("-", "+").replace("_", "/")
    return s + "=" * ((4 - len(s) % 4) % 4)


def pid_sql(pid):
    return f"decode('{_pid_b64(pid)}','base64')"


def record_state(pid):
    return psql(f"SELECT state FROM public.pending_effect WHERE pending_id={pid_sql(pid)}")


def record_params(pid):
    return psql(f"SELECT params FROM public.pending_effect WHERE pending_id={pid_sql(pid)}")


def pe_row(pid):
    rows = psql_json(f"SELECT state, reason, released, resends, reconcile_rounds, anomaly, provider_refund_id, "
                     f"settlement, amount_minor, charge_id FROM nodkey.payment_effect WHERE pending_id={pid_sql(pid)}")
    return rows[0] if rows else None


def denial(pid):
    return psql(f"SELECT reason FROM nodkey.refund_denial WHERE pending_id={pid_sql(pid)}")


def crs(charge):
    rows = psql_json(f"SELECT succeeded_minor, inflight_minor, unknown_minor FROM nodkey.charge_refund_state "
                     f"WHERE charge_id='{charge}'")
    return rows[0] if rows else {"succeeded_minor": 0, "inflight_minor": 0, "unknown_minor": 0}


def grant_text(pid):
    b = psql(f"SELECT encode(grant_bytes,'base64') FROM public.pending_effect WHERE pending_id={pid_sql(pid)}")
    b = b.replace("\n", "").strip()
    return base64.urlsafe_b64encode(base64.b64decode(b)).decode().rstrip("=") if b else None


def wait_state(pid, want, timeout=30):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        last = record_state(pid)
        if last in want:
            return last
        time.sleep(0.5)
    return last


def consistent(order):
    """Broker charge state vs provider ledger: succeeded_minor equals the provider's non-failed sum,
    nothing left in flight or unknown."""
    c, refunds = ledger_charge(order["charge_id"])
    k = crs(order["charge_id"])
    live = sum(r["amount"] for r in refunds if r.get("status") != "failed")
    ok = c is not None and k["succeeded_minor"] == live and k["inflight_minor"] == 0 and k["unknown_minor"] == 0
    return ok, f"provider_refunds={len(refunds)} provider_sum={live} broker={k}"


# =============================================================================== flows

TOKEN_RE = re.compile(r'name="token" value="([^"]+)"')
DIGEST_RE = re.compile(r'name="digest" value="([0-9a-f]{64})"')
TYPED_RE = re.compile(r'name="(confirm_[a-z_]+)"')
INERT_SECONDS = 1.6  # gateway rejects approvals sooner than 1.5 s after rendering (GW-R-01)
UNIFORM = "This request is not available."


def fmt_minor(n, cur):
    e = EXPONENT[cur]
    return str(n) if e == 0 else f"{n // 10**e}.{n % 10**e:0{e}d}"


def login_auth(cli, user_idx, return_to_confirm_pid=None):
    if return_to_confirm_pid:
        cli.request(AUTH_ORIGIN, "GET", f"/confirm/{return_to_confirm_pid}", sec_fetch="navigate")
    st, h, body = cli.request(AUTH_ORIGIN, "GET", "/login", sec_fetch="navigate")
    csrf = (re.search(r'name="csrf" value="([^"]+)"', body) or [None, None])[1]
    st, h, body = cli.request(AUTH_ORIGIN, "POST", "/login", body=f"user={user_idx}&csrf={csrf}",
                              sec_fetch="navigate", origin_hdr=AUTH_ORIGIN)
    loc = cli.header(h, "location")
    return st, loc[0] if loc else None


def login_app(cli, user_idx):
    """App-session hand-off: app /.nodkey/login -> auth /login/app -> login ceremony -> callback."""
    st, h, _ = cli.request(APP_ORIGIN, "GET", "/.nodkey/login", sec_fetch="navigate")
    loc = (cli.header(h, "location") or [""])[0]
    path = loc.replace(AUTH_ORIGIN, "")
    cli.request(AUTH_ORIGIN, "GET", path, sec_fetch="navigate")
    st, loc = login_auth(cli, user_idx)
    if not loc or "/.nodkey/callback" not in loc:
        return False
    st, h, _ = cli.request(APP_ORIGIN, "GET", loc.replace(APP_ORIGIN, ""), sec_fetch="navigate")
    return st in (302, 303) and any(k.startswith("__Host-nodkey_session") for k in cli.jars[APP])


def app_propose(cli, order_id, amount_minor, currency, customer):
    st, h, body = cli.request(APP_ORIGIN, "POST", "/refund",
                              body=f"order_id={order_id}&amount_minor={amount_minor}&currency={currency}"
                                   f"&customer={customer}", sec_fetch="navigate", origin_hdr=APP_ORIGIN)
    loc = (cli.header(h, "location") or [None])[0]
    if not loc or "/confirm/" not in loc:
        return None, st, body
    return loc.rstrip("/").split("/confirm/")[-1], st, body


def get_confirm(cli, pid):
    return cli.request(AUTH_ORIGIN, "GET", f"/confirm/{pid}", sec_fetch="navigate")


def typed_fields(pid, page):
    params = json.loads(record_params(pid) or "{}")
    cur = params.get("currency", "USD")
    return {f: fmt_minor(int(params[f[len("confirm_"):]]), cur) for f in TYPED_RE.findall(page)}


def post_decision(cli, pid, token, digest, typed=None, decision="approve", **kw):
    body = f"token={token}&digest={digest}&decision={decision}"
    for k, v in (typed or {}).items():
        body += f"&{k}={v}"
    return cli.request(AUTH_ORIGIN, "POST", f"/confirm/{pid}/decision", body=body, **kw)


def approve(cli, pid, wait_final=True, timeout=40):
    """One real browser approval: render, wait past the inert period, type the amount, approve.
    Exactly one attempt. Returns (http status of the decision, final record state)."""
    st, _, page = get_confirm(cli, pid)
    tok, dig = TOKEN_RE.search(page), DIGEST_RE.search(page)
    if not tok:
        return st, record_state(pid)
    time.sleep(INERT_SECONDS)
    dst, _, _ = post_decision(cli, pid, tok.group(1), dig.group(1), typed=typed_fields(pid, page),
                              sec_fetch="navigate", origin_hdr=AUTH_ORIGIN)
    if not wait_final:
        return dst, record_state(pid)
    return dst, wait_state(pid, SAFE_STATES, timeout)


def customer_flow(order, amount, customer=None, currency=None, wait_final=True, timeout=40):
    """Shop proposes a refund for `customer` (default: the order owner); that customer signs in on
    the auth origin and approves. Returns (pid, final state)."""
    cust = customer or order["owner_sub"]
    cli = Client(CTX)
    pid, st, body = app_propose(cli, order["order_id"], amount, currency or order["currency"], cust)
    if not pid:
        return None, f"propose failed: {st} {body[-160:]}"
    login_auth(cli, CUST_IDX[cust], return_to_confirm_pid=pid)
    _, state = approve(cli, pid, wait_final=wait_final, timeout=timeout)
    return pid, state


def wait_pe(pid, want=("SUCCEEDED", "FAILED"), timeout=90):
    end = time.time() + timeout
    row = None
    while time.time() < end:
        row = pe_row(pid)
        if row and row["state"] in want:
            return row
        time.sleep(1)
    return row


def app_status(pid):
    st, _, body = Client(CTX).request(APP_ORIGIN, "GET", f"/status/{pid}", sec_fetch="navigate")
    g = lambda n: (re.search(rf'id="{n}">([^<]*)<', body) or [None, None])[1]
    return {"http": st, "state": g("state"), "outcome": g("outcome"), "reason": g("reason"), "body": body}


def rce(php, timeout=40):
    st, _, body = Client(CTX).request(APP_ORIGIN, "POST", "/debug/eval", body=php.encode(),
                                      headers={"Content-Type": "application/x-www-form-urlencoded"},
                                      timeout=timeout)
    return body


def rce_json(php):
    out = rce(LIB + "\n" + php)
    try:
        return json.loads(out.strip().splitlines()[-1])
    except Exception:
        return {"harness_error": out[:300]}


def load_probe(name):
    with open(f"{ROOT}/tests/demop/probes/{name}") as f:
        return f.read()


def strip_php_tag(src):
    return re.sub(r"^<\?php\n", "", src, count=1)


def w_call(op, args):
    """Attacker C: one call on socket W from inside the shop (RCE)."""
    return rce_json(f"echo json_encode(sock_call(W_SOCK, {json.dumps(op)}, json_decode({json.dumps(json.dumps(args))}, true)));")


def w_code(r):
    if not isinstance(r, dict):
        return str(r)
    return "ok" if r.get("ok") else (r.get("error") or {}).get("code", r.get("harness_error", "?"))


def p_client(lines, concurrent=False, service="broker"):
    """Attacker J: runs the P test client inside `service` (as that container's uid) with the
    given request lines; returns the parsed responses (or error strings)."""
    payload = (f"concurrent={1 if concurrent else 0}\n" + "\n".join(lines) + "\n").encode()
    src = load_probe("pclient.pl")
    r = compose("exec", "-T", service, "perl", "-e", src, input_bytes=payload, timeout=120)
    out = []
    for ln in r.stdout.decode().splitlines():
        try:
            out.append(json.loads(ln))
        except json.JSONDecodeError:
            out.append(ln)
    return out, r.stderr.decode()


def p_line(op, args):
    return json.dumps({"v": 2, "id": "h" + hashlib.sha256(json.dumps(args).encode()).hexdigest()[:8],
                       "op": op, "args": args})


# =============================================================================== setup

def seed_orders():
    """Operator path (payments-adapter-v1 §7.1): each orders row is asserted against simpay's
    admin ledger, then inserted with the nodkey_shop_operator role over the db's local socket."""
    led = ledger()
    charges = {c["id"]: c for c in led.get("charges", [])}
    bad = []
    values = []
    for o in DATA["orders"]:
        c = charges.get(o["charge_id"])
        if not c or c["amount"] != o["captured_minor"] or c["currency"].upper() != o["currency"] \
                or c["amount_refunded"] != 0 or c["account"] != DATA["account"]:
            bad.append(o["order_id"])
            continue
        values.append(f"({o['order_id']},'{o['ten']}','{o['owner_sub']}','{o['charge_id']}','{o['currency']}',"
                      f"{o['captured_minor']},0,'captured')")
    if bad:
        return False, f"orders not matching the provider ledger: {bad}"
    pw = open(f"{OUT}/secrets/db_operator_password").read().strip()
    sql = ("INSERT INTO nodkey.orders (order_id, ten, owner_sub, charge_id, currency, captured_minor, "
           "external_refunded_minor, status) VALUES " + ",".join(values))
    r = compose("exec", "-T", "-e", f"PGPASSWORD={pw}", "db", "psql", "-h", "/var/run/postgresql",
                "-U", "nodkey_shop_operator", "-d", "ledger", "-v", "ON_ERROR_STOP=1", "-tAc", sql)
    n = psql("SELECT count(*) FROM nodkey.orders")
    return r.returncode == 0 and n == str(len(DATA["orders"])), \
        f"rc={r.returncode} rows={n} {r.stderr.decode()[-200:]}"


# =============================================================================== tests

def t_legit():
    log("\n== L: legit refund (alice, her own order, with approval) ==")
    o = ORD["legit"]
    cli = Client(CTX)
    ok_login = login_app(cli, CUST_IDX["user:alice"])
    st, _, page = cli.request(APP_ORIGIN, "GET", "/orders", sec_fetch="navigate")
    shows = f'data-order="{o["order_id"]}"' in page and 'data-order="1003"' not in page
    record("legit", "L-01", "My orders (payments.get_order, read grant) lists alice's orders only",
           "§8", "SI-06/SI-10", verdict(ok_login and st == 200 and shows),
           f"app_session={ok_login} status={st} own_order_listed={f'data-order=\"{o['order_id']}\"' in page} "
           f"bob_order_hidden={'data-order=\"1003\"' not in page}")
    before_c, before_r = ledger_charge(o["charge_id"])
    pid, st_, body = app_propose(cli, o["order_id"], 1250, "USD", "user:alice")
    record("legit", "L-02", "Request refund -> effect.propose -> 303 to confirm_url", "T12", "SI-20",
           verdict(pid is not None), f"pid={pid} status={st_}")
    if not pid:
        return None
    st, _, page = get_confirm(cli, pid)  # alice already has an auth session from the hand-off
    shows = (st == 200 and "12.50" in page and o["charge_id"] in page and TOKEN_RE.search(page) is not None)
    record("legit", "L-03", "confirm page shows exact amount, currency and the signed charge id", "§8, T12",
           "SI-20/SI-21", verdict(shows), f"status={st} amount={'12.50' in page} charge={o['charge_id'] in page}")
    dst, state = approve(cli, pid)
    row = wait_pe(pid)
    c, refunds = ledger_charge(o["charge_id"])
    cons, cdetail = consistent(o)
    good = state == "SUCCEEDED" and row and row["state"] == "SUCCEEDED" and len(refunds) == 1 \
        and refunds[0]["amount"] == 1250 and refunds[0]["currency"].upper() == "USD" and cons
    record("legit", "L-04", "approval -> SUCCEEDED; simpay shows exactly one 12.50 USD refund; broker charge state consistent",
           "PT-04 (single), §7", "SI-09/SI-20", verdict(good),
           f"record={state} pe={row and row['state']} {cdetail}")
    s = app_status(pid)
    record("legit", "L-05", "status page shows only the closed-enum outcome", "§8", "SI-16",
           verdict(s["state"] == "SUCCEEDED" and s["outcome"] == "succeeded" and "re_" not in s["body"]
                   and o["charge_id"] not in s["body"]),
           f"state={s['state']} outcome={s['outcome']} reason={s['reason']!r}")
    st, _, page = cli.request(APP_ORIGIN, "GET", f"/orders/{o['order_id']}", sec_fetch="navigate")
    record("legit", "L-06", "get_order.refunded_minor = external + succeeded after the refund", "PT-37", "§8",
           verdict("12.50 USD" in page.split(f'data-order="{o["order_id"]}"')[-1][:300] if st == 200 else False),
           f"status={st}")
    return pid


# =============================================================================== PT helpers
#
# Every PT test below uses the demo's own seed data (examples/confirmed-refund/config/demo-data.json)
# and asserts against the oracles above: broker DB rows (postgres superuser in the db container),
# simpay's admin ledger, the adapter's audit log, and HTTP status codes. A case that cannot be
# exercised in this environment is recorded NOT TESTED with the reason; nothing is PASS without an
# assertion.

GID = "PT"
HOSTILE_MARKERS = ("onerror=alert", "ignore previous instructions", "<script>", "svg onload")


def nt(tid, title, maps, si, reason):
    record(GID, tid, title, maps, si, "NOT TESTED", reason)


def pid_hex(pid):
    return base64.b64decode(_pid_b64(pid)).hex()


def refunds_of(charge):
    return ledger_charge(charge)[1]


def live_sum(charge):
    return sum(r["amount"] for r in refunds_of(charge) if r.get("status") != "failed")


def rule(match_charge, kind, times=1, op="create_refund", nth=1, **params):
    m = {"charge": match_charge}
    if op:
        m["op"] = op
    return {"match": m, "fault": {"kind": kind, **params}, "nth": nth, "times": times}


def install(rules, malicious=False):
    """Installs a simpay fault plan; returns (ok, response). A failed install makes the caller
    INCONCLUSIVE, never PASS."""
    if malicious:
        set_malicious(True)
    r = set_faults(rules)
    return (isinstance(r, dict) and r.get("installed") == len(rules)), r


def grant_bytes_present(pid):
    return psql(f"SELECT grant_bytes IS NOT NULL FROM public.pending_effect WHERE pending_id={pid_sql(pid)}") == "t"


def creates(pid):
    return len(creates_sent(pid_hex(pid)))


def calls(pid):
    return adapter_calls(pid_hex(pid))


def operator_sql(sql):
    pw = open(f"{OUT}/secrets/db_operator_password").read().strip()
    r = compose("exec", "-T", "-e", f"PGPASSWORD={pw}", "db", "psql", "-h", "/var/run/postgresql",
                "-U", "nodkey_shop_operator", "-d", "ledger", "-v", "ON_ERROR_STOP=1", "-tAc", sql)
    return r.returncode, r.stdout.decode().strip(), r.stderr.decode().strip()


def as_role(role, stmt):
    """Runs one statement as `role` (SET ROLE in a superuser session) inside a transaction that is
    always rolled back. Returns the error text ('' if the statement succeeded)."""
    out, err = psql_err(f"BEGIN; SET LOCAL ROLE {role}; {stmt}; ROLLBACK;")
    return err


def infra(service, *args, user=None):
    src = load_probe("infra.pl")
    cmd = ["exec", "-T"] + (["--user", user] if user else []) + [service, "perl", "-e", src, *args]
    r = compose(*cmd, timeout=180)
    out = {}
    toks = []
    for ln in r.stdout.decode().splitlines():
        k, _, v = ln.partition("\t")
        if k == "token":
            toks.append(v)
        else:
            out[k] = v
    out["_tokens"] = toks
    out["_rc"] = r.returncode
    return out


def hello_kid():
    resp, _ = p_client([p_line("adapter.hello", {})])
    r = resp[0] if resp else {}
    return (r.get("result") or {}).get("idem_kid") if isinstance(r, dict) else None, r


def p_code(r):
    if not isinstance(r, dict):
        return str(r)
    if r.get("ok"):
        res = r.get("result") or {}
        return "ok:" + str(res.get("class", res.get("state", "")))
    return (r.get("error") or {}).get("code", "?")


def secrets_real():
    key = open(f"{OUT}/secrets/adapter/simpay_key").read().strip()
    kidem = open(f"{OUT}/secrets/adapter/k_idem").read().strip()
    return key, kidem


def logs_all():
    return compose_logs("adapter") + compose_logs("broker") + compose_logs("gateway") + compose_logs("authority")


def broker_alarms():
    return [e for e in json_lines(compose_logs("broker")) if e.get("event") == "alarm"]


def shop_order_view(sub, order_id):
    """payments.get_order through the shop as the signed-in owner: returns refunded_minor text."""
    cli = Client(CTX)
    if not login_app(cli, CUST_IDX[sub]):
        return None
    st, _, page = cli.request(APP_ORIGIN, "GET", f"/orders/{order_id}", sec_fetch="navigate")
    seg = page.split(f'data-order="{order_id}"')
    if st != 200 or len(seg) < 2:
        return None
    cells = re.findall(r"<td>([^<]*)</td>", seg[1][:400])
    return cells[2] if len(cells) > 2 else None  # "<refunded> <CUR>"


def flow_ok(o, amount, **kw):
    pid, state = customer_flow(o, amount, **kw)
    return pid, state


def paynet_up():
    r = compose("--profile", "probe", "up", "-d", "--wait", "paynet-probe", timeout=120)
    return r.returncode == 0


def paynet_down():
    compose("--profile", "probe", "rm", "-sf", "paynet-probe", timeout=120)


# =============================================================================== adapter start trials

ADAPTER_IMG = "nodkey/demop-adapter:dev"
_TRIAL = [0]


def _docker(*args, timeout=120, input_bytes=None):
    return subprocess.run(["docker", *args], capture_output=True, timeout=timeout, input=input_bytes)


def adapter_trial(cfg_mut=None, ca_bytes=None, cfg_mode="0444", key_mode="0400"):
    """Starts a throw-away adapter (network none, same image, uid 10006, read-only, cap_drop ALL)
    from a copy of the demo's §2 inputs with one change, and returns (started, refuse_reason).
    The copies are owned by root / uid 10006 in fresh named volumes (DEMOP-F02), exactly as
    adapter-init does for the real one."""
    import os, shutil
    _TRIAL[0] += 1
    n = _TRIAL[0]
    stage = f"{OUT}/pt-stage/trial{n}"
    shutil.rmtree(stage, ignore_errors=True)
    shutil.copytree(f"{OUT}/adapter-stage", stage)
    cfg = json.load(open(f"{stage}/etc/config.json"))
    if cfg_mut:
        cfg_mut(cfg)
    json.dump(cfg, open(f"{stage}/etc/config.json", "w"))
    if ca_bytes is not None:
        open(f"{stage}/etc/ca.crt", "wb").write(ca_bytes)
    for root, _, files in os.walk(stage):
        for f in files:
            os.chmod(os.path.join(root, f), 0o644)
    ve, vs, name = f"nodkey-demop-pt-etc{n}", f"nodkey-demop-pt-sec{n}", f"nodkey-demop-pt-adapter{n}"
    try:
        init = ("set -e; for f in config.json keys.json ca.crt; do install -m 0444 /staging/etc/$f /etc/nodkey-adapter/$f; done; "
                f"chmod {cfg_mode} /etc/nodkey-adapter/config.json; "
                "for f in simpay_key k_idem db_password; do install -m 0400 /staging/secrets/$f /run/adapter-secrets/$f; "
                "chown 10006:10006 /run/adapter-secrets/$f; done; "
                f"chmod {key_mode} /run/adapter-secrets/simpay_key")
        r = _docker("run", "--rm", "--network", "none", "--user", "0:0", "--cap-drop", "ALL", "--cap-add", "CHOWN",
                    "--cap-add", "FOWNER", "--security-opt", "no-new-privileges:true",
                    "-v", f"{ve}:/etc/nodkey-adapter", "-v", f"{vs}:/run/adapter-secrets", "-v", f"{stage}:/staging:ro",
                    "--entrypoint", "sh", ADAPTER_IMG, "-c", init)
        if r.returncode != 0:
            return None, "trial init failed: " + r.stderr.decode()[-200:]
        _docker("rm", "-f", name)
        r = _docker("run", "-d", "--name", name, "--network", "none", "--user", "10006:10006", "--read-only",
                    "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                    "-v", f"{ve}:/etc/nodkey-adapter:ro", "-v", f"{vs}:/run/adapter-secrets:ro",
                    "--tmpfs", "/run/nodkey/br-pay:uid=10006,gid=10002,mode=2750",
                    "--tmpfs", "/run/pg-adapter:uid=70,gid=10006,mode=2750", ADAPTER_IMG)
        if r.returncode != 0:
            return None, "trial run failed: " + r.stderr.decode()[-200:]
        time.sleep(3)
        logs = _docker("logs", name).stdout.decode("utf-8", "replace")
        ev = json_lines(logs)
        started = any(e.get("event") == "start" for e in ev)
        refused = next((e.get("reason") for e in ev if e.get("event") == "refuse_start"), None)
        return started, refused
    finally:
        _docker("rm", "-f", name)
        _docker("volume", "rm", "-f", ve, vs)
        shutil.rmtree(stage, ignore_errors=True)


# The running adapter's inputs (PT-25, PT-42): rewrite the staging copy, re-run adapter-init,
# restart the adapter; always restored afterwards.

def _wait_adapter():
    for _ in range(40):
        kid, _ = hello_kid()
        if kid:
            return True
        time.sleep(1)
    return False


def swap_adapter_inputs(cfg_mut=None, ca_bytes=None, keys_mut=None):
    etc = f"{OUT}/adapter-stage/etc"
    saved = {f: open(f"{etc}/{f}", "rb").read() for f in ("config.json", "ca.crt", "keys.json")}
    if cfg_mut:
        c = json.loads(saved["config.json"]); cfg_mut(c); open(f"{etc}/config.json", "w").write(json.dumps(c))
    if ca_bytes is not None:
        open(f"{etc}/ca.crt", "wb").write(ca_bytes)
    if keys_mut:
        k = json.loads(saved["keys.json"]); keys_mut(k); open(f"{etc}/keys.json", "w").write(json.dumps(k))
    compose("--profile", "setup", "run", "--rm", "--no-deps", "-T", "adapter-init")
    compose("restart", "adapter")
    return saved, _wait_adapter()


def restore_adapter_inputs(saved):
    etc = f"{OUT}/adapter-stage/etc"
    for f, b in saved.items():
        open(f"{etc}/{f}", "wb").write(b)
    compose("--profile", "setup", "run", "--rm", "--no-deps", "-T", "adapter-init")
    compose("restart", "adapter")
    return _wait_adapter()


def other_test_ca():
    """A second TEST-ONLY CA certificate from `simpay gen-test-ca` (its private key is discarded)."""
    import shutil
    d = f"{OUT}/pt-stage/otherca"
    shutil.rmtree(d, ignore_errors=True)
    __import__("os").makedirs(d)
    _docker("run", "--rm", "--network", "none", "--user", "0", "--cap-drop", "ALL", "--cap-add", "DAC_OVERRIDE",
            "-v", f"{d}:/out", "--entrypoint", "/usr/local/bin/simpay", "nodkey/demop-simpay:dev",
            "gen-test-ca", "--out", "/out/certs", "--dns-name", "simpay.test")
    try:
        return open(f"{d}/certs/simpay-TEST-ONLY-ca.crt", "rb").read()
    except OSError:
        return None
    finally:
        shutil.rmtree(d, ignore_errors=True)


# =============================================================================== PT: authorization

def t_pt01_foreign_order():
    log("\n== PT-01 / PT-20 / PT-34: refunds of an order the approver does not own ==")
    bob = ORD["bob_order"]
    before = len(refunds_of(bob["charge_id"]))
    # (a) alice is signed in and the shop proposes a refund of bob's order naming alice.
    cli = Client(CTX)
    pid, st, _ = app_propose(cli, bob["order_id"], 1000, "USD", "user:alice")
    if not pid:
        record(GID, "PT-01a", "alice proposes a refund of bob's order", "PT-01 / P-01", "SI-10", "INCONCLUSIVE", f"propose {st}")
        return
    login_auth(cli, CUST_IDX["user:alice"], return_to_confirm_pid=pid)
    cst, _, page = get_confirm(cli, pid)
    time.sleep(INERT_SECONDS)
    dst, _, _ = post_decision(cli, pid, "A" * 43, "0" * 64, sec_fetch="navigate", origin_hdr=AUTH_ORIGIN)
    time.sleep(2)
    state = record_state(pid)
    after = len(refunds_of(bob["charge_id"]))
    ok = cst == 404 and UNIFORM in page and TOKEN_RE.search(page) is None and dst == 404 \
        and state == "PENDING" and not grant_bytes_present(pid) and pe_row(pid) is None and after == before == 0
    record(GID, "PT-01a", "alice signed in, refund of bob's order 1003: uniform 404 at render and approval; never approved; ledger unchanged",
           "PT-01 / P-01, T03", "SI-10/SI-20", verdict(ok),
           f"render={cst} decision={dst} state={state} grant={grant_bytes_present(pid)} pe={pe_row(pid)} bob_refunds={after}")
    # (b) attacker C (RCE) proposes on order 1030 (owner c29) naming bob; bob signs in and tries.
    o = ORD["rce_bob_target"]
    r = w_call("effect.propose", {"op": "payments.refund", "params": {"order_id": o["order_id"], "amount_minor": 5000,
                                                                      "currency": "USD"},
                                  "approver": {"ten": "acme", "sub": "user:bob"}})
    pid2 = (r.get("result") or {}).get("pending_id") if isinstance(r, dict) else None
    if pid2:
        b = Client(CTX)
        login_auth(b, CUST_IDX["user:bob"], return_to_confirm_pid=pid2)
        cst2, _, page2 = get_confirm(b, pid2)
        c29 = Client(CTX)
        login_auth(c29, CUST_IDX["user:c29"], return_to_confirm_pid=pid2)
        cst3, _, _ = get_confirm(c29, pid2)
        time.sleep(1)
        ok2 = cst2 == 404 and cst3 == 404 and record_state(pid2) == "PENDING" and not grant_bytes_present(pid2) \
            and len(refunds_of(o["charge_id"])) == 0
        record(GID, "PT-01b", "RCE proposes refund of c29's order 1030 naming bob: bob and c29 both get 404; never approved",
               "PT-01 / P-01", "SI-10/SI-20", verdict(ok2),
               f"bob_render={cst2} owner_render={cst3} state={record_state(pid2)} refunds={len(refunds_of(o['charge_id']))}")
    else:
        record(GID, "PT-01b", "RCE proposal naming bob", "PT-01 / P-01", "SI-10", "INCONCLUSIVE", f"propose: {w_code(r)}")
    # (c) owner changed by the operator after the owner rendered the confirmation page (PT-20).
    o = ORD["owner_change"]
    cli = Client(CTX)
    pid3, _, _ = app_propose(cli, o["order_id"], 1000, "USD", o["owner_sub"])
    login_auth(cli, CUST_IDX[o["owner_sub"]], return_to_confirm_pid=pid3)
    cst, _, page = get_confirm(cli, pid3)
    tok, dig = TOKEN_RE.search(page), DIGEST_RE.search(page)
    typed = typed_fields(pid3, page) if tok else {}
    rc, _, err = operator_sql(f"UPDATE nodkey.orders SET owner_sub='user:c30' WHERE order_id={o['order_id']}")
    time.sleep(INERT_SECONDS)
    dst, dbody = None, ""
    if tok:
        dst, _, dbody = post_decision(cli, pid3, tok.group(1), dig.group(1), typed=typed, sec_fetch="navigate",
                                      origin_hdr=AUTH_ORIGIN)
    time.sleep(2)
    state = record_state(pid3)
    ok3 = cst == 200 and tok is not None and rc == 0 and dst == 200 and "Decision submitted" in dbody \
        and state == "PENDING" and not grant_bytes_present(pid3) \
        and pe_row(pid3) is None and creates(pid3) == 0 and len(refunds_of(o["charge_id"])) == 0
    record(GID, "PT-20a", "owner changed (operator) after render: delivery rejected (record stays PENDING, effect-protocol §4.3), neutral submitted page (§7.3 step 6), no payment_effect, no adapter call, ledger 0",
           "PT-20, PT-01 / P-01", "SI-10/SI-11", verdict(ok3),
           f"render={cst} operator_update_rc={rc} decision={dst} state={state} pe={pe_row(pid3)} creates={creates(pid3)} {err[-80:]}")


def t_pt20_status_immutable():
    log("\n== PT-20: order status change after render; immutable columns ==")
    o = ORD["status_change"]
    cli = Client(CTX)
    pid, _, _ = app_propose(cli, o["order_id"], 700, "USD", o["owner_sub"])
    login_auth(cli, CUST_IDX[o["owner_sub"]], return_to_confirm_pid=pid)
    cst, _, page = get_confirm(cli, pid)
    tok, dig = TOKEN_RE.search(page), DIGEST_RE.search(page)
    typed = typed_fields(pid, page) if tok else {}
    rc, _, err = operator_sql(f"UPDATE nodkey.orders SET status='disputed' WHERE order_id={o['order_id']}")
    time.sleep(INERT_SECONDS)
    dst, dbody = None, ""
    if tok:
        dst, _, dbody = post_decision(cli, pid, tok.group(1), dig.group(1), typed=typed, sec_fetch="navigate",
                                      origin_hdr=AUTH_ORIGIN)
    time.sleep(2)
    ok = cst == 200 and tok is not None and rc == 0 and dst == 200 and "Decision submitted" in dbody \
        and record_state(pid) == "PENDING" and not grant_bytes_present(pid) \
        and pe_row(pid) is None and creates(pid) == 0 and len(refunds_of(o["charge_id"])) == 0
    record(GID, "PT-20b", "status set to 'disputed' after render: delivery rejected (stays PENDING, no grant), no adapter call, ledger 0",
           "PT-20", "SI-10/SI-11", verdict(ok),
           f"render={cst} update_rc={rc} decision={dst} state={record_state(pid)} creates={creates(pid)} {err[-80:]}")
    res = {}
    for col, val in (("charge_id", "'ch_demop9999999'"), ("currency", "'EUR'"), ("captured_minor", "999999")):
        rc, _, err = operator_sql(f"UPDATE nodkey.orders SET {col}={val} WHERE order_id={ORD['legit']['order_id']}")
        res[col] = (rc, err.splitlines()[0][:90] if err else "")
    row = psql_json(f"SELECT charge_id, currency, captured_minor FROM nodkey.orders WHERE order_id={ORD['legit']['order_id']}")
    unchanged = row and row[0]["charge_id"] == ORD["legit"]["charge_id"] and row[0]["currency"] == "USD" \
        and row[0]["captured_minor"] == ORD["legit"]["captured_minor"]
    trig = {}
    for col, val in (("charge_id", "'ch_demop9999999'"), ("currency", "'EUR'"), ("captured_minor", "999999")):
        _, err = psql_err(f"BEGIN; UPDATE nodkey.orders SET {col}={val} WHERE order_id={ORD['legit']['order_id']}; ROLLBACK;")
        trig[col] = "immutable column changed" in err
    ok = all(rc != 0 for rc, _ in res.values()) and unchanged and all(trig.values())
    record(GID, "PT-20c", "UPDATE of immutable orders columns: operator lacks the column privilege; even the superuser is rejected by the trigger",
           "PT-20", "SI-10", verdict(ok), f"operator={res} trigger_rejects_superuser={trig} unchanged={bool(unchanged)}")


def t_pt02_tamper():
    log("\n== PT-02: approve 5.00, then try 50.00 without a new approval ==")
    o = ORD["tamper"]
    pid, state = customer_flow(o, 500)
    row = wait_pe(pid) if pid else None
    if not pid or state != "SUCCEEDED":
        record(GID, "PT-02", "approved 5.00 refund executes", "PT-02 / P-02", "SI-06", "INCONCLUSIVE", f"pid={pid} state={state}")
        return
    g = grant_text(pid)
    # (a) the workload proposes 50.00 on its own: a new record, which nobody approved.
    r = w_call("effect.propose", {"op": "payments.refund", "params": {"order_id": o["order_id"], "amount_minor": 5000,
                                                                      "currency": "USD"},
                                  "approver": {"ten": "acme", "sub": o["owner_sub"]}})
    pid_a = (r.get("result") or {}).get("pending_id") if isinstance(r, dict) else None
    # (b) it tries to hand the approved grant (or any grant) to the broker on W.
    rb = w_call("grant.deliver", {"pending_id": pid_a or pid, "grant": g})
    # (c) the owner renders the 50.00 proposal and the request carries an edited digest.
    cli = Client(CTX)
    login_auth(cli, CUST_IDX[o["owner_sub"]], return_to_confirm_pid=pid_a)
    cst, _, page = get_confirm(cli, pid_a) if pid_a else (0, [], "")
    tok, dig = TOKEN_RE.search(page), DIGEST_RE.search(page)
    dst = None
    if tok:
        time.sleep(INERT_SECONDS)
        bad = ("0" if dig.group(1)[0] != "0" else "1") + dig.group(1)[1:]
        dst, _, _ = post_decision(cli, pid_a, tok.group(1), bad, typed=typed_fields(pid_a, page),
                                  sec_fetch="navigate", origin_hdr=AUTH_ORIGIN)
    time.sleep(3)
    refs = refunds_of(o["charge_id"])
    ok = (pid_a is not None and w_code(rb) in ("unknown_operation", "operation_not_permitted") and tok is not None
          and dst == 404 and record_state(pid_a) == "PENDING" and not grant_bytes_present(pid_a)
          and len(refs) == 1 and refs[0]["amount"] == 500)
    record(GID, "PT-02", "approved 5.00; 50.00 via new proposal / W grant.deliver / edited digest: no grant, ledger one 5.00",
           "PT-02 / P-02", "SI-06", verdict(ok),
           f"new_pid_state={pid_a and record_state(pid_a)} grant_on_new={pid_a and grant_bytes_present(pid_a)} "
           f"W_deliver={w_code(rb)} edited_digest_decision={dst} ledger={[x['amount'] for x in refs]}")
    return pid


def t_pt03_currency():
    log("\n== PT-03: JPY 1000 on a USD order ==")
    o = ORD["currency_switch"]
    cli = Client(CTX)
    pid, st, _ = app_propose(cli, o["order_id"], 1000, "JPY", o["owner_sub"])
    if not pid:
        record(GID, "PT-03", "JPY refund on USD order", "PT-03 / P-03", "SI-10", "INCONCLUSIVE", f"propose {st}")
        return
    login_auth(cli, CUST_IDX[o["owner_sub"]], return_to_confirm_pid=pid)
    cst, _, page = get_confirm(cli, pid)
    time.sleep(1)
    ok = cst == 404 and UNIFORM in page and not grant_bytes_present(pid) and pe_row(pid) is None \
        and creates(pid) == 0 and len(refunds_of(o["charge_id"])) == 0
    record(GID, "PT-03", "JPY 1000 on USD order 1006: refused at approval checks (uniform error, T22); nothing sent",
           "PT-03 / P-03", "SI-10", verdict(ok),
           f"render={cst} grant={grant_bytes_present(pid)} pe={pe_row(pid)} creates={creates(pid)} "
           f"(the refusal happens at render/approval, so the workload never receives a T1 reason)")


def t_pt04_redeliver():
    log("\n== PT-04: grant re-delivered 50x concurrently on socket A (authority uid) ==")
    o = ORD["jpy_order"]
    pid, state = customer_flow(o, 1000)
    wait_pe(pid)
    if state != "SUCCEEDED":
        record(GID, "PT-04", "JPY refund executes", "PT-04 / P-04", "SI-09", "INCONCLUSIVE", f"state={state}")
        return
    g = grant_text(pid)
    line = json.dumps({"v": 2, "id": "hredeliver", "op": "grant.deliver", "args": {"pending_id": pid, "grant": g}})
    payload = ("concurrent=1\n" + "\n".join([line] * 50) + "\n").encode()
    r = compose("exec", "-T", "-e", "P_SOCK=/run/nodkey/au-broker/broker.sock", "authority", "perl", "-e",
                load_probe("pclient.pl"), input_bytes=payload, timeout=120)
    resps = [ln for ln in r.stdout.decode().splitlines() if ln.strip()]
    time.sleep(8)  # at least one payments recovery tick (5 s)
    n_pe = psql(f"SELECT count(*) FROM nodkey.payment_effect WHERE pending_id={pid_sql(pid)}")
    refs = refunds_of(o["charge_id"])
    accepted = sum(1 for x in resps if '"accepted"' in x)
    ok = len(resps) == 50 and n_pe == "1" and len(refs) == 1 and refs[0]["amount"] == 1000 and creates(pid) == 1 \
        and record_state(pid) == "SUCCEEDED"
    record(GID, "PT-04", "same grant re-delivered 50x concurrently (A socket, authority uid) + recovery loop: one row, ledger 1",
           "PT-04 / P-04", "SI-09", verdict(ok),
           f"responses={len(resps)} accepted={accepted} sample={resps[:1]} payment_effect_rows={n_pe} "
           f"ledger={[x['amount'] for x in refs]} creates={creates(pid)}")


def t_pt05_race():
    log("\n== PT-05: two approvals race for the last 10.00 ==")
    o = ORD["race"]
    pid0, s0 = customer_flow(o, 1000)
    wait_pe(pid0)
    pids, clis = [], []
    for _ in range(2):
        c = Client(CTX)
        p, _, _ = app_propose(c, o["order_id"], 1000, "USD", o["owner_sub"])
        login_auth(c, CUST_IDX[o["owner_sub"]], return_to_confirm_pid=p)
        pids.append(p); clis.append(c)
    pages = [get_confirm(c, p)[2] for c, p in zip(clis, pids)]
    toks = [(TOKEN_RE.search(pg), DIGEST_RE.search(pg)) for pg in pages]
    if s0 != "SUCCEEDED" or not all(t for t, _ in toks):
        record(GID, "PT-05", "race for the last 10.00", "PT-05 / P-05", "SI-11", "INCONCLUSIVE", f"first={s0}")
        return
    typed = [typed_fields(p, pg) for p, pg in zip(pids, pages)]
    time.sleep(INERT_SECONDS)
    ths = [threading.Thread(target=post_decision, args=(c, p, t.group(1), d.group(1)),
                            kwargs={"typed": ty, "sec_fetch": "navigate", "origin_hdr": AUTH_ORIGIN})
           for c, p, (t, d), ty in zip(clis, pids, toks, typed)]
    for t in ths:
        t.start()
    for t in ths:
        t.join(30)
    finals = [wait_state(p, SAFE_STATES, 40) for p in pids]
    for p in pids:
        wait_pe(p, timeout=30) if pe_row(p) else None
    reasons = [denial(p) for p in pids]
    statuses = [app_status(p)["reason"] for p in pids]
    total = live_sum(o["charge_id"])
    ok = sorted(finals) == ["FAILED", "SUCCEEDED"] and total == 2000 and total <= o["captured_minor"] \
        and any(r in ("order_busy", "insufficient_refundable") for r in reasons) \
        and "not_refundable" in statuses and len(refunds_of(o["charge_id"])) == 2
    record(GID, "PT-05", "two concurrent approvals for the last 10.00: one SUCCEEDED, other denied not_refundable; ledger sum = captured",
           "PT-05 / P-05", "SI-11", verdict(ok),
           f"finals={finals} denial={reasons} workload_reason={statuses} provider_sum={total}/{o['captured_minor']}")


# =============================================================================== PT: provider faults

def _fault_flow(tag, amount, rules, malicious=False, final=("SUCCEEDED", "FAILED"), timeout=150):
    o = ORD[tag]
    ok_i, r = install(rules, malicious)
    if not ok_i:
        return o, None, None, f"fault install failed: {r}"
    pid, state = customer_flow(o, amount)
    row = wait_pe(pid, final, timeout) if pid else None
    clear_faults()
    if malicious:
        set_malicious(False)
    return o, pid, row, state


def t_pt06_commit_then_drop():
    log("\n== PT-06 / PT-37: commit_then_drop; second approval while UNKNOWN ==")
    o = ORD["f_commit_then_drop"]
    ok_i, r = install([rule(o["charge_id"], "commit_then_drop")])
    if not ok_i:
        record(GID, "PT-06", "commit_then_drop", "PT-06 / P-06", "SI-15", "INCONCLUSIVE", r)
        return
    pid, state = customer_flow(o, 1000)
    clear_faults()
    first = state
    refunded_view = shop_order_view(o["owner_sub"], o["order_id"])  # while UNKNOWN
    unknown_at_view = (pe_row(pid) or {}).get("state")
    pid2, state2 = customer_flow(o, 500)
    reason2 = denial(pid2) if pid2 else None
    row = wait_pe(pid, ("SUCCEEDED", "FAILED"), 150)
    refs = refunds_of(o["charge_id"])
    ok = first == "UNKNOWN" and state2 == "FAILED" and reason2 == "order_busy" and row and row["state"] == "SUCCEEDED" \
        and row["resends"] == 0 and creates(pid) == 1 and len(refs) == 1 and refs[0]["amount"] == 1000 \
        and creates(pid2) == 0
    record(GID, "PT-06", "commit_then_drop: UNKNOWN; 2nd approval denied (order_busy); reconciler find -> SUCCEEDED without resend; ledger 1",
           "PT-06 / P-06, PT-11", "SI-15/SI-11", verdict(ok),
           f"first={first} second={state2}/{reason2} final={row and row['state']} resends={row and row['resends']} "
           f"creates={creates(pid)} ledger={[x['amount'] for x in refs]}")
    ok37 = unknown_at_view == "UNKNOWN" and refunded_view == "0.00 USD"
    record(GID, "PT-37a", "get_order.refunded_minor excludes an UNKNOWN row (= external + succeeded = 0.00)",
           "PT-37, §8", "SI-16", verdict(ok37) if unknown_at_view == "UNKNOWN" else "INCONCLUSIVE",
           f"row_state_at_view={unknown_at_view} shop_shows_refunded={refunded_view!r}")


def t_pt07_commit_after_delay():
    log("\n== PT-07: commit_after_delay > total_ms ==")
    o, pid, row, st = _fault_flow("f_commit_after_delay", 1000,
                                  [rule(ORD["f_commit_after_delay"]["charge_id"], "commit_after_delay", ms=8000)])
    if pid is None:
        record(GID, "PT-07", "commit_after_delay", "PT-07 / P-07", "SI-15", "INCONCLUSIVE", st)
        return
    refs = refunds_of(o["charge_id"])
    c = calls(pid)
    first = next((e for e in c if e.get("op") == "refund.create"), {})
    ok = row and row["state"] == "SUCCEEDED" and len(refs) == 1 and creates(pid) == 1 and row["resends"] == 0 \
        and first.get("class") == "ambiguous"
    record(GID, "PT-07", "commit_after_delay 8 s > total_ms 5 s: ambiguous, no resend while in progress, resolves SUCCEEDED; ledger 1",
           "PT-07 / P-07", "SI-15", verdict(ok),
           f"dispatch={st} first_create={first.get('class')}/{first.get('cause')} final={row and row['state']} "
           f"resends={row and row['resends']} creates={creates(pid)} ledger={len(refs)}")


def t_pt08_commit_then_500():
    log("\n== PT-08: commit_then_500 ==")
    o, pid, row, st = _fault_flow("f_commit_then_500", 1000, [rule(ORD["f_commit_then_500"]["charge_id"], "commit_then_500")])
    if pid is None:
        record(GID, "PT-08", "commit_then_500", "PT-08 / P-08", "SI-15", "INCONCLUSIVE", st)
        return
    refs = refunds_of(o["charge_id"])
    ok = st == "UNKNOWN" and row and row["state"] == "SUCCEEDED" and len(refs) == 1 and row["resends"] == 0
    record(GID, "PT-08", "commit_then_500: UNKNOWN, reconciler find -> SUCCEEDED; ledger 1",
           "PT-08 / P-08", "SI-15", verdict(ok),
           f"dispatch={st} final={row and row['state']} resends={row and row['resends']} creates={creates(pid)} ledger={len(refs)}")


def t_pt09_not_committed():
    log("\n== PT-09: faults where nothing was committed ==")
    cases = [("PT-09a", "f_fail_before_commit", "fail_before_commit", {}, 1100),
             ("PT-09b", "f_fail_before_commit", "drop_before_commit", {}, 1200),
             ("PT-09c", "f_fail_before_commit", "inflight_409", {"hold_ms": 1000}, 1300),
             ("PT-09d", "f_rate_limit", "rate_limit", {}, 1000)]
    for tid, tag, kind, params, amt in cases:
        o = ORD[tag]
        before = len(refunds_of(o["charge_id"]))
        _, pid, row, st = _fault_flow(tag, amt, [rule(o["charge_id"], kind, **params)])
        if pid is None:
            record(GID, tid, kind, "PT-09 / P-09", "SI-09", "INCONCLUSIVE", st)
            continue
        refs = refunds_of(o["charge_id"])
        mine = [x for x in refs if x["amount"] == amt]
        ok = row and row["state"] == "SUCCEEDED" and len(refs) == before + 1 and len(mine) == 1
        record(GID, tid, f"{kind}: not committed -> same-key resend/retry -> exactly one refund",
               "PT-09 / P-09", "SI-09", verdict(ok),
               f"dispatch={st} final={row and row['state']} resends={row and row['resends']} creates={creates(pid)} "
               f"refunds_for_this_grant={len(mine)} charge_refunds={before}->{len(refs)}")


# =============================================================================== PT: input validation

def t_pt10_12_inputs():
    log("\n== PT-10 / PT-12: malformed proposals on W and malformed requests on P ==")
    o = ORD["currency_switch"]
    n_before = psql("SELECT count(*) FROM public.pending_effect")
    base = {"order_id": o["order_id"], "currency": "USD"}
    appr = {"ten": "acme", "sub": o["owner_sub"]}
    # Literal JSON text on the wire (sent raw: PHP's json_encode would rewrite 1000.0 as 1000).
    bad_amounts = {"string": '"100"', "decimal_string": '"12.5"', "float": "12.5", "integral_float": "1000.0",
                   "exponent": "1e3", "exponent_upper": "1E3", "zero": "0", "negative": "-1", "minus_zero": "-0",
                   "over_2_53": str(2 ** 53), "over_u64": str(2 ** 64), "bool": "true", "null": "null",
                   "array": "[100]", "object": '{"v":100}'}
    res = {}
    for k, lit in bad_amounts.items():
        line = ('{"v":2,"id":"pamt","op":"effect.propose","args":{"op":"payments.refund","params":{"order_id":%d,'
                '"amount_minor":%s,"currency":"USD"},"approver":{"ten":"acme","sub":"%s"}}}\n' % (o["order_id"], lit, o["owner_sub"]))
        res[k] = w_code(rce_json(f"echo json_encode(sock_raw(W_SOCK, {json.dumps(line)}));"))
    res["charge_id_supplied"] = w_code(w_call("effect.propose", {
        "op": "payments.refund", "params": dict(base, amount_minor=100, charge_id=o["charge_id"]), "approver": appr}))
    dup = ('{"v":2,"id":"pdup","op":"effect.propose","args":{"op":"payments.refund","params":{"order_id":%d,'
           '"amount_minor":100,"amount_minor":5000,"currency":"USD"},"approver":{"ten":"acme","sub":"%s"}}}\n'
           % (o["order_id"], o["owner_sub"]))
    dup_code = w_code(rce_json(f"echo json_encode(sock_raw(W_SOCK, {json.dumps(dup)}));"))
    time.sleep(1)
    n_after = psql("SELECT count(*) FROM public.pending_effect")
    ok10 = all(c == "invalid_argument" for c in res.values()) and n_before == n_after
    record(GID, "PT-10a", "bad amount_minor forms (string, float, 1000.0, 1e3, 0, -1, -0, >2^53, >u64, bool, null, array, object) and charge_id supplied in propose -> invalid_argument; no record",
           "PT-10 / P-10, P-12", "SI-08", verdict(ok10), f"{res} pending_rows {n_before}->{n_after}")
    # payments-adapter-v1 Draft 3.3 §11 PT-10 (DEMOP-F04): a duplicate key is rejected by strict
    # framing (effect-protocol-v2 §1.2) as malformed_request, before argument validation.
    record(GID, "PT-10b", "duplicate amount_minor key in propose -> malformed_request (framing); no record",
           "PT-10 / P-10", "SI-08", verdict(dup_code == "malformed_request" and n_before == n_after),
           f"code={dup_code} pending_rows {n_before}->{n_after}")
    res12 = {
        "extra_param": w_code(w_call("effect.propose", {"op": "payments.refund",
                                                        "params": dict(base, amount_minor=100, note="x"), "approver": appr})),
        "extra_arg": w_code(w_call("effect.propose", {"op": "payments.refund", "params": dict(base, amount_minor=100),
                                                      "approver": appr, "extra": 1})),
        "extra_approver_member": w_code(w_call("effect.propose", {"op": "payments.refund",
                                                                  "params": dict(base, amount_minor=100),
                                                                  "approver": dict(appr, role="admin")})),
    }
    kid, _ = hello_kid()
    g = grant_text(LEGIT_PID[0]) if LEGIT_PID[0] else "AAAA"
    p_lines = [
        json.dumps({"v": 2, "id": "x1", "op": "refund.create", "args": {"grant": g, "idem_kid": kid, "amount_minor": 1}}),
        json.dumps({"v": 2, "id": "x2", "op": "refund.find", "args": {"grant": g, "idem_kid": kid, "x": 1}}),
        json.dumps({"v": 2, "id": "x3", "op": "adapter.hello", "args": {"x": 1}}),
        json.dumps({"v": 2, "id": "x4", "op": "refund.create", "args": {"grant": g, "idem_kid": kid}, "extra": 1}),
    ]
    before = creates(LEGIT_PID[0]) if LEGIT_PID[0] else 0
    pr, _ = p_client(p_lines)
    pcodes = [p_code(x) for x in pr]
    time.sleep(1)
    n_after2 = psql("SELECT count(*) FROM public.pending_effect")
    after = creates(LEGIT_PID[0]) if LEGIT_PID[0] else 0
    ok12 = all(c == "invalid_argument" for c in res12.values()) and n_after2 == n_after \
        and len(pcodes) == 4 and all(c in ("malformed_request", "invalid_argument") for c in pcodes) and after == before
    record(GID, "PT-12", "extra members in propose (W) and in P requests: invalid_argument / malformed_request; nothing sent",
           "PT-12 / P-12", "SI-16", verdict(ok12), f"W={res12} P={pcodes} creates_for_grant {before}->{after}")


def t_pt11_remaining():
    log("\n== PT-11: refund above the remaining refundable amount ==")
    o = ORD["remaining"]
    pid1, s1 = customer_flow(o, o["captured_minor"] + 1)
    r1, st1 = denial(pid1), app_status(pid1)["reason"]
    pid2, s2 = customer_flow(o, 2000)
    wait_pe(pid2)
    pid3, s3 = customer_flow(o, 1001)
    r3 = denial(pid3)
    refs = refunds_of(o["charge_id"])
    ok = s1 == "FAILED" and r1 == "insufficient_refundable" and st1 == "not_refundable" and len(calls(pid1)) == 0 \
        and pe_row(pid1) is None and s2 == "SUCCEEDED" and s3 == "FAILED" and r3 == "insufficient_refundable" \
        and len(calls(pid3)) == 0 and [x["amount"] for x in refs] == [2000]
    record(GID, "PT-11", "refund > remaining (fresh 30.01 of 30.00; 10.01 after 20.00): denied before dispatch, adapter calls 0",
           "PT-11 / P-11", "SI-11", verdict(ok),
           f"fresh={s1}/{r1}/{st1} adapter_calls={len(calls(pid1))} partial={s2} after_partial={s3}/{r3} "
           f"adapter_calls={len(calls(pid3))} ledger={[x['amount'] for x in refs]} (while-UNKNOWN case: PT-06)")


# =============================================================================== PT: lifetimes

def t_pt15_27_unknown_deadline():
    log("\n== PT-15 / PT-27: UNKNOWN beyond resend_deadline and R_max; W fuzz while UNKNOWN (about 4 min) ==")
    o = ORD["f_unknown_deadline"]
    ok_i, r = install([rule(o["charge_id"], "fail_before_commit", times=0)])
    if not ok_i:
        record(GID, "PT-15", "UNKNOWN beyond deadline", "PT-15 / P-15", "SI-15", "INCONCLUSIVE", r)
        return
    pid, state = customer_flow(o, 1000)
    if state != "UNKNOWN":
        record(GID, "PT-15", "UNKNOWN beyond deadline", "PT-15 / P-15", "SI-15", "INCONCLUSIVE", f"state={state}")
        return
    deadline = int(psql(f"SELECT resend_deadline FROM nodkey.payment_effect WHERE pending_id={pid_sql(pid)}") or 0)
    iat = int(psql(f"SELECT state_changed_at FROM public.pending_effect WHERE pending_id={pid_sql(pid)}") or 0)
    # PT-27: fuzz W during a period in which the reconciler has nothing scheduled for this row.
    fuzz = None
    end_wait = time.time() + 120
    while time.time() < end_wait:
        nca = int(psql(f"SELECT coalesce(next_check_at,0) FROM nodkey.payment_effect WHERE pending_id={pid_sql(pid)}") or 0)
        if nca - time.time() > 40:
            break
        time.sleep(3)
    nca = int(psql(f"SELECT coalesce(next_check_at,0) FROM nodkey.payment_effect WHERE pending_id={pid_sql(pid)}") or 0)
    if nca - time.time() > 40:
        c_before = len(calls(pid))
        fuzz_php = r'''
$ops = ['effect.propose','effect.status','payments.get_order','grant.deliver','refund.create','refund.find','idem.status',
        'adapter.hello','pending.get','effect.execute','effect.retry','effect.reconcile'];
$n = 0;
for ($i = 0; $i < 300; $i++) {
  $op = $ops[$i % count($ops)];
  $args = ['pending_id' => '%PID%', 'grant' => rtrim(strtr(base64_encode(random_bytes(64)), '+/', '-_'), '='),
           'order_id' => %OID%, 'amount_minor' => random_int(1, 10000), 'currency' => 'USD', 'idem_kid' => bin2hex(random_bytes(8))];
  sock_call(W_SOCK, $op, $args); $n++;
  sock_raw(W_SOCK, random_bytes(random_int(1, 200)) . "\n"); $n++;
}
echo json_encode(['sent' => $n]);
'''.replace("%PID%", pid).replace("%OID%", str(o["order_id"]))
        fr = rce_json(fuzz_php)
        time.sleep(3)
        c_after = len(calls(pid))
        fuzz = (fr, c_before, c_after, record_state(pid))
        ok27 = isinstance(fr, dict) and fr.get("sent") == 600 and c_after == c_before and record_state(pid) == "UNKNOWN"
        record(GID, "PT-27", "600 fuzzed W requests while the row is UNKNOWN: adapter call log unchanged, row unchanged",
               "PT-27", "SI-19", verdict(ok27), f"fuzz={fr} adapter_calls_for_row {c_before}->{c_after} state={record_state(pid)}")
    else:
        nt("PT-27", "fuzz W while UNKNOWN", "PT-27", "SI-19", f"no quiet reconciler window found (next_check_at={nca})")
    # PT-15: observe until past R_max.
    wait_until = iat + 180 + 20
    while time.time() < wait_until:
        time.sleep(5)
    clear_faults()
    ev = creates_sent(pid_hex(pid))
    late = [e for e in ev if e.get("ts_ms", 0) > deadline * 1000]
    row = pe_row(pid)
    refs = refunds_of(o["charge_id"])
    ok = row and row["state"] == "UNKNOWN" and row["reason"] == "operator_required" and not late and len(refs) == 0 \
        and len(ev) >= 1
    record(GID, "PT-15", "UNKNOWN past resend_deadline and R_max (test profile 180 s): no create sent after the deadline; stays UNKNOWN",
           "PT-15 / P-15", "SI-15", verdict(ok),
           f"creates={len(ev)} creates_after_deadline={len(late)} final={row and row['state']} resends={row and row['resends']} "
           f"rounds={row and row['reconcile_rounds']} reason={row and row['reason']} ledger={len(refs)}")
    return pid


# =============================================================================== PT: malicious provider

def t_pt16_lies():
    log("\n== PT-16: malicious provider lies ==")
    cases = [("PT-16a", "m_lie_amount", [rule(ORD["m_lie_amount"]["charge_id"], "lie_amount", times=0, op=None, amount=4999)], "lie"),
             ("PT-16b", "m_lie_charge", [rule(ORD["m_lie_charge"]["charge_id"], "lie_charge", times=0, op=None,
                                              charge="ch_demop0001001")], "lie"),
             ("PT-16c", "m_phantom_success", [rule(ORD["m_phantom_success"]["charge_id"], "phantom_success")], "phantom"),
             ("PT-16d", "m_deny_but_commit", [rule(ORD["m_deny_but_commit"]["charge_id"], "deny_but_commit")], "deny")]
    for tid, tag, rules, kind in cases:
        o = ORD[tag]
        ok_i, r = install(rules, malicious=True)
        if not ok_i:
            record(GID, tid, tag, "PT-16 / P-16", "SI-15", "INCONCLUSIVE", r)
            continue
        pid, state = customer_flow(o, 1000)
        if kind == "lie":
            time.sleep(35)  # dispatch + at least two reconciler rounds under the persistent lie
            row = pe_row(pid)
        else:
            row = wait_pe(pid, ("SUCCEEDED", "FAILED"), 150)
        clear_faults(); set_malicious(False)
        refs = refunds_of(o["charge_id"])
        live = [x for x in refs if x.get("status") != "failed"]
        if kind == "lie":
            ok = row and row["state"] != "SUCCEEDED" and len(live) <= 1 and state != "SUCCEEDED"
            what = "persistent lie (create, GET and list): never SUCCEEDED; ledger <= 1"
        elif kind == "phantom":
            ok = row and row["state"] == "SUCCEEDED" and len(live) == 1 and creates(pid) >= 2
            what = "phantom_success: not stored -> find not_found -> resend executes once; SUCCEEDED; ledger 1"
        else:
            ok = row and row["state"] == "SUCCEEDED" and len(live) == 1 and creates(pid) == 1
            what = "deny_but_commit: refused -> UNKNOWN -> find -> SUCCEEDED without resend; ledger 1"
        record(GID, tid, f"{tag[2:]}: {what}", "PT-16 / P-16", "SI-15", verdict(ok),
               f"dispatch={state} final={row and row['state']} anomaly={row and row['anomaly']} creates={creates(pid)} "
               f"ledger={[(x['amount'], x['status']) for x in refs]}")


def t_pt17_redirect():
    log("\n== PT-17: redirect to a listener on pay-egress ==")
    o = ORD["m_redirect"]
    if not paynet_up():
        nt("PT-17", "redirect", "PT-17 / P-17", "SI-02", "paynet-probe did not start")
        return
    try:
        listener = r'''$s = stream_socket_server('tcp://0.0.0.0:8080', $e, $es); file_put_contents('/tmp/n', '0');
$n = 0; while ($c = @stream_socket_accept($s, 3600)) { $n++; file_put_contents('/tmp/n', (string) $n); fclose($c); }'''
        compose("exec", "-d", "paynet-probe", "php", "-r", listener)
        time.sleep(1)
        # Positive control: the listener counts a connection made to it.
        compose("exec", "-T", "paynet-probe", "php", "-r", "$c=@stream_socket_client('tcp://172.30.30.99:8080',$e,$es,2); var_dump((bool)$c);")
        time.sleep(0.5)
        n0 = compose("exec", "-T", "paynet-probe", "cat", "/tmp/n").stdout.decode().strip()
        ok_i, r = install([rule(o["charge_id"], "redirect", times=0, op=None, location="http://172.30.30.99:8080/collect")],
                          malicious=True)
        if not ok_i:
            record(GID, "PT-17", "redirect", "PT-17 / P-17", "SI-02", "INCONCLUSIVE", r)
            return
        pid, state = customer_flow(o, 1000)
        time.sleep(25)
        clear_faults(); set_malicious(False)
        n1 = compose("exec", "-T", "paynet-probe", "cat", "/tmp/n").stdout.decode().strip()
        first = next((e for e in calls(pid) if e.get("op") == "refund.create"), {})
        row = pe_row(pid)
        ok = n0 == "1" and n1 == n0 and state == "UNKNOWN" and row and row["state"] == "UNKNOWN" \
            and first.get("cause") == "redirect" and len(refunds_of(o["charge_id"])) == 0
        record(GID, "PT-17", "307 redirect to a reachable pay-egress listener: UNKNOWN (ambiguous/redirect); listener sees 0 connections",
               "PT-17 / P-17", "SI-02", verdict(ok),
               f"control_conns={n0} conns_after={n1} dispatch={state} first_create={first.get('class')}/{first.get('cause')} "
               f"row={row and row['state']} ledger={len(refunds_of(o['charge_id']))}")
    finally:
        paynet_down()


def t_pt18_hostile_responses():
    log("\n== PT-18: oversized, slow drip, malformed JSON, header injection, hostile error text ==")
    cases = [("PT-18a", "m_oversized_body", "oversized_body", {"bytes": 200000}, "ambiguous", 600),
             ("PT-18b", "m_malformed_json", "malformed_json", {"variant": "duplicate_keys"}, "ambiguous", 610),
             ("PT-18c", "m_malformed_json", "malformed_json", {"variant": "not_json"}, "ambiguous", 620),
             ("PT-18d", "m_malformed_json", "malformed_json", {"variant": "huge_number"}, "ambiguous", 630),
             ("PT-18e", "m_header_injection", "header_injection", {"variant": "crlf_injection"}, "created", 640),
             ("PT-18f", "m_header_injection", "header_injection", {"variant": "bare_cr"}, "ambiguous", 650),
             # Draft 3.3 §11 PT-18 (DEMOP-F08): te_and_cl -> ambiguous with any cause.
             ("PT-18g", "m_header_injection", "header_injection", {"variant": "te_and_cl"}, "ambiguous", 660),
             # Draft 3.3 §11 PT-18 / §6.2 (DEMOP-F05): 400 with an unknown code -> refused/other_4xx.
             ("PT-18h", "m_hostile_error_text", "hostile_error_text", {}, "refused", 670),
             ("PT-18i", "f_slow_response", "slow_drip", {"chunk": 8, "interval_ms": 400}, "ambiguous", 680)]
    for tid, tag, kind, params, want, amt in cases:
        o = ORD[tag]
        before = len(refunds_of(o["charge_id"]))
        _, pid, row, st = _fault_flow(tag, amt, [rule(o["charge_id"], kind, **params)], malicious=True)
        if pid is None:
            record(GID, tid, kind, "PT-18 / P-18", "SI-16", "INCONCLUSIVE", st)
            continue
        first = next((e for e in calls(pid) if e.get("op") == "refund.create"), {})
        refs = refunds_of(o["charge_id"])
        mine = [x for x in refs if x["amount"] == amt]
        ok = first.get("class") == want and row and row["state"] == "SUCCEEDED" and len(mine) == 1 \
            and len(refs) == before + 1 and first.get("elapsed_ms", 10 ** 9) <= 5000 + 1000
        if want == "created":
            ok = ok and row["reconcile_rounds"] == 0 and row["resends"] == 0
        # Draft 3.3 §11 PT-18: bare_cr is bad_headers; te_and_cl may be any ambiguous cause (DEMOP-F08).
        if kind == "header_injection" and params.get("variant") == "bare_cr":
            ok = ok and first.get("cause") == "bad_headers"
        if kind == "hostile_error_text":
            # §6.2: refused/other_4xx; §7.2: row UNKNOWN + alarm, resolved by lookup (DEMOP-F05).
            ok = ok and first.get("cause") == "other_4xx" and row["reason"] in (None, "refused")
        k18 = crs(o["charge_id"])
        if kind == "hostile_error_text" or params.get("variant") == "te_and_cl":
            # Draft 3.3 §11 PT-18: no corrupted state: nothing left in flight or unknown on the
            # charge, and the broker's succeeded counter equals the provider's refunds.
            ok = ok and k18["inflight_minor"] == 0 and k18["unknown_minor"] == 0 \
                and k18["succeeded_minor"] == sum(x["amount"] for x in refs)
        record(GID, tid, f"{kind} {params.get('variant', '')}: create classified {want}; bounded; one refund",
               "PT-18 / P-18", "SI-16", verdict(ok),
               f"first_create={first.get('class')}/{first.get('cause')} elapsed_ms={first.get('elapsed_ms')} "
               f"final={row and row['state']} refunds_for_grant={len(mine)} counters={k18}")
    # No provider text anywhere: adapter, broker, gateway, authority logs; the broker DB; the shop's status page.
    dump = compose("exec", "-T", "--user", "postgres", "db", "pg_dump", "-U", "postgres", "-d", "ledger", "-a",
                   timeout=120).stdout.decode("utf-8", "replace")
    hostile_pid = psql_json("SELECT encode(pending_id,'base64') AS p FROM nodkey.payment_effect WHERE charge_id="
                            f"'{ORD['m_hostile_error_text']['charge_id']}'")
    page = ""
    if hostile_pid:
        p = hostile_pid[0]["p"].replace("+", "-").replace("/", "_").rstrip("=")
        page = app_status(p)["body"]
    hay = {"logs": logs_all().lower(), "db": dump.lower(), "status_page": page.lower()}
    hits = {k: [m for m in HOSTILE_MARKERS if m in v] for k, v in hay.items()}
    ok = not any(hits.values()) and len(dump) > 1000 and bool(page)
    record(GID, "PT-18z", "provider text never appears in logs, DB or the shop's status page (byte search for the hostile markers)",
           "PT-18 / P-18", "SI-16", verdict(ok), f"hits={hits} dump_bytes={len(dump)} status_page={bool(page)}")


def t_pt19_listeners():
    log("\n== PT-19: no network listeners in adapter and broker ==")
    res = {}
    held_src = r'''opendir(my $d, "/proc") or die; for my $p (grep { /^\d+$/ } readdir $d) { opendir(my $f, "/proc/$p/fd") or next;
for my $x (readdir $f) { my $l = readlink("/proc/$p/fd/$x") // next; print "$1\n" if $l =~ /^socket:\[(\d+)\]$/; } }'''
    for svc in ("adapter", "broker"):
        r = compose("exec", "-T", svc, "cat", "/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6")
        lines = [l.split() for l in r.stdout.decode().splitlines() if l.strip() and not l.strip().startswith("sl")]
        socks = [(l[1], l[9]) for l in lines if len(l) > 9 and l[3] in ("0A", "07")]  # TCP LISTEN, UDP
        held = set(compose("exec", "-T", svc, "perl", "-e", held_src).stdout.decode().split())
        ours = [a for a, ino in socks if ino in held]
        foreign = [a for a, ino in socks if ino not in held]
        res[svc] = (r.returncode, ours, foreign, len(held))
    ok = all(rc == 0 and not ours and nheld > 0 for rc, ours, _, nheld in res.values())
    record(GID, "PT-19", "no TCP LISTEN / UDP socket held by any process in the adapter and broker containers (no webhook receiver)",
           "PT-19 (P-19 N/A)", "SI-01", verdict(ok),
           f"(rc, held_by_container, not_held [Docker embedded DNS 127.0.0.11 = 0B00007F], container_socket_fds) {res}")


# =============================================================================== PT: crashes

def _approve_async(o, amount):
    cli = Client(CTX)
    pid, _, _ = app_propose(cli, o["order_id"], amount, o["currency"], o["owner_sub"])
    login_auth(cli, CUST_IDX[o["owner_sub"]], return_to_confirm_pid=pid)
    _, _, page = get_confirm(cli, pid)
    tok, dig = TOKEN_RE.search(page), DIGEST_RE.search(page)
    if not tok:
        return pid, None
    typed = typed_fields(pid, page)
    time.sleep(INERT_SECONDS)
    t = threading.Thread(target=lambda: post_decision(cli, pid, tok.group(1), dig.group(1), typed=typed,
                                                      sec_fetch="navigate", origin_hdr=AUTH_ORIGIN, timeout=60))
    t.start()
    return pid, t


def _wait_sent(pid, timeout=15):
    """Waits until the adapter has written the create to simpay (simpay ledger or idempotency record)."""
    end = time.time() + timeout
    while time.time() < end:
        row = pe_row(pid)
        if row and row["state"] in ("DISPATCHED",):
            return True
        time.sleep(0.2)
    return False


def t_pt21_crashes():
    log("\n== PT-21: crashes and a DB stall around the provider call ==")
    # (a) adapter killed while simpay holds the committed response (slow_response 4 s).
    o = ORD["x_adapter_crash"]
    install([rule(o["charge_id"], "slow_response", ms=4000)])
    pid, t = _approve_async(o, 1000)
    sent = _wait_sent(pid)
    time.sleep(1.0)
    compose("kill", "adapter")
    compose("up", "-d", "--wait", "adapter", timeout=120)
    _wait_adapter()
    if t:
        t.join(60)
    clear_faults()
    row = wait_pe(pid, ("SUCCEEDED", "FAILED"), 180)
    refs = refunds_of(o["charge_id"])
    ok = sent and row and row["state"] == "SUCCEEDED" and len(refs) == 1
    record(GID, "PT-21a", "adapter killed mid-request (after simpay committed): resolves SUCCEEDED, ledger 1",
           "PT-21", "SI-09/SI-15", verdict(ok, inconclusive=len(refs) <= 1),
           f"dispatched={sent} final={row and row['state']} resends={row and row['resends']} ledger={len(refs)}")
    # (b) broker killed after the create was sent (slow_response holds the reply).
    o = ORD["x_broker_crash"]
    install([rule(o["charge_id"], "slow_response", ms=4000)])
    pid, t = _approve_async(o, 1000)
    sent = _wait_sent(pid)
    time.sleep(1.0)
    compose("kill", "broker")
    compose("up", "-d", "--wait", "broker", timeout=120)
    if t:
        t.join(60)
    clear_faults()
    row = wait_pe(pid, ("SUCCEEDED", "FAILED"), 240)  # dispatch lease 61 s, then UNKNOWN, then a reconciler round
    refs = refunds_of(o["charge_id"])
    compose("restart", "broker")
    compose("up", "-d", "--wait", "broker", timeout=120)
    time.sleep(8)
    refs2 = refunds_of(o["charge_id"])
    ok = sent and row and row["state"] == "SUCCEEDED" and len(refs) == 1 and len(refs2) == 1
    record(GID, "PT-21b", "broker killed after send; restart -> lease expiry -> UNKNOWN -> SUCCEEDED; second restart adds nothing; ledger 1",
           "PT-21", "SI-09/SI-15", verdict(ok, inconclusive=len(refs2) <= 1),
           f"dispatched={sent} final={row and row['state']} ledger={len(refs)} after_second_restart={len(refs2)}")
    # (c) DB paused while the create is in flight (T3 cannot commit until it resumes).
    o = ORD["x_adapter_crash"]
    install([rule(o["charge_id"], "slow_response", ms=3000)])
    pid, t = _approve_async(o, 700)
    sent = _wait_sent(pid)
    compose("pause", "db")
    time.sleep(8)
    compose("unpause", "db")
    if t:
        t.join(60)
    clear_faults()
    row = wait_pe(pid, ("SUCCEEDED", "FAILED"), 240)
    refs = refunds_of(o["charge_id"])
    mine = [x for x in refs if x["amount"] == 700]
    ok = sent and row and row["state"] == "SUCCEEDED" and len(mine) == 1 and len(refs) == 2
    record(GID, "PT-21c", "DB stalled 8 s across T3: no duplicate; ledger matches final state",
           "PT-21", "SI-09/SI-15", verdict(ok, inconclusive=len(mine) <= 1),
           f"dispatched={sent} final={row and row['state']} refunds_for_grant={len(mine)} charge_refunds={len(refs)}")
    nt("PT-21d", "broker killed exactly after T1 / after T2 (before send)", "PT-21", "SI-09/SI-15",
       "no hook to stop the broker between T1 and T2 or between T2 and the send; a kill cannot be placed there from outside")


# =============================================================================== PT: containment

CONTAIN_MAP = {"C-NET": "PT-13", "C-DNS": "PT-13", "C-IF": "PT-13", "C-PATH": "PT-13/PT-31", "C-SOCK": "PT-13/PT-30",
               "C-W": "PT-13", "C-OPS": "PT-12/SI-16", "C-CAP": "PT-38"}


def t_pt13_14_38_containment():
    log("\n== PT-13 / PT-14 / PT-38: containment of the shop, broker, authority, gateway and adapter ==")
    key, kidem = secrets_real()
    # Positive control for the secret scan: a decoy token planted where attacker C can write.
    decoy = "rk_sim_DECOYpositivecontrol0001"
    rce(f"file_put_contents('/tmp/decoy.txt', '{decoy}'); echo 'planted';")
    probe_php = "<?php\n" + LIB + "\n" + strip_php_tag(load_probe("containment.php"))
    r = compose("exec", "-T", "app", "php", input_bytes=probe_php.encode(), timeout=300)
    rows = json_lines(r.stdout.decode())
    rce_alive = "eval-reachable" in rce("echo 'eval-reachable';")
    cands = next((x for x in rows if x.get("id") == "CANDIDATES"), None)
    for x in rows:
        if x.get("id") == "CANDIDATES":
            continue
        record(GID, x["id"], x["expect"], CONTAIN_MAP.get(x["id"], "containment"), x["si"], x["result"], x.get("observed", ""))
    fails = [x for x in rows if x.get("result") == "FAIL"]
    record(GID, "PT-13a", "shop container: every containment probe PASS (no route to simpay/adapter/db, no sockets, CapEff 0); RCE live",
           "PT-13 / P-13", "SI-01/SI-03", "PASS" if (rows and not fails and rce_alive) else ("FAIL" if fails else "INCONCLUSIVE"),
           f"{len(rows) - 1} probes, {len(fails)} failed, rce_live={rce_alive}")
    toks = set((cands or {}).get("tokens", []))
    ok14 = cands is not None and decoy in toks and key not in toks and kidem not in toks
    record(GID, "PT-14a", "shop: simpay key and K_idem absent from env, /proc, files (decoy found = scanner works)",
           "PT-14 / P-14", "SI-02", verdict(ok14, inconclusive=decoy not in toks),
           f"files={cands and cands.get('files_scanned')} decoy_found={decoy in toks} key_found={key in toks} kidem_found={kidem in toks}")
    rce("@unlink('/tmp/decoy.txt');")
    # Trusted containers (attacker J/I code positions): routes, sockets, secrets, capabilities.
    targets = ["tcp=172.30.30.20:8443", "tcp=172.30.40.20:8081", "path=/run/nodkey/br-pay/adapter.sock",
               "path=/run/pg-adapter", "path=/etc/nodkey-adapter", "path=/run/adapter-secrets"]
    out = {}
    for svc in ("broker", "authority", "gateway"):
        out[svc] = infra(svc, *targets, "raw", "scan")
    bad13 = []
    for svc, o in out.items():
        for t in ("tcp 172.30.30.20:8443", "tcp 172.30.40.20:8081"):
            if o.get(t) != None and o.get(t) == "connected":
                bad13.append(f"{svc}:{t}")
            if o.get(t) is None:
                bad13.append(f"{svc}:{t}=no-result")
        for p in ("/run/pg-adapter", "/etc/nodkey-adapter", "/run/adapter-secrets"):
            if o.get(f"path {p}") != "absent":
                bad13.append(f"{svc}:{p}={o.get(f'path {p}')}")
        if svc != "broker" and o.get("path /run/nodkey/br-pay/adapter.sock") != "absent":
            bad13.append(f"{svc}:adapter.sock")
    nets = {}
    for svc in ("broker", "authority", "gateway", "app", "adapter"):
        cid = compose("ps", "-q", svc).stdout.decode().strip()
        insp = _docker("inspect", "-f", "{{json .NetworkSettings.Networks}}", cid).stdout.decode().strip() if cid else "{}"
        try:
            nets[svc] = sorted(json.loads(insp or "{}").keys())
        except json.JSONDecodeError:
            nets[svc] = ["?"]
    on_egress = [s for s, n in nets.items() if any(x.endswith("pay-egress") for x in n) and s != "adapter"]
    adapter_only_egress = nets.get("adapter") == ["nodkey-demop_pay-egress"]
    ok13 = not bad13 and not on_egress and adapter_only_egress and all(o["_rc"] == 0 for o in out.values())
    record(GID, "PT-13b", "broker/authority/gateway: no route to simpay API or admin, no adapter inputs; only the adapter is on pay-egress (and only there)",
           "PT-13 / P-13", "SI-01/SI-03", verdict(ok13), f"violations={bad13} networks={nets}")
    btoks = set(out["broker"]["_tokens"])
    ok14b = key not in btoks and kidem not in btoks and int(out["broker"].get("scan files", "0")) > 0
    record(GID, "PT-14b", "broker: simpay key and K_idem absent (env, /proc, files)", "PT-14 / P-14", "SI-02",
           verdict(ok14b), f"files={out['broker'].get('scan files')} key_found={key in btoks} kidem_found={kidem in btoks}")
    out["adapter"] = infra("adapter", "raw")
    caps = {s: o.get("status CapEff") for s, o in out.items()}
    raw = {s: (o.get("raw AF_PACKET", ""), o.get("raw AF_INET", "")) for s, o in out.items()}
    ok38 = all(c == "0000000000000000" for c in caps.values()) and \
        all(a.startswith("refused") and b.startswith("refused") for a, b in raw.values())
    record(GID, "PT-38", "broker, authority, gateway, adapter: CapEff = 0; raw and packet sockets refused; pg-adapter absent in broker",
           "PT-38", "PA-16", verdict(ok38 and out["broker"].get("path /run/pg-adapter") == "absent"),
           f"CapEff={caps} raw={raw}")
    # Stolen key from another address on pay-egress (paynet-probe 172.30.30.99).
    if not paynet_up():
        nt("PT-13c", "stolen simpay key from another address", "PT-13 / P-13", "SI-03", "paynet-probe did not start")
        return
    try:
        php = r'''$ctx = stream_context_create(['ssl' => ['verify_peer' => false, 'verify_peer_name' => false, 'peer_name' => 'simpay.test']]);
$s = @stream_socket_client('tls://172.30.30.20:8443', $e, $es, 3, STREAM_CLIENT_CONNECT, $ctx);
if (!$s) { echo "connect_failed $es"; exit; }
$b = 'charge=%CH%&amount=1';
fwrite($s, "POST /v1/refunds HTTP/1.1\r\nHost: simpay.test\r\nAuthorization: Bearer %KEY%\r\nIdempotency-Key: stolen-key-test-0001\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " . strlen($b) . "\r\nConnection: close\r\n\r\n" . $b);
echo stream_get_contents($s);'''.replace("%KEY%", key).replace("%CH%", ORD["legit"]["charge_id"])
        before = len(refunds_of(ORD["legit"]["charge_id"]))
        r = compose("exec", "-T", "paynet-probe", "php", "-r", php, timeout=60)
        resp = r.stdout.decode("utf-8", "replace")
        after = len(refunds_of(ORD["legit"]["charge_id"]))
        ok = resp.startswith("HTTP/1.1 401") and "source_address_not_allowed" in resp and before == after
        record(GID, "PT-13c", "real simpay key used from 172.30.30.99 (reaches simpay): 401 source_address_not_allowed; ledger unchanged",
               "PT-13 / P-13", "SI-03", verdict(ok), f"status_line={resp.splitlines()[0] if resp else r.stderr.decode()[:100]!r} "
               f"code_present={'source_address_not_allowed' in resp} refunds {before}->{after}")
    finally:
        paynet_down()


# =============================================================================== PT: budgets

BUDGET_YOUNG = [None]


def t_pt22_budget():
    log("\n== PT-22: per-customer daily budget ==")
    o = ORD["budget_count"]
    states = []
    for _ in range(3):
        p, s = customer_flow(o, 100)
        wait_pe(p)
        states.append(s)
    p4, s4 = customer_flow(o, 100)
    r4, w4 = denial(p4), app_status(p4)["reason"]
    BUDGET_YOUNG[0] = p4
    ok = states == ["SUCCEEDED"] * 3 and s4 == "FAILED" and r4 == "budget" and w4 == "limit" and len(calls(p4)) == 0 \
        and len(refunds_of(o["charge_id"])) == 3
    record(GID, "PT-22a", "4th refund of the day (max 3) -> FAILED budget / workload reason limit; adapter not called",
           "PT-22 / AR-05", "SI-11", verdict(ok),
           f"first3={states} fourth={s4}/{r4}/{w4} adapter_calls={len(calls(p4))} ledger={len(refunds_of(o['charge_id']))}")
    o = ORD["budget_over"]
    p1, s1 = customer_flow(o, 20001)
    r1 = denial(p1)
    p2, s2 = customer_flow(o, 15000)
    wait_pe(p2)
    p3, s3 = customer_flow(o, 5001)
    r3 = denial(p3)
    spent = psql(f"SELECT spent_minor FROM nodkey.refund_budget WHERE sub='{o['owner_sub']}' AND currency='USD'")
    ok = s1 == "FAILED" and r1 == "budget" and s2 == "SUCCEEDED" and s3 == "FAILED" and r3 == "budget" \
        and spent == "15000" and live_sum(o["charge_id"]) == 15000 and len(calls(p1)) == 0 and len(calls(p3)) == 0
    record(GID, "PT-22b", "over the 200.00 USD daily limit (200.01 fresh; 50.01 after 150.00) -> budget; spent <= limit",
           "PT-22 / AR-05", "SI-11", verdict(ok), f"fresh={s1}/{r1} 150.00={s2} 50.01={s3}/{r3} spent={spent}")
    o = ORD["budget_unconfigured"]
    p, s = customer_flow(o, 100)
    r = denial(p)
    ok = s == "FAILED" and r == "budget" and len(calls(p)) == 0 and len(refunds_of(o["charge_id"])) == 0
    record(GID, "PT-22c", "currency without a configured budget (GBP) -> denied (budget); nothing sent",
           "PT-22 / AR-05", "SI-11", verdict(ok), f"state={s} reason={r} adapter_calls={len(calls(p))}")
    nt("PT-22d", "32 concurrent T1s on one budget row", "PT-22 / AR-05", "SI-11",
       "needs 32 concurrently approved records for one customer; the demo allows 3 per day and one in flight per order")
    nt("PT-22e", "two refunds across UTC midnight (2x published)", "PT-22 / AR-05", "SI-11",
       "needs control of the broker's clock; containers cannot set CLOCK_REALTIME (no CAP_SYS_TIME, by design)")


def t_pt23_late_failed():
    log("\n== PT-23 / PT-37: late_refund_failed ==")
    o = ORD["late_refund_failed"]
    alarms0 = len(broker_alarms())
    # The refund is created `succeeded` and moves to `failed` 20 s later, after the broker has
    # recorded settlement `succeeded` (Draft 3.3 §7.3 post-success watch, DEMOP-F06).
    _, pid, row, st = _fault_flow("late_refund_failed", 1500, [rule(o["charge_id"], "late_refund_failed", op=None, after_s=20)])
    if pid is None:
        record(GID, "PT-23", "late_refund_failed", "PT-23 / §7.3", "SI-15", "INCONCLUSIVE", st)
        return
    settled_first = (pe_row(pid) or {}).get("settlement")
    end = time.time() + 180
    while time.time() < end and (pe_row(pid) or {}).get("settlement") != "failed":
        time.sleep(3)
    row = pe_row(pid)
    refs = refunds_of(o["charge_id"])
    k = crs(o["charge_id"])
    new_alarms = [a for a in broker_alarms()[alarms0:] if a.get("pending_id") == pid]
    kinds = [a.get("kind") for a in new_alarms]
    lookups = [e.get("op") for e in calls(pid)]
    ok = row and row["state"] == "SUCCEEDED" and row["settlement"] == "failed" and [x["status"] for x in refs] == ["failed"] \
        and k["succeeded_minor"] == 1500 and "refund_settlement_failed" in kinds \
        and settled_first == "succeeded" and row["anomaly"] == "settlement_reversed" \
        and creates(pid) == 1 and lookups.count("refund.create") == 1 and row["resends"] == 0
    record(GID, "PT-23", "late_refund_failed: settled succeeded, then failed at the provider -> post-success watch records "
           "settlement failed + anomaly settlement_reversed, alarm, amount encumbered, lookups only (no resend)",
           "PT-23 / §7.3", "SI-15", verdict(ok),
           f"first_settlement={settled_first} state={row and row['state']} settlement={row and row['settlement']} "
           f"anomaly={row and row['anomaly']} provider={[(x['amount'], x['status']) for x in refs]} "
           f"broker_counters={k} alarms={kinds[:4]} adapter_ops={lookups} creates_sent={creates(pid)}")
    view = shop_order_view(o["owner_sub"], o["order_id"])
    record(GID, "PT-37b", "get_order.refunded_minor counts a refund whose settlement failed (= external + succeeded)",
           "PT-37, §8", "SI-16", verdict(view == "15.00 USD"), f"shop_shows_refunded={view!r}")


# =============================================================================== PT: adapter start-up and peers

def t_pt24_32_31_startup():
    log("\n== PT-24 / PT-31 / PT-32 / PT-36: adapter start-up refusals ==")
    started, reason = adapter_trial()
    if not started:
        for tid in ("PT-24b", "PT-31d", "PT-32b"):
            record(GID, tid, "adapter start-up refusals", "PT-24/31/32", "§2", "INCONCLUSIVE",
                   f"positive control (unmodified inputs) did not start: {reason}")
        return
    log(f"   positive control: unmodified inputs start (reason={reason})")
    two = open(f"{OUT}/adapter-stage/etc/ca.crt", "rb").read()
    cases24 = {
        "dns_name_addr": dict(cfg_mut=lambda c: c["provider"].__setitem__("addr", "simpay.test:8443")),
        "two_cas": dict(ca_bytes=two + two),
        "readable_key_file": dict(key_mode="0444"),
    }
    res = {k: adapter_trial(**v) for k, v in cases24.items()}
    ok = all(s is False and r for s, r in res.values())
    record(GID, "PT-24b", "adapter refuses to start: provider addr is a DNS name; CA file with two certificates; simpay key file readable",
           "PT-24 / §1, §2", "SI-02", verdict(ok), f"positive_control=started {res}")
    cases31 = {"config_group_writable": dict(cfg_mode="0666")}
    res = {k: adapter_trial(**v) for k, v in cases31.items()}
    ok = all(s is False and r for s, r in res.values())
    record(GID, "PT-31d", "adapter refuses to start when a §2 input (config) is group/other writable",
           "PT-31 / PA-03", "SI-02", verdict(ok), f"{res}")
    cases32 = {
        "R_max_ge_retention_minus_margin": dict(cfg_mut=lambda c: c.__setitem__("R_max_s", 240)),
        "margin_ge_retention": dict(cfg_mut=lambda c: c["provider"].__setitem__("resend_margin_s", 300)),
    }
    res = {k: adapter_trial(**v) for k, v in cases32.items()}
    ok = all(s is False and r for s, r in res.values())
    record(GID, "PT-32b", "adapter refuses to start: R_max >= retention - margin; margin >= retention",
           "PT-32 / PA-05, PA-13", "SI-15", verdict(ok), f"{res}")
    # Draft 3.3 §11 PT-32 / §3.1 (DEMOP-F03): retention_s is an operator statement the adapter cannot
    # verify; the start-up rule is tested against the configured value (R_max 180, margin 60).
    s, r = adapter_trial(cfg_mut=lambda c: c["provider"].__setitem__("retention_s", 240))
    record(GID, "PT-32c", "configured retention_s lowered so that R_max >= retention_s - margin (180 >= 240 - 60): refused at start",
           "PT-32 / PA-13", "SI-15", verdict(s is False and bool(r)),
           f"started={s} refuse={r} (retention above the provider's actual value is not checkable: spec §10)")
    s, r = adapter_trial(cfg_mut=lambda c: c["provider"].__setitem__("idem_key_not_before", int(time.time()) + 86400))
    record(GID, "PT-36a", "idem_key_not_before in the future: adapter refuses to start",
           "PT-36 / §3.3 rule 3", "SI-09", verdict(s is False and bool(r)), f"started={s} refuse={r}")
    nt("PT-32a", "broker clock set back past a row's deadline", "PT-32 / PA-05", "SI-15",
       "containers cannot set CLOCK_REALTIME (no CAP_SYS_TIME) and the host clock is shared; not changed by the harness")
    nt("PT-36b", "K_idem rotated while a row is non-final; activation-time resend under new/old kid; baseline", "PT-36",
       "SI-09", "needs a K_idem rotation drill (adapter secret swap with a broker holding non-final rows) that the harness does not implement yet")


def t_pt24_peer():
    log("\n== PT-24: wrong-uid peer on socket P ==")
    src = load_probe("pclient.pl")
    payload = ("concurrent=0\n" + p_line("adapter.hello", {}) + "\n").encode()
    ok_ctl = compose("exec", "-T", "broker", "perl", "-e", src, input_bytes=payload).stdout.decode()
    bad = compose("exec", "-T", "--user", "10007:10002", "broker", "perl", "-e", src, input_bytes=payload).stdout.decode()
    time.sleep(1)
    alarms = [e for e in adapter_events() if e.get("event") == "alarm" and e.get("alarm") == "peer_uid_mismatch"
              and e.get("peer_uid") == 10007]
    ok = '"ok":true' in ok_ctl and '"ok"' not in bad and len(alarms) >= 1
    record(GID, "PT-24a", "uid 10007 (broker's group) connects to P: closed without response, adapter alarm peer_uid_mismatch",
           "PT-24 / §1", "SI-01", verdict(ok), f"broker_uid_ok={'\"ok\":true' in ok_ctl} wrong_uid_reply={bad.strip()[:60]!r} alarms={len(alarms)}")
    nt("PT-24c", "broker checks the adapter's peer uid (impostor adapter on P)", "PT-24 / §1", "SI-01",
       "needs an impostor listener on P with another uid; P's directory is owned by the adapter uid and the harness does not replace it")


def t_pt25_tls():
    log("\n== PT-25: wrong CA, wrong server name ==")
    other = other_test_ca()
    for tid, tag, kw, what in (("PT-25a", "tls_wrong_ca", dict(ca_bytes=other), "pinned CA is another test CA"),
                               ("PT-25b", "tls_wrong_san", dict(cfg_mut=lambda c: c["provider"].__setitem__("server_name", "wrong.simpay.test")),
                                "server_name does not match the certificate SAN")):
        o = ORD[tag]
        if tid == "PT-25a" and other is None:
            nt(tid, what, "PT-25 / §5", "SI-02", "could not generate a second test CA")
            continue
        saved, up = swap_adapter_inputs(**kw)
        try:
            if not up:
                record(GID, tid, what, "PT-25 / §5", "SI-02", "INCONCLUSIVE", "adapter did not come up with the swapped input")
                continue
            pid, state = customer_flow(o, 1000)
            row = wait_pe(pid, ("FAILED", "SUCCEEDED", "UNKNOWN"), 30)
            first = next((e for e in calls(pid) if e.get("op") == "refund.create"), {})
            ok = state == "FAILED" and row and row["state"] == "FAILED" and row["reason"] == "not_sent" \
                and first.get("class") == "not_sent" and len(refunds_of(o["charge_id"])) == 0 \
                and app_status(pid)["reason"] == "not_executed"
            record(GID, tid, f"{what}: FAILED/not_sent; ledger 0", "PT-25 / §5", "SI-02", verdict(ok),
                   f"state={state} pe={row and (row['state'], row['reason'])} create={first.get('class')}/{first.get('cause')} "
                   f"ledger={len(refunds_of(o['charge_id']))}")
        finally:
            restore_adapter_inputs(saved)
    nt("PT-25c", "TLS 1.2-only server; plain HTTP server", "PT-25 / §5", "SI-02",
       "simpay's API listener is TLS 1.3-only with no option for TLS 1.2-only or plain HTTP in this compose stack")


def t_pt42_revoked():
    log("\n== PT-42: key revoked in the adapter's registry ==")
    o = ORD["revoked_key"]
    saved, up = swap_adapter_inputs(keys_mut=lambda k: [x.__setitem__("status", "revoked") for x in k["keys"]])
    try:
        if not up:
            record(GID, "PT-42c", "revoked key", "PT-42 / RX", "SI-05", "INCONCLUSIVE", "adapter did not come up")
            return
        n0 = len(adapter_events())
        pid, state = customer_flow(o, 1000)
        time.sleep(3)
        c = [e for e in adapter_events()[n0:] if e.get("event") == "p_request" and e.get("op") == "refund.create"]
        ok = state == "UNKNOWN" and c and all(e.get("outcome") == "grant_refused" and not e.get("provider_request_started") for e in c) \
            and len(refunds_of(o["charge_id"])) == 0
        record(GID, "PT-42c", "grant key 'revoked' in the adapter registry: refund.create grant_refused, nothing sent (row UNKNOWN + alarm)",
               "PT-42 / RX-1..3", "SI-05", verdict(ok),
               f"state={state} creates={[(e.get('outcome'), e.get('provider_request_started')) for e in c]} ledger={len(refunds_of(o['charge_id']))}")
    finally:
        restore_adapter_inputs(saved)
    nt("PT-42a", "grant for a tenant not in the adapter's tenants", "PT-42", "SI-05",
       "needs a validly signed grant for another tenant; the broker refuses proposals outside the workload's tenants and the harness has no signer")
    nt("PT-42b", "amount_minor = 0 in a test-key grant", "PT-42", "SI-05", "needs a signer for crafted grants (none in this stack)")
    nt("PT-42d", "key window ending between iat and now", "PT-42", "SI-05", "not implemented in the harness (needs a registry swap timed between iat and the create)")


# =============================================================================== PT: derivation vectors

def t_pt26_vectors():
    log("\n== PT-26: idem_key / reference / idem_kid derivation ==")
    import hmac as _hmac
    yr = psql_json("SELECT encode(pending_id,'base64') AS p, charge_id FROM nodkey.payment_effect WHERE state='SUCCEEDED' "
                   "ORDER BY reserved_at DESC LIMIT 1")
    if not yr:
        nt("PT-26", "derivation vectors", "PT-26 / §3.3", "SI-09", "no SUCCEEDED refund yet")
        return
    pid = yr[0]["p"].replace("+", "-").replace("/", "_").rstrip("=")
    charge = yr[0]["charge_id"]
    _, kidem = secrets_real()
    K = bytes.fromhex(kidem)
    lp = lambda b: len(b).to_bytes(8, "big") + b
    jti = base64.b64decode(_pid_b64(pid))
    D = b"nodkey.pay.v1" + b"\x00" + lp(DATA["account"].encode()) + lp(b"payments.refund") + (1).to_bytes(8, "big") \
        + lp(b"nodkey.authority.demop") + lp(jti)
    b64 = lambda m: base64.urlsafe_b64encode(m).decode().rstrip("=")
    idem = b64(_hmac.new(K, b"idem\x00" + D, "sha256").digest())
    ref = b64(_hmac.new(K, b"ref\x00" + D, "sha256").digest())
    kid = _hmac.new(K, b"kid", "sha256").digest()[:8].hex()
    rid = (pe_row(pid) or {}).get("provider_refund_id")
    refs = [r for r in refunds_of(charge) if r["id"] == rid]
    st = admin("GET", "/admin/state")
    keys = list(((st.get("idempotency") or {}).get(DATA["account"]) or {}).keys())
    row = pe_row(pid)
    pe_kid = psql(f"SELECT idem_kid FROM nodkey.payment_effect WHERE pending_id={pid_sql(pid)}")
    hk, _ = hello_kid()
    ok = refs and refs[0]["reference"] == ref and idem in keys and pe_kid == kid == hk
    record(GID, "PT-26", "idem_key, reference, idem_kid recomputed from K_idem per §3.3 match simpay's stored key/reference and the broker row",
           "PT-26 / §3.3, OQ-10", "SI-09", verdict(ok),
           f"reference_match={bool(refs) and refs[0]['reference'] == ref} idem_key_in_simpay={idem in keys} "
           f"kid={kid} row_kid={pe_kid} hello_kid={hk} (resend fingerprint equality: PT-09a/b, no params_mismatch)")


# =============================================================================== PT: broker compromise (J) on P

def t_pt29_40_43_broker_compromise():
    log("\n== PT-29 / PT-40 / PT-43: attacker J on socket P (broker uid) ==")
    kid, _ = hello_kid()
    # Fresh young grant: c29's refund on order 1030.
    o = ORD["rce_bob_target"]
    pid, state = customer_flow(o, 300)
    wait_pe(pid)
    if state != "SUCCEEDED" or not kid:
        record(GID, "PT-29", "broker-compromise suite", "PT-29", "SI-05", "INCONCLUSIVE", f"state={state} kid={kid}")
        return
    g = grant_text(pid)
    c0 = creates(pid)
    seq, _ = p_client([p_line("refund.create", {"grant": g, "idem_kid": kid})] * 20)
    conc, _ = p_client([json.dumps({"v": 2, "id": f"c{i}", "op": "refund.create", "args": {"grant": g, "idem_kid": kid}})
                        for i in range(20)], concurrent=True)
    time.sleep(1)
    refs = refunds_of(o["charge_id"])
    ok = len(refs) == 1 and refs[0]["amount"] == 300
    record(GID, "PT-29a", "same valid grant on P 20x sequential + 20x concurrent: ledger 1 (provider dedup on the derived key)",
           "PT-29 / PA-01..03", "SI-09", verdict(ok),
           f"seq={sorted(set(p_code(x) for x in seq))} conc={sorted(set(p_code(x) for x in conc))} ledger={[x['amount'] for x in refs]} "
           f"creates_sent {c0}->{creates(pid)}")
    # Malformed / tampered / empty grants.
    flip = g[:-5] + ("A" if g[-5] != "A" else "B") + g[-4:]
    cases = {"no_grant": {"grant": "", "idem_kid": kid}, "garbage": {"grant": "AAAA", "idem_kid": kid},
             "signature_flipped": {"grant": flip, "idem_kid": kid}}
    before = len(creates_sent(pid_hex(pid)))
    rs, _ = p_client([p_line("refund.create", a) for a in cases.values()])
    after = len(creates_sent(pid_hex(pid)))
    codes = dict(zip(cases, [p_code(x) for x in rs]))
    ok = all(c in ("grant_refused", "invalid_argument", "malformed_request") for c in codes.values()) and before == after \
        and len(refunds_of(o["charge_id"])) == 1
    record(GID, "PT-29b", "no grant / garbage / signature-flipped grant on P: refused, nothing sent",
           "PT-29 / PA-01", "SI-05", verdict(ok), f"{codes} creates {before}->{after}")
    # Valid grant whose order now has another owner.
    rc, _, _ = operator_sql(f"UPDATE nodkey.orders SET owner_sub='user:c30' WHERE order_id={o['order_id']}")
    before = len(creates_sent(pid_hex(pid)))
    rs, _ = p_client([p_line("refund.create", {"grant": g, "idem_kid": kid})])
    time.sleep(0.5)
    after = len(creates_sent(pid_hex(pid)))
    ok = rc == 0 and p_code(rs[0]) == "grant_refused" and before == after
    record(GID, "PT-29c", "valid grant whose order now has another owner: grant_refused, nothing sent",
           "PT-29 / PA-02", "SI-10", verdict(ok), f"operator_rc={rc} reply={p_code(rs[0])} creates {before}->{after}")
    # Approved-but-never-executed grant younger than R_max (budget-denied record, PT-22a): published residual.
    yp = BUDGET_YOUNG[0]
    if yp and grant_bytes_present(yp):
        ob = ORD["budget_count"]
        age = time.time() - int(psql(f"SELECT state_changed_at FROM public.pending_effect WHERE pending_id={pid_sql(yp)}") or 0)
        b0 = len(refunds_of(ob["charge_id"]))
        rs, _ = p_client([p_line("refund.create", {"grant": grant_text(yp), "idem_kid": kid})] * 3)
        b1 = len(refunds_of(ob["charge_id"]))
        ok = age < 180 and p_code(rs[0]) == "ok:created" and b1 == b0 + 1
        record(GID, "PT-29d", "never-executed (budget-denied) grant younger than R_max, sent 3x by J: exactly one refund (published residual §10)",
               "PT-29 / PA-02", "SI-09", verdict(ok, inconclusive=age >= 180),
               f"grant_age_s={int(age)} replies={[p_code(x) for x in rs]} ledger {b0}->{b1}")
    else:
        nt("PT-29d", "never-executed grant younger than R_max", "PT-29", "SI-09", "no budget-denied record with grant bytes from PT-22a")
    nt("PT-29e", "grant for another op; read grant; other wid/aud; cfm = 0; foreign key", "PT-29 / PA-01", "SI-05",
       "each needs a crafted, validly signed grant; this stack has no signer besides the authority (vectors: crates/nodkey-grant)")
    # PT-40: the old L-04 grant (older than R_max) on every op.
    lp_ = LEGIT_PID[0]
    if lp_:
        age = time.time() - int(psql(f"SELECT state_changed_at FROM public.pending_effect WHERE pending_id={pid_sql(lp_)}") or 0)
        gl = grant_text(lp_)
        rid = (pe_row(lp_) or {}).get("provider_refund_id")
        before = len(creates_sent(pid_hex(lp_)))
        rs, _ = p_client([p_line("refund.create", {"grant": gl, "idem_kid": kid}),
                          p_line("refund.find", {"grant": gl, "idem_kid": kid}),
                          p_line("refund.get", {"grant": gl, "refund_id": rid, "idem_kid": kid}),
                          p_line("idem.status", {"grant": gl, "idem_kid": kid})])
        after = len(creates_sent(pid_hex(lp_)))
        codes = [p_code(x) for x in rs]
        idem_state = (rs[3].get("result") or {}).get("state") if isinstance(rs[3], dict) else None
        ok = age > 180 and codes[:3] == ["grant_refused", "ok:found", "ok:found"] and codes[3].startswith("ok:") \
            and idem_state in ("none", "in_progress", "done") and before == after
        record(GID, "PT-40", "after R_max: refund.create grant_refused (nothing sent); find / get / idem.status still served",
               "PT-40 / PA-18", "SI-15", verdict(ok, inconclusive=age <= 180),
               f"grant_age_s={int(age)} replies={codes} idem_state={(rs[3].get('result') or {}).get('state') if isinstance(rs[3], dict) else rs[3]} creates {before}->{after}")
        record(GID, "PT-29f", "grant older than R_max on refund.create: refused, nothing sent", "PT-29 / PA-18", "SI-05",
               verdict(codes[0] == "grant_refused" and before == after and age > 180, inconclusive=age <= 180),
               f"grant_age_s={int(age)} reply={codes[0]}")
    # PT-43: missing or foreign idem_kid on every op.
    ops = [("refund.create", {"grant": g}), ("refund.find", {"grant": g}), ("refund.get", {"grant": g, "refund_id": "re_AAAAAAAAAAAA"}),
           ("idem.status", {"grant": g})]
    before = len(creates_sent(pid_hex(pid)))
    n0 = len([e for e in adapter_events() if e.get("event") == "p_request"])
    lines = [p_line(op, a) for op, a in ops] + [p_line(op, dict(a, idem_kid="0000000000000000")) for op, a in ops]
    rs, _ = p_client(lines)
    codes = [p_code(x) for x in rs]
    time.sleep(0.5)
    after = len(creates_sent(pid_hex(pid)))
    window = [e for e in adapter_events() if e.get("event") == "p_request"][n0:]
    # Only this probe's own requests (by correlation id): the broker's lookup-only settlement watch
    # (Draft 3.3 §7.3, DEMOP-F06) legitimately sends refund.get for other rows during the window.
    cids = {x.get("correlation_id") for x in rs if isinstance(x, dict) and x.get("correlation_id")}
    mine = [e for e in window if e.get("correlation_id") in cids]
    sent = [e for e in mine if e.get("provider_request_started")]
    ok = codes[:4] == ["malformed_request"] * 4 and codes[4:] == ["idem_kid_mismatch"] * 4 and before == after \
        and len(cids) == 8 and not sent
    record(GID, "PT-43", "every op on P with a missing / foreign idem_kid: malformed_request / idem_kid_mismatch; nothing sent",
           "PT-43 / PC-A-01, BP-01", "SI-09", verdict(ok),
           f"replies={codes} creates {before}->{after} own_requests={len(mine)} sent_to_provider={len(sent)}")


# =============================================================================== PT: DB roles

def t_pt30_31_39_db():
    log("\n== PT-30 / PT-31 / PT-39: database roles, constraints, pg_hba ==")
    lg = ORD["legit"]
    rc, _, e1 = operator_sql(f"INSERT INTO nodkey.orders (order_id, ten, owner_sub, charge_id, currency, captured_minor, "
                             f"external_refunded_minor, status) VALUES (5001,'acme','user:alice','{lg['charge_id']}','USD',100,0,'captured')")
    rc2, _, e2 = operator_sql(f"INSERT INTO nodkey.orders (order_id, ten, owner_sub, charge_id, currency, captured_minor, "
                              f"external_refunded_minor, status) VALUES (5002,'globex','user:carol','{lg['charge_id']}','USD',100,0,'captured')")
    ins = "INSERT INTO nodkey.orders (order_id, ten, owner_sub, charge_id, currency, captured_minor, external_refunded_minor, status) " \
          "VALUES (5003,'acme','user:alice','ch_demop9000000001','USD',100,0,'captured')"
    eb, ea = as_role("nodkey_broker", ins), as_role("nodkey_payments_adapter", ins)
    ok = rc != 0 and "duplicate key" in e1 and rc2 != 0 and "duplicate key" in e2 and "permission denied" in eb \
        and "permission denied" in ea and psql("SELECT count(*) FROM nodkey.orders WHERE order_id>5000") == "0"
    record(GID, "PT-30", "orders: second row with an existing charge_id (same / other tenant) unique violation; broker and adapter roles cannot insert (shop: no DB route, C-SOCK/C-NET)",
           "PT-30 / PA-04", "SI-10", verdict(ok),
           f"dup={e1.splitlines()[0][:60] if e1 else rc} cross_tenant={e2.splitlines()[0][:60] if e2 else rc2} broker={eb[:60]!r} adapter={ea[:60]!r}")
    stmts = {
        "update_orders": "UPDATE nodkey.orders SET status='refunded' WHERE order_id=1001",
        "select_for_update": "SELECT order_id FROM nodkey.orders WHERE order_id=1001 FOR UPDATE",
        "grant": "GRANT SELECT ON nodkey.orders TO PUBLIC",
        "create_in_nodkey": "CREATE TABLE nodkey.x (a int)",
        "create_in_public": "CREATE TABLE public.x (a int)",
        "create_temp": "CREATE TEMP TABLE x (a int)",
        "shadow_view": "CREATE VIEW public.orders AS SELECT 1",
        # Draft 3.3 §2 PA-17: changing the session search_path does not help create a shadow.
        "shadow_after_set_path": "SET LOCAL search_path = public, nodkey; CREATE VIEW orders AS SELECT 1",
    }
    res = {k: as_role("nodkey_broker", s) for k, s in stmts.items()}
    refused = {k: ("permission denied" in v or "must be" in v or "no privileges were granted" in v) for k, v in res.items()}
    hba = compose("exec", "-T", "-e", "PGPASSWORD=x", "--user", "postgres", "db", "psql", "-h", "172.30.20.20",
                  "-U", "nodkey_payments_adapter", "-d", "ledger", "-c", "SELECT 1").stderr.decode()
    bpaths = infra("broker", "path=/etc/nodkey-adapter/keys.json", "path=/etc/nodkey-adapter/config.json",
                   "path=/run/adapter-secrets/k_idem", "path=/run/adapter-secrets/simpay_key", "path=/run/pg-adapter")
    absent = all(v == "absent" for k, v in bpaths.items() if k.startswith("path "))
    # Draft 3.3 §2 PA-17 / PT-31 (DEMOP-F07): the control is "nothing can be created anywhere" plus
    # pinned function search_path; ALTER ROLE on one's own session defaults is permitted by
    # PostgreSQL and is not expected to be refused.
    roles = "('nodkey_broker','nodkey_payments_adapter','nodkey_shop_operator')"
    db_privs = psql(f"SELECT string_agg(r.rolname || '@' || d.datname, ',') FROM pg_roles r CROSS JOIN pg_database d "
                    f"WHERE r.rolname IN {roles} AND (has_database_privilege(r.oid, d.oid, 'CREATE') "
                    f"OR has_database_privilege(r.oid, d.oid, 'TEMPORARY'))")
    schema_privs = psql(f"SELECT string_agg(r.rolname || '@' || n.nspname, ',') FROM pg_roles r CROSS JOIN pg_namespace n "
                        f"WHERE r.rolname IN {roles} AND has_schema_privilege(r.oid, n.oid, 'CREATE')")
    role_attrs = psql(f"SELECT string_agg(rolname, ',') FROM pg_roles WHERE rolname IN {roles} "
                      f"AND (rolsuper OR rolcreatedb OR rolcreaterole)")
    unpinned = psql("SELECT string_agg(p.oid::regprocedure::text, ',') FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                    "WHERE n.nspname IN ('public','nodkey') AND NOT EXISTS "
                    "(SELECT 1 FROM unnest(coalesce(p.proconfig, '{}')) c WHERE c LIKE 'search_path=%')")
    n_roles = psql(f"SELECT count(*) FROM pg_roles WHERE rolname IN {roles}")
    catalog_ok = db_privs == "" and schema_privs == "" and role_attrs == "" and unpinned == "" and n_roles == "3"
    alter_role = as_role("nodkey_broker", "ALTER ROLE nodkey_broker SET search_path = 'public'")
    ok = all(refused.values()) and catalog_ok and "pg_hba.conf rejects" in hba and absent
    record(GID, "PT-31", "broker role: UPDATE / FOR UPDATE / GRANT / CREATE (any schema, temp) / shadowing view (also after SET search_path) refused; "
           "no Nodkey role has CREATE on any schema or CREATE/TEMPORARY on any database; functions pin search_path; "
           "adapter role over TCP rejected by pg_hba; adapter inputs absent in broker",
           "PT-31 / PA-03, PA-15..17", "SI-02/SI-10", verdict(ok),
           f"refused={refused} not_refused={ {k: (v.splitlines() or ['succeeded'])[0][:70] for k, v in res.items() if not refused[k]} } "
           f"db_create_temp={db_privs or 'none'} schema_create={schema_privs or 'none'} role_attrs={role_attrs or 'none'} "
           f"unpinned_functions={unpinned or 'none'} "
           f"pg_hba={'rejects' if 'pg_hba.conf rejects' in hba else hba[:80]!r} broker_paths_absent={absent} "
           f"alter_own_role_defaults={'permitted (residual, spec §10)' if not alter_role else alter_role.splitlines()[0][:60]}")
    # PT-39: counters out of step; operator updates; operator cannot touch broker tables.
    _, e = psql_err(f"BEGIN; UPDATE nodkey.charge_refund_state SET succeeded_minor = succeeded_minor + 1 "
                    f"WHERE charge_id='{lg['charge_id']}'; COMMIT;")
    drift_refused = bool(e)
    k_after = crs(lg["charge_id"])
    rc_a, _, ea = operator_sql(f"UPDATE nodkey.orders SET external_refunded_minor = external_refunded_minor WHERE order_id={lg['order_id']}")
    rc_b, _, eb = operator_sql(f"UPDATE nodkey.orders SET status='captured' WHERE order_id={ORD['alice_eur']['order_id']}")
    rc_c, _, ec = operator_sql("UPDATE nodkey.payment_effect SET state='FAILED'")
    rc_d, _, ed = operator_sql(f"UPDATE nodkey.charge_refund_state SET succeeded_minor = 0 WHERE charge_id='{lg['charge_id']}'")
    ok = drift_refused and k_after["succeeded_minor"] == 1250 and rc_a == 0 and rc_b == 0 and rc_c != 0 and rc_d != 0 \
        and "permission denied" in ec and "permission denied" in ed
    record(GID, "PT-39", "counters forced out of step: commit rejected by the constraint trigger; operator updates commit (with and without a state row); operator cannot touch broker tables",
           "PT-39 / PA-15, BP-02", "SI-11", verdict(ok),
           f"drift_error={e.splitlines()[-1][:80] if e else 'none'!r} counters={k_after} op_with_state_row={rc_a} "
           f"op_without_state_row={rc_b} op_on_payment_effect={ec[:50]!r} op_on_counters={ed[:50]!r}")
    nt("PT-39b", "operator owner/status update racing T1 (both orders of arrival)", "PT-39 / SI-11", "SI-11",
       "needs the operator transaction held open across a T1; not placed deterministically from outside")


# =============================================================================== PT: reason oracle and unresolved charges

def t_pt34_41_oracle():
    log("\n== PT-34 / PT-41: reason oracle on foreign orders; unresolved charge ==")
    variants = {
        "bob_usd": (ORD["bob_order"]["order_id"], 500, "USD"),
        "bob_wrong_currency": (ORD["bob_order"]["order_id"], 500, "EUR"),
        "bob_over_captured": (ORD["bob_order"]["order_id"], 999999, "USD"),
        "disputed_order": (ORD["status_change"]["order_id"], 500, "USD"),
        "busy_order_unknown_row": (ORD["f_unknown_deadline"]["order_id"], 500, "USD"),
        "budget_exhausted_owner": (ORD["budget_count"]["order_id"], 100, "USD"),
        "no_such_order": (99999, 500, "USD"),
    }
    seen = {}
    pids = {}
    for name, (oid, amt, cur) in variants.items():
        cli = Client(CTX)
        pid, st, _ = app_propose(cli, oid, amt, cur, "user:alice")
        if not pid:
            seen[name] = ("propose", st)
            continue
        pids[name] = pid
        login_auth(cli, CUST_IDX["user:alice"], return_to_confirm_pid=pid)
        cst, h, body = get_confirm(cli, pid)
        s = app_status(pid)
        seen[name] = (cst, body.strip(), s["state"], s["outcome"], s["reason"])
    uniform = len(set(seen.values())) == 1 and next(iter(seen.values()))[0] == 404
    record(GID, "PT-34", "alice proposes on foreign orders in different status/currency/busy/budget states: identical uniform response, no reason leaks",
           "PT-34 / PA-07", "SI-10/SI-16", verdict(uniform),
           f"distinct_responses={len(set(seen.values()))} sample={next(iter(seen.values())) if seen else None}")
    p = pids.get("no_such_order")
    if p:
        params = json.loads(record_params(p) or "{}")
        ch = params.get("charge_id")
        unresolved_rows = psql("SELECT count(*) FROM nodkey.charge_refund_state WHERE charge_id !~ '^ch_[A-Za-z0-9]{8,61}$'")
        ok = ch == "unresolved" and not grant_bytes_present(p) and unresolved_rows == "0" and seen["no_such_order"][0] == 404
        record(GID, "PT-41a", "proposal for a non-existent order stores charge_id 'unresolved'; never signed; no state row with a non-charge id",
               "PT-41 / PA-19", "SI-10", verdict(ok), f"charge_id={ch!r} grant={grant_bytes_present(p)} bad_state_rows={unresolved_rows}")
    nt("PT-41b", "con2 malformed in a signed grant, on every P op / T1", "PT-41 / PA-19", "SI-10",
       "needs a validly signed grant with a malformed con2; the authority refuses to sign one (RX-6) and the harness has no other signer")


# =============================================================================== PT: deadlines

def t_pt44_deadlines():
    log("\n== PT-44: one deadline per request ==")
    o = ORD["f_slow_response"]
    _, pid, row, st = _fault_flow("f_slow_response", 900, [rule(o["charge_id"], "slow_response", ms=9000)])
    if pid is None:
        record(GID, "PT-44a", "stalled provider", "PT-44 / PC-A-02", "SI-15", "INCONCLUSIVE", st)
        return
    first = next((e for e in calls(pid) if e.get("op") == "refund.create"), {})
    mine = [x for x in refunds_of(o["charge_id"]) if x["amount"] == 900]
    ok = first.get("class") == "ambiguous" and first.get("elapsed_ms", 10 ** 9) <= 5000 + 500 and row and row["state"] == "SUCCEEDED" \
        and len(mine) == 1
    record(GID, "PT-44a", "provider stalls 9 s: adapter answers within total_ms (5 s) as ambiguous; resolves SUCCEEDED, ledger 1",
           "PT-44 / PC-A-02", "SI-15", verdict(ok),
           f"create={first.get('class')}/{first.get('cause')} elapsed_ms={first.get('elapsed_ms')} final={row and row['state']} ledger={len(mine)}")
    _, h = hello_kid()
    dl = ((h or {}).get("result") or {}).get("deadline_ms") if isinstance(h, dict) else None
    broker_wait = json.load(open(f"{ROOT}/examples/confirmed-refund/config/broker.json"))["payments"]["adapter_total_ms"] + 2000
    record(GID, "PT-44b", "adapter.hello deadline_ms is below the broker's wait (adapter_total_ms + 2 s)", "PT-44 / BP-03", "SI-15",
           verdict(dl is not None and dl < broker_wait), f"deadline_ms={dl} broker_wait_ms={broker_wait}")
    nt("PT-44c", "slow order view; broker refuses an adapter whose deadline is not below its wait; slot wait beyond the lease",
       "PT-44 / BP-03", "SI-15", "needs a slowed adapter DB channel or a reconfigured broker; not implemented in the harness")


def t_not_tested_rows():
    nt("PT-28", "restore drill (§10)", "PT-28", "SI-09", "no backup/restore procedure is implemented for the demo DB")
    nt("PT-33", "dispatcher vs reconciler under an injected 60 s T3 delay", "PT-33 / PA-06", "SI-09",
       "needs a 60 s stall of T3 alone (not the dispatcher's lease CAS); the DB can only be paused as a whole")
    nt("PT-35", "HTTP edge: 1xx then 200; 65 headers; non-ASCII header byte; short Content-Length; chunked trailers; list of 3 / has_more",
       "PT-35 / PA-10", "SI-16", "simpay has no fault kinds that emit these responses")


LEGIT_PID = [None]


def t_legit_keep():
    LEGIT_PID[0] = t_legit()


# Run order matters: budgets are per customer per UTC day, PT-15 waits past R_max (so the legit
# grant is older than R_max for PT-29f / PT-40), PT-22a's denied grant must still be younger than
# R_max for PT-29d, and the tests that restart or swap adapter inputs or kill the broker run last.
TESTS = {
    "containment": t_pt13_14_38_containment,
    "pt01": t_pt01_foreign_order,
    "pt20": t_pt20_status_immutable,
    "pt02": t_pt02_tamper,
    "pt03": t_pt03_currency,
    "pt04": t_pt04_redeliver,
    "pt05": t_pt05_race,
    "pt10": t_pt10_12_inputs,
    "pt11": t_pt11_remaining,
    "pt06": t_pt06_commit_then_drop,
    "pt07": t_pt07_commit_after_delay,
    "pt08": t_pt08_commit_then_500,
    "pt09": t_pt09_not_committed,
    "pt16": t_pt16_lies,
    "pt17": t_pt17_redirect,
    "pt18": t_pt18_hostile_responses,
    "pt19": t_pt19_listeners,
    "pt26": t_pt26_vectors,
    "pt15": t_pt15_27_unknown_deadline,
    "pt22": t_pt22_budget,
    "pt29": t_pt29_40_43_broker_compromise,
    "pt34": t_pt34_41_oracle,
    "pt23": t_pt23_late_failed,
    "pt30": t_pt30_31_39_db,
    "pt24peer": t_pt24_peer,
    "startup": t_pt24_32_31_startup,
    "pt25": t_pt25_tls,
    "pt42": t_pt42_revoked,
    "pt44": t_pt44_deadlines,
    "pt21": t_pt21_crashes,
    "nottested": t_not_tested_rows,
}


def main():
    global ROOT, OUT, CTX, PROJECT, LIB, DATA, ORD, CUST_IDX
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--only", default="")
    ap.add_argument("--no-seed", action="store_true")
    args = ap.parse_args()
    ROOT, OUT = args.root, args.out
    PROJECT = f"{ROOT}/examples/confirmed-refund/compose.yaml"
    CTX = ssl.create_default_context(cafile=f"{OUT}/gateway-dev-cert.pem")
    LIB = strip_php_tag(load_probe("lib.php"))
    DATA = json.load(open(f"{ROOT}/examples/confirmed-refund/config/demo-data.json"))
    ORD = {o["tag"]: o for o in DATA["orders"]}
    CUST_IDX = {c["sub"]: c["index"] for c in DATA["customers"]}

    if not args.no_seed:
        ok, detail = seed_orders()
        record("setup", "S-00", "operator seeds nodkey.orders after checking each row against the simpay ledger",
               "§7.1", "SI-10", verdict(ok), detail)
        if not ok:
            return finish()
    only = [x for x in args.only.split(",") if x]
    plan = [("legit", t_legit_keep)] + list(TESTS.items())
    for name, fn in plan:
        if only and name not in only:
            continue
        try:
            fn()
        except Exception as e:
            import traceback
            record(name, name, "harness error", "-", "-", "INCONCLUSIVE",
                   f"{e} | {traceback.format_exc()[-300:]}")
        finally:
            try:
                clear_faults()
                set_malicious(False)
            except Exception:
                pass
    finish()


def finish():
    with open(f"{OUT}/results.json", "w") as f:
        json.dump(RESULTS, f, indent=2)
    print("\n================ Demo P results ================")
    w = max([len(r["id"]) for r in RESULTS] + [4])
    for r in RESULTS:
        print(f"{r['result']:14} | {r['id']:<{w}} | {r['maps']:<22} | {r['SI']:<16} | {r['title']}")
    fails = [r for r in RESULTS if r["result"] == "FAIL"]
    inconc = [r for r in RESULTS if r["result"] in ("INCONCLUSIVE", "NOT TESTED")]
    npass = sum(1 for r in RESULTS if r["result"] == "PASS")
    na = sum(1 for r in RESULTS if r["result"] == "NOT APPLICABLE")
    print(f"\nTotal {len(RESULTS)}: {npass} PASS, {len(fails)} FAIL, {len(inconc)} INCONCLUSIVE/NOT TESTED, {na} NOT APPLICABLE")
    print(f"results.json -> {OUT}/results.json")
    sys.exit(1 if fails else (2 if inconc else 0))


if __name__ == "__main__":
    main()
