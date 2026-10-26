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


TESTS = {}


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
    plan = [("legit", t_legit)] + list(TESTS.items())
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
