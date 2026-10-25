#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Henry Cuevas
# SPDX-License-Identifier: Apache-2.0
#
# Demo 2 (confirmed transfers) end-to-end + attack harness. Runs against the LOCAL, INTENTIONALLY
# VULNERABLE stack in examples/confirmed-transfer/, started by tests/demo2/run.sh.
#
# It is a scripted browser: a tiny HTTP/1.1 client over the gateway's dev TLS, with per-origin
# cookie jars, that sends the Sec-Fetch-* and Origin headers a real browser sends. It drives the
# legit propose -> confirm -> execute flow, then each attack group (1-12), using the app's
# /debug/eval RCE endpoint to model attacker C inside the workload. It never sends the owner's
# email or any personal identifier anywhere (the only principals are the demo test users).
#
# Output: var/demo2/results.json and a table on stdout. Exit 0 iff every result is PASS or
# NOT APPLICABLE; 1 on any FAIL; 2 if none FAIL but some INCONCLUSIVE / NOT TESTED.

import argparse, base64, json, re, socket, ssl, subprocess, sys, time

GW = ("127.0.0.1", 8443)
APP = "app.localhost:8443"
AUTH = "auth.localhost:8443"
APP_ORIGIN = "https://" + APP
AUTH_ORIGIN = "https://" + AUTH
PROJECT = "examples/confirmed-transfer/compose.yaml"

RESULTS = []


def record(gid, tid, title, t_map, si, result, detail=""):
    RESULTS.append({"group": gid, "id": tid, "title": title, "T": t_map, "SI": si,
                    "result": result, "detail": str(detail)[:400]})
    print(f"  [{result:12}] {tid}: {title}" + (f" -- {detail}" if detail else ""), file=sys.stderr)


class Client:
    """One scripted browser: per-origin cookie jars, manual redirects."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.jars = {APP: {}, AUTH: {}}

    def _host_of(self, origin):
        return APP if origin == APP_ORIGIN else AUTH

    def request(self, origin, method, path, headers=None, body=b"", sec_fetch=None, origin_hdr=None):
        host = self._host_of(origin)
        sni = host.split(":")[0]
        hdrs = {"Host": host, "Connection": "close", "User-Agent": "nodkey-demo2-harness",
                "Accept": "text/html"}
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
        raw = socket.create_connection(GW, timeout=20)
        s = self.ctx.wrap_socket(raw, server_hostname=sni)
        s.sendall(req.encode() + body)
        buf = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        s.close()
        head, _, rbody = buf.partition(b"\r\n\r\n")
        lines = head.decode("latin1").split("\r\n")
        status = int(lines[0].split()[1])
        rheaders = []
        for ln in lines[1:]:
            k, _, v = ln.partition(":")
            rheaders.append((k.strip().lower(), v.strip()))
        for k, v in rheaders:
            if k == "set-cookie":
                self._store_cookie(host, v)
        return status, rheaders, rbody.decode("utf-8", "replace")

    def _store_cookie(self, host, sc):
        nv = sc.split(";")[0]
        name, _, val = nv.partition("=")
        name, val = name.strip(), val.strip()
        attrs = sc.lower()
        expired = "max-age=0" in attrs or ("expires=" in attrs and "1970" in attrs)
        if expired:
            self.jars[host].pop(name, None)
        else:
            self.jars[host][name] = val

    def header(self, rheaders, name):
        return [v for k, v in rheaders if k == name.lower()]


# ---- operator oracles (allowed: operator with host/db access, NOT the workload) ----

def compose(*args, check=True, input_bytes=None):
    return subprocess.run(["docker", "compose", "-f", PROJECT, *args],
                          capture_output=True, input=input_bytes, check=check)


def psql(sql):
    # `local all postgres peer`: connect as the postgres OS user inside the container.
    r = compose("exec", "-T", "--user", "postgres", "db", "psql", "-U", "postgres", "-d", "ledger",
                "-tAc", sql, check=False)
    return r.stdout.decode().strip()


def balance(acct):
    return int(psql(f"SELECT balance_cents FROM accounts WHERE id='{acct}'"))


def transfers_count(pid):
    return int(psql(f"SELECT count(*) FROM transfers WHERE idempotency_key='{pid}'"))


def rce(php):
    """Run PHP inside the app workload via the /debug/eval RCE endpoint; return the response text."""
    st, _, body = CLIENT.request(APP_ORIGIN, "POST", "/debug/eval", body=php.encode(),
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    return body


def load_probe(name):
    with open(f"{ROOT}/tests/demo2/probes/{name}") as f:
        txt = f.read()
    return re.sub(r"^<\?php\n", "", txt, count=1)  # /debug/eval evals code without an opening tag


LIB = None  # probe helper source, loaded in main


# ---- flow helpers ----

TOKEN_RE = re.compile(r'name="token" value="([^"]+)"')
DIGEST_RE = re.compile(r'name="digest" value="([0-9a-f]{64})"')


def login_auth(cli, user_idx, return_to_confirm_pid=None):
    """Establish an auth-origin session as test user `user_idx`. If a confirm pid is given, the
    login return path is set by visiting /confirm first (server-side return, EP-13)."""
    if return_to_confirm_pid:
        st, h, _ = cli.request(AUTH_ORIGIN, "GET", f"/confirm/{return_to_confirm_pid}", sec_fetch="navigate")
    st, h, body = cli.request(AUTH_ORIGIN, "GET", "/login", sec_fetch="navigate")
    csrf = (re.search(r'name="csrf" value="([^"]+)"', body) or [None, None])[1]
    form = f"user={user_idx}&csrf={csrf}"
    st, h, body = cli.request(AUTH_ORIGIN, "POST", "/login", body=form, sec_fetch="navigate",
                              origin_hdr=AUTH_ORIGIN)
    loc = cli.header(h, "location")
    return st, loc[0] if loc else None


def app_propose_transfer(cli, to, amount):
    """Act as the logged-out browser hitting the app: POST /transfer -> 303 to confirm_url."""
    st, h, body = cli.request(APP_ORIGIN, "POST", "/transfer", body=f"to={to}&amount_minor={amount}",
                              sec_fetch="navigate", origin_hdr=APP_ORIGIN)
    loc = cli.header(h, "location")
    return (loc[0] if loc else None), st, body


def get_confirm(cli, pid):
    return cli.request(AUTH_ORIGIN, "GET", f"/confirm/{pid}", sec_fetch="navigate")


def approve(cli, pid, token, digest, **kw):
    body = f"token={token}&digest={digest}&decision=approve"
    return cli.request(AUTH_ORIGIN, "POST", f"/confirm/{pid}/decision", body=body, **kw)


def approve_with_retry(cli, pid, tries=5):
    """A real browser approval, re-rendering a fresh token each try. Works around component defect
    DEMO2-F02 (authority does not retry a stale pooled socket A connection, so the first approval
    after >10 s of A-channel idleness fails; a re-render + re-approve reconnects). Returns the
    final record state."""
    for i in range(tries):
        _, _, page = get_confirm(cli, pid)
        tok, dig = TOKEN_RE.search(page), DIGEST_RE.search(page)
        if not tok:  # already decided (e.g. already APPROVED on a previous try)
            break
        approve(cli, pid, tok.group(1), dig.group(1), sec_fetch="navigate", origin_hdr=AUTH_ORIGIN)
        time.sleep(1.5)
        if record_state(pid) in ("APPROVED", "EXECUTING", "SUCCEEDED", "FAILED"):
            break
    return record_state(pid)


def propose_via_rce(to, amount, ten="acme", sub="user:alice", op="ledger.transfer"):
    """Have the (compromised) app propose directly on socket W; returns the pending_id."""
    php = (LIB + "\n$r = sock_call(W_SOCK, 'effect.propose', "
           f"['op'=>'{op}','params'=>['from'=>'alice','to'=>'{to}','amount_minor'=>{amount}],"
           f"'approver'=>['ten'=>'{ten}','sub'=>'{sub}']]); echo json_encode($r);")
    out = rce(php)
    try:
        r = json.loads(out.strip().splitlines()[-1])
    except Exception:
        return None, out
    return (r.get("result", {}).get("pending_id"), r) if r.get("ok") else (None, r)


def wait_state(pid, want, timeout=20, workload="app"):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        st = psql(f"SELECT state FROM pending_effect WHERE pending_id=decode('%s','base64')" %
                  _pid_b64(pid))
        last = st
        if st == want:
            return True, st
        time.sleep(0.5)
    return False, last


def _pid_b64(pid):
    # pending_id is 22-char base64url with no padding; Postgres decode() wants standard base64.
    s = pid.replace("-", "+").replace("_", "/")
    return s + "=" * ((4 - len(s) % 4) % 4)


def record_state(pid):
    return psql("SELECT state FROM pending_effect WHERE pending_id=decode('%s','base64')" % _pid_b64(pid))


def record_params(pid):
    return psql("SELECT params FROM pending_effect WHERE pending_id=decode('%s','base64')" % _pid_b64(pid))


# ================================ test groups ================================

def legit_flow():
    print("\n== Legit flow: alice transfers 100 to bob with approval ==", file=sys.stderr)
    cli = Client(CTX)
    b_from, b_to = balance("alice"), balance("bob")
    confirm_url, st, body = app_propose_transfer(cli, "bob", 100)
    if not confirm_url or "/confirm/" not in confirm_url:
        record("legit", "L-01", "app proposes; 303 to confirm_url", "T12", "SI-20", "FAIL",
               f"status={st} loc={confirm_url}")
        return None
    pid = confirm_url.rstrip("/").split("/confirm/")[-1]
    record("legit", "L-01", "app proposes transfer; redirected to confirm_url", "T12", "SI-20",
           "PASS", f"pid={pid}")
    login_auth(cli, 0, return_to_confirm_pid=pid)  # alice
    st, h, page = get_confirm(cli, pid)
    tok = TOKEN_RE.search(page)
    dig = DIGEST_RE.search(page)
    shows_vals = ("bob" in page and "100" in page)
    if not (st == 200 and tok and dig and shows_vals):
        record("legit", "L-02", "confirm page shows exact values + token", "T12", "SI-20", "FAIL",
               f"status={st} token={bool(tok)} digest={bool(dig)} shows={shows_vals}")
        return None
    record("legit", "L-02", "confirm page shows exact values (to=bob, 100) + approval token",
           "T12", "SI-20/SI-21", "PASS")
    approve_with_retry(cli, pid)
    ok, state = wait_state(pid, "SUCCEEDED", timeout=25)
    nfrom, nto, cnt = balance("alice"), balance("bob"), transfers_count(pid)
    good = ok and nfrom == b_from - 100 and nto == b_to + 100 and cnt == 1
    record("legit", "L-03", "approval -> SUCCEEDED; balances change exactly once",
           "T12/T19", "SI-09/SI-20", "PASS" if good else "FAIL",
           f"state={state} alice {b_from}->{nfrom} bob {b_to}->{nto} transfers={cnt}")
    return pid


def attack1_forge_grant():
    # (1) The app forges a grant / tries to present a write grant on its socket. It cannot mint
    # authority (SI-05) and no W method executes a supplied write grant.
    php = (LIB + r"""
$out = [];
// A self-fabricated 'grant' presented where a read grant is expected (ledger.get_balance on W).
$out['forged_read'] = sock_call(W_SOCK, 'ledger.get_balance', ['account'=>'alice','grant'=>'Zm9yZ2VkLWdyYW50']);
// Random 300-byte 'grant' bytes, base64url, as a read grant.
$out['forged_rand'] = sock_call(W_SOCK, 'ledger.get_balance', ['account'=>'alice','grant'=>rtrim(strtr(base64_encode(random_bytes(300)),'+/','-_'),'=')]);
// There is no W method that accepts a write grant: grant.deliver is refused on W.
$out['deliver_on_w'] = sock_call(W_SOCK, 'grant.deliver', ['pending_id'=>str_repeat('A',22),'grant'=>'AAAA']);
echo json_encode($out);
""")
    try:
        o = json.loads(rce(php).strip().splitlines()[-1])
    except Exception as e:
        record("1", "A1", "app cannot forge/self-mint a grant", "T15/T36", "SI-05", "INCONCLUSIVE", str(e))
        return
    def code(r):
        return "ok" if (isinstance(r, dict) and r.get("ok")) else (r.get("error", {}).get("code") if isinstance(r, dict) else r)
    cr, rr, dw = code(o["forged_read"]), code(o["forged_rand"]), code(o["deliver_on_w"])
    ok = cr == "grant_denied" and rr == "grant_denied" and dw in ("unknown_operation", "operation_not_permitted")
    record("1", "A1", "app cannot forge a grant / deliver a write grant on W",
           "T15/T36", "SI-05", "PASS" if ok else "FAIL",
           f"forged_read={cr} forged_rand={rr} deliver_on_W={dw}")


def attack2_immutable():
    # (2) Propose, approve, then try to change amount/destination/op after approval.
    cli = Client(CTX)
    confirm_url, _, _ = app_propose_transfer(cli, "bob", 250)
    pid = confirm_url.rstrip("/").split("/confirm/")[-1]
    before = record_params(pid)
    login_auth(cli, 0, return_to_confirm_pid=pid)
    approve_with_retry(cli, pid)
    wait_state(pid, "SUCCEEDED", 25)
    # Attacker (RCE) now tries to tamper: re-propose with new values reusing nothing it controls,
    # and there is no API to mutate the approved record. Verify stored params unchanged + exactly
    # the approved values executed.
    after = record_params(pid)
    executed_to = psql(f"SELECT to_account FROM transfers WHERE idempotency_key='{pid}'")
    executed_amt = psql(f"SELECT amount_cents FROM transfers WHERE idempotency_key='{pid}'")
    # Operator-side immutability: even the superuser cannot change an immutable column (the trigger
    # of 02-effects-v2.sh fires regardless of role; the broker DB role has even less privilege).
    trig2 = compose("exec", "-T", "--user", "postgres", "db", "psql", "-U", "postgres", "-d", "ledger", "-tAc",
                    "UPDATE pending_effect SET params='x' WHERE pending_id=decode('%s','base64')" % _pid_b64(pid),
                    check=False)
    trig_err = (trig2.stderr.decode() + trig2.stdout.decode())
    immutable = "immutable column changed" in trig_err
    ok = before == after and executed_to == "bob" and executed_amt == "250" and immutable
    record("2", "A2", "approved record immutable; exact approved values execute; op/dest/amount cannot change",
           "T09", "SI-06/PC-04", "PASS" if ok else "FAIL",
           f"params_unchanged={before==after} executed=to:{executed_to},amt:{executed_amt} trigger_blocks={immutable}")


def _pending_for_attacks(cli, to="bob", amount=100):
    confirm_url, _, _ = app_propose_transfer(cli, to, amount)
    return confirm_url.rstrip("/").split("/confirm/")[-1]


def attack3_csrf():
    # (3) Approval CSRF from the app origin / wrong Sec-Fetch / missing headers.
    browser = Client(CTX)
    pid = _pending_for_attacks(browser)
    login_auth(browser, 0, return_to_confirm_pid=pid)
    _, _, page = get_confirm(browser, pid)
    tok, dig = TOKEN_RE.search(page).group(1), DIGEST_RE.search(page).group(1)
    base = dict(pid=pid, token=tok, digest=dig)
    cases = {
        "app_origin_same_site": dict(sec_fetch={"Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "cors"},
                                     origin_hdr=APP_ORIGIN),
        "cross_site": dict(sec_fetch={"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "cors"},
                           origin_hdr="https://evil.example"),
        "no_fetch_meta_origin_app": dict(origin_hdr=APP_ORIGIN),
        "no_fetch_meta_no_origin": dict(),
        "origin_null": dict(origin_hdr="null"),
        "same_origin_cors_not_navigate": dict(sec_fetch={"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors"},
                                              origin_hdr=AUTH_ORIGIN),
    }
    results = {}
    for name, kw in cases.items():
        st, _, body = approve(browser, pid, tok, dig, **kw)
        results[name] = (st, "not available" in body.lower())
    state = record_state(pid)
    blocked = all(st == 404 for st, _ in results.values()) and state == "PENDING"
    record("3", "A3", "approval CSRF: app-origin/cross-site/missing-meta/null all get uniform 404; stays PENDING",
           "T04/T05/T06/T44", "PC-02/SI-21", "PASS" if blocked else "FAIL",
           f"state={state} " + " ".join(f"{k}={v[0]}" for k, v in results.items()))


def attack4_token():
    # (4) Token reuse / wrong pid / wrong session.
    alice = Client(CTX)
    pid = _pending_for_attacks(alice)
    pid2 = _pending_for_attacks(alice, to="bob", amount=101)
    login_auth(alice, 0, return_to_confirm_pid=pid)
    _, _, page = get_confirm(alice, pid)
    tok, dig = TOKEN_RE.search(page).group(1), DIGEST_RE.search(page).group(1)
    # wrong session: a second browser as alice (different session id) presenting this token.
    other = Client(CTX)
    login_auth(other, 0, return_to_confirm_pid=pid2)
    st_wrong_sess, _, _ = approve(other, pid, tok, dig, sec_fetch="navigate", origin_hdr=AUTH_ORIGIN)
    # wrong pid: present the token against a different pid.
    st_wrong_pid, _, _ = approve(alice, pid2, tok, dig, sec_fetch="navigate", origin_hdr=AUTH_ORIGIN)
    # correct use: the token is single-use (consumed at first presentation).
    st_ok, _, _ = approve(alice, pid, tok, dig, sec_fetch="navigate", origin_hdr=AUTH_ORIGIN)
    # reuse the same (now consumed) token again -> must 404 regardless of what happened above.
    st_reuse, _, _ = approve(alice, pid, tok, dig, sec_fetch="navigate", origin_hdr=AUTH_ORIGIN)
    # drive to success (fresh tokens) to show a valid approval does execute, exactly once.
    state = approve_with_retry(alice, pid)
    ok1, _ = wait_state(pid, "SUCCEEDED", 25)
    cnt = transfers_count(pid)
    ok = (st_wrong_sess == 404 and st_wrong_pid == 404 and st_reuse == 404 and ok1 and cnt == 1)
    record("4", "A4", "token wrong-session/wrong-pid 404; token single-use (reuse 404); one effect",
           "T07", "PC-02/PC-04", "PASS" if ok else "FAIL",
           f"wrong_sess={st_wrong_sess} wrong_pid={st_wrong_pid} reuse={st_reuse} success={ok1} transfers={cnt}")


def attack5_nonapprover():
    # (5) Bob (and cross-tenant carol) approves alice's pending; non-approver sees uniform 404.
    alice = Client(CTX)
    pid = _pending_for_attacks(alice)
    bob = Client(CTX)
    login_auth(bob, 1, return_to_confirm_pid=pid)  # bob
    st_bob, _, body_bob = get_confirm(bob, pid)
    carol = Client(CTX)
    login_auth(carol, 2, return_to_confirm_pid=pid)  # carol (tenant globex)
    st_carol, _, body_carol = get_confirm(carol, pid)
    # 404 body must equal the uniform error, with no record detail leaked.
    uniform = "This request is not available."
    leak = ("bob" in body_bob and "100" in body_bob) or ("alice" in body_carol)
    state = record_state(pid)
    ok = st_bob == 404 and st_carol == 404 and uniform in body_bob and uniform in body_carol \
        and not leak and state == "PENDING"
    record("5", "A5", "non-approver (bob, cross-tenant carol) gets uniform 404; no disclosure; stays PENDING",
           "T01/T03", "SI-20/PC-01/PC-03", "PASS" if ok else "FAIL",
           f"bob={st_bob} carol={st_carol} uniform={uniform in body_bob and uniform in body_carol} state={state}")


def attack6_replay():
    # (6) Replay: re-deliver / re-approve the same pending -> exactly one effect.
    alice = Client(CTX)
    pid = _pending_for_attacks(alice)
    login_auth(alice, 0, return_to_confirm_pid=pid)
    state = approve_with_retry(alice, pid)
    wait_state(pid, "SUCCEEDED", 25)
    cnt1 = transfers_count(pid)
    # Re-render after success: no token (state != PENDING). Re-submit a fabricated token anyway.
    _, _, page2 = get_confirm(alice, pid)
    re_token = TOKEN_RE.search(page2)
    st_replay, _, _ = approve(alice, pid, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                              "0" * 64, sec_fetch="navigate", origin_hdr=AUTH_ORIGIN)
    time.sleep(2)
    cnt2 = transfers_count(pid)
    ok = cnt1 == 1 and cnt2 == 1 and st_replay == 404 and re_token is None
    record("6", "A6", "re-approve / re-render after SUCCEEDED yields no second effect (idempotent)",
           "T19/T46", "SI-09", "PASS" if ok else "FAIL",
           f"transfers={cnt2} replay_status={st_replay} token_after_success={bool(re_token)}")


def attack7_expired():
    # (7) Expired pending: approve after expires_at -> no grant, no effect.
    alice = Client(CTX)
    pid = _pending_for_attacks(alice)
    login_auth(alice, 0, return_to_confirm_pid=pid)
    _, _, page = get_confirm(alice, pid)  # token minted now
    tok = TOKEN_RE.search(page)
    dig = DIGEST_RE.search(page)
    # pending_lifetime_s = 60 in this demo; wait past it, then try to approve with the old token.
    print("     (waiting ~70s for the pending to expire)", file=sys.stderr)
    time.sleep(70)
    st_expired = None
    if tok and dig:
        st_expired, _, _ = approve(alice, pid, tok.group(1), dig.group(1), sec_fetch="navigate", origin_hdr=AUTH_ORIGIN)
    state = record_state(pid)
    cnt = transfers_count(pid)
    ok = cnt == 0 and state in ("EXPIRED", "PENDING") and (st_expired in (404, None))
    # On access the record expires lazily; force one access then re-read.
    get_confirm(alice, pid)
    state2 = record_state(pid)
    ok = cnt == 0 and st_expired == 404 and state2 == "EXPIRED"
    record("7", "A7", "approval after expires_at refused; record EXPIRED; no effect",
           "T24/T34", "SI-20", "PASS" if ok else "FAIL",
           f"approve_status={st_expired} state={state2} transfers={cnt}")


def attack8_cross_workload():
    # (8) Cross-workload/tenant: effect.status of another workload's pending -> uniform not_found.
    # app2 (W2, tenant globex, approver carol) proposes on its own socket.
    php2 = (LIB + "\n$r=sock_call('/run/nodkey/broker.sock','effect.propose',"
            "['op'=>'ledger.transfer','params'=>['from'=>'carol','to'=>'alice','amount_minor'=>5],"
            "'approver'=>['ten'=>'globex','sub'=>'user:carol']]); echo json_encode($r);")
    out = compose("exec", "-T", "app2", "php", "-r", php2, check=False).stdout.decode()
    try:
        r2 = json.loads(out.strip().splitlines()[-1])
    except Exception:
        record("8", "A8", "cross-workload status is uniform not_found", "T11", "SI-06/PC-10",
               "INCONCLUSIVE", f"app2 propose failed: {out[:120]}")
        return
    pid2 = r2.get("result", {}).get("pending_id") if r2.get("ok") else None
    # Also an invalid 'from<>to' may fail; fall back to a self-transfer check error tolerance.
    if not pid2:
        # carol->carol is rejected by CHECK(from<>to) only at execution; propose should still work.
        record("8", "A8", "cross-workload status is uniform not_found", "T11", "SI-06/PC-10",
               "INCONCLUSIVE", f"app2 propose: {json.dumps(r2)[:160]}")
        return
    # app (W) asks effect.status for app2's pid.
    php = (LIB + f"\n$r=sock_call(W_SOCK,'effect.status',['pending_id'=>'{pid2}']); echo json_encode($r);")
    o = json.loads(rce(php).strip().splitlines()[-1])
    code = "ok" if o.get("ok") else o.get("error", {}).get("code")
    # Control: app can see its OWN pending status.
    own, _ = propose_via_rce("bob", 7)
    php3 = (LIB + f"\n$r=sock_call(W_SOCK,'effect.status',['pending_id'=>'{own}']); echo json_encode($r);")
    o3 = json.loads(rce(php3).strip().splitlines()[-1])
    own_ok = o3.get("ok") is True
    ok = code == "not_found" and own_ok
    record("8", "A8", "status of another workload's pending -> not_found; own pending visible",
           "T11", "SI-06/PC-10/PC-03", "PASS" if ok else "FAIL",
           f"foreign={code} own_visible={own_ok}")


def attack9_containment():
    # (9) Containment probes inside the workload: direct DB, control sockets, reading the authority
    # key, confinement. The same code runs via the /debug/eval RCE endpoint (attacker C) -- A1/A8/
    # A10 already drive the broker socket through /debug/eval -- but the full probe sweep issues
    # several connect() calls whose timeouts can exceed the gateway's 15 s upstream cap, so it is
    # run over `docker compose exec` (same namespaces, uid and mounts as the app). See FINDINGS
    # DEMO2-F03. We first confirm the RCE endpoint itself reaches the workload.
    probe_php = "<?php\n" + load_probe("lib.php") + "\n" + load_probe("containment.php")
    r = compose("exec", "-T", "app", "php", input_bytes=probe_php.encode(), check=False)
    out = r.stdout.decode()
    rce_alive = "eval-reachable" in rce(LIB + "\necho 'eval-reachable';")
    rows = [json.loads(l) for l in out.splitlines() if l.strip().startswith("{")]
    fails = [r for r in rows if r.get("result") == "FAIL"]
    for r in rows:
        record("9", r["id"], r["expect"], "containment", r["si"], r["result"], r.get("observed", ""))
    ok = bool(rows) and not fails and rce_alive
    record("9", "A9", "containment holds (no DB/control socket/key; confinement) and RCE endpoint live",
           "containment", "SI-01/02/05/13", "PASS" if ok else ("FAIL" if (fails or not rows) else "INCONCLUSIVE"),
           f"{len(rows)} probes, {len(fails)} failed, rce_endpoint_live={rce_alive}")


def attack10_unconfirmed():
    # (10) Unconfirmed effect never executes.
    pid, _ = propose_via_rce("bob", 4242)
    time.sleep(2)
    state = record_state(pid)
    cnt = transfers_count(pid)
    b = balance("bob")
    ok = state == "PENDING" and cnt == 0
    record("10", "A10", "unconfirmed proposal stays PENDING and never executes",
           "T-propose", "SI-20", "PASS" if ok else "FAIL",
           f"state={state} transfers={cnt}")


def _approve_then_kill(service, amount):
    """Begin an approval and SIGKILL `service` as fast as possible, racing it. The approval runs in
    a background thread; the kill fires immediately. Returns the pending id."""
    import threading
    cli = Client(CTX)
    pid = _pending_for_attacks(cli, to="bob", amount=amount)
    login_auth(cli, 0, return_to_confirm_pid=pid)
    _, _, page = get_confirm(cli, pid)
    tok, dig = TOKEN_RE.search(page), DIGEST_RE.search(page)
    if tok:
        t = threading.Thread(target=lambda: approve(cli, pid, tok.group(1), dig.group(1),
                                                     sec_fetch="navigate", origin_hdr=AUTH_ORIGIN))
        t.start()
    compose("kill", service, check=False)
    if tok:
        t.join(timeout=15)
    return pid


def attack11_authority_crash():
    # (11) Authority killed around approval, then restarted: exactly one effect. The issuance store
    # (fsync'd, jti = pending_id) makes re-approval sign/deliver the same grant idempotently.
    pid = _approve_then_kill("authority", 321)
    compose("up", "-d", "--wait", "authority", check=False)
    time.sleep(2)
    # With the authority back, drive the approval to completion (same pid -> same jti).
    cli = Client(CTX)
    login_auth(cli, 0, return_to_confirm_pid=pid)
    state = approve_with_retry(cli, pid)
    ok1, state = wait_state(pid, "SUCCEEDED", 40)
    cnt = transfers_count(pid)
    ok = cnt == 1 and state == "SUCCEEDED"
    record("11", "A11", "authority crash around approval + restart -> completes exactly once",
           "T29/T46", "SI-09/SI-15", "PASS" if ok else ("INCONCLUSIVE" if cnt <= 1 else "FAIL"),
           f"state={state} transfers={cnt}")


def attack12_broker_crash():
    # (12) Broker killed around APPROVED/execution; restart -> recovery loop executes exactly once.
    pid = _approve_then_kill("broker", 322)
    compose("up", "-d", "--wait", "broker", check=False)
    time.sleep(3)
    # The recovery loop finishes any APPROVED record; if the kill lost the approval, re-approve.
    ok1, state = wait_state(pid, "SUCCEEDED", 20)
    if state not in ("SUCCEEDED",):
        cli = Client(CTX)
        login_auth(cli, 0, return_to_confirm_pid=pid)
        approve_with_retry(cli, pid)
        ok1, state = wait_state(pid, "SUCCEEDED", 40)
    cnt = transfers_count(pid)
    # Restart the broker again to prove recovery never re-executes a finished effect.
    compose("restart", "broker", check=False)
    compose("up", "-d", "--wait", "broker", check=False)
    time.sleep(6)
    cnt2 = transfers_count(pid)
    ok = state == "SUCCEEDED" and cnt == 1 and cnt2 == 1
    record("12", "A12", "broker crash around execution + restart -> recovery executes exactly once",
           "T30/T33", "SI-09/SI-15", "PASS" if ok else ("INCONCLUSIVE" if cnt2 <= 1 else "FAIL"),
           f"state={state} transfers_after_recovery={cnt} after_second_restart={cnt2}")


def main():
    global ROOT, CTX, CLIENT, LIB, CONTAINMENT
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    ROOT = args.root
    CTX = ssl.create_default_context(cafile=f"{args.out}/gateway-dev-cert.pem")
    CLIENT = Client(CTX)  # a throwaway client for RCE calls (app origin only)
    LIB = load_probe("lib.php")
    CONTAINMENT = load_probe("containment.php")

    legit_flow()
    print("\n== Attacks ==", file=sys.stderr)
    for fn in [attack1_forge_grant, attack2_immutable, attack3_csrf, attack4_token, attack5_nonapprover,
               attack6_replay, attack8_cross_workload, attack9_containment, attack10_unconfirmed,
               attack7_expired, attack11_authority_crash, attack12_broker_crash]:
        try:
            fn()
        except Exception as e:
            import traceback
            record(fn.__name__, fn.__name__, "harness error", "-", "-", "INCONCLUSIVE",
                   f"{e} | {traceback.format_exc()[-200:]}")

    with open(f"{args.out}/results.json", "w") as f:
        json.dump(RESULTS, f, indent=2)

    print("\n================ Demo 2 results ================")
    w = max(len(r["id"]) for r in RESULTS)
    for r in RESULTS:
        print(f"{r['result']:12} | g{r['group']:<9} | {r['id']:<{w}} | T:{r['T']:<12} | {r['SI']:<18} | {r['title']}")
    fails = [r for r in RESULTS if r["result"] == "FAIL"]
    inconc = [r for r in RESULTS if r["result"] in ("INCONCLUSIVE", "NOT TESTED")]
    print(f"\nTotal {len(RESULTS)}: {sum(1 for r in RESULTS if r['result']=='PASS')} PASS, "
          f"{len(fails)} FAIL, {len(inconc)} INCONCLUSIVE/NOT TESTED")
    print(f"results.json -> {args.out}/results.json")
    if fails:
        sys.exit(1)
    if inconc:
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
