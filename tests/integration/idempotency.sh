#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Henry Cuevas
# SPDX-License-Identifier: Apache-2.0
#
# Idempotency and unknown-outcome tests (SI-09, SI-15; review D1-01) for the LOCAL,
# INTENTIONALLY VULNERABLE php-ledger demo, protected profile.
#
#   tests/integration/idempotency.sh
#
# Prints PASS/FAIL per case. Exit status: 0 if every case PASSes, 1 otherwise.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEMO="$ROOT/examples/php-ledger"
OUT="$ROOT/var/containment"   # compose.protected.yaml reads its secrets from here
PORT=8080
FAILS=0

gen_secrets() {  # same approach as tests/containment/run.sh; local demo secrets only
  local d="$OUT/secrets/protected"
  mkdir -p "$d"
  for s in db_broker_password db_superuser_password db_app_password; do
    [ -s "$d/$s" ] || openssl rand -hex 24 > "$d/$s"
  done
  chmod 0644 "$d"/*
}

compose() { docker compose -f "$DEMO/compose.protected.yaml" "$@"; }
sql() { compose exec -T -u postgres db psql -d ledger -tAXc "$1"; }
balance() { sql "SELECT balance_cents FROM accounts WHERE id = '$1'"; }
rows_for() { sql "SELECT count(*) FROM transfers WHERE idempotency_key = '$1'"; }
newkey() { openssl rand -hex 16; }
result() {  # id verdict detail
  printf '%-4s %-4s %s\n' "$1" "$2" "$3"
  [ "$2" = PASS ] || FAILS=$((FAILS + 1))
}

# Prints one JSON line: {"ok":true,"result":{...}} or {"ok":false,"code":"...","msg":"..."}.
xfer_php() {  # from to amount key
  cat <<PHP
<?php
require '/var/www/app/lib/BrokerClient.php';
\$c = new Nodkey\BrokerClient();
\$t0 = microtime(true);
try {
    \$r = \$c->transfer('$1', '$2', $3, '$4');
    echo json_encode(['ok' => true, 'result' => \$r, 'secs' => round(microtime(true) - \$t0, 1)]), "\n";
} catch (Nodkey\BrokerError \$e) {
    echo json_encode(['ok' => false, 'code' => \$e->errorCode, 'msg' => \$e->getMessage(), 'secs' => round(microtime(true) - \$t0, 1)]), "\n";
}
PHP
}
xfer() { xfer_php "$@" | compose exec -T app php; }
jget() { php -r '$v = json_decode(stream_get_contents(STDIN), true); foreach (explode(".", $argv[1]) as $k) { $v = is_array($v) ? ($v[$k] ?? null) : null; } echo is_bool($v) ? ($v ? "true" : "false") : (string) $v;' -- "$1"; }

cleanup() { compose unpause db >/dev/null 2>&1 || true; compose down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

gen_secrets
echo "== starting protected stack" >&2
compose down -v --remove-orphans >/dev/null 2>&1 || true
compose up -d --build --wait >/dev/null

# ---- (a) same key twice -> one debit, second response replayed
K=$(newkey); b0=$(balance alice)
r1=$(xfer alice bob 100 "$K"); r2=$(xfer alice bob 100 "$K")
b1=$(balance alice); n=$(rows_for "$K")
id1=$(echo "$r1" | jget result.transfer_id); id2=$(echo "$r2" | jget result.transfer_id)
if [ "$(echo "$r1" | jget result.replayed)" = false ] && [ "$(echo "$r2" | jget result.replayed)" = true ] \
   && [ -n "$id1" ] && [ "$id1" = "$id2" ] && [ "$n" = 1 ] && [ $((b0 - b1)) = 100 ]; then
  result A PASS "rows=$n delta=$((b0 - b1)) id=$id1 second.replayed=true"
else
  result A FAIL "r1=$r1 r2=$r2 rows=$n delta=$((b0 - b1))"
fi

# ---- (b) same key, different amount -> idempotency_conflict, no debit
r3=$(xfer alice bob 200 "$K"); b2=$(balance alice); n=$(rows_for "$K")
if [ "$(echo "$r3" | jget code)" = idempotency_conflict ] && [ "$n" = 1 ] && [ "$b2" = "$b1" ]; then
  result B PASS "code=idempotency_conflict rows=$n delta=$((b1 - b2))"
else
  result B FAIL "r3=$r3 rows=$n delta=$((b1 - b2))"
fi

# ---- (c) 20 concurrent submissions with one key -> exactly one debit.
# One container exec starts 20 PHP child processes (proc_open) that all send at the same instant.
K=$(newkey); b0=$(balance alice)
child=$(xfer_php alice bob 7 "$K" | tail -n +2)
conc=$(cat <<PHP
<?php
\$child = base64_decode('$(printf '%s' "$child" | base64 | tr -d '\n')');
\$start = microtime(true) + 1.0;
\$procs = [];
for (\$i = 0; \$i < 20; \$i++) {
    \$code = 'time_sleep_until(' . \$start . ');' . \$child;
    \$procs[] = proc_open(['php', '-r', \$code], [1 => ['pipe', 'w']], \$pipes[\$i]);
}
foreach (\$procs as \$i => \$p) { echo stream_get_contents(\$pipes[\$i][1]); proc_close(\$p); }
PHP
)
out=$(printf '%s' "$conc" | compose exec -T app php)
b1=$(balance alice); n=$(rows_for "$K")
total=$(echo "$out" | grep -c '^{' || true)
fresh=$(echo "$out" | grep -c '"replayed":false' || true)
replayed=$(echo "$out" | grep -c '"replayed":true' || true)
other=$((total - fresh - replayed))
if [ "$total" = 20 ] && [ "$fresh" = 1 ] && [ "$n" = 1 ] && [ $((b0 - b1)) = 7 ]; then
  result C PASS "responses=$total fresh=$fresh replayed=$replayed other=$other rows=$n delta=$((b0 - b1))"
else
  result C FAIL "responses=$total fresh=$fresh replayed=$replayed other=$other rows=$n delta=$((b0 - b1)) out=$(echo "$out" | sort | uniq -c | head -5)"
fi

# ---- (d) D1-01 reproduction: DB paused across the client timeout
K=$(newkey); b0=$(balance alice)
xfer alice bob 1 "$(newkey)" >/dev/null   # warm the broker's DB connection (separate key)
b0=$(balance alice)
compose pause db >/dev/null 2>&1
r1=$(xfer alice bob 100 "$K")          # client timeout is 5 s
compose unpause db >/dev/null 2>&1
sleep 3                                # let the broker's in-flight transaction finish
r2=$(xfer alice bob 100 "$K")
b1=$(balance alice); n=$(rows_for "$K")
c1=$(echo "$r1" | jget code)
echo "     (d) first: $r1" >&2
echo "     (d) retry: $r2" >&2
compose logs --no-log-prefix broker 2>/dev/null | grep "$K" | sed 's/^/     (d) broker: /' >&2 || true
if [ "$c1" = outcome_unknown ] && [ "$(echo "$r2" | jget ok)" = true ] && [ "$n" = 1 ] && [ $((b0 - b1)) = 100 ]; then
  result D PASS "first=outcome_unknown retry.replayed=$(echo "$r2" | jget result.replayed) rows=$n delta=$((b0 - b1))"
else
  result D FAIL "first.code=$c1 retry=$r2 rows=$n delta=$((b0 - b1))"
fi

# ---- (e) UI: form carries a server-generated key; posting the same form twice debits once
form=$(curl -s --max-time 10 "http://127.0.0.1:$PORT/")
K=$(echo "$form" | sed -n 's/.*name="idempotency_key" value="\([A-Za-z0-9_-]*\)".*/\1/p' | head -1)
if [ -z "$K" ]; then
  result E FAIL "no idempotency_key hidden field in form"
else
  b0=$(balance alice)
  post() { curl -s -o "$1" -w '%{http_code}' --max-time 30 -X POST \
             --data "from=alice&to=bob&amount_cents=100&idempotency_key=$K" "http://127.0.0.1:$PORT/transfer"; }
  s1=$(post /dev/null); s2=$(post "$OUT/idem-e2.html")
  b1=$(balance alice); n=$(rows_for "$K")
  if [ "$s1" = 200 ] && [ "$s2" = 200 ] && grep -q 'not charged again' "$OUT/idem-e2.html" && [ "$n" = 1 ] && [ $((b0 - b1)) = 100 ]; then
    result E PASS "http=$s1,$s2 rows=$n delta=$((b0 - b1))"
  else
    result E FAIL "http=$s1,$s2 rows=$n delta=$((b0 - b1)) body=$(head -c 300 "$OUT/idem-e2.html")"
  fi
fi

# ---- (f) UI: unknown outcome renders OUTCOME UNKNOWN with 502 (never DENIED); resubmit is safe
form=$(curl -s --max-time 10 "http://127.0.0.1:$PORT/")
K=$(echo "$form" | sed -n 's/.*name="idempotency_key" value="\([A-Za-z0-9_-]*\)".*/\1/p' | head -1)
b0=$(balance alice)
compose pause db >/dev/null 2>&1
s1=$(post "$OUT/idem-f1.html")
compose unpause db >/dev/null 2>&1
sleep 3
s2=$(post /dev/null)
b1=$(balance alice); n=$(rows_for "$K")
if [ "$s1" = 502 ] && grep -q 'OUTCOME UNKNOWN' "$OUT/idem-f1.html" && ! grep -q 'DENIED' "$OUT/idem-f1.html" \
   && [ "$s2" = 200 ] && [ "$n" = 1 ] && [ $((b0 - b1)) = 100 ]; then
  result F PASS "http=$s1 'OUTCOME UNKNOWN', resubmit http=$s2 rows=$n delta=$((b0 - b1))"
else
  result F FAIL "http=$s1,$s2 rows=$n delta=$((b0 - b1)) body=$(grep -o '<p id="result">[^<]*' "$OUT/idem-f1.html" | head -1)"
fi

# ---- (g) review ID-01: double-submit while the DB is stalled. The second submission waits on the
# broker's connection lock and gets `unavailable`, while the first (same key) commits afterwards.
# The second page must not claim that nothing was charged, and exactly one debit must result.
form=$(curl -s --max-time 10 "http://127.0.0.1:$PORT/")
K=$(echo "$form" | sed -n 's/.*name="idempotency_key" value="\([A-Za-z0-9_-]*\)".*/\1/p' | head -1)
b0=$(balance alice)
compose pause db >/dev/null 2>&1
post "$OUT/idem-g1.html" > "$OUT/idem-g1.status" &
first=$!
sleep 1
s2=$(post "$OUT/idem-g2.html")
compose unpause db >/dev/null 2>&1
wait "$first" || true
sleep 2
b1=$(balance alice); n=$(rows_for "$K")
msg=$(grep -o '<p id="result">[^<]*' "$OUT/idem-g2.html" | head -1)
if [ "$s2" = 503 ] && ! grep -qi 'nothing was charged' "$OUT/idem-g2.html" && ! grep -q 'DENIED' "$OUT/idem-g2.html" \
   && [ "$n" = 1 ] && [ $((b0 - b1)) = 100 ]; then
  result G PASS "second http=$s2 (no 'nothing was charged'), rows=$n delta=$((b0 - b1))"
else
  result G FAIL "second http=$s2 first=$(cat "$OUT/idem-g1.status") rows=$n delta=$((b0 - b1)) msg=$msg"
fi

echo
if [ "$FAILS" -eq 0 ]; then echo "idempotency: all cases PASS"; exit 0; fi
echo "idempotency: $FAILS case(s) FAIL"; exit 1
