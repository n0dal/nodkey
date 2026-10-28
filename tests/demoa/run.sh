#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Henry Cuevas
# SPDX-License-Identifier: Apache-2.0
#
# Demo A (an AI support agent under Nodkey; agent-interface-v1 Draft 2 §5, §7) runner for the
# LOCAL, clearly labelled test stack in examples/agent-support/. Only our own local containers are
# contacted. No model, API key or account is used.
#
#   tests/demoa/run.sh [--keep]      (--keep leaves the second stack running afterwards)
#   tests/demoa/run.sh --up-only     (debugging: build and start one fresh stack, run nothing)
#
# Pass 1: fresh stack -> seed -> the §5 script (S0'..S12) -> final-state snapshot.
# Pass 2: fresh stack again (new secrets, keys, volumes) -> the §5 script -> the snapshot must equal
#         pass 1 (AT-26) -> the AT-xx conformance rows.
# Results: var/demoa/results.json and a table on stdout. Exit 0 only if every result is PASS (or
# NOT APPLICABLE); 1 on any FAIL; 2 if none FAIL but some are INCONCLUSIVE / NOT TESTED.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEMO="$ROOT/examples/agent-support"
OUT="$ROOT/var/demoa"
KEEP="${1:-}"
export COMPOSE_FILE="$DEMO/compose.yaml"
compose() { docker compose -f "$DEMO/compose.yaml" "$@"; }

down() { compose --profile setup --profile probe down -v --remove-orphans >/dev/null 2>&1 || true; }

fresh_stack() {
  echo "== resetting stack (local demo state only)" >&2
  down
  rm -rf "$OUT/config" "$OUT/secrets" "$OUT/adapter-stage" "$OUT/pki" "$OUT/simpay" "$OUT"/*.pem
  mkdir -p "$OUT/config" "$OUT/secrets/adapter" "$OUT/adapter-stage/etc" "$OUT/pki" "$OUT/simpay"
  : > "$OUT/config/keys.json"
  : > "$OUT/config/authority.json"

  echo "== secrets" >&2
  for s in db_broker_password db_superuser_password db_adapter_password db_operator_password db_mailsink_password; do
    openssl rand -hex 24 > "$OUT/secrets/$s"
  done
  cp "$OUT/secrets/db_adapter_password" "$OUT/secrets/adapter/db_password"
  printf 'rk_sim_demoa%s\n' "$(openssl rand -hex 16)" > "$OUT/secrets/adapter/simpay_key"
  openssl rand -hex 32 > "$OUT/secrets/adapter/k_idem"
  chmod 0644 "$OUT/secrets"/db_* "$OUT/secrets/adapter"/*

  echo "== simpay fixture (SIMULATED charges)" >&2
  python3 -I - "$DEMO/config/demo-data.json" "$OUT/secrets/adapter/simpay_key" "$OUT/simpay/fixture.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); key = open(sys.argv[2]).read().strip()
fx = {"accounts": [{"id": d["account"], "keys": [
        {"secret": key, "permissions": {"refunds": "write", "charges": "read"},
         "allowed_cidrs": ["172.30.30.10/32"]}], "webhook_endpoints": []}],
      "charges": [{"id": o["charge_id"], "account": d["account"], "amount_minor": o["captured_minor"],
                   "currency": o["currency"].lower()} for o in d["orders"]]}
json.dump(fx, open(sys.argv[3], "w"), indent=1)
PY
  chmod 0644 "$OUT/simpay/fixture.json"

  echo "== simpay TEST-ONLY PKI (gen-test-ca; CA private key deleted afterwards)" >&2
  mkdir -p "$OUT/pki/gen"
  docker run --rm --network none --user 0 --cap-drop ALL --cap-add DAC_OVERRIDE \
    -v "$OUT/pki/gen:/out" --entrypoint /usr/local/bin/simpay nodkey/demoa-simpay:dev \
    gen-test-ca --out /out/certs --dns-name simpay.test >&2
  cp "$OUT/pki/gen/certs/simpay-TEST-ONLY-ca.crt" "$OUT/pki/ca.crt"
  cp "$OUT/pki/gen/certs/simpay-TEST-ONLY-server.crt" "$OUT/pki/server.crt"
  cp "$OUT/pki/gen/certs/simpay-TEST-ONLY-server.key" "$OUT/pki/server.key"
  rm -rf "$OUT/pki/gen"
  chmod 0444 "$OUT/pki/ca.crt" "$OUT/pki/server.crt"
  chmod 0644 "$OUT/pki/server.key"

  echo "== authority keygen (inside the authority's own volume; network none)" >&2
  compose run --rm --no-deps -T authority keygen \
    --out /var/lib/nodkey-authority/signing.key --iss nodkey.authority.demoa \
    > "$OUT/config/keys.json"
  compose run --rm --no-deps -T --entrypoint chmod authority 0400 /var/lib/nodkey-authority/signing.key
  kid="$(python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); k=d["keys"]; assert len(k)==1; print(k[0]["kid"])' "$OUT/config/keys.json")"
  sed "s/@KID@/$kid/" "$DEMO/config/authority.template.json" > "$OUT/config/authority.json"
  chmod 0444 "$OUT/config/keys.json"
  chmod 0644 "$OUT/config/authority.json"

  echo "== adapter inputs into its volumes" >&2
  cp "$DEMO/config/adapter.json" "$OUT/adapter-stage/etc/config.json"
  cp "$OUT/config/keys.json" "$OUT/adapter-stage/etc/keys.json"
  cp "$OUT/pki/ca.crt" "$OUT/adapter-stage/etc/ca.crt"
  cp -R "$OUT/secrets/adapter" "$OUT/adapter-stage/secrets"
  chmod 0644 "$OUT/adapter-stage/etc"/* "$OUT/adapter-stage/secrets"/*
  compose --profile setup run --rm --no-deps -T adapter-init >&2

  echo "== starting stack" >&2
  compose up -d --wait gateway gateway-port adapter simpay-ctl mcp-front agent mailsink >&2 \
    || { compose ps -a >&2; compose logs --no-color >&2 | tail -150; return 1; }
  for _ in $(seq 1 30); do
    compose exec -T gateway cat /run/gw-tls/gateway-dev-cert.pem > "$OUT/gateway-dev-cert.pem" 2>/dev/null \
      && [ -s "$OUT/gateway-dev-cert.pem" ] && break
    sleep 1
  done
  [ -s "$OUT/gateway-dev-cert.pem" ] || { echo "gateway certificate not available" >&2; return 1; }
}

mkdir -p "$OUT"
rm -f "$OUT/results.json" "$OUT/pass1.json" "$OUT"/*.log "$OUT"/*.jsonl
echo "== building images" >&2
compose --profile setup build >&2

fresh_stack
if [ "$KEEP" = "--up-only" ]; then exit 0; fi
set +e
python3 -I "$ROOT/tests/demoa/harness.py" --root "$ROOT" --out "$OUT" --pass 1
rc1=$?
set -e
compose logs --no-color > "$OUT/stack-pass1.log" 2>&1 || true
if [ "$rc1" -ge 3 ]; then echo "pass 1 harness error ($rc1)" >&2; [ "$KEEP" = "--keep" ] || down; exit 1; fi

fresh_stack
set +e
python3 -I "$ROOT/tests/demoa/harness.py" --root "$ROOT" --out "$OUT" --pass 2
rc=$?
set -e
compose --profile probe logs --no-color > "$OUT/stack.log" 2>&1 || true
[ "$KEEP" = "--keep" ] || down
exit $rc
