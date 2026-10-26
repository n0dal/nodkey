#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Henry Cuevas
# SPDX-License-Identifier: Apache-2.0
#
# Demo P (confirmed refunds via the SIMULATED provider simpay) end-to-end + attack runner for the
# LOCAL, INTENTIONALLY VULNERABLE stack in examples/confirmed-refund/.
#
#   tests/demop/run.sh [--keep]      (--keep leaves the stack running afterwards)
#
# 1. Generates local secrets into var/demop/ (Git-ignored): DB passwords (superuser, broker,
#    adapter, operator), a restricted simpay key (rk_sim_…), K_idem (32 random bytes, hex), the
#    simpay fixture (charges from examples/confirmed-refund/config/demo-data.json), the simpay
#    TEST-ONLY PKI (`simpay gen-test-ca`; the CA private key is deleted afterwards), the authority
#    signing key (`nodkey-authority keygen`, inside the authority volume) and the key registry.
# 2. Copies the adapter's secrets into its volume (uid 10006, mode 0400) with a one-shot service.
# 3. Builds and starts the stack; the harness seeds nodkey.orders through the operator role.
# 4. Runs tests/demop/harness.py. Results: var/demop/results.json and a table on stdout.
# Exit 0 only if every result is PASS (or NOT APPLICABLE); 1 on any FAIL; 2 if none FAIL but some
# are INCONCLUSIVE / NOT TESTED.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEMO="$ROOT/examples/confirmed-refund"
OUT="$ROOT/var/demop"
KEEP="${1:-}"
export COMPOSE_FILE="$DEMO/compose.yaml"
compose() { docker compose -f "$DEMO/compose.yaml" "$@"; }

echo "== resetting stack (local demo state only)" >&2
compose --profile setup --profile probe down -v --remove-orphans >/dev/null 2>&1 || true
rm -rf "$OUT/config" "$OUT/secrets" "$OUT/adapter-stage" "$OUT/pki" "$OUT/simpay" "$OUT/results.json" "$OUT"/*.log "$OUT"/*.pem
mkdir -p "$OUT/config" "$OUT/secrets/adapter" "$OUT/adapter-stage/etc" "$OUT/pki" "$OUT/simpay"
: > "$OUT/config/keys.json"
: > "$OUT/config/authority.json"

echo "== secrets" >&2
for s in db_broker_password db_superuser_password db_adapter_password db_operator_password; do
  openssl rand -hex 24 > "$OUT/secrets/$s"
done
cp "$OUT/secrets/db_adapter_password" "$OUT/secrets/adapter/db_password"
printf 'rk_sim_demop%s\n' "$(openssl rand -hex 16)" > "$OUT/secrets/adapter/simpay_key"
openssl rand -hex 32 > "$OUT/secrets/adapter/k_idem"
# Bind-mounted into containers running as other uids (local demo only); the adapter's copies are
# re-owned 0400 (uid 10006) inside its volume by adapter-init.
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

echo "== building images" >&2
compose --profile setup build >&2

echo "== simpay TEST-ONLY PKI (gen-test-ca; CA private key deleted afterwards)" >&2
mkdir -p "$OUT/pki/gen"
docker run --rm --network none --user 0 --cap-drop ALL --cap-add DAC_OVERRIDE \
  -v "$OUT/pki/gen:/out" --entrypoint /usr/local/bin/simpay nodkey/demop-simpay:dev \
  gen-test-ca --out /out/certs --dns-name simpay.test >&2
cp "$OUT/pki/gen/certs/simpay-TEST-ONLY-ca.crt" "$OUT/pki/ca.crt"
cp "$OUT/pki/gen/certs/simpay-TEST-ONLY-server.crt" "$OUT/pki/server.crt"
cp "$OUT/pki/gen/certs/simpay-TEST-ONLY-server.key" "$OUT/pki/server.key"
rm -rf "$OUT/pki/gen"                               # includes the CA private key
chmod 0444 "$OUT/pki/ca.crt" "$OUT/pki/server.crt"
chmod 0644 "$OUT/pki/server.key"                   # TEST-ONLY server key, readable by simpay's uid

echo "== authority keygen (inside the authority's own volume; network none)" >&2
compose run --rm --no-deps -T authority keygen \
  --out /var/lib/nodkey-authority/signing.key --iss nodkey.authority.demop \
  > "$OUT/config/keys.json"
compose run --rm --no-deps -T --entrypoint chmod authority 0400 /var/lib/nodkey-authority/signing.key
kid="$(python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); k=d["keys"]; assert len(k)==1; print(k[0]["kid"])' "$OUT/config/keys.json")"
sed "s/@KID@/$kid/" "$DEMO/config/authority.template.json" > "$OUT/config/authority.json"
chmod 0444 "$OUT/config/keys.json"
chmod 0644 "$OUT/config/authority.json"
echo "   kid=$kid" >&2

echo "== adapter inputs into its volumes (operator files root 0444; secrets uid 10006 0400)" >&2
cp "$DEMO/config/adapter.json" "$OUT/adapter-stage/etc/config.json"
cp "$OUT/config/keys.json" "$OUT/adapter-stage/etc/keys.json"
cp "$OUT/pki/ca.crt" "$OUT/adapter-stage/etc/ca.crt"
cp -R "$OUT/secrets/adapter" "$OUT/adapter-stage/secrets"
chmod 0644 "$OUT/adapter-stage/etc"/* "$OUT/adapter-stage/secrets"/*
compose --profile setup run --rm --no-deps -T adapter-init >&2

echo "== starting stack" >&2
compose up -d --wait gateway gateway-port adapter simpay-ctl >&2 || { compose ps -a >&2; compose logs --no-color >&2 | tail -120; exit 1; }

for _ in $(seq 1 30); do
  compose exec -T gateway cat /run/gw-tls/gateway-dev-cert.pem > "$OUT/gateway-dev-cert.pem" 2>/dev/null && [ -s "$OUT/gateway-dev-cert.pem" ] && break
  sleep 1
done
[ -s "$OUT/gateway-dev-cert.pem" ] || { echo "gateway certificate not available" >&2; compose logs gateway >&2; exit 1; }

set +e
python3 -I "$ROOT/tests/demop/harness.py" --root "$ROOT" --out "$OUT"
rc=$?
set -e

compose --profile probe logs --no-color > "$OUT/stack.log" 2>&1 || true
if [ "$KEEP" != "--keep" ]; then
  compose --profile setup --profile probe down -v --remove-orphans >/dev/null 2>&1 || true
fi
exit $rc
