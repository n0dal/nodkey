#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 n0dal
# SPDX-License-Identifier: Apache-2.0
#
# Demo 2 (confirmed transfers) end-to-end runner for the LOCAL, INTENTIONALLY VULNERABLE stack in
# examples/confirmed-transfer/.
#
#   tests/demo2/run.sh [--keep]      (--keep leaves the stack running afterwards)
#
# 1. Generates local secrets (DB passwords), the authority signing key (`nodkey-authority keygen`,
#    inside the authority's own volume, then chmod 0400) and, from keygen's stdout, the broker's key
#    registry and the authority config (signing_kid) under var/demo2/ (Git-ignored).
# 2. Builds and starts the stack, waits until the gateway answers.
# 3. Runs tests/demo2/harness.py (scripted browser + attacker + operator oracles).
# Results: var/demo2/results.json and a table on stdout. Exit 0 only if every result is PASS
# (or NOT APPLICABLE); 1 on any FAIL; 2 if none FAIL but some are INCONCLUSIVE / NOT TESTED.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEMO="$ROOT/examples/confirmed-transfer"
OUT="$ROOT/var/demo2"
KEEP="${1:-}"
export COMPOSE_FILE="$DEMO/compose.yaml"
compose() { docker compose -f "$DEMO/compose.yaml" "$@"; }

mkdir -p "$OUT/secrets" "$OUT/config"

echo "== resetting stack (local demo state only)" >&2
compose down -v --remove-orphans >/dev/null 2>&1 || true
# rm -rf: a bind-mount target that did not exist when compose first ran gets auto-created as a
# directory by Docker; replace any such stray with a fresh file below.
rm -rf "$OUT/config/keys.json" "$OUT/config/authority.json" "$OUT/results.json" "$OUT"/*.log
# Pre-create the bind-mount targets as FILES so `compose run authority keygen` (which mounts them)
# does not have Docker create them as directories.
: > "$OUT/config/keys.json"
: > "$OUT/config/authority.json"

for s in db_broker_password db_superuser_password; do
  openssl rand -hex 24 > "$OUT/secrets/$s"
done
chmod 0644 "$OUT/secrets"/*   # bind-mounted into containers running as other uids (local demo only)

echo "== building images" >&2
compose build >&2

echo "== authority keygen (inside the authority's own volume; network none)" >&2
# keygen refuses to overwrite; the volume is fresh after `down -v`.
compose run --rm --no-deps -T authority keygen \
  --out /var/lib/nodkey-authority/signing.key --iss nodkey.authority.demo2 \
  > "$OUT/config/keys.json"
compose run --rm --no-deps -T --entrypoint chmod authority 0400 /var/lib/nodkey-authority/signing.key
kid="$(python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); k=d["keys"]; assert len(k)==1; print(k[0]["kid"])' "$OUT/config/keys.json")"
sed "s/@KID@/$kid/" "$DEMO/config/authority.template.json" > "$OUT/config/authority.json"
chmod 0644 "$OUT/config/keys.json" "$OUT/config/authority.json"
echo "   kid=$kid" >&2

echo "== starting stack" >&2
compose up -d --wait gateway gateway-port app2 >&2 || { compose ps -a >&2; compose logs --no-color >&2 | tail -80; exit 1; }

# The gateway writes its dev certificate at start-up; pin it for the client.
for _ in $(seq 1 30); do
  compose exec -T gateway cat /run/gw-tls/gateway-dev-cert.pem > "$OUT/gateway-dev-cert.pem" 2>/dev/null && [ -s "$OUT/gateway-dev-cert.pem" ] && break
  sleep 1
done
[ -s "$OUT/gateway-dev-cert.pem" ] || { echo "gateway certificate not available" >&2; compose logs gateway >&2; exit 1; }

set +e
python3 -I "$ROOT/tests/demo2/harness.py" --root "$ROOT" --out "$OUT"
rc=$?
set -e

compose logs --no-color > "$OUT/stack.log" 2>&1 || true
if [ "$KEEP" != "--keep" ]; then
  compose down -v --remove-orphans >/dev/null 2>&1 || true
fi
exit $rc
