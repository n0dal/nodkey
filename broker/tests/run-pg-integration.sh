#!/bin/sh
# Runs the broker's PostgreSQL integration tests (tests/pg_integration.rs, marked #[ignore]).
# Starts a throwaway PostgreSQL (image pinned by digest) on 127.0.0.1, initialized with the demo's
# own initdb scripts (01-ledger.sh, 02-effects-v2.sh), runs the ignored tests, removes it.
# Test-only passwords are random per run.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
initdb="$here/../../examples/php-ledger/docker/postgres/initdb"
image="postgres:17-alpine@sha256:eee6c6e1b0894fa4fe0075eb054af9fd1cf39a35321c2d4110626cfe506411fb"
# Under the repository so that VM-based Docker hosts (e.g. Colima) can bind-mount it.
work="$here/../target/pg-it-$$"; mkdir -p "$work"
name="nodkey-broker-it-$$"
super_pw="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
broker_pw="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
printf '%s' "$broker_pw" > "$work/db_broker_password"
chmod 0644 "$work/db_broker_password"
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT INT TERM
docker run -d --name "$name" -e POSTGRES_PASSWORD="$super_pw" \
  -v "$initdb:/docker-entrypoint-initdb.d:ro" \
  -v "$work/db_broker_password:/run/secrets/db_broker_password:ro" \
  -p 127.0.0.1::5432 "$image" >/dev/null
port=""
for _ in $(seq 1 60); do
  if docker exec "$name" pg_isready -U postgres -h 127.0.0.1 >/dev/null 2>&1 \
     && docker exec "$name" psql -U postgres -h 127.0.0.1 -d ledger -tAc "SELECT 1 FROM broker_clock LIMIT 0" >/dev/null 2>&1; then
    port="$(docker port "$name" 5432/tcp | head -1 | sed 's/.*://')"
    break
  fi
  sleep 1
done
[ -n "$port" ] || { docker logs "$name"; echo "postgres did not become ready" >&2; exit 1; }
cd "$here/.."
NODKEY_PG_HOST=127.0.0.1 NODKEY_PG_PORT="$port" \
NODKEY_PG_SUPER_PASSWORD="$super_pw" NODKEY_PG_BROKER_PASSWORD="$broker_pw" \
  cargo test --offline --test pg_integration --test pg_payments -- --ignored --test-threads=4 "$@"
