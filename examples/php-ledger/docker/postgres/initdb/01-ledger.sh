#!/bin/sh
# Creates the simulated ledger. Runs once, as the postgres OS user, over the local socket.
set -eu
BROKER_PW="$(cat /run/secrets/db_broker_password)"
psql -v ON_ERROR_STOP=1 --username postgres --dbname postgres -v broker_pw="$BROKER_PW" <<'SQL'
CREATE DATABASE ledger;
CREATE ROLE nodkey_broker LOGIN PASSWORD :'broker_pw';
SQL
psql -v ON_ERROR_STOP=1 --username postgres --dbname ledger <<'SQL'
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON DATABASE ledger FROM PUBLIC;
GRANT CONNECT ON DATABASE ledger TO nodkey_broker;
GRANT USAGE ON SCHEMA public TO nodkey_broker;
CREATE TABLE accounts (
    id            text PRIMARY KEY CHECK (id ~ '^[a-z0-9_]{1,32}$'),
    balance_cents bigint NOT NULL CHECK (balance_cents >= 0)
);
CREATE TABLE transfers (
    id             bigserial PRIMARY KEY,
    from_account   text NOT NULL REFERENCES accounts(id),
    to_account     text NOT NULL REFERENCES accounts(id),
    amount_cents   bigint NOT NULL CHECK (amount_cents > 0),
    workload       text NOT NULL,
    correlation_id text NOT NULL,
    -- Client-chosen key (SI-09): one committed transfer per (workload, key). The broker stores the
    -- original result so a retry with the same key is answered without a second effect.
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9_-]{16,64}$'),
    from_balance_after_cents bigint NOT NULL CHECK (from_balance_after_cents >= 0),
    created_at     timestamptz NOT NULL DEFAULT now(),
    CHECK (from_account <> to_account),
    CONSTRAINT transfers_workload_idempotency_key_uniq UNIQUE (workload, idempotency_key)
);
INSERT INTO accounts VALUES ('alice', 100000), ('bob', 50000), ('carol', 1000), ('dave', 0);
-- Least privilege for the broker role: no DDL, no DELETE, only balance updates.
GRANT SELECT ON accounts TO nodkey_broker;
GRANT UPDATE (balance_cents) ON accounts TO nodkey_broker;
GRANT INSERT ON transfers TO nodkey_broker;
-- INSERT ... RETURNING id needs SELECT on the returned column. The idempotency lookup
-- (WHERE workload, idempotency_key; returns the stored result) needs SELECT on exactly the
-- columns it reads; correlation_id and created_at stay unreadable.
GRANT SELECT (id, from_account, to_account, amount_cents, from_balance_after_cents,
              workload, idempotency_key) ON transfers TO nodkey_broker;
GRANT USAGE ON SEQUENCE transfers_id_seq TO nodkey_broker;
SQL
# Baseline (conventional) profile only: the app has its own full-access DB role.
if [ -f /run/secrets/db_app_password ]; then
  APP_PW="$(cat /run/secrets/db_app_password)"
  psql -v ON_ERROR_STOP=1 --username postgres --dbname ledger -v app_pw="$APP_PW" <<'SQL'
CREATE ROLE ledger_app LOGIN PASSWORD :'app_pw';
GRANT CONNECT ON DATABASE ledger TO ledger_app;
GRANT USAGE ON SCHEMA public TO ledger_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ledger_app;
SQL
fi
