#!/bin/sh
# Demo A only (LOCAL DEMO): the SIMULATED mail sink's read-only role (tools/mailsink README,
# "Deployment gap"). SELECT on public.outbox and nothing else; login only from the sink's address
# (pg_hba.conf). Runs after 04-mandates.sh, as the postgres OS user.
set -eu
psql -v ON_ERROR_STOP=1 --username postgres --dbname ledger \
  -v pw="$(cat /run/secrets/db_mailsink_password)" <<'SQL'
CREATE ROLE nodkey_mailsink LOGIN NOINHERIT PASSWORD :'pw';
ALTER ROLE nodkey_mailsink SET default_transaction_read_only = on;
GRANT CONNECT ON DATABASE ledger TO nodkey_mailsink;
GRANT USAGE ON SCHEMA public TO nodkey_mailsink;
GRANT SELECT ON public.outbox TO nodkey_mailsink;
SQL
