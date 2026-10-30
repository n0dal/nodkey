#!/bin/sh
# SPDX-FileCopyrightText: 2026 Henry Cuevas
# SPDX-License-Identifier: Apache-2.0
#
# Demo 2 seed (runs after examples/php-ledger 01-ledger.sh and 02-effects-v2.sh). Trusted
# ownership written by the operator: alice and bob in tenant acme, carol in tenant globex.
set -eu
psql -v ON_ERROR_STOP=1 --username postgres --dbname ledger <<'SQL'
INSERT INTO account_owner (account_id, ten, owner_sub) VALUES
  ('alice', 'acme',   'user:alice'),
  ('bob',   'acme',   'user:bob'),
  ('carol', 'globex', 'user:carol');
SQL
