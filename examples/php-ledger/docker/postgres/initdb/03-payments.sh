#!/bin/sh
# SPDX-FileCopyrightText: 2026 Henry Cuevas
# SPDX-License-Identifier: Apache-2.0
#
# Demo P / payments-adapter-v1 Draft 3 §2, §7: schema `nodkey` with the operator-owned orders,
# the broker-owned per-charge state, payment effects, budgets and refund denial reasons.
# Runs once after 01-ledger.sh and 02-effects-v2.sh, as the postgres OS user, over the local socket.
#
# Name resolution (PA-17, Draft 3.3): the control is that every broker/adapter statement is
# schema-qualified, every function pins its search_path, and no Nodkey role has CREATE on any
# schema or CREATE/TEMPORARY on any database, so no shadowing object can exist. The per-role
# `search_path = ''` below is defence in depth only: PostgreSQL lets a role ALTER ROLE its own
# session defaults (DEMOP-F07). Every Nodkey role gets search_path = '' and every broker statement is
# schema-qualified (`public.<ledger and v2 tables>`, `nodkey.<payments tables>`). The existing
# ledger and v2 tables stay in `public`, so Demo 1 and Demo 2 (which do not run this file) are
# unchanged; their trigger functions are pinned to `pg_catalog, public` here so they still resolve
# under the empty search_path.
#
# Optional secrets (absent in Demo 1/2): /run/secrets/db_adapter_password,
# /run/secrets/db_operator_password. Without them the roles exist but cannot log in.
#
# pg_hba (not in this file; the deployment's hba file, payments-adapter-v1 §1), in this order:
#   local  ledger  nodkey_payments_adapter                 scram-sha-256
#   host   all     nodkey_payments_adapter  0.0.0.0/0      reject
#   host   all     nodkey_payments_adapter  ::/0           reject
set -eu
role_login() {
  # $1 role, $2 secret file
  if [ -f "$2" ]; then
    psql -v ON_ERROR_STOP=1 --username postgres --dbname postgres -v pw="$(cat "$2")" -v role="$1" <<'SQL'
ALTER ROLE :"role" LOGIN PASSWORD :'pw';
SQL
  fi
}
psql -v ON_ERROR_STOP=1 --username postgres --dbname postgres <<'SQL'
CREATE ROLE nodkey_payments_adapter NOLOGIN NOINHERIT;
CREATE ROLE nodkey_shop_operator NOLOGIN NOINHERIT;
-- Owner of the counter check (BP-02): may read the two tables it compares, nothing else.
CREATE ROLE nodkey_payments_checker NOLOGIN NOINHERIT;
-- PA-17 (Draft 3.3): no Nodkey role may create objects in any database of the cluster, so the
-- default PUBLIC CREATE/TEMPORARY on the maintenance databases is removed too (`ledger` below).
REVOKE CREATE, TEMPORARY ON DATABASE postgres, template1 FROM PUBLIC;
SQL
role_login nodkey_payments_adapter /run/secrets/db_adapter_password
role_login nodkey_shop_operator /run/secrets/db_operator_password

psql -v ON_ERROR_STOP=1 --username postgres --dbname ledger <<'SQL'
REVOKE CREATE, TEMPORARY ON DATABASE ledger FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE ledger TO nodkey_payments_adapter, nodkey_shop_operator;
ALTER ROLE nodkey_broker SET search_path = '';
ALTER ROLE nodkey_payments_adapter SET search_path = '';
ALTER ROLE nodkey_shop_operator SET search_path = '';

-- Functions from 02-effects-v2.sh resolve names at run time: pin them.
ALTER FUNCTION public.nodkey_is_id(text, integer) SET search_path = pg_catalog, public;
ALTER FUNCTION public.account_owner_lock_account() SET search_path = pg_catalog, public;
ALTER FUNCTION public.pending_effect_guard() SET search_path = pg_catalog, public;
ALTER FUNCTION public.consumed_grant_guard() SET search_path = pg_catalog, public;
ALTER FUNCTION public.broker_clock_monotonic() SET search_path = pg_catalog, public;
ALTER FUNCTION public.pending_effect_requires_consumption() SET search_path = pg_catalog, public;

CREATE SCHEMA nodkey AUTHORIZATION postgres;
REVOKE ALL ON SCHEMA nodkey FROM PUBLIC;
GRANT USAGE ON SCHEMA nodkey TO nodkey_broker, nodkey_payments_adapter, nodkey_shop_operator;

CREATE FUNCTION nodkey.is_id(t text, max_len integer) RETURNS boolean
    LANGUAGE sql IMMUTABLE STRICT SET search_path = ''
    RETURN pg_catalog.octet_length(t) BETWEEN 1 AND max_len AND t OPERATOR(pg_catalog.~) '^[!-~]+$';
CREATE FUNCTION nodkey.is_charge_id(t text) RETURNS boolean
    LANGUAGE sql IMMUTABLE STRICT SET search_path = ''
    RETURN t OPERATOR(pg_catalog.~) '^ch_[A-Za-z0-9]{8,61}$';

-- Trusted order facts (§7.1). Written only by nodkey_shop_operator; the broker reads only.
CREATE TABLE nodkey.orders (
    order_id                bigint PRIMARY KEY CHECK (order_id BETWEEN 1 AND 9007199254740991),
    ten                     text NOT NULL CHECK (nodkey.is_id(ten, 128)),
    owner_sub               text NOT NULL CHECK (nodkey.is_id(owner_sub, 256)),
    charge_id               text NOT NULL UNIQUE CHECK (nodkey.is_charge_id(charge_id)),
    currency                text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    captured_minor          bigint NOT NULL CHECK (captured_minor BETWEEN 1 AND 9007199254740991),
    external_refunded_minor bigint NOT NULL DEFAULT 0
                            CHECK (external_refunded_minor BETWEEN 0 AND captured_minor),
    status                  text NOT NULL CHECK (status IN ('captured','partially_refunded','refunded',
                                                            'disputed','canceled'))
);

-- Broker-owned per-charge state: the T1 lock and the encumbrance counters (PA-15).
CREATE TABLE nodkey.charge_refund_state (
    charge_id       text PRIMARY KEY CHECK (nodkey.is_charge_id(charge_id)),
    succeeded_minor bigint NOT NULL DEFAULT 0 CHECK (succeeded_minor >= 0),
    inflight_minor  bigint NOT NULL DEFAULT 0 CHECK (inflight_minor >= 0),
    unknown_minor   bigint NOT NULL DEFAULT 0 CHECK (unknown_minor >= 0)
);

CREATE FUNCTION nodkey.orders_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = '' AS $$
BEGIN
    IF NEW.order_id IS DISTINCT FROM OLD.order_id OR NEW.charge_id IS DISTINCT FROM OLD.charge_id
       OR NEW.currency IS DISTINCT FROM OLD.currency
       OR NEW.captured_minor IS DISTINCT FROM OLD.captured_minor THEN
        RAISE EXCEPTION 'orders: immutable column changed';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER orders_guard BEFORE UPDATE ON nodkey.orders
    FOR EACH ROW EXECUTE FUNCTION nodkey.orders_guard();

-- An operator change of an order waits for, or blocks, any T1 on its charge (SI-11).
CREATE FUNCTION nodkey.orders_lock_charge() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = '' AS $$
BEGIN
    INSERT INTO nodkey.charge_refund_state (charge_id) VALUES (OLD.charge_id)
        ON CONFLICT (charge_id) DO NOTHING;
    PERFORM 1 FROM nodkey.charge_refund_state WHERE charge_id = OLD.charge_id FOR UPDATE;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION nodkey.orders_lock_charge() FROM PUBLIC;
CREATE TRIGGER orders_lock_charge BEFORE UPDATE OR DELETE ON nodkey.orders
    FOR EACH ROW EXECUTE FUNCTION nodkey.orders_lock_charge();

GRANT SELECT, INSERT ON nodkey.orders TO nodkey_shop_operator;
GRANT UPDATE (ten, owner_sub, external_refunded_minor, status) ON nodkey.orders TO nodkey_shop_operator;
GRANT SELECT ON nodkey.orders TO nodkey_broker;
GRANT SELECT (order_id, ten, owner_sub, charge_id, currency) ON nodkey.orders TO nodkey_payments_adapter;
GRANT SELECT, INSERT ON nodkey.charge_refund_state TO nodkey_broker;
GRANT UPDATE (succeeded_minor, inflight_minor, unknown_minor) ON nodkey.charge_refund_state TO nodkey_broker;

-- One row per decided refund (§7.1, §7.4).
CREATE TABLE nodkey.payment_effect (
    pending_id         bytea PRIMARY KEY REFERENCES public.pending_effect(pending_id),
    order_id           bigint NOT NULL CHECK (order_id BETWEEN 1 AND 9007199254740991),
    charge_id          text NOT NULL CHECK (nodkey.is_charge_id(charge_id)),
    ten                text NOT NULL CHECK (nodkey.is_id(ten, 128)),
    sub                text NOT NULL CHECK (nodkey.is_id(sub, 256)),
    amount_minor       bigint NOT NULL CHECK (amount_minor BETWEEN 1 AND 9007199254740991),
    currency           text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    idem_kid           text NOT NULL CHECK (idem_kid ~ '^[0-9a-f]{16}$'),
    reference          text CHECK (reference ~ '^[A-Za-z0-9_.:-]{1,128}$'),
    state              text NOT NULL CHECK (state IN ('RESERVED','DISPATCHED','SUCCEEDED','FAILED','UNKNOWN')),
    reason             text CHECK (reason IN ('not_dispatched','not_sent','provider_declined',
                                              'lost_response','ambiguous','refused','grant_refused',
                                              'adapter_failure','busy','operator_required',
                                              'key_mismatch')),
    released           boolean NOT NULL DEFAULT false,
    provider_refund_id text CHECK (provider_refund_id ~ '^re_[A-Za-z0-9]{8,64}$'),
    settlement         text CHECK (settlement IN ('pending','succeeded','failed')),
    lease_owner        bytea CHECK (octet_length(lease_owner) = 16),
    lease_until        bigint,
    reserved_at        bigint NOT NULL,
    dispatched_at      bigint,
    resend_deadline    bigint NOT NULL,
    resends            integer NOT NULL DEFAULT 0 CHECK (resends >= 0),
    reconcile_rounds   integer NOT NULL DEFAULT 0 CHECK (reconcile_rounds >= 0),
    next_check_at      bigint,
    resend_stopped     boolean NOT NULL DEFAULT false,
    anomaly            text CHECK (octet_length(anomaly) <= 64),
    CHECK (released = (state = 'FAILED')),
    CHECK ((state = 'SUCCEEDED') = (provider_refund_id IS NOT NULL)),
    CHECK ((state = 'SUCCEEDED') = (settlement IS NOT NULL))
);
CREATE INDEX payment_effect_charge ON nodkey.payment_effect (charge_id);
-- A provider refund id confirms at most one row (BP-08).
CREATE UNIQUE INDEX payment_effect_refund_id ON nodkey.payment_effect (provider_refund_id)
    WHERE provider_refund_id IS NOT NULL;
CREATE INDEX payment_effect_state ON nodkey.payment_effect (state, next_check_at);

CREATE FUNCTION nodkey.payment_effect_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = '' AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'RESERVED' OR NEW.resends <> 0 OR NEW.reconcile_rounds <> 0 THEN
            RAISE EXCEPTION 'payment_effect: rows are created RESERVED';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.pending_id IS DISTINCT FROM OLD.pending_id OR NEW.order_id IS DISTINCT FROM OLD.order_id
       OR NEW.charge_id IS DISTINCT FROM OLD.charge_id OR NEW.ten IS DISTINCT FROM OLD.ten
       OR NEW.sub IS DISTINCT FROM OLD.sub OR NEW.amount_minor IS DISTINCT FROM OLD.amount_minor
       OR NEW.currency IS DISTINCT FROM OLD.currency OR NEW.idem_kid IS DISTINCT FROM OLD.idem_kid
       OR NEW.reserved_at IS DISTINCT FROM OLD.reserved_at
       OR NEW.resend_deadline IS DISTINCT FROM OLD.resend_deadline THEN
        RAISE EXCEPTION 'payment_effect: frozen column changed';
    END IF;
    IF OLD.reference IS NOT NULL AND NEW.reference IS DISTINCT FROM OLD.reference THEN
        RAISE EXCEPTION 'payment_effect: reference is set once';
    END IF;
    IF NEW.resends < OLD.resends OR NEW.reconcile_rounds < OLD.reconcile_rounds
       OR (OLD.resend_stopped AND NOT NEW.resend_stopped) THEN
        RAISE EXCEPTION 'payment_effect: counters never decrease';
    END IF;
    IF OLD.state = 'FAILED' THEN
        RAISE EXCEPTION 'payment_effect: FAILED is final';
    END IF;
    -- SUCCEEDED changes only the settlement: pending -> any; succeeded -> failed (a reversal seen
    -- by the post-success watch, payments-adapter-v1 Draft 3.3 §7.3); failed is final.
    IF OLD.state = 'SUCCEEDED' AND (NEW.state <> 'SUCCEEDED'
         OR NEW.provider_refund_id IS DISTINCT FROM OLD.provider_refund_id
         OR (OLD.settlement <> 'pending' AND NEW.settlement IS DISTINCT FROM OLD.settlement
             AND NOT (OLD.settlement = 'succeeded' AND NEW.settlement = 'failed'))) THEN
        RAISE EXCEPTION 'payment_effect: SUCCEEDED changes only a pending settlement, or succeeded to failed';
    END IF;
    IF NEW.state <> OLD.state AND NOT (
            (OLD.state = 'RESERVED'   AND NEW.state IN ('DISPATCHED','FAILED'))
         OR (OLD.state = 'DISPATCHED' AND NEW.state IN ('SUCCEEDED','FAILED','UNKNOWN'))
         OR (OLD.state = 'UNKNOWN'    AND NEW.state IN ('SUCCEEDED','FAILED'))) THEN
        RAISE EXCEPTION 'payment_effect: transition % -> % not allowed', OLD.state, NEW.state;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER payment_effect_guard BEFORE INSERT OR UPDATE ON nodkey.payment_effect
    FOR EACH ROW EXECUTE FUNCTION nodkey.payment_effect_guard();

-- At commit, the charge's counters equal the sums over its payment_effect rows (PA-15).
-- SECURITY DEFINER (BP-02): a deferred trigger runs at COMMIT as the committing role, which for
-- an operator update of `orders` (through orders_lock_charge) is nodkey_shop_operator, a role
-- without access to either table. The owner is nodkey_payments_checker (SELECT on the two
-- tables only), search_path is empty, EXECUTE is revoked from PUBLIC. Both sides are read in
-- one statement, so one snapshot (BP-06).
CREATE FUNCTION nodkey.charge_counters_check() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = '' AS $$
DECLARE
    r record;
BEGIN
    SELECT s.charge_id IS NOT NULL AS has_row,
           s.succeeded_minor, s.inflight_minor, s.unknown_minor, e.succ, e.infl, e.unk
      INTO r
      FROM (SELECT COALESCE(sum(amount_minor) FILTER (WHERE state = 'SUCCEEDED'), 0) AS succ,
                   COALESCE(sum(amount_minor) FILTER (WHERE state IN ('RESERVED','DISPATCHED')), 0) AS infl,
                   COALESCE(sum(amount_minor) FILTER (WHERE state = 'UNKNOWN'), 0) AS unk
              FROM nodkey.payment_effect WHERE charge_id = NEW.charge_id) e
      LEFT JOIN nodkey.charge_refund_state s ON s.charge_id = NEW.charge_id;
    IF NOT r.has_row THEN
        IF r.succ + r.infl + r.unk <> 0 THEN
            RAISE EXCEPTION 'charge_refund_state: missing row for charge with effects';
        END IF;
        RETURN NULL;
    END IF;
    IF r.succeeded_minor <> r.succ OR r.inflight_minor <> r.infl OR r.unknown_minor <> r.unk THEN
        RAISE EXCEPTION 'charge_refund_state: counters out of step with payment_effect';
    END IF;
    RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION nodkey.charge_counters_check() FROM PUBLIC;
GRANT USAGE ON SCHEMA nodkey TO nodkey_payments_checker;
GRANT SELECT ON nodkey.charge_refund_state, nodkey.payment_effect TO nodkey_payments_checker;
ALTER FUNCTION nodkey.charge_counters_check() OWNER TO nodkey_payments_checker;
-- Fires only on changes that move amounts between states (BP-06): lease, round and settlement
-- bookkeeping does not run the check.
CREATE CONSTRAINT TRIGGER payment_effect_counters AFTER INSERT OR UPDATE OF state, amount_minor, released
    ON nodkey.payment_effect
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION nodkey.charge_counters_check();
CREATE CONSTRAINT TRIGGER charge_refund_state_counters AFTER INSERT OR UPDATE ON nodkey.charge_refund_state
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION nodkey.charge_counters_check();

GRANT SELECT, INSERT ON nodkey.payment_effect TO nodkey_broker;
GRANT UPDATE (reference, state, reason, released, provider_refund_id, settlement, lease_owner,
              lease_until, dispatched_at, resends, reconcile_rounds, next_check_at, resend_stopped,
              anomaly) ON nodkey.payment_effect TO nodkey_broker;

-- Per customer, currency and UTC day (§7.5). Never released.
CREATE TABLE nodkey.refund_budget (
    ten         text NOT NULL CHECK (nodkey.is_id(ten, 128)),
    sub         text NOT NULL CHECK (nodkey.is_id(sub, 256)),
    currency    text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    day         integer NOT NULL CHECK (day >= 0),
    spent_minor bigint NOT NULL DEFAULT 0 CHECK (spent_minor >= 0),
    count       integer NOT NULL DEFAULT 0 CHECK (count >= 0),
    PRIMARY KEY (ten, sub, currency, day)
);
CREATE FUNCTION nodkey.refund_budget_monotonic() RETURNS trigger LANGUAGE plpgsql SET search_path = '' AS $$
BEGIN
    IF NEW.ten IS DISTINCT FROM OLD.ten OR NEW.sub IS DISTINCT FROM OLD.sub
       OR NEW.currency IS DISTINCT FROM OLD.currency OR NEW.day IS DISTINCT FROM OLD.day
       OR NEW.spent_minor < OLD.spent_minor OR NEW.count < OLD.count THEN
        RAISE EXCEPTION 'refund_budget: counters never decrease';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER refund_budget_monotonic BEFORE UPDATE ON nodkey.refund_budget
    FOR EACH ROW EXECUTE FUNCTION nodkey.refund_budget_monotonic();
GRANT SELECT, INSERT ON nodkey.refund_budget TO nodkey_broker;
GRANT UPDATE (spent_minor, count) ON nodkey.refund_budget TO nodkey_broker;

-- Internal reason of a refund denied in T1 (§8); immutable.
CREATE TABLE nodkey.refund_denial (
    pending_id bytea PRIMARY KEY REFERENCES public.pending_effect(pending_id),
    reason     text NOT NULL CHECK (reason IN ('not_owner_or_unknown','currency','order_status',
                                               'order_busy','insufficient_refundable','budget','grant'))
);
GRANT SELECT, INSERT ON nodkey.refund_denial TO nodkey_broker;
SQL
