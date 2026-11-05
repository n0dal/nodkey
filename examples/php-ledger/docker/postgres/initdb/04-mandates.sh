#!/bin/sh
# SPDX-FileCopyrightText: 2026 n0dal
# SPDX-License-Identifier: Apache-2.0
#
# Mandates and agent operations (docs/specs/agent-interface-v1.md Draft 2 §3, §4; effect-protocol-v2
# Draft 4 §12; ADR-0006 Amendment 3). Runs once after 01–03, as the postgres OS user. Additive only:
# Demo 1, Demo 2 and Demo P do not mount this file and the broker touches none of these objects
# unless its workloads file configures `support_principals` (broker README, "Mandates").
#
# - nodkey.customers: operator-written trusted customer facts (email = message recipient).
# - public.pending_effect.awaiting: set once at creation, then only mandate -> confirmation.
# - public.mandate: the broker's mandate rows; terms immutable, counters never decrease.
# - public.mandate_use: which records received an accepted cfm = 2 grant under which mandate (C6).
# - public.outbox: the internal effect of messages.send, read by the simulated mail sink.
set -eu
psql -v ON_ERROR_STOP=1 --username postgres --dbname ledger <<'SQL'
-- Trusted customer facts (AI §3: `customers.email`). Written only by the shop operator.
CREATE TABLE nodkey.customers (
    ten   text NOT NULL CHECK (nodkey.is_id(ten, 128)),
    sub   text NOT NULL CHECK (nodkey.is_id(sub, 64)),
    -- An ID-grammar address: no space, so the reserved unresolved value " " never matches.
    email text NOT NULL CHECK (nodkey.is_id(email, 256)),
    PRIMARY KEY (ten, sub)
);
GRANT SELECT ON nodkey.customers TO nodkey_broker;
GRANT SELECT, INSERT ON nodkey.customers TO nodkey_shop_operator;
GRANT UPDATE (email) ON nodkey.customers TO nodkey_shop_operator;

-- effect-protocol-v2 §12.1.
ALTER TABLE public.pending_effect ADD COLUMN awaiting text
    CHECK (awaiting IN ('mandate', 'confirmation'));
-- The §3.3 guard of 02-effects-v2.sh, unchanged except that a PENDING row may change `awaiting`
-- alone (mandate -> confirmation, checked by the trigger below). Replaces the 02 function body;
-- the search_path pin of 03-payments.sh is restated.
CREATE OR REPLACE FUNCTION public.pending_effect_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, public AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'PENDING' THEN
            RAISE EXCEPTION 'pending_effect: records are created PENDING';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.pending_id IS DISTINCT FROM OLD.pending_id OR NEW.broker_id IS DISTINCT FROM OLD.broker_id
       OR NEW.wid IS DISTINCT FROM OLD.wid OR NEW.ten IS DISTINCT FROM OLD.ten
       OR NEW.approver_sub IS DISTINCT FROM OLD.approver_sub OR NEW.op IS DISTINCT FROM OLD.op
       OR NEW.opv IS DISTINCT FROM OLD.opv OR NEW.params IS DISTINCT FROM OLD.params
       OR NEW.param_types IS DISTINCT FROM OLD.param_types OR NEW.display IS DISTINCT FROM OLD.display
       OR NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
       OR NEW.digest IS DISTINCT FROM OLD.digest THEN
        RAISE EXCEPTION 'pending_effect: immutable column changed';
    END IF;
    IF OLD.grant_bytes IS NOT NULL AND (NEW.grant_bytes IS DISTINCT FROM OLD.grant_bytes
                                        OR NEW.grant_exp IS DISTINCT FROM OLD.grant_exp) THEN
        RAISE EXCEPTION 'pending_effect: grant is set once';
    END IF;
    IF OLD.receipt_id IS NOT NULL AND NEW.receipt_id IS DISTINCT FROM OLD.receipt_id THEN
        RAISE EXCEPTION 'pending_effect: receipt_id is set once';
    END IF;
    IF OLD.outcome_class IS NOT NULL AND OLD.state <> 'UNKNOWN'
       AND NEW.outcome_class IS DISTINCT FROM OLD.outcome_class THEN
        RAISE EXCEPTION 'pending_effect: outcome is set once';
    END IF;
    -- effect-protocol-v2 §12.1: only `awaiting` changes on a PENDING row.
    IF OLD.state = 'PENDING' AND NEW.state = 'PENDING'
       AND NEW.state_changed_at IS NOT DISTINCT FROM OLD.state_changed_at
       AND NEW.grant_bytes IS NULL AND NEW.grant_exp IS NULL
       AND NEW.outcome_class IS NULL AND NEW.receipt_id IS NULL
       AND NEW.awaiting IS DISTINCT FROM OLD.awaiting THEN
        RETURN NEW;
    END IF;
    -- Spec §3.3: there are no other transitions.
    IF NOT ((OLD.state = 'PENDING'   AND NEW.state IN ('DENIED','EXPIRED','APPROVED'))
         OR (OLD.state = 'APPROVED'  AND NEW.state IN ('SUCCEEDED','FAILED','EXECUTING','EXPIRED'))
         OR (OLD.state = 'EXECUTING' AND NEW.state IN ('SUCCEEDED','FAILED','UNKNOWN'))
         OR (OLD.state = 'UNKNOWN'   AND NEW.state IN ('SUCCEEDED','FAILED'))) THEN
        RAISE EXCEPTION 'pending_effect: transition % -> % not allowed', OLD.state, NEW.state;
    END IF;
    IF NEW.state = 'APPROVED' AND OLD.grant_bytes IS NOT NULL THEN
        RAISE EXCEPTION 'pending_effect: grant already stored';
    END IF;
    RETURN NEW;
END $$;
CREATE FUNCTION public.pending_effect_awaiting_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, public AS $$
BEGIN
    IF NEW.awaiting IS DISTINCT FROM OLD.awaiting
       AND NOT (OLD.awaiting = 'mandate' AND NEW.awaiting = 'confirmation') THEN
        RAISE EXCEPTION 'pending_effect: awaiting changes only mandate -> confirmation';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER pending_effect_awaiting_guard BEFORE UPDATE ON public.pending_effect
    FOR EACH ROW EXECUTE FUNCTION public.pending_effect_awaiting_guard();
GRANT UPDATE (awaiting) ON public.pending_effect TO nodkey_broker;
CREATE INDEX pending_effect_mandate_candidates ON public.pending_effect (created_at)
    WHERE state = 'PENDING' AND awaiting = 'mandate';

-- AI §4.2 step 4. mid = the template record's pending_id (= the mandate grant's jti).
CREATE TABLE public.mandate (
    mid                       bytea PRIMARY KEY REFERENCES public.pending_effect(pending_id)
                              CHECK (octet_length(mid) = 16),
    wid                       text NOT NULL CHECK (nodkey_is_id(wid, 256)),
    ten                       text NOT NULL CHECK (nodkey_is_id(ten, 128)),
    sub                       text NOT NULL CHECK (nodkey_is_id(sub, 256)),
    customer_sub              text NOT NULL CHECK (nodkey_is_id(customer_sub, 64)),
    customer_email            text NOT NULL CHECK (nodkey_is_id(customer_email, 256)),
    currency                  text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    refund_max_count          bigint NOT NULL CHECK (refund_max_count >= 0),
    refund_max_per_call_minor bigint NOT NULL CHECK (refund_max_per_call_minor >= 0),
    refund_max_total_minor    bigint NOT NULL CHECK (refund_max_total_minor >= refund_max_per_call_minor),
    message_max_count         bigint NOT NULL CHECK (message_max_count >= 0),
    nbf                       bigint NOT NULL CHECK (nbf >= 0),
    exp                       bigint NOT NULL CHECK (exp > nbf AND exp - nbf <= 3600),
    cfg                       bytea NOT NULL CHECK (octet_length(cfg) = 32),
    state                     text NOT NULL CHECK (state IN ('active', 'revoked', 'expired')),
    state_changed_at          bigint NOT NULL,
    refund_count              bigint NOT NULL DEFAULT 0
                              CHECK (refund_count BETWEEN 0 AND refund_max_count),
    refund_total_minor        bigint NOT NULL DEFAULT 0
                              CHECK (refund_total_minor BETWEEN 0 AND refund_max_total_minor),
    message_count             bigint NOT NULL DEFAULT 0
                              CHECK (message_count BETWEEN 0 AND message_max_count)
);
-- At most one active mandate per (workload, principal) (AI-04). The broker also serializes
-- activation on an advisory lock and expires inactive rows first.
CREATE UNIQUE INDEX mandate_one_active ON public.mandate (wid, ten, sub) WHERE state = 'active';
CREATE INDEX mandate_subject ON public.mandate (ten, sub);
CREATE FUNCTION public.mandate_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, public AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'active' OR NEW.refund_count <> 0 OR NEW.refund_total_minor <> 0
           OR NEW.message_count <> 0 THEN
            RAISE EXCEPTION 'mandate: rows are created active with zero counters';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.mid IS DISTINCT FROM OLD.mid OR NEW.wid IS DISTINCT FROM OLD.wid
       OR NEW.ten IS DISTINCT FROM OLD.ten OR NEW.sub IS DISTINCT FROM OLD.sub
       OR NEW.customer_sub IS DISTINCT FROM OLD.customer_sub
       OR NEW.customer_email IS DISTINCT FROM OLD.customer_email
       OR NEW.currency IS DISTINCT FROM OLD.currency
       OR NEW.refund_max_count IS DISTINCT FROM OLD.refund_max_count
       OR NEW.refund_max_per_call_minor IS DISTINCT FROM OLD.refund_max_per_call_minor
       OR NEW.refund_max_total_minor IS DISTINCT FROM OLD.refund_max_total_minor
       OR NEW.message_max_count IS DISTINCT FROM OLD.message_max_count
       OR NEW.nbf IS DISTINCT FROM OLD.nbf OR NEW.exp IS DISTINCT FROM OLD.exp
       OR NEW.cfg IS DISTINCT FROM OLD.cfg THEN
        RAISE EXCEPTION 'mandate: terms are immutable';
    END IF;
    IF NEW.refund_count < OLD.refund_count OR NEW.refund_total_minor < OLD.refund_total_minor
       OR NEW.message_count < OLD.message_count THEN
        RAISE EXCEPTION 'mandate: counters never decrease';
    END IF;
    IF NEW.state IS DISTINCT FROM OLD.state
       AND NOT (OLD.state = 'active' AND NEW.state IN ('revoked', 'expired')) THEN
        RAISE EXCEPTION 'mandate: state % -> % not allowed', OLD.state, NEW.state;
    END IF;
    IF OLD.state <> 'active' AND (NEW.refund_count <> OLD.refund_count
       OR NEW.refund_total_minor <> OLD.refund_total_minor OR NEW.message_count <> OLD.message_count) THEN
        RAISE EXCEPTION 'mandate: counters of an inactive mandate never change';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER mandate_guard BEFORE INSERT OR UPDATE ON public.mandate
    FOR EACH ROW EXECUTE FUNCTION public.mandate_guard();
GRANT SELECT, INSERT ON public.mandate TO nodkey_broker;
GRANT UPDATE (state, state_changed_at, refund_count, refund_total_minor, message_count)
    ON public.mandate TO nodkey_broker;

-- One row per record whose cfm = 2 grant the broker accepted (AI §4.3 C6; page line §12.6).
CREATE TABLE public.mandate_use (
    pending_id bytea PRIMARY KEY REFERENCES public.pending_effect(pending_id),
    mid        bytea NOT NULL REFERENCES public.mandate(mid),
    op         text NOT NULL CHECK (op ~ '^[a-z0-9_.]{1,64}$'),
    params     text NOT NULL CHECK (octet_length(params) <= 4096)
);
CREATE INDEX mandate_use_mid ON public.mandate_use (mid, op);
GRANT SELECT, INSERT ON public.mandate_use TO nodkey_broker;

-- messages.send (AI §3): one immutable row per executed message; message_id = pending_id.
CREATE TABLE public.outbox (
    message_id bytea PRIMARY KEY REFERENCES public.pending_effect(pending_id),
    ten        text NOT NULL CHECK (nodkey_is_id(ten, 128)),
    "to"       text NOT NULL CHECK (nodkey_is_id("to", 256)),
    body       text NOT NULL CHECK (octet_length(body) <= 256 AND body ~ '^[ -~]*$'),
    created_at bigint NOT NULL CHECK (created_at >= 0)
);
GRANT SELECT, INSERT ON public.outbox TO nodkey_broker;
SQL
