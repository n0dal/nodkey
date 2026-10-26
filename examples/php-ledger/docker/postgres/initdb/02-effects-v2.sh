#!/bin/sh
# Tables for broker protocol v2 (docs/specs/effect-protocol-v2.md Draft 2). Runs once, after
# 01-ledger.sh, as the postgres OS user, over the local socket. Same database as the ledger:
# consumption, pending records and effects commit in one transaction (spec §3.1, §4.4).
#
# Least privilege for nodkey_broker: no DDL, no DELETE anywhere; UPDATE only on the mutable
# columns. Triggers (owned by postgres) enforce immutability and the §3.3 state machine even for
# roles that hold broader privileges.
set -eu
psql -v ON_ERROR_STOP=1 --username postgres --dbname ledger <<'SQL'
-- ID per grant-v1 §5.1: 1..max bytes of 0x21-0x7E. (PostgreSQL regex repetition is capped at 255.)
CREATE FUNCTION nodkey_is_id(t text, max_len integer) RETURNS boolean
    LANGUAGE sql IMMUTABLE STRICT
    RETURN octet_length(t) BETWEEN 1 AND max_len AND t ~ '^[!-~]+$';

-- Which broker protocol owns this database (EP-10: v1 and v2 never share a database).
CREATE TABLE broker_claim (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    protocol  integer NOT NULL CHECK (protocol IN (1, 2)),
    broker_id text NOT NULL CHECK (nodkey_is_id(broker_id, 128))
);
GRANT SELECT, INSERT ON broker_claim TO nodkey_broker;

-- Trusted ownership of ledger accounts (spec §5 approval checks; read grants filter on it).
-- Written by the operator only.
CREATE TABLE account_owner (
    account_id text PRIMARY KEY REFERENCES accounts(id),
    ten        text NOT NULL CHECK (nodkey_is_id(ten, 128)),
    owner_sub  text NOT NULL CHECK (nodkey_is_id(owner_sub, 256))
);
GRANT SELECT ON account_owner TO nodkey_broker;
-- An ownership change waits for the account row lock, so it serializes with any broker
-- transaction that checked ownership under that lock (SI-11).
CREATE FUNCTION account_owner_lock_account() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1 FROM accounts WHERE id = OLD.account_id FOR UPDATE;
    IF TG_OP = 'UPDATE' AND NEW.account_id <> OLD.account_id THEN
        PERFORM 1 FROM accounts WHERE id = NEW.account_id FOR UPDATE;
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER account_owner_lock BEFORE UPDATE OR DELETE ON account_owner
    FOR EACH ROW EXECUTE FUNCTION account_owner_lock_account();

-- Pending effects (spec §3). Immutable except state, state_changed_at, grant (set once at
-- APPROVED), outcome_class and receipt_id (set once in a final state).
CREATE TABLE pending_effect (
    pending_id       bytea PRIMARY KEY CHECK (octet_length(pending_id) = 16),
    broker_id        text NOT NULL CHECK (nodkey_is_id(broker_id, 128)),
    wid              text NOT NULL CHECK (nodkey_is_id(wid, 256)),
    ten              text NOT NULL CHECK (nodkey_is_id(ten, 128)),
    approver_sub     text NOT NULL CHECK (nodkey_is_id(approver_sub, 256)),
    op               text NOT NULL CHECK (op ~ '^[a-z0-9_.]{1,64}$'),
    opv              integer NOT NULL CHECK (opv BETWEEN 1 AND 65535),
    params           text NOT NULL CHECK (octet_length(params) <= 4096),
    param_types      text NOT NULL CHECK (octet_length(param_types) <= 4096),
    display          text NOT NULL CHECK (octet_length(display) <= 1024),
    created_at       bigint NOT NULL CHECK (created_at >= 0),
    expires_at       bigint NOT NULL CHECK (expires_at > created_at),
    digest           bytea NOT NULL CHECK (octet_length(digest) = 32),
    state            text NOT NULL CHECK (state IN ('PENDING','APPROVED','EXECUTING','SUCCEEDED',
                                                    'FAILED','UNKNOWN','DENIED','EXPIRED')),
    state_changed_at bigint NOT NULL,
    grant_bytes      bytea CHECK (octet_length(grant_bytes) BETWEEN 1 AND 2048),
    grant_exp        bigint,
    outcome_class    text CHECK (outcome_class IN ('succeeded','failed','unknown','denied','expired')),
    receipt_id       bytea CHECK (octet_length(receipt_id) = 16),
    CHECK ((grant_bytes IS NULL) = (grant_exp IS NULL)),
    CHECK (state NOT IN ('APPROVED','EXECUTING') OR grant_bytes IS NOT NULL),
    CHECK (state <> 'PENDING' OR (grant_bytes IS NULL AND outcome_class IS NULL AND receipt_id IS NULL)),
    CHECK (state NOT IN ('APPROVED','EXECUTING') OR (outcome_class IS NULL AND receipt_id IS NULL)),
    CHECK (state <> 'UNKNOWN' OR (outcome_class = 'unknown' AND receipt_id IS NULL)),
    CHECK (state <> 'DENIED' OR (outcome_class = 'denied' AND receipt_id IS NOT NULL)),
    CHECK (state <> 'EXPIRED' OR (outcome_class = 'expired' AND receipt_id IS NOT NULL)),
    CHECK (state <> 'SUCCEEDED' OR (outcome_class = 'succeeded' AND receipt_id IS NOT NULL)),
    CHECK (state <> 'FAILED' OR (outcome_class IN ('failed','denied') AND receipt_id IS NOT NULL))
);
CREATE INDEX pending_effect_wid_state ON pending_effect (wid, state, expires_at);
CREATE INDEX pending_effect_state ON pending_effect (state, state_changed_at);
CREATE UNIQUE INDEX pending_effect_receipt ON pending_effect (receipt_id);
-- Render's other_open_on_resource lookup (review BR-06).
CREATE INDEX pending_effect_open_on_from ON pending_effect (op, ten, ((params::jsonb ->> 'from')))
    WHERE state IN ('PENDING','APPROVED','EXECUTING');

CREATE FUNCTION pending_effect_guard() RETURNS trigger LANGUAGE plpgsql AS $$
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
CREATE TRIGGER pending_effect_guard BEFORE INSERT OR UPDATE ON pending_effect
    FOR EACH ROW EXECUTE FUNCTION pending_effect_guard();
GRANT SELECT, INSERT ON pending_effect TO nodkey_broker;
GRANT UPDATE (state, state_changed_at, grant_bytes, grant_exp, outcome_class, receipt_id)
    ON pending_effect TO nodkey_broker;

-- Write-grant consumption (grant-v1 §7.3 W10; ADR-0006 Amendment 1). One row per (iss, jti);
-- outcome moves once from PENDING to ACCEPT or DENIED. Rows are pruned by the operator only,
-- never before exp + skew + margin (grant-v1 §7.6).
CREATE TABLE consumed_grant (
    iss          text NOT NULL CHECK (nodkey_is_id(iss, 128)),
    jti          bytea NOT NULL CHECK (octet_length(jti) = 16),
    exp          bigint NOT NULL,
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    outcome      text NOT NULL CHECK (outcome IN ('PENDING','ACCEPT','DENIED')),
    PRIMARY KEY (iss, jti)
);
CREATE INDEX consumed_grant_jti ON consumed_grant (jti);
CREATE FUNCTION consumed_grant_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.outcome <> 'PENDING' THEN
            RAISE EXCEPTION 'consumed_grant: rows are inserted PENDING';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.iss IS DISTINCT FROM OLD.iss OR NEW.jti IS DISTINCT FROM OLD.jti
       OR NEW.exp IS DISTINCT FROM OLD.exp OR NEW.request_hash IS DISTINCT FROM OLD.request_hash
       OR OLD.outcome <> 'PENDING' OR NEW.outcome NOT IN ('ACCEPT','DENIED') THEN
        RAISE EXCEPTION 'consumed_grant: only PENDING -> ACCEPT|DENIED is allowed';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER consumed_grant_guard BEFORE INSERT OR UPDATE ON consumed_grant
    FOR EACH ROW EXECUTE FUNCTION consumed_grant_guard();
GRANT SELECT, INSERT ON consumed_grant TO nodkey_broker;
GRANT UPDATE (outcome) ON consumed_grant TO nodkey_broker;

-- Defense in depth (review BR-08): leaving APPROVED towards an executed state requires the
-- record's grant (jti = pending_id) to be consumed with a matching decision, checked at commit:
-- SUCCEEDED needs ACCEPT; FAILED needs DENIED or ACCEPT; EXECUTING needs a consumption row.
CREATE FUNCTION pending_effect_requires_consumption() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.state = 'APPROVED' AND NEW.state IN ('SUCCEEDED','FAILED','EXECUTING') AND NOT EXISTS (
        SELECT 1 FROM consumed_grant c WHERE c.jti = NEW.pending_id AND (
               (NEW.state = 'SUCCEEDED' AND c.outcome = 'ACCEPT')
            OR (NEW.state = 'FAILED' AND c.outcome IN ('DENIED','ACCEPT'))
            OR (NEW.state = 'EXECUTING'))) THEN
        RAISE EXCEPTION 'pending_effect: % -> % without a consumed grant', OLD.state, NEW.state;
    END IF;
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER pending_effect_requires_consumption
    AFTER UPDATE ON pending_effect DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION pending_effect_requires_consumption();

-- Revocation (ADR-0006 §6, grant-v1 §8.6): grants with iat < before are revoked for the scope
-- (ten), (ten, wid) or (ten, sub). Written by the operator (and later the gateway's revoke
-- socket); the broker only reads it.
CREATE TABLE revoked_before (
    id     bigserial PRIMARY KEY,
    ten    text NOT NULL CHECK (nodkey_is_id(ten, 128)),
    wid    text CHECK (nodkey_is_id(wid, 256)),
    sub    text CHECK (nodkey_is_id(sub, 256)),
    before bigint NOT NULL CHECK (before >= 0),
    CHECK (wid IS NULL OR sub IS NULL)
);
CREATE INDEX revoked_before_ten ON revoked_before (ten);
GRANT SELECT ON revoked_before TO nodkey_broker;

-- Persisted clock high-water mark (grant-v1 §7.6, ADR-0006 §8). Never decreases.
CREATE TABLE broker_clock (
    broker_id text PRIMARY KEY CHECK (nodkey_is_id(broker_id, 128)),
    mark      bigint NOT NULL CHECK (mark >= 0)
);
CREATE FUNCTION broker_clock_monotonic() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.broker_id IS DISTINCT FROM OLD.broker_id OR NEW.mark < OLD.mark THEN
        RAISE EXCEPTION 'broker_clock: the mark never decreases';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER broker_clock_monotonic BEFORE UPDATE ON broker_clock
    FOR EACH ROW EXECUTE FUNCTION broker_clock_monotonic();
GRANT SELECT, INSERT ON broker_clock TO nodkey_broker;
GRANT UPDATE (mark) ON broker_clock TO nodkey_broker;
SQL
