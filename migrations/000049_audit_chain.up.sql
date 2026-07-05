-- migrations/000049_audit_chain.up.sql
-- Tamper-proof audit Phase 1. Producers INSERT into mxid_audit_pending inside
-- their own state-change transaction (atomic capture). A single ordered chainer
-- drains pending FIFO, computes the HMAC hash chain per (tenant_id, chain_class),
-- and INSERTs into mxid_audit_entry, which is append-only for every role.
-- mxid_audit_chain_head holds each chain's tip; it is the only mutable state.

CREATE TABLE IF NOT EXISTS mxid_audit_pending (
    id            BIGINT       PRIMARY KEY,
    tenant_id     BIGINT       NOT NULL DEFAULT 0,
    chain_class   VARCHAR(16)  NOT NULL,
    actor_id      BIGINT       NOT NULL DEFAULT 0,
    actor_type    VARCHAR(16)  NOT NULL DEFAULT '',
    event_type    VARCHAR(64)  NOT NULL,
    resource_type VARCHAR(32)  NOT NULL DEFAULT '',
    resource_id   BIGINT       NOT NULL DEFAULT 0,
    before        JSONB,
    after         JSONB,
    ip            VARCHAR(64)  NOT NULL DEFAULT '',
    user_agent    VARCHAR(512) NOT NULL DEFAULT '',
    session_id    VARCHAR(128) NOT NULL DEFAULT '',
    detail        JSONB        NOT NULL DEFAULT '{}',
    occurred_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- FIFO drain order for the chainer.
CREATE INDEX IF NOT EXISTS idx_audit_pending_id ON mxid_audit_pending(id);

CREATE TABLE IF NOT EXISTS mxid_audit_entry (
    tenant_id   BIGINT       NOT NULL,
    chain_class VARCHAR(16)  NOT NULL,
    seq         BIGINT       NOT NULL,
    prev_hash   BYTEA        NOT NULL,
    entry_hash  BYTEA        NOT NULL,
    key_id      VARCHAR(64)  NOT NULL DEFAULT 'default',
    payload     JSONB        NOT NULL,
    imported    BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, chain_class, seq)
);

CREATE TABLE IF NOT EXISTS mxid_audit_chain_head (
    tenant_id       BIGINT      NOT NULL,
    chain_class     VARCHAR(16) NOT NULL,
    last_seq        BIGINT      NOT NULL DEFAULT 0,
    last_entry_hash BYTEA       NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, chain_class)
);
