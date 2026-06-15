-- Move uploaded binary assets (app icons, brand logos) out of local disk into
-- the database. The backend then holds NO local file state: under k8s there is
-- no PVC / ReadWriteOnce volume to dead-lock a second replica, under docker an
-- icon survives container restarts (the old data/uploads dir was never even
-- volume-mounted), and every replica serves identical bytes.
--
-- Assets are small (<= 2 MB) and rarely change. The bytes live in a bytea column
-- (PostgreSQL TOASTs anything > 2 KB out-of-line + compressed, so the main heap
-- stays slim) and the serve path strong-caches them, keeping DB load negligible.
--
-- NOT tenant-scoped: icons are public assets fetched by the pre-auth login page
-- (<img> with no cookie), so the serve path runs without a tenant scope. The id
-- is a non-enumerable Snowflake, so by-id fetch needs no tenant filter; tenant_id
-- is metadata only (cleanup / audit).
CREATE TABLE IF NOT EXISTS mxid_upload (
    id         BIGINT       PRIMARY KEY,
    tenant_id  BIGINT       NOT NULL DEFAULT 0,
    category   VARCHAR(32)  NOT NULL,
    mime       VARCHAR(64)  NOT NULL,
    ext        VARCHAR(8)   NOT NULL,
    size       INTEGER      NOT NULL,
    data       BYTEA        NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT now()
);
