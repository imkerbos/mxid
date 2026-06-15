-- Known devices for adaptive authentication. A device is identified by a random
-- opaque id stored in the long-lived httpOnly cookie `mxid_device_id` (set after
-- a successful, fully-authenticated login). A row here means "this device is
-- recognised for this user" — its absence on login is the new-device risk signal
-- that conditional access can require MFA for.
--
-- Keyed per (user_id, device_id): the same browser can be known to user A but
-- new to user B, exactly like Okta / Google "remember this device".
CREATE TABLE mxid_known_device (
    id            BIGINT PRIMARY KEY,
    tenant_id     BIGINT NOT NULL REFERENCES mxid_tenant(id),
    user_id       BIGINT NOT NULL REFERENCES mxid_user(id) ON DELETE CASCADE,
    -- Opaque random id mirrored in the mxid_device_id cookie. Not a secret on
    -- its own (recognition still requires a valid user session), so a plain
    -- index lookup is fine.
    device_id     VARCHAR(64) NOT NULL,
    user_agent    VARCHAR(512),
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, device_id)
);

CREATE INDEX idx_known_device_user ON mxid_known_device (user_id);
