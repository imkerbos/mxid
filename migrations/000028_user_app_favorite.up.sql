-- Per-user app favorites surfaced as a pinned section on the portal home.
-- Order is user-driven (drag-and-drop on the portal) — sort_order is bumped
-- on reorder; cheaper than maintaining a doubly-linked list and good enough
-- for typical N≤50 favorites per user.
CREATE TABLE mxid_user_app_favorite (
    id          BIGINT PRIMARY KEY,
    tenant_id   BIGINT NOT NULL REFERENCES mxid_tenant(id),
    user_id     BIGINT NOT NULL REFERENCES mxid_user(id) ON DELETE CASCADE,
    app_id      BIGINT NOT NULL REFERENCES mxid_app(id) ON DELETE CASCADE,
    sort_order  INTEGER NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT mxid_user_app_favorite_uniq UNIQUE (user_id, app_id)
);

CREATE INDEX idx_user_app_favorite_user
    ON mxid_user_app_favorite (user_id, sort_order, created_at);
