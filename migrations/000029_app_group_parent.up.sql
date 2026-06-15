-- App groups can now nest, so the portal sidebar can render a tree.
-- parent_id is nullable: the root level is "no parent". We use ON DELETE
-- SET NULL so deleting an intermediate group lifts the orphan children up
-- one level — destroying a whole subtree silently is too surprising.
ALTER TABLE mxid_app_group
    ADD COLUMN parent_id BIGINT NULL
    REFERENCES mxid_app_group(id) ON DELETE SET NULL;

CREATE INDEX idx_app_group_parent ON mxid_app_group (parent_id);
