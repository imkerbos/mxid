-- is_builtin marks platform-seeded accounts that must not be federated to an
-- external IdP. The bootstrap `admin` (id=1) is the canonical break-glass
-- account: it can only authenticate locally (password + MFA), never via Lark /
-- Teams / etc. Console external-IdP login refuses any is_builtin user, so the
-- emergency admin path stays independent of any IdP being reachable.
ALTER TABLE mxid_user ADD COLUMN is_builtin BOOLEAN NOT NULL DEFAULT false;

-- Seeded admin is the built-in break-glass account.
UPDATE mxid_user SET is_builtin = true WHERE id = 1;

COMMENT ON COLUMN mxid_user.is_builtin IS 'platform-seeded break-glass account; cannot bind/login via external IdP';
