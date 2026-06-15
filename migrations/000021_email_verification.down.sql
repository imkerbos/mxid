ALTER TABLE mxid_user
    DROP COLUMN IF EXISTS email_verified_at,
    DROP COLUMN IF EXISTS email_verified;
