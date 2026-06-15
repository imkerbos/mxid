-- Email verification flag.
--
-- New column defaults to FALSE so freshly created users start unverified
-- and must complete the verification flow before the email can be used
-- for password reset / security-sensitive operations. Existing rows are
-- intentionally left FALSE too — admins / users will see the badge and
-- can resend verification.
ALTER TABLE mxid_user
    ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMPTZ;

-- Existing admin (seeded with no email) should remain false. Pre-existing
-- users with email but no verification state ought to be considered
-- unverified — safer default; admin can mass-verify if needed.
