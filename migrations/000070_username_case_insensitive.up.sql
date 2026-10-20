-- Usernames are unique per tenant WITHOUT regard to case.
--
-- `alice` and `Alice` are one person, so they must be one account. The
-- original UNIQUE(tenant_id, username) is case-SENSITIVE, which let both exist
-- — and once both exist, every lookup has to decide which one it meant. The
-- answer is to make the state unreachable rather than to handle it.
--
-- NOTE: this file claimed to mirror the existing constraint's scope and did
-- not — idx_user_tenant_username is partial (WHERE deleted_at IS NULL) since
-- 000047, and the index created below is not, so it stopped soft-deleted
-- usernames from being reused. 000071 corrects the scope. Kept as it ran
-- rather than edited, because it is already applied where this is read.
--
-- This CREATE fails if any tenant already holds two usernames differing only
-- by case. That is the intended behaviour: such a pair is a question only an
-- administrator can answer (which of the two is the person?), and answering it
-- by truncating one of them here would delete an account in a migration.
CREATE UNIQUE INDEX IF NOT EXISTS uq_mxid_user_tenant_username_lower
    ON mxid_user (tenant_id, lower(username));
