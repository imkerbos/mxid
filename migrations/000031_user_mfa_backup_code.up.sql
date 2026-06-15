-- One-time MFA recovery codes. Generated as 10 plaintext codes at TOTP
-- enroll time (or explicit regenerate), then ONLY the bcrypt hashes
-- persist. The plaintext is shown to the user once — typical industry
-- shape (GitHub, Auth0, AWS).
--
-- used_at NULL = unused; once consumed during login it's stamped and the
-- row is locked out (one-shot semantics enforced at the service layer).
CREATE TABLE mxid_user_mfa_backup_code (
    id          BIGINT PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES mxid_user(id) ON DELETE CASCADE,
    code_hash   VARCHAR(120) NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_user_mfa_backup_code_user
    ON mxid_user_mfa_backup_code (user_id, used_at);
