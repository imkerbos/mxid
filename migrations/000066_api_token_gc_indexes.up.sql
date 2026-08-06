-- Index the columns the API-token garbage collector filters on.
--
-- The GC runs periodically and deletes on expiry or revocation:
--
--   DELETE FROM mxid_api_token
--   WHERE (expires_at IS NOT NULL AND expires_at < now())
--      OR (revoked_at IS NOT NULL AND revoked_at < now())
--
-- mxid_api_token carried indexes on user_id and prefix only, so neither branch
-- of that OR had one and the delete was a sequential scan. It went unnoticed
-- because the table is empty on a new install — the 200ms it logged there was
-- connection warm-up, not the scan — but the cost grows with every token ever
-- issued, and the GC runs on a schedule against a live connection pool.
--
-- Partial indexes rather than plain ones: the predicate mirrors the query's own
-- NOT NULL test, so the index holds only rows the GC can ever match. In the
-- normal case — tokens that are neither expired nor revoked — nothing is
-- indexed at all, which keeps the write cost of issuing a token unchanged.
--
-- Postgres can still choose a sequential scan for the OR as a whole; splitting
-- the statement in two is what lets it use these per branch. That change lives
-- in the GC itself, and is pointless without the indexes, so both land here.
CREATE INDEX IF NOT EXISTS idx_api_token_expires
    ON mxid_api_token (expires_at) WHERE expires_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_api_token_revoked
    ON mxid_api_token (revoked_at) WHERE revoked_at IS NOT NULL;
