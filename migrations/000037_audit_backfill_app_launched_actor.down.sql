-- No-op. This was a one-way data backfill of actor_name from the user table.
-- We can't safely tell which rows were NULL before the backfill versus which
-- now legitimately hold a name, so reverting would risk wiping valid data.
-- Audit rows are append-only history; leave the recovered names in place.
SELECT 1;
