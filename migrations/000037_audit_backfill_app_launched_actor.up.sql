-- Backfill ActorName for historical app.launched audit rows.
--
-- Before the launch publisher denormalized the username, handleAppLaunched
-- only stored actor_id, leaving actor_name NULL — so the console "操作人"
-- column rendered a dash. The user_id was never lost, so the name is
-- recoverable by joining the user table.
--
-- Scoped to event_type = 'app.launched' to avoid touching rows whose blank
-- actor_name is legitimate (system / anonymous events). Users deleted since
-- the launch stay NULL (no row to join) — acceptable, actor_id still records
-- who acted.
UPDATE mxid_audit_log a
SET actor_name = u.username
FROM mxid_user u
WHERE a.actor_id = u.id
  AND a.event_type = 'app.launched'
  AND a.actor_name IS NULL;
