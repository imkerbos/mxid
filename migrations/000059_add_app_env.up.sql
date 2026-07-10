-- Add a per-app environment label (qa / uat / prod / staging / dev / custom).
--
-- Modelled as a free-form nullable VARCHAR rather than a DB enum: the console
-- offers presets but admins may type a custom value (canary / dr / ...), and we
-- do not want a schema migration every time a new environment name appears. The
-- app group stays the "project" axis; env is an orthogonal per-app tag the
-- portal groups by within a section. NULL/empty = "unlabelled".
ALTER TABLE mxid_app ADD COLUMN IF NOT EXISTS env VARCHAR(64);
