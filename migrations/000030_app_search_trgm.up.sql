-- Accelerate ILIKE '%foo%' searches on the app catalogue. With pg_trgm + a
-- GIN trigram index, planner can use the index for substring searches that
-- otherwise force a full table scan. Threshold pays off at ~hundreds of
-- apps per tenant; cost is negligible (small N today).
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Coalesce(description, '') keeps NULL rows indexable. Concatenation is
-- safe because all three columns are text.
CREATE INDEX idx_app_search_trgm
    ON mxid_app USING gin (
        (lower(name) || ' ' || lower(code) || ' ' || lower(coalesce(description, ''))) gin_trgm_ops
    );
