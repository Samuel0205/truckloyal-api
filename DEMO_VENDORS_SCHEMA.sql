-- ═══════════════════════════════════════════════════════════
--  Demo / internal vendor accounts  ·  Supabase SQL editor
-- ═══════════════════════════════════════════════════════════
--  Run each block on its own. If the editor adds a stray ")"
--  and you get "syntax error at or near )", delete it and
--  re-run that block.
--
--  Additive only. Nothing is dropped, and the app works before,
--  during, and after the run.
-- ═══════════════════════════════════════════════════════════


-- 1 ── Flag a vendor as a demo / internal account.
--      Demo vendors keep working exactly as they do now — they
--      are just left out of the admin dashboard's revenue and
--      vendor counts, so those numbers mean real customers.
ALTER TABLE vendors ADD COLUMN IF NOT EXISTS is_demo BOOLEAN DEFAULT FALSE;


-- 2 ── Backfill: everyone existing is a real account by default.
UPDATE vendors SET is_demo = FALSE WHERE is_demo IS NULL;


-- ═══════════════════════════════════════════════════════════
--  3 ── Mark your own two demo trucks.
--       You can also do this from /admin (Vendors -> View ->
--       "Mark as demo"), which is easier and needs no SQL.
--       Edit the emails below if yours differ.
-- ═══════════════════════════════════════════════════════════
UPDATE vendors
SET is_demo = TRUE
WHERE email IN ('mccunesamuel1@gmail.com', 'flavoronwheels26@gmail.com');


-- ── Verify (optional) ──────────────────────────────────────
-- SELECT truck_name, email, is_demo, plan_active, trial_ends_at
-- FROM vendors ORDER BY created_at;
