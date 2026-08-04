-- ═══════════════════════════════════════════════════════════
--  Per-truck timezone
--  Supabase → SQL Editor → paste ALL of this → Run
-- ═══════════════════════════════════════════════════════════
--  Until this runs, every truck's "today" is decided in the
--  server's timezone (America/New_York by default). For a truck
--  outside Eastern that means:
--    · the posted location clears in the middle of their evening
--    · the schedule flips to tomorrow's stop while they're still out
--    · a customer can earn "once a day" points twice in one day
--
--  One block, safe to run repeatedly, and it ends with proof.
-- ═══════════════════════════════════════════════════════════

-- 1 ── IANA timezone name for this truck, e.g. America/Los_Angeles.
--      NULL means "use the server default", so existing trucks keep
--      behaving exactly as they do today until they set one.
ALTER TABLE public.vendors ADD COLUMN IF NOT EXISTS timezone TEXT;

-- 2 ── Make sure the API can see and write the new column.
GRANT ALL ON TABLE public.vendors TO postgres, service_role, anon, authenticated;

-- 3 ── PostgREST caches the schema; without this the app keeps
--      reporting the column as missing.
NOTIFY pgrst, 'reload schema';

-- 4 ── Proof. Returns a row only if the column really exists.
SELECT 'vendors.timezone EXISTS' AS status,
       COUNT(*)                   AS trucks,
       COUNT(timezone)            AS with_timezone_set
FROM public.vendors;

-- ── Optional: set one manually if a truck ever gets it wrong ──
-- UPDATE public.vendors SET timezone = 'America/Chicago'
-- WHERE email = 'them@theirtruck.com';
--
-- Common US zones:
--   America/New_York   America/Chicago   America/Denver
--   America/Phoenix    America/Los_Angeles
--   America/Anchorage  Pacific/Honolulu
