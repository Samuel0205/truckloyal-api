-- ═══════════════════════════════════════════════════════════
--  Website analytics · page_views
--  Supabase → SQL Editor → paste ALL of this → Run
-- ═══════════════════════════════════════════════════════════
--  This is ONE block on purpose. The earlier version was split
--  into five, and the last of them (NOTIFY) succeeds even when
--  the CREATE TABLE above it failed — so the editor said
--  "Success" while nothing had been created.
--
--  Safe to run as many times as you like.
-- ═══════════════════════════════════════════════════════════

-- 1 ── The table. No cookies, no IP, no personal data: which page,
--      an anonymous random id so repeat loads can be de-duplicated,
--      and where the visitor came from.
CREATE TABLE IF NOT EXISTS public.page_views (
  id         BIGSERIAL PRIMARY KEY,
  path       TEXT NOT NULL DEFAULT '/',
  visitor    TEXT,
  referrer   TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2 ── Indexes for the dashboard's date filter and unique-visitor count.
CREATE INDEX IF NOT EXISTS page_views_created_at_idx ON public.page_views (created_at DESC);
CREATE INDEX IF NOT EXISTS page_views_visitor_idx    ON public.page_views (visitor);

-- 3 ── Match every other table in this database.
--      An earlier version of this file switched RLS on. Nothing else
--      here uses RLS — the app talks to Postgres with the service key
--      and every table relies on that — so page_views was the odd one
--      out, and the only one that failed. It holds no personal data.
ALTER TABLE public.page_views DISABLE ROW LEVEL SECURITY;

-- 4 ── Privileges. A table made in the SQL editor does not always
--      inherit the grants the API roles need, and PostgREST reports a
--      table it cannot touch as "not found in the schema cache"
--      (PGRST205) — which reads like the table is missing when it is
--      really a permissions problem.
GRANT ALL ON TABLE    public.page_views        TO postgres, service_role, anon, authenticated;
GRANT ALL ON SEQUENCE public.page_views_id_seq TO postgres, service_role, anon, authenticated;

-- 5 ── Tell the API the schema changed.
NOTIFY pgrst, 'reload schema';

-- 6 ── Proof. This returns a row only if the table really exists —
--      unlike NOTIFY, which succeeds no matter what.
SELECT
  'page_views EXISTS'                                   AS status,
  (SELECT COUNT(*) FROM public.page_views)              AS rows_so_far,
  (SELECT relrowsecurity FROM pg_class
     WHERE oid = 'public.page_views'::regclass)         AS rls_enabled,
  has_table_privilege('service_role','public.page_views','INSERT') AS service_can_insert;

-- ── If the row above comes back, you are done. ─────────────
--  Load foodtruckrewards.com in another tab, then run:
--    SELECT path, referrer, created_at FROM public.page_views
--    ORDER BY created_at DESC LIMIT 20;
--  Then reload /admin — the red banner should be gone.
