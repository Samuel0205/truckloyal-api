-- ═══════════════════════════════════════════════════════════
--  Site feedback / reviews · site_feedback
--  Supabase → SQL Editor → paste ALL of this → Run
-- ═══════════════════════════════════════════════════════════
--  Feedback left on the website and inside the app — "we're new
--  and always improving, tell us how we're doing". It lands in
--  the Feedback tab of /admin.
--
--  NOT the same thing as the existing `reviews` table. That one
--  is a customer reviewing a food truck. This one is anybody
--  reviewing Food Truck Rewards itself.
--
--  This is ONE block on purpose, and it ends with proof — NOTIFY
--  succeeds even when the CREATE TABLE above it failed, so a
--  migration that ends in NOTIFY can report "Success" while
--  nothing was created.
--
--  Safe to run as many times as you like.
-- ═══════════════════════════════════════════════════════════

-- 1 ── The table.
CREATE TABLE IF NOT EXISTS public.site_feedback (
  id         BIGSERIAL PRIMARY KEY,
  rating     SMALLINT,          -- 1–5 stars, NULL if they only wrote a note
  message    TEXT,              -- what they said
  name       TEXT,              -- optional, so you can reply by name
  email      TEXT,              -- optional, only if they want a reply
  role       TEXT,              -- 'vendor' | 'customer' | 'visitor'
  page       TEXT,              -- where they were when they left it
  is_read    BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2 ── Newest first is the only order the dashboard ever asks for.
CREATE INDEX IF NOT EXISTS site_feedback_created_at_idx ON public.site_feedback (created_at DESC);

-- 3 ── Match every other table in this database. The app talks to
--      Postgres with the service key; nothing here uses RLS.
ALTER TABLE public.site_feedback DISABLE ROW LEVEL SECURITY;

-- 4 ── Privileges. A table made in the SQL editor does not always
--      inherit the grants the API roles need, and PostgREST reports
--      a table it cannot touch as "not found in the schema cache"
--      (PGRST205) — which reads like the table is missing when it is
--      really a permissions problem.
GRANT ALL ON TABLE    public.site_feedback        TO postgres, service_role, anon, authenticated;
GRANT ALL ON SEQUENCE public.site_feedback_id_seq TO postgres, service_role, anon, authenticated;

-- 5 ── Tell the API the schema changed.
NOTIFY pgrst, 'reload schema';

-- 6 ── Proof. This returns a row only if the table really exists —
--      unlike NOTIFY, which succeeds no matter what.
SELECT
  'site_feedback EXISTS'                                   AS status,
  (SELECT COUNT(*) FROM public.site_feedback)              AS rows_so_far,
  (SELECT relrowsecurity FROM pg_class
     WHERE oid = 'public.site_feedback'::regclass)         AS rls_enabled,
  has_table_privilege('service_role','public.site_feedback','INSERT') AS service_can_insert;

-- ── If the row above comes back, you are done. ─────────────
--  Load foodtruckrewards.com, scroll to "How are we doing?",
--  leave a test review, then open /admin → Feedback.
