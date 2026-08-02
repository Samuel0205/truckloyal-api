-- ═══════════════════════════════════════════════════════════
--  Website analytics  ·  run in the Supabase SQL editor
-- ═══════════════════════════════════════════════════════════
--  THIS TABLE WAS NEVER CREATED. The tracking beacon has been
--  firing on every page load, the insert has been failing, and
--  the error was being swallowed — so the admin dashboard has
--  always shown 0 views no matter how much traffic you had.
--
--  Run each block on its own. If the editor adds a stray ")"
--  and you get "syntax error at or near )", delete it.
-- ═══════════════════════════════════════════════════════════


-- 1 ── The table.
--      No cookies, no IP, no personal data — just which page, an
--      anonymous random id so repeat loads can be de-duplicated,
--      and where they came from.
CREATE TABLE IF NOT EXISTS page_views (
  id         BIGSERIAL PRIMARY KEY,
  path       TEXT NOT NULL DEFAULT '/',
  visitor    TEXT,
  referrer   TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- 2 ── The dashboard filters by date on every load.
CREATE INDEX IF NOT EXISTS page_views_created_at_idx ON page_views (created_at DESC);


-- 3 ── Unique-visitor counts group by this.
CREATE INDEX IF NOT EXISTS page_views_visitor_idx ON page_views (visitor);


-- 4 ── The service key writes these rows; nobody else should read
--      them. Enabling RLS with no policy blocks anon/authenticated
--      while the server's service key keeps working.
ALTER TABLE page_views ENABLE ROW LEVEL SECURITY;


-- ── Verify (optional) ──────────────────────────────────────
-- Load foodtruckrewards.com in another tab, then run:
-- SELECT path, referrer, created_at FROM page_views
-- ORDER BY created_at DESC LIMIT 20;
