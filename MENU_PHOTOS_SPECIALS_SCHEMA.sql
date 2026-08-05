-- ═══════════════════════════════════════════════════════════
--  Menu photos + Today's Specials
--  Supabase → SQL Editor → paste ALL of this → Run
-- ═══════════════════════════════════════════════════════════
--  Adds three columns to the existing menu_items table:
--    · image_url      a photo of the item
--    · is_special     pins it to the "Today's Specials" section
--    · special_price  optional deal price; the normal price shows
--                     struck through next to it
--
--  Until this runs the app keeps working exactly as it does now —
--  every query falls back to the old column list — but photos and
--  specials won't save.
--
--  One block, safe to run repeatedly, ends with proof.
-- ═══════════════════════════════════════════════════════════

-- 1 ── The columns. All nullable/defaulted, so existing items are
--      untouched and keep showing their emoji.
ALTER TABLE public.menu_items ADD COLUMN IF NOT EXISTS image_url     TEXT;
ALTER TABLE public.menu_items ADD COLUMN IF NOT EXISTS is_special    BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE public.menu_items ADD COLUMN IF NOT EXISTS special_price NUMERIC(10,2);

-- 2 ── Specials get pulled to the top of the menu, so give that
--      lookup an index of its own.
CREATE INDEX IF NOT EXISTS menu_items_special_idx
  ON public.menu_items (vendor_id, is_special, sort_order);

-- 3 ── Make sure the API can see and write the new columns.
GRANT ALL ON TABLE public.menu_items TO postgres, service_role, anon, authenticated;

-- 4 ── PostgREST caches the schema; without this the app keeps
--      reporting the columns as missing.
NOTIFY pgrst, 'reload schema';

-- 5 ── Proof. Returns a row only if all three columns really exist.
SELECT
  'menu_items photos + specials READY' AS status,
  COUNT(*) FILTER (WHERE column_name = 'image_url')     AS has_image_url,
  COUNT(*) FILTER (WHERE column_name = 'is_special')    AS has_is_special,
  COUNT(*) FILTER (WHERE column_name = 'special_price') AS has_special_price,
  (SELECT COUNT(*) FROM public.menu_items)              AS menu_items_so_far
FROM information_schema.columns
WHERE table_schema = 'public'
  AND table_name   = 'menu_items'
  AND column_name IN ('image_url', 'is_special', 'special_price');

-- ── All three counts should read 1. ────────────────────────
--  Then in the app: Menu → tap an item → Edit → add a photo,
--  or flip "Today's special" on.
--
--  Photos are stored in the existing `profile-pictures` bucket
--  under menu/<vendor id>/, so there is no new bucket to create.
