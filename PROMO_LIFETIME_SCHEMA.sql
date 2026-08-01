-- ═══════════════════════════════════════════════════════════
--  Lifetime promo codes  ·  run in the Supabase SQL editor
-- ═══════════════════════════════════════════════════════════
--  Run each block on its own. The editor likes to add a stray
--  closing bracket when you paste a long script — if you see
--  "syntax error at or near )", delete the extra ) and re-run.
--
--  All four are additive. Nothing is dropped or rewritten, and
--  the app keeps working before, during, and after the run.
-- ═══════════════════════════════════════════════════════════


-- 1 ── Mark a promo code as "free forever".
--      When set, redeeming the code attaches a 100%-off Stripe
--      coupon instead of granting N months of access.
ALTER TABLE promo_codes ADD COLUMN IF NOT EXISTS is_lifetime BOOLEAN DEFAULT FALSE;


-- 2 ── Cache of the Stripe coupon created for this code.
--      Filled in automatically the first time the code is used,
--      so every vendor on the code shares one coupon in Stripe.
ALTER TABLE promo_codes ADD COLUMN IF NOT EXISTS stripe_coupon_id TEXT;


-- 3 ── Which billing promo code this vendor redeemed.
--      Stops the same code being applied over and over to stack
--      free months.
ALTER TABLE vendors ADD COLUMN IF NOT EXISTS billing_promo_code TEXT;


-- 4 ── Backfill: existing codes are month-based, not lifetime.
UPDATE promo_codes SET is_lifetime = FALSE WHERE is_lifetime IS NULL;


-- ── Verify (optional) ──────────────────────────────────────
-- SELECT code, free_months, is_lifetime, stripe_coupon_id, uses, max_uses
-- FROM promo_codes ORDER BY created_at DESC;
