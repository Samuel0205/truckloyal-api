# Staging Setup — a safe place to test before it goes live

Right now every merge to `main` goes straight to your real app. This gives you a
**staging copy** — same code, separate database, fake Stripe money — so you can
break things safely before a real truck or customer ever sees them.

**One-time setup: ~45 minutes, mostly clicking. Cost: $0** (free tiers).

---

## The layout

```
                    ┌─────────────────────────────────────┐
   YOU BUILD  ──►   │  feature branch                     │
                    └──────────────┬──────────────────────┘
                                   │  merge
                                   ▼
   YOU TEST   ──►   ┌─────────────────────────────────────┐
                    │  staging branch                     │
                    │    ├─ Render:   truckloyal-staging  │
                    │    ├─ Supabase: truckloyal-staging  │
                    │    └─ Stripe:   TEST keys (fake $)  │
                    └──────────────┬──────────────────────┘
                                   │  merge (only when it works)
                                   ▼
   CUSTOMERS  ──►   ┌─────────────────────────────────────┐
                    │  main branch                        │
                    │    ├─ Render:   truckloyal-api      │
                    │    ├─ Supabase: (your real project) │
                    │    └─ Stripe:   LIVE keys (real $)  │
                    └─────────────────────────────────────┘
```

Two completely separate worlds. Nothing you do in staging can touch real
vendors, real customers, or real money.

---

## Step 1 — Staging database (Supabase)

1. Supabase → **New project**. Name it `truckloyal-staging`. Free tier.
   Save the database password.
2. Wait for provisioning (~2 min).
3. Copy your real schema. In your **production** project → **SQL Editor**, run
   this — it prints one `create table` line per table:

   ```sql
   select 'create table if not exists ' || table_name || ' (' ||
          string_agg(
            column_name || ' ' || data_type ||
            coalesce(' default ' || column_default, '') ||
            case when is_nullable = 'NO' then ' not null' else '' end,
            ', ' order by ordinal_position
          ) || ');'
   from information_schema.columns
   where table_schema = 'public'
   group by table_name
   order by table_name;
   ```

4. Copy the output rows → paste into the **staging** project's SQL Editor → Run.

   > **If you get `syntax error at or near ")"`:** the Supabase editor
   > auto-added a closing bracket. Delete the stray `)` on the last line and
   > re-run. Paste in smaller chunks if it keeps happening.

5. Verify staging has all **24** tables:

   ```sql
   select table_name from information_schema.tables
   where table_schema = 'public' order by table_name;
   ```

   Expected: `account_deletions, customer_trucks, customers, menu_items,
   notifications, order_items, orders, page_views, password_reset_tokens,
   promo_codes, promo_uses, promos, push_subscriptions, redemptions, reviews,
   rewards, spin_prizes, spin_results, stripe_events, tiers, vendor_posts,
   vendor_schedule, vendors, visits`

   Any missing? The repo has the newer ones as standalone files you can paste:
   `MENU_SCHEMA.sql`, `ORDERS_SCHEMA.sql`, `VENDOR_PUSH_SCHEMA.sql`.

   > **Heads up:** that dump captures tables, columns, types and defaults — but
   > **not** primary keys, foreign keys, or indexes. Fine for testing. If
   > something behaves oddly on staging but works in production, a missing key
   > is the first thing to suspect.

6. Staging → **Settings → API** → copy the **Project URL** and the
   **`service_role`** key. You need both in Step 3.

---

## Step 2 — Staging web service (Render)

1. Render → **New → Web Service** → same GitHub repo.
2. Set:
   - **Name:** `truckloyal-staging`
   - **Branch:** `staging`  ← the important one
   - **Build:** `pip install -r requirements.txt`
   - **Start:** `gunicorn app:app --workers 1 --threads 8 --timeout 60`
   - **Instance type:** Free
3. Create it → you'll get `https://truckloyal-staging.onrender.com`.

> Free instances sleep when idle, so the first load takes ~30 seconds. Fine for
> testing.

---

## Step 3 — Staging environment variables

Render → your **staging** service → **Environment**. The **bold** ones must
differ from production; the rest can be copied.

| Variable | Staging value |
|---|---|
| **`SUPABASE_URL`** | Your **staging** project URL (Step 1) |
| **`SUPABASE_SERVICE_KEY`** | Your **staging** service_role key |
| **`STRIPE_SECRET_KEY`** | `sk_test_…` — **test mode** |
| **`STRIPE_PUBLISHABLE_KEY`** | `pk_test_…` — **test mode** |
| **`STRIPE_PRICE_ID`** | Your **test-mode** $9.99 price id |
| **`STRIPE_WEBHOOK_SECRET`** | From the test webhook (Step 4) |
| **`ADMIN_PASSWORD`** | Different from production |
| **`APP_URL`** / **`SITE_URL`** | Your staging URL |
| **`TESTER_CODE`** | Anything — lets you create free test vendors |
| `JWT_SECRET` | Any random string |
| `CRON_SECRET` | Any random string |
| `APP_TIMEZONE` | `America/New_York` |
| `TRUSTED_PROXY_HOPS` | `1` |
| `VAPID_PUBLIC_KEY` / `VAPID_PRIVATE_KEY` / `VAPID_SUBJECT` | Same as production is fine |
| `GMAIL_USER` / `GMAIL_APP_PASSWORD` | Same as production is fine |
| `ALLOWED_ORIGINS` | Leave empty |

> ⚠️ **The one that really matters:** `STRIPE_SECRET_KEY` must start with
> `sk_test_`. Paste the live key here and a test signup charges a real card.

---

## Step 4 — Stripe test webhook

Stripe keeps test and live completely separate, so staging needs its own.

1. Stripe → toggle **Test mode ON**.
2. **Developers → Webhooks → Add endpoint**
3. URL: `https://truckloyal-staging.onrender.com/api/webhooks/stripe`
4. Subscribe to these 6 events:
   - `customer.subscription.created`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`
   - `customer.subscription.paused`
   - `invoice.payment_failed`
   - `invoice.payment_succeeded`
5. Copy the signing secret (`whsec_…`) → staging's `STRIPE_WEBHOOK_SECRET`.

---

## Step 5 — Verify

At your staging URL:

- [ ] Vendor landing page loads
- [ ] `/get` (customer page) loads
- [ ] `/admin` loads, **staging** admin password works
- [ ] Sign up a test vendor with Stripe test card `4242 4242 4242 4242`
      (any future expiry, any CVC) — **no real money moves**
- [ ] Add a menu item, flip **Taking orders** on
- [ ] From a test customer account: place an order, accept it, mark it picked
      up, confirm points land
- [ ] Your **production** site still works and is untouched

All green? Staging is live.

---

## Using it from here on

1. New work goes on a feature branch → merged into **`staging`**.
2. You click through it at the staging URL.
3. When it's right, merge `staging` → `main` and it goes live.

Staging data is disposable — create fake vendors, place fake orders, break
things deliberately. That's the whole point.

### Handy things to know

- **Reset staging data anytime:** in the staging SQL editor,
  `truncate orders, order_items, visits, customer_trucks restart identity cascade;`
  (never run this in production).
- **Free instance sleeping** is normal — first request wakes it in ~30s.
- **Keeping schemas in sync:** when a change needs a new table or column, run
  that SQL in **staging first**, confirm it works, then run the same SQL in
  production when you merge. Same order every time and the two never drift.
