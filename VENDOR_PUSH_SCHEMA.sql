-- Vendor order alerts — run once in the Supabase SQL editor.
-- Lets the push_subscriptions table hold VENDOR subscriptions alongside
-- customer ones, so a truck gets a phone notification when an order lands.
-- Until this runs, order alerts simply stay off; nothing else is affected.

-- 1. Vendor rows (customer_id is null on these).
alter table push_subscriptions
  add column if not exists vendor_id uuid references vendors(id) on delete cascade;

-- 2. A vendor row has no customer, so customer_id must allow null.
alter table push_subscriptions
  alter column customer_id drop not null;

-- 3. Fast lookup when an order comes in.
create index if not exists push_subscriptions_vendor_idx
  on push_subscriptions (vendor_id);
