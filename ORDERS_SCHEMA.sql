-- Order-ahead (pay at the window) — run once in the Supabase SQL editor.
-- Until this runs, ordering stays hidden in the app and nothing breaks.

create table if not exists orders (
  id            uuid primary key default gen_random_uuid(),
  vendor_id     uuid not null references vendors(id) on delete cascade,
  customer_id   uuid not null references customers(id) on delete cascade,
  order_code    text not null,                 -- short pickup code, e.g. "A47"
  status        text not null default 'pending', -- pending|accepted|ready|completed|cancelled
  subtotal      numeric(10,2) not null default 0,
  note          text default '',               -- customer's note to the truck
  pickup_name   text default '',               -- name they'll answer to
  points_awarded integer default 0,
  created_at    timestamptz default now(),
  accepted_at   timestamptz,
  ready_at      timestamptz,
  completed_at  timestamptz,
  cancelled_at  timestamptz,
  cancel_reason text default ''
);

create table if not exists order_items (
  id           uuid primary key default gen_random_uuid(),
  order_id     uuid not null references orders(id) on delete cascade,
  menu_item_id uuid,                            -- kept loose: item may be deleted later
  name         text not null,                   -- snapshot, so menu edits don't rewrite history
  price        numeric(10,2) not null default 0,-- snapshot
  emoji        text default '',
  qty          integer not null default 1
);

-- The vendor's live queue, and a customer's own order list.
create index if not exists orders_vendor_idx   on orders (vendor_id, status, created_at desc);
create index if not exists orders_customer_idx on orders (customer_id, created_at desc);
create index if not exists order_items_order_idx on order_items (order_id);

-- Lets a truck stop taking orders when they're slammed or closed.
alter table vendors add column if not exists accepting_orders boolean default false;
