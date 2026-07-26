-- Menu items — run once in the Supabase SQL editor.
-- Until this runs, the app treats every truck as having an empty menu
-- (nothing breaks; the Menu screen just shows "no items yet").

create table if not exists menu_items (
  id            uuid primary key default gen_random_uuid(),
  vendor_id     uuid not null references vendors(id) on delete cascade,
  name          text not null,
  description   text default '',
  price         numeric(10,2) not null default 0,
  category      text default '',
  emoji         text default '🍽️',
  is_available  boolean default true,
  sort_order    integer default 0,
  created_at    timestamptz default now()
);

-- Fast lookup of a truck's menu (the query the customer page runs).
create index if not exists menu_items_vendor_idx
  on menu_items (vendor_id, sort_order);
