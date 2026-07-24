#!/usr/bin/env python3
"""
Extend every ACTIVE trial from 14 days to 30 days (adds 16 days).

The trial is enforced by Stripe (it decides when the card is charged); the app's
vendors.trial_ends_at just mirrors it. So this updates BOTH:
  1. the Stripe subscription's trial_end (+16 days)  -> stops the early charge
  2. vendors.trial_ends_at in Supabase               -> keeps the app in sync

Only touches subscriptions Stripe reports as status == "trialing", so already-paid,
cancelled, comped, and promo vendors are left alone.

SAFE BY DEFAULT: dry run unless you pass --confirm. Read the dry-run list first.
Run --confirm ONCE — a second confirmed run would add another 16 days.

Requires the same env vars the app uses (already set in the Render Shell):
    SUPABASE_URL, SUPABASE_SERVICE_KEY, STRIPE_SECRET_KEY   (use your LIVE key)

Usage:
    python extend_trials.py            # dry run — shows what would change
    python extend_trials.py --confirm  # actually extend
"""
import os
import sys
from datetime import datetime, timezone

ADD_DAYS = 30 - 14            # 16 — the amount each 14-day trial is short by
ADD_SECONDS = ADD_DAYS * 86400


def main():
    confirm = "--confirm" in sys.argv

    url = os.environ.get("SUPABASE_URL")
    key = os.environ.get("SUPABASE_SERVICE_KEY")
    skey = os.environ.get("STRIPE_SECRET_KEY")
    if not url or not key:
        sys.exit("ERROR: set SUPABASE_URL and SUPABASE_SERVICE_KEY first.")
    if not skey:
        sys.exit("ERROR: set STRIPE_SECRET_KEY (your LIVE key) first.")

    from supabase import create_client
    import stripe
    stripe.api_key = skey
    sb = create_client(url, key)

    live = skey.startswith("sk_live_")
    print(f"Stripe mode: {'LIVE' if live else 'TEST'}\n")

    # Page through all vendors that have a Stripe subscription.
    vendors, start = [], 0
    while True:
        chunk = (sb.table("vendors")
                 .select("id, truck_name, email, stripe_sub_id, trial_ends_at")
                 .range(start, start + 999).execute().data or [])
        vendors.extend(chunk)
        if len(chunk) < 1000:
            break
        start += 1000

    to_extend = []   # (vendor, sub, new_trial_end_ts)
    skipped_no_sub = 0
    for v in vendors:
        sub_id = v.get("stripe_sub_id")
        if not sub_id:
            skipped_no_sub += 1
            continue
        try:
            sub = stripe.Subscription.retrieve(sub_id)
        except Exception as e:
            print(f"  [skip] {v.get('email')}: can't fetch sub — {e}")
            continue
        if sub.get("status") != "trialing":
            continue
        cur = sub.get("trial_end")
        if not cur:
            continue
        to_extend.append((v, sub, cur + ADD_SECONDS))

    def fmt(ts):
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")

    print(f"Vendors scanned: {len(vendors)}  (no Stripe sub: {skipped_no_sub})")
    print(f"Active trials to extend (+{ADD_DAYS} days): {len(to_extend)}\n")
    for v, sub, new_ts in to_extend:
        print(f"  {(v.get('email') or v['id']):40} "
              f"{(v.get('truck_name') or ''):22} "
              f"{fmt(sub['trial_end'])}  ->  {fmt(new_ts)}")

    if not to_extend:
        print("\nNo active trials found. Nothing to do.")
        return
    if not confirm:
        print(f"\n*** DRY RUN — nothing changed. ***")
        print(f"Re-run with --confirm to extend the {len(to_extend)} trial(s) above.")
        return

    print("\nApplying…")
    done = 0
    for v, sub, new_ts in to_extend:
        try:
            # Extend the real (Stripe) trial — no proration, keep it trialing.
            stripe.Subscription.modify(
                sub["id"], trial_end=int(new_ts), proration_behavior="none"
            )
        except Exception as e:
            print(f"  [stripe FAIL] {v.get('email')}: {e}")
            continue
        try:
            new_iso = datetime.fromtimestamp(new_ts, tz=timezone.utc)\
                .replace(tzinfo=None).isoformat()
            sb.table("vendors").update({"trial_ends_at": new_iso})\
                .eq("id", v["id"]).execute()
        except Exception as e:
            print(f"  [db WARN] {v.get('email')}: Stripe updated but DB not — {e}")
        done += 1
        print(f"  extended {v.get('email') or v['id']} -> {fmt(new_ts)}")

    print(f"\nDone. Extended {done}/{len(to_extend)} trial(s).")


if __name__ == "__main__":
    main()
