#!/usr/bin/env python3
"""
Move every ACTIVE trial onto the current TRIAL_DAYS length (45 days).

The trial is enforced by Stripe (it decides when the card is charged); the app's
vendors.trial_ends_at just mirrors it. So this updates BOTH:
  1. the Stripe subscription's trial_end  -> stops the early charge
  2. vendors.trial_ends_at in Supabase    -> keeps the app in sync

IDEMPOTENT BY DESIGN. It does not add N days — it recomputes each trial as
(trial start + TRIAL_DAYS) from Stripe's own record of when the trial began.
So it doesn't matter whether a vendor originally got 14, 30, 45, or 90 days,
running it twice changes nothing the second time. It also never SHORTENS a
trial: anyone already ending later than the new date is left alone.

Only touches subscriptions Stripe reports as status == "trialing", so
already-paid, cancelled, comped, and promo vendors are left alone.

SAFE BY DEFAULT: dry run unless you pass --confirm. Read the dry-run list first.

Requires the same env vars the app uses (already set in the Render Shell):
    SUPABASE_URL, SUPABASE_SERVICE_KEY, STRIPE_SECRET_KEY   (use your LIVE key)

Usage:
    python extend_trials.py            # dry run — shows what would change
    python extend_trials.py --confirm  # actually extend
"""
import os
import sys
from datetime import datetime, timezone

# Keep in step with TRIAL_DAYS in app.py.
TRIAL_DAYS = int(os.environ.get("TRIAL_DAYS", 45))
DAY = 86400
# Stripe rejects a trial_end that isn't comfortably in the future.
MIN_LEAD_SECONDS = 2 * DAY


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
    print(f"Stripe mode: {'LIVE' if live else 'TEST'}")
    print(f"Target trial length: {TRIAL_DAYS} days\n")

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

    now = int(datetime.now(tz=timezone.utc).timestamp())
    to_extend = []      # (vendor, sub, new_trial_end_ts)
    already_ok = 0      # trial already ends on/after the new date
    too_late = []       # would land inside Stripe's minimum lead time
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

        # Recompute from when the trial actually started, so this is repeatable.
        began = sub.get("trial_start") or sub.get("created")
        if not began:
            continue
        new_ts = began + TRIAL_DAYS * DAY

        if new_ts <= cur:
            already_ok += 1          # never shorten someone's trial
            continue
        if new_ts - now < MIN_LEAD_SECONDS:
            too_late.append((v, cur, new_ts))
            continue
        to_extend.append((v, sub, new_ts))

    def fmt(ts):
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")

    print(f"Vendors scanned: {len(vendors)}  (no Stripe sub: {skipped_no_sub})")
    print(f"Already at {TRIAL_DAYS}+ days: {already_ok}")
    print(f"Trials to extend: {len(to_extend)}\n")
    for v, sub, new_ts in to_extend:
        print(f"  {(v.get('email') or v['id']):40} "
              f"{(v.get('truck_name') or ''):22} "
              f"{fmt(sub['trial_end'])}  ->  {fmt(new_ts)}")

    if too_late:
        print(f"\n  !! {len(too_late)} trial(s) started too long ago — the new end "
              f"date is under {MIN_LEAD_SECONDS // DAY} days out and Stripe will "
              f"reject it. Comp these from the admin page instead:")
        for v, cur, new_ts in too_late:
            print(f"     {(v.get('email') or v['id']):40} "
                  f"ends {fmt(cur)}, would be {fmt(new_ts)}")

    if not to_extend:
        print("\nNothing to extend.")
        return
    if not confirm:
        print("\n*** DRY RUN — nothing changed. ***")
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
