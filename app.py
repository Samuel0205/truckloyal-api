"""
TruckLoyal Flask API
Deploy on Render — same account as your trading bot
Python 3.11+

Install:
  pip install flask flask-cors supabase python-jose bcrypt twilio stripe python-dotenv

Environment variables to set in Render dashboard:
  SUPABASE_URL
  SUPABASE_SERVICE_KEY     ← use service role key (bypasses RLS for backend ops)
  JWT_SECRET               ← any long random string
  TWILIO_SID
  TWILIO_AUTH_TOKEN
  TWILIO_FROM_NUMBER
  STRIPE_SECRET_KEY
  STRIPE_WEBHOOK_SECRET
"""

import os, re, bcrypt, random, string
from datetime import datetime, timedelta, date
from functools import wraps

from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client, Client
from jose import jwt, JWTError
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app, origins=["*"])  # Lock down to your domain in production

# ── Supabase (service role — full access, backend only) ──
sb: Client = create_client(
    os.environ["SUPABASE_URL"],
    os.environ["SUPABASE_SERVICE_KEY"]
)

JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGO   = "HS256"
JWT_EXPIRY = 30  # days


# ══════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════

def make_token(vendor_id: str) -> str:
    payload = {
        "sub": vendor_id,
        "exp": datetime.utcnow() + timedelta(days=JWT_EXPIRY)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def vendor_required(f):
    """Decorator — protects vendor-only routes."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing token"}), 401
        try:
            payload = jwt.decode(auth[7:], JWT_SECRET, algorithms=[JWT_ALGO])
            request.vendor_id = payload["sub"]
        except JWTError:
            return jsonify({"error": "Invalid or expired token"}), 401
        return f(*args, **kwargs)
    return decorated


def gen_code(length=8) -> str:
    """Generate a redemption code like STK-A3F9."""
    return "STK-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=4))


def slugify(name: str) -> str:
    return re.sub(r'[^a-z0-9]', '', name.lower())[:20]


def ok(data=None, **kwargs):
    return jsonify({"ok": True, "data": data, **kwargs})


def err(msg, code=400):
    return jsonify({"ok": False, "error": msg}), code


# ══════════════════════════════════════════════════════
#  HEALTH CHECK
# ══════════════════════════════════════════════════════

@app.route("/")
def health():
    return ok("TruckLoyal API is running 🚚")


# ══════════════════════════════════════════════════════
#  VENDOR AUTH
# ══════════════════════════════════════════════════════

@app.route("/api/vendor/signup", methods=["POST"])
def vendor_signup():
    body = request.json or {}
    email    = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""
    name     = (body.get("truck_name") or "My Food Truck").strip()

    if not email or not password:
        return err("Email and password are required")
    if len(password) < 8:
        return err("Password must be at least 8 characters")

    # Check existing
    existing = sb.table("vendors").select("id").eq("email", email).execute()
    if existing.data:
        return err("An account with this email already exists")

    # Hash password
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    # Build unique slug
    base_slug = slugify(name)
    slug = base_slug
    i = 1
    while sb.table("vendors").select("id").eq("slug", slug).execute().data:
        slug = f"{base_slug}{i}"
        i += 1

    # Create vendor
    vendor = sb.table("vendors").insert({
        "email": email,
        "password_hash": pw_hash,
        "truck_name": name,
        "slug": slug,
    }).execute().data[0]

    # Seed defaults (rewards, prizes, tiers)
    sb.rpc("seed_vendor_defaults", {"v_id": vendor["id"]}).execute()

    token = make_token(vendor["id"])
    return ok({"token": token, "vendor": _safe_vendor(vendor)}), 201


@app.route("/api/vendor/login", methods=["POST"])
def vendor_login():
    body = request.json or {}
    email    = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""

    row = sb.table("vendors").select("*").eq("email", email).execute().data
    if not row:
        return err("Invalid email or password", 401)

    vendor = row[0]
    if not bcrypt.checkpw(password.encode(), vendor["password_hash"].encode()):
        return err("Invalid email or password", 401)

    token = make_token(vendor["id"])
    return ok({"token": token, "vendor": _safe_vendor(vendor)})


@app.route("/api/vendor/me", methods=["GET"])
@vendor_required
def vendor_me():
    vendor = sb.table("vendors").select("*").eq("id", request.vendor_id).execute().data[0]
    return ok(_safe_vendor(vendor))


def _safe_vendor(v: dict) -> dict:
    """Strip sensitive fields before sending to client."""
    v.pop("password_hash", None)
    v.pop("stripe_customer_id", None)
    v.pop("stripe_sub_id", None)
    return v


# ══════════════════════════════════════════════════════
#  VENDOR CONFIG (brand, rewards, prizes, tiers)
# ══════════════════════════════════════════════════════

@app.route("/api/vendor/brand", methods=["PATCH"])
@vendor_required
def update_brand():
    body = request.json or {}
    allowed = ["truck_name", "tagline", "emoji", "color_primary", "color_secondary"]
    updates = {k: v for k, v in body.items() if k in allowed}

    if "truck_name" in updates:
        new_slug = slugify(updates["truck_name"])
        # Ensure uniqueness
        i = 1
        slug = new_slug
        while True:
            clash = sb.table("vendors").select("id").eq("slug", slug).neq("id", request.vendor_id).execute().data
            if not clash:
                break
            slug = f"{new_slug}{i}"; i += 1
        updates["slug"] = slug

    vendor = sb.table("vendors").update(updates).eq("id", request.vendor_id).execute().data[0]
    return ok(_safe_vendor(vendor))


@app.route("/api/vendor/points-config", methods=["PATCH"])
@vendor_required
def update_points_config():
    body = request.json or {}
    allowed = ["pts_per_visit","pts_spin_bonus","pts_streak_mult","pts_referral",
               "double_first_visit","streak_bonus","birthday_reward","winback_enabled"]
    updates = {k: v for k, v in body.items() if k in allowed}
    vendor = sb.table("vendors").update(updates).eq("id", request.vendor_id).execute().data[0]
    return ok(_safe_vendor(vendor))


# ── Rewards ──

@app.route("/api/vendor/rewards", methods=["GET"])
@vendor_required
def get_rewards():
    rows = sb.table("rewards").select("*").eq("vendor_id", request.vendor_id).order("sort_order").execute()
    return ok(rows.data)


@app.route("/api/vendor/rewards", methods=["POST"])
@vendor_required
def add_reward():
    body = request.json or {}
    row = sb.table("rewards").insert({
        "vendor_id":    request.vendor_id,
        "emoji":        body.get("emoji", "🎁"),
        "name":         body["name"],
        "pts_required": int(body["pts_required"]),
        "is_default":   False,
    }).execute().data[0]
    return ok(row), 201


@app.route("/api/vendor/rewards/<reward_id>", methods=["DELETE"])
@vendor_required
def delete_reward(reward_id):
    sb.table("rewards").delete().eq("id", reward_id).eq("vendor_id", request.vendor_id).execute()
    return ok("Deleted")


# ── Spin Prizes ──

@app.route("/api/vendor/prizes", methods=["GET"])
@vendor_required
def get_prizes():
    rows = sb.table("spin_prizes").select("*").eq("vendor_id", request.vendor_id).execute()
    return ok(rows.data)


@app.route("/api/vendor/prizes", methods=["POST"])
@vendor_required
def add_prize():
    body = request.json or {}
    row = sb.table("spin_prizes").insert({
        "vendor_id":   request.vendor_id,
        "emoji":       body.get("emoji", "🎁"),
        "name":        body["name"],
        "probability": int(body["probability"]),
        "prize_type":  body.get("prize_type", "points"),
        "prize_value": body.get("prize_value", ""),
    }).execute().data[0]
    return ok(row), 201


@app.route("/api/vendor/prizes/<prize_id>", methods=["DELETE"])
@vendor_required
def delete_prize(prize_id):
    sb.table("spin_prizes").delete().eq("id", prize_id).eq("vendor_id", request.vendor_id).execute()
    return ok("Deleted")


# ── Tiers ──

@app.route("/api/vendor/tiers", methods=["GET"])
@vendor_required
def get_tiers():
    rows = sb.table("tiers").select("*").eq("vendor_id", request.vendor_id).order("pts_threshold").execute()
    return ok(rows.data)


@app.route("/api/vendor/tiers/<tier_id>", methods=["PATCH"])
@vendor_required
def update_tier(tier_id):
    body = request.json or {}
    allowed = ["name", "icon", "pts_threshold", "perks"]
    updates = {k: v for k, v in body.items() if k in allowed}
    row = sb.table("tiers").update(updates).eq("id", tier_id).eq("vendor_id", request.vendor_id).execute().data[0]
    return ok(row)


# ── Dashboard stats ──

@app.route("/api/vendor/stats", methods=["GET"])
@vendor_required
def vendor_stats():
    vid = request.vendor_id
    today = date.today().isoformat()

    members = sb.table("customers").select("id", count="exact").eq("vendor_id", vid).execute()
    visits_today = sb.table("visits").select("id", count="exact").eq("vendor_id", vid).gte("created_at", today).execute()
    redemptions = sb.table("redemptions").select("id", count="exact").eq("vendor_id", vid).execute()

    return ok({
        "total_members":    members.count,
        "visits_today":     visits_today.count,
        "total_redemptions": redemptions.count,
    })


# ══════════════════════════════════════════════════════
#  PUBLIC — CUSTOMER-FACING  (no vendor auth needed)
# ══════════════════════════════════════════════════════

@app.route("/api/truck/<slug>", methods=["GET"])
def get_truck(slug):
    """Load a truck's public brand config by slug (called when customer scans QR)."""
    row = sb.table("vendors").select(
        "id, truck_name, tagline, emoji, slug, color_primary, color_secondary"
    ).eq("slug", slug).eq("plan_active", True).execute().data

    if not row:
        # Allow trial vendors through too
        row = sb.table("vendors").select(
            "id, truck_name, tagline, emoji, slug, color_primary, color_secondary, trial_ends_at"
        ).eq("slug", slug).execute().data

    if not row:
        return err("Truck not found", 404)

    vendor = row[0]

    # Get rewards, tiers
    rewards = sb.table("rewards").select("*").eq("vendor_id", vendor["id"]).eq("is_active", True).order("sort_order").execute().data
    tiers   = sb.table("tiers").select("*").eq("vendor_id", vendor["id"]).order("pts_threshold").execute().data
    prizes  = sb.table("spin_prizes").select("*").eq("vendor_id", vendor["id"]).eq("is_active", True).execute().data

    return ok({
        "vendor":  vendor,
        "rewards": rewards,
        "tiers":   tiers,
        "prizes":  prizes,
    })


# ── Customer join / lookup ──

@app.route("/api/customer/join", methods=["POST"])
def customer_join():
    """Called when a customer enters their phone number."""
    body = request.json or {}
    phone     = re.sub(r'\D', '', body.get("phone", ""))
    vendor_id = body.get("vendor_id")
    name      = body.get("name", "")

    if not phone or len(phone) < 10:
        return err("Valid phone number required")
    if not vendor_id:
        return err("vendor_id required")

    # Lookup or create
    existing = sb.table("customers").select("*").eq("phone", phone).eq("vendor_id", vendor_id).execute().data

    if existing:
        customer = existing[0]
        is_new = False
    else:
        # Check for referral
        ref_code = body.get("ref_code")
        referred_by = None
        if ref_code:
            ref = sb.table("customers").select("id").eq("referral_code", ref_code).execute().data
            if ref:
                referred_by = ref[0]["id"]

        customer = sb.table("customers").insert({
            "phone":       phone,
            "vendor_id":   vendor_id,
            "name":        name,
            "referred_by": referred_by,
        }).execute().data[0]
        is_new = True

    return ok({
        "customer": customer,
        "is_new":   is_new,
    })


# ── Record a visit + calculate points ──

@app.route("/api/customer/visit", methods=["POST"])
def record_visit():
    """Called every time a customer scans the QR code."""
    body        = request.json or {}
    customer_id = body.get("customer_id")
    vendor_id   = body.get("vendor_id")

    if not customer_id or not vendor_id:
        return err("customer_id and vendor_id required")

    customer = sb.table("customers").select("*").eq("id", customer_id).execute().data[0]
    vendor   = sb.table("vendors").select("*").eq("id", vendor_id).execute().data[0]

    today = date.today()
    last  = customer.get("last_visit_date")
    last_date = date.fromisoformat(last) if last else None

    # ── Streak logic ──
    if last_date == today:
        return err("Already checked in today — come back tomorrow! 🔥", 409)

    if last_date and (today - last_date).days == 1:
        new_streak = customer["current_streak"] + 1
    else:
        new_streak = 1

    longest = max(customer["longest_streak"], new_streak)

    # ── Points calculation ──
    base = vendor["pts_per_visit"]
    breakdown = {"base": base}

    # First visit double
    if vendor["double_first_visit"] and customer["visit_count"] == 0:
        breakdown["first_visit_bonus"] = base
        base *= 2

    # Streak multiplier
    streak_bonus = 0
    if vendor["streak_bonus"] and new_streak > 1:
        streak_bonus = int(base * (vendor["pts_streak_mult"] - 1))
        breakdown["streak_bonus"] = streak_bonus

    spin_bonus = vendor["pts_spin_bonus"]
    breakdown["spin_bonus"] = spin_bonus

    total_pts = base + streak_bonus + spin_bonus

    # ── Create visit record ──
    visit = sb.table("visits").insert({
        "customer_id":   customer_id,
        "vendor_id":     vendor_id,
        "pts_earned":    total_pts,
        "pts_breakdown": breakdown,
        "streak_day":    new_streak,
    }).execute().data[0]

    # ── Update customer ──
    new_balance = customer["points_balance"] + total_pts
    new_total   = customer["points_total"]   + total_pts
    new_visits  = customer["visit_count"]    + 1

    # Check tier upgrade
    tiers = sb.table("tiers").select("*").eq("vendor_id", vendor_id).order("pts_threshold", desc=True).execute().data
    new_tier_id = customer["current_tier_id"]
    tier_upgraded = False
    for tier in tiers:
        if new_total >= tier["pts_threshold"]:
            if tier["id"] != customer["current_tier_id"]:
                new_tier_id   = tier["id"]
                tier_upgraded = True
            break

    sb.table("customers").update({
        "points_balance":  new_balance,
        "points_total":    new_total,
        "visit_count":     new_visits,
        "current_streak":  new_streak,
        "longest_streak":  longest,
        "last_visit_date": today.isoformat(),
        "current_tier_id": new_tier_id,
    }).eq("id", customer_id).execute()

    # ── Spin prizes weighted random ──
    prizes = sb.table("spin_prizes").select("*").eq("vendor_id", vendor_id).eq("is_active", True).execute().data
    spin_result = None
    if prizes:
        total_weight = sum(p["probability"] for p in prizes)
        r = random.uniform(0, total_weight)
        cumulative = 0
        won_prize = prizes[-1]
        for p in prizes:
            cumulative += p["probability"]
            if r <= cumulative:
                won_prize = p
                break

        spin_result = sb.table("spin_results").insert({
            "customer_id": customer_id,
            "vendor_id":   vendor_id,
            "visit_id":    visit["id"],
            "prize_id":    won_prize["id"],
            "prize_name":  won_prize["name"],
            "prize_type":  won_prize["prize_type"],
            "prize_value": won_prize["prize_value"],
        }).execute().data[0]

        # Update visit with spin result
        sb.table("visits").update({"spin_result_id": spin_result["id"]}).eq("id", visit["id"]).execute()

    # ── Referral bonus (first visit) ──
    if customer["visit_count"] == 0 and customer.get("referred_by"):
        ref_pts = vendor["pts_referral"]
        ref_cust = sb.table("customers").select("*").eq("id", customer["referred_by"]).execute().data[0]
        sb.table("customers").update({
            "points_balance": ref_cust["points_balance"] + ref_pts,
            "points_total":   ref_cust["points_total"]   + ref_pts,
        }).eq("id", customer["referred_by"]).execute()

    return ok({
        "visit":         visit,
        "pts_earned":    total_pts,
        "breakdown":     breakdown,
        "new_balance":   new_balance,
        "new_streak":    new_streak,
        "spin_result":   spin_result,
        "tier_upgraded": tier_upgraded,
        "new_tier_id":   new_tier_id,
    })


# ── Redeem a reward ──

@app.route("/api/customer/redeem", methods=["POST"])
def redeem_reward():
    body        = request.json or {}
    customer_id = body.get("customer_id")
    reward_id   = body.get("reward_id")

    customer = sb.table("customers").select("*").eq("id", customer_id).execute().data[0]
    reward   = sb.table("rewards").select("*").eq("id", reward_id).execute().data[0]

    if customer["points_balance"] < reward["pts_required"]:
        return err(f"Not enough points. Need {reward['pts_required']}, have {customer['points_balance']}")

    code = gen_code()
    redemption = sb.table("redemptions").insert({
        "customer_id": customer_id,
        "vendor_id":   reward["vendor_id"],
        "reward_id":   reward_id,
        "pts_spent":   reward["pts_required"],
        "code":        code,
        "expires_at":  (datetime.utcnow() + timedelta(hours=24)).isoformat(),
    }).execute().data[0]

    # Deduct points
    sb.table("customers").update({
        "points_balance": customer["points_balance"] - reward["pts_required"],
        "total_saved":    float(customer["total_saved"]) + 5.00,  # approx value
    }).eq("id", customer_id).execute()

    return ok({
        "code":        code,
        "reward_name": reward["name"],
        "expires_at":  redemption["expires_at"],
    })


# ── Validate a redemption code (cashier scans) ──

@app.route("/api/redeem/validate", methods=["POST"])
def validate_code():
    body = request.json or {}
    code = (body.get("code") or "").upper()

    row = sb.table("redemptions").select("*, rewards(name, emoji)").eq("code", code).execute().data
    if not row:
        return err("Code not found", 404)

    r = row[0]
    if r["status"] == "used":
        return err("Code already used")
    if r["status"] == "expired" or datetime.fromisoformat(r["expires_at"].replace("Z","")) < datetime.utcnow():
        sb.table("redemptions").update({"status": "expired"}).eq("id", r["id"]).execute()
        return err("Code has expired")

    # Mark used
    sb.table("redemptions").update({
        "status":  "used",
        "used_at": datetime.utcnow().isoformat(),
    }).eq("id", r["id"]).execute()

    return ok({
        "valid":       True,
        "reward_name": r["rewards"]["name"],
        "reward_emoji": r["rewards"]["emoji"],
    })


# ── Customer history ──

@app.route("/api/customer/<customer_id>/history", methods=["GET"])
def customer_history(customer_id):
    visits = sb.table("visits").select("*, spin_results(prize_name, prize_emoji)").eq("customer_id", customer_id).order("created_at", desc=True).limit(30).execute()
    redemptions = sb.table("redemptions").select("*, rewards(name, emoji)").eq("customer_id", customer_id).order("created_at", desc=True).limit(20).execute()
    return ok({"visits": visits.data, "redemptions": redemptions.data})


# ══════════════════════════════════════════════════════
#  STRIPE WEBHOOKS
# ══════════════════════════════════════════════════════

@app.route("/api/webhooks/stripe", methods=["POST"])
def stripe_webhook():
    try:
        import stripe
        stripe.api_key = os.environ["STRIPE_SECRET_KEY"]
        payload = request.data
        sig     = request.headers.get("Stripe-Signature")
        event   = stripe.Webhook.construct_event(payload, sig, os.environ["STRIPE_WEBHOOK_SECRET"])
    except Exception as e:
        return err(str(e))

    if event["type"] == "customer.subscription.created":
        sub = event["data"]["object"]
        sb.table("vendors").update({
            "stripe_sub_id": sub["id"],
            "plan_active":   True,
        }).eq("stripe_customer_id", sub["customer"]).execute()

    elif event["type"] in ("customer.subscription.deleted", "customer.subscription.paused"):
        sub = event["data"]["object"]
        sb.table("vendors").update({"plan_active": False}).eq("stripe_customer_id", sub["customer"]).execute()

    return ok("received")


# ══════════════════════════════════════════════════════
#  RUN
# ══════════════════════════════════════════════════════

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
