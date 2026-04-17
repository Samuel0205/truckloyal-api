"""
Food Truck Rewards — Flask API
Deploy on Render (Python 3.11+)

pip install flask flask-cors supabase python-jose bcrypt twilio stripe python-dotenv

Environment variables (set in Render dashboard):
  SUPABASE_URL
  SUPABASE_SERVICE_KEY     ← service role key (bypasses RLS)
  JWT_SECRET               ← any long random string
  TWILIO_SID               ← optional, for SMS
  TWILIO_AUTH_TOKEN        ← optional
  TWILIO_FROM_NUMBER       ← optional
  STRIPE_SECRET_KEY        ← optional, for billing
  STRIPE_WEBHOOK_SECRET    ← optional
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
CORS(app, origins=["*"])

# ── Supabase ──
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

def make_vendor_token(vendor_id: str) -> str:
    payload = {
        "sub":  vendor_id,
        "type": "vendor",
        "exp":  datetime.utcnow() + timedelta(days=JWT_EXPIRY)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def make_customer_token(customer_id: str) -> str:
    payload = {
        "sub":  customer_id,
        "type": "customer",
        "exp":  datetime.utcnow() + timedelta(days=JWT_EXPIRY * 2)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def vendor_required(f):
    """Protects vendor-only routes via Bearer token."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return err("Missing token", 401)
        try:
            payload = jwt.decode(auth[7:], JWT_SECRET, algorithms=[JWT_ALGO])
            if payload.get("type") != "vendor":
                return err("Invalid token type", 401)
            request.vendor_id = payload["sub"]
        except JWTError:
            return err("Invalid or expired token", 401)
        return f(*args, **kwargs)
    return decorated


def gen_code() -> str:
    """Generate a unique redemption code like STK-A3F9."""
    chars = string.ascii_uppercase + string.digits
    return "STK-" + "".join(random.choices(chars, k=4))


def gen_rewards_id() -> str:
    """Generate a customer rewards ID like FTR-000123."""
    return "FTR-" + "".join(random.choices(string.digits, k=6))


def slugify(name: str) -> str:
    return re.sub(r'[^a-z0-9]', '', name.lower())[:24]


def ok(data=None, **kwargs):
    return jsonify({"ok": True, "data": data, **kwargs})


def err(msg, code=400):
    return jsonify({"ok": False, "error": msg}), code


def _safe_vendor(v: dict) -> dict:
    v.pop("password_hash", None)
    v.pop("stripe_customer_id", None)
    v.pop("stripe_sub_id", None)
    return v


def _safe_customer(c: dict) -> dict:
    """Strip any internal fields before sending to client."""
    c.pop("password_hash", None)
    return c


def _calc_points(vendor: dict, order_total: float, visit_count: int,
                 current_streak: int) -> dict:
    """
    Calculate total points for a visit + order.
    Returns dict with breakdown and total.
    """
    pts_per_dollar = vendor.get("pts_per_dollar") or 10
    pts_per_visit  = vendor.get("pts_per_visit")  or 50
    streak_mult    = vendor.get("pts_streak_mult") or 1.5

    base_visit  = pts_per_visit
    order_pts   = int(order_total * pts_per_dollar) if order_total else 0
    breakdown   = {"base_visit": base_visit, "order_pts": order_pts}

    # First visit double
    if vendor.get("double_first_visit") and visit_count == 0:
        base_visit *= 2
        breakdown["first_visit_bonus"] = pts_per_visit

    # Streak multiplier on visit pts
    streak_bonus = 0
    if vendor.get("streak_bonus") and current_streak > 1:
        streak_bonus = int(base_visit * (streak_mult - 1))
        breakdown["streak_bonus"] = streak_bonus

    total = base_visit + order_pts + streak_bonus
    breakdown["total"] = total
    return breakdown


# ══════════════════════════════════════════════════════
#  HEALTH CHECK
# ══════════════════════════════════════════════════════

@app.route("/")
def health():
    return ok("Food Truck Rewards API 🚚")


# ══════════════════════════════════════════════════════
#  VENDOR AUTH
# ══════════════════════════════════════════════════════

@app.route("/api/vendor/signup", methods=["POST"])
def vendor_signup():
    body       = request.json or {}
    email      = (body.get("email") or "").strip().lower()
    password   = body.get("password") or ""
    truck_name = (body.get("truck_name") or "My Food Truck").strip()
    owner_name = (body.get("owner_name") or "").strip()

    if not email or not password:
        return err("Email and password are required")
    if len(password) < 8:
        return err("Password must be at least 8 characters")

    existing = sb.table("vendors").select("id").eq("email", email).execute()
    if existing.data:
        return err("An account with this email already exists")

    pw_hash   = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    base_slug = slugify(truck_name)
    slug = base_slug
    i = 1
    while sb.table("vendors").select("id").eq("slug", slug).execute().data:
        slug = f"{base_slug}{i}"; i += 1

    trial_end = (datetime.utcnow() + timedelta(days=14)).isoformat()

    vendor = sb.table("vendors").insert({
        "email":          email,
        "password_hash":  pw_hash,
        "truck_name":     truck_name,
        "owner_name":     owner_name,
        "slug":           slug,
        "trial_ends_at":  trial_end,
        "plan_active":    True,
        # Default points config
        "pts_per_visit":      50,
        "pts_per_dollar":     10,
        "pts_spin_bonus":     25,
        "pts_streak_mult":    1.5,
        "pts_referral":       100,
        "double_first_visit": True,
        "streak_bonus":       True,
        "birthday_reward":    False,
        "winback_enabled":    False,
        "referral_bonus":     True,
    }).execute().data[0]

    # Seed default rewards, spin prizes, tiers
    try:
        sb.rpc("seed_vendor_defaults", {"v_id": vendor["id"]}).execute()
    except Exception:
        pass  # Seed is optional — app still works without it

    token = make_vendor_token(vendor["id"])
    return ok({"token": token, "vendor": _safe_vendor(vendor)}), 201


@app.route("/api/vendor/login", methods=["POST"])
def vendor_login():
    body     = request.json or {}
    email    = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""

    row = sb.table("vendors").select("*").eq("email", email).execute().data
    if not row:
        return err("Invalid email or password", 401)

    vendor = row[0]
    if not bcrypt.checkpw(password.encode(), vendor["password_hash"].encode()):
        return err("Invalid email or password", 401)

    token = make_vendor_token(vendor["id"])
    return ok({"token": token, "vendor": _safe_vendor(vendor)})


@app.route("/api/vendor/me", methods=["GET"])
@vendor_required
def vendor_me():
    vendor = sb.table("vendors").select("*").eq("id", request.vendor_id).execute().data[0]
    return ok(_safe_vendor(vendor))


# ══════════════════════════════════════════════════════
#  VENDOR CONFIG (brand, points, rewards, prizes, tiers)
# ══════════════════════════════════════════════════════

@app.route("/api/vendor/brand", methods=["PATCH"])
@vendor_required
def update_brand():
    body    = request.json or {}
    allowed = ["truck_name", "tagline", "emoji", "color_primary", "color_secondary"]
    updates = {k: v for k, v in body.items() if k in allowed}

    if "truck_name" in updates:
        base_slug = slugify(updates["truck_name"])
        slug = base_slug; i = 1
        while True:
            clash = sb.table("vendors").select("id").eq("slug", slug).neq("id", request.vendor_id).execute().data
            if not clash: break
            slug = f"{base_slug}{i}"; i += 1
        updates["slug"] = slug

    vendor = sb.table("vendors").update(updates).eq("id", request.vendor_id).execute().data[0]
    return ok(_safe_vendor(vendor))


@app.route("/api/vendor/points-config", methods=["PATCH"])
@vendor_required
def update_points_config():
    body    = request.json or {}
    allowed = [
        "pts_per_visit", "pts_per_dollar", "pts_spin_bonus",
        "pts_streak_mult", "pts_referral",
        "double_first_visit", "streak_bonus", "birthday_reward",
        "winback_enabled", "referral_bonus"
    ]
    updates = {k: v for k, v in body.items() if k in allowed}
    vendor  = sb.table("vendors").update(updates).eq("id", request.vendor_id).execute().data[0]
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
    if not body.get("name") or not body.get("pts_required"):
        return err("name and pts_required are required")
    row = sb.table("rewards").insert({
        "vendor_id":    request.vendor_id,
        "emoji":        body.get("emoji", "🎁"),
        "name":         body["name"],
        "pts_required": int(body["pts_required"]),
        "is_active":    True,
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
    if not body.get("name") or not body.get("probability"):
        return err("name and probability are required")
    row = sb.table("spin_prizes").insert({
        "vendor_id":   request.vendor_id,
        "emoji":       body.get("emoji", "⚡"),
        "name":        body["name"],
        "probability": int(body["probability"]),
        "prize_type":  body.get("prize_type", "points"),
        "prize_value": str(body.get("prize_value", "50")),
        "is_active":   True,
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
    body    = request.json or {}
    allowed = ["name", "icon", "pts_threshold", "perks"]
    updates = {k: v for k, v in body.items() if k in allowed}
    row = sb.table("tiers").update(updates).eq("id", tier_id).eq("vendor_id", request.vendor_id).execute().data[0]
    return ok(row)


# ── Dashboard stats ──

@app.route("/api/vendor/stats", methods=["GET"])
@vendor_required
def vendor_stats():
    vid   = request.vendor_id
    today = date.today().isoformat()

    members      = sb.table("customer_trucks").select("id", count="exact").eq("vendor_id", vid).execute()
    visits_today = sb.table("visits").select("id", count="exact").eq("vendor_id", vid).gte("created_at", today).execute()
    redemptions  = sb.table("redemptions").select("id", count="exact").eq("vendor_id", vid).execute()

    return ok({
        "total_members":     members.count      or 0,
        "visits_today":      visits_today.count or 0,
        "total_redemptions": redemptions.count  or 0,
    })


# ══════════════════════════════════════════════════════
#  VENDOR: AWARD POINTS AT WINDOW
#  Called when vendor manually awards points for an order
# ══════════════════════════════════════════════════════

@app.route("/api/vendor/find-customer", methods=["POST"])
@vendor_required
def find_customer():
    """
    Vendor looks up a customer at the window.
    Supports: phone number, rewards_id, or QR scan (also rewards_id).
    """
    body      = request.json or {}
    vendor_id = request.vendor_id
    phone     = re.sub(r'\D', '', body.get("phone") or "")
    rid       = (body.get("rewards_id") or "").strip().upper()

    customer = None

    if phone and len(phone) >= 10:
        # Look up global customer by phone
        row = sb.table("customers").select("*").eq("phone", phone).execute().data
        if row:
            customer = row[0]
    elif rid:
        row = sb.table("customers").select("*").eq("rewards_id", rid).execute().data
        if row:
            customer = row[0]

    if not customer:
        return err("Customer not found. Ask them to sign up at foodtruckrewards.app", 404)

    # Get their points/stats at THIS vendor specifically
    ct = sb.table("customer_trucks").select("*").eq("customer_id", customer["id"]).eq("vendor_id", vendor_id).execute().data
    vendor_pts    = ct[0]["points_balance"] if ct else 0
    vendor_visits = ct[0]["visit_count"]    if ct else 0

    return ok({
        "id":             customer["id"],
        "name":           customer["name"],
        "phone":          customer["phone"],
        "email":          customer["email"],
        "rewards_id":     customer["rewards_id"],
        "points_balance": vendor_pts,
        "visit_count":    vendor_visits,
        # Include streak info if they have a record at this vendor
        "current_streak": ct[0].get("current_streak", 0) if ct else 0,
    })


@app.route("/api/vendor/award-points", methods=["POST"])
@vendor_required
def award_points():
    """
    Vendor awards points for an order at the window.
    Calculates: base visit pts + order dollar pts + streak bonus.
    """
    body        = request.json or {}
    vendor_id   = request.vendor_id
    customer_id = body.get("customer_id")
    order_total = float(body.get("order_total") or 0)
    pts_awarded = body.get("pts_awarded")  # Optional override from frontend calc

    if not customer_id:
        return err("customer_id is required")

    # Load vendor config
    vendor = sb.table("vendors").select("*").eq("id", vendor_id).execute().data
    if not vendor:
        return err("Vendor not found", 404)
    vendor = vendor[0]

    # Load customer
    customer = sb.table("customers").select("*").eq("id", customer_id).execute().data
    if not customer:
        return err("Customer not found", 404)
    customer = customer[0]

    # Load or create customer_trucks record (per-vendor relationship)
    ct_row = sb.table("customer_trucks").select("*").eq("customer_id", customer_id).eq("vendor_id", vendor_id).execute().data

    today     = date.today()
    today_iso = today.isoformat()

    if ct_row:
        ct = ct_row[0]
        last_date = date.fromisoformat(ct["last_visit_date"]) if ct.get("last_visit_date") else None

        # Check already visited today
        if last_date == today:
            # Allow extra order points but no visit bonus
            order_pts = int(order_total * (vendor.get("pts_per_dollar") or 10))
            if order_pts <= 0:
                return err("Already awarded visit points today. Order total required for additional points.", 409)
            total_pts = order_pts
            new_streak = ct["current_streak"]
        else:
            if last_date and (today - last_date).days == 1:
                new_streak = ct["current_streak"] + 1
            else:
                new_streak = 1
            breakdown = _calc_points(vendor, order_total, ct["visit_count"], new_streak - 1)
            total_pts = breakdown["total"]

        new_balance  = ct["points_balance"] + total_pts
        new_total    = ct["points_total"]   + total_pts
        new_visits   = ct["visit_count"]    + (0 if last_date == today else 1)
        longest      = max(ct.get("longest_streak") or 0, new_streak)

        sb.table("customer_trucks").update({
            "points_balance":  new_balance,
            "points_total":    new_total,
            "visit_count":     new_visits,
            "current_streak":  new_streak,
            "longest_streak":  longest,
            "last_visit_date": today_iso,
        }).eq("id", ct["id"]).execute()

    else:
        # First time this customer visits this vendor
        breakdown = _calc_points(vendor, order_total, 0, 0)
        total_pts = breakdown["total"]
        new_streak = 1

        ct = sb.table("customer_trucks").insert({
            "customer_id":    customer_id,
            "vendor_id":      vendor_id,
            "points_balance": total_pts,
            "points_total":   total_pts,
            "visit_count":    1,
            "current_streak": 1,
            "longest_streak": 1,
            "last_visit_date": today_iso,
        }).execute().data[0]
        new_balance = total_pts

    # Log visit
    sb.table("visits").insert({
        "customer_id": customer_id,
        "vendor_id":   vendor_id,
        "pts_earned":  total_pts,
        "order_total": order_total,
        "streak_day":  new_streak,
        "awarded_by":  "vendor",
    }).execute()

    return ok({
        "pts_awarded":   total_pts,
        "new_balance":   new_balance,
        "new_streak":    new_streak,
        "customer_name": customer["name"],
    })


# ══════════════════════════════════════════════════════
#  VENDOR: REDEMPTION CONFIRMATION
#  Two-step: customer generates code → vendor confirms
# ══════════════════════════════════════════════════════

@app.route("/api/vendor/redemption/<code>", methods=["GET"])
@vendor_required
def lookup_redemption_code(code):
    """
    Vendor enters a customer's redemption code to see what it is
    before confirming. Does NOT mark it used yet.
    """
    code = code.upper().strip()
    vendor_id = request.vendor_id

    row = sb.table("redemptions").select(
        "*, rewards(name, emoji, pts_required), customers(name, rewards_id)"
    ).eq("code", code).eq("vendor_id", vendor_id).execute().data

    if not row:
        return err("Code not found or doesn't belong to your truck", 404)

    r = row[0]

    if r["status"] == "used":
        return err("This code has already been used")

    # Check expiry
    expires = r.get("expires_at")
    if expires:
        exp_dt = datetime.fromisoformat(expires.replace("Z", ""))
        if exp_dt < datetime.utcnow():
            sb.table("redemptions").update({"status": "expired"}).eq("id", r["id"]).execute()
            return err("This code has expired — customer needs to generate a new one")

    return ok({
        "redemption_id":   r["id"],
        "code":            code,
        "reward_name":     r["rewards"]["name"],
        "reward_emoji":    r["rewards"]["emoji"],
        "pts_cost":        r["rewards"]["pts_required"],
        "customer_name":   r["customers"]["name"],
        "customer_rid":    r["customers"]["rewards_id"],
        "status":          r["status"],
    })


@app.route("/api/vendor/confirm-redemption", methods=["POST"])
@vendor_required
def confirm_redemption():
    """
    Vendor confirms they gave the customer their reward.
    Marks code as used. Points were already deducted when customer generated the code.
    """
    body      = request.json or {}
    code      = (body.get("redemption_code") or "").upper().strip()
    vendor_id = request.vendor_id

    if not code:
        return err("Redemption code is required")

    row = sb.table("redemptions").select(
        "*, rewards(name, pts_required)"
    ).eq("code", code).eq("vendor_id", vendor_id).execute().data

    if not row:
        return err("Code not found", 404)

    r = row[0]

    if r["status"] == "used":
        return err("This code has already been confirmed")
    if r["status"] == "expired":
        return err("This code has expired")

    # Mark as used
    sb.table("redemptions").update({
        "status":       "used",
        "used_at":      datetime.utcnow().isoformat(),
        "confirmed_by": vendor_id,
    }).eq("id", r["id"]).execute()

    return ok({
        "confirmed":    True,
        "reward_name":  r["rewards"]["name"],
        "pts_deducted": r["rewards"]["pts_required"],
    })


# ══════════════════════════════════════════════════════
#  PUBLIC — TRUCK CONFIG (customer side, no auth)
# ══════════════════════════════════════════════════════

@app.route("/api/truck/<slug>", methods=["GET"])
@app.route("/api/truck/<slug>/config", methods=["GET"])
def get_truck_config(slug):
    """
    Public endpoint — called when customer scans a truck QR or opens their dashboard.
    Returns brand, rewards, prizes, tiers.
    """
    row = sb.table("vendors").select(
        "id, truck_name, tagline, emoji, slug, color_primary, color_secondary, "
        "pts_per_visit, pts_per_dollar, pts_spin_bonus, pts_streak_mult, pts_referral, "
        "double_first_visit, streak_bonus, birthday_reward, plan_active, trial_ends_at"
    ).eq("slug", slug).execute().data

    if not row:
        return err("Truck not found", 404)

    vendor = row[0]

    # Allow trial vendors
    is_active = vendor.get("plan_active")
    trial_end = vendor.get("trial_ends_at")
    if not is_active and trial_end:
        trial_dt = datetime.fromisoformat(trial_end.replace("Z", ""))
        if trial_dt > datetime.utcnow():
            is_active = True

    if not is_active:
        return err("This truck's loyalty program is not currently active", 403)

    rewards = sb.table("rewards").select("*").eq("vendor_id", vendor["id"]).eq("is_active", True).order("sort_order").execute().data
    prizes  = sb.table("spin_prizes").select("*").eq("vendor_id", vendor["id"]).eq("is_active", True).execute().data
    tiers   = sb.table("tiers").select("*").eq("vendor_id", vendor["id"]).order("pts_threshold").execute().data

    return ok({
        "vendor":  vendor,
        "rewards": rewards,
        "prizes":  prizes,
        "tiers":   tiers,
    })


# ══════════════════════════════════════════════════════
#  CUSTOMER AUTH — Global accounts (not per-truck)
# ══════════════════════════════════════════════════════

@app.route("/api/customer/signup", methods=["POST"])
def customer_signup():
    """
    Create a global customer account.
    One account works across all trucks.
    """
    body  = request.json or {}
    name  = (body.get("name") or "").strip()
    phone = re.sub(r'\D', '', body.get("phone") or "")
    email = (body.get("email") or "").strip().lower()

    if not name:
        return err("Name is required")
    if len(phone) < 10:
        return err("Valid phone number is required")
    if not email or "@" not in email:
        return err("Valid email address is required")

    # Check for existing account
    existing_phone = sb.table("customers").select("id").eq("phone", phone).execute().data
    if existing_phone:
        return err("An account with this phone number already exists. Please sign in.")

    existing_email = sb.table("customers").select("id").eq("email", email).execute().data
    if existing_email:
        return err("An account with this email already exists. Please sign in.")

    # Generate unique rewards ID
    rid = gen_rewards_id()
    while sb.table("customers").select("id").eq("rewards_id", rid).execute().data:
        rid = gen_rewards_id()

    # Generate referral code
    ref_code = "".join(random.choices(string.ascii_uppercase + string.digits, k=8))
    while sb.table("customers").select("id").eq("referral_code", ref_code).execute().data:
        ref_code = "".join(random.choices(string.ascii_uppercase + string.digits, k=8))

    # Check for referral from URL
    ref_by_code = body.get("ref_code")
    referred_by = None
    if ref_by_code:
        ref = sb.table("customers").select("id").eq("referral_code", ref_by_code).execute().data
        if ref:
            referred_by = ref[0]["id"]

    customer = sb.table("customers").insert({
        "name":          name,
        "phone":         phone,
        "email":         email,
        "rewards_id":    rid,
        "referral_code": ref_code,
        "referred_by":   referred_by,
    }).execute().data[0]

    token = make_customer_token(customer["id"])
    return ok({
        "token":    token,
        "customer": _safe_customer(customer),
        "trucks":   [],
    }), 201


@app.route("/api/customer/login", methods=["POST"])
def customer_login():
    """
    Sign in with phone OR email.
    Returns customer + all trucks they've joined.
    """
    body  = request.json or {}
    phone = re.sub(r'\D', '', body.get("phone") or "")
    email = (body.get("email") or "").strip().lower()

    if not phone and not email:
        return err("Phone number or email is required")

    customer = None
    if phone and len(phone) >= 10:
        row = sb.table("customers").select("*").eq("phone", phone).execute().data
        if row:
            customer = row[0]
    if not customer and email:
        row = sb.table("customers").select("*").eq("email", email).execute().data
        if row:
            customer = row[0]

    if not customer:
        return err("No account found. Please sign up first.", 404)

    # Load all trucks this customer has joined with their per-truck stats
    trucks = _get_customer_trucks(customer["id"])

    token = make_customer_token(customer["id"])
    return ok({
        "token":    token,
        "customer": _safe_customer(customer),
        "trucks":   trucks,
    })


def _get_customer_trucks(customer_id: str) -> list:
    """
    Get all trucks a customer has joined, with their per-truck stats merged in.
    """
    ct_rows = sb.table("customer_trucks").select(
        "*, vendors(id, truck_name, tagline, emoji, slug, color_primary, color_secondary)"
    ).eq("customer_id", customer_id).execute().data

    result = []
    for ct in ct_rows:
        vendor = ct.pop("vendors", {}) or {}
        entry  = {**vendor}
        entry["points_balance"]  = ct.get("points_balance", 0)
        entry["points_total"]    = ct.get("points_total", 0)
        entry["visit_count"]     = ct.get("visit_count", 0)
        entry["current_streak"]  = ct.get("current_streak", 0)
        entry["longest_streak"]  = ct.get("longest_streak", 0)
        entry["total_saved"]     = ct.get("total_saved", 0)
        entry["last_visit_date"] = ct.get("last_visit_date")
        result.append(entry)

    return result


# ══════════════════════════════════════════════════════
#  CUSTOMER: JOIN A TRUCK
# ══════════════════════════════════════════════════════

@app.route("/api/customer/join-truck", methods=["POST"])
def customer_join_truck():
    """
    Customer joins a truck by slug (from QR scan or direct link).
    Creates a customer_trucks row if one doesn't exist.
    Returns the truck's public config.
    """
    body        = request.json or {}
    slug        = (body.get("slug") or "").strip().lower()
    customer_id = body.get("customer_id")

    if not slug:
        return err("Truck code (slug) is required")
    if not customer_id:
        return err("customer_id is required — please sign in")

    # Find truck
    vendor = sb.table("vendors").select("*").eq("slug", slug).execute().data
    if not vendor:
        return err("Truck not found. Double-check the code.", 404)
    vendor = vendor[0]

    # Check customer exists
    customer = sb.table("customers").select("id, name").eq("id", customer_id).execute().data
    if not customer:
        return err("Customer account not found", 404)

    # Create customer_trucks link if it doesn't exist
    existing = sb.table("customer_trucks").select("id").eq("customer_id", customer_id).eq("vendor_id", vendor["id"]).execute().data
    if not existing:
        sb.table("customer_trucks").insert({
            "customer_id":    customer_id,
            "vendor_id":      vendor["id"],
            "points_balance": 0,
            "points_total":   0,
            "visit_count":    0,
            "current_streak": 0,
            "longest_streak": 0,
            "total_saved":    0.0,
        }).execute()

    # Return truck public config
    rewards = sb.table("rewards").select("*").eq("vendor_id", vendor["id"]).eq("is_active", True).order("sort_order").execute().data
    prizes  = sb.table("spin_prizes").select("*").eq("vendor_id", vendor["id"]).eq("is_active", True).execute().data
    tiers   = sb.table("tiers").select("*").eq("vendor_id", vendor["id"]).order("pts_threshold").execute().data

    # Build truck entry for customer's list
    ct = sb.table("customer_trucks").select("*").eq("customer_id", customer_id).eq("vendor_id", vendor["id"]).execute().data[0]
    truck_entry = {
        "id":             vendor["id"],
        "truck_name":     vendor["truck_name"],
        "tagline":        vendor.get("tagline", ""),
        "emoji":          vendor.get("emoji", "🚚"),
        "slug":           vendor["slug"],
        "color_primary":  vendor.get("color_primary", "#FF5722"),
        "color_secondary":vendor.get("color_secondary", "#F9A825"),
        "points_balance": ct["points_balance"],
        "points_total":   ct["points_total"],
        "visit_count":    ct["visit_count"],
        "current_streak": ct["current_streak"],
        "total_saved":    ct["total_saved"],
        "rewards":        rewards,
        "prizes":         prizes,
        "tiers":          tiers,
    }

    return ok({"truck": truck_entry, "is_new": not bool(existing)}), 201


# ══════════════════════════════════════════════════════
#  CUSTOMER: CHECK IN (self-service via QR scan)
# ══════════════════════════════════════════════════════

@app.route("/api/customer/visit", methods=["POST"])
def record_visit():
    """
    Customer checks in at a truck by scanning the truck's QR code.
    Awards base visit points + spin result.
    Order-based points are separate via /api/vendor/award-points.
    """
    body        = request.json or {}
    customer_id = body.get("customer_id")
    vendor_id   = body.get("vendor_id")

    if not customer_id or not vendor_id:
        return err("customer_id and vendor_id are required")

    customer = sb.table("customers").select("*").eq("id", customer_id).execute().data
    if not customer:
        return err("Customer not found", 404)
    customer = customer[0]

    vendor = sb.table("vendors").select("*").eq("id", vendor_id).execute().data
    if not vendor:
        return err("Vendor not found", 404)
    vendor = vendor[0]

    today     = date.today()
    today_iso = today.isoformat()

    # Get or create customer_trucks record
    ct_row = sb.table("customer_trucks").select("*").eq("customer_id", customer_id).eq("vendor_id", vendor_id).execute().data

    if ct_row:
        ct = ct_row[0]
        last_date = date.fromisoformat(ct["last_visit_date"]) if ct.get("last_visit_date") else None

        if last_date == today:
            return err("Already checked in today — come back tomorrow! 🔥", 409)

        new_streak = (ct["current_streak"] + 1) if (last_date and (today - last_date).days == 1) else 1
        longest    = max(ct.get("longest_streak") or 0, new_streak)

        # Calculate points
        breakdown = _calc_points(vendor, 0, ct["visit_count"], new_streak - 1)
        total_pts = breakdown["total"]

        new_balance = ct["points_balance"] + total_pts
        new_total   = ct["points_total"]   + total_pts
        new_visits  = ct["visit_count"]    + 1

        # Check tier upgrade
        tiers = sb.table("tiers").select("*").eq("vendor_id", vendor_id).order("pts_threshold", desc=True).execute().data
        new_tier_id    = ct.get("current_tier_id")
        tier_upgraded  = False
        for tier in tiers:
            if new_total >= tier["pts_threshold"]:
                if tier["id"] != ct.get("current_tier_id"):
                    new_tier_id   = tier["id"]
                    tier_upgraded = True
                break

        sb.table("customer_trucks").update({
            "points_balance":  new_balance,
            "points_total":    new_total,
            "visit_count":     new_visits,
            "current_streak":  new_streak,
            "longest_streak":  longest,
            "last_visit_date": today_iso,
            "current_tier_id": new_tier_id,
        }).eq("id", ct["id"]).execute()

    else:
        # First visit to this truck
        breakdown = _calc_points(vendor, 0, 0, 0)
        total_pts = breakdown["total"]
        new_streak = 1; new_balance = total_pts; new_visits = 1
        new_total  = total_pts; tier_upgraded = False; new_tier_id = None

        ct = sb.table("customer_trucks").insert({
            "customer_id":    customer_id,
            "vendor_id":      vendor_id,
            "points_balance": total_pts,
            "points_total":   total_pts,
            "visit_count":    1,
            "current_streak": 1,
            "longest_streak": 1,
            "last_visit_date": today_iso,
        }).execute().data[0]

    # Log visit
    visit = sb.table("visits").insert({
        "customer_id": customer_id,
        "vendor_id":   vendor_id,
        "pts_earned":  total_pts,
        "streak_day":  new_streak,
        "awarded_by":  "customer",
    }).execute().data[0]

    # Spin result (weighted random from vendor's prizes)
    prizes = sb.table("spin_prizes").select("*").eq("vendor_id", vendor_id).eq("is_active", True).execute().data
    spin_result = None
    if prizes:
        total_weight = sum(p["probability"] for p in prizes)
        r = random.uniform(0, total_weight)
        cum = 0; won = prizes[-1]
        for p in prizes:
            cum += p["probability"]
            if r <= cum:
                won = p; break

        spin_pts = int(won.get("prize_value") or won.get("pts") or 25)

        spin_result = sb.table("spin_results").insert({
            "customer_id": customer_id,
            "vendor_id":   vendor_id,
            "visit_id":    visit["id"],
            "prize_id":    won["id"],
            "prize_name":  won["name"],
            "prize_type":  won.get("prize_type", "points"),
            "prize_value": won.get("prize_value", "25"),
        }).execute().data[0]

        # Award spin bonus points
        sb.table("customer_trucks").update({
            "points_balance": new_balance + spin_pts,
            "points_total":   new_total   + spin_pts,
        }).eq("customer_id", customer_id).eq("vendor_id", vendor_id).execute()

        sb.table("visits").update({"spin_result_id": spin_result["id"]}).eq("id", visit["id"]).execute()

    # Handle referral bonus (first ever visit to any truck)
    global_visits = sb.table("visits").select("id", count="exact").eq("customer_id", customer_id).execute()
    if global_visits.count == 1 and customer.get("referred_by"):
        # This is their very first visit anywhere — award referral bonus
        ref_ct = sb.table("customer_trucks").select("*").eq("customer_id", customer["referred_by"]).eq("vendor_id", vendor_id).execute().data
        ref_pts = vendor.get("pts_referral") or 100
        if ref_ct:
            sb.table("customer_trucks").update({
                "points_balance": ref_ct[0]["points_balance"] + ref_pts,
                "points_total":   ref_ct[0]["points_total"]   + ref_pts,
            }).eq("id", ref_ct[0]["id"]).execute()

    return ok({
        "visit":         visit,
        "pts_earned":    total_pts,
        "new_balance":   new_balance,
        "new_streak":    new_streak,
        "spin_result":   spin_result,
        "tier_upgraded": tier_upgraded,
        "new_tier_id":   new_tier_id,
    })


# ══════════════════════════════════════════════════════
#  CUSTOMER: GENERATE REDEMPTION CODE
#  Customer side — generates code, deducts points immediately
# ══════════════════════════════════════════════════════

@app.route("/api/customer/redeem", methods=["POST"])
def customer_redeem():
    """
    Customer requests to redeem a reward.
    Deducts points and generates a one-time code.
    Vendor then confirms via /api/vendor/confirm-redemption.
    """
    body        = request.json or {}
    customer_id = body.get("customer_id")
    reward_id   = body.get("reward_id")

    if not customer_id or not reward_id:
        return err("customer_id and reward_id are required")

    reward = sb.table("rewards").select("*").eq("id", reward_id).execute().data
    if not reward:
        return err("Reward not found", 404)
    reward = reward[0]

    vendor_id = reward["vendor_id"]

    # Check customer_trucks balance
    ct = sb.table("customer_trucks").select("*").eq("customer_id", customer_id).eq("vendor_id", vendor_id).execute().data
    if not ct:
        return err("You haven't visited this truck yet")
    ct = ct[0]

    if ct["points_balance"] < reward["pts_required"]:
        return err(f"Not enough points. Need {reward['pts_required']}, you have {ct['points_balance']}")

    # Generate unique code
    code = gen_code()
    while sb.table("redemptions").select("id").eq("code", code).execute().data:
        code = gen_code()

    redemption = sb.table("redemptions").insert({
        "customer_id": customer_id,
        "vendor_id":   vendor_id,
        "reward_id":   reward_id,
        "pts_spent":   reward["pts_required"],
        "code":        code,
        "status":      "pending",
        "expires_at":  (datetime.utcnow() + timedelta(hours=24)).isoformat(),
    }).execute().data[0]

    # Deduct points immediately
    saved_value = float(body.get("reward_value") or 5.0)
    sb.table("customer_trucks").update({
        "points_balance": ct["points_balance"] - reward["pts_required"],
        "total_saved":    float(ct.get("total_saved") or 0) + saved_value,
    }).eq("id", ct["id"]).execute()

    return ok({
        "code":        code,
        "reward_name": reward["name"],
        "reward_emoji": reward["emoji"],
        "pts_spent":   reward["pts_required"],
        "expires_at":  redemption["expires_at"],
    })


# ══════════════════════════════════════════════════════
#  CUSTOMER: HISTORY
# ══════════════════════════════════════════════════════

@app.route("/api/customer/<customer_id>/history", methods=["GET"])
def customer_history(customer_id):
    visits = sb.table("visits").select(
        "*, spin_results(prize_name, prize_value)"
    ).eq("customer_id", customer_id).order("created_at", desc=True).limit(50).execute()

    redemptions = sb.table("redemptions").select(
        "*, rewards(name, emoji)"
    ).eq("customer_id", customer_id).order("created_at", desc=True).limit(30).execute()

    return ok({
        "visits":      visits.data,
        "redemptions": redemptions.data,
    })


@app.route("/api/customer/<customer_id>/trucks", methods=["GET"])
def customer_trucks(customer_id):
    """Return all trucks a customer has joined with per-truck stats."""
    trucks = _get_customer_trucks(customer_id)
    return ok(trucks)


# ══════════════════════════════════════════════════════
#  STRIPE WEBHOOKS (billing)
# ══════════════════════════════════════════════════════

@app.route("/api/webhooks/stripe", methods=["POST"])
def stripe_webhook():
    try:
        import stripe
        stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")
        payload = request.data
        sig     = request.headers.get("Stripe-Signature")
        event   = stripe.Webhook.construct_event(
            payload, sig, os.environ.get("STRIPE_WEBHOOK_SECRET", "")
        )
    except Exception as e:
        return err(str(e))

    etype = event["type"]
    if etype == "customer.subscription.created":
        sub = event["data"]["object"]
        sb.table("vendors").update({
            "stripe_sub_id": sub["id"],
            "plan_active":   True,
        }).eq("stripe_customer_id", sub["customer"]).execute()

    elif etype in ("customer.subscription.deleted", "customer.subscription.paused"):
        sub = event["data"]["object"]
        sb.table("vendors").update({"plan_active": False}).eq("stripe_customer_id", sub["customer"]).execute()

    return ok("received")


# ══════════════════════════════════════════════════════
#  RUN
# ══════════════════════════════════════════════════════

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
