"""
Food Truck Rewards — Flask API  v2.0
Deploy on Render (Python 3.11+)

pip install flask flask-cors supabase python-jose bcrypt stripe python-dotenv

Environment variables (Render dashboard):
  SUPABASE_URL
  SUPABASE_SERVICE_KEY       ← service role key
  JWT_SECRET                 ← any long random string
  STRIPE_SECRET_KEY          ← from Stripe dashboard
  STRIPE_WEBHOOK_SECRET      ← from Stripe webhook settings
  STRIPE_PRICE_ID            ← recurring $9.99/mo price ID from Stripe
  ADMIN_PASSWORD             ← password for your admin dashboard
  GRACE_PERIOD_DAYS          ← days before locking after failed payment (default 5)
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

sb: Client = create_client(
    os.environ["SUPABASE_URL"],
    os.environ["SUPABASE_SERVICE_KEY"]
)

JWT_SECRET         = os.environ["JWT_SECRET"]
JWT_ALGO           = "HS256"
JWT_EXPIRY         = 30   # days
GRACE_PERIOD_DAYS  = int(os.environ.get("GRACE_PERIOD_DAYS", 5))
MONTHLY_PRICE      = 9.99
STRIPE_PRICE_ID    = os.environ.get("STRIPE_PRICE_ID", "")
ADMIN_PASSWORD     = os.environ.get("ADMIN_PASSWORD", "changeme123")


# ══════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════

def make_vendor_token(vendor_id: str) -> str:
    return jwt.encode({
        "sub": vendor_id, "type": "vendor",
        "exp": datetime.utcnow() + timedelta(days=JWT_EXPIRY)
    }, JWT_SECRET, algorithm=JWT_ALGO)


def make_customer_token(customer_id: str) -> str:
    return jwt.encode({
        "sub": customer_id, "type": "customer",
        "exp": datetime.utcnow() + timedelta(days=JWT_EXPIRY * 2)
    }, JWT_SECRET, algorithm=JWT_ALGO)


def make_admin_token() -> str:
    return jwt.encode({
        "sub": "admin", "type": "admin",
        "exp": datetime.utcnow() + timedelta(hours=12)
    }, JWT_SECRET, algorithm=JWT_ALGO)


def vendor_required(f):
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


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return err("Missing token", 401)
        try:
            payload = jwt.decode(auth[7:], JWT_SECRET, algorithms=[JWT_ALGO])
            if payload.get("type") != "admin":
                return err("Admin access required", 403)
        except JWTError:
            return err("Invalid or expired token", 401)
        return f(*args, **kwargs)
    return decorated


def vendor_active_required(f):
    """Checks vendor is paid/trial/grace before allowing access."""
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

        vendor = sb.table("vendors").select(
            "id, plan_active, trial_ends_at, payment_failed_at, promo_expires_at"
        ).eq("id", request.vendor_id).execute().data
        if not vendor:
            return err("Vendor not found", 404)
        v = vendor[0]

        if _vendor_is_active(v):
            return f(*args, **kwargs)
        return err("Your subscription is inactive. Please update your payment method.", 403)
    return decorated


def _parse_dt(iso_str: str):
    """Parse ISO datetime string, always returning timezone-naive UTC datetime."""
    if not iso_str:
        return None
    # Remove Z and +00:00 suffixes, strip microseconds if needed
    s = iso_str.replace("Z", "").replace("+00:00", "").split("+")[0].strip()
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None


def _vendor_is_active(v: dict) -> bool:
    """Return True if vendor should have access."""
    now = datetime.utcnow()
    if v.get("plan_active"):
        return True
    trial = _parse_dt(v.get("trial_ends_at"))
    if trial and trial > now:
        return True
    promo = _parse_dt(v.get("promo_expires_at"))
    if promo and promo > now:
        return True
    failed = _parse_dt(v.get("payment_failed_at"))
    if failed and (now - failed).days <= GRACE_PERIOD_DAYS:
        return True
    return False


def _vendor_status(v: dict) -> str:
    """Return human-readable status string."""
    now = datetime.utcnow()
    if v.get("plan_active"):
        return "active"
    trial = _parse_dt(v.get("trial_ends_at"))
    if trial and trial > now:
        return "trial"
    promo = _parse_dt(v.get("promo_expires_at"))
    if promo and promo > now:
        return "promo"
    failed = _parse_dt(v.get("payment_failed_at"))
    if failed and (now - failed).days <= GRACE_PERIOD_DAYS:
        return "grace"
    return "inactive"


def gen_code() -> str:
    chars = string.ascii_uppercase + string.digits
    return "STK-" + "".join(random.choices(chars, k=4))


def gen_rewards_id() -> str:
    return "FTR-" + "".join(random.choices(string.digits, k=6))


def gen_vendor_number() -> str:
    """Generate unique 4-digit vendor number like #1042."""
    while True:
        num = str(random.randint(1000, 9999))
        existing = sb.table("vendors").select("id").eq("vendor_number", num).execute().data
        if not existing:
            return num


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
    c.pop("password_hash", None)
    return c


def _calc_points(vendor: dict, order_total: float,
                 visit_count: int, current_streak: int) -> dict:
    pts_per_dollar = vendor.get("pts_per_dollar") or 10
    pts_per_visit  = vendor.get("pts_per_visit")  or 50
    streak_mult    = vendor.get("pts_streak_mult") or 1.5

    base      = pts_per_visit
    order_pts = int(order_total * pts_per_dollar) if order_total else 0
    breakdown = {"base_visit": base, "order_pts": order_pts}

    if vendor.get("double_first_visit") and visit_count == 0:
        base *= 2
        breakdown["first_visit_bonus"] = pts_per_visit

    streak_bonus = 0
    if vendor.get("streak_bonus") and current_streak > 1:
        streak_bonus = int(base * (streak_mult - 1))
        breakdown["streak_bonus"] = streak_bonus

    total = base + order_pts + streak_bonus
    breakdown["total"] = total
    return breakdown


def _get_customer_trucks(customer_id: str) -> list:
    ct_rows = sb.table("customer_trucks").select(
        "*, vendors(id, truck_name, tagline, emoji, slug, "
        "color_primary, color_secondary, vendor_number, location_today)"
    ).eq("customer_id", customer_id).execute().data

    result = []
    for ct in ct_rows:
        vendor = ct.pop("vendors", {}) or {}
        entry  = {**vendor,
                  "points_balance":  ct.get("points_balance", 0),
                  "points_total":    ct.get("points_total", 0),
                  "visit_count":     ct.get("visit_count", 0),
                  "current_streak":  ct.get("current_streak", 0),
                  "longest_streak":  ct.get("longest_streak", 0),
                  "total_saved":     ct.get("total_saved", 0),
                  "last_visit_date": ct.get("last_visit_date")}
        result.append(entry)
    return result


def _stripe():
    import stripe
    stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")
    return stripe


# ══════════════════════════════════════════════════════
#  HEALTH
# ══════════════════════════════════════════════════════

@app.route("/")
def health():
    return ok("Food Truck Rewards API v2 🚚")


# ══════════════════════════════════════════════════════
#  ADMIN AUTH
# ══════════════════════════════════════════════════════

@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    body = request.json or {}
    if body.get("password") != ADMIN_PASSWORD:
        return err("Invalid password", 401)
    return ok({"token": make_admin_token()})


# ══════════════════════════════════════════════════════
#  ADMIN — OVERVIEW DATA
# ══════════════════════════════════════════════════════

@app.route("/api/admin/stats", methods=["GET"])
@admin_required
def admin_stats():
    vendors     = sb.table("vendors").select("id, plan_active, trial_ends_at, "
                  "payment_failed_at, promo_expires_at, created_at, "
                  "truck_name, email, vendor_number, slug").execute().data
    customers   = sb.table("customers").select("id", count="exact").execute()
    visits      = sb.table("visits").select("id", count="exact").execute()
    redemptions = sb.table("redemptions").select("id", count="exact").execute()
    promos      = sb.table("promo_codes").select("*").execute().data

    active_vendors = [v for v in vendors if _vendor_is_active(v)]
    paying_vendors = [v for v in vendors if v.get("plan_active")]
    trial_vendors  = [v for v in vendors
                      if not v.get("plan_active") and _vendor_is_active(v)]
    grace_vendors  = [v for v in vendors
                      if not v.get("plan_active") and v.get("payment_failed_at")]

    mrr = len(paying_vendors) * MONTHLY_PRICE

    return ok({
        "vendors":         vendors,
        "total_vendors":   len(vendors),
        "active_vendors":  len(active_vendors),
        "paying_vendors":  len(paying_vendors),
        "trial_vendors":   len(trial_vendors),
        "grace_vendors":   len(grace_vendors),
        "total_customers": customers.count or 0,
        "total_visits":    visits.count    or 0,
        "total_redemptions": redemptions.count or 0,
        "mrr":             round(mrr, 2),
        "promo_codes":     promos,
    })


@app.route("/api/admin/vendor/<vendor_id>", methods=["GET"])
@admin_required
def admin_get_vendor(vendor_id):
    vendor = sb.table("vendors").select("*").eq("id", vendor_id).execute().data
    if not vendor:
        return err("Not found", 404)
    v = _safe_vendor(vendor[0])
    members = sb.table("customer_trucks").select("id", count="exact").eq("vendor_id", vendor_id).execute()
    visits  = sb.table("visits").select("id", count="exact").eq("vendor_id", vendor_id).execute()
    v["total_members"] = members.count or 0
    v["total_visits"]  = visits.count  or 0
    return ok(v)


@app.route("/api/admin/vendor/<vendor_id>/override", methods=["POST"])
@admin_required
def admin_override_vendor(vendor_id):
    """Manually activate or deactivate a vendor."""
    body   = request.json or {}
    active = bool(body.get("plan_active", True))
    sb.table("vendors").update({
        "plan_active":       active,
        "payment_failed_at": None if active else None,
    }).eq("id", vendor_id).execute()
    return ok(f"Vendor {'activated' if active else 'deactivated'}")


# ══════════════════════════════════════════════════════
#  ADMIN — PROMO CODES
# ══════════════════════════════════════════════════════

@app.route("/api/admin/promo-codes", methods=["GET"])
@admin_required
def list_promo_codes():
    rows = sb.table("promo_codes").select("*").order("created_at", desc=True).execute()
    return ok(rows.data)


@app.route("/api/admin/promo-codes", methods=["POST"])
@admin_required
def create_promo_code():
    body     = request.json or {}
    code     = (body.get("code") or "").strip().upper()
    months   = int(body.get("free_months") or 1)
    max_uses = body.get("max_uses")          # None = unlimited

    if not code:
        return err("Code is required")
    if len(code) < 3:
        return err("Code must be at least 3 characters")

    existing = sb.table("promo_codes").select("id").eq("code", code).execute().data
    if existing:
        return err("A promo code with that name already exists")

    row = sb.table("promo_codes").insert({
        "code":       code,
        "free_months": months,
        "max_uses":    max_uses,
        "uses":        0,
        "is_active":   True,
    }).execute().data[0]
    return ok(row), 201


@app.route("/api/admin/promo-codes/<code_id>", methods=["PATCH"])
@admin_required
def update_promo_code(code_id):
    body    = request.json or {}
    allowed = ["is_active", "free_months", "max_uses"]
    updates = {k: v for k, v in body.items() if k in allowed}
    row = sb.table("promo_codes").update(updates).eq("id", code_id).execute().data[0]
    return ok(row)


@app.route("/api/admin/promo-codes/<code_id>", methods=["DELETE"])
@admin_required
def delete_promo_code(code_id):
    sb.table("promo_codes").delete().eq("id", code_id).execute()
    return ok("Deleted")


# ══════════════════════════════════════════════════════
#  VENDOR AUTH + BILLING
# ══════════════════════════════════════════════════════

@app.route("/api/vendor/signup", methods=["POST"])
def vendor_signup():
    body         = request.json or {}
    email        = (body.get("email") or "").strip().lower()
    password     = body.get("password") or ""
    truck_name   = (body.get("truck_name") or "My Food Truck").strip()
    owner_name   = (body.get("owner_name") or "").strip()
    promo_code   = (body.get("promo_code") or "").strip().upper()

    if not email or not password:
        return err("Email and password are required")
    if len(password) < 8:
        return err("Password must be at least 8 characters")

    existing = sb.table("vendors").select("id").ilike("email", email).execute()
    if existing.data:
        return err("An account with this email already exists")

    pw_hash      = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    base_slug    = slugify(truck_name)
    slug         = base_slug
    i = 1
    while sb.table("vendors").select("id").eq("slug", slug).execute().data:
        slug = f"{base_slug}{i}"; i += 1

    vendor_number = gen_vendor_number()
    trial_end     = (datetime.utcnow() + timedelta(days=14)).isoformat()

    # Handle promo code
    promo_expires = None
    if promo_code:
        pc = sb.table("promo_codes").select("*").eq("code", promo_code).eq("is_active", True).execute().data
        if not pc:
            return err("Invalid or expired promo code")
        pc = pc[0]
        max_uses = pc.get("max_uses")
        if max_uses and pc.get("uses", 0) >= max_uses:
            return err("This promo code has reached its maximum uses")
        months = pc.get("free_months", 1)
        promo_expires = (datetime.utcnow() + timedelta(days=30 * months)).isoformat()
        # Increment uses
        sb.table("promo_codes").update({"uses": pc["uses"] + 1}).eq("id", pc["id"]).execute()

    vendor = sb.table("vendors").insert({
        "email":           email,
        "password_hash":   pw_hash,
        "truck_name":      truck_name,
        "owner_name":      owner_name,
        "slug":            slug,
        "vendor_number":   vendor_number,
        "trial_ends_at":   trial_end,
        "promo_expires_at": promo_expires,
        "plan_active":     False,   # becomes True once Stripe subscription is active
        "pts_per_visit":   50,
        "pts_per_dollar":  10,
        "pts_spin_bonus":  25,
        "pts_streak_mult": 1.5,
        "pts_referral":    100,
        "double_first_visit": True,
        "streak_bonus":    True,
        "birthday_reward": False,
        "winback_enabled": False,
        "referral_bonus":  True,
    }).execute().data[0]

    # Seed defaults
    try:
        sb.rpc("seed_vendor_defaults", {"v_id": vendor["id"]}).execute()
    except Exception:
        pass

    # Create Stripe customer
    stripe_customer_id = None
    try:
        stripe = _stripe()
        sc = stripe.Customer.create(
            email=email,
            name=truck_name,
            metadata={"vendor_id": vendor["id"], "vendor_number": vendor_number}
        )
        stripe_customer_id = sc.id
        sb.table("vendors").update({"stripe_customer_id": sc.id}).eq("id", vendor["id"]).execute()
    except Exception:
        pass  # Stripe optional during development

    token = make_vendor_token(vendor["id"])
    return ok({
        "token":              token,
        "vendor":             _safe_vendor(vendor),
        "stripe_customer_id": stripe_customer_id,
        "trial_ends_at":      trial_end,
    }), 201


@app.route("/api/vendor/login", methods=["POST"])
def vendor_login():
    body     = request.json or {}
    email    = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""

    row = sb.table("vendors").select("*").ilike("email", email).execute().data
    if not row:
        print(f"[LOGIN FAIL] No vendor found for email: {email}")
        return err("Invalid email or password", 401)
    vendor = row[0]

    pw_hash = vendor.get("password_hash")
    if not pw_hash:
        print(f"[LOGIN FAIL] No password_hash for vendor: {email}")
        return err("Account setup incomplete. Please contact support.", 401)

    try:
        if not bcrypt.checkpw(password.encode(), pw_hash.encode()):
            print(f"[LOGIN FAIL] Wrong password for: {email}")
            return err("Invalid email or password", 401)
    except Exception as e:
        print(f"[LOGIN ERROR] bcrypt error for {email}: {e}")
        return err("Login error — please contact support", 500)

    is_active = _vendor_is_active(vendor)
    token     = make_vendor_token(vendor["id"])

    return ok({
        "token":     token,
        "vendor":    _safe_vendor(vendor),
        "is_active": is_active,
        "status":    _vendor_status(vendor),
    })


@app.route("/api/vendor/me", methods=["GET"])
@vendor_required
def vendor_me():
    vendor = sb.table("vendors").select("*").eq("id", request.vendor_id).execute().data[0]
    v = _safe_vendor(vendor)
    v["status"]    = _vendor_status(vendor)
    v["is_active"] = _vendor_is_active(vendor)
    return ok(v)


# ══════════════════════════════════════════════════════
#  VENDOR — STRIPE BILLING
# ══════════════════════════════════════════════════════

@app.route("/api/vendor/create-setup-intent", methods=["POST"])
@vendor_required
def create_setup_intent():
    """
    Creates a Stripe SetupIntent so the frontend can securely
    collect and save the vendor's card without charging immediately.
    The card gets attached to their Stripe customer for future use.
    """
    vendor = sb.table("vendors").select(
        "stripe_customer_id, email, truck_name"
    ).eq("id", request.vendor_id).execute().data

    if not vendor:
        return err("Vendor not found", 404)
    vendor = vendor[0]

    stripe = _stripe()

    try:
        # Create Stripe customer if they don't have one yet
        customer_id = vendor.get("stripe_customer_id")
        if not customer_id:
            sc = stripe.Customer.create(
                email=vendor["email"],
                name=vendor["truck_name"],
                metadata={"vendor_id": request.vendor_id},
                # Stripe will send automatic invoice emails to this address
                invoice_settings={"default_payment_method": None}
            )
            customer_id = sc.id
            sb.table("vendors").update({
                "stripe_customer_id": customer_id
            }).eq("id", request.vendor_id).execute()

        # Create SetupIntent — this lets frontend save card without charging
        setup_intent = stripe.SetupIntent.create(
            customer=customer_id,
            payment_method_types=["card"],
            usage="off_session",  # card will be charged later automatically
            metadata={"vendor_id": request.vendor_id}
        )

        return ok({"client_secret": setup_intent.client_secret})

    except Exception as e:
        return err(str(e))


@app.route("/api/vendor/create-subscription", methods=["POST"])
@vendor_required
def create_subscription():
    """
    Creates a Stripe subscription with 14-day trial.
    payment_method_id comes from the confirmed SetupIntent.
    """
    body           = request.json or {}
    payment_method = body.get("payment_method_id")

    if not payment_method:
        return err("payment_method_id is required")

    vendor = sb.table("vendors").select("*").eq("id", request.vendor_id).execute().data[0]
    stripe = _stripe()

    try:
        # Set as default payment method on customer
        stripe.PaymentMethod.attach(payment_method, customer=vendor["stripe_customer_id"])
        stripe.Customer.modify(
            vendor["stripe_customer_id"],
            invoice_settings={"default_payment_method": payment_method}
        )

        # Create subscription with 14-day trial — no charge today
        subscription = stripe.Subscription.create(
            customer=vendor["stripe_customer_id"],
            items=[{"price": STRIPE_PRICE_ID}],
            trial_period_days=14,
            default_payment_method=payment_method,
            expand=["latest_invoice.payment_intent"],
            # Automatically email invoice receipts after each payment
            collection_method="charge_automatically",
        )

        sb.table("vendors").update({
            "stripe_sub_id": subscription.id,
            "plan_active":   True,
            "payment_failed_at": None,
        }).eq("id", request.vendor_id).execute()

        return ok({
            "subscription_id": subscription.id,
            "status":          subscription.status,
            "trial_end":       subscription.trial_end,
        })

    except Exception as e:
        return err(str(e))


@app.route("/api/vendor/billing-portal", methods=["POST"])
@vendor_required
def billing_portal():
    """Return Stripe billing portal URL for vendor to manage payment."""
    vendor = sb.table("vendors").select("stripe_customer_id").eq("id", request.vendor_id).execute().data[0]
    stripe = _stripe()
    try:
        session = stripe.billing_portal.Session.create(
            customer=vendor["stripe_customer_id"],
            return_url="https://truckloyal-app.onrender.com",
        )
        return ok({"url": session.url})
    except Exception as e:
        return err(str(e))


@app.route("/api/vendor/cancel-subscription", methods=["POST"])
@vendor_required
def cancel_subscription():
    """Cancel at end of current billing period."""
    vendor = sb.table("vendors").select("stripe_sub_id, stripe_customer_id").eq("id", request.vendor_id).execute().data[0]
    stripe = _stripe()
    try:
        if vendor.get("stripe_sub_id"):
            stripe.Subscription.modify(
                vendor["stripe_sub_id"],
                cancel_at_period_end=True
            )
        sb.table("vendors").update({
            "plan_active":        False,
            "cancellation_date":  datetime.utcnow().isoformat(),
        }).eq("id", request.vendor_id).execute()
        return ok("Subscription cancelled. You have access until the end of your billing period.")
    except Exception as e:
        # Cancel locally even if Stripe fails
        sb.table("vendors").update({"plan_active": False}).eq("id", request.vendor_id).execute()
        return ok("Account cancelled.")


@app.route("/api/vendor/apply-promo", methods=["POST"])
@vendor_required
def apply_promo():
    """Apply a promo code to an existing vendor account."""
    body = request.json or {}
    code = (body.get("code") or "").strip().upper()

    if not code:
        return err("Promo code is required")

    pc = sb.table("promo_codes").select("*").eq("code", code).eq("is_active", True).execute().data
    if not pc:
        return err("Invalid or expired promo code")
    pc = pc[0]

    max_uses = pc.get("max_uses")
    if max_uses and pc.get("uses", 0) >= max_uses:
        return err("This promo code has reached its maximum uses")

    months       = pc.get("free_months", 1)
    promo_expires = (datetime.utcnow() + timedelta(days=30 * months)).isoformat()

    sb.table("vendors").update({
        "promo_expires_at": promo_expires,
    }).eq("id", request.vendor_id).execute()
    sb.table("promo_codes").update({"uses": pc["uses"] + 1}).eq("id", pc["id"]).execute()

    return ok({
        "promo_expires_at": promo_expires,
        "free_months":      months,
    })


@app.route("/api/vendor/delete-account", methods=["DELETE"])
@vendor_required
def delete_vendor_account():
    """Permanently delete vendor account and all data."""
    body     = request.json or {}
    confirm  = body.get("confirm")

    if confirm != "DELETE":
        return err('Send {"confirm": "DELETE"} to confirm account deletion')

    vendor = sb.table("vendors").select("stripe_sub_id, stripe_customer_id").eq("id", request.vendor_id).execute().data[0]

    # Cancel Stripe subscription
    try:
        stripe = _stripe()
        if vendor.get("stripe_sub_id"):
            stripe.Subscription.delete(vendor["stripe_sub_id"])
    except Exception:
        pass

    # Delete vendor (cascades to rewards, prizes, tiers, visits, redemptions)
    sb.table("vendors").delete().eq("id", request.vendor_id).execute()
    return ok("Account permanently deleted")


# ══════════════════════════════════════════════════════
#  VENDOR CONFIG
# ══════════════════════════════════════════════════════

@app.route("/api/vendor/brand", methods=["PATCH"])
@vendor_required
def update_brand():
    body    = request.json or {}
    allowed = ["truck_name", "tagline", "emoji", "color_primary",
               "color_secondary", "profile_picture_url", "location_today"]
    updates = {k: v for k, v in body.items() if k in allowed}

    if "truck_name" in updates:
        base = slugify(updates["truck_name"])
        slug = base; i = 1
        while True:
            clash = sb.table("vendors").select("id").eq("slug", slug).neq("id", request.vendor_id).execute().data
            if not clash: break
            slug = f"{base}{i}"; i += 1
        updates["slug"] = slug

    vendor = sb.table("vendors").update(updates).eq("id", request.vendor_id).execute().data[0]
    return ok(_safe_vendor(vendor))


@app.route("/api/vendor/profile", methods=["PATCH"])
@vendor_required
def update_vendor_profile():
    """Update vendor owner profile details."""
    body    = request.json or {}
    allowed = ["owner_name", "phone", "profile_picture_url"]
    updates = {k: v for k, v in body.items() if k in allowed}

    # Password change
    if body.get("new_password"):
        if len(body["new_password"]) < 8:
            return err("Password must be at least 8 characters")
        # Verify current password
        vendor = sb.table("vendors").select("password_hash").eq("id", request.vendor_id).execute().data[0]
        if not bcrypt.checkpw((body.get("current_password","")).encode(), vendor["password_hash"].encode()):
            return err("Current password is incorrect")
        updates["password_hash"] = bcrypt.hashpw(body["new_password"].encode(), bcrypt.gensalt()).decode()

    vendor = sb.table("vendors").update(updates).eq("id", request.vendor_id).execute().data[0]
    return ok(_safe_vendor(vendor))


@app.route("/api/vendor/points-config", methods=["PATCH"])
@vendor_required
def update_points_config():
    body    = request.json or {}
    allowed = ["pts_per_visit", "pts_per_dollar", "pts_spin_bonus",
               "pts_streak_mult", "pts_referral", "double_first_visit",
               "streak_bonus", "birthday_reward", "winback_enabled", "referral_bonus"]
    updates = {k: v for k, v in body.items() if k in allowed}
    vendor  = sb.table("vendors").update(updates).eq("id", request.vendor_id).execute().data[0]
    return ok(_safe_vendor(vendor))


# ── Rewards / Prizes / Tiers ──

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


# ── Stats ──

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
#  VENDOR — AWARD POINTS AT WINDOW
# ══════════════════════════════════════════════════════

@app.route("/api/vendor/find-customer", methods=["POST"])
@vendor_required
def find_customer():
    body      = request.json or {}
    vendor_id = request.vendor_id
    phone     = re.sub(r'\D', '', body.get("phone") or "")
    rid       = (body.get("rewards_id") or "").strip().upper()
    number    = (body.get("vendor_number") or "").strip()

    customer = None
    if phone and len(phone) >= 10:
        row = sb.table("customers").select("*").eq("phone", phone).execute().data
        if row: customer = row[0]
    elif rid:
        row = sb.table("customers").select("*").eq("rewards_id", rid).execute().data
        if row: customer = row[0]
    elif number:
        # Find by rewards number (same as rewards_id lookup)
        row = sb.table("customers").select("*").eq("rewards_id", number.upper()).execute().data
        if row: customer = row[0]

    if not customer:
        return err("Customer not found. Ask them to sign up at foodtruckrewards.app", 404)

    ct = sb.table("customer_trucks").select("*").eq("customer_id", customer["id"]).eq("vendor_id", vendor_id).execute().data
    return ok({
        "id":             customer["id"],
        "name":           customer["name"],
        "phone":          customer["phone"],
        "email":          customer["email"],
        "rewards_id":     customer["rewards_id"],
        "points_balance": ct[0]["points_balance"] if ct else 0,
        "visit_count":    ct[0]["visit_count"]    if ct else 0,
        "current_streak": ct[0].get("current_streak", 0) if ct else 0,
    })


@app.route("/api/vendor/award-points", methods=["POST"])
@vendor_required
def award_points():
    body        = request.json or {}
    vendor_id   = request.vendor_id
    customer_id = body.get("customer_id")
    order_total = float(body.get("order_total") or 0)

    if not customer_id:
        return err("customer_id is required")

    vendor = sb.table("vendors").select("*").eq("id", vendor_id).execute().data
    if not vendor: return err("Vendor not found", 404)
    vendor = vendor[0]

    customer = sb.table("customers").select("*").eq("id", customer_id).execute().data
    if not customer: return err("Customer not found", 404)
    customer = customer[0]

    today     = date.today()
    today_iso = today.isoformat()

    ct_row = sb.table("customer_trucks").select("*").eq("customer_id", customer_id).eq("vendor_id", vendor_id).execute().data

    if ct_row:
        ct        = ct_row[0]
        last_date = date.fromisoformat(ct["last_visit_date"]) if ct.get("last_visit_date") else None
        already_visited = (last_date == today)

        if already_visited:
            # Only award order pts, no visit bonus
            order_pts = int(order_total * (vendor.get("pts_per_dollar") or 10))
            if order_pts <= 0:
                return err("Already awarded visit points today. Enter an order total to award order points.", 409)
            total_pts = order_pts
            new_streak = ct["current_streak"]
        else:
            new_streak = (ct["current_streak"] + 1) if (last_date and (today - last_date).days == 1) else 1
            breakdown  = _calc_points(vendor, order_total, ct["visit_count"], new_streak - 1)
            total_pts  = breakdown["total"]

        new_balance = ct["points_balance"] + total_pts
        new_total   = ct["points_total"]   + total_pts
        new_visits  = ct["visit_count"]    + (0 if already_visited else 1)
        longest     = max(ct.get("longest_streak") or 0, new_streak)

        sb.table("customer_trucks").update({
            "points_balance":  new_balance,
            "points_total":    new_total,
            "visit_count":     new_visits,
            "current_streak":  new_streak,
            "longest_streak":  longest,
            "last_visit_date": today_iso,
        }).eq("id", ct["id"]).execute()
    else:
        breakdown = _calc_points(vendor, order_total, 0, 0)
        total_pts = breakdown["total"]
        new_streak = 1; new_balance = total_pts
        sb.table("customer_trucks").insert({
            "customer_id":    customer_id,
            "vendor_id":      vendor_id,
            "points_balance": total_pts,
            "points_total":   total_pts,
            "visit_count":    1,
            "current_streak": 1,
            "longest_streak": 1,
            "last_visit_date": today_iso,
        }).execute()

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
#  VENDOR — REDEMPTION CONFIRMATION
# ══════════════════════════════════════════════════════

@app.route("/api/vendor/redemption/<code>", methods=["GET"])
@vendor_required
def lookup_redemption_code(code):
    code      = code.upper().strip()
    vendor_id = request.vendor_id

    row = sb.table("redemptions").select(
        "*, rewards(name, emoji, pts_required), customers(name, rewards_id)"
    ).eq("code", code).eq("vendor_id", vendor_id).execute().data

    if not row:
        return err("Code not found or doesn't belong to your truck", 404)
    r = row[0]
    if r["status"] == "used":
        return err("This code has already been used")

    expires = r.get("expires_at")
    if expires:
        if datetime.fromisoformat(expires.replace("Z","").replace("+00:00","").split("+")[0].strip()) < datetime.utcnow():
            sb.table("redemptions").update({"status":"expired"}).eq("id", r["id"]).execute()
            return err("This code has expired")

    return ok({
        "redemption_id": r["id"],
        "code":          code,
        "reward_name":   r["rewards"]["name"],
        "reward_emoji":  r["rewards"]["emoji"],
        "pts_cost":      r["rewards"]["pts_required"],
        "customer_name": r["customers"]["name"],
        "customer_rid":  r["customers"]["rewards_id"],
        "status":        r["status"],
    })


@app.route("/api/vendor/confirm-redemption", methods=["POST"])
@vendor_required
def confirm_redemption():
    body      = request.json or {}
    code      = (body.get("redemption_code") or "").upper().strip()
    vendor_id = request.vendor_id
    if not code: return err("Redemption code is required")

    row = sb.table("redemptions").select(
        "*, rewards(name, pts_required)"
    ).eq("code", code).eq("vendor_id", vendor_id).execute().data
    if not row: return err("Code not found", 404)
    r = row[0]
    if r["status"] == "used":    return err("Already confirmed")
    if r["status"] == "expired": return err("Code expired")

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
#  PUBLIC — TRUCK CONFIG
# ══════════════════════════════════════════════════════

@app.route("/api/vendor/upload-picture", methods=["POST"])
@vendor_required
def vendor_upload_picture():
    """
    Accepts a base64 image, uploads to Supabase Storage,
    saves the public URL to vendor row.
    Falls back to storing base64 directly if storage unavailable.
    """
    body  = request.json or {}
    b64   = body.get("image_b64", "")
    if not b64:
        return err("image_b64 required")

    # Try Supabase Storage upload
    try:
        import base64, uuid
        # Strip data URI prefix if present
        if "," in b64:
            b64 = b64.split(",", 1)[1]
        img_bytes = base64.b64decode(b64)
        filename  = f"vendors/{request.vendor_id}/{uuid.uuid4()}.jpg"
        sb.storage.from_("profile-pictures").upload(
            filename, img_bytes,
            {"content-type": "image/jpeg", "upsert": "true"}
        )
        supabase_url = os.environ["SUPABASE_URL"]
        public_url   = f"{supabase_url}/storage/v1/object/public/profile-pictures/{filename}"
    except Exception:
        # Fallback: store base64 data URI directly
        public_url = "data:image/jpeg;base64," + b64 if "data:" not in b64 else b64

    sb.table("vendors").update({
        "profile_picture_url": public_url
    }).eq("id", request.vendor_id).execute()

    return ok({"url": public_url})


@app.route("/api/customer/upload-picture", methods=["POST"])
def customer_upload_picture():
    """
    Accepts a base64 image from customer, uploads to Supabase Storage,
    saves public URL to customer row.
    """
    auth = request.headers.get("X-Customer-Token", "")
    if not auth:
        return err("Missing customer token", 401)
    try:
        payload     = jwt.decode(auth, JWT_SECRET, algorithms=[JWT_ALGO])
        customer_id = payload["sub"]
    except JWTError:
        return err("Invalid token", 401)

    body = request.json or {}
    b64  = body.get("image_b64", "")
    if not b64:
        return err("image_b64 required")

    try:
        import base64, uuid
        if "," in b64:
            b64 = b64.split(",", 1)[1]
        img_bytes = base64.b64decode(b64)
        filename  = f"customers/{customer_id}/{uuid.uuid4()}.jpg"
        sb.storage.from_("profile-pictures").upload(
            filename, img_bytes,
            {"content-type": "image/jpeg", "upsert": "true"}
        )
        supabase_url = os.environ["SUPABASE_URL"]
        public_url   = f"{supabase_url}/storage/v1/object/public/profile-pictures/{filename}"
    except Exception:
        public_url = "data:image/jpeg;base64," + b64 if "data:" not in b64 else b64

    sb.table("customers").update({
        "profile_picture_url": public_url
    }).eq("id", customer_id).execute()

    return ok({"url": public_url})


@app.route("/api/trucks/search", methods=["GET"])
def search_trucks():
    """Search trucks by name or vendor number."""
    q = (request.args.get("q") or "").strip()
    if len(q) < 1:
        return ok([])

    results = []

    # Search by truck name (case-insensitive)
    name_rows = sb.table("vendors").select(
        "id, truck_name, emoji, slug, vendor_number, "
        "color_primary, color_secondary, tagline, plan_active, trial_ends_at, promo_expires_at"
    ).ilike("truck_name", f"%{q}%").limit(10).execute().data
    results.extend(name_rows)

    # Also search by vendor number if query looks like a number
    if q.isdigit() or (q.startswith('#') and q[1:].isdigit()):
        num = q.lstrip('#')
        num_rows = sb.table("vendors").select(
            "id, truck_name, emoji, slug, vendor_number, "
            "color_primary, color_secondary, tagline, plan_active, trial_ends_at, promo_expires_at"
        ).eq("vendor_number", num).limit(5).execute().data
        # Avoid duplicates
        existing_ids = {r["id"] for r in results}
        results.extend([r for r in num_rows if r["id"] not in existing_ids])

    # Filter to active vendors only
    now = datetime.utcnow()
    active = []
    for r in results:
        if _vendor_is_active(r):
            # Remove billing fields before sending to client
            r.pop("plan_active", None)
            r.pop("trial_ends_at", None)
            r.pop("promo_expires_at", None)
            active.append(r)

    return ok(active)


@app.route("/api/truck/<slug>", methods=["GET"])
@app.route("/api/truck/<slug>/config", methods=["GET"])
def get_truck_config(slug):
    row = sb.table("vendors").select(
        "id, truck_name, tagline, emoji, slug, vendor_number, "
        "color_primary, color_secondary, profile_picture_url, "
        "pts_per_visit, pts_per_dollar, pts_spin_bonus, pts_streak_mult, "
        "pts_referral, double_first_visit, streak_bonus, "
        "plan_active, trial_ends_at, promo_expires_at, location_today"
    ).eq("slug", slug).execute().data

    if not row: return err("Truck not found", 404)
    vendor = row[0]

    if not _vendor_is_active(vendor):
        return err("This truck's loyalty program is not currently active", 403)

    rewards = sb.table("rewards").select("*").eq("vendor_id", vendor["id"]).eq("is_active", True).order("sort_order").execute().data
    prizes  = sb.table("spin_prizes").select("*").eq("vendor_id", vendor["id"]).eq("is_active", True).execute().data
    tiers   = sb.table("tiers").select("*").eq("vendor_id", vendor["id"]).order("pts_threshold").execute().data

    return ok({"vendor": vendor, "rewards": rewards, "prizes": prizes, "tiers": tiers})


# ══════════════════════════════════════════════════════
#  CUSTOMER AUTH
# ══════════════════════════════════════════════════════

@app.route("/api/customer/signup", methods=["POST"])
def customer_signup():
    body  = request.json or {}
    name  = (body.get("name") or "").strip()
    phone = re.sub(r'\D', '', body.get("phone") or "")
    email = (body.get("email") or "").strip().lower()

    if not name:  return err("Name is required")
    if len(phone) < 10: return err("Valid phone number is required")
    if not email or "@" not in email: return err("Valid email is required")

    if sb.table("customers").select("id").eq("phone", phone).execute().data:
        return err("An account with this phone number already exists. Please sign in.")
    if sb.table("customers").select("id").ilike("email", email).execute().data:
        return err("An account with this email already exists. Please sign in.")

    rid = gen_rewards_id()
    while sb.table("customers").select("id").eq("rewards_id", rid).execute().data:
        rid = gen_rewards_id()

    ref_code = "".join(random.choices(string.ascii_uppercase + string.digits, k=8))
    while sb.table("customers").select("id").eq("referral_code", ref_code).execute().data:
        ref_code = "".join(random.choices(string.ascii_uppercase + string.digits, k=8))

    referred_by = None
    if body.get("ref_code"):
        ref = sb.table("customers").select("id").eq("referral_code", body["ref_code"]).execute().data
        if ref: referred_by = ref[0]["id"]

    customer = sb.table("customers").insert({
        "name": name, "phone": phone, "email": email,
        "rewards_id": rid, "referral_code": ref_code, "referred_by": referred_by,
    }).execute().data[0]

    token = make_customer_token(customer["id"])
    return ok({"token": token, "customer": _safe_customer(customer), "trucks": []}), 201


@app.route("/api/customer/login", methods=["POST"])
def customer_login():
    body  = request.json or {}
    phone = re.sub(r'\D', '', body.get("phone") or "")
    email = (body.get("email") or "").strip().lower()
    if not phone and not email:
        return err("Phone number or email is required")

    customer = None
    if phone and len(phone) >= 10:
        row = sb.table("customers").select("*").eq("phone", phone).execute().data
        if row: customer = row[0]
    if not customer and email:
        row = sb.table("customers").select("*").ilike("email", email).execute().data
        if row: customer = row[0]
    if not customer:
        return err("No account found. Please sign up first.", 404)

    trucks = _get_customer_trucks(customer["id"])
    token  = make_customer_token(customer["id"])
    return ok({"token": token, "customer": _safe_customer(customer), "trucks": trucks})


@app.route("/api/customer/profile", methods=["PATCH"])
def update_customer_profile():
    """Update customer profile. Auth via X-Customer-Token header."""
    auth = request.headers.get("X-Customer-Token", "")
    if not auth:
        return err("Missing customer token", 401)
    try:
        payload     = jwt.decode(auth, JWT_SECRET, algorithms=[JWT_ALGO])
        customer_id = payload["sub"]
    except JWTError:
        return err("Invalid token", 401)

    body    = request.json or {}
    allowed = ["name", "profile_picture_url", "birthday"]
    updates = {k: v for k, v in body.items() if k in allowed}

    # Phone/email change with uniqueness check
    if body.get("phone"):
        phone = re.sub(r'\D', '', body["phone"])
        if len(phone) < 10: return err("Valid phone number required")
        clash = sb.table("customers").select("id").eq("phone", phone).neq("id", customer_id).execute().data
        if clash: return err("Phone number already in use")
        updates["phone"] = phone

    if body.get("email"):
        email = body["email"].strip().lower()
        if "@" not in email: return err("Valid email required")
        clash = sb.table("customers").select("id").ilike("email", email).neq("id", customer_id).execute().data
        if clash: return err("Email already in use")
        updates["email"] = email

    customer = sb.table("customers").update(updates).eq("id", customer_id).execute().data[0]
    return ok(_safe_customer(customer))


@app.route("/api/customer/delete-account", methods=["DELETE"])
def delete_customer_account():
    auth = request.headers.get("X-Customer-Token", "")
    if not auth: return err("Missing token", 401)
    try:
        payload     = jwt.decode(auth, JWT_SECRET, algorithms=[JWT_ALGO])
        customer_id = payload["sub"]
    except JWTError:
        return err("Invalid token", 401)

    body = request.json or {}
    if body.get("confirm") != "DELETE":
        return err('Send {"confirm": "DELETE"} to confirm')

    sb.table("customers").delete().eq("id", customer_id).execute()
    return ok("Account deleted")


# ══════════════════════════════════════════════════════
#  CUSTOMER — JOIN TRUCK
# ══════════════════════════════════════════════════════

@app.route("/api/customer/join-truck", methods=["POST"])
def customer_join_truck():
    body        = request.json or {}
    slug        = (body.get("slug") or "").strip().lower()
    customer_id = body.get("customer_id")

    if not slug:        return err("Truck code is required")
    if not customer_id: return err("customer_id is required")

    vendor = sb.table("vendors").select("*").eq("slug", slug).execute().data
    if not vendor: return err("Truck not found", 404)
    vendor = vendor[0]

    if not _vendor_is_active(vendor):
        return err("This truck's loyalty program is not currently active", 403)

    existing = sb.table("customer_trucks").select("id").eq("customer_id", customer_id).eq("vendor_id", vendor["id"]).execute().data
    if not existing:
        sb.table("customer_trucks").insert({
            "customer_id": customer_id, "vendor_id": vendor["id"],
            "points_balance": 0, "points_total": 0,
            "visit_count": 0, "current_streak": 0,
            "longest_streak": 0, "total_saved": 0.0,
        }).execute()

    rewards = sb.table("rewards").select("*").eq("vendor_id", vendor["id"]).eq("is_active", True).order("sort_order").execute().data
    prizes  = sb.table("spin_prizes").select("*").eq("vendor_id", vendor["id"]).eq("is_active", True).execute().data
    tiers   = sb.table("tiers").select("*").eq("vendor_id", vendor["id"]).order("pts_threshold").execute().data
    ct      = sb.table("customer_trucks").select("*").eq("customer_id", customer_id).eq("vendor_id", vendor["id"]).execute().data[0]

    return ok({
        "truck": {
            "id": vendor["id"], "truck_name": vendor["truck_name"],
            "tagline": vendor.get("tagline",""), "emoji": vendor.get("emoji","🚚"),
            "slug": vendor["slug"], "vendor_number": vendor.get("vendor_number",""),
            "color_primary": vendor.get("color_primary","#FF5722"),
            "color_secondary": vendor.get("color_secondary","#F9A825"),
            "profile_picture_url": vendor.get("profile_picture_url",""),
            "location_today": vendor.get("location_today",""),
            "points_balance": ct["points_balance"],
            "points_total":   ct["points_total"],
            "visit_count":    ct["visit_count"],
            "current_streak": ct["current_streak"],
            "total_saved":    ct["total_saved"],
            "rewards": rewards, "prizes": prizes, "tiers": tiers,
        },
        "is_new": not bool(existing)
    }), 201


# ══════════════════════════════════════════════════════
#  CUSTOMER — CHECK IN (self-service)
# ══════════════════════════════════════════════════════

@app.route("/api/customer/visit", methods=["POST"])
def record_visit():
    body        = request.json or {}
    customer_id = body.get("customer_id")
    vendor_id   = body.get("vendor_id")
    if not customer_id or not vendor_id:
        return err("customer_id and vendor_id required")

    customer = sb.table("customers").select("*").eq("id", customer_id).execute().data
    if not customer: return err("Customer not found", 404)
    customer = customer[0]

    vendor = sb.table("vendors").select("*").eq("id", vendor_id).execute().data
    if not vendor: return err("Vendor not found", 404)
    vendor = vendor[0]

    if not _vendor_is_active(vendor):
        return err("This truck's loyalty program is not currently active", 403)

    today     = date.today()
    today_iso = today.isoformat()
    ct_row    = sb.table("customer_trucks").select("*").eq("customer_id", customer_id).eq("vendor_id", vendor_id).execute().data

    if ct_row:
        ct        = ct_row[0]
        last_date = date.fromisoformat(ct["last_visit_date"]) if ct.get("last_visit_date") else None
        if last_date == today:
            return err("Already checked in today — come back tomorrow! 🔥", 409)

        new_streak = (ct["current_streak"]+1) if (last_date and (today-last_date).days==1) else 1
        longest    = max(ct.get("longest_streak") or 0, new_streak)
        breakdown  = _calc_points(vendor, 0, ct["visit_count"], new_streak-1)
        total_pts  = breakdown["total"]
        new_balance= ct["points_balance"] + total_pts
        new_total  = ct["points_total"]   + total_pts
        new_visits = ct["visit_count"]    + 1

        tiers = sb.table("tiers").select("*").eq("vendor_id", vendor_id).order("pts_threshold", desc=True).execute().data
        new_tier_id = ct.get("current_tier_id"); tier_upgraded = False
        for tier in tiers:
            if new_total >= tier["pts_threshold"]:
                if tier["id"] != ct.get("current_tier_id"):
                    new_tier_id = tier["id"]; tier_upgraded = True
                break

        sb.table("customer_trucks").update({
            "points_balance": new_balance, "points_total": new_total,
            "visit_count": new_visits, "current_streak": new_streak,
            "longest_streak": longest, "last_visit_date": today_iso,
            "current_tier_id": new_tier_id,
        }).eq("id", ct["id"]).execute()
    else:
        breakdown  = _calc_points(vendor, 0, 0, 0)
        total_pts  = breakdown["total"]
        new_streak = 1; new_balance = total_pts; new_visits = 1
        new_total  = total_pts; tier_upgraded = False; new_tier_id = None
        sb.table("customer_trucks").insert({
            "customer_id": customer_id, "vendor_id": vendor_id,
            "points_balance": total_pts, "points_total": total_pts,
            "visit_count": 1, "current_streak": 1,
            "longest_streak": 1, "last_visit_date": today_iso,
        }).execute()

    visit = sb.table("visits").insert({
        "customer_id": customer_id, "vendor_id": vendor_id,
        "pts_earned": total_pts, "streak_day": new_streak, "awarded_by": "customer",
    }).execute().data[0]

    # Spin
    prizes = sb.table("spin_prizes").select("*").eq("vendor_id", vendor_id).eq("is_active", True).execute().data
    spin_result = None
    if prizes:
        total_w = sum(p["probability"] for p in prizes)
        r = random.uniform(0, total_w); cum = 0; won = prizes[-1]
        for p in prizes:
            cum += p["probability"]
            if r <= cum: won = p; break

        spin_pts = int(won.get("prize_value") or 25)
        spin_result = sb.table("spin_results").insert({
            "customer_id": customer_id, "vendor_id": vendor_id,
            "visit_id": visit["id"], "prize_id": won["id"],
            "prize_name": won["name"], "prize_type": won.get("prize_type","points"),
            "prize_value": won.get("prize_value","25"),
        }).execute().data[0]
        sb.table("customer_trucks").update({
            "points_balance": new_balance + spin_pts,
            "points_total":   new_total   + spin_pts,
        }).eq("customer_id", customer_id).eq("vendor_id", vendor_id).execute()
        sb.table("visits").update({"spin_result_id": spin_result["id"]}).eq("id", visit["id"]).execute()

    return ok({
        "visit": visit, "pts_earned": total_pts, "new_balance": new_balance,
        "new_streak": new_streak, "spin_result": spin_result,
        "tier_upgraded": tier_upgraded, "new_tier_id": new_tier_id,
    })


# ══════════════════════════════════════════════════════
#  CUSTOMER — REDEEM
# ══════════════════════════════════════════════════════

@app.route("/api/customer/redeem", methods=["POST"])
def customer_redeem():
    body        = request.json or {}
    customer_id = body.get("customer_id")
    reward_id   = body.get("reward_id")
    if not customer_id or not reward_id:
        return err("customer_id and reward_id required")

    reward = sb.table("rewards").select("*").eq("id", reward_id).execute().data
    if not reward: return err("Reward not found", 404)
    reward = reward[0]

    ct = sb.table("customer_trucks").select("*").eq("customer_id", customer_id).eq("vendor_id", reward["vendor_id"]).execute().data
    if not ct: return err("You haven't visited this truck yet")
    ct = ct[0]

    if ct["points_balance"] < reward["pts_required"]:
        return err(f"Not enough points. Need {reward['pts_required']}, you have {ct['points_balance']}")

    code = gen_code()
    while sb.table("redemptions").select("id").eq("code", code).execute().data:
        code = gen_code()

    redemption = sb.table("redemptions").insert({
        "customer_id": customer_id, "vendor_id": reward["vendor_id"],
        "reward_id": reward_id, "pts_spent": reward["pts_required"],
        "code": code, "status": "pending",
        "expires_at": (datetime.utcnow() + timedelta(hours=24)).isoformat(),
    }).execute().data[0]

    sb.table("customer_trucks").update({
        "points_balance": ct["points_balance"] - reward["pts_required"],
        "total_saved":    float(ct.get("total_saved") or 0) + float(body.get("reward_value") or 5.0),
    }).eq("id", ct["id"]).execute()

    return ok({
        "code": code, "reward_name": reward["name"],
        "reward_emoji": reward["emoji"], "pts_spent": reward["pts_required"],
        "expires_at": redemption["expires_at"],
    })


@app.route("/api/customer/<customer_id>/history", methods=["GET"])
def customer_history(customer_id):
    visits = sb.table("visits").select("*, spin_results(prize_name, prize_value)").eq("customer_id", customer_id).order("created_at", desc=True).limit(50).execute()
    redemptions = sb.table("redemptions").select("*, rewards(name, emoji)").eq("customer_id", customer_id).order("created_at", desc=True).limit(30).execute()
    return ok({"visits": visits.data, "redemptions": redemptions.data})


@app.route("/api/customer/<customer_id>/trucks", methods=["GET"])
def customer_trucks_list(customer_id):
    return ok(_get_customer_trucks(customer_id))


# ══════════════════════════════════════════════════════
#  PASSWORD RESET — Vendor + Customer
#  Secure flow:
#  1. POST /api/auth/forgot-password  → generates token, sends email
#  2. POST /api/auth/reset-password   → verifies token, sets new password
# ══════════════════════════════════════════════════════

def _send_reset_email(to_email: str, reset_url: str, user_type: str, name: str) -> bool:
    """
    Send password reset email via Resend API.
    
    IMPORTANT: Resend's onboarding@resend.dev can only send to your
    verified Resend account email. To send to any address, you must
    verify a domain at resend.com/domains.
    
    Workaround: Set RESEND_FROM to a verified domain sender like
    noreply@yourdomain.com after verifying in Resend dashboard.
    """
    resend_key = os.environ.get("RESEND_API_KEY", "")
    if not resend_key:
        print(f"[PASSWORD RESET] No RESEND_API_KEY. Reset URL: {reset_url}")
        return False

    import urllib.request, json as _json

    truck_or_name = "your Food Truck Rewards account"
    if user_type == "vendor":
        truck_or_name = f"your vendor account ({name})"
    elif name:
        truck_or_name = f"your account ({name})"

    html_body = f"""<!DOCTYPE html>
    <html>
    <body style="font-family:Arial,sans-serif;background:#FFF8F0;padding:32px;margin:0">
      <div style="max-width:480px;margin:0 auto;background:white;border-radius:16px;padding:32px;box-shadow:0 4px 20px rgba(0,0,0,.08)">
        <div style="text-align:center;margin-bottom:24px">
          <div style="font-size:48px">🔥</div>
          <h1 style="color:#FF5722;font-size:22px;margin:8px 0">Food Truck Rewards</h1>
        </div>
        <h2 style="color:#2D1B0E;font-size:18px;margin-bottom:8px">Reset Your Password</h2>
        <p style="color:#666;font-size:14px;line-height:1.6;margin-bottom:24px">
          We received a request to reset the password for {truck_or_name}.
          Click the button below to set a new password.
        </p>
        <div style="text-align:center;margin-bottom:24px">
          <a href="{reset_url}"
             style="background:#FF5722;color:white;padding:14px 32px;border-radius:10px;
                    text-decoration:none;font-weight:bold;font-size:15px;display:inline-block">
            Reset My Password
          </a>
        </div>
        <p style="color:#999;font-size:12px;line-height:1.6">
          This link expires in <strong>1 hour</strong> and can only be used once.
          If you did not request a password reset, safely ignore this email.
        </p>
        <hr style="border:none;border-top:1px solid #eee;margin:24px 0">
        <p style="color:#ccc;font-size:11px;text-align:center">
          Food Truck Rewards · support@foodtruckrewards.app
        </p>
      </div>
    </body>
    </html>"""

    resend_from = os.environ.get("RESEND_FROM", "onboarding@resend.dev")

    payload = _json.dumps({
        "from": f"Food Truck Rewards <{resend_from}>",
        "to": [to_email],
        "subject": "Reset your Food Truck Rewards password",
        "html": html_body,
    }).encode()

    try:
        req = urllib.request.Request(
            "https://api.resend.com/emails",
            data=payload,
            headers={
                "Authorization": f"Bearer {resend_key}",
                "Content-Type": "application/json",
            }
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            body_resp = resp.read().decode()
            print(f"[EMAIL SUCCESS] Sent to {to_email}. Response: {body_resp}")
            return resp.status in (200, 201)
    except urllib.error.HTTPError as e:
        error_body = e.read().decode()
        print(f"[EMAIL ERROR] HTTP {e.code}: {error_body}")
        print(f"[EMAIL DEBUG] From: {resend_from}, To: {to_email}")
        print(f"[EMAIL DEBUG] Reset URL: {reset_url}")
        return False
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")
        print(f"[EMAIL DEBUG] Reset URL for manual use: {reset_url}")
        return False


@app.route("/api/auth/forgot-password", methods=["POST"])
def forgot_password():
    """
    Request a password reset. Works for both vendors and customers.
    ALWAYS returns 200 — never reveals if email exists (security).
    """
    body      = request.json or {}
    email     = (body.get("email") or "").strip().lower()
    user_type = (body.get("user_type") or "vendor")

    SAFE_RESPONSE = ok("If an account with that email exists, a reset link has been sent.")

    if not email or "@" not in email:
        return err("Valid email address is required")
    if user_type not in ("vendor", "customer"):
        return err("user_type must be 'vendor' or 'customer'")

    try:
        table      = "vendors" if user_type == "vendor" else "customers"
        name_field = "truck_name" if user_type == "vendor" else "name"
        row = sb.table(table).select(f"id, email, {name_field}").ilike("email", email).execute().data

        if not row:
            return SAFE_RESPONSE

        user = row[0]

        # Remove old unused tokens
        try:
            sb.table("password_reset_tokens").delete().eq("user_id", user["id"]).eq("used", False).execute()
        except Exception:
            pass  # Table may not exist yet — still generate token

        # Generate secure token
        import secrets
        raw_token  = secrets.token_urlsafe(32)
        token_hash = bcrypt.hashpw(raw_token.encode(), bcrypt.gensalt()).decode()
        expires_at = (datetime.utcnow() + timedelta(hours=1)).isoformat()

        try:
            sb.table("password_reset_tokens").insert({
                "user_type":  user_type,
                "user_id":    user["id"],
                "email":      email,
                "token_hash": token_hash,
                "expires_at": expires_at,
                "used":       False,
            }).execute()
        except Exception as e:
            print(f"[RESET TOKEN] Could not store token: {e}")
            # Return success but log — user won't get email but won't see error
            return SAFE_RESPONSE

        app_url   = os.environ.get("APP_URL", "https://truckloyal-app.onrender.com")
        reset_url = f"{app_url}?reset_token={raw_token}&user_type={user_type}&email={email}"
        name      = user.get(name_field, "")
        _send_reset_email(email, reset_url, user_type, name)

    except Exception as e:
        print(f"[FORGOT PASSWORD ERROR] {e}")
        # Always return success — never leak error details

    return SAFE_RESPONSE


@app.route("/api/auth/reset-password", methods=["POST"])
def reset_password():
    """
    Complete a password reset using the token from the email link.
    Token is verified, single-use, and expires after 1 hour.
    """
    body         = request.json or {}
    raw_token    = body.get("token", "").strip()
    new_password = body.get("new_password", "")
    user_type    = body.get("user_type", "vendor")
    email        = (body.get("email") or "").strip().lower()

    if not raw_token:
        return err("Reset token is required")
    if not new_password or len(new_password) < 8:
        return err("Password must be at least 8 characters")
    if not email:
        return err("Email is required")

    # Find tokens for this email (not yet used, not expired)
    now = datetime.utcnow()
    tokens = sb.table("password_reset_tokens").select("*").ilike("email", email).eq("user_type", user_type).eq("used", False).execute().data

    if not tokens:
        return err("This reset link is invalid or has already been used", 400)

    # Find matching token by checking against all hashes (usually just 1)
    matched = None
    for t in tokens:
        # Check expiry first
        exp = datetime.fromisoformat(t["expires_at"].replace("Z","").replace("+00:00","").split("+")[0].strip())
        if exp < now:
            continue
        # Verify token against stored hash
        try:
            if bcrypt.checkpw(raw_token.encode(), t["token_hash"].encode()):
                matched = t
                break
        except Exception:
            continue

    if not matched:
        return err("This reset link is invalid or has expired. Please request a new one.", 400)

    # Hash the new password
    new_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()

    # Update password in the right table
    table = "vendors" if user_type == "vendor" else "customers"
    sb.table(table).update({"password_hash": new_hash}).eq("id", matched["user_id"]).execute()

    # Mark token as used — single use only
    sb.table("password_reset_tokens").update({
        "used":    True,
        "used_at": now.isoformat(),
    }).eq("id", matched["id"]).execute()

    # Also invalidate any other tokens for this user
    sb.table("password_reset_tokens").delete().eq("user_id", matched["user_id"]).eq("used", False).execute()

    return ok("Password updated successfully. You can now sign in with your new password.")


@app.route("/api/auth/verify-reset-token", methods=["POST"])
def verify_reset_token():
    """
    Quick check if a reset token is still valid before showing the
    reset form. Doesn't consume the token.
    """
    body      = request.json or {}
    raw_token = body.get("token", "").strip()
    email     = (body.get("email") or "").strip().lower()
    user_type = body.get("user_type", "vendor")

    if not raw_token or not email:
        return err("Token and email are required")

    now    = datetime.utcnow()
    tokens = sb.table("password_reset_tokens").select("*").ilike("email", email).eq("user_type", user_type).eq("used", False).execute().data

    for t in tokens:
        exp = datetime.fromisoformat(t["expires_at"].replace("Z","").replace("+00:00","").split("+")[0].strip())
        if exp < now:
            continue
        try:
            if bcrypt.checkpw(raw_token.encode(), t["token_hash"].encode()):
                minutes_left = int((exp - now).total_seconds() / 60)
                return ok({"valid": True, "minutes_remaining": minutes_left})
        except Exception:
            continue

    return ok({"valid": False})


@app.route("/api/auth/forgot-password", methods=["OPTIONS"])
@app.route("/api/auth/reset-password", methods=["OPTIONS"])
@app.route("/api/auth/verify-reset-token", methods=["OPTIONS"])
def auth_options():
    return ok("ok")


# ══════════════════════════════════════════════════════

@app.route("/api/webhooks/stripe", methods=["POST"])
def stripe_webhook():
    try:
        stripe = _stripe()
        payload = request.data
        sig     = request.headers.get("Stripe-Signature")
        event   = stripe.Webhook.construct_event(
            payload, sig, os.environ.get("STRIPE_WEBHOOK_SECRET","")
        )
    except Exception as e:
        return err(str(e))

    etype = event["type"]
    obj   = event["data"]["object"]

    if etype == "customer.subscription.created":
        sb.table("vendors").update({
            "stripe_sub_id": obj["id"], "plan_active": True,
            "payment_failed_at": None,
        }).eq("stripe_customer_id", obj["customer"]).execute()

    elif etype == "customer.subscription.updated":
        active = obj["status"] in ("active", "trialing")
        sb.table("vendors").update({
            "plan_active": active,
            "stripe_sub_id": obj["id"],
        }).eq("stripe_customer_id", obj["customer"]).execute()

    elif etype in ("customer.subscription.deleted", "customer.subscription.paused"):
        sb.table("vendors").update({
            "plan_active": False,
        }).eq("stripe_customer_id", obj["customer"]).execute()

    elif etype == "invoice.payment_failed":
        # Start grace period clock
        sb.table("vendors").update({
            "plan_active":        False,
            "payment_failed_at":  datetime.utcnow().isoformat(),
        }).eq("stripe_customer_id", obj["customer"]).execute()

    elif etype == "invoice.payment_succeeded":
        # Clear grace period
        sb.table("vendors").update({
            "plan_active":        True,
            "payment_failed_at":  None,
        }).eq("stripe_customer_id", obj["customer"]).execute()

    return ok("received")


# ══════════════════════════════════════════════════════
#  RUN
# ══════════════════════════════════════════════════════

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
