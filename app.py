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

import os, re, bcrypt, random, string, time
from datetime import datetime, timedelta, date
from functools import wraps
from collections import defaultdict

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from supabase import create_client, Client
from jose import jwt, JWTError
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# ── CORS — restrict to your domains only ──────────────────
CORS(app, origins="*")

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
#  RATE LIMITING — simple in-memory per IP
# ══════════════════════════════════════════════════════

_rate_store = defaultdict(list)

def rate_limit(max_calls: int, window_seconds: int):
    """Decorator — limits an endpoint to max_calls per window per IP."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip  = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
            key = f"{f.__name__}:{ip}"
            now = time.time()
            _rate_store[key] = [t for t in _rate_store[key] if now - t < window_seconds]
            if len(_rate_store[key]) >= max_calls:
                return jsonify({"error": "Too many requests — please slow down"}), 429
            _rate_store[key].append(now)
            return f(*args, **kwargs)
        return wrapper
    return decorator


# ══════════════════════════════════════════════════════
#  SECURITY HEADERS
# ══════════════════════════════════════════════════════

_STATIC_PATHS = {'/manifest.json', '/icon-192.png', '/icon-512.png', '/privacy', '/terms', '/sw.js', '/install', '/get'}

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["X-Frame-Options"]          = "DENY"
    response.headers["X-XSS-Protection"]         = "1; mode=block"
    response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
    if request.path not in _STATIC_PATHS:
        response.headers["Cache-Control"] = "no-store"
    return response


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


def make_token(payload: dict) -> str:
    """Generic token maker — merges payload with expiry."""
    payload["exp"] = datetime.utcnow() + timedelta(days=JWT_EXPIRY)
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


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
        "color_primary, color_secondary, vendor_number, location_today, profile_picture_url, "
        "plan_active, trial_ends_at, promo_expires_at, payment_failed_at)"
    ).eq("customer_id", customer_id).execute().data

    result = []
    for ct in ct_rows:
        vendor = ct.pop("vendors", {}) or {}
        is_active = _vendor_is_active(vendor)
        # Strip raw billing fields — only expose the computed status to customers
        for k in ("plan_active", "trial_ends_at", "promo_expires_at", "payment_failed_at"):
            vendor.pop(k, None)
        entry  = {**vendor,
                  "is_active":       is_active,
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
#  HEALTH + SERVE FRONTEND APP
# ══════════════════════════════════════════════════════

@app.route("/")
def health():
    return ok("Food Truck Rewards API v2 🚚")


@app.route("/app")
@app.route("/app/")
def serve_app():
    resp = send_from_directory('.', 'index.html')
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp


@app.route("/styles.css")
def serve_styles():
    resp = send_from_directory('.', 'styles.css')
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp


@app.route("/manifest.json")
def serve_manifest():
    from flask import Response
    import json
    manifest = {
        "name": "TruckLoyal",
        "short_name": "TruckLoyal",
        "description": "Food truck loyalty rewards — earn points, get rewards",
        "start_url": "/app",
        "display": "standalone",
        "background_color": "#FF5722",
        "theme_color": "#FF5722",
        "orientation": "portrait",
        "icons": [
            {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any maskable"},
            {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any maskable"},
        ]
    }
    resp = Response(json.dumps(manifest), mimetype='application/manifest+json')
    resp.headers['Cache-Control'] = 'public, max-age=86400'
    return resp


@app.route("/icon-192.png")
def serve_icon_192():
    resp = send_from_directory('.', 'icon-192.png')
    resp.headers['Cache-Control'] = 'public, max-age=604800'
    return resp


@app.route("/icon-512.png")
def serve_icon_512():
    resp = send_from_directory('.', 'icon-512.png')
    resp.headers['Cache-Control'] = 'public, max-age=604800'
    return resp


@app.route("/sw.js")
def serve_sw():
    resp = send_from_directory('.', 'sw.js')
    resp.headers['Content-Type'] = 'application/javascript'
    # Allow the worker to control the whole site (root scope)
    resp.headers['Service-Worker-Allowed'] = '/'
    # Never cache the worker itself so updates roll out immediately
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return resp


@app.route("/install")
@app.route("/get")
def serve_install():
    resp = send_from_directory('.', 'install.html')
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return resp


@app.route("/privacy")
def privacy_policy():
    from flask import Response
    html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Privacy Policy — TruckLoyal</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#FFF8F0;color:#2D1B0E;line-height:1.7;font-size:15px}
  .header{background:#FF5722;color:white;padding:28px 24px 20px;text-align:center}
  .header h1{font-size:22px;font-weight:900;margin-bottom:4px}
  .header p{font-size:13px;opacity:.85}
  .body{max-width:680px;margin:0 auto;padding:20px 20px 60px}
  .card{background:white;border:1.5px solid rgba(180,120,60,.15);border-radius:16px;padding:18px;margin-bottom:14px;box-shadow:0 2px 8px rgba(180,100,40,.08)}
  h2{font-size:15px;font-weight:800;margin-bottom:10px;color:#FF5722}
  p{margin-bottom:8px;color:#2D1B0E}
  p:last-child{margin-bottom:0}
  strong{font-weight:700}
  a{color:#FF5722;text-decoration:none}
</style>
</head>
<body>
<div class="header">
  <h1>🔥 TruckLoyal</h1>
  <p>Privacy Policy &mdash; Last updated: April 2026</p>
</div>
<div class="body">
  <div class="card">
    <h2>1. Information We Collect</h2>
    <p><strong>Vendor accounts:</strong> Name, business name, email address, password (hashed — never stored in plain text), and payment method (processed and stored securely by Stripe — we never see your full card number).</p>
    <p><strong>Customer accounts:</strong> Name, phone number, email address, visit history, and points balance. This data is used solely to operate the loyalty program on your behalf.</p>
  </div>
  <div class="card">
    <h2>2. How We Use Your Information</h2>
    <p>We use your information to operate the Service, process payments, send billing receipts, provide customer support, and improve the platform. We do not use your data or your customers' data for advertising.</p>
    <p>We may send you service-related emails such as payment receipts, trial expiration reminders, and important account notices. You cannot opt out of transactional emails while your account is active.</p>
  </div>
  <div class="card">
    <h2>3. Data Sharing</h2>
    <p>We do not sell, rent, or share your personal information or your customers' personal information with third parties for marketing purposes.</p>
    <p><strong>Payment processing:</strong> Payment information is shared with Stripe, Inc. for billing purposes. Stripe's privacy policy applies to that data.</p>
    <p><strong>Infrastructure:</strong> We use Supabase for database hosting and Render for application hosting. These providers process data on our behalf under data processing agreements.</p>
  </div>
  <div class="card">
    <h2>4. Data Security</h2>
    <p>All data is transmitted over HTTPS (TLS encryption). Passwords are hashed using bcrypt and are never stored in plain text. Payment data is handled entirely by Stripe and subject to PCI-DSS compliance. We perform regular security reviews of our infrastructure.</p>
  </div>
  <div class="card">
    <h2>5. Data Retention &amp; Deletion</h2>
    <p>Active vendor accounts and associated customer data are retained as long as the account is active. Upon cancellation, all data is retained for 30 days then permanently deleted.</p>
    <p>You may request immediate deletion of your account and data by emailing <a href="mailto:flavoronwheels26@gmail.com">flavoronwheels26@gmail.com</a>. We will complete deletion within 14 business days.</p>
  </div>
  <div class="card">
    <h2>6. Your Rights</h2>
    <p>You have the right to access, correct, or delete your personal data at any time. Contact us at <a href="mailto:flavoronwheels26@gmail.com">flavoronwheels26@gmail.com</a> to exercise these rights.</p>
    <p>If you are in the European Economic Area (EEA), you have additional rights under GDPR including the right to data portability and the right to lodge a complaint with your local data protection authority.</p>
  </div>
  <div class="card">
    <h2>7. Push Notifications</h2>
    <p>If you grant permission, we may send push notifications to your device about loyalty rewards, points earned, and messages from food trucks you follow. You can withdraw this permission at any time in your device settings.</p>
  </div>
  <div class="card">
    <h2>8. Cookies &amp; Local Storage</h2>
    <p>This application uses browser localStorage to maintain your session and preferences. We do not use third-party tracking cookies or advertising pixels.</p>
  </div>
  <div class="card">
    <h2>9. Changes to This Policy</h2>
    <p>We may update this Privacy Policy from time to time. We will notify you of significant changes by email at least 14 days before they take effect. Continued use of the Service after changes constitutes acceptance.</p>
  </div>
  <div class="card">
    <h2>10. Contact</h2>
    <p>TruckLoyal &mdash; Operated by Samuel McCune<br>Email: <a href="mailto:flavoronwheels26@gmail.com">flavoronwheels26@gmail.com</a></p>
  </div>
</div>
</body>
</html>"""
    resp = Response(html, mimetype='text/html')
    resp.headers['Cache-Control'] = 'public, max-age=86400'
    return resp


@app.route("/terms")
def terms_of_service():
    from flask import Response
    html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Terms of Service — TruckLoyal</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#FFF8F0;color:#2D1B0E;line-height:1.7;font-size:15px}
  .header{background:#FF5722;color:white;padding:28px 24px 20px;text-align:center}
  .header h1{font-size:22px;font-weight:900;margin-bottom:4px}
  .header p{font-size:13px;opacity:.85}
  .body{max-width:680px;margin:0 auto;padding:20px 20px 60px}
  .card{background:white;border:1.5px solid rgba(180,120,60,.15);border-radius:16px;padding:18px;margin-bottom:14px;box-shadow:0 2px 8px rgba(180,100,40,.08)}
  h2{font-size:15px;font-weight:800;margin-bottom:10px;color:#FF5722}
  p{margin-bottom:8px;color:#2D1B0E}
  p:last-child{margin-bottom:0}
  strong{font-weight:700}
  a{color:#FF5722;text-decoration:none}
</style>
</head>
<body>
<div class="header">
  <h1>🔥 TruckLoyal</h1>
  <p>Terms of Service &mdash; Last updated: April 2026</p>
</div>
<div class="body">
  <div class="card">
    <h2>1. Agreement to Terms</h2>
    <p>By creating a vendor account on TruckLoyal ("Service"), you agree to be bound by these Terms of Service ("Terms"). If you do not agree, do not use the Service. These Terms apply to all vendors who sign up for a paid subscription.</p>
  </div>
  <div class="card">
    <h2>2. Subscription &amp; Billing</h2>
    <p><strong>Free Trial:</strong> New vendor accounts receive a 14-day free trial beginning on the date of account creation. No charge is made during the trial period.</p>
    <p><strong>Billing Cycle:</strong> After the trial period ends, your payment method will be charged <strong>$9.99 USD</strong> on the same date each month.</p>
    <p><strong>Automatic Renewal:</strong> Your subscription automatically renews monthly until cancelled. By providing your payment method, you authorize TruckLoyal to charge your card on a recurring monthly basis.</p>
    <p><strong>Failed Payments:</strong> If your payment fails, you have a 5-day grace period to update your payment method before your account is suspended.</p>
    <p><strong>Price Changes:</strong> We reserve the right to change subscription pricing with at least 30 days written notice to your registered email address.</p>
  </div>
  <div class="card">
    <h2>3. Cancellation Policy</h2>
    <p><strong>How to Cancel:</strong> You may cancel at any time via Settings &rarr; Subscription &rarr; Cancel within the app, or by emailing <a href="mailto:flavoronwheels26@gmail.com">flavoronwheels26@gmail.com</a>.</p>
    <p><strong>Effect of Cancellation:</strong> Your account remains active through the end of your current billing period. You will not be charged for the next month.</p>
    <p><strong>No Partial Refunds:</strong> We do not issue refunds for partial months of service or unused features.</p>
    <p><strong>Trial Cancellation:</strong> Cancel during your 14-day trial and you will not be charged.</p>
  </div>
  <div class="card">
    <h2>4. Refund Policy</h2>
    <p>All subscription fees are non-refundable except as required by applicable law. If you believe you were charged in error, contact us within 30 days at <a href="mailto:flavoronwheels26@gmail.com">flavoronwheels26@gmail.com</a>.</p>
    <p>Chargebacks initiated without contacting us first may result in immediate account suspension.</p>
  </div>
  <div class="card">
    <h2>5. Service &amp; Data</h2>
    <p><strong>Your Data:</strong> You own your customer data. We do not sell your data or your customers' data to third parties.</p>
    <p><strong>Data Retention:</strong> Upon cancellation, your data is retained for 30 days then permanently deleted.</p>
    <p><strong>Account Termination:</strong> We reserve the right to suspend or terminate accounts that violate these Terms, engage in fraudulent activity, or fail to pay after the grace period.</p>
  </div>
  <div class="card">
    <h2>6. Limitation of Liability</h2>
    <p>TruckLoyal is provided "as is" without warranties of any kind. To the maximum extent permitted by law, TruckLoyal and its operators shall not be liable for any indirect, incidental, or consequential damages.</p>
    <p>Our total liability shall not exceed the amount you paid us in the 12 months preceding the claim.</p>
  </div>
  <div class="card">
    <h2>7. Governing Law</h2>
    <p>These Terms are governed by the laws of the State of Ohio, United States. Any disputes shall be resolved in the courts of Ohio.</p>
  </div>
  <div class="card">
    <h2>8. Contact</h2>
    <p>TruckLoyal &mdash; Operated by Samuel McCune<br>Email: <a href="mailto:flavoronwheels26@gmail.com">flavoronwheels26@gmail.com</a><br><br>For billing questions, cancellations, or disputes, email us. We respond within 2 business days.</p>
  </div>
</div>
</body>
</html>"""
    resp = Response(html, mimetype='text/html')
    resp.headers['Cache-Control'] = 'public, max-age=86400'
    return resp


# ══════════════════════════════════════════════════════
#  ADMIN AUTH
# ══════════════════════════════════════════════════════

@app.route("/api/admin/reset-locations", methods=["POST"])
def reset_locations():
    """Reset all stale location_today fields — call this daily at midnight via cron."""
    body = request.json or {}
    if body.get("secret") != ADMIN_PASSWORD:
        return err("Unauthorized", 401)

    today = date.today().isoformat()
    result = sb.table("vendors")\
        .update({"location_today": ""})\
        .neq("location_updated_date", today)\
        .neq("location_today", "")\
        .execute()
    cleared = len(result.data) if result.data else 0
    print(f"[DAILY RESET] Cleared location_today for {cleared} vendors")
    return ok({"cleared": cleared, "date": today})


@app.route("/api/admin/login", methods=["POST"])
@rate_limit(5, 900)
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
    """Manually activate, deactivate, or block a vendor."""
    body    = request.json or {}
    updates = {}

    if "plan_active" in body:
        updates["plan_active"] = bool(body["plan_active"])
        if updates["plan_active"]:
            updates["payment_failed_at"] = None
            updates["is_blocked"] = False

    if "is_blocked" in body:
        updates["is_blocked"]   = bool(body["is_blocked"])
        updates["blocked_email"] = body.get("blocked_email", "")
        if updates["is_blocked"]:
            updates["plan_active"] = False
            vendor = sb.table("vendors").select("email").eq("id", vendor_id).execute().data
            if vendor:
                updates["blocked_email"] = vendor[0]["email"]

    if updates:
        sb.table("vendors").update(updates).eq("id", vendor_id).execute()

    action = "blocked" if body.get("is_blocked") else \
             "unblocked" if body.get("is_blocked") == False else \
             "activated" if body.get("plan_active") else "deactivated"
    return ok(f"Vendor {action}")


@app.route("/api/admin/customer/<customer_id>/block", methods=["POST"])
@admin_required
def admin_block_customer(customer_id):
    """Block a customer account permanently."""
    body      = request.json or {}
    is_blocked = bool(body.get("is_blocked", True))
    customer  = sb.table("customers").select("email").eq("id", customer_id).execute().data
    if not customer:
        return err("Customer not found", 404)
    sb.table("customers").update({
        "is_blocked":    is_blocked,
        "blocked_email": customer[0]["email"] if is_blocked else "",
    }).eq("id", customer_id).execute()
    return ok(f"Customer {'blocked' if is_blocked else 'unblocked'}")


@app.route("/api/admin/customers", methods=["GET"])
@admin_required
def admin_get_customers():
    """Get all customers for admin view."""
    customers = sb.table("customers").select(
        "id, name, email, phone, created_at, is_blocked, referral_code"
    ).order("created_at", desc=True).limit(200).execute().data or []
    for c in customers:
        visits = sb.table("visits").select("id", count="exact")\
            .eq("customer_id", c["id"]).execute()
        c["total_visits"] = visits.count or 0
    return ok(customers)

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
    max_uses = body.get("max_uses")

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
@rate_limit(5, 3600)
def vendor_signup():
    body         = request.json or {}
    email        = (body.get("email") or "").strip().lower()
    password     = body.get("password") or ""
    truck_name   = (body.get("truck_name") or "My Food Truck").strip()
    owner_name   = (body.get("owner_name") or "").strip()
    promo_code   = (body.get("promo_code") or "").strip().upper()
    is_tester    = bool(body.get("is_tester", False))

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
        sb.table("promo_codes").update({"uses": pc["uses"] + 1}).eq("id", pc["id"]).execute()

    service_states = (body.get("service_states") or "").strip().upper()

    vendor = sb.table("vendors").insert({
        "email":           email,
        "password_hash":   pw_hash,
        "truck_name":      truck_name,
        "owner_name":      owner_name,
        "slug":            slug,
        "vendor_number":   vendor_number,
        "service_states":  service_states,
        "trial_ends_at":   trial_end,
        "promo_expires_at": promo_expires,
        "plan_active":     True if is_tester else False,
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

    try:
        sb.rpc("seed_vendor_defaults", {"v_id": vendor["id"]}).execute()
    except Exception:
        pass

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
        pass

    token = make_vendor_token(vendor["id"])
    return ok({
        "token":              token,
        "vendor":             _safe_vendor(vendor),
        "stripe_customer_id": stripe_customer_id,
        "trial_ends_at":      trial_end,
    }), 201


@app.route("/api/vendor/login", methods=["POST"])
@rate_limit(10, 60)
def vendor_login():
    body     = request.json or {}
    email    = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""

    row = sb.table("vendors").select("*").ilike("email", email).execute().data
    if not row:
        return err("Invalid email or password", 401)
    vendor = row[0]

    if vendor.get("is_blocked"):
        return err("This account has been suspended. Contact support@foodtruckrewards.app", 403)

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

    last_loc_date = vendor.get("location_updated_date", "")
    if vendor.get("location_today") and last_loc_date and last_loc_date != date.today().isoformat():
        sb.table("vendors").update({"location_today": "", "location_updated_date": date.today().isoformat()})\
            .eq("id", request.vendor_id).execute()
        vendor["location_today"] = ""

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
    vendor = sb.table("vendors").select(
        "stripe_customer_id, email, truck_name"
    ).eq("id", request.vendor_id).execute().data

    if not vendor:
        return err("Vendor not found", 404)
    vendor = vendor[0]

    stripe = _stripe()

    try:
        customer_id = vendor.get("stripe_customer_id")
        if not customer_id:
            sc = stripe.Customer.create(
                email=vendor["email"],
                name=vendor["truck_name"],
                metadata={"vendor_id": request.vendor_id},
                invoice_settings={"default_payment_method": None}
            )
            customer_id = sc.id
            sb.table("vendors").update({
                "stripe_customer_id": customer_id
            }).eq("id", request.vendor_id).execute()

        setup_intent = stripe.SetupIntent.create(
            customer=customer_id,
            payment_method_types=["card"],
            usage="off_session",
            metadata={"vendor_id": request.vendor_id}
        )

        return ok({"client_secret": setup_intent.client_secret})

    except Exception as e:
        return err(str(e))


@app.route("/api/vendor/create-subscription", methods=["POST"])
@vendor_required
def create_subscription():
    body           = request.json or {}
    payment_method = body.get("payment_method_id")

    if not payment_method:
        return err("payment_method_id is required")

    vendor = sb.table("vendors").select("*").eq("id", request.vendor_id).execute().data[0]
    stripe = _stripe()

    try:
        stripe.PaymentMethod.attach(payment_method, customer=vendor["stripe_customer_id"])
        stripe.Customer.modify(
            vendor["stripe_customer_id"],
            invoice_settings={"default_payment_method": payment_method}
        )

        subscription = stripe.Subscription.create(
            customer=vendor["stripe_customer_id"],
            items=[{"price": STRIPE_PRICE_ID}],
            trial_period_days=14,
            default_payment_method=payment_method,
            expand=["latest_invoice.payment_intent"],
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
    vendor = sb.table("vendors").select("stripe_customer_id").eq("id", request.vendor_id).execute().data[0]
    stripe = _stripe()
    try:
        session = stripe.billing_portal.Session.create(
            customer=vendor["stripe_customer_id"],
            return_url="https://truckloyal-api.onrender.com/app",
        )
        return ok({"url": session.url})
    except Exception as e:
        return err(str(e))


@app.route("/api/vendor/cancel-subscription", methods=["POST"])
@vendor_required
def cancel_subscription():
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
        sb.table("vendors").update({"plan_active": False}).eq("id", request.vendor_id).execute()
        return ok("Account cancelled.")


@app.route("/api/vendor/apply-promo", methods=["POST"])
@vendor_required
def apply_vendor_billing_promo():
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
    body     = request.json or {}
    confirm  = body.get("confirm")

    if confirm != "DELETE":
        return err('Send {"confirm": "DELETE"} to confirm account deletion')

    vendor = sb.table("vendors").select("stripe_sub_id, stripe_customer_id").eq("id", request.vendor_id).execute().data[0]

    try:
        stripe = _stripe()
        if vendor.get("stripe_sub_id"):
            stripe.Subscription.delete(vendor["stripe_sub_id"])
    except Exception:
        pass

    sb.table("vendors").delete().eq("id", request.vendor_id).execute()
    return ok("Account permanently deleted")


# ══════════════════════════════════════════════════════
#  VENDOR CONFIG
# ══════════════════════════════════════════════════════

@app.route("/api/vendor/brand", methods=["PATCH"])
@vendor_active_required
def update_brand():
    body    = request.json or {}
    allowed = ["truck_name", "tagline", "emoji", "color_primary",
               "color_secondary", "profile_picture_url", "location_today",
               "location_zip", "home_zip", "service_states"]
    updates = {k: v for k, v in body.items() if k in allowed}

    if "location_today" in updates:
        updates["location_updated_date"] = date.today().isoformat()

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
@vendor_active_required
def update_vendor_profile():
    body    = request.json or {}
    allowed = ["owner_name", "phone", "profile_picture_url"]
    updates = {k: v for k, v in body.items() if k in allowed}

    if body.get("email"):
        new_email = body["email"].strip().lower()
        existing = sb.table("vendors").select("id").ilike("email", new_email)\
            .neq("id", request.vendor_id).execute().data
        if existing:
            return err("That email is already in use by another account")
        updates["email"] = new_email

    if body.get("new_password"):
        if len(body["new_password"]) < 8:
            return err("Password must be at least 8 characters")
        vendor = sb.table("vendors").select("password_hash").eq("id", request.vendor_id).execute().data[0]
        if not bcrypt.checkpw((body.get("current_password","")).encode(), vendor["password_hash"].encode()):
            return err("Current password is incorrect")
        updates["password_hash"] = bcrypt.hashpw(body["new_password"].encode(), bcrypt.gensalt()).decode()

    vendor = sb.table("vendors").update(updates).eq("id", request.vendor_id).execute().data[0]
    return ok(_safe_vendor(vendor))


@app.route("/api/vendor/points-config", methods=["PATCH"])
@vendor_active_required
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
@vendor_active_required
def get_rewards():
    rows = sb.table("rewards").select("*").eq("vendor_id", request.vendor_id).order("sort_order").execute()
    return ok(rows.data)

@app.route("/api/vendor/rewards", methods=["POST"])
@vendor_active_required
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
@vendor_active_required
def delete_reward(reward_id):
    sb.table("rewards").delete().eq("id", reward_id).eq("vendor_id", request.vendor_id).execute()
    return ok("Deleted")

@app.route("/api/vendor/prizes", methods=["GET"])
@vendor_active_required
def get_prizes():
    rows = sb.table("spin_prizes").select("*").eq("vendor_id", request.vendor_id).execute()
    return ok(rows.data)

@app.route("/api/vendor/prizes", methods=["POST"])
@vendor_active_required
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
@vendor_active_required
def delete_prize(prize_id):
    sb.table("spin_prizes").delete().eq("id", prize_id).eq("vendor_id", request.vendor_id).execute()
    return ok("Deleted")

@app.route("/api/vendor/tiers", methods=["GET"])
@vendor_active_required
def get_tiers():
    rows = sb.table("tiers").select("*").eq("vendor_id", request.vendor_id).order("pts_threshold").execute()
    return ok(rows.data)

@app.route("/api/vendor/tiers/<tier_id>", methods=["PATCH"])
@vendor_active_required
def update_tier(tier_id):
    body    = request.json or {}
    allowed = ["name", "icon", "pts_threshold", "perks"]
    updates = {k: v for k, v in body.items() if k in allowed}
    row = sb.table("tiers").update(updates).eq("id", tier_id).eq("vendor_id", request.vendor_id).execute().data[0]
    return ok(row)


# ── Stats ──

@app.route("/api/vendor/analytics", methods=["GET"])
@vendor_active_required
def vendor_analytics():
    vid   = request.vendor_id
    today = date.today().isoformat()

    members      = sb.table("customer_trucks").select("id, points_balance, points_total, visit_count", count="exact").eq("vendor_id", vid).execute()
    visits_today = sb.table("visits").select("id", count="exact").eq("vendor_id", vid).gte("created_at", today).execute()
    visits_total = sb.table("visits").select("id", count="exact").eq("vendor_id", vid).execute()
    redemptions  = sb.table("redemptions").select("id, reward_id, status").eq("vendor_id", vid).neq("status", "expired").execute()

    member_data  = members.data or []
    total_pts_outstanding = sum(m.get("points_balance", 0) for m in member_data)
    total_pts_earned      = sum(m.get("points_total", 0) for m in member_data)
    avg_pts    = round(total_pts_earned / len(member_data)) if member_data else 0
    avg_visits = round(sum(m.get("visit_count", 0) for m in member_data) / len(member_data), 1) if member_data else 0
    active_members = len([m for m in member_data if m.get("visit_count", 0) > 0])

    rdm_data = redemptions.data or []
    reward_ids = list({r["reward_id"] for r in rdm_data if r.get("reward_id")})
    reward_map = {}
    if reward_ids:
        rewards_rows = sb.table("rewards").select("id, name, emoji").in_("id", reward_ids).execute().data or []
        reward_map = {r["id"]: f"{r.get('emoji','🎁')} {r.get('name','Reward')}" for r in rewards_rows}

    rdm_by_reward = {}
    for r in rdm_data:
        key = reward_map.get(r.get("reward_id"), "🎁 Unknown Reward")
        rdm_by_reward[key] = rdm_by_reward.get(key, 0) + 1

    return ok({
        "total_members":         members.count or 0,
        "active_members":        active_members,
        "visits_today":          visits_today.count or 0,
        "visits_total":          visits_total.count or 0,
        "total_redemptions":     len(rdm_data),
        "redemptions_by_reward": rdm_by_reward,
        "total_pts_outstanding": total_pts_outstanding,
        "total_pts_earned":      total_pts_earned,
        "avg_pts_per_member":    avg_pts,
        "avg_visits_per_member": avg_visits,
    })


@app.route("/api/vendor/members", methods=["GET"])
@vendor_active_required
def vendor_members():
    vid  = request.vendor_id
    rows = sb.table("customer_trucks").select(
        "points_balance, points_total, visit_count, current_streak, "
        "longest_streak, last_visit_date, "
        "customers(name, rewards_id, profile_picture_url)"
    ).eq("vendor_id", vid).order("points_total", desc=True).limit(100).execute()

    members = []
    for r in (rows.data or []):
        cust = r.pop("customers", {}) or {}
        members.append({
            "name":                cust.get("name", "Member"),
            "rewards_id":          cust.get("rewards_id", ""),
            "profile_picture_url": cust.get("profile_picture_url", ""),
            "points_balance":      r.get("points_balance", 0),
            "points_total":        r.get("points_total", 0),
            "visit_count":         r.get("visit_count", 0),
            "current_streak":      r.get("current_streak", 0),
            "last_visit":          r.get("last_visit_date", ""),
        })
    return ok(members)


@app.route("/api/vendor/stats", methods=["GET"])
@vendor_active_required
def vendor_stats():
    vid   = request.vendor_id
    today = date.today().isoformat()
    members      = sb.table("customer_trucks").select("id", count="exact").eq("vendor_id", vid).execute()
    visits_today = sb.table("visits").select("id", count="exact").eq("vendor_id", vid).gte("created_at", today).execute()
    redemptions  = sb.table("redemptions").select("id", count="exact").eq("vendor_id", vid).neq("status", "expired").execute()
    return ok({
        "total_members":     members.count      or 0,
        "visits_today":      visits_today.count or 0,
        "total_redemptions": redemptions.count  or 0,
    })


# ══════════════════════════════════════════════════════
#  VENDOR — AWARD POINTS AT WINDOW
# ══════════════════════════════════════════════════════

@app.route("/api/vendor/find-customer", methods=["POST"])
@vendor_active_required
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
@vendor_active_required
def award_points():
    body        = request.json or {}
    vendor_id   = request.vendor_id
    customer_id = body.get("customer_id")
    try:
        order_total = float(body.get("order_total") or 0)
    except (ValueError, TypeError):
        order_total = 0.0

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
@vendor_active_required
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

    reward_data   = r.get("rewards") or {}
    customer_data = r.get("customers") or {}
    return ok({
        "redemption_id": r["id"],
        "code":          code,
        "reward_name":   reward_data.get("name", "Reward"),
        "reward_emoji":  reward_data.get("emoji", "🎁"),
        "pts_cost":      reward_data.get("pts_required", 0),
        "customer_name": customer_data.get("name", "Customer"),
        "customer_rid":  customer_data.get("rewards_id", ""),
        "status":        r["status"],
    })


@app.route("/api/vendor/confirm-redemption", methods=["POST"])
@vendor_active_required
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

    reward_data = r.get("rewards") or {}
    return ok({
        "confirmed":    True,
        "reward_name":  reward_data.get("name", "Reward"),
        "pts_deducted": reward_data.get("pts_required", 0),
    })


# ══════════════════════════════════════════════════════
#  PUBLIC — TRUCK CONFIG & PICTURES
# ══════════════════════════════════════════════════════

@app.route("/api/vendor/upload-picture", methods=["POST"])
@vendor_active_required
def vendor_upload_picture():
    body  = request.json or {}
    b64   = body.get("image_b64", "")
    if not b64:
        return err("image_b64 required")

    try:
        import base64, uuid
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
        public_url = "data:image/jpeg;base64," + b64 if "data:" not in b64 else b64

    sb.table("vendors").update({
        "profile_picture_url": public_url
    }).eq("id", request.vendor_id).execute()

    return ok({"url": public_url})


@app.route("/api/customer/upload-picture", methods=["POST"])
def customer_upload_picture():
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
    q = (request.args.get("q") or "").strip()
    if len(q) < 1:
        return ok([])

    results = []

    name_rows = sb.table("vendors").select(
        "id, truck_name, emoji, slug, vendor_number, "
        "color_primary, color_secondary, tagline, plan_active, trial_ends_at, promo_expires_at"
    ).ilike("truck_name", f"%{q}%").limit(10).execute().data
    results.extend(name_rows)

    if q.isdigit() or (q.startswith('#') and q[1:].isdigit()):
        num = q.lstrip('#')
        num_rows = sb.table("vendors").select(
            "id, truck_name, emoji, slug, vendor_number, "
            "color_primary, color_secondary, tagline, plan_active, trial_ends_at, promo_expires_at"
        ).eq("vendor_number", num).limit(5).execute().data
        existing_ids = {r["id"] for r in results}
        results.extend([r for r in num_rows if r["id"] not in existing_ids])

    now = datetime.utcnow()
    active = []
    for r in results:
        if _vendor_is_active(r):
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
        "plan_active, trial_ends_at, promo_expires_at, location_today, location_updated_date"
    ).eq("slug", slug).execute().data

    if not row: return err("Truck not found", 404)
    vendor = row[0]

    if not _vendor_is_active(vendor):
        return err("This truck's loyalty program is not currently active", 403)

    last_loc_date = vendor.get("location_updated_date", "")
    if vendor.get("location_today") and last_loc_date and last_loc_date != date.today().isoformat():
        vendor["location_today"] = ""

    rewards = sb.table("rewards").select("*").eq("vendor_id", vendor["id"]).eq("is_active", True).order("sort_order").execute().data
    prizes  = sb.table("spin_prizes").select("*").eq("vendor_id", vendor["id"]).eq("is_active", True).execute().data
    tiers   = sb.table("tiers").select("*").eq("vendor_id", vendor["id"]).order("pts_threshold").execute().data

    return ok({"vendor": vendor, "rewards": rewards, "prizes": prizes, "tiers": tiers})


# ══════════════════════════════════════════════════════
#  CUSTOMER AUTH
# ══════════════════════════════════════════════════════

@app.route("/api/customer/signup", methods=["POST"])
@rate_limit(5, 3600)
def customer_signup():
    body     = request.json or {}
    name     = (body.get("name") or "").strip()
    email    = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""

    if not name:  return err("Name is required")
    if not email or "@" not in email: return err("Valid email is required")
    if not password or len(password) < 8:
        return err("Password must be at least 8 characters")

    try:
        blocked = sb.table("customers").select("id").eq("blocked_email", email).execute().data
        if blocked:
            return err("This email address cannot be used to create an account.", 403)
        blocked_v = sb.table("vendors").select("id").eq("blocked_email", email).execute().data
        if blocked_v:
            return err("This email address cannot be used to create an account.", 403)
    except Exception:
        pass  # blocked_email column may not exist yet — safe to skip

    if sb.table("customers").select("id").ilike("email", email).execute().data:
        return err("An account with this email already exists. Please sign in.")

    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

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
        "name": name, "email": email,
        "password_hash": pw_hash, "phone": "",
        "rewards_id": rid, "referral_code": ref_code, "referred_by": referred_by,
    }).execute().data[0]

    token = make_customer_token(customer["id"])
    return ok({"token": token, "customer": _safe_customer(customer), "trucks": []}), 201


@app.route("/api/customer/login", methods=["POST"])
@rate_limit(10, 60)
def customer_login():
    body     = request.json or {}
    email    = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""

    if not email:
        return err("Email is required")
    if not password:
        return err("Password is required")

    row = sb.table("customers").select("*").ilike("email", email).execute().data
    if not row:
        return err("No account found with that email. Please sign up.", 404)

    customer = row[0]

    if customer.get("is_blocked"):
        return err("This account has been suspended. Contact support@foodtruckrewards.app", 403)

    pw_hash  = customer.get("password_hash")

    if not pw_hash:
        print(f"[CUSTOMER LOGIN] No password_hash for: {email}")
        return err("Account needs password setup. Please use forgot password.", 401)

    try:
        if not bcrypt.checkpw(password.encode(), pw_hash.encode()):
            return err("Invalid email or password", 401)
    except Exception as e:
        print(f"[CUSTOMER LOGIN ERROR] {e}")
        return err("Login error — please try again", 500)

    trucks = _get_customer_trucks(customer["id"])
    token  = make_customer_token(customer["id"])
    return ok({"token": token, "customer": _safe_customer(customer), "trucks": trucks})


@app.route("/api/customer/profile", methods=["PATCH"])
def update_customer_profile():
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

    visit_rows = sb.table("visits").insert({
        "customer_id": customer_id, "vendor_id": vendor_id,
        "pts_earned": total_pts, "streak_day": new_streak, "awarded_by": "customer",
    }).execute().data
    if not visit_rows:
        return err("Failed to record visit — please try again")
    visit = visit_rows[0]

    prizes = sb.table("spin_prizes").select("*").eq("vendor_id", vendor_id).eq("is_active", True).execute().data
    spin_result = None
    if prizes:
        total_w = sum(p["probability"] for p in prizes)
        r = random.uniform(0, total_w); cum = 0; won = prizes[-1]
        for p in prizes:
            cum += p["probability"]
            if r <= cum: won = p; break

        spin_pts = int(won.get("prize_value") or 25)
        spin_rows = sb.table("spin_results").insert({
            "customer_id": customer_id, "vendor_id": vendor_id,
            "visit_id": visit["id"], "prize_id": won["id"],
            "prize_name": won["name"], "prize_type": won.get("prize_type","points"),
            "prize_value": won.get("prize_value","25"),
        }).execute().data
        spin_result = spin_rows[0] if spin_rows else None
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
    visits = sb.table("visits").select(
        "*, spin_results!spin_results_visit_id_fkey(prize_name, prize_value)"
    ).eq("customer_id", customer_id).order("created_at", desc=True).limit(50).execute()
    redemptions = sb.table("redemptions").select(
        "*, rewards(name, emoji)"
    ).eq("customer_id", customer_id).order("created_at", desc=True).limit(30).execute()
    return ok({"visits": visits.data, "redemptions": redemptions.data})


@app.route("/api/customer/<customer_id>/trucks", methods=["GET"])
def customer_trucks_list(customer_id):
    return ok(_get_customer_trucks(customer_id))


# ══════════════════════════════════════════════════════
#  PASSWORD RESET
# ══════════════════════════════════════════════════════

def _send_reset_email(to_email: str, reset_url: str, user_type: str, name: str) -> bool:
    """Send password reset email via Gmail SMTP."""
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    gmail_user = os.environ.get("GMAIL_USER", "")
    gmail_pass = os.environ.get("GMAIL_APP_PASSWORD", "")

    if not gmail_user or not gmail_pass:
        print(f"[EMAIL] No GMAIL_USER/GMAIL_APP_PASSWORD set.")
        print(f"[EMAIL DEBUG] Reset URL: {reset_url}")
        return False

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
      Food Truck Rewards · flavoronwheels26@gmail.com
    </p>
  </div>
</body>
</html>"""

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Reset your Food Truck Rewards password"
        msg["From"]    = f"Food Truck Rewards <{gmail_user}>"
        msg["To"]      = to_email
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(gmail_user, gmail_pass)
            server.sendmail(gmail_user, to_email, msg.as_string())

        print(f"[EMAIL SUCCESS] Sent to {to_email} via Gmail")
        return True

    except Exception as e:
        print(f"[EMAIL ERROR] {e}")
        print(f"[EMAIL DEBUG] Reset URL: {reset_url}")
        return False


@app.route("/api/auth/forgot-password", methods=["POST"])
@rate_limit(5, 3600)
def forgot_password():
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

        try:
            sb.table("password_reset_tokens").delete().eq("user_id", user["id"]).eq("used", False).execute()
        except Exception:
            pass

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
            return SAFE_RESPONSE

        # Reset link points to the API-served app URL
        app_url   = os.environ.get("APP_URL", "https://truckloyal-api.onrender.com/app")
        reset_url = f"{app_url}?reset_token={raw_token}&user_type={user_type}&email={email}"
        name      = user.get(name_field, "")
        _send_reset_email(email, reset_url, user_type, name)

    except Exception as e:
        print(f"[FORGOT PASSWORD ERROR] {e}")

    return SAFE_RESPONSE


@app.route("/api/auth/reset-password", methods=["POST"])
def reset_password():
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

    now = datetime.utcnow()
    tokens = sb.table("password_reset_tokens").select("*").ilike("email", email).eq("user_type", user_type).eq("used", False).execute().data

    if not tokens:
        return err("This reset link is invalid or has already been used", 400)

    matched = None
    for t in tokens:
        exp = datetime.fromisoformat(t["expires_at"].replace("Z","").replace("+00:00","").split("+")[0].strip())
        if exp < now:
            continue
        try:
            if bcrypt.checkpw(raw_token.encode(), t["token_hash"].encode()):
                matched = t
                break
        except Exception:
            continue

    if not matched:
        return err("This reset link is invalid or has expired. Please request a new one.", 400)

    new_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()

    table = "vendors" if user_type == "vendor" else "customers"
    sb.table(table).update({"password_hash": new_hash}).eq("id", matched["user_id"]).execute()

    sb.table("password_reset_tokens").update({
        "used": True,
    }).eq("id", matched["id"]).execute()

    sb.table("password_reset_tokens").delete().eq("user_id", matched["user_id"]).eq("used", False).execute()

    return ok("Password updated successfully. You can now sign in with your new password.")


@app.route("/api/auth/verify-reset-token", methods=["POST"])
def verify_reset_token():
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
#  STRIPE WEBHOOKS
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
        sb.table("vendors").update({
            "plan_active":        False,
            "payment_failed_at":  datetime.utcnow().isoformat(),
        }).eq("stripe_customer_id", obj["customer"]).execute()

    elif etype == "invoice.payment_succeeded":
        sb.table("vendors").update({
            "plan_active":        True,
            "payment_failed_at":  None,
        }).eq("stripe_customer_id", obj["customer"]).execute()

    return ok("received")


# ══════════════════════════════════════════════════════
#  PUSH NOTIFICATIONS
# ══════════════════════════════════════════════════════

@app.route("/api/vendor/push", methods=["POST"])
@vendor_active_required
@rate_limit(20, 3600)
def send_push():
    body    = request.json or {}
    vid     = request.vendor_id
    title   = (body.get("title") or "").strip()
    message = (body.get("message") or "").strip()
    ntype   = body.get("type", "broadcast")

    if not title or not message:
        return err("Title and message are required")

    members = sb.table("customer_trucks").select(
        "customer_id, customers(push_token, name)"
    ).eq("vendor_id", vid).execute().data or []

    vendor = sb.table("vendors").select("truck_name").eq("id", vid).execute().data
    truck_name = vendor[0]["truck_name"] if vendor else "Your Food Truck"

    try:
        sb.table("notifications").insert({
            "vendor_id": vid,
            "title":     title,
            "message":   message,
            "type":      ntype,
            "sent_to":   len(members),
        }).execute()
    except Exception as e:
        print(f"[NOTIFY LOG ERROR] {e}")

    tokens = []
    for m in members:
        cust = m.get("customers") or {}
        token = cust.get("push_token")
        if token and token.startswith("ExponentPushToken"):
            tokens.append(token)

    sent = 0
    if tokens:
        try:
            import urllib.request, json as _json
            payload = _json.dumps({
                "to": tokens,
                "title": f"🔥 {truck_name}",
                "body": message,
                "sound": "default",
                "data": {"type": ntype, "vendor_id": vid}
            }).encode()
            req = urllib.request.Request(
                "https://exp.host/--/api/v2/push/send",
                data=payload,
                headers={"Content-Type": "application/json", "Accept": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                sent = len(tokens)
        except Exception as e:
            print(f"[PUSH ERROR] {e}")

    return ok({"sent": sent, "total_members": len(members)})


@app.route("/api/vendor/notifications", methods=["GET"])
@vendor_active_required
def get_notifications():
    vid = request.vendor_id
    rows = sb.table("notifications").select("*").eq("vendor_id", vid)\
        .order("created_at", desc=True).limit(20).execute()
    return ok(rows.data or [])


@app.route("/api/customer/<customer_id>/push-token", methods=["POST"])
def save_push_token(customer_id):
    body  = request.json or {}
    token = body.get("token", "")
    if not token:
        return err("Token required")
    sb.table("customers").update({"push_token": token}).eq("id", customer_id).execute()
    return ok("saved")


# ══════════════════════════════════════════════════════
#  PROMOS & FLASH DEALS
# ══════════════════════════════════════════════════════

@app.route("/api/vendor/promos", methods=["GET"])
@vendor_active_required
def get_promos():
    vid = request.vendor_id
    rows = sb.table("promos").select("*").eq("vendor_id", vid)\
        .order("created_at", desc=True).limit(20).execute()
    return ok(rows.data or [])


@app.route("/api/vendor/promos", methods=["POST"])
@vendor_active_required
def create_promo():
    body        = request.json or {}
    vid         = request.vendor_id
    title       = (body.get("title") or "").strip()
    description = (body.get("description") or "").strip()
    promo_type  = body.get("promo_type", "bonus_points")
    value       = body.get("value", 2)
    code        = (body.get("code") or "").strip().upper()
    expires_at  = body.get("expires_at")

    if not title: return err("Title required")
    if not code:
        import string as _s
        code = "".join(random.choices(_s.ascii_uppercase + "0123456789", k=6))

    existing = sb.table("promos").select("id").eq("vendor_id", vid).eq("code", code).execute().data
    if existing: return err("Promo code already exists")

    row = sb.table("promos").insert({
        "vendor_id":   vid,
        "title":       title,
        "description": description,
        "promo_type":  promo_type,
        "value":       value,
        "code":        code,
        "expires_at":  expires_at,
        "active":      True,
        "used_count":  0,
    }).execute().data[0]
    return ok(row), 201


@app.route("/api/vendor/promos/<promo_id>", methods=["DELETE"])
@vendor_active_required
def delete_promo(promo_id):
    vid = request.vendor_id
    sb.table("promos").delete().eq("id", promo_id).eq("vendor_id", vid).execute()
    return ok("deleted")


@app.route("/api/truck/<slug>/promos", methods=["GET"])
def get_truck_promos(slug):
    vendor = sb.table("vendors").select("id").ilike("slug", slug).execute().data
    if not vendor: return err("Truck not found", 404)
    vid = vendor[0]["id"]
    now = datetime.utcnow().isoformat()
    rows = sb.table("promos").select("*").eq("vendor_id", vid).eq("active", True)\
        .or_(f"expires_at.is.null,expires_at.gte.{now}").execute()
    return ok(rows.data or [])


@app.route("/api/customer/apply-promo", methods=["POST"])
def apply_promo():
    body        = request.json or {}
    customer_id = body.get("customer_id")
    vendor_id   = body.get("vendor_id")
    code        = (body.get("code") or "").strip().upper()
    if not all([customer_id, vendor_id, code]):
        return err("customer_id, vendor_id, code required")

    now = datetime.utcnow().isoformat()
    promo = sb.table("promos").select("*").eq("vendor_id", vendor_id).eq("code", code)\
        .eq("active", True).or_(f"expires_at.is.null,expires_at.gte.{now}").execute().data
    if not promo: return err("Promo not found or expired", 404)
    p = promo[0]

    used = sb.table("promo_uses").select("id").eq("promo_id", p["id"])\
        .eq("customer_id", customer_id).execute().data
    if used: return err("You've already used this promo")

    sb.table("promo_uses").insert({"promo_id": p["id"], "customer_id": customer_id, "vendor_id": vendor_id}).execute()
    sb.table("promos").update({"used_count": (p.get("used_count") or 0) + 1}).eq("id", p["id"]).execute()

    bonus_pts = 0
    if p["promo_type"] == "bonus_points":
        bonus_pts = int(p["value"])
        ct = sb.table("customer_trucks").select("points_balance, points_total")\
            .eq("customer_id", customer_id).eq("vendor_id", vendor_id).execute().data
        if ct:
            new_bal = ct[0]["points_balance"] + bonus_pts
            new_tot = ct[0]["points_total"] + bonus_pts
            sb.table("customer_trucks").update({"points_balance": new_bal, "points_total": new_tot})\
                .eq("customer_id", customer_id).eq("vendor_id", vendor_id).execute()

    return ok({"promo": p, "bonus_pts": bonus_pts, "promo_type": p["promo_type"]})


# ══════════════════════════════════════════════════════
#  VENDOR SCHEDULE / LOCATION
# ══════════════════════════════════════════════════════

@app.route("/api/vendor/schedule", methods=["GET"])
@vendor_active_required
def get_schedule():
    vid  = request.vendor_id
    rows = sb.table("vendor_schedule").select("*").eq("vendor_id", vid)\
        .order("day_of_week").execute()
    return ok(rows.data or [])


@app.route("/api/vendor/schedule", methods=["POST"])
@vendor_active_required
def save_schedule():
    body = request.json or {}
    vid  = request.vendor_id
    days = body.get("days", [])

    sb.table("vendor_schedule").delete().eq("vendor_id", vid).execute()
    if days:
        for d in days:
            d["vendor_id"] = vid
        sb.table("vendor_schedule").insert(days).execute()
    return ok("saved")


@app.route("/api/trucks/nearby", methods=["GET"])
def trucks_nearby():
    today = date.today().isoformat()
    dow   = date.today().weekday()

    vendors = sb.table("vendors").select(
        "id, truck_name, slug, emoji, color_primary, profile_picture_url, "
        "location_today, pts_per_visit, pts_per_dollar, plan_active, trial_ends_at"
    ).execute().data or []

    result = []
    for v in vendors:
        if not _vendor_is_active(v): continue
        sched = sb.table("vendor_schedule").select("*")\
            .eq("vendor_id", v["id"]).eq("day_of_week", dow).execute().data
        ratings = sb.table("reviews").select("rating")\
            .eq("vendor_id", v["id"]).execute().data or []
        avg_rating = round(sum(r["rating"] for r in ratings) / len(ratings), 1) if ratings else None
        v["schedule_today"] = sched[0] if sched else None
        v["avg_rating"]     = avg_rating
        v["review_count"]   = len(ratings)
        result.append(v)

    return ok(result)


# ══════════════════════════════════════════════════════
#  REVIEWS & RATINGS
# ══════════════════════════════════════════════════════

@app.route("/api/customer/review", methods=["POST"])
def submit_review():
    body        = request.json or {}
    customer_id = body.get("customer_id")
    vendor_id   = body.get("vendor_id")
    rating      = body.get("rating")
    comment     = (body.get("comment") or "").strip()[:300]

    if not all([customer_id, vendor_id, rating]):
        return err("customer_id, vendor_id, rating required")
    try:
        if not 1 <= int(rating) <= 5:
            return err("Rating must be 1-5")
    except (ValueError, TypeError):
        return err("Rating must be a number 1-5")

    existing = sb.table("reviews").select("id").eq("customer_id", customer_id)\
        .eq("vendor_id", vendor_id).execute().data
    if existing:
        sb.table("reviews").update({"rating": rating, "comment": comment})\
            .eq("id", existing[0]["id"]).execute()
    else:
        sb.table("reviews").insert({
            "customer_id": customer_id, "vendor_id": vendor_id,
            "rating": rating, "comment": comment,
        }).execute()

    return ok("saved")


@app.route("/api/truck/<slug>/schedule", methods=["GET"])
def get_truck_schedule(slug):
    vendor = sb.table("vendors").select("id").ilike("slug", slug).execute().data
    if not vendor: return err("Truck not found", 404)
    vid = vendor[0]["id"]
    rows = sb.table("vendor_schedule").select("*").eq("vendor_id", vid)\
        .order("day_of_week").execute()
    return ok(rows.data or [])


@app.route("/api/truck/<slug>/reviews", methods=["GET"])
def get_truck_reviews(slug):
    vendor = sb.table("vendors").select("id").ilike("slug", slug).execute().data
    if not vendor: return err("Truck not found", 404)
    vid = vendor[0]["id"]
    rows = sb.table("reviews").select(
        "rating, comment, created_at, customers(name, profile_picture_url)"
    ).eq("vendor_id", vid).order("created_at", desc=True).limit(20).execute()
    return ok(rows.data or [])


@app.route("/api/vendor/reviews", methods=["GET"])
@vendor_active_required
def vendor_reviews():
    vid  = request.vendor_id
    rows = sb.table("reviews").select(
        "rating, comment, created_at, customers(name, profile_picture_url)"
    ).eq("vendor_id", vid).order("created_at", desc=True).limit(50).execute()
    data = rows.data or []
    avg  = round(sum(r["rating"] for r in data) / len(data), 1) if data else 0
    return ok({"reviews": data, "avg_rating": avg, "total": len(data)})


# ══════════════════════════════════════════════════════
#  REFERRALS
# ══════════════════════════════════════════════════════

@app.route("/api/customer/referral-complete", methods=["POST"])
def referral_complete():
    body        = request.json or {}
    customer_id = body.get("customer_id")
    vendor_id   = body.get("vendor_id")
    if not customer_id: return err("customer_id required")

    customer = sb.table("customers").select("referred_by, referral_rewarded")\
        .eq("id", customer_id).execute().data
    if not customer: return err("Customer not found", 404)
    c = customer[0]

    if c.get("referral_rewarded"): return ok("already rewarded")
    if not c.get("referred_by"):   return ok("no referrer")

    referrer_id = c["referred_by"]
    REFERRAL_BONUS = 100

    if vendor_id:
        ct = sb.table("customer_trucks").select("points_balance, points_total")\
            .eq("customer_id", referrer_id).eq("vendor_id", vendor_id).execute().data
        if ct:
            sb.table("customer_trucks").update({
                "points_balance": ct[0]["points_balance"] + REFERRAL_BONUS,
                "points_total":   ct[0]["points_total"]   + REFERRAL_BONUS,
            }).eq("customer_id", referrer_id).eq("vendor_id", vendor_id).execute()

    if vendor_id:
        ct2 = sb.table("customer_trucks").select("points_balance, points_total")\
            .eq("customer_id", customer_id).eq("vendor_id", vendor_id).execute().data
        if ct2:
            sb.table("customer_trucks").update({
                "points_balance": ct2[0]["points_balance"] + REFERRAL_BONUS,
                "points_total":   ct2[0]["points_total"]   + REFERRAL_BONUS,
            }).eq("customer_id", customer_id).eq("vendor_id", vendor_id).execute()

    sb.table("customers").update({"referral_rewarded": True})\
        .eq("id", customer_id).execute()

    return ok({"bonus_pts": REFERRAL_BONUS})


# ══════════════════════════════════════════════════════
#  LEADERBOARD
# ══════════════════════════════════════════════════════

@app.route("/api/truck/<slug>/leaderboard", methods=["GET"])
def truck_leaderboard(slug):
    vendor = sb.table("vendors").select("id").ilike("slug", slug).execute().data
    if not vendor: return err("Truck not found", 404)
    vid = vendor[0]["id"]

    rows = sb.table("customer_trucks").select(
        "points_total, visit_count, customers(name, profile_picture_url)"
    ).eq("vendor_id", vid).order("points_total", desc=True).limit(10).execute().data or []

    board = []
    for i, r in enumerate(rows):
        cust = r.get("customers") or {}
        board.append({
            "rank":                i + 1,
            "name":                cust.get("name", "Member"),
            "profile_picture_url": cust.get("profile_picture_url"),
            "points_total":        r.get("points_total", 0),
            "visit_count":         r.get("visit_count", 0),
        })
    return ok(board)


# ══════════════════════════════════════════════════════
#  VENDOR SOCIAL FEED
# ══════════════════════════════════════════════════════

@app.route("/api/vendor/posts", methods=["GET"])
@vendor_active_required
def get_posts():
    vid  = request.vendor_id
    rows = sb.table("vendor_posts").select("*").eq("vendor_id", vid)\
        .order("created_at", desc=True).limit(20).execute()
    return ok(rows.data or [])


@app.route("/api/vendor/posts", methods=["POST"])
@vendor_active_required
def create_post():
    body    = request.json or {}
    vid     = request.vendor_id
    content = (body.get("content") or "").strip()[:500]
    image   = body.get("image_url", "")
    emoji   = body.get("emoji", "🚚")

    if not content: return err("Post content required")

    row = sb.table("vendor_posts").insert({
        "vendor_id": vid, "content": content,
        "image_url": image, "emoji": emoji,
    }).execute().data[0]
    return ok(row), 201


@app.route("/api/vendor/posts/<post_id>", methods=["DELETE"])
@vendor_active_required
def delete_post(post_id):
    vid = request.vendor_id
    sb.table("vendor_posts").delete().eq("id", post_id).eq("vendor_id", vid).execute()
    return ok("deleted")


@app.route("/api/customer/feed", methods=["GET"])
def customer_feed():
    customer_id = request.args.get("customer_id")
    if not customer_id: return err("customer_id required")

    trucks = sb.table("customer_trucks").select("vendor_id")\
        .eq("customer_id", customer_id).execute().data or []
    vids = [t["vendor_id"] for t in trucks]
    if not vids: return ok([])

    posts = []
    for vid in vids:
        rows = sb.table("vendor_posts").select(
            "*, vendors(truck_name, emoji, profile_picture_url)"
        ).eq("vendor_id", vid).order("created_at", desc=True).limit(5).execute().data or []
        posts.extend(rows)

    posts.sort(key=lambda x: x.get("created_at",""), reverse=True)
    return ok(posts[:30])


# ══════════════════════════════════════════════════════
#  REVENUE ANALYTICS
# ══════════════════════════════════════════════════════

@app.route("/api/vendor/revenue", methods=["GET"])
@vendor_active_required
def vendor_revenue():
    vid = request.vendor_id

    vendor = sb.table("vendors").select("pts_per_dollar, pts_per_visit")\
        .eq("id", vid).execute().data
    pts_per_dollar = vendor[0]["pts_per_dollar"] if vendor else 10

    visits = sb.table("visits").select("pts_earned, created_at")\
        .eq("vendor_id", vid).order("created_at", desc=True).execute().data or []

    total_revenue  = 0
    this_month_rev = 0
    this_week_rev  = 0
    now = datetime.utcnow()
    week_start = now - timedelta(days=now.weekday())
    month_start = now.replace(day=1)

    monthly = {}
    for v in visits:
        order_pts = max(0, v.get("pts_earned", 0))
        dollars   = round(order_pts / pts_per_dollar, 2) if pts_per_dollar else 0
        total_revenue += dollars
        try:
            vdate = _parse_dt(v["created_at"])
            if vdate >= _parse_dt(week_start.isoformat()):  this_week_rev  += dollars
            if vdate >= _parse_dt(month_start.isoformat()): this_month_rev += dollars
            month_key = vdate.strftime("%b %Y")
            monthly[month_key] = monthly.get(month_key, 0) + dollars
        except: pass

    return ok({
        "total_revenue":     round(total_revenue, 2),
        "this_week_revenue": round(this_week_rev, 2),
        "this_month_revenue":round(this_month_rev, 2),
        "monthly_breakdown": [{"month": k, "revenue": round(v, 2)} for k,v in sorted(monthly.items())],
        "total_visits":      len(visits),
        "avg_order_value":   round(total_revenue / len(visits), 2) if visits else 0,
    })


# ══════════════════════════════════════════════════════
#  DISCOVERY
# ══════════════════════════════════════════════════════

@app.route("/api/discover", methods=["GET"])
def discover():
    state_filter = request.args.get("state", "").strip().upper()
    dow = date.today().weekday()

    vendors = sb.table("vendors").select(
        "id, truck_name, slug, emoji, color_primary, profile_picture_url, "
        "location_today, service_states, plan_active, trial_ends_at"
    ).execute().data or []

    result = []
    for v in vendors:
        if not _vendor_is_active(v): continue

        if state_filter:
            states = [s.strip().upper() for s in (v.get("service_states") or "").split(",") if s.strip()]
            if not states or state_filter not in states:
                continue

        sched = sb.table("vendor_schedule").select("location, hours")\
            .eq("vendor_id", v["id"]).eq("day_of_week", dow).execute().data
        today_sched = sched[0] if sched else {}
        display_location = v.get("location_today") or today_sched.get("location") or ""
        display_hours    = today_sched.get("hours") or ""

        ratings = sb.table("reviews").select("rating").eq("vendor_id", v["id"]).execute().data or []
        member_count = sb.table("customer_trucks").select("id", count="exact")\
            .eq("vendor_id", v["id"]).execute().count or 0

        v["display_location"] = display_location
        v["display_hours"]    = display_hours
        v["avg_rating"]       = round(sum(r["rating"] for r in ratings)/len(ratings),1) if ratings else None
        v["review_count"]     = len(ratings)
        v["member_count"]     = member_count
        result.append(v)

    return ok(result)


# ══════════════════════════════════════════════════════
#  RUN
# ══════════════════════════════════════════════════════

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
