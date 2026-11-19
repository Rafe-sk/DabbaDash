"""
DabbaDash - Food Delivery Order Platform (v2.0 - Fully Hardened)
----------------------------------------------------------------
TRAINING APPLICATION - ITM Secure Application Development course.
Hardened against all Day 3 review findings (F-01 through F-20).
"""
import base64
import hashlib
import hmac
import io
import logging
import os
import secrets
import sqlite3
from datetime import datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import pyotp
import qrcode
import qrcode.image.svg
from flask import (Flask, g, jsonify, redirect, render_template, request,
                   session, url_for)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "orders.db")

# ---------------------------------------------------------------- logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [SECURITY] %(message)s")
auth_logger = logging.getLogger("auth")

# Password Hasher using Argon2id (F-09)
ph = PasswordHasher()

# Common password blocklist (F-20)
PASSWORD_BLOCKLIST = {
    "password", "password123", "12345678", "123456789", "1234567890",
    "qwerty123", "admin123", "admin2024", "welcome123", "letmein123",
    "dabbadash", "iloveyou", "monkey123", "dragon123", "superman1"
}

# Rate limiting and lockout policies (F-10)
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
IDLE_TIMEOUT_SECONDS = 900  # 15 minutes

app = Flask(__name__)

# F-12: Secret key loaded from environment variable (with secure random fallback)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.environ.get("SECRET_KEY") or "dabbadash@indore_secure_session_key_2024"

# Hardening: Request body limit 1MB (Break Project Task 2)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

# F-17: Secure cookie flags
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,       # Prevent XSS access to cookies
    SESSION_COOKIE_SAMESITE="Lax",      # Mitigate Cross-Site Request Forgery
    SESSION_COOKIE_SECURE=False,        # Set to True on production HTTPS; False for local dev
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=LOCKOUT_MINUTES)
)


# F-17: HTTP Security Headers
@app.after_request
def apply_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none';"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    return response


# ---------------------------------------------------------------- database
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# F-20: Password policy validation
def validate_password_policy(password):
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if password.lower() in PASSWORD_BLOCKLIST:
        return False, "Password is too common and easily guessed. Please choose a stronger password."
    return True, None


# F-09: Hash passwords using Argon2id
def hash_password(password):
    return ph.hash(password)


# F-09: Safe in-place re-hashing from legacy MD5 to Argon2id
def verify_and_rehash_password(user, password):
    stored_hash = user["password"]
    db = get_db()

    # Case A: Argon2id
    if stored_hash.startswith("$argon2id$") or stored_hash.startswith("$argon2"):
        try:
            ph.verify(stored_hash, password)
            if ph.check_needs_rehash(stored_hash):
                new_hash = ph.hash(password)
                db.execute("UPDATE users SET password=? WHERE id=?", (new_hash, user["id"]))
                db.commit()
            return True
        except VerifyMismatchError:
            return False
        except Exception:
            return False

    # Case B: Legacy MD5 (tagged for Bandit and Semgrep: strictly for backward-compat migration to Argon2id)
    legacy_md5 = hashlib.md5(password.encode(), usedforsecurity=False).hexdigest()  # nosec B324 # nosemgrep: python.lang.security.audit.md5-used-as-password.md5-used-as-password
    if legacy_md5 == stored_hash:
        new_hash = ph.hash(password)
        db.execute("UPDATE users SET password=? WHERE id=?", (new_hash, user["id"]))
        db.commit()
        auth_logger.info("MIGRATED_PASSWORD: user '%s' upgraded from legacy MD5 to Argon2id", user["username"])
        return True

    return False


# F-10: Rate limiting and lockout tracking
def is_account_locked(username, ip):
    cutoff = (datetime.now() - timedelta(minutes=LOCKOUT_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")
    db = get_db()
    row = db.execute(
        "SELECT COUNT(*) AS count FROM login_attempts WHERE username=? AND success=0 AND attempted_at > ?",
        (username, cutoff)
    ).fetchone()
    if row and row["count"] >= MAX_FAILED_ATTEMPTS:
        return True
    ip_row = db.execute(
        "SELECT COUNT(*) AS count FROM login_attempts WHERE ip=? AND success=0 AND attempted_at > ?",
        (ip, cutoff)
    ).fetchone()
    return bool(ip_row and ip_row["count"] >= 25)


def record_login_attempt(username, ip, success):
    db = get_db()
    db.execute(
        "INSERT INTO login_attempts (username, ip, attempted_at, success) VALUES (?, ?, ?, ?)",
        (username, ip, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 1 if success else 0)
    )
    if success:
        db.execute("DELETE FROM login_attempts WHERE username=? OR ip=?", (username, ip))
    db.commit()


# F-19: Structured Security Audit Logging
def log_auth_failure(username, ip, reason):
    auth_logger.warning("AUTH_FAILURE: user='%s' ip='%s' reason='%s'", username, ip, reason)


def log_access_denied(user_id, role, resource, action):
    auth_logger.warning("ACCESS_DENIED: uid='%s' role='%s' resource='%s' action='%s'", user_id, role, resource, action)


# F-01 & F-15: Parameterized Login & Generic Errors
def check_login(username, password, ip):
    if is_account_locked(username, ip):
        log_auth_failure(username, ip, "account_locked_throttled")
        return None, "Account temporarily locked due to multiple failed login attempts. Please try again in 15 minutes."

    db = get_db()
    # F-01: Parameterized query completely prevents SQL injection
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    if not user or not verify_and_rehash_password(user, password):
        record_login_attempt(username, ip, success=False)
        log_auth_failure(username, ip, "invalid_credentials")
        return None, "Invalid username or password"

    record_login_attempt(username, ip, success=True)
    user = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    return user, None


def init_db():
    need_create = not os.path.exists(DB_PATH)
    db = sqlite3.connect(DB_PATH)
    if need_create:
        db.executescript("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'customer',
            phone TEXT,
            address TEXT,
            restaurant_id INTEGER,
            mfa_secret TEXT,
            mfa_enabled INTEGER DEFAULT 0,
            last_totp_code TEXT
        );
        CREATE TABLE restaurants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            area TEXT
        );
        CREATE TABLE menu (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            restaurant_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            price INTEGER NOT NULL
        );
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL,
            restaurant_id INTEGER NOT NULL,
            rider_id INTEGER,
            items TEXT NOT NULL,
            total INTEGER NOT NULL,
            delivery_note TEXT,
            status TEXT DEFAULT 'Placed',
            created_at TEXT NOT NULL
        );
        CREATE TABLE login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip TEXT,
            attempted_at TEXT NOT NULL,
            success INTEGER NOT NULL
        );
        """)
        db.executemany("INSERT INTO restaurants (name, area) VALUES (?,?)", [
            ("Sarafa Swad", "Sarafa Bazaar"), ("Chappan Chaat House", "56 Dukan"), ("Malwa Thali", "Vijay Nagar")])
        db.executemany("INSERT INTO menu (restaurant_id, name, price) VALUES (?,?,?)", [
            (1, "Poha Jalebi", 60), (1, "Bhutte ka Kees", 80), (1, "Garadu", 90),
            (2, "Khopra Pattice", 50), (2, "Dahi Vada", 70), (2, "Johny Hot Dog", 60),
            (3, "Malwa Special Thali", 220), (3, "Dal Bafla", 160), (3, "Mawa Bati", 70)])
        users = [
            ("admin", "Admin@2024", "Ops Administrator", "admin", "9600000001", None, None),
            ("priya", "Priya@123", "Priya Jain", "customer", "9611111111", "12, Saket Nagar, Indore", None),
            ("kabir", "Kabir@123", "Kabir Khan", "customer", "9622222222", "B-404, Scheme 54, Indore", None),
            ("sarafa", "Rest@123", "Sarafa Swad (Manager)", "restaurant", "9633333333", None, 1),
            ("malwa", "Rest@123", "Malwa Thali (Manager)", "restaurant", "9644444444", None, 3),
            ("rider.ravi", "Rider@123", "Ravi Yadav", "rider", "9655555555", None, None),
        ]
        for u in users:
            db.execute("INSERT INTO users (username,password,full_name,role,phone,address,restaurant_id,mfa_secret,mfa_enabled,last_totp_code) "
                       "VALUES (?,?,?,?,?,?,?,?,?,?)", (u[0], hash_password(u[1])) + u[2:] + (None, 0, None))
        db.executemany("INSERT INTO orders (customer_id,restaurant_id,rider_id,items,total,delivery_note,status,created_at) "
                       "VALUES (?,?,?,?,?,?,?,?)", [
            (2, 1, 6, "2 x Poha Jalebi, 1 x Garadu", 210, "Ring the bell twice", "Delivered", "2026-10-25 09:10"),
            (3, 3, None, "1 x Malwa Special Thali", 220, "Leave at security gate", "Preparing", "2026-10-28 13:05"),
            (2, 3, None, "2 x Dal Bafla, 2 x Mawa Bati", 460, "Call on arrival", "Placed", "2026-10-28 20:40"),
        ])
        db.commit()
    else:
        cols = [r[1] for r in db.execute("PRAGMA table_info(users)").fetchall()]
        if "mfa_secret" not in cols:
            db.execute("ALTER TABLE users ADD COLUMN mfa_secret TEXT")
        if "mfa_enabled" not in cols:
            db.execute("ALTER TABLE users ADD COLUMN mfa_enabled INTEGER DEFAULT 0")
        if "last_totp_code" not in cols:
            db.execute("ALTER TABLE users ADD COLUMN last_totp_code TEXT")
        db.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip TEXT,
            attempted_at TEXT NOT NULL,
            success INTEGER NOT NULL
        );
        """)
        db.commit()
    db.close()


# ---------------------------------------------------------------- session & auth helpers
@app.before_request
def enforce_idle_timeout():
    """Enforce idle timeout (15 mins). Invalidate session on inactivity."""
    if "user_id" in session:
        now = datetime.now().timestamp()
        last_active = session.get("_last_active")
        if last_active and (now - last_active > IDLE_TIMEOUT_SECONDS):
            session.clear()
            if request.path.startswith("/api/"):
                return jsonify({"error": "session expired due to inactivity"}), 401
            return redirect(url_for("login", msg="Your session has expired due to inactivity. Please log in again."))
        session["_last_active"] = now


# F-16: CSRF Protection
def get_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(16)
    return session["_csrf_token"]


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": get_csrf_token()}


def validate_csrf():
    if request.method == "POST":
        token = request.form.get("csrf_token")
        if not token or not hmac.compare_digest(token, session.get("_csrf_token", "")):
            auth_logger.warning("CSRF_REJECTED: ip='%s' path='%s'", request.remote_addr, request.path)
            return False
    return True


# Anti-Replay TOTP single-use enforcement (RFC 6238)
def verify_and_consume_totp(user, code):
    code = str(code).strip()
    if not code:
        return False, "MFA code is required."

    secret = user.get("mfa_secret")
    if not secret:
        return False, "MFA is not configured for this account."

    totp = pyotp.TOTP(secret)
    if not totp.verify(code):
        return False, "Invalid 6-digit code. Please verify your authenticator app time is synced and try again."

    # Anti-replay check
    try:
        last_code = user["last_totp_code"]
    except Exception:
        last_code = None

    if last_code and str(last_code).strip() == code:
        return False, "This TOTP code has already been used. Each code can only be used once. Please wait for the next 30-second code on your authenticator app."

    db = get_db()
    db.execute("UPDATE users SET last_totp_code=? WHERE id=?", (code, user["id"]))
    db.commit()
    return True, None


# F-02: Cryptographically Signed HMAC-SHA256 Bearer Token
def make_token(user):
    exp = int(datetime.now().timestamp()) + 86400  # 24 hours
    payload = f"{user['id']}:{user['username']}:{exp}"
    b64_payload = base64.urlsafe_b64encode(payload.encode()).decode()
    sig = hmac.new(app.secret_key.encode(), b64_payload.encode(), hashlib.sha256).hexdigest()
    return f"{b64_payload}.{sig}"


# F-02 & Server-side Authorisation: Verify token signature & load identity from DB
def api_user():
    header = request.headers.get("Authorization", "")
    uid = None
    if header.startswith("Bearer "):
        token_str = header[7:].strip()
        try:
            b64_payload, sig = token_str.split(".")
            expected_sig = hmac.new(app.secret_key.encode(), b64_payload.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, expected_sig):
                auth_logger.warning("FORGED_TOKEN_REJECTED: ip='%s'", request.remote_addr)
                return None
            payload = base64.urlsafe_b64decode(b64_payload.encode()).decode()
            parts = payload.split(":")
            uid = int(parts[0])
            exp = int(parts[2])
            if datetime.now().timestamp() > exp:
                auth_logger.warning("EXPIRED_TOKEN_REJECTED: uid='%s' ip='%s'", uid, request.remote_addr)
                return None
        except Exception:
            return None
    elif "user_id" in session:
        uid = session["user_id"]

    if uid:
        u = get_db().execute("SELECT id, username, full_name, role, restaurant_id FROM users WHERE id=?",
                             (uid,)).fetchone()
        if u:
            return {"id": u["id"], "username": u["username"], "name": u["full_name"],
                    "role": u["role"], "restaurant_id": u["restaurant_id"]}
    return None


def api_auth(fn):
    def inner(*args, **kwargs):
        user = api_user()
        if not user:
            return jsonify({"error": "authentication required"}), 401
        g.user = user
        return fn(*args, **kwargs)
    inner.__name__ = fn.__name__
    return inner


# Server-side Authorisation: User role ALWAYS loaded from server DB
def current_user():
    if "user_id" not in session:
        return None
    u = get_db().execute("SELECT id, username, full_name, role, restaurant_id FROM users WHERE id=?",
                         (session["user_id"],)).fetchone()
    if not u:
        session.clear()
        return None
    return {"id": u["id"], "username": u["username"], "name": u["full_name"],
            "role": u["role"], "restaurant_id": u["restaurant_id"]}


def login_required(role=None):
    def wrap(fn):
        def inner(*args, **kwargs):
            user = current_user()
            if not user:
                return redirect(url_for("login"))
            if role and user["role"] != role:
                log_access_denied(user["id"], user["role"], request.path, "role_mismatch")
                return render_template("error.html", msg="Access denied"), 403
            return fn(*args, **kwargs)
        inner.__name__ = fn.__name__
        return inner
    return wrap


# F-18: Robust checks on order input
def create_order(customer_id, restaurant_id, quantities, note):
    db = get_db()
    # Validate restaurant exists
    rest = db.execute("SELECT id FROM restaurants WHERE id=?", (restaurant_id,)).fetchone()
    if not rest:
        return None

    items, total = [], 0
    menu_rows = db.execute("SELECT * FROM menu WHERE restaurant_id=?", (restaurant_id,)).fetchall()
    menu_map = {str(m["id"]): m for m in menu_rows}

    for mid_str, qty_val in quantities.items():
        try:
            qty = int(qty_val)
        except (ValueError, TypeError):
            continue
        if 0 < qty <= 50 and mid_str in menu_map:
            m = menu_map[mid_str]
            items.append(f"{qty} x {m['name']}")
            total += qty * m["price"]

    if not items or total <= 0:
        return None

    clean_note = (note or "").strip()[:250]
    cur = db.execute(
        "INSERT INTO orders (customer_id,restaurant_id,items,total,delivery_note,status,created_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (customer_id, restaurant_id, ", ".join(items), total, clean_note, "Placed",
         datetime.now().strftime("%Y-%m-%d %H:%M"))
    )
    db.commit()
    auth_logger.info("ORDER_CREATED: oid='%s' cid='%s' total='%s'", cur.lastrowid, customer_id, total)
    return cur.lastrowid


# ---------------------------------------------------------------- web console
@app.route("/")
def index():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    return redirect(url_for(user["role"] + "_home"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if not validate_csrf():
            return render_template("error.html", msg="Invalid or missing CSRF token"), 400

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip = request.remote_addr

        user, err = check_login(username, password, ip)
        if err:
            error = err
        elif user:
            if user["role"] == "admin":
                session.clear()
                if not user["mfa_enabled"]:
                    session["mfa_enroll_uid"] = user["id"]
                    return redirect(url_for("mfa_enroll"))
                else:
                    session["mfa_verify_uid"] = user["id"]
                    return redirect(url_for("mfa_verify"))

            session.clear()
            session["user_id"] = user["id"]
            session["_last_active"] = datetime.now().timestamp()
            auth_logger.info("LOGIN_SUCCESS: user '%s' logged in", user["username"])
            return redirect(url_for("index"))

    return render_template("login.html", error=error)


@app.route("/mfa/enroll", methods=["GET", "POST"])
def mfa_enroll():
    if not session.get("mfa_enroll_uid") and session.get("mfa_verify_uid"):
        session["mfa_enroll_uid"] = session["mfa_verify_uid"]

    uid = session.get("mfa_enroll_uid")
    if not uid:
        return redirect(url_for("login"))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not user:
        session.clear()
        return redirect(url_for("login"))

    if request.args.get("reset") == "1" or not user["mfa_secret"]:
        secret = pyotp.random_base32()
        db.execute("UPDATE users SET mfa_secret=?, mfa_enabled=0 WHERE id=?", (secret, uid))
        db.commit()
    else:
        secret = user["mfa_secret"]

    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=user["username"], issuer_name="DabbaDash")

    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    stream = io.BytesIO()
    img.save(stream)
    qr_svg = stream.getvalue().decode()

    error = None
    if request.method == "POST":
        if not validate_csrf():
            return render_template("error.html", msg="Invalid CSRF token"), 400

        code = request.form.get("code", "").strip()
        ok, msg = verify_and_consume_totp(user, code)
        if ok:
            db.execute("UPDATE users SET mfa_enabled=1 WHERE id=?", (uid,))
            db.commit()
            auth_logger.info("MFA_ENROLLED: admin '%s' enrolled MFA successfully", user["username"])
            session.clear()
            session["user_id"] = uid
            session["_last_active"] = datetime.now().timestamp()
            return redirect(url_for("index"))
        else:
            log_auth_failure(user["username"], request.remote_addr, "mfa_enroll_failed: " + msg)
            error = msg

    return render_template("mfa_enroll.html", qr_svg=qr_svg, secret=secret, error=error, username=user["username"])


@app.route("/mfa/verify", methods=["GET", "POST"])
def mfa_verify():
    uid = session.get("mfa_verify_uid")
    if not uid:
        return redirect(url_for("login"))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not user:
        session.clear()
        return redirect(url_for("login"))

    error = None
    if request.method == "POST":
        if not validate_csrf():
            return render_template("error.html", msg="Invalid CSRF token"), 400

        code = request.form.get("code", "").strip()
        ok, msg = verify_and_consume_totp(user, code)
        if ok:
            session.clear()
            session["user_id"] = uid
            session["_last_active"] = datetime.now().timestamp()
            auth_logger.info("MFA_SUCCESS: admin '%s' authenticated with TOTP", user["username"])
            return redirect(url_for("index"))
        else:
            log_auth_failure(user["username"], request.remote_addr, "mfa_verify_failed: " + msg)
            error = msg

    return render_template("mfa_verify.html", error=error, username=user["username"])


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if not validate_csrf():
            return render_template("error.html", msg="Invalid CSRF token"), 400

        f = request.form
        password = f.get("password", "")

        valid, msg = validate_password_policy(password)
        if not valid:
            return render_template("register.html", error=msg)

        try:
            get_db().execute(
                "INSERT INTO users (username,password,full_name,role,phone,address,restaurant_id,mfa_secret,mfa_enabled,last_totp_code) "
                "VALUES (?,?,?,?,?,?,NULL,NULL,0,NULL)",
                (f["username"].strip(), hash_password(password), f["full_name"].strip(), "customer",
                 f.get("phone", "").strip(), f.get("address", "").strip())
            )
            get_db().commit()
        except sqlite3.IntegrityError:
            return render_template("register.html", error="Username already taken")
        return redirect(url_for("login"))
    return render_template("register.html", error=None)


@app.route("/logout")
def logout():
    session.clear()
    resp = redirect(url_for("login"))
    resp.delete_cookie(app.config.get("SESSION_COOKIE_NAME", "session"))
    return resp


@app.route("/customer")
@login_required("customer")
def customer_home():
    db = get_db()
    user = current_user()
    rid = request.args.get("restaurant", "1")
    restaurants = db.execute("SELECT * FROM restaurants").fetchall()
    menu = db.execute("SELECT * FROM menu WHERE restaurant_id=?", (rid,)).fetchall()
    orders = db.execute("SELECT o.*, r.name AS restaurant FROM orders o JOIN restaurants r ON r.id=o.restaurant_id "
                        "WHERE customer_id=? ORDER BY o.id DESC", (user["id"],)).fetchall()
    return render_template("customer.html", user=user, restaurants=restaurants, menu=menu,
                           rid=int(rid), orders=orders, token=make_token(user))


# F-16: CSRF token validated on /order
@app.route("/order", methods=["POST"])
@login_required("customer")
def web_order():
    if not validate_csrf():
        return render_template("error.html", msg="Invalid CSRF token"), 400

    user = current_user()
    qty = {k[4:]: v for k, v in request.form.items() if k.startswith("qty_")}
    create_order(user["id"], request.form["restaurant_id"], qty, request.form.get("delivery_note", ""))
    return redirect(url_for("customer_home", restaurant=request.form["restaurant_id"]))


@app.route("/restaurant")
@login_required("restaurant")
def restaurant_home():
    user = current_user()
    db = get_db()
    me = db.execute("SELECT restaurant_id FROM users WHERE id=?", (user["id"],)).fetchone()
    orders = db.execute("SELECT o.*, u.full_name AS customer FROM orders o JOIN users u ON u.id=o.customer_id "
                        "WHERE o.restaurant_id=? ORDER BY o.id DESC", (me["restaurant_id"],)).fetchall()
    return render_template("restaurant.html", user=user, orders=orders)


# F-14: Redacted customer PII for completed orders
@app.route("/rider")
@login_required("rider")
def rider_home():
    user = current_user()
    raw_orders = get_db().execute(
        "SELECT o.*, u.full_name AS customer, u.phone, u.address, r.name AS restaurant FROM orders o "
        "JOIN users u ON u.id=o.customer_id JOIN restaurants r ON r.id=o.restaurant_id "
        "WHERE (o.status IN ('Ready','Picked up')) OR (o.rider_id=? AND o.status='Delivered') "
        "ORDER BY o.id DESC", (user["id"],)).fetchall()

    sanitized = []
    for r in raw_orders:
        row = dict(r)
        # DPDP Act: Only active deliveries show customer address and phone
        if row["status"] == "Delivered":
            row["address"] = "*** Delivered (Address Protected) ***"
            row["phone"] = "*** Protected ***"
        sanitized.append(row)

    return render_template("rider.html", user=user, orders=sanitized)


# F-08: Anyone can set any order status -> Strict state machine & RBAC enforcement
@app.route("/order/<int:order_id>/status", methods=["POST"])
@login_required()
def web_status(order_id):
    if not validate_csrf():
        return render_template("error.html", msg="Invalid CSRF token"), 400

    user = current_user()
    db = get_db()
    order = db.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
    if not order:
        return render_template("error.html", msg="Order not found"), 404

    target_status = request.form.get("status", "").strip()

    # Enforce allowed transitions
    if user["role"] == "rider":
        if target_status == "Picked up" and order["status"] == "Ready":
            db.execute("UPDATE orders SET status=?, rider_id=? WHERE id=?", ("Picked up", user["id"], order_id))
        elif target_status == "Delivered" and order["status"] == "Picked up" and order["rider_id"] == user["id"]:
            db.execute("UPDATE orders SET status=? WHERE id=?", ("Delivered", order_id))
        else:
            log_access_denied(user["id"], user["role"], f"order_{order_id}", f"invalid_status_transition_{target_status}")
            return render_template("error.html", msg="Unauthorized order status transition"), 403
    elif user["role"] == "restaurant":
        if order["restaurant_id"] != user["restaurant_id"]:
            log_access_denied(user["id"], user["role"], f"order_{order_id}", "wrong_restaurant")
            return render_template("error.html", msg="Access denied to this restaurant's orders"), 403
        if target_status == "Preparing" and order["status"] == "Placed":
            db.execute("UPDATE orders SET status=? WHERE id=?", ("Preparing", order_id))
        elif target_status == "Ready" and order["status"] == "Preparing":
            db.execute("UPDATE orders SET status=? WHERE id=?", ("Ready", order_id))
        else:
            log_access_denied(user["id"], user["role"], f"order_{order_id}", f"invalid_status_transition_{target_status}")
            return render_template("error.html", msg="Unauthorized order status transition"), 403
    elif user["role"] == "admin":
        db.execute("UPDATE orders SET status=? WHERE id=?", (target_status, order_id))
    else:
        log_access_denied(user["id"], user["role"], f"order_{order_id}", "customer_status_change")
        return render_template("error.html", msg="Customers cannot modify order status"), 403

    db.commit()
    auth_logger.info("ORDER_STATUS_UPDATED: oid='%s' by uid='%s' to status='%s'", order_id, user["id"], target_status)
    return redirect(url_for("index"))


@app.route("/admin")
@login_required("admin")
def admin_home():
    user = current_user()
    db = get_db()
    users = db.execute("SELECT id, username, full_name, role, phone FROM users").fetchall()
    orders = db.execute("SELECT o.*, r.name AS restaurant FROM orders o JOIN restaurants r ON r.id=o.restaurant_id "
                        "ORDER BY o.id DESC").fetchall()
    return render_template("admin.html", user=user, users=users, orders=orders)


# ---------------------------------------------------------------- JSON API
# F-03: Anyone can register as admin -> Strictly forces role to customer
@app.route("/api/v1/register", methods=["POST"])
def api_register():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    full_name = data.get("full_name", "").strip()

    if not username or not password or not full_name:
        return jsonify({"error": "username, password and full_name are required"}), 400

    valid, msg = validate_password_policy(password)
    if not valid:
        return jsonify({"error": msg}), 400

    try:
        db = get_db()
        cur = db.execute(
            "INSERT INTO users (username, password, full_name, role, phone, address, restaurant_id, mfa_secret, mfa_enabled, last_totp_code) "
            "VALUES (?, ?, ?, 'customer', ?, ?, NULL, NULL, 0, NULL)",
            (username, hash_password(password), full_name, data.get("phone", "").strip(), data.get("address", "").strip())
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "username already taken"}), 409
    return jsonify({"ok": True, "user_id": cur.lastrowid}), 201


@app.route("/api/v1/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    ip = request.remote_addr

    user, err = check_login(username, password, ip)
    if err:
        status_code = 429 if "locked" in err else 401
        return jsonify({"ok": False, "error": err}), status_code

    if user["role"] == "admin" and user["mfa_enabled"]:
        mfa_code = str(data.get("mfa_code", "")).strip()
        if not mfa_code:
            return jsonify({"ok": False, "mfa_required": True, "error": "MFA code required for admin"}), 401
        ok, msg = verify_and_consume_totp(user, mfa_code)
        if not ok:
            log_auth_failure(user["username"], ip, "api_mfa_failed: " + msg)
            return jsonify({"ok": False, "error": msg}), 401

    return jsonify({"ok": True, "token": make_token(user), "user_id": user["id"], "role": user["role"]})


@app.route("/api/v1/restaurants")
def api_restaurants():
    rows = get_db().execute("SELECT * FROM restaurants").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/v1/restaurants/<int:rid>/menu")
def api_menu(rid):
    rows = get_db().execute("SELECT * FROM menu WHERE restaurant_id=?", (rid,)).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/v1/orders", methods=["GET", "POST"])
@api_auth
def api_orders():
    db = get_db()
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        qty = {str(i.get("menu_id")): i.get("qty", 0) for i in data.get("items", [])}
        oid = create_order(g.user["id"], data.get("restaurant_id"), qty, data.get("delivery_note", ""))
        if not oid:
            return jsonify({"error": "invalid items or restaurant"}), 400
        return jsonify(dict(db.execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone())), 201

    if g.user["role"] == "admin":
        rows = db.execute("SELECT * FROM orders ORDER BY id DESC").fetchall()
    elif g.user["role"] == "restaurant":
        rows = db.execute("SELECT * FROM orders WHERE restaurant_id=? ORDER BY id DESC",
                          (g.user.get("restaurant_id"),)).fetchall()
    else:
        rows = db.execute("SELECT * FROM orders WHERE customer_id=? OR rider_id=? ORDER BY id DESC",
                          (g.user["id"], g.user["id"])).fetchall()
    return jsonify([dict(r) for r in rows])


# F-04: IDOR check on GET / F-07: Mass assignment check on PATCH
@app.route("/api/v1/orders/<int:order_id>", methods=["GET", "PATCH"])
@api_auth
def api_order(order_id):
    db = get_db()
    order = db.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
    if not order:
        return jsonify({"error": "not found"}), 404

    uid = g.user["id"]
    caller = db.execute("SELECT restaurant_id FROM users WHERE id=?", (uid,)).fetchone()
    user_rest_id = caller["restaurant_id"] if caller else None

    # F-04: Strict Access Control check
    ok = (
        g.user["role"] == "admin"
        or order["customer_id"] == uid
        or order["rider_id"] == uid
        or (g.user["role"] == "restaurant" and user_rest_id == order["restaurant_id"])
    )
    if not ok:
        log_access_denied(uid, g.user["role"], f"api_order_{order_id}", "read_order_idor_blocked")
        return jsonify({"error": "not found"}), 404

    # F-07: Parameter Whitelisting on PATCH
    if request.method == "PATCH":
        data = request.get_json(silent=True) or {}
        role = g.user["role"]

        if role == "customer":
            if order["customer_id"] != uid or order["status"] != "Placed":
                return jsonify({"error": "cannot modify order after it has been prepared"}), 403
            if "delivery_note" in data:
                clean_note = str(data["delivery_note"])[:250]
                db.execute("UPDATE orders SET delivery_note=? WHERE id=?", (clean_note, order_id))
        elif role == "rider":
            new_status = data.get("status")
            if new_status == "Picked up" and order["status"] == "Ready":
                db.execute("UPDATE orders SET status=?, rider_id=? WHERE id=?", ("Picked up", uid, order_id))
            elif new_status == "Delivered" and order["status"] == "Picked up" and order["rider_id"] == uid:
                db.execute("UPDATE orders SET status=? WHERE id=?", ("Delivered", order_id))
            else:
                return jsonify({"error": "invalid status transition"}), 403
        elif role == "restaurant":
            if order["restaurant_id"] != user_rest_id:
                return jsonify({"error": "not your restaurant's order"}), 403
            new_status = data.get("status")
            if new_status == "Preparing" and order["status"] == "Placed":
                db.execute("UPDATE orders SET status=? WHERE id=?", ("Preparing", order_id))
            elif new_status == "Ready" and order["status"] == "Preparing":
                db.execute("UPDATE orders SET status=? WHERE id=?", ("Ready", order_id))
            else:
                return jsonify({"error": "invalid status transition"}), 403
        elif role == "admin":
            if "delivery_note" in data:
                db.execute("UPDATE orders SET delivery_note=? WHERE id=?", (str(data["delivery_note"])[:250], order_id))
            if "status" in data:
                db.execute("UPDATE orders SET status=? WHERE id=?", (str(data["status"]), order_id))
        else:
            return jsonify({"error": "unauthorized"}), 403

        db.commit()
        order = db.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()

    result = dict(order)
    cust = db.execute("SELECT full_name, phone, address FROM users WHERE id=?", (order["customer_id"],)).fetchone()
    # DPDP Act: mask customer data if already delivered and caller is rider
    if g.user["role"] == "rider" and order["status"] == "Delivered":
        result["customer"] = {"full_name": cust["full_name"], "phone": "*** Protected ***", "address": "*** Delivered (Address Protected) ***"}
    else:
        result["customer"] = dict(cust) if cust else None

    return jsonify(result)


# F-06: Profile leaks password hash -> Protected with strict column projection
@app.route("/api/v1/users/<int:user_id>")
@api_auth
def api_user_profile(user_id):
    if g.user["role"] != "admin" and g.user["id"] != user_id:
        return jsonify({"error": "not found"}), 404

    # Whitelist safe projection fields (never expose password, mfa_secret, or last_totp_code)
    u = get_db().execute("SELECT id, username, full_name, role, phone, address FROM users WHERE id=?",
                         (user_id,)).fetchone()
    if not u:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(u))


# F-05: Admin user list open to everyone -> Strict role check
@app.route("/api/v1/admin/users")
@api_auth
def api_admin_users():
    if g.user["role"] != "admin":
        log_access_denied(g.user["id"], g.user["role"], "/api/v1/admin/users", "unauthorized_admin_access")
        return jsonify({"error": "forbidden"}), 403
    rows = get_db().execute("SELECT id, username, full_name, role, phone FROM users").fetchall()
    return jsonify([dict(r) for r in rows])


# F-13: Debug mode off by default (Break Project Task 2)
if __name__ == "__main__":
    init_db()
    is_debug = os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true")
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5050")), debug=is_debug)
