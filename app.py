"""
DabbaDash - Food Delivery Order Platform (v1.0 - Hardened Auth & Sessions)
--------------------------------------------------------------------------
TRAINING APPLICATION - ITM Secure Application Development course.
Day 4: Fixed Authentication & Sessions, Added MFA.
"""
import base64
import hashlib
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

# Setup structured logging for authentication events
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [AUTH] %(message)s")
auth_logger = logging.getLogger("auth")

# Password Hasher using Argon2id
ph = PasswordHasher()

# Common password blocklist (min length + dictionary/breached check)
PASSWORD_BLOCKLIST = {
    "password", "password123", "12345678", "123456789", "1234567890",
    "qwerty123", "admin123", "admin2024", "welcome123", "letmein123",
    "dabbadash", "iloveyou", "monkey123", "dragon123", "superman1"
}

# Lockout policy: 5 failed attempts locks the account/IP for 15 minutes
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
IDLE_TIMEOUT_SECONDS = 900  # 15 minutes

app = Flask(__name__)

# Task 3: Secret key loaded from environment variable (with fallback)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.environ.get("SECRET_KEY") or "dabbadash@indore_secure_session_key_2024"

# Task 3: Secure cookie flags and session configuration
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,       # Mitigate XSS cookie theft
    SESSION_COOKIE_SAMESITE="Lax",      # Mitigate CSRF
    SESSION_COOKIE_SECURE=False,        # Set to True on HTTPS in production; False for local http://127.0.0.1
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=LOCKOUT_MINUTES)
)

USER_COLUMNS = ["username", "password", "full_name", "role", "phone", "address", "restaurant_id"]
ORDER_COLUMNS = ["customer_id", "restaurant_id", "rider_id", "items", "total", "delivery_note", "status"]


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


def validate_password_policy(password):
    """Task 1: Enforce minimum length and check against password blocklist."""
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if password.lower() in PASSWORD_BLOCKLIST:
        return False, "Password is too common and easily guessed. Please choose a stronger password."
    return True, None


def hash_password(password):
    """Task 1: Hash passwords using Argon2id."""
    return ph.hash(password)


def verify_and_rehash_password(user, password):
    """
    Task 1: Verifies password against stored hash.
    Safely re-hashes legacy MD5 passwords to Argon2id on next successful login.
    """
    stored_hash = user["password"]
    db = get_db()

    # Case A: Already Argon2id
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

    # Case B: Legacy MD5 - check and re-hash safely
    legacy_md5 = hashlib.md5(password.encode()).hexdigest()
    if legacy_md5 == stored_hash:
        new_hash = ph.hash(password)
        db.execute("UPDATE users SET password=? WHERE id=?", (new_hash, user["id"]))
        db.commit()
        auth_logger.info("MIGRATED_PASSWORD: user '%s' upgraded from legacy MD5 to Argon2id", user["username"])
        return True

    return False


# Task 2: Login throttling, lockout, and failure logging
def is_account_locked(username, ip):
    cutoff = (datetime.now() - timedelta(minutes=LOCKOUT_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")
    db = get_db()
    # Lockout after repeated failures for the specific account
    row = db.execute(
        "SELECT COUNT(*) AS count FROM login_attempts WHERE username=? AND success=0 AND attempted_at > ?",
        (username, cutoff)
    ).fetchone()
    if row and row["count"] >= MAX_FAILED_ATTEMPTS:
        return True
    # IP-level throttling against distributed brute force
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
        # Clear recent failed attempts upon successful login
        db.execute("DELETE FROM login_attempts WHERE username=? OR ip=?", (username, ip))
    db.commit()


def log_auth_failure(username, ip, reason):
    auth_logger.warning("FAILED_LOGIN: username='%s' ip='%s' reason='%s'", username, ip, reason)


def check_login(username, password, ip):
    """
    Shared authentication helper:
    1. Checks lockout.
    2. Uses parameterized SQL queries (prevents SQLi).
    3. Verifies & re-hashes password via Argon2id.
    4. Logs failures and manages attempt counters.
    """
    if is_account_locked(username, ip):
        log_auth_failure(username, ip, "account_locked_throttled")
        return None, "Account temporarily locked due to multiple failed login attempts. Please try again in 15 minutes."

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    if not user or not verify_and_rehash_password(user, password):
        record_login_attempt(username, ip, success=False)
        log_auth_failure(username, ip, "invalid_credentials")
        return None, "Invalid username or password"

    record_login_attempt(username, ip, success=True)
    # Refetch user to get any updated fields
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
            role TEXT NOT NULL DEFAULT 'customer',   -- customer | restaurant | rider | admin
            phone TEXT,
            address TEXT,
            restaurant_id INTEGER,                   -- set for restaurant staff
            mfa_secret TEXT,                         -- Task 5: TOTP MFA secret key
            mfa_enabled INTEGER DEFAULT 0            -- Task 5: TOTP MFA active flag
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
            status TEXT DEFAULT 'Placed',   -- Placed | Preparing | Ready | Picked up | Delivered
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
            # Seed with Argon2id hash directly
            db.execute("INSERT INTO users (username,password,full_name,role,phone,address,restaurant_id,mfa_secret,mfa_enabled) "
                       "VALUES (?,?,?,?,?,?,?,?,?)", (u[0], hash_password(u[1])) + u[2:] + (None, 0))
        db.executemany("INSERT INTO orders (customer_id,restaurant_id,rider_id,items,total,delivery_note,status,created_at) "
                       "VALUES (?,?,?,?,?,?,?,?)", [
            (2, 1, 6, "2 x Poha Jalebi, 1 x Garadu", 210, "Ring the bell twice", "Delivered", "2026-10-25 09:10"),
            (3, 3, None, "1 x Malwa Special Thali", 220, "Leave at security gate", "Preparing", "2026-10-28 13:05"),
            (2, 3, None, "2 x Dal Bafla, 2 x Mawa Bati", 460, "Call on arrival", "Placed", "2026-10-28 20:40"),
        ])
        db.commit()
    else:
        # Schema migration for existing database: ensure MFA columns & login_attempts table exist
        cols = [r[1] for r in db.execute("PRAGMA table_info(users)").fetchall()]
        if "mfa_secret" not in cols:
            db.execute("ALTER TABLE users ADD COLUMN mfa_secret TEXT")
        if "mfa_enabled" not in cols:
            db.execute("ALTER TABLE users ADD COLUMN mfa_enabled INTEGER DEFAULT 0")
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
    """Task 3: Enforce idle timeout (15 mins). Invalidate session on inactivity."""
    if "user_id" in session:
        now = datetime.now().timestamp()
        last_active = session.get("_last_active")
        if last_active and (now - last_active > IDLE_TIMEOUT_SECONDS):
            session.clear()
            if request.path.startswith("/api/"):
                return jsonify({"error": "session expired due to inactivity"}), 401
            return redirect(url_for("login", msg="Your session has expired due to inactivity. Please log in again."))
        session["_last_active"] = now


def make_token(user):
    raw = "%s:%s" % (user["id"], user["username"])
    return base64.b64encode(raw.encode()).decode()


def api_user():
    """
    Task 4: Authorisation data (role, user) loaded from the server database,
    NEVER trusted from client cookies or client-supplied tokens.
    """
    uid = None
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        try:
            parts = base64.b64decode(header[7:]).decode().split(":")
            uid = int(parts[0])
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


def current_user():
    """
    Task 4: User profile and role ALWAYS loaded from the server DB,
    never trusted from the cookie.
    """
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
    """Enforces access control using server-validated role from database."""
    def wrap(fn):
        def inner(*args, **kwargs):
            user = current_user()
            if not user:
                return redirect(url_for("login"))
            if role and user["role"] != role:
                return render_template("error.html", msg="Access denied"), 403
            return fn(*args, **kwargs)
        inner.__name__ = fn.__name__
        return inner
    return wrap


def create_order(customer_id, restaurant_id, quantities, note):
    db = get_db()
    items, total = [], 0
    for m in db.execute("SELECT * FROM menu WHERE restaurant_id=?", (restaurant_id,)).fetchall():
        qty = int(quantities.get(str(m["id"]), 0) or 0)
        if qty > 0:
            items.append("%d x %s" % (qty, m["name"]))
            total += qty * m["price"]
    if not items:
        return None
    cur = db.execute("INSERT INTO orders (customer_id,restaurant_id,items,total,delivery_note,created_at) "
                     "VALUES (?,?,?,?,?,?)", (customer_id, restaurant_id, ", ".join(items), total, note,
                                              datetime.now().strftime("%Y-%m-%d %H:%M")))
    db.commit()
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
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip = request.remote_addr

        user, err = check_login(username, password, ip)
        if err:
            error = err
        elif user:
            # Task 5: For admin role, enforce TOTP MFA with pyotp
            if user["role"] == "admin":
                session.clear()  # Task 3: Prevent session fixation
                if not user["mfa_enabled"]:
                    # Needs QR enrolment
                    session["mfa_enroll_uid"] = user["id"]
                    return redirect(url_for("mfa_enroll"))
                else:
                    # Needs TOTP verification
                    session["mfa_verify_uid"] = user["id"]
                    return redirect(url_for("mfa_verify"))

            # Standard user login: start clean session
            session.clear()  # Task 3: New session at login
            session["user_id"] = user["id"]
            session["_last_active"] = datetime.now().timestamp()
            auth_logger.info("LOGIN_SUCCESS: user '%s' logged in", user["username"])
            return redirect(url_for("index"))

    return render_template("login.html", error=error)


# Task 5: MFA QR Enrolment
@app.route("/mfa/enroll", methods=["GET", "POST"])
def mfa_enroll():
    # Allow switching to enroll from verify (e.g. if user needs to re-scan)
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

    # If reset requested or no secret exists, generate a fresh secret
    if request.args.get("reset") == "1" or not user["mfa_secret"]:
        secret = pyotp.random_base32()
        db.execute("UPDATE users SET mfa_secret=?, mfa_enabled=0 WHERE id=?", (secret, uid))
        db.commit()
    else:
        secret = user["mfa_secret"]

    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=user["username"], issuer_name="DabbaDash")

    # Generate QR Code as SVG
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    stream = io.BytesIO()
    img.save(stream)
    qr_svg = stream.getvalue().decode()

    error = None
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        if totp.verify(code):
            db.execute("UPDATE users SET mfa_enabled=1 WHERE id=?", (uid,))
            db.commit()
            auth_logger.info("MFA_ENROLLED: admin '%s' enrolled MFA successfully", user["username"])
            session.clear()
            session["user_id"] = uid
            session["_last_active"] = datetime.now().timestamp()
            return redirect(url_for("index"))
        else:
            log_auth_failure(user["username"], request.remote_addr, "invalid_mfa_code_during_enroll")
            error = "Invalid 6-digit code. Please verify your authenticator app time is synced and try again."

    return render_template("mfa_enroll.html", qr_svg=qr_svg, secret=secret, error=error, username=user["username"])


# Task 5: MFA TOTP Verification
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
        code = request.form.get("code", "").strip()
        totp = pyotp.TOTP(user["mfa_secret"])
        if totp.verify(code):
            session.clear()
            session["user_id"] = uid
            session["_last_active"] = datetime.now().timestamp()
            auth_logger.info("MFA_SUCCESS: admin '%s' authenticated with TOTP", user["username"])
            return redirect(url_for("index"))
        else:
            log_auth_failure(user["username"], request.remote_addr, "invalid_mfa_code")
            error = "Invalid 6-digit code. Please try again."

    return render_template("mfa_verify.html", error=error, username=user["username"])


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        f = request.form
        password = f.get("password", "")

        # Task 1: Length and blocklist check
        valid, msg = validate_password_policy(password)
        if not valid:
            return render_template("register.html", error=msg)

        try:
            get_db().execute(
                "INSERT INTO users (username,password,full_name,role,phone,address) VALUES (?,?,?,?,?,?)",
                (f["username"].strip(), hash_password(password), f["full_name"].strip(), "customer",
                 f.get("phone"), f.get("address"))
            )
            get_db().commit()
        except sqlite3.IntegrityError:
            return render_template("register.html", error="Username already taken")
        return redirect(url_for("login"))
    return render_template("register.html", error=None)


@app.route("/logout")
def logout():
    """Task 3: Proper logout - clear session and explicitly delete session cookie."""
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


@app.route("/order", methods=["POST"])
@login_required("customer")
def web_order():
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


@app.route("/rider")
@login_required("rider")
def rider_home():
    user = current_user()
    orders = get_db().execute(
        "SELECT o.*, u.full_name AS customer, u.phone, u.address, r.name AS restaurant FROM orders o "
        "JOIN users u ON u.id=o.customer_id JOIN restaurants r ON r.id=o.restaurant_id "
        "WHERE o.status IN ('Ready','Picked up') OR o.rider_id=? ORDER BY o.id DESC", (user["id"],)).fetchall()
    return render_template("rider.html", user=user, orders=orders)


@app.route("/order/<int:order_id>/status", methods=["POST"])
@login_required()
def web_status(order_id):
    user = current_user()
    db = get_db()
    if user["role"] == "rider":
        db.execute("UPDATE orders SET status=?, rider_id=? WHERE id=?",
                   (request.form["status"], user["id"], order_id))
    else:
        db.execute("UPDATE orders SET status=? WHERE id=?", (request.form["status"], order_id))
    db.commit()
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
@app.route("/api/v1/register", methods=["POST"])
def api_register():
    data = request.get_json(silent=True) or {}
    if not data.get("username") or not data.get("password") or not data.get("full_name"):
        return jsonify({"error": "username, password and full_name are required"}), 400

    # Task 1: Length and blocklist check
    valid, msg = validate_password_policy(data.get("password", ""))
    if not valid:
        return jsonify({"error": msg}), 400

    data["password"] = hash_password(data["password"])
    # Default role to customer (prevent mass assignment of admin)
    if "role" not in data or data["role"] not in ["customer", "restaurant", "rider"]:
        data["role"] = "customer"

    fields = {k: v for k, v in data.items() if k in USER_COLUMNS}
    try:
        db = get_db()
        cur = db.execute("INSERT INTO users (%s) VALUES (%s)" % (",".join(fields), ",".join("?" * len(fields))),
                         list(fields.values()))
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "username already taken"}), 409
    return jsonify({"ok": True, "user_id": cur.lastrowid}), 201


@app.route("/api/v1/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    ip = request.remote_addr

    user, err = check_login(username, password, ip)
    if err:
        status_code = 429 if "locked" in err else 401
        return jsonify({"ok": False, "error": err}), status_code

    # Task 5: TOTP check for admin in API
    if user["role"] == "admin" and user["mfa_enabled"]:
        mfa_code = str(data.get("mfa_code", "")).strip()
        if not mfa_code:
            return jsonify({"ok": False, "mfa_required": True, "error": "MFA code required for admin"}), 401
        totp = pyotp.TOTP(user["mfa_secret"])
        if not totp.verify(mfa_code):
            log_auth_failure(user["username"], ip, "invalid_api_mfa_code")
            return jsonify({"ok": False, "error": "invalid MFA code"}), 401

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
            return jsonify({"error": "no valid items"}), 400
        return jsonify(dict(db.execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone())), 201

    # Task 4: Load role strictly from server DB via g.user
    if g.user["role"] == "admin":
        rows = db.execute("SELECT * FROM orders ORDER BY id DESC").fetchall()
    elif g.user["role"] == "restaurant":
        rows = db.execute("SELECT * FROM orders WHERE restaurant_id=? ORDER BY id DESC",
                          (g.user.get("restaurant_id"),)).fetchall()
    else:
        rows = db.execute("SELECT * FROM orders WHERE customer_id=? OR rider_id=? ORDER BY id DESC",
                          (g.user["id"], g.user["id"])).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/v1/orders/<int:order_id>", methods=["GET", "PATCH"])
@api_auth
def api_order(order_id):
    db = get_db()
    order = db.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
    if not order:
        return jsonify({"error": "not found"}), 404

    # Access control check (F-04 IDOR fix)
    uid = g.user["id"]
    caller = db.execute("SELECT restaurant_id FROM users WHERE id=?", (uid,)).fetchone()
    user_rest_id = caller["restaurant_id"] if caller else None

    ok = (
        g.user["role"] == "admin"
        or order["customer_id"] == uid
        or order["rider_id"] == uid
        or (g.user["role"] == "restaurant" and user_rest_id == order["restaurant_id"])
    )
    if not ok:
        return jsonify({"error": "not found"}), 404

    if request.method == "PATCH":
        if g.user["role"] == "customer" and order["customer_id"] != g.user["id"]:
            return jsonify({"error": "not your order"}), 403
        data = request.get_json(silent=True) or {}
        for key, value in data.items():
            if key in ORDER_COLUMNS:
                db.execute("UPDATE orders SET %s=? WHERE id=?" % key, (value, order_id))
        db.commit()
        order = db.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()

    result = dict(order)
    cust = db.execute("SELECT full_name, phone, address FROM users WHERE id=?", (order["customer_id"],)).fetchone()
    result["customer"] = dict(cust) if cust else None
    return jsonify(result)


@app.route("/api/v1/users/<int:user_id>")
@api_auth
def api_user_profile(user_id):
    # Only allow self or admin
    if g.user["role"] != "admin" and g.user["id"] != user_id:
        return jsonify({"error": "not found"}), 404
    u = get_db().execute("SELECT id, username, full_name, role, phone, address FROM users WHERE id=?",
                         (user_id,)).fetchone()
    if not u:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(u))


@app.route("/api/v1/admin/users")
@api_auth
def api_admin_users():
    # Enforce admin role strictly from server
    if g.user["role"] != "admin":
        return jsonify({"error": "forbidden"}), 403
    rows = get_db().execute("SELECT id, username, full_name, role, phone FROM users").fetchall()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5050")), debug=True)
