"""
DabbaDash - Food Delivery Order Platform (v1.0)
-----------------------------------------------
TRAINING APPLICATION - ITM Secure Application Development course.
This app is intentionally insecure. Run it only on your own machine
(it listens on 127.0.0.1 only). Never deploy it on a server.

API-first: the mobile apps for customers, restaurants and riders all
talk to the JSON API under /api/v1. The web pages are a small console
for demos and for the operations team.

Run:   python3 app.py      then open  http://127.0.0.1:5050
"""
import base64
import hashlib
import os
import sqlite3
from datetime import datetime

from flask import (Flask, g, jsonify, redirect, render_template, request,
                   session, url_for)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "orders.db")

app = Flask(__name__)
app.secret_key = "dabbadash@indore"

# Maps service used to calculate delivery distance
MAPS_API_KEY = "AIzaSyD-DabbaDash-9xQ2LmP4vT7wK1nR8sY3"

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


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def init_db():
    if os.path.exists(DB_PATH):
        return
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'customer',   -- customer | restaurant | rider | admin
        phone TEXT,
        address TEXT,
        restaurant_id INTEGER                     -- set for restaurant staff
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
        db.execute("INSERT INTO users (username,password,full_name,role,phone,address,restaurant_id) "
                   "VALUES (?,?,?,?,?,?,?)", (u[0], hash_password(u[1])) + u[2:])
    db.executemany("INSERT INTO orders (customer_id,restaurant_id,rider_id,items,total,delivery_note,status,created_at) "
                   "VALUES (?,?,?,?,?,?,?,?)", [
        (2, 1, 6, "2 x Poha Jalebi, 1 x Garadu", 210, "Ring the bell twice", "Delivered", "2026-10-25 09:10"),
        (3, 3, None, "1 x Malwa Special Thali", 220, "Leave at security gate", "Preparing", "2026-10-28 13:05"),
        (2, 3, None, "2 x Dal Bafla, 2 x Mawa Bati", 460, "Call on arrival", "Placed", "2026-10-28 20:40"),
    ])
    db.commit()
    db.close()


# ---------------------------------------------------------------- auth helpers
def check_login(username, password):
    """Shared by the web login page and the API login."""
    query = ("SELECT * FROM users WHERE username = '" + username +
             "' AND password = '" + hash_password(password) + "'")
    return get_db().execute(query).fetchone(), query


def make_token(user):
    # Mobile apps send this back as  Authorization: Bearer <token>
    raw = "%s:%s:%s" % (user["id"], user["username"], user["role"])
    return base64.b64encode(raw.encode()).decode()


def api_user():
    """Who is calling the API? Uses the Bearer token, or the web session."""
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        try:
            uid, username, role = base64.b64decode(header[7:]).decode().split(":")
            return {"id": int(uid), "username": username, "role": role}
        except Exception:
            return None
    if "user_id" in session:
        return {"id": session["user_id"], "username": session["username"], "role": session["role"]}
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
    if "user_id" not in session:
        return None
    return {"id": session["user_id"], "name": session["name"], "role": session["role"]}


def login_required(role=None):
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
        try:
            user, query = check_login(request.form.get("username", ""), request.form.get("password", ""))
        except Exception as e:
            return render_template("error.html", msg="Database error: " + str(e)), 500
        if user:
            session["user_id"], session["username"] = user["id"], user["username"]
            session["name"], session["role"] = user["full_name"], user["role"]
            return redirect(url_for("index"))
        error = "Invalid username or password"
    return render_template("login.html", error=error)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        f = request.form
        try:
            get_db().execute("INSERT INTO users (username,password,full_name,role,phone,address) VALUES (?,?,?,?,?,?)",
                             (f["username"], hash_password(f["password"]), f["full_name"], "customer",
                              f.get("phone"), f.get("address")))
            get_db().commit()
        except sqlite3.IntegrityError:
            return render_template("register.html", error="Username already taken")
        return redirect(url_for("login"))
    return render_template("register.html", error=None)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/customer")
@login_required("customer")
def customer_home():
    db = get_db()
    rid = request.args.get("restaurant", "1")
    restaurants = db.execute("SELECT * FROM restaurants").fetchall()
    menu = db.execute("SELECT * FROM menu WHERE restaurant_id=?", (rid,)).fetchall()
    orders = db.execute("SELECT o.*, r.name AS restaurant FROM orders o JOIN restaurants r ON r.id=o.restaurant_id "
                        "WHERE customer_id=? ORDER BY o.id DESC", (session["user_id"],)).fetchall()
    return render_template("customer.html", user=current_user(), restaurants=restaurants, menu=menu,
                           rid=int(rid), orders=orders, token=make_token(
                               {"id": session["user_id"], "username": session["username"], "role": "customer"}))


@app.route("/order", methods=["POST"])
@login_required("customer")
def web_order():
    qty = {k[4:]: v for k, v in request.form.items() if k.startswith("qty_")}
    create_order(session["user_id"], request.form["restaurant_id"], qty, request.form.get("delivery_note", ""))
    return redirect(url_for("customer_home", restaurant=request.form["restaurant_id"]))


@app.route("/restaurant")
@login_required("restaurant")
def restaurant_home():
    db = get_db()
    me = db.execute("SELECT restaurant_id FROM users WHERE id=?", (session["user_id"],)).fetchone()
    orders = db.execute("SELECT o.*, u.full_name AS customer FROM orders o JOIN users u ON u.id=o.customer_id "
                        "WHERE o.restaurant_id=? ORDER BY o.id DESC", (me["restaurant_id"],)).fetchall()
    return render_template("restaurant.html", user=current_user(), orders=orders)


@app.route("/rider")
@login_required("rider")
def rider_home():
    orders = get_db().execute(
        "SELECT o.*, u.full_name AS customer, u.phone, u.address, r.name AS restaurant FROM orders o "
        "JOIN users u ON u.id=o.customer_id JOIN restaurants r ON r.id=o.restaurant_id "
        "WHERE o.status IN ('Ready','Picked up') OR o.rider_id=? ORDER BY o.id DESC", (session["user_id"],)).fetchall()
    return render_template("rider.html", user=current_user(), orders=orders)


@app.route("/order/<int:order_id>/status", methods=["POST"])
@login_required()
def web_status(order_id):
    db = get_db()
    if session["role"] == "rider":
        db.execute("UPDATE orders SET status=?, rider_id=? WHERE id=?",
                   (request.form["status"], session["user_id"], order_id))
    else:
        db.execute("UPDATE orders SET status=? WHERE id=?", (request.form["status"], order_id))
    db.commit()
    return redirect(url_for("index"))


@app.route("/admin")
@login_required("admin")
def admin_home():
    db = get_db()
    users = db.execute("SELECT id, username, full_name, role, phone FROM users").fetchall()
    orders = db.execute("SELECT o.*, r.name AS restaurant FROM orders o JOIN restaurants r ON r.id=o.restaurant_id "
                        "ORDER BY o.id DESC").fetchall()
    return render_template("admin.html", user=current_user(), users=users, orders=orders)


# ---------------------------------------------------------------- JSON API (used by the mobile apps)
@app.route("/api/v1/register", methods=["POST"])
def api_register():
    data = request.get_json(silent=True) or {}
    if not data.get("username") or not data.get("password") or not data.get("full_name"):
        return jsonify({"error": "username, password and full_name are required"}), 400
    data["password"] = hash_password(data["password"])
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
    try:
        user, query = check_login(data.get("username", ""), data.get("password", ""))
    except Exception as e:
        return jsonify({"error": "database error", "detail": str(e), "query": query_for_debug(data)}), 500
    if not user:
        return jsonify({"ok": False, "error": "invalid credentials"}), 401
    return jsonify({"ok": True, "token": make_token(user), "user_id": user["id"], "role": user["role"]})


def query_for_debug(data):
    return ("SELECT * FROM users WHERE username = '" + data.get("username", "") +
            "' AND password = '" + hash_password(data.get("password", "")) + "'")


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
    u = get_db().execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not u:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(u))


@app.route("/api/v1/admin/users")
@api_auth
def api_admin_users():
    rows = get_db().execute("SELECT * FROM users").fetchall()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5050")), debug=True)
