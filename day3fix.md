# Day 3 Code Review Security Fixes Report – DabbaDash (Group 3)

**Application:** DabbaDash Food Delivery Platform (`app.py`, `templates/`)  
**Course:** ITM Secure Application Development  
**Scope:** Remediation of all 20 findings from Day 3 Code Review (F-01 to F-20)  
**Status:** **All 20 Flaws Remediated and Verified (100% Fixed)**

---

## 1. Executive Summary & Overview

During the Day 3 Code Review of the DabbaDash order platform, 20 security vulnerabilities were discovered across 3 severity tiers:
- **5 Critical Findings** (F-01 to F-05): SQL injection, forged bearer tokens, admin self-registration, order IDOR, and unprotected admin endpoints.
- **9 High Findings** (F-06 to F-14): Credential leaks, mass assignment, unauthenticated order state manipulation, weak MD5 hashing, infinite login brute-force, stored XSS, hardcoded secrets, enabled debug mode, and DPDP customer address leakage.
- **6 Medium Findings** (F-15 to F-20): Information disclosure in errors, missing CSRF tokens, missing security headers, weak input validation on orders, absence of audit logging, and lack of password complexity rules.

Every finding has been patched in code, verified with automated security tools (Bandit AST Scanner, `pip-audit`), and backed by automated pre-commit scanning.

---

## 2. Summary Findings Register

| ID | Title | Severity | CWE | OWASP 2025 Category | Status | Target File(s) |
|---|---|---|---|---|---|---|
| **F-01** | SQL Injection in Login | **Critical** | CWE-89 | A05:2025 Injection | **Fixed** | `app.py` `check_login()` |
| **F-02** | Forgeable Bearer Token | **Critical** | CWE-345 | A08:2025 Integrity Failures | **Fixed** | `app.py` `make_token()`, `api_user()` |
| **F-03** | Anyone Can Register as Admin | **Critical** | CWE-915 | A01:2025 Broken Access Control | **Fixed** | `app.py` `api_register()` |
| **F-04** | Any User Can Read Any Order (IDOR) | **Critical** | CWE-639 | A01:2025 Broken Access Control | **Fixed** | `app.py` `api_order()` |
| **F-05** | Admin User List Open to Everyone | **Critical** | CWE-862 | A01:2025 Broken Access Control | **Fixed** | `app.py` `api_admin_users()` |
| **F-06** | User Profile Leaks Password Hash | **High** | CWE-200 | A01:2025 Broken Access Control | **Fixed** | `app.py` `api_user_profile()` |
| **F-07** | PATCH Can Change Any Order Field | **High** | CWE-915 | A01:2025 Broken Access Control | **Fixed** | `app.py` `api_order()` PATCH |
| **F-08** | Anyone Can Set Any Order Status | **High** | CWE-862 | A01:2025 Broken Access Control | **Fixed** | `app.py` `web_status()` |
| **F-09** | Passwords Stored as Plain MD5 | **High** | CWE-328 | A04:2025 Cryptographic Failures | **Fixed** | `app.py` `hash_password()`, `check_login()` |
| **F-10** | No Limit on Login Attempts | **High** | CWE-307 | A07:2025 Authentication Failures | **Fixed** | `app.py` `is_account_locked()`, `check_login()` |
| **F-11** | Stored XSS on Rider Page | **High** | CWE-79 | A05:2025 Injection | **Fixed** | `templates/rider.html` |
| **F-12** | Secrets Hard-Coded in Code | **High** | CWE-798 | A04:2025 Cryptographic Failures | **Fixed** | `app.py` |
| **F-13** | Debug Mode Left On | **High** | CWE-489 | A02:2025 Security Misconfiguration | **Fixed** | `app.py` `__main__` |
| **F-14** | Riders See Every Customer's Address | **High** | CWE-359 | A01:2025 Broken Access Control | **Fixed** | `app.py` `rider_home()`, `api_order()` |
| **F-15** | Errors Reveal SQL and Internals | **Medium** | CWE-209 | A10:2025 Exceptional Conditions | **Fixed** | `app.py` `api_login()`, `login()` |
| **F-16** | No CSRF Protection | **Medium** | CWE-352 | A01:2025 Broken Access Control | **Fixed** | `app.py`, all HTML templates |
| **F-17** | No Security Headers, Weak Cookies | **Medium** | CWE-693 | A02:2025 Security Misconfiguration | **Fixed** | `app.py` `apply_security_headers()` |
| **F-18** | Weak Checks on Order Input | **Medium** | CWE-20 | A06:2025 Insecure Design | **Fixed** | `app.py` `create_order()` |
| **F-19** | No Audit Log of Security Events | **Medium** | CWE-778 | A09:2025 Security Logging | **Fixed** | `app.py` `auth_logger` |
| **F-20** | No Password Rules | **Medium** | CWE-521 | A07:2025 Authentication Failures | **Fixed** | `app.py` `validate_password_policy()` |

---

## 3. Detailed Fixes: The 5 Critical Findings

---

### F-01: SQL Injection in Login
- **Classification:** CWE-89 | OWASP A05:2025 Injection
- **Severity:** Critical
- **Location:** `app.py`, `check_login()`
- **Root Cause:** Dynamic string concatenation joined user-supplied username directly into the SQL query string, allowing complete authentication bypass with `admin' --`.

#### Before (Vulnerable):
```python
def check_login(username, password):
    query = ("SELECT * FROM users WHERE username = '" + username +
             "' AND password = '" + hash_password(password) + "'")
    return get_db().execute(query).fetchone(), query
```

#### After (Fixed):
```python
def check_login(username, password, ip):
    ...
    db = get_db()
    # Parameterized query treats input strictly as literal values
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not user or not verify_and_rehash_password(user, password):
        record_login_attempt(username, ip, success=False)
        log_auth_failure(username, ip, "invalid_credentials")
        return None, "Invalid username or password"
    ...
    return user, None
```

#### Proof of Fix:
- Sending `username: "admin' --"` with password `"x"` to `/api/v1/login` returns **HTTP 401 Unauthorized** with `{"ok": false, "error": "Invalid username or password"}`.

---

### F-02: Forgeable Bearer Token
- **Classification:** CWE-345 | OWASP A08:2025 Software and Data Integrity Failures
- **Severity:** Critical
- **Location:** `app.py`, `make_token()`, `api_user()`
- **Root Cause:** The API token was an unsigned Base64 string `id:username:role`. Any user could change their user ID or role to `admin` without detection.

#### Before (Vulnerable):
```python
def make_token(user):
    raw = "%s:%s:%s" % (user["id"], user["username"], user["role"])
    return base64.b64encode(raw.encode()).decode()

def api_user():
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        uid, username, role = base64.b64decode(header[7:]).decode().split(":")
        return {"id": int(uid), "username": username, "role": role}
```

#### After (Fixed):
```python
def make_token(user):
    exp = int(datetime.now().timestamp()) + 86400  # 24-hour expiration
    payload = f"{user['id']}:{user['username']}:{exp}"
    b64_payload = base64.urlsafe_b64encode(payload.encode()).decode()
    sig = hmac.new(app.secret_key.encode(), b64_payload.encode(), hashlib.sha256).hexdigest()
    return f"{b64_payload}.{sig}"

def api_user():
    header = request.headers.get("Authorization", "")
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
            uid, exp = int(parts[0]), int(parts[2])
            if datetime.now().timestamp() > exp:
                return None
        except Exception:
            return None
```

#### Proof of Fix:
- Sending a modified token `1:admin:9999999999.fake_sig` returns **HTTP 401 Unauthorized**.

---

### F-03: Anyone Can Register as Admin
- **Classification:** CWE-915 | OWASP A01:2025 Broken Access Control
- **Severity:** Critical
- **Location:** `app.py`, `api_register()`
- **Root Cause:** The endpoint filtered by `USER_COLUMNS`, which included `role`. An attacker could post `{"role": "admin"}` to create an administrator account.

#### Before (Vulnerable):
```python
USER_COLUMNS = ["username", "password", "full_name", "role", "phone", "address", "restaurant_id"]

fields = {k: v for k, v in data.items() if k in USER_COLUMNS}
db.execute("INSERT INTO users (%s) VALUES (%s)" % (",".join(fields), ",".join("?" * len(fields))),
           list(fields.values()))
```

#### After (Fixed):
```python
# Hardcoded parameter mapping; ignores any role sent by client
cur = db.execute(
    "INSERT INTO users (username, password, full_name, role, phone, address, restaurant_id, mfa_secret, mfa_enabled, last_totp_code) "
    "VALUES (?, ?, ?, 'customer', ?, ?, NULL, NULL, 0, NULL)",
    (username, hash_password(password), full_name, data.get("phone", "").strip(), data.get("address", "").strip())
)
```

#### Proof of Fix:
- Registering with `{"username": "hacker", "role": "admin"}` creates an account with `role: "customer"`.

---

### F-04: Any User Can Read Any Order (IDOR)
- **Classification:** CWE-639 | OWASP A01:2025 Broken Access Control
- **Severity:** Critical
- **Location:** `app.py`, `api_order()`
- **Root Cause:** The endpoint queried orders by ID only (`SELECT * FROM orders WHERE id=?`), leaking customer names, phone numbers, and home addresses across users.

#### Before (Vulnerable):
```python
@app.route("/api/v1/orders/<int:order_id>", methods=["GET", "PATCH"])
@api_auth
def api_order(order_id):
    db = get_db()
    order = db.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
    # No authorization check!
    cust = db.execute("SELECT full_name, phone, address FROM users WHERE id=?", (order["customer_id"],)).fetchone()
    result["customer"] = dict(cust)
    return jsonify(result)
```

#### After (Fixed):
```python
uid = g.user["id"]
caller = db.execute("SELECT restaurant_id FROM users WHERE id=?", (uid,)).fetchone()
user_rest_id = caller["restaurant_id"] if caller else None

# Allow only customer owner, assigned rider, order's restaurant, or admin
ok = (
    g.user["role"] == "admin"
    or order["customer_id"] == uid
    or order["rider_id"] == uid
    or (g.user["role"] == "restaurant" and user_rest_id == order["restaurant_id"])
)
if not ok:
    log_access_denied(uid, g.user["role"], f"api_order_{order_id}", "read_order_idor_blocked")
    return jsonify({"error": "not found"}), 404
```

#### Proof of Fix:
- Authenticated as `kabir` (customer ID 3), calling `GET /api/v1/orders/1` (Priya's order) returns **HTTP 404 Not Found**.

---

### F-05: Admin User List Open to Everyone
- **Classification:** CWE-862 | OWASP A01:2025 Broken Access Control
- **Severity:** Critical
- **Location:** `app.py`, `api_admin_users()`
- **Root Cause:** The endpoint had `@api_auth` but never validated whether `g.user["role"] == "admin"`. Any customer could dump the entire user list.

#### Before (Vulnerable):
```python
@app.route("/api/v1/admin/users")
@api_auth
def api_admin_users():
    rows = get_db().execute("SELECT * FROM users").fetchall()
    return jsonify([dict(r) for r in rows])
```

#### After (Fixed):
```python
@app.route("/api/v1/admin/users")
@api_auth
def api_admin_users():
    if g.user["role"] != "admin":
        log_access_denied(g.user["id"], g.user["role"], "/api/v1/admin/users", "unauthorized_admin_access")
        return jsonify({"error": "forbidden"}), 403
    rows = get_db().execute("SELECT id, username, full_name, role, phone FROM users").fetchall()
    return jsonify([dict(r) for r in rows])
```

#### Proof of Fix:
- Customer calling `GET /api/v1/admin/users` returns **HTTP 403 Forbidden**.

---

## 4. Detailed Fixes: The 9 High Findings

---

### F-06: User Profile Leaks Password Hash
- **Classification:** CWE-200 | OWASP A01:2025 Broken Access Control
- **Fix:** Whitelisted safe projection columns (`id, username, full_name, role, phone, address`). Password hashes, MFA secrets, and TOTP data are excluded. Access is restricted to self or admin.

### F-07: PATCH Can Change Any Order Field
- **Classification:** CWE-915 | OWASP A01:2025 Broken Access Control
- **Fix:** Parameter whitelisting on `PATCH /api/v1/orders/<id>`:
  - `customer`: Can only edit `delivery_note` (and only if order status is `Placed`).
  - `rider`: Can only advance status to `Picked up` or `Delivered`.
  - `restaurant`: Can only advance status to `Preparing` or `Ready`.
  - Modification of `total`, `items`, `customer_id`, or `restaurant_id` is blocked.

### F-08: Anyone Can Set Any Order Status
- **Classification:** CWE-862 | OWASP A01:2025 Broken Access Control
- **Fix:** In `web_status()`, enforced finite-state transitions:
  - Customers are denied (`403 Forbidden`).
  - Riders can only mark `Ready -> Picked up` and `Picked up -> Delivered`.
  - Kitchen staff can only mark their own restaurant's orders `Placed -> Preparing` and `Preparing -> Ready`.

### F-09: Passwords Stored as Plain MD5
- **Classification:** CWE-328 | OWASP A04:2025 Cryptographic Failures
- **Fix:** Migrated to **Argon2id** (`argon2-cffi`). Existing users with MD5 hashes (`3e17f774c...`) are automatically verified against MD5 on next login and upgraded in-place to `$argon2id$v=19$...`.

### F-10: No Limit on Login Attempts
- **Classification:** CWE-307 | OWASP A07:2025 Authentication Failures
- **Fix:** Implemented 15-minute account lockout after 5 consecutive failed login attempts, tracked in the `login_attempts` SQLite table, plus IP-level rate limiting.

### F-11: Stored XSS on Rider Page
- **Classification:** CWE-79 | OWASP A05:2025 Injection
- **Fix:** In `templates/rider.html`, removed `{{ o.delivery_note|safe }}` and replaced with `{{ o.delivery_note }}`. Jinja2 automatically escapes all HTML tags (`<script>`, `<img>`, etc.).

### F-12: Secrets Hard-Coded in Code
- **Classification:** CWE-798 | OWASP A04:2025 Cryptographic Failures
- **Fix:** Removed hardcoded `MAPS_API_KEY` and session key `dabbadash@indore`. Keys are loaded from `os.environ.get("SECRET_KEY")` and `os.environ.get("MAPS_API_KEY")`.

### F-13: Debug Mode Left On
- **Classification:** CWE-489 | OWASP A02:2025 Security Misconfiguration
- **Fix:** Changed `debug=True` in `app.run()` to `debug = os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true")`. Defaults to `False`.

### F-14: Riders See Every Customer's Address
- **Classification:** CWE-359 | OWASP A01:2025 Broken Access Control (DPDP Act 2023)
- **Fix:** In `rider_home()`, customer phone and home address are redacted as `*** Delivered (Address Protected) ***` once an order is marked `Delivered`.

---

## 5. Detailed Fixes: The 6 Medium Findings

---

### F-15: Errors Reveal SQL and Internals
- **Classification:** CWE-209 | OWASP A10:2025 Exceptional Conditions
- **Fix:** Removed `query_for_debug` and raw `str(e)` exception leakage. Authentication failures return generic `"Invalid username or password"`.

### F-16: No CSRF Protection
- **Classification:** CWE-352 | OWASP A01:2025 Broken Access Control
- **Fix:** Implemented synchronized cryptographic CSRF tokens stored in session (`session["_csrf_token"]`), auto-injected into all forms, and validated on all POST requests (`validate_csrf()`).

### F-17: No Security Headers, Weak Cookie Flags
- **Classification:** CWE-693 | OWASP A02:2025 Security Misconfiguration
- **Fix:** Configured `apply_security_headers()` injecting CSP, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, and `Permissions-Policy`. Cookie flags set to `HttpOnly=True` and `SameSite='Lax'`.

### F-18: Weak Checks on Order Input
- **Classification:** CWE-20 | OWASP A06:2025 Insecure Design
- **Fix:** In `create_order()`, item quantities must be integers between 1 and 50 ($1 \le \text{qty} \le 50$), restaurant must exist, delivery notes limited to 250 characters, and order total calculated strictly from database prices.

### F-19: No Audit Log of Security Events
- **Classification:** CWE-778 | OWASP A09:2025 Security Logging
- **Fix:** Added structured audit logging via `auth_logger` capturing login failures, account lockouts, CSRF rejections, unauthorized IDOR attempts, and order state updates.

### F-20: No Password Rules
- **Classification:** CWE-521 | OWASP A07:2025 Authentication Failures
- **Fix:** Enforced minimum 8-character password length and dictionary blocklist check against top breached passwords during user sign-up.

---

## 6. Verification and Testing Evidence

### 6.1. Automated Static Analysis (Bandit)
```bash
./venv/bin/bandit -r app.py
```
**Bandit Output:**
```text
Run metrics:
	Total issues (by severity): High: 0, Medium: 0, Low: 0
Test results:
	No issues identified.
```

### 6.2. Dependency Vulnerability Audit (`pip-audit`)
```bash
./venv/bin/pip-audit
```
**Audit Output:**
```text
No known vulnerabilities found
```

### 6.3. Automated Pre-Commit Hook
Configured in `.githooks/pre-commit`:
- Automatically scans staged diffs for high-entropy API keys or private keys.
- Executes Bandit static analysis on `app.py`.
- Blocks commit if any security violation is detected.

---

## 7. Git Audit Progression

```text
388293f Break Project: Complete Application Hardening against Day 3 Review (F-01 to F-20)
7e24d44 Add detailed Day 4 MFA & Authentication hardening documentation in mfa.md
6102ab9 Enforce RFC 6238 TOTP anti-replay: each 6-digit code can only be used once
74cb7a0 Allow re-enrolling QR code from /mfa/verify and enhance QR code SVG styling
3534a1c Day 4: Fix Authentication & Sessions, Add TOTP MFA
22e8ed3 Initial commit before Day 4 security fixes
```

To view the complete change diff between the vulnerable and hardened application:
```bash
git diff 22e8ed3 HEAD
```
