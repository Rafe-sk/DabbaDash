# OWASP ASVS 5.0 Verification Checklist – DabbaDash (Group 3)

**Project:** DabbaDash Food Delivery Order Platform  
**Target Milestone:** Break Project (Hardened Application Review)  
**Standard:** OWASP Application Security Verification Standard (ASVS) 5.0 (Chapters V6, V7, V8, V13, V14, V16)

---

## Summary of Compliance

| ASVS Chapter | Chapter Title | Verification Scope | Status |
|---|---|---|---|
| **V6** | **Cryptography** | Password storage, secret keys, token integrity | **PASS (100%)** |
| **V7** | **Session Management** | Cookie attributes, session fixation, idle timeout, logout | **PASS (100%)** |
| **V8** | **Access Control** | Horizontal/Vertical authorization (IDOR, RBAC, BFLA) | **PASS (100%)** |
| **V13** | **Data Protection & Privacy** | DPDP Act compliance, PII masking, error data leakage | **PASS (100%)** |
| **V14** | **Configuration & Architecture** | Debug mode, HTTP security headers, request limits | **PASS (100%)** |
| **V16** | **Input Validation & Sanitization** | SQL injection, XSS, CSRF, input bounds validation | **PASS (100%)** |

---

## Detailed Evidence by Category

### V6: Cryptography Verification Standard

| Requirement ID | Verification Requirement | Status | Evidence in Codebase |
|---|---|---|---|
| **V6.1.1** | Passwords must be stored using a modern, salted, memory-hard hashing algorithm. | **PASS** | `app.py`: Implemented Argon2id via `argon2-cffi` (`PasswordHasher()`). Legacy MD5 hashes are automatically and safely migrated in-place upon user login. |
| **V6.2.1** | Secret keys must not be hardcoded in application source code. | **PASS** | `app.py`: Hardcoded `MAPS_API_KEY` and session key removed. Secrets loaded dynamically from environment variables (`SECRET_KEY`, `FLASK_SECRET_KEY`). |
| **V6.3.1** | Authentication tokens must be cryptographically signed to prevent tampering. | **PASS** | `app.py` (`make_token` / `api_user`): Switched from plain Base64 to HMAC-SHA256 signed bearer tokens with timestamp expiration. Forged tokens are rejected. |
| **V6.4.1** | Multi-factor authentication must use industry-standard algorithms. | **PASS** | `app.py`: RFC 6238 Time-based One-Time Password (TOTP) implemented via `pyotp` for the `admin` role, with single-use anti-replay enforcement (`last_totp_code`). |

---

### V7: Session Management Verification Standard

| Requirement ID | Verification Requirement | Status | Evidence in Codebase |
|---|---|---|---|
| **V7.1.1** | Session identifiers must be renewed upon login to prevent Session Fixation. | **PASS** | `app.py` (`login()`): `session.clear()` called immediately upon successful credential validation before assigning `session["user_id"]`. |
| **V7.2.1** | Session cookies must enforce secure attributes (`HttpOnly`, `SameSite`). | **PASS** | `app.py`: Configured `SESSION_COOKIE_HTTPONLY=True` (blocks JavaScript access) and `SESSION_COOKIE_SAMESITE="Lax"` (mitigates CSRF). |
| **V7.3.1** | Sessions must terminate after a defined period of inactivity (Idle Timeout). | **PASS** | `app.py` (`enforce_idle_timeout`): `@app.before_request` tracks `_last_active`. After 15 minutes (900s) of inactivity, the session is invalidated and redirected to login. |
| **V7.4.1** | Logout functionality must fully destroy the server and client session state. | **PASS** | `app.py` (`logout()`): Calls `session.clear()` and explicitly deletes the session cookie with `resp.delete_cookie()`. |

---

### V8: Access Control Verification Standard

| Requirement ID | Verification Requirement | Status | Evidence in Codebase |
|---|---|---|---|
| **V8.1.1** | Access control decisions must be enforced on the trusted server, not from client cookies or tokens. | **PASS** | `app.py` (`current_user` / `api_user`): User `role` and permissions are queried fresh from the SQLite database on each request, never trusted from client input. |
| **V8.2.1** | Users must not be able to view or modify resources owned by other users (IDOR prevention). | **PASS** | `app.py` (`api_order`): Only the customer who placed the order, the assigned rider, the preparing restaurant, or admin can access `/api/v1/orders/<id>`. Returns 404 otherwise. |
| **V8.3.1** | Administrative interfaces must enforce strict function-level authorization. | **PASS** | `app.py` (`api_admin_users`): Endpoint explicitly enforces `g.user["role"] == "admin"`, returning 403 Forbidden to unauthorized callers. |
| **V8.4.1** | Modifying record states must follow legitimate role transitions (RBAC state machine). | **PASS** | `app.py` (`web_status` / `api_order` PATCH): Customers cannot change status; riders can only transition `Ready -> Picked up -> Delivered`; restaurants can only transition `Placed -> Preparing -> Ready`. |

---

### V13: Data Protection & Privacy Verification Standard (DPDP Act 2023)

| Requirement ID | Verification Requirement | Status | Evidence in Codebase |
|---|---|---|---|
| **V13.1.1** | Personal Data (PII) must be masked once a business need concludes. | **PASS** | `app.py` (`rider_home` / `api_order`): Once an order is marked `Delivered`, the customer's phone number and home address are redacted as `*** Delivered (Address Protected) ***`. |
| **V13.2.1** | User profile endpoints must not leak sensitive authentication credentials or hashes. | **PASS** | `app.py` (`api_user_profile`): Query projects safe fields (`id, username, full_name, role, phone, address`). Password hashes, MFA secrets, and TOTP codes are never exposed. |
| **V13.3.1** | Error responses must not leak sensitive system data or SQL queries. | **PASS** | `app.py` (`check_login` / `api_login`): Removed `query_for_debug` and raw SQL exceptions. Returns generic `"Invalid username or password"`. |

---

### V14: Configuration & Architecture Verification Standard

| Requirement ID | Verification Requirement | Status | Evidence in Codebase |
|---|---|---|---|
| **V14.1.1** | Debug mode and development backdoors must be disabled in production. | **PASS** | `app.py`: `app.run(..., debug=is_debug)` where `is_debug` defaults to `False` unless explicitly enabled via `FLASK_DEBUG=1`. |
| **V14.2.1** | HTTP responses must include defensive security headers. | **PASS** | `app.py` (`apply_security_headers`): Enforces `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, and `Permissions-Policy`. |
| **V14.3.1** | Application must limit request body size to mitigate Denial of Service. | **PASS** | `app.py`: Configured `MAX_CONTENT_LENGTH = 1 * 1024 * 1024` (1MB limit). |
| **V14.4.1** | Dead or insecure code must be eliminated from the codebase. | **PASS** | Removed insecure string SQL builders (`query_for_debug`), insecure MD5 hashing functions, and unparameterized query branches. |

---

### V16: Input Validation & Sanitization Verification Standard

| Requirement ID | Verification Requirement | Status | Evidence in Codebase |
|---|---|---|---|
| **V16.1.1** | All database queries must use parameterized queries or prepared statements. | **PASS** | `app.py`: 100% of queries use SQLite `?` placeholders. Zero string concatenation into SQL commands. |
| **V16.2.1** | Dynamic user input in HTML templates must be contextually auto-escaped. | **PASS** | `templates/rider.html`: Removed `|safe` filter from `{{ o.delivery_note }}`. Jinja2 automatically escapes HTML tags, stopping Stored XSS. |
| **V16.3.1** | State-changing HTTP POST requests must require Cross-Site Request Forgery (CSRF) tokens. | **PASS** | `app.py` & templates: Implemented synchronized CSRF tokens injected into all forms and verified on POST (`validate_csrf()`). |
| **V16.4.1** | Numerical and string inputs must enforce positive bounds and size limits. | **PASS** | `app.py` (`create_order`): Item quantities restricted to $1 \le \text{qty} \le 50$, order note limited to 250 characters, and order total computed strictly from database menu prices. |
| **V16.5.1** | Passwords must satisfy length and dictionary blocklist requirements. | **PASS** | `app.py` (`validate_password_policy`): Rejects passwords shorter than 8 characters or appearing in common breached password lists. |
