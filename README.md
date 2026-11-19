# DabbaDash – Food Delivery Order Platform (Group 3)

**Hardened Production-Grade Application, ITM Secure Application Development course.**

## About DabbaDash
DabbaDash is an API-first food delivery platform operating in Indore and Bhopal with about 1,200 partner restaurants, 2,500 riders, and 300,000 customers.
- **Mobile JSON API**: `/api/v1/...` powers customer, restaurant, and rider apps.
- **Operations Web Console**: `/` management dashboard for administrative oversight and kitchen/rider dispatch.
- **Compliance**: Fully compliant with the Indian **Digital Personal Data Protection (DPDP) Act 2023** and **OWASP ASVS 5.0**.

---

## Security Changes (Hardening Against Day 3 Review)

All 20 security vulnerabilities discovered during the Day 3 Code Review (F-01 through F-20) have been remediated and verified.

### Findings Register (F-01 to F-20)

| ID | Title | Location | CWE | OWASP 2025 Category | Severity | Status | Remediation Summary |
|---|---|---|---|---|---|---|---|
| **F-01** | SQL injection in login | `app.py` `check_login()` | CWE-89 | A05:2025 Injection | **Critical** | **Fixed** | Replaced dynamic string concatenation with parameterized SQL query (`WHERE username=?`). |
| **F-02** | Forgeable bearer token | `app.py` `make_token()` | CWE-345 | A08:2025 Integrity Failures | **Critical** | **Fixed** | Cryptographically signed HMAC-SHA256 bearer tokens with 24h expiration timestamp and server validation. |
| **F-03** | Anyone can register as admin | `app.py` `api_register()` | CWE-915 | A01:2025 Broken Access Control | **Critical** | **Fixed** | Eliminated mass assignment; hardcoded `role = 'customer'` for all public registrations. |
| **F-04** | Any user can read any order (IDOR) | `app.py` `api_order()` | CWE-639 | A01:2025 Broken Access Control | **Critical** | **Fixed** | Strict ownership check; only customer owner, assigned rider, restaurant, or admin can read order (otherwise returns 404). |
| **F-05** | Admin user list open to everyone | `app.py` `api_admin_users()` | CWE-862 | A01:2025 Broken Access Control | **Critical** | **Fixed** | Enforced server-side `g.user["role"] == "admin"` authorization check (returns 403 Forbidden). |
| **F-06** | User profile leaks password hash | `app.py` `api_user_profile()` | CWE-200 | A01:2025 Broken Access Control | **High** | **Fixed** | Restricted to self/admin; safe SQL projection omitting `password`, `mfa_secret`, and `last_totp_code`. |
| **F-07** | PATCH can change any order field | `app.py` `api_order()` | CWE-915 | A01:2025 Broken Access Control | **High** | **Fixed** | Role-based parameter whitelisting; customers only edit notes before prep; riders/kitchen only advance status. |
| **F-08** | Anyone can set any order status | `app.py` `web_status()` | CWE-862 | A01:2025 Broken Access Control | **High** | **Fixed** | Finite-state machine validation preventing unauthorized role status transitions. |
| **F-09** | Passwords stored as plain MD5 | `app.py` `hash_password()` | CWE-328 | A04:2025 Cryptographic Failures | **High** | **Fixed** | Migrated to Argon2id (`argon2-cffi`) with safe, automatic in-place re-hashing on login. |
| **F-10** | No limit on login attempts | `app.py` `check_login()` | CWE-307 | A07:2025 Authentication Failures | **High** | **Fixed** | Account lockout after 5 consecutive failed attempts (15-minute window) + IP-level throttling. |
| **F-11** | Stored XSS on rider page | `templates/rider.html` | CWE-79 | A05:2025 Injection | **High** | **Fixed** | Removed `\|safe` filter from `{{ o.delivery_note }}` to enable contextual Jinja2 HTML auto-escaping. |
| **F-12** | Secrets hard-coded in code | `app.py` | CWE-798 | A04:2025 Cryptographic Failures | **High** | **Fixed** | Removed hardcoded secrets; dynamically loaded via environment variables (`SECRET_KEY`, `FLASK_SECRET_KEY`). |
| **F-13** | Debug mode left on | `app.py` `app.run()` | CWE-489 | A02:2025 Security Misconfiguration | **High** | **Fixed** | Disabled debug mode by default (`debug = False`); controlled via `FLASK_DEBUG=1`. |
| **F-14** | Riders see every customer's address | `app.py` `rider_home()` | CWE-359 | A01:2025 Broken Access Control | **High** | **Fixed** | DPDP Act protection: masked customer phone and address on completed/delivered orders. |
| **F-15** | Errors reveal SQL and internals | `app.py` `api_login()` | CWE-209 | A10:2025 Exceptional Conditions | **Medium** | **Fixed** | Removed `query_for_debug` and raw SQL exception leakage; returns generic error messages. |
| **F-16** | No CSRF protection | `app.py` & templates | CWE-352 | A01:2025 Broken Access Control | **Medium** | **Fixed** | Generated synchronized cryptographic CSRF tokens, injected into all forms and verified on POST. |
| **F-17** | No security headers, weak cookies | `app.py` | CWE-693 | A02:2025 Security Misconfiguration | **Medium** | **Fixed** | Added CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and HttpOnly/SameSite cookies. |
| **F-18** | Weak checks on order input | `app.py` `create_order()` | CWE-20 | A06:2025 Insecure Design | **Medium** | **Fixed** | Quantity validation ($1 \le \text{qty} \le 50$), restaurant existence verification, server-side price calculation. |
| **F-19** | No audit log of security events | `app.py` | CWE-778 | A09:2025 Security Logging | **Medium** | **Fixed** | Structured audit logging for login failures, lockouts, access denials, MFA events, and status updates. |
| **F-20** | No password rules | `app.py` registration | CWE-521 | A07:2025 Authentication Failures | **Medium** | **Fixed** | Enforced 8-character minimum length and dictionary blocklist check during user sign-up. |

---

## Live Demo: 3 Old Attacks That Now Fail

### Demo 1: SQL Injection Login Attempt (F-01)
- **Old Attack**: Authenticating as admin without password using `admin' --`.
  ```bash
  curl -s -X POST http://127.0.0.1:5050/api/v1/login \
       -H "Content-Type: application/json" \
       -d '{"username":"admin'\'' --","password":"x"}'
  ```
- **Result Today**: **`401 Unauthorized`** (`{"error": "Invalid username or password", "ok": false}`). Parameterized SQL treats the input strictly as literal string data.

### Demo 2: Insecure Direct Object Reference (F-04 IDOR)
- **Old Attack**: Customer Kabir reading Customer Priya's order details and address.
  ```bash
  # Log in as Kabir
  KABIR_TOKEN=$(curl -s -X POST http://127.0.0.1:5050/api/v1/login -H "Content-Type: application/json" -d '{"username":"kabir","password":"Kabir@123"}' | grep -o '"token":"[^"]*' | cut -d'"' -f4)

  # Attempt to read Order #1 (Priya's order)
  curl -i http://127.0.0.1:5050/api/v1/orders/1 -H "Authorization: Bearer $KABIR_TOKEN"
  ```
- **Result Today**: **`404 Not Found`** (`{"error": "not found"}`). Order ownership is strictly enforced on the server.

### Demo 3: Self-Assigned Privilege Escalation (F-03)
- **Old Attack**: Registering a new account with `"role": "admin"`.
  ```bash
  curl -s -X POST http://127.0.0.1:5050/api/v1/register \
       -H "Content-Type: application/json" \
       -d '{"username":"attacker","password":"Password@123","full_name":"Attacker","role":"admin"}'
  ```
- **Result Today**: The `role` parameter is ignored. The account is created strictly with `role: "customer"`.

---

## Run it (Local Environment)

```bash
cd G3_DabbaDash_Orders
python3 -m venv venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
python3 app.py
```
Open **http://127.0.0.1:5050** in your browser.

### Test Accounts
| Role | Username | Password | Notes |
|---|---|---|---|
| Admin | `admin` | `Admin@2024` | Requires TOTP MFA enrollment on first login |
| Customer | `priya` | `Priya@123` | Auto-migrates from MD5 to Argon2id on login |
| Customer | `kabir` | `Kabir@123` | Auto-migrates from MD5 to Argon2id on login |
| Restaurant | `sarafa` | `Rest@123` | Kitchen staff (Sarafa Bazaar) |
| Rider | `rider.ravi` | `Rider@123` | Delivery partner (masked customer PII on completion) |

---

## Security Documentation & Verification
- **OWASP ASVS 5.0 Verification Checklist**: Full details in [`ASVS_CHECKLIST.md`](file:///Users/rafeshaikh/Desktop/cybersecurity/AbhishekSir/G3_DabbaDash_Orders/ASVS_CHECKLIST.md).
- **MFA Architecture & Anti-Replay Report**: Technical specification in [`mfa.md`](file:///Users/rafeshaikh/Desktop/cybersecurity/AbhishekSir/G3_DabbaDash_Orders/mfa.md).
- **Automated Pre-Commit Hook**: Configured in `.githooks/pre-commit` (runs Bandit static analysis and staged secret scanning before commits).
