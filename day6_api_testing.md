# Day 6 API Security Testing Report – DabbaDash (Group 3)

**Application:** DabbaDash Food Delivery API Platform  
**Target Milestone:** Day 6 Task – API Test Scripts for Your App  
**Original Version Path:** `/Users/rafeshaikh/Downloads/G3_DabbaDash_Orders`  
**Hardened Version Path:** `/Users/rafeshaikh/Desktop/cybersecurity/AbhishekSir/G3_DabbaDash_Orders`  
**Standard:** OWASP API Security Top 10 (2023)

---

## 1. Executive Summary

This report documents the creation, execution, and verification of automated security test scripts attacking the DabbaDash REST API. 

The test suite consists of **10 specialized security attack tests** written using `pytest` and Python's test engine. Each test simulates a real-world adversarial attack mapped directly to the **OWASP API Security Top 10 (2023)**.

### Results Summary:
- **Original Version (`Downloads`):** **9 FAILED, 1 PASSED** (90% failure rate; 9 vulnerabilities confirmed live).
- **Hardened Version (Current Workspace):** **10 PASSED, 0 FAILED** (100% pass rate; all attacks neutralized).

---

## 2. Role $\times$ Endpoint Test Matrix

The following matrix lists every API endpoint across all 5 user roles, detailing the expected HTTP status code for legitimate and unauthorized requests:

| API Endpoint | HTTP Method | Public / Unauth | Customer (`kabir`) | Restaurant (`sarafa`) | Rider (`ravi`) | Admin (`admin`) |
|---|---|---|---|---|---|---|
| `/api/v1/register` | `POST` | `201 Created` | `201 Created` | `201 Created` | `201 Created` | `201 Created` |
| `/api/v1/login` | `POST` | `200 OK` / `401` | `200 OK` | `200 OK` | `200 OK` | `200 OK` (w/ MFA) |
| `/api/v1/restaurants` | `GET` | `200 OK` | `200 OK` | `200 OK` | `200 OK` | `200 OK` |
| `/api/v1/restaurants/<id>/menu` | `GET` | `200 OK` | `200 OK` | `200 OK` | `200 OK` | `200 OK` |
| `/api/v1/orders` | `GET` | `401 Unauth` | `200` (Own Orders) | `200` (Kitchen Orders) | `200` (Rider Deliveries) | `200` (All Orders) |
| `/api/v1/orders` | `POST` | `401 Unauth` | `201 Created` | `400 Bad Request` | `400 Bad Request` | `201 Created` |
| `/api/v1/orders/<id>` | `GET` | `401 Unauth` | `200` (If Owner) / `404` | `200` (If Kitchen) / `404` | `200` (If Assigned) / `404` | `200 OK` (Always) |
| `/api/v1/orders/<id>` | `PATCH` | `401 Unauth` | `200` (Notes only) / `403` | `200` (Prep status) / `403` | `200` (Pickup status) / `403` | `200 OK` |
| `/api/v1/users/<id>` | `GET` | `401 Unauth` | `200` (Self) / `404` | `200` (Self) / `404` | `200` (Self) / `404` | `200 OK` (Any User) |
| `/api/v1/admin/users` | `GET` | `401 Unauth` | `403 Forbidden` | `403 Forbidden` | `403 Forbidden` | `200 OK` |

---

## 3. OWASP API Security Top 10 (2023) Mapping

Each test in [`tests/test_api_security.py`](file:///Users/rafeshaikh/Desktop/cybersecurity/AbhishekSir/G3_DabbaDash_Orders/tests/test_api_security.py) maps directly to an industry standard risk:

| Test Name | Attack Description | OWASP API 2023 Category | CWE |
|---|---|---|---|
| `test_sql_injection_login_blocked` | Injecting SQL syntax (`admin' --`) into authentication query | **API8:2023 Security Misconfiguration / Injection** | CWE-89 |
| `test_order_bola_idor_blocked` | Customer accessing another customer's private order and address | **API1:2023 Broken Object Level Authorization (BOLA)** | CWE-639 |
| `test_mass_assignment_admin_role_blocked` | Submitting `{"role": "admin"}` in public registration payload | **API3:2023 Broken Object Property Level Authorization** | CWE-915 |
| `test_profile_property_level_data_exposure` | Extracting password hashes and secrets from user profile endpoint | **API3:2023 Broken Object Property Level Authorization** | CWE-200 |
| `test_function_level_authorization_admin_users` | Non-admin caller attempting to access operations user directory | **API5:2023 Broken Function Level Authorization (BFLA)** | CWE-862 |
| `test_auth_missing_token_rejected` | Accessing private order endpoints with no authorization token | **API2:2023 Broken Authentication** | CWE-306 |
| `test_auth_forged_bearer_token_rejected` | Sending forged Base64 bearer token without valid HMAC signature | **API2:2023 Broken Authentication** | CWE-345 |
| `test_rate_limiting_login_lockout` | Attempting 6 consecutive rapid brute-force login attempts | **API4:2023 Unrestricted Resource Consumption** | CWE-307 |
| `test_order_patch_mass_assignment_price_tampering` | Manipulating order price (`{"total": 1}`) via PATCH request | **API3:2023 Broken Object Property Level Authorization** | CWE-915 |
| `test_password_policy_enforcement` | Registering with short or breached dictionary passwords | **API2:2023 Broken Authentication** | CWE-521 |

---

## 4. Execution Output Comparison: Original vs Hardened

### 4.1. Original Version (`/Users/rafeshaikh/Downloads/G3_DabbaDash_Orders`)
**Command:**
```bash
TEST_TARGET=original pytest tests/test_api_security.py -v
```

**Output Summary:**
```text
============================= test session starts ==============================
collected 10 items

tests/test_api_security.py::test_sql_injection_login_blocked FAILED      [ 10%]
tests/test_api_security.py::test_order_bola_idor_blocked FAILED          [ 20%]
tests/test_api_security.py::test_mass_assignment_admin_role_blocked FAILED [ 30%]
tests/test_api_security.py::test_profile_property_level_data_exposure FAILED [ 40%]
tests/test_api_security.py::test_function_level_authorization_admin_users FAILED [ 50%]
tests/test_api_security.py::test_auth_missing_token_rejected PASSED      [ 60%]
tests/test_api_security.py::test_auth_forged_bearer_token_rejected FAILED [ 70%]
tests/test_api_security.py::test_rate_limiting_login_lockout FAILED      [ 80%]
tests/test_api_security.py::test_order_patch_mass_assignment_price_tampering FAILED [ 90%]
tests/test_api_security.py::test_password_policy_enforcement FAILED      [100%]

========================= 9 failed, 1 passed in 0.13s ==========================
```
*(Raw output saved in [`tests/test_output_original.txt`](file:///Users/rafeshaikh/Desktop/cybersecurity/AbhishekSir/G3_DabbaDash_Orders/tests/test_output_original.txt))*

---

### 4.2. Hardened Version (Current Workspace)
**Command:**
```bash
pytest tests/test_api_security.py -v
```

**Output Summary:**
```text
============================= test session starts ==============================
collected 10 items

tests/test_api_security.py::test_sql_injection_login_blocked PASSED      [ 10%]
tests/test_api_security.py::test_order_bola_idor_blocked PASSED          [ 20%]
tests/test_api_security.py::test_mass_assignment_admin_role_blocked PASSED [ 30%]
tests/test_api_security.py::test_profile_property_level_data_exposure PASSED [ 40%]
tests/test_api_security.py::test_function_level_authorization_admin_users PASSED [ 50%]
tests/test_api_security.py::test_auth_missing_token_rejected PASSED      [ 60%]
tests/test_api_security.py::test_auth_forged_bearer_token_rejected PASSED [ 70%]
tests/test_api_security.py::test_rate_limiting_login_lockout PASSED      [ 80%]
tests/test_api_security.py::test_order_patch_mass_assignment_price_tampering PASSED [ 90%]
tests/test_api_security.py::test_password_policy_enforcement PASSED      [100%]

============================== 10 passed in 0.48s ==============================
```
*(Raw output saved in [`tests/test_output_hardened.txt`](file:///Users/rafeshaikh/Desktop/cybersecurity/AbhishekSir/G3_DabbaDash_Orders/tests/test_output_hardened.txt))*

---

## 5. Side-by-Side Test Comparison Table

| Test Suite Item | Original Vulnerable Behavior | Hardened Secure Behavior | Original Result | Hardened Result |
|---|---|---|---|---|
| **1. SQL Injection Login** | Granted admin session on `admin' --` (200 OK) | Parameterized query blocks injection (401 Unauthorized) | **FAIL** | **PASS** |
| **2. BOLA / IDOR Orders** | Allowed Kabir to read Priya's address (200 OK) | Enforces ownership; unauthorized reads return 404 Not Found | **FAIL** | **PASS** |
| **3. Mass Assignment Admin** | Set `role = 'admin'` from JSON body (201 Created) | Role field ignored; forced to `customer` | **FAIL** | **PASS** |
| **4. Password Hash Exposure** | Returned raw MD5 hash in user profile JSON | Safe column projection; credentials omitted | **FAIL** | **PASS** |
| **5. BFLA Admin Users** | Dumped all users to normal customers (200 OK) | Enforced `role == 'admin'`, returning 403 Forbidden | **FAIL** | **PASS** |
| **6. Missing Token Check** | Blocked unauthenticated requests (401 Unauthorized) | Blocked unauthenticated requests (401 Unauthorized) | **PASS** | **PASS** |
| **7. Forged Bearer Token** | Accepted arbitrary forged Base64 string | Verifies HMAC-SHA256 signature; rejects altered tokens | **FAIL** | **PASS** |
| **8. Login Rate Limiting** | Allowed unlimited brute-force attacks | Triggers account lockout after 5 failures (429) | **FAIL** | **PASS** |
| **9. Price Tampering PATCH** | Allowed changing order total to ₹1 | Parameter whitelisting blocks price and status tampering | **FAIL** | **PASS** |
| **10. Password Policy** | Accepted weak 3-character passwords (`123`) | Enforces 8+ chars and blocks breached dictionary words | **FAIL** | **PASS** |

---

## 6. One Bug the Tests Found That Was Missed

### The Flaw: Mass Assignment on `PATCH /api/v1/orders/<id>` (Price Tampering)
- **What happened:** In the original application, the developer defined:
  ```python
  ORDER_COLUMNS = ["customer_id", "restaurant_id", "rider_id", "items", "total", "delivery_note", "status"]
  ```
  When updating an order with `PATCH`, the backend iterated over all keys matching `ORDER_COLUMNS`:
  ```python
  for key, value in data.items():
      if key in ORDER_COLUMNS:
          db.execute("UPDATE orders SET %s=? WHERE id=?" % key, (value, order_id))
  ```
- **The Impact:** A customer could place an order worth ₹460, and immediately send `PATCH /api/v1/orders/3` with `{"total": 1, "status": "Delivered"}`. The system would happily update the price to **₹1** in the database!
- **How the Test Caught It:** `test_order_patch_mass_assignment_price_tampering` attempted to patch an order with `{"total": 1}` and verified that the database total did not change. The original version failed immediately with `AssertionError: Price tampering succeeded! Order total updated to 1`.
- **The Remediation:** Implemented strict role-based parameter whitelisting in `app.py`. Customers are only permitted to update the `delivery_note` field, and only while the order is in `Placed` status. Price, items, and status cannot be modified via customer PATCH.

---

## 7. Deep Code Walkthrough of 2 Core Tests

### Test Walkthrough 1: SQL Injection Login (`test_sql_injection_login_blocked`)
```python
def test_sql_injection_login_blocked(client):
    """
    ATTACK: Send SQL injection payload `admin' --` to login endpoint.
    EXPECTED: 401 Unauthorized (must NOT grant admin session).
    """
    payload = {"username": "admin' --", "password": "arbitrary_password"}
    res = client.post("/api/v1/login", json=payload)

    # In hardened app: must be 401 Unauthorized
    # In original app: returns 200 OK with admin token (VULNERABLE)
    assert res.status_code == 401, f"SQL injection succeeded! Status: {res.status_code}, Body: {res.get_json()}"
    data = res.get_json() or {}
    assert data.get("ok") is not True, "SQL injection granted access!"
```
**Mechanism:**
1. The test sends a classic SQL injection payload `admin' --` in the `username` field with an arbitrary dummy password.
2. In the **original app**, the vulnerable query string concatenation:
   `"SELECT * FROM users WHERE username = 'admin' --' AND password = '...'"`
   evaluates the SQL comment (`--`), truncating the password check. SQLite logs the user in as `admin`, returning HTTP 200 and an admin bearer token. The assertion `assert res.status_code == 401` fails.
3. In the **hardened app**, the parameterized query:
   `db.execute("SELECT * FROM users WHERE username = ?", (username,))`
   treats `admin' --` as literal text. Because no user exists with the exact literal username `"admin' --"`, authentication fails with HTTP 401.

---

### Test Walkthrough 2: BOLA / IDOR on Orders (`test_order_bola_idor_blocked`)
```python
def test_order_bola_idor_blocked(client):
    """
    ATTACK: Customer Kabir (ID 3) requests Order #1 belonging to Priya (ID 2).
    EXPECTED: 404 Not Found (must NOT leak Priya's phone or address).
    """
    token = get_auth_token(client, "kabir", "Kabir@123")
    assert token is not None, "Failed to authenticate as kabir"

    headers = {"Authorization": f"Bearer {token}"}
    res = client.get("/api/v1/orders/1", headers=headers)

    # In hardened app: returns 404 Not Found
    # In original app: returns 200 OK with Priya's phone & address (VULNERABLE)
    assert res.status_code == 404, f"BOLA vulnerability present! Kabir can view Order #1 (status {res.status_code})"
    data = res.get_json() or {}
    assert "customer" not in data or data.get("customer") is None, "Customer PII was exposed to an unauthorized user!"
```
**Mechanism:**
1. The test logs in legitimately as `kabir` (customer ID 3) and extracts a valid bearer token.
2. It then sends an authenticated request to `GET /api/v1/orders/1`. Order #1 belongs to `priya` (customer ID 2).
3. In the **original app**, `api_order()` fetched the order strictly by primary key without checking if `order["customer_id"] == g.user["id"]`. It responded with HTTP 200 containing Priya's private address (`12, Saket Nagar, Indore`) and phone number (`9611111111`). The test failed.
4. In the **hardened app**, `api_order()` verifies that Kabir does not own the order, is not the assigned rider, and is not an administrator. It responds with **HTTP 404 Not Found**, concealing both the data and the existence of the order. The test passes.

---

## 8. Presentation Guide for Day 7 (10–15 Min Team Split)

| Team Member | Topic to Present | Key Talking Points |
|---|---|---|
| **Member 1** | **Role $\times$ Endpoint Matrix & Methodology** | Present the 10-endpoint $\times$ 5-role matrix. Explain the principle of least privilege: why public routes, customers, and operations staff should only access their designated endpoints. |
| **Member 2** | **BOLA & Mass Assignment Attacks** | Walk through `test_order_bola_idor_blocked` and `test_order_patch_mass_assignment_price_tampering`. Show how the original app allowed users to snoop on customer addresses and tamper with order prices. |
| **Member 3** | **Authentication & Cryptographic Token Attacks** | Walk through `test_sql_injection_login_blocked` and `test_auth_forged_bearer_token_rejected`. Explain why unsigned Base64 tokens are vulnerable and demonstrate HMAC-SHA256 signature verification. |
| **Member 4** | **BFLA & Data Exposure Attacks** | Walk through `test_function_level_authorization_admin_users` and `test_profile_property_level_data_exposure`. Explain why customer accounts must not access administrative user dumps and why password hashes must never be serialized in JSON. |
| **Member 5** | **Execution Evidence (Original vs Hardened)** | Show the live comparison: 9 tests failing on the original app (`9 failed, 1 passed`) versus 10 tests passing on the hardened app (`10 passed`). Highlight the 1 bug caught by the test suite (price tampering). |

---

## 9. How to Re-Run the Tests

```bash
# 1. Activate virtual environment
source venv/bin/activate

# 2. Run test suite against the Hardened App (100% Pass)
pytest tests/test_api_security.py -v

# 3. Run test suite against the Original Vulnerable App (90% Fail)
TEST_TARGET=original pytest tests/test_api_security.py -v
```
