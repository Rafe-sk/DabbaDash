"""
DabbaDash - Automated API Security Test Suite (Day 6)
======================================================
Course: ITM Secure Application Development
Mapping: OWASP API Security Top 10 (2023)

Usage:
  # Run against Hardened App:
  pytest tests/test_api_security.py -v

  # Run against Original App:
  TEST_TARGET=original pytest tests/test_api_security.py -v
"""
import base64
import importlib.util
import os
import pytest

ORIGINAL_APP_DIR = "/Users/rafeshaikh/Downloads/G3_DabbaDash_Orders"
HARDENED_APP_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def load_app_module(target):
    if target == "original":
        app_path = os.path.join(ORIGINAL_APP_DIR, "app.py")
        mod_name = "orig_app"
    else:
        app_path = os.path.join(HARDENED_APP_DIR, "app.py")
        mod_name = "hardened_app"

    spec = importlib.util.spec_from_file_location(mod_name, app_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.init_db()
    return module


@pytest.fixture(scope="module")
def app_instance():
    target = os.environ.get("TEST_TARGET", "hardened").lower()
    return load_app_module(target)


@pytest.fixture
def client(app_instance):
    return app_instance.app.test_client()


# Helper: obtain token for given credentials
def get_auth_token(client, username, password):
    res = client.post("/api/v1/login", json={"username": username, "password": password})
    if res.status_code == 200:
        return res.get_json().get("token")
    return None


# ==============================================================================
# TEST 1: SQL Injection in Login
# Mapping: OWASP API8:2023 - Security Misconfiguration / Injection
# ==============================================================================
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


# ==============================================================================
# TEST 2: Broken Object Level Authorization (BOLA / IDOR) on Orders
# Mapping: OWASP API1:2023 - Broken Object Level Authorization
# ==============================================================================
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


# ==============================================================================
# TEST 3: Mass Assignment / Privilege Escalation in Registration
# Mapping: OWASP API3:2023 - Broken Object Property Level Authorization
# ==============================================================================
def test_mass_assignment_admin_role_blocked(client, app_instance):
    """
    ATTACK: Register a new account supplying {"role": "admin"}.
    EXPECTED: Role must NOT be set to 'admin'; must default strictly to 'customer'.
    """
    import secrets
    test_user = f"attacker_{secrets.token_hex(4)}"
    payload = {
        "username": test_user,
        "password": "StrongPassword@123",
        "full_name": "Attacker Test",
        "role": "admin"
    }
    res = client.post("/api/v1/register", json=payload)
    assert res.status_code == 201, f"Registration failed: {res.get_data(as_text=True)}"

    with app_instance.app.app_context():
        db = app_instance.get_db()
        row = db.execute("SELECT role FROM users WHERE username=?", (test_user,)).fetchone()
        assert row is not None
        # In hardened app: role is strictly 'customer'
        # In original app: role becomes 'admin' (VULNERABLE)
        assert row["role"] != "admin", f"Mass assignment succeeded! User registered with elevated role: {row['role']}"
        assert row["role"] == "customer", f"Expected customer role, got {row['role']}"


# ==============================================================================
# TEST 4: Sensitive Data Exposure / Property-Level Authorization
# Mapping: OWASP API3:2023 - Broken Object Property Level Authorization
# ==============================================================================
def test_profile_property_level_data_exposure(client):
    """
    ATTACK: Query user profile endpoint GET /api/v1/users/<id>.
    EXPECTED: Response must NEVER contain password hash, mfa_secret, or credentials.
    """
    token = get_auth_token(client, "priya", "Priya@123")
    assert token is not None, "Failed to authenticate as priya"

    headers = {"Authorization": f"Bearer {token}"}
    res = client.get("/api/v1/users/2", headers=headers)
    assert res.status_code == 200, f"Profile fetch failed: {res.status_code}"

    data = res.get_json() or {}
    # In hardened app: password and secrets are omitted
    # In original app: leaks raw MD5 password hash (VULNERABLE)
    assert "password" not in data, f"Sensitive data exposure! Password hash exposed in API response: {data.get('password')}"
    assert "mfa_secret" not in data, "MFA secret leaked in API response!"


# ==============================================================================
# TEST 5: Broken Function Level Authorization (BFLA) on Admin User List
# Mapping: OWASP API5:2023 - Broken Function Level Authorization
# ==============================================================================
def test_function_level_authorization_admin_users(client):
    """
    ATTACK: Standard customer (Kabir) calls GET /api/v1/admin/users.
    EXPECTED: 403 Forbidden (administrative function must be restricted to admin).
    """
    token = get_auth_token(client, "kabir", "Kabir@123")
    assert token is not None, "Failed to authenticate as kabir"

    headers = {"Authorization": f"Bearer {token}"}
    res = client.get("/api/v1/admin/users", headers=headers)

    # In hardened app: returns 403 Forbidden
    # In original app: returns 200 OK with all user records (VULNERABLE)
    assert res.status_code == 403, f"BFLA vulnerability! Customer accessed admin user list: status {res.status_code}"


# ==============================================================================
# TEST 6: Broken Authentication - Missing Token
# Mapping: OWASP API2:2023 - Broken Authentication
# ==============================================================================
def test_auth_missing_token_rejected(client):
    """
    ATTACK: Access protected endpoint /api/v1/orders without Authorization header.
    EXPECTED: 401 Unauthorized.
    """
    res = client.get("/api/v1/orders")
    assert res.status_code == 401, f"Protected endpoint accessible without token! Status: {res.status_code}"


# ==============================================================================
# TEST 7: Broken Authentication - Forged / Tampered Bearer Token
# Mapping: OWASP API2:2023 - Broken Authentication
# ==============================================================================
def test_auth_forged_bearer_token_rejected(client):
    """
    ATTACK: Send forged/tampered bearer token (e.g. Base64 encoded '1:admin:admin').
    EXPECTED: 401 Unauthorized (must reject unsigned or altered tokens).
    """
    forged_token = base64.b64encode(b"1:admin:admin").decode()
    headers = {"Authorization": f"Bearer {forged_token}"}
    res = client.get("/api/v1/orders", headers=headers)

    # In hardened app: returns 401 Unauthorized (invalid HMAC signature)
    # In original app: returns 200 OK (VULNERABLE)
    assert res.status_code == 401, f"Forged token accepted! Status: {res.status_code}"


# ==============================================================================
# TEST 8: Unrestricted Resource Consumption / Login Brute-Force
# Mapping: OWASP API4:2023 - Unrestricted Resource Consumption
# ==============================================================================
def test_rate_limiting_login_lockout(client, app_instance):
    """
    ATTACK: Send 6 consecutive incorrect password attempts for user 'kabir'.
    EXPECTED: Account/IP lockout triggered (429 Too Many Requests or locked error).
    """
    import secrets
    target_user = f"brute_{secrets.token_hex(4)}"

    # Register test user
    client.post("/api/v1/register", json={
        "username": target_user,
        "password": "InitialPassword@123",
        "full_name": "Brute Target"
    })

    last_res = None
    for i in range(6):
        last_res = client.post("/api/v1/login", json={"username": target_user, "password": f"WrongPwd{i}"})

    # In hardened app: 6th attempt is locked out with 429
    # In original app: continues returning 401 without lockout (VULNERABLE)
    assert last_res.status_code == 429, f"No rate limiting or lockout! Status on 6th attempt: {last_res.status_code}"
    data = last_res.get_json() or {}
    assert "locked" in data.get("error", "").lower(), "Error message did not indicate lockout!"


# ==============================================================================
# TEST 9: Order PATCH Mass Assignment / Price Tampering
# Mapping: OWASP API3:2023 - Broken Object Property Level Authorization
# ==============================================================================
def test_order_patch_mass_assignment_price_tampering(client, app_instance):
    """
    ATTACK: Customer modifies order total to ₹1 via PATCH /api/v1/orders/<id>.
    EXPECTED: Total must NOT be updated.
    """
    token = get_auth_token(client, "priya", "Priya@123")
    assert token is not None, "Failed to authenticate as priya"

    headers = {"Authorization": f"Bearer {token}"}
    # Attempt to tamper with order #1 total
    patch_payload = {"total": 1, "status": "Delivered"}
    res = client.patch("/api/v1/orders/1", json=patch_payload, headers=headers)

    with app_instance.app.app_context():
        db = app_instance.get_db()
        order = db.execute("SELECT total FROM orders WHERE id=1").fetchone()
        # In hardened app: total remains ₹210
        # In original app: total becomes ₹1 (VULNERABLE)
        assert order["total"] != 1, f"Price tampering succeeded! Order total updated to {order['total']}"
        assert order["total"] == 210, f"Expected total 210, got {order['total']}"


# ==============================================================================
# TEST 10: Password Policy Enforcement (Weak / Breached Passwords)
# Mapping: OWASP API2:2023 - Broken Authentication
# ==============================================================================
def test_password_policy_enforcement(client):
    """
    ATTACK: Register user with weak/blocklisted password ('123' or 'password123').
    EXPECTED: 400 Bad Request with password policy error.
    """
    # Test short password
    res = client.post("/api/v1/register", json={
        "username": "weak_user_1",
        "password": "123",
        "full_name": "Weak User"
    })
    # In hardened app: returns 400 Bad Request
    # In original app: returns 201 Created (VULNERABLE)
    assert res.status_code == 400, f"Weak password accepted! Status: {res.status_code}"

    # Test dictionary blocklisted password
    res2 = client.post("/api/v1/register", json={
        "username": "weak_user_2",
        "password": "password123",
        "full_name": "Weak User 2"
    })
    assert res2.status_code == 400, f"Common breached password accepted! Status: {res2.status_code}"
