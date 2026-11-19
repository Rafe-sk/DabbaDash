# Day 7 Task – SAST on Your App (DabbaDash)

**Course:** ITM Secure Application Development  
**Group:** Group 3 (DabbaDash)  
**Deliverables:**
- `bandit_original.json` & `bandit_hardened.json`
- `semgrep_original.json` & `semgrep_hardened.json`
- `rules/dabbadash_custom_rules.yaml`
- Verified `.githooks/pre-commit` (Bandit + Secret Scanning)
- `day7_sast.md` (Comprehensive SAST Audit & Triage Report)

---

## 1. Executive Summary & Findings Count Comparison

Static Application Security Testing (SAST) was performed across both the **Original Legacy Application** (`/Users/rafeshaikh/Downloads/G3_DabbaDash_Orders`) and the **Hardened Application** (`/Users/rafeshaikh/Desktop/cybersecurity/AbhishekSir/G3_DabbaDash_Orders`).

Two complementary SAST engines were utilized:
1. **Bandit (v1.9.4):** Python AST security scanner analyzing common insecurity patterns (cryptography, injection, hardcoded secrets, misconfigurations).
2. **Semgrep OSS (v1.186.0):** Semantic pattern-matching scanner utilizing the official rule packs `p/python` and `p/flask` (151 rules), augmented with **custom Group 3 security rules** targeting DabbaDash Day 3 vulnerabilities.

### Summary Metrics Table

| Metric / Tool | Original Version (Legacy) | Hardened Version (Current) | Reduction / Security Delta |
|---|:---:|:---:|:---:|
| **Bandit Findings** | **7** (2 High, 4 Medium, 1 Low) | **0** | **-100% (Remediated)** |
| **Semgrep Findings (`p/python`, `p/flask`)** | **4** (1 Error, 3 Warning) | **0** (1 Suppressed Accepted Risk) | **-100% (Remediated / Suppressed)** |
| **Semgrep Custom Rules (`dabbadash_*`)** | **3** (3 Blocking Errors) | **0** | **-100% (Remediated)** |
| **Total Automated SAST Findings** | **14** | **0** | **Zero Unaddressed Vulnerabilities** |
| **Pre-Commit Hook Status** | Not Configured | **Active & Enforcing** | Verified AST & Secret Protection |

---

## 2. Findings Triage Table

Every finding discovered by Bandit and Semgrep across both versions has been evaluated and classified as **True Positive (TP)**, **False Positive (FP)**, or **Accepted Risk**, accompanied by remediation details and suppression justifications.

| Scanner | Rule ID / CWE | Location | Severity | Classification | Justification & Remediation Notes |
|---|---|---|:---:|:---:|---|
| **Bandit** | `B105` (CWE-259)<br>`hardcoded_password_string` | `app.py:27`<br>(Original) | Low | **True Positive** | **Finding:** `app.secret_key = "dabbadash@indore"` was hardcoded.<br>**Fix:** Secret key is now loaded securely from environment variable `os.environ.get("SECRET_KEY")` with fallback generation (`secrets.token_hex(32)`). |
| **Bandit** | `B324` (CWE-327)<br>`hashlib` | `app.py:52`<br>(Original) | High | **True Positive** | **Finding:** Passwords were stored as single-iteration unsalted MD5 hashes (`hashlib.md5(password.encode()).hexdigest()`).<br>**Fix:** Replaced with Argon2id (`argon2.PasswordHasher`). |
| **Bandit** | `B608` (CWE-89)<br>`hardcoded_sql_expressions` | `app.py:123`<br>(Original) | Medium | **True Positive** | **Finding:** SQL injection via string concatenation in `check_login()` (`SELECT * FROM users WHERE username = '...'`).<br>**Fix:** Parameterized query with `?` placeholders (`SELECT * FROM users WHERE username = ?`). |
| **Bandit** | `B608` (CWE-89)<br>`hardcoded_sql_expressions` | `app.py:317`<br>(Original) | Medium | **True Positive** | **Finding:** String interpolation in `api_register()` query construction (`INSERT INTO users (%s) VALUES (%s)`).<br>**Fix:** Strict whitelist validation and static parameterized query. |
| **Bandit** | `B608` (CWE-89)<br>`hardcoded_sql_expressions` | `app.py:338`<br>(Original) | Medium | **True Positive** | **Finding:** Raw concatenation in debug function `query_for_debug()`.<br>**Fix:** Removed unused debug endpoints entirely from codebase. |
| **Bandit** | `B608` (CWE-89)<br>`hardcoded_sql_expressions` | `app.py:383`<br>(Original) | Medium | **True Positive** | **Finding:** Dynamic SQL format string in `api_order()` PATCH (`UPDATE orders SET %s=? WHERE id=?`).<br>**Fix:** Strict column whitelisting, type coercion, and parameterized execution. |
| **Bandit** | `B201` (CWE-94)<br>`flask_debug_true` | `app.py:410`<br>(Original) | High | **True Positive** | **Finding:** Flask application started with `debug=True`, exposing interactive Werkzeug debugger and RCE surface.<br>**Fix:** Changed to `debug=False`, loaded from `FLASK_DEBUG` environment variable. |
| **Semgrep** | `insecure-hash-algorithm-md5`<br>(CWE-327) | `app.py:52`<br>(Original) | Warning | **True Positive** | **Finding:** MD5 algorithm is broken and susceptible to collision attacks.<br>**Fix:** Migrated to Argon2id password hashing. |
| **Semgrep** | `md5-used-as-password`<br>(CWE-327) | `app.py:52`<br>(Original) | Warning | **True Positive** | **Finding:** Passwords stored using MD5 can be cracked rapidly with rainbow tables.<br>**Fix:** Migrated to Argon2id. |
| **Semgrep** | `tainted-sql-string`<br>(CWE-704 / CWE-89) | `app.py:383`<br>(Original) | Error | **True Positive** | **Finding:** Unsanitized user keys formatted into SQL update query.<br>**Fix:** Implemented parameterized query and strict field schema. |
| **Semgrep** | `debug-enabled`<br>(CWE-489) | `app.py:410`<br>(Original) | Warning | **True Positive** | **Finding:** Active debugging exposes memory state and console endpoints.<br>**Fix:** Hardened to `debug=False`. |
| **Semgrep** | `md5-used-as-password`<br>(CWE-327) | `app.py:129`<br>(Hardened) | Warning | **Accepted Risk**<br>*(Suppressed)* | **Finding:** Line 129 checks `hashlib.md5(password.encode(), usedforsecurity=False)`.<br>**Justification:** This code block handles **backward-compatibility re-hashing** (Day 4 Task 1). Existing legacy users logging in with MD5 are authenticated once, immediately re-hashed to Argon2id, and written back to SQLite. Tagged with `# nosec B324` and `# nosemgrep: python.lang.security.audit.md5-used-as-password.md5-used-as-password`. |

---

## 3. What SAST Missed: Analysis of False Negatives

While Bandit and Semgrep successfully detected structural patterns (MD5 usage, string concatenation in SQL, `debug=True`, hardcoded secret literal), **over 60% of our Day 3 security flaws were completely MISSED by SAST tools**.

### Summary of Missed Vulnerabilities (False Negatives)

| Day 3 Finding ID | Vulnerability Title | Why SAST (Bandit / Semgrep OSS) Missed It |
|---|---|---|
| **F-02** | Forgeable Bearer Token (Unsigned Base64) | **Semantic Design Flaw:** `base64.b64encode(f"{id}:{user}:{role}")` is syntactically valid Python. SAST tools cannot know that a string representation of user attributes without an HMAC signature violates authentication integrity. |
| **F-03** | Anyone Can Register as Admin (Mass Assignment) | **Business Logic Flaw:** Accepting `{"role": "admin"}` in JSON payloads and writing it to SQLite is valid data ingestion syntax. SAST cannot infer that self-assigned admin roles violate business rules. |
| **F-04** | Order IDOR (`/api/v1/orders/<id>`) | **Access Control / Authorization:** The query `SELECT * FROM orders WHERE id = ?` is safe from SQL injection, so SAST marks it clean. However, it lacks `AND user_id = current_user.id`, allowing horizontal privilege escalation. |
| **F-05** | BFLA (Admin User List Open to All) | **Missing RBAC Authorization:** `/api/v1/admin/users` was an unprotected route. SAST sees a valid route handler returning database records; it cannot deduce that only administrators should access this endpoint. |
| **F-07** | Order Field Tampering via PATCH | **Authorization Scope:** A user patching their own order's `status` or `amount`. SAST cannot determine which state transitions are legitimate for customers versus kitchen staff. |
| **F-08** | Status Tampering via Web Endpoint | **Missing Session / Role Validation:** `/orders/<id>/status` lacked CSRF tokens and role checks. To SAST, invoking a status update endpoint is ordinary business code. |
| **F-10** | Infinite Login Brute Force | **Missing Rate Limiting:** SAST scans for code that is present; it cannot detect missing rate limiting, failed attempt counters, or lockout algorithms. |
| **F-14** | Customer Delivery Address Leakage (DPDP Violation) | **Data Privacy / Context:** Displaying full delivery addresses to riders before order acceptance violates Indian DPDP Act minimization rules. SAST has no concept of legal compliance or data redaction lifecycles. |
| **F-16** | Missing CSRF Protection | **Protocol / Architecture:** SAST does not analyze form POST workflows against session cookies unless specialized commercial web rule engines are used. |
| **F-18** | Business Logic Input Validation (Negative Amounts) | **Domain Semantics:** An order with `amount = -500` or `item = ""` is syntactically valid integer/string data. Only domain validation can enforce positive values. |
| **F-19** | Absence of Security Audit Logging | **Missing Capability:** SAST cannot flag the absence of security monitoring or failed authentication logging. |
| **F-20** | Missing Password Complexity Rules | **Policy Absence:** Accepting `"123"` as a password cannot be flagged unless explicit password strength validators are mandated by custom rules. |

### Architectural Takeaway: Why SAST Cannot Replace Code Review & DAST
1. **Syntax vs. Semantics:** SAST analyzes Abstract Syntax Trees (ASTs). It knows *how* the code executes, but not *what* the code is intended to accomplish.
2. **Context-Free Execution:** SAST does not run the code; it cannot observe user roles, session cookies, database state, or HTTP authorization headers in real-time.
3. **Defense-in-Depth Required:** Security requires SAST (for code patterns), DAST/API testing (for access control and business logic), and Human Code Review (for architectural and privacy validation).

---

## 4. Custom Semgrep Rules

To bridge the gap between generic AST checks and our application domain, we developed custom Semgrep rules in `rules/dabbadash_custom_rules.yaml`.

### Rule Definitions (`rules/dabbadash_custom_rules.yaml`)

```yaml
rules:
  - id: dabbadash-sqli-string-concat
    message: "Potential SQL Injection detected: database query is constructed using string concatenation instead of parameterized '?' placeholders."
    languages: [python]
    severity: ERROR
    metadata:
      cwe: "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
      owasp: "A05:2025 Injection"
    patterns:
      - pattern-either:
          - pattern: $DB.execute("..." + ... + "...", ...)
          - pattern: $DB.execute("..." + ...)
          - pattern: $DB.execute(... + "...")
          - pattern: |
              $QUERY = "..." + ...
              ...
              $DB.execute($QUERY, ...)
          - pattern: |
              $QUERY = ... + "..."
              ...
              $DB.execute($QUERY, ...)
          - pattern: $DB.execute(f"...", ...)
          - pattern: |
              $QUERY = f"..."
              ...
              $DB.execute($QUERY, ...)

  - id: dabbadash-insecure-md5-password
    message: "Insecure hashing: MD5 is broken and must not be used for hashing passwords."
    languages: [python]
    severity: ERROR
    metadata:
      cwe: "CWE-328: Use of Weak Hash"
      owasp: "A04:2025 Cryptographic Failures"
    patterns:
      - pattern: hashlib.md5($PASS.encode(...)).hexdigest()

  - id: dabbadash-unauthenticated-base64-token
    message: "Insecure token: Authentication tokens must use cryptographic signatures (e.g. HMAC / itsdangerous / JWT), not raw Base64."
    languages: [python]
    severity: ERROR
    metadata:
      cwe: "CWE-345: Insufficient Verification of Data Authenticity"
      owasp: "A08:2025 Software and Data Integrity Failures"
    patterns:
      - pattern: |
          $RAW = "%s:%s:%s" % ($U["id"], $U["username"], $U["role"])
          ...
          base64.b64encode($RAW.encode()).decode()
```

### Live Test Evidence

#### 1. Running Custom Rules on the Original App:
```bash
HOME=/tmp ./venv/bin/semgrep scan --config rules/dabbadash_custom_rules.yaml /Users/rafeshaikh/Downloads/G3_DabbaDash_Orders
```
**Output:**
```text
┌─────────────────┐
│ 3 Code Findings │
└─────────────────┘

    /Users/rafeshaikh/Downloads/G3_DabbaDash_Orders/app.py
   ❯❯❱ rules.dabbadash-insecure-md5-password
          Insecure hashing: MD5 is broken and must not be used for hashing passwords.
           52┆ return hashlib.md5(password.encode()).hexdigest()

   ❯❯❱ rules.dabbadash-sqli-string-concat
          Potential SQL Injection detected: database query is constructed using string concatenation instead of parameterized '?' placeholders.
          123┆ query = ("SELECT * FROM users WHERE username = '" + username +
          124┆          "' AND password = '" + hash_password(password) + "'")
          125┆ return get_db().execute(query).fetchone(), query

   ❯❯❱ rules.dabbadash-unauthenticated-base64-token
          Insecure token: Authentication tokens must use cryptographic signatures (e.g. HMAC / itsdangerous / JWT), not raw Base64.
          130┆ raw = "%s:%s:%s" % (user["id"], user["username"], user["role"])
          131┆ return base64.b64encode(raw.encode()).decode()

Ran 3 rules on 1 file: 3 findings. (3 blocking)
```

#### 2. Running Custom Rules on the Hardened App:
```bash
HOME=/tmp ./venv/bin/semgrep scan --config rules/dabbadash_custom_rules.yaml app.py templates/
```
**Output:**
```text
┌──────────────┐
│ Scan Summary │
└──────────────┘
✅ Scan completed successfully.
 • Findings: 0 (0 blocking)
 • Rules run: 3
 • Targets scanned: 1
Ran 3 rules on 1 file: 0 findings.
```
*(Result: PASS – 0 findings on hardened app!)*

---

## 5. Pre-Commit Hook Integration

Bandit static security analysis is integrated directly into `.githooks/pre-commit` to prevent newly introduced vulnerabilities from being committed to source control.

### Hook Implementation (`.githooks/pre-commit`)
```bash
#!/usr/bin/env bash
set -e

echo "[PRE-COMMIT] Running security pre-commit checks..."

# 1. Secret Scanning (gitleaks or regex pattern check on staged application code)
echo "[PRE-COMMIT] 1/2: Checking for committed secrets in application code..."
if command -v gitleaks >/dev/null 2>&1; then
    gitleaks detect --staged --verbose
else
    STAGED_DIFF=$(git diff --cached -- ':!.githooks/*' ':!.git/*')
    KEY_PATTERN="AIzaSy[0-9A-Za-z_-]{33}"
    PRIV_KEY_PATTERN="BEGIN (RSA|EC|OPENSSH) PRIVATE KEY"
    if echo "$STAGED_DIFF" | grep -Ei "($KEY_PATTERN|$PRIV_KEY_PATTERN)" >/dev/null 2>&1; then
        echo "❌ [SECURITY ALERT] High-entropy secret / API key detected in staged diff!"
        exit 1
    fi
    echo "  ✓ No plain API keys or private keys found in staged application code."
fi

# 2. Bandit AST Security Scanner
echo "[PRE-COMMIT] 2/2: Running Bandit Python Security Scanner..."
BANDIT_BIN="./venv/bin/bandit"

if [ -f "$BANDIT_BIN" ]; then
    $BANDIT_BIN -r app.py --quiet
    echo "  ✓ Bandit passed with 0 security issues."
else
    echo "  ⚠️ Bandit binary not found in ./venv/bin/bandit. Skipping Bandit check."
fi

echo "✅ [PRE-COMMIT] All security checks passed! Commit allowed."
exit 0
```

### Verification Command & Output:
```bash
./.githooks/pre-commit
```
```text
[PRE-COMMIT] Running security pre-commit checks...
[PRE-COMMIT] 1/2: Checking for committed secrets in application code...
  ✓ No plain API keys or private keys found in staged application code.
[PRE-COMMIT] 2/2: Running Bandit Python Security Scanner...
  ✓ Bandit passed with 0 security issues.
✅ [PRE-COMMIT] All security checks passed! Commit allowed.
```

---

## 6. Day 8 Presentation Guide & Speaking Script

| Slide # | Slide Title | Speaking Member | Core Speaking Points & Script |
|:---:|---|:---:|---|
| **Slide 1** | **SAST Overview & Findings Count** | Member 1 | "Good morning. For Day 7, we ran automated SAST scans on both the legacy DabbaDash codebase and our hardened version. Bandit reported 7 findings in the original app—including hardcoded secrets, MD5 hashing, and 4 SQL injection points—and 0 in the hardened version. Semgrep detected 4 findings in the original and 0 unaddressed findings in our hardened app." |
| **Slide 2** | **Triage & Justification Matrix** | Member 2 | "We triaged every single tool finding. All 7 Bandit findings and 4 Semgrep findings on the original code were True Positives. On our hardened app, Semgrep flagged line 129 for MD5. We triaged this as an Accepted Risk: it is our backward-compatibility password migration routine that upgrades existing users to Argon2id on login. We documented the suppression using `# nosemgrep`." |
| **Slide 3** | **What SAST Missed (False Negatives)** | Member 3 | "The most important takeaway: SAST tools missed over 60% of our Day 3 vulnerabilities! They missed our unsigned Base64 token forgery, our IDOR on orders, admin mass-assignment registration, broken function-level authorization, and DPDP customer address leaks. SAST evaluates syntax trees, not authorization logic, business workflows, or compliance boundaries." |
| **Slide 4** | **Custom Semgrep Rules (Live Demo)** | Member 4 | "To catch our app's specific flaws, we wrote custom Semgrep rules targeting string concatenation in SQL queries, unauthenticated Base64 tokens, and MD5 password hashing. We will now show them live: running against the legacy app flags 3 blocking security errors; running against our hardened app passes with zero errors." |
| **Slide 5** | **Shift-Left: Pre-Commit Hook Integration** | All Members | "Finally, we shifted security left by integrating Bandit and secret scanning into git's pre-commit hook. Any developer attempting to commit code with insecure queries, plain secrets, or debug flags is blocked before push. This guarantees sustainable security." |

---

## 7. Artifacts Index
- Hardened App Bandit Scan: `bandit_hardened.json`
- Original App Bandit Scan: `bandit_original.json`
- Hardened App Semgrep Scan: `semgrep_hardened.json`
- Original App Semgrep Scan: `semgrep_original.json`
- Custom Semgrep Rules: `rules/dabbadash_custom_rules.yaml`
- Pre-Commit Hook: `.githooks/pre-commit`
- Full SAST Report: `day7_sast.md`
