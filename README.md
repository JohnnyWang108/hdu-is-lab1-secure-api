# Secure REST API — HDU Information Security Lab, Work 1

A small, deliberately hardened REST API built for the lab
*"Secure REST API Development with CI/CD and Real CVE Vulnerability Analysis"*.

- **Stack:** Python 3.13 + Flask + SQLite
- **Security tooling:** Bandit (SAST), pip-audit (SCA) in a GitHub Actions CI/CD pipeline
- **CVE part:** [CVE-2018-1000656](https://nvd.nist.gov/vuln/detail/CVE-2018-1000656)
  reproduced with Vulhub, root cause analyzed and fixed (see [CVE section](#cve-analysis-cve-2018-1000656)).

## 1. Project description

The API demonstrates the full security lifecycle from the lab:

1. a protected **data endpoint** that requires authentication;
2. **basic security measures** against the OWASP Top 10 items
   A03:2021 (Injection) and A07:2021 (Identification and Authentication
   Failures), plus XSS output escaping;
3. a **CI/CD pipeline** that runs tests and security scanners on every push;
4. a **real CVE** reproduced in a Docker/Vulhub environment and fixed.

## 2. API endpoints

| Method | Endpoint       | Auth | Description |
|--------|----------------|------|-------------|
| POST   | `/auth/login`  | no   | Authenticate and receive a JWT |
| GET    | `/api/data`    | JWT  | List of users (protected) |
| POST   | `/api/notes`   | JWT  | Create a note (the third endpoint, chosen by me) |
| GET    | `/api/notes`   | JWT  | List notes (content is HTML-escaped) |

### How to call them

```bash
# 1. Login -> returns a JWT
curl -X POST http://127.0.0.1:5000/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": "Admin#2024!"}'
# {"token": "<JWT>", "expires_in_minutes": 30}

# 2. Protected data endpoint (needs the token)
curl http://127.0.0.1:5000/api/data -H "Authorization: Bearer <JWT>"

# 3. Third endpoint: create a note
curl -X POST http://127.0.0.1:5000/api/notes \
     -H "Authorization: Bearer <JWT>" -H "Content-Type: application/json" \
     -d '{"content": "hello <b>world</b>"}'

# 4. List notes (content is escaped)
curl http://127.0.0.1:5000/api/notes -H "Authorization: Bearer <JWT>"
```

Seed users: `admin / Admin#2024!` and `alice / Alice@Pass123`.

**Error behavior:** missing/garbage token → `401`; wrong password or unknown
user → `401` with the *same* generic body (no user enumeration).

## 3. Implemented security measures

### 3.1 SQL injection (A03:2021)

All SQL is built with **parameterized queries** (SQLite `?` placeholders).
User input is never concatenated into SQL strings.

```python
row = db.execute(
    "SELECT id, username, password_hash FROM users WHERE username = ?",
    (username,),
).fetchone()
```

Payloads such as `' OR 1=1 --` are treated as ordinary (non-matching)
usernames and are rejected with `401`. See `tests/test_api.py`.

### 3.2 XSS

Every user-controlled value returned by the API (usernames in `/api/data`,
note content in `/api/notes`) is escaped with `html.escape()` before it is
serialized, so a stored payload like
`<script>alert('xss')</script>` comes back as
`&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;` and cannot execute in a
browser that renders the response.

### 3.3 Broken authentication (A07:2021)

- **JWT (HS256)** issued on successful login, with `iat`/`exp` claims and a
  30-minute lifetime; the secret comes from the `JWT_SECRET` environment
  variable (never hard-coded in production).
- **Middleware** (`@token_required`) verifies the token on every protected
  endpoint and rejects missing/expired/forged tokens with `401`.
- **Passwords are never stored in plaintext** — they are hashed with
  **bcrypt** (12 rounds, salted) at registration/seed time and verified with
  `bcrypt.checkpw()`.
- Generic "Invalid credentials" responses prevent user enumeration, and
  input length limits reduce abuse surface.

## 4. CI/CD pipeline (GitHub Actions)

`.github/workflows/ci.yml` runs on **every push and pull request**:

| Job | Tool | What it does |
|-----|------|--------------|
| `test` | pytest | 14 security/functional tests |
| `sast-bandit` | [Bandit](https://github.com/PyCQA/bandit) | static analysis of our code; fails on HIGH-severity findings, report uploaded as artifact |
| `sca-pip-audit` | [pip-audit](https://github.com/pypa/pip-audit) | scans dependencies against known CVEs; fails if any vulnerable dependency is found, report uploaded as artifact |

**Latest pipeline run:** <link to Actions run — filled after push>

**Screenshots of the reports (from the Actions tab):**

<!-- CI SCREENSHOTS PLACEHOLDER -->

## 5. Running locally

```bash
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt -r requirements-dev.txt   # Windows
$env:JWT_SECRET="your-secret"
.venv\Scripts\python app.py            # http://127.0.0.1:5000
.venv\Scripts\pytest -v                # run the test suite
```

## 6. CVE analysis: CVE-2018-1000656

<!-- CVE SECTION PLACEHOLDER — filled after Vulhub reproduction -->

## 7. Repository links

- Repository: <link>
- Latest CI run: <link>
