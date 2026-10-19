"""Security test suite: authentication, SQLi resistance, XSS escaping,
JWT enforcement on protected endpoints."""
import os
import sqlite3

import bcrypt

XSS_PAYLOAD = "<script>alert('xss')</script>"
SQLI_PAYLOAD = "' OR 1=1 --"


def login(client, username, password):
    return client.post(
        "/auth/login", json={"username": username, "password": password}
    )


def auth_header(client, username="admin", password="Admin#2024!"):
    resp = login(client, username, password)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    return {"Authorization": "Bearer " + resp.get_json()["token"]}


# ---------------------------------------------------------------- auth ---

def test_login_success_returns_jwt(client):
    resp = login(client, "admin", "Admin#2024!")
    assert resp.status_code == 200
    assert resp.get_json()["token"]


def test_login_wrong_password_rejected(client):
    assert login(client, "admin", "wrong-password").status_code == 401


def test_login_unknown_user_same_generic_error(client):
    """No user enumeration: identical error for unknown user / wrong password."""
    a = login(client, "nosuchuser", "x")
    b = login(client, "admin", "wrong")
    assert a.status_code == b.status_code == 401
    assert a.get_json() == b.get_json()


def test_login_missing_fields_rejected(client):
    assert client.post("/auth/login", json={}).status_code == 400


# ----------------------------------------------------------------- SQLi ---

def test_sqli_payload_in_username_rejected(client):
    for payload in (SQLI_PAYLOAD, "admin'--", "' OR '1'='1"):
        assert login(client, payload, "x").status_code == 401, payload


def test_sqli_payload_in_password_rejected(client):
    assert login(client, "admin", SQLI_PAYLOAD).status_code == 401


def test_sqli_does_not_leak_users(client):
    """' OR 1=1 -- must NOT return a token (would be full bypass)."""
    resp = login(client, SQLI_PAYLOAD, SQLI_PAYLOAD)
    assert resp.status_code == 401
    assert "token" not in resp.get_json()


# ---------------------------------------------------- JWT enforcement ---

def test_data_without_token_denied(client):
    assert client.get("/api/data").status_code == 401


def test_data_with_garbage_token_denied(client):
    resp = client.get(
        "/api/data", headers={"Authorization": "Bearer garbage.token.here"}
    )
    assert resp.status_code == 401


def test_data_with_valid_token_ok(client):
    resp = client.get("/api/data", headers=auth_header(client))
    assert resp.status_code == 200
    assert isinstance(resp.get_json()["users"], list)


# --------------------------------------------------- password storage ---

def test_passwords_stored_as_bcrypt_hashes_only(client):
    conn = sqlite3.connect(os.environ["DATABASE_PATH"])
    rows = conn.execute("SELECT password_hash FROM users").fetchall()
    conn.close()
    assert rows
    for (password_hash,) in rows:
        assert password_hash.startswith("$2"), "plaintext password found!"
        assert "Admin#2024!" not in password_hash


# -------------------------------------------------------------- notes ---

def test_note_endpoints_require_auth(client):
    assert client.post("/api/notes", json={"content": "hi"}).status_code == 401
    assert client.get("/api/notes").status_code == 401


def test_note_created_and_xss_escaped(client):
    headers = auth_header(client)
    resp = client.post("/api/notes", json={"content": XSS_PAYLOAD}, headers=headers)
    assert resp.status_code == 201
    listing = client.get("/api/notes", headers=headers)
    assert listing.status_code == 200
    content = listing.get_json()["notes"][-1]["content"]
    assert "<script>" not in content
    assert "&lt;script&gt;" in content


def test_username_escaped_in_data_response(client):
    """A malicious username must come back escaped."""
    conn = sqlite3.connect(os.environ["DATABASE_PATH"])
    conn.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (
            "evil<img src=x onerror=alert(1)>",
            bcrypt.hashpw(b"x", bcrypt.gensalt(4)).decode("utf-8"),
        ),
    )
    conn.commit()
    conn.close()
    resp = client.get("/api/data", headers=auth_header(client))
    usernames = [u["username"] for u in resp.get_json()["users"]]
    joined = "".join(usernames)
    assert "<img" not in joined
    assert "&lt;img" in joined
