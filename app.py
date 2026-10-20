# Secure REST API - HDU Information Security Lab, Work 1
#
# Security measures implemented:
#  1. SQL injection  -> parameterized queries only (SQLite "?" placeholders)
#  2. XSS            -> all user-controlled data is HTML-escaped in responses
#  3. Broken auth    -> bcrypt password hashing + JWT (HS256) with expiry,
#                       enforced by the @token_required decorator
import html
import os
from datetime import datetime, timedelta, timezone
from functools import wraps

import bcrypt
import jwt
from flask import Flask, g, jsonify, render_template, request

from database import get_db, init_db, close_db

JWT_SECRET = os.environ.get("JWT_SECRET", "dev-only-secret-change-me")
JWT_ALGORITHM = "HS256"
JWT_EXPIRES_MINUTES = 30
BCRYPT_ROUNDS = 12

MAX_USERNAME_LEN = 64
MAX_PASSWORD_LEN = 128
MAX_NOTE_LEN = 1000


def token_required(view):
    """Verify the Bearer JWT before letting the request reach the endpoint."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing or malformed Authorization header"}), 401
        token = auth[7:].strip()
        try:
            claims = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        g.current_user_id = int(claims["sub"])
        g.current_username = claims["username"]
        return view(*args, **kwargs)

    return wrapped


def create_app() -> Flask:
    app = Flask(__name__)
    app.teardown_appcontext(close_db)
    init_db()

    # ------------------------------------------------------------------ #
    # GET / - tiny web UI for manual testing (calls the API with fetch)
    # ------------------------------------------------------------------ #
    @app.get("/")
    def index():
        return render_template("index.html")

    # ------------------------------------------------------------------ #
    # POST /auth/login - issue a JWT after verifying bcrypt password hash
    # ------------------------------------------------------------------ #
    @app.post("/auth/login")
    def login():
        payload = request.get_json(silent=True) or {}
        username = str(payload.get("username", "")).strip()
        password = str(payload.get("password", ""))

        if not username or not password:
            return jsonify({"error": "Missing username or password"}), 400
        if len(username) > MAX_USERNAME_LEN or len(password) > MAX_PASSWORD_LEN:
            # same generic message as an authentication failure
            return jsonify({"error": "Invalid credentials"}), 401

        db = get_db()
        # SQLi protection: parameterized query - input is never concatenated
        row = db.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        # Same generic error for unknown user and wrong password
        # (prevents user enumeration).
        if row is None or not bcrypt.checkpw(
            password.encode("utf-8"), row["password_hash"].encode("utf-8")
        ):
            return jsonify({"error": "Invalid credentials"}), 401

        now = datetime.now(timezone.utc)
        token = jwt.encode(
            {
                "sub": str(row["id"]),
                "username": row["username"],
                "iat": now,
                "exp": now + timedelta(minutes=JWT_EXPIRES_MINUTES),
            },
            JWT_SECRET,
            algorithm=JWT_ALGORITHM,
        )
        return jsonify({"token": token, "expires_in_minutes": JWT_EXPIRES_MINUTES}), 200

    # ------------------------------------------------------------------ #
    # GET /api/data - protected data endpoint (list of users)
    # ------------------------------------------------------------------ #
    @app.get("/api/data")
    @token_required
    def get_data():
        db = get_db()
        rows = db.execute(
            "SELECT id, username, created_at FROM users ORDER BY id"
        ).fetchall()
        # XSS protection: user-controlled fields are escaped on output.
        users = [
            {
                "id": row["id"],
                "username": html.escape(row["username"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]
        return jsonify({"users": users}), 200

    # ------------------------------------------------------------------ #
    # POST /api/notes - the third endpoint (of my own choice):
    # create a note; protected by JWT
    # ------------------------------------------------------------------ #
    @app.post("/api/notes")
    @token_required
    def create_note():
        payload = request.get_json(silent=True) or {}
        content = str(payload.get("content", "")).strip()
        if not content:
            return jsonify({"error": "Note content is required"}), 400
        if len(content) > MAX_NOTE_LEN:
            return jsonify({"error": "Note content too long"}), 400

        db = get_db()
        # SQLi protection: parameterized INSERT.
        cur = db.execute(
            "INSERT INTO notes (user_id, content) VALUES (?, ?)",
            (g.current_user_id, content),
        )
        db.commit()
        return jsonify({"id": cur.lastrowid, "message": "Note created"}), 201

    # ------------------------------------------------------------------ #
    # GET /api/notes - read notes back; content is escaped (XSS demo)
    # ------------------------------------------------------------------ #
    @app.get("/api/notes")
    @token_required
    def list_notes():
        db = get_db()
        rows = db.execute(
            "SELECT id, user_id, content, created_at FROM notes ORDER BY id"
        ).fetchall()
        notes = [
            {
                "id": row["id"],
                "user_id": row["user_id"],
                "content": html.escape(row["content"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]
        return jsonify({"notes": notes}), 200

    @app.errorhandler(404)
    def not_found(_error):
        return jsonify({"error": "Not found"}), 404

    return app


if __name__ == "__main__":
    # Debug is disabled on purpose; run with a real WSGI server in production.
    create_app().run(host="127.0.0.1", port=5000, debug=False)
