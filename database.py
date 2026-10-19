"""SQLite storage layer.

Every query uses parameterized statements ("?" placeholders) - string
concatenation is never used to build SQL, which prevents SQL injection.
"""
import os
import sqlite3
from pathlib import Path

import bcrypt
from flask import g

BCRYPT_ROUNDS = 12


def _db_path() -> Path:
    return Path(
        os.environ.get("DATABASE_PATH")
        or (Path(__file__).resolve().parent / "app.db")
    )


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(_db_path())
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_exc=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    """Create tables and seed demo users (passwords bcrypt-hashed)."""
    conn = sqlite3.connect(_db_path())
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at    TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS notes (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL REFERENCES users(id),
            content    TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        """
    )
    # Seed demo users. Passwords are stored ONLY as bcrypt hashes.
    seeds = [("admin", "Admin#2024!"), ("alice", "Alice@Pass123")]
    for username, password in seeds:
        row = conn.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        if row is None:
            password_hash = bcrypt.hashpw(
                password.encode("utf-8"), bcrypt.gensalt(BCRYPT_ROUNDS)
            ).decode("utf-8")
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash),
            )
    conn.commit()
    conn.close()
