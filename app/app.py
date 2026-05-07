"""
Secure Flask REST API — sample target application for CI/CD security scanning.
Demonstrates: parameterized queries, PBKDF2 password hashing, security headers,
rate limiting, and input validation.
"""

import hashlib
import os
import secrets
import sqlite3

from flask import Flask, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

DATABASE = os.environ.get("DATABASE_PATH", "/tmp/app.db")


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                owner_id INTEGER,
                FOREIGN KEY (owner_id) REFERENCES users(id)
            );
        """)


@app.after_request
def add_security_headers(response):
    # Suppress Werkzeug version disclosure (ZAP rule 10036)
    response.headers["Server"] = "secure-api"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # base-uri, form-action, frame-ancestors have no default-src fallback (ZAP rule 10055)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
    )
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy", "version": "1.0.0"})


@app.route("/api/users", methods=["POST"])
@limiter.limit("10 per minute")
def create_user():
    data = request.get_json(silent=True)
    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "username and password required"}), 400

    username = str(data["username"]).strip()
    if not (3 <= len(username) <= 50) or not username.isalnum():
        return jsonify({"error": "username must be 3-50 alphanumeric characters"}), 400

    password = str(data["password"])
    if len(password) < 8:
        return jsonify({"error": "password must be at least 8 characters"}), 400

    salt = secrets.token_hex(32)
    pw_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 260_000
    ).hex()
    stored = f"{salt}:{pw_hash}"

    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, stored),
            )
        return jsonify({"message": "user created"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "username already exists"}), 409


@app.route("/api/items", methods=["GET"])
@limiter.limit("60 per minute")
def list_items():
    with get_db() as conn:
        rows = conn.execute("SELECT id, name, description FROM items").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/items/<int:item_id>", methods=["GET"])
@limiter.limit("60 per minute")
def get_item(item_id: int):
    with get_db() as conn:
        row = conn.execute(
            "SELECT id, name, description FROM items WHERE id = ?", (item_id,)
        ).fetchone()
    if row is None:
        return jsonify({"error": "item not found"}), 404
    return jsonify(dict(row))


@app.route("/api/items", methods=["POST"])
@limiter.limit("20 per minute")
def create_item():
    data = request.get_json(silent=True)
    if not data or "name" not in data:
        return jsonify({"error": "name required"}), 400

    name = str(data["name"])[:255].strip()
    if not name:
        return jsonify({"error": "name must not be empty"}), 400

    description = str(data.get("description", ""))[:1000]

    with get_db() as conn:
        cursor = conn.execute(
            "INSERT INTO items (name, description) VALUES (?, ?)",
            (name, description),
        )
        item_id = cursor.lastrowid

    return jsonify({"id": item_id, "message": "item created"}), 201


@app.route("/api/items/<int:item_id>", methods=["DELETE"])
@limiter.limit("10 per minute")
def delete_item(item_id: int):
    with get_db() as conn:
        cursor = conn.execute("DELETE FROM items WHERE id = ?", (item_id,))
        if cursor.rowcount == 0:
            return jsonify({"error": "item not found"}), 404
    return jsonify({"message": "item deleted"})


# Runs under both Gunicorn (imported as a module) and direct python app.py
init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
