"""
INTENTIONALLY VULNERABLE — for security gate demonstration only.
DO NOT deploy. DO NOT use any pattern shown here in production code.

Purpose: copy this file into app/ on the vuln-demo branch and open a PR
to main. The security pipeline will block the merge with findings from
Gitleaks (hardcoded credential) and CodeQL (injection vulnerabilities).

Each vulnerability is labelled with the CWE it maps to and the gate
that catches it.
"""

import os
import sqlite3
import subprocess

# ── GITLEAKS will flag this (CWE-798: Use of Hard-coded Credentials) ─────────
# Gitleaks pattern: generic-api-key / flask-secret-key
INTERNAL_API_KEY = "sk-prod-4xQr9mK2vL8nPz3wYb7cHj1tFe6uDs0A"  # noqa: S105
DATABASE_PASSWORD = "super_secret_db_password_123"               # noqa: S105


# ── CODEQL will flag this: SQL Injection (CWE-89) ────────────────────────────
# CodeQL rule: py/sql-injection
# Data flow: `username` (HTTP input) → string-formatted SQL query → execute()
def get_user_vulnerable(conn: sqlite3.Connection, username: str):
    # VULNERABLE: f-string injects unsanitised input directly into the query.
    # An attacker can pass username="' OR '1'='1" to dump the entire table.
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return conn.execute(query).fetchall()


# Secure equivalent — parameterised query, no injection possible:
def get_user_secure(conn: sqlite3.Connection, username: str):
    return conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchall()


# ── CODEQL will flag this: OS Command Injection (CWE-78) ─────────────────────
# CodeQL rule: py/command-line-injection
# Data flow: `host` (HTTP input) → shell=True subprocess → OS
def ping_host_vulnerable(host: str) -> str:
    # VULNERABLE: user-controlled `host` is interpolated into a shell command.
    # An attacker can pass host="8.8.8.8; cat /etc/passwd" to run arbitrary commands.
    result = subprocess.run(
        f"ping -c 1 {host}", shell=True, capture_output=True, text=True  # noqa: S602
    )
    return result.stdout


# Secure equivalent — pass args as a list, shell=False:
def ping_host_secure(host: str) -> str:
    result = subprocess.run(
        ["ping", "-c", "1", host], shell=False, capture_output=True, text=True  # noqa: S603
    )
    return result.stdout


# ── CODEQL will flag this: Path Traversal (CWE-22) ───────────────────────────
# CodeQL rule: py/path-injection
# Data flow: `filename` (HTTP input) → os.path.join → open()
def read_report_vulnerable(filename: str) -> str:
    # VULNERABLE: `filename` is not validated against a safe base directory.
    # An attacker can pass filename="../../etc/passwd" to read arbitrary files.
    path = os.path.join("/var/reports", filename)
    with open(path) as f:
        return f.read()


# Secure equivalent — resolve and assert the path stays inside the base dir:
def read_report_secure(filename: str) -> str:
    base = "/var/reports"
    path = os.path.realpath(os.path.join(base, filename))
    if not path.startswith(os.path.realpath(base) + os.sep):
        raise ValueError("Path traversal attempt detected")
    with open(path) as f:
        return f.read()


# ── ZAP will flag this at runtime: missing security headers ──────────────────
# The DAST gate catches issues that are invisible to static analysis.
# This Flask app returns responses with no Content-Security-Policy,
# no X-Frame-Options, and no X-Content-Type-Options — FAIL-level in zap-rules.tsv.
# The secure version in app/app.py adds all headers via @after_request.
