"""
CodeAlpha Task 3 - Remediated Target: User Management Service
SECURE IMPLEMENTATION WITH DEFENSE-IN-DEPTH CONTROLS
"""
import os
import sqlite3
import subprocess
import ipaddress
from pathlib import Path
from flask import Flask, request, jsonify

app = Flask(__name__)

# FIX 1: Secrets managed via environment variables (never hardcoded)
API_SECRET_KEY = os.environ.get("API_SECRET_KEY")
if not API_SECRET_KEY:
    raise RuntimeError("CRITICAL: API_SECRET_KEY environment variable is not set!")

BASE_LOG_DIR = Path("/var/log/app/").resolve()

def get_db():
    conn = sqlite3.connect("users.db")
    return conn

@app.route("/api/login", methods=["POST"])
def login():
    """
    FIX 2: Parameterized Queries (Prepared Statements)
    Prevents SQL injection by treating input strictly as data, not executable code.
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"status": "error", "message": "Missing credentials"}), 400

    conn = get_db()
    cursor = conn.cursor()

    # Safe: Input bound via placeholders (?)
    cursor.execute(
        "SELECT id, username FROM users WHERE username = ? AND password = ?",
        (username, password)
    )
    user = cursor.fetchone()

    if user:
        return jsonify({"status": "success", "user": user[1]})
    return jsonify({"status": "failed", "message": "Invalid credentials"}), 401

@app.route("/api/ping", methods=["GET"])
def ping_host():
    """
    FIX 3: Strict Input Validation & Subprocess Array Execution
    Enforces IP-only input and executes without a shell wrapper.
    """
    host = request.args.get("host", "").strip()

    # Step A: Validate that host is strictly an IPv4 or IPv6 address
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return jsonify({"status": "error", "message": "Invalid IP address provided."}), 400

    # Step B: Run ping safely using a parameter list without shell=True
    try:
        proc = subprocess.run(
            ["ping", "-c", "1", "-W", "2", host],
            capture_output=True,
            text=True,
            timeout=5,
            check=False
        )
        return jsonify({"output": proc.stdout})
    except subprocess.TimeoutExpired:
        return jsonify({"status": "error", "message": "Ping request timed out."}), 504

@app.route("/api/view_log", methods=["GET"])
def view_log():
    """
    FIX 4: Path Normalization and Canonical Directory Boundary Enforcement
    Mitigates Path Traversal (CWE-22) attacks.
    """
    filename = request.args.get("file", "")
    if not filename:
        return jsonify({"status": "error", "message": "Filename parameter required"}), 400

    # Resolve safe canonical path
    safe_path = (BASE_LOG_DIR / filename).resolve()

    # Ensure the resolved path remains inside BASE_LOG_DIR
    if not safe_path.is_relative_to(BASE_LOG_DIR):
        return jsonify({"status": "error", "message": "Access denied: Unauthorized directory access"}), 403

    if not safe_path.is_file():
        return jsonify({"status": "error", "message": "File not found"}), 404

    try:
        with open(safe_path, "r", encoding="utf-8") as f:
            content = f.read(4096)  # Prevent denial of service via memory exhaustion
        return jsonify({"file_content": content})
    except Exception as e:
        return jsonify({"status": "error", "message": "Error reading file"}), 500

if __name__ == "__main__":
    # FIX 5: Disable debug mode in production
    app.run(host="127.0.0.1", port=5000, debug=False)
