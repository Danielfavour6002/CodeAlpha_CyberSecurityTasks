"""
CodeAlpha Task 3 - Target Codebase: User Management Service
VULNERABLE REFERENCE IMPLEMENTATION FOR SECURITY AUDIT
"""
import os
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

# FLAW 1: Hardcoded sensitive secret / API token
API_SECRET_KEY = "SUPER_SECRET_PRODUCTION_KEY_DO_NOT_LEAK_12345"

def get_db():
    conn = sqlite3.connect("users.db")
    return conn

@app.route("/api/login", methods=["POST"])
def login():
    """
    FLAW 2: SQL Injection (SQLi)
    User input concatenated directly into SQL statement.
    """
    username = request.json.get("username")
    password = request.json.get("password")

    conn = get_db()
    cursor = conn.cursor()
    
    # Vulnerable query construction:
    query = f"SELECT id, username FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    
    if user:
        return jsonify({"status": "success", "user": user[1]})
    return jsonify({"status": "failed", "message": "Invalid credentials"}), 401

@app.route("/api/ping", methods=["GET"])
def ping_host():
    """
    FLAW 3: Command Injection (CWE-78)
    Untrusted user parameter passed directly into shell execution.
    """
    host = request.args.get("host")
    # Vulnerable shell invocation:
    output = os.popen(f"ping -c 1 {host}").read()
    return jsonify({"output": output})

@app.route("/api/view_log", methods=["GET"])
def view_log():
    """
    FLAW 4: Directory / Path Traversal (CWE-22)
    Input filename read without sanitization or boundary checks.
    """
    filename = request.args.get("file")
    log_dir = "/var/log/app/"
    target_path = log_dir + filename
    
    # Vulnerable file open:
    with open(target_path, "r") as f:
        content = f.read()
    return jsonify({"file_content": content})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
