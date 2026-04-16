"""
Sample vulnerable application for testing SecureFlow.
Run:  python3 main.py test.py
"""
from flask import Flask, request
import hashlib
import pickle
import yaml
import os
import requests

app = Flask(__name__)

# ─── A02: Hardcoded secrets ─────────────────────────────────────────────────
password = "admin123"
api_key = "sk-secret-key-12345"

# ─── A01: Broken Access Control — route with DB but no auth ─────────────────
@app.route("/user/<int:uid>")
def get_user(uid):
    user = db.session.query(User).get(uid)
    return user.to_json()

# ─── A01: Secure route (should NOT be flagged) ─────────────────────────────
@app.route("/profile/<int:uid>")
@login_required
def get_profile(uid):
    user = db.session.query(User).get(uid)
    return user.to_json()

# ─── A02: Weak hash algorithm ──────────────────────────────────────────────
def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()

# ─── A03: SQL Injection ────────────────────────────────────────────────────
@app.route("/search")
def search():
    q = request.args.get("q")
    db.execute("SELECT * FROM items WHERE name = '" + q + "'")

# ─── A03: OS Command Injection ─────────────────────────────────────────────
@app.route("/ping")
def ping():
    host = request.args.get("host")
    os.system("ping " + host)

# ─── A04: Insecure Design — model without validation ───────────────────────
class UserModel:
    def __init__(self, name, email):
        self.name = name
        self.email = email

# ─── A05: Security Misconfiguration ────────────────────────────────────────
app.run(debug=True, host="0.0.0.0")

# ─── A07: Plaintext password comparison ────────────────────────────────────
def login(user_input):
    if user_input == "hardcoded_pass":
        return True

# ─── A08: Unsafe deserialization ───────────────────────────────────────────
def load_data(raw):
    return pickle.loads(raw)

def load_config(data):
    return yaml.load(data)

# ─── A09: Missing logging on sensitive operation ──────────────────────────
def authenticate(username, pw):
    return check_credentials(username, pw)

def transfer(from_acct, to_acct, amount):
    db.execute_transfer(from_acct, to_acct, amount)

# ─── A10: SSRF ─────────────────────────────────────────────────────────────
@app.route("/fetch")
def fetch_url():
    url = request.args.get("url")
    return requests.get(url).text
