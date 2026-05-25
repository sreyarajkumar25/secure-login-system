#!/usr/bin/env python3
"""
Secure Login System
- bcrypt password hashing
- Parameterized SQL (SQL injection protection)
- Session management with logout
- Optional TOTP 2FA
"""

import io
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from typing import Optional

import bcrypt
import pyotp
import qrcode
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

APP_DIR = Path(__file__).parent
DB_PATH = APP_DIR / "users.db"
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=2)

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,32}$")
EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                totp_secret TEXT,
                totp_enabled INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                ip_address TEXT,
                success INTEGER NOT NULL,
                attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def validate_username(username: str) -> Optional[str]:
    if not username or not USERNAME_RE.match(username):
        return "Username must be 3-32 characters (letters, numbers, underscore)."
    return None


def validate_email(email: str) -> Optional[str]:
    if not email or not EMAIL_RE.match(email):
        return "Please enter a valid email address."
    return None


def validate_password(password: str) -> Optional[str]:
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if not re.search(r"[A-Z]", password):
        return "Password must contain an uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must contain a lowercase letter."
    if not re.search(r"\d", password):
        return "Password must contain a number."
    return None


def log_attempt(username: str, success: bool) -> None:
    ip = request.remote_addr or "unknown"
    with get_db() as conn:
        conn.execute(
            "INSERT INTO login_attempts (username, ip_address, success) VALUES (?, ?, ?)",
            (username, ip, int(success)),
        )


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        for check in (validate_username(username), validate_email(email), validate_password(password)):
            if check:
                flash(check, "danger")
                return render_template("register.html")

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")

        try:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                    (username, email, hash_password(password)),
                )
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username or email already exists.", "danger")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        totp_code = request.form.get("totp_code", "").strip()

        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,),
            ).fetchone()

        if not user or not verify_password(password, user["password_hash"]):
            log_attempt(username, False)
            flash("Invalid username or password.", "danger")
            return render_template("login.html")

        if user["totp_enabled"]:
            if not totp_code:
                session["pending_2fa_user_id"] = user["id"]
                flash("Enter your 2FA code from your authenticator app.", "info")
                return render_template("login.html", show_2fa=True)

            totp = pyotp.TOTP(user["totp_secret"])
            if not totp.verify(totp_code, valid_window=1):
                log_attempt(username, False)
                flash("Invalid 2FA code.", "danger")
                return render_template("login.html", show_2fa=True)

        session.permanent = True
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["login_time"] = datetime.now(timezone.utc).isoformat()
        session.pop("pending_2fa_user_id", None)
        log_attempt(username, True)
        flash(f"Welcome back, {user['username']}!", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    with get_db() as conn:
        user = conn.execute(
            "SELECT username, email, totp_enabled, created_at FROM users WHERE id = ?",
            (session["user_id"],),
        ).fetchone()
    return render_template("dashboard.html", user=user)


@app.route("/setup-2fa", methods=["GET", "POST"])
@login_required
def setup_2fa():
    with get_db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE id = ?",
            (session["user_id"],),
        ).fetchone()

    if request.method == "POST":
        code = request.form.get("totp_code", "").strip()
        secret = session.get("pending_totp_secret")
        if not secret:
            flash("2FA setup session expired. Please try again.", "warning")
            return redirect(url_for("setup_2fa"))

        totp = pyotp.TOTP(secret)
        if totp.verify(code, valid_window=1):
            with get_db() as conn:
                conn.execute(
                    "UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?",
                    (secret, session["user_id"]),
                )
            session.pop("pending_totp_secret", None)
            flash("Two-factor authentication enabled!", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid code. Please try again.", "danger")

    secret = user["totp_secret"] or pyotp.random_base32()
    session["pending_totp_secret"] = secret
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=user["email"], issuer_name="SecureLoginApp")

    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    import base64
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return render_template(
        "setup_2fa.html",
        secret=secret,
        qr_code=qr_b64,
        already_enabled=bool(user["totp_enabled"]),
    )


@app.route("/disable-2fa", methods=["POST"])
@login_required
def disable_2fa():
    password = request.form.get("password", "")
    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()

    if not verify_password(password, user["password_hash"]):
        flash("Incorrect password.", "danger")
        return redirect(url_for("setup_2fa"))

    with get_db() as conn:
        conn.execute(
            "UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?",
            (session["user_id"],),
        )
    flash("Two-factor authentication disabled.", "info")
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    init_db()
    print("\n  Secure Login System")
    print("  Open http://127.0.0.1:5000 in your browser\n")
    app.run(debug=True, host="127.0.0.1", port=5000)
