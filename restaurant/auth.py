"""Register / Login module (separate from the main app). Role based access."""
import hashlib
import hmac
import os
import re
import secrets
import time
from functools import wraps

from flask import Blueprint, g, redirect, render_template, request, session, url_for

import logger
import storage
from storage import AppError

ROLES = ("admin", "cashier", "kitchen", "customer")
STAFF = ("admin", "cashier", "kitchen")
HOME = {"admin": "/admin", "cashier": "/pos", "kitchen": "/kitchen", "customer": "/"}
USERNAME_RE = r"[A-Za-z0-9_]{3,20}"
PHONE_RE = r"\+?[0-9\-]{8,15}"

bp = Blueprint("auth", __name__)
_hits = {}


# ---------- password hashing (scrypt, standard library) ----------
def hash_password(password):
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1)
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_password(password, stored):
    try:
        _, salt, digest = stored.split("$")
        new = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2 ** 14, r=8, p=1)
        return hmac.compare_digest(new.hex(), digest)
    except (ValueError, AttributeError):
        return False


DUMMY_HASH = hash_password("dummy-password-1")


def check_password_policy(password):
    if not isinstance(password, str) or not 8 <= len(password) <= 100:
        raise AppError("รหัสผ่านต้องยาว 8-100 ตัวอักษร")
    if not (re.search(r"[A-Za-z]", password) and re.search(r"[0-9]", password)):
        raise AppError("รหัสผ่านต้องมีทั้งตัวอักษรและตัวเลข")


def find_user(db, username):
    name = str(username).strip().lower()
    return next((u for u in db["users"] if u["username"].lower() == name), None)


# ---------- rate limiting (in memory) ----------
def client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    return forwarded or request.remote_addr or "?"


def is_blocked(key, limit, window):
    now = time.time()
    if len(_hits) > 5000:
        _hits.clear()
    hits = [t for t in _hits.get(key, []) if now - t < window]
    _hits[key] = hits
    return len(hits) >= limit


def record_hit(key):
    _hits.setdefault(key, []).append(time.time())


def rate_limit(key, limit, window):
    if is_blocked(key, limit, window):
        raise AppError("ส่งคำขอถี่เกินไป กรุณารอสักครู่", 429)
    record_hit(key)


# ---------- current user + role decorator ----------
@bp.before_app_request
def load_user():
    g.user = None
    if request.endpoint == "static":
        return
    uid = session.get("uid")
    if uid:
        user = next((u for u in storage.load()["users"] if u["id"] == uid), None)
        session_version = session.get("session_version", 0)
        if user and user["active"] and session_version == user.get("session_version", 0):
            g.user = user
        else:
            session.clear()


def role_required(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if g.user is None:
                if request.path.startswith("/api/"):
                    raise AppError("กรุณาเข้าสู่ระบบ", 401)
                return redirect(url_for("auth.login"))
            if g.user["role"] not in roles:
                raise AppError("คุณไม่มีสิทธิ์เข้าถึงส่วนนี้", 403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def start_session(user):
    session.clear()
    session["uid"] = user["id"]
    session["session_version"] = user.get("session_version", 0)
    session["csrf"] = secrets.token_hex(16)
    session.permanent = True


# ---------- routes ----------
@bp.route("/login", methods=("GET", "POST"))
def login():
    if request.method == "GET":
        return render_template("login.html")
    username = str(request.form.get("username", "")).strip()
    password = str(request.form.get("password", ""))
    key = f"login:{client_ip()}:{username.lower()}"
    if is_blocked(key, 5, 300):
        return render_template("login.html", error="ลองผิดหลายครั้ง กรุณารอ 5 นาที"), 429
    user = find_user(storage.load(), username)
    valid = verify_password(password, user["password_hash"] if user else DUMMY_HASH)
    if not (user and valid and user["active"]):
        record_hit(key)
        logger.log_action(username or "-", "login_failed", "auth", "", client_ip())
        return render_template("login.html", error="ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง"), 400
    _hits.pop(key, None)
    start_session(user)
    logger.log_action(user["username"], "login", "auth")
    return redirect(HOME[user["role"]])


@bp.route("/register", methods=("GET", "POST"))
def register():
    if request.method == "GET":
        return render_template("register.html")
    form = request.form
    try:
        username = str(form.get("username", "")).strip()
        name = str(form.get("name", "")).strip()
        phone = str(form.get("phone", "")).strip()
        password = str(form.get("password", ""))
        if not re.fullmatch(USERNAME_RE, username):
            raise AppError("ชื่อผู้ใช้ต้องเป็น a-z, 0-9, _ ยาว 3-20 ตัว")
        if not 1 <= len(name) <= 50:
            raise AppError("กรุณากรอกชื่อ (ไม่เกิน 50 ตัวอักษร)")
        if phone and not re.fullmatch(PHONE_RE, phone):
            raise AppError("เบอร์โทรไม่ถูกต้อง")
        check_password_policy(password)
        if password != form.get("confirm", ""):
            raise AppError("รหัสผ่านยืนยันไม่ตรงกัน")
        rate_limit(f"register:{client_ip()}", 5, 600)
        with storage.transaction() as db:
            if find_user(db, username):
                raise AppError("ชื่อผู้ใช้นี้ถูกใช้แล้ว")
            user = {"id": storage.next_id(db, "users"), "username": username, "name": name,
                    "phone": phone, "role": "customer", "active": True, "points": 0,
                    "session_version": 0,
                    "password_hash": hash_password(password)}
            db["users"].append(user)
    except AppError as e:
        return render_template("register.html", error=e.message), e.status
    logger.log_action(username, "register", "users", user["id"])
    start_session(user)
    return redirect("/")


@bp.post("/logout")
def logout():
    if g.user:
        logger.log_action(g.user["username"], "logout", "auth")
    session.clear()
    return redirect("/")
