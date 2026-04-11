"""
User Manager
─────────────
Multi-user system with:
  • Role-based access (admin, analyst, viewer)
  • Bcrypt password hashing
  • TOTP MFA (Google Authenticator / Authy compatible)
  • Session tokens
  • Login rate limiting (lockout after N failed attempts)
  • Audit log
  • Admin-only user creation/removal
"""

import json
import hashlib
import hmac
import os
import time
import base64
import struct
import datetime
import threading
import secrets
from pathlib import Path
from typing import Optional


USERS_FILE    = Path("config/users.json")
SESSIONS_FILE = Path("config/web_sessions.json")
AUDIT_FILE    = Path("config/audit.log")

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS     = 300   # 5 minutes
SESSION_TTL_HOURS   = 24


# ── Password hashing (SHA-256 based, no bcrypt dependency) ─────────
def _hash_password(password: str, salt: str = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(32)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
    return base64.b64encode(h).decode(), salt

def _verify_password(password: str, stored_hash: str, salt: str) -> bool:
    h, _ = _hash_password(password, salt)
    return hmac.compare_digest(h, stored_hash)


# ── TOTP (RFC 6238) ────────────────────────────────────────────────
def _totp_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode()

def _hotp(secret: str, counter: int) -> str:
    key = base64.b32decode(secret.upper())
    msg = struct.pack(">Q", counter)
    h   = hmac.new(key, msg, "sha1").digest()
    offset = h[-1] & 0x0F
    code   = struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF
    return str(code % 1_000_000).zfill(6)

def _totp(secret: str) -> str:
    return _hotp(secret, int(time.time()) // 30)

def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    """Accept codes from window steps before/after current."""
    t = int(time.time()) // 30
    for delta in range(-window, window + 1):
        if hmac.compare_digest(_hotp(secret, t + delta), str(code).strip()):
            return True
    return False

def totp_uri(secret: str, username: str, issuer: str = "VAPT-Framework") -> str:
    return (f"otpauth://totp/{issuer}:{username}"
            f"?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30")


class UserManager:

    ROLES = ("admin", "analyst", "viewer")

    def __init__(self, log=None):
        self.log   = log
        self._lock = threading.Lock()
        self.users    = {}   # username → user dict
        self.sessions = {}   # token → {username, expires}
        self._load()
        self._ensure_default_admin()

    # ── Persistence ───────────────────────────────────────────────
    def _load(self):
        if USERS_FILE.exists():
            try:
                self.users = json.loads(USERS_FILE.read_text())
            except Exception:
                pass
        if SESSIONS_FILE.exists():
            try:
                self.sessions = json.loads(SESSIONS_FILE.read_text())
                # Remove expired
                now = time.time()
                self.sessions = {
                    k: v for k, v in self.sessions.items()
                    if v.get("expires", 0) > now
                }
            except Exception:
                pass

    def _save_users(self):
        USERS_FILE.parent.mkdir(exist_ok=True)
        USERS_FILE.write_text(json.dumps(self.users, indent=2))

    def _save_sessions(self):
        SESSIONS_FILE.parent.mkdir(exist_ok=True)
        SESSIONS_FILE.write_text(json.dumps(self.sessions, indent=2))

    def _ensure_default_admin(self):
        """Create default admin if no users exist."""
        if not self.users:
            self.create_user("admin", "admin123", "admin", created_by="system")
            if self.log:
                self.log.warning(
                    "Default admin created: admin / admin123 — CHANGE THIS IMMEDIATELY")

    # ── User CRUD ─────────────────────────────────────────────────
    def create_user(self, username: str, password: str, role: str = "analyst",
                    created_by: str = "admin") -> dict:
        username = username.lower().strip()
        if not username or len(username) < 3:
            raise ValueError("Username must be at least 3 characters")
        if username in self.users:
            raise ValueError(f"User '{username}' already exists")
        if role not in self.ROLES:
            raise ValueError(f"Invalid role. Choose: {self.ROLES}")
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")

        pw_hash, salt = _hash_password(password)
        user = {
            "username":        username,
            "password_hash":   pw_hash,
            "salt":            salt,
            "role":            role,
            "mfa_enabled":     False,
            "mfa_secret":      None,
            "created_at":      datetime.datetime.now().isoformat(),
            "created_by":      created_by,
            "last_login":      None,
            "failed_attempts": 0,
            "locked_until":    None,
            "active":          True,
        }
        with self._lock:
            self.users[username] = user
            self._save_users()
        self._audit(f"User created: {username} (role={role}) by {created_by}")
        return self._safe_user(user)

    def remove_user(self, username: str, by: str = "admin") -> bool:
        username = username.lower()
        if username == "admin":
            raise ValueError("Cannot remove the admin account")
        with self._lock:
            if username not in self.users:
                return False
            del self.users[username]
            # Revoke all sessions
            self.sessions = {k: v for k, v in self.sessions.items()
                             if v.get("username") != username}
            self._save_users()
            self._save_sessions()
        self._audit(f"User removed: {username} by {by}")
        return True

    def update_user(self, username: str, by: str = "admin", **kwargs) -> dict:
        username = username.lower()
        user = self.users.get(username)
        if not user:
            raise ValueError("User not found")
        if "password" in kwargs:
            pw_hash, salt = _hash_password(kwargs.pop("password"))
            user["password_hash"] = pw_hash
            user["salt"]          = salt
        if "role" in kwargs:
            role = kwargs.pop("role")
            if role not in self.ROLES:
                raise ValueError(f"Invalid role: {role}")
            user["role"] = role
        if "active" in kwargs:
            user["active"] = bool(kwargs.pop("active"))
        with self._lock:
            self._save_users()
        self._audit(f"User updated: {username} by {by}")
        return self._safe_user(user)

    def list_users(self) -> list:
        return [self._safe_user(u) for u in self.users.values()]

    # ── Authentication ─────────────────────────────────────────────
    def authenticate(self, username: str, password: str,
                     totp_code: str = None, ip: str = "") -> Optional[str]:
        """
        Returns session token on success, raises ValueError on failure.
        """
        username = username.lower().strip()
        user = self.users.get(username)

        if not user or not user.get("active"):
            self._audit(f"Login failed: {username} (not found) from {ip}")
            raise ValueError("Invalid credentials")

        # Lockout check
        locked_until = user.get("locked_until")
        if locked_until and time.time() < locked_until:
            remaining = int(locked_until - time.time())
            raise ValueError(f"Account locked. Try again in {remaining}s")

        # Password check
        if not _verify_password(password, user["password_hash"], user["salt"]):
            user["failed_attempts"] = user.get("failed_attempts", 0) + 1
            if user["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
                user["locked_until"] = time.time() + LOCKOUT_SECONDS
                self._save_users()
                self._audit(f"Account locked: {username} after {MAX_FAILED_ATTEMPTS} failures from {ip}")
                raise ValueError(f"Too many failed attempts. Account locked for {LOCKOUT_SECONDS}s")
            self._save_users()
            self._audit(f"Login failed: {username} (wrong password) from {ip}")
            raise ValueError("Invalid credentials")

        # MFA check
        if user.get("mfa_enabled"):
            if not totp_code:
                raise ValueError("MFA_REQUIRED")
            if not verify_totp(user["mfa_secret"], totp_code):
                self._audit(f"MFA failed: {username} from {ip}")
                raise ValueError("Invalid MFA code")

        # Success — reset failed attempts
        user["failed_attempts"] = 0
        user["locked_until"]    = None
        user["last_login"]      = datetime.datetime.now().isoformat()
        self._save_users()

        # Create session token
        token = secrets.token_urlsafe(48)
        expires = time.time() + SESSION_TTL_HOURS * 3600
        with self._lock:
            self.sessions[token] = {
                "username": username,
                "role":     user["role"],
                "expires":  expires,
                "ip":       ip,
                "created":  datetime.datetime.now().isoformat(),
            }
            self._save_sessions()

        self._audit(f"Login success: {username} (role={user['role']}) from {ip}")
        return token

    def verify_session(self, token: str) -> Optional[dict]:
        """Returns session dict if valid, else None."""
        if not token:
            return None
        s = self.sessions.get(token)
        if not s:
            return None
        if s.get("expires", 0) < time.time():
            with self._lock:
                self.sessions.pop(token, None)
                self._save_sessions()
            return None
        return s

    def logout(self, token: str):
        with self._lock:
            username = self.sessions.get(token, {}).get("username","?")
            self.sessions.pop(token, None)
            self._save_sessions()
        self._audit(f"Logout: {username}")

    # ── MFA management ─────────────────────────────────────────────
    def setup_mfa(self, username: str) -> dict:
        """Generate MFA secret. User must verify before enabling."""
        username = username.lower()
        user     = self.users.get(username)
        if not user:
            raise ValueError("User not found")
        secret = _totp_secret()
        user["mfa_pending_secret"] = secret
        self._save_users()
        return {
            "secret":  secret,
            "uri":     totp_uri(secret, username),
            "backup":  [secrets.token_hex(8) for _ in range(8)],
        }

    def enable_mfa(self, username: str, totp_code: str) -> bool:
        """Verify code from pending setup, then enable MFA."""
        username = username.lower()
        user     = self.users.get(username)
        if not user:
            raise ValueError("User not found")
        secret = user.get("mfa_pending_secret")
        if not secret:
            raise ValueError("No pending MFA setup. Call setup_mfa first.")
        if not verify_totp(secret, totp_code):
            raise ValueError("Invalid MFA code")
        user["mfa_secret"]         = secret
        user["mfa_enabled"]        = True
        user["mfa_pending_secret"] = None
        self._save_users()
        self._audit(f"MFA enabled: {username}")
        return True

    def disable_mfa(self, username: str, by: str = None) -> bool:
        username = username.lower()
        user     = self.users.get(username)
        if not user:
            raise ValueError("User not found")
        user["mfa_enabled"] = False
        user["mfa_secret"]  = None
        self._save_users()
        self._audit(f"MFA disabled: {username} by {by or username}")
        return True

    # ── Audit log ─────────────────────────────────────────────────
    def _audit(self, msg: str):
        ts   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] {msg}\n"
        try:
            AUDIT_FILE.parent.mkdir(exist_ok=True)
            with open(AUDIT_FILE, "a") as f:
                f.write(line)
        except Exception:
            pass
        if self.log:
            self.log.info(f"[AUDIT] {msg}")

    def get_audit_log(self, lines: int = 100) -> list:
        if not AUDIT_FILE.exists():
            return []
        try:
            all_lines = AUDIT_FILE.read_text().splitlines()
            return all_lines[-lines:]
        except Exception:
            return []

    # ── Helpers ───────────────────────────────────────────────────
    def _safe_user(self, user: dict) -> dict:
        """Return user dict without sensitive fields."""
        return {
            k: v for k, v in user.items()
            if k not in ("password_hash", "salt", "mfa_secret", "mfa_pending_secret")
        }

    def get_user(self, username: str) -> Optional[dict]:
        u = self.users.get(username.lower())
        return self._safe_user(u) if u else None


# Singleton
_instance: Optional[UserManager] = None
def get_user_manager(log=None) -> UserManager:
    global _instance
    if _instance is None:
        _instance = UserManager(log)
    return _instance
