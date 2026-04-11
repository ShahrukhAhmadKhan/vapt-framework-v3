"""
Session Manager
───────────────
Stores and manages authenticated sessions for scanning:
  • Basic auth (username / password)
  • Form-based login (POST to login URL, capture cookies)
  • Cookie injection (paste raw cookies)
  • Custom header injection (API tokens, Bearer tokens)
  • Session re-use across scan modules
"""

import json
import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar
import ssl
from pathlib import Path
from typing import Optional

SESSION_FILE = Path("config/sessions.json")


class SessionManager:

    def __init__(self, log=None):
        self.log      = log
        self.sessions = {}
        self._load()

    # ── Persistence ───────────────────────────────────────────────
    def _load(self):
        if SESSION_FILE.exists():
            try:
                self.sessions = json.loads(SESSION_FILE.read_text())
            except Exception:
                pass

    def _save(self):
        SESSION_FILE.parent.mkdir(exist_ok=True)
        SESSION_FILE.write_text(json.dumps(self.sessions, indent=2))

    # ── Add sessions ───────────────────────────────────────────────
    def add_basic_auth(self, name: str, username: str, password: str, target: str = "") -> dict:
        s = {
            "name": name, "type": "basic",
            "username": username, "password": password,
            "target": target, "status": "ready",
        }
        self.sessions[name] = s
        self._save()
        if self.log:
            self.log.success(f"Session '{name}' saved (basic auth)")
        return s

    def add_cookie_session(self, name: str, cookies: str, target: str = "") -> dict:
        s = {
            "name": name, "type": "cookie",
            "cookies": cookies, "target": target, "status": "ready",
        }
        self.sessions[name] = s
        self._save()
        return s

    def add_token_session(self, name: str, token: str, header: str = "Authorization",
                          prefix: str = "Bearer", target: str = "") -> dict:
        s = {
            "name": name, "type": "token",
            "token": token, "header": header, "prefix": prefix,
            "target": target, "status": "ready",
        }
        self.sessions[name] = s
        self._save()
        return s

    def add_form_login(self, name: str, login_url: str,
                       username_field: str, password_field: str,
                       username: str, password: str,
                       extra_fields: dict = None, target: str = "") -> dict:
        s = {
            "name": name, "type": "form",
            "login_url": login_url,
            "username_field": username_field, "password_field": password_field,
            "username": username, "password": password,
            "extra_fields": extra_fields or {}, "target": target,
            "status": "not_authenticated", "cookies": "",
        }
        self.sessions[name] = s
        self._save()
        return s

    # ── Authenticate form login ────────────────────────────────────
    def authenticate(self, name: str) -> dict:
        s = self.sessions.get(name)
        if not s:
            return {"ok": False, "error": "Session not found"}

        if s["type"] != "form":
            s["status"] = "ready"
            return {"ok": True, "msg": "No authentication needed for this session type"}

        try:
            jar    = http.cookiejar.CookieJar()
            ctx    = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(jar),
                urllib.request.HTTPSHandler(context=ctx),
            )

            data = {
                s["username_field"]: s["username"],
                s["password_field"]: s["password"],
                **s.get("extra_fields", {}),
            }
            req  = urllib.request.Request(
                s["login_url"],
                data=urllib.parse.urlencode(data).encode(),
                method="POST",
            )
            opener.open(req, timeout=20)

            # Extract cookies
            cookie_str = "; ".join(f"{c.name}={c.value}" for c in jar)
            s["cookies"] = cookie_str
            s["status"]  = "authenticated"
            self._save()

            if self.log:
                self.log.success(f"Session '{name}' authenticated. Cookies captured.")
            return {"ok": True, "cookies": cookie_str}

        except Exception as e:
            s["status"] = "failed"
            self._save()
            if self.log:
                self.log.error(f"Session '{name}' auth failed: {e}")
            return {"ok": False, "error": str(e)}

    # ── Get headers/cookies for a session ─────────────────────────
    def get_headers(self, name: str) -> dict:
        """Returns dict of HTTP headers to inject for this session."""
        s = self.sessions.get(name)
        if not s:
            return {}
        if s["type"] == "basic":
            import base64
            creds = base64.b64encode(f"{s['username']}:{s['password']}".encode()).decode()
            return {"Authorization": f"Basic {creds}"}
        if s["type"] in ("cookie", "form"):
            return {"Cookie": s.get("cookies", "")}
        if s["type"] == "token":
            return {s["header"]: f"{s['prefix']} {s['token']}".strip()}
        return {}

    def get_cookie_str(self, name: str) -> str:
        s = self.sessions.get(name)
        if not s:
            return ""
        if s["type"] in ("cookie", "form"):
            return s.get("cookies", "")
        return ""

    def get_nuclei_flags(self, name: str) -> list:
        """Returns nuclei CLI flags for authenticated scan."""
        s = self.sessions.get(name)
        if not s:
            return []
        flags = []
        h = self.get_headers(name)
        for k, v in h.items():
            flags += ["-H", f"{k}: {v}"]
        return flags

    # ── Management ────────────────────────────────────────────────
    def remove(self, name: str):
        self.sessions.pop(name, None)
        self._save()

    def list_sessions(self) -> list:
        return list(self.sessions.values())

    def get(self, name: str) -> Optional[dict]:
        return self.sessions.get(name)

    def to_dict(self) -> dict:
        return {"sessions": list(self.sessions.values()), "total": len(self.sessions)}


# Singleton
_instance = None
def get_session_manager(log=None) -> SessionManager:
    global _instance
    if _instance is None:
        _instance = SessionManager(log)
    return _instance
