"""
Proxy Manager
─────────────
Supports:
  • Static proxy  — single proxy for all requests
  • Rotating pool — round-robin or random from list
  • Per-protocol  — HTTP, HTTPS, SOCKS5
  • Proxy health check before use
  • Used by all scan modules via get_proxy()
"""

import random
import socket
import urllib.request
import urllib.error
import json
import threading
from pathlib import Path
from typing import Optional

PROXY_FILE = Path("config/proxies.json")


class ProxyManager:

    def __init__(self, log=None):
        self.log      = log
        self.proxies  = []
        self.mode     = "none"   # none | static | rotating
        self._lock    = threading.Lock()
        self._rr_idx  = 0
        self._load()

    # ── Persistence ───────────────────────────────────────────────
    def _load(self):
        if PROXY_FILE.exists():
            try:
                data = json.loads(PROXY_FILE.read_text())
                self.proxies = data.get("proxies", [])
                self.mode    = data.get("mode", "none")
            except Exception:
                pass

    def save(self, proxies: list, mode: str):
        self.proxies = proxies
        self.mode    = mode
        PROXY_FILE.parent.mkdir(exist_ok=True)
        PROXY_FILE.write_text(json.dumps({"proxies": proxies, "mode": mode}, indent=2))
        if self.log:
            self.log.success(f"Proxy config saved: {len(proxies)} proxies, mode={mode}")

    # ── Get proxy for current request ─────────────────────────────
    def get_proxy(self) -> Optional[dict]:
        """Returns a proxy dict for use with requests/urllib, or None."""
        if self.mode == "none" or not self.proxies:
            return None

        active = [p for p in self.proxies if p.get("enabled", True)]
        if not active:
            return None

        if self.mode == "static":
            p = active[0]
        elif self.mode == "rotating_random":
            p = random.choice(active)
        else:  # rotating_rr (round-robin)
            with self._lock:
                p = active[self._rr_idx % len(active)]
                self._rr_idx += 1

        return self._build_proxy_dict(p)

    def get_proxies_for_requests(self) -> dict:
        """Returns dict suitable for requests library proxies= param."""
        p = self.get_proxy()
        if not p:
            return {}
        url = p["url"]
        return {"http": url, "https": url}

    def get_env_for_subprocess(self) -> dict:
        """Returns env vars for subprocess tools (curl, nmap via proxychains)."""
        p = self.get_proxy()
        if not p:
            return {}
        return {
            "http_proxy":  p["url"],
            "https_proxy": p["url"],
            "HTTP_PROXY":  p["url"],
            "HTTPS_PROXY": p["url"],
        }

    # ── Health check ───────────────────────────────────────────────
    def health_check(self, proxy: dict, timeout: int = 8) -> dict:
        """Check if a proxy is reachable. Returns status dict."""
        url = self._build_url(proxy)
        try:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": url, "https": url})
            )
            opener.addheaders = [("User-Agent", "curl/7.88")]
            r = opener.open("http://httpbin.org/ip", timeout=timeout)
            body = json.loads(r.read())
            return {"ok": True, "ip": body.get("origin","?"), "url": url}
        except Exception as e:
            return {"ok": False, "error": str(e), "url": url}

    def check_all(self) -> list:
        results = []
        for p in self.proxies:
            r = self.health_check(p)
            p["last_check"] = r
            results.append({**p, **r})
        return results

    # ── Helpers ────────────────────────────────────────────────────
    def _build_url(self, p: dict) -> str:
        proto = p.get("protocol", "http")
        host  = p.get("host", "")
        port  = p.get("port", 8080)
        user  = p.get("username", "")
        pw    = p.get("password", "")
        if user and pw:
            return f"{proto}://{user}:{pw}@{host}:{port}"
        return f"{proto}://{host}:{port}"

    def _build_proxy_dict(self, p: dict) -> dict:
        return {"url": self._build_url(p), "host": p.get("host"), "port": p.get("port")}

    # ── API helpers ────────────────────────────────────────────────
    def to_dict(self) -> dict:
        return {"mode": self.mode, "proxies": self.proxies, "total": len(self.proxies)}

    def add_proxy(self, host, port, protocol="http", username="", password="", label=""):
        proxy = {
            "host": host, "port": int(port), "protocol": protocol,
            "username": username, "password": password,
            "label": label or f"{host}:{port}", "enabled": True,
        }
        self.proxies.append(proxy)
        self.save(self.proxies, self.mode)
        return proxy

    def remove_proxy(self, idx: int):
        if 0 <= idx < len(self.proxies):
            removed = self.proxies.pop(idx)
            self.save(self.proxies, self.mode)
            return removed
        return None

    def toggle_proxy(self, idx: int):
        if 0 <= idx < len(self.proxies):
            self.proxies[idx]["enabled"] = not self.proxies[idx].get("enabled", True)
            self.save(self.proxies, self.mode)


# Singleton
_instance = None
def get_proxy_manager(log=None) -> ProxyManager:
    global _instance
    if _instance is None:
        _instance = ProxyManager(log)
    return _instance
