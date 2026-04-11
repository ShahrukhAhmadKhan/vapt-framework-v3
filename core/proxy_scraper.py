"""
Auto Proxy Scraper & Manager
─────────────────────────────
Continuously:
  • Scrapes free public proxies from multiple sources
  • Tests each proxy for connectivity and speed
  • Removes dead proxies automatically
  • Re-checks all proxies every N minutes
  • Finds the best proxy for a specific target
  • Monitors proxy health during active scans
  • Sends Telegram alerts when proxy fails during scan
  • Auto-resumes scan when working proxy is found

Sources scraped:
  • free-proxy-list.net
  • proxyscrape.com API
  • geonode.com API
  • openproxy.space
  • github proxy lists
"""

import threading
import time
import json
import urllib.request
import urllib.error
import ssl
import socket
import datetime
import random
from pathlib import Path
from typing import Optional, Callable

SCRAPED_PROXY_FILE = Path("config/scraped_proxies.json")
RECHECK_INTERVAL   = 15 * 60   # recheck all proxies every 15 minutes
SCRAPE_INTERVAL    = 30 * 60   # scrape new proxies every 30 minutes
TEST_TIMEOUT       = 8          # seconds per proxy test
TEST_URL           = "http://httpbin.org/ip"
TEST_URL_SSL       = "https://httpbin.org/ip"
MAX_PROXIES        = 200        # keep top N fastest proxies
MIN_WORKING        = 5          # minimum working proxies before scan


class AutoProxyScraper:

    def __init__(self, log=None, telegram_notify: Callable = None):
        self.log              = log
        self.telegram_notify  = telegram_notify   # fn(msg) → sends to all allowed chats
        self.proxies          = []                # list of proxy dicts
        self.working          = []                # verified working proxies
        self._lock            = threading.Lock()
        self._running         = False
        self._scrape_thread   = None
        self._check_thread    = None
        self.silent           = False             # suppress logs during active scans
        self._load()

    # ── Start / Stop ───────────────────────────────────────────────
    def start(self):
        if self._running:
            return
        self._running = True
        self._scrape_thread = threading.Thread(target=self._scrape_loop, daemon=True)
        self._check_thread  = threading.Thread(target=self._check_loop,  daemon=True)
        self._scrape_thread.start()
        self._check_thread.start()
        if self.log:
            self.log.success("Auto proxy scraper started")

    def stop(self):
        self._running = False

    # ── Main loops ─────────────────────────────────────────────────
    def _scrape_loop(self):
        """Scrape new proxies every SCRAPE_INTERVAL seconds."""
        while self._running:
            try:
                self._log("info", "Scraping new proxies from public sources…")
                new_proxies = self._scrape_all()
                self._log("info", f"  Scraped {len(new_proxies)} raw proxies")

                # Merge with existing (avoid duplicates)
                with self._lock:
                    existing = {f"{p['host']}:{p['port']}" for p in self.proxies}
                    added = 0
                    for p in new_proxies:
                        key = f"{p['host']}:{p['port']}"
                        if key not in existing:
                            self.proxies.append(p)
                            existing.add(key)
                            added += 1
                self._log("success", f"  Added {added} new proxies (total: {len(self.proxies)})")
                self._save()
            except Exception as e:
                self._log("error", f"Scraper error: {e}")
            time.sleep(SCRAPE_INTERVAL)

    def _check_loop(self):
        """Test all proxies every RECHECK_INTERVAL seconds."""
        # Initial delay — let scraper run first
        time.sleep(10)
        while self._running:
            try:
                self._log("info", f"Testing {len(self.proxies)} proxies…")
                self._test_all()
                self._log("success",
                    f"  Working: {len(self.working)} / {len(self.proxies)} proxies")
                self._save()
            except Exception as e:
                self._log("error", f"Check loop error: {e}")
            time.sleep(RECHECK_INTERVAL)

    # ── Scraping sources ───────────────────────────────────────────
    def _scrape_all(self) -> list:
        scrapers = [
            self._scrape_proxyscrape,
            self._scrape_geonode,
            self._scrape_free_proxy_list,
            self._scrape_openproxy,
        ]
        all_proxies = []
        for fn in scrapers:
            try:
                result = fn()
                all_proxies.extend(result)
                self._log("info", f"  {fn.__name__}: {len(result)} proxies")
            except Exception as e:
                self._log("warning", f"  {fn.__name__} failed: {e}")
        return all_proxies

    def _scrape_proxyscrape(self) -> list:
        url = ("https://api.proxyscrape.com/v3/free-proxy-list/get"
               "?request=displayproxies&protocol=http&timeout=5000"
               "&country=all&ssl=all&anonymity=elite,anonymous")
        data = self._fetch(url)
        proxies = []
        for line in data.splitlines():
            line = line.strip()
            if ":" in line:
                host, _, port = line.partition(":")
                try:
                    proxies.append(self._make_proxy(host, int(port), "http"))
                except ValueError:
                    pass
        return proxies

    def _scrape_geonode(self) -> list:
        url = ("https://proxylist.geonode.com/api/proxy-list"
               "?limit=100&page=1&sort_by=lastChecked&sort_type=desc"
               "&protocols=http,https&anonymityLevel=elite,anonymous")
        data = self._fetch(url)
        proxies = []
        try:
            items = json.loads(data).get("data", [])
            for item in items:
                host = item.get("ip","")
                port = item.get("port","")
                proto = (item.get("protocols") or ["http"])[0]
                if host and port:
                    proxies.append(self._make_proxy(host, int(port), proto))
        except Exception:
            pass
        return proxies

    def _scrape_free_proxy_list(self) -> list:
        """Scrape free-proxy-list.net via their API endpoint."""
        url = "https://free-proxy-list.net/"
        data = self._fetch(url)
        proxies = []
        import re
        # Pattern: IP:PORT in the page table
        matches = re.findall(
            r'<td>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})</td><td>(\d+)</td>',
            data
        )
        for host, port in matches[:50]:
            try:
                proxies.append(self._make_proxy(host, int(port), "http"))
            except ValueError:
                pass
        return proxies

    def _scrape_openproxy(self) -> list:
        """Scrape from openproxy.space list."""
        url = "https://openproxy.space/list/http"
        data = self._fetch(url)
        proxies = []
        import re
        matches = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)', data)
        for host, port in matches[:50]:
            try:
                proxies.append(self._make_proxy(host, int(port), "http"))
            except ValueError:
                pass
        return proxies

    # ── Testing ────────────────────────────────────────────────────
    def _test_all(self):
        """Test all proxies in parallel threads."""
        with self._lock:
            proxies_to_test = list(self.proxies)

        results = []
        threads = []
        lock    = threading.Lock()

        def test_one(p):
            r = self._test_proxy(p)
            if r["ok"]:
                with lock:
                    results.append({**p, **r})

        # Max 50 concurrent test threads
        batch_size = 50
        for i in range(0, len(proxies_to_test), batch_size):
            batch = proxies_to_test[i:i+batch_size]
            ts = [threading.Thread(target=test_one, args=(p,), daemon=True)
                  for p in batch]
            for t in ts: t.start()
            for t in ts: t.join(timeout=TEST_TIMEOUT + 2)

        # Sort by speed (fastest first)
        results.sort(key=lambda x: x.get("latency_ms", 9999))

        with self._lock:
            self.working = results[:MAX_PROXIES]
            # Keep all proxies but mark status
            working_keys = {f"{p['host']}:{p['port']}" for p in self.working}
            for p in self.proxies:
                k = f"{p['host']}:{p['port']}"
                p["working"]    = k in working_keys
                p["last_check"] = datetime.datetime.now().isoformat()

    def _test_proxy(self, proxy: dict, target_url: str = None) -> dict:
        """Test a single proxy. Returns {ok, latency_ms, exit_ip}."""
        url = target_url or TEST_URL
        proxy_url = self._build_url(proxy)
        start = time.time()
        try:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
            )
            opener.addheaders = [("User-Agent","Mozilla/5.0")]
            r    = opener.open(url, timeout=TEST_TIMEOUT)
            body = r.read(512).decode(errors="replace")
            ms   = int((time.time() - start) * 1000)
            # Try to extract exit IP
            exit_ip = ""
            try:
                exit_ip = json.loads(body).get("origin","")
            except Exception:
                pass
            return {"ok": True, "latency_ms": ms, "exit_ip": exit_ip}
        except Exception as e:
            return {"ok": False, "error": str(e)[:80], "latency_ms": 9999}

    # ── Best proxy for target ──────────────────────────────────────
    def find_best_for_target(self, target_url: str,
                              max_candidates: int = 10) -> Optional[dict]:
        """
        From working proxies, find the fastest one that can reach target_url.
        Tests top candidates in parallel.
        """
        with self._lock:
            candidates = list(self.working[:max_candidates])

        if not candidates:
            self._log("warning", "No working proxies available to test against target")
            return None

        self._log("info", f"Finding best proxy for {target_url} from {len(candidates)} candidates…")

        results = []
        lock    = threading.Lock()

        def test_one(p):
            r = self._test_proxy(p, target_url=target_url)
            if r["ok"]:
                with lock:
                    results.append({**p, **r})

        ts = [threading.Thread(target=test_one, args=(p,), daemon=True)
              for p in candidates]
        for t in ts: t.start()
        for t in ts: t.join(timeout=TEST_TIMEOUT + 2)

        if not results:
            self._log("warning", f"No proxy can reach {target_url}")
            return None

        results.sort(key=lambda x: x["latency_ms"])
        best = results[0]
        self._log("success",
            f"Best proxy: {best['host']}:{best['port']} ({best['latency_ms']}ms)")
        return best

    # ── Scan monitor ───────────────────────────────────────────────
    def monitor_scan_proxy(self, session_id: str, proxy: dict,
                            target_url: str,
                            pause_callback:  Callable,
                            resume_callback: Callable,
                            stop_event: threading.Event):
        """
        Background thread: monitors proxy health during an active scan.
        Calls pause_callback() if proxy dies, resume_callback(new_proxy) when restored.
        Sends Telegram messages throughout.
        """
        CHECK_INTERVAL = 20   # seconds between health checks
        paused         = False
        current_proxy  = proxy

        self._log("info", f"  Proxy monitor started for session {session_id}")

        while not stop_event.is_set():
            time.sleep(CHECK_INTERVAL)
            if stop_event.is_set():
                break

            result = self._test_proxy(current_proxy, target_url=target_url)

            if result["ok"]:
                if paused:
                    self._log("success",
                        f"  Proxy restored for {session_id} — resuming scan")
                    self._notify(
                        f"✅ *Proxy restored* — Session `{session_id}`\n"
                        f"Proxy: `{current_proxy['host']}:{current_proxy['port']}`\n"
                        f"Latency: {result['latency_ms']}ms\n"
                        f"🔄 *Scan auto-resumed*"
                    )
                    resume_callback(current_proxy)
                    paused = False
            else:
                if not paused:
                    self._log("warning",
                        f"  Proxy died for session {session_id}: {result.get('error','')}")
                    self._notify(
                        f"⚠️ *Proxy failed* — Session `{session_id}`\n"
                        f"Proxy: `{current_proxy['host']}:{current_proxy['port']}`\n"
                        f"Error: {result.get('error','connection lost')}\n"
                        f"⏸ *Scan paused* — searching for new proxy…"
                    )
                    pause_callback()
                    paused = True

                # Try to find a replacement proxy
                new_proxy = self.find_best_for_target(target_url)
                if new_proxy:
                    current_proxy = new_proxy
                    self._log("success",
                        f"  New proxy found for {session_id}: "
                        f"{new_proxy['host']}:{new_proxy['port']}")
                    self._notify(
                        f"🔍 *New proxy found* — Session `{session_id}`\n"
                        f"New proxy: `{new_proxy['host']}:{new_proxy['port']}`\n"
                        f"Latency: {new_proxy['latency_ms']}ms\n"
                        f"🔄 Testing connectivity before resuming…"
                    )
                else:
                    self._notify(
                        f"❌ *No working proxy found* — Session `{session_id}`\n"
                        f"Scan remains paused. Will retry in {CHECK_INTERVAL}s…\n"
                        f"Rescanning proxy pool for new proxies…"
                    )
                    # Trigger emergency scrape
                    threading.Thread(
                        target=self._emergency_scrape_and_test,
                        args=(target_url,),
                        daemon=True
                    ).start()

    def _emergency_scrape_and_test(self, target_url: str):
        """Emergency scrape when all proxies are dead during a scan."""
        self._log("info", "Emergency proxy scrape triggered…")
        try:
            new_proxies = self._scrape_all()
            with self._lock:
                existing = {f"{p['host']}:{p['port']}" for p in self.proxies}
                for p in new_proxies:
                    k = f"{p['host']}:{p['port']}"
                    if k not in existing:
                        self.proxies.append(p)
            self._test_all()
            self._log("success", f"Emergency scrape done. Working: {len(self.working)}")
            if self.working:
                self._notify(
                    f"✅ *Emergency proxy scrape complete*\n"
                    f"Found {len(self.working)} working proxies\n"
                    f"Active scans will auto-resume shortly."
                )
        except Exception as e:
            self._log("error", f"Emergency scrape failed: {e}")

    # ── Public interface ───────────────────────────────────────────
    def get_best_proxy(self) -> Optional[dict]:
        """Get the fastest currently working proxy."""
        with self._lock:
            return self.working[0] if self.working else None

    def get_proxy_for_requests(self) -> dict:
        """Dict for requests library proxies= param."""
        p = self.get_best_proxy()
        if not p:
            return {}
        url = self._build_url(p)
        return {"http": url, "https": url}

    def get_status(self) -> dict:
        with self._lock:
            return {
                "total":    len(self.proxies),
                "working":  len(self.working),
                "running":  self._running,
                "top5":     [
                    {"host": p["host"], "port": p["port"],
                     "latency_ms": p.get("latency_ms",0),
                     "exit_ip": p.get("exit_ip","")}
                    for p in self.working[:5]
                ],
            }

    def get_all_working(self) -> list:
        with self._lock:
            return list(self.working)

    # ── Persistence ────────────────────────────────────────────────
    def _save(self):
        SCRAPED_PROXY_FILE.parent.mkdir(exist_ok=True)
        with self._lock:
            data = {
                "updated":  datetime.datetime.now().isoformat(),
                "total":    len(self.proxies),
                "working":  len(self.working),
                "proxies":  self.proxies[:500],
            }
        try:
            SCRAPED_PROXY_FILE.write_text(json.dumps(data, indent=2))
        except Exception:
            pass

    def _load(self):
        if not SCRAPED_PROXY_FILE.exists():
            return
        try:
            data = json.loads(SCRAPED_PROXY_FILE.read_text())
            self.proxies = data.get("proxies", [])
            self.working = [p for p in self.proxies if p.get("working")]
            if self.log:
                self.log.info(f"Loaded {len(self.proxies)} cached proxies "
                              f"({len(self.working)} working)")
        except Exception:
            pass

    # ── Helpers ────────────────────────────────────────────────────
    def _make_proxy(self, host: str, port: int, protocol: str = "http") -> dict:
        return {
            "host": host.strip(), "port": int(port),
            "protocol": protocol, "username": "", "password": "",
            "label": f"auto:{host}:{port}",
            "working": False, "latency_ms": 9999,
            "exit_ip": "", "last_check": "",
            "source": "auto",
        }

    def _build_url(self, proxy: dict) -> str:
        proto = proxy.get("protocol","http")
        host  = proxy.get("host","")
        port  = proxy.get("port", 8080)
        user  = proxy.get("username","")
        pw    = proxy.get("password","")
        if user and pw:
            return f"{proto}://{user}:{pw}@{host}:{port}"
        return f"{proto}://{host}:{port}"

    def _fetch(self, url: str, timeout: int = 15) -> str:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            req = urllib.request.Request(
                url, headers={"User-Agent": "Mozilla/5.0"}
            )
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return r.read(1024*512).decode(errors="replace")
        except Exception:
            return ""

    def _notify(self, msg: str):
        if self.telegram_notify:
            try:
                self.telegram_notify(msg)
            except Exception:
                pass

    def _log(self, level: str, msg: str):
        """Log to file only — never interrupts scan terminal output."""
        import pathlib, datetime
        log_file = pathlib.Path("config/proxy_scraper.log")
        try:
            log_file.parent.mkdir(exist_ok=True)
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            with open(log_file, "a") as f:
                f.write(f"[{ts}] [{level.upper()}] {msg}\n")
        except Exception:
            pass


# ── Singleton ─────────────────────────────────────────────────────
_instance: Optional[AutoProxyScraper] = None

def get_auto_scraper(log=None, telegram_notify=None) -> AutoProxyScraper:
    global _instance
    if _instance is None:
        _instance = AutoProxyScraper(log=log, telegram_notify=telegram_notify)
    return _instance
