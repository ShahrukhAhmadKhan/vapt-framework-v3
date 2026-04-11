"""
Telegram Bot — Fixed + Auto-Proxy Notifications
"""

import json
import threading
import urllib.request
import urllib.parse
import urllib.error
import time
import datetime
from pathlib import Path
from typing import Optional

BOT_CONFIG_FILE = Path("config/bot_config.json")

HELP_TEXT = (
    "⚡ VAPT-Framework v3 - Complete Guide\n\n"
    "SCANNING:\n"
    "/scan example.com - Full scan (recon+ports+web+CVE+report)\n"
    "/scan 192.168.1.1 --type ip - IP address scan\n"
    "/scan 10.0.0.0/24 --type range - Full CIDR range\n"
    "/scan corp.local --type ad - Active Directory enum\n"
    "/scan url.com --proxy auto - Use auto proxy pool\n"
    "/scan url.com --modules recon,scan,report - Custom modules\n\n"
    "MODULES (comma-separated with --modules):\n"
    "recon - WHOIS, DNS, subdomains, email harvest\n"
    "scan - nmap port scan + NSE scripts\n"
    "web - nikto, directory brute force, headers\n"
    "nuclei - Template-based vulnerability scanner\n"
    "exploit - CVE check (EternalBlue, Log4Shell...)\n"
    "ad - LDAP, SMB, Kerberos enumeration\n"
    "report - Generate HTML+JSON+TXT report\n\n"
    "MANAGEMENT:\n"
    "/status - List all scan sessions\n"
    "/report SESSION_ID - Get report link\n"
    "/proxies - Auto proxy pool status\n"
    "/tools - Tool installation status\n"
    "/stop SESSION_ID - Request scan stop\n\n"
    "AI ASSISTANT:\n"
    "/ask what is log4shell\n"
    "/ask port 445 open what to check\n"
    "/ask write executive summary\n\n"
    "UTILITIES:\n"
    "/myid - Get your Telegram chat ID\n"
    "/help - Show this guide\n\n"
    "LEGAL: Only scan targets you own or have written permission to test."
)


class TelegramBot:

    def __init__(self, scan_callback, log=None):
        self.scan_callback = scan_callback
        self.log           = log
        self.token         = None
        self.allowed_ids   = []
        self.offset        = 0
        self._running      = False
        self._thread       = None
        self._load_config()

    def _load_config(self):
        if BOT_CONFIG_FILE.exists():
            try:
                cfg = json.loads(BOT_CONFIG_FILE.read_text())
                self.token       = cfg.get("telegram_token", "")
                self.allowed_ids = [str(i) for i in cfg.get("allowed_chat_ids", [])]
            except Exception:
                pass

    def save_config(self, token: str, allowed_ids: list, webhook_url: str = ""):
        BOT_CONFIG_FILE.parent.mkdir(exist_ok=True)
        BOT_CONFIG_FILE.write_text(json.dumps({
            "telegram_token":    token,
            "allowed_chat_ids":  allowed_ids,
            "webhook_url":       webhook_url,
        }, indent=2))
        self.token       = token
        self.allowed_ids = [str(i) for i in allowed_ids]

    # ── Start / Stop ───────────────────────────────────────────────
    def start(self):
        if not self.token:
            return False
        self._running = True
        self._thread  = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()
        if self.log:
            self.log.success("Telegram bot started")
        return True

    def stop(self):
        self._running = False

    @property
    def is_running(self):
        return self._running and self._thread is not None and self._thread.is_alive()

    # ── Poll ───────────────────────────────────────────────────────
    def _poll_loop(self):
        while self._running:
            try:
                updates = self._get_updates()
                for u in updates:
                    self._handle_update(u)
            except Exception as e:
                if self.log:
                    self.log.error(f"Bot poll error: {e}")
            time.sleep(2)

    def _get_updates(self) -> list:
        url    = f"https://api.telegram.org/bot{self.token}/getUpdates"
        params = urllib.parse.urlencode({"offset": self.offset, "timeout": 20})
        try:
            r    = urllib.request.urlopen(f"{url}?{params}", timeout=25)
            data = json.loads(r.read())
            updates = data.get("result", [])
            if updates:
                self.offset = updates[-1]["update_id"] + 1
            return updates
        except Exception:
            return []

    # ── Handle update ──────────────────────────────────────────────
    def _handle_update(self, update: dict):
        msg = update.get("message") or update.get("edited_message")
        if not msg:
            return
        chat_id = str(msg["chat"]["id"])
        text    = msg.get("text", "").strip()
        user    = msg.get("from", {}).get("username", "unknown")

        if not text.startswith("/"):
            return

        # Auth
        if self.allowed_ids and chat_id not in self.allowed_ids:
            self._send(chat_id,
                f"Unauthorised. Your chat ID: {chat_id}\n"
                f"Add it to allowed_chat_ids in Settings.")
            return

        parts = text.split()
        cmd   = parts[0].lower().split("@")[0]  # strip @botname suffix

        if self.log:
            self.log.info(f"Bot cmd @{user}: {text[:80]}")

        if cmd == "/help":
            self._send(chat_id, HELP_TEXT, parse_mode="Markdown")
        elif cmd == "/scan":
            self._cmd_scan(chat_id, parts[1:])
        elif cmd == "/status":
            self._cmd_status(chat_id)
        elif cmd == "/sessions":
            self._cmd_status(chat_id)
        elif cmd == "/report":
            sid = parts[1].upper() if len(parts) > 1 else ""
            self._cmd_report(chat_id, sid)
        elif cmd == "/proxies":
            self._cmd_proxies(chat_id)
        elif cmd == "/tools":
            self._cmd_tools(chat_id)
        elif cmd == "/ask":
            self._cmd_ask(chat_id, " ".join(parts[1:]))
        elif cmd == "/myid":
            self._send(chat_id, f"Your chat ID: {chat_id}")
        elif cmd == "/stop":
            sid = parts[1].upper() if len(parts) > 1 else ""
            self._send(chat_id, f"Stop requested for {sid}.")
        else:
            self._send(chat_id, f"Unknown command: {cmd}\nUse /help")

    # ── Commands ───────────────────────────────────────────────────
    def _cmd_scan(self, chat_id: str, args: list):
        if not args:
            self._send(chat_id,
                "Usage: /scan target [--type domain|ip|range|ad] [--modules mod1,mod2]")
            return

        target  = args[0]
        ttype   = "domain"
        modules = ["recon","scan","web","exploit","report"]
        use_proxy = False

        i = 1
        while i < len(args):
            if args[i] == "--type" and i+1 < len(args):
                ttype = args[i+1]; i += 2
            elif args[i] == "--modules" and i+1 < len(args):
                modules = args[i+1].split(","); i += 2
            elif args[i] == "--proxy" and i+1 < len(args):
                use_proxy = args[i+1].lower() == "auto"; i += 2
            else:
                i += 1

        # Show what modules will actually run
        self._send(chat_id,
            f"Scan started\n"
            f"Target: {target}\n"
            f"Type: {ttype}\n"
            f"Modules: {', '.join(modules)}\n"
            f"Proxy: {'auto' if use_proxy else 'none'}\n"
            f"Updates will follow as each module completes.")

        def _run():
            try:
                sid = self.scan_callback(
                    target, ttype, modules,
                    telegram_chat_id=chat_id,
                    use_auto_proxy=use_proxy,
                )
                self._send(chat_id,
                    f"Session ID: {sid}\n"
                    f"Use /report {sid} when scan completes.")
            except Exception as e:
                self._send(chat_id, f"Scan error: {e}")

        threading.Thread(target=_run, daemon=True).start()

    def _cmd_status(self, chat_id: str):
        try:
            r    = urllib.request.urlopen("http://localhost:5000/api/sessions", timeout=5)
            data = json.loads(r.read())
            if not data:
                self._send(chat_id, "No scans yet."); return
            lines = ["Active Scans:"]
            for s in data[-8:]:
                emoji = {"running":"⏳","complete":"✅","error":"❌","queued":"🕐"}.get(s["status"],"•")
                lines.append(f"{emoji} {s['id']} — {s['target']} ({s['status']})")
            self._send(chat_id, "\n".join(lines))
        except Exception as e:
            self._send(chat_id, f"Could not reach framework: {e}")

    def _cmd_report(self, chat_id: str, sid: str):
        if not sid:
            self._send(chat_id, "Usage: /report SESSION_ID"); return
        try:
            url  = f"http://localhost:5000/api/session/{sid}"
            r    = urllib.request.urlopen(url, timeout=8)
            data = json.loads(r.read())
        except Exception as e:
            self._send(chat_id, f"Could not retrieve session {sid}: {e}"); return

        status = data.get("status","unknown")
        target = data.get("target","")
        rpt    = data.get("report_path","")

        if status == "running":
            self._send(chat_id,
                f"Scan still running for {sid}\n"
                f"Target: {target}\n"
                f"Use /status to check progress.")
            return

        if status == "error":
            self._send(chat_id, f"Scan {sid} ended with error.")
            return

        if rpt:
            # Send summary message
            findings = data.get("findings", {})
            exploits = []
            for t, d in findings.get("exploit", {}).items():
                exploits.extend(d.get("cve_matches", []))
            crit = sum(1 for f in exploits if f.get("severity") == "CRITICAL")
            high = sum(1 for f in exploits if f.get("severity") == "HIGH")

            self._send(chat_id,
                f"Report Ready\n"
                f"Session: {sid}\n"
                f"Target: {target}\n"
                f"Critical: {crit} | High: {high}\n"
                f"Link: http://localhost:5000/report-files/{rpt}")

            # Send the actual HTML file
            self._send_document(chat_id, rpt, f"VAPT_Report_{sid}.html")
        else:
            self._send(chat_id,
                f"Session {sid} is {status} but no report file found.\n"
                f"Make sure the report module was included in the scan.")

    def _send_document(self, chat_id: str, report_path: str, filename: str):
        """Send the HTML report file via Telegram sendDocument."""
        if not self.token:
            return
        # Read report file from disk
        from pathlib import Path
        report_file = Path("reports") / report_path
        if not report_file.exists():
            self._send(chat_id, f"Report file not found: {report_path}")
            return
        try:
            import io
            file_bytes = report_file.read_bytes()
            boundary   = "----VAPTFrameworkBoundary"
            body  = f"--{boundary}\r\n"
            body += f'Content-Disposition: form-data; name="chat_id"\r\n\r\n{chat_id}\r\n'
            body += f"--{boundary}\r\n"
            body += f'Content-Disposition: form-data; name="document"; filename="{filename}"\r\n'
            body += "Content-Type: text/html\r\n\r\n"
            body_bytes = body.encode() + file_bytes + f"\r\n--{boundary}--\r\n".encode()

            req = urllib.request.Request(
                f"https://api.telegram.org/bot{self.token}/sendDocument",
                data=body_bytes,
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=60)
            if self.log:
                self.log.success(f"Report file sent to Telegram chat {chat_id}")
        except Exception as e:
            if self.log:
                self.log.error(f"Failed to send report file: {e}")
            self._send(chat_id, f"Could not send file: {e}\nOpen via browser link above.")

    def _cmd_proxies(self, chat_id: str):
        try:
            r    = urllib.request.urlopen("http://localhost:5000/api/proxies/auto/status", timeout=5)
            data = json.loads(r.read())
            top  = data.get("top5",[])
            top_str = "\n".join(
                f"  {p['host']}:{p['port']} — {p['latency_ms']}ms"
                for p in top
            ) if top else "  None yet"
            self._send(chat_id,
                f"Proxy Pool Status\n"
                f"Total: {data.get('total',0)}\n"
                f"Working: {data.get('working',0)}\n"
                f"Auto-scraper: {'running' if data.get('running') else 'stopped'}\n\n"
                f"Top proxies:\n{top_str}")
        except Exception as e:
            self._send(chat_id, f"Proxy status error: {e}")

    def _cmd_tools(self, chat_id: str):
        try:
            r    = urllib.request.urlopen("http://localhost:5000/api/tools/check", timeout=10)
            data = json.loads(r.read())
            ok   = sum(1 for v in data.values() if v["installed"])
            bad  = len(data) - ok
            self._send(chat_id,
                f"Tool Arsenal\n"
                f"Installed: {ok}\n"
                f"Missing: {bad}\n"
                f"Total: {len(data)}\n\n"
                f"Use GUI Toolbox to auto-install missing tools.")
        except Exception as e:
            self._send(chat_id, f"Could not check tools: {e}")

    def _cmd_ask(self, chat_id: str, question: str):
        if not question:
            self._send(chat_id, "Usage: /ask your security question"); return
        self._send(chat_id, "Asking AI assistant...")
        try:
            from ai.ollama_assistant import OllamaAssistant
            ai  = OllamaAssistant()
            ans = ai.chat(question)
            for chunk in [ans[i:i+4000] for i in range(0, len(ans), 4000)]:
                self._send(chat_id, chunk)
        except Exception as e:
            self._send(chat_id, f"AI error: {e}")

    # ── Notify all users ───────────────────────────────────────────
    def notify_all(self, msg: str):
        """Send message to all allowed chat IDs (used by proxy scraper)."""
        for cid in self.allowed_ids:
            self._send(cid, msg)

    def notify(self, chat_id: str, session_id: str, module: str,
               status: str, details: str = ""):
        emoji = {"complete":"✅","error":"❌","running":"⏳","paused":"⏸"}.get(status,"•")
        msg   = f"{emoji} {session_id} — {module}: {status}"
        if details:
            msg += f"\n{details[:300]}"
        self._send(chat_id, msg)

    # ── Send ───────────────────────────────────────────────────────
    def _send(self, chat_id: str, text: str, parse_mode: str = "") -> bool:
        if not self.token:
            return False
        url  = f"https://api.telegram.org/bot{self.token}/sendMessage"
        data = {"chat_id": chat_id, "text": str(text)[:4096]}
        if parse_mode:
            data["parse_mode"] = parse_mode
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(data).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=10)
            return True
        except Exception as e:
            if self.log:
                self.log.error(f"Telegram send error: {e}")
            return False
