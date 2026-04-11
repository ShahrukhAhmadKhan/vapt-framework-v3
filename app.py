#!/usr/bin/env python3
"""VAPT-Framework v3 — Full GUI + Auth + Bot + AI + Auto-Proxy"""

import os, sys, threading, json, uuid, datetime, time
from pathlib import Path
from functools import wraps
from flask import Flask, render_template, request, jsonify, send_from_directory, redirect
from flask_socketio import SocketIO, emit

BASE = Path(__file__).parent
sys.path.insert(0, str(BASE))

# ── Core imports ──────────────────────────────────────────────────────
from core.logger          import SocketLogger
from core.auth_gate       import AuthorisationGate
from core.installer       import ToolInstaller
from core.scope_parser    import ScopeParser
from core.proxy_manager   import get_proxy_manager
from core.proxy_scraper   import get_auto_scraper
from core.session_manager import get_session_manager
from core.user_manager    import get_user_manager
from core.api_keys        import get_api_key_manager
from modules.recon        import ReconModule
from modules.scanner      import ScannerModule
from modules.web_audit    import WebAuditModule
from modules.ad_enum      import ADEnumModule
from modules.exploit      import ExploitCheckModule
from modules.tech_detect  import TechDetectModule
from modules.nuclei_engine import NucleiEngine
from modules.msf_module   import MSFModule
from modules.vuln_verifier import VulnVerifier
from modules.path_scanner  import PathScanner
from modules.ip_resolver   import IPResolver
from reports.generator    import ReportGenerator
from ai.ollama_assistant  import OllamaAssistant
from bot.telegram_bot     import TelegramBot

# ── App setup ─────────────────────────────────────────────────────────
app      = Flask(__name__, template_folder="app/templates", static_folder="app/static")
app.config["SECRET_KEY"] = os.urandom(24).hex()
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

SESSIONS    = {}
REPORTS_DIR = BASE / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# ── Singletons ────────────────────────────────────────────────────────
proxy_mgr = get_proxy_manager()
sess_mgr  = get_session_manager()
user_mgr  = get_user_manager()
api_keys  = get_api_key_manager()
ai        = OllamaAssistant()

# ── Auth decorators ───────────────────────────────────────────────────
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = (request.headers.get("X-Token") or
                 request.cookies.get("vapt_token") or "")
        sess  = user_mgr.verify_session(token) if token else None
        if not sess:
            return jsonify({"error": "Unauthorised"}), 401
        request.current_user = sess
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    @require_auth
    def decorated(*args, **kwargs):
        if request.current_user.get("role") != "admin":
            return jsonify({"error": "Admin required"}), 403
        return f(*args, **kwargs)
    return decorated

# ── Telegram bot + auto-proxy ─────────────────────────────────────────
def _scan_callback(target, ttype, modules,
                   telegram_chat_id=None, use_auto_proxy=False):
    sid = _create_session(target, ttype, modules)
    threading.Thread(
        target=_run_scan,
        args=(sid, target, ttype, modules,
              {"authorised_by": "Telegram", "confirmed": True},
              None, None, telegram_chat_id, use_auto_proxy),
        daemon=True
    ).start()
    return sid

tg_bot = TelegramBot(scan_callback=_scan_callback)
tg_bot.start()

def _tg_notify_all(msg: str):
    tg_bot.notify_all(msg)

auto_scraper = get_auto_scraper(telegram_notify=_tg_notify_all)
auto_scraper.start()


# ══════════════════════════════════════════════════════════════════════
# PAGE ROUTES
# ══════════════════════════════════════════════════════════════════════

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan")
def scan_page():
    return render_template("scan.html")

@app.route("/targets")
def targets_page():
    return render_template("targets.html")

@app.route("/reports")
def reports_page():
    return render_template("reports.html", reports=_list_reports())

@app.route("/tools")
def tools_page():
    return render_template("tools.html")

@app.route("/proxies")
def proxies_page():
    return render_template("proxies.html")

@app.route("/sessions-page")
def sessions_page():
    return render_template("sessions_page.html")

@app.route("/ai-chat")
def ai_chat_page():
    return render_template("ai_chat.html")

@app.route("/settings")
def settings_page():
    return render_template("settings.html")

@app.route("/api-keys")
def api_keys_page():
    return render_template("api_keys.html")

@app.route("/admin")
def admin_page():
    return render_template("admin.html", current_user="admin")

@app.route("/report-files/<path:filename>")
def serve_report(filename):
    return send_from_directory(str(REPORTS_DIR), filename)


# ══════════════════════════════════════════════════════════════════════
# AUTH API
# ══════════════════════════════════════════════════════════════════════

@app.route("/api/auth/login", methods=["POST"])
def api_login():
    d   = request.json or {}
    ip  = request.remote_addr or ""
    try:
        token = user_mgr.authenticate(
            d.get("username",""), d.get("password",""),
            totp_code=d.get("totp_code"), ip=ip
        )
        return jsonify({"token": token})
    except ValueError as e:
        msg = str(e)
        if msg == "MFA_REQUIRED":
            return jsonify({"mfa_required": True})
        return jsonify({"error": msg}), 401

@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    token = request.headers.get("X-Token","")
    user_mgr.logout(token)
    return jsonify({"ok": True})

@app.route("/api/auth/verify")
def api_verify():
    token = request.headers.get("X-Token","")
    sess  = user_mgr.verify_session(token)
    if sess:
        return jsonify({"valid": True,
                        "username": sess["username"],
                        "role": sess["role"]})
    return jsonify({"valid": False})

@app.route("/api/auth/me")
@require_auth
def api_me():
    u = user_mgr.get_user(request.current_user["username"])
    return jsonify(u or {})

@app.route("/api/auth/mfa/setup", methods=["POST"])
@require_auth
def api_mfa_setup():
    try:
        return jsonify(user_mgr.setup_mfa(request.current_user["username"]))
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/auth/mfa/enable", methods=["POST"])
@require_auth
def api_mfa_enable():
    code = (request.json or {}).get("code","")
    try:
        user_mgr.enable_mfa(request.current_user["username"], code)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/auth/mfa/disable", methods=["POST"])
@require_auth
def api_mfa_disable():
    try:
        user_mgr.disable_mfa(request.current_user["username"])
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ══════════════════════════════════════════════════════════════════════
# USER MANAGEMENT API (admin only)
# ══════════════════════════════════════════════════════════════════════

@app.route("/api/users")
@require_admin
def api_list_users():
    return jsonify(user_mgr.list_users())

@app.route("/api/users/create", methods=["POST"])
@require_admin
def api_create_user():
    d  = request.json or {}
    by = request.current_user["username"]
    try:
        u = user_mgr.create_user(
            d.get("username",""), d.get("password",""),
            d.get("role","analyst"), created_by=by)
        return jsonify(u)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/users/remove/<username>", methods=["DELETE"])
@require_admin
def api_remove_user(username):
    try:
        user_mgr.remove_user(username, by=request.current_user["username"])
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/users/update/<username>", methods=["POST"])
@require_admin
def api_update_user(username):
    d = request.json or {}
    try:
        u = user_mgr.update_user(username, by=request.current_user["username"], **d)
        return jsonify(u)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/users/audit")
@require_admin
def api_audit_log():
    return jsonify({"lines": user_mgr.get_audit_log(200)})


# ══════════════════════════════════════════════════════════════════════
# SCAN API
# ══════════════════════════════════════════════════════════════════════

@app.route("/api/scan/start", methods=["POST"])
def api_start_scan():
    data           = request.json or {}
    target         = data.get("target","").strip()
    ttype          = data.get("type","domain")
    modules        = data.get("modules",["recon","scan","web","exploit","report"])
    scope          = data.get("scope",{})
    proxy_mode     = data.get("proxy_mode", None)
    session_name   = data.get("auth_session", None)
    use_auto_proxy = data.get("use_auto_proxy", False)

    if not target:
        return jsonify({"error": "Target required"}), 400

    # Normalise module aliases so user-friendly names work
    modules = _normalise_modules(modules)

    sid = _create_session(target, ttype, modules)
    threading.Thread(
        target=_run_scan,
        args=(sid, target, ttype, modules, scope,
              proxy_mode, session_name, None, use_auto_proxy),
        daemon=True
    ).start()
    return jsonify({"session_id": sid})

@app.route("/api/sessions")
def api_sessions():
    return jsonify(list(SESSIONS.values()))

@app.route("/api/session/<sid>")
def api_session(sid):
    s = SESSIONS.get(sid.upper(), SESSIONS.get(sid))
    return jsonify(s) if s else (jsonify({"error": "not found"}), 404)

@app.route("/api/reports")
def api_reports():
    return jsonify(_list_reports())


# ══════════════════════════════════════════════════════════════════════
# VULNERABILITY VERIFIER + AI EXPLANATION
# ══════════════════════════════════════════════════════════════════════

@app.route("/api/verify", methods=["POST"])
def api_verify_vuln():
    d      = request.json or {}
    url    = d.get("url","")
    params = d.get("params", None)
    checks = d.get("checks", ["all"])
    explain = d.get("explain", True)   # use AI to explain findings

    if not url:
        return jsonify({"error": "url required"}), 400

    v       = VulnVerifier(timeout=12)
    results = v.verify_all(url, params) if "all" in checks else []

    if not results:
        for check in checks:
            if check == "all":
                continue
            fn = getattr(v, f"check_{check}", None)
            if fn:
                r = fn(url, params)
                if r and r.get("vuln"):
                    results.append(r)

    # AI explanation for each finding (like Acunetix)
    if explain and results and ai.available:
        for finding in results:
            try:
                finding["ai_explanation"] = _explain_vuln(finding)
            except Exception:
                finding["ai_explanation"] = None

    return jsonify({
        "results":    results,
        "total":      len(results),
        "url":        url,
        "vulnerable": len(results) > 0,
    })

@app.route("/api/verify/explain", methods=["POST"])
def api_explain_finding():
    """Get AI explanation for a single finding — like Acunetix/HCL detail view."""
    finding = request.json or {}
    explanation = _explain_vuln(finding)
    return jsonify({"explanation": explanation})

def _explain_vuln(finding: dict) -> dict:
    """
    Generate structured explanation like Acunetix:
    - What it is
    - How it was found
    - Real-world impact
    - CVSS context
    - Step-by-step remediation
    - References
    """
    if not ai.available:
        return _static_explanation(finding)

    vuln_type = finding.get("type","")
    severity  = finding.get("severity","")
    evidence  = finding.get("evidence","")
    payload   = finding.get("payload","")
    url       = finding.get("url","")

    prompt = f"""You are a security expert writing a vulnerability report like Acunetix or HCL AppScan.

Vulnerability found:
- Type: {vuln_type}
- Severity: {severity}
- URL: {url}
- Evidence: {evidence}
- Payload used: {payload}

Write a structured explanation with these EXACT sections (use these headings):

**DESCRIPTION**
(2-3 sentences explaining what this vulnerability is and how it works technically)

**HOW IT WAS DETECTED**
(Explain what the scanner did to find this — the payload and what response confirmed it)

**BUSINESS IMPACT**
(Real-world consequences if exploited — data breach, account takeover, server compromise etc.)

**PROOF OF CONCEPT**
(Simple example of how an attacker could exploit this on this specific URL)

**REMEDIATION**
(Step-by-step fix — be specific to the technology if possible)

**REFERENCES**
(List 2-3 relevant CVEs, OWASP links, or vendor advisories)

Be concise and technical. Write for a developer who needs to fix this."""

    response = ai.chat(prompt)
    return {
        "raw":        response,
        "sections":   _parse_explanation_sections(response),
        "generated":  True,
        "model":      ai.model,
    }

def _parse_explanation_sections(text: str) -> dict:
    """Parse AI response into structured sections."""
    sections = {}
    current  = None
    lines    = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("**") and stripped.endswith("**"):
            if current and lines:
                sections[current] = "\n".join(lines).strip()
            current = stripped.strip("*").strip()
            lines   = []
        elif current:
            lines.append(line)
    if current and lines:
        sections[current] = "\n".join(lines).strip()
    return sections

def _static_explanation(finding: dict) -> dict:
    """Fallback explanations when Ollama is not available."""
    STATIC = {
        "SQL Injection (Error-Based)": {
            "DESCRIPTION": "SQL Injection occurs when user-supplied data is included in SQL queries without proper sanitisation. Error-based SQLi causes the database to return error messages that reveal information about its structure.",
            "BUSINESS IMPACT": "An attacker can read, modify, or delete all data in the database. In many cases this leads to complete server compromise via xp_cmdshell or INTO OUTFILE.",
            "REMEDIATION": "Use parameterised queries (prepared statements) in all database calls. Never concatenate user input into SQL strings. Use an ORM.",
            "REFERENCES": "OWASP A03:2021 — https://owasp.org/Top10/A03_2021-Injection/\nCWE-89 — https://cwe.mitre.org/data/definitions/89.html",
        },
        "SQL Injection (Time-Based Blind)": {
            "DESCRIPTION": "Time-based blind SQL injection injects time-delay commands (SLEEP, WAITFOR) into queries. The vulnerability is confirmed when the server response is delayed by the injected sleep duration.",
            "BUSINESS IMPACT": "Full database read access via slow data extraction. Even without visible output, every database record can be extracted byte by byte.",
            "REMEDIATION": "Use parameterised queries. Implement a WAF rule to block SLEEP/WAITFOR in parameters. Use least-privilege database accounts.",
            "REFERENCES": "OWASP A03:2021 — https://owasp.org/Top10/A03_2021-Injection/",
        },
        "Reflected XSS": {
            "DESCRIPTION": "Reflected Cross-Site Scripting occurs when user input is echoed back in an HTTP response without encoding, allowing script injection that executes in the victim's browser.",
            "BUSINESS IMPACT": "Session hijacking, credential theft, keylogging, phishing pages hosted on a trusted domain, browser exploitation.",
            "REMEDIATION": "HTML-encode all user output. Implement Content-Security-Policy. Use modern frameworks that auto-escape output.",
            "REFERENCES": "OWASP A03:2021 — https://owasp.org/Top10/A03_2021-Injection/\nCWE-79 — https://cwe.mitre.org/data/definitions/79.html",
        },
        "Path Traversal / LFI": {
            "DESCRIPTION": "Path traversal allows attackers to read arbitrary files on the server by manipulating file path parameters with sequences like ../../../etc/passwd.",
            "BUSINESS IMPACT": "Read of /etc/passwd, private keys, configuration files with credentials, source code, or any file the web server process can read.",
            "REMEDIATION": "Validate file paths against a strict allowlist. Use basename() to strip path separators. Never build paths from user input.",
            "REFERENCES": "CWE-22 — https://cwe.mitre.org/data/definitions/22.html",
        },
        "Command Injection (Time-Based)": {
            "DESCRIPTION": "OS Command Injection allows attackers to execute arbitrary system commands by injecting shell metacharacters into parameters that are passed to system calls.",
            "BUSINESS IMPACT": "Complete server compromise — remote code execution with web server privileges, data exfiltration, ransomware, pivoting to internal network.",
            "REMEDIATION": "Never pass user input to OS commands. Use language APIs instead of shell. If unavoidable, use allowlists and proper escaping.",
            "REFERENCES": "CWE-78 — https://cwe.mitre.org/data/definitions/78.html\nOWASP A03:2021",
        },
        "Open Redirect": {
            "DESCRIPTION": "An open redirect allows attackers to redirect users to arbitrary external URLs via a trusted domain parameter, bypassing trust controls.",
            "BUSINESS IMPACT": "Phishing attacks using trusted domain, OAuth token theft, bypassing referrer checks, malware distribution via trusted link.",
            "REMEDIATION": "Whitelist allowed redirect destinations. Never redirect to user-supplied URLs. Validate against a list of trusted domains.",
            "REFERENCES": "CWE-601 — https://cwe.mitre.org/data/definitions/601.html",
        },
        "Clickjacking": {
            "DESCRIPTION": "Missing X-Frame-Options allows the page to be embedded in an iframe on a malicious site, tricking users into clicking UI elements they cannot see.",
            "BUSINESS IMPACT": "Tricking users into performing unintended actions (like/share/purchase/delete) by overlaying invisible iframes over legitimate content.",
            "REMEDIATION": "Add 'X-Frame-Options: DENY' header. Or use CSP: 'frame-ancestors none'. Apply to all pages, especially authenticated ones.",
            "REFERENCES": "OWASP A05:2021 — https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        },
        "CORS Origin Reflection": {
            "DESCRIPTION": "The server reflects the Origin header value back in Access-Control-Allow-Origin, allowing any website to make cross-origin requests.",
            "BUSINESS IMPACT": "A malicious website can make authenticated API calls on behalf of logged-in users and read the responses — equivalent to CSRF with data exfiltration.",
            "REMEDIATION": "Whitelist specific allowed origins. Never reflect the request Origin header. Validate against a hardcoded allowlist.",
            "REFERENCES": "OWASP A05:2021 — https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        },
    }

    vuln_type = finding.get("type","")
    data      = STATIC.get(vuln_type, {
        "DESCRIPTION": f"{vuln_type} vulnerability detected.",
        "BUSINESS IMPACT": "Could lead to data exposure or system compromise.",
        "REMEDIATION": finding.get("remediation","Consult OWASP guidelines."),
        "REFERENCES": "https://owasp.org",
    })
    return {"sections": data, "generated": False, "model": "static"}


# ══════════════════════════════════════════════════════════════════════
# AUTO PROXY API
# ══════════════════════════════════════════════════════════════════════

@app.route("/api/proxies/auto/status")
def api_auto_proxy_status():
    return jsonify(auto_scraper.get_status())

@app.route("/api/proxies/auto/working")
def api_auto_proxy_working():
    return jsonify(auto_scraper.get_all_working()[:50])

@app.route("/api/proxies/auto/scrape", methods=["POST"])
def api_auto_proxy_scrape():
    def _do():
        new = auto_scraper._scrape_all()
        with auto_scraper._lock:
            existing = {f"{p['host']}:{p['port']}" for p in auto_scraper.proxies}
            for p in new:
                k = f"{p['host']}:{p['port']}"
                if k not in existing:
                    auto_scraper.proxies.append(p)
        auto_scraper._test_all()
        auto_scraper._save()
        socketio.emit("proxy_update", auto_scraper.get_status())
    threading.Thread(target=_do, daemon=True).start()
    return jsonify({"status": "started"})

@app.route("/api/proxies/auto/test", methods=["POST"])
def api_auto_proxy_test():
    def _do():
        auto_scraper._test_all()
        auto_scraper._save()
        socketio.emit("proxy_update", auto_scraper.get_status())
    threading.Thread(target=_do, daemon=True).start()
    return jsonify({"status": "started"})

@app.route("/api/proxies/auto/find-best", methods=["POST"])
def api_auto_proxy_find_best():
    d      = request.json or {}
    target = d.get("target","http://httpbin.org/ip")
    best   = auto_scraper.find_best_for_target(target)
    return jsonify(best or {"error": "no working proxy found"})


# ══════════════════════════════════════════════════════════════════════
# MANUAL PROXY API
# ══════════════════════════════════════════════════════════════════════

@app.route("/api/proxies", methods=["GET"])
def api_get_proxies():
    return jsonify(proxy_mgr.to_dict())

@app.route("/api/proxies/add", methods=["POST"])
def api_add_proxy():
    d = request.json or {}
    p = proxy_mgr.add_proxy(
        host=d.get("host",""), port=d.get("port",8080),
        protocol=d.get("protocol","http"),
        username=d.get("username",""), password=d.get("password",""),
        label=d.get("label",""),
    )
    return jsonify(p)

@app.route("/api/proxies/remove/<int:idx>", methods=["DELETE"])
def api_remove_proxy(idx):
    return jsonify(proxy_mgr.remove_proxy(idx) or {"error":"not found"})

@app.route("/api/proxies/mode", methods=["POST"])
def api_proxy_mode():
    mode = (request.json or {}).get("mode","none")
    proxy_mgr.save(proxy_mgr.proxies, mode)
    return jsonify({"mode": mode})

@app.route("/api/proxies/check", methods=["POST"])
def api_proxy_check():
    return jsonify(proxy_mgr.check_all())

@app.route("/api/proxies/toggle/<int:idx>", methods=["POST"])
def api_proxy_toggle(idx):
    proxy_mgr.toggle_proxy(idx)
    return jsonify({"ok": True})


# ══════════════════════════════════════════════════════════════════════
# AUTH SESSION API
# ══════════════════════════════════════════════════════════════════════

@app.route("/api/auth-sessions", methods=["GET"])
def api_get_auth_sessions():
    return jsonify(sess_mgr.to_dict())

@app.route("/api/auth-sessions/add", methods=["POST"])
def api_add_auth_session():
    d     = request.json or {}
    stype = d.get("type","basic")
    name  = d.get("name","").strip()
    if not name:
        return jsonify({"error":"Name required"}), 400
    if stype == "basic":
        s = sess_mgr.add_basic_auth(name, d.get("username",""), d.get("password",""), d.get("target",""))
    elif stype == "cookie":
        s = sess_mgr.add_cookie_session(name, d.get("cookies",""), d.get("target",""))
    elif stype == "token":
        s = sess_mgr.add_token_session(name, d.get("token",""), d.get("header","Authorization"), d.get("prefix","Bearer"), d.get("target",""))
    elif stype == "form":
        s = sess_mgr.add_form_login(name, d.get("login_url",""), d.get("username_field","username"), d.get("password_field","password"), d.get("username",""), d.get("password",""), d.get("extra_fields",{}), d.get("target",""))
    else:
        return jsonify({"error":"Unknown type"}), 400
    return jsonify(s)

@app.route("/api/auth-sessions/authenticate/<n>", methods=["POST"])
def api_authenticate_session(n):
    return jsonify(sess_mgr.authenticate(n))

@app.route("/api/auth-sessions/remove/<n>", methods=["DELETE"])
def api_remove_auth_session(n):
    sess_mgr.remove(n)
    return jsonify({"ok": True})


# ══════════════════════════════════════════════════════════════════════
# AI API
# ══════════════════════════════════════════════════════════════════════

@app.route("/api/ai/chat", methods=["POST"])
def api_ai_chat():
    d = request.json or {}
    return jsonify({"reply": ai.chat(d.get("message",""), d.get("context",None))})

@app.route("/api/ai/status")
def api_ai_status():
    return jsonify(ai.get_status())

@app.route("/api/ai/clear", methods=["POST"])
def api_ai_clear():
    ai.clear_history()
    return jsonify({"ok": True})


# ══════════════════════════════════════════════════════════════════════
# BOT API
# ══════════════════════════════════════════════════════════════════════

@app.route("/api/bot/status")
def api_bot_status():
    return jsonify({"running": tg_bot.is_running, "token_set": bool(tg_bot.token)})

@app.route("/api/bot/config", methods=["POST"])
def api_bot_config():
    d = request.json or {}
    tg_bot.save_config(d.get("token",""), d.get("allowed_ids",[]))
    tg_bot.start()
    return jsonify({"ok": True})

@app.route("/api/bot/test", methods=["POST"])
def api_bot_test():
    d  = request.json or {}
    ok = tg_bot._send(str(d.get("chat_id","")), "VAPT-Framework v3 connected!")
    return jsonify({"ok": ok})


# ══════════════════════════════════════════════════════════════════════
# API KEYS
# ══════════════════════════════════════════════════════════════════════

@app.route("/api/keys", methods=["GET"])
def api_list_keys():
    return jsonify(api_keys.list_all())

@app.route("/api/keys/set", methods=["POST"])
def api_set_key():
    d = request.json or {}
    service = d.get("service","").strip()
    key     = d.get("key","").strip()
    if not service or not key:
        return jsonify({"error":"service and key required"}), 400
    return jsonify(api_keys.set_key(service, key))

@app.route("/api/keys/remove", methods=["POST"])
def api_remove_key():
    d = request.json or {}
    service = d.get("service","")
    key     = d.get("key","")
    return jsonify(api_keys.remove_key(service, key or None))

@app.route("/api/keys/status")
def api_keys_status():
    all_keys = api_keys.list_all()
    configured = [s for s,v in all_keys.items() if v.get("configured")]
    return jsonify({
        "total_services":      len(all_keys),
        "configured_services": len(configured),
        "configured":          configured,
    })


# ══════════════════════════════════════════════════════════════════════
# TOOLS API
# ══════════════════════════════════════════════════════════════════════

@app.route("/api/tools/check")
def api_tools_check():
    from core.installer import TOOLS
    import subprocess
    result = {}
    for name, info in TOOLS.items():
        cmd = info.get("check",[name,"--version"])
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=5)
            result[name] = {"installed": r.returncode in (0,1), "desc": info["desc"]}
        except Exception:
            result[name] = {"installed": False, "desc": info["desc"]}
    return jsonify(result)

@app.route("/api/tools/install", methods=["POST"])
def api_tools_install():
    def _do():
        log = SocketLogger(socketio, "tools")
        ToolInstaller(log).install_all(dry_run=False)
        socketio.emit("tool_install_done", {"status":"complete"})
    threading.Thread(target=_do, daemon=True).start()
    return jsonify({"status":"started"})


# ══════════════════════════════════════════════════════════════════════
# NUCLEI API
# ══════════════════════════════════════════════════════════════════════

@app.route("/api/nuclei/scan", methods=["POST"])
def api_nuclei_scan():
    d      = request.json or {}
    target = d.get("target","")
    if not target:
        return jsonify({"error":"target required"}), 400
    sid    = d.get("session_id","")
    log    = SocketLogger(socketio, sid or "nuclei")
    engine = NucleiEngine(log, socketio=socketio, session_id=sid)
    result = engine.run(target,
                        tech_tags=d.get("tags",[]) or None,
                        severities=d.get("severities",["critical","high","medium"]))
    return jsonify(result)


# ══════════════════════════════════════════════════════════════════════
# WEBSOCKET
# ══════════════════════════════════════════════════════════════════════

@socketio.on("connect")
def on_connect():
    emit("connected", {"msg":"VAPT-Framework v3"})

@socketio.on("join_session")
def on_join(data):
    sid = data.get("session_id","").upper()
    s   = SESSIONS.get(sid)
    if s:
        emit("session_state", s)

@socketio.on("ai_chat")
def on_ai_chat(data):
    sid     = data.get("session_id","ai")
    message = data.get("message","")
    context = data.get("context", None)
    full    = ""
    for token in ai.stream_chat(message, context):
        full += token
        emit("ai_token", {"session_id": sid, "token": token})
    emit("ai_done", {"session_id": sid, "full": full})


# ══════════════════════════════════════════════════════════════════════
# SCAN RUNNER
# ══════════════════════════════════════════════════════════════════════

# Valid module names and their aliases
MODULE_ALIASES = {
    # Recon / subdomains
    "subdomains":    "recon",
    "subdomain":     "recon",
    "sub":           "recon",
    "enumeration":   "recon",
    "enumerate":     "recon",
    "osint":         "recon",
    "passive":       "recon",
    # Scan
    "portscan":      "scan",
    "ports":         "scan",
    "nmap":          "scan",
    "naabu":         "scan",
    # Web
    "webapp":        "web",
    "webaudit":      "web",
    "http":          "web",
    "nikto":         "web",
    "dirb":          "web",
    "fuzz":          "web",
    # CVE / exploit
    "cve":           "exploit",
    "cves":          "exploit",
    "vulns":         "exploit",
    "vulnerabilities":"exploit",
    # Path scanner
    "path":          "paths",
    "pathscan":      "paths",
    "sqli":          "paths",
    "xss":           "paths",
    # Nuclei
    "templates":     "nuclei",
    # Verify
    "verification":  "verify",
    # Metasploit
    "metasploit":    "msf",
    "msfconsole":    "msf",
    # Active Directory
    "activedirectory":"ad",
    "ldap":          "ad",
    "smb":           "ad",
    # All
    "full":          "all",
    "everything":    "all",
}

ALL_MODULES = ["recon","scan","web","nuclei","paths","verify","exploit","ad","msf","report"]

def _normalise_modules(modules: list) -> list:
    """Resolve module aliases and expand 'all'."""
    normalised = []
    for m in modules:
        m = m.strip().lower()
        if m in ("all","full","everything"):
            return ALL_MODULES
        resolved = MODULE_ALIASES.get(m, m)
        if resolved not in normalised:
            normalised.append(resolved)
    # Always include report if any scan module selected
    if normalised and "report" not in normalised:
        normalised.append("report")
    return normalised


def _create_session(target, ttype, modules):
    sid = str(uuid.uuid4())[:8].upper()
    SESSIONS[sid] = {
        "id": sid, "target": target, "type": ttype, "modules": modules,
        "status": "queued",
        "started": datetime.datetime.now().isoformat(),
        "findings": {}, "report_path": None,
        # Real-time progress tracking
        "progress": {
            "current_module": None,
            "modules_done":   [],
            "modules_total":  len(modules),
            "percent":        0,
            "eta_seconds":    None,
        },
    }
    return sid


def _run_scan(sid, target, ttype, modules, scope_data,
              proxy_mode=None, session_name=None,
              tg_chat_id=None, use_auto_proxy=False):
    """
    Parallel scan runner:
    - Phase 1 (parallel): tech_detect + recon run simultaneously
    - Phase 2 (parallel): port_scan + nuclei run simultaneously
    - Phase 3 (sequential): web_audit, paths, verify, ad, exploit, report
    Proxy scraper runs in its own daemon threads — never blocks scan.
    """
    log       = SocketLogger(socketio, sid)
    s         = SESSIONS[sid]
    paused    = threading.Event()
    stop_ev   = threading.Event()
    start_t   = time.time()
    done_lock = threading.Lock()
    done_count= [0]

    pm = auto_scraper if use_auto_proxy else (proxy_mgr if proxy_mode else None)

    def status(st, msg, **kw):
        s["status"] = st
        socketio.emit("scan_status",
                      {"session_id":sid,"status":st,"msg":msg,**kw})
        if tg_chat_id:
            tg_bot.notify(tg_chat_id, sid, "scan", st, msg)

    def prog(module, data):
        with done_lock:
            done_count[0] += 1
            dc = done_count[0]
        mod_total = max(len(modules), 1)
        pct = int(dc / mod_total * 100)
        elapsed = time.time() - start_t
        eta = int((elapsed / dc) * (mod_total - dc)) if dc else None
        s["progress"].update({
            "current_module": module,
            "modules_done":   s["progress"]["modules_done"] + [module],
            "percent":        pct,
            "eta_seconds":    eta,
        })
        socketio.emit("scan_progress",
                      {"session_id":sid,"module":module,"data":data,
                       "progress":s["progress"]})
        socketio.emit("scan_progress_bar",
                      {"session_id":sid,"module":module,"percent":pct,
                       "modules_done":dc,"modules_total":mod_total,
                       "eta_seconds":eta})

    def tg(module, detail=""):
        if tg_chat_id:
            tg_bot.notify(tg_chat_id, sid, module, "complete", detail)

    try:
        gate    = AuthorisationGate(log)
        session = gate.verify_programmatic(target, scope_data)
        if not session:
            status("error","Authorisation failed"); return

        scope   = ScopeParser(log)
        targets = scope.parse(target, ttype)
        log.info(f"Targets: {targets}")

        # Auto proxy setup
        if use_auto_proxy and targets:
            log.info("Finding best proxy for target…")
            best = auto_scraper.find_best_for_target(f"http://{targets[0]}")
            if best:
                current_proxy = best
                log.success(f"Proxy: {best['host']}:{best['port']} ({best['latency_ms']}ms)")
                tg(f"proxy", f"Best proxy: {best['host']}:{best['port']} ({best['latency_ms']}ms)")
                def on_pause():
                    paused.set()
                    status("paused","Proxy failed — scan paused")
                def on_resume(new_proxy):
                    paused.clear()
                    status("running",f"Resumed: {new_proxy['host']}:{new_proxy['port']}")
                threading.Thread(
                    target=auto_scraper.monitor_scan_proxy,
                    args=(sid, best, f"http://{targets[0]}",
                          on_pause, on_resume, stop_ev),
                    daemon=True).start()

        findings = {
            "meta":  {"session":session,"target":target,"type":ttype,
                      "started":datetime.datetime.now().isoformat(),
                      "modules":modules},
            "tech":  {},"recon":{},"scan":{},"web":{},"ad":{},
            "exploit":{},"nuclei":{},"verify":{},"paths":{},
            "ip_resolution":{},
        }

        for t in targets:
            log.banner(f"Target: {t}")
            while paused.is_set(): time.sleep(2)

            # ── PHASE 1: Parallel — tech detect + recon ──────────────
            phase1_results = {}
            phase1_errors  = {}

            def run_tech():
                try:
                    if "tech" in modules or "web" in modules:
                        status("running",f"Tech detect → {t}")
                        td = TechDetectModule(log, session_name=session_name)
                        phase1_results["tech"] = td.run(t)
                except Exception as e:
                    phase1_errors["tech"] = str(e)
                    log.error(f"Tech detect error: {e}")

            def run_recon():
                try:
                    if "recon" in modules:
                        status("running",f"Recon → {t}")
                        phase1_results["recon"] = ReconModule(log).run(t, ttype)
                except Exception as e:
                    phase1_errors["recon"] = str(e)
                    log.error(f"Recon error: {e}")

            th1 = threading.Thread(target=run_tech,  daemon=True)
            th2 = threading.Thread(target=run_recon, daemon=True)
            th1.start(); th2.start()
            th1.join();  th2.join()

            if "tech" in phase1_results:
                findings["tech"][t] = phase1_results["tech"]
                prog("tech", findings["tech"][t])
                td_data = findings["tech"][t]
                techs   = td_data.get("technologies", [])
                cms     = td_data.get("cms", "")
                server  = td_data.get("server", "")
                cves    = td_data.get("cve_hints", [])
                if techs:
                    msg = f"Technologies on {t}:\n" + "\n".join(f"  • {x}" for x in techs[:12])
                    if cms:    msg += f"\nCMS: {cms}"
                    if server: msg += f"\nServer: {server}"
                    if cves:   msg += f"\n⚠ CVE hints: {', '.join(cves[:4])}"
                else:
                    msg = f"No technologies detected on {t}. Tools (httpx/whatweb) may need installation."
                tg("tech", msg)

            if "recon" in phase1_results:
                findings["recon"][t] = phase1_results["recon"]
                prog("recon", findings["recon"][t])
                rd      = findings["recon"][t]
                subs    = rd.get("subdomains",{}).get("domains",[])
                emails  = rd.get("harvester",{}).get("emails",[])
                msg = f"Recon complete for {t}:"
                if subs:   msg += f"\n{len(subs)} subdomains: " + ", ".join(subs[:8])
                if emails: msg += f"\nEmails: " + ", ".join(emails[:4])
                tg("recon", msg)

            # IP resolution AFTER recon so we have subdomains
            status("running", f"IP resolve → {t}")
            ip_res     = IPResolver(log)
            subdomains = list(findings["recon"].get(t,{}).get("subdomains",{}).get("domains",[]))[:30]
            findings["ip_resolution"][t] = ip_res.resolve_all(t, subdomains)
            ip_data = findings["ip_resolution"][t]
            scan_ips = ip_data.get("scan_ips", [])
            skip_ips = ip_data.get("skip_ips", [])
            ip_lines = []
            for host, info in ip_data.get("hosts",{}).items():
                ip     = info.get("ip","N/A")
                is_cdn = info.get("is_cdn",False)
                cdn    = info.get("cdn_name","")
                status_str = f"({cdn} — CDN, skipped)" if is_cdn else "(direct — scanning)"
                ip_lines.append(f"  {host} → {ip} {status_str}")
            tg("ip", "IP Resolution:\n" + "\n".join(ip_lines[:8]))

            tech_tags = findings["tech"].get(t,{}).get("nuclei_tags",[])
            while paused.is_set(): time.sleep(2)

            # ── PHASE 2: Parallel — port scan + nuclei ───────────────
            phase2_results = {}

            def run_scan():
                try:
                    if "scan" in modules:
                        status("running",f"Port scan → {t}")
                        phase2_results["scan"] = ScannerModule(log).run(t, ttype)
                except Exception as e:
                    log.error(f"Port scan error: {e}")

            def run_nuclei():
                try:
                    if "nuclei" in modules or "web" in modules:
                        status("running",f"Nuclei → {t}")
                        engine = NucleiEngine(log, session_name=session_name,
                                              socketio=socketio, session_id=sid)
                        phase2_results["nuclei"] = engine.run(
                            t, tech_tags=tech_tags or None,
                            severities=["critical","high","medium","low"])
                except Exception as e:
                    log.error(f"Nuclei error: {e}")

            th3 = threading.Thread(target=run_scan,   daemon=True)
            th4 = threading.Thread(target=run_nuclei, daemon=True)
            th3.start(); th4.start()
            th3.join();  th4.join()

            if "scan" in phase2_results:
                findings["scan"][t] = phase2_results["scan"]
                prog("scan", findings["scan"][t])
                sd       = findings["scan"][t]
                open_p   = sd.get("open_ports",[])
                notable  = sd.get("notable",[])
                nmap_d   = sd.get("nmap_detail",{}) or {}
                # Build detailed port message for telegram
                msg = f"Port scan on {t}: {len(open_p)} open ports"
                if open_p:
                    msg += f"\nPorts: {', '.join(str(p) for p in open_p[:20])}"
                if notable:
                    msg += "\nNotable:"
                    for p in notable[:8]:
                        msg += f"\n  [{p['severity']}] Port {p['port']} ({p['service']}) — {p['note'][:60]}"
                # Nmap service banners
                hosts = nmap_d.get("hosts",[])
                if hosts:
                    msg += "\nServices:"
                    for host in hosts:
                        for pp in host.get("ports",[])[:8]:
                            svc = f"{pp.get('product','')} {pp.get('version','')}".strip()
                            if svc:
                                msg += f"\n  {pp['port']}/{pp['protocol']} {pp['service']} — {svc}"
                tg("scan", msg)

            if "nuclei" in phase2_results:
                findings["nuclei"][t] = phase2_results["nuclei"]
                prog("nuclei", findings["nuclei"][t])
                nf = findings["nuclei"][t]
                nc = nf.get("summary",{})
                tg("nuclei", f"Nuclei: {nf.get('total',0)} findings "
                   f"(crit:{nc.get('critical',0)} high:{nc.get('high',0)} "
                   f"med:{nc.get('medium',0)})")

            while paused.is_set(): time.sleep(2)

            # ── PHASE 3: Sequential — web, paths, verify, ad, msf, exploit
            if "web" in modules and ttype in ("domain","ip"):
                status("running",f"Web audit → {t}")
                findings["web"][t] = WebAuditModule(log).run(t)
                prog("web", findings["web"][t])
                wd = findings["web"][t]
                missing = wd.get("headers",{}).get("missing",[])
                tg("web", f"Web audit complete. Missing headers: {len(missing)}")

            if "web" in modules or "paths" in modules:
                while paused.is_set(): time.sleep(2)
                status("running",f"Path discovery + vuln check → {t}")
                proxy_url = None
                if use_auto_proxy and hasattr(auto_scraper, "get_best_proxy"):
                    bp = auto_scraper.get_best_proxy()
                    if bp:
                        proxy_url = f"{bp.get('protocol','http')}://{bp['host']}:{bp['port']}"
                ps = PathScanner(log, threads=25, proxy=proxy_url)
                orig_url = target if target.startswith("http") else f"http://{t}"
                path_res = ps.run(t, base_url=orig_url)
                for vf in path_res.get("vuln_findings",[]):
                    try: vf["ai_explanation"] = _explain_vuln(vf)
                    except: pass
                findings["paths"][t] = path_res
                prog("paths", findings["paths"][t])
                n  = len(path_res.get("vuln_findings",[]))
                np = len(path_res.get("paths_found",[]))
                msg = f"Path scan: {np} paths, {n} vulns"
                if n:
                    for vf in path_res.get("vuln_findings",[])[:4]:
                        msg += f"\n  [{vf.get('severity','')}] {vf.get('type','')} — {vf.get('url','')[:50]}"
                tg("paths", msg)

            if "verify" in modules:
                while paused.is_set(): time.sleep(2)
                status("running",f"Vuln verify → {t}")
                v   = VulnVerifier(timeout=12)
                raw = v.verify_all(f"http://{t}")
                for r in raw:
                    try: r["ai_explanation"] = _explain_vuln(r)
                    except: pass
                findings["verify"][t] = {"results":raw,"total":len(raw)}
                prog("verify", findings["verify"][t])
                tg("verify", f"Verified: {len(raw)} vulnerabilities")

            if "ad" in modules and ttype == "ad":
                while paused.is_set(): time.sleep(2)
                status("running",f"AD enum → {t}")
                findings["ad"][t] = ADEnumModule(log).run(t)
                prog("ad", findings["ad"][t])
                tg("ad", "AD enumeration complete")

            if "msf" in modules:
                while paused.is_set(): time.sleep(2)
                status("running",f"MSF → {t}")
                open_ports = findings["scan"].get(t,{}).get("open_ports",[])
                msf = MSFModule(log)
                findings["scan"][t]["msf"] = msf.run_from_scan(t, open_ports, auth_id=session["id"])
                prog("msf", findings["scan"][t]["msf"])

            if "exploit" in modules:
                while paused.is_set(): time.sleep(2)
                status("running",f"CVE check → {t}")
                findings["exploit"][t] = ExploitCheckModule(log).run(
                    findings["scan"].get(t,{}))
                prog("exploit", findings["exploit"][t])
                ec  = findings["exploit"][t]
                nc  = ec.get("cve_matches",[])
                msg = f"CVE check: {len(nc)} matches"
                for cv in nc[:4]:
                    msg += f"\n  [{cv.get('severity','')}] {cv.get('cve','')} — {cv.get('name','')}"
                tg("exploit", msg)

        stop_ev.set()
        findings["meta"]["finished"] = datetime.datetime.now().isoformat()
        s["findings"] = findings
        s["progress"]["percent"] = 100

        if "report" in modules:
            ts     = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            outdir = REPORTS_DIR / f"scan_{ts}_{sid}"
            outdir.mkdir(parents=True, exist_ok=True)
            ReportGenerator(log, outdir, "all").generate(findings)
            s["report_path"] = f"scan_{ts}_{sid}/report.html"
            status("complete","Scan complete", report=s["report_path"])
            if tg_chat_id:
                # Summary message
                all_f = ReportGenerator(log, outdir, "none")._collect(findings) if False else []
                tg_bot.notify(tg_chat_id, sid, "report", "complete",
                              f"Report ready:\nhttp://localhost:5000/report-files/{s['report_path']}")
                tg_bot._send_document(tg_chat_id, s["report_path"],
                                      f"VAPT_Report_{sid}.html")
        else:
            status("complete","Scan complete")

    except Exception as e:
        import traceback as _tb
        stop_ev.set()
        log.error(f"Fatal: {e}\n{_tb.format_exc()[:1000]}")
        status("error", str(e))

def _list_reports():
    out = []
    for d in sorted(REPORTS_DIR.iterdir(), reverse=True):
        html = d / "report.html"
        if html.exists():
            out.append({
                "name":    d.name,
                "url":     f"/report-files/{d.name}/report.html",
                "created": datetime.datetime.fromtimestamp(
                    d.stat().st_mtime).isoformat(),
            })
    return out[:30]


if __name__ == "__main__":
    print("\n  VAPT-Framework v3")
    print("  -> http://localhost:5000")
    print("  Default login: admin / admin123\n")
    socketio.run(app, host="0.0.0.0", port=5000,
                 debug=False, allow_unsafe_werkzeug=True)
