"""
Path Scanner & Per-Path Vulnerability Engine
─────────────────────────────────────────────
1. Discovers all paths using ffuf/gobuster/dirb
2. Crawls discovered pages with katana
3. Extracts all parameters from each path
4. Runs full vulnerability checks on EVERY path:
   - SQLi (error, boolean-blind, time-based)
   - XSS (reflected)
   - Path traversal
   - IDOR
   - Open redirect
   - Command injection
5. Groups findings by URL and severity
"""

import subprocess
import shutil
import json
import re
import urllib.parse
import urllib.request
import ssl
import time
import threading
from pathlib import Path
from typing import Optional


# Extended wordlists — tries in order, uses first found
WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirb/big.txt",
]

# Extensions to try
EXTENSIONS = "php,asp,aspx,jsp,html,htm,txt,xml,json,bak,old,zip,sql,config,env"


class PathScanner:

    def __init__(self, log=None, threads=30, timeout=20, proxy: str = None):
        self.log     = log
        self.threads = threads
        self.timeout = timeout
        self.proxy   = proxy

    def run(self, target: str, base_url: str = None) -> dict:
        """
        Full path discovery + per-path vuln scanning.
        target: hostname (e.g. testaspnet.vulnweb.com)
        base_url: original URL with path (e.g. http://testaspnet.vulnweb.com/login.aspx)
        """
        self._log("banner", f"PATH SCANNER → {target}")

        scheme   = "http"
        base_url = base_url or f"{scheme}://{target}"
        if not base_url.startswith("http"):
            base_url = f"{scheme}://{target}"

        results = {
            "target":        target,
            "base_url":      base_url,
            "paths_found":   [],
            "forms_found":   [],
            "params_found":  [],
            "vuln_findings": [],
        }

        # 1. Discover paths
        paths = self._discover_paths(target, base_url)
        results["paths_found"] = paths
        self._log("success", f"  Discovered {len(paths)} paths")

        # 2. Crawl for more paths and extract forms/params
        crawled = self._crawl(base_url)
        for url in crawled:
            if url not in paths:
                paths.append(url)
        results["paths_found"] = paths

        # 3. Extract forms and parameters from all paths
        forms, params = self._extract_forms_and_params(paths)
        results["forms_found"]  = forms
        results["params_found"] = params
        self._log("success",
            f"  Forms: {len(forms)} | URLs with params: {len(params)}")

        # 4. Run vuln checks on every URL with params + every form
        self._log("info", f"  Running vuln checks on {len(params)+len(forms)} attack surfaces…")
        vuln_findings = []

        # Check parameterised URLs
        for entry in params:
            url       = entry["url"]
            url_params = entry["params"]
            findings  = self._scan_url(url, url_params)
            vuln_findings.extend(findings)

        # Check forms (POST)
        for form in forms:
            findings = self._scan_form(form)
            vuln_findings.extend(findings)

        results["vuln_findings"] = vuln_findings
        self._log("success",
            f"  Path scan complete: {len(vuln_findings)} vulnerabilities found")

        return results

    # ── Path Discovery ─────────────────────────────────────────────
    def _discover_paths(self, target: str, base_url: str) -> list:
        paths = set()
        wordlist = self._get_wordlist()

        # ffuf
        if shutil.which("ffuf") and wordlist:
            self._log("info", "  Running ffuf path discovery…")
            fuzz_url = f"{base_url.rstrip('/')}/FUZZ"
            cmd = [
                "ffuf", "-u", fuzz_url, "-w", wordlist,
                "-t", str(self.threads), "-mc", "200,201,301,302,403,500",
                "-of", "json", "-o", "-",
                "-e", f".{EXTENSIONS.replace(',',',.')}",
                "-timeout", str(self.timeout),
                "-fs", "0",   # filter empty responses
            ]
            if self.proxy:
                cmd += ["-x", self.proxy]
            out = self._run(cmd, timeout=300)
            try:
                data = json.loads(out)
                for r in data.get("results", []):
                    paths.add(r.get("url",""))
            except Exception:
                # Parse plain output
                for line in out.splitlines():
                    m = re.search(r'https?://\S+', line)
                    if m:
                        paths.add(m.group(0))

        # gobuster (if ffuf found nothing or not installed)
        if (not paths or not shutil.which("ffuf")) and shutil.which("gobuster") and wordlist:
            self._log("info", "  Running gobuster path discovery…")
            cmd = [
                "gobuster", "dir",
                "-u", base_url, "-w", wordlist,
                "-t", str(self.threads),
                "-x", EXTENSIONS,
                "-q", "--no-error",
                "--timeout", f"{self.timeout}s",
            ]
            if self.proxy:
                cmd += ["--proxy", self.proxy]
            out = self._run(cmd, timeout=300)
            for line in out.splitlines():
                if line.startswith("/"):
                    path = line.split()[0]
                    paths.add(f"{base_url.rstrip('/')}{path}")
                elif "http" in line:
                    m = re.search(r'(https?://\S+)', line)
                    if m:
                        paths.add(m.group(1))

        # Always include the original base URL
        paths.add(base_url)

        # Add common paths for ASP.NET (detected from tech)
        common_aspnet = [
            "/login.aspx", "/default.aspx", "/index.aspx",
            "/admin/", "/admin/login.aspx",
            "/search.aspx", "/register.aspx",
            "/user/", "/account/", "/profile.aspx",
            "/api/", "/ws/", "/service.asmx",
            "/web.config", "/global.asax",
        ]
        for p in common_aspnet:
            paths.add(f"http://{target}{p}")

        return sorted(paths)

    def _crawl(self, base_url: str) -> list:
        """Use katana to crawl and find more URLs."""
        if not shutil.which("katana"):
            return []
        self._log("info", "  Crawling with katana…")
        cmd = [
            "katana", "-u", base_url,
            "-depth", "4", "-silent",
            "-jc",           # JS crawling
            "-kf", "all",    # known files
            "-concurrency", str(self.threads),
            "-timeout", str(self.timeout),
        ]
        if self.proxy:
            cmd += ["-proxy", self.proxy]
        out = self._run(cmd, timeout=180)
        urls = []
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("http") and base_url.split("/")[2] in line:
                urls.append(line)
        return list(set(urls))

    # ── Form + Parameter Extraction ────────────────────────────────
    def _extract_forms_and_params(self, urls: list) -> tuple:
        forms  = []
        params = []
        seen   = set()

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        for url in urls[:100]:  # cap at 100 URLs
            if url in seen:
                continue
            seen.add(url)

            # Extract params from URL query string
            parsed = urllib.parse.urlparse(url)
            qs     = urllib.parse.parse_qs(parsed.query)
            if qs:
                params.append({"url": url, "params": list(qs.keys())})

            # Fetch and parse forms
            try:
                req  = urllib.request.Request(
                    url,
                    headers={"User-Agent":"Mozilla/5.0 VAPTScanner/3.0"}
                )
                with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
                    body = r.read(256*1024).decode(errors="replace")
                    page_forms = self._parse_forms(url, body)
                    forms.extend(page_forms)
            except Exception:
                pass

        return forms, params

    def _parse_forms(self, page_url: str, html: str) -> list:
        """Extract all forms from HTML."""
        forms = []
        # Find form blocks
        for form_match in re.finditer(
                r'<form[^>]*>(.*?)</form>', html,
                re.IGNORECASE | re.DOTALL):
            form_html = form_match.group(0)

            # Action
            action_m  = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method_m  = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            action    = action_m.group(1) if action_m else page_url
            method    = method_m.group(1).upper() if method_m else "GET"

            # Resolve relative action
            if action and not action.startswith("http"):
                action = urllib.parse.urljoin(page_url, action)

            # Input fields
            fields = {}
            for inp in re.finditer(
                    r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>',
                    form_html, re.IGNORECASE):
                name  = inp.group(1)
                type_m = re.search(r'type=["\']([^"\']*)["\']', inp.group(0), re.IGNORECASE)
                itype = type_m.group(1).lower() if type_m else "text"
                # Default values
                if itype == "hidden":
                    val_m = re.search(r'value=["\']([^"\']*)["\']', inp.group(0), re.IGNORECASE)
                    fields[name] = val_m.group(1) if val_m else ""
                elif itype not in ("submit","button","image","reset"):
                    fields[name] = "test"

            if fields:
                forms.append({
                    "action":    action,
                    "method":    method,
                    "fields":    fields,
                    "page_url":  page_url,
                })

        return forms

    # ── Vulnerability Scanning ─────────────────────────────────────
    def _scan_url(self, url: str, params: list) -> list:
        """Run all vuln checks on a parameterised URL."""
        from modules.vuln_verifier import VulnVerifier
        v       = VulnVerifier(timeout=10, proxy=self.proxy)
        results = v.verify_all(url, params)
        for r in results:
            r["source_url"] = url
            r["method"]     = "GET"
        return results

    def _scan_form(self, form: dict) -> list:
        """Test a form for vulnerabilities (POST-based)."""
        findings = []
        action   = form["action"]
        fields   = form["fields"]
        method   = form["method"]

        SQLI_PAYLOADS = ["'", "''", "' OR '1'='1", "'; DROP TABLE--", "1' AND SLEEP(3)--"]
        SQLI_ERRORS   = ["sql syntax","mysql_fetch","ORA-","syntax error","SQLite","SQLSTATE"]

        for field_name in fields:
            for payload in SQLI_PAYLOADS:
                test_fields = dict(fields)
                test_fields[field_name] = payload

                status, body = self._post(action, test_fields)

                # Error-based
                for err in SQLI_ERRORS:
                    if err.lower() in body.lower():
                        findings.append({
                            "vuln":       True,
                            "type":       "SQL Injection (Form/POST)",
                            "severity":   "CRITICAL",
                            "evidence":   f"DB error '{err}' in response to POST payload",
                            "payload":    payload,
                            "param":      field_name,
                            "url":        action,
                            "source_url": form["page_url"],
                            "method":     method,
                            "remediation":"Use parameterised queries in all database operations.",
                        })
                        break

                # XSS
                xss_payload = f'<script>alert("VAPTFW")</script>'
                test_fields2 = dict(fields)
                test_fields2[field_name] = xss_payload
                _, xss_body = self._post(action, test_fields2)
                if xss_payload in xss_body or "VAPTFW" in xss_body:
                    findings.append({
                        "vuln":       True,
                        "type":       "Reflected XSS (Form/POST)",
                        "severity":   "HIGH",
                        "evidence":   f"XSS payload reflected in POST response (field: {field_name})",
                        "payload":    xss_payload,
                        "param":      field_name,
                        "url":        action,
                        "source_url": form["page_url"],
                        "method":     method,
                        "remediation":"Encode all output. Implement Content-Security-Policy.",
                    })

        return findings

    def _post(self, url: str, data: dict) -> tuple:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        try:
            body_bytes = urllib.parse.urlencode(data).encode()
            req = urllib.request.Request(
                url, data=body_bytes, method="POST",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent":   "Mozilla/5.0 VAPTScanner/3.0",
                }
            )
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as r:
                return r.status, r.read(128*1024).decode(errors="replace")
        except Exception as e:
            return 0, str(e)

    # ── Helpers ───────────────────────────────────────────────────
    def _get_wordlist(self) -> Optional[str]:
        for w in WORDLISTS:
            if Path(w).exists():
                return w
        return None

    def _run(self, cmd, timeout=120) -> str:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout, errors="replace")
            return r.stdout + r.stderr
        except subprocess.TimeoutExpired:
            return ""
        except FileNotFoundError:
            return ""
        except Exception as e:
            return str(e)

    def _log(self, level: str, msg: str):
        if self.log:
            getattr(self.log, level, self.log.info)(msg)
        else:
            print(f"[PATH_SCANNER] [{level.upper()}] {msg}")
