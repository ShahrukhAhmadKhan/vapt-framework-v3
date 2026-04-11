"""
Web Audit Module
─────────────────
Web application vulnerability assessment:
  • nikto (server misconfigs, outdated software)
  • nuclei (ProjectDiscovery template-based scanning)
  • gobuster / ffuf (directory and file bruteforce)
  • katana (web crawler)
  • SSL/TLS analysis
  • Security headers check
  • WordPress scan (if WP detected)
"""

import subprocess
import shutil
import json
import urllib.request
import ssl
import socket
import re
from pathlib import Path


WORDLISTS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/opt/SecLists/Discovery/Web-Content/common.txt",
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
]


class WebAuditModule:

    def __init__(self, log, threads=10, timeout=30):
        self.log     = log
        self.threads = threads
        self.timeout = timeout

    def run(self, target: str) -> dict:
        self.log.banner(f"WEB AUDIT → {target}")
        results = {}

        # Determine scheme
        base_url = self._probe_scheme(target)
        results["base_url"] = base_url

        results["headers"]       = self._check_headers(base_url)
        results["ssl"]           = self._check_ssl(target)
        results["nikto"]         = self._nikto(target)
        results["nuclei"]        = self._nuclei(target)
        results["directories"]   = self._dir_brute(base_url)
        results["crawler"]       = self._crawl(base_url)

        # WordPress?
        if self._is_wordpress(base_url):
            self.log.info("  WordPress detected — running wpscan")
            results["wpscan"] = self._wpscan(target)

        return results

    # ─────────────────────────────────────────────────────────────
    def _probe_scheme(self, target) -> str:
        for scheme in ("https", "http"):
            url = f"{scheme}://{target}"
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                req = urllib.request.Request(url, method="HEAD")
                urllib.request.urlopen(req, timeout=10, context=ctx if scheme == "https" else None)
                return url
            except Exception:
                continue
        return f"http://{target}"

    def _check_headers(self, url) -> dict:
        found, missing = {}, []
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            req  = urllib.request.Request(url)
            resp = urllib.request.urlopen(req, timeout=10, context=ctx)
            hdrs = dict(resp.headers)
            server  = hdrs.get("Server", "not disclosed")
            powered = hdrs.get("X-Powered-By", "not disclosed")
            found["Server"]       = server
            found["X-Powered-By"] = powered

            for h in SECURITY_HEADERS:
                if any(h.lower() == k.lower() for k in hdrs):
                    found[h] = "present"
                else:
                    missing.append(h)
        except Exception as e:
            found["error"] = str(e)

        return {"present": found, "missing": missing,
                "severity": "MEDIUM" if missing else "PASS"}

    def _check_ssl(self, host) -> dict:
        try:
            ctx  = ssl.create_default_context()
            conn = ctx.wrap_socket(socket.socket(), server_hostname=host)
            conn.settimeout(self.timeout)
            conn.connect((host, 443))
            cert    = conn.getpeercert()
            version = conn.version()
            cipher  = conn.cipher()
            conn.close()
            issues = []
            if version in ("TLSv1","TLSv1.1","SSLv2","SSLv3"):
                issues.append(f"Weak TLS version: {version}")
            return {
                "version":  version,
                "cipher":   cipher[0] if cipher else "unknown",
                "subject":  dict(x[0] for x in cert.get("subject",[])),
                "expires":  cert.get("notAfter",""),
                "issues":   issues,
                "severity": "HIGH" if issues else "PASS",
            }
        except ssl.SSLError as e:
            return {"error": str(e), "severity": "HIGH"}
        except Exception as e:
            return {"error": str(e), "severity": "INFO"}

    def _nikto(self, target) -> dict:
        if not shutil.which("nikto"):
            return {"error": "nikto not installed"}
        self.log.info("  Running nikto...")
        out = self._run([
            "nikto", "-h", target, "-Format", "json",
            "-Tuning", "123456789a", "-maxtime", "300"
        ], timeout=360)
        try:
            data = json.loads(out)
            return {"vulnerabilities": data.get("vulnerabilities", []), "source": "nikto"}
        except json.JSONDecodeError:
            # Parse plain text output
            vulns = []
            for line in out.splitlines():
                if "+ " in line:
                    vulns.append(line.strip())
            return {"vulnerabilities": vulns, "source": "nikto_text"}

    def _nuclei(self, target) -> dict:
        if not shutil.which("nuclei"):
            return {"error": "nuclei not installed"}
        self.log.info("  Running nuclei (critical + high + medium templates)...")
        # Update templates silently first
        self._run(["nuclei", "-update-templates", "-silent"], timeout=60)

        out = self._run([
            "nuclei", "-u", target,
            "-severity", "critical,high,medium",
            "-json",
            "-silent",
            "-timeout", str(self.timeout),
            "-bulk-size", str(self.threads),
        ], timeout=600)

        findings = []
        for line in out.splitlines():
            try:
                d = json.loads(line)
                findings.append({
                    "template":  d.get("template-id",""),
                    "name":      d.get("info",{}).get("name",""),
                    "severity":  d.get("info",{}).get("severity","").upper(),
                    "url":       d.get("matched-at",""),
                    "extracted": d.get("extracted-results",[]),
                })
            except Exception:
                pass
        return {"findings": findings, "total": len(findings)}

    def _dir_brute(self, url) -> dict:
        wordlist = next((w for w in WORDLISTS if Path(w).exists()), None)
        if not wordlist:
            return {"error": "No wordlist found. Install seclists: apt install seclists"}

        if shutil.which("gobuster"):
            self.log.info("  Running gobuster directory scan...")
            out = self._run([
                "gobuster", "dir",
                "-u", url,
                "-w", wordlist,
                "-t", str(self.threads),
                "-q", "-o", "-",
                "--timeout", f"{self.timeout}s",
            ], timeout=300)
            found = [l.strip() for l in out.splitlines() if l.startswith("/")]
            return {"tool": "gobuster", "found": found, "total": len(found)}

        if shutil.which("ffuf"):
            self.log.info("  Running ffuf directory scan...")
            out = self._run([
                "ffuf", "-u", f"{url}/FUZZ",
                "-w", wordlist,
                "-t", str(self.threads),
                "-fc", "404",
                "-of", "json", "-o", "-",
            ], timeout=300)
            try:
                data  = json.loads(out)
                found = [r.get("url","") for r in data.get("results",[])]
                return {"tool": "ffuf", "found": found, "total": len(found)}
            except Exception:
                return {"tool": "ffuf", "raw": out[:500]}

        return {"error": "Neither gobuster nor ffuf is installed"}

    def _crawl(self, url) -> dict:
        if not shutil.which("katana"):
            return {"error": "katana not installed"}
        self.log.info("  Running katana crawler...")
        out = self._run([
            "katana", "-u", url, "-silent",
            "-depth", "3",
            "-concurrency", str(self.threads),
            "-timeout", str(self.timeout),
        ], timeout=180)
        urls = [l.strip() for l in out.splitlines() if l.strip().startswith("http")]
        return {"urls_found": len(urls), "sample": urls[:50]}

    def _is_wordpress(self, url) -> bool:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            resp = urllib.request.urlopen(f"{url}/wp-login.php", timeout=8, context=ctx)
            return resp.status == 200
        except Exception:
            return False

    def _wpscan(self, target) -> dict:
        if not shutil.which("wpscan"):
            return {"error": "wpscan not installed. Run: gem install wpscan"}
        out = self._run([
            "wpscan", "--url", target,
            "--enumerate", "vp,vt,u",
            "--format", "json",
        ], timeout=300)
        try:
            return json.loads(out)
        except Exception:
            return {"raw": out[:1000]}

    # ─────────────────────────────────────────────────────────────
    def _run(self, cmd, timeout=60):
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
