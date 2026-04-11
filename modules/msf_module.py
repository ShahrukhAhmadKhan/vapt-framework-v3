"""
Metasploit Integration Module
──────────────────────────────
Runs authorised Metasploit modules against targets via:
  • msfconsole CLI (subprocess)
  • Docker Kali container (isolated)

IMPORTANT: Only runs check/auxiliary modules by default.
Exploit modules require explicit --allow-exploit flag per engagement.
All sessions are logged with timestamp and authorisation ID.
"""

import subprocess
import shutil
import json
import os
import time
import threading
from pathlib import Path


# Safe auxiliary modules for VA (check/scan, not exploit)
SAFE_MODULES = {
    "smb_version":     "auxiliary/scanner/smb/smb_version",
    "smb_ms17_010":    "auxiliary/scanner/smb/smb_ms17_010",
    "rdp_scanner":     "auxiliary/scanner/rdp/rdp_scanner",
    "ftp_version":     "auxiliary/scanner/ftp/ftp_version",
    "ftp_anonymous":   "auxiliary/scanner/ftp/anonymous",
    "ssh_version":     "auxiliary/scanner/ssh/ssh_version",
    "http_version":    "auxiliary/scanner/http/http_version",
    "ssl_version":     "auxiliary/scanner/ssl/openssl_heartbleed",
    "mysql_version":   "auxiliary/scanner/mysql/mysql_version",
    "mssql_ping":      "auxiliary/scanner/mssql/mssql_ping",
    "redis_server":    "auxiliary/scanner/redis/redis_server",
    "mongodb_detect":  "auxiliary/scanner/mongodb/mongodb_detect",
    "smtp_enum":       "auxiliary/scanner/smtp/smtp_enum",
    "snmp_enum":       "auxiliary/scanner/snmp/snmp_enum",
    "dns_bruteforce":  "auxiliary/gather/dns_bruteforce",
    "http_title":      "auxiliary/scanner/http/title",
    "dir_scanner":     "auxiliary/scanner/http/dir_scanner",
    "wp_scanner":      "auxiliary/scanner/http/wordpress_scanner",
    "vnc_none_auth":   "auxiliary/scanner/vnc/vnc_none_auth",
    "ldap_enum":       "auxiliary/gather/ldap_query",
}


class MSFModule:

    def __init__(self, log, use_docker: bool = False):
        self.log        = log
        self.use_docker = use_docker
        self._check_msf()

    def _check_msf(self):
        if self.use_docker:
            self.available = shutil.which("docker") is not None
            self.method    = "docker"
        elif shutil.which("msfconsole"):
            self.available = True
            self.method    = "local"
        else:
            self.available = False
            self.method    = "none"

    # ── Run a module ──────────────────────────────────────────────
    def run_module(self, module_key: str, target: str, port: int = None,
                   extra_opts: dict = None, auth_id: str = "") -> dict:
        """
        Run a safe auxiliary/scanner module.
        module_key: key from SAFE_MODULES dict
        """
        if not self.available:
            return {"error": "msfconsole not available. Install Metasploit or use Docker mode."}

        module = SAFE_MODULES.get(module_key)
        if not module:
            return {"error": f"Unknown module: {module_key}. Use list_modules() to see available."}

        self.log.banner(f"MSF → {module_key} @ {target}")
        self.log.info(f"  Auth ID: {auth_id or 'interactive'}")

        # Build RC script
        opts = extra_opts or {}
        rc_lines = [
            f"use {module}",
            f"set RHOSTS {target}",
        ]
        if port:
            rc_lines.append(f"set RPORT {port}")
        for k, v in opts.items():
            rc_lines.append(f"set {k.upper()} {v}")
        rc_lines += ["run", "exit -y"]

        rc_content = "\n".join(rc_lines)
        rc_path    = Path("/tmp/vapt_msf.rc")
        rc_path.write_text(rc_content)

        self.log.debug(f"  RC: {rc_content}")

        if self.method == "local":
            return self._run_local(rc_path, module_key, target)
        elif self.method == "docker":
            return self._run_docker(rc_content, module_key, target)

    def _run_local(self, rc_path: Path, module_key: str, target: str) -> dict:
        try:
            result = subprocess.run(
                ["msfconsole", "-q", "-r", str(rc_path)],
                capture_output=True, text=True, timeout=120, errors="replace"
            )
            output = result.stdout + result.stderr
            self.log.info(f"  MSF output: {len(output.splitlines())} lines")
            return self._parse_output(output, module_key, target)
        except subprocess.TimeoutExpired:
            return {"error": "MSF timeout (120s)", "output": ""}
        except Exception as e:
            return {"error": str(e), "output": ""}

    def _run_docker(self, rc_content: str, module_key: str, target: str) -> dict:
        """Run msfconsole in a Docker Kali container."""
        try:
            cmd = [
                "docker", "run", "--rm", "--network=host",
                "kalilinux/kali-rolling",
                "bash", "-c",
                f"apt-get install -y -q metasploit-framework 2>/dev/null; "
                f"echo '{rc_content}' | msfconsole -q -r /dev/stdin"
            ]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300, errors="replace"
            )
            output = result.stdout + result.stderr
            return self._parse_output(output, module_key, target)
        except subprocess.TimeoutExpired:
            return {"error": "Docker MSF timeout (300s)"}
        except Exception as e:
            return {"error": str(e)}

    # ── Run multiple modules against scan results ─────────────────
    def run_from_scan(self, target: str, open_ports: list, auth_id: str = "") -> dict:
        """Auto-select modules based on open ports."""
        PORT_MODULE_MAP = {
            21:   "ftp_version",
            22:   "ssh_version",
            25:   "smtp_enum",
            80:   "http_version",
            110:  None,
            135:  None,
            139:  "smb_version",
            143:  None,
            389:  "ldap_enum",
            443:  "http_version",
            445:  ["smb_version","smb_ms17_010"],
            3306: "mysql_version",
            3389: "rdp_scanner",
            5432: None,
            5900: "vnc_none_auth",
            6379: "redis_server",
            8080: "http_title",
            8443: "http_title",
            9200: None,
            27017:"mongodb_detect",
        }

        results = {}
        for port in open_ports:
            mods = PORT_MODULE_MAP.get(port)
            if not mods:
                continue
            if isinstance(mods, str):
                mods = [mods]
            for mod in mods:
                key = f"{mod}_{port}"
                results[key] = self.run_module(mod, target, port=port, auth_id=auth_id)

        return results

    # ── Output parser ─────────────────────────────────────────────
    def _parse_output(self, output: str, module_key: str, target: str) -> dict:
        lines    = output.splitlines()
        findings = []
        for line in lines:
            l = line.strip()
            if any(kw in l.lower() for kw in
                   ["vulnerable","found","detected","open","running","version",
                    "success","login","anonymous","error code"]):
                findings.append(l)

        is_vuln = any("vulnerable" in l.lower() or "success" in l.lower()
                      for l in findings)
        return {
            "module":   module_key,
            "target":   target,
            "findings": findings,
            "vulnerable": is_vuln,
            "raw_lines": len(lines),
        }

    # ── Utilities ─────────────────────────────────────────────────
    def list_modules(self) -> dict:
        return SAFE_MODULES

    def generate_msf_report(self, results: dict) -> str:
        """Generate a text report from MSF scan results."""
        lines = ["=" * 60, "METASPLOIT SCAN REPORT", "=" * 60, ""]
        for key, r in results.items():
            lines.append(f"Module: {r.get('module',key)}")
            lines.append(f"Target: {r.get('target','')}")
            lines.append(f"Vulnerable: {'YES ⚠' if r.get('vulnerable') else 'No'}")
            for f in r.get("findings", []):
                lines.append(f"  → {f}")
            lines.append("")
        return "\n".join(lines)
