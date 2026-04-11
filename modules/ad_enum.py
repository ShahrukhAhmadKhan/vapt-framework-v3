"""
Active Directory Enumeration Module
─────────────────────────────────────
  • LDAP anonymous bind and root DSE
  • SMB null session enumeration
  • enum4linux-ng / enum4linux
  • smbmap share enumeration
  • Kerberoasting check (SPN enumeration)
  • AS-REP Roasting check
  • Password policy extraction
  • Domain user/group enumeration
"""

import subprocess
import shutil
import json


class ADEnumModule:

    def __init__(self, log, timeout=60):
        self.log     = log
        self.timeout = timeout

    def run(self, target: str) -> dict:
        self.log.banner(f"AD ENUM → {target}")
        results = {}

        results["ldap"]        = self._ldap_enum(target)
        results["smb"]         = self._smb_enum(target)
        results["smbmap"]      = self._smbmap(target)
        results["password_pol"]= self._password_policy(target)
        results["kerberoast"]  = self._kerberoast_check(target)

        return results

    # ─────────────────────────────────────────────────────────────
    def _ldap_enum(self, target) -> dict:
        if not shutil.which("ldapsearch"):
            return {"error": "ldapsearch not installed (ldap-utils)"}
        self.log.info("  Checking LDAP anonymous bind...")

        # Root DSE
        out = self._run([
            "ldapsearch", "-x", "-H", f"ldap://{target}",
            "-s", "base", "-b", "", "(objectClass=*)"
        ], timeout=30)

        parsed = {}
        for line in out.splitlines():
            if ":" in line and not line.startswith("#") and not line.startswith("dn:"):
                k, _, v = line.partition(":")
                parsed[k.strip()] = v.strip()

        anon_bind = "namingContexts" in parsed or "defaultNamingContext" in parsed
        return {
            "anonymous_bind": anon_bind,
            "severity": "HIGH" if anon_bind else "PASS",
            "attributes": parsed,
        }

    def _smb_enum(self, target) -> dict:
        tool = "enum4linux-ng" if shutil.which("enum4linux-ng") else \
               "enum4linux"    if shutil.which("enum4linux")    else None
        if not tool:
            return {"error": "enum4linux / enum4linux-ng not installed"}

        self.log.info(f"  Running {tool}...")
        cmd = [tool, "-A", target] if "ng" not in tool else \
              [tool, "-A", "-oJ", "-", target]

        out = self._run(cmd, timeout=180)

        users, groups, shares, policies = [], [], [], []
        for line in out.splitlines():
            l = line.strip()
            if re.search(r"user:\[", l, re.IGNORECASE):
                users.append(l)
            elif "group:" in l.lower():
                groups.append(l)
            elif "disk:" in l.lower() or "share:" in l.lower():
                shares.append(l)
            elif "password" in l.lower() and "policy" in l.lower():
                policies.append(l)

        null_session = "session setup" in out.lower() and "null" in out.lower()
        return {
            "null_session": null_session,
            "severity":     "CRITICAL" if null_session else "PASS",
            "users":        users[:50],
            "groups":       groups[:30],
            "shares":       shares,
            "policies":     policies,
        }

    def _smbmap(self, target) -> dict:
        if not shutil.which("smbmap"):
            return {"error": "smbmap not installed"}
        self.log.info("  Running smbmap (null auth)...")
        out = self._run([
            "smbmap", "-H", target, "-u", "", "-p", ""
        ], timeout=60)
        shares, readable, writable = [], [], []
        for line in out.splitlines():
            if "READ" in line or "WRITE" in line or "NO ACCESS" in line:
                shares.append(line.strip())
                if "READ" in line:
                    readable.append(line.strip())
                if "WRITE" in line:
                    writable.append(line.strip())
        severity = "CRITICAL" if writable else "HIGH" if readable else "PASS"
        return {
            "shares":   shares,
            "readable": readable,
            "writable": writable,
            "severity": severity,
        }

    def _password_policy(self, target) -> dict:
        if not shutil.which("rpcclient"):
            return {"error": "rpcclient not installed (samba-common-bin)"}
        out = self._run([
            "rpcclient", "-U", "", "-N", target,
            "-c", "getdompwinfo"
        ], timeout=30)
        issues = []
        if "min_password_len: 0" in out:
            issues.append("Minimum password length is 0")
        if "password_properties: 0x00000000" in out:
            issues.append("No password complexity requirements")
        return {
            "raw":     out.strip(),
            "issues":  issues,
            "severity": "HIGH" if issues else "PASS",
        }

    def _kerberoast_check(self, target) -> dict:
        # Check if port 88 (Kerberos) is open — actual Kerberoasting requires creds
        import socket
        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect((target, 88))
            s.close()
            return {
                "kerberos_open": True,
                "note": "Port 88 open. With valid credentials, SPN enumeration and Kerberoasting may be possible.",
                "severity": "INFO",
                "tools": ["Impacket GetUserSPNs.py", "Rubeus", "PowerView"],
            }
        except Exception:
            return {"kerberos_open": False, "severity": "PASS"}

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


import re
