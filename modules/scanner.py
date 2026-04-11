"""
Scanner Module
──────────────
Port scanning and service fingerprinting:
  • nmap (TCP SYN, service version, OS detection, NSE scripts)
  • naabu (fast port discovery)
  • masscan (optional ultra-fast sweep for large ranges)
  • CVE cross-referencing via nmap scripts
"""

import subprocess
import shutil
import json
import re
import xml.etree.ElementTree as ET


# Common dangerous ports and notes for the report
NOTABLE_PORTS = {
    21:   ("FTP",       "MEDIUM", "Check anonymous login, weak creds, old versions"),
    22:   ("SSH",       "LOW",    "Check version, key auth enforcement"),
    23:   ("Telnet",    "HIGH",   "Unencrypted protocol — critical if exposed"),
    25:   ("SMTP",      "MEDIUM", "Check open relay, banner leakage"),
    53:   ("DNS",       "MEDIUM", "Check zone transfer, DNSSEC"),
    80:   ("HTTP",      "LOW",    "Enumerate web app"),
    110:  ("POP3",      "MEDIUM", "Check unencrypted auth"),
    111:  ("RPC",       "HIGH",   "RPC misconfig is common attack vector"),
    135:  ("MSRPC",     "HIGH",   "Windows RPC — often exploitable"),
    139:  ("NetBIOS",   "HIGH",   "SMB null sessions, enumeration"),
    143:  ("IMAP",      "MEDIUM", "Check unencrypted auth"),
    389:  ("LDAP",      "HIGH",   "Check anonymous bind, AD enumeration"),
    443:  ("HTTPS",     "LOW",    "Enumerate web app, check TLS"),
    445:  ("SMB",       "CRITICAL","EternalBlue, pass-the-hash, ransomware vector"),
    512:  ("rexec",     "CRITICAL","Legacy — almost always exploitable"),
    513:  ("rlogin",    "CRITICAL","Legacy — almost always exploitable"),
    514:  ("syslog",    "MEDIUM", "Unauthenticated log injection possible"),
    631:  ("CUPS",      "MEDIUM", "Check for unauth print server"),
    873:  ("rsync",     "HIGH",   "Check unauthenticated access"),
    1433: ("MSSQL",     "HIGH",   "Database exposure — check credentials"),
    1521: ("Oracle DB", "HIGH",   "Database exposure"),
    2049: ("NFS",       "HIGH",   "Check exported shares"),
    3306: ("MySQL",     "HIGH",   "Database exposure — check credentials"),
    3389: ("RDP",       "HIGH",   "BlueKeep, credential brute force vector"),
    4444: ("Metasploit","CRITICAL","Default Metasploit handler port"),
    5432: ("PostgreSQL","HIGH",   "Database exposure"),
    5900: ("VNC",       "HIGH",   "Unencrypted remote desktop"),
    5985: ("WinRM",     "HIGH",   "Windows remote management"),
    6379: ("Redis",     "CRITICAL","Unauthenticated Redis = code execution"),
    8080: ("HTTP-Alt",  "LOW",    "Enumerate web app"),
    8443: ("HTTPS-Alt", "LOW",    "Enumerate web app, check TLS"),
    9200: ("Elasticsearch","CRITICAL","Unauthenticated ES = data exposure"),
    27017:("MongoDB",   "CRITICAL","Unauthenticated Mongo = data exposure"),
}

NSE_SCRIPTS = [
    "vuln",
    "auth",
    "default",
    "banner",
    "http-headers",
    "ssl-cert",
    "ssl-enum-ciphers",
    "smb-vuln-ms17-010",       # EternalBlue
    "smb-vuln-ms08-067",
    "rdp-vuln-ms12-020",
    "ftp-anon",
    "ftp-bounce",
    "smtp-open-relay",
    "mysql-empty-password",
    "redis-info",
    "mongodb-info",
    "dns-zone-transfer",
    "ldap-rootdse",
]


class ScannerModule:

    def __init__(self, log, threads=10, timeout=30):
        self.log     = log
        self.threads = threads
        self.timeout = timeout

    def run(self, target: str, target_type: str) -> dict:
        self.log.banner(f"SCAN → {target}")
        results = {}

        # Fast port discovery first
        open_ports = self._fast_port_scan(target)
        results["open_ports"] = open_ports
        self.log.info(f"  Found {len(open_ports)} open ports")

        # Deep nmap on discovered ports
        if open_ports:
            results["nmap_detail"] = self._nmap_deep(target, open_ports)
        else:
            # Full nmap if fast scan returned nothing
            results["nmap_detail"] = self._nmap_full(target)

        # Annotate notable ports
        results["notable"] = self._annotate_ports(open_ports)

        return results

    # ─────────────────────────────────────────────────────────────
    def _fast_port_scan(self, target) -> list:
        # Try naabu first (fast), fallback to nmap
        if shutil.which("naabu"):
            self.log.debug("Using naabu for fast port discovery")
            out = self._run([
                "naabu", "-host", target,
                "-p", "-",            # all ports
                "-rate", "1000",
                "-silent", "-json"
            ], timeout=300)
            ports = []
            for line in out.splitlines():
                try:
                    d = json.loads(line)
                    if "port" in d:
                        ports.append(int(d["port"]))
                except Exception:
                    pass
            if ports:
                return sorted(set(ports))

        # Fallback: nmap fast scan
        if shutil.which("nmap"):
            self.log.debug("Using nmap fast scan")
            out = self._run([
                "nmap", "-p-", "--min-rate", "1000",
                "-T4", "--open", "-oG", "-", target
            ], timeout=300)
            ports = []
            for line in out.splitlines():
                if "Ports:" in line:
                    for m in re.finditer(r"(\d+)/open", line):
                        ports.append(int(m.group(1)))
            return sorted(set(ports))

        return []

    def _nmap_deep(self, target, ports: list) -> dict:
        if not shutil.which("nmap"):
            return {"error": "nmap not installed"}

        port_str   = ",".join(str(p) for p in ports[:200])  # cap at 200 ports
        script_str = ",".join(NSE_SCRIPTS)

        self.log.info(f"  Running deep nmap on {len(ports)} ports with NSE scripts...")
        out = self._run([
            "nmap", "-sV", "-sC",
            "-p", port_str,
            "--script", script_str,
            "-O", "--osscan-guess",
            "-oX", "-",
            target
        ], timeout=600)

        return self._parse_nmap_xml(out)

    def _nmap_full(self, target) -> dict:
        if not shutil.which("nmap"):
            return {"error": "nmap not installed"}
        self.log.info("  Running full nmap scan (no pre-discovered ports)...")
        out = self._run([
            "nmap", "-sV", "-sC", "-p", "1-65535",
            "--min-rate", "500",
            "-oX", "-", target
        ], timeout=600)
        return self._parse_nmap_xml(out)

    def _parse_nmap_xml(self, xml_str: str) -> dict:
        result = {"hosts": [], "raw_xml_lines": len(xml_str.splitlines())}
        try:
            root = ET.fromstring(xml_str)
            for host in root.findall("host"):
                h = {"address": "", "hostnames": [], "ports": [], "os": [], "scripts": []}

                addr = host.find("address")
                if addr is not None:
                    h["address"] = addr.get("addr","")

                for hn in host.findall(".//hostname"):
                    h["hostnames"].append(hn.get("name",""))

                for port in host.findall(".//port"):
                    state = port.find("state")
                    if state is None or state.get("state") != "open":
                        continue
                    service = port.find("service")
                    p = {
                        "port":     int(port.get("portid",0)),
                        "protocol": port.get("protocol","tcp"),
                        "service":  service.get("name","") if service is not None else "",
                        "product":  service.get("product","") if service is not None else "",
                        "version":  service.get("version","") if service is not None else "",
                        "scripts":  [],
                    }
                    for script in port.findall("script"):
                        p["scripts"].append({
                            "id":     script.get("id",""),
                            "output": script.get("output","")[:500],
                        })
                    h["ports"].append(p)

                for osmatch in host.findall(".//osmatch"):
                    h["os"].append({
                        "name":     osmatch.get("name",""),
                        "accuracy": osmatch.get("accuracy",""),
                    })

                result["hosts"].append(h)
        except ET.ParseError:
            result["parse_error"] = "XML parse failed (tool may not have run)"
        return result

    def _annotate_ports(self, ports: list) -> list:
        notes = []
        for p in ports:
            if p in NOTABLE_PORTS:
                svc, severity, note = NOTABLE_PORTS[p]
                notes.append({
                    "port":     p,
                    "service":  svc,
                    "severity": severity,
                    "note":     note,
                })
        return notes

    # ─────────────────────────────────────────────────────────────
    def _run(self, cmd, timeout=60):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout, errors="replace")
            return r.stdout + r.stderr
        except subprocess.TimeoutExpired:
            self.log.warning(f"  Timeout: {' '.join(cmd[:3])}")
            return ""
        except FileNotFoundError:
            return ""
        except Exception as e:
            return str(e)
