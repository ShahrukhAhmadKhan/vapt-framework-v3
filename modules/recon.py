"""
Recon Module
─────────────
Passive + active reconnaissance:
  • WHOIS
  • DNS enumeration (A, MX, NS, TXT, CNAME)
  • Subdomain discovery (subfinder, amass, dnsx)
  • theHarvester (emails, hosts, IPs)
  • OSINT: Shodan (if API key), Google dork suggestions
  • HTTP technology fingerprinting (whatweb, httpx)
  • WAF detection (wafw00f)
"""

import subprocess
import shutil
import json
import socket
import re
from concurrent.futures import ThreadPoolExecutor, as_completed


class ReconModule:

    def __init__(self, log, threads=10, timeout=30):
        self.log     = log
        self.threads = threads
        self.timeout = timeout

    def run(self, target: str, target_type: str) -> dict:
        self.log.banner(f"RECON → {target}")
        results = {}

        tasks = {
            "whois":       lambda: self._whois(target),
            "dns":         lambda: self._dns_enum(target),
            "subdomains":  lambda: self._subdomains(target) if target_type == "domain" else {},
            "harvester":   lambda: self._harvester(target),
            "httpx_probe": lambda: self._httpx_probe(target),
            "waf":         lambda: self._waf_detect(target) if target_type == "domain" else {},
            "whatweb":     lambda: self._whatweb(target),
            "reverse_dns": lambda: self._reverse_dns(target) if target_type == "ip" else {},
        }

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(fn): name for name, fn in tasks.items()}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    results[name] = future.result()
                    self.log.success(f"  Recon/{name} complete")
                except Exception as e:
                    self.log.error(f"  Recon/{name} failed: {e}")
                    results[name] = {"error": str(e)}

        return results

    # ─────────────────────────────────────────────────────────────
    def _whois(self, target):
        if not shutil.which("whois"):
            return {"error": "whois not installed"}
        out = self._run(["whois", target], timeout=self.timeout)
        # Parse key fields
        parsed = {}
        for line in out.splitlines():
            for key in ("Registrar","Registrant","Creation Date","Expiry Date","Name Server","CIDR","NetRange","OrgName","Country"):
                if key.lower() in line.lower() and ":" in line:
                    k, _, v = line.partition(":")
                    parsed[k.strip()] = v.strip()
        return {"raw_lines": len(out.splitlines()), "parsed": parsed}

    def _dns_enum(self, target):
        results = {}
        if not shutil.which("dnsrecon"):
            # Fallback: basic socket lookups
            try:
                results["A"] = socket.gethostbyname_ex(target)[2]
            except Exception:
                results["A"] = []
            return results

        out = self._run(["dnsrecon", "-d", target, "-t", "std"], timeout=60)
        record_types = {}
        for line in out.splitlines():
            for rtype in ("A","AAAA","MX","NS","TXT","CNAME","SOA","PTR"):
                if f" {rtype} " in line:
                    record_types.setdefault(rtype, []).append(line.strip())
        return record_types

    def _subdomains(self, domain):
        found = set()

        # 1. subfinder (ProjectDiscovery) — best passive source
        if shutil.which("subfinder"):
            self.log.info(f"  Running subfinder on {domain}…")
            cmd = ["subfinder", "-d", domain, "-silent", "-all",
                   "-timeout", "30"]
            # Load provider config if it exists
            import pathlib
            cfg = pathlib.Path.home() / ".config/subfinder/provider-config.yaml"
            if cfg.exists():
                cmd += ["-pc", str(cfg)]
            out = self._run(cmd, timeout=180)
            new = {l.strip() for l in out.splitlines()
                   if l.strip() and domain in l}
            found.update(new)
            self.log.success(f"  subfinder: {len(new)} subdomains")

        # 2. assetfinder
        if shutil.which("assetfinder"):
            out = self._run(["assetfinder", "--subs-only", domain], timeout=60)
            new = {l.strip() for l in out.splitlines()
                   if l.strip() and domain in l}
            found.update(new)
            self.log.success(f"  assetfinder: {len(new)} subdomains")

        # 3. amass (passive)
        if shutil.which("amass"):
            out = self._run(["amass", "enum", "-passive", "-d", domain,
                             "-timeout", "3"], timeout=240)
            new = {l.strip() for l in out.splitlines()
                   if l.strip() and domain in l}
            found.update(new)
            self.log.success(f"  amass: {len(new)} subdomains")

        # 4. Certificate Transparency — crt.sh (no API key needed)
        ct_subs = self._crtsh(domain)
        found.update(ct_subs)
        if ct_subs:
            self.log.success(f"  crt.sh: {len(ct_subs)} subdomains")

        # 5. Wayback Machine URLs for subdomain hints
        wb_subs = self._wayback_subdomains(domain)
        found.update(wb_subs)

        # 6. gau (GetAllURLs) for more subdomain hints
        if shutil.which("gau"):
            out = self._run(["gau", "--subs", domain], timeout=60)
            import re
            new = set()
            for line in out.splitlines():
                m = re.search(r'https?://([^/]+)', line)
                if m:
                    host = m.group(1).lower()
                    if host.endswith(f".{domain}"):
                        new.add(host)
            found.update(new)

        # 7. Brute force with dnsx if found subdomains to resolve
        resolved = []
        if shutil.which("dnsx") and found:
            import tempfile, os as _os
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                f.write("\n".join(sorted(found)))
                fname = f.name
            out = self._run(["dnsx", "-l", fname, "-a", "-resp",
                             "-silent", "-timeout", "5"], timeout=180)
            resolved = [l.strip() for l in out.splitlines() if l.strip()]
            _os.unlink(fname)
        elif found:
            # Fallback: basic DNS check
            import socket as _sock
            alive = []
            for sub in list(found)[:100]:
                try:
                    _sock.gethostbyname(sub)
                    alive.append(sub)
                except Exception:
                    pass
            resolved = alive

        total = len(found)
        self.log.success(f"  Total unique subdomains: {total}")

        return {
            "total":    total,
            "domains":  sorted(found),
            "resolved": resolved,
        }

    def _crtsh(self, domain: str) -> set:
        """Certificate transparency via crt.sh — finds many subdomains."""
        import urllib.request, json, ssl, re
        found = set()
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            req = urllib.request.Request(url,
                headers={"User-Agent":"VAPTFramework/3.0"})
            with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
                data = json.loads(r.read())
            for entry in data:
                for name in str(entry.get("name_value","")).split("\n"):
                    name = name.strip().lstrip("*.")
                    if name.endswith(f".{domain}") or name == domain:
                        found.add(name.lower())
        except Exception as e:
            self.log.debug(f"  crt.sh error: {e}")
        return found

    def _wayback_subdomains(self, domain: str) -> set:
        """Extract subdomains from Wayback Machine CDX API."""
        import urllib.request, ssl, re
        found = set()
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            url = (f"http://web.archive.org/cdx/search/cdx?url=*.{domain}"
                   f"&output=text&fl=original&collapse=urlkey&limit=5000")
            req = urllib.request.Request(url,
                headers={"User-Agent":"VAPTFramework/3.0"})
            with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
                body = r.read().decode(errors="replace")
            for line in body.splitlines():
                m = re.search(r"https?://([^/:]+)", line)
                if m:
                    host = m.group(1).lower()
                    if host.endswith(f".{domain}"):
                        found.add(host)
        except Exception:
            pass
        return found

    def _harvester(self, target):
        if not shutil.which("theHarvester"):
            return {"error": "theHarvester not installed"}
        out = self._run([
            "theHarvester", "-d", target, "-b", "bing,google,dnsdumpster,crtsh",
            "-l", "200"
        ], timeout=120)

        emails, hosts, ips = [], [], []
        for line in out.splitlines():
            line = line.strip()
            if re.match(r"[^@]+@[^@]+\.[^@]+", line):
                emails.append(line)
            elif re.match(r"\d+\.\d+\.\d+\.\d+", line):
                ips.append(line)
            elif "." in line and len(line) > 4:
                hosts.append(line)

        return {"emails": list(set(emails)), "hosts": list(set(hosts)), "ips": list(set(ips))}

    def _httpx_probe(self, target):
        if not shutil.which("httpx"):
            return {"error": "httpx not installed"}
        out = self._run([
            "httpx", "-u", target, "-title", "-tech-detect",
            "-status-code", "-content-length", "-silent"
        ], timeout=60)
        return {"results": [l.strip() for l in out.splitlines() if l.strip()]}

    def _waf_detect(self, target):
        if not shutil.which("wafw00f"):
            return {"error": "wafw00f not installed"}
        for scheme in (f"https://{target}", f"http://{target}"):
            out = self._run(["wafw00f", scheme], timeout=30)
            if "is behind" in out.lower() or "no waf" in out.lower():
                return {"output": out.strip()}
        return {"output": "No result"}

    def _whatweb(self, target):
        if not shutil.which("whatweb"):
            return {"error": "whatweb not installed"}
        for scheme in (f"https://{target}", f"http://{target}"):
            out = self._run(["whatweb", "--color=never", scheme], timeout=30)
            if out.strip():
                return {"output": out.strip()}
        return {"output": "No result"}

    def _reverse_dns(self, ip):
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return {"hostname": hostname}
        except Exception:
            return {"hostname": None}

    # ─────────────────────────────────────────────────────────────
    def _run(self, cmd, timeout=30):
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout, errors="replace"
            )
            return r.stdout + r.stderr
        except subprocess.TimeoutExpired:
            return ""
        except FileNotFoundError:
            return ""
        except Exception as e:
            return str(e)
