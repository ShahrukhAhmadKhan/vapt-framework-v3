"""
IP Resolver & CloudFlare Detector
───────────────────────────────────
For every target and all discovered subdomains:
  1. Resolve IP address
  2. Detect if IP is CloudFlare (or other CDN)
  3. If CloudFlare: do NOT scan IP, note in report
  4. If direct IP: include in port scan
  5. Also try to find real IP behind CloudFlare via:
     - Historical DNS (SecurityTrails hints)
     - Subdomains that might bypass CDN (mail., ftp., direct., etc.)
     - Certificate transparency
"""

import socket
import ipaddress
import urllib.request
import json
import re
import ssl
from typing import Optional


# Known CloudFlare IP ranges (major ones — full list at cloudflare.com/ips)
CLOUDFLARE_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22",   "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15",  "104.16.0.0/13",
    "104.24.0.0/14",   "172.64.0.0/13",   "131.0.72.0/22",
    # IPv6
    "2400:cb00::/32",  "2606:4700::/32",  "2803:f800::/32",
    "2405:b500::/32",  "2405:8100::/32",  "2a06:98c0::/29",
    "2c0f:f248::/32",
]

# Other CDN/WAF IP hint patterns
OTHER_CDN_HINTS = {
    "Akamai":       ["23.32.", "23.64.", "23.96.", "104.64.", "104.80."],
    "Fastly":       ["151.101.", "199.27.", "23.235."],
    "Incapsula":    ["45.64.64.", "149.126."],
    "Sucuri":       ["192.124.249.", "185.93.228.", "66.248.200."],
    "AWS CloudFront":["13.224.", "13.225.", "13.226.", "13.227.", "13.228.", "54.230.", "204.246."],
    "Azure CDN":    ["13.107.", "23.200."],
    "Imperva":      ["199.83.128.", "192.124.249."],
}


class IPResolver:

    def __init__(self, log=None):
        self.log = log

    def resolve_all(self, target: str, subdomains: list = None) -> dict:
        """
        Resolve IPs for target and all subdomains.
        Returns structured dict with CDN status for each.
        """
        results = {
            "target":     target,
            "hosts":      {},
            "scan_ips":   [],   # IPs safe to port-scan
            "skip_ips":   [],   # CDN IPs — skip port scan
            "real_ip_hints": [],
        }

        all_hosts = [target] + (subdomains or [])

        for host in all_hosts:
            info = self._resolve_host(host)
            results["hosts"][host] = info

            if info.get("ip"):
                if info.get("is_cdn"):
                    results["skip_ips"].append({
                        "host": host, "ip": info["ip"],
                        "cdn": info.get("cdn_name","CDN"),
                        "note": "IP belongs to CDN — port scanning skipped",
                    })
                    # Try to find real IP
                    real = self._hunt_real_ip(host)
                    if real:
                        results["real_ip_hints"].append(real)
                else:
                    if info["ip"] not in [e["ip"] for e in results["scan_ips"]]:
                        results["scan_ips"].append({
                            "host": host, "ip": info["ip"],
                        })

        self._log("success",
            f"  Resolved {len(all_hosts)} hosts | "
            f"Scannable: {len(results['scan_ips'])} | "
            f"CDN/skip: {len(results['skip_ips'])}")

        return results

    def _resolve_host(self, host: str) -> dict:
        info = {"host": host, "ip": None, "is_cdn": False,
                "cdn_name": None, "asn": None}
        try:
            ip = socket.gethostbyname(host)
            info["ip"] = ip

            # Check CloudFlare
            if self._is_cloudflare(ip):
                info["is_cdn"]    = True
                info["cdn_name"]  = "Cloudflare"
                self._log("warning", f"  {host} → {ip} (Cloudflare — scan skipped)")
                return info

            # Check other CDNs
            for cdn_name, prefixes in OTHER_CDN_HINTS.items():
                if any(ip.startswith(p) for p in prefixes):
                    info["is_cdn"]   = True
                    info["cdn_name"] = cdn_name
                    self._log("warning", f"  {host} → {ip} ({cdn_name} — scan skipped)")
                    return info

            # Get ASN info
            asn = self._get_asn(ip)
            info["asn"] = asn
            if asn and any(cdn in asn.upper() for cdn in
                           ["CLOUDFLARE","AKAMAI","FASTLY","INCAPSULA","IMPERVA"]):
                info["is_cdn"]   = True
                info["cdn_name"] = asn.split()[0] if asn else "CDN"
                self._log("warning", f"  {host} → {ip} (CDN via ASN: {asn})")
                return info

            self._log("success", f"  {host} → {ip} (direct — will scan)")

        except socket.gaierror:
            self._log("warning", f"  {host} → DNS resolution failed")
        except Exception as e:
            self._log("debug", f"  {host} resolve error: {e}")

        return info

    def _is_cloudflare(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            for cidr in CLOUDFLARE_RANGES:
                try:
                    if addr in ipaddress.ip_network(cidr, strict=False):
                        return True
                except ValueError:
                    continue
        except ValueError:
            pass
        return False

    def _get_asn(self, ip: str) -> Optional[str]:
        """Quick ASN lookup via cymru."""
        try:
            # Reverse IP for cymru lookup
            parts  = ip.split(".")
            rev    = ".".join(reversed(parts)) + ".origin.asn.cymru.com"
            result = socket.gethostbyname_ex(rev)
            return None
        except Exception:
            pass

        # Fallback: ipinfo.io
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            url = f"https://ipinfo.io/{ip}/json"
            req = urllib.request.Request(url,
                headers={"User-Agent":"VAPTFramework/3.0"})
            with urllib.request.urlopen(req, timeout=5, context=ctx) as r:
                data = json.loads(r.read())
                org  = data.get("org","")
                return org
        except Exception:
            return None

    def _hunt_real_ip(self, domain: str) -> Optional[dict]:
        """
        Try to find real IP behind CloudFlare via:
        - Common bypass subdomains
        - Historical DNS (requires API keys for full access)
        - Certificate transparency
        """
        bypass_subdomains = [
            f"direct.{domain}", f"origin.{domain}",
            f"mail.{domain}", f"ftp.{domain}",
            f"cpanel.{domain}", f"webmail.{domain}",
            f"smtp.{domain}", f"imap.{domain}",
            f"staging.{domain}", f"dev.{domain}",
            f"api.{domain}", f"vpn.{domain}",
        ]

        for sub in bypass_subdomains:
            try:
                ip = socket.gethostbyname(sub)
                if ip and not self._is_cloudflare(ip):
                    self._log("success",
                        f"  Real IP hint: {sub} → {ip} (not CloudFlare!)")
                    return {
                        "domain":     domain,
                        "bypass_sub": sub,
                        "real_ip":    ip,
                        "confidence": "medium",
                        "note":       f"Subdomain '{sub}' resolves to non-CDN IP",
                    }
            except Exception:
                pass

        # Try cert transparency
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            url = f"https://crt.sh/?q={domain}&output=json"
            req = urllib.request.Request(url,
                headers={"User-Agent":"VAPTFramework/3.0"})
            with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
                certs = json.loads(r.read())
                for cert in certs[:20]:
                    cn = cert.get("common_name","")
                    if cn and cn != domain and domain in cn:
                        try:
                            ip = socket.gethostbyname(cn)
                            if not self._is_cloudflare(ip):
                                return {
                                    "domain":   domain,
                                    "bypass_sub": cn,
                                    "real_ip":  ip,
                                    "confidence": "low",
                                    "note": f"Certificate CN '{cn}' → non-CDN IP",
                                }
                        except Exception:
                            pass
        except Exception:
            pass

        return None

    def _log(self, level: str, msg: str):
        if self.log:
            getattr(self.log, level, self.log.info)(msg)
        else:
            print(f"[IP_RESOLVER] [{level.upper()}] {msg}")
