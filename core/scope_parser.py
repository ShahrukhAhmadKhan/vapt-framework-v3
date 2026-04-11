"""
Scope / Target Parser — Fixed
Handles full URLs, strips protocol/path to give tools just the hostname.
  http://testaspnet.vulnweb.com/login.aspx  →  testaspnet.vulnweb.com
  https://192.168.1.1:8080/admin            →  192.168.1.1
"""

import ipaddress
import urllib.parse
from pathlib import Path


class ScopeParser:

    def __init__(self, log):
        self.log = log

    def parse(self, target: str, target_type: str) -> list:
        if target_type == "list":
            return self._parse_file(target)
        if target_type == "range":
            return self._parse_cidr(target)
        return [self._normalise(target.strip())]

    def _normalise(self, target: str) -> str:
        if "://" in target:
            parsed = urllib.parse.urlparse(target)
            host   = parsed.hostname or parsed.netloc
            if host and ":" in host:
                host = host.split(":")[0]
            if host:
                if self.log:
                    self.log.info(f"  URL normalised: {target} -> {host}")
                return host
        return target

    def _parse_file(self, path: str) -> list:
        p = Path(path)
        if not p.exists():
            self.log.error(f"Target file not found: {path}")
            return []
        lines = [
            self._normalise(l.strip())
            for l in p.read_text().splitlines()
            if l.strip() and not l.startswith("#")
        ]
        self.log.info(f"Loaded {len(lines)} targets from {path}")
        return lines

    def _parse_cidr(self, cidr: str) -> list:
        cidr = self._normalise(cidr)
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            hosts   = [str(h) for h in network.hosts()]
            self.log.info(f"CIDR {cidr} -> {len(hosts)} hosts")
            return hosts
        except ValueError as e:
            self.log.error(f"Invalid CIDR: {e}")
            return [cidr]
