"""
API Key Manager
────────────────
Manages API keys for external services:
  • Subfinder sources: Shodan, Chaos, Virustotal, SecurityTrails, etc.
  • Shodan (direct search)
  • VirusTotal
  • Censys

Keys are stored in config/api_keys.json and automatically
loaded into subfinder's provider-config.yaml.
"""

import json
import yaml
import os
from pathlib import Path

KEYS_FILE        = Path("config/api_keys.json")
SUBFINDER_CONFIG = Path.home() / ".config/subfinder/provider-config.yaml"

# All sources subfinder supports that need API keys
SUBFINDER_SOURCES = {
    "shodan":         {"keys": [], "note": "Get at shodan.io — student accounts work"},
    "chaos":          {"keys": [], "note": "ProjectDiscovery chaos.projectdiscovery.io"},
    "virustotal":     {"keys": [], "note": "virustotal.com — free account gives key"},
    "securitytrails": {"keys": [], "note": "securitytrails.com"},
    "censys":         {"secrets": [], "note": "censys.io — free account"},
    "bevigil":        {"keys": [], "note": "bevigil.com"},
    "binaryedge":     {"keys": [], "note": "binaryedge.io"},
    "bufferover":     {"keys": [], "note": "tls.bufferover.run"},
    "c99":            {"keys": [], "note": "c99.nl"},
    "fullhunt":       {"keys": [], "note": "fullhunt.io"},
    "github":         {"keys": [], "note": "github.com personal access token"},
    "hunter":         {"keys": [], "note": "hunter.io"},
    "intelx":         {"keys": [], "note": "intelx.io"},
    "leakix":         {"keys": [], "note": "leakix.net"},
    "netlas":         {"keys": [], "note": "netlas.io"},
    "quake":          {"keys": [], "note": "quake.360.net"},
    "shodan":         {"keys": [], "note": "shodan.io"},
    "zoomeye":        {"keys": [], "note": "zoomeye.org"},
    "whoisxmlapi":    {"keys": [], "note": "whoisxmlapi.com — free 500/month"},
}


class APIKeyManager:

    def __init__(self, log=None):
        self.log  = log
        self.keys = {}
        self._load()

    def _load(self):
        if KEYS_FILE.exists():
            try:
                self.keys = json.loads(KEYS_FILE.read_text())
            except Exception:
                self.keys = {}

    def _save(self):
        KEYS_FILE.parent.mkdir(exist_ok=True)
        KEYS_FILE.write_text(json.dumps(self.keys, indent=2))

    def set_key(self, service: str, key: str) -> dict:
        """Add/update an API key."""
        service = service.lower().strip()
        if service not in self.keys:
            self.keys[service] = []
        if key not in self.keys[service]:
            self.keys[service].append(key)
        self._save()
        self._update_subfinder_config()
        if self.log:
            self.log.success(f"API key saved for {service}")
        return {"service": service, "keys_count": len(self.keys[service])}

    def remove_key(self, service: str, key: str = None) -> dict:
        """Remove a key or all keys for a service."""
        service = service.lower().strip()
        if key:
            self.keys[service] = [k for k in self.keys.get(service, []) if k != key]
        else:
            self.keys.pop(service, None)
        self._save()
        self._update_subfinder_config()
        return {"service": service, "removed": True}

    def get_keys(self, service: str) -> list:
        return self.keys.get(service.lower(), [])

    def list_all(self) -> dict:
        result = {}
        for service, info in SUBFINDER_SOURCES.items():
            keys = self.keys.get(service, [])
            result[service] = {
                "configured": len(keys) > 0,
                "keys_count": len(keys),
                "note":       info.get("note", ""),
            }
        # Add non-subfinder keys
        for service, keys in self.keys.items():
            if service not in result:
                result[service] = {
                    "configured": True,
                    "keys_count": len(keys),
                    "note":       "",
                }
        return result

    def _update_subfinder_config(self):
        """Write subfinder provider-config.yaml from stored keys."""
        SUBFINDER_CONFIG.parent.mkdir(parents=True, exist_ok=True)
        config = {}
        for service in SUBFINDER_SOURCES:
            keys = self.keys.get(service, [])
            if keys:
                # subfinder uses different field names per source
                if service in ("censys",):
                    config[service] = keys  # censys uses list of id:secret pairs
                else:
                    config[service] = keys
        if config:
            try:
                SUBFINDER_CONFIG.write_text(yaml.dump(config, default_flow_style=False))
                if self.log:
                    self.log.success(f"Subfinder config updated: {len(config)} sources")
            except Exception as e:
                if self.log:
                    self.log.error(f"Failed to write subfinder config: {e}")
                # Fallback: write raw JSON-like YAML
                lines = []
                for svc, keys in config.items():
                    lines.append(f"{svc}:")
                    for k in keys:
                        lines.append(f"  - {k}")
                SUBFINDER_CONFIG.write_text("\n".join(lines) + "\n")

    def get_shodan_key(self) -> str:
        keys = self.keys.get("shodan", [])
        return keys[0] if keys else ""

    def get_virustotal_key(self) -> str:
        keys = self.keys.get("virustotal", [])
        return keys[0] if keys else ""


# Singleton
_instance = None
def get_api_key_manager(log=None) -> APIKeyManager:
    global _instance
    if _instance is None:
        _instance = APIKeyManager(log)
    return _instance
