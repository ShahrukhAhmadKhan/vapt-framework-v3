"""
Nuclei Engine — Enhanced
─────────────────────────
• Auto-selects templates based on detected technologies
• Session-aware (injects auth headers/cookies)
• Proxy-aware
• Custom template support
• Real-time finding streaming via WebSocket
• Severity filtering
• Rate limiting controls
"""

import subprocess
import shutil
import json
import os
from pathlib import Path
from typing import Optional


SEVERITY_ALL      = ["critical","high","medium","low","info"]
SEVERITY_HIGH     = ["critical","high"]
SEVERITY_CRITICAL = ["critical"]

NUCLEI_TEMPLATES_DIR = Path.home() / "nuclei-templates"


class NucleiEngine:

    def __init__(self, log, session_name: str = None, proxy_manager=None, socketio=None, session_id=None):
        self.log        = log
        self.session    = session_name
        self.proxy      = proxy_manager
        self.socketio   = socketio
        self.session_id = session_id

    def run(self, target: str, tech_tags: list = None,
            severities: list = None, custom_templates: list = None,
            rate_limit: int = 150, threads: int = 25,
            timeout: int = 10) -> dict:
        """
        Run nuclei with smart template selection.
        tech_tags: from TechDetectModule (e.g. ['wordpress','apache'])
        """
        self.log.banner(f"NUCLEI ENGINE → {target}")

        if not shutil.which("nuclei"):
            self.log.error("nuclei not installed. Run: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
            return {"error": "nuclei not installed", "findings": []}

        # Update templates silently
        self._update_templates()

        severities = severities or ["critical","high","medium"]
        findings   = []

        # ── Build nuclei command ──────────────────────────────────
        cmd = [
            "nuclei",
            "-u", target,
            "-severity", ",".join(severities),
            "-rate-limit", str(rate_limit),
            "-concurrency", str(threads),
            "-timeout", str(timeout),
            "-json",
            "-silent",
            "-no-color",
        ]

        # Session headers
        if self.session:
            from core.session_manager import get_session_manager
            sm = get_session_manager()
            for flag in sm.get_nuclei_flags(self.session):
                cmd.append(flag)

        # Proxy
        if self.proxy:
            p = self.proxy.get_proxy()
            if p:
                cmd += ["-proxy", p["url"]]

        # Technology-aware template tags
        if tech_tags:
            tag_str = ",".join(tech_tags)
            cmd += ["-tags", tag_str]
            self.log.info(f"  Using tech-aware templates: {tag_str}")
        else:
            # Default: run all templates (slower but comprehensive)
            pass

        # Custom templates
        if custom_templates:
            for tpl in custom_templates:
                if Path(tpl).exists():
                    cmd += ["-t", tpl]

        self.log.info(f"  Severities: {', '.join(severities)}")
        self.log.info(f"  Rate limit: {rate_limit} req/s | Threads: {threads}")

        # ── Stream output ─────────────────────────────────────────
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, errors="replace",
            )
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    finding = self._parse_finding(d, target)
                    findings.append(finding)
                    self.log.finding(
                        finding["severity"].upper(),
                        finding["name"],
                        finding.get("url","")
                    )
                    # Stream to GUI
                    if self.socketio and self.session_id:
                        self.socketio.emit("nuclei_finding", {
                            "session_id": self.session_id,
                            "finding":    finding,
                        })
                except json.JSONDecodeError:
                    pass
            proc.wait()
        except Exception as e:
            self.log.error(f"Nuclei error: {e}")

        # Summary
        summary = self._summarise(findings)
        self.log.success(f"  Nuclei complete: {len(findings)} findings "
                         f"({summary['critical']} critical, {summary['high']} high)")
        return {"findings": findings, "total": len(findings), "summary": summary}

    # ── Targeted scans ────────────────────────────────────────────
    def run_cve_scan(self, target: str) -> dict:
        """Run only CVE templates."""
        return self.run(target, severities=["critical","high"], tech_tags=["cve"])

    def run_exposure_scan(self, target: str) -> dict:
        """Run exposure + misconfig templates."""
        return self.run(target, tech_tags=["exposure","misconfig","default-login"])

    def run_xss_sqli(self, target: str) -> dict:
        """Run XSS + SQLi templates."""
        return self.run(target, tech_tags=["xss","sqli","injection"])

    # ── Template management ───────────────────────────────────────
    def list_templates(self, tag: str = None) -> list:
        """List available nuclei templates."""
        if not NUCLEI_TEMPLATES_DIR.exists():
            return []
        pattern = f"**/*{tag}*.yaml" if tag else "**/*.yaml"
        templates = list(NUCLEI_TEMPLATES_DIR.glob(pattern))
        return [str(t.relative_to(NUCLEI_TEMPLATES_DIR)) for t in templates[:100]]

    def _update_templates(self):
        try:
            subprocess.run(
                ["nuclei", "-update-templates", "-silent"],
                capture_output=True, timeout=60
            )
        except Exception:
            pass

    # ── Helpers ───────────────────────────────────────────────────
    def _parse_finding(self, d: dict, target: str) -> dict:
        info = d.get("info", {})
        return {
            "template_id":  d.get("template-id", ""),
            "name":         info.get("name", ""),
            "severity":     info.get("severity", "info"),
            "description":  info.get("description", ""),
            "reference":    info.get("reference", []),
            "tags":         info.get("tags", []),
            "cvss_score":   info.get("classification",{}).get("cvss-score",""),
            "cve_id":       info.get("classification",{}).get("cve-id",""),
            "url":          d.get("matched-at", target),
            "extracted":    d.get("extracted-results", []),
            "matcher_name": d.get("matcher-name",""),
            "curl_command": d.get("curl-command",""),
            "target":       target,
        }

    def _summarise(self, findings: list) -> dict:
        s = {sev: 0 for sev in ["critical","high","medium","low","info"]}
        for f in findings:
            k = f.get("severity","info").lower()
            s[k] = s.get(k, 0) + 1
        return s
