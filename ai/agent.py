"""
Agentic VA/PT Assistant
────────────────────────
Uses local Ollama model to:
  1. Understand a target description in plain language
  2. Plan the appropriate scan strategy
  3. Execute scans automatically
  4. Interpret results and decide next steps
  5. Generate findings explanations
  6. Summarise everything in plain English

Works via chat — user says "scan example.com and tell me what's vulnerable"
and the agent handles everything.

Uses standard Ollama models (llama3.2:3b or better) — works well for
security reasoning and scan planning without needing any special models.
"""

import json
import re
import threading
from typing import Optional, Callable

from ai.ollama_assistant import OllamaAssistant


AGENT_SYSTEM = """You are an expert automated penetration testing agent integrated into VAPT-Framework v3.
You help security professionals by:
1. Understanding their target and goals from natural language
2. Planning and executing appropriate scans
3. Interpreting results and identifying risks
4. Suggesting next steps based on findings

You have access to these scan modules:
- recon: WHOIS, DNS, subdomain discovery, OSINT
- scan: Port scanning (nmap/naabu), service detection
- web: Web application audit (nikto, directory brute, headers, SSL)
- nuclei: Vulnerability templates
- paths: Path discovery + SQLi/XSS/LFI verification on every page
- exploit: CVE cross-reference against discovered services
- ad: Active Directory enumeration
- report: Generate professional report

When planning a scan, respond with valid JSON in this exact format:
{
  "action": "scan",
  "target": "example.com",
  "type": "domain",
  "modules": ["recon","scan","web","exploit","report"],
  "reasoning": "Why these modules for this target",
  "proxy": false
}

If the user asks a question (not requesting a scan), just answer it.
If they want to stop or change direction, say so clearly.
Always prioritise authorised testing only."""


class VAPTAgent:

    def __init__(self, scan_callback: Callable, notify_callback: Callable = None,
                 log=None):
        """
        scan_callback: fn(target, type, modules, ...) -> session_id
        notify_callback: fn(msg) -> sends update to user (Telegram or WebSocket)
        """
        self.scan_callback   = scan_callback
        self.notify          = notify_callback or (lambda msg: None)
        self.log             = log
        self.ai              = OllamaAssistant(log=log)
        self.history         = []
        self.active_sessions = []

    # ── Main entry point ───────────────────────────────────────────
    def chat(self, user_message: str, context: dict = None) -> dict:
        """
        Process a user message. Returns:
        {
          "reply":      str  (text response to user),
          "action":     str  (None | "scan_started" | "scan_planned"),
          "session_id": str  (if scan started),
          "plan":       dict (scan plan if one was generated),
        }
        """
        if not self.ai.available:
            return {
                "reply":  ("AI assistant is offline. Start Ollama: `ollama serve` "
                           "then `ollama pull llama3.2:3b`"),
                "action": None,
            }

        self.history.append({"role":"user","content":user_message})

        # Build context string
        ctx_str = ""
        if context:
            ctx_str = f"\nContext: {json.dumps(context, default=str)[:500]}"

        # Build prompt
        prompt = f"""{user_message}{ctx_str}

If this is a scan request, respond with JSON as shown in your instructions.
If it's a question or conversation, respond normally in plain text."""

        reply = self.ai.chat(prompt)
        self.history.append({"role":"assistant","content":reply})

        # Try to extract scan plan from JSON in reply
        plan = self._extract_plan(reply)

        if plan and plan.get("action") == "scan":
            # Confirm with user before executing
            target  = plan.get("target","")
            type_   = plan.get("type","domain")
            modules = plan.get("modules",["recon","scan","exploit","report"])
            reason  = plan.get("reasoning","")

            confirm_msg = (
                f"I'll scan: **{target}**\n"
                f"Type: {type_}\n"
                f"Modules: {', '.join(modules)}\n"
                f"Reason: {reason}\n\n"
                f"Reply 'yes' to start or describe changes."
            )
            return {
                "reply":  confirm_msg,
                "action": "scan_planned",
                "plan":   plan,
            }

        return {"reply": reply, "action": None}

    def execute_plan(self, plan: dict, auth_by: str = "Agent") -> dict:
        """Execute a confirmed scan plan."""
        target  = plan.get("target","")
        type_   = plan.get("type","domain")
        modules = plan.get("modules",["recon","scan","exploit","report"])
        proxy   = plan.get("proxy", False)

        try:
            sid = self.scan_callback(
                target, type_, modules,
                scope_data={"authorised_by": auth_by, "confirmed": True},
                use_auto_proxy=proxy,
            )
            self.active_sessions.append(sid)
            self.notify(
                f"🤖 Agent started scan\n"
                f"Session: {sid}\n"
                f"Target: {target}\n"
                f"Modules: {', '.join(modules)}"
            )
            return {"session_id": sid, "started": True}
        except Exception as e:
            return {"error": str(e), "started": False}

    def interpret_results(self, findings: dict) -> str:
        """Ask AI to interpret scan results and suggest next steps."""
        if not self.ai.available:
            return "AI offline — cannot interpret results automatically."

        summary = self._summarise_findings(findings)
        prompt  = (
            f"These are scan results from a penetration test:\n\n"
            f"{json.dumps(summary, indent=2, default=str)[:2000]}\n\n"
            f"As a penetration tester:\n"
            f"1. What are the most critical findings?\n"
            f"2. What should be investigated next?\n"
            f"3. What is the overall risk level?\n"
            f"Be concise and actionable."
        )
        return self.ai.chat(prompt)

    def suggest_scan(self, description: str) -> dict:
        """
        Given a target description, suggest an appropriate scan plan.
        e.g. "university website in the UK" -> domain scan with web+paths
        """
        prompt = (
            f"A penetration tester wants to scan: {description}\n\n"
            f"Suggest the best scan configuration as JSON:\n"
            f"Consider: what type of target, which modules are most relevant,\n"
            f"any special considerations.\n"
            f"Respond ONLY with valid JSON."
        )
        reply = self.ai.chat(prompt)
        plan  = self._extract_plan(reply)
        return plan or {"error": "Could not generate plan", "raw": reply}

    # ── Helpers ────────────────────────────────────────────────────
    def _extract_plan(self, text: str) -> Optional[dict]:
        """Extract JSON scan plan from AI response."""
        # Try direct JSON parse
        try:
            stripped = text.strip()
            if stripped.startswith("{"):
                d = json.loads(stripped)
                if d.get("action") == "scan":
                    return d
        except Exception:
            pass

        # Try extracting JSON block
        match = re.search(r'\{[^{}]*"action"\s*:\s*"scan"[^{}]*\}', text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except Exception:
                pass

        # Try code block
        for pattern in [r'```json\s*(\{.*?\})\s*```', r'```\s*(\{.*?\})\s*```']:
            match = re.search(pattern, text, re.DOTALL)
            if match:
                try:
                    d = json.loads(match.group(1))
                    if d.get("action") == "scan":
                        return d
                except Exception:
                    pass

        return None

    def _summarise_findings(self, findings: dict) -> dict:
        """Create a compact summary of findings for AI interpretation."""
        summary = {"modules_run": list(findings.get("meta",{}).get("modules",[])),
                   "target": findings.get("meta",{}).get("target","")}

        # Tech
        for t, td in findings.get("tech",{}).items():
            summary["technologies"] = td.get("technologies",[])

        # Ports
        for t, sd in findings.get("scan",{}).items():
            summary["open_ports"]     = sd.get("open_ports",[])
            summary["notable_ports"]  = sd.get("notable",[])

        # CVE matches
        cves = []
        for t, ed in findings.get("exploit",{}).items():
            cves.extend(ed.get("cve_matches",[]))
        summary["cve_matches"] = cves[:5]

        # Path vulns
        vulns = []
        for t, pd in findings.get("paths",{}).items():
            vulns.extend(pd.get("vuln_findings",[])[:5])
        summary["path_vulns"] = vulns

        # Nuclei
        nfindings = []
        for t, nd in findings.get("nuclei",{}).items():
            nfindings.extend(nd.get("findings",[])[:5])
        summary["nuclei_findings"] = nfindings

        return summary

    def clear(self):
        self.history         = []
        self.active_sessions = []
