"""
Ollama AI Assistant
────────────────────
Local AI model integration for VA/PT guidance.
Uses Ollama (llama3.2:3b or any small model) running locally.

Features:
  • Explain findings in plain language
  • Suggest next steps based on scan results
  • Generate remediation recommendations
  • Answer VA/PT questions interactively
  • Summarise full scan reports
  • Suggest nuclei templates for detected technologies
"""

import json
import urllib.request
import urllib.error
from typing import Optional, Generator


OLLAMA_URL    = "http://localhost:11434"
DEFAULT_MODEL = "llama3.2:3b"

SYSTEM_PROMPT = """You are an expert penetration tester and vulnerability assessment specialist
with 10+ years of experience. You help security professionals understand findings, plan attacks
(on authorised targets), interpret scan results, and write professional reports.

You give concise, actionable advice. When discussing vulnerabilities:
1. Explain the vulnerability clearly
2. State the real-world impact
3. Give a clear remediation step
4. Mention relevant CVEs if known

You are integrated into VAPT-Framework v3. You only assist with AUTHORISED security testing."""


class OllamaAssistant:

    def __init__(self, model: str = DEFAULT_MODEL, log=None):
        self.model   = model
        self.log     = log
        self.history = []   # conversation history
        self.available = self._check()

    # ── Availability check ─────────────────────────────────────────
    def _check(self) -> bool:
        try:
            r = urllib.request.urlopen(f"{OLLAMA_URL}/api/tags", timeout=3)
            return r.status == 200
        except Exception:
            return False

    def pull_model(self) -> bool:
        """Pull the model if not available."""
        import subprocess, shutil
        if not shutil.which("ollama"):
            if self.log:
                self.log.error("Ollama not installed. Install: curl -fsSL https://ollama.com/install.sh | sh")
            return False
        try:
            subprocess.run(["ollama", "pull", self.model], timeout=300)
            self.available = True
            return True
        except Exception as e:
            if self.log:
                self.log.error(f"Failed to pull model: {e}")
            return False

    # ── Core chat ──────────────────────────────────────────────────
    def chat(self, message: str, context: dict = None) -> str:
        """Send a message and get a response."""
        if not self.available:
            return "⚠ Ollama not running. Start with: `ollama serve` then `ollama pull llama3.2:3b`"

        # Add context if provided
        full_message = message
        if context:
            ctx_str = json.dumps(context, indent=2, default=str)[:2000]
            full_message = f"Context from scan:\n```json\n{ctx_str}\n```\n\n{message}"

        self.history.append({"role": "user", "content": full_message})

        payload = json.dumps({
            "model":    self.model,
            "messages": [{"role": "system", "content": SYSTEM_PROMPT}] + self.history,
            "stream":   False,
            "options":  {"temperature": 0.3, "num_predict": 1024},
        }).encode()

        try:
            req = urllib.request.Request(
                f"{OLLAMA_URL}/api/chat",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=120) as r:
                resp = json.loads(r.read())
                reply = resp.get("message", {}).get("content", "No response")
                self.history.append({"role": "assistant", "content": reply})
                return reply
        except urllib.error.URLError as e:
            return f"⚠ Ollama connection error: {e}"
        except Exception as e:
            return f"⚠ Error: {e}"

    def stream_chat(self, message: str, context: dict = None) -> Generator[str, None, None]:
        """Stream response token by token."""
        if not self.available:
            yield "⚠ Ollama not running."
            return

        full_message = message
        if context:
            ctx_str = json.dumps(context, indent=2, default=str)[:2000]
            full_message = f"Context:\n```json\n{ctx_str}\n```\n\n{message}"

        self.history.append({"role": "user", "content": full_message})

        payload = json.dumps({
            "model":    self.model,
            "messages": [{"role": "system", "content": SYSTEM_PROMPT}] + self.history[-10:],
            "stream":   True,
            "options":  {"temperature": 0.3, "num_predict": 1024},
        }).encode()

        full_reply = ""
        try:
            req = urllib.request.Request(
                f"{OLLAMA_URL}/api/chat",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=120) as r:
                for line in r:
                    if not line.strip():
                        continue
                    try:
                        d     = json.loads(line)
                        token = d.get("message",{}).get("content","")
                        full_reply += token
                        yield token
                        if d.get("done"):
                            break
                    except Exception:
                        pass
        except Exception as e:
            yield f"\n⚠ Error: {e}"

        self.history.append({"role": "assistant", "content": full_reply})

    # ── Specialised prompts ────────────────────────────────────────
    def explain_finding(self, finding: dict) -> str:
        prompt = f"""Explain this security finding in plain English for a client report:
Finding: {finding.get('name', '')}
CVE: {finding.get('cve_id', 'N/A')}
Severity: {finding.get('severity', '')}
Description: {finding.get('description', '')}
URL/Location: {finding.get('url', '')}

Provide: 1) What it means 2) Real-world impact 3) How to fix it"""
        return self.chat(prompt)

    def suggest_next_steps(self, scan_summary: dict) -> str:
        prompt = f"""Based on these scan results, what should a penetration tester do next?
Prioritise by impact. Be specific about tools and techniques to use.

Scan results: {json.dumps(scan_summary, indent=2, default=str)[:1500]}"""
        return self.chat(prompt)

    def generate_exec_summary(self, findings: dict) -> str:
        prompt = f"""Write a professional executive summary for a penetration test report.
Use formal language. Include: risk level, key findings count, business impact, recommendations.

Findings data: {json.dumps(findings, indent=2, default=str)[:2000]}"""
        return self.chat(prompt)

    def suggest_nuclei_templates(self, technologies: list) -> str:
        tech_str = ", ".join(technologies)
        prompt = f"""For a web application running: {tech_str}

List the most impactful nuclei template tags I should run.
Format as: nuclei -tags <tag1,tag2,...>
Then explain why each tag is relevant."""
        return self.chat(prompt)

    def explain_port(self, port: int, service: str, version: str) -> str:
        prompt = f"""Port {port} is open running {service} {version}.
What are the top 3 things to check for vulnerabilities on this service?
Include specific tools and commands."""
        return self.chat(prompt)

    def assess_cve(self, cve_id: str, target_context: str = "") -> str:
        prompt = f"""Explain {cve_id} for a penetration tester:
1. What is it?
2. How to verify if target is vulnerable
3. Exploitation steps (conceptual - for authorised testing)
4. Remediation
{f'Target context: {target_context}' if target_context else ''}"""
        return self.chat(prompt)

    def clear_history(self):
        self.history = []

    def get_status(self) -> dict:
        models = []
        try:
            r = urllib.request.urlopen(f"{OLLAMA_URL}/api/tags", timeout=3)
            data   = json.loads(r.read())
            models = [m["name"] for m in data.get("models",[])]
        except Exception:
            pass
        return {
            "available": self.available,
            "model":     self.model,
            "models":    models,
            "url":       OLLAMA_URL,
        }
