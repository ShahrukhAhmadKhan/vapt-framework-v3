"""
Technology Detection Module
────────────────────────────
Identifies technologies running on a target using:
  • httpx (ProjectDiscovery) — tech-detect flag
  • WhatWeb                  — technology fingerprinting
  • Wappalyzer-python        — offline fingerprint DB
  • SSL cert analysis        — framework/server hints
  • Custom header analysis   — X-Powered-By, Server, etc.

Results are used to:
  • Focus nuclei templates on detected tech
  • Guide AI assistant for relevant CVE suggestions
  • Show in GUI tech stack panel
"""

import subprocess
import shutil
import json
import ssl
import socket
import urllib.request
import re
from typing import Optional


# Technology → CVE hints mapping
TECH_CVE_HINTS = {
    "wordpress":    ["CVE-2023-2745","CVE-2022-21661","CVE-2021-29447"],
    "drupal":       ["CVE-2019-6340","CVE-2018-7600","Drupalgeddon"],
    "joomla":       ["CVE-2023-23752","CVE-2015-8562"],
    "apache":       ["CVE-2021-41773","CVE-2021-42013","CVE-2017-7679"],
    "nginx":        ["CVE-2021-23017","CVE-2019-20372"],
    "iis":          ["CVE-2021-31166","CVE-2017-7269"],
    "php":          ["CVE-2019-11043","CVE-2021-21703"],
    "laravel":      ["CVE-2021-3129","CVE-2018-15133"],
    "django":       ["CVE-2022-34265","CVE-2021-35042"],
    "spring":       ["CVE-2022-22965","CVE-2022-22963","Log4Shell"],
    "tomcat":       ["CVE-2020-1938","CVE-2019-0232","CVE-2017-12615"],
    "jenkins":      ["CVE-2024-23897","CVE-2023-27898","CVE-2019-1003000"],
    "gitlab":       ["CVE-2021-22205","CVE-2022-2992"],
    "grafana":      ["CVE-2021-43798","CVE-2022-31107"],
    "elasticsearch":["CVE-2021-22145","CVE-2015-5378"],
    "mongodb":      ["CVE-2021-32040"],
    "redis":        ["CVE-2022-0543"],
    "log4j":        ["CVE-2021-44228","CVE-2021-45046"],
    "struts":       ["CVE-2017-5638","CVE-2018-11776"],
    "exchange":     ["CVE-2021-26855","CVE-2021-34473"],
    "sharepoint":   ["CVE-2019-0604","CVE-2020-0646"],
}

NUCLEI_TECH_TAGS = {
    "wordpress":     "wordpress",
    "drupal":        "drupal",
    "joomla":        "joomla",
    "apache":        "apache",
    "nginx":         "nginx",
    "iis":           "iis",
    "php":           "php",
    "laravel":       "laravel",
    "django":        "django",
    "spring":        "springboot",
    "tomcat":        "tomcat",
    "jenkins":       "jenkins",
    "gitlab":        "gitlab",
    "grafana":       "grafana",
    "elasticsearch": "elasticsearch",
    "redis":         "redis",
    "mongodb":       "mongodb",
    "log4j":         "log4j",
}


class TechDetectModule:

    def __init__(self, log, session_name: str = None, proxy_manager=None):
        self.log      = log
        self.session  = session_name
        self.proxy    = proxy_manager

    def run(self, target: str) -> dict:
        self.log.banner(f"TECH DETECT → {target}")
        results = {
            "target":       target,
            "technologies": [],
            "server":       "",
            "frameworks":   [],
            "cms":          None,
            "cve_hints":    [],
            "nuclei_tags":  [],
            "raw":          {},
        }

        techs = set()

        # 1. Direct header analysis first (fastest, always works)
        headers = self._header_analysis(target)
        for t in headers.get("tech", []):
            if t: techs.add(t.lower())
        server = headers.get("server", "")

        # 2. httpx (if installed)
        httpx_data = self._httpx_tech(target)
        for t in httpx_data.get("tech", []):
            if t: techs.add(t.lower())

        # 3. whatweb (if installed)
        whatweb = self._whatweb(target)
        for t in whatweb.get("tech", []):
            if t: techs.add(t.lower())

        # 4. Wappalyzer (if installed)
        wappy = self._wappalyzer(target)
        for t in wappy.get("tech", []):
            if t: techs.add(t.lower())

        # 5. Fallback: fetch page and pattern-match tech signatures
        if not techs:
            page_techs = self._pattern_detect(target)
            techs.update(page_techs)

        results["raw"]          = {"httpx": httpx_data, "whatweb": whatweb,
                                   "headers": headers}
        results["technologies"] = sorted(techs)
        results["server"]       = server
        results["cms"]          = self._detect_cms(techs)

        # CVE hints + nuclei tags
        cve_hints = []
        nucl_tags = set()
        for tech in techs:
            for key, hints in TECH_CVE_HINTS.items():
                if key in tech:
                    cve_hints.extend(hints)
            for key, tag in NUCLEI_TECH_TAGS.items():
                if key in tech:
                    nucl_tags.add(tag)

        results["cve_hints"]   = list(set(cve_hints))
        results["nuclei_tags"] = list(nucl_tags)

        n = len(techs)
        self.log.success(f"  Detected {n} technologies: {', '.join(list(techs)[:8])}")
        if results["cve_hints"]:
            self.log.warning(f"  CVE hints: {', '.join(results['cve_hints'][:5])}")

        return results

    def _pattern_detect(self, target: str) -> set:
        """Pattern match page content for tech signatures — no external tools needed."""
        import urllib.request, ssl, re
        techs = set()
        PATTERNS = {
            r"asp\.net":                    "microsoft asp.net",
            r"x-aspnet-version":            "microsoft asp.net",
            r"x-powered-by.*asp":           "microsoft asp.net",
            r"\.aspx":                      "microsoft asp.net",
            r"server:\s*microsoft-iis":     "iis",
            r"iis/[\d.]+":                  "iis",
            r"server:\s*apache":            "apache",
            r"server:\s*nginx":             "nginx",
            r"server:\s*lighttpd":          "lighttpd",
            r"x-powered-by.*php":           "php",
            r"wp-content":                  "wordpress",
            r"wp-includes":                 "wordpress",
            r"drupal":                      "drupal",
            r"joomla":                      "joomla",
            r"jquery":                      "jquery",
            r"bootstrap":                   "bootstrap",
            r"react":                       "react",
            r"angular":                     "angular",
            r"vue\.js":                     "vue.js",
            r"laravel":                     "laravel",
            r"django":                      "django",
            r"spring":                      "spring",
            r"tomcat":                      "tomcat",
            r"x-powered-by.*express":       "express.js",
            r"set-cookie.*phpsessid":       "php",
            r"set-cookie.*jsessionid":      "java",
            r"set-cookie.*asp\.net_sessionid": "microsoft asp.net",
            r"windows\s+server":            "windows server",
            r"x-generator.*wordpress":      "wordpress",
        }
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        for scheme in (f"https://{target}", f"http://{target}"):
            try:
                req  = urllib.request.Request(scheme,
                    headers={"User-Agent":"Mozilla/5.0 VAPTScanner/3.0"})
                resp = urllib.request.urlopen(req, timeout=10, context=ctx)
                body = resp.read(64*1024).decode(errors="replace")
                hdrs = str(dict(resp.headers)).lower()
                combined = body.lower() + " " + hdrs
                for pattern, tech in PATTERNS.items():
                    if re.search(pattern, combined, re.IGNORECASE):
                        techs.add(tech)
                if techs:
                    break
            except Exception:
                continue
        return techs

    # ── httpx tech-detect ─────────────────────────────────────────
    def _httpx_tech(self, target) -> dict:
        if not shutil.which("httpx"):
            return {"tech": [], "error": "httpx not installed"}

        extra_headers = []
        if self.session:
            try:
                from core.session_manager import get_session_manager
                sm = get_session_manager()
                for k, v in sm.get_headers(self.session).items():
                    extra_headers += ["-H", f"{k}: {v}"]
            except Exception:
                pass

        # Try both http and https
        tech, title, status = [], "", ""
        for scheme in ("https", "http"):
            url = f"{scheme}://{target}"
            cmd = ["httpx", "-u", url,
                   "-tech-detect",    # detect technologies
                   "-title",          # page title
                   "-status-code",    # response code
                   "-json",
                   "-silent",
                   "-timeout", "15",
            ] + extra_headers

            if self.proxy:
                p = self.proxy.get_proxy() if hasattr(self.proxy, 'get_proxy') else None
                if p:
                    cmd += ["-proxy", p["url"]]

            out = self._run(cmd, timeout=30)
            for line in out.splitlines():
                try:
                    d = json.loads(line)
                    # httpx v2+ uses "technologies" array of dicts or strings
                    raw_tech = (d.get("tech") or
                                d.get("technologies") or
                                d.get("tech-detect") or [])
                    # Normalise: could be list of strings or list of dicts
                    for t in raw_tech:
                        if isinstance(t, str):
                            tech.append(t)
                        elif isinstance(t, dict):
                            name = t.get("name","")
                            ver  = t.get("version","")
                            tech.append(f"{name}:{ver}" if ver else name)
                    title  = d.get("title","")
                    status = str(d.get("status-code","") or d.get("status",""))
                    if tech:
                        break
                except Exception:
                    pass
            if tech:
                break

        return {"tech": list(set(tech)), "title": title, "status": status}

    # ── WhatWeb ───────────────────────────────────────────────────
    def _whatweb(self, target) -> dict:
        if not shutil.which("whatweb"):
            return {"tech": [], "error": "whatweb not installed"}
        out = self._run(["whatweb", "--color=never", "--log-json=-",
                         f"https://{target}"], timeout=40)
        tech = []
        for line in out.splitlines():
            try:
                d = json.loads(line)
                plugins = d.get("plugins",{})
                tech.extend(plugins.keys())
            except Exception:
                # Parse plain text
                matches = re.findall(r'\[([^\[\]]+)\]', line)
                tech.extend(matches)
        return {"tech": list(set(tech))}

    # ── Header analysis ───────────────────────────────────────────
    def _header_analysis(self, target) -> dict:
        tech   = []
        server = ""
        for scheme in ("https", "http"):
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                url = f"{scheme}://{target}"
                req = urllib.request.Request(url, method="GET",
                    headers={"User-Agent":"Mozilla/5.0 VAPTScanner/3.0"})
                resp = urllib.request.urlopen(req, timeout=12, context=ctx)
                hdrs = dict(resp.headers)
                body = resp.read(4096).decode(errors="replace")

                server  = hdrs.get("Server","") or hdrs.get("server","")
                powered = hdrs.get("X-Powered-By","") or hdrs.get("x-powered-by","")
                aspnet  = hdrs.get("X-AspNet-Version","")
                via     = hdrs.get("Via","")

                if server:  tech.append(server.split("/")[0].strip())
                if powered: tech.append(powered.split(";")[0].strip())
                if aspnet:  tech.append(f"Microsoft ASP.NET:{aspnet}")

                for h, val in hdrs.items():
                    h_low = h.lower()
                    if h_low == "x-generator":          tech.append(val)
                    elif h_low == "x-drupal-cache":     tech.append("Drupal")
                    elif "wordpress" in h_low:          tech.append("WordPress")
                    elif h_low == "x-joomla-token":     tech.append("Joomla")
                    elif "laravel" in h_low:            tech.append("Laravel")

                # Body hints
                body_low = body.lower()
                if "wp-content" in body_low or "wp-includes" in body_low:
                    tech.append("WordPress")
                if "/sites/default/files" in body_low:
                    tech.append("Drupal")
                if "joomla" in body_low:
                    tech.append("Joomla")
                if "aspnetForm" in body or "ViewState" in body:
                    tech.append("Microsoft ASP.NET")
                if "laravel_session" in body_low:
                    tech.append("Laravel")

                break  # got response, stop
            except Exception:
                continue
        return {"tech": [t for t in tech if t], "server": server}

    # ── Wappalyzer ────────────────────────────────────────────────
    def _wappalyzer(self, target) -> dict:
        """Use wappalyzer-python if installed, else skip."""
        try:
            import Wappalyzer
            webpage = Wappalyzer.WebPage.new_from_url(
                f"https://{target}", verify=False, timeout=15
            )
            analyzer = Wappalyzer.Wappalyzer.latest()
            detected = list(analyzer.analyze(webpage))
            return {"tech": detected}
        except ImportError:
            pass
        except Exception as e:
            pass

        # Fallback: wappalyzer CLI
        if shutil.which("wappalyzer"):
            out = self._run(["wappalyzer", f"https://{target}", "--pretty"], timeout=30)
            try:
                d = json.loads(out)
                return {"tech": [t["name"] for t in d.get("technologies",[])] }
            except Exception:
                pass

        return {"tech": []}

    # ── CMS detection ─────────────────────────────────────────────
    def _detect_cms(self, techs: set) -> Optional[str]:
        cms_map = {
            "wordpress": "WordPress", "drupal": "Drupal", "joomla": "Joomla",
            "magento": "Magento", "shopify": "Shopify", "wix": "Wix",
            "squarespace": "Squarespace", "typo3": "TYPO3",
            "concrete5": "Concrete5", "ghost": "Ghost",
        }
        for key, name in cms_map.items():
            if any(key in t for t in techs):
                return name
        return None

    def _run(self, cmd, timeout=30):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout, errors="replace")
            return r.stdout + r.stderr
        except Exception:
            return ""
