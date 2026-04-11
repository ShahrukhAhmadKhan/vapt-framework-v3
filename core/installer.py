"""
Tool Installer
──────────────
Detects OS, checks for required tools, installs missing ones automatically.
Supports: Debian/Ubuntu, Kali, Arch, macOS (brew), manual fallback.
"""

import subprocess
import shutil
import platform
import sys
import os


TOOLS = {
    # ── Recon ──────────────────────────────────────────────────
    "nmap": {
        "apt": "nmap", "brew": "nmap", "pacman": "nmap",
        "desc": "Network port scanner",
        "check": ["nmap", "--version"],
    },
    "theHarvester": {
        "apt": "theharvester", "brew": None, "pacman": None,
        "pip": "theHarvester",
        "desc": "Email/domain/host OSINT harvester",
        "check": ["theHarvester", "-h"],
    },
    "subfinder": {
        "apt": None, "brew": "subfinder",
        "go":  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "desc": "ProjectDiscovery subdomain finder",
        "check": ["subfinder", "-version"],
    },
    "httpx": {
        "apt": None, "brew": None,
        "go":  "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "desc": "ProjectDiscovery fast HTTP prober",
        "check": ["httpx", "-version"],
    },
    "nuclei": {
        "apt": None, "brew": "nuclei",
        "go":  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "desc": "ProjectDiscovery vulnerability scanner",
        "check": ["nuclei", "-version"],
    },
    "dnsx": {
        "apt": None, "brew": None,
        "go":  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        "desc": "ProjectDiscovery DNS toolkit",
        "check": ["dnsx", "-version"],
    },
    "katana": {
        "apt": None, "brew": None,
        "go":  "github.com/projectdiscovery/katana/cmd/katana@latest",
        "desc": "ProjectDiscovery crawler",
        "check": ["katana", "-version"],
    },
    "naabu": {
        "apt": None, "brew": None,
        "go":  "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        "desc": "ProjectDiscovery fast port scanner",
        "check": ["naabu", "-version"],
    },
    "amass": {
        "apt": "amass", "brew": "amass",
        "go":  "github.com/owasp-amass/amass/v4/...@master",
        "desc": "OWASP Attack Surface Mapping",
        "check": ["amass", "-version"],
    },
    "gobuster": {
        "apt": "gobuster", "brew": "gobuster",
        "go":  "github.com/OJ/gobuster/v3@latest",
        "desc": "Directory/DNS/vhost brute forcer",
        "check": ["gobuster", "version"],
    },
    "nikto": {
        "apt": "nikto", "brew": "nikto",
        "desc": "Web server vulnerability scanner",
        "check": ["nikto", "-Version"],
    },
    "whatweb": {
        "apt": "whatweb", "brew": "whatweb",
        "desc": "Web technology fingerprinter",
        "check": ["whatweb", "--version"],
    },
    "wafw00f": {
        "apt": "wafw00f", "pip": "wafw00f",
        "desc": "WAF detection tool",
        "check": ["wafw00f", "--version"],
    },
    "wpscan": {
        "apt": "wpscan", "brew": "wpscan",
        "gem": "wpscan",
        "desc": "WordPress vulnerability scanner",
        "check": ["wpscan", "--version"],
    },
    "enum4linux": {
        "apt": "enum4linux", "brew": None,
        "desc": "SMB/NetBIOS enumeration",
        "check": ["enum4linux"],
    },
    "smbmap": {
        "apt": "smbmap", "pip": "smbmap",
        "desc": "SMB share enumeration",
        "check": ["smbmap", "-h"],
    },
    "ffuf": {
        "apt": "ffuf", "brew": "ffuf",
        "go":  "github.com/ffuf/ffuf/v2@latest",
        "desc": "Fast web fuzzer",
        "check": ["ffuf", "-V"],
    },
    "masscan": {
        "apt": "masscan", "brew": "masscan",
        "desc": "Ultra-fast port scanner",
        "check": ["masscan", "--version"],
    },
    "dnsrecon": {
        "apt": "dnsrecon", "pip": "dnsrecon",
        "desc": "DNS enumeration",
        "check": ["dnsrecon", "-h"],
    },
    "assetfinder": {
        "apt": None, "brew": None,
        "go":  "github.com/tomnomnom/assetfinder@latest",
        "desc": "Fast subdomain finder by tomnomnom",
        "check": ["assetfinder", "-h"],
    },
    "gau": {
        "apt": None, "brew": None,
        "go":  "github.com/lc/gau/v2/cmd/gau@latest",
        "desc": "GetAllURLs — fetch URLs from Wayback/CommonCrawl",
        "check": ["gau", "-h"],
    },
    "waybackurls": {
        "apt": None, "brew": None,
        "go":  "github.com/tomnomnom/waybackurls@latest",
        "desc": "Fetch URLs from Wayback Machine",
        "check": ["waybackurls", "-h"],
    },
    "httpx": {
        "apt": None, "brew": None,
        "go":  "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "desc": "Fast HTTP prober (ProjectDiscovery)",
        "check": ["httpx", "-version"],
    },
    "whois": {
        "apt": "whois", "brew": "whois",
        "desc": "WHOIS lookup",
        "check": ["whois", "--version"],
    },
    "curl": {
        "apt": "curl", "brew": "curl",
        "desc": "HTTP client",
        "check": ["curl", "--version"],
    },
    "python3": {
        "apt": "python3", "brew": "python3",
        "desc": "Python 3 runtime",
        "check": ["python3", "--version"],
    },
}


class ToolInstaller:

    def __init__(self, log):
        self.log    = log
        self.system = platform.system().lower()
        self.distro = self._detect_distro()
        self.pm     = self._detect_package_manager()

    def install_all(self, dry_run=False):
        self.log.banner("TOOL INSTALLER / CHECKER")
        self.log.info(f"System: {self.system} | Distro: {self.distro} | Package manager: {self.pm}")

        present, missing = [], []

        for name, info in TOOLS.items():
            if self._is_installed(info["check"]):
                self.log.success(f"[✓] {name:<20}  {info['desc']}")
                present.append(name)
            else:
                self.log.warning(f"[✗] {name:<20}  {info['desc']}  ← MISSING")
                missing.append((name, info))

        print(f"\n  {len(present)} tools present, {len(missing)} missing.\n")

        if not missing:
            self.log.success("All tools are installed. Ready to scan!")
            return

        if dry_run:
            self.log.info("Dry-run mode: skipping installation.")
            return

        if self.pm is None:
            self.log.error("No supported package manager found. Install missing tools manually.")
            self._print_manual_instructions(missing)
            return

        confirm = input(f"\n  Install {len(missing)} missing tools? [y/N]: ").strip().lower()
        if confirm != "y":
            self.log.info("Installation skipped.")
            return

        for name, info in missing:
            self._install_tool(name, info)

    def _install_tool(self, name, info):
        self.log.info(f"Installing {name}...")

        # Try pip first if available
        if "pip" in info:
            if self._run(["pip3", "install", "--break-system-packages", "-q", info["pip"]]):
                self.log.success(f"  ✓ {name} installed via pip")
                return

        # Try Go install
        if "go" in info:
            if shutil.which("go"):
                if self._run(["go", "install", info["go"]]):
                    self.log.success(f"  ✓ {name} installed via go install")
                    return

        # Try system package manager
        pkg = info.get(self.pm)
        if pkg:
            cmd = self._build_install_cmd(pkg)
            if cmd and self._run(cmd):
                self.log.success(f"  ✓ {name} installed via {self.pm}")
                return

        # Try gem (Ruby)
        if "gem" in info and shutil.which("gem"):
            if self._run(["sudo", "gem", "install", info["gem"]]):
                self.log.success(f"  ✓ {name} installed via gem")
                return

        self.log.error(f"  ✗ Could not install {name} automatically. Install manually.")

    def _build_install_cmd(self, pkg):
        if self.pm == "apt":
            return ["sudo", "apt-get", "install", "-y", "-q", pkg]
        if self.pm == "brew":
            return ["brew", "install", pkg]
        if self.pm == "pacman":
            return ["sudo", "pacman", "-S", "--noconfirm", pkg]
        return None

    def _is_installed(self, cmd):
        try:
            result = subprocess.run(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5
            )
            return result.returncode in (0, 1)   # some tools return 1 on --version
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _run(self, cmd):
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=120)
            return result.returncode == 0
        except Exception:
            return False

    def _detect_distro(self):
        try:
            data = open("/etc/os-release").read().lower()
            for d in ("kali","ubuntu","debian","arch","fedora","centos","rhel","parrot"):
                if d in data:
                    return d
        except FileNotFoundError:
            pass
        return platform.system().lower()

    def _detect_package_manager(self):
        for pm, cmd in [("apt","apt-get"),("brew","brew"),("pacman","pacman")]:
            if shutil.which(cmd):
                return pm
        return None

    def _print_manual_instructions(self, missing):
        print("\n  Manual installation instructions:")
        for name, info in missing:
            if "go" in info:
                print(f"    {name}: go install {info['go']}")
            elif "pip" in info:
                print(f"    {name}: pip3 install {info['pip']}")
            else:
                print(f"    {name}: Install via your system package manager")
