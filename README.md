# ⚡ VAPT-Framework v3 — Advanced Edition

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python"/>
  <img src="https://img.shields.io/badge/Flask-3.0-lightgrey?style=for-the-badge&logo=flask"/>
  <img src="https://img.shields.io/badge/Telegram-Bot-26A5E4?style=for-the-badge&logo=telegram"/>
  <img src="https://img.shields.io/badge/Ollama-AI-black?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Metasploit-Integrated-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker"/>
  <img src="https://img.shields.io/badge/For-Authorised_Use_Only-red?style=for-the-badge"/>
</p>

<p align="center">
  <b>Full-featured GUI VAPT Framework with AI, Telegram Bot, Proxy Rotation and MSF Integration</b><br/>
  By <a href="https://github.com/ShahrukhAhmadKhan">Shahrukh Ahmad Khan</a> — MSc Cybersecurity, University of Cambridge
</p>

---

## 🆕 What's New in v3

| Feature | v2 | v3 |
|---------|:--:|:--:|
| Proxy support (static + rotating + SOCKS5) | ❌ | ✅ |
| Auth sessions (basic, form login, cookie, token) | ❌ | ✅ |
| Technology detection (httpx, Wappalyzer, WhatWeb) | ❌ | ✅ |
| Tech-aware Nuclei (auto-selects templates) | ❌ | ✅ |
| Telegram bot (scan via chat command) | ❌ | ✅ |
| Local AI assistant (Ollama llama3.2:3b) | ❌ | ✅ |
| Metasploit integration (auxiliary scanners) | ❌ | ✅ |
| CVE explanation via AI | ❌ | ✅ |
| Real-time Nuclei finding stream | ❌ | ✅ |

---

## 🤖 Telegram Bot

Send commands directly from Telegram:

```
/scan example.com                          → Full domain scan
/scan 192.168.1.1 --type ip               → IP scan
/scan 10.0.0.0/24 --type range           → Network sweep
/scan corp.local --type ad               → Active Directory
/scan example.com --modules recon,scan   → Custom modules
/status                                   → Active scans
/report <session_id>                      → Get report link
/ask What is Log4Shell?                   → AI assistant
/tools                                    → Tool status
```

**Setup:** Settings page → enter bot token from @BotFather → add your chat ID → save.

---

## 🔄 Proxy Manager

- **Static** — all requests through one proxy
- **Round Robin** — cycles through proxy list per request
- **Random** — picks random proxy per request
- Supports HTTP, HTTPS, SOCKS4, SOCKS5
- Auth support (username:password)
- Built-in health checker (tests each proxy)
- Used by: recon, nuclei, web audit modules

---

## 🔑 Auth Sessions

Scan authenticated targets (admin panels, APIs, internal apps):

| Type | Use Case |
|------|---------|
| **Basic Auth** | Username/password protected endpoints |
| **Form Login** | POST to login URL, captures cookies automatically |
| **Cookie Injection** | Paste raw cookies from browser DevTools |
| **API Token / Bearer** | REST API endpoints with token auth |

Sessions are automatically injected into: nuclei flags, HTTP requests, httpx scans.

---

## 🧠 AI Assistant (Ollama)

Local AI model — no data leaves your machine.

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull recommended model (2GB)
ollama pull llama3.2:3b

# Or better quality (4.7GB)
ollama pull llama3.1:8b
```

Capabilities:
- Explain any vulnerability in plain English
- Suggest next steps from scan results
- Generate executive summaries
- Answer VA/PT questions interactively
- Suggest nuclei templates for detected tech
- Assess CVEs with exploitation context

---

## 🔬 Tech Detection

Auto-detects technology stack before scanning to focus nuclei templates:

- **httpx** (ProjectDiscovery) — tech-detect flag
- **WhatWeb** — CMS, server, framework detection
- **Wappalyzer** — 1500+ technology signatures
- **Header analysis** — Server, X-Powered-By, framework hints

Detected tech automatically maps to targeted nuclei tags: `wordpress`, `apache`, `spring`, `log4j` etc.

---

## 🗡️ Metasploit Integration

Runs authorised **auxiliary/scanner** modules only:

| Port | Auto-runs |
|------|-----------|
| 21   | ftp_version, ftp_anonymous |
| 22   | ssh_version |
| 445  | smb_version, smb_ms17_010 |
| 3389 | rdp_scanner |
| 6379 | redis_server |
| 27017| mongodb_detect |
| 5900 | vnc_none_auth |

Uses local `msfconsole` or Docker Kali container.

---

## 🚀 Quick Start

### Docker (recommended)
```bash
git clone https://github.com/ShahrukhAhmadKhan/vapt-framework-v3
cd vapt-framework-v3
docker-compose up --build
# Open http://localhost:5000
```

### Direct on Kali/Ubuntu
```bash
pip3 install flask flask-socketio eventlet python-telegram-bot --break-system-packages
# Install Ollama (optional but recommended)
curl -fsSL https://ollama.com/install.sh | sh && ollama pull llama3.2:3b
python3 app.py
# Open http://localhost:5000
# Go to Toolbox → Auto-Install Missing tools
```

---

## 🖥️ GUI Pages

| Page | Description |
|------|-------------|
| Dashboard | Stats, quick launch, tool status |
| New Scan | Target config, modules, proxy/session selector, live terminal |
| Targets | Saved target manager |
| Proxies | Add/manage/test proxy list, set rotation mode |
| Auth Sessions | Login credentials and cookies for authenticated scans |
| AI Assistant | Chat with local Ollama AI for VA/PT guidance |
| Reports | Browse all generated reports |
| Toolbox | Tool checker and auto-installer |
| Settings | Telegram bot config, framework settings |

---

## 👨‍💻 Author

**Shahrukh Ahmad Khan**
- 🎓 MSc Cybersecurity — University of Cambridge
- 🔐 Information Security Analyst | Penetration Tester | 5+ years VAPT
- 🏅 CAP | Practical Ethical Hacking | CCNA | IT Academy
- 🔗 [LinkedIn](https://www.linkedin.com/in/shahrukhkhan-42659a20) | [GitHub](https://github.com/ShahrukhAhmadKhan)

---

## ⚖️ Legal

Authorised security testing only. Computer Misuse Act 1990 (UK) / PECA 2016 (Pakistan).

## 📄 License
MIT
