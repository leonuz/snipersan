# SniperSan

**AI-Powered Web Penetration Testing Agent**

SniperSan is an autonomous web penetration testing agent built on Claude. It performs full-cycle security assessments — from reconnaissance to exploitation to reporting — using an agentic loop that decides which tools to run based on what it discovers.

> **For authorized testing only.** Using this tool against systems without explicit written permission is illegal.

---

## Features

- **3 operation modes** — Auto (fully autonomous), Chat (interactive), Quick Scan (passive recon)
- **25 integrated tools** across recon, enumeration, vulnerability scanning, and exploitation
- **AI-driven methodology** — the agent adapts its approach based on findings
- **WPScan integration** — deep WordPress vulnerability scanning with CVE data
- **JS secret scanning** — detects API keys, tokens, and credentials in JavaScript files
- **Multi-format reports** — HTML dashboard, Markdown, and JSON output

---

## Requirements

**Python dependencies:**
```
anthropic>=0.84.0
rich>=13.0.0
python-dotenv>=1.0.0
requests>=2.31.0
beautifulsoup4>=4.12.0
lxml>=5.0.0
jinja2>=3.1.0
```

**System tools:**
- `nmap` — port scanning (`apt install nmap`)
- `wpscan` — WordPress scanning (`gem install wpscan`)

---

## Installation

```bash
git clone <repo>
cd snipersan

pip install -r requirements.txt

cp .env.example .env
# Edit .env and add your keys
```

**.env file:**
```
ANTHROPIC_API_KEY=sk-ant-...
WPSCAN_API_TOKEN=your-wpscan-token
```

---

## Usage

```bash
python3 main.py
```

### Modes

| Mode | Description |
|------|-------------|
| **Auto Mode** | Fully autonomous pentest. Agent runs all phases and generates a report. |
| **Chat Mode** | Interactive session. You direct the agent with natural language. |
| **Quick Scan** | Passive recon only (headers, SSL, robots.txt, tech fingerprinting, nmap). No active exploitation. |

---

## Tool Inventory

### Reconnaissance (8 tools)
| Tool | Description |
|------|-------------|
| `run_nmap` | Port scan — basic, quick, full, or vuln modes |
| `check_headers` | HTTP security headers analysis |
| `check_ssl` | SSL/TLS certificate and cipher check |
| `check_robots_sitemap` | robots.txt and sitemap.xml analysis |
| `spider_urls` | Web crawler — collects URLs, forms, interesting paths |
| `fingerprint_tech` | Technology detection (CMS, framework, server, cookies) |
| `scan_js_secrets` | Scans JS files for hardcoded secrets and API keys |
| `run_wpscan` | Full WordPress vulnerability scan with CVE data |

### Enumeration (2 tools)
| Tool | Description |
|------|-------------|
| `dir_bust` | Directory and file brute-force (367-entry wordlist) |
| `subdomain_enum` | Subdomain brute-force (281-entry wordlist) |

### Vulnerability Scanning (8 tools)
| Tool | Description |
|------|-------------|
| `test_sqli` | SQL injection — error-based and time-based blind |
| `test_xss` | Reflected XSS and server-side template injection |
| `check_cors` | CORS misconfiguration (wildcard, origin reflection, null) |
| `check_csrf` | CSRF token absence in POST forms |
| `check_sensitive_files` | Exposed files (.env, .git, backups, phpinfo, etc.) |
| `test_open_redirect` | Open redirect via common redirect parameters |
| `check_http_methods` | Dangerous HTTP methods (TRACE, PUT, DELETE) |
| `test_403_bypass` | 403 Forbidden bypass via headers and URL tricks |

### Exploitation (5 tools)
| Tool | Description |
|------|-------------|
| `test_lfi` | Local File Inclusion and path traversal |
| `test_command_injection` | OS command injection (time-based and output-based) |
| `test_xxe` | XML External Entity injection |
| `test_ssrf` | Server-Side Request Forgery (AWS metadata, internal hosts) |
| `test_jwt` | JWT attacks — alg:none, weak secrets, missing expiry |

### Reporting (2 tools)
| Tool | Description |
|------|-------------|
| `generate_poc` | Proof-of-Concept generator for confirmed vulnerabilities |
| `generate_report` | Final report — HTML, Markdown, or JSON |

---

## Reports

Reports are saved to the `reports/` directory, named `<domain>_<timestamp>.<ext>`.

**HTML report includes:**
- Risk overview dashboard (CRITICAL / HIGH / MEDIUM / LOW / INFO counts)
- Executive summary
- Full vulnerability list with payloads and evidence
- Open ports and services table
- Detected technologies
- Interesting paths discovered
- SSL/TLS details

---

## Project Structure

```
snipersan/
├── main.py              # Entry point — menus, modes, CLI
├── agent.py             # Claude agent loop, tool definitions, dispatcher
├── config.py            # Configuration and environment variables
├── requirements.txt
├── .env.example
├── tools/
│   ├── recon.py         # Recon tools + JS scanner + WPScan
│   ├── enumeration.py   # Dir bust + subdomain enum
│   ├── vuln_scan.py     # Vuln scanning tools
│   ├── exploit.py       # Exploitation + JWT + PoC generation
│   └── reporter.py      # HTML / Markdown / JSON report generation
├── wordlists/
│   ├── common.txt       # 367 web paths for dir busting
│   └── subdomains.txt   # 281 subdomains for enumeration
├── reports/             # Generated reports (auto-created)
└── templates/           # Custom report templates (optional)
```

---

## Chat Mode Commands

| Command | Action |
|---------|--------|
| `findings` | Print all collected findings as JSON |
| `report [html\|markdown\|json]` | Save report in specified format |
| `quit` / `exit` / `q` | Exit the session |

---

## WPScan Integration

WPScan runs automatically when WordPress is detected during fingerprinting. It enumerates:
- Vulnerable plugins (with CVE IDs and fix versions)
- Vulnerable themes
- WordPress core vulnerabilities
- User accounts
- Config backups, DB exports, timthumbs

Requires a WPScan API token in `.env` for vulnerability data.
