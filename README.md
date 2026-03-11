# SniperSan

**AI-Powered Web Penetration Testing Agent**

SniperSan is an autonomous web penetration testing agent built on Claude. It performs full-cycle security assessments — from reconnaissance to exploitation to reporting — using an agentic loop that decides which tools to run based on what it discovers.

> **For authorized testing only.** Using this tool against systems without explicit written permission is illegal.

---

## Features

- **3 operation modes** — Auto (fully autonomous), Chat (interactive), Quick Scan (passive recon)
- **Multi-LLM backend** — Claude (Anthropic API) or any Ollama model (qwen3.5:9b, deepseek-r1:14b, llama3.1:8b, and more)
- **39 integrated tools** across recon, enumeration, vulnerability scanning, and exploitation
- **AI-driven methodology** — the agent adapts its approach based on findings
- **Shodan integration** — passive recon via Shodan API (ports, CVEs, ASN, banners)
- **WPScan integration** — deep WordPress vulnerability scanning with CVE data
- **Scan profiles** — stealth, aggressive, api-only, wordpress
- **JS secret scanning** — detects API keys, tokens, and credentials in JavaScript files
- **CVSS v3.1 auto-scoring** — automatic severity rating for all findings
- **Multi-format reports** — HTML dashboard, Markdown, JSON, and PDF output

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
git clone https://github.com/leonuz/snipersan.git
cd snipersan

python3 -m venv venv
venv/bin/pip install -r requirements.txt

cp .env.example .env
# Edit .env and add your keys
```

**.env file:**
```
ANTHROPIC_API_KEY=sk-ant-...
WPSCAN_API_TOKEN=your-wpscan-token
SHODAN_API_KEY=your-shodan-key

# Ollama (local LLM backend)
OLLAMA_HOST=http://sniperx1.uzc:11434
OLLAMA_MODEL=qwen3.5:9b
```

---

## Usage

```bash
# Interactive (LLM selector + mode menu)
venv/bin/python3 main.py

# Fully automated with Claude
venv/bin/python3 main.py --llm claude -t https://target.com -m auto -y

# Fully automated with Ollama (local, no data leaves machine)
venv/bin/python3 main.py --llm ollama --model qwen3.5:9b -t https://target.com -m auto -y

# Passive recon only
venv/bin/python3 main.py -t https://target.com -m quick -y
```

### LLM Selection

At startup, SniperSAN shows an interactive selector with all available models:

```
# │ Model               │ Backend
──┼─────────────────────┼──────────────────────
1 │ claude-sonnet-4-6   │ ☁️  Anthropic API
2 │ qwen3.5:9b          │ 🖥️  Ollama [default]
3 │ qwen2.5:7b-instruct │ 🖥️  Ollama
4 │ llama3.1:8b         │ 🖥️  Ollama
5 │ deepseek-r1:14b     │ 🖥️  Ollama
```

Skip the selector with `--llm claude` or `--llm ollama [--model <name>]`.

### Scan Modes

| Mode | Description |
|------|-------------|
| **Auto Mode** | Fully autonomous pentest. Agent runs all phases and generates a report. |
| **Chat Mode** | Interactive session. You direct the agent with natural language. |
| **Quick Scan** | Passive recon only (headers, SSL, robots.txt, tech fingerprinting, nmap). No active exploitation. |

### Scan Profiles

| Profile | Description |
|---------|-------------|
| `stealth` | Passive only — no active exploitation, no noisy scans |
| `aggressive` | All tools enabled including brute-force and exploitation |
| `api-only` | Focus on API endpoints, JSON responses, auth mechanisms |
| `wordpress` | WordPress-specific tools including WPScan |

---

## Tool Inventory

### Reconnaissance (9 tools)
| Tool | Description |
|------|-------------|
| `shodan_lookup` | Passive Shodan query — ports, CVEs, banners, ASN, geolocation (no target traffic) |
| `run_nmap` | Port scan — basic, quick, full, or vuln modes |
| `check_headers` | HTTP security headers analysis |
| `check_ssl` | SSL/TLS certificate and cipher check |
| `check_robots_sitemap` | robots.txt and sitemap.xml analysis |
| `spider_urls` | Web crawler — collects URLs, forms, interesting paths |
| `fingerprint_tech` | Technology detection (CMS, framework, server, cookies) |
| `scan_js_secrets` | Scans JS files for hardcoded secrets and API keys |
| `run_wpscan` | Full WordPress vulnerability scan with CVE data |

### Enumeration (8 tools)
| Tool | Description |
|------|-------------|
| `dir_bust` | Directory and file brute-force (367-entry wordlist) |
| `subdomain_enum` | Subdomain brute-force + crt.sh certificate transparency |
| `dns_enum` | DNS records (A/MX/TXT/NS/SOA) + AXFR zone transfer attempt |
| `detect_waf` | WAF detection (Cloudflare, Sucuri, Imperva, ModSecurity, Barracuda) |
| `vhost_enum` | Virtual host enumeration via Host header fuzzing |
| `param_discovery` | 80 common GET/POST parameter discovery |
| `api_endpoint_discovery` | REST endpoint extraction from JS bundles |
| `check_http_methods` | Dangerous HTTP methods (TRACE, PUT, DELETE, CONNECT) |

### Vulnerability Scanning (13 tools)
| Tool | Description |
|------|-------------|
| `test_sqli` | SQL injection — error-based and time-based blind |
| `test_xss` | Reflected XSS and SSTI (7 engine fingerprints + RCE payloads) |
| `check_cors` | CORS misconfiguration (wildcard, origin reflection, null) |
| `check_csrf` | CSRF token absence in POST forms |
| `check_sensitive_files` | Exposed files (.env, .git, backups, phpinfo, etc.) |
| `test_open_redirect` | Open redirect via common redirect parameters |
| `test_403_bypass` | 403 Forbidden bypass via headers and URL tricks |
| `test_jwt` | JWT attacks — alg:none, weak secrets, missing expiry |
| `test_idor` | IDOR via path + query param ID variants; PII → CRITICAL |
| `test_graphql` | GraphQL security — introspection, mutations, alias batching, field suggestion |
| `test_default_creds` | Default credentials (25 pairs, 9 admin paths, HTTP Basic + form) |
| `login_brute_force` | Login brute-force with lockout detection (429 / "too many attempts") |
| `password_spray` | Password spray with Retry-After header support |

### Exploitation (7 tools)
| Tool | Description |
|------|-------------|
| `test_lfi` | Local File Inclusion and path traversal |
| `test_command_injection` | OS command injection (time-based and output-based) |
| `test_xxe` | XML External Entity injection |
| `test_ssrf` | Server-Side Request Forgery (AWS/GCP metadata, internal hosts) |
| `http_request_smuggling` | HTTP smuggling — CL.TE / TE.CL / TE.TE via raw sockets |
| `run_nuclei` | Nuclei v3.7.1 — tag-based template scanning |
| `test_auth_bypass` | Auth bypass — SQLi in login, type juggling, mass assignment |

### Reporting (2 tools)
| Tool | Description |
|------|-------------|
| `generate_poc` | Proof-of-Concept generator for confirmed vulnerabilities |
| `generate_report` | Final report — HTML, Markdown, JSON, or PDF (CVSS scores included) |

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
├── main.py              # Entry point — menus, modes, CLI args
├── agent.py             # Agentic loop, tool definitions, dispatcher (backend-agnostic)
├── llm.py               # Multi-LLM abstraction: ClaudeBackend + OllamaBackend + selector
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
