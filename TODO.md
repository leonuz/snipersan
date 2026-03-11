# TODO

Active task list for SniperSan development. Items are grouped by area and ordered by priority within each group.

---

## Bugs / Fixes

- [ ] **nmap XML parsing is fragile** — current regex-based parser misses services when attributes are on multiple lines; switch to `xml.etree.ElementTree`
- [ ] **`spider_urls` strips query params** — `full.split("?")[0]` discards params before crawling, missing parameterized endpoints
- [ ] **`test_sqli` time-based false positives** — slow servers trigger the 2.5s threshold; add baseline timing measurement first
- [ ] **`check_cors` OPTIONS may 405** — some servers reject OPTIONS; fall back to GET with Origin header
- [ ] **`test_jwt` `hmac.new` deprecation** — deprecated in Python 3.12+; replace with `hmac.HMAC`
- [ ] **WPScan JSON parsing** — mixed stdout (status lines + JSON) can break `json_start` detection if wpscan emits an error before JSON
- [ ] **`dir_bust` false-positive filter** — size-based filter misses custom 404 pages with variable content (e.g. embedded timestamps)
- [ ] **Report filename collision** — timestamp is second-precision; rapid consecutive scans can overwrite reports

---

## Features

### High Priority
- [ ] **OpenClaw skill** — `/snipersan` SSH-based skill for OpenClaw orchestrator
- [ ] **`--query` mode** — single-shot invocation for external callers (like SniperFIN)
- [ ] **SecLists integration** — download common.txt (4700 entries) and subdomains (9985 entries) from SecLists on first run
- [ ] **WHOIS lookup** — registrar info, registration dates, nameservers via `python-whois`
- [ ] **Auth bypass patterns** — SQLi in login fields, type juggling payloads, mass assignment
- [ ] **API endpoint discovery** — extract REST endpoints from JS bundle source
- [ ] **Remediation guidance** — per-vulnerability fix text in HTML and Markdown reports

### Medium Priority
- [x] **Multi-LLM backend** — Claude (Anthropic) + Ollama (local) with interactive selector, `--llm`/`--model` CLI flags
- [x] **Shodan lookup** — passive recon via Shodan API (optional `SHODAN_API_KEY` in `.env`)
- [ ] **Recursive dir busting** — follow discovered directories and bust recursively
- [ ] **Executive summary AI section** — use Claude to write natural-language summary in report
- [ ] **Diff reports** — compare two scan runs, highlight new/fixed findings
- [ ] **Proxy support** — `--proxy` flag routes all requests through Burp Suite or SOCKS5
- [ ] **Rate limit flag** — `--rate N` requests/second cap to avoid WAF blocks

### Low Priority
- [ ] **WebSocket detection and fuzzing** — flag ws:// endpoints; send fuzz messages
- [ ] **Prototype pollution** — `__proto__` injection via query params and JSON body
- [ ] **OAuth/OIDC testing** — token leakage, state bypass, redirect_uri manipulation
- [ ] **Scan resume** — save findings mid-scan to JSON; `--resume` flag to pick up where left off
- [ ] **CONTRIBUTING.md** — guide for adding new tools and submitting PRs

---

## Code Quality

- [ ] **Unit tests** — add `tests/` directory with mocked HTTP responses for each tool
- [ ] **Extract `_get_base_url` and `_get_domain`** — duplicated across `recon.py`, `enumeration.py`, `vuln_scan.py`, `exploit.py`; move to shared `utils.py`
- [ ] **Logging** — replace bare `print` with structured logging; write debug log to file alongside report
- [ ] **Config validation** — warn on startup if nmap/wpscan/nuclei not found in `$PATH`
- [ ] **Request timeout tuning** — `DEFAULT_TIMEOUT = 10` too short for slow targets; make configurable per tool or via `--timeout`
- [ ] **Type hints** — add type hints to all public functions in `vuln_scan.py` and `exploit.py`

---

## Documentation

- [x] README.md
- [x] CHANGELOG.md
- [x] ROADMAP.md
- [x] TODO.md
- [ ] `CONTRIBUTING.md` — guide for adding new tools and submitting PRs
- [ ] Inline docstrings for all public functions (NumPy style)
- [ ] Example report screenshots in README
- [ ] Video walkthrough / demo GIF

---

## Completed

- [x] Core agent loop with Claude tool use (anthropic SDK)
- [x] Auto mode, Chat mode, Quick Scan mode
- [x] nmap integration (basic/quick/full/vuln)
- [x] HTTP security headers analysis
- [x] SSL/TLS certificate check
- [x] robots.txt / sitemap.xml analysis
- [x] Web crawler / spider
- [x] Technology fingerprinting
- [x] Directory brute-force with false-positive filtering
- [x] Subdomain brute-force enumeration
- [x] SQL injection testing (error-based + time-based)
- [x] XSS testing
- [x] CORS misconfiguration testing
- [x] CSRF detection
- [x] Sensitive file exposure check (26 paths)
- [x] Open redirect testing
- [x] LFI / path traversal
- [x] Command injection (time-based + output-based)
- [x] XXE injection
- [x] SSRF (AWS/GCP metadata, internal hosts) + false-positive baseline fix
- [x] PoC generator
- [x] HTML / Markdown / JSON reports
- [x] JS secret scanner (12 secret patterns)
- [x] HTTP methods check (TRACE/PUT/DELETE/CONNECT)
- [x] 403 bypass tester (header tricks + path manipulation)
- [x] JWT vulnerability tester (alg:none, weak secrets, missing exp)
- [x] WPScan integration with CVE data and API token
- [x] wordlists/common.txt (367 entries)
- [x] wordlists/subdomains.txt (281 entries)
- [x] Legal disclaimer gate
- [x] Rich terminal UI
- [x] CLI args (`-t`, `-m`, `-f`, `-p`, `-y`)
- [x] WAF detection (Cloudflare, Sucuri, Imperva, ModSecurity, Barracuda)
- [x] Certificate transparency via crt.sh
- [x] DNS enumeration (A/MX/TXT/NS/SOA + AXFR)
- [x] Virtual host enumeration (Host header fuzzing)
- [x] Parameter discovery (80 common GET/POST params)
- [x] SSTI extended (7 engine fingerprints + RCE escalation payloads)
- [x] IDOR testing (path + query param ID variants, PII detection)
- [x] GraphQL security testing (6 checks)
- [x] Nuclei integration (v3.7.1, tag-based templates)
- [x] Default credentials testing (25 pairs, 9 admin paths)
- [x] Login brute-force with lockout detection
- [x] Password spray with Retry-After support
- [x] HTTP request smuggling (CL.TE / TE.CL / TE.TE via raw sockets)
- [x] PDF export via WeasyPrint
- [x] CVSS v3.1 auto-scoring (18-entry lookup table)
- [x] Scan profiles (stealth / aggressive / api-only / wordpress)
- [x] IP target normalization (defaults to http://)
- [x] Shodan lookup (open ports, CVEs, banners, ASN, ISP, geolocation)
- [x] Multi-LLM backend: `ClaudeBackend` + `OllamaBackend` abstraction in `llm.py`
- [x] Interactive LLM selector at startup (Rich table, live Ollama model list)
- [x] `--llm` / `--model` CLI flags for non-interactive LLM selection
