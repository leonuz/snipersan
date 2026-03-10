# Changelog

All notable changes to SniperSan are documented here.

---

## [1.3.2] — 2026-03-10

### Added
- **`shodan_lookup`** — Passive Shodan query for the target IP: open ports, service banners, CVEs, ASN, ISP, geolocation, OS, tags. Runs before nmap in the recon phase — zero traffic sent to the target. Flags CRITICAL if Shodan reports known CVEs; HIGH if dangerous ports (21, 23, 445, 3389, 5900, 6379, 27017, 9200, 5432, 3306) are exposed.
- **`SHODAN_API_KEY`** config — loaded from `.env`; tool gracefully reports missing key without crashing

### Changed
- `requirements.txt` — added `shodan>=1.31.0`
- `.env.example` — added `SHODAN_API_KEY` placeholder
- System prompt recon phase order: `detect_waf → shodan_lookup → nmap → ...`
- Stealth profile now includes `shodan_lookup` (fully passive, no target traffic)
- Agent tool count: 38 → 39

---

## [1.3.1] — 2026-03-10

### Added
- **GitHub repository** — Project is now publicly available at https://github.com/leonuz/snipersan
- **`install.sh`** — Automated installer for Debian/Ubuntu: installs system dependencies (nmap, Ruby, WPScan, Nuclei), WeasyPrint system libs, Python packages, and walks through `.env` setup interactively
- **`.gitignore`** — Excludes `.env`, `__pycache__`, generated reports, IDE files, and `.claude/` internals from version control
- **`requirements.txt` updated** — Added missing packages: `cvss>=2.6`, `dnspython>=2.6.0`, `weasyprint>=62.0`
- **`reports/.gitkeep`** — `reports/` directory is now tracked in git so it exists on fresh clones without committing generated output

### Changed
- Project is now installable on any fresh Debian/Ubuntu server with a single command: `bash install.sh`

---

## [1.3.0] — 2026-03-10

### Added

**Recon**
- **`detect_waf`** — WAF detection via HTTP probing; identifies Cloudflare, Sucuri, Imperva Incapsula, ModSecurity, Barracuda by header signatures, body patterns, and status code differentials
- **`subdomain_crtsh`** — Passive subdomain discovery via crt.sh certificate transparency logs; resolves each subdomain to IP
- **`dns_enum`** — DNS record enumeration (A, MX, TXT, NS, SOA) + AXFR zone transfer attempt against each NS; flags zone transfer success as critical
- **CVSS v3.1 auto-scoring** — Every vulnerability in every report now carries an auto-calculated CVSS v3.1 base score and vector using an 18-entry lookup table

**Enumeration**
- **`vhost_enum`** — Virtual host discovery via Host header fuzzing; compares status/size against baseline to flag hidden vhosts
- **`param_discovery`** — Hidden parameter brute-force (80 common param names) via GET or POST; flags params that produce responses differing from baseline

**Vulnerability Scanning**
- **`test_ssti`** — Extended SSTI testing with engine fingerprinting: Jinja2, Twig, Smarty, Freemarker/Velocity, ERB, Ruby Slim, Thymeleaf; includes RCE escalation payload per detected engine
- **`test_idor`** — IDOR testing on path segments and query params; generates ID variants (n±1, 0, 1, 9999); escalates to CRITICAL if PII fields detected in response
- **`test_graphql`** — GraphQL security testing: introspection disclosure, sensitive field exposure, mutations without auth, alias batching DoS, field suggestion schema leak
- **`run_nuclei`** — Nuclei v3.7.1 integration with JSONL output parsing; supports tag-based template selection (cves, vulnerabilities, exposures, misconfiguration)

**Exploitation**
- **`test_default_creds`** — Tests 25 common credential pairs (admin/admin, ubnt/ubnt, pi/raspberry, etc.) via form-based and HTTP Basic Auth across 9 default admin paths
- **`brute_force_login`** — Targeted username brute-force against detected login forms; detects lockout (429 / "too many attempts"); caps at 50 attempts
- **`password_spray`** — Low-rate spray of single password across multiple usernames; respects `Retry-After` headers; tests form and HTTP Basic Auth
- **`test_request_smuggling`** — HTTP Request Smuggling via raw sockets: CL.TE, TE.CL, and three TE.TE obfuscation variants (xchunked, space-before-colon, chunked+identity)

**Reporting**
- **PDF export** — `generate_pdf()` via WeasyPrint; generates HTML first then renders to PDF; accessible via `--format pdf` or `generate_report` tool
- **CVSS scores in HTML reports** — Vulnerability cards now display CVSS score and rating alongside evidence

**CLI**
- **`--profile` flag** — Four scan profiles: `stealth` (passive recon only), `aggressive` (all tools), `api-only` (API surface focus), `wordpress` (WP-specific methodology)
- **SSRF false-positive fix** — Baseline comparison prevents flagging static responses as SSRF; eliminated 20 false positives on `192.168.0.82`
- **IP target normalization** — IP addresses now default to `http://` instead of `https://`

### Changed
- Agent methodology reordered: `detect_waf` now runs first in recon phase
- System prompt updated with full 5-phase tool sequence
- Agent tool count: 25 → 38
- `requirements.txt` updated: added `cvss`, `dnspython`, `weasyprint`
- Nuclei v3.7.1 installed as system binary

---

## [1.2.0] — 2026-03-10

### Added
- **WPScan integration** (`run_wpscan`) — full WordPress vulnerability scanning with CVE data, plugin/theme enumeration, user discovery, config backup detection
- **`WPSCAN_API_TOKEN`** config — pulls live vulnerability data from WPScan API
- **JS secret scanner** (`scan_js_secrets`) — discovers hardcoded secrets in JavaScript files: AWS keys, GitHub tokens, Stripe keys, Google API keys, Bearer tokens, JWTs, internal URLs, generic API keys/passwords
- **HTTP methods checker** (`check_http_methods`) — tests for dangerous methods via OPTIONS header and active probing (TRACE, PUT, DELETE, CONNECT)
- **403 bypass tester** (`test_403_bypass`) — header-based bypass (X-Forwarded-For, X-Original-URL, X-Real-IP, etc.) and path manipulation variants
- **JWT vulnerability tester** (`test_jwt`) — auto-discovers JWTs from cookies and page content, tests alg:none attack, weak secret brute-force, missing expiry, sensitive data in payload
- **Wordlists** — `wordlists/common.txt` (367 web paths) and `wordlists/subdomains.txt` (281 subdomains), replacing empty fallback lists

### Changed
- Agent tool count: 21 → 25
- `SYSTEM_PROMPT` now instructs agent to run WPScan immediately upon WordPress detection

---

## [1.1.0] — 2026-03-10

### Added
- **`test_sqli`** — SQL injection testing (error-based, time-based blind) on URL params and forms
- **`test_xss`** — Reflected XSS and server-side template injection detection
- **`check_cors`** — CORS misconfiguration: wildcard, origin reflection, null origin
- **`check_csrf`** — CSRF token absence detection in POST forms
- **`check_sensitive_files`** — Checks 26 sensitive paths (.env, .git, phpinfo, AWS credentials, SSH keys, DB dumps, etc.)
- **`test_open_redirect`** — Open redirect via 15 common redirect parameters
- **`test_lfi`** — Local File Inclusion and path traversal (16 payloads, URL-encoded variants, PHP wrappers)
- **`test_command_injection`** — OS command injection, time-based and output-based detection
- **`test_xxe`** — XML External Entity injection
- **`test_ssrf`** — Server-Side Request Forgery, AWS/GCP metadata endpoint detection
- **`generate_poc`** — PoC generator for SQLi, XSS, CORS, LFI, command injection
- **Chat mode** — Interactive session with `findings`, `report`, and `quit` commands
- **Quick Scan mode** — Passive recon without active exploitation

### Changed
- Agent loop now supports up to 50 iterations with safety limit
- Tool results truncated to 8000 chars before sending back to Claude to manage context

---

## [1.0.0] — 2026-03-10

### Added
- Initial release of SniperSan
- **`run_nmap`** — Port scanning with basic, quick, full, and vuln modes; XML output parsing
- **`check_headers`** — HTTP security headers analysis (HSTS, CSP, X-Frame-Options, etc.)
- **`check_ssl`** — SSL/TLS certificate validation, expiry check, cipher and TLS version detection
- **`check_robots_sitemap`** — robots.txt disallowed paths and sitemap URL extraction
- **`spider_urls`** — Web crawler collecting URLs, forms, and interesting paths
- **`fingerprint_tech`** — Technology detection via signature matching (WordPress, Drupal, Laravel, React, Angular, etc.)
- **`dir_bust`** — Threaded directory/file brute-force with false-positive filtering
- **`subdomain_enum`** — Threaded subdomain brute-force via DNS resolution
- **`generate_report`** — Multi-format report generation (HTML, Markdown, JSON)
- **Auto mode** — Fully autonomous pentest with agentic Claude loop
- **Legal disclaimer** gate at startup
- **Rich terminal UI** — colored output, panels, status spinners, tables
- HTML report dashboard with risk overview, vulnerability cards, port table, SSL details
- Markdown report with severity tables and recon sections
- JSON report with full structured findings
