# Roadmap

Planned features and improvements for SniperSan, ordered by priority.

---

## Completed (v1.0 – v1.3)

### v1.3.0 ✅
- **WAF detection** — Cloudflare, Sucuri, Imperva, ModSecurity, Barracuda via header + body probing
- **Certificate transparency** — crt.sh passive subdomain discovery with IP resolution
- **DNS enumeration** — A/MX/TXT/NS/SOA + AXFR zone transfer attempt
- **Virtual host enumeration** — Host header fuzzing against discovered IPs
- **Parameter discovery** — 80 common GET/POST params, baseline comparison
- **SSTI extended** — 7 engine fingerprints (Jinja2, Twig, Smarty, Freemarker, ERB, Ruby Slim, Thymeleaf) with RCE escalation
- **IDOR tester** — path and query param ID variants (n±1, 0, 1, 9999); PII → CRITICAL
- **GraphQL security** — introspection, sensitive fields, mutations, alias batching, field suggestion
- **Nuclei integration** — v3.7.1, tag-based template selection, JSONL parsing
- **Default credentials** — 25 pairs, form-based + HTTP Basic across 9 admin paths
- **Login brute-force** — lockout detection (429 / "too many attempts"), 50-attempt cap
- **Password spray** — Retry-After header support, configurable delay
- **HTTP request smuggling** — CL.TE / TE.CL / TE.TE variants via raw sockets
- **PDF export** — WeasyPrint HTML-to-PDF rendering
- **CVSS v3.1 auto-scoring** — 18-entry lookup table, score + vector + rating in reports
- **Scan profiles** — stealth / aggressive / api-only / wordpress
- **SSRF false-positive fix** — baseline comparison; eliminated 20 FPs
- **IP target normalization** — IPs default to `http://`

### v1.2.0 ✅
- WPScan integration with CVE data and API token support
- JS secret scanner (AWS, GitHub, Stripe, Google, JWT, Bearer, internal URLs)
- HTTP methods checker (TRACE/PUT/DELETE/CONNECT)
- 403 bypass tester (header tricks + path manipulation)
- JWT tester (alg:none, weak secrets, missing exp, sensitive payload)
- wordlists/common.txt (367 entries), wordlists/subdomains.txt (281 entries)

### v1.1.0 ✅
- SQLi, XSS, CORS, CSRF, sensitive files, open redirect, LFI, command injection, XXE, SSRF
- PoC generator, Chat mode, Quick Scan mode

### v1.0.0 ✅
- Core agent loop, nmap, headers, SSL, robots/sitemap, spider, fingerprint, dir bust, subdomain enum
- HTML/Markdown/JSON reports, legal disclaimer, Rich terminal UI

---

## Completed (v1.4) ✅

### Multi-LLM Backend
- **`llm.py`** — abstraction layer: `ClaudeBackend` + `OllamaBackend` with unified interface
- **LLM selector at startup** — Rich table showing Claude + all available Ollama models (queried live from server)
- **Claude backend** — Anthropic API with native tool use
- **Ollama backend** — local models via OpenAI-compatible `/v1/chat/completions` at `http://sniperx1.uzc:11434`
  - Available models: `qwen3.5:9b` (default), `qwen2.5:7b-instruct`, `llama3.1:8b`, `llama3`, `deepseek-r1:14b`, `llava`
  - Tool use via OpenAI function-calling format (supported by qwen3.5, llama3.1, deepseek-r1)
  - 100% local — pentest data never leaves the machine
- **`--llm` CLI flag** — non-interactive: `--llm claude` or `--llm ollama`
- **`--model` CLI flag** — specify Ollama model: `--model deepseek-r1:14b`
- **`OLLAMA_HOST`** / **`OLLAMA_MODEL`** config — loaded from `.env`, default `http://sniperx1.uzc:11434` / `qwen3.5:9b`
- **Tool format converter** `_anthropic_to_openai_tools()` — Anthropic `input_schema` → OpenAI `parameters`

---

## Near-term (v1.5)

### OpenClaw Integration
- **`/snipersan` skill** — SSH-based skill for OpenClaw orchestrator (same pattern as SniperFIN)
- **`--query` mode** — single-shot invocation for external callers

### Active Exploitation
- **Auth bypass patterns** — SQLi in login fields, type juggling, mass assignment tests
- **Mass assignment** — Send extra JSON fields to API endpoints, check if accepted
- **IDOR with token escalation** — Swap session tokens between accounts to confirm privilege escalation
- **Prototype pollution** — Query param and JSON body fuzzing for `__proto__` pollution

### Passive Recon
- **WHOIS lookup** — Registrar info, registration dates, nameservers via `python-whois`
- **Google dorking** — Automated dork queries for sensitive file/panel exposure

### Enumeration
- **Larger wordlists** — SecLists integration: common.txt → 4700 entries, subdomains → 9985 entries
- **Recursive dir busting** — Follow discovered directories and bust recursively
- **API endpoint discovery** — Detect and enumerate REST API endpoints from JS bundles

### Reporting
- **Remediation guidance** — Per-vulnerability fix recommendations with code examples
- **Executive summary** — Use Claude to write natural-language executive summary section
- **Diff reports** — Compare two scan runs and highlight new/fixed vulnerabilities

---

## Medium-term (v1.5)

### Vulnerability Coverage
- **XXE OOB** — Out-of-band XXE with DNS callback detection (requires collaborator setup)
- **WebSocket testing** — Connect to discovered WebSocket endpoints, fuzz messages
- **Deserialization** — Java, PHP, Python pickle deserialization probe payloads
- **OAuth/OIDC testing** — Token leakage, state parameter bypass, redirect_uri manipulation
- **Race conditions** — Concurrent request testing for TOCTOU and quantity bypass

### Integrations
- **Metasploit RPC** — Trigger Metasploit modules for confirmed high/critical findings
- **Burp Suite export** — Export findings in Burp Suite XML format
- **JIRA/GitHub Issues** — Auto-create tickets for discovered vulnerabilities

### Infrastructure
- **Proxy support** — `--proxy` flag to route all traffic through Burp Suite or SOCKS5
- **Rate limiting** — Configurable request rate (`--rate`) to avoid WAF blocks
- **Scan resume** — Save findings mid-scan; resume if interrupted

---

## Long-term (v2.0)

### Architecture
- **Plugin system** — External tool plugins with standard interface; community contributions without modifying core
- **Multi-target scanning** — Accept target list or CIDR range; parallel scanning with per-target reports
- **Session management** — Persist authenticated sessions across tool calls (cookie jar, Bearer token)

### Intelligence
- **Context-aware payload generation** — Use Claude to craft payloads specific to detected tech stack
- **Vulnerability chaining** — Agent reasons about combining low-severity issues (CORS + XSS + CSRF) into critical chains
- **Confidence scoring** — Per-finding confidence rating; high-confidence findings verified with secondary probe

### Infrastructure
- **Web UI** — Browser-based dashboard for launching scans and browsing reports in real time
- **REST API** — Headless operation for CI/CD pipeline integration
- **Docker image** — Pre-built container with all dependencies (nmap, wpscan, nuclei) included
- **Distributed scanning** — Split enumeration work across multiple workers

---

## Known Limitations

| Limitation | Workaround |
|------------|------------|
| No authenticated session support | Manually pass cookies in chat mode |
| No out-of-band detection (XXE, SSRF blind) | Confirm manually with Burp Collaborator |
| Dir bust limited to 367 paths | Replace `common.txt` with SecLists for deeper coverage |
| No JavaScript rendering | Spider misses content from JS-heavy SPAs |
| Nuclei requires manual install | `nuclei` binary must be in `$PATH` |
| PDF export requires WeasyPrint system libs | Install `libpango` / `libcairo` on headless servers |
