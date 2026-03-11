"""Multi-LLM pentest agent with tool use."""
import json
import sys
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown

from tools import recon, enumeration, vuln_scan, exploit, reporter

console = Console()

# ─── Tool Definitions for Claude ─────────────────────────────────────────────

TOOLS = [
    {
        "name": "run_nmap",
        "description": "Run nmap port scan against the target. Use scan_type: 'basic' (top 1000 ports), 'quick' (fast scan), 'full' (all ports), 'vuln' (vulnerability scripts).",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target domain or IP"},
                "scan_type": {"type": "string", "enum": ["basic", "quick", "full", "vuln"],
                             "description": "Type of nmap scan"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "check_headers",
        "description": "Analyze HTTP security headers for missing or misconfigured security headers.",
        "input_schema": {
            "type": "object",
            "properties": {"target": {"type": "string", "description": "Target URL"}},
            "required": ["target"]
        }
    },
    {
        "name": "check_robots_sitemap",
        "description": "Fetch robots.txt and sitemap.xml to discover hidden paths and structure.",
        "input_schema": {
            "type": "object",
            "properties": {"target": {"type": "string", "description": "Target URL"}},
            "required": ["target"]
        }
    },
    {
        "name": "check_ssl",
        "description": "Analyze SSL/TLS certificate configuration, expiry, and cipher strength.",
        "input_schema": {
            "type": "object",
            "properties": {"target": {"type": "string", "description": "Target domain or URL"}},
            "required": ["target"]
        }
    },
    {
        "name": "spider_urls",
        "description": "Crawl the target website to discover URLs, forms, and interesting paths.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "max_urls": {"type": "integer", "description": "Max URLs to crawl (default: 50)"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "fingerprint_tech",
        "description": "Detect technologies, frameworks, CMS, and server software used by the target.",
        "input_schema": {
            "type": "object",
            "properties": {"target": {"type": "string", "description": "Target URL"}},
            "required": ["target"]
        }
    },
    {
        "name": "dir_bust",
        "description": "Brute-force directories and files on the target web server.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "wordlist": {"type": "string", "description": "Wordlist name: 'common' (default)"},
                "extensions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "File extensions to append (e.g. ['php', 'html', 'txt'])"
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "subdomain_enum",
        "description": "Enumerate subdomains of the target domain via brute-force.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target domain or URL"},
            },
            "required": ["target"]
        }
    },
    {
        "name": "test_sqli",
        "description": "Test for SQL injection vulnerabilities in URL parameters and forms.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL (with or without params)"},
                "forms": {
                    "type": "array",
                    "description": "List of forms from spider results to test",
                    "items": {"type": "object"}
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "test_xss",
        "description": "Test for Cross-Site Scripting (XSS) vulnerabilities.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "forms": {
                    "type": "array",
                    "description": "List of forms from spider results to test",
                    "items": {"type": "object"}
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "check_cors",
        "description": "Test for CORS (Cross-Origin Resource Sharing) misconfiguration.",
        "input_schema": {
            "type": "object",
            "properties": {"target": {"type": "string", "description": "Target URL"}},
            "required": ["target"]
        }
    },
    {
        "name": "check_csrf",
        "description": "Check for CSRF vulnerabilities in forms.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "forms": {
                    "type": "array",
                    "description": "Forms to test (from spider)",
                    "items": {"type": "object"}
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "check_sensitive_files",
        "description": "Check for exposed sensitive files (.env, .git, config files, backups, etc.).",
        "input_schema": {
            "type": "object",
            "properties": {"target": {"type": "string", "description": "Target URL"}},
            "required": ["target"]
        }
    },
    {
        "name": "test_open_redirect",
        "description": "Test for open redirect vulnerabilities.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "urls": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Additional URLs to test (from spider)"
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "test_lfi",
        "description": "Test for Local File Inclusion (LFI) and Path Traversal vulnerabilities.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL (with params if known)"},
            },
            "required": ["target"]
        }
    },
    {
        "name": "test_command_injection",
        "description": "Test for OS Command Injection vulnerabilities.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
            },
            "required": ["target"]
        }
    },
    {
        "name": "test_xxe",
        "description": "Test for XML External Entity (XXE) injection vulnerabilities.",
        "input_schema": {
            "type": "object",
            "properties": {"target": {"type": "string", "description": "Target URL"}},
            "required": ["target"]
        }
    },
    {
        "name": "test_ssrf",
        "description": "Test for Server-Side Request Forgery (SSRF) vulnerabilities.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
            },
            "required": ["target"]
        }
    },
    {
        "name": "generate_poc",
        "description": "Generate a Proof-of-Concept for a confirmed vulnerability.",
        "input_schema": {
            "type": "object",
            "properties": {
                "vulnerability": {
                    "type": "object",
                    "description": "The vulnerability dict with type, url, parameter, payload, severity"
                }
            },
            "required": ["vulnerability"]
        }
    },
    {
        "name": "detect_waf",
        "description": "Detect WAF (Web Application Firewall) type via HTTP probing. Run this early in recon to know if payloads need evasion.",
        "input_schema": {
            "type": "object",
            "properties": {"target": {"type": "string", "description": "Target URL"}},
            "required": ["target"]
        }
    },
    {
        "name": "subdomain_crtsh",
        "description": "Passive subdomain discovery via crt.sh certificate transparency logs. No active probing — use before subdomain_enum.",
        "input_schema": {
            "type": "object",
            "properties": {"target": {"type": "string", "description": "Target domain or URL"}},
            "required": ["target"]
        }
    },
    {
        "name": "dns_enum",
        "description": "DNS enumeration: A, MX, TXT, NS, SOA records plus AXFR zone transfer attempt.",
        "input_schema": {
            "type": "object",
            "properties": {"target": {"type": "string", "description": "Target domain or URL"}},
            "required": ["target"]
        }
    },
    {
        "name": "shodan_lookup",
        "description": "Query Shodan for existing scan data on the target IP: open ports, services, banners, CVEs, ASN, ISP, geolocation. Passive — no traffic sent to target. Automatically skipped for private/internal IPs (CTF labs, 10.x, 192.168.x, *.htb, *.thm, localhost).",
        "input_schema": {
            "type": "object",
            "properties": {"target": {"type": "string", "description": "Target domain or URL"}},
            "required": ["target"]
        }
    },
    {
        "name": "vhost_enum",
        "description": "Virtual host enumeration by fuzzing the Host header to discover hidden vhosts on the same IP.",
        "input_schema": {
            "type": "object",
            "properties": {"target": {"type": "string", "description": "Target domain or URL"}},
            "required": ["target"]
        }
    },
    {
        "name": "param_discovery",
        "description": "Discover hidden GET or POST parameters by brute-forcing common parameter names and comparing responses.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "method": {"type": "string", "enum": ["GET", "POST"], "description": "HTTP method to use (default: GET)"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "run_wpscan",
        "description": "Run WPScan against a WordPress site to detect vulnerabilities in core, plugins, themes, and enumerate users. Only use when the target is confirmed to be WordPress.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target WordPress URL"},
                "enumerate": {
                    "type": "string",
                    "description": "Enumeration options (default: 'vp,vt,tt,cb,dbe,u,m'). Use 'ap' for all plugins, 'at' for all themes."
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "scan_js_secrets",
        "description": "Scan JavaScript files for hardcoded secrets, API keys, tokens, and sensitive data.",
        "input_schema": {
            "type": "object",
            "properties": {"target": {"type": "string", "description": "Target URL"}},
            "required": ["target"]
        }
    },
    {
        "name": "check_http_methods",
        "description": "Test for dangerous HTTP methods (TRACE, PUT, DELETE, CONNECT) that should be disabled.",
        "input_schema": {
            "type": "object",
            "properties": {"target": {"type": "string", "description": "Target URL"}},
            "required": ["target"]
        }
    },
    {
        "name": "test_403_bypass",
        "description": "Test for 403 Forbidden bypass using header manipulation and URL tricks.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "paths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Paths that returned 403 to test bypass on"
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "test_ssti",
        "description": "Test for Server-Side Template Injection with engine fingerprinting (Jinja2, Twig, Smarty, Freemarker, ERB, Thymeleaf). Includes RCE escalation payloads.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "forms": {"type": "array", "items": {"type": "object"}, "description": "Forms from spider results"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "test_idor",
        "description": "Test for Insecure Direct Object Reference by incrementing/decrementing numeric IDs in URLs and query params.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "urls": {"type": "array", "items": {"type": "string"}, "description": "Additional URLs from spider to test"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "test_graphql",
        "description": "Test GraphQL endpoints for introspection, sensitive field exposure, unauthenticated mutations, and alias batching abuse.",
        "input_schema": {
            "type": "object",
            "properties": {"target": {"type": "string", "description": "Target URL"}},
            "required": ["target"]
        }
    },
    {
        "name": "run_nuclei",
        "description": "Run Nuclei scanner with community CVE/vulnerability templates. Use after initial recon to catch known CVEs.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "templates": {"type": "string", "description": "Comma-separated tags: cves,vulnerabilities,exposures,misconfiguration (default: all)"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "test_default_creds",
        "description": "Test common default credentials (admin/admin, root/root, ubnt/ubnt, etc.) on discovered login panels via form and HTTP Basic Auth.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "login_urls": {"type": "array", "items": {"type": "string"}, "description": "Specific login page URLs to test"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "brute_force_login",
        "description": "Brute-force a login form for a specific username using a built-in password wordlist. Detects lockout.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL with login form"},
                "username": {"type": "string", "description": "Username to brute-force (default: admin)"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "password_spray",
        "description": "Low-rate password spray: test one password against multiple usernames with delays to avoid lockout.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "usernames": {"type": "array", "items": {"type": "string"}, "description": "List of usernames (e.g. from WPScan enumeration)"},
                "password": {"type": "string", "description": "Password to spray (default: Password1!)"},
                "delay": {"type": "number", "description": "Seconds between attempts (default: 5)"}
            },
            "required": ["target", "usernames"]
        }
    },
    {
        "name": "test_request_smuggling",
        "description": "Test for HTTP Request Smuggling via raw sockets: CL.TE, TE.CL, and TE.TE obfuscation variants.",
        "input_schema": {
            "type": "object",
            "properties": {"target": {"type": "string", "description": "Target URL"}},
            "required": ["target"]
        }
    },
    {
        "name": "test_jwt",
        "description": "Test JWT vulnerabilities: alg:none attack, weak secrets, missing expiry, sensitive data in payload.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "token": {"type": "string", "description": "JWT token to test (optional, will auto-discover)"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "generate_report",
        "description": "Generate the final penetration test report in the chosen format.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target that was tested"},
                "format": {"type": "string", "enum": ["json", "markdown", "html"],
                          "description": "Report format"},
                "summary": {"type": "string", "description": "Executive summary of findings"}
            },
            "required": ["target", "format"]
        }
    },
]


# ─── Tool Dispatcher ──────────────────────────────────────────────────────────

def _dispatch_tool(name: str, inputs: dict, findings: dict) -> Any:
    """Execute the requested tool and return results."""
    target = inputs.get("target", "")

    if name == "run_nmap":
        result = recon.run_nmap(target, inputs.get("scan_type", "basic"))
        findings["nmap"] = result
        return result

    elif name == "check_headers":
        result = recon.check_headers(target)
        findings["headers"] = result
        return result

    elif name == "check_robots_sitemap":
        result = recon.check_robots_sitemap(target)
        findings["robots"] = result
        return result

    elif name == "check_ssl":
        result = recon.check_ssl(target)
        findings["ssl"] = result
        return result

    elif name == "spider_urls":
        result = recon.spider_urls(target, inputs.get("max_urls", 50))
        findings["spider"] = result
        return result

    elif name == "fingerprint_tech":
        result = recon.fingerprint_tech(target)
        findings["fingerprint"] = result
        return result

    elif name == "dir_bust":
        result = enumeration.dir_bust(
            target,
            inputs.get("wordlist", "common"),
            extensions=inputs.get("extensions")
        )
        findings["dir_bust"] = result
        return result

    elif name == "subdomain_enum":
        result = enumeration.subdomain_enum(target)
        findings["subdomains"] = result
        return result

    elif name == "test_sqli":
        result = vuln_scan.test_sqli(target, forms=inputs.get("forms"))
        findings.setdefault("vulns", {})["sqli"] = result
        return result

    elif name == "test_xss":
        result = vuln_scan.test_xss(target, forms=inputs.get("forms"))
        findings.setdefault("vulns", {})["xss"] = result
        return result

    elif name == "check_cors":
        result = vuln_scan.check_cors(target)
        findings.setdefault("vulns", {})["cors"] = result
        return result

    elif name == "check_csrf":
        result = vuln_scan.check_csrf(target, forms=inputs.get("forms"))
        findings.setdefault("vulns", {})["csrf"] = result
        return result

    elif name == "check_sensitive_files":
        result = vuln_scan.check_sensitive_files(target)
        findings.setdefault("vulns", {})["sensitive_files"] = result
        return result

    elif name == "test_open_redirect":
        result = vuln_scan.test_open_redirect(target, urls=inputs.get("urls"))
        findings.setdefault("vulns", {})["open_redirect"] = result
        return result

    elif name == "test_lfi":
        result = exploit.test_lfi(target)
        findings.setdefault("vulns", {})["lfi"] = result
        return result

    elif name == "test_command_injection":
        result = exploit.test_command_injection(target)
        findings.setdefault("vulns", {})["cmd_injection"] = result
        return result

    elif name == "test_xxe":
        result = exploit.test_xxe(target)
        findings.setdefault("vulns", {})["xxe"] = result
        return result

    elif name == "test_ssrf":
        result = exploit.test_ssrf(target)
        findings.setdefault("vulns", {})["ssrf"] = result
        return result

    elif name == "detect_waf":
        result = recon.detect_waf(target)
        findings["waf"] = result
        return result

    elif name == "subdomain_crtsh":
        result = recon.subdomain_crtsh(target)
        findings["subdomains_passive"] = result
        return result

    elif name == "dns_enum":
        result = recon.dns_enum(target)
        findings["dns"] = result
        return result

    elif name == "shodan_lookup":
        result = recon.shodan_lookup(target)
        findings["shodan"] = result
        return result

    elif name == "vhost_enum":
        result = enumeration.vhost_enum(target)
        findings["vhosts"] = result
        return result

    elif name == "param_discovery":
        result = enumeration.param_discovery(target, method=inputs.get("method", "GET"))
        findings["params"] = result
        return result

    elif name == "run_wpscan":
        result = recon.run_wpscan(target, inputs.get("enumerate", "vp,vt,tt,cb,dbe,u,m"))
        findings["wpscan"] = result
        return result

    elif name == "test_ssti":
        result = vuln_scan.test_ssti(target, forms=inputs.get("forms"))
        findings.setdefault("vulns", {})["ssti"] = result
        return result

    elif name == "test_idor":
        result = vuln_scan.test_idor(target, urls=inputs.get("urls"))
        findings.setdefault("vulns", {})["idor"] = result
        return result

    elif name == "test_graphql":
        result = vuln_scan.test_graphql(target)
        findings.setdefault("vulns", {})["graphql"] = result
        return result

    elif name == "run_nuclei":
        result = vuln_scan.run_nuclei(target, templates=inputs.get("templates", "cves,vulnerabilities,exposures,misconfiguration"))
        findings.setdefault("vulns", {})["nuclei"] = result
        return result

    elif name == "test_default_creds":
        result = exploit.test_default_creds(target, login_urls=inputs.get("login_urls"))
        findings.setdefault("vulns", {})["default_creds"] = result
        return result

    elif name == "brute_force_login":
        result = exploit.brute_force_login(target, username=inputs.get("username", "admin"))
        findings.setdefault("vulns", {})["brute_force"] = result
        return result

    elif name == "password_spray":
        result = exploit.password_spray(target, usernames=inputs["usernames"],
                                        password=inputs.get("password", "Password1!"),
                                        delay=inputs.get("delay", 5.0))
        findings.setdefault("vulns", {})["password_spray"] = result
        return result

    elif name == "test_request_smuggling":
        result = exploit.test_request_smuggling(target)
        findings.setdefault("vulns", {})["smuggling"] = result
        return result

    elif name == "scan_js_secrets":
        result = recon.scan_js_secrets(target)
        findings.setdefault("vulns", {})["js_secrets"] = result
        return result

    elif name == "check_http_methods":
        result = vuln_scan.check_http_methods(target)
        findings.setdefault("vulns", {})["http_methods"] = result
        return result

    elif name == "test_403_bypass":
        result = vuln_scan.test_403_bypass(target, paths=inputs.get("paths"))
        findings.setdefault("vulns", {})["bypass_403"] = result
        return result

    elif name == "test_jwt":
        result = exploit.test_jwt(target, token=inputs.get("token"))
        findings.setdefault("vulns", {})["jwt"] = result
        return result

    elif name == "generate_poc":
        return exploit.generate_poc(inputs["vulnerability"])

    elif name == "generate_report":
        return reporter.generate_report(
            inputs["target"],
            findings,
            inputs["format"],
            inputs.get("summary", "")
        )

    else:
        return {"error": f"Unknown tool: {name}"}


# ─── Agent Loop ───────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are SniperSan, an expert web penetration testing agent. Your mission is to perform a comprehensive security assessment of the given target.

Follow this methodology:
1. **Reconnaissance**: detect_waf → shodan_lookup → nmap → check_headers → check_ssl → check_robots_sitemap → fingerprint_tech → scan_js_secrets → dns_enum → subdomain_crtsh. If WordPress detected → run_wpscan immediately.
2. **Enumeration**: spider_urls → dir_bust → subdomain_enum → vhost_enum → param_discovery
3. **Vulnerability Scanning**: test_sqli → test_xss → test_ssti → check_cors → check_csrf → check_sensitive_files → test_open_redirect → check_http_methods → test_403_bypass → test_graphql → run_nuclei → test_idor
4. **Exploitation**: test_lfi → test_command_injection → test_xxe → test_ssrf → test_jwt → test_request_smuggling → test_default_creds. If users found (WPScan/spider) → password_spray.
5. **Reporting**: generate_poc for critical findings → generate_report

Rules:
- Always start with passive recon before active testing
- Use spider results (forms, URLs) to inform vulnerability testing
- Be systematic and thorough - test all discovered endpoints
- Generate PoC for critical/high severity vulnerabilities
- Provide clear, actionable findings in your final report
- When done with all testing, call generate_report to save the results

Always explain what you're doing and why. Be methodical."""


class PentestAgent:
    def __init__(self, llm_backend=None):
        from llm import ClaudeBackend
        self.llm = llm_backend or ClaudeBackend()
        self.findings = {}
        self.messages = []
        self.report_path = None

    def run(self, target: str, report_format: str = "html", profile: str | None = None, scope: str | None = None) -> dict:
        """Run the full pentest agent loop."""
        self.findings = {}
        self.messages = []

        PROFILE_INSTRUCTIONS = {
            "stealth": (
                "PROFILE: STEALTH — Passive recon only. Use: detect_waf, shodan_lookup, check_headers, check_ssl, "
                "check_robots_sitemap, fingerprint_tech, scan_js_secrets, dns_enum, subdomain_crtsh. "
                "Do NOT run active exploitation, brute-force, dir_bust, or nmap. Minimal footprint."
            ),
            "aggressive": (
                "PROFILE: AGGRESSIVE — Use every available tool. Be thorough and exhaustive. "
                "Run all recon, all enumeration, all vuln scans, all exploitation tools. "
                "Run nuclei, brute_force_login, test_default_creds, password_spray if users found."
            ),
            "api-only": (
                "PROFILE: API-ONLY — Focus on API attack surface. Skip spider/dir_bust. "
                "Prioritize: param_discovery, test_graphql, test_jwt, check_cors, test_sqli on API params, "
                "test_idor, run_nuclei with 'exposures,misconfiguration' tags, check_http_methods."
            ),
            "wordpress": (
                "PROFILE: WORDPRESS — WordPress-specific assessment. Run wpscan first, then: "
                "check_sensitive_files (wp-config, backups), test_sqli on WP params, "
                "scan_js_secrets, test_default_creds on /wp-login.php, "
                "password_spray with enumerated WP users."
            ),
        }

        profile_note = f"\n\n{PROFILE_INSTRUCTIONS[profile]}" if profile else ""

        # Build scope instruction
        scope_note = ""
        if scope:
            if scope.startswith("webport:"):
                port = scope.split(":", 1)[1]
                scope_note = (
                    f"\n\nSCOPE: WEB APPLICATION ON PORT {port} — "
                    f"The target runs a web application on port {port} (e.g. 8080, 8443, 3000). "
                    f"Run nmap only on port {port} with vuln/http scripts ('vuln' scan type, '-p {port}'). "
                    f"Use {target.rstrip('/')}:{port} as the base URL for ALL web testing. "
                    f"Run the full web testing methodology (spider, dir_bust, sqli, xss, etc.) against that port. "
                    f"Skip: full port scans, subdomain_enum, vhost_enum, dns_enum, subdomain_crtsh."
                )
            elif scope.isdigit():
                port = scope
                scope_note = (
                    f"\n\nSCOPE: SERVICE PORT {port} — Focus exclusively on port {port}. "
                    f"Run nmap only against port {port} with service/version detection and relevant scripts. "
                    f"Identify the service running → apply appropriate tests for that protocol. "
                    f"Skip: web vuln scanning, dir_bust, subdomain_enum, vhost_enum, dns_enum."
                )
            elif scope == "web":
                scope_note = (
                    "\n\nSCOPE: WEB ONLY (80/443) — Focus on standard web ports. "
                    "Run nmap basic on ports 80/443 only. "
                    "Skip: full port scans, subdomain_enum, dns_enum, vhost_enum. "
                    "Prioritize: spider, dir_bust, full vuln scanning, exploitation."
                )
            elif scope == "recon":
                scope_note = (
                    "\n\nSCOPE: RECON ONLY — Passive and active reconnaissance, no exploitation. "
                    "Run: shodan_lookup, nmap, check_headers, check_ssl, fingerprint_tech, "
                    "dns_enum, subdomain_crtsh, detect_waf, spider_urls. "
                    "Do NOT run any vulnerability scanning or exploitation tools."
                )

        initial_message = (
            f"Begin a {'targeted' if scope else 'comprehensive'} web penetration test against: {target}\n\n"
            f"Report format requested: {report_format}{profile_note}{scope_note}\n\n"
            f"Perform {'the scoped' if scope else 'all'} phases and generate the final report in {report_format} format."
        )

        self.messages.append({"role": "user", "content": initial_message})

        if scope and scope.startswith("webport:"):
            scope_label = f"Web port {scope.split(':', 1)[1]}"
        elif scope and scope.isdigit():
            scope_label = f"Service port {scope}"
        else:
            scope_label = (scope or "full").upper()
        console.print(Panel(
            f"[bold cyan]Target:[/bold cyan] {target}\n"
            f"[bold cyan]Report:[/bold cyan] {report_format.upper()}\n"
            f"[bold cyan]Scope:[/bold cyan]  {scope_label}"
            + (f"\n[bold cyan]Profile:[/bold cyan] {profile.upper()}" if profile else ""),
            title="[bold magenta]SniperSan Agent Starting[/bold magenta]",
            border_style="magenta"
        ))

        iteration = 0
        max_iterations = 50  # Safety limit

        while iteration < max_iterations:
            iteration += 1

            with console.status(f"[cyan]Agent thinking ({self.llm.name})...[/cyan]"):
                response = self.llm.chat(
                    messages=self.messages,
                    system=SYSTEM_PROMPT,
                    tools=TOOLS,
                )

            # Add assistant response to history
            self.messages.append(self.llm.build_assistant_message(response))

            # Display text output
            if response["text"]:
                console.print(Panel(
                    Markdown(response["text"]),
                    title="[bold green]Agent[/bold green]",
                    border_style="green"
                ))

            # Process tool calls
            tool_results = []
            for tc in response["tool_calls"]:
                tool_name  = tc["name"]
                tool_input = tc["input"]

                console.print(f"\n[bold yellow]→ Tool:[/bold yellow] [cyan]{tool_name}[/cyan]")
                if "target" in tool_input:
                    console.print(f"  [dim]Target: {tool_input.get('target')}[/dim]")

                with console.status(f"[yellow]Running {tool_name}...[/yellow]"):
                    try:
                        result = _dispatch_tool(tool_name, tool_input, self.findings)

                        if tool_name == "generate_report" and isinstance(result, str):
                            self.report_path = result

                        _display_tool_result(tool_name, result)

                        tool_results.append({
                            "id": tc["id"],
                            "name": tool_name,
                            "content": json.dumps(result, default=str)[:8000],
                        })

                    except Exception as e:
                        error_msg = f"Tool error: {e}"
                        console.print(f"  [red]{error_msg}[/red]")
                        tool_results.append({
                            "id": tc["id"],
                            "name": tool_name,
                            "content": json.dumps({"error": error_msg}),
                        })

            # Send tool results back
            if tool_results:
                self.messages.append(self.llm.build_tool_result_message(tool_results))

            # Stop conditions
            if response["stop_reason"] == "end_turn" and not response["tool_calls"]:
                console.print("\n[bold green]✓ Agent completed all tasks.[/bold green]")
                break

        return {
            "findings": self.findings,
            "report_path": self.report_path,
            "iterations": iteration
        }

    def chat(self, target: str) -> None:
        """Interactive chat mode with the agent."""
        self.findings = {}
        self.messages = []

        console.print(Panel(
            "[bold]Interactive mode[/bold]\n"
            "Type your instructions. The agent will execute tools based on your commands.\n"
            "Commands: [cyan]quit[/cyan], [cyan]report[/cyan], [cyan]findings[/cyan]",
            title="[bold magenta]SniperSan Interactive[/bold magenta]",
            border_style="magenta"
        ))

        # Prime with target context
        self.messages.append({
            "role": "user",
            "content": f"Target for this session: {target}. "
                      f"Wait for my specific instructions before running tests."
        })

        # Get initial ack
        resp = self.llm.chat(messages=self.messages, system=SYSTEM_PROMPT, tools=TOOLS)
        self.messages.append(self.llm.build_assistant_message(resp))
        if resp["text"]:
            console.print(f"[green]Agent:[/green] {resp['text']}")

        while True:
            try:
                user_input = console.input("\n[bold blue]You:[/bold blue] ").strip()
            except (EOFError, KeyboardInterrupt):
                break

            if not user_input:
                continue

            if user_input.lower() in ("quit", "exit", "q"):
                break
            elif user_input.lower() == "findings":
                console.print_json(json.dumps(self.findings, default=str, indent=2))
                continue
            elif user_input.lower().startswith("report"):
                parts = user_input.split()
                fmt = parts[1] if len(parts) > 1 else "html"
                path = reporter.generate_report(target, self.findings, fmt)
                console.print(f"[green]Report saved: {path}[/green]")
                continue

            self.messages.append({"role": "user", "content": user_input})

            # Agent response loop
            while True:
                with console.status(f"[cyan]Thinking ({self.llm.name})...[/cyan]"):
                    response = self.llm.chat(messages=self.messages, system=SYSTEM_PROMPT, tools=TOOLS)

                self.messages.append(self.llm.build_assistant_message(response))

                if response["text"]:
                    console.print(f"\n[green]Agent:[/green] {response['text']}")

                tool_results = []
                for tc in response["tool_calls"]:
                    console.print(f"\n[yellow]→ {tc['name']}[/yellow] [dim]{tc['input'].get('target', '')}[/dim]")
                    with console.status(f"[yellow]Running {tc['name']}...[/yellow]"):
                        try:
                            result = _dispatch_tool(tc["name"], tc["input"], self.findings)
                            if tc["name"] == "generate_report" and isinstance(result, str):
                                self.report_path = result
                            _display_tool_result(tc["name"], result)
                            tool_results.append({
                                "id": tc["id"],
                                "name": tc["name"],
                                "content": json.dumps(result, default=str)[:8000],
                            })
                        except Exception as e:
                            tool_results.append({
                                "id": tc["id"],
                                "name": tc["name"],
                                "content": json.dumps({"error": str(e)}),
                            })

                if tool_results:
                    self.messages.append(self.llm.build_tool_result_message(tool_results))

                if response["stop_reason"] == "end_turn":
                    break


def _display_tool_result(tool_name: str, result: Any) -> None:
    """Display a concise summary of tool results."""
    if not isinstance(result, dict):
        if isinstance(result, str):
            console.print(f"  [green]→ {result}[/green]")
        return

    if not result.get("success", True):
        console.print(f"  [red]✗ Error: {result.get('error', 'unknown')}[/red]")
        return

    # Tool-specific summaries
    if tool_name == "run_nmap":
        ports = result.get("open_ports", [])
        console.print(f"  [green]✓ {len(ports)} open ports found[/green]")
        for s in result.get("services", [])[:5]:
            console.print(f"    [dim]{s['port']}/{s.get('protocol','tcp')} {s['service']} {s['product']} {s['version']}[/dim]")

    elif tool_name == "check_headers":
        missing = result.get("missing_headers", [])
        high = [h for h in missing if h.get("severity") == "HIGH"]
        console.print(f"  [{'red' if high else 'yellow'}]✓ {len(missing)} missing security headers ({len(high)} HIGH)[/{'red' if high else 'yellow'}]")

    elif tool_name in ("test_sqli", "test_xss", "check_cors", "check_csrf",
                       "test_open_redirect", "test_lfi", "test_command_injection",
                       "test_xxe", "test_ssrf"):
        vulns = result.get("vulnerabilities", [])
        if vulns:
            console.print(f"  [bold red]⚠ {len(vulns)} vulnerabilities found![/bold red]")
            for v in vulns[:3]:
                console.print(f"    [red]• [{v.get('severity')}] {v.get('type')} @ {v.get('parameter', v.get('url', ''))}[/red]")
        else:
            console.print(f"  [green]✓ No vulnerabilities found[/green]")

    elif tool_name == "check_sensitive_files":
        found = result.get("found", [])
        if found:
            console.print(f"  [bold red]⚠ {len(found)} sensitive files exposed![/bold red]")
            for f in found[:3]:
                console.print(f"    [red]• [{f.get('severity')}] {f.get('path')}[/red]")
        else:
            console.print(f"  [green]✓ No sensitive files found[/green]")

    elif tool_name == "dir_bust":
        found = result.get("interesting", [])
        console.print(f"  [green]✓ {len(found)} interesting paths found (scanned {result.get('total_scanned', 0)})[/green]")

    elif tool_name == "subdomain_enum":
        found = result.get("found", [])
        console.print(f"  [green]✓ {len(found)} subdomains found[/green]")

    elif tool_name == "spider_urls":
        urls = result.get("urls_found", [])
        forms = result.get("forms", [])
        console.print(f"  [green]✓ {len(urls)} URLs, {len(forms)} forms found[/green]")

    elif tool_name == "fingerprint_tech":
        tech = result.get("technologies", [])
        console.print(f"  [green]✓ Technologies: {', '.join(tech) or 'none detected'}[/green]")

    elif tool_name == "check_ssl":
        issues = result.get("issues", [])
        days = result.get("days_until_expiry", "?")
        console.print(f"  [green]✓ SSL OK | Expires in {days} days | {len(issues)} issues[/green]")

    elif tool_name == "detect_waf":
        if result.get("waf_detected"):
            console.print(f"  [bold yellow]⚠ WAF detected: {result['waf_name']} [{result['confidence']}] — {result['evidence']}[/bold yellow]")
        else:
            console.print(f"  [green]✓ No WAF detected[/green]")

    elif tool_name == "subdomain_crtsh":
        found = result.get("found", [])
        console.print(f"  [green]✓ crt.sh: {len(found)} passive subdomains found[/green]")
        for s in found[:3]:
            console.print(f"    [dim]{s['subdomain']} → {s['ip']}[/dim]")

    elif tool_name == "dns_enum":
        recs = result.get("records", {})
        zt = result.get("zone_transfer_success", False)
        summary = ", ".join(f"{k}:{len(v)}" for k, v in recs.items() if v)
        console.print(f"  [{'bold red' if zt else 'green'}]{'⚠ ZONE TRANSFER SUCCESS!' if zt else '✓'} DNS: {summary}[/{'bold red' if zt else 'green'}]")

    elif tool_name == "vhost_enum":
        found = result.get("found", [])
        console.print(f"  [{'bold red' if found else 'green'}]{'⚠' if found else '✓'} {len(found)} vhosts discovered[/{'bold red' if found else 'green'}]")
        for v in found[:3]:
            console.print(f"    [red]• {v['vhost']} [{v['status']}][/red]")

    elif tool_name == "param_discovery":
        found = result.get("active_params", [])
        console.print(f"  [{'yellow' if found else 'green'}]✓ {len(found)} active params found[/{'yellow' if found else 'green'}]")
        for p in found[:5]:
            console.print(f"    [dim]• ?{p['param']}= [status {p['status']}][/dim]")

    elif tool_name == "test_ssti":
        vulns = result.get("vulnerabilities", [])
        if vulns:
            console.print(f"  [bold red]⚠ {len(vulns)} SSTI vulnerabilities found![/bold red]")
            for v in vulns:
                console.print(f"    [red]• {v['type']} @ {v['parameter']}[/red]")
        else:
            console.print(f"  [green]✓ No SSTI detected[/green]")

    elif tool_name == "test_idor":
        vulns = result.get("vulnerabilities", [])
        if vulns:
            console.print(f"  [bold red]⚠ {len(vulns)} IDOR vulnerabilities found![/bold red]")
            for v in vulns[:3]:
                console.print(f"    [red]• [{v['severity']}] {v['url']}[/red]")
        else:
            console.print(f"  [green]✓ No IDOR detected[/green]")

    elif tool_name == "test_graphql":
        vulns = result.get("vulnerabilities", [])
        eps = result.get("endpoints_found", [])
        if vulns:
            console.print(f"  [bold red]⚠ GraphQL: {len(vulns)} issues on {len(eps)} endpoint(s)![/bold red]")
            for v in vulns[:3]:
                console.print(f"    [red]• [{v['severity']}] {v['type']}[/red]")
        else:
            console.print(f"  [green]✓ No GraphQL issues ({len(eps)} endpoints probed)[/green]")

    elif tool_name == "run_nuclei":
        vulns = result.get("vulnerabilities", [])
        if vulns:
            console.print(f"  [bold red]⚠ Nuclei: {len(vulns)} findings![/bold red]")
            for v in vulns[:5]:
                console.print(f"    [red]• [{v['severity']}] {v['type']}[/red]")
        else:
            console.print(f"  [green]✓ Nuclei: no findings[/green]")

    elif tool_name == "test_default_creds":
        vulns = result.get("vulnerabilities", [])
        if vulns:
            console.print(f"  [bold red]⚠ {len(vulns)} default credential(s) found![/bold red]")
            for v in vulns:
                console.print(f"    [red]• {v['username']}:{v['password']} @ {v['url']} [{v['auth_type']}][/red]")
        else:
            console.print(f"  [green]✓ No default credentials found[/green]")

    elif tool_name == "brute_force_login":
        vulns = result.get("vulnerabilities", [])
        locked = result.get("locked_out", False)
        attempts = result.get("attempts_made", 0)
        if vulns:
            console.print(f"  [bold red]⚠ Password found after {attempts} attempts![/bold red]")
            console.print(f"    [red]• {vulns[0]['username']}:{vulns[0]['password']}[/red]")
        elif locked:
            console.print(f"  [yellow]⚠ Account locked after {attempts} attempts[/yellow]")
        else:
            console.print(f"  [green]✓ No password found ({attempts} attempts)[/green]")

    elif tool_name == "password_spray":
        vulns = result.get("vulnerabilities", [])
        rl = result.get("rate_limited", False)
        if vulns:
            console.print(f"  [bold red]⚠ {len(vulns)} valid credential(s) found![/bold red]")
            for v in vulns:
                console.print(f"    [red]• {v['username']}:{v['password']}[/red]")
        else:
            console.print(f"  [green]✓ No valid credentials{'  (rate limited)' if rl else ''}[/green]")

    elif tool_name == "test_request_smuggling":
        vulns = result.get("vulnerabilities", [])
        tests = result.get("tests_performed", [])
        if vulns:
            console.print(f"  [bold red]⚠ {len(vulns)} smuggling indicator(s) — verify manually![/bold red]")
        else:
            console.print(f"  [green]✓ No smuggling detected ({', '.join(tests)})[/green]")

    elif tool_name == "run_wpscan":
        vulns = result.get("vulnerabilities", [])
        users = result.get("users_found", [])
        plugins = result.get("plugins", {})
        ver = result.get("wp_version", "?")
        if not result.get("success"):
            console.print(f"  [red]✗ WPScan error: {result.get('error', 'unknown')}[/red]")
        elif vulns:
            console.print(f"  [bold red]⚠ WP {ver} | {len(vulns)} vulns | {len(plugins)} plugins | users: {', '.join(users) or 'none'}[/bold red]")
            for v in vulns[:5]:
                cve = f" [{v['cve']}]" if v.get("cve") else ""
                console.print(f"    [red]• [{v['severity']}] {v['type']}{cve}[/red]")
        else:
            console.print(f"  [green]✓ WP {ver} | No vulns | {len(plugins)} plugins | users: {', '.join(users) or 'none'}[/green]")

    elif tool_name == "scan_js_secrets":
        found = result.get("findings", [])
        scanned = len(result.get("js_files_scanned", []))
        if found:
            console.print(f"  [bold red]⚠ {len(found)} secrets found in {scanned} JS files![/bold red]")
            for f in found[:3]:
                console.print(f"    [red]• [{f.get('severity')}] {f.get('type')} @ {f.get('url','').split('/')[-1]}[/red]")
        else:
            console.print(f"  [green]✓ No secrets found ({scanned} JS files scanned)[/green]")

    elif tool_name == "check_http_methods":
        vulns = result.get("vulnerabilities", [])
        allowed = result.get("allowed_methods", [])
        if vulns:
            console.print(f"  [bold red]⚠ {len(vulns)} dangerous methods enabled![/bold red]")
            for v in vulns:
                console.print(f"    [red]• [{v.get('severity')}] {v.get('method')}[/red]")
        else:
            console.print(f"  [green]✓ No dangerous methods (allowed: {', '.join(allowed) or 'unknown'})[/green]")

    elif tool_name == "test_403_bypass":
        vulns = result.get("vulnerabilities", [])
        if vulns:
            console.print(f"  [bold red]⚠ {len(vulns)} 403 bypass(es) found![/bold red]")
            for v in vulns[:3]:
                console.print(f"    [red]• {v.get('url')} via {v.get('bypass_header', 'path trick')}[/red]")
        else:
            console.print(f"  [green]✓ No 403 bypasses found[/green]")

    elif tool_name == "test_jwt":
        vulns = result.get("vulnerabilities", [])
        tokens = result.get("tokens_found", 0)
        if vulns:
            console.print(f"  [bold red]⚠ {len(vulns)} JWT issue(s) found![/bold red]")
            for v in vulns[:3]:
                console.print(f"    [red]• [{v.get('severity')}] {v.get('type')}[/red]")
        else:
            console.print(f"  [green]✓ No JWT issues found ({tokens} token(s) checked)[/green]")

    elif tool_name == "generate_report":
        if isinstance(result, str):
            console.print(f"  [bold green]✓ Report saved: {result}[/bold green]")

    elif tool_name == "generate_poc":
        console.print(f"  [green]✓ PoC generated for: {result.get('vulnerability', '?')}[/green]")

    else:
        console.print(f"  [green]✓ Done[/green]")
