"""Reconnaissance tools: nmap, headers, robots.txt, whois, SSL."""
import subprocess
import socket
import ssl
import json
import re
from urllib.parse import urlparse
from datetime import datetime

import requests
from bs4 import BeautifulSoup

from config import DEFAULT_TIMEOUT, TOOL_PATHS, WPSCAN_API_TOKEN, SHODAN_API_KEY


def _get_base_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target.rstrip("/")


def _get_domain(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return urlparse(target).netloc
    return target.split("/")[0]


def run_nmap(target: str, scan_type: str = "basic") -> dict:
    """Run nmap port scan against target."""
    domain = _get_domain(target)
    result = {"tool": "nmap", "target": domain, "scan_type": scan_type}

    scan_args = {
        "basic": ["-sV", "-sC", "--top-ports", "1000", "-T4"],
        "full": ["-sV", "-sC", "-p-", "-T4"],
        "quick": ["-F", "-T4"],
        "udp": ["-sU", "--top-ports", "100", "-T4"],
        "vuln": ["-sV", "--script=vuln", "-T4"],
    }

    args = scan_args.get(scan_type, scan_args["basic"])

    try:
        cmd = ["nmap", "-oX", "-"] + args + [domain]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        # Parse XML output for key info
        ports = []
        for line in proc.stdout.split("\n"):
            if 'portid=' in line and 'state="open"' in line:
                port_match = re.search(r'portid="(\d+)"', line)
                proto_match = re.search(r'protocol="(\w+)"', line)
                if port_match:
                    ports.append({
                        "port": int(port_match.group(1)),
                        "protocol": proto_match.group(1) if proto_match else "tcp"
                    })

        # Also parse service info
        services = []
        service_pattern = re.findall(
            r'portid="(\d+)".*?name="([^"]*)".*?product="([^"]*)".*?version="([^"]*)"',
            proc.stdout, re.DOTALL
        )
        for match in service_pattern:
            services.append({
                "port": match[0],
                "service": match[1],
                "product": match[2],
                "version": match[3]
            })

        result["raw_output"] = proc.stdout[:3000]
        result["open_ports"] = ports
        result["services"] = services
        result["stderr"] = proc.stderr[:500] if proc.stderr else ""
        result["success"] = proc.returncode == 0

    except subprocess.TimeoutExpired:
        result["error"] = "nmap scan timed out after 300s"
        result["success"] = False
    except FileNotFoundError:
        result["error"] = "nmap not found. Install with: apt install nmap"
        result["success"] = False
    except Exception as e:
        result["error"] = str(e)
        result["success"] = False

    return result


def check_headers(target: str) -> dict:
    """Analyze HTTP security headers."""
    url = _get_base_url(target)
    result = {"tool": "headers", "target": url}

    security_headers = {
        "Strict-Transport-Security": {"severity": "HIGH", "desc": "HSTS not set"},
        "X-Frame-Options": {"severity": "MEDIUM", "desc": "Clickjacking protection missing"},
        "X-Content-Type-Options": {"severity": "MEDIUM", "desc": "MIME sniffing protection missing"},
        "Content-Security-Policy": {"severity": "HIGH", "desc": "CSP not set"},
        "X-XSS-Protection": {"severity": "LOW", "desc": "XSS filter header missing"},
        "Referrer-Policy": {"severity": "LOW", "desc": "Referrer policy not set"},
        "Permissions-Policy": {"severity": "LOW", "desc": "Permissions policy not set"},
        "X-Powered-By": {"severity": "INFO", "desc": "Server technology exposed"},
        "Server": {"severity": "INFO", "desc": "Server version may be exposed"},
    }

    try:
        resp = requests.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True,
                           headers={"User-Agent": "Mozilla/5.0 (compatible; SniperSan/1.0)"})

        headers_present = dict(resp.headers)
        missing = []
        present = []
        info_leaks = []

        for header, meta in security_headers.items():
            if header in headers_present:
                if meta["severity"] == "INFO":
                    info_leaks.append({
                        "header": header,
                        "value": headers_present[header],
                        "severity": "INFO"
                    })
                else:
                    present.append({"header": header, "value": headers_present[header]})
            else:
                if meta["severity"] != "INFO":
                    missing.append({
                        "header": header,
                        "severity": meta["severity"],
                        "description": meta["desc"]
                    })

        result["status_code"] = resp.status_code
        result["redirect_chain"] = [str(r.url) for r in resp.history]
        result["final_url"] = str(resp.url)
        result["missing_headers"] = missing
        result["present_headers"] = present
        result["info_leaks"] = info_leaks
        result["all_headers"] = dict(resp.headers)
        result["success"] = True

    except requests.exceptions.SSLError as e:
        result["error"] = f"SSL error: {e}"
        result["success"] = False
    except Exception as e:
        result["error"] = str(e)
        result["success"] = False

    return result


def check_robots_sitemap(target: str) -> dict:
    """Fetch and analyze robots.txt and sitemap.xml."""
    url = _get_base_url(target)
    result = {"tool": "robots_sitemap", "target": url}

    paths_of_interest = []
    disallowed = []
    sitemaps = []

    # robots.txt
    try:
        resp = requests.get(f"{url}/robots.txt", timeout=DEFAULT_TIMEOUT,
                           headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            result["robots_txt"] = resp.text[:2000]
            for line in resp.text.split("\n"):
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        disallowed.append(path)
                        paths_of_interest.append(path)
                elif line.lower().startswith("sitemap:"):
                    sitemap_url = line.split(":", 1)[1].strip()
                    sitemaps.append(sitemap_url)
        else:
            result["robots_txt"] = None
    except Exception as e:
        result["robots_error"] = str(e)

    # sitemap.xml
    sitemap_urls_found = []
    for sitemap_url in (sitemaps or [f"{url}/sitemap.xml"]):
        try:
            resp = requests.get(sitemap_url, timeout=DEFAULT_TIMEOUT,
                               headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "xml")
                locs = [loc.text for loc in soup.find_all("loc")][:50]
                sitemap_urls_found.extend(locs)
        except Exception:
            pass

    result["disallowed_paths"] = disallowed
    result["sitemap_urls"] = sitemap_urls_found[:50]
    result["interesting_paths"] = paths_of_interest[:30]
    result["success"] = True
    return result


def check_ssl(target: str) -> dict:
    """Analyze SSL/TLS certificate and configuration."""
    domain = _get_domain(target)
    result = {"tool": "ssl_check", "target": domain}
    issues = []

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(DEFAULT_TIMEOUT)
            s.connect((domain, 443))
            cert = s.getpeercert()
            cipher = s.cipher()
            version = s.version()

        # Parse expiry
        not_after = cert.get("notAfter", "")
        if not_after:
            exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (exp_date - datetime.utcnow()).days
            result["expires"] = not_after
            result["days_until_expiry"] = days_left
            if days_left < 30:
                issues.append({"severity": "HIGH", "issue": f"Certificate expires in {days_left} days"})
            elif days_left < 90:
                issues.append({"severity": "MEDIUM", "issue": f"Certificate expires in {days_left} days"})

        # SAN
        san = []
        for field in cert.get("subjectAltName", []):
            if field[0] == "DNS":
                san.append(field[1])
        result["san_domains"] = san

        # Subject
        subject = dict(x[0] for x in cert.get("subject", []))
        result["subject"] = subject
        result["issuer"] = dict(x[0] for x in cert.get("issuer", []))

        # TLS version
        result["tls_version"] = version
        result["cipher"] = cipher[0] if cipher else "unknown"
        if version in ("TLSv1", "TLSv1.1", "SSLv3"):
            issues.append({"severity": "HIGH", "issue": f"Weak TLS version: {version}"})

        result["issues"] = issues
        result["success"] = True

    except ssl.SSLError as e:
        result["error"] = f"SSL error: {e}"
        result["issues"] = [{"severity": "HIGH", "issue": str(e)}]
        result["success"] = False
    except Exception as e:
        result["error"] = str(e)
        result["success"] = False

    return result


def spider_urls(target: str, max_urls: int = 50) -> dict:
    """Crawl target and collect internal URLs."""
    url = _get_base_url(target)
    domain = _get_domain(target)
    result = {"tool": "spider", "target": url}

    visited = set()
    to_visit = {url}
    found_urls = []
    forms = []
    interesting = []

    interesting_patterns = re.compile(
        r"(admin|login|logout|signup|register|upload|config|backup|"
        r"api|graphql|swagger|phpinfo|\.env|\.git|debug|test|dev)",
        re.IGNORECASE
    )

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (compatible; SniperSan/1.0)"

    while to_visit and len(visited) < max_urls:
        current = to_visit.pop()
        if current in visited:
            continue
        visited.add(current)

        try:
            resp = session.get(current, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
            found_urls.append({"url": current, "status": resp.status_code,
                               "content_type": resp.headers.get("Content-Type", "")})

            if "text/html" not in resp.headers.get("Content-Type", ""):
                continue

            soup = BeautifulSoup(resp.text, "lxml")

            # Collect forms
            for form in soup.find_all("form"):
                action = form.get("action", "")
                method = form.get("method", "GET").upper()
                inputs = [{"name": i.get("name"), "type": i.get("type", "text")}
                          for i in form.find_all("input")]
                forms.append({"page": current, "action": action,
                              "method": method, "inputs": inputs})

            # Collect links
            for tag in soup.find_all(["a", "link", "script", "img"]):
                href = tag.get("href") or tag.get("src", "")
                if not href:
                    continue
                if href.startswith("/"):
                    full = f"{url}{href}"
                elif href.startswith("http"):
                    if domain not in href:
                        continue
                    full = href
                else:
                    continue

                full = full.split("#")[0].split("?")[0]
                if full not in visited and full not in to_visit:
                    to_visit.add(full)
                    if interesting_patterns.search(full):
                        interesting.append(full)

        except Exception:
            pass

    result["urls_found"] = found_urls[:max_urls]
    result["forms"] = forms[:20]
    result["interesting_paths"] = list(set(interesting))[:20]
    result["total_crawled"] = len(visited)
    result["success"] = True
    return result


def fingerprint_tech(target: str) -> dict:
    """Detect technologies, frameworks, and CMS."""
    url = _get_base_url(target)
    result = {"tool": "fingerprint", "target": url}
    tech = []

    signatures = {
        "WordPress": [r"wp-content", r"wp-includes", r"/wp-login\.php"],
        "Drupal": [r"Drupal", r"/sites/default/", r"drupal\.js"],
        "Joomla": [r"/components/com_", r"Joomla"],
        "Laravel": [r"laravel_session", r"XSRF-TOKEN"],
        "Django": [r"csrfmiddlewaretoken", r"django"],
        "React": [r"react", r"__REACT"],
        "Angular": [r"ng-version", r"angular"],
        "Vue.js": [r"__vue__", r"data-v-"],
        "jQuery": [r"jquery"],
        "Bootstrap": [r"bootstrap"],
        "Apache": [r"Apache"],
        "Nginx": [r"nginx"],
        "PHP": [r"\.php", r"X-Powered-By: PHP"],
        "ASP.NET": [r"ASP\.NET", r"__VIEWSTATE"],
        "Node.js": [r"X-Powered-By: Express"],
    }

    try:
        resp = requests.get(url, timeout=DEFAULT_TIMEOUT,
                           headers={"User-Agent": "Mozilla/5.0"})
        content = resp.text + str(dict(resp.headers))

        for tech_name, patterns in signatures.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    tech.append(tech_name)
                    break

        # Cookies fingerprinting
        cookies_info = []
        for cookie in resp.cookies:
            flags = []
            if not cookie.secure:
                flags.append("no-Secure-flag")
            cookies_info.append({"name": cookie.name, "flags": flags})

        result["technologies"] = list(set(tech))
        result["cookies"] = cookies_info
        result["server"] = resp.headers.get("Server", "unknown")
        result["powered_by"] = resp.headers.get("X-Powered-By", "unknown")
        result["success"] = True

    except Exception as e:
        result["error"] = str(e)
        result["success"] = False

    return result


# ─── JS Secret Scanner ────────────────────────────────────────────────────────

JS_SECRET_PATTERNS = {
    "AWS Access Key":  (r"AKIA[0-9A-Z]{16}", "CRITICAL"),
    "AWS Secret Key":  (r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", "CRITICAL"),
    "Generic API Key": (r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]", "HIGH"),
    "Generic Secret":  (r"(?i)(secret|password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]", "HIGH"),
    "Bearer Token":    (r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]{20,}", "HIGH"),
    "GitHub Token":    (r"ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}", "CRITICAL"),
    "Slack Token":     (r"xox[baprs]-[0-9a-zA-Z]{10,48}", "HIGH"),
    "Google API Key":  (r"AIza[0-9A-Za-z\-_]{35}", "HIGH"),
    "Stripe Key":      (r"(?:r|s)k_(?:live|test)_[0-9a-zA-Z]{24,}", "CRITICAL"),
    "Private Key":     (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "CRITICAL"),
    "JWT Token":       (r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", "MEDIUM"),
    "Internal URL":    (r"https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)", "MEDIUM"),
}


def scan_js_secrets(target: str) -> dict:
    """Scan JavaScript files for hardcoded secrets, API keys, and sensitive data."""
    url = _get_base_url(target)
    result = {"tool": "js_secrets", "target": url}
    findings = []
    js_files_scanned = []

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (compatible; SniperSan/1.0)"

    # Collect JS file URLs from the page
    js_urls = set()
    try:
        resp = session.get(url, timeout=DEFAULT_TIMEOUT)
        soup = BeautifulSoup(resp.text, "lxml")
        for tag in soup.find_all("script"):
            src = tag.get("src", "")
            if src:
                if src.startswith("http"):
                    if _get_domain(url) in src:
                        js_urls.add(src)
                elif src.startswith("/"):
                    js_urls.add(f"{url}{src}")
                else:
                    js_urls.add(f"{url}/{src}")

        # Check common JS bundle paths
        for path in ["main.js", "app.js", "bundle.js",
                     "static/js/main.chunk.js", "assets/js/app.js",
                     "js/app.js", "dist/bundle.js"]:
            js_urls.add(f"{url}/{path}")
    except Exception:
        pass

    compiled = {name: (re.compile(pat), sev)
                for name, (pat, sev) in JS_SECRET_PATTERNS.items()}

    for js_url in list(js_urls)[:20]:
        try:
            resp = session.get(js_url, timeout=DEFAULT_TIMEOUT)
            if resp.status_code != 200:
                continue
            content = resp.text[:100_000]
            js_files_scanned.append(js_url)

            for secret_type, (pattern, severity) in compiled.items():
                for match in pattern.finditer(content):
                    start = max(0, match.start() - 30)
                    end = min(len(content), match.end() + 30)
                    snippet = content[start:end].replace("\n", " ").strip()
                    findings.append({
                        "type": f"Exposed Secret: {secret_type}",
                        "severity": severity,
                        "url": js_url,
                        "match": match.group()[:80],
                        "context": snippet[:150],
                        "evidence": f"{secret_type} pattern matched in JS file"
                    })
        except Exception:
            pass

    result["findings"] = findings
    result["js_files_scanned"] = js_files_scanned
    result["total_found"] = len(findings)
    result["success"] = True
    return result


# ─── WPScan ───────────────────────────────────────────────────────────────────

def run_wpscan(target: str, enumerate: str = "vp,vt,tt,cb,dbe,u,m") -> dict:
    """Run WPScan against a WordPress target to find vulnerabilities, plugins, themes, and users.

    enumerate options:
      vp = vulnerable plugins, ap = all plugins
      vt = vulnerable themes,  at = all themes
      tt = timthumbs, cb = config backups, dbe = db exports
      u  = users,    m  = media
    """
    url = _get_base_url(target)
    result = {"tool": "wpscan", "target": url}

    cmd = [
        "wpscan",
        "--url", url,
        "--output-format", "json",
        "--enumerate", enumerate,
        "--random-user-agent",
        "--disable-tls-checks",
    ]

    if WPSCAN_API_TOKEN:
        cmd += ["--api-token", WPSCAN_API_TOKEN]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        raw = proc.stdout

        # WPScan mixes status lines with JSON — find the JSON object
        json_start = raw.find("{")
        if json_start != -1:
            data = json.loads(raw[json_start:])
        else:
            result["error"] = "No JSON output from wpscan"
            result["raw"] = raw[:2000]
            result["success"] = False
            return result

        # ── Parse vulnerabilities ──────────────────────────────────────────
        vulnerabilities = []

        def _extract_vulns(item_dict: dict, context: str) -> None:
            for item_name, item_data in item_dict.items():
                if not isinstance(item_data, dict):
                    continue
                for vuln in item_data.get("vulnerabilities", []):
                    severity = "HIGH"
                    cvss = vuln.get("cvss", {})
                    if isinstance(cvss, dict):
                        score = float(cvss.get("score", 0) or 0)
                        if score >= 9.0:
                            severity = "CRITICAL"
                        elif score >= 7.0:
                            severity = "HIGH"
                        elif score >= 4.0:
                            severity = "MEDIUM"
                        else:
                            severity = "LOW"

                    refs = vuln.get("references", {})
                    cve_list = refs.get("cve", []) if isinstance(refs, dict) else []

                    vulnerabilities.append({
                        "type": f"WordPress {context}: {vuln.get('title', 'Unknown')}",
                        "severity": severity,
                        "url": url,
                        "component": item_name,
                        "cve": ", ".join(f"CVE-{c}" for c in cve_list) if cve_list else "",
                        "fixed_in": vuln.get("fixed_in", ""),
                        "references": refs.get("url", [])[:3] if isinstance(refs, dict) else [],
                        "evidence": f"WPScan detected vulnerable {context.lower()}: {item_name}"
                    })

        # Core vulns
        for vuln in data.get("vulnerabilities", []):
            refs = vuln.get("references", {})
            cve_list = refs.get("cve", []) if isinstance(refs, dict) else []
            vulnerabilities.append({
                "type": f"WordPress Core: {vuln.get('title', 'Unknown')}",
                "severity": "HIGH",
                "url": url,
                "component": "WordPress Core",
                "cve": ", ".join(f"CVE-{c}" for c in cve_list) if cve_list else "",
                "fixed_in": vuln.get("fixed_in", ""),
                "evidence": "WPScan detected WordPress core vulnerability"
            })

        # Plugin vulns
        _extract_vulns(data.get("plugins", {}), "Plugin")

        # Theme vulns
        _extract_vulns(data.get("themes", {}), "Theme")

        # ── Parse users ───────────────────────────────────────────────────
        users_found = list(data.get("users", {}).keys())

        # ── Parse interesting findings ────────────────────────────────────
        interesting = [
            {"finding": f.get("to_s", ""), "references": f.get("references", {}).get("url", [])}
            for f in data.get("interesting_findings", [])
        ]

        # ── WordPress version ─────────────────────────────────────────────
        wp_version_data = data.get("version", {})
        wp_version = wp_version_data.get("number", "unknown") if wp_version_data else "unknown"

        result["wp_version"] = wp_version
        result["vulnerabilities"] = vulnerabilities
        result["users_found"] = users_found
        result["interesting_findings"] = interesting
        result["plugins"] = {k: v.get("version", {}).get("number") for k, v in data.get("plugins", {}).items()}
        result["themes"] = {k: v.get("version", {}).get("number") for k, v in data.get("themes", {}).items()}
        result["total_vulns"] = len(vulnerabilities)
        result["success"] = True

    except subprocess.TimeoutExpired:
        result["error"] = "WPScan timed out after 300s"
        result["success"] = False
    except FileNotFoundError:
        result["error"] = "wpscan not found. Install with: gem install wpscan"
        result["success"] = False
    except json.JSONDecodeError as e:
        result["error"] = f"Failed to parse WPScan JSON: {e}"
        result["raw"] = raw[:2000] if "raw" in locals() else ""
        result["success"] = False
    except Exception as e:
        result["error"] = str(e)
        result["success"] = False

    return result


# ─── WAF Detection ────────────────────────────────────────────────────────────

def detect_waf(target: str) -> dict:
    """Detect WAF type via HTTP probing."""
    url = _get_base_url(target)
    result = {"tool": "waf_detection", "target": url}

    headers = {"User-Agent": "Mozilla/5.0 (compatible; SniperSan/1.0)"}
    probe_params = {"id": "1' OR '1'='1", "q": "<script>alert(1)</script>"}

    waf_detected = False
    waf_name = "Unknown WAF"
    confidence = "LOW"
    evidence = ""

    try:
        # Baseline request
        baseline_resp = requests.get(url, timeout=DEFAULT_TIMEOUT, headers=headers)
        baseline_status = baseline_resp.status_code

        # Malicious probe request
        probe_resp = requests.get(url, params=probe_params, timeout=DEFAULT_TIMEOUT,
                                  headers=headers)
        probe_status = probe_resp.status_code
        probe_headers = probe_resp.headers
        probe_body = probe_resp.text[:5000]

        # Header-based WAF signatures
        if "CF-Ray" in probe_headers:
            waf_detected = True
            waf_name = "Cloudflare"
            confidence = "HIGH"
            evidence = "CF-Ray header present"
        elif "X-Sucuri-ID" in probe_headers:
            waf_detected = True
            waf_name = "Sucuri"
            confidence = "HIGH"
            evidence = "X-Sucuri-ID header present"
        elif probe_headers.get("X-CDN", "").lower() == "incapsula":
            waf_detected = True
            waf_name = "Imperva Incapsula"
            confidence = "HIGH"
            evidence = "X-CDN: Incapsula header present"
        elif probe_headers.get("Server", "").lower() == "cloudflare":
            waf_detected = True
            waf_name = "Cloudflare"
            confidence = "HIGH"
            evidence = "Server: cloudflare header present"
        elif "X-Powered-By-Plesk" in probe_headers:
            waf_detected = True
            waf_name = "Plesk"
            confidence = "HIGH"
            evidence = "X-Powered-By-Plesk header present"

        # Body-based WAF signatures
        if not waf_detected:
            if "Access Denied" in probe_body and "Barracuda" in probe_body:
                waf_detected = True
                waf_name = "Barracuda"
                confidence = "HIGH"
                evidence = "Body contains 'Access Denied' and 'Barracuda'"
            elif "mod_security" in probe_body or "ModSecurity" in probe_body:
                waf_detected = True
                waf_name = "ModSecurity"
                confidence = "HIGH"
                evidence = "Body contains ModSecurity signature"
            elif "Request rejected" in probe_body:
                waf_detected = True
                waf_name = "Unknown WAF"
                confidence = "MEDIUM"
                evidence = "Body contains 'Request rejected'"

        # Status code-based detection
        if not waf_detected:
            if probe_status in (406, 501):
                waf_detected = True
                waf_name = "Unknown WAF"
                confidence = "MEDIUM"
                evidence = f"Malicious probe returned HTTP {probe_status}"
            elif baseline_status == 200 and probe_status in (403, 406, 501):
                waf_detected = True
                waf_name = "Unknown WAF"
                confidence = "MEDIUM"
                evidence = (f"Baseline returned {baseline_status} but "
                            f"malicious probe returned {probe_status}")

    except Exception as e:
        result["error"] = str(e)
        result["waf_detected"] = False
        result["waf_name"] = "Unknown WAF"
        result["confidence"] = "LOW"
        result["evidence"] = ""
        result["success"] = False
        return result

    result["waf_detected"] = waf_detected
    result["waf_name"] = waf_name if waf_detected else "None detected"
    result["confidence"] = confidence
    result["evidence"] = evidence
    result["success"] = True
    return result


# ─── Subdomain Discovery (crt.sh) ─────────────────────────────────────────────

def subdomain_crtsh(target: str) -> dict:
    """Passive subdomain discovery via crt.sh certificate transparency logs."""
    domain = _get_domain(target)
    result = {"tool": "crtsh", "target": target}

    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0 (compatible; SniperSan/1.0)"}
        )
        resp.raise_for_status()
        data = resp.json()

        # Extract and deduplicate subdomains
        subdomains = set()
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip()
                if sub.startswith("*."):
                    sub = sub[2:]
                if sub and sub.endswith(domain):
                    subdomains.add(sub)

        # Resolve IPs
        found = []
        for sub in sorted(subdomains):
            ip = ""
            try:
                ip = socket.gethostbyname(sub)
            except Exception:
                pass
            found.append({"subdomain": sub, "ip": ip})

        result["found"] = found
        result["total_found"] = len(found)
        result["success"] = True

    except Exception as e:
        result["found"] = []
        result["total_found"] = 0
        result["error"] = str(e)
        result["success"] = False

    return result


# ─── DNS Enumeration ──────────────────────────────────────────────────────────

def dns_enum(target: str) -> dict:
    """DNS enumeration using dnspython."""
    import dns.resolver
    import dns.query
    import dns.zone
    import dns.exception

    domain = _get_domain(target)
    result = {"tool": "dns_enum", "target": target}

    records = {"A": [], "MX": [], "TXT": [], "NS": [], "SOA": []}
    zone_transfer_success = False
    zone_transfer_data = []

    for rtype in records.keys():
        try:
            answers = dns.resolver.resolve(domain, rtype)
            for rdata in answers:
                records[rtype].append(str(rdata))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception:
            pass

    # Attempt zone transfer from each NS
    for ns_name in records.get("NS", []):
        ns_name = ns_name.rstrip(".")
        try:
            ns_ip = socket.gethostbyname(ns_name)
            xfr = dns.query.xfr(ns_ip, domain, timeout=10)
            z = dns.zone.from_xfr(xfr)
            for name, node in z.nodes.items():
                zone_transfer_data.append(f"{name} {node.to_text(name)}")
            zone_transfer_success = True
        except Exception:
            pass

    result["records"] = records
    result["zone_transfer_success"] = zone_transfer_success
    result["zone_transfer_data"] = zone_transfer_data
    result["success"] = True
    return result


def shodan_lookup(target: str) -> dict:
    """Query Shodan for existing scan data on the target IP/domain."""
    import shodan as shodan_lib

    result = {"tool": "shodan_lookup", "target": target}

    if not SHODAN_API_KEY:
        result["error"] = "SHODAN_API_KEY not configured"
        result["success"] = False
        return result

    domain = _get_domain(target)

    # Resolve domain to IP if needed
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        result["error"] = f"Could not resolve {domain}"
        result["success"] = False
        return result

    result["ip"] = ip

    try:
        api = shodan_lib.Shodan(SHODAN_API_KEY)
        host = api.host(ip)

        # Core host info
        result["hostnames"] = host.get("hostnames", [])
        result["domains"] = host.get("domains", [])
        result["org"] = host.get("org", "")
        result["isp"] = host.get("isp", "")
        result["asn"] = host.get("asn", "")
        result["country"] = host.get("country_name", "")
        result["city"] = host.get("city", "")
        result["os"] = host.get("os", "")
        result["last_update"] = host.get("last_update", "")
        result["tags"] = host.get("tags", [])
        result["vulns"] = list(host.get("vulns", {}).keys())

        # Open ports and services
        ports = []
        for item in host.get("data", []):
            port_info = {
                "port": item.get("port"),
                "transport": item.get("transport", "tcp"),
                "product": item.get("product", ""),
                "version": item.get("version", ""),
                "cpe": item.get("cpe", []),
                "banner": (item.get("data", "") or "")[:200].strip(),
            }
            # SSL info if present
            if "ssl" in item:
                ssl_data = item["ssl"]
                port_info["ssl"] = {
                    "subject": ssl_data.get("cert", {}).get("subject", {}),
                    "expires": ssl_data.get("cert", {}).get("expires", ""),
                    "cipher": ssl_data.get("cipher", {}).get("name", ""),
                }
            ports.append(port_info)

        result["ports"] = ports
        result["open_port_numbers"] = sorted({p["port"] for p in ports})

        # Severity: CRITICAL if known CVEs, HIGH if dangerous ports open
        dangerous_ports = {21, 23, 445, 3389, 5900, 6379, 27017, 9200, 5432, 3306}
        exposed = dangerous_ports & set(result["open_port_numbers"])
        if result["vulns"]:
            result["severity"] = "CRITICAL"
            result["finding"] = f"Shodan reports {len(result['vulns'])} known CVE(s): {', '.join(result['vulns'][:5])}"
        elif exposed:
            result["severity"] = "HIGH"
            result["finding"] = f"Dangerous services exposed: ports {sorted(exposed)}"
        else:
            result["severity"] = "INFO"
            result["finding"] = f"{len(ports)} services indexed by Shodan"

        result["success"] = True

    except shodan_lib.APIError as e:
        result["error"] = str(e)
        result["success"] = False

    return result
