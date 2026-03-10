"""Enumeration: directory brute-force, subdomain discovery."""
import subprocess
import concurrent.futures
from pathlib import Path
from urllib.parse import urlparse

import requests

from config import DEFAULT_TIMEOUT, DEFAULT_THREADS, MAX_DIRS_TO_SCAN, WORDLISTS_DIR


def _get_base_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target.rstrip("/")


def _get_domain(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return urlparse(target).netloc
    return target.split("/")[0]


def _load_wordlist(wordlist: str = "common") -> list[str]:
    """Load wordlist from file or use built-in."""
    wl_path = WORDLISTS_DIR / f"{wordlist}.txt"
    if not wl_path.exists():
        wl_path = Path(wordlist)

    if wl_path.exists():
        with open(wl_path) as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]

    # Fallback minimal built-in wordlist
    return [
        "admin", "administrator", "login", "logout", "dashboard", "panel",
        "wp-admin", "wp-login.php", "phpmyadmin", "pma", "config", "backup",
        "api", "v1", "v2", "graphql", "swagger", "swagger-ui", "docs", "api-docs",
        "upload", "uploads", "files", "images", "static", "assets", "media",
        "robots.txt", "sitemap.xml", ".env", ".git", ".htaccess", ".htpasswd",
        "test", "dev", "debug", "info", "phpinfo.php", "shell", "webshell",
        "index.php", "index.html", "home", "user", "users", "register", "signup",
        "forgot", "reset", "password", "auth", "oauth", "callback", "token",
        "cgi-bin", "server-status", "server-info", "readme", "readme.txt",
        "changelog", "license", "install", "setup", "update", "error", "logs",
        "log", "tmp", "temp", "cache", "db", "database", "sql", "dump",
        "console", "terminal", "shell.php", "cmd.php", "exec.php",
        "portal", "support", "help", "contact", "about", "mail", "webmail",
        "cpanel", "whm", "plesk", "directadmin", "ftp", "ssh",
    ]


def _check_path(url: str, path: str, session: requests.Session) -> dict | None:
    """Check if a path exists on the server."""
    target = f"{url}/{path}"
    try:
        resp = session.get(target, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
        if resp.status_code not in (404, 400, 410):
            return {
                "path": f"/{path}",
                "url": target,
                "status": resp.status_code,
                "size": len(resp.content),
                "redirect": resp.headers.get("Location", ""),
            }
    except Exception:
        pass
    return None


def dir_bust(target: str, wordlist: str = "common", threads: int = DEFAULT_THREADS,
             extensions: list[str] | None = None) -> dict:
    """Brute-force directories and files on target."""
    url = _get_base_url(target)
    result = {"tool": "dir_bust", "target": url, "wordlist": wordlist}

    words = _load_wordlist(wordlist)[:MAX_DIRS_TO_SCAN]

    # Add extension variants
    if extensions:
        extended = []
        for word in words:
            extended.append(word)
            for ext in extensions:
                extended.append(f"{word}.{ext}")
        words = extended

    found = []
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (compatible; SniperSan/1.0)"

    # Detect 404 page
    try:
        fake_resp = session.get(f"{url}/this_path_does_not_exist_snipersan_xyz123",
                                timeout=DEFAULT_TIMEOUT, allow_redirects=False)
        fake_status = fake_resp.status_code
        fake_size = len(fake_resp.content)
    except Exception:
        fake_status = 404
        fake_size = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(_check_path, url, word, session): word for word in words}
        for future in concurrent.futures.as_completed(futures):
            hit = future.result()
            if hit:
                # Filter false positives
                if hit["status"] == fake_status and abs(hit["size"] - fake_size) < 50:
                    continue
                found.append(hit)

    # Sort by status code
    found.sort(key=lambda x: x["status"])

    interesting = [f for f in found if f["status"] in (200, 201, 301, 302, 403)]
    result["found"] = found
    result["interesting"] = interesting
    result["total_scanned"] = len(words)
    result["total_found"] = len(found)
    result["success"] = True
    return result


def _check_subdomain(domain: str, sub: str, session: requests.Session) -> dict | None:
    """Check if a subdomain resolves."""
    import socket
    subdomain = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(subdomain)
        # Try HTTP
        status = None
        for scheme in ("https", "http"):
            try:
                resp = session.get(f"{scheme}://{subdomain}", timeout=DEFAULT_TIMEOUT,
                                   allow_redirects=False)
                status = resp.status_code
                break
            except Exception:
                pass
        return {"subdomain": subdomain, "ip": ip, "http_status": status}
    except socket.gaierror:
        return None


def subdomain_enum(target: str, wordlist: str = "subdomains",
                   threads: int = DEFAULT_THREADS) -> dict:
    """Enumerate subdomains via brute-force."""
    domain = _get_domain(target)
    # Remove www if present
    if domain.startswith("www."):
        domain = domain[4:]

    result = {"tool": "subdomain_enum", "target": domain}

    # Subdomain wordlist
    wl_path = WORDLISTS_DIR / "subdomains.txt"
    if wl_path.exists():
        with open(wl_path) as f:
            subs = [line.strip() for line in f if line.strip()][:500]
    else:
        subs = [
            "www", "mail", "ftp", "remote", "blog", "webmail", "server", "ns1", "ns2",
            "smtp", "secure", "vpn", "m", "shop", "cloud", "api", "dev", "staging",
            "admin", "portal", "test", "app", "beta", "mobile", "static", "assets",
            "cdn", "img", "images", "media", "downloads", "support", "help",
            "docs", "wiki", "git", "gitlab", "github", "ci", "jenkins", "jira",
            "confluence", "dashboard", "monitor", "status", "internal", "intranet",
            "db", "database", "mysql", "redis", "elasticsearch", "kibana",
            "grafana", "prometheus", "backup", "old", "new", "v2", "v3",
        ]

    found = []
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0"

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(_check_subdomain, domain, sub, session): sub for sub in subs}
        for future in concurrent.futures.as_completed(futures):
            hit = future.result()
            if hit:
                found.append(hit)

    found.sort(key=lambda x: x["subdomain"])
    result["found"] = found
    result["total_found"] = len(found)
    result["total_checked"] = len(subs)
    result["success"] = True
    return result


# ─── Virtual Host Enumeration ─────────────────────────────────────────────────

VHOST_BUILTIN = [
    "www", "mail", "admin", "api", "dev", "staging", "test", "app", "portal",
    "dashboard", "internal", "intranet", "vpn", "ftp", "smtp", "webmail",
    "mx", "ns1", "shop", "store", "blog", "docs", "wiki", "status", "monitor",
    "git", "jenkins", "ci", "cdn", "static",
]


def vhost_enum(target: str, wordlist: str = "subdomains") -> dict:
    """Virtual host enumeration via Host header fuzzing."""
    import socket

    base_url = _get_base_url(target)
    result = {"tool": "vhost_enum", "target": base_url}

    # Resolve IP
    domain = _get_domain(target)
    # Strip port if present
    domain_clean = domain.split(":")[0]

    try:
        ip = socket.gethostbyname(domain_clean)
        base_domain = domain_clean
    except socket.gaierror:
        # Target might already be an IP
        ip = domain_clean
        base_domain = "target.local"

    result["ip"] = ip

    # Load wordlist
    wl_path = WORDLISTS_DIR / f"{wordlist}.txt"
    if wl_path.exists():
        with open(wl_path) as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")][:500]
    else:
        words = VHOST_BUILTIN

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (compatible; SniperSan/1.0)"

    # Baseline: GET with default host
    baseline_status = None
    baseline_size = 0
    try:
        baseline_resp = session.get(f"http://{ip}/", timeout=DEFAULT_TIMEOUT,
                                    allow_redirects=False)
        baseline_status = baseline_resp.status_code
        baseline_size = len(baseline_resp.content)
    except Exception:
        pass

    result["baseline_status"] = baseline_status
    result["baseline_size"] = baseline_size

    found = []

    def _check_vhost(word: str) -> dict | None:
        vhost = f"{word}.{base_domain}"
        try:
            resp = session.get(
                f"http://{ip}/",
                headers={"Host": vhost},
                timeout=DEFAULT_TIMEOUT,
                allow_redirects=False,
            )
            size = len(resp.content)
            size_diff = abs(size - baseline_size)
            threshold = max(baseline_size * 0.1, 50)
            if resp.status_code != baseline_status or size_diff > threshold:
                return {
                    "vhost": vhost,
                    "status": resp.status_code,
                    "size": size,
                    "size_diff": size_diff,
                }
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(_check_vhost, word): word for word in words}
        for future in concurrent.futures.as_completed(futures):
            hit = future.result()
            if hit:
                found.append(hit)

    found.sort(key=lambda x: x["vhost"])
    result["found"] = found
    result["total_found"] = len(found)
    result["success"] = True
    return result


# ─── Parameter Discovery ──────────────────────────────────────────────────────

PARAM_LIST = [
    "id", "user", "username", "email", "page", "limit", "offset", "search", "q",
    "query", "filter", "sort", "order", "type", "action", "mode", "format", "lang",
    "locale", "token", "key", "api_key", "auth", "session", "debug", "test", "admin",
    "file", "path", "url", "redirect", "return", "next", "callback", "ref", "source",
    "from", "to", "date", "start", "end", "category", "tag", "name", "title", "desc",
    "description", "content", "data", "value", "param", "var", "field", "status",
    "state", "role", "level", "group", "org", "account", "profile", "setting",
    "config", "version", "v", "output", "view", "template", "layout", "theme",
    "style", "class", "method", "func", "cmd", "exec", "run", "op", "do", "task",
    "job", "report", "export", "import",
]

PROBE_VALUE = "SniperSanProbe7x3k9"


def param_discovery(target: str, method: str = "GET") -> dict:
    """Hidden parameter discovery via brute-force."""
    url = _get_base_url(target)
    result = {"tool": "param_discovery", "target": url, "method": method.upper()}

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (compatible; SniperSan/1.0)"

    # Baseline request
    baseline_status = None
    baseline_size = 0
    try:
        if method.upper() == "POST":
            baseline_resp = session.post(url, data={}, timeout=DEFAULT_TIMEOUT)
        else:
            baseline_resp = session.get(url, timeout=DEFAULT_TIMEOUT)
        baseline_status = baseline_resp.status_code
        baseline_size = len(baseline_resp.content)
    except Exception:
        pass

    result["baseline_status"] = baseline_status
    result["baseline_size"] = baseline_size

    active_params = []

    def _check_param(param: str) -> dict | None:
        try:
            if method.upper() == "POST":
                resp = session.post(url, data={param: PROBE_VALUE}, timeout=DEFAULT_TIMEOUT)
            else:
                resp = session.get(url, params={param: PROBE_VALUE}, timeout=DEFAULT_TIMEOUT)
            size = len(resp.content)
            size_diff = abs(size - baseline_size)
            if resp.status_code != baseline_status or size_diff > 50:
                return {
                    "param": param,
                    "status": resp.status_code,
                    "size": size,
                    "size_diff": size_diff,
                }
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(_check_param, param): param for param in PARAM_LIST}
        for future in concurrent.futures.as_completed(futures):
            hit = future.result()
            if hit:
                active_params.append(hit)

    active_params.sort(key=lambda x: x["param"])
    result["active_params"] = active_params
    result["total_found"] = len(active_params)
    result["success"] = True
    return result
