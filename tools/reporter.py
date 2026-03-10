"""Report generation: Markdown, JSON, HTML."""
import json
from datetime import datetime
from pathlib import Path

from jinja2 import Template
from cvss import CVSS3

from config import REPORTS_DIR, TEMPLATES_DIR


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#d97706",
    "LOW": "#65a30d",
    "INFO": "#2563eb",
}


CVSS_VECTORS = {
    "SQLi": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "XSS": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "SSTI": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "LFI": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "Command Injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "XXE": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "SSRF": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
    "CORS": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
    "CSRF": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
    "Open Redirect": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "JWT": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "403 Bypass": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "IDOR": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "GraphQL": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "Request Smuggling": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",
    "Exposed Secret": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "WordPress": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "Default": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
}


def _get_cvss(vuln: dict) -> dict:
    """Calculate CVSS v3.1 score for a vulnerability."""
    vuln_type = vuln.get("type", "")
    vector = None
    for key, vec in CVSS_VECTORS.items():
        if key.lower() in vuln_type.lower():
            vector = vec
            break
    if not vector:
        vector = CVSS_VECTORS["Default"]
    try:
        c = CVSS3(vector)
        return {"score": float(str(c.base_score)), "vector": vector, "rating": c.severities()[0]}
    except Exception:
        return {"score": 0.0, "vector": vector, "rating": "Unknown"}


def _ensure_reports_dir():
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def _timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _collect_all_vulns(findings: dict) -> list[dict]:
    """Flatten all vulnerabilities from all tools."""
    all_vulns = []
    for tool_name, data in findings.items():
        if isinstance(data, dict):
            vulns = data.get("vulnerabilities", data.get("found", []))
            if isinstance(vulns, list):
                for v in vulns:
                    if isinstance(v, dict):
                        v["_tool"] = tool_name
                        v["cvss"] = _get_cvss(v)
                        all_vulns.append(v)
    all_vulns.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO"), 5))
    return all_vulns


def generate_json(target: str, findings: dict, summary: str = "") -> str:
    """Generate JSON report."""
    _ensure_reports_dir()
    ts = _timestamp()
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    filename = f"{domain}_{ts}.json"
    filepath = REPORTS_DIR / filename

    report = {
        "meta": {
            "target": target,
            "generated_at": datetime.now().isoformat(),
            "tool": "SniperSan",
            "version": "1.0"
        },
        "summary": summary,
        "findings": findings,
        "vulnerabilities": _collect_all_vulns(findings),
        "stats": _compute_stats(findings)
    }

    with open(filepath, "w") as f:
        json.dump(report, f, indent=2, default=str)

    return str(filepath)


def generate_markdown(target: str, findings: dict, summary: str = "") -> str:
    """Generate Markdown report."""
    _ensure_reports_dir()
    ts = _timestamp()
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    filename = f"{domain}_{ts}.md"
    filepath = REPORTS_DIR / filename

    all_vulns = _collect_all_vulns(findings)
    stats = _compute_stats(findings)

    lines = [
        f"# SniperSan - Penetration Test Report",
        f"",
        f"**Target:** `{target}`  ",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"**Tool:** SniperSan v1.0",
        f"",
        f"---",
        f"",
        f"## Executive Summary",
        f"",
        summary or "_No summary provided._",
        f"",
        f"---",
        f"",
        f"## Risk Overview",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
    ]

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = stats["by_severity"].get(sev, 0)
        lines.append(f"| {sev} | {count} |")

    lines += [
        f"| **TOTAL** | **{stats['total_vulns']}** |",
        f"",
        f"---",
        f"",
        f"## Vulnerabilities",
        f"",
    ]

    if not all_vulns:
        lines.append("_No vulnerabilities found._")
    else:
        for i, vuln in enumerate(all_vulns, 1):
            sev = vuln.get("severity", "INFO")
            lines += [
                f"### [{sev}] {vuln.get('type', 'Unknown')}",
                f"",
                f"- **URL:** `{vuln.get('url', '-')}`",
            ]
            if vuln.get("parameter"):
                lines.append(f"- **Parameter:** `{vuln['parameter']}`")
            if vuln.get("payload"):
                lines.append(f"- **Payload:** `{vuln['payload']}`")
            if vuln.get("evidence"):
                lines.append(f"- **Evidence:** {vuln['evidence']}")
            if vuln.get("recommendation"):
                lines.append(f"- **Recommendation:** {vuln['recommendation']}")
            lines.append(f"")

    # Recon sections
    lines += ["---", "", "## Reconnaissance Results", ""]

    # Open ports
    nmap = findings.get("nmap", {})
    if nmap.get("success"):
        lines += ["### Open Ports", ""]
        services = nmap.get("services", [])
        if services:
            lines += ["| Port | Service | Product | Version |",
                      "|------|---------|---------|---------|"]
            for s in services:
                lines.append(f"| {s['port']} | {s['service']} | {s['product']} | {s['version']} |")
        ports = nmap.get("open_ports", [])
        if ports and not services:
            lines.append(f"Open ports: {', '.join(str(p['port']) for p in ports)}")
        lines.append("")

    # Technologies
    fp = findings.get("fingerprint", {})
    if fp.get("technologies"):
        lines += ["### Detected Technologies", ""]
        for tech in fp["technologies"]:
            lines.append(f"- {tech}")
        lines.append("")

    # Directory busting
    dirs = findings.get("dir_bust", {})
    if dirs.get("interesting"):
        lines += ["### Interesting Paths", ""]
        lines += ["| Path | Status | Size |", "|------|--------|------|"]
        for d in dirs["interesting"][:20]:
            lines.append(f"| `{d['path']}` | {d['status']} | {d['size']} |")
        lines.append("")

    # SSL
    ssl_data = findings.get("ssl", {})
    if ssl_data.get("success"):
        lines += ["### SSL/TLS", ""]
        lines.append(f"- **TLS Version:** {ssl_data.get('tls_version', 'unknown')}")
        lines.append(f"- **Cipher:** {ssl_data.get('cipher', 'unknown')}")
        lines.append(f"- **Expires:** {ssl_data.get('expires', 'unknown')} "
                     f"({ssl_data.get('days_until_expiry', '?')} days)")
        if ssl_data.get("san_domains"):
            lines.append(f"- **SAN Domains:** {', '.join(ssl_data['san_domains'][:10])}")
        lines.append("")

    lines += ["---", "", "_Report generated by SniperSan_"]

    with open(filepath, "w") as f:
        f.write("\n".join(lines))

    return str(filepath)


def generate_html(target: str, findings: dict, summary: str = "") -> str:
    """Generate HTML report."""
    _ensure_reports_dir()
    ts = _timestamp()
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    filename = f"{domain}_{ts}.html"
    filepath = REPORTS_DIR / filename

    all_vulns = _collect_all_vulns(findings)
    stats = _compute_stats(findings)

    # Check for custom template
    template_path = TEMPLATES_DIR / "report.html"

    html_template = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SniperSan Report - {{ target }}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #e2e8f0; }
  .header { background: linear-gradient(135deg, #1e1b4b, #312e81); padding: 40px; }
  .header h1 { font-size: 2rem; color: #a78bfa; margin-bottom: 8px; }
  .header .meta { color: #94a3b8; font-size: 0.9rem; }
  .container { max-width: 1200px; margin: 0 auto; padding: 24px; }
  .card { background: #1e293b; border-radius: 12px; padding: 24px; margin-bottom: 24px; border: 1px solid #334155; }
  .card h2 { font-size: 1.2rem; color: #a78bfa; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid #334155; }
  .stats-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; }
  .stat-card { border-radius: 8px; padding: 16px; text-align: center; }
  .stat-card .count { font-size: 2rem; font-weight: bold; }
  .stat-card .label { font-size: 0.8rem; opacity: 0.8; }
  .CRITICAL { background: #450a0a; border: 1px solid #dc2626; }
  .CRITICAL .count { color: #f87171; }
  .HIGH { background: #431407; border: 1px solid #ea580c; }
  .HIGH .count { color: #fb923c; }
  .MEDIUM { background: #422006; border: 1px solid #d97706; }
  .MEDIUM .count { color: #fbbf24; }
  .LOW { background: #1a2e05; border: 1px solid #65a30d; }
  .LOW .count { color: #a3e635; }
  .INFO { background: #172554; border: 1px solid #2563eb; }
  .INFO .count { color: #60a5fa; }
  .vuln-item { border-radius: 8px; padding: 16px; margin-bottom: 12px; border-left: 4px solid; }
  .vuln-CRITICAL { background: #1c0505; border-color: #dc2626; }
  .vuln-HIGH { background: #1c0a03; border-color: #ea580c; }
  .vuln-MEDIUM { background: #1c1203; border-color: #d97706; }
  .vuln-LOW { background: #0d1c03; border-color: #65a30d; }
  .vuln-INFO { background: #030d1c; border-color: #2563eb; }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 9999px; font-size: 0.75rem; font-weight: bold; margin-bottom: 8px; }
  .badge-CRITICAL { background: #dc2626; color: white; }
  .badge-HIGH { background: #ea580c; color: white; }
  .badge-MEDIUM { background: #d97706; color: white; }
  .badge-LOW { background: #65a30d; color: white; }
  .badge-INFO { background: #2563eb; color: white; }
  .vuln-title { font-size: 1rem; font-weight: 600; color: #f1f5f9; margin-bottom: 8px; }
  .vuln-detail { font-size: 0.85rem; color: #94a3b8; margin: 4px 0; }
  .vuln-detail code { background: #0f172a; padding: 2px 6px; border-radius: 4px; color: #a78bfa; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th { background: #334155; padding: 10px; text-align: left; color: #94a3b8; }
  td { padding: 10px; border-bottom: 1px solid #1e293b; }
  tr:hover { background: #243044; }
  .summary { background: #0f2740; border-radius: 8px; padding: 16px; font-size: 0.95rem; line-height: 1.6; white-space: pre-wrap; }
  .no-vulns { text-align: center; color: #4ade80; padding: 24px; font-size: 1.1rem; }
</style>
</head>
<body>
<div class="header">
  <h1>🎯 SniperSan - Penetration Test Report</h1>
  <div class="meta">
    Target: <strong>{{ target }}</strong> &nbsp;|&nbsp;
    Date: {{ date }} &nbsp;|&nbsp;
    Total Vulnerabilities: {{ stats.total_vulns }}
  </div>
</div>
<div class="container">

  <!-- Stats -->
  <div class="card">
    <h2>Risk Overview</h2>
    <div class="stats-grid">
      {% for sev in ['CRITICAL','HIGH','MEDIUM','LOW','INFO'] %}
      <div class="stat-card {{ sev }}">
        <div class="count">{{ stats.by_severity.get(sev, 0) }}</div>
        <div class="label">{{ sev }}</div>
      </div>
      {% endfor %}
    </div>
  </div>

  <!-- Summary -->
  {% if summary %}
  <div class="card">
    <h2>Executive Summary</h2>
    <div class="summary">{{ summary }}</div>
  </div>
  {% endif %}

  <!-- Vulnerabilities -->
  <div class="card">
    <h2>Vulnerabilities ({{ stats.total_vulns }})</h2>
    {% if all_vulns %}
      {% for vuln in all_vulns %}
      <div class="vuln-item vuln-{{ vuln.severity }}">
        <span class="badge badge-{{ vuln.severity }}">{{ vuln.severity }}</span>
        <div class="vuln-title">{{ vuln.type }}</div>
        {% if vuln.url %}<div class="vuln-detail">URL: <code>{{ vuln.url }}</code></div>{% endif %}
        {% if vuln.parameter %}<div class="vuln-detail">Parameter: <code>{{ vuln.parameter }}</code></div>{% endif %}
        {% if vuln.payload %}<div class="vuln-detail">Payload: <code>{{ vuln.payload }}</code></div>{% endif %}
        {% if vuln.evidence %}<div class="vuln-detail">Evidence: {{ vuln.evidence }}</div>{% endif %}
        {% if vuln.cvss %}<div class="vuln-detail">CVSS: <code>{{ vuln.cvss.score }} ({{ vuln.cvss.rating }})</code></div>{% endif %}
        {% if vuln.recommendation %}<div class="vuln-detail">Fix: {{ vuln.recommendation }}</div>{% endif %}
      </div>
      {% endfor %}
    {% else %}
      <div class="no-vulns">✅ No vulnerabilities found</div>
    {% endif %}
  </div>

  <!-- Open Ports -->
  {% if findings.nmap and findings.nmap.services %}
  <div class="card">
    <h2>Open Ports & Services</h2>
    <table>
      <tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th></tr>
      {% for s in findings.nmap.services %}
      <tr><td>{{ s.port }}</td><td>{{ s.service }}</td><td>{{ s.product }}</td><td>{{ s.version }}</td></tr>
      {% endfor %}
    </table>
  </div>
  {% endif %}

  <!-- Technologies -->
  {% if findings.fingerprint and findings.fingerprint.technologies %}
  <div class="card">
    <h2>Detected Technologies</h2>
    <div style="display:flex;flex-wrap:wrap;gap:8px;">
      {% for tech in findings.fingerprint.technologies %}
      <span style="background:#334155;padding:4px 12px;border-radius:9999px;font-size:0.85rem;">{{ tech }}</span>
      {% endfor %}
    </div>
  </div>
  {% endif %}

  <!-- Directories -->
  {% if findings.dir_bust and findings.dir_bust.interesting %}
  <div class="card">
    <h2>Interesting Paths</h2>
    <table>
      <tr><th>Path</th><th>Status</th><th>Size</th></tr>
      {% for d in findings.dir_bust.interesting[:30] %}
      <tr>
        <td><code>{{ d.path }}</code></td>
        <td>{{ d.status }}</td>
        <td>{{ d.size }} bytes</td>
      </tr>
      {% endfor %}
    </table>
  </div>
  {% endif %}

  <!-- SSL -->
  {% if findings.ssl and findings.ssl.success %}
  <div class="card">
    <h2>SSL/TLS</h2>
    <table>
      <tr><th>Property</th><th>Value</th></tr>
      <tr><td>TLS Version</td><td>{{ findings.ssl.tls_version }}</td></tr>
      <tr><td>Cipher</td><td>{{ findings.ssl.cipher }}</td></tr>
      <tr><td>Expires</td><td>{{ findings.ssl.expires }} ({{ findings.ssl.days_until_expiry }} days)</td></tr>
      {% if findings.ssl.san_domains %}
      <tr><td>SAN Domains</td><td>{{ findings.ssl.san_domains[:10]|join(', ') }}</td></tr>
      {% endif %}
    </table>
  </div>
  {% endif %}

</div>
<div style="text-align:center;padding:24px;color:#475569;font-size:0.8rem;">
  Generated by SniperSan &nbsp;|&nbsp; {{ date }}
</div>
</body>
</html>"""

    tmpl = Template(html_template)
    html = tmpl.render(
        target=target,
        date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        findings=findings,
        all_vulns=all_vulns,
        stats=stats,
        summary=summary,
    )

    with open(filepath, "w") as f:
        f.write(html)

    return str(filepath)


def _compute_stats(findings: dict) -> dict:
    all_vulns = _collect_all_vulns(findings)
    by_sev = {}
    for v in all_vulns:
        sev = v.get("severity", "INFO")
        by_sev[sev] = by_sev.get(sev, 0) + 1
    return {
        "total_vulns": len(all_vulns),
        "by_severity": by_sev,
        "critical": by_sev.get("CRITICAL", 0),
        "high": by_sev.get("HIGH", 0),
        "medium": by_sev.get("MEDIUM", 0),
        "low": by_sev.get("LOW", 0),
    }


def generate_pdf(target: str, findings: dict, summary: str = "") -> str:
    """Generate PDF report via WeasyPrint."""
    try:
        from weasyprint import HTML as WPHTML
    except ImportError:
        raise RuntimeError("weasyprint not installed: pip install weasyprint")

    # Generate HTML first
    html_path = generate_html(target, findings, summary)

    # Convert to PDF
    pdf_path = html_path.replace(".html", ".pdf")
    WPHTML(filename=html_path).write_pdf(pdf_path)
    return pdf_path


def generate_report(target: str, findings: dict, format: str, summary: str = "") -> str:
    """Generate report in specified format. Returns file path."""
    fmt = format.lower()
    if fmt == "json":
        return generate_json(target, findings, summary)
    elif fmt == "markdown" or fmt == "md":
        return generate_markdown(target, findings, summary)
    elif fmt == "html":
        return generate_html(target, findings, summary)
    elif fmt == "pdf":
        return generate_pdf(target, findings, summary)
    else:
        raise ValueError(f"Unknown format: {format}. Use: json, markdown, html, pdf")
