import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


class ReportGenerator:
    FORMATS = ("html", "json", "both")

    def __init__(self, report_dir="reports"):
        self.report_dir = Path(report_dir)

    @staticmethod
    def _slug(target):
        try:
            hostname = urlsplit(target).hostname or "target"
        except ValueError:
            hostname = "target"

        slug = re.sub(r"[^a-zA-Z0-9.-]+", "-", hostname)
        return slug.strip(".-")[:80] or "target"

    @staticmethod
    def _timestamp():
        return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    @staticmethod
    def _safe_json(results, target):
        return {
            "tool": "RRI",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target": target,
            "results": results,
        }

    @staticmethod
    def _items(results, key, list_key):
        module = results.get(key)
        if not isinstance(module, dict):
            return []
        items = module.get(list_key, [])
        return items if isinstance(items, list) else []

    @staticmethod
    def _count(results, key, list_key):
        return len(ReportGenerator._items(results, key, list_key))

    @staticmethod
    def _severity_counts(results):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for key, list_key in (
            ("headers_analysis", "findings"),
            ("security_checks", "findings"),
            ("correlation", "correlations"),
        ):
            for item in ReportGenerator._items(results, key, list_key):
                if not isinstance(item, dict):
                    continue
                severity = str(item.get("severity", "info")).lower()
                if severity in counts:
                    counts[severity] += 1

        return counts

    @staticmethod
    def _e(value):
        return html.escape(str(value if value is not None else ""), quote=True)

    def _html_report(self, document):
        results = document["results"]
        target = self._e(document["target"])
        generated = self._e(document["generated_at"])

        technologies = self._items(results, "technology", "technologies")
        endpoints = self._items(results, "api_discovery", "endpoints")
        header_findings = self._items(results, "headers_analysis", "findings")
        security_findings = self._items(results, "security_checks", "findings")
        correlations = self._items(results, "correlation", "correlations")
        discovered_urls = self._items(results, "crawler", "discovered_urls")
        discovered_paths = self._items(results, "path_discovery", "discovered_paths")
        dns_records = self._items(results, "dns_info", "records")
        js_scripts = self._items(results, "js_analysis", "analyzed_scripts")
        http_info = results.get("http_info", {})
        tls_info = results.get("tls_analysis", {})
        if not isinstance(http_info, dict):
            http_info = {}
        if not isinstance(tls_info, dict):
            tls_info = {}

        severity = self._severity_counts(results)
        total_findings = sum(severity.values())

        def cell(value):
            return f"<td>{self._e(value)}</td>"

        technology_rows = "".join(
            "<tr>"
            + cell(item.get("name", ""))
            + cell(item.get("category", ""))
            + cell(item.get("confidence", ""))
            + cell(item.get("score", ""))
            + "</tr>"
            for item in technologies if isinstance(item, dict)
        ) or '<tr><td colspan="4">No technologies detected.</td></tr>'

        endpoint_rows = "".join(
            "<tr>"
            + cell(item.get("url", ""))
            + cell(item.get("category", ""))
            + cell(item.get("confidence", ""))
            + cell(item.get("score", ""))
            + "</tr>"
            for item in endpoints if isinstance(item, dict)
        ) or '<tr><td colspan="4">No API endpoints discovered.</td></tr>'

        def finding_rows(items):
            rows = []
            for item in items:
                if not isinstance(item, dict):
                    continue
                rows.append(
                    "<tr>"
                    + cell(item.get("severity", ""))
                    + cell(item.get("title", ""))
                    + cell(item.get("category", ""))
                    + cell(item.get("evidence", ""))
                    + cell(item.get("recommendation", ""))
                    + "</tr>"
                )
            return "".join(rows) or '<tr><td colspan="5">No findings.</td></tr>'

        correlation_rows = "".join(
            "<tr>"
            + cell(item.get("type", item.get("category", "")))
            + cell(item.get("severity", ""))
            + cell(item.get("confidence", ""))
            + cell(item.get("evidence", ""))
            + "</tr>"
            for item in correlations if isinstance(item, dict)
        ) or '<tr><td colspan="4">No correlations found.</td></tr>'

        crawled_url_rows = "".join(
            "<tr>"
            + cell(item.get("url", ""))
            + cell(item.get("verification_status", ""))
            + cell(item.get("http_status", ""))
            + cell(item.get("discovery_source", ""))
            + "</tr>"
            for item in discovered_urls if isinstance(item, dict)
        ) or '<tr><td colspan="4">No URLs discovered.</td></tr>'

        path_rows = "".join(
            "<tr>"
            + cell(item.get("path", ""))
            + cell(item.get("verification_status", ""))
            + cell(item.get("discovery_source", ""))
            + cell(item.get("http_status", ""))
            + "</tr>"
            for item in discovered_paths if isinstance(item, dict)
        ) or '<tr><td colspan="4">No paths discovered.</td></tr>'

        dns_rows = "".join(
            "<tr>"
            + cell(item.get("record_type", ""))
            + cell(item.get("hostname", ""))
            + cell(", ".join(item.get("values", [])) if isinstance(item.get("values"), list) else "")
            + cell(item.get("discovery_source", ""))
            + "</tr>"
            for item in dns_records if isinstance(item, dict)
        ) or '<tr><td colspan="4">No DNS records found.</td></tr>'

        js_script_rows = "".join(
            "<tr>"
            + cell(item.get("script_url", ""))
            + cell(item.get("discovery_source", ""))
            + cell(len(item.get("api_paths", [])))
            + cell(len(item.get("internal_routes", [])))
            + cell(len(item.get("urls", [])))
            + "</tr>"
            for item in js_scripts if isinstance(item, dict)
        ) or '<tr><td colspan="5">No JavaScript files analyzed.</td></tr>'

        severity_cards = "".join(
            f'<div class="severity"><strong>{count}</strong>'
            f'<span>{self._e(name.title())}</span></div>'
            for name, count in severity.items()
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>RRI Recon Report</title>
<style>
:root {{
  color-scheme: dark;
  --bg: #101820;
  --panel: #192630;
  --line: #30434f;
  --text: #e8f0f4;
  --muted: #9fb0ba;
  --blue: #55b8e8;
  --green: #54d6a0;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  padding: 24px;
  background: var(--bg);
  color: var(--text);
  font-family: system-ui, sans-serif;
}}
main {{ max-width: 1200px; margin: auto; }}
header, section, .card {{
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 12px;
}}
header {{ padding: 24px; margin-bottom: 20px; }}
h1 {{ margin: 0 0 12px; color: var(--blue); }}
h2 {{ color: var(--green); margin-top: 0; }}
p, small {{ color: var(--muted); }}
section {{ padding: 20px; margin: 18px 0; }}
.stats {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
  gap: 12px;
  margin: 18px 0;
}}
.card {{ padding: 18px; }}
.card strong {{ display: block; font-size: 28px; color: var(--blue); }}
.severity {{
  display: flex;
  justify-content: space-between;
  gap: 12px;
  padding: 12px;
  background: var(--bg);
  border: 1px solid var(--line);
  border-radius: 8px;
}}
.severity strong {{ color: var(--blue); }}
.table-wrap {{ overflow-x: auto; }}
table {{ width: 100%; border-collapse: collapse; min-width: 650px; }}
th, td {{
  padding: 11px;
  border-bottom: 1px solid var(--line);
  text-align: left;
  overflow-wrap: anywhere;
}}
th {{ color: var(--blue); background: #14212a; }}
footer {{ text-align: center; padding: 24px; color: var(--muted); }}
@media (max-width: 600px) {{
  body {{ padding: 12px; }}
  header, section {{ padding: 15px; }}
}}
</style>
</head>
<body>
<main>
<header>
  <h1>RRI — Recon Intelligence</h1>
  <p><strong>Target:</strong> {target}</p>
  <p><strong>Generated:</strong> {generated}</p>
  <p>Passive analysis report. Findings require manual verification.</p>
</header>

<div class="stats">
  <div class="card"><strong>{len(technologies)}</strong>Technologies</div>
  <div class="card"><strong>{len(endpoints)}</strong>API endpoints</div>
  <div class="card"><strong>{len(discovered_urls)}</strong>Discovered URLs</div>
  <div class="card"><strong>{len(discovered_paths)}</strong>Discovered paths</div>
  <div class="card"><strong>{len(dns_records)}</strong>DNS records</div>
  <div class="card"><strong>{len(js_scripts)}</strong>JS scripts</div>
  <div class="card"><strong>{len(header_findings) + len(security_findings)}</strong>Security findings</div>
  <div class="card"><strong>{len(correlations)}</strong>Correlations</div>
  <div class="card"><strong>{total_findings}</strong>Severity entries</div>
</div>

<section>
<h2>Severity Overview</h2>
<div class="stats">{severity_cards}</div>
</section>

<section>
<h2>Technology Fingerprinting</h2>
<div class="table-wrap"><table>
<thead><tr><th>Technology</th><th>Category</th><th>Confidence</th><th>Score</th></tr></thead>
<tbody>{technology_rows}</tbody>
</table></div>
</section>

<section>
<h2>API Discovery</h2>
<div class="table-wrap"><table>
<thead><tr><th>Endpoint</th><th>Category</th><th>Confidence</th><th>Score</th></tr></thead>
<tbody>{endpoint_rows}</tbody>
</table></div>
</section>

<section>
<h2>Headers Analysis</h2>
<div class="table-wrap"><table>
<thead><tr><th>Severity</th><th>Finding</th><th>Category</th><th>Evidence</th><th>Recommendation</th></tr></thead>
<tbody>{finding_rows(header_findings)}</tbody>
</table></div>
</section>

<section>
<h2>Security Checks</h2>
<div class="table-wrap"><table>
<thead><tr><th>Severity</th><th>Finding</th><th>Category</th><th>Evidence</th><th>Recommendation</th></tr></thead>
<tbody>{finding_rows(security_findings)}</tbody>
</table></div>
</section>

<section>
<h2>Correlation Analysis</h2>
<p>Correlation does not establish that a vulnerability is exploitable.</p>
<div class="table-wrap"><table>
<thead><tr><th>Type</th><th>Severity</th><th>Confidence</th><th>Evidence</th></tr></thead>
<tbody>{correlation_rows}</tbody>
</table></div>
</section>

<section>
<h2>Crawled URLs</h2>
<div class="table-wrap"><table>
<thead><tr><th>URL</th><th>Verification</th><th>HTTP Status</th><th>Source</th></tr></thead>
<tbody>{crawled_url_rows}</tbody>
</table></div>
</section>

<section>
<h2>Discovered Paths</h2>
<div class="table-wrap"><table>
<thead><tr><th>Path</th><th>Verification</th><th>Source</th><th>HTTP Status</th></tr></thead>
<tbody>{path_rows}</tbody>
</table></div>
</section>

<section>
<h2>DNS Information</h2>
<div class="table-wrap"><table>
<thead><tr><th>Record Type</th><th>Hostname</th><th>Values</th><th>Source</th></tr></thead>
<tbody>{dns_rows}</tbody>
</table></div>
</section>

<section>
<h2>JavaScript Analysis</h2>
<div class="table-wrap"><table>
<thead><tr><th>Script URL</th><th>Source</th><th>API Paths</th><th>Routes</th><th>URLs</th></tr></thead>
<tbody>{js_script_rows}</tbody>
</table></div>
</section>

<section>
<h2>HTTP Information</h2>
<div class="table-wrap"><table>
<thead><tr><th>Property</th><th>Value</th></tr></thead>
<tbody>
<tr>{cell("HTTP Status")}{cell(http_info.get("http_status", "N/A"))}</tr>
<tr>{cell("Server")}{cell(http_info.get("server", "N/A"))}</tr>
<tr>{cell("Content Type")}{cell(http_info.get("content_type", "N/A"))}</tr>
<tr>{cell("Content Length")}{cell(http_info.get("content_length", "N/A"))}</tr>
<tr>{cell("Header Count")}{cell(http_info.get("header_count", "N/A"))}</tr>
</tbody>
</table></div>
</section>

<section>
<h2>TLS Certificate Analysis</h2>
<div class="table-wrap"><table>
<thead><tr><th>Property</th><th>Value</th></tr></thead>
<tbody>
<tr>{cell("TLS Version")}{cell(tls_info.get("tls_version", "N/A"))}</tr>
<tr>{cell("Cipher Suite")}{cell(tls_info.get("cipher_suite", "N/A"))}</tr>
<tr>{cell("Certificate Valid")}{cell(tls_info.get("cert_valid", "N/A"))}</tr>
<tr>{cell("Hostname Valid")}{cell(tls_info.get("cert_hostname_valid", "N/A"))}</tr>
<tr>{cell("Issuer")}{cell(tls_info.get("cert_issuer", "N/A"))}</tr>
<tr>{cell("Not Before")}{cell(tls_info.get("cert_not_before", "N/A"))}</tr>
<tr>{cell("Not After")}{cell(tls_info.get("cert_not_after", "N/A"))}</tr>
</tbody>
</table></div>
</section>

<footer>Generated locally by RRI — Recon Intelligence</footer>
</main>
</body>
</html>"""

    def generate(self, results, target, report_format="html", output=None):
        if report_format not in self.FORMATS:
            raise ValueError("Format must be html, json, or both.")

        if not isinstance(results, dict):
            raise ValueError("Results must be a dictionary.")

        if not isinstance(target, str) or not target:
            raise ValueError("A valid target is required.")

        self.report_dir.mkdir(parents=True, exist_ok=True)

        document = self._safe_json(results, target)
        timestamp = self._timestamp()
        slug = self._slug(target)

        formats = ("html", "json") if report_format == "both" else (report_format,)
        paths = []

        for fmt in formats:
            if output:
                base = Path(output)
                if report_format == "both":
                    path = base.with_suffix(f".{fmt}")
                elif base.suffix:
                    path = base
                else:
                    path = base.with_suffix(f".{fmt}")
            else:
                path = self.report_dir / f"rri_{slug}_{timestamp}.{fmt}"

            path.parent.mkdir(parents=True, exist_ok=True)

            if fmt == "json":
                content = json.dumps(
                    document,
                    indent=2,
                    ensure_ascii=False,
                    default=str,
                )
            else:
                content = self._html_report(document)

            path.write_text(content + "\n", encoding="utf-8")
            paths.append(path)

        return paths
