"""
Report Generator Module for NightWatch.

Generates comprehensive security reports in multiple formats:
- JSON (machine-readable, for automation)
- HTML (interactive, for human review)
- Markdown (for GitHub/Notion integration)
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from jinja2 import Template

from ..utils.logging_utils import get_logger

log = get_logger("report_generator")


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NightWatch Security Report - {{ project_name }}</title>
    <style>
        :root {
            --bg: #0d1117;
            --surface: #161b22;
            --border: #30363d;
            --text: #e6edf3;
            --text-muted: #8b949e;
            --accent: #58a6ff;
            --critical: #f85149;
            --high: #ff7b72;
            --medium: #d29922;
            --low: #58a6ff;
            --info: #8b949e;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        header { border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }
        h1 { font-size: 1.8rem; color: var(--accent); margin-bottom: 0.5rem; }
        .meta { color: var(--text-muted); font-size: 0.9rem; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .card { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 1.25rem; }
        .card-label { font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); margin-bottom: 0.5rem; }
        .card-value { font-size: 2rem; font-weight: 600; }
        .severity-critical { color: var(--critical); }
        .severity-high { color: var(--high); }
        .severity-medium { color: var(--medium); }
        .severity-low { color: var(--low); }
        .severity-info { color: var(--info); }
        h2 { font-size: 1.3rem; margin-bottom: 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
        section { margin-bottom: 2rem; }
        table { width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 6px; overflow: hidden; }
        th { background: var(--bg); text-align: left; padding: 0.75rem 1rem; font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); border-bottom: 1px solid var(--border); }
        td { padding: 0.75rem 1rem; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: rgba(255,255,255,0.02); }
        .badge { display: inline-block; padding: 0.2rem 0.5rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
        .badge-critical { background: rgba(248,81,73,0.15); color: var(--critical); }
        .badge-high { background: rgba(255,123,114,0.15); color: var(--high); }
        .badge-medium { background: rgba(210,153,34,0.15); color: var(--medium); }
        .badge-low { background: rgba(88,166,255,0.15); color: var(--low); }
        .badge-info { background: rgba(139,148,158,0.15); color: var(--info); }
        .tag { display: inline-block; background: rgba(88,166,255,0.1); color: var(--accent); padding: 0.1rem 0.4rem; border-radius: 4px; font-size: 0.75rem; margin-right: 0.25rem; }
        .code { font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; background: var(--surface); padding: 0.1rem 0.3rem; border-radius: 3px; font-size: 0.85em; }
        .footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--text-muted); font-size: 0.85rem; text-align: center; }
        .toc { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 1rem; margin-bottom: 2rem; }
        .toc ul { list-style: none; display: flex; flex-wrap: wrap; gap: 0.5rem; }
        .toc a { color: var(--accent); text-decoration: none; }
        .toc a:hover { text-decoration: underline; }
    </style>
</head>
<body>
<div class="container">
    <header>
        <h1>NightWatch Security Report</h1>
        <p class="meta">
            Project: <strong>{{ project_name }}</strong> &bull;
            Target: <code>{{ target_domain }}</code> &bull;
            Generated: {{ generated_at }} &bull;
            NightWatch v{{ version }}
        </p>
    </header>

    <nav class="toc">
        <ul>
            <li><a href="#summary">Summary</a></li>
            <li><a href="#subdomains">Subdomains ({{ subdomains|length }})</a></li>
            <li><a href="#hosts">Host Scan Results ({{ hosts|length }})</a></li>
            <li><a href="#vulnerabilities">Vulnerabilities ({{ vulnerabilities|length }})</a></li>
            <li><a href="#changes">Change Log ({{ changes|length }})</a></li>
        </ul>
    </nav>

    <section id="summary">
        <h2>Scan Summary</h2>
        <div class="summary-grid">
            <div class="card">
                <div class="card-label">Subdomains</div>
                <div class="card-value">{{ subdomains|length }}</div>
            </div>
            <div class="card">
                <div class="card-label">Hosts Scanned</div>
                <div class="card-value">{{ hosts|length }}</div>
            </div>
            <div class="card">
                <div class="card-label">Vulnerabilities</div>
                <div class="card-value">{{ vulnerabilities|length }}</div>
            </div>
            <div class="card">
                <div class="card-label">Changes</div>
                <div class="card-value">{{ changes|length }}</div>
            </div>
        </div>
        {% if vulnerability_summary %}
        <div class="summary-grid" style="margin-top:1rem">
            {% if vulnerability_summary.critical > 0 %}
            <div class="card"><div class="card-label">Critical</div><div class="card-value severity-critical">{{ vulnerability_summary.critical }}</div></div>
            {% endif %}
            {% if vulnerability_summary.high > 0 %}
            <div class="card"><div class="card-label">High</div><div class="card-value severity-high">{{ vulnerability_summary.high }}</div></div>
            {% endif %}
            {% if vulnerability_summary.medium > 0 %}
            <div class="card"><div class="card-label">Medium</div><div class="card-value severity-medium">{{ vulnerability_summary.medium }}</div></div>
            {% endif %}
            {% if vulnerability_summary.low > 0 %}
            <div class="card"><div class="card-label">Low</div><div class="card-value severity-low">{{ vulnerability_summary.low }}</div></div>
            {% endif %}
        </div>
        {% endif %}
    </section>

    {% if subdomains %}
    <section id="subdomains">
        <h2>Discovered Subdomains</h2>
        <table>
            <thead><tr><th>Subdomain</th><th>IP Address</th><th>Source</th><th>Last Seen</th><th>Tags</th></tr></thead>
            <tbody>
            {% for sub in subdomains[:100] %}
            <tr>
                <td><code>{{ sub.domain }}</code></td>
                <td>{{ sub.ip_address or '—' }}</td>
                <td>{{ sub.source }}</td>
                <td>{{ sub.last_seen }}</td>
                <td>{% for tag in (sub.tags or []) %}<span class="tag">{{ tag }}</span>{% endfor %}</td>
            </tr>
            {% endfor %}
            </tbody>
        </table>
        {% if subdomains|length > 100 %}<p style="color:var(--text-muted);margin-top:0.5rem">Showing 100 of {{ subdomains|length }} subdomains</p>{% endif %}
    </section>
    {% endif %}

    {% if hosts %}
    <section id="hosts">
        <h2>Host Scan Results</h2>
        <table>
            <thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Status</th><th>Title/Server</th><th>Technologies</th></tr></thead>
            <tbody>
            {% for host in hosts[:100] %}
            <tr>
                <td><code>{{ host.host }}</code></td>
                <td>{{ host.port }}</td>
                <td>{{ host.service or '—' }}</td>
                <td>{{ host.status_code or '—' }}</td>
                <td>{{ host.title or host.server_header or '—' }}</td>
                <td>{% for tech in (host.technology or [])[:5] %}<span class="tag">{{ tech }}</span>{% endfor %}</td>
            </tr>
            {% endfor %}
            </tbody>
        </table>
        {% if hosts|length > 100 %}<p style="color:var(--text-muted);margin-top:0.5rem">Showing 100 of {{ hosts|length }} hosts</p>{% endif %}
    </section>
    {% endif %}

    {% if vulnerabilities %}
    <section id="vulnerabilities">
        <h2>Vulnerability Findings</h2>
        <table>
            <thead><tr><th>Severity</th><th>CVE / Title</th><th>CVSS</th><th>Host</th><th>Remediation</th></tr></thead>
            <tbody>
            {% for vuln in vulnerabilities %}
            <tr>
                <td><span class="badge badge-{{ vuln.severity }}">{{ vuln.severity }}</span></td>
                <td><strong>{{ vuln.cve_id or 'N/A' }}</strong><br><small>{{ vuln.title }}</small></td>
                <td>{{ vuln.cvss_score or '—' }}</td>
                <td>{{ vuln.host or '—' }}</td>
                <td><small>{{ vuln.remediation or '—' }}</small></td>
            </tr>
            {% endfor %}
            </tbody>
        </table>
    </section>
    {% endif %}

    {% if changes %}
    <section id="changes">
        <h2>Change Log</h2>
        <table>
            <thead><tr><th>Time</th><th>Type</th><th>Severity</th><th>Description</th></tr></thead>
            <tbody>
            {% for change in changes %}
            <tr>
                <td>{{ change.detected_at }}</td>
                <td><code>{{ change.change_type }}</code></td>
                <td><span class="badge badge-{{ change.severity }}">{{ change.severity }}</span></td>
                <td>{{ change.description }}</td>
            </tr>
            {% endfor %}
            </tbody>
        </table>
    </section>
    {% endif %}

    <div class="footer">
        <p>Generated by <strong>NightWatch</strong> — AI-Powered Attack Surface Monitoring Framework</p>
        <p>Report ID: {{ report_id }} &bull; Scan Duration: {{ scan_duration }}s</p>
    </div>
</div>
</body>
</html>"""


class ReportGenerator:
    """Generates security reconnaissance reports in multiple formats."""

    def __init__(self, config=None):
        self.config = config

    async def generate_report(
        self,
        project_data: Dict[str, Any],
        output_dir: str = None,
        formats: List[str] = None
    ) -> Dict[str, str]:
        """
        Generate reports for a project.

        Args:
            project_data: Dict containing project, subdomains, hosts, vulnerabilities, changes
            output_dir: Directory to save reports
            formats: List of formats to generate ['json', 'html', 'markdown']

        Returns:
            Dict mapping format name to output file path
        """
        formats = formats or ["json", "html", "markdown"]
        output_dir = Path(output_dir or self.config.output_dir if self.config else "reports")
        output_dir.mkdir(parents=True, exist_ok=True)

        project_name = project_data.get("project", {}).get("name", "unknown")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_id = f"nw_{project_name}_{timestamp}"

        outputs = {}

        if "json" in formats:
            json_path = output_dir / f"{report_id}.json"
            await self._generate_json(project_data, json_path)
            outputs["json"] = str(json_path)

        if "html" in formats:
            html_path = output_dir / f"{report_id}.html"
            await self._generate_html(project_data, html_path)
            outputs["html"] = str(html_path)

        if "markdown" in formats:
            md_path = output_dir / f"{report_id}.md"
            await self._generate_markdown(project_data, md_path)
            outputs["markdown"] = str(md_path)

        log.info(f"Generated reports: {outputs}")
        return outputs

    async def _generate_json(self, data: Dict[str, Any], path: Path):
        """Generate JSON report."""
        # Serialize datetime objects
        serializable = self._make_serializable(data)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(serializable, f, indent=2, default=str)

    async def _generate_html(self, data: Dict[str, Any], path: Path):
        """Generate HTML report."""
        template = Template(HTML_TEMPLATE)
        html = template.render(
            project_name=data.get("project", {}).get("name", "Unknown"),
            target_domain=data.get("project", {}).get("target_domain", "Unknown"),
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            version="1.0.0",
            report_id=path.stem,
            subdomains=data.get("subdomains", []),
            hosts=data.get("hosts", []),
            vulnerabilities=data.get("vulnerabilities", []),
            changes=data.get("changes", []),
            vulnerability_summary=self._summarize_vulnerabilities(data.get("vulnerabilities", [])),
            scan_duration=data.get("scan_duration", 0),
        )
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    async def _generate_markdown(self, data: Dict[str, Any], path: Path):
        """Generate Markdown report."""
        project = data.get("project", {})
        summary = data.get("summary", {})
        subdomains = data.get("subdomains", [])
        hosts = data.get("hosts", [])
        vulns = data.get("vulnerabilities", [])
        changes = data.get("changes", [])

        lines = [
            f"# NightWatch Security Report",
            "",
            f"**Project:** {project.get('name', 'Unknown')}  ",
            f"**Target:** `{project.get('target_domain', 'Unknown')}`  ",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
            f"**Version:** NightWatch v1.0.0",
            "",
            "---",
            "",
            "## Summary",
            "",
            f"| Metric | Count |",
            f"|--------|-------|",
            f"| Subdomains | {len(subdomains)} |",
            f"| Hosts | {len(hosts)} |",
            f"| Vulnerabilities | {len(vulns)} |",
            f"| Changes | {len(changes)} |",
            "",
        ]

        if vulns:
            vuln_summary = self._summarize_vulnerabilities(vulns)
            if vuln_summary.get("critical"):
                lines.append(f"- :red_circle: **Critical:** {vuln_summary['critical']}")
            if vuln_summary.get("high"):
                lines.append(f"- :orange_circle: **High:** {vuln_summary['high']}")
            if vuln_summary.get("medium"):
                lines.append(f"- :yellow_circle: **Medium:** {vuln_summary['medium']}")
            if vuln_summary.get("low"):
                lines.append(f"- :large_blue_circle: **Low:** {vuln_summary['low']}")
            lines.append("")

        if subdomains:
            lines.extend([
                "## Discovered Subdomains",
                "",
                "| Subdomain | IP | Source |",
                "|-----------|-----|--------|",
            ])
            for sub in subdomains[:50]:
                lines.append(f"| `{sub.get('domain', '')}` | {sub.get('ip_address', '—')} | {sub.get('source', '')} |")
            if len(subdomains) > 50:
                lines.append(f"\n_Showing 50 of {len(subdomains)} subdomains_")
            lines.append("")

        if vulns:
            lines.extend([
                "## Vulnerabilities",
                "",
                "| Severity | CVE | Title | Remediation |",
                "|----------|-----|-------|-------------|",
            ])
            for v in vulns:
                lines.append(f"| {v.get('severity', '').upper()} | {v.get('cve_id', 'N/A')} | {v.get('title', '')[:60]} | {str(v.get('remediation', ''))[:50]} |")
            lines.append("")

        if changes:
            lines.extend([
                "## Change Log",
                "",
                "| Time | Type | Description |",
                "|------|------|-------------|",
            ])
            for c in changes[-20:]:
                lines.append(f"| {c.get('detected_at', '')} | `{c.get('change_type', '')}` | {c.get('description', '')[:60]} |")
            lines.append("")

        lines.extend([
            "---",
            "",
            f"*Generated by [NightWatch](https://github.com/BiswasM21/NightWatch) — {datetime.now().strftime('%Y-%m-%d')}*",
        ])

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def _summarize_vulnerabilities(self, vulns: List[Dict]) -> Dict[str, int]:
        """Summarize vulnerabilities by severity."""
        summary = {}
        for v in vulns:
            sev = v.get("severity", "info")
            summary[sev] = summary.get(sev, 0) + 1
        return summary

    def _make_serializable(self, obj):
        """Convert objects to JSON-serializable format."""
        if isinstance(obj, dict):
            return {k: self._make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._make_serializable(i) for i in obj]
        elif hasattr(obj, "__dict__"):
            return self._make_serializable(vars(obj))
        elif isinstance(obj, datetime):
            return obj.isoformat()
        else:
            return obj
