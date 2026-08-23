"""Render PTAS JSON report data as a standalone, print-friendly HTML file."""

from __future__ import annotations

from collections import Counter
from html import escape
import re


class HtmlReportRenderer:
    """Encapsulate the HtmlReportRenderer service behavior.

    Keeping this integration separate prevents external-tool details from leaking into
    use cases.
    """
    CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
    SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

    @staticmethod
    def _text(value) -> str:
        """Perform the service-level operation needed to text.

        Inputs are converted to the external tool or renderer format and the normalized
        result is returned to the use case.
        """
        return escape(str(value)) if value not in (None, "") else "Not available"

    @classmethod
    def _cve_badges(cls, value) -> str:
        """Perform the service-level operation needed to cve badges.

        Inputs are converted to the external tool or renderer format and the normalized
        result is returned to the use case.
        """
        cves = sorted({item.upper() for item in cls.CVE_PATTERN.findall(str(value or ""))})
        if not cves:
            return '<span class="muted">No CVE reference</span>'
        return "".join(
            f'<a class="cve" href="https://nvd.nist.gov/vuln/detail/{escape(cve)}">{escape(cve)}</a>'
            for cve in cves
        )

    @classmethod
    def render(cls, report: dict) -> str:
        """Perform the service-level operation needed to render.

        Inputs are converted to the external tool or renderer format and the normalized
        result is returned to the use case.
        """
        metadata = report.get("report_metadata", {})
        findings = report.get("vulnerabilities", [])
        severity_counts = Counter(
            str(item.get("severity", "INFO")).upper() for item in findings
        )
        type_counts = Counter(str(item.get("type", "UNKNOWN")) for item in findings)
        targets = sorted({str(item.get("host")) for item in findings if item.get("host")})
        recommendations = sum(len(item.get("recommendations", [])) for item in findings)

        severity_cards = "".join(
            f'<div class="metric severity-{level.lower()}"><span>{level.title()}</span>'
            f'<strong>{severity_counts.get(level, 0)}</strong></div>'
            for level in cls.SEVERITIES
        )
        type_rows = "".join(
            f"<tr><td>{escape(name.replace('_', ' ').title())}</td><td>{count}</td></tr>"
            for name, count in sorted(type_counts.items())
        ) or '<tr><td colspan="2">No findings</td></tr>'

        finding_sections = []
        for index, finding in enumerate(findings, start=1):
            severity = str(finding.get("severity", "INFO")).upper()
            finding_type = str(finding.get("type", "UNKNOWN"))
            endpoint = str(finding.get("host", "Unknown target"))
            if finding.get("port") is not None:
                endpoint += f":{finding['port']}"
            rec_html = ""
            for rec_index, rec in enumerate(finding.get("recommendations", []), start=1):
                command = rec.get("execution_steps")
                rec_html += f"""
                <div class="recommendation">
                  <div class="recommendation-title">Recommendation {rec_index}: {cls._text(rec.get('attack_technique'))}</div>
                  <p>{cls._text(rec.get('exploitation_method'))}</p>
                  <div class="rec-meta">Risk: {cls._text(rec.get('risk_level'))} · Priority: {cls._text(rec.get('priority'))} · Status: {cls._text(rec.get('status'))}</div>
                  {f'<pre><code>{cls._text(command)}</code></pre>' if command else ''}
                </div>"""
            if not rec_html:
                rec_html = '<p class="muted">No stored validation recommendation for this finding.</p>'
            finding_sections.append(
                f"""
                <article class="finding">
                  <div class="finding-head">
                    <div><span class="finding-number">F-{index:03d}</span><h3>{cls._text(finding.get('description'))}</h3></div>
                    <span class="severity severity-{severity.lower()}">{escape(severity)}</span>
                  </div>
                  <div class="facts">
                    <div><span>Target</span><strong>{escape(endpoint)}</strong></div>
                    <div><span>Service</span><strong>{cls._text(finding.get('service'))}</strong></div>
                    <div><span>Type</span><strong>{escape(finding_type.replace('_', ' ').title())}</strong></div>
                    <div><span>Status</span><strong>{cls._text(finding.get('status'))}</strong></div>
                  </div>
                  <div class="detail-grid">
                    <section><h4>Detected version</h4><p>{cls._text(finding.get('version'))}</p></section>
                    <section><h4>CVE references</h4><div class="cves">{cls._cve_badges(finding.get('cves'))}</div></section>
                  </div>
                  <section><h4>Evidence and description</h4><pre class="evidence">{cls._text(finding.get('description'))}</pre></section>
                  <section><h4>Remediation / verification note</h4><p>{cls._text(finding.get('remediation'))}</p></section>
                  <section><h4>Recommendations</h4>{rec_html}</section>
                </article>"""
            )

        return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{cls._text(metadata.get('title', 'PTAS Security Assessment'))}</title>
<style>
:root{{--ink:#172033;--muted:#667085;--line:#e4e7ec;--paper:#fff;--bg:#f2f4f7;--brand:#155eef;--critical:#b42318;--high:#e04f16;--medium:#dc8a00;--low:#1570ef;--info:#475467}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--ink);font:14px/1.55 Inter,Segoe UI,Arial,sans-serif}}
.page{{width:min(1180px,calc(100% - 32px));margin:32px auto}} .hero{{background:linear-gradient(135deg,#101828,#173b75 62%,#155eef);color:#fff;border-radius:20px;padding:42px;box-shadow:0 18px 45px #10182822}}
.eyebrow{{font-size:12px;font-weight:800;letter-spacing:.16em;text-transform:uppercase;color:#b2ccff}} h1{{font-size:36px;line-height:1.15;margin:10px 0}} .hero p{{max-width:760px;color:#d1e0ff}}
.metadata{{display:flex;flex-wrap:wrap;gap:10px;margin-top:24px}} .metadata span{{background:#ffffff17;border:1px solid #ffffff2b;border-radius:999px;padding:7px 12px}}
.metrics{{display:grid;grid-template-columns:repeat(7,1fr);gap:12px;margin:20px 0}} .metric{{background:var(--paper);border:1px solid var(--line);border-top:4px solid var(--brand);border-radius:14px;padding:16px;box-shadow:0 5px 16px #1018280c}} .metric span{{display:block;color:var(--muted);font-size:12px;font-weight:700;text-transform:uppercase}} .metric strong{{font-size:28px}} .severity-critical{{--accent:var(--critical)}} .severity-high{{--accent:var(--high)}} .severity-medium{{--accent:var(--medium)}} .severity-low{{--accent:var(--low)}} .severity-info{{--accent:var(--info)}} .metric[class*=severity-]{{border-top-color:var(--accent)}}
.panel,.finding{{background:var(--paper);border:1px solid var(--line);border-radius:16px;padding:24px;margin:16px 0;box-shadow:0 5px 16px #1018280c}} h2{{font-size:22px;margin:0 0 16px}} h3{{display:inline;font-size:17px;margin-left:10px}} h4{{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:#344054;margin:18px 0 7px}}
.summary-grid{{display:grid;grid-template-columns:1fr 1fr;gap:24px}} table{{width:100%;border-collapse:collapse}} td{{padding:9px;border-bottom:1px solid var(--line)}} td:last-child{{text-align:right;font-weight:800}}
.finding-head{{display:flex;justify-content:space-between;gap:16px;align-items:flex-start}} .finding-number{{font:700 12px ui-monospace,monospace;color:var(--brand)}} .severity{{padding:5px 10px;border-radius:999px;color:#fff;background:var(--accent,var(--info));font-size:11px;font-weight:800}}
.facts{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:18px 0}} .facts div{{background:#f9fafb;border-radius:10px;padding:12px}} .facts span{{display:block;color:var(--muted);font-size:11px;text-transform:uppercase}} .facts strong{{word-break:break-word}}
.detail-grid{{display:grid;grid-template-columns:1fr 1fr;gap:20px}} .cve{{display:inline-block;margin:3px 5px 3px 0;padding:5px 9px;border-radius:7px;background:#eef4ff;color:#1849a9;text-decoration:none;font:700 12px ui-monospace,monospace}}
pre{{white-space:pre-wrap;word-break:break-word;background:#101828;color:#e4e7ec;border-radius:10px;padding:14px;max-height:380px;overflow:auto}} .evidence{{background:#f8fafc;color:#344054;border:1px solid var(--line)}} .recommendation{{border-left:4px solid var(--brand);background:#f8faff;padding:14px 16px;margin:10px 0;border-radius:0 10px 10px 0}} .recommendation-title{{font-weight:800}} .rec-meta,.muted{{color:var(--muted)}} footer{{padding:28px 0;color:var(--muted);text-align:center}}
@media(max-width:900px){{.metrics{{grid-template-columns:repeat(2,1fr)}}.facts{{grid-template-columns:repeat(2,1fr)}}.summary-grid,.detail-grid{{grid-template-columns:1fr}}}}
@media print{{body{{background:#fff}}.page{{width:100%;margin:0}}.hero,.panel,.finding{{box-shadow:none;break-inside:avoid}}.hero{{border-radius:0}}a{{color:inherit;text-decoration:none}}}}
</style>
</head>
<body><main class="page">
<header class="hero"><div class="eyebrow">PTAS · Security Assessment Report</div>
<h1>{cls._text(metadata.get('title', 'PTAS Security Assessment'))}</h1>
<p>{cls._text(metadata.get('description'))}</p>
<div class="metadata"><span>Scan #{cls._text(metadata.get('scan_id'))}</span><span>{cls._text(metadata.get('scan_type'))}</span><span>Status: {cls._text(metadata.get('scan_status'))}</span><span>Generated: {cls._text(metadata.get('generated_at'))}</span></div></header>
<section class="metrics"><div class="metric"><span>Findings</span><strong>{len(findings)}</strong></div><div class="metric"><span>Recommendations</span><strong>{recommendations}</strong></div>{severity_cards}</section>
<section class="panel"><h2>Executive summary</h2><div class="summary-grid"><div><p>This report contains evidence collected by PTAS from explicitly scoped assessment tools. Open services and database correlations are observations or candidates unless a finding explicitly states that an applicable check returned <strong>VULNERABLE</strong>.</p><p><strong>Targets:</strong> {escape(', '.join(targets) or 'No target recorded')}</p></div><div><table>{type_rows}</table></div></div></section>
<section><h2>Detailed findings</h2>{''.join(finding_sections) or '<div class="panel">No findings were recorded.</div>'}</section>
<footer>Generated by the AI-Powered Penetration Testing Assist System · Validate all findings before remediation or further testing.</footer>
</main></body></html>"""
