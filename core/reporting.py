# reporting.py
import json
import datetime
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

def write_html_report(findings, path):
    """
    Generál egy HTML riportot a XSS találatokból.
    """
    from html import escape

    # HTML fejlécek és stílus
    html_content = [
        "<!DOCTYPE html>",
        "<html lang=\"hu\">",
        "<head>",
        "    <meta charset=\"UTF-8\">",
        "    <title>XSS Report</title>",
        "    <style>",
        "        body { background-color: #1e1e2f; color: #f0f0f0; font-family: 'Segoe UI', sans-serif; }",
        "        .container { max-width: 1000px; margin: auto; padding: 2rem; }",
        "        h1 { color: #00d4ff; }",
        "        h2 { margin-top: 2rem; color: #5fdde5; }",
        "        table { width: 100%; border-collapse: collapse; margin-bottom: 3rem; }",
        "        th, td { padding: 0.5rem; border: 1px solid #444; vertical-align: top; white-space: nowrap; }",
        "        td:first-child { white-space: normal; word-break: break-all; }",
        "        th { background-color: #292940; color: #fff; }",
        "        tr:nth-child(even) { background-color: #2a2a3d; }",
        "        .actions { white-space: nowrap; }",
        "        .actions button, .actions a { display: inline-block; margin-right: 4px; vertical-align: middle; background: none; border: none; color: #00d4ff; font-size: 1rem; cursor: pointer; }",
        "        .actions button:hover { color: #00ffff; }",
        "        .payload { color: #d14c4c; font-weight: bold; font-family: monospace; }",
        "    </style>",
        "    <script>",
        "        function copyToClipboard(text) { navigator.clipboard.writeText(text).then(() => { alert('Copied: ' + text); }); }",
        "        function hideRow(button) { button.closest('tr').style.display = 'none'; }",
        "        function toggleSeen(button) { button.innerText = button.innerText === '☑️' ? '✅' : '☑️'; }",
        "    </script>",
        "</head>",
        "<body>",
        "    <div class=\"container\">",  
        "        <h1>XSS Findings</h1>"
    ]

    # Csoportosítás domain szerint
    domain_map = {}
    for finding in findings:
        domain = finding.get('domain', '')
        domain_map.setdefault(domain, []).append(finding)

    # Minden domain riportolása
    for domain, vulns in domain_map.items():
        html_content.append(f"        <h2>{escape(domain)}</h2>")
        html_content.append("        <table>")
        html_content.append("            <thead><tr><th>URL</th><th>Payload</th><th>Actions</th></tr></thead>")
        html_content.append("            <tbody>")
        for vuln in vulns:
            url = escape(vuln['vulnerable_url'])
            payload = escape(vuln['payload'])
            html_content.append(
                "                <tr>"
                f"<td>{url}</td>"
                f"<td class=\"payload\">{payload}</td>"
                "<td class=\"actions\">"
                f"<a href=\"{url}\" target=\"_blank\" title=\"Open\">🌐</a>"
                f"<button onclick=\"copyToClipboard('{url}')\" title=\"Copy URL\">📋</button>"
                f"<button onclick=\"copyToClipboard('{payload}')\" title=\"Copy Payload\">📋</button>"
                f"<button onclick=\"hideRow(this)\" title=\"Hide Row\">🗑️</button>"
                f"<button onclick=\"toggleSeen(this)\" title=\"Mark as seen\">☑️</button>"
                "</td></tr>"
            )
        html_content.append("            </tbody>")
        html_content.append("        </table>")

    # Footer és záró tag
    html_content.extend([
        "    </div>",
        "</body>",
        "</html>"
    ])

    report_file = Path(path)
    report_file.parent.mkdir(parents=True, exist_ok=True)
    report_file.write_text('\n'.join(html_content), encoding='utf-8')
    logger.info(f"[+] HTML report saved: {path}")


def save_reports(findings, out_file, html_report=None):
    """
    Mentés JSON-be és opcionálisan HTML-be.
    """
    # JSON mentés
    out_dir = Path('output')
    out_dir.mkdir(exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d")
    base_json = Path(out_file)
    if base_json.name == 'hu_report.json':
        json_path = out_dir / f"{timestamp}_report.json"
        counter = 1
        while json_path.exists():
            json_path = out_dir / f"{timestamp}_report_{counter}.json"
            counter += 1
    else:
        json_path = base_json
    with json_path.open('w', encoding='utf-8') as f:
        json.dump(findings, f, indent=4)
    logger.info(f"[+] Report saved: {json_path}")

    # HTML mentés, ha kell
    if html_report:
        if html_report == 'auto':
            html_path = out_dir / f"{timestamp}_report.html"
            counter = 1
            while html_path.exists():
                html_path = out_dir / f"{timestamp}_report_{counter}.html"
                counter += 1
        else:
            html_path = Path(html_report)
        write_html_report(findings, html_path)