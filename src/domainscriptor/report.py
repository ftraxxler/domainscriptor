"""Report-Export: erzeugt aus den gesammelten Findings einen Bericht in
Markdown, HTML oder JSON.

Die Funktionen hier sind rein (nehmen strukturierte Findings entgegen und geben
einen String zurück), damit sie leicht testbar sind. Das Schreiben auf die Platte
übernimmt ``write_report``.
"""
from __future__ import annotations

import html
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

FORMATS = ("markdown", "html", "json")


def _group_by_host(findings: List[dict]) -> Dict[str, List[dict]]:
    grouped: Dict[str, List[dict]] = defaultdict(list)
    for f in findings:
        grouped[f.get("ip_hostname") or "(unknown)"].append(f)
    return dict(sorted(grouped.items()))


def _stats(findings: List[dict]) -> dict:
    hosts = {f.get("ip_hostname") for f in findings if f.get("ip_hostname")}
    tools = defaultdict(int)
    protocols = defaultdict(int)
    for f in findings:
        tools[f.get("toolname") or "?"] += 1
        protocols[f.get("protocol") or "?"] += 1
    return {
        "total_findings": len(findings),
        "hosts": len(hosts),
        "by_tool": dict(sorted(tools.items())),
        "by_protocol": dict(sorted(protocols.items())),
    }


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _sorted_structured_findings(structured: Optional[dict]) -> List[dict]:
    items = (structured or {}).get("findings") or []
    return sorted(items, key=lambda f: _SEV_RANK.get(str(f.get("severity", "")).lower(), 0),
                  reverse=True)


def build_json(findings: List[dict], ai_analysis: Optional[str] = None,
               structured: Optional[dict] = None) -> str:
    payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "stats": _stats(findings),
        "findings": findings,
    }
    if structured:
        payload["structured"] = {
            "hosts": structured.get("hosts", []),
            "findings": _sorted_structured_findings(structured),
            "credentials": structured.get("credentials", []),
        }
    if ai_analysis:
        payload["ai_analysis"] = ai_analysis
    return json.dumps(payload, indent=2, ensure_ascii=False)


def build_markdown(findings: List[dict], ai_analysis: Optional[str] = None,
                   structured: Optional[dict] = None) -> str:
    stats = _stats(findings)
    lines: List[str] = []
    lines.append("# Domainscriptor Report")
    lines.append("")
    lines.append(f"*Generiert: {datetime.now().isoformat(timespec='seconds')}*")
    lines.append("")

    lines.append("## Zusammenfassung")
    lines.append("")
    lines.append(f"- **Findings gesamt:** {stats['total_findings']}")
    lines.append(f"- **Hosts:** {stats['hosts']}")
    if stats["by_tool"]:
        tool_str = ", ".join(f"{k} ({v})" for k, v in stats["by_tool"].items())
        lines.append(f"- **Tools:** {tool_str}")
    if stats["by_protocol"]:
        proto_str = ", ".join(f"{k} ({v})" for k, v in stats["by_protocol"].items())
        lines.append(f"- **Protokolle:** {proto_str}")
    lines.append("")

    struct_findings = _sorted_structured_findings(structured)
    if struct_findings:
        lines.append("## Priorisierte Findings")
        lines.append("")
        lines.append("| Severity | Kategorie | Host | Tool | Titel |")
        lines.append("|----------|-----------|------|------|-------|")
        for f in struct_findings:
            title = str(f.get("title", "")).replace("|", "\\|")
            lines.append(
                f"| {str(f.get('severity', '')).upper()} | {f.get('category', '')} "
                f"| {f.get('host', '')} | {f.get('tool', '')} "
                f"| {title} |"
            )
        lines.append("")

    creds = (structured or {}).get("credentials") or []
    if creds:
        lines.append("## Credentials")
        lines.append("")
        lines.append("| Domain | User | Typ | Secret | Quelle |")
        lines.append("|--------|------|-----|--------|--------|")
        for c in creds:
            lines.append(
                f"| {c.get('domain', '')} | {c.get('username', '')} "
                f"| {c.get('secret_type', '')} | {c.get('secret_value', '')} "
                f"| {c.get('source_tool', '')} |"
            )
        lines.append("")

    if ai_analysis:
        lines.append("## KI-Analyse")
        lines.append("")
        lines.append(ai_analysis.strip())
        lines.append("")

    lines.append("## Findings nach Host")
    lines.append("")
    for host, host_findings in _group_by_host(findings).items():
        lines.append(f"### {host}")
        lines.append("")
        for f in host_findings:
            lines.append(
                f"#### {f.get('toolname', '?')} — {f.get('protocol', '?')}  "
                f"<sub>{f.get('timestamp', '')}</sub>"
            )
            lines.append("")
            data = f.get("data") or []
            if not data:
                lines.append("_(keine Daten)_")
                lines.append("")
                continue
            for item in data:
                if isinstance(item, dict):
                    parts = [f"**{k}**: {v}" for k, v in item.items()
                             if v is not None and str(v).strip()]
                    lines.append("- " + "  ·  ".join(parts) if parts else "- _(leer)_")
                else:
                    lines.append(f"- {item}")
            lines.append("")

    return "\n".join(lines)


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="de" data-bs-theme="dark"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Domainscriptor Report</title>
<style>
  body {{ background:#0d1117; color:#c9d1d9; font-family:system-ui,sans-serif;
          font-size:14px; margin:0; padding:2rem; max-width:1000px; margin:0 auto; }}
  h1 {{ color:#e6edf3; border-bottom:1px solid #30363d; padding-bottom:.4rem; }}
  h2 {{ color:#e6edf3; margin-top:2rem; border-bottom:1px solid #21262d; padding-bottom:.3rem; }}
  h3 {{ color:#79c0ff; margin-top:1.5rem; }}
  h4 {{ color:#d2a8ff; margin:.8rem 0 .3rem; font-size:.95rem; }}
  .meta {{ color:#8b949e; font-size:.8rem; }}
  .card {{ background:#161b22; border:1px solid #30363d; border-radius:.5rem;
           padding:1rem 1.25rem; margin-bottom:1rem; }}
  .kv {{ margin:.15rem 0; }}
  .k {{ color:#8b949e; }}
  .v {{ color:#7ee787; font-family:monospace; }}
  .pill {{ display:inline-block; background:#1f6feb33; color:#58a6ff;
           border-radius:1rem; padding:.1rem .6rem; font-size:.75rem; margin-right:.3rem; }}
  pre {{ white-space:pre-wrap; }}
  table.tbl {{ width:100%; border-collapse:collapse; margin:.5rem 0 1.5rem; font-size:.82rem; }}
  table.tbl th {{ text-align:left; color:#8b949e; border-bottom:1px solid #30363d;
                  padding:.35rem .5rem; text-transform:uppercase; font-size:.7rem; }}
  table.tbl td {{ padding:.35rem .5rem; border-bottom:1px solid #21262d; vertical-align:top; }}
  .sev {{ font-weight:600; font-size:.72rem; }}
  .sev-critical {{ color:#ff7b72; }} .sev-high {{ color:#ffa657; }}
  .sev-medium {{ color:#e3b341; }} .sev-low {{ color:#58a6ff; }} .sev-info {{ color:#8b949e; }}
</style></head><body>
<h1>⌬ Domainscriptor Report</h1>
<p class="meta">Generiert: {generated}</p>
<div class="card">
  <span class="pill">{total} Findings</span>
  <span class="pill">{hosts} Hosts</span>
  {tool_pills}
</div>
{struct_section}
{ai_section}
{host_sections}
</body></html>"""


def build_html(findings: List[dict], ai_analysis: Optional[str] = None,
               structured: Optional[dict] = None) -> str:
    stats = _stats(findings)
    esc = html.escape

    tool_pills = "".join(
        f'<span class="pill">{esc(k)}: {v}</span>' for k, v in stats["by_tool"].items()
    )

    struct_section = ""
    struct_findings = _sorted_structured_findings(structured)
    if struct_findings:
        rows = "".join(
            f"<tr><td><span class='sev sev-{esc(str(f.get('severity','')).lower())}'>"
            f"{esc(str(f.get('severity','')).upper())}</span></td>"
            f"<td>{esc(str(f.get('category','')))}</td><td>{esc(str(f.get('host','')))}</td>"
            f"<td>{esc(str(f.get('tool','')))}</td><td>{esc(str(f.get('title','')))}</td></tr>"
            for f in struct_findings
        )
        struct_section += (
            "<h2>Priorisierte Findings</h2><table class='tbl'><thead><tr>"
            "<th>Severity</th><th>Kategorie</th><th>Host</th><th>Tool</th><th>Titel</th>"
            f"</tr></thead><tbody>{rows}</tbody></table>"
        )
    creds = (structured or {}).get("credentials") or []
    if creds:
        rows = "".join(
            f"<tr><td>{esc(str(c.get('domain','')))}</td><td>{esc(str(c.get('username','')))}</td>"
            f"<td>{esc(str(c.get('secret_type','')))}</td>"
            f"<td class='v'>{esc(str(c.get('secret_value','')))}</td>"
            f"<td>{esc(str(c.get('source_tool','')))}</td></tr>"
            for c in creds
        )
        struct_section += (
            "<h2>Credentials</h2><table class='tbl'><thead><tr>"
            "<th>Domain</th><th>User</th><th>Typ</th><th>Secret</th><th>Quelle</th>"
            f"</tr></thead><tbody>{rows}</tbody></table>"
        )

    ai_section = ""
    if ai_analysis:
        ai_section = (
            '<h2>KI-Analyse</h2><div class="card"><pre>'
            + esc(ai_analysis.strip()) + "</pre></div>"
        )

    host_sections: List[str] = ["<h2>Findings nach Host</h2>"]
    for host, host_findings in _group_by_host(findings).items():
        host_sections.append(f"<h3>{esc(host)}</h3>")
        for f in host_findings:
            host_sections.append('<div class="card">')
            host_sections.append(
                f"<h4>{esc(str(f.get('toolname', '?')))} — "
                f"{esc(str(f.get('protocol', '?')))} "
                f"<span class='meta'>{esc(str(f.get('timestamp', '')))}</span></h4>"
            )
            data = f.get("data") or []
            if not data:
                host_sections.append('<p class="meta">(keine Daten)</p>')
            for item in data:
                if isinstance(item, dict):
                    for k, v in item.items():
                        if v is None or not str(v).strip():
                            continue
                        host_sections.append(
                            f'<div class="kv"><span class="k">{esc(str(k))}:</span> '
                            f'<span class="v">{esc(str(v))}</span></div>'
                        )
                else:
                    host_sections.append(f'<div class="kv v">{esc(str(item))}</div>')
            host_sections.append("</div>")

    return _HTML_TEMPLATE.format(
        generated=esc(datetime.now().isoformat(timespec="seconds")),
        total=stats["total_findings"],
        hosts=stats["hosts"],
        tool_pills=tool_pills,
        struct_section=struct_section,
        ai_section=ai_section,
        host_sections="\n".join(host_sections),
    )


_BUILDERS = {
    "markdown": build_markdown,
    "html": build_html,
    "json": build_json,
}
_EXTENSIONS = {"markdown": "md", "html": "html", "json": "json"}


def render(fmt: str, findings: List[dict], ai_analysis: Optional[str] = None,
           structured: Optional[dict] = None) -> str:
    fmt = (fmt or "markdown").lower()
    if fmt not in _BUILDERS:
        raise ValueError(f"Unbekanntes Format '{fmt}'. Erlaubt: {', '.join(FORMATS)}")
    return _BUILDERS[fmt](findings, ai_analysis, structured)


def default_filename(fmt: str) -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"domainscriptor_report_{ts}.{_EXTENSIONS[fmt.lower()]}"


def write_report(
    fmt: str,
    findings: List[dict],
    out_dir: Path,
    output: Optional[str] = None,
    ai_analysis: Optional[str] = None,
    structured: Optional[dict] = None,
) -> Path:
    content = render(fmt, findings, ai_analysis, structured)
    out_dir = Path(out_dir)
    if output:
        path = Path(output)
        if not path.is_absolute():
            path = out_dir / path
    else:
        path = out_dir / default_filename(fmt)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path
