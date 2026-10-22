import json
import logging
import math
import threading
from urllib.parse import urlencode

from flask import Flask, request, render_template_string
from markupsafe import Markup, escape

from domainscriptor.data.db_reader import DBReader


_PER_PAGE = 30

_PROTOCOL_COLORS = {
    "SMB":        "danger",
    "LDAP":       "primary",
    "TCP":        "success",
    "UDP":        "warning",
    "NTLMV2":     "danger",
    "LLMNR":      "info",
    "MDNS":       "info",
    "NB-NTS":     "info",
    "SRV":        "secondary",
    # Shortcut/tool protocols — each gets its own badge so they stand out as a
    # distinct "tool" in the UI (like SMB-DIFF already did).
    "SMB-SHARES": "info",
    "SMB-DIFF":   "warning",
    "SMB-LOOT":   "danger",
}

_TEMPLATE = """
<!DOCTYPE html>
<html lang="de" data-bs-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DomainScriptor</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body { background: #0d1117; font-size: .9rem; }
    .navbar  { background: #161b22 !important; border-bottom: 1px solid #30363d; }
    .brand   { font-family: monospace; font-size: 1.1rem; letter-spacing: 1px; color: #e6edf3; }
    .filter-bar { background: #161b22; border: 1px solid #30363d; border-radius: .5rem; padding: .75rem 1rem; }
    .table   { --bs-table-bg: transparent; --bs-table-color: #c9d1d9; }
    .table thead th { color: #8b949e; font-size: .75rem; text-transform: uppercase;
                      letter-spacing: .05em; border-color: #30363d; }
    .table td { border-color: #21262d; vertical-align: middle; }
    .table tbody tr:hover { background: #1c2128 !important; }
    code { color: #79c0ff; background: transparent; }
    .data-preview { color: #8b949e; max-width: 380px; overflow: hidden;
                    text-overflow: ellipsis; white-space: nowrap; font-size: .8rem; }
    .data-full { font-size: .75rem; background: #0d1117; border: 1px solid #30363d;
                 border-radius: .375rem; padding: .6rem; max-height: 200px;
                 overflow-y: auto; white-space: pre-wrap; color: #7ee787; }
    .toggle-link { font-size: .75rem; color: #58a6ff !important; text-decoration: none; }
    .toggle-link:hover { text-decoration: underline !important; }
    .badge { font-size: .7rem; }
    .form-control, .form-select {
      background: #0d1117; color: #e6edf3; border-color: #30363d; font-size: .85rem; }
    .form-control:focus, .form-select:focus {
      background: #0d1117; color: #e6edf3; border-color: #58a6ff;
      box-shadow: 0 0 0 .2rem rgba(88,166,255,.15); }
    .form-control::placeholder { color: #484f58; }
    .page-link { background: #161b22; border-color: #30363d; color: #8b949e; }
    .page-link:hover { background: #1c2128; color: #e6edf3; }
    .page-item.active .page-link { background: #1f6feb; border-color: #1f6feb; color: #fff; }
    .page-item.disabled .page-link { background: #161b22; color: #484f58; }
    .stat-pill { background: #161b22; border: 1px solid #30363d; border-radius: 2rem;
                 padding: .2rem .75rem; font-size: .78rem; color: #8b949e; }
    /* Readable rendering of a row's data entries */
    .dtable { width: 100%; font-size: .78rem; border-collapse: collapse; margin-top: .25rem; }
    .dtable th { color: #8b949e; text-transform: uppercase; font-size: .68rem;
                 letter-spacing: .04em; text-align: left; padding: .2rem .5rem;
                 border-bottom: 1px solid #30363d; font-weight: 600; }
    .dtable td { color: #c9d1d9; padding: .2rem .5rem; border-bottom: 1px solid #21262d;
                 vertical-align: top; }
    .dtable td.mono, .dtable code { font-family: monospace; color: #79c0ff; }
    .tag { display: inline-block; padding: .05rem .4rem; border-radius: .3rem;
           font-size: .68rem; font-weight: 600; }
    .tag-ok   { background: rgba(63,185,80,.18);  color: #3fb950; }
    .tag-deny { background: rgba(248,81,73,.18);   color: #f85149; }
    .tag-adm  { background: rgba(210,153,34,.18);  color: #d29922; }
    .tag-hit  { background: rgba(248,81,73,.22);   color: #ff7b72; }
    .tag-dim  { background: #21262d; color: #8b949e; }
    .snip { font-family: monospace; color: #ffa657; font-size: .72rem; word-break: break-all; }
  </style>
</head>
<body>

<nav class="navbar navbar-dark mb-3">
  <div class="container-fluid">
    <span class="brand">⌬ DomainScriptor</span>
    <span class="stat-pill">{{ total }} Einträge</span>
  </div>
</nav>

<div class="container-fluid px-4">

  <form method="get" class="filter-bar mb-3">
    <div class="row g-2 align-items-center">
      <div class="col-md-3">
        <input type="text" name="ip" class="form-control form-control-sm"
               placeholder="IP / Hostname" value="{{ filters.ip }}">
      </div>
      <div class="col-md-2">
        <select name="protocol" class="form-select form-select-sm">
          <option value="">Alle Protokolle</option>
          {% for p in protocols %}
          <option value="{{ p }}" {% if filters.protocol == p %}selected{% endif %}>{{ p }}</option>
          {% endfor %}
        </select>
      </div>
      <div class="col-md-2">
        <select name="tool" class="form-select form-select-sm">
          <option value="">Alle Tools</option>
          {% for t in tools %}
          <option value="{{ t }}" {% if filters.tool == t %}selected{% endif %}>{{ t }}</option>
          {% endfor %}
        </select>
      </div>
      <div class="col">
        <input type="text" name="search" class="form-control form-control-sm"
               placeholder="Suche in Daten …" value="{{ filters.search }}">
      </div>
      <div class="col-auto d-flex gap-2">
        <button type="submit" class="btn btn-sm btn-primary">Suchen</button>
        {% if filters.ip or filters.protocol or filters.tool or filters.search %}
        <a href="/" class="btn btn-sm btn-outline-secondary">Zurücksetzen</a>
        {% endif %}
      </div>
    </div>
  </form>

  <div class="table-responsive">
    <table class="table table-sm table-hover mb-2">
      <thead>
        <tr>
          <th style="width:50px">#</th>
          <th style="width:130px">Zeitstempel</th>
          <th>IP / Host</th>
          <th style="width:110px">Protokoll</th>
          <th style="width:110px">Tool</th>
          <th>Daten</th>
        </tr>
      </thead>
      <tbody>
        {% for row in rows %}
        <tr>
          <td class="text-secondary">{{ row.id }}</td>
          <td class="text-secondary" style="font-family:monospace;font-size:.78rem">
            {{ row.timestamp[:16] }}
          </td>
          <td><code>{{ row.ip_hostname }}</code></td>
          <td>
            <span class="badge bg-{{ row.protocol | protocol_color }}">{{ row.protocol }}</span>
          </td>
          <td><span style="color:#d2a8ff;font-size:.82rem">{{ row.toolname }}</span></td>
          <td>
            <div class="data-preview">{{ row.data_preview }}</div>
            {% if row.data_entries > 0 %}
            <a class="toggle-link" data-bs-toggle="collapse" href="#d{{ row.id }}">
              {{ row.data_entries }} {{ "Eintrag" if row.data_entries == 1 else "Einträge" }} anzeigen
            </a>
            <div class="collapse mt-1" id="d{{ row.id }}">
              {{ row.data_html }}
              <a class="toggle-link d-inline-block mt-1" data-bs-toggle="collapse" href="#j{{ row.id }}">
                Rohdaten (JSON)
              </a>
              <div class="collapse" id="j{{ row.id }}">
                <div class="data-full">{{ row.data_full }}</div>
              </div>
            </div>
            {% endif %}
          </td>
        </tr>
        {% endfor %}
        {% if not rows %}
        <tr>
          <td colspan="6" class="text-center text-secondary py-5">Keine Einträge gefunden.</td>
        </tr>
        {% endif %}
      </tbody>
    </table>
  </div>

  {% if total_pages > 1 %}
  <nav class="d-flex justify-content-center mt-3">
    <ul class="pagination pagination-sm">
      <li class="page-item {% if page <= 1 %}disabled{% endif %}">
        <a class="page-link" href="?{{ qs }}&page={{ page - 1 }}">‹</a>
      </li>
      {% for p in page_range %}
        {% if p == -1 %}
        <li class="page-item disabled"><span class="page-link">…</span></li>
        {% else %}
        <li class="page-item {% if p == page %}active{% endif %}">
          <a class="page-link" href="?{{ qs }}&page={{ p }}">{{ p }}</a>
        </li>
        {% endif %}
      {% endfor %}
      <li class="page-item {% if page >= total_pages %}disabled{% endif %}">
        <a class="page-link" href="?{{ qs }}&page={{ page + 1 }}">›</a>
      </li>
    </ul>
  </nav>
  {% endif %}

</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""


def _page_range(current: int, total: int) -> list[int]:
    if total <= 9:
        return list(range(1, total + 1))
    pages: list[int] = []
    for p in range(1, total + 1):
        if p == 1 or p == total or abs(p - current) <= 2:
            if pages and p - pages[-1] > 1:
                pages.append(-1)
            pages.append(p)
    return pages


def _data_preview(data: list, max_len: int = 90) -> str:
    if not data:
        return ""
    try:
        first = data[0]
        parts = [str(v) for v in first.values()
                 if v is not None and str(v).strip() and not isinstance(v, (dict, list))]
        preview = "  ·  ".join(parts)
        return (preview[:max_len] + "…") if len(preview) > max_len else preview
    except Exception:
        return ""


def _esc(v) -> str:
    return str(escape("" if v is None else str(v)))


def _render_shares(data: list) -> str:
    rows = []
    for s in data:
        admin = str(s.get("name", "")).endswith("$")
        tag = " <span class='tag tag-adm'>admin</span>" if admin else ""
        rows.append(
            f"<tr><td class='mono'>{_esc(s.get('name'))}{tag}</td>"
            f"<td>{_esc(s.get('share_type'))}</td>"
            f"<td>{_esc(s.get('comment'))}</td></tr>")
    return ("<table class='dtable'><thead><tr><th>Share</th><th>Type</th>"
            f"<th>Comment</th></tr></thead><tbody>{''.join(rows)}</tbody></table>")


def _render_loot(data: list) -> str:
    rows = []
    for f in data:
        matches = f.get("matches") or []
        if matches:
            pats = ", ".join(sorted({m.get("pattern", "") for m in matches}))
            mcell = (f"<span class='tag tag-hit'>{len(matches)} hit(s)</span> "
                     f"<span class='snip'>{_esc(pats)}</span>")
        else:
            mcell = "<span class='tag tag-dim'>—</span>"
        rows.append(
            f"<tr><td>{_esc(f.get('share'))}</td>"
            f"<td class='mono'>{_esc(f.get('remote_path'))}</td>"
            f"<td>{_esc(f.get('size'))}</td><td>{mcell}</td></tr>")
    return ("<table class='dtable'><thead><tr><th>Share</th><th>File</th>"
            f"<th>Size</th><th>Credentials</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>")


def _render_diff(data: list) -> str:
    users = [d.get("user", "") for d in data]
    all_shares = sorted({sh for d in data for sh in (d.get("shares") or {})})
    head = "".join(f"<th>{_esc(u)}</th>" for u in users)
    body = []
    for sh in all_shares:
        cells = [f"<td class='mono'>{_esc(sh)}</td>"]
        for d in data:
            info = (d.get("shares") or {}).get(sh)
            if not info:
                cells.append("<td><span class='tag tag-dim'>—</span></td>")
            elif info.get("access") == "OK":
                n = len(info.get("files") or [])
                cells.append(f"<td><span class='tag tag-ok'>OK ({n})</span></td>")
            else:
                cells.append(f"<td><span class='tag tag-deny'>{_esc(info.get('access'))}</span></td>")
        body.append("<tr>" + "".join(cells) + "</tr>")
    return (f"<table class='dtable'><thead><tr><th>Share</th>{head}</tr></thead>"
            f"<tbody>{''.join(body)}</tbody></table>")


def _render_generic(data: list):
    """Flat list-of-dicts → a compact table; returns None if the shape doesn't fit."""
    if not isinstance(data, list) or not data or not isinstance(data[0], dict):
        return None
    keys: list = []
    for d in data:
        if not isinstance(d, dict):
            return None
        for k in d.keys():
            if k not in keys:
                keys.append(k)
    keys = keys[:8]
    head = "".join(f"<th>{_esc(k)}</th>" for k in keys)
    rows = []
    for d in data[:200]:
        cells = []
        for k in keys:
            v = d.get(k)
            if isinstance(v, (dict, list)):
                v = json.dumps(v, ensure_ascii=False)
            cells.append(f"<td>{_esc(v)}</td>")
        rows.append("<tr>" + "".join(cells) + "</tr>")
    return (f"<table class='dtable'><thead><tr>{head}</tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>")


def _render_data(protocol: str, data: list) -> Markup:
    """Readable HTML for a row's data; template keeps a JSON fallback regardless."""
    try:
        if not data:
            return Markup("")
        proto = (protocol or "").upper()
        if proto == "SMB-SHARES":
            return Markup(_render_shares(data))
        if proto == "SMB-LOOT":
            return Markup(_render_loot(data))
        if proto == "SMB-DIFF":
            return Markup(_render_diff(data))
        generic = _render_generic(data)
        if generic:
            return Markup(generic)
    except Exception:
        pass
    return Markup("")


def create_app(db_reader: DBReader) -> Flask:
    app = Flask(__name__)

    @app.template_filter("protocol_color")
    def protocol_color(proto: str) -> str:
        return _PROTOCOL_COLORS.get(proto.upper(), "secondary")

    @app.route("/")
    def index():
        ip       = request.args.get("ip", "").strip()
        protocol = request.args.get("protocol", "").strip()
        tool     = request.args.get("tool", "").strip()
        search   = request.args.get("search", "").strip()
        page     = max(1, int(request.args.get("page", 1) or 1))

        protocols = db_reader.get_distinct_protocols()
        tools     = db_reader.get_distinct_tools()

        total, entries = db_reader.fetch_filtered_raw(
            ip=ip, protocol=protocol, tool=tool, search=search,
            page=page, per_page=_PER_PAGE,
        )

        total_pages = max(1, math.ceil(total / _PER_PAGE))
        page = min(page, total_pages)

        rows = []
        for e in entries:
            rows.append({
                "id":           e["id"],
                "protocol":     e["protocol"],
                "ip_hostname":  e["ip_hostname"],
                "toolname":     e["toolname"],
                "timestamp":    e["timestamp"],
                "data_preview": _data_preview(e["data"]),
                "data_entries": len(e["data"]),
                "data_html":    _render_data(e["protocol"], e["data"]),
                "data_full":    json.dumps(e["data"], indent=2, ensure_ascii=False),
            })

        qs_filters = {k: v for k, v in
                      {"ip": ip, "protocol": protocol, "tool": tool, "search": search}.items() if v}
        qs = urlencode(qs_filters)

        return render_template_string(
            _TEMPLATE,
            rows=rows,
            protocols=protocols,
            tools=tools,
            filters={"ip": ip, "protocol": protocol, "tool": tool, "search": search},
            total=total,
            page=page,
            total_pages=total_pages,
            page_range=_page_range(page, total_pages),
            qs=qs,
        )

    return app


def start_in_thread(db_reader: DBReader, host: str = "127.0.0.1", port: int = 5000) -> None:
    app = create_app(db_reader)

    # Silence the Flask/Werkzeug development server: no startup banner, no
    # "development server" warning, no per-request access logs. The caller
    # prints a single "Web UI: <url>" line instead.
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    try:
        import flask.cli
        flask.cli.show_server_banner = lambda *args, **kwargs: None
    except Exception:
        pass

    thread = threading.Thread(
        target=lambda: app.run(host=host, port=port, debug=False, use_reloader=False),
        name="domainscriptor-webui",
        daemon=True,
    )
    thread.start()
