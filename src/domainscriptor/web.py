import json
import math
import threading
from urllib.parse import urlencode

from flask import Flask, request, render_template_string

from domainscriptor.data.db_reader import DBReader


_PER_PAGE = 30

_PROTOCOL_COLORS = {
    "SMB":    "danger",
    "LDAP":   "primary",
    "TCP":    "success",
    "UDP":    "warning",
    "NTLMV2": "danger",
    "LLMNR":  "info",
    "MDNS":   "info",
    "NB-NTS": "info",
    "SRV":    "secondary",
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
              <div class="data-full">{{ row.data_full }}</div>
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
        parts = [str(v) for v in first.values() if v is not None and str(v).strip()]
        preview = "  ·  ".join(parts)
        return (preview[:max_len] + "…") if len(preview) > max_len else preview
    except Exception:
        return ""


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
    thread = threading.Thread(
        target=lambda: app.run(host=host, port=port, debug=False, use_reloader=False),
        name="domainscriptor-webui",
        daemon=True,
    )
    thread.start()
