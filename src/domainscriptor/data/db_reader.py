import json
import re
import sqlite3
import threading
from typing import List, Tuple

import typer

from domainscriptor.data.canonical_db import CanonicalDataModel, SettingsDataModel


def _normalizer_settings_result(rows):
    result = []
    for row in rows:
        result.append((row[0], SettingsDataModel(
            domain=row[1],
            username=row[2],
            password=row[3],
            is_default=bool(row[4]) if len(row) > 4 else False,
        )))

    return result


def _pretty_format_canonical(entries: List[CanonicalDataModel]) -> str:
    lines = []

    for e in entries:
        lines.append("─" * 72)
        lines.append(f"Protocol : {e.protocol}")
        lines.append(f"IP/Host  : {e.ip_hostname}")
        lines.append(f"Tool     : {e.toolname}")
        lines.append(f"Time     : {e.timestamp}")
        lines.append("─" * 72)

        if not e.data:
            lines.append("  (no data)")
            lines.append("")
            continue

        for i, item in enumerate(e.data, 1):
            lines.append(f"  [{i}]")
            for k, v in item.items():
                lines.append(f"    {k:<10}: {v}")
            lines.append("")

    return "\n".join(lines)


def _normalizer_canonical_result(rows):
    result = []
    for row in rows:
        result.append(CanonicalDataModel(
            protocol=row[1],
            ip_hostname=row[2],
            toolname=row[3],
            timestamp=row[4],
            data=json.loads(row[5])
        ))
    return _pretty_format_canonical(result)


class DBReader:
    def __init__(self, db_path: str):
        self.conn = sqlite3.connect(
            f"file:{db_path}?mode=ro", uri=True, check_same_thread=False
        )
        self._lock = threading.RLock()

    def fetch_all(self) -> List[CanonicalDataModel]:
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM canonical_data")
            rows = cursor.fetchall()
        return _normalizer_canonical_result(rows)

    def get_by_protocol(self, protocol: str):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT * FROM canonical_data WHERE protocol = ?", (protocol,)
            )
            rows = cursor.fetchall()
        return _normalizer_canonical_result(rows)

    def get_by_ip(self, ip: str):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT * FROM canonical_data WHERE ip_hostname = ?", (ip,)
            )
            rows = cursor.fetchall()
        return _normalizer_canonical_result(rows)

    def get_by_tool(self, tool: str):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT * FROM canonical_data WHERE toolname = ?", (tool,)
            )
            rows = cursor.fetchall()
        return _normalizer_canonical_result(rows)

    def _normalize_for_fts(self, search_string) -> str:
        cleaned = re.sub(r"[^A-Za-z0-9]+", " ", search_string)
        cleaned = re.sub(r"\s+", " ", cleaned).strip()
        return cleaned

    def search_in_data(self, fts_query: str, limit: int = 200) -> str:
        fts_query = self._normalize_for_fts(fts_query) + "*"
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("""
                SELECT c.id, c.protocol, c.ip_hostname, c.toolname, c.timestamp, c.data
                FROM canonical_data_fts f
                         JOIN canonical_data c ON c.id = f.rowid
                WHERE canonical_data_fts MATCH ? LIMIT ?
                """, (fts_query, limit))
            rows = cur.fetchall()
        return _normalizer_canonical_result(rows)

    def fetch_settings(self):
        with self._lock:
            cur = self.conn.execute(
                "SELECT * FROM pentest_config ORDER BY domain, username"
            )
            rows = cur.fetchall()
        return _normalizer_settings_result(rows)

    def get_settings_by_id(self, idx):
        with self._lock:
            cur = self.conn.execute(
                "SELECT * FROM pentest_config WHERE id = ? ORDER BY domain, username",
                (idx,)
            )
            rows = cur.fetchall()
        return _normalizer_settings_result(rows)

    # ── Web UI ────────────────────────────────────────────────────────────────

    def fetch_filtered_raw(
        self,
        ip: str = "",
        protocol: str = "",
        tool: str = "",
        search: str = "",
        page: int = 1,
        per_page: int = 30,
    ) -> tuple[int, list[dict]]:
        conditions: list[str] = []
        params: list = []
        if ip:
            conditions.append("ip_hostname LIKE ?")
            params.append(f"%{ip}%")
        if protocol:
            conditions.append("protocol = ?")
            params.append(protocol)
        if tool:
            conditions.append("toolname = ?")
            params.append(tool)
        if search:
            conditions.append("data LIKE ?")
            params.append(f"%{search}%")

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        offset = (page - 1) * per_page

        with self._lock:
            total = self.conn.execute(
                f"SELECT COUNT(*) FROM canonical_data {where}", params
            ).fetchone()[0]
            rows = self.conn.execute(
                f"SELECT id, protocol, ip_hostname, toolname, timestamp, data "
                f"FROM canonical_data {where} ORDER BY id DESC LIMIT ? OFFSET ?",
                params + [per_page, offset],
            ).fetchall()

        entries = []
        for row in rows:
            try:
                data = json.loads(row[5])
            except Exception:
                data = []
            entries.append({
                "id":          row[0],
                "protocol":    row[1],
                "ip_hostname": row[2],
                "toolname":    row[3],
                "timestamp":   row[4],
                "data":        data,
            })
        return total, entries

    def fetch_all_raw(self) -> list[dict]:
        """Alle Findings als strukturierte Dicts (für Report-Export, AI, etc.)."""
        with self._lock:
            rows = self.conn.execute(
                "SELECT id, protocol, ip_hostname, toolname, timestamp, data "
                "FROM canonical_data ORDER BY id ASC"
            ).fetchall()

        entries = []
        for row in rows:
            try:
                data = json.loads(row[5])
            except Exception:
                data = []
            entries.append({
                "id": row[0],
                "protocol": row[1],
                "ip_hostname": row[2],
                "toolname": row[3],
                "timestamp": row[4],
                "data": data,
            })
        return entries

    # ── Strukturierte Entitäten ────────────────────────────────────────────

    _SEV_ORDER = (
        "CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
        "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END"
    )

    def get_hosts(self) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT identifier, ip, hostname, os, domain, first_seen, last_seen "
                "FROM hosts ORDER BY identifier"
            ).fetchall()
        cols = ["identifier", "ip", "hostname", "os", "domain", "first_seen", "last_seen"]
        return [dict(zip(cols, r)) for r in rows]

    def get_findings(self, severity: str = "", category: str = "",
                     host: str = "") -> list[dict]:
        conditions, params = [], []
        if severity:
            conditions.append("severity = ?")
            params.append(severity.lower())
        if category:
            conditions.append("category = ?")
            params.append(category.upper())
        if host:
            conditions.append("h.identifier LIKE ?")
            params.append(f"%{host}%")
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        with self._lock:
            rows = self.conn.execute(
                f"SELECT f.category, f.title, f.severity, f.protocol, f.tool, "
                f"h.identifier, f.created_at, f.evidence "
                f"FROM findings f LEFT JOIN hosts h ON h.id = f.host_id "
                f"{where} ORDER BY {self._SEV_ORDER} DESC, f.id DESC",
                params,
            ).fetchall()
        cols = ["category", "title", "severity", "protocol", "tool",
                "host", "created_at", "evidence"]
        out = []
        for r in rows:
            d = dict(zip(cols, r))
            try:
                d["evidence"] = json.loads(d["evidence"]) if d["evidence"] else {}
            except Exception:
                d["evidence"] = {}
            out.append(d)
        return out

    def get_credentials(self) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT c.domain, c.username, c.secret_type, c.secret_value, "
                "c.source_tool, c.valid, h.identifier, c.created_at "
                "FROM credentials c LEFT JOIN hosts h ON h.id = c.host_id "
                "ORDER BY c.domain, c.username"
            ).fetchall()
        cols = ["domain", "username", "secret_type", "secret_value",
                "source_tool", "valid", "host", "created_at"]
        return [dict(zip(cols, r)) for r in rows]

    def get_distinct_protocols(self) -> list[str]:
        with self._lock:
            return [r[0] for r in self.conn.execute(
                "SELECT DISTINCT protocol FROM canonical_data ORDER BY protocol"
            ).fetchall()]

    def get_distinct_tools(self) -> list[str]:
        with self._lock:
            return [r[0] for r in self.conn.execute(
                "SELECT DISTINCT toolname FROM canonical_data ORDER BY toolname"
            ).fetchall()]

    def close(self):
        self.conn.close()
