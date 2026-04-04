import json
import re
import sqlite3
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
        # read-only Verbindung
        self.conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)

    def fetch_all(self) -> List[CanonicalDataModel]:
        cursor = self.conn.cursor()
        cursor.execute("""
                       SELECT *
                       FROM canonical_data
                       """)
        rows = cursor.fetchall()
        return _normalizer_canonical_result(rows)

    def get_by_protocol(self, protocol: str):
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM canonical_data WHERE protocol = ?",
            (protocol,)
        )
        rows = cursor.fetchall()
        return _normalizer_canonical_result(rows)

    def get_by_ip(self, ip: str):
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM canonical_data WHERE ip_hostname = ?",
            (ip,)
        )
        rows = cursor.fetchall()
        return _normalizer_canonical_result(rows)

    def get_by_tool(self, tool: str):
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM canonical_data WHERE toolname = ?",
            (tool,)
        )
        rows = cursor.fetchall()
        return _normalizer_canonical_result(rows)

    def _normalize_for_fts(self, search_string) -> str:
        cleaned = re.sub(r"[^A-Za-z0-9]+", " ", search_string)
        cleaned = re.sub(r"\s+", " ", cleaned).strip()
        return cleaned

    def search_in_data(self, fts_query: str, limit: int = 200) -> str:
        """
        fts_query Beispiele:
          - exe
          - "Windows 10"
          - SMBv1
          - win*
        """
        cur = self.conn.cursor()
        fts_query = self._normalize_for_fts(fts_query) + "*"
        cur.execute("""
                    SELECT c.id, c.protocol, c.ip_hostname, c.toolname, c.timestamp, c.data
                    FROM canonical_data_fts f
                             JOIN canonical_data c ON c.id = f.rowid
                    WHERE canonical_data_fts MATCH ? LIMIT ?
                    """, (fts_query, limit))

        rows = cur.fetchall()
        return _normalizer_canonical_result(rows)

    def fetch_settings(self):
        cur = self.conn.execute("""
                                SELECT *
                                FROM pentest_config
                                ORDER BY domain, username
                                """)
        rows = cur.fetchall()
        return _normalizer_settings_result(rows)

    def get_settings_by_id(self, idx):
        cur = self.conn.execute("""
                                SELECT *
                                FROM pentest_config
                                WHERE id = ?
                                ORDER BY domain, username
                                """, (idx,))
        rows = cur.fetchall()
        return _normalizer_settings_result(rows)

    def close(self):
        self.conn.close()
