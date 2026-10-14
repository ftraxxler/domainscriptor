from datetime import datetime
import sqlite3
import json
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class CanonicalDataModel:
    protocol: str
    ip_hostname: str
    toolname: str
    timestamp: str
    data: List[Dict]


@dataclass
class SettingsDataModel:
    domain: str
    username: str
    password: str
    is_default: bool = False


class CanonicalDB:
    def __init__(self, db_path):
        self.conn = sqlite3.connect(db_path)

    def insert(self, canonical_objects):
        if not isinstance(canonical_objects, list):
            canonical_objects = [canonical_objects]

        with self.conn:
            for canonical_object in canonical_objects:
                self._insert_one(canonical_object)

    def _insert_one(self, canonical_object: CanonicalDataModel):
        cursor = self.conn.cursor()
        cursor.execute("""
                       INSERT INTO canonical_data
                           (protocol, ip_hostname, toolname, timestamp, data)
                       VALUES (?, ?, ?, ?, ?)
                       """, (
                           canonical_object.protocol,
                           canonical_object.ip_hostname,
                           canonical_object.toolname,
                           canonical_object.timestamp,
                           json.dumps(canonical_object.data)
                       ))
        self.conn.commit()

    def close(self):
        self.conn.close()

    def _create_table(self):
        cursor = self.conn.cursor()
        cursor.execute("""
                       CREATE TABLE canonical_data
                       (
                           id          INTEGER PRIMARY KEY AUTOINCREMENT,
                           protocol    TEXT,
                           ip_hostname TEXT,
                           toolname    TEXT,
                           timestamp   TEXT,
                           data        TEXT
                       )
                       """)
        # 2) FTS5 nur auf data (contentless index wäre möglich, aber so ist es am simpelsten)
        # content='canonical_data' + content_rowid='id' => "external content" mode

        cursor.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS canonical_data_fts
        USING fts5(
            data,
            content='canonical_data',
            content_rowid='id'
        );
        """)

        # 3) Trigger zum Sync
        cursor.execute("""
                       CREATE TRIGGER IF NOT EXISTS canonical_data_ai
        AFTER INSERT ON canonical_data
                       BEGIN
                       INSERT INTO canonical_data_fts(rowid, data)
                       VALUES (new.id, new.data);
                       END;
                       """)

        cursor.execute("""
                       CREATE TRIGGER IF NOT EXISTS canonical_data_ad
        AFTER
                       DELETE
                       ON canonical_data
                       BEGIN
                       INSERT INTO canonical_data_fts(canonical_data_fts, rowid, data)
                       VALUES ('delete', old.id, old.data);
                       END;
                       """)

        cursor.execute("""
                       CREATE TRIGGER IF NOT EXISTS canonical_data_au
        AFTER
                       UPDATE ON canonical_data
                       BEGIN
                       INSERT INTO canonical_data_fts(canonical_data_fts, rowid, data)
                       VALUES ('delete', old.id, old.data);
                       INSERT INTO canonical_data_fts(rowid, data)
                       VALUES (new.id, new.data);
                       END;
                       """)

        cursor.execute("""
                       CREATE TABLE pentest_config
                       (
                           id         INTEGER PRIMARY KEY AUTOINCREMENT,
                           domain     TEXT,
                           username   TEXT,
                           password   TEXT,
                           is_default INTEGER NOT NULL DEFAULT 0,
                           UNIQUE (domain, username)
                       )
                       """)
        self._create_structured_tables(cursor)
        self.conn.commit()

    def _create_structured_tables(self, cursor):
        """Normalisierte Entitäten (additiv zum rohen canonical_data-Log)."""
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hosts (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                identifier TEXT NOT NULL UNIQUE,
                ip         TEXT,
                hostname   TEXT,
                os         TEXT,
                domain     TEXT,
                first_seen TEXT,
                last_seen  TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id    INTEGER REFERENCES hosts(id),
                category   TEXT,
                title      TEXT,
                severity   TEXT,
                protocol   TEXT,
                tool       TEXT,
                evidence   TEXT,
                created_at TEXT,
                UNIQUE (host_id, tool, protocol, title)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id     INTEGER REFERENCES hosts(id),
                domain      TEXT,
                username    TEXT,
                secret_type TEXT,
                secret_value TEXT,
                source_tool TEXT,
                valid       INTEGER NOT NULL DEFAULT 1,
                created_at  TEXT,
                last_seen   TEXT,
                UNIQUE (domain, username, secret_type, secret_value)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_sev ON findings(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_cat ON findings(category)")

    def init_database(self):
        self._create_table()

    def migrate(self):
        cursor = self.conn.cursor()
        cursor.execute("PRAGMA table_info(pentest_config)")
        columns = {row[1] for row in cursor.fetchall()}
        if "is_default" not in columns:
            cursor.execute(
                "ALTER TABLE pentest_config ADD COLUMN is_default INTEGER NOT NULL DEFAULT 0"
            )
        # Strukturierte Tabellen für bestehende Datenbanken nachrüsten.
        self._create_structured_tables(cursor)
        self.conn.commit()

    # ── Strukturierte Entitäten ────────────────────────────────────────────

    def upsert_host(self, host) -> int:
        now = datetime.now().isoformat()
        with self.conn:
            self.conn.execute("""
                INSERT INTO hosts (identifier, ip, hostname, os, domain, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(identifier) DO UPDATE SET
                    ip        = COALESCE(excluded.ip, hosts.ip),
                    hostname  = COALESCE(excluded.hostname, hosts.hostname),
                    os        = COALESCE(excluded.os, hosts.os),
                    domain    = COALESCE(excluded.domain, hosts.domain),
                    last_seen = excluded.last_seen
            """, (host.identifier, host.ip, host.hostname, host.os, host.domain, now, now))
            row = self.conn.execute(
                "SELECT id FROM hosts WHERE identifier = ?", (host.identifier,)
            ).fetchone()
        return row[0]

    def insert_finding(self, finding, host_id: int):
        now = datetime.now().isoformat()
        with self.conn:
            self.conn.execute("""
                INSERT INTO findings
                    (host_id, category, title, severity, protocol, tool, evidence, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(host_id, tool, protocol, title) DO UPDATE SET
                    severity   = excluded.severity,
                    evidence   = excluded.evidence,
                    created_at = excluded.created_at
            """, (
                host_id, finding.category.value, finding.title, finding.severity.value,
                finding.protocol, finding.tool, json.dumps(finding.evidence), now,
            ))

    def insert_credential(self, cred, host_id: Optional[int]):
        now = datetime.now().isoformat()
        with self.conn:
            self.conn.execute("""
                INSERT INTO credentials
                    (host_id, domain, username, secret_type, secret_value, source_tool,
                     valid, created_at, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(domain, username, secret_type, secret_value) DO UPDATE SET
                    valid       = excluded.valid,
                    source_tool = excluded.source_tool,
                    last_seen   = excluded.last_seen
            """, (
                host_id, cred.domain, cred.username, cred.secret_type.value,
                cred.secret_value, cred.source_tool, 1 if cred.valid else 0, now, now,
            ))

    def insert_structured(self, host, findings, credentials):
        host_id = self.upsert_host(host)
        for f in findings:
            self.insert_finding(f, host_id)
        for c in credentials:
            self.insert_credential(c, host_id)

    def add_or_update_settings(self, settings: List[SettingsDataModel]):
        if settings:
            with self.conn:
                for setting in settings:
                    self._insert_settings(setting)

    def _insert_settings(self, settings: SettingsDataModel):
        self.conn.execute("""
                          INSERT INTO pentest_config (domain, username, password)
                          VALUES (?, ?, ?) ON CONFLICT(domain, username) DO
                          UPDATE SET
                              password = excluded.password
                          """, (settings.domain, settings.username, settings.password))
        self.conn.commit()

    def delete_setting(self, setting_id: str):
        self.conn.execute("""
                          DELETE
                          FROM pentest_config
                          WHERE id = ?
                          """, (setting_id,))
        self.conn.commit()

    def set_default_setting(self, setting_id: str):
        with self.conn:
            self.conn.execute("UPDATE pentest_config SET is_default = 0")
            self.conn.execute(
                "UPDATE pentest_config SET is_default = 1 WHERE id = ?", (setting_id,)
            )



