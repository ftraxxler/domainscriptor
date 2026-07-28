from datetime import datetime
import sqlite3
import json
from dataclasses import dataclass
from typing import Dict, List


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
        self.conn.commit()

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
            self.conn.commit()

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



