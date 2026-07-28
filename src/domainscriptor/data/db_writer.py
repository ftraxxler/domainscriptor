import threading
from dataclasses import dataclass
from queue import Queue, Empty
from typing import List, Union

import typer

from domainscriptor.data.canonical_db import CanonicalDB, CanonicalDataModel, SettingsDataModel


@dataclass
class InsertCanonical:
    obj: CanonicalDataModel


@dataclass
class UpsertSetting:
    obj: List[SettingsDataModel]


@dataclass
class DeleteSetting:
    setting_id: str


@dataclass
class SetDefaultSetting:
    setting_id: str


DBTasks = Union[InsertCanonical, UpsertSetting, DeleteSetting, SetDefaultSetting]


class DBWriter(threading.Thread):
    def __init__(self, db_path: str, q: Queue[DBTasks]):
        super().__init__(daemon=True)
        self.q = q
        self.db_path = db_path
        self.db = None
        self._stop_evt = threading.Event()

    def stop(self):
        self._stop_evt.set()

    def submit_canonical_data(self, data: CanonicalDataModel):
        insert_canonical = InsertCanonical(obj=data)
        self.q.put(insert_canonical)

    def submit_setting(self, setting: List[SettingsDataModel]):
        insert_setting = UpsertSetting(obj=setting)
        self.q.put(insert_setting)

    def delete_setting(self, setting_id):
        delete_setting = DeleteSetting(setting_id=setting_id)
        self.q.put(delete_setting)

    def set_default_setting(self, setting_id):
        set_default = SetDefaultSetting(setting_id=setting_id)
        self.q.put(set_default)

    def init_database(self, settings):
        db = CanonicalDB(self.db_path)
        db.init_database()
        db.add_or_update_settings(settings)
        db.close()

    def migrate_database(self):
        db = CanonicalDB(self.db_path)
        db.migrate()
        db.close()

    def run(self):
        self.db = CanonicalDB(self.db_path)
        try:
            while not self._stop_evt.is_set():
                try:
                    task = self.q.get(timeout=0.5)
                except Empty:
                    continue

                try:
                    if isinstance(task, InsertCanonical):
                        self.db.insert(task.obj)

                    elif isinstance(task, UpsertSetting):
                        self.db.add_or_update_settings(task.obj)

                    elif isinstance(task, DeleteSetting):
                        self.db.delete_setting(task.setting_id)

                    elif isinstance(task, SetDefaultSetting):
                        self.db.set_default_setting(task.setting_id)

                finally:
                    self.q.task_done()
        finally:
            self.db.close()
