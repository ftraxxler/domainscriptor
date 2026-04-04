from dataclasses import dataclass, asdict
from datetime import datetime
import threading
import time
import requests
from typing import List, Dict

import typer

from domainscriptor.data.canonical_db import CanonicalDataModel
from domainscriptor.data.db_writer import InsertCanonical

API_PATH = "http://127.0.0.1:9090/ntlmrelayx/api/v1.0/relays"
LINE_START = typer.style("[NTLMRelay] ", fg=typer.colors.GREEN, bold=True)


@dataclass
class NtlmEntry:
    protocol: str
    ip: str
    user: str
    admin_status: str

    def to_dict(self):
        data = asdict(self)
        return data


class NTLMRelayWatcher():
    def __init__(self, queue, api_url: str = API_PATH, poll_interval: float = 10.0):
        self.api_url = api_url
        self.poll_interval = poll_interval
        self.latest_entries = []
        self.queue = queue
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def follow(self):
        # Delay Start
        time.sleep(10)
        while not self._stop_event.is_set():
            self.check_for_new_entries()
            time.sleep(self.poll_interval)

    def check_for_new_entries(self):
        try:
            response = requests.get(self.api_url)
            response.raise_for_status()  # Falls der Statuscode nicht 200 ist, wird eine Exception geworfen
            data = response.json()  # Antwort als JSON parsen
            self.process_entries(data)
        except requests.RequestException as e:
            typer.echo(LINE_START + f"Fehler bei API-Abfrage: {e}")

    def process_entries(self, new_entries: List[List[str]]):
        for entry in new_entries:
            protocol = entry[0]
            ip = entry[1]
            user = entry[2]
            admin_status = entry[3]

            if not any(
                    existing_entry.ip == ip and existing_entry.user == user
                    for existing_entry in self.latest_entries
            ):
                ntlm_entry = NtlmEntry(protocol, ip, user, admin_status)
                self.latest_entries.append(ntlm_entry)
                typer.echo(LINE_START + f"Neuer Eintrag gefunden: {ip} - {user} (Admin: {admin_status})")

                data = CanonicalDataModel(protocol, ip, "ntlmrelayx", datetime.now().isoformat(),
                                          [ntlm_entry.to_dict()])
                self.queue.put(InsertCanonical(obj=data))

    def get_latest_entries(self) -> List[Dict[str, str]]:
        return self.latest_entries
