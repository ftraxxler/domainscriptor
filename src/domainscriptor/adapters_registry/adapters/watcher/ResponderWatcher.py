import os
import re
import time
import hashlib
import threading
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional, Literal, List

import typer

from domainscriptor.data.canonical_db import CanonicalDB, CanonicalDataModel
from domainscriptor.data.db_writer import InsertCanonical

Proto = Literal["LLMNR", "MDNS", "NTLMV2"]

RE_POISON = re.compile(
    r"\[\*\]\s*\[(?P<proto>LLMNR|MDNS|NB-NTS)\]\s*Poisoned answer sent to\s+"
    r"(?P<ip>\S+)\s+for name\s+(?P<name>\S+)",
    re.IGNORECASE,
)

RE_CLIENT = re.compile(
    r"\[\s*SMB\s*\]\s*NTLMv2-SSP\s*Client\s*:\s*(?P<ip>\S+)",
    re.IGNORECASE,
)

RE_USER = re.compile(
    r"\[\s*SMB\s*\]\s*NTLMv2-SSP\s*Username\s*:\s*(?P<user>.+)$",
    re.IGNORECASE,
)

RE_HASH = re.compile(
    r"\[\s*SMB\s*\]\s*NTLMv2-SSP\s*Hash\s*:\s*(?P<hash>.+)$",
    re.IGNORECASE,
)

DEFAULT_PATH = "/usr/share/responder/logs/Responder-Session.log"

LINE_START = typer.style("[Responder] ", fg=typer.colors.GREEN, bold=True)


@dataclass
class Event:
    ts: datetime
    kind: Proto
    ip: str
    name: Optional[str] = None
    username: Optional[str] = None
    hash_fingerprint: Optional[str] = None

    def to_dict(self):
        data = asdict(self)
        data["ts"] = data["ts"].isoformat()
        return data


class ResponderLogWatcher:
    def __init__(self, queue, path: str = DEFAULT_PATH):
        self.path = path
        self.events: List[Event] = []
        self.queue = queue
        self._pending_client_ip: Optional[str] = None
        self._pending_user: Optional[str] = None

        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def _fp(self, s: str) -> str:
        return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()

    def write(self, ev: Event):
        if ev.kind in ("LLMNR", "MDNS", "NB-NTS"):
            typer.echo(LINE_START + f"Proto: {ev.kind} Name: {ev.name} IP: {ev.ip}")
        elif ev.kind == "NTLMV2":
            typer.echo(LINE_START + f"NTLMV2 Client: {ev.ip} User: {ev.username}")

        data = CanonicalDataModel(ev.kind, ev.ip, "responder", datetime.now().isoformat(), [ev.to_dict()])
        self.queue.put(InsertCanonical(obj=data))

    def process_line(self, line: str) -> Optional[Event]:
        line = line.rstrip("\n")

        m = RE_POISON.search(line)
        if m:
            ev = Event(
                ts=datetime.now(),
                kind=m.group("proto").upper(),
                ip=m.group("ip"),
                name=m.group("name"),
            )
            self.write(ev)

        m = RE_CLIENT.search(line)
        if m:
            self._pending_client_ip = m.group("ip")
            self._pending_user = None
            return None

        m = RE_USER.search(line)
        if m:
            self._pending_user = m.group("user").strip()
            return None

        m = RE_HASH.search(line)
        if m and self._pending_client_ip:
            raw_hash = m.group("hash").strip()

            ev = Event(
                ts=datetime.now(),
                kind="NTLMV2",
                ip=self._pending_client_ip,
                username=self._pending_user,  # kann None sein ✅
                hash_fingerprint=self._fp(raw_hash),  # kein Klartext ✅
            )

            # block reset
            self._pending_client_ip = None
            self._pending_user = None

            self.write(ev)

    def follow(self, poll_interval: float = 0.25, start_at_end: bool = True):
        # Delay Start
        time.sleep(10)
        with open(self.path, "r", encoding="utf-8", errors="ignore") as f:
            if start_at_end:
                f.seek(0, os.SEEK_END)

            while not self._stop_event.is_set():
                pos = f.tell()
                line = f.readline()
                if not line:
                    f.seek(pos)
                    time.sleep(poll_interval)
                    continue
                self.process_line(line)
