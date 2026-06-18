import shlex
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
import re

import typer

from ..abstract_adapter import Adapter, AdapterError
from typing import Optional, List

from ...data.canonical_db import CanonicalDataModel, SettingsDataModel

_SMBCLIENT_LS_RE = re.compile(
    r"""
        ^\s*
        (?P<name>.+?)                 # Dateiname (non-greedy)
        \s{2,}                        # mind. 2 Spaces als Spaltentrenner
        (?P<type>[A-Z])               # A oder D (in der Praxis meist A/D)
        \s+
        (?P<size>\d+)
        \s+
        (?P<dow>[A-Za-z]{3})\s+
        (?P<mon>[A-Za-z]{3})\s+
        (?P<day>\d{1,2})\s+
        (?P<time>\d{2}:\d{2}:\d{2})\s+
        (?P<year>\d{4})
        \s*$
        """,
    re.VERBOSE,
)


@dataclass()
class SmbEntry:
    name: str
    extention: str
    raw_type: int
    size: str
    mtime: datetime
    is_dir: bool

    def __str__(self) -> str:
        kind = "DIR " if self.is_dir else "FILE"
        return f"{kind:4} {self.size:>8}  {self.mtime:%Y-%m-%d %H:%M:%S}  {self.name}"

    def __repr__(self) -> str:
        return (
            "SmbEntry("
            f"name={self.name!r}, "
            f"type={self.extention!r}, "
            f"size={self.size}, "
            f"mtime={self.mtime.isoformat()}, "
            f"is_dir={self.is_dir}"
            ")"
        )

    def to_dict(self):
        data = asdict(self)
        data["mtime"] = self.mtime.isoformat()
        return data


@dataclass()
class SmbShare:
    name: str
    extention: str
    raw_type: int
    size: str
    mtime: datetime
    is_dir: bool


class SmbclientParseError(Exception):
    pass


class SMBClientAdapter(Adapter):
    """
    Adapter für den Aufruf von `smbclient`.

    Beispiele:
        smbclient //10.0.0.20/SHARE -U "user%pass" -W WORKGROUP -c "ls"
    """

    name = "smbclient"
    executable = "smbclient"
    help_List = {
        "target": None,
        "username": None,
        "command": None,
        "password": None,
        "share": None,
        "domain": None,
        "recursive": None,
        "extra_args": None,
        "proxy": None
    }
    ip_hostname = ""

    def build_command(
            self,
            target: str,
            domain: Optional[str] = None,
            username: Optional[str] = None,
            command: str = "ls",
            password: Optional[str] = None,
            share: Optional[str] = None,
            recursive: Optional[bool] = None,
            extra_args: Optional[List[str]] = None,
            proxy: Optional[bool] = None,
            auth: Optional[SettingsDataModel] = None,
            **kwargs
    ) -> List[str]:
        """
        Erzeugt die smbclient Kommandozeile.

        - target: IP oder Hostname (z.B. "10.0.0.20" oder "host.local")
        - share: Name der Freigabe (z.B. "SHARE"). Wenn None -> "IPC$"
        - username/password: werden in -U "user%pass" zusammengeführt (oder nur user bei -U user)
        - domain: optional -W DOMAIN
        - command: optional -c "<command>" (z.B. "ls" oder "get foo")
        - extra_args: weitere Argumente (als Liste)
        """
        if not target:
            raise AdapterError("target erforderlich", tool=self.executable)

        if not username and not (auth and auth.username):
            raise AdapterError("username erforderlich", tool=self.executable)

        if proxy:
            if not domain and not (auth and auth.domain):
                raise AdapterError("Domain erforderlich für proxychain", tool=self.executable)

        share = share or "IPC$"
        uri = f"//{target}/{share}"

        cmd: List[str] = [self.executable, uri]

        if not username and auth and auth.username:
            username = auth.username

        if not password and auth and auth.password:
            password = auth.password

        if not domain and auth and auth.domain:
            domain = auth.domain
        if password is not None:
            user_spec = f"{username}%{password}"
        elif proxy:
            user_spec = f"{username}%Proxy"
        else:
            user_spec = username

        if domain:
            user_spec = f"{domain}\\"+user_spec

        cmd += ["-U", user_spec]


        if command and not recursive:
            cmd += ["-c", command]
        elif recursive:
            cmd += ["-c", "recurse;" + command]

        if extra_args:
            cmd.extend(shlex.split(extra_args) if isinstance(extra_args, str) else extra_args)

        if proxy:
            proxychain = ["proxychains", "-q"]
            cmd = proxychain + cmd

        self.ip_hostname = target
        return cmd

    @staticmethod
    def prettify(entries: List[SmbEntry]):
        output = ""
        header = f"{'NAME':40} {'TYPE':6} {'SIZE':>8} {'MODIFIED':20} {'KIND'}\n"
        output += header
        output += "-" * len(header) + "\n"
        for e in entries:
            kind = "DIR" if e.is_dir else "FILE"
            ftype = e.extention or "-"
            mtime = datetime.fromisoformat(str(e.mtime)).strftime("%Y-%m-%d %H:%M")

            output += f"{e.name:40} {ftype:6} {e.size:8} {mtime:20} {kind}\n"

        return output

    def normalizer(self, entries):
        protocol = "SMB"
        data = [e.to_dict() for e in entries]
        canonical_data_object = CanonicalDataModel(protocol, self.ip_hostname, self.name, datetime.now().isoformat(),
                                                   data)
        return canonical_data_object

    def parse_output(self, stdout: str):
        entries: List[SmbEntry] = []
        ignore_dots = True

        for line in stdout.splitlines():
            line = line.rstrip("\n")
            if not line.strip():
                continue

            m = _SMBCLIENT_LS_RE.match(line)
            if not m:
                continue

            name = m.group("name").strip()

            if ignore_dots and name in (".", ".."):
                continue

            raw_type = m.group("type")
            size = int(m.group("size"))

            ts_str = f"{m.group('dow')} {m.group('mon')} {m.group('day')} {m.group('time')} {m.group('year')}"
            mtime = datetime.strptime(ts_str, "%a %b %d %H:%M:%S %Y")

            is_dir = raw_type == "D"

            if not is_dir:
                suffix = Path(name).suffix
                extention = suffix[1:].lower() if suffix else None
            else:
                extention = None

            entries.append(
                SmbEntry(
                    name=name,
                    extention=extention,
                    raw_type=raw_type,
                    size=size,
                    mtime=mtime,
                    is_dir=is_dir,
                )
            )

        typer.echo(SMBClientAdapter.prettify(entries))
        return self.normalizer(entries)
