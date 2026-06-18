import re
import shlex
from collections import defaultdict
from datetime import datetime
from typing import Optional, List

import typer

from ..abstract_adapter import Adapter, AdapterError
from dataclasses import dataclass, asdict

from ...data.canonical_db import CanonicalDataModel, SettingsDataModel

NXC_LINE_RE = re.compile(
    r"^\s*(?P<protocol>\S+)\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<port>\d{1,5})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<message>.*\S)?\s*$"
)


@dataclass
class NxcEntry:
    protocol: str
    ip: str
    port: int
    hostname: str
    message: str

    def to_dict(self):
        data = asdict(self)
        return data


def parse_nxc_line(line: str) -> Optional[NxcEntry]:
    m = NXC_LINE_RE.match(line)
    if not m:
        return None
    return NxcEntry(
        protocol=m.group("protocol"),
        ip=m.group("ip"),
        port=int(m.group("port")),
        hostname=m.group("hostname"),
        message=(m.group("message") or "").strip(),
    )


class NXCAdapter(Adapter):
    """
    Adapter für NetExec (nxc).
    Typische Aufrufe:
      nxc smb 10.0.0.5 -u user -p pass --shares
      nxc smb 10.0.0.0/24 -u user -H <hash> -x "whoami"
    """

    name = "nxc"
    executable = "nxc"  # ggf. absoluter Pfad oder alias
    help_List = {
        "protocol": None,
        "target": None,
        "targets_file": None,
        "username": None,
        "password": None,
        "hashes": None,
        "local_auth": None,
        "port": None,
        "command": None,
        "module": None,
        "module_args": None,
        "extra_args": None,
        "proxy": None,
    }

    returnCode_version = 1
    used_protocol = ""

    def build_command(
            self,
            protocol: str = "smb",
            target: Optional[str] = None,
            targets_file: Optional[str] = None,
            domain: Optional[str] = None,
            username: Optional[str] = None,
            password: Optional[str] = None,
            hashes: Optional[str] = None,
            local_auth: bool = False,
            port: Optional[int] = None,
            command: Optional[str] = None,
            module: Optional[str] = None,
            module_args: Optional[str] = None,
            extra_args: Optional[List[str]] = None,
            auth: Optional[SettingsDataModel] = None,
            proxy: Optional[bool] = None,
            **kwargs,
    ) -> List[str]:
        if not target and not targets_file:
            raise AdapterError(
                "Entweder 'target' oder 'targets_file' ist erforderlich.",
                tool=self.executable,
            )

        if proxy:
            if not domain and not (auth and auth.domain):
                raise AdapterError("Domain erforderlich für proxychain", tool=self.executable)

        cmd: List[str] = [self.executable, protocol]

        # Ziel(e)
        if target:
            cmd.append(target)
        if targets_file:
            cmd += [targets_file]

        # Auth
        if domain:
            cmd += ["-d", domain]
        elif auth and auth.domain:
            cmd += ["-d", auth.domain]

        if username or username=="":
            cmd += ["-u", username]
        elif auth and auth.username:
            cmd += ["-u", auth.username]

        if proxy:
            cmd += ["-p", "Proxy"]
        elif password or password=="":
            cmd += ["-p", password]
        elif auth and auth.password:
            cmd += ["-p", auth.password]

        if hashes:
            cmd += ["--hashes", hashes]

        if local_auth:
            cmd.append("--local-auth")

        if port is not None:
            cmd += ["-p", str(port)]

        if command:
            cmd += ["-x", command]

        if module:
            cmd += ["-M", module]
            if module_args:
                cmd += ["-o", module_args]

        if extra_args:
            cmd.extend(shlex.split(extra_args))

        if proxy:
            proxychain = ["proxychains", "-q"]
            cmd = proxychain + cmd

        self.used_protocol = protocol
        return cmd

    def normalizer(self, entries):
        canonical_data_list = []
        entries_by_ip = defaultdict(list)

        for entry in entries:
            entries_by_ip[entry.ip].append(entry.to_dict())

        entries_by_ip = dict(entries_by_ip)

        for ip, data in entries_by_ip.items():
            canonical_data_object = CanonicalDataModel(self.used_protocol, ip, self.name, datetime.now().isoformat(),
                                                       data)
            canonical_data_list.append(canonical_data_object)
        return canonical_data_list

    def parse_output(self, stdout: str):
        original_output = stdout
        entries = []
        typer.echo(original_output)
        for line in stdout.splitlines():
            line = line.rstrip("\n")
            if not line.strip():
                continue
            nxcEntry = parse_nxc_line(line)
            if nxcEntry:
                entries.append(nxcEntry)

        return self.normalizer(entries)
