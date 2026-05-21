import re
import shlex

from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional, List

import typer

from ..abstract_adapter import Adapter, AdapterError
from ...data.canonical_db import CanonicalDataModel


NMAP_HOST_RE = re.compile(
    r"^Nmap scan report for (?P<host>.+)$"
)

NMAP_IP_IN_HOST_RE = re.compile(
    r"^(?P<hostname>.*?)\s+\((?P<ip>\d{1,3}(?:\.\d{1,3}){3})\)$"
)

NMAP_PORT_RE = re.compile(
    r"^(?P<port>\d+)\/(?P<protocol>\w+)\s+"
    r"(?P<state>\S+)\s+"
    r"(?P<service>\S+)"
    r"(?:\s+(?P<details>.*))?$"
)


@dataclass
class NmapEntry:
    ip: str
    hostname: str
    port: int
    protocol: str
    state: str
    service: str
    details: str

    def to_dict(self):
        return asdict(self)


def parse_nmap_host(line: str):
    """
    Beispiele:
      Nmap scan report for 10.0.0.5
      Nmap scan report for server.local (10.0.0.5)
    """

    m = NMAP_HOST_RE.match(line)
    if not m:
        return None, None

    host = m.group("host").strip()

    ip_match = NMAP_IP_IN_HOST_RE.match(host)
    if ip_match:
        hostname = ip_match.group("hostname").strip()
        ip = ip_match.group("ip").strip()
        return ip, hostname

    return host, ""


def parse_nmap_port_line(line: str) -> Optional[dict]:
    """
    Beispiel:
      22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu
      80/tcp open  http    Apache httpd 2.4.52
      445/tcp closed microsoft-ds
    """

    m = NMAP_PORT_RE.match(line)
    if not m:
        return None

    return {
        "port": int(m.group("port")),
        "protocol": m.group("protocol"),
        "state": m.group("state"),
        "service": m.group("service"),
        "details": (m.group("details") or "").strip(),
    }


class NmapAdapter(Adapter):
    """
    Adapter für Nmap.

    Typische Aufrufe:
      nmap 10.0.0.5
      nmap -sV 10.0.0.5
      nmap -sS -p 22,80,443 10.0.0.0/24
      nmap -A -T4 10.0.0.5
    """

    name = "nmap"
    executable = "nmap"

    help_List = {
        "target": None,
        "targets_file": None,
        "ports": None,
        "scan_type": None,
        "service_detection": None,
        "os_detection": None,
        "script_scan": None,
        "timing": None,
        "extra_args": None,
    }

    returnCode_version = 1
    used_protocol = "tcp"

    def build_command(
        self,
        target: Optional[str] = None,
        targets_file: Optional[str] = None,
        ports: Optional[str] = None,
        scan_type: Optional[str] = None,
        service_detection: bool = False,
        os_detection: bool = False,
        script_scan: bool = False,
        timing: Optional[str] = None,
        extra_args: Optional[List[str]] = None,
        **kwargs,
    ) -> List[str]:

        if not target and not targets_file:
            raise AdapterError(
                "Entweder 'target' oder 'targets_file' ist erforderlich.",
                tool=self.executable,
            )

        cmd: List[str] = [self.executable]

        # Scan-Typ, z. B. -sS, -sT, -sU
        if scan_type:
            cmd.append(scan_type)

            if scan_type == "-sU":
                self.used_protocol = "udp"
            else:
                self.used_protocol = "tcp"

        # Ports, z. B. 22,80,443 oder 1-1000
        if ports:
            cmd += ["-p", ports]

        # Service-Version-Erkennung
        if service_detection:
            cmd.append("-sV")

        # OS-Erkennung
        if os_detection:
            cmd.append("-O")

        # Default Scripts
        if script_scan:
            cmd.append("-sC")

        # Timing, z. B. T3, T4 oder -T4
        if timing:
            if not timing.startswith("-"):
                timing = f"-{timing}"
            cmd.append(timing)

        # Ziel
        if target:
            cmd.append(target)

        # Zielliste
        if targets_file:
            cmd += ["-iL", targets_file]

        # Zusätzliche Argumente
        if extra_args:
            if isinstance(extra_args, list):
                for arg in extra_args:
                    cmd.extend(shlex.split(arg))
            else:
                cmd.extend(shlex.split(extra_args))

        return cmd

    def parse_output(self, stdout: str):
        original_output = stdout
        entries = []

        typer.echo(original_output)

        current_ip = ""
        current_hostname = ""

        for line in stdout.splitlines():
            line = line.strip()

            if not line:
                continue

            parsed_ip, parsed_hostname = parse_nmap_host(line)
            if parsed_ip:
                current_ip = parsed_ip
                current_hostname = parsed_hostname
                continue

            port_data = parse_nmap_port_line(line)
            if port_data and current_ip:
                entry = NmapEntry(
                    ip=current_ip,
                    hostname=current_hostname,
                    port=port_data["port"],
                    protocol=port_data["protocol"],
                    state=port_data["state"],
                    service=port_data["service"],
                    details=port_data["details"],
                )

                entries.append(entry)

        return self.normalizer(entries)

    def normalizer(self, entries: List[NmapEntry]):
        canonical_data_list = []
        entries_by_ip = defaultdict(list)

        for entry in entries:
            entries_by_ip[entry.ip].append(entry.to_dict())

        entries_by_ip = dict(entries_by_ip)

        for ip, data in entries_by_ip.items():
            canonical_data_object = CanonicalDataModel(
                self.used_protocol,
                ip,
                self.name,
                datetime.now().isoformat(),
                data,
            )
            canonical_data_list.append(canonical_data_object)

        return canonical_data_list