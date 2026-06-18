import re
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional, List
from collections import defaultdict

import typer

from ..abstract_adapter import Adapter, AdapterError
from ...data.canonical_db import CanonicalDataModel


_SRV_RE = re.compile(
    r"service\s*=\s*\d+\s+\d+\s+\d+\s+(?P<host>\S+?)\.?\s*$",
    re.IGNORECASE,
)

_ADDR_RE = re.compile(
    r"^(?P<host>\S+)\s+(?:internet address|AAAA address)\s*=\s*(?P<ip>\S+)",
    re.IGNORECASE,
)


@dataclass
class NslookupEntry:
    hostname: str
    ip: str
    record_type: str

    def to_dict(self):
        return asdict(self)


class NslookupAdapter(Adapter):
    name = "nslookup"
    executable = "nslookup"
    version_cmd = ["-version"]
    help_cmd = ["-version"]
    test_args = version_cmd
    help_List = {
        "domain": None,
        "record_type": None,
        "query": None,
    }

    _used_record_type = "SRV"

    def build_command(
        self,
        domain: Optional[str] = None,
        record_type: str = "SRV",
        query: Optional[str] = None,
        **kwargs,
    ) -> List[str]:
        if not domain and not query:
            raise AdapterError("'domain' oder 'query' ist erforderlich", tool=self.executable)

        self._used_record_type = record_type.upper()
        lookup_target = query or f"_ldap._tcp.dc._msdcs.{domain}"
        return [self.executable, f"-type={record_type}", lookup_target]

    def parse_output(self, stdout: str):
        entries: List[NslookupEntry] = []
        hostnames: List[str] = []
        ip_map: dict[str, str] = {}

        typer.echo(stdout)

        for line in stdout.splitlines():
            m = _SRV_RE.search(line)
            if m:
                host = m.group("host").rstrip(".")
                if host not in hostnames:
                    hostnames.append(host)

            m = _ADDR_RE.match(line.strip())
            if m:
                ip_map[m.group("host").rstrip(".")] = m.group("ip")

        for host in hostnames:
            ip = ip_map.get(host, "")
            entries.append(NslookupEntry(hostname=host, ip=ip, record_type=self._used_record_type))

        return self.normalizer(entries)

    def normalizer(self, entries: List[NslookupEntry]):
        canonical_data_list = []
        entries_by_host = defaultdict(list)

        for e in entries:
            key = e.ip or e.hostname
            entries_by_host[key].append(e.to_dict())

        for key, data in entries_by_host.items():
            canonical_data_list.append(
                CanonicalDataModel(
                    self._used_record_type,
                    key,
                    self.name,
                    datetime.now().isoformat(),
                    data,
                )
            )
        return canonical_data_list
