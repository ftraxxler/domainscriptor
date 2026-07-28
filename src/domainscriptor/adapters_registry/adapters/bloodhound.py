import json
import shlex
from datetime import datetime
from pathlib import Path
from typing import Optional, List

import typer

from ..abstract_adapter import Adapter, AdapterError
from ...data.canonical_db import CanonicalDataModel, SettingsDataModel

COLLECTION_FILE_SUFFIXES = {
    "domains": "_domains.json",
    "computers": "_computers.json",
    "users": "_users.json",
    "groups": "_groups.json",
    "gpos": "_gpos.json",
    "ous": "_ous.json",
    "containers": "_containers.json",
    "trusts": "_trusts.json",
}


class BloodhoundAdapter(Adapter):
    """
    Adapter für BloodHound.py (bloodhound-ce-python), sammelt AD-Objekte (Computer, User,
    Gruppen, GPOs, ...) über LDAP/SMB als JSON für die spätere Analyse in BloodHound.
    """

    name = "bloodhound-ce"
    executable = "bloodhound-ce-python"
    help_List = {
        "domain": None,
        "dc": None,
        "collection_method": None,
        "output_dir": None,
        "zip": None,
        "dns_tcp": None,
        "extra_args": None,
    }

    returnCode_version = 0
    version_cmd = ["-h"]
    test_args = ["-h"]

    def build_command(
        self,
        domain: Optional[str] = None,
        dc: Optional[str] = None,
        collection_method: str = "All,LoggedOn",
        output_dir: Optional[str] = None,
        zip: bool = False,
        dns_tcp: bool = False,
        extra_args: Optional[List[str]] = None,
        auth: Optional[SettingsDataModel] = None,
        **kwargs,
    ) -> List[str]:
        domain = domain or (auth.domain if auth else None)
        username = auth.username if auth else None
        password = auth.password if auth else None

        if not domain:
            raise AdapterError("domain erforderlich", tool=self.executable)
        if not username or not password:
            raise AdapterError(
                "Zugangsdaten erforderlich (Settings via 'settings add'/'settings default')",
                tool=self.executable,
            )
        if not dc:
            raise AdapterError("DC-IP erforderlich", tool=self.executable)

        out_dir = (
            Path(output_dir) if output_dir else Path("loot") / "bloodhound" / domain
        )
        out_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir = out_dir
        self.used_domain = domain

        cmd = [
            self.executable,
            "-u",
            username,
            "-p",
            password,
            "-d",
            domain,
            "-c",
            collection_method,
            "--outputdirectory",
            str(out_dir),
        ]

        if dc:
            cmd += ["-dc", dc]
        if dns_tcp:
            cmd.append("--dns-tcp")
        if zip:
            cmd.append("--zip")
        if extra_args:
            cmd.extend(
                shlex.split(extra_args) if isinstance(extra_args, str) else extra_args
            )

        return cmd

    def parse_output(self, stdout: str):
        typer.echo(stdout)

        collected = {}
        for label, suffix in COLLECTION_FILE_SUFFIXES.items():
            matches = sorted(self.output_dir.glob(f"*{suffix}"))
            if not matches:
                continue
            latest = matches[-1]
            count = None
            try:
                with open(latest, encoding="utf-8") as f:
                    payload = json.load(f)
                count = len(payload.get("data", []))
            except (OSError, json.JSONDecodeError):
                pass
            collected[label] = {"file": str(latest), "count": count}

        entries = [
            {
                "output_dir": str(self.output_dir),
                "collected": collected,
            }
        ]
        return self.normalizer(entries)

    def normalizer(self, entries):
        return [
            CanonicalDataModel(
                "AD", self.used_domain, self.name, datetime.now().isoformat(), entries
            )
        ]
