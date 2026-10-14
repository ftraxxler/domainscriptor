import re
import shlex
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional, List

import typer

from ..abstract_adapter import Adapter, AdapterError
from ...data.canonical_db import CanonicalDataModel, SettingsDataModel

# [+] VALID USERNAME:       jdoe@corp.local
# [+] jdoe@corp.local:Summer2024   (passwordspray)
_VALID_USER_RE = re.compile(
    r"\[\+\]\s*VALID USERNAME:\s*(?P<user>\S+)",
    re.IGNORECASE,
)
_VALID_CRED_RE = re.compile(
    r"\[\+\]\s*(?P<user>\S+@\S+):(?P<password>\S+)",
    re.IGNORECASE,
)


@dataclass
class KerbruteEntry:
    username: str
    domain: str
    kind: str                       # "valid_user" | "valid_credential"
    password: Optional[str] = None

    def to_dict(self):
        return asdict(self)


class KerbruteAdapter(Adapter):
    """
    Adapter für kerbrute (Kerberos pre-auth user enumeration / password spray).

    Beispiele:
      kerbrute userenum -d corp.local --dc 10.0.0.1 users.txt
      kerbrute passwordspray -d corp.local --dc 10.0.0.1 users.txt 'Summer2024!'
    """

    name = "kerbrute"
    executable = "kerbrute"
    help_List = {
        "mode": None,          # userenum | passwordspray | bruteuser
        "domain": None,
        "dc": None,
        "userlist": None,
        "password": None,      # für passwordspray
        "username": None,      # für bruteuser
        "extra_args": None,
    }

    returnCode_version = 0
    version_cmd = ["version"]
    help_cmd = ["--help"]
    test_args = ["version"]

    _MODES = {"userenum", "passwordspray", "bruteuser"}

    def __init__(self, **config):
        super().__init__(**config)
        self.used_domain = ""

    def build_command(
        self,
        mode: str = "userenum",
        domain: Optional[str] = None,
        dc: Optional[str] = None,
        userlist: Optional[str] = None,
        password: Optional[str] = None,
        username: Optional[str] = None,
        extra_args: Optional[str] = None,
        auth: Optional[SettingsDataModel] = None,
        **kwargs,
    ) -> List[str]:
        mode = (mode or "userenum").lower()
        if mode not in self._MODES:
            raise AdapterError(
                f"Unbekannter mode '{mode}'. Erlaubt: {', '.join(sorted(self._MODES))}",
                tool=self.executable,
            )

        domain = domain or (auth.domain if auth else None)
        if not domain:
            raise AdapterError("'domain' erforderlich", tool=self.executable)
        self.used_domain = domain

        cmd: List[str] = [self.executable, mode, "-d", domain]
        if dc:
            cmd += ["--dc", dc]

        if mode == "bruteuser":
            if not username:
                raise AdapterError("'username' erforderlich für bruteuser", tool=self.executable)
            if not userlist:
                raise AdapterError("'userlist' (Passwortliste) erforderlich für bruteuser", tool=self.executable)
            cmd += [userlist, username]
        else:
            if not userlist:
                raise AdapterError("'userlist' erforderlich", tool=self.executable)
            cmd.append(userlist)
            if mode == "passwordspray":
                spray_pw = password or (auth.password if auth else None)
                if not spray_pw:
                    raise AdapterError("'password' erforderlich für passwordspray", tool=self.executable)
                cmd.append(spray_pw)

        if extra_args:
            cmd.extend(shlex.split(extra_args) if isinstance(extra_args, str) else extra_args)

        return cmd

    def parse_output(self, stdout: str):
        typer.echo(stdout)
        entries: List[KerbruteEntry] = []
        seen = set()

        for line in stdout.splitlines():
            m = _VALID_CRED_RE.search(line)
            if m:
                # valid_credential (enthält Passwort, z. B. aus passwordspray)
                user = m.group("user")
                key = ("cred", user)
                if key not in seen:
                    seen.add(key)
                    dom = user.split("@")[-1] if "@" in user else self.used_domain
                    entries.append(KerbruteEntry(
                        username=user, domain=dom, kind="valid_credential",
                        password=m.group("password"),
                    ))
                continue

            m = _VALID_USER_RE.search(line)
            if m:
                user = m.group("user")
                key = ("user", user)
                if key not in seen:
                    seen.add(key)
                    dom = user.split("@")[-1] if "@" in user else self.used_domain
                    entries.append(KerbruteEntry(
                        username=user, domain=dom, kind="valid_user",
                    ))

        return self.normalizer(entries)

    def normalizer(self, entries):
        by_domain = defaultdict(list)
        for e in entries:
            by_domain[e.domain].append(e.to_dict())

        result = []
        for domain, data in by_domain.items():
            result.append(CanonicalDataModel(
                "KERBEROS", domain, self.name, datetime.now().isoformat(), data,
            ))
        return result
