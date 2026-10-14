import re
import shlex
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional, List

import typer

from ..abstract_adapter import Adapter, AdapterError
from ...data.canonical_db import CanonicalDataModel, SettingsDataModel

# domain\user:rid:lmhash:nthash:::
_SECRET_RE = re.compile(
    r"^(?P<account>[^:\s]+):(?P<rid>\d+):(?P<lm>[0-9a-fA-F]{32}):(?P<nt>[0-9a-fA-F]{32}):::",
)
# Kerberos keys / cleartext:  user:aes256-cts-hmac-sha1-96:<key>
_KERB_RE = re.compile(
    r"^(?P<account>[^:\s]+):(?P<keytype>aes256-cts-hmac-sha1-96|aes128-cts-hmac-sha1-96|des-cbc-md5):(?P<key>[0-9a-fA-F]+)\s*$",
)


@dataclass
class SecretEntry:
    account: str
    kind: str                       # "ntlm" | "kerberos_key"
    rid: Optional[str] = None
    nt_hash: Optional[str] = None
    lm_hash: Optional[str] = None
    key_type: Optional[str] = None
    key: Optional[str] = None

    def to_dict(self):
        return asdict(self)


class SecretsdumpAdapter(Adapter):
    """
    Adapter für impacket-secretsdump (NTLM-Hashes / Kerberos-Keys via DRSUAPI, SAM, LSA).

    Beispiele:
      impacket-secretsdump corp.local/admin:'Pass123'@10.0.0.1
      impacket-secretsdump -hashes :<nthash> corp.local/admin@10.0.0.1 -just-dc
    """

    name = "secretsdump"
    executable = "impacket-secretsdump"
    help_List = {
        "target": None,
        "username": None,
        "password": None,
        "domain": None,
        "hashes": None,
        "just_dc": None,
        "just_dc_ntlm": None,
        "extra_args": None,
    }

    returnCode_version = 0
    version_cmd = ["-h"]
    help_cmd = ["-h"]
    test_args = ["-h"]

    def __init__(self, **config):
        super().__init__(**config)
        self.used_target = ""

    def build_command(
        self,
        target: Optional[str] = None,
        domain: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        hashes: Optional[str] = None,
        just_dc: bool = False,
        just_dc_ntlm: bool = False,
        extra_args: Optional[str] = None,
        auth: Optional[SettingsDataModel] = None,
        **kwargs,
    ) -> List[str]:
        if not target:
            raise AdapterError("'target' (IP/Hostname des DC/Hosts) erforderlich", tool=self.executable)

        domain = domain or (auth.domain if auth else None)
        username = username or (auth.username if auth else None)
        if password is None and auth:
            password = auth.password
        if not username:
            raise AdapterError("'username' erforderlich", tool=self.executable)
        if not hashes and not password:
            raise AdapterError("'password' oder 'hashes' erforderlich", tool=self.executable)

        # [domain/]user[:password]@target
        identity = f"{domain}/{username}" if domain else username
        if password and not hashes:
            identity += f":{password}"
        identity += f"@{target}"

        cmd: List[str] = [self.executable, identity]
        if hashes:
            cmd += ["-hashes", hashes]
        if just_dc:
            cmd.append("-just-dc")
        if just_dc_ntlm:
            cmd.append("-just-dc-ntlm")
        if extra_args:
            cmd.extend(shlex.split(extra_args) if isinstance(extra_args, str) else extra_args)

        self.used_target = target
        return cmd

    def parse_output(self, stdout: str):
        typer.echo(stdout)
        entries: List[SecretEntry] = []
        seen = set()

        for line in stdout.splitlines():
            line = line.strip()
            m = _SECRET_RE.match(line)
            if m:
                acct = m.group("account")
                if (acct, "ntlm") in seen:
                    continue
                seen.add((acct, "ntlm"))
                entries.append(SecretEntry(
                    account=acct,
                    kind="ntlm",
                    rid=m.group("rid"),
                    lm_hash=m.group("lm"),
                    nt_hash=m.group("nt"),
                ))
                continue

            m = _KERB_RE.match(line)
            if m:
                acct = m.group("account")
                key_type = m.group("keytype")
                if (acct, key_type) in seen:
                    continue
                seen.add((acct, key_type))
                entries.append(SecretEntry(
                    account=acct,
                    kind="kerberos_key",
                    key_type=key_type,
                    key=m.group("key"),
                ))

        return self.normalizer(entries)

    def normalizer(self, entries):
        if not entries:
            return []
        data = [e.to_dict() for e in entries]
        return [CanonicalDataModel(
            "SECRETS", self.used_target, self.name, datetime.now().isoformat(), data,
        )]
