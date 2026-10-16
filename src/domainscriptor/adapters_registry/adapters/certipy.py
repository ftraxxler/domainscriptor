import re
import shlex
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional, List

import typer

from ..abstract_adapter import Adapter, AdapterError
from ...data.canonical_db import CanonicalDataModel, SettingsDataModel

# A vulnerability line in `certipy find -stdout`, e.g.:
#       ESC1                                : 'CORP.LOCAL\\Domain Users' can enroll, ...
_ESC_RE = re.compile(r"^\s*(?P<esc>ESC\d+)\s*:\s*(?P<desc>.+?)\s*$")
# The template a block belongs to:
#     Template Name                         : ESC1-Template
_TEMPLATE_RE = re.compile(r"^\s*Template Name\s*:\s*(?P<name>.+?)\s*$")

# ESCs that typically yield (near-)immediate domain compromise.
_CRITICAL_ESCS = {"ESC1", "ESC3", "ESC6", "ESC8"}


@dataclass
class CertipyFinding:
    esc: str
    template: str
    description: str

    def to_dict(self):
        return asdict(self)


class CertipyAdapter(Adapter):
    """
    Adapter für Certipy (certipy-ad), AD CS (ADCS) Enumeration und Missbrauch.

    Standard-Aktion ist ``find`` (ESC1-ESC16 Template-/CA-Schwachstellen). Die
    Ausgabe wird mit ``-stdout`` auf die Konsole geleitet und nach ESC-Findings
    geparst.

    Beispiele:
      runcommand certipy target=10.0.0.1 username=user password=pass domain=corp.local
      runcommand certipy target=10.0.0.1 username=user hashes=:<nthash> vulnerable=true
    """

    name = "certipy"
    executable = "certipy-ad"
    help_List = {
        "action": None,            # find (default) | req | auth | shadow | ...
        "target": None,            # DC / target IP or hostname
        "dc_ip": None,
        "domain": None,
        "username": None,
        "password": None,
        "hashes": None,
        "nameserver": None,        # -ns
        "dns_tcp": None,
        "vulnerable": None,        # only vulnerable templates (find)
        "extra_args": None,
    }

    returnCode_version = 0
    version_cmd = ["-v"]
    help_cmd = ["-h"]
    test_args = ["-h"]

    def __init__(self, **config):
        super().__init__(**config)
        self.used_target = ""

    def build_command(
        self,
        action: str = "find",
        target: Optional[str] = None,
        dc_ip: Optional[str] = None,
        domain: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        hashes: Optional[str] = None,
        nameserver: Optional[str] = None,
        dns_tcp: bool = False,
        vulnerable: bool = True,
        extra_args: Optional[str] = None,
        auth: Optional[SettingsDataModel] = None,
        **kwargs,
    ) -> List[str]:
        domain = domain or (auth.domain if auth else None)
        username = username or (auth.username if auth else None)
        if password is None and auth:
            password = auth.password

        dc_ip = dc_ip or target
        if not dc_ip:
            raise AdapterError("'target' oder 'dc_ip' (DC-IP) erforderlich", tool=self.executable)
        if not username:
            raise AdapterError("'username' erforderlich", tool=self.executable)
        if not hashes and not password:
            raise AdapterError("'password' oder 'hashes' erforderlich", tool=self.executable)

        identity = f"{username}@{domain}" if domain else username

        cmd: List[str] = [self.executable, action, "-u", identity]
        if password and not hashes:
            cmd += ["-p", password]
        if hashes:
            cmd += ["-hashes", hashes]
        cmd += ["-dc-ip", dc_ip]
        if nameserver:
            cmd += ["-ns", nameserver]
        if dns_tcp:
            cmd.append("-dns-tcp")
        if action == "find":
            cmd.append("-stdout")        # parseable output on the console
            if vulnerable:
                cmd.append("-vulnerable")
        if extra_args:
            cmd.extend(shlex.split(extra_args) if isinstance(extra_args, str) else extra_args)

        self.used_target = dc_ip
        return cmd

    def parse_output(self, stdout: str):
        typer.echo(stdout)
        findings = parse_certipy_find(stdout)
        return self.normalizer(findings)

    def normalizer(self, findings: List["CertipyFinding"]):
        if not findings:
            return []
        data = [f.to_dict() for f in findings]
        return [CanonicalDataModel(
            "ADCS", self.used_target, self.name, datetime.now().isoformat(), data,
        )]


def parse_certipy_find(stdout: str) -> List[CertipyFinding]:
    """Extract ESC vulnerability findings from `certipy find -stdout` output.

    Tracks the most recent ``Template Name`` so each ESC line is attributed to
    the template it was reported under.
    """
    findings: List[CertipyFinding] = []
    current_template = ""
    for line in stdout.splitlines():
        t = _TEMPLATE_RE.match(line)
        if t:
            current_template = t.group("name").strip()
            continue
        m = _ESC_RE.match(line)
        if m:
            findings.append(CertipyFinding(
                esc=m.group("esc"),
                template=current_template,
                description=m.group("desc").strip(),
            ))
    return findings


def certipy_severity(esc: str) -> bool:
    """Return True if the given ESC id is considered critical."""
    return esc.upper() in _CRITICAL_ESCS
