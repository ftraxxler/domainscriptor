from ..abstract_adapter import Adapter, AdapterError
from typing import Optional, List


class SMBExecAdapter(Adapter):
    name = "smbexec"
    executable = "impacket-smbexec"  # ggf. smbexec.py oder absoluter Pfad
    help_List = {
        "target": None,
        "username": None,
        "password": None,
        "domain": None,
        "command": None,
        "extra_args": None,
    }
    returnCode_version = 2

    def build_command(
            self,
            target: str,
            username: str,
            password: Optional[str] = None,
            domain: Optional[str] = None,
            command: Optional[str] = None,
            extra_args: Optional[List[str]] = None,
            **kwargs
    ):
        if not target or not username:
            raise AdapterError("target und username erforderlich", tool=self.executable)
        cmd = [self.executable, "-target", target, "-u", username]
        if password:
            cmd += ["-p", password]
        if domain:
            cmd += ["-d", domain]
        if command:
            cmd += ["-x", command]
        if extra_args:
            cmd.append(extra_args)
        return cmd

    def parse_output(self, stdout: str, stderr: str):
        parsed = {}
        if "Access denied" in stdout or "ACCESS_DENIED" in stdout.upper():
            parsed["auth"] = "denied"
        return parsed or None
