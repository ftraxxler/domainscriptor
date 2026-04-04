from typing import Optional, List, Dict, Any

from .watcher.NTLMRelayWatcher import NTLMRelayWatcher
from ..base import Adapter, AdapterError


class NTLMRelayAdapter(Adapter):
    """
    Adapter für ntlmrelayx (Impacket).
    Beispielaufrufe:
      ntlmrelayx.py -tf targets.txt -smb2support -of loot.txt -c "whoami"
      ntlmrelayx.py -t smb://10.0.0.5 -smb2support -c "whoami"
    """

    name = "ntlmrelayx"
    # ggf. "ntlmrelayx" oder absoluter Pfad, je nach Installation
    executable = "impacket-ntlmrelayx"
    watcher = NTLMRelayWatcher
    help_List = {
        "targets_file=": None,
        "target=": None,
        "protocol=": None,
        "command=": None,
        "loot_dir=": None,
        "interface=": None,
        "extra_args=": None,
        "smb2support": None,
        "keeprelaying": None,
        "socks": None,
    }

    run_background = True
    test_args = ["--help"]

    def build_command(
            self,
            targets_file: Optional[str] = None,  # -tf target file
            target: Optional[
                str
            ] = None,  # -t single target, z.B. 10.0.0.5 oder smb://10.0.0.5
            protocol: str = "smb",  # wird für target ohne schema benutzt: smb://<target>
            command: Optional[str] = None,  # -c "cmd"
            loot_dir: Optional[str] = None,  # -of / -lootdir o.ä. je nach Version
            smb2support: bool = True,  # -smb2support
            keeprelaying: bool = True,
            interface: Optional[str] = None,  # -i interface
            socks: bool = True,
            extra_args: Optional[List[str]] = None,
            **kwargs,
    ) -> List[str]:
        if not targets_file and not target:
            raise AdapterError(
                "Entweder 'targets_file' oder 'target' ist erforderlich.",
                tool=self.executable,
            )

        cmd: List[str] = [self.executable]

        if targets_file:
            cmd += ["-tf", targets_file]

        if target:
            if "://" not in target:
                target = f"{protocol}://{target}"
            cmd += ["-t", target]

        if smb2support:
            cmd.append("-smb2support")

        if keeprelaying:
            cmd.append("--keep-relaying")

        if loot_dir:
            cmd += ["-of", loot_dir]

        if interface:
            cmd += ["-i", interface]

        if socks:
            cmd.append("-socks")

        if command:
            cmd += ["-c", command]

        if extra_args:
            cmd.append(extra_args)

        return cmd

    def parse_output(self, stdout: str) -> Optional[Dict[str, Any]]:
        pass
