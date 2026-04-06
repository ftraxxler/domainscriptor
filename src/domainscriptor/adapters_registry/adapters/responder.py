from ..base import Adapter, AdapterError
from typing import Optional, List
from domainscriptor.adapters_registry.adapters.watcher.ResponderWatcher import ResponderLogWatcher


class ResponderAdapter(Adapter):
    name = "responder"
    executable = "responder"
    watcher = ResponderLogWatcher
    help_List = {
        "interface": None,
        "extra_args": None,
    }
    run_background = True

    def build_command(
            self,
            interface: str,
            extra_args: Optional[List[str]] = None,
            **kwargs
    ):
        if not interface:
            raise AdapterError("interface erforderlich", tool=self.executable)
        cmd = [self.executable, "-I", interface]
        if extra_args:
            cmd.append(extra_args)
        return cmd

    def parse_output(self, stdout: str):
        return None
