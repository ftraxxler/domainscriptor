from typing import Optional, List, Dict, Any, Union

import typer

from ..base import Adapter, AdapterError
import shlex


class ProxychainsAdapter(Adapter):
    """
    Adapter für proxychains / proxychains4.
    Wrappt ein beliebiges Kommando, z.B.:

      proxychains4 nxc smb 10.0.0.5 -u user -p pass
      proxychains4 ntlmrelayx.py -tf targets.txt -smb2support
    """

    name = "proxychains"
    executable = "proxychains4"  # ggf. "proxychains" je nach System
    test_args = ["--help"]
    help_List = None

    returnCode_version = 1

    def build_command(
            self,
            **kwargs,
    ):
        raise NotImplementedError(f"This adapter is only for checking if proxychains is available. To call nxc and smbclient over proxychains use the designated parameter when calling them")

    def parse_output(self, stdout: str):
        pass
