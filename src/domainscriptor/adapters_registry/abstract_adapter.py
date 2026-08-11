from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import shutil
import subprocess
import threading
from typing import Any, Dict, List, Optional

import typer

from domainscriptor import Runner
from domainscriptor.data.db_writer import InsertCanonical


@dataclass
class AdapterResult:
    ok: bool
    returncode: int
    stdout: str
    stderr: str
    parsed: Optional[Dict[str, Any]] = field(default=None)


class AdapterError(RuntimeError):
    def __init__(
        self, message: str, *, tool: str | None = None, detail: str | None = None
    ):
        super().__init__(message)
        self.tool = tool
        self.detail = detail


class Adapter(ABC):
    """
    Basis-Interface für externe CLI-Tools.
    Implementiere `build_command und normalizer
    """

    name: str = "base"
    executable: str = ""  # z.B. "responder", "smbexec"
    watcher = None
    help_List: List = None
    default_timeout: float = 300  # Sekunden
    returnCode_version = 0
    version_cmd = ["--version"]
    help_cmd = ["--help"]
    run_background = False
    test_args = None

    def __init__(self, **config):
        self.config = config

    @classmethod
    def is_installed(cls) -> bool:
        return bool(shutil.which(cls.executable))

    @classmethod
    def can_run(cls, timeout: int = 5) -> bool:
        """
        Führt einen minimalen Testlauf aus, um zu prüfen, ob das Tool auch wirklich
        gestartet werden kann (z. B. "--version" oder "-h").
        Gibt True zurück, wenn Exitcode 0 oder 1 (häufig bei -h) geliefert wird.
        """
        if not cls.is_installed():
            raise RuntimeError(f"{cls.executable} is not installed")

        args = cls.test_args or ["--version"]
        try:
            result = subprocess.run(
                [cls.executable, *args],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                text=True,
            )
            # viele CLI-Tools geben 0 oder 1 bei Hilfe/Version zurück
            if result.returncode != cls.returnCode_version:
                raise RuntimeError(f"{cls.executable} can not be executed")
        except (FileNotFoundError, subprocess.SubprocessError):
            raise RuntimeError(f"{cls.executable} can not be executed")

    @abstractmethod
    def build_command(self, **kwargs) -> List[str]:
        """
        Muss den kompletten argv-Befehl liefern, z.B. ["responder", "-I", "eth0", "-wrf"].
        """
        raise NotImplementedError

    def parse_output(self, stdout: str):
        """
        Optional: Tool-spezifisches Parsen. Default: nichts.
        """
        return None

    @abstractmethod
    def normalizer(self, entries):
        """
        Converts tool specific data to the normalized data
        """
        raise NotImplementedError

    def version(self, timeout: int = 5):
        try:
            result = subprocess.run(
                [self.executable, *self.version_cmd],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                text=True,
            )
            # viele CLI-Tools geben 0 oder 1 bei Hilfe/Version zurück
            # print(f"Logging Result {result}")
            return result.stdout
        except (FileNotFoundError, subprocess.SubprocessError):
            raise RuntimeError(f"Error running command")

    def help(self, timeout: int = 5):

        try:
            result = subprocess.run(
                [self.executable, *self.help_cmd],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                text=True,
            )
            # viele CLI-Tools geben 0 oder 1 bei Hilfe/Version zurück
            # print(f"Logging Result {result}")
            help_output = result.stdout
            help_output += "\n" + "-" * 10 + "\n"
            help_output += "Domainscriptor Help\n"
            if self.help_List is not None:
                help_output += "\n".join(self.help_List.keys()) + "\n"
            return help_output
        except (FileNotFoundError, subprocess.SubprocessError):
            raise RuntimeError(f"Error running command")

    def run(self, runner, queue, auth=None, timeout: int = default_timeout, **kwargs):
        try:
            cmd = self.build_command(auth=auth, **kwargs)
            typer.echo(f"Running command: {cmd}")
            if self.run_background:
                runner.run_async(self.executable, cmd, self.watcher, queue)
            else:
                result = subprocess.run(
                    [*cmd],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=timeout,
                    text=True,
                )
                # print(f"Logging Result {result}")
                output = self.parse_output(result.stdout)
                return output
        except (TimeoutError, subprocess.TimeoutExpired):
            raise RuntimeError("Running command timed out")
        except (FileNotFoundError, subprocess.SubprocessError):
            raise RuntimeError(f"Error running command")
        except NotImplementedError as e:
            typer.echo(typer.style(str(e), fg=typer.colors.RED, bold=True))
