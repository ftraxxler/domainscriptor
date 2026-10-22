from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import contextlib
import io
import shutil
import subprocess
import threading
from typing import Any, Dict, List, Optional

import typer

from ..logging_setup import get_logger, log_command, log_command_result


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
    cwd: Optional[str] = None  # working directory for the subprocess (e.g. tools that write to CWD)

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

    def run(self, runner, queue, auth=None, timeout: int = default_timeout,
            background: bool = False, attach: bool = False, persist=None, log_dir=None,
            **kwargs):
        # build_command kann AdapterError (RuntimeError) werfen – diese Meldung ist
        # bewusst aussagekräftig und wird nicht in eine generische Meldung übersetzt.
        cmd = self.build_command(auth=auth, **kwargs)
        source = "async" if (self.run_background or background) else "exec"
        log_command(cmd, source=source, adapter=self.name)
        try:
            typer.echo(f"Running command: {cmd}")
            if self.run_background:
                runner.run_async(self.executable, cmd, self.watcher, queue)
                return None

            # Background (detached) and attach (foreground, detach key detaches) both
            # run as managed jobs; results are parsed and persisted on completion.
            if background or attach:
                def _on_complete(output: str):
                    # Parse quietly: the raw output is already in the job's logfile
                    # (view with 'showoutput'); don't let parse_output dump it to the
                    # console after the job has been backgrounded.
                    data = None
                    try:
                        with contextlib.redirect_stdout(io.StringIO()):
                            data = self.parse_output(output)
                    except Exception:
                        get_logger("job").exception(
                            "parse_output failed for %s", self.name
                        )
                    log_command_result(self.name, "bg-done")
                    if data and persist:
                        persist(data)

                job_name, logfile = runner.run_job(
                    self.name, cmd, on_complete=_on_complete,
                    cwd=self.cwd, log_dir=log_dir,
                )
                if background:
                    msg = f"[bg] {self.name} gestartet (job: {job_name})"
                    if logfile:
                        msg += f" → {logfile}"
                    typer.secho(msg, fg=typer.colors.GREEN)
                    return None

                # attach: stream output; the detach key detaches and returns to the prompt
                detached = runner.follow(job_name, timeout=timeout)
                if detached:
                    typer.secho(
                        f"\n[bg] {self.name} in den Hintergrund verschoben "
                        f"(job: {job_name}) – 'reattach {job_name}' zum erneut Anhängen, "
                        f"'showoutput {job_name}' zum Nachsehen.",
                        fg=typer.colors.YELLOW,
                    )
                return None

            result = subprocess.run(
                [*cmd],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                text=True,
                cwd=self.cwd,
            )
            log_command_result(self.name, result.returncode)
            if result.returncode not in (0, 1) and result.stderr.strip():
                # Nicht abbrechen (viele Tools liefern !=0 bei Findings), aber warnen.
                last_err = result.stderr.strip().splitlines()[-1]
                get_logger("adapter").warning(
                    "%s exit %s: %s", self.executable, result.returncode, last_err
                )
                typer.secho(
                    f"[{self.executable}] exit {result.returncode}: {last_err}",
                    fg=typer.colors.YELLOW,
                )
            return self.parse_output(result.stdout)
        except (TimeoutError, subprocess.TimeoutExpired):
            get_logger("adapter").error("%s timed out after %ss", self.executable, timeout)
            raise RuntimeError(f"'{self.executable}' timed out after {timeout}s")
        except FileNotFoundError:
            get_logger("adapter").error("%s not found on PATH", self.executable)
            raise RuntimeError(f"'{self.executable}' not found (is it installed and on PATH?)")
        except subprocess.SubprocessError as e:
            get_logger("adapter").error("Error running %s: %s", self.executable, e)
            raise RuntimeError(f"Error running '{self.executable}': {e}")
        except NotImplementedError as e:
            typer.echo(typer.style(str(e), fg=typer.colors.RED, bold=True))
