from dataclasses import dataclass
import os
import subprocess
import threading
import time
from typing import Any,Callable, Dict, List, Literal, Optional
import typer

from domainscriptor.adapters_registry.adapters.watcher.NTLMRelayWatcher import NTLMRelayWatcher
from domainscriptor.adapters_registry.adapters.watcher.ResponderWatcher import ResponderLogWatcher

JobType = Literal["process", "thread"]


@dataclass
class Job:
    name: str
    kind: JobType
    process: Optional[subprocess.Popen] = None
    thread: Optional[threading.Thread] = None
    stop_fn: Optional[Callable[[], None]] = None
    watcher: Optional[Any] = None

    def is_process(self) -> bool:
        return self.kind == "process"

    def is_thread(self) -> bool:
        return self.kind == "thread"

    def is_alive(self) -> bool:
        if self.is_process() and self.process:
            return self.process.poll() is None
        if self.is_thread() and self.thread:
            return self.thread.is_alive()
        return False

    def stop(self):
        if self.is_process() and self.process and self.process.poll() is None:
            self.process.terminate()
        elif self.is_thread() and self.stop_fn:
            self.stop_fn()


class Runner:

    def __init__(self):
        self.running_processes: Dict[str] = {}

    def stream_output(self, process: subprocess.Popen,stop_event: threading.Event):
        """Liest stdout+stderr in Echtzeit aus."""

        for line in process.stdout:
            if stop_event.is_set():
                break
            # Only for debugging
            #typer.echo(line.rstrip())
            pass

        if process.stdout:
            process.stdout.close()

        process.wait()
        typer.secho(f"\n✅ Prozess beendet: {process.args}\n", fg=typer.colors.GREEN)

    def run_async(self, name, cmd, watcher_cls, queue):
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        jobs: List[Job] = []

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=env
        )

        typer.secho(f"🚀 Starte {name} im Hintergrund: {' '.join(cmd)}", fg=typer.colors.CYAN)
        tool_job = Job(name=str(name + "-Tool"), kind="process", process=process)
        jobs.append(tool_job)

        typer.secho(f"🚀 Starte Stout für {name} im Hintergrund ", fg=typer.colors.CYAN)
        stout_stop_event = threading.Event()
        stout_thread = threading.Thread(target=self.stream_output, args=(process,stout_stop_event,), daemon=True)
        stout_thread.start()
        stout_job = Job(name=str(name + "-stout"), kind="thread", thread=stout_thread,stop_fn=stout_stop_event.set)
        jobs.append(stout_job)

        typer.secho(f"🚀 Starte Watcher für {name} im Hintergrund ", fg=typer.colors.CYAN)

        watcher = watcher_cls(queue=queue)
        watcher_thread = threading.Thread(
            target=watcher.follow,
            daemon=True,
        )
        watcher_thread.start()
        watcher_job = Job(name=str(name + "-watcher"), kind="thread", thread=watcher_thread, stop_fn=watcher.stop,watcher=watcher)
        jobs.append(watcher_job)

        self.running_processes[name] = jobs

    def show_processes(self):
        return self.running_processes.keys()

    def stop_process(self, name: str, timeout: float = 5.0):
        jobs = self.running_processes[name]
        if not jobs:
            typer.echo(f"Process/Job-Gruppe '{name}' existiert nicht")
            return

        typer.secho(f"🛑 Stoppe Jobs für: {name}", fg=typer.colors.YELLOW)

        # 1) Erst Threads kooperativ stoppen (Watcher)
        for job in jobs:
            if job.kind == "thread" and job.stop_fn:
                try:
                    job.stop_fn()
                    typer.echo(f"  • Thread stop_fn aufgerufen: {job.name}")
                except Exception as e:
                    typer.secho(f"  • stop_fn Fehler bei {job.name}: {e}", fg=typer.colors.RED)

        # 2) Prozesse terminieren
        for job in jobs:
            if job.kind == "process" and job.process:
                p = job.process
                if p.poll() is None:
                    try:
                        p.terminate()
                        typer.echo(f"  • terminate(): {job.name} (pid={p.pid})")
                    except Exception as e:
                        typer.secho(f"  • terminate Fehler bei {job.name}: {e}", fg=typer.colors.RED)

        # 3) Warten + ggf. kill
        deadline = time.time() + timeout
        for job in jobs:
            if job.kind == "process" and job.process:
                p = job.process
                if p.poll() is None:
                    remaining = deadline - time.time()
                    if remaining > 0:
                        try:
                            p.wait(timeout=remaining)
                        except Exception:
                            pass
                if p.poll() is None:
                    try:
                        p.kill()
                        typer.secho(f"  • kill(): {job.name} (pid={p.pid})", fg=typer.colors.RED)
                    except Exception as e:
                        typer.secho(f"  • kill Fehler bei {job.name}: {e}", fg=typer.colors.RED)

        # 4) Threads kurz joinen (optional)
        for job in jobs:
            if job.kind == "thread" and job.thread:
                job.thread.join(timeout=1.0)

        del self.running_processes[name]
        typer.secho(f"✅ '{name}' gestoppt.", fg=typer.colors.GREEN)

    def stop_tool(self, name: str):
        self.stop_process(name)

    def stop_all(self):
        for name in list(self.running_processes.keys()):
            self.stop_process(name)


    def get_relays(self):
        if self.running_processes["impacket-ntlmrelayx"]:
            jobs = self.running_processes["impacket-ntlmrelayx"]
            if not jobs:
                typer.echo("Keine Jobs für 'impacket-ntlmrelayx' gefunden")
                return None
            for job in jobs:
                if job.name == "impacket-ntlmrelayx-watcher":
                    ntlmrelay_watcher = job.watcher
                    return ntlmrelay_watcher.get_latest_entries()
            typer.echo("Watcher not running")
        else:
            typer.echo("Impacket-NTLMRelay not running")
        return None
