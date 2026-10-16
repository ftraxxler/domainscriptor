from dataclasses import dataclass
import os
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Any,Callable, Dict, List, Literal, Optional
import typer

from domainscriptor.adapters_registry.adapters.watcher.NTLMRelayWatcher import NTLMRelayWatcher
from domainscriptor.adapters_registry.adapters.watcher.ResponderWatcher import ResponderLogWatcher
from domainscriptor.logging_setup import redact_command

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
        self._job_counter: Dict[str, int] = {}
        self.job_logs: Dict[str, Optional[str]] = {}
        self.job_meta: Dict[str, dict] = {}

    def _next_job_name(self, base: str) -> str:
        self._job_counter[base] = self._job_counter.get(base, 0) + 1
        return f"{base}-{self._job_counter[base]}"

    def run_job(self, base_name, cmd, on_complete=None, cwd=None, log_dir=None):
        """Start ``cmd`` as a detached background job.

        Output is written to ``<log_dir>/jobs/<job>.log`` (view with 'showoutput',
        stream live with 'follow'/attach). The job runs silently; when it exits it
        prints a completion message, passes the full captured output to
        ``on_complete`` (parse + persist), and removes itself from the running list
        (its log stays available). Returns ``(job_name, logfile_path_or_None)``.
        """
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        job_name = self._next_job_name(base_name)

        logfile = None
        if log_dir:
            try:
                jobs_dir = Path(log_dir) / "jobs"
                jobs_dir.mkdir(parents=True, exist_ok=True)
                logfile = jobs_dir / f"{job_name}.log"
            except OSError:
                logfile = None
        self.job_logs[job_name] = str(logfile) if logfile else None

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=env,
            cwd=cwd,
            start_new_session=True,  # own session: Ctrl-Z to the app won't stop the tool
        )

        stop_event = threading.Event()

        def _pump():
            captured: List[str] = []
            f = open(logfile, "w", encoding="utf-8") if logfile else None
            try:
                for line in process.stdout:
                    captured.append(line)
                    if f:
                        f.write(line)
                        f.flush()
                    if stop_event.is_set():
                        break
            finally:
                if process.stdout:
                    process.stdout.close()
                if f:
                    f.close()
            process.wait()
            # The job is done: drop it from the running list (log stays for
            # 'showoutput'), then notify and persist results.
            self.running_processes.pop(job_name, None)
            typer.secho(
                f"\n✅ [bg] {job_name} beendet (exit {process.returncode}) "
                f"— 'showoutput {job_name}'",
                fg=typer.colors.GREEN,
            )
            if on_complete and not stop_event.is_set():
                try:
                    on_complete("".join(captured))
                except Exception as e:
                    typer.secho(
                        f"[bg] {job_name}: Ergebnis-Verarbeitung fehlgeschlagen: {e}",
                        fg=typer.colors.RED,
                    )

        thread = threading.Thread(target=_pump, name=f"{job_name}-pump", daemon=True)
        thread.start()

        self.running_processes[job_name] = [
            Job(name=f"{job_name}-Tool", kind="process", process=process),
            Job(name=f"{job_name}-pump", kind="thread", thread=thread,
                stop_fn=stop_event.set),
        ]
        self.job_meta[job_name] = {
            "pid": process.pid,
            "started": time.time(),
            "cmd": redact_command(cmd),
            "logfile": str(logfile) if logfile else None,
        }
        return job_name, (str(logfile) if logfile else None)

    def job_info(self) -> List[dict]:
        """Info rows for the currently running jobs (finished jobs are removed)."""
        rows = []
        for name, jobs in list(self.running_processes.items()):
            proc = next((j.process for j in jobs if j.is_process()), None)
            meta = self.job_meta.get(name, {})
            rows.append({
                "job": name,
                "pid": meta.get("pid") or (proc.pid if proc else None),
                "alive": bool(proc and proc.poll() is None),
                "started": meta.get("started"),
                "cmd": meta.get("cmd", ""),
                "logfile": meta.get("logfile") or self.job_logs.get(name),
            })
        return rows

    def is_job_running(self, job_name: str) -> bool:
        jobs = self.running_processes.get(job_name)
        if not jobs:
            return False
        proc = next((j.process for j in jobs if j.is_process()), None)
        return proc is not None and proc.poll() is None

    def follow(self, job_name: str, timeout: Optional[float] = None) -> bool:
        """Stream a job's output to the console by tailing its logfile: first the
        output captured so far, then new output live, until the job finishes or the
        user presses Ctrl-Z (SIGTSTP) to detach. Works both for the initial
        foreground run and for re-attaching later.

        Returns True if detached while still running, False if it finished (or no
        live job exists, in which case the whole captured log is printed).
        """
        if job_name not in self.job_logs:
            typer.secho(f"Unknown job '{job_name}'.", fg=typer.colors.YELLOW)
            return False

        logpath = self.job_logs.get(job_name)
        jobs = self.running_processes.get(job_name)
        proc = next((j.process for j in jobs if j.is_process()), None) if jobs else None

        if not logpath:
            typer.secho(f"No output log for job '{job_name}'.", fg=typer.colors.YELLOW)
            return False

        # Job already finished → just print the whole captured log.
        if proc is None or proc.poll() is not None:
            out = self.read_output(job_name, max_lines=10_000)
            if out:
                typer.echo(out, nl=False)
            typer.secho(f"[{job_name}] finished — nothing more to stream.",
                        fg=typer.colors.YELLOW)
            return False

        detached = {"flag": False}

        def _on_tstp(signum, frame):
            detached["flag"] = True

        prev_handler = None
        try:
            prev_handler = signal.signal(signal.SIGTSTP, _on_tstp)
        except (ValueError, OSError, AttributeError):
            prev_handler = None  # not main thread / unsupported platform

        f = None
        try:
            for _ in range(200):  # wait briefly for the logfile to appear
                if Path(logpath).exists():
                    break
                time.sleep(0.01)
            try:
                f = open(logpath, "r", encoding="utf-8", errors="replace")
            except OSError:
                f = None

            deadline = (time.time() + timeout) if timeout else None
            while True:
                if f:
                    chunk = f.read()
                    if chunk:
                        typer.echo(chunk, nl=False)
                if detached["flag"]:
                    break
                if proc.poll() is not None:
                    if f:  # drain whatever was written at the very end
                        time.sleep(0.05)
                        chunk = f.read()
                        if chunk:
                            typer.echo(chunk, nl=False)
                    break
                if deadline and time.time() > deadline:
                    typer.secho(
                        f"\n[{job_name}] follow timeout after {timeout}s "
                        f"(job keeps running; see 'showoutput {job_name}')",
                        fg=typer.colors.YELLOW,
                    )
                    break
                time.sleep(0.1)
        finally:
            if f:
                f.close()
            if prev_handler is not None:
                try:
                    signal.signal(signal.SIGTSTP, prev_handler)
                except (ValueError, OSError):
                    pass

        return detached["flag"] and proc.poll() is None

    def read_output(self, job_name: str, max_lines: int = 40) -> Optional[str]:
        """Return the last ``max_lines`` of a background job's captured output."""
        path = self.job_logs.get(job_name)
        if not path:
            return None
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            return None
        return "".join(lines[-max_lines:])

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

        typer.secho(f"🚀 Starte {name} im Hintergrund: {' '.join(cmd)}", fg=typer.colors.GREEN)
        tool_job = Job(name=str(name + "-Tool"), kind="process", process=process)
        jobs.append(tool_job)

        typer.secho(f"🚀 Starte Stout für {name} im Hintergrund ", fg=typer.colors.GREEN)
        stout_stop_event = threading.Event()
        stout_thread = threading.Thread(target=self.stream_output, args=(process,stout_stop_event,), daemon=True)
        stout_thread.start()
        stout_job = Job(name=str(name + "-stout"), kind="thread", thread=stout_thread,stop_fn=stout_stop_event.set)
        jobs.append(stout_job)

        typer.secho(f"🚀 Starte Watcher für {name} im Hintergrund ", fg=typer.colors.GREEN)

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
        return list(self.running_processes.keys())

    def stop_process(self, name: str, timeout: float = 5.0):
        jobs = self.running_processes.get(name)
        if not jobs:
            typer.secho(
                f"Kein laufender Prozess/Job '{name}' (evtl. bereits beendet).",
                fg=typer.colors.YELLOW,
            )
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

        self.running_processes.pop(name, None)
        typer.secho(f"✅ '{name}' gestoppt.", fg=typer.colors.GREEN)

    def stop_tool(self, name: str):
        self.stop_process(name)

    def stop_all(self):
        for name in list(self.running_processes.keys()):
            self.stop_process(name)

    def get_relays(self):
        jobs = self.running_processes.get("impacket-ntlmrelayx")
        if not jobs:
            typer.echo("Impacket-NTLMRelay not running")
            return None
        for job in jobs:
            if job.name == "impacket-ntlmrelayx-watcher":
                return job.watcher.get_latest_entries()
        typer.echo("Watcher not running")
        return None
