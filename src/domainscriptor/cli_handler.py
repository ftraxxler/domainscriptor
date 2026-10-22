import os
import sys
import traceback
from pathlib import Path
from typing import Annotated, Optional
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.history import FileHistory
from prompt_toolkit.patch_stdout import patch_stdout
import typer
import click
import shlex

from domainscriptor.engine import Engine
from . import project_info
from .cli_completioner import (
    MainCompleter, RuncommandCompleter, StopProcessCompleter, JobNameCompleter,
)
from .logging_setup import get_logger, log_command
from .term_ui import page_output

info = project_info()

argument_handler = typer.Typer(
    add_completion=False, no_args_is_help=True, help=info["description"]
)


@argument_handler.callback(invoke_without_command=True)
def main(
        version: bool = typer.Option(
            False,
            "--version",
            is_eager=True,  # parse before other args
        ),
):
    if version:
        typer.echo(f"{info['name']} {info['version']}")
        raise typer.Exit()


@argument_handler.command()
def help(ctx: typer.Context, adapter: Annotated[str, typer.Argument()] = None):
    """
    Show global help or command-specific help. If ADAPTERNAME is provided, show help for that adapter`s commands/options.
    """
    eng: Engine = ctx.obj
    if adapter:
        typer.echo(eng.show_adapter_help(adapter))
    else:
        argument_handler(["--help"], standalone_mode=False)


@argument_handler.command()
def version(ctx: typer.Context, adapter: Annotated[str, typer.Argument()] = None):
    """
    Print the Domainscriptor version. If ADAPTERNAME is provided, also show the adapter version/info (if available).
    """
    eng: Engine = ctx.obj
    if adapter:
        typer.echo(eng.show_adapter_version(adapter))
    else:
        argument_handler(["--version"], standalone_mode=False)


@argument_handler.command("showadapters")
def show_adapters(ctx: typer.Context):
    """
    List all registered adapters, including their name, type, and current status (enabled/disabled).
    """
    eng: Engine = ctx.obj
    eng.render_adapters()


@argument_handler.command("showprocesses")
def show_processes(ctx: typer.Context):
    """
    Show background processes started by Domainscriptor
    """
    eng: Engine = ctx.obj
    eng.render_processes()


@argument_handler.command("stopprocess")
def stop_process(ctx: typer.Context, name: str):
    """
    Stop a background process by NAME. Use 'showprocesses' to see valid process names.
    """
    eng: Engine = ctx.obj
    eng.stop_process(name)


def ensure_root_or_reexec() -> None:
    """Sorgt dafür, dass Domainscriptor mit Root-Rechten läuft.

    - Wenn bereits Root → tue nichts
    """
    if os.geteuid() == 0:
        return  # schon root

    # Schutz vor Endlosschleife
    if os.environ.get("DOMAINSCRIPTOR_ELEVATED") == "1":
        typer.secho("❌ Konnte nicht auf Root-Rechte eskalieren.", fg=typer.colors.RED)
        raise typer.Exit()

    env = os.environ.copy()
    env["DOMAINSCRIPTOR_ELEVATED"] = "1"

    # sys.executable ist dein venv-Python
    cmd = ["sudo", sys.executable, "-m", "domainscriptor.main", *sys.argv[1:]]

    typer.secho(
        f"⚡ Starte Domainscriptor neu mit Root-Rechten ...", fg=typer.colors.YELLOW
    )
    os.execvpe("sudo", cmd, env)


@argument_handler.command()
def start():
    """
    Start the Domainscriptor engine and initialize adapters. This will prepare the DB and load configuration
    """
    typer.echo(f"Starting Domainscriptor ...")
    ensure_root_or_reexec()

    # Print Banner
    typer.echo(f"{info['banner']}")

    try:
        engine = Engine(argument_handler)
        engine.init_database_connection()
        engine.start_webui()
        if engine.created_new_db:
            engine.offer_reconnaissance()
    except RuntimeError as runtimeError:
        typer.secho(f"Error: {runtimeError.args[0]}", fg=typer.colors.RED)
        raise typer.Exit()

    adapters = {k: None for k in engine.show_adapters()}
    adapter_helps = engine.get_help_List()
    commands =      {
            "help": adapters,
            "version": adapters,
            "runcommand": None,
            "showadapters": None,
            "showprocesses": None,
            "showoutput": None,
            "reattach": None,
            "stopprocess": None,
            "fetch": {"byIp": None, "byToolname": None, "byProtocol": None, "search": None,
                      "hosts": None, "findings": None, "creds": None},
            "settings": {"add": None, "delete": None, "default": None},
            "shortcuts": {"get_relayable": None, "get_dc": None, "smb_check": None, "ldap_check": None,
                          "list_shares": None, "hunt_creds": None, "diff_shares": None,
                          "collect_ad": None},
            "targets": None,
            "relayable": None,
            "ai": {"suggest": None, "analyze": None},
            "report": {"markdown": None, "html": None, "json": None},
            "config": {"show": None, "init": None},
        }
    base_completer = NestedCompleter.from_nested_dict(commands)
    runcommand_completer = RuncommandCompleter(adapter_helps)
    stopprocess_completer = StopProcessCompleter(engine.show_processes)#Wichtig hier Funktion übergeben
    command_completers = {
        "stopprocess": stopprocess_completer,
        "showoutput": JobNameCompleter("showoutput", engine.list_job_names),
        "reattach": JobNameCompleter("reattach", engine.list_job_names),
    }

    # Persistent command history so the arrow keys walk through all past commands
    # (and across restarts), not just the most recent one.
    history = None
    try:
        hist_path = Path(engine.config.path("log_dir")) / "prompt_history"
        hist_path.parent.mkdir(parents=True, exist_ok=True)
        history = FileHistory(str(hist_path))
    except OSError:
        history = None

    session = PromptSession(
        "domainscriptor> ",
        completer=MainCompleter(
            base_completer, runcommand_completer, command_completers,
        ),
        history=history,
    )
    with patch_stdout(raw=True):
        while True:
            try:
                command = session.prompt().strip()

                if command in {"exit", "quit"}:
                    if typer.confirm("Are you sure you want to close the program?", default=False):
                        engine.exit()
                        break
                    else:
                        continue
                if not command:
                    continue

                log_command(command, source="user")
                args = shlex.split(command)
                argument_handler(
                    args=args, standalone_mode=False, obj=engine, allow_extra_args=True
                )
            except KeyboardInterrupt:
                if typer.confirm("Are you sure you want to close the program?", default=False):
                    engine.exit()
                    break
                continue

            except EOFError:
                if typer.confirm("Are you sure you want to close the program?", default=False):
                    engine.exit()
                    break
                continue
            except click.exceptions.UsageError as exc:
                typer.secho(f"❌ Fehler: {exc.message}", fg=typer.colors.RED)
            except Exception as exc:
                get_logger("shell").exception("Unexpected error running command: %s", command)
                typer.secho(f"Unexpected error: {exc}", fg=typer.colors.RED)
                traceback.print_exc()


@argument_handler.command("runcommand", context_settings={"allow_extra_args": True})
def run_command(command: str, ctx: typer.Context):
    """
    Execute a command inside a specific adapter. Use this to run adapter-specific actions without starting a full workflow.

    Append '&' or pass 'background=true' to run the command in the background and
    keep working; view its output later with 'showoutput <job>'.
    """
    eng: Engine = ctx.obj
    args = list(ctx.args)

    background = False
    if "&" in args:
        background = True
        args = [a for a in args if a != "&"]

    kwargs = dict(a.split("=", 1) for a in args if "=" in a)
    bg_kw = kwargs.pop("background", None)
    if bg_kw is not None:
        background = str(bg_kw).strip().lower() in ("1", "true", "yes", "y", "on")

    # Interactive foreground runs attach so the user can press the detach key
    # (default Ctrl-G) to send the command to the background and keep working.
    eng.run_task(command, background=background, attach=not background, **kwargs)


@argument_handler.command("showoutput")
def show_output(ctx: typer.Context, name: str,
                lines: Annotated[int, typer.Argument()] = 40):
    """
    Show the last output lines of a background job (see 'showprocesses' for names).
    """
    eng: Engine = ctx.obj
    eng.show_job_output(name, max_lines=lines)


@argument_handler.command("reattach")
def reattach(ctx: typer.Context, name: str):
    """
    Re-attach to a running background job: stream its output live again (detach key
    detaches once more). If the job already finished, its full log is shown.
    """
    eng: Engine = ctx.obj
    eng.reattach_job(name)


@argument_handler.command(context_settings={"allow_extra_args": True})
def fetch(ctx: typer.Context,
          field: str = typer.Argument(None),
          value: Optional[str] = typer.Argument(None)):
    """
    Fetch and store data from adapters into the database (discovery/results). Typically used after 'start' or after running adapter commands.
    """
    eng: Engine = ctx.obj
    if field is None:
        page_output(eng.read_data())
    elif field == "hosts":
        page_output(eng.get_hosts_report())
    elif field == "findings":
        # optionaler value = Severity-Filter (info|low|medium|high|critical)
        page_output(eng.get_findings_report(severity=value or ""))
    elif field == "creds":
        page_output(eng.get_credentials_report())
    elif value:
        if field == "byIp":
            page_output(eng.read_data_ip(value))
        elif field == "byProtocol":
            page_output(eng.read_data_protocol(value))
        elif field == "byToolname":
            page_output(eng.read_data_tool(value))
        elif field == "search":
            page_output(eng.search_data(value))
        else:
            typer.echo("Invalid field or value not specified")
    else:
        typer.echo("Invalid field or value not specified")


@argument_handler.command(context_settings={"allow_extra_args": True})
def settings(
        ctx: typer.Context,
        field: Optional[str] = typer.Argument(
            None,
            help="add | delete | default (omit to list)"
        ),
        setting_id: Optional[str] = typer.Argument(
            None,
            help="Setting ID (for delete/default)"
        ),
):
    """
    Fetch, add and remove the current settings which are predefined user logins
    """
    eng: Engine = ctx.obj
    if field is None:
        typer.echo(eng.get_settings())
    elif field == "delete":
        if setting_id:
            table = eng.get_settings_by_id(setting_id)
            if typer.confirm(f"Following entry will be deleted:\n{table}\nAre you sure?"):
                eng.delete_setting(setting_id)
        else:
            typer.echo("Entry ID is required")
    elif field == "add":
        typer.echo(eng.add_settings())
    elif field == "default":
        if setting_id:
            eng.set_default_setting(setting_id)
            typer.echo(f"Setting {setting_id} is now the default credential.")
        else:
            typer.echo("Entry ID is required")
    else:
        typer.echo("Invalid field")


@argument_handler.command(context_settings={"allow_extra_args": True})
def shortcuts(ctx: typer.Context, field: str = typer.Argument(
    ...,
    help="get_dc | get_relayable | smb_check | ldap_check | list_shares | hunt_creds | diff_shares | collect_ad"),
              proxy: Optional[str] = typer.Argument(
                  False,
                  help="Set to use a relay/proxychains for authenticated checks"
              )):
    """
    Run shortcuts to simplify complex commands and run multiple commands at once
    """
    eng: Engine = ctx.obj
    if field == "get_dc":
        typer.echo("Getting dc and save it in dc.txt")
        typer.echo(eng.get_dcs())
    elif field == "get_relayable":
        typer.echo("Getting smb_relayable hosts and save it in smb_relayable.txt")
        typer.echo(eng.get_relayable())
    elif field == "smb_check":
        typer.echo("Checking smb host")
        typer.echo(eng.check_smb_security(proxy=proxy))

    elif field == "ldap_check":
        typer.echo("Checking ldap security")
        typer.echo(eng.check_ldap_security(proxy=proxy))
    elif field == "list_shares":
        typer.echo("Listing SMB shares")
        page_output(eng.list_shares())
    elif field == "hunt_creds":
        typer.echo("Hunting for credential-bearing documents on SMB shares")
        page_output(eng.hunt_smb_credentials())
    elif field == "diff_shares":
        typer.echo("Comparing share/file visibility across saved users")
        page_output(eng.diff_shares())
    elif field == "collect_ad":
        eng.collect_bloodhound()
    else:
        typer.echo("Entry ID is required")


@argument_handler.command()
def targets(ctx: typer.Context, parameter: Optional[str] = typer.Argument(
    None,
    help="'set' to (re)define targets (omit to list)"
), ):
    """
    Prints out the set targets
    """
    eng: Engine = ctx.obj
    if parameter is None:
        eng.get_targets()
    elif parameter == "set":
        eng.set_target()


@argument_handler.command()
def relayable(ctx: typer.Context):
    """
    Prints out the relayable targets
    """
    eng: Engine = ctx.obj
    eng.show_relayable()


@argument_handler.command(context_settings={"allow_extra_args": True})
def report(
    ctx: typer.Context,
    fmt: str = typer.Argument("markdown", help="markdown | html | json"),
    output: Optional[str] = typer.Argument(None, help="Optional output file path"),
    ai: bool = typer.Option(False, "--ai", help="Include AI analysis in the report"),
):
    """
    Export collected findings as a report (markdown | html | json).
    """
    eng: Engine = ctx.obj
    typer.echo(eng.export_report(fmt=fmt, output=output, include_ai=ai))


@argument_handler.command()
def config(
    ctx: typer.Context,
    action: str = typer.Argument("show", help="show | init"),
    path: Optional[str] = typer.Argument(None, help="Target path for 'init'"),
):
    """
    Show the effective configuration or write a sample config file ('init').
    """
    from domainscriptor.config import write_sample_config, get_config
    if action == "init":
        target = path or "domainscriptor.toml"
        written = write_sample_config(target)
        typer.secho(f"Sample config written to {written}", fg=typer.colors.GREEN)
        typer.echo("Edit it and restart Domainscriptor, or set DOMAINSCRIPTOR_CONFIG.")
    elif action == "show":
        eng: Engine = ctx.obj
        if eng is not None:
            typer.echo(eng.show_config())
        else:
            # Außerhalb der Shell (ohne Engine-Objekt): Config direkt laden.
            import json as _json
            typer.echo(_json.dumps(get_config().as_dict(), indent=2))
    else:
        typer.secho(f"Unknown action '{action}'. Use 'show' or 'init'.", fg=typer.colors.RED)


@argument_handler.command()
def ai(ctx: typer.Context, action: str = typer.Argument(..., help="suggest | analyze")):
    """
    AI-powered assistant. 'suggest' recommends next commands; 'analyze' scans findings for vulnerabilities.
    Requires OPENROUTER_API_KEY environment variable.
    """
    eng: Engine = ctx.obj
    try:
        if action == "suggest":
            typer.echo("Asking AI for next steps ...")
            typer.echo(eng.ai_suggest())
        elif action == "analyze":
            typer.echo("Asking AI to analyze findings ...")
            typer.echo(eng.ai_analyze())
        else:
            typer.secho(f"Unknown action '{action}'. Use 'suggest' or 'analyze'.", fg=typer.colors.RED)
    except RuntimeError as e:
        typer.secho(str(e), fg=typer.colors.RED)
