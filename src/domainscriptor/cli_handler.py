import os
import sys
import traceback
from typing import Annotated, Optional
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.patch_stdout import patch_stdout
import typer
import click
import shlex

from domainscriptor.engine import Engine
from . import project_info
from .cli_completioner import MainCompleter, RuncommandCompleter, StopProcessCompleter

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


@argument_handler.command()
def showAdapters(ctx: typer.Context):
    """
    List all registered adapters, including their name, type, and current status (enabled/disabled).
    """
    eng: Engine = ctx.obj
    typer.echo(f"{eng.show_adapters()}")


@argument_handler.command()
def showProcesses(ctx: typer.Context):
    """
    Show background processes started by Domainscriptor
    """
    eng: Engine = ctx.obj
    typer.echo(f"{eng.show_processes()}")


@argument_handler.command()
def stopProcess(ctx: typer.Context, name: str):
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
            "stopprocess": None,
            "fetch": {"byIp": None, "byToolname": None, "byProtocol": None, "search": None},
            "settings": {"add": None, "delete": None},
            "shortcuts": {"get_relayable": None, "get_dc": None, "smb_check": None, "ldap_check": None},
            "targets": None,
            "relayable": None,
            "ai": {"suggest": None, "analyze": None},
        }
    base_completer = NestedCompleter.from_nested_dict(commands)
    runcommand_completer = RuncommandCompleter(adapter_helps)
    stopprocess_completer = StopProcessCompleter(engine.show_processes)#Wichtig hier Funktion übergeben
    session = PromptSession(
        "domainscriptor> ",
        completer=MainCompleter(base_completer,runcommand_completer,stopprocess_completer),
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
                typer.secho(f"Unknow Error happen", fg=typer.colors.RED)
                typer.secho(f"{traceback.print_exc()}", fg=typer.colors.RED)


@argument_handler.command(context_settings={"allow_extra_args": True})
def runCommand(command: str, ctx: typer.Context):
    """
    Execute a command inside a specific adapter. Use this to run adapter-specific actions without starting a full workflow.
    """
    eng: Engine = ctx.obj
    kwargs = dict(a.split("=", 1) for a in ctx.args if "=" in a)
    eng.run_task(command, **kwargs)


@argument_handler.command(context_settings={"allow_extra_args": True})
def fetch(ctx: typer.Context,
          field: str = typer.Argument(None),
          value: Optional[str] = typer.Argument(None)):
    """
    Fetch and store data from adapters into the database (discovery/results). Typically used after 'start' or after running adapter commands.
    """
    eng: Engine = ctx.obj
    if field is None:
        typer.echo(eng.read_data())
    elif value:
        if field == "byIp":
            typer.echo(eng.read_data_ip(value))
        elif field == "byProtocol":
            typer.echo(eng.read_data_protocol(value))
        elif field == "byToolname":
            typer.echo(eng.read_data_tool(value))
        elif field == "search":
            typer.echo(eng.search_data(value))
    else:
        typer.echo("Invalid field or value not specified")


@argument_handler.command(context_settings={"allow_extra_args": True})
def settings(
        ctx: typer.Context,
        field: Optional[str] = typer.Argument(
            None,
            help="delete"
        ),
        setting_id: Optional[str] = typer.Argument(
            None,
            help="Value for the field"
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
    else:
        typer.echo("Invalid field")


@argument_handler.command(context_settings={"allow_extra_args": True})
def shortcuts(ctx: typer.Context, field: str = typer.Argument(
    ...,
    help="delete"),
              proxy: Optional[str] = typer.Argument(
                  False,
                  help="Value for the field"
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
    else:
        typer.echo("Entry ID is required")


@argument_handler.command()
def targets(ctx: typer.Context, parameter: Optional[str] = typer.Argument(
    None,
    help="delete"
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
