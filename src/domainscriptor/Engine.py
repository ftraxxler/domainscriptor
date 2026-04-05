from datetime import datetime
import re

from queue import Queue
from pathlib import Path
from typing import List, Tuple

import typer
from domainscriptor.Runner import Runner
from domainscriptor.automations import *
from domainscriptor.adapters_registry.adapters.ntlmrelayx import NTLMRelayAdapter
from domainscriptor.adapters_registry.adapters.nxc import NXCAdapter
from domainscriptor.adapters_registry.adapters.proxychains import ProxychainsAdapter
from domainscriptor.adapters_registry.adapters.responder import ResponderAdapter
from domainscriptor.adapters_registry.adapters.smbexec import SMBExecAdapter
from domainscriptor.adapters_registry.adapters.smbclient import SMBClientAdapter
from domainscriptor.adapters_registry.base import Adapter
from domainscriptor.adapters_registry.registry import Adapter_Registry
from domainscriptor.data.canonical_db import SettingsDataModel
from domainscriptor.data.db_reader import DBReader
from domainscriptor.data.db_writer import DBWriter


def _return_file_content(name, max_lines=15):
    preview = []

    with open(name, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            if i < max_lines:
                preview.append(line)
            else:
                preview.append("\n... file continuous ...\n")
                break

    return "".join(preview)


def _pretty_format_settings(settings: List[Tuple[str, SettingsDataModel]]):
    if not settings:
        return "No entries found."

    headers = ["ID", "Domain", "User", "PW"]
    rows = []
    for setting_id, setting in settings:
        rows.append([
            str(setting_id),
            setting.domain,
            setting.username,
            setting.password
        ])

    col_widths = []
    for col in range(len(headers)):
        max_width = max(
            len(headers[col]),
            max(len(row[col]) for row in rows)
        )
        col_widths.append(max_width)

    header_line = " | ".join(
        headers[i].ljust(col_widths[i]) for i in range(len(headers))
    )

    separator = "-+-".join(
        "-" * col_widths[i] for i in range(len(headers))
    )

    row_lines = []
    for row in rows:
        line = " | ".join(
            row[i].ljust(col_widths[i]) for i in range(len(headers))
        )
        row_lines.append(line)

    table = "\n".join([header_line, separator] + row_lines)

    return table


class Engine:
    def __init__(self, argument_handler):
        self.argument_handler = argument_handler
        self.adapter_registry: Adapter_Registry = Adapter_Registry()
        self.runner = Runner()
        self.queue = None
        self.db_writer: DBWriter = None
        self.db_reader: DBReader = None
        self.load_adapters()

    def load_adapters(self):
        self.adapter_registry.register(ResponderAdapter)
        self.adapter_registry.register(SMBExecAdapter)
        self.adapter_registry.register(SMBClientAdapter)
        self.adapter_registry.register(NTLMRelayAdapter)
        self.adapter_registry.register(NXCAdapter)
        self.adapter_registry.register(ProxychainsAdapter)

    def init_database_connection(self, db_dir: str = "."):
        self.queue = Queue()
        db_dir = Path(db_dir)
        db_dir.mkdir(parents=True, exist_ok=True)

        db_files = list(db_dir.glob("*.db"))
        db_path = self._choose_database(db_files, db_dir)
        new_db = not db_path.exists()
        db_writer = DBWriter(db_path, self.queue)
        if new_db:
            settings = None
            if typer.confirm("Do you want to set initial settings?"):
                settings = self._init_setting()
            self._set_target()
            db_writer.init_database(settings)

        db_writer.start()
        self.db_writer = db_writer
        self.db_reader = DBReader(db_path)

    def create_adapter(self, name: str, **cfg) -> Adapter:
        return self.adapter_registry.create(name, **cfg)

    def show_adapters(self):
        return self.adapter_registry.list_names()

    def get_help_List(self):
        adapters = self.adapter_registry._adapters

        helps = {}
        for key, value in adapters.items():
            helps[key] = value.help_List

        return helps

    def show_adapter_help(self, adapter_name: str):
        kwargs = {}
        adapter = self.create_adapter(adapter_name, **kwargs)
        return adapter.help()

    def show_adapter_version(self, adapter_name: str):
        kwargs = {}
        adapter = self.create_adapter(adapter_name, **kwargs)
        return adapter.version()

    def show_processes(self):
        return self.runner.show_processes()

    def stop_process(self, name: str):
        return self.runner.stop_tool(name)

    def exit(self):
        self.runner.stop_all()
        self.queue.join()
        self.db_writer.stop()
        self.db_writer.join()

    def write_data(self, data):
        self.db_writer.submit_canonical_data(data)

    def read_data(self):
        return self.db_reader.fetch_all()

    def read_data_ip(self, ip):
        return self.db_reader.get_by_ip(ip)

    def read_data_protocol(self, protocol):
        return self.db_reader.get_by_protocol(protocol)

    def read_data_tool(self, tool):
        return self.db_reader.get_by_tool(tool)

    def search_data(self, search):
        return self.db_reader.search_in_data(search)

    def get_settings(self):
        return _pretty_format_settings(self.db_reader.fetch_settings())

    def get_settings_by_id(self, id):
        return _pretty_format_settings(self.db_reader.get_settings_by_id(id))

    def add_settings(self):
        settings = self._init_setting()
        self.db_writer.submit_setting(settings)

    def delete_setting(self, setting_id: str):
        self.db_writer.delete_setting(setting_id)

    def get_default_Credentials(self):
        # TODO value default in DB
        setting_list = self.db_reader.fetch_settings()
        settings=None
        if setting_list:
            idx, settings = setting_list[0]
        return settings

    def run_task(self, adapter_name: str, return_output=False, **kwargs):
        try:
            adapter = self.create_adapter(adapter_name, **kwargs.pop("adapter_config", {}))
            #typer.echo(f"Logging Command: {kwargs}")
            default_settings = self.get_default_Credentials()
            # typer.echo(f"Default Settings {default_settings}")
            data = adapter.run(self.runner, self.queue, auth=default_settings, **kwargs)
            if data:
                # typer.echo(f"Logging normalized Data: {data}")
                self.write_data(data)
                if return_output:
                    return data
        except RuntimeError as e:
            typer.echo(typer.style(str(e), fg=typer.colors.RED, bold=True))
        except TypeError as e:
            typer.echo(typer.style(str(e), fg=typer.colors.RED, bold=True))

    def get_dcs(self):
        if self._check_adapter_exists("nxc") and self.get_default_Credentials():
            ip = typer.prompt("Enter IP for DC check")
            result = self.run_task("nxc", return_output=True,
                                   **{'protocol': 'ldap', 'target': ip, 'extra_args': '--dc-list'})
            result = result[0]
            ips = []
            for entry in result.data:
                for ip in re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", entry["message"]):
                    if ip not in ips:
                        ips.append(ip)

            typer.echo(f"IPS {ips}")

        else:
            pass

        with open("dc_ips.txt", "w", encoding="utf-8") as f:
            for ip in ips:
                f.write(ip + "\n")

    def get_relayable(self):
        if self._check_adapter_exists("nxc"):
            self.run_task("nxc", **{'targets_file': 'targets.txt', 'extra_args': '--gen-relay-list smb_relayable.txt'})
            result = _return_file_content("smb_relayable.txt")
            return f"SMB-Relayable:\n{result}"

        return "Adapter does not exist"

    def check_smb_security(self, ip=None,proxy=False):
        relay = self._get_available_relays()
        if self._check_adapter_exists("nxc"):
            if not ip:
                ip = typer.prompt("Enter IP to check")

            for checks in get_smb_security_commands():
                parameters = checks["parameters"]
                parameters["target"] = ip
                if proxy and relay and checks["creds_required"]:
                    parameters["proxy"] = str(proxy)
                    domain,username = relay.user.split("/")
                    parameters["domain"]=domain
                    parameters["username"]=username
                result = self.run_task("nxc", **parameters)

    def check_ldap_security(self, ip=None,proxy=False):
        relay = self._get_available_relays()
        if self._check_adapter_exists("nxc"):
            if not ip:
                ip = typer.prompt("Enter IP to check")

            for checks in get_ldap_security_commands():
                parameters = checks["parameters"]
                parameters["target"] = ip
                if proxy and relay and checks["creds_required"]:
                    parameters["proxy"] = str(proxy)
                    domain, username = relay.user.split("/")
                    parameters["domain"] = domain
                    parameters["username"] = username
                result = self.run_task("nxc", **parameters)

    def _choose_database(self, db_files, db_dir):
        if db_files:
            typer.echo("Existing databases found:\n")
            for i, db in enumerate(db_files, start=1):
                typer.echo(f"{i}. {db.name}")

            typer.echo("0. Create new database")

            choice = typer.prompt("Select database", type=int)

            if choice == 0:
                return self._create_new_db_name(db_dir)
            elif 1 <= choice <= len(db_files):
                return db_files[choice - 1]
            else:
                typer.echo("Invalid choice. Creating new database.")
                return self._create_new_db_name(db_dir)
        else:
            typer.echo("No database found. Creating a new one.")
            return self._create_new_db_name(db_dir)

    def _create_new_db_name(self, db_dir):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        new_name = f"domainscriptor_{timestamp}.db"
        return db_dir / new_name

    def _init_setting(self):
        settings = []
        while True:
            typer.echo("The following settings can be set Domain, Username and Passwort")
            domain = typer.prompt("Domain")
            username = typer.prompt("Username")
            password = typer.prompt("Password")
            settings_data = SettingsDataModel(domain, username, password)
            settings.append(settings_data)

            if not typer.confirm("Do you want to add other user?"):
                break

        typer.echo(f"Settings created for {settings}")
        return settings

    def _set_target(self):
        typer.echo("Set the target IP ranges Format X.X.X.X(/Y) (separate by ,)")
        targets = typer.prompt("Targets")
        targets = targets.split(",")
        with open("targets.txt", "w") as f:
            for target in targets:
                f.write(target.strip() + "\n")

    def _check_adapter_exists(self, adapter_name):
        return adapter_name in self.adapter_registry.list_names()


    def _get_available_relays(self):
        relays = self.runner.get_relays()
        if relays:
            typer.echo(f"Found {len(relays)} relays")
            typer.echo(f"Relays: {relays}")
        if not typer.confirm("Do you want to use a relay?"):
            return None
        else:
            index = 1
            for relay in relays:
                typer.echo(f"ID: {index} IP: {relay.ip} User: {relay.user} Admin: {relay.admin_status} ")
                index += 1
            index = typer.prompt(f"Select relay", type=int)
            return relays[index-1]
