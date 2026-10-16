"""Zentrale Konfiguration für Domainscriptor.

Lädt Einstellungen aus einer TOML-Datei und erlaubt Overrides per Umgebungsvariable.
Suchreihenfolge für die Config-Datei:

  1. Pfad aus ``DOMAINSCRIPTOR_CONFIG``
  2. ``./domainscriptor.toml`` (Arbeitsverzeichnis)
  3. ``~/.config/domainscriptor/config.toml``

Hinweis: Domainscriptor eskaliert sich via ``sudo`` auf Root. Dadurch wird ``~``
zu ``/root``. Für eine benutzerspezifische Config ist daher die projekt-lokale
``./domainscriptor.toml`` (oder ``DOMAINSCRIPTOR_CONFIG``) zuverlässiger.
"""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field, asdict, fields, is_dataclass
from pathlib import Path
from typing import Optional

CONFIG_ENV = "DOMAINSCRIPTOR_CONFIG"


@dataclass
class PathsConfig:
    work_dir: str = "."
    db_dir: str = "."
    targets_file: str = "targets.txt"
    relayable_file: str = "smb_relayable.txt"
    dc_file: str = "dc_ips.txt"
    loot_dir: str = "loot"
    report_dir: str = "reports"
    log_dir: str = "logs"


@dataclass
class LoggingConfig:
    level: str = "INFO"


@dataclass
class WebConfig:
    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 5000


@dataclass
class AIConfig:
    provider: str = "openrouter"
    model: str = ""


@dataclass
class ToolsConfig:
    responder_log: str = "/usr/share/responder/logs/Responder-Session.log"
    default_timeout: int = 300


@dataclass
class Config:
    paths: PathsConfig = field(default_factory=PathsConfig)
    web: WebConfig = field(default_factory=WebConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    tools: ToolsConfig = field(default_factory=ToolsConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)

    # ── Pfad-Helfer ─────────────────────────────────────────────────────────
    def path(self, name: str) -> Path:
        """Gibt einen in ``paths`` konfigurierten Dateinamen als absoluten Pfad
        relativ zum ``work_dir`` zurück (z. B. ``config.path("targets_file")``)."""
        value = getattr(self.paths, name)
        p = Path(value)
        if p.is_absolute():
            return p
        return (Path(self.paths.work_dir) / p).resolve()

    def as_dict(self) -> dict:
        return asdict(self)


def _coerce_section(section_cls, data: dict):
    """Baut eine Section-Dataclass, ignoriert unbekannte Keys und castet Typen grob."""
    kwargs = {}
    for f in fields(section_cls):
        if f.name not in data:
            continue
        value = data[f.name]
        if f.type in ("int", int) and not isinstance(value, bool):
            try:
                value = int(value)
            except (TypeError, ValueError):
                continue
        elif f.type in ("bool", bool):
            value = _as_bool(value)
        kwargs[f.name] = value
    return section_cls(**kwargs)


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def find_config_path() -> Optional[Path]:
    explicit = os.environ.get(CONFIG_ENV)
    if explicit:
        p = Path(explicit).expanduser()
        return p if p.exists() else None

    candidates = [
        Path.cwd() / "domainscriptor.toml",
        Path.home() / ".config" / "domainscriptor" / "config.toml",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def _apply_env_overrides(cfg: Config) -> None:
    env = os.environ
    if "DOMAINSCRIPTOR_WORK_DIR" in env:
        cfg.paths.work_dir = env["DOMAINSCRIPTOR_WORK_DIR"]
    if "DOMAINSCRIPTOR_DB_DIR" in env:
        cfg.paths.db_dir = env["DOMAINSCRIPTOR_DB_DIR"]
    if "DOMAINSCRIPTOR_WEB_HOST" in env:
        cfg.web.host = env["DOMAINSCRIPTOR_WEB_HOST"]
    if "DOMAINSCRIPTOR_WEB_PORT" in env:
        try:
            cfg.web.port = int(env["DOMAINSCRIPTOR_WEB_PORT"])
        except ValueError:
            pass
    if "DOMAINSCRIPTOR_WEB_ENABLED" in env:
        cfg.web.enabled = _as_bool(env["DOMAINSCRIPTOR_WEB_ENABLED"])
    if "DOMAINSCRIPTOR_RESPONDER_LOG" in env:
        cfg.tools.responder_log = env["DOMAINSCRIPTOR_RESPONDER_LOG"]
    if "DOMAINSCRIPTOR_LOG_DIR" in env:
        cfg.paths.log_dir = env["DOMAINSCRIPTOR_LOG_DIR"]
    if "DOMAINSCRIPTOR_LOG_LEVEL" in env:
        cfg.logging.level = env["DOMAINSCRIPTOR_LOG_LEVEL"].upper()
    # AI: AI_PROVIDER wird auch direkt vom ai_client gelesen – hier für Konsistenz.
    if "AI_PROVIDER" in env:
        cfg.ai.provider = env["AI_PROVIDER"].lower()


def load_config(path: Optional[Path] = None) -> Config:
    """Lädt die Konfiguration (Defaults < TOML-Datei < Umgebungsvariablen)."""
    cfg = Config()
    path = path or find_config_path()

    if path and path.exists():
        try:
            with open(path, "rb") as f:
                raw = tomllib.load(f)
        except (OSError, tomllib.TOMLDecodeError):
            raw = {}
        if isinstance(raw.get("paths"), dict):
            cfg.paths = _coerce_section(PathsConfig, raw["paths"])
        if isinstance(raw.get("web"), dict):
            cfg.web = _coerce_section(WebConfig, raw["web"])
        if isinstance(raw.get("ai"), dict):
            cfg.ai = _coerce_section(AIConfig, raw["ai"])
        if isinstance(raw.get("tools"), dict):
            cfg.tools = _coerce_section(ToolsConfig, raw["tools"])
        if isinstance(raw.get("logging"), dict):
            cfg.logging = _coerce_section(LoggingConfig, raw["logging"])

    _apply_env_overrides(cfg)
    return cfg


_CACHED: Optional[Config] = None


def get_config(reload: bool = False) -> Config:
    """Prozessweit gecachte Konfiguration."""
    global _CACHED
    if _CACHED is None or reload:
        _CACHED = load_config()
    return _CACHED


SAMPLE_CONFIG = """\
# Domainscriptor Konfiguration
# Speichern als ./domainscriptor.toml oder ~/.config/domainscriptor/config.toml
# (oder Pfad via DOMAINSCRIPTOR_CONFIG setzen).

[paths]
work_dir      = "."                 # Basisverzeichnis für alle Ausgabedateien
db_dir        = "."                 # Ablage der .db-Dateien
targets_file  = "targets.txt"
relayable_file = "smb_relayable.txt"
dc_file       = "dc_ips.txt"
loot_dir      = "loot"
report_dir    = "reports"
log_dir       = "logs"              # domainscriptor.log + commands.log

[logging]
level = "INFO"                      # DEBUG | INFO | WARNING | ERROR

[web]
enabled = true
host    = "127.0.0.1"
port    = 5000

[ai]
provider = "openrouter"             # openrouter | anthropic | openai
model    = ""                        # leer = Provider-Default

[tools]
responder_log   = "/usr/share/responder/logs/Responder-Session.log"
default_timeout = 300
"""


def write_sample_config(path: Path) -> Path:
    path = Path(path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(SAMPLE_CONFIG, encoding="utf-8")
    return path
