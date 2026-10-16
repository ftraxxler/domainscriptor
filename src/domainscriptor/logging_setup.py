"""Zentrales Logging für Domainscriptor.

Konfiguriert zwei rotierende Logdateien im konfigurierten ``log_dir``:

* ``domainscriptor.log`` – Anwendungs-Events, Warnungen und Fehler der App selbst.
* ``commands.log``       – jeder ausgeführte Befehl (Shell-Eingabe und das
                           tatsächlich gestartete externe Tool-Kommando inkl. Exitcode).

Credentials (Passwörter, Hashes) werden vor dem Schreiben maskiert – ein
Pentest-Tool darf keine Klartext-Zugangsdaten in Logdateien ablegen.

Logging darf die App niemals zum Absturz bringen: Setup-Fehler (z. B. nicht
beschreibbares Verzeichnis) werden still verschluckt.
"""
from __future__ import annotations

import logging
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Iterable, Union

APP_LOGGER = "domainscriptor"
COMMAND_LOGGER = "domainscriptor.commands"

_MAX_BYTES = 2_000_000
_BACKUP_COUNT = 5

# Flags, deren nachfolgender Wert ein Geheimnis ist (positional).
_SENSITIVE_FLAGS = {"-p", "--password", "-H", "--hashes", "--hash"}
# Keys in key=value-Form, deren Wert maskiert wird.
_SENSITIVE_KV_RE = re.compile(
    r"\b(password|passwort|pass|hashes?|ntlm|secret)(\s*=\s*)(\S+)", re.IGNORECASE
)
_REDACTED = "***"

_configured = False


def redact_command(cmd: Union[str, Iterable]) -> str:
    """Return a loggable string with passwords/hashes masked.

    Accepts either an argv list (``["nxc", "-p", "secret"]``) or a raw command
    string (``"runcommand nxc password=secret"``).
    """
    if isinstance(cmd, (list, tuple)):
        out = []
        mask_next = False
        for tok in cmd:
            tok = str(tok)
            if mask_next:
                out.append(_REDACTED)
                mask_next = False
                continue
            if tok in _SENSITIVE_FLAGS:
                out.append(tok)
                mask_next = True
                continue
            out.append(_SENSITIVE_KV_RE.sub(rf"\1\2{_REDACTED}", tok))
        return " ".join(out)
    return _SENSITIVE_KV_RE.sub(rf"\1\2{_REDACTED}", str(cmd))


def setup_logging(log_dir, level: str = "INFO") -> None:
    """Configure the app and command loggers. Idempotent and failure-safe."""
    global _configured

    try:
        log_dir = Path(log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return  # never let logging setup break the app

    lvl = getattr(logging, str(level).upper(), logging.INFO)

    app_logger = logging.getLogger(APP_LOGGER)
    app_logger.setLevel(lvl)
    cmd_logger = logging.getLogger(COMMAND_LOGGER)
    cmd_logger.setLevel(logging.INFO)
    cmd_logger.propagate = False  # commands go only to commands.log

    if _configured:
        return

    try:
        app_handler = RotatingFileHandler(
            log_dir / "domainscriptor.log",
            maxBytes=_MAX_BYTES, backupCount=_BACKUP_COUNT, encoding="utf-8",
        )
        app_handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-7s %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S",
        ))
        app_logger.addHandler(app_handler)

        cmd_handler = RotatingFileHandler(
            log_dir / "commands.log",
            maxBytes=_MAX_BYTES, backupCount=_BACKUP_COUNT, encoding="utf-8",
        )
        cmd_handler.setFormatter(logging.Formatter(
            "%(asctime)s %(message)s", "%Y-%m-%d %H:%M:%S",
        ))
        cmd_logger.addHandler(cmd_handler)
    except OSError:
        return

    _configured = True
    app_logger.info(
        "Logging initialized (level=%s, dir=%s)", logging.getLevelName(lvl), log_dir
    )


def get_logger(name: str | None = None) -> logging.Logger:
    """Return the app logger, or a child logger ``domainscriptor.<name>``."""
    return logging.getLogger(f"{APP_LOGGER}.{name}" if name else APP_LOGGER)


def log_command(cmd, source: str = "exec", adapter: str | None = None) -> None:
    """Log an executed command (secrets redacted) to commands.log."""
    prefix = f"[{source}]"
    if adapter:
        prefix += f"[{adapter}]"
    logging.getLogger(COMMAND_LOGGER).info("%s %s", prefix, redact_command(cmd))


def log_command_result(adapter: str, returncode, source: str = "exec") -> None:
    """Log the exit status of an executed command to commands.log."""
    logging.getLogger(COMMAND_LOGGER).info(
        "[%s][%s] exit=%s", source, adapter, returncode
    )
