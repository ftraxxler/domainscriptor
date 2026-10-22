"""Terminal UI helpers: nxc-style ANSI colors, a pager for long output, and a
raw-mode key reader used to detach a running job with a configurable key
(default Ctrl-G) instead of Ctrl-Z/SIGTSTP (which zsh and job control grab).

Everything here degrades gracefully when stdout/stdin is not a TTY.
"""
from __future__ import annotations

import os
import select
import shlex
import shutil
import subprocess
import sys
from typing import Optional

try:  # POSIX only; absent on non-tty / Windows
    import termios
    import tty
except ImportError:  # pragma: no cover
    termios = None
    tty = None


# ── Colors (nxc-style) ───────────────────────────────────────────────────────

_CODES = {
    "red": "31", "green": "32", "yellow": "33", "blue": "34",
    "magenta": "35", "cyan": "36", "white": "37", "grey": "90",
    "bold": "1", "dim": "2",
}


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    try:
        return os.isatty(1)
    except OSError:
        return False


COLOR_ENABLED = _supports_color()


def color(text, *styles, force: Optional[bool] = None) -> str:
    """Wrap ``text`` in ANSI style codes (no-op when color is disabled)."""
    on = COLOR_ENABLED if force is None else force
    text = str(text)
    if not on or not styles:
        return text
    codes = ";".join(_CODES[s] for s in styles if s in _CODES)
    if not codes:
        return text
    return f"\033[{codes}m{text}\033[0m"


def status_tag(ok: bool) -> str:
    """nxc-style ``[+]`` (green) / ``[-]`` (red) marker."""
    return color("[+]", "green", "bold") if ok else color("[-]", "red", "bold")


# ── Pager (mouse-wheel scrollback for long output) ─────────────────────────────

def stdout_is_tty() -> bool:
    """Whether real terminal output is available.

    ``sys.stdout`` is unreliable here: inside prompt_toolkit's ``patch_stdout``
    it is swapped for a proxy whose ``isatty()`` is False even in a real
    terminal, which would wrongly disable the pager. The OS-level fd 1 is not
    touched by that patch, so check it directly.
    """
    for probe in (1, sys.__stdout__, sys.stdout):
        try:
            if isinstance(probe, int):
                return os.isatty(probe)
            if probe is not None and probe.isatty():
                return True
        except (AttributeError, ValueError, OSError):
            continue
    return False


def page_output(text, pager_cmd: Optional[str] = None,
                min_lines: Optional[int] = None) -> None:
    """Print ``text``; if it is taller than the terminal, show it through a pager
    (``less -R`` by default) so it can be scrolled with the mouse wheel / keys.

    Falls back to a plain print when stdout is not a TTY, the text is short, or
    the pager cannot be launched.
    """
    if text is None:
        return
    text = str(text)

    if not stdout_is_tty():
        print(text)
        return

    rows = shutil.get_terminal_size((80, 24)).lines
    threshold = min_lines if min_lines is not None else max(rows - 2, 10)
    if text.count("\n") + 1 <= threshold:
        print(text)
        return

    if pager_cmd is None:
        try:
            from .config import get_config
            pager_cmd = get_config().tools.pager
        except Exception:
            pager_cmd = "less -R"
    if not pager_cmd:
        print(text)
        return

    try:
        env = os.environ.copy()
        # R: keep ANSI colors. Full-screen less (no -F/-X) so PgUp/PgDn/arrows and
        # the mouse wheel all scroll — the whole point of paging here.
        env["LESS"] = "R"
        proc = subprocess.Popen(shlex.split(pager_cmd), stdin=subprocess.PIPE,
                                text=True, env=env)
        proc.communicate(text)
    except (OSError, ValueError, BrokenPipeError):
        print(text)
    except KeyboardInterrupt:
        # q / Ctrl-C out of the pager: swallow so it doesn't bubble to the shell.
        pass


# ── Detach key (replaces Ctrl-Z / SIGTSTP) ─────────────────────────────────────

def parse_key_spec(spec: Optional[str]) -> bytes:
    """Turn a config value like ``ctrl-g`` or ``q`` into the raw byte it produces."""
    spec = (spec or "").strip().lower()
    if spec.startswith("ctrl-") and len(spec) == 6 and spec[5].isalpha():
        return bytes([ord(spec[5].upper()) - 64])  # ctrl-a -> 0x01, ctrl-g -> 0x07
    if len(spec) == 1:
        return spec.encode()
    return b"\x07"  # default: Ctrl-G


def key_display(spec: Optional[str]) -> str:
    """Human-readable name for messages, e.g. ``ctrl-g`` -> ``Ctrl-G``."""
    spec = (spec or "").strip().lower()
    if spec.startswith("ctrl-") and len(spec) == 6:
        return f"Ctrl-{spec[5].upper()}"
    if len(spec) == 1:
        return spec.upper()
    return "Ctrl-G"


class DetachKeyReader:
    """Context manager that puts stdin in cbreak mode and lets you poll for a
    single detach key without blocking. No-op when stdin is not a TTY, so
    non-interactive runs simply stream to completion.
    """

    def __init__(self, detach_bytes: bytes):
        self.detach = detach_bytes
        self.fd: Optional[int] = None
        self._old = None

    def __enter__(self) -> "DetachKeyReader":
        if termios is None:
            return self
        try:
            fd = sys.stdin.fileno()
            if not os.isatty(fd):
                return self
            self._old = termios.tcgetattr(fd)
            tty.setcbreak(fd)
            self.fd = fd
        except (ValueError, OSError, termios.error):
            self.fd = None
        return self

    def pressed(self) -> bool:
        """True if the detach key is waiting in the input buffer (non-blocking)."""
        if self.fd is None:
            return False
        try:
            ready, _, _ = select.select([self.fd], [], [], 0)
            if not ready:
                return False
            ch = os.read(self.fd, 1)
            return ch == self.detach
        except (OSError, ValueError):
            return False

    def __exit__(self, *exc) -> None:
        if self.fd is not None and self._old is not None:
            try:
                termios.tcsetattr(self.fd, termios.TCSADRAIN, self._old)
            except (ValueError, OSError, termios.error):
                pass
