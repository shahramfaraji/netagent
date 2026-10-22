"""Optional tool installation, only with explicit user consent.

netagent never installs anything silently. Before any install it prints the exact command
and waits for a typed "y"/"yes". Installs go through the platform package manager
(winget / brew / apt-get / dnf) or pip -- netagent never downloads and runs an installer
itself. Nothing is installed when stdin/stderr is not a terminal or NETAGENT_NO_INSTALL is set.
"""
from __future__ import annotations

import importlib
import importlib.util
import logging
import os
import shutil
import subprocess
import sys
from typing import Callable

log = logging.getLogger(__name__)

NETMIKO_REQUIREMENT = "netmiko>=4.3"
_declined: set[str] = set()  # ask at most once per tool per run


def _interactive() -> bool:
    if os.environ.get("NETAGENT_NO_INSTALL"):
        return False
    try:
        return sys.stdin.isatty() and sys.stderr.isatty()
    except (AttributeError, ValueError):
        return False


def confirm(question: str) -> bool:
    """Ask on stderr (stdout may carry JSON). Anything but y/yes, or no terminal, means no."""
    if not _interactive():
        return False
    print(f"{question} [y/N] ", end="", file=sys.stderr, flush=True)
    try:
        answer = input()
    except EOFError:
        return False
    return answer.strip().lower() in {"y", "yes"}


def _display(command: list[str]) -> str:
    return subprocess.list2cmdline(command)


def _run_install(command: list[str], run: Callable) -> bool:
    try:
        return run(command, check=False).returncode == 0
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("Install command failed to run (%s)", type(exc).__name__)
        return False


def find_nmap() -> str | None:
    exe = shutil.which("nmap")
    if exe:
        return exe
    if sys.platform == "win32":  # a fresh install is not on this process's PATH yet
        for var in ("ProgramFiles", "ProgramFiles(x86)"):
            base = os.environ.get(var)
            candidate = os.path.join(base, "Nmap", "nmap.exe") if base else ""
            if candidate and os.path.isfile(candidate):
                return candidate
    return None


def nmap_install_command() -> list[str] | None:
    if sys.platform == "win32":
        return ["winget", "install", "--id", "Insecure.Nmap", "--exact"] if shutil.which("winget") else None
    if sys.platform == "darwin":
        return ["brew", "install", "nmap"] if shutil.which("brew") else None
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    if is_root:
        prefix: list[str] = []
    elif shutil.which("sudo"):
        prefix = ["sudo"]
    else:
        return None
    if shutil.which("apt-get"):
        return [*prefix, "apt-get", "install", "-y", "nmap"]
    if shutil.which("dnf"):
        return [*prefix, "dnf", "install", "-y", "nmap"]
    return None


def ensure_nmap(ask: Callable[[str], bool] | None = None, run: Callable | None = None) -> str | None:
    """Return the nmap path, offering to install it (with consent) when missing."""
    exe = find_nmap()
    if exe or "nmap" in _declined:
        return exe
    command = nmap_install_command()
    if command is None:
        log.warning("Nmap is not installed and no supported package manager was found; "
                    "see https://nmap.org/download.html")
        return None
    ask = ask or confirm
    if not ask(f"Nmap is not installed. Install it now with: {_display(command)}?"):
        _declined.add("nmap")
        return None
    if not _run_install(command, run or subprocess.run):
        _declined.add("nmap")
        log.warning("Nmap installation did not complete")
        return None
    return find_nmap()


def ensure_netmiko(ask: Callable[[str], bool] | None = None, run: Callable | None = None) -> bool:
    """Return True when netmiko is importable, offering a pip install (with consent) if not."""
    if importlib.util.find_spec("netmiko") is not None:
        return True
    if "netmiko" in _declined:
        return False
    command = [sys.executable, "-m", "pip", "install", NETMIKO_REQUIREMENT]
    ask = ask or confirm
    question = ("Netmiko (needed for SSH) is not installed. Install it into this Python "
                f"environment with: {_display(command)}?")
    if not ask(question):
        _declined.add("netmiko")
        return False
    if not _run_install(command, run or subprocess.run):
        _declined.add("netmiko")
        log.warning("Netmiko installation did not complete")
        return False
    importlib.invalidate_caches()
    return importlib.util.find_spec("netmiko") is not None
