"""SSH config collection (Netmiko, read-only commands) and versioned storage with diffs."""
from __future__ import annotations

import difflib
import hashlib
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from .credentials import Credential, redact
from .models import Device

log = logging.getLogger(__name__)

SHOW_CONFIG = {
    "cisco_ios": "show running-config",
    "cisco_nxos": "show running-config",
    "cisco_asa": "show running-config",
    "arista_eos": "show running-config",
    "juniper_junos": "show configuration | display set",
    "fortinet": "show full-configuration",
    "mikrotik_routeros": "/export",
}
SHOW_NEIGHBORS = {
    "cisco_ios": "show cdp neighbors detail",
    "cisco_nxos": "show cdp neighbors detail",
    "arista_eos": "show lldp neighbors detail",
    "juniper_junos": "show lldp neighbors",
}
# Lines that change every fetch and would create noisy diffs
VOLATILE = [re.compile(p) for p in (r"^! Last configuration change", r"^! NVRAM config last updated",
                                     r"^ntp clock-period", r"^Current configuration :", r"^## Last commit")]


def normalize(config: str) -> str:
    lines = [ln.rstrip() for ln in config.replace("\r\n", "\n").split("\n")]
    return "\n".join(ln for ln in lines if not any(v.match(ln) for v in VOLATILE)).strip() + "\n"


def fetch(device: Device, cred: Credential, timeout: int = 30) -> dict[str, str]:
    try:
        from netmiko import ConnectHandler  # optional dependency
    except ImportError as exc:
        raise RuntimeError("netmiko not installed: pip install 'netagent[ssh]'") from exc
    params = dict(device_type=device.platform, host=device.host, port=device.port,
                  username=cred.username, password=cred.password, secret=cred.secret,
                  timeout=timeout, auth_timeout=timeout, fast_cli=False)
    try:
        with ConnectHandler(**params) as conn:
            if cred.secret and device.platform.startswith("cisco"):
                conn.enable()
            out = {"config": conn.send_command(SHOW_CONFIG[device.platform], read_timeout=timeout * 4)}
            if device.platform in SHOW_NEIGHBORS:
                out["neighbors"] = conn.send_command(SHOW_NEIGHBORS[device.platform], read_timeout=timeout * 2)
            return out
    except Exception as exc:  # report without leaking secrets
        raise RuntimeError(redact(f"{device.hostname}: {type(exc).__name__}: {exc}", cred)) from None


class ConfigStore:
    """data/<hostname>/<timestamp>.cfg + latest.cfg; only writes a new version when content changes."""

    def __init__(self, root: str | Path = "data/configs") -> None:
        self.root = Path(root)

    def _dir(self, hostname: str) -> Path:
        d = (self.root / hostname).resolve()
        if self.root.resolve() not in d.parents:
            raise ValueError("path traversal blocked")
        d.mkdir(parents=True, exist_ok=True)
        return d

    def latest(self, hostname: str) -> str | None:
        p = self._dir(hostname) / "latest.cfg"
        return p.read_text(encoding="utf-8") if p.exists() else None

    def versions(self, hostname: str) -> list[Path]:
        return sorted(p for p in self._dir(hostname).glob("*.cfg") if p.name != "latest.cfg")

    def save(self, hostname: str, config: str, when: datetime | None = None) -> tuple[bool, str]:
        """Returns (changed, unified_diff)."""
        new = normalize(config)
        old = self.latest(hostname)
        if old == new:
            return False, ""
        diff = "".join(difflib.unified_diff((old or "").splitlines(True), new.splitlines(True),
                                            fromfile="previous", tofile="current"))
        ts = (when or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%S%fZ")
        d = self._dir(hostname)
        (d / f"{ts}.cfg").write_text(new, encoding="utf-8")
        (d / "latest.cfg").write_text(new, encoding="utf-8")
        log.info("saved %s sha256=%s", hostname, hashlib.sha256(new.encode()).hexdigest()[:12])
        return True, diff
