"""SSH config collection (Netmiko, read-only commands) and versioned storage with diffs."""
from __future__ import annotations

import difflib
import hashlib
import json
import logging
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .credentials import Credential, quiet_transport_logs, redact
from .deps import ensure_netmiko
from .models import Device
from .ssh import connection_params

log = logging.getLogger(__name__)

ROUTEROS_READ_ONLY_COMMANDS = {
    "routeros_resource": "/system resource print",
    "routeros_ip_service": "/ip service print detail without-paging",
    "routeros_snmp": "/snmp print",
    "routeros_ntp_client": "/system ntp client print",
    "routeros_ntp_servers": "/system ntp client servers print detail without-paging",
    "routeros_export_verbose": "/export verbose",
    "routeros_user": "/user print detail without-paging",
    "routeros_ip_ssh": "/ip ssh print detail without-paging",
    "routeros_mac_server": "/tool mac-server print detail without-paging",
    "routeros_mac_winbox": "/tool mac-server mac-winbox print detail without-paging",
    "routeros_neighbor_discovery": "/ip neighbor discovery-settings print detail without-paging",
    "routeros_ip_dns": "/ip dns print detail without-paging",
    "routeros_bandwidth_server": "/tool bandwidth-server print detail without-paging",
    "routeros_ip_firewall_filter": "/ip firewall filter print detail without-paging",
    "routeros_logging_action": "/system logging action print detail without-paging",
    "routeros_logging": "/system logging print detail without-paging",
}

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
VOLATILE = [re.compile(p, re.I) for p in (
    r"^! Last configuration change", r"^! NVRAM config last updated",
    r"^ntp clock-period", r"^Current configuration :", r"^## Last commit",
    r"^#\s+(?:[A-Z][a-z]{2}/\d{1,2}/\d{4}|\d{4}-\d{2}-\d{2}).*\bby RouterOS\b",
)]


def normalize(config: str) -> str:
    lines = [ln.rstrip() for ln in config.replace("\r\n", "\n").split("\n")]
    return "\n".join(ln for ln in lines if not any(v.match(ln) for v in VOLATILE)).strip() + "\n"


def check_ssh_connection(device: Device, cred: Credential, timeout: int = 15,
                         known_hosts: str | Path | None = None) -> None:
    """Verify SSH authentication and prompt access without running configuration commands."""
    try:
        from netmiko import ConnectHandler  # optional dependency
    except ImportError as exc:
        if not ensure_netmiko():
            raise RuntimeError("netmiko not installed: pip install 'netagent[ssh]'") from exc
        from netmiko import ConnectHandler

    params = connection_params(device, cred, timeout=timeout, known_hosts=known_hosts)
    try:
        with quiet_transport_logs(), ConnectHandler(**params) as conn:
            conn.find_prompt()
    except Exception as exc:
        raise RuntimeError(redact(f"{device.hostname}: {type(exc).__name__}: {exc}", cred)) from None


def fetch(device: Device, cred: Credential, timeout: int = 30,
          known_hosts: str | Path | None = None) -> dict[str, str]:
    try:
        from netmiko import ConnectHandler  # optional dependency
    except ImportError as exc:
        if not ensure_netmiko():
            raise RuntimeError("netmiko not installed: pip install 'netagent[ssh]'") from exc
        from netmiko import ConnectHandler
    params = connection_params(device, cred, timeout=timeout, known_hosts=known_hosts)
    try:
        with quiet_transport_logs(), ConnectHandler(**params) as conn:
            if cred.secret and device.platform.startswith("cisco"):
                conn.enable()
            out = {"config": conn.send_command(SHOW_CONFIG[device.platform], read_timeout=timeout * 4)}
            if device.platform == "mikrotik_routeros":
                for key, command in ROUTEROS_READ_ONLY_COMMANDS.items():
                    out[key] = conn.send_command(command, read_timeout=timeout * 2)
            if device.platform in SHOW_NEIGHBORS:
                out["neighbors"] = conn.send_command(SHOW_NEIGHBORS[device.platform], read_timeout=timeout * 2)
            return out
    except Exception as exc:  # report without leaking secrets
        raise RuntimeError(redact(f"{device.hostname}: {type(exc).__name__}: {exc}", cred)) from None


class ConfigStore:
    """data/<hostname>/<timestamp>.cfg + latest.cfg; only writes a new version when content changes."""

    def __init__(self, root: str | Path = "data/configs") -> None:
        self.root = Path(root)
        self._host_locks: dict[str, threading.Lock] = {}
        self._host_locks_guard = threading.Lock()

    def _host_lock(self, hostname: str) -> threading.Lock:
        """Return a stable per-host lock so concurrent saves cannot race on latest.cfg."""
        with self._host_locks_guard:
            return self._host_locks.setdefault(hostname, threading.Lock())

    def _dir(self, hostname: str) -> Path:
        root = self.root.resolve()
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        root.chmod(0o700)
        d = (root / hostname).resolve()
        if root not in d.parents:
            raise ValueError("path traversal blocked")
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
        d.chmod(0o700)
        return d

    def latest(self, hostname: str) -> str | None:
        p = self._dir(hostname) / "latest.cfg"
        return p.read_text(encoding="utf-8") if p.exists() else None

    def versions(self, hostname: str) -> list[Path]:
        return sorted(p for p in self._dir(hostname).glob("*.cfg") if p.name != "latest.cfg")

    @staticmethod
    def _write_private(path: Path, content: str) -> None:
        """Atomically write a config snapshot with owner-only permissions."""
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(path)
        finally:
            if temporary.exists():
                temporary.unlink()

    def backup(self, hostname: str, config: str, when: datetime | None = None) -> Path:
        """Always persist a private pre-change snapshot, even if it matches latest."""
        snapshot = normalize(config)
        ts = (when or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%S%fZ")
        path = self._dir(hostname) / f"backup-{ts}-{uuid.uuid4().hex[:8]}.cfg"
        self._write_private(path, snapshot)
        log.info("created pre-change backup %s sha256=%s", hostname,
                 hashlib.sha256(snapshot.encode()).hexdigest()[:12])
        return path

    def record_deployment(self, hostname: str, manifest: dict) -> Path:
        """Store metadata only; credentials and config contents are never written here."""
        directory = (self.root.parent / "deployments" / hostname).resolve()
        root = (self.root.parent / "deployments").resolve()
        if root not in directory.parents:
            raise ValueError("path traversal blocked")
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)
        path = directory / "latest.json"
        self._write_private(path, json.dumps(manifest, indent=2, sort_keys=True))
        return path

    def load_deployment(self, hostname: str) -> dict:
        path = (self.root.parent / "deployments" / hostname / "latest.json").resolve()
        root = (self.root.parent / "deployments").resolve()
        if root not in path.parents:
            raise ValueError("path traversal blocked")
        if not path.exists():
            raise RuntimeError(f"no deployment record for {hostname}")
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("invalid deployment record")
        return data

    def save_artifacts(self, hostname: str, artifacts: dict[str, str]) -> list[Path]:
        """Persist supplementary command output beside the device's config snapshots."""
        directory = self._dir(hostname)
        written = []
        for name, content in artifacts.items():
            if not re.fullmatch(r"routeros_[a-z0-9_]+", name):
                continue
            path = directory / f"latest.{name}.txt"
            self._write_private(path, content.rstrip() + "\n")
            written.append(path)
        return written

    def save(self, hostname: str, config: str, when: datetime | None = None) -> tuple[bool, str]:
        """Returns (changed, unified_diff); serializes concurrent writes per hostname."""
        with self._host_lock(hostname):
            new = normalize(config)
            old = self.latest(hostname)
            if old == new:
                return False, ""
            diff = "".join(difflib.unified_diff((old or "").splitlines(True), new.splitlines(True),
                                                fromfile="previous", tofile="current"))
            ts = (when or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%S%fZ")
            d = self._dir(hostname)
            self._write_private(d / f"{ts}-{uuid.uuid4().hex[:8]}.cfg", new)
            self._write_private(d / "latest.cfg", new)
            log.info("saved %s sha256=%s", hostname, hashlib.sha256(new.encode()).hexdigest()[:12])
            return True, diff
