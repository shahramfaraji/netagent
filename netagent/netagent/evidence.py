"""Read-only Cisco IOS evidence collection with a strict command allowlist."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .credentials import Credential, quiet_transport_logs
from .models import Device
from .ssh import connection_params

try:
    from netmiko import ConnectHandler
except ImportError:  # optional dependency; report a clear error only when collection is requested
    ConnectHandler = None

IOS_READ_ONLY_COMMANDS = {
    "show_version": "show version",
    "show_running_config": "show running-config",
    "show_interfaces_status": "show interfaces status",
    "show_vlan_brief": "show vlan brief",
    "show_cdp_neighbors_detail": "show cdp neighbors detail",
    "show_lldp_neighbors_detail": "show lldp neighbors detail",
}
ALLOWED_COMMANDS = frozenset(IOS_READ_ONLY_COMMANDS.values())
EVIDENCE_FILENAMES = {key: f"{key}.txt" for key in IOS_READ_ONLY_COMMANDS}


def run_allowed_command(transport: Any, command: str, timeout: int = 60) -> str:
    """Run exactly one allowlisted read-only command on an injected transport."""
    if command not in ALLOWED_COMMANDS:
        raise ValueError(f"command is not in the Cisco IOS read-only allowlist: {command!r}")
    return str(transport.send_command(command, read_timeout=timeout))


def _write_evidence(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    if os.name != "nt":
        path.chmod(0o600)


def collect_readonly_evidence(transport: Any, output_dir: str | Path, timeout: int = 60) -> dict[str, Any]:
    """Collect allowlisted command outputs into separate files; no device setup or mutation."""
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    paths: dict[str, str] = {}
    for key, command in IOS_READ_ONLY_COMMANDS.items():
        result = run_allowed_command(transport, command, timeout=timeout)
        path = output / EVIDENCE_FILENAMES[key]
        _write_evidence(path, result)
        paths[key] = str(path)
    warnings = []
    if os.name == "nt":
        warnings.append("Windows ACLs were not verified; file mode 0600 is not a security guarantee on Windows.")
    return {"files": paths, "warnings": warnings, "commands": list(IOS_READ_ONLY_COMMANDS.values())}


def collect_device_readonly_evidence(
    device: Device,
    credential: Credential,
    output_dir: str | Path,
    *,
    timeout: int = 60,
    known_hosts: str | Path | None = None,
) -> dict[str, Any]:
    """Connect to one Cisco IOS device with strict SSH host-key checking and collect allowlisted evidence."""
    if device.platform != "cisco_ios":
        raise ValueError(f"read-only STIG evidence collection supports only cisco_ios, not {device.platform!r}")
    if ConnectHandler is None:
        raise RuntimeError("netmiko not installed; install the optional SSH dependency before collecting evidence")
    params = connection_params(device, credential, timeout=timeout, known_hosts=known_hosts)
    with quiet_transport_logs():
        with ConnectHandler(**params) as transport:
            return collect_readonly_evidence(transport, output_dir, timeout=timeout)


def load_evidence(directory: str | Path) -> dict[str, str]:
    """Load existing evidence files; missing files are omitted so downstream checks become UNKNOWN."""
    root = Path(directory)
    evidence: dict[str, str] = {}
    for key, filename in EVIDENCE_FILENAMES.items():
        path = root / filename
        if path.is_file():
            evidence[key] = path.read_text(encoding="utf-8", errors="replace")
    return evidence


def load_evidence_bundle(directory: str | Path) -> tuple[str | None, dict[str, str]]:
    """Return (running-config, evidence map); absent config remains None."""
    evidence = load_evidence(directory)
    return evidence.get("show_running_config"), evidence
