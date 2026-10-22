from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path

SUPPORTED_PLATFORMS = {"cisco_ios", "cisco_nxos", "cisco_asa", "juniper_junos", "arista_eos", "fortinet", "mikrotik_routeros"}
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")


class InventoryError(ValueError):
    pass


@dataclass
class Device:
    hostname: str
    host: str
    platform: str
    role: str = "unknown"  # switch | router | firewall | unknown
    port: int = 22
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not _HOSTNAME_RE.match(self.hostname):
            raise InventoryError(f"invalid hostname: {self.hostname!r}")
        try:
            ipaddress.ip_address(self.host)
        except ValueError as exc:
            raise InventoryError(f"invalid IP for {self.hostname}: {self.host!r}") from exc
        if self.platform not in SUPPORTED_PLATFORMS:
            raise InventoryError(f"unsupported platform for {self.hostname}: {self.platform!r}")
        if not (1 <= int(self.port) <= 65535):
            raise InventoryError(f"invalid port for {self.hostname}: {self.port}")

    def to_dict(self) -> dict:
        return asdict(self)


def load_inventory(path: str | Path) -> list[Device]:
    """Load devices from JSON. Credentials are never part of the inventory."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    devices = data.get("devices", data) if isinstance(data, dict) else data
    result: list[Device] = []
    seen: set[str] = set()
    for raw in devices:
        if any(k in raw for k in ("password", "secret", "enable_password")):
            raise InventoryError(f"credentials must not be stored in inventory ({raw.get('hostname')})")
        dev = Device(**raw)
        if dev.hostname in seen:
            raise InventoryError(f"duplicate hostname: {dev.hostname}")
        seen.add(dev.hostname)
        result.append(dev)
    return result


def save_inventory(devices: list[Device], path: str | Path) -> None:
    Path(path).write_text(json.dumps({"devices": [d.to_dict() for d in devices]}, indent=2), encoding="utf-8")
