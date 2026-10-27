"""Cisco IOS interface inventory and conservative role classification.

Operator role files are JSON objects mapping interface names to
{"role": "uplink|host|ap|phone|server|unused", "note": "..."}.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from ..stig_assessment import _config_tree

OPERATOR_ROLES = {"uplink", "host", "ap", "phone", "server", "unused"}


@dataclass(frozen=True)
class InterfaceInfo:
    name: str
    kind: str
    admin_shutdown: bool
    mode: str
    access_vlan: int | None
    native_vlan: int | None
    allowed_vlans: tuple[int, ...] | str | None
    voice_vlan_present: bool
    channel_group: str | None
    description: str | None
    role: str
    source: str
    evidence: tuple[str, ...]
    note: str | None = None
    hint: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _int_after(prefix: str, lines: list[str]) -> int | None:
    for line in lines:
        match = re.match(rf"^{re.escape(prefix)}\s+(\d+)\b", line, re.IGNORECASE)
        if match:
            return int(match.group(1))
    return None


def _parse_vlan_list(value: str) -> tuple[int, ...] | str | None:
    value = value.strip().casefold()
    if not value:
        return None
    if value == "all":
        return "all"
    if value.startswith("none"):
        return ()
    result: set[int] = set()
    for part in value.split(","):
        part = part.strip()
        match = re.fullmatch(r"(\d+)\s*-\s*(\d+)", part)
        if match:
            start, end = int(match.group(1)), int(match.group(2))
            if end < start or end - start > 4094:
                return None
            result.update(range(start, end + 1))
        elif part.isdigit():
            result.add(int(part))
        elif part:
            return None
    return tuple(sorted(result))


def _kind(name: str, lines: list[str]) -> str:
    folded = name.casefold()
    if re.match(r"^(?:port-channel|po)\s*\d+", folded):
        return "port-channel"
    if re.match(r"^(?:vlan)\s*\d+", folded):
        return "svi"
    if re.match(r"^loopback\s*\d+", folded):
        return "loopback"
    if "no switchport" in lines:
        return "routed"
    if re.match(r"^(?:gigabitethernet|fastethernet|tengigabitethernet|ethernet|gi|fa|te)\s*\d", folded):
        return "physical"
    return "other"


def _inferred_role(kind: str, shutdown: bool, mode: str, voice: bool) -> str:
    if shutdown:
        return "shutdown_unused"
    if kind in {"svi", "loopback", "routed"} or mode == "routed":
        return "routed_or_svi"
    if mode == "trunk":
        return "trunk"
    if mode in {"dynamic_auto", "dynamic_desirable"}:
        return "dynamic"
    if mode == "access":
        return "access_voice" if voice else "access_host"
    return "unknown"


def _load_operator_roles(roles_dir: str | Path | None, hostname: str | None) -> dict[str, dict[str, str]]:
    if roles_dir is None or not hostname:
        return {}
    path = Path(roles_dir) / f"{hostname}.json"
    if not path.is_file():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: operator role file must be a JSON object")
    roles: dict[str, dict[str, str]] = {}
    for interface, item in raw.items():
        if not isinstance(interface, str) or not isinstance(item, dict):
            raise ValueError(f"{path}: each interface must map to an object")
        role = item.get("role")
        note = item.get("note", "")
        if role not in OPERATOR_ROLES:
            raise ValueError(f"{path}: invalid role for {interface!r}; expected one of {', '.join(sorted(OPERATOR_ROLES))}")
        if not isinstance(note, str):
            raise ValueError(f"{path}: note for {interface!r} must be a string")
        roles[interface.casefold()] = {"role": role, "note": note}
    return roles


def classify_interfaces(
    config: str,
    hostname: str | None = None,
    roles_dir: str | Path | None = None,
    hints: dict[str, str] | None = None,
    operator_roles: dict[str, dict[str, str]] | None = None,
) -> list[InterfaceInfo]:
    """Parse interface blocks and infer roles conservatively; operator labels override inference."""
    loaded_roles = _load_operator_roles(roles_dir, hostname)
    for interface, item in (operator_roles or {}).items():
        role = item.get("role")
        note = item.get("note", "")
        if role not in OPERATOR_ROLES or not isinstance(note, str):
            raise ValueError(f"invalid operator role for {interface!r}")
        loaded_roles[interface.casefold()] = {"role": role, "note": note}
    operator_roles = loaded_roles
    hints = {key.casefold(): value for key, value in (hints or {}).items()}
    tree = _config_tree(config)
    inventory: list[InterfaceInfo] = []
    for node in tree:
        match = re.match(r"^interface\s+(.+)$", node["line"])
        if not match:
            continue
        name = node.get("raw_line", node["line"]).split(None, 1)[1].strip()
        children = node["children"]
        lines = [child["line"] for child in children]
        raw_lines = [child.get("raw_line", child["line"]) for child in children]
        evidence = (node.get("raw_line", node["line"]), *raw_lines)
        shutdown = "shutdown" in lines
        no_switchport = "no switchport" in lines
        mode = "none"
        for candidate in ("access", "trunk", "dynamic auto", "dynamic desirable"):
            if f"switchport mode {candidate}" in lines:
                mode = candidate.replace(" ", "_")
                break
        if no_switchport:
            mode = "routed"
        elif mode == "none" and _kind(name, lines) == "physical":
            # Catalyst 2960 switchports default to dynamic auto; do not call these access ports.
            mode = "dynamic_auto"
        access_vlan = _int_after("switchport access vlan", lines)
        native_vlan = _int_after("switchport trunk native vlan", lines)
        allowed_vlans: tuple[int, ...] | str | None = None
        for line in lines:
            allowed_match = re.match(r"^switchport trunk allowed vlan\s+(.+)$", line)
            if allowed_match:
                allowed_vlans = _parse_vlan_list(allowed_match.group(1))
                break
        voice_vlan_present = any(line.startswith("switchport voice vlan ") for line in lines)
        channel_group = None
        for line in lines:
            channel_match = re.match(r"^channel-group\s+(\d+)\b", line)
            if channel_match:
                channel_group = channel_match.group(1)
                break
        description = None
        for raw in raw_lines:
            if raw.casefold().startswith("description "):
                description = raw[len("description "):].strip()
                break
        kind = _kind(name, lines)
        role = _inferred_role(kind, shutdown, mode, voice_vlan_present)
        source = "inferred"
        note = None
        operator = operator_roles.get(name.casefold())
        hint = hints.get(name.casefold())
        if operator:
            role = operator["role"]
            source = "operator"
            note = operator["note"] or None
        elif role == "unknown" and hint:
            # Neighbor data is explicitly a hint; it never upgrades unknown to a proven role.
            source = "hint"
        inventory.append(InterfaceInfo(
            name=name,
            kind=kind,
            admin_shutdown=shutdown,
            mode=mode,
            access_vlan=access_vlan,
            native_vlan=native_vlan,
            allowed_vlans=allowed_vlans,
            voice_vlan_present=voice_vlan_present,
            channel_group=channel_group,
            description=description,
            role=role,
            source=source,
            evidence=tuple(evidence),
            note=note,
            hint=hint,
        ))
    return inventory
