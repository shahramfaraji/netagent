"""Build a topology graph from CDP/LLDP neighbor output."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Link:
    local: str
    local_if: str
    remote: str
    remote_if: str

    def key(self) -> tuple:
        a, b = (self.local, self.local_if), (self.remote, self.remote_if)
        return tuple(sorted([a, b]))


_CDP_BLOCK = re.compile(r"-{5,}")
_CDP_ID = re.compile(r"Device ID:\s*(\S+)")
_CDP_IF = re.compile(r"Interface:\s*([^,]+),\s*Port ID \(outgoing port\):\s*(\S+)")
_LLDP_SYS = re.compile(r"System Name:\s*(\S+)")
_LLDP_LOCAL = re.compile(r"Local (?:Intf|Interface|Port id):\s*(\S+)", re.I)
_LLDP_PORT = re.compile(r"Port id:\s*(\S+)", re.I)


def _short(name: str) -> str:
    return name.split(".")[0].split("(")[0]


def parse_cdp(local: str, text: str) -> list[Link]:
    links = []
    for block in _CDP_BLOCK.split(text):
        dev, intf = _CDP_ID.search(block), _CDP_IF.search(block)
        if dev and intf:
            links.append(Link(local, intf.group(1).strip(), _short(dev.group(1)), intf.group(2).strip()))
    return links


def parse_lldp(local: str, text: str) -> list[Link]:
    links = []
    for block in re.split(r"\n\s*\n", text):
        sysname, lif = _LLDP_SYS.search(block), _LLDP_LOCAL.search(block)
        ports = [m for m in _LLDP_PORT.finditer(block) if not block[max(0, m.start() - 6):m.start()].lower().endswith("local ")]
        if sysname and lif:
            rport = ports[-1].group(1) if ports else "?"
            links.append(Link(local, lif.group(1), _short(sysname.group(1)), rport))
    return links


def parse_neighbors(local: str, text: str) -> list[Link]:
    return parse_cdp(local, text) if "Device ID:" in text else parse_lldp(local, text)


def build_graph(links: list[Link], roles: dict[str, str] | None = None) -> dict:
    roles = roles or {}
    uniq: dict[tuple, Link] = {}
    for link in links:
        uniq.setdefault(link.key(), link)  # A->B and B->A collapse into one edge
    nodes = sorted({n for link in uniq.values() for n in (link.local, link.remote)} | set(roles))
    return {
        "nodes": [{"id": n, "role": roles.get(n, "unknown")} for n in nodes],
        "links": [link.__dict__ for link in uniq.values()],
    }


def to_mermaid(graph: dict) -> str:
    shape = {"router": ("((", "))"), "firewall": ("{{", "}}"), "switch": ("[", "]")}
    safe = lambda s: re.sub(r"[^A-Za-z0-9_]", "_", s)
    lines = ["graph LR"]
    for n in graph["nodes"]:
        o, c = shape.get(n["role"], ("(", ")"))
        lines.append(f'  {safe(n["id"])}{o}"{n["id"]}"{c}')
    for link in graph["links"]:
        lines.append(f'  {safe(link["local"])} ---|"{link["local_if"]} - {link["remote_if"]}"| {safe(link["remote"])}')
    return "\n".join(lines) + "\n"


def to_json(graph: dict) -> str:
    return json.dumps(graph, indent=2)
