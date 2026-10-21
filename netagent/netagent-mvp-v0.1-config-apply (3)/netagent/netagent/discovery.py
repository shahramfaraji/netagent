"""Discovery: Nmap (if installed) with a pure-Python TCP fallback. Only scans ranges the user passes."""
from __future__ import annotations

import ipaddress
import logging
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

MGMT_PORTS = (22, 23, 161, 443, 830)
MAX_HOSTS = 4096
log = logging.getLogger(__name__)


@dataclass
class DiscoveredHost:
    ip: str
    open_ports: list[int] = field(default_factory=list)
    hostname: str = ""
    os_guess: str = ""

    @property
    def guessed_role(self) -> str:
        g = self.os_guess.lower()
        if any(k in g for k in ("asa", "fortios", "fortigate", "pan-os", "firewall")):
            return "firewall"
        if any(k in g for k in ("ios xr", "junos", "routeros", "router")):
            return "router"
        if any(k in g for k in ("nx-os", "eos", "switch", "catalyst")):
            return "switch"
        return "unknown"


def expand_targets(cidr: str) -> list[str]:
    net = ipaddress.ip_network(cidr, strict=False)
    if net.num_addresses > MAX_HOSTS:
        raise ValueError(f"range too large ({net.num_addresses} > {MAX_HOSTS}); split it")
    hosts = list(net.hosts()) or [net.network_address]
    return [str(h) for h in hosts]


def _tcp_open(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def tcp_scan(cidr: str, ports=MGMT_PORTS, timeout: float = 0.5, workers: int = 64) -> list[DiscoveredHost]:
    ips = expand_targets(cidr)
    tcp_ports = [p for p in ports if p != 161]

    def probe(ip: str) -> DiscoveredHost | None:
        open_ports = [p for p in tcp_ports if _tcp_open(ip, p, timeout)]
        return DiscoveredHost(ip, open_ports) if open_ports else None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return [h for h in pool.map(probe, ips) if h]


def parse_nmap_xml(xml_text: str) -> list[DiscoveredHost]:
    root = ET.fromstring(xml_text)
    hosts: list[DiscoveredHost] = []
    for h in root.findall("host"):
        status = h.find("status")
        if status is not None and status.get("state") != "up":
            continue
        addr = next((a.get("addr") for a in h.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")), None)
        if not addr:
            continue
        ports = [int(p.get("portid")) for p in h.findall("ports/port")
                 if p.find("state") is not None and p.find("state").get("state") == "open"]
        name_el = h.find("hostnames/hostname")
        os_el = h.find("os/osmatch")
        hosts.append(DiscoveredHost(addr, ports, name_el.get("name", "") if name_el is not None else "",
                                    os_el.get("name", "") if os_el is not None else ""))
    return hosts


def nmap_scan(cidr: str, ports=MGMT_PORTS) -> list[DiscoveredHost]:
    expand_targets(cidr)  # validates and enforces size limit
    exe = shutil.which("nmap")
    if not exe:
        raise FileNotFoundError("nmap not installed")
    port_arg = ",".join(str(p) for p in ports)
    # list-form args: no shell, no injection
    out = subprocess.run([exe, "-n", "-Pn", "--open", "-p", port_arg, "-oX", "-", cidr],
                         capture_output=True, text=True, timeout=900, check=True)
    return parse_nmap_xml(out.stdout)


def discover(cidr: str) -> list[DiscoveredHost]:
    try:
        return nmap_scan(cidr)
    except (FileNotFoundError, OSError, subprocess.SubprocessError, ET.ParseError) as exc:
        log.warning(
            "Nmap failed (%s); falling back to TCP connect scan. Fallback checks TCP "
            "management ports only and does not provide Nmap hostnames or OS guesses.",
            type(exc).__name__,
        )
        return tcp_scan(cidr)
