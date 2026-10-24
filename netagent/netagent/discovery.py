"""Discovery using Nmap, with a conservative pure-Python TCP fallback."""
from __future__ import annotations

import ipaddress
import logging
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from .deps import ensure_nmap

MGMT_PORTS = (22, 23, 443, 830)
MAX_HOSTS = 4096
log = logging.getLogger(__name__)


@dataclass
class DiscoveredHost:
    ip: str
    open_ports: list[int] = field(default_factory=list)
    hostname: str = ""
    os_guess: str = ""
    services: list[dict[str, str | int]] = field(default_factory=list)

    @property
    def guessed_role(self) -> str:
        # Prefer explicit service fingerprints over Nmap's OS guess: OS matching
        # can identify the wrong vendor/model even when a service is distinctive.
        os_text = self.os_guess.lower()
        service_text = " ".join(
            str(value).lower()
            for service in self.services
            for value in service.values()
        )
        all_text = f"{service_text} {os_text}"

        firewall_markers = (
            "cisco asa", " asa ", "fortios", "fortigate", "pan-os",
            "palo alto", "sophos firewall", "check point", "sonicwall",
            "pfsense", "opnsense", "firewall",
        )
        if any(marker in f" {all_text} " for marker in firewall_markers):
            return "firewall"

        # RouterOS in a service fingerprint should override a conflicting OS guess.
        router_markers = (
            "routeros", "routerboard", "mikrotik", "junos", "ios xr",
            " cisco ios router", "router",
        )
        if any(marker in all_text for marker in router_markers):
            return "router"

        switch_markers = (
            "nx-os", "arista eos", "catalyst", "procurve", "arubaos-switch",
            "aruba cx", "comware", "dell networking", "extreme networks",
            "switch", "ios ",
        )
        if any(marker in all_text for marker in switch_markers):
            return "switch"

        # Nmap's model strings sometimes explicitly identify a wireless AP.
        if any(marker in os_text for marker in ("wireless access point", " wap", "wap ")):
            return "access_point"

        # Dropbear/BusyBox and OpenSSH alone do not establish a device role.
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
        addr = next(
            (a.get("addr") for a in h.findall("address")
             if a.get("addrtype") in ("ipv4", "ipv6")),
            None,
        )
        if not addr:
            continue

        open_ports: list[int] = []
        services: list[dict[str, str | int]] = []
        for p in h.findall("ports/port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            try:
                port_id = int(p.get("portid", ""))
            except ValueError:
                continue
            open_ports.append(port_id)
            service_el = p.find("service")
            if service_el is not None:
                service: dict[str, str | int] = {
                    "port": port_id,
                    "protocol": p.get("protocol", "tcp"),
                }
                for attr in ("name", "product", "version", "extrainfo", "tunnel"):
                    value = service_el.get(attr)
                    if value:
                        service[attr] = value
                services.append(service)

        name_el = h.find("hostnames/hostname")
        os_matches = h.findall("os/osmatch")
        os_guess = os_matches[0].get("name", "") if os_matches else ""
        hosts.append(
            DiscoveredHost(
                ip=addr,
                open_ports=sorted(set(open_ports)),
                hostname=name_el.get("name", "") if name_el is not None else "",
                os_guess=os_guess,
                services=services,
            )
        )
    return hosts


def nmap_scan(cidr: str, ports=MGMT_PORTS) -> list[DiscoveredHost]:
    expand_targets(cidr)  # validates and enforces size limit
    exe = shutil.which("nmap") or ensure_nmap()
    if not exe:
        raise FileNotFoundError("nmap not installed")
    port_arg = ",".join(str(p) for p in ports)
    # -O requests OS fingerprinting; -sV probes detected open ports for service/version.
    # Reverse DNS is enabled by omitting -n. Nmap may need Administrator privileges
    # for OS detection on Windows; without them, results may be partial.
    cmd = [
        exe, "-Pn", "--open", "-sV", "-O", "-p", port_arg,
        "-oX", "-", cidr,
    ]
    out = subprocess.run(
        cmd, capture_output=True, text=True, timeout=900, check=True
    )
    if out.stderr.strip():
        log.debug("Nmap stderr: %s", out.stderr.strip())
    return parse_nmap_xml(out.stdout)


def discover(cidr: str) -> list[DiscoveredHost]:
    try:
        return nmap_scan(cidr)
    except FileNotFoundError as exc:
        # ensure_nmap has already asked for permission when interactive.
        # If installation was declined/unavailable, explain the reduced fallback.
        log.warning(
            "%s. Using the built-in TCP fallback; it checks only management ports "
            "and cannot identify hostnames, operating systems, or service versions.",
            exc,
        )
        return tcp_scan(cidr)
    except (OSError, subprocess.SubprocessError, ET.ParseError) as exc:
        log.warning(
            "Nmap failed (%s); falling back to TCP connect scan. The fallback "
            "does not identify hostnames, operating systems, or service versions.",
            type(exc).__name__,
        )
        return tcp_scan(cidr)
