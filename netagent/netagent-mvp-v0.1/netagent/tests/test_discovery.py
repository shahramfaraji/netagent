import socket, threading, unittest
from netagent.discovery import DiscoveredHost, expand_targets, parse_nmap_xml, tcp_scan

NMAP_XML = """<?xml version="1.0"?><nmaprun>
<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>
<hostnames><hostname name="edge-r1"/></hostnames>
<ports><port protocol="tcp" portid="22"><state state="open"/></port>
<port protocol="tcp" portid="23"><state state="closed"/></port></ports>
<os><osmatch name="Cisco IOS router"/></os></host>
<host><status state="down"/><address addr="10.0.0.9" addrtype="ipv4"/></host>
</nmaprun>"""


class TestDiscovery(unittest.TestCase):
    def test_parse_nmap(self):
        hosts = parse_nmap_xml(NMAP_XML)
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].open_ports, [22])
        self.assertEqual(hosts[0].guessed_role, "router")

    def test_role_guess(self):
        self.assertEqual(DiscoveredHost("1.1.1.1", [22], os_guess="Cisco ASA").guessed_role, "firewall")
        self.assertEqual(DiscoveredHost("1.1.1.1", [22], os_guess="Arista EOS").guessed_role, "switch")

    def test_range_limits(self):
        self.assertEqual(len(expand_targets("10.0.0.0/30")), 2)
        self.assertEqual(expand_targets("10.0.0.5/32"), ["10.0.0.5"])
        with self.assertRaises(ValueError):
            expand_targets("10.0.0.0/8")
        with self.assertRaises(ValueError):
            expand_targets("10.0.0.0/24; rm -rf /")

    def test_tcp_scan_finds_local_listener(self):
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen()
        port = srv.getsockname()[1]
        threading.Thread(target=lambda: srv.accept(), daemon=True).start()
        try:
            hosts = tcp_scan("127.0.0.1/32", ports=(port,), timeout=1)
        finally:
            srv.close()
        self.assertEqual([h.open_ports for h in hosts], [[port]])
