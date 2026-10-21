import unittest
from pathlib import Path
from netagent.topology import build_graph, parse_neighbors, parse_lldp, to_mermaid

EX = Path(__file__).parent.parent / "examples/neighbors"
LLDP = """Local Intf: Ethernet1
Chassis id: 001c.7300.0001
Port id: Ethernet49
System Name: spine1.dc

Local Intf: Ethernet2
Port id: Ethernet49
System Name: spine2
"""


class TestTopology(unittest.TestCase):
    def test_cdp_and_dedup(self):
        links = []
        for f in EX.glob("*.txt"):
            links += parse_neighbors(f.stem, f.read_text())
        self.assertEqual(len(links), 3)  # sw->r1, sw->fw, r1->sw (dup)
        g = build_graph(links, {"core-sw1": "switch", "edge-r1": "router", "fw1": "firewall"})
        self.assertEqual(len(g["links"]), 2)
        self.assertEqual({n["id"] for n in g["nodes"]}, {"core-sw1", "edge-r1", "fw1"})

    def test_lldp(self):
        links = parse_lldp("leaf1", LLDP)
        self.assertEqual([(l.local_if, l.remote, l.remote_if) for l in links],
                         [("Ethernet1", "spine1", "Ethernet49"), ("Ethernet2", "spine2", "Ethernet49")])

    def test_mermaid_safe_ids(self):
        g = build_graph(parse_lldp("leaf-1", LLDP))
        mm = to_mermaid(g)
        self.assertTrue(mm.startswith("graph LR"))
        self.assertIn("leaf_1", mm)
