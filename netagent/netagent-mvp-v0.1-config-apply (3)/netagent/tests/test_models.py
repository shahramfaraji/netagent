import json, tempfile, unittest
from pathlib import Path
from netagent.models import Device, InventoryError, load_inventory


class TestInventory(unittest.TestCase):
    def _write(self, data):
        p = Path(tempfile.mkdtemp()) / "inv.json"
        p.write_text(json.dumps(data)); return p

    def test_example_loads(self):
        devs = load_inventory(Path(__file__).parent.parent / "examples/inventory.json")
        self.assertEqual(len(devs), 3)

    def test_rejects_password_in_inventory(self):
        p = self._write({"devices": [{"hostname": "a", "host": "10.0.0.1", "platform": "cisco_ios", "password": "x"}]})
        with self.assertRaises(InventoryError):
            load_inventory(p)

    def test_rejects_bad_ip_platform_hostname_port(self):
        for kw in ({"host": "999.1.1.1"}, {"platform": "bogus"}, {"hostname": "../etc"}, {"port": 0}):
            base = {"hostname": "a", "host": "10.0.0.1", "platform": "cisco_ios"} | kw
            with self.assertRaises(InventoryError):
                Device(**base)

    def test_rejects_duplicates(self):
        d = {"hostname": "a", "host": "10.0.0.1", "platform": "cisco_ios"}
        with self.assertRaises(InventoryError):
            load_inventory(self._write({"devices": [d, d]}))
