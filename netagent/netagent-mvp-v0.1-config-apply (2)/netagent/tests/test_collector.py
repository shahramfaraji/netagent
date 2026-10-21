import tempfile, unittest
from netagent.collector import ConfigStore, normalize, fetch
from netagent.credentials import Credential
from netagent.models import Device


class TestStore(unittest.TestCase):
    def setUp(self):
        self.store = ConfigStore(tempfile.mkdtemp())

    def test_versioning_and_diff(self):
        changed, _ = self.store.save("sw1", "hostname sw1\n")
        self.assertTrue(changed)
        changed, diff = self.store.save("sw1", "hostname sw1\n")
        self.assertFalse(changed); self.assertEqual(diff, "")
        changed, diff = self.store.save("sw1", "hostname sw1\nntp server 1.1.1.1\n")
        self.assertTrue(changed); self.assertIn("+ntp server 1.1.1.1", diff)
        self.assertEqual(len(self.store.versions("sw1")), 2)

    def test_volatile_lines_ignored(self):
        a = "! Last configuration change at 10:00\nhostname x\n"
        b = "! Last configuration change at 11:00\nhostname x\n"
        self.assertEqual(normalize(a), normalize(b))

    def test_path_traversal_blocked(self):
        with self.assertRaises(ValueError):
            self.store.save("../../evil", "x")

    def test_fetch_without_netmiko_is_clear_error(self):
        dev = Device("sw1", "10.0.0.1", "cisco_ios")
        try:
            import netmiko  # noqa: F401
            self.skipTest("netmiko installed")
        except ImportError:
            pass
        with self.assertRaisesRegex(RuntimeError, "netmiko not installed"):
            fetch(dev, Credential("u", "p"))
