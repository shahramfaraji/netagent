import stat, tempfile, threading, unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
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

    def test_backup_files_are_private_and_timestamp_collisions_do_not_overwrite(self):
        when = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)
        barrier = threading.Barrier(2)

        def save(config):
            barrier.wait()
            return self.store.save("sw1", config, when=when)

        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(save, ("hostname first\n", "hostname second\n")))

        device_dir = self.store.root / "sw1"
        versions = self.store.versions("sw1")
        self.assertEqual(len(versions), 2)
        self.assertNotEqual(versions[0].name, versions[1].name)
        self.assertEqual({p.read_text() for p in versions},
                         {"hostname first\n", "hostname second\n"})
        self.assertEqual(stat.S_IMODE(self.store.root.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(device_dir.stat().st_mode), 0o700)
        for path in [*versions, device_dir / "latest.cfg"]:
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertFalse(list(device_dir.glob(".*.tmp")))

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
