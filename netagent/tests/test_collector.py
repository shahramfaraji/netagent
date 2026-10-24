import os, stat, tempfile, threading, unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from netagent.collector import ConfigStore, normalize, fetch, check_ssh_connection
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
        if os.name != "nt":  # POSIX permission bits are not meaningful on Windows
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

    def test_ssh_check_opens_session_and_reads_prompt_only(self):
        from unittest.mock import MagicMock, patch
        import sys
        from types import ModuleType

        mock_netmiko = ModuleType("netmiko")
        connection = MagicMock()
        connection.__enter__.return_value = connection
        mock_netmiko.ConnectHandler = MagicMock(return_value=connection)
        device = Device("mt-router", "192.0.2.222", "mikrotik_routeros")
        with patch.dict(sys.modules, {"netmiko": mock_netmiko}):
            check_ssh_connection(device, Credential("operator", "test-password"))
        connection.find_prompt.assert_called_once_with()
        connection.send_command.assert_not_called()
        mock_netmiko.ConnectHandler.assert_called_once()
        params = mock_netmiko.ConnectHandler.call_args.kwargs
        self.assertEqual(params["device_type"], "mikrotik_routeros")
        self.assertEqual(params["host"], "192.0.2.222")

    def test_fetch_without_netmiko_is_clear_error(self):
        dev = Device("sw1", "10.0.0.1", "cisco_ios")
        try:
            import netmiko  # noqa: F401
            self.skipTest("netmiko installed")
        except ImportError:
            pass
        with self.assertRaisesRegex(RuntimeError, "netmiko not installed"):
            fetch(dev, Credential("u", "p"))
