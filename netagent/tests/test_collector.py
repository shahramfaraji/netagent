import os, stat, tempfile, threading, unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from datetime import datetime, timezone
from netagent.collector import ConfigStore, normalize, fetch, check_ssh_connection
from netagent.credentials import Credential
from netagent.models import Device


class TestStore(unittest.TestCase):
    def setUp(self):
        self.store = ConfigStore(tempfile.mkdtemp())

    def test_routeros_artifacts_are_saved_as_separate_neighbor_files(self):
        paths = self.store.save_artifacts("lab-router", {
            "routeros_resource": "version: 7.23.7", "routeros_ip_service": "0 name=ssh disabled=no",
            "not_allowed": "ignored",
        })
        self.assertEqual({p.name for p in paths}, {"latest.routeros_resource.txt", "latest.routeros_ip_service.txt"})
        self.assertEqual((self.store.root / "lab-router" / "latest.routeros_resource.txt").read_text(), "version: 7.23.7\n")

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

    def test_routeros_v6_and_v7_export_headers_are_volatile(self):
        v6a = "# oct/24/2026 by RouterOS 6.49.18\nhostname lab-router\n"
        v6b = "# oct/25/2026 by RouterOS 6.49.18\nhostname lab-router\n"
        v7a = "# 2026-10-24 08:30:00 by RouterOS 7.23.7\nhostname lab-router\n"
        v7b = "# 2026-10-25 09:45:00 by RouterOS 7.23.7\nhostname lab-router\n"
        self.assertEqual(normalize(v6a), normalize(v6b))
        self.assertEqual(normalize(v7a), normalize(v7b))

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
        self.assertIs(params["ssh_strict"], True)
        self.assertIs(params["alt_host_keys"], True)
        self.assertTrue(Path(params["alt_key_file"]).exists())

    def test_fetch_uses_strict_host_key_parameters_with_mock_connector(self):
        from unittest.mock import MagicMock, patch
        import sys
        from types import ModuleType

        mock_netmiko = ModuleType("netmiko")
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.send_command.return_value = "/system identity\\nset name=lab-router"
        mock_netmiko.ConnectHandler = MagicMock(return_value=connection)
        device = Device("lab-router", "192.0.2.25", "mikrotik_routeros")
        with patch.dict(sys.modules, {"netmiko": mock_netmiko}):
            result = fetch(device, Credential("operator", "fixture-password"))
        self.assertIn("config", result)
        self.assertIn("routeros_resource", result)
        self.assertIn("routeros_ip_service", result)
        self.assertIn("routeros_export_verbose", result)
        commands = [call.args[0] for call in connection.send_command.call_args_list]
        self.assertIn("/system resource print", commands)
        self.assertIn("/ip service print detail without-paging", commands)
        self.assertIn("/export verbose", commands)
        self.assertFalse(any("show-sensitive" in command for command in commands))
        params = mock_netmiko.ConnectHandler.call_args.kwargs
        self.assertIs(params["ssh_strict"], True)
        self.assertIs(params["alt_host_keys"], True)
        self.assertTrue(Path(params["alt_key_file"]).exists())

    def test_unknown_host_key_error_fails_closed_without_retrying_unverified(self):
        from unittest.mock import MagicMock, patch
        import sys
        from types import ModuleType

        mock_netmiko = ModuleType("netmiko")
        mock_netmiko.ConnectHandler = MagicMock(side_effect=Exception("host key not present in known_hosts"))
        device = Device("lab-router", "192.0.2.25", "mikrotik_routeros")
        with patch.dict(sys.modules, {"netmiko": mock_netmiko}):
            with self.assertRaisesRegex(RuntimeError, "host key not present"):
                check_ssh_connection(device, Credential("operator", "fixture-password"))
        mock_netmiko.ConnectHandler.assert_called_once()
        self.assertIs(mock_netmiko.ConnectHandler.call_args.kwargs["ssh_strict"], True)

    def test_fetch_without_netmiko_is_clear_error(self):
        dev = Device("sw1", "10.0.0.1", "cisco_ios")
        try:
            import netmiko  # noqa: F401
            self.skipTest("netmiko installed")
        except ImportError:
            pass
        with self.assertRaisesRegex(RuntimeError, "netmiko not installed"):
            fetch(dev, Credential("u", "p"))
