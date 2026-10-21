import tempfile
import unittest
from pathlib import Path

from netagent.collector import ConfigStore
from netagent.credentials import Credential
from netagent.deploy import apply_config, clean_candidate, preview_config, redact_config, rollback_config
from netagent.models import Device


class FakeConnection:
    def __init__(self, running="hostname sw1\ninterface Loopback0\n description old\n"):
        self.running = running
        self.initial_running = running
        self.calls = []
        self.apply_error = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def send_command(self, command, **kwargs):
        self.calls.append(("command", command))
        if command == "show running-config":
            return self.running
        if command == "configure replace ?":
            return "flash: configuration files\nnvram: startup configuration"
        if command.startswith("dir flash:"):
            return command.split(":", 1)[1]
        raise AssertionError(command)

    def send_command_timing(self, command, **kwargs):
        self.calls.append(("timing", command))
        if command == "\n":
            return "Copy complete."
        if command.startswith("copy running-config"):
            return "Destination filename [backup]?"
        if command.startswith("configure replace"):
            if command.endswith("-preapply.cfg force"):
                self.running = self.initial_running
            return "Configure replace completed successfully"
        raise AssertionError(command)

    def send_config_set(self, lines, **kwargs):
        self.calls.append(("apply", list(lines)))
        if self.apply_error:
            raise ValueError("% Invalid input detected")
        self.running = "hostname sw1\ninterface Loopback0\n description new\n"
        return "Config applied"


class TestDeploy(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.store = ConfigStore(self.root / "configs")
        self.device = Device("sw1", "192.0.2.10", "cisco_ios")
        self.cred = Credential("operator", "never-log-this")
        self.candidate = "interface Loopback0\n description new\n"

    def test_clean_candidate_rejects_empty_and_exec_or_destructive_commands(self):
        candidates = (
            "  \n! comment\n", "write memory\n", "reload\n",
            "copy running-config flash:x\n", "configure replace flash:x force\n",
            "end\n", "do reload\n",
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                clean_candidate(candidate)

    def test_candidate_has_size_and_command_limits(self):
        with self.assertRaisesRegex(ValueError, "64 KiB"):
            clean_candidate("x" * (64 * 1024 + 1))
        with self.assertRaisesRegex(ValueError, "500-command"):
            clean_candidate("\n".join("description x" for _ in range(501)))
        with self.assertRaisesRegex(ValueError, "control character"):
            clean_candidate("description one\vdescription two")

    def test_preview_is_read_only_and_redacts_secret_lines(self):
        conn = FakeConnection(running="hostname sw1\nusername admin secret top-secret\n")
        preview = preview_config(self.device, "username admin secret another-secret\n", self.cred,
                                 connector=lambda **kwargs: conn)
        self.assertIn("sensitive config line redacted", preview.diff)
        self.assertFalse(any(kind in ("apply", "timing") for kind, _ in conn.calls))

    def test_preview_does_not_mistake_a_command_elsewhere_for_a_noop(self):
        running = "interface Loopback0\n description old\ninterface Loopback1\n description new\n"
        conn = FakeConnection(running=running)
        preview = preview_config(self.device, self.candidate, self.cred,
                                 connector=lambda **kwargs: conn)
        self.assertTrue(preview.changed)

    def test_apply_skips_when_candidate_matches_entire_running_config(self):
        current = "hostname sw1\ninterface Loopback0\n description new\n"
        conn = FakeConnection(running=current)
        result = apply_config(self.device, current, self.cred, self.store,
                              approve=lambda preview: self.fail("no-op must not request live approval"),
                              connector=lambda **kwargs: conn)
        self.assertIn("No changes detected", result)
        self.assertFalse(any(kind in ("apply", "timing") for kind, _ in conn.calls))

    def test_apply_requires_approval_before_any_backup_or_device_write(self):
        conn = FakeConnection()
        result = apply_config(self.device, self.candidate, self.cred, self.store,
                              approve=lambda preview: False, connector=lambda **kwargs: conn)
        self.assertIn("Approval declined", result)
        self.assertIn("verified backups retained", result)
        self.assertTrue(list((self.root / "configs").glob("sw1/backup-*.cfg")))
        self.assertFalse(any(kind == "apply" for kind, _ in conn.calls))
        self.assertTrue(any(kind == "timing" and command.startswith("copy running-config")
                            for kind, command in conn.calls))

    def test_apply_backups_then_applies_and_records_rollback(self):
        conn = FakeConnection()
        result = apply_config(self.device, self.candidate, self.cred, self.store,
                              approve=lambda preview: True, connector=lambda **kwargs: conn)
        self.assertIn("Applied to sw1", result)
        calls = conn.calls
        copy_index = next(i for i, (kind, command) in enumerate(calls)
                          if kind == "timing" and command.startswith("copy running-config"))
        verify_index = next(i for i, (kind, command) in enumerate(calls)
                            if kind == "command" and command.startswith("dir flash:"))
        apply_index = next(i for i, (kind, _) in enumerate(calls) if kind == "apply")
        self.assertLess(copy_index, verify_index)
        self.assertLess(verify_index, apply_index)
        self.assertTrue(any(p.name.startswith("backup-") for p in (self.root / "configs/sw1").glob("*.cfg")))
        manifest = self.store.load_deployment("sw1")
        self.assertEqual(manifest["status"], "applied")
        self.assertRegex(manifest["remote_backup"], r"^flash:netagent-[0-9a-f]{12}-preapply\.cfg$")
        self.assertNotIn("password", (self.root / "deployments/sw1/latest.json").read_text().lower())

    def test_apply_never_writes_when_device_backup_cannot_be_verified(self):
        conn = FakeConnection()
        original_send_command = conn.send_command

        def missing_backup(command, **kwargs):
            if command.startswith("dir flash:"):
                conn.calls.append(("command", command))
                return "No such file or directory"
            return original_send_command(command, **kwargs)

        conn.send_command = missing_backup
        with self.assertRaisesRegex(RuntimeError, "backup file was not found"):
            apply_config(self.device, self.candidate, self.cred, self.store,
                         approve=lambda _: True, connector=lambda **kwargs: conn)
        self.assertFalse(any(kind == "apply" for kind, _ in conn.calls))

    def test_apply_failure_attempts_automatic_rollback(self):
        conn = FakeConnection()
        conn.apply_error = True
        with self.assertRaisesRegex(RuntimeError, "automatic rollback completed"):
            apply_config(self.device, self.candidate, self.cred, self.store,
                         approve=lambda preview: True, connector=lambda **kwargs: conn)
        self.assertTrue(any(kind == "timing" and command.startswith("configure replace flash:")
                            for kind, command in conn.calls))

    def test_apply_readback_failure_triggers_verified_rollback(self):
        class ReadbackFailureConnection(FakeConnection):
            def __init__(self):
                super().__init__()
                self.show_count = 0

            def send_command(self, command, **kwargs):
                if command == "show running-config":
                    self.show_count += 1
                    if self.show_count == 2:
                        raise ConnectionError("readback unavailable")
                return super().send_command(command, **kwargs)

        conn = ReadbackFailureConnection()
        with self.assertRaisesRegex(RuntimeError, "automatic rollback completed"):
            apply_config(self.device, self.candidate, self.cred, self.store,
                         approve=lambda preview: True, connector=lambda **kwargs: conn)
        self.assertEqual(conn.running, conn.initial_running)
        self.assertEqual(self.store.load_deployment("sw1")["status"], "failed_rolled_back")

    def test_apply_failure_reports_manual_recovery_if_rollback_fails(self):
        conn = FakeConnection()
        conn.apply_error = True
        def fail_rollback(command, **kwargs):
            conn.calls.append(("timing", command))
            if command == "\n":
                return "Copy complete."
            if command.startswith("configure replace"):
                return "% Invalid input detected"
            if command.startswith("copy running-config"):
                return "Destination filename [backup]?"
            raise AssertionError(command)
        conn.send_command_timing = fail_rollback
        with self.assertRaisesRegex(RuntimeError, "could not be confirmed"):
            apply_config(self.device, self.candidate, self.cred, self.store,
                         approve=lambda preview: True, connector=lambda **kwargs: conn)

    def test_rollback_backs_up_current_config_before_restore(self):
        self.store.record_deployment("sw1", {
            "status": "applied", "platform": "cisco_ios",
            "remote_backup": "flash:netagent-123456abcdef-preapply.cfg",
        })
        conn = FakeConnection()
        result = rollback_config(self.device, self.cred, self.store,
                                 approve=lambda hostname, target, local, recovery: hostname == "sw1",
                                 connector=lambda **kwargs: conn)
        self.assertIn("Rolled back sw1", result)
        calls = conn.calls
        copy_index = next(i for i, (kind, command) in enumerate(calls)
                          if kind == "timing" and command.startswith("copy running-config"))
        verify_indexes = [i for i, (kind, command) in enumerate(calls)
                          if kind == "command" and command.startswith("dir flash:")]
        restore_index = next(
            i for i, (kind, command) in enumerate(calls)
            if kind == "timing" and command.startswith("configure replace flash:netagent-123456abcdef")
        )
        self.assertLess(verify_indexes[0], copy_index)
        self.assertLess(copy_index, verify_indexes[1])
        self.assertLess(verify_indexes[1], restore_index)
        self.assertEqual(self.store.load_deployment("sw1")["status"], "rolled_back")

    def test_rollback_decline_does_not_create_backup_or_mutate_device(self):
        self.store.record_deployment("sw1", {
            "status": "applied", "platform": "cisco_ios",
            "remote_backup": "flash:netagent-123456abcdef-preapply.cfg",
        })
        conn = FakeConnection()
        result = rollback_config(self.device, self.cred, self.store,
                                 approve=lambda hostname, target, local, recovery: False,
                                 connector=lambda **kwargs: conn)
        self.assertIn("Approval declined", result)
        self.assertIn("verified recovery backups retained", result)
        self.assertTrue(list((self.root / "configs").glob("sw1/backup-*.cfg")))
        self.assertFalse(any(kind == "timing" and command.startswith("configure replace")
                            for kind, command in conn.calls))

    def test_rollback_rejects_tampered_snapshot_path(self):
        self.store.record_deployment("sw1", {
            "status": "applied", "platform": "cisco_ios", "remote_backup": "flash:../../startup-config",
        })
        with self.assertRaisesRegex(RuntimeError, "invalid rollback snapshot"):
            rollback_config(self.device, self.cred, self.store, approve=lambda *_: True,
                            connector=lambda **kwargs: self.fail("must reject before connecting"))

    def test_apply_fails_closed_when_rollback_capability_is_missing(self):
        conn = FakeConnection()
        def unsupported(command, **kwargs):
            if command == "configure replace ?":
                return "unknown command"
            return FakeConnection.send_command(conn, command, **kwargs)

        conn.send_command = unsupported
        with self.assertRaisesRegex(RuntimeError, "does not advertise configure-replace"):
            apply_config(self.device, self.candidate, self.cred, self.store,
                         approve=lambda _: self.fail("must preflight rollback before prompting"),
                         connector=lambda **kwargs: conn)
        self.assertFalse(any(kind in ("apply", "timing") for kind, _ in conn.calls))

    def test_unsupported_platform_fails_closed(self):
        device = Device("router1", "192.0.2.11", "juniper_junos")
        with self.assertRaisesRegex(RuntimeError, "read-only"):
            apply_config(device, self.candidate, self.cred, self.store, approve=lambda _: True,
                         connector=lambda **kwargs: self.fail("unsupported platform must not connect"))

    def test_store_backup_always_writes_even_when_latest_matches(self):
        self.store.save("sw1", "hostname sw1\n")
        first = self.store.backup("sw1", "hostname sw1\n")
        second = self.store.backup("sw1", "hostname sw1\n")
        self.assertTrue(first.exists())
        self.assertTrue(second.exists())
        self.assertNotEqual(first, second)
        self.assertEqual(first.stat().st_mode & 0o777, 0o600)

    def test_manifest_path_traversal_is_blocked(self):
        with self.assertRaisesRegex(ValueError, "path traversal"):
            self.store.record_deployment("../../outside", {"status": "applied"})
        with self.assertRaisesRegex(ValueError, "path traversal"):
            self.store.load_deployment("../../outside")


if __name__ == "__main__":
    unittest.main()
