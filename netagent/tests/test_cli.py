import json, tempfile, unittest
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import patch
from netagent.cli import main
from netagent.deploy import ApprovalResult, ApplyPreview
from netagent.credentials import Credential

EX = Path(__file__).parent.parent / "examples"


class TestCLI(unittest.TestCase):
    def test_audit_and_topology_end_to_end(self):
        out = Path(tempfile.mkdtemp())
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            rc = main(["audit", "--rules", str(EX / "rules/baseline.json"), "--inventory", str(EX / "inventory.json"),
                       "--configs", str(EX / "configs"), "--out", str(out / "r.md"), "--fail-on-high"])
            # The inventory includes fw1 without a saved config, so the audit is incomplete.
            self.assertEqual(rc, 1)
            self.assertIn("## Missing configurations", (out / "r.md").read_text())
            self.assertIn("fw1", (out / "r.md").read_text())
            rc = main(["topology", "--neighbors", str(EX / "neighbors"), "--inventory", str(EX / "inventory.json"),
                       "--out", str(out / "topo")])
        self.assertEqual(rc, 0)
        self.assertIn("NO-TELNET", (out / "r.md").read_text())
        self.assertTrue((out / "topo/topology.mmd").exists())

    def test_apply_defaults_to_read_only_dry_run(self):
        temp = Path(tempfile.mkdtemp())
        inventory = temp / "inventory.json"
        candidate = temp / "candidate.cfg"
        inventory.write_text(json.dumps({"devices": [{
            "hostname": "sw1", "host": "192.0.2.10", "platform": "cisco_ios"
        }]}), encoding="utf-8")
        candidate.write_text("interface Loopback0\n description managed\n", encoding="utf-8")
        preview = ApplyPreview("sw1", "cisco_ios", "+ description managed\n", "a" * 64, 2, "b" * 64, True)
        output = StringIO()
        with patch("netagent.cli.get_credential", return_value=Credential("operator", "fixture-only-credential")), \
             patch("netagent.cli.preview_config", return_value=preview), \
             patch("netagent.cli.apply_config") as live_apply, redirect_stdout(output):
            rc = main([
                "apply", "--inventory", str(inventory), "--device", "sw1",
                "--config", str(candidate),
            ])
        self.assertEqual(rc, 0)
        live_apply.assert_not_called()
        self.assertIn("DRY RUN", output.getvalue())
        self.assertIn("not a simulated post-change config", output.getvalue())

    def test_apply_interactive_confirmation_requires_exact_hostname(self):
        temp = Path(tempfile.mkdtemp())
        inventory = temp / "inventory.json"
        candidate = temp / "candidate.cfg"
        inventory.write_text(json.dumps({"devices": [{
            "hostname": "sw1", "host": "192.0.2.10", "platform": "cisco_ios"
        }]}), encoding="utf-8")
        candidate.write_text("interface Loopback0\n description managed\n", encoding="utf-8")
        preview = ApplyPreview("sw1", "cisco_ios", "+ description managed\n", "a" * 64, 2, "b" * 64, True,
                               "backup-local.cfg", "flash:netagent-123456abcdef-preapply.cfg")

        def fake_apply(_device, _candidate, _cred, _store, approve, **kwargs):
            decision = approve(preview)
            approved = decision.approved if isinstance(decision, ApprovalResult) else bool(decision)
            return "Applied" if approved else "Approval declined; device was not modified."

        output = StringIO()
        with patch("netagent.cli._require_interactive_approval"), \
             patch("netagent.cli.get_credential", return_value=Credential("operator", "fixture-only-credential")), \
             patch("netagent.cli.apply_config", side_effect=fake_apply) as live_apply, \
             patch("builtins.input", return_value="not-sw1"), redirect_stdout(output):
            rc = main(["apply", "--inventory", str(inventory), "--device", "sw1", "--config", str(candidate), "--apply"])
        self.assertEqual(rc, 2)
        live_apply.assert_called_once()
        self.assertIn("LIVE CHANGE PREVIEW", output.getvalue())
        self.assertIn("Approval declined", output.getvalue())

    def test_live_apply_fails_closed_without_interactive_terminal(self):
        temp = Path(tempfile.mkdtemp())
        inventory = temp / "inventory.json"
        candidate = temp / "candidate.cfg"
        inventory.write_text(json.dumps({"devices": [{
            "hostname": "sw1", "host": "192.0.2.10", "platform": "cisco_ios"
        }]}), encoding="utf-8")
        candidate.write_text("interface Loopback0\n description managed\n", encoding="utf-8")
        err = StringIO()
        with patch(
            "netagent.cli._require_interactive_approval",
            side_effect=RuntimeError("interactive terminal required"),
        ), patch("netagent.cli.get_credential") as get_credential, \
             patch("netagent.cli.apply_config") as live_apply, \
             redirect_stdout(StringIO()), redirect_stderr(err):
            rc = main([
                "apply", "--inventory", str(inventory), "--device", "sw1",
                "--config", str(candidate), "--apply",
            ])
        self.assertEqual(rc, 1)
        get_credential.assert_not_called()
        live_apply.assert_not_called()
        self.assertIn("interactive terminal required", err.getvalue())

    def test_audit_unknown_exits_three_unless_allow_unknown_is_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inventory = root / "inventory.json"
            inventory.write_text(json.dumps({"devices": [{
                "hostname": "r1", "host": "192.0.2.25", "platform": "mikrotik_routeros"
            }]}), encoding="utf-8")
            configs = root / "configs" / "r1"
            configs.mkdir(parents=True)
            (configs / "latest.cfg").write_text("# RouterOS 7.23.7\n/system identity\nset name=r1\n", encoding="utf-8")
            rules = root / "rules.json"
            rules.write_text(json.dumps({"rules": [{
                "id": "MT-VERSION", "description": "minimum version", "severity": "high",
                "platforms": ["mikrotik_routeros"], "check": "minimum_version",
                "options": {"minimum_version": ""}
            }]}), encoding="utf-8")
            common = ["audit", "--rules", str(rules), "--inventory", str(inventory), "--configs", str(root / "configs")]
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                self.assertEqual(main(common), 3)
                self.assertEqual(main(common + ["--allow-unknown"]), 0)

    def test_audit_fails_with_nonzero_code_when_all_configs_are_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.md"
            err = StringIO()
            with redirect_stdout(StringIO()), redirect_stderr(err):
                rc = main(["audit", "--rules", str(EX / "rules/baseline.json"),
                           "--inventory", str(EX / "inventory.json"),
                           "--configs", str(Path(tmp) / "empty"), "--out", str(out)])
            self.assertEqual(rc, 1)
            self.assertIn("missing config", err.getvalue())
            report = out.read_text()
            self.assertIn("## Missing configurations", report)
            for hostname in ("core-sw1", "edge-r1", "fw1"):
                self.assertIn(hostname, report)

    def test_trust_host_key_fails_closed_without_interactive_terminal(self):
        with tempfile.TemporaryDirectory() as tmp:
            inventory = Path(tmp) / "inventory.json"
            inventory.write_text(json.dumps({"devices": [{
                "hostname": "lab-router", "host": "192.0.2.25", "platform": "mikrotik_routeros"
            }]}), encoding="utf-8")
            err = StringIO()
            with patch("netagent.cli.trust_host_key") as trust, \
                 patch("sys.stdin.isatty", return_value=False), \
                 redirect_stdout(StringIO()), redirect_stderr(err):
                rc = main(["trust-host-key", "--inventory", str(inventory), "--device", "lab-router"])
            self.assertEqual(rc, 1)
            trust.assert_not_called()
            self.assertIn("requires an interactive terminal", err.getvalue())

    def test_test_ssh_targets_only_named_inventory_device(self):
        with tempfile.TemporaryDirectory() as tmp:
            inventory = Path(tmp) / "inventory.json"
            inventory.write_text(json.dumps({"devices": [
                {"hostname": "mt-router", "host": "192.168.28.222", "platform": "mikrotik_routeros", "role": "router"},
                {"hostname": "other", "host": "192.0.2.2", "platform": "cisco_ios"},
            ]}), encoding="utf-8")
            with patch("netagent.cli.get_credential", return_value=Credential("operator", "fixture-password")), \
                 patch("netagent.cli.check_ssh_connection") as test_connection, \
                 redirect_stdout(StringIO()):
                rc = main(["test-ssh", "--inventory", str(inventory), "--device", "mt-router"])
            self.assertEqual(rc, 0)
            device = test_connection.call_args.args[0]
            self.assertEqual(device.hostname, "mt-router")
            self.assertEqual(device.host, "192.168.28.222")
            self.assertEqual(device.platform, "mikrotik_routeros")

    def test_bad_cidr_returns_error_code(self):
        err = StringIO()
        with redirect_stdout(StringIO()), redirect_stderr(err):
            self.assertEqual(main(["discover", "not-a-network"]), 1)
        self.assertIn("error:", err.getvalue())

