import os
import stat
import tempfile
import unittest
from pathlib import Path

from netagent.evidence import (
    ALLOWED_COMMANDS, IOS_READ_ONLY_COMMANDS, collect_readonly_evidence,
    load_evidence, load_evidence_bundle, run_allowed_command,
)
from netagent.stig_assessment import AssessmentRule, DeviceContext, evaluate_rule


class MockTransport:
    def __init__(self):
        self.commands = []

    def send_command(self, command, read_timeout=60):
        self.commands.append(command)
        return f"SYNTHETIC OUTPUT FOR {command}"


class TestEvidenceCollection(unittest.TestCase):
    def test_allowlist_rejects_non_read_only_command_before_transport(self):
        transport = MockTransport()
        with self.assertRaisesRegex(ValueError, "allowlist"):
            run_allowed_command(transport, "configure terminal")
        self.assertEqual(transport.commands, [])
        self.assertEqual(len(ALLOWED_COMMANDS), 6)

    def test_collects_each_allowlisted_command_to_a_separate_file(self):
        transport = MockTransport()
        with tempfile.TemporaryDirectory() as tmp:
            result = collect_readonly_evidence(transport, tmp)
            self.assertEqual(set(result["files"]), set(IOS_READ_ONLY_COMMANDS))
            self.assertEqual(set(transport.commands), ALLOWED_COMMANDS)
            self.assertEqual(len(list(Path(tmp).glob("*.txt"))), 6)
            for key, path in result["files"].items():
                self.assertIn(IOS_READ_ONLY_COMMANDS[key], Path(path).read_text(encoding="utf-8"))
            if __import__("os").name == "nt":
                self.assertTrue(any("not a security guarantee" in warning for warning in result["warnings"]))

    def test_missing_evidence_is_omitted_and_downstream_rule_returns_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, evidence = load_evidence_bundle(tmp)
            self.assertIsNone(config)
            self.assertEqual(evidence, {})
            rule = AssessmentRule(
                control_id="SYN-EVIDENCE", rule_id="SYN-EVIDENCE", title="Synthetic evidence check",
                severity="medium", status="approved", automation_level="automated",
                target_platform="cisco_ios", evidence_requirements=("show_vlan_brief",),
                check_strategy={"type": "evidence_regex", "evidence_key": "show_vlan_brief", "pattern": r"(?m)^10\s+USERS\s+active$"},
            )
            result = evaluate_rule(rule, DeviceContext("synthetic-sw1", "cisco_ios", family="Catalyst 2960-X"), config, evidence)
            self.assertEqual(result.status, "UNKNOWN")

    @unittest.skipIf(os.name == "nt", "POSIX mode bits are not a Windows ACL guarantee")
    def test_overwriting_existing_evidence_restricts_permissive_file_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "show_version.txt"
            path.write_text("old synthetic evidence", encoding="utf-8")
            path.chmod(0o644)
            transport = MockTransport()
            collect_readonly_evidence(transport, tmp)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_evidence_loader_maps_saved_files_to_engine_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "show_version.txt"
            path.write_text("SYNTHETIC SHOW VERSION", encoding="utf-8")
            evidence = load_evidence(tmp)
            self.assertEqual(evidence, {"show_version": "SYNTHETIC SHOW VERSION"})


if __name__ == "__main__":
    unittest.main()
