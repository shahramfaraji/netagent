import json
import tempfile
import unittest
from pathlib import Path

from tools.catalog_to_drafts import classify_control, generate


class TestCatalogToDrafts(unittest.TestCase):
    def test_generates_manual_draft_and_manifest(self):
        control = {
            "control_id": "V-1",
            "rule_id": "SV-1_rule",
            "stig": "NDM",
            "stig_id": "CISC-ND-000001",
            "severity": "medium",
            "category": "CAT II",
            "title": "Synthetic test control",
            "source_ref": {"benchmark_id": "synthetic"},
            "check_text": "Synthetic check text",
            "fix_text": "Synthetic fix text",
            "cci": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            catalog = root / "catalog.json"
            out = root / "drafts"
            catalog.write_text(json.dumps({"catalog_version": "test", "controls": [control]}), encoding="utf-8")
            manifest = generate(catalog, out)
            files = list(out.glob("*.json"))
            draft_files = [path for path in files if path.name != "manifest.json"]
            self.assertEqual(manifest["generated_count"], 1)
            self.assertEqual(len(draft_files), 1)
            draft = json.loads(draft_files[0].read_text(encoding="utf-8"))
            self.assertEqual(draft["status"], "draft")
            self.assertEqual(draft["automation_level"], "manual")
            self.assertIsNone(draft["check_strategy"])
            self.assertEqual(draft["applicability"], "unknown")
            self.assertIn(draft["triage_classification"], {"manual_review", "semi_automated", "candidate_automated"})

    def test_topology_dependent_control_stays_manual_review(self):
        classification, _ = classify_control({
            "title": "Root Guard",
            "check_text": "Review the switch topology and verify Root Guard on all ports connecting to access layer switches. If not configured, this is a finding.",
        })
        self.assertEqual(classification, "manual_review")

    def test_simple_binary_global_command_is_candidate_only(self):
        classification, _ = classify_control({
            "title": "QoS enabled",
            "check_text": "Verify QoS is enabled:\n\nmls qos\n\nIf QoS has not been enabled, this is a finding.",
        })
        self.assertEqual(classification, "candidate_automated")

    def test_acl_placement_and_policy_stay_manual(self):
        classification, _ = classify_control({
            "title": "Management ACL",
            "check_text": "Verify the line vty has an ACL inbound applied:\n\nline vty 0 1\naccess-class MANAGEMENT_NET in\n\nip access-list extended MANAGEMENT_NET\npermit ip 10.1.1.0 0.0.0.255 any\n\nIf incorrect, this is a finding.",
        })
        self.assertEqual(classification, "manual_review")

    def test_multiple_global_commands_are_not_candidates(self):
        classification, _ = classify_control({
            "title": "Loop Guard",
            "check_text": "Review the switch configuration:\n\nspanning-tree mode pvst\nspanning-tree loopguard default\n\nIf STP Loop Guard is not enabled, this is a finding.",
        })
        self.assertEqual(classification, "semi_automated")


if __name__ == "__main__":
    unittest.main()
