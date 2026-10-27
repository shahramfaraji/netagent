import json
import tempfile
import unittest
from pathlib import Path

from netagent.assess.interfaces import classify_interfaces
from netagent.stig_assessment import AssessmentRule, DeviceContext, evaluate_rule, evaluate_rule_levels


class TestInterfaceAssessment(unittest.TestCase):
    def setUp(self):
        self.repo_root = Path(__file__).resolve().parents[1]
        self.fixture = self.repo_root / "tests" / "fixtures" / "stig" / "interfaces" / "interfaces-sample.cfg"
        self.config = self.fixture.read_text(encoding="utf-8")

    def test_classifies_synthetic_interface_inventory(self):
        inventory = {item.name: item for item in classify_interfaces(self.config, hostname="synthetic-sw1")}
        self.assertEqual(inventory["GigabitEthernet1/0/1"].kind, "physical")
        self.assertEqual(inventory["GigabitEthernet1/0/1"].role, "access_host")
        self.assertEqual(inventory["GigabitEthernet1/0/2"].role, "access_voice")
        self.assertTrue(inventory["GigabitEthernet1/0/2"].voice_vlan_present)
        self.assertEqual(inventory["GigabitEthernet1/0/24"].role, "trunk")
        self.assertEqual(inventory["GigabitEthernet1/0/24"].native_vlan, 99)
        self.assertEqual(inventory["GigabitEthernet1/0/24"].allowed_vlans, (10, 20, 99))
        self.assertEqual(inventory["GigabitEthernet1/0/24"].channel_group, "1")
        self.assertEqual(inventory["GigabitEthernet1/0/3"].mode, "dynamic_auto")
        self.assertEqual(inventory["GigabitEthernet1/0/3"].role, "dynamic")
        self.assertTrue(inventory["GigabitEthernet1/0/4"].admin_shutdown)
        self.assertEqual(inventory["GigabitEthernet1/0/4"].role, "shutdown_unused")
        self.assertEqual(inventory["Port-channel1"].kind, "port-channel")
        self.assertEqual(inventory["Port-channel1"].role, "trunk")
        self.assertEqual(inventory["Vlan10"].role, "routed_or_svi")
        self.assertEqual(inventory["Loopback0"].role, "routed_or_svi")
        self.assertEqual(inventory["Tunnel0"].role, "unknown")
        self.assertIn("SYNTHETIC_HOST", inventory["GigabitEthernet1/0/1"].description)
        self.assertTrue(inventory["GigabitEthernet1/0/1"].evidence)

    def test_interface_parser_is_case_insensitive_for_ios_commands(self):
        config = (
            "INTERFACE GigabitEthernet1/0/5\n"
            " SWITCHPORT MODE ACCESS\n"
            " SWITCHPORT ACCESS VLAN 30\n"
            " SWITCHPORT VOICE VLAN 40\n"
            " SPANNING-TREE BPDUguard ENABLE\n"
            "!\n"
            "interface GigabitEthernet1/0/6\n"
            " No Switchport\n"
            " IP address 192.0.2.30 255.255.255.0\n"
            "!\n"
        )
        inventory = {item.name: item for item in classify_interfaces(config)}
        access = inventory["GigabitEthernet1/0/5"]
        self.assertEqual(access.kind, "physical")
        self.assertEqual(access.mode, "access")
        self.assertEqual(access.access_vlan, 30)
        self.assertTrue(access.voice_vlan_present)
        self.assertEqual(access.role, "access_voice")
        routed = inventory["GigabitEthernet1/0/6"]
        self.assertEqual(routed.kind, "routed")
        self.assertEqual(routed.mode, "routed")
        self.assertEqual(routed.role, "routed_or_svi")

    def test_for_each_interface_scope_filters_kinds_and_excludes_shutdown(self):
        rule = AssessmentRule(
            control_id="SYN-SCOPE-1", rule_id="SYN-SCOPE-1", title="Synthetic scoped check",
            severity="medium", status="approved", automation_level="automated",
            target_platform="cisco_ios", target_families=("Catalyst 2960-X",),
            check_strategy={
                "type": "for_each_interface",
                "scope": {"kinds": ["physical"], "exclude_shutdown": True},
                "check": {"type": "config_regex_count", "pattern": r"^interface\s+", "min_count": 1},
            },
        )
        device = DeviceContext("synthetic-sw1", "cisco_ios", family="Catalyst 2960-X")
        result = evaluate_rule(rule, device, self.config)
        self.assertEqual(result.status, "PASS")
        self.assertIn("in-scope interface(s)", result.detail)
        self.assertNotIn("GigabitEthernet1/0/4", result.detail)

    def test_operator_role_overrides_inference_and_hint_is_not_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            role_file = Path(tmp) / "synthetic-sw1.json"
            role_file.write_text(json.dumps({
                "GigabitEthernet1/0/24": {"role": "uplink", "note": "Operator-confirmed synthetic uplink"}
            }), encoding="utf-8")
            inventory = {item.name: item for item in classify_interfaces(
                self.config, hostname="synthetic-sw1", roles_dir=tmp,
                hints={"Tunnel0": "uplink"},
            )}
        self.assertEqual(inventory["GigabitEthernet1/0/24"].role, "uplink")
        self.assertEqual(inventory["GigabitEthernet1/0/24"].source, "operator")
        self.assertEqual(inventory["Tunnel0"].role, "unknown")
        self.assertEqual(inventory["Tunnel0"].source, "hint")
        self.assertEqual(inventory["Tunnel0"].hint, "uplink")

    def test_for_each_interface_bpdu_guard_is_unknown_if_any_candidate_role_is_unknown(self):
        rule = AssessmentRule(
            control_id="SYN-BPDU-1", rule_id="SYN-BPDU-1", title="Synthetic BPDU guard check",
            severity="high", status="approved", automation_level="automated",
            target_platform="cisco_ios", target_families=("Catalyst 2960-X",),
            check_strategy={
                "type": "for_each_interface",
                "scope": {"roles": ["access_host", "access_voice"], "exclude_shutdown": True},
                "check": {"type": "config_line_present", "line": "spanning-tree bpduguard enable"},
            },
        )
        device = DeviceContext("synthetic-sw1", "cisco_ios", family="Catalyst 2960-X")
        result = evaluate_rule(rule, device, self.config)
        self.assertEqual(result.status, "UNKNOWN")
        self.assertIn("Tunnel0", result.detail)
        self.assertIn("unknown", result.detail.casefold())

    def test_pro_cell_is_unknown_when_candidate_interface_role_is_unknown(self):
        rule = AssessmentRule(
            control_id="SYN-BPDU-LEVELS", rule_id="SYN-BPDU-LEVELS", title="Synthetic BPDU guard levels",
            severity="high", status="approved", automation_level="automated",
            target_platform="cisco_ios", target_families=("Catalyst 2960-X",), level="standard",
            standard_check={"type": "config_line_present", "line": "hostname synthetic-sw1"},
            pro_check={
                "type": "for_each_interface",
                "scope": {"roles": ["access_host", "access_voice"], "exclude_shutdown": True},
                "check": {"type": "config_line_present", "line": "spanning-tree bpduguard enable"},
            },
            recommendation="Enable BPDU guard on classified access ports.",
        )
        device = DeviceContext("synthetic-sw1", "cisco_ios", family="Catalyst 2960-X")
        row = evaluate_rule_levels(rule, device, self.config, level="pro")
        self.assertEqual(row.standard.status, "PASS")
        self.assertEqual(row.pro.status, "UNKNOWN")
        self.assertIn("Tunnel0", row.pro.detail)

    def test_interface_inventory_report_lists_role_counts_and_unknown_names(self):
        from netagent.stig_assessment import report_markdown
        inventory = classify_interfaces(self.config, hostname="synthetic-sw1")
        report = report_markdown(DeviceContext("synthetic-sw1", "cisco_ios"), [], interfaces=inventory)
        self.assertIn("## Interface inventory", report)
        self.assertIn("| access_host | 1 |", report)
        self.assertIn("Unknown-role interfaces: Tunnel0", report)


if __name__ == "__main__":
    unittest.main()
