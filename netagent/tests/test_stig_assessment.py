import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from netagent.stig_assessment import (
    AssessmentRule, DeviceContext, Waiver, assess, coverage_summary, evaluate_rule,
    exit_code, load_approved_rules, load_waivers, parse_ios_show_version, report_markdown,
)


def rule(**overrides):
    values = dict(
        control_id="V-1", rule_id="SV-1_rule", title="Synthetic control",
        severity="medium", status="approved", automation_level="automated",
        target_platform="cisco_ios", target_families=("Catalyst 2960-X",),
        profiles=(), evidence_requirements=(),
        check_strategy={"type": "config_line_present", "line": "mls qos"},
        pass_condition={"line_present": "mls qos"}, fail_condition={"line_missing": "mls qos"},
        remediation="Configure mls qos.", source_ref={"benchmark_id": "synthetic"},
    )
    values.update(overrides)
    return AssessmentRule(**values)


class TestStigAssessment(unittest.TestCase):
    def setUp(self):
        self.device = DeviceContext("sw1", "cisco_ios", family="Catalyst 2960-X")

    def test_config_line_pass_and_fail(self):
        r = rule()
        self.assertEqual(evaluate_rule(r, self.device, "hostname sw1\nmls qos\n").status, "PASS")
        self.assertEqual(evaluate_rule(r, self.device, "hostname sw1\n").status, "FAIL")

    def test_missing_config_is_unknown_not_pass(self):
        self.assertEqual(evaluate_rule(rule(), self.device, None).status, "UNKNOWN")
        self.assertEqual(evaluate_rule(rule(), self.device, "").status, "UNKNOWN")

    def test_unknown_family_is_unknown(self):
        device = DeviceContext("sw1", "cisco_ios")
        self.assertEqual(evaluate_rule(rule(), device, "mls qos").status, "UNKNOWN")

    def test_wrong_platform_and_family_are_not_applicable(self):
        self.assertEqual(evaluate_rule(rule(), DeviceContext("fw", "cisco_asa"), "mls qos").status, "NOT_APPLICABLE")
        self.assertEqual(evaluate_rule(rule(), DeviceContext("sw2", "cisco_ios", family="Catalyst 9300"), "mls qos").status, "NOT_APPLICABLE")

    def test_show_version_parser_only_infers_known_families(self):
        parsed = parse_ios_show_version("Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E\nModel Number : WS-C2960X-48FPD-L")
        self.assertEqual(parsed["family"], "Catalyst 2960-X")
        self.assertEqual(parsed["version"], "15.2(7)E")
        self.assertIsNone(parse_ios_show_version("random text")["family"])

    def test_evidence_regex_missing_and_match(self):
        r = rule(evidence_requirements=("show_vtp_status",), check_strategy={
            "type": "evidence_regex", "evidence_key": "show_vtp_status",
            "pattern": r"(?im)^VTP Version running\s*:\s*2$", "expect_match": True,
        })
        self.assertEqual(evaluate_rule(r, self.device, "mls qos").status, "UNKNOWN")
        result = evaluate_rule(r, self.device, "mls qos", {"show_vtp_status": "VTP Version running : 2"})
        self.assertEqual(result.status, "PASS")

    def test_waiver_requires_reason_approver_and_expiry(self):
        r = rule()
        active = Waiver("V-1", "Accepted test exception", "reviewer", date(2027, 1, 1))
        expired = Waiver("V-1", "Old exception", "reviewer", date(2025, 1, 1))
        self.assertEqual(evaluate_rule(r, self.device, "mls qos", waiver=active, today=date(2026, 1, 1)).status, "WAIVED")
        self.assertEqual(evaluate_rule(r, self.device, "mls qos", waiver=expired, today=date(2026, 1, 1)).status, "PASS")

    def test_config_paths_present_checks_hierarchy_not_just_global_presence(self):
        r = rule(check_strategy={
            "type": "config_paths_present",
            "paths": [["aaa common-criteria policy PASSWORD_POLICY", "min-length 15"]],
        })
        nested = "aaa common-criteria policy PASSWORD_POLICY\n min-length 15\n!\n"
        misplaced = "aaa common-criteria policy PASSWORD_POLICY\n!\nmin-length 15\n"
        self.assertEqual(evaluate_rule(r, self.device, nested).status, "PASS")
        result = evaluate_rule(r, self.device, misplaced)
        self.assertEqual(result.status, "FAIL")
        self.assertIn("Missing configuration path", result.detail)

    def test_config_regex_count_fails_below_minimum_and_does_not_overclaim_pass(self):
        r = rule(check_strategy={
            "type": "config_regex_count",
            "pattern": r"(?im)^[ \t]*tacacs-server host\b",
            "min_count": 2,
            "partial": True,
        })
        one_server = "tacacs-server host 10.0.0.1\n"
        two_servers = one_server + "tacacs-server host 10.0.0.2\n"
        self.assertEqual(evaluate_rule(r, self.device, one_server).status, "FAIL")
        self.assertEqual(evaluate_rule(r, self.device, two_servers).status, "MANUAL")

    def test_auth_server_count_accepts_tacacs_and_radius_as_partial_evidence(self):
        r = rule(check_strategy={
            "type": "config_regex_count",
            "pattern": r"(?im)^[ \t]*(?:tacacs-server host|radius server)\b",
            "min_count": 2,
            "partial": True,
            "partial_note": "Does not prove distinct endpoints or admin-login usage.",
        })
        one_server = "tacacs-server host 10.0.0.1\n"
        two_server_types = one_server + "radius server ISE_RADIUS\n"
        self.assertEqual(evaluate_rule(r, self.device, one_server).status, "FAIL")
        result = evaluate_rule(r, self.device, two_server_types)
        self.assertEqual(result.status, "MANUAL")
        self.assertIn("distinct endpoints", result.detail)

    def test_admin_auth_server_count_uses_the_configured_default_method(self):
        r = rule(check_strategy={"type": "admin_auth_server_count", "min_count": 2})
        config = (
            "aaa authentication login default group tacacs+ local\n"
            "tacacs-server host 192.0.2.10\n"
            "radius server RADIUS_UNUSED\n"
            " address ipv4 192.0.2.20 auth-port 1812 acct-port 1813\n"
        )
        result = evaluate_rule(r, self.device, config)
        self.assertEqual(result.status, "FAIL")
        self.assertIn("uses tacacs+", result.detail)
        two_tacacs = config + "tacacs-server host 192.0.2.11\n"
        self.assertEqual(evaluate_rule(r, self.device, two_tacacs).status, "MANUAL")

    def test_emergency_local_account_requires_policy_and_fallback(self):
        r = rule(check_strategy={"type": "emergency_local_account"})
        config = (
            "username emergency privilege 10 common-criteria-policy POLICY_A secret 9 synthetic\n"
            "aaa common-criteria policy POLICY_A\n"
            " min-length 15\n"
            "!\n"
            "aaa authentication login default group tacacs+ local\n"
        )
        self.assertEqual(evaluate_rule(r, self.device, config).status, "MANUAL")
        no_policy = config.replace(" common-criteria-policy POLICY_A", "")
        self.assertEqual(evaluate_rule(r, self.device, no_policy).status, "FAIL")

    def test_vty_management_acl_requires_acl_on_each_vty_block(self):
        r = rule(check_strategy={"type": "vty_management_acl"})
        config = "line vty 0 4\n transport input ssh\n"
        result = evaluate_rule(r, self.device, config)
        self.assertEqual(result.status, "FAIL")
        self.assertIn("no inbound access-class", result.detail)

    def test_manual_review_strategy_returns_manual(self):
        r = rule(check_strategy={
            "type": "manual_review",
            "reason": "Interface roles need human validation.",
        })
        result = evaluate_rule(r, self.device, "hostname sw1")
        self.assertEqual(result.status, "MANUAL")
        self.assertIn("Interface roles", result.detail)

    def test_config_paths_and_regex_requires_each_predicate(self):
        r = rule(check_strategy={
            "type": "config_paths_and_regex",
            "paths": [["archive", "log config", "logging enable"]],
            "patterns": [{
                "pattern": r"(?im)^aaa new-model$",
                "description": "AAA global mode is enabled",
            }],
        })
        valid = "aaa new-model\narchive\n log config\n  logging enable\n"
        self.assertEqual(evaluate_rule(r, self.device, valid).status, "PASS")
        no_global_aaa = "archive\n log config\n  logging enable\n"
        result = evaluate_rule(r, self.device, no_global_aaa)
        self.assertEqual(result.status, "FAIL")
        self.assertIn("AAA global mode", result.detail)

    def test_common_criteria_policy_requires_directive_and_username_binding(self):
        r = rule(check_strategy={
            "type": "common_criteria_policy",
            "directive": "min-length 15",
        })
        compliant = (
            "aaa common-criteria policy POLICY_A\n"
            " min-length 15\n"
            "!\n"
            "username admin common-criteria-policy POLICY_A secret 9 synthetic\n"
        )
        self.assertEqual(evaluate_rule(r, self.device, compliant).status, "PASS")

        policy_not_bound = (
            "aaa common-criteria policy POLICY_A\n"
            " min-length 15\n"
            "!\n"
            "username admin secret 9 synthetic\n"
        )
        result = evaluate_rule(r, self.device, policy_not_bound)
        self.assertEqual(result.status, "FAIL")
        self.assertIn("not verified for every local username", result.detail)

        one_account_unbound = compliant + "username local2 secret 9 synthetic\n"
        self.assertEqual(evaluate_rule(r, self.device, one_account_unbound).status, "FAIL")

        setting_missing = (
            "aaa common-criteria policy POLICY_A\n"
            " upper-case 1\n"
            "!\n"
            "username admin common-criteria-policy POLICY_A secret 9 synthetic\n"
        )
        self.assertEqual(evaluate_rule(r, self.device, setting_missing).status, "FAIL")

    def test_loader_accepts_new_safe_strategy_types(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = {
                "status": "approved", "automation_level": "automated",
                "rule_id": "SV-1_rule", "title": "T", "severity": "medium",
                "target_platform": "cisco_ios",
            }
            (root / "paths.json").write_text(json.dumps({
                **base, "control_id": "V-1",
                "check_strategy": {"type": "config_paths_present", "paths": [["archive", "log config", "logging enable"]]},
            }), encoding="utf-8")
            (root / "count.json").write_text(json.dumps({
                **base, "control_id": "V-2",
                "check_strategy": {"type": "config_regex_count", "pattern": r"(?im)^[ \t]*tacacs-server host\b", "min_count": 2, "partial": True},
            }), encoding="utf-8")
            (root / "manual.json").write_text(json.dumps({
                **base, "control_id": "V-3", "automation_level": "semi_automated",
                "check_strategy": {"type": "manual_review", "reason": "Review required"},
            }), encoding="utf-8")
            (root / "cc.json").write_text(json.dumps({
                **base, "control_id": "V-4",
                "check_strategy": {"type": "common_criteria_policy", "directive": "min-length 15"},
            }), encoding="utf-8")
            (root / "authservers.json").write_text(json.dumps({
                **base, "control_id": "V-6",
                "check_strategy": {"type": "admin_auth_server_count", "min_count": 2},
            }), encoding="utf-8")
            (root / "emergency.json").write_text(json.dumps({
                **base, "control_id": "V-7",
                "check_strategy": {"type": "emergency_local_account"},
            }), encoding="utf-8")
            (root / "vtyacl.json").write_text(json.dumps({
                **base, "control_id": "V-8",
                "check_strategy": {"type": "vty_management_acl"},
            }), encoding="utf-8")
            (root / "combined.json").write_text(json.dumps({
                **base, "control_id": "V-5",
                "check_strategy": {
                    "type": "config_paths_and_regex",
                    "paths": [["archive", "log config", "logging enable"]],
                    "patterns": [{"pattern": r"(?im)^aaa new-model$", "description": "AAA global mode is enabled"}],
                },
            }), encoding="utf-8")
            loaded = load_approved_rules(root)
            self.assertEqual({item.control_id for item in loaded}, {"V-1", "V-2", "V-3", "V-4", "V-5", "V-6", "V-7", "V-8"})

    def test_loader_ignores_drafts_and_rejects_unsupported_strategy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "draft.json").write_text(json.dumps({"status": "draft"}), encoding="utf-8")
            (root / "good.json").write_text(json.dumps({
                "status": "approved", "automation_level": "automated",
                "control_id": "V-1", "rule_id": "SV-1", "title": "T", "severity": "medium",
                "target_platform": "cisco_ios", "check_strategy": {"type": "config_line_present", "line": "mls qos"},
            }), encoding="utf-8")
            self.assertEqual([r.control_id for r in load_approved_rules(root)], ["V-1"])
            (root / "bad.json").write_text(json.dumps({
                "status": "approved", "automation_level": "automated",
                "control_id": "V-2", "rule_id": "SV-2", "title": "T", "severity": "medium",
                "target_platform": "cisco_ios", "check_strategy": {"type": "arbitrary_python"},
            }), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_approved_rules(root)

    def test_duplicate_approved_ids_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = {
                "status": "approved", "automation_level": "automated", "control_id": "V-1",
                "rule_id": "SV-1", "title": "T", "severity": "medium", "target_platform": "cisco_ios",
                "check_strategy": {"type": "config_line_present", "line": "mls qos"},
            }
            (root / "a.json").write_text(json.dumps(payload), encoding="utf-8")
            (root / "b.json").write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate control_id"):
                load_approved_rules(root)

    def test_coverage_exit_policy_and_report(self):
        results = assess([rule()], self.device, "hostname sw1")
        counts = coverage_summary(results)
        self.assertEqual(counts["FAIL"], 1)
        self.assertEqual(counts["TOTAL"], 1)
        self.assertEqual(exit_code(results, fail_on="medium"), 2)
        unknown = [evaluate_rule(rule(), DeviceContext("sw", "cisco_ios"), None)]
        self.assertEqual(exit_code(unknown), 3)
        self.assertEqual(exit_code(unknown, allow_unknown=True), 0)
        report = report_markdown(self.device, results)
        self.assertIn("| V-1 | medium | FAIL |", report)

    def test_batch_01_synthetic_rule_fixtures(self):
        repo_root = Path(__file__).resolve().parents[1]
        fixture_root = Path(__file__).parent / "fixtures" / "stig" / "cisco_ios" / "batch_01"
        draft_root = repo_root / "rules" / "cisco_ios" / "drafts"
        self.assertEqual(load_approved_rules(draft_root), [])

        candidates = [
            ("l2s-cisc-l2-000040-v-220625.json", "v-220625-pass.cfg", "v-220625-fail.cfg", "mls qos", "V-220625"),
            ("l2s-cisc-l2-000110-v-220631.json", "v-220631-pass.cfg", "v-220631-fail.cfg", "spanning-tree loopguard default", "V-220631"),
        ]
        device = DeviceContext("synthetic-sw1", "cisco_ios", family="Catalyst 2960-X")
        for draft_name, pass_name, fail_name, expected_line, control_id in candidates:
            with self.subTest(control_id=control_id):
                raw = json.loads((draft_root / draft_name).read_text(encoding="utf-8"))
                self.assertEqual(raw["status"], "draft")
                self.assertEqual(raw["control_id"], control_id)
                self.assertEqual(raw["check_strategy"]["line"], expected_line)
                candidate_rule = rule(
                    control_id=raw["control_id"], rule_id=raw["rule_id"], title=raw["title"],
                    severity=raw["severity"], check_strategy=raw["check_strategy"],
                    source_ref=raw["source_ref"], remediation=raw["remediation"],
                )
                pass_config = (fixture_root / pass_name).read_text(encoding="utf-8")
                fail_config = (fixture_root / fail_name).read_text(encoding="utf-8")
                self.assertEqual(evaluate_rule(candidate_rule, device, pass_config).status, "PASS")
                self.assertEqual(evaluate_rule(candidate_rule, device, fail_config).status, "FAIL")

    def test_profile_filter(self):
        r = rule(profiles=("switch-access",))
        result = assess([r], DeviceContext("sw1", "cisco_ios", family="Catalyst 2960-X", profiles=("datacenter",)), "mls qos")
        self.assertEqual(result[0].status, "NOT_APPLICABLE")
        unverified = assess([r], DeviceContext("sw1", "cisco_ios", family="Catalyst 2960-X"), "mls qos")
        self.assertEqual(unverified[0].status, "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
