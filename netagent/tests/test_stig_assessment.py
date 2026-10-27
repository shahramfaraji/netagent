import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from netagent.stig_assessment import (
    AssessmentRule, CheckCell, DeviceContext, RuleRow, Waiver, assess, coverage_summary, evaluate_rule,
    exit_code, evaluate_rule_levels, load_approved_rules, load_waivers, parse_ios_show_version, report_markdown,
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

    def test_config_line_present_defaults_to_global_context(self):
        config = "interface GigabitEthernet1/0/1\n switchport mode access\n"
        r = rule(check_strategy={"type": "config_line_present", "line": "switchport mode access"})
        self.assertEqual(evaluate_rule(r, self.device, config).status, "FAIL")
        any_context = rule(check_strategy={"type": "config_line_present", "line": "switchport mode access", "context": "any"})
        self.assertEqual(evaluate_rule(any_context, self.device, config).status, "PASS")

    def test_banner_text_cannot_satisfy_config_line_path_or_regex_checks(self):
        multiline_banner = "banner motd #\nmls qos\ninterface GigabitEthernet1/0/1\n#\nhostname synthetic-sw1\n"
        inline_banner = "banner login @mls qos interface GigabitEthernet1/0/1@\nhostname synthetic-sw1\n"
        control_banner = "banner motd ^Cmls qos interface GigabitEthernet1/0/1^C\nhostname synthetic-sw1\n"
        line_rule = rule(check_strategy={"type": "config_line_present", "line": "mls qos"})
        path_rule = rule(check_strategy={"type": "config_paths_present", "paths": [["interface GigabitEthernet1/0/1", "mls qos"]]})
        regex_rule = rule(check_strategy={
            "type": "config_paths_and_regex", "paths": [["hostname synthetic-sw1"]],
            "patterns": [{"pattern": r"(?m)^mls qos$", "description": "synthetic command"}],
        })
        hostname_rule = rule(check_strategy={"type": "config_line_present", "line": "hostname synthetic-sw1"})
        other_delimiters = (
            "banner motd $mls qos interface GigabitEthernet1/0/1$\nhostname synthetic-sw1\n",
            "banner login %mls qos interface GigabitEthernet1/0/1%\nhostname synthetic-sw1\n",
            "banner exec /mls qos interface GigabitEthernet1/0/1/\nhostname synthetic-sw1\n",
        )
        for banner in (multiline_banner, inline_banner, control_banner, *other_delimiters):
            with self.subTest(banner=banner.splitlines()[0]):
                self.assertEqual(evaluate_rule(line_rule, self.device, banner).status, "FAIL")
                self.assertEqual(evaluate_rule(path_rule, self.device, banner).status, "FAIL")
                self.assertEqual(evaluate_rule(regex_rule, self.device, banner).status, "FAIL")
                self.assertEqual(evaluate_rule(hostname_rule, self.device, banner).status, "PASS")

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
        self.assertEqual(parsed["family_status"], "supported")
        out_of_scope = parse_ios_show_version("Cisco IOS Software, C2960 Software, Version 12.2(55)SE\nModel Number : WS-C2960-24TT-L")
        self.assertEqual(out_of_scope["model"], "WS-C2960-24TT-L")
        self.assertEqual(out_of_scope["family_status"], "out_of_scope_model")
        for model in ("WS-C2960S-24TS-L", "WS-C2960CX-8TC-L", "WS-C2960+24TC-L"):
            with self.subTest(model=model):
                parsed_out_of_scope = parse_ios_show_version(f"Model Number : {model}")
                self.assertEqual(parsed_out_of_scope["model"], model)
                self.assertEqual(parsed_out_of_scope["family_status"], "out_of_scope_model")
                self.assertIsNone(parsed_out_of_scope["family"])
        self.assertEqual(parse_ios_show_version(None)["family_status"], "unknown")
        out_of_scope_result = evaluate_rule(
            rule(), DeviceContext("legacy-sw", "cisco_ios", show_version="Cisco IOS Software, Version 12.2(55)SE\nModel Number : WS-C2960-24TT-L"),
            "mls qos",
        )
        self.assertEqual(out_of_scope_result.status, "UNKNOWN")
        self.assertIn("outside supported scope", out_of_scope_result.detail)

        conflicting_verified_family = evaluate_rule(
            rule(),
            DeviceContext(
                "legacy-sw", "cisco_ios", family="Catalyst 2960-X",
                show_version="Cisco IOS Software, Version 12.2(55)SE\nModel Number : WS-C2960-24TT-L",
            ),
            "mls qos",
        )
        self.assertEqual(conflicting_verified_family.status, "UNKNOWN")
        self.assertIn("outside supported scope", conflicting_verified_family.detail)
        waived_out_of_scope = evaluate_rule(
            rule(), DeviceContext(
                "legacy-sw", "cisco_ios", family="Catalyst 2960-X",
                show_version="Model Number : WS-C2960-24TT-L",
            ), "mls qos",
            waiver=Waiver("V-1", "Synthetic waiver", "reviewer", date(2027, 1, 1), ("legacy-sw",)),
            today=date(2026, 1, 1),
        )
        self.assertEqual(waived_out_of_scope.status, "UNKNOWN")

    def test_evidence_regex_missing_and_match(self):
        r = rule(evidence_requirements=("show_vtp_status",), check_strategy={
            "type": "evidence_regex", "evidence_key": "show_vtp_status",
            "pattern": r"(?im)^VTP Version running\s*:\s*2$", "expect_match": True,
        })
        self.assertEqual(evaluate_rule(r, self.device, "mls qos").status, "UNKNOWN")
        result = evaluate_rule(r, self.device, "mls qos", {"show_vtp_status": "VTP Version running : 2"})
        self.assertEqual(result.status, "PASS")

    def test_waiver_loader_requires_explicit_host_scope_and_allows_wildcard(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "waivers.json"
            base = {"control_id": "V-1", "reason": "synthetic exception", "approved_by": "reviewer", "expires_on": "2027-01-01"}
            path.write_text(json.dumps({"waivers": [base]}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "hostnames"):
                load_waivers(path)
            path.write_text(json.dumps({"waivers": [{**base, "hostnames": ["*"]}]}), encoding="utf-8")
            loaded = load_waivers(path)
            result = evaluate_rule(rule(), self.device, "hostname sw1", waiver=loaded["V-1"], today=date(2026, 1, 1))
            self.assertEqual(result.status, "WAIVED")
            self.assertIn("Explicit wildcard", result.detail)

    def test_waiver_requires_reason_approver_and_expiry(self):
        r = rule()
        active = Waiver("V-1", "Accepted test exception", "reviewer", date(2027, 1, 1), ("sw1",))
        expired = Waiver("V-1", "Old exception", "reviewer", date(2025, 1, 1), ("sw1",))
        self.assertEqual(evaluate_rule(r, self.device, "mls qos", waiver=active, today=date(2026, 1, 1)).status, "WAIVED")
        expired_result = evaluate_rule(r, self.device, "hostname sw1", waiver=expired, today=date(2026, 1, 1))
        self.assertEqual(expired_result.status, "FAIL")
        self.assertIn("Expired waiver ignored", expired_result.detail)
        expired_report = report_markdown(self.device, [expired_result])
        self.assertIn("Expired waiver ignored", expired_report)
        self.assertIn("result is not waived", expired_report)
        wrong_host = Waiver("V-1", "Scoped exception", "reviewer", date(2027, 1, 1), ("other-sw",))
        self.assertEqual(evaluate_rule(r, self.device, "hostname sw1", waiver=wrong_host, today=date(2026, 1, 1)).status, "FAIL")

    def test_config_tree_preserves_tabs_mixed_indentation_and_separator_variants(self):
        r = rule(check_strategy={"type": "config_paths_present", "paths": [
            ["tacacs server AUTH_A", "address ipv4 192.0.2.10"],
            ["track 10 ip sla 10 reachability", "delay down 10 up 5"],
            ["line vty 0 4", "transport input ssh"],
        ]})
        configs = (
            "tacacs server AUTH_A\n\taddress ipv4 192.0.2.10\n!\ntrack 10 ip sla 10 reachability\n  delay down 10 up 5\n!\nline vty 0 4\n transport input ssh\n",
            "tacacs server AUTH_A\n address ipv4 192.0.2.10\ntrack 10 ip sla 10 reachability\n\tdelay down 10 up 5\nline vty 0 4\n\ttransport input ssh\n",
            "tacacs server AUTH_A\n \taddress ipv4 192.0.2.10\n!\ntrack 10 ip sla 10 reachability\n \tdelay down 10 up 5\n!\nline vty 0 4\n \ttransport input ssh\n",
        )
        for config in configs:
            with self.subTest(config=repr(config)):
                self.assertEqual(evaluate_rule(r, self.device, config).status, "PASS")

    def test_config_tree_preserves_tacacs_server_child_indentation(self):
        r = rule(check_strategy={"type": "config_paths_present", "paths": [["tacacs server AUTH_A", "address ipv4 192.0.2.10"]]})
        config = "tacacs server AUTH_A\n address ipv4 192.0.2.10\n"
        self.assertEqual(evaluate_rule(r, self.device, config).status, "PASS")

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

    def test_capability_flags_downgrade_unprovable_pass_and_fail(self):
        cannot_prove_pass = rule(check_strategy={"type": "config_line_present", "line": "mls qos", "can_pass": False})
        pass_result = evaluate_rule(cannot_prove_pass, self.device, "mls qos")
        self.assertEqual(pass_result.status, "MANUAL")
        self.assertEqual(pass_result.downgraded_from, "PASS")
        cannot_prove_fail = rule(check_strategy={"type": "config_line_present", "line": "mls qos", "can_fail": False})
        fail_result = evaluate_rule(cannot_prove_fail, self.device, "hostname sw1")
        self.assertEqual(fail_result.status, "MANUAL")
        self.assertEqual(fail_result.downgraded_from, "FAIL")

    def test_loader_rejects_both_capabilities_false_except_manual_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = {
                "status": "approved", "automation_level": "automated", "control_id": "V-1",
                "rule_id": "SV-1", "title": "T", "severity": "medium", "target_platform": "cisco_ios", "level": "standard",
                "standard_check": {"type": "config_line_present", "line": "mls qos", "can_pass": False, "can_fail": False},
            }
            (root / "bad.json").write_text(json.dumps(base), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "manual_review"):
                load_approved_rules(root)

    def test_can_only_prove_failure_check_does_not_claim_safe_configuration(self):
        telnet_check = rule(check_strategy={
            "type": "evidence_regex",
            "evidence_key": "show_running_config",
            "pattern": r"(?im)^\s*transport input .*\btelnet\b",
            "expect_match": False,
            "can_pass": False,
            "can_fail": True,
        })
        safe_but_not_proven = evaluate_rule(
            telnet_check, self.device, None, {"show_running_config": "line vty 0 4\n transport input ssh\n"}
        )
        unsafe = evaluate_rule(
            telnet_check, self.device, None, {"show_running_config": "line vty 0 4\n transport input telnet ssh\n"}
        )
        self.assertEqual(safe_but_not_proven.status, "MANUAL")
        self.assertEqual(safe_but_not_proven.downgraded_from, "PASS")
        self.assertEqual(unsafe.status, "FAIL")
        self.assertIsNone(unsafe.downgraded_from)

    def test_unknown_and_manual_remain_distinct_in_status_and_counts(self):
        unknown = evaluate_rule(rule(), self.device, None)
        manual = evaluate_rule(
            rule(check_strategy={"type": "manual_review", "reason": "Synthetic human review"}),
            self.device, "hostname synthetic-sw1",
        )
        counts = coverage_summary([unknown, manual])
        self.assertEqual(unknown.status, "UNKNOWN")
        self.assertEqual(manual.status, "MANUAL")
        self.assertEqual(counts["UNKNOWN"], 1)
        self.assertEqual(counts["MANUAL"], 1)
        self.assertEqual(counts["TOTAL"], 2)

    def test_exit_code_decision_matrix_for_standard_statuses(self):
        statuses = [
            ("PASS", 0),
            ("FAIL", 2),
            ("UNKNOWN", 3),
            ("MANUAL", 0),
            ("WAIVED", 0),
            ("NOT_APPLICABLE", 0),
        ]
        for status, expected_default in statuses:
            with self.subTest(status=status, policy="default"):
                row = RuleRow("V-MATRIX", "SV-MATRIX", "Synthetic", "high",
                              CheckCell(status, "synthetic", "presence"), None)
                self.assertEqual(exit_code([row]), expected_default)
            with self.subTest(status=status, policy="allow-unknown"):
                row = RuleRow("V-MATRIX", "SV-MATRIX", "Synthetic", "high",
                              CheckCell(status, "synthetic", "presence"), None)
                expected = 0 if status == "UNKNOWN" else expected_default
                self.assertEqual(exit_code([row], allow_unknown=True), expected)
            with self.subTest(status=status, policy="strict-manual"):
                row = RuleRow("V-MATRIX", "SV-MATRIX", "Synthetic", "high",
                              CheckCell(status, "synthetic", "presence"), None)
                expected = 3 if status == "MANUAL" else expected_default
                self.assertEqual(exit_code([row], strict_manual=True), expected)

    def test_exit_code_decision_matrix_for_pro_and_precedence(self):
        def row(standard_status="PASS", pro_status="PASS", severity="high"):
            return RuleRow(
                "V-MATRIX", "SV-MATRIX", "Synthetic", severity,
                CheckCell(standard_status, "synthetic", "presence"),
                CheckCell(pro_status, "synthetic", "applied"),
            )

        cases = [
            ("pro-fail-opt-in-off", row(pro_status="FAIL"), {}, 0),
            ("pro-fail-opt-in-on", row(pro_status="FAIL"), {"fail_on_pro": "high"}, 2),
            ("pro-fail-below-threshold", row(pro_status="FAIL", severity="low"), {"fail_on_pro": "high"}, 0),
            ("standard-fail-wins-over-unknown", row(standard_status="FAIL", pro_status="UNKNOWN"), {"fail_on": "high"}, 2),
            ("standard-fail-wins-over-manual", row(standard_status="FAIL", pro_status="MANUAL"), {"fail_on": "high", "strict_manual": True}, 2),
            ("standard-fail-and-pro-fail", row(standard_status="FAIL", pro_status="FAIL"), {"fail_on": "high", "fail_on_pro": "high"}, 2),
            ("unknown-with-low-fail", row(standard_status="UNKNOWN", pro_status="FAIL", severity="low"), {"fail_on": "high", "fail_on_pro": "none"}, 3),
            ("invalid-standard-threshold", row(pro_status="FAIL"), {"fail_on": "urgent", "fail_on_pro": "high"}, 1),
            ("invalid-pro-threshold", row(), {"fail_on": "high", "fail_on_pro": "urgent"}, 1),
        ]
        for name, result_row, options, expected in cases:
            with self.subTest(case=name):
                self.assertEqual(exit_code([result_row], **options), expected)

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
                "target_platform": "cisco_ios", "level": "standard",
            }
            (root / "paths.json").write_text(json.dumps({
                **base, "control_id": "V-1",
                "standard_check": {"type": "config_paths_present", "paths": [["archive", "log config", "logging enable"]]},
            }), encoding="utf-8")
            (root / "count.json").write_text(json.dumps({
                **base, "control_id": "V-2",
                "standard_check": {"type": "config_regex_count", "pattern": r"(?im)^[ \t]*tacacs-server host\b", "min_count": 2, "partial": True},
            }), encoding="utf-8")
            (root / "manual.json").write_text(json.dumps({
                **base, "control_id": "V-3", "automation_level": "semi_automated",
                "standard_check": {"type": "manual_review", "reason": "Review required"},
            }), encoding="utf-8")
            (root / "cc.json").write_text(json.dumps({
                **base, "control_id": "V-4",
                "standard_check": {"type": "common_criteria_policy", "directive": "min-length 15"},
            }), encoding="utf-8")
            (root / "authservers.json").write_text(json.dumps({
                **base, "control_id": "V-6",
                "standard_check": {"type": "admin_auth_server_count", "min_count": 2},
            }), encoding="utf-8")
            (root / "emergency.json").write_text(json.dumps({
                **base, "control_id": "V-7",
                "standard_check": {"type": "emergency_local_account"},
            }), encoding="utf-8")
            (root / "vtyacl.json").write_text(json.dumps({
                **base, "control_id": "V-8",
                "standard_check": {"type": "vty_management_acl"},
            }), encoding="utf-8")
            (root / "combined.json").write_text(json.dumps({
                **base, "control_id": "V-5",
                "standard_check": {
                    "type": "config_paths_and_regex",
                    "paths": [["archive", "log config", "logging enable"]],
                    "patterns": [{"pattern": r"(?im)^aaa new-model$", "description": "AAA global mode is enabled"}],
                },
            }), encoding="utf-8")
            loaded = load_approved_rules(root)
            self.assertEqual({item.control_id for item in loaded}, {"V-1", "V-2", "V-3", "V-4", "V-5", "V-6", "V-7", "V-8"})

    def test_loader_accepts_for_each_interface_strategy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "interface.json").write_text(json.dumps({
                "status": "approved", "automation_level": "automated",
                "control_id": "V-INTERFACE", "rule_id": "SV-INTERFACE", "title": "Interface check",
                "severity": "high", "target_platform": "cisco_ios", "level": "standard",
                "standard_check": {
                    "type": "for_each_interface",
                    "scope": {"roles": ["access_host"], "exclude_shutdown": True},
                    "check": {"type": "config_line_present", "line": "spanning-tree bpduguard enable"},
                },
            }), encoding="utf-8")
            loaded = load_approved_rules(root)
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0].check_strategy["type"], "for_each_interface")

    def test_loader_ignores_drafts_and_rejects_unsupported_strategy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "draft.json").write_text(json.dumps({"status": "draft"}), encoding="utf-8")
            (root / "good.json").write_text(json.dumps({
                "status": "approved", "automation_level": "automated",
                "control_id": "V-1", "rule_id": "SV-1", "title": "T", "severity": "medium",
                "target_platform": "cisco_ios", "level": "standard", "standard_check": {"type": "config_line_present", "line": "mls qos"},
            }), encoding="utf-8")
            self.assertEqual([r.control_id for r in load_approved_rules(root)], ["V-1"])
            (root / "bad.json").write_text(json.dumps({
                "status": "approved", "automation_level": "automated",
                "control_id": "V-2", "rule_id": "SV-2", "title": "T", "severity": "medium",
                "target_platform": "cisco_ios", "level": "standard", "standard_check": {"type": "arbitrary_python"},
            }), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_approved_rules(root)

    def test_duplicate_approved_ids_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = {
                "status": "approved", "automation_level": "automated", "control_id": "V-1",
                "rule_id": "SV-1", "title": "T", "severity": "medium", "target_platform": "cisco_ios", "level": "standard",
                "standard_check": {"type": "config_line_present", "line": "mls qos"},
            }
            (root / "a.json").write_text(json.dumps(payload), encoding="utf-8")
            (root / "b.json").write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate control_id"):
                load_approved_rules(root)

    def test_assess_sorts_by_severity_then_control_id(self):
        rules = [
            rule(control_id="V-LOW", severity="low"),
            rule(control_id="V-HIGH-B", severity="high"),
            rule(control_id="V-MEDIUM", severity="medium"),
            rule(control_id="V-CRITICAL", severity="critical"),
            rule(control_id="V-HIGH-A", severity="high"),
        ]
        results = assess(rules, self.device, "mls qos")
        self.assertEqual(
            [item.control_id for item in results],
            ["V-CRITICAL", "V-HIGH-A", "V-HIGH-B", "V-MEDIUM", "V-LOW"],
        )

    def test_coverage_exit_policy_and_report(self):
        results = assess([rule()], self.device, "hostname sw1")
        counts = coverage_summary(results)
        self.assertEqual(counts["FAIL"], 1)
        self.assertEqual(counts["TOTAL"], 1)
        self.assertEqual(exit_code(results, fail_on="medium"), 2)
        unknown = [evaluate_rule(rule(), DeviceContext("sw", "cisco_ios"), None)]
        self.assertEqual(exit_code(unknown), 3)
        self.assertEqual(exit_code(unknown, allow_unknown=True), 0)
        self.assertEqual(exit_code([results[0], unknown[0]], fail_on="medium"), 2)
        manual = [evaluate_rule(rule(check_strategy={"type": "manual_review", "reason": "Human review"}), self.device, "mls qos")]
        self.assertEqual(exit_code(manual), 0)
        self.assertEqual(exit_code(manual, strict_manual=True), 3)
        low_fail = [evaluate_rule(rule(severity="low"), self.device, "hostname sw1")]
        self.assertEqual(exit_code([low_fail[0], unknown[0]], fail_on="high"), 3)
        report = report_markdown(self.device, results)
        self.assertIn("| V-1 | medium | FAIL |", report)
        unsorted = [
            evaluate_rule(rule(control_id="V-LOW", severity="low"), self.device, "mls qos"),
            evaluate_rule(rule(control_id="V-HIGH", severity="high"), self.device, "mls qos"),
        ]
        rendered = report_markdown(self.device, unsorted)
        self.assertLess(rendered.index("| V-HIGH |"), rendered.index("| V-LOW |"))

    def test_smoke_harness_uses_synthetic_fixture_not_legacy_config(self):
        repo_root = Path(__file__).resolve().parents[1]
        fixture = repo_root / "examples" / "configs" / "stig-sample-sw1.cfg"
        harness = repo_root / "tools" / "stig_config_smoke.py"
        old_harness = repo_root / "tools" / "test_stig_config.py"
        self.assertTrue(fixture.is_file())
        self.assertTrue(harness.is_file())
        self.assertFalse(old_harness.exists())
        config = fixture.read_text(encoding="utf-8")
        self.assertIn("hostname synthetic-sw1", config)
        self.assertIn("192.0.2.", config)
        for required in (
            "aaa new-model", "tacacs server AUTH_A", "radius server RADIUS_TEST",
            "line vty 0 4", "access-class MGMT_SYNTHETIC in",
            "interface GigabitEthernet1/0/1", "switchport mode access",
            "switchport voice vlan 20", "interface GigabitEthernet1/0/24",
            "switchport mode trunk", "switchport trunk allowed vlan",
        ):
            with self.subTest(required=required):
                self.assertIn(required, config)
        harness_source = harness.read_text(encoding="utf-8")
        self.assertIn("examples", harness_source)
        self.assertIn("stig-sample-sw1.cfg", harness_source)
        self.assertNotIn("config" + ".old", harness_source)

        # Scan test/tool source references only; never open the legacy config itself.
        for source_root in (repo_root / "tests", repo_root / "tools"):
            for source in source_root.rglob("*.py"):
                if source == Path(__file__):
                    continue
                self.assertNotIn("config" + ".old", source.read_text(encoding="utf-8"), str(source))

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

    def test_evaluate_rule_levels_standard_only_dual_and_pro_only(self):
        standard_only = rule(
            level="standard", standard_check={"type": "config_line_present", "line": "mls qos"},
        )
        standard_row = evaluate_rule_levels(standard_only, self.device, "mls qos", level="pro")
        self.assertEqual(standard_row.standard.status, "PASS")
        self.assertIsNone(standard_row.pro)

        dual = rule(
            level="standard",
            severity="high",
            standard_check={"type": "config_line_present", "line": "mls qos"},
            pro_check={"type": "config_line_present", "line": "spanning-tree bpduguard enable"},
            recommendation="Enable BPDU guard on access ports.",
            rationale="Helps reduce accidental Layer 2 loops.",
        )
        dual_row = evaluate_rule_levels(dual, self.device, "mls qos", level="pro")
        self.assertEqual(dual_row.standard.status, "PASS")
        self.assertEqual(dual_row.standard.depth, "presence")
        self.assertEqual(dual_row.pro.status, "FAIL")
        self.assertEqual(dual_row.pro.depth, "applied")
        self.assertEqual(exit_code([dual_row]), 0)
        self.assertEqual(exit_code([dual_row], fail_on_pro="high"), 2)
        standard_run = evaluate_rule_levels(dual, self.device, "mls qos", level="standard")
        self.assertEqual(standard_run.standard.status, "PASS")
        self.assertEqual(standard_run.pro.status, "NOT_RUN")

        pro_only = rule(
            level="pro", standard_check=None,
            pro_check={"type": "config_line_present", "line": "spanning-tree bpduguard enable"},
            recommendation="Enable BPDU guard.",
        )
        pro_row = evaluate_rule_levels(pro_only, self.device, "mls qos", level="pro")
        self.assertIsNone(pro_row.standard)
        self.assertEqual(pro_row.pro.status, "FAIL")

    def test_loader_validates_strategy_details_for_both_standard_and_pro_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = {
                "status": "approved", "automation_level": "automated", "control_id": "V-DUAL",
                "rule_id": "SV-DUAL", "title": "Dual synthetic rule", "severity": "medium",
                "target_platform": "cisco_ios", "level": "standard",
                "standard_check": {"type": "config_line_present", "line": "mls qos"},
                "pro_check": {"type": "evidence_regex", "evidence_key": "show_version", "pattern": "["},
                "recommendation": "Review applied configuration.",
            }
            (root / "dual.json").write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid evidence regex"):
                load_approved_rules(root)

    def test_rule_level_loader_rejects_invalid_schema_combinations_and_unknown_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = {
                "status": "approved", "automation_level": "automated", "control_id": "V-1",
                "rule_id": "SV-1", "title": "T", "severity": "medium", "target_platform": "cisco_ios",
            }
            cases = [
                ({**base, "level": "standard"}, "standard_check"),
                ({**base, "level": "pro"}, "pro_check"),
                ({**base, "level": "pro", "standard_check": {"type": "config_line_present", "line": "mls qos"}, "pro_check": {"type": "config_line_present", "line": "mls qos"}, "recommendation": "Advice"}, "forbids standard_check"),
                ({**base, "level": "pro", "pro_check": {"type": "config_line_present", "line": "mls qos"}}, "recommendation"),
                ({**base, "level": "standard", "standard_check": {"type": "config_line_present", "line": "mls qos"}, "unexpected": True}, "unknown approved-rule key"),
            ]
            for payload, message in cases:
                with self.subTest(message=message):
                    for item in root.iterdir():
                        item.unlink()
                    (root / "rule.json").write_text(json.dumps(payload), encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, message):
                        load_approved_rules(root)

    def test_level_waiver_is_applied_to_both_cells_with_device_scope(self):
        dual = rule(
            level="standard", standard_check={"type": "config_line_present", "line": "mls qos"},
            pro_check={"type": "config_line_present", "line": "spanning-tree bpduguard enable"},
            recommendation="Enable BPDU guard.",
        )
        waiver = Waiver("V-1", "Synthetic exception", "reviewer", date(2027, 1, 1), ("sw1",))
        row = evaluate_rule_levels(dual, self.device, "hostname sw1", waivers={"V-1": waiver}, today=date(2026, 1, 1))
        self.assertEqual(row.standard.status, "WAIVED")
        self.assertEqual(row.pro.status, "WAIVED")

    def test_profile_filter(self):
        r = rule(profiles=("switch-access",))
        result = assess([r], DeviceContext("sw1", "cisco_ios", family="Catalyst 2960-X", profiles=("datacenter",)), "mls qos")
        self.assertEqual(result[0].status, "NOT_APPLICABLE")
        unverified = assess([r], DeviceContext("sw1", "cisco_ios", family="Catalyst 2960-X"), "mls qos")
        self.assertEqual(unverified[0].status, "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
