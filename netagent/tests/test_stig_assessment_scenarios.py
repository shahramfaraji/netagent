import unittest

from netagent.stig_assessment import AssessmentRule, DeviceContext, evaluate_rule


def make_rule(control_id, strategy, *, severity="medium"):
    return AssessmentRule(
        control_id=control_id,
        rule_id=f"SV-{control_id}_rule",
        title=f"Synthetic test for {control_id}",
        severity=severity,
        status="approved",
        automation_level="automated",
        target_platform="cisco_ios",
        target_families=("Catalyst 2960-X",),
        check_strategy=strategy,
    )


class TestStigAssessmentStrategyScenarios(unittest.TestCase):
    """Positive/negative synthetic scenarios for each assessment strategy.

    Fixtures contain only documentation-range addresses and synthetic account
    strings; no actual device credentials are used.
    """

    def setUp(self):
        self.device = DeviceContext("synthetic-sw", "cisco_ios", family="Catalyst 2960-X")

    def status(self, control_id, strategy, config, evidence=None):
        return evaluate_rule(make_rule(control_id, strategy), self.device, config, evidence).status

    def test_config_line_present_positive_negative_and_comment(self):
        strategy = {"type": "config_line_present", "line": "mls qos"}
        self.assertEqual(self.status("T-01", strategy, "hostname sw\nmls qos\n"), "PASS")
        self.assertEqual(self.status("T-01", strategy, "hostname sw\n"), "FAIL")
        self.assertEqual(self.status("T-01", strategy, "! mls qos\nhostname sw\n"), "FAIL")
        self.assertEqual(self.status("T-01", strategy, ""), "UNKNOWN")

    def test_config_paths_present_positive_negative_and_misplaced_directive(self):
        strategy = {
            "type": "config_paths_present",
            "paths": [["archive", "log config", "logging enable"]],
        }
        good = "archive\n log config\n  logging enable\n!\n"
        missing = "archive\n log config\n!\n"
        misplaced = "archive\n!\n log config\n  logging enable\n"
        self.assertEqual(self.status("T-02", strategy, good), "PASS")
        self.assertEqual(self.status("T-02", strategy, missing), "FAIL")
        self.assertEqual(self.status("T-02", strategy, misplaced), "FAIL")
        self.assertEqual(self.status("T-02", strategy, None), "UNKNOWN")

    def test_config_paths_and_regex_requires_both_path_and_regex(self):
        strategy = {
            "type": "config_paths_and_regex",
            "paths": [["archive", "log config", "logging enable"]],
            "patterns": [{
                "pattern": r"(?im)^aaa new-model$",
                "description": "AAA global mode",
            }],
        }
        good = "aaa new-model\narchive\n log config\n  logging enable\n"
        missing_path = "aaa new-model\narchive\n log config\n"
        missing_pattern = "archive\n log config\n  logging enable\n"
        self.assertEqual(self.status("T-03", strategy, good), "PASS")
        self.assertEqual(self.status("T-03", strategy, missing_path), "FAIL")
        self.assertEqual(self.status("T-03", strategy, missing_pattern), "FAIL")

    def test_common_criteria_policy_positive_and_negative(self):
        strategy = {"type": "common_criteria_policy", "directive": "min-length 15"}
        good = (
            "aaa common-criteria policy POLICY_A\n"
            " min-length 15\n"
            "!\n"
            "username admin common-criteria-policy POLICY_A secret 9 synthetic\n"
        )
        directive_missing = (
            "aaa common-criteria policy POLICY_A\n"
            " upper-case 1\n"
            "!\n"
            "username admin common-criteria-policy POLICY_A secret 9 synthetic\n"
        )
        account_unbound = (
            "aaa common-criteria policy POLICY_A\n"
            " min-length 15\n"
            "!\n"
            "username admin secret 9 synthetic\n"
        )
        self.assertEqual(self.status("T-04", strategy, good), "PASS")
        self.assertEqual(self.status("T-04", strategy, directive_missing), "FAIL")
        self.assertEqual(self.status("T-04", strategy, account_unbound), "FAIL")

    def test_admin_auth_server_count_follows_default_login_method(self):
        strategy = {"type": "admin_auth_server_count", "min_count": 2}
        one_tacacs_plus_unrelated_radius = (
            "aaa authentication login default group tacacs+ local\n"
            "tacacs-server host 192.0.2.10\n"
            "radius server NOT_USED_BY_DEFAULT_LOGIN\n"
            " address ipv4 192.0.2.20 auth-port 1812 acct-port 1813\n"
        )
        two_tacacs = one_tacacs_plus_unrelated_radius + "tacacs-server host 192.0.2.11\n"
        missing_login = "tacacs-server host 192.0.2.10\ntacacs-server host 192.0.2.11\n"
        self.assertEqual(self.status("T-05", strategy, one_tacacs_plus_unrelated_radius), "FAIL")
        self.assertEqual(self.status("T-05", strategy, two_tacacs), "MANUAL")
        self.assertEqual(self.status("T-05", strategy, missing_login), "FAIL")
        self.assertEqual(self.status("T-05", strategy, ""), "UNKNOWN")

    def test_emergency_local_account_precheck(self):
        strategy = {"type": "emergency_local_account"}
        good_precheck = (
            "username emergency privilege 10 common-criteria-policy POLICY_A secret 9 synthetic\n"
            "aaa common-criteria policy POLICY_A\n"
            " min-length 15\n"
            "!\n"
            "aaa authentication login default group tacacs+ local\n"
        )
        missing_policy = good_precheck.replace(" common-criteria-policy POLICY_A", "")
        multiple_accounts = good_precheck + "username spare privilege 1 secret 9 synthetic\n"
        no_fallback = good_precheck.replace("aaa authentication login default group tacacs+ local\n", "")
        self.assertEqual(self.status("T-06", strategy, good_precheck), "MANUAL")
        self.assertEqual(self.status("T-06", strategy, missing_policy), "FAIL")
        self.assertEqual(self.status("T-06", strategy, multiple_accounts), "FAIL")
        self.assertEqual(self.status("T-06", strategy, no_fallback), "FAIL")

    def test_vty_management_acl_precheck(self):
        strategy = {"type": "vty_management_acl"}
        good_acl = (
            "line vty 0 4\n"
            " access-class MGMT in\n"
            " transport input ssh\n"
            "!\n"
            "line vty 5 15\n"
            " access-class MGMT in\n"
            " transport input ssh\n"
            "!\n"
            "ip access-list extended MGMT\n"
            " permit ip 192.0.2.0 0.0.0.255 any\n"
            " deny ip any any log-input\n"
        )
        no_access_class = "line vty 0 4\n transport input ssh\n"
        missing_acl = "line vty 0 4\n access-class MISSING in\n transport input ssh\n"
        missing_deny = (
            "line vty 0 4\n access-class MGMT in\n!\n"
            "ip access-list extended MGMT\n permit ip 192.0.2.0 0.0.0.255 any\n"
        )
        self.assertEqual(self.status("T-07", strategy, good_acl), "MANUAL")
        self.assertEqual(self.status("T-07", strategy, no_access_class), "FAIL")
        self.assertEqual(self.status("T-07", strategy, missing_acl), "FAIL")
        self.assertEqual(self.status("T-07", strategy, missing_deny), "FAIL")

    def test_config_regex_count_pass_fail_and_partial_manual(self):
        count_strategy = {
            "type": "config_regex_count",
            "pattern": r"(?im)^[ \t]*logging(?: host)?\s+192\.0\.2\.\d+\b",
            "min_count": 2,
        }
        one = "logging 192.0.2.10\n"
        two = one + "logging host 192.0.2.11\n"
        with_comment = one + "! logging 192.0.2.99\n"
        self.assertEqual(self.status("T-08", count_strategy, one), "FAIL")
        self.assertEqual(self.status("T-08", count_strategy, two), "PASS")
        self.assertEqual(self.status("T-08", count_strategy, with_comment), "FAIL")
        partial_strategy = {**count_strategy, "partial": True, "partial_note": "Delivery must be verified."}
        result = evaluate_rule(make_rule("T-08P", partial_strategy), self.device, two)
        self.assertEqual(result.status, "MANUAL")
        self.assertIn("Delivery must be verified", result.detail)

    def test_evidence_regex_pass_fail_and_unknown(self):
        strategy = {
            "type": "evidence_regex",
            "evidence_key": "show_vtp_status",
            "pattern": r"(?im)^VTP Version running\s*:\s*2$",
            "expect_match": True,
        }
        self.assertEqual(self.status("T-09", strategy, "hostname sw", {"show_vtp_status": "VTP Version running : 2"}), "PASS")
        self.assertEqual(self.status("T-09", strategy, "hostname sw", {"show_vtp_status": "VTP Version running : 3"}), "FAIL")
        self.assertEqual(self.status("T-09", strategy, "hostname sw", {}), "UNKNOWN")

    def test_manual_review_always_requires_human_review(self):
        strategy = {"type": "manual_review", "reason": "Validate operational behavior with a reviewer."}
        self.assertEqual(self.status("T-10", strategy, "mls qos"), "MANUAL")
        # This strategy expresses a human-review requirement, not a config predicate.
        # It remains MANUAL even when the config text is empty; evidence-based
        # strategies are responsible for returning UNKNOWN when their evidence is absent.
        self.assertEqual(self.status("T-10", strategy, ""), "MANUAL")


if __name__ == "__main__":
    unittest.main()
