import unittest
from pathlib import Path

from netagent.compliance import evaluate_detailed, load_rules, report_markdown
from netagent.routeros import merge_routeros_data, parse_export, parse_print_detail

ROOT = Path(__file__).parent.parent

SAFE_CONFIG = '''# RouterOS 7.23.7 lab export
/ip service
set ftp disabled=yes
set telnet disabled=yes
set www disabled=yes
set api disabled=yes
set api-ssl disabled=yes
set ssh address=192.0.2.0/24 disabled=no
set winbox address=192.0.2.0/24 disabled=no
/interface pptp-server server
set enabled=no
/system ntp client servers
add address=time.example.invalid
/system logging action
add name=remote target=remote remote=192.0.2.50
/system logging
add topics=info action=remote
/snmp
set enabled=no
/user
add name=operator group=full
/ip ssh
set strong-crypto=yes
/tool mac-server
set allowed-interface-list=MGMT
/tool mac-server mac-winbox
set allowed-interface-list=MGMT
/ip neighbor discovery-settings
set discover-interface-list=MGMT
/ip firewall filter
add chain=input action=accept protocol=tcp dst-port=22 src-address=192.0.2.0/24
add chain=input action=drop
/ip dns
set allow-remote-requests=no
/tool bandwidth-server
set enabled=no
'''


class TestMikroTikRules(unittest.TestCase):
    def setUp(self):
        self.rules = load_rules(ROOT / "examples" / "rules" / "mikrotik_routeros.json")
        self.config = (ROOT / "examples" / "configs" / "mikrotik-lab.cfg").read_text(encoding="utf-8")

    def _rule(self, rule_id):
        return next(rule for rule in self.rules if rule.id == rule_id)

    def test_current_fixture_flags_enabled_pptp_without_real_config_dependency(self):
        findings, unknowns, _ = evaluate_detailed("lab-router", "mikrotik_routeros", self.config, self.rules)
        self.assertIn("MT-PPTP-ENABLED", {finding.rule_id for finding in findings})
        self.assertTrue(unknowns)  # Compact exports omit values that must be collected separately.

    def test_absent_sections_are_unknown_not_pass_or_violation(self):
        findings, unknowns, evaluated = evaluate_detailed(
            "r1", "mikrotik_routeros", "# RouterOS export\n/system identity\nset name=r1\n", self.rules
        )
        self.assertEqual(findings, [])
        self.assertEqual(evaluated, 0)
        self.assertEqual(len(unknowns), len(self.rules))

    def test_telnet_address_and_disabled_no_are_not_a_false_negative(self):
        config = "/ip service\nset telnet address=10.0.0.0/8 disabled=no\n"
        findings, unknowns, evaluated = evaluate_detailed(
            "r1", "mikrotik_routeros", config, [self._rule("MT-SERVICE-TELNET")]
        )
        self.assertEqual([f.rule_id for f in findings], ["MT-SERVICE-TELNET"])
        self.assertEqual(unknowns, [])
        self.assertEqual(evaluated, 1)

    def test_enabled_service_missing_from_compact_export_is_unknown(self):
        findings, unknowns, evaluated = evaluate_detailed(
            "r1", "mikrotik_routeros", "/system identity\nset name=r1\n", [self._rule("MT-SERVICE-FTP")]
        )
        self.assertEqual(findings, [])
        self.assertEqual([u.rule_id for u in unknowns], ["MT-SERVICE-FTP"])
        self.assertEqual(evaluated, 0)

    def test_structured_service_print_detects_enabled_default_service(self):
        artifacts = {"routeros_ip_service": '0 name="ftp" port=21 disabled=no\n1 name="telnet" port=23 disabled=yes\n'}
        findings, unknowns, evaluated = evaluate_detailed(
            "r1", "mikrotik_routeros", "# compact export omits default services\n", [self._rule("MT-SERVICE-FTP")], artifacts
        )
        self.assertEqual([f.rule_id for f in findings], ["MT-SERVICE-FTP"])
        self.assertEqual(unknowns, [])
        self.assertEqual(evaluated, 1)

    def test_unparseable_structured_output_does_not_fall_back_to_export_pass(self):
        config = "/ip service\nset ftp disabled=yes\n"
        artifacts = {"routeros_ip_service": "bad command name print (line 1 column 1)"}
        findings, unknowns, evaluated = evaluate_detailed(
            "r1", "mikrotik_routeros", config, [self._rule("MT-SERVICE-FTP")], artifacts
        )
        self.assertEqual(findings, [])
        self.assertEqual([u.rule_id for u in unknowns], ["MT-SERVICE-FTP"])
        self.assertEqual(evaluated, 0)

    def test_remote_syslog_action_and_remote_address_on_different_add_lines_do_not_pass(self):
        config = "/system logging action\nadd name=remote target=remote\nadd name=other remote=192.0.2.50\n/system logging\nadd topics=info action=remote\n"
        findings, unknowns, evaluated = evaluate_detailed(
            "r1", "mikrotik_routeros", config, [self._rule("MT-REMOTE-SYSLOG")]
        )
        self.assertEqual([f.rule_id for f in findings], ["MT-REMOTE-SYSLOG"])
        self.assertEqual(unknowns, [])
        self.assertEqual(evaluated, 1)

    def test_compliant_fixture_passes_all_configured_checks(self):
        rules = load_rules(ROOT / "examples" / "rules" / "mikrotik_routeros.json")
        next(r for r in rules if r.id == "MT-MINIMUM-VERSION").options["minimum_version"] = "7.10"
        findings, unknowns, evaluated = evaluate_detailed("safe-fixture", "mikrotik_routeros", SAFE_CONFIG, rules)
        self.assertEqual(findings, [])
        self.assertEqual([u.rule_id for u in unknowns], ["MT-ADMIN-PASSWORD-POLICY"])
        self.assertEqual(evaluated, len(rules) - 1)

    def test_insecure_fixture_flags_enabled_services_and_unsafe_settings(self):
        config = SAFE_CONFIG.replace("set telnet disabled=yes", "set telnet address=10.0.0.0/8 disabled=no")
        config = config.replace("set ftp disabled=yes", "set ftp disabled=no")
        config = config.replace("set enabled=no", "set enabled=yes", 1)
        config = config.replace("target=remote remote=192.0.2.50", "target=remote")
        config = config.replace("set allow-remote-requests=no", "set allow-remote-requests=yes")
        config = config.replace("set enabled=no", "set enabled=yes", 1)
        next(r for r in self.rules if r.id == "MT-MINIMUM-VERSION").options["minimum_version"] = "7.10"
        findings, unknowns, _ = evaluate_detailed("unsafe-fixture", "mikrotik_routeros", config, self.rules)
        ids = {f.rule_id for f in findings}
        self.assertTrue({"MT-SERVICE-FTP", "MT-SERVICE-TELNET", "MT-PPTP-ENABLED", "MT-DNS-REMOTE-REQUESTS"}.issubset(ids))
        self.assertEqual([u.rule_id for u in unknowns], ["MT-ADMIN-PASSWORD-POLICY"])

    def test_parser_handles_continuation_and_quoted_values(self):
        parsed = parse_export('/system identity\nset name="lab \\\n router"\n')
        self.assertEqual(parsed["sections"]["/system identity"][0]["name"], "lab router")
        detail = parse_print_detail('0 name="lab router" address=192.0.2.5\n', "test")
        self.assertEqual(detail["records"][0]["name"], "lab router")

    def test_version_rule_is_unknown_until_minimum_is_configured(self):
        rule = self._rule("MT-MINIMUM-VERSION")
        findings, unknowns, evaluated = evaluate_detailed("r1", "mikrotik_routeros", SAFE_CONFIG, [rule])
        self.assertEqual(findings, [])
        self.assertEqual([u.rule_id for u in unknowns], ["MT-MINIMUM-VERSION"])
        self.assertEqual(evaluated, 0)
        rule.options["minimum_version"] = "7.24"
        findings, unknowns, evaluated = evaluate_detailed("r1", "mikrotik_routeros", SAFE_CONFIG, [rule])
        self.assertEqual([f.rule_id for f in findings], ["MT-MINIMUM-VERSION"])
        self.assertEqual(unknowns, [])
        self.assertEqual(evaluated, 1)

    def test_report_hides_score_when_any_check_is_unknown(self):
        findings, unknowns, evaluated = evaluate_detailed("lab-router", "mikrotik_routeros", self.config, self.rules)
        report = report_markdown({"lab-router": findings}, len(self.rules), {"lab-router": unknowns}, {"lab-router": evaluated})
        self.assertIn("| lab-router | N/A |", report)
        self.assertIn("**[UNKNOWN]", report)


if __name__ == "__main__":
    unittest.main()
