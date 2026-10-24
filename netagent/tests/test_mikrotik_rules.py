import unittest
from pathlib import Path

from netagent.compliance import evaluate_detailed, load_rules, report_markdown


ROOT = Path(__file__).parent.parent


class TestMikroTikRules(unittest.TestCase):
    def setUp(self):
        self.rules = load_rules(ROOT / "examples" / "rules" / "mikrotik_routeros.json")
        self.config = (
            ROOT / "data" / "configs" / "mikrotik-28-222" / "latest.cfg"
        ).read_text(encoding="utf-8")

    def test_current_router_flags_enabled_pptp(self):
        findings, unknowns, evaluated = evaluate_detailed(
            "mikrotik-28-222", "mikrotik_routeros", self.config, self.rules
        )
        self.assertIn("MT-PPTP-ENABLED", {finding.rule_id for finding in findings})
        self.assertNotIn("MT-SERVICE-FTP", {finding.rule_id for finding in findings})
        self.assertNotIn("MT-SERVICE-TELNET", {finding.rule_id for finding in findings})
        self.assertEqual(evaluated, 6)
        self.assertEqual(
            {item.rule_id for item in unknowns},
            {"MT-NTP-CONFIGURED", "MT-REMOTE-SYSLOG", "MT-SNMP-ENABLED"},
        )

    def test_absent_section_is_unknown_not_a_pass_or_violation(self):
        findings, unknowns, evaluated = evaluate_detailed(
            "r1", "mikrotik_routeros", "# RouterOS export\n/system identity\nset name=r1\n", self.rules
        )
        self.assertEqual(findings, [])
        self.assertEqual(evaluated, 0)
        self.assertEqual(len(unknowns), 9)

    def test_report_hides_score_when_any_check_is_unknown(self):
        findings, unknowns, evaluated = evaluate_detailed(
            "mikrotik-28-222", "mikrotik_routeros", self.config, self.rules
        )
        report = report_markdown(
            {"mikrotik-28-222": findings},
            len(self.rules),
            {"mikrotik-28-222": unknowns},
            {"mikrotik-28-222": evaluated},
        )
        self.assertIn("| mikrotik-28-222 | N/A |", report)
        self.assertIn("**[UNKNOWN] MT-NTP-CONFIGURED**", report)
        self.assertIn("Rule score is a rule-weight summary, not a security percentage", report)


    def test_explicitly_compliant_fixture_passes_all_rules(self):
        config = """# RouterOS fixture
/ip service
set ftp disabled=yes
set telnet disabled=yes
set www disabled=yes
set api disabled=yes
set api-ssl disabled=yes
/interface pptp-server server
set enabled=no
/system ntp client servers
add address=time.example.invalid
/system logging action
add name=remote target=remote remote=192.0.2.50
/snmp
set enabled=no
"""
        findings, unknowns, evaluated = evaluate_detailed(
            "safe-fixture", "mikrotik_routeros", config, self.rules
        )
        self.assertEqual(findings, [])
        self.assertEqual(unknowns, [])
        self.assertEqual(evaluated, 9)

    def test_explicitly_insecure_fixture_flags_only_enabled_services(self):
        config = """# RouterOS fixture
/ip service
set ftp disabled=no
set telnet disabled=no
set www disabled=no
set api disabled=no
set api-ssl disabled=no
/interface pptp-server server
set enabled=yes
/system ntp client servers
add address=time.example.invalid
/system logging action
add name=remote target=remote remote=192.0.2.50
/snmp
set enabled=yes
"""
        findings, unknowns, evaluated = evaluate_detailed(
            "unsafe-fixture", "mikrotik_routeros", config, self.rules
        )
        self.assertEqual(
            {finding.rule_id for finding in findings},
            {
                "MT-SERVICE-FTP", "MT-SERVICE-TELNET", "MT-SERVICE-WWW",
                "MT-SERVICE-API", "MT-SERVICE-API-SSL", "MT-PPTP-ENABLED",
                "MT-SNMP-ENABLED",
            },
        )
        self.assertEqual(unknowns, [])
        self.assertEqual(evaluated, 9)

if __name__ == "__main__":
    unittest.main()
