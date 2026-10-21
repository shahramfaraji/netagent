import unittest
from pathlib import Path
from netagent.compliance import Rule, evaluate, load_rules, report_markdown, score

ROOT = Path(__file__).parent.parent / "examples"


class TestCompliance(unittest.TestCase):
    def setUp(self):
        self.rules = load_rules(ROOT / "rules/baseline.json")

    def test_clean_device(self):
        cfg = (ROOT / "configs/core-sw1.cfg").read_text()
        self.assertEqual(evaluate("core-sw1", "cisco_ios", cfg, self.rules), [])

    def test_bad_device_sorted_by_severity(self):
        cfg = (ROOT / "configs/edge-r1.cfg").read_text()
        fs = evaluate("edge-r1", "cisco_ios", cfg, self.rules)
        ids = [f.rule_id for f in fs]
        self.assertEqual(fs[0].severity, "critical")
        for rid in ("NO-TELNET", "SSH-V2", "NO-SNMP-PUBLIC", "NTP", "LOGGING", "PASSWORD-ENCRYPTION"):
            self.assertIn(rid, ids)
        self.assertLess(score(fs, len(self.rules)), 50)

    def test_platform_filter(self):
        fs = evaluate("fw1", "cisco_asa", "hostname fw1\n", self.rules)
        self.assertEqual({f.rule_id for f in fs}, {"NTP", "LOGGING"})

    def test_invalid_rules(self):
        with self.assertRaises(ValueError):
            Rule("x", "d", "urgent", must_contain=["a"])
        with self.assertRaises(ValueError):
            Rule("x", "d", "low")
        import re
        with self.assertRaises(re.error):
            Rule("x", "d", "low", must_contain=["("])

    def test_report(self):
        cfg = (ROOT / "configs/edge-r1.cfg").read_text()
        md = report_markdown({"edge-r1": evaluate("edge-r1", "cisco_ios", cfg, self.rules)}, len(self.rules))
        self.assertIn("[CRITICAL] NO-TELNET", md)
