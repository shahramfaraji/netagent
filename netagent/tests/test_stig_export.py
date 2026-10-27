import json
import unittest
from pathlib import Path
import xml.etree.ElementTree as ET

from netagent.stig_assessment import CheckCell, RuleRow
from netagent.stig_export import (
    XCCDF_NS, build_cklb, build_xccdf_testresult, render_cklb, render_xccdf_testresult,
)

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "examples" / "sample-synthetic.cklb"


def make_row(control_id, standard_status, pro_status=None, *, level="standard", standard_depth="presence"):
    standard = CheckCell(standard_status, "Synthetic standard detail", standard_depth) if standard_status else None
    pro = CheckCell(pro_status, "Synthetic pro detail", "applied", "Synthetic recommendation") if pro_status else None
    return RuleRow(
        control_id=control_id, rule_id=f"SV-{control_id}", title=f"Synthetic {control_id}",
        severity="high", standard=standard, pro=pro, level=level, rationale="Synthetic rationale",
        stig_id=f"CISC-{control_id}", stig_part="L2S", evidence_refs=("synthetic-evidence.txt",),
    )


def catalog_fixture():
    return {
        "catalog_version": "Y26M04",
        "sources": [
            {"stig": "L2S", "benchmark_id": "Cisco_IOS_Switch_L2S_STIG", "title": "Synthetic Cisco L2S STIG",
             "file": "synthetic-xccdf.xml", "date": "01 Jan 2026", "version": "3", "release": "1"},
            {"stig": "RTR", "benchmark_id": "Cisco_IOS_Switch_RTR_STIG", "title": "Synthetic Cisco RTR STIG",
             "file": "synthetic-rtr.xml", "date": "01 Jan 2026", "version": "3", "release": "1"},
        ],
        "controls": [
            {"control_id": "V-SYN-1", "rule_id": "SV-SYN-1r1_rule", "stig_id": "CISC-SYN-1", "stig": "L2S",
             "severity": "high", "title": "Synthetic pass", "check_text": "Synthetic check", "fix_text": "Synthetic fix",
             "description": "Synthetic discussion", "cci": ["CCI-000001"]},
            {"control_id": "V-SYN-2", "rule_id": "SV-SYN-2r1_rule", "stig_id": "CISC-SYN-2", "stig": "L2S",
             "severity": "medium", "title": "Synthetic unreviewed", "check_text": "Synthetic check", "fix_text": "",
             "description": "", "cci": []},
            {"control_id": "V-SYN-3", "rule_id": "SV-SYN-3r1_rule", "stig_id": "CISC-SYN-3", "stig": "L2S",
             "severity": "low", "title": "Synthetic waived", "check_text": "Synthetic check", "fix_text": "",
             "description": "", "cci": []},
            {"control_id": "V-SYN-4", "rule_id": "SV-SYN-4r1_rule", "stig_id": "CISC-SYN-4", "stig": "L2S",
             "severity": "low", "title": "Synthetic not applicable", "check_text": "Synthetic check", "fix_text": "",
             "description": "", "cci": []},
            {"control_id": "V-SYN-5", "rule_id": "SV-SYN-5r1_rule", "stig_id": "CISC-SYN-5", "stig": "L2S",
             "severity": "low", "title": "Synthetic manual", "check_text": "Synthetic check", "fix_text": "",
             "description": "", "cci": []},
            {"control_id": "V-SYN-6", "rule_id": "SV-SYN-6r1_rule", "stig_id": "CISC-SYN-6", "stig": "L2S",
             "severity": "low", "title": "Synthetic unknown", "check_text": "Synthetic check", "fix_text": "",
             "description": "", "cci": []},
            {"control_id": "V-SYN-7", "rule_id": "SV-SYN-7r1_rule", "stig_id": "CISC-SYN-7", "stig": "L2S",
             "severity": "low", "title": "Synthetic fail", "check_text": "Synthetic check", "fix_text": "",
             "description": "", "cci": []},
            {"control_id": "V-RTR-1", "rule_id": "SV-RTR-1r1_rule", "stig_id": "CISC-RTR-1", "stig": "RTR",
             "severity": "low", "title": "Other part", "check_text": "Synthetic check", "fix_text": "",
             "description": "", "cci": []},
        ],
    }


class TestStigExport(unittest.TestCase):
    def setUp(self):
        self.catalog = catalog_fixture()
        self.rows = [
            make_row("V-SYN-1", "PASS", "FAIL"),
            make_row("V-SYN-3", "WAIVED", "WAIVED"),
            make_row("V-SYN-4", "NOT_APPLICABLE"),
            make_row("V-SYN-5", "MANUAL"),
            make_row("V-SYN-6", "UNKNOWN"),
            make_row("V-SYN-7", "FAIL"),
        ]

    def test_cklb_includes_all_controls_in_selected_part_and_maps_statuses(self):
        result = build_cklb(self.catalog, self.rows, TEMPLATE, "L2S", "synthetic-sw1", "pro")
        self.assertEqual(result["stigs"][0]["size"], 7)
        self.assertEqual([item["group_id"] for item in result["stigs"][0]["rules"]],
                         ["V-SYN-1", "V-SYN-2", "V-SYN-3", "V-SYN-4", "V-SYN-5", "V-SYN-6", "V-SYN-7"])
        by_id = {item["group_id"]: item for item in result["stigs"][0]["rules"]}
        self.assertEqual(by_id["V-SYN-1"]["status"], "open")
        self.assertIn("presence only", by_id["V-SYN-1"]["comments"])
        self.assertIn("Standard: PASS", by_id["V-SYN-1"]["comments"])
        self.assertIn("Pro: FAIL", by_id["V-SYN-1"]["comments"])
        self.assertEqual(by_id["V-SYN-2"]["status"], "not_reviewed")
        self.assertEqual(by_id["V-SYN-3"]["status"], "not_reviewed")
        self.assertEqual(by_id["V-SYN-3"]["finding_details"], "")
        self.assertEqual(by_id["V-SYN-4"]["status"], "not_applicable")
        self.assertEqual(by_id["V-SYN-5"]["status"], "not_reviewed")
        self.assertEqual(by_id["V-SYN-6"]["status"], "not_reviewed")
        self.assertEqual(by_id["V-SYN-7"]["status"], "open")
        self.assertEqual(result["target_data"]["host_name"], "synthetic-sw1")
        self.assertEqual(result["stigs"][0]["stig_id"], "Cisco_IOS_Switch_L2S_STIG")
        self.assertEqual(result["stigs"][0]["rules"][0]["status"], "open")
        self.assertNotIn("V-RTR-1", json.dumps(result))

    def test_standard_level_uses_standard_cell_and_waiver_never_becomes_not_a_finding(self):
        result = build_cklb(self.catalog, self.rows, TEMPLATE, "L2S", "synthetic-sw1", "standard")
        by_id = {item["group_id"]: item for item in result["stigs"][0]["rules"]}
        self.assertEqual(by_id["V-SYN-1"]["status"], "not_a_finding")
        self.assertEqual(by_id["V-SYN-3"]["status"], "not_reviewed")
        self.assertIn("Pro: WAIVED", by_id["V-SYN-3"]["comments"])

    def test_xccdf_11_export_includes_all_controls_and_safe_result_mapping(self):
        text = render_xccdf_testresult(self.catalog, self.rows, "L2S", "synthetic-sw1", "pro")
        root = ET.fromstring(text)
        q = lambda name: f"{{{XCCDF_NS}}}{name}"
        self.assertEqual(root.tag, q("TestResult"))
        results = root.findall(q("rule-result"))
        self.assertEqual(len(results), 7)
        mapped = {item.attrib["idref"]: item.findtext(q("result")) for item in results}
        self.assertEqual(mapped["SV-SYN-1r1_rule"], "fail")
        self.assertEqual(mapped["SV-SYN-2r1_rule"], "notchecked")
        self.assertEqual(mapped["SV-SYN-3r1_rule"], "notchecked")
        self.assertEqual(mapped["SV-SYN-4r1_rule"], "notapplicable")
        self.assertEqual(mapped["SV-SYN-5r1_rule"], "notchecked")
        self.assertEqual(mapped["SV-SYN-6r1_rule"], "notchecked")
        self.assertEqual(mapped["SV-SYN-7r1_rule"], "fail")
        self.assertIn("presence only", text)

    def test_export_redacts_secret_like_values_from_assessment_details(self):
        secret_row = RuleRow(
            control_id="V-SYN-1", rule_id="SV-SYN-1r1_rule", title="Synthetic secret redaction",
            severity="high", standard=CheckCell("FAIL", "username test secret 5 dont-print-this", "presence"),
            pro=CheckCell("FAIL", "snmp-server community dont-print-this-too", "applied"),
            level="standard",
        )
        result = build_cklb(self.catalog, [secret_row], TEMPLATE, "L2S", "synthetic-sw1", "pro")
        rendered = json.dumps(result)
        self.assertNotIn("dont-print-this", rendered)
        self.assertIn("<REDACTED>", rendered)

    def test_invalid_part_or_level_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unknown STIG part"):
            build_cklb(self.catalog, self.rows, TEMPLATE, "INVALID", "synthetic-sw1")
        with self.assertRaisesRegex(ValueError, "level"):
            build_xccdf_testresult(self.catalog, self.rows, "L2S", "synthetic-sw1", "invalid")


if __name__ == "__main__":
    unittest.main()
