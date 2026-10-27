import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from netagent.cli import main


class TestAssessCLI(unittest.TestCase):
    def test_no_approved_rules_reports_no_rules_and_writes_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rules = root / "rules"
            rules.mkdir()
            evidence = root / "evidence"
            evidence.mkdir()
            catalog = root / "catalog.json"
            catalog.write_text(json.dumps({
                "catalog_version": "synthetic-v1",
                "sources": [{"stig": "L2S", "benchmark_id": "SYN-L2S", "title": "Synthetic L2S",
                             "file": "synthetic.xml", "date": "01 Jan 2026", "version": "1", "release": "1"}],
                "controls": [{"control_id": "V-SYN-1", "rule_id": "SV-SYN-1_rule", "stig_id": "CISC-SYN-1",
                              "stig": "L2S", "severity": "high", "title": "Synthetic control",
                              "check_text": "Synthetic check", "fix_text": "", "description": "", "cci": []}],
            }), encoding="utf-8")
            out = root / "report.json"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main([
                    "assess", "--hostname", "synthetic-sw1", "--evidence-dir", str(evidence),
                    "--rules", str(rules), "--catalog", str(catalog), "--format", "json", "--out", str(out),
                ])
            self.assertEqual(code, 0)
            self.assertIn("nothing executed", stdout.getvalue())
            report = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(report["verdict"]["code"], "NO_RULES")

    def test_end_to_end_evidence_to_all_five_formats_with_synthetic_approved_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rules = root / "rules"
            rules.mkdir()
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "show_running_config.txt").write_text(
                "service timestamps log datetime localtime\n", encoding="utf-8"
            )
            (rules / "synthetic-rule.json").write_text(json.dumps({
                "status": "approved", "automation_level": "automated", "control_id": "V-SYN-1",
                "rule_id": "SV-SYN-1r1_rule", "title": "Synthetic timestamp rule", "severity": "high",
                "target_platform": "cisco_ios", "target_families": ["Catalyst 2960-X"],
                "level": "standard", "standard_check": {"type": "config_line_present",
                    "line": "service timestamps log datetime localtime"},
                "stig_id": "CISC-SYN-1", "stig_part": "L2S",
            }), encoding="utf-8")
            catalog = root / "catalog.json"
            catalog.write_text(json.dumps({
                "catalog_version": "synthetic-v1",
                "sources": [{"stig": "L2S", "benchmark_id": "SYN-L2S", "title": "Synthetic L2S",
                             "file": "synthetic.xml", "date": "01 Jan 2026", "version": "1", "release": "1"}],
                "controls": [{"control_id": "V-SYN-1", "rule_id": "SV-SYN-1r1_rule", "stig_id": "CISC-SYN-1",
                              "stig": "L2S", "severity": "high", "title": "Synthetic timestamp rule",
                              "check_text": "Synthetic check", "fix_text": "", "description": "", "cci": []}],
            }), encoding="utf-8")
            for format_name, suffix in (("md", "md"), ("html", "html"), ("json", "json"),
                                        ("cklb", "cklb"), ("xccdf", "xml")):
                out = root / f"report.{suffix}"
                code = main([
                    "assess", "--hostname", "synthetic-sw1", "--evidence-dir", str(evidence),
                    "--rules", str(rules), "--catalog", str(catalog), "--cklb-template",
                    str(Path(__file__).resolve().parents[1] / "examples" / "sample-synthetic.cklb"),
                    "--stig-part", "L2S", "--family", "Catalyst 2960-X", "--level", "pro",
                    "--format", format_name, "--out", str(out),
                ])
                self.assertEqual(code, 0, format_name)
                self.assertTrue(out.is_file(), format_name)
                rendered = out.read_text(encoding="utf-8")
                self.assertTrue(rendered.strip(), format_name)
                if format_name == "json":
                    self.assertEqual(json.loads(rendered)["verdict"]["code"], "ACHIEVED")
                elif format_name == "cklb":
                    self.assertEqual(json.loads(rendered)["stigs"][0]["rules"][0]["status"], "not_a_finding")
                elif format_name == "xccdf":
                    self.assertIn("TestResult", rendered)

    def test_standard_level_cli_does_not_evaluate_pro_or_change_minimum_verdict(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rules = root / "rules"
            rules.mkdir()
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "show_running_config.txt").write_text("mls qos\n", encoding="utf-8")
            (rules / "dual-rule.json").write_text(json.dumps({
                "status": "approved", "automation_level": "automated", "control_id": "V-SYN-DUAL",
                "rule_id": "SV-SYN-DUAL_rule", "title": "Synthetic dual-level control", "severity": "high",
                "target_platform": "cisco_ios", "target_families": ["Catalyst 2960-X"],
                "level": "standard",
                "standard_check": {"type": "config_line_present", "line": "mls qos"},
                "pro_check": {"type": "config_line_present", "line": "spanning-tree bpduguard enable"},
                "recommendation": "Enable BPDU guard on access ports.",
            }), encoding="utf-8")
            catalog = root / "catalog.json"
            catalog.write_text(json.dumps({
                "catalog_version": "synthetic-v1",
                "sources": [],
                "controls": [{
                    "control_id": "V-SYN-DUAL", "rule_id": "SV-SYN-DUAL_rule", "stig_id": "CISC-SYN-DUAL",
                    "stig": "L2S", "severity": "high", "title": "Synthetic dual-level control",
                    "check_text": "Synthetic check", "fix_text": "", "description": "", "cci": [],
                }],
            }), encoding="utf-8")
            out = root / "report.json"
            code = main([
                "assess", "--hostname", "synthetic-sw1", "--evidence-dir", str(evidence),
                "--rules", str(rules), "--catalog", str(catalog), "--family", "Catalyst 2960-X",
                "--level", "standard", "--format", "json", "--out", str(out),
            ])
            self.assertEqual(code, 0)
            report = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(report["run_metadata"]["level"], "standard")
            self.assertEqual(report["rows"][0]["standard"]["status"], "PASS")
            self.assertEqual(report["rows"][0]["pro"]["status"], "NOT_RUN")
            self.assertEqual(report["verdict"]["code"], "ACHIEVED")
            self.assertEqual(report["pro_counts"]["NOT_RUN"], 1)

    def test_assess_parser_exposes_requested_controls(self):
        from netagent.cli import build_parser
        args = build_parser().parse_args([
            "assess", "--hostname", "synthetic-sw1", "--evidence-dir", "evidence",
            "--level", "standard", "--fail-on", "medium", "--fail-on-pro", "high",
            "--allow-unknown", "--strict-manual", "--roles-dir", "roles", "--waivers", "waivers.json",
            "--format", "xccdf", "--out", "report.xml",
        ])
        self.assertEqual(args.level, "standard")
        self.assertEqual(args.fail_on, "medium")
        self.assertEqual(args.fail_on_pro, "high")
        self.assertTrue(args.allow_unknown)
        self.assertTrue(args.strict_manual)
        self.assertEqual(args.roles_dir, "roles")
        self.assertEqual(args.format, "xccdf")


if __name__ == "__main__":
    unittest.main()
