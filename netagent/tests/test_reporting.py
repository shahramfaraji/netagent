import os
import unittest
from datetime import date
from pathlib import Path

from netagent.stig_assessment import (
    AssessmentRule, CheckCell, DeviceContext, RuleRow, Waiver, evaluate_rule_levels,
)
from netagent.reporting import (
    CELL_LABELS, build_json_report, minimum_verdict,
    render_html_report, render_json_report, render_markdown_report,
)


def row(control_id, status, *, level="standard", pro_status="NOT_RUN", detail="Synthetic detail", title="Synthetic title"):
    return RuleRow(
        control_id=control_id,
        rule_id=f"rule-{control_id}",
        title=title,
        severity="medium",
        standard=CheckCell(status, detail, "presence") if status is not None else None,
        pro=CheckCell(pro_status, "Pro detail", "applied", "Synthetic recommendation") if pro_status is not None else None,
        level=level,
        rationale="Synthetic rationale",
        source_ref={"note": "password 5 supersecret"},
        stig_id="STIG-SYN-1",
        stig_part="L2S",
        evidence_refs=("synthetic-evidence.txt",),
    )


def golden_report():
    device = DeviceContext("synthetic-golden-sw1", "cisco_ios", family="Catalyst 2960-X")
    rows = [
        row("CTRL-FAIL", "FAIL", title="Synthetic failed control", detail="missing mls qos", pro_status="MANUAL"),
        row("CTRL-PASS", "PASS", title="Synthetic passing control", detail="mls qos present", pro_status="PASS"),
    ]
    return build_json_report(
        device, rows, catalog_version="synthetic-golden-v1",
        run_metadata={"run_id": "golden-synthetic-fixed"},
    )


class TestReporting(unittest.TestCase):
    def test_markdown_and_html_match_golden_files(self):
        fixture_dir = Path(__file__).parent / "fixtures" / "reports"
        fixture_dir.mkdir(parents=True, exist_ok=True)
        outputs = {
            "synthetic-report.md": render_markdown_report(golden_report()),
            "synthetic-report.html": render_html_report(golden_report()),
        }
        if os.environ.get("UPDATE_REPORT_GOLDENS") == "1":
            for filename, content in outputs.items():
                (fixture_dir / filename).write_text(content, encoding="utf-8")
        for filename, content in outputs.items():
            path = fixture_dir / filename
            self.assertTrue(path.exists(), f"Missing golden fixture: {path}; set UPDATE_REPORT_GOLDENS=1 once to create it")
            self.assertEqual(path.read_text(encoding="utf-8"), content, f"Golden output changed: {filename}")

    def test_minimum_verdict_precedence_and_no_rules(self):
        self.assertEqual(minimum_verdict([])["code"], "NO_RULES")
        self.assertEqual(minimum_verdict([row("NA", "NOT_APPLICABLE")])["code"], "NO_RULES")
        self.assertEqual(minimum_verdict([row("P", "PASS")])["code"], "ACHIEVED")
        self.assertEqual(minimum_verdict([row("W", "WAIVED")])["code"], "ACHIEVED_WITH_WAIVERS")
        self.assertEqual(minimum_verdict([row("U", "UNKNOWN")])["code"], "INCOMPLETE")
        self.assertEqual(minimum_verdict([row("M", "MANUAL")])["code"], "INCOMPLETE")
        self.assertEqual(minimum_verdict([row("F", "FAIL"), row("U", "UNKNOWN")])["code"], "NOT_ACHIEVED")
        self.assertEqual(minimum_verdict([row("PRO", None, level="pro", pro_status="FAIL")])["code"], "NO_RULES")

    def test_markdown_and_html_cover_status_labels_and_escape_script(self):
        statuses = ["PASS", "FAIL", "UNKNOWN", "MANUAL", "WAIVED", "NOT_APPLICABLE", "NOT_RUN"]
        rows = [
            row(f"CTRL-{index}", status, title="<script>alert(1)</script>" if index == 0 else "Synthetic title",
                detail="<script>alert(1)</script> | command\nsecond line" if index == 0 else "Synthetic detail")
            for index, status in enumerate(statuses)
        ]
        report = build_json_report(
            DeviceContext("synthetic-sw1", "cisco_ios", family="Catalyst 2960-X"),
            rows,
            catalog_version="Y26M04",
            run_metadata={"run_id": "synthetic-run"},
        )
        markdown = render_markdown_report(report)
        html = render_html_report(report)
        json_text = render_json_report(report)
        for status in statuses:
            self.assertIn(CELL_LABELS[status], markdown)
            self.assertIn(CELL_LABELS[status], html)
        self.assertIn("Pro (ارتقا)", markdown)
        self.assertIn("پوشش Pro", markdown)
        self.assertIn("پاس‌شدن این ستون یعنی تنظیمات حداقلی در کانفیگ وجود دارد؛ نحوه اعمال روی پورت‌ها بررسی نشده است.", markdown)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertNotIn("<script>alert(1)</script>", markdown)
        self.assertNotIn("supersecret", json_text)
        self.assertIn("حداقل امنیت برقرار نیست", markdown)

    def test_report_orders_standard_fail_then_incomplete_then_other(self):
        rows = [row("A-PASS", "PASS"), row("Z-UNKNOWN", "UNKNOWN"), row("M-MANUAL", "MANUAL"), row("B-FAIL", "FAIL")]
        report = build_json_report(DeviceContext("synthetic-sw1", "cisco_ios"), rows, run_metadata={"run_id": "fixed"})
        self.assertEqual([item["control_id"] for item in report["rows"]], ["B-FAIL", "M-MANUAL", "Z-UNKNOWN", "A-PASS"])

    def test_report_has_real_fix_first_list_column_disclaimer_and_pro_n_of_m(self):
        rows = [
            row("CTRL-PASS", "PASS", pro_status="PASS"),
            row("CTRL-FAIL", "FAIL", pro_status="FAIL"),
        ]
        report = build_json_report(
            DeviceContext("synthetic-sw1", "cisco_ios", family="Catalyst 2960-X"),
            rows,
            catalog_version="synthetic-v1",
            run_metadata={"run_id": "synthetic-run"},
        )
        markdown = render_markdown_report(report)
        html = render_html_report(report)
        disclaimer = "پاس‌شدن این ستون یعنی تنظیمات حداقلی در کانفیگ وجود دارد؛ نحوه اعمال روی پورت‌ها بررسی نشده است."

        self.assertIn("CTRL-FAIL", markdown.split("## مواردی که ابتدا باید اصلاح شوند", 1)[1].split("## جزئیات کنترل‌ها", 1)[0])
        self.assertNotIn("CTRL-PASS", markdown.split("## مواردی که ابتدا باید اصلاح شوند", 1)[1].split("## جزئیات کنترل‌ها", 1)[0])
        self.assertIn("N of M", markdown)
        self.assertIn("FAIL: 1 of 2", markdown)
        self.assertIn(disclaimer, markdown)
        self.assertIn(disclaimer, html)
        self.assertIn("FAIL: 1 of 2", html)
        self.assertIn("<th>Standard (حداقل)", html)
        html_fix_section = html.split("<h2>مواردی که ابتدا باید اصلاح شوند</h2>", 1)[1].split("<h2>جزئیات کنترل‌ها</h2>", 1)[0]
        self.assertIn("CTRL-FAIL", html_fix_section)
        self.assertNotIn("CTRL-PASS", html_fix_section)

    def test_expired_waiver_is_not_counted_as_waived_in_minimum_verdict(self):
        device = DeviceContext("synthetic-sw1", "cisco_ios", family="Catalyst 2960-X")
        assessment_rule = AssessmentRule(
            control_id="CTRL-EXPIRED", rule_id="RULE-EXPIRED", title="Synthetic expired waiver",
            severity="high", status="approved", automation_level="automated", target_platform="cisco_ios",
            target_families=("Catalyst 2960-X",), level="standard",
            standard_check={"type": "config_line_present", "line": "mls qos"},
            source_ref={"note": "synthetic"},
        )
        expired = Waiver("CTRL-EXPIRED", "Synthetic expired exception", "reviewer", date(2025, 1, 1), ("synthetic-sw1",))
        evaluated = evaluate_rule_levels(
            assessment_rule, device, "hostname synthetic-sw1", waivers={"CTRL-EXPIRED": expired},
            today=date(2026, 1, 1), level="standard",
        )
        report = build_json_report(device, [evaluated], run_metadata={"run_id": "synthetic-expired-waiver"})
        self.assertEqual(evaluated.standard.status, "FAIL")
        self.assertIn("Expired waiver ignored", evaluated.standard.detail)
        self.assertEqual(report["verdict"]["code"], "NOT_ACHIEVED")
        self.assertEqual(report["verdict"]["counts"]["waived"], 0)
        self.assertEqual(report["verdict"]["counts"]["fail"], 1)

    def test_banner_line_xss_is_escaped_in_html_and_markdown(self):
        banner = "banner motd #<script>alert(1)</script>#"
        report = build_json_report(
            DeviceContext("synthetic-sw1", "cisco_ios", family="Catalyst 2960-X"),
            [row("CTRL-BANNER", "PASS", detail=banner)],
            run_metadata={"run_id": "synthetic-banner-xss"},
        )
        markdown = render_markdown_report(report)
        html = render_html_report(report)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertNotIn("<script>alert(1)</script>", markdown)
        self.assertIn("banner motd", markdown)

    def test_standard_verdict_ignores_pro_failures(self):
        item = row("DUAL", "PASS", pro_status="FAIL")
        report = build_json_report(DeviceContext("synthetic-sw1", "cisco_ios"), [item], run_metadata={"run_id": "fixed"})
        self.assertEqual(report["verdict"]["code"], "ACHIEVED")
        self.assertEqual(report["pro_counts"]["FAIL"], 1)
        self.assertEqual(report["pro_counts"]["total"], 1)


if __name__ == "__main__":
    unittest.main()
