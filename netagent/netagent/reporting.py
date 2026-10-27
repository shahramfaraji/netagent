"""Safe dual-column JSON, Markdown, and HTML reporting for Standard/Pro assessments."""
from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable

from .stig_assessment import CheckCell, DeviceContext, RuleRow, SEVERITY_RANK, parse_ios_show_version

CELL_LABELS = {
    "PASS": "✅ برقرار",
    "FAIL": "❌ ناموفق",
    "UNKNOWN": "❓ داده ناقص",
    "MANUAL": "✋ بازبینی دستی",
    "WAIVED": "⚪ استثنا",
    "NOT_RUN": "➖ ندارد",
    "NOT_APPLICABLE": "نامرتبط",
}
VERDICT_LABELS = {
    "NOT_ACHIEVED": "حداقل امنیت برقرار نیست",
    "INCOMPLETE": "ارزیابی ناقص",
    "ACHIEVED_WITH_WAIVERS": "برقرار با استثنا",
    "ACHIEVED": "حداقل امنیت برقرار است",
    "NO_RULES": "هیچ قانون Standard فعالی وجود ندارد",
}
STATUS_ORDER = ("PASS", "FAIL", "UNKNOWN", "MANUAL", "WAIVED", "NOT_APPLICABLE", "NOT_RUN")


def _redact(value: Any) -> str:
    """Redact common secret-bearing patterns before any human-readable output."""
    text = str(value if value is not None else "")
    text = re.sub(r"(?im)^\s*username\s+\S+.*?\b(?:secret|password)\s+\d+\s+\S+.*$", "username <REDACTED> secret <REDACTED>", text)
    text = re.sub(r"(?im)\b(?:enable\s+secret|password|secret)\s+\d+\s+\S+", "secret <REDACTED>", text)
    text = re.sub(r"(?im)\bsnmp-server\s+community\s+\S+", "snmp-server community <REDACTED>", text)
    text = re.sub(r"(?im)\bkey\s+7\s+\S+", "key 7 <REDACTED>", text)
    text = re.sub(r"(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", "<REDACTED PRIVATE KEY>", text)
    return text


def _md(value: Any) -> str:
    return html.escape(_redact(value), quote=False).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _sanitize(value: Any) -> Any:
    if isinstance(value, str):
        return _redact(value)
    if isinstance(value, dict):
        return {str(key): _sanitize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize(item) for item in value]
    return value


def _cell_dict(cell: CheckCell | None) -> dict[str, Any] | None:
    if cell is None:
        return None
    return {
        "status": cell.status,
        "detail": _redact(cell.detail),
        "depth": cell.depth,
        "recommendation": _redact(cell.recommendation) if cell.recommendation else None,
        "downgraded_from": cell.downgraded_from,
    }


def _row_sort_key(row: RuleRow) -> tuple[int, int, str]:
    status = row.standard.status if row.standard else "NOT_APPLICABLE"
    if status == "FAIL":
        group = 0
    elif status in {"UNKNOWN", "MANUAL"}:
        group = 1
    else:
        group = 2
    return group, SEVERITY_RANK.get(row.severity.casefold(), len(SEVERITY_RANK)), row.control_id


def minimum_verdict(rows: Iterable[RuleRow]) -> dict[str, Any]:
    """Compute the minimum verdict only from Standard cells of level=standard rules."""
    counts = {
        "applicable": 0, "evaluated": 0, "pass": 0, "fail": 0, "unknown": 0,
        "manual": 0, "waived": 0, "not_applicable": 0,
    }
    for row in rows:
        if row.level != "standard" or row.standard is None:
            continue
        status = row.standard.status
        if status == "NOT_APPLICABLE":
            counts["not_applicable"] += 1
            continue
        if status == "NOT_RUN":
            continue
        counts["applicable"] += 1
        if status in {"PASS", "FAIL", "UNKNOWN", "MANUAL", "WAIVED"}:
            counts["evaluated"] += 1
            counts[status.casefold()] += 1
    if counts["applicable"] == 0:
        verdict = "NO_RULES"
    elif counts["fail"]:
        verdict = "NOT_ACHIEVED"
    elif counts["unknown"] or counts["manual"]:
        verdict = "INCOMPLETE"
    elif counts["waived"]:
        verdict = "ACHIEVED_WITH_WAIVERS"
    else:
        verdict = "ACHIEVED"
    return {"code": verdict, "label": VERDICT_LABELS[verdict], "counts": counts}


def build_json_report(
    device: DeviceContext,
    rows: Iterable[RuleRow],
    catalog_version: str = "unknown",
    run_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the canonical JSON report; renderers derive their output from this structure."""
    ordered = sorted(rows, key=_row_sort_key)
    verdict = minimum_verdict(ordered)
    pro_counts = {status: 0 for status in STATUS_ORDER}
    for row in ordered:
        if row.pro is not None:
            pro_counts[row.pro.status if row.pro.status in pro_counts else "UNKNOWN"] += 1
    pro_counts["total"] = sum(pro_counts.values())
    parsed = parse_ios_show_version(device.show_version) if device.show_version else {"model": None, "family_status": "unknown"}
    report_rows = []
    for row in ordered:
        report_rows.append({
            "control_id": row.control_id,
            "rule_id": row.rule_id,
            "stig_id": row.stig_id,
            "stig_part": row.stig_part,
            "severity": row.severity,
            "title": _redact(row.title),
            "standard": _cell_dict(row.standard),
            "pro": _cell_dict(row.pro),
            "rationale": _redact(row.rationale) if row.rationale else None,
            "evidence_refs": [_redact(item) for item in row.evidence_refs],
            "source_ref": _sanitize(row.source_ref),
        })
    return {
        "device": {
            "hostname": _redact(device.hostname),
            "platform": _redact(device.platform),
            "model": _redact(parsed.get("model")) if parsed.get("model") else None,
            "family": _redact(device.family or parsed.get("family")) if (device.family or parsed.get("family")) else None,
            "family_status": parsed.get("family_status", "unknown"),
        },
        "catalog_version": _redact(catalog_version),
        "run_metadata": _sanitize(run_metadata or {"generated_at": datetime.now(timezone.utc).isoformat()}),
        "verdict": verdict,
        "pro_counts": pro_counts,
        "rows": report_rows,
    }


def render_markdown_report(report: dict[str, Any]) -> str:
    device = report["device"]
    verdict = report["verdict"]
    counts = verdict["counts"]
    out = [
        "# ارزیابی امنیت پیکربندی Cisco IOS",
        "",
        f"- دستگاه: <bdi dir=\"ltr\">{_md(device.get('hostname'))}</bdi>",
        f"- مدل: <bdi dir=\"ltr\">{_md(device.get('model') or 'نامشخص')}</bdi>",
        f"- خانواده: <bdi dir=\"ltr\">{_md(device.get('family') or 'نامشخص')}</bdi>",
        f"- نسخه کاتالوگ: <bdi dir=\"ltr\">{_md(report.get('catalog_version', 'unknown'))}</bdi>",
        "",
        f"## حکم حداقل امنیت: {_md(verdict['label'])}",
        "",
        f"قابل ارزیابی: {counts['applicable']} | ارزیابی‌شده: {counts['evaluated']} | برقرار: {counts['pass']} | ناموفق: {counts['fail']} | داده ناقص: {counts['unknown']} | بازبینی دستی: {counts['manual']} | استثنا: {counts['waived']} | نامرتبط: {counts['not_applicable']}",
        "",
        "## مواردی که ابتدا باید اصلاح شوند",
        "فهرست زیر فقط کنترل‌های ناموفق Standard را نشان می‌دهد.",
        "",
        "| کنترل | شدت | Standard (حداقل): پاس‌شدن این ستون یعنی تنظیمات حداقلی در کانفیگ وجود دارد؛ نحوه اعمال روی پورت‌ها بررسی نشده است. | Pro (ارتقا) |",
        "|---|---|---|---|",
    ]
    failing_rows = [item for item in report["rows"] if item.get("standard") and item["standard"].get("status") == "FAIL"]
    if not failing_rows:
        out.append("| — | — | مورد ناموفق وجود ندارد | — |")
    for row in failing_rows:
        standard = row["standard"]
        pro = row["pro"]
        std_text = CELL_LABELS.get(standard["status"], _md(standard["status"])) if standard else "➖ ندارد"
        if standard and standard.get("detail"):
            std_text += " — " + _md(standard["detail"])
        pro_text = CELL_LABELS.get(pro["status"], _md(pro["status"])) if pro else "➖ ندارد"
        pro_parts = []
        if pro:
            if pro.get("recommendation"):
                pro_parts.append(_md(pro["recommendation"]))
            if row.get("rationale"):
                pro_parts.append(_md(row["rationale"]))
            if pro.get("detail"):
                pro_parts.append(_md(pro["detail"]))
        if pro_parts:
            pro_text += " — " + "; ".join(pro_parts)
        control = f"<bdi dir=\"ltr\">{_md(row['control_id'])}</bdi>"
        if row.get("stig_id"):
            control += f" (<bdi dir=\"ltr\">{_md(row['stig_id'])}</bdi>)"
        out.append(f"| {control} | {_md(row['severity'])} | {std_text} | {pro_text} |")
    out += ["", "## جزئیات کنترل‌ها", "", "| کنترل | شدت | Standard (حداقل) | Pro (ارتقا) |", "|---|---|---|---|"]
    for row in report["rows"]:
        standard = row["standard"]
        pro = row["pro"]
        std_text = CELL_LABELS.get(standard["status"], _md(standard["status"])) if standard else "➖ ندارد"
        if standard and standard.get("detail"):
            std_text += " — " + _md(standard["detail"])
        pro_text = CELL_LABELS.get(pro["status"], _md(pro["status"])) if pro else "➖ ندارد"
        pro_parts = []
        if pro:
            if pro.get("recommendation"):
                pro_parts.append(_md(pro["recommendation"]))
            if row.get("rationale"):
                pro_parts.append(_md(row["rationale"]))
            if pro.get("detail"):
                pro_parts.append(_md(pro["detail"]))
        if pro_parts:
            pro_text += " — " + "; ".join(pro_parts)
        control = f'<bdi dir="ltr">{_md(row["control_id"])}</bdi>'
        if row.get("stig_id"):
            control += f' (<bdi dir="ltr">{_md(row["stig_id"])}</bdi>)'
        out.append(f"| {control} | {_md(row['severity'])} | {std_text} | {pro_text} |")
    pro_counts = report.get("pro_counts", {})
    pro_total = pro_counts.get("total", 0)
    pro_summary = " | ".join(
        f"{_md(status)}: {count} of {pro_total}"
        for status, count in pro_counts.items()
        if status != "total" and count
    ) or f"هیچ کنترل Pro اجرا نشده است (0 of {pro_total})"
    out += [
        "",
        "## خلاصه وضعیت Pro",
        "",
        "پوشش Pro (تعداد کنترل‌ها، نه درصد؛ قالب N of M): " + pro_summary,
        "",
        "Standard: «پاس‌شدن این ستون یعنی تنظیمات حداقلی در کانفیگ وجود دارد؛ نحوه اعمال روی پورت‌ها بررسی نشده است.»",
    ]
    return "\n".join(out) + "\n"


def render_html_report(report: dict[str, Any]) -> str:
    device = report["device"]
    verdict = report["verdict"]
    counts = verdict["counts"]

    def esc(value: Any) -> str:
        return html.escape(_redact(value), quote=True)

    body_rows = []
    fix_rows = []
    for row in report["rows"]:
        standard = row["standard"]
        pro = row["pro"]
        std_label = CELL_LABELS.get(standard["status"], standard["status"]) if standard else "➖ ندارد"
        std_detail = standard.get("detail", "") if standard else ""
        pro_label = CELL_LABELS.get(pro["status"], pro["status"]) if pro else "➖ ندارد"
        pro_parts = []
        if pro:
            if pro.get("recommendation"):
                pro_parts.append(pro["recommendation"])
            if row.get("rationale"):
                pro_parts.append(row["rationale"])
            if pro.get("detail"):
                pro_parts.append(pro["detail"])
        control = f'<bdi dir="ltr">{esc(row["control_id"])}</bdi>'
        if row.get("stig_id"):
            control += f' (<bdi dir="ltr">{esc(row["stig_id"])}</bdi>)'
        rendered_row = (
            "<tr>"
            f"<td>{control}</td><td>{esc(row['severity'])}</td>"
            f"<td>{esc(std_label)} — {esc(std_detail)}</td>"
            f"<td>{esc(pro_label)} — {esc('; '.join(pro_parts))}</td>"
            "</tr>"
        )
        body_rows.append(rendered_row)
        if standard and standard.get("status") == "FAIL":
            fix_rows.append(rendered_row)
    pro_count_values = report.get("pro_counts", {})
    pro_total = pro_count_values.get("total", 0)
    pro_counts = " | ".join(
        f"{esc(status)}: {count} of {pro_total}"
        for status, count in pro_count_values.items()
        if status != "total" and count
    ) or f"هیچ کنترل Pro اجرا نشده است (0 of {pro_total})"
    return (
        '<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">'
        "<title>ارزیابی امنیت پیکربندی Cisco IOS</title>"
        "<style>body{font-family: sans-serif; margin:2rem} table{border-collapse:collapse;width:100%}"
        "th,td{border:1px solid #888;padding:.5rem;vertical-align:top} th{background:#eee}"
        "bdi{unicode-bidi:isolate}</style></head><body>"
        "<h1>ارزیابی امنیت پیکربندی Cisco IOS</h1>"
        f"<p>دستگاه: <bdi dir=\"ltr\">{esc(device.get('hostname'))}</bdi> | "
        f"مدل: <bdi dir=\"ltr\">{esc(device.get('model') or 'نامشخص')}</bdi> | "
        f"خانواده: <bdi dir=\"ltr\">{esc(device.get('family') or 'نامشخص')}</bdi></p>"
        f"<p>نسخه کاتالوگ: <bdi dir=\"ltr\">{esc(report.get('catalog_version', 'unknown'))}</bdi></p>"
        f"<h2>حکم حداقل امنیت: {esc(verdict['label'])}</h2>"
        f"<p>قابل ارزیابی: {counts['applicable']} | ارزیابی‌شده: {counts['evaluated']} | برقرار: {counts['pass']} | "
        f"ناموفق: {counts['fail']} | داده ناقص: {counts['unknown']} | بازبینی دستی: {counts['manual']} | "
        f"استثنا: {counts['waived']} | نامرتبط: {counts['not_applicable']}</p>"
        "<h2>مواردی که ابتدا باید اصلاح شوند</h2>"
        "<p>این فهرست فقط کنترل‌های ناموفق Standard را نشان می‌دهد.</p>"
        "<table><thead><tr><th>کنترل</th><th>شدت</th>"
        "<th>Standard (حداقل): پاس‌شدن این ستون یعنی تنظیمات حداقلی در کانفیگ وجود دارد؛ نحوه اعمال روی پورت‌ها بررسی نشده است.</th>"
        "<th>Pro (ارتقا)</th></tr></thead><tbody>"
        + ("".join(fix_rows) if fix_rows else "<tr><td colspan=\"4\">مورد ناموفق وجود ندارد</td></tr>")
        + "</tbody></table>"
        "<h2>جزئیات کنترل‌ها</h2>"
        "<table><thead><tr><th>کنترل</th><th>شدت</th><th>Standard (حداقل)</th><th>Pro (ارتقا)</th></tr></thead><tbody>"
        + "".join(body_rows)
        + "</tbody></table>"
        f"<p>پوشش Pro (تعداد کنترل‌ها، نه درصد): {pro_counts}</p>"
        "<p>Standard: «پاس‌شدن این ستون یعنی تنظیمات حداقلی در کانفیگ وجود دارد؛ نحوه اعمال روی پورت‌ها بررسی نشده است.»</p>"
        "</body></html>"
    )


def render_json_report(report: dict[str, Any]) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
