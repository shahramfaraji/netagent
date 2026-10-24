"""Rule-based compliance checks for saved network configurations.

Regex rules are intentionally conservative: a missing configuration section can
mean either "not configured" or "not included in this export". Such cases are
reported as UNKNOWN when a rule defines scope_pattern.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

SEVERITIES = ("critical", "high", "medium", "low")


@dataclass
class Rule:
    id: str
    description: str
    severity: str
    platforms: list[str] = field(default_factory=list)
    must_contain: list[str] = field(default_factory=list)
    must_not_contain: list[str] = field(default_factory=list)
    remediation: str = ""
    scope_pattern: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"rule {self.id}: severity must be one of {SEVERITIES}")
        for pattern in self.must_contain + self.must_not_contain:
            re.compile(pattern)
        if self.scope_pattern:
            re.compile(self.scope_pattern)
        if not (self.must_contain or self.must_not_contain):
            raise ValueError(f"rule {self.id}: needs must_contain or must_not_contain")


@dataclass
class Finding:
    hostname: str
    rule_id: str
    severity: str
    description: str
    detail: str
    remediation: str


@dataclass
class Unknown:
    hostname: str
    rule_id: str
    description: str
    detail: str


def load_rules(path: str | Path) -> list[Rule]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    rules = [Rule(**rule) for rule in raw.get("rules", raw)]
    ids = [rule.id for rule in rules]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate rule ids")
    return rules


def evaluate_detailed(
    hostname: str, platform: str, config: str, rules: list[Rule]
) -> tuple[list[Finding], list[Unknown], int]:
    """Return findings, unknown results, and number of applicable/evaluable rules."""
    findings: list[Finding] = []
    unknowns: list[Unknown] = []
    evaluated = 0
    for rule in rules:
        if rule.platforms and platform not in rule.platforms:
            continue
        if rule.scope_pattern and not re.search(rule.scope_pattern, config, re.M):
            unknowns.append(Unknown(
                hostname, rule.id, rule.description,
                f"scope not present in exported config; cannot verify: /{rule.scope_pattern}/",
            ))
            continue
        evaluated += 1
        for pattern in rule.must_contain:
            if not re.search(pattern, config, re.M):
                findings.append(Finding(
                    hostname, rule.id, rule.severity, rule.description,
                    f"missing: /{pattern}/", rule.remediation,
                ))
        for pattern in rule.must_not_contain:
            match = re.search(pattern, config, re.M)
            if match:
                line = config[:match.start()].count("\n") + 1
                findings.append(Finding(
                    hostname, rule.id, rule.severity, rule.description,
                    f"forbidden match at line {line}: /{pattern}/", rule.remediation,
                ))
    order = {severity: index for index, severity in enumerate(SEVERITIES)}
    return sorted(findings, key=lambda item: (order[item.severity], item.rule_id)), unknowns, evaluated


def evaluate(hostname: str, platform: str, config: str, rules: list[Rule]) -> list[Finding]:
    """Backward-compatible findings-only API."""
    findings, _, _ = evaluate_detailed(hostname, platform, config, rules)
    return findings


def score(findings: list[Finding], rules_count: int) -> int:
    if rules_count == 0:
        return 100
    weight = {"critical": 25, "high": 10, "medium": 5, "low": 2}
    return max(0, 100 - sum(weight[finding.severity] for finding in findings))


def report_markdown(
    results: dict[str, list[Finding]],
    rules_count: int,
    unknown_results: dict[str, list[Unknown]] | None = None,
    evaluated_counts: dict[str, int] | None = None,
) -> str:
    unknown_results = unknown_results or {}
    evaluated_counts = evaluated_counts or {}
    out = ["# Compliance report", ""]
    out.append("| Device | Rule score | Critical | High | Medium | Low | Unknown | Evaluated rules |")
    out.append("|---|---:|---:|---:|---:|---:|---:|---:|")
    for host, findings in sorted(results.items()):
        counts = {severity: sum(1 for finding in findings if finding.severity == severity)
                  for severity in SEVERITIES}
        unknown_count = len(unknown_results.get(host, []))
        evaluated_count = evaluated_counts.get(host, rules_count)
        displayed_score = "N/A" if unknown_count or evaluated_count == 0 else str(score(findings, rules_count))
        out.append(
            f"| {host} | {displayed_score} | {counts['critical']} | {counts['high']} | "
            f"{counts['medium']} | {counts['low']} | {unknown_count} | "
            f"{evaluated_count} |"
        )
    for host, findings in sorted(results.items()):
        out += ["", f"## {host}"]
        if not findings:
            out.append("No rule violations detected among evaluated rules.")
        for finding in findings:
            out.append(
                f"- **[{finding.severity.upper()}] {finding.rule_id}**: {finding.description} "
                f"({finding.detail})"
                + (f"\n  - Fix: `{finding.remediation}`" if finding.remediation else "")
            )
        for item in unknown_results.get(host, []):
            out.append(f"- **[UNKNOWN] {item.rule_id}**: {item.description} ({item.detail})")
    out += ["", "> Rule score is a rule-weight summary, not a security percentage. "
            "N/A means one or more checks could not be evaluated, or no rules applied to this platform."]
    return "\n".join(out) + "\n"
