"""User-defined compliance rules evaluated against stored configs."""
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
    platforms: list[str] = field(default_factory=list)  # empty = all
    must_contain: list[str] = field(default_factory=list)
    must_not_contain: list[str] = field(default_factory=list)
    remediation: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"rule {self.id}: severity must be one of {SEVERITIES}")
        for p in self.must_contain + self.must_not_contain:
            re.compile(p)  # fail fast on bad regex
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


def load_rules(path: str | Path) -> list[Rule]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    rules = [Rule(**r) for r in raw.get("rules", raw)]
    ids = [r.id for r in rules]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate rule ids")
    return rules


def evaluate(hostname: str, platform: str, config: str, rules: list[Rule]) -> list[Finding]:
    findings = []
    for r in rules:
        if r.platforms and platform not in r.platforms:
            continue
        for pat in r.must_contain:
            if not re.search(pat, config, re.M):
                findings.append(Finding(hostname, r.id, r.severity, r.description, f"missing: /{pat}/", r.remediation))
        for pat in r.must_not_contain:
            m = re.search(pat, config, re.M)
            if m:
                line = config[: m.start()].count("\n") + 1
                findings.append(Finding(hostname, r.id, r.severity, r.description, f"forbidden match at line {line}: /{pat}/", r.remediation))
    order = {s: i for i, s in enumerate(SEVERITIES)}
    return sorted(findings, key=lambda f: (order[f.severity], f.rule_id))


def score(findings: list[Finding], rules_count: int) -> int:
    if rules_count == 0:
        return 100
    weight = {"critical": 25, "high": 10, "medium": 5, "low": 2}
    return max(0, 100 - sum(weight[f.severity] for f in findings))


def report_markdown(results: dict[str, list[Finding]], rules_count: int) -> str:
    out = ["# Compliance report", ""]
    out.append("| Device | Score | Critical | High | Medium | Low |")
    out.append("|---|---|---|---|---|---|")
    for host, fs in sorted(results.items()):
        c = {s: sum(1 for f in fs if f.severity == s) for s in SEVERITIES}
        out.append(f"| {host} | {score(fs, rules_count)} | {c['critical']} | {c['high']} | {c['medium']} | {c['low']} |")
    for host, fs in sorted(results.items()):
        out += ["", f"## {host}"]
        if not fs:
            out.append("No findings.")
        for f in fs:
            out.append(f"- **[{f.severity.upper()}] {f.rule_id}**: {f.description} ({f.detail})"
                       + (f"\n  - Fix: `{f.remediation}`" if f.remediation else ""))
    return "\n".join(out) + "\n"
