"""Fail-closed assessment engine for reviewed Cisco IOS STIG rules.

Drafts are never loaded as executable rules. This module is deliberately separate
from netagent.compliance and the config deployment/apply workflow.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Iterable

STATUSES = ("PASS", "FAIL", "UNKNOWN", "MANUAL", "NOT_APPLICABLE", "WAIVED")
AUTOMATABLE_LEVELS = {"automated", "semi_automated"}


@dataclass(frozen=True)
class AssessmentRule:
    control_id: str
    rule_id: str
    title: str
    severity: str
    status: str
    automation_level: str
    target_platform: str
    target_families: tuple[str, ...] = ()
    profiles: tuple[str, ...] = ()
    evidence_requirements: tuple[str, ...] = ()
    check_strategy: dict[str, Any] | None = None
    pass_condition: Any = None
    fail_condition: Any = None
    remediation: str | None = None
    source_ref: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Waiver:
    control_id: str
    reason: str
    approved_by: str
    expires_on: date


@dataclass(frozen=True)
class AssessmentResult:
    control_id: str
    rule_id: str
    title: str
    severity: str
    status: str
    detail: str
    remediation: str | None = None
    source_ref: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DeviceContext:
    hostname: str
    platform: str
    family: str | None = None
    show_version: str | None = None
    profiles: tuple[str, ...] = ()


def load_approved_rules(root: str | Path, profiles: Iterable[str] = ()) -> list[AssessmentRule]:
    """Load only explicitly approved, supported rules. Drafts are ignored by design."""
    root = Path(root)
    selected_profiles = set(profiles)
    rules: list[AssessmentRule] = []
    for path in sorted(root.rglob("*.json")):
        if path.name.lower() == "manifest.json":
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot read rule file {path}: {exc}") from exc
        if not isinstance(raw, dict):
            raise ValueError(f"{path}: rule must be a JSON object")
        if raw.get("status") != "approved":
            continue
        if raw.get("automation_level") not in AUTOMATABLE_LEVELS:
            continue
        required = ("control_id", "rule_id", "title", "severity", "target_platform", "check_strategy")
        missing = [key for key in required if not raw.get(key)]
        if missing:
            raise ValueError(f"{path}: approved rule missing required fields: {', '.join(missing)}")
        severity = str(raw["severity"]).lower()
        if severity not in {"critical", "high", "medium", "low"}:
            raise ValueError(f"{path}: unsupported severity {severity!r}")
        rule_profiles = tuple(raw.get("profiles") or ())
        if selected_profiles and rule_profiles and not selected_profiles.intersection(rule_profiles):
            continue
        strategy = raw["check_strategy"]
        supported_strategies = {
            "config_line_present", "config_paths_present", "config_paths_and_regex",
            "config_regex_count", "common_criteria_policy", "admin_auth_server_count",
            "emergency_local_account", "vty_management_acl", "evidence_regex",
            "manual_review",
        }
        if not isinstance(strategy, dict) or strategy.get("type") not in supported_strategies:
            raise ValueError(f"{path}: unsupported check_strategy")
        if strategy["type"] == "config_line_present" and not isinstance(strategy.get("line"), str):
            raise ValueError(f"{path}: config_line_present requires a line string")
        if strategy["type"] in {"config_paths_present", "config_paths_and_regex"}:
            paths = strategy.get("paths")
            if (not isinstance(paths, list) or not paths
                    or any(not isinstance(p, list) or not p
                           or any(not isinstance(line, str) or not line.strip() for line in p)
                           for p in paths)):
                raise ValueError(f"{path}: {strategy['type']} requires non-empty paths of non-empty strings")
        if strategy["type"] == "config_paths_and_regex":
            patterns = strategy.get("patterns")
            if (not isinstance(patterns, list) or not patterns
                    or any(not isinstance(p, dict) or not isinstance(p.get("pattern"), str)
                           or not isinstance(p.get("description"), str)
                           for p in patterns)):
                raise ValueError(f"{path}: config_paths_and_regex requires patterns with pattern and description")
            for item in patterns:
                try:
                    re.compile(item["pattern"], re.M)
                except re.error as exc:
                    raise ValueError(f"{path}: invalid combined-check regex: {exc}") from exc
        if strategy["type"] == "common_criteria_policy":
            directive = strategy.get("directive")
            if not isinstance(directive, str) or not directive.strip():
                raise ValueError(f"{path}: common_criteria_policy requires a directive")
        if strategy["type"] == "admin_auth_server_count":
            minimum = strategy.get("min_count", 2)
            if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 1:
                raise ValueError(f"{path}: admin_auth_server_count requires positive min_count")
        if strategy["type"] == "config_regex_count":
            pattern = strategy.get("pattern")
            minimum = strategy.get("min_count")
            if not isinstance(pattern, str) or not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 1:
                raise ValueError(f"{path}: config_regex_count requires pattern and positive min_count")
            if "partial_note" in strategy and not isinstance(strategy["partial_note"], str):
                raise ValueError(f"{path}: config_regex_count partial_note must be a string")
            try:
                re.compile(pattern, re.M)
            except re.error as exc:
                raise ValueError(f"{path}: invalid config count regex: {exc}") from exc
        if strategy["type"] == "manual_review" and not isinstance(strategy.get("reason"), str):
            raise ValueError(f"{path}: manual_review requires a reason")
        if strategy["type"] == "evidence_regex":
            if not isinstance(strategy.get("evidence_key"), str) or not isinstance(strategy.get("pattern"), str):
                raise ValueError(f"{path}: evidence_regex requires evidence_key and pattern")
            try:
                re.compile(strategy["pattern"], re.M)
            except re.error as exc:
                raise ValueError(f"{path}: invalid evidence regex: {exc}") from exc
        rules.append(AssessmentRule(
            control_id=str(raw["control_id"]),
            rule_id=str(raw["rule_id"]),
            title=str(raw["title"]),
            severity=severity,
            status="approved",
            automation_level=str(raw["automation_level"]),
            target_platform=str(raw["target_platform"]),
            target_families=tuple(raw.get("target_families") or ()),
            profiles=rule_profiles,
            evidence_requirements=tuple(raw.get("evidence_requirements") or ()),
            check_strategy=dict(strategy),
            pass_condition=raw.get("pass_condition"),
            fail_condition=raw.get("fail_condition"),
            remediation=raw.get("remediation"),
            source_ref=raw.get("source_ref") or {},
        ))
    ids = [rule.control_id for rule in rules]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate control_id among approved rules")
    return rules


def load_waivers(path: str | Path | None) -> dict[str, Waiver]:
    if path is None:
        return {}
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    entries = raw.get("waivers") if isinstance(raw, dict) else None
    if not isinstance(entries, list):
        raise ValueError("waiver file must contain a waivers list")
    out: dict[str, Waiver] = {}
    for item in entries:
        if not isinstance(item, dict):
            raise ValueError("each waiver must be an object")
        required = ("control_id", "reason", "approved_by", "expires_on")
        if any(not item.get(key) for key in required):
            raise ValueError("waiver requires control_id, reason, approved_by, expires_on")
        try:
            expiry = date.fromisoformat(item["expires_on"])
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid waiver expires_on for {item.get('control_id')}") from exc
        waiver = Waiver(item["control_id"], item["reason"], item["approved_by"], expiry)
        if waiver.control_id in out:
            raise ValueError(f"duplicate waiver for {waiver.control_id}")
        out[waiver.control_id] = waiver
    return out


def parse_ios_show_version(text: str | None) -> dict[str, str | None]:
    """Extract only clear model/version tokens; never infer a family from vague output."""
    if not text:
        return {"model": None, "version": None, "family": None}
    model = None
    version = None
    model_match = re.search(r"(?im)^\s*Model Number\s*:\s*(WS-C\d{4,5}[A-Z0-9-]*)", text)
    if not model_match:
        model_match = re.search(r"(?im)^\s*(?:cisco\s+)?(WS-C\d{4,5}[A-Z0-9-]*)\s+", text)
    if model_match:
        model = model_match.group(1).upper()
    version_match = re.search(r"(?im)^Cisco IOS Software.*?Version\s+([^,\s]+)", text)
    if not version_match:
        version_match = re.search(r"(?im)^Cisco IOS XE Software.*?Version\s+([^,\s]+)", text)
    if version_match:
        version = version_match.group(1)
    family = None
    if model:
        if re.match(r"WS-C2960XR", model):
            family = "Catalyst 2960-XR"
        elif re.match(r"WS-C2960X", model):
            family = "Catalyst 2960-X"
        elif re.match(r"WS-C2960L", model):
            family = "Catalyst 2960-L"
    return {"model": model, "version": version, "family": family}


def _result(rule: AssessmentRule, status: str, detail: str) -> AssessmentResult:
    return AssessmentResult(rule.control_id, rule.rule_id, rule.title, rule.severity,
                            status, detail, rule.remediation, rule.source_ref)


def _config_tree(config: str) -> list[dict[str, Any]]:
    """Parse indented IOS configuration into a small hierarchy for context checks."""
    roots: list[dict[str, Any]] = []
    stack: list[tuple[int, dict[str, Any]]] = []
    for raw_line in config.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        if raw_line.lstrip().startswith("!"):
            stack.clear()
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" \\t"))
        node = {"line": re.sub(r"\s+", " ", stripped).casefold(), "children": []}
        while stack and stack[-1][0] >= indent:
            stack.pop()
        if stack:
            stack[-1][1]["children"].append(node)
        else:
            roots.append(node)
        stack.append((indent, node))
    return roots


def _has_config_path(nodes: list[dict[str, Any]], path: list[str]) -> bool:
    expected = [re.sub(r"\s+", " ", line.strip()).casefold() for line in path]
    def descend(candidates: list[dict[str, Any]], index: int) -> bool:
        for node in candidates:
            if node["line"] != expected[index]:
                continue
            if index == len(expected) - 1 or descend(node["children"], index + 1):
                return True
        return False
    return descend(nodes, 0)


def evaluate_rule(
    rule: AssessmentRule,
    device: DeviceContext,
    config: str | None,
    evidence: dict[str, str] | None = None,
    waiver: Waiver | None = None,
    today: date | None = None,
) -> AssessmentResult:
    """Evaluate one approved rule; absent or ambiguous evidence never yields PASS."""
    today = today or date.today()
    evidence = evidence or {}
    if waiver:
        if waiver.expires_on >= today:
            return _result(rule, "WAIVED", f"Approved by {waiver.approved_by}; expires {waiver.expires_on.isoformat()}: {waiver.reason}")
    if device.platform != rule.target_platform:
        return _result(rule, "NOT_APPLICABLE", f"Rule targets {rule.target_platform}; device platform is {device.platform}.")
    family = device.family
    if not family and device.show_version:
        family = parse_ios_show_version(device.show_version)["family"]
    if rule.target_families:
        if family is None:
            return _result(rule, "UNKNOWN", "Device family is not verified; provide family or recognizable show-version evidence.")
        if family not in rule.target_families:
            return _result(rule, "NOT_APPLICABLE", f"Verified device family {family!r} is outside the rule target families.")
    if rule.evidence_requirements:
        missing = [key for key in rule.evidence_requirements if key not in evidence or not evidence[key].strip()]
        if missing:
            return _result(rule, "UNKNOWN", "Required evidence is missing: " + ", ".join(missing))
    strategy = rule.check_strategy or {}
    kind = strategy.get("type")
    if kind == "config_line_present":
        if config is None or not config.strip():
            return _result(rule, "UNKNOWN", "Configuration evidence is missing or empty.")
        expected = strategy["line"].strip()
        lines = {line.strip() for line in config.splitlines() if line.strip() and not line.lstrip().startswith("!")}
        if expected in lines:
            return _result(rule, "PASS", f"Required configuration line is present: {expected}")
        return _result(rule, "FAIL", f"Required configuration line was not found: {expected}")
    if kind in {"config_paths_present", "config_paths_and_regex"}:
        if config is None or not config.strip():
            return _result(rule, "UNKNOWN", "Configuration evidence is missing or empty.")
        tree = _config_tree(config)
        missing_paths = [path for path in strategy["paths"] if not _has_config_path(tree, path)]
        if missing_paths:
            rendered = [" -> ".join(path) for path in missing_paths]
            return _result(rule, "FAIL", "Missing configuration path(s): " + "; ".join(rendered))
        if kind == "config_paths_and_regex":
            clean_config = "\n".join(line for line in config.splitlines() if not line.lstrip().startswith("!"))
            for item in strategy["patterns"]:
                if not re.search(item["pattern"], clean_config, re.M):
                    return _result(rule, "FAIL", "Missing required configuration evidence: " + item["description"])
        return _result(rule, "PASS", f"All {len(strategy['paths'])} required configuration path(s) and accompanying checks are present.")
    if kind == "common_criteria_policy":
        if config is None or not config.strip():
            return _result(rule, "UNKNOWN", "Configuration evidence is missing or empty.")
        tree = _config_tree(config)
        directive = re.sub(r"\s+", " ", strategy["directive"].strip()).casefold()
        policies: dict[str, set[str]] = {}
        usernames: list[tuple[str, str | None]] = []
        for node in tree:
            policy_match = re.match(r"^aaa common-criteria policy\s+(\S+)$", node["line"])
            if policy_match:
                policies[policy_match.group(1)] = {child["line"] for child in node["children"]}
                continue
            if node["line"].startswith("username "):
                binding = re.search(r"\bcommon-criteria-policy\s+(\S+)", node["line"])
                usernames.append((node["line"], binding.group(1) if binding else None))
        compliant_policies = {name for name, directives in policies.items() if directive in directives}
        if not compliant_policies:
            return _result(rule, "FAIL", f"No common-criteria policy contains required directive: {strategy['directive']}.")
        if not usernames:
            return _result(rule, "FAIL", f"The policy directive is present, but no local username is configured to use a common-criteria policy: {strategy['directive']}.")
        unbound = [name for name, policy_name in usernames if policy_name not in compliant_policies]
        if unbound:
            return _result(rule, "FAIL", f"The required password-policy directive is not verified for every local username ({len(unbound)} account(s) unbound or using a different/incomplete policy).")
        return _result(rule, "PASS", f"The required directive {strategy['directive']} is configured in a common-criteria policy and bound to every configured local username.")
    if kind == "admin_auth_server_count":
        if config is None or not config.strip():
            return _result(rule, "UNKNOWN", "Configuration evidence is missing or empty.")
        clean_config = "\n".join(line for line in config.splitlines() if not line.lstrip().startswith("!"))
        login_match = re.search(r"(?im)^[ \t]*aaa authentication login default group\s+(\S+)", clean_config)
        if not login_match:
            return _result(rule, "FAIL", "No default administrative login method referencing an authentication server group was found.")
        method = login_match.group(1).casefold()
        tree = _config_tree(config)
        if method == "tacacs+":
            count = len(re.findall(r"(?im)^[ \t]*tacacs-server host\s+\S+", clean_config))
            count += sum(1 for node in tree if re.match(r"^tacacs server\s+\S+$", node["line"])
                         and any(child["line"].startswith("address ipv4 ") for child in node["children"]))
        elif method == "radius":
            count = len(re.findall(r"(?im)^[ \t]*radius-server host\s+\S+", clean_config))
            count += sum(1 for node in tree if re.match(r"^radius server\s+\S+$", node["line"])
                         and any(child["line"].startswith("address ipv4 ") for child in node["children"]))
        else:
            group = next((node for node in tree if node["line"] in {
                f"aaa group server radius {method}", f"aaa group server tacacs+ {method}"
            }), None)
            if group is None:
                return _result(rule, "MANUAL", f"Cannot resolve administrative authentication group {method!r} to server definitions.")
            names = set()
            for child in group["children"]:
                match = re.match(r"^server name\s+(\S+)$", child["line"])
                if match:
                    names.add(match.group(1))
            protocol = "radius" if group["line"].startswith("aaa group server radius ") else "tacacs"
            prefix = "radius server " if protocol == "radius" else "tacacs server "
            count = sum(1 for node in tree if node["line"].startswith(prefix)
                        and node["line"][len(prefix):] in names
                        and any(child["line"].startswith("address ipv4 ") for child in node["children"]))
        minimum = strategy.get("min_count", 2)
        if count < minimum:
            return _result(rule, "FAIL", f"Default administrative login uses {method} but only {count} matching server definition(s) were found; {minimum} required.")
        return _result(rule, "MANUAL", f"Default administrative login uses {method} and {count} matching server definition(s) were found. Confirm distinct endpoints and all console, VTY, and HTTP login bindings.")

    if kind == "emergency_local_account":
        if config is None or not config.strip():
            return _result(rule, "UNKNOWN", "Configuration evidence is missing or empty.")
        tree = _config_tree(config)
        usernames = [node for node in tree if node["line"].startswith("username ")]
        if len(usernames) != 1:
            return _result(rule, "FAIL", f"Expected exactly one local username entry; found {len(usernames)}.")
        login_ok = any(re.match(r"^aaa authentication login default group (?:radius|tacacs\+) local$", node["line"])
                       for node in tree)
        if not login_ok:
            return _result(rule, "FAIL", "Default login does not show remote-server authentication followed by local fallback.")
        username_line = usernames[0]["line"]
        if not re.search(r"\bprivilege\s+\d+\b", username_line):
            return _result(rule, "FAIL", "Local account lacks an explicit privilege level.")
        policy = re.search(r"\bcommon-criteria-policy\s+(\S+)", username_line)
        if not policy:
            return _result(rule, "FAIL", "Local account is not bound to a common-criteria password policy.")
        if not any(node["line"] == f"aaa common-criteria policy {policy.group(1)}" for node in tree):
            return _result(rule, "FAIL", "Local account references an undefined common-criteria password policy.")
        return _result(rule, "MANUAL", "One local account, explicit privilege, password-policy binding, and remote-to-local fallback are present. Validate privilege suitability and actual failover behavior.")

    if kind == "vty_management_acl":
        if config is None or not config.strip():
            return _result(rule, "UNKNOWN", "Configuration evidence is missing or empty.")
        tree = _config_tree(config)
        vty_blocks = [node for node in tree if re.match(r"^line vty\s+\d+(?:\s+\d+)?$", node["line"])]
        if not vty_blocks:
            return _result(rule, "UNKNOWN", "No VTY line configuration was found.")
        for block in vty_blocks:
            match = next((re.match(r"^access-class\s+(\S+)\s+in$", child["line"])
                          for child in block["children"]
                          if re.match(r"^access-class\s+\S+\s+in$", child["line"])), None)
            if not match:
                return _result(rule, "FAIL", f"{block['line']} has no inbound access-class.")
            acl_name = match.group(1)
            acl = next((node for node in tree
                        if re.match(r"^ip access-list (?:standard|extended)\s+", node["line"])
                        and node["line"].split()[-1] == acl_name), None)
            if not acl:
                return _result(rule, "FAIL", f"VTY references ACL {acl_name!r}, but that ACL was not found.")
            if not any(child["line"].startswith("permit ") for child in acl["children"]):
                return _result(rule, "FAIL", f"ACL {acl_name!r} has no permit entry.")
            if not any(re.match(r"^deny ip any any(?: log-input)?$", child["line"]) for child in acl["children"]):
                return _result(rule, "FAIL", f"ACL {acl_name!r} has no explicit deny-all entry.")
        return _result(rule, "MANUAL", "All VTY blocks have inbound ACLs with permit and deny-all entries. Validate that permitted networks match the approved management network.")

    if kind == "config_regex_count":
        if config is None or not config.strip():
            return _result(rule, "UNKNOWN", "Configuration evidence is missing or empty.")
        clean_lines = [line for line in config.splitlines() if not line.lstrip().startswith("!")]
        count = len(re.findall(strategy["pattern"], "\n".join(clean_lines), re.M))
        minimum = strategy["min_count"]
        if count < minimum:
            return _result(rule, "FAIL", f"Configuration evidence has {count} matching declaration(s); at least {minimum} are required.")
        if strategy.get("partial", False):
            detail = f"Count precheck satisfied ({count} matching declaration(s)); the complete control needs additional review."
            if strategy.get("partial_note"):
                detail += " " + strategy["partial_note"]
            return _result(rule, "MANUAL", detail)
        return _result(rule, "PASS", f"Configuration evidence has {count} matching declaration(s); at least {minimum} are required.")
    if kind == "manual_review":
        reason = strategy.get("reason", "This control requires human review.")
        return _result(rule, "MANUAL", reason)
    if kind == "evidence_regex":
        key = strategy["evidence_key"]
        if key not in evidence or not evidence[key].strip():
            return _result(rule, "UNKNOWN", f"Required evidence {key!r} is missing.")
        try:
            match = re.search(strategy["pattern"], evidence[key], re.M)
        except re.error as exc:
            return _result(rule, "MANUAL", f"Invalid rule pattern; human review required: {exc}")
        expected_match = bool(strategy.get("expect_match", True))
        if bool(match) == expected_match:
            return _result(rule, "PASS", f"Evidence {key!r} satisfied the reviewed pattern.")
        return _result(rule, "FAIL", f"Evidence {key!r} did not satisfy the reviewed pattern.")
    return _result(rule, "MANUAL", f"Unsupported or missing check strategy {kind!r}; human review required.")


def assess(
    rules: Iterable[AssessmentRule],
    device: DeviceContext,
    config: str | None,
    evidence: dict[str, str] | None = None,
    waivers: dict[str, Waiver] | None = None,
    today: date | None = None,
) -> list[AssessmentResult]:
    waivers = waivers or {}
    results = []
    for rule in rules:
        if rule.profiles and not device.profiles:
            results.append(_result(rule, "UNKNOWN", "Device assessment profile is not verified for this profile-scoped rule."))
            continue
        if rule.profiles and not set(rule.profiles).intersection(device.profiles):
            results.append(_result(rule, "NOT_APPLICABLE", "Rule is outside the selected device assessment profile."))
            continue
        results.append(evaluate_rule(rule, device, config, evidence, waivers.get(rule.control_id), today))
    return sorted(results, key=lambda item: (item.severity, item.control_id))


def coverage_summary(results: Iterable[AssessmentResult]) -> dict[str, int]:
    items = list(results)
    counts = {status: 0 for status in STATUSES}
    for result in items:
        counts[result.status] += 1
    counts["TOTAL"] = len(items)
    return counts


def exit_code(results: Iterable[AssessmentResult], fail_on: str = "high", allow_unknown: bool = False) -> int:
    """0 complete; 2 threshold finding; 3 unknown/manual; 1 invalid policy."""
    if fail_on not in {"none", "critical", "high", "medium", "low"}:
        return 1
    items = list(results)
    if not allow_unknown and any(item.status in {"UNKNOWN", "MANUAL"} for item in items):
        return 3
    if fail_on != "none":
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        threshold = rank[fail_on]
        if any(item.status == "FAIL" and item.severity in rank and rank[item.severity] <= threshold for item in items):
            return 2
    return 0


def report_markdown(device: DeviceContext, results: Iterable[AssessmentResult]) -> str:
    items = list(results)
    counts = coverage_summary(items)
    out = [
        "# Cisco IOS STIG assessment",
        "",
        f"- Device: {device.hostname}",
        f"- Platform: {device.platform}",
        f"- Family: {device.family or (parse_ios_show_version(device.show_version).get('family') if device.show_version else None) or 'unverified'}",
        "",
        "| Status | Count |",
        "|---|---:|",
    ]
    for status in STATUSES:
        out.append(f"| {status} | {counts[status]} |")
    out += ["", "| Control | Severity | Status | Title | Detail |", "|---|---|---|---|---|"]
    for item in items:
        clean_detail = item.detail.replace("|", "\\|").replace("\n", " ")
        clean_title = item.title.replace("|", "\\|")
        out.append(f"| {item.control_id} | {item.severity} | {item.status} | {clean_title} | {clean_detail} |")
    out += ["", "> Results are evidence-based assessments, not a security percentage. Draft rules are never evaluated."]
    return "\n".join(out) + "\n"
