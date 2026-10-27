"""Fail-closed assessment engine for reviewed Cisco IOS STIG rules.

Drafts are never loaded as executable rules. This module is deliberately separate
from netagent.compliance and the config deployment/apply workflow.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, replace
from datetime import date
from pathlib import Path
from typing import Any, Iterable

STATUSES = ("PASS", "FAIL", "UNKNOWN", "MANUAL", "NOT_APPLICABLE", "WAIVED")
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
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
    level: str | None = None
    standard_check: dict[str, Any] | None = None
    pro_check: dict[str, Any] | None = None
    recommendation: str | None = None
    rationale: str | None = None
    stig_id: str | None = None
    stig_part: str | None = None
    evidence_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class CheckCell:
    status: str
    detail: str
    depth: str
    recommendation: str | None = None
    downgraded_from: str | None = None


@dataclass(frozen=True)
class RuleRow:
    control_id: str
    rule_id: str
    title: str
    severity: str
    standard: CheckCell | None
    pro: CheckCell | None
    level: str | None = None
    rationale: str | None = None
    source_ref: dict[str, Any] = field(default_factory=dict)
    stig_id: str | None = None
    stig_part: str | None = None
    evidence_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class Waiver:
    control_id: str
    reason: str
    approved_by: str
    expires_on: date
    hostnames: tuple[str, ...] = ()


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
    downgraded_from: str | None = None


@dataclass(frozen=True)
class DeviceContext:
    hostname: str
    platform: str
    family: str | None = None
    show_version: str | None = None
    profiles: tuple[str, ...] = ()
    roles_dir: str | Path | None = None
    operator_roles: dict[str, dict[str, str]] | None = None


def _validate_capabilities(strategy: dict[str, Any], path: Path | str) -> None:
    for key in ("can_pass", "can_fail"):
        if key in strategy and not isinstance(strategy[key], bool):
            raise ValueError(f"{path}: {key} must be a boolean")
    if strategy.get("can_pass", True) is False and strategy.get("can_fail", True) is False and strategy.get("type") != "manual_review":
        raise ValueError(f"{path}: both can_pass and can_fail cannot be false; use manual_review")


def _apply_capability_policy(result: AssessmentResult, strategy: dict[str, Any]) -> AssessmentResult:
    can_pass = strategy.get("can_pass", True)
    can_fail = strategy.get("can_fail", True)
    if can_pass is False and can_fail is False:
        return replace(result, status="MANUAL", detail=result.detail + " Check cannot prove either pass or fail; manual review required.", downgraded_from=result.status if result.status in {"PASS", "FAIL"} else result.downgraded_from)
    if result.status == "PASS" and not can_pass:
        return replace(result, status="MANUAL", detail=result.detail + " Downgraded from PASS because this check cannot prove compliance.", downgraded_from="PASS")
    if result.status == "FAIL" and not can_fail:
        return replace(result, status="MANUAL", detail=result.detail + " Downgraded from FAIL because this check cannot prove non-compliance.", downgraded_from="FAIL")
    return result


def _validate_strategy_details(strategy: dict[str, Any], path: Path) -> None:
    """Validate strategy-specific fields for each independent Standard/Pro check."""
    kind = strategy.get("type")
    if kind == "config_line_present":
        if not isinstance(strategy.get("line"), str):
            raise ValueError(f"{path}: config_line_present requires a line string")
        if strategy.get("context", "global") not in {"global", "any"}:
            raise ValueError(f"{path}: config_line_present context must be global or any")
    elif kind in {"config_paths_present", "config_paths_and_regex"}:
        paths = strategy.get("paths")
        if (not isinstance(paths, list) or not paths
                or any(not isinstance(item, list) or not item
                       or any(not isinstance(line, str) or not line.strip() for line in item)
                       for item in paths)):
            raise ValueError(f"{path}: {kind} requires non-empty paths of non-empty strings")
        if kind == "config_paths_and_regex":
            patterns = strategy.get("patterns")
            if (not isinstance(patterns, list) or not patterns
                    or any(not isinstance(item, dict) or not isinstance(item.get("pattern"), str)
                           or not isinstance(item.get("description"), str) for item in patterns)):
                raise ValueError(f"{path}: config_paths_and_regex requires patterns with pattern and description")
            for item in patterns:
                try:
                    re.compile(item["pattern"], re.M)
                except re.error as exc:
                    raise ValueError(f"{path}: invalid combined-check regex: {exc}") from exc
    elif kind == "common_criteria_policy":
        if not isinstance(strategy.get("directive"), str) or not strategy["directive"].strip():
            raise ValueError(f"{path}: common_criteria_policy requires a directive")
    elif kind == "admin_auth_server_count":
        minimum = strategy.get("min_count", 2)
        if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 1:
            raise ValueError(f"{path}: admin_auth_server_count requires positive min_count")
    elif kind == "config_regex_count":
        pattern, minimum = strategy.get("pattern"), strategy.get("min_count")
        if not isinstance(pattern, str) or not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 1:
            raise ValueError(f"{path}: config_regex_count requires pattern and positive min_count")
        if "partial_note" in strategy and not isinstance(strategy["partial_note"], str):
            raise ValueError(f"{path}: config_regex_count partial_note must be a string")
        try:
            re.compile(pattern, re.M)
        except re.error as exc:
            raise ValueError(f"{path}: invalid config count regex: {exc}") from exc
    elif kind == "manual_review":
        if not isinstance(strategy.get("reason"), str):
            raise ValueError(f"{path}: manual_review requires a reason")
    elif kind == "evidence_regex":
        if not isinstance(strategy.get("evidence_key"), str) or not isinstance(strategy.get("pattern"), str):
            raise ValueError(f"{path}: evidence_regex requires evidence_key and pattern")
        try:
            re.compile(strategy["pattern"], re.M)
        except re.error as exc:
            raise ValueError(f"{path}: invalid evidence regex: {exc}") from exc
    elif kind == "for_each_interface":
        scope, check = strategy.get("scope"), strategy.get("check")
        if not isinstance(scope, dict) or not scope or set(scope) - {"roles", "kinds", "exclude_shutdown"}:
            raise ValueError(f"{path}: for_each_interface requires a valid scope object")
        if "roles" in scope and (not isinstance(scope["roles"], list) or any(not isinstance(v, str) for v in scope["roles"])):
            raise ValueError(f"{path}: for_each_interface scope.roles must be a list of strings")
        if "kinds" in scope and (not isinstance(scope["kinds"], list) or any(not isinstance(v, str) for v in scope["kinds"])):
            raise ValueError(f"{path}: for_each_interface scope.kinds must be a list of strings")
        if "exclude_shutdown" in scope and not isinstance(scope["exclude_shutdown"], bool):
            raise ValueError(f"{path}: for_each_interface exclude_shutdown must be boolean")
        supported = {"config_line_present", "config_paths_present", "config_paths_and_regex", "config_regex_count",
                     "common_criteria_policy", "admin_auth_server_count", "emergency_local_account",
                     "vty_management_acl", "evidence_regex", "manual_review"}
        if not isinstance(check, dict) or check.get("type") not in supported:
            raise ValueError(f"{path}: for_each_interface requires a supported non-recursive check object")
        _validate_capabilities(check, path)
        _validate_strategy_details(check, path)


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
        allowed_keys = {
            "status", "automation_level", "control_id", "rule_id", "title", "severity", "target_platform",
            "target_families", "profiles", "evidence_requirements", "level", "standard_check", "pro_check",
            "recommendation", "rationale", "pass_condition", "fail_condition", "remediation", "source_ref",
            "stig_id", "stig_part", "evidence_refs",
        }
        unknown_keys = sorted(set(raw) - allowed_keys)
        if unknown_keys:
            raise ValueError(f"{path}: unknown approved-rule key(s): {', '.join(unknown_keys)}")
        required = ("control_id", "rule_id", "title", "severity", "target_platform", "level")
        missing = [key for key in required if not raw.get(key)]
        if missing:
            raise ValueError(f"{path}: approved rule missing required fields: {', '.join(missing)}")
        level = raw.get("level")
        standard_check = raw.get("standard_check")
        pro_check = raw.get("pro_check")
        if level not in {"standard", "pro"}:
            raise ValueError(f"{path}: level must be standard or pro")
        if level == "standard" and not isinstance(standard_check, dict):
            raise ValueError(f"{path}: level standard requires standard_check")
        if level == "pro" and (not isinstance(pro_check, dict) or standard_check is not None):
            raise ValueError(f"{path}: level pro requires pro_check and forbids standard_check")
        if standard_check is not None and not isinstance(standard_check, dict):
            raise ValueError(f"{path}: standard_check must be an object")
        if pro_check is not None and not isinstance(pro_check, dict):
            raise ValueError(f"{path}: pro_check must be an object")
        if standard_check is None and pro_check is None:
            raise ValueError(f"{path}: at least one check is required")
        if pro_check is not None and (not isinstance(raw.get("recommendation"), str) or not raw["recommendation"].strip()):
            raise ValueError(f"{path}: recommendation is required when pro_check exists")
        severity = str(raw["severity"]).lower()
        if severity not in {"critical", "high", "medium", "low"}:
            raise ValueError(f"{path}: unsupported severity {severity!r}")
        rule_profiles = tuple(raw.get("profiles") or ())
        if selected_profiles and rule_profiles and not selected_profiles.intersection(rule_profiles):
            continue
        strategy = standard_check or pro_check
        supported_strategies = {
            "config_line_present", "config_paths_present", "config_paths_and_regex",
            "config_regex_count", "common_criteria_policy", "admin_auth_server_count",
            "emergency_local_account", "vty_management_acl", "evidence_regex",
            "manual_review", "for_each_interface",
        }
        for extra_check in (standard_check, pro_check):
            if extra_check is not None and (not isinstance(extra_check, dict) or extra_check.get("type") not in supported_strategies):
                raise ValueError(f"{path}: unsupported standard_check or pro_check strategy")
            if extra_check is not None:
                _validate_capabilities(extra_check, path)
                _validate_strategy_details(extra_check, path)
                if extra_check.get("type") == "config_line_present" and not isinstance(extra_check.get("line"), str):
                    raise ValueError(f"{path}: config_line_present requires a line string")
                if extra_check.get("type") in {"config_paths_present", "config_paths_and_regex"}:
                    paths = extra_check.get("paths")
                    if not isinstance(paths, list) or not paths or any(not isinstance(p, list) or not p or any(not isinstance(line, str) or not line.strip() for line in p) for p in paths):
                        raise ValueError(f"{path}: path check requires non-empty paths of non-empty strings")
                if extra_check.get("type") == "config_regex_count":
                    minimum = extra_check.get("min_count")
                    if not isinstance(extra_check.get("pattern"), str) or not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 1:
                        raise ValueError(f"{path}: config_regex_count requires pattern and positive min_count")
                if extra_check.get("type") == "evidence_regex" and (not isinstance(extra_check.get("evidence_key"), str) or not isinstance(extra_check.get("pattern"), str)):
                    raise ValueError(f"{path}: evidence_regex requires evidence_key and pattern")
        if not isinstance(strategy, dict) or strategy.get("type") not in supported_strategies:
            raise ValueError(f"{path}: unsupported check_strategy")
        _validate_capabilities(strategy, path)
        if strategy.get("type") == "for_each_interface":
            scope = strategy.get("scope")
            check = strategy.get("check")
            if not isinstance(scope, dict) or not scope or set(scope) - {"roles", "kinds", "exclude_shutdown"}:
                raise ValueError(f"{path}: for_each_interface requires a valid scope object")
            if "roles" in scope and (not isinstance(scope["roles"], list) or any(not isinstance(v, str) for v in scope["roles"])):
                raise ValueError(f"{path}: for_each_interface scope.roles must be a list of strings")
            if "kinds" in scope and (not isinstance(scope["kinds"], list) or any(not isinstance(v, str) for v in scope["kinds"])):
                raise ValueError(f"{path}: for_each_interface scope.kinds must be a list of strings")
            if "exclude_shutdown" in scope and not isinstance(scope["exclude_shutdown"], bool):
                raise ValueError(f"{path}: for_each_interface scope.exclude_shutdown must be boolean")
            if not isinstance(check, dict) or check.get("type") not in supported_strategies - {"for_each_interface"}:
                raise ValueError(f"{path}: for_each_interface requires a supported non-recursive check object")
            _validate_capabilities(check, path)
            if check.get("type") == "config_line_present" and not isinstance(check.get("line"), str):
                raise ValueError(f"{path}: for_each_interface config_line_present check requires a line string")
            if check.get("type") in {"config_paths_present", "config_paths_and_regex"}:
                paths = check.get("paths")
                if not isinstance(paths, list) or not paths or any(not isinstance(p, list) or not p for p in paths):
                    raise ValueError(f"{path}: for_each_interface path check requires non-empty paths")
            if check.get("type") == "config_regex_count":
                if not isinstance(check.get("pattern"), str) or not isinstance(check.get("min_count"), int) or isinstance(check.get("min_count"), bool) or check["min_count"] < 1:
                    raise ValueError(f"{path}: for_each_interface config_regex_count requires pattern and positive min_count")
        if strategy["type"] == "config_line_present":
            if not isinstance(strategy.get("line"), str):
                raise ValueError(f"{path}: config_line_present requires a line string")
            if strategy.get("context", "global") not in {"global", "any"}:
                raise ValueError(f"{path}: config_line_present context must be global or any")
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
            level=level,
            standard_check=dict(standard_check) if standard_check is not None else None,
            pro_check=dict(pro_check) if pro_check is not None else None,
            recommendation=raw.get("recommendation"),
            rationale=raw.get("rationale"),
            stig_id=raw.get("stig_id"),
            stig_part=raw.get("stig_part"),
            evidence_refs=tuple(raw.get("evidence_refs") or ()),
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
        required = ("control_id", "reason", "approved_by", "expires_on", "hostnames")
        if any(not item.get(key) for key in required):
            raise ValueError("waiver requires control_id, reason, approved_by, expires_on, and hostnames")
        hostnames = item.get("hostnames")
        if not isinstance(hostnames, list) or not hostnames or any(not isinstance(host, str) or not host.strip() for host in hostnames):
            raise ValueError("waiver hostnames must be a non-empty list of hostnames or [\"*\"]")
        if "*" in hostnames and hostnames != ["*"]:
            raise ValueError("wildcard waiver scope must be exactly [\"*\"]")
        try:
            expiry = date.fromisoformat(item["expires_on"])
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid waiver expires_on for {item.get('control_id')}") from exc
        waiver = Waiver(item["control_id"], item["reason"], item["approved_by"], expiry, tuple(hostnames))
        if waiver.control_id in out:
            raise ValueError(f"duplicate waiver for {waiver.control_id}")
        out[waiver.control_id] = waiver
    return out


def parse_ios_show_version(text: str | None) -> dict[str, str | None]:
    """Extract only clear model/version tokens; never infer a family from vague output."""
    if not text:
        return {"model": None, "version": None, "family": None, "family_status": "unknown"}
    model = None
    version = None
    # Preserve the model token from the explicit field, including identifiers
    # such as WS-C2960+24TC-L. The project supports only 2960-X/XR/L families.
    model_match = re.search(
        r"(?im)^\s*Model Number\s*:\s*([A-Za-z0-9][A-Za-z0-9+._/-]*)", text
    )
    if not model_match:
        model_match = re.search(
            r"(?im)^\s*(?:cisco\s+)?(WS-C[0-9A-Z+-]+)\s+", text
        )
    if model_match:
        model = model_match.group(1).strip().upper()
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
    # Scope evidence: resorce/Cisco switch and router/U_Cisco_IOS_Switch_RTR_V3R3_Manual_STIG/U_Cisco_IOS_Switch_RTR_STIG_V3R3_Manual-xccdf.xml titles this benchmark "Cisco IOS Switch RTR" but does not enumerate supported models. The project scope is intentionally limited to 2960-X/XR/L.
    family_status = "supported" if family else ("out_of_scope_model" if model else "unknown")
    return {"model": model, "version": version, "family": family, "family_status": family_status}


def _result(rule: AssessmentRule, status: str, detail: str) -> AssessmentResult:
    return AssessmentResult(rule.control_id, rule.rule_id, rule.title, rule.severity,
                            status, detail, rule.remediation, rule.source_ref)


def _strip_banner_blocks(config: str) -> str:
    """Remove IOS banner commands and bodies, including inline one-line banners."""
    output: list[str] = []
    delimiter: str | None = None
    for line in config.splitlines():
        if delimiter is not None:
            if delimiter in line:
                delimiter = None
            continue

        # The delimiter is the first token after the banner type. IOS permits
        # the closing delimiter on the same line or on a later line.
        match = re.match(r"^[ \t]*banner\s+\S+\s+(\^C|.)", line, re.IGNORECASE)
        if match:
            delimiter = match.group(1)
            banner_body = line[match.end():]
            if delimiter in banner_body:
                delimiter = None
            continue

        output.append(line)
    return "\n".join(output)


def _config_tree(config: str) -> list[dict[str, Any]]:
    """Parse indented IOS configuration into a small hierarchy for context checks."""
    config = _strip_banner_blocks(config)
    roots: list[dict[str, Any]] = []
    stack: list[tuple[int, dict[str, Any]]] = []
    for raw_line in config.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        if raw_line.lstrip().startswith("!"):
            stack.clear()
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" \t"))
        node = {"line": re.sub(r"\s+", " ", stripped).casefold(), "raw_line": stripped, "children": []}
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


def _evaluate_rule_impl(
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
    # A supplied show-version model outside the verified project scope must
    # never be assessed as supported merely because DeviceContext.family was set.
    if device.platform == rule.target_platform and device.show_version:
        parsed_model = parse_ios_show_version(device.show_version)
        if parsed_model.get("family_status") == "out_of_scope_model":
            return _result(
                rule,
                "UNKNOWN",
                f"Detected model {parsed_model.get('model')} is outside supported scope; supported families are Catalyst 2960-X/XR/L.",
            )
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
            parsed = parse_ios_show_version(device.show_version) if device.show_version else {"model": None, "family_status": "unknown"}
            if parsed.get("family_status") == "out_of_scope_model":
                return _result(rule, "UNKNOWN", f"Detected model {parsed.get('model')} is outside supported scope; supported families are Catalyst 2960-X/XR/L.")
            return _result(rule, "UNKNOWN", "Device family is not verified; provide family or recognizable show-version evidence.")
        if family not in rule.target_families:
            return _result(rule, "NOT_APPLICABLE", f"Verified device family {family!r} is outside the rule target families.")
    if rule.evidence_requirements:
        missing = [key for key in rule.evidence_requirements if key not in evidence or not evidence[key].strip()]
        if missing:
            return _result(rule, "UNKNOWN", "Required evidence is missing: " + ", ".join(missing))
    strategy = rule.check_strategy or {}
    kind = strategy.get("type")
    if kind == "for_each_interface":
        if config is None or not config.strip():
            return _result(rule, "UNKNOWN", "Configuration evidence is missing or empty; interface scope cannot be determined.")
        from .assess.interfaces import classify_interfaces
        scope = strategy["scope"]
        inventory = classify_interfaces(config, hostname=device.hostname, roles_dir=device.roles_dir, operator_roles=device.operator_roles)
        kinds = set(scope.get("kinds", ()))
        roles = set(scope.get("roles", ()))
        candidates = [
            item for item in inventory
            if (not kinds or item.kind in kinds)
            and not (scope.get("exclude_shutdown", True) and item.admin_shutdown)
            and (not roles or item.role in roles or item.role == "unknown")
        ]
        if not candidates:
            return _result(rule, "NOT_APPLICABLE", "No interfaces matched the configured scope.")
        unknown_roles = [item.name for item in candidates if item.role == "unknown"]
        check = dict(strategy["check"])
        if check.get("type") == "config_line_present":
            check.setdefault("context", "any")
        failed: list[str] = []
        unknown_checks: list[str] = []
        manual: list[str] = []
        for interface in candidates:
            if interface.role == "unknown":
                continue
            interface_config = "\n".join([f"interface {interface.name}", *[f" {line}" for line in interface.evidence[1:]]])
            subrule = replace(rule, check_strategy=check, evidence_requirements=())
            result = _apply_capability_policy(_evaluate_rule_impl(subrule, device, interface_config, evidence, None, today), check)
            if result.status == "FAIL":
                failed.append(interface.name)
            elif result.status == "UNKNOWN":
                unknown_checks.append(interface.name)
            elif result.status == "MANUAL":
                manual.append(interface.name)
        if failed:
            names = ", ".join(failed[:10])
            suffix = f" (and {len(failed) - 10} more)" if len(failed) > 10 else ""
            return _result(rule, "FAIL", f"Sub-check failed on {len(failed)} of {len(candidates)} in-scope interface(s): {names}{suffix}")
        if unknown_roles:
            names = ", ".join(unknown_roles[:10])
            suffix = f" (and {len(unknown_roles) - 10} more)" if len(unknown_roles) > 10 else ""
            return _result(rule, "UNKNOWN", f"Interface role is unknown for {len(unknown_roles)} of {len(candidates)} candidate interface(s): {names}{suffix}")
        if unknown_checks:
            names = ", ".join(unknown_checks[:10])
            suffix = f" (and {len(unknown_checks) - 10} more)" if len(unknown_checks) > 10 else ""
            return _result(rule, "UNKNOWN", f"Sub-check evidence is unknown on {len(unknown_checks)} of {len(candidates)} interface(s): {names}{suffix}")
        if manual:
            names = ", ".join(manual[:10])
            suffix = f" (and {len(manual) - 10} more)" if len(manual) > 10 else ""
            return _result(rule, "MANUAL", f"Sub-check requires manual review on {len(manual)} of {len(candidates)} interface(s): {names}{suffix}")
        return _result(rule, "PASS", f"Sub-check passed on {len(candidates)} of {len(candidates)} in-scope interface(s).")
    if kind == "config_line_present":
        if config is None or not config.strip():
            return _result(rule, "UNKNOWN", "Configuration evidence is missing or empty.")
        expected = strategy["line"].strip()
        clean_config = _strip_banner_blocks(config)
        context = strategy.get("context", "global")
        lines = {
            line.strip() for line in clean_config.splitlines()
            if line.strip() and not line.lstrip().startswith("!")
            and (context == "any" or not line[:1].isspace())
        }
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
            clean_config = "\n".join(line for line in _strip_banner_blocks(config).splitlines() if not line.lstrip().startswith("!"))
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
        clean_config = "\n".join(line for line in _strip_banner_blocks(config).splitlines() if not line.lstrip().startswith("!"))
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
        clean_lines = [line for line in _strip_banner_blocks(config).splitlines() if not line.lstrip().startswith("!")]
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


def evaluate_rule(
    rule: AssessmentRule,
    device: DeviceContext,
    config: str | None,
    evidence: dict[str, str] | None = None,
    waiver: Waiver | None = None,
    today: date | None = None,
) -> AssessmentResult:
    """Evaluate one rule with host-scoped waiver enforcement and expiry reporting."""
    today = today or date.today()
    scoped = waiver is not None and (device.hostname in waiver.hostnames or waiver.hostnames == ("*",))
    active = scoped and waiver.expires_on >= today
    expired = scoped and waiver.expires_on < today
    result = _apply_capability_policy(_evaluate_rule_impl(rule, device, config, evidence, waiver if active else None, today), rule.check_strategy or {})
    if expired:
        result = replace(result, detail=result.detail + f" Expired waiver ignored (expired {waiver.expires_on.isoformat()}); result is not waived.")
    elif active and waiver.hostnames == ("*",):
        result = replace(result, detail=result.detail + " Explicit wildcard waiver scope (*) applies to all hosts.")
    return result


def evaluate_rule_levels(
    rule: AssessmentRule,
    device: DeviceContext,
    config: str | None,
    evidence: dict[str, str] | None = None,
    roles: dict[str, dict[str, str]] | None = None,
    waivers: dict[str, Waiver] | None = None,
    today: date | None = None,
    level: str = "pro",
) -> RuleRow:
    """Evaluate Standard and Pro cells independently; Standard remains the minimum verdict."""
    if level not in {"standard", "pro"}:
        raise ValueError("level must be 'standard' or 'pro'")
    if roles is not None:
        device = replace(device, operator_roles=roles)
    standard_check = rule.standard_check
    pro_check = rule.pro_check
    if standard_check is None and pro_check is None and rule.check_strategy is not None:
        # Compatibility for in-memory legacy rules; approved file schema is validated separately.
        standard_check = rule.check_strategy
    waiver = (waivers or {}).get(rule.control_id)

    def evaluate_cell(check: dict[str, Any], depth: str, recommendation: str | None = None) -> CheckCell:
        cell_rule = replace(rule, check_strategy=check)
        result = evaluate_rule(cell_rule, device, config, evidence, waiver, today)
        return CheckCell(
            status=result.status,
            detail=result.detail,
            depth=depth,
            recommendation=recommendation,
            downgraded_from=result.downgraded_from,
        )

    standard = evaluate_cell(standard_check, "presence") if standard_check is not None else None
    if level == "standard":
        pro = CheckCell("NOT_RUN", "Not run because --level standard was selected.", "applied", rule.recommendation) if pro_check is not None else None
    else:
        pro = evaluate_cell(pro_check, "applied", rule.recommendation) if pro_check is not None else None
    return RuleRow(
        control_id=rule.control_id,
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        standard=standard,
        pro=pro,
        level=rule.level,
        rationale=rule.rationale,
        source_ref=rule.source_ref,
        stig_id=rule.stig_id,
        stig_part=rule.stig_part,
        evidence_refs=rule.evidence_refs,
    )


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
    return sorted(
        results,
        key=lambda item: (SEVERITY_RANK.get(item.severity.casefold(), len(SEVERITY_RANK)), item.control_id),
    )


def coverage_summary(results: Iterable[AssessmentResult]) -> dict[str, int]:
    items = list(results)
    counts = {status: 0 for status in STATUSES}
    for result in items:
        counts[result.status] += 1
    counts["TOTAL"] = len(items)
    return counts


def exit_code(
    results: Iterable[AssessmentResult | RuleRow],
    fail_on: str = "high",
    allow_unknown: bool = False,
    strict_manual: bool = False,
    fail_on_pro: str = "none",
) -> int:
    """0 complete; 2 qualifying Standard/opt-in Pro finding; 3 incomplete by policy; 1 invalid policy."""
    valid_thresholds = {"none", "critical", "high", "medium", "low"}
    if fail_on not in valid_thresholds or fail_on_pro not in valid_thresholds:
        return 1
    items = list(results)
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    def qualifies(status: str, severity: str, threshold: str) -> bool:
        return threshold != "none" and status == "FAIL" and severity.casefold() in rank and rank[severity.casefold()] <= rank[threshold]

    standard_cells: list[tuple[str, str]] = []
    for item in items:
        # Accept RuleRow-like objects as well as the exact class. This keeps
        # the policy correct if callers load equivalent rows through a module
        # alias or test harness.
        if hasattr(item, "standard") and hasattr(item, "pro"):
            standard = item.standard
            pro = item.pro
            if standard is not None:
                standard_cells.append((standard.status, item.severity))
            if pro is not None and qualifies(pro.status, item.severity, fail_on_pro):
                return 2
        else:
            standard_cells.append((item.status, item.severity))
    if any(qualifies(status, severity, fail_on) for status, severity in standard_cells):
        return 2
    if not allow_unknown and any(status == "UNKNOWN" for status, _ in standard_cells):
        return 3
    if strict_manual and any(status == "MANUAL" for status, _ in standard_cells):
        return 3
    return 0


def report_markdown(
    device: DeviceContext,
    results: Iterable[AssessmentResult],
    interfaces: Iterable[Any] | None = None,
) -> str:
    items = sorted(
        results,
        key=lambda item: (SEVERITY_RANK.get(item.severity.casefold(), len(SEVERITY_RANK)), item.control_id),
    )
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
    if interfaces is not None:
        inventory = list(interfaces)
        role_counts: dict[str, int] = {}
        for interface in inventory:
            role = interface.role if hasattr(interface, "role") else interface.get("role", "unknown")
            role_counts[role] = role_counts.get(role, 0) + 1
        out += ["", "## Interface inventory", "", "| Role | Count |", "|---|---:|"]
        for role, count in sorted(role_counts.items()):
            out.append(f"| {role} | {count} |")
        unknown = [interface.name if hasattr(interface, "name") else interface.get("name", "unknown")
                   for interface in inventory
                   if (interface.role if hasattr(interface, "role") else interface.get("role", "unknown")) == "unknown"]
        out += ["", "Unknown-role interfaces: " + (", ".join(unknown) if unknown else "none")]
    out += ["", "| Control | Severity | Status | Title | Detail |", "|---|---|---|---|---|"]
    for item in items:
        clean_detail = item.detail.replace("|", "\\|").replace("\n", " ")
        clean_title = item.title.replace("|", "\\|")
        out.append(f"| {item.control_id} | {item.severity} | {item.status} | {clean_title} | {clean_detail} |")
    out += ["", "> Results are evidence-based assessments, not a security percentage. Draft rules are never evaluated."]
    return "\n".join(out) + "\n"
