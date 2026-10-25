"""Local smoke-test harness for selected Cisco IOS STIG checks.

This harness deliberately evaluates draft/test-only rules. It does not approve rules,
collect device evidence, print the config, or modify a device or the source config.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from netagent.stig_assessment import AssessmentRule, DeviceContext, evaluate_rule, coverage_summary


DEFAULT_CONFIG = PROJECT_ROOT / "examples" / "configs" / "config.old"
CATALOG_PATH = PROJECT_ROOT / "standards" / "disa-cisco-ios-switch" / "Y26M04" / "catalog.json"
DRAFT_ROOT = PROJECT_ROOT / "rules" / "cisco_ios" / "drafts"
FAMILIES = ("Catalyst 2960-X", "Catalyst 2960-XR", "Catalyst 2960-L")

# These remain drafts in the real rules directory. This harness loads them explicitly
# for testing only; the production approved-rule loader continues to ignore them.
PILOT_IDS = {"V-220625", "V-220631"}

# Test-only assessment strategies keyed by real STIG control IDs from catalog.json.
# Context paths verify parent/child hierarchy; count prechecks cannot produce PASS
# for controls that need additional review.
TEST_STRATEGIES = {
    "V-220571": {
        "type": "config_paths_present",
        "paths": [["archive", "log config", "logging enable"]],
    },
    "V-220578": {
        "type": "config_paths_present",
        "paths": [["logging userinfo"], ["archive", "log config", "logging enable"]],
    },
    "V-220587": {
        "type": "emergency_local_account",
    },
    "V-220589": {
        "type": "common_criteria_policy",
        "directive": "min-length 15",
    },
    "V-220590": {
        "type": "common_criteria_policy",
        "directive": "upper-case 1",
    },
    "V-220591": {
        "type": "common_criteria_policy",
        "directive": "lower-case 1",
    },
    "V-220592": {
        "type": "common_criteria_policy",
        "directive": "numeric-count 1",
    },
    "V-220593": {
        "type": "common_criteria_policy",
        "directive": "special-case 1",
    },
    "V-220594": {
        "type": "common_criteria_policy",
        "directive": "char-changes 8",
    },
    "V-220582": {
        "type": "config_paths_present",
        "paths": [["archive", "log config", "logging enable"]],
    },
    "V-220575": {
        "type": "vty_management_acl",
    },
    "V-220617": {
        "type": "admin_auth_server_count",
        "min_count": 2,
    },
    "V-220620": {
        "type": "config_regex_count",
        "pattern": r"(?im)^[ \t]*logging(?: host)?\s+(?:\d{1,3}\.){3}\d{1,3}\b",
        "min_count": 2,
        "partial": True,
        "partial_note": "This counts logging destination declarations only; it does not prove log delivery, destination independence, or alert routing.",
    },
    "V-220623": {
        "type": "manual_review",
        "reason": "Full 802.1X/MAB assessment requires classifying every host-facing interface and validating port-control, host-mode, RADIUS group and operational evidence.",
    },
}

AAA_IDS = set(TEST_STRATEGIES)
LAYER2_IDS = set(PILOT_IDS)


def load_catalog_controls() -> dict[str, dict]:
    raw = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    controls = raw.get("controls")
    if not isinstance(controls, list):
        raise ValueError(f"Invalid STIG catalog format: {CATALOG_PATH}")
    return {item["control_id"]: item for item in controls if item.get("control_id")}


def from_draft(raw: dict) -> AssessmentRule:
    return AssessmentRule(
        control_id=raw["control_id"],
        rule_id=raw["rule_id"],
        title=raw["title"],
        severity=raw["severity"].lower(),
        status=raw.get("status", "draft"),
        automation_level=raw.get("automation_level", "manual"),
        target_platform=raw["target_platform"],
        target_families=tuple(raw.get("target_families") or ()),
        profiles=tuple(raw.get("profiles") or ()),
        evidence_requirements=tuple(raw.get("evidence_requirements") or ()),
        check_strategy=raw.get("check_strategy"),
        pass_condition=raw.get("pass_condition"),
        fail_condition=raw.get("fail_condition"),
        remediation=raw.get("remediation"),
        source_ref=raw.get("source_ref") or {},
    )


def load_test_rules() -> list[AssessmentRule]:
    catalog = load_catalog_controls()
    found: dict[str, AssessmentRule] = {}

    for path in sorted(DRAFT_ROOT.glob("*.json")):
        if path.name == "manifest.json":
            continue
        raw = json.loads(path.read_text(encoding="utf-8"))
        if raw.get("control_id") in PILOT_IDS:
            found[raw["control_id"]] = from_draft(raw)

    missing_pilots = PILOT_IDS - set(found)
    if missing_pilots:
        raise ValueError("Pilot draft(s) not found: " + ", ".join(sorted(missing_pilots)))

    for control_id, strategy in TEST_STRATEGIES.items():
        item = catalog.get(control_id)
        if item is None:
            raise ValueError(f"Control {control_id} is missing from {CATALOG_PATH}")
        found[control_id] = AssessmentRule(
            control_id=control_id,
            rule_id=item["rule_id"],
            title=item["title"],
            severity=item["severity"].lower(),
            status="draft",
            automation_level="manual",
            target_platform="cisco_ios",
            target_families=FAMILIES,
            check_strategy=strategy,
            source_ref=item.get("source_ref") or {},
        )
    return [found[key] for key in sorted(found)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config", type=Path, default=DEFAULT_CONFIG,
        help="path to the IOS config file (default: examples/configs/config.old)",
    )
    parser.add_argument(
        "--family", choices=FAMILIES, default=None,
        help="verified target family; omit to make family-dependent rules UNKNOWN",
    )
    parser.add_argument(
        "--group", choices=("all", "aaa", "layer2"), default="all",
        help="run all selected checks, AAA-related checks, or the two Layer-2 pilot checks",
    )
    args = parser.parse_args()

    try:
        config = args.config.read_text(encoding="utf-8", errors="replace")
        rules = load_test_rules()
    except (OSError, json.JSONDecodeError, KeyError, ValueError) as exc:
        parser.error(str(exc))

    if args.group == "aaa":
        rules = [rule for rule in rules if rule.control_id in AAA_IDS]
    elif args.group == "layer2":
        rules = [rule for rule in rules if rule.control_id in LAYER2_IDS]

    device = DeviceContext(
        hostname=args.config.stem,
        platform="cisco_ios",
        family=args.family,
    )
    results = [evaluate_rule(rule, device, config) for rule in rules]

    print("Cisco IOS STIG engine test (explicit test-only draft rules; NOT an approved assessment)")
    print(f"Config file: {args.config}")
    print(f"Device family: {args.family or 'unverified'}")
    print(f"Check group: {args.group}")
    print(f"Rules tested: {len(results)}")
    print("Configuration contents, IP addresses, usernames, and secrets are not printed.")
    print()
    by_id = {rule.control_id: rule for rule in rules}
    for result in results:
        rule = by_id[result.control_id]
        print(f"{result.control_id} | {result.severity.upper():6} | {result.status:16} | {result.title}")
        print(f"  {result.detail}")
    print()
    print("Summary:", json.dumps(coverage_summary(results), sort_keys=True))
    print()
    print("Limitations:")
    print("- These are draft smoke-test checks sourced from the local STIG catalog, not approved production rules.")
    print("- A PASS only covers the explicit configured predicate; it does not prove the whole switch meets STIG.")
    print("- Manual/partial controls remain MANUAL; command presence does not prove runtime behavior.")
    print("- Model/IOS feature support and the complete device applicability profile have not been verified.")
    print("- load_approved_rules() continues to ignore all drafts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
