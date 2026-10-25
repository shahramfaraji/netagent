"""Generate conservative, non-executable draft rule skeletons from a DISA catalog."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


def slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def classify_control(control: dict) -> tuple[str, str]:
    """Conservative heuristic triage only; never approves a rule for execution."""
    raw_text = control.get("check_text") or ""
    text = raw_text.lower()
    title = (control.get("title") or "").lower()
    combined = text + "\n" + title

    # These checks depend on network design, interface/ACL placement, external evidence,
    # or operational context. Do not infer those facts from a running-config snippet.
    manual_signals = (
        "review the switch topology", "as determined by the site", "organization-defined",
        "organization defined", "site-specific", "site specific", "approved by",
        "documented", "risk assessment", "management approval", "not applicable for the dodin",
        "external interface", "all access switch ports", "all host-facing", "all user-facing",
        "all interfaces", "connecting to", "as required by the organization", "if applicable",
        "verify with the system administrator", "interface gigabitethernet", "interface vlan",
        "access-list", "access-group", "access-class", "log-input", "out-of-band", "oobm",
        "multicast", "ip core infrastructure", "authorized sources", "authorized destinations",
        "trustpoint", "trust point", "certificate", "account of last resort",
        "only one local account", "at least two", "two central log servers",
        "all internal interfaces", "external or ce-facing", "operational network",
        "when connected to", "dodin backbone", "depending on", "depending upon",
        "step 1:", "step 2:", "step 3:", "step 4:",
    )
    if any(signal in combined for signal in manual_signals):
        return (
            "manual_review",
            "Source text indicates interface/ACL placement, topology, certificate or account context, applicability, or other environmental judgment; keep manual until reviewed.",
        )

    explicit_binary = "this is a finding" in text
    # Extract likely IOS configuration lines. A candidate must be a single direct global
    # command check: examples with multi-line stanzas, interface context, placeholders,
    # ellipses, or explanatory qualifications are intentionally not candidates.
    config_lines = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line or line.startswith(("!", "#", "…", "...")):
            continue
        if re.match(r"^(?:SW\S*[>#]\s*)", line, re.I):
            line = re.sub(r"^(?:SW\S*[>#]\s*)", "", line, flags=re.I).strip()
        if re.match(
            r"^(?:no\s+)?(?:aaa|service|logging|ntp|snmp-server|ip\s+ssh|ip\s+http|"
            r"ipv6\s+unicast-routing|mls\s+qos|spanning-tree|login|banner|exec-timeout|"
            r"transport input|username|enable secret|enable password|crypto|clock|vtp|"
            r"errdisable|lldp|cdp|password)\b",
            line,
            re.I,
        ):
            config_lines.append(re.sub(r"\s+", " ", line.lower()))
    unique_commands = set(config_lines)
    disqualifiers = (
        "step ", "note:", "example", "x.x.x", "xxxxxxxx", "…", "...",
        "all ports", "all interfaces", "topology", "redundant", "at least",
        "depending on", "depending upon", "if configured", "if the switch is configured",
        "not applicable", "only permit", "only allow",
    )
    simple_global_command = (
        explicit_binary
        and len(unique_commands) == 1
        and not any(marker in text for marker in disqualifiers)
        and not re.search(r"(?m)^\s*interface\s+", text)
        and not re.search(r"(?m)^\s*(?:ip|ipv6)\s+access-list\b", text)
    )
    if simple_global_command:
        return (
            "candidate_automated",
            "Narrow heuristic candidate: one direct global IOS command and a binary finding statement; syntax, defaults, platform support, and fixtures still require validation.",
        )

    if explicit_binary and unique_commands:
        return (
            "semi_automated",
            "Configuration evidence may be machine-readable, but the check includes multiple commands, a configuration stanza, qualifications, or parsing complexity; human review is required before implementation.",
        )

    return (
        "manual_review",
        "No sufficiently clear single-command configuration-only pattern was identified; human review is required.",
    )


def generate(catalog_path: Path, output_dir: Path) -> dict:
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    controls = catalog.get("controls")
    if not isinstance(controls, list):
        raise ValueError("catalog must contain a controls list")

    seen = set()
    counts = {"total": 0, "severity": {}, "stig": {}, "classification": {}}
    for control in controls:
        required = ("control_id", "rule_id", "stig", "stig_id", "severity", "title", "source_ref", "check_text", "fix_text")
        missing = [key for key in required if key not in control]
        if missing:
            raise ValueError(f"{control.get('control_id', '<unknown>')}: missing {', '.join(missing)}")
        filename = f"{slug(control['stig'])}-{slug(control['stig_id'])}-{slug(control['control_id'])}.json"
        if filename in seen:
            raise ValueError(f"duplicate output filename: {filename}")
        seen.add(filename)
        classification, rationale = classify_control(control)
        draft = {
            "schema_version": 1,
            "status": "draft",
            "automation_level": "manual",
            "triage_classification": classification,
            "classification_rationale": rationale,
            "target_platform": "cisco_ios",
            "target_families": ["Catalyst 2960-X", "Catalyst 2960-XR", "Catalyst 2960-L"],
            "control_id": control["control_id"],
            "rule_id": control["rule_id"],
            "stig": control["stig"],
            "stig_id": control["stig_id"],
            "severity": control["severity"],
            "category": control.get("category"),
            "title": control["title"],
            "source_ref": control["source_ref"],
            "source_check_text": control["check_text"],
            "source_fix_text": control["fix_text"],
            "cci": control.get("cci", []),
            "applicability": "unknown",
            "evidence_requirements": [],
            "check_strategy": None,
            "pass_condition": None,
            "fail_condition": None,
            "remediation": None,
            "fixture_status": "not_created",
            "reviewer": None,
            "review_notes": [],
        }
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / filename).write_text(
            json.dumps(draft, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        counts["total"] += 1
        counts["severity"][control["severity"]] = counts["severity"].get(control["severity"], 0) + 1
        counts["stig"][control["stig"]] = counts["stig"].get(control["stig"], 0) + 1
        counts["classification"][classification] = counts["classification"].get(classification, 0) + 1

    manifest = {
        "schema_version": 1,
        "catalog_version": catalog.get("catalog_version"),
        "source_catalog": catalog_path.as_posix(),
        "generated_count": counts["total"],
        "policy": "All controls remain status=draft and automation_level=manual. Triage classification is heuristic only; no rule is executable or approved.",
        "classification_method": "Conservative keyword/structure heuristic over source check text; requires human review and fixture-backed validation.",
        "counts": counts,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=Path("standards/disa-cisco-ios-switch/Y26M04/catalog.json"))
    parser.add_argument("--out", type=Path, default=Path("rules/cisco_ios/drafts"))
    args = parser.parse_args()
    manifest = generate(args.catalog, args.out)
    print(f"Generated {manifest['generated_count']} draft skeletons in {args.out}")
    print("Severity counts: " + json.dumps(manifest["counts"]["severity"], sort_keys=True))
    print("STIG counts: " + json.dumps(manifest["counts"]["stig"], sort_keys=True))
    print("Triage counts: " + json.dumps(manifest["counts"]["classification"], sort_keys=True))
    print("Note: triage is heuristic only; all rules remain manual and non-executable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
