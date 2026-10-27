"""netagent CLI: discover | backup | apply | rollback | topology | audit"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from . import __version__
from .collector import ConfigStore, fetch, check_ssh_connection
from .compliance import evaluate_detailed, load_rules, report_markdown
from .credentials import get_credential
from .discovery import discover
from .deploy import (ApprovalResult, ApprovalStatus, apply_config, preview_config, redact_config,
                     rollback_config, risky_command_groups, load_risk_allowlist)
from .models import load_inventory
from .topology import build_graph, parse_neighbors, to_json, to_mermaid
from .ssh import trust_host_key
from .evidence import collect_device_readonly_evidence, load_evidence_bundle
from .reporting import build_json_report, render_html_report, render_json_report, render_markdown_report
from .stig_assessment import DeviceContext, evaluate_rule_levels, exit_code, load_approved_rules, load_waivers
from .stig_export import render_cklb, render_xccdf_testresult


def cmd_discover(a) -> int:
    hosts = discover(a.cidr)
    rows = [{"ip": h.ip, "open_ports": h.open_ports, "hostname": h.hostname,
             "os_guess": h.os_guess, "role_guess": h.guessed_role,
             "services": h.services} for h in hosts]
    text = json.dumps(rows, indent=2)
    Path(a.out).write_text(text, encoding="utf-8") if a.out else print(text)
    print(f"{len(rows)} host(s) with management ports open", file=sys.stderr)
    return 0


def cmd_trust_host_key(a) -> int:
    if a.no_prompt or not sys.stdin.isatty():
        raise RuntimeError("trust-on-first-use requires an interactive terminal; unknown hosts are rejected in non-interactive mode")
    device = _selected_device(a.inventory, a.device)
    print(trust_host_key(device, known_hosts=a.known_hosts))
    return 0


def cmd_collect_evidence(a) -> int:
    device = _selected_device(a.inventory, a.device)
    if device.platform != "cisco_ios":
        raise ValueError(f"read-only STIG evidence collection supports only cisco_ios, not {device.platform!r}")
    cred = get_credential(prompt=not a.no_prompt)
    result = collect_device_readonly_evidence(
        device, cred, a.out_dir, timeout=a.timeout, known_hosts=a.known_hosts
    )
    print(f"Collected {len(result['files'])} evidence files for {device.hostname} -> {a.out_dir}")
    for warning in result["warnings"]:
        print(f"WARNING: {warning}", file=sys.stderr)
    return 0


def cmd_test_ssh(a) -> int:
    device = _selected_device(a.inventory, a.device)
    cred = get_credential(prompt=not a.no_prompt)
    check_ssh_connection(device, cred)
    print(f"SSH OK: {device.hostname} ({device.host}:{device.port}, {device.platform})")
    return 0


def cmd_backup(a) -> int:
    devices = load_inventory(a.inventory)
    if a.device:
        devices = [device for device in devices if device.hostname == a.device]
        if not devices:
            raise ValueError(f"device {a.device!r} was not found in inventory")
    cred = get_credential(prompt=not a.no_prompt)
    store = ConfigStore(Path(a.data) / "configs")
    nbr_dir = Path(a.data) / "neighbors"
    nbr_dir.mkdir(parents=True, exist_ok=True)
    failed = 0
    for d in devices:
        try:
            out = fetch(d, cred)
        except RuntimeError as exc:
            failed += 1
            print(f"FAIL {exc}", file=sys.stderr)
            continue
        changed, _ = store.save(d.hostname, out["config"])
        artifacts = {key: value for key, value in out.items() if key.startswith("routeros_")}
        if artifacts:
            store.save_artifacts(d.hostname, artifacts)
        if "neighbors" in out:
            (nbr_dir / f"{d.hostname}.txt").write_text(out["neighbors"], encoding="utf-8")
        print(f"{'CHANGED' if changed else 'same   '} {d.hostname}")
    return 1 if failed else 0


def _selected_device(inventory: str, hostname: str):
    devices = load_inventory(inventory)
    matches = [device for device in devices if device.hostname == hostname]
    if not matches:
        raise ValueError(f"device {hostname!r} was not found in inventory")
    return matches[0]


def _require_interactive_approval() -> None:
    if not sys.stdin.isatty():
        raise RuntimeError("live config changes require an interactive terminal; dry-run remains available")


def cmd_apply(a) -> int:
    device = _selected_device(a.inventory, a.device)
    candidate = Path(a.config).read_text(encoding="utf-8")
    if a.apply:
        _require_interactive_approval()
    cred = get_credential(prompt=not a.no_prompt)
    store = ConfigStore(Path(a.data) / "configs")
    if not a.apply:
        preview = preview_config(device, candidate, cred)
        print(f"DRY RUN for {preview.hostname} ({preview.platform})")
        print(f"Current config sha256={preview.current_config_sha256}")
        if not preview.changed:
            print("No changes detected; device was not modified.")
            return 0
        print(f"Candidate: {preview.candidate_lines} command(s), sha256={preview.candidate_sha256}")
        print("Candidate commands (preview only, not a simulated post-change config):")
        print(preview.diff)
        if preview.risky_commands:
            print("Management-risk commands (require exact allowlist entries and separate confirmation):")
            for command in preview.risky_commands:
                print(f"  {redact_config(command)}")
        return 0

    def approve(preview):
        print(f"\nLIVE CHANGE PREVIEW for {preview.hostname} ({preview.platform})")
        print(f"Current config sha256={preview.current_config_sha256}")
        print(f"Candidate: {preview.candidate_lines} command(s), sha256={preview.candidate_sha256}")
        print("Candidate commands (preview only, not a simulated post-change config):")
        print(preview.diff)
        print(f"Verified backups: local {preview.local_backup}, device {preview.device_backup}")
        if input(f"Type {preview.hostname} to approve this config change: ").strip() != preview.hostname:
            return ApprovalResult(ApprovalStatus.DECLINED)
        confirmed_groups = []
        if preview.risky_commands:
            print("MANAGEMENT-RISK COMMANDS (each group requires its own confirmation):")
            for group, commands in risky_command_groups(preview.risky_commands).items():
                print(f"  [{group}]")
                for command in commands:
                    print(f"    {redact_config(command)}")
                expected = f"RISK {preview.hostname} {group}"
                if input(f"Type {expected} to confirm this risk group: ").strip() != expected:
                    return ApprovalResult(ApprovalStatus.DECLINED)
                confirmed_groups.append(group)
        return ApprovalResult(ApprovalStatus.APPROVED, risk_groups_confirmed=tuple(confirmed_groups))

    risk_allowlist = tuple(a.allow_risky_command) + load_risk_allowlist(a.risk_allowlist)
    result = apply_config(device, candidate, cred, store, approve=approve,
                          allow_risky_commands=risk_allowlist)
    print(result)
    return 2 if result.startswith("Approval declined") else 0


def cmd_rollback(a) -> int:
    device = _selected_device(a.inventory, a.device)
    store = ConfigStore(Path(a.data) / "configs")
    manifest = store.load_deployment(device.hostname)
    target = manifest.get("remote_backup", "")
    if not a.apply:
        print(f"ROLLBACK DRY RUN for {device.hostname}")
        print(f"Recorded state: {manifest.get('status', 'unknown')}; snapshot to restore: {target or 'not recorded'}")
        print("Device was not modified. Use --apply for an interactive, backed-up rollback.")
        return 0
    _require_interactive_approval()
    cred = get_credential(prompt=not a.no_prompt)

    def approve(hostname, backup, local_backup, recovery_backup):
        print(f"\nLIVE ROLLBACK PREVIEW for {hostname}")
        print(f"Will restore the recorded pre-apply snapshot: {backup}")
        print(f"Verified recovery backups: local {local_backup}, device {recovery_backup}")
        return input(f"Type {hostname} to approve this rollback: ").strip() == hostname

    def approve_changed(hostname, current_hash, recorded_hash):
        print("\nCURRENT CONFIG DIFFERS FROM THE RECORDED POST-APPLY HASH")
        print(f"Current SHA-256: {current_hash}")
        print(f"Recorded SHA-256: {recorded_hash or 'missing'}")
        expected = f"CONFIG CHANGED {hostname}"
        return input(f"Type {expected} to continue rollback despite the mismatch: ").strip() == expected

    result = rollback_config(device, cred, store, approve=approve, approve_changed=approve_changed)
    print(result)
    return 2 if result.startswith("Approval declined") else 0


def cmd_topology(a) -> int:
    devices = {d.hostname: d.role for d in load_inventory(a.inventory)} if a.inventory else {}
    links = []
    for f in sorted(Path(a.neighbors).glob("*.txt")):
        links += parse_neighbors(f.stem, f.read_text(encoding="utf-8"))
    graph = build_graph(links, devices)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "topology.json").write_text(to_json(graph), encoding="utf-8")
    (out / "topology.mmd").write_text(to_mermaid(graph), encoding="utf-8")
    print(f"{len(graph['nodes'])} nodes, {len(graph['links'])} links -> {out}")
    return 0


def cmd_audit(a) -> int:
    rules = load_rules(a.rules)
    devices = load_inventory(a.inventory)
    configs = Path(a.configs)
    results = {}
    unknown_results = {}
    evaluated_counts = {}
    missing = []
    for d in devices:
        p = configs / d.hostname / "latest.cfg"
        if not p.exists():
            p = configs / f"{d.hostname}.cfg"
        if not p.exists():
            missing.append(d.hostname)
            print(f"missing config for {d.hostname}", file=sys.stderr)
            continue
        artifacts = {
            file.name[len("latest."):-len(".txt")]: file.read_text(encoding="utf-8")
            for file in p.parent.glob("latest.routeros_*.txt")
        }
        findings, unknowns, evaluated = evaluate_detailed(
            d.hostname, d.platform, p.read_text(encoding="utf-8"), rules, artifacts=artifacts
        )
        results[d.hostname] = findings
        unknown_results[d.hostname] = unknowns
        evaluated_counts[d.hostname] = evaluated
    md = report_markdown(results, len(rules), unknown_results, evaluated_counts)
    if missing:
        md += "\n## Missing configurations\n\n"
        md += "".join(f"- **{hostname}**: no configuration available; audit incomplete.\n"
                      for hostname in sorted(missing))
    Path(a.out).write_text(md, encoding="utf-8") if a.out else print(md)
    worst = [f for fs in results.values() for f in fs if f.severity in ("critical", "high")]
    has_unknown = any(unknown_results.values())
    if missing:
        return 1
    if has_unknown and not a.allow_unknown:
        return 3
    if a.fail_on_high and worst:
        return 2
    return 0


def cmd_assess(a) -> int:
    rules = load_approved_rules(a.rules)
    config, evidence = load_evidence_bundle(a.evidence_dir)
    show_version = evidence.get("show_version")
    device = DeviceContext(
        hostname=a.hostname,
        platform="cisco_ios",
        family=a.family,
        show_version=show_version,
        roles_dir=a.roles_dir,
    )
    roles = None
    if a.roles_dir:
        role_path = Path(a.roles_dir) / f"{a.hostname}.json"
        if role_path.is_file():
            raw_roles = json.loads(role_path.read_text(encoding="utf-8"))
            roles = raw_roles.get("interfaces", raw_roles) if isinstance(raw_roles, dict) else None
            if not isinstance(roles, dict):
                raise ValueError(f"invalid operator role file: {role_path}")
    waivers = load_waivers(a.waivers)
    rows = [
        evaluate_rule_levels(rule, device, config, evidence, roles=roles, waivers=waivers, level=a.level)
        for rule in rules
    ]
    catalog = json.loads(Path(a.catalog).read_text(encoding="utf-8"))
    report = build_json_report(device, rows, catalog_version=catalog.get("catalog_version", "unknown"),
                               run_metadata={"level": a.level, "evidence_dir": str(a.evidence_dir), "approved_rule_count": len(rules)})
    if not rules:
        print("nothing executed: no approved rules are available; verdict NO_RULES")
    if a.format == "json":
        output = render_json_report(report)
    elif a.format == "md":
        output = render_markdown_report(report)
    elif a.format == "html":
        output = render_html_report(report)
    elif a.format == "cklb":
        output = render_cklb(catalog, rows, a.cklb_template, a.stig_part, a.hostname, a.level)
    elif a.format == "xccdf":
        output = render_xccdf_testresult(catalog, rows, a.stig_part, a.hostname, a.level)
    else:
        raise ValueError(f"unsupported report format: {a.format}")
    if a.out:
        out_path = Path(a.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output, encoding="utf-8")
    else:
        print(output, end="" if output.endswith("\n") else "\n")
    return exit_code(rows, fail_on=a.fail_on, allow_unknown=a.allow_unknown,
                     strict_manual=a.strict_manual, fail_on_pro=a.fail_on_pro)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="netagent", description="Network discovery, backup, topology, compliance (MVP)")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("discover", help="scan a CIDR for management ports")
    s.add_argument("cidr"); s.add_argument("--out")
    s.set_defaults(func=cmd_discover)

    s = sub.add_parser("trust-host-key", help="interactively verify and pin one SSH host key")
    s.add_argument("--inventory", required=True)
    s.add_argument("--device", required=True, help="exact inventory hostname; one device per invocation")
    s.add_argument("--known-hosts", help="known_hosts file (default: NETAGENT_KNOWN_HOSTS or data/known_hosts)")
    s.add_argument("--no-prompt", action="store_true", help="forbidden for trust-on-first-use; fails closed")
    s.set_defaults(func=cmd_trust_host_key)

    s = sub.add_parser("collect-evidence", help="collect allowlisted read-only Cisco IOS STIG evidence over verified SSH")
    s.add_argument("--inventory", required=True)
    s.add_argument("--device", required=True, help="exact inventory hostname; one device per invocation")
    s.add_argument("--out-dir", required=True, help="directory for separate evidence output files")
    s.add_argument("--timeout", type=int, default=60)
    s.add_argument("--known-hosts", help="known_hosts file (default: NETAGENT_KNOWN_HOSTS or data/known_hosts)")
    s.add_argument("--no-prompt", action="store_true", help="use environment credentials only")
    s.set_defaults(func=cmd_collect_evidence)

    s = sub.add_parser("test-ssh", help="test SSH login to one inventory device; no config commands")
    s.add_argument("--inventory", required=True)
    s.add_argument("--device", required=True, help="exact inventory hostname; one device per invocation")
    s.add_argument("--no-prompt", action="store_true", help="use environment credentials only")
    s.set_defaults(func=cmd_test_ssh)

    s = sub.add_parser("backup", help="fetch configs over SSH (read-only)")
    s.add_argument("--inventory", required=True); s.add_argument("--data", default="data")
    s.add_argument("--device", help="optional exact hostname; when set, back up only that device")
    s.add_argument("--no-prompt", action="store_true", help="use env vars only")
    s.set_defaults(func=cmd_backup)

    s = sub.add_parser(
        "apply", help="preview a config candidate; live writes require --apply and interactive approval"
    )
    s.add_argument("--inventory", required=True)
    s.add_argument("--device", required=True, help="exact inventory hostname; one device per invocation")
    s.add_argument("--config", required=True, help="candidate config snippet")
    s.add_argument("--data", default="data")
    s.add_argument("--no-prompt", action="store_true", help="use environment credentials only")
    s.add_argument(
        "--apply", action="store_true",
        help="enable live apply after preview, backup and typed confirmation",
    )
    s.add_argument("--allow-risky-command", action="append", default=[], metavar="EXACT_LINE",
                   help="allow an exact management-risk command line; still requires separate typed risk confirmation")
    s.add_argument("--risk-allowlist", help="JSON file containing an allowed_commands list of exact command lines")
    s.set_defaults(func=cmd_apply)

    s = sub.add_parser("rollback", help="preview or restore the latest applied config snapshot")
    s.add_argument("--inventory", required=True)
    s.add_argument("--device", required=True, help="exact inventory hostname; one device per invocation")
    s.add_argument("--data", default="data")
    s.add_argument("--no-prompt", action="store_true", help="use environment credentials only")
    s.add_argument("--apply", action="store_true", help="enable rollback after backup and interactive approval")
    s.set_defaults(func=cmd_rollback)

    s = sub.add_parser("topology", help="build topology from neighbor outputs")
    s.add_argument("--neighbors", default="data/neighbors"); s.add_argument("--inventory")
    s.add_argument("--out", default="data/topology")
    s.set_defaults(func=cmd_topology)

    s = sub.add_parser("assess", help="assess Cisco IOS STIG evidence and export a report")
    s.add_argument("--hostname", required=True, help="synthetic or operator-supplied device hostname")
    s.add_argument("--evidence-dir", required=True, help="directory containing read-only evidence files")
    s.add_argument("--rules", default="rules/cisco_ios", help="directory of rules; only status=approved rules execute")
    s.add_argument("--catalog", default="standards/disa-cisco-ios-switch/Y26M04/catalog.json")
    s.add_argument("--cklb-template", default="examples/sample-synthetic.cklb", help="sanitized CKLB template; STIG Viewer import still needs validation")
    s.add_argument("--stig-part", choices=("L2S", "NDM", "RTR"), default="L2S")
    s.add_argument("--family", help="explicitly verified device family; otherwise derived only from show version")
    s.add_argument("--level", choices=("standard", "pro"), default="pro")
    s.add_argument("--fail-on", choices=("none", "critical", "high", "medium", "low"), default="high")
    s.add_argument("--fail-on-pro", choices=("none", "critical", "high", "medium", "low"), default="none")
    s.add_argument("--allow-unknown", action="store_true")
    s.add_argument("--strict-manual", action="store_true")
    s.add_argument("--roles-dir")
    s.add_argument("--waivers")
    s.add_argument("--format", choices=("cklb", "xccdf", "md", "html", "json"), default="md")
    s.add_argument("--out")
    s.set_defaults(func=cmd_assess)

    s = sub.add_parser("audit", help="check configs against rules")
    s.add_argument("--rules", required=True); s.add_argument("--inventory", required=True)
    s.add_argument("--configs", default="data/configs"); s.add_argument("--out")
    s.add_argument("--fail-on-high", action="store_true", help="return exit code 2 for critical/high findings")
    s.add_argument("--allow-unknown", action="store_true", help="exit 0/2 even if one or more checks are UNKNOWN")
    s.set_defaults(func=cmd_audit)
    return p


def main(argv=None) -> int:
    a = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.WARNING, format="%(levelname)s %(message)s")
    try:
        return a.func(a)
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
