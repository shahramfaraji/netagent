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
from .deploy import apply_config, preview_config, rollback_config
from .models import load_inventory
from .topology import build_graph, parse_neighbors, to_json, to_mermaid


def cmd_discover(a) -> int:
    hosts = discover(a.cidr)
    rows = [{"ip": h.ip, "open_ports": h.open_ports, "hostname": h.hostname,
             "os_guess": h.os_guess, "role_guess": h.guessed_role,
             "services": h.services} for h in hosts]
    text = json.dumps(rows, indent=2)
    Path(a.out).write_text(text, encoding="utf-8") if a.out else print(text)
    print(f"{len(rows)} host(s) with management ports open", file=sys.stderr)
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
        return 0

    def approve(preview):
        print(f"\nLIVE CHANGE PREVIEW for {preview.hostname} ({preview.platform})")
        print(f"Current config sha256={preview.current_config_sha256}")
        print(f"Candidate: {preview.candidate_lines} command(s), sha256={preview.candidate_sha256}")
        print("Candidate commands (preview only, not a simulated post-change config):")
        print(preview.diff)
        print(f"Verified backups: local {preview.local_backup}, device {preview.device_backup}")
        return input(f"Type {preview.hostname} to approve this config change: ").strip() == preview.hostname

    result = apply_config(device, candidate, cred, store, approve=approve)
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

    result = rollback_config(device, cred, store, approve=approve)
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
        findings, unknowns, evaluated = evaluate_detailed(
            d.hostname, d.platform, p.read_text(encoding="utf-8"), rules
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
    if a.fail_on_high and (worst or has_unknown):
        return 2
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="netagent", description="Network discovery, backup, topology, compliance (MVP)")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("discover", help="scan a CIDR for management ports")
    s.add_argument("cidr"); s.add_argument("--out")
    s.set_defaults(func=cmd_discover)

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

    s = sub.add_parser("audit", help="check configs against rules")
    s.add_argument("--rules", required=True); s.add_argument("--inventory", required=True)
    s.add_argument("--configs", default="data/configs"); s.add_argument("--out")
    s.add_argument("--fail-on-high", action="store_true")
    s.set_defaults(func=cmd_audit)
    return p


def main(argv=None) -> int:
    a = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.WARNING, format="%(levelname)s %(message)s")
    try:
        return a.func(a)
    except (ValueError, RuntimeError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
