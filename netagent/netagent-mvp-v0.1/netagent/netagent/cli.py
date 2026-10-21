"""netagent CLI: discover | backup | topology | audit"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from . import __version__
from .collector import ConfigStore, fetch
from .compliance import evaluate, load_rules, report_markdown
from .credentials import get_credential
from .discovery import discover
from .models import load_inventory
from .topology import build_graph, parse_neighbors, to_json, to_mermaid


def cmd_discover(a) -> int:
    hosts = discover(a.cidr)
    rows = [{"ip": h.ip, "open_ports": h.open_ports, "hostname": h.hostname,
             "os_guess": h.os_guess, "role_guess": h.guessed_role} for h in hosts]
    text = json.dumps(rows, indent=2)
    Path(a.out).write_text(text, encoding="utf-8") if a.out else print(text)
    print(f"{len(rows)} host(s) with management ports open", file=sys.stderr)
    return 0


def cmd_backup(a) -> int:
    devices = load_inventory(a.inventory)
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
    for d in devices:
        p = configs / d.hostname / "latest.cfg"
        if not p.exists():
            p = configs / f"{d.hostname}.cfg"
        if not p.exists():
            print(f"skip {d.hostname}: no config", file=sys.stderr)
            continue
        results[d.hostname] = evaluate(d.hostname, d.platform, p.read_text(encoding="utf-8"), rules)
    md = report_markdown(results, len(rules))
    Path(a.out).write_text(md, encoding="utf-8") if a.out else print(md)
    worst = [f for fs in results.values() for f in fs if f.severity in ("critical", "high")]
    return 2 if worst and a.fail_on_high else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="netagent", description="Network discovery, backup, topology, compliance (MVP)")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("discover", help="scan a CIDR for management ports")
    s.add_argument("cidr"); s.add_argument("--out")
    s.set_defaults(func=cmd_discover)

    s = sub.add_parser("backup", help="fetch configs over SSH (read-only)")
    s.add_argument("--inventory", required=True); s.add_argument("--data", default="data")
    s.add_argument("--no-prompt", action="store_true", help="use env vars only")
    s.set_defaults(func=cmd_backup)

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
