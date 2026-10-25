#!/usr/bin/env python3
"""Convert DISA Cisco IOS Switch STIG XCCDF files to a deterministic JSON catalog."""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import sys
import zipfile
from pathlib import Path
from typing import Iterable
import xml.etree.ElementTree as ET

TOOL_VERSION = "1.0.0"
EXPECTED_NAMESPACE = "http://checklists.nist.gov/xccdf/1.1"
SEVERITIES = {"high", "medium", "low"}
COMMAND_RE = re.compile(
    r"(?im)^\s*(?:SW\d+\([^)]*\)#\s*)?"
    r"((?:no\s+|default\s+)?(?:aaa|archive|banner|boot|class-map|control-plane|"
    r"crypto|enable|exec-timeout|interface|ip|ipv6|line|logging|login|ntp|"
    r"service|snmp-server|spanning-tree|switchport|username|vlan|vtp)\b[^\r\n]*)"
)
MENTION_PATTERNS = {
    "interfaces": r"\binterfaces?\b", "vty": r"\b(?:line\s+vty|vty)\b",
    "aaa": r"\baaa\b", "snmp": r"\bsnmp-server\b|\bSNMP\b",
    "logging": r"\blogging\b|\bsyslog\b", "ntp": r"\bntp\b",
    "access_lists": r"\baccess[- ]list\b|\baccess-class\b",
    "authentication": r"\bauthenticat(?:e|ion|ing)\b",
}


class CatalogError(ValueError):
    """Invalid or unsafe source data."""


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def child(element: ET.Element, name: str) -> ET.Element | None:
    return next((item for item in element if local_name(item.tag) == name), None)


def children(element: ET.Element, name: str) -> list[ET.Element]:
    return [item for item in element if local_name(item.tag) == name]


def text_of(element: ET.Element | None) -> str:
    if element is None:
        return ""
    return "".join(element.itertext())


def clean_markup(value: str) -> str:
    """Flatten text and embedded escaped XML fragments without retaining tag markup."""
    result = html.unescape(value)
    result = re.sub(r"(?is)<[^>]*>", " ", result)
    result = html.unescape(result).replace("\u00a0", " ")
    result = re.sub(r"[ \t\r\f\v]+", " ", result)
    result = re.sub(r" *\n *", "\n", result)
    result = re.sub(r"\n{3,}", "\n\n", result)
    return result.strip()


def safe_parse(data: bytes, source_name: str) -> ET.Element:
    if re.search(rb"<!\s*(?:DOCTYPE|ENTITY)\b", data, re.IGNORECASE):
        raise CatalogError(f"{source_name}: DOCTYPE/ENTITY declarations are forbidden")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise CatalogError(f"{source_name}: invalid XML: {exc}") from exc
    if local_name(root.tag) != "Benchmark":
        raise CatalogError(f"{source_name}: root element is not Benchmark")
    namespace = root.tag[1:].split("}", 1)[0] if root.tag.startswith("{") else ""
    if namespace != EXPECTED_NAMESPACE:
        raise CatalogError(f"{source_name}: unexpected XCCDF namespace {namespace!r}")
    return root


def release_fields(root: ET.Element) -> tuple[str, str, str]:
    version = text_of(child(root, "version"))
    status = child(root, "status")
    status_date = status.attrib.get("date", "") if status is not None else ""
    release_info = next(
        (text_of(item) for item in children(root, "plain-text")
         if item.attrib.get("id") == "release-info"), ""
    )
    release_match = re.search(r"\bRelease:\s*([^\s]+)", release_info, re.I)
    date_match = re.search(r"\bBenchmark Date:\s*(\d{1,2}\s+[A-Za-z]{3}\s+\d{4})", release_info, re.I)
    release = release_match.group(1) if release_match else ""
    benchmark_date = date_match.group(1) if date_match else status_date
    if not version or not release or not benchmark_date:
        raise CatalogError(f"Benchmark {root.attrib.get('id', '<missing-id>')!r}: incomplete version/release/date")
    return version, release, benchmark_date


def part_from_id(benchmark_id: str) -> str:
    match = re.search(r"Cisco_IOS_Switch_(L2S|RTR|NDM)_STIG$", benchmark_id)
    if not match:
        raise CatalogError(f"unsupported benchmark id: {benchmark_id!r}")
    return match.group(1)


def infer_catalog_version(zip_stem: str) -> str:
    """Infer the DISA release label from a ZIP basename, including underscore boundaries."""
    match = re.search(r"(?<![A-Za-z0-9])(Y\d{2}M\d{2})(?![A-Za-z0-9])", zip_stem, re.I)
    return match.group(1).upper() if match else "combined"


def heuristic_hints(check_text: str, fix_text: str, description: str) -> dict:
    combined = "\n".join((check_text, fix_text, description))
    commands = sorted({
        clean_markup(match.group(1)).strip()
        for match in COMMAND_RE.finditer(combined)
        if clean_markup(match.group(1)).strip()
    })
    mentions = sorted(key for key, pattern in MENTION_PATTERNS.items()
                      if re.search(pattern, combined, re.I))
    return {"heuristic": True, "commands": commands, "mentions": mentions}


def parse_xccdf(data: bytes, source_name: str, source_sha256: str) -> tuple[dict, list[dict]]:
    root = safe_parse(data, source_name)
    benchmark_id = root.attrib.get("id", "").strip()
    if not benchmark_id:
        raise CatalogError(f"{source_name}: missing Benchmark id")
    part = part_from_id(benchmark_id)
    version, release, benchmark_date = release_fields(root)
    groups = children(root, "Group")
    controls = []
    for group in groups:
        control_id = group.attrib.get("id", "").strip()
        rules = children(group, "Rule")
        if not re.fullmatch(r"V-\d+", control_id) or len(rules) != 1:
            raise CatalogError(f"{source_name}: Group {control_id!r} must have a V-ID and exactly one Rule")
        rule = rules[0]
        rule_id = rule.attrib.get("id", "").strip()
        title = clean_markup(text_of(child(rule, "title")))
        severity = rule.attrib.get("severity", "").strip().lower()
        stig_id = clean_markup(text_of(child(rule, "version")))
        if not rule_id or not title or severity not in SEVERITIES or not stig_id:
            raise CatalogError(f"{source_name}: {control_id} missing rule id/title/STIG ID or invalid severity")
        check = child(rule, "check")
        check_text = clean_markup(text_of(child(check, "check-content"))) if check is not None else ""
        fix_text = clean_markup(text_of(child(rule, "fixtext")))
        description = clean_markup(text_of(child(rule, "description")))
        cci = sorted({
            text_of(item).strip() for item in children(rule, "ident")
            if item.attrib.get("system", "").rstrip("/").endswith("/cci") and text_of(item).strip()
        })
        category = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}[severity]
        controls.append({
            "control_id": control_id, "rule_id": rule_id, "stig_id": stig_id,
            "stig": part, "title": title, "severity": severity, "category": category,
            "description": description, "check_text": check_text, "fix_text": fix_text,
            "cci": cci,
            "source_ref": {"file": Path(source_name).name, "sha256": source_sha256,
                           "benchmark_id": benchmark_id, "version": version,
                           "release": release, "date": benchmark_date},
            "hints": heuristic_hints(check_text, fix_text, description),
        })
    if not controls:
        raise CatalogError(f"{source_name}: no Group/Rule controls found")
    controls.sort(key=lambda item: (item["stig"], item["control_id"], item["rule_id"]))
    metadata = {
        "file": Path(source_name).name, "sha256": source_sha256,
        "benchmark_id": benchmark_id, "title": clean_markup(text_of(child(root, "title"))),
        "version": version, "release": release, "date": benchmark_date, "stig": part,
        "groups": len(groups), "rules": len(controls),
        "severity_counts": {level: sum(c["severity"] == level for c in controls)
                            for level in ("high", "medium", "low")},
    }
    return metadata, controls


def read_xml_files(paths: Iterable[Path]) -> list[tuple[str, bytes]]:
    result = []
    for path in paths:
        if not path.is_file():
            raise CatalogError(f"XCCDF file does not exist: {path}")
        result.append((str(path), path.read_bytes()))
    return result


def read_zip_xml(zip_path: Path) -> list[tuple[str, bytes]]:
    if not zip_path.is_file():
        raise CatalogError(f"ZIP file does not exist: {zip_path}")
    try:
        with zipfile.ZipFile(zip_path) as archive:
            candidates = sorted(
                [info for info in archive.infolist()
                 if not info.is_dir() and info.filename.lower().endswith(".xml")
                 and "xccdf" in Path(info.filename).name.lower()],
                key=lambda info: info.filename.lower(),
            )
            result = [(info.filename, archive.read(info)) for info in candidates]
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise CatalogError(f"cannot read ZIP {zip_path}: {exc}") from exc
    if not result:
        raise CatalogError(f"{zip_path}: no XCCDF XML files found")
    return result


def build_catalog(sources: list[tuple[str, bytes]], version_label: str) -> dict:
    metadata_list, controls = [], []
    seen_controls, seen_rules, seen_stig_ids = set(), set(), set()
    for name, data in sources:
        metadata, parsed = parse_xccdf(data, name, hashlib.sha256(data).hexdigest())
        metadata_list.append(metadata)
        for control in parsed:
            for field, seen in (("control_id", seen_controls), ("rule_id", seen_rules), ("stig_id", seen_stig_ids)):
                value = control[field]
                key = f"{control['stig']}:{value}" if field == "stig_id" else value
                if key in seen:
                    raise CatalogError(f"duplicate {field}: {key}")
                seen.add(key)
            controls.append(control)
    controls.sort(key=lambda item: (item["stig"], item["control_id"], item["rule_id"]))
    metadata_list.sort(key=lambda item: (item["stig"], item["file"]))
    return {
        "schema_version": 1, "catalog_version": version_label,
        "generated_by": {"tool": "tools/xccdf_to_catalog.py", "version": TOOL_VERSION},
        "sources": metadata_list, "control_count": len(controls),
        "severity_counts": {level: sum(c["severity"] == level for c in controls)
                            for level in ("high", "medium", "low")},
        "controls": controls,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--zip", dest="zip_path", type=Path, help="DISA STIG ZIP")
    source.add_argument("--xccdf", nargs="+", type=Path, help="one or more XCCDF XML files")
    parser.add_argument("--sha256", help="expected ZIP SHA-256; only valid with --zip")
    parser.add_argument("--version", help="catalog version label; inferred from ZIP name when possible")
    parser.add_argument("--out", type=Path, help="output path (default standards/disa-cisco-ios-switch/<version>/catalog.json)")
    args = parser.parse_args(argv)
    try:
        if args.sha256 and not args.zip_path:
            raise CatalogError("--sha256 can only be used with --zip")
        if args.zip_path:
            if args.sha256:
                expected = args.sha256.strip().lower()
                if not re.fullmatch(r"[0-9a-f]{64}", expected):
                    raise CatalogError("--sha256 must contain 64 hexadecimal characters")
                actual = hashlib.sha256(args.zip_path.read_bytes()).hexdigest()
                if actual != expected:
                    raise CatalogError(f"ZIP SHA-256 mismatch: expected {expected}, got {actual}")
            sources = read_zip_xml(args.zip_path)
            version_label = args.version or infer_catalog_version(args.zip_path.stem)
        else:
            sources = read_xml_files(args.xccdf or [])
            version_label = args.version or "combined"
        catalog = build_catalog(sources, version_label)
        output = args.out or Path("standards") / "disa-cisco-ios-switch" / version_label / "catalog.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(catalog, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8", newline="\n")
        print(f"Wrote {catalog['control_count']} controls from {len(catalog['sources'])} XCCDF file(s) to {output}")
        print("Severity counts: " + json.dumps(catalog["severity_counts"], sort_keys=True))
        return 0
    except (CatalogError, OSError, zipfile.BadZipFile) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
