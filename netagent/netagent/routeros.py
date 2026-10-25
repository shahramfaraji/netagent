"""Conservative RouterOS export/print parser used by compliance audits.

TODO(verify-on-device): validate command output variants against supported RouterOS
v6/v7 releases before relying on inferred defaults. Missing values stay unknown.
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

_TOKEN = re.compile(r'([^\s="\\]+|"(?:\\.|[^"\\])*"|[^\s=]+)')
_PAIR = re.compile(r'(?<!\S)([A-Za-z0-9_.-]+)\s*(?:=|:)\s*("(?:\\.|[^"\\])*"|[^\s]+)')


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]
        value = re.sub(r'\\([\\"$])', r'\1', value)
    return value


def _logical_lines(text: str) -> list[str]:
    lines: list[str] = []
    current = ""
    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        stripped = line.rstrip()
        continued = stripped.endswith("\\")
        current += stripped[:-1].rstrip() + " " if continued else stripped.lstrip()
        if not continued:
            lines.append(current.strip())
            current = ""
    if current.strip():
        lines.append(current.strip())
    return lines


def parse_pairs(line: str) -> dict[str, str]:
    """Parse key=value pairs without splitting spaces inside quoted values."""
    return {key: _unquote(value) for key, value in _PAIR.findall(line)}


def parse_export(text: str) -> dict[str, Any]:
    """Parse RouterOS export sections and each set/add/remove command."""
    sections: dict[str, list[dict[str, Any]]] = defaultdict(list)
    section = ""
    header_version = re.search(r"RouterOS\s+(\d+(?:\.\d+)+)", text, re.I)
    version = header_version.group(1) if header_version else None
    for line in _logical_lines(text):
        match = re.search(r'RouterOS\s+(\d+(?:\.\d+)+)', line, re.I)
        if match:
            version = match.group(1)
        if line.startswith("/") and not line.startswith("/ "):
            section = line.strip()
            sections.setdefault(section, [])
            continue
        if not section or not re.match(r"^(?:set|add|remove|enable|disable|ip|tool|system|interface|user|print|export)\b", line):
            continue
        command = line.split(None, 1)[0]
        rest = line[len(command):].strip()
        # `set telnet ...` has a positional item before key/value pairs.
        positional = rest.split(None, 1)[0] if rest and "=" not in rest.split(None, 1)[0] else ""
        item: dict[str, Any] = {"_command": command}
        if positional:
            item["_item"] = positional
        item.update(parse_pairs(rest))
        sections[section].append(item)
    return {"version": version, "sections": dict(sections)}


def parse_print_detail(text: str, section: str) -> dict[str, Any]:
    """Parse `print detail`/`print` output into indexed records."""
    records: list[dict[str, str]] = []
    for line in _logical_lines(text):
        if line.startswith("Flags:") or line.startswith("Columns:") or line.startswith("#"):
            continue
        line = re.sub(r"^\s*\d+\s+", "", line)
        pairs = parse_pairs(line)
        if pairs:
            pairs.setdefault("_command", "add")
            records.append(pairs)
    return {"section": section, "records": records, "parse_ok": bool(records)}


def merge_routeros_data(config: str, artifacts: dict[str, str] | None = None) -> dict[str, Any]:
    """Combine export and command-specific output; an empty print is not a pass."""
    data = parse_export(config)
    data["prints"] = {}
    section_names = {
        "resource": "resource", "ip_service": "ip_service", "snmp": "snmp",
        "ntp_client": "ntp_client", "ntp_servers": "ntp_servers", "user": "user",
        "ip_ssh": "ip_ssh", "mac_server": "mac_server", "mac_winbox": "mac_winbox",
        "neighbor_discovery": "neighbor_discovery", "ip_dns": "ip_dns",
        "bandwidth_server": "bandwidth_server", "ip_firewall_filter": "ip_firewall_filter",
        "logging_action": "logging_action", "logging": "logging",
    }
    for key, content in (artifacts or {}).items():
        if key.startswith("routeros_"):
            section = key.removeprefix("routeros_")
            data["prints"][section_names.get(section, section)] = parse_print_detail(content, section)
    # Resource output includes version in RouterOS print output even when the
    # export header is compact or absent.
    resource = (artifacts or {}).get("routeros_resource", "")
    version_match = re.search(r"version\s*[:=]\s*([0-9]+(?:\.[0-9A-Za-z]+)+)", resource, re.I)
    if version_match:
        data["version"] = version_match.group(1)
    return data


def section_records(data: dict[str, Any], section: str) -> list[dict[str, str]] | None:
    """Return parsed records; None means absent/unparseable, [] means parsed empty."""
    print_data = data.get("prints", {}).get(section)
    if print_data is not None:
        if print_data.get("parse_ok"):
            return print_data["records"]
        return None
    # Export data is only a record of explicitly exported values, not necessarily defaults.
    export_paths = {
        "ip_service": "/ip service", "snmp": "/snmp",
        "ntp_client": "/system ntp client", "ntp_servers": "/system ntp client servers",
        "user": "/user", "ip_ssh": "/ip ssh", "mac_server": "/tool mac-server",
        "mac_winbox": "/tool mac-server mac-winbox",
        "neighbor_discovery": "/ip neighbor discovery-settings", "ip_dns": "/ip dns",
        "bandwidth_server": "/tool bandwidth-server", "ip_firewall_filter": "/ip firewall filter",
        "logging_action": "/system logging action", "logging": "/system logging",
    }
    sections = data.get("sections", {})
    export_key = section if section in sections else export_paths.get(section, section)
    if export_key in sections:
        return sections[export_key]
    return None


def check_rule(check: str, data: dict[str, Any], config: str, options: dict[str, Any] | None = None) -> tuple[str, str]:
    """Return ('pass'|'finding'|'unknown', detail) for a named RouterOS check."""
    options = options or {}
    sections = data.get("sections", {})
    prints = data.get("prints", {})

    def unknown(reason: str) -> tuple[str, str]:
        return "unknown", reason

    def result_bad(bad: bool, why: str) -> tuple[str, str]:
        return ("finding", why) if bad else ("pass", why)

    service_names = {
        "service_ftp_enabled": "ftp", "service_telnet_enabled": "telnet",
        "service_www_enabled": "www", "service_api_enabled": "api",
        "service_api_ssl_enabled": "api-ssl", "service_winbox_enabled": "winbox",
        "service_ssh_address": "ssh", "service_winbox_address": "winbox",
    }
    if check in service_names:
        service = service_names[check]
        records = section_records(data, "ip_service")
        if records is None:
            # TODO(verify-on-device): confirm service defaults for each supported RouterOS release.
            return unknown(f"/ip service print detail unavailable; compact export may omit default service {service}")
        row = next((r for r in records if r.get("name", r.get("_item", "")).lower() == service), None)
        if row is None:
            return unknown(f"service {service} absent from parsed records; default not assumed")
        if check.endswith("_enabled"):
            if "disabled" not in row:
                return unknown(f"service {service} has no parsed disabled flag")
            return result_bad(row["disabled"].lower() == "no", f"service {service} disabled={row['disabled']}")
        if "address" not in row:
            return "finding", f"service {service} has no address restriction"
        address = row["address"].strip()
        return result_bad(address in ("", "0.0.0.0/0", "::/0"), f"service {service} address={address}")

    if check == "pptp_enabled":
        records = sections.get("/interface pptp-server server")
        if records is None:
            return unknown("PPTP server section absent; default not assumed")
        row = next((r for r in records if r.get("_command") == "set"), None)
        if row is None or "enabled" not in row:
            return unknown("PPTP enabled flag not present in export")
        return result_bad(row["enabled"].lower() == "yes", f"PPTP enabled={row['enabled']}")

    if check == "ntp_configured":
        rows = section_records(data, "ntp_servers")
        if rows is None and "ntp_servers" in prints:
            return unknown("NTP server print output is unparseable; export is not used as a fallback")
        if rows is None:
            rows = sections.get("/system ntp client servers")
        if rows is None:
            legacy_rows = sections.get("/system ntp client")
            if legacy_rows is not None and any(r.get("_command") == "add" and r.get("address") for r in legacy_rows):
                return "pass", "legacy RouterOS NTP server record configured"
            return unknown("NTP server list output/section unavailable")
        configured = any(r.get("_command") == "add" and (r.get("address") or r.get("_item")) for r in rows)
        return result_bad(not configured, "no explicit NTP server record found" if not configured else "NTP server configured")

    if check == "remote_syslog_action":
        actions = section_records(data, "logging_action")
        if actions is None:
            return unknown("logging action section unavailable")
        remote_actions = {r.get("name") for r in actions if r.get("target") == "remote" and r.get("remote")}
        if not remote_actions:
            return "finding", "no remote logging action with both target=remote and remote address"
        rules = section_records(data, "logging")
        if rules is None:
            return unknown("/system logging rules unavailable; cannot verify remote action is used")
        used = any(r.get("action") in remote_actions for r in rules if r.get("_command") == "add")
        return result_bad(not used, "remote action is not referenced by a logging rule" if not used else "remote action is referenced by a logging rule")

    if check == "snmp_disabled":
        records = section_records(data, "snmp")
        if records is None:
            return unknown("SNMP print output/section unavailable")
        row = next((r for r in records if "enabled" in r), None)
        if row is None:
            return unknown("SNMP enabled flag unavailable; default not assumed")
        return result_bad(row["enabled"].lower() == "yes", f"SNMP enabled={row['enabled']}")

    if check == "default_admin_user":
        rows = section_records(data, "user")
        if rows is None:
            return unknown("/user export section unavailable; user list must be collected without secrets")
        present = any(r.get("name", r.get("_item", "")) == "admin" and r.get("_command") in ("add", "set") for r in rows)
        return result_bad(present, "default admin account is present" if present else "default admin account not found in export")

    if check == "admin_password_policy":
        return unknown("password strength/policy is not exposed by the non-secret user listing; password data is deliberately not collected")

    if check == "ssh_strong_crypto":
        rows = section_records(data, "ip_ssh")
        if rows is None:
            return unknown("/ip ssh section unavailable")
        row = next((r for r in rows if "strong-crypto" in r), None)
        if row is None:
            return unknown("strong-crypto setting not explicitly exported")
        return result_bad(row["strong-crypto"].lower() != "yes", f"strong-crypto={row['strong-crypto']}")

    if check in ("mac_server_scope", "mac_winbox_scope", "neighbor_discovery_scope"):
        paths = {"mac_server_scope": "/tool mac-server", "mac_winbox_scope": "/tool mac-server mac-winbox", "neighbor_discovery_scope": "/ip neighbor discovery-settings"}
        print_section = {"mac_server_scope": "mac_server", "mac_winbox_scope": "mac_winbox", "neighbor_discovery_scope": "neighbor_discovery"}[check]
        rows = section_records(data, print_section)
        if rows is None:
            return unknown(f"{paths[check]} section unavailable")
        row = next((r for r in rows if "allowed-interface-list" in r or "discover-interface-list" in r), None)
        if row is None:
            return unknown(f"{paths[check]} scope not explicitly exported")
        field = "allowed-interface-list" if check != "neighbor_discovery_scope" else "discover-interface-list"
        if field not in row:
            return unknown(f"{field} not explicitly exported; scope not assumed")
        return result_bad(row[field].lower() in ("all", ""), f"{field}={row[field]}")

    if check == "input_final_drop":
        rows = section_records(data, "ip_firewall_filter")
        if rows is None:
            return unknown("/ip firewall filter section unavailable")
        input_rows = [r for r in rows if r.get("_command") == "add" and r.get("chain") == "input"]
        if not input_rows:
            return unknown("no parsed input-chain filter rules")
        last = input_rows[-1]
        good = last.get("action") == "drop" and last.get("disabled", "no") != "yes"
        return result_bad(not good, f"last exported input-chain rule action={last.get('action', 'unknown')}")

    if check == "dns_remote_requests":
        rows = section_records(data, "ip_dns")
        if rows is None:
            return unknown("/ip dns section unavailable")
        row = next((r for r in rows if "allow-remote-requests" in r), None)
        if row is None:
            return unknown("allow-remote-requests not explicitly exported")
        return result_bad(row["allow-remote-requests"].lower() == "yes", f"allow-remote-requests={row['allow-remote-requests']}")

    if check == "bandwidth_test_server":
        rows = section_records(data, "bandwidth_server")
        if rows is None:
            return unknown("/tool bandwidth-server section unavailable")
        row = next((r for r in rows if "enabled" in r), None)
        if row is None:
            return unknown("bandwidth-test server enabled state unavailable")
        return result_bad(row["enabled"].lower() == "yes", f"bandwidth-test server enabled={row['enabled']}")

    if check == "minimum_version":
        minimum = str(options.get("minimum_version") or "").strip()
        version = str(data.get("version") or "").strip()
        if not minimum:
            return unknown("minimum RouterOS version is not configured (set rule option minimum_version)")
        if not version:
            return unknown("RouterOS version could not be parsed")
        def parts(v: str) -> tuple[int, ...]:
            match = re.match(r"^(\d+(?:\.\d+)*)", v)
            return tuple(int(x) for x in match.group(1).split(".")) if match else ()
        actual, required = parts(version), parts(minimum)
        if not actual or not required:
            return unknown(f"cannot compare parsed versions actual={version!r}, minimum={minimum!r}")
        width = max(len(actual), len(required))
        actual += (0,) * (width - len(actual)); required += (0,) * (width - len(required))
        return result_bad(actual < required, f"RouterOS version {version}; configured minimum {minimum}")

    return unknown(f"unsupported RouterOS check {check!r}")
