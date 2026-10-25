# netagent (MVP)

Network discovery, read-only SSH config backup, topology map and compliance audit, plus a guarded single-device Cisco IOS config deployment workflow.

## Scope (v0.1)
- `discover`: scan a CIDR for management ports (Nmap if installed, TCP fallback). Max /20 per run.
- `backup`: fetch configs + CDP/LLDP neighbors over SSH, versioned with diffs. For MikroTik, also captures read-only RouterOS resource, service, SNMP, NTP, user, SSH, MAC-server, neighbor-discovery, DNS, bandwidth-test, firewall, logging, and `/export verbose` outputs into separate `latest.routeros_*.txt` files beside the config.
- `topology`: build a graph from neighbor output -> `topology.json` + Mermaid `topology.mmd`.
- `audit`: evaluate configs against user rules (regex must/must-not), severity-sorted Markdown report + score. MikroTik rules use parsed RouterOS data rather than regex matching; absent or unparseable inputs stay `UNKNOWN` instead of silently passing.
- `audit` exits nonzero when any inventory device has no saved configuration; this is an incomplete audit, not a pass. Exit codes: `0` = completed under current options, `1` = missing config or operational error, `2` = critical/high finding with `--fail-on-high`, `3` = one or more `UNKNOWN` checks. `--allow-unknown` opts out of exit code 3; UNKNOWN items remain in the report.
- If Nmap is missing, times out, exits unsuccessfully, or returns invalid XML, discovery logs the failure and falls back to TCP connect checks. The fallback checks TCP ports only and does not provide Nmap hostnames or OS guesses.
- `apply`: read-only dry-run by default. Live apply is opt-in, one inventory device at a time, and currently supports Cisco IOS only.
- `rollback`: read-only preview by default; live rollback restores the last successful apply snapshot.

## Config apply safety

Candidate files are command snippets, not full running-config dumps. `apply` defaults to a read-only preview against the live running config. No-op detection checks each command in its own IOS configuration context, avoiding false no-ops when a command exists under a different interface or stanza. Previews redact secret values while preserving surrounding command context. Management-risk commands require an exact-line `--allow-risky-command` entry and a second typed confirmation (`RISK HOSTNAME`) after the normal hostname approval. The allowlist does not override the separate confirmation. To make a live change, pass `--apply` from an interactive terminal. The workflow probes `configure replace` and configuration-revert timer support, saves a local versioned snapshot and a unique device-side `flash:` snapshot, verifies both backups, and records an `applying` manifest before writes. It arms a five-minute revert timer, applies the snippet, opens a fresh SSH session, verifies the candidate commands and their SHA-256 hash, finalizes the manifest, and only then issues `configure confirm`. If apply, reachability, hash verification, finalization, or timer confirmation fails, it attempts `configure replace` from the device-side snapshot and records rollback status. Timer command syntax and output vary by IOS/IOS-XE version and remain `TODO(verify-on-device)` until validated on the intended software. Use `rollback --apply` to restore the latest successful deployment, after verifying the target snapshot and creating a fresh pre-rollback snapshot that is shown before the separate typed confirmation.

This first transactional adapter is deliberately limited to `cisco_ios`; other platforms fail closed and stay read-only. Keep device-side snapshots until the change is verified and follow your organization's change window/access procedures. A failed rollback is reported explicitly and may require operator recovery. Tests use mocked transports only: no live device or vendor firmware was exercised.

```bash
# Read-only preview (default)
netagent apply --inventory inventory.json --device core-sw1 --config candidate.cfg --data data

# Live apply, only from an interactive terminal
netagent apply --inventory inventory.json --device core-sw1 --config candidate.cfg --data data --apply

# Read-only rollback preview, then separately approve a live rollback
netagent rollback --inventory inventory.json --device core-sw1 --data data
netagent rollback --inventory inventory.json --device core-sw1 --data data --apply
```

## Security
- Credentials are prompted at runtime or read from `NETAGENT_USERNAME` / `NETAGENT_PASSWORD` / `NETAGENT_SECRET` only; they are never stored in inventory, deployment metadata, or logs.
- SSH host keys are verified strictly. Netmiko connections reject unknown or changed keys by default; host keys are loaded from `data/known_hosts` unless `NETAGENT_KNOWN_HOSTS` overrides that path. Do not disable strict checking to work around a host-key error.
- To pin a new host key, run `netagent trust-host-key --inventory inventory.json --device DEVICE_NAME` from an interactive terminal. Verify the displayed SHA-256 fingerprint through an independent trusted channel, then type the exact fingerprint. The command reads the public host key only; it does not authenticate or run configuration commands. Changed keys are rejected rather than overwritten. `--no-prompt` and non-interactive sessions fail closed.
- Secret-bearing candidate lines are redacted in apply previews. Captured configs may contain secrets; config snapshots are atomically written with owner-only file permissions (0600). Candidate files must still be protected as sensitive local data.
- Live config writes require dry-run preview, a verified backup, a typed human approval, and a rollback path. There is no unattended/`--yes` apply mode.
- Discovery scans only the range passed by the operator.

## MikroTik SSH test

The automated MikroTik rule tests use the synthetic, sanitized fixture `examples/configs/mikrotik-lab.cfg`; tests do not depend on ignored local device captures.

Use the dedicated inventory example for the discovered MikroTik at `192.168.28.222`.
The SSH test authenticates and reads the device prompt only; it does not run configuration commands.
The backup command runs RouterOS `/export` and additional read-only `print` commands, including `/export verbose`, and stores each result separately under the selected data directory. The audit reads the matching `latest.routeros_*.txt` artifacts when present. It never uses `show-sensitive`.

The minimum RouterOS version check is intentionally `UNKNOWN` until you set `options.minimum_version` in `examples/rules/mikrotik_routeros.json` to your organization's approved minimum. The administrator password-strength check is also intentionally `UNKNOWN`: password values are never collected. Parser behavior and defaults across RouterOS v6/v7 still require validation against representative exports; absent or unparseable sections are not assumed safe.
Treat saved configurations as sensitive files.

```powershell
python -m pip install -e ".[ssh]"
netagent test-ssh --inventory examples/mikrotik-inventory.json --device mikrotik-28-222
netagent backup --inventory examples/mikrotik-inventory.json --device mikrotik-28-222 --data data
```

Credentials are prompted at runtime. Do not put passwords into the inventory file or paste them into chat.
Run the backup only after the SSH test succeeds.

## Quick start
```bash
pip install -e .[ssh]
python -m unittest discover -s tests -t .
netagent audit --rules examples/rules/baseline.json --inventory examples/inventory.json --configs examples/configs
netagent topology --neighbors examples/neighbors --inventory examples/inventory.json --out out/
netagent discover 10.0.0.0/24
netagent backup --inventory inventory.json
```
