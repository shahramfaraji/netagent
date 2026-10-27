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

Candidate files are command snippets, not full running-config dumps. `apply` defaults to a read-only preview against the live running config. No-op detection checks each command in its own IOS configuration context, avoiding false no-ops when a command exists under a different interface or stanza. Previews redact secret values while preserving surrounding command context. Shell/destructive commands (`tclsh`, `clear`, `debug`, `crypto key zeroize`, `archive`, `reload`, `erase`, `format`, `delete`, `copy`, and `write`) are hard-denied. Management-risk commands require an exact-line `--allow-risky-command` entry or a JSON `--risk-allowlist` file with an `allowed_commands` array, then a separate typed confirmation for every risk group (`RISK HOSTNAME GROUP`) after the normal hostname approval. The allowlist never overrides the group confirmations. To make a live change, pass `--apply` from an interactive terminal. The workflow probes `configure replace` and configuration-revert timer support, saves a local versioned snapshot and a unique device-side `flash:` snapshot, verifies both backups, and records an `applying` manifest before writes. It arms a five-minute revert timer, applies the snippet, opens a fresh SSH session, verifies the candidate commands and their SHA-256 hash, finalizes the manifest, and only then issues `configure confirm`. If apply, reachability, hash verification, finalization, or timer confirmation fails, it attempts `configure replace` from the device-side snapshot and records rollback status. Timer command syntax and output vary by IOS/IOS-XE version and remain `TODO(verify-on-device)` until validated on the intended software. Use `rollback --apply` to restore the latest successful deployment. The current running-config SHA-256 is compared with the recorded post-apply hash; if it differs or the hash is missing, the operator must first type `CONFIG CHANGED HOSTNAME`, then complete the normal rollback approval after the target snapshot is verified and a fresh pre-rollback snapshot is created.

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

## Cisco IOS STIG assessment (experimental)

`assess` reads previously collected evidence files only. It does not connect to devices. Only rules explicitly marked `status: approved` execute; the real catalog rules remain drafts and require human approval. The Standard and Pro columns are separate: Standard is the minimum-security verdict, while Pro is a stricter applied-depth/recommendation layer. A Standard PASS means the required configuration is present; it does **not** prove the setting is applied to every relevant interface or operationally effective.

```powershell
python -m netagent assess --hostname synthetic-sw1 --evidence-dir examples/evidence --rules rules/cisco_ios --level pro --stig-part L2S --format md --out out/assessment.md
python -m netagent assess --hostname synthetic-sw1 --evidence-dir examples/evidence --rules rules/cisco_ios --level pro --stig-part L2S --format json --out out/assessment.json
python -m netagent assess --hostname synthetic-sw1 --evidence-dir examples/evidence --rules rules/cisco_ios --level pro --stig-part L2S --format html --out out/assessment.html
python -m netagent assess --hostname synthetic-sw1 --evidence-dir examples/evidence --rules rules/cisco_ios --level pro --stig-part L2S --format cklb --out out/assessment.cklb
python -m netagent assess --hostname synthetic-sw1 --evidence-dir examples/evidence --rules rules/cisco_ios --level pro --stig-part L2S --format xccdf --out out/assessment.xml
```

Exit codes: `0` completed under the selected policy; `1` invalid policy/runtime error; `2` a qualifying Standard finding at or above `--fail-on` (default `high`), or a qualifying Pro finding only when `--fail-on-pro` is set to a severity threshold; `3` unresolved Standard `UNKNOWN` unless `--allow-unknown`, or Standard `MANUAL` only when `--strict-manual` is enabled. A zero-approved-rule run reports `nothing executed` and `NO_RULES`.

Exit-code decision order (first matching condition wins):

| Priority | Condition | Exit code |
|---:|---|---:|
| 1 | Invalid `--fail-on` or `--fail-on-pro` value | `1` |
| 2 | Standard `FAIL` at/above `--fail-on` threshold | `2` |
| 3 | Pro `FAIL` at/above `--fail-on-pro` threshold (Pro is opt-in; default is `none`) | `2` |
| 4 | Standard `UNKNOWN` exists and `--allow-unknown` is not set | `3` |
| 5 | Standard `MANUAL` exists and `--strict-manual` is set | `3` |
| 6 | No condition above applies | `0` |

`--allow-unknown` only changes the exit code; it does not remove UNKNOWN findings from reports. `--strict-manual` affects MANUAL only when no qualifying FAIL or unresolved UNKNOWN has higher precedence. `UNKNOWN` (evidence missing/uninterpretable or device scope unsupported) and `MANUAL` (evidence exists but needs human judgment) remain separate statuses and counts. Per-check `can_pass` / `can_fail` capability flags default to `true`; if a check cannot substantiate a PASS or FAIL, that result is downgraded to `MANUAL` with its original status recorded in `downgraded_from`. Checks that cannot prove either outcome should use `manual_review`.

The CKLB exporter currently uses the sanitized converter fixture at `examples/sample-synthetic.cklb` as a structural template. That fixture is **not** an export produced by DISA STIG Viewer 3; import compatibility remains unverified until a generated checklist is opened in STIG Viewer 3. XCCDF output is a TestResult export and has not yet been schema-validated against the official XCCDF 1.1 schema. No live device testing has been performed.

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

## Local web UI (experimental)

The optional browser UI calls the existing netagent modules in-process; GitHub is not a runtime dependency. The first web version provides local inventory/backup summaries, report listing, read-only SSH backup, and explicitly triggered discovery. It does not expose live config apply/rollback.

Install the optional web dependencies from the project root:

```powershell
python -m pip install -e ".[web,ssh]"
.\\run-web.ps1
```

Open `http://127.0.0.1:8765`. The script creates a temporary operator token for the discovery and backup actions; enter it in the relevant form. The token is not saved to disk. To bind to the LAN, run `.\\run-web.ps1 -Lan`; this listens on all interfaces, so only do this on a trusted network and restrict access with Windows Firewall. Do not forward this port to the Internet. The service refuses non-loopback binding unless a token of at least 24 characters is configured.

The API documentation is at `/api/docs`. Set `NETAGENT_DATA_DIR` to override the local data directory. No device discovery or SSH connection runs merely by opening the dashboard.

## Quick start
```bash
pip install -e .[ssh]
python -m unittest discover -s tests -t .
netagent audit --rules examples/rules/baseline.json --inventory examples/inventory.json --configs examples/configs
netagent topology --neighbors examples/neighbors --inventory examples/inventory.json --out out/
netagent discover 10.0.0.0/24
netagent backup --inventory inventory.json
```
