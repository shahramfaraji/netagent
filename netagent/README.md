# netagent (MVP)

Network discovery, read-only SSH config backup, topology map and compliance audit, plus a guarded single-device Cisco IOS config deployment workflow.

## Scope (v0.1)
- `discover`: scan a CIDR for management ports (Nmap if installed, TCP fallback). Max /20 per run.
- `backup`: fetch configs + CDP/LLDP neighbors over SSH, versioned with diffs.
- `topology`: build a graph from neighbor output -> `topology.json` + Mermaid `topology.mmd`.
- `audit`: evaluate configs against user rules (regex must/must-not), severity-sorted Markdown report + score.
- `audit` exits nonzero when any inventory device has no saved configuration; this is an incomplete audit, not a pass.
- If Nmap is missing, times out, exits unsuccessfully, or returns invalid XML, discovery logs the failure and falls back to TCP connect checks. The fallback checks TCP ports only and does not provide Nmap hostnames or OS guesses.
- `apply`: read-only dry-run by default. Live apply is opt-in, one inventory device at a time, and currently supports Cisco IOS only.
- `rollback`: read-only preview by default; live rollback restores the last successful apply snapshot.

## Config apply safety

Candidate files are command snippets, not full running-config dumps. `apply` defaults to a read-only preview against the live running config. It shows the current-config hash and the redacted candidate command list, not a simulated resulting-config diff. To make a live change, pass `--apply` from an interactive terminal and type the exact inventory hostname after reviewing that preview. The workflow verifies `configure replace` support, saves a local versioned snapshot and a unique device-side `flash:` snapshot, verifies both backups, then presents them with the candidate preview for typed human approval before applying. If applying or post-change verification fails, it attempts `configure replace` from the device-side snapshot. Use `rollback --apply` to restore the latest successful deployment, after verifying the target snapshot and creating a fresh pre-rollback snapshot that is shown before the separate typed confirmation.

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
- Secret-bearing candidate lines are redacted in apply previews. Captured configs may contain secrets; config snapshots are atomically written with owner-only file permissions (0600). Candidate files must still be protected as sensitive local data.
- Live config writes require dry-run preview, a verified backup, a typed human approval, and a rollback path. There is no unattended/`--yes` apply mode.
- Discovery scans only the range passed by the operator.

## MikroTik SSH test

Use the dedicated inventory example for the discovered MikroTik at `192.168.28.222`.
The SSH test authenticates and reads the device prompt only; it does not run configuration commands.
The backup command runs RouterOS `/export` (read-only) and stores the result under the selected data directory.
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
