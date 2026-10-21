# netagent (MVP)

Network discovery, read-only SSH config backup, topology map and compliance audit.

## Scope (v0.1)
- `discover`: scan a CIDR for management ports (Nmap if installed, TCP fallback). Max /20 per run.
- `backup`: fetch running config + CDP/LLDP neighbors over SSH (Netmiko, read-only commands), versioned with diffs.
- `topology`: build a graph from neighbor output -> `topology.json` + Mermaid `topology.mmd`.
- `audit`: evaluate configs against user rules (regex must/must-not), severity-sorted Markdown report + score.
- `audit` exits nonzero when any inventory device has no saved configuration; this is an incomplete audit, not a pass.
- If Nmap is missing, times out, exits unsuccessfully, or returns invalid XML, discovery logs the failure and falls back to TCP connect checks. The fallback checks TCP ports only and does not provide Nmap hostnames or OS guesses.

Out of scope for v0.1: pushing config to devices, monitoring, web UI.

## Security
- Credentials are never stored: prompted at runtime or read from `NETAGENT_USERNAME` / `NETAGENT_PASSWORD` / `NETAGENT_SECRET`.
- Inventory rejects password fields. Errors are redacted. Scans only the range you pass.

## Quick start
```bash
pip install -e .[ssh]
python -m unittest discover -s tests -t .
netagent audit --rules examples/rules/baseline.json --inventory examples/inventory.json --configs examples/configs
netagent topology --neighbors examples/neighbors --inventory examples/inventory.json --out out/
netagent discover 10.0.0.0/24
netagent backup --inventory inventory.json
```
