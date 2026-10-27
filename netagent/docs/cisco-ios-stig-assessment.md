# Cisco IOS STIG assessment engine

This module is separate from the legacy `netagent.compliance` API and the apply/rollback workflow.

## Safety model

- Only rules with `status: approved` and `automation_level: automated` or `semi_automated` are loaded.
- Drafts are ignored, even if their heuristic triage label says `candidate_automated`.
- Supported strategies include literal config-line checks, hierarchical configuration-path checks, combined path/regex checks, AAA common-criteria policy checks tied to local usernames, administrative authentication-server counting aligned to the configured default login method, emergency local-account prechecks, VTY management-ACL prechecks, regex declaration-count prechecks, regex checks over named evidence artifacts, and explicit manual-review rules. No rule-supplied Python or shell commands are executed.
- Missing configuration or required evidence yields `UNKNOWN` for evidence-based checks, never `PASS`. Explicit `manual_review` rules remain `MANUAL`; an unverified target family yields `UNKNOWN`.
- A verified platform/family mismatch yields `NOT_APPLICABLE`.
- Waivers require a control ID, reason, approver and expiry date. An unexpired waiver yields `WAIVED`; an expired waiver no longer overrides assessment.
- No device collection is performed by this module. Evidence is supplied by the caller; a future read-only collector must use a fixed command allowlist and remain separate from assessment logic.
- This is an assessment-only component. It does not modify device configurations.

## Approved rule format (example only)

```json
{
  "status": "approved",
  "automation_level": "automated",
  "control_id": "V-220625",
  "rule_id": "SV-220625r991847_rule",
  "title": "Synthetic reviewed example",
  "severity": "medium",
  "target_platform": "cisco_ios",
  "target_families": ["Catalyst 2960-X"],
  "profiles": ["switch-access"],
  "evidence_requirements": [],
  "check_strategy": {
    "type": "config_line_present",
    "line": "mls qos"
  },
  "pass_condition": {"line_present": "mls qos"},
  "fail_condition": {"line_missing": "mls qos"},
  "remediation": "Review and approve remediation separately."
}
```

Do not mark a STIG draft approved until the source check is reviewed, model/software applicability is verified, and positive/negative fixtures are added.

## Local assessment smoke test

Run `python tools/stig_config_smoke.py --family "Catalyst 2960-X"` from the repository root to exercise the synthetic, sanitized `examples/configs/stig-sample-sw1.cfg` fixture against an explicit test-only set of controls. Use `--group aaa` for AAA-related controls or `--group layer2` for the two Layer-2 pilot controls. The harness does not approve or persist these rules and never prints the configuration contents or secrets.

`config_paths_present` requires command paths to be nested in the configuration hierarchy. `config_paths_and_regex` requires both nested paths and additional regex evidence. `common_criteria_policy` checks for a policy directive and verifies that every configured local username is tied to a policy containing that directive; this is a conservative test predicate, not a complete vendor/STIG applicability decision. Cisco documents that common-criteria policies are applied to user profiles through the `username ... common-criteria-policy ...` configuration. `config_regex_count` can detect a missing minimum count; when marked `partial: true`, it returns `MANUAL` instead of claiming the whole control passed. `manual_review` explicitly keeps controls requiring interface roles, account interpretation, or operational evidence in `MANUAL`.
