# Cisco IOS STIG rule review — Batch 01

## Status

**Pilot review only — no rules approved for execution.** This batch tests the rule-review workflow using synthetic configuration fixtures. Both rules remain `status: draft`; the assessment loader must continue to ignore them.

Source benchmark: DISA Cisco IOS Switch L2S STIG, Version 3, Release 1, benchmark date 24 Jul 2024. Source file SHA-256 recorded in each draft's `source_ref`.

## Candidate controls

| Control | Severity | Proposed check | Decision | Blocking items |
|---|---|---|---|---|
| V-220625 / CISC-L2-000040 | CAT II / medium | Exact global config line `mls qos` | Pilot candidate | Verify support and semantics for each intended model and IOS release; confirm QoS behavior expected by the requirement |
| V-220631 / CISC-L2-000110 | CAT II / medium | Exact global config line `spanning-tree loopguard default` | Pilot candidate | Verify command support, STP-mode interactions, and applicability for each intended model and IOS release |

The strategy currently checks exact line presence only. It does not prove runtime feature operation or validate the full device topology. A positive result therefore means only that the reviewed configuration line was found in the supplied config.

## Controls deliberately excluded from this pilot

- **V-220623 (802.1X/MAB):** depends on identifying every host-facing interface, exception handling, AAA/RADIUS state and device context.
- **V-220629 (Root Guard):** requires topology knowledge to identify access-layer uplinks.
- **V-220630 (BPDU Guard):** requires identifying user-facing/untrusted interfaces; global and interface-level variants must be considered.
- **V-220637 (IGMP/MLD snooping):** includes global defaults and per-VLAN overrides; a single positive-line check can miss disabled VLANs.
- **V-220638 (Rapid STP/MSTP):** requirement is conditional on topology and allows alternative STP modes.
- **V-220624 (VTP authentication):** must correlate VTP operating mode, password state and evidence from show commands.

These remain drafts and should not be marked automated based on heuristic triage alone.

## Synthetic fixtures

- `tests/fixtures/stig/cisco_ios/batch_01/v-220625-pass.cfg`
- `tests/fixtures/stig/cisco_ios/batch_01/v-220625-fail.cfg`
- `tests/fixtures/stig/cisco_ios/batch_01/v-220631-pass.cfg`
- `tests/fixtures/stig/cisco_ios/batch_01/v-220631-fail.cfg`

Fixtures are intentionally synthetic and do not represent any live device. Tests verify expected PASS/FAIL behavior and assert that draft rules are not loaded as approved rules.

## Approval gate

Before any candidate changes from draft to approved:
1. Confirm exact target models and IOS/IOS XE releases.
2. Verify command support and semantics against vendor documentation for those versions.
3. Review both positive and negative fixtures, including missing/empty evidence behavior.
4. Add reviewer identity and date to the review record.
5. Keep remediation advisory; never auto-apply it.

## Batch outcome

Two pilot candidates prepared with positive/negative synthetic fixtures. No rules have been approved or made executable. This is intentionally smaller than the planned 20–30 rule batch because model/software applicability has not yet been confirmed.
