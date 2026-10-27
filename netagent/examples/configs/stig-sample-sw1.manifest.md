# stig-sample-sw1.cfg — fixture manifest

Synthetic Cisco Catalyst WS-C2960X-24TS-L / IOS 15.2 configuration (449 lines). No real data: RFC 5737 addresses,
`example.invalid`, secrets are the literal `<REDACTED>`.

## Read this first
- "Intended" = what the fixture was DESIGNED to show, based on the `fix_text` of the DISA catalog (Y26M04) as read by the consultant.
  It is NOT an official verdict. A human records the final expected result when a rule is approved.
- Config syntax was NOT verified on a real device. This file is for the parser/engine, not for loading onto a switch.
- Mixed compliance is intentional so that both PASS and FAIL paths can be tested.
- Secret scanner: the file contains `username ... secret <REDACTED>` and `key <REDACTED>`; the scanner must treat the
  `<REDACTED>` placeholder as safe (allowlist this file), otherwise it will flag these lines.

## Interface layout
| Ports | Design |
|---|---|
| Gi1/0/1-8 | access VLAN 10 + voice VLAN 20, 802.1X+MAB, portfast, BPDU guard, storm-control, IP Source Guard; UUFB only on 1-4 |
| Gi1/0/9-14 | access VLAN 30, portfast + BPDU guard only (no 802.1X, storm-control, IPSG) |
| Gi1/0/15-16 | access, no `switchport access vlan` (default VLAN 1) |
| Gi1/0/17 | access on VLAN 998 (= the trunk native VLAN) |
| Gi1/0/18-20, 27-28 | shutdown, parked on VLAN 999 (compliant unused ports) |
| Gi1/0/21 | trunk to an access-layer switch: nonegotiate, native 998, VLAN 1 pruned, root guard |
| Gi1/0/22 | shutdown, still on default VLAN (non-compliant unused port) |
| Gi1/0/23 | trunk with defaults only (no nonegotiate, native VLAN 1, VLAN 1 not pruned) |
| Gi1/0/24 | uplink trunk: nonegotiate, native 998, VLAN 1 pruned, DHCP snooping and ARP inspection trust |
| Gi1/0/25-26 | no `switchport mode` line = dynamic auto (2960 default) |
| Fa0 / Vlan1 / Vlan99 | shutdown / shutdown, no IP / management SVI on VLAN 99 |

## Control coverage (intended)
| Control | Where | Intended |
|---|---|---|
| V-220571, 220578, 220582 | `archive / log config`, `logging userinfo` | PASS |
| V-220575 | `line vty 0 4` has access-class, `line vty 5 15` does not | FAIL (per-block aggregation) |
| V-220576 | `login block-for 900 attempts 3 within 120` | PASS |
| V-220577 | synthetic banner (not the required text) | FAIL or MANUAL (exact text required, unverified) |
| V-220580 | `service timestamps log datetime localtime` | PASS |
| V-220581 | `MANAGEMENT_NET` uses `log-input`, `BLOCK_INBOUND` does not | FAIL (per-ACL) |
| V-220586 | only part of the listed services disabled | FAIL or MANUAL (unverified) |
| V-220587 | one local user bound to the password policy + `group TACACS_GROUP local` | PASS or MANUAL |
| V-220589..594 | `aaa common-criteria policy PASSWORD_POLICY` with all directives | PASS |
| V-220595 | `service password-encryption`, `enable secret` | PASS |
| V-220596 | console and vty 0 4 `exec-timeout 5 0`; vty 5 15 uses 15 | FAIL |
| V-220599 | `logging buffered 64000 informational` | PASS |
| V-220601, 220606 | two authenticated NTP servers | PASS |
| V-220604, 220605 | SNMPv3 group with `priv` (no community strings) | PASS |
| V-220607, 220608 | SSH v2 + approved MAC/cipher lists | PASS |
| V-220612 | `login on-failure log`, `login on-success log` | PASS |
| V-220617 | two TACACS servers through the named group `TACACS_GROUP` | PASS |
| V-220620 | two `logging host` lines | PASS or MANUAL |
| V-220623 | 802.1X only on Gi1/0/1-8 | FAIL or MANUAL |
| V-220624 | `vtp mode transparent` | NOT_APPLICABLE |
| V-220625, 220631, 220638, 220639 | `mls qos`, `loopguard default`, rapid-pvst, `udld enable` | PASS |
| V-220629 | root guard on Gi1/0/21 | PASS (needs operator role `downlink`) |
| V-220630 | BPDU guard on every access port | PASS |
| V-220632 | UUFB only on Gi1/0/1-4 | FAIL |
| V-220633 | DHCP snooping on VLANs 10,20,30 | PASS |
| V-220634 | IP Source Guard only on Gi1/0/1-8 | FAIL |
| V-220635 | ARP inspection on VLANs 10,20 but not 30 | FAIL |
| V-220636 | storm-control only on Gi1/0/1-8 | FAIL |
| V-220637 | no `ip igmp snooping` line (default behavior is not shown in running-config) | MANUAL/UNKNOWN edge case (default-on is the consultant's knowledge, unverified) |
| V-220640, 220643, 220646 | Gi1/0/21 and 24 compliant, Gi1/0/23 not | FAIL (per-interface aggregation) |
| V-220641 | Gi1/0/22 shut down but not parked | FAIL |
| V-220642 | Gi1/0/15-16 on the default VLAN | FAIL (note: 802.1X dynamic VLANs may justify it; real result may be MANUAL) |
| V-220644 | management on VLAN 99, Vlan1 shut | PASS |
| V-220645 | Gi1/0/25-26 dynamic mode | FAIL or role-dependent |
| V-220647 | Gi1/0/17 on the native VLAN 998 | FAIL |

Not covered: V-220570, 220572-220574, 220583-220585, 220600, 220609 (CoPP, platform support unverified), 220611, 220613, 220618, 220619, 220621 (needs `show version`).

## Deliberate engine traps
1. **Banner opacity:** the banner text contains `transport input telnet` and `no ip http server`; neither may be read as configuration.
2. **Blocks starting with `t`:** `tacacs server TACACS_A/B` — catches the indentation bug in `_config_tree`.
3. **Named AAA groups:** `group TACACS_GROUP` instead of the literal `group tacacs+`.
4. **Per-block / per-interface / per-ACL aggregation** (vty, trunks, access ports, ACLs).
5. **Absent default settings** (IGMP snooping) and **dynamic-auto ports** without a `switchport mode` line.
6. **Model evidence in config:** `switch 1 provision ws-c2960x-24ts-l`.

## Observed with the repo's smoke harness (draft rules, commit 95eb93e, family set manually)
| Control | Observed | Matches intent? |
|---|---|---|
| 220571, 220578, 220582 | PASS | yes |
| 220575 | FAIL (vty 5 15) | yes |
| 220589-220594 | PASS | yes |
| 220620 | MANUAL (count precheck satisfied) | yes |
| 220623 | MANUAL | yes |
| 220625, 220631 | PASS | yes |
| **220617** | **FAIL (0 server definitions found)** | **no — caused by the `lstrip(" \\t")` bug: `tacacs server TACACS_A` loses its children** |
| **220587** | **FAIL** | **no — named group `TACACS_GROUP` is not understood; with the literal `group tacacs+` the same rule returns MANUAL** |

## Companion file
`stig-sample-sw1.roles.json` — operator role map for the Pro (interface role) tests.
