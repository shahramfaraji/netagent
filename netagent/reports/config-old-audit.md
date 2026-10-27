# Compliance report

| Device | Rule score | Critical | High | Medium | Low | Unknown | Evaluated rules |
|---|---:|---:|---:|---:|---:|---:|---:|
| SW1ACC-R4-Ed_Mazandaran | 85 | 0 | 1 | 1 | 0 | 0 | 6 |

## SW1ACC-R4-Ed_Mazandaran
- **[HIGH] SSH-V2**: SSH must be version 2 (missing: /^ip ssh version 2/)
  - Fix: `ip ssh version 2`
- **[MEDIUM] LOGGING**: Remote syslog configured (missing: /^logging (host )?\d+\.\d+\.\d+\.\d+/)
  - Fix: `logging host <ip>`

> Rule score is a rule-weight summary, not a security percentage. N/A means one or more checks could not be evaluated, or no rules applied to this platform.
