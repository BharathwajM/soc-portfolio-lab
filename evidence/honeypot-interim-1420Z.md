# Honeypot interim check (2026-11-07, 14:20–14:26 UTC, ~2 h 40 min after exposure)

`vm-honeypot` (52.253.112.30): RDP 3389 open to the internet since ~11:40 UTC. Booted 11:35:55. Planned collection ends ~23:40 UTC.

## Sentinel (`SecurityEvent`, Computer `vm-honeypot`, since 11:00)

| Failed logons (4625) | Successful logons (4624) | Source IPs | Usernames tried | Last event |
|---|---|---|---|---|
| 0 | 12 (all `SYSTEM`, type 5) | 0 | 0 | 13:40:45 |

Sentinel incidents since 11:40: none from the sign-in rule.

## On the host (Run Command, read-only)

| Check | Result |
|---|---|
| Audit policy, Logon | Success and Failure |
| Security 4625 since 11:30 | **0**, so the pipeline isn't dropping failures; nobody has tried a password |
| Security 4624 11:46–14:00 | 12 (Sentinel: 12, so ingestion is complete) |
| 4624 by type since 11:30 | type 5 = 67 (services, mostly at boot), type 2 = 4, type 0 = 1 |
| Type 2 / 0 logons | 11:36:00–01 `Font Driver Host\UMFD-0`, `UMFD-1`, `Window Manager\DWM-1` ×2 (winlogon/wininit), `NT AUTHORITY\SYSTEM` type 0: all boot-time system sessions |
| Network (3) / RDP (10) logons | none |
| RDP auth success (TerminalServices 1149) | 0 |
| NLA required | yes (`UserAuthentication = 1`) |
| NLA bad-credential events (RdpCoreTS 140) | 0 |
| RDP TCP connections accepted (RdpCoreTS 131) | **6 from 4 IPs**, first 11:52:28, last 14:13:45 |

Connecting IPs (scanners: they opened a TCP session and left without sending credentials):

| IP | Connections |
|---|---|
| 35.210.114.22 | 2 |
| 82.147.85.101 | 2 |
| 35.206.146.145 | 1 |
| 199.165.159.121 | 1 |

## Interpretation

- The port was discovered about 12 minutes after exposure, but in the first 2.5 hours only internet-wide scanners connected. Nobody started a password-guessing attack. That is normal for a new IP: scanners find the port first, and brute-force lists pick it up later.
- With NLA on, a password attempt would show as RdpCoreTS 140 plus Security 4625. Both are 0.
- **No compromise.** There are no network, RDP or unexpected interactive logons.

## Change made

The sign-in DCR only sees password attempts, so scanner connections were invisible in Sentinel. I added `dcr-soc-rdp`, associated with `vm-honeypot` as `dcra-honeypot-rdp`, at ~14:25 UTC. It collects RdpCoreTS 131 (connection accepted), 140 (NLA bad credentials) and TerminalServices 1149 (RDP auth success) into the `Event` table. It only collects events from the moment the agent loads it; earlier connections stay on the host and are listed above.
