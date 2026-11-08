# Honeypot interim check #2 (2026-11-07, 21:31–21:36 UTC, ~9 h 50 min after exposure)

`vm-honeypot` (52.253.112.30), RDP 3389 open to the internet since ~11:40 UTC. VM running. Collection ends ~23:40 UTC.

## Sentinel (`SecurityEvent`, since 11:40)

| Failed logons (4625) | Source IPs | Usernames tried | Successful logons (4624) |
|---|---|---|---|
| 2,801 | 2 | 11 | 27, all `SYSTEM` type 5 (no network/RDP logons) |

### Source IPs

| IP | Country (`geo_info_from_ip_address`) | Failures | Usernames | First seen | Last seen |
|---|---|---|---|---|---|
| 78.46.176.17 | Germany | 2,799 | 10 | 17:39:39 | 21:33:17 (still active) |
| 175.203.62.5 | South Korea | 2 | 1 (`Test`) | 19:52:01 | 19:52:02 |

### Usernames tried

| Username | Attempts |
|---|---|
| Administrator | 402 |
| Admin | 400 |
| server | 393 |
| user | 391 |
| support | 390 |
| remote | 388 |
| test | 388 |
| ME | 8 |
| DefaultAccount | 8 |
| guest | 6 |
| Test | 2 |

The VM's real admin username was **not** tried.

### Failure reasons (all logon type 3, `NtLmSsp`, i.e. NLA)

| SubStatus | Meaning | Count |
|---|---|---|
| `0xc0000064` | Username does not exist | 2,766 |
| `0xc000006a` | Username exists, wrong password | 14: `DefaultAccount` ×8, `Guest` ×6 (built-in, disabled by default) |

## RDP connection telemetry (`dcr-soc-rdp`, `Event` table)

The DCR added at ~14:25 is now confirmed working.

| EventID | Meaning | Rows | First | Last |
|---|---|---|---|---|
| 131 | TCP connection accepted | 2,793 | 16:38:17 | 21:33:16 |
| 140 | NLA bad credentials | 2,776 | 17:39:39 | 21:33:17 |

## Sentinel incidents

The "SOC Lab - Repeated Windows Sign-in Failures" rule raised **8 incidents (#5–#12)**, all Medium and New. They were created at 17:52, 18:22, 18:52, 19:22, 19:52, 20:22, 20:52 and 21:22. That is one every 30 minutes while the attack ran (cause to confirm in the rule's suppression/grouping settings at the final check). They are left open for the final investigation.

## On the host (Run Command, 21:32 UTC)

| Check | Result |
|---|---|
| RdpCoreTS 131 (connections) | 143 in the log, all 78.46.176.17, last 21:32:00 |
| RdpCoreTS 140 (NLA bad credentials) | 144 |
| TerminalServices 1149 (RDP auth success) | **0** |
| Security 4625 | 2,764 |
| Security 4624 type 3 / 10 | **0** |

The local RdpCoreTS log holds only the most recent ~143 connections. It has rolled over and lost the morning's scanner connections (6 from 4 IPs, recorded in [honeypot-interim-1420Z.md](honeypot-interim-1420Z.md)). The `Event` table in Sentinel keeps the full history from 16:38 onward. This is a real-world argument for central log collection.

## Interpretation

- The brute-force started about **6 h after exposure** (17:39 UTC). Scanners found the port in 12 minutes.
- It is one dominant source (a German hosting-range IP) cycling through a 7-name generic wordlist at roughly 11–12 attempts per minute.
- **No compromise.** No 4624 network/RDP logon and no 1149 RDP success. Every attempt failed at NLA before a session was created.
