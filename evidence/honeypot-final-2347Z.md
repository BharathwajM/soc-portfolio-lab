# Honeypot final collection (2026-11-07, pulled 23:45–23:47 UTC, ~12 h 5 min after exposure)

`vm-honeypot` (Windows Server 2022, public IP 52.253.112.30). The NSG allowed RDP 3389 from any source from ~11:40 UTC. NLA was required. Logs reached `law-soc-lab` via Azure Monitor Agent (`dcr-soc-signins` for 4624/4625, plus `dcr-soc-rdp` for RDP connection events from ~14:25).

## Totals (Sentinel `SecurityEvent`, 11:40 → 23:45)

| Metric | Value |
|---|---|
| Failed logons (4625) | **4,473** |
| Source IPs (4625) | 2 |
| Usernames tried | 11 |
| First / last failure | 17:39:39 / 23:45:37 (attack still running at end of collection) |
| Rate | 12.2 per minute on average, peak 14 per minute, over 367 consecutive minutes |
| Successful logons (4624) | 38, all `SYSTEM` logon type 5 (services). **0 network (3) or RDP (10) logons** |

## Source IPs (4625)

| IP | Geo (`geo_info_from_ip_address`) | Failures | Usernames | First | Last |
|---|---|---|---|---|---|
| 78.46.176.17 | Germany, Falkenstein (hosting range) | 4,471 | 10 | 17:39:39 | 23:45:37 |
| 175.203.62.5 | South Korea, Yesan-gun | 2 | 1 (`Test`) | 19:52:01 | 19:52:02 |

## Usernames (all logon type 3, `NtLmSsp`, i.e. NLA)

| Username | Attempts | SubStatus |
|---|---|---|
| Administrator | 645 | `0xc0000064`, no such user |
| Admin | 642 | `0xc0000064` |
| server | 635 | `0xc0000064` |
| user | 634 | `0xc0000064` |
| support | 632 | `0xc0000064` |
| test | 631 | `0xc0000064` |
| remote | 630 | `0xc0000064` |
| ME | 8 | `0xc0000064` |
| DefaultAccount | 8 | `0xc000006a`, account exists but the password was wrong (built-in, disabled) |
| guest | 6 | `0xc000006a` (built-in, disabled) |
| Test | 2 | `0xc0000064` |

The VM's real admin account was **never targeted**. Azure renames the built-in `Administrator`, so the most-tried name does not exist on the VM.

## Hourly timeline (4625)

| Hour (UTC) | Failures | Source IPs |
|---|---|---|
| 17:00 | 203 (from 17:39) | 1 |
| 18:00 | 701 | 1 |
| 19:00 | 717 | 2 |
| 20:00 | 739 | 1 |
| 21:00 | 751 | 1 |
| 22:00 | 764 | 1 |
| 23:00 | 598 (to 23:45) | 1 |

Before 17:39 there were **zero** password attempts, only scanner connections (see below and [honeypot-interim-1420Z.md](honeypot-interim-1420Z.md)).

## RDP connection telemetry (`Event` table, from `dcr-soc-rdp`)

| EventID | Meaning | Rows | Distinct IPs | First | Last |
|---|---|---|---|---|---|
| 131 | TCP connection accepted | 4,495 | 17 | 16:38:17 | 23:45:36 |
| 140 | NLA bad credentials | 4,474 | 2 | 17:39:39 | 23:45:37 |

Top connecting IPs (131):

| IP | Connections | First | Last |
|---|---|---|---|
| 78.46.176.17 | 4,473 | 17:39:38 | 23:45:36 |
| 216.25.90.11 | 3 | 16:38:17 | 16:38:17 |
| 198.235.24.79 | 3 | 22:39:49 | 22:39:50 |
| 175.203.62.5 | 2 | 19:52:01 | 19:52:02 |
| 4.247.144.80 | 2 | 20:15:50 | 20:21:54 |
| 194.180.49.36 | 1 | 17:39:43 | 17:39:43 |
| 194.187.178.{28,74,90,163,203,235} | 1 each | 18:36:21 | 18:36:21 |
| …plus 5 more IPs with 1 connection each | | | |

15 of the 17 connecting IPs were scanners that opened a session and left without sending credentials. Earlier scanner connections (11:52–14:13, 6 from 4 IPs) were captured on the host before this DCR existed. That gives up to 21 distinct connecting IPs over 12 hours.

## Detection: Sentinel incidents

Rule "SOC Lab - Repeated Windows Sign-in Failures" (`a82b3a31-dfe0-4a6c-a69b-cf2bb6b88af3`): runs every 5 min over 10 min, triggers on > 0 rows, **alert suppression 30 min**, grouping off.

| Incidents | Created (UTC) | Alerts each |
|---|---|---|
| #5 → #16 (12) | 17:52:11, 18:22:27, 18:52:25, 19:22:20, 19:52:21, 20:22:22, 20:52:25, 21:22:23, 21:52:25, 22:22:22, 22:52:31, 23:22:28 | 1 |

First detection: 12 min 32 s after the first failure (17:39:39 → 17:52:11). The 30-minute spacing comes from the suppression setting. Because grouping is off, each new alert after suppression opened a new incident: 12 incidents for one continuous attack at the time of this pull, and 13 by teardown.

## On the host (Run Command, 23:47 UTC)

| Check | Result |
|---|---|
| Security 4625 since 11:30 | 4,493 (first 17:39:39, last 23:46:46) |
| Security 4624 type 3/10 | **0** |
| TerminalServices 1149 (RDP auth success) | **0** |
| 4720 / 4732 (user created / added to group) | **0** |
| Local users | DefaultAccount (disabled), Guest (disabled), admin account (enabled), WDAGUtilityAccount (disabled). No new accounts |
| Account lockout threshold | 10 |

## Teardown (2026-11-08)

- One more incident, #17, was created at ~23:52, after this pull, while the attack was still running.
- `az group delete -n rg-soc-honeypot` ran 00:15:07 → 00:18:17 UTC; `az group exists` returns `false`. `dcr-soc-rdp` was deleted.
- #5–#17 (13) were closed as TruePositive / SuspiciousActivity. Incidents created since 13:00: `Closed=13`.
- `rg-soc-lab` still holds `law-soc-lab`, Sentinel, `dcr-soc-signins`, `dcr-soc-defender` and `vm-soc-win` with its network resources.

The host count (4,493) is 20 higher than Sentinel (4,473) only because it was read a minute later, while the attack was still running.
