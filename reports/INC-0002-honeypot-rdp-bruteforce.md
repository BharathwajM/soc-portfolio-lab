# INC-0002: Internet RDP brute force against honeypot vm-honeypot

> **HONEYPOT.** `vm-honeypot` was exposed to the internet on purpose to collect real attack traffic. It held no data, and its admin account used a unique username and a long password. Everything below is real, unsolicited traffic.

| Field | Value |
|---|---|
| Sentinel incidents | #5–#17 (13 incidents, 1 alert each; #17 was raised at ~23:52, after the data pull), plus #18 raised at 00:22:28 after the batch was closed (see timeline) |
| Analytics rule | SOC Lab - Repeated Windows Sign-in Failures (`a82b3a31-dfe0-4a6c-a69b-cf2bb6b88af3`) |
| Severity | Medium |
| First incident (UTC) | 2026-11-07 17:52:11 |
| Workspace | `law-soc-lab` (Japan East) |
| Affected host | `vm-honeypot` (Windows Server 2022, public IP 52.253.112.30, RDP 3389 open to `*`, NLA required) |
| Exposure window | 11:40 → 00:15 UTC (12 h 35 min); data analysed to 23:45 |
| Attackers | 78.46.176.17 (Germany, hosting range): 4,471 attempts. 175.203.62.5 (South Korea): 2 attempts |
| MITRE ATT&CK | T1110.001 Brute Force: Password Guessing; T1110.003 Password Spraying (one password list across several usernames); T1133 External Remote Services (target) |
| Disposition | **True positive, unsuccessful.** Real password-guessing attack; no account was compromised |
| Status | Closed 2026-11-08 ~00:19 UTC: #5–#17 True Positive / Suspicious activity. Honeypot deleted 00:18:17 |

## 1. Detection

AMA forwarded Security events 4624/4625 to `SecurityEvent` via `dcr-soc-signins`. The scheduled rule (5 min over 10 min) alerts when one account/host pair has 5 or more failures, and it suppresses repeat alerts for 30 minutes. At ~14:25 I added `dcr-soc-rdp`, which forwards RDP connection events (RdpCoreTS 131/140, TerminalServices 1149) to `Event`, so connections that never reach a password prompt are visible too.

The first incident was created **12 min 32 s** after the first failed logon.

## 2. Timeline (UTC, 2026-11-07)

| Time | Event | Source |
|---|---|---|
| 11:35:55 | VM boots | Host |
| ~11:40 | NSG rule opens 3389 to the internet | Azure |
| 11:52:28 | First RDP connection from an internet scanner (**12 min** after exposure) | Host RdpCoreTS 131 |
| 11:52–14:13 | 6 scanner connections from 4 IPs; no credentials sent | Host ([interim 14:20](../evidence/honeypot-interim-1420Z.md)) |
| ~14:25 | `dcr-soc-rdp` added | Cloud Shell |
| 16:38:17 | First RDP connection seen in Sentinel (216.25.90.11); this confirms the new DCR works | `Event` 131 |
| **17:39:39** | **Brute force starts** from 78.46.176.17: first 4625 (~6 h after exposure) | `SecurityEvent` |
| 17:52:11 | **Incident #5** created | Sentinel |
| 18:36:21 | Burst of single connections from 6 addresses in 194.187.178.0/24 (scanner) | `Event` 131 |
| 19:52:01–02 | 175.203.62.5 tries `Test` twice | `SecurityEvent` |
| 17:52 → 23:22 | One new incident every 30 min (#5–#16) while the attack continues | Sentinel |
| 23:45:37 | Last failure collected for analysis; attack still running | `SecurityEvent` |
| ~23:52 | Incident #17 created (the attack was still running) | Sentinel |
| 2026-11-08 00:15:07 | Teardown started: `az group delete -n rg-soc-honeypot` | Cloud Shell |
| 00:18:17 | `rg-soc-honeypot` gone (VM, disk, NIC, NSG, public IP); `dcr-soc-rdp` deleted | Azure |
| ~00:19 | #5–#17 closed as True Positive / Suspicious activity | Sentinel API |
| 00:22:28 | **Incident #18** created from the attack's last failures (the final one was at 00:14:58; 4,859 from 78.46.176.17 over the whole exposure). Missed: it was raised after the batch close | Sentinel |
| ~04:15 | Final review before teardown finds #18 still "New". It was never closed; the workspace was deleted at 04:20 | Sentinel Logs (`SecurityIncident`) |

## 3. Investigation (NIST SP 800-61: detection & analysis)

- **What was attempted?** 4,473 network logons (type 3, via NLA/`NtLmSsp`) over 367 minutes. The rate was a steady 12 per minute, peaking at 14. That steady pace points to an automated tool working through a list.
- **Which accounts?** A short generic wordlist: `Administrator` 645, `Admin` 642, `server` 635, `user` 634, `support` 632, `test` 631, `remote` 630, plus `ME`, `DefaultAccount`, `guest` and `Test`.
  - 4,459 attempts failed with `0xc0000064` (the user doesn't exist).
  - 14 failed with `0xc000006a` (wrong password) against `DefaultAccount` and `Guest`. Those are built-in accounts and disabled by default.
  - The real admin username was **never tried**.
- **Did anything succeed?**
  - **No.** In Sentinel there were 0 logons of type 3 or 10; the 38 successful logons were all `SYSTEM` type 5 (services).
  - On the host there were 0 RDP authentication successes (1149), 0 new users or group changes (4720/4732), and no new local accounts.
  - Every attempt failed at NLA, before a desktop session was created.
- **Who else?**
  - 17 IPs connected to 3389 after 16:38, and 4 more earlier. Only 2 of them sent credentials; the rest were scanners mapping the port.
  - 78.46.176.17 sits in a hosting provider's range in Falkenstein, Germany. That fits a rented or compromised server used for scanning.
- **Logging gap found.** The VM's local RdpCoreTS log rolled over and kept only the last ~143 connections, so the morning's scanner activity was gone from the host by evening. Sentinel kept the full history from 16:38.

## 4. Containment, eradication, recovery

Lab (done 2026-11-08):
1. **Contain and eradicate.** Deleted `rg-soc-honeypot` (00:15:07 → 00:18:17 UTC), which removed the VM, NIC, disk, NSG and public IP. Deleted `dcr-soc-rdp`. The collected logs stay in `law-soc-lab`. `vm-soc-win` and its DCRs were not touched.
2. Closed #5–#17 as True Positive / Suspicious activity, referencing this report.

If this were a production server:

1. **Contain.** Remove the `Allow 3389 from *` rule at once. Put RDP behind Azure Bastion, a VPN, or just-in-time VM access limited to known IPs. Block 78.46.176.17 at the NSG/firewall as a stop-gap only, because attackers rotate IPs.
2. **Scope.** Query 4625/4624 for the same IPs across all hosts. Confirm there were no type 3/10 successes, no 1149 events, and no new accounts, services or scheduled tasks anywhere.
3. **Eradicate and recover.** If any logon had succeeded, isolate the host, reset the credential and rebuild from a known-good image.
4. **Harden.** Keep NLA on. Keep the account lockout threshold (it was 10 here). Keep `Administrator` renamed and `Guest`/`DefaultAccount` disabled. Use long unique passwords or, better, no password-based RDP from the internet at all.

## 5. Post-incident: what I learned and changed

- **Exposure finds you fast.** Scanners connected in 12 minutes. Password guessing started 6 hours later and never stopped. Leaving RDP open to `*` is a matter of when, not if.
- **One attack, thirteen incidents.** The rule's 30-minute suppression with grouping off turned one continuous attack into 13 incidents, one per half hour. **Fix:** enable incident grouping by IP/host over a few hours, so one attack is one incident with many alerts.
- **Closing a batch is not the end.** I closed #5–#17 at 00:19, but the rule's 10-minute lookback still held failures from the attack's final minutes, and it raised #18 three minutes later. **Fix:** after closing incidents for an attack, wait at least one full lookback after the activity stops, then re-check the queue.
- **The rule counted the wrong thing for this attack.** It thresholds per account, so a spray across 10 usernames still alerted only because each name got many tries. **Tuning:** add a second rule that counts distinct usernames per source IP (spraying) and map the `IpAddress` entity so incidents carry the attacker IP.
- **Collect connection telemetry centrally.** Sign-in events alone missed every scanner that never sent a password, and the host's own RDP log overwrote itself within hours. The RDP DCR closed both gaps.
- **Implemented 2026-11-08.** Grouping is now on for the sign-in rule (by Host). The new spray rule (one IP, 10+ failures, 3+ accounts, grouped by IP) fires on 78.46.176.17 in 40 of 41 ten-minute windows of this attack and nowhere else, so this attack would have been one incident. See [evidence/tuning-and-mde-setup.md](../evidence/tuning-and-mde-setup.md).
- **Basic hygiene beat the attack.** A non-default admin name, NLA and a strong password meant 4,473 attempts never got past the login check.
