# INC-0001: Repeated Windows sign-in failures on vm-soc-win

> **LAB SIMULATION.** Every event in this report came from `scripts/Simulate-SigninFailures.ps1` on a dedicated Azure lab VM. No real user, system or attacker was involved.

| Field | Value |
|---|---|
| Sentinel incident | #1, `467fdcd9-1fdf-484f-acd7-32a300831311` |
| Analytics rule | SOC Lab - Repeated Windows Sign-in Failures |
| Severity | Medium |
| Created (UTC) | 2026-11-07 09:27:23 |
| Workspace | `law-soc-lab` (Japan East) |
| Affected host | `vm-soc-win` (Windows Server 2022, Azure Monitor Agent, DCR `dcr-soc-signins`) |
| Target account | `soclab-probe` (does not exist on the host) |
| MITRE ATT&CK | Credential Access, T1110 Brute Force |
| Disposition | Benign positive: authorised simulation, detection worked as designed |

## 1. Detection logic

The scheduled rule ([detections/repeated-windows-signin-failures.kql](../detections/repeated-windows-signin-failures.kql)) runs every 5 minutes over a 10-minute lookback. It groups Windows event 4625 (failed logon) by `Computer` and target account and raises an alert when a pair reaches **5 or more** failures.

## 2. Timeline (UTC, 2026-11-07)

| Time | Event | Source |
|---|---|---|
| 09:12:28, 09:16:10 | Two smoke runs: one 4625 each for `soclab-smoke`, confirmed in `SecurityEvent` before the rule was enabled | `evidence/windows-smoke-event.txt`, `evidence/sentinel-smoke-ingestion.json`, `evidence/sentinel-logon-outcome-check.md` |
| 09:17:25.239 | Negative control: 1 × 4625 for `soclab-control` (RecordId 4153) | `evidence/windows-signin-test-events.txt` |
| 09:17:25.553 | First failure for `soclab-probe` (RecordId 4155) | same |
| 09:17:27.114 | Sixth and last failure for `soclab-probe` (RecordId 4165), ~1.6 s after the first | same |
| — | Sentinel `SecurityEvent` shows 6 × 4625 for `soclab-probe` and 1 × 4625 for `soclab-control`, matching the host | `evidence/sentinel-signin-counts.json` |
| — | Detection query returns one row: `vm-soc-win` / `soclab-probe`, 6 attempts, status `0xc000006d` | `evidence/sentinel-detection-results.json` |
| 09:27:23 | Incident #1 created by the scheduled rule | `evidence/sentinel-incident.json` |

## 3. Evidence and analysis

- **Volume and speed.** Six failures against one account in about 1.6 seconds suggests automation rather than a person mistyping a password.
- **Status code.** `0xc000006d` (STATUS_LOGON_FAILURE) means a bad username or bad credentials. The account does not exist on the host, which the simulation script checks before it runs.
- **Source.** `SourceAddresses` is empty. The attempts came from an interactive (type 2) logon call on the VM itself, not over the network. A real incident with this pattern would point to code running on the host, not an external brute-force attack.
- **Negative control.** `soclab-control` had a single failure. It appears in `SecurityEvent` but is correctly **not** alerted, which shows the threshold separates noise from a pattern.
- **Successful logon check.** Sentinel has **no 4624 (successful logon) events** for any lab account between 09:00 and 10:30 UTC. The only events are 4625 failures (control 1, probe 6, smoke 2); see `evidence/sentinel-logon-outcome-check.md`. On the host, every attempt returned Win32 error 1326, and the script aborts if any logon succeeds.
- **Endpoint state.** Microsoft Defender Antivirus: enabled, real-time protection on (`evidence/windows-defender-status.txt`). That is the VM's built-in AV status, not a Defender for Endpoint subscription.

```kusto
// Any successful logon for the targeted account around the failure window
SecurityEvent
| where TimeGenerated between (datetime(2026-11-07 09:07:00) .. datetime(2026-11-07 09:37:00))
| where EventID == 4624 and TargetUserName =~ "soclab-probe"
| project TimeGenerated, Computer, TargetUserName, LogonType, IpAddress
```

## 4. Triage decision

**Benign positive.** The activity matches the authorised simulation exactly: same host, same fictitious accounts, same counts, record IDs and timestamps on the host and in Sentinel. Close the incident in Sentinel as *Benign Positive - Suspicious but expected* and add a comment that references this report.

## 5. Recommended response if this happened outside the lab

1. **Scope.** Search the same account and host over 24 hours and the same account across all hosts. Look for 4624 successes, 4740 lockouts and 4648 explicit-credential logons.
2. **Find the source.** With no network address, identify the local process (4688 process creation or EDR telemetry) that made the logon calls.
3. **Contain.** If a success followed the failures, disable or reset the account, revoke sessions and isolate the host. If the source is remote, block it at the NSG or firewall.
4. **Harden.** Confirm the account lockout policy, keep RDP and SMB closed to the internet (this lab's NSG has no inbound allow rules), and require MFA for privileged access.
5. **Tune.** Keep the threshold at 5 in 10 minutes and add a companion rule for failures followed by a success.

Format based on NIST SP 800-61 incident handling phases: detection and analysis, containment, eradication, recovery.
