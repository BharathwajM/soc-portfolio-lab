# Defender Antivirus → Sentinel evidence (2026-11-07, UTC)

> **LAB TEST.** The "malware" is the EICAR test file, a harmless string every antivirus detects on purpose.

## Pipeline set up

| Item | Value |
|---|---|
| Data collection rule | `dcr-soc-defender` (Japan East). XPath `Microsoft-Windows-Windows Defender/Operational!*[System[(EventID=1116 or EventID=1117)]]`, stream `Microsoft-Event` → `law-soc-lab` ([detections/defender-dcr.json](../detections/defender-dcr.json)) |
| Association | `dcra-soc-defender` → `vm-soc-win` (Azure Monitor Agent already installed) |
| Analytics rule | `soc-lab-defender-av-detection`: "SOC Lab - Defender Antivirus Malware Detection", High, every 5 min over 10 min, Host entity from `Computer`, custom details Threat / FilePath / Actions ([detections/defender-analytics-rule.json](../detections/defender-analytics-rule.json)) |

## Run 1 (12:31 UTC): detected on the host, not collected

Output of [scripts/Invoke-EicarTest.ps1](../scripts/Invoke-EicarTest.ps1) via Run Command:

```
Wrote EICAR test file at 2026-11-07T12:31:39.0399419Z
File still on disk: False
Detection: Virus:DOS/EICAR_Test_File | action success: True | file:_C:\soclab-eicar\eicar-test.txt
Event 1117 at 2026-11-07T12:31:50.1846645Z
Event 1116 at 2026-11-07T12:31:39.4791686Z
```

Polled `Event` every ~40 s from 12:32:29 to 12:45 → **0 rows**. The DCR had been associated only minutes earlier. Azure Monitor Agent picks up new DCRs on its own polling cycle, and it does not backfill Windows events that were written before the new subscription was active.

## Run 2 (12:44 UTC): end to end

```
Wrote EICAR test file at 2026-11-07T12:44:56.4599313Z
File still on disk: False
Detection: Virus:DOS/EICAR_Test_File | action success: True | file:_C:\soclab-eicar\eicar-test.txt
Event 1117 at 2026-11-07T12:45:06.6683967Z
Event 1116 at 2026-11-07T12:44:56.5034738Z
```

### Events in Sentinel (`Event` table)

| EventID | TimeGenerated | Ingested | Lag | Action | Threat | Process | User | Origin |
|---|---|---|---|---|---|---|---|---|
| 1116 | 12:44:56.503 | 12:48:10.236 | 3 m 14 s | Not Applicable | Virus:DOS/EICAR_Test_File | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | NT AUTHORITY\SYSTEM | Local machine |
| 1117 | 12:45:06.668 | 12:45:48.124 | 42 s | Quarantine | Virus:DOS/EICAR_Test_File | same | same | same |

### Detection query (first run, 12:45:51, before 1116 arrived)

```json
{"Computer":"vm-soc-win","Threat":"Virus:DOS/EICAR_Test_File","Severity":"Severe",
 "Path":"file:_C:\\soclab-eicar\\eicar-test.txt","Actions":"[\"Quarantine\"]","EventIDs":"[1117]","Events":"1",
 "First":"2026-11-07T12:45:06.6683967Z","Last":"2026-11-07T12:45:06.6683967Z"}
```

### Alerts and incidents

| Incident | Id | Alert generated | Query window (UTC) | Rows | Created | Closed |
|---|---|---|---|---|---|---|
| #2 | `e3844e91-3245-4502-a330-0460d0f24712` | 12:50:08.61 (SystemAlertId `16427f49-2168-bec7-efeb-e8ba388c1ce5`) | 12:35:00 → 12:45:01 (event 1116 only, Actions "Not Applicable") | 1 | 12:50:23.28 | 12:54:32, BenignPositive / SuspiciousButExpected |
| #3 | `b6862aae-6595-4289-b821-fc8ba2ab8083` | 12:55:19 (alert `1d4d5efd-ec42-1083-b6f2-82c5f172e7bb`) | ~12:40 → 12:50 (1116 + 1117 summarised into one row, last seen 12:45:06) | 1 | 12:55:19.83 | 12:57:53, BenignPositive (duplicate of #2) |
| #4 | `042619e5-c2d3-4623-8f46-05ccc0e1d3c9` | 12:58:15 | immediate run after the rule edit at 12:57:56 (event 1117) | 1 | 12:58:15.81 | 14:25:41, BenignPositive (duplicate of #2) |

Time from the Defender detection (12:44:56) to incident #2: **5 min 27 s**.

### Scope checks

- Defender detections in the last 7 days (`Event`, 1116/1117): **2 events, 1 host, 1 threat** (`Virus:DOS/EICAR_Test_File`). Run 1 never reached the workspace.
- Logons on `vm-soc-win` 12:30–13:00 (`SecurityEvent`): one 4624 for `NT AUTHORITY\SYSTEM` (the Run Command extension). No interactive or network logons.

### Tuning applied

The rule's 10-minute lookback overlaps its 5-minute schedule. That overlap is deliberate: event 1116 arrived 3 minutes late and would have been missed with a 5-minute lookback. The cost is that the same detection alerted twice. Incident grouping is now **enabled** on the rule (match all entities, 5 h window, don't reopen closed incidents), so a repeat alert for the same host joins the open incident instead of creating a new one.

Incident #1 (`467fdcd9-1fdf-484f-acd7-32a300831311`, sign-in failures) was closed at 12:54:39 as BenignPositive / SuspiciousButExpected in the same pass.
