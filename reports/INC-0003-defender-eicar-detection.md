# INC-0003: Microsoft Defender Antivirus malware detection on vm-soc-win

> **LAB TEST.** The detected file is the EICAR anti-malware test file, written on purpose by [scripts/Invoke-EicarTest.ps1](../scripts/Invoke-EicarTest.ps1). It is harmless and contains no code. (INC-0002 is reserved for the internet honeypot.)

| Field | Value |
|---|---|
| Sentinel incident | #2, `e3844e91-3245-4502-a330-0460d0f24712` (duplicates #3 `b6862aae-6595-4289-b821-fc8ba2ab8083` and #4 `042619e5-c2d3-4623-8f46-05ccc0e1d3c9`) |
| Analytics rule | SOC Lab - Defender Antivirus Malware Detection |
| Severity | High |
| Created (UTC) | 2026-11-07 12:50:23 |
| Workspace | `law-soc-lab` (Japan East) |
| Affected host | `vm-soc-win` (Windows Server 2022, Azure Monitor Agent, DCRs `dcr-soc-signins` + `dcr-soc-defender`) |
| Threat | `Virus:DOS/EICAR_Test_File`, Defender severity Severe |
| File | `C:\soclab-eicar\eicar-test.txt` |
| Action | Quarantined by Defender Antivirus (event 1117) |
| MITRE ATT&CK | Not mapped: test artefact, no technique was performed |
| Disposition | Benign positive: authorised test; detection, response and alerting worked as designed |
| Status | Closed 12:54:32 (#2), 12:57:53 (#3), 14:25:41 (#4) |

## 1. Detection logic

Defender Antivirus writes event **1116** to `Microsoft-Windows-Windows Defender/Operational` when it detects malware and event **1117** when it takes action. The DCR `dcr-soc-defender` sends only those two IDs to the `Event` table. The scheduled rule ([detections/defender-antivirus-malware-detection.kql](../detections/defender-antivirus-malware-detection.kql)) parses threat name, path, action and severity out of `EventData`. It summarises by host, threat and path and raises one High alert per row. It runs every 5 minutes over a 10-minute lookback and maps `Computer` to a Host entity.

## 2. Timeline (UTC, 2026-11-07)

| Time | Event | Source |
|---|---|---|
| ~12:2x | `dcr-soc-defender`, association and analytics rule created | Cloud Shell, stage 1 |
| 12:31:39 | Run 1: EICAR written, Defender 1116 + 1117 on the host; **never reached Sentinel** | Run Command output |
| 12:32–12:45 | `Event` table polled: 0 rows (agent had not loaded the new DCR yet) | `evidence/sentinel-defender-detection.md` |
| 12:44:56.460 | Run 2: EICAR written to `C:\soclab-eicar\eicar-test.txt` by `powershell.exe` (SYSTEM, via Run Command) | Run Command output |
| 12:44:56.503 | **1116** Malware detected (`Virus:DOS/EICAR_Test_File`) | `Event` |
| 12:45:06.668 | **1117** Action taken: Quarantine | `Event` |
| 12:45:16 | Script confirms the file is no longer on disk | Run Command output |
| 12:45:48 | 1117 ingested (42 s lag) | `ingestion_time()` |
| 12:48:10 | 1116 ingested (3 min 14 s lag) | `ingestion_time()` |
| 12:50:08 | Alert raised, query window 12:35:00–12:45:01 | `SecurityAlert` |
| 12:50:23 | **Incident #2 created** (5 min 27 s after detection) | Sentinel |
| 12:55:19 | Next rule run re-alerts on the same events → incident #3 | Sentinel |
| 12:54:32 / 12:57:53 | #2 closed as benign positive; #3 closed as duplicate | Sentinel API |
| 12:57:56 | Rule edited to enable grouping. Saving triggers an immediate run. | rule `lastModifiedUtc` |
| 12:58:15 | That run re-alerts event 1117 → **incident #4** (#2/#3 closed, reopen off, so a new incident) | Sentinel |
| 14:25:41 | #4 closed as duplicate | Sentinel API |

## 3. Investigation (NIST SP 800-61: detection & analysis)

- **Is it real malware?** No. The threat name is the EICAR test signature, and the file was written by the authorised lab script at the recorded time.
- **Was it contained?** Yes. Event 1117 shows `Quarantine`, and the script confirmed the file was gone 20 seconds after it was written. Nothing executed: EICAR is a text file and was never run.
- **How did it get there?** `powershell.exe` running as `NT AUTHORITY\SYSTEM`, origin "Local machine". That matches Azure Run Command. The only logon in the 12:30–13:00 window is a 4624 for SYSTEM; there were no interactive or network logons.
- **Is anything else affected?** In the last 7 days the workspace holds 2 Defender detection events, on 1 host, for 1 threat. No other host or threat.
- **Did the pipeline lose anything?** Yes, during setup. Run 1 at 12:31 was detected and quarantined on the host but never reached Sentinel, because the agent had not yet loaded the new DCR. Lesson: after adding a DCR, verify with a test event before relying on it.

## 4. Containment, eradication, recovery

Lab: nothing further needed. Defender quarantined the file automatically. The test folder `C:\soclab-eicar` holds no live file.

If the same alert fired with a real threat name, I would do the following:

1. **Contain.** Isolate the host. With Defender for Endpoint that is one click; without it, apply a deny-all NSG to the VM's NIC and keep Azure Run Command open for investigation.
2. **Scope.** Look for the same hash, path or threat on other hosts. Check what wrote the file, using the parent process and `SecurityEvent` 4688 if process auditing is on, and whether it ran. Look at logons on the host in the hours before.
3. **Eradicate.** Confirm the quarantine succeeded (`Get-MpThreatDetection`), run a full scan, and remove persistence (services, scheduled tasks, Run keys).
4. **Recover.** Rebuild from a known-good image if anything executed, and rotate credentials used on the host.
5. **Lessons learned.** Add the indicator to a watchlist and decide whether to block it at the email or web layer.

## 5. Post-incident: what I changed

- **Duplicate incident.** The 10-minute lookback overlaps the 5-minute schedule, so the second run picked up the same events and created incident #3. I kept the overlap, because 1116 arrived 3 minutes late and a 5-minute lookback could miss it. Instead I **enabled incident grouping** on the rule (match all entities, 5 h, don't reopen closed incidents), so repeat alerts for the same host join the open incident.
- **Editing a rule re-runs it.** Saving the grouping change made Sentinel run the rule straight away, and the same event raised a third incident (#4). Grouping didn't help because the earlier incidents were already closed and "reopen closed incidents" is off. Lesson: tune a rule before closing the incidents it raised, or expect one more alert.
- **Alert content.** The first alert only contained event 1116 (action "Not Applicable"), because 1117 landed after the window closed. The analyst still has to check the quarantine result in the incident timeline or on the host. Don't assume the alert shows the final state.
- **Coverage gap.** This rule sees only what Defender Antivirus logs locally. It has no process tree, no device timeline and no remote isolation. Those need Microsoft Defender for Endpoint (Plan 1/2), which this subscription does not include.
