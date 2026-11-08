# Post-honeypot tuning and Defender for Endpoint setup (2026-11-08, UTC)

## 1. Alert-flood fix: INC-0002 lessons applied

### New rule: password spray from one source IP

| Item | Value |
|---|---|
| Rule | `SOC Lab - Password Spray from One Source IP` (`5f1a7c2e-9b3d-4e8a-b6c4-2d7e0f9a1b35`) |
| Logic | [detections/password-spray-by-source-ip.kql](../detections/password-spray-by-source-ip.kql): one IP with 10+ failed logons against 3+ distinct accounts in 10 min |
| Schedule | Every 5 min over 10 min, Medium, Credential Access / T1110 |
| Entities | IP (`IpAddress`), Host (`Computer`); custom details FailedAttempts, DistinctAccounts |
| Incident grouping | On, by **IP** entity, 24 h lookback, don't reopen closed incidents. One attacker gives one incident with many alerts. |
| Full definition | [detections/password-spray-analytics-rule.json](../detections/password-spray-analytics-rule.json) |

### Backtest against the real honeypot data (10-minute windows, 2026-11-07 00:00 → 11-08 00:30)

| Source | 10-min windows active | Windows where the rule fires | First fire | Max failures / accounts in a window |
|---|---|---|---|---|
| 78.46.176.17 (attacker) | 41 | **40** | 17:40 window | 133 / 10 |
| 175.203.62.5 (2 attempts) | 1 | 0 | none | 2 / 1 |
| vm-soc-win (9 simulated local failures, no source IP) | n/a | 0 | none (filtered: `IpAddress` is "-") | n/a |

With IP grouping, the 40 alerts would form **1 incident**. The live sign-in rule created 14, including #18 after the initial batch was closed.

### Existing rule tuned: repeated sign-in failures

`SOC Lab - Repeated Windows Sign-in Failures` (`a82b3a31-…`): entities are still Host + Account, and suppression is still 30 min. **Incident grouping is now on**, by Host, over a 24 h lookback, without reopening closed incidents. Repeat alerts for the same machine now join one open incident.

Saving the rule triggers an immediate run. The honeypot was already deleted and no failures were arriving, so no new incident was created (contrast INC-0003, #4).

## 2. Microsoft Defender for Endpoint (via Defender for Servers Plan 1)

| Step | Result |
|---|---|
| `Microsoft.Security` resource provider | Was **not registered** on the subscription; registered 2026-11-08 ~00:55 |
| Defender for Servers (`VirtualMachines` pricing) | `Free` → **`Standard` / `P1`**, enabled 00:59:50 UTC, **30-day free trial** (`P30D`) → ends **~2026-12-08** |
| MDE integration (`settings/WDATP`) | Enabled |
| Sentinel data connector | Microsoft Defender for Cloud (`AzureSecurityCenter`), alerts Enabled → `SecurityAlert` table |
| Sentinel incident rule | `SOC Lab - Incidents from Defender for Cloud (incl. Defender for Endpoint) alerts` (Microsoft Security, product filter "Azure Security Center") |
| MDE agent on `vm-soc-win` | `MDE.Windows` extension **Succeeded**, deployed automatically by Defender for Cloud within ~1.5 h. At 02:35: `Sense` service Running, `OnboardingState` 1, Defender Antivirus `AMRunningMode` Normal, real-time protection on. |

## 3. Defender for Endpoint validation (2026-11-08, UTC)

Two tests ran on `vm-soc-win` through Azure Run Command:

1. [scripts/Invoke-EicarTest.ps1](../scripts/Invoke-EicarTest.ps1). The EICAR file was written at 02:36:45 and quarantined at once: `Virus:DOS/EICAR_Test_File`, action success True, file gone from disk. Events 1116 (02:36:45) and 1117 (02:36:59) were logged.
2. [scripts/Invoke-MdeDetectionTest.ps1](../scripts/Invoke-MdeDetectionTest.ps1), Microsoft's documented MDE detection test, started at 02:37:40. A hidden PowerShell tries to download `invoice.exe` from 127.0.0.1. Nothing downloaded (`invoice.exe` exists: False).

### What came back

| Time (alert) | Severity | Alert | Source |
|---|---|---|---|
| ~02:37 | Informational | 'EICAR_Test_File' malware was prevented | Defender for Endpoint |
| ~02:38 | Medium | Suspicious PowerShell command line | Defender for Endpoint |
| ~02:40 | Medium | Suspicious RunCommandExtension.exe behavior detected | Defender for Endpoint |
| ~02:40 | Medium | Suspicious activity through Azure VM extension process | Defender for Endpoint |
| ~02:42 | Medium | Azure RunScript used to deploy malicious code | Defender for Endpoint |
| 02:41 | High | SOC Lab - Defender Antivirus Malware Detection (my KQL rule on events 1116/1117) | Sentinel scheduled rule |

- **Sentinel incident #19** (Medium): "Multi-stage incident involving Execution & Lateral movement on one endpoint". It holds all 5 Defender for Endpoint alerts and was created at 02:37:55, about 1 minute after the EICAR file was written. The alerts reached Sentinel `SecurityAlert` through the Defender for Cloud connector.
- **Sentinel incident #20** (High): from my own Defender Antivirus rule, the same pipeline as INC-0003.
- **Closed** #19 and #20 as Benign Positive / Suspicious but expected (planned tests).

**What this shows.** Defender Antivirus only saw the EICAR file. Defender for Endpoint also flagged the *behaviour*: a hidden PowerShell download, and the fact that the scripts arrived through the Azure Run Command extension. It mapped that delivery path to "lateral movement", because an attacker with Azure rights could push code the same way. In a real SOC, the next step would be to check who ran the Run Command (Azure Activity log) before closing.

## 4. Shutdown (2026-11-08 ~02:47 UTC)

- Defender for Servers (`VirtualMachines` pricing) set back to **Free**, ending the trial early, so nothing will bill after 2026-12-08.
- `vm-soc-win` **deallocated** (no compute charges). The workspace, rules, DCRs and logs stay in `rg-soc-lab`.

## 5. Final review and teardown (2026-11-08 ~04:15–04:24 UTC)

- Portal screenshots taken from Sentinel → Logs ([images/screenshots/](../images/screenshots/)). The Azure portal's Sentinel Incidents and Analytics pages now say "This page was moved to Defender portal", so incidents were listed from the `SecurityIncident` table.
- The incident list showed **#18 still "New"**: a 14th honeypot incident raised at 00:22:28, three minutes after #5–#17 were closed. See the INC-0002 timeline and lessons.
- `az group delete -n rg-soc-lab --yes` started 04:20:13 UTC. It removed 12 resources: `law-soc-lab` with the SecurityInsights solution, `dcr-soc-signins`, `dcr-soc-defender`, `vm-soc-win` and its `AzureMonitorWindowsAgent` and `MDE.Windows` extensions, `os-soc-lab`, `vm-soc-winVMNic`, `pip-soc-lab`, `vnet-soc-lab` and `nsg-soc-lab`. There were no resource locks. It finished at 04:23:16 (exit 0), and `az group exists -n rg-soc-lab` returns `false`. The only group left in the subscription is Azure's automatic `NetworkWatcherRG` (free).
