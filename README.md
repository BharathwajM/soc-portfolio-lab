# SOC Portfolio Lab

A hands-on SOC lab in two parts. In Azure, I built Microsoft Sentinel detections, tested them with simulated attacks and EICAR, and ran an internet-facing RDP honeypot for 12 hours. Locally, I ran an OpenVAS scan, fixed what it found, and rescanned to prove the fix.

## Results at a glance

| Case | What happened | Write-up |
|---|---|---|
| Failed sign-in detection | Six simulated failures raised an incident. A single-failure negative control did not. | [INC-0001](reports/INC-0001-repeated-signin-failures.md) |
| Malware detection | Defender quarantined EICAR in 10 s, and Sentinel opened a High incident 5.5 min later. | [INC-0003](reports/INC-0003-defender-eicar-detection.md) |
| Internet RDP honeypot | 4,473 failed logons from 2 IPs by the 23:45 UTC data cut. No logon succeeded. | [INC-0002](reports/INC-0002-honeypot-rdp-bruteforce.md) |
| Defender for Endpoint | Microsoft's detection test raised 5 alerts, which Sentinel merged into one incident. | [Evidence](evidence/tuning-and-mde-setup.md) |
| OpenVAS scan, fix, rescan | High findings went from 4 to 0 and medium from 9 to 0. | [VULN-0001](reports/VULN-0001-apache-remediation.md) |

**Skills shown:** Microsoft Sentinel, KQL detection rules, Azure Monitor Agent and data collection rules, Defender Antivirus and Defender for Endpoint, incident triage and NIST SP 800-61 reporting, MITRE ATT&CK mapping, detection tuning and backtesting, OpenVAS vulnerability management.

## 1. Detecting repeated failed sign-ins

A scheduled KQL rule ([detection](detections/repeated-windows-signin-failures.kql)) raises an incident when one account fails to log on 5 or more times on one host within 10 minutes (MITRE ATT&CK T1110, Brute Force).

**Result:** Incident #1 fired for `soclab-probe` (6 failures in about 1.6 s). The `soclab-control` negative control, with one failure, did not raise an alert. Both usernames are fictitious, and the script checks that neither exists before testing.

<details>
<summary>How I built and tested it</summary>

1. Created `rg-soc-lab` in Azure for Students and the `law-soc-lab` Log Analytics workspace in Japan East.
2. Enabled Microsoft Sentinel on `law-soc-lab` and installed the Windows Security Events solution to get the **Windows Security Events via AMA** connector.
3. Deployed a small Windows Server 2022 VM, `vm-soc-win`, with a system-assigned identity and Trusted Launch. Its network security group has no custom inbound allow rules, and guest commands ran through Azure Run Command.
4. Installed Azure Monitor Agent and associated `dcr-soc-signins`, which sends logon successes (4624) and failures (4625) to the `SecurityEvent` table.
5. Ran [the simulation script](scripts/Simulate-SigninFailures.ps1) in `Smoke` mode to confirm events arrived before deploying the rule.
6. Deployed the KQL as a scheduled rule (every 5 minutes, 10-minute lookback, threshold 5 per account and host, mapped to Credential Access / T1110).
7. Ran the simulation in `Full` mode, then investigated the incident: compared the test with the control, checked for any successful 4624 for the same account, and recorded the timeline, evidence and disposition.

To rebuild today, connect the Sentinel workspace to the Microsoft Defender portal. Microsoft ends Sentinel support in the Azure portal on **31 March 2027**. [Defender portal onboarding](https://learn.microsoft.com/en-us/microsoft-365/security/defender/microsoft-sentinel-onboard) · [Portal support timeline](https://learn.microsoft.com/en-us/azure/sentinel/microsoft-sentinel-defender-portal)

</details>

## 2. Bringing malware detections into Sentinel

The VM runs Microsoft Defender Antivirus. A data collection rule ([`defender-dcr.json`](detections/defender-dcr.json)) forwards only its detection events, 1116 (malware detected) and 1117 (action taken), to Sentinel. A High-severity rule ([KQL](detections/defender-antivirus-malware-detection.kql), [full definition](detections/defender-analytics-rule.json)) maps the Host entity and shows the threat, file path and action taken.

**Result:** Defender quarantined the EICAR test file within 10 s, and Incident #2 (High) opened 5 min 27 s after the detection. Two things went wrong along the way, and both are written up:

- My first test, run right after the DCR was created, never reached Sentinel because the agent had not loaded the rule yet. I now wait 5 to 10 minutes after associating a DCR.
- The overlapping lookback created a duplicate incident (#3), so I enabled incident grouping. Saving that change re-ran the rule and raised one more duplicate (#4).

Evidence: [sentinel-defender-detection.md](evidence/sentinel-defender-detection.md). The test script is [Invoke-EicarTest.ps1](scripts/Invoke-EicarTest.ps1).

## 3. Internet RDP honeypot

I deployed a second Windows Server 2022 VM, `vm-honeypot`, in its own resource group with RDP (3389) open to the internet. It used a non-default admin name, a long password and Network Level Authentication (NLA). Besides logon events, a second DCR collected RDP connection events (RdpCoreTS 131 and 140, TerminalServices 1149), so scanners that never sent a password were still visible. I left it exposed for 12 hours.

**Result:**

- Scanners found the port within 12 minutes. Password guessing started about 6 hours later.
- By the 23:45 UTC data cut there were **4,473 failed logons**: 4,471 from one German hosting IP and 2 from South Korea. 21 IPs connected in total.
- Attackers tried 11 generic usernames (Administrator, Admin, server, user and others) at about 12 per minute.
- **No logon succeeded.** The real admin name was never tried, and every attempt failed at NLA.
- The sign-in rule raised 14 incidents for one continuous attack. I closed 13 as true positives at 00:19 UTC, right after deleting the honeypot, but the attack's last minutes raised #18 at 00:22. It sat as "New" until my final review at about 04:15 UTC (visible in the incident list below). Lesson: check the queue again after closing a batch while a rule is still running.

Evidence: [honeypot-final-2347Z.md](evidence/honeypot-final-2347Z.md). Write-up: [INC-0002](reports/INC-0002-honeypot-rdp-bruteforce.md), which also covers the final count of 4,859 failures from the main IP over the whole exposure.

![Sentinel Logs: the two source IPs through 23:45 UTC](images/screenshots/honeypot-attackers-kql.png)

![Failed RDP logons per hour on the honeypot](images/honeypot-hourly.png)

![Usernames the attackers tried](images/honeypot-usernames.png)

### Tuning after the honeypot

- **New rule for password spraying** ([KQL](detections/password-spray-by-source-ip.kql), [definition](detections/password-spray-analytics-rule.json)): one IP with 10+ failures against 3+ accounts in 10 minutes, grouped by IP. Replayed against the honeypot data, it matched 40 of 41 active ten-minute windows for the main IP and would have raised one incident instead of 14. The [replay guide](backtests/README.md) has the KQL and a synthetic run on the real five-minute schedule, and two [regression tests](backtests/test_replay.py) check the window boundaries.
- **Existing sign-in rule:** incident grouping turned on (by Host, 24 h).
- **Defender for Endpoint:** enabled through Defender for Servers Plan 1 (30-day trial). I reran EICAR and [Microsoft's MDE detection test](scripts/Invoke-MdeDetectionTest.ps1). MDE raised 5 alerts, from the EICAR block to "Suspicious PowerShell command line" to "Azure RunScript used to deploy malicious code", which flagged my own Run Command delivery. Sentinel merged them into one incident (#19) about a minute later. Both test incidents were closed as benign positives, then the plan was set back to Free. Details: [tuning-and-mde-setup.md](evidence/tuning-and-mde-setup.md).

![Sentinel Logs: the 5 Defender for Endpoint alerts behind incident #19](images/screenshots/incident-19-mde-alerts.png)

![Sentinel Logs: the incident list, with 20 total and 18 visible](images/screenshots/sentinel-incidents.png)

Screenshots were taken on 2026-11-08 from Sentinel Logs just before teardown. Microsoft has moved Sentinel's Incidents page to the Defender portal, so the incident list is shown through the `SecurityIncident` table. The account name in the portal header is blanked.

## 4. OpenVAS: scan, fix, rescan

I ran Greenbone Community Edition (OpenVAS) in containers inside a dedicated WSL environment. The target was an intentionally outdated Apache 2.4.49 container on an internal Docker network with no host ports exposed. I scanned it, upgraded Apache, rescanned, fixed the remaining configuration finding (`TraceEnable Off`), and scanned a third time with the same target and settings.

**Result:**

| Scan | Apache | High | Medium | Low | Total |
|---|---|---|---|---|---|
| Baseline | 2.4.49 | 4 | 9 | 3 | 28 |
| Patched | 2.4.69 | 0 | 1 (TRACE) | 2 | 15 |
| Hardened | 2.4.69 + `TraceEnable Off` | 0 | 0 | 2 | 14 |

![OpenVAS findings before and after the fix](images/openvas-before-after.png)

The upgrade cleared all 13 Apache version findings (18 CVEs, top CVSS 8.2), and the config change cleared TRACE. CVE-2021-41773 and CVE-2021-42013 were not reported, because the default `Require all denied` root config blocks the active check. An empty result for a well-known CVE does not mean the version is safe. Write-up: [VULN-0001](reports/VULN-0001-apache-remediation.md).

<details>
<summary>How to run it</summary>

Run each phase as root inside the `SOC-OpenVAS` WSL distro with [scripts/run-openvas.sh](scripts/run-openvas.sh) `baseline | patched | hardened`. The wrapper recreates the target and checks that the scanner can reach `172.31.250.10:80` before scanning. WSL shuts the distro down when idle, which stops the target. Without that check, a scan can come back nearly empty and look clean, which is what happened on my first baseline attempt.

</details>

## Teardown

Everything was deleted on 2026-11-08 so the lab costs nothing: the Azure resource groups (workspace, Sentinel, DCRs, VMs) and the `SOC-OpenVAS` WSL environment (about 54 GB). The KQL, rule definitions, DCRs, scripts, evidence and reports in this repo are enough to rebuild it.

## References

- [Microsoft Sentinel Windows event connector](https://learn.microsoft.com/en-us/azure/sentinel/connect-services-windows-based)
- [Windows failed logon event 4625](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625)
- [MITRE ATT&CK T1110 Brute Force](https://attack.mitre.org/techniques/T1110/)
- [Microsoft Defender Antivirus event IDs (1116, 1117)](https://learn.microsoft.com/defender-endpoint/troubleshoot-microsoft-defender-antivirus)
- [EICAR anti-malware test file](https://www.eicar.org/download-anti-malware-testfile/)
- [NIST incident response guidance](https://csrc.nist.gov/projects/incident-response)
- [Greenbone Community Containers](https://greenbone.github.io/docs/latest/22.4/container/)
- [Apache HTTP Server 2.4 security advisories](https://httpd.apache.org/security/vulnerabilities_24.html)

---

*Part of my security portfolio. See also: [AD attack & detection lab (Splunk)](https://github.com/BharathwajM/ad-attack-detection-lab) · [Phishing triage tool (Python)](https://github.com/BharathwajM/phishing-triage-automation) · [Essential Eight hardening lab (PowerShell)](https://github.com/BharathwajM/essential-eight-lab).*
