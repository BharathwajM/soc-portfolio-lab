# Logon outcome check (run in law-soc-lab Logs, 2026-11-07)

```kusto
SecurityEvent
| where TimeGenerated between (datetime(2026-11-07 09:00:00) .. datetime(2026-11-07 10:30:00))
| where TargetUserName in~ ("soclab-probe", "soclab-control", "soclab-smoke")
| summarize Count = count(), First = min(TimeGenerated), Last = max(TimeGenerated)
    by EventID, Activity, TargetUserName, Computer
| order by EventID asc, TargetUserName asc
```

| EventID | Activity | TargetUserName | Computer | Count | First (UTC) |
|---|---|---|---|---|---|
| 4625 | An account failed to log on. | soclab-control | vm-soc-win | 1 | 09:17:25.239 |
| 4625 | An account failed to log on. | soclab-probe | vm-soc-win | 6 | 09:17:25.552 |
| 4625 | An account failed to log on. | soclab-smoke | vm-soc-win | 2 | 09:12:28.536 |

No 4624 (successful logon) rows exist for any lab account between 09:00 and 10:30 UTC.
