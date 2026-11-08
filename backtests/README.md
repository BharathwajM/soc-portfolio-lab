# Password-spray backtest

The [Sentinel rule](../detections/password-spray-by-source-ip.kql) matches a source IP with at least ten failed logons against at least three distinct usernames. It runs every five minutes and looks back ten minutes.

## Historical honeypot

The [saved notes](../evidence/tuning-and-mde-setup.md) report **40 matching fixed bins out of 41 active bins** for the main source. [Fixed-bin KQL](password-spray-fixed-bins.kql) reconstructs that analysis from the documented rules and UTC bounds. The interval starts at 2026-11-07 00:00 inclusive and ends at 2026-11-08 00:30 exclusive. The lab preserved aggregate results and later deleted its workspace. This repository contains the historical summary and a separate synthetic event fixture.

## Scheduled replay

[Scheduled KQL](password-spray-scheduled.kql) uses the same UTC data bounds. It returns one row per matching run and IP. Runs start at 00:10 UTC so the first run has a complete ten-minute window. Each run uses `[run time − 10 minutes, run time)`. The replay models event timestamps and leaves ingestion latency, the Sentinel scheduling delay and incident state outside the model. See [Microsoft's scheduling and grouping documentation](https://learn.microsoft.com/en-us/azure/sentinel/scheduled-rules-overview).

Run the reproducible fixture locally with Python 3.9 or later.

```bash
python backtests/replay.py backtests/synthetic-4625.csv --start 2026-11-08T00:00:00Z --end 2026-11-08T00:30:00Z
```

| Synthetic source | Matching fixed bins | Matching scheduled runs | Explanation |
|---|---:|---:|---|
| 192.0.2.10 | 0 | 1 (00:15 UTC) | Ten attempts straddle the 00:10 fixed-bin boundary. |
| 192.0.2.20 | 1 | 2 (00:20 and 00:25 UTC) | The same burst is in two consecutive lookbacks. |
| 192.0.2.30 | 0 | 0 | Ten attempts target one username. |

The fixture yields **three matching run/IP pairs across five scheduled runs**. If the two source IPs start with no open incidents and grouping behaves as configured, those pairs project **two incident groups** within the 24-hour grouping window. The replay counts query matches. Sentinel creates and manages incidents separately.

The regression tests check the exact fixture match times and the window boundaries.

~~~bash
python -m unittest discover -s backtests -v
~~~

For a replay using your own lab export, provide a CSV with `TimeGenerated`, `EventID`, `IpAddress`, and `TargetUserName`. Use ISO 8601 timestamps with an explicit offset, and choose five-minute UTC boundaries matching the complete event coverage. The first complete scheduled window starts ten minutes after the lower bound. Compare the local output with the two KQL queries in a workspace that contains the same events.
