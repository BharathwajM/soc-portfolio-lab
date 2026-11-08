"""Replay the password-spray rule from an exported SecurityEvent CSV."""
import argparse
import csv
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

STEP = timedelta(minutes=5)
LOOKBACK = timedelta(minutes=10)
FIELDS = {"TimeGenerated", "EventID", "IpAddress", "TargetUserName"}
EXCLUDED_IPS = {"", "-", "127.0.0.1", "::1"}


def parse_time(value):
    iso_time = value[:-1] + "+00:00" if value.endswith("Z") else value
    stamp = datetime.fromisoformat(iso_time)
    if stamp.tzinfo is None:
        raise ValueError("timestamps require a UTC offset or Z")
    return stamp.astimezone(timezone.utc)


def read_events(path, start, end):
    with path.open(encoding="utf-8-sig", newline="") as stream:
        rows = csv.DictReader(stream)
        if not FIELDS.issubset(rows.fieldnames or ()):
            raise ValueError("CSV needs TimeGenerated, EventID, IpAddress and TargetUserName")
        for row in rows:
            if any(row[field] is None for field in FIELDS):
                raise ValueError(f"incomplete CSV row {rows.line_num}")
            if row["EventID"] == "4625" and row["IpAddress"] not in EXCLUDED_IPS:
                stamp = parse_time(row["TimeGenerated"])
                if start <= stamp < end:
                    yield stamp, row["IpAddress"], row["TargetUserName"]


def summarize(buckets):
    results = []
    for (stamp, ip), accounts in sorted(buckets.items()):
        distinct = len(set(accounts))
        results.append({
            "time_utc": stamp.isoformat().replace("+00:00", "Z"),
            "source_ip": ip,
            "failed_attempts": len(accounts),
            "distinct_accounts": distinct,
            "matched": len(accounts) >= 10 and distinct >= 3,
        })
    return results


def replay(events, start, end):
    fixed = defaultdict(list)
    rolling = defaultdict(list)
    for stamp, ip, account in events:
        fixed_start = start + ((stamp - start) // LOOKBACK) * LOOKBACK
        fixed[fixed_start, ip].append(account)

        five_minute_start = start + ((stamp - start) // STEP) * STEP
        for run in (five_minute_start + STEP, five_minute_start + LOOKBACK):
            if start + LOOKBACK <= run <= end:
                rolling[run, ip].append(account)

    fixed_rows = summarize(fixed)
    scheduled_matches = [row for row in summarize(rolling) if row["matched"]]
    return {
        "fixed_bins": fixed_rows,
        "scheduled_runs": (end - start - LOOKBACK) // STEP + 1,
        "matched_scheduled_runs": len({row["time_utc"] for row in scheduled_matches}),
        "matching_run_ip_pairs": len(scheduled_matches),
        "matching_source_ips": sorted({row["source_ip"] for row in scheduled_matches}),
        "scheduled_matches": scheduled_matches,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", type=Path, help="exported SecurityEvent CSV")
    parser.add_argument("--start", type=parse_time, required=True)
    parser.add_argument("--end", type=parse_time, required=True)
    args = parser.parse_args()
    if any(t.minute % 5 or t.second or t.microsecond for t in (args.start, args.end)):
        parser.error("start and end must fall on five-minute UTC boundaries")
    if args.end - args.start < LOOKBACK:
        parser.error("the replay needs at least ten minutes of event coverage")
    try:
        result = replay(read_events(args.csv, args.start, args.end), args.start, args.end)
    except (OSError, ValueError, csv.Error) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
