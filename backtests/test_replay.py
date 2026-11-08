"""Regression coverage for the password-spray replay's window boundaries."""
import unittest
from datetime import timedelta
from pathlib import Path

from replay import parse_time, read_events, replay

START = parse_time("2026-11-08T00:00:00Z")


class ReplayTests(unittest.TestCase):
    def test_synthetic_fixture_matches_expected_runs(self):
        end = START + timedelta(minutes=30)
        fixture = Path(__file__).with_name("synthetic-4625.csv")
        result = replay(read_events(fixture, START, end), START, end)

        self.assertEqual(result["scheduled_runs"], 5)
        self.assertEqual(result["matched_scheduled_runs"], 3)
        self.assertEqual(result["matching_run_ip_pairs"], 3)
        self.assertEqual(
            [(row["time_utc"], row["source_ip"]) for row in result["scheduled_matches"]],
            [
                ("2026-11-08T00:15:00Z", "192.0.2.10"),
                ("2026-11-08T00:20:00Z", "192.0.2.20"),
                ("2026-11-08T00:25:00Z", "192.0.2.20"),
            ],
        )
        self.assertEqual(
            [(row["time_utc"], row["source_ip"]) for row in result["fixed_bins"] if row["matched"]],
            [("2026-11-08T00:10:00Z", "192.0.2.20")],
        )

    def test_run_includes_lookback_start_and_excludes_run_time(self):
        events = [
            (START + timedelta(minutes=minute), "192.0.2.10", f"account-{index % 3}")
            for minute in (0, 5, 10)
            for index in range(5)
        ]
        end = START + timedelta(minutes=15)
        result = replay(events, START, end)

        self.assertEqual(result["scheduled_runs"], 2)
        self.assertEqual(
            [(row["time_utc"], row["failed_attempts"], row["distinct_accounts"])
             for row in result["scheduled_matches"]],
            [("2026-11-08T00:10:00Z", 10, 3), ("2026-11-08T00:15:00Z", 10, 3)],
        )


if __name__ == "__main__":
    unittest.main()
