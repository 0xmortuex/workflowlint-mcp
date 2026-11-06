"""The cron implementation against 40 expressions with exact next-run lists, plus edge cases and errors."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from cron_table import TABLE

from workflowlint_mcp.cron import (
    CronError,
    congestion_notes,
    explain_cron,
    format_time,
    next_runs,
    parse_cron,
)


def utc(s: str) -> datetime:
    return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)


def test_table_has_forty_rows():
    assert len(TABLE) == 40


@pytest.mark.parametrize("expr,ref,expected", TABLE, ids=[f"{r[0]} @{r[1]}" for r in TABLE])
def test_next_runs_exact(expr, ref, expected):
    got = [t.strftime("%Y-%m-%dT%H:%M") for t in next_runs(parse_cron(expr), utc(ref), 5)]
    assert got == expected


def test_hand_checked_calendar_facts():
    # Feb 2026 has 28 days: the next leap day is 2028-02-29, a Tuesday.
    runs = next_runs(parse_cron("0 0 29 2 *"), utc("2026-02-26T13:20:00"), 1)
    assert format_time(runs[0]) == "Tue 2028-02-29 00:00 UTC"
    # The OR rule: the 13th OR any Friday (2026-02-27 is a Friday).
    runs = next_runs(parse_cron("0 0 13 * 5"), utc("2026-02-26T13:20:00"), 2)
    assert [format_time(r) for r in runs] == ["Fri 2026-02-27 00:00 UTC", "Fri 2026-03-06 00:00 UTC"]
    # A starred field makes it AND: Mondays that are also day 1,4,7,...
    runs = next_runs(parse_cron("0 0 */3 * 1"), utc("2026-02-26T13:20:00"), 1)
    assert runs[0].day in (1, 4, 7, 10, 13, 16, 19, 22, 25, 28, 31) and runs[0].weekday() == 0


def test_strictly_after_and_seconds_ignored():
    assert next_runs(parse_cron("*/10 * * * *"), utc("2026-03-01T00:10:00"), 1)[0] == utc("2026-03-01T00:20:00")
    assert next_runs(parse_cron("*/10 * * * *"), utc("2026-03-01T00:09:59"), 1)[0] == utc("2026-03-01T00:10:00")


def test_never_matching_returns_empty():
    assert next_runs(parse_cron("0 0 31 2 *"), utc("2026-01-01T00:00:00")) == []


def test_sunday_zero_and_seven_agree():
    a = next_runs(parse_cron("0 0 * * 0"), utc("2026-01-01T00:00:00"), 3)
    b = next_runs(parse_cron("0 0 * * 7"), utc("2026-01-01T00:00:00"), 3)
    c = next_runs(parse_cron("0 0 * * SUN"), utc("2026-01-01T00:00:00"), 3)
    assert a == b == c


@pytest.mark.parametrize("bad,fragment", [
    ("* * * *", "expected 5 fields"),
    ("* * * * * *", "expected 5 fields"),
    ("60 * * * *", "outside 0-59"),
    ("* 24 * * *", "outside 0-23"),
    ("* * 0 * *", "outside 1-31"),
    ("* * * 13 *", "outside 1-12"),
    ("* * * * 8", "outside 0-7"),
    ("@daily", "macros"),
    ("*/0 * * * *", "step must be at least 1"),
    ("*/x * * * *", "not a positive number"),
    ("5-1 * * * *", "backwards"),
    ("* * * FOO *", "unknown name"),
    ("* * * * ?", "not a number"),
    ("1,,2 * * * *", "empty item"),
    ("L * * * *", "not a number"),
    ("", "expected 5 fields"),
    ("x" * 500, "too long"),
])
def test_parse_errors_are_specific(bad, fragment):
    with pytest.raises(CronError, match=fragment):
        parse_cron(bad)


def test_explanations_read_like_english():
    assert explain_cron(parse_cron("17 3 * * *")) == "At 03:17, every day (UTC)"
    assert explain_cron(parse_cron("*/15 * * * *")).startswith("Every 15 minutes")
    assert "Monday through Friday" in explain_cron(parse_cron("0 9 * * 1-5"))
    assert "OR" in explain_cron(parse_cron("0 0 13 * 5"))
    assert "February" in explain_cron(parse_cron("0 0 1 2 *"))


def test_congestion_notes():
    ref = utc("2026-02-26T13:20:00")
    assert any("Minute 0" in n for n in congestion_notes(parse_cron("0 * * * *"), ref))
    assert any("5 minutes" in n for n in congestion_notes(parse_cron("*/2 * * * *"), ref))
    assert congestion_notes(parse_cron("17 3 * * 1"), ref) == []
