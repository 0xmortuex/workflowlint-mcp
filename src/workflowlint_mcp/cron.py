"""A small POSIX/vixie-style cron implementation for GitHub's `schedule:` (always UTC).

Supported per field: `*`, `*/n`, `a`, `a-b`, `a-b/n`, `a/n` (a through the field maximum), and comma lists of
those; month and weekday names (JAN-DEC, SUN-SAT, any case). Not supported (GitHub rejects them too):
`@daily`-style macros, `?`, `L`, `W`, `#`.

Day matching follows vixie cron: when both day-of-month and day-of-week are restricted (neither field
starts with `*`) a day matches if EITHER matches; otherwise both must match.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone

MONTHS = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"]
DAYS = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"]
MONTH_NAMES = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October",
               "November", "December"]
DAY_NAMES = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]

MAX_TEXT = 200
SEARCH_YEARS = 8


class CronError(ValueError):
    pass


@dataclass(frozen=True)
class Cron:
    text: str
    fields: tuple[str, str, str, str, str]
    minutes: frozenset[int]
    hours: frozenset[int]
    doms: frozenset[int]
    months: frozenset[int]
    dows: frozenset[int]  # 0 = Sunday
    dom_star: bool
    dow_star: bool


_SPECS = (
    ("minute", 0, 59, None),
    ("hour", 0, 23, None),
    ("day-of-month", 1, 31, None),
    ("month", 1, 12, MONTHS),
    ("day-of-week", 0, 7, DAYS),
)


def _value(tok: str, name: str, lo: int, hi: int, names: list[str] | None, offset: int) -> int:
    if names is not None and tok.isalpha():
        up = tok.upper()
        if up not in names:
            raise CronError(f"{name}: unknown name {tok!r} (use {', '.join(names)})")
        return names.index(up) + offset
    if not tok.isdigit():
        raise CronError(f"{name}: {tok!r} is not a number" + (" or name" if names else ""))
    v = int(tok)
    if v < lo or v > hi:
        raise CronError(f"{name}: {v} is outside {lo}-{hi}")
    return v


def _field(text: str, idx: int) -> frozenset[int]:
    name, lo, hi, names = _SPECS[idx]
    offset = 1 if name == "month" else 0
    out: set[int] = set()
    if not text:
        raise CronError(f"{name}: empty field")
    for item in text.split(","):
        if not item:
            raise CronError(f"{name}: empty item in list {text!r}")
        base, _, step_s = item.partition("/")
        if "/" in item and not step_s.isdigit():
            raise CronError(f"{name}: step {step_s!r} is not a positive number")
        step = int(step_s) if step_s else 1
        if step < 1:
            raise CronError(f"{name}: step must be at least 1")
        if base == "*":
            a, b = lo, hi
            if name == "day-of-week":
                b = 6
        elif "-" in base:
            left, _, right = base.partition("-")
            a = _value(left, name, lo, hi, names, offset)
            b = _value(right, name, lo, hi, names, offset)
            if a > b:
                raise CronError(f"{name}: range {base!r} runs backwards")
        else:
            a = _value(base, name, lo, hi, names, offset)
            b = hi if step_s else a
        for v in range(a, b + 1, step):
            out.add(v)
    if name == "day-of-week" and 7 in out:
        out.discard(7)
        out.add(0)
    return frozenset(out)


def parse_cron(text: str) -> Cron:
    if len(text) > MAX_TEXT:
        raise CronError("cron expression is far too long")
    stripped = text.strip()
    if stripped.startswith("@"):
        raise CronError("macros like @daily are not supported by GitHub; write the five fields")
    parts = stripped.split()
    if len(parts) != 5:
        raise CronError(f"expected 5 fields (minute hour day-of-month month day-of-week), got {len(parts)}")
    sets = [_field(p, i) for i, p in enumerate(parts)]
    return Cron(
        stripped, (parts[0], parts[1], parts[2], parts[3], parts[4]),
        sets[0], sets[1], sets[2], sets[3], sets[4],
        parts[2].startswith("*"), parts[4].startswith("*"),
    )


def _day_matches(c: Cron, d: date) -> bool:
    if d.month not in c.months:
        return False
    dom = d.day in c.doms
    dow = (d.weekday() + 1) % 7 in c.dows
    if c.dom_star or c.dow_star:
        return dom and dow
    return dom or dow


def next_runs(c: Cron, after: datetime, count: int = 5) -> list[datetime]:
    """The next `count` run times strictly after `after` (UTC). May return fewer for dates that never
    occur (0 0 31 2 *)."""
    if after.tzinfo is None:
        after = after.replace(tzinfo=timezone.utc)
    after = after.astimezone(timezone.utc)
    start = after.replace(second=0, microsecond=0)
    out: list[datetime] = []
    day = start.date()
    hours = sorted(c.hours)
    minutes = sorted(c.minutes)
    for _ in range(SEARCH_YEARS * 366):
        if _day_matches(c, day):
            for h in hours:
                for m in minutes:
                    t = datetime(day.year, day.month, day.day, h, m, tzinfo=timezone.utc)
                    if t > after:
                        out.append(t)
                        if len(out) >= count:
                            return out
        day += timedelta(days=1)
    return out


def format_time(t: datetime) -> str:
    return f"{DAY_NAMES[(t.weekday() + 1) % 7][:3]} {t:%Y-%m-%d %H:%M} UTC"


# ---------------------------------------------------------------------------------------------------------
# Plain English


def _runs(values: list[int], label: object) -> str:
    """[1,2,3,5] -> "1 through 3, 5" with a label function applied to each end."""
    f = label if callable(label) else str
    parts = []
    i = 0
    while i < len(values):
        j = i
        while j + 1 < len(values) and values[j + 1] == values[j] + 1:
            j += 1
        if j - i >= 2:
            parts.append(f"{f(values[i])} through {f(values[j])}")
        else:
            parts.extend(f(v) for v in values[i:j + 1])
        i = j + 1
    return ", ".join(parts[:-1]) + " and " + parts[-1] if len(parts) > 1 else parts[0]


def _step_of(text: str) -> int | None:
    if "," not in text and "/" in text:
        s = text.split("/", 1)[1]
        return int(s) if s.isdigit() else None
    return None


def explain_cron(c: Cron) -> str:
    mi, ho, dm, mo, dw = c.fields
    mins, hrs = sorted(c.minutes), sorted(c.hours)
    if mi == "*" and ho == "*":
        when = "every minute"
    elif _step_of(mi) and ho == "*" and mi.startswith("*"):
        when = f"every {_step_of(mi)} minutes"
    elif _step_of(mi) and mi.startswith("*") and ho != "*":
        when = f"every {_step_of(mi)} minutes during hour {_runs(hrs, lambda h: f'{h:02d}:00')}"
    elif len(mins) == 1 and len(hrs) == 1:
        when = f"at {hrs[0]:02d}:{mins[0]:02d}"
    elif len(mins) == 1 and ho == "*":
        when = f"at minute {mins[0]} of every hour"
    elif mi == "*":
        when = f"every minute during hour {_runs(hrs, lambda h: f'{h:02d}:00')}"
    elif len(mins) == 1:
        when = f"at minute {mins[0]} of hour {_runs(hrs, str)}"
    elif len(hrs) == 1:
        when = f"at {_runs(mins, lambda m: f'{hrs[0]:02d}:{m:02d}')}"
    elif ho == "*":
        when = f"at minutes {_runs(mins, str)} of every hour"
    else:
        when = f"at minutes {_runs(mins, str)} of hours {_runs(hrs, str)}"
    if _step_of(ho) and len(mins) == 1 and ho.startswith("*"):
        when = f"at minute {mins[0]} of every {_step_of(ho)} hours"

    dom_txt: str | None
    if dm == "*":
        dom_txt = None
    elif c.dom_star:
        dom_txt = f"every {_step_of(dm)} days of the month"
    else:
        dom_txt = f"day-of-month {_runs(sorted(c.doms), str)}"
    dow_txt: str | None
    if dw == "*":
        dow_txt = None
    elif c.dow_star:
        dow_txt = f"every {_step_of(dw)} days of the week"
    else:
        dow_txt = _runs(sorted(c.dows), lambda d: DAY_NAMES[d])
    if dom_txt and dow_txt:
        if c.dom_star or c.dow_star:
            day = f"on {dom_txt} and on {dow_txt}"
        else:
            day = f"on {dom_txt} OR on {dow_txt} (cron runs when either matches)"
    elif dom_txt:
        day = f"on {dom_txt}"
    elif dow_txt:
        day = f"on {dow_txt}"
    else:
        day = "every day"
    month = "" if mo == "*" else f", only in {_runs(sorted(c.months), lambda m: MONTH_NAMES[m - 1])}"
    return f"{when[0].upper()}{when[1:]}, {day}{month} (UTC)"


def congestion_notes(c: Cron, after: datetime) -> list[str]:
    notes = []
    if c.minutes == frozenset({0}):
        notes.append(
            "Minute 0 is the busiest moment on GitHub's scheduler; runs queued then are often delayed by "
            "10-30 minutes or dropped under load. Pick an off-peak minute such as 17 or 43."
        )
    runs = next_runs(c, after, 12)
    if len(runs) >= 2 and min((b - a).total_seconds() for a, b in zip(runs, runs[1:], strict=False)) < 300:
        notes.append("Runs closer than 5 minutes apart: GitHub's shortest supported schedule interval is "
                     "5 minutes, so some will be skipped.")
    return notes
