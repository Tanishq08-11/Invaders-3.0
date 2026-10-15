"""
Timestamp normalisation
========================
`parse_timestamp(value)` turns a supplied event timestamp into an aware UTC datetime.

Accepted inputs
  • int / float / numeric string — Unix epoch. Values in [MIN_SECONDS, MAX_SECONDS] are
    seconds. Values in [MIN_SECONDS*1000, MAX_SECONDS*1000] are milliseconds — the two
    ranges do not overlap, so the unit is identified reliably (no guessing in between).
  • ISO-8601 strings ("2026-10-15T10:00:00Z", "+05:30" offsets, "2026-10-15 10:00:00").
    A string without an offset is interpreted as UTC (documented policy).
  • datetime — aware values are converted to UTC; naive values are taken as UTC.

Missing values (None, "", 0) are reported as `missing` so the caller can fall back to the
receive time *and say so*. Anything else that cannot be parsed is `invalid` — it is never
silently replaced by the current time.
"""
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

# 2000-01-01 .. 2100-01-01 in seconds; the millisecond range is the same span ×1000.
MIN_SECONDS = 946_684_800
MAX_SECONDS = 4_102_444_800


@dataclass
class ParsedTime:
    value: Optional[datetime]       # aware UTC, or None
    status: str                     # "ok" | "missing" | "invalid"
    unit: Optional[str] = None      # "seconds" | "milliseconds" | "iso8601" | "datetime"
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.status == "ok"


def _from_epoch(x: float) -> ParsedTime:
    if math.isnan(x) or math.isinf(x):
        return ParsedTime(None, "invalid", error="timestamp is not a finite number")
    if x == 0:
        return ParsedTime(None, "missing")
    if MIN_SECONDS <= x <= MAX_SECONDS:
        return ParsedTime(datetime.fromtimestamp(x, tz=timezone.utc), "ok", "seconds")
    if MIN_SECONDS * 1000 <= x <= MAX_SECONDS * 1000:
        return ParsedTime(datetime.fromtimestamp(x / 1000.0, tz=timezone.utc), "ok", "milliseconds")
    return ParsedTime(None, "invalid", error=f"epoch value {x!r} is outside 2000–2100 in seconds or milliseconds")


def parse_timestamp(value: Any) -> ParsedTime:
    if value is None or value == "":
        return ParsedTime(None, "missing")
    if isinstance(value, bool):
        return ParsedTime(None, "invalid", error="boolean is not a timestamp")
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return ParsedTime(dt.astimezone(timezone.utc), "ok", "datetime")
    if isinstance(value, (int, float)):
        return _from_epoch(float(value))
    if isinstance(value, str):
        s = value.strip()
        try:
            return _from_epoch(float(s))
        except ValueError:
            pass
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00").replace("z", "+00:00"))
        except ValueError:
            return ParsedTime(None, "invalid", error=f"unrecognised timestamp format: {s[:40]!r}")
        dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
        if not (MIN_SECONDS <= dt.timestamp() <= MAX_SECONDS):
            return ParsedTime(None, "invalid", error="timestamp is outside 2000–2100")
        return ParsedTime(dt, "ok", "iso8601")
    return ParsedTime(None, "invalid", error=f"unsupported timestamp type {type(value).__name__}")


def to_epoch(dt: Optional[datetime]) -> Optional[float]:
    """Aware or naive-UTC datetime → epoch seconds (SQLite returns naive UTC datetimes)."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def naive_utc(ts: float) -> datetime:
    """Epoch seconds → naive UTC datetime, for comparisons against stored SQLite values."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).replace(tzinfo=None)
