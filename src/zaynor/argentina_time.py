"""Argentina-time (UTC-3, fixed, no DST since 2009) timestamp formatting.

Used wherever ZAYNOR records or displays *when* something happened —
audit trail entries, report generation — never in a sealed/decision-path
value (CLAUDE.md 5.2: a result seal must be reproducible bit-for-bit;
a timestamp inside it would make every run produce a different hash).

A fixed offset, not a tzdata zone lookup: Argentina has used UTC-3
year-round since 2009, so `timezone(timedelta(hours=-3))` is exact and
carries no dependency on the system's tzdata being present or current.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

ARGENTINA_OFFSET = timezone(timedelta(hours=-3))


def now_argentina() -> datetime:
    return datetime.now(tz=ARGENTINA_OFFSET)


def format_argentina(moment: datetime | None = None) -> str:
    """ISO 8601 with an explicit -03:00 offset and second precision.

    An explicit offset (never a naive datetime, never assumed-local) so a
    reader anywhere can tell what moment this actually names.
    """
    value = moment if moment is not None else now_argentina()
    return value.astimezone(ARGENTINA_OFFSET).isoformat(timespec="seconds")
