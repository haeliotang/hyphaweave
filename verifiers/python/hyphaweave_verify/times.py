# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Timestamp literal (TS) grammar and helpers (CONTRACT §0 / spec §2.8).

A TS is ``YYYY-MM-DDTHH:MM:SS.sssZ``: RFC 3339 UTC, exactly three fractional
digits, literal ``Z``, years 0000-9999, seconds 00-59 (no leap second 60; a
leap second is attributed to the following second). No other offset and no
other precision is accepted. The grammar is checked by re-serializing the
parsed components, so every accepted value has exactly one spelling.
"""

from __future__ import annotations

import re

TS_PATTERN = re.compile(
    r"^(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})"
    r"T(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
    r"\.(?P<millisecond>[0-9]{3})Z$"
)

_MONTH_DAYS = (0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def _is_leap_year(year: int) -> bool:
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


def _days_in_month(year: int, month: int) -> int:
    if month == 2 and _is_leap_year(year):
        return 29
    return _MONTH_DAYS[month]


def parse_timestamp(value: object) -> tuple[int, int, int, int, int, int, int]:
    """Parse a TS into ``(year, month, day, hour, minute, second, millisecond)``.

    Raises :class:`ValueError` for anything that is not exactly the grammar.
    """
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    match = TS_PATTERN.match(value)
    if match is None:
        raise ValueError("timestamp does not match YYYY-MM-DDTHH:MM:SS.sssZ")
    year = int(match.group("year"))
    month = int(match.group("month"))
    day = int(match.group("day"))
    hour = int(match.group("hour"))
    minute = int(match.group("minute"))
    second = int(match.group("second"))
    millisecond = int(match.group("millisecond"))
    if not 1 <= month <= 12:
        raise ValueError("month out of range")
    if not 1 <= day <= _days_in_month(year, month):
        raise ValueError("day out of range")
    if hour > 23:
        raise ValueError("hour out of range")
    if minute > 59:
        raise ValueError("minute out of range")
    # Seconds 60 (leap second) are deliberately rejected by the profile.
    if second > 59:
        raise ValueError("second out of range")
    return (year, month, day, hour, minute, second, millisecond)


def is_valid_timestamp(value: object) -> bool:
    """Whether ``value`` is a well-formed TS literal."""
    try:
        parse_timestamp(value)
    except ValueError:
        return False
    return True


def timestamp_sort_key(value: str) -> tuple[int, int, int, int, int, int, int]:
    """Return a comparable key for a valid TS literal."""
    return parse_timestamp(value)
