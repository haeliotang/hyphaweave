// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Timestamp literal (TS) grammar and arithmetic (§2.8).
//!
//! `TS = YYYY-MM-DDTHH:MM:SS.sssZ`, UTC only, proleptic Gregorian calendar,
//! seconds 00–59 (no leap second), exactly three fractional millisecond digits.
//! All times handled by the verifier are claimed times; nothing here reads the
//! wall clock.

use std::fmt;

/// A validated `weave-record/1` timestamp literal at millisecond precision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp {
    /// Year, `0000`–`9999`.
    pub year: u16,
    /// Month, `01`–`12`.
    pub month: u8,
    /// Day of month, `01`–`31`.
    pub day: u8,
    /// Hour, `00`–`23`.
    pub hour: u8,
    /// Minute, `00`–`59`.
    pub minute: u8,
    /// Second, `00`–`59`.
    pub second: u8,
    /// Millisecond, `000`–`999`.
    pub millisecond: u16,
}

impl Timestamp {
    /// Parses the exact §2.8 grammar. Returns `None` for any deviation: wrong
    /// length, non-digit, invalid calendar date-time, leap second, offset form
    /// or wrong fraction length.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let bytes = text.as_bytes();
        if bytes.len() != 24 {
            return None;
        }
        if bytes[4] != b'-'
            || bytes[7] != b'-'
            || bytes[10] != b'T'
            || bytes[13] != b':'
            || bytes[16] != b':'
            || bytes[19] != b'.'
            || bytes[23] != b'Z'
        {
            return None;
        }
        let digits = |range: std::ops::Range<usize>| -> Option<u32> {
            let mut value = 0u32;
            for &byte in &bytes[range] {
                if !byte.is_ascii_digit() {
                    return None;
                }
                value = value * 10 + u32::from(byte - b'0');
            }
            Some(value)
        };
        let year = u16::try_from(digits(0..4)?).ok()?;
        let month = u8::try_from(digits(5..7)?).ok()?;
        let day = u8::try_from(digits(8..10)?).ok()?;
        let hour = u8::try_from(digits(11..13)?).ok()?;
        let minute = u8::try_from(digits(14..16)?).ok()?;
        let second = u8::try_from(digits(17..19)?).ok()?;
        let millisecond = u16::try_from(digits(20..23)?).ok()?;
        if !(1..=12).contains(&month)
            || day < 1
            || day > days_in_month(year, month)?
            || hour > 23
            || minute > 59
            || second > 59
        {
            return None;
        }
        Some(Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            millisecond,
        })
    }

    /// Serialises back to the canonical 24-byte literal.
    #[must_use]
    pub fn to_ts_string(self) -> String {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
            self.year, self.month, self.day, self.hour, self.minute, self.second, self.millisecond
        )
    }

    /// Milliseconds since the Unix epoch (1970-01-01T00:00:00.000Z). Negative
    /// for earlier timestamps; the proleptic Gregorian calendar covers years
    /// `0000`–`9999`, so the value fits an `i64` comfortably.
    #[must_use]
    pub fn to_unix_millis(self) -> i64 {
        let days = days_from_civil(i32::from(self.year), i32::from(self.month), i32::from(self.day));
        let millis = i64::from(self.hour) * 3_600_000
            + i64::from(self.minute) * 60_000
            + i64::from(self.second) * 1_000
            + i64::from(self.millisecond);
        days * 86_400_000 + millis
    }

    /// Builds a timestamp from milliseconds since the Unix epoch (used to
    /// render `genTime`); returns `None` when the year would leave `0000`–`9999`.
    #[must_use]
    pub fn from_unix_millis(millis: i64) -> Option<Self> {
        let days = millis.div_euclid(86_400_000);
        let rest = millis.rem_euclid(86_400_000);
        let (year, month, day) = civil_from_days(days);
        if !(0..=9999).contains(&year) {
            return None;
        }
        let hour = u8::try_from(rest / 3_600_000).ok()?;
        let minute = u8::try_from((rest / 60_000) % 60).ok()?;
        let second = u8::try_from((rest / 1_000) % 60).ok()?;
        let millisecond = u16::try_from(rest % 1_000).ok()?;
        Some(Self {
            year: u16::try_from(year).ok()?,
            month: u8::try_from(month).ok()?,
            day: u8::try_from(day).ok()?,
            hour,
            minute,
            second,
            millisecond,
        })
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_ts_string())
    }
}

/// True when `year` is a leap year in the proleptic Gregorian calendar.
#[must_use]
pub fn is_leap_year(year: u16) -> bool {
    let year = u32::from(year);
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

/// Number of days in `month` of `year`, or `None` for an invalid month.
#[must_use]
pub fn days_in_month(year: u16, month: u8) -> Option<u8> {
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => return None,
    };
    Some(days)
}

/// Days since the Unix epoch for a civil date (Howard Hinnant's algorithm).
fn days_from_civil(year: i32, month: i32, day: i32) -> i64 {
    let year = year - i32::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    i64::from(era * 146_097 + day_of_era - 719_468)
}

/// Civil date for a day count since the Unix epoch (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i32, i32, i32) {
    let days = i32::try_from(days).unwrap_or(if days < 0 { i32::MIN } else { i32::MAX })
        + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i32::from(month <= 2);
    (year, month, day)
}
