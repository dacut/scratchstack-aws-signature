use std::str::FromStr;

use chrono::format::{ParseError, ParseResult};
use chrono::naive::{NaiveDate, NaiveDateTime, NaiveTime};
use chrono::offset::FixedOffset;
use chrono::DateTime;
use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    /// ISO 8601 timestamp format
    static ref ISO_8601_REGEX: Regex = Regex::new(
        r"(?x)^
        (?P<year>\d{4})-?
        (?P<month>0[1-9]|1[0-2])-?
        (?P<day>0[1-9]|[12][0-9]|3[01])
        T
        (?P<hour>[01][0-9]|2[0-3]):?
        (?P<minute>[0-5][0-9]):?
        (?P<second>[0-5][0-9]|6[0-1])
        (?P<offset>[-+][01][0-9]:?[0-5][0-9]|Z)$").unwrap();

    static ref INVALID: ParseError = DateTime::<FixedOffset>::from_str("").unwrap_err();
}

pub trait ParseISO8601<T> {
    fn parse_from_iso8601(s: &str) -> ParseResult<T>;
}

impl ParseISO8601<DateTime<FixedOffset>> for DateTime<FixedOffset> {
    fn parse_from_iso8601(s: &str) -> ParseResult<DateTime<FixedOffset>> {
        if let Some(cap) = ISO_8601_REGEX.captures(&s) {
            let year_match = cap.name("year").unwrap();
            let year_str: &str = year_match.as_str();
            let year = i32::from_str(year_str).unwrap();

            let month_match = cap.name("month").unwrap();
            let month_str: &str = month_match.as_str();
            let month = u32::from_str(month_str).unwrap();

            let day_match = cap.name("day").unwrap();
            let day_str: &str = day_match.as_str();
            let day = u32::from_str(day_str).unwrap();

            let naive_date = NaiveDate::from_ymd(year, month, day);

            let hour_match = cap.name("hour").unwrap();
            let hour_str: &str = hour_match.as_str();
            let hour = u32::from_str(hour_str).unwrap();

            let minute_match = cap.name("minute").unwrap();
            let minute_str: &str = minute_match.as_str();
            let minute = u32::from_str(minute_str).unwrap();

            let second_match = cap.name("second").unwrap();
            let second_str: &str = second_match.as_str();
            let second = u32::from_str(second_str).unwrap();

            let naive_time = NaiveTime::from_hms(hour, minute, second);
            let naive_dt = NaiveDateTime::new(naive_date, naive_time);

            let offset_match = cap.name("offset").unwrap();
            let offset_str: &str = offset_match.as_str();

            let offset_secs = if offset_str == "Z" {
                0
            } else {
                let offset_condensed = offset_str.replace(':', "");
                // Must be [+-]HHMM at this point
                assert_eq!(offset_condensed.len(), 5);
                let (sign_str, hm) = offset_condensed.split_at(1);
                let (hour_off_str, minute_off_str) = hm.split_at(2);

                let sign = if sign_str == "-" { -1 } else { 1 };

                let hour = i32::from_str(hour_off_str).unwrap();
                let min = i32::from_str(minute_off_str).unwrap();
                sign * (hour * 3600 + min * 60)
            };

            let offset = FixedOffset::east(offset_secs);
            Ok(DateTime::from_utc(naive_dt, offset))
        } else {
            Err(*INVALID)
        }
    }
}
