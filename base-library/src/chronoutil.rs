use {
    chrono::{
        format::{ParseError, ParseResult},
        offset::{FixedOffset, TimeZone},
        DateTime,
    },
    lazy_static::lazy_static,
    regex::Regex,
    std::str::FromStr,
};

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
        (?:[.,](?P<frac>[0-9]+))?
        (?P<offset>[-+][01][0-9]:?[0-5][0-9]|Z)$").unwrap();

    static ref INVALID: ParseError = DateTime::<FixedOffset>::from_str("").unwrap_err();
}

pub trait ParseISO8601<T> {
    fn parse_from_iso8601(s: &str) -> ParseResult<T>;
}

impl ParseISO8601<DateTime<FixedOffset>> for DateTime<FixedOffset> {
    fn parse_from_iso8601(s: &str) -> ParseResult<DateTime<FixedOffset>> {
        if let Some(cap) = ISO_8601_REGEX.captures(s) {
            let year_match = cap.name("year").unwrap();
            let year_str: &str = year_match.as_str();
            let year = i32::from_str(year_str).unwrap();

            let month_match = cap.name("month").unwrap();
            let month_str: &str = month_match.as_str();
            let month = u32::from_str(month_str).unwrap();

            let day_match = cap.name("day").unwrap();
            let day_str: &str = day_match.as_str();
            let day = u32::from_str(day_str).unwrap();

            let hour_match = cap.name("hour").unwrap();
            let hour_str: &str = hour_match.as_str();
            let hour = u32::from_str(hour_str).unwrap();

            let minute_match = cap.name("minute").unwrap();
            let minute_str: &str = minute_match.as_str();
            let minute = u32::from_str(minute_str).unwrap();

            let second_match = cap.name("second").unwrap();
            let second_str: &str = second_match.as_str();
            let second = u32::from_str(second_str).unwrap();

            let frac_match_result = cap.name("frac");
            let nanos = match frac_match_result {
                None => 0,
                Some(frac_match) => {
                    let mut frac_str = frac_match.as_str().to_string();
                    while frac_str.len() < 9 {
                        frac_str.push('0');
                    }

                    frac_str.truncate(9);
                    u32::from_str(&frac_str).unwrap()
                }
            };

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

                let sign = if sign_str == "-" {
                    -1
                } else {
                    1
                };

                let hour = i32::from_str(hour_off_str).unwrap();
                let min = i32::from_str(minute_off_str).unwrap();
                sign * (hour * 3600 + min * 60)
            };

            Ok(FixedOffset::east(offset_secs).ymd(year, month, day).and_hms_nano(hour, minute, second, nanos))
        } else {
            Err(*INVALID)
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::ParseISO8601,
        chrono::{DateTime, Datelike, Timelike},
    };

    #[test]
    fn check_iso8601_error_handling() {
        match DateTime::parse_from_iso8601("blatantly-wrong") {
            Ok(_) => panic!("Expected a ParseError"),
            Err(_) => 1,
        };

        match DateTime::parse_from_iso8601("2001-01-001T00:00:00Z") {
            Ok(_) => panic!("Expected a ParseError"),
            Err(_) => 1,
        };
    }

    #[test]
    fn check_iso8601_tz_formats() {
        let dt = DateTime::parse_from_iso8601("2001-02-03T15:16:17.000123456Z").unwrap();
        assert_eq!((dt.year(), dt.month(), dt.day()), (2001, 2, 3));
        assert_eq!((dt.hour(), dt.minute(), dt.second()), (15, 16, 17));
        assert_eq!(dt.nanosecond(), 123456);
        assert_eq!(dt.timezone().utc_minus_local(), 0);

        let dt = DateTime::parse_from_iso8601("2001-02-03T15:16:17.123Z").unwrap();
        assert_eq!((dt.year(), dt.month(), dt.day()), (2001, 2, 3));
        assert_eq!((dt.hour(), dt.minute(), dt.second()), (15, 16, 17));
        assert_eq!(dt.nanosecond(), 123000000);
        assert_eq!(dt.timezone().utc_minus_local(), 0);

        let dt = DateTime::parse_from_iso8601("2001-02-03T15:16:17.123456789123Z").unwrap();
        assert_eq!((dt.year(), dt.month(), dt.day()), (2001, 2, 3));
        assert_eq!((dt.hour(), dt.minute(), dt.second()), (15, 16, 17));
        assert_eq!(dt.nanosecond(), 123456789);
        assert_eq!(dt.timezone().utc_minus_local(), 0);

        let dt = DateTime::parse_from_iso8601("2001-02-03T15:16:17-02:45").unwrap();
        assert_eq!((dt.year(), dt.month(), dt.day()), (2001, 2, 3));
        assert_eq!((dt.hour(), dt.minute(), dt.second()), (15, 16, 17));
        assert_eq!(dt.timezone().utc_minus_local(), ((2 * 60) + 45) * 60);

        let dt = DateTime::parse_from_iso8601("20010203T151617-0245").unwrap();
        assert_eq!((dt.year(), dt.month(), dt.day()), (2001, 2, 3));
        assert_eq!((dt.hour(), dt.minute(), dt.second()), (15, 16, 17));
        assert_eq!(dt.timezone().utc_minus_local(), ((2 * 60) + 45) * 60);
    }
}
