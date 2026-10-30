//! Ports of `irrd/utils/validators.py` and of the CPython `strptime` subset
//! that RPSL `changed` dates go through.

use crate::messages;
use crate::py;

/// `parse_as_number(value, permit_plain, asdot_permitted)`.
///
/// Returns the normalised `AS<n>` text and the number, or v4's
/// `ValidationError` text. `asdot_queries` is the
/// `compatibility.asdot_queries` setting; it only matters when the caller
/// permits asdot, which no RPSL field does.
pub fn parse_as_number(
    value: &str,
    permit_plain: bool,
    asdot_permitted: bool,
    asdot_queries: bool,
) -> Result<(String, u32), String> {
    let value = py::upper(value);
    let value: &str = &value;
    let has_as = value.starts_with("AS");
    if !permit_plain && !has_as {
        return Err(messages::asn_must_start_with_as(value));
    }
    let number = if has_as { &value[2..] } else { value };

    let value_int: py::PyInt = if asdot_permitted && asdot_queries && number.contains('.') {
        let parts: Vec<&str> = number.split('.').collect();
        if parts.len() != 2 {
            return Err(messages::asn_asdot_format(value));
        }
        let high = py::parse_int(parts[0], 10)
            .map_err(|_| messages::asn_asdot_high_invalid(value))?;
        let low =
            py::parse_int(parts[1], 10).map_err(|_| messages::asn_asdot_low_invalid(value))?;
        let high = high.to_i128();
        let low = low.to_i128();
        if high.is_none_or(|h| h > 65535) {
            return Err(messages::asn_asdot_high_range(value));
        }
        if low.is_none_or(|l| l > 65535) {
            return Err(messages::asn_asdot_low_range(value));
        }
        let (h, l) = (high.unwrap_or(0), low.unwrap_or(0));
        py::PyInt::Small(h * 65536 + l)
    } else {
        py::parse_int(number, 10).map_err(|_| messages::asn_not_numeric(value))?
    };

    match value_int.to_i128() {
        Some(v) if (0..=4_294_967_295).contains(&v) => {
            let v = v as u32;
            Ok((format!("AS{v}"), v))
        }
        _ => Err(messages::asn_out_of_range(value)),
    }
}

/// `datetime.datetime.strptime(date, "%Y%m%d")`, returning CPython's
/// `ValueError` text on failure.
///
/// CPython builds the regex
/// `(?P<Y>\d\d\d\d)(?P<m>1[0-2]|0[1-9]|[1-9])(?P<d>3[0-1]|[1-2]\d|0[1-9]|[1-9]| [1-9])`
/// and matches it at the start of the string, leftmost alternative first.
pub(crate) fn strptime_ymd(data: &str) -> Result<(), String> {
    let chars: Vec<char> = data.chars().collect();
    let no_match = || {
        Err(messages::strptime_no_match(
            &py::repr(data),
            &py::repr("%Y%m%d"),
        ))
    };
    if chars.len() < 4 || !chars[..4].iter().all(|&c| py::is_re_digit(c)) {
        return no_match();
    }
    let year: u32 = chars[..4]
        .iter()
        .fold(0, |acc, &c| acc * 10 + u32::from(py::decimal_value(c).unwrap_or(0)));
    let rest = &chars[4..];
    let ascii = |i: usize, set: &dyn Fn(char) -> bool| rest.get(i).is_some_and(|&c| set(c));

    // Month alternatives in order: 1[0-2] | 0[1-9] | [1-9]
    let month_alts: [(usize, &dyn Fn() -> Option<u32>); 3] = [
        (2, &|| {
            (ascii(0, &|c| c == '1') && ascii(1, &|c| ('0'..='2').contains(&c)))
                .then(|| 10 + digit(rest[1]))
        }),
        (2, &|| {
            (ascii(0, &|c| c == '0') && ascii(1, &|c| ('1'..='9').contains(&c)))
                .then(|| digit(rest[1]))
        }),
        (1, &|| ascii(0, &|c| ('1'..='9').contains(&c)).then(|| digit(rest[0]))),
    ];
    for (mlen, mfn) in month_alts {
        let Some(month) = mfn() else { continue };
        let d = &rest[mlen..];
        let at = |i: usize, set: &dyn Fn(char) -> bool| d.get(i).is_some_and(|&c| set(c));
        // Day alternatives in order: 3[0-1] | [1-2]\d | 0[1-9] | [1-9] | ' '[1-9]
        let day_alts: [(usize, Option<u32>); 5] = [
            (
                2,
                (at(0, &|c| c == '3') && at(1, &|c| c == '0' || c == '1'))
                    .then(|| 30 + digit(d[1])),
            ),
            (
                2,
                (at(0, &|c| c == '1' || c == '2') && at(1, &py::is_re_digit))
                    .then(|| digit(d[0]) * 10 + u32::from(py::decimal_value(d[1]).unwrap_or(0))),
            ),
            (
                2,
                (at(0, &|c| c == '0') && at(1, &|c| ('1'..='9').contains(&c)))
                    .then(|| digit(d[1])),
            ),
            (1, at(0, &|c| ('1'..='9').contains(&c)).then(|| digit(d[0]))),
            (
                2,
                (at(0, &|c| c == ' ') && at(1, &|c| ('1'..='9').contains(&c)))
                    .then(|| digit(d[1])),
            ),
        ];
        for (dlen, day) in day_alts {
            let Some(day) = day else { continue };
            let remaining: String = d[dlen..].iter().collect();
            if !remaining.is_empty() {
                return Err(messages::strptime_unconverted(&remaining));
            }
            if year == 0 {
                return Err(messages::date_year_out_of_range(year));
            }
            if day > days_in_month(year, month) {
                return Err(messages::DATE_DAY_OUT_OF_RANGE.to_owned());
            }
            return Ok(());
        }
    }
    no_match()
}

fn digit(c: char) -> u32 {
    c.to_digit(10).unwrap_or(0)
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
                29
            } else {
                28
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_numbers() {
        assert_eq!(
            parse_as_number("as65537", false, false, false),
            Ok(("AS65537".to_owned(), 65537))
        );
        assert_eq!(
            parse_as_number("65537", false, false, false),
            Err("Invalid AS number 65537: must start with \"AS\"".to_owned())
        );
        assert_eq!(
            parse_as_number("ASx", false, false, false),
            Err("Invalid AS number ASX: number part is not numeric".to_owned())
        );
        assert_eq!(
            parse_as_number("AS4294967296", false, false, false),
            Err("Invalid AS number AS4294967296: valid range is 0-4294967295".to_owned())
        );
        assert_eq!(
            parse_as_number("AS1.2", false, true, true),
            Ok(("AS65538".to_owned(), 65538))
        );
    }

    #[test]
    fn strptime_matches_cpython() {
        let r = |s: &str| strptime_ymd(s).err().unwrap_or_else(|| "OK".to_owned());
        assert_eq!(r("20230231"), "day is out of range for month");
        assert_eq!(r("00000101"), "year 0 is out of range");
        assert_eq!(r("2023"), "time data '2023' does not match format '%Y%m%d'");
        assert_eq!(r("202301011"), "unconverted data remains: 1");
        assert_eq!(r("20231301"), "unconverted data remains: 1");
        assert_eq!(r("2023011"), "OK");
        assert_eq!(
            r("20230100"),
            "time data '20230100' does not match format '%Y%m%d'"
        );
        assert_eq!(r("19990229"), "day is out of range for month");
        assert_eq!(r("20000229"), "OK");
        assert_eq!(r("202301 1"), "OK");
        assert_eq!(
            r("٢٠٢٣٠١٠١"),
            "time data '٢٠٢٣٠١٠١' does not match format '%Y%m%d'"
        );
    }
}
