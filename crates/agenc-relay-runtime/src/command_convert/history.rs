//! Exact conversion of the pinned history command grammar into domain selectors.

use agenc_relay_admin::decode_fixed_base64url;
use agenc_relay_client_wire::ParsedMessage;
use agenc_relay_domain::{HistoryQuery, HistoryReference, HistorySelector, HistoryTimestamp};
use agenc_relay_types::MessageId;

use crate::RuntimeError;

pub(super) fn query(message: &ParsedMessage) -> Result<HistoryQuery, RuntimeError> {
    let operation = super::parameter(message, 0)?;
    let first = super::parameter(message, 2)?;
    let selector = match operation {
        "LATEST" => HistorySelector::Latest(if first == "*" {
            None
        } else {
            Some(reference(first)?)
        }),
        "BEFORE" => HistorySelector::Before(reference(first)?),
        "AFTER" => HistorySelector::After(reference(first)?),
        "AROUND" => HistorySelector::Around(reference(first)?),
        "BETWEEN" => {
            HistorySelector::Between(reference(first)?, reference(super::parameter(message, 3)?)?)
        }
        _ => return Err(RuntimeError::InvalidValue),
    };
    let limit = message
        .middle()
        .last()
        .ok_or(RuntimeError::InvalidValue)?
        .parse()
        .map_err(|_| RuntimeError::InvalidValue)?;
    HistoryQuery::new(selector, limit).map_err(|_| RuntimeError::InvalidValue)
}

fn reference(value: &str) -> Result<HistoryReference, RuntimeError> {
    if let Some(message_id) = value.strip_prefix("msgid=") {
        let bytes = decode_fixed_base64url::<16>(message_id.as_bytes())
            .map_err(|_| RuntimeError::InvalidValue)?;
        return Ok(HistoryReference::Message(MessageId::from_bytes(bytes)));
    }
    let timestamp = value
        .strip_prefix("timestamp=")
        .ok_or(RuntimeError::InvalidValue)?;
    let value = timestamp_milliseconds(timestamp)?;
    Ok(HistoryReference::Timestamp(
        HistoryTimestamp::new(value).map_err(|_| RuntimeError::InvalidValue)?,
    ))
}

fn timestamp_milliseconds(value: &str) -> Result<u64, RuntimeError> {
    let bytes = value.as_bytes();
    let punctuation = [
        (4, b'-'),
        (7, b'-'),
        (10, b'T'),
        (13, b':'),
        (16, b':'),
        (19, b'.'),
        (23, b'Z'),
    ];
    if bytes.len() != 24
        || punctuation
            .iter()
            .any(|(index, value)| bytes.get(*index) != Some(value))
    {
        return Err(RuntimeError::InvalidValue);
    }
    let year = digits(bytes.get(0..4))?;
    let month = digits(bytes.get(5..7))?;
    let day = digits(bytes.get(8..10))?;
    let hour = digits(bytes.get(11..13))?;
    let minute = digits(bytes.get(14..16))?;
    let second = digits(bytes.get(17..19))?;
    let millis = digits(bytes.get(20..23))?;
    let days = days_since_epoch(year, month, day)?;
    // Leap-second text has no distinct unsigned Unix-millisecond representation.
    if hour > 23 || minute > 59 || second > 59 {
        return Err(RuntimeError::InvalidValue);
    }
    days.checked_mul(86_400)
        .and_then(|value| value.checked_add(hour * 3_600 + minute * 60 + second))
        .and_then(|value| value.checked_mul(1_000))
        .and_then(|value| value.checked_add(millis))
        .ok_or(RuntimeError::InvalidValue)
}

fn digits(bytes: Option<&[u8]>) -> Result<u64, RuntimeError> {
    let bytes = bytes.ok_or(RuntimeError::InvalidValue)?;
    let mut result = 0_u64;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return Err(RuntimeError::InvalidValue);
        }
        result = result
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(byte - b'0')))
            .ok_or(RuntimeError::InvalidValue)?;
    }
    Ok(result)
}

fn days_since_epoch(year: u64, month: u64, day: u64) -> Result<u64, RuntimeError> {
    if !(1970..=9999).contains(&year) || !(1..=12).contains(&month) {
        return Err(RuntimeError::InvalidValue);
    }
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let lengths = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let month_index = usize::try_from(month - 1).map_err(|_| RuntimeError::InvalidValue)?;
    if day == 0
        || lengths
            .get(month_index)
            .is_none_or(|maximum| day > *maximum)
    {
        return Err(RuntimeError::InvalidValue);
    }
    let previous = year - 1;
    let leap_days = previous / 4 - previous / 100 + previous / 400 - 477;
    let months: u64 = lengths.iter().take(month_index).sum();
    Ok((year - 1970) * 365 + leap_days + months + day - 1)
}

#[cfg(test)]
mod tests {
    use super::timestamp_milliseconds;

    #[test]
    fn exact_milliseconds_preserve_leap_days_and_fractional_order() {
        assert_eq!(timestamp_milliseconds("1970-01-01T00:00:00.001Z"), Ok(1));
        assert_eq!(
            timestamp_milliseconds("2000-02-29T12:34:56.789Z"),
            Ok(951_827_696_789)
        );
        assert_eq!(
            timestamp_milliseconds("2100-03-01T00:00:00.000Z"),
            Ok(4_107_542_400_000)
        );
        assert_eq!(
            timestamp_milliseconds("9999-12-31T23:59:59.999Z"),
            Ok(253_402_300_799_999)
        );
    }

    #[test]
    fn unrepresentable_or_noncanonical_timestamps_are_rejected() {
        for value in [
            "1969-12-31T23:59:59.999Z",
            "2100-02-29T00:00:00.000Z",
            "2026-02-31T00:00:00.000Z",
            "2026-01-01T00:00:60.000Z",
            "2026-01-01T00:00:00.0001Z",
            "2026-01-01T00:00:00.000+00:00",
        ] {
            assert!(timestamp_milliseconds(value).is_err(), "{value}");
        }
    }
}
