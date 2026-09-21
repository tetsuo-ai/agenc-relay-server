//! Registration grammar helpers: an empty list needs more parameters and a
//! leap second is accepted only at the last minute of a month.
#![forbid(unsafe_code)]

use super::{RegistrationGrammarError, validate_clock_time, validate_csv};

#[test]
fn an_empty_list_parameter_needs_more_parameters() {
    assert_eq!(
        validate_csv("", 4, |_| Ok(()), |left, right| left == right).err(),
        Some(RegistrationGrammarError::NeedMoreParameters)
    );
    assert_eq!(
        validate_csv("a,,b", 4, |_| Ok(()), |left, right| left == right).err(),
        Some(RegistrationGrammarError::InvalidArgument)
    );
    assert_eq!(
        validate_csv("a,b", 4, |_| Ok(()), |left, right| left == right).ok(),
        Some(2)
    );
}

#[test]
fn a_leap_second_is_valid_only_at_the_last_minute_of_a_month_end() {
    assert!(validate_clock_time(23, 59, 60, true).is_ok());
    for (hour, minute, month_end) in [(22, 59, true), (23, 58, true), (23, 59, false)] {
        assert_eq!(
            validate_clock_time(hour, minute, 60, month_end).err(),
            Some(RegistrationGrammarError::InvalidArgument),
            "{hour}:{minute}:60 month_end={month_end}"
        );
    }
    assert_eq!(
        validate_clock_time(24, 0, 0, false).err(),
        Some(RegistrationGrammarError::InvalidArgument)
    );
}
