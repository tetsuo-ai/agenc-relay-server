//! Clock loss expires a pending token without inventing another lifetime.

#![forbid(unsafe_code)]

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn reading(seconds: u64, nanoseconds: u32) -> Sample {
    Sample {
        boot_id: [1; 16],
        offset_seconds: -30,
        offset_nanoseconds: 7,
        seconds,
        nanoseconds,
    }
}

#[test]
fn observations_preserve_the_original_deadline_and_expire_at_equality() -> TestResult {
    let start = reading(1_000, 50);
    let original = start.deadline().map_err(|_| "arm")?;
    assert_eq!(
        (original.deadline_seconds(), original.deadline_nanoseconds()),
        (1_900, 50)
    );
    let later = reading(1_600, 50);
    let observed = later
        .observe(original, Some(start))
        .map_err(|_| "observe")?;
    assert_eq!(observed.deadline_seconds(), original.deadline_seconds());
    assert_eq!(
        observed.deadline_nanoseconds(),
        original.deadline_nanoseconds()
    );
    assert_eq!(
        later.remaining(observed).map_err(|_| "remaining")?,
        Duration::from_secs(300)
    );
    assert!(reading(1_900, 49).observe(observed, None).is_ok());
    for sample in [reading(1_900, 50), reading(2_000, 0)] {
        assert_eq!(
            sample.observe(observed, None),
            Err(RetirementReason::DeadlineReached)
        );
    }
    Ok(())
}

#[test]
fn reboot_namespace_change_backwards_time_and_overflow_refuse_a_pending_token() -> TestResult {
    let start = reading(1_000, 0);
    let deadline = start.deadline().map_err(|_| "arm")?;
    let later = reading(1_100, 0);
    for changed in [
        Sample {
            boot_id: [2; 16],
            ..later
        },
        Sample {
            offset_seconds: -31,
            ..later
        },
        Sample {
            offset_nanoseconds: 8,
            ..later
        },
    ] {
        assert_eq!(
            changed.observe(deadline, None),
            Err(RetirementReason::ClockScopeLost)
        );
    }
    assert_eq!(
        reading(999, 999).observe(deadline, None),
        Err(RetirementReason::ClockInvalid)
    );
    assert_eq!(
        later.observe(deadline, Some(reading(1_200, 0))),
        Err(RetirementReason::ClockInvalid)
    );
    assert_eq!(
        reading(u64::MAX - 899, 0).deadline(),
        Err(RetirementReason::ClockInvalid)
    );
    assert_eq!(
        reading(1_100, NANOSECONDS).observe(deadline, None),
        Err(RetirementReason::ClockInvalid)
    );
    Ok(())
}

#[test]
fn boot_and_namespace_parsers_require_exact_complete_coordinates() -> TestResult {
    assert_eq!(
        parse_boot_id(b"01234567-89ab-cdef-0123-456789abcdef\n").map_err(|_| "uuid")?,
        [
            1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239
        ]
    );
    for bad in [
        b"01234567_89ab-cdef-0123-456789abcdef".as_slice(),
        b"01234567-89ab-cdef-0123-456789abcdeg".as_slice(),
        b"01234567-89ab-cdef-0123-456789abcdef\n\n".as_slice(),
        b"0123456789abcdef0123456789abcdef".as_slice(),
    ] {
        assert!(parse_boot_id(bad).is_err());
    }
    assert_eq!(
        parse_offset(b"monotonic -42 17\nboottime 0 0\n").map_err(|_| "offset")?,
        (-42, 17)
    );
    for bad in [
        "monotonic 0 0\n",
        "boottime 0 0\n",
        "monotonic 0 0\nmonotonic 0 0\nboottime 0 0\n",
        "monotonic 0 1000000000\nboottime 0 0\n",
        "monotonic 0 -1\nboottime 0 0\n",
        "monotonic 9223372036854775808 0\nboottime 0 0\n",
        "monotonic 0 0 extra\nboottime 0 0\n",
    ] {
        assert!(parse_offset(bad.as_bytes()).is_err());
    }
    Ok(())
}

const CHILD_DEADLINE: &str = "AGENC_CAP70_CHILD_CLOCK_DEADLINE";

#[test]
fn a_child_process_uses_the_parent_deadline_without_restarting_its_lifetime() -> TestResult {
    let current = sample().map_err(|_| "qualified host clock coordinate")?;
    let deadline = current.deadline().map_err(|_| "arm")?;
    let boot: String = deadline
        .boot_id()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let encoded = format!(
        "{boot}:{}:{}:{}:{}:{}:{}",
        deadline.offset_seconds(),
        deadline.offset_nanoseconds(),
        deadline.deadline_seconds(),
        deadline.deadline_nanoseconds(),
        deadline.observed_seconds(),
        deadline.observed_nanoseconds()
    );
    let status = std::process::Command::new(std::env::current_exe()?)
        .args(["--exact", "e2ee::coordinator::delivery_owner::clock::tests::child_process_checks_the_original_pending_deadline", "--test-threads=1"])
        .env(CHILD_DEADLINE, encoded)
        .status()?;
    assert!(status.success());
    Ok(())
}

#[test]
fn child_process_checks_the_original_pending_deadline() -> TestResult {
    let Ok(encoded) = std::env::var(CHILD_DEADLINE) else {
        return Ok(());
    };
    let fields: Vec<_> = encoded.split(':').collect();
    let [
        boot,
        offset_seconds,
        offset_nanos,
        deadline_seconds,
        deadline_nanos,
        observed_seconds,
        observed_nanos,
    ] = fields.as_slice()
    else {
        return Err("parent deadline fields".into());
    };
    if boot.len() != 32 {
        return Err("parent boot identity".into());
    }
    let mut boot_id = [0; 16];
    for (index, byte) in boot_id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(boot.get(index * 2..index * 2 + 2).ok_or("boot byte")?, 16)?;
    }
    let deadline = PendingDeadline::new(PendingDeadlineFields {
        boot_id,
        offset_seconds: offset_seconds.parse()?,
        offset_nanoseconds: offset_nanos.parse()?,
        deadline_seconds: deadline_seconds.parse()?,
        deadline_nanoseconds: deadline_nanos.parse()?,
        observed_seconds: observed_seconds.parse()?,
        observed_nanoseconds: observed_nanos.parse()?,
    })?;
    let current = sample().map_err(|_| "child clock")?;
    let observed = current
        .observe(deadline, None)
        .map_err(|_| "same clock coordinate")?;
    assert_eq!(observed.deadline_seconds(), deadline.deadline_seconds());
    assert_eq!(
        observed.deadline_nanoseconds(),
        deadline.deadline_nanoseconds()
    );
    assert!(
        current.remaining(observed).map_err(|_| "remaining")?
            < Duration::from_secs(LIFETIME_SECONDS)
    );
    Ok(())
}
