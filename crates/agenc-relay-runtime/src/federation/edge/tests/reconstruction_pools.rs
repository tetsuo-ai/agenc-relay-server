#![forbid(unsafe_code)]

//! RUN-08: the restore's own admission ceilings.
//!
//! A restore must be able to rebuild every state the live path can admit. An
//! edge holds the active projection generation and, from the moment a
//! snapshot install begins until retention has swept the superseded rows, a
//! pending one, and `sync.rs` admits each of them up to the fixed
//! standing-projection ceilings. One shared pool the size of a single
//! generation therefore refused a durable state that crossed no admission
//! ceiling at all, so each family now carries its own pool. Every pool still
//! fails closed at its own ceiling, and it says so as a ceiling rather than as
//! stale durable state.

use super::{
    EdgeRestoreCause, MAX_COMPANION_BYTES, MAX_GENERATION_BYTES, MAX_GENERATION_ROWS, Restore,
};
use crate::RuntimeError;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn both_projection_generations_and_the_companion_rows_fit_beside_one_another() -> TestResult {
    let mut restore = Restore::default();
    let mut cause = EdgeRestoreCause::Unclassified;
    restore.charge_generation(false, MAX_GENERATION_BYTES, &mut cause)?;
    // One shared pool refused here, although the live path admits each
    // generation up to this ceiling and both generations' rows are durable at
    // once across a snapshot install.
    restore.charge_generation(true, MAX_GENERATION_BYTES, &mut cause)?;
    restore.charge_companion(MAX_COMPANION_BYTES, &mut cause)?;
    assert_eq!(cause, EdgeRestoreCause::Unclassified);
    Ok(())
}

#[test]
fn each_pool_fails_closed_at_its_own_ceiling_and_names_the_ceiling() -> TestResult {
    let mut restore = Restore::default();
    let mut cause = EdgeRestoreCause::Unclassified;
    restore.charge_generation(false, MAX_GENERATION_BYTES, &mut cause)?;
    assert_eq!(
        restore.charge_generation(false, 1, &mut cause),
        Err(RuntimeError::LimitExceeded)
    );
    assert_eq!(cause, EdgeRestoreCause::ActiveProjectionCeiling);

    let mut restore = Restore::default();
    let mut cause = EdgeRestoreCause::Unclassified;
    restore.charge_generation(true, MAX_GENERATION_BYTES, &mut cause)?;
    assert_eq!(
        restore.charge_generation(true, 1, &mut cause),
        Err(RuntimeError::LimitExceeded)
    );
    assert_eq!(cause, EdgeRestoreCause::PendingProjectionCeiling);

    let mut restore = Restore::default();
    let mut cause = EdgeRestoreCause::Unclassified;
    restore.charge_companion(MAX_COMPANION_BYTES, &mut cause)?;
    assert_eq!(
        restore.charge_companion(1, &mut cause),
        Err(RuntimeError::LimitExceeded)
    );
    assert_eq!(cause, EdgeRestoreCause::CompanionCeiling);
    Ok(())
}

#[test]
fn each_generation_admits_its_whole_admitted_entry_count_before_it_refuses() -> TestResult {
    let mut restore = Restore::default();
    let mut cause = EdgeRestoreCause::Unclassified;
    for _ in 0..MAX_GENERATION_ROWS {
        restore.charge_generation(false, 0, &mut cause)?;
        restore.charge_generation(true, 0, &mut cause)?;
    }
    assert_eq!(cause, EdgeRestoreCause::Unclassified);
    assert_eq!(
        restore.charge_generation(false, 0, &mut cause),
        Err(RuntimeError::LimitExceeded)
    );
    assert_eq!(cause, EdgeRestoreCause::ActiveProjectionCeiling);
    assert_eq!(
        restore.charge_generation(true, 0, &mut cause),
        Err(RuntimeError::LimitExceeded)
    );
    assert_eq!(cause, EdgeRestoreCause::PendingProjectionCeiling);
    Ok(())
}
