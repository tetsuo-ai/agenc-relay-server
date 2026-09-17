#![forbid(unsafe_code)]

//! COV-01: the maintenance key-state decoder and the defence-in-depth
//! transition checks the Stage 10 report recorded as never executed.
//!
//! The decoder cases run through the real `Reader`, so each field boundary is
//! proved by a truncation rather than by a constructed error. The two
//! re-validation cases build a state through the module-private constructor
//! because no public constructor can produce one: they prove the transition
//! checker still refuses such a value instead of trusting its caller.

use super::*;

/// The canonical encoded length of one key-state tuple.
const KEY_STATE_BYTES: usize = 4 + 32 + 4 + 32 + 8;

fn stable() -> Result<MaintenanceKeyState, AdminError> {
    MaintenanceKeyState::new(5, [11; 32], 0, [0; 32], 0)
}

fn rotating() -> Result<MaintenanceKeyState, AdminError> {
    MaintenanceKeyState::new(6, [12; 32], 5, [11; 32], 9)
}

fn encode(value: MaintenanceKeyState) -> Result<Vec<u8>, AdminError> {
    let mut writer = Writer::with_ceiling(KEY_STATE_BYTES);
    value.put(&mut writer)?;
    Ok(writer.finish())
}

/// Every field boundary inside one key-state tuple refuses a short buffer, and
/// only the exact length decodes back to the value that was written.
#[test]
fn a_key_state_refuses_a_buffer_truncated_at_any_field() -> Result<(), AdminError> {
    let encoded = encode(rotating()?)?;
    assert_eq!(encoded.len(), KEY_STATE_BYTES);
    // One prefix ends immediately before each of the five fields.
    for length in [0, 4, 36, 40, 72] {
        let prefix = encoded.get(..length).ok_or(AdminError::Audit)?;
        let mut reader = Reader::new(prefix);
        assert_eq!(
            MaintenanceKeyState::take(&mut reader),
            Err(AdminError::Audit),
            "prefix of {length} bytes"
        );
    }
    let mut reader = Reader::new(&encoded);
    assert_eq!(MaintenanceKeyState::take(&mut reader)?, rotating()?);
    reader.finish()?;
    Ok(())
}

/// A transition body whose operation discriminator is unassigned is refused
/// before either key-state tuple is read.
#[test]
fn a_transition_refuses_an_unassigned_operation_discriminator() -> Result<(), AdminError> {
    let mut writer = Writer::with_ceiling(2 + 2 * KEY_STATE_BYTES);
    writer.put_u16(3)?;
    stable()?.put(&mut writer)?;
    rotating()?.put(&mut writer)?;
    let encoded = writer.finish();
    let mut reader = Reader::new(&encoded);
    assert_eq!(
        MaintenanceTransition::take(&mut reader),
        Err(AdminError::Audit)
    );

    // A body too short to hold the discriminator is refused at the same point.
    for length in [0, 1] {
        let prefix = encoded.get(..length).ok_or(AdminError::Audit)?;
        let mut reader = Reader::new(prefix);
        assert_eq!(
            MaintenanceTransition::take(&mut reader),
            Err(AdminError::Audit),
            "prefix of {length} bytes"
        );
    }

    // The same body under an assigned discriminator decodes.
    let mut valid = Writer::with_ceiling(2 + 2 * KEY_STATE_BYTES);
    valid.put_u16(MaintenanceOperation::LoginIndexRotateStart.as_u16())?;
    stable()?.put(&mut valid)?;
    rotating()?.put(&mut valid)?;
    let valid = valid.finish();
    let mut reader = Reader::new(&valid);
    let decoded = MaintenanceTransition::take(&mut reader)?;
    reader.finish()?;
    assert_eq!(decoded.preceding(), stable()?);
    assert_eq!(decoded.resulting(), rotating()?);
    Ok(())
}

/// A rotation start whose resulting state reports no previous generation is
/// refused: the new generation must name the generation it replaced.
#[test]
fn a_rotation_start_requires_the_resulting_state_to_name_its_predecessor() -> Result<(), AdminError>
{
    let orphan = MaintenanceKeyState::new(6, [12; 32], 0, [0; 32], 0)?;
    assert_eq!(
        MaintenanceTransition::new(
            MaintenanceOperation::LoginIndexRotateStart,
            stable()?,
            orphan,
        ),
        Err(AdminError::Audit)
    );
    // The same start with the predecessor named is admitted.
    MaintenanceTransition::new(
        MaintenanceOperation::LoginIndexRotateStart,
        stable()?,
        rotating()?,
    )?;
    Ok(())
}

/// The transition checker re-validates both key-state tuples rather than
/// trusting the caller, and still refuses a rotation start that would install
/// the key it claims to replace.
///
/// No public constructor can build these values, so each is assembled through
/// the module-private form; the point of the case is that the checker does not
/// depend on that constructor having run.
#[test]
fn the_transition_checker_revalidates_both_tuples_and_the_installed_key() {
    let broken = MaintenanceKeyState {
        current_generation: 0,
        current_key_id: [11; 32],
        previous_generation: 0,
        previous_key_id: [0; 32],
        previous_entry_count: 0,
    };
    let sound = MaintenanceKeyState {
        current_generation: 5,
        current_key_id: [11; 32],
        previous_generation: 0,
        previous_key_id: [0; 32],
        previous_entry_count: 0,
    };
    for (preceding, resulting) in [(broken, sound), (sound, broken)] {
        let transition = MaintenanceTransition {
            operation: MaintenanceOperation::LoginIndexRotateStart,
            preceding,
            resulting,
        };
        assert_eq!(transition.validate(), Err(AdminError::Audit));
    }

    // A resulting state that repeats the preceding current key is refused even
    // though every other rotation-start rule is satisfied.
    let repeated = MaintenanceTransition {
        operation: MaintenanceOperation::LoginIndexRotateStart,
        preceding: sound,
        resulting: MaintenanceKeyState {
            current_generation: 6,
            current_key_id: [11; 32],
            previous_generation: 5,
            previous_key_id: [11; 32],
            previous_entry_count: 0,
        },
    };
    assert_eq!(repeated.validate_start(), Err(AdminError::Audit));
}
