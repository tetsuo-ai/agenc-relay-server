#![forbid(unsafe_code)]
//! Maintenance records preserve exact scope, transition, and signature authority.

mod goldens;
use super::*;
use agenc_ircd_types::{DatabaseId, RecoveryEpoch, ServerIncarnation};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn scope() -> MaintenanceAuditScope {
    MaintenanceAuditScope::new(
        NetworkId::from_bytes([1; 32]),
        ServerId::from_bytes([2; 16]),
        DatabaseId::from_bytes([3; 16]),
        ServerIncarnation::from_bytes([4; 16]),
        RecoveryEpoch::from_bytes([5; 16]),
    )
}

fn bytes(hex: &str) -> TestResult<Vec<u8>> {
    let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err("incomplete hex pair".into());
    }
    pairs
        .iter()
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect()
}

fn start_transition(count: u64) -> Result<MaintenanceTransition, AdminError> {
    MaintenanceTransition::new(
        MaintenanceOperation::LoginIndexRotateStart,
        MaintenanceKeyState::new(5, [11; 32], 0, [0; 32], 0)?,
        MaintenanceKeyState::new(6, [12; 32], 5, [11; 32], count)?,
    )
}

fn start_tbs() -> TestResult<MaintenanceAuditEventTbs> {
    let key = Ed25519SecretKey::from_bytes([7; 32]);
    Ok(MaintenanceAuditEventTbs::new(
        scope(),
        *audit_signing_key_id(key.public_key().as_bytes())?.as_bytes(),
        MaintenanceAuditPosition::new(1, 1000, 10, 11, [6; 32])?,
        start_transition(9)?,
    )?)
}

fn signed_start() -> TestResult<MaintenanceAuditEvent> {
    Ok(MaintenanceAuditEvent::sign(
        start_tbs()?,
        &Ed25519SecretKey::from_bytes([7; 32]),
    )?)
}

#[test]
fn independent_start_and_finish_goldens_round_trip_exactly() -> TestResult {
    let key = Ed25519SecretKey::from_bytes([7; 32]);
    let start = signed_start()?;
    let finish_transition = MaintenanceTransition::new(
        MaintenanceOperation::LoginIndexRotateFinish,
        MaintenanceKeyState::new(6, [12; 32], 5, [11; 32], 0)?,
        MaintenanceKeyState::new(6, [12; 32], 0, [0; 32], 0)?,
    )?;
    let finish = MaintenanceAuditEvent::sign(
        MaintenanceAuditEventTbs::new(
            scope(),
            start.tbs().audit_signing_key_id(),
            MaintenanceAuditPosition::new(2, 1000, 11, 12, start.event_hash())?,
            finish_transition,
        )?,
        &key,
    )?;
    for (event, expected) in [(start, goldens::START), (finish, goldens::FINISH)] {
        assert_eq!(event.tbs().encode()?.len(), 358);
        assert_eq!(event.encode()?.len(), 454);
        assert_eq!(event.encode()?, bytes(expected)?);
        let decoded = MaintenanceAuditEvent::decode_exact(&event.encode()?)?;
        assert_eq!(decoded, event);
        decoded.verify_scope(scope(), key.public_key())?;
        assert_eq!(
            MaintenanceAuditEventTbs::decode_exact(&event.tbs().encode()?)?,
            *event.tbs()
        );
    }
    Ok(())
}

#[test]
fn an_actually_signed_encoding_two_event_is_refused_by_the_legacy_decoder() -> TestResult {
    let event = signed_start()?;
    event.verify_scope(scope(), Ed25519SecretKey::from_bytes([7; 32]).public_key())?;
    assert!(crate::AdminAuditEvent::decode_exact(&event.encode()?).is_err());
    assert!(crate::AdminAuditEventTbs::decode_exact(&event.tbs().encode()?).is_err());
    Ok(())
}

#[test]
fn maintenance_refuses_all_truncations_trailing_data_and_unknown_discriminators() -> TestResult {
    let encoded = signed_start()?.encode()?;
    for length in 0..encoded.len() {
        assert!(
            MaintenanceAuditEvent::decode_exact(encoded.get(..length).ok_or("prefix")?).is_err()
        );
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(MaintenanceAuditEvent::decode_exact(&trailing).is_err());
    for (offset, value) in [(1, 1), (1, 3), (3, 0), (3, 2), (165, 0), (165, 3)] {
        let mut altered = encoded.clone();
        *altered.get_mut(offset).ok_or("discriminator")? = value;
        assert!(MaintenanceAuditEvent::decode_exact(&altered).is_err());
    }
    let tbs = signed_start()?.tbs().encode()?;
    assert!(maintenance_audit_hash_refuses_sizes(&tbs)?);
    Ok(())
}

fn maintenance_audit_hash_refuses_sizes(tbs: &[u8]) -> TestResult<bool> {
    let shorter = tbs.get(..357).ok_or("tbs prefix")?;
    let mut longer = tbs.to_vec();
    longer.push(0);
    Ok(
        agenc_ircd_crypto::maintenance_audit_event_hash(shorter).is_err()
            && agenc_ircd_crypto::maintenance_audit_event_hash(&longer).is_err(),
    )
}

#[test]
fn key_states_refuse_noncanonical_absence_nonconsecutive_generations_and_equal_keys() {
    for (current, key, previous, old, count) in [
        (0, [1; 32], 0, [0; 32], 0),
        (1, [1; 32], 0, [2; 32], 0),
        (1, [1; 32], 0, [0; 32], 1),
        (3, [1; 32], 1, [2; 32], 0),
        (2, [1; 32], 1, [1; 32], 0),
        (1, [1; 32], u32::MAX, [2; 32], 0),
    ] {
        assert!(MaintenanceKeyState::new(current, key, previous, old, count).is_err());
    }
}

#[test]
fn transitions_refuse_changed_previous_identity_changed_current_and_nonzero_finish_count()
-> TestResult {
    let stable = MaintenanceKeyState::new(5, [11; 32], 0, [0; 32], 0)?;
    for after in [
        MaintenanceKeyState::new(6, [12; 32], 5, [13; 32], 0)?,
        MaintenanceKeyState::new(7, [12; 32], 6, [11; 32], 0)?,
        stable,
    ] {
        assert!(
            MaintenanceTransition::new(MaintenanceOperation::LoginIndexRotateStart, stable, after)
                .is_err()
        );
    }
    let transition = MaintenanceKeyState::new(6, [12; 32], 5, [11; 32], 1)?;
    let finished = MaintenanceKeyState::new(6, [12; 32], 0, [0; 32], 0)?;
    assert!(
        MaintenanceTransition::new(
            MaintenanceOperation::LoginIndexRotateFinish,
            transition,
            finished
        )
        .is_err()
    );
    let zero = MaintenanceKeyState::new(6, [12; 32], 5, [11; 32], 0)?;
    for after in [
        stable,
        MaintenanceKeyState::new(6, [13; 32], 0, [0; 32], 0)?,
        zero,
    ] {
        assert!(
            MaintenanceTransition::new(MaintenanceOperation::LoginIndexRotateFinish, zero, after)
                .is_err()
        );
    }
    assert!(
        MaintenanceTransition::new(
            MaintenanceOperation::LoginIndexRotateFinish,
            finished,
            finished
        )
        .is_err()
    );
    assert!(
        MaintenanceTransition::new(MaintenanceOperation::LoginIndexRotateStart, zero, finished)
            .is_err()
    );
    assert!(start_transition(0).is_ok());
    assert!(start_transition(u64::MAX).is_ok());
    Ok(())
}

#[test]
fn decoding_applies_the_same_transition_and_generation_guards() -> TestResult {
    let encoded = signed_start()?.encode()?;
    for (offset, value) in [
        (169, 0),
        (173, 99),
        (205, 1),
        (241, 1),
        (249, 7),
        (285, 99),
        (163, 12),
    ] {
        let mut altered = encoded.clone();
        *altered.get_mut(offset).ok_or("tuple field")? = value;
        assert!(
            MaintenanceAuditEvent::decode_exact(&altered).is_err(),
            "offset {offset}"
        );
    }
    Ok(())
}

#[test]
fn audit_positions_refuse_genesis_forks_and_sequence_or_state_overflow() -> TestResult {
    assert!(MaintenanceAuditPosition::new(0, 0, 0, 1, [0; 32]).is_ok());
    assert!(MaintenanceAuditPosition::new(0, 0, 0, 1, [1; 32]).is_err());
    assert!(MaintenanceAuditPosition::new(u64::MAX, 0, 0, 1, [0; 32]).is_err());
    assert!(MaintenanceAuditPosition::new(1, 0, u64::MAX, 0, [1; 32]).is_err());
    assert!(MaintenanceAuditPosition::new(1, 0, 10, 10, [1; 32]).is_err());
    assert!(MaintenanceAuditPosition::new(1, 0, 10, 12, [1; 32]).is_err());
    let stable = MaintenanceKeyState::new(u32::MAX, [11; 32], 0, [0; 32], 0)?;
    assert!(
        MaintenanceTransition::new(MaintenanceOperation::LoginIndexRotateStart, stable, stable)
            .is_err()
    );
    Ok(())
}

#[test]
fn trusted_network_server_and_key_selectors_are_required() -> TestResult {
    let event = signed_start()?;
    let key = Ed25519SecretKey::from_bytes([7; 32]);
    assert!(
        event
            .verify(
                NetworkId::from_bytes([9; 32]),
                scope().server_id(),
                key.public_key()
            )
            .is_err()
    );
    assert!(
        event
            .verify(
                scope().network_id(),
                ServerId::from_bytes([9; 16]),
                key.public_key()
            )
            .is_err()
    );
    assert!(
        event
            .verify(
                scope().network_id(),
                scope().server_id(),
                Ed25519SecretKey::from_bytes([8; 32]).public_key()
            )
            .is_err()
    );
    let original = *event.tbs();
    let wrong = MaintenanceAuditEventTbs::new(
        scope(),
        [0; 32],
        original.position(),
        original.transition(),
    )?;
    assert!(MaintenanceAuditEvent::sign(wrong, &key).is_err());
    Ok(())
}

#[test]
fn historical_scope_stays_signed_without_becoming_the_replacement_scope() -> TestResult {
    let event = signed_start()?;
    let key = Ed25519SecretKey::from_bytes([7; 32]).public_key();
    for (database, incarnation, epoch) in [
        ([9; 16], [4; 16], [5; 16]),
        ([3; 16], [9; 16], [5; 16]),
        ([3; 16], [4; 16], [9; 16]),
    ] {
        let replacement = MaintenanceAuditScope::new(
            scope().network_id(),
            scope().server_id(),
            DatabaseId::from_bytes(database),
            ServerIncarnation::from_bytes(incarnation),
            RecoveryEpoch::from_bytes(epoch),
        );
        assert!(event.verify_scope(replacement, key).is_err());
        event.verify(replacement.network_id(), replacement.server_id(), key)?;
    }
    Ok(())
}

#[test]
fn signatures_hashes_and_both_domain_substitutions_are_refused() -> TestResult {
    let key = Ed25519SecretKey::from_bytes([7; 32]);
    let original = signed_start()?;
    let mut event = original.clone();
    event.server_signature =
        sign_canonical(&key, SignatureDomain::AdminAuditEvent, &event.event_hash)?;
    assert_eq!(
        event.verify_scope(scope(), key.public_key()),
        Err(AdminError::Signature)
    );
    let mut event = original.clone();
    event.event_hash = *agenc_ircd_crypto::admin_audit_event_hash(&event.tbs.encode()?)?.as_bytes();
    event.server_signature = sign_canonical(
        &key,
        SignatureDomain::MaintenanceAuditEvent,
        &event.event_hash,
    )?;
    assert_eq!(
        event.verify_scope(scope(), key.public_key()),
        Err(AdminError::Audit)
    );
    let mut event = original.clone();
    event.server_signature = Ed25519Signature::from_bytes([0xff; 64]);
    assert_eq!(
        event.verify_scope(scope(), key.public_key()),
        Err(AdminError::Signature)
    );
    let mut encoded = original.encode()?;
    *encoded.get_mut(99).ok_or("timestamp")? ^= 1;
    let event = MaintenanceAuditEvent::decode_exact(&encoded)?;
    assert_eq!(
        event.verify_scope(scope(), key.public_key()),
        Err(AdminError::Audit)
    );
    Ok(())
}

#[test]
fn strict_signature_verification_rejects_an_identity_point_even_with_matching_key_id_and_hash()
-> TestResult {
    let mut point = [0; 32];
    *point.first_mut().ok_or("point")? = 1;
    let key = Ed25519PublicKey::from_bytes(point)?;
    let original = start_tbs()?;
    let tbs = MaintenanceAuditEventTbs::new(
        scope(),
        *audit_signing_key_id(key.as_bytes())?.as_bytes(),
        original.position(),
        original.transition(),
    )?;
    let mut signature = [0; 64];
    signature.get_mut(..32).ok_or("R")?.copy_from_slice(&point);
    let event = MaintenanceAuditEvent {
        event_hash: tbs.hash()?,
        tbs,
        server_signature: Ed25519Signature::from_bytes(signature),
    };
    assert_eq!(event.verify_scope(scope(), key), Err(AdminError::Signature));
    Ok(())
}

/// COV-01: the maintenance TBS decoder accepts exactly its fixed 358-byte
/// length; every shorter and every longer buffer is refused before any field
/// is read, so a truncated or padded body can never authenticate.
#[test]
fn the_maintenance_tbs_decoder_accepts_only_its_exact_length() -> TestResult {
    let encoded = start_tbs()?.encode()?;
    assert_eq!(encoded.len(), MAINTENANCE_AUDIT_TBS_BYTES);
    assert_eq!(
        MaintenanceAuditEventTbs::decode_exact(&encoded)?,
        start_tbs()?
    );
    for length in [0, 1, MAINTENANCE_AUDIT_TBS_BYTES - 1] {
        let prefix = encoded.get(..length).ok_or("prefix")?;
        assert_eq!(
            MaintenanceAuditEventTbs::decode_exact(prefix),
            Err(AdminError::Audit),
            "prefix of {length} bytes"
        );
    }
    let mut padded = encoded.clone();
    padded.push(0);
    assert_eq!(
        MaintenanceAuditEventTbs::decode_exact(&padded),
        Err(AdminError::Audit)
    );
    Ok(())
}
