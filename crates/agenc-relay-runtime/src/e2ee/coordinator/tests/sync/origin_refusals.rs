#![forbid(unsafe_code)]

//! An origin declaration is mirrored only when every field agrees with the
//! descriptor, the base origin, and the generation rules. A malformed
//! declaration is a violation; a well-formed one whose principal or device
//! attachment the base origin or the directory does not hold is refused for
//! its origin alone, and the link stays up.

use super::*;

const ACCOUNT: [u8; 24] = [b'a'; 24];

fn rewire(origin: &ArcFederationOrigin) -> TestResult<Vec<u8>> {
    wire(ArcWireObjectKind::FederationOrigin, origin)
}

/// Declares a generation-zero origin changed by `mutate` on a reset link and
/// expects the declaration to be a protocol violation that mirrors nothing.
fn assert_refused(mutate: impl FnOnce(&mut ArcFederationOrigin) -> TestResult) -> TestResult {
    let mut sync = Sync::new()?;
    sync.reset()?;
    let (mut origin, _) = origin_object(0, [0; 32], None, None)?;
    mutate(&mut origin)?;
    let bytes = rewire(&origin)?;
    assert_eq!(
        sync.declare(false, 0, &bytes).err(),
        Some(CompanionFault::Protocol)
    );
    assert!(sync.harness.coordinator.state.origins.is_empty());
    Ok(())
}

/// Declares the generation-zero `bytes` on `sync` and expects the
/// declaration to be refused for its origin alone: nothing is acknowledged
/// or mirrored, and the edge's deletion of the origin is acknowledged.
fn assert_refused_for_origin(mut sync: Sync, bytes: &[u8]) -> TestResult {
    let refused = sync
        .declare(false, 0, bytes)
        .map_err(|fault| format!("the link failed: {fault:?}"))?;
    assert!(frames(&refused)?.is_empty(), "nothing is acknowledged");
    assert!(sync.harness.coordinator.state.origins.is_empty());
    let acknowledged = frames(&delete(&mut sync, 0, 0).map_err(|f| format!("{f:?}"))?)?;
    assert_eq!(acknowledged.len(), 1, "the deletion is acknowledged");
    Ok(())
}

/// A generation-zero origin changed by `mutate`, declared on a reset link
/// whose base origin is unauthenticated, is refused for its origin alone.
fn assert_mutation_refused_for_origin(
    mutate: impl FnOnce(&mut ArcFederationOrigin) -> TestResult,
) -> TestResult {
    let mut sync = Sync::new()?;
    sync.reset()?;
    let (mut origin, _) = origin_object(0, [0; 32], None, None)?;
    mutate(&mut origin)?;
    assert_refused_for_origin(sync, &rewire(&origin)?)
}

#[test]
fn a_reset_naming_another_coordinator_is_a_violation() -> TestResult {
    let mut sync = Sync::new()?;
    let refused = sync.frame(CompanionFrame::OriginReset {
        coordinator_server_id: [0x77; 16],
        server_incarnation: INCARNATION,
    });
    assert_eq!(refused.err(), Some(CompanionFault::Protocol));
    let (_, bytes) = origin_object(0, [0; 32], None, None)?;
    assert_eq!(
        sync.declare(false, 0, &bytes).err(),
        Some(CompanionFault::Protocol),
        "the refused reset must not open the origin set"
    );
    Ok(())
}

#[test]
fn a_reset_for_an_incarnation_that_is_not_live_is_a_violation() -> TestResult {
    let mut sync = Sync::new()?;
    sync.host.incarnation = Some([0x55; 16]);
    let refused = sync.frame(CompanionFrame::OriginReset {
        coordinator_server_id: COORDINATOR,
        server_incarnation: INCARNATION,
    });
    assert_eq!(refused.err(), Some(CompanionFault::Protocol));
    Ok(())
}

#[test]
fn an_origin_object_of_another_network_is_refused() -> TestResult {
    assert_refused(|origin| {
        origin.network_id = [0x70; 32];
        Ok(())
    })
}

#[test]
fn an_origin_object_of_another_home_server_is_refused() -> TestResult {
    assert_refused(|origin| {
        origin.home_server_id = [0x71; 16];
        Ok(())
    })
}

#[test]
fn an_origin_object_of_another_incarnation_is_refused() -> TestResult {
    assert_refused(|origin| {
        origin.server_incarnation = [0x72; 16];
        Ok(())
    })
}

#[test]
fn an_origin_object_of_another_origin_is_refused() -> TestResult {
    assert_refused(|origin| {
        origin.origin_id = [0x73; 16];
        Ok(())
    })
}

#[test]
fn an_origin_object_of_another_generation_than_its_descriptor_is_refused() -> TestResult {
    assert_refused(|origin| {
        origin.origin_generation = 1;
        Ok(())
    })
}

#[test]
fn an_origin_object_of_an_unknown_profile_version_is_refused() -> TestResult {
    assert_refused(|origin| {
        origin.profile_version = 2;
        Ok(())
    })
}

#[test]
fn an_origin_object_of_another_connection_is_refused() -> TestResult {
    assert_refused(|origin| {
        origin.connection_id = [0x74; 16];
        Ok(())
    })?;
    assert_refused(|origin| {
        origin.connection_nonce = [0x75; 32];
        Ok(())
    })
}

#[test]
fn an_origin_object_whose_session_differs_from_the_base_is_refused() -> TestResult {
    // A session without its user is malformed.
    assert_refused(|origin| {
        origin.user_id = Opaque::new(Vec::new())?;
        Ok(())
    })?;
    // Another session, or none where the base holds one, is a principal the
    // base origin does not hold.
    assert_mutation_refused_for_origin(|origin| {
        origin.session_id = Opaque::new(vec![0x76; 16])?;
        Ok(())
    })?;
    assert_mutation_refused_for_origin(|origin| {
        origin.session_id = Opaque::new(Vec::new())?;
        origin.user_id = Opaque::new(Vec::new())?;
        Ok(())
    })
}

#[test]
fn an_origin_object_claiming_an_account_the_base_lacks_is_refused() -> TestResult {
    assert_mutation_refused_for_origin(|origin| {
        origin.account_id = Opaque::new(ACCOUNT.to_vec())?;
        origin.account_session_generation = 1;
        Ok(())
    })?;
    // An account session generation without an account is malformed, and so
    // is an account without one.
    assert_refused(|origin| {
        origin.account_session_generation = 1;
        Ok(())
    })?;
    assert_refused(|origin| {
        origin.account_id = Opaque::new(ACCOUNT.to_vec())?;
        Ok(())
    })
}

/// Declares `account` at `generation` against a base authenticated as
/// [`ACCOUNT`] at account session generation three.
fn declare_authenticated(account: [u8; 24], generation: u64) -> TestResult<Sync> {
    let mut sync = Sync::new()?;
    sync.host.origin.as_mut().ok_or("base origin")?.account = Some((ACCOUNT, 3));
    sync.reset()?;
    let (_, bytes) = origin_object(0, [0; 32], Some((account, generation)), None)?;
    let declared = sync
        .declare(false, 0, &bytes)
        .map_err(|fault| format!("the link failed: {fault:?}"))?;
    let acknowledged = frames(&declared)?.len();
    assert_eq!(
        acknowledged,
        usize::from(account == ACCOUNT && generation == 3)
    );
    Ok(sync)
}

#[test]
fn an_authenticated_origin_mirrors_the_base_account_and_generation_exactly() -> TestResult {
    let accepted = declare_authenticated(ACCOUNT, 3)?;
    let origin = accepted
        .harness
        .coordinator
        .state
        .origins
        .values()
        .next()
        .ok_or("origin")?;
    assert_eq!(origin.account_id, Some(ACCOUNT));
    let other = declare_authenticated([b'b'; 24], 3)?;
    assert!(other.harness.coordinator.state.origins.is_empty());
    let stale = declare_authenticated(ACCOUNT, 2)?;
    assert!(stale.harness.coordinator.state.origins.is_empty());
    Ok(())
}

#[test]
fn an_origin_object_omitting_the_base_account_is_refused() -> TestResult {
    let mut sync = Sync::new()?;
    sync.host.origin.as_mut().ok_or("base origin")?.account = Some((ACCOUNT, 3));
    sync.reset()?;
    let (_, bytes) = origin_object(0, [0; 32], None, None)?;
    assert_refused_for_origin(sync, &bytes)
}

#[test]
fn an_attached_device_needs_an_account_and_a_nonzero_generation() -> TestResult {
    // A device without an account names an attachment no principal holds.
    assert_mutation_refused_for_origin(|origin| {
        origin.attached_device_id = Opaque::new(vec![7; 16])?;
        origin.device_session_generation = 1;
        Ok(())
    })?;
    // A generation without a device, or a device without one, is malformed.
    assert_refused(|origin| {
        origin.device_session_generation = 1;
        Ok(())
    })?;
    assert_refused(|origin| {
        origin.attached_device_id = Opaque::new(vec![7; 16])?;
        Ok(())
    })
}

#[test]
fn an_attached_device_the_directory_does_not_know_is_refused() -> TestResult {
    let mut sync = Sync::new()?;
    sync.host.origin.as_mut().ok_or("base origin")?.account = Some((ACCOUNT, 3));
    sync.reset()?;
    let (_, bytes) = origin_object(0, [0; 32], Some((ACCOUNT, 3)), Some(([7; 16], 1)))?;
    assert_refused_for_origin(sync, &bytes)
}

#[test]
fn a_first_declaration_must_open_generation_zero_without_a_predecessor() -> TestResult {
    assert_refused(|origin| {
        origin.previous_origin_state_id = [9; 32];
        Ok(())
    })?;
    let mut sync = Sync::new()?;
    sync.host.origin.as_mut().ok_or("base origin")?.generation = 1;
    sync.reset()?;
    let (_, bytes) = origin_object(1, [9; 32], None, None)?;
    assert_eq!(
        sync.declare(false, 1, &bytes).err(),
        Some(CompanionFault::Protocol),
        "ADD cannot open a later generation"
    );
    Ok(())
}

#[test]
fn an_update_cannot_open_generation_zero() -> TestResult {
    let mut sync = Sync::new()?;
    sync.reset()?;
    let (_, bytes) = origin_object(0, [0; 32], None, None)?;
    assert_eq!(
        sync.declare(true, 0, &bytes).err(),
        Some(CompanionFault::Protocol)
    );
    assert!(sync.harness.coordinator.state.origins.is_empty());
    Ok(())
}

/// A link with the generation-zero origin accepted; returns its state id.
fn accepted() -> TestResult<(Sync, [u8; 32])> {
    let mut sync = Sync::new()?;
    sync.reset()?;
    let (origin, bytes) = origin_object(0, [0; 32], None, None)?;
    sync.declare(false, 0, &bytes)?;
    let state_id = semantic_id_of(SemanticHashDomain::FederationOriginState, &origin)?;
    Ok((sync, state_id))
}

#[test]
fn an_update_must_advance_by_one_and_name_its_predecessor() -> TestResult {
    let (mut sync, state_id) = accepted()?;
    sync.host.origin.as_mut().ok_or("base origin")?.generation = 2;
    let (_, skipped) = origin_object(2, state_id, None, None)?;
    assert_eq!(
        sync.declare(true, 2, &skipped).err(),
        Some(CompanionFault::Protocol)
    );
    sync.host.origin.as_mut().ok_or("base origin")?.generation = 1;
    let (_, unanchored) = origin_object(1, [9; 32], None, None)?;
    assert_eq!(
        sync.declare(true, 1, &unanchored).err(),
        Some(CompanionFault::Protocol)
    );
    let (_, successor) = origin_object(1, state_id, None, None)?;
    assert_eq!(
        sync.declare(false, 1, &successor).err(),
        Some(CompanionFault::Protocol),
        "ADD cannot advance an origin"
    );
    Ok(())
}

#[test]
fn a_different_object_at_the_accepted_generation_is_refused() -> TestResult {
    let (mut sync, _) = accepted()?;
    let (_, conflicting) = origin_object(0, [9; 32], None, None)?;
    for update in [false, true] {
        assert_eq!(
            sync.declare(update, 0, &conflicting).err(),
            Some(CompanionFault::Protocol)
        );
    }
    let stored = sync.harness.coordinator.state.origins.values().next();
    assert_eq!(stored.map(|origin| origin.previous_state_id), Some([0; 32]));
    Ok(())
}

fn delete(sync: &mut Sync, generation: u64, next: u64) -> Result<Vec<Action>, CompanionFault> {
    sync.frame(CompanionFrame::OriginDel {
        coordinator_server_id: COORDINATOR,
        server_incarnation: INCARNATION,
        origin_id: ORIGIN,
        origin_generation: generation,
        next_operation_sequence: next,
    })
}

/// The fence state of the one declared origin: its next sequence and
/// whether a deletion fenced it.
fn fence(sync: &Sync) -> TestResult<(u64, bool)> {
    let origin = sync
        .harness
        .coordinator
        .state
        .origins
        .values()
        .next()
        .ok_or("origin")?;
    Ok((origin.next_sequence, origin.fenced))
}

/// The accepted origin after three requests executed under generation zero.
fn executed_three() -> TestResult<Sync> {
    let (mut sync, _) = accepted()?;
    sync.harness
        .coordinator
        .state
        .origins
        .values_mut()
        .next()
        .ok_or("origin")?
        .next_sequence = 3;
    Ok(sync)
}

/// Companion 12.5: "`DEL` supplies the next unused sequence and permanently
/// fences later requests". The deletion names the generation the
/// coordinator holds and a next sequence at or above the one executed
/// there; the origin is fenced at the stated sequence, which a later
/// deletion does not undercut.
#[test]
fn a_delete_fences_the_accepted_generation_at_the_stated_sequence() -> TestResult {
    let mut sync = executed_three()?;
    let actions = delete(&mut sync, 0, 5)?;
    assert!(matches!(
        frames(&actions)?.as_slice(),
        [CompanionFrame::OriginAck {
            object_id: None,
            origin_generation: 0,
            ..
        }]
    ));
    assert_eq!(fence(&sync)?, (5, true), "fenced at the stated sequence");
    assert_eq!(frames(&delete(&mut sync, 0, 4)?)?.len(), 1);
    assert_eq!(
        fence(&sync)?,
        (5, true),
        "the fence keeps the stated sequence"
    );
    assert_eq!(frames(&delete(&mut sync, 0, 5)?)?.len(), 1);
    assert_eq!(fence(&sync)?, (5, true));
    Ok(())
}

/// A deletion naming another generation, or a sequence below the executed
/// one, closes that origin alone where it stands: it is acknowledged, the
/// origin is fenced at the generation and next sequence the coordinator
/// holds, and the link stays up.
#[test]
fn a_mismatched_delete_closes_only_its_origin_where_it_stands() -> TestResult {
    for (generation, next) in [(1, 3), (0, 2), (2, 9)] {
        let mut sync = executed_three()?;
        let actions = delete(&mut sync, generation, next)
            .map_err(|fault| format!("the link failed: {fault:?}"))?;
        assert!(
            matches!(
                frames(&actions)?.as_slice(),
                [CompanionFrame::OriginAck {
                    object_id: None,
                    origin_generation,
                    ..
                }] if *origin_generation == generation
            ),
            "({generation}, {next})"
        );
        assert_eq!(fence(&sync)?, (3, true), "({generation}, {next})");
        let held = sync.harness.coordinator.state.origins.values().next();
        assert_eq!(held.map(|origin| origin.generation), Some(0));
    }
    Ok(())
}

#[test]
fn a_delete_naming_another_coordinator_or_a_stale_incarnation_is_refused() -> TestResult {
    let (mut sync, _) = accepted()?;
    let refused = sync.frame(CompanionFrame::OriginDel {
        coordinator_server_id: [0x77; 16],
        server_incarnation: INCARNATION,
        origin_id: ORIGIN,
        origin_generation: 0,
        next_operation_sequence: 0,
    });
    assert_eq!(refused.err(), Some(CompanionFault::Protocol));
    sync.host.incarnation = Some([0x55; 16]);
    assert_eq!(
        delete(&mut sync, 0, 0).err(),
        Some(CompanionFault::Protocol)
    );
    assert_eq!(fence(&sync)?, (0, false), "nothing is fenced");
    Ok(())
}

#[test]
fn a_delete_at_the_executed_sequence_fences_there() -> TestResult {
    let (mut sync, _) = accepted()?;
    let actions = delete(&mut sync, 0, 0)?;
    assert!(matches!(
        frames(&actions)?.as_slice(),
        [CompanionFrame::OriginAck {
            object_id: None,
            origin_generation: 0,
            ..
        }]
    ));
    assert_eq!(fence(&sync)?, (0, true));
    Ok(())
}

#[test]
fn a_delete_of_an_origin_never_learned_is_acknowledged_without_state() -> TestResult {
    let mut sync = Sync::new()?;
    sync.reset()?;
    let actions = delete(&mut sync, 4, 9)?;
    assert!(matches!(
        frames(&actions)?.as_slice(),
        [CompanionFrame::OriginAck {
            object_id: None,
            origin_generation: 4,
            ..
        }]
    ));
    assert!(sync.harness.coordinator.state.origins.is_empty());
    Ok(())
}

#[test]
fn a_fenced_origin_accepts_neither_a_redeclaration_nor_a_successor() -> TestResult {
    let (mut sync, state_id) = accepted()?;
    delete(&mut sync, 0, 0)?;
    let (_, bytes) = origin_object(0, [0; 32], None, None)?;
    assert_eq!(
        sync.declare(false, 0, &bytes).err(),
        Some(CompanionFault::Protocol)
    );
    sync.host.origin.as_mut().ok_or("base origin")?.generation = 1;
    let (_, successor) = origin_object(1, state_id, None, None)?;
    assert_eq!(
        sync.declare(true, 1, &successor).err(),
        Some(CompanionFault::Protocol)
    );
    Ok(())
}

#[test]
fn a_cached_declaration_of_a_superseded_object_is_refused() -> TestResult {
    let (mut sync, state_id) = accepted()?;
    sync.host.origin.as_mut().ok_or("base origin")?.generation = 1;
    let (_, successor) = origin_object(1, state_id, None, None)?;
    sync.declare(true, 1, &successor)?;
    // The base regresses only in this fixture: it isolates the cached path,
    // which must compare the retained object with the accepted state.
    sync.host.origin.as_mut().ok_or("base origin")?.generation = 0;
    let (_, superseded) = origin_object(0, [0; 32], None, None)?;
    assert_eq!(
        sync.declare(false, 0, &superseded).err(),
        Some(CompanionFault::Protocol)
    );
    let stored = sync.harness.coordinator.state.origins.values().next();
    assert_eq!(stored.map(|origin| origin.generation), Some(1));
    Ok(())
}
