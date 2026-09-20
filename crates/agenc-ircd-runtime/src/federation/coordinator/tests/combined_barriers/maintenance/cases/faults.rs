//! Offline replay maintenance refuses a job driven out of order and stops
//! once its peer, its stream or the core no longer match the chosen candidate.
#![forbid(unsafe_code)]

use super::*;
use crate::e2ee::coordinator::{CompanionFault, ReplayMaintenanceCandidate};

#[tokio::test]
async fn an_expiry_job_refuses_out_of_order_pages_and_a_drifted_stream() -> TestResult {
    let mut fixture = Box::pin(expired(true, true)).await?;
    let commit = fixture.core.context_mut()?.head().storage_commit_sequence;
    let backing = fixture.core.context_mut()?.backing_reservations();
    let now = fixture.core.context_mut()?.utc_now()?.get();
    let executor = fixture
        .coordinator
        .companion_exec
        .as_ref()
        .ok_or("executor")?;
    let candidate =
        ReplayMaintenanceCandidate::due(executor, PEER, now)?.ok_or("a due candidate")?;

    let mut early = candidate.clone().begin(executor, None, commit, &backing)?;
    assert_eq!(
        early.admit(commit, false, Vec::new()).err(),
        Some(CompanionFault::Storage),
        "a page before any read is outstanding"
    );
    assert!(early.next()?.is_some());
    assert_eq!(early.next().err(), Some(CompanionFault::Storage));
    assert!(early.finish(executor).is_err(), "a read is outstanding");
    let fresh = candidate.clone().begin(executor, None, commit, &backing)?;
    assert!(fresh.finish(executor).is_err(), "no page was read");

    let executor = fixture
        .coordinator
        .companion_exec
        .as_mut()
        .ok_or("executor")?;
    let stream = executor.state.streams.get_mut(&PEER).ok_or("stream")?;
    let owner = stream.owner.clone();
    let replay = stream.replay;

    stream.hold_after = Some(0);
    assert_eq!(candidate.validate(executor), Err(CompanionFault::Protocol));
    let stream = executor.state.streams.get_mut(&PEER).ok_or("stream")?;
    stream.hold_after = None;

    stream.barrier = Some((0, 0));
    assert_eq!(candidate.validate(executor), Err(CompanionFault::Protocol));
    let stream = executor.state.streams.get_mut(&PEER).ok_or("stream")?;
    stream.barrier = None;

    stream.replay = None;
    assert_eq!(candidate.validate(executor), Err(CompanionFault::Protocol));
    let stream = executor.state.streams.get_mut(&PEER).ok_or("stream")?;
    stream.replay = replay;

    stream.owner = None;
    assert_eq!(candidate.validate(executor), Err(CompanionFault::Protocol));
    assert_eq!(
        ReplayMaintenanceCandidate::due(executor, PEER, now).err(),
        Some(CompanionFault::Storage)
    );
    let stream = executor.state.streams.get_mut(&PEER).ok_or("stream")?;
    stream.owner = owner;
    candidate.validate(executor)?;

    let stream = executor.state.streams.get_mut(&PEER).ok_or("stream")?;
    stream.hold_after = Some(1);
    let held = ReplayMaintenanceCandidate::due(executor, PEER, now)?.ok_or("a held candidate")?;
    assert_eq!(
        held.begin(executor, None, commit, &backing).err(),
        Some(CompanionFault::Storage),
        "a held stream needs the protected first sequence"
    );
    Ok(())
}

#[tokio::test]
async fn a_peer_whose_base_scope_changed_cannot_start_maintenance() -> TestResult {
    let mut fixture = Box::pin(expired(true, true)).await?;
    fixture
        .coordinator
        .peers
        .get_mut(&PEER)
        .ok_or("peer")?
        .client_resync_epoch = 1;
    wake(&mut fixture)?;
    assert!(!fixture.coordinator.replay_maintenance.busy());
    assert!(fixture.coordinator.pending.is_none());
    assert_eq!(stream(&fixture)?.rows.len(), 2);
    Ok(())
}

#[tokio::test]
async fn a_maintenance_read_is_dropped_when_the_core_is_staging_quiescing_or_gated() -> TestResult {
    for variant in 0..3 {
        let mut fixture = Box::pin(expired(true, true)).await?;
        wake(&mut fixture)?;
        let message = fixture.core.next_storage_read().await?;
        match variant {
            0 => fixture.coordinator.pending = Some(PendingCommit::Cleanup { peer: PEER }),
            1 => fixture.core.context_mut()?.quiesce_for_test(),
            _ => {
                fixture
                    .coordinator
                    .barriers
                    .insert(PEER, fixture.gate.clone());
            }
        }
        fixture
            .coordinator
            .storage_read_completed(fixture.core.context_mut()?, message);
        assert!(
            !fixture.coordinator.replay_maintenance.busy(),
            "variant {variant}"
        );
        assert_eq!(stream(&fixture)?.rows.len(), 2, "variant {variant}");
        fixture.coordinator.pending = None;
    }
    Ok(())
}
