//! The cleanup job itself refuses pages it did not ask for, and a candidate
//! stops matching a stream whose owner, inventory or barriers changed.
#![forbid(unsafe_code)]

use super::*;
use crate::e2ee::coordinator::{CompanionFault, replay_cleanup};
use agenc_ircd_storage::{PersistentRecordValue, ReadPlan, StoredKey};

fn candidate(fixture: &Fixture) -> TestResult<replay_cleanup::Candidate> {
    let executor = fixture
        .coordinator
        .companion_exec
        .as_ref()
        .ok_or("executor")?;
    Ok(replay_cleanup::Candidate::current(executor, PEER)?.ok_or("cleanup candidate")?)
}

fn job(fixture: &mut Fixture, commit: u64) -> TestResult<replay_cleanup::Job> {
    let backing = fixture.core.context_mut()?.backing_reservations();
    let candidate = candidate(fixture)?;
    let executor = fixture
        .coordinator
        .companion_exec
        .as_ref()
        .ok_or("executor")?;
    Ok(candidate.begin(executor, commit, &backing)?)
}

#[tokio::test]
async fn a_cleanup_job_refuses_pages_out_of_order_and_finishes_only_when_done() -> TestResult {
    let mut fixture = Box::pin(logically_expired()).await?;
    let commit = fixture.core.context_mut()?.head().storage_commit_sequence;

    let mut early = job(&mut fixture, commit)?;
    assert_eq!(
        early.admit(commit, false, Vec::new()).err(),
        Some(CompanionFault::Storage),
        "a page before any read is outstanding"
    );
    assert_eq!(early.next().err(), Some(CompanionFault::Storage));
    let executor = fixture
        .coordinator
        .companion_exec
        .as_ref()
        .ok_or("executor")?;
    assert!(
        early.finish(executor).is_err(),
        "a failed job never finishes"
    );

    let mut twice = job(&mut fixture, commit)?;
    assert!(twice.next()?.is_some());
    assert_eq!(twice.next().err(), Some(CompanionFault::Storage));

    let mut moved = job(&mut fixture, commit)?;
    assert!(moved.next()?.is_some());
    assert_eq!(
        moved
            .admit(commit.saturating_add(1), false, Vec::new())
            .err(),
        Some(CompanionFault::Storage),
        "a page read under another commit"
    );

    let mut truncated = job(&mut fixture, commit)?;
    assert!(truncated.next()?.is_some());
    assert_eq!(
        truncated.admit(commit, true, Vec::new()).err(),
        Some(CompanionFault::Storage),
        "a truncated page without rows"
    );

    let mut waiting = job(&mut fixture, commit)?;
    assert!(waiting.next()?.is_some());
    let fresh = job(&mut fixture, commit)?;
    let executor = fixture
        .coordinator
        .companion_exec
        .as_ref()
        .ok_or("executor")?;
    assert!(waiting.finish(executor).is_err(), "a read is outstanding");
    assert!(fresh.finish(executor).is_err(), "no page was read");
    Ok(())
}

#[tokio::test]
async fn a_cleanup_candidate_stops_matching_a_changed_stream() -> TestResult {
    let mut fixture = Box::pin(logically_expired()).await?;
    let candidate = candidate(&fixture)?;
    let executor = fixture
        .coordinator
        .companion_exec
        .as_mut()
        .ok_or("executor")?;
    let stream = executor.state.streams.get_mut(&PEER).ok_or("stream")?;
    let owner = stream.owner.clone();
    let replay = stream.replay;

    stream.hold_after = Some(0);
    assert!(replay_cleanup::Candidate::current(executor, PEER)?.is_none());
    assert_eq!(candidate.validate(executor), Err(CompanionFault::Protocol));
    let stream = executor.state.streams.get_mut(&PEER).ok_or("stream")?;
    stream.hold_after = None;

    stream.barrier = Some((0, 0));
    assert!(replay_cleanup::Candidate::current(executor, PEER)?.is_none());
    assert_eq!(candidate.validate(executor), Err(CompanionFault::Protocol));
    let stream = executor.state.streams.get_mut(&PEER).ok_or("stream")?;
    stream.barrier = None;

    stream.replay = None;
    assert!(replay_cleanup::Candidate::current(executor, PEER)?.is_none());
    assert_eq!(candidate.validate(executor), Err(CompanionFault::Protocol));
    let stream = executor.state.streams.get_mut(&PEER).ok_or("stream")?;
    stream.replay = replay;

    stream.owner = None;
    assert_eq!(
        replay_cleanup::Candidate::current(executor, PEER).err(),
        Some(CompanionFault::Storage)
    );
    assert_eq!(candidate.validate(executor), Err(CompanionFault::Protocol));
    let stream = executor.state.streams.get_mut(&PEER).ok_or("stream")?;
    stream.owner = owner;

    assert!(replay_cleanup::Candidate::current(executor, PEER)?.is_some());
    candidate.validate(executor)?;
    Ok(())
}

/// Reads the durable replay owner row the way the maintenance read does.
async fn owner_row(fixture: &mut Fixture) -> TestResult<(StoredKey, PersistentRecordValue)> {
    let plan = ReadPlan::exact(
        agenc_ircd_storage::TableId::E2eeState,
        replay::replay_owner_key(fixture.gate.scope(), 0)?,
    );
    let id = fixture.core.context_mut()?.submit_storage_read(plan)?;
    let message = fixture.core.next_storage_read().await?;
    assert_eq!(id, message.read_id);
    let result = message.result?;
    let row = result.records.first().ok_or("owner row")?;
    let context = fixture.core.context_mut()?;
    let plaintext = context.open_storage_plaintext(row.table, &row.key, &row.sealed_record)?;
    let value = PersistentRecordValue::decode(row.table, plaintext.expose_for_storage_codec())?;
    Ok((row.key.clone(), value))
}

#[tokio::test]
async fn the_owner_page_must_hold_exactly_one_complete_row() -> TestResult {
    let mut fixture = Box::pin(logically_expired()).await?;
    let commit = fixture.core.context_mut()?.head().storage_commit_sequence;
    let owner = owner_row(&mut fixture).await?;
    let again = owner_row(&mut fixture).await?;

    let mut empty = job(&mut fixture, commit)?;
    assert!(empty.next()?.is_some());
    assert_eq!(
        empty.admit(commit, false, Vec::new()).err(),
        Some(CompanionFault::Storage)
    );

    let mut cut = job(&mut fixture, commit)?;
    assert!(cut.next()?.is_some());
    assert_eq!(
        cut.admit(commit, true, vec![again]).err(),
        Some(CompanionFault::Storage)
    );

    let mut exact = job(&mut fixture, commit)?;
    assert!(exact.next()?.is_some());
    exact.admit(commit, false, vec![owner])?;
    assert!(exact.next()?.is_some(), "the row page follows the owner");
    Ok(())
}

#[tokio::test]
async fn a_maintenance_read_answered_with_foreign_or_oversized_rows_is_refused() -> TestResult {
    for variant in 0..3 {
        let mut fixture = Box::pin(logically_expired()).await?;
        retry(&mut fixture)?;
        let mut message = fixture.core.next_storage_read().await?;
        let result = message.result.as_mut().map_err(|_| "the read failed")?;
        match variant {
            0 => {
                for row in &mut result.records {
                    row.table = agenc_ircd_storage::TableId::Audit;
                }
            }
            1 => {
                for row in &mut result.records {
                    row.sealed_record.resize(8_193, 0);
                }
            }
            _ => {
                result.truncated = true;
                result.records.clear();
            }
        }
        fixture
            .coordinator
            .storage_read_completed(fixture.core.context_mut()?, message);
        assert!(!fixture.coordinator.replay_maintenance.busy());
        assert!(fixture.coordinator.pending.is_none());
        assert_eq!(
            physical_rows(&mut fixture, false).await?,
            2,
            "variant {variant}"
        );
    }
    Ok(())
}
