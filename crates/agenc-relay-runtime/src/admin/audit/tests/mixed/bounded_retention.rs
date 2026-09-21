//! RUN-12 (issue #180): retention is bounded by its checkpoint ceiling and
//! not by the size of the audit log, it resumes from the checkpoint chain
//! across sweeps and across a restart, and shutdown flush runs none of it.
#![forbid(unsafe_code)]
#![cfg(test)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::*;
use crate::admin::{
    AdminAdmissionSnapshot, AdminLifecycleControl, AdminOwner, AdminOwnerClocks, AdminOwnerHealth,
    AdminOwnerRuntime, FlushAcknowledgement, admin_lifecycle_channel, admin_transport_channel,
};
use crate::budget::{MemoryBudget, MemoryCharge};
use crate::cancel::CancellationToken;
use crate::observe::health::{Liveness, ReadinessGate};
use crate::runtime_config::RuntimeConfigHandle;
use crate::state_core::admin_core_channel;
use crate::state_core::durable::{AccountingCeilings, project_admin_audit_retention};
use crate::supervisor::{
    PhaseOutcome, ShutdownFailure, ShutdownHooks, ShutdownPhase, ShutdownPlan, run_shutdown,
};
use crate::test_support::golden_snapshot;
use agenc_relay_admin::MAX_AUDIT_EXPORT_BYTES;
use agenc_relay_testkit::{DeterministicMonotonicClock, DeterministicWallClock, ScriptedEntropy};
use agenc_relay_types::TransactionId;

/// Retained events in the large log: tens of thousands, five checkpoints'
/// worth, every one of them older than any retention window used here.
const LARGE_LOG: u64 = 20_000;
/// Creation time of every seeded event.
const SEEDED_AT: u64 = 49;
/// A wall clock far enough ahead that the golden thirty-day window has
/// expired every seeded event.
const LONG_AFTER: u64 = 10_000_000;

/// A trust entry whose window covers both the seeded events and a
/// checkpoint signed `LONG_AFTER`.
fn wide_trust(fixture: &Fixture) -> TestResult<AuditTrustManifestEntry> {
    Ok(AuditTrustManifestEntry {
        not_after: LONG_AFTER * 2,
        ..fixture.trust()?
    })
}

/// A maintenance-event chain of `(count, created_at)` segments.
fn segmented_chain(fixture: &Fixture, segments: &[(u64, u64)]) -> TestResult<Vec<AuditEvent>> {
    let mut cursor = AuditChainCursor::genesis();
    let mut events = Vec::new();
    for (count, created_at) in segments {
        for _ in 0..*count {
            let event = fixture.maintenance(cursor, *created_at, fixture.scope())?;
            cursor = cursor.advance_event(&event)?;
            events.push(event);
        }
    }
    Ok(events)
}

fn large_chain(fixture: &Fixture, count: u64) -> TestResult<Vec<AuditEvent>> {
    segmented_chain(fixture, &[(count, SEEDED_AT)])
}

/// The authority a node holds after it verified `events` at startup, built
/// from the chain's own marks. `reconstruct` verifies about two hundred
/// events a second in a debug build, which is the very cost this work takes
/// off the shutdown path; the restart case below still pays it once.
fn verified_authority(
    fixture: &Fixture,
    core: &StateCoreFixture,
    events: &[AuditEvent],
    trust: AuditTrustManifestEntry,
) -> TestResult<AuditAuthority> {
    let source = core.audit_source()?;
    let cursor = events
        .iter()
        .try_fold(AuditChainCursor::genesis(), |cursor, event| {
            cursor.advance_event(event)
        })?;
    let latest_created_at = events.iter().map(AuditEvent::created_at).max().unwrap_or(0);
    let mut authority = AuditAuthority::empty_for_test()?;
    authority.scope = source.scope;
    authority.signing_key = Ed25519SecretKey::from_bytes([4; 32]);
    authority.signing_key_id = trust.key_id;
    authority.signing_not_before = trust.not_before;
    authority.signing_not_after = trust.not_after;
    authority.cursor = cursor;
    authority.latest_created_at = latest_created_at;
    authority.export = Some(Arc::new(AuditExportSource {
        binding: maintenance::session_binding(source.scope, &source.keys)?,
        storage: source.storage,
        keys: source.keys,
        trust: AuditTrust::new(&[trust])?,
        operators: fixture.operators()?,
    }));
    Ok(authority)
}

fn authority_at(
    fixture: &Fixture,
    core: &StateCoreFixture,
    now: u64,
) -> TestResult<AuditAuthority> {
    let source = core.audit_source()?;
    Ok(AuditAuthority::reconstruct(
        source.scope,
        Ed25519SecretKey::from_bytes([4; 32]),
        &[fixture.trust()?],
        source.storage,
        source.keys,
        &fixture.operators()?,
        now,
    )?)
}

fn visited() -> u64 {
    RETENTION_EVENTS_VISITED.with(std::cell::Cell::get)
}

/// Commits one signed retention checkpoint exactly as the state owner does.
fn commit_checkpoint(
    core: &mut StateCoreFixture,
    checkpoint: &AdminAuditCheckpoint,
    transaction: u8,
) -> TestResult {
    let source = core.audit_source()?;
    let projected = project_admin_audit_retention(
        TransactionId::from_bytes([transaction; 16]),
        checkpoint,
        core.context_mut()?.index(),
        &source.keys,
        source.head,
        AccountingCeilings {
            database_max_bytes: 1_073_741_824,
            backup_max_bytes: 2_147_483_648,
        },
    )?;
    let _receipt = commit(&source.storage, projected.into_parts().0)?;
    Ok(())
}

#[tokio::test]
async fn a_sweep_reads_only_what_it_deletes_and_resumes_across_ticks_and_a_restart() -> TestResult {
    let fixture = Fixture::new();
    // Two expired generations ahead of a retained tail five times their size.
    let events = segmented_chain(&fixture, &[(300, 49), (200, 70), (1_500, 75)])?;
    let total = u64::try_from(events.len())?;
    let mut core = core(&events)?;
    let mut authority = verified_authority(&fixture, &core, &events, fixture.trust()?)?;

    // A clock behind the verified chain and a window longer than the clock
    // both decline before anything is read.
    assert_eq!(authority.prepare_retention(10, 1)?.run()?, None);
    assert_eq!(authority.prepare_retention(80, 100)?.run()?, None);

    // First tick, cutoff 60: the scan stops at the first retained event.
    let first = authority
        .prepare_retention(80, 20)?
        .run()?
        .ok_or("first expired prefix")?;
    assert_eq!(
        (first.deleted_first_sequence, first.deleted_count),
        (0, 300)
    );
    assert_eq!(visited(), 301, "the scan read past its prefix of {total}");
    let checkpoint = authority.sign_retention(first)?;
    commit_checkpoint(&mut core, &checkpoint, 92)?;
    authority.commit_retention(&checkpoint)?;
    assert_eq!(
        authority.prepare_retention(80, 20)?.run()?,
        None,
        "nothing else is expired at this cutoff"
    );
    assert_eq!(visited(), 1);

    // Second tick, cutoff 71: it continues at the sequence the checkpoint
    // names, from the authority's marks, with no checkpoint scan.
    let second = authority
        .prepare_retention(95, 24)?
        .run()?
        .ok_or("second expired prefix")?;
    assert_eq!(
        (second.deleted_first_sequence, second.deleted_count),
        (300, 200)
    );
    assert_eq!(second.checkpoint_sequence, 1);
    assert_eq!(
        second.previous_checkpoint_hash,
        checkpoint.checkpoint_hash()
    );
    assert_eq!(visited(), 201);

    // A restart instead of that second tick. The checkpoint chain is the
    // persisted continuation: the authority reconstructed from storage,
    // which verifies the retained chain once, proposes the same checkpoint.
    drop(authority);
    core.audit_reopen()?;
    let restored = authority_at(&fixture, &core, 60)?;
    assert_eq!(restored.retained_first_sequence, 300);
    assert_eq!(
        restored.retained_previous_hash,
        checkpoint.tbs().deleted_last_event_hash
    );
    assert_eq!(restored.latest_created_at, 80);
    let resumed = restored
        .prepare_retention(95, 24)?
        .run()?
        .ok_or("resumed expired prefix")?;
    assert_eq!(resumed, second);
    Ok(())
}

#[tokio::test]
async fn a_sweep_still_refuses_a_forged_event_inside_the_prefix_it_would_delete() -> TestResult {
    let fixture = Fixture::new();
    let mut events = large_chain(&fixture, 8)?;
    // Sequence 3 is re-signed by a key the trust manifest does not hold.
    let forged = Fixture {
        audit: Ed25519SecretKey::from_bytes([44; 32]),
        ..Fixture::new()
    };
    let cursor = events
        .iter()
        .take(3)
        .try_fold(AuditChainCursor::genesis(), |cursor, event| {
            cursor.advance_event(event)
        })?;
    let mut replacement = forged.maintenance(cursor, SEEDED_AT, fixture.scope())?;
    std::mem::swap(events.get_mut(3).ok_or("event three")?, &mut replacement);
    let core = core(&events)?;
    // The authority's marks are taken from an honest chain of the same
    // shape; only the stored rows carry the forgery.
    let honest = core_authority_marks(&fixture)?;
    let source = core.audit_source()?;
    let job = AuditRetentionJob {
        source: Arc::new(AuditExportSource {
            binding: maintenance::session_binding(source.scope, &source.keys)?,
            storage: source.storage,
            keys: source.keys,
            trust: AuditTrust::new(&[wide_trust(&fixture)?])?,
            operators: fixture.operators()?,
        }),
        ..honest
    };
    assert!(
        job.run().is_err(),
        "a deletion must fail closed on an unverifiable event"
    );
    Ok(())
}

#[tokio::test]
async fn a_sweep_never_selects_past_the_head_the_authority_verified() -> TestResult {
    let fixture = Fixture::new();
    let events = large_chain(&fixture, 8)?;
    let core = core(&events)?;
    let mut authority = verified_authority(&fixture, &core, &events, fixture.trust()?)?;
    // The authority's verified head stands at sequence five; the rows at
    // five and beyond are in storage but were never released into it.
    authority.cursor = events
        .iter()
        .take(5)
        .try_fold(AuditChainCursor::genesis(), |cursor, event| {
            cursor.advance_event(event)
        })?;
    let tbs = authority
        .prepare_retention(80, 20)?
        .run()?
        .ok_or("expired prefix")?;
    assert_eq!(
        (tbs.deleted_first_sequence, tbs.deleted_last_sequence),
        (0, 4)
    );
    assert_eq!(visited(), 6);
    Ok(())
}

/// A retention job over an honest eight-event chain, used for its marks.
fn core_authority_marks(fixture: &Fixture) -> TestResult<AuditRetentionJob> {
    let core = core(&large_chain(fixture, 8)?)?;
    Ok(authority_at(fixture, &core, 60)?.prepare_retention(80, 20)?)
}

/// The daemon's flush shape: the admin owner's acknowledgements, then the
/// administrative and the state flush through `flush_admin_and_state`.
struct AdminStopHooks {
    admin: AdminLifecycleControl,
    acknowledgements: Vec<FlushAcknowledgement>,
    state_flushed: Arc<AtomicBool>,
}

impl ShutdownHooks for AdminStopHooks {
    async fn run(
        &mut self,
        phase: ShutdownPhase,
        _budget: Duration,
    ) -> Result<(), ShutdownFailure> {
        let failed = |_| ShutdownFailure::Audit;
        match phase {
            ShutdownPhase::Quiesce => self.admin.quiesce().await.map_err(failed),
            ShutdownPhase::Drain => {
                self.acknowledgements = self.admin.drain().await.map_err(failed)?;
                Ok(())
            }
            ShutdownPhase::Flush => {
                let flushed = Arc::clone(&self.state_flushed);
                crate::daemon::flush_admin_and_state(
                    &mut self.acknowledgements,
                    self.admin.drain(),
                    self.admin.flush(),
                    async move {
                        flushed.store(true, Ordering::Release);
                        Ok(())
                    },
                )
                .await
            }
            ShutdownPhase::Stop => Ok(()),
        }
    }

    fn stop_deadline_expired(&mut self) {}
}

#[tokio::test]
async fn a_node_with_a_large_expired_audit_log_stops_inside_its_plan() -> TestResult {
    let fixture = Fixture::new();
    let events = large_chain(&fixture, LARGE_LOG)?;
    let core = core(&events)?;
    let authority = verified_authority(&fixture, &core, &events, wide_trust(&fixture)?)?;
    // Nothing answers the core port: a retention commit requested during
    // the stop would never return, so a sweep on the shutdown path cannot
    // pass this test by being fast.
    let (port, mut core_inbox) = admin_core_channel();
    let scope = fixture.scope();
    let backing = MemoryCharge::allocation(MAX_AUDIT_EXPORT_BYTES)?
        .bytes()
        .checked_mul(2)
        .ok_or("export budget overflow")?;
    let owner = AdminOwner::new(
        AdminSessionBinding {
            network_id: scope.network_id(),
            server_id: scope.server_id(),
        },
        fixture.operators()?,
        AdminAdmissionSnapshot::new(vec![1_000], Vec::new(), Vec::new()),
        authority,
        port,
        AdminOwnerRuntime {
            health: AdminOwnerHealth {
                readiness: Arc::new(ReadinessGate::new()),
                liveness: Arc::new(Liveness::new()),
            },
            config: Some(RuntimeConfigHandle::new(golden_snapshot("AgenC", None)?)),
            reload: None,
            backup: None,
            process: None,
            fatal: None,
            observer: None,
            budget: Arc::new(MemoryBudget::new(backing)),
            entropy: Box::new(ScriptedEntropy::new(vec![7; 64])?),
            clocks: AdminOwnerClocks {
                monotonic: Box::new(DeterministicMonotonicClock::at(0)),
                wall: Box::new(DeterministicWallClock::at(LONG_AFTER)),
            },
        },
    );
    let (_transport, inbox) = admin_transport_channel(AdminSessionBinding {
        network_id: scope.network_id(),
        server_id: scope.server_id(),
    });
    let (lifecycle, lifecycle_inbox) = admin_lifecycle_channel();
    let root = CancellationToken::root();
    let task = tokio::spawn(owner.run(inbox, lifecycle_inbox, root.clone()));

    let plan = ShutdownPlan::new(
        Duration::from_secs(2),
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(2),
    )?;
    let state_flushed = Arc::new(AtomicBool::new(false));
    let mut hooks = AdminStopHooks {
        admin: lifecycle,
        acknowledgements: Vec::new(),
        state_flushed: Arc::clone(&state_flushed),
    };
    let (_signals, mut signal_receiver) = tokio::sync::mpsc::channel(4);
    let started = tokio::time::Instant::now();
    let report = run_shutdown(plan, &mut hooks, &mut signal_receiver).await;
    assert!(started.elapsed() <= plan.total());
    assert_eq!(report.first_problem(), None, "{report:?}");
    for phase in ShutdownPhase::ALL {
        assert_eq!(report.outcome(phase), PhaseOutcome::Completed, "{report:?}");
    }
    assert!(state_flushed.load(Ordering::Acquire));
    assert!(
        tokio::time::timeout(
            Duration::from_millis(50),
            core_inbox.complete_next_for_test(Ok(()))
        )
        .await
        .is_err(),
        "the stop asked the state owner for administrative work"
    );
    root.cancel();
    task.await?;
    drop(core);
    Ok(())
}
