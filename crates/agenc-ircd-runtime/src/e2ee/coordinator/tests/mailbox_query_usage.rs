//! Mailbox cuts share actual local query admission and release on origin fencing.

#![forbid(unsafe_code)]

use super::*;
use crate::connection::ConnectionGeneration;
use crate::runtime_config::{
    ConfigRevision, RuntimeConfigHandle, RuntimeConfigSnapshot, RuntimeResourceLimits,
};
use crate::state_core::StateCoreContext;
use crate::test_support::{self, StateCoreFixture};

#[path = "mailbox_publication.rs"]
mod publication;
use agenc_ircd_config::LimitKey;
use agenc_ircd_types::UserId;

fn configuration(values: &[(LimitKey, u64)]) -> TestResult<Arc<RuntimeConfigSnapshot>> {
    let mut config = test_support::golden_config()?;
    for (key, value) in values {
        config.limits.values = config.limits.values.with(*key, *value);
    }
    Ok(Arc::new(RuntimeConfigSnapshot::from_parts(
        ConfigRevision::INITIAL,
        config,
        test_support::golden_parts("query-test", None)?,
    )))
}

fn limits(values: &[(LimitKey, u64)]) -> TestResult<RuntimeResourceLimits> {
    configuration(values)?
        .runtime_resource_limits()
        .ok_or_else(|| "query limits".into())
}

fn mailbox() -> TestResult<(Harness, ScriptedEntropy)> {
    let (mut source, _, _) = finalization_fixture()?;
    let binding = source.binding_bytes()?;
    for _ in 0..33 {
        deliver_binding(&mut source, &binding)?;
    }
    let entropy = ScriptedEntropy::new((1..=192_u8).flat_map(|byte| [byte; 32]).collect())?;
    Ok((source, entropy))
}

fn local() -> TestResult<(StateCoreFixture, UserId)> {
    let mut fixture = StateCoreFixture::new(vec![1; 1024])?;
    let config = configuration(&[(LimitKey::QuerySnapshotsPerSession, 1)])?;
    let _reload = fixture.install_reload_port(RuntimeConfigHandle::new(config))?;
    let context = fixture.context_mut()?;
    let user = test_support::seed_session(context, 1, "MailboxQuery", None)?;
    let _sink = test_support::bind_live_session(
        context,
        1,
        user,
        test_support::negotiated_capabilities(&[])?,
        true,
    )?;
    Ok((fixture, user.user_id))
}

fn evaluate_local(
    source: &Harness,
    context: &StateCoreContext,
    user: UserId,
    entropy: &mut ScriptedEntropy,
) -> TestResult<Result<Outcome, Fail>> {
    evaluate_request_with_queries(
        source,
        Op::FetchMailbox,
        &[2, 0],
        None,
        entropy,
        context.query_reservations(user),
    )
}

#[test]
fn mailbox_query_admission_shares_a_real_local_lease_and_refunds_an_uncommitted_cut() -> TestResult
{
    let (mut source, mut entropy) = mailbox()?;
    let (mut fixture, user) = local()?;
    let context = fixture.context_mut()?;
    source.backing = context.backing_reservations();
    let generation = ConnectionGeneration::new(1);
    let local = context
        .prepare_query_snapshot(generation, 1, 256)?
        .finish(1, 256)?;
    context
        .sessions_mut()
        .begin_active_query(generation, local.rows(), local.bytes())?;
    let before = entropy.remaining();
    assert!(evaluate_local(&source, context, user, &mut entropy)?.is_err());
    assert_eq!(entropy.remaining(), before);
    context.sessions_mut().end_active_query(generation);
    drop(local);
    let candidate = ok(evaluate_local(&source, context, user, &mut entropy)?)?;
    let usage = context.sessions().queue_snapshot();
    assert_eq!((usage.query_snapshots(), usage.query_rows()), (1, 33));
    assert_eq!(usage.max_query_snapshots_per_session(), 1);
    assert!(context.prepare_query_snapshot(generation, 1, 256).is_err());
    drop(candidate);
    let released = context.sessions().queue_snapshot();
    assert_eq!(
        (
            released.query_snapshots(),
            released.query_rows(),
            released.query_bytes()
        ),
        (0, 0, 0)
    );
    assert!(context.prepare_query_snapshot(generation, 1, 256).is_ok());
    Ok(())
}

#[test]
fn mailbox_query_byte_admission_counts_the_shared_index_before_entropy() -> TestResult {
    let (mut source, mut entropy) = mailbox()?;
    let candidate = ok(evaluate_request_with_entropy(
        &source,
        Op::FetchMailbox,
        &[2, 0],
        None,
        &mut entropy,
    )?)?;
    let exact = source.query_sessions.queue_snapshot().query_bytes();
    assert!(exact > 0);
    drop(candidate);
    source.query_limits = limits(&[(LimitKey::QuerySnapshotBytesGlobal, exact - 1)])?;
    let before = entropy.remaining();
    assert!(
        evaluate_request_with_entropy(&source, Op::FetchMailbox, &[2, 0], None, &mut entropy)?
            .is_err()
    );
    assert_eq!(entropy.remaining(), before);
    assert_eq!(source.query_sessions.queue_snapshot().query_bytes(), 0);
    source.query_limits = limits(&[(LimitKey::QuerySnapshotBytesGlobal, exact)])?;
    let candidate = ok(evaluate_request_with_entropy(
        &source,
        Op::FetchMailbox,
        &[2, 0],
        None,
        &mut entropy,
    )?)?;
    assert_eq!(source.query_sessions.queue_snapshot().query_bytes(), exact);
    drop(candidate);
    Ok(())
}

#[test]
fn mailbox_query_row_limits_include_independent_users_without_merging_their_slots() -> TestResult {
    let (mut source, mut entropy) = mailbox()?;
    source.query_limits = limits(&[(LimitKey::QuerySnapshotRows, 32)])?;
    let before = entropy.remaining();
    assert!(
        evaluate_request_with_entropy(&source, Op::FetchMailbox, &[2, 0], None, &mut entropy)?
            .is_err()
    );
    assert_eq!(entropy.remaining(), before);
    source.query_limits = limits(&[
        (LimitKey::QuerySnapshotRows, 33),
        (LimitKey::QuerySnapshotRowsGlobal, 33),
        (LimitKey::QuerySnapshotsPerSession, 1),
    ])?;
    let other = source
        .query_sessions
        .query_reservations(
            UserId::from_bytes([199; 16]),
            source.query_limits,
            source.backing.clone(),
        )
        .reserve_snapshot(1, 0)?;
    assert!(
        evaluate_request_with_entropy(&source, Op::FetchMailbox, &[2, 0], None, &mut entropy)?
            .is_err()
    );
    assert_eq!(entropy.remaining(), before);
    drop(other);
    let candidate = ok(evaluate_request_with_entropy(
        &source,
        Op::FetchMailbox,
        &[2, 0],
        None,
        &mut entropy,
    )?)?;
    assert_eq!(source.query_sessions.queue_snapshot().query_rows(), 33);
    drop(candidate);
    source.query_limits = limits(&[(LimitKey::QuerySnapshotsPerSession, 1)])?;
    let other = source
        .query_sessions
        .query_reservations(
            UserId::from_bytes([199; 16]),
            source.query_limits,
            source.backing.clone(),
        )
        .reserve_snapshot(1, 0)?;
    let candidate = ok(evaluate_request_with_entropy(
        &source,
        Op::FetchMailbox,
        &[2, 0],
        None,
        &mut entropy,
    )?)?;
    let usage = source.query_sessions.queue_snapshot();
    assert_eq!(
        (
            usage.query_snapshots(),
            usage.max_query_snapshots_per_session()
        ),
        (2, 1)
    );
    drop((candidate, other));
    Ok(())
}

struct Host([u8; 16]);
impl crate::e2ee::coordinator::sync::CompanionHost for Host {
    fn live_incarnation(&self, _: ServerId) -> Option<[u8; 16]> {
        Some(self.0)
    }
    fn base_origin(
        &self,
        _: &crate::e2ee::coordinator::CompanionOriginKey,
    ) -> Option<crate::e2ee::coordinator::sync::BaseOriginView> {
        None
    }
    fn base_origins_ready(&self, _: ServerId) -> bool {
        false
    }
    fn base_resync_epoch(&self, _: ServerId) -> u64 {
        0
    }
    fn state_generation(&self) -> u64 {
        1
    }
    fn holds_channel(&self, _: [u8; 16]) -> bool {
        false
    }
    fn hosts_account(&self, _: &[u8; 24]) -> bool {
        false
    }
}

#[test]
fn mailbox_query_origin_close_releases_only_after_the_exact_descriptor_passes() -> TestResult {
    use crate::e2ee::coordinator::sync::OriginDescriptor;
    use crate::e2ee::coordinator::tests::{HOME, INCARNATION, ORIGIN};
    let (mut source, _, _, _) = paged_mailbox()?;
    let descriptor = OriginDescriptor {
        coordinator_server_id: *source.coordinator.server_id.as_bytes(),
        server_incarnation: INCARNATION,
        origin_id: ORIGIN,
        origin_generation: 0,
        object_id: [0; 32],
    };
    let before = source.query_sessions.queue_snapshot();
    assert_eq!(before.query_snapshots(), 1);
    assert!(
        source
            .coordinator
            .origin_del(
                ServerId::from_bytes(HOME),
                descriptor,
                source.sequence + 1,
                &Host(INCARNATION)
            )
            .is_err()
    );
    assert_eq!(source.query_sessions.queue_snapshot(), before);
    source.coordinator.origin_del(
        ServerId::from_bytes(HOME),
        descriptor,
        source.sequence,
        &Host(INCARNATION),
    )?;
    let after = source.query_sessions.queue_snapshot();
    assert_eq!(
        (
            after.query_snapshots(),
            after.query_rows(),
            after.query_bytes()
        ),
        (0, 0, 0)
    );
    Ok(())
}

#[test]
fn mailbox_query_incarnation_fencing_keeps_an_unchanged_suspended_cut() -> TestResult {
    use crate::e2ee::coordinator::tests::{HOME, INCARNATION};
    let (mut source, _, _, _) = paged_mailbox()?;
    let coordinator = *source.coordinator.server_id.as_bytes();
    source.coordinator.origin_reset(
        ServerId::from_bytes(HOME),
        coordinator,
        INCARNATION,
        &Host(INCARNATION),
    )?;
    assert_eq!(source.query_sessions.queue_snapshot().query_snapshots(), 1);
    source.coordinator.origin_reset(
        ServerId::from_bytes([199; 16]),
        coordinator,
        [198; 16],
        &Host([198; 16]),
    )?;
    assert_eq!(source.query_sessions.queue_snapshot().query_snapshots(), 1);
    source.coordinator.origin_reset(
        ServerId::from_bytes(HOME),
        coordinator,
        [198; 16],
        &Host([198; 16]),
    )?;
    let after = source.query_sessions.queue_snapshot();
    assert_eq!(
        (
            after.query_snapshots(),
            after.query_rows(),
            after.query_bytes()
        ),
        (0, 0, 0)
    );
    Ok(())
}
