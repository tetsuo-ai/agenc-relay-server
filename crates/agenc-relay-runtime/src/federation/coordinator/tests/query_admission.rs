//! A real directory query must observe the configured shared query allowance.

#![forbid(unsafe_code)]

use super::*;
use crate::runtime_config::RuntimeConfigHandle;
use crate::test_support::{self, StateCoreFixture, TestResult};
use agenc_relay_domain::{CanonicalCommand, PlanDecision};

#[path = "query_lifetime.rs"]
mod lifetime;
pub(in crate::federation::coordinator) use lifetime::fixture as names_query_fixture;

#[test]
fn a_directory_query_observes_the_shared_session_snapshot_ceiling() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![7; 128])?;
    let config = test_support::golden_snapshot("directory-query", None)?;
    let _reload = fixture.install_reload_port(RuntimeConfigHandle::new(config))?;
    let context = fixture.context_mut()?;
    let user = test_support::seed_session(context, 1, "DirectoryQuota", None)?;
    let _sink = test_support::bind_live_session(
        context,
        1,
        user,
        test_support::negotiated_capabilities(&[])?,
        true,
    )?;
    let PlanDecision::Query(plan) =
        test_support::plan_live(context, user, &|| CanonicalCommand::list(Vec::new()))?
    else {
        return Err("LIST query plan".into());
    };
    let mut held = Vec::new();
    for _ in 0..4 {
        held.push(
            context
                .query_reservations(user.user_id)
                .reserve_snapshot(1, 0)?,
        );
    }
    assert_eq!(context.sessions().queue_snapshot().query_snapshots(), 4);
    assert!(
        context
            .prepare_query_snapshot(crate::connection::ConnectionGeneration::new(1), 1, 256)
            .is_err()
    );
    let identity = QueryIdentity {
        session_id: user.session_id,
        user_id: user.user_id,
        account: None,
        kind: FederationDirectoryQueryKind::List,
        arm: Vec::new(),
    };
    let scope = CursorScope {
        coordinator: ServerId::from_bytes([2; 16]),
        network_id: NetworkId::from_bytes([3; 32]),
    };
    let mut queries = Queries::new([4; 32], [5; 16]);
    assert!(
        matches!(
            queries.first_page(context, &scope, &identity, &plan),
            Err(DomainError::ServerBusy)
        ),
        "a valid FQUERY cannot bypass the same full session allowance"
    );
    drop(held);
    assert!(
        queries
            .first_page(context, &scope, &identity, &plan)
            .is_ok()
    );
    Ok(())
}
