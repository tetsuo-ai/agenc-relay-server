//! A READY committed under a base epoch the host no longer covers installs
//! the owner without activating the stream.

#![forbid(unsafe_code)]

use super::*;

#[test]
fn a_ready_committed_under_another_base_epoch_activates_nothing() -> TestResult {
    let mut sync = Sync::new()?;
    let page = frames(&sync.resume(0, None).map_err(|fault| format!("{fault:?}"))?)?;
    let (cut, _, _) = begin_cut(&page)?;
    let actions = sync.frame(CompanionFrame::StateCut {
        active: false,
        server_id: COORDINATOR,
        snapshot_token: cut.token,
        state_generation: cut.state_generation,
        delivery_generation: cut.delivery_generation,
        snapshot_digest: cut.digest,
    })?;
    let Some(Action::Stage { work, .. }) = actions.into_iter().next() else {
        return Err("expected the staged READY".into());
    };
    sync.harness.coordinator.set_pending(work);
    let committed = sync
        .harness
        .coordinator
        .batch_applied(Some(999))
        .map_err(|fault| format!("{fault:?}"))?;
    assert!(matches!(committed, Some(Committed::Lines(lines)) if lines.is_empty()));
    assert!(!sync.harness.coordinator.accepting_requests(home()));
    Ok(())
}
