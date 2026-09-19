//! A reload that cannot be prepared or audited never activates.
#![forbid(unsafe_code)]

use super::harness::{CoreReply, Session, drive};
use super::*;
use crate::runtime_config::{PreparedReload, ReloadPreparationInbox, reload_preparation_channel};
use crate::test_support::{
    StateCoreFixture, TestResult, golden_config, golden_parts, golden_snapshot,
};

const REHASH: &str = "REHASH :reload now";

fn install_reload(
    session: &mut Session,
) -> TestResult<(ReloadPreparationInbox, RuntimeConfigHandle)> {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let handle = RuntimeConfigHandle::new(golden_snapshot("AgenC", None)?);
    let (activation, _) = fixture.install_reload_port(handle.clone())?;
    let (reload, preparation) = reload_preparation_channel(activation);
    drop(fixture);
    session.owner.reload = Some(reload);
    Ok((preparation, handle))
}

/// Sends REHASH, answers its preparation with a changed configuration, and
/// lets the scripted core answer `replies`.
async fn rehash_prepared(
    session: &mut Session,
    preparation: &mut ReloadPreparationInbox,
    handle: &RuntimeConfigHandle,
    replies: &[CoreReply],
) -> TestResult {
    let prepared = PreparedReload::new(
        &handle.load(),
        golden_config()?,
        golden_parts("Changed", None)?,
    )?;
    let line = signed_line(0, REHASH)?;
    let Session {
        owner,
        core,
        root,
        generation,
        ..
    } = session;
    let work = async {
        tokio::join!(owner.line(*generation, &line, root), async {
            if let Some(request) = preparation.recv().await {
                request.send(Ok(prepared));
            }
        });
    };
    drive(work, core, replies).await
}

#[tokio::test]
async fn a_reload_nobody_can_prepare_is_unavailable_and_observed_rejected() -> TestResult {
    let mut session = Session::authenticated().await?;
    let (preparation, _handle) = install_reload(&mut session)?;
    drop(preparation);
    let reply = session.command(0, REHASH, &[]).await?;
    assert_eq!(
        reply,
        "FAIL REHASH STORAGE_UNAVAILABLE :Administrative reload unavailable"
    );

    let (metrics, _log) = session.observe();
    session.command(1, REHASH, &[]).await?;
    let reloads = metrics
        .snapshot(crate::observe::metrics::MetricsView::Operator)
        .counters
        .into_iter()
        .filter(|(key, _)| key.name == crate::observe::metrics::MetricName::Reloads)
        .map(|(_, count)| count)
        .sum::<u64>();
    assert_eq!(reloads, 1);
    Ok(())
}

#[tokio::test]
async fn a_prepared_reload_whose_intent_is_refused_never_activates() -> TestResult {
    let mut session = Session::authenticated().await?;
    let (mut preparation, handle) = install_reload(&mut session)?;
    let refused = [CoreReply::Next(Err(AdminCoreFailure::Busy))];
    rehash_prepared(&mut session, &mut preparation, &handle, &refused).await?;
    assert_eq!(
        session.text()?,
        "FAIL REHASH BUSY :Administrative action busy"
    );
    assert_eq!(&*handle.load().display_name(), "AgenC");
    Ok(())
}

#[tokio::test]
async fn a_prepared_reload_without_an_audit_time_never_activates() -> TestResult {
    let mut session = Session::authenticated().await?;
    let (mut preparation, handle) = install_reload(&mut session)?;
    session.break_wall_clock();
    rehash_prepared(&mut session, &mut preparation, &handle, &[]).await?;
    assert_eq!(
        session.text()?,
        "FAIL REHASH STORAGE_UNAVAILABLE :Administrative audit unavailable"
    );
    assert_eq!(&*handle.load().display_name(), "AgenC");
    Ok(())
}
