//! Every private inbox is installed at most once, and never over work the
//! core still owes an answer for.
#![forbid(unsafe_code)]

use agenc_ircd_admin::AdminAuditPhase;

use super::support::audit_event;
use super::*;
use crate::runtime_config::{
    PreparedReload, ReloadCoreRequest, RuntimeConfigHandle, reload_channel,
};
use crate::state_core::admin::{AdminCoreRequest, admin_core_channel};
use crate::test_support::{golden_config, golden_parts, golden_snapshot};

fn reload_inbox(
    handle: &RuntimeConfigHandle,
) -> TestResult<crate::runtime_config::ReloadCoreInbox> {
    let admission = Arc::new(crate::admission::TransportAdmission::new(
        handle.load().rates(),
        1,
        Arc::new(crate::budget::MemoryBudget::new(64 * 1_024 * 1_024)),
        Box::new(crate::clock::SystemMonotonicClock::start()),
    )?);
    let (_port, inbox) = reload_channel(handle.clone(), admission);
    Ok(inbox)
}

#[test]
fn the_admin_inbox_installs_once_and_never_over_an_unanswered_commit() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![9; 4096])?;
    let _port = fixture.install_admin_port()?;
    assert!(fixture.install_admin_port().is_err());

    let mut fixture = StateCoreFixture::new(vec![9; 4096])?;
    let state = fixture.state_mut()?;
    let (reply, _response) = oneshot::channel();
    let exit = state.step_admin_request(AdminCoreRequest::CommitAudit {
        event: Box::new(audit_event(AdminAuditPhase::Observed, b"MOTD")?),
        reply,
    });
    assert!(exit.is_none());
    let (_port, inbox) = admin_core_channel();
    assert!(matches!(
        state.install_admin_inbox(inbox),
        Err(crate::RuntimeError::InvalidValue)
    ));
    assert!(!state.admin_open);
    Ok(())
}

#[test]
fn the_federation_and_maintenance_inboxes_install_once() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let state = fixture.state_mut()?;
    let (_federation, receiver) = mpsc::channel(1);
    assert!(state.install_federation_inbox(receiver).is_ok());
    let (_second, receiver) = mpsc::channel(1);
    assert!(matches!(
        state.install_federation_inbox(receiver),
        Err(crate::RuntimeError::InvalidValue)
    ));
    let (_maintenance, receiver) = mpsc::channel(1);
    assert!(state.install_maintenance_inbox(receiver).is_ok());
    let (_second, receiver) = mpsc::channel(1);
    assert!(matches!(
        state.install_maintenance_inbox(receiver),
        Err(crate::RuntimeError::InvalidValue)
    ));
    Ok(())
}

#[test]
fn the_reload_inbox_installs_once_even_after_its_port_closed() -> TestResult {
    let handle = RuntimeConfigHandle::new(golden_snapshot("AgenC", None)?);
    let mut fixture = StateCoreFixture::new(vec![9; 4096])?;
    let state = fixture.state_mut()?;
    assert!(state.install_reload_inbox(reload_inbox(&handle)?).is_ok());
    assert!(matches!(
        state.install_reload_inbox(reload_inbox(&handle)?),
        Err(crate::RuntimeError::InvalidValue)
    ));
    // The run loop marks the inbox closed once every port is gone; the
    // handle it installed still fences a second installation.
    state.reload_open = false;
    assert!(matches!(
        state.install_reload_inbox(reload_inbox(&handle)?),
        Err(crate::RuntimeError::InvalidValue)
    ));
    Ok(())
}

#[test]
fn the_reload_inbox_never_installs_over_a_pending_activation() -> TestResult {
    let handle = RuntimeConfigHandle::new(golden_snapshot("AgenC", None)?);
    let mut fixture = StateCoreFixture::new(vec![9; 4096])?;
    let state = fixture.state_mut()?;
    let prepared = PreparedReload::new(
        &handle.load(),
        golden_config()?,
        golden_parts("AgenC", Some("Pending"))?,
    )?;
    let (reply, _response) = oneshot::channel();
    let exit = state.step_reload_request(ReloadCoreRequest::ActivateSignal {
        prepared: Box::new(prepared),
        reply,
    });
    assert!(exit.is_none());
    assert!(matches!(
        state.install_reload_inbox(reload_inbox(&handle)?),
        Err(crate::RuntimeError::InvalidValue)
    ));
    assert!(state.reload_handle.is_none());
    Ok(())
}
