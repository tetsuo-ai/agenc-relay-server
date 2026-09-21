#![forbid(unsafe_code)]

//! Deadline-precedence regressions for account-service carrier entry points.

use std::error::Error;

use agenc_relay_client_wire::{
    ACCOUNT_IDLE_TIMEOUT_MILLIS, AccountCarrierKind, AccountTransfer, AuthTransportError,
};

#[test]
fn account_deadline_precedes_tag_validation() -> Result<(), Box<dyn Error>> {
    let mut transfer = AccountTransfer::new(AccountCarrierKind::Create)?;
    transfer.client("START", Some("4726"), false, 0)?;

    assert!(matches!(
        transfer.client("DATA", None, true, ACCOUNT_IDLE_TIMEOUT_MILLIS),
        Err(AuthTransportError::TimedOut)
    ));
    Ok(())
}
