#![forbid(unsafe_code)]

//! Transport-loss precedence regressions for the registration coordinator.

use std::error::Error;

use agenc_ircd_client_wire::{
    AccessTokenPolicy, REGISTRATION_TIMEOUT_MILLIS, RegistrationEvent, RegistrationPhase,
    RegistrationState,
};

#[test]
fn transport_close_wins_at_the_registration_deadline() -> Result<(), Box<dyn Error>> {
    let mut state = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;

    let actions = state.event(
        RegistrationEvent::TransportClosed,
        REGISTRATION_TIMEOUT_MILLIS,
    )?;

    assert!(actions.is_empty());
    assert_eq!(state.phase(), RegistrationPhase::Closed);
    Ok(())
}
