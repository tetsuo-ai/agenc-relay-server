#![forbid(unsafe_code)]

//! COV-01: the channel-control account fence that runs before a target name is
//! looked up.
//!
//! The fence exists so that an unauthenticated client learns nothing about
//! whether a channel exists: it must refuse every channel-control command from
//! a guest and admit the same command from an account, without ever consulting
//! the name.

use agenc_ircd_client_wire::{
    ChannelControlCommand, PostRegistrationCommandKind, RegisteredCommandKind,
};
use agenc_ircd_domain::DomainError;

use super::super::require_channel_control_account;

/// Every channel-control kind is refused for a session with no account and
/// admitted for one with an account, and no other command family is affected
/// by the fence in either direction.
#[test]
fn channel_controls_need_an_account_and_no_other_family_does() {
    let controls = [
        ChannelControlCommand::Register,
        ChannelControlCommand::Unregister,
        ChannelControlCommand::History,
    ];
    for control in controls {
        let kind =
            RegisteredCommandKind::Public(PostRegistrationCommandKind::ChannelControl(control));
        assert_eq!(
            require_channel_control_account(kind, false),
            Err(DomainError::RegistrationRequired),
            "{control:?}"
        );
        assert_eq!(
            require_channel_control_account(kind, true),
            Ok(()),
            "{control:?}"
        );
    }

    // The nickname family is never fenced, with or without an account.
    for has_account in [false, true] {
        assert_eq!(
            require_channel_control_account(RegisteredCommandKind::Nickname, has_account),
            Ok(())
        );
    }
}
