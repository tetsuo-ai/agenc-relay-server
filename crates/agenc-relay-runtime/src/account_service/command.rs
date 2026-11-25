//! Exact IRC carrier chosen at registration, retained through response framing.

use agenc_relay_client_wire::{AccountCarrierKind, InitialRootCarrier};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AccountCommand {
    Base(AccountCarrierKind),
    InitialRoot(InitialRootCarrier),
}

#[cfg(test)]
mod tests {
    use agenc_relay_client_wire::{AccountCarrierAction, AccountCarrierPhase, InitialRootCarrier};

    #[test]
    fn opted_in_ready_frames_keep_the_exact_family_and_phase() -> Result<(), crate::RuntimeError> {
        let cases = [
            (
                InitialRootCarrier::GuardedCreation,
                AccountCarrierPhase::Start,
                "ACCTCREATE READY CLAIMSTART 4726",
            ),
            (
                InitialRootCarrier::GuardedCreation,
                AccountCarrierPhase::Finish,
                "ACCTCREATE READY FINISH 4726",
            ),
            (
                InitialRootCarrier::Claim,
                AccountCarrierPhase::Finish,
                "ACCTROOT READY CLAIM 4726",
            ),
        ];
        for (family, phase, expected) in cases {
            let frame = super::super::render_account_action(
                "relay.example",
                family,
                AccountCarrierAction::Ready(phase),
            )?;
            assert_eq!(
                format!("{} {}", frame.command(), frame.middle().join(" ")),
                expected
            );
            assert_eq!(frame.trailing(), None);
        }
        assert!(
            agenc_relay_client_wire::WireMessage::new("relay.example", "ACCTROOT", &["END"], None)
                .is_err()
        );
        assert!(
            super::super::render_account_action(
                "relay.example",
                InitialRootCarrier::Claim,
                AccountCarrierAction::ResponseStart(AccountCarrierPhase::Start)
            )
            .is_err()
        );
        Ok(())
    }
}

impl From<AccountCarrierKind> for AccountCommand {
    fn from(kind: AccountCarrierKind) -> Self {
        Self::Base(kind)
    }
}

impl From<InitialRootCarrier> for AccountCommand {
    fn from(carrier: InitialRootCarrier) -> Self {
        Self::InitialRoot(carrier)
    }
}

impl AccountCommand {
    pub(crate) const fn command(self) -> &'static str {
        match self {
            Self::Base(kind) => kind.command(),
            Self::InitialRoot(family) => family.command(),
        }
    }

    pub(super) const fn unavailable(self) -> &'static str {
        match self {
            Self::Base(AccountCarrierKind::Create)
            | Self::InitialRoot(InitialRootCarrier::GuardedCreation) => {
                "Account creation unavailable"
            }
            Self::Base(AccountCarrierKind::Credentials) => "Credential change unavailable",
            Self::InitialRoot(InitialRootCarrier::Claim) => "Account root claim unavailable",
        }
    }
}
