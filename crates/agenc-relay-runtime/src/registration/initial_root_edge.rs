//! Select the same connection-scoped account transport for assembly, forwarding and reply.
#![forbid(unsafe_code)]

use super::EdgeCarrier;
use crate::account_service::AccountCommand;
use crate::connection::ConnectionGeneration;
use crate::federation::LinkId;
use crate::federation::edge::{
    EdgeFederation,
    initial_root::{Carrier, OwnedCarrier},
};
use crate::state_core::StateCoreContext;
use agenc_relay_client_wire::{AccountCarrierKind, AccountTransfer, InitialRootCarrier};
use agenc_relay_types::FederationOpcode;

impl EdgeCarrier {
    pub(super) fn pin_initial_root(&mut self, link: LinkId) -> bool {
        *self.root_link.get_or_insert(link) == link
    }

    pub(super) fn transfer(&mut self, kind: AccountCommand) -> Option<&mut AccountTransfer> {
        match kind {
            AccountCommand::Base(AccountCarrierKind::Create)
                if self.creation.initial_root_family().is_none() =>
            {
                Some(&mut self.creation)
            }
            AccountCommand::Base(AccountCarrierKind::Create) => None,
            AccountCommand::Base(AccountCarrierKind::Credentials) => Some(&mut self.credentials),
            AccountCommand::InitialRoot(InitialRootCarrier::GuardedCreation)
                if self.root_link.is_some() =>
            {
                self.creation.select_guarded_creation().ok()?;
                Some(&mut self.creation)
            }
            AccountCommand::InitialRoot(InitialRootCarrier::Claim) if self.root_link.is_some() => {
                Some(self.claim.get_or_insert_with(|| {
                    AccountTransfer::initial_root(InitialRootCarrier::Claim)
                }))
            }
            AccountCommand::InitialRoot(_) => None,
        }
    }
}

pub(super) fn forward(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    origin: (ConnectionGeneration, u64),
    kind: AccountCommand,
    finish: bool,
    link: Option<LinkId>,
    envelope: &[u8],
) -> bool {
    let (generation, carrier_generation) = origin;
    let opcode = match (kind, finish) {
        (AccountCommand::Base(AccountCarrierKind::Create), false) => {
            FederationOpcode::AccountCreateStart
        }
        (AccountCommand::Base(AccountCarrierKind::Create), true) => {
            FederationOpcode::AccountCreateFinish
        }
        (AccountCommand::Base(AccountCarrierKind::Credentials), false) => {
            FederationOpcode::CredentialChangeStart
        }
        (AccountCommand::Base(AccountCarrierKind::Credentials), true) => {
            FederationOpcode::CredentialChangeFinish
        }
        (AccountCommand::InitialRoot(family), _) => {
            let Some((carrier, link)) = Carrier::from_phase(family, finish).zip(link) else {
                return false;
            };
            return (OwnedCarrier { carrier, link })
                .send(edge, context, generation, carrier_generation, envelope)
                .is_ok();
        }
    };
    edge.send_account_carrier(
        context,
        generation,
        opcode,
        envelope,
        finish,
        carrier_generation,
    )
}
