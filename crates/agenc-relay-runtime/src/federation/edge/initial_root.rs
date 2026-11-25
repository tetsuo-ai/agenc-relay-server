//! Optional account carriers keep the exact coordinator link that admitted the client.
#![forbid(unsafe_code)]

use agenc_relay_client_wire::{InitialRootCarrier, WireMessage};
use agenc_relay_federation_wire::{
    DecodeBudget, FederationProfile, InitialRootOperation, InitialRootRequest, SchemaObject,
};
use agenc_relay_types::FederationOpcode;

use super::request::{self, EdgeCompletion, PendingKind, PendingRequest, RemoteCarrierOutcome};
use super::{EdgeFederation, Violation};
use crate::connection::ConnectionGeneration;
use crate::federation::LinkId;
use crate::federation::codec::operations::FederatedOperation;
use crate::federation::codec::results::ResultArm;
use crate::state_core::StateCoreContext;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Carrier {
    GuardedStart,
    GuardedFinish,
    Claim,
}

impl Carrier {
    pub(crate) fn from_phase(family: InitialRootCarrier, finish: bool) -> Option<Self> {
        match (family, finish) {
            (InitialRootCarrier::GuardedCreation, false) => Some(Self::GuardedStart),
            (InitialRootCarrier::GuardedCreation, true) => Some(Self::GuardedFinish),
            (InitialRootCarrier::Claim, true) => Some(Self::Claim),
            (InitialRootCarrier::Claim, false) => None,
        }
    }
    pub(super) fn from_operation(operation: InitialRootOperation) -> Self {
        match operation {
            InitialRootOperation::ClaimedCreateStart => Self::GuardedStart,
            InitialRootOperation::Claim => Self::Claim,
        }
    }
    fn operation(self) -> Option<InitialRootOperation> {
        match self {
            Self::GuardedStart => Some(InitialRootOperation::ClaimedCreateStart),
            Self::GuardedFinish => None,
            Self::Claim => Some(InitialRootOperation::Claim),
        }
    }
    fn phase(self) -> (InitialRootCarrier, bool) {
        match self {
            Self::GuardedStart => (InitialRootCarrier::GuardedCreation, false),
            Self::GuardedFinish => (InitialRootCarrier::GuardedCreation, true),
            Self::Claim => (InitialRootCarrier::Claim, true),
        }
    }
    fn opcode(self) -> FederationOpcode {
        self.operation().map_or(
            FederationOpcode::AccountCreateFinish,
            InitialRootOperation::base_layout,
        )
    }
    pub(super) fn outcome(
        self,
        result: ResultArm,
        replies: &[WireMessage],
    ) -> RemoteCarrierOutcome {
        match (self, result) {
            (Self::GuardedFinish, arm) => request::carrier_outcome(arm, replies, false),
            (carrier, ResultArm::InitialRoot(op, bytes)) if carrier.operation() == Some(op) => {
                RemoteCarrierOutcome::Challenge(bytes.into_vec())
            }
            _ => RemoteCarrierOutcome::Failed { chunks: Vec::new() },
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct OwnedCarrier {
    pub(crate) carrier: Carrier,
    pub(crate) link: LinkId,
}

impl OwnedCarrier {
    pub(super) fn completion(
        self,
        generation: ConnectionGeneration,
        carrier_generation: u64,
        outcome: RemoteCarrierOutcome,
    ) -> EdgeCompletion {
        EdgeCompletion::InitialRoot {
            generation,
            carrier_generation,
            link: self.link,
            phase: self.carrier.phase(),
            outcome,
        }
    }

    pub(crate) fn send(
        self,
        edge: &mut EdgeFederation,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        carrier_generation: u64,
        bytes: &[u8],
    ) -> Result<(), Violation> {
        if !edge.network_available()
            || edge.initial_root_link() != Some(self.link)
            || edge.journal.retry.recovering
        {
            return Err(Violation::Phase);
        }
        let origin = edge
            .origins
            .get(&generation)
            .filter(|origin| !origin.deleted)
            .ok_or(Violation::Phase)?;
        let session = match self.carrier {
            Carrier::Claim if origin.account.is_some() => {
                Some(origin.session.ok_or(Violation::Phase)?.0)
            }
            Carrier::GuardedStart | Carrier::GuardedFinish if origin.session.is_none() => None,
            _ => return Err(Violation::Phase),
        };
        if bytes.len() != agenc_relay_types::ACCOUNT_SERVICE_ENVELOPE_BYTES as usize {
            return Err(Violation::Codec);
        }
        let opcode = self.carrier.opcode();
        if !origin.pending_updates.is_empty() {
            return request::defer_account_carrier(
                edge,
                context,
                generation,
                (opcode, Some(self)),
                bytes,
                self.carrier.phase().1,
                carrier_generation,
            );
        }
        let prepared = if let Some(operation) = self.carrier.operation() {
            request::prepare_encoded(edge, context, generation, opcode, |header| {
                InitialRootRequest {
                    operation,
                    layout: *header,
                    session,
                    envelope: bytes,
                }
                .encode(FederationProfile::InitialRoot)
            })?
        } else {
            let envelope = SchemaObject::decode_exact(
                "AccountServiceEnvelope",
                bytes,
                &mut DecodeBudget::new(8_192, 64),
            )
            .map_err(|_| Violation::Codec)?;
            request::prepare_request(
                edge,
                context,
                generation,
                &FederatedOperation::AccountService {
                    opcode,
                    session_id: None,
                    envelope,
                },
            )?
        };
        request::register_request(
            edge,
            context,
            generation,
            prepared,
            PendingKind::InitialRoot {
                carrier: self.carrier,
                link: Some(self.link),
                carrier_generation,
            },
        );
        Ok(())
    }
}

pub(super) fn request_extension(request: &PendingRequest) -> Option<InitialRootOperation> {
    match request.kind {
        PendingKind::InitialRoot { carrier, .. } => carrier.operation(),
        _ => None,
    }
}

pub(super) fn can_send(edge: &EdgeFederation, request: &PendingRequest) -> bool {
    match request.kind {
        PendingKind::InitialRoot { link, .. } => link.is_some() && edge.initial_root_link() == link,
        _ => true,
    }
}
