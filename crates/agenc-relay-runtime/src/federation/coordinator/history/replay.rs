//! Exact original selection replay and its one permitted terminal expiry transition.

use agenc_relay_domain::federation::{MutationContext, OperationKey, OriginKey};
use agenc_relay_domain::{ChannelNameValue, HistorySelection};
use agenc_relay_federation_wire::{
    DecodeBudget, FederationHash32, OperationDescriptor, RequestHeader, SchemaObject,
    federation_object_id,
};
use agenc_relay_storage::history_records::{HistoryCoordinatorResultRecord, HistoryResultStatus};
use agenc_relay_types::{ChannelInstanceId, ServerId, SessionId, UserId};

use super::{
    FederationCoordinator, FreshRequest, LinkId, Prepared, Reading, ResultArm, StateCoreContext,
    Violation, page_positions, read_or_prepare, request, stage, wall_milliseconds,
};
use crate::state_core::session::BoundSession;

pub(in crate::federation::coordinator) fn restore(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    descriptor: OperationDescriptor,
    record: HistoryCoordinatorResultRecord,
) -> Result<(), Violation> {
    let fresh = request_of(coordinator, peer, descriptor, &record)?;
    let mut reading = Reading {
        link,
        peer,
        fresh,
        record,
        selection: None,
        replay_snapshot: None,
        previous_cursor: None,
        replay: true,
        terminal_transition: false,
    };
    if let HistoryResultStatus::Expired { result_object_id } = reading.record.status {
        let bytes = terminal_bytes(coordinator, &reading)?;
        if federation_object_id(&bytes).as_bytes() != &result_object_id {
            return Err(Violation::Codec);
        }
        coordinator.send_result(context, link, peer, descriptor, &bytes);
        return Ok(());
    }
    let restored = restore_snapshot(context, &reading);
    match restored {
        Ok(snapshot) => {
            reading.replay_snapshot = Some(snapshot);
            read_or_prepare(coordinator, context, reading)
        }
        Err(_) => expire(coordinator, context, reading),
    }
}

fn request_of(
    coordinator: &FederationCoordinator,
    peer: ServerId,
    descriptor: OperationDescriptor,
    record: &HistoryCoordinatorResultRecord,
) -> Result<FreshRequest, Violation> {
    let mut budget = DecodeBudget::new(2_048, 64);
    let object = SchemaObject::decode_exact(
        "FederationRequest",
        &record.request.request_object,
        &mut budget,
    )
    .map_err(|_| Violation::Codec)?;
    let header = RequestHeader::from_object(&object).map_err(|_| Violation::Codec)?;
    let hash = federation_object_id(&record.request.request_object);
    request::check_descriptor(coordinator, peer, &descriptor, &header, hash)?;
    if header.replay_key.to_bytes() != record.request.replay_key
        || hash.as_bytes() != &record.request.request_object_id
        || header.request_id.as_bytes() != &record.request.request_id
        || header.opcode != agenc_relay_types::FederationOpcode::HistoryQuery
    {
        return Err(Violation::Codec);
    }
    let key = OperationKey {
        origin: OriginKey {
            home_server_id: peer,
            server_incarnation: header.replay_key.server_incarnation,
            origin_id: header.replay_key.origin_id,
        },
        generation: header.replay_key.origin_generation,
        sequence: header.replay_key.operation_sequence,
    };
    Ok(FreshRequest {
        key,
        header,
        descriptor,
        request_object_id: FederationHash32::from_bytes(record.request.request_object_id),
        bound: None,
        command: None,
        mutation: MutationContext::default(),
        charge: None,
    })
}

fn restore_snapshot(
    context: &StateCoreContext,
    reading: &Reading,
) -> Result<crate::state_core::history::HistorySnapshot, Violation> {
    if wall_milliseconds(context)? >= reading.record.page.deadline_unix_milliseconds {
        return Err(Violation::Origin);
    }
    let auth = reading.record.page.authorization;
    let bound = BoundSession {
        session_id: SessionId::from_bytes(auth.session_id),
        user_id: UserId::from_bytes(auth.user_id),
        capability_hash: [0; 32],
    };
    let selection =
        HistorySelection::new(page_positions(reading)?).map_err(|_| Violation::Codec)?;
    context
        .history_restore_selection(
            bound,
            ChannelInstanceId::from_bytes(reading.record.page.channel_id),
            auth,
            selection,
            ChannelNameValue::parse(&reading.record.page.channel_name)
                .map_err(|_| Violation::Codec)?,
            reading.record.page.state_cut,
        )
        .map_err(|_| Violation::Origin)
}

pub(super) fn expire(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    mut reading: Reading,
) -> Result<(), Violation> {
    let bytes = terminal_bytes(coordinator, &reading)?;
    reading.terminal_transition = reading.record.status == HistoryResultStatus::Available;
    reading.record.status = HistoryResultStatus::Expired {
        result_object_id: *federation_object_id(&bytes).as_bytes(),
    };
    reading.selection = None;
    reading.replay_snapshot = None;
    stage(
        coordinator,
        context,
        Prepared {
            reading,
            bytes,
            _permit: None,
        },
    )
}

fn terminal_bytes(
    coordinator: &FederationCoordinator,
    reading: &Reading,
) -> Result<Vec<u8>, Violation> {
    request::encode_result(
        coordinator,
        &reading.fresh,
        &ResultArm::HistoryExpired {
            original_result_object_id: reading.record.original_result_object_id,
        },
        None,
        Vec::new(),
    )
}
