//! Bounded history selections, asynchronous body reads, and metadata-only commits.

mod replay;

use std::collections::BTreeMap;

use agenc_ircd_crypto::{QueryCursorKey, authenticate_query_cursor};
use agenc_ircd_domain::federation::{OriginKey, RetainedRequest};
use agenc_ircd_domain::{DomainError, HistoryQuery};
use agenc_ircd_federation_wire::{CanonicalEncode, federation_object_id};
use agenc_ircd_storage::TableId;
use agenc_ircd_storage::federation_records::request_result_key;
use agenc_ircd_storage::history_records::{
    HISTORY_COORDINATOR_RESULT_KIND, HistoryCoordinatorResultRecord, HistoryPageMetadata,
    HistoryRequestIdentity, HistoryResultStatus,
};
use agenc_ircd_types::ServerId;

use super::convert::HistoryRequest;
use super::request::{self, FreshRequest};
use super::{FederationCoordinator, PendingCommit, Violation};
use crate::bridge::{StorageReadCompletionMessage, StorageReadId};
use crate::federation::LinkId;
use crate::federation::codec::{
    history as codec, operations::FederatedOperation, results::ResultArm,
};
use crate::state_core::StateCoreContext;
use crate::state_core::history::{HISTORY_PAGE_MESSAGES, HistorySnapshot};

const MAX_QUERIES: usize = 256;
const IDLE_MILLISECONDS: u64 = 60_000;
const TOTAL_MILLISECONDS: u64 = 600_000;

pub(super) struct HistoryQueries {
    key: QueryCursorKey,
    nonce: [u8; 16],
    counter: u64,
    cursors: BTreeMap<[u8; 32], Selection>,
    pub(super) metadata_read: Option<StorageReadId>,
    pending: Option<(StorageReadId, Reading)>,
    retention: crate::federation::history_retention::Retention,
}

struct Selection {
    snapshot: HistorySnapshot,
    query: HistoryQuery,
    origin: OriginKey,
    origin_generation: u64,
    token: [u8; 32],
    offset: usize,
    page: u32,
    created: u64,
    touched: u64,
    created_wall: u64,
}

struct Reading {
    link: LinkId,
    peer: ServerId,
    fresh: FreshRequest,
    record: HistoryCoordinatorResultRecord,
    selection: Option<Selection>,
    replay_snapshot: Option<HistorySnapshot>,
    previous_cursor: Option<[u8; 32]>,
    replay: bool,
    terminal_transition: bool,
}

pub(super) struct Prepared {
    reading: Reading,
    bytes: Vec<u8>,
    _permit: Option<crate::budget::MemoryPermit>,
}

impl HistoryQueries {
    pub(super) fn new(key: [u8; 32], nonce: [u8; 16]) -> Self {
        Self {
            key: QueryCursorKey::from_bytes(key),
            nonce,
            counter: 0,
            cursors: BTreeMap::new(),
            metadata_read: None,
            pending: None,
            retention: crate::federation::history_retention::Retention::default(),
        }
    }

    pub(super) fn busy(&self) -> bool {
        self.metadata_read.is_some() || self.pending.is_some()
    }

    pub(super) fn owns(&self, read: StorageReadId) -> bool {
        self.pending.as_ref().is_some_and(|(id, _)| *id == read) || self.retention.owns(read)
    }

    fn expire(&mut self, now: u64) {
        self.cursors.retain(|_, selection| {
            now.saturating_sub(selection.created) < TOTAL_MILLISECONDS
                && now.saturating_sub(selection.touched) < IDLE_MILLISECONDS
        });
    }

    fn cursor(&mut self, selection: &Selection) -> Result<[u8; 32], Violation> {
        self.counter = self.counter.checked_add(1).ok_or(Violation::Ceiling)?;
        let selector = codec::selector_object(selection.query.selector())
            .and_then(|value| value.as_object().encode_canonical())
            .map_err(|_| Violation::Codec)?;
        let authorization = codec::authorization_object(selection.snapshot.authorization)
            .and_then(|value| value.encode_canonical())
            .map_err(|_| Violation::Codec)?;
        let mut binding = Vec::with_capacity(512);
        binding.extend_from_slice(b"history\0");
        binding.extend_from_slice(&self.nonce);
        binding.extend_from_slice(&self.counter.to_be_bytes());
        binding.extend_from_slice(selection.origin.home_server_id.as_bytes());
        binding.extend_from_slice(selection.origin.server_incarnation.as_bytes());
        binding.extend_from_slice(selection.origin.origin_id.as_bytes());
        binding.extend_from_slice(&selection.origin_generation.to_be_bytes());
        binding.extend_from_slice(selection.snapshot.channel_id.as_bytes());
        binding.extend_from_slice(&selection.token);
        binding.extend_from_slice(&selection.snapshot.snapshot_state_generation.to_be_bytes());
        binding.extend_from_slice(&selection.page.to_be_bytes());
        binding.extend_from_slice(&selection.query.limit().to_be_bytes());
        binding.extend_from_slice(selector.as_slice());
        binding.extend_from_slice(authorization.as_slice());
        authenticate_query_cursor(&self.key, &binding)
            .map(|mac| *mac.expose_for_storage())
            .map_err(|_| Violation::Codec)
    }
}

pub(super) fn begin(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    fresh: FreshRequest,
    query: HistoryRequest,
    operation: FederatedOperation,
) -> Result<(), Violation> {
    coordinator.history.expire(context.now().get());
    let selection = match take_selection(coordinator, context, &fresh, &query) {
        Ok(selection) => selection,
        Err(_) if query.cursor.is_some() => {
            return request::finish_without_plan(
                coordinator,
                context,
                link,
                peer,
                fresh,
                ResultArm::Failed {
                    code: "QUERY_EXPIRED".to_owned(),
                    context: String::new(),
                },
                Vec::new(),
            );
        }
        Err(error) => {
            return request::finish_failed(coordinator, context, link, peer, fresh, error);
        }
    };
    let request_object = fresh
        .header
        .build(&operation.to_object().map_err(|_| Violation::Codec)?)
        .and_then(|object| object.encode_canonical())
        .map_err(|_| Violation::Codec)?;
    if federation_object_id(request_object.as_slice()) != fresh.request_object_id {
        return Err(Violation::Codec);
    }
    let record = record_for(
        coordinator,
        &fresh,
        &selection,
        request_object.as_slice().to_vec(),
    )?;
    let reading = Reading {
        link,
        peer,
        fresh,
        record,
        selection: Some(selection),
        replay_snapshot: None,
        previous_cursor: query.cursor,
        replay: false,
        terminal_transition: false,
    };
    read_or_prepare(coordinator, context, reading)
}

fn take_selection(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    fresh: &FreshRequest,
    query: &HistoryRequest,
) -> Result<Selection, DomainError> {
    if let Some(cursor) = query.cursor {
        let selection = coordinator
            .history
            .cursors
            .get(&cursor)
            .ok_or(DomainError::BadState)?;
        if selection.origin != fresh.key.origin
            || selection.origin_generation != fresh.key.generation
            || selection.query != query.query
            || selection.snapshot.channel_id != query.channel_id
            || selection.snapshot.authorization.session_id != *query.bound.session_id.as_bytes()
            || context.history_recheck(&selection.snapshot).is_err()
        {
            return Err(DomainError::BadState);
        }
        return coordinator
            .history
            .cursors
            .remove(&cursor)
            .ok_or(DomainError::BadState);
    }
    if coordinator.history.cursors.len() >= MAX_QUERIES
        || coordinator
            .history
            .cursors
            .values()
            .any(|selection| selection.origin == fresh.key.origin)
    {
        return Err(DomainError::ServerBusy);
    }
    let snapshot = context
        .history_select(query.bound, query.channel_id, query.query)
        .map_err(|_| DomainError::Forbidden)?;
    let mut token = [0; 32];
    context
        .entropy_mut()
        .fill_exact(&mut token)
        .map_err(|_| DomainError::ServerBusy)?;
    let now = context.now().get();
    let created_wall = wall_milliseconds(context).map_err(|_| DomainError::WallClockUnavailable)?;
    Ok(Selection {
        snapshot,
        query: query.query,
        origin: fresh.key.origin,
        origin_generation: fresh.key.generation,
        token,
        offset: 0,
        page: 0,
        created: now,
        touched: now,
        created_wall,
    })
}

fn record_for(
    coordinator: &mut FederationCoordinator,
    fresh: &FreshRequest,
    selection: &Selection,
    request_object: Vec<u8>,
) -> Result<HistoryCoordinatorResultRecord, Violation> {
    let end = selection
        .offset
        .saturating_add(HISTORY_PAGE_MESSAGES)
        .min(selection.snapshot.references().len());
    let next_cursor = if end < selection.snapshot.references().len() {
        Some(coordinator.history.cursor(selection)?)
    } else {
        None
    };
    Ok(HistoryCoordinatorResultRecord {
        request: HistoryRequestIdentity {
            replay_key: fresh.header.replay_key.to_bytes(),
            request_id: *fresh.header.request_id.as_bytes(),
            request_object_id: *fresh.request_object_id.as_bytes(),
            request_object,
        },
        original_result_object_id: [0; 32],
        status: HistoryResultStatus::Available,
        page: HistoryPageMetadata {
            authorization: selection.snapshot.authorization,
            channel_id: *selection.snapshot.channel_id.as_bytes(),
            channel_name: selection.snapshot.channel_name.canonical().to_owned(),
            snapshot_token: selection.token,
            state_cut: selection.snapshot.snapshot_state_generation,
            page_sequence: selection.page,
            next_cursor,
            selected: selection
                .snapshot
                .references()
                .get(selection.offset..end)
                .ok_or(Violation::Codec)?
                .to_vec(),
            created_unix_milliseconds: selection.created_wall,
            deadline_unix_milliseconds: selection
                .created_wall
                .checked_add(TOTAL_MILLISECONDS)
                .ok_or(Violation::Ceiling)?,
        },
    })
}

fn snapshot(reading: &Reading) -> Result<&HistorySnapshot, Violation> {
    reading
        .selection
        .as_ref()
        .map(|selection| &selection.snapshot)
        .or(reading.replay_snapshot.as_ref())
        .ok_or(Violation::Codec)
}

fn page_positions(reading: &Reading) -> Result<Vec<agenc_ircd_domain::HistoryPosition>, Violation> {
    reading
        .record
        .page
        .selected
        .iter()
        .map(|row| {
            agenc_ircd_domain::HistoryPosition::new(
                row.channel_sequence,
                agenc_ircd_types::MessageId::from_bytes(row.message_id),
                row.received_unix_milliseconds,
            )
            .map_err(|_| Violation::Codec)
        })
        .collect()
}

fn read_or_prepare(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    reading: Reading,
) -> Result<(), Violation> {
    let positions = page_positions(&reading)?;
    if positions.is_empty() {
        return prepare(coordinator, context, reading, None);
    }
    let read_id = context
        .history_read(snapshot(&reading)?, &positions)
        .map_err(|_| Violation::Ceiling)?;
    coordinator.history.pending = Some((read_id, reading));
    Ok(())
}

pub(super) fn read_completed(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    message: StorageReadCompletionMessage,
) {
    if coordinator.history.retention.owns(message.read_id) {
        cleanup_completed(coordinator, context, message);
        return;
    }
    let Some((_, reading)) = coordinator.history.pending.take() else {
        return;
    };
    let positions = page_positions(&reading);
    let materialized = positions.and_then(|positions| {
        let result = message.result.as_ref().map_err(|_| Violation::Codec)?;
        context
            .history_materialize(snapshot(&reading)?, &positions, result)
            .map_err(|_| Violation::Codec)
    });
    let link = reading.link;
    let peer = reading.peer;
    let result = match materialized {
        Ok(materialized) => prepare(coordinator, context, reading, Some(materialized)),
        Err(_) if reading.replay => replay::expire(coordinator, context, reading),
        Err(_) => request::finish_failed(
            coordinator,
            context,
            reading.link,
            reading.peer,
            reading.fresh,
            DomainError::BadState,
        ),
    };
    if let Err(violation) = result {
        coordinator.fail_link(context, link, peer, violation);
    }
}

fn prepare(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    mut reading: Reading,
    materialized: Option<crate::state_core::history::HistoryMaterialized>,
) -> Result<(), Violation> {
    context
        .history_recheck(snapshot(&reading)?)
        .map_err(|_| Violation::Origin)?;
    let messages = materialized
        .as_ref()
        .map_or(&[][..], |materialized| materialized.messages());
    let arm = ResultArm::HistoryPage(
        codec::page_object(&reading.record.page, messages).map_err(|_| Violation::Codec)?,
    );
    let bytes = request::encode_result(coordinator, &reading.fresh, &arm, None, Vec::new())?;
    let digest = *federation_object_id(&bytes).as_bytes();
    if reading.replay {
        if digest != reading.record.original_result_object_id {
            return replay::expire(coordinator, context, reading);
        }
        coordinator.send_result(
            context,
            reading.link,
            reading.peer,
            reading.fresh.descriptor,
            &bytes,
        );
        return Ok(());
    }
    reading.record.original_result_object_id = digest;
    let permit = materialized.map(|page| page.into_permit());
    stage(
        coordinator,
        context,
        Prepared {
            reading,
            bytes,
            _permit: permit,
        },
    )
}

fn stage(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    prepared: Prepared,
) -> Result<(), Violation> {
    let plan = context
        .domain()
        .plan_account_service_checkpoint()
        .map_err(|_| Violation::Ceiling)?;
    let revision = plan.resulting_revision().get();
    let reading = &prepared.reading;
    let mut writes = vec![request::row(
        TableId::RequestResult,
        HISTORY_COORDINATOR_RESULT_KIND,
        request_result_key(reading.record.request.replay_key).map_err(|_| Violation::Codec)?,
        revision,
        reading.record.encode().map_err(|_| Violation::Codec)?,
    )?];
    if !reading.replay {
        writes.push(super::origin::origin_row(
            coordinator,
            reading.fresh.key.origin,
            reading
                .fresh
                .key
                .sequence
                .checked_add(1)
                .ok_or(Violation::Ceiling)?,
            revision,
        )?);
    }
    let fanout = crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())
        .map_err(|_| Violation::Ceiling)?;
    if context
        .stage_durable_with_account_service(plan, fanout, None, 0, writes)
        .is_err()
    {
        rejected(coordinator, prepared);
        return Err(Violation::Ceiling);
    }
    coordinator.pending = Some(PendingCommit::History(Box::new(prepared)));
    Ok(())
}

pub(super) fn committed(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    prepared: Prepared,
) {
    let Prepared {
        mut reading,
        bytes,
        _permit,
    } = prepared;
    if !reading.replay {
        let _ = coordinator
            .origins
            .commit_request(reading.fresh.key, reading.fresh.header.request_id);
        coordinator.retained.insert(
            reading.fresh.key,
            RetainedRequest {
                request_id: reading.fresh.header.request_id,
                request_object_id: *reading.fresh.request_object_id.as_bytes(),
            },
        );
        coordinator.counters.requests_committed =
            coordinator.counters.requests_committed.saturating_add(1);
    }
    let channel = agenc_ircd_types::ChannelInstanceId::from_bytes(reading.record.page.channel_id);
    let count_result = if !reading.replay {
        context.history_result_retained(channel, true)
    } else if reading.terminal_transition {
        context.history_result_retained(channel, false)
    } else {
        Ok(())
    };
    if count_result.is_err() {
        coordinator.fail_link(context, reading.link, reading.peer, Violation::Codec);
        return;
    }
    if reading.record.status == HistoryResultStatus::Available
        && snapshot(&reading).is_ok_and(|snapshot| context.history_recheck(snapshot).is_err())
    {
        reading.replay = true;
        let link = reading.link;
        let peer = reading.peer;
        if let Err(error) = replay::expire(coordinator, context, reading) {
            coordinator.fail_link(context, link, peer, error);
        }
        return;
    }
    if let (Some(cursor), Some(mut selection)) =
        (reading.record.page.next_cursor, reading.selection.take())
    {
        selection.offset = selection
            .offset
            .saturating_add(reading.record.page.selected.len());
        selection.page = selection.page.saturating_add(1);
        selection.touched = context.now().get();
        coordinator.history.cursors.insert(cursor, selection);
    }
    coordinator.send_result(
        context,
        reading.link,
        reading.peer,
        reading.fresh.descriptor,
        &bytes,
    );
}

pub(super) fn rejected(coordinator: &mut FederationCoordinator, prepared: Prepared) {
    if let (Some(cursor), Some(selection)) =
        (prepared.reading.previous_cursor, prepared.reading.selection)
    {
        coordinator.history.cursors.insert(cursor, selection);
    }
}

fn wall_milliseconds(context: &StateCoreContext) -> Result<u64, Violation> {
    context
        .utc_now()
        .map_err(|_| Violation::Ceiling)?
        .get()
        .checked_mul(1_000)
        .ok_or(Violation::Ceiling)
}

pub(super) use replay::restore;

impl FederationCoordinator {
    pub(crate) fn retain_history(&mut self, context: &mut StateCoreContext) {
        self.history.expire(context.now().get());
        if self.pending.is_none() && !self.history.busy() {
            self.history.retention.begin(context);
        }
    }
}

fn operation_key(
    bytes: [u8; 64],
) -> Result<agenc_ircd_domain::federation::OperationKey, Violation> {
    let (home, rest) = bytes.split_at(16);
    let (incarnation, rest) = rest.split_at(16);
    let (origin, rest) = rest.split_at(16);
    let (generation, sequence) = rest.split_at(8);
    Ok(agenc_ircd_domain::federation::OperationKey {
        origin: OriginKey {
            home_server_id: ServerId::from_bytes(home.try_into().map_err(|_| Violation::Codec)?),
            server_incarnation: agenc_ircd_types::ServerIncarnation::from_bytes(
                incarnation.try_into().map_err(|_| Violation::Codec)?,
            ),
            origin_id: agenc_ircd_types::OriginId::from_bytes(
                origin.try_into().map_err(|_| Violation::Codec)?,
            ),
        },
        generation: u64::from_be_bytes(generation.try_into().map_err(|_| Violation::Codec)?),
        sequence: u64::from_be_bytes(sequence.try_into().map_err(|_| Violation::Codec)?),
    })
}

fn cleanup_completed(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    message: StorageReadCompletionMessage,
) {
    coordinator.history.retention.completed();
    if coordinator.pending.is_some() || context.pending_len() != 0 {
        return;
    }
    let Ok(result) = message.result else {
        return;
    };
    let Ok(plan) = context.domain().plan_account_service_checkpoint() else {
        return;
    };
    let cleanup = coordinator.history.retention.prepare(
        context,
        &result,
        plan.resulting_revision().get(),
        HISTORY_COORDINATOR_RESULT_KIND,
        |bytes| {
            operation_key(*bytes)
                .ok()
                .and_then(|key| coordinator.origins.origin(&key.origin))
                .is_some_and(|origin| {
                    matches!(
                        origin.status,
                        agenc_ircd_domain::federation::OriginStatus::Deleted
                            | agenc_ircd_domain::federation::OriginStatus::Fenced
                    )
                })
        },
    );
    let Ok(mut cleanup) = cleanup else {
        return;
    };
    if cleanup.writes.is_empty() {
        coordinator.history.retention.committed(&cleanup);
        return;
    }
    let Ok(fanout) = crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new()) else {
        return;
    };
    if context
        .stage_durable_with_account_service(
            plan,
            fanout,
            None,
            0,
            std::mem::take(&mut cleanup.writes),
        )
        .is_ok()
    {
        coordinator.pending = Some(PendingCommit::HistoryCleanup(cleanup));
    }
}

pub(super) fn cleanup_committed(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    cleanup: crate::federation::history_retention::Cleanup,
) {
    for channel in &cleanup.deleted_available_channels {
        if context.history_result_retained(*channel, false).is_err() {
            return;
        }
    }
    for bytes in &cleanup.deleted {
        if let Ok(key) = operation_key(*bytes)
            && let Some(retained) = coordinator.retained.remove(&key)
        {
            coordinator
                .origins
                .retire_request_id(retained.request_id, key);
        }
    }
    coordinator.history.retention.committed(&cleanup);
}
