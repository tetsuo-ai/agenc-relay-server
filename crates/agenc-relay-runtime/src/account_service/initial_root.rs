//! Registered private account operations share the OPAQUE actor's replay and commit barrier.

use super::*;
use crate::bridge::crypto::InitialRootSealJob;
use crate::state_core::durable::claim_replays::{CLAIM_REPLAY_SECONDS, ClaimReplay};
use agenc_relay_auth::{
    InitialRootServiceEnvelope, InitialRootServiceResponse, initial_root::DurableClaimReplay,
};
use agenc_relay_types::SessionId;

const REGISTERED_CLAIM_VERSION: u16 = 3;
const MAX_IDLE_RETIREMENTS: usize = 32;

fn trusted_now(context: &StateCoreContext) -> Option<u64> {
    context
        .utc_now()
        .ok()
        .filter(|wall| context.drift().accepts_wall(context.now(), *wall))
        .map(|wall| wall.get())
}

/// Reconstruct only the compact owner and authenticated deadline. The protected
/// HPKE request/response remain solely in their original exact-result row.
pub(crate) fn claim_replay_metadata(
    key: &StoredKey,
    value: &PersistentRecordValue,
) -> Result<Option<ClaimReplay>, RuntimeError> {
    if key.as_bytes().len() != 16 || value.record_kind() != REQUEST_RESULT_KIND {
        return Ok(None);
    }
    let body =
        ProtocolRecordBody::decode(TableId::RequestResult, REQUEST_RESULT_KIND, value.body())?;
    if !body
        .canonical_object()
        .starts_with(&REGISTERED_CLAIM_VERSION.to_be_bytes())
    {
        // The previous account API used its own version and had no private expiry.
        return if value.expires_at().is_none() {
            Ok(None)
        } else {
            Err(RuntimeError::InvalidValue)
        };
    }
    let expires = value
        .expires_at()
        .filter(|n| *n >= CLAIM_REPLAY_SECONDS)
        .ok_or(RuntimeError::InvalidValue)?;
    let (owner, result) = RegisteredClaim::decode(body.canonical_object())?;
    let request = InitialRootServiceEnvelope::parse(result.request)
        .map_err(|_| RuntimeError::InvalidValue)?;
    let response = InitialRootServiceResponse::parse(result.response)
        .map_err(|_| RuntimeError::InvalidValue)?;
    let claim = agenc_relay_crypto::InitialRootExchange::Claim;
    let id = request.client_request_id();
    if request.message_kind() != claim
        || response.response_kind() != claim
        || response.client_request_id() != id
        || key.as_bytes() != id.as_bytes()
    {
        return Err(RuntimeError::InvalidValue);
    }
    Ok(Some(ClaimReplay {
        account: owner.account,
        id,
        expires,
    }))
}

pub(super) struct GuardedStartRelease {
    pub(super) request: RequestContext,
    pub(super) sealed: Box<agenc_relay_auth::GuardedAccountStart>,
    pub(super) reservation: Option<CreationReservation>,
}

impl GuardedStartRelease {
    pub(super) fn cleanup(&self) -> TransactionCleanup {
        TransactionCleanup::creation(self.sealed.transaction_id(), self.reservation.clone())
    }
}

impl PendingRead {
    pub(super) fn guarded_cleanup(&self) -> Option<TransactionCleanup> {
        match self {
            Self::GuardedResult(start) | Self::GuardedTransaction { start, .. } => {
                Some(start.cleanup())
            }
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct RegisteredClaim {
    account: AccountId,
    session: SessionId,
    generation: Generation,
}

impl RegisteredClaim {
    fn encode(self, result: &RequestResultRecord) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 + 24 + 16 + 8 + REQUEST_RESULT_BYTES);
        bytes.extend_from_slice(&REGISTERED_CLAIM_VERSION.to_be_bytes());
        bytes.extend_from_slice(self.account.to_text().as_bytes());
        bytes.extend_from_slice(self.session.as_bytes());
        bytes.extend_from_slice(&self.generation.get().to_be_bytes());
        bytes.extend_from_slice(&result.encode());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<(Self, RequestResultRecord), RuntimeError> {
        let (binding, result) = bytes
            .split_at_checked(2 + 24 + 16 + 8)
            .ok_or(RuntimeError::InvalidValue)?;
        let mut fields = RequestResultCursor::new(binding);
        if fields.read_u16()? != REGISTERED_CLAIM_VERSION {
            return Err(RuntimeError::InvalidValue);
        }
        let account = AccountId::parse_wire_bytes(&fields.read_array::<24>()?)
            .map_err(|_| RuntimeError::InvalidValue)?;
        let session = SessionId::from_bytes(fields.read_array()?);
        let generation =
            Generation::new(fields.read_u64()?).map_err(|_| RuntimeError::InvalidValue)?;
        fields.finish()?;
        let stored = RequestResultRecord::decode(result)?;
        if stored.terminal != RequestTerminal::Accepted || stored.terminal_account.is_some() {
            return Err(RuntimeError::InvalidValue);
        }
        Ok((
            Self {
                account,
                session,
                generation,
            },
            stored,
        ))
    }
}

impl AccountServiceCoordinator {
    pub(super) fn read_guarded_result(
        &mut self,
        context: &mut StateCoreContext,
        start: GuardedStartRelease,
    ) -> Option<CarrierCompletion> {
        let generation = start.request.generation;
        let close = CarrierCompletion::closed(generation, start.request.carrier_generation);
        let cleanup = start.cleanup();
        let stage = || request_result_key(start.request.envelope.client_request_id());
        if self.connections.contains_key(&generation)
            && let Ok(key) = stage()
            && let Ok(id) =
                context.submit_storage_read(ReadPlan::exact(TableId::RequestResult, key))
            && !self.reads.contains_key(&id)
        {
            self.reads.insert(id, PendingRead::GuardedResult(start));
            return None;
        }
        let _queued = self.queue_transaction_cleanup(
            context,
            generation,
            LiveTransactionClass::Creation,
            cleanup,
        );
        Some(close)
    }

    pub(super) fn read_guarded_transaction(
        &mut self,
        context: &mut StateCoreContext,
        start: GuardedStartRelease,
        result: ReadResult,
    ) -> Result<Vec<CarrierCompletion>, RuntimeError> {
        let request = &start.request;
        let key = request_result_key(request.envelope.client_request_id())?;
        let value = read_optional_persistent(context, result, TableId::RequestResult, &key)?
            .ok_or(RuntimeError::InvalidValue)?;
        if value.record_kind() != REQUEST_RESULT_KIND {
            return Err(RuntimeError::InvalidValue);
        }
        let body =
            ProtocolRecordBody::decode(TableId::RequestResult, REQUEST_RESULT_KIND, value.body())?;
        let replay = RequestResultRecord::decode(body.canonical_object())?;
        if replay.route != request.route
            || replay.request != *request.envelope.as_bytes()
            || replay.terminal != RequestTerminal::Start
            || replay.terminal_account.is_some()
        {
            return Err(RuntimeError::InvalidValue);
        }
        let key = StoredKey::new(start.sealed.transaction_id().as_bytes().to_vec())?;
        let id = context.submit_storage_read(ReadPlan::exact(TableId::AuthTransaction, key))?;
        if self
            .reads
            .insert(
                id,
                PendingRead::GuardedTransaction {
                    start,
                    replay: Box::new(replay),
                },
            )
            .is_some()
        {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(Vec::new())
    }

    pub(super) fn release_guarded_start(
        &mut self,
        context: &mut StateCoreContext,
        start: GuardedStartRelease,
        replay: RequestResultRecord,
        result: ReadResult,
    ) -> Result<Vec<CarrierCompletion>, RuntimeError> {
        let key = StoredKey::new(start.sealed.transaction_id().as_bytes().to_vec())?;
        let value = read_optional_persistent(context, result, TableId::AuthTransaction, &key)?
            .ok_or(RuntimeError::InvalidValue)?;
        if value.record_kind() != CREATION_TRANSACTION_KIND {
            return Err(RuntimeError::InvalidValue);
        }
        let utc = context.utc_now().map_err(|_| RuntimeError::InvalidValue)?;
        start
            .sealed
            .live_record_expiry(context.now(), utc)
            .map_err(|_| RuntimeError::InvalidValue)?;
        let saved_request = InitialRootServiceEnvelope::parse(replay.request)
            .map_err(|_| RuntimeError::InvalidValue)?;
        let saved_response = InitialRootServiceResponse::parse(replay.response)
            .map_err(|_| RuntimeError::InvalidValue)?;
        let record = agenc_relay_auth::GuardedCreationTransactionRecord::parse(value.body())
            .map_err(|_| RuntimeError::InvalidValue)?;
        let transaction_id = start.sealed.transaction_id();
        if !self
            .connections
            .get(&start.request.generation)
            .is_some_and(|c| {
                c.route == start.request.route
                    && c.creation.initial_root_family() == Some(InitialRootCarrier::GuardedCreation)
            })
        {
            return Err(RuntimeError::InvalidValue);
        }
        let transaction = start
            .sealed
            .into_committed(
                &saved_request,
                &saved_response,
                &record,
                context.head().account_service_response_count,
            )
            .map_err(|_| RuntimeError::InvalidValue)?;
        let request = start.request;
        let frames = self.response_frames(context, &request, saved_response.as_bytes(), false)?;
        let completion = self
            .install_creation(
                context,
                request.generation,
                request.carrier_generation,
                transaction,
                start.reservation,
            )
            .ok_or(RuntimeError::InvalidValue)?;
        if !completion.close && context.send_to(request.generation, frames).is_err() {
            context
                .timers_mut()
                .cancel(TimerKind::Reservation, TimedId::Transaction(transaction_id));
            self.transaction_owners.remove(&transaction_id);
            let _discarded = self.take_live_transaction(
                request.generation,
                LiveTransactionClass::Creation,
                transaction_id,
            );
            return Err(RuntimeError::MemoryExhausted);
        }
        Ok(vec![completion])
    }
    /// A quiet relay also releases elapsed exact responses. Batches are small and
    /// their memory charges remain held until the normal commit callback applies.
    pub(crate) fn retire_claim_results(
        &self,
        context: &mut StateCoreContext,
    ) -> Result<(), RuntimeError> {
        if self.pending_authority.is_some()
            || context.pending_len() != 0
            || context.in_flight()
            || context.is_quiescing()
        {
            return Ok(());
        }
        let Some(now) = trusted_now(context) else {
            return Ok(());
        };
        let writes: Vec<_> = context
            .index()
            .expired_claim_replays(now, MAX_IDLE_RETIREMENTS)
            .map(|id| {
                AccountServiceDurableWrite::delete(TableId::RequestResult, request_result_key(id)?)
            })
            .collect::<Result<_, _>>()?;
        if !writes.is_empty() {
            let plan = context
                .domain()
                .plan_account_service_checkpoint()
                .map_err(|_| RuntimeError::InvalidValue)?;
            if !matches!(
                context.stage_durable_with_account_service(
                    plan,
                    FanoutRequest::new(Vec::new(), Vec::new())?,
                    None,
                    0,
                    writes,
                ),
                Ok(StageAccepted::Staged { .. })
            ) {
                return Err(RuntimeError::InvalidValue);
            }
        }
        Ok(())
    }

    pub(super) fn queue_claim(
        &mut self,
        context: &StateCoreContext,
        request: RequestContext,
        opened: OpenedClaim,
    ) -> Result<Vec<CarrierCompletion>, RuntimeError> {
        let scope = self.registered_claim(context, request.generation)?;
        self.push_ready_seal(ReadySeal::Claim {
            request,
            scope,
            opened,
        })?;
        Ok(Vec::new())
    }

    pub(super) fn prepare_claim(
        &self,
        context: &StateCoreContext,
        request: RequestContext,
        scope: RegisteredClaim,
        opened: OpenedClaim,
        count: u64,
    ) -> Result<(PendingCrypto, RuntimeCryptoJob), CarrierCompletion> {
        let close = CarrierCompletion::closed(request.generation, request.carrier_generation);
        if self.registered_claim(context, request.generation).ok() != Some(scope) {
            return Err(close);
        }
        let (cut, record) = context
            .initial_root_admission(scope.account, scope.generation)
            .map_err(|_| close)?;
        let job = InitialRootSealJob::new(opened, scope.account, record, count);
        Ok((
            PendingCrypto::ClaimSeal {
                request,
                scope,
                cut,
            },
            RuntimeCryptoJob::InitialRootSeal(Box::new(job)),
        ))
    }

    // agenc-review: focus owner=runtime reviewed=2026-11-25 reason=the refreshed registration cut, shared counter, claim decision, timed local replay and remote response form one atomic storage batch
    pub(super) fn stage_claim(
        &mut self,
        context: &mut StateCoreContext,
        request: RequestContext,
        scope: RegisteredClaim,
        cut: InitialRootCut,
        prepared: Box<PreparedClaim>,
    ) -> Result<(), RuntimeError> {
        if self.registered_claim(context, request.generation)? != scope
            || context.head().account_service_response_count.checked_add(1)
                != Some(prepared.next_response_count())
        {
            return Err(RuntimeError::InvalidValue);
        }
        let mut writes = Vec::new();
        writes
            .try_reserve_exact(3)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        let now = trusted_now(context).ok_or(RuntimeError::InvalidValue)?;
        let id = request.envelope.client_request_id();
        if context
            .index()
            .holds(TableId::RequestResult, &request_result_key(id)?)
        {
            return Err(RuntimeError::InvalidValue);
        }
        if let Some(expired) = context.index().claim_replay_room(scope.account, now)? {
            writes.push(AccountServiceDurableWrite::delete(
                TableId::RequestResult,
                request_result_key(expired)?,
            )?);
        }
        let expires = now
            .checked_add(CLAIM_REPLAY_SECONDS)
            .ok_or(RuntimeError::Overflow)?;
        let plan = context.plan_initial_root_choice(cut, prepared.new_choice(), &mut writes)?;
        let revision = plan.resulting_revision().get();
        let response = prepared.bytes_for_commit();
        let retained = RequestResultRecord {
            route: request.route,
            terminal: RequestTerminal::Accepted,
            terminal_account: None,
            request: *request.envelope.as_bytes(),
            response: *response,
        };
        writes.push(store_timed_request_result(
            revision,
            id,
            scope.encode(&retained),
            Some(expires),
        )?);
        context.join_remote_account_response(
            request.generation,
            revision,
            response,
            None,
            &mut writes,
        )?;
        // Local ciphertext is released from the exact recorded operation after the commit callback.
        let fanout = FanoutRequest::new(Vec::new(), Vec::new())?;
        if !matches!(
            context.stage_durable_with_account_service(
                plan,
                fanout,
                Some(StagedOrigin::silent(request.generation)),
                1,
                writes
            ),
            Ok(StageAccepted::Staged { .. })
        ) {
            return Err(RuntimeError::InvalidValue);
        }
        self.pending_authority = Some(PendingAuthority::Claim {
            request,
            scope,
            prepared,
        });
        Ok(())
    }

    pub(super) fn read_committed_claim(
        &mut self,
        context: &mut StateCoreContext,
        request: RequestContext,
        scope: RegisteredClaim,
        prepared: Box<PreparedClaim>,
    ) -> Result<(), RuntimeError> {
        let key = request_result_key(request.envelope.client_request_id())?;
        let read = context.submit_storage_read(ReadPlan::exact(TableId::RequestResult, key))?;
        if self
            .reads
            .insert(
                read,
                PendingRead::CommittedClaim {
                    request,
                    scope,
                    prepared,
                },
            )
            .is_some()
        {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(())
    }

    pub(crate) fn require_live_claim_result(
        context: &StateCoreContext,
        expires: Option<u64>,
    ) -> Result<(), RuntimeError> {
        match trusted_now(context).zip(expires) {
            Some((now, deadline)) if now < deadline => Ok(()),
            _ => Err(RuntimeError::InvalidValue),
        }
    }

    pub(super) fn release_claim(
        &mut self,
        context: &mut StateCoreContext,
        request: RequestContext,
        scope: RegisteredClaim,
        prepared: Box<PreparedClaim>,
        result: ReadResult,
    ) -> Result<Vec<CarrierCompletion>, RuntimeError> {
        let key = request_result_key(request.envelope.client_request_id())?;
        let value = read_optional_persistent(context, result, TableId::RequestResult, &key)?
            .ok_or(RuntimeError::InvalidValue)?;
        if value.record_kind() != REQUEST_RESULT_KIND
            || self.registered_claim(context, request.generation)? != scope
        {
            return Err(RuntimeError::InvalidValue);
        }
        let body =
            ProtocolRecordBody::decode(TableId::RequestResult, REQUEST_RESULT_KIND, value.body())?;
        let (stored_scope, stored) = RegisteredClaim::decode(body.canonical_object())?;
        if stored_scope != scope
            || stored.route != request.route
            || stored.request != *request.envelope.as_bytes()
        {
            return Err(RuntimeError::InvalidValue);
        }
        // The durable readback can complete after the admitted result's delivery window.
        Self::require_live_claim_result(context, value.expires_at())?;
        let saved_request = InitialRootServiceEnvelope::parse(stored.request)
            .map_err(|_| RuntimeError::InvalidValue)?;
        let saved_response = InitialRootServiceResponse::parse(stored.response)
            .map_err(|_| RuntimeError::InvalidValue)?;
        let record = context.initial_root_claim(scope.account)?;
        let verified = prepared
            .into_committed(DurableClaimReplay {
                request: &saved_request,
                response: &saved_response,
                response_count: context.head().account_service_response_count,
                record: record.as_ref(),
            })
            .map_err(|_| RuntimeError::InvalidValue)?;
        let frames = self.response_frames(context, &request, verified.as_bytes(), true)?;
        context
            .send_to(request.generation, frames)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        Ok(vec![CarrierCompletion::finished(
            request.generation,
            request.carrier_generation,
            ResultClass::Ok,
        )])
    }

    pub(super) fn registered_claim(
        &self,
        context: &StateCoreContext,
        connection: ConnectionGeneration,
    ) -> Result<RegisteredClaim, RuntimeError> {
        let bound = context
            .sessions()
            .connection(connection)
            .filter(|entry| !entry.sink_gone())
            .and_then(|entry| entry.session())
            .ok_or(RuntimeError::InvalidValue)?;
        let session = context
            .domain()
            .session(bound.user_id)
            .filter(|s| s.session_id() == bound.session_id)
            .ok_or(RuntimeError::InvalidValue)?;
        let account = session.account_id().ok_or(RuntimeError::InvalidValue)?;
        let generation = session.account_session_generation();
        if !context
            .domain()
            .account(account)
            .is_some_and(|a| a.session_generation() == generation)
        {
            return Err(RuntimeError::InvalidValue);
        }
        let scope = RegisteredClaim {
            account,
            session: bound.session_id,
            generation,
        };
        let owner = self
            .connections
            .get(&connection)
            .ok_or(RuntimeError::InvalidValue)?;
        if owner.claim_scope.is_some_and(|original| original != scope) {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(scope)
    }

    pub(super) fn replay_initial_root(
        &mut self,
        context: &mut StateCoreContext,
        request: RequestContext,
        stored: RequestResultRecord,
    ) -> Result<Vec<CarrierCompletion>, RuntimeError> {
        let Some(RequestKind::InitialRoot(expected)) = request.expected_message_kind() else {
            return Err(RuntimeError::InvalidValue);
        };
        let response = InitialRootServiceResponse::parse(stored.response)
            .map_err(|_| RuntimeError::InvalidValue)?;
        if stored.route != request.route
            || stored.request != *request.envelope.as_bytes()
            || stored.terminal_account.is_some()
            || response.response_kind() != expected
            || response.client_request_id() != request.envelope.client_request_id()
        {
            return Err(RuntimeError::InvalidValue);
        }
        context.bind_verified_root_replay(request.generation, response.as_bytes());
        let frames = self.response_frames(context, &request, response.as_bytes(), true)?;
        context
            .send_to(request.generation, frames)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        Ok(vec![CarrierCompletion::finished(
            request.generation,
            request.carrier_generation,
            ResultClass::Ok,
        )])
    }

    pub(super) fn replay_registered_claim(
        &mut self,
        context: &mut StateCoreContext,
        request: RequestContext,
        bytes: &[u8],
    ) -> Result<Vec<CarrierCompletion>, RuntimeError> {
        let current = self.registered_claim(context, request.generation)?;
        let (original, stored) = RegisteredClaim::decode(bytes)?;
        if current != original {
            return Err(RuntimeError::InvalidValue);
        }
        self.replay_initial_root(context, request, stored)
    }
}

#[cfg(test)]
pub(crate) fn test_registered_receipt(
    account: AccountId,
    revision: u64,
    expires: u64,
    request: &InitialRootServiceEnvelope,
    response: &[u8; ACCOUNT_SERVICE_RESPONSE_BYTES],
) -> Result<AccountServiceDurableWrite, RuntimeError> {
    let version = Generation::new(1).map_err(|_| RuntimeError::InvalidValue)?;
    let scope = RegisteredClaim {
        session: SessionId::from_bytes([15; 16]),
        account,
        generation: version,
    };
    let original = RequestResultRecord {
        route: ConnectionRoute {
            origin_id: OriginId::from_bytes([11; 16]),
            origin_generation: version,
            connection_id: ConnectionId::from_bytes([12; 16]),
            connection_nonce: [13; 32],
        },
        terminal: RequestTerminal::Accepted,
        terminal_account: None,
        request: *request.as_bytes(),
        response: *response,
    };
    store_timed_request_result(
        revision,
        request.client_request_id(),
        scope.encode(&original),
        Some(expires),
    )
}
