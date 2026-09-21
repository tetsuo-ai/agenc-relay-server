//! Exact federation responses joined to remote account-service transactions.

use super::projector::RequestBinding;
use super::{StateCoreContext, durable::AccountServiceDurableWrite};
use crate::RuntimeError;
use crate::connection::ConnectionGeneration;
use crate::federation::codec::results::ResultArm;
use agenc_relay_federation_wire::RequestCorrelation;
use agenc_relay_federation_wire::{
    CanonicalEncode, FederationHash32, RequestHeader, ResultHeader, SchemaObject,
    federation_object_id, result_kind_permitted,
};
use agenc_relay_storage::federation_records::{
    COORDINATOR_RESULT_KIND, CoordinatorResultRecord, request_result_key,
};
use agenc_relay_storage::{PersistentRecordValue, StoredKey, TableId};
use agenc_relay_types::EventId;

pub(crate) struct RemoteResultBinding {
    header: RequestHeader,
    request_object_id: FederationHash32,
    origin: AccountServiceDurableWrite,
    prepared: Option<(u64, Vec<u8>)>,
}

pub(crate) struct CommittedRemoteResult {
    pub(crate) header: RequestHeader,
    pub(crate) request_object_id: FederationHash32,
    pub(crate) bytes: Vec<u8>,
}

impl StateCoreContext {
    pub(crate) fn bind_remote_account_result(
        &mut self,
        generation: ConnectionGeneration,
        header: RequestHeader,
        request_object_id: FederationHash32,
        origin: AccountServiceDurableWrite,
    ) {
        self.remote_account_results.insert(
            generation,
            RemoteResultBinding {
                header,
                request_object_id,
                origin,
                prepared: None,
            },
        );
    }

    pub(crate) fn remote_account_result_writes(
        &mut self,
        generation: ConnectionGeneration,
        revision: u64,
        arm: &ResultArm,
        replies: Vec<SchemaObject>,
    ) -> Result<Vec<AccountServiceDurableWrite>, RuntimeError> {
        if !self.remote_account_results.contains_key(&generation) {
            return Ok(Vec::new());
        }
        let completion_event_id = if matches!(arm, ResultArm::Committed { .. }) {
            let mut bytes = [0; 16];
            self.entropy_mut()
                .fill_exact(&mut bytes)
                .map_err(|_| RuntimeError::InvalidValue)?;
            Some(EventId::from_bytes(bytes))
        } else {
            None
        };
        let binding = self
            .remote_account_results
            .get_mut(&generation)
            .ok_or(RuntimeError::InvalidValue)?;
        let bytes = binding.encode_result(arm, replies, completion_event_id)?;
        let record = CoordinatorResultRecord {
            request_id: *binding.header.request_id.as_bytes(),
            request_object_id: *binding.request_object_id.as_bytes(),
            result_object_id: *federation_object_id(&bytes).as_bytes(),
            result_object: bytes.clone(),
            completion_event_id: completion_event_id.map(|id| *id.as_bytes()),
            resulting_state_generation: revision,
        };
        let result = row(
            TableId::RequestResult,
            request_result_key(binding.header.replay_key.to_bytes())?,
            COORDINATOR_RESULT_KIND,
            revision,
            record.encode()?,
        )?;
        let origin = binding.origin_at(revision)?;
        binding.prepared = Some((self.head.storage_commit_sequence, bytes));
        if let Some(completion_event_id) = completion_event_id {
            let header = binding.header;
            self.set_request_binding(RequestBinding {
                home: header.replay_key.home_server_id,
                correlation: RequestCorrelation {
                    replay_key: header.replay_key,
                    request_id: header.request_id,
                },
                completion_event_id,
            });
        }
        Ok(vec![result, origin])
    }

    /// Local carriers have no binding and add no federation rows.
    pub(crate) fn join_remote_account_response(
        &mut self,
        generation: ConnectionGeneration,
        revision: u64,
        response: &[u8],
        semantic: Option<ResultArm>,
        writes: &mut Vec<AccountServiceDurableWrite>,
    ) -> Result<(), RuntimeError> {
        let Some(binding) = self.remote_account_results.get(&generation) else {
            return Ok(());
        };
        let (arm, replies) = crate::remote_accounts::sealed_result(
            self.server_prefix(),
            binding.header.opcode,
            response,
            semantic,
        )?;
        writes.extend(self.remote_account_result_writes(generation, revision, &arm, replies)?);
        Ok(())
    }

    pub(crate) fn take_remote_account_result(
        &mut self,
        generation: ConnectionGeneration,
    ) -> Option<CommittedRemoteResult> {
        let binding = self.remote_account_results.get(&generation)?;
        let (staged_after, _) = binding.prepared.as_ref()?;
        let key = request_result_key(binding.header.replay_key.to_bytes()).ok()?;
        if self.head.storage_commit_sequence <= *staged_after
            || !self.index.holds(TableId::RequestResult, &key)
        {
            return None;
        }
        let binding = self.remote_account_results.remove(&generation)?;
        Some(CommittedRemoteResult {
            header: binding.header,
            request_object_id: binding.request_object_id,
            bytes: binding.prepared?.1,
        })
    }

    pub(crate) fn take_committed_remote_results(&mut self) -> Vec<CommittedRemoteResult> {
        let generations: Vec<_> = self.remote_account_results.keys().copied().collect();
        generations
            .into_iter()
            .filter_map(|generation| self.take_remote_account_result(generation))
            .collect()
    }

    pub(crate) fn forget_remote_account_result(&mut self, generation: ConnectionGeneration) {
        // A closed transport cannot discard a result whose batch still owes a receipt.
        if self
            .remote_account_results
            .get(&generation)
            .is_some_and(|binding| binding.prepared.is_none())
        {
            self.remote_account_results.remove(&generation);
        }
    }

    pub(crate) fn reject_remote_account_results(&mut self) {
        self.remote_account_results
            .retain(|_, binding| binding.prepared.is_none());
    }
}

impl RemoteResultBinding {
    fn encode_result(
        &self,
        arm: &ResultArm,
        replies: Vec<SchemaObject>,
        completion_event_id: Option<EventId>,
    ) -> Result<Vec<u8>, RuntimeError> {
        if !result_kind_permitted(self.header.opcode, arm.kind()) {
            return Err(RuntimeError::InvalidValue);
        }
        let header = ResultHeader {
            network_id: self.header.network_id,
            replay_key: self.header.replay_key,
            request_id: self.header.request_id,
            request_object_id: self.request_object_id,
            completion_event_id,
            result_kind: arm.kind(),
        };
        let object = arm
            .to_object()
            .and_then(|arm| header.build(&arm, replies))
            .map_err(|_| RuntimeError::InvalidValue)?;
        Ok(object
            .encode_canonical()
            .map_err(|_| RuntimeError::InvalidValue)?
            .as_slice()
            .to_vec())
    }

    fn origin_at(&self, revision: u64) -> Result<AccountServiceDurableWrite, RuntimeError> {
        let AccountServiceDurableWrite::Put {
            table,
            key,
            plaintext,
        } = &self.origin
        else {
            return Err(RuntimeError::InvalidValue);
        };
        let value = PersistentRecordValue::decode(*table, plaintext)?;
        row(
            *table,
            key.clone(),
            value.record_kind(),
            revision,
            value.body().to_vec(),
        )
    }
}

fn row(
    table: TableId,
    key: StoredKey,
    kind: u16,
    revision: u64,
    body: Vec<u8>,
) -> Result<AccountServiceDurableWrite, RuntimeError> {
    let value =
        PersistentRecordValue::new(table, kind, revision, 0, None, Vec::new(), body)?.encode()?;
    AccountServiceDurableWrite::put(table, key, value)
}
