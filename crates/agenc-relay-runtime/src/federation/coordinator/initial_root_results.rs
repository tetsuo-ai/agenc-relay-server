//! Retain both outer request identity and exact committed response for the authenticated origin.
#![forbid(unsafe_code)]

use super::{FederationCoordinator, Violation};
use crate::state_core::StateCoreContext;
use crate::state_core::durable::federated_claims::{Key, WEEK};
use agenc_relay_federation_wire::{
    DecodeBudget, FederationProfile, InitialRootResult, OperationDescriptor, RequestHeader,
    ResultHeader,
};
use agenc_relay_types::{FederationResultKind, NetworkId, ServerId};
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};

#[derive(Default)]
pub(super) struct Admissions(Arc<Mutex<BTreeSet<Key>>>);

pub(super) struct Intake {
    key: Key,
    owners: Arc<Mutex<BTreeSet<Key>>>,
    _backing: crate::budget::MemoryPermit,
    pub(super) deadline: u64,
}

impl Drop for Intake {
    fn drop(&mut self) {
        self.owners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.key);
    }
}

pub(crate) fn trusted_now(context: &StateCoreContext) -> Option<u64> {
    context.trusted_federation_utc().ok()
}

pub(super) fn replayable(context: &StateCoreContext, key: &Key) -> Result<bool, Violation> {
    let row = context
        .index()
        .federated_claim(key)
        .ok_or(Violation::Origin)?;
    Ok(row.may_replay(trusted_now(context).ok_or(Violation::Origin)?))
}

impl FederationCoordinator {
    pub(super) fn admit_initial_root(
        &mut self,
        context: &StateCoreContext,
        header: &RequestHeader,
    ) -> Result<Option<Arc<Intake>>, Violation> {
        let deadline = trusted_now(context)
            .and_then(|now| now.checked_add(WEEK))
            .ok_or(Violation::Origin)?;
        let key = header.replay_key.to_bytes();
        let mut owners = self.root_intakes.0.lock().map_err(|_| Violation::Ceiling)?;
        let pending = owners
            .iter()
            .filter(|other| context.index().federated_claim(other).is_none());
        match context.index().require_federated_claim_room(&key, pending) {
            Ok(()) => {}
            Err(crate::RuntimeError::LimitExceeded) => return Ok(None),
            Err(_) => return Err(Violation::Origin),
        }
        let Ok(backing) = context.reserve_output_backing(512) else {
            return Ok(None);
        };
        if !owners.insert(key) {
            return Err(Violation::Origin);
        }
        let slot = Arc::new(Intake {
            key,
            deadline,
            owners: self.root_intakes.0.clone(),
            _backing: backing,
        });
        Ok(Some(slot))
    }
}

pub(super) fn authorized_output<'a>(
    context: &StateCoreContext,
    network: NetworkId,
    peer: ServerId,
    descriptor: &OperationDescriptor,
    encoded: &'a [u8],
) -> Result<std::borrow::Cow<'a, [u8]>, Violation> {
    let mut budget = DecodeBudget::new(1 << 20, 4_096);
    let checked = InitialRootResult::decode(FederationProfile::InitialRoot, encoded, &mut budget)
        .map_err(|_| Violation::Codec)?;
    if !matches_request(network, peer, descriptor, &checked.layout) {
        return Err(Violation::Origin);
    }
    let now = trusted_now(context).ok_or(Violation::Phase)?;
    let key = checked.layout.replay_key.to_bytes();
    if let Some(held) = context.index().federated_claim(&key) {
        if !held.may_replay(now) {
            return Ok(std::borrow::Cow::Owned(expired_output(checked.layout)?));
        }
        if context.index().holds_federated_claim(&key, encoded) {
            return Ok(std::borrow::Cow::Borrowed(encoded));
        }
    } else if terminal_refusal(&checked, &mut budget)? {
        return Ok(std::borrow::Cow::Borrowed(encoded));
    }
    Err(Violation::Origin)
}

fn matches_request(
    network: NetworkId,
    peer: ServerId,
    descriptor: &OperationDescriptor,
    header: &ResultHeader,
) -> bool {
    let key = header.replay_key;
    header.network_id == network
        && key.home_server_id == peer
        && key.server_incarnation == descriptor.server_incarnation
        && key.origin_id == descriptor.origin_id
        && key.origin_generation == descriptor.origin_generation
        && key.operation_sequence == descriptor.operation_sequence
        && header.request_id == descriptor.request_id
        && header.request_object_id == descriptor.object_id
}

fn expired_output(header: ResultHeader) -> Result<Vec<u8>, Violation> {
    use crate::federation::codec::results::ResultArm;
    let denied = ResultArm::Failed {
        code: "ORIGIN_EXPIRED".into(),
        context: String::new(),
    }
    .to_object()
    .map_err(|_| Violation::Codec)?;
    let header = ResultHeader {
        result_kind: FederationResultKind::Failed,
        completion_event_id: None,
        ..header
    };
    InitialRootResult::encode_failed(FederationProfile::InitialRoot, &header, &denied, vec![])
        .map_err(|_| Violation::Codec)
}

// A durable origin tombstone can answer after the individual result row has retired.
fn terminal_refusal(
    checked: &InitialRootResult<'_>,
    budget: &mut DecodeBudget,
) -> Result<bool, Violation> {
    use crate::federation::codec::results::ResultArm;
    if checked.sealed.is_some()
        || !checked
            .indexed_replies()
            .map_err(|_| Violation::Codec)?
            .is_empty()
    {
        return Ok(false);
    }
    let arm = checked.failed_arm(budget).map_err(|_| Violation::Codec)?;
    let failed =
        ResultArm::from_object(FederationResultKind::Failed, &arm).map_err(|_| Violation::Codec)?;
    Ok(
        matches!(failed, ResultArm::Failed{code,context} if code == "ORIGIN_EXPIRED" && context.is_empty()),
    )
}

#[cfg(test)]
mod tests;
