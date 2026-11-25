//! Retain both outer request identity and exact committed response for the authenticated origin.
#![forbid(unsafe_code)]

use super::{FederationCoordinator, Violation};
use crate::state_core::StateCoreContext;
use crate::state_core::durable::federated_claims::{Key, WEEK};
use agenc_relay_federation_wire::RequestHeader;
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
    let wall = context.utc_now().ok()?;
    context
        .drift()
        .accepts_wall(context.now(), wall)
        .then_some(wall.get())
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
    ) -> Result<Arc<Intake>, Violation> {
        let deadline = trusted_now(context)
            .and_then(|now| now.checked_add(WEEK))
            .ok_or(Violation::Origin)?;
        let key = header.replay_key.to_bytes();
        let mut owners = self.root_intakes.0.lock().map_err(|_| Violation::Ceiling)?;
        let pending = owners
            .iter()
            .filter(|other| context.index().federated_claim(other).is_none());
        context
            .index()
            .require_federated_claim_room(&key, pending)
            .map_err(|_| Violation::Ceiling)?;
        let backing = context
            .reserve_output_backing(512)
            .map_err(|_| Violation::Ceiling)?;
        if !owners.insert(key) {
            return Err(Violation::Origin);
        }
        let slot = Arc::new(Intake {
            key,
            deadline,
            owners: self.root_intakes.0.clone(),
            _backing: backing,
        });
        Ok(slot)
    }
}

pub(super) fn authorized_output<'a>(
    context: &StateCoreContext,
    network: agenc_relay_types::NetworkId,
    peer: agenc_relay_types::ServerId,
    descriptor: &agenc_relay_federation_wire::OperationDescriptor,
    encoded: &'a [u8],
) -> Result<std::borrow::Cow<'a, [u8]>, Violation> {
    use crate::federation::codec::results::ResultArm;
    use agenc_relay_federation_wire::{DecodeBudget, FederationProfile, InitialRootResult};
    let mut budget = DecodeBudget::new(1 << 20, 4_096);
    let checked = InitialRootResult::decode(FederationProfile::InitialRoot, encoded, &mut budget)
        .map_err(|_| Violation::Codec)?;
    let h = checked.layout;
    let key = h.replay_key;
    if h.network_id != network
        || key.home_server_id != peer
        || key.server_incarnation != descriptor.server_incarnation
        || key.origin_id != descriptor.origin_id
        || key.origin_generation != descriptor.origin_generation
        || key.operation_sequence != descriptor.operation_sequence
        || h.request_id != descriptor.request_id
        || h.request_object_id != descriptor.object_id
    {
        return Err(Violation::Origin);
    }
    let now = trusted_now(context).ok_or(Violation::Phase)?;
    let k = key.to_bytes();
    if let Some(held) = context.index().federated_claim(&k) {
        if held.may_replay(now) && context.index().holds_federated_claim(&k, encoded) {
            return Ok(std::borrow::Cow::Borrowed(encoded));
        }
        if !held.may_replay(now) {
            let denied = ResultArm::Failed {
                code: "ORIGIN_EXPIRED".into(),
                context: String::new(),
            }
            .to_object()
            .map_err(|_| Violation::Codec)?;
            let header = agenc_relay_federation_wire::ResultHeader {
                result_kind: agenc_relay_types::FederationResultKind::Failed,
                completion_event_id: None,
                ..h
            };
            let bytes = InitialRootResult::encode_failed(
                FederationProfile::InitialRoot,
                &header,
                &denied,
                vec![],
            )
            .map_err(|_| Violation::Codec)?;
            return Ok(std::borrow::Cow::Owned(bytes));
        }
        return Err(Violation::Origin);
    }
    // The terminal ORIGIN_EXPIRED classification is the one refusal which has no original row.
    if checked.sealed.is_none()
        && checked
            .indexed_replies()
            .map_err(|_| Violation::Codec)?
            .is_empty()
    {
        let arm = checked
            .failed_arm(&mut budget)
            .map_err(|_| Violation::Codec)?;
        let failed = ResultArm::from_object(agenc_relay_types::FederationResultKind::Failed, &arm)
            .map_err(|_| Violation::Codec)?;
        if matches!(failed, ResultArm::Failed{code,context} if code == "ORIGIN_EXPIRED" && context.is_empty())
        {
            return Ok(std::borrow::Cow::Borrowed(encoded));
        }
    }
    Err(Violation::Origin)
}

#[cfg(test)]
mod tests;
