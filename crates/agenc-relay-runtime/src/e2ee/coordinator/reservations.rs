//! Durable route grants. A stored owner is an account digest. A Direct grant
//! stores a commitment to the pair and its nonce, which can be opened when
//! the two accounts are presented again after restart.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound::{Excluded, Included};

use agenc_relay_domain::e2ee::{
    BindingSummary, DirectPair, ReservationId, RouteReservation, RouteTable, RouteTarget,
};
use agenc_relay_e2ee::limits::MAX_RESERVATION_OBJECT;
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::conversation::{ArcConversationKind, ArcReservation};
use agenc_relay_e2ee::route::{channel_route_binding, direct_route_binding};
use agenc_relay_e2ee::tls::{DecodeBudget, TlsDecode};
use agenc_relay_storage::e2ee_records::{ClaimRow, ObjectRow};
use agenc_relay_storage::{PersistentRecordValue, StoredKey, TableId};
use agenc_relay_types::{AccountId, ChannelInstanceId};

use super::CompanionFault;
use crate::budget::{BackingReservationPort, MemoryPermit};
use crate::state_core::durable::AccountServiceDurableWrite as Write;

type Id = [u8; 16];
pub(super) type Deadline = (u64, Id);

// Covers the stored lease and its B-tree entries during assembly and service.
const ENTRY_BACKING: usize = 768;

/// Direct creators are always the smaller account. Historic rows commit to
/// their peer using a per-grant nonce, so their stable lookup scope is the
/// creator; channel grants have a stable concrete instance across renewals.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
enum Scope {
    Channel([u8; 16]),
    Direct([u8; 32]),
}

impl Scope {
    fn requested(target: RouteTarget, owner: [u8; 32]) -> Self {
        match target {
            RouteTarget::Channel(instance) => Self::Channel(*instance.as_bytes()),
            RouteTarget::Direct(_) => Self::Direct(owner),
        }
    }
}

#[derive(Clone, Copy)]
enum Target {
    Channel(ChannelInstanceId),
    Direct { nonce: [u8; 32], binding: [u8; 32] },
}

impl Target {
    fn matches(self, network: &[u8; 32], target: RouteTarget) -> bool {
        match (self, target) {
            (Self::Channel(leased), RouteTarget::Channel(requested)) => leased == requested,
            (Self::Direct { nonce, binding }, RouteTarget::Direct(pair)) => {
                commitment(network, &nonce, pair) == Some(binding)
            }
            _ => false,
        }
    }
}

fn commitment(network: &[u8; 32], nonce: &[u8; 32], pair: DirectPair) -> Option<[u8; 32]> {
    let a = pair.smaller().to_text();
    let b = pair.larger().to_text();
    direct_route_binding(
        network,
        nonce,
        a.as_bytes().try_into().ok()?,
        b.as_bytes().try_into().ok()?,
    )
    .ok()
}

pub(super) struct Lease {
    id: Id,
    expires: u64,
    owner: [u8; 32],
    device: [u8; 16],
    predecessor: Option<[u8; 32]>,
    target: Target,
    _backing: Option<MemoryPermit>,
}

impl Lease {
    fn scope(&self) -> Scope {
        match self.target {
            Target::Channel(instance) => Scope::Channel(*instance.as_bytes()),
            Target::Direct { .. } => Scope::Direct(self.owner),
        }
    }

    pub(super) fn new(
        grant: &ArcReservation,
        owner: [u8; 32],
        device: [u8; 16],
        predecessor: Option<[u8; 32]>,
        backing: Option<MemoryPermit>,
    ) -> Result<Self, CompanionFault> {
        let t = &grant.tbs;
        let target = match t.kind {
            ArcConversationKind::Channel if t.conversation_nonce.as_slice().is_empty() => {
                let instance = t
                    .channel_instance_id
                    .as_slice()
                    .try_into()
                    .map_err(|_| CompanionFault::Storage)?;
                if channel_route_binding(&t.network_id, &instance).ok() != Some(t.route_binding) {
                    return Err(CompanionFault::Storage);
                }
                Target::Channel(ChannelInstanceId::from_bytes(instance))
            }
            ArcConversationKind::Direct if t.channel_instance_id.as_slice().is_empty() => {
                Target::Direct {
                    nonce: t
                        .conversation_nonce
                        .as_slice()
                        .try_into()
                        .map_err(|_| CompanionFault::Storage)?,
                    binding: t.route_binding,
                }
            }
            _ => return Err(CompanionFault::Storage),
        };
        Ok(Self {
            id: t.reservation_id,
            expires: t.expires_at,
            owner,
            device,
            predecessor,
            target,
            _backing: backing,
        })
    }
    fn permits_bind(
        &self,
        exec: &super::ops::Exec<'_>,
        summary: &BindingSummary,
        target: RouteTarget,
        owner: [u8; 32],
    ) -> Option<bool> {
        let migration = summary.binding_generation != 0;
        let same_binding = self
            .predecessor
            .is_none_or(|id| migration && id == summary.previous_binding_id);
        let same_device = !migration || self.device == exec.attached_device().ok()?.0;
        Some(
            self.owner == owner
                && same_binding
                && same_device
                && self.expires > exec.now
                && self.target.matches(&exec.coordinator.network_id, target),
        )
    }

    pub(super) fn reserve_backing(
        port: &BackingReservationPort,
    ) -> Result<MemoryPermit, CompanionFault> {
        port.reserve(ENTRY_BACKING)
            .map_err(|_| CompanionFault::Ceiling)
    }
}

#[derive(Default)]
pub(super) struct Leases {
    by_id: BTreeMap<Id, Lease>,
    by_predecessor: BTreeMap<[u8; 32], Id>,
    deadlines: BTreeSet<Deadline>,
    scopes: BTreeSet<(Scope, u64, Id)>,
}

impl Leases {
    pub(super) fn insert(&mut self, lease: Lease) {
        if let Some(binding) = lease.predecessor {
            self.by_predecessor.insert(binding, lease.id);
        }
        self.scopes.insert((lease.scope(), lease.expires, lease.id));
        self.deadlines.insert((lease.expires, lease.id));
        self.by_id.insert(lease.id, lease);
    }
    pub(super) fn remove(&mut self, id: Id) {
        if let Some(lease) = self.by_id.remove(&id) {
            if let Some(binding) = lease.predecessor
                && self.by_predecessor.get(&binding) == Some(&id)
            {
                self.by_predecessor.remove(&binding);
            }
            self.scopes.remove(&(lease.scope(), lease.expires, id));
            self.deadlines.remove(&(lease.expires, id));
        }
    }
    pub(super) fn for_predecessor(&self, binding: &[u8; 32]) -> Option<Id> {
        self.by_predecessor.get(binding).copied()
    }
    pub(super) fn contains(&self, id: &Id) -> bool {
        self.by_id.contains_key(id)
    }
    pub(super) fn expired(&self, now: u64, limit: usize) -> Vec<Deadline> {
        self.deadlines
            .range(..=(now, [u8::MAX; 16]))
            .take(limit)
            .copied()
            .collect()
    }
    pub(super) fn has_deadline(&self, deadline: &Deadline) -> bool {
        self.deadlines.contains(deadline)
    }
    /// Reclaim every expired claim in this scope in the same mutation as
    /// the replacement. A backlog beyond one bounded write set drains via
    /// the independent maintenance worker before another grant can issue.
    pub(super) fn superseded(
        &self,
        target: RouteTarget,
        owner: [u8; 32],
        now: u64,
    ) -> Option<Vec<Id>> {
        let scope = Scope::requested(target, owner);
        let limit = super::request_expiry::MAX_EXPIRY_ENTRIES / 2;
        let ids: Vec<_> = self
            .scopes
            .range((scope, 0, [0; 16])..=(scope, now, [u8::MAX; 16]))
            .take(limit + 1)
            .map(|(_, _, id)| *id)
            .collect();
        (ids.len() <= limit).then_some(ids)
    }

    pub(super) fn conflict(
        &self,
        network: &[u8; 32],
        owner: &[u8; 32],
        target: RouteTarget,
        now: u64,
        except: Option<Id>,
    ) -> bool {
        let scope = Scope::requested(target, *owner);
        self.scopes
            .range((
                Excluded((scope, now, [u8::MAX; 16])),
                Included((scope, u64::MAX, [u8::MAX; 16])),
            ))
            .filter(|(_, _, id)| Some(*id) != except)
            .filter_map(|(_, _, id)| self.by_id.get(id))
            .any(|lease| lease.target.matches(network, target))
    }
    /// Install an outstanding grant in the domain's trial table only if its
    /// protected owner, target and validity agree with the verified request.
    pub(super) fn prepare_bind(
        &self,
        routes: &mut RouteTable,
        id: Id,
        account: AccountId,
        exec: &super::ops::Exec<'_>,
        summary: &BindingSummary,
    ) -> Option<()> {
        let network = &exec.coordinator.network_id;
        let owner = exec.account_digest().ok()?;
        let now = exec.now;
        let lease = self.by_id.get(&id)?;
        let target = match (summary.channel_instance_id, summary.direct_pair) {
            (Some(instance), None) => RouteTarget::Channel(instance),
            (None, Some(pair)) => RouteTarget::Direct(pair),
            _ => return None,
        };
        let binding_change = summary.binding_generation != 0;
        if !lease.permits_bind(exec, summary, target, owner)?
            || self.conflict(network, &owner, target, now, Some(id))
        {
            return None;
        }
        if routes.reservations().any(|r| r.reservation_id.0 == id) {
            return Some(());
        }
        let id = ReservationId(id);
        if binding_change {
            let nonce = match lease.target {
                Target::Direct { nonce, .. } => Some(nonce),
                Target::Channel(_) => None,
            };
            return routes
                .reserve_binding_change(
                    summary.conversation_id,
                    RouteReservation {
                        reservation_id: id,
                        target,
                        owner: account,
                        expires_at: lease.expires,
                        conversation_nonce: nonce,
                    },
                )
                .ok();
        }
        match (target, lease.target) {
            (RouteTarget::Channel(instance), _) => routes
                .reserve_channel(id, instance, account, lease.expires)
                .ok(),
            (RouteTarget::Direct(pair), Target::Direct { nonce, .. }) => routes
                .reserve_direct(id, pair, nonce, account, lease.expires)
                .ok(),
            _ => None,
        }
    }
}

/// A finalized ReInit takes ownership of the successor. Retire any outstanding
/// same-group grant in the receipt that freezes the old group.
pub(super) fn retire_predecessor(
    exec: &super::ops::Exec<'_>,
    outcome: &mut super::request::Outcome,
    binding: [u8; 32],
) -> Result<(), super::ops::Fail> {
    let Some(grant) = exec
        .coordinator
        .state
        .reservations
        .for_predecessor(&binding)
    else {
        return Ok(());
    };
    outcome.writes.push(delete(grant).map_err(|_| {
        super::ops::Fail::from(agenc_relay_e2ee::wire::reply::E2eeReplyCode::InvalidFragment)
    })?);
    outcome.effects.push(Box::new(move |state| {
        state.reservations.remove(grant);
        state.routes.remove_reservation(ReservationId(grant));
    }));
    Ok(())
}

pub(super) fn delete(id: Id) -> Result<Write, crate::RuntimeError> {
    Write::delete(TableId::E2eeState, ClaimRow::reservation_key(&id)?)
}

struct Row {
    id: Id,
    owner: [u8; 32],
    device: [u8; 16],
    predecessor: Option<[u8; 32]>,
    kind: u16,
    binding: [u8; 32],
    expires: u64,
    backing: Option<MemoryPermit>,
    grant: Option<Lease>,
    network: Option<[u8; 32]>,
}

impl Row {
    fn read(&mut self, bytes: &[u8]) -> Result<(), CompanionFault> {
        let mut budget = DecodeBudget::new(MAX_RESERVATION_OBJECT, 4096);
        let object =
            ArcWireObject::decode_kind(bytes, Some(ArcWireObjectKind::Reservation), &mut budget)
                .map_err(|_| CompanionFault::Storage)?;
        let mut budget = DecodeBudget::new(MAX_RESERVATION_OBJECT, 4096);
        let grant = ArcReservation::decode_exact(object.body(), &mut budget)
            .map_err(|_| CompanionFault::Storage)?;
        let t = &grant.tbs;
        if t.profile_version != agenc_relay_e2ee::limits::PROFILE_VERSION
            || t.reservation_id != self.id
            || t.expires_at != self.expires
            || t.route_binding != self.binding
            || u16::from(t.kind.value()) != self.kind
        {
            return Err(CompanionFault::Storage);
        }
        self.network = Some(t.network_id);
        self.grant = Some(Lease::new(
            &grant,
            self.owner,
            self.device,
            self.predecessor,
            self.backing.take(),
        )?);
        Ok(())
    }
}

#[derive(Default)]
pub(super) struct Rows(BTreeMap<[u8; 32], Row>);

impl Rows {
    pub(super) fn admit(
        &mut self,
        key: &StoredKey,
        body: &[u8],
        port: Option<&BackingReservationPort>,
    ) -> Result<(), CompanionFault> {
        let row = ClaimRow::decode(body).map_err(|_| CompanionFault::Storage)?;
        match row {
            ClaimRow::Lock { .. } => {
                ClaimRow::parse_lock_key(key).map_err(|_| CompanionFault::Storage)?;
            }
            ClaimRow::Reservation {
                owner_account_digest,
                owner_device_id,
                previous_binding,
                kind,
                lock_id,
                route_binding,
                reservation_object_id,
                expires_at,
                ..
            } => {
                let id =
                    ClaimRow::parse_reservation_key(key).map_err(|_| CompanionFault::Storage)?;
                if lock_id != [0; 32] || self.0.contains_key(&reservation_object_id) {
                    return Err(CompanionFault::Storage);
                }
                self.0.insert(
                    reservation_object_id,
                    Row {
                        id,
                        owner: owner_account_digest,
                        device: owner_device_id,
                        predecessor: previous_binding,
                        kind,
                        binding: route_binding,
                        expires: expires_at,
                        backing: port.map(Lease::reserve_backing).transpose()?,
                        grant: None,
                        network: None,
                    },
                );
            }
        }
        Ok(())
    }
    pub(super) fn object(
        &mut self,
        key: &StoredKey,
        value: &PersistentRecordValue,
    ) -> Result<(), CompanionFault> {
        let id: [u8; 32] = key
            .as_bytes()
            .try_into()
            .map_err(|_| CompanionFault::Storage)?;
        if let Some(row) = self.0.get_mut(&id) {
            let object = ObjectRow::decode(value.body()).map_err(|_| CompanionFault::Storage)?;
            if object.key().map_err(|_| CompanionFault::Storage)? != *key {
                return Err(CompanionFault::Storage);
            }
            if row.grant.is_none() {
                row.read(&object.bytes)?;
            }
        }
        Ok(())
    }
    pub(super) fn finish(
        self,
        state: &super::CompanionState,
        network: [u8; 32],
    ) -> Result<Leases, CompanionFault> {
        // Old stores kept the owner row after BIND. The concrete commitment
        // persists on the bound conversation, including its closed history.
        // Index only the claim rows being recovered when reconciling that history.
        let mut unused: BTreeSet<_> = self
            .0
            .values()
            .filter(|row| row.predecessor.is_none())
            .map(|row| row.binding)
            .collect();
        let requested: BTreeSet<_> = self.0.values().filter_map(|row| row.predecessor).collect();
        let mut current = BTreeSet::new();
        for (id, conversation) in &state.conversations {
            unused.remove(&conversation.route_binding);
            if requested.contains(&conversation.binding)
                && state
                    .routes
                    .route(&agenc_relay_domain::e2ee::ConversationId(*id))
                    .is_some_and(|entry| entry.accepts_traffic())
                && state
                    .routes
                    .is_current(&agenc_relay_domain::e2ee::ConversationId(*id))
            {
                current.insert(conversation.binding);
            }
        }
        let mut leases = Leases::default();
        for (id, mut row) in self.0 {
            if row.grant.is_none() {
                row.read(state.objects.get(&id).ok_or(CompanionFault::Storage)?)?;
            }
            if row.network != Some(network) || leases.contains(&row.id) {
                return Err(CompanionFault::Storage);
            }
            let mut lease = row.grant.ok_or(CompanionFault::Storage)?;
            let retired = row.predecessor.map_or_else(
                || !unused.contains(&row.binding),
                |id| !current.contains(&id),
            );
            if retired {
                // A consumed claim is immediately eligible for durable cleanup.
                lease.expires = 0;
            }
            leases.insert(lease);
        }
        Ok(leases)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scope_over_the_expiry_write_limit_waits_for_bounded_maintenance()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut leases = Leases::default();
        let channel = ChannelInstanceId::from_bytes([2; 16]);
        let target = RouteTarget::Channel(channel);
        let limit = super::super::request_expiry::MAX_EXPIRY_ENTRIES / 2;
        for serial in 0..=limit {
            leases.insert(Lease {
                id: u128::try_from(serial)?.to_be_bytes(),
                owner: [3; 32],
                device: [0; 16],
                predecessor: None,
                target: Target::Channel(channel),
                expires: 90,
                _backing: None,
            });
        }
        assert!(leases.superseded(target, [3; 32], 90).is_none());
        let other = RouteTarget::Channel(ChannelInstanceId::from_bytes([4; 16]));
        assert_eq!(leases.superseded(other, [3; 32], 90), Some(vec![]));
        let page = leases.expired(90, limit);
        assert_eq!(page.len(), limit);
        for (_, id) in page {
            leases.remove(id);
        }
        assert_eq!(
            leases
                .superseded(target, [3; 32], 90)
                .ok_or("remaining claim")?
                .len(),
            1
        );
        Ok(())
    }
}
