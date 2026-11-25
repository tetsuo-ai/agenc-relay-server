//! Project only the rows touched by this serialized storage batch.
#![forbid(unsafe_code)]

use super::*;
use agenc_relay_storage::RecordMutation;

pub(in crate::state_core) fn account(
    network: NetworkId,
    id: AccountId,
) -> Result<Digest, RuntimeError> {
    account_id_digest(network.as_bytes(), id.to_text().as_bytes()).map_err(|_| stale())
}

#[derive(Default)]
struct ObjectChange<'a> {
    object: Option<u64>,
    owner: Option<(u64, &'a RecordMutation)>,
}

#[derive(Default)]
struct Plan<'a> {
    new_users: BTreeSet<Digest>,
    retired: BTreeSet<Digest>,
    delta: BTreeMap<Digest, i128>,
    objects: BTreeMap<ObjectDigest, ObjectChange<'a>>,
    updates: Updates,
}

pub(super) fn project(projection: &Projection<'_>) -> Result<Updates, RuntimeError> {
    let mut plan = Plan::default();
    plan.lifecycle(projection)?;
    if projection.index.guarded_directory.users.is_empty() && plan.new_users.is_empty() {
        return Ok(plan.updates);
    }
    for mutation in &projection.mutations {
        plan.row(projection.index, mutation)?;
    }
    for (id, change) in std::mem::take(&mut plan.objects) {
        plan.object(projection.index, id, change)?;
    }
    plan.finish(projection.index)?;
    Ok(plan.updates)
}

impl<'a> Plan<'a> {
    fn lifecycle(&mut self, projection: &Projection<'_>) -> Result<(), RuntimeError> {
        let network = projection.keys.binding().network_id();
        for update in &projection.updates {
            match update {
                IndexUpdate::InitialRootOwner(owner)
                    if !projection
                        .index
                        .initial_root_owners
                        .contains_key(&owner.row().account) =>
                {
                    let digest = account(network, owner.row().account)?;
                    if !self.new_users.insert(digest) {
                        return Err(stale());
                    }
                    let key = RootClaimOwner::key(network, owner.row().account)?;
                    let receipt = projection
                        .mutations
                        .iter()
                        .find(|m| m.table() == TableId::E2eeState && m.key() == &key)
                        .ok_or_else(stale)?;
                    let (_, receipt_charge) = changed_charge(receipt)?;
                    let subtotal = Subtotal {
                        account: digest,
                        bytes: 4096,
                    };
                    let width = subtotal
                        .record(1)?
                        .encode()?
                        .len()
                        .checked_add(MIN_SEALED_RECORD_BYTES)
                        .ok_or(RuntimeError::Overflow)?;
                    let self_charge = sealed_charge(&subtotal.key()?, width)?;
                    self.delta
                        .insert(digest, i128::from(receipt_charge) + i128::from(self_charge));
                }
                IndexUpdate::RemoveInitialRootOwner(id) => {
                    self.retired.insert(account(network, *id)?);
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn guarded(&self, index: &DurableIndex, digest: &Digest) -> bool {
        !self.retired.contains(digest)
            && (self.new_users.contains(digest)
                || index.guarded_directory.users.contains_key(digest))
    }

    fn row(
        &mut self,
        index: &DurableIndex,
        mutation: &'a RecordMutation,
    ) -> Result<(), RuntimeError> {
        if mutation.table() == TableId::E2eeState
            && mutation
                .key()
                .as_bytes()
                .starts_with(agenc_relay_storage::e2ee_records::prefix::OWNER)
        {
            let id = ObjectOwnerRow::parse_key(mutation.key())?;
            self.objects.entry(id).or_default().owner =
                Some((changed_charge(mutation)?.1, mutation));
            return Ok(());
        }
        let Some(class) = Allocation::change(mutation)? else {
            return Ok(());
        };
        let (before, after) = changed_charge(mutation)?;
        match class {
            Allocation::Account(digest) if self.guarded(index, &digest) => {
                *self.delta.entry(digest).or_default() += i128::from(after) - i128::from(before);
            }
            Allocation::Account(_) => {}
            Allocation::Stock(owner) => {
                let owners = owner
                    .filter(|d| self.guarded(index, d))
                    .into_iter()
                    .collect();
                self.members(
                    index,
                    Resource::Stock(mutation.key().clone()),
                    before,
                    after,
                    &owners,
                )?;
            }
            Allocation::Object(id) => self.objects.entry(id).or_default().object = Some(after),
            Allocation::Ownership(..) => return Err(stale()),
        }
        Ok(())
    }

    fn object(
        &mut self,
        index: &DurableIndex,
        id: ObjectDigest,
        change: ObjectChange<'_>,
    ) -> Result<(), RuntimeError> {
        let resource = Resource::Object(id);
        let previous = index.guarded_directory.members.get(&resource);
        if previous.is_none() && change.owner.is_none() {
            return Ok(());
        }
        let digests = match &change.owner {
            None => previous.into_iter().flatten().map(|h| h.digest).collect(),
            Some((_, mutation)) => {
                let Some(Allocation::Ownership(_, payers)) = Allocation::change(mutation)? else {
                    return Err(stale());
                };
                self.resolve(index, &payers)
            }
        };
        if previous.is_none() && digests.is_empty() {
            return Ok(());
        }
        let object_charge =
            index.current_charge(TableId::E2eeObject, &StoredKey::new(id.to_vec())?)?;
        let owner_charge = index.current_charge(TableId::E2eeState, &ObjectOwnerRow::key(&id)?)?;
        let before = object_charge
            .checked_add(owner_charge)
            .ok_or(RuntimeError::Overflow)?;
        let after = change
            .object
            .unwrap_or(object_charge)
            .checked_add(change.owner.map_or(owner_charge, |(size, _)| size))
            .ok_or(RuntimeError::Overflow)?;
        self.members(index, resource, before, after, &digests)
    }

    fn resolve(&self, index: &DurableIndex, payers: &[Payer]) -> BTreeSet<Digest> {
        let mut found = BTreeSet::new();
        for payer in payers {
            match payer {
                Payer::Account(digest) if self.guarded(index, digest) => {
                    found.insert(*digest);
                }
                Payer::Account(_) => {}
                Payer::Stock(key) => {
                    let stock = Resource::Stock(key.clone());
                    let owners = self
                        .updates
                        .members
                        .get(&stock)
                        .or_else(|| index.guarded_directory.members.get(&stock));
                    found.extend(
                        owners
                            .into_iter()
                            .flatten()
                            .map(|holder| holder.digest)
                            .filter(|digest| self.guarded(index, digest)),
                    );
                }
            }
        }
        found
    }

    fn members(
        &mut self,
        index: &DurableIndex,
        resource: Resource,
        before: u64,
        after: u64,
        digests: &BTreeSet<Digest>,
    ) -> Result<(), RuntimeError> {
        let previous = index.guarded_directory.members.get(&resource);
        for holder in previous.into_iter().flatten() {
            if self.guarded(index, &holder.digest) {
                *self.delta.entry(holder.digest).or_default() -= i128::from(before);
            }
        }
        for digest in digests {
            *self.delta.entry(*digest).or_default() += i128::from(after);
        }
        if !previous
            .into_iter()
            .flatten()
            .map(|holder| holder.digest)
            .eq(digests.iter().copied())
        {
            let owners = index.holders(&resource, digests)?;
            self.updates.members.insert(resource, owners);
        }
        Ok(())
    }

    fn finish(&mut self, index: &DurableIndex) -> Result<(), RuntimeError> {
        for (digest, diff) in &self.delta {
            if *diff == 0 || self.retired.contains(digest) {
                continue;
            }
            let before = index
                .guarded_directory
                .users
                .get(digest)
                .map_or(0, |row| row.bytes);
            let after = u64::try_from(i128::from(before) + diff).map_err(|_| stale())?;
            if after > index.guarded_directory.limit {
                return Err(StorageError::LimitExceeded.into());
            }
            self.updates.totals.insert(*digest, Some(after));
        }
        self.updates
            .totals
            .extend(self.retired.iter().map(|digest| (*digest, None)));
        Ok(())
    }
}
