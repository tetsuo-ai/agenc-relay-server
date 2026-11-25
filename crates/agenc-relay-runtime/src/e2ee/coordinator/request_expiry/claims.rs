//! Retire one durable claim and its ownership in the request-maintenance batch.

use super::super::resident::PACKAGE_DECODE_BACKING;
use super::{CompanionFault, CompanionState, MAX_EXPIRY_ENTRIES, Write};
use crate::budget::BackingReservationPort;
use agenc_relay_domain::e2ee::directory::{ClaimOutcome, ClaimParameters};
use agenc_relay_storage::e2ee_records::PackageRow;
use agenc_relay_storage::{StoredKey, TableId};

pub(super) type ClaimKey = ([u8; 32], [u8; 16]);

pub(super) struct Claim {
    key: ClaimKey,
    row_key: StoredKey,
    stale_stock: Option<StoredKey>,
    parameters: ClaimParameters,
    outcome: ClaimOutcome,
    retain_until: u64,
    output_backing: usize,
}

impl Claim {
    /// Scans a bounded page and stages at most one owner rewrite. A live cursor
    /// can start over after restart because the commit removes the durable row.
    pub(super) fn capture(
        state: &CompanionState,
        cursor: &mut Option<ClaimKey>,
        now: u64,
        backing: &BackingReservationPort,
    ) -> Result<Option<Self>, CompanionFault> {
        let mut scanned = 0;
        for (key, retain_until, outcome) in state
            .directory
            .claims_after(*cursor)
            .take(MAX_EXPIRY_ENTRIES)
        {
            scanned += 1;
            *cursor = Some(key);
            if retain_until == 0 || now < retain_until {
                continue;
            }
            let row_key =
                PackageRow::claim_key(&key.0, &key.1).map_err(|_| CompanionFault::Storage)?;
            let (parameters, _) = state
                .directory
                .stored_claim(&key.0, &key.1)
                .ok_or(CompanionFault::Storage)?;
            let ClaimOutcome::Claimed {
                key_package_ref,
                object_id,
            } = outcome
            else {
                if !state.empty_claims.contains(&key) {
                    return Err(CompanionFault::Storage);
                }
                return Ok(Some(Self {
                    key,
                    row_key,
                    stale_stock: None,
                    parameters,
                    outcome: outcome.clone(),
                    retain_until,
                    output_backing: 0,
                }));
            };
            if !state.spent_package_rows.contains_key(&row_key) {
                return Err(CompanionFault::Storage);
            }
            let Some(account) = state.owners.account(object_id) else {
                continue;
            };
            if !account.owners.contains_key(row_key.as_bytes()) {
                continue;
            }
            if !package_expired(state, object_id, key_package_ref, now, backing)? {
                continue;
            }
            // The staged owner row keeps the other references. Charge for
            // their keys, the ledger copies and the encoded write.
            let references = account
                .owners
                .keys()
                .map(|owner| owner.len() * 8 + 512)
                .sum::<usize>();
            return Ok(Some(Self {
                key,
                row_key,
                stale_stock: stale_stock_key(state, key_package_ref, object_id)?,
                parameters,
                outcome: outcome.clone(),
                retain_until,
                output_backing: references + 16_384,
            }));
        }
        if scanned < MAX_EXPIRY_ENTRIES {
            *cursor = None;
        }
        Ok(None)
    }

    pub(super) const fn output_backing(&self) -> usize {
        self.output_backing
    }

    pub(super) fn delete_count(&self) -> usize {
        1 + usize::from(self.stale_stock.is_some())
    }

    pub(super) fn write(&self, writes: &mut Vec<Write>) -> Result<(), crate::RuntimeError> {
        writes.push(Write::delete(TableId::E2eeState, self.row_key.clone())?);
        if let Some(stock) = &self.stale_stock {
            writes.push(Write::delete(TableId::E2eeState, stock.clone())?);
        }
        Ok(())
    }

    pub(super) fn matches(&self, state: &CompanionState) -> bool {
        state
            .directory
            .claim_retained_until(&self.key.0, &self.key.1)
            == Some(self.retain_until)
            && state.directory.stored_claim(&self.key.0, &self.key.1)
                == Some((self.parameters, &self.outcome))
            && match self.outcome {
                ClaimOutcome::Claimed { .. } => {
                    state.spent_package_rows.contains_key(&self.row_key)
                }
                ClaimOutcome::Unavailable => state.empty_claims.contains(&self.key),
            }
            && self.stale_stock.as_ref().is_none_or(|stock| {
                matches!(&self.outcome, ClaimOutcome::Claimed { object_id, .. }
                    if stock_owns(state, stock, object_id))
            })
    }

    pub(super) fn remove(&self, state: &mut CompanionState) {
        state.directory.forget_claim(&self.key.0, &self.key.1);
        let ClaimOutcome::Claimed {
            key_package_ref, ..
        } = &self.outcome
        else {
            state.empty_claims.retire(&self.key);
            return;
        };
        let claim = state.spent_package_rows.remove(&self.row_key);
        let stock = self
            .stale_stock
            .as_ref()
            .and_then(|key| state.spent_package_rows.remove(key));
        if stock.is_some() {
            state.directory.release_withheld_package(key_package_ref);
        }
        if state.spent_package_rows.is_empty() {
            state.spent_package_rows.clear();
        }
        drop((claim, stock));
    }
}

// Earlier releases could leave a dispensed package under its stock key.
// Only the exact redundant owner may retire with the claim.
fn stale_stock_key(
    state: &CompanionState,
    reference: &[u8],
    object: &[u8; 32],
) -> Result<Option<StoredKey>, CompanionFault> {
    let key = PackageRow::package_key(reference).map_err(|_| CompanionFault::Storage)?;
    Ok(stock_owns(state, &key, object).then_some(key))
}

fn stock_owns(state: &CompanionState, stock: &StoredKey, object: &[u8; 32]) -> bool {
    state
        .owners
        .owned_by(stock.as_bytes())
        .is_some_and(|objects| objects.len() == 1 && objects.contains(object))
}

// Older rows carried only the claim timeout. The original signed lifetime is
// an independent floor and applies only to its matching package reference.
fn package_expired(
    state: &CompanionState,
    id: &[u8; 32],
    reference: &[u8],
    now: u64,
    backing: &BackingReservationPort,
) -> Result<bool, CompanionFault> {
    let _decode = backing
        .reserve(PACKAGE_DECODE_BACKING)
        .map_err(|_| CompanionFault::Ceiling)?;
    Ok(state
        .objects
        .get(id)
        .and_then(|bytes| super::super::ops::directory::retained_key_package(bytes))
        .is_some_and(|package| {
            reference == package.key_package_ref && now >= package.leaf_node.lifetime.not_after
        }))
}
