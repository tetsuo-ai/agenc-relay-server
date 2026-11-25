//! Retire one durable claim and its ownership in the request-maintenance batch.

use super::{CompanionFault, CompanionState, MAX_EXPIRY_ENTRIES, Write};
use crate::budget::BackingReservationPort;
use agenc_relay_domain::e2ee::directory::{ClaimOutcome, ClaimParameters};
use agenc_relay_e2ee::limits::MAX_KEY_PACKAGE_OBJECT;
use agenc_relay_e2ee::mls_outer::{MlsOuterMessage, parse_mls_message};
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::tls::DecodeBudget;
use agenc_relay_storage::e2ee_records::PackageRow;
use agenc_relay_storage::{StoredKey, TableId};

pub(super) type ClaimKey = ([u8; 32], [u8; 16]);

pub(super) struct Claim {
    key: ClaimKey,
    row_key: StoredKey,
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
            let ClaimOutcome::Claimed { object_id, .. } = outcome else {
                if !state.empty_claims.contains(&key) {
                    return Err(CompanionFault::Storage);
                }
                return Ok(Some(Self {
                    key,
                    row_key,
                    parameters,
                    outcome: outcome.clone(),
                    retain_until,
                    output_backing: 0,
                }));
            };
            let Some(account) = state.owners.account(object_id) else {
                continue;
            };
            if !account.owners.contains_key(row_key.as_bytes()) {
                continue;
            }
            let _decode = backing
                .reserve(MAX_KEY_PACKAGE_OBJECT * 8)
                .map_err(|_| CompanionFault::Ceiling)?;
            // Older rows carried only the claim timeout. The retained signed
            // lifetime is an independent floor and must also have elapsed.
            if !package_expiry(state, object_id).is_some_and(|expiry| now >= expiry) {
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

    pub(super) fn write(&self) -> Result<Write, crate::RuntimeError> {
        Write::delete(TableId::E2eeState, self.row_key.clone())
    }

    pub(super) fn matches(&self, state: &CompanionState) -> bool {
        state
            .directory
            .claim_retained_until(&self.key.0, &self.key.1)
            == Some(self.retain_until)
            && state.directory.stored_claim(&self.key.0, &self.key.1)
                == Some((self.parameters, &self.outcome))
            && (self.outcome != ClaimOutcome::Unavailable || state.empty_claims.contains(&self.key))
    }

    pub(super) fn remove(&self, state: &mut CompanionState) {
        state.directory.forget_claim(&self.key.0, &self.key.1);
        if self.outcome == ClaimOutcome::Unavailable {
            state.empty_claims.retire(&self.key);
        }
    }
}

fn package_expiry(state: &CompanionState, id: &[u8; 32]) -> Option<u64> {
    let bytes = state.objects.get(id)?;
    let mut budget = DecodeBudget::new(MAX_KEY_PACKAGE_OBJECT, 1 << 14);
    let object =
        ArcWireObject::decode_kind(bytes, Some(ArcWireObjectKind::KeyPackageMls), &mut budget)
            .ok()?;
    let mut budget = DecodeBudget::new(MAX_KEY_PACKAGE_OBJECT, 1 << 14);
    let MlsOuterMessage::KeyPackage(package) =
        parse_mls_message(object.body(), &mut budget).ok()?
    else {
        return None;
    };
    Some(package.leaf_node.lifetime.not_after)
}
