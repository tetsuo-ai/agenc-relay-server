#![forbid(unsafe_code)]

//! Sequencer signer ownership across key-set changes (companion 9.2.1).
//!
//! Startup compares the configured key set with the durably accepted one
//! and the permanent credential history, derives the private signers the
//! `normal` routes and unfinished receipts require, and stages one batch
//! that records the accepted set, the history of every credential it
//! introduces or retires, and every release fact. A set that omits a
//! credential a `normal` route still pins is refused before that
//! credential's overlap deadline and accepted at or after it, when every
//! such route is blocked; a required retired credential is served by the
//! configured retired-retained key or reported missing.

use std::collections::{BTreeMap, BTreeSet};

use agenc_ircd_crypto::Ed25519SecretKey;
use agenc_ircd_e2ee::identity::Interval;
use agenc_ircd_e2ee::limits::MAX_SEQUENCER_KEY_OVERLAP_SECONDS;
use agenc_ircd_e2ee::sequencer::VerifiedSequencerCredential;
use agenc_ircd_e2ee::signature::{RoleKey, SignerRole};
use agenc_ircd_storage::TableId;
use agenc_ircd_storage::e2ee_records::{
    KEYSET_ROW_KIND, KeySetRow, SEQUENCER_HISTORY_ROW_KIND, SequencerHistoryRow,
};

use super::{CompanionCoordinator, CompanionFault, SequencerSigner};
use crate::state_core::durable::AccountServiceDurableWrite;

/// What startup found: the durable facts, the configured set, and the
/// requirements the live state places on private signers.
#[derive(Clone, Debug, Default)]
pub(crate) struct Proposal {
    /// The durably accepted key set, if any.
    pub(crate) accepted: Option<KeySetRow>,
    /// The permanent credential history by credential identifier.
    pub(crate) history: BTreeMap<[u8; 32], SequencerHistoryRow>,
    /// The credential each `normal` live route pins.
    pub(crate) pins: BTreeMap<[u8; 32], [u8; 32]>,
    /// The credentials unfinished candidate and ReInit-attempt receipts name.
    pub(crate) receipts: BTreeSet<[u8; 32]>,
}

/// What this startup records and installs once its batch is durable.
#[derive(Clone, Debug, Default)]
pub(crate) struct Reconciliation {
    /// The key-set row to record, when the accepted set advances.
    key_set: Option<KeySetRow>,
    /// The history rows to write or rewrite.
    history: BTreeMap<[u8; 32], SequencerHistoryRow>,
    /// The routes blocked on a retired credential, with that credential.
    blocked: BTreeMap<[u8; 32], [u8; 32]>,
    /// The retired credential the live state still requires, if any.
    required_retired: Option<[u8; 32]>,
    /// The credentials whose signers this startup releases.
    released: Vec<[u8; 32]>,
}

/// The facts reported after the reconciliation committed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SignerReport {
    /// Routes blocked on a retired credential.
    pub blocked_routes: u64,
    /// Whether a required retired-retained signer is not configured.
    pub retired_missing: bool,
    /// Signers released by this startup.
    pub released: u64,
}

fn credential_of(
    row: &SequencerHistoryRow,
    credential_id: [u8; 32],
) -> Option<VerifiedSequencerCredential> {
    Some(VerifiedSequencerCredential {
        credential_id,
        generation: row.key_generation,
        key: RoleKey::new(SignerRole::Sequencer, row.public_key).ok()?,
        interval: Interval {
            not_before: row.interval.0,
            not_after: row.interval.1,
        },
        previous_key_id: row.previous_key_id,
    })
}

fn history_of(
    credential: &VerifiedSequencerCredential,
    introduced_set: u64,
) -> SequencerHistoryRow {
    SequencerHistoryRow {
        key_generation: credential.generation,
        public_key: *credential.key.as_bytes(),
        interval: (
            credential.interval.not_before,
            credential.interval.not_after,
        ),
        previous_key_id: credential.previous_key_id,
        introduced_set,
        retired_set: None,
        released: false,
    }
}

impl Proposal {
    /// Decides the reconciliation at the trusted time `now`: refuses a set
    /// below or inconsistent with the accepted one, a discontinuous
    /// succession, and an omitted credential a `normal` route still pins
    /// before its overlap deadline.
    pub(crate) fn decide(
        &self,
        coordinator: &CompanionCoordinator,
        now: u64,
    ) -> Result<Reconciliation, CompanionFault> {
        let set = coordinator.key_set().ok_or(CompanionFault::Storage)?;
        let configured = KeySetRow {
            generation: set.set_generation,
            digest: set.digest,
            credential_ids: set
                .credentials
                .iter()
                .map(|credential| credential.credential_id)
                .collect(),
        };
        let mut reconciliation = Reconciliation::default();
        let omitted = self.omitted(&configured, &mut reconciliation)?;
        for credential in &set.credentials {
            let id = credential.credential_id;
            if !self.history.contains_key(&id) {
                reconciliation
                    .history
                    .insert(id, history_of(credential, configured.generation));
            }
        }
        for id in omitted {
            // An omitted credential was in the accepted set, so its row is
            // not yet retired; the set that omits it retires it.
            let mut row = *self.history.get(&id).ok_or(CompanionFault::Storage)?;
            let _retired = row.retired_set.get_or_insert(configured.generation);
            reconciliation.history.insert(id, row);
            if self.pins.values().any(|pin| *pin == id) {
                let successor_start = set
                    .credentials
                    .iter()
                    .find(|credential| credential.previous_key_id == id)
                    .or_else(|| set.current())
                    .map(|credential| credential.interval.not_before)
                    .ok_or(CompanionFault::Storage)?;
                let deadline = successor_start.saturating_add(MAX_SEQUENCER_KEY_OVERLAP_SECONDS);
                (now >= deadline)
                    .then_some(())
                    .ok_or(CompanionFault::Storage)?;
            }
        }
        self.requirements(&configured, &mut reconciliation);
        self.check_retired_key(coordinator, &reconciliation)?;
        Ok(reconciliation)
    }

    /// A configured retired-retained key must be the key of exactly the
    /// credential the live state requires; a released or unrelated key is
    /// refused (architecture 9457, companion 9.2.1).
    fn check_retired_key(
        &self,
        coordinator: &CompanionCoordinator,
        reconciliation: &Reconciliation,
    ) -> Result<(), CompanionFault> {
        let Some(key) = coordinator.pending_retired_key.as_ref() else {
            return Ok(());
        };
        let required = reconciliation.required_retired.and_then(|id| {
            reconciliation
                .history
                .get(&id)
                .or_else(|| self.history.get(&id))
                .map(|row| row.public_key)
        });
        (required == Some(*key.public_key().as_bytes()))
            .then_some(())
            .ok_or(CompanionFault::Storage)
    }

    /// The accepted credentials the configured set omits, after the set is
    /// checked against the accepted one.
    fn omitted(
        &self,
        configured: &KeySetRow,
        reconciliation: &mut Reconciliation,
    ) -> Result<Vec<[u8; 32]>, CompanionFault> {
        let Some(accepted) = &self.accepted else {
            reconciliation.key_set = Some(configured.clone());
            return Ok(Vec::new());
        };
        if accepted.generation == configured.generation {
            return (accepted.digest == configured.digest)
                .then_some(Vec::new())
                .ok_or(CompanionFault::Storage);
        }
        let advances = accepted.generation.checked_add(1) == Some(configured.generation);
        let continuous = configured
            .credential_ids
            .first()
            .is_some_and(|current| accepted.credential_ids.contains(current));
        (advances && continuous)
            .then_some(())
            .ok_or(CompanionFault::Storage)?;
        reconciliation.key_set = Some(configured.clone());
        Ok(accepted
            .credential_ids
            .iter()
            .filter(|id| !configured.credential_ids.contains(id))
            .copied()
            .collect())
    }

    /// Every pin outside the configured set blocks its route; every such
    /// pin or unfinished receipt requires the retired-retained signer; a
    /// retired credential nothing requires is released.
    fn requirements(&self, configured: &KeySetRow, reconciliation: &mut Reconciliation) {
        let mut required = BTreeSet::new();
        for (conversation, pin) in &self.pins {
            if !configured.credential_ids.contains(pin) {
                reconciliation.blocked.insert(*conversation, *pin);
                required.insert(*pin);
            }
        }
        for id in &self.receipts {
            if !configured.credential_ids.contains(id) {
                required.insert(*id);
            }
        }
        reconciliation.required_retired = required.iter().next().copied();
        for (id, row) in &self.history {
            let history = reconciliation.history.get(id).copied().unwrap_or(*row);
            let retired = history.retired_set.is_some() || !configured.credential_ids.contains(id);
            if retired && !history.released && !required.contains(id) {
                let mut released = history;
                released.retired_set = released.retired_set.or(Some(configured.generation));
                released.released = true;
                reconciliation.history.insert(*id, released);
                reconciliation.released.push(*id);
            }
        }
    }
}

impl Reconciliation {
    /// The durable writes of this reconciliation.
    pub(crate) fn writes(&self) -> Result<Vec<AccountServiceDurableWrite>, CompanionFault> {
        let mut writes = Vec::new();
        let row = |kind, key, body| {
            super::request::state_row(TableId::E2eeState, kind, key, body)
                .map_err(|_| CompanionFault::Storage)
        };
        if let Some(set) = &self.key_set {
            let key = KeySetRow::key().map_err(|_| CompanionFault::Storage)?;
            let body = set.encode().map_err(|_| CompanionFault::Storage)?;
            writes.push(row(KEYSET_ROW_KIND, key, body)?);
        }
        for (id, history) in &self.history {
            let key = SequencerHistoryRow::key(id).map_err(|_| CompanionFault::Storage)?;
            let body = history.encode().map_err(|_| CompanionFault::Storage)?;
            writes.push(row(SEQUENCER_HISTORY_ROW_KIND, key, body)?);
        }
        Ok(writes)
    }

    /// Installs the reconciliation once its batch is durable: the blocked
    /// routes, the retired-retained signer the configured key serves, the
    /// released facts, and the report.
    pub(crate) fn apply(self, coordinator: &mut CompanionCoordinator) {
        for (conversation, pin) in &self.blocked {
            coordinator
                .state
                .conversations
                .entry(*conversation)
                .and_modify(|state| state.blocked_credential_id = Some(*pin));
        }
        let mut report = SignerReport {
            blocked_routes: u64::try_from(self.blocked.len()).unwrap_or(u64::MAX),
            retired_missing: false,
            released: u64::try_from(self.released.len()).unwrap_or(u64::MAX),
        };
        let retired_key = coordinator.pending_retired_key.take();
        if let Some(required) = self.required_retired {
            // `decide` refused any configured key other than this
            // credential's, so a present key installs.
            let credential = self
                .history
                .get(&required)
                .or_else(|| coordinator.signer_history.get(&required))
                .and_then(|row| credential_of(row, required));
            let installed = retired_key
                .zip(credential)
                .is_some_and(|(key, credential)| coordinator.install_retired(key, credential));
            report.retired_missing = !installed;
        }
        for (id, row) in &self.history {
            coordinator.signer_history.insert(*id, *row);
        }
        coordinator.signer_report = report;
    }
}

impl CompanionCoordinator {
    /// Installs the retired-retained signer beside the active and successor
    /// signers; a key shared with either changes nothing.
    fn install_retired(
        &mut self,
        key: Ed25519SecretKey,
        credential: VerifiedSequencerCredential,
    ) -> bool {
        self.signer.as_mut().is_some_and(|signers| {
            let distinct = std::iter::once(&signers.active)
                .chain(signers.successor.as_ref())
                .all(|signer| signer.key.public_key().as_bytes() != key.public_key().as_bytes());
            distinct
                .then(|| {
                    signers.retired = Some((
                        SequencerSigner {
                            key,
                            credential_id: credential.credential_id,
                        },
                        credential,
                    ));
                })
                .is_some()
        })
    }
}
