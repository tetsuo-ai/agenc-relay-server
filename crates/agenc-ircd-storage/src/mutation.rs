//! Owned, prevalidated storage-only mutation and read plans.

use std::collections::BTreeSet;

use agenc_ircd_crypto::{MAX_STORAGE_PLAINTEXT_BYTES, StorageDigest};
use agenc_ircd_types::TransactionId;
use zeroize::Zeroizing;

use crate::{
    MAX_SEALED_RECORD_BYTES, MAX_STORED_KEY_BYTES, MAX_TRACKED_MUTATIONS, MAX_TRANSACTION_PLANS,
    MIN_SEALED_RECORD_BYTES, StorageError, StorageFaultSite, StoredKey, TableId,
    logical_record_charge,
};

/// Exact upper bound on one owned storage handoff allocation.
pub const MAX_STORAGE_MUTATION_BATCH_BYTES: usize = 58_720_240;
const MAX_TRACKED_MUTATION_BYTES: usize = 16_777_216;
/// Greatest logical records removed by one retention transaction.
pub const MAX_RETENTION_DELETIONS: usize = 1_000;
/// Greatest rows one consistent range read returns.
const MAX_RANGE_READ_RECORDS: u16 = 4_096;

/// Existing record metadata required to validate replacement/deletion accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExistingRecord {
    record_schema: u32,
    sealed_record_id: StorageDigest,
    sealed_record_bytes: u32,
}

impl ExistingRecord {
    /// Validates a current record descriptor.
    pub fn new(
        record_schema: u32,
        sealed_record_id: StorageDigest,
        sealed_record_bytes: usize,
    ) -> Result<Self, StorageError> {
        if record_schema == 0
            || !(MIN_SEALED_RECORD_BYTES..=MAX_SEALED_RECORD_BYTES).contains(&sealed_record_bytes)
        {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(Self {
            record_schema,
            sealed_record_id,
            sealed_record_bytes: u32::try_from(sealed_record_bytes)
                .map_err(|_| StorageError::Overflow)?,
        })
    }

    /// Returns the nonzero record schema.
    #[must_use]
    pub const fn record_schema(self) -> u32 {
        self.record_schema
    }

    /// Returns the complete current envelope identifier.
    #[must_use]
    pub const fn sealed_record_id(self) -> StorageDigest {
        self.sealed_record_id
    }

    /// Returns the complete current envelope length.
    #[must_use]
    pub const fn sealed_record_bytes(self) -> u32 {
        self.sealed_record_bytes
    }
}

/// One complete insertion, replacement, or deletion with no runtime handles.
pub struct RecordMutation {
    table: TableId,
    key: StoredKey,
    kind: RecordMutationKind,
}

enum RecordMutationKind {
    Put {
        record_schema: u32,
        before: Option<ExistingRecord>,
        plaintext: Zeroizing<Vec<u8>>,
    },
    Delete {
        before: ExistingRecord,
    },
}

impl RecordMutation {
    /// Creates an insertion or replacement from a bounded canonical plaintext.
    pub fn put(
        table: TableId,
        key: StoredKey,
        record_schema: u32,
        before: Option<ExistingRecord>,
        plaintext: Vec<u8>,
    ) -> Result<Self, StorageError> {
        if record_schema == 0 || plaintext.len() > MAX_STORAGE_PLAINTEXT_BYTES {
            return Err(StorageError::LimitExceeded);
        }
        if before.is_some_and(|record| record.record_schema != record_schema) {
            return Err(StorageError::UnsupportedVersion);
        }
        Ok(Self {
            table,
            key,
            kind: RecordMutationKind::Put {
                record_schema,
                before,
                plaintext: Zeroizing::new(plaintext),
            },
        })
    }

    /// Creates an exact deletion precondition.
    #[must_use]
    pub fn delete(table: TableId, key: StoredKey, before: ExistingRecord) -> Self {
        Self {
            table,
            key,
            kind: RecordMutationKind::Delete { before },
        }
    }

    /// Returns the touched table.
    #[must_use]
    pub const fn table(&self) -> TableId {
        self.table
    }

    /// Borrows the exact touched key.
    #[must_use]
    pub const fn key(&self) -> &StoredKey {
        &self.key
    }

    pub(crate) const fn before(&self) -> Option<ExistingRecord> {
        match &self.kind {
            RecordMutationKind::Put { before, .. } => *before,
            RecordMutationKind::Delete { before } => Some(*before),
        }
    }

    pub(crate) fn resulting_sealed_bytes(&self) -> Result<Option<usize>, StorageError> {
        match &self.kind {
            RecordMutationKind::Put { plaintext, .. } => plaintext
                .len()
                .checked_add(MIN_SEALED_RECORD_BYTES)
                .map(Some)
                .ok_or(StorageError::Overflow),
            RecordMutationKind::Delete { .. } => Ok(None),
        }
    }

    pub(crate) fn plaintext(&self) -> Option<&[u8]> {
        match &self.kind {
            RecordMutationKind::Put { plaintext, .. } => Some(plaintext),
            RecordMutationKind::Delete { .. } => None,
        }
    }

    /// Returns the nonzero record codec schema required by the mutation.
    #[must_use]
    pub const fn record_schema(&self) -> u32 {
        match &self.kind {
            RecordMutationKind::Put { record_schema, .. } => *record_schema,
            RecordMutationKind::Delete { before } => before.record_schema,
        }
    }

    /// Reports whether this mutation durably removes its exact prior envelope.
    #[must_use]
    pub const fn is_deletion(&self) -> bool {
        matches!(self.kind, RecordMutationKind::Delete { .. })
    }
}

/// Exact prior accounting state and configured ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageAccountingLimits {
    /// Current authenticated logical database bytes.
    pub current_logical_database_bytes: u64,
    /// Current authenticated backup stream bytes.
    pub current_backup_stream_bytes: u64,
    /// Configured logical database ceiling.
    pub database_max_bytes: u64,
    /// Configured exact backup stream ceiling.
    pub backup_max_bytes: u64,
}

/// Complete owned mutation handoff accepted by the storage owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageMutationHead {
    /// One transaction identity bound to the complete batch.
    pub transaction_id: TransactionId,
    /// Expected prior storage commit sequence.
    pub expected_storage_commit_sequence: u64,
    /// Expected prior logical state generation.
    pub expected_state_generation: u64,
    /// Exact successor logical state generation.
    pub resulting_state_generation: u64,
    /// Number of plans in this batch that advance logical state.
    pub state_advancing_plan_count: u16,
    /// Expected prior coordinator response count.
    pub expected_account_service_response_count: u64,
    /// Exact successor coordinator response count.
    pub resulting_account_service_response_count: u64,
}

/// Complete owned mutation handoff accepted by the storage owner.
pub struct StorageMutationBatch {
    transaction_id: TransactionId,
    expected_storage_commit_sequence: u64,
    expected_state_generation: u64,
    resulting_state_generation: u64,
    state_advancing_plan_count: u16,
    expected_account_service_response_count: u64,
    resulting_account_service_response_count: u64,
    plan_count: u16,
    seal_count: u32,
    expected_logical_database_bytes: u64,
    expected_backup_stream_bytes: u64,
    resulting_logical_database_bytes: u64,
    resulting_backup_stream_bytes: u64,
    mutations: Vec<RecordMutation>,
    fault_site: Option<StorageFaultSite>,
}

impl StorageMutationBatch {
    /// Recomputes every count and byte bound before accepting an owned batch.
    // agenc-review: focus owner=storage reviewed=2026-08-27 reason=single validation pass binds ordering uniqueness accounting and seal count
    pub fn new(
        head: StorageMutationHead,
        plan_count: usize,
        accounting: StorageAccountingLimits,
        mutations: Vec<RecordMutation>,
    ) -> Result<Self, StorageError> {
        Self::new_for_scope(head, plan_count, accounting, mutations, MutationScope::Live)
    }

    /// Builds an authentication-finish batch containing one exact lazy index migration.
    pub fn new_login_index_lazy(
        head: StorageMutationHead,
        plan_count: usize,
        accounting: StorageAccountingLimits,
        mutations: Vec<RecordMutation>,
    ) -> Result<Self, StorageError> {
        let login_deletions = mutations
            .iter()
            .filter(|mutation| mutation.table() == TableId::LoginIndex && mutation.is_deletion())
            .count();
        let login_insertions = mutations
            .iter()
            .filter(|mutation| mutation.table() == TableId::LoginIndex && !mutation.is_deletion())
            .count();
        let key_state_updates = mutations
            .iter()
            .filter(|mutation| {
                mutation.table() == TableId::LoginIndexKeyState && !mutation.is_deletion()
            })
            .count();
        if login_deletions != 1 || login_insertions != 1 || key_state_updates != 1 {
            return Err(StorageError::InvalidEncoding);
        }
        Self::new(head, plan_count, accounting, mutations)
            .map(|batch| batch.with_fault_site(StorageFaultSite::LoginIndexLazyMigration))
    }

    /// Builds one non-state-advancing deletion set with its durable successor cursor.
    pub fn retention_deletion(
        head: StorageMutationHead,
        accounting: StorageAccountingLimits,
        cursor: RecordMutation,
        mut deletions: Vec<RecordMutation>,
    ) -> Result<Self, StorageError> {
        if deletions.is_empty()
            || deletions.len() > MAX_RETENTION_DELETIONS
            || deletions.iter().any(|mutation| !mutation.is_deletion())
            || cursor.is_deletion()
            || head.resulting_state_generation != head.expected_state_generation
            || head.resulting_account_service_response_count
                != head.expected_account_service_response_count
            || head.state_advancing_plan_count != 0
        {
            return Err(StorageError::InvalidEncoding);
        }
        deletions
            .try_reserve_exact(1)
            .map_err(|_| StorageError::AllocationFailed)?;
        deletions.push(cursor);
        Self::new(head, 1, accounting, deletions)
    }

    pub(crate) fn new_construction(
        head: StorageMutationHead,
        accounting: StorageAccountingLimits,
        mutations: Vec<RecordMutation>,
    ) -> Result<Self, StorageError> {
        Self::new_for_scope(head, 1, accounting, mutations, MutationScope::Construction)
    }

    // agenc-review: focus owner=storage reviewed=2026-08-28 reason=single admission transcript binds ordering uniqueness accounting manifest charge and seal count
    fn new_for_scope(
        head: StorageMutationHead,
        plan_count: usize,
        accounting: StorageAccountingLimits,
        mut mutations: Vec<RecordMutation>,
        scope: MutationScope,
    ) -> Result<Self, StorageError> {
        if (
            !(1..=MAX_TRANSACTION_PLANS).contains(&plan_count),
            mutations.is_empty(),
            mutations.len() > MAX_TRACKED_MUTATIONS,
            head.resulting_account_service_response_count
                < head.expected_account_service_response_count,
        ) != (false, false, false, false)
        {
            return Err(StorageError::LimitExceeded);
        }
        let state_generation_delta = head
            .resulting_state_generation
            .checked_sub(head.expected_state_generation)
            .ok_or(StorageError::StaleState)?;
        if (
            usize::from(head.state_advancing_plan_count) > plan_count,
            state_generation_delta != u64::from(head.state_advancing_plan_count),
        ) != (false, false)
        {
            return Err(StorageError::InvalidEncoding);
        }
        let response_delta = head
            .resulting_account_service_response_count
            .checked_sub(head.expected_account_service_response_count)
            .ok_or(StorageError::Overflow)?;
        if response_delta > u64::try_from(plan_count).map_err(|_| StorageError::Overflow)? {
            return Err(StorageError::InvalidEncoding);
        }
        mutations.sort_by(|left, right| {
            (left.table(), left.key().as_bytes()).cmp(&(right.table(), right.key().as_bytes()))
        });
        let mut identities = BTreeSet::new();
        let mut puts = 0_usize;
        let mut logical = accounting.current_logical_database_bytes;
        let mut backup = accounting.current_backup_stream_bytes;
        let mut owned_bytes = 0_usize;
        let mut tracked_mutation_bytes = 0_usize;
        for mutation in &mutations {
            if (
                !mutation.table().is_integrity_tracked(),
                (scope, mutation.table()) == (MutationScope::Live, TableId::StorageConstruction),
            ) != (false, false)
            {
                return Err(StorageError::InvalidEncoding);
            }
            let identity = (mutation.table(), mutation.key().as_bytes());
            if !identities.insert(identity) {
                return Err(StorageError::InvalidEncoding);
            }
            let key_len = mutation.key().as_bytes().len();
            owned_bytes = owned_bytes
                .checked_add(key_len)
                .and_then(|value| value.checked_add(mutation.plaintext().map_or(0, <[u8]>::len)))
                .ok_or(StorageError::Overflow)?;
            if let Some(before) = mutation.before() {
                let before_bytes = usize::try_from(before.sealed_record_bytes)
                    .map_err(|_| StorageError::Overflow)?;
                tracked_mutation_bytes = tracked_mutation_bytes
                    .checked_add(before_bytes)
                    .ok_or(StorageError::Overflow)?;
                logical = logical
                    .checked_sub(logical_record_charge(key_len, before_bytes)?)
                    .ok_or(StorageError::StaleState)?;
                backup = backup
                    .checked_sub(backup_record_charge(key_len, before_bytes)?)
                    .ok_or(StorageError::StaleState)?;
            }
            if let Some(after_bytes) = mutation.resulting_sealed_bytes()? {
                tracked_mutation_bytes = tracked_mutation_bytes
                    .checked_add(after_bytes)
                    .ok_or(StorageError::Overflow)?;
                puts = puts.checked_add(1).ok_or(StorageError::Overflow)?;
                logical = logical
                    .checked_add(logical_record_charge(key_len, after_bytes)?)
                    .ok_or(StorageError::Overflow)?;
                backup = backup
                    .checked_add(backup_record_charge(key_len, after_bytes)?)
                    .ok_or(StorageError::Overflow)?;
            }
            tracked_mutation_bytes = tracked_mutation_bytes
                .checked_add(key_len)
                .ok_or(StorageError::Overflow)?;
        }
        let manifest_plaintext_bytes = manifest_plaintext_bytes(&mutations)?;
        let manifest_sealed_bytes = manifest_plaintext_bytes
            .checked_add(MIN_SEALED_RECORD_BYTES)
            .ok_or(StorageError::Overflow)?;
        logical = logical
            .checked_add(logical_record_charge(8, manifest_sealed_bytes)?)
            .ok_or(StorageError::Overflow)?;
        backup = backup
            .checked_add(backup_record_charge(8, manifest_sealed_bytes)?)
            .ok_or(StorageError::Overflow)?;
        // Every mutation that reached this point is integrity tracked and the batch is non-empty,
        // so the tracked count needs no separate check.
        if (
            owned_bytes > MAX_STORAGE_MUTATION_BATCH_BYTES,
            tracked_mutation_bytes > MAX_TRACKED_MUTATION_BYTES,
            logical > accounting.database_max_bytes,
            backup > accounting.backup_max_bytes,
        ) != (false, false, false, false)
        {
            return Err(StorageError::LimitExceeded);
        }
        let seal_count = puts.checked_add(2).ok_or(StorageError::Overflow)?;
        Ok(Self {
            transaction_id: head.transaction_id,
            expected_storage_commit_sequence: head.expected_storage_commit_sequence,
            expected_state_generation: head.expected_state_generation,
            resulting_state_generation: head.resulting_state_generation,
            state_advancing_plan_count: head.state_advancing_plan_count,
            expected_account_service_response_count: head.expected_account_service_response_count,
            resulting_account_service_response_count: head.resulting_account_service_response_count,
            plan_count: u16::try_from(plan_count).map_err(|_| StorageError::Overflow)?,
            seal_count: u32::try_from(seal_count).map_err(|_| StorageError::Overflow)?,
            expected_logical_database_bytes: accounting.current_logical_database_bytes,
            expected_backup_stream_bytes: accounting.current_backup_stream_bytes,
            resulting_logical_database_bytes: logical,
            resulting_backup_stream_bytes: backup,
            mutations,
            fault_site: None,
        })
    }

    /// Returns the one transaction identity bound to the handoff.
    #[must_use]
    pub const fn transaction_id(&self) -> TransactionId {
        self.transaction_id
    }

    /// Returns the expected prior commit sequence.
    #[must_use]
    pub const fn expected_storage_commit_sequence(&self) -> u64 {
        self.expected_storage_commit_sequence
    }

    /// Returns the prior logical generation.
    #[must_use]
    pub const fn expected_state_generation(&self) -> u64 {
        self.expected_state_generation
    }

    /// Returns the exact successor logical generation.
    #[must_use]
    pub const fn resulting_state_generation(&self) -> u64 {
        self.resulting_state_generation
    }

    /// Returns the exact number of plans that advance logical state.
    #[must_use]
    pub const fn state_advancing_plan_count(&self) -> u16 {
        self.state_advancing_plan_count
    }

    /// Returns the expected prior coordinator-sealed response count.
    #[must_use]
    pub const fn expected_account_service_response_count(&self) -> u64 {
        self.expected_account_service_response_count
    }

    /// Returns the exact successor coordinator-sealed response count.
    #[must_use]
    pub const fn resulting_account_service_response_count(&self) -> u64 {
        self.resulting_account_service_response_count
    }

    /// Returns the number of compatible logical plans in the batch.
    #[must_use]
    pub const fn plan_count(&self) -> u16 {
        self.plan_count
    }

    /// Returns the exact reservation length.
    #[must_use]
    pub const fn seal_count(&self) -> u32 {
        self.seal_count
    }

    /// Returns the authenticated logical charge expected before the batch.
    #[must_use]
    pub const fn expected_logical_database_bytes(&self) -> u64 {
        self.expected_logical_database_bytes
    }

    /// Returns the authenticated backup-stream length expected before the batch.
    #[must_use]
    pub const fn expected_backup_stream_bytes(&self) -> u64 {
        self.expected_backup_stream_bytes
    }

    /// Returns the recomputed successor logical charge.
    #[must_use]
    pub const fn resulting_logical_database_bytes(&self) -> u64 {
        self.resulting_logical_database_bytes
    }

    /// Returns the recomputed successor backup size.
    #[must_use]
    pub const fn resulting_backup_stream_bytes(&self) -> u64 {
        self.resulting_backup_stream_bytes
    }

    /// Borrows canonical mutations in table/key order.
    #[must_use]
    pub fn mutations(&self) -> &[RecordMutation] {
        &self.mutations
    }

    pub(crate) fn with_fault_site(mut self, fault_site: StorageFaultSite) -> Self {
        self.fault_site = Some(fault_site);
        self
    }

    pub(crate) const fn fault_site(&self) -> Option<StorageFaultSite> {
        self.fault_site
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum MutationScope {
    Live,
    Construction,
}

fn manifest_plaintext_bytes(mutations: &[RecordMutation]) -> Result<usize, StorageError> {
    let mut bytes = 162_usize;
    for mutation in mutations
        .iter()
        .filter(|mutation| mutation.table().is_integrity_tracked())
    {
        let before_identifier = if mutation.before().is_some() { 32 } else { 0 };
        let after_identifier = if mutation.plaintext().is_some() {
            32
        } else {
            0
        };
        bytes = bytes
            .checked_add(26)
            .and_then(|value| value.checked_add(mutation.key().as_bytes().len()))
            .and_then(|value| value.checked_add(before_identifier))
            .and_then(|value| value.checked_add(after_identifier))
            .ok_or(StorageError::Overflow)?;
    }
    if bytes > crate::MAX_INTEGRITY_PLAINTEXT_BYTES {
        return Err(StorageError::LimitExceeded);
    }
    Ok(bytes)
}

pub(crate) fn manifest_sealed_record_bytes(
    mutations: &[RecordMutation],
) -> Result<usize, StorageError> {
    manifest_plaintext_bytes(mutations)?
        .checked_add(MIN_SEALED_RECORD_BYTES)
        .ok_or(StorageError::Overflow)
}

fn backup_record_charge(key_bytes: usize, sealed_record_bytes: usize) -> Result<u64, StorageError> {
    if (
        key_bytes == 0,
        key_bytes > MAX_STORED_KEY_BYTES,
        !(MIN_SEALED_RECORD_BYTES..=MAX_SEALED_RECORD_BYTES).contains(&sealed_record_bytes),
    ) != (false, false, false)
    {
        return Err(StorageError::LimitExceeded);
    }
    let bytes = 18_usize
        .checked_add(key_bytes)
        .and_then(|value| value.checked_add(sealed_record_bytes))
        .ok_or(StorageError::Overflow)?;
    u64::try_from(bytes).map_err(|_| StorageError::Overflow)
}

/// Bounded consistent read request.
pub struct ReadPlan {
    kind: ReadPlanKind,
}

pub(crate) enum ReadPlanKind {
    Exact {
        table: TableId,
        key: StoredKey,
    },
    Range {
        table: TableId,
        start: StoredKey,
        end: StoredKey,
        limit: u16,
    },
}

impl ReadPlan {
    /// Creates one exact read request.
    #[must_use]
    pub fn exact(table: TableId, key: StoredKey) -> Self {
        Self {
            kind: ReadPlanKind::Exact { table, key },
        }
    }

    /// Creates a bounded range request.
    pub fn range(
        table: TableId,
        start: StoredKey,
        end: StoredKey,
        limit: u16,
    ) -> Result<Self, StorageError> {
        if start >= end || limit == 0 || limit > MAX_RANGE_READ_RECORDS {
            return Err(StorageError::LimitExceeded);
        }
        Ok(Self {
            kind: ReadPlanKind::Range {
                table,
                start,
                end,
                limit,
            },
        })
    }

    pub(crate) const fn kind(&self) -> &ReadPlanKind {
        &self.kind
    }
}

/// One raw sealed row returned from a consistent read transaction.
pub struct ReadRecord {
    /// Registered table.
    pub table: TableId,
    /// Exact stored key.
    pub key: StoredKey,
    /// Complete canonical SealedRecord bytes.
    pub sealed_record: Vec<u8>,
}

/// Complete bounded consistent-read result.
pub struct ReadResult {
    /// Commit sequence observed by the immutable read transaction.
    pub storage_commit_sequence: u64,
    /// Rows in canonical table/key order.
    pub records: Vec<ReadRecord>,
}

/// Successful durable receipt returned only after guard installation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitReceipt {
    /// Matching submitted transaction.
    pub transaction_id: TransactionId,
    /// Successive authenticated storage commit sequence.
    pub storage_commit_sequence: u64,
    /// Resulting logical state generation.
    pub state_generation: u64,
    /// Complete committed rollback-guard hash.
    pub rollback_guard_hash: StorageDigest,
}

/// Closed storage outcome; uncertainty is never represented as rejection.
pub enum CommitOutcome {
    /// Database commit and committed-guard replacement are durable.
    Committed(CommitReceipt),
    /// The irreversible commit was proven not to have begun.
    Rejected(StorageError),
    /// Persistence may have occurred; the owner is permanently closed.
    Indeterminate,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PersistentRecordValue;

    #[test]
    fn manifest_and_backup_charge_helpers_reject_their_exact_ceilings() -> Result<(), StorageError>
    {
        assert_eq!(
            backup_record_charge(0, MIN_SEALED_RECORD_BYTES),
            Err(StorageError::LimitExceeded),
        );
        assert_eq!(
            backup_record_charge(MAX_STORED_KEY_BYTES + 1, MIN_SEALED_RECORD_BYTES),
            Err(StorageError::LimitExceeded),
        );
        assert_eq!(
            backup_record_charge(1, MIN_SEALED_RECORD_BYTES - 1),
            Err(StorageError::LimitExceeded),
        );
        assert_eq!(
            backup_record_charge(1, MAX_SEALED_RECORD_BYTES + 1),
            Err(StorageError::LimitExceeded),
        );

        let plaintext = PersistentRecordValue::new(
            TableId::Sanction,
            1,
            1,
            0,
            None,
            Vec::new(),
            crate::domain_records::fixtures::live_body(TableId::Sanction, 1)?,
        )?
        .encode()?;
        let mut mutations = Vec::new();
        mutations
            .try_reserve_exact(4_100)
            .map_err(|_| StorageError::AllocationFailed)?;
        for index in 0_u64..4_100 {
            let mut key = vec![0_u8; MAX_STORED_KEY_BYTES];
            key.get_mut(..8)
                .ok_or(StorageError::InvalidEncoding)?
                .copy_from_slice(&index.to_be_bytes());
            mutations.push(RecordMutation::put(
                TableId::Sanction,
                StoredKey::new(key)?,
                1,
                None,
                plaintext.clone(),
            )?);
        }
        assert_eq!(
            manifest_plaintext_bytes(&mutations),
            Err(StorageError::LimitExceeded),
        );
        Ok(())
    }
}
