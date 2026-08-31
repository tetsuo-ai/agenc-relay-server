//! The runtime layer of the persistence boundary (spec 21.5, lines
//! 4152-4165; spec 23.2 table registry, lines 4700-4750).
//!
//! The domain declares logical writes, storage owns the body codecs, and
//! this module owns what neither may know: the keyed stored keys, the
//! before-image of every row it touches, the head counters, and the
//! projection of a batch of plans into one `StorageMutationBatch` that
//! carries no handle, closure, frame, or permit.

use std::collections::{BTreeMap, BTreeSet};

use agenc_ircd_admin::{AdminAuditCheckpoint, AdminAuditEvent};
use agenc_ircd_crypto::{
    DatabaseBinding, OpenedStoragePlaintext, StorageMasterKey, StorageTable, derive_storage_index,
};
use agenc_ircd_domain::{
    ChannelNameValue, DurableAccount, DurableChannel, DurableSanction, DurableWrite, MutationPlan,
    NicknameValue,
};
use agenc_ircd_storage::{
    AccountRecordBody, ChannelRecordBody, CommitReceipt, ExistingRecord, LIVE_RECORD_KIND,
    MAX_TRANSACTION_PLANS, PersistentRecordValue, ReadPlan, RecordMutation, RecordReference,
    RecoveredStorageState, SanctionRecordBody, SealedRecord, StorageAccountingLimits, StorageError,
    StorageMutationBatch, StorageMutationHead, StoragePort, StoredKey, TableId,
    validate_record_plaintext,
};
use agenc_ircd_types::{AccountId, ChannelInstanceId, EntropySource, TransactionId};
use zeroize::Zeroizing;

use crate::RuntimeError;
use crate::bridge::storage::read_blocking;

/// The record kind Stage 5 reserves for an account or channel tombstone
/// (`validate_record_counters`, storage records.rs).
pub const TOMBSTONE_RECORD_KIND: u16 = 2;
/// The record schema every Stage 06 domain row is sealed under.
pub const DOMAIN_RECORD_SCHEMA: u32 = 1;
/// Sanction stored-key scope tag for a network-wide sanction (spec 23.2:
/// "scope + random sanction ID").
pub const SANCTION_SCOPE_NETWORK: u16 = 0;
/// Sanction stored-key scope tag for a channel-scoped sanction.
pub const SANCTION_SCOPE_CHANNEL: u16 = 1;
/// Random bytes in a sanction stored key.
pub const SANCTION_KEY_RANDOM_BYTES: usize = 16;
/// Largest expired audit prefix replaced by one checkpoint per sweep.
pub(crate) const MAX_AUDIT_RETENTION_EVENTS: usize = 4_096;

/// Derives every stored key the runtime writes and opens sealed rows.
///
/// Holds the master key for the lifetime of the state owner; it never leaves
/// this type except through the crypto adapters.
pub struct KeyDeriver {
    master_key: StorageMasterKey,
    binding: DatabaseBinding,
    key_generation: u32,
}

impl KeyDeriver {
    /// Binds the master key to the database identity and its active
    /// storage-key generation.
    pub fn new(
        master_key: StorageMasterKey,
        binding: DatabaseBinding,
        key_generation: u32,
    ) -> Result<Self, RuntimeError> {
        if key_generation == 0 {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(Self {
            master_key,
            binding,
            key_generation,
        })
    }

    /// Returns the immutable record-encryption binding.
    #[must_use]
    pub const fn binding(&self) -> DatabaseBinding {
        self.binding
    }

    /// Returns the active storage-key generation.
    #[must_use]
    pub const fn key_generation(&self) -> u32 {
        self.key_generation
    }

    /// The `account` table key: the 24-byte account identity text.
    pub fn account_key(account_id: AccountId) -> Result<StoredKey, RuntimeError> {
        Ok(StoredKey::new(account_id.to_text().into_bytes())?)
    }

    /// The `channel` table key: the 16 instance identity bytes.
    pub fn channel_key(channel_id: ChannelInstanceId) -> Result<StoredKey, RuntimeError> {
        Ok(StoredKey::new(channel_id.as_bytes().to_vec())?)
    }

    /// The `channel_name` table key: the keyed digest of the canonical name.
    pub fn channel_name_key(&self, name: &ChannelNameValue) -> Result<StoredKey, RuntimeError> {
        self.keyed(TableId::ChannelName, name.canonical().as_bytes())
    }

    /// The `nickname_reservation` table key: the keyed digest of the
    /// canonical nickname.
    pub fn nickname_key(&self, nickname: &NicknameValue) -> Result<StoredKey, RuntimeError> {
        self.keyed(
            TableId::NicknameReservation,
            nickname.canonical().as_bytes(),
        )
    }

    /// The `sanction` table key: the scope tag followed by random bytes.
    pub fn sanction_key(
        scope: Option<ChannelInstanceId>,
        random: [u8; SANCTION_KEY_RANDOM_BYTES],
    ) -> Result<StoredKey, RuntimeError> {
        let tag = match scope {
            None => SANCTION_SCOPE_NETWORK,
            Some(_) => SANCTION_SCOPE_CHANNEL,
        };
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(2 + SANCTION_KEY_RANDOM_BYTES)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        bytes.extend_from_slice(&tag.to_be_bytes());
        bytes.extend_from_slice(&random);
        Ok(StoredKey::new(bytes)?)
    }

    /// Authenticates and opens one sealed row of the active generation.
    pub fn open(
        &self,
        table: TableId,
        key: &StoredKey,
        sealed: &SealedRecord,
    ) -> Result<OpenedStoragePlaintext, RuntimeError> {
        Ok(sealed.open(
            &self.master_key,
            self.binding,
            table,
            DOMAIN_RECORD_SCHEMA,
            self.key_generation,
            key,
        )?)
    }

    fn keyed(&self, table: TableId, semantic: &[u8]) -> Result<StoredKey, RuntimeError> {
        let crypto_table =
            StorageTable::new(table.as_u16()).map_err(|_| RuntimeError::InvalidValue)?;
        let index = derive_storage_index(
            &self.master_key,
            self.binding,
            crypto_table,
            self.key_generation,
            semantic,
        )
        .map_err(|_| RuntimeError::InvalidValue)?;
        Ok(StoredKey::new(index.expose_for_storage_key().to_vec())?)
    }
}

/// What the index knows about one stored row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IndexedRow {
    /// The exact sealed identity and length read from the database.
    Known(ExistingRecord),
    /// A row this process wrote whose sealed identity has not been read back
    /// yet; a projection that needs it must refresh first.
    Pending {
        /// The plaintext length of the written row.
        plaintext_bytes: usize,
    },
}

/// Head counters the next batch must be fenced against.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeadCounters {
    /// Last committed logical state generation.
    pub state_generation: u64,
    /// Last observed storage commit sequence.
    pub storage_commit_sequence: u64,
    /// Committed account-service response count.
    pub account_service_response_count: u64,
    /// Authenticated logical database bytes.
    pub logical_database_bytes: u64,
    /// Authenticated backup stream bytes.
    pub backup_stream_bytes: u64,
}

impl HeadCounters {
    /// Seeds the counters from the recovered storage facts.
    #[must_use]
    pub const fn from_recovered(recovered: &RecoveredStorageState) -> Self {
        Self {
            state_generation: recovered.state_generation(),
            storage_commit_sequence: recovered.storage_commit_sequence(),
            account_service_response_count: recovered.account_service_response_count(),
            logical_database_bytes: recovered.logical_database_bytes(),
            backup_stream_bytes: recovered.backup_stream_bytes(),
        }
    }

    /// Advances the counters after a committed batch.
    #[must_use]
    pub const fn after_commit(self, receipt: &CommitReceipt, batch: &ProjectedBatch) -> Self {
        Self {
            state_generation: receipt.state_generation,
            storage_commit_sequence: receipt.storage_commit_sequence,
            account_service_response_count: batch.resulting_account_service_response_count,
            logical_database_bytes: batch.resulting_logical_database_bytes,
            backup_stream_bytes: batch.resulting_backup_stream_bytes,
        }
    }
}

/// Configured storage ceilings the batch must respect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountingCeilings {
    /// Configured logical database ceiling.
    pub database_max_bytes: u64,
    /// Configured backup stream ceiling.
    pub backup_max_bytes: u64,
}

/// One change the index applies after the batch it belongs to commits.
#[derive(Clone, Eq, PartialEq)]
pub enum IndexUpdate {
    /// A row was written; its sealed identity must be read back.
    Put {
        /// The touched table.
        table: TableId,
        /// The touched key.
        key: StoredKey,
        /// The written plaintext length.
        plaintext_bytes: usize,
    },
    /// A row was deleted.
    Delete {
        /// The touched table.
        table: TableId,
        /// The touched key.
        key: StoredKey,
    },
    /// An account now owns a nickname reservation row.
    NicknameOwned {
        /// The owning account.
        account_id: AccountId,
        /// The canonical nickname.
        canonical: String,
        /// The reservation row key.
        key: StoredKey,
    },
    /// An account released a nickname reservation row.
    NicknameReleased {
        /// The releasing account.
        account_id: AccountId,
        /// The canonical nickname.
        canonical: String,
    },
    /// A channel gained its name row.
    ChannelNamed {
        /// The channel.
        channel_id: ChannelInstanceId,
        /// The name row key.
        key: StoredKey,
    },
    /// A channel lost its name row.
    ChannelUnnamed {
        /// The channel.
        channel_id: ChannelInstanceId,
    },
}

/// Before-images and secondary-row ownership for every durable row.
#[derive(Default)]
pub struct DurableIndex {
    rows: BTreeMap<(TableId, StoredKey), IndexedRow>,
    nicknames: BTreeMap<AccountId, BTreeMap<String, StoredKey>>,
    channel_names: BTreeMap<ChannelInstanceId, StoredKey>,
}

impl DurableIndex {
    /// Creates an empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one row read from the database.
    pub fn record_known(&mut self, table: TableId, key: StoredKey, existing: ExistingRecord) {
        self.rows.insert((table, key), IndexedRow::Known(existing));
    }

    /// Records that an account owns a nickname reservation row.
    pub fn record_nickname(&mut self, account_id: AccountId, canonical: String, key: StoredKey) {
        self.nicknames
            .entry(account_id)
            .or_default()
            .insert(canonical, key);
    }

    /// Records a channel's name row.
    pub fn record_channel_name(&mut self, channel_id: ChannelInstanceId, key: StoredKey) {
        self.channel_names.insert(channel_id, key);
    }

    /// Returns the before-image for a row, `None` when the row is absent.
    ///
    /// A pending row is a caller error: the index must be refreshed after
    /// every commit before the next projection.
    pub fn existing(
        &self,
        table: TableId,
        key: &StoredKey,
    ) -> Result<Option<ExistingRecord>, RuntimeError> {
        match self.rows.get(&(table, key.clone())) {
            None => Ok(None),
            Some(IndexedRow::Known(existing)) => Ok(Some(*existing)),
            Some(IndexedRow::Pending { .. }) => {
                Err(RuntimeError::Storage(StorageError::StaleState))
            }
        }
    }

    /// Returns the nickname rows an account owns, keyed by canonical name.
    #[must_use]
    pub fn nickname_rows(&self, account_id: AccountId) -> BTreeMap<String, StoredKey> {
        self.nicknames.get(&account_id).cloned().unwrap_or_default()
    }

    /// Returns a channel's name row key, if it has one.
    #[must_use]
    pub fn channel_name_row(&self, channel_id: ChannelInstanceId) -> Option<&StoredKey> {
        self.channel_names.get(&channel_id)
    }

    /// Applies the updates of a committed batch.
    pub fn apply(&mut self, updates: &[IndexUpdate]) {
        for update in updates {
            self.apply_one(update);
        }
    }

    fn apply_one(&mut self, update: &IndexUpdate) {
        match update {
            IndexUpdate::Put {
                table,
                key,
                plaintext_bytes,
            } => {
                self.rows.insert(
                    (*table, key.clone()),
                    IndexedRow::Pending {
                        plaintext_bytes: *plaintext_bytes,
                    },
                );
            }
            IndexUpdate::Delete { table, key } => {
                self.rows.remove(&(*table, key.clone()));
            }
            IndexUpdate::NicknameOwned {
                account_id,
                canonical,
                key,
            } => self.record_nickname(*account_id, canonical.clone(), key.clone()),
            IndexUpdate::NicknameReleased {
                account_id,
                canonical,
            } => self.release_nickname(*account_id, canonical),
            IndexUpdate::ChannelNamed { channel_id, key } => {
                self.channel_names.insert(*channel_id, key.clone());
            }
            IndexUpdate::ChannelUnnamed { channel_id } => {
                self.channel_names.remove(channel_id);
            }
        }
    }

    fn release_nickname(&mut self, account_id: AccountId, canonical: &str) {
        let Some(rows) = self.nicknames.get_mut(&account_id) else {
            return;
        };
        rows.remove(canonical);
        if rows.is_empty() {
            self.nicknames.remove(&account_id);
        }
    }

    /// Lists the rows whose sealed identity must be read back.
    #[must_use]
    pub fn pending_rows(&self) -> Vec<(TableId, StoredKey)> {
        self.rows
            .iter()
            .filter(|(_, row)| matches!(row, IndexedRow::Pending { .. }))
            .map(|((table, key), _)| (*table, key.clone()))
            .collect()
    }

    /// Replaces pending rows with the identities read back from storage.
    ///
    /// A row that is pending but absent from the read, or whose sealed
    /// length disagrees with the written plaintext, means the database no
    /// longer matches this process's view.
    pub fn refresh(
        &mut self,
        rows: Vec<(TableId, StoredKey, Option<ExistingRecord>)>,
    ) -> Result<(), RuntimeError> {
        for (table, key, existing) in rows {
            let slot = self
                .rows
                .get_mut(&(table, key))
                .ok_or(RuntimeError::Storage(StorageError::StaleState))?;
            let IndexedRow::Pending { plaintext_bytes } = *slot else {
                return Err(RuntimeError::Storage(StorageError::StaleState));
            };
            let Some(existing) = existing else {
                return Err(RuntimeError::Storage(StorageError::StaleState));
            };
            if !sealed_length_matches(plaintext_bytes, existing) {
                return Err(RuntimeError::Storage(StorageError::StaleState));
            }
            *slot = IndexedRow::Known(existing);
        }
        Ok(())
    }

    /// Returns the number of tracked rows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Returns whether no row is tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

/// A sealed envelope is the plaintext plus the fixed envelope and tag
/// (`MIN_SEALED_RECORD_BYTES` covers an empty plaintext).
fn sealed_length_matches(plaintext_bytes: usize, existing: ExistingRecord) -> bool {
    let expected = plaintext_bytes.checked_add(agenc_ircd_storage::MIN_SEALED_RECORD_BYTES);
    expected.is_some_and(|expected| {
        usize::try_from(existing.sealed_record_bytes()).is_ok_and(|actual| actual == expected)
    })
}

/// A domain entity a pending batch reserves while its plans are in flight
/// (spec lines 4167-4168).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EntityId {
    /// One account.
    Account(AccountId),
    /// One channel instance.
    Channel(ChannelInstanceId),
}

/// The entities a plan's logical writes touch.
#[must_use]
pub fn touched_entities(plan: &MutationPlan) -> BTreeSet<EntityId> {
    plan.durable_writes()
        .iter()
        .filter_map(|write| match write {
            DurableWrite::PutAccount(account) => Some(EntityId::Account(account.account_id)),
            DurableWrite::TombstoneAccount(account_id) => Some(EntityId::Account(*account_id)),
            DurableWrite::PutChannel(channel) => Some(EntityId::Channel(channel.channel_id)),
            DurableWrite::TombstoneChannel { channel_id, .. } => {
                Some(EntityId::Channel(*channel_id))
            }
            DurableWrite::AppendSanction(_) => None,
        })
        .collect()
}

/// One already encoded account-service row that must commit with a domain plan.
///
/// The storage plaintext remains zeroizing while StateCore gathers a batch.
/// Its constructor accepts only the closed account-service record set and
/// validates the complete table codec before the write can be staged.
pub(crate) enum AccountServiceDurableWrite {
    Put {
        table: TableId,
        key: StoredKey,
        plaintext: Zeroizing<Vec<u8>>,
    },
    Delete {
        table: TableId,
        key: StoredKey,
    },
}

impl AccountServiceDurableWrite {
    pub(crate) fn put(
        table: TableId,
        key: StoredKey,
        plaintext: Vec<u8>,
    ) -> Result<Self, RuntimeError> {
        if !account_service_table(table) {
            return Err(RuntimeError::InvalidValue);
        }
        validate_record_plaintext(table, &key, DOMAIN_RECORD_SCHEMA, &plaintext)?;
        Ok(Self::Put {
            table,
            key,
            plaintext: Zeroizing::new(plaintext),
        })
    }

    pub(crate) fn delete(table: TableId, key: StoredKey) -> Result<Self, RuntimeError> {
        if !account_service_table(table) {
            return Err(RuntimeError::InvalidValue);
        }
        agenc_ircd_storage::table_schema(table).validate_key(key.as_bytes())?;
        Ok(Self::Delete { table, key })
    }

    pub(crate) fn revalidate(self) -> Result<Self, RuntimeError> {
        match self {
            Self::Put {
                table,
                key,
                plaintext,
            } => Self::put(table, key, plaintext.as_slice().to_vec()),
            Self::Delete { table, key } => Self::delete(table, key),
        }
    }
}

const fn account_service_table(table: TableId) -> bool {
    matches!(
        table,
        TableId::Account
            | TableId::LoginIndex
            | TableId::OpaqueRecord
            | TableId::AuthTransaction
            | TableId::RegistrationInvite
            | TableId::Session
            | TableId::RequestResult
            | TableId::LoginIndexKeyState
    )
}

/// One plan submitted for projection.
pub struct PlanProjection<'a> {
    /// The domain plan.
    pub plan: &'a MutationPlan,
    /// Account-service response count permits this plan consumes.
    pub response_count_increment: u64,
    /// Exact account-service rows inseparable from this plan.
    pub(crate) account_service_writes: &'a [AccountServiceDurableWrite],
}

/// A batch ready for the storage owner plus the index changes to apply once
/// it commits.
pub struct ProjectedBatch {
    batch: StorageMutationBatch,
    updates: Vec<IndexUpdate>,
    advancing_plans: u16,
    resulting_account_service_response_count: u64,
    resulting_logical_database_bytes: u64,
    resulting_backup_stream_bytes: u64,
}

impl ProjectedBatch {
    /// Returns the transaction identity bound to the batch.
    #[must_use]
    pub const fn transaction_id(&self) -> TransactionId {
        self.batch.transaction_id()
    }

    /// Returns the number of plans that advance the state generation.
    #[must_use]
    pub const fn advancing_plans(&self) -> u16 {
        self.advancing_plans
    }

    /// Borrows the index updates.
    #[must_use]
    pub fn updates(&self) -> &[IndexUpdate] {
        &self.updates
    }

    /// Returns the number of record mutations.
    #[must_use]
    pub fn mutation_count(&self) -> usize {
        self.batch.mutations().len()
    }

    /// Splits the projection into the owned batch and the retained updates.
    #[must_use]
    pub fn into_parts(self) -> (StorageMutationBatch, RetainedProjection) {
        (
            self.batch,
            RetainedProjection {
                updates: self.updates,
                resulting_account_service_response_count: self
                    .resulting_account_service_response_count,
                resulting_logical_database_bytes: self.resulting_logical_database_bytes,
                resulting_backup_stream_bytes: self.resulting_backup_stream_bytes,
            },
        )
    }
}

/// What StateCore keeps after handing the batch to storage.
pub struct RetainedProjection {
    updates: Vec<IndexUpdate>,
    resulting_account_service_response_count: u64,
    resulting_logical_database_bytes: u64,
    resulting_backup_stream_bytes: u64,
}

impl RetainedProjection {
    /// Borrows the index updates.
    #[must_use]
    pub fn updates(&self) -> &[IndexUpdate] {
        &self.updates
    }

    /// Advances the head counters with the receipt of this projection.
    #[must_use]
    pub const fn advance(&self, receipt: &CommitReceipt) -> HeadCounters {
        HeadCounters {
            state_generation: receipt.state_generation,
            storage_commit_sequence: receipt.storage_commit_sequence,
            account_service_response_count: self.resulting_account_service_response_count,
            logical_database_bytes: self.resulting_logical_database_bytes,
            backup_stream_bytes: self.resulting_backup_stream_bytes,
        }
    }
}

/// Reads the exact sealed identity and length of rows written by a committed
/// batch. This runs on the caller's blocking thread, never on a Tokio worker.
pub(crate) fn read_back(
    port: &StoragePort,
    rows: Vec<(TableId, StoredKey)>,
) -> Result<Vec<(TableId, StoredKey, Option<ExistingRecord>)>, RuntimeError> {
    let mut read_rows = Vec::new();
    read_rows
        .try_reserve_exact(rows.len())
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    for (table, key) in rows {
        let existing = read_existing(port, table, &key)?;
        read_rows.push((table, key, existing));
    }
    Ok(read_rows)
}

fn read_existing(
    port: &StoragePort,
    table: TableId,
    key: &StoredKey,
) -> Result<Option<ExistingRecord>, RuntimeError> {
    let result = read_blocking(port, ReadPlan::exact(table, key.clone()))?;
    let mut records = result.records.into_iter();
    let Some(record) = records.next() else {
        return Ok(None);
    };
    if records.next().is_some() || record.table != table || record.key != *key {
        return Err(RuntimeError::Storage(StorageError::StaleState));
    }
    let sealed = SealedRecord::decode(&record.sealed_record)?;
    Ok(Some(ExistingRecord::new(
        sealed.record_schema(),
        sealed.record_id()?,
        record.sealed_record.len(),
    )?))
}

struct Projection<'a> {
    index: &'a DurableIndex,
    keys: &'a KeyDeriver,
    mutations: Vec<RecordMutation>,
    updates: Vec<IndexUpdate>,
    touched: BTreeSet<(TableId, StoredKey)>,
}

/// Projects every plan's logical writes into one owned storage batch.
///
/// Returns `None` when no plan produces a persisted delta; such plans are
/// applied in the same actor step without a storage round trip (spec line
/// 4165 keeps the ordering rule for reserved entities).
pub fn project_batch(
    transaction_id: TransactionId,
    plans: &[PlanProjection<'_>],
    index: &DurableIndex,
    keys: &KeyDeriver,
    head: HeadCounters,
    ceilings: AccountingCeilings,
    entropy: &mut dyn EntropySource,
) -> Result<Option<ProjectedBatch>, RuntimeError> {
    if plans.is_empty() || plans.len() > MAX_TRANSACTION_PLANS {
        return Err(RuntimeError::InvalidValue);
    }
    let mut projection = Projection {
        index,
        keys,
        mutations: Vec::new(),
        updates: Vec::new(),
        touched: BTreeSet::new(),
    };
    let mut advancing: u16 = 0;
    let mut response_count = head.account_service_response_count;
    for plan in plans {
        let before = projection.mutations.len();
        let revision = plan.plan.resulting_revision().get();
        for write in plan.plan.durable_writes() {
            projection.project_write(write, revision, entropy)?;
        }
        for write in plan.account_service_writes {
            projection.project_account_service_write(write, revision)?;
        }
        if projection.mutations.len() > before {
            advancing = advancing.checked_add(1).ok_or(RuntimeError::Overflow)?;
        }
        response_count = response_count
            .checked_add(plan.response_count_increment)
            .ok_or(RuntimeError::Overflow)?;
    }
    if projection.mutations.is_empty() {
        return Ok(None);
    }
    let batch = StorageMutationBatch::new(
        StorageMutationHead {
            transaction_id,
            expected_storage_commit_sequence: head.storage_commit_sequence,
            expected_state_generation: head.state_generation,
            resulting_state_generation: head
                .state_generation
                .checked_add(u64::from(advancing))
                .ok_or(RuntimeError::Overflow)?,
            state_advancing_plan_count: advancing,
            expected_account_service_response_count: head.account_service_response_count,
            resulting_account_service_response_count: response_count,
        },
        plans.len(),
        StorageAccountingLimits {
            current_logical_database_bytes: head.logical_database_bytes,
            current_backup_stream_bytes: head.backup_stream_bytes,
            database_max_bytes: ceilings.database_max_bytes,
            backup_max_bytes: ceilings.backup_max_bytes,
        },
        projection.mutations,
    )?;
    Ok(Some(ProjectedBatch {
        resulting_logical_database_bytes: batch.resulting_logical_database_bytes(),
        resulting_backup_stream_bytes: batch.resulting_backup_stream_bytes(),
        resulting_account_service_response_count: response_count,
        batch,
        updates: projection.updates,
        advancing_plans: advancing,
    }))
}

/// Projects one signed administrative audit append without advancing the
/// logical protocol-state generation.
pub(crate) fn project_admin_audit_event(
    transaction_id: TransactionId,
    event: &AdminAuditEvent,
    index: &DurableIndex,
    keys: &KeyDeriver,
    head: HeadCounters,
    ceilings: AccountingCeilings,
) -> Result<ProjectedBatch, RuntimeError> {
    let sequence = event.tbs().audit_sequence;
    let revision = sequence.checked_add(1).ok_or(RuntimeError::Overflow)?;
    let key = StoredKey::new(sequence.to_be_bytes().to_vec())?;
    let value = PersistentRecordValue::new(
        TableId::Audit,
        LIVE_RECORD_KIND,
        revision,
        0,
        None,
        Vec::new(),
        event.encode().map_err(|_| RuntimeError::InvalidValue)?,
    )?;
    let mut projection = Projection {
        index,
        keys,
        mutations: Vec::new(),
        updates: Vec::new(),
        touched: BTreeSet::new(),
    };
    projection.put(TableId::Audit, key, value)?;
    let batch = StorageMutationBatch::new(
        StorageMutationHead {
            transaction_id,
            expected_storage_commit_sequence: head.storage_commit_sequence,
            expected_state_generation: head.state_generation,
            resulting_state_generation: head.state_generation,
            state_advancing_plan_count: 0,
            expected_account_service_response_count: head.account_service_response_count,
            resulting_account_service_response_count: head.account_service_response_count,
        },
        1,
        StorageAccountingLimits {
            current_logical_database_bytes: head.logical_database_bytes,
            current_backup_stream_bytes: head.backup_stream_bytes,
            database_max_bytes: ceilings.database_max_bytes,
            backup_max_bytes: ceilings.backup_max_bytes,
        },
        projection.mutations,
    )?;
    Ok(ProjectedBatch {
        resulting_logical_database_bytes: batch.resulting_logical_database_bytes(),
        resulting_backup_stream_bytes: batch.resulting_backup_stream_bytes(),
        resulting_account_service_response_count: head.account_service_response_count,
        batch,
        updates: projection.updates,
        advancing_plans: 0,
    })
}

/// Replaces one verified, nonempty retained audit prefix with one signed
/// checkpoint without advancing logical protocol state.
// agenc-review: focus owner=runtime reviewed=2026-08-30 reason=one projection must visibly couple every prefix deletion with the replacement checkpoint and accounting fence
pub(crate) fn project_admin_audit_retention(
    transaction_id: TransactionId,
    checkpoint: &AdminAuditCheckpoint,
    index: &DurableIndex,
    keys: &KeyDeriver,
    head: HeadCounters,
    ceilings: AccountingCeilings,
) -> Result<ProjectedBatch, RuntimeError> {
    checkpoint
        .tbs()
        .validate()
        .map_err(|_| RuntimeError::InvalidValue)?;
    let tbs = checkpoint.tbs();
    let deleted_count = usize::try_from(tbs.deleted_count).map_err(|_| RuntimeError::Overflow)?;
    if deleted_count == 0 || deleted_count > MAX_AUDIT_RETENTION_EVENTS {
        return Err(RuntimeError::LimitExceeded);
    }
    let mut projection = Projection {
        index,
        keys,
        mutations: Vec::new(),
        updates: Vec::new(),
        touched: BTreeSet::new(),
    };
    let mut sequence = tbs.deleted_first_sequence;
    loop {
        projection.delete(
            TableId::Audit,
            StoredKey::new(sequence.to_be_bytes().to_vec())?,
        )?;
        if sequence == tbs.deleted_last_sequence {
            break;
        }
        sequence = sequence.checked_add(1).ok_or(RuntimeError::Overflow)?;
    }
    let checkpoint_revision = tbs
        .checkpoint_sequence
        .checked_add(1)
        .ok_or(RuntimeError::Overflow)?;
    let checkpoint_key = StoredKey::new(tbs.checkpoint_sequence.to_be_bytes().to_vec())?;
    let checkpoint_value = PersistentRecordValue::new(
        TableId::AuditCheckpoint,
        LIVE_RECORD_KIND,
        checkpoint_revision,
        0,
        None,
        Vec::new(),
        checkpoint
            .encode()
            .map_err(|_| RuntimeError::InvalidValue)?,
    )?;
    projection.put(TableId::AuditCheckpoint, checkpoint_key, checkpoint_value)?;
    let batch = StorageMutationBatch::new(
        StorageMutationHead {
            transaction_id,
            expected_storage_commit_sequence: head.storage_commit_sequence,
            expected_state_generation: head.state_generation,
            resulting_state_generation: head.state_generation,
            state_advancing_plan_count: 0,
            expected_account_service_response_count: head.account_service_response_count,
            resulting_account_service_response_count: head.account_service_response_count,
        },
        1,
        StorageAccountingLimits {
            current_logical_database_bytes: head.logical_database_bytes,
            current_backup_stream_bytes: head.backup_stream_bytes,
            database_max_bytes: ceilings.database_max_bytes,
            backup_max_bytes: ceilings.backup_max_bytes,
        },
        projection.mutations,
    )?;
    Ok(ProjectedBatch {
        resulting_logical_database_bytes: batch.resulting_logical_database_bytes(),
        resulting_backup_stream_bytes: batch.resulting_backup_stream_bytes(),
        resulting_account_service_response_count: head.account_service_response_count,
        batch,
        updates: projection.updates,
        advancing_plans: 0,
    })
}

impl Projection<'_> {
    fn project_account_service_write(
        &mut self,
        write: &AccountServiceDurableWrite,
        revision: u64,
    ) -> Result<(), RuntimeError> {
        match write {
            AccountServiceDurableWrite::Put {
                table,
                key,
                plaintext,
            } => {
                if !matches!(*table, TableId::LoginIndex | TableId::LoginIndexKeyState)
                    && PersistentRecordValue::decode(*table, plaintext)?.revision() != revision
                {
                    return Err(RuntimeError::Storage(StorageError::StaleState));
                }
                self.put_plaintext(*table, key.clone(), plaintext.as_slice().to_vec())
            }
            AccountServiceDurableWrite::Delete { table, key } => self.delete(*table, key.clone()),
        }
    }

    fn project_write(
        &mut self,
        write: &DurableWrite,
        revision: u64,
        entropy: &mut dyn EntropySource,
    ) -> Result<(), RuntimeError> {
        match write {
            DurableWrite::PutAccount(account) => self.put_account(account, revision),
            DurableWrite::TombstoneAccount(account_id) => {
                self.tombstone_account(*account_id, revision)
            }
            DurableWrite::PutChannel(channel) => self.put_channel(channel, revision),
            DurableWrite::TombstoneChannel { channel_id, name } => {
                self.tombstone_channel(*channel_id, name, revision)
            }
            DurableWrite::AppendSanction(sanction) => {
                self.append_sanction(sanction, revision, entropy)
            }
        }
    }

    fn put_account(&mut self, account: &DurableAccount, revision: u64) -> Result<(), RuntimeError> {
        let key = KeyDeriver::account_key(account.account_id)?;
        let value = PersistentRecordValue::new(
            TableId::Account,
            LIVE_RECORD_KIND,
            revision,
            account.session_generation.get(),
            None,
            Vec::new(),
            AccountRecordBody::encode(account)?,
        )?;
        self.put(TableId::Account, key.clone(), value)?;
        let owned = self.index.nickname_rows(account.account_id);
        let mut wanted = BTreeMap::new();
        for nickname in &account.reserved_nicknames {
            wanted.insert(nickname.canonical().to_owned(), nickname);
        }
        for (canonical, nickname) in &wanted {
            if owned.contains_key(canonical) {
                continue;
            }
            self.reserve_nickname(account.account_id, &key, nickname, revision)?;
        }
        for (canonical, row_key) in &owned {
            if wanted.contains_key(canonical) {
                continue;
            }
            self.delete(TableId::NicknameReservation, row_key.clone())?;
            self.updates.push(IndexUpdate::NicknameReleased {
                account_id: account.account_id,
                canonical: canonical.clone(),
            });
        }
        Ok(())
    }

    fn reserve_nickname(
        &mut self,
        account_id: AccountId,
        account_key: &StoredKey,
        nickname: &NicknameValue,
        revision: u64,
    ) -> Result<(), RuntimeError> {
        let row_key = self.keys.nickname_key(nickname)?;
        let value = PersistentRecordValue::new(
            TableId::NicknameReservation,
            LIVE_RECORD_KIND,
            revision,
            0,
            None,
            vec![RecordReference::new(TableId::Account, account_key.clone())?],
            nickname.presentation().as_bytes().to_vec(),
        )?;
        self.put(TableId::NicknameReservation, row_key.clone(), value)?;
        self.updates.push(IndexUpdate::NicknameOwned {
            account_id,
            canonical: nickname.canonical().to_owned(),
            key: row_key,
        });
        Ok(())
    }

    fn tombstone_account(
        &mut self,
        account_id: AccountId,
        revision: u64,
    ) -> Result<(), RuntimeError> {
        let key = KeyDeriver::account_key(account_id)?;
        let value = PersistentRecordValue::new(
            TableId::Account,
            TOMBSTONE_RECORD_KIND,
            revision,
            0,
            None,
            Vec::new(),
            Vec::new(),
        )?;
        self.put(TableId::Account, key, value)?;
        for (canonical, row_key) in self.index.nickname_rows(account_id) {
            self.delete(TableId::NicknameReservation, row_key)?;
            self.updates.push(IndexUpdate::NicknameReleased {
                account_id,
                canonical,
            });
        }
        Ok(())
    }

    fn put_channel(&mut self, channel: &DurableChannel, revision: u64) -> Result<(), RuntimeError> {
        let key = KeyDeriver::channel_key(channel.channel_id)?;
        let value = PersistentRecordValue::new(
            TableId::Channel,
            LIVE_RECORD_KIND,
            revision,
            0,
            None,
            Vec::new(),
            ChannelRecordBody::encode(channel)?,
        )?;
        self.put(TableId::Channel, key.clone(), value)?;
        if self.index.channel_name_row(channel.channel_id).is_some() {
            return Ok(());
        }
        let name_key = self.keys.channel_name_key(&channel.name)?;
        let name_value = PersistentRecordValue::new(
            TableId::ChannelName,
            LIVE_RECORD_KIND,
            revision,
            0,
            None,
            vec![RecordReference::new(TableId::Channel, key)?],
            channel.name.presentation().as_bytes().to_vec(),
        )?;
        self.put(TableId::ChannelName, name_key.clone(), name_value)?;
        self.updates.push(IndexUpdate::ChannelNamed {
            channel_id: channel.channel_id,
            key: name_key,
        });
        Ok(())
    }

    fn tombstone_channel(
        &mut self,
        channel_id: ChannelInstanceId,
        name: &ChannelNameValue,
        revision: u64,
    ) -> Result<(), RuntimeError> {
        let key = KeyDeriver::channel_key(channel_id)?;
        let value = PersistentRecordValue::new(
            TableId::Channel,
            TOMBSTONE_RECORD_KIND,
            revision,
            0,
            None,
            Vec::new(),
            Vec::new(),
        )?;
        self.put(TableId::Channel, key, value)?;
        let name_key = match self.index.channel_name_row(channel_id) {
            Some(key) => key.clone(),
            None => self.keys.channel_name_key(name)?,
        };
        self.delete(TableId::ChannelName, name_key)?;
        self.updates
            .push(IndexUpdate::ChannelUnnamed { channel_id });
        Ok(())
    }

    fn append_sanction(
        &mut self,
        sanction: &DurableSanction,
        revision: u64,
        entropy: &mut dyn EntropySource,
    ) -> Result<(), RuntimeError> {
        let mut random = [0_u8; SANCTION_KEY_RANDOM_BYTES];
        entropy
            .fill_exact(&mut random)
            .map_err(|_| RuntimeError::Storage(StorageError::Unavailable))?;
        let key = KeyDeriver::sanction_key(sanction.channel_id, random)?;
        if self.index.existing(TableId::Sanction, &key)?.is_some() {
            return Err(RuntimeError::InvalidValue);
        }
        let value = PersistentRecordValue::new(
            TableId::Sanction,
            LIVE_RECORD_KIND,
            revision,
            0,
            sanction.expires_at.map(agenc_ircd_types::UtcSecond::get),
            Vec::new(),
            SanctionRecordBody::encode(sanction)?,
        )?;
        self.put(TableId::Sanction, key, value)
    }

    /// Appends one put with the exact before-image from the index.
    fn put(
        &mut self,
        table: TableId,
        key: StoredKey,
        value: PersistentRecordValue,
    ) -> Result<(), RuntimeError> {
        self.put_plaintext(table, key, value.encode()?)
    }

    fn put_plaintext(
        &mut self,
        table: TableId,
        key: StoredKey,
        plaintext: Vec<u8>,
    ) -> Result<(), RuntimeError> {
        self.touch(table, &key)?;
        let before = self.index.existing(table, &key)?;
        let plaintext_bytes = plaintext.len();
        self.mutations.push(RecordMutation::put(
            table,
            key.clone(),
            DOMAIN_RECORD_SCHEMA,
            before,
            plaintext,
        )?);
        self.updates.push(IndexUpdate::Put {
            table,
            key,
            plaintext_bytes,
        });
        Ok(())
    }

    /// Appends one deletion; the row must exist.
    fn delete(&mut self, table: TableId, key: StoredKey) -> Result<(), RuntimeError> {
        self.touch(table, &key)?;
        let before = self
            .index
            .existing(table, &key)?
            .ok_or(RuntimeError::Storage(StorageError::StaleState))?;
        self.mutations
            .push(RecordMutation::delete(table, key.clone(), before));
        self.updates.push(IndexUpdate::Delete { table, key });
        Ok(())
    }

    /// One batch touches each row at most once (storage rejects duplicates,
    /// and two plans rewriting one row would need the second before-image).
    fn touch(&mut self, table: TableId, key: &StoredKey) -> Result<(), RuntimeError> {
        if !self.touched.insert((table, key.clone())) {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agenc_ircd_admin::{
        AdminAuditCheckpoint, AdminAuditCheckpointTbs, AdminAuditEventTbs, AdminAuditPhase,
        AdminCommandTbs, AdminSessionId,
    };
    use agenc_ircd_crypto::{Ed25519SecretKey, LoginIndexKey, StorageDigest, audit_signing_key_id};
    use agenc_ircd_domain::{AccountState, DomainState};
    use agenc_ircd_storage::{
        LOGIN_INDEX_KEY_STATE_KEY, LoginIndexKeyState, MIN_SEALED_RECORD_BYTES,
        logical_record_charge,
    };
    use agenc_ircd_testkit::{ScriptedEntropy, account_id};
    use agenc_ircd_types::{
        DatabaseId, Generation, NetworkId, OperatorId, Revision, ServerId, ServerIncarnation,
    };

    fn binding() -> DatabaseBinding {
        DatabaseBinding::new(
            NetworkId::from_bytes([1; 32]),
            ServerId::from_bytes([2; 16]),
            ServerIncarnation::from_bytes([3; 16]),
            DatabaseId::from_bytes([4; 16]),
        )
    }

    fn keys() -> Result<KeyDeriver, RuntimeError> {
        KeyDeriver::new(StorageMasterKey::from_bytes([7; 32]), binding(), 1)
    }

    const fn head(logical: u64, backup: u64) -> HeadCounters {
        HeadCounters {
            state_generation: 0,
            storage_commit_sequence: 0,
            account_service_response_count: 0,
            logical_database_bytes: logical,
            backup_stream_bytes: backup,
        }
    }

    const fn ceilings() -> AccountingCeilings {
        AccountingCeilings {
            database_max_bytes: 1_000_000,
            backup_max_bytes: 1_000_000,
        }
    }

    fn account_plan() -> Result<MutationPlan, RuntimeError> {
        let state = DomainState::new().map_err(|_| RuntimeError::InvalidValue)?;
        let generation = Generation::new(1).map_err(|_| RuntimeError::InvalidValue)?;
        let account = AccountState::new(account_id(1), generation, state.revision());
        state
            .plan_account_created(account)
            .map_err(|_| RuntimeError::InvalidValue)
    }

    fn audit_event() -> Result<AdminAuditEvent, RuntimeError> {
        let operator_key = Ed25519SecretKey::from_bytes([21; 32]);
        let audit_key = Ed25519SecretKey::from_bytes([22; 32]);
        let command = AdminCommandTbs::new(
            NetworkId::from_bytes([1; 32]),
            ServerId::from_bytes([2; 16]),
            AdminSessionId::from_bytes([23; 16]),
            0,
            None,
            b"MOTD",
        )
        .map_err(|_| RuntimeError::InvalidValue)?;
        let operator_signature = command
            .sign(&operator_key)
            .map_err(|_| RuntimeError::InvalidValue)?;
        let key_id = *audit_signing_key_id(audit_key.public_key().as_bytes())
            .map_err(|_| RuntimeError::InvalidValue)?
            .as_bytes();
        AdminAuditEvent::sign(
            AdminAuditEventTbs {
                network_id: NetworkId::from_bytes([1; 32]),
                server_id: ServerId::from_bytes([2; 16]),
                audit_signing_key_id: key_id,
                audit_sequence: 0,
                created_at: 50,
                operator_id: OperatorId::from_bytes([24; 16]),
                command_tbs: command,
                operator_signature,
                phase: AdminAuditPhase::Observed,
                previous_event_hash: [0; 32],
            },
            &audit_key,
        )
        .map_err(|_| RuntimeError::InvalidValue)
    }

    #[test]
    fn audit_projection_does_not_advance_protocol_state() -> Result<(), RuntimeError> {
        let current = HeadCounters {
            state_generation: 9,
            storage_commit_sequence: 4,
            account_service_response_count: 3,
            logical_database_bytes: 0,
            backup_stream_bytes: 0,
        };
        let projected = project_admin_audit_event(
            TransactionId::from_bytes([25; 16]),
            &audit_event()?,
            &DurableIndex::new(),
            &keys()?,
            current,
            ceilings(),
        )?;
        assert_eq!(projected.advancing_plans(), 0);
        assert_eq!(projected.batch.expected_state_generation(), 9);
        assert_eq!(projected.batch.resulting_state_generation(), 9);
        assert_eq!(projected.batch.state_advancing_plan_count(), 0);
        assert_eq!(projected.batch.plan_count(), 1);
        let mutation = projected
            .batch
            .mutations()
            .first()
            .ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(mutation.table(), TableId::Audit);
        assert_eq!(mutation.key().as_bytes(), 0_u64.to_be_bytes());
        assert_eq!(projected.updates().len(), 1);
        Ok(())
    }

    #[test]
    fn audit_retention_deletes_prefix_and_puts_checkpoint_in_one_batch() -> Result<(), RuntimeError>
    {
        let event = audit_event()?;
        let audit_key = Ed25519SecretKey::from_bytes([22; 32]);
        let key_id = *audit_signing_key_id(audit_key.public_key().as_bytes())
            .map_err(|_| RuntimeError::InvalidValue)?
            .as_bytes();
        let checkpoint = AdminAuditCheckpoint::sign(
            AdminAuditCheckpointTbs {
                network_id: NetworkId::from_bytes([1; 32]),
                server_id: ServerId::from_bytes([2; 16]),
                audit_signing_key_id: key_id,
                checkpoint_sequence: 0,
                created_at: 100,
                deleted_first_sequence: 0,
                deleted_last_sequence: 0,
                deleted_count: 1,
                deleted_last_event_hash: event.event_hash(),
                next_retained_sequence: 1,
                previous_checkpoint_hash: [0; 32],
            },
            &audit_key,
        )
        .map_err(|_| RuntimeError::InvalidValue)?;
        let mut index = DurableIndex::new();
        index.record_known(
            TableId::Audit,
            StoredKey::new(0_u64.to_be_bytes().to_vec())?,
            ExistingRecord::new(
                DOMAIN_RECORD_SCHEMA,
                StorageDigest::from_bytes([31; 32]),
                MIN_SEALED_RECORD_BYTES,
            )?,
        );
        let projected = project_admin_audit_retention(
            TransactionId::from_bytes([32; 16]),
            &checkpoint,
            &index,
            &keys()?,
            head(100_000, 100_000),
            ceilings(),
        )?;
        assert_eq!(projected.batch.plan_count(), 1);
        assert_eq!(projected.batch.state_advancing_plan_count(), 0);
        assert_eq!(projected.batch.mutations().len(), 2);
        assert_eq!(
            projected
                .batch
                .mutations()
                .first()
                .map(RecordMutation::table),
            Some(TableId::Audit)
        );
        assert_eq!(
            projected
                .batch
                .mutations()
                .get(1)
                .map(RecordMutation::table),
            Some(TableId::AuditCheckpoint)
        );
        assert_eq!(projected.updates().len(), 2);
        Ok(())
    }

    fn auth_transaction_write(revision: u64) -> Result<AccountServiceDurableWrite, RuntimeError> {
        let key = StoredKey::new(vec![6; 16])?;
        let value = PersistentRecordValue::new(
            TableId::AuthTransaction,
            1,
            revision,
            0,
            Some(30),
            Vec::new(),
            vec![7; 32],
        )?;
        AccountServiceDurableWrite::put(TableId::AuthTransaction, key, value.encode()?)
    }

    fn project_account(
        index: &DurableIndex,
        head: HeadCounters,
    ) -> Result<ProjectedBatch, RuntimeError> {
        let plan = account_plan()?;
        let projections = [PlanProjection {
            plan: &plan,
            response_count_increment: 0,
            account_service_writes: &[],
        }];
        let mut entropy =
            ScriptedEntropy::new(Vec::new()).map_err(|_| RuntimeError::InvalidValue)?;
        project_batch(
            TransactionId::from_bytes([9; 16]),
            &projections,
            index,
            &keys()?,
            head,
            ceilings(),
            &mut entropy,
        )?
        .ok_or(RuntimeError::InvalidValue)
    }

    #[test]
    fn account_projection_binds_head_counts_and_the_exact_before_image() -> Result<(), RuntimeError>
    {
        let current = head(10_000, 20_000);
        let fresh = project_account(&DurableIndex::new(), current)?;
        assert_eq!(fresh.batch.expected_state_generation(), 0);
        assert_eq!(fresh.batch.resulting_state_generation(), 1);
        assert_eq!(fresh.batch.state_advancing_plan_count(), 1);
        assert_eq!(fresh.batch.plan_count(), 1);
        assert_eq!(fresh.mutation_count(), 1);
        assert_eq!(
            fresh.batch.mutations().first().map(RecordMutation::table),
            Some(TableId::Account)
        );

        let mut existing = DurableIndex::new();
        let account_key = KeyDeriver::account_key(account_id(1))?;
        let sealed_bytes = 100;
        existing.record_known(
            TableId::Account,
            account_key.clone(),
            ExistingRecord::new(
                DOMAIN_RECORD_SCHEMA,
                StorageDigest::from_bytes([5; 32]),
                sealed_bytes,
            )?,
        );
        let replacement = project_account(&existing, current)?;
        let prior_charge = logical_record_charge(account_key.as_bytes().len(), sealed_bytes)?;
        // A present integrity before-image adds the 32-byte prior record ID
        // to the successor manifest compared with an absent before-image.
        let manifest_growth = u64::try_from(StorageDigest::from_bytes([0; 32]).as_bytes().len())
            .map_err(|_| RuntimeError::Overflow)?;
        assert_eq!(
            fresh.resulting_logical_database_bytes,
            replacement
                .resulting_logical_database_bytes
                .checked_add(prior_charge)
                .and_then(|value| value.checked_sub(manifest_growth))
                .ok_or(RuntimeError::Overflow)?
        );
        assert_eq!(
            fresh.resulting_backup_stream_bytes,
            replacement
                .resulting_backup_stream_bytes
                .checked_add(prior_charge)
                .and_then(|value| value.checked_add(8))
                .and_then(|value| value.checked_sub(manifest_growth))
                .ok_or(RuntimeError::Overflow)?
        );
        Ok(())
    }

    #[test]
    fn account_service_checkpoint_advances_with_its_validated_row() -> Result<(), RuntimeError> {
        let state = DomainState::new().map_err(|_| RuntimeError::InvalidValue)?;
        let plan = state
            .plan_account_service_checkpoint()
            .map_err(|_| RuntimeError::InvalidValue)?;
        assert!(plan.durable_writes().is_empty());
        let write = auth_transaction_write(plan.resulting_revision().get())?;
        let projections = [PlanProjection {
            plan: &plan,
            response_count_increment: 1,
            account_service_writes: std::slice::from_ref(&write),
        }];
        let mut entropy =
            ScriptedEntropy::new(Vec::new()).map_err(|_| RuntimeError::InvalidValue)?;
        let projected = project_batch(
            TransactionId::from_bytes([10; 16]),
            &projections,
            &DurableIndex::new(),
            &keys()?,
            head(0, 0),
            ceilings(),
            &mut entropy,
        )?
        .ok_or(RuntimeError::InvalidValue)?;

        assert_eq!(projected.advancing_plans(), 1);
        assert_eq!(projected.mutation_count(), 1);
        assert_eq!(projected.batch.resulting_state_generation(), 1);
        assert_eq!(
            projected.batch.resulting_account_service_response_count(),
            1
        );
        assert_eq!(projected.updates().len(), 1);
        assert_eq!(
            projected
                .batch
                .mutations()
                .first()
                .map(RecordMutation::table),
            Some(TableId::AuthTransaction)
        );
        Ok(())
    }

    #[test]
    fn account_service_projection_rejects_wrong_table_and_revision() -> Result<(), RuntimeError> {
        assert_eq!(
            AccountServiceDurableWrite::put(
                TableId::Channel,
                StoredKey::new(vec![8; 16])?,
                vec![1],
            )
            .err(),
            Some(RuntimeError::InvalidValue)
        );

        let state = DomainState::new().map_err(|_| RuntimeError::InvalidValue)?;
        let plan = state
            .plan_account_service_checkpoint()
            .map_err(|_| RuntimeError::InvalidValue)?;
        let stale = auth_transaction_write(
            plan.resulting_revision()
                .get()
                .checked_add(1)
                .ok_or(RuntimeError::Overflow)?,
        )?;
        let projections = [PlanProjection {
            plan: &plan,
            response_count_increment: 0,
            account_service_writes: std::slice::from_ref(&stale),
        }];
        let mut entropy =
            ScriptedEntropy::new(Vec::new()).map_err(|_| RuntimeError::InvalidValue)?;
        assert_eq!(
            project_batch(
                TransactionId::from_bytes([11; 16]),
                &projections,
                &DurableIndex::new(),
                &keys()?,
                head(0, 0),
                ceilings(),
                &mut entropy,
            )
            .err(),
            Some(RuntimeError::Storage(StorageError::StaleState))
        );
        Ok(())
    }

    #[test]
    fn account_service_write_set_accepts_only_the_login_index_control_row()
    -> Result<(), RuntimeError> {
        let network = NetworkId::from_bytes([12; 32]);
        let login_key = LoginIndexKey::from_bytes([13; 32]);
        let state = LoginIndexKeyState::stable(1, login_key.key_id(network))?;
        let write = AccountServiceDurableWrite::put(
            TableId::LoginIndexKeyState,
            StoredKey::new(LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
            state.encode()?,
        );
        assert!(write.is_ok());
        assert_eq!(
            AccountServiceDurableWrite::put(
                TableId::StateMeta,
                StoredKey::new(agenc_ircd_storage::STATE_META_STORED_KEY.to_vec())?,
                vec![0; 8],
            )
            .err(),
            Some(RuntimeError::InvalidValue)
        );
        Ok(())
    }

    #[test]
    fn deletion_requires_an_exact_known_before_image() -> Result<(), RuntimeError> {
        let keys = keys()?;
        let row_key = StoredKey::new(vec![1])?;
        let empty = DurableIndex::new();
        let mut missing = Projection {
            index: &empty,
            keys: &keys,
            mutations: Vec::new(),
            updates: Vec::new(),
            touched: BTreeSet::new(),
        };
        assert_eq!(
            missing.delete(TableId::NicknameReservation, row_key.clone()),
            Err(RuntimeError::Storage(StorageError::StaleState))
        );

        let mut known = DurableIndex::new();
        known.record_known(
            TableId::NicknameReservation,
            row_key.clone(),
            ExistingRecord::new(
                DOMAIN_RECORD_SCHEMA,
                StorageDigest::from_bytes([6; 32]),
                MIN_SEALED_RECORD_BYTES,
            )?,
        );
        let mut present = Projection {
            index: &known,
            keys: &keys,
            mutations: Vec::new(),
            updates: Vec::new(),
            touched: BTreeSet::new(),
        };
        present.delete(TableId::NicknameReservation, row_key)?;
        assert_eq!(present.mutations.len(), 1);
        assert!(
            present
                .mutations
                .first()
                .is_some_and(RecordMutation::is_deletion)
        );
        Ok(())
    }

    #[test]
    fn pending_index_rows_require_the_exact_sealed_length() -> Result<(), RuntimeError> {
        let key = StoredKey::new(vec![8])?;
        let update = IndexUpdate::Put {
            table: TableId::Account,
            key: key.clone(),
            plaintext_bytes: 10,
        };
        let mut index = DurableIndex::new();
        index.apply(&[update]);
        assert_eq!(index.pending_rows().len(), 1);
        let wrong = ExistingRecord::new(
            DOMAIN_RECORD_SCHEMA,
            StorageDigest::from_bytes([1; 32]),
            MIN_SEALED_RECORD_BYTES,
        )?;
        assert_eq!(
            index.refresh(vec![(TableId::Account, key.clone(), Some(wrong))]),
            Err(RuntimeError::Storage(StorageError::StaleState))
        );
        let exact = ExistingRecord::new(
            DOMAIN_RECORD_SCHEMA,
            StorageDigest::from_bytes([2; 32]),
            MIN_SEALED_RECORD_BYTES + 10,
        )?;
        index.refresh(vec![(TableId::Account, key.clone(), Some(exact))])?;
        assert_eq!(index.existing(TableId::Account, &key)?, Some(exact));
        Ok(())
    }

    #[test]
    fn projection_rejects_empty_and_response_count_overflow() -> Result<(), RuntimeError> {
        let mut entropy =
            ScriptedEntropy::new(Vec::new()).map_err(|_| RuntimeError::InvalidValue)?;
        assert_eq!(
            project_batch(
                TransactionId::from_bytes([1; 16]),
                &[],
                &DurableIndex::new(),
                &keys()?,
                head(0, 0),
                ceilings(),
                &mut entropy,
            )
            .err(),
            Some(RuntimeError::InvalidValue)
        );
        let plan = account_plan()?;
        let projections = [PlanProjection {
            plan: &plan,
            response_count_increment: 1,
            account_service_writes: &[],
        }];
        let overflowing = HeadCounters {
            account_service_response_count: u64::MAX,
            ..head(0, 0)
        };
        assert_eq!(
            project_batch(
                TransactionId::from_bytes([2; 16]),
                &projections,
                &DurableIndex::new(),
                &keys()?,
                overflowing,
                ceilings(),
                &mut entropy,
            )
            .err(),
            Some(RuntimeError::Overflow)
        );
        Ok(())
    }

    #[test]
    fn key_shapes_and_generation_validation_are_closed() -> Result<(), RuntimeError> {
        assert!(matches!(
            KeyDeriver::new(StorageMasterKey::from_bytes([1; 32]), binding(), 0),
            Err(RuntimeError::InvalidValue)
        ));
        assert_eq!(KeyDeriver::account_key(account_id(1))?.as_bytes().len(), 24);
        assert_eq!(
            KeyDeriver::channel_key(ChannelInstanceId::from_bytes([2; 16]))?
                .as_bytes()
                .len(),
            16
        );
        let sanction = KeyDeriver::sanction_key(None, [3; SANCTION_KEY_RANDOM_BYTES])?;
        assert_eq!(sanction.as_bytes().len(), 2 + SANCTION_KEY_RANDOM_BYTES);
        assert_eq!(
            sanction.as_bytes().get(..2),
            Some(SANCTION_SCOPE_NETWORK.to_be_bytes().as_slice())
        );
        assert!(Revision::new(0).is_ok());
        Ok(())
    }
}
