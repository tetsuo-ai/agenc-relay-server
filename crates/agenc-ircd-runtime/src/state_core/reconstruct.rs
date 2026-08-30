//! Rebuilding the live domain state from the authenticated database at
//! startup (spec 23.5.3, lines 5563-5614; spec 25.3 readiness, line 6708).
//!
//! Every persisted row is opened under the active key generation, decoded
//! through the storage body codecs, cross-checked against its secondary
//! rows, and only then handed to `DomainState::restore`. The scan runs
//! blocking reads and belongs on a blocking thread, never a Tokio worker
//! (spec line 4242).

use std::collections::{BTreeMap, BTreeSet};

use agenc_ircd_auth::{
    AuthenticationTransactionRecord, CreationTransactionRecord, CredentialChangeTransactionRecord,
    OPAQUE_REGISTRATION_RECORD_BYTES, OpaqueRegistrationRecord,
};
use agenc_ircd_domain::{DomainState, DurableAccount, DurableChannel, DurableSanction};
use agenc_ircd_storage::{
    AccountRecordBody, ChannelRecordBody, ExistingRecord, LIVE_RECORD_KIND,
    LOGIN_INDEX_KEY_STATE_KEY, LoginIndexKeyState, LoginIndexStoredKey, LoginIndexValue,
    LoginIndexValueKind, MAX_STORED_KEY_BYTES, OPAQUE_FAKE_RECORD_KEY, PersistentRecordValue,
    ReadPlan, SanctionRecordBody, SealedRecord, StorageError, StoragePort, StoredKey, TableId,
};
use agenc_ircd_types::{
    AccountId, ChannelInstanceId, ChannelName, InviteId, MonotonicTick, Nickname, Revision,
    TransactionId, UtcSecond,
};

use crate::RuntimeError;
use crate::StateCoreSeed;
use crate::bridge::storage::read_blocking;
use crate::state_core::durable::{
    DOMAIN_RECORD_SCHEMA, DurableIndex, HeadCounters, KeyDeriver, SANCTION_KEY_RANDOM_BYTES,
    SANCTION_SCOPE_CHANNEL, SANCTION_SCOPE_NETWORK, TOMBSTONE_RECORD_KIND,
};

/// Rows fetched per consistent range read (the storage crate's range limit).
pub const RECONSTRUCTION_PAGE_ROWS: u16 = 4_096;
const CREATION_TRANSACTION_KIND: u16 = 1;
const AUTHENTICATION_TRANSACTION_KIND: u16 = 2;
const CREDENTIAL_CHANGE_TRANSACTION_KIND: u16 = 3;
const INVITATION_RESERVATION_KIND: u16 = 1;
const INVITATION_TOMBSTONE_KIND: u16 = 2;
/// The tables Stage 06 reconstructs, in scan order.
pub const RECONSTRUCTED_TABLES: [TableId; 12] = [
    TableId::Account,
    TableId::NicknameReservation,
    TableId::Channel,
    TableId::ChannelName,
    TableId::Sanction,
    TableId::LoginIndex,
    TableId::OpaqueRecord,
    TableId::AuthTransaction,
    TableId::RegistrationInvite,
    TableId::Session,
    TableId::RequestResult,
    TableId::LoginIndexKeyState,
];

/// Account-service rows needed before the first live request is accepted.
pub struct AccountServiceReconstruction {
    login_index_key_state: LoginIndexKeyState,
    fake_opaque_record: [u8; OPAQUE_REGISTRATION_RECORD_BYTES],
    startup_transaction_cleanups: Vec<RecoveredAccountTransactionCleanup>,
}

impl AccountServiceReconstruction {
    /// Returns the authenticated current/previous login-index generation state.
    #[must_use]
    pub const fn login_index_key_state(&self) -> LoginIndexKeyState {
        self.login_index_key_state
    }

    /// Returns the stable fake OPAQUE record restored from authenticated storage.
    #[must_use]
    pub const fn fake_opaque_record(&self) -> &[u8; OPAQUE_REGISTRATION_RECORD_BYTES] {
        &self.fake_opaque_record
    }

    /// Returns the authenticated connection-bound rows that must be deleted
    /// before this process accepts account work.
    #[must_use]
    pub fn startup_transaction_cleanups(&self) -> &[RecoveredAccountTransactionCleanup] {
        &self.startup_transaction_cleanups
    }
}

/// One fully cross-validated startup deletion for connection-bound account
/// state left by the prior process.
#[derive(Clone)]
pub struct RecoveredAccountTransactionCleanup {
    transaction_id: TransactionId,
    login_key: Option<StoredKey>,
    invitation_id: Option<InviteId>,
}

impl RecoveredAccountTransactionCleanup {
    /// Returns the transaction row to delete.
    #[must_use]
    pub const fn transaction_id(&self) -> TransactionId {
        self.transaction_id
    }

    /// Borrows the admitted login reservation to delete, if any.
    #[must_use]
    pub const fn login_key(&self) -> Option<&StoredKey> {
        self.login_key.as_ref()
    }

    /// Returns the admitted invitation reservation to delete, if any.
    #[must_use]
    pub const fn invitation_id(&self) -> Option<InviteId> {
        self.invitation_id
    }

    pub(crate) fn into_parts(self) -> (TransactionId, Option<StoredKey>, Option<InviteId>) {
        (self.transaction_id, self.login_key, self.invitation_id)
    }
}

/// The live state, the before-image index, and the head counters.
pub struct Reconstruction {
    /// The validated domain state at the recovered revision.
    pub domain: DomainState,
    /// Every durable row's sealed identity plus secondary-row ownership.
    pub index: DurableIndex,
    /// The counters the first batch is fenced against.
    pub head: HeadCounters,
    /// Authenticated account-service startup state.
    pub account_service: AccountServiceReconstruction,
}

#[derive(Default)]
struct AccountServiceScan {
    login_index_key_state: Option<LoginIndexKeyState>,
    fake_opaque_record: Option<[u8; OPAQUE_REGISTRATION_RECORD_BYTES]>,
    transactions: BTreeMap<TransactionId, RecoveredTransaction>,
    login_reservations: BTreeMap<TransactionId, RecoveredLoginReservation>,
    invitation_reservations: BTreeMap<TransactionId, RecoveredInvitationReservation>,
}

impl AccountServiceScan {
    fn finish(self) -> Result<AccountServiceReconstruction, RuntimeError> {
        let Self {
            login_index_key_state,
            fake_opaque_record,
            transactions,
            login_reservations,
            invitation_reservations,
        } = self;
        let login_index_key_state =
            login_index_key_state.ok_or(RuntimeError::Storage(StorageError::StaleState))?;
        let startup_transaction_cleanups = recover_account_transaction_cleanups(
            transactions,
            login_index_key_state,
            login_reservations,
            invitation_reservations,
        )?;
        Ok(AccountServiceReconstruction {
            login_index_key_state,
            fake_opaque_record: fake_opaque_record
                .ok_or(RuntimeError::Storage(StorageError::StaleState))?,
            startup_transaction_cleanups,
        })
    }
}

enum RecoveredTransaction {
    Authentication,
    Creation {
        expires_at: u64,
        reservation_digest: Option<agenc_ircd_crypto::LoginIndexDigest>,
        reservation_invitation: Option<InviteId>,
    },
    CredentialChange,
}

struct RecoveredLoginReservation {
    key: StoredKey,
    expires_at: u64,
}

struct RecoveredInvitationReservation {
    invitation_id: InviteId,
    expires_at: u64,
}

fn recover_account_transaction_cleanups(
    transactions: BTreeMap<TransactionId, RecoveredTransaction>,
    login_index_key_state: LoginIndexKeyState,
    mut login_reservations: BTreeMap<TransactionId, RecoveredLoginReservation>,
    mut invitation_reservations: BTreeMap<TransactionId, RecoveredInvitationReservation>,
) -> Result<Vec<RecoveredAccountTransactionCleanup>, RuntimeError> {
    let mut cleanups = Vec::new();
    cleanups
        .try_reserve_exact(transactions.len())
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    for (transaction_id, transaction) in transactions {
        cleanups.push(recover_account_transaction_cleanup(
            transaction_id,
            transaction,
            login_index_key_state,
            &mut login_reservations,
            &mut invitation_reservations,
        )?);
    }
    if !login_reservations.is_empty() || !invitation_reservations.is_empty() {
        return Err(RuntimeError::Storage(StorageError::StaleState));
    }
    Ok(cleanups)
}

fn recover_account_transaction_cleanup(
    transaction_id: TransactionId,
    transaction: RecoveredTransaction,
    login_index_key_state: LoginIndexKeyState,
    login_reservations: &mut BTreeMap<TransactionId, RecoveredLoginReservation>,
    invitation_reservations: &mut BTreeMap<TransactionId, RecoveredInvitationReservation>,
) -> Result<RecoveredAccountTransactionCleanup, RuntimeError> {
    match transaction {
        RecoveredTransaction::Authentication | RecoveredTransaction::CredentialChange => {
            if login_reservations.contains_key(&transaction_id)
                || invitation_reservations.contains_key(&transaction_id)
            {
                return Err(RuntimeError::Storage(StorageError::StaleState));
            }
            Ok(RecoveredAccountTransactionCleanup {
                transaction_id,
                login_key: None,
                invitation_id: None,
            })
        }
        RecoveredTransaction::Creation {
            expires_at,
            reservation_digest,
            reservation_invitation,
        } => recover_creation_transaction_cleanup(
            transaction_id,
            expires_at,
            reservation_digest,
            reservation_invitation,
            login_index_key_state,
            login_reservations,
            invitation_reservations,
        ),
    }
}

fn recover_creation_transaction_cleanup(
    transaction_id: TransactionId,
    expires_at: u64,
    reservation_digest: Option<agenc_ircd_crypto::LoginIndexDigest>,
    reservation_invitation: Option<InviteId>,
    login_index_key_state: LoginIndexKeyState,
    login_reservations: &mut BTreeMap<TransactionId, RecoveredLoginReservation>,
    invitation_reservations: &mut BTreeMap<TransactionId, RecoveredInvitationReservation>,
) -> Result<RecoveredAccountTransactionCleanup, RuntimeError> {
    let Some(digest) = reservation_digest else {
        if login_reservations.contains_key(&transaction_id)
            || invitation_reservations.contains_key(&transaction_id)
            || reservation_invitation.is_some()
        {
            return Err(RuntimeError::Storage(StorageError::StaleState));
        }
        return Ok(RecoveredAccountTransactionCleanup {
            transaction_id,
            login_key: None,
            invitation_id: None,
        });
    };
    let expected_login_key =
        LoginIndexStoredKey::new(login_index_key_state.current_generation(), digest)?.encode()?;
    let login = login_reservations
        .remove(&transaction_id)
        .ok_or(RuntimeError::Storage(StorageError::StaleState))?;
    if login.key != expected_login_key || login.expires_at != expires_at {
        return Err(RuntimeError::Storage(StorageError::StaleState));
    }
    let invitation_id = recover_creation_invitation(
        transaction_id,
        expires_at,
        reservation_invitation,
        invitation_reservations,
    )?;
    Ok(RecoveredAccountTransactionCleanup {
        transaction_id,
        login_key: Some(login.key),
        invitation_id,
    })
}

fn recover_creation_invitation(
    transaction_id: TransactionId,
    expires_at: u64,
    expected: Option<InviteId>,
    reservations: &mut BTreeMap<TransactionId, RecoveredInvitationReservation>,
) -> Result<Option<InviteId>, RuntimeError> {
    let Some(expected) = expected else {
        if reservations.contains_key(&transaction_id) {
            return Err(RuntimeError::Storage(StorageError::StaleState));
        }
        return Ok(None);
    };
    let invitation = reservations
        .remove(&transaction_id)
        .ok_or(RuntimeError::Storage(StorageError::StaleState))?;
    if invitation.invitation_id != expected || invitation.expires_at != expires_at {
        return Err(RuntimeError::Storage(StorageError::StaleState));
    }
    Ok(Some(expected))
}

#[derive(Default)]
struct Scan {
    index: DurableIndex,
    accounts: BTreeMap<AccountId, DurableAccount>,
    account_keys: BTreeMap<StoredKey, AccountId>,
    channels: BTreeMap<ChannelInstanceId, DurableChannel>,
    channel_keys: BTreeMap<StoredKey, ChannelInstanceId>,
    sanctions: Vec<DurableSanction>,
    nickname_rows: Vec<(StoredKey, PersistentRecordValue)>,
    channel_name_rows: Vec<(StoredKey, PersistentRecordValue)>,
    account_service: AccountServiceScan,
}

/// Reads every reconstructed table and restores the domain state.
pub fn reconstruct(
    seed: &StateCoreSeed,
    port: &StoragePort,
    keys: &KeyDeriver,
) -> Result<Reconstruction, RuntimeError> {
    let mut scan = Scan::default();
    for table in RECONSTRUCTED_TABLES {
        scan_table(port, table, |key, sealed| {
            scan.admit(keys, table, key, &sealed)
        })?;
    }
    scan.bind_nicknames(keys)?;
    scan.bind_channel_names(keys)?;
    let account_service = scan.account_service.finish()?;
    let revision =
        Revision::new(seed.storage().state_generation()).map_err(|_| RuntimeError::InvalidValue)?;
    let domain = DomainState::restore(
        revision,
        scan.accounts.into_values().collect(),
        scan.channels.into_values().collect(),
        scan.sanctions,
    )
    .map_err(|_| RuntimeError::Storage(StorageError::StaleState))?;
    Ok(Reconstruction {
        domain,
        index: scan.index,
        head: HeadCounters::from_recovered(seed.storage()),
        account_service,
    })
}

/// Visits every row of one table in key order through bounded pages.
fn scan_table(
    port: &StoragePort,
    table: TableId,
    mut visit: impl FnMut(StoredKey, Vec<u8>) -> Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    let end = StoredKey::new(vec![0xff; MAX_STORED_KEY_BYTES])?;
    let mut start = StoredKey::new(vec![0])?;
    loop {
        let plan = ReadPlan::range(table, start.clone(), end.clone(), RECONSTRUCTION_PAGE_ROWS)?;
        let result = read_blocking(port, plan)?;
        let page_rows = result.records.len();
        let mut last: Option<StoredKey> = None;
        for record in result.records {
            if record.table != table {
                return Err(RuntimeError::Storage(StorageError::StaleState));
            }
            last = Some(record.key.clone());
            visit(record.key, record.sealed_record)?;
        }
        let Some(last) = last else {
            return Ok(());
        };
        if page_rows < usize::from(RECONSTRUCTION_PAGE_ROWS) {
            return Ok(());
        }
        start = successor(&last)?;
    }
}

/// The smallest key strictly greater than `key`.
fn successor(key: &StoredKey) -> Result<StoredKey, RuntimeError> {
    let mut bytes = key.as_bytes().to_vec();
    bytes
        .try_reserve_exact(1)
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    bytes.push(0);
    Ok(StoredKey::new(bytes)?)
}

fn invalid_account_service_record() -> RuntimeError {
    RuntimeError::Storage(StorageError::InvalidEncoding)
}

fn validate_creation_transaction_reference(
    invitation_id: Option<InviteId>,
    value: &PersistentRecordValue,
) -> Result<(), RuntimeError> {
    match (invitation_id, value.references()) {
        (None, []) => Ok(()),
        (Some(invite_id), [reference])
            if reference.table() == TableId::RegistrationInvite
                && reference.key().as_bytes() == invite_id.as_bytes() =>
        {
            Ok(())
        }
        _ => Err(RuntimeError::Storage(StorageError::StaleState)),
    }
}

impl Scan {
    /// Records one row's identity and decodes its live body.
    fn admit(
        &mut self,
        keys: &KeyDeriver,
        table: TableId,
        key: StoredKey,
        sealed: &[u8],
    ) -> Result<(), RuntimeError> {
        let envelope = SealedRecord::decode(sealed)?;
        let existing = ExistingRecord::new(
            envelope.record_schema(),
            envelope.record_id()?,
            sealed.len(),
        )?;
        if envelope.record_schema() != DOMAIN_RECORD_SCHEMA {
            return Err(RuntimeError::Storage(StorageError::UnsupportedVersion));
        }
        let opened = keys.open(table, &key, &envelope)?;
        if table == TableId::LoginIndex {
            let stored_key = LoginIndexStoredKey::decode(key.as_bytes())?;
            let value = LoginIndexValue::decode(opened.expose_for_storage_codec(), &stored_key)?;
            if let LoginIndexValueKind::CreationReservation {
                transaction_id,
                expires_at,
            } = value.kind()
                && self
                    .account_service
                    .login_reservations
                    .insert(
                        *transaction_id,
                        RecoveredLoginReservation {
                            key: key.clone(),
                            expires_at: *expires_at,
                        },
                    )
                    .is_some()
            {
                return Err(RuntimeError::Storage(StorageError::StaleState));
            }
            self.index.record_known(table, key, existing);
            return Ok(());
        }
        if table == TableId::LoginIndexKeyState {
            if key.as_bytes() != LOGIN_INDEX_KEY_STATE_KEY
                || self.account_service.login_index_key_state.is_some()
            {
                return Err(RuntimeError::Storage(StorageError::StaleState));
            }
            self.account_service.login_index_key_state = Some(LoginIndexKeyState::decode(
                opened.expose_for_storage_codec(),
            )?);
            self.index.record_known(table, key, existing);
            return Ok(());
        }
        let value = PersistentRecordValue::decode(table, opened.expose_for_storage_codec())?;
        self.index.record_known(table, key.clone(), existing);
        match (table, value.record_kind()) {
            (TableId::Account | TableId::Channel, TOMBSTONE_RECORD_KIND) => Ok(()),
            (TableId::Account, LIVE_RECORD_KIND) => self.admit_account(key, &value),
            (TableId::Channel, LIVE_RECORD_KIND) => self.admit_channel(key, &value),
            (TableId::NicknameReservation, LIVE_RECORD_KIND) => {
                self.nickname_rows.push((key, value));
                Ok(())
            }
            (TableId::ChannelName, LIVE_RECORD_KIND) => {
                self.channel_name_rows.push((key, value));
                Ok(())
            }
            (TableId::Sanction, LIVE_RECORD_KIND) => self.admit_sanction(&key, &value),
            (TableId::OpaqueRecord, LIVE_RECORD_KIND) => self.admit_opaque_record(&key, &value),
            (TableId::OpaqueRecord, TOMBSTONE_RECORD_KIND) if value.body().is_empty() => Ok(()),
            (TableId::AuthTransaction, record_kind) => {
                self.admit_auth_transaction(&key, &value, record_kind)
            }
            (TableId::RegistrationInvite, record_kind) => {
                self.admit_registration_invite(&key, &value, record_kind)
            }
            (TableId::Session | TableId::RequestResult, _) => Ok(()),
            _ => Err(RuntimeError::Storage(StorageError::InvalidEncoding)),
        }
    }

    fn admit_auth_transaction(
        &mut self,
        key: &StoredKey,
        value: &PersistentRecordValue,
        record_kind: u16,
    ) -> Result<(), RuntimeError> {
        let keyed_transaction = TransactionId::from_bytes(
            key.as_bytes()
                .try_into()
                .map_err(|_| RuntimeError::Storage(StorageError::InvalidEncoding))?,
        );
        if value.generation() != 0 {
            return Err(RuntimeError::Storage(StorageError::StaleState));
        }
        let transaction = match record_kind {
            AUTHENTICATION_TRANSACTION_KIND => {
                Self::decode_authentication_transaction(value, keyed_transaction)?
            }
            CREATION_TRANSACTION_KIND => {
                Self::decode_creation_transaction(value, keyed_transaction)?
            }
            CREDENTIAL_CHANGE_TRANSACTION_KIND => {
                self.decode_credential_transaction(value, keyed_transaction)?
            }
            _ => return Err(RuntimeError::Storage(StorageError::InvalidEncoding)),
        };
        if self
            .account_service
            .transactions
            .insert(keyed_transaction, transaction)
            .is_some()
        {
            return Err(RuntimeError::Storage(StorageError::StaleState));
        }
        Ok(())
    }

    fn decode_authentication_transaction(
        value: &PersistentRecordValue,
        keyed_transaction: TransactionId,
    ) -> Result<RecoveredTransaction, RuntimeError> {
        let record = AuthenticationTransactionRecord::parse(value.body())
            .map_err(|_| invalid_account_service_record())?;
        let durable_expires_at = record
            .durable_expires_at_utc()
            .map_err(|_| invalid_account_service_record())?;
        let restored = record
            .restore(
                MonotonicTick::from_ticks(0),
                UtcSecond::from_unix_seconds(0),
            )
            .map_err(|_| invalid_account_service_record())?;
        if restored.binding().transaction_id() != keyed_transaction
            || value.expires_at() != Some(durable_expires_at.get())
            || !value.references().is_empty()
        {
            return Err(RuntimeError::Storage(StorageError::StaleState));
        }
        Ok(RecoveredTransaction::Authentication)
    }

    fn decode_creation_transaction(
        value: &PersistentRecordValue,
        keyed_transaction: TransactionId,
    ) -> Result<RecoveredTransaction, RuntimeError> {
        let metadata = CreationTransactionRecord::parse(value.body())
            .and_then(CreationTransactionRecord::into_restart_cleanup_metadata)
            .map_err(|_| invalid_account_service_record())?;
        if metadata.transaction_id() != keyed_transaction
            || value.expires_at() != Some(metadata.durable_expires_at_utc().get())
        {
            return Err(RuntimeError::Storage(StorageError::StaleState));
        }
        let reservation_invitation = metadata
            .reservation_invitation()
            .map(|(invite_id, _)| invite_id);
        validate_creation_transaction_reference(reservation_invitation, value)?;
        let reservation_digest = metadata.reservation_login_digest().map(|digest| {
            agenc_ircd_crypto::LoginIndexDigest::from_storage_key(*digest.expose_for_storage_key())
        });
        Ok(RecoveredTransaction::Creation {
            expires_at: metadata.durable_expires_at_utc().get(),
            reservation_digest,
            reservation_invitation,
        })
    }

    fn decode_credential_transaction(
        &self,
        value: &PersistentRecordValue,
        keyed_transaction: TransactionId,
    ) -> Result<RecoveredTransaction, RuntimeError> {
        let metadata = CredentialChangeTransactionRecord::parse(value.body())
            .and_then(CredentialChangeTransactionRecord::into_restart_cleanup_metadata)
            .map_err(|_| invalid_account_service_record())?;
        if metadata.transaction_id() != keyed_transaction
            || value.expires_at() != Some(metadata.durable_expires_at_utc().get())
        {
            return Err(RuntimeError::Storage(StorageError::StaleState));
        }
        match (metadata.reservation_account_id(), value.references()) {
            (None, []) => {}
            (Some(account_id), [reference])
                if reference.table() == TableId::Account
                    && self.account_keys.get(reference.key()) == Some(&account_id) => {}
            _ => return Err(RuntimeError::Storage(StorageError::StaleState)),
        }
        Ok(RecoveredTransaction::CredentialChange)
    }

    fn admit_registration_invite(
        &mut self,
        key: &StoredKey,
        value: &PersistentRecordValue,
        record_kind: u16,
    ) -> Result<(), RuntimeError> {
        let invitation_id = InviteId::from_bytes(
            key.as_bytes()
                .try_into()
                .map_err(|_| RuntimeError::Storage(StorageError::InvalidEncoding))?,
        );
        let expires_at = value
            .expires_at()
            .ok_or(RuntimeError::Storage(StorageError::StaleState))?;
        if value.generation() != 0 || !value.body().is_empty() {
            return Err(RuntimeError::Storage(StorageError::StaleState));
        }
        match (record_kind, value.references()) {
            (INVITATION_RESERVATION_KIND, [reference])
                if reference.table() == TableId::AuthTransaction =>
            {
                let transaction_id = TransactionId::from_bytes(
                    reference
                        .key()
                        .as_bytes()
                        .try_into()
                        .map_err(|_| RuntimeError::Storage(StorageError::InvalidEncoding))?,
                );
                if self
                    .account_service
                    .invitation_reservations
                    .insert(
                        transaction_id,
                        RecoveredInvitationReservation {
                            invitation_id,
                            expires_at,
                        },
                    )
                    .is_some()
                {
                    return Err(RuntimeError::Storage(StorageError::StaleState));
                }
                Ok(())
            }
            (INVITATION_TOMBSTONE_KIND, [reference])
                if reference.table() == TableId::Account
                    && self
                        .index
                        .existing(TableId::Account, reference.key())?
                        .is_some() =>
            {
                Ok(())
            }
            _ => Err(RuntimeError::Storage(StorageError::StaleState)),
        }
    }

    fn admit_opaque_record(
        &mut self,
        key: &StoredKey,
        value: &PersistentRecordValue,
    ) -> Result<(), RuntimeError> {
        let encoded: [u8; OPAQUE_REGISTRATION_RECORD_BYTES] = value
            .body()
            .try_into()
            .map_err(|_| RuntimeError::Storage(StorageError::InvalidEncoding))?;
        let record = OpaqueRegistrationRecord::from_bytes(encoded)
            .map_err(|_| RuntimeError::Storage(StorageError::InvalidEncoding))?;
        if key.as_bytes() == OPAQUE_FAKE_RECORD_KEY {
            if value.generation() != 0
                || value.expires_at().is_some()
                || !value.references().is_empty()
                || self.account_service.fake_opaque_record.is_some()
            {
                return Err(RuntimeError::Storage(StorageError::StaleState));
            }
            self.account_service.fake_opaque_record = Some(*record.expose_for_persistence());
        }
        Ok(())
    }

    fn admit_account(
        &mut self,
        key: StoredKey,
        value: &PersistentRecordValue,
    ) -> Result<(), RuntimeError> {
        let account = AccountRecordBody::decode(value.body())?;
        if KeyDeriver::account_key(account.account_id)? != key
            || account.session_generation.get() != value.generation()
            || account.revision.get() != value.revision()
        {
            return Err(RuntimeError::Storage(StorageError::StaleState));
        }
        self.account_keys.insert(key, account.account_id);
        if self.accounts.insert(account.account_id, account).is_some() {
            return Err(RuntimeError::Storage(StorageError::StaleState));
        }
        Ok(())
    }

    fn admit_channel(
        &mut self,
        key: StoredKey,
        value: &PersistentRecordValue,
    ) -> Result<(), RuntimeError> {
        let channel = ChannelRecordBody::decode(value.body())?;
        if KeyDeriver::channel_key(channel.channel_id)? != key
            || channel.revision.get() != value.revision()
        {
            return Err(RuntimeError::Storage(StorageError::StaleState));
        }
        self.channel_keys.insert(key, channel.channel_id);
        if self.channels.insert(channel.channel_id, channel).is_some() {
            return Err(RuntimeError::Storage(StorageError::StaleState));
        }
        Ok(())
    }

    fn admit_sanction(
        &mut self,
        key: &StoredKey,
        value: &PersistentRecordValue,
    ) -> Result<(), RuntimeError> {
        let sanction = SanctionRecordBody::decode(value.body())?;
        let expected_scope = if sanction.channel_id.is_some() {
            SANCTION_SCOPE_CHANNEL
        } else {
            SANCTION_SCOPE_NETWORK
        };
        let key_bytes = key.as_bytes();
        let valid_key = key_bytes.len() == 2 + SANCTION_KEY_RANDOM_BYTES
            && key_bytes.get(..2) == Some(expected_scope.to_be_bytes().as_slice());
        let expires_at = sanction.expires_at.map(agenc_ircd_types::UtcSecond::get);
        if !valid_key
            || sanction.revision.get() != value.revision()
            || expires_at != value.expires_at()
        {
            return Err(RuntimeError::Storage(StorageError::StaleState));
        }
        self.sanctions.push(sanction);
        Ok(())
    }

    /// Every reservation row must name an account that reserves that
    /// nickname, and every reserved nickname must have exactly one row.
    fn bind_nicknames(&mut self, keys: &KeyDeriver) -> Result<(), RuntimeError> {
        let mut seen: BTreeMap<AccountId, BTreeSet<String>> = BTreeMap::new();
        for (row_key, value) in &self.nickname_rows {
            let spelling = std::str::from_utf8(value.body())
                .map_err(|_| RuntimeError::Storage(StorageError::InvalidEncoding))?;
            let nickname = Nickname::parse(spelling)
                .map_err(|_| RuntimeError::Storage(StorageError::InvalidEncoding))?;
            let canonical = nickname.canonical().to_owned();
            let nickname_value =
                agenc_ircd_domain::NicknameValue::parse(nickname.presentation())
                    .map_err(|_| RuntimeError::Storage(StorageError::InvalidEncoding))?;
            if keys.nickname_key(&nickname_value)? != *row_key {
                return Err(RuntimeError::Storage(StorageError::StaleState));
            }
            let [reference] = value.references() else {
                return Err(RuntimeError::Storage(StorageError::StaleState));
            };
            let account_id = *self
                .account_keys
                .get(reference.key())
                .filter(|_| reference.table() == TableId::Account)
                .ok_or(RuntimeError::Storage(StorageError::StaleState))?;
            let account = self
                .accounts
                .get(&account_id)
                .ok_or(RuntimeError::Storage(StorageError::StaleState))?;
            if !account
                .reserved_nicknames
                .iter()
                .any(|reserved| reserved.canonical() == canonical)
                || !seen
                    .entry(account_id)
                    .or_default()
                    .insert(canonical.clone())
            {
                return Err(RuntimeError::Storage(StorageError::StaleState));
            }
            self.index
                .record_nickname(account_id, canonical, row_key.clone());
        }
        for account in self.accounts.values() {
            let rows = seen.get(&account.account_id).map_or(0, BTreeSet::len);
            if rows != account.reserved_nicknames.len() {
                return Err(RuntimeError::Storage(StorageError::StaleState));
            }
        }
        Ok(())
    }

    /// Every name row must reference a live channel of that name, and every
    /// live channel must own exactly one name row.
    fn bind_channel_names(&mut self, keys: &KeyDeriver) -> Result<(), RuntimeError> {
        let mut named = BTreeSet::new();
        for (row_key, value) in &self.channel_name_rows {
            let spelling = std::str::from_utf8(value.body())
                .map_err(|_| RuntimeError::Storage(StorageError::InvalidEncoding))?;
            let name = ChannelName::parse(spelling)
                .map_err(|_| RuntimeError::Storage(StorageError::InvalidEncoding))?;
            let name_value = agenc_ircd_domain::ChannelNameValue::parse(name.presentation())
                .map_err(|_| RuntimeError::Storage(StorageError::InvalidEncoding))?;
            if keys.channel_name_key(&name_value)? != *row_key {
                return Err(RuntimeError::Storage(StorageError::StaleState));
            }
            let [reference] = value.references() else {
                return Err(RuntimeError::Storage(StorageError::StaleState));
            };
            let channel_id = *self
                .channel_keys
                .get(reference.key())
                .filter(|_| reference.table() == TableId::Channel)
                .ok_or(RuntimeError::Storage(StorageError::StaleState))?;
            let channel = self
                .channels
                .get(&channel_id)
                .ok_or(RuntimeError::Storage(StorageError::StaleState))?;
            if channel.name.canonical() != name.canonical() || !named.insert(channel_id) {
                return Err(RuntimeError::Storage(StorageError::StaleState));
            }
            self.index.record_channel_name(channel_id, row_key.clone());
        }
        if named.len() != self.channels.len() {
            return Err(RuntimeError::Storage(StorageError::StaleState));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agenc_ircd_auth::OpaqueProfile;
    use agenc_ircd_crypto::{
        DatabaseBinding, LoginIndexDigest, LoginIndexKey, LoginIndexKeyId, StorageMasterKey,
    };
    use agenc_ircd_domain::{
        DirectMessagePolicy, DurableSanction, GuestDirectMessagePolicy, ModerationAction,
        ModerationReasonCode, NicknameValue, PresencePolicy, Principal,
    };
    use agenc_ircd_storage::{RecordReference, StorageSealContext};
    use agenc_ircd_testkit::account_id;
    use agenc_ircd_types::{
        DatabaseId, Generation, NetworkId, ServerId, ServerIncarnation, UserId, UtcSecond,
    };

    const MASTER_BYTES: [u8; 32] = [7; 32];

    fn binding() -> DatabaseBinding {
        DatabaseBinding::new(
            NetworkId::from_bytes([1; 32]),
            ServerId::from_bytes([2; 16]),
            ServerIncarnation::from_bytes([3; 16]),
            DatabaseId::from_bytes([4; 16]),
        )
    }

    fn keys() -> Result<KeyDeriver, RuntimeError> {
        KeyDeriver::new(StorageMasterKey::from_bytes(MASTER_BYTES), binding(), 1)
    }

    fn seal(
        table: TableId,
        key: &StoredKey,
        value: &PersistentRecordValue,
        nonce: u8,
    ) -> Result<Vec<u8>, RuntimeError> {
        let master = StorageMasterKey::from_bytes(MASTER_BYTES);
        let context = StorageSealContext::new(&master, binding(), 1)?;
        Ok(context
            .seal(
                table,
                DOMAIN_RECORD_SCHEMA,
                [nonce; 24],
                key,
                &value.encode()?,
            )?
            .encode()?)
    }

    fn account(nickname: Option<NicknameValue>) -> Result<DurableAccount, RuntimeError> {
        Ok(DurableAccount {
            account_id: account_id(1),
            label: None,
            presence: PresencePolicy::Private,
            guest_direct_messages: GuestDirectMessagePolicy::Allow,
            direct_messages: DirectMessagePolicy::Allow,
            contacts: Vec::new(),
            reserved_nicknames: nickname.into_iter().collect(),
            session_generation: Generation::new(1).map_err(|_| RuntimeError::InvalidValue)?,
            revision: Revision::new(1).map_err(|_| RuntimeError::InvalidValue)?,
        })
    }

    fn account_value(account: &DurableAccount) -> Result<PersistentRecordValue, RuntimeError> {
        Ok(PersistentRecordValue::new(
            TableId::Account,
            LIVE_RECORD_KIND,
            account.revision.get(),
            account.session_generation.get(),
            None,
            Vec::new(),
            AccountRecordBody::encode(account)?,
        )?)
    }

    fn reservation_value(
        account_key: &StoredKey,
        nickname: &NicknameValue,
    ) -> Result<PersistentRecordValue, RuntimeError> {
        Ok(PersistentRecordValue::new(
            TableId::NicknameReservation,
            LIVE_RECORD_KIND,
            1,
            0,
            None,
            vec![RecordReference::new(TableId::Account, account_key.clone())?],
            nickname.presentation().as_bytes().to_vec(),
        )?)
    }

    #[test]
    fn live_account_and_reservation_bind_to_their_keyed_rows() -> Result<(), RuntimeError> {
        let keys = keys()?;
        let nickname = NicknameValue::parse("Alice").map_err(|_| RuntimeError::InvalidValue)?;
        let account = account(Some(nickname.clone()))?;
        let account_key = KeyDeriver::account_key(account.account_id)?;
        let nickname_key = keys.nickname_key(&nickname)?;
        let mut scan = Scan::default();
        scan.admit(
            &keys,
            TableId::Account,
            account_key.clone(),
            &seal(TableId::Account, &account_key, &account_value(&account)?, 1)?,
        )?;
        scan.admit(
            &keys,
            TableId::NicknameReservation,
            nickname_key.clone(),
            &seal(
                TableId::NicknameReservation,
                &nickname_key,
                &reservation_value(&account_key, &nickname)?,
                2,
            )?,
        )?;
        scan.bind_nicknames(&keys)?;
        assert!(scan.index.nickname_rows(account.account_id).get("alice") == Some(&nickname_key));
        Ok(())
    }

    #[test]
    fn semantic_secondary_key_and_dangling_reference_are_rejected() -> Result<(), RuntimeError> {
        let keys = keys()?;
        let nickname = NicknameValue::parse("Alice").map_err(|_| RuntimeError::InvalidValue)?;
        let account = account(Some(nickname.clone()))?;
        let account_key = KeyDeriver::account_key(account.account_id)?;
        let wrong_key = StoredKey::new(vec![9; 32])?;
        let mut nickname_scan = Scan::default();
        nickname_scan.admit(
            &keys,
            TableId::Account,
            account_key.clone(),
            &seal(TableId::Account, &account_key, &account_value(&account)?, 3)?,
        )?;
        nickname_scan.admit(
            &keys,
            TableId::NicknameReservation,
            wrong_key.clone(),
            &seal(
                TableId::NicknameReservation,
                &wrong_key,
                &reservation_value(&account_key, &nickname)?,
                4,
            )?,
        )?;
        assert!(matches!(
            nickname_scan.bind_nicknames(&keys),
            Err(RuntimeError::Storage(StorageError::StaleState))
        ));

        let channel_id = ChannelInstanceId::from_bytes([5; 16]);
        let channel_key = KeyDeriver::channel_key(channel_id)?;
        let name = agenc_ircd_domain::ChannelNameValue::parse("#missing")
            .map_err(|_| RuntimeError::InvalidValue)?;
        let name_key = keys.channel_name_key(&name)?;
        let name_value = PersistentRecordValue::new(
            TableId::ChannelName,
            LIVE_RECORD_KIND,
            1,
            0,
            None,
            vec![RecordReference::new(TableId::Channel, channel_key)?],
            name.presentation().as_bytes().to_vec(),
        )?;
        let mut channel_scan = Scan::default();
        channel_scan.admit(
            &keys,
            TableId::ChannelName,
            name_key.clone(),
            &seal(TableId::ChannelName, &name_key, &name_value, 5)?,
        )?;
        assert!(matches!(
            channel_scan.bind_channel_names(&keys),
            Err(RuntimeError::Storage(StorageError::StaleState))
        ));
        Ok(())
    }

    #[test]
    fn envelope_revision_and_sanction_metadata_must_match_the_body() -> Result<(), RuntimeError> {
        let keys = keys()?;
        let account = account(None)?;
        let account_key = KeyDeriver::account_key(account.account_id)?;
        let mismatched = PersistentRecordValue::new(
            TableId::Account,
            LIVE_RECORD_KIND,
            2,
            account.session_generation.get(),
            None,
            Vec::new(),
            AccountRecordBody::encode(&account)?,
        )?;
        let mut scan = Scan::default();
        assert!(matches!(
            scan.admit(
                &keys,
                TableId::Account,
                account_key.clone(),
                &seal(TableId::Account, &account_key, &mismatched, 6)?,
            ),
            Err(RuntimeError::Storage(StorageError::StaleState))
        ));

        let sanction = DurableSanction {
            actor: Principal::Account(account_id(1)),
            target: Principal::Guest(UserId::from_bytes([8; 16])),
            channel_id: None,
            action: ModerationAction::Mute,
            reason_code: ModerationReasonCode::Spam,
            reason: None,
            created_at: UtcSecond::from_unix_seconds(1),
            expires_at: Some(UtcSecond::from_unix_seconds(10)),
            revision: Revision::new(1).map_err(|_| RuntimeError::InvalidValue)?,
        };
        let wrong_scope_key = KeyDeriver::sanction_key(
            Some(ChannelInstanceId::from_bytes([9; 16])),
            [10; SANCTION_KEY_RANDOM_BYTES],
        )?;
        let sanction_value = PersistentRecordValue::new(
            TableId::Sanction,
            LIVE_RECORD_KIND,
            1,
            0,
            Some(10),
            Vec::new(),
            SanctionRecordBody::encode(&sanction)?,
        )?;
        assert!(matches!(
            scan.admit(
                &keys,
                TableId::Sanction,
                wrong_scope_key.clone(),
                &seal(TableId::Sanction, &wrong_scope_key, &sanction_value, 7)?,
            ),
            Err(RuntimeError::Storage(StorageError::StaleState))
        ));
        Ok(())
    }

    #[test]
    fn account_tombstones_are_indexed_but_not_restored() -> Result<(), RuntimeError> {
        let keys = keys()?;
        let key = KeyDeriver::account_key(account_id(3))?;
        let value = PersistentRecordValue::new(
            TableId::Account,
            TOMBSTONE_RECORD_KIND,
            1,
            0,
            None,
            Vec::new(),
            Vec::new(),
        )?;
        let mut scan = Scan::default();
        scan.admit(
            &keys,
            TableId::Account,
            key.clone(),
            &seal(TableId::Account, &key, &value, 8)?,
        )?;
        assert!(scan.accounts.is_empty());
        assert!(scan.index.existing(TableId::Account, &key)?.is_some());
        Ok(())
    }

    fn account_service_scan() -> Result<AccountServiceScan, RuntimeError> {
        Ok(AccountServiceScan {
            login_index_key_state: Some(LoginIndexKeyState::stable(
                3,
                LoginIndexKeyId::from_bytes([12; 32]),
            )?),
            fake_opaque_record: Some([13; OPAQUE_REGISTRATION_RECORD_BYTES]),
            ..AccountServiceScan::default()
        })
    }

    #[test]
    fn recovered_creation_cross_binds_both_reservations() -> Result<(), RuntimeError> {
        let transaction_id = TransactionId::from_bytes([14; 16]);
        let invitation_id = InviteId::from_bytes([15; 16]);
        let digest_bytes = [16; 32];
        let login_key =
            LoginIndexStoredKey::new(3, LoginIndexDigest::from_storage_key(digest_bytes))?
                .encode()?;
        let expires_at = 900;
        let mut scan = account_service_scan()?;
        scan.transactions.insert(
            transaction_id,
            RecoveredTransaction::Creation {
                expires_at,
                reservation_digest: Some(LoginIndexDigest::from_storage_key(digest_bytes)),
                reservation_invitation: Some(invitation_id),
            },
        );
        scan.login_reservations.insert(
            transaction_id,
            RecoveredLoginReservation {
                key: login_key.clone(),
                expires_at,
            },
        );
        scan.invitation_reservations.insert(
            transaction_id,
            RecoveredInvitationReservation {
                invitation_id,
                expires_at,
            },
        );

        let reconstruction = scan.finish()?;
        let [cleanup] = reconstruction.startup_transaction_cleanups() else {
            return Err(RuntimeError::InvalidValue);
        };
        assert_eq!(cleanup.transaction_id(), transaction_id);
        assert!(cleanup.login_key() == Some(&login_key));
        assert_eq!(cleanup.invitation_id(), Some(invitation_id));
        Ok(())
    }

    #[test]
    fn recovered_creation_rejects_missing_or_mismatched_reservations() -> Result<(), RuntimeError> {
        let transaction_id = TransactionId::from_bytes([17; 16]);
        let digest_bytes = [18; 32];
        let mut missing = account_service_scan()?;
        missing.transactions.insert(
            transaction_id,
            RecoveredTransaction::Creation {
                expires_at: 901,
                reservation_digest: Some(LoginIndexDigest::from_storage_key(digest_bytes)),
                reservation_invitation: None,
            },
        );
        assert!(matches!(
            missing.finish(),
            Err(RuntimeError::Storage(StorageError::StaleState))
        ));

        let login_key =
            LoginIndexStoredKey::new(3, LoginIndexDigest::from_storage_key(digest_bytes))?
                .encode()?;
        let mut mismatched = account_service_scan()?;
        mismatched.transactions.insert(
            transaction_id,
            RecoveredTransaction::Creation {
                expires_at: 901,
                reservation_digest: Some(LoginIndexDigest::from_storage_key(digest_bytes)),
                reservation_invitation: None,
            },
        );
        mismatched.login_reservations.insert(
            transaction_id,
            RecoveredLoginReservation {
                key: login_key,
                expires_at: 902,
            },
        );
        assert!(matches!(
            mismatched.finish(),
            Err(RuntimeError::Storage(StorageError::StaleState))
        ));
        Ok(())
    }

    #[test]
    fn latent_rejection_recovers_only_the_transaction_delete() -> Result<(), RuntimeError> {
        let transaction_id = TransactionId::from_bytes([19; 16]);
        let mut scan = account_service_scan()?;
        scan.transactions.insert(
            transaction_id,
            RecoveredTransaction::Creation {
                expires_at: 903,
                reservation_digest: None,
                reservation_invitation: None,
            },
        );

        let reconstruction = scan.finish()?;
        let [cleanup] = reconstruction.startup_transaction_cleanups() else {
            return Err(RuntimeError::InvalidValue);
        };
        assert_eq!(cleanup.transaction_id(), transaction_id);
        assert!(cleanup.login_key().is_none());
        assert!(cleanup.invitation_id().is_none());
        Ok(())
    }

    #[test]
    fn invitation_tombstone_is_validated_without_becoming_startup_cleanup()
    -> Result<(), RuntimeError> {
        let keys = keys()?;
        let account_key = KeyDeriver::account_key(account_id(20))?;
        let account_tombstone = PersistentRecordValue::new(
            TableId::Account,
            TOMBSTONE_RECORD_KIND,
            1,
            0,
            None,
            Vec::new(),
            Vec::new(),
        )?;
        let mut scan = Scan::default();
        scan.admit(
            &keys,
            TableId::Account,
            account_key.clone(),
            &seal(TableId::Account, &account_key, &account_tombstone, 12)?,
        )?;
        let invitation_key = StoredKey::new(InviteId::from_bytes([21; 16]).as_bytes().to_vec())?;
        let tombstone = PersistentRecordValue::new(
            TableId::RegistrationInvite,
            INVITATION_TOMBSTONE_KIND,
            1,
            0,
            Some(904),
            vec![RecordReference::new(TableId::Account, account_key)?],
            Vec::new(),
        )?;
        scan.admit(
            &keys,
            TableId::RegistrationInvite,
            invitation_key.clone(),
            &seal(TableId::RegistrationInvite, &invitation_key, &tombstone, 13)?,
        )?;
        assert!(scan.account_service.invitation_reservations.is_empty());
        assert!(
            scan.index
                .existing(TableId::RegistrationInvite, &invitation_key)?
                .is_some()
        );
        Ok(())
    }

    #[test]
    fn account_service_scan_restores_key_state_and_validates_the_fake_record()
    -> Result<(), RuntimeError> {
        let keys = keys()?;
        let profile = OpaqueProfile::generate(NetworkId::from_bytes([1; 32]))
            .map_err(|_| RuntimeError::InvalidValue)?;
        let fake_key = StoredKey::new(OPAQUE_FAKE_RECORD_KEY.to_vec())?;
        let fake_value = PersistentRecordValue::new(
            TableId::OpaqueRecord,
            LIVE_RECORD_KIND,
            1,
            0,
            None,
            Vec::new(),
            profile.expose_fake_record_for_persistence().to_vec(),
        )?;
        let mut scan = Scan::default();
        scan.admit(
            &keys,
            TableId::OpaqueRecord,
            fake_key.clone(),
            &seal(TableId::OpaqueRecord, &fake_key, &fake_value, 9)?,
        )?;
        assert!(
            scan.index
                .existing(TableId::OpaqueRecord, &fake_key)?
                .is_some()
        );

        let login_key = LoginIndexKey::from_bytes([11; 32]);
        let key_state =
            LoginIndexKeyState::stable(1, login_key.key_id(NetworkId::from_bytes([1; 32])))?;
        let key_state_key = StoredKey::new(LOGIN_INDEX_KEY_STATE_KEY.to_vec())?;
        let master = StorageMasterKey::from_bytes(MASTER_BYTES);
        let context = agenc_ircd_storage::StorageSealContext::new(&master, binding(), 1)?;
        let sealed_key_state = context
            .seal(
                TableId::LoginIndexKeyState,
                DOMAIN_RECORD_SCHEMA,
                [10; 24],
                &key_state_key,
                &key_state.encode()?,
            )?
            .encode()?;
        scan.admit(
            &keys,
            TableId::LoginIndexKeyState,
            key_state_key,
            &sealed_key_state,
        )?;
        let account_service = scan.account_service.finish()?;
        assert_eq!(account_service.login_index_key_state(), key_state);
        assert_eq!(
            account_service.fake_opaque_record(),
            profile.expose_fake_record_for_persistence()
        );

        let invalid_value = PersistentRecordValue::new(
            TableId::OpaqueRecord,
            LIVE_RECORD_KIND,
            1,
            0,
            None,
            Vec::new(),
            vec![0; OPAQUE_REGISTRATION_RECORD_BYTES],
        )?;
        let mut invalid_scan = Scan::default();
        assert!(matches!(
            invalid_scan.admit(
                &keys,
                TableId::OpaqueRecord,
                fake_key.clone(),
                &seal(TableId::OpaqueRecord, &fake_key, &invalid_value, 11)?,
            ),
            Err(RuntimeError::Storage(StorageError::InvalidEncoding))
        ));
        Ok(())
    }
}
