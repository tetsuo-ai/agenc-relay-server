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
    AuthenticationGrantRecord, AuthenticationTransactionRecord, CreationTransactionRecord,
    CredentialChangeTransactionRecord, OPAQUE_REGISTRATION_RECORD_BYTES, OpaqueRegistrationRecord,
};
use agenc_ircd_domain::{
    DomainState, DurableAccount, DurableChannel, DurableSanction, DurableSession,
};
use agenc_ircd_storage::{
    AccountRecordBody, ChannelNameRecordBody, ChannelRecordBody, ExistingRecord, LIVE_RECORD_KIND,
    LOGIN_INDEX_KEY_STATE_KEY, LoginIndexKeyState, LoginIndexStoredKey, LoginIndexValue,
    LoginIndexValueKind, MAX_STORED_KEY_BYTES, OPAQUE_FAKE_RECORD_KEY, PersistentRecordValue,
    ReadPlan, SanctionRecordBody, SealedRecord, SessionRecordBody, StorageError, StoragePort,
    StoredKey, TableId,
};
use agenc_ircd_types::{
    AccountId, ChannelInstanceId, InviteId, MonotonicTick, Nickname, Revision, SessionId,
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
const AUTHENTICATION_GRANT_KIND: u16 = 4;
const INVITATION_RESERVATION_KIND: u16 = 1;
const INVITATION_TOMBSTONE_KIND: u16 = 2;
/// The tables reconstruction scans, in scan order. The Stage 06 tables are
/// decoded into the account service; the federation and E2EE tables are
/// indexed for identity and sizing so later writes carry the right
/// before-image, and their contents reload through bounded reads.
pub const RECONSTRUCTED_TABLES: [TableId; 20] = [
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
    TableId::FederationPeer,
    TableId::FederationOrigin,
    TableId::EdgeOutbox,
    TableId::EdgeProjection,
    TableId::E2eeObject,
    TableId::E2eeState,
    TableId::Audit,
    TableId::AuditCheckpoint,
];

/// Account-service rows needed before the first live request is accepted.
pub struct AccountServiceReconstruction {
    login_index_key_state: LoginIndexKeyState,
    fake_opaque_record: [u8; OPAQUE_REGISTRATION_RECORD_BYTES],
    live_login_keys: BTreeMap<AccountId, StoredKey>,
    login_deletion_tombstones: BTreeMap<(u64, AccountId), StoredKey>,
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

    /// Borrows the one validated live private login-index key for each account.
    #[must_use]
    pub const fn live_login_keys(&self) -> &BTreeMap<AccountId, StoredKey> {
        &self.live_login_keys
    }

    /// Borrows validated login tombstones ordered by expiry and Account ID.
    #[must_use]
    pub const fn login_deletion_tombstones(&self) -> &BTreeMap<(u64, AccountId), StoredKey> {
        &self.login_deletion_tombstones
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
    live_accounts: BTreeSet<AccountId>,
    deleted_accounts: BTreeSet<AccountId>,
    live_login_keys: BTreeMap<AccountId, StoredKey>,
    login_deletion_accounts: BTreeSet<AccountId>,
    login_deletion_tombstones: BTreeMap<(u64, AccountId), StoredKey>,
    opaque_accounts: BTreeSet<AccountId>,
    login_entry_counts: BTreeMap<u32, u64>,
    transactions: BTreeMap<TransactionId, RecoveredTransaction>,
    login_reservations: BTreeMap<TransactionId, RecoveredLoginReservation>,
    invitation_reservations: BTreeMap<TransactionId, RecoveredInvitationReservation>,
}

impl AccountServiceScan {
    fn finish(self) -> Result<AccountServiceReconstruction, RuntimeError> {
        let Self {
            login_index_key_state,
            fake_opaque_record,
            live_accounts,
            deleted_accounts,
            live_login_keys,
            login_deletion_accounts,
            login_deletion_tombstones,
            opaque_accounts,
            login_entry_counts,
            transactions,
            login_reservations,
            invitation_reservations,
        } = self;
        let login_index_key_state =
            login_index_key_state.ok_or(RuntimeError::Storage(StorageError::StaleState))?;
        validate_login_index_generations(login_index_key_state, &login_entry_counts)?;
        if live_accounts.len() != live_login_keys.len()
            || live_accounts.len() != opaque_accounts.len()
            || live_accounts
                .iter()
                .any(|account_id| !live_login_keys.contains_key(account_id))
            || live_login_keys
                .keys()
                .any(|account_id| !opaque_accounts.contains(account_id))
        {
            return Err(RuntimeError::Storage(StorageError::StaleState));
        }
        if login_deletion_accounts
            .iter()
            .any(|account_id| !deleted_accounts.contains(account_id))
        {
            return Err(RuntimeError::Storage(StorageError::StaleState));
        }
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
            live_login_keys,
            login_deletion_tombstones,
            startup_transaction_cleanups,
        })
    }
}

fn validate_login_index_generations(
    key_state: LoginIndexKeyState,
    entry_counts: &BTreeMap<u32, u64>,
) -> Result<(), RuntimeError> {
    let current = key_state.current_generation();
    let previous = key_state.previous();
    if entry_counts.keys().any(|generation| {
        *generation != current && previous.is_none_or(|value| *generation != value.0)
    }) {
        return Err(RuntimeError::Storage(StorageError::StaleState));
    }
    if let Some((previous_generation, expected_count)) = previous
        && entry_counts.get(&previous_generation).copied().unwrap_or(0) != expected_count
    {
        return Err(RuntimeError::Storage(StorageError::StaleState));
    }
    Ok(())
}

enum RecoveredTransaction {
    Authentication,
    AuthenticationGrant,
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
        RecoveredTransaction::Authentication
        | RecoveredTransaction::AuthenticationGrant
        | RecoveredTransaction::CredentialChange => {
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
    sessions: BTreeMap<SessionId, DurableSession>,
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
    monotonic_now: MonotonicTick,
    utc_now: UtcSecond,
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
    let domain = DomainState::restore_authoritative(
        revision,
        scan.accounts.into_values().collect(),
        scan.sessions.into_values().collect(),
        scan.channels.into_values().collect(),
        scan.sanctions,
        monotonic_now,
        utc_now,
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
pub(crate) fn scan_table(
    port: &StoragePort,
    table: TableId,
    mut visit: impl FnMut(StoredKey, Vec<u8>) -> Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    let end = StoredKey::new(vec![0xff; MAX_STORED_KEY_BYTES])?;
    let mut start = StoredKey::new(vec![0])?;
    loop {
        let plan = ReadPlan::range(table, start.clone(), end.clone(), RECONSTRUCTION_PAGE_ROWS)?;
        let result = read_blocking(port, plan)?;
        let truncated = result.truncated;
        let mut last: Option<StoredKey> = None;
        for record in result.records {
            if record.table != table {
                return Err(RuntimeError::Storage(StorageError::StaleState));
            }
            last = Some(record.key.clone());
            visit(record.key, record.sealed_record)?;
        }
        // A page may stop short of the row limit at the storage byte budget,
        // so the store's own truncation flag decides whether rows remain.
        let Some(last) = last else {
            return Ok(());
        };
        if !truncated {
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

fn session_id_from_key(key: &StoredKey) -> Result<SessionId, RuntimeError> {
    Ok(SessionId::from_bytes(key.as_bytes().try_into().map_err(
        |_| RuntimeError::Storage(StorageError::InvalidEncoding),
    )?))
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
            self.admit_login_index(&key, opened.expose_for_storage_codec())?;
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
            (TableId::Account, TOMBSTONE_RECORD_KIND) => self.admit_account_tombstone(&key, &value),
            (TableId::Session, TOMBSTONE_RECORD_KIND) => self.admit_session_tombstone(&key, &value),
            (TableId::Channel, TOMBSTONE_RECORD_KIND) => self.admit_channel_tombstone(&key, &value),
            (TableId::Account, LIVE_RECORD_KIND) => self.admit_account(key, &value),
            (TableId::Session, LIVE_RECORD_KIND) => self.admit_session(key, &value),
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
            // Federation, E2EE and audit rows are indexed for identity and
            // sizing here. Their owners authenticate and reconstruct their
            // contents through bounded reads before listener admission.
            (
                TableId::RequestResult
                | TableId::FederationPeer
                | TableId::FederationOrigin
                | TableId::EdgeOutbox
                | TableId::EdgeProjection
                | TableId::E2eeObject
                | TableId::E2eeState
                | TableId::Audit
                | TableId::AuditCheckpoint,
                _,
            ) => Ok(()),
            _ => Err(RuntimeError::Storage(StorageError::InvalidEncoding)),
        }
    }

    fn admit_channel_tombstone(
        &mut self,
        key: &StoredKey,
        value: &PersistentRecordValue,
    ) -> Result<(), RuntimeError> {
        let channel_id = ChannelInstanceId::from_bytes(
            key.as_bytes()
                .try_into()
                .map_err(|_| RuntimeError::Storage(StorageError::InvalidEncoding))?,
        );
        if KeyDeriver::channel_key(channel_id)? != *key
            || value.generation() != 0
            || value.expires_at().is_some()
            || !value.references().is_empty()
            || !value.body().is_empty()
        {
            return Err(RuntimeError::Storage(StorageError::StaleState));
        }
        Ok(())
    }

    fn admit_session_tombstone(
        &mut self,
        key: &StoredKey,
        value: &PersistentRecordValue,
    ) -> Result<(), RuntimeError> {
        let session_id = session_id_from_key(key)?;
        if KeyDeriver::session_key(session_id)? != *key
            || value.generation() != 0
            || value.expires_at().is_some()
            || !value.references().is_empty()
            || !value.body().is_empty()
        {
            return Err(RuntimeError::Storage(StorageError::StaleState));
        }
        Ok(())
    }

    fn admit_login_index(&mut self, key: &StoredKey, opened: &[u8]) -> Result<(), RuntimeError> {
        let stored_key = LoginIndexStoredKey::decode(key.as_bytes())?;
        let value = LoginIndexValue::decode(opened, &stored_key)?;
        let count = self
            .account_service
            .login_entry_counts
            .entry(value.generation())
            .or_insert(0);
        *count = count.checked_add(1).ok_or(RuntimeError::Overflow)?;
        match value.kind() {
            LoginIndexValueKind::Live { account_id, .. } => {
                if !self.accounts.contains_key(account_id)
                    || self
                        .account_service
                        .live_login_keys
                        .insert(*account_id, key.clone())
                        .is_some()
                {
                    return Err(RuntimeError::Storage(StorageError::StaleState));
                }
            }
            LoginIndexValueKind::CreationReservation {
                transaction_id,
                expires_at,
            } => {
                if self
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
            }
            LoginIndexValueKind::DeletionTombstone {
                deleted_account_id,
                expires_at,
            } => {
                if !self
                    .account_service
                    .login_deletion_accounts
                    .insert(*deleted_account_id)
                    || self
                        .account_service
                        .login_deletion_tombstones
                        .insert((*expires_at, *deleted_account_id), key.clone())
                        .is_some()
                {
                    return Err(RuntimeError::Storage(StorageError::StaleState));
                }
            }
        }
        Ok(())
    }

    fn admit_account_tombstone(
        &mut self,
        key: &StoredKey,
        value: &PersistentRecordValue,
    ) -> Result<(), RuntimeError> {
        let account_id = AccountId::parse_wire_bytes(key.as_bytes())
            .map_err(|_| RuntimeError::Storage(StorageError::InvalidEncoding))?;
        if KeyDeriver::account_key(account_id)? != *key
            || value.generation() != 0
            || value.expires_at().is_some()
            || !value.references().is_empty()
            || !value.body().is_empty()
            || !self.account_service.deleted_accounts.insert(account_id)
        {
            return Err(RuntimeError::Storage(StorageError::StaleState));
        }
        Ok(())
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
            AUTHENTICATION_GRANT_KIND => {
                self.decode_authentication_grant(value, keyed_transaction)?
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

    fn decode_authentication_grant(
        &self,
        value: &PersistentRecordValue,
        keyed_transaction: TransactionId,
    ) -> Result<RecoveredTransaction, RuntimeError> {
        let metadata = AuthenticationGrantRecord::parse(value.body())
            .and_then(AuthenticationGrantRecord::into_restart_metadata)
            .map_err(|_| invalid_account_service_record())?;
        if metadata.transaction_id() != keyed_transaction
            || value.expires_at() != Some(metadata.durable_expires_at_utc().get())
        {
            return Err(RuntimeError::Storage(StorageError::StaleState));
        }
        let [reference] = value.references() else {
            return Err(RuntimeError::Storage(StorageError::StaleState));
        };
        let referenced_account = self
            .account_keys
            .get(reference.key())
            .filter(|_| reference.table() == TableId::Account)
            .ok_or(RuntimeError::Storage(StorageError::StaleState))?;
        let account = self
            .accounts
            .get(referenced_account)
            .ok_or(RuntimeError::Storage(StorageError::StaleState))?;
        if *referenced_account != metadata.account_id()
            || account.session_generation != metadata.account_session_generation()
        {
            return Err(RuntimeError::Storage(StorageError::StaleState));
        }
        Ok(RecoveredTransaction::AuthenticationGrant)
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
            return self.admit_fake_opaque_record(value, &record);
        }
        self.admit_live_opaque_record(key, value)
    }

    fn admit_fake_opaque_record(
        &mut self,
        value: &PersistentRecordValue,
        record: &OpaqueRegistrationRecord,
    ) -> Result<(), RuntimeError> {
        if value.generation() != 0
            || value.expires_at().is_some()
            || !value.references().is_empty()
            || self.account_service.fake_opaque_record.is_some()
        {
            return Err(RuntimeError::Storage(StorageError::StaleState));
        }
        self.account_service.fake_opaque_record = Some(*record.expose_for_persistence());
        Ok(())
    }

    fn admit_live_opaque_record(
        &mut self,
        key: &StoredKey,
        value: &PersistentRecordValue,
    ) -> Result<(), RuntimeError> {
        let account_id = AccountId::parse_wire_bytes(key.as_bytes())
            .map_err(|_| RuntimeError::Storage(StorageError::InvalidEncoding))?;
        let account = self
            .accounts
            .get(&account_id)
            .ok_or(RuntimeError::Storage(StorageError::StaleState))?;
        if !crate::account_service::opaque_record_matches_account(
            value,
            account_id,
            account.revision.get(),
            account.session_generation.get(),
        ) || !self.account_service.opaque_accounts.insert(account_id)
        {
            return Err(RuntimeError::Storage(StorageError::StaleState));
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
        if !self
            .account_service
            .live_accounts
            .insert(account.account_id)
            || self.accounts.insert(account.account_id, account).is_some()
        {
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

    fn admit_session(
        &mut self,
        key: StoredKey,
        value: &PersistentRecordValue,
    ) -> Result<(), RuntimeError> {
        let keyed_session_id = session_id_from_key(&key)?;
        let session = SessionRecordBody::decode(value.body())?;
        if session.session_id != keyed_session_id
            || KeyDeriver::session_key(session.session_id)? != key
            || session.generation.get() != value.generation()
            || session.revision.get() != value.revision()
            || value.expires_at().is_some()
        {
            return Err(RuntimeError::Storage(StorageError::StaleState));
        }
        self.validate_session_references(&session, value)?;
        if self.sessions.insert(session.session_id, session).is_some() {
            return Err(RuntimeError::Storage(StorageError::StaleState));
        }
        Ok(())
    }

    fn validate_session_references(
        &self,
        session: &DurableSession,
        value: &PersistentRecordValue,
    ) -> Result<(), RuntimeError> {
        let mut references = value.references().iter();
        if let Some(account_id) = session.account_id {
            let reference = references
                .next()
                .ok_or(RuntimeError::Storage(StorageError::StaleState))?;
            if reference.table() != TableId::Account
                || self.account_keys.get(reference.key()) != Some(&account_id)
            {
                return Err(RuntimeError::Storage(StorageError::StaleState));
            }
        }
        for channel_id in &session.joined_channels {
            let reference = references
                .next()
                .ok_or(RuntimeError::Storage(StorageError::StaleState))?;
            if reference.table() != TableId::Channel
                || self.channel_keys.get(reference.key()) != Some(channel_id)
            {
                return Err(RuntimeError::Storage(StorageError::StaleState));
            }
        }
        if references.next().is_some() {
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
            let binding = ChannelNameRecordBody::decode(value.body())?;
            if keys.channel_name_key(&binding.name)? != *row_key {
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
            if binding.channel_id != channel_id
                || channel.name != binding.name
                || !named.insert(channel_id)
            {
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
    use agenc_ircd_auth::{
        AUTHENTICATION_GRANT_RECORD_BYTES, AUTHENTICATION_TRANSACTION_RECORD_BYTES,
        CREATION_TRANSACTION_RECORD_BYTES, CREDENTIAL_CHANGE_TRANSACTION_RECORD_BYTES,
        OPAQUE_SERVER_LOGIN_STATE_BYTES, OpaqueProfile,
    };
    use agenc_ircd_crypto::{
        DatabaseBinding, LoginIndexDigest, LoginIndexKey, LoginIndexKeyId, StorageMasterKey,
    };
    use agenc_ircd_domain::{
        ChannelModes, ChannelNameValue, ChannelScope, ContentPolicy, DirectMessagePolicy,
        DisplayNameValue, DurableSanction, DurableWrite, GuestDirectMessagePolicy, HistoryPolicy,
        ModerationAction, ModerationReasonCode, NicknameValue, PersistencePolicy, PresencePolicy,
        Principal, Role, Visibility,
    };
    use agenc_ircd_storage::{RecordReference, StorageSealContext};
    use agenc_ircd_testkit::{account_id, deterministic_cloak};
    use agenc_ircd_types::{
        AccountServiceMessageKind, DatabaseId, Generation, NetworkId, ServerId, ServerIncarnation,
        UserId, UtcSecond,
    };

    const MASTER_BYTES: [u8; 32] = [7; 32];
    /// The network identity written into every hand-built transaction body.
    const TEST_NETWORK: [u8; 32] = [1; 32];
    /// The START disposition code that admits reservations.
    const ADMITTED_DISPOSITION: u16 = 0;
    /// The record code of `AuthError::InvitationRejected`.
    const REJECTED_DISPOSITION: u16 = 8;

    fn stale<T>(result: Result<T, RuntimeError>) -> bool {
        matches!(result, Err(RuntimeError::Storage(StorageError::StaleState)))
    }

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

    fn seal_raw(
        table: TableId,
        key: &StoredKey,
        value: &[u8],
        nonce: u8,
    ) -> Result<Vec<u8>, RuntimeError> {
        seal_with_schema(table, key, value, nonce, DOMAIN_RECORD_SCHEMA)
    }

    fn seal_with_schema(
        table: TableId,
        key: &StoredKey,
        value: &[u8],
        nonce: u8,
        record_schema: u32,
    ) -> Result<Vec<u8>, RuntimeError> {
        let master = StorageMasterKey::from_bytes(MASTER_BYTES);
        let context = StorageSealContext::new(&master, binding(), 1)?;
        Ok(context
            .seal(table, record_schema, [nonce; 24], key, value)?
            .encode()?)
    }

    fn admit_sealed(
        scan: &mut Scan,
        keys: &KeyDeriver,
        table: TableId,
        key: &StoredKey,
        value: &PersistentRecordValue,
        nonce: u8,
    ) -> Result<(), RuntimeError> {
        scan.admit(keys, table, key.clone(), &seal(table, key, value, nonce)?)
    }

    fn scan_with_account(
        keys: &KeyDeriver,
        account: &DurableAccount,
        nonce: u8,
    ) -> Result<Scan, RuntimeError> {
        let mut scan = Scan::default();
        let key = KeyDeriver::account_key(account.account_id)?;
        admit_sealed(
            &mut scan,
            keys,
            TableId::Account,
            &key,
            &account_value(account)?,
            nonce,
        )?;
        Ok(scan)
    }

    fn account_seeded(seed: u8) -> Result<DurableAccount, RuntimeError> {
        let mut account = account(None)?;
        account.account_id = account_id(seed);
        Ok(account)
    }

    fn channel(seed: u8, name: &str) -> Result<DurableChannel, RuntimeError> {
        Ok(DurableChannel {
            channel_id: ChannelInstanceId::from_bytes([seed; 16]),
            name: ChannelNameValue::parse(name).map_err(|_| RuntimeError::InvalidValue)?,
            scope: ChannelScope::Global,
            visibility: Visibility::Listed,
            content_policy: ContentPolicy::Plaintext,
            persistence: PersistencePolicy::Registered,
            creator: Principal::Account(account_id(seed)),
            created_at: UtcSecond::from_unix_seconds(1),
            revision: Revision::new(1).map_err(|_| RuntimeError::InvalidValue)?,
            modes: ChannelModes::default(),
            key_verifier: None,
            member_limit: None,
            topic: None,
            memberships: Vec::new(),
            role_grants: vec![(account_id(seed), Role::Owner)],
            bans: Vec::new(),
            exceptions: Vec::new(),
            invite_exceptions: Vec::new(),
            invites: Vec::new(),
            history: HistoryPolicy::Off,
            e2ee_removal_pending: Vec::new(),
            admin_quarantined: false,
        })
    }

    fn channel_value(
        channel: &DurableChannel,
        revision: u64,
    ) -> Result<PersistentRecordValue, RuntimeError> {
        Ok(PersistentRecordValue::new(
            TableId::Channel,
            LIVE_RECORD_KIND,
            revision,
            0,
            None,
            Vec::new(),
            ChannelRecordBody::encode(channel)?,
        )?)
    }

    fn channel_name_row(
        channel_key: &StoredKey,
        body: Vec<u8>,
    ) -> Result<PersistentRecordValue, RuntimeError> {
        Ok(PersistentRecordValue::new(
            TableId::ChannelName,
            LIVE_RECORD_KIND,
            1,
            0,
            None,
            vec![RecordReference::new(TableId::Channel, channel_key.clone())?],
            body,
        )?)
    }

    fn sanction(
        channel_id: Option<ChannelInstanceId>,
        expires_at: Option<u64>,
    ) -> Result<DurableSanction, RuntimeError> {
        Ok(DurableSanction {
            actor: Principal::Account(account_id(1)),
            target: Principal::Guest(UserId::from_bytes([8; 16])),
            channel_id,
            action: ModerationAction::Mute,
            reason_code: ModerationReasonCode::Spam,
            reason: None,
            created_at: UtcSecond::from_unix_seconds(1),
            expires_at: expires_at.map(UtcSecond::from_unix_seconds),
            revision: Revision::new(1).map_err(|_| RuntimeError::InvalidValue)?,
        })
    }

    fn sanction_value(
        sanction: &DurableSanction,
        revision: u64,
        expires_at: Option<u64>,
    ) -> Result<PersistentRecordValue, RuntimeError> {
        Ok(PersistentRecordValue::new(
            TableId::Sanction,
            LIVE_RECORD_KIND,
            revision,
            0,
            expires_at,
            Vec::new(),
            SanctionRecordBody::encode(sanction)?,
        )?)
    }

    /// Writes the fixed route the account service binds a transaction to.
    fn put_route(body: &mut Vec<u8>) {
        body.extend_from_slice(&[21; 16]);
        body.extend_from_slice(&[22; 16]);
        body.extend_from_slice(&[23; 16]);
        body.extend_from_slice(&1_u64.to_be_bytes());
        body.extend_from_slice(&[24; 16]);
        body.extend_from_slice(&[25; 32]);
    }

    /// Writes a START request binding for `message_kind` on `TEST_NETWORK`.
    fn put_request_binding(body: &mut Vec<u8>, message_kind: AccountServiceMessageKind) {
        body.extend_from_slice(&TEST_NETWORK);
        body.extend_from_slice(&[26; 16]);
        body.extend_from_slice(&[27; 32]);
        body.extend_from_slice(&[28; 16]);
        body.extend_from_slice(&message_kind.wire_value().to_be_bytes());
    }

    /// Writes the version-one header shared by every transaction record class.
    fn transaction_header(class: u16, transaction_id: TransactionId, expires_at: u64) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&1_u16.to_be_bytes());
        body.extend_from_slice(&class.to_be_bytes());
        body.extend_from_slice(transaction_id.as_bytes());
        body.extend_from_slice(&TEST_NETWORK);
        put_route(&mut body);
        body.extend_from_slice(&expires_at.to_be_bytes());
        body
    }

    fn sized(body: Vec<u8>, expected: usize) -> Result<Vec<u8>, RuntimeError> {
        if body.len() != expected {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(body)
    }

    fn disposition(admitted: bool) -> u16 {
        if admitted {
            ADMITTED_DISPOSITION
        } else {
            REJECTED_DISPOSITION
        }
    }

    fn authentication_body(
        transaction_id: TransactionId,
        expires_at: u64,
    ) -> Result<Vec<u8>, RuntimeError> {
        let mut body =
            transaction_header(AUTHENTICATION_TRANSACTION_KIND, transaction_id, expires_at);
        put_request_binding(&mut body, AccountServiceMessageKind::OpaqueAuthStart);
        // A reject-at-finish candidate carries all-zero account fields.
        body.extend_from_slice(&[2]);
        body.extend_from_slice(&[0; 24]);
        body.extend_from_slice(&0_u64.to_be_bytes());
        body.extend_from_slice(&0_u64.to_be_bytes());
        body.extend_from_slice(&[29; 32]);
        // All-zero server login state is structurally valid.
        body.extend_from_slice(&[0; OPAQUE_SERVER_LOGIN_STATE_BYTES]);
        sized(body, AUTHENTICATION_TRANSACTION_RECORD_BYTES)
    }

    fn creation_body(
        transaction_id: TransactionId,
        expires_at: u64,
        admitted: bool,
        invitation: Option<InviteId>,
    ) -> Result<Vec<u8>, RuntimeError> {
        let mut body = transaction_header(CREATION_TRANSACTION_KIND, transaction_id, expires_at);
        put_request_binding(&mut body, AccountServiceMessageKind::AccountCreateStart);
        body.extend_from_slice(&disposition(admitted).to_be_bytes());
        body.extend_from_slice(&[30; 32]);
        body.extend_from_slice(&[29; 32]);
        match invitation {
            Some(invite_id) => {
                body.extend_from_slice(&[1]);
                body.extend_from_slice(invite_id.as_bytes());
                // Invitation interval: not_before 3_000 < expires_at 3_600.
                body.extend_from_slice(&3_000_u64.to_be_bytes());
                body.extend_from_slice(&3_600_u64.to_be_bytes());
            }
            None => {
                body.extend_from_slice(&[0]);
                body.extend_from_slice(&[0; 16]);
                body.extend_from_slice(&0_u64.to_be_bytes());
                body.extend_from_slice(&0_u64.to_be_bytes());
            }
        }
        sized(body, CREATION_TRANSACTION_RECORD_BYTES)
    }

    fn credential_change_body(
        transaction_id: TransactionId,
        expires_at: u64,
        admitted: bool,
        account: &DurableAccount,
    ) -> Result<Vec<u8>, RuntimeError> {
        let mut body = transaction_header(
            CREDENTIAL_CHANGE_TRANSACTION_KIND,
            transaction_id,
            expires_at,
        );
        put_request_binding(&mut body, AccountServiceMessageKind::CredentialChangeStart);
        body.extend_from_slice(&disposition(admitted).to_be_bytes());
        body.extend_from_slice(account.account_id.to_text().as_bytes());
        body.extend_from_slice(&account.revision.get().to_be_bytes());
        body.extend_from_slice(&account.session_generation.get().to_be_bytes());
        body.extend_from_slice(&[29; 32]);
        sized(body, CREDENTIAL_CHANGE_TRANSACTION_RECORD_BYTES)
    }

    fn transaction_value(
        record_kind: u16,
        expires_at: u64,
        references: Vec<RecordReference>,
        body: Vec<u8>,
    ) -> Result<PersistentRecordValue, RuntimeError> {
        Ok(PersistentRecordValue::new(
            TableId::AuthTransaction,
            record_kind,
            1,
            0,
            Some(expires_at),
            references,
            body,
        )?)
    }

    fn transaction_key(transaction_id: TransactionId) -> Result<StoredKey, RuntimeError> {
        Ok(StoredKey::new(transaction_id.as_bytes().to_vec())?)
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
            admin_suspension_expires_at: None,
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

    fn session(joined_channels: Vec<ChannelInstanceId>) -> Result<DurableSession, RuntimeError> {
        Ok(DurableSession {
            session_id: SessionId::from_bytes([41; 16]),
            user_id: UserId::from_bytes([42; 16]),
            home_server_id: ServerId::from_bytes([43; 16]),
            account_id: None,
            account_session_generation: Generation::new(0)
                .map_err(|_| RuntimeError::InvalidValue)?,
            generation: Generation::new(1).map_err(|_| RuntimeError::InvalidValue)?,
            nickname: NicknameValue::parse("Restarted").map_err(|_| RuntimeError::InvalidValue)?,
            display_name: DisplayNameValue::prepare("Restarted")
                .map_err(|_| RuntimeError::InvalidValue)?,
            public_cloak: deterministic_cloak(44).map_err(|_| RuntimeError::InvalidValue)?,
            away: Some("back soon".to_owned()),
            operator_notices: true,
            connection_nonce: [45; 32],
            negotiated_capability_hash: [46; 32],
            joined_channels,
            created_at_utc: UtcSecond::from_unix_seconds(900),
            revision: Revision::new(2).map_err(|_| RuntimeError::InvalidValue)?,
        })
    }

    fn session_value(
        session: &DurableSession,
        references: Vec<RecordReference>,
    ) -> Result<PersistentRecordValue, RuntimeError> {
        Ok(PersistentRecordValue::new(
            TableId::Session,
            LIVE_RECORD_KIND,
            session.revision.get(),
            session.generation.get(),
            None,
            references,
            SessionRecordBody::encode(session)?,
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

    fn authentication_grant_value(
        transaction_id: TransactionId,
        account: &DurableAccount,
        account_key: &StoredKey,
        account_session_generation: u64,
    ) -> Result<PersistentRecordValue, RuntimeError> {
        let expires_at = 930_u64;
        let mut body = Vec::with_capacity(AUTHENTICATION_GRANT_RECORD_BYTES);
        body.extend_from_slice(&1_u16.to_be_bytes());
        body.extend_from_slice(&AUTHENTICATION_GRANT_KIND.to_be_bytes());
        body.extend_from_slice(transaction_id.as_bytes());
        body.extend_from_slice(&[21; 32]);
        body.extend_from_slice(&[22; 32]);
        body.extend_from_slice(&[23; 16]);
        body.extend_from_slice(&[24; 16]);
        body.extend_from_slice(&[25; 16]);
        body.extend_from_slice(&1_u64.to_be_bytes());
        body.extend_from_slice(&[26; 16]);
        body.extend_from_slice(&[27; 32]);
        body.extend_from_slice(account.account_id.to_text().as_bytes());
        body.extend_from_slice(&account_session_generation.to_be_bytes());
        body.extend_from_slice(&expires_at.to_be_bytes());
        if body.len() != AUTHENTICATION_GRANT_RECORD_BYTES {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(PersistentRecordValue::new(
            TableId::AuthTransaction,
            AUTHENTICATION_GRANT_KIND,
            1,
            0,
            Some(expires_at),
            vec![RecordReference::new(TableId::Account, account_key.clone())?],
            body,
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
            ChannelNameRecordBody::encode(channel_id, &name)?,
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

    #[test]
    fn live_sessions_restore_and_plan_one_durable_restart_cleanup() -> Result<(), RuntimeError> {
        let keys = keys()?;
        let session = session(Vec::new())?;
        let key = KeyDeriver::session_key(session.session_id)?;
        let value = session_value(&session, Vec::new())?;
        let mut scan = Scan::default();
        scan.admit(
            &keys,
            TableId::Session,
            key.clone(),
            &seal(TableId::Session, &key, &value, 40)?,
        )?;
        let mut domain = DomainState::restore_authoritative(
            Revision::new(2).map_err(|_| RuntimeError::InvalidValue)?,
            Vec::new(),
            scan.sessions.into_values().collect(),
            Vec::new(),
            Vec::new(),
            MonotonicTick::from_ticks(50),
            UtcSecond::from_unix_seconds(1_000),
        )
        .map_err(|_| RuntimeError::InvalidValue)?;
        let plan = domain
            .plan_session_disconnected(session.user_id)
            .map_err(|_| RuntimeError::InvalidValue)?;
        assert!(matches!(
            plan.durable_writes(),
            [DurableWrite::TombstoneSession(session_id)] if *session_id == session.session_id
        ));
        let prepared = domain
            .prepare_mutation(plan)
            .map_err(|_| RuntimeError::InvalidValue)?;
        domain
            .apply_prepared(prepared)
            .map_err(|_| RuntimeError::InvalidValue)?;
        assert_eq!(domain.session_count(), 0);
        Ok(())
    }

    #[test]
    fn session_rows_require_exact_live_channel_references() -> Result<(), RuntimeError> {
        let keys = keys()?;
        let channel_id = ChannelInstanceId::from_bytes([47; 16]);
        let channel_key = KeyDeriver::channel_key(channel_id)?;
        let session = session(vec![channel_id])?;
        let session_key = KeyDeriver::session_key(session.session_id)?;

        let mut missing = Scan::default();
        let missing_value = session_value(&session, Vec::new())?;
        assert!(matches!(
            missing.admit(
                &keys,
                TableId::Session,
                session_key.clone(),
                &seal(TableId::Session, &session_key, &missing_value, 41)?,
            ),
            Err(RuntimeError::Storage(StorageError::StaleState))
        ));

        let mut exact = Scan::default();
        exact.channel_keys.insert(channel_key.clone(), channel_id);
        let exact_value = session_value(
            &session,
            vec![RecordReference::new(TableId::Channel, channel_key)?],
        )?;
        exact.admit(
            &keys,
            TableId::Session,
            session_key.clone(),
            &seal(TableId::Session, &session_key, &exact_value, 42)?,
        )?;
        assert_eq!(exact.sessions.len(), 1);
        Ok(())
    }

    #[test]
    fn session_tombstones_are_indexed_but_not_restored() -> Result<(), RuntimeError> {
        let keys = keys()?;
        let session_id = SessionId::from_bytes([48; 16]);
        let key = KeyDeriver::session_key(session_id)?;
        let value = PersistentRecordValue::new(
            TableId::Session,
            TOMBSTONE_RECORD_KIND,
            3,
            0,
            None,
            Vec::new(),
            Vec::new(),
        )?;
        let mut scan = Scan::default();
        scan.admit(
            &keys,
            TableId::Session,
            key.clone(),
            &seal(TableId::Session, &key, &value, 43)?,
        )?;
        assert!(scan.sessions.is_empty());
        assert!(scan.index.existing(TableId::Session, &key)?.is_some());
        Ok(())
    }

    #[test]
    fn authentication_grant_requires_its_live_account_and_generation() -> Result<(), RuntimeError> {
        let keys = keys()?;
        let account = account(None)?;
        let account_key = KeyDeriver::account_key(account.account_id)?;
        let transaction_id = TransactionId::from_bytes([28; 16]);
        let transaction_key = StoredKey::new(transaction_id.as_bytes().to_vec())?;

        let mut valid = Scan::default();
        valid.admit(
            &keys,
            TableId::Account,
            account_key.clone(),
            &seal(
                TableId::Account,
                &account_key,
                &account_value(&account)?,
                13,
            )?,
        )?;
        let grant = authentication_grant_value(
            transaction_id,
            &account,
            &account_key,
            account.session_generation.get(),
        )?;
        valid.admit(
            &keys,
            TableId::AuthTransaction,
            transaction_key.clone(),
            &seal(TableId::AuthTransaction, &transaction_key, &grant, 14)?,
        )?;
        assert!(matches!(
            valid.account_service.transactions.get(&transaction_id),
            Some(RecoveredTransaction::AuthenticationGrant)
        ));

        let mut stale_generation = Scan::default();
        stale_generation.admit(
            &keys,
            TableId::Account,
            account_key.clone(),
            &seal(
                TableId::Account,
                &account_key,
                &account_value(&account)?,
                15,
            )?,
        )?;
        let stale = authentication_grant_value(transaction_id, &account, &account_key, 2)?;
        assert!(matches!(
            stale_generation.admit(
                &keys,
                TableId::AuthTransaction,
                transaction_key.clone(),
                &seal(TableId::AuthTransaction, &transaction_key, &stale, 16)?,
            ),
            Err(RuntimeError::Storage(StorageError::StaleState))
        ));

        let missing_reference = PersistentRecordValue::new(
            TableId::AuthTransaction,
            AUTHENTICATION_GRANT_KIND,
            grant.revision(),
            0,
            grant.expires_at(),
            Vec::new(),
            grant.body().to_vec(),
        )?;
        let mut missing = Scan::default();
        assert!(matches!(
            missing.admit(
                &keys,
                TableId::AuthTransaction,
                transaction_key.clone(),
                &seal(
                    TableId::AuthTransaction,
                    &transaction_key,
                    &missing_reference,
                    17,
                )?,
            ),
            Err(RuntimeError::Storage(StorageError::StaleState))
        ));
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
    fn login_deletion_tombstone_restores_only_for_a_deleted_account() -> Result<(), RuntimeError> {
        let keys = keys()?;
        let deleted_account_id = account_id(22);
        let account_key = KeyDeriver::account_key(deleted_account_id)?;
        let account_tombstone = PersistentRecordValue::new(
            TableId::Account,
            TOMBSTONE_RECORD_KIND,
            1,
            0,
            None,
            Vec::new(),
            Vec::new(),
        )?;
        let login_key = LoginIndexStoredKey::new(3, LoginIndexDigest::from_storage_key([23; 32]))?;
        let stored_login_key = login_key.encode()?;
        let login_tombstone = LoginIndexValue::new(
            &login_key,
            LoginIndexValueKind::DeletionTombstone {
                deleted_account_id,
                expires_at: 2_592_100,
            },
        )?;
        let mut scan = Scan::default();
        scan.admit(
            &keys,
            TableId::Account,
            account_key.clone(),
            &seal(TableId::Account, &account_key, &account_tombstone, 14)?,
        )?;
        scan.admit(
            &keys,
            TableId::LoginIndex,
            stored_login_key.clone(),
            &seal_raw(
                TableId::LoginIndex,
                &stored_login_key,
                &login_tombstone.encode()?,
                15,
            )?,
        )?;
        assert!(
            scan.account_service
                .login_deletion_tombstones
                .get(&(2_592_100, deleted_account_id))
                == Some(&stored_login_key)
        );

        let mut missing_owner = account_service_scan()?;
        missing_owner
            .login_deletion_accounts
            .insert(deleted_account_id);
        missing_owner
            .login_deletion_tombstones
            .insert((2_592_100, deleted_account_id), stored_login_key);
        assert!(matches!(
            missing_owner.finish(),
            Err(RuntimeError::Storage(StorageError::StaleState))
        ));
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

    #[test]
    fn live_login_and_opaque_rows_restore_one_cross_bound_account_key() -> Result<(), RuntimeError>
    {
        let keys = keys()?;
        let account = account(None)?;
        let account_key = KeyDeriver::account_key(account.account_id)?;
        let profile = OpaqueProfile::generate(NetworkId::from_bytes([1; 32]))
            .map_err(|_| RuntimeError::InvalidValue)?;
        let login_key = LoginIndexStoredKey::new(1, LoginIndexDigest::from_storage_key([31; 32]))?;
        let stored_login_key = login_key.encode()?;
        let login_value = LoginIndexValue::new(
            &login_key,
            LoginIndexValueKind::Live {
                account_id: account.account_id,
                opaque_credential_id: agenc_ircd_types::OpaqueCredentialId::from_bytes([32; 32]),
            },
        )?;
        let opaque_value = PersistentRecordValue::new(
            TableId::OpaqueRecord,
            LIVE_RECORD_KIND,
            account.revision.get(),
            account.session_generation.get(),
            None,
            vec![RecordReference::new(TableId::Account, account_key.clone())?],
            profile.expose_fake_record_for_persistence().to_vec(),
        )?;

        let mut valid = Scan::default();
        valid.admit(
            &keys,
            TableId::Account,
            account_key.clone(),
            &seal(
                TableId::Account,
                &account_key,
                &account_value(&account)?,
                32,
            )?,
        )?;
        valid.admit(
            &keys,
            TableId::LoginIndex,
            stored_login_key.clone(),
            &seal_raw(
                TableId::LoginIndex,
                &stored_login_key,
                &login_value.encode()?,
                33,
            )?,
        )?;
        valid.admit(
            &keys,
            TableId::OpaqueRecord,
            account_key.clone(),
            &seal(TableId::OpaqueRecord, &account_key, &opaque_value, 34)?,
        )?;
        valid.account_service.login_index_key_state = Some(LoginIndexKeyState::stable(
            1,
            LoginIndexKeyId::from_bytes([35; 32]),
        )?);
        valid.account_service.fake_opaque_record =
            Some(*profile.expose_fake_record_for_persistence());
        let reconstructed = valid.account_service.finish()?;
        assert!(
            reconstructed.live_login_keys().get(&account.account_id) == Some(&stored_login_key)
        );

        let mut orphan_account = Scan::default();
        orphan_account.admit(
            &keys,
            TableId::Account,
            account_key.clone(),
            &seal(
                TableId::Account,
                &account_key,
                &account_value(&account)?,
                35,
            )?,
        )?;
        orphan_account.account_service.login_index_key_state = Some(LoginIndexKeyState::stable(
            1,
            LoginIndexKeyId::from_bytes([36; 32]),
        )?);
        orphan_account.account_service.fake_opaque_record =
            Some(*profile.expose_fake_record_for_persistence());
        assert!(matches!(
            orphan_account.account_service.finish(),
            Err(RuntimeError::Storage(StorageError::StaleState))
        ));

        let mut missing_account = Scan::default();
        assert!(matches!(
            missing_account.admit(
                &keys,
                TableId::LoginIndex,
                stored_login_key.clone(),
                &seal_raw(
                    TableId::LoginIndex,
                    &stored_login_key,
                    &login_value.encode()?,
                    37,
                )?,
            ),
            Err(RuntimeError::Storage(StorageError::StaleState))
        ));

        let mut missing_reference = Scan::default();
        missing_reference.admit(
            &keys,
            TableId::Account,
            account_key.clone(),
            &seal(
                TableId::Account,
                &account_key,
                &account_value(&account)?,
                38,
            )?,
        )?;
        let opaque_without_reference = PersistentRecordValue::new(
            TableId::OpaqueRecord,
            LIVE_RECORD_KIND,
            account.revision.get(),
            account.session_generation.get(),
            None,
            Vec::new(),
            profile.expose_fake_record_for_persistence().to_vec(),
        )?;
        assert!(matches!(
            missing_reference.admit(
                &keys,
                TableId::OpaqueRecord,
                account_key.clone(),
                &seal(
                    TableId::OpaqueRecord,
                    &account_key,
                    &opaque_without_reference,
                    39,
                )?,
            ),
            Err(RuntimeError::Storage(StorageError::StaleState))
        ));
        let stable = LoginIndexKeyState::stable(1, LoginIndexKeyId::from_bytes([40; 32]))?;
        assert!(matches!(
            validate_login_index_generations(stable, &BTreeMap::from([(2, 1)])),
            Err(RuntimeError::Storage(StorageError::StaleState))
        ));
        let transition = LoginIndexKeyState::transition(
            1,
            LoginIndexKeyId::from_bytes([41; 32]),
            LoginIndexKeyId::from_bytes([42; 32]),
            2,
        )?;
        assert!(matches!(
            validate_login_index_generations(transition, &BTreeMap::from([(1, 1)])),
            Err(RuntimeError::Storage(StorageError::StaleState))
        ));
        Ok(())
    }

    #[test]
    fn finish_rejects_every_live_account_row_mismatch() -> Result<(), RuntimeError> {
        let login_key =
            LoginIndexStoredKey::new(3, LoginIndexDigest::from_storage_key([50; 32]))?.encode()?;

        let mut missing_opaque = account_service_scan()?;
        missing_opaque.live_accounts.insert(account_id(1));
        missing_opaque
            .live_login_keys
            .insert(account_id(1), login_key.clone());
        assert!(stale(missing_opaque.finish()));

        let mut foreign_login = account_service_scan()?;
        foreign_login.live_accounts.insert(account_id(1));
        foreign_login
            .live_login_keys
            .insert(account_id(2), login_key.clone());
        foreign_login.opaque_accounts.insert(account_id(1));
        assert!(stale(foreign_login.finish()));

        let mut foreign_opaque = account_service_scan()?;
        foreign_opaque.live_accounts.insert(account_id(1));
        foreign_opaque
            .live_login_keys
            .insert(account_id(1), login_key.clone());
        foreign_opaque.opaque_accounts.insert(account_id(2));
        assert!(stale(foreign_opaque.finish()));

        let mut deleted = account_service_scan()?;
        deleted.deleted_accounts.insert(account_id(3));
        deleted.login_deletion_accounts.insert(account_id(3));
        deleted
            .login_deletion_tombstones
            .insert((2_592_100, account_id(3)), login_key.clone());
        let reconstruction = deleted.finish()?;
        assert!(
            reconstruction
                .login_deletion_tombstones()
                .get(&(2_592_100, account_id(3)))
                == Some(&login_key)
        );
        assert!(reconstruction.live_login_keys().is_empty());
        Ok(())
    }

    #[test]
    fn login_index_generation_counts_must_match_the_key_state() -> Result<(), RuntimeError> {
        let stable = LoginIndexKeyState::stable(1, LoginIndexKeyId::from_bytes([51; 32]))?;
        validate_login_index_generations(stable, &BTreeMap::from([(1, 3)]))?;
        validate_login_index_generations(stable, &BTreeMap::new())?;

        let transition = LoginIndexKeyState::transition(
            1,
            LoginIndexKeyId::from_bytes([52; 32]),
            LoginIndexKeyId::from_bytes([53; 32]),
            2,
        )?;
        validate_login_index_generations(transition, &BTreeMap::from([(1, 2), (2, 1)]))?;
        assert!(stale(validate_login_index_generations(
            transition,
            &BTreeMap::from([(1, 2), (5, 1)]),
        )));
        assert!(stale(validate_login_index_generations(
            transition,
            &BTreeMap::new(),
        )));
        Ok(())
    }

    #[test]
    fn leftover_reservations_without_an_owning_transaction_are_stale() -> Result<(), RuntimeError> {
        let transaction_id = TransactionId::from_bytes([54; 16]);
        let login_key =
            LoginIndexStoredKey::new(3, LoginIndexDigest::from_storage_key([55; 32]))?.encode()?;

        let mut login_only = account_service_scan()?;
        login_only.login_reservations.insert(
            transaction_id,
            RecoveredLoginReservation {
                key: login_key,
                expires_at: 905,
            },
        );
        assert!(stale(login_only.finish()));

        let mut invitation_only = account_service_scan()?;
        invitation_only.invitation_reservations.insert(
            transaction_id,
            RecoveredInvitationReservation {
                invitation_id: InviteId::from_bytes([56; 16]),
                expires_at: 905,
            },
        );
        assert!(stale(invitation_only.finish()));
        Ok(())
    }

    #[test]
    fn non_creation_transactions_recover_only_their_own_row() -> Result<(), RuntimeError> {
        let authentication_id = TransactionId::from_bytes([57; 16]);
        let grant_id = TransactionId::from_bytes([58; 16]);
        let change_id = TransactionId::from_bytes([59; 16]);

        let mut plain = account_service_scan()?;
        plain
            .transactions
            .insert(authentication_id, RecoveredTransaction::Authentication);
        plain
            .transactions
            .insert(grant_id, RecoveredTransaction::AuthenticationGrant);
        plain
            .transactions
            .insert(change_id, RecoveredTransaction::CredentialChange);
        let reconstruction = plain.finish()?;
        let cleanups = reconstruction.startup_transaction_cleanups();
        let recovered: Vec<TransactionId> = cleanups
            .iter()
            .map(RecoveredAccountTransactionCleanup::transaction_id)
            .collect();
        assert_eq!(recovered, vec![authentication_id, grant_id, change_id]);
        assert!(
            cleanups
                .iter()
                .all(|cleanup| cleanup.login_key().is_none() && cleanup.invitation_id().is_none())
        );

        let login_key =
            LoginIndexStoredKey::new(3, LoginIndexDigest::from_storage_key([60; 32]))?.encode()?;
        let mut with_login = account_service_scan()?;
        with_login
            .transactions
            .insert(authentication_id, RecoveredTransaction::Authentication);
        with_login.login_reservations.insert(
            authentication_id,
            RecoveredLoginReservation {
                key: login_key,
                expires_at: 906,
            },
        );
        assert!(stale(with_login.finish()));

        let mut with_invitation = account_service_scan()?;
        with_invitation
            .transactions
            .insert(change_id, RecoveredTransaction::CredentialChange);
        with_invitation.invitation_reservations.insert(
            change_id,
            RecoveredInvitationReservation {
                invitation_id: InviteId::from_bytes([61; 16]),
                expires_at: 906,
            },
        );
        assert!(stale(with_invitation.finish()));
        Ok(())
    }

    #[test]
    fn rejected_creation_must_not_own_any_reservation() -> Result<(), RuntimeError> {
        let transaction_id = TransactionId::from_bytes([62; 16]);
        let invitation_id = InviteId::from_bytes([63; 16]);
        let rejected = || RecoveredTransaction::Creation {
            expires_at: 907,
            reservation_digest: None,
            reservation_invitation: None,
        };
        let login_key =
            LoginIndexStoredKey::new(3, LoginIndexDigest::from_storage_key([64; 32]))?.encode()?;

        let mut with_login = account_service_scan()?;
        with_login.transactions.insert(transaction_id, rejected());
        with_login.login_reservations.insert(
            transaction_id,
            RecoveredLoginReservation {
                key: login_key,
                expires_at: 907,
            },
        );
        assert!(stale(with_login.finish()));

        let mut with_invitation = account_service_scan()?;
        with_invitation
            .transactions
            .insert(transaction_id, rejected());
        with_invitation.invitation_reservations.insert(
            transaction_id,
            RecoveredInvitationReservation {
                invitation_id,
                expires_at: 907,
            },
        );
        assert!(stale(with_invitation.finish()));

        let mut with_metadata = account_service_scan()?;
        with_metadata.transactions.insert(
            transaction_id,
            RecoveredTransaction::Creation {
                expires_at: 907,
                reservation_digest: None,
                reservation_invitation: Some(invitation_id),
            },
        );
        assert!(stale(with_metadata.finish()));
        Ok(())
    }

    #[test]
    fn creation_login_reservation_must_use_the_current_generation_key() -> Result<(), RuntimeError>
    {
        let transaction_id = TransactionId::from_bytes([65; 16]);
        let digest_bytes = [66; 32];
        let previous_generation_key =
            LoginIndexStoredKey::new(2, LoginIndexDigest::from_storage_key(digest_bytes))?
                .encode()?;
        let mut scan = account_service_scan()?;
        scan.transactions.insert(
            transaction_id,
            RecoveredTransaction::Creation {
                expires_at: 908,
                reservation_digest: Some(LoginIndexDigest::from_storage_key(digest_bytes)),
                reservation_invitation: None,
            },
        );
        scan.login_reservations.insert(
            transaction_id,
            RecoveredLoginReservation {
                key: previous_generation_key,
                expires_at: 908,
            },
        );
        assert!(stale(scan.finish()));
        Ok(())
    }

    #[test]
    fn creation_invitation_reservation_must_match_the_transaction_exactly()
    -> Result<(), RuntimeError> {
        let transaction_id = TransactionId::from_bytes([67; 16]);
        let invitation_id = InviteId::from_bytes([68; 16]);
        let digest_bytes = [69; 32];
        let expires_at = 909;
        let creation = |reservation_invitation: Option<InviteId>| RecoveredTransaction::Creation {
            expires_at,
            reservation_digest: Some(LoginIndexDigest::from_storage_key(digest_bytes)),
            reservation_invitation,
        };
        let login_key =
            LoginIndexStoredKey::new(3, LoginIndexDigest::from_storage_key(digest_bytes))?
                .encode()?;
        let login = || RecoveredLoginReservation {
            key: login_key.clone(),
            expires_at,
        };

        let mut unexpected = account_service_scan()?;
        unexpected
            .transactions
            .insert(transaction_id, creation(None));
        unexpected
            .login_reservations
            .insert(transaction_id, login());
        unexpected.invitation_reservations.insert(
            transaction_id,
            RecoveredInvitationReservation {
                invitation_id,
                expires_at,
            },
        );
        assert!(stale(unexpected.finish()));

        let mut missing = account_service_scan()?;
        missing
            .transactions
            .insert(transaction_id, creation(Some(invitation_id)));
        missing.login_reservations.insert(transaction_id, login());
        assert!(stale(missing.finish()));

        let mut wrong_id = account_service_scan()?;
        wrong_id
            .transactions
            .insert(transaction_id, creation(Some(invitation_id)));
        wrong_id.login_reservations.insert(transaction_id, login());
        wrong_id.invitation_reservations.insert(
            transaction_id,
            RecoveredInvitationReservation {
                invitation_id: InviteId::from_bytes([70; 16]),
                expires_at,
            },
        );
        assert!(stale(wrong_id.finish()));

        let mut wrong_expiry = account_service_scan()?;
        wrong_expiry
            .transactions
            .insert(transaction_id, creation(Some(invitation_id)));
        wrong_expiry
            .login_reservations
            .insert(transaction_id, login());
        wrong_expiry.invitation_reservations.insert(
            transaction_id,
            RecoveredInvitationReservation {
                invitation_id,
                expires_at: 910,
            },
        );
        assert!(stale(wrong_expiry.finish()));
        Ok(())
    }

    #[test]
    fn foreign_record_schema_is_rejected_before_decoding() -> Result<(), RuntimeError> {
        let keys = keys()?;
        let account = account(None)?;
        let key = KeyDeriver::account_key(account.account_id)?;
        let sealed = seal_with_schema(
            TableId::Account,
            &key,
            &account_value(&account)?.encode()?,
            71,
            2,
        )?;
        let mut scan = Scan::default();
        assert!(matches!(
            scan.admit(&keys, TableId::Account, key, &sealed),
            Err(RuntimeError::Storage(StorageError::UnsupportedVersion))
        ));
        assert!(scan.index.is_empty());
        Ok(())
    }

    fn sealed_key_state(
        key: &StoredKey,
        state: LoginIndexKeyState,
        nonce: u8,
    ) -> Result<Vec<u8>, RuntimeError> {
        seal_raw(TableId::LoginIndexKeyState, key, &state.encode()?, nonce)
    }

    #[test]
    fn login_index_key_state_row_must_use_its_fixed_key_exactly_once() -> Result<(), RuntimeError> {
        let keys = keys()?;
        let state = LoginIndexKeyState::stable(1, LoginIndexKeyId::from_bytes([72; 32]))?;
        let wrong_key = StoredKey::new(vec![73; 8])?;
        let mut wrong = Scan::default();
        assert!(stale(wrong.admit(
            &keys,
            TableId::LoginIndexKeyState,
            wrong_key.clone(),
            &sealed_key_state(&wrong_key, state, 73)?,
        )));
        assert!(wrong.account_service.login_index_key_state.is_none());

        let fixed_key = StoredKey::new(LOGIN_INDEX_KEY_STATE_KEY.to_vec())?;
        let mut duplicate = Scan::default();
        duplicate.admit(
            &keys,
            TableId::LoginIndexKeyState,
            fixed_key.clone(),
            &sealed_key_state(&fixed_key, state, 74)?,
        )?;
        assert!(stale(duplicate.admit(
            &keys,
            TableId::LoginIndexKeyState,
            fixed_key.clone(),
            &sealed_key_state(&fixed_key, state, 75)?,
        )));
        assert_eq!(duplicate.account_service.login_index_key_state, Some(state));
        Ok(())
    }

    #[test]
    fn opaque_tombstones_admit_only_empty_bodies() -> Result<(), RuntimeError> {
        let keys = keys()?;
        let key = KeyDeriver::account_key(account_id(76))?;
        let empty = PersistentRecordValue::new(
            TableId::OpaqueRecord,
            TOMBSTONE_RECORD_KIND,
            1,
            0,
            None,
            Vec::new(),
            Vec::new(),
        )?;
        let mut scan = Scan::default();
        admit_sealed(&mut scan, &keys, TableId::OpaqueRecord, &key, &empty, 76)?;
        assert!(scan.account_service.opaque_accounts.is_empty());
        assert!(scan.index.existing(TableId::OpaqueRecord, &key)?.is_some());

        let stray = PersistentRecordValue::new(
            TableId::OpaqueRecord,
            TOMBSTONE_RECORD_KIND,
            1,
            0,
            None,
            Vec::new(),
            vec![1],
        )?;
        let mut rejected = Scan::default();
        assert!(matches!(
            admit_sealed(
                &mut rejected,
                &keys,
                TableId::OpaqueRecord,
                &key,
                &stray,
                77
            ),
            Err(RuntimeError::Storage(StorageError::InvalidEncoding))
        ));
        Ok(())
    }

    #[test]
    fn session_tombstones_require_bare_metadata() -> Result<(), RuntimeError> {
        let keys = keys()?;
        let key = KeyDeriver::session_key(SessionId::from_bytes([78; 16]))?;
        let account_reference =
            RecordReference::new(TableId::Account, KeyDeriver::account_key(account_id(1))?)?;
        let tombstone = |generation: u64,
                         expires_at: Option<u64>,
                         references: Vec<RecordReference>,
                         body: Vec<u8>| {
            PersistentRecordValue::new(
                TableId::Session,
                TOMBSTONE_RECORD_KIND,
                1,
                generation,
                expires_at,
                references,
                body,
            )
        };
        for value in [
            tombstone(1, None, Vec::new(), Vec::new())?,
            tombstone(0, Some(79), Vec::new(), Vec::new())?,
            tombstone(0, None, vec![account_reference], Vec::new())?,
            tombstone(0, None, Vec::new(), vec![1])?,
        ] {
            let mut scan = Scan::default();
            assert!(stale(admit_sealed(
                &mut scan,
                &keys,
                TableId::Session,
                &key,
                &value,
                79,
            )));
        }
        Ok(())
    }

    #[test]
    fn account_tombstones_require_bare_metadata_and_one_row() -> Result<(), RuntimeError> {
        let keys = keys()?;
        let key = KeyDeriver::account_key(account_id(80))?;
        let channel_reference = RecordReference::new(
            TableId::Channel,
            KeyDeriver::channel_key(ChannelInstanceId::from_bytes([81; 16]))?,
        )?;
        let tombstone = |generation: u64,
                         expires_at: Option<u64>,
                         references: Vec<RecordReference>,
                         body: Vec<u8>| {
            PersistentRecordValue::new(
                TableId::Account,
                TOMBSTONE_RECORD_KIND,
                1,
                generation,
                expires_at,
                references,
                body,
            )
        };
        for value in [
            tombstone(1, None, Vec::new(), Vec::new())?,
            tombstone(0, Some(82), Vec::new(), Vec::new())?,
            tombstone(0, None, vec![channel_reference], Vec::new())?,
            tombstone(0, None, Vec::new(), vec![1])?,
        ] {
            let mut scan = Scan::default();
            assert!(stale(admit_sealed(
                &mut scan,
                &keys,
                TableId::Account,
                &key,
                &value,
                82,
            )));
        }

        let mut duplicate = Scan::default();
        let bare = tombstone(0, None, Vec::new(), Vec::new())?;
        admit_sealed(&mut duplicate, &keys, TableId::Account, &key, &bare, 83)?;
        assert!(stale(admit_sealed(
            &mut duplicate,
            &keys,
            TableId::Account,
            &key,
            &bare,
            84,
        )));
        assert_eq!(duplicate.account_service.deleted_accounts.len(), 1);
        Ok(())
    }

    fn login_row(
        key: &LoginIndexStoredKey,
        kind: LoginIndexValueKind,
    ) -> Result<(StoredKey, Vec<u8>), RuntimeError> {
        Ok((key.encode()?, LoginIndexValue::new(key, kind)?.encode()?))
    }

    #[test]
    fn login_index_rows_reject_duplicate_bindings() -> Result<(), RuntimeError> {
        let keys = keys()?;
        let account = account(None)?;
        let mut scan = scan_with_account(&keys, &account, 85)?;
        let admit_login = |scan: &mut Scan, row: &(StoredKey, Vec<u8>), nonce: u8| {
            scan.admit(
                &keys,
                TableId::LoginIndex,
                row.0.clone(),
                &seal_raw(TableId::LoginIndex, &row.0, &row.1, nonce)?,
            )
        };
        let live = |digest: u8| {
            login_row(
                &LoginIndexStoredKey::new(1, LoginIndexDigest::from_storage_key([digest; 32]))?,
                LoginIndexValueKind::Live {
                    account_id: account.account_id,
                    opaque_credential_id: agenc_ircd_types::OpaqueCredentialId::from_bytes(
                        [digest; 32],
                    ),
                },
            )
        };
        admit_login(&mut scan, &live(86)?, 86)?;
        assert!(stale(admit_login(&mut scan, &live(87)?, 87)));
        assert_eq!(scan.account_service.live_login_keys.len(), 1);

        let transaction_id = TransactionId::from_bytes([88; 16]);
        let reservation = |digest: u8| {
            login_row(
                &LoginIndexStoredKey::new(1, LoginIndexDigest::from_storage_key([digest; 32]))?,
                LoginIndexValueKind::CreationReservation {
                    transaction_id,
                    expires_at: 911,
                },
            )
        };
        let reserved = reservation(89)?;
        admit_login(&mut scan, &reserved, 89)?;
        assert!(
            scan.account_service
                .login_reservations
                .get(&transaction_id)
                .is_some_and(|login| login.key == reserved.0 && login.expires_at == 911)
        );
        assert!(stale(admit_login(&mut scan, &reservation(90)?, 90)));
        assert_eq!(scan.account_service.login_reservations.len(), 1);

        let deleted_account_id = account_id(91);
        let tombstone = |digest: u8| {
            login_row(
                &LoginIndexStoredKey::new(1, LoginIndexDigest::from_storage_key([digest; 32]))?,
                LoginIndexValueKind::DeletionTombstone {
                    deleted_account_id,
                    expires_at: 2_592_100,
                },
            )
        };
        admit_login(&mut scan, &tombstone(92)?, 92)?;
        assert!(stale(admit_login(&mut scan, &tombstone(93)?, 93)));
        assert_eq!(scan.account_service.login_deletion_tombstones.len(), 1);
        assert_eq!(scan.account_service.login_entry_counts.get(&1), Some(&6));
        Ok(())
    }

    #[test]
    fn auth_transaction_rows_require_zero_generation_and_one_row_per_key()
    -> Result<(), RuntimeError> {
        let keys = keys()?;
        let account = account(None)?;
        let account_key = KeyDeriver::account_key(account.account_id)?;
        let transaction_id = TransactionId::from_bytes([94; 16]);
        let key = transaction_key(transaction_id)?;
        let grant = authentication_grant_value(
            transaction_id,
            &account,
            &account_key,
            account.session_generation.get(),
        )?;
        let mut scan = scan_with_account(&keys, &account, 94)?;
        let generation_one = PersistentRecordValue::new(
            TableId::AuthTransaction,
            AUTHENTICATION_GRANT_KIND,
            1,
            1,
            grant.expires_at(),
            grant.references().to_vec(),
            grant.body().to_vec(),
        )?;
        assert!(stale(admit_sealed(
            &mut scan,
            &keys,
            TableId::AuthTransaction,
            &key,
            &generation_one,
            95,
        )));
        admit_sealed(&mut scan, &keys, TableId::AuthTransaction, &key, &grant, 96)?;
        assert!(stale(admit_sealed(
            &mut scan,
            &keys,
            TableId::AuthTransaction,
            &key,
            &grant,
            97,
        )));
        assert_eq!(scan.account_service.transactions.len(), 1);
        Ok(())
    }

    #[test]
    fn authentication_transactions_bind_key_expiry_and_carry_no_references()
    -> Result<(), RuntimeError> {
        let keys = keys()?;
        let transaction_id = TransactionId::from_bytes([98; 16]);
        let key = transaction_key(transaction_id)?;
        let account_reference =
            RecordReference::new(TableId::Account, KeyDeriver::account_key(account_id(1))?)?;
        let authentication = |body_transaction_id: TransactionId,
                              value_expires_at: u64,
                              references: Vec<RecordReference>| {
            transaction_value(
                AUTHENTICATION_TRANSACTION_KIND,
                value_expires_at,
                references,
                authentication_body(body_transaction_id, 912)?,
            )
        };

        let mut valid = Scan::default();
        admit_sealed(
            &mut valid,
            &keys,
            TableId::AuthTransaction,
            &key,
            &authentication(transaction_id, 912, Vec::new())?,
            98,
        )?;
        assert!(matches!(
            valid.account_service.transactions.get(&transaction_id),
            Some(RecoveredTransaction::Authentication)
        ));

        for value in [
            authentication(TransactionId::from_bytes([99; 16]), 912, Vec::new())?,
            authentication(transaction_id, 913, Vec::new())?,
            authentication(transaction_id, 912, vec![account_reference])?,
        ] {
            let mut scan = Scan::default();
            assert!(stale(admit_sealed(
                &mut scan,
                &keys,
                TableId::AuthTransaction,
                &key,
                &value,
                99,
            )));
            assert!(scan.account_service.transactions.is_empty());
        }
        Ok(())
    }

    #[test]
    fn creation_transactions_bind_key_expiry_and_invitation_reference() -> Result<(), RuntimeError>
    {
        let keys = keys()?;
        let transaction_id = TransactionId::from_bytes([100; 16]);
        let key = transaction_key(transaction_id)?;
        let invitation_id = InviteId::from_bytes([101; 16]);
        let invitation_reference = RecordReference::new(
            TableId::RegistrationInvite,
            StoredKey::new(invitation_id.as_bytes().to_vec())?,
        )?;
        let creation = |body_transaction_id: TransactionId,
                        value_expires_at: u64,
                        admitted: bool,
                        invitation: Option<InviteId>,
                        references: Vec<RecordReference>| {
            transaction_value(
                CREATION_TRANSACTION_KIND,
                value_expires_at,
                references,
                creation_body(body_transaction_id, 914, admitted, invitation)?,
            )
        };

        let mut admitted = Scan::default();
        admit_sealed(
            &mut admitted,
            &keys,
            TableId::AuthTransaction,
            &key,
            &creation(
                transaction_id,
                914,
                true,
                Some(invitation_id),
                vec![invitation_reference.clone()],
            )?,
            100,
        )?;
        assert!(matches!(
            admitted.account_service.transactions.get(&transaction_id),
            Some(RecoveredTransaction::Creation {
                expires_at: 914,
                reservation_digest: Some(_),
                reservation_invitation: Some(reserved),
            }) if *reserved == invitation_id
        ));

        let mut rejected = Scan::default();
        admit_sealed(
            &mut rejected,
            &keys,
            TableId::AuthTransaction,
            &key,
            &creation(transaction_id, 914, false, Some(invitation_id), Vec::new())?,
            101,
        )?;
        assert!(matches!(
            rejected.account_service.transactions.get(&transaction_id),
            Some(RecoveredTransaction::Creation {
                reservation_digest: None,
                reservation_invitation: None,
                ..
            })
        ));

        let account_reference =
            RecordReference::new(TableId::Account, KeyDeriver::account_key(account_id(1))?)?;
        let foreign_invitation =
            RecordReference::new(TableId::RegistrationInvite, StoredKey::new(vec![102; 16])?)?;
        for value in [
            creation(
                TransactionId::from_bytes([103; 16]),
                914,
                true,
                None,
                Vec::new(),
            )?,
            creation(transaction_id, 915, true, None, Vec::new())?,
            creation(transaction_id, 914, true, Some(invitation_id), Vec::new())?,
            creation(
                transaction_id,
                914,
                true,
                Some(invitation_id),
                vec![account_reference],
            )?,
            creation(
                transaction_id,
                914,
                true,
                Some(invitation_id),
                vec![foreign_invitation],
            )?,
            creation(transaction_id, 914, true, None, vec![invitation_reference])?,
        ] {
            let mut scan = Scan::default();
            assert!(stale(admit_sealed(
                &mut scan,
                &keys,
                TableId::AuthTransaction,
                &key,
                &value,
                103,
            )));
            assert!(scan.account_service.transactions.is_empty());
        }
        Ok(())
    }

    #[test]
    fn credential_changes_bind_key_expiry_and_reserved_account_reference()
    -> Result<(), RuntimeError> {
        let keys = keys()?;
        let account = account(None)?;
        let account_key = KeyDeriver::account_key(account.account_id)?;
        let account_reference = RecordReference::new(TableId::Account, account_key)?;
        let transaction_id = TransactionId::from_bytes([104; 16]);
        let key = transaction_key(transaction_id)?;
        let change = |body_transaction_id: TransactionId,
                      value_expires_at: u64,
                      admitted: bool,
                      references: Vec<RecordReference>| {
            transaction_value(
                CREDENTIAL_CHANGE_TRANSACTION_KIND,
                value_expires_at,
                references,
                credential_change_body(body_transaction_id, 916, admitted, &account)?,
            )
        };

        let mut admitted = scan_with_account(&keys, &account, 104)?;
        admit_sealed(
            &mut admitted,
            &keys,
            TableId::AuthTransaction,
            &key,
            &change(transaction_id, 916, true, vec![account_reference.clone()])?,
            105,
        )?;
        assert!(matches!(
            admitted.account_service.transactions.get(&transaction_id),
            Some(RecoveredTransaction::CredentialChange)
        ));

        let mut rejected = Scan::default();
        admit_sealed(
            &mut rejected,
            &keys,
            TableId::AuthTransaction,
            &key,
            &change(transaction_id, 916, false, Vec::new())?,
            106,
        )?;
        assert!(matches!(
            rejected.account_service.transactions.get(&transaction_id),
            Some(RecoveredTransaction::CredentialChange)
        ));

        let other_reference =
            RecordReference::new(TableId::Account, KeyDeriver::account_key(account_id(2))?)?;
        let channel_reference = RecordReference::new(
            TableId::Channel,
            KeyDeriver::channel_key(ChannelInstanceId::from_bytes([107; 16]))?,
        )?;
        for value in [
            change(
                TransactionId::from_bytes([108; 16]),
                916,
                true,
                vec![account_reference.clone()],
            )?,
            change(transaction_id, 917, true, vec![account_reference.clone()])?,
            change(transaction_id, 916, true, vec![channel_reference])?,
            change(transaction_id, 916, true, vec![other_reference])?,
            change(transaction_id, 916, true, Vec::new())?,
            change(transaction_id, 916, false, vec![account_reference])?,
        ] {
            let mut scan = scan_with_account(&keys, &account, 108)?;
            assert!(stale(admit_sealed(
                &mut scan,
                &keys,
                TableId::AuthTransaction,
                &key,
                &value,
                109,
            )));
            assert!(scan.account_service.transactions.is_empty());
        }
        Ok(())
    }

    #[test]
    fn authentication_grants_bind_key_expiry_and_referenced_account() -> Result<(), RuntimeError> {
        let keys = keys()?;
        let account = account(None)?;
        let account_key = KeyDeriver::account_key(account.account_id)?;
        let transaction_id = TransactionId::from_bytes([110; 16]);
        let key = transaction_key(transaction_id)?;
        let grant = authentication_grant_value(transaction_id, &account, &account_key, 1)?;

        let foreign = authentication_grant_value(
            TransactionId::from_bytes([111; 16]),
            &account,
            &account_key,
            1,
        )?;
        let mut foreign_scan = scan_with_account(&keys, &account, 110)?;
        assert!(stale(admit_sealed(
            &mut foreign_scan,
            &keys,
            TableId::AuthTransaction,
            &key,
            &foreign,
            111,
        )));

        let wrong_expiry = PersistentRecordValue::new(
            TableId::AuthTransaction,
            AUTHENTICATION_GRANT_KIND,
            1,
            0,
            Some(931),
            grant.references().to_vec(),
            grant.body().to_vec(),
        )?;
        let mut expiry_scan = scan_with_account(&keys, &account, 112)?;
        assert!(stale(admit_sealed(
            &mut expiry_scan,
            &keys,
            TableId::AuthTransaction,
            &key,
            &wrong_expiry,
            113,
        )));

        let other = account_seeded(2)?;
        let other_key = KeyDeriver::account_key(other.account_id)?;
        let mut other_scan = scan_with_account(&keys, &account, 114)?;
        admit_sealed(
            &mut other_scan,
            &keys,
            TableId::Account,
            &other_key,
            &account_value(&other)?,
            115,
        )?;
        let misbound = authentication_grant_value(transaction_id, &account, &other_key, 1)?;
        assert!(stale(admit_sealed(
            &mut other_scan,
            &keys,
            TableId::AuthTransaction,
            &key,
            &misbound,
            116,
        )));
        assert!(other_scan.account_service.transactions.is_empty());
        Ok(())
    }

    #[test]
    fn registration_invite_rows_are_validated_by_kind() -> Result<(), RuntimeError> {
        let keys = keys()?;
        let invitation_id = InviteId::from_bytes([117; 16]);
        let invitation_key = StoredKey::new(invitation_id.as_bytes().to_vec())?;
        let transaction_id = TransactionId::from_bytes([118; 16]);
        let transaction_reference =
            RecordReference::new(TableId::AuthTransaction, transaction_key(transaction_id)?)?;
        let account_reference =
            RecordReference::new(TableId::Account, KeyDeriver::account_key(account_id(119))?)?;
        let invite =
            |record_kind: u16, generation: u64, references: Vec<RecordReference>, body: Vec<u8>| {
                PersistentRecordValue::new(
                    TableId::RegistrationInvite,
                    record_kind,
                    1,
                    generation,
                    Some(918),
                    references,
                    body,
                )
            };

        let mut reserved = Scan::default();
        admit_sealed(
            &mut reserved,
            &keys,
            TableId::RegistrationInvite,
            &invitation_key,
            &invite(
                INVITATION_RESERVATION_KIND,
                0,
                vec![transaction_reference.clone()],
                Vec::new(),
            )?,
            117,
        )?;
        assert!(
            reserved
                .account_service
                .invitation_reservations
                .get(&transaction_id)
                .is_some_and(|reservation| reservation.invitation_id == invitation_id
                    && reservation.expires_at == 918)
        );
        let second_key = StoredKey::new(InviteId::from_bytes([120; 16]).as_bytes().to_vec())?;
        assert!(stale(admit_sealed(
            &mut reserved,
            &keys,
            TableId::RegistrationInvite,
            &second_key,
            &invite(
                INVITATION_RESERVATION_KIND,
                0,
                vec![transaction_reference.clone()],
                Vec::new(),
            )?,
            118,
        )));

        for value in [
            invite(
                INVITATION_RESERVATION_KIND,
                1,
                vec![transaction_reference.clone()],
                Vec::new(),
            )?,
            invite(
                INVITATION_RESERVATION_KIND,
                0,
                vec![transaction_reference.clone()],
                vec![1],
            )?,
            invite(
                INVITATION_RESERVATION_KIND,
                0,
                vec![account_reference.clone()],
                Vec::new(),
            )?,
            invite(
                INVITATION_TOMBSTONE_KIND,
                0,
                vec![transaction_reference],
                Vec::new(),
            )?,
            invite(
                INVITATION_TOMBSTONE_KIND,
                0,
                vec![account_reference],
                Vec::new(),
            )?,
            invite(INVITATION_TOMBSTONE_KIND, 0, Vec::new(), Vec::new())?,
        ] {
            let mut scan = Scan::default();
            assert!(stale(admit_sealed(
                &mut scan,
                &keys,
                TableId::RegistrationInvite,
                &invitation_key,
                &value,
                119,
            )));
            assert!(scan.account_service.invitation_reservations.is_empty());
        }
        Ok(())
    }

    #[test]
    fn fake_opaque_record_requires_bare_metadata_and_one_row() -> Result<(), RuntimeError> {
        let keys = keys()?;
        let profile = OpaqueProfile::generate(NetworkId::from_bytes([1; 32]))
            .map_err(|_| RuntimeError::InvalidValue)?;
        let fake_key = StoredKey::new(OPAQUE_FAKE_RECORD_KEY.to_vec())?;
        let fake = |generation: u64, expires_at: Option<u64>, references: Vec<RecordReference>| {
            PersistentRecordValue::new(
                TableId::OpaqueRecord,
                LIVE_RECORD_KIND,
                1,
                generation,
                expires_at,
                references,
                profile.expose_fake_record_for_persistence().to_vec(),
            )
        };
        let account_reference =
            RecordReference::new(TableId::Account, KeyDeriver::account_key(account_id(1))?)?;
        for value in [
            fake(1, None, Vec::new())?,
            fake(0, Some(919), Vec::new())?,
            fake(0, None, vec![account_reference])?,
        ] {
            let mut scan = Scan::default();
            assert!(stale(admit_sealed(
                &mut scan,
                &keys,
                TableId::OpaqueRecord,
                &fake_key,
                &value,
                121,
            )));
            assert!(scan.account_service.fake_opaque_record.is_none());
        }

        let mut duplicate = Scan::default();
        admit_sealed(
            &mut duplicate,
            &keys,
            TableId::OpaqueRecord,
            &fake_key,
            &fake(0, None, Vec::new())?,
            122,
        )?;
        assert!(stale(admit_sealed(
            &mut duplicate,
            &keys,
            TableId::OpaqueRecord,
            &fake_key,
            &fake(0, None, Vec::new())?,
            123,
        )));
        assert!(duplicate.account_service.fake_opaque_record.is_some());
        Ok(())
    }

    #[test]
    fn live_opaque_records_bind_generation_reference_and_one_row() -> Result<(), RuntimeError> {
        let keys = keys()?;
        let account = account(None)?;
        let account_key = KeyDeriver::account_key(account.account_id)?;
        let profile = OpaqueProfile::generate(NetworkId::from_bytes([1; 32]))
            .map_err(|_| RuntimeError::InvalidValue)?;
        let opaque = |generation: u64, expires_at: Option<u64>, reference: RecordReference| {
            PersistentRecordValue::new(
                TableId::OpaqueRecord,
                LIVE_RECORD_KIND,
                1,
                generation,
                expires_at,
                vec![reference],
                profile.expose_fake_record_for_persistence().to_vec(),
            )
        };
        let self_reference = RecordReference::new(TableId::Account, account_key.clone())?;
        let other_reference =
            RecordReference::new(TableId::Account, KeyDeriver::account_key(account_id(2))?)?;
        let channel_reference = RecordReference::new(
            TableId::Channel,
            KeyDeriver::channel_key(ChannelInstanceId::from_bytes([124; 16]))?,
        )?;
        let generation = account.session_generation.get();
        for value in [
            opaque(2, None, self_reference.clone())?,
            opaque(generation, Some(920), self_reference.clone())?,
            opaque(generation, None, channel_reference)?,
            opaque(generation, None, other_reference)?,
        ] {
            let mut scan = scan_with_account(&keys, &account, 124)?;
            assert!(stale(admit_sealed(
                &mut scan,
                &keys,
                TableId::OpaqueRecord,
                &account_key,
                &value,
                125,
            )));
            assert!(scan.account_service.opaque_accounts.is_empty());
        }

        let mut duplicate = scan_with_account(&keys, &account, 126)?;
        admit_sealed(
            &mut duplicate,
            &keys,
            TableId::OpaqueRecord,
            &account_key,
            &opaque(generation, None, self_reference.clone())?,
            127,
        )?;
        assert!(
            duplicate
                .account_service
                .opaque_accounts
                .contains(&account.account_id)
        );
        assert!(stale(admit_sealed(
            &mut duplicate,
            &keys,
            TableId::OpaqueRecord,
            &account_key,
            &opaque(generation, None, self_reference)?,
            128,
        )));
        Ok(())
    }

    #[test]
    fn recovery_restores_the_unchanged_opaque_row_with_the_advanced_account()
    -> Result<(), RuntimeError> {
        let keys = keys()?;
        let original = account(None)?;
        let account_key = KeyDeriver::account_key(original.account_id)?;
        let profile = OpaqueProfile::generate(NetworkId::from_bytes([1; 32]))
            .map_err(|_| RuntimeError::InvalidValue)?;
        let opaque = PersistentRecordValue::new(
            TableId::OpaqueRecord,
            LIVE_RECORD_KIND,
            original.revision.get(),
            original.session_generation.get(),
            None,
            vec![RecordReference::new(TableId::Account, account_key.clone())?],
            profile.expose_fake_record_for_persistence().to_vec(),
        )?;
        let original_opaque = opaque.encode()?;
        let recovered = restored_credential_test_record(
            TableId::Account,
            &account_key,
            &account_value(&original)?,
            agenc_ircd_storage::StorageConstructionAction::RestoreAccount,
        )?;
        let opaque = restored_credential_test_record(
            TableId::OpaqueRecord,
            &account_key,
            &opaque,
            agenc_ircd_storage::StorageConstructionAction::RestoreCopy,
        )?;
        assert_eq!(recovered.revision(), original.revision.get() + 1);
        assert_eq!(
            recovered.generation(),
            original.session_generation.get() + 1
        );
        let mut scan = Scan::default();
        admit_sealed(
            &mut scan,
            &keys,
            TableId::Account,
            &account_key,
            &recovered,
            161,
        )?;
        admit_sealed(
            &mut scan,
            &keys,
            TableId::OpaqueRecord,
            &account_key,
            &opaque,
            162,
        )?;
        assert!(
            scan.account_service
                .opaque_accounts
                .contains(&original.account_id)
        );
        assert_eq!(opaque.encode()?, original_opaque);
        Ok(())
    }

    #[test]
    fn recovery_discards_registered_channel_sessions_before_domain_reconstruction()
    -> Result<(), RuntimeError> {
        let owner = account_seeded(171)?;
        let user_id = agenc_ircd_types::UserId::from_bytes([172; 16]);
        let mut original = channel(171, "#restore-memberships")?;
        original.content_policy = ContentPolicy::E2eeBound;
        original
            .memberships
            .push(agenc_ircd_domain::DurableMembership {
                user_id,
                account_id: Some(owner.account_id),
                session_role: Role::Member,
                effective_role: Role::Owner,
                membership_revision: original.revision,
                joined_at: original.created_at,
            });
        original.invites.push(agenc_ircd_domain::DurableInvite {
            invite_id: InviteId::from_bytes([173; 16]),
            target: Principal::Account(owner.account_id),
            inviter: user_id,
            creation_revision: original.revision,
            expires_at_utc: UtcSecond::from_unix_seconds(600),
        });
        original.e2ee_removal_pending.push(user_id);
        let key = KeyDeriver::channel_key(original.channel_id)?;
        let recovered = restored_credential_test_record(
            TableId::Channel,
            &key,
            &channel_value(&original, original.revision.get())?,
            agenc_ircd_storage::StorageConstructionAction::RestoreChannel,
        )?;
        let channel = ChannelRecordBody::decode(recovered.body())?;
        assert_eq!(channel.revision.get(), original.revision.get() + 1);
        assert_eq!(channel.role_grants, original.role_grants);
        let restored = DomainState::restore_authoritative(
            Revision::new(0).map_err(|_| RuntimeError::InvalidValue)?,
            vec![owner],
            Vec::new(),
            vec![channel],
            Vec::new(),
            MonotonicTick::from_ticks(0),
            UtcSecond::from_unix_seconds(1),
        )
        .map_err(|_| RuntimeError::InvalidValue)?;
        let channel = restored
            .durable_channel(original.channel_id)
            .ok_or(RuntimeError::InvalidValue)?;
        assert!(channel.memberships.is_empty());
        assert!(channel.invites.is_empty());
        assert!(channel.e2ee_removal_pending.is_empty());
        Ok(())
    }

    fn restored_credential_test_record(
        table: TableId,
        key: &StoredKey,
        value: &PersistentRecordValue,
        action: agenc_ircd_storage::StorageConstructionAction,
    ) -> Result<PersistentRecordValue, RuntimeError> {
        use agenc_ircd_storage::{
            ConstructionSourceRecord, ConstructionTransformer, RecoveryTransformV1, SealedRecord,
            StorageConstructionKind, StorageConstructionPlanEntry, StorageConstructionSource,
            StorageConstructionSourceKind,
        };
        let sealed = seal(table, key, value, 163)?;
        let source = StorageConstructionSource::new(
            StorageConstructionSourceKind::BackupRecord,
            table,
            key.clone(),
            1,
            SealedRecord::decode(&sealed)?.record_id()?,
            1,
        )?;
        let opened = ConstructionSourceRecord::open(
            &source,
            &sealed,
            &StorageMasterKey::from_bytes(MASTER_BYTES),
            binding(),
            1,
        )?;
        let entry = StorageConstructionPlanEntry::new(
            StorageConstructionKind::Restore,
            vec![source],
            table,
            key.clone(),
            1,
            action,
            0,
        )?;
        let restored = RecoveryTransformV1::new(
            agenc_ircd_types::RecoveryEpoch::from_bytes([164; 16]),
            agenc_ircd_crypto::StorageDigest::from_bytes([165; 32]),
        )
        .transform(StorageConstructionKind::Restore, &entry, &[opened])?;
        Ok(PersistentRecordValue::decode(table, &restored)?)
    }

    #[test]
    fn live_accounts_bind_key_generation_and_one_row() -> Result<(), RuntimeError> {
        let keys = keys()?;
        let account = account(None)?;
        let account_key = KeyDeriver::account_key(account.account_id)?;

        let foreign_key = KeyDeriver::account_key(account_id(2))?;
        let mut foreign = Scan::default();
        assert!(stale(admit_sealed(
            &mut foreign,
            &keys,
            TableId::Account,
            &foreign_key,
            &account_value(&account)?,
            129,
        )));
        assert!(foreign.accounts.is_empty());

        let wrong_generation = PersistentRecordValue::new(
            TableId::Account,
            LIVE_RECORD_KIND,
            account.revision.get(),
            2,
            None,
            Vec::new(),
            AccountRecordBody::encode(&account)?,
        )?;
        let mut generation = Scan::default();
        assert!(stale(admit_sealed(
            &mut generation,
            &keys,
            TableId::Account,
            &account_key,
            &wrong_generation,
            130,
        )));
        assert!(generation.accounts.is_empty());

        let mut duplicate = scan_with_account(&keys, &account, 131)?;
        assert!(stale(admit_sealed(
            &mut duplicate,
            &keys,
            TableId::Account,
            &account_key,
            &account_value(&account)?,
            132,
        )));
        assert_eq!(duplicate.accounts.len(), 1);
        Ok(())
    }

    #[test]
    fn live_channels_bind_key_revision_and_one_row() -> Result<(), RuntimeError> {
        let keys = keys()?;
        let channel = channel(133, "#fixture")?;
        let channel_key = KeyDeriver::channel_key(channel.channel_id)?;

        let mut valid = Scan::default();
        admit_sealed(
            &mut valid,
            &keys,
            TableId::Channel,
            &channel_key,
            &channel_value(&channel, 1)?,
            133,
        )?;
        assert!(valid.channel_keys.get(&channel_key) == Some(&channel.channel_id));
        assert!(stale(admit_sealed(
            &mut valid,
            &keys,
            TableId::Channel,
            &channel_key,
            &channel_value(&channel, 1)?,
            134,
        )));
        assert_eq!(valid.channels.len(), 1);

        let foreign_key = KeyDeriver::channel_key(ChannelInstanceId::from_bytes([135; 16]))?;
        let mut foreign = Scan::default();
        assert!(stale(admit_sealed(
            &mut foreign,
            &keys,
            TableId::Channel,
            &foreign_key,
            &channel_value(&channel, 1)?,
            135,
        )));
        assert!(foreign.channels.is_empty());

        let mut revision = Scan::default();
        assert!(stale(admit_sealed(
            &mut revision,
            &keys,
            TableId::Channel,
            &channel_key,
            &channel_value(&channel, 2)?,
            136,
        )));
        assert!(revision.channels.is_empty());
        Ok(())
    }

    #[test]
    fn live_sessions_bind_identity_counters_and_one_row() -> Result<(), RuntimeError> {
        let keys = keys()?;
        let session = session(Vec::new())?;
        let session_key = KeyDeriver::session_key(session.session_id)?;
        let body = SessionRecordBody::encode(&session)?;
        let value = |generation: u64, revision: u64, expires_at: Option<u64>| {
            PersistentRecordValue::new(
                TableId::Session,
                LIVE_RECORD_KIND,
                revision,
                generation,
                expires_at,
                Vec::new(),
                body.clone(),
            )
        };

        let foreign_key = KeyDeriver::session_key(SessionId::from_bytes([137; 16]))?;
        let mut foreign = Scan::default();
        assert!(stale(admit_sealed(
            &mut foreign,
            &keys,
            TableId::Session,
            &foreign_key,
            &value(1, 2, None)?,
            137,
        )));
        assert!(foreign.sessions.is_empty());

        for row in [
            value(2, 2, None)?,
            value(1, 3, None)?,
            value(1, 2, Some(921))?,
        ] {
            let mut scan = Scan::default();
            assert!(stale(admit_sealed(
                &mut scan,
                &keys,
                TableId::Session,
                &session_key,
                &row,
                138,
            )));
            assert!(scan.sessions.is_empty());
        }

        let mut duplicate = Scan::default();
        admit_sealed(
            &mut duplicate,
            &keys,
            TableId::Session,
            &session_key,
            &value(1, 2, None)?,
            139,
        )?;
        assert!(stale(admit_sealed(
            &mut duplicate,
            &keys,
            TableId::Session,
            &session_key,
            &value(1, 2, None)?,
            140,
        )));
        assert_eq!(duplicate.sessions.len(), 1);
        Ok(())
    }

    #[test]
    fn session_account_references_must_name_the_live_account_exactly() -> Result<(), RuntimeError> {
        let keys = keys()?;
        let account = account(None)?;
        let account_key = KeyDeriver::account_key(account.account_id)?;
        let mut linked = session(Vec::new())?;
        linked.account_id = Some(account.account_id);
        linked.account_session_generation = account.session_generation;
        let session_key = KeyDeriver::session_key(linked.session_id)?;
        let account_reference = RecordReference::new(TableId::Account, account_key)?;

        let mut bound = scan_with_account(&keys, &account, 141)?;
        admit_sealed(
            &mut bound,
            &keys,
            TableId::Session,
            &session_key,
            &session_value(&linked, vec![account_reference.clone()])?,
            142,
        )?;
        assert_eq!(bound.sessions.len(), 1);

        let channel_id = ChannelInstanceId::from_bytes([143; 16]);
        let channel_key = KeyDeriver::channel_key(channel_id)?;
        let channel_reference = RecordReference::new(TableId::Channel, channel_key.clone())?;
        let other_reference =
            RecordReference::new(TableId::Account, KeyDeriver::account_key(account_id(2))?)?;
        for references in [
            Vec::new(),
            vec![channel_reference.clone()],
            vec![other_reference],
        ] {
            let mut scan = scan_with_account(&keys, &account, 144)?;
            assert!(stale(admit_sealed(
                &mut scan,
                &keys,
                TableId::Session,
                &session_key,
                &session_value(&linked, references)?,
                145,
            )));
            assert!(scan.sessions.is_empty());
        }

        let joined = session(vec![channel_id])?;
        let joined_key = KeyDeriver::session_key(joined.session_id)?;
        let mut wrong_table = Scan::default();
        wrong_table
            .channel_keys
            .insert(channel_key.clone(), channel_id);
        assert!(stale(admit_sealed(
            &mut wrong_table,
            &keys,
            TableId::Session,
            &joined_key,
            &session_value(&joined, vec![account_reference.clone()])?,
            146,
        )));

        let unknown_reference = RecordReference::new(
            TableId::Channel,
            KeyDeriver::channel_key(ChannelInstanceId::from_bytes([147; 16]))?,
        )?;
        let mut unknown_channel = Scan::default();
        unknown_channel.channel_keys.insert(channel_key, channel_id);
        assert!(stale(admit_sealed(
            &mut unknown_channel,
            &keys,
            TableId::Session,
            &joined_key,
            &session_value(&joined, vec![unknown_reference])?,
            147,
        )));

        let guest = session(Vec::new())?;
        let mut stray = Scan::default();
        assert!(stale(admit_sealed(
            &mut stray,
            &keys,
            TableId::Session,
            &session_key,
            &session_value(&guest, vec![account_reference])?,
            148,
        )));
        assert!(stray.sessions.is_empty());
        Ok(())
    }

    #[test]
    fn sanctions_bind_scope_key_revision_and_expiry() -> Result<(), RuntimeError> {
        let keys = keys()?;
        let channel_id = ChannelInstanceId::from_bytes([149; 16]);
        let scoped = sanction(Some(channel_id), Some(10))?;
        let scoped_key =
            KeyDeriver::sanction_key(Some(channel_id), [150; SANCTION_KEY_RANDOM_BYTES])?;
        let mut valid = Scan::default();
        admit_sealed(
            &mut valid,
            &keys,
            TableId::Sanction,
            &scoped_key,
            &sanction_value(&scoped, 1, Some(10))?,
            149,
        )?;
        assert_eq!(valid.sanctions.len(), 1);

        let mut long_key_bytes = scoped_key.as_bytes().to_vec();
        long_key_bytes.push(0);
        let long_key = StoredKey::new(long_key_bytes)?;
        let mut long = Scan::default();
        assert!(stale(admit_sealed(
            &mut long,
            &keys,
            TableId::Sanction,
            &long_key,
            &sanction_value(&scoped, 1, Some(10))?,
            150,
        )));
        assert!(long.sanctions.is_empty());

        let network = sanction(None, Some(10))?;
        let network_key = KeyDeriver::sanction_key(None, [151; SANCTION_KEY_RANDOM_BYTES])?;
        let mut revision = Scan::default();
        assert!(stale(admit_sealed(
            &mut revision,
            &keys,
            TableId::Sanction,
            &network_key,
            &sanction_value(&network, 2, Some(10))?,
            151,
        )));
        let mut expiry = Scan::default();
        assert!(stale(admit_sealed(
            &mut expiry,
            &keys,
            TableId::Sanction,
            &network_key,
            &sanction_value(&network, 1, None)?,
            152,
        )));
        assert!(expiry.sanctions.is_empty());
        Ok(())
    }

    #[test]
    fn nickname_rows_must_match_account_reservations_exactly() -> Result<(), RuntimeError> {
        let keys = keys()?;
        let nickname = NicknameValue::parse("Alice").map_err(|_| RuntimeError::InvalidValue)?;
        let nickname_key = keys.nickname_key(&nickname)?;
        let reserving = account(Some(nickname.clone()))?;
        let account_key = KeyDeriver::account_key(reserving.account_id)?;

        let mut missing_row = scan_with_account(&keys, &reserving, 153)?;
        assert!(stale(missing_row.bind_nicknames(&keys)));

        let unreferenced = PersistentRecordValue::new(
            TableId::NicknameReservation,
            LIVE_RECORD_KIND,
            1,
            0,
            None,
            Vec::new(),
            nickname.presentation().as_bytes().to_vec(),
        )?;
        let mut no_reference = scan_with_account(&keys, &reserving, 154)?;
        admit_sealed(
            &mut no_reference,
            &keys,
            TableId::NicknameReservation,
            &nickname_key,
            &unreferenced,
            155,
        )?;
        assert!(stale(no_reference.bind_nicknames(&keys)));

        let unreserved = account(None)?;
        let mut not_reserved = scan_with_account(&keys, &unreserved, 156)?;
        admit_sealed(
            &mut not_reserved,
            &keys,
            TableId::NicknameReservation,
            &nickname_key,
            &reservation_value(&account_key, &nickname)?,
            157,
        )?;
        assert!(stale(not_reserved.bind_nicknames(&keys)));

        let mut duplicate = scan_with_account(&keys, &reserving, 158)?;
        admit_sealed(
            &mut duplicate,
            &keys,
            TableId::NicknameReservation,
            &nickname_key,
            &reservation_value(&account_key, &nickname)?,
            159,
        )?;
        admit_sealed(
            &mut duplicate,
            &keys,
            TableId::NicknameReservation,
            &nickname_key,
            &reservation_value(&account_key, &nickname)?,
            160,
        )?;
        assert!(stale(duplicate.bind_nicknames(&keys)));
        Ok(())
    }

    #[test]
    fn channel_name_rows_must_match_live_channels_exactly() -> Result<(), RuntimeError> {
        let keys = keys()?;
        let channel = channel(161, "#fixture")?;
        let channel_key = KeyDeriver::channel_key(channel.channel_id)?;
        let name_key = keys.channel_name_key(&channel.name)?;
        let typed_body = ChannelNameRecordBody::encode(channel.channel_id, &channel.name)?;
        let scan_with_channel = |nonce: u8| {
            let mut scan = Scan::default();
            admit_sealed(
                &mut scan,
                &keys,
                TableId::Channel,
                &channel_key,
                &channel_value(&channel, 1)?,
                nonce,
            )?;
            Ok::<Scan, RuntimeError>(scan)
        };

        let mut typed = scan_with_channel(161)?;
        admit_sealed(
            &mut typed,
            &keys,
            TableId::ChannelName,
            &name_key,
            &channel_name_row(&channel_key, typed_body.clone())?,
            162,
        )?;
        typed.bind_channel_names(&keys)?;
        assert!(typed.index.channel_name_row(channel.channel_id) == Some(&name_key));

        assert!(matches!(
            channel_name_row(
                &channel_key,
                channel.name.presentation().as_bytes().to_vec()
            ),
            Err(RuntimeError::Storage(StorageError::UnsupportedVersion))
        ));

        let mut unnamed = scan_with_channel(165)?;
        assert!(stale(unnamed.bind_channel_names(&keys)));

        let other_name =
            ChannelNameValue::parse("#other").map_err(|_| RuntimeError::InvalidValue)?;
        let other_key = keys.channel_name_key(&other_name)?;
        let mut wrong_key = scan_with_channel(166)?;
        admit_sealed(
            &mut wrong_key,
            &keys,
            TableId::ChannelName,
            &other_key,
            &channel_name_row(&channel_key, typed_body.clone())?,
            167,
        )?;
        assert!(stale(wrong_key.bind_channel_names(&keys)));

        let unreferenced = PersistentRecordValue::new(
            TableId::ChannelName,
            LIVE_RECORD_KIND,
            1,
            0,
            None,
            Vec::new(),
            typed_body.clone(),
        )?;
        let mut no_reference = scan_with_channel(168)?;
        admit_sealed(
            &mut no_reference,
            &keys,
            TableId::ChannelName,
            &name_key,
            &unreferenced,
            169,
        )?;
        assert!(stale(no_reference.bind_channel_names(&keys)));

        let misbound_body =
            ChannelNameRecordBody::encode(ChannelInstanceId::from_bytes([170; 16]), &channel.name)?;
        let mut misbound = scan_with_channel(170)?;
        admit_sealed(
            &mut misbound,
            &keys,
            TableId::ChannelName,
            &name_key,
            &channel_name_row(&channel_key, misbound_body)?,
            171,
        )?;
        assert!(stale(misbound.bind_channel_names(&keys)));

        let renamed_body = ChannelNameRecordBody::encode(channel.channel_id, &other_name)?;
        let mut renamed = scan_with_channel(172)?;
        admit_sealed(
            &mut renamed,
            &keys,
            TableId::ChannelName,
            &other_key,
            &channel_name_row(&channel_key, renamed_body)?,
            173,
        )?;
        assert!(stale(renamed.bind_channel_names(&keys)));

        let mut doubled = scan_with_channel(174)?;
        admit_sealed(
            &mut doubled,
            &keys,
            TableId::ChannelName,
            &name_key,
            &channel_name_row(&channel_key, typed_body.clone())?,
            175,
        )?;
        admit_sealed(
            &mut doubled,
            &keys,
            TableId::ChannelName,
            &name_key,
            &channel_name_row(&channel_key, typed_body)?,
            176,
        )?;
        assert!(stale(doubled.bind_channel_names(&keys)));
        Ok(())
    }
}
