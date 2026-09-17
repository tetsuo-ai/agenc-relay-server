//! Durable ownership accounts of retained objects (companion 15 and 16).
//!
//! Every table-22 object is owned by the table-23 rows that name it: the
//! sequencer, candidate, proof, policy and membership rows of a conversation,
//! the route and reservation rows, the directory rows of an account, key
//! packages and claims, attach challenges, mailbox items and tokens, replay
//! rows, and the outbox and barrier rows of delivered events. The owning set
//! is derived from those rows, never declared separately, so one derivation
//! serves live batches and startup reconstruction alike. Each object's
//! `owner/v1/` row persists what the rows cannot say: the retention class the
//! owners imply, the trusted time of acceptance, and the trusted time the last
//! owner retired. The per-conversation and global disk quotas are charged from
//! the same accounts, once per object however many rows name it.

#![forbid(unsafe_code)]

use super::CompanionState;
use crate::state_core::durable::AccountServiceDurableWrite as Write;
use agenc_ircd_e2ee::limits::{MAX_STORED_BYTES_PER_CONVERSATION, RECOVERY_HEADROOM_BYTES};
use agenc_ircd_e2ee::object::{IrcWireObject, ObjectId};
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode as Code;
use agenc_ircd_storage::e2ee_records::delivery_recovery::DeliveryRecoveryRow;
use agenc_ircd_storage::e2ee_records::delivery_recovery::outbox::OUTBOX_PREFIX;
use agenc_ircd_storage::e2ee_records::{
    ATTACH_ROW_KIND, AttachRow, BARRIER_ROW_KIND, CLAIM_ROW_KIND, ClaimRow,
    DELIVERY_RECOVERY_ROW_KIND, DIRECTORY_ROW_KIND, DirectoryRow, MAILBOX_ROW_KIND, MailboxRow,
    OBJECT_RECORD_KIND, OWNER_ROW_KIND, ObjectOwnerRow, ObjectRow, PACKAGE_ROW_KIND, PackageRow,
    RECOVERY_RECORD_ROW_KIND, RECOVERY_SUBMISSION_ROW_KIND, REPLAY_ROW_KIND, ROUTE_ROW_KIND,
    RecoveryRecordRow, RecoverySubmissionRow, ReplayRow, RetentionClass, RouteRow,
    SEQUENCER_ROW_KIND, SequencerRow, barrier, prefix,
};
use agenc_ircd_storage::{
    MAX_RECORD_REFERENCES, PersistentRecordValue, RecordReference, StoredKey, TableId,
};
use std::collections::{BTreeMap, BTreeSet};

/// The table-23 key bytes of one owning row.
pub(crate) type OwnerKey = Vec<u8>;

/// The second recorded for an acceptance or retirement whose trusted time
/// is unknown (`UNDATED_SECOND`): a reconstructed account persisted, or a
/// last owner retired, by a batch admitted without a trusted clock, or an
/// account whose every owner a restore dropped. The next dated batch that
/// touches the account replaces it, and nothing ages by this value.
pub(crate) const UNDATED: u64 = agenc_ircd_storage::e2ee_records::UNDATED_SECOND;

/// One object's ownership account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Account {
    /// The `IrcWireObjectKind` wire value.
    pub(crate) kind: u8,
    /// The complete encoded object length.
    pub(crate) size: u64,
    /// The strongest retention class an owner implies.
    pub(crate) retention: RetentionClass,
    /// The trusted acceptance time, or the reconstruction floor.
    pub(crate) accepted_at: u64,
    /// Whether `accepted_at` is a reconstruction floor.
    pub(crate) reconstructed: bool,
    /// The trusted time the last owner retired.
    pub(crate) retired_at: Option<u64>,
    /// Every owning row and the conversation it charges, if any.
    pub(crate) owners: BTreeMap<OwnerKey, Option<[u8; 32]>>,
}

impl Account {
    /// The conversations this object is charged to.
    pub(crate) fn conversations(&self) -> BTreeSet<[u8; 32]> {
        self.owners.values().flatten().copied().collect()
    }

    fn row(&self) -> ObjectOwnerRow {
        ObjectOwnerRow {
            kind: self.kind,
            size: self.size,
            retention: self.retention,
            accepted_at: self.accepted_at,
            reconstructed: self.reconstructed,
            retired_at: self.retired_at,
        }
    }
}

/// Every account, with the indexes the quotas and retirements need.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Ledger {
    accounts: BTreeMap<[u8; 32], Account>,
    by_owner: BTreeMap<OwnerKey, BTreeSet<[u8; 32]>>,
    conversation_bytes: BTreeMap<[u8; 32], u64>,
    total_bytes: u64,
}

impl Ledger {
    pub(crate) fn account(&self, id: &[u8; 32]) -> Option<&Account> {
        self.accounts.get(id)
    }

    #[cfg(test)]
    pub(crate) fn accounts(&self) -> impl Iterator<Item = (&[u8; 32], &Account)> {
        self.accounts.iter()
    }

    /// The bytes charged to one conversation.
    pub(crate) fn conversation_bytes(&self, conversation: &[u8; 32]) -> u64 {
        self.conversation_bytes
            .get(conversation)
            .copied()
            .unwrap_or(0)
    }

    /// The bytes of every accounted object.
    pub(crate) fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    pub(crate) fn owned_by(&self, owner: &[u8]) -> Option<&BTreeSet<[u8; 32]>> {
        self.by_owner.get(owner)
    }

    /// Installs one account, replacing the previous one and its indexes.
    pub(crate) fn install(&mut self, id: [u8; 32], account: Account) {
        self.retire_indexes(&id);
        for owner in account.owners.keys() {
            self.by_owner.entry(owner.clone()).or_default().insert(id);
        }
        for conversation in account.conversations() {
            let bytes = self.conversation_bytes.entry(conversation).or_default();
            *bytes = bytes.saturating_add(account.size);
        }
        self.total_bytes = self.total_bytes.saturating_add(account.size);
        self.accounts.insert(id, account);
    }

    fn retire_indexes(&mut self, id: &[u8; 32]) {
        let Some(previous) = self.accounts.remove(id) else {
            return;
        };
        for owner in previous.owners.keys() {
            // Every owner of an installed account is indexed.
            let emptied = self.by_owner.get_mut(owner).is_some_and(|ids| {
                ids.remove(id);
                ids.is_empty()
            });
            if emptied {
                self.by_owner.remove(owner);
            }
        }
        for conversation in previous.conversations() {
            let drained = self
                .conversation_bytes
                .get_mut(&conversation)
                .is_some_and(|bytes| {
                    *bytes = bytes.saturating_sub(previous.size);
                    *bytes == 0
                });
            if drained {
                self.conversation_bytes.remove(&conversation);
            }
        }
        self.total_bytes = self.total_bytes.saturating_sub(previous.size);
    }
}

/// One object a row names, with the retention its row implies and the
/// conversation it charges.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Owned {
    pub(crate) object_id: [u8; 32],
    pub(crate) retention: RetentionClass,
    pub(crate) conversation: Option<[u8; 32]>,
}

fn owned(object_id: [u8; 32], retention: RetentionClass, conversation: Option<[u8; 32]>) -> Owned {
    Owned {
        object_id,
        retention,
        conversation,
    }
}

/// The retention a stronger class supersedes: a proof outlives ordinary
/// material, which outlives a mailbox payload, which outlives replay state.
fn strength(class: RetentionClass) -> u8 {
    match class {
        RetentionClass::SecurityProof => 3,
        RetentionClass::Ordinary => 2,
        RetentionClass::Mailbox => 1,
        RetentionClass::Replay => 0,
    }
}

fn stronger(left: RetentionClass, right: RetentionClass) -> RetentionClass {
    if strength(right) > strength(left) {
        right
    } else {
        left
    }
}

fn invalid<E>(_: E) -> Code {
    Code::InvalidFragment
}

/// The objects one table-23 row owns. A row kind that names no object owns
/// nothing; an undecodable row is refused.
pub(crate) fn owned_by(key: &StoredKey, kind: u16, body: &[u8]) -> Result<Vec<Owned>, Code> {
    let bytes = key.as_bytes();
    Ok(match kind {
        ROUTE_ROW_KIND => route_owned(key, body)?,
        CLAIM_ROW_KIND => claim_owned(body)?,
        SEQUENCER_ROW_KIND => sequencer_owned(key, body)?,
        DIRECTORY_ROW_KIND => directory_owned(body)?,
        PACKAGE_ROW_KIND => package_owned(body)?,
        ATTACH_ROW_KIND => attach_owned(body)?,
        MAILBOX_ROW_KIND => mailbox_owned(body)?,
        REPLAY_ROW_KIND if bytes.starts_with(prefix::REPLAY) => replay_owned(body)?,
        BARRIER_ROW_KIND if bytes.starts_with(prefix::BARRIER_PART) => barrier_owned(body)?,
        DELIVERY_RECOVERY_ROW_KIND if bytes.starts_with(OUTBOX_PREFIX) => outbox_owned(body)?,
        RECOVERY_SUBMISSION_ROW_KIND => recovery_submission_owned(key, body)?,
        RECOVERY_RECORD_ROW_KIND => recovery_record_owned(key, body)?,
        // Other key families of these kinds (delivery owners, ACK ranges, cut
        // pages, barrier heads, origin sequences) name no retained object.
        _ => vec![],
    })
}

fn route_owned(key: &StoredKey, body: &[u8]) -> Result<Vec<Owned>, Code> {
    let row = RouteRow::decode(body).map_err(invalid)?;
    let conversation = RouteRow::parse_key(key).map_err(invalid)?;
    let id = *ObjectId::compute(&row.route_state).as_bytes();
    Ok(vec![owned(
        id,
        RetentionClass::SecurityProof,
        Some(conversation),
    )])
}

fn claim_owned(body: &[u8]) -> Result<Vec<Owned>, Code> {
    Ok(match ClaimRow::decode(body).map_err(invalid)? {
        ClaimRow::Reservation {
            reservation_object_id,
            ..
        } => vec![owned(reservation_object_id, RetentionClass::Ordinary, None)],
        ClaimRow::Lock { .. } => vec![],
    })
}

fn directory_owned(body: &[u8]) -> Result<Vec<Owned>, Code> {
    Ok(match DirectoryRow::decode(body).map_err(invalid)? {
        DirectoryRow::Identity {
            object_id,
            chain_object_ids,
            ..
        } => std::iter::once(object_id)
            .chain(chain_object_ids)
            .map(|id| owned(id, RetentionClass::SecurityProof, None))
            .collect(),
        DirectoryRow::Roster { object_id, .. } | DirectoryRow::BindingLock { object_id, .. } => {
            vec![owned(object_id, RetentionClass::SecurityProof, None)]
        }
        DirectoryRow::Capability { object_id, .. } => {
            vec![owned(object_id, RetentionClass::Ordinary, None)]
        }
    })
}

fn package_owned(body: &[u8]) -> Result<Vec<Owned>, Code> {
    Ok(match PackageRow::decode(body).map_err(invalid)? {
        PackageRow::Package { object_id, .. } => {
            vec![owned(object_id, RetentionClass::Ordinary, None)]
        }
        PackageRow::Claim { object_id, .. } => object_id
            .map(|id| owned(id, RetentionClass::Ordinary, None))
            .into_iter()
            .collect(),
    })
}

fn attach_owned(body: &[u8]) -> Result<Vec<Owned>, Code> {
    Ok(AttachRow::decode(body)
        .map_err(invalid)?
        .challenge
        .map(|challenge| owned(challenge.object_id, RetentionClass::Ordinary, None))
        .into_iter()
        .collect())
}

fn mailbox_owned(body: &[u8]) -> Result<Vec<Owned>, Code> {
    Ok(match MailboxRow::decode(body).map_err(invalid)? {
        MailboxRow::Item { object_id, .. }
        | MailboxRow::Token { object_id, .. }
        | MailboxRow::Ack { object_id, .. } => {
            vec![owned(object_id, RetentionClass::Mailbox, None)]
        }
    })
}

fn replay_owned(body: &[u8]) -> Result<Vec<Owned>, Code> {
    let row = ReplayRow::decode(body).map_err(invalid)?;
    Ok(std::iter::once(row.request_object_id)
        .chain(row.result_object_id)
        .chain(row.response_object_ids)
        .map(|id| owned(id, RetentionClass::Replay, None))
        .collect())
}

fn barrier_owned(body: &[u8]) -> Result<Vec<Owned>, Code> {
    let part = barrier::BarrierPart::decode(body).map_err(invalid)?;
    Ok(std::iter::once(part.event_object_id)
        .chain(part.payload_object_id)
        .map(|id| owned(id, RetentionClass::Replay, None))
        .collect())
}

fn outbox_owned(body: &[u8]) -> Result<Vec<Owned>, Code> {
    Ok(match DeliveryRecoveryRow::decode(body).map_err(invalid)? {
        DeliveryRecoveryRow::Outbox(row) => std::iter::once(row.event_object_id())
            .chain(row.payload_object_id())
            .map(|id| owned(id, RetentionClass::Replay, None))
            .collect(),
        DeliveryRecoveryRow::Owner(_)
        | DeliveryRecoveryRow::CutPage(_)
        | DeliveryRecoveryRow::Barrier(_) => vec![],
    })
}

fn recovery_submission_owned(key: &StoredKey, body: &[u8]) -> Result<Vec<Owned>, Code> {
    let row = RecoverySubmissionRow::decode(body).map_err(invalid)?;
    let (conversation, _) = RecoverySubmissionRow::parse_key(key).map_err(invalid)?;
    let mut owned_objects = vec![owned(
        row.submission_object_id,
        RetentionClass::Ordinary,
        Some(conversation),
    )];
    if row.element_retained {
        // Records and closes are the proofs a recovery adopts; references
        // are the ordinary material they name.
        let class = if row.element_kind == 3 {
            RetentionClass::Ordinary
        } else {
            RetentionClass::SecurityProof
        };
        owned_objects.push(owned(row.element_object_id, class, Some(conversation)));
    }
    Ok(owned_objects)
}

fn recovery_record_owned(key: &StoredKey, body: &[u8]) -> Result<Vec<Owned>, Code> {
    let row = RecoveryRecordRow::decode(body).map_err(invalid)?;
    let (conversation, _) = RecoveryRecordRow::parse_key(key).map_err(invalid)?;
    Ok(vec![owned(
        row.record_object_id,
        RetentionClass::SecurityProof,
        Some(conversation),
    )])
}

fn sequencer_owned(key: &StoredKey, body: &[u8]) -> Result<Vec<Owned>, Code> {
    let row = SequencerRow::decode(body).map_err(invalid)?;
    let conversation = sequencer_conversation(key)?;
    Ok(match row {
        SequencerRow::Record {
            record_object_id,
            security_proof,
            ..
        } => {
            let class = if security_proof {
                RetentionClass::SecurityProof
            } else {
                RetentionClass::Ordinary
            };
            vec![owned(record_object_id, class, Some(conversation))]
        }
        SequencerRow::Candidate {
            commit_object_id, ..
        } => vec![owned(
            commit_object_id,
            RetentionClass::Ordinary,
            Some(conversation),
        )],
        SequencerRow::Proof { object_id, .. } => {
            vec![owned(
                object_id,
                RetentionClass::Ordinary,
                Some(conversation),
            )]
        }
        SequencerRow::Policy { object_id, .. } | SequencerRow::Membership { object_id, .. } => {
            vec![owned(
                object_id,
                RetentionClass::SecurityProof,
                Some(conversation),
            )]
        }
    })
}

/// The conversation a sequencer row's key names.
fn sequencer_conversation(key: &StoredKey) -> Result<[u8; 32], Code> {
    let bytes = key.as_bytes();
    if bytes.starts_with(prefix::RECORD) {
        SequencerRow::parse_record_key(key).map(|(conversation, _)| conversation)
    } else if bytes.starts_with(prefix::CANDIDATE) {
        SequencerRow::parse_candidate_key(key).map(|(conversation, _)| conversation)
    } else if bytes.starts_with(prefix::POLICY) {
        SequencerRow::parse_policy_key(key).map(|(conversation, _)| conversation)
    } else if bytes.starts_with(prefix::MEMBERSHIP) {
        SequencerRow::parse_membership_key(key).map(|(conversation, ..)| conversation)
    } else {
        SequencerRow::parse_proof_key(key).map(|parts| parts.conversation_id)
    }
    .map_err(invalid)
}

/// The accounts one batch changes, and the owner rows that persist them.
pub(crate) struct Staged {
    accounts: BTreeMap<[u8; 32], Account>,
    pub(crate) writes: Vec<Write>,
}

impl Staged {
    /// Installs the accounts; the owner rows are already part of the batch.
    pub(crate) fn apply(self, state: &mut CompanionState) {
        for (id, account) in self.accounts {
            state.owners.install(id, account);
        }
        sync_conversation_bytes(state);
    }
}

/// Mirrors the ledger's per-conversation charge into each retained
/// conversation's `stored_bytes`.
fn sync_conversation_bytes(state: &mut CompanionState) {
    for (conversation, bytes) in &state.owners.conversation_bytes {
        if let Some(retained) = state.conversations.get_mut(conversation) {
            retained.stored_bytes = *bytes;
        }
    }
}

/// The sizes and kinds of the objects a batch may account for.
struct Sizes<'a> {
    state: &'a CompanionState,
    staged: BTreeMap<[u8; 32], (u8, u64)>,
}

impl Sizes<'_> {
    fn of(&self, id: &[u8; 32]) -> Option<(u8, u64)> {
        if let Some(found) = self.staged.get(id) {
            return Some(*found);
        }
        if let Some(account) = self.state.owners.account(id) {
            return Some((account.kind, account.size));
        }
        let bytes = self.state.objects.get(id)?;
        let (kind, _) = IrcWireObject::peek(bytes).ok()?;
        Some((kind.value(), u64::try_from(bytes.len()).ok()?))
    }
}

/// The account of `id` as this batch will leave it: the retained account
/// copied on first touch, or a fresh one for an object the batch introduces.
/// A reconstructed account without a trusted acceptance time takes this
/// batch's time as its floor. `None` is an object this coordinator does not
/// retain, which no row can charge.
fn account_of<'a>(
    sizes: &Sizes<'_>,
    touched: &'a mut BTreeMap<[u8; 32], Account>,
    id: [u8; 32],
    now: u64,
) -> Result<Option<&'a mut Account>, Code> {
    if let std::collections::btree_map::Entry::Vacant(slot) = touched.entry(id) {
        let account = match sizes.state.owners.account(&id) {
            Some(existing) => {
                let mut copied = existing.clone();
                // An unknown acceptance time takes this batch's trusted
                // time as its floor, or stays undated without one.
                if copied.accepted_at == 0 || (copied.accepted_at == UNDATED && now != 0) {
                    copied.accepted_at = if now == 0 { UNDATED } else { now };
                    copied.reconstructed = true;
                }
                copied
            }
            None => {
                let Some((kind, size)) = sizes.of(&id) else {
                    return Ok(None);
                };
                Account {
                    kind,
                    size,
                    retention: RetentionClass::Replay,
                    accepted_at: now,
                    reconstructed: false,
                    retired_at: None,
                    owners: BTreeMap::new(),
                }
            }
        };
        slot.insert(account);
    }
    touched.get_mut(&id).map(Some).ok_or(Code::InvalidFragment)
}

/// Derives every ownership change of `writes` against `state`, checks the
/// per-conversation, headroom and global quotas, and returns the owner rows
/// to add to the batch. Nothing here allocates a durable row before the
/// quota admitted it; a refusal leaves the batch unstaged.
pub(crate) fn stage(
    state: &CompanionState,
    writes: &[Write],
    now: u64,
    security_mutation: bool,
    global_limit: u64,
) -> Result<Staged, Code> {
    let invalid = |_| Code::InvalidFragment;
    let touched = derive(state, writes, now)?;
    check_quotas(state, &touched, security_mutation, global_limit)?;
    let mut staged_writes = Vec::with_capacity(touched.len());
    for (id, account) in &touched {
        if account.owners.len() > MAX_RECORD_REFERENCES {
            return Err(Code::RateLimited);
        }
        let references = account
            .owners
            .keys()
            .map(|owner| {
                StoredKey::new(owner.clone())
                    .and_then(|key| RecordReference::new(TableId::E2eeState, key))
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(invalid)?;
        let body = account.row().encode().map_err(invalid)?;
        let encoded = PersistentRecordValue::new(
            TableId::E2eeState,
            OWNER_ROW_KIND,
            1,
            0,
            None,
            references,
            body,
        )
        .and_then(|value| value.encode())
        .map_err(invalid)?;
        let key = ObjectOwnerRow::key(id).map_err(invalid)?;
        staged_writes
            .push(Write::put(TableId::E2eeState, key, encoded).map_err(|_| Code::InvalidFragment)?);
    }
    Ok(Staged {
        accounts: touched,
        writes: staged_writes,
    })
}

/// The accounts `writes` change. A batch that introduces an account or an
/// owner needs a trusted time; without one (`now == 0`) it is refused
/// rather than dated, while a batch that only retires owners records an
/// undated retirement.
fn derive(
    state: &CompanionState,
    writes: &[Write],
    now: u64,
) -> Result<BTreeMap<[u8; 32], Account>, Code> {
    let invalid = |_| Code::InvalidFragment;
    let mut sizes = Sizes {
        state,
        staged: BTreeMap::new(),
    };
    for write in writes {
        let Some((TableId::E2eeObject, _, encoded)) = write.encoded_record() else {
            continue;
        };
        let value = PersistentRecordValue::decode(TableId::E2eeObject, encoded).map_err(invalid)?;
        // Table 22 admits only object records; the codec refused anything else.
        (value.record_kind() == OBJECT_RECORD_KIND)
            .then_some(())
            .ok_or(Code::InvalidFragment)?;
        let row = ObjectRow::decode(value.body()).map_err(invalid)?;
        let id = *ObjectId::compute(&row.bytes).as_bytes();
        let kind = row.kind().map_err(invalid)?.value();
        let size = u64::try_from(row.bytes.len()).map_err(|_| Code::RateLimited)?;
        sizes.staged.insert(id, (kind, size));
    }

    let mut touched: BTreeMap<[u8; 32], Account> = BTreeMap::new();
    // Whether the batch introduces an account or an owner, which needs a
    // trusted acceptance time; retirements alone can be left undated.
    let mut dated = false;
    for write in writes {
        match write {
            Write::Put { table, key, .. } if *table == TableId::E2eeState => {
                // A put always carries its encoded record.
                let (_, _, encoded) = write.encoded_record().ok_or(Code::InvalidFragment)?;
                let value =
                    PersistentRecordValue::decode(TableId::E2eeState, encoded).map_err(invalid)?;
                if value.record_kind() == OWNER_ROW_KIND {
                    // Only this module writes owner rows.
                    return Err(Code::InvalidFragment);
                }
                let owner = key.as_bytes().to_vec();
                let new: Vec<Owned> = owned_by(key, value.record_kind(), value.body())?;
                let named: BTreeSet<[u8; 32]> = new.iter().map(|o| o.object_id).collect();
                // Every object the index names is accounted, so the account exists.
                for previous in state.owners.owned_by(&owner).into_iter().flatten() {
                    if !named.contains(previous) {
                        account_of(&sizes, &mut touched, *previous, now)?
                            .ok_or(Code::InvalidFragment)?
                            .owners
                            .remove(&owner);
                    }
                }
                for item in new {
                    let Some(account) = account_of(&sizes, &mut touched, item.object_id, now)?
                    else {
                        continue;
                    };
                    account.retention = stronger(account.retention, item.retention);
                    if account
                        .owners
                        .insert(owner.clone(), item.conversation)
                        .is_none()
                    {
                        dated = true;
                    }
                    account.retired_at = None;
                }
            }
            Write::Delete { table, key } if *table == TableId::E2eeState => {
                let owner = key.as_bytes().to_vec();
                for previous in state.owners.owned_by(&owner).into_iter().flatten() {
                    account_of(&sizes, &mut touched, *previous, now)?
                        .ok_or(Code::InvalidFragment)?
                        .owners
                        .remove(&owner);
                }
            }
            _ => {}
        }
    }
    // An object put without any owner is accounted as already retired.
    for id in sizes.staged.keys() {
        if !touched.contains_key(id) && state.owners.account(id).is_none() {
            account_of(&sizes, &mut touched, *id, now)?;
            dated = true;
        }
    }
    if dated && now == 0 {
        return Err(Code::RateLimited);
    }
    let retired_at = if now == 0 { UNDATED } else { now };
    for account in touched.values_mut() {
        if account.owners.is_empty() {
            // A retirement dated by an earlier trusted batch keeps its time;
            // an undated one takes this batch's trusted time.
            if account
                .retired_at
                .is_none_or(|at| at == UNDATED && now != 0)
            {
                account.retired_at = Some(retired_at);
            }
        }
    }
    Ok(touched)
}

/// Charges every touched conversation and the global ceiling before the batch
/// stages: an object counts once per conversation, a proof-producing batch
/// must leave the recovery headroom free, and a refusal changes nothing.
fn check_quotas(
    state: &CompanionState,
    touched: &BTreeMap<[u8; 32], Account>,
    security_mutation: bool,
    global_limit: u64,
) -> Result<(), Code> {
    let mut conversation_delta: BTreeMap<[u8; 32], i128> = BTreeMap::new();
    let mut total_delta: i128 = 0;
    for (id, account) in touched {
        let previous = state.owners.account(id);
        let previous_conversations = previous.map(Account::conversations).unwrap_or_default();
        let size = i128::from(account.size);
        for conversation in account.conversations() {
            if !previous_conversations.contains(&conversation) {
                *conversation_delta.entry(conversation).or_default() += size;
            }
        }
        for conversation in previous_conversations {
            if !account.conversations().contains(&conversation) {
                *conversation_delta.entry(conversation).or_default() -= size;
            }
        }
        if previous.is_none() {
            total_delta += size;
        }
    }
    let quota = i128::from(MAX_STORED_BYTES_PER_CONVERSATION);
    let headroom = i128::from(RECOVERY_HEADROOM_BYTES);
    for (conversation, delta) in conversation_delta {
        let projected = i128::from(state.owners.conversation_bytes(&conversation)) + delta;
        if projected > quota || (security_mutation && delta > 0 && projected + headroom > quota) {
            return Err(Code::RateLimited);
        }
    }
    if global_limit != 0
        && i128::from(state.owners.total_bytes()) + total_delta > i128::from(global_limit)
    {
        return Err(Code::RateLimited);
    }
    Ok(())
}

/// Startup reconstruction: the accounts read back, the retained objects'
/// identities, and the owners derived from every row, reconciled once all
/// rows are known.
#[derive(Default)]
pub(crate) struct Rebuild {
    objects: BTreeMap<[u8; 32], (u8, u64)>,
    stored: BTreeMap<[u8; 32], (ObjectOwnerRow, BTreeSet<OwnerKey>)>,
    derived: BTreeMap<[u8; 32], DerivedOwners>,
    diagnostics: Diagnostics,
}

/// What reconstruction had to conclude without complete evidence. Nothing
/// here deletes: an object without trustworthy ownership evidence is
/// retained, its account rebuilt from the authoritative rows, and its age
/// left unknown until a later batch dates it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Diagnostics {
    /// Objects without an account, rebuilt without a trusted acceptance time.
    pub reconstructed: usize,
    /// Objects no row names, retained because nothing proves their
    /// retention ended.
    pub unowned: usize,
    /// Accounts whose references, kind, size, or retirement disagree with
    /// the rows that name their object; the rows win.
    pub mismatched: usize,
    /// Accounts of objects that no longer exist, ignored.
    pub orphaned: usize,
    /// Rows or accounts that did not decode, which restore nothing.
    pub undecodable: usize,
}

impl Diagnostics {
    /// Whether reconstruction found every account complete and consistent.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        *self == Self::default()
    }
}

impl Rebuild {
    /// Records the identity, kind and size of one retained object.
    pub(crate) fn admit_object(&mut self, key: &StoredKey, value: &PersistentRecordValue) {
        let parsed = ObjectRow::decode(value.body()).ok().and_then(|row| {
            Some((
                row.kind().ok()?.value(),
                u64::try_from(row.bytes.len()).ok()?,
            ))
        });
        let id: Option<[u8; 32]> = key.as_bytes().try_into().ok();
        match (id, parsed) {
            (Some(id), Some(meta)) => {
                self.objects.insert(id, meta);
            }
            _ => self.diagnostics.undecodable += 1,
        }
    }

    /// Records one owner row. References outside table 23 are not owners
    /// this module wrote, so the account cannot be trusted.
    fn admit_owner(&mut self, key: &StoredKey, value: &PersistentRecordValue) {
        self.diagnostics.undecodable += usize::from(self.owner_account(key, value).is_none());
    }

    fn owner_account(&mut self, key: &StoredKey, value: &PersistentRecordValue) -> Option<()> {
        let id = ObjectOwnerRow::parse_key(key).ok()?;
        let row = ObjectOwnerRow::decode(value.body()).ok()?;
        let references = value
            .references()
            .iter()
            .map(|reference| {
                (reference.table() == TableId::E2eeState)
                    .then(|| reference.key().as_bytes().to_vec())
            })
            .collect::<Option<BTreeSet<_>>>()?;
        self.stored.insert(id, (row, references));
        Some(())
    }

    /// Derives the objects one state row owns.
    pub(crate) fn admit_row(&mut self, key: &StoredKey, value: &PersistentRecordValue) {
        if value.record_kind() == OWNER_ROW_KIND {
            self.admit_owner(key, value);
            return;
        }
        let items = owned_by(key, value.record_kind(), value.body()).unwrap_or_else(|_| {
            self.diagnostics.undecodable += 1;
            Vec::new()
        });
        for item in items {
            let entry = self
                .derived
                .entry(item.object_id)
                .or_insert((item.retention, BTreeMap::new()));
            entry.0 = stronger(entry.0, item.retention);
            entry.1.insert(key.as_bytes().to_vec(), item.conversation);
        }
    }

    /// Reconciles the accounts against the retained objects and the rows
    /// that name them. A stored account is trusted only when it names
    /// exactly those rows with the object's kind and size; otherwise the
    /// rows rebuild it. Nothing is aged by invention: a rebuilt account
    /// keeps a trusted acceptance time only when the stored row proved the
    /// same object.
    pub(crate) fn finish(mut self, state: &mut CompanionState) -> Diagnostics {
        let mut ledger = Ledger::default();
        self.diagnostics.orphaned += self
            .stored
            .keys()
            .filter(|id| !self.objects.contains_key(*id))
            .count();
        let objects = std::mem::take(&mut self.objects);
        for (id, (kind, size)) in &objects {
            let account = reconcile(
                &mut self.diagnostics,
                self.stored.get(id),
                self.derived.get(id),
                *kind,
                *size,
            );
            ledger.install(*id, account);
        }
        state.owners = ledger;
        sync_conversation_bytes(state);
        self.diagnostics
    }
}

type StoredAccount = (ObjectOwnerRow, BTreeSet<OwnerKey>);
type DerivedOwners = (RetentionClass, BTreeMap<OwnerKey, Option<[u8; 32]>>);

/// One object's account after reconciliation, counting what the evidence
/// could not support.
fn reconcile(
    diagnostics: &mut Diagnostics,
    stored: Option<&StoredAccount>,
    derived: Option<&DerivedOwners>,
    kind: u8,
    size: u64,
) -> Account {
    // An object no row names has the weakest class, as a fresh account
    // does before its first owner; its age, not its class, retains it.
    let empty = (RetentionClass::Replay, BTreeMap::new());
    let (retention, owners) = derived.unwrap_or(&empty);
    let same_object = stored.is_some_and(|(row, _)| row.kind == kind && row.size == size);
    let consistent = stored.is_some_and(|(row, references)| {
        same_object
            && *references == owners.keys().cloned().collect::<BTreeSet<_>>()
            && row.retired_at.is_some() == owners.is_empty()
    });
    let mut account = Account {
        kind,
        size,
        retention: *retention,
        accepted_at: 0,
        reconstructed: true,
        retired_at: None,
        owners: owners.clone(),
    };
    match stored {
        Some((row, _)) if consistent => {
            account.retention = stronger(row.retention, *retention);
            account.accepted_at = row.accepted_at;
            account.reconstructed = row.reconstructed;
            account.retired_at = row.retired_at;
        }
        Some((row, _)) => {
            diagnostics.mismatched += 1;
            if same_object {
                account.retention = stronger(row.retention, *retention);
                account.accepted_at = row.accepted_at;
            }
        }
        None => diagnostics.reconstructed += 1,
    }
    if !consistent && owners.is_empty() {
        diagnostics.unowned += 1;
    }
    account
}
