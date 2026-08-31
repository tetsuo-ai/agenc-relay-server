//! Startup reconstruction and append cursor for the signed admin audit chain.

use std::collections::{BTreeMap, BTreeSet};

use agenc_ircd_admin::{
    AdminAuditCheckpoint, AdminAuditCheckpointTbs, AdminAuditEvent, AdminAuditEventTbs,
    AdminAuditPhase, AdminCommand, AdminCommandEvent, AdminSessionBinding, AuditChainCursor,
    AuditRange, CanonicalCommand, OperatorRegistry, render_export_batch,
};
use agenc_ircd_config::AuditTrustManifestEntry;
use agenc_ircd_crypto::{Ed25519PublicKey, Ed25519SecretKey, audit_signing_key_id};
use agenc_ircd_storage::{
    PersistentRecordValue, ReadPlan, SealedRecord, StoragePort, StoredKey, TableId,
    validate_record_plaintext,
};
use agenc_ircd_types::{AccountId, ChannelInstanceId, OperatorId, UtcSecond};

use crate::RuntimeError;
use crate::state_core::durable::{DOMAIN_RECORD_SCHEMA, KeyDeriver, MAX_AUDIT_RETENTION_EVENTS};
use crate::sync::Arc;

const RANGE_READ_LIMIT: u16 = 4_096;

/// Verified audit authority transferred into the sole `AdminOwner`.
pub(crate) struct AuditAuthority {
    signing_key: Ed25519SecretKey,
    signing_key_id: [u8; 32],
    signing_not_before: u64,
    signing_not_after: u64,
    cursor: AuditChainCursor,
    retained_first_sequence: u64,
    next_checkpoint_sequence: u64,
    previous_checkpoint_hash: [u8; 32],
    policy: AdminPolicySeed,
    export: Option<Arc<AuditExportSource>>,
    reconciled: bool,
}

#[derive(Clone, Default)]
pub(crate) struct AdminPolicySeed {
    suspensions: BTreeMap<AccountId, UtcSecond>,
    quarantined_channels: BTreeSet<ChannelInstanceId>,
}

impl AdminPolicySeed {
    pub(crate) fn into_parts(self) -> (Vec<(AccountId, UtcSecond)>, Vec<ChannelInstanceId>) {
        (
            self.suspensions.into_iter().collect(),
            self.quarantined_channels.into_iter().collect(),
        )
    }

    fn observe(&mut self, event: &AdminAuditEvent) -> Result<(), RuntimeError> {
        if event.tbs().phase != AdminAuditPhase::CommittedMutation {
            return Ok(());
        }
        let canonical = CanonicalCommand::check(event.tbs().command_tbs.canonical_command())
            .map_err(|_| RuntimeError::InvalidValue)?;
        match AdminCommand::parse(canonical).map_err(|_| RuntimeError::InvalidValue)? {
            AdminCommand::AccountSuspend {
                account, seconds, ..
            } => {
                let expires_at = event
                    .tbs()
                    .created_at
                    .checked_add(seconds.get())
                    .ok_or(RuntimeError::Overflow)?;
                self.suspensions
                    .insert(account, UtcSecond::from_unix_seconds(expires_at));
            }
            AdminCommand::AccountRestore { account, .. } => {
                self.suspensions.remove(&account);
            }
            AdminCommand::ChannelQuarantine { channel, .. } => {
                self.quarantined_channels.insert(channel);
            }
            _ => return Err(RuntimeError::InvalidValue),
        }
        Ok(())
    }
}

impl AuditAuthority {
    /// Reconstructs both signed tables before any administrative authority is
    /// accepted. Stored keys, envelopes, trust windows, signatures, chains,
    /// checkpoint coverage, and retained intents are all verified here.
    pub(crate) fn reconstruct(
        binding: AdminSessionBinding,
        signing_key: Ed25519SecretKey,
        trust_entries: &[AuditTrustManifestEntry],
        storage: StoragePort,
        keys: KeyDeriver,
        operators: &OperatorRegistry,
        now_unix_seconds: u64,
    ) -> Result<Self, RuntimeError> {
        let trust = AuditTrust::new(trust_entries)?;
        let signing_key_id = *audit_signing_key_id(signing_key.public_key().as_bytes())
            .map_err(|_| RuntimeError::InvalidValue)?
            .as_bytes();
        let current = trust.trusted(signing_key_id, now_unix_seconds)?;
        if current.public_key != signing_key.public_key() {
            return Err(RuntimeError::InvalidValue);
        }

        let checkpoints = read_checkpoints(&storage, &keys)?;
        let (checkpoint_cursor, next_checkpoint_sequence, previous_checkpoint_hash) =
            verify_checkpoints(binding, &trust, &checkpoints.records)?;
        let retained_first_sequence = checkpoint_cursor.next_sequence;
        let events = read_events(&storage, &keys)?;
        if checkpoints.storage_commit_sequence != events.storage_commit_sequence {
            return Err(RuntimeError::InvalidValue);
        }
        let (cursor, policy) = verify_events(
            binding,
            &trust,
            operators,
            checkpoint_cursor,
            &events.records,
        )?;
        let export = Arc::new(AuditExportSource {
            binding,
            storage,
            keys,
            trust,
            operators: operators.clone(),
        });

        Ok(Self {
            signing_key,
            signing_key_id,
            signing_not_before: current.not_before,
            signing_not_after: current.not_after,
            cursor,
            retained_first_sequence,
            next_checkpoint_sequence,
            previous_checkpoint_hash,
            policy,
            export: Some(export),
            reconciled: true,
        })
    }

    pub(crate) fn is_reconciled(&self) -> bool {
        let key_matches = audit_signing_key_id(self.signing_key.public_key().as_bytes())
            .is_ok_and(|derived| derived.as_bytes() == &self.signing_key_id);
        let checkpoint_position_valid =
            self.next_checkpoint_sequence != 0 || self.previous_checkpoint_hash == [0; 32];
        let event_position_valid =
            self.cursor.next_sequence != 0 || self.cursor.previous_event_hash == [0; 32];
        self.reconciled && key_matches && checkpoint_position_valid && event_position_valid
    }

    pub(crate) fn policy_seed(&self) -> AdminPolicySeed {
        self.policy.clone()
    }

    pub(crate) fn prepare_export(
        &self,
        range: AuditRange,
        batch_id: [u8; 16],
    ) -> Result<AuditExportJob, RuntimeError> {
        let source = self.export.as_ref().ok_or(RuntimeError::InvalidValue)?;
        Ok(AuditExportJob {
            source: Arc::clone(source),
            range,
            batch_id,
            expected_cursor: self.cursor,
            expected_checkpoint_sequence: self.next_checkpoint_sequence,
            expected_checkpoint_hash: self.previous_checkpoint_hash,
        })
    }

    pub(crate) fn prepare_retention(
        &self,
        now: u64,
        retention_seconds: u64,
    ) -> Result<AuditRetentionJob, RuntimeError> {
        let source = self.export.as_ref().ok_or(RuntimeError::InvalidValue)?;
        Ok(AuditRetentionJob {
            source: Arc::clone(source),
            now,
            retention_seconds,
            signing_key_id: self.signing_key_id,
            expected_cursor: self.cursor,
            expected_retained_first_sequence: self.retained_first_sequence,
            expected_checkpoint_sequence: self.next_checkpoint_sequence,
            expected_checkpoint_hash: self.previous_checkpoint_hash,
        })
    }

    pub(crate) fn sign_retention(
        &self,
        tbs: AdminAuditCheckpointTbs,
    ) -> Result<AdminAuditCheckpoint, RuntimeError> {
        if tbs.audit_signing_key_id != self.signing_key_id
            || tbs.created_at < self.signing_not_before
            || tbs.created_at >= self.signing_not_after
            || tbs.checkpoint_sequence != self.next_checkpoint_sequence
            || tbs.deleted_first_sequence != self.retained_first_sequence
            || tbs.previous_checkpoint_hash != self.previous_checkpoint_hash
            || tbs.next_retained_sequence > self.cursor.next_sequence
        {
            return Err(RuntimeError::InvalidValue);
        }
        AdminAuditCheckpoint::sign(tbs, &self.signing_key).map_err(|_| RuntimeError::InvalidValue)
    }

    pub(crate) fn commit_retention(
        &mut self,
        checkpoint: &AdminAuditCheckpoint,
    ) -> Result<(), RuntimeError> {
        let tbs = checkpoint.tbs();
        if tbs.checkpoint_sequence != self.next_checkpoint_sequence
            || tbs.deleted_first_sequence != self.retained_first_sequence
            || tbs.previous_checkpoint_hash != self.previous_checkpoint_hash
        {
            return Err(RuntimeError::InvalidValue);
        }
        checkpoint
            .verify(self.signing_key.public_key())
            .map_err(|_| RuntimeError::InvalidValue)?;
        self.retained_first_sequence = tbs.next_retained_sequence;
        self.next_checkpoint_sequence = self
            .next_checkpoint_sequence
            .checked_add(1)
            .ok_or(RuntimeError::Overflow)?;
        self.previous_checkpoint_hash = checkpoint.checkpoint_hash();
        Ok(())
    }

    pub(crate) fn prepare_event(
        &self,
        binding: AdminSessionBinding,
        operator_id: OperatorId,
        command: &AdminCommandEvent,
        phase: AdminAuditPhase,
        created_at: u64,
    ) -> Result<AdminAuditEvent, RuntimeError> {
        if !self.reconciled
            || created_at < self.signing_not_before
            || created_at >= self.signing_not_after
            || command.tbs.network_id() != binding.network_id
            || command.tbs.server_id() != binding.server_id
        {
            return Err(RuntimeError::InvalidValue);
        }
        AdminAuditEvent::sign(
            AdminAuditEventTbs {
                network_id: binding.network_id,
                server_id: binding.server_id,
                audit_signing_key_id: self.signing_key_id,
                audit_sequence: self.cursor.next_sequence,
                created_at,
                operator_id,
                command_tbs: command.tbs.clone(),
                operator_signature: command.operator_signature,
                phase,
                previous_event_hash: self.cursor.previous_event_hash,
            },
            &self.signing_key,
        )
        .map_err(|_| RuntimeError::InvalidValue)
    }

    pub(crate) fn commit_event(&mut self, event: &AdminAuditEvent) -> Result<(), RuntimeError> {
        self.cursor = self
            .cursor
            .advance(event)
            .map_err(|_| RuntimeError::InvalidValue)?;
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn empty_for_test() -> Result<Self, RuntimeError> {
        let signing_key = Ed25519SecretKey::from_bytes([99; 32]);
        let signing_key_id = audit_signing_key_id(signing_key.public_key().as_bytes())
            .map_err(|_| RuntimeError::InvalidValue)?
            .as_bytes()
            .to_owned();
        Ok(Self {
            signing_key,
            signing_key_id,
            signing_not_before: 0,
            signing_not_after: u64::MAX,
            cursor: AuditChainCursor::genesis(),
            retained_first_sequence: 0,
            next_checkpoint_sequence: 0,
            previous_checkpoint_hash: [0; 32],
            policy: AdminPolicySeed::default(),
            export: None,
            reconciled: true,
        })
    }
}

pub(crate) struct AuditRetentionJob {
    source: Arc<AuditExportSource>,
    now: u64,
    retention_seconds: u64,
    signing_key_id: [u8; 32],
    expected_cursor: AuditChainCursor,
    expected_retained_first_sequence: u64,
    expected_checkpoint_sequence: u64,
    expected_checkpoint_hash: [u8; 32],
}

impl AuditRetentionJob {
    pub(crate) fn run(self) -> Result<Option<AdminAuditCheckpointTbs>, RuntimeError> {
        self.source.retention_tbs(
            self.now,
            self.retention_seconds,
            self.signing_key_id,
            self.expected_cursor,
            self.expected_retained_first_sequence,
            self.expected_checkpoint_sequence,
            self.expected_checkpoint_hash,
        )
    }
}

pub(crate) struct AuditExportJob {
    source: Arc<AuditExportSource>,
    range: AuditRange,
    batch_id: [u8; 16],
    expected_cursor: AuditChainCursor,
    expected_checkpoint_sequence: u64,
    expected_checkpoint_hash: [u8; 32],
}

impl AuditExportJob {
    pub(crate) fn run(self) -> Result<Vec<String>, RuntimeError> {
        self.source.freeze(
            self.range,
            self.batch_id,
            self.expected_cursor,
            self.expected_checkpoint_sequence,
            self.expected_checkpoint_hash,
        )
    }
}

struct AuditExportSource {
    binding: AdminSessionBinding,
    storage: StoragePort,
    keys: KeyDeriver,
    trust: AuditTrust,
    operators: OperatorRegistry,
}

impl AuditExportSource {
    fn freeze(
        &self,
        range: AuditRange,
        batch_id: [u8; 16],
        expected_cursor: AuditChainCursor,
        expected_checkpoint_sequence: u64,
        expected_checkpoint_hash: [u8; 32],
    ) -> Result<Vec<String>, RuntimeError> {
        let checkpoints = read_checkpoints(&self.storage, &self.keys)?;
        let events = read_events(&self.storage, &self.keys)?;
        if checkpoints.storage_commit_sequence != events.storage_commit_sequence {
            return Err(RuntimeError::InvalidValue);
        }
        let (checkpoint_cursor, next_checkpoint_sequence, previous_checkpoint_hash) =
            verify_checkpoints(self.binding, &self.trust, &checkpoints.records)?;
        if next_checkpoint_sequence != expected_checkpoint_sequence
            || previous_checkpoint_hash != expected_checkpoint_hash
        {
            return Err(RuntimeError::InvalidValue);
        }
        let (cursor, _policy) = verify_events(
            self.binding,
            &self.trust,
            &self.operators,
            checkpoint_cursor,
            &events.records,
        )?;
        if cursor != expected_cursor {
            return Err(RuntimeError::InvalidValue);
        }
        let selected_checkpoints: Vec<_> = checkpoints
            .records
            .into_iter()
            .filter(|checkpoint| {
                let tbs = checkpoint.tbs();
                tbs.deleted_first_sequence <= range.to()
                    && tbs.deleted_last_sequence >= range.from()
            })
            .collect();
        let selected_events: Vec<_> = events
            .records
            .into_iter()
            .filter(|event| range.contains(event.tbs().audit_sequence))
            .collect();
        verify_export_coverage(
            range,
            cursor.next_sequence,
            &selected_checkpoints,
            &selected_events,
        )?;
        render_export_batch(&batch_id, range, &selected_checkpoints, &selected_events)
            .map_err(|_| RuntimeError::InvalidValue)
    }

    // agenc-review: allow owner=runtime reviewed=2026-08-30 reason=retention freeze keeps every expected audit and checkpoint fence explicit at the blocking boundary
    // agenc-review: focus owner=runtime reviewed=2026-08-30 reason=the signed checkpoint scan preserves all current cursor and trust fences in one immutable job
    #[allow(clippy::too_many_arguments)]
    fn retention_tbs(
        &self,
        now: u64,
        retention_seconds: u64,
        signing_key_id: [u8; 32],
        expected_cursor: AuditChainCursor,
        expected_retained_first_sequence: u64,
        expected_checkpoint_sequence: u64,
        expected_checkpoint_hash: [u8; 32],
    ) -> Result<Option<AdminAuditCheckpointTbs>, RuntimeError> {
        let checkpoints = read_checkpoints(&self.storage, &self.keys)?;
        let events = read_events(&self.storage, &self.keys)?;
        if checkpoints.storage_commit_sequence != events.storage_commit_sequence {
            return Err(RuntimeError::InvalidValue);
        }
        let (checkpoint_cursor, next_checkpoint_sequence, previous_checkpoint_hash) =
            verify_checkpoints(self.binding, &self.trust, &checkpoints.records)?;
        if checkpoint_cursor.next_sequence != expected_retained_first_sequence
            || next_checkpoint_sequence != expected_checkpoint_sequence
            || previous_checkpoint_hash != expected_checkpoint_hash
        {
            return Err(RuntimeError::InvalidValue);
        }
        let (cursor, _policy) = verify_events(
            self.binding,
            &self.trust,
            &self.operators,
            checkpoint_cursor,
            &events.records,
        )?;
        if cursor != expected_cursor {
            return Err(RuntimeError::InvalidValue);
        }
        let latest_created_at = checkpoints
            .records
            .iter()
            .map(|checkpoint| checkpoint.tbs().created_at)
            .chain(events.records.iter().map(|event| event.tbs().created_at))
            .max()
            .unwrap_or(0);
        let Some(cutoff) = now.checked_sub(retention_seconds) else {
            return Ok(None);
        };
        if now < latest_created_at {
            return Ok(None);
        }

        let Some((deleted_last_sequence, deleted_last_event_hash)) =
            select_expired_prefix(&events.records, cutoff)?
        else {
            return Ok(None);
        };
        let deleted_count = deleted_last_sequence
            .checked_sub(expected_retained_first_sequence)
            .and_then(|count| count.checked_add(1))
            .ok_or(RuntimeError::Overflow)?;
        Ok(Some(AdminAuditCheckpointTbs {
            network_id: self.binding.network_id,
            server_id: self.binding.server_id,
            audit_signing_key_id: signing_key_id,
            checkpoint_sequence: expected_checkpoint_sequence,
            created_at: now,
            deleted_first_sequence: expected_retained_first_sequence,
            deleted_last_sequence,
            deleted_count,
            deleted_last_event_hash,
            next_retained_sequence: deleted_last_sequence
                .checked_add(1)
                .ok_or(RuntimeError::Overflow)?,
            previous_checkpoint_hash: expected_checkpoint_hash,
        }))
    }
}

fn select_expired_prefix(
    events: &[AdminAuditEvent],
    cutoff: u64,
) -> Result<Option<(u64, [u8; 32])>, RuntimeError> {
    let mut pending = BTreeSet::<Vec<u8>>::new();
    let mut candidate = None;
    for event in events.iter().take(MAX_AUDIT_RETENTION_EVENTS) {
        if event.tbs().created_at >= cutoff {
            break;
        }
        let command = event
            .tbs()
            .command_tbs
            .encode()
            .map_err(|_| RuntimeError::InvalidValue)?;
        match event.tbs().phase {
            AdminAuditPhase::Intent if intent_requires_outcome(event)? => {
                if !pending.insert(command) {
                    return Err(RuntimeError::InvalidValue);
                }
            }
            AdminAuditPhase::OutcomeSuccess | AdminAuditPhase::OutcomeFailure => {
                if !pending.remove(&command) {
                    return Err(RuntimeError::InvalidValue);
                }
            }
            AdminAuditPhase::Intent
            | AdminAuditPhase::CommittedMutation
            | AdminAuditPhase::Observed => {}
        }
        if pending.is_empty() {
            candidate = Some((event.tbs().audit_sequence, event.event_hash()));
        }
    }
    Ok(candidate)
}

fn verify_export_coverage(
    range: AuditRange,
    next_sequence: u64,
    checkpoints: &[AdminAuditCheckpoint],
    events: &[AdminAuditEvent],
) -> Result<(), RuntimeError> {
    if range.from() >= next_sequence {
        return (checkpoints.is_empty() && events.is_empty())
            .then_some(())
            .ok_or(RuntimeError::InvalidValue);
    }
    let last = range.to().min(next_sequence.saturating_sub(1));
    let mut intervals = Vec::new();
    intervals
        .try_reserve_exact(checkpoints.len().saturating_add(events.len()))
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    intervals.extend(checkpoints.iter().map(|checkpoint| {
        let tbs = checkpoint.tbs();
        (
            tbs.deleted_first_sequence.max(range.from()),
            tbs.deleted_last_sequence.min(last),
        )
    }));
    intervals.extend(events.iter().map(|event| {
        let sequence = event.tbs().audit_sequence;
        (sequence, sequence)
    }));
    intervals.sort_unstable();
    let mut expected = range.from();
    for (first, interval_last) in intervals {
        if first != expected || interval_last < first {
            return Err(RuntimeError::InvalidValue);
        }
        expected = interval_last.checked_add(1).ok_or(RuntimeError::Overflow)?;
    }
    if expected != last.saturating_add(1) {
        return Err(RuntimeError::InvalidValue);
    }
    Ok(())
}

struct AuditTrust {
    keys: BTreeMap<[u8; 32], TrustedAuditKey>,
}

#[derive(Clone, Copy)]
struct TrustedAuditKey {
    public_key: Ed25519PublicKey,
    not_before: u64,
    not_after: u64,
}

impl AuditTrust {
    fn new(entries: &[AuditTrustManifestEntry]) -> Result<Self, RuntimeError> {
        let mut keys = BTreeMap::new();
        for entry in entries {
            let public_key = Ed25519PublicKey::from_bytes(entry.ed25519_public_key)
                .map_err(|_| RuntimeError::InvalidValue)?;
            let derived = *audit_signing_key_id(public_key.as_bytes())
                .map_err(|_| RuntimeError::InvalidValue)?
                .as_bytes();
            if derived != entry.key_id
                || entry.not_before >= entry.not_after
                || keys
                    .insert(
                        entry.key_id,
                        TrustedAuditKey {
                            public_key,
                            not_before: entry.not_before,
                            not_after: entry.not_after,
                        },
                    )
                    .is_some()
            {
                return Err(RuntimeError::InvalidValue);
            }
        }
        if keys.is_empty() {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(Self { keys })
    }

    fn resolve(&self, key_id: [u8; 32], created_at: u64) -> Result<Ed25519PublicKey, RuntimeError> {
        Ok(self.trusted(key_id, created_at)?.public_key)
    }

    fn trusted(&self, key_id: [u8; 32], created_at: u64) -> Result<TrustedAuditKey, RuntimeError> {
        let key = self.keys.get(&key_id).ok_or(RuntimeError::InvalidValue)?;
        if created_at < key.not_before || created_at >= key.not_after {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(*key)
    }
}

fn read_checkpoints(
    storage: &StoragePort,
    keys: &KeyDeriver,
) -> Result<TableRead<AdminAuditCheckpoint>, RuntimeError> {
    read_table(storage, keys, TableId::AuditCheckpoint, |sequence, body| {
        let checkpoint =
            AdminAuditCheckpoint::decode_exact(body).map_err(|_| RuntimeError::InvalidValue)?;
        if checkpoint.tbs().checkpoint_sequence != sequence {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(checkpoint)
    })
}

fn read_events(
    storage: &StoragePort,
    keys: &KeyDeriver,
) -> Result<TableRead<AdminAuditEvent>, RuntimeError> {
    read_table(storage, keys, TableId::Audit, |sequence, body| {
        let event = AdminAuditEvent::decode_exact(body).map_err(|_| RuntimeError::InvalidValue)?;
        if event.tbs().audit_sequence != sequence {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(event)
    })
}

// agenc-review: focus owner=runtime reviewed=2026-08-30 reason=bounded paged audit reconstruction validates one consistent encrypted table view and exact sequence keys
fn read_table<T>(
    storage: &StoragePort,
    keys: &KeyDeriver,
    table: TableId,
    mut decode: impl FnMut(u64, &[u8]) -> Result<T, RuntimeError>,
) -> Result<TableRead<T>, RuntimeError> {
    let mut start = 0_u64;
    let end = StoredKey::new(vec![0xff; 9])?;
    let mut expected_commit = None;
    let mut output = Vec::new();
    loop {
        let plan = ReadPlan::range(
            table,
            StoredKey::new(start.to_be_bytes().to_vec())?,
            StoredKey::new(end.as_bytes().to_vec())?,
            RANGE_READ_LIMIT,
        )?;
        let result = storage.try_read(plan)?.wait()?;
        match expected_commit {
            None => expected_commit = Some(result.storage_commit_sequence),
            Some(expected) if expected == result.storage_commit_sequence => {}
            Some(_) => return Err(RuntimeError::InvalidValue),
        }
        let count = result.records.len();
        let mut last = None;
        for record in result.records {
            let sequence = sequence_key(&record.key)?;
            if sequence < start || last.is_some_and(|previous| sequence <= previous) {
                return Err(RuntimeError::InvalidValue);
            }
            let sealed = SealedRecord::decode(&record.sealed_record)?;
            let plaintext = keys.open(table, &record.key, &sealed)?;
            validate_record_plaintext(
                table,
                &record.key,
                DOMAIN_RECORD_SCHEMA,
                plaintext.expose_for_storage_codec(),
            )?;
            let value = PersistentRecordValue::decode(table, plaintext.expose_for_storage_codec())?;
            let expected_revision = sequence.checked_add(1).ok_or(RuntimeError::Overflow)?;
            if value.record_kind() != 1
                || value.revision() != expected_revision
                || value.generation() != 0
                || value.expires_at().is_some()
                || !value.references().is_empty()
            {
                return Err(RuntimeError::InvalidValue);
            }
            output.push(decode(sequence, value.body())?);
            last = Some(sequence);
        }
        if count < usize::from(RANGE_READ_LIMIT) {
            break;
        }
        let last = last.ok_or(RuntimeError::InvalidValue)?;
        if last == u64::MAX {
            break;
        }
        start = last.checked_add(1).ok_or(RuntimeError::Overflow)?;
    }
    Ok(TableRead {
        records: output,
        storage_commit_sequence: expected_commit.ok_or(RuntimeError::InvalidValue)?,
    })
}

struct TableRead<T> {
    records: Vec<T>,
    storage_commit_sequence: u64,
}

fn sequence_key(key: &StoredKey) -> Result<u64, RuntimeError> {
    let bytes: [u8; 8] = key
        .as_bytes()
        .try_into()
        .map_err(|_| RuntimeError::InvalidValue)?;
    Ok(u64::from_be_bytes(bytes))
}

fn verify_checkpoints(
    binding: AdminSessionBinding,
    trust: &AuditTrust,
    checkpoints: &[AdminAuditCheckpoint],
) -> Result<(AuditChainCursor, u64, [u8; 32]), RuntimeError> {
    let mut next_sequence = 0_u64;
    let mut next_deleted = 0_u64;
    let mut previous_hash = [0_u8; 32];
    let mut cursor = AuditChainCursor::genesis();
    for checkpoint in checkpoints {
        let tbs = checkpoint.tbs();
        if tbs.network_id != binding.network_id
            || tbs.server_id != binding.server_id
            || tbs.checkpoint_sequence != next_sequence
            || tbs.deleted_first_sequence != next_deleted
            || tbs.previous_checkpoint_hash != previous_hash
        {
            return Err(RuntimeError::InvalidValue);
        }
        let key = trust.resolve(tbs.audit_signing_key_id, tbs.created_at)?;
        checkpoint
            .verify(key)
            .map_err(|_| RuntimeError::InvalidValue)?;
        cursor = AuditChainCursor::after_checkpoint(tbs);
        next_deleted = tbs.next_retained_sequence;
        previous_hash = checkpoint.checkpoint_hash();
        next_sequence = next_sequence.checked_add(1).ok_or(RuntimeError::Overflow)?;
    }
    Ok((cursor, next_sequence, previous_hash))
}

// agenc-review: focus owner=runtime reviewed=2026-08-30 reason=single gapless verification pass binds trust signatures hashes chain position and intent outcome pairing
fn verify_events(
    binding: AdminSessionBinding,
    trust: &AuditTrust,
    operators: &OperatorRegistry,
    mut cursor: AuditChainCursor,
    events: &[AdminAuditEvent],
) -> Result<(AuditChainCursor, AdminPolicySeed), RuntimeError> {
    let mut unmatched_intents: BTreeMap<Vec<u8>, u64> = BTreeMap::new();
    let mut policy = AdminPolicySeed::default();
    for event in events {
        let tbs = event.tbs();
        if tbs.network_id != binding.network_id
            || tbs.server_id != binding.server_id
            || tbs.command_tbs.network_id() != binding.network_id
            || tbs.command_tbs.server_id() != binding.server_id
        {
            return Err(RuntimeError::InvalidValue);
        }
        let audit_key = trust.resolve(tbs.audit_signing_key_id, tbs.created_at)?;
        let operator_key = operators
            .verification_key(tbs.operator_id)
            .map_err(|_| RuntimeError::InvalidValue)?;
        event
            .verify(audit_key, operator_key)
            .map_err(|_| RuntimeError::InvalidValue)?;
        cursor = cursor
            .advance(event)
            .map_err(|_| RuntimeError::InvalidValue)?;

        let command = tbs
            .command_tbs
            .encode()
            .map_err(|_| RuntimeError::InvalidValue)?;
        match tbs.phase {
            AdminAuditPhase::Intent => {
                if intent_requires_outcome(event)?
                    && unmatched_intents
                        .insert(command, tbs.audit_sequence)
                        .is_some()
                {
                    return Err(RuntimeError::InvalidValue);
                }
            }
            AdminAuditPhase::OutcomeSuccess | AdminAuditPhase::OutcomeFailure => {
                if !intent_requires_outcome(event)? || unmatched_intents.remove(&command).is_none()
                {
                    return Err(RuntimeError::InvalidValue);
                }
            }
            AdminAuditPhase::CommittedMutation => policy.observe(event)?,
            AdminAuditPhase::Observed => {}
        }
    }
    if !unmatched_intents.is_empty() {
        return Err(RuntimeError::InvalidValue);
    }
    Ok((cursor, policy))
}

fn intent_requires_outcome(event: &AdminAuditEvent) -> Result<bool, RuntimeError> {
    let canonical = CanonicalCommand::check(event.tbs().command_tbs.canonical_command())
        .map_err(|_| RuntimeError::InvalidValue)?;
    match AdminCommand::parse(canonical).map_err(|_| RuntimeError::InvalidValue)? {
        AdminCommand::Kill { .. } | AdminCommand::Rehash(_) | AdminCommand::BackupCreate(_) => {
            Ok(true)
        }
        AdminCommand::Restart(_) | AdminCommand::Die(_) => Ok(false),
        _ => Err(RuntimeError::InvalidValue),
    }
}

#[cfg(test)]
mod tests {
    use agenc_ircd_admin::{
        AdminAuditCheckpointTbs, AdminAuditEventTbs, AdminCommandTbs, AdminSessionId,
        OperatorRecord,
    };
    use agenc_ircd_crypto::audit_signing_key_id;
    use agenc_ircd_types::{AdminPermission, AdminPermissionSet, NetworkId, OperatorId, ServerId};

    use super::*;

    const CREATED_AT: u64 = 50;

    fn binding() -> AdminSessionBinding {
        AdminSessionBinding {
            network_id: NetworkId::from_bytes([1; 32]),
            server_id: ServerId::from_bytes([2; 16]),
        }
    }

    fn registry(
        operator_id: OperatorId,
        operator_key: &Ed25519SecretKey,
    ) -> Result<OperatorRegistry, RuntimeError> {
        let mut permissions = AdminPermissionSet::EMPTY;
        permissions.insert(AdminPermission::Observe);
        let record = OperatorRecord::new(
            operator_id,
            operator_key.public_key(),
            None,
            vec![1_000],
            Vec::new(),
            permissions,
            false,
        )
        .map_err(|_| RuntimeError::InvalidValue)?;
        OperatorRegistry::from_records(vec![record]).map_err(|_| RuntimeError::InvalidValue)
    }

    fn trust_entry(audit_key: &Ed25519SecretKey) -> Result<AuditTrustManifestEntry, RuntimeError> {
        let public_key = audit_key.public_key();
        let key_id = *audit_signing_key_id(public_key.as_bytes())
            .map_err(|_| RuntimeError::InvalidValue)?
            .as_bytes();
        Ok(AuditTrustManifestEntry {
            key_id,
            ed25519_public_key: *public_key.as_bytes(),
            not_before: 1,
            not_after: 100,
        })
    }

    struct EventFixture<'a> {
        binding: AdminSessionBinding,
        audit_key: &'a Ed25519SecretKey,
        operator_key: &'a Ed25519SecretKey,
        operator_id: OperatorId,
    }

    impl EventFixture<'_> {
        fn event(
            &self,
            cursor: AuditChainCursor,
            command_counter: u64,
            phase: AdminAuditPhase,
            command: &[u8],
        ) -> Result<AdminAuditEvent, RuntimeError> {
            let command_tbs = AdminCommandTbs::new(
                self.binding.network_id,
                self.binding.server_id,
                AdminSessionId::from_bytes([3; 16]),
                command_counter,
                None,
                command,
            )
            .map_err(|_| RuntimeError::InvalidValue)?;
            let operator_signature = command_tbs
                .sign(self.operator_key)
                .map_err(|_| RuntimeError::InvalidValue)?;
            let key_id = *audit_signing_key_id(self.audit_key.public_key().as_bytes())
                .map_err(|_| RuntimeError::InvalidValue)?
                .as_bytes();
            AdminAuditEvent::sign(
                AdminAuditEventTbs {
                    network_id: self.binding.network_id,
                    server_id: self.binding.server_id,
                    audit_signing_key_id: key_id,
                    audit_sequence: cursor.next_sequence,
                    created_at: CREATED_AT,
                    operator_id: self.operator_id,
                    command_tbs,
                    operator_signature,
                    phase,
                    previous_event_hash: cursor.previous_event_hash,
                },
                self.audit_key,
            )
            .map_err(|_| RuntimeError::InvalidValue)
        }
    }

    #[test]
    fn verifies_gapless_events_and_rejects_unmatched_intents() -> Result<(), RuntimeError> {
        let binding = binding();
        let audit_key = Ed25519SecretKey::from_bytes([4; 32]);
        let operator_key = Ed25519SecretKey::from_bytes([5; 32]);
        let operator_id = OperatorId::from_bytes([6; 16]);
        let registry = registry(operator_id, &operator_key)?;
        let trust = AuditTrust::new(&[trust_entry(&audit_key)?])?;
        let fixture = EventFixture {
            binding,
            audit_key: &audit_key,
            operator_key: &operator_key,
            operator_id,
        };

        let first = fixture.event(
            AuditChainCursor::genesis(),
            0,
            AdminAuditPhase::Intent,
            b"KILL AAAAAAAAAAAAAAAAAAAAAA :reason text",
        )?;
        assert!(
            verify_events(
                binding,
                &trust,
                &registry,
                AuditChainCursor::genesis(),
                std::slice::from_ref(&first),
            )
            .is_err()
        );

        let cursor = AuditChainCursor::genesis()
            .advance(&first)
            .map_err(|_| RuntimeError::InvalidValue)?;
        let outcome = fixture.event(
            cursor,
            0,
            AdminAuditPhase::OutcomeSuccess,
            b"KILL AAAAAAAAAAAAAAAAAAAAAA :reason text",
        )?;
        let (verified, _policy) = verify_events(
            binding,
            &trust,
            &registry,
            AuditChainCursor::genesis(),
            &[first, outcome],
        )?;
        assert_eq!(verified.next_sequence, 2);

        let terminal = fixture.event(
            AuditChainCursor::genesis(),
            1,
            AdminAuditPhase::Intent,
            b"DIE :planned maintenance",
        )?;
        let (verified, _policy) = verify_events(
            binding,
            &trust,
            &registry,
            AuditChainCursor::genesis(),
            std::slice::from_ref(&terminal),
        )?;
        assert_eq!(verified.next_sequence, 1);
        let terminal_cursor = AuditChainCursor::genesis()
            .advance(&terminal)
            .map_err(|_| RuntimeError::InvalidValue)?;
        let invalid_terminal_outcome = fixture.event(
            terminal_cursor,
            1,
            AdminAuditPhase::OutcomeSuccess,
            b"DIE :planned maintenance",
        )?;
        assert!(
            verify_events(
                binding,
                &trust,
                &registry,
                AuditChainCursor::genesis(),
                &[terminal, invalid_terminal_outcome],
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn retention_prefix_never_splits_an_intent_from_its_outcome() -> Result<(), RuntimeError> {
        let binding = binding();
        let audit_key = Ed25519SecretKey::from_bytes([4; 32]);
        let operator_key = Ed25519SecretKey::from_bytes([5; 32]);
        let operator_id = OperatorId::from_bytes([6; 16]);
        let fixture = EventFixture {
            binding,
            audit_key: &audit_key,
            operator_key: &operator_key,
            operator_id,
        };
        let observed = fixture.event(
            AuditChainCursor::genesis(),
            0,
            AdminAuditPhase::Observed,
            b"MOTD",
        )?;
        let cursor = AuditChainCursor::genesis()
            .advance(&observed)
            .map_err(|_| RuntimeError::InvalidValue)?;
        let intent = fixture.event(
            cursor,
            1,
            AdminAuditPhase::Intent,
            b"KILL AAAAAAAAAAAAAAAAAAAAAA :policy action",
        )?;
        let observed_hash = observed.event_hash();
        assert_eq!(
            select_expired_prefix(&[observed.clone(), intent.clone()], CREATED_AT + 1)?,
            Some((0, observed_hash))
        );

        let cursor = cursor
            .advance(&intent)
            .map_err(|_| RuntimeError::InvalidValue)?;
        let outcome = fixture.event(
            cursor,
            1,
            AdminAuditPhase::OutcomeSuccess,
            b"KILL AAAAAAAAAAAAAAAAAAAAAA :policy action",
        )?;
        let outcome_hash = outcome.event_hash();
        assert_eq!(
            select_expired_prefix(&[observed, intent, outcome], CREATED_AT + 1)?,
            Some((2, outcome_hash))
        );

        let terminal = fixture.event(
            AuditChainCursor::genesis(),
            2,
            AdminAuditPhase::Intent,
            b"RESTART :planned maintenance",
        )?;
        assert_eq!(
            select_expired_prefix(std::slice::from_ref(&terminal), CREATED_AT + 1)?,
            Some((0, terminal.event_hash()))
        );
        Ok(())
    }

    #[test]
    fn verifies_checkpoint_coverage_and_trust_window() -> Result<(), RuntimeError> {
        let binding = binding();
        let audit_key = Ed25519SecretKey::from_bytes([7; 32]);
        let entry = trust_entry(&audit_key)?;
        let trust = AuditTrust::new(&[entry])?;
        let checkpoint = AdminAuditCheckpoint::sign(
            AdminAuditCheckpointTbs {
                network_id: binding.network_id,
                server_id: binding.server_id,
                audit_signing_key_id: entry.key_id,
                checkpoint_sequence: 0,
                created_at: CREATED_AT,
                deleted_first_sequence: 0,
                deleted_last_sequence: 4,
                deleted_count: 5,
                deleted_last_event_hash: [8; 32],
                next_retained_sequence: 5,
                previous_checkpoint_hash: [0; 32],
            },
            &audit_key,
        )
        .map_err(|_| RuntimeError::InvalidValue)?;
        let (cursor, next_checkpoint, previous_hash) =
            verify_checkpoints(binding, &trust, std::slice::from_ref(&checkpoint))?;
        assert_eq!(cursor.next_sequence, 5);
        assert_eq!(next_checkpoint, 1);
        assert_eq!(previous_hash, checkpoint.checkpoint_hash());

        let expired = AuditTrust {
            keys: BTreeMap::from([(
                entry.key_id,
                TrustedAuditKey {
                    public_key: audit_key.public_key(),
                    not_before: 1,
                    not_after: CREATED_AT,
                },
            )]),
        };
        assert!(verify_checkpoints(binding, &expired, &[checkpoint]).is_err());
        Ok(())
    }
}
