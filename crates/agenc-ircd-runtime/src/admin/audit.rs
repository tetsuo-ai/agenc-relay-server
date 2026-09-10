//! Startup reconstruction and append cursor for the signed admin audit chain.

mod maintenance;
mod mixed;
#[cfg(test)]
#[path = "audit/tests/mixed/mod.rs"]
mod mixed_tests;

pub(crate) use maintenance::PreparedMaintenanceAudit;

use std::collections::{BTreeMap, BTreeSet};

use agenc_ircd_admin::{
    AdminAuditCheckpoint, AdminAuditCheckpointTbs, AdminAuditEvent, AdminAuditEventTbs,
    AdminAuditPhase, AdminCommand, AdminCommandEvent, AdminSessionBinding, AuditChainCursor,
    AuditEvent, AuditRange, CanonicalCommand, MAX_AUDIT_EXPORT_RECORDS, MaintenanceAuditScope,
    OperatorRegistry, render_export_batch,
};
use agenc_ircd_config::AuditTrustManifestEntry;
use agenc_ircd_crypto::{Ed25519PublicKey, Ed25519SecretKey, audit_signing_key_id};
use agenc_ircd_storage::{
    PersistentRecordValue, ReadPlan, SealedRecord, StoragePort, StoredKey, TableId,
    validate_record_plaintext,
};
use agenc_ircd_types::{AccountId, ChannelInstanceId, OperatorId, UserId, UtcSecond};

use crate::RuntimeError;
use crate::state_core::durable::{DOMAIN_RECORD_SCHEMA, KeyDeriver, MAX_AUDIT_RETENTION_EVENTS};
use crate::sync::Arc;

const RANGE_READ_LIMIT: u16 = 4_096;

/// Verified audit authority transferred into the sole `AdminOwner`.
pub(crate) struct AuditAuthority {
    scope: MaintenanceAuditScope,
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
    pending_startup_action: Option<PendingStartupAction>,
    startup_action_in_progress: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum PendingStartupActionKind {
    Kill(UserId),
    Rehash,
    BackupCreate,
}

/// A single verified trailing external-action intent that must be reconciled
/// before the owner accepts administrative authority.
pub(crate) struct PendingStartupAction {
    kind: PendingStartupActionKind,
    intent: AdminAuditEvent,
}

impl PendingStartupAction {
    fn from_verified(
        intent: &AdminAuditEvent,
        command: &AdminCommand,
    ) -> Result<Self, RuntimeError> {
        let kind = match command {
            AdminCommand::Kill { user, .. } => PendingStartupActionKind::Kill(*user),
            AdminCommand::Rehash(_) => PendingStartupActionKind::Rehash,
            AdminCommand::BackupCreate(_) => PendingStartupActionKind::BackupCreate,
            _ => return Err(RuntimeError::InvalidValue),
        };
        Ok(Self {
            kind,
            intent: intent.clone(),
        })
    }

    pub(crate) const fn kind(&self) -> PendingStartupActionKind {
        self.kind
    }

    pub(crate) const fn audit_sequence(&self) -> u64 {
        self.intent.tbs().audit_sequence
    }

    pub(crate) const fn created_at(&self) -> u64 {
        self.intent.tbs().created_at
    }

    const fn intent_hash(&self) -> [u8; 32] {
        self.intent.event_hash()
    }
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
            AdminCommand::ChannelHistoryPurge { .. } => {}
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
        scope: MaintenanceAuditScope,
        signing_key: Ed25519SecretKey,
        trust_entries: &[AuditTrustManifestEntry],
        storage: StoragePort,
        keys: KeyDeriver,
        operators: &OperatorRegistry,
        now_unix_seconds: u64,
    ) -> Result<Self, RuntimeError> {
        let binding = maintenance::session_binding(scope, &keys)?;
        let trust = AuditTrust::new(trust_entries)?;
        let signing_key_id = *audit_signing_key_id(signing_key.public_key().as_bytes())
            .map_err(|_| RuntimeError::InvalidValue)?
            .as_bytes();
        let current = trust.trusted(signing_key_id, now_unix_seconds)?;
        if current.public_key != signing_key.public_key() {
            return Err(RuntimeError::InvalidValue);
        }

        let mut checkpoint_verifier = CheckpointVerifier::new(binding, &trust);
        let checkpoint_commit_sequence = scan_checkpoints(&storage, &keys, |checkpoint| {
            checkpoint_verifier.observe(&checkpoint)
        })?;
        let checkpoints = checkpoint_verifier.finish();
        let retained_first_sequence = checkpoints.cursor.next_sequence;
        let mut event_verifier = EventVerifier::new(binding, &trust, operators, checkpoints.cursor);
        let event_commit_sequence = scan_events(&storage, &keys, |event| {
            event_verifier.observe_event(&event)
        })?;
        if checkpoint_commit_sequence != event_commit_sequence {
            return Err(RuntimeError::InvalidValue);
        }
        let events = event_verifier.finish();
        let export = Arc::new(AuditExportSource {
            binding,
            storage,
            keys,
            trust,
            operators: operators.clone(),
        });

        Ok(Self {
            scope,
            signing_key,
            signing_key_id,
            signing_not_before: current.not_before,
            signing_not_after: current.not_after,
            cursor: events.cursor,
            retained_first_sequence,
            next_checkpoint_sequence: checkpoints.next_sequence,
            previous_checkpoint_hash: checkpoints.previous_hash,
            policy: events.policy,
            export: Some(export),
            reconciled: true,
            pending_startup_action: events.pending_startup_action,
            startup_action_in_progress: None,
        })
    }

    pub(crate) fn is_reconciled(&self) -> bool {
        self.base_authority_is_valid()
            && self.pending_startup_action.is_none()
            && self.startup_action_in_progress.is_none()
    }

    fn base_authority_is_valid(&self) -> bool {
        let key_matches = audit_signing_key_id(self.signing_key.public_key().as_bytes())
            .is_ok_and(|derived| derived.as_bytes() == &self.signing_key_id);
        let checkpoint_position_valid =
            self.next_checkpoint_sequence != 0 || self.previous_checkpoint_hash == [0; 32];
        let event_position_valid =
            self.cursor.next_sequence != 0 || self.cursor.previous_event_hash == [0; 32];
        self.reconciled && key_matches && checkpoint_position_valid && event_position_valid
    }

    pub(crate) fn take_pending_startup_action(&mut self) -> Option<PendingStartupAction> {
        if !self.base_authority_is_valid() || self.startup_action_in_progress.is_some() {
            return None;
        }
        let action = self.pending_startup_action.take()?;
        self.startup_action_in_progress = Some(action.intent_hash());
        Some(action)
    }

    pub(crate) fn prepare_startup_outcome(
        &self,
        action: &PendingStartupAction,
        phase: AdminAuditPhase,
        created_at: u64,
    ) -> Result<AdminAuditEvent, RuntimeError> {
        let intent = action.intent.tbs();
        let expected_sequence = intent
            .audit_sequence
            .checked_add(1)
            .ok_or(RuntimeError::Overflow)?;
        if !self.base_authority_is_valid()
            || self.startup_action_in_progress != Some(action.intent_hash())
            || !matches!(
                phase,
                AdminAuditPhase::OutcomeSuccess | AdminAuditPhase::OutcomeFailure
            )
            || created_at < self.signing_not_before
            || created_at >= self.signing_not_after
            || self.cursor.next_sequence != expected_sequence
            || self.cursor.previous_event_hash != action.intent_hash()
        {
            return Err(RuntimeError::InvalidValue);
        }
        AdminAuditEvent::sign(
            AdminAuditEventTbs {
                network_id: intent.network_id,
                server_id: intent.server_id,
                audit_signing_key_id: self.signing_key_id,
                audit_sequence: self.cursor.next_sequence,
                created_at,
                operator_id: intent.operator_id,
                command_tbs: intent.command_tbs.clone(),
                operator_signature: intent.operator_signature,
                phase,
                previous_event_hash: self.cursor.previous_event_hash,
            },
            &self.signing_key,
        )
        .map_err(|_| RuntimeError::InvalidValue)
    }

    /// Advances authority only after the caller durably committed this exact
    /// startup outcome. A mismatch leaves authority permanently closed for
    /// this process so startup reconstruction must run again.
    pub(crate) fn resolve_committed_startup_action(
        &mut self,
        action: PendingStartupAction,
        outcome: &AdminAuditEvent,
    ) -> Result<(), RuntimeError> {
        let expected =
            self.prepare_startup_outcome(&action, outcome.tbs().phase, outcome.tbs().created_at)?;
        if expected != *outcome {
            return Err(RuntimeError::InvalidValue);
        }
        let next = self
            .cursor
            .advance(outcome)
            .map_err(|_| RuntimeError::InvalidValue)?;
        self.cursor = next;
        self.startup_action_in_progress = None;
        Ok(())
    }

    pub(crate) fn policy_seed(&self) -> AdminPolicySeed {
        self.policy.clone()
    }

    pub(crate) fn prepare_export(
        &self,
        range: AuditRange,
        batch_id: [u8; 16],
    ) -> Result<AuditExportJob, RuntimeError> {
        if !self.is_reconciled() {
            return Err(RuntimeError::InvalidValue);
        }
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
        if !self.is_reconciled() {
            return Err(RuntimeError::InvalidValue);
        }
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
        if !self.is_reconciled()
            || tbs.audit_signing_key_id != self.signing_key_id
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
        if !self.is_reconciled()
            || tbs.checkpoint_sequence != self.next_checkpoint_sequence
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
        if !self.is_reconciled()
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
        if !self.is_reconciled() {
            return Err(RuntimeError::InvalidValue);
        }
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
            scope: MaintenanceAuditScope::new(
                agenc_ircd_types::NetworkId::from_bytes([1; 32]),
                agenc_ircd_types::ServerId::from_bytes([2; 16]),
                agenc_ircd_types::DatabaseId::from_bytes([4; 16]),
                agenc_ircd_types::ServerIncarnation::from_bytes([3; 16]),
                agenc_ircd_types::RecoveryEpoch::from_bytes([5; 16]),
            ),
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
            pending_startup_action: None,
            startup_action_in_progress: None,
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
    pub(crate) fn run(self) -> Result<PreparedAuditExport, RuntimeError> {
        self.source.freeze(
            self.range,
            self.batch_id,
            self.expected_cursor,
            self.expected_checkpoint_sequence,
            self.expected_checkpoint_hash,
        )
    }
}

/// One fully verified and bounded storage view waiting for its own signed
/// `Observed` event. The object is consumed when that event is appended, so a
/// frozen view cannot be released twice or with two different cursor advances.
pub(crate) struct PreparedAuditExport {
    binding: AdminSessionBinding,
    trust: AuditTrust,
    operators: OperatorRegistry,
    range: AuditRange,
    batch_id: [u8; 16],
    expected_cursor: AuditChainCursor,
    selection: ExportSelection,
}

impl PreparedAuditExport {
    pub(crate) fn finish_with_observed(
        mut self,
        observed: &AdminAuditEvent,
    ) -> Result<Vec<String>, RuntimeError> {
        if observed.tbs().phase != AdminAuditPhase::Observed {
            return Err(RuntimeError::InvalidValue);
        }
        if parse_event_command(observed)? != AdminCommand::AuditExport(self.range) {
            return Err(RuntimeError::InvalidValue);
        }
        let mut verifier = EventVerifier::new(
            self.binding,
            &self.trust,
            &self.operators,
            self.expected_cursor,
        );
        verifier.observe(observed)?;
        let verified = verifier.finish_reconciled()?;
        self.selection.consider_event(observed.clone())?;
        self.selection.ensure_bounded()?;
        verify_export_coverage(
            self.range,
            verified.cursor.next_sequence,
            &self.selection.checkpoints,
            &self.selection.events,
        )?;
        render_export_batch(
            &self.batch_id,
            self.range,
            &self.selection.checkpoints,
            &self.selection.events,
        )
        .map_err(|_| RuntimeError::InvalidValue)
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
    ) -> Result<PreparedAuditExport, RuntimeError> {
        let mut selection = ExportSelection::new(range);
        let mut checkpoint_verifier = CheckpointVerifier::new(self.binding, &self.trust);
        scan_checkpoints(&self.storage, &self.keys, |checkpoint| {
            checkpoint_verifier.observe(&checkpoint)?;
            selection.consider_checkpoint(checkpoint)
        })?;
        let checkpoints = checkpoint_verifier.finish();
        if checkpoints.next_sequence != expected_checkpoint_sequence
            || checkpoints.previous_hash != expected_checkpoint_hash
        {
            return Err(RuntimeError::InvalidValue);
        }
        let mut event_verifier = EventVerifier::new(
            self.binding,
            &self.trust,
            &self.operators,
            checkpoints.cursor,
        );
        scan_events(&self.storage, &self.keys, |event| {
            event_verifier.observe_event(&event)?;
            selection.consider_mixed(event)
        })?;
        let events = event_verifier.finish_reconciled()?;
        if events.cursor != expected_cursor {
            return Err(RuntimeError::InvalidValue);
        }
        selection.ensure_bounded()?;
        Ok(PreparedAuditExport {
            binding: self.binding,
            trust: self.trust.clone(),
            operators: self.operators.clone(),
            range,
            batch_id,
            expected_cursor,
            selection,
        })
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
        let cutoff = now.checked_sub(retention_seconds);
        let mut selector = cutoff.map(RetentionSelector::new);
        let mut checkpoint_verifier = CheckpointVerifier::new(self.binding, &self.trust);
        scan_checkpoints(&self.storage, &self.keys, |checkpoint| {
            checkpoint_verifier.observe(&checkpoint)
        })?;
        let checkpoints = checkpoint_verifier.finish();
        if checkpoints.cursor.next_sequence != expected_retained_first_sequence
            || checkpoints.next_sequence != expected_checkpoint_sequence
            || checkpoints.previous_hash != expected_checkpoint_hash
        {
            return Err(RuntimeError::InvalidValue);
        }
        let mut event_verifier = EventVerifier::new(
            self.binding,
            &self.trust,
            &self.operators,
            checkpoints.cursor,
        );
        scan_events(&self.storage, &self.keys, |event| {
            event_verifier.observe_event(&event)?;
            if let Some(selector) = &mut selector {
                selector.observe_event(&event)?;
            }
            Ok(())
        })?;
        let events = event_verifier.finish_reconciled()?;
        if events.cursor != expected_cursor {
            return Err(RuntimeError::InvalidValue);
        }
        let latest_created_at = checkpoints.latest_created_at.max(events.latest_created_at);
        if now < latest_created_at {
            return Ok(None);
        }

        let Some(selector) = selector else {
            return Ok(None);
        };
        let Some((deleted_last_sequence, deleted_last_event_hash)) = selector.candidate() else {
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

struct ExportSelection {
    range: AuditRange,
    checkpoints: Vec<AdminAuditCheckpoint>,
    events: Vec<AuditEvent>,
    overflowed: bool,
}

impl ExportSelection {
    const fn new(range: AuditRange) -> Self {
        Self {
            range,
            checkpoints: Vec::new(),
            events: Vec::new(),
            overflowed: false,
        }
    }

    fn consider_checkpoint(
        &mut self,
        checkpoint: AdminAuditCheckpoint,
    ) -> Result<(), RuntimeError> {
        let tbs = checkpoint.tbs();
        if tbs.deleted_first_sequence <= self.range.to()
            && tbs.deleted_last_sequence >= self.range.from()
        {
            self.push_checkpoint(checkpoint)?;
        }
        Ok(())
    }

    fn consider_event(&mut self, event: AdminAuditEvent) -> Result<(), RuntimeError> {
        if self.range.contains(event.tbs().audit_sequence) {
            self.push_event(AuditEvent::Admin(event))?;
        }
        Ok(())
    }

    fn push_checkpoint(&mut self, checkpoint: AdminAuditCheckpoint) -> Result<(), RuntimeError> {
        if !self.reserve_record()? {
            return Ok(());
        }
        self.checkpoints
            .try_reserve(1)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        self.checkpoints.push(checkpoint);
        Ok(())
    }

    fn push_event(&mut self, event: AuditEvent) -> Result<(), RuntimeError> {
        if !self.reserve_record()? {
            return Ok(());
        }
        self.events
            .try_reserve(1)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        self.events.push(event);
        Ok(())
    }

    fn reserve_record(&mut self) -> Result<bool, RuntimeError> {
        if self.overflowed {
            return Ok(false);
        }
        let selected = self
            .checkpoints
            .len()
            .checked_add(self.events.len())
            .ok_or(RuntimeError::Overflow)?;
        if selected == MAX_AUDIT_EXPORT_RECORDS {
            self.overflowed = true;
            return Ok(false);
        }
        Ok(true)
    }

    fn ensure_bounded(&self) -> Result<(), RuntimeError> {
        if self.overflowed {
            Err(RuntimeError::LimitExceeded)
        } else {
            Ok(())
        }
    }
}

struct RetentionSelector {
    cutoff: u64,
    examined: usize,
    pending: BTreeSet<Vec<u8>>,
    candidate: Option<(u64, [u8; 32])>,
    complete: bool,
}

impl RetentionSelector {
    const fn new(cutoff: u64) -> Self {
        Self {
            cutoff,
            examined: 0,
            pending: BTreeSet::new(),
            candidate: None,
            complete: false,
        }
    }

    fn observe(&mut self, event: &AdminAuditEvent) -> Result<(), RuntimeError> {
        if self.complete || self.examined == MAX_AUDIT_RETENTION_EVENTS {
            self.complete = true;
            return Ok(());
        }
        if event.tbs().created_at >= self.cutoff {
            self.complete = true;
            return Ok(());
        }
        self.examined = self.examined.checked_add(1).ok_or(RuntimeError::Overflow)?;
        let parsed = parse_event_command(event)?;
        if !super::audit_phase_is_valid(&parsed, event.tbs().phase) {
            return Err(RuntimeError::InvalidValue);
        }
        self.observe_phase(event, &parsed)?;
        if self.pending.is_empty() {
            self.candidate = Some((event.tbs().audit_sequence, event.event_hash()));
        }
        Ok(())
    }

    fn observe_phase(
        &mut self,
        event: &AdminAuditEvent,
        parsed: &AdminCommand,
    ) -> Result<(), RuntimeError> {
        let command = event
            .tbs()
            .command_tbs
            .encode()
            .map_err(|_| RuntimeError::InvalidValue)?;
        match event.tbs().phase {
            AdminAuditPhase::Intent if command_requires_outcome(parsed)? => {
                if !self.pending.insert(command) {
                    return Err(RuntimeError::InvalidValue);
                }
            }
            AdminAuditPhase::OutcomeSuccess | AdminAuditPhase::OutcomeFailure => {
                if !command_requires_outcome(parsed)? || !self.pending.remove(&command) {
                    return Err(RuntimeError::InvalidValue);
                }
            }
            AdminAuditPhase::Intent
            | AdminAuditPhase::CommittedMutation
            | AdminAuditPhase::Observed => {}
        }
        Ok(())
    }

    fn candidate(self) -> Option<(u64, [u8; 32])> {
        self.candidate
    }
}

#[cfg(test)]
fn select_expired_prefix(
    events: &[AdminAuditEvent],
    cutoff: u64,
) -> Result<Option<(u64, [u8; 32])>, RuntimeError> {
    let mut selector = RetentionSelector::new(cutoff);
    for event in events {
        selector.observe(event)?;
    }
    Ok(selector.candidate())
}

fn verify_export_coverage(
    range: AuditRange,
    next_sequence: u64,
    checkpoints: &[AdminAuditCheckpoint],
    events: &[AuditEvent],
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
        let sequence = event.audit_sequence();
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

#[derive(Clone)]
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

fn scan_checkpoints(
    storage: &StoragePort,
    keys: &KeyDeriver,
    mut visit: impl FnMut(AdminAuditCheckpoint) -> Result<(), RuntimeError>,
) -> Result<u64, RuntimeError> {
    scan_table(
        storage,
        keys,
        TableId::AuditCheckpoint,
        |sequence, kind, body| {
            let checkpoint =
                AdminAuditCheckpoint::decode_exact(body).map_err(|_| RuntimeError::InvalidValue)?;
            if kind != 1 || checkpoint.tbs().checkpoint_sequence != sequence {
                return Err(RuntimeError::InvalidValue);
            }
            visit(checkpoint)
        },
    )
}

fn scan_events(
    storage: &StoragePort,
    keys: &KeyDeriver,
    mut visit: impl FnMut(AuditEvent) -> Result<(), RuntimeError>,
) -> Result<u64, RuntimeError> {
    scan_table(storage, keys, TableId::Audit, |sequence, kind, body| {
        visit(mixed::decode_event(sequence, kind, body)?)
    })
}

// AdminOwner serializes audit mutations while a live scan runs. Its captured
// event and checkpoint hashes fence the complete signed chains. Unrelated
// storage commits may advance between pages without changing those chains.
// Startup additionally compares the two scans' commit positions while it has
// exclusive authority over the unopened runtime.
fn scan_table(
    storage: &StoragePort,
    keys: &KeyDeriver,
    table: TableId,
    visit: impl FnMut(u64, u16, &[u8]) -> Result<(), RuntimeError>,
) -> Result<u64, RuntimeError> {
    scan_table_pages(
        keys,
        table,
        |plan| Ok(storage.try_read(plan)?.wait()?),
        visit,
    )
}

// agenc-review: focus owner=runtime reviewed=2026-09-05 reason=bounded authenticated audit pages preserve sequence ordering and reject regressing storage positions while the caller verifies both captured signed chain heads
fn scan_table_pages(
    keys: &KeyDeriver,
    table: TableId,
    mut read: impl FnMut(ReadPlan) -> Result<agenc_ircd_storage::ReadResult, RuntimeError>,
    mut visit: impl FnMut(u64, u16, &[u8]) -> Result<(), RuntimeError>,
) -> Result<u64, RuntimeError> {
    let mut start = 0_u64;
    let end = StoredKey::new(vec![0xff; 9])?;
    let mut expected_commit = None;
    loop {
        let plan = ReadPlan::range(
            table,
            StoredKey::new(start.to_be_bytes().to_vec())?,
            StoredKey::new(end.as_bytes().to_vec())?,
            RANGE_READ_LIMIT,
        )?;
        let result = read(plan)?;
        match expected_commit {
            None => expected_commit = Some(result.storage_commit_sequence),
            Some(expected) if expected <= result.storage_commit_sequence => {
                expected_commit = Some(result.storage_commit_sequence);
            }
            Some(_) => return Err(RuntimeError::InvalidValue),
        }
        let count = result.records.len();
        if count > usize::from(RANGE_READ_LIMIT) {
            return Err(RuntimeError::LimitExceeded);
        }
        let truncated = result.truncated;
        let mut last = None;
        for record in result.records {
            if record.table != table {
                return Err(RuntimeError::InvalidValue);
            }
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
            if !mixed::permitted_kind(table, value.record_kind())
                || value.revision() != expected_revision
                || value.generation() != 0
                || value.expires_at().is_some()
                || !value.references().is_empty()
            {
                return Err(RuntimeError::InvalidValue);
            }
            visit(sequence, value.record_kind(), value.body())?;
            last = Some(sequence);
        }
        // A page may stop short of the row limit at the storage byte budget,
        // so the store's own truncation flag decides whether rows remain.
        let Some(last) = last else {
            if truncated {
                return Err(RuntimeError::InvalidValue);
            }
            break;
        };
        if !truncated || last == u64::MAX {
            break;
        }
        start = last.checked_add(1).ok_or(RuntimeError::Overflow)?;
    }
    expected_commit.ok_or(RuntimeError::InvalidValue)
}

fn sequence_key(key: &StoredKey) -> Result<u64, RuntimeError> {
    let bytes: [u8; 8] = key
        .as_bytes()
        .try_into()
        .map_err(|_| RuntimeError::InvalidValue)?;
    Ok(u64::from_be_bytes(bytes))
}

#[cfg(test)]
fn verify_checkpoints(
    binding: AdminSessionBinding,
    trust: &AuditTrust,
    checkpoints: &[AdminAuditCheckpoint],
) -> Result<(AuditChainCursor, u64, [u8; 32]), RuntimeError> {
    let mut verifier = CheckpointVerifier::new(binding, trust);
    for checkpoint in checkpoints {
        verifier.observe(checkpoint)?;
    }
    let verified = verifier.finish();
    Ok((
        verified.cursor,
        verified.next_sequence,
        verified.previous_hash,
    ))
}

struct CheckpointVerification {
    cursor: AuditChainCursor,
    next_sequence: u64,
    previous_hash: [u8; 32],
    latest_created_at: u64,
}

struct CheckpointVerifier<'a> {
    binding: AdminSessionBinding,
    trust: &'a AuditTrust,
    next_sequence: u64,
    next_deleted: u64,
    previous_hash: [u8; 32],
    cursor: AuditChainCursor,
    latest_created_at: u64,
}

impl<'a> CheckpointVerifier<'a> {
    const fn new(binding: AdminSessionBinding, trust: &'a AuditTrust) -> Self {
        Self {
            binding,
            trust,
            next_sequence: 0,
            next_deleted: 0,
            previous_hash: [0; 32],
            cursor: AuditChainCursor::genesis(),
            latest_created_at: 0,
        }
    }

    fn observe(&mut self, checkpoint: &AdminAuditCheckpoint) -> Result<(), RuntimeError> {
        let tbs = checkpoint.tbs();
        if tbs.network_id != self.binding.network_id
            || tbs.server_id != self.binding.server_id
            || tbs.checkpoint_sequence != self.next_sequence
            || tbs.deleted_first_sequence != self.next_deleted
            || tbs.previous_checkpoint_hash != self.previous_hash
        {
            return Err(RuntimeError::InvalidValue);
        }
        let key = self
            .trust
            .resolve(tbs.audit_signing_key_id, tbs.created_at)?;
        checkpoint
            .verify(key)
            .map_err(|_| RuntimeError::InvalidValue)?;
        self.cursor = AuditChainCursor::after_checkpoint(tbs);
        self.next_deleted = tbs.next_retained_sequence;
        self.previous_hash = checkpoint.checkpoint_hash();
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(RuntimeError::Overflow)?;
        self.latest_created_at = self.latest_created_at.max(tbs.created_at);
        Ok(())
    }

    const fn finish(self) -> CheckpointVerification {
        CheckpointVerification {
            cursor: self.cursor,
            next_sequence: self.next_sequence,
            previous_hash: self.previous_hash,
            latest_created_at: self.latest_created_at,
        }
    }
}

// agenc-review: focus owner=runtime reviewed=2026-08-30 reason=single gapless verification pass binds trust signatures hashes chain position and intent outcome pairing
#[cfg(test)]
fn verify_events(
    binding: AdminSessionBinding,
    trust: &AuditTrust,
    operators: &OperatorRegistry,
    cursor: AuditChainCursor,
    events: &[AdminAuditEvent],
) -> Result<(AuditChainCursor, AdminPolicySeed), RuntimeError> {
    let mut verifier = EventVerifier::new(binding, trust, operators, cursor);
    for event in events {
        verifier.observe(event)?;
    }
    let verified = verifier.finish_reconciled()?;
    Ok((verified.cursor, verified.policy))
}

struct EventVerification {
    cursor: AuditChainCursor,
    policy: AdminPolicySeed,
    latest_created_at: u64,
    pending_startup_action: Option<PendingStartupAction>,
}

struct EventVerifier<'a> {
    binding: AdminSessionBinding,
    trust: &'a AuditTrust,
    operators: &'a OperatorRegistry,
    cursor: AuditChainCursor,
    unmatched_intent: Option<PendingStartupAction>,
    policy: AdminPolicySeed,
    latest_created_at: u64,
}

impl<'a> EventVerifier<'a> {
    fn new(
        binding: AdminSessionBinding,
        trust: &'a AuditTrust,
        operators: &'a OperatorRegistry,
        cursor: AuditChainCursor,
    ) -> Self {
        Self {
            binding,
            trust,
            operators,
            cursor,
            unmatched_intent: None,
            policy: AdminPolicySeed::default(),
            latest_created_at: 0,
        }
    }

    fn observe(&mut self, event: &AdminAuditEvent) -> Result<(), RuntimeError> {
        let parsed = self.verify_event(event)?;
        self.cursor = self
            .cursor
            .advance(event)
            .map_err(|_| RuntimeError::InvalidValue)?;
        self.observe_phase(event, &parsed)?;
        self.latest_created_at = self.latest_created_at.max(event.tbs().created_at);
        Ok(())
    }

    fn verify_event(&self, event: &AdminAuditEvent) -> Result<AdminCommand, RuntimeError> {
        let tbs = event.tbs();
        if tbs.network_id != self.binding.network_id
            || tbs.server_id != self.binding.server_id
            || tbs.command_tbs.network_id() != self.binding.network_id
            || tbs.command_tbs.server_id() != self.binding.server_id
        {
            return Err(RuntimeError::InvalidValue);
        }
        let audit_key = self
            .trust
            .resolve(tbs.audit_signing_key_id, tbs.created_at)?;
        let operator_key = self
            .operators
            .verification_key(tbs.operator_id)
            .map_err(|_| RuntimeError::InvalidValue)?;
        event
            .verify(audit_key, operator_key)
            .map_err(|_| RuntimeError::InvalidValue)?;
        let parsed = parse_event_command(event)?;
        if !super::audit_phase_is_valid(&parsed, tbs.phase) {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(parsed)
    }

    fn observe_phase(
        &mut self,
        event: &AdminAuditEvent,
        parsed: &AdminCommand,
    ) -> Result<(), RuntimeError> {
        let tbs = event.tbs();
        if self.unmatched_intent.is_some()
            && !matches!(
                tbs.phase,
                AdminAuditPhase::OutcomeSuccess | AdminAuditPhase::OutcomeFailure
            )
        {
            return Err(RuntimeError::InvalidValue);
        }
        match tbs.phase {
            AdminAuditPhase::Intent => self.observe_intent(event, parsed)?,
            AdminAuditPhase::OutcomeSuccess | AdminAuditPhase::OutcomeFailure => {
                self.observe_outcome(event, parsed)?;
            }
            AdminAuditPhase::CommittedMutation => self.policy.observe(event)?,
            AdminAuditPhase::Observed => {}
        }
        Ok(())
    }

    fn observe_intent(
        &mut self,
        event: &AdminAuditEvent,
        parsed: &AdminCommand,
    ) -> Result<(), RuntimeError> {
        if !command_requires_outcome(parsed)? {
            return Ok(());
        }
        if self.unmatched_intent.is_some() {
            return Err(RuntimeError::InvalidValue);
        }
        self.unmatched_intent = Some(PendingStartupAction::from_verified(event, parsed)?);
        Ok(())
    }

    fn observe_outcome(
        &mut self,
        event: &AdminAuditEvent,
        parsed: &AdminCommand,
    ) -> Result<(), RuntimeError> {
        if !command_requires_outcome(parsed)? {
            return Err(RuntimeError::InvalidValue);
        }
        let command = encoded_command(event)?;
        match self.unmatched_intent.take() {
            Some(pending)
                if pending.intent.tbs().operator_id == event.tbs().operator_id
                    && pending.intent.tbs().operator_signature
                        == event.tbs().operator_signature
                    && encoded_command(&pending.intent)? == command =>
            {
                Ok(())
            }
            _ => Err(RuntimeError::InvalidValue),
        }
    }

    fn finish(self) -> EventVerification {
        EventVerification {
            cursor: self.cursor,
            policy: self.policy,
            latest_created_at: self.latest_created_at,
            pending_startup_action: self.unmatched_intent,
        }
    }

    fn finish_reconciled(self) -> Result<EventVerification, RuntimeError> {
        let verified = self.finish();
        if verified.pending_startup_action.is_some() {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(verified)
    }
}

fn parse_event_command(event: &AdminAuditEvent) -> Result<AdminCommand, RuntimeError> {
    let canonical = CanonicalCommand::check(event.tbs().command_tbs.canonical_command())
        .map_err(|_| RuntimeError::InvalidValue)?;
    AdminCommand::parse(canonical).map_err(|_| RuntimeError::InvalidValue)
}

fn encoded_command(event: &AdminAuditEvent) -> Result<Vec<u8>, RuntimeError> {
    event
        .tbs()
        .command_tbs
        .encode()
        .map_err(|_| RuntimeError::InvalidValue)
}

const fn command_requires_outcome(command: &AdminCommand) -> Result<bool, RuntimeError> {
    match command {
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
        AdminAuditCheckpointTbs, AdminAuditEventTbs, AdminCommandEvent, AdminCommandTbs,
        AdminSessionId, ConfirmationState, OperatorRecord,
    };
    use agenc_ircd_crypto::audit_signing_key_id;
    use agenc_ircd_types::{AdminPermission, AdminPermissionSet, NetworkId, OperatorId, ServerId};

    use super::*;

    const CREATED_AT: u64 = 50;

    #[test]
    fn signed_audit_pages_allow_unrelated_commits_and_reject_changed_rows()
    -> crate::test_support::TestResult {
        use agenc_ircd_crypto::{DatabaseBinding, StorageMasterKey};
        use agenc_ircd_storage::{ReadRecord, ReadResult, StorageSealContext};
        use agenc_ircd_types::{DatabaseId, ServerIncarnation};

        let binding = binding();
        let database = DatabaseBinding::new(
            binding.network_id,
            binding.server_id,
            ServerIncarnation::from_bytes([3; 16]),
            DatabaseId::from_bytes([4; 16]),
        );
        let master = StorageMasterKey::from_bytes([7; 32]);
        let keys = KeyDeriver::new(StorageMasterKey::from_bytes([7; 32]), database, 1)?;
        let seal = StorageSealContext::new(&master, database, 1)?;
        let audit_key = Ed25519SecretKey::from_bytes([4; 32]);
        let operator_key = Ed25519SecretKey::from_bytes([5; 32]);
        let operator_id = OperatorId::from_bytes([6; 16]);
        let fixture = EventFixture {
            binding,
            audit_key: &audit_key,
            operator_key: &operator_key,
            operator_id,
        };
        let trust = AuditTrust::new(&[trust_entry(&audit_key)?])?;
        let operators = registry(operator_id, &operator_key)?;
        let first = fixture.event(
            AuditChainCursor::genesis(),
            0,
            AdminAuditPhase::Observed,
            b"MOTD",
        )?;
        let second = fixture.event(
            AuditChainCursor::genesis().advance(&first)?,
            1,
            AdminAuditPhase::Observed,
            b"MOTD",
        )?;
        let expected = AuditChainCursor::genesis()
            .advance(&first)?
            .advance(&second)?;

        for (commits, corrupt, succeeds) in [
            ([10, 11], false, true),
            ([11, 10], false, false),
            ([10, 11], true, false),
        ] {
            let mut pages = Vec::new();
            for (index, event) in [first.clone(), second.clone()].into_iter().enumerate() {
                let key = StoredKey::new(event.tbs().audit_sequence.to_be_bytes().to_vec())?;
                let value = PersistentRecordValue::new(
                    TableId::Audit,
                    1,
                    event.tbs().audit_sequence + 1,
                    0,
                    None,
                    Vec::new(),
                    event.encode()?,
                )?;
                let mut encoded = seal
                    .seal(
                        TableId::Audit,
                        DOMAIN_RECORD_SCHEMA,
                        [u8::try_from(index)?; 24],
                        &key,
                        &value.encode()?,
                    )?
                    .encode()?;
                if corrupt && index == 1 {
                    let last = encoded.last_mut().ok_or(RuntimeError::InvalidValue)?;
                    *last ^= 1;
                }
                pages.push(ReadResult {
                    storage_commit_sequence: *commits
                        .get(index)
                        .ok_or(RuntimeError::InvalidValue)?,
                    records: vec![ReadRecord {
                        table: TableId::Audit,
                        key,
                        sealed_record: encoded,
                    }],
                    truncated: index == 0,
                });
            }
            let mut pages = pages.into_iter();
            let mut verifier =
                EventVerifier::new(binding, &trust, &operators, AuditChainCursor::genesis());
            let outcome = scan_table_pages(
                &keys,
                TableId::Audit,
                |_| pages.next().ok_or(RuntimeError::InvalidValue),
                |_, _, body| {
                    verifier.observe(
                        &AdminAuditEvent::decode_exact(body)
                            .map_err(|_| RuntimeError::InvalidValue)?,
                    )
                },
            );
            assert_eq!(outcome.is_ok(), succeeds);
            if succeeds {
                assert_eq!(outcome?, 11);
                assert_eq!(verifier.finish_reconciled()?.cursor, expected);
                assert!(pages.next().is_none());
            }
        }
        Ok(())
    }

    #[test]
    fn audit_scan_rejects_a_truncated_page_without_progress() -> Result<(), RuntimeError> {
        use agenc_ircd_crypto::{DatabaseBinding, StorageMasterKey};
        use agenc_ircd_types::{DatabaseId, ServerIncarnation};
        let binding = binding();
        let keys = KeyDeriver::new(
            StorageMasterKey::from_bytes([7; 32]),
            DatabaseBinding::new(
                binding.network_id,
                binding.server_id,
                ServerIncarnation::from_bytes([3; 16]),
                DatabaseId::from_bytes([4; 16]),
            ),
            1,
        )?;
        assert!(
            scan_table_pages(
                &keys,
                TableId::Audit,
                |_| Ok(agenc_ircd_storage::ReadResult {
                    storage_commit_sequence: 10,
                    records: Vec::new(),
                    truncated: true
                }),
                |_, _, _| Ok(())
            )
            .is_err()
        );
        Ok(())
    }

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

    // agenc-review: allow owner=runtime reviewed=2026-08-31 reason=negative audit vectors name every independently corrupted binding and signing input at one test boundary
    #[allow(clippy::too_many_arguments)]
    fn signed_event_with(
        outer_binding: AdminSessionBinding,
        command_binding: AdminSessionBinding,
        cursor: AuditChainCursor,
        command_counter: u64,
        phase: AdminAuditPhase,
        command: &[u8],
        declared_audit_key_id: [u8; 32],
        audit_key: &Ed25519SecretKey,
        operator_key: &Ed25519SecretKey,
        operator_id: OperatorId,
    ) -> Result<AdminAuditEvent, RuntimeError> {
        let command_tbs = AdminCommandTbs::new(
            command_binding.network_id,
            command_binding.server_id,
            AdminSessionId::from_bytes([3; 16]),
            command_counter,
            None,
            command,
        )
        .map_err(|_| RuntimeError::InvalidValue)?;
        let operator_signature = command_tbs
            .sign(operator_key)
            .map_err(|_| RuntimeError::InvalidValue)?;
        AdminAuditEvent::sign(
            AdminAuditEventTbs {
                network_id: outer_binding.network_id,
                server_id: outer_binding.server_id,
                audit_signing_key_id: declared_audit_key_id,
                audit_sequence: cursor.next_sequence,
                created_at: CREATED_AT,
                operator_id,
                command_tbs,
                operator_signature,
                phase,
                previous_event_hash: cursor.previous_event_hash,
            },
            audit_key,
        )
        .map_err(|_| RuntimeError::InvalidValue)
    }

    fn command_event(
        binding: AdminSessionBinding,
        operator_key: &Ed25519SecretKey,
        counter: u64,
        command: &[u8],
    ) -> Result<AdminCommandEvent, RuntimeError> {
        let canonical = CanonicalCommand::check(command).map_err(|_| RuntimeError::InvalidValue)?;
        let parsed = AdminCommand::parse(canonical).map_err(|_| RuntimeError::InvalidValue)?;
        let tbs = AdminCommandTbs::new(
            binding.network_id,
            binding.server_id,
            AdminSessionId::from_bytes([3; 16]),
            counter,
            None,
            command,
        )
        .map_err(|_| RuntimeError::InvalidValue)?;
        let operator_signature = tbs
            .sign(operator_key)
            .map_err(|_| RuntimeError::InvalidValue)?;
        Ok(AdminCommandEvent {
            command: parsed,
            counter,
            tbs,
            operator_signature,
            confirmation: ConfirmationState::NotRequired,
        })
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
    fn streaming_verifier_allows_only_one_pending_external_intent() -> Result<(), RuntimeError> {
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
            b"KILL AAAAAAAAAAAAAAAAAAAAAA :policy action",
        )?;
        let cursor = AuditChainCursor::genesis()
            .advance(&first)
            .map_err(|_| RuntimeError::InvalidValue)?;
        let second = fixture.event(cursor, 1, AdminAuditPhase::Intent, b"REHASH :reload now")?;
        let mut verifier =
            EventVerifier::new(binding, &trust, &registry, AuditChainCursor::genesis());
        verifier.observe(&first)?;
        assert!(verifier.observe(&second).is_err());

        let action_observed = fixture.event(
            AuditChainCursor::genesis(),
            2,
            AdminAuditPhase::Observed,
            b"KILL AAAAAAAAAAAAAAAAAAAAAA :policy action",
        )?;
        let mut phase_verifier =
            EventVerifier::new(binding, &trust, &registry, AuditChainCursor::genesis());
        assert!(phase_verifier.observe(&action_observed).is_err());
        Ok(())
    }

    #[test]
    fn trailing_intent_blocks_authority_until_exact_outcome_commits() -> Result<(), RuntimeError> {
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
        let intent = fixture.event(
            AuditChainCursor::genesis(),
            0,
            AdminAuditPhase::Intent,
            b"KILL AAAAAAAAAAAAAAAAAAAAAA :policy action",
        )?;
        let mut verifier =
            EventVerifier::new(binding, &trust, &registry, AuditChainCursor::genesis());
        verifier.observe(&intent)?;
        let verified = verifier.finish();

        let mut authority = AuditAuthority::empty_for_test()?;
        authority.cursor = verified.cursor;
        authority.pending_startup_action = verified.pending_startup_action;
        assert!(!authority.is_reconciled());
        let action = authority
            .take_pending_startup_action()
            .ok_or(RuntimeError::InvalidValue)?;
        assert!(matches!(action.kind(), PendingStartupActionKind::Kill(_)));
        assert!(authority.take_pending_startup_action().is_none());
        assert!(
            authority
                .prepare_startup_outcome(&action, AdminAuditPhase::Observed, CREATED_AT)
                .is_err()
        );
        let outcome = authority.prepare_startup_outcome(
            &action,
            AdminAuditPhase::OutcomeSuccess,
            CREATED_AT,
        )?;
        assert_eq!(outcome.tbs().operator_id, intent.tbs().operator_id);
        assert_eq!(
            outcome.tbs().operator_signature,
            intent.tbs().operator_signature
        );
        assert_eq!(outcome.tbs().command_tbs, intent.tbs().command_tbs);
        authority.resolve_committed_startup_action(action, &outcome)?;
        assert!(authority.is_reconciled());
        assert_eq!(authority.cursor.next_sequence, 2);
        Ok(())
    }

    #[test]
    fn outcome_cannot_close_another_operators_intent() -> Result<(), RuntimeError> {
        let binding = binding();
        let audit_key = Ed25519SecretKey::from_bytes([4; 32]);
        let first_operator_key = Ed25519SecretKey::from_bytes([5; 32]);
        let second_operator_key = Ed25519SecretKey::from_bytes([8; 32]);
        let first_operator = OperatorId::from_bytes([6; 16]);
        let second_operator = OperatorId::from_bytes([7; 16]);
        let mut permissions = AdminPermissionSet::EMPTY;
        permissions.insert(AdminPermission::Observe);
        let records = [
            (first_operator, &first_operator_key, 1_000),
            (second_operator, &second_operator_key, 1_001),
        ]
        .into_iter()
        .map(|(operator_id, operator_key, uid)| {
            OperatorRecord::new(
                operator_id,
                operator_key.public_key(),
                None,
                vec![uid],
                Vec::new(),
                permissions,
                false,
            )
            .map_err(|_| RuntimeError::InvalidValue)
        })
        .collect::<Result<Vec<_>, _>>()?;
        let registry =
            OperatorRegistry::from_records(records).map_err(|_| RuntimeError::InvalidValue)?;
        let trust = AuditTrust::new(&[trust_entry(&audit_key)?])?;
        let first = EventFixture {
            binding,
            audit_key: &audit_key,
            operator_key: &first_operator_key,
            operator_id: first_operator,
        };
        let intent = first.event(
            AuditChainCursor::genesis(),
            0,
            AdminAuditPhase::Intent,
            b"KILL AAAAAAAAAAAAAAAAAAAAAA :policy action",
        )?;
        let cursor = AuditChainCursor::genesis()
            .advance(&intent)
            .map_err(|_| RuntimeError::InvalidValue)?;
        let second = EventFixture {
            binding,
            audit_key: &audit_key,
            operator_key: &second_operator_key,
            operator_id: second_operator,
        };
        let outcome = second.event(
            cursor,
            0,
            AdminAuditPhase::OutcomeSuccess,
            b"KILL AAAAAAAAAAAAAAAAAAAAAA :policy action",
        )?;
        let mut verifier =
            EventVerifier::new(binding, &trust, &registry, AuditChainCursor::genesis());
        verifier.observe(&intent)?;
        assert!(verifier.observe(&outcome).is_err());
        Ok(())
    }

    #[test]
    fn prepared_export_verifies_and_includes_its_own_observed_event() -> Result<(), RuntimeError> {
        let binding = binding();
        let audit_key = Ed25519SecretKey::from_bytes([4; 32]);
        let operator_key = Ed25519SecretKey::from_bytes([5; 32]);
        let operator_id = OperatorId::from_bytes([6; 16]);
        let operators = registry(operator_id, &operator_key)?;
        let trust = AuditTrust::new(&[trust_entry(&audit_key)?])?;
        let fixture = EventFixture {
            binding,
            audit_key: &audit_key,
            operator_key: &operator_key,
            operator_id,
        };
        let range = AuditRange::new(0, 0).map_err(|_| RuntimeError::InvalidValue)?;
        let observed = fixture.event(
            AuditChainCursor::genesis(),
            0,
            AdminAuditPhase::Observed,
            b"AUDIT EXPORT 0 0",
        )?;
        let prepared = PreparedAuditExport {
            binding,
            trust,
            operators,
            range,
            batch_id: [0; 16],
            expected_cursor: AuditChainCursor::genesis(),
            selection: ExportSelection::new(range),
        };
        let lines = prepared.finish_with_observed(&observed)?;
        assert_eq!(lines.len(), 3);
        assert!(
            lines
                .get(1)
                .is_some_and(|line| line.contains("NOTE AUDIT EVENT"))
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

    #[test]
    fn audit_trust_rejects_every_key_identity_and_window_failure() -> Result<(), RuntimeError> {
        let audit_key = Ed25519SecretKey::from_bytes([7; 32]);
        let entry = trust_entry(&audit_key)?;
        assert!(AuditTrust::new(&[]).is_err());

        let mut wrong_id = entry;
        wrong_id.key_id = [0; 32];
        assert!(AuditTrust::new(&[wrong_id]).is_err());

        let mut empty_window = entry;
        empty_window.not_before = empty_window.not_after;
        assert!(AuditTrust::new(&[empty_window]).is_err());
        assert!(AuditTrust::new(&[entry, entry]).is_err());

        let trust = AuditTrust::new(&[entry])?;
        assert_eq!(
            trust.resolve(entry.key_id, CREATED_AT)?,
            audit_key.public_key()
        );
        assert!(trust.resolve([9; 32], CREATED_AT).is_err());
        assert!(trust.resolve(entry.key_id, entry.not_before - 1).is_err());
        assert!(trust.resolve(entry.key_id, entry.not_after).is_err());
        Ok(())
    }

    #[test]
    fn checkpoint_verification_rejects_every_chain_and_signature_mismatch()
    -> Result<(), RuntimeError> {
        let binding = binding();
        let audit_key = Ed25519SecretKey::from_bytes([7; 32]);
        let other_key = Ed25519SecretKey::from_bytes([8; 32]);
        let entry = trust_entry(&audit_key)?;
        let trust = AuditTrust::new(&[entry])?;
        let baseline_tbs = AdminAuditCheckpointTbs {
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
        };
        let baseline = AdminAuditCheckpoint::sign(baseline_tbs, &audit_key)
            .map_err(|_| RuntimeError::InvalidValue)?;

        for changed in [
            AdminAuditCheckpointTbs {
                network_id: NetworkId::from_bytes([9; 32]),
                ..baseline_tbs
            },
            AdminAuditCheckpointTbs {
                server_id: ServerId::from_bytes([9; 16]),
                ..baseline_tbs
            },
            AdminAuditCheckpointTbs {
                checkpoint_sequence: 1,
                ..baseline_tbs
            },
            AdminAuditCheckpointTbs {
                deleted_first_sequence: 1,
                deleted_count: 4,
                ..baseline_tbs
            },
        ] {
            let checkpoint = AdminAuditCheckpoint::sign(changed, &audit_key)
                .map_err(|_| RuntimeError::InvalidValue)?;
            assert!(verify_checkpoints(binding, &trust, &[checkpoint]).is_err());
        }

        let wrong_signature = AdminAuditCheckpoint::sign(baseline_tbs, &other_key)
            .map_err(|_| RuntimeError::InvalidValue)?;
        assert!(verify_checkpoints(binding, &trust, &[wrong_signature]).is_err());

        let unknown_key_tbs = AdminAuditCheckpointTbs {
            audit_signing_key_id: [9; 32],
            ..baseline_tbs
        };
        let unknown_key = AdminAuditCheckpoint::sign(unknown_key_tbs, &audit_key)
            .map_err(|_| RuntimeError::InvalidValue)?;
        assert!(verify_checkpoints(binding, &trust, &[unknown_key]).is_err());

        let second_tbs = AdminAuditCheckpointTbs {
            checkpoint_sequence: 1,
            deleted_first_sequence: 5,
            deleted_last_sequence: 5,
            deleted_count: 1,
            deleted_last_event_hash: [10; 32],
            next_retained_sequence: 6,
            previous_checkpoint_hash: baseline.checkpoint_hash(),
            ..baseline_tbs
        };
        let second = AdminAuditCheckpoint::sign(second_tbs, &audit_key)
            .map_err(|_| RuntimeError::InvalidValue)?;
        let (cursor, next, previous) = verify_checkpoints(binding, &trust, &[baseline, second])?;
        assert_eq!(cursor.next_sequence, 6);
        assert_eq!(next, 2);
        assert_eq!(previous, second.checkpoint_hash());

        let wrong_deleted = AdminAuditCheckpoint::sign(
            AdminAuditCheckpointTbs {
                deleted_first_sequence: 6,
                deleted_last_sequence: 6,
                next_retained_sequence: 7,
                ..second_tbs
            },
            &audit_key,
        )
        .map_err(|_| RuntimeError::InvalidValue)?;
        assert!(verify_checkpoints(binding, &trust, &[baseline, wrong_deleted]).is_err());

        let wrong_previous = AdminAuditCheckpoint::sign(
            AdminAuditCheckpointTbs {
                previous_checkpoint_hash: [11; 32],
                ..second_tbs
            },
            &audit_key,
        )
        .map_err(|_| RuntimeError::InvalidValue)?;
        assert!(verify_checkpoints(binding, &trust, &[baseline, wrong_previous]).is_err());
        Ok(())
    }

    #[test]
    fn event_verification_rejects_every_binding_authority_signature_and_chain_failure()
    -> Result<(), RuntimeError> {
        let binding = binding();
        let command_binding = binding;
        let audit_key = Ed25519SecretKey::from_bytes([4; 32]);
        let other_audit_key = Ed25519SecretKey::from_bytes([8; 32]);
        let operator_key = Ed25519SecretKey::from_bytes([5; 32]);
        let other_operator_key = Ed25519SecretKey::from_bytes([9; 32]);
        let operator_id = OperatorId::from_bytes([6; 16]);
        let registry = registry(operator_id, &operator_key)?;
        let entry = trust_entry(&audit_key)?;
        let trust = AuditTrust::new(&[entry])?;
        let cursor = AuditChainCursor::genesis();

        let valid = signed_event_with(
            binding,
            command_binding,
            cursor,
            0,
            AdminAuditPhase::Observed,
            b"MOTD",
            entry.key_id,
            &audit_key,
            &operator_key,
            operator_id,
        )?;
        assert!(verify_events(binding, &trust, &registry, cursor, &[valid]).is_ok());

        let wrong_outer_bindings = [
            AdminSessionBinding {
                network_id: NetworkId::from_bytes([9; 32]),
                ..binding
            },
            AdminSessionBinding {
                server_id: ServerId::from_bytes([9; 16]),
                ..binding
            },
        ];
        for outer in wrong_outer_bindings {
            let event = signed_event_with(
                outer,
                command_binding,
                cursor,
                0,
                AdminAuditPhase::Observed,
                b"MOTD",
                entry.key_id,
                &audit_key,
                &operator_key,
                operator_id,
            )?;
            assert!(verify_events(binding, &trust, &registry, cursor, &[event]).is_err());
        }

        let wrong_command_bindings = [
            AdminSessionBinding {
                network_id: NetworkId::from_bytes([9; 32]),
                ..binding
            },
            AdminSessionBinding {
                server_id: ServerId::from_bytes([9; 16]),
                ..binding
            },
        ];
        for command_binding in wrong_command_bindings {
            let event = signed_event_with(
                binding,
                command_binding,
                cursor,
                0,
                AdminAuditPhase::Observed,
                b"MOTD",
                entry.key_id,
                &audit_key,
                &operator_key,
                operator_id,
            )?;
            assert!(verify_events(binding, &trust, &registry, cursor, &[event]).is_err());
        }

        let unknown_audit_key = signed_event_with(
            binding,
            binding,
            cursor,
            0,
            AdminAuditPhase::Observed,
            b"MOTD",
            [11; 32],
            &audit_key,
            &operator_key,
            operator_id,
        )?;
        assert!(verify_events(binding, &trust, &registry, cursor, &[unknown_audit_key]).is_err());

        let unknown_operator = signed_event_with(
            binding,
            binding,
            cursor,
            0,
            AdminAuditPhase::Observed,
            b"MOTD",
            entry.key_id,
            &audit_key,
            &operator_key,
            OperatorId::from_bytes([12; 16]),
        )?;
        assert!(verify_events(binding, &trust, &registry, cursor, &[unknown_operator]).is_err());

        let wrong_audit_signature = signed_event_with(
            binding,
            binding,
            cursor,
            0,
            AdminAuditPhase::Observed,
            b"MOTD",
            entry.key_id,
            &other_audit_key,
            &operator_key,
            operator_id,
        )?;
        assert!(
            verify_events(binding, &trust, &registry, cursor, &[wrong_audit_signature]).is_err()
        );

        let wrong_operator_signature = signed_event_with(
            binding,
            binding,
            cursor,
            0,
            AdminAuditPhase::Observed,
            b"MOTD",
            entry.key_id,
            &audit_key,
            &other_operator_key,
            operator_id,
        )?;
        assert!(
            verify_events(
                binding,
                &trust,
                &registry,
                cursor,
                &[wrong_operator_signature],
            )
            .is_err()
        );

        for broken_cursor in [
            AuditChainCursor {
                next_sequence: 1,
                ..cursor
            },
            AuditChainCursor {
                previous_event_hash: [13; 32],
                ..cursor
            },
        ] {
            let event = signed_event_with(
                binding,
                binding,
                broken_cursor,
                0,
                AdminAuditPhase::Observed,
                b"MOTD",
                entry.key_id,
                &audit_key,
                &operator_key,
                operator_id,
            )?;
            assert!(verify_events(binding, &trust, &registry, cursor, &[event]).is_err());
        }
        Ok(())
    }

    #[test]
    fn audit_mutations_rebuild_policy_and_reject_invalid_phase_pairings() -> Result<(), RuntimeError>
    {
        let binding = binding();
        let audit_key = Ed25519SecretKey::from_bytes([4; 32]);
        let operator_key = Ed25519SecretKey::from_bytes([5; 32]);
        let operator_id = OperatorId::from_bytes([6; 16]);
        let registry = registry(operator_id, &operator_key)?;
        let entry = trust_entry(&audit_key)?;
        let trust = AuditTrust::new(&[entry])?;
        let fixture = EventFixture {
            binding,
            audit_key: &audit_key,
            operator_key: &operator_key,
            operator_id,
        };
        let account = "a_AAAAAAAAAAAAAAAAAAAAAA";
        let channel = "AAAAAAAAAAAAAAAAAAAAAA";
        let commands = [
            format!("ACCOUNT SUSPEND {account} 60 :policy action"),
            format!("ACCOUNT RESTORE {account} :policy action"),
            format!("CHANNEL QUARANTINE {channel} :policy action"),
        ];
        let mut cursor = AuditChainCursor::genesis();
        let mut events = Vec::new();
        for (counter, command) in commands.iter().enumerate() {
            let counter = u64::try_from(counter).map_err(|_| RuntimeError::Overflow)?;
            let event = fixture.event(
                cursor,
                counter,
                AdminAuditPhase::CommittedMutation,
                command.as_bytes(),
            )?;
            cursor = cursor
                .advance(&event)
                .map_err(|_| RuntimeError::InvalidValue)?;
            events.push(event);
        }
        let (_, policy) = verify_events(
            binding,
            &trust,
            &registry,
            AuditChainCursor::genesis(),
            &events,
        )?;
        let (suspensions, quarantines) = policy.into_parts();
        assert!(suspensions.is_empty());
        assert_eq!(quarantines.len(), 1);

        let invalid_mutation = fixture.event(
            AuditChainCursor::genesis(),
            4,
            AdminAuditPhase::CommittedMutation,
            b"MOTD",
        )?;
        assert!(
            verify_events(
                binding,
                &trust,
                &registry,
                AuditChainCursor::genesis(),
                &[invalid_mutation],
            )
            .is_err()
        );

        let orphan = fixture.event(
            AuditChainCursor::genesis(),
            5,
            AdminAuditPhase::OutcomeFailure,
            b"BACKUP CREATE :nightly run",
        )?;
        assert!(
            verify_events(
                binding,
                &trust,
                &registry,
                AuditChainCursor::genesis(),
                &[orphan],
            )
            .is_err()
        );

        let first = fixture.event(
            AuditChainCursor::genesis(),
            6,
            AdminAuditPhase::Intent,
            b"REHASH :reload now",
        )?;
        let second_cursor = AuditChainCursor::genesis()
            .advance(&first)
            .map_err(|_| RuntimeError::InvalidValue)?;
        let duplicate = fixture.event(
            second_cursor,
            6,
            AdminAuditPhase::Intent,
            b"REHASH :reload now",
        )?;
        assert!(
            verify_events(
                binding,
                &trust,
                &registry,
                AuditChainCursor::genesis(),
                &[first, duplicate],
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn retention_selection_and_export_coverage_are_total_and_gapless() -> Result<(), RuntimeError> {
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
        assert_eq!(
            select_expired_prefix(std::slice::from_ref(&observed), CREATED_AT)?,
            None
        );
        assert_eq!(
            select_expired_prefix(std::slice::from_ref(&observed), CREATED_AT + 1)?,
            Some((0, observed.event_hash()))
        );

        let orphan_outcome = fixture.event(
            AuditChainCursor::genesis(),
            1,
            AdminAuditPhase::OutcomeFailure,
            b"BACKUP CREATE :nightly run",
        )?;
        assert!(select_expired_prefix(&[orphan_outcome], CREATED_AT + 1).is_err());

        let invalid_intent = fixture.event(
            AuditChainCursor::genesis(),
            2,
            AdminAuditPhase::Intent,
            b"MOTD",
        )?;
        assert!(select_expired_prefix(&[invalid_intent], CREATED_AT + 1).is_err());

        let observed = AuditEvent::Admin(observed);
        let range = AuditRange::new(0, 0).map_err(|_| RuntimeError::InvalidValue)?;
        assert!(verify_export_coverage(range, 0, &[], &[]).is_ok());
        assert!(verify_export_coverage(range, 0, &[], std::slice::from_ref(&observed)).is_err());
        assert!(verify_export_coverage(range, 1, &[], std::slice::from_ref(&observed)).is_ok());
        assert!(
            verify_export_coverage(range, 1, &[], &[observed.clone(), observed.clone()]).is_err()
        );

        let entry = trust_entry(&audit_key)?;
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
        let event_five = fixture.event(
            AuditChainCursor {
                previous_event_hash: checkpoint.tbs().deleted_last_event_hash,
                next_sequence: 5,
            },
            3,
            AdminAuditPhase::Observed,
            b"MOTD",
        )?;
        let full = AuditRange::new(0, 5).map_err(|_| RuntimeError::InvalidValue)?;
        assert!(
            verify_export_coverage(full, 6, &[checkpoint], &[AuditEvent::Admin(event_five)])
                .is_ok()
        );
        assert!(verify_export_coverage(full, 6, &[checkpoint], &[]).is_err());

        let disjoint = AuditRange::new(5, 5).map_err(|_| RuntimeError::InvalidValue)?;
        assert!(verify_export_coverage(disjoint, 6, &[checkpoint], &[]).is_err());
        Ok(())
    }

    #[test]
    fn authority_checks_event_and_retention_fences_before_advancing() -> Result<(), RuntimeError> {
        let binding = binding();
        let operator_key = Ed25519SecretKey::from_bytes([5; 32]);
        let operator_id = OperatorId::from_bytes([6; 16]);
        let command = command_event(binding, &operator_key, 0, b"MOTD")?;
        let mut authority = AuditAuthority::empty_for_test()?;
        assert!(authority.is_reconciled());
        assert!(
            authority
                .prepare_export(
                    AuditRange::new(0, 0).map_err(|_| RuntimeError::InvalidValue)?,
                    [0; 16]
                )
                .is_err()
        );
        assert!(authority.prepare_retention(CREATED_AT, 1).is_err());

        let mut invalid = AuditAuthority::empty_for_test()?;
        invalid.reconciled = false;
        assert!(!invalid.is_reconciled());
        assert!(
            invalid
                .prepare_event(
                    binding,
                    operator_id,
                    &command,
                    AdminAuditPhase::Observed,
                    CREATED_AT,
                )
                .is_err()
        );

        let mut wrong_key_id = AuditAuthority::empty_for_test()?;
        wrong_key_id.signing_key_id = [1; 32];
        assert!(!wrong_key_id.is_reconciled());
        let mut wrong_checkpoint_position = AuditAuthority::empty_for_test()?;
        wrong_checkpoint_position.previous_checkpoint_hash = [2; 32];
        assert!(!wrong_checkpoint_position.is_reconciled());
        let mut wrong_event_position = AuditAuthority::empty_for_test()?;
        wrong_event_position.cursor.previous_event_hash = [3; 32];
        assert!(!wrong_event_position.is_reconciled());

        authority.signing_not_before = 10;
        authority.signing_not_after = 100;
        assert!(
            authority
                .prepare_event(binding, operator_id, &command, AdminAuditPhase::Observed, 9,)
                .is_err()
        );
        assert!(
            authority
                .prepare_event(
                    binding,
                    operator_id,
                    &command,
                    AdminAuditPhase::Observed,
                    100,
                )
                .is_err()
        );
        let wrong_binding = AdminSessionBinding {
            network_id: NetworkId::from_bytes([9; 32]),
            ..binding
        };
        assert!(
            authority
                .prepare_event(
                    wrong_binding,
                    operator_id,
                    &command,
                    AdminAuditPhase::Observed,
                    CREATED_AT,
                )
                .is_err()
        );

        let event = authority.prepare_event(
            binding,
            operator_id,
            &command,
            AdminAuditPhase::Observed,
            CREATED_AT,
        )?;
        authority.commit_event(&event)?;
        assert_eq!(authority.cursor.next_sequence, 1);
        assert!(authority.commit_event(&event).is_err());

        let checkpoint_tbs = AdminAuditCheckpointTbs {
            network_id: binding.network_id,
            server_id: binding.server_id,
            audit_signing_key_id: authority.signing_key_id,
            checkpoint_sequence: 0,
            created_at: CREATED_AT,
            deleted_first_sequence: 0,
            deleted_last_sequence: 0,
            deleted_count: 1,
            deleted_last_event_hash: event.event_hash(),
            next_retained_sequence: 1,
            previous_checkpoint_hash: [0; 32],
        };
        for changed in [
            AdminAuditCheckpointTbs {
                audit_signing_key_id: [4; 32],
                ..checkpoint_tbs
            },
            AdminAuditCheckpointTbs {
                created_at: 9,
                ..checkpoint_tbs
            },
            AdminAuditCheckpointTbs {
                created_at: 100,
                ..checkpoint_tbs
            },
            AdminAuditCheckpointTbs {
                checkpoint_sequence: 1,
                ..checkpoint_tbs
            },
            AdminAuditCheckpointTbs {
                deleted_first_sequence: 1,
                ..checkpoint_tbs
            },
            AdminAuditCheckpointTbs {
                previous_checkpoint_hash: [5; 32],
                ..checkpoint_tbs
            },
            AdminAuditCheckpointTbs {
                next_retained_sequence: 2,
                ..checkpoint_tbs
            },
        ] {
            assert!(authority.sign_retention(changed).is_err());
        }

        let other_key = Ed25519SecretKey::from_bytes([8; 32]);
        let wrong_signature = AdminAuditCheckpoint::sign(checkpoint_tbs, &other_key)
            .map_err(|_| RuntimeError::InvalidValue)?;
        assert!(authority.commit_retention(&wrong_signature).is_err());

        let checkpoint = authority.sign_retention(checkpoint_tbs)?;
        authority.commit_retention(&checkpoint)?;
        assert_eq!(authority.retained_first_sequence, 1);
        assert_eq!(authority.next_checkpoint_sequence, 1);
        assert_eq!(
            authority.previous_checkpoint_hash,
            checkpoint.checkpoint_hash()
        );
        assert!(authority.commit_retention(&checkpoint).is_err());
        Ok(())
    }
}
