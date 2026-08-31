//! Startup reconstruction and append cursor for the signed admin audit chain.

use std::collections::BTreeMap;

use agenc_ircd_admin::{
    AdminAuditCheckpoint, AdminAuditEvent, AdminAuditEventTbs, AdminAuditPhase, AdminCommandEvent,
    AdminSessionBinding, AuditChainCursor, OperatorRegistry,
};
use agenc_ircd_config::AuditTrustManifestEntry;
use agenc_ircd_crypto::{Ed25519PublicKey, Ed25519SecretKey, audit_signing_key_id};
use agenc_ircd_storage::{
    PersistentRecordValue, ReadPlan, SealedRecord, StoragePort, StoredKey, TableId,
    validate_record_plaintext,
};
use agenc_ircd_types::OperatorId;

use crate::RuntimeError;
use crate::state_core::durable::{DOMAIN_RECORD_SCHEMA, KeyDeriver};

const RANGE_READ_LIMIT: u16 = 4_096;

/// Verified audit authority transferred into the sole `AdminOwner`.
pub(crate) struct AuditAuthority {
    signing_key: Ed25519SecretKey,
    signing_key_id: [u8; 32],
    signing_not_before: u64,
    signing_not_after: u64,
    cursor: AuditChainCursor,
    next_checkpoint_sequence: u64,
    previous_checkpoint_hash: [u8; 32],
    reconciled: bool,
}

impl AuditAuthority {
    /// Reconstructs both signed tables before any administrative authority is
    /// accepted. Stored keys, envelopes, trust windows, signatures, chains,
    /// checkpoint coverage, and retained intents are all verified here.
    pub(crate) fn reconstruct(
        binding: AdminSessionBinding,
        signing_key: Ed25519SecretKey,
        trust_entries: &[AuditTrustManifestEntry],
        storage: &StoragePort,
        keys: &KeyDeriver,
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

        let checkpoints = read_checkpoints(storage, keys)?;
        let (checkpoint_cursor, next_checkpoint_sequence, previous_checkpoint_hash) =
            verify_checkpoints(binding, &trust, &checkpoints)?;
        let events = read_events(storage, keys)?;
        let cursor = verify_events(binding, &trust, operators, checkpoint_cursor, &events)?;

        Ok(Self {
            signing_key,
            signing_key_id,
            signing_not_before: current.not_before,
            signing_not_after: current.not_after,
            cursor,
            next_checkpoint_sequence,
            previous_checkpoint_hash,
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
            next_checkpoint_sequence: 0,
            previous_checkpoint_hash: [0; 32],
            reconciled: true,
        })
    }
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
) -> Result<Vec<AdminAuditCheckpoint>, RuntimeError> {
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
) -> Result<Vec<AdminAuditEvent>, RuntimeError> {
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
) -> Result<Vec<T>, RuntimeError> {
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
    Ok(output)
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
) -> Result<AuditChainCursor, RuntimeError> {
    let mut unmatched_intents: BTreeMap<Vec<u8>, u64> = BTreeMap::new();
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
                if unmatched_intents
                    .insert(command, tbs.audit_sequence)
                    .is_some()
                {
                    return Err(RuntimeError::InvalidValue);
                }
            }
            AdminAuditPhase::OutcomeSuccess | AdminAuditPhase::OutcomeFailure => {
                unmatched_intents.remove(&command);
            }
            AdminAuditPhase::CommittedMutation | AdminAuditPhase::Observed => {}
        }
    }
    if !unmatched_intents.is_empty() {
        return Err(RuntimeError::InvalidValue);
    }
    Ok(cursor)
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
        let verified = verify_events(
            binding,
            &trust,
            &registry,
            AuditChainCursor::genesis(),
            &[first, outcome],
        )?;
        assert_eq!(verified.next_sequence, 2);
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
