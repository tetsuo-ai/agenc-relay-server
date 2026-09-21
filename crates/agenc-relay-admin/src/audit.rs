//! Section 16.4 signed audit events, checkpoints, the retained chain, and the
//! `AUDIT EXPORT` batch framing (spec 2318-2416, 4521-4541).

mod export;

use agenc_relay_crypto::{
    CryptoError, Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature, SignatureDomain,
    admin_audit_checkpoint_hash, admin_audit_event_hash, sign_canonical, verify_canonical,
};
use agenc_relay_types::{NetworkId, OperatorId, ServerId};

use crate::base64::encode_base64url;
use crate::codec::{Reader, Writer};
use crate::tbs::MAX_TBS_BYTES;
use crate::{
    AdminCommandTbs, AdminError, AuditRange, MAX_AUDIT_EXPORT_BYTES, MAX_AUDIT_EXPORT_RECORDS,
};

/// `profile_version` of both audit structures (spec 2327, 2348).
const AUDIT_VERSION: u16 = 1;
/// `safe_outcome_code<1..64>` ceiling (spec 2336).
const MAX_OUTCOME_CODE_BYTES: usize = 64;
/// Fixed event TBS bytes before the embedded command TBS and after it:
/// version, network, server, key id, sequence, created_at, operator id,
/// operator signature, phase, one-byte code length, previous hash.
const EVENT_TBS_FIXED_BYTES: usize = 2 + 32 + 16 + 32 + 8 + 8 + 16 + 64 + 1 + 1 + 32;
/// Largest event TBS encoding.
const MAX_EVENT_TBS_BYTES: usize = EVENT_TBS_FIXED_BYTES + MAX_TBS_BYTES + MAX_OUTCOME_CODE_BYTES;
/// Largest complete `AdminAuditEvent` encoding: TBS, hash, signature.
pub const MAX_AUDIT_EVENT_BYTES: usize = MAX_EVENT_TBS_BYTES + 32 + 64;
/// Exact `AdminAuditCheckpointTBS` size (spec 2346-2359).
const CHECKPOINT_TBS_BYTES: usize = 2 + 32 + 16 + 32 + 8 + 8 + 8 + 8 + 8 + 32 + 8 + 32;
/// Exact complete `AdminAuditCheckpoint` size: TBS, hash, signature.
const CHECKPOINT_BYTES: usize = CHECKPOINT_TBS_BYTES + 32 + 64;

/// `AdminAuditPhase` (spec 2321-2323).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminAuditPhase {
    /// A durable mutation committed in the same transaction.
    CommittedMutation = 1,
    /// A signed intent recorded before an external action.
    Intent = 2,
    /// The external action succeeded.
    OutcomeSuccess = 3,
    /// The external action failed.
    OutcomeFailure = 4,
    /// A read-only command succeeded.
    Observed = 5,
}

impl AdminAuditPhase {
    /// Returns the wire value.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::CommittedMutation => 1,
            Self::Intent => 2,
            Self::OutcomeSuccess => 3,
            Self::OutcomeFailure => 4,
            Self::Observed => 5,
        }
    }

    /// Parses the wire value.
    pub const fn from_u8(value: u8) -> Result<Self, AdminError> {
        match value {
            1 => Ok(Self::CommittedMutation),
            2 => Ok(Self::Intent),
            3 => Ok(Self::OutcomeSuccess),
            4 => Ok(Self::OutcomeFailure),
            5 => Ok(Self::Observed),
            _ => Err(AdminError::Audit),
        }
    }

    /// The closed `safe_outcome_code` for this phase (spec 2382-2386).
    #[must_use]
    pub const fn safe_outcome_code(self) -> &'static str {
        match self {
            Self::CommittedMutation => "COMMITTED",
            Self::Intent => "PENDING",
            Self::OutcomeSuccess => "SUCCEEDED",
            Self::OutcomeFailure => "FAILED",
            Self::Observed => "OBSERVED",
        }
    }
}

/// `AdminAuditEventTBS` (spec 2325-2338).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminAuditEventTbs {
    /// Network identity.
    pub network_id: NetworkId,
    /// Server identity.
    pub server_id: ServerId,
    /// `SHA256("agenc-chat audit signing key v1" || public_key)`.
    pub audit_signing_key_id: [u8; 32],
    /// Gapless sequence starting at zero.
    pub audit_sequence: u64,
    /// Unix seconds.
    pub created_at: u64,
    /// The authenticated operator.
    pub operator_id: OperatorId,
    /// The exact signed command structure.
    pub command_tbs: AdminCommandTbs,
    /// The operator signature that verified the command.
    pub operator_signature: Ed25519Signature,
    /// The phase this event records.
    pub phase: AdminAuditPhase,
    /// Hash of the previous event, or 32 zero bytes for sequence zero.
    pub previous_event_hash: [u8; 32],
}

impl AdminAuditEventTbs {
    /// TLS-encodes the structure in field order.
    pub fn encode(&self) -> Result<Vec<u8>, AdminError> {
        let mut writer = Writer::with_ceiling(MAX_EVENT_TBS_BYTES);
        writer.put_u16(AUDIT_VERSION)?;
        writer.put_fixed(self.network_id.as_bytes())?;
        writer.put_fixed(self.server_id.as_bytes())?;
        writer.put_fixed(&self.audit_signing_key_id)?;
        writer.put_u64(self.audit_sequence)?;
        writer.put_u64(self.created_at)?;
        writer.put_fixed(self.operator_id.as_bytes())?;
        writer.put_fixed(&self.command_tbs.encode()?)?;
        writer.put_fixed(self.operator_signature.as_bytes())?;
        writer.put_u8(self.phase.as_u8())?;
        writer.put_vector_u8(self.phase.safe_outcome_code().as_bytes())?;
        writer.put_fixed(&self.previous_event_hash)?;
        Ok(writer.finish())
    }

    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, AdminError> {
        if reader.u16()? != AUDIT_VERSION {
            return Err(AdminError::Audit);
        }
        let network_id = NetworkId::from_bytes(reader.fixed::<32>()?);
        let server_id = ServerId::from_bytes(reader.fixed::<16>()?);
        let audit_signing_key_id = reader.fixed::<32>()?;
        let audit_sequence = reader.u64()?;
        let created_at = reader.u64()?;
        let operator_id = OperatorId::from_bytes(reader.fixed::<16>()?);
        let command_tbs = AdminCommandTbs::decode_from(reader)?;
        let operator_signature = Ed25519Signature::from_bytes(reader.fixed::<64>()?);
        let phase = AdminAuditPhase::from_u8(reader.u8()?)?;
        let code = reader.vector_u8(MAX_OUTCOME_CODE_BYTES)?;
        if code != phase.safe_outcome_code().as_bytes() {
            return Err(AdminError::Audit);
        }
        let previous_event_hash = reader.fixed::<32>()?;
        Ok(Self {
            network_id,
            server_id,
            audit_signing_key_id,
            audit_sequence,
            created_at,
            operator_id,
            command_tbs,
            operator_signature,
            phase,
            previous_event_hash,
        })
    }

    /// Decodes exactly one structure with no trailing bytes.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, AdminError> {
        let mut reader = Reader::new(bytes);
        let tbs = Self::decode_from(&mut reader)?;
        reader.finish()?;
        Ok(tbs)
    }

    /// `SHA256("agenc-chat admin audit event v1" || TLS-encode(tbs))`.
    pub fn hash(&self) -> Result<[u8; 32], AdminError> {
        let encoded = self.encode()?;
        admin_audit_event_hash(&encoded)
            .map(|digest| *digest.as_bytes())
            .map_err(map_crypto)
    }
}

/// A complete signed audit event (spec 2340-2344).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminAuditEvent {
    tbs: AdminAuditEventTbs,
    event_hash: [u8; 32],
    server_signature: Ed25519Signature,
}

impl AdminAuditEvent {
    /// Hashes and signs the structure with the dedicated audit key.
    pub fn sign(tbs: AdminAuditEventTbs, audit_key: &Ed25519SecretKey) -> Result<Self, AdminError> {
        let event_hash = tbs.hash()?;
        let server_signature =
            sign_canonical(audit_key, SignatureDomain::AdminAuditEvent, &event_hash)
                .map_err(map_crypto)?;
        Ok(Self {
            tbs,
            event_hash,
            server_signature,
        })
    }

    /// Borrows the signed structure.
    #[must_use]
    pub const fn tbs(&self) -> &AdminAuditEventTbs {
        &self.tbs
    }

    /// Returns the event hash that later events chain to.
    #[must_use]
    pub const fn event_hash(&self) -> [u8; 32] {
        self.event_hash
    }

    /// Encodes the structure, hash, and signature.
    pub fn encode(&self) -> Result<Vec<u8>, AdminError> {
        let mut writer = Writer::with_ceiling(MAX_AUDIT_EVENT_BYTES);
        writer.put_fixed(&self.tbs.encode()?)?;
        writer.put_fixed(&self.event_hash)?;
        writer.put_fixed(self.server_signature.as_bytes())?;
        Ok(writer.finish())
    }

    /// Decodes exactly one event with no trailing bytes.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, AdminError> {
        let mut reader = Reader::new(bytes);
        let tbs = AdminAuditEventTbs::decode_from(&mut reader)?;
        let event_hash = reader.fixed::<32>()?;
        let server_signature = Ed25519Signature::from_bytes(reader.fixed::<64>()?);
        reader.finish()?;
        Ok(Self {
            tbs,
            event_hash,
            server_signature,
        })
    }

    /// Re-verifies the hash, the server signature, and the embedded operator
    /// signature over the command structure (spec 2374-2379).
    pub fn verify(
        &self,
        audit_key: Ed25519PublicKey,
        operator_key: Ed25519PublicKey,
    ) -> Result<(), AdminError> {
        if self.tbs.hash()? != self.event_hash {
            return Err(AdminError::Audit);
        }
        verify_canonical(
            audit_key,
            SignatureDomain::AdminAuditEvent,
            &self.event_hash,
            self.server_signature,
        )
        .map_err(map_crypto)?;
        self.tbs
            .command_tbs
            .verify(operator_key, self.tbs.operator_signature)
    }
}

/// `AdminAuditCheckpointTBS` (spec 2346-2359).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdminAuditCheckpointTbs {
    /// Network identity.
    pub network_id: NetworkId,
    /// Server identity.
    pub server_id: ServerId,
    /// The audit signing key identifier.
    pub audit_signing_key_id: [u8; 32],
    /// Gapless checkpoint sequence starting at zero.
    pub checkpoint_sequence: u64,
    /// Unix seconds.
    pub created_at: u64,
    /// First deleted event sequence.
    pub deleted_first_sequence: u64,
    /// Last deleted event sequence.
    pub deleted_last_sequence: u64,
    /// `deleted_last_sequence - deleted_first_sequence + 1`.
    pub deleted_count: u64,
    /// Verified hash of the last deleted event.
    pub deleted_last_event_hash: [u8; 32],
    /// `deleted_last_sequence + 1`.
    pub next_retained_sequence: u64,
    /// Hash of the previous checkpoint, or 32 zero bytes for sequence zero.
    pub previous_checkpoint_hash: [u8; 32],
}

impl AdminAuditCheckpointTbs {
    /// Checks the arithmetic relations of spec 2402-2406.
    pub fn validate(&self) -> Result<(), AdminError> {
        if self.deleted_first_sequence > self.deleted_last_sequence {
            return Err(AdminError::Audit);
        }
        let span = self
            .deleted_last_sequence
            .checked_sub(self.deleted_first_sequence)
            .and_then(|span| span.checked_add(1))
            .ok_or(AdminError::Overflow)?;
        let next = self
            .deleted_last_sequence
            .checked_add(1)
            .ok_or(AdminError::Overflow)?;
        if span != self.deleted_count || next != self.next_retained_sequence {
            return Err(AdminError::Audit);
        }
        if self.checkpoint_sequence == 0 && self.previous_checkpoint_hash != [0; 32] {
            return Err(AdminError::Audit);
        }
        Ok(())
    }

    /// TLS-encodes the exact 194-byte structure.
    pub fn encode(&self) -> Result<Vec<u8>, AdminError> {
        let mut writer = Writer::with_ceiling(CHECKPOINT_TBS_BYTES);
        writer.put_u16(AUDIT_VERSION)?;
        writer.put_fixed(self.network_id.as_bytes())?;
        writer.put_fixed(self.server_id.as_bytes())?;
        writer.put_fixed(&self.audit_signing_key_id)?;
        writer.put_u64(self.checkpoint_sequence)?;
        writer.put_u64(self.created_at)?;
        writer.put_u64(self.deleted_first_sequence)?;
        writer.put_u64(self.deleted_last_sequence)?;
        writer.put_u64(self.deleted_count)?;
        writer.put_fixed(&self.deleted_last_event_hash)?;
        writer.put_u64(self.next_retained_sequence)?;
        writer.put_fixed(&self.previous_checkpoint_hash)?;
        Ok(writer.finish())
    }

    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, AdminError> {
        if reader.u16()? != AUDIT_VERSION {
            return Err(AdminError::Audit);
        }
        Ok(Self {
            network_id: NetworkId::from_bytes(reader.fixed::<32>()?),
            server_id: ServerId::from_bytes(reader.fixed::<16>()?),
            audit_signing_key_id: reader.fixed::<32>()?,
            checkpoint_sequence: reader.u64()?,
            created_at: reader.u64()?,
            deleted_first_sequence: reader.u64()?,
            deleted_last_sequence: reader.u64()?,
            deleted_count: reader.u64()?,
            deleted_last_event_hash: reader.fixed::<32>()?,
            next_retained_sequence: reader.u64()?,
            previous_checkpoint_hash: reader.fixed::<32>()?,
        })
    }

    /// Decodes exactly one structure with no trailing bytes.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, AdminError> {
        let mut reader = Reader::new(bytes);
        let tbs = Self::decode_from(&mut reader)?;
        reader.finish()?;
        Ok(tbs)
    }

    /// `SHA256("agenc-chat admin audit checkpoint v1" || TLS-encode(tbs))`.
    pub fn hash(&self) -> Result<[u8; 32], AdminError> {
        let encoded = self.encode()?;
        admin_audit_checkpoint_hash(&encoded)
            .map(|digest| *digest.as_bytes())
            .map_err(map_crypto)
    }
}

/// A complete signed checkpoint (spec 2361-2365).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdminAuditCheckpoint {
    tbs: AdminAuditCheckpointTbs,
    checkpoint_hash: [u8; 32],
    checkpoint_signature: Ed25519Signature,
}

impl AdminAuditCheckpoint {
    /// Validates, hashes, and signs the structure with the audit key.
    pub fn sign(
        tbs: AdminAuditCheckpointTbs,
        audit_key: &Ed25519SecretKey,
    ) -> Result<Self, AdminError> {
        tbs.validate()?;
        let checkpoint_hash = tbs.hash()?;
        let checkpoint_signature = sign_canonical(
            audit_key,
            SignatureDomain::AdminAuditCheckpoint,
            &checkpoint_hash,
        )
        .map_err(map_crypto)?;
        Ok(Self {
            tbs,
            checkpoint_hash,
            checkpoint_signature,
        })
    }

    /// Borrows the signed structure.
    #[must_use]
    pub const fn tbs(&self) -> &AdminAuditCheckpointTbs {
        &self.tbs
    }

    /// Returns the checkpoint hash later checkpoints chain to.
    #[must_use]
    pub const fn checkpoint_hash(&self) -> [u8; 32] {
        self.checkpoint_hash
    }

    /// Encodes the exact 290-byte checkpoint.
    pub fn encode(&self) -> Result<Vec<u8>, AdminError> {
        let mut writer = Writer::with_ceiling(CHECKPOINT_BYTES);
        writer.put_fixed(&self.tbs.encode()?)?;
        writer.put_fixed(&self.checkpoint_hash)?;
        writer.put_fixed(self.checkpoint_signature.as_bytes())?;
        Ok(writer.finish())
    }

    /// Decodes exactly one checkpoint with no trailing bytes.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, AdminError> {
        let mut reader = Reader::new(bytes);
        let tbs = AdminAuditCheckpointTbs::decode_from(&mut reader)?;
        let checkpoint_hash = reader.fixed::<32>()?;
        let checkpoint_signature = Ed25519Signature::from_bytes(reader.fixed::<64>()?);
        reader.finish()?;
        Ok(Self {
            tbs,
            checkpoint_hash,
            checkpoint_signature,
        })
    }

    /// Re-verifies the arithmetic, hash, and signature.
    pub fn verify(&self, audit_key: Ed25519PublicKey) -> Result<(), AdminError> {
        self.tbs.validate()?;
        if self.tbs.hash()? != self.checkpoint_hash {
            return Err(AdminError::Audit);
        }
        verify_canonical(
            audit_key,
            SignatureDomain::AdminAuditCheckpoint,
            &self.checkpoint_hash,
            self.checkpoint_signature,
        )
        .map_err(map_crypto)
    }
}

/// The position of the retained event chain (spec 2387-2390, 2406-2409).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditChainCursor {
    /// Hash the next event must name as its previous hash.
    pub previous_event_hash: [u8; 32],
    /// Sequence the next event must carry.
    pub next_sequence: u64,
}

impl AuditChainCursor {
    /// The empty chain: sequence zero and a zero previous hash.
    #[must_use]
    pub const fn genesis() -> Self {
        Self {
            previous_event_hash: [0; 32],
            next_sequence: 0,
        }
    }

    /// The position after a checkpoint deleted a prefix.
    #[must_use]
    pub const fn after_checkpoint(checkpoint: &AdminAuditCheckpointTbs) -> Self {
        Self {
            previous_event_hash: checkpoint.deleted_last_event_hash,
            next_sequence: checkpoint.next_retained_sequence,
        }
    }

    /// Accepts one event exactly at the cursor and moves past it.
    pub fn advance(self, event: &AdminAuditEvent) -> Result<Self, AdminError> {
        let tbs = event.tbs();
        self.advance_position(
            tbs.audit_sequence,
            tbs.previous_event_hash,
            event.event_hash(),
        )
    }

    pub(crate) fn advance_position(
        self,
        sequence: u64,
        previous_hash: [u8; 32],
        event_hash: [u8; 32],
    ) -> Result<Self, AdminError> {
        if sequence != self.next_sequence || previous_hash != self.previous_event_hash {
            return Err(AdminError::Audit);
        }
        let next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(AdminError::Overflow)?;
        Ok(Self {
            previous_event_hash: event_hash,
            next_sequence,
        })
    }
}

/// Renders the exact `AUDIT EXPORT` batch (spec 4523-4541).
///
/// Callers verify every record first; this function checks ordering,
/// coverage against the requested range, and the record and byte ceilings,
/// and refuses to render a partial batch.
pub fn render_export_batch(
    batch_id: &[u8; 16],
    range: AuditRange,
    checkpoints: &[AdminAuditCheckpoint],
    events: &[crate::AuditEvent],
) -> Result<Vec<String>, AdminError> {
    export::render(
        batch_id,
        range,
        checkpoints,
        events.iter().map(export::EventRef::from),
    )
}

fn check_checkpoint_order(
    range: AuditRange,
    checkpoints: &[AdminAuditCheckpoint],
) -> Result<(), AdminError> {
    let mut previous: Option<u64> = None;
    for checkpoint in checkpoints {
        let tbs = checkpoint.tbs();
        if previous.is_some_and(|last| tbs.checkpoint_sequence <= last) {
            return Err(AdminError::Audit);
        }
        let intersects =
            tbs.deleted_first_sequence <= range.to() && tbs.deleted_last_sequence >= range.from();
        if !intersects {
            return Err(AdminError::Audit);
        }
        previous = Some(tbs.checkpoint_sequence);
    }
    Ok(())
}

fn check_event_order(
    range: AuditRange,
    events: impl Iterator<Item = u64>,
) -> Result<(), AdminError> {
    let mut previous: Option<u64> = None;
    for sequence in events {
        if !range.contains(sequence) || previous.is_some_and(|last| sequence <= last) {
            return Err(AdminError::Audit);
        }
        previous = Some(sequence);
    }
    Ok(())
}

fn check_export_coverage(
    range: AuditRange,
    checkpoints: &[AdminAuditCheckpoint],
    events: impl ExactSizeIterator<Item = u64>,
) -> Result<(), AdminError> {
    let records = checkpoints
        .len()
        .checked_add(events.len())
        .ok_or(AdminError::Overflow)?;
    let mut spans = Vec::with_capacity(records);
    for checkpoint in checkpoints {
        let tbs = checkpoint.tbs();
        spans.push((
            tbs.deleted_first_sequence.max(range.from()),
            tbs.deleted_last_sequence.min(range.to()),
        ));
    }
    spans.extend(events.map(|sequence| (sequence, sequence)));
    spans.sort_unstable();

    let Some((first_start, first_end)) = spans.first().copied() else {
        return Ok(());
    };
    if first_start != range.from() {
        return Err(AdminError::Audit);
    }
    let mut covered_through = first_end;
    for (start, end) in spans.into_iter().skip(1) {
        let expected = covered_through.checked_add(1).ok_or(AdminError::Overflow)?;
        if start != expected {
            return Err(AdminError::Audit);
        }
        covered_through = end;
    }
    Ok(())
}

fn check_export_bytes(lines: &[String]) -> Result<(), AdminError> {
    let total = lines.iter().try_fold(0_u64, |total, line| {
        let with_crlf = u64::try_from(line.len())
            .ok()
            .and_then(|length| length.checked_add(2))?;
        total.checked_add(with_crlf)
    });
    match total {
        Some(bytes) if bytes <= MAX_AUDIT_EXPORT_BYTES => Ok(()),
        Some(_) => Err(AdminError::Limit),
        None => Err(AdminError::Overflow),
    }
}

fn map_crypto(error: CryptoError) -> AdminError {
    match error {
        CryptoError::AuthenticationFailed => AdminError::Signature,
        CryptoError::LimitExceeded => AdminError::Limit,
        CryptoError::Overflow => AdminError::Overflow,
        _ => AdminError::Audit,
    }
}

#[cfg(test)]
mod tests {
    use agenc_relay_crypto::{Ed25519SecretKey, audit_signing_key_id};
    use agenc_relay_types::{NetworkId, OperatorId, ServerId};

    use super::{
        AdminAuditCheckpoint, AdminAuditCheckpointTbs, AdminAuditEvent, AdminAuditEventTbs,
        AdminAuditPhase, AuditChainCursor, MAX_AUDIT_EVENT_BYTES, render_export_batch,
    };
    use crate::{AdminCommandTbs, AdminError, AdminSessionId, AuditRange};

    fn audit_key() -> Ed25519SecretKey {
        Ed25519SecretKey::from_bytes([11; 32])
    }

    fn operator_key() -> Ed25519SecretKey {
        Ed25519SecretKey::from_bytes([12; 32])
    }

    fn key_id() -> Result<[u8; 32], AdminError> {
        audit_signing_key_id(audit_key().public_key().as_bytes())
            .map(|digest| *digest.as_bytes())
            .map_err(|_| AdminError::Overflow)
    }

    fn event_tbs(
        sequence: u64,
        previous: [u8; 32],
        phase: AdminAuditPhase,
    ) -> Result<AdminAuditEventTbs, AdminError> {
        let command_tbs = AdminCommandTbs::new(
            NetworkId::from_bytes([1; 32]),
            ServerId::from_bytes([2; 16]),
            AdminSessionId::from_bytes([3; 16]),
            sequence,
            None,
            b"STATS RUNTIME",
        )?;
        let operator_signature = command_tbs.sign(&operator_key())?;
        Ok(AdminAuditEventTbs {
            network_id: NetworkId::from_bytes([1; 32]),
            server_id: ServerId::from_bytes([2; 16]),
            audit_signing_key_id: key_id()?,
            audit_sequence: sequence,
            created_at: 1_700_000_000,
            operator_id: OperatorId::from_bytes([4; 16]),
            command_tbs,
            operator_signature,
            phase,
            previous_event_hash: previous,
        })
    }

    fn checkpoint_tbs(
        first: u64,
        last: u64,
        last_hash: [u8; 32],
    ) -> Result<AdminAuditCheckpointTbs, AdminError> {
        Ok(AdminAuditCheckpointTbs {
            network_id: NetworkId::from_bytes([1; 32]),
            server_id: ServerId::from_bytes([2; 16]),
            audit_signing_key_id: key_id()?,
            checkpoint_sequence: 0,
            created_at: 1_700_000_100,
            deleted_first_sequence: first,
            deleted_last_sequence: last,
            deleted_count: last - first + 1,
            deleted_last_event_hash: last_hash,
            next_retained_sequence: last + 1,
            previous_checkpoint_hash: [0; 32],
        })
    }

    #[test]
    fn phases_map_to_wire_values_and_codes() {
        for (phase, value, code) in [
            (AdminAuditPhase::CommittedMutation, 1, "COMMITTED"),
            (AdminAuditPhase::Intent, 2, "PENDING"),
            (AdminAuditPhase::OutcomeSuccess, 3, "SUCCEEDED"),
            (AdminAuditPhase::OutcomeFailure, 4, "FAILED"),
            (AdminAuditPhase::Observed, 5, "OBSERVED"),
        ] {
            assert_eq!(phase.as_u8(), value);
            assert_eq!(AdminAuditPhase::from_u8(value), Ok(phase));
            assert_eq!(phase.safe_outcome_code(), code);
        }
        assert_eq!(AdminAuditPhase::from_u8(0), Err(AdminError::Audit));
        assert_eq!(AdminAuditPhase::from_u8(6), Err(AdminError::Audit));
    }

    #[test]
    fn events_encode_hash_sign_verify_and_chain() -> Result<(), AdminError> {
        let first = AdminAuditEvent::sign(
            event_tbs(0, [0; 32], AdminAuditPhase::Observed)?,
            &audit_key(),
        )?;
        let encoded = first.encode()?;
        assert!(encoded.len() <= MAX_AUDIT_EVENT_BYTES);
        assert_eq!(AdminAuditEvent::decode_exact(&encoded)?, first);
        first.verify(audit_key().public_key(), operator_key().public_key())?;
        assert_eq!(
            first.verify(operator_key().public_key(), operator_key().public_key()),
            Err(AdminError::Signature)
        );
        assert_eq!(
            first.verify(audit_key().public_key(), audit_key().public_key()),
            Err(AdminError::Signature)
        );
        assert_eq!(first.tbs().phase, AdminAuditPhase::Observed);

        let cursor = AuditChainCursor::genesis().advance(&first)?;
        assert_eq!(cursor.next_sequence, 1);
        assert_eq!(cursor.previous_event_hash, first.event_hash());
        let second = AdminAuditEvent::sign(
            event_tbs(1, first.event_hash(), AdminAuditPhase::Intent)?,
            &audit_key(),
        )?;
        let cursor = cursor.advance(&second)?;
        assert_eq!(cursor.next_sequence, 2);
        let gap = AdminAuditEvent::sign(
            event_tbs(3, second.event_hash(), AdminAuditPhase::Intent)?,
            &audit_key(),
        )?;
        assert_eq!(cursor.advance(&gap), Err(AdminError::Audit));
        let fork = AdminAuditEvent::sign(
            event_tbs(2, [9; 32], AdminAuditPhase::Intent)?,
            &audit_key(),
        )?;
        assert_eq!(cursor.advance(&fork), Err(AdminError::Audit));
        let exhausted = AuditChainCursor {
            previous_event_hash: [0; 32],
            next_sequence: u64::MAX,
        };
        let last = AdminAuditEvent::sign(
            event_tbs(u64::MAX, [0; 32], AdminAuditPhase::Observed)?,
            &audit_key(),
        )?;
        assert_eq!(exhausted.advance(&last), Err(AdminError::Overflow));

        let mut tampered = encoded.clone();
        *tampered.get_mut(60).ok_or(AdminError::Audit)? ^= 1;
        let decoded = AdminAuditEvent::decode_exact(&tampered)?;
        assert_eq!(
            decoded.verify(audit_key().public_key(), operator_key().public_key()),
            Err(AdminError::Audit)
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            AdminAuditEvent::decode_exact(&trailing),
            Err(AdminError::Audit)
        );
        let mut wrong_code = encoded;
        // The outcome code sits after the phase byte; flip its first letter.
        let phase_offset =
            2 + 32 + 16 + 32 + 8 + 8 + 16 + first.tbs().command_tbs.encode()?.len() + 64;
        *wrong_code
            .get_mut(phase_offset + 2)
            .ok_or(AdminError::Audit)? = b'X';
        assert_eq!(
            AdminAuditEvent::decode_exact(&wrong_code),
            Err(AdminError::Audit)
        );
        assert_eq!(
            AdminAuditEventTbs::decode_exact(&first.tbs().encode()?)?,
            *first.tbs()
        );
        Ok(())
    }

    #[test]
    fn checkpoints_validate_arithmetic_encode_exactly_and_verify() -> Result<(), AdminError> {
        let tbs = checkpoint_tbs(0, 9, [7; 32])?;
        assert_eq!(tbs.encode()?.len(), 194);
        let checkpoint = AdminAuditCheckpoint::sign(tbs, &audit_key())?;
        let encoded = checkpoint.encode()?;
        assert_eq!(encoded.len(), 290);
        assert_eq!(AdminAuditCheckpoint::decode_exact(&encoded)?, checkpoint);
        checkpoint.verify(audit_key().public_key())?;
        assert_eq!(
            checkpoint.verify(operator_key().public_key()),
            Err(AdminError::Signature)
        );
        assert_eq!(checkpoint.checkpoint_hash(), tbs.hash()?);
        assert_eq!(AdminAuditCheckpointTbs::decode_exact(&tbs.encode()?)?, tbs);
        let cursor = AuditChainCursor::after_checkpoint(checkpoint.tbs());
        assert_eq!(cursor.next_sequence, 10);
        assert_eq!(cursor.previous_event_hash, [7; 32]);

        let mut wrong_count = tbs;
        wrong_count.deleted_count = 9;
        assert_eq!(wrong_count.validate(), Err(AdminError::Audit));
        let mut wrong_next = tbs;
        wrong_next.next_retained_sequence = 11;
        assert_eq!(wrong_next.validate(), Err(AdminError::Audit));
        let mut inverted = tbs;
        inverted.deleted_first_sequence = 10;
        assert_eq!(inverted.validate(), Err(AdminError::Audit));
        let mut genesis_hash = tbs;
        genesis_hash.previous_checkpoint_hash = [1; 32];
        assert_eq!(genesis_hash.validate(), Err(AdminError::Audit));
        let mut overflow = tbs;
        overflow.deleted_last_sequence = u64::MAX;
        overflow.deleted_first_sequence = 0;
        assert_eq!(overflow.validate(), Err(AdminError::Overflow));
        assert_eq!(
            AdminAuditCheckpoint::sign(wrong_count, &audit_key()).err(),
            Some(AdminError::Audit)
        );
        let mut short = encoded;
        short.pop();
        assert_eq!(
            AdminAuditCheckpoint::decode_exact(&short),
            Err(AdminError::Audit)
        );
        let mut wrong_version = tbs.encode()?;
        *wrong_version.get_mut(1).ok_or(AdminError::Audit)? = 9;
        assert_eq!(
            AdminAuditCheckpointTbs::decode_exact(&wrong_version),
            Err(AdminError::Audit)
        );
        Ok(())
    }

    #[test]
    fn export_batches_render_exactly_and_reject_bad_order_or_coverage() -> Result<(), AdminError> {
        let e0 = AdminAuditEvent::sign(
            event_tbs(0, [0; 32], AdminAuditPhase::Observed)?,
            &audit_key(),
        )?;
        let e1 = AdminAuditEvent::sign(
            event_tbs(1, e0.event_hash(), AdminAuditPhase::Observed)?,
            &audit_key(),
        )?;
        let checkpoint =
            AdminAuditCheckpoint::sign(checkpoint_tbs(0, 0, e0.event_hash())?, &audit_key())?;
        let range = AuditRange::new(0, 5)?;
        let lines = render_export_batch(
            &[0; 16],
            range,
            &[checkpoint],
            &[crate::AuditEvent::Admin(e1.clone())],
        )?;
        assert_eq!(lines.len(), 4);
        assert_eq!(
            lines.first().map(String::as_str),
            Some("BATCH +AAAAAAAAAAAAAAAAAAAAAA agenc.ag/audit 0 5 1 1")
        );
        let checkpoint_line = lines.get(1).cloned().unwrap_or_default();
        assert!(
            checkpoint_line.starts_with("@batch=AAAAAAAAAAAAAAAAAAAAAA NOTE AUDIT CHECKPOINT ")
        );
        assert!(checkpoint_line.ends_with(" :Audit checkpoint"));
        let event_line = lines.get(2).cloned().unwrap_or_default();
        assert!(event_line.starts_with("@batch=AAAAAAAAAAAAAAAAAAAAAA NOTE AUDIT EVENT "));
        assert!(event_line.ends_with(" :Audit event"));
        assert!(
            lines
                .iter()
                .all(|line| line.len() <= crate::MAX_ADMIN_OUTPUT_LINE_BYTES)
        );
        assert_eq!(
            lines.last().map(String::as_str),
            Some("BATCH -AAAAAAAAAAAAAAAAAAAAAA")
        );

        let empty = render_export_batch(&[0; 16], AuditRange::new(50, 60)?, &[], &[])?;
        assert_eq!(
            empty.first().map(String::as_str),
            Some("BATCH +AAAAAAAAAAAAAAAAAAAAAA agenc.ag/audit 50 60 0 0")
        );
        assert_eq!(empty.len(), 2);

        assert_eq!(
            render_export_batch(
                &[0; 16],
                range,
                &[],
                &[
                    crate::AuditEvent::Admin(e1.clone()),
                    crate::AuditEvent::Admin(e0.clone())
                ]
            ),
            Err(AdminError::Audit)
        );
        assert_eq!(
            render_export_batch(
                &[0; 16],
                AuditRange::new(2, 5)?,
                &[],
                &[crate::AuditEvent::Admin(e1.clone())]
            ),
            Err(AdminError::Audit)
        );
        assert_eq!(
            render_export_batch(&[0; 16], AuditRange::new(3, 5)?, &[checkpoint], &[]),
            Err(AdminError::Audit)
        );
        assert_eq!(
            render_export_batch(&[0; 16], range, &[checkpoint, checkpoint], &[]),
            Err(AdminError::Audit)
        );
        let e2 = AdminAuditEvent::sign(
            event_tbs(2, e1.event_hash(), AdminAuditPhase::Observed)?,
            &audit_key(),
        )?;
        assert_eq!(
            render_export_batch(
                &[0; 16],
                range,
                std::slice::from_ref(&checkpoint),
                &[crate::AuditEvent::Admin(e2.clone())]
            ),
            Err(AdminError::Audit)
        );
        let overlapping_checkpoint =
            AdminAuditCheckpoint::sign(checkpoint_tbs(0, 1, e1.event_hash())?, &audit_key())?;
        assert_eq!(
            render_export_batch(
                &[0; 16],
                range,
                std::slice::from_ref(&overlapping_checkpoint),
                &[crate::AuditEvent::Admin(e1.clone())]
            ),
            Err(AdminError::Audit)
        );
        let many = vec![crate::AuditEvent::Admin(e1); 10_001];
        assert_eq!(
            render_export_batch(&[0; 16], AuditRange::new(0, u64::MAX)?, &[], &many),
            Err(AdminError::Limit)
        );
        Ok(())
    }

    #[path = "export_records.rs"]
    mod export_records;

    #[test]
    fn a_checkpoint_with_a_mismatched_hash_fails_verification() -> Result<(), AdminError> {
        let first = AdminAuditEvent::sign(
            event_tbs(0, [0; 32], AdminAuditPhase::Observed)?,
            &audit_key(),
        )?;
        let mut checkpoint =
            AdminAuditCheckpoint::sign(checkpoint_tbs(0, 0, first.event_hash())?, &audit_key())?;
        checkpoint.verify(audit_key().public_key())?;
        checkpoint.checkpoint_hash = [9; 32];
        assert_eq!(
            checkpoint.verify(audit_key().public_key()),
            Err(AdminError::Audit)
        );
        Ok(())
    }

    #[test]
    fn export_checkpoints_must_intersect_the_requested_range() -> Result<(), AdminError> {
        let first = AdminAuditEvent::sign(
            event_tbs(0, [0; 32], AdminAuditPhase::Observed)?,
            &audit_key(),
        )?;
        let second = AdminAuditEvent::sign(
            event_tbs(1, first.event_hash(), AdminAuditPhase::Observed)?,
            &audit_key(),
        )?;
        for (deleted_first, deleted_last) in [(20, 20), (0, 0)] {
            let checkpoint = AdminAuditCheckpoint::sign(
                checkpoint_tbs(deleted_first, deleted_last, first.event_hash())?,
                &audit_key(),
            )?;
            assert_eq!(
                render_export_batch(
                    &[0; 16],
                    AuditRange::new(10, 15)?,
                    &[checkpoint],
                    &[crate::AuditEvent::Admin(second.clone())],
                )
                .err(),
                Some(AdminError::Audit),
                "deleted {deleted_first}..={deleted_last}"
            );
        }
        Ok(())
    }

    #[test]
    fn export_bytes_are_bounded() -> Result<(), AdminError> {
        let limit =
            usize::try_from(crate::MAX_AUDIT_EXPORT_BYTES).map_err(|_| AdminError::Overflow)?;
        assert_eq!(
            super::check_export_bytes(&["x".repeat(limit)]),
            Err(AdminError::Limit)
        );
        assert_eq!(super::check_export_bytes(&["ok".to_owned()]), Ok(()));
        Ok(())
    }
}
