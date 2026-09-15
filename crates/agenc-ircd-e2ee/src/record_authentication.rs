//! Authentication of one historical sequencer record at an expected position.
//!
//! The caller supplies the position and credential committed by previously
//! validated history. A current ECAP key set does not establish historical
//! authority. This check authenticates ordering and semantic identity; it does
//! not validate controller approval, finality votes, MLS processing or recovery
//! completion. A caller must validate those proofs before installing any head.

#![forbid(unsafe_code)]

mod fields;
mod identity;

use crate::error::E2eeError;
use crate::object::{IrcWireObject, IrcWireObjectKind, ObjectId};
use crate::objects::sequencing::IrcSequencerRecord;
use crate::sequencer::VerifiedSequencerCredential;
use crate::tls::{DecodeBudget, TlsDecode};

/// The exact position and credential established by trusted prior history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedRecord {
    /// Network containing the log.
    pub network_id: [u8; 32],
    /// Conversation containing the log, including the old ReInit conversation.
    pub conversation_id: [u8; 32],
    /// Expected sequence, calculated without wrapping from the stored head.
    pub route_sequence: u64,
    /// Semantic ID of the immediately preceding record or external anchor.
    pub predecessor_record_id: [u8; 32],
    /// Credential committed for this position by the validated context history.
    pub sequencer_credential_id: [u8; 32],
}

/// Identities authenticated by the sequencer signature and the exact position.
/// This value grants no authority to close or unblock a route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedRecord {
    semantic_id: [u8; 32],
    object_id: ObjectId,
}

impl AuthenticatedRecord {
    /// Semantic record ID, independent of signatures and alternative proofs.
    #[must_use]
    pub const fn semantic_id(&self) -> &[u8; 32] {
        &self.semantic_id
    }

    /// Transport identity of this exact complete record object.
    #[must_use]
    pub const fn object_id(&self) -> &ObjectId {
        &self.object_id
    }
}

/// Authenticates a complete `sequencer_record` without changing caller state.
///
/// `attempt_object` must contain the exact referenced `reinit_attempt` object
/// for an attempt receipt and must be absent for every other arm. The receipt
/// alone cannot prove the attempt's semantic ID. `sequenced_at` is informational;
/// it is never used to choose a credential or to establish certificate time.
///
/// The caller reserves work memory before this call and supplies the associated
/// decode budget. At most one record and one attempt are decoded; all encodings
/// and decoded values are released before this function returns.
pub fn authenticate_record(
    bytes: &[u8],
    attempt_object: Option<&[u8]>,
    expected: &ExpectedRecord,
    credential: &VerifiedSequencerCredential,
    budget: &mut DecodeBudget,
) -> Result<AuthenticatedRecord, E2eeError> {
    let object =
        IrcWireObject::decode_kind(bytes, Some(IrcWireObjectKind::SequencerRecord), budget)?;
    let record = IrcSequencerRecord::decode_exact(object.body(), budget)?;
    let semantic_id =
        authenticate_decoded_record(&record, attempt_object, expected, credential, budget)?;
    Ok(AuthenticatedRecord {
        semantic_id,
        object_id: ObjectId::compute(bytes),
    })
}

/// The same authentication over an already decoded record, for a caller
/// that needs the record's content afterwards (the historical chain).
pub(crate) fn authenticate_decoded_record(
    record: &IrcSequencerRecord,
    attempt_object: Option<&[u8]>,
    expected: &ExpectedRecord,
    credential: &VerifiedSequencerCredential,
    budget: &mut DecodeBudget,
) -> Result<[u8; 32], E2eeError> {
    fields::authenticate(record, expected, credential)?;
    identity::verify(record, attempt_object, budget)
}
