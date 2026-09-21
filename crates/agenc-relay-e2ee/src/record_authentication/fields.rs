//! Exact outer context and registered signature domains for all six records.
#![forbid(unsafe_code)]

use super::ExpectedRecord;
use crate::error::E2eeError;
use crate::limits::PROFILE_VERSION;
use crate::objects::sequencing::ArcSequencerRecord;
use crate::sequencer::VerifiedSequencerCredential;
use crate::tls::TlsEncode;
use agenc_relay_crypto::SignatureDomain;

struct Signed<'a> {
    profile: u16,
    position: ExpectedRecord,
    domain: SignatureDomain,
    tbs: &'a dyn TlsEncode,
    signature: &'a [u8; 64],
}

/// The exact position and credential the record itself claims, before any
/// signature check. A caller compares it with the position trusted history
/// established; it grants no authority on its own.
pub(super) fn position(record: &ArcSequencerRecord) -> ExpectedRecord {
    fields(record).position
}

pub(super) fn authenticate(
    record: &ArcSequencerRecord,
    expected: &ExpectedRecord,
    credential: &VerifiedSequencerCredential,
) -> Result<(), E2eeError> {
    let signed = fields(record);
    if signed.profile != PROFILE_VERSION
        || signed.position != *expected
        || credential.credential_id != expected.sequencer_credential_id
    {
        return Err(E2eeError::ProfileMismatch);
    }
    credential
        .key
        .verify(signed.domain, &signed.tbs.encode()?, signed.signature)
}

fn fields(record: &ArcSequencerRecord) -> Signed<'_> {
    match record {
        ArcSequencerRecord::Candidate(value) => candidate(value),
        ArcSequencerRecord::Finalization(value) => finalization(value),
        ArcSequencerRecord::Abort(value) => abort(value),
        ArcSequencerRecord::ReinitAttempt(value) => reinit_attempt(value),
        ArcSequencerRecord::ReinitActivation(value) => reinit_activation(value),
        ArcSequencerRecord::ReinitAbort(value) => reinit_abort(value),
    }
}

fn candidate(value: &crate::objects::sequencing::ArcCandidateReceipt) -> Signed<'_> {
    Signed {
        profile: value.tbs.profile_version,
        position: ExpectedRecord {
            network_id: value.tbs.network_id,
            conversation_id: value.tbs.conversation_id,
            route_sequence: value.tbs.route_sequence,
            predecessor_record_id: value.tbs.predecessor_record_id,
            sequencer_credential_id: value.tbs.sequencer_key_id,
        },
        domain: SignatureDomain::CandidateReceipt,
        tbs: &value.tbs,
        signature: &value.sequencer_signature,
    }
}

fn finalization(
    value: &crate::objects::sequencing::ArcCommitFinalizationCertificate,
) -> Signed<'_> {
    Signed {
        profile: value.tbs.profile_version,
        position: ExpectedRecord {
            network_id: value.tbs.network_id,
            conversation_id: value.tbs.conversation_id,
            route_sequence: value.tbs.route_sequence,
            predecessor_record_id: value.tbs.predecessor_record_id,
            sequencer_credential_id: value.tbs.sequencer_key_id,
        },
        domain: SignatureDomain::CommitFinalization,
        tbs: &value.tbs,
        signature: &value.sequencer_signature,
    }
}

fn abort(value: &crate::objects::sequencing::ArcCommitAbortCertificate) -> Signed<'_> {
    Signed {
        profile: value.tbs.profile_version,
        position: ExpectedRecord {
            network_id: value.tbs.network_id,
            conversation_id: value.tbs.conversation_id,
            route_sequence: value.tbs.route_sequence,
            predecessor_record_id: value.tbs.predecessor_record_id,
            sequencer_credential_id: value.tbs.sequencer_key_id,
        },
        domain: SignatureDomain::CandidateAbort,
        tbs: &value.tbs,
        signature: &value.sequencer_signature,
    }
}

fn reinit_attempt(value: &crate::objects::reinit::ArcReInitAttemptReceipt) -> Signed<'_> {
    Signed {
        profile: value.tbs.profile_version,
        position: ExpectedRecord {
            network_id: value.tbs.network_id,
            conversation_id: value.tbs.old_conversation_id,
            route_sequence: value.tbs.route_sequence,
            predecessor_record_id: value.tbs.predecessor_record_id,
            sequencer_credential_id: value.tbs.sequencer_key_id,
        },
        domain: SignatureDomain::ReinitAttemptReceipt,
        tbs: &value.tbs,
        signature: &value.sequencer_signature,
    }
}

fn reinit_activation(value: &crate::objects::reinit::ArcReInitActivationCertificate) -> Signed<'_> {
    Signed {
        profile: value.tbs.profile_version,
        position: ExpectedRecord {
            network_id: value.tbs.network_id,
            conversation_id: value.tbs.old_conversation_id,
            route_sequence: value.tbs.route_sequence,
            predecessor_record_id: value.tbs.predecessor_record_id,
            sequencer_credential_id: value.tbs.sequencer_key_id,
        },
        domain: SignatureDomain::ReinitActivation,
        tbs: &value.tbs,
        signature: &value.sequencer_signature,
    }
}

fn reinit_abort(value: &crate::objects::reinit::ArcReInitAbortCertificate) -> Signed<'_> {
    Signed {
        profile: value.tbs.profile_version,
        position: ExpectedRecord {
            network_id: value.tbs.network_id,
            conversation_id: value.tbs.old_conversation_id,
            route_sequence: value.tbs.route_sequence,
            predecessor_record_id: value.tbs.predecessor_record_id,
            sequencer_credential_id: value.tbs.sequencer_key_id,
        },
        domain: SignatureDomain::ReinitAttemptAbort,
        tbs: &value.tbs,
        signature: &value.sequencer_signature,
    }
}

/// The sequencing second the record itself carries: a receipt states its
/// own `sequenced_at`, and a terminal certificate embeds the receipt it
/// terminates, whose `sequenced_at` is the only signed time it carries and
/// a lower bound on its own. Informational for historical authority; a
/// witness resolution reads it to place a successor credential inside its
/// overlap window (companion 12.5.1).
pub(super) const fn sequenced_at(record: &ArcSequencerRecord) -> u64 {
    match record {
        ArcSequencerRecord::Candidate(value) => value.tbs.sequenced_at,
        ArcSequencerRecord::Finalization(value) => value.tbs.request.proof.receipt.tbs.sequenced_at,
        ArcSequencerRecord::Abort(value) => value.tbs.request.receipt.tbs.sequenced_at,
        ArcSequencerRecord::ReinitAttempt(value) => value.tbs.sequenced_at,
        ArcSequencerRecord::ReinitActivation(value) => value.tbs.request.receipt.tbs.sequenced_at,
        ArcSequencerRecord::ReinitAbort(value) => value.tbs.request.receipt.tbs.sequenced_at,
    }
}
