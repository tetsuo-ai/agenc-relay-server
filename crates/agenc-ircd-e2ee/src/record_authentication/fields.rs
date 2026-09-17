//! Exact outer context and registered signature domains for all six records.
#![forbid(unsafe_code)]

use super::ExpectedRecord;
use crate::error::E2eeError;
use crate::limits::PROFILE_VERSION;
use crate::objects::sequencing::IrcSequencerRecord;
use crate::sequencer::VerifiedSequencerCredential;
use crate::tls::TlsEncode;
use agenc_ircd_crypto::SignatureDomain;

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
pub(super) fn position(record: &IrcSequencerRecord) -> ExpectedRecord {
    fields(record).position
}

pub(super) fn authenticate(
    record: &IrcSequencerRecord,
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

fn fields(record: &IrcSequencerRecord) -> Signed<'_> {
    match record {
        IrcSequencerRecord::Candidate(value) => candidate(value),
        IrcSequencerRecord::Finalization(value) => finalization(value),
        IrcSequencerRecord::Abort(value) => abort(value),
        IrcSequencerRecord::ReinitAttempt(value) => reinit_attempt(value),
        IrcSequencerRecord::ReinitActivation(value) => reinit_activation(value),
        IrcSequencerRecord::ReinitAbort(value) => reinit_abort(value),
    }
}

fn candidate(value: &crate::objects::sequencing::IrcCandidateReceipt) -> Signed<'_> {
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
    value: &crate::objects::sequencing::IrcCommitFinalizationCertificate,
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

fn abort(value: &crate::objects::sequencing::IrcCommitAbortCertificate) -> Signed<'_> {
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

fn reinit_attempt(value: &crate::objects::reinit::IrcReInitAttemptReceipt) -> Signed<'_> {
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

fn reinit_activation(value: &crate::objects::reinit::IrcReInitActivationCertificate) -> Signed<'_> {
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

fn reinit_abort(value: &crate::objects::reinit::IrcReInitAbortCertificate) -> Signed<'_> {
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
