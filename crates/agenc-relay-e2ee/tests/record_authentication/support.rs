#![forbid(unsafe_code)]
//! Real outer signatures over deliberately synthetic inner endpoint evidence.
use super::shapes;
use agenc_relay_crypto::{Ed25519SecretKey, SemanticHashDomain, SignatureDomain, sign_canonical};
use agenc_relay_e2ee::ids::semantic_id_of;
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind, ObjectId};
use agenc_relay_e2ee::objects::conversation::{ArcSequencerCredential, ArcSequencerCredentialTbs};
use agenc_relay_e2ee::objects::reinit::ArcReInitAttempt;
use agenc_relay_e2ee::objects::sequencing::ArcSequencerRecord;
pub(super) use agenc_relay_e2ee::objects::sequencing::ArcSequencerRecordKind as Kind;
pub(super) use agenc_relay_e2ee::record_authentication::ExpectedRecord;
use agenc_relay_e2ee::record_authentication::{AuthenticatedRecord, authenticate_record};
use agenc_relay_e2ee::sequencer::{VerifiedSequencerCredential, verify_sequencer_credential};
use agenc_relay_e2ee::{DecodeBudget, E2eeError, Opaque, TlsEncode};

pub(super) type TestResult = Result<(), Box<dyn std::error::Error>>;
pub(super) const KINDS: [Kind; 6] = [
    Kind::CandidateRecord,
    Kind::FinalizationRecord,
    Kind::AbortRecord,
    Kind::ReinitAttemptRecord,
    Kind::ReinitActivationRecord,
    Kind::ReinitAbortRecord,
];
pub(super) const TERMINALS: [Kind; 4] = [
    Kind::FinalizationRecord,
    Kind::AbortRecord,
    Kind::ReinitActivationRecord,
    Kind::ReinitAbortRecord,
];
pub(super) fn budget() -> DecodeBudget {
    DecodeBudget::new(1 << 25, 1 << 18)
}
pub(super) fn object(
    kind: ArcWireObjectKind,
    value: &impl TlsEncode,
) -> Result<Vec<u8>, E2eeError> {
    ArcWireObject::new(kind, value.encode()?)?.encode()
}

pub(super) struct Case {
    pub(super) record: ArcSequencerRecord,
    pub(super) attempt: Option<ArcReInitAttempt>,
    pub(super) credential: VerifiedSequencerCredential,
    pub(super) expected: ExpectedRecord,
}

impl Case {
    pub(super) fn new(kind: Kind) -> Result<Self, E2eeError> {
        let secret = Ed25519SecretKey::from_bytes([60; 32]);
        let credential = verify_sequencer_credential(
            &[1; 32],
            &ArcSequencerCredential {
                tbs: ArcSequencerCredentialTbs {
                    profile_version: 1,
                    network_id: [1; 32],
                    key_generation: 0,
                    sequencer_public_key: *secret.public_key().as_bytes(),
                    not_before: 5,
                    not_after: 10,
                    previous_key_id: [0; 32],
                },
                continuity_signature: Opaque::new(Vec::new())?,
            },
            None,
        )?;
        let (record, attempt, sequence, predecessor) = match kind {
            Kind::CandidateRecord => (
                ArcSequencerRecord::Candidate(shapes::receipt()),
                None,
                0,
                [50; 32],
            ),
            Kind::FinalizationRecord => (
                ArcSequencerRecord::Finalization(shapes::finalization()?),
                None,
                1,
                [52; 32],
            ),
            Kind::AbortRecord => (
                ArcSequencerRecord::Abort(shapes::abort()?),
                None,
                1,
                [52; 32],
            ),
            Kind::ReinitAttemptRecord => (
                ArcSequencerRecord::ReinitAttempt(shapes::attempt_receipt()),
                Some(shapes::reinit_attempt()?),
                2,
                [58; 32],
            ),
            Kind::ReinitActivationRecord => (
                ArcSequencerRecord::ReinitActivation(shapes::activation()?),
                None,
                3,
                [85; 32],
            ),
            Kind::ReinitAbortRecord => (
                ArcSequencerRecord::ReinitAbort(shapes::reinit_abort()?),
                None,
                3,
                [85; 32],
            ),
        };
        let expected = ExpectedRecord {
            network_id: [1; 32],
            conversation_id: [20; 32],
            route_sequence: sequence,
            predecessor_record_id: predecessor,
            sequencer_credential_id: credential.credential_id,
        };
        let mut case = Self {
            record,
            attempt,
            credential,
            expected,
        };
        *case.key_id() = credential.credential_id;
        if let Some(attempt) = &case.attempt {
            let id = semantic_id_of(SemanticHashDomain::ReinitAttemptId, &attempt.tbs)?;
            let ArcSequencerRecord::ReinitAttempt(value) = &mut case.record else {
                return Err(E2eeError::InvalidValue);
            };
            value.tbs.reinit_attempt_id = id;
            case.refresh_attempt_object_id()?;
        } else if kind != Kind::CandidateRecord {
            case.refresh_terminal_id()?;
        }
        case.resign()?;
        Ok(case)
    }
    pub(super) fn bytes(&self) -> Result<Vec<u8>, E2eeError> {
        object(ArcWireObjectKind::SequencerRecord, &self.record)
    }
    pub(super) fn authenticate(&self) -> Result<AuthenticatedRecord, E2eeError> {
        let attempt = self
            .attempt
            .as_ref()
            .map(|value| object(ArcWireObjectKind::ReinitAttempt, value))
            .transpose()?;
        authenticate_record(
            &self.bytes()?,
            attempt.as_deref(),
            &self.expected,
            &self.credential,
            &mut budget(),
        )
    }
    pub(super) fn domain(&self) -> SignatureDomain {
        match &self.record {
            ArcSequencerRecord::Candidate(_) => SignatureDomain::CandidateReceipt,
            ArcSequencerRecord::Finalization(_) => SignatureDomain::CommitFinalization,
            ArcSequencerRecord::Abort(_) => SignatureDomain::CandidateAbort,
            ArcSequencerRecord::ReinitAttempt(_) => SignatureDomain::ReinitAttemptReceipt,
            ArcSequencerRecord::ReinitActivation(_) => SignatureDomain::ReinitActivation,
            ArcSequencerRecord::ReinitAbort(_) => SignatureDomain::ReinitAttemptAbort,
        }
    }
    pub(super) fn resign(&mut self) -> Result<(), E2eeError> {
        self.sign_as(self.domain(), &Ed25519SecretKey::from_bytes([60; 32]))
    }
    pub(super) fn sign_as(
        &mut self,
        domain: SignatureDomain,
        secret: &Ed25519SecretKey,
    ) -> Result<(), E2eeError> {
        let (tbs, signature): (&dyn TlsEncode, &mut [u8; 64]) = match &mut self.record {
            ArcSequencerRecord::Candidate(value) => (&value.tbs, &mut value.sequencer_signature),
            ArcSequencerRecord::Finalization(value) => (&value.tbs, &mut value.sequencer_signature),
            ArcSequencerRecord::Abort(value) => (&value.tbs, &mut value.sequencer_signature),
            ArcSequencerRecord::ReinitAttempt(value) => {
                (&value.tbs, &mut value.sequencer_signature)
            }
            ArcSequencerRecord::ReinitActivation(value) => {
                (&value.tbs, &mut value.sequencer_signature)
            }
            ArcSequencerRecord::ReinitAbort(value) => (&value.tbs, &mut value.sequencer_signature),
        };
        *signature = *sign_canonical(secret, domain, &tbs.encode()?)
            .map_err(|_| E2eeError::SignatureInvalid)?
            .as_bytes();
        Ok(())
    }
    fn key_id(&mut self) -> &mut [u8; 32] {
        match &mut self.record {
            ArcSequencerRecord::Candidate(value) => &mut value.tbs.sequencer_key_id,
            ArcSequencerRecord::Finalization(value) => &mut value.tbs.sequencer_key_id,
            ArcSequencerRecord::Abort(value) => &mut value.tbs.sequencer_key_id,
            ArcSequencerRecord::ReinitAttempt(value) => &mut value.tbs.sequencer_key_id,
            ArcSequencerRecord::ReinitActivation(value) => &mut value.tbs.sequencer_key_id,
            ArcSequencerRecord::ReinitAbort(value) => &mut value.tbs.sequencer_key_id,
        }
    }
    pub(super) fn outer_profile(&mut self) -> &mut u16 {
        match &mut self.record {
            ArcSequencerRecord::Candidate(value) => &mut value.tbs.profile_version,
            ArcSequencerRecord::Finalization(value) => &mut value.tbs.profile_version,
            ArcSequencerRecord::Abort(value) => &mut value.tbs.profile_version,
            ArcSequencerRecord::ReinitAttempt(value) => &mut value.tbs.profile_version,
            ArcSequencerRecord::ReinitActivation(value) => &mut value.tbs.profile_version,
            ArcSequencerRecord::ReinitAbort(value) => &mut value.tbs.profile_version,
        }
    }
    pub(super) fn semantic_id(&self) -> Result<[u8; 32], E2eeError> {
        match &self.record {
            ArcSequencerRecord::Candidate(value) => {
                semantic_id_of(SemanticHashDomain::CandidateId, &value.tbs)
            }
            ArcSequencerRecord::Finalization(value) => semantic_id_of(
                SemanticHashDomain::FinalizationId,
                &value.tbs.request.proof.core,
            ),
            ArcSequencerRecord::Abort(value) => {
                semantic_id_of(SemanticHashDomain::AbortId, &value.tbs.request.core)
            }
            ArcSequencerRecord::ReinitActivation(value) => semantic_id_of(
                SemanticHashDomain::ReinitActivationId,
                &value.tbs.request.core,
            ),
            ArcSequencerRecord::ReinitAbort(value) => {
                semantic_id_of(SemanticHashDomain::ReinitAbortId, &value.tbs.request.core)
            }
            ArcSequencerRecord::ReinitAttempt(_) => semantic_id_of(
                SemanticHashDomain::ReinitAttemptId,
                &self.attempt.as_ref().ok_or(E2eeError::InvalidValue)?.tbs,
            ),
        }
    }
    pub(super) fn asserted_id(&mut self) -> Result<&mut [u8; 32], E2eeError> {
        match &mut self.record {
            ArcSequencerRecord::Finalization(value) => Ok(&mut value.tbs.finalization_id),
            ArcSequencerRecord::Abort(value) => Ok(&mut value.tbs.abort_id),
            ArcSequencerRecord::ReinitActivation(value) => Ok(&mut value.tbs.reinit_activation_id),
            ArcSequencerRecord::ReinitAbort(value) => Ok(&mut value.tbs.reinit_abort_id),
            _ => Err(E2eeError::InvalidValue),
        }
    }
    pub(super) fn refresh_terminal_id(&mut self) -> Result<(), E2eeError> {
        let id = self.semantic_id()?;
        *self.asserted_id()? = id;
        Ok(())
    }
    pub(super) fn refresh_attempt_object_id(&mut self) -> Result<(), E2eeError> {
        let bytes = object(
            ArcWireObjectKind::ReinitAttempt,
            self.attempt.as_ref().ok_or(E2eeError::InvalidValue)?,
        )?;
        let ArcSequencerRecord::ReinitAttempt(value) = &mut self.record else {
            return Err(E2eeError::InvalidValue);
        };
        value.tbs.attempt_object_id = *ObjectId::compute(&bytes).as_bytes();
        Ok(())
    }
    pub(super) fn core_context(
        &mut self,
    ) -> Result<(&mut u16, &mut [u8; 32], &mut [u8; 32]), E2eeError> {
        match &mut self.record {
            ArcSequencerRecord::Finalization(value) => {
                let core = &mut value.tbs.request.proof.core;
                Ok((
                    &mut core.profile_version,
                    &mut core.network_id,
                    &mut core.conversation_id,
                ))
            }
            ArcSequencerRecord::Abort(value) => {
                let core = &mut value.tbs.request.core;
                Ok((
                    &mut core.profile_version,
                    &mut core.network_id,
                    &mut core.conversation_id,
                ))
            }
            ArcSequencerRecord::ReinitActivation(value) => {
                let core = &mut value.tbs.request.core;
                Ok((
                    &mut core.profile_version,
                    &mut core.network_id,
                    &mut core.old_conversation_id,
                ))
            }
            ArcSequencerRecord::ReinitAbort(value) => {
                let core = &mut value.tbs.request.core;
                Ok((
                    &mut core.profile_version,
                    &mut core.network_id,
                    &mut core.old_conversation_id,
                ))
            }
            _ => Err(E2eeError::InvalidValue),
        }
    }
}
