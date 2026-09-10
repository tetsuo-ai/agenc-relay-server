#![forbid(unsafe_code)]
//! Real outer signatures over deliberately synthetic inner endpoint evidence.
use super::shapes;
use agenc_ircd_crypto::{Ed25519SecretKey, SemanticHashDomain, SignatureDomain, sign_canonical};
use agenc_ircd_e2ee::ids::semantic_id_of;
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind, ObjectId};
use agenc_ircd_e2ee::objects::conversation::{IrcSequencerCredential, IrcSequencerCredentialTbs};
use agenc_ircd_e2ee::objects::reinit::IrcReInitAttempt;
use agenc_ircd_e2ee::objects::sequencing::IrcSequencerRecord;
pub(super) use agenc_ircd_e2ee::objects::sequencing::IrcSequencerRecordKind as Kind;
pub(super) use agenc_ircd_e2ee::record_authentication::ExpectedRecord;
use agenc_ircd_e2ee::record_authentication::{AuthenticatedRecord, authenticate_record};
use agenc_ircd_e2ee::sequencer::{VerifiedSequencerCredential, verify_sequencer_credential};
use agenc_ircd_e2ee::{DecodeBudget, E2eeError, Opaque, TlsEncode};

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
    kind: IrcWireObjectKind,
    value: &impl TlsEncode,
) -> Result<Vec<u8>, E2eeError> {
    IrcWireObject::new(kind, value.encode()?)?.encode()
}

pub(super) struct Case {
    pub(super) record: IrcSequencerRecord,
    pub(super) attempt: Option<IrcReInitAttempt>,
    pub(super) credential: VerifiedSequencerCredential,
    pub(super) expected: ExpectedRecord,
}

impl Case {
    pub(super) fn new(kind: Kind) -> Result<Self, E2eeError> {
        let secret = Ed25519SecretKey::from_bytes([60; 32]);
        let credential = verify_sequencer_credential(
            &[1; 32],
            &IrcSequencerCredential {
                tbs: IrcSequencerCredentialTbs {
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
                IrcSequencerRecord::Candidate(shapes::receipt()),
                None,
                0,
                [50; 32],
            ),
            Kind::FinalizationRecord => (
                IrcSequencerRecord::Finalization(shapes::finalization()?),
                None,
                1,
                [52; 32],
            ),
            Kind::AbortRecord => (
                IrcSequencerRecord::Abort(shapes::abort()?),
                None,
                1,
                [52; 32],
            ),
            Kind::ReinitAttemptRecord => (
                IrcSequencerRecord::ReinitAttempt(shapes::attempt_receipt()),
                Some(shapes::reinit_attempt()?),
                2,
                [58; 32],
            ),
            Kind::ReinitActivationRecord => (
                IrcSequencerRecord::ReinitActivation(shapes::activation()?),
                None,
                3,
                [85; 32],
            ),
            Kind::ReinitAbortRecord => (
                IrcSequencerRecord::ReinitAbort(shapes::reinit_abort()?),
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
            let IrcSequencerRecord::ReinitAttempt(value) = &mut case.record else {
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
        object(IrcWireObjectKind::SequencerRecord, &self.record)
    }
    pub(super) fn authenticate(&self) -> Result<AuthenticatedRecord, E2eeError> {
        let attempt = self
            .attempt
            .as_ref()
            .map(|value| object(IrcWireObjectKind::ReinitAttempt, value))
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
            IrcSequencerRecord::Candidate(_) => SignatureDomain::CandidateReceipt,
            IrcSequencerRecord::Finalization(_) => SignatureDomain::CommitFinalization,
            IrcSequencerRecord::Abort(_) => SignatureDomain::CandidateAbort,
            IrcSequencerRecord::ReinitAttempt(_) => SignatureDomain::ReinitAttemptReceipt,
            IrcSequencerRecord::ReinitActivation(_) => SignatureDomain::ReinitActivation,
            IrcSequencerRecord::ReinitAbort(_) => SignatureDomain::ReinitAttemptAbort,
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
            IrcSequencerRecord::Candidate(value) => (&value.tbs, &mut value.sequencer_signature),
            IrcSequencerRecord::Finalization(value) => (&value.tbs, &mut value.sequencer_signature),
            IrcSequencerRecord::Abort(value) => (&value.tbs, &mut value.sequencer_signature),
            IrcSequencerRecord::ReinitAttempt(value) => {
                (&value.tbs, &mut value.sequencer_signature)
            }
            IrcSequencerRecord::ReinitActivation(value) => {
                (&value.tbs, &mut value.sequencer_signature)
            }
            IrcSequencerRecord::ReinitAbort(value) => (&value.tbs, &mut value.sequencer_signature),
        };
        *signature = *sign_canonical(secret, domain, &tbs.encode()?)
            .map_err(|_| E2eeError::SignatureInvalid)?
            .as_bytes();
        Ok(())
    }
    fn key_id(&mut self) -> &mut [u8; 32] {
        match &mut self.record {
            IrcSequencerRecord::Candidate(value) => &mut value.tbs.sequencer_key_id,
            IrcSequencerRecord::Finalization(value) => &mut value.tbs.sequencer_key_id,
            IrcSequencerRecord::Abort(value) => &mut value.tbs.sequencer_key_id,
            IrcSequencerRecord::ReinitAttempt(value) => &mut value.tbs.sequencer_key_id,
            IrcSequencerRecord::ReinitActivation(value) => &mut value.tbs.sequencer_key_id,
            IrcSequencerRecord::ReinitAbort(value) => &mut value.tbs.sequencer_key_id,
        }
    }
    pub(super) fn outer_profile(&mut self) -> &mut u16 {
        match &mut self.record {
            IrcSequencerRecord::Candidate(value) => &mut value.tbs.profile_version,
            IrcSequencerRecord::Finalization(value) => &mut value.tbs.profile_version,
            IrcSequencerRecord::Abort(value) => &mut value.tbs.profile_version,
            IrcSequencerRecord::ReinitAttempt(value) => &mut value.tbs.profile_version,
            IrcSequencerRecord::ReinitActivation(value) => &mut value.tbs.profile_version,
            IrcSequencerRecord::ReinitAbort(value) => &mut value.tbs.profile_version,
        }
    }
    pub(super) fn semantic_id(&self) -> Result<[u8; 32], E2eeError> {
        match &self.record {
            IrcSequencerRecord::Candidate(value) => {
                semantic_id_of(SemanticHashDomain::CandidateId, &value.tbs)
            }
            IrcSequencerRecord::Finalization(value) => semantic_id_of(
                SemanticHashDomain::FinalizationId,
                &value.tbs.request.proof.core,
            ),
            IrcSequencerRecord::Abort(value) => {
                semantic_id_of(SemanticHashDomain::AbortId, &value.tbs.request.core)
            }
            IrcSequencerRecord::ReinitActivation(value) => semantic_id_of(
                SemanticHashDomain::ReinitActivationId,
                &value.tbs.request.core,
            ),
            IrcSequencerRecord::ReinitAbort(value) => {
                semantic_id_of(SemanticHashDomain::ReinitAbortId, &value.tbs.request.core)
            }
            IrcSequencerRecord::ReinitAttempt(_) => semantic_id_of(
                SemanticHashDomain::ReinitAttemptId,
                &self.attempt.as_ref().ok_or(E2eeError::InvalidValue)?.tbs,
            ),
        }
    }
    pub(super) fn asserted_id(&mut self) -> Result<&mut [u8; 32], E2eeError> {
        match &mut self.record {
            IrcSequencerRecord::Finalization(value) => Ok(&mut value.tbs.finalization_id),
            IrcSequencerRecord::Abort(value) => Ok(&mut value.tbs.abort_id),
            IrcSequencerRecord::ReinitActivation(value) => Ok(&mut value.tbs.reinit_activation_id),
            IrcSequencerRecord::ReinitAbort(value) => Ok(&mut value.tbs.reinit_abort_id),
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
            IrcWireObjectKind::ReinitAttempt,
            self.attempt.as_ref().ok_or(E2eeError::InvalidValue)?,
        )?;
        let IrcSequencerRecord::ReinitAttempt(value) = &mut self.record else {
            return Err(E2eeError::InvalidValue);
        };
        value.tbs.attempt_object_id = *ObjectId::compute(&bytes).as_bytes();
        Ok(())
    }
    pub(super) fn core_context(
        &mut self,
    ) -> Result<(&mut u16, &mut [u8; 32], &mut [u8; 32]), E2eeError> {
        match &mut self.record {
            IrcSequencerRecord::Finalization(value) => {
                let core = &mut value.tbs.request.proof.core;
                Ok((
                    &mut core.profile_version,
                    &mut core.network_id,
                    &mut core.conversation_id,
                ))
            }
            IrcSequencerRecord::Abort(value) => {
                let core = &mut value.tbs.request.core;
                Ok((
                    &mut core.profile_version,
                    &mut core.network_id,
                    &mut core.conversation_id,
                ))
            }
            IrcSequencerRecord::ReinitActivation(value) => {
                let core = &mut value.tbs.request.core;
                Ok((
                    &mut core.profile_version,
                    &mut core.network_id,
                    &mut core.old_conversation_id,
                ))
            }
            IrcSequencerRecord::ReinitAbort(value) => {
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
