#![forbid(unsafe_code)]
//! A real-signature conversation log: the pinned genesis authority plus a
//! sequencer that signs records at exact positions, controllers that approve
//! authorizations, and council devices that vote. Inner MLS evidence
//! (ACK leaf signatures, digests, Commit bytes) stays synthetic; every
//! outer signature and identifier the verifier checks is real.

use agenc_ircd_crypto::{SemanticHashDomain, SignatureDomain};
use agenc_ircd_e2ee::finality::{ReinitVoteSlot, Terminal, VoteSlot, reinit_vote_tbs, vote_tbs};
use agenc_ircd_e2ee::history::{ChainLimits, HistoricalChain, RecordReferences};
use agenc_ircd_e2ee::ids::{conversation_id, proof_set_digest, semantic_id_of};
use agenc_ircd_e2ee::initial_authority::{
    ExpectedInitialAuthority, InitialAuthority, InitialAuthorityEvidence, InitialPrincipalEvidence,
    authenticate_initial_authority,
};
use agenc_ircd_e2ee::objects::conversation::*;
use agenc_ircd_e2ee::objects::reinit::*;
use agenc_ircd_e2ee::objects::sequencing::*;
use agenc_ircd_e2ee::{
    DecodeBudget, E2eeError, IrcWireObject, IrcWireObjectKind, ObjectId, Opaque, TlsEncode, TlsVec,
};
use agenc_ircd_testkit::e2ee_client::*;

pub(super) type TestResult = Result<(), Box<dyn std::error::Error>>;
pub(super) const ACCOUNT: [u8; 24] = [b'a'; 24];
pub(super) const OTHER: [u8; 24] = [b'b'; 24];
pub(super) const GROUP: [u8; 32] = [25; 32];
pub(super) const SEQUENCER_SEED: u8 = 60;
/// Inside every roster and credential interval of the fixture.
pub(super) const VALIDATION_TIME: u64 = 150;

pub(super) fn budget() -> DecodeBudget {
    DecodeBudget::new(64 * 1024 * 1024, 1 << 18)
}

pub(super) fn object(
    kind: IrcWireObjectKind,
    value: &impl TlsEncode,
) -> Result<Vec<u8>, E2eeError> {
    IrcWireObject::new(kind, value.encode()?)?.encode()
}

pub(super) fn object_id(bytes: &[u8]) -> [u8; 32] {
    *ObjectId::compute(bytes).as_bytes()
}

/// The pinned genesis: two principals, a creator-only bootstrap policy, the
/// generation-one operational policy, and sequencer key generation zero.
pub(super) struct Genesis {
    pub(super) principals: Vec<Principal>,
    pub(super) package: IrcConversationBindingPackage,
    pub(super) core: IrcContextCoreTbs,
    pub(super) bootstrap_policy: IrcPolicy,
    pub(super) operational_policy: IrcPolicy,
    pub(super) credential: IrcSequencerCredential,
    pub(super) expected: ExpectedInitialAuthority,
    pub(super) conversation: [u8; 32],
}

impl Genesis {
    pub(super) fn new() -> Result<Self, E2eeError> {
        Self::with_group(GROUP)
    }

    pub(super) fn with_group(group: [u8; 32]) -> Result<Self, E2eeError> {
        let principals = vec![
            principal(40, &ACCOUNT, &[7, 8])?,
            principal(41, &OTHER, &[9])?,
        ];
        let refs = principals.iter().collect::<Vec<_>>();
        let conversation = conversation_id(&NETWORK, &group)?;
        let kind = IrcConversationKind::Channel;
        let bootstrap_policy = policy(&PolicySpec::bootstrap(&refs, conversation, kind)?)?;
        let operational_policy = policy(&PolicySpec::operational(
            &refs,
            conversation,
            kind,
            policy_id_of(&bootstrap_policy)?,
        )?)?;
        let authority = root_fingerprint(&principals.first().ok_or(E2eeError::InvalidValue)?.root)?;
        let mut package = binding_package(&BindingSpec {
            principals: &refs,
            route: channel_route(b"#room", authority)?,
            channel_instance_id: Some([1; 16]),
            conversation_nonce: None,
            group_id: group,
            generation: 0,
            previous_binding_id: [0; 32],
            lock_sequence: 0,
            previous_lock_ids: Vec::new(),
            plan_devices: vec![(&ACCOUNT, authority, 7)],
            initial_policy_id: policy_id_of(&bootstrap_policy)?,
            required_operational_policy_id: policy_id_of(&operational_policy)?,
        })?;
        let credential = sequencer_credential(&key(SEQUENCER_SEED), 0, (0, 1_000_000), None)?;
        package.binding.tbs.sequencer_credential_id =
            semantic_id_of(SemanticHashDomain::SequencerKey, &credential.tbs)?;
        let tbs = &package.binding.tbs;
        let core = IrcContextCoreTbs {
            profile_version: 1,
            mls_version: 1,
            cipher_suite: 1,
            group_id: tbs.group_id.clone(),
            network_id: NETWORK,
            conversation_id: conversation,
            kind,
            semantic_route_lock_id: tbs.semantic_route_lock_id,
            route_binding: tbs.route_binding,
            initial_validation_time: 100,
            initial_policy_id: tbs.initial_policy_id,
            required_operational_policy_id: tbs.required_operational_policy_id,
            initial_bootstrap_pending: 1,
            initial_member_plan_id: tbs.initial_member_plan_id,
            sequencer_credential_id: tbs.sequencer_credential_id,
            encoded_required_capabilities: Opaque::new(vec![
                0, 2, 0xf1, 0xc1, 0, 0, 0, 2, 0xf1, 0xc0,
            ])?,
        };
        let mut genesis = Self {
            principals,
            package,
            core,
            bootstrap_policy,
            operational_policy,
            credential,
            expected: ExpectedInitialAuthority {
                network_id: NETWORK,
                conversation_id: conversation,
                binding_id: [0; 32],
            },
            conversation,
        };
        genesis.seal()?;
        Ok(genesis)
    }

    fn seal(&mut self) -> Result<(), E2eeError> {
        self.package.binding.tbs.context_core_id =
            semantic_id_of(SemanticHashDomain::ContextCoreId, &self.core)?;
        let binding_id = semantic_id_of(SemanticHashDomain::BindingId, &self.package.binding.tbs)?;
        let mut approvals = self.package.binding.approvals.as_slice().to_vec();
        for approval in &mut approvals {
            let seed = *approval
                .signer_device_id
                .first()
                .ok_or(E2eeError::InvalidValue)?;
            approval.device_signature = sign(
                &key(seed),
                SignatureDomain::ConversationBinding,
                &self.package.binding.tbs,
            )?;
        }
        self.package.binding.approvals = TlsVec::new(approvals)?;
        let mut locks = self.package.root_binding_locks.as_slice().to_vec();
        for lock in &mut locks {
            let principal = self
                .principals
                .iter()
                .find(|principal| principal.root.tbs.account_id == lock.tbs.account_id)
                .ok_or(E2eeError::InvalidValue)?;
            lock.tbs.binding_id = binding_id;
            lock.root_signature = sign(
                &principal.root_secret,
                SignatureDomain::RootBindingLock,
                &lock.tbs,
            )?;
        }
        self.package.root_binding_locks = TlsVec::new(locks)?;
        self.expected.binding_id = binding_id;
        Ok(())
    }

    pub(super) fn authority(&self) -> Result<InitialAuthority, E2eeError> {
        let binding = object(IrcWireObjectKind::ConversationBinding, &self.package)?;
        let core = self.core.encode()?;
        let policy = object(IrcWireObjectKind::Policy, &self.bootstrap_policy)?;
        let credential = self.credential.encode()?;
        let pairs = self
            .principals
            .iter()
            .map(|principal| {
                Ok((
                    object(IrcWireObjectKind::RootIdentity, &principal.root)?,
                    object(IrcWireObjectKind::DeviceRoster, &principal.roster)?,
                ))
            })
            .collect::<Result<Vec<_>, E2eeError>>()?;
        let principals = pairs
            .iter()
            .map(|(root, roster)| InitialPrincipalEvidence {
                root_object: root,
                roster_object: roster,
            })
            .collect::<Vec<_>>();
        authenticate_initial_authority(
            &self.expected,
            &InitialAuthorityEvidence {
                binding_object: &binding,
                context_core: &core,
                initial_policy_object: &policy,
                sequencer_credential: &credential,
                principals: &principals,
            },
            &mut budget(),
        )
    }

    pub(super) fn chain(&self) -> Result<HistoricalChain, E2eeError> {
        HistoricalChain::open(
            &NETWORK,
            &self.conversation,
            &self.authority()?,
            ChainLimits::DEFAULT,
        )
    }

    pub(super) fn genesis_id(&self) -> Result<[u8; 32], E2eeError> {
        semantic_id_of(
            SemanticHashDomain::GroupGenesisId,
            &IrcGroupGenesisTbs {
                network_id: NETWORK,
                conversation_id: self.conversation,
                group_id: self.package.binding.tbs.group_id.clone(),
                binding_id: self.expected.binding_id,
                context_core_id: self.package.binding.tbs.context_core_id,
            },
        )
    }

    pub(super) fn principal(&self, index: usize) -> Result<&Principal, E2eeError> {
        self.principals.get(index).ok_or(E2eeError::InvalidValue)
    }
}

/// The sequencer's view of the log it signs.
pub(super) struct Log {
    pub(super) conversation: [u8; 32],
    pub(super) sequencer_seed: u8,
    pub(super) credential_id: [u8; 32],
    pub(super) route_sequence: u64,
    pub(super) head: [u8; 32],
    pub(super) epoch: u64,
    pub(super) accepted_state_id: [u8; 32],
    pub(super) candidate_sequence: u32,
    pub(super) policy_id: [u8; 32],
}

/// One built record: its complete wire object and semantic identifier.
pub(super) struct Built {
    pub(super) bytes: Vec<u8>,
    pub(super) id: [u8; 32],
}

/// The fields a candidate carries into its terminal.
#[derive(Clone)]
pub(super) struct Candidate {
    pub(super) receipt: IrcCandidateReceipt,
    pub(super) id: [u8; 32],
}

/// Who approves an authorization and who votes on its terminal, as
/// `(principal index, device seed)` pairs.
pub(super) struct Council<'a> {
    pub(super) genesis: &'a Genesis,
    pub(super) approvers: Vec<(usize, u8)>,
    pub(super) voters: Vec<(usize, u8)>,
}

impl Log {
    pub(super) fn new(genesis: &Genesis) -> Result<Self, E2eeError> {
        Ok(Self {
            conversation: genesis.conversation,
            sequencer_seed: SEQUENCER_SEED,
            credential_id: semantic_id_of(
                SemanticHashDomain::SequencerKey,
                &genesis.credential.tbs,
            )?,
            route_sequence: 0,
            head: genesis.genesis_id()?,
            epoch: 0,
            accepted_state_id: genesis.genesis_id()?,
            candidate_sequence: 0,
            policy_id: policy_id_of(&genesis.bootstrap_policy)?,
        })
    }

    /// A copy of the log for building records on a branch.
    pub(super) fn clone_for_fork(&self) -> Self {
        Self {
            conversation: self.conversation,
            sequencer_seed: self.sequencer_seed,
            credential_id: self.credential_id,
            route_sequence: self.route_sequence,
            head: self.head,
            epoch: self.epoch,
            accepted_state_id: self.accepted_state_id,
            candidate_sequence: self.candidate_sequence,
            policy_id: self.policy_id,
        }
    }

    fn advance(&mut self, id: [u8; 32]) {
        self.route_sequence = self.route_sequence.saturating_add(1);
        self.head = id;
    }

    fn signed(
        &self,
        record: &mut IrcSequencerRecord,
        domain: SignatureDomain,
    ) -> Result<(), E2eeError> {
        let (tbs, signature): (Vec<u8>, &mut [u8; 64]) = match record {
            IrcSequencerRecord::Candidate(value) => {
                (value.tbs.encode()?, &mut value.sequencer_signature)
            }
            IrcSequencerRecord::Finalization(value) => {
                (value.tbs.encode()?, &mut value.sequencer_signature)
            }
            IrcSequencerRecord::Abort(value) => {
                (value.tbs.encode()?, &mut value.sequencer_signature)
            }
            IrcSequencerRecord::ReinitAttempt(value) => {
                (value.tbs.encode()?, &mut value.sequencer_signature)
            }
            IrcSequencerRecord::ReinitActivation(value) => {
                (value.tbs.encode()?, &mut value.sequencer_signature)
            }
            IrcSequencerRecord::ReinitAbort(value) => {
                (value.tbs.encode()?, &mut value.sequencer_signature)
            }
        };
        *signature = *agenc_ircd_crypto::sign_canonical(&key(self.sequencer_seed), domain, &tbs)
            .map_err(|_| E2eeError::SignatureInvalid)?
            .as_bytes();
        Ok(())
    }

    pub(super) fn candidate(
        &mut self,
        commit_object_id: [u8; 32],
    ) -> Result<(Built, Candidate), E2eeError> {
        let tbs = IrcCandidateReceiptTbs {
            profile_version: 1,
            network_id: NETWORK,
            conversation_id: self.conversation,
            route_sequence: self.route_sequence,
            prior_epoch: self.epoch,
            resulting_epoch: self.epoch.saturating_add(1),
            candidate_sequence: self.candidate_sequence,
            commit_object_id,
            prior_state_id: self.accepted_state_id,
            predecessor_record_id: self.head,
            sequenced_at: VALIDATION_TIME,
            sequencer_key_id: self.credential_id,
        };
        let id = semantic_id_of(SemanticHashDomain::CandidateId, &tbs)?;
        let mut record = IrcSequencerRecord::Candidate(IrcCandidateReceipt {
            tbs,
            sequencer_signature: [0; 64],
        });
        self.signed(&mut record, SignatureDomain::CandidateReceipt)?;
        let IrcSequencerRecord::Candidate(receipt) = &record else {
            return Err(E2eeError::InvalidValue);
        };
        let candidate = Candidate {
            receipt: receipt.clone(),
            id,
        };
        self.advance(id);
        Ok((
            Built {
                bytes: object(IrcWireObjectKind::SequencerRecord, &record)?,
                id,
            },
            candidate,
        ))
    }

    /// The authorization TBS for `candidate` under the current policy.
    pub(super) fn authorization_tbs(
        &self,
        candidate: &Candidate,
        rule: IrcCommitAuthorizationRule,
        bits: u32,
        resulting_policy_id: [u8; 32],
        transition_target_digest: [u8; 32],
    ) -> IrcCommitAuthorizationTbs {
        IrcCommitAuthorizationTbs {
            profile_version: 1,
            network_id: NETWORK,
            conversation_id: self.conversation,
            prior_epoch: self.epoch,
            prior_state_id: self.accepted_state_id,
            candidate_id: candidate.id,
            commit_object_id: candidate.receipt.tbs.commit_object_id,
            canonical_validation_time: VALIDATION_TIME,
            old_policy_id: self.policy_id,
            authorization_rule: rule,
            action_bits: bits,
            resulting_policy_id,
            resulting_group_context_digest: [53; 32],
            resulting_ratchet_tree_digest: [54; 32],
            transition_target_digest,
        }
    }

    pub(super) fn slot(&self, candidate: &Candidate) -> VoteSlot {
        VoteSlot {
            network_id: NETWORK,
            conversation_id: self.conversation,
            prior_epoch: self.epoch,
            prior_state_id: self.accepted_state_id,
            candidate_sequence: candidate.receipt.tbs.candidate_sequence,
            predecessor_record_id: candidate.receipt.tbs.predecessor_record_id,
        }
    }

    /// A finalization proof for `candidate` under `authorization`, with one
    /// synthetic ACK from old leaf zero and real council votes.
    pub(super) fn finalization_request(
        &self,
        candidate: &Candidate,
        authorization: IrcCommitAuthorization,
        council: &Council<'_>,
    ) -> Result<(IrcFinalizationRequest, [u8; 32]), E2eeError> {
        let ack = IrcCommitAck {
            tbs: IrcCommitAckTbs {
                profile_version: 1,
                network_id: NETWORK,
                conversation_id: self.conversation,
                prior_epoch: self.epoch,
                candidate_id: candidate.id,
                commit_object_id: candidate.receipt.tbs.commit_object_id,
                old_leaf_index: 0,
                old_credential_hash: [55; 32],
                resulting_epoch: self.epoch.saturating_add(1),
                resulting_group_context_digest: authorization.tbs.resulting_group_context_digest,
                resulting_ratchet_tree_digest: authorization.tbs.resulting_ratchet_tree_digest,
                finalization_authenticator: [56; 32],
            },
            old_leaf_signature: Opaque::new(vec![57; 64])?,
        };
        let core = IrcFinalizationCoreTbs {
            profile_version: 1,
            network_id: NETWORK,
            conversation_id: self.conversation,
            prior_epoch: self.epoch,
            prior_state_id: self.accepted_state_id,
            candidate_id: candidate.id,
            commit_object_id: candidate.receipt.tbs.commit_object_id,
            resulting_epoch: self.epoch.saturating_add(1),
            old_policy_id: self.policy_id,
            commit_authorization_id: semantic_id_of(
                SemanticHashDomain::CommitAuthorizationId,
                &authorization.tbs,
            )?,
            acknowledgement_set_digest: proof_set_digest(
                SemanticHashDomain::AcknowledgementSet,
                std::slice::from_ref(&ack.tbs),
            )?,
            resulting_group_context_digest: authorization.tbs.resulting_group_context_digest,
            resulting_ratchet_tree_digest: authorization.tbs.resulting_ratchet_tree_digest,
            finalization_authenticator: [56; 32],
        };
        let finalization_id = semantic_id_of(SemanticHashDomain::FinalizationId, &core)?;
        let tbs = vote_tbs(
            &self.slot(candidate),
            candidate.id,
            Terminal::finalize(finalization_id),
        );
        let votes = council.votes(&tbs)?;
        Ok((
            IrcFinalizationRequest {
                proof: IrcFinalizationProof {
                    core,
                    receipt: candidate.receipt.clone(),
                    authorization,
                    acknowledgements: TlsVec::new(vec![ack])?,
                },
                votes: TlsVec::new(votes)?,
            },
            finalization_id,
        ))
    }

    /// Signs and adopts a finalization certificate for `request`.
    pub(super) fn finalization(
        &mut self,
        request: IrcFinalizationRequest,
        finalization_id: [u8; 32],
        resulting_policy_id: [u8; 32],
    ) -> Result<Built, E2eeError> {
        let mut record = IrcSequencerRecord::Finalization(IrcCommitFinalizationCertificate {
            tbs: IrcCommitFinalizationTbs {
                profile_version: 1,
                network_id: NETWORK,
                conversation_id: self.conversation,
                route_sequence: self.route_sequence,
                predecessor_record_id: self.head,
                finalization_id,
                sequencer_key_id: self.credential_id,
                request,
            },
            sequencer_signature: [0; 64],
        });
        self.signed(&mut record, SignatureDomain::CommitFinalization)?;
        self.advance(finalization_id);
        self.epoch = self.epoch.saturating_add(1);
        self.accepted_state_id = finalization_id;
        self.candidate_sequence = 0;
        self.policy_id = resulting_policy_id;
        Ok(Built {
            bytes: object(IrcWireObjectKind::SequencerRecord, &record)?,
            id: finalization_id,
        })
    }

    /// One routine self-update candidate finalized by `council`.
    pub(super) fn routine_step(
        &mut self,
        commit_object_id: [u8; 32],
        council: &Council<'_>,
    ) -> Result<(Built, Built), E2eeError> {
        let (candidate_record, candidate) = self.candidate(commit_object_id)?;
        let tbs = self.authorization_tbs(
            &candidate,
            IrcCommitAuthorizationRule::RoutineSelfUpdate,
            0,
            self.policy_id,
            [0; 32],
        );
        let authorization = council.authorization(tbs)?;
        let (request, finalization_id) =
            self.finalization_request(&candidate, authorization, council)?;
        let policy_id = self.policy_id;
        let finalization = self.finalization(request, finalization_id, policy_id)?;
        Ok((candidate_record, finalization))
    }

    pub(super) fn abort(
        &mut self,
        candidate: &Candidate,
        reason: IrcCommitAbortReason,
        council: &Council<'_>,
    ) -> Result<Built, E2eeError> {
        let core = IrcAbortCoreTbs {
            profile_version: 1,
            network_id: NETWORK,
            conversation_id: self.conversation,
            prior_state_id: self.accepted_state_id,
            candidate_id: candidate.id,
            prior_epoch: self.epoch,
            reason,
            evidence_digest: [65; 32],
        };
        let abort_id = semantic_id_of(SemanticHashDomain::AbortId, &core)?;
        let terminal = Terminal::abort(abort_id, u16::from(reason.value()))?;
        let tbs = vote_tbs(&self.slot(candidate), candidate.id, terminal);
        let votes = council.votes(&tbs)?;
        let mut record = IrcSequencerRecord::Abort(IrcCommitAbortCertificate {
            tbs: IrcCommitAbortTbs {
                profile_version: 1,
                network_id: NETWORK,
                conversation_id: self.conversation,
                route_sequence: self.route_sequence,
                predecessor_record_id: self.head,
                abort_id,
                sequencer_key_id: self.credential_id,
                request: IrcAbortRequest {
                    core,
                    receipt: candidate.receipt.clone(),
                    votes: TlsVec::new(votes)?,
                },
            },
            sequencer_signature: [0; 64],
        });
        self.signed(&mut record, SignatureDomain::CandidateAbort)?;
        self.advance(abort_id);
        self.candidate_sequence = self.candidate_sequence.saturating_add(1);
        Ok(Built {
            bytes: object(IrcWireObjectKind::SequencerRecord, &record)?,
            id: abort_id,
        })
    }

    /// A ReInit attempt after the old ReInit Commit finalized with
    /// `target_context_digest`, approved by `council`'s approvers.
    pub(super) fn reinit_attempt(
        &mut self,
        old_reinit_state_id: [u8; 32],
        attempt_sequence: u32,
        target_context_digest: [u8; 32],
        council: &Council<'_>,
    ) -> Result<(Vec<u8>, Built, IrcReInitAttemptReceipt, IrcReInitAttempt), E2eeError> {
        let tbs = IrcReInitAttemptTbs {
            profile_version: 1,
            network_id: NETWORK,
            old_conversation_id: self.conversation,
            new_conversation_id: [70; 32],
            old_reinit_state_id,
            attempt_sequence,
            creator_old_leaf_index: 0,
            creator_old_credential_hash: [55; 32],
            target_group_id: Opaque::new(vec![71; 32])?,
            target_version: 1,
            target_suite: 1,
            target_context_digest,
            target_binding_id: [73; 32],
            initial_member_plan_id: [29; 32],
            key_package_plan_id: [0; 32],
            initial_commit_digest: [0; 32],
            attempt_authorization_id: [0; 32],
            new_group_info_digest: [77; 32],
            new_group_context_digest: [78; 32],
            new_ratchet_tree_digest: [79; 32],
            new_exporter_authenticator: [80; 32],
        };
        let plan = IrcKeyPackagePlan {
            entries: TlsVec::new(vec![
                IrcKeyPackagePlanEntry {
                    account_id: account_field(&ACCOUNT)?,
                    root_fingerprint: root_fingerprint(&council.genesis.principal(0)?.root)?,
                    device_id: [7; 16],
                    capability_id: [207; 32],
                    key_package_ref: Opaque::new(Vec::new())?,
                    leaf_signature_scheme: 0x0807,
                    leaf_signature_key_digest: [81; 32],
                    creator: 1,
                },
                IrcKeyPackagePlanEntry {
                    account_id: account_field(&OTHER)?,
                    root_fingerprint: root_fingerprint(&council.genesis.principal(1)?.root)?,
                    device_id: [9; 16],
                    capability_id: [209; 32],
                    key_package_ref: Opaque::new(vec![82; 16])?,
                    leaf_signature_scheme: 0x0807,
                    leaf_signature_key_digest: [83; 32],
                    creator: 0,
                },
            ])?,
        };
        let initial_commit = Opaque::new(vec![84; 100])?;
        let mut tbs = tbs;
        tbs.key_package_plan_id = semantic_id_of(SemanticHashDomain::KeyPackagePlanId, &plan)?;
        tbs.initial_commit_digest =
            agenc_ircd_e2ee::ids::initial_commit_digest(initial_commit.as_slice())?;
        let authorization_tbs = IrcReInitAttemptAuthorizationTbs {
            profile_version: 1,
            network_id: NETWORK,
            old_conversation_id: tbs.old_conversation_id,
            old_reinit_state_id: tbs.old_reinit_state_id,
            attempt_sequence: tbs.attempt_sequence,
            creator_old_leaf_index: tbs.creator_old_leaf_index,
            creator_old_credential_hash: tbs.creator_old_credential_hash,
            new_conversation_id: tbs.new_conversation_id,
            target_context_digest: tbs.target_context_digest,
            target_binding_id: tbs.target_binding_id,
            initial_member_plan_id: tbs.initial_member_plan_id,
            key_package_plan_id: tbs.key_package_plan_id,
            initial_commit_digest: tbs.initial_commit_digest,
            new_group_info_digest: tbs.new_group_info_digest,
            new_group_context_digest: tbs.new_group_context_digest,
            new_ratchet_tree_digest: tbs.new_ratchet_tree_digest,
            new_exporter_authenticator: tbs.new_exporter_authenticator,
        };
        tbs.attempt_authorization_id = semantic_id_of(
            SemanticHashDomain::ReinitAttemptAuthorizationId,
            &authorization_tbs,
        )?;
        let approvals = council.approvals(
            &authorization_tbs,
            SignatureDomain::ReinitAttemptAuthorization,
        )?;
        let attempt = IrcReInitAttempt {
            tbs,
            key_package_plan: plan,
            initial_commit_bytes: initial_commit,
            authorization: IrcReInitAttemptAuthorization {
                tbs: authorization_tbs,
                approvals: TlsVec::new(approvals)?,
            },
            creator_old_leaf_signature: Opaque::new(vec![85; 64])?,
        };
        let attempt_bytes = object(IrcWireObjectKind::ReinitAttempt, &attempt)?;
        let attempt_id = semantic_id_of(SemanticHashDomain::ReinitAttemptId, &attempt.tbs)?;
        let receipt_tbs = IrcReInitAttemptReceiptTbs {
            profile_version: 1,
            network_id: NETWORK,
            old_conversation_id: self.conversation,
            old_reinit_state_id,
            route_sequence: self.route_sequence,
            attempt_sequence,
            predecessor_record_id: self.head,
            reinit_attempt_id: attempt_id,
            attempt_object_id: object_id(&attempt_bytes),
            sequenced_at: VALIDATION_TIME,
            sequencer_key_id: self.credential_id,
        };
        let mut record = IrcSequencerRecord::ReinitAttempt(IrcReInitAttemptReceipt {
            tbs: receipt_tbs,
            sequencer_signature: [0; 64],
        });
        self.signed(&mut record, SignatureDomain::ReinitAttemptReceipt)?;
        let IrcSequencerRecord::ReinitAttempt(receipt) = &record else {
            return Err(E2eeError::InvalidValue);
        };
        let receipt = receipt.clone();
        self.advance(attempt_id);
        Ok((
            attempt_bytes,
            Built {
                bytes: object(IrcWireObjectKind::SequencerRecord, &record)?,
                id: attempt_id,
            },
            receipt,
            attempt,
        ))
    }

    fn reinit_slot(&self, receipt: &IrcReInitAttemptReceipt) -> ReinitVoteSlot {
        ReinitVoteSlot {
            network_id: NETWORK,
            old_conversation_id: self.conversation,
            old_reinit_state_id: receipt.tbs.old_reinit_state_id,
            attempt_sequence: receipt.tbs.attempt_sequence,
            predecessor_record_id: receipt.tbs.predecessor_record_id,
        }
    }

    fn reinit_ack(
        attempt: &IrcReInitAttempt,
        entry: &IrcKeyPackagePlanEntry,
        index: u32,
    ) -> Result<IrcReInitAck, E2eeError> {
        let tbs = &attempt.tbs;
        let creator = entry.creator == 1;
        Ok(IrcReInitAck {
            tbs: IrcReInitAckTbs {
                profile_version: 1,
                network_id: NETWORK,
                old_conversation_id: tbs.old_conversation_id,
                new_conversation_id: tbs.new_conversation_id,
                old_reinit_state_id: tbs.old_reinit_state_id,
                reinit_attempt_id: semantic_id_of(SemanticHashDomain::ReinitAttemptId, tbs)?,
                ack_kind: if creator {
                    IrcReInitAckKind::CreatorState
                } else {
                    IrcReInitAckKind::WelcomeJoin
                },
                new_group_info_digest: tbs.new_group_info_digest,
                new_group_context_digest: tbs.new_group_context_digest,
                new_ratchet_tree_digest: tbs.new_ratchet_tree_digest,
                new_exporter_authenticator: tbs.new_exporter_authenticator,
                old_leaf_index: index,
                old_credential_hash: if creator {
                    tbs.creator_old_credential_hash
                } else {
                    [66; 32]
                },
                new_leaf_index: index,
                key_package_ref: entry.key_package_ref.clone(),
            },
            old_leaf_signature: Opaque::new(vec![89; 64])?,
        })
    }

    pub(super) fn reinit_activation(
        &mut self,
        receipt: &IrcReInitAttemptReceipt,
        attempt: &IrcReInitAttempt,
        council: &Council<'_>,
    ) -> Result<Built, E2eeError> {
        let acks = attempt
            .key_package_plan
            .entries
            .as_slice()
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                Self::reinit_ack(attempt, entry, u32::try_from(index).unwrap_or(0))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let tbs: Vec<_> = acks.iter().map(|ack| ack.tbs.clone()).collect();
        let core = IrcReInitActivationCoreTbs {
            profile_version: 1,
            network_id: NETWORK,
            old_conversation_id: self.conversation,
            new_conversation_id: attempt.tbs.new_conversation_id,
            old_reinit_state_id: attempt.tbs.old_reinit_state_id,
            attempt_sequence: attempt.tbs.attempt_sequence,
            reinit_attempt_id: receipt.tbs.reinit_attempt_id,
            new_group_info_digest: attempt.tbs.new_group_info_digest,
            new_group_context_digest: attempt.tbs.new_group_context_digest,
            new_ratchet_tree_digest: attempt.tbs.new_ratchet_tree_digest,
            new_exporter_authenticator: attempt.tbs.new_exporter_authenticator,
            acknowledgement_set_digest: proof_set_digest(
                SemanticHashDomain::ReinitAcknowledgementSet,
                &tbs,
            )?,
        };
        let activation_id = semantic_id_of(SemanticHashDomain::ReinitActivationId, &core)?;
        let vote = reinit_vote_tbs(
            &self.reinit_slot(receipt),
            receipt.tbs.reinit_attempt_id,
            Terminal::finalize(activation_id),
        );
        let votes = council.reinit_votes(&vote)?;
        let mut record = IrcSequencerRecord::ReinitActivation(IrcReInitActivationCertificate {
            tbs: IrcReInitActivationTbs {
                profile_version: 1,
                network_id: NETWORK,
                old_conversation_id: self.conversation,
                route_sequence: self.route_sequence,
                predecessor_record_id: self.head,
                reinit_activation_id: activation_id,
                sequencer_key_id: self.credential_id,
                request: IrcReInitActivationRequest {
                    core,
                    receipt: receipt.clone(),
                    attempt: attempt.clone(),
                    acknowledgements: TlsVec::new(acks)?,
                    votes: TlsVec::new(votes)?,
                },
            },
            sequencer_signature: [0; 64],
        });
        self.signed(&mut record, SignatureDomain::ReinitActivation)?;
        self.advance(activation_id);
        Ok(Built {
            bytes: object(IrcWireObjectKind::SequencerRecord, &record)?,
            id: activation_id,
        })
    }

    pub(super) fn reinit_abort(
        &mut self,
        receipt: &IrcReInitAttemptReceipt,
        attempt: &IrcReInitAttempt,
        reason_code: u16,
        council: &Council<'_>,
    ) -> Result<Built, E2eeError> {
        let core = IrcReInitAbortCoreTbs {
            profile_version: 1,
            network_id: NETWORK,
            old_conversation_id: self.conversation,
            old_reinit_state_id: attempt.tbs.old_reinit_state_id,
            attempt_sequence: attempt.tbs.attempt_sequence,
            slot_predecessor_record_id: receipt.tbs.predecessor_record_id,
            reinit_attempt_id: receipt.tbs.reinit_attempt_id,
            reason_code,
            evidence_digest: [94; 32],
        };
        let abort_id = semantic_id_of(SemanticHashDomain::ReinitAbortId, &core)?;
        let vote = reinit_vote_tbs(
            &self.reinit_slot(receipt),
            receipt.tbs.reinit_attempt_id,
            Terminal::abort(abort_id, reason_code)?,
        );
        let votes = council.reinit_votes(&vote)?;
        let mut record = IrcSequencerRecord::ReinitAbort(IrcReInitAbortCertificate {
            tbs: IrcReInitAbortTbs {
                profile_version: 1,
                network_id: NETWORK,
                old_conversation_id: self.conversation,
                route_sequence: self.route_sequence,
                predecessor_record_id: self.head,
                reinit_abort_id: abort_id,
                sequencer_key_id: self.credential_id,
                request: IrcReInitAbortRequest {
                    core,
                    receipt: receipt.clone(),
                    attempt: attempt.clone(),
                    votes: TlsVec::new(votes)?,
                },
            },
            sequencer_signature: [0; 64],
        });
        self.signed(&mut record, SignatureDomain::ReinitAttemptAbort)?;
        self.advance(abort_id);
        Ok(Built {
            bytes: object(IrcWireObjectKind::SequencerRecord, &record)?,
            id: abort_id,
        })
    }

    /// A close authorization naming the head finalization.
    pub(super) fn close(
        &self,
        binding_id: [u8; 32],
        intent: IrcCloseIntent,
        council: &Council<'_>,
    ) -> Result<(Vec<u8>, [u8; 32]), E2eeError> {
        self.close_signed(
            binding_id,
            intent,
            council,
            SignatureDomain::CloseAuthorization,
        )
    }

    /// A close authorization whose approvals sign under `domain`.
    pub(super) fn close_signed(
        &self,
        binding_id: [u8; 32],
        intent: IrcCloseIntent,
        council: &Council<'_>,
        domain: SignatureDomain,
    ) -> Result<(Vec<u8>, [u8; 32]), E2eeError> {
        let close_intent_id = semantic_id_of(SemanticHashDomain::CloseIntentId, &intent)?;
        let tbs = IrcCloseAuthorizationTbs {
            profile_version: 1,
            network_id: NETWORK,
            conversation_id: self.conversation,
            binding_id,
            authorizing_terminal_id: self.head,
            close_intent: intent,
            close_intent_id,
        };
        let approvals = council.approvals(&tbs, domain)?;
        let close = IrcCloseAuthorization {
            tbs,
            approvals: TlsVec::new(approvals)?,
        };
        let id = semantic_id_of(SemanticHashDomain::CloseAuthorizationId, &close.tbs)?;
        Ok((object(IrcWireObjectKind::CloseAuthorization, &close)?, id))
    }
}

impl Council<'_> {
    pub(super) fn authorization(
        &self,
        tbs: IrcCommitAuthorizationTbs,
    ) -> Result<IrcCommitAuthorization, E2eeError> {
        let approvers = self
            .approvers
            .iter()
            .map(|(index, device)| Ok((self.genesis.principal(*index)?, *device)))
            .collect::<Result<Vec<_>, E2eeError>>()?;
        commit_authorization(tbs, &approvers)
    }

    pub(super) fn approvals(
        &self,
        tbs: &impl TlsEncode,
        domain: SignatureDomain,
    ) -> Result<Vec<IrcCommitApproval>, E2eeError> {
        let mut approvals = self
            .approvers
            .iter()
            .map(|(index, device)| {
                commit_approval(self.genesis.principal(*index)?, *device, tbs, domain)
            })
            .collect::<Result<Vec<_>, _>>()?;
        approvals
            .sort_by_key(|approval| (approval.signer_root_fingerprint, approval.signer_device_id));
        Ok(approvals)
    }

    pub(super) fn votes(
        &self,
        tbs: &IrcDispositionVoteTbs,
    ) -> Result<Vec<IrcFinalityVote>, E2eeError> {
        let mut votes = self
            .voters
            .iter()
            .map(|(index, device)| finality_vote(self.genesis.principal(*index)?, *device, tbs))
            .collect::<Result<Vec<_>, _>>()?;
        votes.sort_by_key(|vote| (vote.signer_root_fingerprint, vote.signer_device_id));
        Ok(votes)
    }

    pub(super) fn reinit_votes(
        &self,
        tbs: &IrcReInitDispositionVoteTbs,
    ) -> Result<Vec<IrcFinalityVote>, E2eeError> {
        let mut votes = self
            .voters
            .iter()
            .map(|(index, device)| {
                let principal = self.genesis.principal(*index)?;
                Ok(IrcFinalityVote {
                    signer_root_fingerprint: root_fingerprint(&principal.root)?,
                    signer_device_id: [*device; 16],
                    signer_device_certificate_id: certificate_id_of(principal, *device)?,
                    device_signature: sign(&key(*device), SignatureDomain::ReinitDisposition, tbs)?,
                })
            })
            .collect::<Result<Vec<_>, E2eeError>>()?;
        votes.sort_by_key(|vote| (vote.signer_root_fingerprint, vote.signer_device_id));
        Ok(votes)
    }
}

/// Adopts `record` with no references and returns the step.
pub(super) fn adopt(
    chain: &mut HistoricalChain,
    record: &Built,
) -> Result<agenc_ircd_e2ee::history::ChainStep, E2eeError> {
    chain.advance(&record.bytes, &RecordReferences::default(), &mut budget())
}
