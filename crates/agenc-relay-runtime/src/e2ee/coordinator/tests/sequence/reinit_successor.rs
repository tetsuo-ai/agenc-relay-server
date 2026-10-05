#![forbid(unsafe_code)]

//! The ReInit successor a harness conversation migrates to, built as
//! companion 13.8 describes it, and the finalized ReInit Commit whose
//! authorization commits that successor's target: the support of the
//! sequencer's attempt checks and of the successor installation.
//!
//! The successor keeps the old binding's semantic route lock, concrete route
//! and principals, names a generation-zero policy of the harness principal,
//! pins the harness's sequencer credential, and plans exactly the devices of
//! the KeyPackage plan it is built from. Its target's extension list carries
//! the context and an empty `required_capabilities` extension, so the
//! target meets every structural rule a sequencer applies to the target an
//! attempt carries.

use agenc_relay_crypto::SemanticHashDomain;
use agenc_relay_e2ee::context::context_core_id;
use agenc_relay_e2ee::finality::Terminal;
use agenc_relay_e2ee::ids::{account_id_digest, conversation_id, semantic_id_of};
use agenc_relay_e2ee::limits::ARC_MLS_CONTEXT_EXTENSION;
use agenc_relay_e2ee::object::ArcWireObjectKind;
use agenc_relay_e2ee::objects::aad::ArcCommitAad;
use agenc_relay_e2ee::objects::conversation::{
    ArcCommitAuthorizationRule, ArcContextCoreTbs, ArcConversationBinding,
    ArcConversationBindingPackage, ArcConversationLifecycle, ArcConversationLifecycleKind,
    ArcInitialMemberPlan, ArcInitialMemberPlanEntry, ArcKeyPackagePlan, ArcKeyPackagePlanEntry,
    ArcMlsContext, ArcRosterHead, action_bits,
};
use agenc_relay_e2ee::objects::federation::ArcFederationOpcode as Op;
use agenc_relay_e2ee::objects::reinit::ArcReInitTargetTbs;
use agenc_relay_e2ee::objects::sequencing::{
    ArcCandidateReceipt, ArcCommitAck, ArcFinalizationCoreTbs, ArcFinalizationProof,
    ArcFinalizationRequest,
};
use agenc_relay_e2ee::reinit_target::REQUIRED_CAPABILITIES_EXTENSION;
use agenc_relay_e2ee::route::verify_initial_member_plan;
use agenc_relay_e2ee::tls::{DecodeBudget, Opaque, TlsDecode, TlsEncode, TlsVec};

use super::super::support::{
    PolicySpec, authorization_tbs, commit_authorization, opaque_v, policy, policy_id_of,
    private_message_at_epoch, root_fingerprint, roster_id,
};
use super::super::{
    DEVICE, DEVICE_ID, Harness, LEAF_SEED, NETWORK, ResultBody, TestResult, object_id, ok, wire,
    wire_raw,
};
use super::leaf_membership::{commit_ack_as, credential_of};
use super::{COMMIT_CONTENT_TYPE, vote};

/// The successor group every harness ReInit targets.
pub(in crate::e2ee::coordinator::tests) const SUCCESSOR_GROUP: [u8; 32] = [11; 32];
/// The successor's cipher suite, the harness policies' selected suite.
pub(in crate::e2ee::coordinator::tests) const SUCCESSOR_SUITE: u16 = 1;
/// The successor context's initial validation time.
const SUCCESSOR_VALIDATION_TIME: u64 = 60;
/// An empty RFC 9420 `RequiredCapabilities`: three empty vectors.
const REQUIRED_CAPABILITIES: [u8; 3] = [0, 0, 0];

/// One ReInit successor of a bound harness conversation.
#[derive(Clone, Debug)]
pub(in crate::e2ee::coordinator::tests) struct Successor {
    /// The exact target every attempt carries.
    pub(in crate::e2ee::coordinator::tests) target: ArcReInitTargetTbs,
    /// `target_context_digest`, the digest the ReInit authorization commits.
    pub(in crate::e2ee::coordinator::tests) digest: [u8; 32],
    /// The successor conversation.
    pub(in crate::e2ee::coordinator::tests) conversation: [u8; 32],
    /// The successor binding's identifier.
    pub(in crate::e2ee::coordinator::tests) binding_id: [u8; 32],
    /// The semantic initial member plan's identifier.
    pub(in crate::e2ee::coordinator::tests) plan_id: [u8; 32],
    /// The KeyPackage plan every attempt for this target carries.
    pub(in crate::e2ee::coordinator::tests) plan: ArcKeyPackagePlan,
    /// The successor context the extension list carries.
    pub(in crate::e2ee::coordinator::tests) context: ArcMlsContext,
}

impl Successor {
    /// The successor's binding package: the context's binding with the plan
    /// the KeyPackage plan forms and no root binding lock (companion 13.8).
    pub(in crate::e2ee::coordinator::tests) fn package(
        &self,
    ) -> TestResult<ArcConversationBindingPackage> {
        Ok(ArcConversationBindingPackage {
            binding: self.context.current_binding.clone(),
            initial_member_plan: formed_plan(&self.plan)?,
            root_binding_locks: TlsVec::new(Vec::new())?,
        })
    }
}

/// The successor conversation of every harness ReInit.
pub(in crate::e2ee::coordinator::tests) fn new_conversation() -> TestResult<[u8; 32]> {
    Ok(conversation_id(&NETWORK, &SUCCESSOR_GROUP)?)
}

/// The KeyPackage plan of the harness's attached device as the only
/// continuing leaf, the creator.
pub(in crate::e2ee::coordinator::tests) fn creator_plan(
    harness: &Harness,
) -> TestResult<ArcKeyPackagePlan> {
    Ok(ArcKeyPackagePlan {
        entries: TlsVec::new(vec![creator_entry(harness)?])?,
    })
}

/// The creator's plan entry: the attached device with its capability.
pub(in crate::e2ee::coordinator::tests) fn creator_entry(
    harness: &Harness,
) -> TestResult<ArcKeyPackagePlanEntry> {
    Ok(ArcKeyPackagePlanEntry {
        account_id: Opaque::from_slice(&harness.account)?,
        root_fingerprint: root_fingerprint(&harness.principal.root)?,
        device_id: DEVICE_ID,
        capability_id: [13; 32],
        key_package_ref: Opaque::new(vec![14; 32])?,
        leaf_signature_scheme: 0x0807,
        leaf_signature_key_digest: [18; 32],
        creator: 1,
    })
}

/// The `ArcInitialMemberPlan` a KeyPackage plan forms: its device tuples
/// and capability IDs in the plan's order (companion 9.4 and 13.8).
fn formed_plan(plan: &ArcKeyPackagePlan) -> TestResult<ArcInitialMemberPlan> {
    let entries = plan
        .entries
        .as_slice()
        .iter()
        .map(|entry| ArcInitialMemberPlanEntry {
            account_id: entry.account_id.clone(),
            root_fingerprint: entry.root_fingerprint,
            device_id: entry.device_id,
            capability_id: entry.capability_id,
        })
        .collect();
    Ok(ArcInitialMemberPlan {
        entries: TlsVec::new(entries)?,
    })
}

/// An MLS `Extension extensions<V>` list of `(type, data)` pairs.
fn extension_list(extensions: &[(u16, &[u8])]) -> TestResult<Vec<u8>> {
    let mut body = Vec::new();
    for (extension_type, data) in extensions {
        body.extend_from_slice(&extension_type.to_be_bytes());
        opaque_v(&mut body, data)?;
    }
    let mut list = Vec::new();
    opaque_v(&mut list, &body)?;
    Ok(list)
}

/// The successor of the bound conversation `old` whose initial member plan
/// `plan` forms, on the group [`SUCCESSOR_GROUP`].
pub(in crate::e2ee::coordinator::tests) fn successor(
    harness: &Harness,
    old: [u8; 32],
    plan: ArcKeyPackagePlan,
) -> TestResult<Successor> {
    successor_on(harness, old, plan, SUCCESSOR_GROUP)
}

/// The successor of `old` on `group` whose initial member plan `plan` forms.
pub(in crate::e2ee::coordinator::tests) fn successor_on(
    harness: &Harness,
    old: [u8; 32],
    plan: ArcKeyPackagePlan,
    group: [u8; 32],
) -> TestResult<Successor> {
    let sequencer = harness
        .coordinator
        .current_credential()
        .cloned()
        .ok_or("the harness sequencer credential")?;
    successor_pinned(harness, old, plan, group, sequencer)
}

/// [`successor_on`] pinning the sequencer credential `sequencer`.
pub(in crate::e2ee::coordinator::tests) fn successor_pinned(
    harness: &Harness,
    old: [u8; 32],
    plan: ArcKeyPackagePlan,
    group: [u8; 32],
    sequencer: agenc_relay_e2ee::objects::conversation::ArcSequencerCredential,
) -> TestResult<Successor> {
    successor_edited(harness, old, plan, group, sequencer, |_| Ok(()))
}

/// [`successor_pinned`] with `edit` applied to the successor's
/// generation-zero policy before the context and the binding name it.
pub(in crate::e2ee::coordinator::tests) fn successor_edited(
    harness: &Harness,
    old: [u8; 32],
    plan: ArcKeyPackagePlan,
    group: [u8; 32],
    sequencer: agenc_relay_e2ee::objects::conversation::ArcSequencerCredential,
    edit: fn(&mut agenc_relay_e2ee::objects::conversation::ArcPolicy) -> TestResult,
) -> TestResult<Successor> {
    let state = &harness.coordinator.state;
    let old_object = state
        .conversations
        .get(&old)
        .ok_or("the old conversation")?
        .binding_object_id;
    let old_package =
        crate::e2ee::coordinator::ops::route_successor::binding_object(state, &old_object)
            .ok_or("the old binding")?;
    let old_binding = &old_package.binding.tbs;
    let conversation = conversation_id(&NETWORK, &group)?;
    let principals = std::slice::from_ref(&harness.principal);
    let mut policy = policy(&PolicySpec::bootstrap(
        principals,
        conversation,
        old_binding.kind,
    ))?;
    edit(&mut policy)?;
    let policy_id = policy_id_of(&policy)?;
    let plan_id = verify_initial_member_plan(&formed_plan(&plan)?)?;
    let mut binding = old_binding.clone();
    binding.binding_generation = old_binding.binding_generation.saturating_add(1);
    binding.previous_binding_id = semantic_id_of(SemanticHashDomain::BindingId, old_binding)?;
    binding.group_id = Opaque::from_slice(&group)?;
    binding.conversation_id = conversation;
    binding.cipher_suite = SUCCESSOR_SUITE;
    binding.initial_policy_id = policy_id;
    binding.required_operational_policy_id = policy_id;
    binding.initial_member_plan_id = plan_id;
    binding.sequencer_credential_id =
        semantic_id_of(SemanticHashDomain::SequencerKey, &sequencer.tbs)?;
    let core = ArcContextCoreTbs {
        profile_version: 1,
        mls_version: 1,
        cipher_suite: SUCCESSOR_SUITE,
        group_id: Opaque::from_slice(&group)?,
        network_id: NETWORK,
        conversation_id: conversation,
        kind: binding.kind,
        semantic_route_lock_id: binding.semantic_route_lock_id,
        route_binding: binding.route_binding,
        initial_validation_time: SUCCESSOR_VALIDATION_TIME,
        initial_policy_id: policy_id,
        required_operational_policy_id: policy_id,
        initial_bootstrap_pending: 0,
        initial_member_plan_id: plan_id,
        sequencer_credential_id: binding.sequencer_credential_id,
        encoded_required_capabilities: Opaque::from_slice(&REQUIRED_CAPABILITIES)?,
    };
    let core_id = context_core_id(&core)?;
    binding.context_core_id = core_id;
    let binding_id = semantic_id_of(SemanticHashDomain::BindingId, &binding)?;
    let head = ArcRosterHead {
        account_id_digest: account_id_digest(&NETWORK, &harness.account)?,
        root_generation: harness.principal.root.tbs.root_generation,
        root_fingerprint: root_fingerprint(&harness.principal.root)?,
        roster_generation: harness.principal.roster.tbs.roster_generation,
        roster_id: roster_id(&harness.principal.roster)?,
    };
    let context = ArcMlsContext {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: conversation,
        kind: binding.kind,
        route_binding: binding.route_binding,
        initial_validation_time: SUCCESSOR_VALIDATION_TIME,
        policy,
        sequencer,
        current_binding: ArcConversationBinding {
            tbs: binding,
            approvals: TlsVec::new(Vec::new())?,
        },
        lifecycle: ArcConversationLifecycle {
            kind: ArcConversationLifecycleKind::ActiveConversation,
            close_intent_id: [0; 32],
        },
        private_topic: Opaque::new(Vec::new())?,
        bootstrap_pending: 0,
        roster_heads: TlsVec::new(vec![head])?,
        pending_joins: TlsVec::new(Vec::new())?,
    };
    let extensions = extension_list(&[
        (REQUIRED_CAPABILITIES_EXTENSION, &REQUIRED_CAPABILITIES),
        (ARC_MLS_CONTEXT_EXTENSION, &context.encode()?),
    ])?;
    let target = ArcReInitTargetTbs {
        profile_version: 1,
        network_id: NETWORK,
        old_conversation_id: old,
        new_conversation_id: conversation,
        target_group_id: Opaque::from_slice(&group)?,
        target_version: 1,
        target_suite: SUCCESSOR_SUITE,
        target_context_core_id: core_id,
        target_binding_id: binding_id,
        initial_member_plan_id: plan_id,
        encoded_target_extensions: Opaque::new(extensions)?,
    };
    let digest = semantic_id_of(SemanticHashDomain::ReinitTarget, &target)?;
    Ok(Successor {
        target,
        digest,
        conversation,
        binding_id,
        plan_id,
        plan,
        context,
    })
}

/// One old leaf that acknowledges the ReInit Commit: its index, its
/// credential hash, and its leaf key seed.
#[derive(Clone, Copy, Debug)]
pub(in crate::e2ee::coordinator::tests) struct Acker {
    /// Old leaf index.
    pub(in crate::e2ee::coordinator::tests) leaf: u32,
    /// Old leaf key seed.
    pub(in crate::e2ee::coordinator::tests) leaf_seed: u8,
}

/// The attached device's old leaf 0.
pub(in crate::e2ee::coordinator::tests) const LEAF_ZERO: Acker = Acker {
    leaf: 0,
    leaf_seed: LEAF_SEED,
};

/// The authorization one finalized Commit carries: its rule, its action
/// bits, its resulting policy (`None` keeps the current one), and its
/// transition target digest.
#[derive(Clone, Copy, Debug)]
pub(in crate::e2ee::coordinator::tests) struct Authorized {
    /// The authorization rule.
    pub(in crate::e2ee::coordinator::tests) rule: ArcCommitAuthorizationRule,
    /// The action bits.
    pub(in crate::e2ee::coordinator::tests) bits: u32,
    /// The resulting policy, if it changes.
    pub(in crate::e2ee::coordinator::tests) resulting_policy_id: Option<[u8; 32]>,
    /// The transition target digest.
    pub(in crate::e2ee::coordinator::tests) target_digest: [u8; 32],
}

impl Authorized {
    /// The controlled ReInit transition that commits `digest`.
    pub(in crate::e2ee::coordinator::tests) const fn reinit(digest: [u8; 32]) -> Self {
        Self {
            rule: ArcCommitAuthorizationRule::ControlledTransition,
            bits: action_bits::REINIT,
            resulting_policy_id: None,
            target_digest: digest,
        }
    }
}

impl Harness {
    /// Finalizes the bootstrap activation of a bound `conversation`, which
    /// installs its operational policy, with the attached device's ACK.
    pub(in crate::e2ee::coordinator::tests) fn activate_bootstrap(
        &mut self,
        conversation: [u8; 32],
    ) -> TestResult<[u8; 32]> {
        let operational = policy_id_of(&self.operational_policy)?;
        self.finalize_commit(
            conversation,
            Authorized {
                rule: ArcCommitAuthorizationRule::BootstrapActivation,
                bits: action_bits::POLICY | action_bits::BOOTSTRAP,
                resulting_policy_id: Some(operational),
                target_digest: [0; 32],
            },
            &[LEAF_ZERO],
        )
    }

    /// Sequences one Commit candidate of `conversation` at its accepted
    /// epoch, acknowledged by `ackers`, and finalizes it under `authorized`,
    /// voted by every council device of the current policy (and of the
    /// resulting one). Returns the finalization identifier.
    pub(in crate::e2ee::coordinator::tests) fn finalize_commit(
        &mut self,
        conversation: [u8; 32],
        authorized: Authorized,
        ackers: &[Acker],
    ) -> TestResult<[u8; 32]> {
        let state = self
            .coordinator
            .state
            .conversations
            .get(&conversation)
            .ok_or("the conversation")?;
        let old_policy_id = state.current_policy_id;
        let validation_time = state.last_validation_time.saturating_add(1);
        let (group_id, route_binding) = (state.group_id.clone(), state.route_binding);
        let council = state
            .policies
            .get(&old_policy_id)
            .ok_or("the current policy")?
            .policy
            .clone();
        let log = self
            .coordinator
            .state
            .logs
            .get(&conversation)
            .ok_or("the sequencer log")?;
        let epoch = log.accepted_epoch();
        let prior_state_id = *log.accepted_state_id();
        let aad = ArcCommitAad {
            profile_version: 1,
            network_id: NETWORK,
            conversation_id: conversation,
            route_binding,
            validation_time,
            prior_state_id,
        }
        .encode()?;
        let commit = wire_raw(
            ArcWireObjectKind::CommitMls,
            private_message_at_epoch(&group_id, epoch, COMMIT_CONTENT_TYPE, &aad)?,
        )?;
        let outcome = ok(self.run(Op::SubmitCandidate, &conversation, Some(&commit))?)?;
        let event = outcome.events.first().ok_or("the candidate event")?;
        let mut budget = DecodeBudget::new(1 << 16, 1 << 10);
        let receipt = ArcCandidateReceipt::decode_exact(&event.encoded_result, &mut budget)?;
        let candidate_id = semantic_id_of(SemanticHashDomain::CandidateId, &receipt.tbs)?;
        let commit_object_id = object_id(&commit);
        let mut acks: Vec<ArcCommitAck> = ackers
            .iter()
            .map(|acker| {
                commit_ack_as(
                    conversation,
                    epoch,
                    candidate_id,
                    commit_object_id,
                    acker.leaf,
                    credential_of(acker.leaf),
                    acker.leaf_seed,
                    agenc_relay_crypto::SignatureDomain::CommitProcessed,
                )
            })
            .collect::<TestResult<_>>()?;
        acks.sort_by_key(|ack| ack.tbs.old_leaf_index);
        let mut tbs = authorization_tbs(
            conversation,
            old_policy_id,
            authorized.rule,
            authorized.bits,
        );
        tbs.prior_epoch = epoch;
        tbs.prior_state_id = prior_state_id;
        tbs.candidate_id = candidate_id;
        tbs.commit_object_id = commit_object_id;
        tbs.canonical_validation_time = validation_time;
        tbs.resulting_policy_id = authorized.resulting_policy_id.unwrap_or(old_policy_id);
        tbs.transition_target_digest = authorized.target_digest;
        let authorization = commit_authorization(tbs, &[(&self.principal, DEVICE)])?;
        let acknowledgements: Vec<_> = acks.iter().map(|ack| ack.tbs.clone()).collect();
        let core = ArcFinalizationCoreTbs {
            profile_version: 1,
            network_id: NETWORK,
            conversation_id: conversation,
            prior_epoch: epoch,
            prior_state_id,
            candidate_id,
            commit_object_id,
            resulting_epoch: epoch.saturating_add(1),
            old_policy_id,
            commit_authorization_id: semantic_id_of(
                SemanticHashDomain::CommitAuthorizationId,
                &authorization.tbs,
            )?,
            acknowledgement_set_digest: agenc_relay_e2ee::ids::proof_set_digest(
                SemanticHashDomain::AcknowledgementSet,
                &acknowledgements,
            )?,
            resulting_group_context_digest: [2; 32],
            resulting_ratchet_tree_digest: [3; 32],
            finalization_authenticator: [4; 32],
        };
        let finalization_id = semantic_id_of(SemanticHashDomain::FinalizationId, &core)?;
        let fingerprint = root_fingerprint(&self.principal.root)?;
        let votes = self
            .devices
            .iter()
            .filter(|device| {
                council
                    .council_member(&fingerprint, &[**device; 16])
                    .is_some()
            })
            .map(|device| {
                vote(
                    self,
                    *device,
                    &receipt,
                    candidate_id,
                    Terminal::finalize(finalization_id),
                )
            })
            .collect::<TestResult<Vec<_>>>()?;
        let request = wire(
            ArcWireObjectKind::FinalizationRequest,
            &ArcFinalizationRequest {
                proof: ArcFinalizationProof {
                    core,
                    receipt,
                    authorization,
                    acknowledgements: TlsVec::new(acks)?,
                },
                votes: TlsVec::new(votes)?,
            },
        )?;
        let outcome = ok(self.run(Op::SubmitFinalization, &conversation, Some(&request))?)?;
        let ResultBody::Finalized(_, _, finalized, _) = outcome.result else {
            return Err("expected a finalization".into());
        };
        assert_eq!(finalized, finalization_id);
        Ok(finalization_id)
    }

    /// Finalizes the ReInit Commit of `conversation` whose authorization
    /// commits the target of the successor `plan` forms, acknowledged by
    /// `ackers`, and keeps that successor for the attempts that follow.
    /// Returns the finalization, the old ReInit state.
    pub(in crate::e2ee::coordinator::tests) fn finalize_reinit_with(
        &mut self,
        conversation: [u8; 32],
        plan: ArcKeyPackagePlan,
        ackers: &[Acker],
    ) -> TestResult<[u8; 32]> {
        let successor = successor(self, conversation, plan)?;
        let finalization =
            self.finalize_commit(conversation, Authorized::reinit(successor.digest), ackers)?;
        self.reinit = Some(successor);
        Ok(finalization)
    }

    /// [`Self::finalize_reinit`] for a successor on `group`.
    pub(in crate::e2ee::coordinator::tests) fn finalize_reinit_to(
        &mut self,
        conversation: [u8; 32],
        group: [u8; 32],
    ) -> TestResult<[u8; 32]> {
        let successor = successor_on(self, conversation, creator_plan(self)?, group)?;
        let finalization = self.finalize_commit(
            conversation,
            Authorized::reinit(successor.digest),
            &[LEAF_ZERO],
        )?;
        self.reinit = Some(successor);
        Ok(finalization)
    }

    /// [`Self::finalize_reinit_with`] for the attached device as the only
    /// continuing leaf.
    pub(in crate::e2ee::coordinator::tests) fn finalize_reinit(
        &mut self,
        conversation: [u8; 32],
    ) -> TestResult<[u8; 32]> {
        let plan = creator_plan(self)?;
        self.finalize_reinit_with(conversation, plan, &[LEAF_ZERO])
    }

    /// Binds `#room` and finalizes its ReInit Commit with the attached device
    /// as the only continuing leaf; returns the old conversation.
    pub(in crate::e2ee::coordinator::tests) fn bind_channel_for_reinit(
        &mut self,
    ) -> TestResult<[u8; 32]> {
        let conversation = self.bind_channel()?;
        self.finalize_reinit(conversation)?;
        Ok(conversation)
    }
}
