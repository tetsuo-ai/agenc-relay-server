//! The ReInit target of companion Section 13.8: its reconstruction from the
//! ReInit Proposal, the checks of the target every attempt carries, and the
//! checks that bind both to the finalized old ReInit Commit, to every
//! attempt, to a later joiner's ReInit entries, and to the successor initial
//! Commit.
//!
//! The target covers no accepted-state or record ID of the old group. Every
//! field is fixed by the old conversation and the Proposal, so
//! [`reconstruct_reinit_target`] derives the complete target from the
//! Proposal's group ID, version, cipher suite and exact extension list, and
//! checks the successor context in that list against the old conversation's
//! current binding and verifies its policy. An old-group endpoint calls it
//! with the Proposal of the staged old Commit before it approves,
//! acknowledges or votes, and a continuing member with the successor's
//! epoch-1 GroupContext before it acknowledges an attempt.
//!
//! Every `ArcReInitAttempt` carries the exact target in `target`, so a
//! verifier that never sees the Proposal checks the same bytes:
//! [`check_carried_target`] applies the structural rules (the first two
//! endpoint rules, with the target in place of the Proposal) and requires
//! the target's derived IDs to be the ones its extension list yields. The
//! sequencer's attempt checks are [`AuthorizedReinit::check_attempt`], an
//! endpoint's are [`AuthorizedReinit::check_attempt_target`], and a member
//! that joins the successor after activation checks its join bundle's ReInit
//! entries with [`AuthorizedReinit::check_join_entries`].
//!
//! [`AuthorizedReinit`] recomputes the hash links from a finalized old ReInit
//! Commit to the target digest its authorization committed and to the
//! finalization ID every later ReInit object names.
//! [`AuthorizedReinit::check_staged`] checks a staged ReInit wrapper and
//! [`AuthorizedReinit::check_initial_commit`] the successor initial Commit's
//! public frame and authenticated data, which a caller that holds the attempt
//! must check itself: [`crate::history::HistoricalChain`] does not.
//!
//! Only public bytes enter this module. It checks structure, hash links, and
//! the successor policy's approvals under the given rosters. Controller
//! approvals of the old Commit, finality votes, sequencer signatures, ACK
//! sets, quorums and record positions are verified by
//! [`crate::history::HistoricalChain`] or by the caller under the old policy,
//! and whether the old conversation's accepted state is the ReInit
//! finalization is the sequencer's own state. Endpoint-only, never claimed
//! here: that the Proposal is the one inside the old Commit, the successor's
//! MLS state, and that the successor's roster heads and initial member plan
//! are the ones the controllers approved.

use std::collections::BTreeSet;

use agenc_relay_crypto::SemanticHashDomain;

use crate::context::{check_binding_agreement, check_private_topic, context_core_id};
use crate::error::E2eeError;
use crate::ids::{SemanticId, conversation_id, semantic_id_of};
use crate::limits::{
    ARC_MLS_CONTEXT_EXTENSION, MAX_ARC_MLS_CONTEXT_EXTENSION, MLS_VERSION_MLS10, PROFILE_VERSION,
    suite_is_enabled,
};
use crate::mls_outer::{MlsContentType, MlsOuterMessage, MlsReader, parse_mls_message};
use crate::objects::aad::ArcCommitAad;
use crate::objects::conversation::{
    ArcBindingChainEntry, ArcBindingProofKind, ArcCommitAuthorizationRule, ArcContextCoreTbs,
    ArcConversationBindingTbs, ArcConversationLifecycleKind, ArcInitialMemberPlan,
    ArcInitialMemberPlanEntry, ArcKeyPackagePlan, ArcMlsContext, ArcPolicyChainEntry,
    ArcPolicyProofKind, ArcPolicyTbs, action_bits,
};
use crate::objects::reinit::{
    ArcReInitActivationCertificate, ArcReInitAttempt, ArcReInitAttemptTbs, ArcReInitTargetTbs,
};
use crate::objects::sequencing::ArcFinalizationProof;
use crate::objects::{GROUP_ID_BYTES, group_id_bytes};
use crate::policy::verify_policy;
use crate::route::{PrincipalRosters, VerifiedBinding, verify_initial_member_plan};
use crate::sequencer::{verify_opened_credential, verify_sequencer_credential};
use crate::tls::{DecodeBudget, Opaque, TlsDecode, TlsVec, ensure_canonical};
use crate::welcome::VerifiedStagedReInit;

/// The RFC 9420 `required_capabilities` extension type.
pub const REQUIRED_CAPABILITIES_EXTENSION: u16 = 0x0003;

/// The public fields of one decoded RFC 9420 ReInit Proposal, or equally of
/// the successor's epoch-1 GroupContext a continuing member holds after it
/// staged the successor (companion 13.8 step 3), or of a carried target
/// ([`ReinitProposal::of_target`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReinitProposal<'a> {
    /// The successor group ID.
    pub group_id: &'a [u8],
    /// The successor protocol version.
    pub version: u16,
    /// The successor cipher suite.
    pub cipher_suite: u16,
    /// The exact encoded `Extension extensions<V>` list, length prefix
    /// included, as it appears in the Proposal and the successor
    /// GroupContext.
    pub encoded_extensions: &'a [u8],
}

impl<'a> ReinitProposal<'a> {
    /// The Proposal fields a target names: its group ID, version, suite and
    /// exact extension list, which companion 13.8 lets a verifier without the
    /// Proposal check in its place.
    #[must_use]
    pub fn of_target(target: &'a ArcReInitTargetTbs) -> Self {
        Self {
            group_id: target.target_group_id.as_slice(),
            version: target.target_version,
            cipher_suite: target.target_suite,
            encoded_extensions: target.encoded_target_extensions.as_slice(),
        }
    }
}

/// A target whose extension list meets the structural rules of companion
/// 13.8 (the first two endpoint rules) against the old conversation's
/// current binding, and whose every field is the value that list yields.
/// The only constructors are [`check_carried_target`] and
/// [`reconstruct_reinit_target`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CarriedTarget {
    tbs: ArcReInitTargetTbs,
    digest: SemanticId,
    context: ArcMlsContext,
}

impl CarriedTarget {
    /// The `ArcReInitTargetTBS`.
    #[must_use]
    pub const fn tbs(&self) -> &ArcReInitTargetTbs {
        &self.tbs
    }

    /// `target_context_digest`, the Section 2.2 hash of the target.
    #[must_use]
    pub const fn digest(&self) -> &SemanticId {
        &self.digest
    }

    /// The successor context the extension list carries.
    #[must_use]
    pub const fn context(&self) -> &ArcMlsContext {
        &self.context
    }

    /// The successor context's concrete route, which the successor initial
    /// Commit's authenticated data names.
    #[must_use]
    pub const fn route_binding(&self) -> &SemanticId {
        &self.context.route_binding
    }
}

/// A target reconstructed from its Proposal by an endpoint: a
/// [`CarriedTarget`] whose successor policy also verified under the rosters
/// the endpoint supplied. The only constructor is
/// [`reconstruct_reinit_target`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReinitTarget {
    target: CarriedTarget,
}

impl ReinitTarget {
    /// The reconstructed `ArcReInitTargetTBS`.
    #[must_use]
    pub const fn tbs(&self) -> &ArcReInitTargetTbs {
        &self.target.tbs
    }

    /// `target_context_digest`, the Section 2.2 hash of the target.
    #[must_use]
    pub const fn digest(&self) -> &SemanticId {
        &self.target.digest
    }

    /// The successor context's concrete route, which the successor initial
    /// Commit's authenticated data names.
    #[must_use]
    pub const fn route_binding(&self) -> &SemanticId {
        self.target.route_binding()
    }

    /// The reconstruction as the structurally checked target every verifier
    /// shares.
    #[must_use]
    pub const fn carried(&self) -> &CarriedTarget {
        &self.target
    }
}

/// Reconstructs the ReInit target of the conversation `old_binding` binds
/// from its Proposal (companion 13.8).
///
/// The structural rules of [`check_carried_target`] apply to the Proposal:
/// the extension list carries exactly one `ARC_MLS_CONTEXT_EXTENSION` and one
/// `required_capabilities` extension and no repeated type (RFC 9420 Section
/// 13.4); the context describes the successor as companion 13.8 states it
/// once activated; and the `ArcContextCoreTBS` recomputed from the Proposal,
/// the `required_capabilities` data, the context and its binding has the
/// binding's `context_core_id`. The successor policy must also verify under
/// `rosters`. The target's binding ID, plan ID and context core ID are then
/// read from that binding.
pub fn reconstruct_reinit_target(
    network_id: &[u8; 32],
    old_binding: &VerifiedBinding,
    rosters: &PrincipalRosters,
    proposal: &ReinitProposal<'_>,
    budget: &mut DecodeBudget,
) -> Result<ReinitTarget, E2eeError> {
    let target = successor_target(network_id, &Predecessor::of(old_binding), proposal, budget)?;
    verify_policy(
        network_id,
        &target.tbs.new_conversation_id,
        &target.context.policy,
        rosters,
        None,
    )?;
    Ok(ReinitTarget { target })
}

/// Checks a target that a verifier holds without the Proposal, such as the
/// one an attempt carries (companion 13.8): its extension list meets the
/// first two endpoint rules with the target in place of the Proposal, against
/// `old_binding`, the old conversation's current binding, and the target's
/// profile version, network, conversations, group, version, suite, context
/// core, binding and plan are exactly the values that list yields.
pub fn check_carried_target(
    network_id: &[u8; 32],
    old_binding: &VerifiedBinding,
    target: &ArcReInitTargetTbs,
    budget: &mut DecodeBudget,
) -> Result<CarriedTarget, E2eeError> {
    carried_after(network_id, &Predecessor::of(old_binding), target, budget)
}

fn carried_after(
    network_id: &[u8; 32],
    old: &Predecessor,
    target: &ArcReInitTargetTbs,
    budget: &mut DecodeBudget,
) -> Result<CarriedTarget, E2eeError> {
    let checked = successor_target(network_id, old, &ReinitProposal::of_target(target), budget)?;
    if checked.tbs != *target {
        return Err(E2eeError::InvalidValue);
    }
    Ok(checked)
}

/// The structural rules shared by every verifier of a target: the
/// extension-list shape and context core (the first endpoint rule), and the
/// successor the context and its binding describe (the second).
fn successor_target(
    network_id: &[u8; 32],
    old: &Predecessor,
    proposal: &ReinitProposal<'_>,
    budget: &mut DecodeBudget,
) -> Result<CarriedTarget, E2eeError> {
    if proposal.version != MLS_VERSION_MLS10 || !suite_is_enabled(proposal.cipher_suite) {
        return Err(E2eeError::ProfileMismatch);
    }
    let group_id: [u8; GROUP_ID_BYTES] = proposal
        .group_id
        .try_into()
        .map_err(|_| E2eeError::InvalidValue)?;
    let new_conversation_id = conversation_id(network_id, &group_id)?;
    if new_conversation_id == old.conversation_id {
        return Err(E2eeError::InvalidValue);
    }
    let (context_bytes, required_capabilities) =
        extension_parts(proposal.encoded_extensions, budget)?;
    if context_bytes.len() > MAX_ARC_MLS_CONTEXT_EXTENSION {
        return Err(E2eeError::LimitExceeded);
    }
    let context = ArcMlsContext::decode_exact(context_bytes, budget)?;
    let successor = Successor {
        network_id,
        conversation_id: &new_conversation_id,
        group_id: &group_id,
        proposal,
        old,
    };
    let binding = successor.binding_of(&context)?;
    successor.check_context(&context, binding)?;
    let core = successor.core(&context, binding, required_capabilities)?;
    if context_core_id(&core)? != binding.context_core_id {
        return Err(E2eeError::InvalidValue);
    }
    let tbs = ArcReInitTargetTbs {
        profile_version: PROFILE_VERSION,
        network_id: *network_id,
        old_conversation_id: old.conversation_id,
        new_conversation_id,
        target_group_id: Opaque::from_slice(&group_id)?,
        target_version: proposal.version,
        target_suite: proposal.cipher_suite,
        target_context_core_id: binding.context_core_id,
        target_binding_id: semantic_id_of(SemanticHashDomain::BindingId, binding)?,
        initial_member_plan_id: binding.initial_member_plan_id,
        encoded_target_extensions: Opaque::from_slice(proposal.encoded_extensions)?,
    };
    let digest = semantic_id_of(SemanticHashDomain::ReinitTarget, &tbs)?;
    Ok(CarriedTarget {
        tbs,
        digest,
        context,
    })
}

/// Splits an encoded extension list into the context and
/// `required_capabilities` extension data. Every extension type occurs at
/// most once (RFC 9420 Section 13.4); both named types are required.
fn extension_parts<'a>(
    encoded: &'a [u8],
    budget: &mut DecodeBudget,
) -> Result<(&'a [u8], &'a [u8]), E2eeError> {
    let body = {
        let mut reader = MlsReader::new(encoded, budget);
        let length = reader.varint()?;
        let offset = encoded
            .len()
            .checked_sub(reader.remaining())
            .ok_or(E2eeError::Truncated)?;
        let body = encoded.get(offset..).ok_or(E2eeError::Truncated)?;
        if body.len() < length {
            return Err(E2eeError::Truncated);
        }
        if body.len() > length {
            return Err(E2eeError::TrailingBytes);
        }
        body
    };
    let mut reader = MlsReader::new(body, budget);
    let mut types = BTreeSet::new();
    let mut context = None;
    let mut capabilities = None;
    while reader.remaining() > 0 {
        let extension_type = reader.u16()?;
        let length = reader.opaque_v()?.len();
        let end = body
            .len()
            .checked_sub(reader.remaining())
            .ok_or(E2eeError::Truncated)?;
        let start = end.checked_sub(length).ok_or(E2eeError::Truncated)?;
        let data = body.get(start..end).ok_or(E2eeError::Truncated)?;
        if !types.insert(extension_type) {
            return Err(E2eeError::NonCanonical);
        }
        match extension_type {
            ARC_MLS_CONTEXT_EXTENSION => context = Some(data),
            REQUIRED_CAPABILITIES_EXTENSION => capabilities = Some(data),
            _ => {}
        }
    }
    match (context, capabilities) {
        (Some(context), Some(capabilities)) => Ok((context, capabilities)),
        _ => Err(E2eeError::InvalidValue),
    }
}

/// What a ReInit successor's binding must replace: the old conversation's
/// current binding, from the verifier's retained [`VerifiedBinding`] or, for
/// a later joiner, from the binding-chain entry that precedes the ReInit
/// entry.
struct Predecessor {
    conversation_id: SemanticId,
    binding_id: SemanticId,
    generation: u64,
    lock_id: SemanticId,
    route_binding: SemanticId,
    channel_instance_id: Option<[u8; 16]>,
    conversation_nonce: Option<[u8; 32]>,
}

impl Predecessor {
    fn of(binding: &VerifiedBinding) -> Self {
        Self {
            conversation_id: binding.conversation_id,
            binding_id: binding.binding_id,
            generation: binding.generation,
            lock_id: binding.route.lock_id,
            route_binding: binding.route_binding,
            channel_instance_id: binding.channel_instance_id,
            conversation_nonce: binding.conversation_nonce,
        }
    }

    fn of_entry(entry: &ArcBindingChainEntry) -> Result<Self, E2eeError> {
        let binding = &entry.package.binding.tbs;
        Ok(Self {
            conversation_id: binding.conversation_id,
            binding_id: semantic_id_of(SemanticHashDomain::BindingId, binding)?,
            generation: binding.binding_generation,
            lock_id: binding.semantic_route_lock_id,
            route_binding: binding.route_binding,
            channel_instance_id: binding.channel_instance_id.empty_or_fixed::<16>()?,
            conversation_nonce: binding.conversation_nonce.empty_or_fixed::<32>()?,
        })
    }
}

/// What the Proposal and the old conversation fix about the successor before
/// its context is read.
struct Successor<'a> {
    network_id: &'a [u8; 32],
    conversation_id: &'a SemanticId,
    group_id: &'a [u8; GROUP_ID_BYTES],
    proposal: &'a ReinitProposal<'a>,
    old: &'a Predecessor,
}

impl Successor<'_> {
    /// The context's current binding, once the context and the binding both
    /// describe this successor as companion 13.8 states it: an active,
    /// non-bootstrapping conversation with no close intent and no pending
    /// join (companion 9.5 and 13.8), and the unapproved replacement of the
    /// old binding, keeping its semantic route and concrete route, for this
    /// group, conversation, version and suite (companion 9.4). That the
    /// binding names the context's network, conversation, kind and route is
    /// the binding agreement every context meets, checked with the other
    /// context rules in [`Self::check_context`].
    fn binding_of<'c>(
        &self,
        context: &'c ArcMlsContext,
    ) -> Result<&'c ArcConversationBindingTbs, E2eeError> {
        let named_context = (
            context.profile_version,
            context.network_id,
            context.bootstrap_pending,
            context.lifecycle.kind,
            context.lifecycle.close_intent_id,
        );
        let expected_context = (
            PROFILE_VERSION,
            *self.network_id,
            0,
            ArcConversationLifecycleKind::ActiveConversation,
            [0; 32],
        );
        let binding = &context.current_binding.tbs;
        let named_binding = (
            binding.profile_version,
            group_id_bytes(&binding.group_id)?,
            binding.conversation_id,
            binding.mls_version,
            binding.cipher_suite,
        );
        let expected_binding = (
            PROFILE_VERSION,
            *self.group_id,
            *self.conversation_id,
            self.proposal.version,
            self.proposal.cipher_suite,
        );
        if named_context != expected_context
            || !context.pending_joins.is_empty()
            || named_binding != expected_binding
            || !context.current_binding.approvals.is_empty()
        {
            return Err(E2eeError::InvalidValue);
        }
        self.check_lineage(binding)?;
        Ok(binding)
    }

    /// The binding replaces the old conversation's current binding: the next
    /// generation, that binding's ID, and the same semantic route lock and
    /// concrete route, which the activation remaps, with the replaced
    /// binding's channel instance or conversation nonce (companion 9.4 and
    /// 13.8).
    fn check_lineage(&self, binding: &ArcConversationBindingTbs) -> Result<(), E2eeError> {
        let old = self.old;
        let named = (
            Some(binding.binding_generation),
            binding.previous_binding_id,
            binding.semantic_route_lock_id,
            binding.route_binding,
            binding.channel_instance_id.empty_or_fixed::<16>()?,
            binding.conversation_nonce.empty_or_fixed::<32>()?,
        );
        let expected = (
            old.generation.checked_add(1),
            old.binding_id,
            old.lock_id,
            old.route_binding,
            old.channel_instance_id,
            old.conversation_nonce,
        );
        if named == expected {
            Ok(())
        } else {
            Err(E2eeError::InvalidValue)
        }
    }

    /// The context meets the rules every context extension meets (the
    /// binding's recomputed route lock, the private topic, canonical roster
    /// heads; companion 9.4 and 9.5), and its policy and sequencer credential
    /// are the ones the binding names: the generation-zero policy of this
    /// conversation, kind and suite, and a structurally valid credential
    /// (companion 9.2, 9.3 and 13.8).
    fn check_context(
        &self,
        context: &ArcMlsContext,
        binding: &ArcConversationBindingTbs,
    ) -> Result<(), E2eeError> {
        check_binding_agreement(self.network_id, context)?;
        check_private_topic(context.kind, context.private_topic.as_slice())?;
        ensure_canonical(context.roster_heads.as_slice(), |head| {
            (
                head.account_id_digest,
                head.root_generation,
                head.root_fingerprint,
            )
        })?;
        check_policy_named(binding, &context.policy.tbs)?;
        let sequencer = if context.sequencer.tbs.key_generation == 0 {
            verify_sequencer_credential(self.network_id, &context.sequencer, None)?
        } else {
            verify_opened_credential(self.network_id, &context.sequencer)?
        };
        if sequencer.credential_id == binding.sequencer_credential_id {
            Ok(())
        } else {
            Err(E2eeError::InvalidValue)
        }
    }

    /// The successor's `ArcContextCoreTBS`, recomputed from the Proposal,
    /// the `required_capabilities` data, the context and its binding.
    fn core(
        &self,
        context: &ArcMlsContext,
        binding: &ArcConversationBindingTbs,
        required_capabilities: &[u8],
    ) -> Result<ArcContextCoreTbs, E2eeError> {
        Ok(ArcContextCoreTbs {
            profile_version: PROFILE_VERSION,
            mls_version: self.proposal.version,
            cipher_suite: self.proposal.cipher_suite,
            group_id: Opaque::from_slice(self.group_id)?,
            network_id: *self.network_id,
            conversation_id: *self.conversation_id,
            kind: binding.kind,
            semantic_route_lock_id: binding.semantic_route_lock_id,
            route_binding: binding.route_binding,
            initial_validation_time: context.initial_validation_time,
            initial_policy_id: binding.initial_policy_id,
            required_operational_policy_id: binding.required_operational_policy_id,
            initial_bootstrap_pending: 0,
            initial_member_plan_id: binding.initial_member_plan_id,
            sequencer_credential_id: binding.sequencer_credential_id,
            encoded_required_capabilities: Opaque::from_slice(required_capabilities)?,
        })
    }
}

/// The successor policy is the one its binding names: the generation-zero
/// policy of the binding's network, conversation, kind and suite, whose
/// Section 2.2 ID is both the binding's initial and its required operational
/// policy ID (companion 9.5 and 13.8).
fn check_policy_named(
    binding: &ArcConversationBindingTbs,
    policy: &ArcPolicyTbs,
) -> Result<(), E2eeError> {
    let policy_id = semantic_id_of(SemanticHashDomain::PolicyId, policy)?;
    let named = (
        policy.profile_version,
        policy.network_id,
        policy.conversation_id,
        policy.kind,
        policy.selected_suite,
        policy.policy_generation,
        policy.previous_policy_id,
        policy_id,
        policy_id,
    );
    let expected = (
        PROFILE_VERSION,
        binding.network_id,
        binding.conversation_id,
        binding.kind,
        binding.cipher_suite,
        0,
        [0; 32],
        binding.initial_policy_id,
        binding.required_operational_policy_id,
    );
    if named == expected {
        Ok(())
    } else {
        Err(E2eeError::InvalidValue)
    }
}

/// The Section 2.2 digest of a target that names this profile, network and
/// old conversation.
pub(crate) fn target_digest(
    network_id: &[u8; 32],
    old_conversation_id: &SemanticId,
    target: &ArcReInitTargetTbs,
) -> Result<SemanticId, E2eeError> {
    let named = (
        target.profile_version,
        target.network_id,
        target.old_conversation_id,
    );
    if named != (PROFILE_VERSION, *network_id, *old_conversation_id) {
        return Err(E2eeError::InvalidValue);
    }
    semantic_id_of(SemanticHashDomain::ReinitTarget, target)
}

/// The Section 2.2 ID of the `ArcInitialMemberPlan` a KeyPackage plan
/// forms: its device tuples and capability IDs in the plan's canonical
/// order (companion 9.4 and 13.8).
fn formed_plan_id(plan: &ArcKeyPackagePlan) -> Result<SemanticId, E2eeError> {
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
    verify_initial_member_plan(&ArcInitialMemberPlan {
        entries: TlsVec::new(entries)?,
    })
}

/// The target fields every attempt repeats (companion 13.8), retained by a
/// historical chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TargetFacts {
    new_conversation_id: SemanticId,
    group_id: [u8; GROUP_ID_BYTES],
    version: u16,
    suite: u16,
    binding_id: SemanticId,
    plan_id: SemanticId,
}

impl TargetFacts {
    /// The facts of a target whose successor conversation is the one its
    /// group ID names on `network_id`, and not the old conversation.
    pub(crate) fn of(
        network_id: &[u8; 32],
        target: &ArcReInitTargetTbs,
    ) -> Result<Self, E2eeError> {
        let group_id = group_id_bytes(&target.target_group_id)?;
        if target.new_conversation_id != conversation_id(network_id, &group_id)?
            || target.new_conversation_id == target.old_conversation_id
        {
            return Err(E2eeError::InvalidValue);
        }
        Ok(Self {
            new_conversation_id: target.new_conversation_id,
            group_id,
            version: target.target_version,
            suite: target.target_suite,
            binding_id: target.target_binding_id,
            plan_id: target.initial_member_plan_id,
        })
    }

    /// An attempt must name the target's group, version, suite, successor
    /// conversation, binding and plan.
    pub(crate) fn check_attempt(&self, attempt: &ArcReInitAttemptTbs) -> Result<(), E2eeError> {
        let named = (
            attempt.new_conversation_id,
            group_id_bytes(&attempt.target_group_id)?,
            attempt.target_version,
            attempt.target_suite,
            attempt.target_binding_id,
            attempt.initial_member_plan_id,
        );
        let expected = (
            self.new_conversation_id,
            self.group_id,
            self.version,
            self.suite,
            self.binding_id,
            self.plan_id,
        );
        if named == expected {
            Ok(())
        } else {
            Err(E2eeError::InvalidValue)
        }
    }
}

/// The finalized old ReInit Commit, reduced to what its finalization proof
/// binds: the accepted state before the candidate, the finalization ID every
/// later ReInit object names, and the target digest the authorization
/// committed (companion 9.3, 12.4 and 13.8).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizedReinit {
    network_id: [u8; 32],
    old_conversation_id: SemanticId,
    prior_state_id: SemanticId,
    finalization_id: SemanticId,
    target_context_digest: SemanticId,
    validation_time: u64,
}

impl AuthorizedReinit {
    /// Recomputes the hash links of a ReInit finalization proof: the
    /// authorization carries the ReInit bit alone as a controlled transition
    /// with a nonzero target digest; the authorization, the core and the
    /// receipt name one network, conversation, prior epoch, prior state,
    /// candidate and Commit object; and the core commits the recomputed
    /// authorization ID. Signatures, approvals, votes and the record position
    /// are not checked here.
    pub fn from_proof(proof: &ArcFinalizationProof) -> Result<Self, E2eeError> {
        let authorization = &proof.authorization.tbs;
        let core = &proof.core;
        let receipt = &proof.receipt.tbs;
        if authorization.action_bits != action_bits::REINIT
            || authorization.authorization_rule != ArcCommitAuthorizationRule::ControlledTransition
            || authorization.transition_target_digest == [0; 32]
        {
            return Err(E2eeError::InvalidValue);
        }
        let candidate_id = semantic_id_of(SemanticHashDomain::CandidateId, receipt)?;
        let by_receipt = (
            receipt.profile_version,
            receipt.network_id,
            receipt.conversation_id,
            receipt.prior_epoch,
            receipt.prior_state_id,
            candidate_id,
            receipt.commit_object_id,
        );
        let by_authorization = (
            authorization.profile_version,
            authorization.network_id,
            authorization.conversation_id,
            authorization.prior_epoch,
            authorization.prior_state_id,
            authorization.candidate_id,
            authorization.commit_object_id,
        );
        let by_core = (
            core.profile_version,
            core.network_id,
            core.conversation_id,
            core.prior_epoch,
            core.prior_state_id,
            core.candidate_id,
            core.commit_object_id,
        );
        let authorization_id =
            semantic_id_of(SemanticHashDomain::CommitAuthorizationId, authorization)?;
        if by_authorization != by_receipt
            || by_core != by_receipt
            || core.commit_authorization_id != authorization_id
        {
            return Err(E2eeError::InvalidValue);
        }
        if receipt.profile_version != PROFILE_VERSION {
            return Err(E2eeError::ProfileMismatch);
        }
        Ok(Self {
            network_id: receipt.network_id,
            old_conversation_id: receipt.conversation_id,
            prior_state_id: receipt.prior_state_id,
            finalization_id: semantic_id_of(SemanticHashDomain::FinalizationId, core)?,
            target_context_digest: authorization.transition_target_digest,
            validation_time: authorization.canonical_validation_time,
        })
    }

    /// The accepted state before the old ReInit candidate.
    #[must_use]
    pub const fn prior_state_id(&self) -> &SemanticId {
        &self.prior_state_id
    }

    /// The old ReInit Commit's finalization ID, `old_reinit_state_id`.
    #[must_use]
    pub const fn finalization_id(&self) -> &SemanticId {
        &self.finalization_id
    }

    /// The target digest the old candidate authorization committed.
    #[must_use]
    pub const fn target_context_digest(&self) -> &SemanticId {
        &self.target_context_digest
    }

    /// A presented, reconstructed or carried target must name this network
    /// and old conversation and hash to the authorized digest, so a target
    /// replaced after finalization is refused.
    pub fn check_target(&self, target: &ArcReInitTargetTbs) -> Result<(), E2eeError> {
        let digest = target_digest(&self.network_id, &self.old_conversation_id, target)?;
        if digest != self.target_context_digest {
            return Err(E2eeError::InvalidValue);
        }
        Ok(())
    }

    /// The attempt names this profile, network, old conversation and
    /// finalization ID.
    fn check_finalization_named(&self, attempt: &ArcReInitAttemptTbs) -> Result<(), E2eeError> {
        let named = (
            attempt.profile_version,
            attempt.network_id,
            attempt.old_conversation_id,
            attempt.old_reinit_state_id,
        );
        let expected = (
            PROFILE_VERSION,
            self.network_id,
            self.old_conversation_id,
            self.finalization_id,
        );
        if named == expected {
            Ok(())
        } else {
            Err(E2eeError::InvalidValue)
        }
    }

    /// The links every verifier of an attempt checks against the target the
    /// attempt carries: the attempt names this finalization, the carried
    /// target hashes to the attempt's `target_context_digest`, which is the
    /// authorized digest, and the attempt's group, version, suite, successor
    /// conversation, binding and plan are the carried target's.
    fn check_carried_links(&self, attempt: &ArcReInitAttempt) -> Result<(), E2eeError> {
        let tbs = &attempt.tbs;
        self.check_finalization_named(tbs)?;
        self.check_target(&attempt.target)?;
        if tbs.target_context_digest != self.target_context_digest {
            return Err(E2eeError::InvalidValue);
        }
        TargetFacts::of(&self.network_id, &attempt.target)?.check_attempt(tbs)
    }

    /// The sequencer's checks of one attempt before it signs an attempt
    /// receipt (companion 13.8), for an attempt on a conversation whose
    /// accepted state is this finalization, which the caller establishes:
    /// the attempt names this finalization ID; the target it carries hashes
    /// to its `target_context_digest`, which is the authorized digest; its
    /// group, version, suite, successor conversation, binding and plan are
    /// the carried target's; the device tuples and capability IDs of its
    /// `ArcKeyPackagePlan`, in that plan's order, form the semantic plan the
    /// target names; and the carried target meets [`check_carried_target`]
    /// against `old_binding`, the old conversation's current binding (a
    /// binding of any other conversation rebuilds a target that names that
    /// conversation, which is not the carried one). Returns the checked
    /// carried target.
    pub fn check_attempt(
        &self,
        attempt: &ArcReInitAttempt,
        old_binding: &VerifiedBinding,
        budget: &mut DecodeBudget,
    ) -> Result<CarriedTarget, E2eeError> {
        self.check_carried_links(attempt)?;
        if formed_plan_id(&attempt.key_package_plan)? != attempt.target.initial_member_plan_id {
            return Err(E2eeError::InvalidValue);
        }
        check_carried_target(&self.network_id, old_binding, &attempt.target, budget)
    }

    /// An endpoint's check of one attempt against its own reconstruction
    /// (companion 13.8): the attempt names this finalization ID, the target
    /// it carries is byte for byte the reconstruction, which hashes to the
    /// authorized digest the attempt names, the attempt's group, version,
    /// suite, successor conversation, binding and plan are that target's, and
    /// its KeyPackage plan forms the target's semantic plan.
    pub fn check_attempt_target(
        &self,
        attempt: &ArcReInitAttempt,
        target: &ReinitTarget,
    ) -> Result<(), E2eeError> {
        if attempt.target != *target.tbs() {
            return Err(E2eeError::InvalidValue);
        }
        self.check_carried_links(attempt)?;
        if formed_plan_id(&attempt.key_package_plan)? == target.tbs().initial_member_plan_id {
            Ok(())
        } else {
            Err(E2eeError::InvalidValue)
        }
    }

    /// A staged ReInit wrapper, already verified by
    /// [`crate::welcome::verify_staged_reinit`], must name this old
    /// conversation and this finalization ID (companion 13.8).
    pub fn check_staged(&self, staged: &VerifiedStagedReInit) -> Result<(), E2eeError> {
        let named = (staged.old_conversation_id, staged.old_reinit_state_id);
        if named == (self.old_conversation_id, self.finalization_id) {
            Ok(())
        } else {
            Err(E2eeError::InvalidValue)
        }
    }

    /// A later joiner's check of its join bundle's ReInit entries
    /// (companion 9.5 and 13.8) against the target the activation's attempt
    /// carries. `self` comes from the old ReInit finalization certificate
    /// the Welcome wrapper references, so [`Self::from_proof`] has applied
    /// the old-authorization and finalization rules; then the activation's
    /// attempt must name this finalization and the authorized digest, and
    /// the target it carries must hash to that digest; that target must meet
    /// the structural rules with `previous`, the binding-chain entry that
    /// precedes the ReInit entry, as the old conversation's current binding,
    /// and the attempt must name its group, version, suite, conversation,
    /// binding and plan; the activation core must name this finalization and
    /// that attempt; `entry` must be a `reinit_target_transition` whose
    /// binding is the binding in the carried target's context and whose
    /// package carries that binding's plan and no root binding lock; and
    /// `policy` must be a `policy_reinit_target_transition` whose policy is
    /// the one in that context. That the activation certificate verifies
    /// under the old policy (its sequencer signature, ACK set and quorum) is
    /// checked by [`crate::history::HistoricalChain`] or the caller.
    pub fn check_join_entries(
        &self,
        activation: &ArcReInitActivationCertificate,
        previous: &ArcBindingChainEntry,
        entry: &ArcBindingChainEntry,
        policy: &ArcPolicyChainEntry,
        budget: &mut DecodeBudget,
    ) -> Result<(), E2eeError> {
        let request = &activation.tbs.request;
        let attempt = &request.attempt;
        self.check_carried_links(attempt)?;
        let old = Predecessor::of_entry(previous)?;
        let carried = carried_after(&self.network_id, &old, &attempt.target, budget)?;
        self.check_activation_core(activation)?;
        check_binding_entry(&carried, entry)?;
        let named = (policy.proof_kind, &policy.policy);
        if named
            == (
                ArcPolicyProofKind::PolicyReinitTargetTransition,
                &carried.context.policy,
            )
        {
            Ok(())
        } else {
            Err(E2eeError::InvalidValue)
        }
    }

    /// The activation core names this network, old conversation and
    /// finalization, the attempt it carries and its successor conversation,
    /// and the certificate's activation ID is the core's.
    fn check_activation_core(
        &self,
        activation: &ArcReInitActivationCertificate,
    ) -> Result<(), E2eeError> {
        let request = &activation.tbs.request;
        let core = &request.core;
        let attempt = &request.attempt.tbs;
        let named = (
            core.profile_version,
            core.network_id,
            core.old_conversation_id,
            core.new_conversation_id,
            core.old_reinit_state_id,
            core.reinit_attempt_id,
            activation.tbs.reinit_activation_id,
        );
        let expected = (
            PROFILE_VERSION,
            self.network_id,
            self.old_conversation_id,
            attempt.new_conversation_id,
            self.finalization_id,
            semantic_id_of(SemanticHashDomain::ReinitAttemptId, attempt)?,
            semantic_id_of(SemanticHashDomain::ReinitActivationId, core)?,
        );
        if named == expected {
            Ok(())
        } else {
            Err(E2eeError::InvalidValue)
        }
    }

    /// The successor initial Commit (companion 13.8): a `PrivateMessage` of
    /// the target group at epoch zero with `commit` content, whose
    /// authenticated data is the `ArcCommitAad` naming the target's profile
    /// version and network, the successor conversation and route, a
    /// validation time no earlier than the old ReInit Commit's, and this
    /// finalization ID as prior state. Naming the successor's own activation
    /// ID, or any other successor state, is refused.
    pub fn check_initial_commit(
        &self,
        initial_commit_bytes: &[u8],
        target: &CarriedTarget,
        budget: &mut DecodeBudget,
    ) -> Result<(), E2eeError> {
        self.check_target(&target.tbs)?;
        let MlsOuterMessage::Private(header) = parse_mls_message(initial_commit_bytes, budget)?
        else {
            return Err(E2eeError::WrongKind);
        };
        let aad = ArcCommitAad::decode_exact(&header.authenticated_data, budget)?;
        let frame = (
            header.group_id.as_slice(),
            header.epoch,
            header.content_type,
        );
        let expected_frame = (
            target.tbs.target_group_id.as_slice(),
            0,
            MlsContentType::Commit,
        );
        let named = (
            aad.profile_version,
            aad.network_id,
            aad.conversation_id,
            aad.route_binding,
            aad.prior_state_id,
        );
        let expected = (
            target.tbs.profile_version,
            target.tbs.network_id,
            target.tbs.new_conversation_id,
            target.context.route_binding,
            self.finalization_id,
        );
        if frame != expected_frame
            || named != expected
            || aad.validation_time < self.validation_time
        {
            return Err(E2eeError::InvalidValue);
        }
        Ok(())
    }
}

/// The ReInit binding-chain entry is a `reinit_target_transition` whose
/// binding is exactly the binding in the carried target's context, and
/// whose package carries that binding's semantic plan and no root binding
/// lock (companion 9.4 and 13.8).
fn check_binding_entry(
    carried: &CarriedTarget,
    entry: &ArcBindingChainEntry,
) -> Result<(), E2eeError> {
    let package = &entry.package;
    let named = (
        entry.proof_kind,
        &package.binding,
        verify_initial_member_plan(&package.initial_member_plan)?,
    );
    let expected = (
        ArcBindingProofKind::ReinitTargetTransition,
        &carried.context.current_binding,
        carried.tbs.initial_member_plan_id,
    );
    if named == expected && package.root_binding_locks.is_empty() {
        Ok(())
    } else {
        Err(E2eeError::InvalidValue)
    }
}
