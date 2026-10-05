#![forbid(unsafe_code)]

//! Every Section 13.8 ReInit rejection rule, each shown by one edit of the
//! independent vectors, with the unedited control accepted beside it: the
//! reconstruction refuses a Proposal or context that does not describe the
//! successor; the old authorization and finalization must name one prior
//! state and commit one target; every later object must name the one
//! finalization; an attempt must name the one digest and target; the successor
//! initial Commit must name the old finalization; and a historical chain that
//! bound the target refuses an attempt a chain without it cannot tell apart.
//! Edited records are re-signed with the generator's fixed seeds.

use super::successor::{recore, relink_policy};
use super::support::*;

use agenc_relay_crypto::{SemanticHashDomain, SignatureDomain};
use agenc_relay_e2ee::finality::{ReinitVoteSlot, Terminal, reinit_vote_tbs};
use agenc_relay_e2ee::history::{ChainStep, HistoricalChain, RecordReferences};
use agenc_relay_e2ee::ids::{conversation_id, proof_set_digest, semantic_id_of};
use agenc_relay_e2ee::limits::MAX_ARC_MLS_CONTEXT_EXTENSION;
use agenc_relay_e2ee::mls_outer::{MlsReader, mls_varint_encode};
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind, ObjectId};
use agenc_relay_e2ee::objects::aad::ArcCommitAad;
use agenc_relay_e2ee::objects::conversation::{
    ArcBindingApproval, ArcCommitAuthorizationRule, ArcConversationKind,
    ArcConversationLifecycleKind, ArcKeyPackagePlanEntry, ArcMlsContext, ArcPendingJoin,
    action_bits,
};
use agenc_relay_e2ee::objects::reinit::{
    ArcReInitActivationRequest, ArcReInitAttempt, ArcReInitAttemptAuthorizationTbs,
    ArcReInitAttemptTbs, ArcReInitTargetTbs,
};
use agenc_relay_e2ee::objects::sequencing::{ArcFinalizationProof, ArcSequencerRecord};
use agenc_relay_e2ee::reinit_target::{
    AuthorizedReinit, CarriedTarget, REQUIRED_CAPABILITIES_EXTENSION, ReinitTarget,
    check_carried_target,
};
use agenc_relay_e2ee::route::VerifiedBinding;
use agenc_relay_e2ee::{E2eeError, Opaque, TlsDecode, TlsEncode, TlsVec};
use agenc_relay_testkit::e2ee_client::{key, sign};

/// The sequencer key seed of the generator's conversation.
const SEQUENCER_SEED: u8 = 115;
/// The creator's controller device seed.
const CONTROLLER_SEED: u8 = 112;
const CONTEXT_EXTENSION: u16 = 0xF1C1;
const FINALIZATION: &str = "suite-0001-record-03-reinit-finalization.bin";
const ATTEMPT: &str = "suite-0001-attempt-0.bin";
const RECEIPT: &str = "suite-0001-record-04-attempt-0-receipt.bin";
const ACTIVATION: &str = "suite-0001-record-05-activation.bin";

type ContextEdit = (&'static str, fn(&mut ArcMlsContext));

// --- extension lists ---------------------------------------------------------

fn split_extensions(encoded: &[u8]) -> TestResult<Vec<(u16, Vec<u8>)>> {
    let mut outer_budget = budget();
    let mut outer = MlsReader::new(encoded, &mut outer_budget);
    let body = outer.opaque_v()?.to_vec();
    outer.finish()?;
    let mut inner_budget = budget();
    let mut inner = MlsReader::new(&body, &mut inner_budget);
    let mut parts = Vec::new();
    while inner.remaining() > 0 {
        let extension_type = inner.u16()?;
        parts.push((extension_type, inner.opaque_v()?.to_vec()));
    }
    Ok(parts)
}

fn join_extensions(parts: &[(u16, Vec<u8>)]) -> TestResult<Vec<u8>> {
    let mut body = Vec::new();
    for (extension_type, data) in parts {
        body.extend_from_slice(&extension_type.to_be_bytes());
        mls_varint_encode(&mut body, data.len())?;
        body.extend_from_slice(data);
    }
    let mut encoded = Vec::new();
    mls_varint_encode(&mut encoded, body.len())?;
    encoded.extend_from_slice(&body);
    Ok(encoded)
}

/// Reconstructs the suite-0x0001 target from `extensions` in place of its own.
fn reconstruct_with(extensions: &[u8]) -> TestResult<Result<ReinitTarget, E2eeError>> {
    let proposal = Proposal::of(1)?;
    let mut fields = proposal.fields();
    fields.encoded_extensions = extensions;
    reconstruct(&fields)
}

/// Reconstructs the suite-0x0001 target after `edit` changed its context.
fn reconstruct_with_context(
    edit: impl FnOnce(&mut ArcMlsContext),
) -> TestResult<Result<ReinitTarget, E2eeError>> {
    let mut parts = split_extensions(&Proposal::of(1)?.extensions)?;
    let (_, data) = parts
        .iter_mut()
        .find(|(extension_type, _)| *extension_type == CONTEXT_EXTENSION)
        .ok_or("no context extension")?;
    let mut context = ArcMlsContext::decode_exact(data, &mut budget())?;
    edit(&mut context);
    *data = context.encode()?;
    reconstruct_with(&join_extensions(&parts)?)
}

/// The suite-0x0001 extension list rewritten so that its context describes
/// `group` consistently: the context, its binding and its re-signed
/// generation-zero policy name the conversation of `group`, the binding names
/// that policy, and it commits the context core recomputed for it (companion
/// 9.4), exactly as a sender that chose `group` would build it.
fn consistent_extensions_for(group: &[u8; 32]) -> TestResult<Vec<u8>> {
    let network = network()?;
    let conversation = conversation_id(&network, group)?;
    let mut parts = split_extensions(&Proposal::of(1)?.extensions)?;
    let capabilities = parts
        .iter()
        .find(|(extension_type, _)| *extension_type == REQUIRED_CAPABILITIES_EXTENSION)
        .ok_or("no required capabilities")?
        .1
        .clone();
    let (_, data) = parts
        .iter_mut()
        .find(|(extension_type, _)| *extension_type == CONTEXT_EXTENSION)
        .ok_or("no context extension")?;
    let mut context = ArcMlsContext::decode_exact(data, &mut budget())?;
    context.conversation_id = conversation;
    context.policy.tbs.conversation_id = conversation;
    let binding = &mut context.current_binding.tbs;
    binding.group_id = Opaque::from_slice(group)?;
    binding.conversation_id = conversation;
    relink_policy(&mut context)?;
    recore(&mut context, &capabilities)?;
    *data = context.encode()?;
    join_extensions(&parts)
}

#[test]
fn an_unedited_context_rebuilds_the_recorded_target() -> TestResult {
    let rebuilt = reconstruct_with_context(|_| {})??;
    assert_eq!(
        rebuilt.digest(),
        &id("suite-0001-target.bin", "target_context_digest")?
    );
    Ok(())
}

#[test]
fn a_proposal_outside_the_profile_or_naming_the_old_group_is_refused() -> TestResult {
    let proposal = Proposal::of(1)?;
    let network = network()?;
    let old = old_conversation()?;
    let old_group = hex(&global("old_group_id")?)?;
    let other_group = [0x42_u8; 32];
    let short_group = [0x41_u8; 31];
    let cases: [(&str, u16, u16, &[u8], E2eeError); 5] = [
        (
            "version",
            2,
            1,
            proposal.group_id.as_slice(),
            E2eeError::ProfileMismatch,
        ),
        (
            "disabled suite",
            1,
            2,
            proposal.group_id.as_slice(),
            E2eeError::ProfileMismatch,
        ),
        (
            "short group ID",
            1,
            1,
            &short_group,
            E2eeError::InvalidValue,
        ),
        (
            "the old group",
            1,
            1,
            old_group.as_slice(),
            E2eeError::InvalidValue,
        ),
        ("another group", 1, 1, &other_group, E2eeError::InvalidValue),
    ];
    for (name, version, suite, group_id, expected) in cases {
        let mut fields = proposal.fields();
        fields.version = version;
        fields.cipher_suite = suite;
        fields.group_id = group_id;
        assert_eq!(reconstruct(&fields)?, Err(expected), "{name}");
    }

    // The helper reproduces the recorded list for the recorded successor, and
    // a context rebuilt consistently for a fresh group yields that group's
    // target; the same context rebuilt for the old group is refused, by the
    // rule that the successor is never the old conversation alone.
    let successor: [u8; 32] = proposal.group_id.as_slice().try_into()?;
    assert_eq!(consistent_extensions_for(&successor)?, proposal.extensions);
    let fresh = other_group;
    let fresh_extensions = consistent_extensions_for(&fresh)?;
    let mut fields = proposal.fields();
    fields.group_id = &fresh;
    fields.encoded_extensions = &fresh_extensions;
    let rebuilt = reconstruct(&fields)??;
    assert_eq!(
        rebuilt.tbs().new_conversation_id,
        conversation_id(&network, &fresh)?
    );
    let old_group: [u8; 32] = old_group.as_slice().try_into()?;
    assert_eq!(conversation_id(&network, &old_group)?, old);
    let old_extensions = consistent_extensions_for(&old_group)?;
    fields.group_id = &old_group;
    fields.encoded_extensions = &old_extensions;
    assert_eq!(
        reconstruct(&fields)?,
        Err(E2eeError::InvalidValue),
        "a consistent context for the old group"
    );
    Ok(())
}

#[test]
fn an_extension_list_that_is_not_one_canonical_vector_is_refused() -> TestResult {
    let encoded = Proposal::of(1)?.extensions;
    let parts = split_extensions(&encoded)?;
    let first = *encoded.first().ok_or("empty list")?;
    let prefix = 1_usize << (first >> 6);
    let body = encoded.get(prefix..).ok_or("short list")?.to_vec();
    assert!(
        (0x40..0x4000).contains(&body.len()),
        "the fixture's list uses a two-byte prefix"
    );
    let length = u32::try_from(body.len())?;

    let mut longer = Vec::new();
    mls_varint_encode(&mut longer, body.len() + 1)?;
    longer.extend_from_slice(&body);
    let mut trailing = encoded.clone();
    trailing.push(0);
    let mut padded_prefix = (0x8000_0000_u32 | length).to_be_bytes().to_vec();
    padded_prefix.extend_from_slice(&body);
    let mut cut = Vec::new();
    mls_varint_encode(&mut cut, body.len() - 1)?;
    cut.extend_from_slice(body.get(..body.len() - 1).ok_or("short list")?);
    let without_context: Vec<_> = parts
        .iter()
        .filter(|(extension_type, _)| *extension_type != CONTEXT_EXTENSION)
        .cloned()
        .collect();
    let capabilities = parts
        .iter()
        .find(|(extension_type, _)| *extension_type == REQUIRED_CAPABILITIES_EXTENSION)
        .ok_or("no required capabilities")?
        .1
        .clone();
    let oversized = [
        (REQUIRED_CAPABILITIES_EXTENSION, capabilities),
        (
            CONTEXT_EXTENSION,
            vec![0; MAX_ARC_MLS_CONTEXT_EXTENSION + 1],
        ),
    ];
    let cases: [(&str, Vec<u8>, E2eeError); 7] = [
        ("empty", Vec::new(), E2eeError::Truncated),
        (
            "declared longer than its body",
            longer,
            E2eeError::Truncated,
        ),
        ("a trailing byte", trailing, E2eeError::TrailingBytes),
        (
            "a non-minimal length prefix",
            padded_prefix,
            E2eeError::NonCanonical,
        ),
        ("a cut final extension", cut, E2eeError::Truncated),
        (
            "no context extension",
            join_extensions(&without_context)?,
            E2eeError::InvalidValue,
        ),
        (
            "an oversized context",
            join_extensions(&oversized)?,
            E2eeError::LimitExceeded,
        ),
    ];
    for (name, extensions, expected) in cases {
        assert_eq!(
            reconstruct_with(&extensions)?.err(),
            Some(expected),
            "{name}"
        );
    }

    // Another extension type is carried and changes the digest, which covers
    // the exact bytes; the list stays one canonical vector.
    let mut extra = parts.clone();
    extra.push((0x0005, vec![7; 3]));
    let rebuilt = reconstruct_with(&join_extensions(&extra)?)??;
    assert_ne!(
        rebuilt.digest(),
        &id("suite-0001-target.bin", "target_context_digest")?
    );
    Ok(())
}

#[test]
fn a_context_that_does_not_describe_the_successor_rebuilds_no_target() -> TestResult {
    let edits: [ContextEdit; 20] = [
        ("context profile", |context| context.profile_version = 2),
        ("context network", |context| context.network_id = [9; 32]),
        ("context conversation", |context| {
            context.conversation_id = [9; 32]
        }),
        ("bootstrap pending", |context| context.bootstrap_pending = 1),
        ("closing lifecycle", |context| {
            context.lifecycle.kind = ArcConversationLifecycleKind::ClosingConversation;
            context.lifecycle.close_intent_id = [9; 32];
        }),
        ("close intent while active", |context| {
            context.lifecycle.close_intent_id = [9; 32]
        }),
        ("closing lifecycle without an intent", |context| {
            context.lifecycle.kind = ArcConversationLifecycleKind::ClosingConversation
        }),
        ("pending join", |context| {
            if let Ok(key_package_ref) = Opaque::new(vec![1; 32])
                && let Ok(joins) = TlsVec::new(vec![ArcPendingJoin {
                    leaf_index: 1,
                    key_package_ref,
                }])
            {
                context.pending_joins = joins;
            }
        }),
        ("approved replacement binding", |context| {
            if let Ok(approvals) = TlsVec::new(vec![ArcBindingApproval {
                signer_root_fingerprint: [9; 32],
                signer_device_id: [9; 16],
                signer_device_certificate_id: [9; 32],
                device_signature: [9; 64],
            }]) {
                context.current_binding.approvals = approvals;
            }
        }),
        ("generation-zero binding", |context| {
            context.current_binding.tbs.binding_generation = 0
        }),
        ("binding without a predecessor", |context| {
            context.current_binding.tbs.previous_binding_id = [0; 32]
        }),
        ("binding profile", |context| {
            context.current_binding.tbs.profile_version = 2
        }),
        ("binding network", |context| {
            context.current_binding.tbs.network_id = [9; 32]
        }),
        ("context kind", |context| {
            context.kind = ArcConversationKind::Direct
        }),
        ("binding group", |context| {
            if let Ok(group) = Opaque::new(vec![9; 32]) {
                context.current_binding.tbs.group_id = group;
            }
        }),
        ("binding conversation", |context| {
            context.current_binding.tbs.conversation_id = [9; 32]
        }),
        // The context and its binding agree on another conversation while the
        // binding keeps the context core recomputed for the Proposal's group.
        ("binding and context conversation", |context| {
            context.conversation_id = [9; 32];
            context.current_binding.tbs.conversation_id = [9; 32];
        }),
        ("context route", |context| context.route_binding = [9; 32]),
        ("binding version", |context| {
            context.current_binding.tbs.mls_version = 2
        }),
        ("binding suite", |context| {
            context.current_binding.tbs.cipher_suite = 3
        }),
    ];
    for (name, edit) in edits {
        assert_eq!(
            reconstruct_with_context(edit)?.err(),
            Some(E2eeError::InvalidValue),
            "{name}"
        );
    }
    Ok(())
}

#[test]
fn a_binding_whose_context_core_is_not_the_recomputed_one_rebuilds_no_target() -> TestResult {
    let edits: [ContextEdit; 8] = [
        ("context core ID", |context| {
            context.current_binding.tbs.context_core_id = [9; 32]
        }),
        ("initial validation time", |context| {
            context.initial_validation_time += 1
        }),
        ("route lock", |context| {
            context.current_binding.tbs.semantic_route_lock_id = [9; 32]
        }),
        ("route", |context| {
            context.current_binding.tbs.route_binding = [9; 32];
            context.route_binding = [9; 32];
        }),
        ("initial policy", |context| {
            context.current_binding.tbs.initial_policy_id = [9; 32]
        }),
        ("operational policy", |context| {
            context.current_binding.tbs.required_operational_policy_id = [9; 32]
        }),
        ("plan", |context| {
            context.current_binding.tbs.initial_member_plan_id = [9; 32]
        }),
        ("sequencer credential", |context| {
            context.current_binding.tbs.sequencer_credential_id = [9; 32]
        }),
    ];
    for (name, edit) in edits {
        assert_eq!(
            reconstruct_with_context(edit)?.err(),
            Some(E2eeError::InvalidValue),
            "{name}"
        );
    }
    let mut parts = split_extensions(&Proposal::of(1)?.extensions)?;
    for (extension_type, data) in &mut parts {
        if *extension_type == REQUIRED_CAPABILITIES_EXTENSION {
            data.push(0);
        }
    }
    assert_eq!(
        reconstruct_with(&join_extensions(&parts)?)?.err(),
        Some(E2eeError::InvalidValue),
        "required capabilities"
    );
    Ok(())
}

// --- the old authorization and finalization -------------------------------------

type ProofEdit = (&'static str, fn(&mut ArcFinalizationProof));

#[test]
fn the_old_authorization_must_carry_the_reinit_bit_alone_and_a_target() -> TestResult {
    let edits: [ProofEdit; 5] = [
        ("ReInit with a roster change", |proof| {
            proof.authorization.tbs.action_bits = action_bits::REINIT | action_bits::ROSTER
        }),
        ("no action", |proof| proof.authorization.tbs.action_bits = 0),
        ("a binding change", |proof| {
            proof.authorization.tbs.action_bits = action_bits::BINDING
        }),
        ("another rule", |proof| {
            proof.authorization.tbs.authorization_rule =
                ArcCommitAuthorizationRule::RoutineSelfUpdate
        }),
        ("no target", |proof| {
            proof.authorization.tbs.transition_target_digest = [0; 32]
        }),
    ];
    let original = finalization_proof(FINALIZATION)?;
    AuthorizedReinit::from_proof(&original)?;
    for (name, edit) in edits {
        let mut proof = original.clone();
        edit(&mut proof);
        // The core commits the edited authorization, so only the rule under
        // test can refuse it.
        recommit(&mut proof)?;
        assert_eq!(
            AuthorizedReinit::from_proof(&proof),
            Err(E2eeError::InvalidValue),
            "{name}"
        );
    }
    Ok(())
}

/// Makes the finalization core commit the proof's current authorization.
fn recommit(proof: &mut ArcFinalizationProof) -> TestResult {
    proof.core.commit_authorization_id = semantic_id_of(
        SemanticHashDomain::CommitAuthorizationId,
        &proof.authorization.tbs,
    )?;
    Ok(())
}

#[test]
fn the_authorization_core_and_receipt_must_name_one_prior_state_and_candidate() -> TestResult {
    // Edits of the authorization's position are recommitted by the core, so
    // the position rule alone refuses them; the last two edits test the
    // commitment itself.
    let recommitted = [
        "authorization prior state",
        "authorization candidate",
        "authorization Commit",
        "authorization epoch",
        "authorization network",
    ];
    let edits: [ProofEdit; 13] = [
        ("authorization prior state", |proof| {
            proof.authorization.tbs.prior_state_id = [9; 32]
        }),
        ("core prior state", |proof| {
            proof.core.prior_state_id = [9; 32]
        }),
        ("receipt prior state", |proof| {
            proof.receipt.tbs.prior_state_id = [9; 32]
        }),
        ("authorization candidate", |proof| {
            proof.authorization.tbs.candidate_id = [9; 32]
        }),
        ("core candidate", |proof| proof.core.candidate_id = [9; 32]),
        ("authorization Commit", |proof| {
            proof.authorization.tbs.commit_object_id = [9; 32]
        }),
        ("core Commit", |proof| proof.core.commit_object_id = [9; 32]),
        ("authorization epoch", |proof| {
            proof.authorization.tbs.prior_epoch += 1
        }),
        ("core epoch", |proof| proof.core.prior_epoch += 1),
        ("authorization network", |proof| {
            proof.authorization.tbs.network_id = [9; 32]
        }),
        ("core conversation", |proof| {
            proof.core.conversation_id = [9; 32]
        }),
        ("core authorization ID", |proof| {
            proof.core.commit_authorization_id = [9; 32]
        }),
        ("a changed authorization field", |proof| {
            proof.authorization.tbs.resulting_group_context_digest = [9; 32]
        }),
    ];
    let original = finalization_proof(FINALIZATION)?;
    for (name, edit) in edits {
        let mut proof = original.clone();
        edit(&mut proof);
        if recommitted.contains(&name) {
            recommit(&mut proof)?;
        }
        assert_eq!(
            AuthorizedReinit::from_proof(&proof),
            Err(E2eeError::InvalidValue),
            "{name}"
        );
    }

    // One consistent proof of another profile version is not this profile's.
    let mut other = original.clone();
    other.receipt.tbs.profile_version = 2;
    other.authorization.tbs.profile_version = 2;
    other.core.profile_version = 2;
    other.core.candidate_id = semantic_id_of(SemanticHashDomain::CandidateId, &other.receipt.tbs)?;
    other.authorization.tbs.candidate_id = other.core.candidate_id;
    other.core.commit_authorization_id = semantic_id_of(
        SemanticHashDomain::CommitAuthorizationId,
        &other.authorization.tbs,
    )?;
    assert_eq!(
        AuthorizedReinit::from_proof(&other),
        Err(E2eeError::ProfileMismatch)
    );

    // The finalization ID is the hash of the core, not a carried value.
    let mut edited = original.clone();
    edited.core.finalization_authenticator = [9; 32];
    let authorized = AuthorizedReinit::from_proof(&edited)?;
    assert_ne!(
        authorized.finalization_id(),
        &id(FINALIZATION, "semantic_id")?
    );
    assert_eq!(
        authorized.finalization_id(),
        &semantic_id_of(SemanticHashDomain::FinalizationId, &edited.core)?
    );
    Ok(())
}

// --- targets and attempts ----------------------------------------------------------

type TargetEdit = (&'static str, fn(&mut ArcReInitTargetTbs));
type AttemptEdit = (&'static str, fn(&mut ArcReInitAttemptTbs));

fn authorized() -> TestResult<AuthorizedReinit> {
    Ok(AuthorizedReinit::from_proof(&finalization_proof(
        FINALIZATION,
    )?)?)
}

fn target_edits() -> [TargetEdit; 11] {
    [
        ("profile", |target| target.profile_version = 2),
        ("network", |target| target.network_id = [9; 32]),
        ("old conversation", |target| {
            target.old_conversation_id = [9; 32]
        }),
        ("new conversation", |target| {
            target.new_conversation_id = [9; 32]
        }),
        ("group", |target| {
            if let Ok(group) = Opaque::new(vec![9; 32]) {
                target.target_group_id = group;
            }
        }),
        ("version", |target| target.target_version = 2),
        ("suite", |target| target.target_suite = 3),
        ("context core", |target| {
            target.target_context_core_id = [9; 32]
        }),
        ("binding", |target| target.target_binding_id = [9; 32]),
        ("plan", |target| target.initial_member_plan_id = [9; 32]),
        ("extensions", |target| {
            if let Ok(extensions) = Opaque::new(vec![0]) {
                target.encoded_target_extensions = extensions;
            }
        }),
    ]
}

#[test]
fn a_target_replaced_after_finalization_is_refused() -> TestResult {
    let authorized = authorized()?;
    let target = Proposal::of(1)?.reconstruct()?;
    authorized.check_target(target.tbs())?;
    let other = Proposal::of(3)?.reconstruct()?;
    assert_eq!(
        authorized.check_target(other.tbs()),
        Err(E2eeError::InvalidValue)
    );
    for (name, edit) in target_edits() {
        let mut replaced = target.tbs().clone();
        edit(&mut replaced);
        assert_eq!(
            authorized.check_target(&replaced),
            Err(E2eeError::InvalidValue),
            "{name}"
        );
    }

    // A target naming another profile, network or old conversation is
    // refused even when the authorization committed exactly its digest.
    for (name, edit) in target_edits() {
        if !["profile", "network", "old conversation"].contains(&name) {
            continue;
        }
        let mut misnamed = target.tbs().clone();
        edit(&mut misnamed);
        let mut proof = finalization_proof(FINALIZATION)?;
        proof.authorization.tbs.transition_target_digest =
            semantic_id_of(SemanticHashDomain::ReinitTarget, &misnamed)?;
        recommit(&mut proof)?;
        let committed = AuthorizedReinit::from_proof(&proof)?;
        assert_eq!(
            committed.check_target(&misnamed),
            Err(E2eeError::InvalidValue),
            "{name}"
        );
    }
    Ok(())
}

/// The old conversation's current binding when the ReInit is prepared.
fn old_binding() -> TestResult<VerifiedBinding> {
    Ok(old_authority()?.0)
}

/// The sequencer's checks of `attempt` under `authorized`.
fn sequenced(
    authorized: &AuthorizedReinit,
    attempt: &ArcReInitAttempt,
) -> TestResult<Result<CarriedTarget, E2eeError>> {
    Ok(authorized.check_attempt(attempt, &old_binding()?, &mut budget()))
}

#[test]
fn an_attempt_must_name_the_finalization_and_the_authorized_digest() -> TestResult {
    let authorized = authorized()?;
    let attempt = attempt(ATTEMPT)?;
    let target = Proposal::of(1)?.reconstruct()?;
    sequenced(&authorized, &attempt)??;
    authorized.check_attempt_target(&attempt, &target)?;
    let edits: [AttemptEdit; 5] = [
        ("profile", |attempt| attempt.profile_version = 2),
        ("network", |attempt| attempt.network_id = [9; 32]),
        ("old conversation", |attempt| {
            attempt.old_conversation_id = [9; 32]
        }),
        ("another finalization", |attempt| {
            attempt.old_reinit_state_id = [9; 32]
        }),
        ("another digest", |attempt| {
            attempt.target_context_digest = [9; 32]
        }),
    ];
    for (name, edit) in edits {
        let mut edited = attempt.clone();
        edit(&mut edited.tbs);
        assert_eq!(
            sequenced(&authorized, &edited)?.err(),
            Some(E2eeError::InvalidValue),
            "{name}"
        );
        assert_eq!(
            authorized.check_attempt_target(&edited, &target),
            Err(E2eeError::InvalidValue),
            "{name} at an endpoint"
        );
    }
    // The other suite's digest, and the prior state the pre-revision
    // reading would have used in the target, are both refused.
    let mut other_digest = attempt.clone();
    other_digest.tbs.target_context_digest = id("suite-0003-target.bin", "target_context_digest")?;
    assert!(sequenced(&authorized, &other_digest)?.is_err());
    let mut prior_state = attempt.clone();
    prior_state.tbs.old_reinit_state_id = *authorized.prior_state_id();
    assert!(sequenced(&authorized, &prior_state)?.is_err());
    // The sequencer's binding must be the old conversation's.
    let mut elsewhere = old_binding()?;
    elsewhere.conversation_id = [9; 32];
    assert_eq!(
        authorized.check_attempt(&attempt, &elsewhere, &mut budget()),
        Err(E2eeError::InvalidValue)
    );
    Ok(())
}

#[test]
fn an_attempt_must_name_the_fields_of_the_target_it_carries() -> TestResult {
    let authorized = authorized()?;
    let attempt = attempt(ATTEMPT)?;
    let target = Proposal::of(1)?.reconstruct()?;
    let edits: [AttemptEdit; 6] = [
        ("new conversation", |attempt| {
            attempt.new_conversation_id = [9; 32]
        }),
        ("group", |attempt| {
            if let Ok(group) = Opaque::new(vec![9; 32]) {
                attempt.target_group_id = group;
            }
        }),
        ("version", |attempt| attempt.target_version = 2),
        ("suite", |attempt| attempt.target_suite = 3),
        ("binding", |attempt| attempt.target_binding_id = [9; 32]),
        ("plan", |attempt| attempt.initial_member_plan_id = [9; 32]),
    ];
    for (name, edit) in edits {
        let mut edited = attempt.clone();
        edit(&mut edited.tbs);
        // The sequencer compares them with the target the attempt carries.
        assert_eq!(
            sequenced(&authorized, &edited)?.err(),
            Some(E2eeError::InvalidValue),
            "{name}"
        );
        assert_eq!(
            authorized.check_attempt_target(&edited, &target),
            Err(E2eeError::InvalidValue),
            "{name} at an endpoint"
        );
    }
    let other = Proposal::of(3)?.reconstruct()?;
    assert!(authorized.check_attempt_target(&attempt, &other).is_err());
    // A reconstruction that differs only where the attempt repeats nothing,
    // its extension list, is not the target the attempt carries.
    let mut parts = split_extensions(&Proposal::of(1)?.extensions)?;
    parts.push((0x0005, vec![7; 3]));
    let uncommitted = reconstruct_with(&join_extensions(&parts)?)??;
    assert_eq!(
        authorized.check_attempt_target(&attempt, &uncommitted),
        Err(E2eeError::InvalidValue)
    );
    Ok(())
}

#[test]
fn an_attempt_must_carry_the_authorized_target() -> TestResult {
    let authorized = authorized()?;
    let attempt = attempt(ATTEMPT)?;
    let target = Proposal::of(1)?.reconstruct()?;
    // Every edit of the carried bytes, the other suite's target, and a
    // target whose list carries one more extension: the bytes no longer
    // hash to the digest the attempt names and the finalization authorized.
    let mut parts = split_extensions(&Proposal::of(1)?.extensions)?;
    parts.push((0x0005, vec![7; 3]));
    let mut carried = vec![
        Proposal::of(3)?.reconstruct()?.tbs().clone(),
        reconstruct_with(&join_extensions(&parts)?)??.tbs().clone(),
    ];
    for (_, edit) in target_edits() {
        let mut replaced = target.tbs().clone();
        edit(&mut replaced);
        carried.push(replaced);
    }
    for replaced in carried {
        let mut edited = attempt.clone();
        edited.target = replaced;
        assert!(sequenced(&authorized, &edited)?.is_err());
        assert!(authorized.check_attempt_target(&edited, &target).is_err());
    }
    Ok(())
}

/// One edit of an attempt's KeyPackage plan entries.
type PlanEdit = (&'static str, fn(&mut Vec<ArcKeyPackagePlanEntry>));

#[test]
fn an_attempt_plan_must_form_the_target_semantic_plan() -> TestResult {
    let authorized = authorized()?;
    let attempt = attempt(ATTEMPT)?;
    let target = Proposal::of(1)?.reconstruct()?;
    let refused: [PlanEdit; 6] = [
        ("capability", |entries| {
            if let Some(entry) = entries.first_mut() {
                entry.capability_id = [9; 32];
            }
        }),
        ("device", |entries| {
            if let Some(entry) = entries.last_mut() {
                entry.device_id = [0xFF; 16];
            }
        }),
        ("root", |entries| {
            if let Some(entry) = entries.first_mut() {
                entry.root_fingerprint = [9; 32];
            }
        }),
        ("account", |entries| {
            if let Some(entry) = entries.last_mut()
                && let Ok(account) = Opaque::new(vec![b'z'; 24])
            {
                entry.account_id = account;
            }
        }),
        ("a missing entry", |entries| {
            entries.pop();
        }),
        ("another order", |entries| entries.reverse()),
    ];
    for (name, edit) in refused {
        let mut edited = attempt.clone();
        let mut entries = edited.key_package_plan.entries.as_slice().to_vec();
        edit(&mut entries);
        edited.key_package_plan.entries = TlsVec::new(entries)?;
        assert!(sequenced(&authorized, &edited)?.is_err(), "{name}");
        assert!(
            authorized.check_attempt_target(&edited, &target).is_err(),
            "{name} at an endpoint"
        );
    }
    // The one-use fields a semantic plan omits do not change it.
    let mut fresh = attempt.clone();
    let mut entries = fresh.key_package_plan.entries.as_slice().to_vec();
    for entry in &mut entries {
        entry.leaf_signature_key_digest = [9; 32];
        if entry.creator == 0 {
            entry.key_package_ref = Opaque::new(vec![9; 32])?;
        }
    }
    fresh.key_package_plan.entries = TlsVec::new(entries)?;
    sequenced(&authorized, &fresh)??;
    authorized.check_attempt_target(&fresh, &target)?;
    Ok(())
}

/// The suite-0x0001 finalization proof re-committed to `target`'s digest,
/// and the suite-0x0001 attempt carrying `target` and naming its fields.
fn committed_to(target: &ArcReInitTargetTbs) -> TestResult<(AuthorizedReinit, ArcReInitAttempt)> {
    let digest = semantic_id_of(SemanticHashDomain::ReinitTarget, target)?;
    let mut proof = finalization_proof(FINALIZATION)?;
    proof.authorization.tbs.transition_target_digest = digest;
    recommit(&mut proof)?;
    let authorized = AuthorizedReinit::from_proof(&proof)?;
    let mut attempt = attempt(ATTEMPT)?;
    attempt.tbs.old_reinit_state_id = *authorized.finalization_id();
    attempt.tbs.target_context_digest = digest;
    attempt.tbs.new_conversation_id = target.new_conversation_id;
    attempt.tbs.target_group_id = target.target_group_id.clone();
    attempt.tbs.target_version = target.target_version;
    attempt.tbs.target_suite = target.target_suite;
    attempt.tbs.target_binding_id = target.target_binding_id;
    attempt.tbs.initial_member_plan_id = target.initial_member_plan_id;
    attempt.target = target.clone();
    Ok((authorized, attempt))
}

#[test]
fn the_sequencer_rebuilds_the_carried_target_from_its_extension_list() -> TestResult {
    let network = network()?;
    let binding = old_binding()?;
    let target = Proposal::of(1)?.reconstruct()?;
    let carried = check_carried_target(&network, &binding, target.tbs(), &mut budget())?;
    assert_eq!(&carried, target.carried());
    // Each derived field edited, the list kept: the target is not the one its
    // list yields, although an authorization committed exactly its digest.
    for (name, edit) in target_edits() {
        let mut edited = target.tbs().clone();
        edit(&mut edited);
        assert!(
            check_carried_target(&network, &binding, &edited, &mut budget()).is_err(),
            "{name}"
        );
        let (authorized, attempt) = committed_to(&edited)?;
        assert!(
            sequenced(&authorized, &attempt)?.is_err(),
            "{name} sequenced"
        );
    }
    // A list that fails the structural rules, with every other field
    // consistent: refused although its digest was authorized.
    for (file, expected) in [
        (
            "reject-extensions-duplicate-context.bin",
            E2eeError::NonCanonical,
        ),
        (
            "reject-extensions-missing-required-capabilities.bin",
            E2eeError::InvalidValue,
        ),
        (
            "reject-extensions-context-core-mismatch.bin",
            E2eeError::InvalidValue,
        ),
        (
            "reject-extensions-later-joiner-context.bin",
            E2eeError::InvalidValue,
        ),
    ] {
        let mut edited = target.tbs().clone();
        edited.encoded_target_extensions = Opaque::new(read(file)?)?;
        assert_eq!(
            check_carried_target(&network, &binding, &edited, &mut budget()).err(),
            Some(expected),
            "{file}"
        );
        let (authorized, attempt) = committed_to(&edited)?;
        assert_eq!(
            sequenced(&authorized, &attempt)?.err(),
            Some(expected),
            "{file}"
        );
    }
    // A consistent target of another old binding is refused against this one.
    let mut other = binding.clone();
    other.binding_id = [9; 32];
    assert_eq!(
        check_carried_target(&network, &other, target.tbs(), &mut budget()).err(),
        Some(E2eeError::InvalidValue)
    );
    // The control: the authorization committed to the recorded target.
    let (authorized, attempt) = committed_to(target.tbs())?;
    assert_eq!(sequenced(&authorized, &attempt)??, carried);
    Ok(())
}

// --- the successor initial Commit ------------------------------------------------------

/// One `PrivateMessage` frame with synthetic sender data and ciphertext.
fn frame(group: &[u8], epoch: u64, content_type: u8, aad: &[u8]) -> TestResult<Vec<u8>> {
    let mut out = vec![0, 1, 0, 2];
    mls_varint_encode(&mut out, group.len())?;
    out.extend_from_slice(group);
    out.extend_from_slice(&epoch.to_be_bytes());
    out.push(content_type);
    mls_varint_encode(&mut out, aad.len())?;
    out.extend_from_slice(aad);
    for filler in [vec![1; 32], vec![2; 64]] {
        mls_varint_encode(&mut out, filler.len())?;
        out.extend_from_slice(&filler);
    }
    Ok(out)
}

#[test]
fn the_successor_initial_commit_must_name_the_old_finalization() -> TestResult {
    let authorized = authorized()?;
    let target = Proposal::of(1)?.reconstruct()?;
    let group = target.tbs().target_group_id.as_slice().to_vec();
    let aad = ArcCommitAad {
        profile_version: 1,
        network_id: network()?,
        conversation_id: target.tbs().new_conversation_id,
        route_binding: *target.route_binding(),
        validation_time: 150,
        prior_state_id: *authorized.finalization_id(),
    };
    // The earliest permitted time is the old ReInit Commit's own.
    authorized.check_initial_commit(
        &frame(&group, 0, 3, &aad.encode()?)?,
        target.carried(),
        &mut budget(),
    )?;
    let cases = [
        (
            "profile",
            ArcCommitAad {
                profile_version: 2,
                ..aad.clone()
            },
        ),
        (
            "network",
            ArcCommitAad {
                network_id: [9; 32],
                ..aad.clone()
            },
        ),
        (
            "the old conversation",
            ArcCommitAad {
                conversation_id: old_conversation()?,
                ..aad.clone()
            },
        ),
        (
            "another route",
            ArcCommitAad {
                route_binding: [9; 32],
                ..aad.clone()
            },
        ),
        (
            "no prior state",
            ArcCommitAad {
                prior_state_id: [0; 32],
                ..aad.clone()
            },
        ),
        (
            "another prior state",
            ArcCommitAad {
                prior_state_id: [9; 32],
                ..aad.clone()
            },
        ),
        (
            "the successor's own activation",
            ArcCommitAad {
                prior_state_id: id(ACTIVATION, "semantic_id")?,
                ..aad.clone()
            },
        ),
        (
            "the old candidate's prior state",
            ArcCommitAad {
                prior_state_id: *authorized.prior_state_id(),
                ..aad.clone()
            },
        ),
        (
            "an earlier time",
            ArcCommitAad {
                validation_time: 149,
                ..aad.clone()
            },
        ),
    ];
    for (name, edited) in cases {
        assert_eq!(
            authorized.check_initial_commit(
                &frame(&group, 0, 3, &edited.encode()?)?,
                target.carried(),
                &mut budget()
            ),
            Err(E2eeError::InvalidValue),
            "{name}"
        );
    }
    let encoded = aad.encode()?;
    let mut trailing = encoded.clone();
    trailing.push(0);
    let frames: [(&str, Vec<u8>, E2eeError); 4] = [
        (
            "another group",
            frame(&[9; 32], 0, 3, &encoded)?,
            E2eeError::InvalidValue,
        ),
        (
            "a later epoch",
            frame(&group, 1, 3, &encoded)?,
            E2eeError::InvalidValue,
        ),
        (
            "application content",
            frame(&group, 0, 1, &encoded)?,
            E2eeError::InvalidValue,
        ),
        (
            "trailing AAD bytes",
            frame(&group, 0, 3, &trailing)?,
            E2eeError::TrailingBytes,
        ),
    ];
    for (name, bytes, expected) in frames {
        assert_eq!(
            authorized.check_initial_commit(&bytes, target.carried(), &mut budget()),
            Err(expected),
            "{name}"
        );
    }
    // Only a PrivateMessage carries the successor initial Commit: a Welcome
    // and the successor GroupInfo message mls-rs 0.56 returns are refused.
    let welcome_message = [0, 1, 0, 3, 0, 1, 0, 1, 0xAA];
    let group_info_message = [0, 1, 0, 4, 0];
    for (name, bytes) in [
        ("a Welcome", welcome_message.as_slice()),
        ("a GroupInfo", group_info_message.as_slice()),
    ] {
        assert_eq!(
            authorized.check_initial_commit(bytes, target.carried(), &mut budget()),
            Err(E2eeError::WrongKind),
            "{name}"
        );
    }
    let welcome = read("suite-0001-attempt-0.bin")?;
    assert!(
        authorized
            .check_initial_commit(&welcome, target.carried(), &mut budget())
            .is_err(),
        "not an MLS message"
    );
    let other = Proposal::of(3)?.reconstruct()?;
    assert_eq!(
        authorized.check_initial_commit(
            &read("suite-0001-initial-commit-0.bin")?,
            other.carried(),
            &mut budget()
        ),
        Err(E2eeError::InvalidValue),
        "another target"
    );
    // A target of the same successor group, conversation and route whose
    // list carries one more extension has another digest: the Commit is not
    // checked against a target the authorization never committed.
    let mut parts = split_extensions(&Proposal::of(1)?.extensions)?;
    parts.push((0x0005, vec![7; 3]));
    let uncommitted = reconstruct_with(&join_extensions(&parts)?)??;
    assert_eq!(
        (
            uncommitted.tbs().new_conversation_id,
            uncommitted.route_binding()
        ),
        (target.tbs().new_conversation_id, target.route_binding())
    );
    assert_eq!(
        authorized.check_initial_commit(
            &frame(&group, 0, 3, &encoded)?,
            uncommitted.carried(),
            &mut budget()
        ),
        Err(E2eeError::InvalidValue),
        "a target the authorization did not commit"
    );
    Ok(())
}

// --- the historical chain -------------------------------------------------------------------

/// The chain after the suite-0x0001 ReInit finalization.
fn finalized_chain() -> TestResult<HistoricalChain> {
    let mut chain = activated_chain()?;
    advance(&mut chain, "suite-0001-record-02-reinit-candidate.bin")?;
    advance(&mut chain, FINALIZATION)?;
    Ok(chain)
}

fn authorization_of(tbs: &ArcReInitAttemptTbs) -> ArcReInitAttemptAuthorizationTbs {
    ArcReInitAttemptAuthorizationTbs {
        profile_version: tbs.profile_version,
        network_id: tbs.network_id,
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
    }
}

fn record_bytes(record: &ArcSequencerRecord) -> TestResult<Vec<u8>> {
    Ok(ArcWireObject::new(ArcWireObjectKind::SequencerRecord, record.encode()?)?.encode()?)
}

/// The suite-0x0001 attempt after `edit`, re-approved by the controller
/// (unless `keep_authorization`), and the receipt re-sequenced for it.
fn resequenced(
    keep_authorization: bool,
    edit: impl FnOnce(&mut ArcReInitAttempt),
) -> TestResult<(Vec<u8>, Vec<u8>)> {
    let mut attempt = attempt(ATTEMPT)?;
    edit(&mut attempt);
    if !keep_authorization {
        attempt.authorization.tbs = authorization_of(&attempt.tbs);
    }
    let mut approvals = attempt.authorization.approvals.as_slice().to_vec();
    for approval in &mut approvals {
        approval.device_signature = sign(
            &key(CONTROLLER_SEED),
            SignatureDomain::ReinitAttemptAuthorization,
            &attempt.authorization.tbs,
        )?;
    }
    attempt.authorization.approvals = TlsVec::new(approvals)?;
    attempt.tbs.attempt_authorization_id = semantic_id_of(
        SemanticHashDomain::ReinitAttemptAuthorizationId,
        &attempt.authorization.tbs,
    )?;
    let object =
        ArcWireObject::new(ArcWireObjectKind::ReinitAttempt, attempt.encode()?)?.encode()?;
    let ArcSequencerRecord::ReinitAttempt(mut receipt) = record(RECEIPT)? else {
        return Err("the receipt file holds another record".into());
    };
    receipt.tbs.reinit_attempt_id =
        semantic_id_of(SemanticHashDomain::ReinitAttemptId, &attempt.tbs)?;
    receipt.tbs.attempt_object_id = *ObjectId::compute(&object).as_bytes();
    receipt.sequencer_signature = sign(
        &key(SEQUENCER_SEED),
        SignatureDomain::ReinitAttemptReceipt,
        &receipt.tbs,
    )?;
    Ok((
        record_bytes(&ArcSequencerRecord::ReinitAttempt(receipt))?,
        object,
    ))
}

fn adopt_attempt(
    chain: &mut HistoricalChain,
    receipt: &[u8],
    object: &[u8],
) -> TestResult<ChainStep> {
    Ok(chain.advance(
        receipt,
        &RecordReferences {
            attempt_object: Some(object),
            ..RecordReferences::default()
        },
        &mut budget(),
    )?)
}

fn refused(chain: &HistoricalChain, receipt: &[u8], object: &[u8]) -> bool {
    let mut probe = chain.clone();
    adopt_attempt(&mut probe, receipt, object).is_err() && probe.head() == chain.head()
}

#[test]
fn a_target_binds_only_to_a_finalized_reinit_whose_digest_it_has() -> TestResult {
    let target = Proposal::of(1)?.reconstruct()?;
    let mut active = activated_chain()?;
    assert_eq!(
        active.bind_reinit_target(target.tbs()),
        Err(E2eeError::InvalidValue),
        "an active conversation has no ReInit to bind"
    );
    let mut chain = finalized_chain()?;
    let other = Proposal::of(3)?.reconstruct()?;
    assert_eq!(
        chain.bind_reinit_target(other.tbs()),
        Err(E2eeError::InvalidValue)
    );
    for (name, edit) in target_edits() {
        let mut replaced = target.tbs().clone();
        edit(&mut replaced);
        assert!(chain.bind_reinit_target(&replaced).is_err(), "{name}");
    }
    chain.bind_reinit_target(target.tbs())?;
    chain.bind_reinit_target(target.tbs())?;
    let (receipt, object) = resequenced(false, |_| {})?;
    adopt_attempt(&mut chain, &receipt, &object)?;
    advance(&mut chain, ACTIVATION)?;
    assert_eq!(
        chain.bind_reinit_target(target.tbs()),
        Err(E2eeError::InvalidValue),
        "an activated lineage has ended"
    );
    Ok(())
}

type AttemptObjectEdit = (&'static str, fn(&mut ArcReInitAttempt));

#[test]
fn every_chain_refuses_an_attempt_that_does_not_repeat_its_carried_target() -> TestResult {
    let target = Proposal::of(1)?.reconstruct()?;
    let unbound = finalized_chain()?;
    let mut bound = finalized_chain()?;
    bound.bind_reinit_target(target.tbs())?;
    let (receipt, object) = resequenced(false, |_| {})?;
    assert!(
        !refused(&unbound, &receipt, &object),
        "the unedited attempt"
    );
    assert!(
        !refused(&bound, &receipt, &object),
        "the unedited attempt, bound"
    );
    let edits: [AttemptObjectEdit; 6] = [
        ("new conversation", |attempt| {
            attempt.tbs.new_conversation_id = [9; 32]
        }),
        ("group", |attempt| {
            if let Ok(group) = Opaque::new(vec![9; 32]) {
                attempt.tbs.target_group_id = group;
            }
        }),
        ("version", |attempt| attempt.tbs.target_version = 2),
        ("suite", |attempt| attempt.tbs.target_suite = 3),
        ("binding", |attempt| attempt.tbs.target_binding_id = [9; 32]),
        ("plan", |attempt| {
            attempt.tbs.initial_member_plan_id = [9; 32]
        }),
    ];
    for (name, edit) in edits {
        let (receipt, object) = resequenced(false, edit)?;
        assert!(refused(&unbound, &receipt, &object), "{name}");
        assert!(refused(&bound, &receipt, &object), "{name}, bound");
    }
    Ok(())
}

#[test]
fn a_chain_refuses_a_carried_target_other_than_the_authorized_one() -> TestResult {
    let target = Proposal::of(1)?.reconstruct()?;
    let unbound = finalized_chain()?;
    let mut bound = finalized_chain()?;
    bound.bind_reinit_target(target.tbs())?;
    // Without a bound target the carried bytes must hash to the digest; with
    // one they must be its bytes. Either refuses every replaced target.
    let mut replaced = vec![Proposal::of(3)?.reconstruct()?.tbs().clone()];
    for (_, edit) in target_edits() {
        let mut edited = target.tbs().clone();
        edit(&mut edited);
        replaced.push(edited);
    }
    for other in replaced {
        let (receipt, object) = resequenced(false, |attempt| attempt.target = other.clone())?;
        assert!(refused(&unbound, &receipt, &object));
        assert!(refused(&bound, &receipt, &object));
    }
    Ok(())
}

#[test]
fn a_late_binding_never_vouches_for_an_open_attempt() -> TestResult {
    let target = Proposal::of(1)?.reconstruct()?;
    // The unedited attempt, opened on a chain without the target: even the
    // matching target does not bind now, and the refusal changes nothing.
    let mut open = finalized_chain()?;
    let (receipt, object) = resequenced(false, |_| {})?;
    adopt_attempt(&mut open, &receipt, &object)?;
    let head = open.head().record_id;
    assert_eq!(
        open.bind_reinit_target(target.tbs()),
        Err(E2eeError::InvalidValue)
    );
    assert_eq!(open.head().record_id, head);
    Ok(())
}

#[test]
fn every_object_after_finalization_must_name_that_finalization() -> TestResult {
    let chain = finalized_chain()?;
    let (receipt, object) = resequenced(false, |_| {})?;
    assert!(!refused(&chain, &receipt, &object));

    // An attempt, its authorization, or its receipt naming another
    // finalization.
    let (receipt, object) =
        resequenced(false, |attempt| attempt.tbs.old_reinit_state_id = [9; 32])?;
    assert!(refused(&chain, &receipt, &object), "attempt");
    let (receipt, object) = resequenced(true, |attempt| {
        attempt.authorization.tbs.old_reinit_state_id = [9; 32]
    })?;
    assert!(refused(&chain, &receipt, &object), "attempt authorization");
    let ArcSequencerRecord::ReinitAttempt(mut other) = record(RECEIPT)? else {
        return Err("the receipt file holds another record".into());
    };
    other.tbs.old_reinit_state_id = [9; 32];
    other.sequencer_signature = sign(
        &key(SEQUENCER_SEED),
        SignatureDomain::ReinitAttemptReceipt,
        &other.tbs,
    )?;
    assert!(
        refused(
            &chain,
            &record_bytes(&ArcSequencerRecord::ReinitAttempt(other))?,
            &read(ATTEMPT)?
        ),
        "receipt"
    );

    // An activation core, an ACK, or the votes naming another finalization.
    let mut open = chain.clone();
    adopt_attempt(&mut open, &read(RECEIPT)?, &read(ATTEMPT)?)?;
    let activation_refused = |edit: fn(&mut ArcReInitActivationRequest), slot: [u8; 32]| {
        let bytes = resigned_activation(edit, slot)?;
        let mut probe = open.clone();
        let refused = probe
            .advance(&bytes, &RecordReferences::default(), &mut budget())
            .is_err()
            && probe.head() == open.head();
        Ok::<bool, Box<dyn std::error::Error>>(refused)
    };
    let finalization_id = id(FINALIZATION, "semantic_id")?;
    assert!(!activation_refused(|_| {}, finalization_id)?, "unedited");
    assert!(
        activation_refused(
            |request| request.core.old_reinit_state_id = [9; 32],
            finalization_id
        )?,
        "activation core"
    );
    assert!(
        activation_refused(
            |request| {
                let mut acks = request.acknowledgements.as_slice().to_vec();
                if let Some(first) = acks.first_mut() {
                    first.tbs.old_reinit_state_id = [9; 32];
                }
                if let Ok(acks) = TlsVec::new(acks) {
                    request.acknowledgements = acks;
                }
            },
            finalization_id
        )?,
        "acknowledgement"
    );
    assert!(activation_refused(|_| {}, [9; 32])?, "votes");
    Ok(())
}

/// The suite-0x0001 activation after `edit`, with its ACK-set digest,
/// activation ID, votes over `slot_state`'s slot and certificate recomputed.
fn resigned_activation(
    edit: fn(&mut ArcReInitActivationRequest),
    slot_state: [u8; 32],
) -> TestResult<Vec<u8>> {
    let ArcSequencerRecord::ReinitActivation(mut certificate) = record(ACTIVATION)? else {
        return Err("the activation file holds another record".into());
    };
    let request = &mut certificate.tbs.request;
    edit(request);
    let acks: Vec<_> = request
        .acknowledgements
        .as_slice()
        .iter()
        .map(|ack| ack.tbs.clone())
        .collect();
    request.core.acknowledgement_set_digest =
        proof_set_digest(SemanticHashDomain::ReinitAcknowledgementSet, &acks)?;
    let activation_id = semantic_id_of(SemanticHashDomain::ReinitActivationId, &request.core)?;
    let receipt = &request.receipt.tbs;
    let slot = ReinitVoteSlot {
        network_id: receipt.network_id,
        old_conversation_id: receipt.old_conversation_id,
        old_reinit_state_id: slot_state,
        attempt_sequence: receipt.attempt_sequence,
        predecessor_record_id: receipt.predecessor_record_id,
    };
    let vote = reinit_vote_tbs(
        &slot,
        receipt.reinit_attempt_id,
        Terminal::finalize(activation_id),
    );
    let mut votes = request.votes.as_slice().to_vec();
    for signer in &mut votes {
        let seed = *signer.signer_device_id.first().ok_or("empty device ID")?;
        signer.device_signature = sign(&key(seed), SignatureDomain::ReinitDisposition, &vote)?;
    }
    request.votes = TlsVec::new(votes)?;
    certificate.tbs.reinit_activation_id = activation_id;
    certificate.sequencer_signature = sign(
        &key(SEQUENCER_SEED),
        SignatureDomain::ReinitActivation,
        &certificate.tbs,
    )?;
    record_bytes(&ArcSequencerRecord::ReinitActivation(certificate))
}
