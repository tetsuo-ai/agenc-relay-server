#![forbid(unsafe_code)]

//! The successor context a ReInit target carries, beyond its own fields
//! (companion 9.2 to 9.5 and 13.8): its binding replaces the old
//! conversation's current binding, it meets every rule of a context
//! extension, and its policy and sequencer credential are the ones its
//! binding names. Each case edits the suite-0x0001 context, re-signs what the
//! edit invalidates, and recomputes the binding's context core, so that only
//! the rule under test separates it from the accepted control. Each structural
//! case is refused twice: by an endpoint's reconstruction from the Proposal,
//! and by the sequencer's check of the target a sender carrying the edited
//! list would build, which has no rosters and verifies no policy approval.

use super::support::*;

use agenc_relay_crypto::SignatureDomain;
use agenc_relay_e2ee::context::context_core_id;
use agenc_relay_e2ee::ids::semantic_id_of;
use agenc_relay_e2ee::mls_outer::{MlsReader, mls_varint_encode};
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::conversation::{
    ArcContextCoreTbs, ArcConversationKind, ArcMlsContext, ArcPolicy, ArcPolicyTbs,
};
use agenc_relay_e2ee::objects::reinit::ArcReInitTargetTbs;
use agenc_relay_e2ee::reinit_target::{
    CarriedTarget, REQUIRED_CAPABILITIES_EXTENSION, ReinitTarget, check_carried_target,
};
use agenc_relay_e2ee::route::{channel_route_binding, verify_semantic_route};
use agenc_relay_e2ee::{E2eeError, Opaque, TlsDecode, TlsEncode, TlsVec};
use agenc_relay_testkit::e2ee_client::{key, sign};

use agenc_relay_crypto::SemanticHashDomain;

const CONTEXT_EXTENSION: u16 = 0xF1C1;

type Edit = (&'static str, fn(&mut ArcMlsContext) -> TestResult);

/// The suite-0x0001 extension list, split into `(type, data)` pairs.
fn parts() -> TestResult<Vec<(u16, Vec<u8>)>> {
    let encoded = Proposal::of(1)?.extensions;
    let mut outer_budget = budget();
    let mut outer = MlsReader::new(&encoded, &mut outer_budget);
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

fn join(parts: &[(u16, Vec<u8>)]) -> TestResult<Vec<u8>> {
    let mut body = Vec::new();
    for (extension_type, data) in parts {
        body.extend_from_slice(&extension_type.to_be_bytes());
        mls_varint_encode(&mut body, data.len())?;
        body.extend_from_slice(data);
    }
    let mut out = Vec::new();
    mls_varint_encode(&mut out, body.len())?;
    out.extend_from_slice(&body);
    Ok(out)
}

fn part(parts: &[(u16, Vec<u8>)], wanted: u16) -> TestResult<Vec<u8>> {
    Ok(parts
        .iter()
        .find(|(extension_type, _)| *extension_type == wanted)
        .ok_or("missing extension")?
        .1
        .clone())
}

/// Re-signs the context's policy with the generator's device seeds and
/// names its new ID as the binding's initial and required operational policy.
pub(crate) fn relink_policy(context: &mut ArcMlsContext) -> TestResult {
    let mut approvals = context.policy.approvals.as_slice().to_vec();
    for approval in &mut approvals {
        let seed = *approval.signer_device_id.first().ok_or("empty device ID")?;
        approval.device_signature = sign(
            &key(seed),
            SignatureDomain::PolicyApproval,
            &context.policy.tbs,
        )?;
    }
    context.policy.approvals = TlsVec::new(approvals)?;
    let policy_id = semantic_id_of(SemanticHashDomain::PolicyId, &context.policy.tbs)?;
    let binding = &mut context.current_binding.tbs;
    binding.initial_policy_id = policy_id;
    binding.required_operational_policy_id = policy_id;
    Ok(())
}

/// Recomputes the binding's context core from the context and the binding,
/// as a sender that chose these values would (companion 9.4).
pub(crate) fn recore(context: &mut ArcMlsContext, capabilities: &[u8]) -> TestResult {
    let binding = &context.current_binding.tbs;
    let core = ArcContextCoreTbs {
        profile_version: 1,
        mls_version: binding.mls_version,
        cipher_suite: binding.cipher_suite,
        group_id: binding.group_id.clone(),
        network_id: binding.network_id,
        conversation_id: binding.conversation_id,
        kind: binding.kind,
        semantic_route_lock_id: binding.semantic_route_lock_id,
        route_binding: binding.route_binding,
        initial_validation_time: context.initial_validation_time,
        initial_policy_id: binding.initial_policy_id,
        required_operational_policy_id: binding.required_operational_policy_id,
        initial_bootstrap_pending: 0,
        initial_member_plan_id: binding.initial_member_plan_id,
        sequencer_credential_id: binding.sequencer_credential_id,
        encoded_required_capabilities: Opaque::from_slice(capabilities)?,
    };
    context.current_binding.tbs.context_core_id = context_core_id(&core)?;
    Ok(())
}

/// The context core the reconstruction recomputes: the Proposal's group,
/// version and suite and the successor conversation its group names, with
/// the binding's other fields. A binding that commits it can be refused only
/// by another rule.
fn recore_for_proposal(context: &mut ArcMlsContext, capabilities: &[u8]) -> TestResult {
    let proposal = Proposal::of(1)?;
    recore(context, capabilities)?;
    let binding = &context.current_binding.tbs;
    let core = ArcContextCoreTbs {
        profile_version: 1,
        mls_version: 1,
        cipher_suite: proposal.suite,
        group_id: Opaque::from_slice(&proposal.group_id)?,
        network_id: network()?,
        conversation_id: id("suite-0001-extensions.bin", "new_conversation_id")?,
        kind: binding.kind,
        semantic_route_lock_id: binding.semantic_route_lock_id,
        route_binding: binding.route_binding,
        initial_validation_time: context.initial_validation_time,
        initial_policy_id: binding.initial_policy_id,
        required_operational_policy_id: binding.required_operational_policy_id,
        initial_bootstrap_pending: 0,
        initial_member_plan_id: binding.initial_member_plan_id,
        sequencer_credential_id: binding.sequencer_credential_id,
        encoded_required_capabilities: Opaque::from_slice(capabilities)?,
    };
    context.current_binding.tbs.context_core_id = context_core_id(&core)?;
    Ok(())
}

/// Both readings of one edited successor context.
struct Rebuilt {
    /// An endpoint's reconstruction from the Proposal.
    endpoint: Result<ReinitTarget, E2eeError>,
    /// The sequencer's check of the target a sender carrying the edited list
    /// would build.
    carried: Result<CarriedTarget, E2eeError>,
}

/// Applies `edit` to the suite-0x0001 context, recomputes its core (from the
/// binding, or as the reconstruction does with `for_proposal`), and reads the
/// result both ways.
fn rebuilt_with(
    edit: fn(&mut ArcMlsContext) -> TestResult,
    for_proposal: bool,
) -> TestResult<Rebuilt> {
    let mut parts = parts()?;
    let capabilities = part(&parts, REQUIRED_CAPABILITIES_EXTENSION)?;
    let mut context =
        ArcMlsContext::decode_exact(&part(&parts, CONTEXT_EXTENSION)?, &mut budget())?;
    edit(&mut context)?;
    if for_proposal {
        recore_for_proposal(&mut context, &capabilities)?;
    } else {
        recore(&mut context, &capabilities)?;
    }
    for (extension_type, data) in &mut parts {
        if *extension_type == CONTEXT_EXTENSION {
            *data = context.encode()?;
        }
    }
    let extensions = join(&parts)?;
    let proposal = Proposal::of(1)?;
    let mut fields = proposal.fields();
    fields.encoded_extensions = &extensions;
    let endpoint = reconstruct(&fields)?;
    let binding = &context.current_binding.tbs;
    let target = ArcReInitTargetTbs {
        profile_version: 1,
        network_id: network()?,
        old_conversation_id: old_conversation()?,
        new_conversation_id: id("suite-0001-extensions.bin", "new_conversation_id")?,
        target_group_id: Opaque::from_slice(&proposal.group_id)?,
        target_version: 1,
        target_suite: proposal.suite,
        target_context_core_id: binding.context_core_id,
        target_binding_id: semantic_id_of(SemanticHashDomain::BindingId, binding)?,
        initial_member_plan_id: binding.initial_member_plan_id,
        encoded_target_extensions: Opaque::from_slice(&extensions)?,
    };
    let carried = check_carried_target(&network()?, &old_authority()?.0, &target, &mut budget());
    Ok(Rebuilt { endpoint, carried })
}

/// Applies `edit` to the suite-0x0001 context, recomputes its core, and
/// reconstructs the target from the result.
fn rebuilt(
    edit: fn(&mut ArcMlsContext) -> TestResult,
) -> TestResult<Result<ReinitTarget, E2eeError>> {
    Ok(rebuilt_with(edit, false)?.endpoint)
}

fn assert_refused(edits: &[Edit], expected: &E2eeError) -> TestResult {
    for (name, edit) in edits {
        let rebuilt = rebuilt_with(*edit, false)?;
        assert_eq!(rebuilt.endpoint.err().as_ref(), Some(expected), "{name}");
        assert_eq!(
            rebuilt.carried.err().as_ref(),
            Some(expected),
            "{name}, carried"
        );
    }
    Ok(())
}

#[test]
fn the_controls_rebuild_the_recorded_target() -> TestResult {
    let digest = id("suite-0001-target.bin", "target_context_digest")?;
    let unedited = rebuilt(|_| Ok(()))??;
    assert_eq!(
        unedited.digest(),
        &digest,
        "recomputing the core is idempotent"
    );
    let resigned = rebuilt(relink_policy)??;
    assert_eq!(resigned.digest(), &digest, "re-signing is deterministic");
    // The sequencer rebuilds the same target from the carried list alone.
    let both = rebuilt_with(|_| Ok(()), false)?;
    assert_eq!(&both.carried?, both.endpoint?.carried());
    let core = rebuilt_with(|_| Ok(()), true)?;
    assert_eq!(
        core.endpoint?.digest(),
        &digest,
        "the proposal's core is the binding's"
    );
    Ok(())
}

#[test]
fn the_successor_binding_must_name_the_proposal_conversation_and_suite() -> TestResult {
    // The binding, the context and the policy agree on another conversation,
    // or the binding and the policy on another suite, and the binding
    // commits the core the reconstruction recomputes from the Proposal:
    // only the comparison with the Proposal refuses them.
    let edits: [Edit; 2] = [
        ("another conversation", |context| {
            context.conversation_id = [9; 32];
            context.current_binding.tbs.conversation_id = [9; 32];
            edit_policy(context, |policy| policy.conversation_id = [9; 32])
        }),
        ("another suite", |context| {
            context.current_binding.tbs.cipher_suite = 3;
            edit_policy(context, |policy| policy.selected_suite = 3)
        }),
    ];
    for (name, edit) in edits {
        let rebuilt = rebuilt_with(edit, true)?;
        assert_eq!(
            rebuilt.endpoint.err(),
            Some(E2eeError::InvalidValue),
            "{name}"
        );
        assert_eq!(
            rebuilt.carried.err(),
            Some(E2eeError::InvalidValue),
            "{name}, carried"
        );
    }
    Ok(())
}

#[test]
fn the_successor_binding_must_replace_the_old_binding() -> TestResult {
    let edits: [Edit; 6] = [
        ("generation two", |context| {
            context.current_binding.tbs.binding_generation = 2;
            Ok(())
        }),
        ("generation zero", |context| {
            context.current_binding.tbs.binding_generation = 0;
            Ok(())
        }),
        ("another previous binding", |context| {
            context.current_binding.tbs.previous_binding_id = [9; 32];
            Ok(())
        }),
        ("no previous binding", |context| {
            context.current_binding.tbs.previous_binding_id = [0; 32];
            Ok(())
        }),
        ("another semantic route", |context| {
            let network = context.network_id;
            let binding = &mut context.current_binding.tbs;
            binding.semantic_route.canonical_channel_name = Opaque::from_slice(b"#other")?;
            binding.semantic_route_lock_id =
                verify_semantic_route(&network, &binding.semantic_route)?.lock_id;
            Ok(())
        }),
        ("another concrete route", |context| {
            let route = channel_route_binding(&context.network_id, &[9; 16])?;
            let binding = &mut context.current_binding.tbs;
            binding.channel_instance_id = Opaque::from_slice(&[9; 16])?;
            binding.route_binding = route;
            context.route_binding = route;
            Ok(())
        }),
    ];
    assert_refused(&edits, &E2eeError::InvalidValue)?;

    // Each concrete-route field is compared on its own: the route binding
    // alone, the channel instance alone, and a conversation nonce a channel
    // binding does not carry.
    let one_field: [Edit; 3] = [
        ("another route binding", |context| {
            context.current_binding.tbs.route_binding = [9; 32];
            context.route_binding = [9; 32];
            Ok(())
        }),
        ("another channel instance", |context| {
            context.current_binding.tbs.channel_instance_id = Opaque::from_slice(&[9; 16])?;
            Ok(())
        }),
        ("a conversation nonce", |context| {
            context.current_binding.tbs.conversation_nonce = Opaque::from_slice(&[9; 32])?;
            Ok(())
        }),
    ];
    assert_refused(&one_field, &E2eeError::InvalidValue)
}

#[test]
fn the_successor_binding_must_have_the_kind_of_the_route_it_keeps() -> TestResult {
    // The context, the binding and the policy all name the direct kind, so
    // the binding agrees with its context and names its policy, while the
    // binding keeps the old channel's semantic route, lock, channel instance
    // and route binding: only the shape every binding has against the route
    // it carries separates it from the control (companion 9.4 and 13.8).
    let edits: [Edit; 1] = [("the direct kind throughout", |context| {
        context.kind = ArcConversationKind::Direct;
        context.current_binding.tbs.kind = ArcConversationKind::Direct;
        edit_policy(context, |policy| policy.kind = ArcConversationKind::Direct)
    })];
    assert_refused(&edits, &E2eeError::InvalidValue)?;

    // The generator's independent vectors of the same successor: the
    // extension list an endpoint reconstructs from, and the target a sender
    // carrying that list builds, which the sequencer and a later joiner
    // check without the Proposal.
    let list = "reject-extensions-kind-changed.bin";
    let proposal = Proposal {
        group_id: hex(&entry(list, "group_id")?)?,
        suite: entry(list, "cipher_suite")?.parse()?,
        extensions: read(list)?,
    };
    let endpoint = reconstruct(&proposal.fields())?
        .err()
        .ok_or("the endpoint rebuilt a target")?;
    assert_eq!(format!("E2eeError::{endpoint:?}"), entry(list, "expected")?);
    let file = "reject-target-kind-changed.bin";
    let target = ArcReInitTargetTbs::decode_exact(&read(file)?, &mut budget())?;
    assert_eq!(
        semantic_id_of(SemanticHashDomain::ReinitTarget, &target)?,
        id(file, "target_context_digest")?
    );
    assert_eq!(
        target.encoded_target_extensions.as_slice(),
        proposal.extensions.as_slice()
    );
    let carried = check_carried_target(&network()?, &old_authority()?.0, &target, &mut budget())
        .err()
        .ok_or("the sequencer accepted the carried target")?;
    assert_eq!(format!("E2eeError::{carried:?}"), entry(file, "expected")?);
    Ok(())
}

#[test]
fn the_successor_context_meets_every_context_extension_rule() -> TestResult {
    assert_eq!(
        rebuilt(|context| {
            // The lock stays the old one, so the binding still replaces the
            // old binding, but its semantic route no longer hashes to it.
            context
                .current_binding
                .tbs
                .semantic_route
                .canonical_channel_name = Opaque::from_slice(b"#other")?;
            Ok(())
        })?
        .err(),
        Some(E2eeError::InvalidValue),
        "a route lock that is not its route's"
    );
    assert_eq!(
        rebuilt(|context| {
            context.private_topic = Opaque::from_slice(b"topic\x07")?;
            Ok(())
        })?
        .err(),
        Some(E2eeError::InvalidValue),
        "a control code in the private topic"
    );
    assert_eq!(
        rebuilt(|context| {
            let mut heads = context.roster_heads.as_slice().to_vec();
            heads.reverse();
            context.roster_heads = TlsVec::new(heads)?;
            Ok(())
        })?
        .err(),
        Some(E2eeError::NonCanonical),
        "roster heads out of order"
    );
    // A topic without control codes is carried.
    let topic = rebuilt(|context| {
        context.private_topic = Opaque::from_slice(b"topic")?;
        Ok(())
    })??;
    assert_ne!(
        topic.digest(),
        &id("suite-0001-target.bin", "target_context_digest")?
    );
    Ok(())
}

/// The old conversation's operational policy object, decoded.
fn old_operational_policy() -> TestResult<ArcPolicy> {
    let mut budget = budget();
    let object = ArcWireObject::decode_kind(
        &read("policy-operational.bin")?,
        Some(ArcWireObjectKind::Policy),
        &mut budget,
    )?;
    Ok(ArcPolicy::decode_exact(object.body(), &mut budget)?)
}

fn edit_policy(context: &mut ArcMlsContext, edit: fn(&mut ArcPolicyTbs)) -> TestResult {
    edit(&mut context.policy.tbs);
    relink_policy(context)
}

#[test]
fn the_successor_policy_must_be_the_one_its_binding_names() -> TestResult {
    let edits: [Edit; 9] = [
        ("the old conversation's policy", |context| {
            context.policy = old_operational_policy()?;
            relink_policy(context)
        }),
        ("another conversation", |context| {
            edit_policy(context, |policy| policy.conversation_id = [9; 32])
        }),
        ("another network", |context| {
            edit_policy(context, |policy| policy.network_id = [9; 32])
        }),
        ("another profile", |context| {
            edit_policy(context, |policy| policy.profile_version = 2)
        }),
        ("a later generation", |context| {
            edit_policy(context, |policy| {
                policy.policy_generation = 5;
                policy.previous_policy_id = [9; 32];
            })
        }),
        ("a later generation alone", |context| {
            edit_policy(context, |policy| policy.policy_generation = 5)
        }),
        ("a predecessor alone", |context| {
            edit_policy(context, |policy| policy.previous_policy_id = [9; 32])
        }),
        ("another suite", |context| {
            edit_policy(context, |policy| policy.selected_suite = 3)
        }),
        ("another kind", |context| {
            edit_policy(context, |policy| policy.kind = ArcConversationKind::Direct)
        }),
    ];
    assert_refused(&edits, &E2eeError::InvalidValue)?;
    let unlinked: [Edit; 2] = [
        ("another initial policy", |context| {
            context.current_binding.tbs.initial_policy_id = [9; 32];
            Ok(())
        }),
        ("another operational policy", |context| {
            context.current_binding.tbs.required_operational_policy_id = [9; 32];
            Ok(())
        }),
    ];
    assert_refused(&unlinked, &E2eeError::InvalidValue)?;
    // An approval that does not verify is the endpoint's to refuse: the
    // sequencer, which verifies no policy under rosters, rebuilds the target.
    let unverified = rebuilt_with(
        |context| {
            let mut approvals = context.policy.approvals.as_slice().to_vec();
            if let Some(first) = approvals.first_mut() {
                first.device_signature[0] ^= 1;
            }
            context.policy.approvals = TlsVec::new(approvals)?;
            Ok(())
        },
        false,
    )?;
    assert!(
        unverified.endpoint.is_err(),
        "an approval that does not verify"
    );
    assert!(unverified.carried.is_ok(), "carried");
    Ok(())
}

#[test]
fn the_successor_sequencer_credential_must_be_the_one_its_binding_names() -> TestResult {
    let unlinked: [Edit; 2] = [
        ("another validity", |context| {
            context.sequencer.tbs.not_after += 1;
            Ok(())
        }),
        ("another credential ID named", |context| {
            context.current_binding.tbs.sequencer_credential_id = [9; 32];
            Ok(())
        }),
    ];
    assert_refused(&unlinked, &E2eeError::InvalidValue)?;
    let malformed: [Edit; 3] = [
        ("generation zero with a predecessor", |context| {
            context.sequencer.tbs.previous_key_id = [9; 32];
            relink_sequencer(context)
        }),
        ("a later generation without a predecessor", |context| {
            context.sequencer.tbs.key_generation = 1;
            context.sequencer.continuity_signature = Opaque::from_slice(&[7; 64])?;
            relink_sequencer(context)
        }),
        ("an empty validity", |context| {
            context.sequencer.tbs.not_after = context.sequencer.tbs.not_before;
            relink_sequencer(context)
        }),
    ];
    assert_refused(&malformed, &E2eeError::InvalidValue)?;
    assert_eq!(
        rebuilt(|context| {
            context.sequencer.tbs.network_id = [9; 32];
            relink_sequencer(context)
        })?
        .err(),
        Some(E2eeError::ProfileMismatch),
        "another network"
    );
    assert!(
        rebuilt(|context| {
            context.sequencer.tbs.key_generation = 1;
            context.sequencer.tbs.previous_key_id = [9; 32];
            relink_sequencer(context)
        })?
        .is_err(),
        "a later generation without its continuity signature"
    );

    // A successor pinned to a rotated credential, named by its binding, is
    // accepted: the structure a peer can check without its predecessor.
    let rotated = rebuilt(|context| {
        context.sequencer.tbs.key_generation = 1;
        context.sequencer.tbs.previous_key_id = [9; 32];
        context.sequencer.continuity_signature = Opaque::from_slice(&[7; 64])?;
        relink_sequencer(context)
    })??;
    assert_ne!(
        rotated.digest(),
        &id("suite-0001-target.bin", "target_context_digest")?
    );
    Ok(())
}

/// Names the context's sequencer credential by its new ID in the binding.
fn relink_sequencer(context: &mut ArcMlsContext) -> TestResult {
    context.current_binding.tbs.sequencer_credential_id =
        semantic_id_of(SemanticHashDomain::SequencerKey, &context.sequencer.tbs)?;
    Ok(())
}
