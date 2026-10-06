#![forbid(unsafe_code)]

//! The MLS context extension and the context core.

use std::error::Error;

use super::*;
use crate::ids::{account_id_digest, conversation_id};
use crate::objects::conversation::{
    ArcConversationLifecycle, ArcConversationLifecycleKind, ArcMlsContext, ArcPendingJoin,
    ArcRosterHead,
};
use crate::route::verify_binding_package;
use crate::test_support::*;
use crate::tls::{Opaque, TlsVec};

type TestResult = Result<(), Box<dyn Error>>;

const GROUP: [u8; 32] = [25; 32];

fn channel_principals() -> Result<Vec<Principal>, E2eeError> {
    Ok(vec![
        principal(40, &ACCOUNT, &[7])?,
        principal(41, &OTHER_ACCOUNT, &[9])?,
    ])
}

fn channel_spec(principals: &[Principal]) -> Result<BindingSpec<'_>, Box<dyn Error>> {
    let first = principals.first().ok_or("principal")?;
    let second = principals.get(1).ok_or("principal")?;
    Ok(BindingSpec {
        principals,
        route: channel_route(b"#room", root_fingerprint(&first.root)?)?,
        channel_instance_id: Some([1; 16]),
        conversation_nonce: None,
        group_id: GROUP,
        generation: 0,
        previous_binding_id: [0; 32],
        lock_sequence: 0,
        plan_devices: vec![
            (&ACCOUNT, root_fingerprint(&first.root)?, 7),
            (&OTHER_ACCOUNT, root_fingerprint(&second.root)?, 9),
        ],
    })
}

fn roster_heads(principals: &[Principal]) -> Result<Vec<ArcRosterHead>, E2eeError> {
    let mut heads = principals
        .iter()
        .map(|principal| {
            Ok(ArcRosterHead {
                account_id_digest: account_id_digest(
                    &NETWORK,
                    principal.root.tbs.account_id.as_slice(),
                )?,
                root_generation: 0,
                root_fingerprint: root_fingerprint(&principal.root)?,
                roster_generation: 0,
                roster_id: roster_id(&principal.roster)?,
            })
        })
        .collect::<Result<Vec<_>, E2eeError>>()?;
    heads.sort_by_key(|head| {
        (
            head.account_id_digest,
            head.root_generation,
            head.root_fingerprint,
        )
    });
    Ok(heads)
}

fn context(principals: &[Principal]) -> Result<ArcMlsContext, Box<dyn Error>> {
    let id = conversation_id(&NETWORK, &GROUP)?;
    let package = binding_package(&channel_spec(principals)?)?;
    Ok(ArcMlsContext {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: id,
        kind: ArcConversationKind::Channel,
        route_binding: package.binding.tbs.route_binding,
        initial_validation_time: 100,
        policy: policy(&PolicySpec::moderated(principals, id))?,
        sequencer: sequencer_credential(&key(60), 0, (0, 1_000_000), None)?,
        current_binding: package.binding,
        lifecycle: ArcConversationLifecycle {
            kind: ArcConversationLifecycleKind::ActiveConversation,
            close_intent_id: [0; 32],
        },
        private_topic: Opaque::from_slice("caf\u{e9} talk".as_bytes())?,
        bootstrap_pending: 0,
        roster_heads: TlsVec::new(roster_heads(principals)?)?,
        pending_joins: TlsVec::new(Vec::new())?,
    })
}

#[test]
fn a_context_verifies_and_reports_its_state() -> TestResult {
    let principals = channel_principals()?;
    let rosters = principal_rosters(&principals)?;
    let context = context(&principals)?;
    let verified = verify_context(&NETWORK, &context, &rosters, None, None)?;
    assert_eq!(verified.kind, ArcConversationKind::Channel);
    assert_eq!(verified.close_intent_id, None);
    assert!(!verified.bootstrap_pending);
    assert_eq!(verified.roster_heads.len(), 2);
    assert_eq!(verified.pending_join, None);
    assert_eq!(verified.private_topic, "caf\u{e9} talk".as_bytes());
    assert_eq!(verified.policy.generation, 0);
    assert_eq!(verified.sequencer.generation, 0);
    assert_eq!(
        verified.binding_id,
        semantic_id_of(SemanticHashDomain::BindingId, &context.current_binding.tbs)?
    );
    let again = verify_context(&NETWORK, &context, &rosters, None, None)?;
    assert_eq!(again.context_digest, verified.context_digest);
    let mut closing = context.clone();
    closing.lifecycle = ArcConversationLifecycle {
        kind: ArcConversationLifecycleKind::ClosingConversation,
        close_intent_id: [5; 32],
    };
    closing.pending_joins = TlsVec::new(vec![ArcPendingJoin {
        leaf_index: 3,
        key_package_ref: Opaque::new(vec![4; 32])?,
    }])?;
    closing.bootstrap_pending = 1;
    let verified_closing = verify_context(&NETWORK, &closing, &rosters, None, None)?;
    assert_eq!(verified_closing.close_intent_id, Some([5; 32]));
    assert!(verified_closing.bootstrap_pending);
    assert_eq!(
        verified_closing.pending_join.map(|join| join.leaf_index),
        Some(3)
    );
    assert_ne!(verified_closing.context_digest, verified.context_digest);
    Ok(())
}

#[test]
fn every_context_rule_has_a_negative() -> TestResult {
    let principals = channel_principals()?;
    let rosters = principal_rosters(&principals)?;
    let good = context(&principals)?;
    let verify = |context: &ArcMlsContext| {
        verify_context(&NETWORK, context, &rosters, None, None).map(|_| ())
    };
    let mut wrong_profile = good.clone();
    wrong_profile.profile_version = 2;
    assert_eq!(verify(&wrong_profile), Err(E2eeError::ProfileMismatch));
    assert_eq!(
        verify_context(&[2; 32], &good, &rosters, None, None).map(|_| ()),
        Err(E2eeError::ProfileMismatch)
    );
    let mut closing_without_intent = good.clone();
    closing_without_intent.lifecycle.kind = ArcConversationLifecycleKind::ClosingConversation;
    assert_eq!(
        verify(&closing_without_intent),
        Err(E2eeError::InvalidValue)
    );
    let mut active_with_intent = good.clone();
    active_with_intent.lifecycle.close_intent_id = [5; 32];
    assert_eq!(verify(&active_with_intent), Err(E2eeError::InvalidValue));
    let mut control_topic = good.clone();
    control_topic.private_topic = Opaque::from_slice(b"a\x01b")?;
    assert_eq!(verify(&control_topic), Err(E2eeError::InvalidValue));
    let mut bidi_topic = good.clone();
    bidi_topic.private_topic = Opaque::from_slice("a\u{202e}b".as_bytes())?;
    assert_eq!(verify(&bidi_topic), Err(E2eeError::InvalidValue));
    let mut malformed_topic = good.clone();
    malformed_topic.private_topic = Opaque::from_slice(&[0xff, 0xfe])?;
    assert_eq!(verify(&malformed_topic), Err(E2eeError::InvalidValue));
    let mut bad_flag = good.clone();
    bad_flag.bootstrap_pending = 2;
    assert_eq!(verify(&bad_flag), Err(E2eeError::InvalidValue));
    let mut unsorted = good.clone();
    let mut heads = unsorted.roster_heads.as_slice().to_vec();
    heads.reverse();
    unsorted.roster_heads = TlsVec::new(heads)?;
    assert_eq!(verify(&unsorted), Err(E2eeError::NonCanonical));
    let mut two_joins = good.clone();
    let join = ArcPendingJoin {
        leaf_index: 3,
        key_package_ref: Opaque::new(vec![4; 32])?,
    };
    two_joins.pending_joins = TlsVec::new(vec![join.clone(), join])?;
    assert_eq!(verify(&two_joins), Err(E2eeError::InvalidValue));
    let mut wrong_route = good.clone();
    wrong_route.route_binding = [9; 32];
    assert_eq!(verify(&wrong_route), Err(E2eeError::InvalidValue));
    let mut wrong_conversation = good.clone();
    wrong_conversation.conversation_id = [9; 32];
    assert_ne!(verify(&wrong_conversation), Ok(()));
    let mut wrong_kind = good.clone();
    wrong_kind.kind = ArcConversationKind::Direct;
    wrong_kind.private_topic = Opaque::new(Vec::new())?;
    assert_eq!(verify(&wrong_kind), Err(E2eeError::InvalidValue));
    let mut later_generation = good;
    later_generation.policy.tbs.policy_generation = 1;
    assert_eq!(verify(&later_generation), Err(E2eeError::InvalidValue));
    Ok(())
}

#[test]
fn the_private_topic_rules_are_closed() -> TestResult {
    assert_eq!(
        check_private_topic(ArcConversationKind::Channel, b""),
        Ok(())
    );
    assert_eq!(
        check_private_topic(
            ArcConversationKind::Channel,
            "plain \u{1f600} text".as_bytes()
        ),
        Ok(())
    );
    assert_eq!(
        check_private_topic(ArcConversationKind::Direct, b"x"),
        Err(E2eeError::InvalidValue)
    );
    assert_eq!(
        check_private_topic(ArcConversationKind::Channel, &[b'a'; 4_096]),
        Ok(())
    );
    assert_eq!(
        check_private_topic(ArcConversationKind::Channel, &[b'a'; 4_097]),
        Err(E2eeError::LimitExceeded)
    );
    assert_eq!(
        check_private_topic(ArcConversationKind::Channel, b"tab\there"),
        Err(E2eeError::InvalidValue)
    );
    assert_eq!(
        check_private_topic(ArcConversationKind::Channel, "del\u{7f}".as_bytes()),
        Err(E2eeError::InvalidValue)
    );
    assert_eq!(
        check_private_topic(ArcConversationKind::Channel, "c1\u{85}".as_bytes()),
        Err(E2eeError::InvalidValue)
    );
    assert_eq!(
        check_private_topic(ArcConversationKind::Channel, "iso\u{2066}late".as_bytes()),
        Err(E2eeError::InvalidValue)
    );
    Ok(())
}

#[test]
fn the_context_core_seals_the_binding() -> TestResult {
    let principals = channel_principals()?;
    let rosters = principal_rosters(&principals)?;
    let package = binding_package(&channel_spec(&principals)?)?;
    let mut binding = verify_binding_package(&NETWORK, &package, &rosters)?;
    let core = ArcContextCoreTbs {
        profile_version: 1,
        mls_version: 1,
        cipher_suite: 1,
        group_id: Opaque::new(GROUP.to_vec())?,
        network_id: NETWORK,
        conversation_id: binding.conversation_id,
        kind: ArcConversationKind::Channel,
        semantic_route_lock_id: binding.route.lock_id,
        route_binding: binding.route_binding,
        initial_validation_time: 100,
        initial_policy_id: [27; 32],
        required_operational_policy_id: [28; 32],
        initial_bootstrap_pending: 1,
        initial_member_plan_id: binding.initial_member_plan_id,
        sequencer_credential_id: binding.sequencer_credential_id,
        encoded_required_capabilities: Opaque::new(vec![0, 1])?,
    };
    let id = context_core_id(&core)?;
    assert_eq!(
        verify_context_core(&NETWORK, &core, &binding),
        Err(E2eeError::InvalidValue),
        "the carried core identifier must match"
    );
    binding.context_core_id = id;
    assert_eq!(verify_context_core(&NETWORK, &core, &binding), Ok(id));
    let mut other_suite = core.clone();
    other_suite.cipher_suite = 3;
    assert_eq!(
        verify_context_core(&NETWORK, &other_suite, &binding),
        Err(E2eeError::InvalidValue)
    );
    let mut not_pending = core.clone();
    not_pending.initial_bootstrap_pending = 0;
    assert_eq!(
        verify_context_core(&NETWORK, &not_pending, &binding),
        Err(E2eeError::InvalidValue)
    );
    let mut bad_flag = core.clone();
    bad_flag.initial_bootstrap_pending = 7;
    assert_eq!(
        verify_context_core(&NETWORK, &bad_flag, &binding),
        Err(E2eeError::InvalidValue)
    );
    let mut wrong_group = core;
    wrong_group.group_id = Opaque::new(vec![1; 32])?;
    assert_eq!(
        verify_context_core(&NETWORK, &wrong_group, &binding),
        Err(E2eeError::InvalidValue)
    );
    Ok(())
}

/// The context's sequencer continues `previous_sequencer` through the shared
/// credential chain, so a successor that reuses its predecessor's public key
/// is refused here too (companion 9.2.1), while one with a fresh key
/// verifies.
#[test]
fn a_context_sequencer_successor_needs_a_fresh_key() -> TestResult {
    let principals = channel_principals()?;
    let rosters = principal_rosters(&principals)?;
    let mut context = context(&principals)?;
    let first_secret = key(60);
    let first = context.sequencer.clone();
    let previous = verify_sequencer_credential(&NETWORK, &first, None)?;
    let successor = |secret: &agenc_relay_crypto::Ed25519SecretKey| {
        sequencer_credential(secret, 1, (500, 2_000_000), Some((&first_secret, &first)))
    };
    context.sequencer = successor(&key(61))?;
    let verified = verify_context(&NETWORK, &context, &rosters, None, Some(&previous))?;
    assert_eq!(verified.sequencer.generation, 1);
    context.sequencer = successor(&first_secret)?;
    assert_eq!(
        verify_context(&NETWORK, &context, &rosters, None, Some(&previous)).map(|_| ()),
        Err(E2eeError::InvalidValue)
    );
    Ok(())
}
