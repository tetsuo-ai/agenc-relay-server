#![forbid(unsafe_code)]

//! Route identity and binding validation tests.

use std::error::Error;

use agenc_ircd_crypto::SignatureDomain;

use super::*;
use crate::identity::{verify_root_identity, verify_roster};
use crate::objects::conversation::{
    IrcCloseAuthorization, IrcCloseAuthorizationTbs, IrcCloseIntent, IrcCommitApproval,
    IrcConversationKind,
};
use crate::test_support::*;
use crate::tls::{Opaque, TlsVec};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn channel_names_follow_the_portable_profile() {
    assert_eq!(
        canonical_channel_name(b"#Room.1_x-y+z"),
        Ok(b"#room.1_x-y+z".to_vec())
    );
    assert_eq!(canonical_channel_name(b"#a"), Ok(b"#a".to_vec()));
    let longest = b"#"
        .iter()
        .chain([b'a'; 63].iter())
        .copied()
        .collect::<Vec<u8>>();
    assert_eq!(canonical_channel_name(&longest), Ok(longest.clone()));
    let too_long = b"#"
        .iter()
        .chain([b'a'; 64].iter())
        .copied()
        .collect::<Vec<u8>>();
    assert_eq!(
        canonical_channel_name(&too_long),
        Err(E2eeError::InvalidValue)
    );
    for bad in [
        &b""[..],
        b"#",
        b"room",
        b"#ro om",
        b"&room",
        b"#r\xc3\xa9",
        b"#ro,om",
    ] {
        assert_eq!(
            canonical_channel_name(bad),
            Err(E2eeError::InvalidValue),
            "{bad:?}"
        );
    }
}

#[test]
fn route_bindings_and_semantic_routes_are_shaped_by_kind() -> TestResult {
    let channel = channel_route_binding(&NETWORK, &[1; 16])?;
    assert_ne!(channel, channel_route_binding(&NETWORK, &[2; 16])?);
    let direct = direct_route_binding(&NETWORK, &[3; 32], &ACCOUNT, &OTHER_ACCOUNT)?;
    assert_eq!(
        direct_route_binding(&NETWORK, &[3; 32], &OTHER_ACCOUNT, &ACCOUNT),
        Err(E2eeError::InvalidValue)
    );
    assert_ne!(channel, direct);

    let route = verify_semantic_route(&NETWORK, &channel_route(b"#room", [5; 32])?)?;
    assert_eq!(route.kind, IrcConversationKind::Channel);
    assert!(
        matches!(route.key, SemanticRouteKey::Channel { ref canonical_name, authority_root } if canonical_name == b"#room" && authority_root == [5; 32])
    );
    let direct = verify_semantic_route(&NETWORK, &direct_route(&ACCOUNT, &OTHER_ACCOUNT)?)?;
    assert!(
        matches!(direct.key, SemanticRouteKey::Direct { account_a, account_b } if account_a == ACCOUNT && account_b == OTHER_ACCOUNT)
    );
    assert_ne!(route.lock_id, direct.lock_id);

    let mut uppercase = channel_route(b"#Room", [5; 32])?;
    assert_eq!(
        verify_semantic_route(&NETWORK, &uppercase),
        Err(E2eeError::NonCanonical)
    );
    uppercase.canonical_channel_name = Opaque::from_slice(b"#room")?;
    uppercase.channel_authority_root_fingerprint = [0; 32];
    assert_eq!(
        verify_semantic_route(&NETWORK, &uppercase),
        Err(E2eeError::InvalidValue),
        "a channel needs a pinned authority root"
    );
    let mut swapped = direct_route(&OTHER_ACCOUNT, &ACCOUNT)?;
    assert_eq!(
        verify_semantic_route(&NETWORK, &swapped),
        Err(E2eeError::NonCanonical)
    );
    swapped = direct_route(&ACCOUNT, &OTHER_ACCOUNT)?;
    swapped.canonical_channel_name = Opaque::from_slice(b"#x")?;
    assert_eq!(
        verify_semantic_route(&NETWORK, &swapped),
        Err(E2eeError::InvalidValue)
    );
    let mut incarnation = direct_route(&ACCOUNT, &OTHER_ACCOUNT)?;
    incarnation.semantic_incarnation = 1;
    assert_eq!(
        verify_semantic_route(&NETWORK, &incarnation),
        Err(E2eeError::InvalidValue),
        "incarnation one needs a predecessor close id"
    );
    incarnation.predecessor_close_id = [9; 32];
    assert_eq!(
        verify_semantic_route(&NETWORK, &incarnation)?.incarnation,
        1
    );
    assert_eq!(
        verify_semantic_route(&[2; 32], &incarnation),
        Err(E2eeError::ProfileMismatch)
    );
    Ok(())
}

fn rosters(principals: &[Principal]) -> Result<PrincipalRosters, Box<dyn Error>> {
    let mut map = PrincipalRosters::new();
    for principal in principals {
        let root = verify_root_identity(&NETWORK, &principal.root, None)?;
        let roster = verify_roster(&root, &principal.roster, None)?;
        map.insert(root.account_id, (root, roster));
    }
    Ok(map)
}

fn direct_spec<'a>(principals: &'a [Principal]) -> Result<BindingSpec<'a>, Box<dyn Error>> {
    let fingerprint_a = root_fingerprint(&principals.first().ok_or("principal")?.root)?;
    let fingerprint_b = root_fingerprint(&principals.get(1).ok_or("principal")?.root)?;
    Ok(BindingSpec {
        principals,
        route: direct_route(&ACCOUNT, &OTHER_ACCOUNT)?,
        channel_instance_id: None,
        conversation_nonce: Some([3; 32]),
        group_id: [25; 32],
        generation: 0,
        previous_binding_id: [0; 32],
        lock_sequence: 0,
        plan_devices: vec![
            (&ACCOUNT, fingerprint_a, 7),
            (&OTHER_ACCOUNT, fingerprint_b, 9),
        ],
    })
}

#[test]
fn a_direct_binding_needs_both_principals_unanimously_and_locked() -> TestResult {
    let principals = vec![
        principal(40, &ACCOUNT, &[7, 8])?,
        principal(41, &OTHER_ACCOUNT, &[9])?,
    ];
    let rosters = rosters(&principals)?;
    let package = binding_package(&direct_spec(&principals)?)?;
    let verified = verify_binding_package(&NETWORK, &package, &rosters)?;
    assert_eq!(verified.generation, 0);
    assert_eq!(verified.principals, vec![ACCOUNT, OTHER_ACCOUNT]);
    assert_eq!(verified.locks.len(), 2);
    assert_eq!(verified.conversation_nonce, Some([3; 32]));
    assert_eq!(verified.channel_instance_id, None);
    assert_eq!(verified.group_id, [25; 32]);
    assert_eq!(verified.route.kind, IrcConversationKind::Direct);
    assert_eq!(package.binding.approvals.len(), 3);

    // Dropping one device's approval breaks unanimity.
    let mut partial = package.clone();
    let mut approvals = partial.binding.approvals.as_slice().to_vec();
    approvals.pop();
    partial.binding.approvals = TlsVec::new(approvals)?;
    assert_eq!(
        verify_binding_package(&NETWORK, &partial, &rosters),
        Err(E2eeError::InvalidValue)
    );
    // A forged approval signature.
    let mut forged = package.clone();
    let mut approvals = forged.binding.approvals.as_slice().to_vec();
    if let Some(first) = approvals.first_mut() {
        first.device_signature = [0; 64];
    }
    forged.binding.approvals = TlsVec::new(approvals)?;
    assert_eq!(
        verify_binding_package(&NETWORK, &forged, &rosters),
        Err(E2eeError::SignatureInvalid)
    );
    // Unsorted approvals.
    let mut unsorted = package.clone();
    let mut approvals = unsorted.binding.approvals.as_slice().to_vec();
    approvals.reverse();
    unsorted.binding.approvals = TlsVec::new(approvals)?;
    assert_eq!(
        verify_binding_package(&NETWORK, &unsorted, &rosters),
        Err(E2eeError::NonCanonical)
    );
    // A missing lock.
    let mut unlocked = package.clone();
    let mut locks = unlocked.root_binding_locks.as_slice().to_vec();
    locks.pop();
    unlocked.root_binding_locks = TlsVec::new(locks)?;
    assert_eq!(
        verify_binding_package(&NETWORK, &unlocked, &rosters),
        Err(E2eeError::InvalidValue)
    );
    // A lock signed by the wrong root.
    let mut wrong_lock = package.clone();
    let mut locks = wrong_lock.root_binding_locks.as_slice().to_vec();
    if let Some(first) = locks.first_mut() {
        first.root_signature = sign(&key(42), SignatureDomain::RootBindingLock, &first.tbs)?;
    }
    wrong_lock.root_binding_locks = TlsVec::new(locks)?;
    assert_eq!(
        verify_binding_package(&NETWORK, &wrong_lock, &rosters),
        Err(E2eeError::SignatureInvalid)
    );
    // A tampered TBS field invalidates every approval.
    let mut tampered = package.clone();
    tampered.binding.tbs.cipher_suite = 3;
    assert_eq!(
        verify_binding_package(&NETWORK, &tampered, &rosters),
        Err(E2eeError::SignatureInvalid)
    );
    // A roster the verifier does not hold.
    let mut missing = rosters.clone();
    missing.remove(&OTHER_ACCOUNT);
    assert_eq!(
        verify_binding_package(&NETWORK, &package, &missing),
        Err(E2eeError::InvalidValue)
    );
    Ok(())
}

#[test]
fn binding_shapes_and_concrete_routes_are_checked_exactly() -> TestResult {
    let principals = vec![
        principal(40, &ACCOUNT, &[7])?,
        principal(41, &OTHER_ACCOUNT, &[9])?,
    ];
    let rosters = rosters(&principals)?;
    let base = direct_spec(&principals)?;
    // Channel-shaped concrete fields on a direct route.
    let package = binding_package(&BindingSpec {
        channel_instance_id: Some([1; 16]),
        conversation_nonce: None,
        route: direct_route(&ACCOUNT, &OTHER_ACCOUNT)?,
        plan_devices: base.plan_devices.clone(),
        ..base
    });
    assert!(package.is_err() || verify_binding_package(&NETWORK, &package?, &rosters).is_err());
    // Wrong nonce changes the route binding.
    let good = binding_package(&direct_spec(&principals)?)?;
    let mut wrong_route = good.clone();
    wrong_route.binding.tbs.route_binding = [1; 32];
    assert_eq!(
        verify_binding_package(&NETWORK, &wrong_route, &rosters),
        Err(E2eeError::InvalidValue)
    );
    let mut wrong_conversation = good.clone();
    wrong_conversation.binding.tbs.conversation_id = [1; 32];
    assert_eq!(
        verify_binding_package(&NETWORK, &wrong_conversation, &rosters),
        Err(E2eeError::InvalidValue)
    );
    let mut wrong_lock_id = good.clone();
    wrong_lock_id.binding.tbs.semantic_route_lock_id = [1; 32];
    assert_eq!(
        verify_binding_package(&NETWORK, &wrong_lock_id, &rosters),
        Err(E2eeError::InvalidValue)
    );
    let mut wrong_plan = good.clone();
    wrong_plan.binding.tbs.initial_member_plan_id = [1; 32];
    assert_eq!(
        verify_binding_package(&NETWORK, &wrong_plan, &rosters),
        Err(E2eeError::InvalidValue)
    );
    let mut bad_suite = good.clone();
    bad_suite.binding.tbs.cipher_suite = 4;
    assert_eq!(
        verify_binding_package(&NETWORK, &bad_suite, &rosters),
        Err(E2eeError::ProfileMismatch)
    );
    let mut short_group = good.clone();
    short_group.binding.tbs.group_id = Opaque::new(vec![1; 31])?;
    assert_eq!(
        verify_binding_package(&NETWORK, &short_group, &rosters),
        Err(E2eeError::InvalidValue)
    );
    let mut stale_roster = good;
    let mut principals_field = stale_roster.binding.tbs.principals.as_slice().to_vec();
    if let Some(first) = principals_field.first_mut() {
        first.roster_generation = 1;
    }
    stale_roster.binding.tbs.principals = TlsVec::new(principals_field)?;
    assert_eq!(
        verify_binding_package(&NETWORK, &stale_roster, &rosters),
        Err(E2eeError::InvalidValue)
    );
    Ok(())
}

#[test]
fn channel_bindings_need_the_authority_root_and_replacements_carry_no_proofs() -> TestResult {
    let principals = vec![principal(40, &ACCOUNT, &[7])?];
    let rosters = rosters(&principals)?;
    let authority = root_fingerprint(&principals.first().ok_or("principal")?.root)?;
    let spec = BindingSpec {
        principals: &principals,
        route: channel_route(b"#room", authority)?,
        channel_instance_id: Some([1; 16]),
        conversation_nonce: None,
        group_id: [25; 32],
        generation: 0,
        previous_binding_id: [0; 32],
        lock_sequence: 0,
        plan_devices: vec![(&ACCOUNT, authority, 7)],
    };
    let package = binding_package(&spec)?;
    let verified = verify_binding_package(&NETWORK, &package, &rosters)?;
    assert_eq!(verified.channel_instance_id, Some([1; 16]));
    assert!(matches!(
        verified.route.key,
        SemanticRouteKey::Channel { .. }
    ));
    // An authority root no principal holds.
    let foreign = binding_package(&BindingSpec {
        route: channel_route(b"#room", [9; 32])?,
        plan_devices: vec![(&ACCOUNT, authority, 7)],
        ..spec
    })?;
    assert_eq!(
        verify_binding_package(&NETWORK, &foreign, &rosters),
        Err(E2eeError::InvalidValue)
    );
    // A replacement binding: generation one, empty approvals and locks.
    let replacement = binding_package(&BindingSpec {
        route: channel_route(b"#room", authority)?,
        generation: 1,
        previous_binding_id: verified.binding_id,
        plan_devices: vec![(&ACCOUNT, authority, 7)],
        ..spec
    })?;
    let verified_replacement = verify_binding_package(&NETWORK, &replacement, &rosters)?;
    assert!(is_binding_successor(&verified, &verified_replacement));
    assert!(!is_binding_successor(&verified_replacement, &verified));
    let mut proofs_on_replacement = replacement;
    proofs_on_replacement.root_binding_locks = package.root_binding_locks.clone();
    assert_eq!(
        verify_binding_package(&NETWORK, &proofs_on_replacement, &rosters),
        Err(E2eeError::InvalidValue)
    );
    let mut zero_with_previous = package;
    zero_with_previous.binding.tbs.previous_binding_id = [1; 32];
    assert_eq!(
        verify_binding_package(&NETWORK, &zero_with_previous, &rosters),
        Err(E2eeError::InvalidValue)
    );
    // Next incarnation continuity.
    let mut closed = verified.route.clone();
    closed.incarnation = 0;
    let mut next = closed.clone();
    next.incarnation = 1;
    next.predecessor_close_id = [4; 32];
    assert!(is_next_incarnation(&closed, [4; 32], &next));
    assert!(!is_next_incarnation(&closed, [5; 32], &next));
    Ok(())
}

#[test]
fn initial_member_plans_are_canonical_and_duplicate_free() -> TestResult {
    use crate::objects::conversation::{IrcInitialMemberPlan, IrcInitialMemberPlanEntry};
    let entry = |device: u8, capability: u8| -> Result<IrcInitialMemberPlanEntry, E2eeError> {
        Ok(IrcInitialMemberPlanEntry {
            account_id: account_field(&ACCOUNT)?,
            root_fingerprint: [5; 32],
            device_id: [device; 16],
            capability_id: [capability; 32],
        })
    };
    let good = IrcInitialMemberPlan {
        entries: TlsVec::new(vec![entry(1, 10)?, entry(2, 11)?])?,
    };
    assert!(verify_initial_member_plan(&good).is_ok());
    let unsorted = IrcInitialMemberPlan {
        entries: TlsVec::new(vec![entry(2, 11)?, entry(1, 10)?])?,
    };
    assert_eq!(
        verify_initial_member_plan(&unsorted),
        Err(E2eeError::NonCanonical)
    );
    let mut duplicate_capability = IrcInitialMemberPlan {
        entries: TlsVec::new(vec![entry(1, 10)?, entry(2, 10)?])?,
    };
    assert_eq!(
        verify_initial_member_plan(&duplicate_capability),
        Err(E2eeError::NonCanonical)
    );
    let mut foreign_root = entry(3, 12)?;
    foreign_root.root_fingerprint = [4; 32];
    duplicate_capability.entries = TlsVec::new(vec![foreign_root, entry(3, 13)?])?;
    assert_eq!(
        verify_initial_member_plan(&duplicate_capability),
        Err(E2eeError::NonCanonical),
        "one device id under two roots"
    );
    Ok(())
}

#[test]
fn close_authorization_ids_bind_the_intent() -> TestResult {
    let intent = IrcCloseIntent {
        reason_code: 1,
        validation_time: 9,
    };
    let intent_id = crate::ids::semantic_id_of(
        agenc_ircd_crypto::SemanticHashDomain::CloseIntentId,
        &intent,
    )?;
    let close = IrcCloseAuthorization {
        tbs: IrcCloseAuthorizationTbs {
            profile_version: 1,
            network_id: NETWORK,
            conversation_id: [20; 32],
            binding_id: [34; 32],
            authorizing_terminal_id: [43; 32],
            close_intent: intent,
            close_intent_id: intent_id,
        },
        approvals: TlsVec::new(vec![IrcCommitApproval {
            signer_root_fingerprint: [5; 32],
            signer_device_id: [7; 16],
            signer_device_certificate_id: [21; 32],
            device_signature: [45; 64],
        }])?,
    };
    let close_id = close_authorization_id(&close)?;
    assert_ne!(close_id, intent_id);
    let mut wrong_intent = close.clone();
    wrong_intent.tbs.close_intent_id = [1; 32];
    assert_eq!(
        close_authorization_id(&wrong_intent),
        Err(E2eeError::InvalidValue)
    );
    let mut version = close;
    version.tbs.profile_version = 2;
    assert_eq!(
        close_authorization_id(&version),
        Err(E2eeError::ProfileMismatch)
    );
    assert_ne!(channel_name_hash(b"#a")?, channel_name_hash(b"#b")?);
    Ok(())
}

#[path = "route/fences.rs"]
mod fences;

#[test]
fn binding_shape_pins_approvals_and_locks_are_checked_field_by_field() -> TestResult {
    let principals = vec![
        principal(40, &ACCOUNT, &[7])?,
        principal(41, &OTHER_ACCOUNT, &[9])?,
    ];
    let rosters = rosters(&principals)?;
    let good = binding_package(&direct_spec(&principals)?)?;
    let verify = |package: &crate::objects::conversation::IrcConversationBindingPackage| {
        verify_binding_package(&NETWORK, package, &rosters).err()
    };
    let mut profile = good.clone();
    profile.binding.tbs.profile_version = 2;
    assert_eq!(verify(&profile), Some(E2eeError::ProfileMismatch));
    let mut network = good.clone();
    network.binding.tbs.network_id = [9; 32];
    assert_eq!(verify(&network), Some(E2eeError::ProfileMismatch));
    let mut mls = good.clone();
    mls.binding.tbs.mls_version = 2;
    assert_eq!(verify(&mls), Some(E2eeError::ProfileMismatch));
    let mut kind = good.clone();
    kind.binding.tbs.kind = IrcConversationKind::Channel;
    assert_eq!(verify(&kind), Some(E2eeError::InvalidValue));
    let mut core = good.clone();
    core.binding.tbs.context_core_id = [0; 32];
    assert_eq!(verify(&core), Some(E2eeError::InvalidValue));
    let mut sequencer = good.clone();
    sequencer.binding.tbs.sequencer_credential_id = [0; 32];
    assert_eq!(verify(&sequencer), Some(E2eeError::InvalidValue));

    let mut wrong_root = good.clone();
    let mut pins = wrong_root.binding.tbs.principals.as_slice().to_vec();
    if let Some(first) = pins.first_mut() {
        first.root_fingerprint = [9; 32];
    }
    wrong_root.binding.tbs.principals = TlsVec::new(pins)?;
    assert_eq!(verify(&wrong_root), Some(E2eeError::InvalidValue));
    let mut wrong_roster = good.clone();
    let mut pins = wrong_roster.binding.tbs.principals.as_slice().to_vec();
    if let Some(first) = pins.first_mut() {
        first.roster_id = [9; 32];
    }
    wrong_roster.binding.tbs.principals = TlsVec::new(pins)?;
    assert_eq!(verify(&wrong_roster), Some(E2eeError::InvalidValue));

    let mut wrong_certificate = good.clone();
    let mut approvals = wrong_certificate.binding.approvals.as_slice().to_vec();
    if let Some(first) = approvals.first_mut() {
        first.signer_device_certificate_id = [9; 32];
    }
    wrong_certificate.binding.approvals = TlsVec::new(approvals)?;
    assert_eq!(verify(&wrong_certificate), Some(E2eeError::InvalidValue));

    type Corrupt = fn(&mut crate::objects::conversation::IrcRootBindingLockTbs);
    let corruptions: [Corrupt; 7] = [
        |lock| lock.profile_version = 2,
        |lock| lock.network_id = [9; 32],
        |lock| lock.root_fingerprint = [9; 32],
        |lock| lock.semantic_route_lock_id = [9; 32],
        |lock| lock.binding_id = [9; 32],
        |lock| lock.roster_generation = 5,
        |lock| lock.roster_id = [9; 32],
    ];
    for corrupt in corruptions {
        let mut package = good.clone();
        let mut locks = package.root_binding_locks.as_slice().to_vec();
        if let Some(first) = locks.first_mut() {
            corrupt(&mut first.tbs);
        }
        package.root_binding_locks = TlsVec::new(locks)?;
        assert_eq!(verify(&package), Some(E2eeError::InvalidValue));
    }
    Ok(())
}

#[test]
fn a_direct_binding_names_exactly_the_route_principals() -> TestResult {
    let principals = vec![
        principal(40, &ACCOUNT, &[7])?,
        principal(41, &OTHER_ACCOUNT, &[9])?,
    ];
    let rosters = rosters(&principals)?;
    let third: [u8; 24] = [b'c'; 24];
    let spec = BindingSpec {
        route: direct_route(&ACCOUNT, &third)?,
        ..direct_spec(&principals)?
    };
    let package = binding_package(&spec);
    assert!(package.is_err() || verify_binding_package(&NETWORK, &package?, &rosters).is_err());
    Ok(())
}

#[test]
fn successor_and_incarnation_rules_check_each_field() -> TestResult {
    let principals = vec![
        principal(40, &ACCOUNT, &[7])?,
        principal(41, &OTHER_ACCOUNT, &[9])?,
    ];
    let rosters = rosters(&principals)?;
    let current = verify_binding_package(
        &NETWORK,
        &binding_package(&direct_spec(&principals)?)?,
        &rosters,
    )?;
    let successor_spec = BindingSpec {
        generation: 1,
        previous_binding_id: current.binding_id,
        ..direct_spec(&principals)?
    };
    let successor = verify_binding_package(&NETWORK, &binding_package(&successor_spec)?, &rosters)?;
    assert!(is_binding_successor(&current, &successor));
    let mut wrong_previous = successor.clone();
    wrong_previous.previous_binding_id = [1; 32];
    assert!(!is_binding_successor(&current, &wrong_previous));
    let mut other_lock = successor.clone();
    other_lock.route.lock_id = [1; 32];
    assert!(!is_binding_successor(&current, &other_lock));

    let closed = verify_semantic_route(&NETWORK, &direct_route(&ACCOUNT, &OTHER_ACCOUNT)?)?;
    let mut next = closed.clone();
    next.incarnation = 1;
    next.predecessor_close_id = [5; 32];
    assert!(is_next_incarnation(&closed, [5; 32], &next));
    let mut other_key = verify_semantic_route(&NETWORK, &channel_route(b"#room", [4; 32])?)?;
    other_key.incarnation = 1;
    other_key.predecessor_close_id = [5; 32];
    assert!(!is_next_incarnation(&closed, [5; 32], &other_key));
    let mut skipped = next.clone();
    skipped.incarnation = 2;
    assert!(!is_next_incarnation(&closed, [5; 32], &skipped));
    Ok(())
}

/// A principal whose roster holds `certificates` in place of the default ones.
fn with_devices(
    mut principal: Principal,
    certificates: Vec<crate::objects::identity::IrcDeviceCertificate>,
) -> Result<Principal, Box<dyn Error>> {
    principal.roster = roster(
        &principal.root_secret,
        &principal.root,
        0,
        [0; 32],
        (100, 100 + 6 * 24 * 3600),
        certificates,
        Vec::new(),
    )?;
    Ok(principal)
}

fn channel_spec<'a>(
    principals: &'a [Principal],
    device: u8,
) -> Result<BindingSpec<'a>, Box<dyn Error>> {
    let authority = root_fingerprint(&principals.first().ok_or("principal")?.root)?;
    Ok(BindingSpec {
        principals,
        route: channel_route(b"#room", authority)?,
        channel_instance_id: Some([1; 16]),
        conversation_nonce: None,
        group_id: [25; 32],
        generation: 0,
        previous_binding_id: [0; 32],
        lock_sequence: 0,
        plan_devices: vec![(&ACCOUNT, authority, device)],
    })
}

#[test]
fn a_binding_needs_a_device_that_may_bind_and_refuses_approvals_from_others() -> TestResult {
    // A sole principal whose only device lacks binding authority.
    let limited = principal(42, &ACCOUNT, &[11])?;
    let observer = certificate(
        &limited.root_secret,
        &limited.root,
        &DeviceSpec {
            flags: 2,
            ..DeviceSpec::new(11)
        },
    )?;
    let principals = vec![with_devices(limited, vec![observer])?];
    let sole = rosters(&principals)?;
    let package = binding_package(&channel_spec(&principals, 11)?)?;
    assert_eq!(
        verify_binding_package(&NETWORK, &package, &sole),
        Err(E2eeError::InvalidValue),
        "no device may bind"
    );
    // A principal with one binding device and one observer: the observer's
    // approval is refused, and without it the package is complete.
    let mixed = principal(40, &ACCOUNT, &[7, 8])?;
    let binder = certificate(&mixed.root_secret, &mixed.root, &DeviceSpec::new(7))?;
    let observer = certificate(
        &mixed.root_secret,
        &mixed.root,
        &DeviceSpec {
            flags: 2,
            ..DeviceSpec::new(8)
        },
    )?;
    let principals = vec![with_devices(mixed, vec![binder, observer])?];
    let mixed_rosters = rosters(&principals)?;
    let package = binding_package(&channel_spec(&principals, 7)?)?;
    assert_eq!(
        verify_binding_package(&NETWORK, &package, &mixed_rosters),
        Err(E2eeError::InvalidValue),
        "an approval from a device that may not bind"
    );
    let mut honest = package;
    let approvals: Vec<_> = honest
        .binding
        .approvals
        .as_slice()
        .iter()
        .filter(|approval| approval.signer_device_id != [8; 16])
        .cloned()
        .collect();
    honest.binding.approvals = TlsVec::new(approvals)?;
    assert!(verify_binding_package(&NETWORK, &honest, &mixed_rosters).is_ok());
    Ok(())
}
