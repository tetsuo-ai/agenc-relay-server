//! Startup route reconstruction refuses malformed targets, colliding
//! successors, unanchored successors, and votes it cannot tie to a roster.
#![forbid(unsafe_code)]

use super::super::tests::support::{
    BindingSpec, NETWORK, Principal, binding_package, channel_route, finality_vote, principal,
    root_fingerprint,
};
use super::*;
use agenc_relay_e2ee::objects::federation::ArcRouteStateKind;
use agenc_relay_e2ee::objects::sequencing::ArcDispositionVoteTbs;
use agenc_relay_e2ee::tls::{Opaque, TlsEncode};
use agenc_relay_storage::e2ee_records::DeliveryGrant;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const DEVICE: u8 = 7;
const ACCOUNT_A: [u8; 24] = *b"aaaaaaaaaaaaaaaaaaaaaaaa";
const ACCOUNT_B: [u8; 24] = *b"bbbbbbbbbbbbbbbbbbbbbbbb";
const OLD: [u8; 32] = [0x10; 32];
const NEW: [u8; 32] = [0x20; 32];

fn route_state(
    kind: ArcConversationKind,
    instance: &[u8],
    accounts: (&[u8], &[u8]),
) -> TestResult<ArcFederationRouteState> {
    Ok(ArcFederationRouteState {
        profile_version: 1,
        network_id: NETWORK,
        state_generation: 1,
        conversation_id: OLD,
        conversation_kind: kind,
        route_binding: [1; 32],
        semantic_route_lock_id: [2; 32],
        channel_instance_id: Opaque::new(instance.to_vec())?,
        canonical_channel_name_hash: [3; 32],
        direct_account_a: Opaque::new(accounts.0.to_vec())?,
        direct_account_b: Opaque::new(accounts.1.to_vec())?,
        binding_id: [4; 32],
        finalized_epoch: 0,
        accepted_state_id: [5; 32],
        sequencer_record_head_sequence: 0,
        sequencer_record_head_id: [5; 32],
        state: ArcRouteStateKind::ActiveRoute,
    })
}

fn account_text(seed: u8) -> TestResult<[u8; 24]> {
    let id = AccountId::from_random(agenc_relay_types::AccountRandomId::from_bytes([seed; 16]));
    Ok(id.to_text().as_bytes().try_into()?)
}

#[test]
fn channel_route_target_needs_a_sixteen_byte_instance() -> TestResult {
    let route = route_state(ArcConversationKind::Channel, &[8; 16], (&[], &[]))?;
    assert_eq!(
        route_target(&route),
        Some(RouteTarget::Channel(ChannelInstanceId::from_bytes([8; 16])))
    );
    let route = route_state(ArcConversationKind::Channel, &[], (&[], &[]))?;
    assert_eq!(route_target(&route), None);
    Ok(())
}

#[test]
fn direct_route_target_needs_two_distinct_valid_accounts() -> TestResult {
    let (first, second) = (account_text(1)?, account_text(2)?);
    let route = route_state(ArcConversationKind::Direct, &[], (&first, &second))?;
    assert!(matches!(route_target(&route), Some(RouteTarget::Direct(_))));
    let same = route_state(ArcConversationKind::Direct, &[], (&first, &first))?;
    assert_eq!(route_target(&same), None);
    let missing = route_state(ArcConversationKind::Direct, &[], (&first, &[]))?;
    assert_eq!(route_target(&missing), None);
    let absent = route_state(ArcConversationKind::Direct, &[], (&[], &second))?;
    assert_eq!(route_target(&absent), None);
    Ok(())
}

#[test]
fn direct_route_target_refuses_account_bytes_that_are_not_an_account_id() -> TestResult {
    let valid = account_text(1)?;
    let route = route_state(ArcConversationKind::Direct, &[], (&[b'!'; 24], &valid))?;
    assert_eq!(route_target(&route), None);
    let route = route_state(ArcConversationKind::Direct, &[], (&valid, &[b'!'; 24]))?;
    assert_eq!(route_target(&route), None);
    Ok(())
}

fn bare_route_row(lifecycle: RowLifecycle, close_id: Option<[u8; 32]>) -> RouteRow {
    RouteRow {
        route_state: Vec::new(),
        lifecycle,
        binding_id: [1; 32],
        lock_id: [2; 32],
        accepted_state_id: [3; 32],
        sequencer_head_id: [4; 32],
        route_sequence: 0,
        close_id,
        predecessor_close_id: None,
        recovery_gate: false,
        stored_bytes: 0,
        sequencer_credential_id: None,
        blocked_credential_id: None,
    }
}

#[test]
fn tombstone_without_a_close_id_falls_back_to_the_sequencer_head() {
    assert_eq!(
        route_lifecycle(&bare_route_row(RowLifecycle::Tombstone, None)),
        RouteLifecycle::Tombstone { close_id: [4; 32] }
    );
    assert_eq!(
        route_lifecycle(&bare_route_row(RowLifecycle::Tombstone, Some([9; 32]))),
        RouteLifecycle::Tombstone { close_id: [9; 32] }
    );
    assert_eq!(
        route_lifecycle(&bare_route_row(RowLifecycle::Closing, Some([9; 32]))),
        RouteLifecycle::Closing
    );
    assert_eq!(
        route_lifecycle(&bare_route_row(RowLifecycle::Active, None)),
        RouteLifecycle::Active
    );
}

#[test]
fn log_phase_without_a_reinit_head_record_follows_the_close_id() -> TestResult {
    let state = CompanionState::default();
    let records = BTreeMap::new();
    let open = restore_log_phase(
        &state,
        OLD,
        &bare_route_row(RowLifecycle::Active, None),
        &records,
    )
    .ok_or("open phase")?;
    assert_eq!(open.phase, Phase::Open);
    let closed = restore_log_phase(
        &state,
        OLD,
        &bare_route_row(RowLifecycle::Closing, Some([9; 32])),
        &records,
    )
    .ok_or("closed phase")?;
    assert_eq!(closed.phase, Phase::Closed { close_id: [9; 32] });
    assert!(closed.attempt.is_none());
    Ok(())
}

#[test]
fn log_phase_refuses_a_reinit_head_whose_record_object_is_not_retained() {
    let state = CompanionState::default();
    let head = RecordRow {
        record_object_id: [7; 32],
        record_id: [4; 32],
        record_kind: REINIT_ATTEMPT_RECORD,
        terminal: false,
        predecessor_record_id: [0; 32],
    };
    let records = BTreeMap::from([(0_u64, &head)]);
    let row = bare_route_row(RowLifecycle::Active, None);
    assert!(restore_log_phase(&state, OLD, &row, &records).is_none());
}

// ---------------------------------------------------------------------------
// Successor anchors.

fn migrated_log(old: [u8; 32], new: [u8; 32]) -> SequencerLog {
    SequencerLog::restore(
        old,
        Head {
            sequence: 3,
            record_id: [0x33; 32],
            recorded: true,
        },
        [0x44; 32],
        2,
        Phase::Migrated {
            activation_id: [0x33; 32],
            new_conversation_id: new,
        },
    )
}

#[test]
fn an_activation_without_a_successor_route_anchors_the_successor_log() -> TestResult {
    let mut state = CompanionState::default();
    state.logs.insert(OLD, migrated_log(OLD, NEW));
    restore_successors(&mut state, &ObjectIndex::default())?;
    let anchored = state.logs.get(&NEW).ok_or("successor log")?;
    assert_eq!(anchored.accepted_epoch(), 1);
    assert_eq!(anchored.head().record_id, [0x33; 32]);
    assert!(!anchored.head().recorded);
    assert!(state.lifecycles.contains_key(&NEW));
    Ok(())
}

#[test]
fn two_activations_naming_distinct_successors_anchor_both() -> TestResult {
    let mut state = CompanionState::default();
    state.logs.insert(OLD, migrated_log(OLD, NEW));
    state
        .logs
        .insert([0x11; 32], migrated_log([0x11; 32], [0x21; 32]));
    restore_successors(&mut state, &ObjectIndex::default())?;
    assert!(state.logs.contains_key(&NEW));
    assert!(state.logs.contains_key(&[0x21; 32]));
    Ok(())
}

#[test]
fn two_activations_naming_one_successor_fail_startup() {
    let mut state = CompanionState::default();
    state.logs.insert(OLD, migrated_log(OLD, NEW));
    state.logs.insert([0x11; 32], migrated_log([0x11; 32], NEW));
    assert_eq!(
        restore_successors(&mut state, &ObjectIndex::default()),
        Err(super::super::CompanionFault::Storage)
    );
}

#[test]
fn a_successor_log_without_a_conversation_fails_startup() {
    let mut state = CompanionState::default();
    state.logs.insert(OLD, migrated_log(OLD, NEW));
    state
        .logs
        .insert(NEW, SequencerLog::from_activation(NEW, [0x33; 32]));
    assert_eq!(
        restore_successors(&mut state, &ObjectIndex::default()),
        Err(super::super::CompanionFault::Storage)
    );
}

#[test]
fn a_successor_lifecycle_without_a_conversation_fails_startup() {
    let mut state = CompanionState::default();
    state.logs.insert(OLD, migrated_log(OLD, NEW));
    state.lifecycles.insert(NEW, Lifecycle::successor());
    assert_eq!(
        restore_successors(&mut state, &ObjectIndex::default()),
        Err(super::super::CompanionFault::Storage)
    );
}

#[test]
fn a_successor_route_without_a_conversation_fails_startup() {
    let mut state = CompanionState::default();
    state.logs.insert(OLD, migrated_log(OLD, NEW));
    state.routes.restore_entry(RouteEntry {
        conversation_id: ConversationId(NEW),
        target: RouteTarget::Channel(ChannelInstanceId::from_bytes([8; 16])),
        lock: SemanticLockId([2; 32]),
        incarnation: 0,
        binding_id: [1; 32],
        binding_generation: 1,
        lifecycle: RouteLifecycle::Active,
        recovery: RecoveryState::Normal,
    });
    assert_eq!(
        restore_successors(&mut state, &ObjectIndex::default()),
        Err(super::super::CompanionFault::Storage)
    );
}

#[test]
fn a_successor_conversation_without_a_retained_activation_fails_startup() {
    let mut state = CompanionState::default();
    state.logs.insert(OLD, migrated_log(OLD, NEW));
    state
        .conversations
        .insert(NEW, ConversationState::default());
    assert_eq!(
        restore_successors(&mut state, &ObjectIndex::default()),
        Err(super::super::CompanionFault::Storage)
    );
}

fn package(
    principal: &Principal,
    conversation: [u8; 32],
    generation: u64,
    previous: [u8; 32],
) -> TestResult<ArcConversationBindingPackage> {
    let fingerprint = root_fingerprint(&principal.root)?;
    let mut package = binding_package(&BindingSpec {
        principals: std::slice::from_ref(principal),
        route: channel_route(b"#room", fingerprint)?,
        channel_instance_id: Some([8; 16]),
        conversation_nonce: None,
        group_id: [33; 32],
        generation: 0,
        previous_binding_id: [0; 32],
        lock_sequence: 0,
        plan_devices: vec![(&ACCOUNT_A, fingerprint, DEVICE)],
        initial_policy_id: [1; 32],
        required_operational_policy_id: [2; 32],
        sequencer_credential_id: [3; 32],
    })?;
    // The anchoring pass reads only these three facts and never re-verifies.
    package.binding.tbs.conversation_id = conversation;
    package.binding.tbs.binding_generation = generation;
    package.binding.tbs.previous_binding_id = previous;
    Ok(package)
}

/// A state with one conversation per `(conversation, binding)` pair.
fn conversations(pairs: &[([u8; 32], [u8; 32])]) -> CompanionState {
    let mut state = CompanionState::default();
    for (conversation, binding) in pairs {
        state.conversations.insert(
            *conversation,
            ConversationState {
                binding: *binding,
                ..ConversationState::default()
            },
        );
        state.logs.insert(
            *conversation,
            SequencerLog::from_activation(*conversation, [0; 32]),
        );
        state
            .lifecycles
            .insert(*conversation, Lifecycle::successor());
    }
    state
}

fn bindings_index(packages: Vec<([u8; 32], ArcConversationBindingPackage)>) -> ObjectIndex {
    let mut index = ObjectIndex::default();
    for (binding, package) in packages {
        index.bindings.insert(binding, ([0; 32], package));
    }
    index
}

const OLD_BINDING: [u8; 32] = [0xb0; 32];
const NEW_BINDING: [u8; 32] = [0xb1; 32];

#[test]
fn an_unverified_successor_is_discarded_with_its_log_and_lifecycle() -> TestResult {
    let principal = principal(40, &ACCOUNT_A, &[DEVICE])?;
    let mut state = conversations(&[(OLD, OLD_BINDING), (NEW, NEW_BINDING)]);
    let index = bindings_index(vec![
        (OLD_BINDING, package(&principal, OLD, 0, [0; 32])?),
        (NEW_BINDING, package(&principal, NEW, 1, OLD_BINDING)?),
    ]);
    discard_unanchored_successors(&mut state, &index, &std::collections::BTreeSet::new());
    assert!(state.conversations.contains_key(&OLD));
    assert!(!state.conversations.contains_key(&NEW));
    assert!(!state.logs.contains_key(&NEW));
    assert!(!state.lifecycles.contains_key(&NEW));
    Ok(())
}

#[test]
fn a_verified_successor_survives_only_while_its_predecessor_does() -> TestResult {
    let principal = principal(40, &ACCOUNT_A, &[DEVICE])?;
    let verified = std::collections::BTreeSet::from([NEW]);
    let index = bindings_index(vec![
        (OLD_BINDING, package(&principal, OLD, 0, [0; 32])?),
        (NEW_BINDING, package(&principal, NEW, 1, OLD_BINDING)?),
    ]);
    let mut state = conversations(&[(OLD, OLD_BINDING), (NEW, NEW_BINDING)]);
    discard_unanchored_successors(&mut state, &index, &verified);
    assert!(state.conversations.contains_key(&NEW));
    let mut orphaned = conversations(&[(NEW, NEW_BINDING)]);
    discard_unanchored_successors(&mut orphaned, &index, &verified);
    assert!(!orphaned.conversations.contains_key(&NEW));
    Ok(())
}

#[test]
fn a_verified_successor_whose_previous_binding_is_not_retained_is_discarded() -> TestResult {
    let principal = principal(40, &ACCOUNT_A, &[DEVICE])?;
    let index = bindings_index(vec![(
        NEW_BINDING,
        package(&principal, NEW, 1, OLD_BINDING)?,
    )]);
    let mut state = conversations(&[(NEW, NEW_BINDING)]);
    discard_unanchored_successors(&mut state, &index, &std::collections::BTreeSet::from([NEW]));
    assert!(state.conversations.is_empty());
    Ok(())
}

#[test]
fn a_rebinding_of_the_same_conversation_is_not_treated_as_a_successor() -> TestResult {
    let principal = principal(40, &ACCOUNT_A, &[DEVICE])?;
    let index = bindings_index(vec![
        (OLD_BINDING, package(&principal, OLD, 0, [0; 32])?),
        (NEW_BINDING, package(&principal, OLD, 1, OLD_BINDING)?),
    ]);
    let mut state = conversations(&[(OLD, NEW_BINDING)]);
    discard_unanchored_successors(&mut state, &index, &std::collections::BTreeSet::new());
    assert!(state.conversations.contains_key(&OLD));
    Ok(())
}

// ---------------------------------------------------------------------------
// Principal roots.

fn retain(
    state: &mut CompanionState,
    kind: ArcWireObjectKind,
    value: &impl TlsEncode,
) -> TestResult<[u8; 32]> {
    let bytes = ArcWireObject::new(kind, value.encode()?)?.encode()?;
    let object_id = *agenc_relay_e2ee::ObjectId::compute(&bytes).as_bytes();
    state.objects.insert(object_id, bytes);
    Ok(object_id)
}

/// Publishes `principal`'s root as the directory head of `account`.
fn publish_root(
    state: &mut CompanionState,
    account: &[u8; 24],
    principal: &Principal,
    fingerprint: [u8; 32],
) -> TestResult {
    let object_id = retain(state, ArcWireObjectKind::RootIdentity, &principal.root)?;
    let digest = agenc_relay_e2ee::ids::account_id_digest(&NETWORK, account)?;
    let entry = AccountEntry {
        root: Some(RootHead {
            generation: 0,
            fingerprint,
            chain: vec![object_id],
        }),
        ..AccountEntry::default()
    };
    state.directory.restore_account(digest, entry);
    Ok(())
}

#[test]
fn principal_roots_are_the_verified_chain_of_the_account() -> TestResult {
    let principal = principal(40, &ACCOUNT_A, &[DEVICE])?;
    let fingerprint = root_fingerprint(&principal.root)?;
    let mut state = CompanionState::default();
    publish_root(&mut state, &ACCOUNT_A, &principal, fingerprint)?;
    let roots = principal_roots(&state, &NETWORK, &ACCOUNT_A).ok_or("roots")?;
    assert_eq!(roots.len(), 1);
    assert_eq!(
        roots.first().map(|root| root.fingerprint),
        Some(fingerprint)
    );
    Ok(())
}

#[test]
fn principal_roots_refuse_a_chain_published_under_another_account() -> TestResult {
    let principal = principal(40, &ACCOUNT_A, &[DEVICE])?;
    let fingerprint = root_fingerprint(&principal.root)?;
    let mut state = CompanionState::default();
    publish_root(&mut state, &ACCOUNT_B, &principal, fingerprint)?;
    assert!(principal_roots(&state, &NETWORK, &ACCOUNT_B).is_none());
    Ok(())
}

#[test]
fn principal_roots_refuse_a_head_that_names_another_fingerprint() -> TestResult {
    let principal = principal(40, &ACCOUNT_A, &[DEVICE])?;
    let mut state = CompanionState::default();
    publish_root(&mut state, &ACCOUNT_A, &principal, [0xee; 32])?;
    assert!(principal_roots(&state, &NETWORK, &ACCOUNT_A).is_none());
    Ok(())
}

#[test]
fn principal_rosters_skip_accounts_without_roots_and_roots_without_snapshots() -> TestResult {
    let principal = principal(40, &ACCOUNT_A, &[DEVICE])?;
    let fingerprint = root_fingerprint(&principal.root)?;
    let mut state = CompanionState::default();
    publish_root(&mut state, &ACCOUNT_A, &principal, fingerprint)?;
    let conversation = ConversationState {
        principal_accounts: vec![ACCOUNT_B, ACCOUNT_A],
        ..ConversationState::default()
    };
    let empty = ObjectIndex::default();
    assert!(principal_rosters(&state, &NETWORK, &conversation, &empty).is_empty());
    let mut index = ObjectIndex::default();
    index
        .rosters
        .insert(fingerprint, vec![principal.roster.clone()]);
    let rosters = principal_rosters(&state, &NETWORK, &conversation, &index);
    assert_eq!(rosters.len(), 1);
    Ok(())
}

#[test]
fn principal_rosters_skip_a_snapshot_the_root_did_not_sign() -> TestResult {
    let principal = principal(40, &ACCOUNT_A, &[DEVICE])?;
    let forger = super::super::tests::support::principal(41, &ACCOUNT_A, &[DEVICE])?;
    let fingerprint = root_fingerprint(&principal.root)?;
    let mut state = CompanionState::default();
    publish_root(&mut state, &ACCOUNT_A, &principal, fingerprint)?;
    let conversation = ConversationState {
        principal_accounts: vec![ACCOUNT_A],
        ..ConversationState::default()
    };
    let mut index = ObjectIndex::default();
    index.rosters.insert(fingerprint, vec![forger.roster]);
    assert!(principal_rosters(&state, &NETWORK, &conversation, &index).is_empty());
    Ok(())
}

// ---------------------------------------------------------------------------
// Votes and proofs.

fn historical(principal: &Principal) -> TestResult<Vec<(VerifiedRoot, VerifiedRoster)>> {
    let root = verify_root_identity(&NETWORK, &principal.root, None)?;
    let roster = restore_roster(&root, &principal.roster)?;
    Ok(vec![(root, roster)])
}

fn vote_of(principal: &Principal, device: u8) -> TestResult<ArcFinalityVote> {
    let slot = VoteSlot {
        network_id: NETWORK,
        conversation_id: OLD,
        prior_epoch: 0,
        prior_state_id: [1; 32],
        candidate_sequence: 0,
        predecessor_record_id: [2; 32],
    };
    let tbs: ArcDispositionVoteTbs = vote_tbs(&slot, [3; 32], Terminal::finalize([4; 32]));
    Ok(finality_vote(principal, device, &tbs)?)
}

fn vote_parts(fingerprint: [u8; 32], device: u8) -> ProofKeyParts {
    ProofKeyParts {
        role: ProofRole::Vote,
        conversation_id: OLD,
        subject_id: [3; 32],
        root_fingerprint: fingerprint,
        device_id: [device; 16],
    }
}

#[test]
fn a_vote_row_replays_the_vote_of_its_signer_under_the_retained_roster() -> TestResult {
    let principal = principal(40, &ACCOUNT_A, &[DEVICE])?;
    let fingerprint = root_fingerprint(&principal.root)?;
    let votes = vec![vote_of(&principal, DEVICE)?];
    let mut seen = Vec::new();
    let replayed = replay_vote(
        &mut QuorumLedger::new(),
        &historical(&principal)?,
        &vote_parts(fingerprint, DEVICE),
        &votes,
        |_, rosters, vote| {
            seen.push((rosters.len(), vote.signer_device_id));
            Ok(())
        },
    );
    assert!(replayed);
    assert_eq!(seen, vec![(1, [DEVICE; 16])]);
    Ok(())
}

#[test]
fn a_vote_row_whose_signer_cast_no_vote_in_the_request_is_not_replayed() -> TestResult {
    let principal = principal(40, &ACCOUNT_A, &[DEVICE])?;
    let fingerprint = root_fingerprint(&principal.root)?;
    let votes = vec![vote_of(&principal, DEVICE)?];
    let history = historical(&principal)?;
    for parts in [
        vote_parts([0xee; 32], DEVICE),
        vote_parts(fingerprint, DEVICE + 1),
    ] {
        let replayed = replay_vote(
            &mut QuorumLedger::new(),
            &history,
            &parts,
            &votes,
            |_, _, _| Ok(()),
        );
        assert!(!replayed);
    }
    Ok(())
}

#[test]
fn a_vote_without_a_retained_roster_naming_its_certificate_is_not_replayed() -> TestResult {
    let principal = principal(40, &ACCOUNT_A, &[DEVICE])?;
    let other = super::super::tests::support::principal(41, &ACCOUNT_B, &[DEVICE])?;
    let fingerprint = root_fingerprint(&principal.root)?;
    let mut vote = vote_of(&principal, DEVICE)?;
    let parts = vote_parts(fingerprint, DEVICE);
    let record = |_: &mut QuorumLedger, _: &PrincipalRosters, _: &ArcFinalityVote| Ok(());
    // Only another root's roster is retained.
    let foreign = historical(&other)?;
    assert!(!replay_vote(
        &mut QuorumLedger::new(),
        &foreign,
        &parts,
        std::slice::from_ref(&vote),
        record
    ));
    // The roster is retained but holds another certificate for the device.
    vote.signer_device_certificate_id = [0xee; 32];
    assert!(!replay_vote(
        &mut QuorumLedger::new(),
        &historical(&principal)?,
        &parts,
        std::slice::from_ref(&vote),
        record
    ));
    Ok(())
}

#[test]
fn a_vote_the_ledger_refuses_is_not_counted_as_replayed() -> TestResult {
    let principal = principal(40, &ACCOUNT_A, &[DEVICE])?;
    let fingerprint = root_fingerprint(&principal.root)?;
    let votes = vec![vote_of(&principal, DEVICE)?];
    let replayed = replay_vote(
        &mut QuorumLedger::new(),
        &historical(&principal)?,
        &vote_parts(fingerprint, DEVICE),
        &votes,
        |_, _, _| Err(E2eeError::InvalidValue),
    );
    assert!(!replayed);
    Ok(())
}

fn sequencer_rows(proofs: Vec<(ProofKeyParts, [u8; 32])>) -> SequencerRows {
    SequencerRows {
        records: BTreeMap::new(),
        candidates: BTreeMap::new(),
        proofs,
        policies: BTreeMap::new(),
        memberships: super::super::membership_restore::Rows::default(),
    }
}

#[test]
fn vote_rows_exclude_other_roles_subjects_conversations_and_request_rows() {
    let counted = vote_parts([5; 32], DEVICE);
    let approval = ProofKeyParts {
        role: ProofRole::Approval,
        ..counted
    };
    let request_row = vote_parts(super::super::ops::sequence::REQUEST_ROW_ROOT, DEVICE);
    let other_conversation = ProofKeyParts {
        conversation_id: NEW,
        ..counted
    };
    let other_subject = ProofKeyParts {
        subject_id: [9; 32],
        ..counted
    };
    let rows = sequencer_rows(vec![
        (approval, [1; 32]),
        (request_row, [2; 32]),
        (other_conversation, [3; 32]),
        (other_subject, [4; 32]),
        (counted, [5; 32]),
    ]);
    let selected: Vec<[u8; 32]> = vote_rows_of(&rows, OLD, [3; 32])
        .map(|(_, object_id)| object_id)
        .collect();
    assert_eq!(selected, vec![[5; 32]]);
}

#[test]
fn proof_rows_fill_approvals_acknowledgements_and_pending_requests() {
    let mut conversation = ConversationState::default();
    let mut ack_device = [0; 16];
    ack_device[15] = 6;
    let proofs = vec![
        (
            ProofKeyParts {
                role: ProofRole::Approval,
                ..vote_parts([5; 32], DEVICE)
            },
            [1; 32],
        ),
        (
            ProofKeyParts {
                role: ProofRole::Ack,
                device_id: ack_device,
                ..vote_parts([5; 32], DEVICE)
            },
            [2; 32],
        ),
        (
            vote_parts(super::super::ops::sequence::REQUEST_ROW_ROOT, DEVICE),
            [3; 32],
        ),
        (vote_parts([5; 32], DEVICE), [4; 32]),
    ];
    fill_proofs(&mut conversation, &proofs);
    let approvals = conversation.approvals.get(&[3; 32]);
    assert_eq!(
        approvals.and_then(|map| map.get(&([5; 32], [DEVICE; 16]))),
        Some(&[1; 32])
    );
    let acks = conversation.acks.get(&[3; 32]);
    assert_eq!(acks.and_then(|map| map.get(&6)), Some(&[2; 32]));
    let pending = conversation.pending_requests.get(&[3; 32]);
    assert_eq!(pending.map(|set| set.contains(&[3; 32])), Some(true));
    assert_eq!(pending.map(|set| set.len()), Some(1));
}

#[test]
fn terminal_requests_map_only_to_the_slot_kind_they_decide() -> TestResult {
    let finalize = TerminalRequest::Finalize([1; 32], Vec::new(), Some([2; 32]));
    let (terminal, _, resulting) = candidate_terminal(&finalize).ok_or("finalize")?;
    assert_eq!(terminal, Terminal::finalize([1; 32]));
    assert_eq!(resulting, Some([2; 32]));
    assert!(attempt_terminal(&finalize).is_none());
    let abort = TerminalRequest::Abort([3; 32], 2, Vec::new());
    let (terminal, _, resulting) = candidate_terminal(&abort).ok_or("abort")?;
    assert_eq!(terminal, Terminal::abort([3; 32], 2)?);
    assert_eq!(resulting, None);
    let activate = TerminalRequest::Activate([4; 32], Vec::new());
    assert!(candidate_terminal(&activate).is_none());
    let (terminal, _) = attempt_terminal(&activate).ok_or("activate")?;
    assert_eq!(terminal, Terminal::finalize([4; 32]));
    Ok(())
}

#[test]
fn an_abort_request_with_a_zero_reason_names_no_terminal() {
    let abort = TerminalRequest::Abort([3; 32], 0, Vec::new());
    assert!(candidate_terminal(&abort).is_none());
    let attempt_abort = TerminalRequest::AbortAttempt([3; 32], 0, Vec::new());
    assert!(attempt_terminal(&attempt_abort).is_none());
    let valid = TerminalRequest::AbortAttempt([3; 32], 7, Vec::new());
    assert!(attempt_terminal(&valid).is_some());
}

// ---------------------------------------------------------------------------
// Mailbox rows.

fn item_row(grant: Option<DeliveryGrant>) -> MailboxRow {
    MailboxRow::Item {
        object_id: [1; 32],
        conversation_id: OLD,
        inserted_at: 5,
        expires_at: 900,
        grant,
    }
}

fn token_row() -> MailboxRow {
    MailboxRow::Token {
        account_digest: [6; 32],
        device_id: [7; 16],
        kind: RowMailboxKind::Welcome,
        sequence: 2,
        object_id: [1; 32],
        session_generation: 3,
        expires_at: 800,
    }
}

fn ack_row() -> MailboxRow {
    MailboxRow::Ack {
        object_id: [1; 32],
        acknowledged_at: 5,
        retain_until: 9,
    }
}

#[test]
fn mailbox_rows_under_a_foreign_key_are_not_sorted_into_the_restore() -> TestResult {
    let foreign = RouteRow::key(&[0x55; 32])?;
    let mut rows = MailboxRows::default();
    rows.admit(&foreign, item_row(None));
    rows.admit(&foreign, token_row());
    rows.admit(&foreign, ack_row());
    assert!(rows.items.is_empty());
    assert!(rows.grants.is_empty());
    assert!(rows.acks.is_empty());
    Ok(())
}

#[test]
fn mailbox_rows_are_sorted_by_the_arm_their_key_names() -> TestResult {
    let mut rows = MailboxRows::default();
    let item_key = MailboxRow::item_key(&[6; 32], &[7; 16], RowMailboxKind::Welcome, 2)?;
    rows.admit(&item_key, item_row(None));
    rows.admit(&MailboxRow::token_key(&[8; 32])?, token_row());
    rows.admit(
        &MailboxRow::ack_key(&[6; 32], &[7; 16], &[8; 32])?,
        ack_row(),
    );
    let target = Target {
        account_digest: [6; 32],
        device_id: [7; 16],
    };
    let slot = (target, MailboxKind::Welcome, 2);
    assert_eq!(
        rows.items.get(&slot).map(|item| item.object_id),
        Some([1; 32])
    );
    let (granted, object_id, grant) = rows.grants.first().ok_or("grant")?;
    assert_eq!(
        (*granted, *object_id, grant.token),
        (slot, [1; 32], [8; 32])
    );
    assert_eq!(rows.acks, vec![(target, [8; 32], [1; 32], 9)]);
    Ok(())
}

#[test]
fn mailbox_arm_helpers_ignore_rows_of_another_arm() -> TestResult {
    let mut rows = MailboxRows::default();
    let item_key = MailboxRow::item_key(&[6; 32], &[7; 16], RowMailboxKind::Welcome, 2)?;
    rows.admit_item(&item_key, ack_row());
    rows.admit_token(&MailboxRow::token_key(&[8; 32])?, item_row(None));
    rows.admit_ack(
        &MailboxRow::ack_key(&[6; 32], &[7; 16], &[8; 32])?,
        token_row(),
    );
    assert!(rows.items.is_empty());
    assert!(rows.grants.is_empty());
    assert!(rows.acks.is_empty());
    Ok(())
}

#[test]
fn a_granted_item_without_its_token_row_fails_the_mailbox_restore() -> TestResult {
    let grant = DeliveryGrant {
        token: [8; 32],
        session_generation: 3,
        expires_at: 800,
    };
    let item_key = MailboxRow::item_key(&[6; 32], &[7; 16], RowMailboxKind::Welcome, 2)?;
    let mut state = CompanionState::default();
    assert_eq!(
        restore_mailboxes(&mut state, vec![(item_key, item_row(Some(grant)))]),
        Err(super::super::CompanionFault::Storage)
    );
    Ok(())
}

#[test]
fn a_token_row_without_its_item_fails_the_mailbox_restore() -> TestResult {
    let mut state = CompanionState::default();
    let rows = vec![(MailboxRow::token_key(&[8; 32])?, token_row())];
    assert_eq!(
        restore_mailboxes(&mut state, rows),
        Err(super::super::CompanionFault::Storage)
    );
    Ok(())
}
