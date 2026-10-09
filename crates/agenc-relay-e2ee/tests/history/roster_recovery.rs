#![forbid(unsafe_code)]

//! The validation time a finalization's roots and rosters must cover
//! (companion 8.2 to 8.4 and 12.4): a principal whose roster expired may
//! sign only the `roster_recovery` candidate that installs its continuous,
//! unexpired successor and changes nothing else; a principal that signs
//! nothing in a record does not block it; no record installs a root or
//! roster that does not cover its time; and a record installs at most one
//! root continuation and one roster per account (companion 9.3 and 13.7.2).

use super::*;
use agenc_relay_e2ee::Opaque;
use agenc_relay_e2ee::membership::LeafMembershipSet;
use agenc_relay_e2ee::objects::identity::{ArcDeviceRoster, ArcRootIdentity};

/// The canonical validation time of every record after the bootstrap, which
/// the fixture activates at `VALIDATION_TIME`.
const T: u64 = 300_000;
/// A successor interval that covers `T`.
const SUCCESSOR: (u64, u64) = (250_000, 768_400);

/// The genesis whose second principal holds `devices` under a
/// generation-zero roster ending at `not_after`; the creator's devices 7
/// and 8 stay live.
fn lapsing(not_after: u64, devices: &[u8]) -> Result<Genesis, E2eeError> {
    Genesis::with_principals(vec![
        principal(40, &ACCOUNT, &[7, 8])?,
        principal_with_roster(41, &OTHER, devices, (100, not_after))?,
    ])
}

/// The second principal's roster `generation` naming `previous` over
/// `interval`, keeping `kept` with their generation-zero certificates.
fn successor(
    genesis: &Genesis,
    generation: u64,
    previous: [u8; 32],
    interval: (u64, u64),
    kept: &[u8],
) -> Result<ArcDeviceRoster, E2eeError> {
    let other = genesis.principal(1)?;
    let certificates = kept
        .iter()
        .map(|device| active_certificate(other, *device))
        .collect::<Result<Vec<_>, _>>()?;
    roster(
        &other.root_secret,
        &other.root,
        generation,
        previous,
        interval,
        certificates,
        Vec::new(),
    )
}

/// One candidate after the bootstrap and the finalization that certifies
/// it at `T`: its rule and action bits, who approves and votes, and the
/// objects the caller supplies with it.
#[derive(Clone)]
struct Attempt<'a> {
    rule: ArcCommitAuthorizationRule,
    bits: u32,
    approvers: Vec<(usize, u8)>,
    voters: Vec<(usize, u8)>,
    roots: Vec<&'a ArcRootIdentity>,
    rosters: Vec<&'a ArcDeviceRoster>,
    policy: Option<&'a ArcPolicy>,
    memberships: Option<&'a LeafMembershipSet>,
}

impl<'a> Attempt<'a> {
    /// A `roster_recovery` carrying `rosters`, voted by `voters`.
    fn recovery(voters: Vec<(usize, u8)>, rosters: Vec<&'a ArcDeviceRoster>) -> Self {
        Self {
            rule: ArcCommitAuthorizationRule::RosterRecovery,
            bits: action_bits::ROSTER,
            approvers: Vec::new(),
            voters,
            roots: Vec::new(),
            rosters,
            policy: None,
            memberships: None,
        }
    }

    /// A routine self-update voted by `voters`.
    fn routine(voters: Vec<(usize, u8)>) -> Self {
        Self {
            rule: ArcCommitAuthorizationRule::RoutineSelfUpdate,
            bits: 0,
            ..Self::recovery(voters, Vec::new())
        }
    }

    /// A controlled transition with `bits`, approved by the creator's
    /// device 7 under the operational policy's threshold of one.
    fn controlled(bits: u32, voters: Vec<(usize, u8)>, rosters: Vec<&'a ArcDeviceRoster>) -> Self {
        Self {
            rule: ArcCommitAuthorizationRule::ControlledTransition,
            bits,
            approvers: vec![(0, 7)],
            ..Self::recovery(voters, rosters)
        }
    }
}

/// Activates `genesis`, opens one candidate, and offers the chain the
/// finalization `attempt` describes; returns the chain and its step.
fn finalize_at(
    genesis: &Genesis,
    attempt: &Attempt<'_>,
) -> Result<(HistoricalChain, ChainStep), Box<dyn std::error::Error>> {
    let (mut chain, mut log) = activated(genesis)?;
    let (candidate_record, candidate) = log.candidate([2; 32])?;
    adopt(&mut chain, &candidate_record)?;
    let resulting = match attempt.policy {
        Some(policy) => policy_id_of(policy)?,
        None => log.policy_id,
    };
    let mut tbs = log.authorization_tbs(&candidate, attempt.rule, attempt.bits, resulting, [0; 32]);
    tbs.canonical_validation_time = T;
    let council = Council {
        genesis,
        approvers: attempt.approvers.clone(),
        voters: attempt.voters.clone(),
    };
    let (request, id) =
        log.finalization_request(&candidate, council.authorization(tbs)?, &council)?;
    let record = log.finalization(request, id, resulting)?;
    let roots = attempt
        .roots
        .iter()
        .map(|root| object(ArcWireObjectKind::RootIdentity, *root))
        .collect::<Result<Vec<_>, _>>()?;
    let rosters = attempt
        .rosters
        .iter()
        .map(|roster| object(ArcWireObjectKind::DeviceRoster, *roster))
        .collect::<Result<Vec<_>, _>>()?;
    let policy = attempt
        .policy
        .map(|policy| object(ArcWireObjectKind::Policy, policy))
        .transpose()?;
    let roots: Vec<&[u8]> = roots.iter().map(Vec::as_slice).collect();
    let rosters: Vec<&[u8]> = rosters.iter().map(Vec::as_slice).collect();
    let references = RecordReferences {
        root_objects: &roots,
        roster_objects: &rosters,
        policy_object: policy.as_deref(),
        memberships: attempt.memberships,
        ..RecordReferences::default()
    };
    let step = chain.advance(&record.bytes, &references, &mut budget())?;
    Ok((chain, step))
}

/// The roster generation and devices the chain now holds for `account`.
fn held(chain: &HistoricalChain, account: &[u8; 24]) -> Result<(u64, Vec<[u8; 16]>), String> {
    let (_, roster) = chain.principals().get(account).ok_or("principal")?;
    Ok((roster.generation, roster.devices.keys().copied().collect()))
}

#[test]
fn an_expired_predecessor_recovers_through_its_continuous_successor() -> TestResult {
    // At `T` the predecessor still covers the time; one second earlier it
    // has expired, and only the recovery exception admits device 9's vote,
    // checked against the expired predecessor and the successor alike.
    for not_after in [T, T - 1] {
        let genesis = lapsing(not_after, &[9])?;
        let previous = roster_id(&genesis.principal(1)?.roster)?;
        let next = successor(&genesis, 1, previous, SUCCESSOR, &[9])?;
        // n = 3 and q = 2: one device of each principal.
        let (chain, step) = finalize_at(
            &genesis,
            &Attempt::recovery(vec![(0, 7), (1, 9)], vec![&next]),
        )?;
        let ChainStep::Finalized { transitions, .. } = step else {
            return Err(format!("not finalized at {not_after}").into());
        };
        assert_eq!(transitions.roster_heads, vec![(OTHER, roster_id(&next)?)]);
        assert_eq!(held(&chain, &OTHER)?, (1, vec![[9; 16]]));
    }
    Ok(())
}

#[test]
fn a_recovery_removes_the_devices_its_successor_drops() -> TestResult {
    let genesis = lapsing(T - 1, &[9, 10])?;
    let previous = roster_id(&genesis.principal(1)?.roster)?;
    let next = successor(&genesis, 1, previous, SUCCESSOR, &[9])?;
    let mut recovery = Attempt::recovery(vec![(0, 7), (0, 8), (1, 9)], vec![&next]);
    recovery.bits = action_bits::ROSTER | action_bits::REMOVE_LEAF;
    // n = 4 and q = 3: both creator devices and the device the successor keeps.
    let (chain, step) = finalize_at(&genesis, &recovery)?;
    assert!(matches!(step, ChainStep::Finalized { .. }));
    assert_eq!(held(&chain, &OTHER)?, (1, vec![[9; 16]]));
    // The device the successor drops is removed by the candidate and may
    // authenticate only the public removal path: its vote is refused.
    let mut removed = recovery.clone();
    removed.voters = vec![(0, 7), (0, 8), (1, 10)];
    assert!(finalize_at(&genesis, &removed).is_err());
    Ok(())
}

#[test]
fn a_recovery_admits_no_other_shape() -> TestResult {
    let genesis = lapsing(T - 1, &[9])?;
    let other = genesis.principal(1)?;
    let previous = roster_id(&other.roster)?;
    let next = successor(&genesis, 1, previous, SUCCESSOR, &[9])?;
    let skipped = successor(&genesis, 2, previous, SUCCESSOR, &[9])?;
    let expired = successor(&genesis, 1, previous, (100, T - 1), &[9])?;
    let early = successor(&genesis, 1, previous, (T + 1, T + 100_000), &[9])?;
    // A continued root starts a new lineage, which does not continue the
    // expired roster.
    let new_secret = key(45);
    let continued = root(
        &new_secret,
        &OTHER,
        1,
        (0, 2_000_000),
        Some((&other.root_secret, &other.root)),
    )?;
    let reissued = roster(
        &new_secret,
        &continued,
        0,
        [0; 32],
        SUCCESSOR,
        vec![certificate(
            &new_secret,
            &continued,
            &DeviceSpec {
                interval: (0, 2_000_000),
                enrollment: (SUCCESSOR.0 - 10, SUCCESSOR.0),
                ..DeviceSpec::new(9)
            },
        )?],
        Vec::new(),
    )?;
    // The creator continues its root beside the recovery, reissuing its
    // devices under the new root.
    let creator = genesis.principal(0)?;
    let creator_secret = key(46);
    let creator_root = root(
        &creator_secret,
        &ACCOUNT,
        1,
        (0, 2_000_000),
        Some((&creator.root_secret, &creator.root)),
    )?;
    let reissue = |device| {
        certificate(
            &creator_secret,
            &creator_root,
            &DeviceSpec {
                interval: (0, 2_000_000),
                enrollment: (SUCCESSOR.0 - 10, SUCCESSOR.0),
                ..DeviceSpec::new(device)
            },
        )
    };
    let creator_reissued = roster(
        &creator_secret,
        &creator_root,
        0,
        [0; 32],
        SUCCESSOR,
        vec![reissue(7)?, reissue(8)?],
        Vec::new(),
    )?;
    // The creator renews its own live roster, and the lapsed one is not
    // renewed.
    let creator_renewed = roster(
        &creator.root_secret,
        &creator.root,
        1,
        roster_id(&creator.roster)?,
        SUCCESSOR,
        vec![
            active_certificate(creator, 7)?,
            active_certificate(creator, 8)?,
        ],
        Vec::new(),
    )?;
    let voters = vec![(0, 7), (1, 9)];
    let recovery = |rosters| Attempt::recovery(voters.clone(), rosters);
    let add = Attempt::controlled(
        action_bits::ROSTER | action_bits::ADD_LEAF,
        voters.clone(),
        vec![&next],
    );
    let mut add_labelled = add.clone();
    add_labelled.rule = ArcCommitAuthorizationRule::RosterRecovery;
    add_labelled.approvers = Vec::new();
    let controlled = Attempt::controlled(action_bits::ROSTER, voters.clone(), vec![&next]);
    let mut approved = recovery(vec![&next]);
    approved.approvers = vec![(1, 9)];
    let mut rotated = recovery(vec![&reissued]);
    rotated.roots = vec![&continued];
    let mut beside = recovery(vec![&creator_reissued, &next]);
    beside.roots = vec![&creator_root];
    let refs = [creator, other];
    let mut spec = PolicySpec::operational(
        &refs,
        genesis.conversation,
        ArcConversationKind::Channel,
        [0; 32],
    )?;
    spec.generation = 2;
    spec.previous_policy_id = policy_id_of(&genesis.operational_policy)?;
    let next_policy = policy(&spec)?;
    let mut with_policy = Attempt::controlled(
        action_bits::ROSTER | action_bits::POLICY,
        voters.clone(),
        vec![&next],
    );
    with_policy.policy = Some(&next_policy);
    let cases = [
        ("a skipped generation", recovery(vec![&skipped])),
        ("a successor that expired", recovery(vec![&expired])),
        ("a successor not yet valid", recovery(vec![&early])),
        (
            "the expired roster reaffirmed",
            recovery(vec![&other.roster]),
        ),
        ("a successor under a continued root", rotated),
        ("a root continuation beside it", beside),
        (
            "another principal's successor only",
            recovery(vec![&creator_renewed]),
        ),
        ("an Add", add),
        ("an Add labelled roster recovery", add_labelled),
        ("the policy bit", with_policy),
        ("the controlled-transition label", controlled),
        ("an approval from the expired roster", approved),
        (
            "a reduced quorum",
            Attempt::recovery(vec![(1, 9)], vec![&next]),
        ),
    ];
    for (name, attempt) in &cases {
        assert!(finalize_at(&genesis, attempt).is_err(), "{name}");
    }
    finalize_at(&genesis, &recovery(vec![&next]))?;
    Ok(())
}

#[test]
fn a_lapsed_principal_that_signs_nothing_does_not_block_a_finalization() -> TestResult {
    let genesis = lapsing(T - 1, &[9])?;
    // n = 3 and q = 2: the creator's devices reach the quorum alone.
    let (_, step) = finalize_at(&genesis, &Attempt::routine(vec![(0, 7), (0, 8)]))?;
    assert!(matches!(step, ChainStep::Finalized { .. }));
    // A live controller removes the lapsed principal's leaf (companion 8.4:
    // a stale account is removed or renewed).
    let removal = Attempt::controlled(action_bits::REMOVE_LEAF, vec![(0, 7), (0, 8)], vec![]);
    finalize_at(&genesis, &removal)?;
    // Outside the recovery exception its expired roster authorizes no vote.
    assert!(finalize_at(&genesis, &Attempt::routine(vec![(0, 7), (0, 8), (1, 9)])).is_err());
    // A policy transition names every principal's roster head, so the
    // lapsed principal blocks it even when silent; live, the same
    // transition finalizes.
    for (not_after, finalizes) in [(T - 1, false), (600_000, true)] {
        let genesis = lapsing(not_after, &[9])?;
        let refs = [genesis.principal(0)?, genesis.principal(1)?];
        let mut spec = PolicySpec::operational(
            &refs,
            genesis.conversation,
            ArcConversationKind::Channel,
            [0; 32],
        )?;
        spec.generation = 2;
        spec.previous_policy_id = policy_id_of(&genesis.operational_policy)?;
        let next_policy = policy(&spec)?;
        let mut change = Attempt::controlled(action_bits::POLICY, vec![(0, 7), (0, 8)], vec![]);
        change.policy = Some(&next_policy);
        assert_eq!(
            finalize_at(&genesis, &change).is_ok(),
            finalizes,
            "{not_after}"
        );
    }
    Ok(())
}

#[test]
fn an_identified_acknowledgement_uses_its_signers_roster() -> TestResult {
    // The creator's roster lapses; the other principal's three devices
    // reach the quorum alone (n = 5, q = 3).
    let genesis = Genesis::with_principals(vec![
        principal_with_roster(40, &ACCOUNT, &[7, 8], (100, T - 1))?,
        principal(41, &OTHER, &[9, 10, 12])?,
    ])?;
    let routine = Attempt::routine(vec![(1, 9), (1, 10), (1, 12)]);
    // Without leaf-membership facts no ACK signer is known.
    finalize_at(&genesis, &routine)?;
    // With them, the creator's leaf zero signs the only ACK, and its expired
    // roster authorizes no ordinary Commit ACK.
    let facts = memberships(&genesis, &[(0, 7, CREATOR_LEAF_SEED, 0, [55; 32])])?;
    let mut identified = routine.clone();
    identified.memberships = Some(&facts);
    assert!(finalize_at(&genesis, &identified).is_err());
    Ok(())
}

#[test]
fn a_finalization_never_installs_a_roster_that_does_not_cover_its_time() -> TestResult {
    // Both principals are live at `T`.
    let genesis = lapsing(600_000, &[9])?;
    let previous = roster_id(&genesis.principal(1)?.roster)?;
    let expired = successor(&genesis, 1, previous, (100, T - 1), &[9])?;
    let opening = successor(&genesis, 1, previous, (T, T + 100_000), &[9])?;
    let voters = vec![(0, 7), (1, 9)];
    for attempt in [
        Attempt::recovery(voters.clone(), vec![&expired]),
        Attempt::controlled(action_bits::ROSTER, voters.clone(), vec![&expired]),
    ] {
        assert!(finalize_at(&genesis, &attempt).is_err());
    }
    // A successor that opens exactly at the time is installed.
    let (chain, _) = finalize_at(&genesis, &Attempt::recovery(voters, vec![&opening]))?;
    assert_eq!(held(&chain, &OTHER)?, (1, vec![[9; 16]]));
    Ok(())
}

/// Leaf-membership facts naming `device` of `principal` as the holder of
/// old leaf zero, whose key signs the fixture's only ACK.
fn leaf_zero_held_by(
    genesis: &Genesis,
    principal: &Principal,
    device: u8,
) -> Result<LeafMembershipSet, Box<dyn std::error::Error>> {
    use agenc_relay_crypto::SignatureDomain;
    use agenc_relay_e2ee::identity::{verify_root_identity, verify_roster};
    use agenc_relay_e2ee::membership::verify_leaf_membership_proof;
    use agenc_relay_e2ee::objects::membership::{
        ArcLeafDispositionKind, ArcLeafMembershipProof, ArcLeafMembershipProofTbs,
    };
    let root = verify_root_identity(&NETWORK, &principal.root, None)?;
    let roster = verify_roster(&root, &principal.roster, None)?;
    let tbs = ArcLeafMembershipProofTbs {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: genesis.conversation,
        epoch: 0,
        leaf_index: 0,
        old_credential_hash: [55; 32],
        leaf_signature_scheme: 0x0807,
        leaf_signature_key: Opaque::from_slice(&public(&key(CREATOR_LEAF_SEED)))?,
        account_id: principal.root.tbs.account_id.clone(),
        device_id: [device; 16],
        root_generation: 0,
        root_fingerprint: root_fingerprint(&principal.root)?,
        roster_generation: 0,
        roster_id: roster_id(&principal.roster)?,
        credential_generation: 0,
        disposition: ArcLeafDispositionKind::Continuing,
        removal_finalization_id: [0; 32],
    };
    let proof = ArcLeafMembershipProof {
        device_signature: sign(&key(device), SignatureDomain::LeafMembership, &tbs)?,
        possession_signature: Opaque::from_slice(&sign(
            &key(CREATOR_LEAF_SEED),
            SignatureDomain::LeafMembershipPossession,
            &tbs,
        )?)?,
        tbs,
    };
    let verified =
        verify_leaf_membership_proof(&NETWORK, &genesis.conversation, &proof, &root, &roster)
            .map_err(|refusal| format!("{refusal:?}"))?;
    let object_id = object_id(&object(ArcWireObjectKind::LeafMembershipProof, &proof)?);
    let mut set = LeafMembershipSet::default();
    set.insert(object_id, verified);
    Ok(set)
}

#[test]
fn an_acknowledgement_from_outside_the_binding_principals_is_the_callers_check() -> TestResult {
    // A channel member whose account is no binding principal holds leaf
    // zero; the chain keeps no roster of that account, so the time its
    // roster covers is the caller's check, as is its device activity.
    let genesis = lapsing(600_000, &[9])?;
    let member = principal_with_roster(42, b"cccccccccccccccccccccccc", &[13], (100, T - 1))?;
    let facts = leaf_zero_held_by(&genesis, &member, 13)?;
    let mut routine = Attempt::routine(vec![(0, 7), (0, 8)]);
    routine.memberships = Some(&facts);
    let (_, step) = finalize_at(&genesis, &routine)?;
    assert!(matches!(step, ChainStep::Finalized { .. }));
    Ok(())
}

/// The second principal's roster `generation` naming `previous` over
/// `interval` that reissues `device` with a new certificate (serial 2,
/// enrolled for that generation) under the same root and device key.
fn reissuing(
    genesis: &Genesis,
    generation: u64,
    previous: [u8; 32],
    interval: (u64, u64),
    device: u8,
) -> Result<ArcDeviceRoster, E2eeError> {
    let other = genesis.principal(1)?;
    let reissued = certificate(
        &other.root_secret,
        &other.root,
        &DeviceSpec {
            interval: (0, 2_000_000),
            enrollment: (interval.0 - 10, interval.0),
            target_roster_generation: generation,
            serial: 2,
            ..DeviceSpec::new(device)
        },
    )?;
    roster(
        &other.root_secret,
        &other.root,
        generation,
        previous,
        interval,
        vec![reissued],
        Vec::new(),
    )
}

/// The second principal's root `generation` of seed `seed` over `interval`,
/// continuing `previous`, with its generation-zero roster reissuing device 9
/// over `SUCCESSOR`.
fn continued_root(
    seed: u8,
    generation: u64,
    interval: (u64, u64),
    previous: (&agenc_relay_crypto::Ed25519SecretKey, &ArcRootIdentity),
) -> Result<(ArcRootIdentity, ArcDeviceRoster), E2eeError> {
    let secret = key(seed);
    let continued = root(&secret, &OTHER, generation, interval, Some(previous))?;
    let reissued = certificate(
        &secret,
        &continued,
        &DeviceSpec {
            interval: (0, 2_000_000),
            enrollment: (SUCCESSOR.0 - 10, SUCCESSOR.0),
            ..DeviceSpec::new(9)
        },
    )?;
    let first = roster(
        &secret,
        &continued,
        0,
        [0; 32],
        SUCCESSOR,
        vec![reissued],
        Vec::new(),
    )?;
    Ok((continued, first))
}

#[test]
fn a_record_installs_one_roster_per_account() -> TestResult {
    // The roster a record installs for an account is exactly the successor
    // its context head names (companion 9.3), so a second, different roster
    // of that account is refused even when it continues the first, and in
    // particular a record cannot reach a live roster through an expired one.
    let genesis = lapsing(T - 1, &[9])?;
    let previous = roster_id(&genesis.principal(1)?.roster)?;
    let first = successor(&genesis, 1, previous, SUCCESSOR, &[9])?;
    let second = successor(&genesis, 2, roster_id(&first)?, SUCCESSOR, &[9])?;
    let lapsed_first = successor(&genesis, 1, previous, (100, T - 1), &[9])?;
    let after_lapsed = successor(&genesis, 2, roster_id(&lapsed_first)?, SUCCESSOR, &[9])?;
    let voters = vec![(0, 7), (1, 9)];
    for (name, rosters) in [
        ("two successive rosters", vec![&first, &second]),
        (
            "an expired roster and its live successor",
            vec![&lapsed_first, &after_lapsed],
        ),
    ] {
        let attempt = Attempt::recovery(voters.clone(), rosters);
        assert!(finalize_at(&genesis, &attempt).is_err(), "{name}");
    }
    // A live principal's controlled transition is held to the same rule.
    let live = lapsing(600_000, &[9])?;
    let live_previous = roster_id(&live.principal(1)?.roster)?;
    let expired = successor(&live, 1, live_previous, (100, T - 1), &[9])?;
    let after = successor(&live, 2, roster_id(&expired)?, SUCCESSOR, &[9])?;
    for rosters in [vec![&expired], vec![&expired, &after]] {
        let attempt = Attempt::controlled(action_bits::ROSTER, voters.clone(), rosters);
        assert!(finalize_at(&live, &attempt).is_err());
    }
    // The rule holds in any order: the current roster reaffirmed before or
    // after its successor, and a different roster after or between repeats
    // of one, are refused.
    let current = &live.principal(1)?.roster;
    let next = successor(&live, 1, live_previous, SUCCESSOR, &[9])?;
    let later = successor(&live, 2, roster_id(&next)?, SUCCESSOR, &[9])?;
    for (name, rosters) in [
        ("the current roster, then a successor", vec![current, &next]),
        ("a successor, then the current roster", vec![&next, current]),
        ("another after a repeat", vec![&next, &next, &later]),
        ("another between repeats", vec![&next, &later, &next]),
    ] {
        let attempt = Attempt::controlled(action_bits::ROSTER, voters.clone(), rosters);
        assert!(finalize_at(&live, &attempt).is_err(), "{name}");
    }
    // A reaffirmation supplied twice is installed and reported once.
    let twice = Attempt::controlled(action_bits::ROSTER, voters.clone(), vec![current, current]);
    let (_, step) = finalize_at(&live, &twice)?;
    let ChainStep::Finalized { transitions, .. } = step else {
        return Err("the repeated reaffirmation was not finalized".into());
    };
    assert_eq!(transitions.roster_heads, vec![(OTHER, live_previous)]);
    // An exact repeat, as when two submitters supply the same reference, is
    // installed and reported once.
    let (chain, step) = finalize_at(&genesis, &Attempt::recovery(voters, vec![&first, &first]))?;
    let ChainStep::Finalized { transitions, .. } = step else {
        return Err("the repeated roster was not finalized".into());
    };
    assert_eq!(transitions.roster_heads, vec![(OTHER, roster_id(&first)?)]);
    assert_eq!(held(&chain, &OTHER)?, (1, vec![[9; 16]]));
    Ok(())
}

#[test]
fn a_record_continues_an_accounts_root_once() -> TestResult {
    // Both principals are live at `T`; the second continues its root under
    // a controlled transition its own devices do not sign.
    let genesis = lapsing(600_000, &[9])?;
    let other = genesis.principal(1)?;
    let (next, next_roster) =
        continued_root(45, 1, (0, 2_000_000), (&other.root_secret, &other.root))?;
    let (after, after_roster) = continued_root(46, 2, (0, 2_000_000), (&key(45), &next))?;
    let mut once = Attempt::controlled(
        action_bits::ROSTER,
        vec![(0, 7), (0, 8)],
        vec![&next_roster],
    );
    once.roots = vec![&next];
    let (chain, step) = finalize_at(&genesis, &once)?;
    let ChainStep::Finalized { transitions, .. } = step else {
        return Err("the continued root was not finalized".into());
    };
    assert_eq!(transitions.roots, vec![(OTHER, root_fingerprint(&next)?)]);
    assert_eq!(held(&chain, &OTHER)?, (0, vec![[9; 16]]));
    // A second continuation of the same account in one record is refused:
    // the record continues an account's root at most once (companion
    // 13.7.2), so every root it installs is the one its time check sees.
    let mut twice = Attempt::controlled(
        action_bits::ROSTER,
        vec![(0, 7), (0, 8)],
        vec![&after_roster],
    );
    twice.roots = vec![&next, &after];
    assert!(finalize_at(&genesis, &twice).is_err());
    // An exact repeat of the continued root is installed and reported once.
    let mut repeated = once.clone();
    repeated.roots = vec![&next, &next];
    let (_, step) = finalize_at(&genesis, &repeated)?;
    let ChainStep::Finalized { transitions, .. } = step else {
        return Err("the repeated root was not finalized".into());
    };
    assert_eq!(transitions.roots, vec![(OTHER, root_fingerprint(&next)?)]);
    Ok(())
}

#[test]
fn a_record_installs_one_roster_for_each_of_two_accounts() -> TestResult {
    // The rule is per account: a Commit carries each account's roster once
    // (companion 9.3), so one record may renew two accounts. A controlled
    // transition carrying the creator's same-root renewal and the second
    // principal's successor installs both, with one head for each account.
    let genesis = lapsing(600_000, &[9])?;
    let creator = genesis.principal(0)?;
    let other = genesis.principal(1)?;
    let renewed = roster(
        &creator.root_secret,
        &creator.root,
        1,
        roster_id(&creator.roster)?,
        SUCCESSOR,
        vec![
            active_certificate(creator, 7)?,
            active_certificate(creator, 8)?,
        ],
        Vec::new(),
    )?;
    let next = successor(&genesis, 1, roster_id(&other.roster)?, SUCCESSOR, &[9])?;
    let heads = vec![(ACCOUNT, roster_id(&renewed)?), (OTHER, roster_id(&next)?)];
    // An exact repeat of one account's roster around the other's is still
    // installed once.
    for rosters in [vec![&renewed, &next], vec![&renewed, &next, &renewed]] {
        let attempt = Attempt::controlled(action_bits::ROSTER, vec![(0, 7), (0, 8)], rosters);
        let (chain, step) = finalize_at(&genesis, &attempt)?;
        let ChainStep::Finalized { transitions, .. } = step else {
            return Err("the two accounts' rosters were not finalized".into());
        };
        assert_eq!(transitions.roster_heads, heads);
        assert_eq!(held(&chain, &ACCOUNT)?, (1, vec![[7; 16], [8; 16]]));
        assert_eq!(held(&chain, &OTHER)?, (1, vec![[9; 16]]));
    }
    Ok(())
}

/// The creator's root generation one of seed `seed`, continuing its genesis
/// root, with its generation-zero roster reissuing devices 7 and 8 over
/// `SUCCESSOR`.
fn creator_continued_root(
    genesis: &Genesis,
    seed: u8,
) -> Result<(ArcRootIdentity, ArcDeviceRoster), E2eeError> {
    let creator = genesis.principal(0)?;
    let secret = key(seed);
    let continued = root(
        &secret,
        &ACCOUNT,
        1,
        (0, 2_000_000),
        Some((&creator.root_secret, &creator.root)),
    )?;
    let reissue = |device| {
        certificate(
            &secret,
            &continued,
            &DeviceSpec {
                interval: (0, 2_000_000),
                enrollment: (SUCCESSOR.0 - 10, SUCCESSOR.0),
                ..DeviceSpec::new(device)
            },
        )
    };
    let first = roster(
        &secret,
        &continued,
        0,
        [0; 32],
        SUCCESSOR,
        vec![reissue(7)?, reissue(8)?],
        Vec::new(),
    )?;
    Ok((continued, first))
}

#[test]
fn a_record_continues_the_roots_of_two_accounts() -> TestResult {
    // Each of two accounts continues its root once in one record, with the
    // new root's generation-zero roster (companion 8.2 and 13.7.2), so the
    // record installs one root and one roster for each account.
    let genesis = lapsing(600_000, &[9])?;
    let other = genesis.principal(1)?;
    let (creator_root, creator_first) = creator_continued_root(&genesis, 46)?;
    let (other_root, other_first) =
        continued_root(45, 1, (0, 2_000_000), (&other.root_secret, &other.root))?;
    let mut both = Attempt::controlled(
        action_bits::ROSTER,
        vec![(0, 7), (0, 8)],
        vec![&creator_first, &other_first],
    );
    both.roots = vec![&creator_root, &other_root];
    let (chain, step) = finalize_at(&genesis, &both)?;
    let ChainStep::Finalized { transitions, .. } = step else {
        return Err("the two accounts' root continuations were not finalized".into());
    };
    assert_eq!(
        transitions.roots,
        vec![
            (ACCOUNT, root_fingerprint(&creator_root)?),
            (OTHER, root_fingerprint(&other_root)?),
        ]
    );
    assert_eq!(
        transitions.roster_heads,
        vec![
            (ACCOUNT, roster_id(&creator_first)?),
            (OTHER, roster_id(&other_first)?),
        ]
    );
    assert_eq!(held(&chain, &ACCOUNT)?, (0, vec![[7; 16], [8; 16]]));
    assert_eq!(held(&chain, &OTHER)?, (0, vec![[9; 16]]));
    Ok(())
}

#[test]
fn a_finalization_never_installs_a_root_that_does_not_cover_its_time() -> TestResult {
    // Both principals are live at `T`; the second continues its root with a
    // root whose first roster covers `T` (companion 8.2: a root used for a
    // candidate covers its canonical validation time).
    let genesis = lapsing(600_000, &[9])?;
    let other = genesis.principal(1)?;
    let predecessor = (&other.root_secret, &other.root);
    let (late, late_roster) = continued_root(47, 1, (T + 1, 2_000_000), predecessor)?;
    let (opening, opening_roster) = continued_root(48, 1, (T, 2_000_000), predecessor)?;
    let mut refused = Attempt::controlled(
        action_bits::ROSTER,
        vec![(0, 7), (0, 8)],
        vec![&late_roster],
    );
    refused.roots = vec![&late];
    assert!(finalize_at(&genesis, &refused).is_err());
    // A root that opens exactly at the time is installed.
    let mut installed = Attempt::controlled(
        action_bits::ROSTER,
        vec![(0, 7), (0, 8)],
        vec![&opening_roster],
    );
    installed.roots = vec![&opening];
    let (chain, _) = finalize_at(&genesis, &installed)?;
    let (root, _) = chain.principals().get(&OTHER).ok_or("principal")?;
    assert_eq!(root.fingerprint, root_fingerprint(&opening)?);
    Ok(())
}

#[test]
fn a_recovery_refuses_a_vote_from_a_device_whose_certificate_its_successor_replaces() -> TestResult
{
    let genesis = lapsing(T - 1, &[9])?;
    let previous = roster_id(&genesis.principal(1)?.roster)?;
    let replaced = reissuing(&genesis, 1, previous, SUCCESSOR, 9)?;
    // The successor itself is a valid continuous roster: a live controlled
    // transition that the lapsed principal does not sign installs it.
    let controlled =
        Attempt::controlled(action_bits::ROSTER, vec![(0, 7), (0, 8)], vec![&replaced]);
    let (chain, _) = finalize_at(&genesis, &controlled)?;
    assert_eq!(held(&chain, &OTHER)?, (1, vec![[9; 16]]));
    // Inside the exception the old leaf is checked against both rosters
    // (companion 8.4), so device 9's vote under the certificate the
    // successor replaced is refused.
    let recovery = Attempt::recovery(vec![(0, 7), (1, 9)], vec![&replaced]);
    assert!(finalize_at(&genesis, &recovery).is_err());
    Ok(())
}

#[test]
fn a_recovery_admits_an_acknowledgement_only_from_a_device_its_successor_keeps() -> TestResult {
    // Device 9 of the lapsed principal only acknowledges; the creator's
    // devices reach the quorum (n = 3, q = 2). Within the recovery its
    // unchanged old leaf may produce a processing ACK (companion 8.4).
    let genesis = lapsing(T - 1, &[9])?;
    let previous = roster_id(&genesis.principal(1)?.roster)?;
    let next = successor(&genesis, 1, previous, SUCCESSOR, &[9])?;
    let facts = memberships(&genesis, &[(1, 9, CREATOR_LEAF_SEED, 0, [55; 32])])?;
    let mut recovery = Attempt::recovery(vec![(0, 7), (0, 8)], vec![&next]);
    recovery.memberships = Some(&facts);
    let (_, step) = finalize_at(&genesis, &recovery)?;
    assert!(matches!(step, ChainStep::Finalized { .. }));
    // The same ACK in a routine record is refused: no exception there.
    let mut routine = Attempt::routine(vec![(0, 7), (0, 8)]);
    routine.memberships = Some(&facts);
    assert!(finalize_at(&genesis, &routine).is_err());
    // An ACK from the device the successor drops is refused, as its vote is
    // (n = 4, q = 3).
    let genesis = lapsing(T - 1, &[9, 10])?;
    let previous = roster_id(&genesis.principal(1)?.roster)?;
    let next = successor(&genesis, 1, previous, SUCCESSOR, &[9])?;
    let facts = memberships(&genesis, &[(1, 10, CREATOR_LEAF_SEED, 0, [55; 32])])?;
    let mut removal = Attempt::recovery(vec![(0, 7), (0, 8), (1, 9)], vec![&next]);
    removal.bits = action_bits::ROSTER | action_bits::REMOVE_LEAF;
    removal.memberships = Some(&facts);
    assert!(finalize_at(&genesis, &removal).is_err());
    // Without the dropped device's ACK the same record finalizes.
    removal.memberships = None;
    finalize_at(&genesis, &removal)?;
    Ok(())
}
