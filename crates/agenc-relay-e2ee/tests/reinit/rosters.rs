#![forbid(unsafe_code)]

//! The successor rosters of a ReInit (companion 8.2, 9.4, 9.5 and 13.8): an
//! endpoint verifies the successor under the rosters the successor
//! context's own roster heads name, every head of an account the old context
//! also names carries the old head's root or a continuous successor of it,
//! and the successor binding's principals name those rosters. The vectors
//! rotate the root of account `d` continuously (`root-d-1.bin`), once at the
//! old suite and once with a suite change from `0x0001` to `0x0003`; the
//! rejection vectors carry a forged continuity signature, a fresh root, a
//! binding principal that keeps the old root, and a rotation of the
//! channel-authority root the old semantic route lock names.

use super::support::*;

use std::collections::BTreeMap;

use agenc_relay_e2ee::history::ChainStep;
use agenc_relay_e2ee::identity::{
    AccountIdBytes, VerifiedRoot, verify_first_contact_roster, verify_root_identity,
};
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::conversation::{
    ArcBindingChainEntry, ArcMlsContext, ArcPolicyChainEntry, ArcRosterHead,
};
use agenc_relay_e2ee::objects::identity::{ArcDeviceRoster, ArcRootIdentity};
use agenc_relay_e2ee::objects::reinit::ArcReInitTargetTbs;
use agenc_relay_e2ee::objects::sequencing::ArcSequencerRecord;
use agenc_relay_e2ee::reinit_target::{
    AuthorizedReinit, OldConversation, ReinitProposal, SuccessorRosters, check_carried_target,
    reconstruct_reinit_target,
};
use agenc_relay_e2ee::route::PrincipalRosters;
use agenc_relay_e2ee::{E2eeError, TlsDecode, TlsEncode, TlsVec};

const C: AccountIdBytes = [b'c'; 24];
const D: AccountIdBytes = [b'd'; 24];

type Chains = BTreeMap<AccountIdBytes, Vec<ArcRootIdentity>>;

/// One edit of a roster head.
type HeadEdit = (&'static str, fn(&mut ArcRosterHead));

/// One `root_identity` vector, decoded.
fn root(file: &str) -> TestResult<ArcRootIdentity> {
    let mut budget = budget();
    let object = ArcWireObject::decode_kind(
        &read(file)?,
        Some(ArcWireObjectKind::RootIdentity),
        &mut budget,
    )?;
    Ok(ArcRootIdentity::decode_exact(object.body(), &mut budget)?)
}

/// One `device_roster` vector, decoded.
fn roster(file: &str) -> TestResult<ArcDeviceRoster> {
    let mut budget = budget();
    let object = ArcWireObject::decode_kind(
        &read(file)?,
        Some(ArcWireObjectKind::DeviceRoster),
        &mut budget,
    )?;
    Ok(ArcDeviceRoster::decode_exact(object.body(), &mut budget)?)
}

/// The old conversation's rosters with `account`'s entry replaced by the
/// root in `root_file`, verified against `predecessor`, and the roster in
/// `roster_file`, admitted at first contact.
fn with_root(
    rosters: &PrincipalRosters,
    account: AccountIdBytes,
    (root_file, roster_file): (&str, &str),
    predecessor: Option<&VerifiedRoot>,
) -> TestResult<PrincipalRosters> {
    let network = network()?;
    let verified = verify_root_identity(&network, &root(root_file)?, predecessor)?;
    let roster = verify_first_contact_roster(&verified, &roster(roster_file)?, &[])?;
    let mut rosters = rosters.clone();
    rosters.insert(account, (verified, roster));
    Ok(rosters)
}

/// The old conversation's verified root of `account`.
fn old_root(account: AccountIdBytes) -> TestResult<VerifiedRoot> {
    let (_, rosters) = old_authority()?;
    Ok(rosters.get(&account).ok_or("no old root")?.0)
}

/// The successor rosters after `d`'s continuous rotation, and the chain that
/// carries `d` from its old root to the new one.
fn rotated_d() -> TestResult<(PrincipalRosters, Chains)> {
    let (_, old) = old_authority()?;
    let rosters = with_root(
        &old,
        D,
        ("root-d-1.bin", "roster-d-1.bin"),
        Some(&old_root(D)?),
    )?;
    let chains = BTreeMap::from([(D, vec![root("root-d.bin")?, root("root-d-1.bin")?])]);
    Ok((rosters, chains))
}

/// The Proposal fields of one reconstruction-only or logged successor.
fn proposal_of(extensions_file: &str) -> TestResult<(Vec<u8>, u16, Vec<u8>)> {
    Ok((
        hex(&entry(extensions_file, "group_id")?)?,
        entry(extensions_file, "cipher_suite")?.parse()?,
        read(extensions_file)?,
    ))
}

/// Reconstructs the successor of `extensions_file` under `rosters` and
/// `chains`, with the old conversation's own roster heads.
fn rebuilt(
    extensions_file: &str,
    rosters: &PrincipalRosters,
    chains: &Chains,
) -> TestResult<Result<agenc_relay_e2ee::reinit_target::ReinitTarget, E2eeError>> {
    let (group, suite, extensions) = proposal_of(extensions_file)?;
    reconstruct_under(
        &ReinitProposal {
            group_id: &group,
            version: 1,
            cipher_suite: suite,
            encoded_extensions: &extensions,
        },
        rosters,
        chains,
    )
}

/// Reconstructs the successor of `extensions_file` with the old context's
/// roster heads replaced by `old_heads`.
fn rebuilt_after(
    extensions_file: &str,
    old_heads: &[ArcRosterHead],
    rosters: &PrincipalRosters,
    chains: &Chains,
) -> TestResult<Result<agenc_relay_e2ee::reinit_target::ReinitTarget, E2eeError>> {
    let (group, suite, extensions) = proposal_of(extensions_file)?;
    let (binding, _) = old_authority()?;
    Ok(reconstruct_reinit_target(
        &network()?,
        &OldConversation {
            binding: &binding,
            roster_heads: old_heads,
        },
        &SuccessorRosters {
            rosters,
            root_chains: chains,
        },
        &ReinitProposal {
            group_id: &group,
            version: 1,
            cipher_suite: suite,
            encoded_extensions: &extensions,
        },
        &mut budget(),
    ))
}

#[test]
fn a_root_rotation_reinit_rebuilds_under_the_successor_rosters_and_activates() -> TestResult {
    let (rosters, chains) = rotated_d()?;
    let target = rebuilt("rotation-extensions.bin", &rosters, &chains)??;
    assert_eq!(target.tbs().encode()?, read("rotation-target.bin")?);
    assert_eq!(
        target.digest(),
        &id("rotation-target.bin", "target_context_digest")?
    );
    // The successor's roster heads name d's new root, which continues d's old
    // one, and its binding names d by that root.
    let d_root = &rosters.get(&D).ok_or("no d")?.0;
    assert_eq!(d_root.generation, 1);
    assert_eq!(d_root.fingerprint, id("root-d-1.bin", "root_fingerprint")?);
    assert_eq!(
        id("root-d-1.bin", "previous_root_fingerprint")?,
        old_root(D)?.fingerprint
    );

    // The old conversation activates it through the shared history: its old
    // council and controllers authorize and certify a successor named by the
    // new root, and the sequencer's check rebuilds the same target from the
    // carried bytes alone.
    let mut chain = activated_chain()?;
    advance(&mut chain, "rotation-record-02-reinit-candidate.bin")?;
    let finalization = "rotation-record-03-reinit-finalization.bin";
    advance(&mut chain, finalization)?;
    let authorized = AuthorizedReinit::from_proof(&finalization_proof(finalization)?)?;
    authorized.check_target(target.tbs())?;
    let attempt = attempt("rotation-attempt-0.bin")?;
    let (binding, _) = old_authority()?;
    let carried = authorized.check_attempt(&attempt, &binding, &mut budget())?;
    assert_eq!(&carried, target.carried());
    authorized.check_attempt_target(&attempt, &target)?;
    authorized.check_initial_commit(
        &read("rotation-initial-commit-0.bin")?,
        target.carried(),
        &mut budget(),
    )?;
    chain.bind_reinit_target(target.tbs())?;
    advance_attempt(
        &mut chain,
        "rotation-record-04-attempt-0-receipt.bin",
        "rotation-attempt-0.bin",
    )?;
    assert!(matches!(
        advance(&mut chain, "rotation-record-05-activation.bin")?,
        ChainStep::ReinitActivated { new_conversation_id, .. }
            if new_conversation_id == target.tbs().new_conversation_id
    ));

    // A later joiner accepts the rotated successor's entries.
    let ArcSequencerRecord::ReinitActivation(activation) =
        record("rotation-record-05-activation.bin")?
    else {
        return Err("not an activation".into());
    };
    let previous = ArcBindingChainEntry::decode_exact(
        &read("join-genesis-binding-entry.bin")?,
        &mut budget(),
    )?;
    let entry = ArcBindingChainEntry::decode_exact(
        &read("rotation-join-binding-entry.bin")?,
        &mut budget(),
    )?;
    let policy =
        ArcPolicyChainEntry::decode_exact(&read("rotation-join-policy-entry.bin")?, &mut budget())?;
    authorized.check_join_entries(&activation, &previous, &entry, &policy, &mut budget())?;
    Ok(())
}

#[test]
fn a_suite_change_reinit_moves_from_0x0001_to_0x0003() -> TestResult {
    let (binding, old) = old_authority()?;
    assert_eq!(binding.cipher_suite, 1);
    // The suite change alone, under the old conversation's rosters, which the
    // successor's heads name unchanged.
    let three = rebuilt("suite-0003-extensions.bin", &old, &BTreeMap::new())??;
    assert_eq!(three.tbs().target_suite, 3);
    assert_eq!(
        three.carried().context().current_binding.tbs.cipher_suite,
        3
    );
    assert_eq!(three.carried().context().policy.tbs.selected_suite, 3);
    assert_eq!(
        three.digest(),
        &id("suite-0003-target.bin", "target_context_digest")?
    );
    // The suite change together with d's root rotation.
    let (rosters, chains) = rotated_d()?;
    let both = rebuilt("rotation-0003-extensions.bin", &rosters, &chains)??;
    assert_eq!(both.tbs().encode()?, read("rotation-0003-target.bin")?);
    assert_eq!(both.tbs().target_suite, 3);
    assert_eq!(
        check_carried_target(&network()?, &binding, both.tbs(), &mut budget())?,
        *both.carried()
    );
    // Neither rebuilds under the other's rosters.
    assert!(rebuilt("rotation-0003-extensions.bin", &old, &BTreeMap::new())?.is_err());
    assert!(rebuilt("suite-0003-extensions.bin", &rosters, &chains)?.is_err());
    Ok(())
}

#[test]
fn the_successor_rosters_must_be_the_ones_its_roster_heads_name() -> TestResult {
    let (rosters, chains) = rotated_d()?;
    rebuilt("rotation-extensions.bin", &rosters, &chains)??;
    let (_, old) = old_authority()?;
    let (c_root, c_roster) = old.get(&C).ok_or("no c")?.clone();
    let mut extra = rosters.clone();
    extra.insert([b'e'; 24], (c_root, c_roster.clone()));
    let mut missing = rosters.clone();
    missing.remove(&C);
    let mut other_roster = rosters.clone();
    if let Some(entry) = other_roster.get_mut(&D) {
        entry.1 = old.get(&D).ok_or("no d")?.1.clone();
    }
    let mut other_generation = rosters.clone();
    if let Some(entry) = other_generation.get_mut(&C) {
        entry.1.generation = 1;
    }
    let fresh = with_root(&old, D, ("root-d-fresh.bin", "roster-d-fresh.bin"), None)?;
    for (name, supplied) in [
        ("the old conversation's rosters", &old),
        ("an extra roster", &extra),
        ("a missing roster", &missing),
        ("the old roster under the new root", &other_roster),
        ("another roster generation", &other_generation),
        ("another root of the account", &fresh),
    ] {
        assert_eq!(
            rebuilt("rotation-extensions.bin", supplied, &chains)?.err(),
            Some(E2eeError::InvalidValue),
            "{name}"
        );
    }

    // A successor head the rosters do not cover, and each field of d's head
    // naming something other than d's supplied root and roster, while the
    // binding's principals and the policy still name the supplied rosters:
    // only the comparison of heads and rosters refuses them.
    let (group, suite, extensions) = proposal_of("rotation-extensions.bin")?;
    let fields = |extensions: &[u8]| -> TestResult<Result<_, E2eeError>> {
        reconstruct_under(
            &ReinitProposal {
                group_id: &group,
                version: 1,
                cipher_suite: suite,
                encoded_extensions: extensions,
            },
            &rosters,
            &chains,
        )
    };
    let d_digest = agenc_relay_e2ee::ids::account_id_digest(&network()?, &D)?;
    let unrostered = with_heads(&extensions, |heads| {
        heads.push(ArcRosterHead {
            account_id_digest: [0xEE; 32],
            root_generation: 0,
            root_fingerprint: [0xEE; 32],
            roster_generation: 0,
            roster_id: [0xEE; 32],
        });
    })?;
    assert_eq!(
        fields(&unrostered)?.err(),
        Some(E2eeError::InvalidValue),
        "a head without a roster"
    );
    let head_edits: [HeadEdit; 4] = [
        ("root generation", |head| head.root_generation += 1),
        ("root fingerprint", |head| head.root_fingerprint = [9; 32]),
        ("roster generation", |head| head.roster_generation += 1),
        ("roster ID", |head| head.roster_id = [9; 32]),
    ];
    for (name, edit) in head_edits {
        let edited = with_heads(&extensions, |heads| {
            for head in heads.iter_mut() {
                if head.account_id_digest == d_digest {
                    edit(head);
                }
            }
        })?;
        assert_eq!(
            fields(&edited)?.err(),
            Some(E2eeError::InvalidValue),
            "d's head names another {name}"
        );
    }

    // Two heads for one account never name its roster, even when the head
    // count equals the roster count.
    let (group, suite, extensions) = proposal_of("rotation-extensions.bin")?;
    let c_digest = agenc_relay_e2ee::ids::account_id_digest(&network()?, &C)?;
    let doubled = with_heads(&extensions, |heads| {
        heads.retain(|head| head.account_id_digest == c_digest);
        if let Some(first) = heads.first().cloned() {
            let mut twin = first;
            twin.root_generation += 1;
            heads.push(twin);
        }
    })?;
    assert_eq!(
        reconstruct_under(
            &ReinitProposal {
                group_id: &group,
                version: 1,
                cipher_suite: suite,
                encoded_extensions: &doubled,
            },
            &rosters,
            &chains,
        )?
        .err(),
        Some(E2eeError::InvalidValue)
    );
    Ok(())
}

/// The extension list `extensions` with its context's roster heads edited by
/// `edit`. The context core does not cover the heads.
fn with_heads(
    extensions: &[u8],
    edit: impl FnOnce(&mut Vec<ArcRosterHead>),
) -> TestResult<Vec<u8>> {
    use agenc_relay_e2ee::mls_outer::{MlsReader, mls_varint_encode};
    let mut outer_budget = budget();
    let mut outer = MlsReader::new(extensions, &mut outer_budget);
    let body = outer.opaque_v()?.to_vec();
    outer.finish()?;
    let mut inner_budget = budget();
    let mut inner = MlsReader::new(&body, &mut inner_budget);
    let mut parts = Vec::new();
    while inner.remaining() > 0 {
        let extension_type = inner.u16()?;
        parts.push((extension_type, inner.opaque_v()?.to_vec()));
    }
    let mut edit = Some(edit);
    let mut out_body = Vec::new();
    for (extension_type, data) in parts {
        let data = if extension_type == 0xF1C1 {
            let mut context = ArcMlsContext::decode_exact(&data, &mut budget())?;
            let mut heads = context.roster_heads.as_slice().to_vec();
            if let Some(edit) = edit.take() {
                edit(&mut heads);
            }
            context.roster_heads = TlsVec::new(heads)?;
            context.encode()?
        } else {
            data
        };
        out_body.extend_from_slice(&extension_type.to_be_bytes());
        mls_varint_encode(&mut out_body, data.len())?;
        out_body.extend_from_slice(&data);
    }
    let mut out = Vec::new();
    mls_varint_encode(&mut out, out_body.len())?;
    out.extend_from_slice(&out_body);
    Ok(out)
}

#[test]
fn a_successor_root_must_continue_the_old_head_root() -> TestResult {
    let (rosters, chains) = rotated_d()?;
    rebuilt("rotation-extensions.bin", &rosters, &chains)??;
    let chain_of = |files: &[&str]| -> TestResult<Chains> {
        Ok(BTreeMap::from([(
            D,
            files
                .iter()
                .map(|file| root(file))
                .collect::<TestResult<Vec<_>>>()?,
        )]))
    };
    let cases: [(&str, Chains); 6] = [
        ("no chain", BTreeMap::new()),
        ("an empty chain", BTreeMap::from([(D, Vec::new())])),
        ("the new root alone", chain_of(&["root-d-1.bin"])?),
        ("the old root alone", chain_of(&["root-d.bin"])?),
        (
            "a chain from another account's root",
            chain_of(&["root-c.bin", "root-d-1.bin"])?,
        ),
        (
            "a chain to another root of the account",
            chain_of(&["root-d.bin", "root-d-fresh.bin"])?,
        ),
    ];
    for (name, supplied) in cases {
        assert!(
            rebuilt("rotation-extensions.bin", &rosters, &supplied)?.is_err(),
            "{name}"
        );
    }
    // A continuity signature by another key than d's old root: the same
    // generation-one root, so the same fingerprint the successor names.
    let forged = chain_of(&["root-d.bin", "reject-root-d-1-forged-continuity.bin"])?;
    assert_eq!(
        id("reject-root-d-1-forged-continuity.bin", "root_fingerprint")?,
        id("root-d-1.bin", "root_fingerprint")?
    );
    assert_eq!(
        rebuilt("rotation-extensions.bin", &rosters, &forged)?.err(),
        Some(E2eeError::SignatureInvalid)
    );
    assert_eq!(
        entry("reject-root-d-1-forged-continuity.bin", "expected")?,
        "E2eeError::SignatureInvalid"
    );

    // A successor naming a generation-zero root of d that does not continue
    // d's old root: no chain can carry the old root to it.
    let (_, old) = old_authority()?;
    let fresh = with_root(&old, D, ("root-d-fresh.bin", "roster-d-fresh.bin"), None)?;
    for (name, supplied) in [
        ("without a chain", BTreeMap::new()),
        (
            "with a chain to it",
            chain_of(&["root-d.bin", "root-d-fresh.bin"])?,
        ),
        (
            "with d's rotation",
            chain_of(&["root-d.bin", "root-d-1.bin"])?,
        ),
    ] {
        assert!(
            rebuilt(
                "reject-rotation-fresh-root-extensions.bin",
                &fresh,
                &supplied
            )?
            .is_err(),
            "{name}"
        );
    }

    // A rollback: the old context names d's rotated root, the successor its
    // older one.
    let rotated_heads = heads_of(&rosters)?;
    for (name, supplied) in [
        ("without a chain", BTreeMap::new()),
        (
            "with a reversed chain",
            chain_of(&["root-d-1.bin", "root-d.bin"])?,
        ),
    ] {
        assert!(
            rebuilt_after("suite-0001-extensions.bin", &rotated_heads, &old, &supplied)?.is_err(),
            "{name}"
        );
    }

    // A fork: the old context names another generation-one root of d, a
    // sibling of the rotation's root. A chain from d's generation-zero root
    // verifies and ends at the rotation's root, but does not start at the
    // root the old context names, and a chain from the sibling does not reach
    // the rotation's root.
    let sibling = id("root-d-1-sibling.bin", "root_fingerprint")?;
    assert_ne!(sibling, id("root-d-1.bin", "root_fingerprint")?);
    let d_digest = agenc_relay_e2ee::ids::account_id_digest(&network()?, &D)?;
    let mut forked = heads_of(&old)?;
    for head in &mut forked {
        if head.account_id_digest == d_digest {
            head.root_generation = 1;
            head.root_fingerprint = sibling;
        }
    }
    for (name, supplied) in [
        (
            "from the common ancestor",
            chain_of(&["root-d.bin", "root-d-1.bin"])?,
        ),
        (
            "from the sibling",
            chain_of(&["root-d-1-sibling.bin", "root-d-1.bin"])?,
        ),
    ] {
        assert!(
            rebuilt_after("rotation-extensions.bin", &forked, &rosters, &supplied)?.is_err(),
            "{name}"
        );
    }

    // Two old heads for one account name no single old root to continue.
    let old_heads = heads_of(&old)?;
    let mut doubled = old_heads.clone();
    doubled.extend(heads_of(&rosters)?.into_iter().filter(|head| {
        old_heads
            .iter()
            .all(|old| old.root_fingerprint != head.root_fingerprint)
    }));
    doubled.sort_by_key(|head| {
        (
            head.account_id_digest,
            head.root_generation,
            head.root_fingerprint,
        )
    });
    assert_eq!(
        rebuilt_after("rotation-extensions.bin", &doubled, &rosters, &chains)?.err(),
        Some(E2eeError::InvalidValue)
    );

    // An account the old context does not name needs no chain, and an
    // account whose root is unchanged needs none either.
    let only_c: Vec<ArcRosterHead> = heads_of(&old)?
        .into_iter()
        .filter(|head| {
            head.root_fingerprint
                == old
                    .get(&C)
                    .map(|(root, _)| root.fingerprint)
                    .unwrap_or_default()
        })
        .collect();
    assert_eq!(only_c.len(), 1);
    rebuilt_after(
        "rotation-extensions.bin",
        &only_c,
        &rosters,
        &BTreeMap::new(),
    )??;
    rebuilt("suite-0001-extensions.bin", &old, &BTreeMap::new())??;
    Ok(())
}

#[test]
fn the_successor_binding_principals_must_name_the_successor_rosters() -> TestResult {
    let (rosters, chains) = rotated_d()?;
    // The heads, policy and plan name d's new root while the binding keeps
    // d's old one.
    assert_eq!(
        rebuilt(
            "reject-rotation-stale-principal-extensions.bin",
            &rosters,
            &chains
        )?
        .err(),
        Some(E2eeError::InvalidValue)
    );
    Ok(())
}

#[test]
fn a_reinit_cannot_rotate_the_channel_authority_root() -> TestResult {
    // c's root is the channel-authority root the old semantic route names.
    // A successor that names c's continuously rotated root keeps that route
    // lock, so its binding names no root the lock's authority fingerprint
    // names: the reconstruction refuses it although c's continuity and every
    // structural rule hold (the limitation recorded under decision D-12).
    let (_, old) = old_authority()?;
    let c_old = old_root(C)?;
    let rosters = with_root(&old, C, ("root-c-1.bin", "roster-c-1.bin"), Some(&c_old))?;
    let chains = BTreeMap::from([(C, vec![root("root-c.bin")?, root("root-c-1.bin")?])]);
    let file = "reject-rotation-channel-authority-extensions.bin";
    assert_eq!(
        rebuilt(file, &rosters, &chains)?.err(),
        Some(E2eeError::InvalidValue)
    );
    assert_eq!(entry(file, "expected")?, "E2eeError::InvalidValue");
    let (binding, _) = old_authority()?;
    let agenc_relay_e2ee::route::SemanticRouteKey::Channel { authority_root, .. } =
        &binding.route.key
    else {
        return Err("the old conversation is a channel".into());
    };
    assert_eq!(*authority_root, c_old.fingerprint);
    // The structural rules alone accept it: only the binding's principals,
    // checked under the successor rosters, refuse it.
    let (group, suite, extensions) = proposal_of(file)?;
    let mut fields = Proposal::of(1)?;
    fields.group_id = group;
    fields.suite = suite;
    fields.extensions = extensions;
    let target = carried_tbs(&fields)?;
    check_carried_target(&network()?, &binding, &target, &mut budget())?;
    Ok(())
}

/// The target a sender carrying `proposal`'s list would build, read from
/// the list's own context and binding.
fn carried_tbs(proposal: &Proposal) -> TestResult<ArcReInitTargetTbs> {
    use agenc_relay_crypto::SemanticHashDomain;
    use agenc_relay_e2ee::ids::{conversation_id, semantic_id_of};
    use agenc_relay_e2ee::mls_outer::MlsReader;
    let mut outer_budget = budget();
    let mut outer = MlsReader::new(&proposal.extensions, &mut outer_budget);
    let body = outer.opaque_v()?.to_vec();
    let mut inner_budget = budget();
    let mut inner = MlsReader::new(&body, &mut inner_budget);
    let mut context = None;
    while inner.remaining() > 0 {
        let extension_type = inner.u16()?;
        let data = inner.opaque_v()?.to_vec();
        if extension_type == 0xF1C1 {
            context = Some(ArcMlsContext::decode_exact(&data, &mut budget())?);
        }
    }
    let context = context.ok_or("no context")?;
    let binding = &context.current_binding.tbs;
    let network = network()?;
    Ok(ArcReInitTargetTbs {
        profile_version: 1,
        network_id: network,
        old_conversation_id: old_conversation()?,
        new_conversation_id: conversation_id(&network, &proposal.group_id)?,
        target_group_id: agenc_relay_e2ee::Opaque::from_slice(&proposal.group_id)?,
        target_version: 1,
        target_suite: proposal.suite,
        target_context_core_id: binding.context_core_id,
        target_binding_id: semantic_id_of(SemanticHashDomain::BindingId, binding)?,
        initial_member_plan_id: binding.initial_member_plan_id,
        encoded_target_extensions: agenc_relay_e2ee::Opaque::from_slice(&proposal.extensions)?,
    })
}
