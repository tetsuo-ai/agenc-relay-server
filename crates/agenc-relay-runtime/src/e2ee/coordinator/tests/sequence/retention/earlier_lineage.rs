//! Restore of directory stores written before the lineage rules (G-08,
//! storage generation 5): the rows of `test-data/stage-ten/e2ee-lineage/`,
//! written by the test harness of the start commit (`eb2b025`), which this
//! tree seals into a storage fixture and restores through the storage reads
//! a restart uses, and through the harness's reload for the requests that
//! follow.
//!
//! A head naming a roster the account replaced under the same root restores
//! against it and holds it from then on; a root that awaits its first roster
//! restores pending beside the roster it follows; a rotation stored with the
//! counters its coordinator admitted keeps them under its root; and a head
//! whose named roster the store no longer holds restores nothing.

#![forbid(unsafe_code)]

use super::super::reinit::successor::reconstruction::reconstruct;
use super::earlier_stores::{restarted_from, rows_of};
use super::*;
use crate::e2ee::coordinator::tests::support::{capabilities, roster};
use crate::e2ee::coordinator::tests::{DEVICE_ID, ROOT_SEED, account_param};
use agenc_relay_e2ee::ids::account_id_digest;
use agenc_relay_e2ee::limits::{MAX_IDENTITY_OBJECT, MAX_ROSTER_OBJECT};
use agenc_relay_e2ee::objects::identity::{
    ArcDeviceCapabilities, ArcDeviceRoster, ArcRootIdentity,
};
use agenc_relay_storage::e2ee_records::DirectoryRow;

/// The stores of this topic's fixtures.
const STORES: [&str; 4] = [
    "renewed-roster",
    "renewed-roster-expired",
    "root-pending",
    "rotated-continued",
];

fn rows(name: &str) -> TestResult<Vec<Write>> {
    rows_of("e2ee-lineage", name)
}

fn restarted(name: &str) -> TestResult<Harness> {
    restarted_from(rows(name)?)
}

/// The retained objects of `kind` that decode as `T`, with their identifiers.
fn stored<T: TlsDecode>(
    harness: &Harness,
    kind: ArcWireObjectKind,
    limit: usize,
) -> Vec<([u8; 32], T)> {
    harness
        .coordinator
        .state
        .objects
        .iter()
        .filter_map(|(id, bytes)| {
            let mut budget = DecodeBudget::new(limit, 1 << 16);
            let object = agenc_relay_e2ee::object::ArcWireObject::decode_kind(
                bytes,
                Some(kind),
                &mut budget,
            )
            .ok()?;
            Some((*id, T::decode_exact(object.body(), &mut budget).ok()?))
        })
        .collect()
}

/// The retained roster of `generation` signed under the root of
/// `root_generation`, with its object identifier.
fn roster_at(
    harness: &Harness,
    root_generation: u64,
    generation: u64,
) -> TestResult<([u8; 32], ArcDeviceRoster)> {
    stored::<ArcDeviceRoster>(harness, ArcWireObjectKind::DeviceRoster, MAX_ROSTER_OBJECT)
        .into_iter()
        .find(|(_, roster)| {
            (roster.tbs.root_generation, roster.tbs.roster_generation)
                == (root_generation, generation)
        })
        .ok_or_else(|| format!("roster {generation} of root {root_generation}").into())
}

/// The retained root identity of `generation`.
fn root_at(harness: &Harness, generation: u64) -> TestResult<ArcRootIdentity> {
    stored::<ArcRootIdentity>(
        harness,
        ArcWireObjectKind::RootIdentity,
        MAX_IDENTITY_OBJECT,
    )
    .into_iter()
    .map(|(_, root)| root)
    .find(|root| root.tbs.root_generation == generation)
    .ok_or_else(|| format!("root {generation}").into())
}

/// A restored capability head: its generation, identifier and the roster it
/// names.
type Head = (u64, [u8; 32], [u8; 32]);

/// The principal's root and roster generations and the pending root's
/// generation.
type Heads = (Option<(u64, u64)>, Option<u64>);

/// Device 7's restored capability head.
fn head(harness: &Harness) -> TestResult<Option<Head>> {
    let digest = account_id_digest(&NETWORK, &harness.account)?;
    Ok(harness
        .coordinator
        .state
        .directory
        .account(&digest)
        .and_then(|entry| entry.capabilities.get(&DEVICE_ID))
        .map(|head| (head.generation, head.capability_id, head.roster_id)))
}

/// The principal's restored root and roster generations and the pending
/// root's generation, if any.
fn heads(harness: &Harness) -> TestResult<Heads> {
    let digest = account_id_digest(&NETWORK, &harness.account)?;
    let state = &harness.coordinator.state;
    Ok((
        state
            .principals
            .get(&digest)
            .map(|(root, roster)| (root.generation, roster.generation)),
        state.pending_roots.get(&digest).map(|root| root.generation),
    ))
}

/// Publishes `value` under `op`, returning `None` when it is stored and its
/// refusal code otherwise.
fn publish(
    harness: &mut Harness,
    op: Op,
    params: &[u8],
    kind: ArcWireObjectKind,
    value: &impl TlsEncode,
) -> TestResult<Option<E2eeReplyCode>> {
    let bytes = wire(kind, value)?;
    Ok(code(harness.run(op, params, Some(&bytes))?))
}

/// Device 7's capability statement of `generation` naming `roster` and the
/// statement `previous`.
fn statement(
    roster: &ArcDeviceRoster,
    generation: u64,
    previous: [u8; 32],
) -> TestResult<ArcDeviceCapabilities> {
    Ok(capabilities(
        DEVICE,
        roster,
        generation,
        previous,
        (100, 200),
        vec![1, 3],
    )?)
}

/// The roster of `generation` naming `previous` under `root`, signed with
/// the key of `seed`, keeping device 7 certified for `target`.
fn roster_under(
    seed: u8,
    root: &ArcRootIdentity,
    generation: u64,
    previous: [u8; 32],
    target: u64,
) -> TestResult<ArcDeviceRoster> {
    let secret = key(seed);
    let spec = crate::e2ee::coordinator::tests::support::DeviceSpec {
        target_roster_generation: target,
        ..crate::e2ee::coordinator::tests::support::DeviceSpec::new(DEVICE)
    };
    Ok(roster(
        &secret,
        root,
        generation,
        previous,
        (100, 100 + 6 * 24 * 3600),
        vec![crate::e2ee::coordinator::tests::support::certificate(
            &secret, root, &spec,
        )?],
        Vec::new(),
    )?)
}

#[tokio::test]
async fn every_earlier_lineage_store_restores_from_sealed_storage() -> TestResult {
    for name in STORES {
        let (_, result) = Box::pin(reconstruct(&rows(name)?)).await?;
        assert!(result.is_ok(), "{name}: {result:?}");
    }
    Ok(())
}

#[test]
fn an_earlier_head_naming_the_replaced_roster_restores_and_holds_it() -> TestResult {
    let mut harness = restarted("renewed-roster")?;
    let (first_object, first) = roster_at(&harness, 0, 0)?;
    let (_, renewed) = roster_at(&harness, 0, 1)?;
    assert_eq!(heads(&harness)?, (Some((0, 1)), None));
    let (generation, capability_id, named) = head(&harness)?.ok_or("restored head")?;
    assert_eq!(
        (generation, named),
        (
            0,
            crate::e2ee::coordinator::tests::support::roster_id(&first)?
        )
    );
    // The earlier store records no holder of the replaced roster; the
    // restart derives that the capability row holds it.
    assert!(harness.coordinator.owner_reconstruction.mismatched > 0);
    let digest = account_id_digest(&NETWORK, &harness.account)?;
    let row = DirectoryRow::capability_key(&digest, &DEVICE_ID)?
        .as_bytes()
        .to_vec();
    assert_held_by(&harness, first_object, std::slice::from_ref(&row))?;
    // Expiry past every window keeps it. Until a batch next writes its
    // owner row, each restart derives the holding again and restores the
    // head.
    assert!(!expire(&mut harness, PAST_EVERY_WINDOW)?.contains(&first_object));
    let mut restarted = harness.reloaded()?;
    assert!(restarted.coordinator.owner_reconstruction.mismatched > 0);
    assert_held_by(&restarted, first_object, std::slice::from_ref(&row))?;
    assert_eq!(head(&restarted)?, head(&harness)?);
    // The device's next statement continues the head; a reset is refused.
    restarted.attach()?;
    let reset = statement(&renewed, 0, [0; 32])?;
    let next = statement(&renewed, 1, capability_id)?;
    for (value, expected) in [
        (&reset, Some(E2eeReplyCode::BindingAuthInvalid)),
        (&next, None),
    ] {
        assert_eq!(
            publish(
                &mut restarted,
                Op::PublishCapabilities,
                &DEVICE_ID,
                ArcWireObjectKind::DeviceCapabilities,
                value,
            )?,
            expected
        );
    }
    // That statement names the current roster: the replaced roster retires,
    // expiry collects it, and the next restart reconstructs clean.
    assert!(expire(&mut restarted, PAST_EVERY_WINDOW)?.contains(&first_object));
    let reopened = restarted.reloaded()?;
    assert!(reopened.coordinator.owner_reconstruction.is_clean());
    assert_eq!(
        head(&reopened)?.map(|(generation, _, _)| generation),
        Some(1)
    );
    Ok(())
}

#[test]
fn an_earlier_pending_root_restores_beside_the_roster_it_follows() -> TestResult {
    let mut harness = restarted("root-pending")?;
    // The account keeps its roster and capability head while the newer root
    // awaits its first roster.
    assert_eq!(heads(&harness)?, (Some((0, 0)), Some(1)));
    assert_eq!(
        head(&harness)?.map(|(generation, _, _)| generation),
        Some(0)
    );
    let (_, first) = roster_at(&harness, 0, 0)?;
    let continued = root_at(&harness, 1)?;
    let carried = roster_under(
        ROOT_SEED + 1,
        &continued,
        1,
        crate::e2ee::coordinator::tests::support::roster_id(&first)?,
        1,
    )?;
    let fresh = roster_under(ROOT_SEED + 1, &continued, 0, [0; 32], 0)?;
    for (value, expected) in [
        (&carried, Some(E2eeReplyCode::BindingAuthInvalid)),
        (&fresh, None),
    ] {
        assert_eq!(
            publish(
                &mut harness,
                Op::PublishRoster,
                &[],
                ArcWireObjectKind::DeviceRoster,
                value,
            )?,
            expected
        );
    }
    // The new root's first roster leaves no head of the old root.
    assert_eq!(heads(&harness)?, (Some((1, 0)), None));
    assert_eq!(head(&harness)?, None);
    Ok(())
}

#[test]
fn an_earlier_rotation_keeps_the_counters_it_was_admitted_with() -> TestResult {
    let mut harness = restarted("rotated-continued")?;
    // The rotation's roster continued the old root's counter; it restores
    // under its own root with the device's continued statement.
    assert_eq!(heads(&harness)?, (Some((1, 1)), None));
    let (generation, capability_id, _) = head(&harness)?.ok_or("restored head")?;
    assert_eq!(generation, 1);
    let (_, current) = roster_at(&harness, 1, 1)?;
    let continued = root_at(&harness, 1)?;
    // Under that root the next roster and statement advance by one from
    // the stored heads; a reset to generation zero is refused.
    let current_id = crate::e2ee::coordinator::tests::support::roster_id(&current)?;
    let reset = roster_under(ROOT_SEED + 1, &continued, 0, [0; 32], 0)?;
    let next = roster_under(ROOT_SEED + 1, &continued, 2, current_id, 1)?;
    for (value, expected) in [
        (&reset, Some(E2eeReplyCode::BindingAuthInvalid)),
        (&next, None),
    ] {
        assert_eq!(
            publish(
                &mut harness,
                Op::PublishRoster,
                &[],
                ArcWireObjectKind::DeviceRoster,
                value,
            )?,
            expected
        );
    }
    harness.attach()?;
    let following = statement(&next, 2, capability_id)?;
    assert_eq!(
        publish(
            &mut harness,
            Op::PublishCapabilities,
            &DEVICE_ID,
            ArcWireObjectKind::DeviceCapabilities,
            &following,
        )?,
        None
    );
    Ok(())
}

#[test]
fn an_earlier_head_whose_named_roster_was_collected_restores_nothing() -> TestResult {
    let mut harness = restarted("renewed-roster-expired")?;
    // Object expiry collected the replaced roster the head names, so the
    // head cannot be re-verified and restores nothing.
    assert!(roster_at(&harness, 0, 0).is_err());
    assert_eq!(heads(&harness)?, (Some((0, 1)), None));
    assert_eq!(head(&harness)?, None);
    let page = [account_param(&harness.account), vec![0]].concat();
    assert!(
        ok(harness.run(Op::FetchCapabilities, &page, None)?)?
            .responses
            .is_empty()
    );
    // Without a head the device's next statement is a generation-zero one.
    let (_, renewed) = roster_at(&harness, 0, 1)?;
    harness.attach()?;
    assert_eq!(
        publish(
            &mut harness,
            Op::PublishCapabilities,
            &DEVICE_ID,
            ArcWireObjectKind::DeviceCapabilities,
            &statement(&renewed, 0, [0; 32])?,
        )?,
        None
    );
    Ok(())
}
