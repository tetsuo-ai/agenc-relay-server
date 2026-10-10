#![forbid(unsafe_code)]

//! `EKEY FETCH ROOT-CHAIN`, `CAPABILITIES` and `BINDING-LOCKS` hold more
//! than one batch of entries (companion 11.6): a root chain is one complete
//! contiguous chain object, the capability set pages in Device-ID order
//! with every active device exactly once, and a root's binding locks page
//! contiguously, each over one immutable cut.

use agenc_relay_crypto::SemanticHashDomain;
use agenc_relay_domain::e2ee::projection::{EmptyKind, StoreKind};
use agenc_relay_e2ee::ids::{account_id_digest, semantic_id_of};
use agenc_relay_e2ee::limits::MAX_BATCH_OBJECTS;
use agenc_relay_e2ee::object::ArcWireObject;
use agenc_relay_e2ee::objects::identity::{
    ArcAccountRootChain, ArcDeviceCapabilities, ArcRootIdentity,
};

use super::super::super::ROOT_SEED;
use super::super::super::support::{capabilities, root};
use super::*;
use crate::e2ee::coordinator::LockEntry;

/// Publishes roots of the harness account after its first until the chain
/// holds `count`, each continuing the one before; returns the chain.
fn publish_roots(harness: &mut Harness, count: usize) -> TestResult<Vec<ArcRootIdentity>> {
    let mut chain = vec![harness.principal.root.clone()];
    let mut seed = ROOT_SEED;
    while chain.len() < count {
        let previous = chain.last().ok_or("a root")?;
        let next_seed = seed.checked_add(1).ok_or("a root seed")?;
        let next = root(
            &key(next_seed),
            &harness.account,
            previous.tbs.root_generation + 1,
            (0, 2_000_000),
            Some((&key(seed), previous)),
        )?;
        let bytes = wire(ArcWireObjectKind::RootIdentity, &next)?;
        let outcome = ok(harness.run(Op::PublishIdentity, &[], Some(&bytes))?)?;
        assert_eq!(
            outcome.result,
            ResultBody::Stored(StoreKind::Identity, object_id(&bytes))
        );
        chain.push(next);
        seed = next_seed;
    }
    Ok(chain)
}

/// The roots of a root-chain page's one chain object.
fn chain_roots(page: &Page) -> TestResult<Vec<ArcRootIdentity>> {
    let [bytes] = page.objects.as_slice() else {
        return Err("a root-chain page holds one chain object".into());
    };
    let mut budget = DecodeBudget::new(1 << 21, 1 << 16);
    let object = ArcWireObject::decode_kind(
        bytes,
        Some(ArcWireObjectKind::RootIdentityChain),
        &mut budget,
    )?;
    Ok(
        ArcAccountRootChain::decode_exact(object.body(), &mut budget)?
            .roots
            .into_items(),
    )
}

#[test]
fn a_root_chain_longer_than_one_batch_is_one_complete_contiguous_page() -> TestResult {
    let mut harness = Harness::new()?;
    harness.publish_identity_and_roster()?;
    let roots = publish_roots(&mut harness, ENTRIES)?;
    let account = account_param(&harness.account);
    let from = |first: u64| [account.clone(), first.to_be_bytes().to_vec()].concat();
    let whole = pages(&mut harness, Op::FetchRootChain, &from(0))?;
    assert_eq!(counts(&whole), vec![1]);
    assert_eq!(chain_roots(whole.first().ok_or("a page")?)?, roots);
    let tail = pages(&mut harness, Op::FetchRootChain, &from(25))?;
    assert_eq!(
        chain_roots(tail.first().ok_or("a page")?)?.as_slice(),
        roots.get(25..).ok_or("a tail")?
    );
    let past = ok(harness.run(Op::FetchRootChain, &[from(40), vec![0]].concat(), None)?)?;
    assert_eq!(past.result, ResultBody::Empty(EmptyKind::RootChain));
    assert_eq!(
        harness.coordinator.state.listing_snapshots.cursors(),
        0,
        "a listing that fits one page keeps no cut"
    );
    Ok(())
}

/// A principal of `ENTRIES` devices: the harness device and those after it.
pub(super) fn many_devices() -> Vec<u8> {
    std::iter::once(DEVICE)
        .chain((100..).take(ENTRIES - 1))
        .collect()
}

/// A harness whose principal holds `devices` and whose councils hold only
/// the harness device, with its identity and roster published.
pub(super) fn provisioned(devices: &[u8]) -> TestResult<Harness> {
    let mut harness = Harness::with_councils(devices, &[DEVICE], &[DEVICE])?;
    harness.publish_identity_and_roster()?;
    Ok(harness)
}

/// Attaches each device in turn and publishes its statement of
/// `generation`; returns the statements' objects.
pub(super) fn publish_statements(
    harness: &mut Harness,
    devices: &[u8],
) -> TestResult<Vec<Vec<u8>>> {
    let roster = harness.principal.roster.clone();
    let mut statements = Vec::new();
    for device in devices {
        harness.attach_as(*device)?;
        let statement = capabilities(*device, &roster, 0, [0; 32], (100, 200), vec![1, 3])?;
        let bytes = wire(ArcWireObjectKind::DeviceCapabilities, &statement)?;
        let outcome = ok(harness.run(Op::PublishCapabilities, &[*device; 16], Some(&bytes))?)?;
        assert_eq!(
            outcome.result,
            ResultBody::Stored(StoreKind::Capabilities, object_id(&bytes))
        );
        statements.push(bytes);
    }
    Ok(statements)
}

fn statement(bytes: &[u8]) -> TestResult<ArcDeviceCapabilities> {
    let mut budget = DecodeBudget::new(1 << 17, 1 << 12);
    let object = ArcWireObject::decode_kind(
        bytes,
        Some(ArcWireObjectKind::DeviceCapabilities),
        &mut budget,
    )?;
    Ok(ArcDeviceCapabilities::decode_exact(
        object.body(),
        &mut budget,
    )?)
}

#[test]
fn capabilities_page_every_active_device_once_over_one_immutable_cut() -> TestResult {
    let devices = many_devices();
    let mut harness = provisioned(&devices)?;
    let statements = publish_statements(&mut harness, &devices)?;
    let prefix = account_param(&harness.account);
    let first = page(&mut harness, Op::FetchCapabilities, &prefix, None)?;
    assert_eq!(first.objects.len(), MAX_BATCH_OBJECTS);
    // The last device publishes its next statement between the pages.
    let last = *devices.last().ok_or("a device")?;
    let previous = statement(statements.last().ok_or("a statement")?)?;
    let next = capabilities(
        last,
        &harness.principal.roster,
        1,
        semantic_id_of(SemanticHashDomain::CapabilityId, &previous.tbs)?,
        (100, 200),
        vec![1, 3],
    )?;
    let next_bytes = wire(ArcWireObjectKind::DeviceCapabilities, &next)?;
    ok(harness.run(Op::PublishCapabilities, &[last; 16], Some(&next_bytes))?)?;
    let second = page(&mut harness, Op::FetchCapabilities, &prefix, first.next)?;
    assert_eq!(second.snapshot, first.snapshot);
    assert_eq!(second.next, None);
    assert_eq!(second.objects.len(), ENTRIES - MAX_BATCH_OBJECTS);
    let cut = [first.objects, second.objects].concat();
    assert_eq!(cut, statements, "the cut keeps the statement it captured");
    // Complete-set validation: every active device of the current roster
    // exactly once, in Device-ID order, each naming that roster.
    let roster_id = super::super::super::support::roster_id(&harness.principal.roster)?;
    let named: Vec<[u8; 16]> = cut
        .iter()
        .map(|bytes| {
            let statement = statement(bytes)?;
            assert_eq!(statement.tbs.roster_id, roster_id);
            Ok(statement.tbs.device_id)
        })
        .collect::<TestResult<_>>()?;
    let mut expected: Vec<[u8; 16]> = devices.iter().map(|device| [*device; 16]).collect();
    expected.sort_unstable();
    assert_eq!(named, expected);
    // A new cut holds the device's next statement.
    let fresh = pages(&mut harness, Op::FetchCapabilities, &prefix)?;
    assert_eq!(objects(&fresh).last(), Some(&next_bytes));
    assert_eq!(harness.coordinator.state.listing_snapshots.cursors(), 0);
    Ok(())
}

/// Retains `count` binding locks of the harness root after its bound
/// chain, from sequence `from`; returns their objects.
pub(in crate::e2ee::coordinator::tests) fn seed_locks(
    harness: &mut Harness,
    from: u64,
    count: u64,
) -> TestResult<Vec<Vec<u8>>> {
    let digest = account_id_digest(&NETWORK, &harness.account)?;
    let fingerprint = root_fingerprint(&harness.principal.root)?;
    let mut locks = Vec::new();
    for sequence in from..from + count {
        let bytes = object_of(ArcWireObjectKind::RootBindingLock, 300, sequence)?;
        let object_id = retain(harness, bytes.clone());
        harness
            .coordinator
            .state
            .binding_locks
            .entry((digest, fingerprint))
            .or_default()
            .insert(
                sequence,
                LockEntry {
                    lock_id: [u8::try_from(sequence % 256)?; 32],
                    object_id,
                },
            );
        locks.push(bytes);
    }
    Ok(locks)
}

/// The parameters of `EKEY FETCH BINDING-LOCKS` of the harness root from
/// `first`.
pub(in crate::e2ee::coordinator::tests) fn locks_from(
    harness: &Harness,
    first: u64,
) -> TestResult<Vec<u8>> {
    Ok([
        account_param(&harness.account),
        root_fingerprint(&harness.principal.root)?.to_vec(),
        first.to_be_bytes().to_vec(),
    ]
    .concat())
}

#[test]
fn binding_locks_page_one_roots_chain_contiguously_over_one_immutable_cut() -> TestResult {
    let mut harness = Harness::new()?;
    harness.bind_channel()?;
    let bound = harness
        .coordinator
        .state
        .binding_locks
        .values()
        .flat_map(|chain| chain.values())
        .map(|entry| entry.object_id)
        .collect::<Vec<_>>();
    assert_eq!(
        bound.len(),
        1,
        "the bound channel locks the harness root once"
    );
    let mut locks = vec![
        harness
            .coordinator
            .state
            .objects
            .get(bound.first().ok_or("a lock")?)
            .cloned()
            .ok_or("the bound lock object")?,
    ];
    locks.extend(seed_locks(&mut harness, 1, ENTRIES as u64 - 1)?);
    let prefix = locks_from(&harness, 0)?;
    let first = page(&mut harness, Op::FetchBindingLocks, &prefix, None)?;
    assert_eq!(first.objects.len(), MAX_BATCH_OBJECTS);
    // The chain grows between the pages.
    let later = seed_locks(&mut harness, ENTRIES as u64, 1)?;
    let second = page(&mut harness, Op::FetchBindingLocks, &prefix, first.next)?;
    assert_eq!(second.snapshot, first.snapshot);
    assert_eq!(second.next, None);
    assert_eq!([first.objects, second.objects].concat(), locks);
    // A later first position pages the rest of the chain, the growth included.
    let tail = locks_from(&harness, 30)?;
    let rest = pages(&mut harness, Op::FetchBindingLocks, &tail)?;
    assert_eq!(
        objects(&rest),
        [locks.get(30..).ok_or("a tail")?.to_vec(), later].concat()
    );
    // Another root's chain is empty.
    let other = [
        account_param(&harness.account),
        vec![0x77; 32],
        0_u64.to_be_bytes().to_vec(),
        vec![0],
    ]
    .concat();
    assert_eq!(
        ok(harness.run(Op::FetchBindingLocks, &other, None)?)?.result,
        ResultBody::Empty(EmptyKind::BindingLock)
    );
    Ok(())
}

/// A gap in a root's lock chain ends the contiguous run it begins.
#[test]
fn a_binding_lock_run_ends_at_the_first_gap() -> TestResult {
    let mut harness = Harness::new()?;
    harness.bind_channel()?;
    let early = seed_locks(&mut harness, 1, 3)?;
    seed_locks(&mut harness, 5, 3)?;
    let prefix = locks_from(&harness, 1)?;
    let run = pages(&mut harness, Op::FetchBindingLocks, &prefix)?;
    assert_eq!(objects(&run), early);
    Ok(())
}
