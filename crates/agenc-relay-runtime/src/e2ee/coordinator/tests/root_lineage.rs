#![forbid(unsafe_code)]

//! A continuous root rotation through the directory handlers (companion 8.2,
//! 8.4, 8.5, 11.6 and 14): the new root's roster and capability lineages
//! start at generation zero with all-zero predecessors, a same-root successor
//! advances its head by exactly one, and attachment counters keep their
//! account and device scope. While the new root awaits its first roster the
//! account keeps its roster, devices and capability heads, and a restart
//! rebuilds that state, and every later one, exactly as the live handlers
//! left it, so the next publications are admitted and refused alike.

use super::*;
use agenc_relay_crypto::SemanticHashDomain;
use agenc_relay_domain::e2ee::directory::AccountEntry;
use agenc_relay_e2ee::ids::semantic_id_of;
use agenc_relay_e2ee::objects::identity::{
    ArcDeviceCapabilities, ArcDeviceRoster, ArcRootIdentity,
};

/// The signing seed of the account's continued root.
const NEXT_ROOT_SEED: u8 = ROOT_SEED + 1;
/// A second device of the account.
const SECOND_DEVICE: u8 = 8;

/// One root of the harness account: its signing seed and its identity.
#[derive(Clone)]
struct AccountRoot {
    seed: u8,
    root: ArcRootIdentity,
}

impl AccountRoot {
    /// The root the harness provisions, at generation zero.
    fn first(harness: &Harness) -> Self {
        Self {
            seed: ROOT_SEED,
            root: harness.principal.root.clone(),
        }
    }

    /// The continuous successor of this root, signed with `seed` and
    /// continuity-signed by this root (companion 8.2).
    fn next(&self, harness: &Harness, seed: u8) -> TestResult<Self> {
        let root = support::root(
            &key(seed),
            &harness.account,
            self.root.tbs.root_generation + 1,
            (0, 2_000_000),
            Some((&key(self.seed), &self.root)),
        )?;
        Ok(Self { seed, root })
    }

    /// This root's roster of `generation` naming `previous`, with each
    /// `(device, target generation)` certified as `principal` certifies it,
    /// so a device continuing under the same root keeps its certificate.
    fn roster(
        &self,
        generation: u64,
        previous: [u8; 32],
        devices: &[(u8, u64)],
    ) -> TestResult<ArcDeviceRoster> {
        let secret = key(self.seed);
        let mut certificates = devices
            .iter()
            .map(|(seed, target)| {
                let spec = DeviceSpec {
                    target_roster_generation: *target,
                    ..DeviceSpec::new(*seed)
                };
                certificate(&secret, &self.root, &spec)
            })
            .collect::<Result<Vec<_>, _>>()?;
        certificates.sort_by_key(|certificate| certificate.tbs.device_id);
        Ok(support::roster(
            &secret,
            &self.root,
            generation,
            previous,
            (100, 100 + 6 * 24 * 3600),
            certificates,
            Vec::new(),
        )?)
    }
}

/// Device `seed`'s capability statement of `generation` naming `roster` and
/// the previous statement `previous`.
fn statement(
    seed: u8,
    roster: &ArcDeviceRoster,
    generation: u64,
    previous: [u8; 32],
) -> TestResult<ArcDeviceCapabilities> {
    Ok(capabilities(
        seed,
        roster,
        generation,
        previous,
        (100, 200),
        vec![1, 3],
    )?)
}

fn capability_id(statement: &ArcDeviceCapabilities) -> TestResult<[u8; 32]> {
    Ok(semantic_id_of(
        SemanticHashDomain::CapabilityId,
        &statement.tbs,
    )?)
}

/// The publication of `root`, `roster` or `statement` objects.
enum Publication<'a> {
    Root(&'a ArcRootIdentity),
    Roster(&'a ArcDeviceRoster),
    Capabilities(u8, &'a ArcDeviceCapabilities),
}

impl Publication<'_> {
    /// Runs the publication, returning `None` when it is stored and its
    /// refusal code otherwise.
    fn run(&self, harness: &mut Harness) -> TestResult<Option<E2eeReplyCode>> {
        let (op, params, kind, bytes) = match self {
            Self::Root(root) => (
                Op::PublishIdentity,
                Vec::new(),
                StoreKind::Identity,
                wire(ArcWireObjectKind::RootIdentity, *root)?,
            ),
            Self::Roster(roster) => (
                Op::PublishRoster,
                Vec::new(),
                StoreKind::Roster,
                wire(ArcWireObjectKind::DeviceRoster, *roster)?,
            ),
            Self::Capabilities(seed, statement) => (
                Op::PublishCapabilities,
                vec![*seed; 16],
                StoreKind::Capabilities,
                wire(ArcWireObjectKind::DeviceCapabilities, *statement)?,
            ),
        };
        match harness.run(op, &params, Some(&bytes))? {
            Ok(outcome) => {
                assert_eq!(outcome.result, ResultBody::Stored(kind, object_id(&bytes)));
                Ok(None)
            }
            Err(fail) => Ok(Some(fail.code)),
        }
    }

    /// Runs the publication and requires it to be stored.
    fn stored(&self, harness: &mut Harness) -> TestResult {
        match self.run(harness)? {
            None => Ok(()),
            Some(code) => Err(format!("refused with {code:?}").into()),
        }
    }
}

/// The account's directory entry, principal heads, pending root and
/// capability predecessors, as one comparable view.
#[derive(Debug, Eq, PartialEq)]
struct View {
    entry: Option<AccountEntry>,
    principal: Option<([u8; 32], u64, [u8; 32])>,
    pending: Option<[u8; 32]>,
    heads: Vec<([u8; 16], u64, [u8; 32])>,
}

fn view(harness: &Harness) -> TestResult<View> {
    let digest = account_id_digest(&NETWORK, &harness.account)?;
    let state = &harness.coordinator.state;
    Ok(View {
        entry: state.directory.account(&digest).cloned(),
        principal: state
            .principals
            .get(&digest)
            .map(|(root, roster)| (root.fingerprint, roster.generation, roster.roster_id)),
        pending: state
            .pending_roots
            .get(&digest)
            .map(|root| root.fingerprint),
        heads: state
            .capabilities
            .iter()
            .filter(|((account, _), _)| *account == digest)
            .map(|((_, device), head)| (*device, head.generation, head.capability_id))
            .collect(),
    })
}

/// Whether the harness store holds device `seed`'s capability row.
fn capability_row(harness: &Harness, seed: u8) -> TestResult<bool> {
    use crate::state_core::durable::AccountServiceDurableWrite as Write;
    let digest = account_id_digest(&NETWORK, &harness.account)?;
    let key =
        agenc_relay_storage::e2ee_records::DirectoryRow::capability_key(&digest, &[seed; 16])?;
    Ok(harness
        .writes
        .iter()
        .any(|write| matches!(write, Write::Put { key: stored, .. } if *stored == key)))
}

/// The objects one fetch answers with, or nothing for an empty answer.
fn fetched(harness: &mut Harness, op: Op, params: &[u8]) -> TestResult<Vec<Vec<u8>>> {
    let outcome = ok(harness.run(op, params, None)?)?;
    Ok(outcome
        .responses
        .into_iter()
        .map(|response| response.bytes)
        .collect())
}

/// What a client reads about the account: its root, root chain, roster and
/// capability statements.
fn directory_reads(harness: &mut Harness) -> TestResult<Vec<Vec<Vec<u8>>>> {
    let account = account_param(&harness.account);
    Ok(vec![
        fetched(harness, Op::FetchIdentity, &account)?,
        fetched(
            harness,
            Op::FetchRootChain,
            &[account.clone(), vec![0; 8], vec![0]].concat(),
        )?,
        fetched(harness, Op::FetchRoster, &account)?,
        fetched(harness, Op::FetchCapabilities, &[account, vec![0]].concat())?,
    ])
}

/// Requires the restart of `harness` to hold exactly its live state and to
/// answer every directory read alike, and returns the restarted harness.
fn restarted_alike(harness: &mut Harness) -> TestResult<Harness> {
    let mut restarted = harness.reloaded()?;
    assert_eq!(view(&restarted)?, view(harness)?);
    assert_eq!(directory_reads(&mut restarted)?, directory_reads(harness)?);
    Ok(restarted)
}

/// A provisioned account: the first root, its roster of `devices`, device 7
/// attached and its generation-zero capability statement published.
fn provisioned(devices: &[u8]) -> TestResult<(Harness, ArcDeviceCapabilities)> {
    let mut harness = Harness::with_devices(devices)?;
    harness.publish_identity_and_roster()?;
    harness.attach()?;
    let first = statement(DEVICE, &harness.principal.roster, 0, [0; 32])?;
    Publication::Capabilities(DEVICE, &first).stored(&mut harness)?;
    Ok((harness, first))
}

#[test]
fn a_rotated_root_starts_its_roster_and_capability_lineages_at_zero() -> TestResult {
    let (mut harness, first) = provisioned(&[DEVICE])?;
    let old = AccountRoot::first(&harness);
    let old_roster = harness.principal.roster.clone();
    let rotated = old.next(&harness, NEXT_ROOT_SEED)?;
    Publication::Root(&rotated.root).stored(&mut harness)?;
    // The old root's roster counter does not continue under the new root.
    let continued = rotated.roster(1, support::roster_id(&old_roster)?, &[(DEVICE, 1)])?;
    assert_eq!(
        Publication::Roster(&continued).run(&mut harness)?,
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    // A roster is signed under the newest root.
    let stale = old.roster(1, support::roster_id(&old_roster)?, &[(DEVICE, 0)])?;
    assert_eq!(
        Publication::Roster(&stale).run(&mut harness)?,
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    assert!(capability_row(&harness, DEVICE)?);
    let fresh = rotated.roster(0, [0; 32], &[(DEVICE, 0)])?;
    Publication::Roster(&fresh).stored(&mut harness)?;
    // The new root's first roster keeps no capability head of the old root,
    // in memory or in storage.
    assert!(!capability_row(&harness, DEVICE)?);
    let account = account_param(&harness.account);
    assert!(
        fetched(
            &mut harness,
            Op::FetchCapabilities,
            &[account, vec![0]].concat()
        )?
        .is_empty()
    );
    // Nor does the device's capability counter continue.
    let carried = statement(DEVICE, &fresh, 1, capability_id(&first)?)?;
    assert_eq!(
        Publication::Capabilities(DEVICE, &carried).run(&mut harness)?,
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    let restarted_first = statement(DEVICE, &fresh, 0, [0; 32])?;
    Publication::Capabilities(DEVICE, &restarted_first).stored(&mut harness)?;
    // Under the new root, successors advance by exactly one again.
    let next = rotated.roster(1, support::roster_id(&fresh)?, &[(DEVICE, 0)])?;
    Publication::Roster(&next).stored(&mut harness)?;
    let following = statement(DEVICE, &next, 1, capability_id(&restarted_first)?)?;
    Publication::Capabilities(DEVICE, &following).stored(&mut harness)?;
    restarted_alike(&mut harness)?;
    Ok(())
}

#[test]
fn a_restart_at_each_step_of_a_rotation_rebuilds_the_live_state() -> TestResult {
    let (harness, first) = provisioned(&[DEVICE])?;
    let old = AccountRoot::first(&harness);
    let old_roster = harness.principal.roster.clone();
    let rotated = old.next(&harness, NEXT_ROOT_SEED)?;
    let fresh = rotated.roster(0, [0; 32], &[(DEVICE, 0)])?;
    let continued = rotated.roster(1, support::roster_id(&old_roster)?, &[(DEVICE, 1)])?;
    let new_first = statement(DEVICE, &fresh, 0, [0; 32])?;
    let carried = statement(DEVICE, &fresh, 1, capability_id(&first)?)?;
    let new_next = statement(DEVICE, &fresh, 1, capability_id(&new_first)?)?;
    let steps = [
        Publication::Root(&rotated.root),
        Publication::Roster(&fresh),
        Publication::Capabilities(DEVICE, &new_first),
        Publication::Capabilities(DEVICE, &new_next),
    ];
    // After each step a restarted coordinator refuses, as the live one
    // does, the old root's counters continued under the new root, and
    // stores the next step as the live one does.
    let probes = [
        Publication::Roster(&continued),
        Publication::Capabilities(DEVICE, &carried),
    ];
    for done in 1..=steps.len() {
        let mut live = harness.reloaded()?;
        for step in steps.iter().take(done) {
            step.stored(&mut live)?;
        }
        let mut restarted = restarted_alike(&mut live)?;
        for probe in &probes {
            let refused = probe.run(&mut live)?;
            assert!(refused.is_some(), "after step {done}");
            assert_eq!(probe.run(&mut restarted)?, refused, "after step {done}");
        }
        if let Some(next) = steps.get(done) {
            next.stored(&mut live)?;
            next.stored(&mut restarted)?;
            assert_eq!(view(&restarted)?, view(&live)?, "after step {}", done + 1);
        }
    }
    Ok(())
}

#[test]
fn while_the_new_root_awaits_its_roster_the_account_keeps_its_devices() -> TestResult {
    let (mut harness, first) = provisioned(&[DEVICE])?;
    let rotated = AccountRoot::first(&harness).next(&harness, NEXT_ROOT_SEED)?;
    let before = view(&harness)?;
    Publication::Root(&rotated.root).stored(&mut harness)?;
    let pending = view(&harness)?;
    // The new root waits beside the unchanged roster and capability heads.
    assert_eq!(pending.principal, before.principal);
    assert_eq!(pending.heads, before.heads);
    assert_eq!(
        pending.pending,
        Some(support::root_fingerprint(&rotated.root)?)
    );
    let mut restarted = restarted_alike(&mut harness)?;
    // The device stays attached and active: it continues its statement
    // under the roster the account still holds, live and after the restart.
    for coordinator in [&mut harness, &mut restarted] {
        let next = statement(
            DEVICE,
            &coordinator.principal.roster,
            1,
            capability_id(&first)?,
        )?;
        Publication::Capabilities(DEVICE, &next).stored(coordinator)?;
        assert_eq!(coordinator.attach()?.0, 2);
    }
    assert_eq!(view(&restarted)?, view(&harness)?);
    Ok(())
}

#[test]
fn a_same_root_successor_advances_by_exactly_one() -> TestResult {
    let (mut harness, first) = provisioned(&[DEVICE])?;
    let root = AccountRoot::first(&harness);
    let roster = harness.principal.roster.clone();
    let renewed = root.roster(1, support::roster_id(&roster)?, &[(DEVICE, 0)])?;
    let next = statement(DEVICE, &renewed, 1, capability_id(&first)?)?;
    let restarted = restarted_alike(&mut harness)?;
    for mut coordinator in [harness, restarted] {
        // A roster reset, a skipped generation and a second generation-zero
        // roster of the same root are refused.
        let reset = root.roster(0, [0; 32], &[(DEVICE, 0)])?;
        let skipped = root.roster(2, support::roster_id(&roster)?, &[(DEVICE, 0)])?;
        for refused in [&reset, &skipped] {
            assert!(
                Publication::Roster(refused)
                    .run(&mut coordinator)?
                    .is_some()
            );
        }
        Publication::Roster(&renewed).stored(&mut coordinator)?;
        // A capability reset, gap and fork are refused.
        let reset = statement(DEVICE, &renewed, 0, [0; 32])?;
        let gap = statement(DEVICE, &renewed, 2, capability_id(&first)?)?;
        for refused in [&reset, &gap] {
            assert!(
                Publication::Capabilities(DEVICE, refused)
                    .run(&mut coordinator)?
                    .is_some()
            );
        }
        Publication::Capabilities(DEVICE, &next).stored(&mut coordinator)?;
        let fork = capabilities(
            DEVICE,
            &renewed,
            1,
            capability_id(&first)?,
            (120, 220),
            vec![1],
        )?;
        assert!(
            Publication::Capabilities(DEVICE, &fork)
                .run(&mut coordinator)?
                .is_some()
        );
    }
    Ok(())
}

#[test]
fn a_device_leaving_the_roster_leaves_no_capability_head() -> TestResult {
    let (mut harness, _) = provisioned(&[DEVICE, SECOND_DEVICE])?;
    harness.attach_as(SECOND_DEVICE)?;
    let roster = harness.principal.roster.clone();
    let second = statement(SECOND_DEVICE, &roster, 0, [0; 32])?;
    Publication::Capabilities(SECOND_DEVICE, &second).stored(&mut harness)?;
    harness.attach_as(DEVICE)?;
    let root = AccountRoot::first(&harness);
    let without = root.roster(1, support::roster_id(&roster)?, &[(DEVICE, 0)])?;
    Publication::Roster(&without).stored(&mut harness)?;
    // The head of the device the roster revoked leaves memory and storage in
    // the roster's batch; the remaining device keeps its head.
    assert!(!capability_row(&harness, SECOND_DEVICE)?);
    assert!(capability_row(&harness, DEVICE)?);
    let heads: Vec<[u8; 16]> = view(&harness)?
        .heads
        .iter()
        .map(|(device, _, _)| *device)
        .collect();
    assert_eq!(heads, vec![DEVICE_ID]);
    restarted_alike(&mut harness)?;
    Ok(())
}

#[test]
fn a_restart_keeps_a_head_that_names_a_superseded_roster() -> TestResult {
    let (mut harness, first) = provisioned(&[DEVICE])?;
    let roster = harness.principal.roster.clone();
    let renewed =
        AccountRoot::first(&harness).roster(1, support::roster_id(&roster)?, &[(DEVICE, 0)])?;
    Publication::Roster(&renewed).stored(&mut harness)?;
    // The head names the replaced roster: no current statement, yet the
    // head the device's next statement continues (companion 8.5 and 14).
    let page = [account_param(&harness.account), vec![0]].concat();
    assert!(fetched(&mut harness, Op::FetchCapabilities, &page)?.is_empty());
    let restarted = restarted_alike(&mut harness)?;
    let next = statement(DEVICE, &renewed, 1, capability_id(&first)?)?;
    let reset = statement(DEVICE, &renewed, 0, [0; 32])?;
    let gap = statement(DEVICE, &renewed, 2, capability_id(&first)?)?;
    let fork = capabilities(
        DEVICE,
        &renewed,
        1,
        capability_id(&first)?,
        (120, 220),
        vec![1],
    )?;
    let listed = wire(ArcWireObjectKind::DeviceCapabilities, &next)?;
    for mut coordinator in [harness, restarted] {
        for refused in [&reset, &gap] {
            assert!(
                Publication::Capabilities(DEVICE, refused)
                    .run(&mut coordinator)?
                    .is_some()
            );
        }
        Publication::Capabilities(DEVICE, &next).stored(&mut coordinator)?;
        assert!(
            Publication::Capabilities(DEVICE, &fork)
                .run(&mut coordinator)?
                .is_some()
        );
        assert_eq!(
            fetched(&mut coordinator, Op::FetchCapabilities, &page)?,
            vec![listed.clone()]
        );
    }
    Ok(())
}

#[test]
fn a_capability_page_lists_only_statements_naming_the_current_roster() -> TestResult {
    let (mut harness, first) = provisioned(&[DEVICE, SECOND_DEVICE])?;
    harness.attach_as(SECOND_DEVICE)?;
    let roster = harness.principal.roster.clone();
    let second = statement(SECOND_DEVICE, &roster, 0, [0; 32])?;
    Publication::Capabilities(SECOND_DEVICE, &second).stored(&mut harness)?;
    let renewed = AccountRoot::first(&harness).roster(
        1,
        support::roster_id(&roster)?,
        &[(DEVICE, 0), (SECOND_DEVICE, 0)],
    )?;
    Publication::Roster(&renewed).stored(&mut harness)?;
    harness.attach_as(DEVICE)?;
    let next = statement(DEVICE, &renewed, 1, capability_id(&first)?)?;
    Publication::Capabilities(DEVICE, &next).stored(&mut harness)?;
    let page = [account_param(&harness.account), vec![0]].concat();
    let mut restarted = restarted_alike(&mut harness)?;
    let following = statement(SECOND_DEVICE, &renewed, 1, capability_id(&second)?)?;
    for coordinator in [&mut harness, &mut restarted] {
        // Only device 7's statement names the current roster; device 8's
        // head, which names the replaced one, is left out of the page and
        // continued by its next statement.
        assert_eq!(
            fetched(coordinator, Op::FetchCapabilities, &page)?,
            vec![wire(ArcWireObjectKind::DeviceCapabilities, &next)?]
        );
        coordinator.attach_as(SECOND_DEVICE)?;
        Publication::Capabilities(SECOND_DEVICE, &following).stored(coordinator)?;
        assert_eq!(fetched(coordinator, Op::FetchCapabilities, &page)?.len(), 2);
    }
    Ok(())
}

#[test]
fn attachment_counters_outlive_a_rotation() -> TestResult {
    let (mut harness, _) = provisioned(&[DEVICE, SECOND_DEVICE])?;
    assert_eq!(harness.attach_as(SECOND_DEVICE)?.0, 1);
    harness.attach_as(DEVICE)?;
    let rotated = AccountRoot::first(&harness).next(&harness, NEXT_ROOT_SEED)?;
    Publication::Root(&rotated.root).stored(&mut harness)?;
    // The new root's first roster leaves out the second device, and its
    // next one enrolls it again under the new root.
    let fresh = rotated.roster(0, [0; 32], &[(DEVICE, 0)])?;
    Publication::Roster(&fresh).stored(&mut harness)?;
    let returned = rotated.roster(
        1,
        support::roster_id(&fresh)?,
        &[(DEVICE, 0), (SECOND_DEVICE, 1)],
    )?;
    let mut restarted = restarted_alike(&mut harness)?;
    // The second device's attachment counter, scoped to the account and
    // device, continues where it stood, live and after a restart.
    for coordinator in [&mut harness, &mut restarted] {
        Publication::Roster(&returned).stored(coordinator)?;
        assert_eq!(coordinator.attach_as(SECOND_DEVICE)?.0, 2);
    }
    Ok(())
}

#[test]
fn a_root_continues_the_root_that_awaits_its_first_roster() -> TestResult {
    let mut harness = Harness::new()?;
    let first = AccountRoot::first(&harness);
    Publication::Root(&first.root).stored(&mut harness)?;
    // Before any roster, the next root continues the pending one.
    let second = first.next(&harness, NEXT_ROOT_SEED)?;
    Publication::Root(&second.root).stored(&mut harness)?;
    let mut restarted = restarted_alike(&mut harness)?;
    let roster = second.roster(0, [0; 32], &[(DEVICE, 0)])?;
    let skipped = first.next(&harness, NEXT_ROOT_SEED + 1)?;
    for coordinator in [&mut harness, &mut restarted] {
        // A second successor of the first root is refused.
        assert!(Publication::Root(&skipped.root).run(coordinator)?.is_some());
        Publication::Roster(&roster).stored(coordinator)?;
    }
    assert_eq!(view(&restarted)?, view(&harness)?);
    Ok(())
}

#[test]
fn a_root_recovery_rotates_again_from_the_root_that_awaits_its_roster() -> TestResult {
    // The root holder publishes a continued root, loses the roster it
    // prepared for it, and recovers with a further continuous rotation after
    // the coordinator restarted.
    let (mut harness, first) = provisioned(&[DEVICE])?;
    let old = AccountRoot::first(&harness);
    let abandoned = old.next(&harness, NEXT_ROOT_SEED)?;
    Publication::Root(&abandoned.root).stored(&mut harness)?;
    let mut restarted = restarted_alike(&mut harness)?;
    let recovered = abandoned.next(&restarted, NEXT_ROOT_SEED + 1)?;
    let roster = recovered.roster(0, [0; 32], &[(DEVICE, 0)])?;
    let late = abandoned.roster(0, [0; 32], &[(DEVICE, 0)])?;
    let new_first = statement(DEVICE, &roster, 0, [0; 32])?;
    let carried = statement(DEVICE, &roster, 1, capability_id(&first)?)?;
    for coordinator in [&mut harness, &mut restarted] {
        Publication::Root(&recovered.root).stored(coordinator)?;
        // The abandoned root's roster is refused once a newer root exists.
        assert!(Publication::Roster(&late).run(coordinator)?.is_some());
        Publication::Roster(&roster).stored(coordinator)?;
        assert!(
            Publication::Capabilities(DEVICE, &carried)
                .run(coordinator)?
                .is_some()
        );
        Publication::Capabilities(DEVICE, &new_first).stored(coordinator)?;
    }
    assert_eq!(view(&restarted)?, view(&harness)?);
    let reads = directory_reads(&mut harness)?;
    assert_eq!(directory_reads(&mut restarted)?, reads);
    Ok(())
}
