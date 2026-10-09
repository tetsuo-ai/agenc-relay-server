//! Startup restores directory, package, and mailbox rows only when their key,
//! retained object, and recorded identifiers agree.
#![forbid(unsafe_code)]

use super::super::tests::support::{
    DeviceSpec, NETWORK, Principal, capabilities, certificate, key, principal, root,
    root_fingerprint, roster, roster_id,
};
use super::*;
use agenc_relay_e2ee::ids::account_id_digest;
use agenc_relay_e2ee::tls::TlsEncode;
use agenc_relay_storage::e2ee_records::{AttachChallenge, ClaimOutcome as RowClaimOutcome};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const DEVICE: u8 = 7;
const ACCOUNT: [u8; 24] = *b"aaaaaaaaaaaaaaaaaaaaaaaa";

fn foreign_key() -> TestResult<StoredKey> {
    Ok(RouteRow::key(&[0x55; 32])?)
}

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

/// A principal whose root and roster objects are retained, with the rows
/// that publish them.
struct Fixture {
    state: CompanionState,
    principal: Principal,
    digest: [u8; 32],
    identity: DirectoryRow,
    roster: DirectoryRow,
}

fn fixture() -> TestResult<Fixture> {
    fixture_with(&[DEVICE])
}

/// The fixture of an account whose roster keeps `devices` active.
fn fixture_with(devices: &[u8]) -> TestResult<Fixture> {
    let principal = principal(40, &ACCOUNT, devices)?;
    let mut state = CompanionState::default();
    let root_object = retain(&mut state, ArcWireObjectKind::RootIdentity, &principal.root)?;
    let roster_object = retain(
        &mut state,
        ArcWireObjectKind::DeviceRoster,
        &principal.roster,
    )?;
    let fingerprint = root_fingerprint(&principal.root)?;
    let identity = DirectoryRow::Identity {
        root_generation: 0,
        root_fingerprint: fingerprint,
        object_id: root_object,
        chain_object_ids: vec![root_object],
    };
    let roster = DirectoryRow::Roster {
        roster_generation: 0,
        roster_id: roster_id(&principal.roster)?,
        root_fingerprint: fingerprint,
        object_id: roster_object,
        active_devices: devices.iter().map(|seed| [*seed; 16]).collect(),
    };
    Ok(Fixture {
        state,
        digest: account_id_digest(&NETWORK, &ACCOUNT)?,
        principal,
        identity,
        roster,
    })
}

impl Fixture {
    fn rows(&self) -> TestResult<Vec<(StoredKey, DirectoryRow)>> {
        Ok(vec![
            (
                DirectoryRow::identity_key(&self.digest)?,
                self.identity.clone(),
            ),
            (DirectoryRow::roster_key(&self.digest)?, self.roster.clone()),
        ])
    }

    fn restore(&mut self, rows: Vec<(StoredKey, DirectoryRow)>) {
        restore_directory(&mut self.state, &NETWORK, rows, Vec::new());
    }
}

#[test]
fn identity_and_roster_rows_restore_the_principal() -> TestResult {
    let mut fixture = fixture()?;
    let rows = fixture.rows()?;
    fixture.restore(rows);
    let entry = fixture
        .state
        .directory
        .account(&fixture.digest)
        .ok_or("entry")?;
    assert_eq!(entry.root.as_ref().map(|root| root.generation), Some(0));
    let roster = entry.roster.as_ref().ok_or("roster head")?;
    assert_eq!(
        roster.active_devices,
        std::collections::BTreeSet::from([[DEVICE; 16]])
    );
    assert!(fixture.state.principals.contains_key(&fixture.digest));
    assert!(fixture.state.pending_roots.is_empty());
    Ok(())
}

#[test]
fn identity_without_a_roster_is_kept_as_a_pending_root() -> TestResult {
    let mut fixture = fixture()?;
    let rows = vec![(
        DirectoryRow::identity_key(&fixture.digest)?,
        fixture.identity.clone(),
    )];
    fixture.restore(rows);
    assert!(fixture.state.principals.is_empty());
    let pending = fixture
        .state
        .pending_roots
        .get(&fixture.digest)
        .ok_or("pending root")?;
    assert_eq!(
        pending.fingerprint,
        root_fingerprint(&fixture.principal.root)?
    );
    Ok(())
}

#[test]
fn a_roster_restores_under_the_root_that_signed_it_beside_a_newer_pending_root() -> TestResult {
    let mut fixture = fixture()?;
    // The account published a continued root and not yet its first roster.
    let next = root(
        &key(41),
        &ACCOUNT,
        1,
        (0, 2_000_000),
        Some((&fixture.principal.root_secret, &fixture.principal.root)),
    )?;
    let next_object = retain(&mut fixture.state, ArcWireObjectKind::RootIdentity, &next)?;
    let DirectoryRow::Identity { object_id, .. } = fixture.identity.clone() else {
        return Err("identity row".into());
    };
    fixture.identity = DirectoryRow::Identity {
        root_generation: 1,
        root_fingerprint: root_fingerprint(&next)?,
        object_id: next_object,
        chain_object_ids: vec![object_id, next_object],
    };
    let rows = fixture.rows()?;
    fixture.restore(rows);
    let first = root_fingerprint(&fixture.principal.root)?;
    let (principal_root, roster) = fixture
        .state
        .principals
        .get(&fixture.digest)
        .ok_or("principal")?;
    assert_eq!((principal_root.fingerprint, roster.generation), (first, 0));
    assert_eq!(
        fixture
            .state
            .pending_roots
            .get(&fixture.digest)
            .map(|root| root.fingerprint),
        Some(root_fingerprint(&next)?)
    );
    let entry = fixture
        .state
        .directory
        .account(&fixture.digest)
        .ok_or("entry")?;
    assert_eq!(entry.root.as_ref().map(|root| root.generation), Some(1));
    assert_eq!(
        entry.roster.as_ref().map(|roster| roster.root_fingerprint),
        Some(first)
    );
    assert!(entry.device_active(&[DEVICE; 16]));
    Ok(())
}

#[test]
fn identity_row_under_a_foreign_key_restores_nothing() -> TestResult {
    let mut fixture = fixture()?;
    let rows = vec![(foreign_key()?, fixture.identity.clone())];
    fixture.restore(rows);
    assert_eq!(fixture.state.directory.entry_count(), 0);
    assert!(fixture.state.pending_roots.is_empty());
    Ok(())
}

#[test]
fn identity_row_naming_another_fingerprint_is_refused() -> TestResult {
    let fixture = fixture()?;
    let DirectoryRow::Identity {
        object_id,
        chain_object_ids,
        ..
    } = fixture.identity.clone()
    else {
        return Err("identity row".into());
    };
    let key = DirectoryRow::identity_key(&fixture.digest)?;
    let forged = DirectoryRow::Identity {
        root_generation: 0,
        root_fingerprint: [0xee; 32],
        object_id,
        chain_object_ids: chain_object_ids.clone(),
    };
    assert!(restore_identity(&fixture.state, &NETWORK, &key, forged).is_none());
    let stale = DirectoryRow::Identity {
        root_generation: 1,
        root_fingerprint: root_fingerprint(&fixture.principal.root)?,
        object_id,
        chain_object_ids,
    };
    assert!(restore_identity(&fixture.state, &NETWORK, &key, stale).is_none());
    Ok(())
}

#[test]
fn identity_row_with_an_unretained_or_empty_chain_is_refused() -> TestResult {
    let fixture = fixture()?;
    let key = DirectoryRow::identity_key(&fixture.digest)?;
    let fingerprint = root_fingerprint(&fixture.principal.root)?;
    for chain in [vec![[0xaa; 32]], Vec::new()] {
        let row = DirectoryRow::Identity {
            root_generation: 0,
            root_fingerprint: fingerprint,
            object_id: [0xaa; 32],
            chain_object_ids: chain,
        };
        assert!(restore_identity(&fixture.state, &NETWORK, &key, row).is_none());
    }
    Ok(())
}

#[test]
fn restore_identity_refuses_a_row_of_another_directory_kind() -> TestResult {
    let fixture = fixture()?;
    let key = DirectoryRow::identity_key(&fixture.digest)?;
    assert!(restore_identity(&fixture.state, &NETWORK, &key, fixture.roster.clone()).is_none());
    Ok(())
}

fn roster_with(
    fixture: &Fixture,
    id: Option<[u8; 32]>,
    fingerprint: Option<[u8; 32]>,
) -> DirectoryRow {
    match fixture.roster.clone() {
        DirectoryRow::Roster {
            roster_generation,
            roster_id,
            root_fingerprint,
            object_id,
            active_devices,
        } => DirectoryRow::Roster {
            roster_generation,
            roster_id: id.unwrap_or(roster_id),
            root_fingerprint: fingerprint.unwrap_or(root_fingerprint),
            object_id,
            active_devices,
        },
        other => other,
    }
}

#[test]
fn roster_row_naming_another_roster_or_root_is_refused() -> TestResult {
    for (id, fingerprint) in [(Some([0xee; 32]), None), (None, Some([0xee; 32]))] {
        let mut fixture = fixture()?;
        let mut rows = fixture.rows()?;
        let forged = roster_with(&fixture, id, fingerprint);
        if let Some(last) = rows.last_mut() {
            last.1 = forged;
        }
        fixture.restore(rows);
        assert!(fixture.state.principals.is_empty());
        assert!(fixture.state.pending_roots.contains_key(&fixture.digest));
    }
    Ok(())
}

#[test]
fn roster_row_under_a_foreign_key_or_without_a_root_is_refused() -> TestResult {
    let mut fixture = fixture()?;
    let mut entries = BTreeMap::new();
    let roots = BTreeMap::new();
    let key = DirectoryRow::roster_key(&fixture.digest)?;
    let row = fixture.roster.clone();
    assert!(restore_roster_row(&mut fixture.state, &roots, &mut entries, &key, &row).is_none());
    let foreign = foreign_key()?;
    assert!(restore_roster_row(&mut fixture.state, &roots, &mut entries, &foreign, &row).is_none());
    let identity = fixture.identity.clone();
    assert!(
        restore_roster_row(&mut fixture.state, &roots, &mut entries, &key, &identity).is_none()
    );
    assert!(entries.is_empty());
    Ok(())
}

/// The capability row of `DEVICE`, its retained object, and its identifier.
fn capability_row(fixture: &mut Fixture) -> TestResult<(DirectoryRow, [u8; 32])> {
    let object = capabilities(
        DEVICE,
        &fixture.principal.roster,
        0,
        [0; 32],
        (100, 100_000),
        vec![1],
    )?;
    let capability_id =
        agenc_relay_e2ee::ids::semantic_id_of(SemanticHashDomain::CapabilityId, &object.tbs)?;
    let object_id = retain(
        &mut fixture.state,
        ArcWireObjectKind::DeviceCapabilities,
        &object,
    )?;
    let row = DirectoryRow::Capability {
        generation: 0,
        capability_id,
        roster_id: roster_id(&fixture.principal.roster)?,
        object_id,
    };
    Ok((row, capability_id))
}

#[test]
fn capability_row_restores_the_device_capability_head() -> TestResult {
    let mut fixture = fixture()?;
    let (row, capability_id) = capability_row(&mut fixture)?;
    let mut rows = fixture.rows()?;
    rows.push((
        DirectoryRow::capability_key(&fixture.digest, &[DEVICE; 16])?,
        row,
    ));
    fixture.restore(rows);
    let entry = fixture
        .state
        .directory
        .account(&fixture.digest)
        .ok_or("entry")?;
    let head = entry.capabilities.get(&[DEVICE; 16]).ok_or("head")?;
    assert_eq!(head.capability_id, capability_id);
    assert!(
        fixture
            .state
            .capabilities
            .contains_key(&(fixture.digest, [DEVICE; 16]))
    );
    Ok(())
}

/// Replaces the fixture's roster row with the account's next roster under
/// `root` (the fixture's root, or a continued one signed by `secret`),
/// keeping `devices` active, and returns that roster's identifier. The
/// earlier roster's object stays retained when `retain_earlier` holds.
fn renew(
    fixture: &mut Fixture,
    next_root: Option<&agenc_relay_e2ee::objects::identity::ArcRootIdentity>,
    devices: &[u8],
    retain_earlier: bool,
) -> TestResult<[u8; 32]> {
    let earlier = roster_id(&fixture.principal.roster)?;
    let (secret, signing, generation, previous) = match next_root {
        Some(next) => (key(41), next.clone(), 0, [0; 32]),
        None => (key(40), fixture.principal.root.clone(), 1, earlier),
    };
    let certificates = devices
        .iter()
        .map(|seed| certificate(&secret, &signing, &DeviceSpec::new(*seed)))
        .collect::<Result<Vec<_>, _>>()?;
    let next = roster(
        &secret,
        &signing,
        generation,
        previous,
        (100, 100 + 6 * 24 * 3600),
        certificates,
        Vec::new(),
    )?;
    let next_object = retain(&mut fixture.state, ArcWireObjectKind::DeviceRoster, &next)?;
    if !retain_earlier {
        let DirectoryRow::Roster { object_id, .. } = fixture.roster.clone() else {
            return Err("roster row".into());
        };
        fixture.state.objects.remove(&object_id);
    }
    fixture.roster = DirectoryRow::Roster {
        roster_generation: generation,
        roster_id: roster_id(&next)?,
        root_fingerprint: root_fingerprint(&signing)?,
        object_id: next_object,
        active_devices: devices.iter().map(|seed| [*seed; 16]).collect(),
    };
    Ok(roster_id(&next)?)
}

/// Restores the fixture's rows with `row` as device 7's capability row and
/// returns the restored capability head, if any.
fn restored_head(fixture: &mut Fixture, row: DirectoryRow) -> TestResult<Option<CapabilityHead>> {
    let mut rows = fixture.rows()?;
    rows.push((
        DirectoryRow::capability_key(&fixture.digest, &[DEVICE; 16])?,
        row,
    ));
    fixture.restore(rows);
    let head = fixture
        .state
        .directory
        .account(&fixture.digest)
        .and_then(|entry| entry.capabilities.get(&[DEVICE; 16]).copied());
    assert_eq!(
        head.is_some(),
        fixture
            .state
            .capabilities
            .contains_key(&(fixture.digest, [DEVICE; 16]))
    );
    Ok(head)
}

#[test]
fn a_capability_head_restores_against_the_earlier_roster_it_names() -> TestResult {
    let mut fixture = fixture()?;
    let (row, capability_id) = capability_row(&mut fixture)?;
    let earlier = roster_id(&fixture.principal.roster)?;
    renew(&mut fixture, None, &[DEVICE], true)?;
    let head = restored_head(&mut fixture, row)?.ok_or("restored head")?;
    // The head keeps its generation and identifier and names the earlier
    // roster; it is not a current statement.
    assert_eq!(
        (head.generation, head.capability_id, head.roster_id),
        (0, capability_id, earlier)
    );
    assert!(
        fixture
            .state
            .directory
            .capability_page(&fixture.digest)
            .is_empty()
    );
    Ok(())
}

#[test]
fn a_capability_head_restores_nothing_without_its_named_roster_root_or_device() -> TestResult {
    // The earlier roster the head names is no longer retained.
    let mut collected = fixture()?;
    let (row, _) = capability_row(&mut collected)?;
    renew(&mut collected, None, &[DEVICE], false)?;
    assert_eq!(restored_head(&mut collected, row)?, None);
    // The current roster no longer keeps the device.
    let mut revoked = fixture()?;
    let (row, _) = capability_row(&mut revoked)?;
    renew(&mut revoked, None, &[], true)?;
    assert_eq!(restored_head(&mut revoked, row)?, None);
    // The head belongs to an earlier root's lineage.
    let mut rotated = fixture()?;
    let (row, _) = capability_row(&mut rotated)?;
    let next = root(
        &key(41),
        &ACCOUNT,
        1,
        (0, 2_000_000),
        Some((&rotated.principal.root_secret, &rotated.principal.root)),
    )?;
    let next_object = retain(&mut rotated.state, ArcWireObjectKind::RootIdentity, &next)?;
    let DirectoryRow::Identity { object_id, .. } = rotated.identity.clone() else {
        return Err("identity row".into());
    };
    rotated.identity = DirectoryRow::Identity {
        root_generation: 1,
        root_fingerprint: root_fingerprint(&next)?,
        object_id: next_object,
        chain_object_ids: vec![object_id, next_object],
    };
    renew(&mut rotated, Some(&next), &[DEVICE], true)?;
    assert_eq!(restored_head(&mut rotated, row)?, None);
    Ok(())
}

#[test]
fn capability_row_naming_another_capability_or_device_is_refused() -> TestResult {
    // Both devices are active, so the row filed under device 8 reaches the
    // comparison with the statement it holds, device 7's.
    let mut fixture = fixture_with(&[DEVICE, DEVICE + 1])?;
    let (row, _) = capability_row(&mut fixture)?;
    let DirectoryRow::Capability {
        generation,
        roster_id,
        object_id,
        ..
    } = row.clone()
    else {
        return Err("capability row".into());
    };
    let forged = DirectoryRow::Capability {
        generation,
        capability_id: [0xee; 32],
        roster_id,
        object_id,
    };
    let mut rows = fixture.rows()?;
    rows.push((
        DirectoryRow::capability_key(&fixture.digest, &[DEVICE; 16])?,
        forged,
    ));
    rows.push((
        DirectoryRow::capability_key(&fixture.digest, &[DEVICE + 1; 16])?,
        row,
    ));
    fixture.restore(rows);
    assert!(fixture.state.capabilities.is_empty());
    Ok(())
}

#[test]
fn capability_row_without_a_restored_roster_is_refused() -> TestResult {
    let mut fixture = fixture()?;
    let (row, _) = capability_row(&mut fixture)?;
    let mut entries = BTreeMap::new();
    let key = DirectoryRow::capability_key(&fixture.digest, &[DEVICE; 16])?;
    assert!(restore_capability_row(&mut fixture.state, &mut entries, &key, &row).is_none());
    let foreign = foreign_key()?;
    assert!(restore_capability_row(&mut fixture.state, &mut entries, &foreign, &row).is_none());
    let identity = fixture.identity.clone();
    assert!(restore_capability_row(&mut fixture.state, &mut entries, &key, &identity).is_none());
    assert!(entries.is_empty());
    Ok(())
}

#[test]
fn capability_row_whose_object_is_not_retained_is_refused() -> TestResult {
    let mut fixture = fixture()?;
    let (row, _) = capability_row(&mut fixture)?;
    let DirectoryRow::Capability { object_id, .. } = &row else {
        return Err("capability row".into());
    };
    fixture.state.objects.remove(object_id);
    let mut rows = fixture.rows()?;
    rows.push((
        DirectoryRow::capability_key(&fixture.digest, &[DEVICE; 16])?,
        row,
    ));
    fixture.restore(rows);
    assert!(fixture.state.capabilities.is_empty());
    Ok(())
}

#[test]
fn binding_lock_rows_restore_the_chain_and_the_next_sequence() -> TestResult {
    let mut state = CompanionState::default();
    let lock = |marker: u8| DirectoryRow::BindingLock {
        lock_id: [marker; 32],
        binding_id: [marker; 32],
        object_id: [marker; 32],
    };
    let rows = vec![
        (
            DirectoryRow::binding_lock_key(&[1; 32], &[2; 32], 4)?,
            lock(4),
        ),
        (
            DirectoryRow::binding_lock_key(&[1; 32], &[2; 32], 1)?,
            lock(1),
        ),
        (foreign_key()?, lock(9)),
    ];
    restore_directory(&mut state, &NETWORK, rows, Vec::new());
    let chain = state
        .binding_locks
        .get(&([1; 32], [2; 32]))
        .ok_or("chain")?;
    assert_eq!(chain.keys().copied().collect::<Vec<_>>(), vec![1, 4]);
    let entry = state.directory.account(&[1; 32]).ok_or("entry")?;
    assert_eq!(entry.lock_sequences.get(&[2; 32]), Some(&5));
    Ok(())
}

#[test]
fn restore_capability_row_refuses_a_row_of_another_directory_kind() -> TestResult {
    let mut fixture = fixture()?;
    let rows = fixture.rows()?;
    fixture.restore(rows);
    let mut entries = BTreeMap::new();
    let key = DirectoryRow::capability_key(&fixture.digest, &[DEVICE; 16])?;
    let roster = fixture.roster.clone();
    assert!(restore_capability_row(&mut fixture.state, &mut entries, &key, &roster).is_none());
    assert!(entries.is_empty());
    assert!(fixture.state.capabilities.is_empty());
    Ok(())
}

#[test]
fn restore_lock_row_refuses_a_row_of_another_directory_kind() -> TestResult {
    let mut fixture = fixture()?;
    let mut entries = BTreeMap::new();
    let key = DirectoryRow::binding_lock_key(&[1; 32], &[2; 32], 4)?;
    let identity = fixture.identity.clone();
    assert!(restore_lock_row(&mut fixture.state, &mut entries, &key, &identity).is_none());
    assert!(fixture.state.binding_locks.is_empty());
    Ok(())
}

#[test]
fn attachment_row_restores_the_session_and_its_open_challenge() -> TestResult {
    let mut state = CompanionState::default();
    let challenge = AttachChallenge {
        connection_id: [1; 16],
        connection_nonce: [2; 32],
        server_challenge: [3; 32],
        reserved_generation: 6,
        expires_at: 900,
        object_id: [4; 32],
    };
    let attachments = vec![
        (
            AttachRow::key(&[1; 32], &[5; 16])?,
            AttachRow {
                session_generation: 5,
                challenge: Some(challenge),
            },
        ),
        (
            AttachRow::key(&[1; 32], &[6; 16])?,
            AttachRow {
                session_generation: 2,
                challenge: None,
            },
        ),
        (
            foreign_key()?,
            AttachRow {
                session_generation: 8,
                challenge: None,
            },
        ),
    ];
    restore_directory(&mut state, &NETWORK, Vec::new(), attachments);
    assert_eq!(state.challenges.get(&([1; 32], [5; 16])), Some(&[3; 32]));
    assert_eq!(state.challenges.len(), 1);
    assert_eq!(state.directory.session_generation(&[1; 32], &[5; 16]), 5);
    assert_eq!(state.directory.session_generation(&[1; 32], &[6; 16]), 2);
    assert_eq!(state.directory.entry_count(), 1);
    Ok(())
}

// ---------------------------------------------------------------------------
// Packages.

fn package_row(state: PackageState) -> PackageRow {
    let claimed = !matches!(state, PackageState::Published);
    PackageRow::Package {
        account_digest: [1; 32],
        device_id: [2; 16],
        suite: 1,
        expires_at: 900,
        object_id: [3; 32],
        state,
        claimed_by: claimed.then_some(([4; 32], [5; 16])),
    }
}

#[test]
fn only_published_packages_under_a_package_key_are_restocked() -> TestResult {
    let mut state = CompanionState::default();
    let rows = vec![
        (
            PackageRow::package_key(b"published")?,
            package_row(PackageState::Published),
        ),
        (
            PackageRow::package_key(b"claimed")?,
            package_row(PackageState::Claimed),
        ),
        (
            PackageRow::package_key(b"revoked")?,
            package_row(PackageState::Revoked),
        ),
        (foreign_key()?, package_row(PackageState::Published)),
    ];
    restore_packages(&mut state, rows);
    assert_eq!(state.directory.stock(&[1; 32], &[2; 16]), 1);
    Ok(())
}

fn claim_row(object_id: Option<[u8; 32]>) -> PackageRow {
    PackageRow::Claim {
        target_account_digest: [1; 32],
        target_device_id: [2; 16],
        suite: 1,
        outcome: if object_id.is_some() {
            RowClaimOutcome::Claimed
        } else {
            RowClaimOutcome::KeyUnavailable
        },
        key_package_ref: if object_id.is_some() {
            b"ref".to_vec()
        } else {
            Vec::new()
        },
        object_id,
        retain_until: 900,
    }
}

#[test]
fn claim_rows_restore_their_outcome_only_under_a_claim_key() -> TestResult {
    let mut state = CompanionState::default();
    let rows = vec![
        (
            PackageRow::claim_key(&[6; 32], &[1; 16])?,
            claim_row(Some([3; 32])),
        ),
        (PackageRow::claim_key(&[6; 32], &[2; 16])?, claim_row(None)),
        (foreign_key()?, claim_row(None)),
    ];
    restore_packages(&mut state, rows);
    assert_eq!(
        state.directory.claim_status(&[6; 32], &[1; 16]),
        Some(&ClaimOutcome::Claimed {
            key_package_ref: b"ref".to_vec(),
            object_id: [3; 32],
        })
    );
    assert_eq!(
        state.directory.claim_status(&[6; 32], &[2; 16]),
        Some(&ClaimOutcome::Unavailable)
    );
    Ok(())
}

#[test]
fn package_restore_helpers_ignore_rows_of_the_other_arm() -> TestResult {
    let mut state = CompanionState::default();
    restore_package_row(
        &mut state,
        &PackageRow::package_key(b"published")?,
        claim_row(None),
    );
    restore_claim_row(
        &mut state,
        &PackageRow::claim_key(&[6; 32], &[1; 16])?,
        package_row(PackageState::Published),
    );
    assert_eq!(state.directory.stock(&[1; 32], &[2; 16]), 0);
    assert!(state.directory.claim_status(&[6; 32], &[1; 16]).is_none());
    Ok(())
}
