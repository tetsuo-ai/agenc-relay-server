#![forbid(unsafe_code)]

//! The account directory.

use super::*;

const ACCOUNT: Id = [1; 32];
const ROOT: Id = [2; 32];
const DEVICE_A: Id16 = [10; 16];
const DEVICE_B: Id16 = [11; 16];

fn provisioned() -> Result<Directory, DirectoryError> {
    let mut directory = Directory::new();
    directory.publish_root(ACCOUNT, 0, ROOT, [3; 32])?;
    directory.publish_roster(
        ACCOUNT,
        0,
        [4; 32],
        ROOT,
        [DEVICE_A, DEVICE_B].into_iter().collect(),
        [5; 32],
    )?;
    Ok(directory)
}

fn package(device: Id16, seed: u8, expires_at: u64) -> Package {
    Package {
        account_digest: ACCOUNT,
        device_id: device,
        suite: 1,
        expires_at,
        object_id: [seed; 32],
    }
}

#[test]
fn heads_advance_by_one_and_bind_to_each_other() -> Result<(), DirectoryError> {
    let mut directory = Directory::new();
    assert_eq!(
        directory.publish_root(ACCOUNT, 1, ROOT, [3; 32]),
        Err(DirectoryError::GenerationGap)
    );
    assert_eq!(
        directory.publish_roster(ACCOUNT, 0, [4; 32], ROOT, BTreeSet::new(), [5; 32]),
        Err(DirectoryError::HeadMismatch),
        "a roster needs a root"
    );
    directory.publish_root(ACCOUNT, 0, ROOT, [3; 32])?;
    assert_eq!(
        directory.publish_roster(ACCOUNT, 0, [4; 32], [9; 32], BTreeSet::new(), [5; 32]),
        Err(DirectoryError::HeadMismatch)
    );
    directory.publish_roster(
        ACCOUNT,
        0,
        [4; 32],
        ROOT,
        [DEVICE_A].into_iter().collect(),
        [5; 32],
    )?;
    assert_eq!(
        directory.publish_roster(ACCOUNT, 2, [4; 32], ROOT, BTreeSet::new(), [5; 32]),
        Err(DirectoryError::GenerationGap)
    );
    directory.publish_root(ACCOUNT, 1, [6; 32], [7; 32])?;
    let root = directory
        .account(&ACCOUNT)
        .and_then(|entry| entry.root.clone())
        .ok_or(DirectoryError::HeadMismatch)?;
    assert_eq!(root.generation, 1);
    assert_eq!(root.chain, vec![[3; 32], [7; 32]]);
    let crowded: BTreeSet<Id16> = (0..65_u8).map(|index| [index; 16]).collect();
    assert_eq!(
        directory.publish_roster(ACCOUNT, 0, [4; 32], [6; 32], crowded, [5; 32]),
        Err(DirectoryError::GenerationGap),
        "more active devices than an account may hold"
    );
    Ok(())
}

#[test]
fn a_rotated_root_starts_its_roster_and_capability_lineages() -> Result<(), DirectoryError> {
    const NEXT_ROOT: Id = [6; 32];
    let mut directory = provisioned()?;
    let head = CapabilityHead {
        generation: 0,
        capability_id: [20; 32],
        roster_id: [4; 32],
        object_id: [21; 32],
    };
    directory.publish_capability(ACCOUNT, DEVICE_A, head)?;
    let challenge = directory.attach_begin(ACCOUNT, DEVICE_B, [1; 16], 0)?;
    directory.attach_finish(ACCOUNT, DEVICE_B, [1; 16], challenge.reserved_generation, 0)?;
    // Under one root a roster advances the head by exactly one.
    for generation in [0, 2] {
        assert_eq!(
            directory.publish_roster(ACCOUNT, generation, [8; 32], ROOT, BTreeSet::new(), [5; 32]),
            Err(DirectoryError::GenerationGap),
            "generation {generation} under the same root"
        );
    }
    directory.publish_root(ACCOUNT, 1, NEXT_ROOT, [7; 32])?;
    // While the new root's first roster is pending the account keeps its
    // roster and capability heads.
    assert!(directory.capability_page(&ACCOUNT) == vec![(DEVICE_A, [21; 32])]);
    let only_a: BTreeSet<Id16> = [DEVICE_A].into_iter().collect();
    assert_eq!(
        directory.publish_roster(ACCOUNT, 1, [9; 32], NEXT_ROOT, only_a.clone(), [10; 32]),
        Err(DirectoryError::GenerationGap),
        "the old root's counter does not continue under the new root"
    );
    assert_eq!(
        directory.publish_roster(ACCOUNT, 0, [9; 32], ROOT, only_a.clone(), [10; 32]),
        Err(DirectoryError::HeadMismatch),
        "a roster signs under the newest root"
    );
    directory.publish_roster(ACCOUNT, 0, [9; 32], NEXT_ROOT, only_a, [10; 32])?;
    let entry = directory
        .account(&ACCOUNT)
        .ok_or(DirectoryError::HeadMismatch)?;
    assert!(entry.capabilities.is_empty(), "no head of the earlier root");
    // The new root's capability lineage starts at generation zero.
    directory.publish_capability(
        ACCOUNT,
        DEVICE_A,
        CapabilityHead {
            roster_id: [9; 32],
            capability_id: [22; 32],
            object_id: [23; 32],
            ..head
        },
    )?;
    // Device B's attachment counter outlives the roster it left, so its
    // enrollment under the new root continues it.
    assert_eq!(directory.session_generation(&ACCOUNT, &DEVICE_B), 1);
    directory.publish_roster(
        ACCOUNT,
        1,
        [11; 32],
        NEXT_ROOT,
        [DEVICE_A, DEVICE_B].into_iter().collect(),
        [12; 32],
    )?;
    let challenge = directory.attach_begin(ACCOUNT, DEVICE_B, [1; 16], 0)?;
    assert_eq!(challenge.reserved_generation, 2);
    Ok(())
}

#[test]
fn capabilities_follow_the_roster_and_page_in_device_order() -> Result<(), DirectoryError> {
    let mut directory = provisioned()?;
    let head = CapabilityHead {
        generation: 0,
        capability_id: [20; 32],
        roster_id: [4; 32],
        object_id: [21; 32],
    };
    assert_eq!(
        directory.publish_capability(ACCOUNT, [12; 16], head),
        Err(DirectoryError::DeviceInactive)
    );
    assert_eq!(
        directory.publish_capability(
            ACCOUNT,
            DEVICE_A,
            CapabilityHead {
                roster_id: [9; 32],
                ..head
            }
        ),
        Err(DirectoryError::HeadMismatch)
    );
    directory.publish_capability(ACCOUNT, DEVICE_B, head)?;
    directory.publish_capability(ACCOUNT, DEVICE_A, head)?;
    assert_eq!(
        directory.publish_capability(ACCOUNT, DEVICE_A, head),
        Err(DirectoryError::GenerationGap),
        "the generation must grow"
    );
    assert_eq!(
        directory.capability_page(&ACCOUNT),
        vec![(DEVICE_A, [21; 32]), (DEVICE_B, [21; 32])]
    );
    directory.publish_roster(
        ACCOUNT,
        1,
        [8; 32],
        ROOT,
        [DEVICE_A].into_iter().collect(),
        [5; 32],
    )?;
    assert_eq!(
        directory.capability_page(&ACCOUNT),
        vec![(DEVICE_A, [21; 32])]
    );
    assert!(directory.capability_page(&[9; 32]).is_empty());
    directory.record_binding_lock(ACCOUNT, ROOT, 0)?;
    assert_eq!(
        directory.record_binding_lock(ACCOUNT, ROOT, 0),
        Err(DirectoryError::GenerationGap)
    );
    directory.record_binding_lock(ACCOUNT, ROOT, 1)?;
    assert_eq!(
        directory.record_binding_lock([9; 32], ROOT, 0),
        Err(DirectoryError::HeadMismatch)
    );
    Ok(())
}

#[test]
fn attachment_is_a_compare_and_swap_on_the_session_generation() -> Result<(), DirectoryError> {
    let mut directory = provisioned()?;
    assert_eq!(directory.session_generation(&ACCOUNT, &DEVICE_A), 0);
    assert_eq!(
        directory.attach_begin(ACCOUNT, [12; 16], [1; 16], 100),
        Err(DirectoryError::DeviceInactive)
    );
    assert_eq!(
        directory.attach_finish(ACCOUNT, [12; 16], [1; 16], 1, 100),
        Err(DirectoryError::DeviceInactive),
        "a finish for a device the roster does not list"
    );
    let first = directory.attach_begin(ACCOUNT, DEVICE_A, [1; 16], 100)?;
    assert_eq!(first.reserved_generation, 1);
    assert_eq!(first.expires_at, 160);
    let second = directory.attach_begin(ACCOUNT, DEVICE_A, [2; 16], 101)?;
    assert_eq!(
        directory.attach_finish(ACCOUNT, DEVICE_A, [1; 16], 1, 102),
        Err(DirectoryError::AttachConflict),
        "the earlier challenge was invalidated"
    );
    assert_eq!(
        directory.attach_finish(ACCOUNT, DEVICE_A, [2; 16], 2, 102),
        Err(DirectoryError::AttachConflict),
        "the reserved generation must match"
    );
    assert_eq!(
        directory.attach_finish(ACCOUNT, DEVICE_A, [2; 16], second.reserved_generation, 200),
        Err(DirectoryError::AttachConflict),
        "expired"
    );
    assert_eq!(
        directory.attach_finish(ACCOUNT, DEVICE_A, [2; 16], second.reserved_generation, 150)?,
        1
    );
    assert_eq!(directory.session_generation(&ACCOUNT, &DEVICE_A), 1);
    assert_eq!(
        directory.attach_finish(ACCOUNT, DEVICE_A, [2; 16], 1, 151),
        Err(DirectoryError::AttachConflict),
        "no outstanding challenge"
    );
    let third = directory.attach_begin(ACCOUNT, DEVICE_A, [3; 16], 160)?;
    assert_eq!(third.reserved_generation, 2);
    directory.expire(230);
    assert_eq!(
        directory.attach_finish(ACCOUNT, DEVICE_A, [3; 16], 2, 231),
        Err(DirectoryError::AttachConflict)
    );
    assert_eq!(
        directory.attach_finish([9; 32], DEVICE_A, [3; 16], 2, 231),
        Err(DirectoryError::HeadMismatch)
    );
    Ok(())
}

#[test]
fn packages_are_one_use_and_claims_are_idempotent() -> Result<(), DirectoryError> {
    let mut directory = provisioned()?;
    let now = 1_000;
    assert_eq!(
        directory.publish_package(vec![1], package(DEVICE_A, 1, now), now),
        Err(DirectoryError::ExpiryOutOfRange)
    );
    assert_eq!(
        directory.publish_package(vec![1], package(DEVICE_A, 1, now + 604_801), now),
        Err(DirectoryError::ExpiryOutOfRange)
    );
    assert_eq!(
        directory.publish_package(vec![1], package([12; 16], 1, now + 100), now),
        Err(DirectoryError::DeviceInactive)
    );
    directory.publish_package(vec![2], package(DEVICE_A, 2, now + 7_200), now)?;
    directory.publish_package(vec![1], package(DEVICE_A, 1, now + 7_200), now)?;
    directory.publish_package(vec![3], package(DEVICE_A, 3, now + 1_800), now)?;
    assert_eq!(
        directory.publish_package(vec![1], package(DEVICE_A, 9, now + 7_200), now),
        Err(DirectoryError::DuplicatePackage)
    );
    assert_eq!(directory.stock(&ACCOUNT, &DEVICE_A), 3);
    let parameters = ClaimParameters {
        target_account_digest: ACCOUNT,
        target_device_id: DEVICE_A,
        suite: 1,
    };
    let claimant = [7; 32];
    let outcome = directory.claim_package(claimant, [1; 16], parameters, now)?;
    assert_eq!(
        outcome,
        ClaimOutcome::Claimed {
            key_package_ref: vec![1],
            object_id: [1; 32],
        },
        "the smallest acceptable reference is dispensed; ref 3 lacks claim validity"
    );
    assert_eq!(directory.stock(&ACCOUNT, &DEVICE_A), 2);
    assert_eq!(
        directory.claim_package(claimant, [1; 16], parameters, now + 5)?,
        outcome,
        "an identical retry replays without consuming"
    );
    assert_eq!(directory.stock(&ACCOUNT, &DEVICE_A), 2);
    assert_eq!(
        directory.claim_package(
            claimant,
            [1; 16],
            ClaimParameters {
                suite: 3,
                ..parameters
            },
            now
        ),
        Err(DirectoryError::OperationConflict)
    );
    assert_eq!(directory.claim_status(&claimant, &[1; 16]), Some(&outcome));
    assert_eq!(directory.claim_status(&claimant, &[2; 16]), None);
    assert_eq!(
        directory.claim_package(claimant, [2; 16], parameters, now)?,
        ClaimOutcome::Claimed {
            key_package_ref: vec![2],
            object_id: [2; 32],
        }
    );
    assert_eq!(
        directory.claim_package(claimant, [3; 16], parameters, now)?,
        ClaimOutcome::Unavailable
    );
    assert_eq!(
        directory.claim_package(
            claimant,
            [4; 16],
            ClaimParameters {
                target_device_id: [12; 16],
                ..parameters
            },
            now
        ),
        Err(DirectoryError::DeviceInactive)
    );
    assert_eq!(
        directory.revoke_package(&DEVICE_B, &[3]),
        Err(DirectoryError::NotOwner)
    );
    directory.revoke_package(&DEVICE_A, &[3])?;
    assert_eq!(
        directory.revoke_package(&DEVICE_A, &[3]),
        Err(DirectoryError::KeyUnavailable)
    );
    directory.publish_package(vec![4], package(DEVICE_B, 4, now + 7_200), now)?;
    let burned = directory.publish_roster(
        ACCOUNT,
        1,
        [8; 32],
        ROOT,
        [DEVICE_A].into_iter().collect(),
        [5; 32],
    )?;
    assert_eq!(burned, vec![vec![4]], "a removed device's stock burns");
    directory.publish_package(vec![5], package(DEVICE_A, 5, now + 100), now)?;
    assert_eq!(directory.expire(now + 100), vec![vec![5]]);
    directory.expire(now + 604_801);
    assert_eq!(directory.claim_status(&claimant, &[1; 16]), None);
    assert!(!DirectoryError::Overflow.to_string().is_empty());
    Ok(())
}

#[test]
fn a_stored_claim_keeps_the_parameters_it_was_made_with() -> Result<(), DirectoryError> {
    let mut directory = provisioned()?;
    let now = 1_000;
    directory.publish_package(vec![1], package(DEVICE_B, 1, now + 7_200), now)?;
    let target_b = ClaimParameters {
        target_account_digest: ACCOUNT,
        target_device_id: DEVICE_B,
        suite: 1,
    };
    let claimant = [7; 32];
    let claimed = directory.claim_package(claimant, [1; 16], target_b, now)?;
    let target_a = ClaimParameters {
        target_device_id: DEVICE_A,
        ..target_b
    };
    let empty = directory.claim_package(claimant, [2; 16], target_a, now)?;
    assert_eq!(empty, ClaimOutcome::Unavailable);
    assert_eq!(
        directory.stored_claim(&claimant, &[1; 16]),
        Some((target_b, &claimed))
    );
    assert_eq!(
        directory.stored_claim(&claimant, &[2; 16]),
        Some((target_a, &ClaimOutcome::Unavailable))
    );
    assert_eq!(directory.stored_claim(&claimant, &[3; 16]), None);
    assert_eq!(directory.stored_claim(&[8; 32], &[1; 16]), None);
    directory.restore_claim(claimant, [4; 16], target_a, ClaimOutcome::Unavailable, now);
    assert_eq!(
        directory.stored_claim(&claimant, &[4; 16]),
        Some((target_a, &ClaimOutcome::Unavailable))
    );
    Ok(())
}

#[test]
fn a_roster_burns_only_its_own_accounts_packages() -> Result<(), DirectoryError> {
    const OTHER: Id = [30; 32];
    let mut directory = provisioned()?;
    directory.publish_root(OTHER, 0, [31; 32], [32; 32])?;
    directory.publish_roster(
        OTHER,
        0,
        [33; 32],
        [31; 32],
        [DEVICE_B].into_iter().collect(),
        [34; 32],
    )?;
    directory.publish_package(b"own".to_vec(), package(DEVICE_B, 40, 1_000), 100)?;
    directory.publish_package(
        b"other".to_vec(),
        Package {
            account_digest: OTHER,
            ..package(DEVICE_B, 41, 1_000)
        },
        100,
    )?;
    // The account's roster revokes device B: only that account's package of
    // device B is burned.
    let burned = directory.publish_roster(
        ACCOUNT,
        1,
        [8; 32],
        ROOT,
        [DEVICE_A].into_iter().collect(),
        [5; 32],
    )?;
    assert_eq!(burned, vec![b"own".to_vec()]);
    assert_eq!(
        directory.revoke_package(&DEVICE_B, b"other"),
        Ok(()),
        "the other account's package is still published"
    );
    Ok(())
}
