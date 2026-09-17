#![forbid(unsafe_code)]

//! A device that states its own removal at the epoch it reached claims
//! nothing, even where it also holds a continuing proof at that epoch.

use super::*;

type FenceResult = Result<(), Box<dyn Error>>;

fn claims(set: &LeafMembershipSet) -> Vec<(u32, u64)> {
    set.expected_continuing(|_, _| true)
        .iter()
        .map(|entry| (entry.proof.leaf_index, entry.proof.epoch))
        .collect()
}

#[test]
fn a_removal_at_the_highest_epoch_retires_the_device_that_stated_it() -> FenceResult {
    let mut set = LeafMembershipSet::default();
    // Device 7 continues at leaf 0 and states its own removal of leaf 1 in
    // the same epoch, so both proofs are claimed at the epoch it reached.
    let continuing = proof(0, 1, 7, 5, true);
    let removed = proof(1, 2, 7, 5, false);
    assert_eq!(set.admit(&object(1), &continuing), Ok(Admission::Stored));
    set.insert(object(1), continuing);
    assert_eq!(
        set.admit(&object(2), &removed),
        Ok(Admission::Stored),
        "a removal of another leaf is not a duplicate continuing leaf"
    );
    set.insert(object(2), removed);
    // Device 8 continues at the same epoch and is unaffected by the fence.
    set.insert(object(3), proof(2, 3, 8, 5, true));

    assert_eq!(
        claims(&set),
        vec![(2, 5)],
        "the retired device states no continuing claim"
    );
    // Refusing the claim deletes nothing: both proofs stay retained and the
    // continuing proof still identifies the ACKs of its own epoch.
    assert_eq!(set.len(), 3);
    assert!(set.signer(0, &[1; 32], 5).is_some());
    assert!(set.signer(1, &[2; 32], 5).is_none());
    Ok(())
}

#[test]
fn a_removal_below_the_highest_epoch_leaves_the_claim_standing() -> FenceResult {
    let mut set = LeafMembershipSet::default();
    // The same two proofs, with the removal one epoch behind the continuing
    // proof: the removal is no longer claimed, so the device still claims.
    set.insert(object(1), proof(0, 1, 7, 5, true));
    set.insert(object(2), proof(1, 2, 7, 4, false));
    assert_eq!(claims(&set), vec![(0, 5)]);
    // Raising the removal to the continuing epoch retires the device.
    set.insert(object(3), proof(1, 2, 7, 5, false));
    assert!(claims(&set).is_empty());
    assert_eq!(set.len(), 2);
    Ok(())
}
