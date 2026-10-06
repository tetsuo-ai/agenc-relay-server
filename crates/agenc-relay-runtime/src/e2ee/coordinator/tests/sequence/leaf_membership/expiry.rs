//! A leaf proof names the roster its credential was authorized under
//! (companion 13.7.3), which the account replaces long before the leaf
//! leaves the group. A replaced roster that a statement of the conversation
//! names, here the roster head its binding names, stays retained after
//! object expiry, so a device's first proof naming it is still admitted,
//! and the proofs already stored still restore after a restart. A replaced
//! roster that no statement names is collected, and a first proof naming it
//! is refused (`retention::rosters`).

#![forbid(unsafe_code)]

use super::finalization::rotate_roster;
use super::restart::conversation_of;
use super::*;
use crate::e2ee::coordinator::tests::sequence::retention::{PAST_EVERY_WINDOW, expire};

/// The `(leaf index, roster generation)` of every stored proof.
fn stored(harness: &Harness, conversation: [u8; 32]) -> TestResult<Vec<(u32, u64)>> {
    Ok(conversation_of(harness, conversation)?
        .memberships
        .iter()
        .map(|entry| (entry.proof.leaf_index, entry.proof.roster_generation))
        .collect())
}

#[test]
fn a_proof_naming_a_replaced_roster_is_admitted_and_restored_after_expiry() -> TestResult {
    let mut harness = Harness::with_devices(&[DEVICE, SECOND_DEVICE])?;
    let conversation = harness.bind_channel()?;
    rotate_roster(&mut harness, &[DEVICE, SECOND_DEVICE])?;
    expire(&mut harness, PAST_EVERY_WINDOW)?;
    harness.attach_as(SECOND_DEVICE)?;
    // Device 8's credential, and so its proof, still names generation zero.
    let proof = harness.leaf_proof(conversation, SECOND_DEVICE, SECOND_LEAF_SEED, 1)?;
    let outcome = harness.run(
        Op::SubmitMembership,
        &conversation,
        Some(&proof_bytes(&proof)?),
    )?;
    assert_eq!(code(outcome), None);
    assert_eq!(stored(&harness, conversation)?, vec![(0, 0), (1, 0)]);
    expire(&mut harness, PAST_EVERY_WINDOW + 1)?;
    let restarted = harness.reloaded()?;
    assert!(restarted.coordinator.owner_reconstruction.is_clean());
    assert_eq!(stored(&restarted, conversation)?, vec![(0, 0), (1, 0)]);
    Ok(())
}
