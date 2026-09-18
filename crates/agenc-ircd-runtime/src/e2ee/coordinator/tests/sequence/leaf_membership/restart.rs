//! Stored proofs and ACK signers survive reconstruction: after receipt loss
//! and a reload, repeated inputs keep the same authorization and
//! idempotence, including across a roster rotation and a real storage
//! shutdown and reopen.

#![forbid(unsafe_code)]

use super::finalization::rotate_roster;
use super::*;
use crate::state_core::durable::AccountServiceDurableWrite as Write;
use crate::state_core::fanout::FanoutRequest;
use crate::test_support::StateCoreFixture;
use agenc_ircd_storage::{PersistentRecordValue, ReadPlan, StoredKey, TableId};

/// A candidate position: prior epoch, candidate, and Commit object.
type Position = (u64, [u8; 32], [u8; 32]);

/// A channel with both members' proofs, an open candidate, and device 7's
/// accepted ACK; returns the ACK bytes and the candidate position.
fn acknowledged() -> TestResult<(Harness, [u8; 32], Vec<u8>, Position)> {
    let (mut harness, conversation) = two_member_channel()?;
    let (_, commit, candidate) = submit_candidate(&mut harness, conversation, 0, 20)?;
    let ack = commit_ack_as(
        conversation,
        0,
        candidate,
        commit,
        0,
        credential_of(0),
        LEAF_SEED,
        SignatureDomain::CommitProcessed,
    )?;
    let bytes = wire(IrcWireObjectKind::CommitAck, &ack)?;
    ok(harness.run(Op::SubmitCommitAck, &conversation, Some(&bytes))?)?;
    Ok((harness, conversation, bytes, (0, candidate, commit)))
}

/// Repeats device 7's ACK, conflicts it, and admits device 8's ACK.
fn replay_after_restart(
    harness: &mut Harness,
    conversation: [u8; 32],
    bytes: &[u8],
    position: Position,
) -> TestResult {
    let (epoch, candidate, commit) = position;
    let again = ok(harness.run(Op::SubmitCommitAck, &conversation, Some(bytes))?)?;
    assert_eq!(
        again.result,
        ResultBody::CommitAcked(conversation, candidate, object_id(bytes))
    );
    let mut differing = commit_ack_as(
        conversation,
        epoch,
        candidate,
        commit,
        0,
        credential_of(0),
        LEAF_SEED,
        SignatureDomain::CommitProcessed,
    )?;
    differing.tbs.finalization_authenticator = [9; 32];
    differing.old_leaf_signature = Opaque::from_slice(&sign(
        &key(LEAF_SEED),
        SignatureDomain::CommitProcessed,
        &differing.tbs,
    )?)?;
    refused(
        harness,
        Op::SubmitCommitAck,
        &conversation,
        &wire(IrcWireObjectKind::CommitAck, &differing)?,
        E2eeReplyCode::OperationConflict,
    )?;
    harness.attach_as(SECOND_DEVICE)?;
    let second = commit_ack_as(
        conversation,
        epoch,
        candidate,
        commit,
        1,
        credential_of(1),
        SECOND_LEAF_SEED,
        SignatureDomain::CommitProcessed,
    )?;
    ok(harness.run(
        Op::SubmitCommitAck,
        &conversation,
        Some(&wire(IrcWireObjectKind::CommitAck, &second)?),
    )?)?;
    Ok(())
}

pub(super) fn conversation_of(
    harness: &Harness,
    conversation: [u8; 32],
) -> TestResult<&super::super::super::super::ConversationState> {
    Ok(harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("conversation")?)
}

#[test]
fn proofs_and_ack_signers_survive_a_reload_after_receipt_loss() -> TestResult {
    let (harness, conversation, bytes, position) = acknowledged()?;
    let mut reloaded = harness.reloaded()?;
    let before = conversation_of(&harness, conversation)?;
    let after = conversation_of(&reloaded, conversation)?;
    assert_eq!(after.memberships, before.memberships);
    assert_eq!(after.memberships.len(), 2);
    assert_eq!(after.acks, before.acks);
    assert_eq!(after.ack_signers, before.ack_signers);
    replay_after_restart(&mut reloaded, conversation, &bytes, position)
}

#[test]
fn proofs_are_restored_under_their_named_roster_after_a_rotation() -> TestResult {
    let (mut harness, conversation, bytes, position) = acknowledged()?;
    // Both devices stay active under roster generation 1; the proofs keep
    // naming generation 0, which the reload re-verifies from its snapshot.
    rotate_roster(&mut harness, &[DEVICE, SECOND_DEVICE])?;
    let mut reloaded = harness.reloaded()?;
    assert_eq!(
        conversation_of(&reloaded, conversation)?.memberships,
        conversation_of(&harness, conversation)?.memberships
    );
    replay_after_restart(&mut reloaded, conversation, &bytes, position)
}

#[test]
fn a_reload_drops_a_proof_whose_object_is_missing() -> TestResult {
    let (mut harness, conversation, _, _) = acknowledged()?;
    let second = conversation_of(&harness, conversation)?
        .memberships
        .iter()
        .find(|entry| entry.proof.leaf_index == 1)
        .map(|entry| entry.object_id)
        .ok_or("second proof")?;
    let missing = agenc_ircd_storage::e2ee_records::object_key(&second)?;
    harness.writes.retain(|write| {
        !matches!(write, Write::Put { table: TableId::E2eeObject, key, .. } if *key == missing)
    });
    let reloaded = harness.reloaded()?;
    let restored = &conversation_of(&reloaded, conversation)?.memberships;
    assert_eq!(restored.len(), 1);
    assert!(restored.iter().all(|entry| entry.proof.leaf_index == 0));
    Ok(())
}

fn stage(core: &mut StateCoreFixture, writes: &[Write]) -> TestResult {
    let context = core.context_mut()?;
    let plan = context.domain().plan_account_service_checkpoint()?;
    let writes = writes
        .iter()
        .map(|write| {
            let (table, key, bytes) = write.encoded_record().ok_or("put")?;
            Ok(Write::put(table, key.clone(), bytes.to_vec())?
                .at_revision(plan.resulting_revision().get())?)
        })
        .collect::<TestResult<Vec<_>>>()?;
    context
        .stage_durable_with_account_service(
            plan,
            FanoutRequest::new(Vec::new(), Vec::new())?,
            None,
            0,
            writes,
        )
        .map_err(|error| format!("stage: {error:?}"))?;
    Ok(())
}

async fn stored(
    core: &mut StateCoreFixture,
    table: TableId,
    key: &StoredKey,
) -> TestResult<PersistentRecordValue> {
    let read_id = core
        .context_mut()?
        .submit_storage_read(ReadPlan::exact(table, key.clone()))?;
    let message =
        tokio::time::timeout(std::time::Duration::from_secs(5), core.next_storage_read()).await??;
    assert_eq!(message.read_id, read_id);
    let result = message.result?;
    let row = result.records.first().ok_or("committed row")?;
    let opened = core
        .context_mut()?
        .open_storage_plaintext(table, key, &row.sealed_record)?;
    Ok(PersistentRecordValue::decode(
        table,
        opened.expose_for_storage_codec(),
    )?)
}

#[tokio::test]
async fn proofs_and_acks_reopen_from_real_storage_with_the_same_authorization() -> TestResult {
    let mut core = StateCoreFixture::with_registration_router(vec![73; 65_536])?;
    let (harness, conversation, bytes, position) = acknowledged()?;
    stage(&mut core, &harness.writes)?;
    core.commit_staged_batch().await?;
    core.restart_registration_storage(vec![74; 65_536])?;
    // The fresh coordinator keeps the source's delivery identity; only the
    // storage underneath was shut down and reopened.
    let mut fresh = Harness::with_devices(&[DEVICE, SECOND_DEVICE])?;
    for write in &harness.writes {
        let (table, key, _) = write.encoded_record().ok_or("put")?;
        let value = stored(&mut core, table, key).await?;
        fresh
            .coordinator
            .admit_restored_with_backing(table, key, &value, &fresh.backing);
    }
    fresh
        .coordinator
        .finish_restore_with_backing(fresh.backing.clone())?;
    fresh.sequence = harness.sequence;
    let device = harness.device();
    if let Some(origin) = fresh.coordinator.state.origins.get_mut(&origin_key()) {
        origin.next_sequence = harness.sequence;
        origin.device = device;
    }
    let before = conversation_of(&harness, conversation)?;
    let after = conversation_of(&fresh, conversation)?;
    assert_eq!(after.memberships, before.memberships);
    assert_eq!(after.acks, before.acks);
    assert_eq!(after.ack_signers, before.ack_signers);
    replay_after_restart(&mut fresh, conversation, &bytes, position)
}

/// The `membership/v1/` row of `leaf` with `credential_of(leaf)`.
fn membership_key(conversation: [u8; 32], leaf: u32) -> TestResult<StoredKey> {
    Ok(
        agenc_ircd_storage::e2ee_records::SequencerRow::membership_key(
            &conversation,
            leaf,
            &credential_of(leaf),
        )?,
    )
}

/// Replaces the logical row under `key` with `row`.
fn replace_row(
    harness: &mut Harness,
    key: &StoredKey,
    row: agenc_ircd_storage::e2ee_records::SequencerRow,
) -> TestResult {
    let write = crate::e2ee::coordinator::request::state_row(
        TableId::E2eeState,
        agenc_ircd_storage::e2ee_records::SEQUENCER_ROW_KIND,
        key.clone(),
        row.encode()?,
    )
    .map_err(|code| format!("{code:?}"))?;
    let slot = harness
        .writes
        .iter_mut()
        .find(|stored| matches!(stored, Write::Put { key: stored_key, .. } if stored_key == key))
        .ok_or("row")?;
    *slot = write;
    Ok(())
}

pub(super) fn memberships_of(
    harness: &Harness,
    conversation: [u8; 32],
) -> TestResult<Vec<(u32, bool)>> {
    Ok(conversation_of(harness, conversation)?
        .memberships
        .iter()
        .map(|entry| (entry.proof.leaf_index, entry.proof.is_continuing()))
        .collect())
}

#[test]
fn a_removed_proof_reloads_and_keeps_its_leaf_out_of_the_continuing_set() -> TestResult {
    let (mut harness, conversation) = two_member_channel()?;
    let removal = super::finalization::finalize_both(&mut harness, conversation)?;
    harness.attach_as(SECOND_DEVICE)?;
    let mut removed = MembershipSpec::continuing(
        &harness.principal,
        conversation,
        SECOND_DEVICE,
        SECOND_LEAF_SEED,
        1,
    );
    removed.epoch = 1;
    removed.removed = Some(removal);
    harness.publish_membership(conversation, &membership_proof(&removed)?)?;
    let mut reloaded = harness.reloaded()?;
    assert_eq!(
        memberships_of(&reloaded, conversation)?,
        vec![(0, true), (1, false)]
    );
    assert_eq!(
        conversation_of(&reloaded, conversation)?.memberships,
        conversation_of(&harness, conversation)?.memberships
    );
    // The removed leaf still identifies no signer after the reload.
    let (_, commit, candidate) = submit_candidate(&mut reloaded, conversation, 1, 40)?;
    let ack = commit_ack_as(
        conversation,
        1,
        candidate,
        commit,
        1,
        credential_of(1),
        SECOND_LEAF_SEED,
        SignatureDomain::CommitProcessed,
    )?;
    refused(
        &mut reloaded,
        Op::SubmitCommitAck,
        &conversation,
        &wire(IrcWireObjectKind::CommitAck, &ack)?,
        E2eeReplyCode::BindingAuthInvalid,
    )
}

#[test]
fn a_reload_restores_nothing_from_an_inconsistent_row() -> TestResult {
    use agenc_ircd_storage::e2ee_records::SequencerRow;
    type Damage = fn([u8; 32], [u8; 32]) -> SequencerRow;
    let cases: [(&str, Damage); 3] = [
        ("an epoch the proof does not name", |proof, _| {
            SequencerRow::Membership {
                object_id: proof,
                epoch: 5,
                device_id: [SECOND_DEVICE; 16],
                disposition: 1,
            }
        }),
        ("a disposition the proof does not state", |proof, _| {
            SequencerRow::Membership {
                object_id: proof,
                epoch: 0,
                device_id: [SECOND_DEVICE; 16],
                disposition: 2,
            }
        }),
        ("an object that is not a proof", |_, binding| {
            SequencerRow::Membership {
                object_id: binding,
                epoch: 0,
                device_id: [SECOND_DEVICE; 16],
                disposition: 1,
            }
        }),
    ];
    for (name, damage) in cases {
        let (mut harness, conversation, _, _) = acknowledged()?;
        let state = conversation_of(&harness, conversation)?;
        let binding = state.binding_object_id;
        let proof = state
            .memberships
            .iter()
            .find(|entry| entry.proof.leaf_index == 1)
            .map(|entry| entry.object_id)
            .ok_or("second proof")?;
        replace_row(
            &mut harness,
            &membership_key(conversation, 1)?,
            damage(proof, binding),
        )?;
        let reloaded = harness.reloaded()?;
        assert_eq!(
            memberships_of(&reloaded, conversation)?,
            vec![(0, true)],
            "{name}"
        );
    }
    Ok(())
}

#[test]
fn a_reload_admits_proofs_in_order_and_skips_a_conflicting_row() -> TestResult {
    use agenc_ircd_storage::e2ee_records::SequencerRow;
    let (mut harness, conversation, _, _) = acknowledged()?;
    // A row that admission would have refused: device 7's second continuing
    // leaf at the epoch of its leaf 0.
    let duplicate = membership_proof(&MembershipSpec::continuing(
        &harness.principal,
        conversation,
        DEVICE,
        35,
        3,
    ))?;
    let bytes = wire(IrcWireObjectKind::LeafMembershipProof, &duplicate)?;
    harness.writes.push(
        super::super::super::super::CompanionCoordinator::object_write(&bytes)
            .map_err(|code| format!("{code:?}"))?,
    );
    let key = membership_key(conversation, 3)?;
    harness.writes.push(
        crate::e2ee::coordinator::request::state_row(
            TableId::E2eeState,
            agenc_ircd_storage::e2ee_records::SEQUENCER_ROW_KIND,
            key,
            SequencerRow::Membership {
                object_id: object_id(&bytes),
                epoch: 0,
                device_id: DEVICE_ID,
                disposition: 1,
            }
            .encode()?,
        )
        .map_err(|code| format!("{code:?}"))?,
    );
    let reloaded = harness.reloaded()?;
    assert_eq!(
        memberships_of(&reloaded, conversation)?,
        vec![(0, true), (1, true)]
    );
    Ok(())
}

#[test]
fn an_ack_signer_is_restored_only_through_a_restored_proof() -> TestResult {
    let (mut harness, conversation, _, (_, candidate, _)) = acknowledged()?;
    let first = membership_key(conversation, 0)?;
    harness
        .writes
        .retain(|write| !matches!(write, Write::Put { key, .. } if *key == first));
    let reloaded = harness.reloaded()?;
    let state = conversation_of(&reloaded, conversation)?;
    assert!(
        state
            .acks
            .get(&candidate)
            .is_some_and(|acks| acks.contains_key(&0))
    );
    assert!(
        state
            .ack_signers
            .get(&candidate)
            .is_none_or(|signers| signers.is_empty())
    );
    assert_eq!(memberships_of(&reloaded, conversation)?, vec![(1, true)]);
    Ok(())
}

/// Retains `proof` as an injected object with its `membership/v1/` row, as
/// if a row had been written without passing admission.
pub(super) fn inject(
    harness: &mut Harness,
    conversation: [u8; 32],
    proof: &agenc_ircd_e2ee::objects::membership::IrcLeafMembershipProof,
    disposition: u8,
) -> TestResult {
    use agenc_ircd_storage::e2ee_records::SequencerRow;
    let bytes = wire(IrcWireObjectKind::LeafMembershipProof, proof)?;
    harness.writes.push(
        super::super::super::super::CompanionCoordinator::object_write(&bytes)
            .map_err(|code| format!("{code:?}"))?,
    );
    let key = SequencerRow::membership_key(
        &conversation,
        proof.tbs.leaf_index,
        &proof.tbs.old_credential_hash,
    )?;
    harness.writes.push(
        crate::e2ee::coordinator::request::state_row(
            TableId::E2eeState,
            agenc_ircd_storage::e2ee_records::SEQUENCER_ROW_KIND,
            key,
            SequencerRow::Membership {
                object_id: object_id(&bytes),
                epoch: proof.tbs.epoch,
                device_id: proof.tbs.device_id,
                disposition,
            }
            .encode()?,
        )
        .map_err(|code| format!("{code:?}"))?,
    );
    Ok(())
}

#[test]
fn a_reload_skips_an_unverifiable_proof_and_an_unretained_removal() -> TestResult {
    // A proof whose device signature no longer verifies.
    let (mut harness, conversation, _, _) = acknowledged()?;
    let mut forged = membership_proof(&MembershipSpec::continuing(
        &harness.principal,
        conversation,
        SECOND_DEVICE,
        36,
        6,
    ))?;
    if let Some(byte) = forged.device_signature.first_mut() {
        *byte ^= 1;
    }
    inject(&mut harness, conversation, &forged, 1)?;
    let reloaded = harness.reloaded()?;
    assert_eq!(
        memberships_of(&reloaded, conversation)?,
        vec![(0, true), (1, true)]
    );
    // A removed proof naming a finalization the conversation never retained.
    let (mut harness, conversation, _, _) = acknowledged()?;
    let mut unretained =
        MembershipSpec::continuing(&harness.principal, conversation, SECOND_DEVICE, 37, 7);
    unretained.removed = Some([9; 32]);
    let unretained = membership_proof(&unretained)?;
    inject(&mut harness, conversation, &unretained, 2)?;
    let reloaded = harness.reloaded()?;
    assert_eq!(
        memberships_of(&reloaded, conversation)?,
        vec![(0, true), (1, true)]
    );
    Ok(())
}

#[test]
fn a_retained_ack_without_its_object_restores_no_signer() -> TestResult {
    let (mut harness, conversation, bytes, (_, candidate, _)) = acknowledged()?;
    let missing = agenc_ircd_storage::e2ee_records::object_key(&object_id(&bytes))?;
    harness.writes.retain(|write| {
        !matches!(write, Write::Put { table: TableId::E2eeObject, key, .. } if *key == missing)
    });
    let reloaded = harness.reloaded()?;
    let state = conversation_of(&reloaded, conversation)?;
    assert!(
        state
            .acks
            .get(&candidate)
            .is_some_and(|acks| acks.contains_key(&0))
    );
    assert!(
        state
            .ack_signers
            .get(&candidate)
            .is_none_or(|signers| signers.is_empty())
    );
    Ok(())
}
