#![forbid(unsafe_code)]

//! `EGROUP FETCH AUTHORIZATIONS`, `ACKS` and `RECEIPTS` hold more than one
//! batch of proofs (companion 11.5, 11.7): each pages over one immutable
//! cut, so proofs that grow, are replaced or are retired after the cut never
//! enter or leave its pages, and receipts continue contiguously.

use agenc_relay_domain::e2ee::projection::{EmptyKind, StoreKind};
use agenc_relay_e2ee::limits::MAX_BATCH_OBJECTS;

use super::directory::many_devices;
use super::*;

/// The approval envelope of `device` over `tbs`, signed under `fingerprint`
/// when one is given instead of the principal's.
fn approval(
    harness: &Harness,
    tbs: &agenc_relay_e2ee::objects::conversation::ArcCommitAuthorizationTbs,
    device: u8,
    fingerprint: Option<[u8; 32]>,
) -> TestResult<Vec<u8>> {
    let mut envelope = approval_envelope(tbs.clone(), &harness.principal, device)?;
    if let Some(fingerprint) = fingerprint {
        envelope.approval.signer_root_fingerprint = fingerprint;
    }
    wire(ArcWireObjectKind::CommitApproval, &envelope)
}

/// Submits `bytes` as the attached device's approval and requires it stored.
fn submit_approval(harness: &mut Harness, conversation: [u8; 32], bytes: &[u8]) -> TestResult {
    let outcome = ok(harness.run(Op::SubmitAuthorization, &conversation, Some(bytes))?)?;
    assert_eq!(
        outcome.result,
        ResultBody::Stored(StoreKind::Authorization, object_id(bytes))
    );
    Ok(())
}

#[test]
fn authorizations_page_over_one_cut_that_proof_growth_never_changes() -> TestResult {
    let devices = many_devices();
    let mut harness = Harness::with_councils(&devices, &[DEVICE], &[DEVICE])?;
    let conversation = harness.bind_channel()?;
    let tbs = authorization_tbs(
        conversation,
        harness.initial_policy_id()?,
        ArcCommitAuthorizationRule::RoutineSelfUpdate,
        0,
    );
    let mut approvals = Vec::new();
    for device in &devices {
        harness.attach_as(*device)?;
        let bytes = approval(&harness, &tbs, *device, None)?;
        submit_approval(&mut harness, conversation, &bytes)?;
        approvals.push(bytes);
    }
    let prefix = [conversation.to_vec(), tbs.candidate_id.to_vec()].concat();
    let first = page(&mut harness, Op::FetchAuthorizations, &prefix, None)?;
    assert_eq!(first.objects.len(), MAX_BATCH_OBJECTS);
    // Between the pages the attached device replaces its approval, and a
    // further signer slot joins the candidate's proofs.
    let last = *devices.last().ok_or("a device")?;
    let replaced = approval(
        &harness,
        &authorization_tbs(
            conversation,
            harness.initial_policy_id()?,
            ArcCommitAuthorizationRule::RoutineSelfUpdate,
            1,
        ),
        last,
        None,
    )?;
    let grown = approval(&harness, &tbs, last, Some([0xff; 32]))?;
    submit_approval(&mut harness, conversation, &replaced)?;
    submit_approval(&mut harness, conversation, &grown)?;
    let second = page(&mut harness, Op::FetchAuthorizations, &prefix, first.next)?;
    assert_eq!(second.snapshot, first.snapshot);
    assert_eq!(second.next, None);
    assert_eq!(
        [first.objects, second.objects].concat(),
        approvals,
        "the cut keeps every approval it captured and nothing later"
    );
    // A new cut holds the replacement and the grown slot.
    let fresh = objects(&pages(&mut harness, Op::FetchAuthorizations, &prefix)?);
    let mut expected = approvals.clone();
    if let Some(slot) = expected.last_mut() {
        *slot = replaced;
    }
    expected.push(grown);
    assert_eq!(fresh, expected);
    // Another candidate has no approvals.
    let other = [conversation.to_vec(), vec![9; 32], vec![0]].concat();
    assert_eq!(
        ok(harness.run(Op::FetchAuthorizations, &other, None)?)?.result,
        ResultBody::Empty(EmptyKind::Authorizations)
    );
    Ok(())
}

/// Retains synthetic acknowledgements of `selector` for old leaves `leaves`.
fn seed_acks(
    harness: &mut Harness,
    conversation: [u8; 32],
    selector: [u8; 32],
    leaves: std::ops::Range<u32>,
) -> TestResult<Vec<Vec<u8>>> {
    let mut acks = Vec::new();
    for leaf in leaves {
        let bytes = object_of(ArcWireObjectKind::CommitAck, 600, u64::from(leaf))?;
        let id = retain(harness, bytes.clone());
        harness
            .coordinator
            .state
            .conversations
            .get_mut(&conversation)
            .ok_or("a bound conversation")?
            .acks
            .entry(selector)
            .or_default()
            .insert(leaf, id);
        acks.push(bytes);
    }
    Ok(acks)
}

#[test]
fn acknowledgements_page_over_one_cut_that_outlives_their_finalization() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let (receipt, commit_object_id, candidate_id) =
        submit_candidate(&mut harness, conversation, 0, 10)?;
    let ack_bytes = acknowledge(&mut harness, conversation, candidate_id, commit_object_id)?;
    let mut acks = vec![ack_bytes.clone()];
    acks.extend(seed_acks(&mut harness, conversation, candidate_id, 1..40)?);
    let prefix = [conversation.to_vec(), candidate_id.to_vec()].concat();
    let first = page(&mut harness, Op::FetchAcks, &prefix, None)?;
    assert_eq!(first.objects.len(), MAX_BATCH_OBJECTS);
    // A later acknowledgement joins, and then the finalization retires the
    // candidate's acknowledgements from the live state.
    seed_acks(&mut harness, conversation, candidate_id, 40..41)?;
    let request = finalization_request(
        &harness,
        conversation,
        &receipt,
        commit_object_id,
        candidate_id,
        &ack_bytes,
        &[DEVICE],
    )?;
    let finalized = ok(harness.run(Op::SubmitFinalization, &conversation, Some(&request))?)?;
    assert!(matches!(finalized.result, ResultBody::Finalized(..)));
    let empty = [prefix.clone(), vec![0]].concat();
    assert_eq!(
        ok(harness.run(Op::FetchAcks, &empty, None)?)?.result,
        ResultBody::Empty(EmptyKind::Acks)
    );
    let second = page(&mut harness, Op::FetchAcks, &prefix, first.next)?;
    assert_eq!(second.snapshot, first.snapshot);
    assert_eq!(second.next, None);
    assert_eq!([first.objects, second.objects].concat(), acks);
    Ok(())
}

#[test]
fn receipts_page_contiguously_over_one_cut_that_later_records_never_enter() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    submit_candidate(&mut harness, conversation, 0, 10)?;
    let real = harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .and_then(|known| known.records.get(&0))
        .and_then(|id| harness.coordinator.state.objects.get(id))
        .cloned()
        .ok_or("the candidate record")?;
    let mut records = vec![real];
    for sequence in 1..40 {
        records.push(seed_record(&mut harness, conversation, sequence, 900)?);
    }
    let prefix = receipts_from(conversation, 0);
    let first = page(&mut harness, Op::FetchReceipts, &prefix, None)?;
    assert_eq!(first.objects.len(), MAX_BATCH_OBJECTS);
    let later = seed_record(&mut harness, conversation, 40, 900)?;
    let second = page(&mut harness, Op::FetchReceipts, &prefix, first.next)?;
    assert_eq!(second.snapshot, first.snapshot);
    assert_eq!(second.next, None);
    assert_eq!([first.objects, second.objects].concat(), records);
    // The next request continues from the sequence after the cut.
    let next = pages(
        &mut harness,
        Op::FetchReceipts,
        &receipts_from(conversation, 40),
    )?;
    assert_eq!(objects(&next), vec![later]);
    // A record past a gap is not reached; a sequence past the log is empty.
    seed_record(&mut harness, conversation, 42, 900)?;
    assert_eq!(
        objects(&pages(
            &mut harness,
            Op::FetchReceipts,
            &receipts_from(conversation, 38)
        )?)
        .len(),
        3
    );
    let past = [receipts_from(conversation, 41), vec![0]].concat();
    assert_eq!(
        ok(harness.run(Op::FetchReceipts, &past, None)?)?.result,
        ResultBody::Empty(EmptyKind::Receipts)
    );
    // An unknown conversation is refused for its route.
    let unknown = [receipts_from([0x41; 32], 0), vec![0]].concat();
    assert_eq!(
        code(harness.run(Op::FetchReceipts, &unknown, None)?),
        Some(E2eeReplyCode::RouteInvalid)
    );
    Ok(())
}
