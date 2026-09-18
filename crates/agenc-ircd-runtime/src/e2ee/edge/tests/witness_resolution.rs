#![forbid(unsafe_code)]

//! A durable witness resolves only under an authenticated continuation.

use agenc_ircd_crypto::{Ed25519SecretKey, SemanticHashDomain, SignatureDomain, sign_canonical};
use agenc_ircd_e2ee::ids::semantic_id_of;
use agenc_ircd_e2ee::objects::federation::IrcFederationWitnessResolution;
use agenc_ircd_e2ee::objects::sequencing::{
    IrcCandidateReceipt, IrcCandidateReceiptTbs, IrcSequencerRecord,
};
use agenc_ircd_e2ee::wire::fragment::fragment_object;

use super::gating::{durable_fault, next_line};
use super::*;
use crate::budget::{BackingReservationPort, MemoryBudget};
use crate::e2ee::edge::router::Resolved;
use crate::sync::Arc;

const TOKEN: [u8; 16] = [77; 16];
const EDGE: [u8; 16] = [2; 16];
const COORDINATOR: [u8; 16] = [3; 16];
/// The head `install_route` left and the position the violation refused.
const HEAD: [u8; 32] = [59; 32];
const EXPECTED: u64 = 5;

/// One complete `sequencer_record` object and its semantic identifier.
struct Record {
    bytes: Vec<u8>,
    object_id: [u8; 32],
    semantic_id: [u8; 32],
}

fn credential_id() -> TestResult<[u8; 32]> {
    Ok(super::sequencer_key_set()
        .and_then(|set| set.current().map(|credential| credential.credential_id))
        .ok_or("the test key set holds no credential")?)
}

/// A real candidate receipt signed by the key set's only credential.
fn record(sequence: u64, predecessor: [u8; 32], key_id: [u8; 32]) -> TestResult<Record> {
    let tbs = IrcCandidateReceiptTbs {
        profile_version: 1,
        network_id: [1; 32],
        conversation_id: CONVERSATION,
        route_sequence: sequence,
        prior_epoch: sequence,
        resulting_epoch: sequence + 1,
        candidate_sequence: 0,
        commit_object_id: [31; 32],
        prior_state_id: [58; 32],
        predecessor_record_id: predecessor,
        sequenced_at: 1_000,
        sequencer_key_id: key_id,
    };
    let semantic_id = semantic_id_of(SemanticHashDomain::CandidateId, &tbs)?;
    let signature = sign_canonical(
        &Ed25519SecretKey::from_bytes(super::SEQUENCER_SEED),
        SignatureDomain::CandidateReceipt,
        &tbs.encode()?,
    )?;
    let receipt = IrcCandidateReceipt {
        tbs,
        sequencer_signature: *signature.as_bytes(),
    };
    let bytes = IrcWireObject::new(
        IrcWireObjectKind::SequencerRecord,
        IrcSequencerRecord::Candidate(receipt).encode()?,
    )?
    .encode()?;
    Ok(Record {
        object_id: *agenc_ircd_e2ee::ObjectId::compute(&bytes).as_bytes(),
        bytes,
        semantic_id,
    })
}

/// The authentic two-record continuation of the retained head.
fn continuation() -> TestResult<Vec<Record>> {
    let key_id = credential_id()?;
    let first = record(EXPECTED, HEAD, key_id)?;
    let second = record(EXPECTED + 1, first.semantic_id, key_id)?;
    Ok(vec![first, second])
}

fn resolution_object(
    conversation: [u8; 32],
    records: &[Record],
    head: (u64, [u8; 32]),
) -> TestResult<Vec<u8>> {
    anchored_resolution(conversation, records, head, (EXPECTED, HEAD))
}

fn anchored_resolution(
    conversation: [u8; 32],
    records: &[Record],
    head: (u64, [u8; 32]),
    anchor: (u64, [u8; 32]),
) -> TestResult<Vec<u8>> {
    let ids: Vec<u8> = records.iter().flat_map(|record| record.object_id).collect();
    let body = IrcFederationWitnessResolution {
        profile_version: 1,
        network_id: [1; 32],
        coordinator_server_id: COORDINATOR,
        target_server_id: EDGE,
        conversation_id: conversation,
        resolution_token: TOKEN,
        expected_sequence: anchor.0,
        expected_head_id: anchor.1,
        record_count: u32::try_from(records.len())?,
        new_head_sequence: head.0,
        new_head_id: head.1,
        record_object_ids: Opaque::new(ids)?,
    };
    Ok(IrcWireObject::new(IrcWireObjectKind::WitnessResolution, body.encode()?)?.encode()?)
}

fn begin_frames(conversation: [u8; 32], object: &[u8]) -> TestResult<Vec<CompanionFrame>> {
    let object_id = *agenc_ircd_e2ee::ObjectId::compute(object).as_bytes();
    Ok(fragment_object(object)?
        .into_iter()
        .map(|fragment| CompanionFrame::WitnessBegin {
            target_server_id: EDGE,
            conversation_id: conversation,
            resolution_token: TOKEN,
            object_id,
            fragment,
        })
        .collect())
}

fn entry_frames(entry_sequence: u32, record: &Record) -> TestResult<Vec<CompanionFrame>> {
    Ok(fragment_object(&record.bytes)?
        .into_iter()
        .map(|fragment| CompanionFrame::WitnessEntry {
            target_server_id: EDGE,
            resolution_token: TOKEN,
            entry_sequence,
            object_id: record.object_id,
            fragment,
        })
        .collect())
}

fn end_frame(record_count: u32) -> CompanionFrame {
    CompanionFrame::WitnessEnd {
        target_server_id: EDGE,
        resolution_token: TOKEN,
        record_count,
    }
}

/// The complete delivery of one resolution set, in wire order.
fn delivery(records: &[Record], object: &[u8]) -> TestResult<Vec<CompanionFrame>> {
    let mut frames = begin_frames(CONVERSATION, object)?;
    for (index, record) in records.iter().enumerate() {
        frames.extend(entry_frames(u32::try_from(index)?, record)?);
    }
    frames.push(end_frame(u32::try_from(records.len())?));
    Ok(frames)
}

/// A fixture whose durable row is already sealed and whose replacement link
/// reached the blocked witness phase with its request sent.
async fn requesting() -> TestResult<(WitnessFixture, LinkQueue)> {
    let mut fixture = Box::pin(durable_fault()).await?;
    fixture
        .companion
        .restore_witness_backing(BackingReservationPort::new(Arc::new(MemoryBudget::new(
            1 << 20,
        ))))?;
    let (replacement, mut queue) = link_queue(1 << 20);
    establish(&mut fixture.core, &mut fixture.base, &replacement, 2)?;
    while let Ok(line) = tokio::time::timeout(Duration::from_millis(5), queue.recv()).await {
        drop(line.ok_or("replacement base link closed")?);
    }
    assert!(
        fixture
            .companion
            .link_active(fixture.core.context_mut()?, &mut fixture.base)
    );
    assert!(next_line(&mut queue).await?.contains(" ERESUME "));
    assert!(
        fixture
            .companion
            .handle_frames(
                fixture.core.context_mut()?,
                &mut fixture.base,
                vec![CompanionFrame::ResumeOk {
                    target_server_id: EDGE,
                    server_incarnation: [4; 16],
                    delivery_generation: 2,
                    next_delivery_sequence: 7,
                }]
            )
            .is_empty()
    );
    assert!(next_line(&mut queue).await?.contains(" EWITNESS REQUEST "));
    assert_eq!(fixture.companion.phase, Phase::Witness);
    Ok((fixture, queue))
}

fn feed(fixture: &mut WitnessFixture, frames: Vec<CompanionFrame>) -> TestResult {
    assert!(
        fixture
            .companion
            .handle_frames(fixture.core.context_mut()?, &mut fixture.base, frames)
            .is_empty()
    );
    Ok(())
}

fn stored_witness(fixture: &mut WitnessFixture) -> TestResult<bool> {
    let key = WitnessRow::key(&CONVERSATION)?;
    let found = fixture.core.stored_row_exists(TableId::E2eeState, key)?;
    Ok(found)
}

#[tokio::test]
async fn an_authenticated_continuation_installs_its_head_and_deletes_the_row() -> TestResult {
    let (mut fixture, mut queue) = Box::pin(requesting()).await?;
    let records = continuation()?;
    let head = records.last().ok_or("records")?.semantic_id;
    let object = resolution_object(CONVERSATION, &records, (EXPECTED + 1, head))?;
    feed(&mut fixture, delivery(&records, &object)?)?;
    // Nothing is answered before the durable transaction commits.
    assert_open_and_silent(&mut queue).await?;
    assert!(stored_witness(&mut fixture)?);
    fixture.core.commit_staged_batch().await?;
    assert!(
        fixture
            .companion
            .batch_applied(fixture.core.context_mut()?, &mut fixture.base)
            .is_empty()
    );
    let resolved = fixture
        .companion
        .line(&CompanionFrame::WitnessResolved {
            coordinator_server_id: COORDINATOR,
            conversation_id: CONVERSATION,
            resolution_token: TOKEN,
            new_head_sequence: EXPECTED + 1,
            new_head_id: head,
        })
        .map_err(|refusal| refusal.code.to_string())?;
    assert_eq!(next_line(&mut queue).await?, resolved.as_str());
    // Only then do the origins replay.
    assert!(next_line(&mut queue).await?.contains(" EORIGIN RESET "));
    assert_eq!(fixture.companion.phase, Phase::Origins);
    assert!(!fixture.companion.witness_recovery_pending());
    assert!(!fixture.companion.blocked_conversation(&CONVERSATION));
    assert_eq!(
        fixture
            .companion
            .conversations
            .get(&CONVERSATION)
            .map(|route| (
                route.head.sequence,
                route.head.record_id,
                route.head.recorded
            )),
        Some((EXPECTED + 1, head, true))
    );
    assert!(!stored_witness(&mut fixture)?);
    Ok(())
}

#[tokio::test]
async fn an_empty_answer_retains_the_row_and_repeats_its_request() -> TestResult {
    let (mut fixture, mut queue) = Box::pin(requesting()).await?;
    let object = resolution_object(CONVERSATION, &[], (EXPECTED, HEAD))?;
    let mut frames = begin_frames(CONVERSATION, &object)?;
    frames.push(end_frame(0));
    feed(&mut fixture, frames)?;
    assert_eq!(fixture.core.context_mut()?.pending_len(), 0);
    assert!(stored_witness(&mut fixture)?);
    assert!(fixture.companion.witness_recovery_pending());
    assert_eq!(fixture.companion.phase, Phase::Witness);
    assert_open_and_silent(&mut queue).await?;
    // The reserved wake repeats the exact request.
    let entry = due_resolution(&mut fixture)?;
    assert!(fixture.companion.witness_timer_fired(
        fixture.core.context_mut()?,
        &mut fixture.base,
        entry
    ));
    assert!(next_line(&mut queue).await?.contains(" EWITNESS REQUEST "));
    assert_eq!(
        fixture
            .companion
            .conversations
            .get(&CONVERSATION)
            .map(|route| route.head.sequence),
        Some(4)
    );
    Ok(())
}

fn due_resolution(
    fixture: &mut WitnessFixture,
) -> TestResult<crate::state_core::timers::TimerEntry> {
    let timers = fixture.core.context_mut()?.timers_mut();
    for _ in 0..16 {
        let deadline = timers.next_deadline().ok_or("missing resolution wake")?;
        let entry = timers
            .pop_due(deadline)
            .ok_or("missing due resolution wake")?;
        if entry.kind == crate::state_core::timers::TimerKind::CompanionWitnessResolution {
            return Ok(entry);
        }
    }
    Err("resolution wake hidden behind unrelated timers".into())
}

#[tokio::test]
async fn a_forked_first_record_marks_the_row_conflict_and_resumes_the_others() -> TestResult {
    let (mut fixture, mut queue) = Box::pin(requesting()).await?;
    // A real record at the expected position under another predecessor.
    let forked = record(EXPECTED, [99; 32], credential_id()?)?;
    let records = vec![forked];
    let head = records.first().ok_or("records")?.semantic_id;
    let object = resolution_object(CONVERSATION, &records, (EXPECTED, head))?;
    feed(&mut fixture, delivery(&records, &object)?)?;
    assert!(fixture.companion.witness_recovery_pending());
    fixture.core.commit_staged_batch().await?;
    assert!(
        fixture
            .companion
            .batch_applied(fixture.core.context_mut()?, &mut fixture.base)
            .is_empty()
    );
    // No head moved and no RESOLVED went out; the origins replayed instead.
    assert!(next_line(&mut queue).await?.contains(" EORIGIN RESET "));
    assert_eq!(fixture.companion.phase, Phase::Origins);
    assert_eq!(
        fixture
            .companion
            .conversations
            .get(&CONVERSATION)
            .map(|route| route.head.sequence),
        Some(4)
    );
    // The mark is durable, permanent, and confined to its conversation.
    assert!(stored_witness(&mut fixture)?);
    assert!(!fixture.companion.witness_recovery_pending());
    assert!(!fixture.companion.retention_blocked());
    assert!(fixture.companion.blocked_conversation(&CONVERSATION));
    assert!(!fixture.companion.blocked_conversation(&[10; 32]));
    assert!(
        fixture
            .companion
            .witness_blocks(&Resolved::ChannelApplication {
                conversation_id: CONVERSATION,
                channel: CHANNEL,
            })
    );
    assert!(
        !fixture
            .companion
            .witness_blocks(&Resolved::ChannelApplication {
                conversation_id: [10; 32],
                channel: CHANNEL,
            })
    );
    // An EWITNESS frame outside the blocked phase is refused and the mark
    // survives it.
    let object = resolution_object(CONVERSATION, &records, (EXPECTED, head))?;
    feed(&mut fixture, begin_frames(CONVERSATION, &object)?)?;
    assert_eq!(fixture.companion.phase, Phase::Down);
    assert!(fixture.companion.blocked_conversation(&CONVERSATION));
    // The mark is read back from sealed storage, and still blocks only its
    // own conversation.
    fixture.base = base_edge();
    fixture.companion = edge();
    fixture
        .core
        .restore_edge_state(&mut fixture.base, Some(&mut fixture.companion))?;
    assert!(!fixture.companion.witness_recovery_pending());
    assert!(fixture.companion.blocked_conversation(&CONVERSATION));
    assert!(!fixture.companion.blocked_conversation(&[10; 32]));
    Ok(())
}

/// Every refusal below leaves the row exactly where it was and closes the
/// companion phase without moving the head (companion 12.5.1).
async fn assert_refused(frames: Vec<CompanionFrame>) -> TestResult {
    let (mut fixture, _queue) = Box::pin(requesting()).await?;
    feed(&mut fixture, frames)?;
    assert_eq!(fixture.companion.phase, Phase::Down);
    assert_eq!(fixture.core.context_mut()?.pending_len(), 0);
    assert!(stored_witness(&mut fixture)?);
    assert!(fixture.companion.witness_recovery_pending());
    assert_eq!(
        fixture
            .companion
            .conversations
            .get(&CONVERSATION)
            .map(|route| route.head.sequence),
        Some(4)
    );
    assert!(!fixture.companion.blocked_conversation(&[10; 32]));
    Ok(())
}

#[tokio::test]
async fn a_record_under_an_unknown_credential_is_refused() -> TestResult {
    let key_id = credential_id()?;
    let foreign = record(EXPECTED, HEAD, [123; 32])?;
    let object = resolution_object(
        CONVERSATION,
        std::slice::from_ref(&foreign),
        (EXPECTED, foreign.semantic_id),
    )?;
    Box::pin(assert_refused(delivery(
        std::slice::from_ref(&foreign),
        &object,
    )?))
    .await?;
    // The same record under the negotiated credential resolves, so only the
    // key made the difference.
    let signed = record(EXPECTED, HEAD, key_id)?;
    let object = resolution_object(
        CONVERSATION,
        std::slice::from_ref(&signed),
        (EXPECTED, signed.semantic_id),
    )?;
    let (mut fixture, _queue) = Box::pin(requesting()).await?;
    feed(
        &mut fixture,
        delivery(std::slice::from_ref(&signed), &object)?,
    )?;
    assert_ne!(fixture.core.context_mut()?.pending_len(), 0);
    Ok(())
}

#[tokio::test]
async fn a_skipped_position_or_a_declared_identifier_mismatch_is_refused() -> TestResult {
    let key_id = credential_id()?;
    // A first record that starts beyond the expected position.
    let ahead = record(EXPECTED + 1, HEAD, key_id)?;
    let object = resolution_object(
        CONVERSATION,
        std::slice::from_ref(&ahead),
        (EXPECTED + 1, ahead.semantic_id),
    )?;
    Box::pin(assert_refused(delivery(
        std::slice::from_ref(&ahead),
        &object,
    )?))
    .await?;
    // A record whose object is not the identifier the resolution declared.
    let records = continuation()?;
    let head = records.last().ok_or("records")?.semantic_id;
    let object = resolution_object(CONVERSATION, &records, (EXPECTED + 1, head))?;
    let mut frames = begin_frames(CONVERSATION, &object)?;
    frames.extend(entry_frames(0, records.last().ok_or("records")?)?);
    Box::pin(assert_refused(frames)).await?;
    // A second record that does not name the first.
    let mut set = continuation()?;
    set.pop();
    set.push(record(EXPECTED + 1, [88; 32], key_id)?);
    let head = set.last().ok_or("records")?.semantic_id;
    let object = resolution_object(CONVERSATION, &set, (EXPECTED + 1, head))?;
    Box::pin(assert_refused(delivery(&set, &object)?)).await
}

#[tokio::test]
async fn a_wrong_count_anchor_or_declared_head_is_refused() -> TestResult {
    let records = continuation()?;
    let head = records.last().ok_or("records")?.semantic_id;
    // END names another count than the resolution object declared.
    let object = resolution_object(CONVERSATION, &records, (EXPECTED + 1, head))?;
    let mut frames = begin_frames(CONVERSATION, &object)?;
    for (index, record) in records.iter().enumerate() {
        frames.extend(entry_frames(u32::try_from(index)?, record)?);
    }
    frames.push(end_frame(1));
    Box::pin(assert_refused(frames)).await?;
    // The declared head is not the head the verified chain reached.
    let object = resolution_object(CONVERSATION, &records, (EXPECTED + 1, [7; 32]))?;
    Box::pin(assert_refused(delivery(&records, &object)?)).await?;
    // The resolution does not repeat the row's retained anchor.
    let object = anchored_resolution(
        CONVERSATION,
        &records,
        (EXPECTED + 1, head),
        (EXPECTED, [7; 32]),
    )?;
    Box::pin(assert_refused(begin_frames(CONVERSATION, &object)?)).await?;
    let object = anchored_resolution(
        CONVERSATION,
        &records,
        (EXPECTED + 1, head),
        (EXPECTED + 1, HEAD),
    )?;
    Box::pin(assert_refused(begin_frames(CONVERSATION, &object)?)).await?;
    // The resolution names another conversation than the line it opened.
    let object = resolution_object([10; 32], &records, (EXPECTED + 1, head))?;
    Box::pin(assert_refused(begin_frames(CONVERSATION, &object)?)).await
}
