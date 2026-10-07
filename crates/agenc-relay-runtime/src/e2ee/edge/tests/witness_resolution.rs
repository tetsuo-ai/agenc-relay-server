#![forbid(unsafe_code)]

//! A durable witness resolves only under an authenticated continuation.

use agenc_relay_crypto::{Ed25519SecretKey, SemanticHashDomain, SignatureDomain, sign_canonical};
use agenc_relay_e2ee::ids::semantic_id_of;
use agenc_relay_e2ee::objects::federation::ArcFederationWitnessResolution;
use agenc_relay_e2ee::objects::sequencing::{
    ArcCandidateReceipt, ArcCandidateReceiptTbs, ArcSequencerRecord,
};
use agenc_relay_e2ee::wire::fragment::fragment_object;

use super::gating::{durable_fault, next_line};
use super::*;
use crate::budget::{BackingReservationPort, MemoryBudget};
use crate::e2ee::edge::router::Resolved;
use crate::sync::Arc;

#[path = "witness_bridged.rs"]
mod bridged;

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
    signed_record(
        sequence,
        predecessor,
        key_id,
        (super::SEQUENCER_SEED, 1_000),
    )
}

/// A real candidate receipt signed by `seed` at the second `sequenced_at`.
fn signed_record(
    sequence: u64,
    predecessor: [u8; 32],
    key_id: [u8; 32],
    (seed, sequenced_at): ([u8; 32], u64),
) -> TestResult<Record> {
    let tbs = ArcCandidateReceiptTbs {
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
        sequenced_at,
        sequencer_key_id: key_id,
    };
    let semantic_id = semantic_id_of(SemanticHashDomain::CandidateId, &tbs)?;
    let signature = sign_canonical(
        &Ed25519SecretKey::from_bytes(seed),
        SignatureDomain::CandidateReceipt,
        &tbs.encode()?,
    )?;
    let receipt = ArcCandidateReceipt {
        tbs,
        sequencer_signature: *signature.as_bytes(),
    };
    let bytes = ArcWireObject::new(
        ArcWireObjectKind::SequencerRecord,
        ArcSequencerRecord::Candidate(receipt).encode()?,
    )?
    .encode()?;
    Ok(Record {
        object_id: *agenc_relay_e2ee::ObjectId::compute(&bytes).as_bytes(),
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
    let body = ArcFederationWitnessResolution {
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
    Ok(ArcWireObject::new(ArcWireObjectKind::WitnessResolution, body.encode()?)?.encode()?)
}

fn begin_frames(conversation: [u8; 32], object: &[u8]) -> TestResult<Vec<CompanionFrame>> {
    let object_id = *agenc_relay_e2ee::ObjectId::compute(object).as_bytes();
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
    let (fixture, queue, _) = Box::pin(requesting_line()).await?;
    Ok((fixture, queue))
}

/// [`requesting`] with the exact `EWITNESS REQUEST` line the edge sent.
async fn requesting_line() -> TestResult<(WitnessFixture, LinkQueue, String)> {
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
    let request = next_line(&mut queue).await?;
    assert!(request.contains(" EWITNESS REQUEST "));
    assert_eq!(fixture.companion.phase, Phase::Witness);
    Ok((fixture, queue, request))
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
async fn a_resolution_assembles_whatever_the_client_cache_holds() -> TestResult {
    let (mut fixture, _queue) = Box::pin(requesting()).await?;
    crate::e2ee::edge::tests::fill_client_cache(&mut fixture.companion)?;
    // The resolution and its records are keyed by their token, and hold no
    // recent-object slot.
    let records = continuation()?;
    let head = records.last().ok_or("records")?.semantic_id;
    let object = resolution_object(CONVERSATION, &records, (EXPECTED + 1, head))?;
    feed(&mut fixture, delivery(&records, &object)?)?;
    fixture.core.commit_staged_batch().await?;
    assert!(
        fixture
            .companion
            .batch_applied(fixture.core.context_mut()?, &mut fixture.base)
            .is_empty()
    );
    assert!(!fixture.companion.witness_recovery_pending());
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
    Box::pin(assert_refused_under(None, frames)).await
}

/// The same refusal on a link that negotiated `key_set` instead of the
/// single-credential set.
async fn assert_refused_under(
    key_set: Option<agenc_relay_e2ee::sequencer::SequencerKeySet>,
    frames: Vec<CompanionFrame>,
) -> TestResult {
    let (mut fixture, _queue) = Box::pin(requesting()).await?;
    if key_set.is_some() {
        fixture.companion.config.sequencer_key_set = key_set;
    }
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

/// The successor credential of the rotating key set.
fn successor_id() -> TestResult<[u8; 32]> {
    let set = super::rotating_key_set().ok_or("the rotating key set verifies")?;
    match set.credentials.as_slice() {
        [_, successor] => Ok(successor.credential_id),
        _ => Err("the rotating set holds the active key and its successor".into()),
    }
}

/// One successor-signed record at the expected position and its delivery.
fn successor_delivery(sequenced_at: u64) -> TestResult<Vec<CompanionFrame>> {
    let signed = signed_record(
        EXPECTED,
        HEAD,
        successor_id()?,
        (super::SUCCESSOR_SEED, sequenced_at),
    )?;
    let object = resolution_object(
        CONVERSATION,
        std::slice::from_ref(&signed),
        (EXPECTED, signed.semantic_id),
    )?;
    delivery(std::slice::from_ref(&signed), &object)
}

/// Whether a successor-signed record sequenced at `sequenced_at` stages its
/// installation on a link that negotiated the rotating key set.
async fn successor_stages(sequenced_at: u64) -> TestResult<bool> {
    let (mut fixture, _queue) = Box::pin(requesting()).await?;
    fixture.companion.config.sequencer_key_set = super::rotating_key_set();
    feed(&mut fixture, successor_delivery(sequenced_at)?)?;
    Ok(fixture.core.context_mut()?.pending_len() != 0)
}

/// ENC-17 (#162): the overlapping successor signs only inside its window,
/// from its `not_before` through `MAX_SEQUENCER_KEY_OVERLAP` (12.5.1).
#[tokio::test]
async fn a_successor_record_inside_or_at_the_edges_of_its_window_resolves() -> TestResult {
    let closes =
        super::SUCCESSOR_OPENS + agenc_relay_e2ee::limits::MAX_SEQUENCER_KEY_OVERLAP_SECONDS;
    for sequenced_at in [super::SUCCESSOR_OPENS, super::SUCCESSOR_OPENS + 1, closes] {
        assert!(
            Box::pin(successor_stages(sequenced_at)).await?,
            "a successor record sequenced at {sequenced_at} is inside the window"
        );
    }
    // The active credential of the same set has no window.
    let (mut fixture, _queue) = Box::pin(requesting()).await?;
    fixture.companion.config.sequencer_key_set = super::rotating_key_set();
    let active = signed_record(
        EXPECTED,
        HEAD,
        credential_id()?,
        (super::SEQUENCER_SEED, closes + 1),
    )?;
    let object = resolution_object(
        CONVERSATION,
        std::slice::from_ref(&active),
        (EXPECTED, active.semantic_id),
    )?;
    feed(
        &mut fixture,
        delivery(std::slice::from_ref(&active), &object)?,
    )?;
    assert_ne!(fixture.core.context_mut()?.pending_len(), 0);
    Ok(())
}

/// A successor record before its window opens, or past its close, is a
/// record under any other key: the link closes and the row is retained.
#[tokio::test]
async fn a_successor_record_outside_its_window_is_refused() -> TestResult {
    let closes =
        super::SUCCESSOR_OPENS + agenc_relay_e2ee::limits::MAX_SEQUENCER_KEY_OVERLAP_SECONDS;
    for sequenced_at in [super::SUCCESSOR_OPENS - 1, closes + 1, u64::MAX] {
        Box::pin(assert_refused_under(
            super::rotating_key_set(),
            successor_delivery(sequenced_at)?,
        ))
        .await?;
    }
    // A link that never negotiated the successor refuses it at any time.
    Box::pin(assert_refused(successor_delivery(
        super::SUCCESSOR_OPENS + 1,
    )?))
    .await
}

/// ENC-15 (#160): the installer rewrites a head only on a route the base
/// profile still entitles this edge to; an authentic continuation for a
/// channel the base projection no longer hosts closes the link and retains
/// the row.
#[tokio::test]
async fn a_head_is_not_installed_on_a_channel_route_the_base_no_longer_hosts() -> TestResult {
    let records = continuation()?;
    let head = records.last().ok_or("records")?.semantic_id;
    let object = resolution_object(CONVERSATION, &records, (EXPECTED + 1, head))?;
    let (mut fixture, _queue) = Box::pin(requesting()).await?;
    crate::federation::edge::host_nothing(&mut fixture.base)?;
    feed(&mut fixture, delivery(&records, &object)?)?;
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
    Ok(())
}

type ResolutionEdit = fn(&mut ArcFederationWitnessResolution);

/// A resolution object over `records` whose body was edited after it was
/// anchored to the retained row.
fn edited_resolution(records: &[Record], edit: ResolutionEdit) -> TestResult<Vec<u8>> {
    let head = records.last().ok_or("records")?.semantic_id;
    let ids: Vec<u8> = records.iter().flat_map(|record| record.object_id).collect();
    let mut body = ArcFederationWitnessResolution {
        profile_version: 1,
        network_id: [1; 32],
        coordinator_server_id: COORDINATOR,
        target_server_id: EDGE,
        conversation_id: CONVERSATION,
        resolution_token: TOKEN,
        expected_sequence: EXPECTED,
        expected_head_id: HEAD,
        record_count: u32::try_from(records.len())?,
        new_head_sequence: EXPECTED + 1,
        new_head_id: head,
        record_object_ids: Opaque::new(ids)?,
    };
    edit(&mut body);
    Ok(ArcWireObject::new(ArcWireObjectKind::WitnessResolution, body.encode()?)?.encode()?)
}

fn begin_frames_to(
    target: [u8; 16],
    token: [u8; 16],
    object: &[u8],
) -> TestResult<Vec<CompanionFrame>> {
    let object_id = *agenc_relay_e2ee::ObjectId::compute(object).as_bytes();
    Ok(fragment_object(object)?
        .into_iter()
        .map(|fragment| CompanionFrame::WitnessBegin {
            target_server_id: target,
            conversation_id: CONVERSATION,
            resolution_token: token,
            object_id,
            fragment,
        })
        .collect())
}

#[tokio::test]
async fn a_resolution_body_that_is_not_addressed_to_this_edge_is_refused() -> TestResult {
    let records = continuation()?;
    let edits: [(&str, ResolutionEdit); 7] = [
        ("profile", |body| body.profile_version = 2),
        ("network", |body| body.network_id = [9; 32]),
        ("coordinator", |body| body.coordinator_server_id = [9; 16]),
        ("target", |body| body.target_server_id = [9; 16]),
        ("token", |body| body.resolution_token = [9; 16]),
        ("count", |body| body.record_count = 3),
        ("count over the ceiling", |body| {
            body.record_count = u32::MAX
        }),
    ];
    for (name, edit) in edits {
        let object = edited_resolution(&records, edit)?;
        Box::pin(assert_refused(begin_frames(CONVERSATION, &object)?))
            .await
            .map_err(|error| format!("{name}: {error}"))?;
    }
    Ok(())
}

#[tokio::test]
async fn a_begin_for_another_edge_or_beside_an_open_resolution_is_refused() -> TestResult {
    let records = continuation()?;
    let head = records.last().ok_or("records")?.semantic_id;
    let object = resolution_object(CONVERSATION, &records, (EXPECTED + 1, head))?;
    Box::pin(assert_refused(begin_frames_to([9; 16], TOKEN, &object)?)).await?;

    let (mut fixture, _queue) = Box::pin(requesting()).await?;
    feed(&mut fixture, begin_frames(CONVERSATION, &object)?)?;
    assert!(fixture.companion.witness_resolution.is_some());
    assert_eq!(fixture.companion.phase, Phase::Witness);
    // A second resolution under the same token is ignored while one is open.
    let other = resolution_object(CONVERSATION, &records, (EXPECTED + 1, [7; 32]))?;
    feed(&mut fixture, begin_frames(CONVERSATION, &other)?)?;
    assert_eq!(fixture.companion.phase, Phase::Witness);
    // A resolution under another token beside the open one is refused.
    feed(&mut fixture, begin_frames_to(EDGE, [8; 16], &object)?)?;
    assert_eq!(fixture.companion.phase, Phase::Down);
    Ok(())
}

#[tokio::test]
async fn an_entry_for_another_edge_or_outside_the_declared_set_is_refused() -> TestResult {
    let records = continuation()?;
    let head = records.last().ok_or("records")?.semantic_id;
    let object = resolution_object(CONVERSATION, &records, (EXPECTED + 1, head))?;
    let first = records.first().ok_or("records")?;
    let mut frames = begin_frames(CONVERSATION, &object)?;
    frames.extend(fragment_object(&first.bytes)?.into_iter().map(|fragment| {
        CompanionFrame::WitnessEntry {
            target_server_id: [9; 16],
            resolution_token: TOKEN,
            entry_sequence: 0,
            object_id: first.object_id,
            fragment,
        }
    }));
    Box::pin(assert_refused(frames)).await?;
    let mut frames = begin_frames(CONVERSATION, &object)?;
    frames.extend(entry_frames(5, first)?);
    Box::pin(assert_refused(frames)).await
}
