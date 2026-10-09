//! A listing page that keeps a cut arms the cut's expiry before its batch
//! is staged, publishes the cut at its receipt, and the owner's expiry wake
//! releases it (companion 11.7, 16), through real storage.
#![forbid(unsafe_code)]

use super::*;
use agenc_relay_domain::federation::{OriginBinding, OriginEntry, OriginPrincipal, OriginStatus};
use agenc_relay_types::{ConnectionId, OriginId, SessionId, UserId};

/// Gives the fixture origin a base session, as a declared account origin
/// has, so its requests take query snapshots under that session.
fn with_session(f: &mut Fixture) {
    f.coordinator.origins.restore_origin(
        OriginKey {
            home_server_id: PEER,
            server_incarnation: INCARNATION,
            origin_id: OriginId::from_bytes(f.origin_id),
        },
        OriginEntry {
            generation: 0,
            next_sequence: 0,
            object_id: [0; 32],
            binding: OriginBinding {
                connection_id: ConnectionId::from_bytes([0x71; 16]),
                connection_nonce: [0x72; 32],
            },
            principal: OriginPrincipal {
                session: Some((
                    SessionId::from_bytes([0x73; 16]),
                    UserId::from_bytes([0x74; 16]),
                )),
                account: None,
            },
            status: OriginStatus::Live,
            deleted_after: None,
        },
    );
}

/// Retains 40 small receipts of the fixture conversation from its first
/// record on.
fn seed_receipts(f: &mut Fixture, conversation: [u8; 32]) -> TestResult {
    let executor = f.executor_mut()?;
    let state = &mut executor.state;
    let known = state
        .conversations
        .get_mut(&conversation)
        .ok_or("the bound conversation")?;
    let first = known
        .records
        .keys()
        .next_back()
        .map_or(0, |sequence| sequence + 1);
    let mut seeded = Vec::new();
    for sequence in first..first + 40 {
        let mut body = vec![0x5a; 894];
        body.get_mut(..8)
            .ok_or("a record body")?
            .copy_from_slice(&sequence.to_be_bytes());
        let bytes = ArcWireObject::new(ArcWireObjectKind::SequencerRecord, body)?.encode()?;
        let id = *ObjectId::compute(&bytes).as_bytes();
        known.records.insert(sequence, id);
        seeded.push((id, bytes));
    }
    for (id, bytes) in seeded {
        state.object_bytes += bytes.len();
        state.objects.insert(id, bytes);
    }
    Ok(())
}

impl Fixture {
    /// The next cursor of the one result the link carries now, and whether
    /// the result was an object page.
    async fn page_result(&mut self) -> TestResult<(bool, Option<[u8; 32]>)> {
        let mut found = None;
        while self.handle.queued_bytes() != 0 {
            let line = self.queue.recv().await.ok_or("line")?;
            if let ParsedLine::Companion(CompanionFrame::Result { fragment, .. }) = parse_line(
                line.as_str().strip_suffix("\r\n").ok_or("CRLF")?,
                COORDINATOR_NAME,
            )
            .map_err(|e| format!("line: {e:?}"))?
            {
                let mut budget = DecodeBudget::new(1 << 16, 4_096);
                let object = ArcWireObject::decode_kind(
                    &fragment.segment,
                    Some(ArcWireObjectKind::FederationResult),
                    &mut budget,
                )?;
                let result = ArcFederationResult::decode_exact(object.body(), &mut budget)?;
                let next = result.next_cursor.as_slice();
                found = Some((
                    result.result_kind == ArcFederationResultKind::ObjectPage,
                    (!next.is_empty()).then(|| next.try_into()).transpose()?,
                ));
            }
        }
        found.ok_or_else(|| "no result".into())
    }

    /// One request of the origin at `sequence`: `opcode` with `parameters`.
    fn request(
        &self,
        sequence: u64,
        opcode: ArcFederationOpcode,
        parameters: Vec<u8>,
    ) -> TestResult<CompleteRequest> {
        let mut complete = self.whoami(sequence)?;
        let mut budget = DecodeBudget::new(1 << 16, 4_096);
        let object = ArcWireObject::decode_kind(
            &complete.request,
            Some(ArcWireObjectKind::FederationRequest),
            &mut budget,
        )?;
        let mut request = ArcFederationRequest::decode_exact(object.body(), &mut budget)?;
        request.opcode = opcode;
        request.encoded_parameters = Opaque::new(parameters)?;
        complete.request =
            ArcWireObject::new(ArcWireObjectKind::FederationRequest, request.encode()?)?
                .encode()?;
        Ok(complete)
    }
}

/// Dispatches every due timer as the state core does, at most 16, and
/// returns how many listing expiry wakes the owner handled; a wake that
/// keeps re-arming at the same due deadline is cut off.
fn fire_due(coordinator: &mut FederationCoordinator, context: &mut StateCoreContext) -> usize {
    let now = context.now();
    let mut fired = 0;
    for _ in 0..16 {
        let Some(entry) = context.timers_mut().pop_due(now) else {
            break;
        };
        if entry.kind == crate::state_core::timers::TimerKind::ListingSnapshotExpiry
            && coordinator.timer_fired(context, entry)
        {
            fired += 1;
        }
    }
    fired
}

/// The parameters of `EGROUP FETCH RECEIPTS` from zero with `cursor`.
fn receipts(conversation: [u8; 32], cursor: Option<[u8; 32]>) -> Vec<u8> {
    let mut parameters = conversation.to_vec();
    parameters.extend_from_slice(&0_u64.to_be_bytes());
    match cursor {
        Some(cursor) => {
            parameters.push(32);
            parameters.extend_from_slice(&cursor);
        }
        None => parameters.push(0),
    }
    parameters
}

#[tokio::test]
async fn a_cut_paged_to_its_end_through_the_owner_disarms_its_expiry() -> TestResult {
    let authority = fresh_fetch_fixture()?;
    let conversation = authority.conversation;
    let mut f = Box::pin(Fixture::new()).await?;
    with_session(&mut f);
    seed_receipts(&mut f, conversation)?;
    let mut cursor = None;
    let mut pages = 0;
    loop {
        let sequence = f.next_sequence()?;
        let request = f.request(
            sequence,
            ArcFederationOpcode::FetchReceipts,
            receipts(conversation, cursor),
        )?;
        f.submit(&request)?;
        f.commit_pending().await?;
        let (page, next) = f.page_result().await?;
        assert!(page);
        pages += 1;
        match next {
            Some(next) => {
                assert_eq!(f.executor()?.state.listing_snapshots.cursors(), 1);
                assert!(f.executor()?.state.listing_expiry_armed.is_some());
                cursor = Some(next);
            }
            None => break,
        }
    }
    assert_eq!(pages, 2);
    // The last page's receipt released the cut and cancelled its wake.
    assert_eq!(f.executor()?.state.listing_snapshots.cursors(), 0);
    assert_eq!(f.executor()?.state.listing_expiry_armed, None);
    assert!(
        !f.core.context_mut()?.timers_mut().cancel(
            crate::state_core::timers::TimerKind::ListingSnapshotExpiry,
            TimedId::Global
        ),
        "no cut remained yet its expiry stayed armed"
    );
    assert!(f.live());
    Ok(())
}

#[tokio::test]
async fn a_page_that_keeps_a_cut_arms_its_expiry_and_the_owner_releases_it() -> TestResult {
    let authority = fresh_fetch_fixture()?;
    let conversation = authority.conversation;
    let mut f = Box::pin(Fixture::new()).await?;
    with_session(&mut f);
    seed_receipts(&mut f, conversation)?;
    let sequence = f.next_sequence()?;
    let mut parameters = conversation.to_vec();
    parameters.extend_from_slice(&0_u64.to_be_bytes());
    parameters.push(0);
    let staged_at = crate::e2ee::link::tick_millis(f.core.context_mut()?.now());
    f.submit(&f.request(sequence, ArcFederationOpcode::FetchReceipts, parameters)?)?;
    // The expiry is armed before the batch commits, at the cut's lifetime
    // from the request's clock.
    let deadline = f
        .executor()?
        .state
        .listing_expiry_armed
        .ok_or("an armed expiry")?;
    assert!((staged_at + 600_000..=staged_at + 601_000).contains(&deadline));
    assert_eq!(f.executor()?.state.listing_snapshots.cursors(), 0);
    f.commit_pending().await?;
    assert_eq!(
        f.answers().await?,
        vec![(
            sequence,
            Answered::Other(ArcFederationResultKind::ObjectPage)
        )]
    );
    assert_eq!(f.executor()?.state.listing_snapshots.cursors(), 1);
    // The owner's wake at the deadline releases the cut and disarms.
    let context = f.core.context_mut()?;
    context.set_monotonic_for_test(deadline);
    let fired = fire_due(&mut f.coordinator, context);
    assert_eq!(
        fired, 1,
        "the listing expiry wake was due once at the deadline"
    );
    assert_eq!(f.executor()?.state.listing_snapshots.cursors(), 0);
    assert_eq!(f.executor()?.state.listing_expiry_armed, None);
    assert!(f.live());
    Ok(())
}

/// The expiry wake releases the cut it was armed for and is armed again for
/// the earliest cut left.
#[tokio::test]
async fn the_expiry_wake_rearms_for_the_next_cut() -> TestResult {
    let authority = fresh_fetch_fixture()?;
    let conversation = authority.conversation;
    let mut f = Box::pin(Fixture::new()).await?;
    with_session(&mut f);
    seed_receipts(&mut f, conversation)?;
    let mut deadlines = Vec::new();
    for first in [0_u64, 1] {
        let sequence = f.next_sequence()?;
        let mut parameters = conversation.to_vec();
        parameters.extend_from_slice(&first.to_be_bytes());
        parameters.push(0);
        f.submit(&f.request(sequence, ArcFederationOpcode::FetchReceipts, parameters)?)?;
        f.commit_pending().await?;
        assert!(f.page_result().await?.0);
        let now = f.core.context_mut()?.now();
        deadlines.push(crate::e2ee::link::tick_millis(now) + 600_000);
        f.core
            .context_mut()?
            .set_monotonic_for_test(now.get() + 1_000);
    }
    assert_eq!(f.executor()?.state.listing_snapshots.cursors(), 2);
    let first_deadline = f
        .executor()?
        .state
        .listing_expiry_armed
        .ok_or("an armed expiry")?;
    let context = f.core.context_mut()?;
    context.set_monotonic_for_test(first_deadline);
    assert_eq!(fire_due(&mut f.coordinator, context), 1);
    assert_eq!(f.executor()?.state.listing_snapshots.cursors(), 1);
    let rearmed = f
        .executor()?
        .state
        .listing_expiry_armed
        .ok_or("the wake armed again")?;
    assert!(rearmed > first_deadline);
    assert!(
        deadlines
            .last()
            .is_some_and(|last| (*last..*last + 1_000).contains(&rearmed))
    );
    Ok(())
}

/// A wake that cannot be armed again for the cuts left releases every one
/// of them, so no cut outlives its expiry owner.
#[tokio::test]
async fn a_wake_that_cannot_be_armed_again_releases_every_cut() -> TestResult {
    let authority = fresh_fetch_fixture()?;
    let conversation = authority.conversation;
    let mut f = Box::pin(Fixture::new()).await?;
    with_session(&mut f);
    seed_receipts(&mut f, conversation)?;
    for first in [0_u64, 1] {
        let sequence = f.next_sequence()?;
        let mut parameters = conversation.to_vec();
        parameters.extend_from_slice(&first.to_be_bytes());
        parameters.push(0);
        f.submit(&f.request(sequence, ArcFederationOpcode::FetchReceipts, parameters)?)?;
        f.commit_pending().await?;
        assert!(f.page_result().await?.0);
        let now = f.core.context_mut()?.now();
        f.core
            .context_mut()?
            .set_monotonic_for_test(now.get() + 1_000);
    }
    assert_eq!(f.executor()?.state.listing_snapshots.cursors(), 2);
    let deadline = f
        .executor()?
        .state
        .listing_expiry_armed
        .ok_or("an armed expiry")?;
    let context = f.core.context_mut()?;
    context.set_monotonic_for_test(deadline);
    let now = context.now();
    let entry = loop {
        let entry = context.timers_mut().pop_due(now).ok_or("a due wake")?;
        if entry.kind == crate::state_core::timers::TimerKind::ListingSnapshotExpiry {
            break entry;
        }
    };
    *context.timers_mut() = crate::state_core::timers::TimerHeap::with_ceiling(0);
    assert!(f.coordinator.timer_fired(context, entry));
    assert_eq!(f.executor()?.state.listing_snapshots.cursors(), 0);
    assert_eq!(f.executor()?.state.listing_expiry_armed, None);
    assert!(f.live());
    Ok(())
}

/// A page that keeps a cut is not staged without the cut's expiry wake:
/// the request is answered with its failed result, no cut is published,
/// and the link stays up.
#[tokio::test]
async fn a_cut_whose_expiry_cannot_be_armed_is_answered_with_its_failed_result() -> TestResult {
    let authority = fresh_fetch_fixture()?;
    let conversation = authority.conversation;
    let mut f = Box::pin(Fixture::new()).await?;
    with_session(&mut f);
    seed_receipts(&mut f, conversation)?;
    *f.core.context_mut()?.timers_mut() = crate::state_core::timers::TimerHeap::with_ceiling(0);
    let sequence = f.next_sequence()?;
    f.submit(&f.request(
        sequence,
        ArcFederationOpcode::FetchReceipts,
        receipts(conversation, None),
    )?)?;
    f.commit_pending().await?;
    assert_eq!(
        f.answers().await?,
        vec![(
            sequence,
            Answered::Failed(E2eeReplyCode::RateLimited.token().to_owned())
        )]
    );
    assert_eq!(f.executor()?.state.listing_snapshots.cursors(), 0);
    assert_eq!(f.executor()?.state.listing_expiry_armed, None);
    assert!(f.live());
    Ok(())
}
