#![forbid(unsafe_code)]

//! A companion part handed over by the E2EE router must name this edge and the companion
//! stream, carry the exact payload it declares, and belong to the one open barrier; a part
//! of an applied barrier replays from its receipt.

use super::*;

fn live_edge() -> (EdgeFederation, LinkQueue) {
    let (mut base, _) = edges();
    let (handle, queue) = link_queue(1 << 20);
    base.live = Some(LiveLink {
        link: LinkId::new(99),
        handle,
        coordinator_epoch: COORDINATOR_EPOCH,
        coordinator_incarnation: HUB_INCARNATION,
    });
    (base, queue)
}

type PartEdit = fn(&mut BarrierPart, &mut Vec<u8>);

#[tokio::test]
async fn a_companion_part_must_name_this_edge_its_stream_and_its_exact_payload() -> TestResult {
    let edits: [(&str, PartEdit); 4] = [
        ("network", |part, _| part.identity.network_id = [9; 32]),
        ("stream", |part, _| part.stream = CrossProfileStream::Base),
        ("payload bytes", |_, payload| payload.push(0)),
        ("declared size", |part, _| part.payload_object_bytes += 1),
    ];
    for (name, edit) in edits {
        let mut fixture = StateCoreFixture::new(entropy_script())?;
        let (mut base, _queue) = live_edge();
        let (mut parts, mut payload) = parts()?;
        let mut part = parts.pop().ok_or("part")?;
        edit(&mut part, &mut payload);
        assert!(
            !base.companion_barrier_part(fixture.context_mut()?, part, Some(payload)),
            "{name}"
        );
        assert!(base.barrier.open.is_none(), "{name}");
        assert!(base.live.is_none(), "{name}: the violation closed the link");
    }
    Ok(())
}

#[tokio::test]
async fn a_companion_part_of_another_mutation_beside_an_open_barrier_is_refused() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router_and_records(
        entropy_script(),
        crash_rows(1, false)?,
    )?;
    let (mut base, mut companion) = edges();
    fixture.restore_edge_state(&mut base, Some(&mut companion))?;
    assert!(base.barrier.open.is_some());
    let (handle, _queue) = link_queue(1 << 20);
    base.live = Some(LiveLink {
        link: LinkId::new(99),
        handle,
        coordinator_epoch: COORDINATOR_EPOCH,
        coordinator_incarnation: HUB_INCARNATION,
    });
    let (mut parts, payload) = parts()?;
    let mut part = parts.pop().ok_or("part")?;
    part.identity.mutation_id = [78; 16];
    assert!(!base.companion_barrier_part(fixture.context_mut()?, part, Some(payload)));
    assert!(base.barrier.open.is_some(), "the open barrier is untouched");
    Ok(())
}

#[tokio::test]
async fn a_companion_part_of_an_applied_barrier_replays_from_its_receipt() -> TestResult {
    let (mut base, rows) = retained_image(2)?;
    let mut fixture =
        StateCoreFixture::with_registration_router_and_records(entropy_script(), rows)?;
    let (handle, _queue) = link_queue(1 << 20);
    base.live = Some(LiveLink {
        link: LinkId::new(99),
        handle,
        coordinator_epoch: COORDINATOR_EPOCH,
        coordinator_incarnation: HUB_INCARNATION,
    });
    assert!(base.barrier_applied(&MUTATION));
    let bytes = 1_u16.to_be_bytes().to_vec();
    let replay = BarrierPart {
        identity: identity(2),
        stream: CrossProfileStream::Companion,
        part_index: 1,
        delivery_generation: 1,
        delivery_sequence: 0,
        event_id: [1; 16],
        event_object_id: *agenc_ircd_e2ee::ObjectId::compute(&bytes).as_bytes(),
        encoded_event_object: bytes,
        payload_object_id: None,
        payload_object_bytes: 0,
    };
    assert!(base.companion_barrier_part(fixture.context_mut()?, replay.clone(), None));
    assert!(base.live.is_some());
    assert_eq!(
        base.barrier
            .replayed
            .get(&MUTATION)
            .map(std::collections::BTreeSet::len),
        Some(1),
        "the replay waits for the base part"
    );
    let mut foreign = replay;
    foreign.event_id = [9; 16];
    assert!(
        !base.companion_barrier_part(fixture.context_mut()?, foreign, None),
        "a replayed part must repeat its receipt entry"
    );
    Ok(())
}
