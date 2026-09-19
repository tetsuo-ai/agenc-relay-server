#![forbid(unsafe_code)]

//! An incoming event is refused unless the edge is receiving, its header agrees with its carrier
//! and the replica generation, it follows the cursor, and the hold queue has room.

use super::*;
use crate::federation::edge::events::QueuedEvent;

#[test]
fn an_event_is_refused_unless_the_edge_is_receiving() -> TestResult {
    for phase in [Phase::Down, Phase::Resuming, Phase::Snapshot] {
        let mut fixture = PrefixFixture::new()?;
        fixture.edge.phase = phase;
        let (descriptor, object) = ordinary_message(fixture.recipient, 0)?;
        let refused = events::receive(
            &mut fixture.edge,
            fixture.core.context_mut()?,
            descriptor,
            &object,
        );
        assert_eq!(refused.err(), Some(Violation::Phase), "{phase:?}");
    }
    Ok(())
}

#[test]
fn an_event_whose_header_disagrees_with_its_carrier_or_generation_is_refused() -> TestResult {
    type Edit = fn(&mut agenc_ircd_federation_wire::EventDescriptor);
    let edits: [(&str, Edit); 3] = [
        ("delivery sequence", |descriptor| {
            descriptor.delivery_sequence = 1
        }),
        ("event id", |descriptor| {
            descriptor.event_id = EventId::from_bytes([9; 16]);
        }),
        ("object id", |descriptor| {
            descriptor.object_id =
                agenc_ircd_federation_wire::FederationHash32::from_bytes([9; 32]);
        }),
    ];
    for (name, edit) in edits {
        let mut fixture = PrefixFixture::new()?;
        let (mut descriptor, object) = ordinary_message(fixture.recipient, 0)?;
        edit(&mut descriptor);
        let refused = events::receive(
            &mut fixture.edge,
            fixture.core.context_mut()?,
            descriptor,
            &object,
        );
        assert_eq!(refused.err(), Some(Violation::Consistency), "{name}");
    }
    let mut fixture = PrefixFixture::new()?;
    let (descriptor, object) = ordinary_message(fixture.recipient, 0)?;
    fixture.edge.replica.install(2, Vec::new())?;
    let refused = events::receive(
        &mut fixture.edge,
        fixture.core.context_mut()?,
        descriptor,
        &object,
    );
    assert_eq!(
        refused.err(),
        Some(Violation::Consistency),
        "another projection generation"
    );
    Ok(())
}

#[test]
fn an_event_that_skips_the_cursor_is_refused() -> TestResult {
    let mut fixture = PrefixFixture::new()?;
    let (descriptor, object) = ordinary_message(fixture.recipient, 1)?;
    let refused = events::receive(
        &mut fixture.edge,
        fixture.core.context_mut()?,
        descriptor,
        &object,
    );
    assert_eq!(refused.err(), Some(Violation::Consistency));
    Ok(())
}

#[test]
fn a_full_hold_queue_refuses_the_next_event() -> TestResult {
    let mut fixture = PrefixFixture::new()?;
    fixture.edge.commit = Some(PendingCommit::BarrierFence);
    let (_, object) = ordinary_message(fixture.recipient, 0)?;
    let mut budget = DecodeBudget::new(1 << 20, 4_096);
    let event = agenc_ircd_federation_wire::SchemaObject::decode_exact(
        "FederationEvent",
        object.as_slice(),
        &mut budget,
    )?;
    let header = EventHeader::from_object(&event)?;
    for sequence in 0..MAX_QUEUED_EVENTS {
        let mut held = header;
        held.delivery_sequence = u64::try_from(sequence)?;
        fixture.edge.queued_events.push_back(QueuedEvent::Base {
            header: held,
            projected: ProjectedEvent::NetworkNotice {
                code: "HOLD".to_owned(),
                text: "held behind the commit".to_owned(),
            },
            encoded_bytes: 64,
        });
    }
    // The next event follows the held ones exactly, so only the ceiling refuses it.
    let (descriptor, object) =
        ordinary_message(fixture.recipient, u64::try_from(MAX_QUEUED_EVENTS)?)?;
    let refused = events::receive(
        &mut fixture.edge,
        fixture.core.context_mut()?,
        descriptor,
        &object,
    );
    assert_eq!(refused.err(), Some(Violation::Ceiling));
    assert_eq!(fixture.edge.queued_events.len(), MAX_QUEUED_EVENTS);
    Ok(())
}
