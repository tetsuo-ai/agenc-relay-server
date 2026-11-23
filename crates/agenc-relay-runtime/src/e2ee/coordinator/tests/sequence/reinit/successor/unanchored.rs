//! A store holding a ReInit successor's rows without the activation record
//! that installs them (companion 13.8), beside its live predecessor. The
//! successor's route outranks the predecessor's by its binding generation,
//! so startup discards it as unanchored and gives every index it held back
//! to the predecessor by the restore's rank rule; the store still does not
//! start, since the successor's recovery gate row then names no restored
//! route (architecture 18.4), so neither route is served from it.

#![forbid(unsafe_code)]

use super::*;
use crate::state_core::durable::AccountServiceDurableWrite as Write;
use agenc_relay_storage::TableId;

#[test]
fn a_store_holding_an_unanchored_successor_does_not_start() -> TestResult {
    let mut fixture = Fixture::prepare()?;
    let staged = fixture.harness.writes.len();
    // The store as the attempt left it starts, the predecessor current.
    let before = fixture.harness.reloaded()?;
    assert!(
        before
            .coordinator
            .state
            .routes
            .is_current(&ConversationId(fixture.old))
    );
    fixture.activate()?;
    let (old, new) = (fixture.old, fixture.new);
    // Every row the activation wrote but the predecessor's record of the
    // activation itself: the successor's route, binding, policy and gate
    // rows stand with no activation that anchors them.
    let activation = fixture.harness.writes.split_off(staged);
    let mut dropped = 0_usize;
    for write in activation {
        let anchors = matches!(
            &write,
            Write::Put {
                table: TableId::E2eeState,
                key,
                ..
            } if SequencerRow::parse_record_key(key)
                .is_ok_and(|(conversation, _)| conversation == old)
        );
        if anchors {
            dropped += 1;
        } else {
            fixture.harness.writes.push(write);
        }
    }
    assert_eq!(dropped, 1, "the activation record");
    let successor_route = RouteRow::key(&new)?;
    assert!(fixture.harness.writes.iter().any(|write| matches!(
        write,
        Write::Put {
            table: TableId::E2eeState,
            key,
            ..
        } if *key == successor_route
    )));
    let refused = fixture
        .harness
        .reloaded()
        .err()
        .ok_or("the store started")?;
    assert_eq!(
        refused.to_string(),
        crate::e2ee::coordinator::CompanionFault::Storage.to_string()
    );
    Ok(())
}
