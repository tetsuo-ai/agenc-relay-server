#![forbid(unsafe_code)]

//! A validation row that decodes but does not describe the retained ordinary event it stands
//! for retires the link: another record kind, an acknowledged or barrier event, a row keyed to
//! another edge, a row past the cursor, or a page wider than the validation window.

use super::*;
use crate::bridge::StorageReadCompletionMessage;
use agenc_ircd_federation_wire::CrossProfilePart;
use agenc_ircd_storage::StoredKey;

const OTHER_PEER: ServerId = ServerId::from_bytes([52; 16]);

struct Row {
    sequence: u64,
    event_id: EventId,
    kind: u16,
    acknowledged: bool,
    cross_profile: Option<CrossProfilePart>,
    key_peer: ServerId,
}

impl Row {
    fn ordinary(sequence: u64, event_id: EventId) -> Self {
        Self {
            sequence,
            event_id,
            kind: OUTBOX_EVENT_KIND,
            acknowledged: false,
            cross_profile: None,
            key_peer: PEER,
        }
    }

    fn plaintext(&self) -> TestResult<(StoredKey, Vec<u8>)> {
        let event = ProjectedEvent::NetworkNotice {
            code: "REPLAY".to_owned(),
            text: "committed while disconnected".to_owned(),
        };
        let header = EventHeader {
            network_id: NETWORK,
            target_server_id: PEER,
            projection_generation: 0,
            coordinator_state_generation: 1,
            delivery_sequence: self.sequence,
            event_id: self.event_id,
            event_kind: event.kind(),
            correlation: None,
            cross_profile: self.cross_profile,
        };
        let arm = crate::federation::codec::events::event_arm_object(&event)
            .map_err(|error| format!("{error:?}"))?;
        let bytes = header.build(&arm)?.encode_canonical()?.as_slice().to_vec();
        let body = if self.kind == OUTBOX_EVENT_KIND {
            OutboxEventRecord {
                event_id: *self.event_id.as_bytes(),
                event_object_id: *federation_object_id(&bytes).as_bytes(),
                event_object: bytes,
                coordinator_state_generation: 1,
                acknowledged: self.acknowledged,
                completion_replay_key: None,
            }
            .encode()?
        } else {
            agenc_ircd_storage::ProtocolRecordBody::new(TableId::EdgeOutbox, self.kind, 1, bytes)?
                .encode()?
        };
        let value = PersistentRecordValue::new(
            TableId::EdgeOutbox,
            self.kind,
            1,
            0,
            None,
            Vec::new(),
            body,
        )?
        .encode()?;
        Ok((outbox_key(self.key_peer, 0, self.sequence)?, value))
    }
}

fn sealed(fixture: &StateCoreFixture, row: &Row) -> TestResult<agenc_ircd_storage::ReadRecord> {
    let (key, plaintext) = row.plaintext()?;
    let sealed_record = fixture.seal_row_for_test(TableId::EdgeOutbox, &key, &plaintext)?;
    Ok(agenc_ircd_storage::ReadRecord {
        table: TableId::EdgeOutbox,
        key,
        sealed_record,
    })
}

fn page(
    message: &mut StorageReadCompletionMessage,
) -> TestResult<&mut agenc_ircd_storage::ReadResult> {
    message
        .result
        .as_mut()
        .map_err(|error| format!("validation read: {error:?}").into())
}

type Fault = fn(&StateCoreFixture, &mut StorageReadCompletionMessage) -> TestResult;

fn replace_second(
    fixture: &StateCoreFixture,
    message: &mut StorageReadCompletionMessage,
    row: &Row,
) -> TestResult {
    let record = sealed(fixture, row)?;
    let second = page(message)?.records.get_mut(1).ok_or("second row")?;
    *second = record;
    Ok(())
}

fn faults() -> [(&'static str, Fault); 6] {
    [
        ("another record kind", |fixture, message| {
            let mut row = Row::ordinary(1, SECOND);
            row.kind = 2;
            replace_second(fixture, message, &row)
        }),
        ("an acknowledged event", |fixture, message| {
            let mut row = Row::ordinary(1, SECOND);
            row.acknowledged = true;
            replace_second(fixture, message, &row)
        }),
        ("a barrier part", |fixture, message| {
            let mut row = Row::ordinary(1, SECOND);
            row.cross_profile = Some(CrossProfilePart {
                mutation_id: [9; 16],
                part_index: 0,
                part_count: 2,
            });
            replace_second(fixture, message, &row)
        }),
        ("a row keyed to another edge", |fixture, message| {
            let mut row = Row::ordinary(1, SECOND);
            row.key_peer = OTHER_PEER;
            replace_second(fixture, message, &row)
        }),
        ("a row past the cursor", |fixture, message| {
            let record = sealed(fixture, &Row::ordinary(2, SUCCESSOR))?;
            page(message)?.records.push(record);
            Ok(())
        }),
        ("a page wider than the window", |fixture, message| {
            let records = &mut page(message)?.records;
            while records.len() <= 64 {
                records.push(sealed(fixture, &Row::ordinary(0, FIRST))?);
            }
            Ok(())
        }),
    ]
}

#[tokio::test]
async fn a_validation_row_that_is_not_the_retained_event_retires_the_link() -> TestResult {
    for (name, fault) in faults() {
        let (mut fixture, mut coordinator) = rejected_ack_fixture().await?;
        let (handle, _queue) = reconnect_with_cursor(&mut fixture, &mut coordinator, 1, SECOND)?;
        let mut completion = fixture.next_storage_read().await?;
        fault(&fixture, &mut completion)?;
        coordinator.storage_read_completed(fixture.context_mut()?, completion);
        let state = coordinator.peers.get(&PEER).ok_or("peer")?;
        assert!(state.live.is_none(), "{name}");
        assert!(state.reconciliation.is_none(), "{name}");
        assert_eq!(handle.queued_bytes(), 0, "{name}");
        assert_eq!(fixture.context_mut()?.pending_len(), 0, "{name}");
        assert_unreconciled(&mut fixture, &coordinator)?;
    }
    Ok(())
}

#[tokio::test]
async fn an_honest_resealed_row_still_validates() -> TestResult {
    let (mut fixture, mut coordinator) = rejected_ack_fixture().await?;
    let (_handle, _queue) = reconnect_with_cursor(&mut fixture, &mut coordinator, 1, SECOND)?;
    let mut completion = fixture.next_storage_read().await?;
    replace_second(&fixture, &mut completion, &Row::ordinary(1, SECOND))?;
    coordinator.storage_read_completed(fixture.context_mut()?, completion);
    let state = coordinator.peers.get(&PEER).ok_or("peer")?;
    assert!(state.live.is_some());
    assert!(state.reconciliation.is_some(), "the chunk is now staged");
    assert_eq!(fixture.context_mut()?.pending_len(), 1);
    Ok(())
}
