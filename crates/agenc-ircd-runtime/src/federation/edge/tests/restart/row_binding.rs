#![forbid(unsafe_code)]

//! Every barrier row must sit under the key its identity derives, every head must have a peer
//! that still owns it, and a retained receipt must agree with the parts and cursors it covers.

use super::*;
use crate::federation::edge::startup::EdgeRestoreStep;
use agenc_ircd_storage::e2ee_records::barrier::BarrierReceipt;

type PartEdit = fn(&mut BarrierPart);
type ReceiptEdit = fn(&mut BarrierReceipt);

fn part_record(part: &BarrierPart, key: StoredKey) -> TestResult<InitialStorageRecord> {
    record(TableId::E2eeState, BARRIER_ROW_KIND, key, part.encode()?)
}

fn head_record(head: &BarrierHead, key: StoredKey) -> TestResult<InitialStorageRecord> {
    record(TableId::E2eeState, BARRIER_ROW_KIND, key, head.encode()?)
}

fn refused(
    rows: Vec<InitialStorageRecord>,
) -> TestResult<(Option<EdgeRestoreStep>, EdgeFederation)> {
    let fixture = StateCoreFixture::with_registration_router_and_records(entropy_script(), rows)?;
    let (mut base, mut companion) = edges();
    let refusal = fixture.restore_edge_refusal(&mut base, Some(&mut companion))?;
    Ok((refusal.err().map(|refusal| refusal.step), base))
}

/// The peer row of an edge whose installed coordinator identity was edited.
fn peer_row_of(edit: fn(&mut EdgeFederation)) -> TestResult<InitialStorageRecord> {
    let (mut base, _) = edges();
    edit(&mut base);
    let AccountServiceDurableWrite::Put {
        table,
        key,
        plaintext,
    } = base.peer_row(None, 1).map_err(|e| format!("{e:?}"))?
    else {
        return Err("peer row".into());
    };
    Ok(InitialStorageRecord::new(
        table,
        key,
        1,
        plaintext.to_vec(),
    )?)
}

#[tokio::test]
async fn a_part_row_under_another_parts_key_refuses_at_the_companion_state() -> TestResult {
    let mut rows = crash_rows(1, false)?;
    let (parts, _) = parts()?;
    let part = parts.into_iter().next().ok_or("base part")?;
    *rows.get_mut(2).ok_or("part row")? = part_record(&part, identity(2).part_key(1)?)?;
    assert_eq!(refused(rows)?.0, Some(EdgeRestoreStep::CompanionState));
    Ok(())
}

#[tokio::test]
async fn a_head_row_under_another_mutations_key_refuses_at_the_companion_state() -> TestResult {
    let mut rows = crash_rows(1, false)?;
    let mut other = identity(2);
    other.mutation_id = [78; 16];
    let head = BarrierHead::Stage(BarrierAssembly::open(identity(2))?.head().clone());
    *rows.get_mut(3).ok_or("head row")? = head_record(&head, other.head_key()?)?;
    assert_eq!(refused(rows)?.0, Some(EdgeRestoreStep::CompanionState));
    Ok(())
}

#[tokio::test]
async fn a_head_naming_another_coordinator_refuses_at_the_companion_state() -> TestResult {
    let mut rows = crash_rows(0, false)?;
    let mut other = identity(2);
    other.coordinator_server_id = [99; 16];
    let head = BarrierHead::Stage(BarrierAssembly::open(other.clone())?.head().clone());
    *rows.get_mut(2).ok_or("head row")? = head_record(&head, other.head_key()?)?;
    assert_eq!(refused(rows)?.0, Some(EdgeRestoreStep::CompanionState));
    Ok(())
}

#[tokio::test]
async fn a_part_without_its_head_refuses_at_the_barrier_install() -> TestResult {
    let mut rows = crash_rows(1, false)?;
    rows.truncate(3);
    let (step, base) = refused(rows)?;
    assert_eq!(step, Some(EdgeRestoreStep::BarrierInstall));
    assert!(base.barrier.open.is_none());
    Ok(())
}

#[tokio::test]
async fn a_second_open_stage_refuses_at_the_barrier_install() -> TestResult {
    let mut rows = crash_rows(1, false)?;
    let mut other = identity(2);
    other.mutation_id = [78; 16];
    let head = BarrierHead::Stage(BarrierAssembly::open(other.clone())?.head().clone());
    rows.push(head_record(&head, other.head_key()?)?);
    assert_eq!(refused(rows)?.0, Some(EdgeRestoreStep::BarrierInstall));
    Ok(())
}

#[tokio::test]
async fn a_stage_of_a_superseded_epoch_is_fenced_when_its_parts_agree() -> TestResult {
    let mut rows = crash_rows(1, false)?;
    *rows.get_mut(0).ok_or("peer row")? = peer_row_of(|base| {
        base.installed_epoch = Some(RecoveryEpoch::from_bytes([97; 16]));
    })?;
    let (step, base) = refused(rows)?;
    assert_eq!(step, None);
    assert!(base.barrier.open.is_none());
    assert_eq!(base.barrier.fenced.len(), 1);
    Ok(())
}

#[tokio::test]
async fn a_fenced_stage_whose_parts_disagree_refuses_at_the_barrier_install() -> TestResult {
    let edits: [PartEdit; 2] = [
        |part| part.identity.coordinator_state_generation = 11,
        |part| part.part_index = 1,
    ];
    for edit in edits {
        let mut rows = crash_rows(1, false)?;
        *rows.get_mut(0).ok_or("peer row")? = peer_row_of(|base| {
            base.installed_incarnation = Some(ServerIncarnation::from_bytes([98; 16]));
        })?;
        let (parts, _) = parts()?;
        let mut part = parts.into_iter().next().ok_or("base part")?;
        edit(&mut part);
        let key = part.identity.part_key(part.part_index)?;
        *rows.get_mut(2).ok_or("part row")? = part_record(&part, key)?;
        let (step, base) = refused(rows)?;
        assert_eq!(step, Some(EdgeRestoreStep::BarrierInstall));
        assert!(base.barrier.fenced.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn a_part_whose_identity_disagrees_with_its_event_refuses_at_the_barrier_install()
-> TestResult {
    let edits: [PartEdit; 3] = [
        |part| part.identity.network_id = [99; 32],
        |part| part.identity.target_server_id = [99; 16],
        |part| part.identity.part_count = 3,
    ];
    for edit in edits {
        let mut rows = crash_rows(1, false)?;
        let (parts, _) = parts()?;
        let mut part = parts.into_iter().next().ok_or("base part")?;
        edit(&mut part);
        // The row sits under the key its edited identity derives, so only
        // the event header can expose the disagreement.
        let key = part.identity.part_key(part.part_index)?;
        *rows.get_mut(2).ok_or("part row")? = part_record(&part, key)?;
        assert_eq!(refused(rows)?.0, Some(EdgeRestoreStep::BarrierInstall));
    }
    Ok(())
}

#[tokio::test]
async fn a_payload_row_holding_another_object_refuses_at_the_barrier_install() -> TestResult {
    let mut rows = crash_rows(2, true)?;
    let (_, payload) = parts()?;
    let expected = ObjectRow::new(payload)?.key()?;
    let other = ObjectRow::new(
        IrcWireObject::new(IrcWireObjectKind::ApplicationMls, vec![13; 32])?.encode()?,
    )?;
    rows.push(record(
        TableId::E2eeObject,
        OBJECT_RECORD_KIND,
        expected,
        other.encode()?,
    )?);
    assert_eq!(refused(rows)?.0, Some(EdgeRestoreStep::BarrierInstall));
    Ok(())
}

/// A retained two-part receipt whose parts, peer and cursor rows are edited
/// before they are sealed.
struct Retained {
    parts: Vec<BarrierPart>,
    receipt: BarrierReceipt,
    covered: bool,
}

impl Retained {
    fn new() -> TestResult<Self> {
        Self::applied_at(0)
    }

    fn applied_at(applied_at: u64) -> TestResult<Self> {
        let mut assembly = BarrierAssembly::open(identity(2))?;
        let mut parts = Vec::new();
        for index in 0..2_u16 {
            let stream = if index == 0 {
                CrossProfileStream::Base
            } else {
                CrossProfileStream::Companion
            };
            let bytes = index.to_be_bytes().to_vec();
            let object = match stream {
                CrossProfileStream::Base => *federation_object_id(&bytes).as_bytes(),
                CrossProfileStream::Companion => {
                    *agenc_ircd_e2ee::ObjectId::compute(&bytes).as_bytes()
                }
            };
            let part = BarrierPart {
                identity: identity(2),
                stream,
                part_index: index,
                delivery_generation: 1,
                delivery_sequence: u64::from(index.saturating_sub(1)),
                event_id: [u8::try_from(index % 255)?; 16],
                event_object_id: object,
                encoded_event_object: bytes,
                payload_object_id: None,
                payload_object_bytes: 0,
            };
            assembly.stage(part.clone())?;
            parts.push(part);
        }
        Ok(Self {
            parts,
            receipt: assembly.receipt(1, 1, applied_at, applied_at.saturating_add(604_800)),
            covered: true,
        })
    }

    fn rows(self) -> TestResult<Vec<InitialStorageRecord>> {
        let (mut base, _) = edges();
        let mut rows = Vec::new();
        for part in &self.parts {
            rows.push(part_record(part, part.identity.part_key(part.part_index)?)?);
        }
        let ((sequence, event), (generation, companion_sequence, companion_event)) =
            crate::federation::edge::barrier::last_entries(&self.receipt).ok_or("streams")?;
        if self.covered {
            base.cursor = Some((sequence, EventId::from_bytes(event)));
            base.note_companion_delivery(generation, Some((companion_sequence, companion_event)));
        }
        let AccountServiceDurableWrite::Put {
            table,
            key,
            plaintext,
        } = base
            .peer_row(base.cursor, 1)
            .map_err(|e| format!("{e:?}"))?
        else {
            return Err("peer".into());
        };
        rows.push(InitialStorageRecord::new(
            table,
            key,
            1,
            plaintext.to_vec(),
        )?);
        let cursor = DeliveryRow::WitnessedCursor {
            generation,
            next_sequence: companion_sequence + 1,
            acked_sequence: companion_sequence,
            acked_event_id: companion_event,
            barrier_open: false,
        };
        rows.push(record(
            TableId::E2eeState,
            DELIVERY_ROW_KIND,
            DeliveryRow::cursor_key(COORDINATOR.as_bytes())?,
            cursor.encode()?,
        )?);
        rows.push(head_record(
            &BarrierHead::Receipt(self.receipt.clone()),
            self.receipt.identity.head_key()?,
        )?);
        Ok(rows)
    }
}

#[tokio::test]
async fn a_retained_receipt_that_disagrees_with_the_head_or_its_parts_refuses() -> TestResult {
    let edits: [ReceiptEdit; 5] = [
        |receipt| receipt.applied_storage_commit_sequence = 0,
        |receipt| receipt.applied_local_state_generation = 0,
        |receipt| receipt.applied_storage_commit_sequence = u64::MAX / 2,
        |receipt| receipt.applied_local_state_generation = u64::MAX / 2,
        |receipt| receipt.aggregate_event_payload_bytes += 1,
    ];
    for edit in edits {
        let mut retained = Retained::new()?;
        edit(&mut retained.receipt);
        let (step, base) = refused(retained.rows()?)?;
        assert_eq!(step, Some(EdgeRestoreStep::BarrierInstall));
        assert!(base.barrier.applied.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn a_retained_receipt_whose_cursors_do_not_cover_it_refuses() -> TestResult {
    let mut retained = Retained::new()?;
    retained.covered = false;
    assert_eq!(
        refused(retained.rows()?)?.0,
        Some(EdgeRestoreStep::BarrierInstall)
    );
    Ok(())
}

#[tokio::test]
async fn a_retained_part_that_disagrees_with_its_receipt_refuses() -> TestResult {
    let edits: [PartEdit; 2] = [
        |part| part.delivery_generation = 2,
        |part| part.event_object_id = [1; 32],
    ];
    for edit in edits {
        let mut retained = Retained::new()?;
        edit(retained.parts.get_mut(0).ok_or("base part")?);
        assert_eq!(
            refused(retained.rows()?)?.0,
            Some(EdgeRestoreStep::BarrierInstall)
        );
    }
    Ok(())
}

#[tokio::test]
async fn an_unexpired_receipt_missing_a_part_refuses() -> TestResult {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let mut retained = Retained::applied_at(now)?;
    retained.parts.truncate(1);
    assert_eq!(
        refused(retained.rows()?)?.0,
        Some(EdgeRestoreStep::BarrierInstall)
    );
    Ok(())
}
