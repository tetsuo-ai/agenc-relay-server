#![forbid(unsafe_code)]

//! Barrier retention waits for a quiet edge, cleans a fenced stage up with its parts and head,
//! and deletes a payload only once no other retained receipt roots it.

use agenc_relay_storage::e2ee_records::barrier::BarrierReceipt;

use super::*;

const OTHER: [u8; 16] = [78; 16];

fn identity_of(mutation: [u8; 16]) -> BarrierIdentity {
    let mut identity = identity(2);
    identity.mutation_id = mutation;
    identity
}

/// Two parts of one applied barrier; the companion part carries `payload`.
fn receipt_parts(
    mutation: [u8; 16],
    payload: &[u8],
) -> TestResult<(Vec<BarrierPart>, BarrierReceipt)> {
    let mut assembly = BarrierAssembly::open(identity_of(mutation))?;
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
                *agenc_relay_e2ee::ObjectId::compute(&bytes).as_bytes()
            }
        };
        let carries_payload = stream == CrossProfileStream::Companion;
        let part = BarrierPart {
            identity: identity_of(mutation),
            stream,
            part_index: index,
            delivery_generation: 1,
            delivery_sequence: u64::from(index.saturating_sub(1)),
            event_id: [u8::try_from(index % 255)?; 16],
            event_object_id: object,
            encoded_event_object: bytes,
            payload_object_id: carries_payload
                .then(|| *agenc_relay_e2ee::ObjectId::compute(payload).as_bytes()),
            payload_object_bytes: if carries_payload {
                u32::try_from(payload.len())?
            } else {
                0
            },
        };
        assembly.stage(part.clone())?;
        parts.push(part);
    }
    Ok((parts, assembly.receipt(1, 1, 0, 604_800)))
}

/// Two expired receipts sharing one payload object, under one covering cursor.
fn shared_payload_image(payload: &[u8]) -> TestResult<(EdgeFederation, Vec<InitialStorageRecord>)> {
    let (mut base, _) = edges();
    let mut rows = Vec::new();
    let mut cursors = None;
    for mutation in [MUTATION, OTHER] {
        let (parts, receipt) = receipt_parts(mutation, payload)?;
        for part in &parts {
            rows.push(record(
                TableId::E2eeState,
                BARRIER_ROW_KIND,
                part.identity.part_key(part.part_index)?,
                part.encode()?,
            )?);
        }
        rows.push(record(
            TableId::E2eeState,
            BARRIER_ROW_KIND,
            receipt.identity.head_key()?,
            receipt.encode()?,
        )?);
        cursors = crate::federation::edge::barrier::last_entries(&receipt);
        base.barrier.applied.insert(mutation, receipt);
    }
    let ((sequence, event), (generation, companion_sequence, companion_event)) =
        cursors.ok_or("receipt streams")?;
    base.cursor = Some((sequence, EventId::from_bytes(event)));
    base.note_companion_delivery(generation, Some((companion_sequence, companion_event)));
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
    let object = ObjectRow::new(payload.to_vec())?;
    rows.push(record(
        TableId::E2eeObject,
        OBJECT_RECORD_KIND,
        object.key()?,
        object.encode()?,
    )?);
    Ok((base, rows))
}

fn deleted_keys(writes: &[AccountServiceDurableWrite]) -> Vec<(TableId, StoredKey)> {
    writes
        .iter()
        .filter_map(|write| match write {
            AccountServiceDurableWrite::Delete { table, key, .. } => Some((*table, key.clone())),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn retention_waits_while_the_companion_holds_a_pending_batch() -> TestResult {
    let (mut base, rows) = retained_image(2)?;
    let mut fixture =
        StateCoreFixture::with_registration_router_and_records(entropy_script(), rows)?;
    fixture.context_mut()?.set_wall_for_test(604_800);
    base.retain_barriers(fixture.context_mut()?, true);
    assert_eq!(fixture.context_mut()?.pending_len(), 0);
    assert!(base.barrier_applied(&MUTATION));
    Ok(())
}

#[tokio::test]
async fn a_fenced_stage_nobody_needs_is_cleaned_up_with_its_parts_and_head() -> TestResult {
    let mut rows = crash_rows(1, false)?;
    let (mut fenced_base, _) = edges();
    fenced_base.installed_incarnation = Some(ServerIncarnation::from_bytes([98; 16]));
    let AccountServiceDurableWrite::Put {
        table,
        key,
        plaintext,
    } = fenced_base
        .peer_row(None, 1)
        .map_err(|e| format!("{e:?}"))?
    else {
        return Err("peer row".into());
    };
    *rows.get_mut(0).ok_or("peer row")? =
        InitialStorageRecord::new(table, key, 1, plaintext.to_vec())?;
    let mut fixture =
        StateCoreFixture::with_registration_router_and_records(entropy_script(), rows)?;
    let (mut base, mut companion) = edges();
    fixture.restore_edge_state(&mut base, Some(&mut companion))?;
    assert_eq!(base.barrier.fenced.len(), 1);
    fixture.context_mut()?.set_wall_for_test(604_800);
    base.retain_barriers(fixture.context_mut()?, false);
    let writes = fixture.context_mut()?.staged_rows_for_test()?;
    let deleted = deleted_keys(&writes);
    assert!(deleted.contains(&(TableId::E2eeState, identity(2).part_key(0)?)));
    assert!(
        deleted.last() == Some(&(TableId::E2eeState, identity(2).head_key()?)),
        "the head goes last"
    );
    assert!(matches!(
        base.commit,
        Some(PendingCommit::BarrierCleanup {
            mutation_id: MUTATION,
            finished: true
        })
    ));
    let (mut restarted, mut restarted_companion) = edges();
    restarted.installed_incarnation = Some(ServerIncarnation::from_bytes([98; 16]));
    fixture.commit_and_restore_edge(writes, &mut restarted, Some(&mut restarted_companion))?;
    assert!(restarted.barrier.fenced.is_empty());
    assert!(restarted.barrier.open.is_none());
    Ok(())
}

#[tokio::test]
async fn a_payload_rooted_by_another_retained_receipt_survives_until_its_last_cleanup() -> TestResult
{
    let payload = ArcWireObject::new(ArcWireObjectKind::ApplicationMls, vec![14; 32])?.encode()?;
    let payload_key = ObjectRow::new(payload.clone())?.key()?;
    let (mut base, rows) = shared_payload_image(&payload)?;
    let mut fixture =
        StateCoreFixture::with_registration_router_and_records(entropy_script(), rows)?;
    fixture.context_mut()?.set_wall_for_test(604_800);
    base.retain_barriers(fixture.context_mut()?, false);
    let writes = fixture.context_mut()?.staged_rows_for_test()?;
    let deleted = deleted_keys(&writes);
    assert!(
        !deleted.contains(&(TableId::E2eeObject, payload_key.clone())),
        "the other receipt still roots the payload"
    );
    assert!(deleted.contains(&(TableId::E2eeState, identity_of(MUTATION).head_key()?)));
    commit_edge_batches(&mut base, &mut fixture).await?;
    assert!(!base.barrier_applied(&MUTATION));
    assert!(base.barrier_applied(&OTHER));
    assert!(fixture.stored_row_exists(TableId::E2eeObject, payload_key.clone())?);

    base.retain_barriers(fixture.context_mut()?, false);
    let writes = fixture.context_mut()?.staged_rows_for_test()?;
    let deleted = deleted_keys(&writes);
    assert!(
        deleted.contains(&(TableId::E2eeObject, payload_key.clone())),
        "the last receipt releases the payload"
    );
    assert!(deleted.contains(&(TableId::E2eeState, identity_of(OTHER).head_key()?)));
    commit_edge_batches(&mut base, &mut fixture).await?;
    assert!(!base.barrier_applied(&OTHER));
    assert!(!fixture.stored_row_exists(TableId::E2eeObject, payload_key)?);
    Ok(())
}
