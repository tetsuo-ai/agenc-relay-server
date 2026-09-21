//! Closed codec, exact key binding, and cross-record ownership regressions.
#![forbid(unsafe_code)]

use super::*;
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::conversation::ArcConversationKind;
use agenc_relay_e2ee::objects::federation::{ArcFederationRouteState, ArcRouteStateKind};
use agenc_relay_e2ee::tls::{Opaque, TlsEncode};

type TestResult = Result<(), StorageError>;

fn scope() -> Result<DeliveryScope, StorageError> {
    DeliveryScope::new(DeliveryScopeFields {
        network_id: [1; 32],
        coordinator_server_id: [2; 16],
        coordinator_incarnation: [3; 16],
        coordinator_recovery_epoch: [4; 16],
        target_server_id: [5; 16],
        target_incarnation: [6; 16],
        covered_base_client_resync_epoch: 7,
    })
}

fn deadline_fields() -> PendingDeadlineFields {
    PendingDeadlineFields {
        boot_id: [10; 16],
        offset_seconds: -2,
        offset_nanoseconds: 3,
        deadline_seconds: 1_900,
        deadline_nanoseconds: 4,
        observed_seconds: 1_001,
        observed_nanoseconds: 5,
    }
}

fn cut_fields(count: u32, bytes: u64) -> SnapshotCutFields {
    SnapshotCutFields {
        token: [8; 32],
        state_generation: 0,
        delivery_generation: 0,
        entry_count: count,
        digest: [9; 32],
        page_count: count.div_ceil(32).max(1),
        total_object_bytes: bytes,
    }
}

fn owner(
    cursor: DeliveryCursor,
    cut: SnapshotCut,
    phase: CutPhase,
) -> Result<DeliveryOwner, StorageError> {
    DeliveryOwner::new(scope()?, cursor, cut, phase)
}

fn empty_owner(phase: CutPhase) -> Result<DeliveryOwner, StorageError> {
    owner(
        DeliveryCursor::new(0, 0, LastAcknowledged::BeforeFirst)?,
        SnapshotCut::new(cut_fields(0, 0))?,
        phase,
    )
}

fn phase() -> Result<CutPhase, StorageError> {
    Ok(CutPhase::Pending {
        offered_pages: 1,
        deadline: PendingDeadline::new(deadline_fields())?,
    })
}

fn entry(seed: u8) -> Result<SnapshotEntry, StorageError> {
    entry_with(seed, 1, [1; 32], 0)
}

fn entry_with(
    seed: u8,
    profile_version: u16,
    network_id: [u8; 32],
    state_generation: u64,
) -> Result<SnapshotEntry, StorageError> {
    let state = ArcFederationRouteState {
        profile_version,
        network_id,
        state_generation,
        conversation_id: [seed; 32],
        conversation_kind: ArcConversationKind::Channel,
        route_binding: [11; 32],
        semantic_route_lock_id: [12; 32],
        channel_instance_id: Opaque::new(vec![13; 16])
            .map_err(|_| StorageError::InvalidEncoding)?,
        canonical_channel_name_hash: [14; 32],
        direct_account_a: Opaque::new(Vec::new()).map_err(|_| StorageError::InvalidEncoding)?,
        direct_account_b: Opaque::new(Vec::new()).map_err(|_| StorageError::InvalidEncoding)?,
        binding_id: [15; 32],
        finalized_epoch: 1,
        accepted_state_id: [16; 32],
        sequencer_record_head_sequence: 0,
        sequencer_record_head_id: [17; 32],
        state: ArcRouteStateKind::ActiveRoute,
    };
    let bytes = ArcWireObject::new(
        ArcWireObjectKind::FederationState,
        state.encode().map_err(|_| StorageError::InvalidEncoding)?,
    )
    .and_then(|object| object.encode())
    .map_err(|_| StorageError::InvalidEncoding)?;
    SnapshotEntry::new([seed; 32], bytes)
}

fn page_identity(sequence: u32) -> Result<SnapshotPageIdentity, StorageError> {
    SnapshotPageIdentity::new([5; 16], 0, [8; 32], sequence)
}

fn barrier_fields(
    base_acked: bool,
    companion_acked: bool,
) -> Result<DeliveryBarrierFields, StorageError> {
    Ok(DeliveryBarrierFields {
        scope: scope()?,
        mutation_id: [18; 16],
        state_generation: 19,
        part_count: 3,
        base: BarrierEndpoint::new(20, 21, 21, [22; 16])?,
        companion: BarrierEndpoint::new(0, 0, 1, [23; 16])?,
        base_acked,
        companion_acked,
    })
}

fn wrap_inner(inner: Vec<u8>) -> Result<Vec<u8>, StorageError> {
    ProtocolRecordBody::new(TableId::E2eeState, DELIVERY_RECOVERY_ROW_KIND, 1, inner)?.encode()
}

fn inner(row: &DeliveryRecoveryRow) -> Result<Vec<u8>, StorageError> {
    Ok(ProtocolRecordBody::decode(
        TableId::E2eeState,
        DELIVERY_RECOVERY_ROW_KIND,
        &row.encode()?,
    )?
    .canonical_object()
    .to_vec())
}

fn assert_roundtrip(row: &DeliveryRecoveryRow) -> TestResult {
    let bytes = row.encode()?;
    assert_eq!(&DeliveryRecoveryRow::decode_at(&row.key()?, &bytes)?, row);
    assert_eq!(
        super::super::record_kind_for_key(&row.key()?)?,
        DELIVERY_RECOVERY_ROW_KIND
    );
    super::super::validate_state_body(DELIVERY_RECOVERY_ROW_KIND, &bytes)?;
    Ok(())
}

#[test]
fn owner_encoding_pins_field_order_and_distinguishes_before_first_from_zero_ack() -> TestResult {
    let row = DeliveryRecoveryRow::Owner(empty_owner(CutPhase::Ready)?);
    let mut expected = vec![0, 1, 0, 23, 0, 14, 0, 1, 0, 0, 0, 240, 0, 1, 0, 1];
    expected.extend_from_slice(&[1; 32]);
    for value in 2..=6 {
        expected.extend_from_slice(&[value; 16]);
    }
    expected.extend_from_slice(&7_u64.to_be_bytes());
    expected.extend_from_slice(&[0; 18]);
    expected.extend_from_slice(&[8; 32]);
    expected.extend_from_slice(&[0; 20]);
    expected.extend_from_slice(&[9; 32]);
    expected.extend_from_slice(&1_u32.to_be_bytes());
    expected.extend_from_slice(&[0; 8]);
    expected.extend_from_slice(&[0, 2]);
    assert_eq!(row.encode()?, expected);
    assert_roundtrip(&row)?;
    let at = owner(
        DeliveryCursor::new(
            0,
            1,
            LastAcknowledged::At {
                sequence: 0,
                event_id: [0; 16],
            },
        )?,
        SnapshotCut::new(cut_fields(0, 0))?,
        CutPhase::Ready,
    )?;
    let roundtrip = DeliveryRecoveryRow::decode(&DeliveryRecoveryRow::Owner(at).encode()?)?;
    let DeliveryRecoveryRow::Owner(at) = roundtrip else {
        return Err(StorageError::StaleState);
    };
    assert_eq!(
        at.cursor().last_ack(),
        LastAcknowledged::At {
            sequence: 0,
            event_id: [0; 16]
        }
    );
    assert_ne!(at.cursor().last_ack(), LastAcknowledged::BeforeFirst);
    Ok(())
}

#[test]
fn pending_ready_and_retired_keep_exact_cut_and_stream_ownership() -> TestResult {
    let cursor = DeliveryCursor::new(
        0,
        2,
        LastAcknowledged::At {
            sequence: 0,
            event_id: [0; 16],
        },
    )?;
    let cut = SnapshotCut::new(cut_fields(0, 0))?;
    for phase in [
        phase()?,
        CutPhase::Ready,
        CutPhase::Retired(RetirementReason::DeadlineReached),
        CutPhase::Retired(RetirementReason::ClockScopeLost),
        CutPhase::Retired(RetirementReason::ClockInvalid),
        CutPhase::Retired(RetirementReason::TransferRejected),
    ] {
        let row = DeliveryRecoveryRow::Owner(owner(cursor, cut, phase)?);
        assert_roundtrip(&row)?;
        let DeliveryRecoveryRow::Owner(restored) = DeliveryRecoveryRow::decode(&row.encode()?)?
        else {
            return Err(StorageError::StaleState);
        };
        assert_eq!(restored.cursor(), &cursor);
        assert_eq!(restored.cut(), &cut);
        assert_eq!(restored.scope(), &scope()?);
        assert_eq!(restored.phase(), phase);
    }
    Ok(())
}

#[test]
fn empty_cut_has_one_offered_empty_page_and_a_final_cursor() -> TestResult {
    let owner = empty_owner(phase()?)?;
    let page = SnapshotPage::new(page_identity(0)?, Vec::new(), None)?;
    page.validate_for(&owner)?;
    assert_roundtrip(&DeliveryRecoveryRow::CutPage(page))?;
    assert!(SnapshotPage::new(page_identity(0)?, Vec::new(), Some([24; 32])).is_err());
    assert!(
        SnapshotPage::new(page_identity(1)?, Vec::new(), None)?
            .validate_for(&owner)
            .is_err()
    );
    assert!(
        SnapshotCut::new(SnapshotCutFields {
            page_count: 0,
            ..cut_fields(0, 0)
        })
        .is_err()
    );
    assert!(
        SnapshotCut::new(SnapshotCutFields {
            total_object_bytes: 1,
            ..cut_fields(0, 0)
        })
        .is_err()
    );
    Ok(())
}

#[test]
fn page_bytes_random_cursor_and_durable_offered_boundary_survive_decode() -> TestResult {
    let entries: Vec<_> = (1..=32).map(entry).collect::<Result<_, _>>()?;
    let last_entry = entry(33)?;
    let total_bytes = entries
        .iter()
        .map(|entry| entry.bytes().len() as u64)
        .sum::<u64>()
        + last_entry.bytes().len() as u64;
    let cut = SnapshotCut::new(cut_fields(33, total_bytes))?;
    let first = SnapshotPage::new(page_identity(0)?, entries, Some([25; 32]))?;
    let last = SnapshotPage::new(page_identity(1)?, vec![last_entry], None)?;
    for offered_pages in 1..=2 {
        let owner = owner(
            DeliveryCursor::new(0, 0, LastAcknowledged::BeforeFirst)?,
            cut,
            CutPhase::Pending {
                offered_pages,
                deadline: PendingDeadline::new(deadline_fields())?,
            },
        )?;
        first.validate_for(&owner)?;
        last.validate_for(&owner)?;
        assert_roundtrip(&DeliveryRecoveryRow::Owner(owner))?;
    }
    let restored =
        DeliveryRecoveryRow::decode(&DeliveryRecoveryRow::CutPage(first.clone()).encode()?)?;
    assert_eq!(restored, DeliveryRecoveryRow::CutPage(first));
    assert_roundtrip(&DeliveryRecoveryRow::CutPage(last))?;
    Ok(())
}

#[test]
fn exact_keys_reject_wrong_arm_target_generation_token_page_and_length() -> TestResult {
    let owner = DeliveryRecoveryRow::Owner(empty_owner(CutPhase::Ready)?);
    let page =
        DeliveryRecoveryRow::CutPage(SnapshotPage::new(page_identity(0)?, Vec::new(), None)?);
    let barrier =
        DeliveryRecoveryRow::Barrier(DeliveryBarrier::new(barrier_fields(false, false)?)?);
    for row in [&owner, &page, &barrier] {
        let mut bytes = row.key()?.as_bytes().to_vec();
        bytes.push(0);
        assert!(DeliveryRecoveryRow::decode_at(&StoredKey::new(bytes)?, &row.encode()?).is_err());
        assert!(
            DeliveryRecoveryRow::decode_at(&StoredKey::new(OWNER_PREFIX.to_vec())?, &row.encode()?)
                .is_err()
        );
    }
    assert!(page.validate_key(&owner.key()?).is_err());
    assert!(barrier.validate_key(&owner.key()?).is_err());
    assert!(owner.validate_key(&owner_key(&[99; 16])?).is_err());
    for id in [
        SnapshotPageIdentity::new([99; 16], 0, [8; 32], 0)?,
        SnapshotPageIdentity::new([5; 16], 1, [8; 32], 0)?,
        SnapshotPageIdentity::new([5; 16], 0, [99; 32], 0)?,
        page_identity(1)?,
    ] {
        assert!(page.validate_key(&cut_page_key(&id)?).is_err());
    }
    assert_eq!(parse_owner_key(&owner.key()?)?, [5; 16]);
    assert_eq!(parse_barrier_key(&barrier.key()?)?, [5; 16]);
    assert_eq!(parse_cut_page_key(&page.key()?)?, page_identity(0)?);
    Ok(())
}

#[test]
fn closed_codec_refuses_truncation_trailing_bytes_versions_and_arms() -> TestResult {
    let rows = [
        DeliveryRecoveryRow::Owner(empty_owner(phase()?)?),
        DeliveryRecoveryRow::CutPage(SnapshotPage::new(page_identity(0)?, vec![entry(1)?], None)?),
        DeliveryRecoveryRow::Barrier(DeliveryBarrier::new(barrier_fields(true, false)?)?),
    ];
    for row in rows {
        let bytes = row.encode()?;
        for length in 0..bytes.len() {
            assert!(
                DeliveryRecoveryRow::decode(
                    bytes.get(..length).ok_or(StorageError::InvalidEncoding)?
                )
                .is_err()
            );
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(DeliveryRecoveryRow::decode(&trailing).is_err());
        let original = inner(&row)?;
        for (offset, replacement) in [(0, [0, 2]), (2, [0, 0]), (2, [0, 4])] {
            let mut bad = original.clone();
            bad.get_mut(offset..offset + 2)
                .ok_or(StorageError::InvalidEncoding)?
                .copy_from_slice(&replacement);
            assert!(DeliveryRecoveryRow::decode(&wrap_inner(bad)?).is_err());
        }
    }
    Ok(())
}

#[test]
fn wrapped_length_is_checked_before_envelope_decoding() -> TestResult {
    let mut malformed = vec![0; MAX_WRAPPED_BODY_BYTES];
    assert_eq!(
        DeliveryRecoveryRow::decode(&malformed),
        Err(StorageError::UnsupportedVersion)
    );
    malformed.push(0);
    assert_eq!(
        DeliveryRecoveryRow::decode(&malformed),
        Err(StorageError::LimitExceeded)
    );
    let oversized = wrap_inner(vec![0; MAX_PAGE_BODY_BYTES + 1])?;
    assert_eq!(oversized.len(), MAX_WRAPPED_BODY_BYTES + 1);
    assert_eq!(
        DeliveryRecoveryRow::decode(&oversized),
        Err(StorageError::LimitExceeded)
    );
    Ok(())
}

#[test]
fn page_constructor_refuses_duplicate_order_wrong_conversation_and_wrong_wire_kind() -> TestResult {
    assert!(SnapshotPage::new(page_identity(0)?, vec![entry(1)?, entry(1)?], None).is_err());
    assert!(SnapshotPage::new(page_identity(0)?, vec![entry(2)?, entry(1)?], None).is_err());
    assert!(SnapshotPage::new(page_identity(0)?, vec![entry(1)?], Some([0; 32])).is_err());
    assert!(SnapshotEntry::new([2; 32], entry(1)?.bytes().to_vec()).is_err());
    let wrong = ArcWireObject::new(ArcWireObjectKind::RootIdentity, vec![1])
        .and_then(|object| object.encode())
        .map_err(|_| StorageError::InvalidEncoding)?;
    assert!(SnapshotEntry::new([1; 32], wrong).is_err());
    assert!(SnapshotEntry::new([1; 32], vec![0; MAX_ENTRY_BYTES + 1]).is_err());
    assert!(SnapshotPageIdentity::new([5; 16], 0, [8; 32], MAX_SNAPSHOT_PAGES).is_err());
    let oversized: Vec<_> = (1..=33).map(entry).collect::<Result<_, _>>()?;
    assert!(SnapshotPage::new(page_identity(0)?, oversized, None).is_err());
    Ok(())
}

#[test]
fn pending_deadline_refuses_bad_coordinates_backward_samples_and_extension_shapes() -> TestResult {
    let fields = deadline_fields();
    for bad in [
        PendingDeadlineFields {
            offset_nanoseconds: 1_000_000_000,
            ..fields
        },
        PendingDeadlineFields {
            deadline_nanoseconds: 1_000_000_000,
            ..fields
        },
        PendingDeadlineFields {
            observed_nanoseconds: 1_000_000_000,
            ..fields
        },
        PendingDeadlineFields {
            deadline_seconds: 899,
            ..fields
        },
        PendingDeadlineFields {
            observed_seconds: 999,
            ..fields
        },
        PendingDeadlineFields {
            observed_seconds: 1_900,
            observed_nanoseconds: 4,
            ..fields
        },
        PendingDeadlineFields {
            observed_seconds: u64::MAX,
            ..fields
        },
    ] {
        assert!(PendingDeadline::new(bad).is_err());
    }
    let initial = PendingDeadline::new(PendingDeadlineFields {
        observed_seconds: 1_000,
        observed_nanoseconds: 4,
        ..fields
    })?;
    assert_eq!(initial.offset_seconds(), -2);
    assert_eq!(initial.deadline_seconds(), 1_900);
    let last = PendingDeadline::new(PendingDeadlineFields {
        observed_seconds: 1_900,
        observed_nanoseconds: 3,
        ..fields
    })?;
    assert_eq!(last.deadline_nanoseconds(), 4);
    Ok(())
}

#[test]
fn owner_refuses_unassigned_acks_wrong_generation_and_impossible_offered_counts() -> TestResult {
    assert!(
        DeliveryCursor::new(
            0,
            0,
            LastAcknowledged::At {
                sequence: 0,
                event_id: [0; 16]
            }
        )
        .is_err()
    );
    assert!(
        DeliveryCursor::new(
            0,
            u64::MAX,
            LastAcknowledged::At {
                sequence: u64::MAX,
                event_id: [0; 16]
            }
        )
        .is_err()
    );
    let cut = SnapshotCut::new(cut_fields(0, 0))?;
    assert!(
        owner(
            DeliveryCursor::new(1, 0, LastAcknowledged::BeforeFirst)?,
            cut,
            CutPhase::Ready
        )
        .is_err()
    );
    for offered_pages in [0, 2, u32::MAX] {
        assert!(
            empty_owner(CutPhase::Pending {
                offered_pages,
                deadline: PendingDeadline::new(deadline_fields())?
            })
            .is_err()
        );
    }
    assert!(SnapshotCut::new(cut_fields(MAX_SNAPSHOT_ENTRIES + 1, 0)).is_err());
    assert!(SnapshotCut::new(cut_fields(1, MAX_SNAPSHOT_BYTES + 1)).is_err());
    assert!(SnapshotCut::new(cut_fields(1, 0)).is_err());
    Ok(())
}

#[test]
fn barriers_retain_independent_flags_and_require_matching_cursor_coverage() -> TestResult {
    for base_acked in [false, true] {
        for companion_acked in [false, true] {
            let barrier = DeliveryBarrier::new(barrier_fields(base_acked, companion_acked)?)?;
            assert_roundtrip(&DeliveryRecoveryRow::Barrier(barrier.clone()))?;
            let last = if companion_acked {
                LastAcknowledged::At {
                    sequence: 1,
                    event_id: [23; 16],
                }
            } else {
                LastAcknowledged::BeforeFirst
            };
            let owner = owner(
                DeliveryCursor::new(0, 2, last)?,
                SnapshotCut::new(cut_fields(0, 0))?,
                CutPhase::Ready,
            )?;
            barrier.validate_for(&owner, 20)?;
            assert!(barrier.validate_for(&owner, 21).is_err());
            let wrong_flag = DeliveryBarrier::new(DeliveryBarrierFields {
                companion_acked: !companion_acked,
                ..barrier_fields(base_acked, companion_acked)?
            })?;
            assert!(wrong_flag.validate_for(&owner, 20).is_err());
        }
    }
    Ok(())
}

#[test]
fn barrier_refuses_partial_ack_wrong_final_id_and_incomplete_part_ranges() -> TestResult {
    let barrier = DeliveryBarrier::new(barrier_fields(false, true)?)?;
    for last_ack in [
        LastAcknowledged::At {
            sequence: 0,
            event_id: [23; 16],
        },
        LastAcknowledged::At {
            sequence: 1,
            event_id: [24; 16],
        },
    ] {
        let owner = owner(
            DeliveryCursor::new(0, 2, last_ack)?,
            SnapshotCut::new(cut_fields(0, 0))?,
            CutPhase::Ready,
        )?;
        assert!(barrier.validate_for(&owner, 20).is_err());
    }
    assert!(BarrierEndpoint::new(0, 2, 1, [0; 16]).is_err());
    assert!(BarrierEndpoint::new(0, 0, 2_048, [0; 16]).is_err());
    assert!(BarrierEndpoint::new(0, 0, u64::MAX, [0; 16]).is_err());
    assert!(
        DeliveryBarrier::new(DeliveryBarrierFields {
            state_generation: 0,
            ..barrier_fields(false, false)?
        })
        .is_err()
    );
    assert!(
        DeliveryBarrier::new(DeliveryBarrierFields {
            part_count: 2,
            ..barrier_fields(false, false)?
        })
        .is_err()
    );
    let mut bad = inner(&DeliveryRecoveryRow::Barrier(barrier))?;
    let len = bad.len();
    bad.get_mut(len - 2..)
        .ok_or(StorageError::InvalidEncoding)?
        .copy_from_slice(&[0, 2]);
    assert!(DeliveryRecoveryRow::decode(&wrap_inner(bad)?).is_err());
    Ok(())
}

#[test]
fn page_validation_binds_the_identity_the_cut_shape_and_each_entry_scope() -> TestResult {
    let single = || {
        owner(
            DeliveryCursor::new(0, 0, LastAcknowledged::BeforeFirst)?,
            SnapshotCut::new(cut_fields(1, 100))?,
            phase()?,
        )
    };
    let owner = single()?;
    SnapshotPage::new(page_identity(0)?, vec![entry(1)?], None)?.validate_for(&owner)?;
    for (name, identity) in [
        (
            "another target",
            SnapshotPageIdentity::new([6; 16], 0, [8; 32], 0)?,
        ),
        (
            "another generation",
            SnapshotPageIdentity::new([5; 16], 1, [8; 32], 0)?,
        ),
        (
            "another token",
            SnapshotPageIdentity::new([5; 16], 0, [9; 32], 0)?,
        ),
    ] {
        let page = SnapshotPage::new(identity, vec![entry(1)?], None)?;
        assert_eq!(
            page.validate_for(&owner).err(),
            Some(StorageError::StaleState),
            "{name}"
        );
    }
    let short = SnapshotPage::new(page_identity(0)?, Vec::new(), None)?;
    assert_eq!(
        short.validate_for(&owner).err(),
        Some(StorageError::InvalidEncoding),
        "fewer entries than the cut"
    );
    for (name, entry) in [
        ("another network", entry_with(1, 1, [2; 32], 0)?),
        ("a generation past the cut", entry_with(1, 1, [1; 32], 1)?),
    ] {
        let page = SnapshotPage::new(page_identity(0)?, vec![entry], None)?;
        assert_eq!(
            page.validate_for(&owner).err(),
            Some(StorageError::StaleState),
            "{name}"
        );
    }
    // A final page may not offer a further cursor.
    let full = owner_of(32)?;
    let entries = (1..=32).map(entry).collect::<Result<Vec<_>, _>>()?;
    SnapshotPage::new(page_identity(0)?, entries.clone(), None)?.validate_for(&full)?;
    let continued = SnapshotPage::new(page_identity(0)?, entries, Some([24; 32]))?;
    assert_eq!(
        continued.validate_for(&full).err(),
        Some(StorageError::InvalidEncoding)
    );
    // Entry bytes are bounded below and pinned to profile one.
    assert_eq!(
        SnapshotEntry::new([1; 32], Vec::new()).err(),
        Some(StorageError::LimitExceeded)
    );
    assert_eq!(
        entry_with(1, 2, [1; 32], 0).err(),
        Some(StorageError::UnsupportedVersion)
    );
    Ok(())
}

fn owner_of(count: u32) -> Result<DeliveryOwner, StorageError> {
    owner(
        DeliveryCursor::new(0, 0, LastAcknowledged::BeforeFirst)?,
        SnapshotCut::new(cut_fields(count, 100))?,
        phase()?,
    )
}
