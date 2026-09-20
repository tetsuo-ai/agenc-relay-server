//! Stage 08 companion record codecs: every arm round-trips, binds its table
//! and kind, refuses cross-kind replay and malformed bodies, lays keys out
//! exactly, and commits as one atomic set through the engine.

#![forbid(unsafe_code)]

use std::error::Error;

use agenc_ircd_crypto::{LoginIndexKey, RollbackGuardRootKey, StorageDigest, StorageMasterKey};
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
use agenc_ircd_e2ee::tls::TlsEncode;
use agenc_ircd_storage::e2ee_records::barrier::{
    BARRIER_RETENTION_SECONDS, BarrierHead, BarrierIdentity, BarrierPart, BarrierReceipt,
    BarrierStage, CrossProfileStream, HEAD_KEY_BYTES, PART_KEY_BYTES, parse_key,
};
use agenc_ircd_storage::e2ee_records::{
    ATTACH_ROW_KIND, AttachChallenge, AttachRow, BARRIER_ROW_KIND, CLAIM_ROW_KIND, CandidateState,
    ClaimOutcome, ClaimRow, DELIVERY_ROW_KIND, DIRECTORY_ROW_KIND, DeliveryGrant, DeliveryRow,
    DirectoryRow, KEYSET_ROW_KIND, KeySetRow, MAILBOX_ROW_KIND, MailboxKind, MailboxRow,
    OBJECT_RECORD_KIND, ObjectRow, PACKAGE_ROW_KIND, PENDING_ROUTE_ROW_KIND, PackageRow,
    PackageState, PendingRouteRow, ProofRole, RECOVERY_GATE_KIND, REPLAY_ROW_KIND, ROUTE_ROW_KIND,
    ReplayKey, ReplayRow, RouteLifecycle, RouteRow, SEQUENCER_HISTORY_ROW_KIND, SEQUENCER_ROW_KIND,
    SNAPSHOT_MARKER_ROW_KIND, SequencerHistoryRow, SequencerRow, SnapshotMarkerRow, SnapshotPhase,
    check_state_key, object_key, prefix, record_kind_for_key, recovery_gate_key,
    validate_object_body, validate_state_body,
};
use agenc_ircd_storage::{
    CommitOutcome, DatabaseHeaderTbs, InitialStorageRecord, LoginIndexKeyState,
    PersistentRecordValue, ProtocolRecordBody, ReadPlan, RecordMutation, SCHEMA_GENERATION,
    StateDirectory, StorageAccountingLimits, StorageEngineLimits, StorageError,
    StorageInitializationConfig, StorageInitializationMode, StorageInitializationOutcome,
    StorageMutationBatch, StorageMutationHead, StorageOpenConfig, StorageOwner, StoredKey, TableId,
    initialize_storage,
};
use agenc_ircd_types::{
    DatabaseId, NetworkId, RecoveryEpoch, ServerId, ServerIncarnation, TransactionId,
};

type TestResult = Result<(), Box<dyn Error>>;

const CONVERSATION: [u8; 32] = [20; 32];
const ACCOUNT: [u8; 32] = [21; 32];
const DEVICE: [u8; 16] = [7; 16];

#[test]
fn origin_sequence_floors_bind_exact_keys_and_reject_replay_bodies() -> TestResult {
    use agenc_ircd_storage::e2ee_records::origin::{OriginSequenceKey, OriginSequenceRow};

    let parts = OriginSequenceKey {
        home_server_id: [1; 16],
        server_incarnation: [2; 16],
        origin_id: [3; 16],
    };
    let key = OriginSequenceRow::key(&parts)?;
    assert_eq!(OriginSequenceRow::parse_key(&key)?, parts);
    assert_eq!(key.as_bytes().len(), prefix::ORIGIN_SEQUENCE.len() + 48);
    assert_eq!(record_kind_for_key(&key)?, REPLAY_ROW_KIND);
    assert!(ReplayRow::parse_key(&key).is_err());
    let mut shortened = key.as_bytes().to_vec();
    shortened.pop();
    assert!(OriginSequenceRow::parse_key(&StoredKey::new(shortened)?).is_err());
    let mut extended = key.as_bytes().to_vec();
    extended.push(0);
    assert!(OriginSequenceRow::parse_key(&StoredKey::new(extended)?).is_err());

    assert!(
        OriginSequenceRow {
            origin_generation: 0,
            next_sequence: 0
        }
        .encode()
        .is_err()
    );
    for next_sequence in [1, u64::MAX] {
        let row = OriginSequenceRow {
            origin_generation: 7,
            next_sequence,
        };
        let body = row.encode()?;
        assert_eq!(OriginSequenceRow::decode(&body)?, row);
        assert!(ReplayRow::decode(&body).is_err());
        validate_state_body(REPLAY_ROW_KIND, &body)?;
        for length in 0..body.len() {
            assert!(
                OriginSequenceRow::decode(body.get(..length).ok_or("invalid test slice")?).is_err()
            );
        }
        PersistentRecordValue::new(
            TableId::E2eeState,
            REPLAY_ROW_KIND,
            1,
            1,
            None,
            Vec::new(),
            body,
        )?;
    }
    let replay = agenc_ircd_storage::e2ee_records::fixtures::state_body(REPLAY_ROW_KIND, 1)?;
    assert!(OriginSequenceRow::decode(&replay).is_err());
    assert!(OriginSequenceRow::decode(&route_row().encode()?).is_err());
    Ok(())
}

fn object_bytes(kind: IrcWireObjectKind, body_len: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(IrcWireObject::new(kind, vec![9; body_len])?.encode()?)
}

fn route_row() -> RouteRow {
    RouteRow {
        route_state: vec![1, 2, 3],
        lifecycle: RouteLifecycle::Active,
        binding_id: [1; 32],
        lock_id: [2; 32],
        accepted_state_id: [3; 32],
        sequencer_head_id: [4; 32],
        route_sequence: 5,
        close_id: None,
        predecessor_close_id: Some([6; 32]),
        recovery_gate: false,
        stored_bytes: 700,
        sequencer_credential_id: Some([7; 32]),
        blocked_credential_id: None,
    }
}

fn identity() -> BarrierIdentity {
    BarrierIdentity {
        network_id: [1; 32],
        coordinator_server_id: [2; 16],
        coordinator_server_incarnation: [3; 16],
        coordinator_recovery_epoch: [4; 16],
        target_server_id: [5; 16],
        target_server_incarnation: [6; 16],
        mutation_id: [7; 16],
        coordinator_state_generation: 8,
        part_count: 3,
    }
}

fn part(index: u16, stream: CrossProfileStream) -> BarrierPart {
    let companion = stream == CrossProfileStream::Companion;
    BarrierPart {
        identity: identity(),
        stream,
        part_index: index,
        delivery_generation: 1,
        delivery_sequence: u64::from(index) + 10,
        event_id: [index as u8; 16],
        event_object_id: [30 + index as u8; 32],
        encoded_event_object: vec![1; 40],
        payload_object_id: companion.then_some([40; 32]),
        payload_object_bytes: if companion { 100 } else { 0 },
    }
}

fn receipt() -> BarrierReceipt {
    BarrierReceipt {
        identity: identity(),
        applied_storage_commit_sequence: 9,
        applied_local_state_generation: 10,
        applied_at: 1_000,
        retain_until: 1_000 + BARRIER_RETENTION_SECONDS,
        aggregate_event_payload_bytes: 220,
        entries: vec![
            part(0, CrossProfileStream::Base).receipt_entry(),
            part(1, CrossProfileStream::Companion).receipt_entry(),
            part(2, CrossProfileStream::Companion).receipt_entry(),
        ],
    }
}

#[test]
fn keys_classify_by_prefix_and_lay_out_exactly() -> TestResult {
    let cases: Vec<(StoredKey, u16)> = vec![
        (recovery_gate_key(&CONVERSATION)?, RECOVERY_GATE_KIND),
        (RouteRow::key(&CONVERSATION)?, ROUTE_ROW_KIND),
        (ClaimRow::lock_key(&[1; 32])?, CLAIM_ROW_KIND),
        (ClaimRow::reservation_key(&[1; 16])?, CLAIM_ROW_KIND),
        (
            SequencerRow::record_key(&CONVERSATION, 3)?,
            SEQUENCER_ROW_KIND,
        ),
        (
            SequencerRow::candidate_key(&CONVERSATION, 3)?,
            SEQUENCER_ROW_KIND,
        ),
        (
            SequencerRow::proof_key(ProofRole::Ack, &CONVERSATION, &[1; 32], &[2; 32], &DEVICE)?,
            SEQUENCER_ROW_KIND,
        ),
        (DirectoryRow::identity_key(&ACCOUNT)?, DIRECTORY_ROW_KIND),
        (DirectoryRow::roster_key(&ACCOUNT)?, DIRECTORY_ROW_KIND),
        (
            DirectoryRow::capability_key(&ACCOUNT, &DEVICE)?,
            DIRECTORY_ROW_KIND,
        ),
        (
            DirectoryRow::binding_lock_key(&ACCOUNT, &[1; 32], 0)?,
            DIRECTORY_ROW_KIND,
        ),
        (
            SequencerRow::membership_key(&CONVERSATION, 0, &[1; 32])?,
            SEQUENCER_ROW_KIND,
        ),
        (PackageRow::package_key(&[1; 32])?, PACKAGE_ROW_KIND),
        (PackageRow::claim_key(&ACCOUNT, &[1; 16])?, PACKAGE_ROW_KIND),
        (AttachRow::key(&ACCOUNT, &DEVICE)?, ATTACH_ROW_KIND),
        (
            MailboxRow::item_key(&ACCOUNT, &DEVICE, MailboxKind::Welcome, 4)?,
            MAILBOX_ROW_KIND,
        ),
        (MailboxRow::token_key(&[1; 32])?, MAILBOX_ROW_KIND),
        (
            MailboxRow::ack_key(&ACCOUNT, &DEVICE, &[1; 32])?,
            MAILBOX_ROW_KIND,
        ),
        (ReplayRow::key(&replay_key())?, REPLAY_ROW_KIND),
        (DeliveryRow::cursor_key(&[1; 16])?, DELIVERY_ROW_KIND),
        (KeySetRow::key()?, KEYSET_ROW_KIND),
        (identity().head_key()?, BARRIER_ROW_KIND),
        (identity().part_key(2)?, BARRIER_ROW_KIND),
    ];
    for (key, kind) in &cases {
        assert_eq!(record_kind_for_key(key)?, *kind, "{:?}", key.as_bytes());
        assert_eq!(check_state_key(key, *kind), Ok(()));
        assert!(key.as_bytes().len() <= 4_096);
    }
    assert_eq!(
        check_state_key(&RouteRow::key(&CONVERSATION)?, CLAIM_ROW_KIND),
        Err(StorageError::InvalidEncoding)
    );
    assert_eq!(
        record_kind_for_key(&StoredKey::new(b"other/v1/x".to_vec())?),
        Err(StorageError::InvalidEncoding)
    );
    assert_eq!(identity().head_key()?.as_bytes().len(), HEAD_KEY_BYTES);
    assert_eq!(identity().part_key(0)?.as_bytes().len(), PART_KEY_BYTES);
    assert!(identity().part_key(3).is_err());
    let parts = parse_key(&identity().part_key(2)?)?;
    assert_eq!(parts.part_index, Some(2));
    assert_eq!(parts.mutation_id, [7; 16]);
    assert_eq!(parse_key(&identity().head_key()?)?.part_index, None);
    assert_eq!(
        RouteRow::parse_key(&RouteRow::key(&CONVERSATION)?)?,
        CONVERSATION
    );
    assert_eq!(
        SequencerRow::parse_record_key(&SequencerRow::record_key(&CONVERSATION, 77)?)?,
        (CONVERSATION, 77)
    );
    let item = MailboxRow::parse_item_key(&MailboxRow::item_key(
        &ACCOUNT,
        &DEVICE,
        MailboxKind::StagedReinit,
        9,
    )?)?;
    assert_eq!(item.kind, MailboxKind::StagedReinit);
    assert_eq!(item.sequence, 9);
    assert_eq!(item.device_id, DEVICE);
    assert_eq!(
        ReplayRow::parse_key(&ReplayRow::key(&replay_key())?)?,
        replay_key()
    );
    assert!(RouteRow::parse_key(&ClaimRow::lock_key(&[1; 32])?).is_err());
    assert!(PackageRow::package_key(&[]).is_err());
    assert!(PackageRow::package_key(&[1; 256]).is_err());
    assert_eq!(object_key(&[3; 32])?.as_bytes(), &[3; 32]);
    Ok(())
}

fn replay_key() -> ReplayKey {
    ReplayKey {
        home_server_id: [1; 16],
        server_incarnation: [2; 16],
        origin_id: [3; 16],
        origin_generation: 4,
        operation_sequence: 5,
    }
}

#[test]
fn page_plans_cover_every_shape() -> TestResult {
    assert!(SequencerRow::record_range(&CONVERSATION, 0, 10).is_ok());
    assert!(SequencerRow::record_range(&CONVERSATION, u64::MAX, 0).is_ok());
    assert!(SequencerRow::proof_range(ProofRole::Vote, &CONVERSATION, &[1; 32]).is_ok());
    assert!(DirectoryRow::capability_range(&ACCOUNT).is_ok());
    assert!(DirectoryRow::binding_lock_range(&ACCOUNT, &[1; 32], 3, 500).is_ok());
    assert!(MailboxRow::item_range(&ACCOUNT, &DEVICE, MailboxKind::Binding, 0, 32).is_ok());
    assert!(ReplayRow::origin_range(&[1; 16], &[2; 16], &[3; 16], 4).is_ok());
    assert!(agenc_ircd_storage::e2ee_records::prefix_range(prefix::ROUTE, 16).is_ok());
    assert!(
        agenc_ircd_storage::e2ee_records::prefix_range_from(
            prefix::ROUTE,
            &ClaimRow::lock_key(&[1; 32])?,
            16
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn objects_store_exact_bytes_under_their_id() -> TestResult {
    let bytes = object_bytes(IrcWireObjectKind::CommitAck, 200)?;
    let row = ObjectRow::new(bytes.clone())?;
    assert_eq!(row.kind()?, IrcWireObjectKind::CommitAck);
    assert_eq!(
        row.key()?.as_bytes(),
        agenc_ircd_e2ee::ObjectId::compute(&bytes).as_bytes()
    );
    let encoded = row.encode()?;
    assert_eq!(ObjectRow::decode(&encoded)?, row);
    assert_eq!(validate_object_body(&encoded), Ok(()));
    assert!(ObjectRow::new(vec![0; 10]).is_err());
    assert!(
        object_bytes(IrcWireObjectKind::ApplicationMls, 65_531).is_err(),
        "the object crate refuses an oversize envelope before storage sees it"
    );
    assert!(ObjectRow::new(object_bytes(IrcWireObjectKind::ApplicationMls, 65_530)?).is_ok());
    let mut oversize = vec![0, 1, 1, 0, 0xff, 0xfb];
    oversize.extend(std::iter::repeat_n(9, 65_531));
    assert_eq!(
        ObjectRow::new(oversize).map(|_| ()),
        Err(StorageError::InvalidEncoding),
        "a hand-built envelope over the kind maximum is refused by the row"
    );
    assert!(ObjectRow::decode(&route_row().encode()?).is_err());
    assert!(
        PersistentRecordValue::new(
            TableId::E2eeObject,
            OBJECT_RECORD_KIND,
            1,
            1,
            None,
            Vec::new(),
            encoded
        )
        .is_ok()
    );
    assert!(
        PersistentRecordValue::new(
            TableId::E2eeObject,
            OBJECT_RECORD_KIND,
            1,
            1,
            None,
            Vec::new(),
            route_row().encode()?
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn route_and_claim_rows_round_trip_and_check_their_rules() -> TestResult {
    let route = route_row();
    assert_eq!(RouteRow::decode(&route.encode()?)?, route);
    let closing = RouteRow {
        lifecycle: RouteLifecycle::Closing,
        close_id: Some([9; 32]),
        ..route.clone()
    };
    assert_eq!(RouteRow::decode(&closing.encode()?)?, closing);
    let tombstone_without_close = RouteRow {
        lifecycle: RouteLifecycle::Tombstone,
        ..route.clone()
    };
    assert_eq!(
        RouteRow::decode(&tombstone_without_close.encode()?),
        Err(StorageError::InvalidEncoding)
    );
    assert_eq!(
        RouteRow {
            route_state: Vec::new(),
            ..route.clone()
        }
        .encode(),
        Err(StorageError::LimitExceeded)
    );
    assert!(RouteRow::decode(&KeySetRow::decode(&keyset().encode()?)?.encode()?).is_err());
    let lock = ClaimRow::Lock {
        conversation_id: CONVERSATION,
        binding_id: [1; 32],
        incarnation: 2,
    };
    let reservation = ClaimRow::Reservation {
        owner_account_digest: ACCOUNT,
        owner_device_id: DEVICE,
        kind: 1,
        lock_id: [2; 32],
        route_binding: [3; 32],
        reservation_object_id: [4; 32],
        expires_at: 60,
    };
    for row in [&lock, &reservation] {
        assert_eq!(&ClaimRow::decode(&row.encode()?)?, row);
    }
    assert!(lock.matches_key(&ClaimRow::lock_key(&[2; 32])?));
    assert!(!lock.matches_key(&ClaimRow::reservation_key(&[2; 16])?));
    assert!(reservation.matches_key(&ClaimRow::reservation_key(&[2; 16])?));
    assert!(ClaimRow::decode(&route.encode()?).is_err());
    Ok(())
}

fn candidate_row(state: CandidateState, terminal_id: Option<[u8; 32]>) -> SequencerRow {
    SequencerRow::Candidate {
        candidate_id: [1; 32],
        commit_object_id: [2; 32],
        route_sequence: 3,
        candidate_sequence: 4,
        attempts: 5,
        state,
        terminal_id,
    }
}

fn package_row(state: PackageState, claimed_by: Option<([u8; 32], [u8; 16])>) -> PackageRow {
    PackageRow::Package {
        account_digest: ACCOUNT,
        device_id: DEVICE,
        suite: 1,
        expires_at: 100,
        object_id: [1; 32],
        state,
        claimed_by,
    }
}

fn claim_row(
    outcome: ClaimOutcome,
    key_package_ref: Vec<u8>,
    object_id: Option<[u8; 32]>,
) -> PackageRow {
    PackageRow::Claim {
        target_account_digest: ACCOUNT,
        target_device_id: DEVICE,
        suite: 3,
        outcome,
        key_package_ref,
        object_id,
        retain_until: 700,
    }
}

fn item_row(grant: Option<DeliveryGrant>) -> MailboxRow {
    MailboxRow::Item {
        object_id: [1; 32],
        conversation_id: CONVERSATION,
        inserted_at: 10,
        expires_at: 20,
        grant,
    }
}

fn cursor_row(acked_sequence: u64) -> DeliveryRow {
    DeliveryRow::WitnessedCursor {
        generation: 1,
        next_sequence: 5,
        acked_sequence,
        acked_event_id: [1; 16],
        barrier_open: true,
    }
}

fn keyset() -> KeySetRow {
    KeySetRow {
        generation: 3,
        digest: [5; 32],
        credential_ids: vec![[6; 32], [7; 32]],
    }
}

#[test]
fn sequencer_rows_round_trip_and_keep_slot_invariants() -> TestResult {
    let record = SequencerRow::Record {
        record_object_id: [1; 32],
        record_id: [2; 32],
        record_kind: 3,
        terminal: true,
        security_proof: true,
        predecessor_record_id: [4; 32],
    };
    let candidate = candidate_row(CandidateState::Finalized, Some([6; 32]));
    let proof = SequencerRow::Proof {
        role: ProofRole::Vote,
        object_id: [7; 32],
        slot: 2,
    };
    let policy = SequencerRow::Policy {
        object_id: [8; 32],
        generation: 1,
        previous_policy_id: [9; 32],
    };
    let membership = SequencerRow::Membership {
        object_id: [11; 32],
        epoch: 3,
        device_id: DEVICE,
        disposition: 1,
    };
    for row in [&record, &candidate, &proof, &policy, &membership] {
        assert_eq!(&SequencerRow::decode(&row.encode()?)?, row);
    }
    let membership_key = SequencerRow::membership_key(&CONVERSATION, 7, &[12; 32])?;
    assert!(membership.matches_key(&membership_key));
    assert!(!policy.matches_key(&membership_key));
    assert_eq!(
        SequencerRow::parse_membership_key(&membership_key)?,
        (CONVERSATION, 7, [12; 32])
    );
    let unknown_disposition = SequencerRow::Membership {
        object_id: [11; 32],
        epoch: 3,
        device_id: DEVICE,
        disposition: 3,
    };
    assert!(SequencerRow::decode(&unknown_disposition.encode()?).is_err());
    let policy_key = SequencerRow::policy_key(&CONVERSATION, &[10; 32])?;
    assert!(policy.matches_key(&policy_key));
    assert!(!proof.matches_key(&policy_key));
    assert_eq!(
        SequencerRow::parse_policy_key(&policy_key)?,
        (CONVERSATION, [10; 32])
    );
    let unchained = SequencerRow::Policy {
        object_id: [8; 32],
        generation: 0,
        previous_policy_id: [9; 32],
    };
    assert!(SequencerRow::decode(&unchained.encode()?).is_err());
    assert!(record.matches_key(&SequencerRow::record_key(&CONVERSATION, 1)?));
    assert!(candidate.matches_key(&SequencerRow::candidate_key(&CONVERSATION, 1)?));
    assert!(proof.matches_key(&SequencerRow::proof_key(
        ProofRole::Vote,
        &CONVERSATION,
        &[1; 32],
        &[2; 32],
        &DEVICE
    )?));
    assert!(!proof.matches_key(&SequencerRow::proof_key(
        ProofRole::Ack,
        &CONVERSATION,
        &[1; 32],
        &[2; 32],
        &DEVICE
    )?));
    let active_with_terminal = candidate_row(CandidateState::Active, Some([6; 32]));
    assert_eq!(
        SequencerRow::decode(&active_with_terminal.encode()?),
        Err(StorageError::InvalidEncoding)
    );
    let aborted_without_terminal = candidate_row(CandidateState::Aborted, None);
    assert!(SequencerRow::decode(&aborted_without_terminal.encode()?).is_err());
    let ack_with_slot = SequencerRow::Proof {
        role: ProofRole::Approval,
        object_id: [7; 32],
        slot: 1,
    };
    assert!(SequencerRow::decode(&ack_with_slot.encode()?).is_err());
    assert!(SequencerRow::decode(&route_row().encode()?).is_err());
    Ok(())
}

#[test]
fn vote_rows_reject_unknown_terminal_slots_before_storage() -> TestResult {
    for slot in [0, 3, u16::MAX] {
        let body = SequencerRow::Proof {
            role: ProofRole::Vote,
            object_id: [7; 32],
            slot,
        }
        .encode()?;
        assert_eq!(
            SequencerRow::decode(&body),
            Err(StorageError::InvalidEncoding)
        );
        assert!(
            PersistentRecordValue::new(
                TableId::E2eeState,
                SEQUENCER_ROW_KIND,
                1,
                0,
                None,
                Vec::new(),
                body,
            )
            .is_err()
        );
    }
    for slot in [1, 2] {
        let row = SequencerRow::Proof {
            role: ProofRole::Vote,
            object_id: [7; 32],
            slot,
        };
        assert_eq!(SequencerRow::decode(&row.encode()?)?, row);
    }
    Ok(())
}

#[test]
fn directory_rows_round_trip_and_check_chains() -> TestResult {
    let identity_row = DirectoryRow::Identity {
        root_generation: 1,
        root_fingerprint: [1; 32],
        object_id: [3; 32],
        chain_object_ids: vec![[2; 32], [3; 32]],
    };
    let roster = DirectoryRow::Roster {
        roster_generation: 2,
        roster_id: [4; 32],
        root_fingerprint: [1; 32],
        object_id: [5; 32],
        active_devices: vec![[1; 16], [2; 16]],
    };
    let capability = DirectoryRow::Capability {
        generation: 3,
        capability_id: [6; 32],
        roster_id: [4; 32],
        object_id: [7; 32],
    };
    let lock = DirectoryRow::BindingLock {
        lock_id: [8; 32],
        binding_id: [9; 32],
        object_id: [10; 32],
    };
    for row in [&identity_row, &roster, &capability, &lock] {
        assert_eq!(&DirectoryRow::decode(&row.encode()?)?, row);
    }
    assert!(identity_row.matches_key(&DirectoryRow::identity_key(&ACCOUNT)?));
    assert!(roster.matches_key(&DirectoryRow::roster_key(&ACCOUNT)?));
    assert!(capability.matches_key(&DirectoryRow::capability_key(&ACCOUNT, &DEVICE)?));
    assert!(lock.matches_key(&DirectoryRow::binding_lock_key(&ACCOUNT, &[1; 32], 0)?));
    assert!(!lock.matches_key(&DirectoryRow::roster_key(&ACCOUNT)?));
    let short_chain = DirectoryRow::Identity {
        root_generation: 1,
        root_fingerprint: [1; 32],
        object_id: [3; 32],
        chain_object_ids: vec![[3; 32]],
    };
    assert!(DirectoryRow::decode(&short_chain.encode()?).is_err());
    let head_mismatch = DirectoryRow::Identity {
        root_generation: 0,
        root_fingerprint: [1; 32],
        object_id: [3; 32],
        chain_object_ids: vec![[2; 32]],
    };
    assert!(DirectoryRow::decode(&head_mismatch.encode()?).is_err());
    let unsorted = DirectoryRow::Roster {
        roster_generation: 2,
        roster_id: [4; 32],
        root_fingerprint: [1; 32],
        object_id: [5; 32],
        active_devices: vec![[2; 16], [1; 16]],
    };
    assert!(DirectoryRow::decode(&unsorted.encode()?).is_err());
    let crowded = DirectoryRow::Roster {
        roster_generation: 2,
        roster_id: [4; 32],
        root_fingerprint: [1; 32],
        object_id: [5; 32],
        active_devices: (0..65_u8).map(|index| [index; 16]).collect(),
    };
    assert_eq!(
        crowded.encode().map(|_| ()),
        Err(StorageError::LimitExceeded)
    );
    Ok(())
}

#[test]
fn package_attach_and_mailbox_rows_round_trip() -> TestResult {
    let package = package_row(PackageState::Claimed, Some(([2; 32], [3; 16])));
    let claim = claim_row(ClaimOutcome::KeyUnavailable, Vec::new(), None);
    for row in [&package, &claim] {
        assert_eq!(&PackageRow::decode(&row.encode()?)?, row);
    }
    assert!(package.matches_key(&PackageRow::package_key(&[1; 32])?));
    assert!(claim.matches_key(&PackageRow::claim_key(&ACCOUNT, &[1; 16])?));
    let published_with_claim = package_row(PackageState::Published, Some(([2; 32], [3; 16])));
    assert!(PackageRow::decode(&published_with_claim.encode()?).is_err());
    let claimed_without_reference = claim_row(ClaimOutcome::Claimed, Vec::new(), None);
    assert!(PackageRow::decode(&claimed_without_reference.encode()?).is_err());
    let claimed = claim_row(ClaimOutcome::Claimed, vec![4; 32], Some([5; 32]));
    assert_eq!(PackageRow::decode(&claimed.encode()?)?, claimed);

    let attached = AttachRow {
        session_generation: 2,
        challenge: Some(AttachChallenge {
            connection_id: [9; 16],
            connection_nonce: [1; 32],
            server_challenge: [2; 32],
            reserved_generation: 3,
            expires_at: 60,
            object_id: [3; 32],
        }),
    };
    let idle = AttachRow {
        session_generation: 0,
        challenge: None,
    };
    for row in [attached, idle] {
        assert_eq!(AttachRow::decode(&row.encode()?)?, row);
    }
    let stale_reservation = AttachRow {
        session_generation: 3,
        ..attached
    };
    assert!(AttachRow::decode(&stale_reservation.encode()?).is_err());

    let item = item_row(Some(DeliveryGrant {
        token: [2; 32],
        session_generation: 3,
        expires_at: 15,
    }));
    let token = MailboxRow::Token {
        account_digest: ACCOUNT,
        device_id: DEVICE,
        kind: MailboxKind::Application,
        sequence: 4,
        object_id: [1; 32],
        session_generation: 3,
        expires_at: 15,
    };
    let ack = MailboxRow::Ack {
        object_id: [1; 32],
        acknowledged_at: 16,
        retain_until: 1_816,
    };
    for row in [&item, &token, &ack] {
        assert_eq!(&MailboxRow::decode(&row.encode()?)?, row);
    }
    assert!(item.matches_key(&MailboxRow::item_key(
        &ACCOUNT,
        &DEVICE,
        MailboxKind::Welcome,
        1
    )?));
    assert!(token.matches_key(&MailboxRow::token_key(&[2; 32])?));
    assert!(ack.matches_key(&MailboxRow::ack_key(&ACCOUNT, &DEVICE, &[2; 32])?));
    assert!(!ack.matches_key(&MailboxRow::token_key(&[2; 32])?));
    let ungranted = item_row(None);
    assert_eq!(MailboxRow::decode(&ungranted.encode()?)?, ungranted);
    Ok(())
}

#[test]
fn replay_delivery_and_keyset_rows_round_trip() -> TestResult {
    let replay = ReplayRow {
        request_id: [1; 16],
        request_object_id: [2; 32],
        result_object_id: Some([3; 32]),
        response_object_ids: vec![[4; 32], [5; 32]],
        security_mutation: true,
        retain_until: 604_800,
    };
    assert_eq!(ReplayRow::decode(&replay.encode()?)?, replay);
    let pending = ReplayRow {
        result_object_id: None,
        response_object_ids: Vec::new(),
        ..replay.clone()
    };
    assert_eq!(ReplayRow::decode(&pending.encode()?)?, pending);
    let pending_with_descriptors = ReplayRow {
        result_object_id: None,
        ..replay.clone()
    };
    assert!(ReplayRow::decode(&pending_with_descriptors.encode()?).is_err());
    let crowded = ReplayRow {
        response_object_ids: vec![[4; 32]; 33],
        ..replay
    };
    assert_eq!(
        crowded.encode().map(|_| ()),
        Err(StorageError::LimitExceeded)
    );

    let cursor = cursor_row(4);
    assert_eq!(DeliveryRow::decode(&cursor.encode()?)?, cursor);
    assert!(cursor.matches_key(&DeliveryRow::cursor_key(&[1; 16])?));
    let inverted = cursor_row(6);
    assert!(DeliveryRow::decode(&inverted.encode()?).is_err());
    assert_eq!(KeySetRow::decode(&keyset().encode()?)?, keyset());
    assert!(
        KeySetRow {
            credential_ids: Vec::new(),
            ..keyset()
        }
        .encode()
        .is_err()
    );
    assert_eq!(
        KeySetRow {
            credential_ids: vec![[1; 32]; 3],
            ..keyset()
        }
        .encode()
        .map(|_| ()),
        Err(StorageError::LimitExceeded)
    );
    Ok(())
}

#[test]
fn barrier_rows_follow_the_appendix_b_encoding() -> TestResult {
    let mut stage = BarrierStage::empty(identity());
    assert_eq!(stage.received_bitmap.len(), 1);
    assert_eq!(stage.received_count(), 0);
    assert!(!stage.is_complete());
    stage.mark_received(2, 140)?;
    stage.mark_received(0, 40)?;
    assert!(stage.is_received(0) && stage.is_received(2) && !stage.is_received(1));
    assert_eq!(
        stage.mark_received(2, 1),
        Err(StorageError::InvalidEncoding)
    );
    assert_eq!(
        stage.mark_received(3, 1),
        Err(StorageError::InvalidEncoding)
    );
    let head = BarrierHead::Stage(stage.clone());
    assert_eq!(BarrierHead::decode(&head.encode()?)?, head);
    stage.mark_received(1, 40)?;
    assert!(stage.is_complete());
    assert_eq!(stage.aggregate_event_payload_bytes, 220);
    let mut dirty = stage.clone();
    dirty.received_bitmap = vec![0xff];
    assert!(dirty.encode().is_err(), "unused high bits must be zero");
    dirty.received_bitmap = vec![0x07, 0];
    assert!(dirty.encode().is_err(), "bitmap length is exact");

    for part in [
        part(0, CrossProfileStream::Base),
        part(1, CrossProfileStream::Companion),
    ] {
        let encoded = part.encode()?;
        assert_eq!(BarrierPart::decode(&encoded)?, part);
        assert_eq!(validate_state_body(BARRIER_ROW_KIND, &encoded), Ok(()));
        assert!(BarrierHead::decode(&encoded).is_err());
    }
    assert_eq!(
        part(1, CrossProfileStream::Companion).contributed_bytes()?,
        140
    );
    let base_with_payload = BarrierPart {
        payload_object_id: Some([1; 32]),
        payload_object_bytes: 5,
        ..part(0, CrossProfileStream::Base)
    };
    assert!(base_with_payload.encode().is_err());
    let empty_event = BarrierPart {
        encoded_event_object: Vec::new(),
        ..part(0, CrossProfileStream::Base)
    };
    assert!(empty_event.encode().is_err());
    let out_of_range = BarrierPart {
        part_index: 3,
        ..part(0, CrossProfileStream::Base)
    };
    assert!(out_of_range.encode().is_err());

    let receipt = receipt();
    let head = BarrierHead::Receipt(receipt.clone());
    let encoded = head.encode()?;
    assert_eq!(BarrierHead::decode(&encoded)?, head);
    assert_eq!(head.identity().mutation_id, [7; 16]);
    assert_eq!(validate_state_body(BARRIER_ROW_KIND, &encoded), Ok(()));
    let wrong_retention = BarrierReceipt {
        retain_until: 1,
        ..receipt.clone()
    };
    assert!(wrong_retention.encode().is_err());
    let mut disordered = receipt.clone();
    disordered.entries.swap(0, 1);
    assert!(disordered.encode().is_err());
    let mut short = receipt;
    short.entries.pop();
    assert!(short.encode().is_err());
    let one_part = BarrierIdentity {
        part_count: 1,
        ..identity()
    };
    assert!(BarrierStage::empty(one_part).encode().is_err());
    Ok(())
}

#[test]
fn every_kind_validates_its_own_bodies_and_refuses_others() -> TestResult {
    let bodies: Vec<(u16, Vec<u8>)> = vec![
        (ROUTE_ROW_KIND, route_row().encode()?),
        (
            CLAIM_ROW_KIND,
            ClaimRow::Lock {
                conversation_id: CONVERSATION,
                binding_id: [1; 32],
                incarnation: 0,
            }
            .encode()?,
        ),
        (
            SEQUENCER_ROW_KIND,
            SequencerRow::Proof {
                role: ProofRole::Ack,
                object_id: [1; 32],
                slot: 0,
            }
            .encode()?,
        ),
        (
            DIRECTORY_ROW_KIND,
            DirectoryRow::Capability {
                generation: 0,
                capability_id: [1; 32],
                roster_id: [2; 32],
                object_id: [3; 32],
            }
            .encode()?,
        ),
        (
            PACKAGE_ROW_KIND,
            PackageRow::Package {
                account_digest: ACCOUNT,
                device_id: DEVICE,
                suite: 1,
                expires_at: 1,
                object_id: [1; 32],
                state: PackageState::Published,
                claimed_by: None,
            }
            .encode()?,
        ),
        (
            ATTACH_ROW_KIND,
            AttachRow {
                session_generation: 1,
                challenge: None,
            }
            .encode()?,
        ),
        (
            MAILBOX_ROW_KIND,
            MailboxRow::Ack {
                object_id: [1; 32],
                acknowledged_at: 1,
                retain_until: 2,
            }
            .encode()?,
        ),
        (
            REPLAY_ROW_KIND,
            ReplayRow {
                request_id: [1; 16],
                request_object_id: [2; 32],
                result_object_id: None,
                response_object_ids: Vec::new(),
                security_mutation: false,
                retain_until: 1,
            }
            .encode()?,
        ),
        (
            DELIVERY_ROW_KIND,
            DeliveryRow::WitnessedCursor {
                generation: 1,
                next_sequence: 1,
                acked_sequence: 0,
                acked_event_id: [0; 16],
                barrier_open: false,
            }
            .encode()?,
        ),
        (KEYSET_ROW_KIND, keyset().encode()?),
        (
            BARRIER_ROW_KIND,
            BarrierHead::Stage(BarrierStage::empty(identity())).encode()?,
        ),
    ];
    for (kind, body) in &bodies {
        assert_eq!(validate_state_body(*kind, body), Ok(()), "kind {kind}");
        let value = PersistentRecordValue::new(
            TableId::E2eeState,
            *kind,
            1,
            1,
            None,
            Vec::new(),
            body.clone(),
        );
        assert!(value.is_ok(), "the persistent envelope accepts kind {kind}");
        for (other, _) in &bodies {
            if other != kind {
                assert!(
                    validate_state_body(*other, body).is_err(),
                    "kind {kind} body under kind {other}"
                );
            }
        }
        assert!(
            PersistentRecordValue::new(
                TableId::E2eeObject,
                1,
                1,
                1,
                None,
                Vec::new(),
                body.clone()
            )
            .is_err(),
            "kind {kind} body is not an object"
        );
    }
    let first_body = bodies
        .first()
        .map(|(_, body)| body.clone())
        .ok_or("bodies")?;
    assert!(validate_state_body(13, &first_body).is_err());
    assert!(validate_state_body(RECOVERY_GATE_KIND, &first_body).is_err());
    Ok(())
}

struct Engine {
    _directory: crate::TestDirectory,
    owner: StorageOwner,
    limits: StorageEngineLimits,
    logical_bytes: u64,
    backup_bytes: u64,
}

fn engine() -> Result<Engine, Box<dyn Error>> {
    let directory = crate::TestDirectory::create()?;
    let tuple = StateDirectory::probe(directory.path())?;
    let qualification = crate::signed_test_qualification(tuple)?;
    let limits = StorageEngineLimits {
        redb_cache_bytes: 8 * 1_024 * 1_024,
        fixed_reserve_bytes: 64 * 1_024 * 1_024,
        reserve_percent: 1,
        database_max_bytes: 1_073_741_824,
        backup_max_bytes: 2_147_483_648,
        integrity_checkpoint_manifests: 100_000,
    };
    let network = NetworkId::from_bytes([13; 32]);
    let server = ServerId::from_bytes([14; 16]);
    let login_key = LoginIndexKey::from_bytes([15; 32]);
    let key_state = LoginIndexKeyState::stable(1, login_key.key_id(network))?;
    let initial = InitialStorageRecord::new(
        TableId::LoginIndexKeyState,
        StoredKey::new(agenc_ircd_storage::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
        1,
        key_state.encode()?,
    )?;
    let state_directory = StateDirectory::open(directory.path(), &[qualification])?;
    let outcome = initialize_storage(StorageInitializationConfig {
        state_directory,
        header_tbs: DatabaseHeaderTbs::new(
            network,
            server,
            ServerIncarnation::from_bytes([16; 16]),
            DatabaseId::from_bytes([17; 16]),
            1,
            SCHEMA_GENERATION,
            RecoveryEpoch::from_bytes([18; 16]),
        )?,
        storage_master_key: StorageMasterKey::from_bytes([19; 32]),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes([20; 32]),
        mode: StorageInitializationMode::Live,
        initial_records: vec![initial],
        account_service_response_count: 0,
        state_generation: 0,
        predecessor_guard_hash: StorageDigest::from_bytes([0; 32]),
        limits,
    })?;
    let StorageInitializationOutcome::Complete {
        logical_database_bytes,
        backup_stream_bytes,
        ..
    } = outcome
    else {
        return Err(std::io::Error::other("initialization was indeterminate").into());
    };
    let state_directory = StateDirectory::open(directory.path(), &[qualification])?;
    let owner = StorageOwner::start(StorageOpenConfig {
        expected_network_id: network,
        expected_server_id: server,
        state_directory,
        storage_master_key: StorageMasterKey::from_bytes([19; 32]),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes([20; 32]),
        login_index_key: LoginIndexKey::from_bytes([15; 32]),
        previous_login_index_key: None,
        limits,
    })?;
    Ok(Engine {
        _directory: directory,
        owner,
        limits,
        logical_bytes: logical_database_bytes,
        backup_bytes: backup_stream_bytes,
    })
}

fn put(
    table: TableId,
    key: StoredKey,
    kind: u16,
    body: Vec<u8>,
) -> Result<RecordMutation, Box<dyn Error>> {
    let value = PersistentRecordValue::new(table, kind, 1, 1, None, Vec::new(), body)?.encode()?;
    Ok(RecordMutation::put(table, key, 1, None, value)?)
}

#[test]
fn an_e2ee_mutation_commits_object_state_replay_outbox_and_barrier_atomically() -> TestResult {
    let engine = engine()?;
    let object = ObjectRow::new(object_bytes(IrcWireObjectKind::FederationEvent, 300)?)?;
    let object_key = object.key()?;
    let route_key = RouteRow::key(&CONVERSATION)?;
    let replay_key_bytes = ReplayRow::key(&replay_key())?;
    use agenc_ircd_storage::e2ee_records::delivery_recovery::{
        Acknowledgement, DeliveryRecoveryRow, ScopedOutbox, ScopedOutboxFields, fixture_body,
    };
    let DeliveryRecoveryRow::Owner(owner) = DeliveryRecoveryRow::decode(&fixture_body(7)?)? else {
        return Err("delivery scope fixture".into());
    };
    let outbox = ScopedOutbox::new(ScopedOutboxFields {
        scope: *owner.scope(),
        generation: 1,
        sequence: 1,
        event_id: [1; 16],
        event_object_id: *agenc_ircd_e2ee::ObjectId::compute(&object.bytes).as_bytes(),
        event_bytes: u32::try_from(object.bytes.len())?,
        payload_object_id: None,
        payload_bytes: 0,
        acknowledgement: Acknowledgement::Unacknowledged,
        cross_profile: None,
    })?;
    let outbox_key = outbox.key()?;
    let head_key = identity().head_key()?;
    let part_key = identity().part_key(0)?;
    let mutations = vec![
        put(
            TableId::E2eeObject,
            object_key.clone(),
            OBJECT_RECORD_KIND,
            object.encode()?,
        )?,
        put(
            TableId::E2eeState,
            route_key.clone(),
            ROUTE_ROW_KIND,
            route_row().encode()?,
        )?,
        put(
            TableId::E2eeState,
            replay_key_bytes.clone(),
            REPLAY_ROW_KIND,
            ReplayRow {
                request_id: [1; 16],
                request_object_id: [2; 32],
                result_object_id: Some([3; 32]),
                response_object_ids: Vec::new(),
                security_mutation: true,
                retain_until: 1,
            }
            .encode()?,
        )?,
        put(
            TableId::E2eeState,
            outbox_key.clone(),
            agenc_ircd_storage::e2ee_records::DELIVERY_RECOVERY_ROW_KIND,
            DeliveryRecoveryRow::Outbox(outbox).encode()?,
        )?,
        put(
            TableId::E2eeState,
            head_key.clone(),
            BARRIER_ROW_KIND,
            BarrierHead::Stage(BarrierStage::empty(identity())).encode()?,
        )?,
        put(
            TableId::E2eeState,
            part_key.clone(),
            BARRIER_ROW_KIND,
            part(0, CrossProfileStream::Base).encode()?,
        )?,
    ];
    let batch = StorageMutationBatch::new(
        StorageMutationHead {
            transaction_id: TransactionId::from_bytes([21; 16]),
            expected_storage_commit_sequence: 0,
            expected_state_generation: 0,
            resulting_state_generation: 1,
            state_advancing_plan_count: 1,
            expected_account_service_response_count: 0,
            resulting_account_service_response_count: 0,
        },
        1,
        StorageAccountingLimits {
            current_logical_database_bytes: engine.logical_bytes,
            current_backup_stream_bytes: engine.backup_bytes,
            database_max_bytes: engine.limits.database_max_bytes,
            backup_max_bytes: engine.limits.backup_max_bytes,
        },
        mutations,
    )?;
    let port = engine.owner.port();
    let CommitOutcome::Committed(receipt) = port.try_commit(batch)?.wait()? else {
        return Err(std::io::Error::other("commit did not complete").into());
    };
    assert_eq!(receipt.storage_commit_sequence, 1);
    for (table, key) in [
        (TableId::E2eeObject, object_key),
        (TableId::E2eeState, route_key),
        (TableId::E2eeState, replay_key_bytes),
        (TableId::E2eeState, outbox_key),
        (TableId::E2eeState, head_key),
        (TableId::E2eeState, part_key),
    ] {
        let read = port.try_read(ReadPlan::exact(table, key.clone()))?.wait()?;
        assert_eq!(read.records.len(), 1, "{:?}", key.as_bytes());
    }
    let page = port
        .try_read(agenc_ircd_storage::e2ee_records::prefix_range(
            prefix::BARRIER_PART,
            8,
        )?)?
        .wait()?;
    assert_eq!(page.records.len(), 1);
    let recovered = engine.owner.recovered_state();
    assert_eq!(
        recovered.table_record_count(TableId::E2eeObject),
        0,
        "counts refresh on reopen"
    );
    Ok(())
}

#[test]
fn every_state_key_splits_back_into_its_parts() -> Result<(), Box<dyn Error>> {
    let digest = [7; 32];
    let device = [8; 16];
    let other = [9; 32];
    assert_eq!(
        SequencerRow::parse_candidate_key(&SequencerRow::candidate_key(&digest, 5)?)?,
        (digest, 5)
    );
    for role in [ProofRole::Approval, ProofRole::Ack, ProofRole::Vote] {
        let parts = SequencerRow::parse_proof_key(&SequencerRow::proof_key(
            role, &digest, &other, &digest, &device,
        )?)?;
        assert_eq!(parts.role, role);
        assert_eq!(parts.conversation_id, digest);
        assert_eq!(parts.subject_id, other);
        assert_eq!(parts.root_fingerprint, digest);
        assert_eq!(parts.device_id, device);
    }
    assert_eq!(
        DirectoryRow::parse_identity_key(&DirectoryRow::identity_key(&digest)?)?,
        digest
    );
    assert_eq!(
        DirectoryRow::parse_roster_key(&DirectoryRow::roster_key(&digest)?)?,
        digest
    );
    assert_eq!(
        DirectoryRow::parse_capability_key(&DirectoryRow::capability_key(&digest, &device)?)?,
        (digest, device)
    );
    assert_eq!(
        DirectoryRow::parse_binding_lock_key(&DirectoryRow::binding_lock_key(&digest, &other, 3)?)?,
        (digest, other, 3)
    );
    assert_eq!(
        PackageRow::parse_package_key(&PackageRow::package_key(&[1, 2, 3])?)?,
        vec![1, 2, 3]
    );
    assert_eq!(
        PackageRow::parse_claim_key(&PackageRow::claim_key(&digest, &device)?)?,
        (digest, device)
    );
    assert_eq!(
        AttachRow::parse_key(&AttachRow::key(&digest, &device)?)?,
        (digest, device)
    );
    assert_eq!(
        MailboxRow::parse_token_key(&MailboxRow::token_key(&other)?)?,
        other
    );
    assert_eq!(
        MailboxRow::parse_ack_key(&MailboxRow::ack_key(&digest, &device, &other)?)?,
        (digest, device, other)
    );
    assert_eq!(
        DeliveryRow::parse_cursor_key(&DeliveryRow::cursor_key(&device)?)?,
        device
    );
    assert_eq!(
        ClaimRow::parse_lock_key(&ClaimRow::lock_key(&other)?)?,
        other
    );
    assert_eq!(
        ClaimRow::parse_reservation_key(&ClaimRow::reservation_key(&device)?)?,
        device
    );
    // A key of another family never parses as this one.
    assert!(DirectoryRow::parse_roster_key(&DirectoryRow::identity_key(&digest)?).is_err());
    assert!(SequencerRow::parse_proof_key(&SequencerRow::candidate_key(&digest, 1)?).is_err());
    Ok(())
}

#[test]
fn object_owner_rows_round_trip_and_refuse_inconsistent_accounts() -> Result<(), Box<dyn Error>> {
    use agenc_ircd_storage::e2ee_records::{OWNER_ROW_KIND, ObjectOwnerRow, RetentionClass};
    let owned = ObjectOwnerRow {
        kind: IrcWireObjectKind::SequencerRecord.value(),
        size: 4_096,
        retention: RetentionClass::SecurityProof,
        accepted_at: 1_700_000_000,
        reconstructed: false,
        retired_at: None,
    };
    let retired = ObjectOwnerRow {
        retention: RetentionClass::Ordinary,
        retired_at: Some(1_700_000_500),
        ..owned
    };
    let floor = ObjectOwnerRow {
        reconstructed: true,
        retention: RetentionClass::Mailbox,
        ..owned
    };
    for row in [&owned, &retired, &floor] {
        let encoded = row.encode().map_err(|e| format!("encode {row:?}: {e:?}"))?;
        assert_eq!(
            &ObjectOwnerRow::decode(&encoded).map_err(|e| format!("decode {row:?}: {e:?}"))?,
            row
        );
        assert!(validate_state_body(OWNER_ROW_KIND, &encoded).is_ok());
    }
    assert_eq!(owned.object_kind()?, IrcWireObjectKind::SequencerRecord);
    for class in RetentionClass::ALL {
        assert_eq!(RetentionClass::from_wire(class.wire())?, class);
    }
    assert!(RetentionClass::from_wire(0).is_err());
    assert!(RetentionClass::from_wire(5).is_err());
    let key = ObjectOwnerRow::key(&[3; 32]).map_err(|e| format!("key: {e:?}"))?;
    assert!(ObjectOwnerRow::matches_key(&key));
    assert_eq!(
        ObjectOwnerRow::parse_key(&key).map_err(|e| format!("parse: {e:?}"))?,
        [3; 32]
    );
    assert!(!ObjectOwnerRow::matches_key(&object_key(&[3; 32])?));
    assert!(ObjectOwnerRow::range().is_ok());
    // No trusted age, an empty or oversized object, a retirement before
    // acceptance, and an unknown kind are all refused before encoding.
    for bad in [
        ObjectOwnerRow {
            accepted_at: 0,
            ..owned
        },
        ObjectOwnerRow { size: 0, ..owned },
        ObjectOwnerRow {
            size: u64::MAX,
            ..owned
        },
        ObjectOwnerRow {
            retired_at: Some(1),
            ..owned
        },
        ObjectOwnerRow {
            kind: 0xFF,
            ..owned
        },
    ] {
        assert!(bad.encode().is_err(), "{bad:?}");
    }
    let mut encoded = owned.encode()?;
    encoded.push(0);
    assert!(ObjectOwnerRow::decode(&encoded).is_err(), "trailing bytes");
    assert!(validate_state_body(OWNER_ROW_KIND, &[]).is_err());
    Ok(())
}

#[test]
fn object_expiry_progress_rows_round_trip_and_refuse_inconsistent_totals() -> TestResult {
    use agenc_ircd_storage::e2ee_records::{EXPIRY_PROGRESS_ROW_KIND, ObjectExpiryProgressRow};
    let fresh = ObjectExpiryProgressRow::default();
    let resumed = ObjectExpiryProgressRow {
        cursor: Some([9; 32]),
        passes: 12,
        deleted_objects: 40,
        deleted_bytes: 1_048_576,
    };
    let wrapped = ObjectExpiryProgressRow {
        cursor: None,
        ..resumed
    };
    for row in [&fresh, &resumed, &wrapped] {
        let encoded = row.encode().map_err(|e| format!("encode {row:?}: {e:?}"))?;
        assert_eq!(
            &ObjectExpiryProgressRow::decode(&encoded)
                .map_err(|e| format!("decode {row:?}: {e:?}"))?,
            row
        );
        assert!(validate_state_body(EXPIRY_PROGRESS_ROW_KIND, &encoded).is_ok());
    }
    let key = ObjectExpiryProgressRow::key()?;
    assert_eq!(key.as_bytes(), prefix::OBJECT_EXPIRY);
    assert!(ObjectExpiryProgressRow::matches_key(&key));
    assert!(!ObjectExpiryProgressRow::matches_key(&object_key(
        &[9; 32]
    )?));
    assert_eq!(record_kind_for_key(&key)?, EXPIRY_PROGRESS_ROW_KIND);
    check_state_key(&key, EXPIRY_PROGRESS_ROW_KIND)?;
    // A deletion always charges at least one byte, so a count without
    // bytes, bytes without a count, or fewer bytes than objects is forged.
    for bad in [
        ObjectExpiryProgressRow {
            deleted_bytes: 0,
            ..resumed
        },
        ObjectExpiryProgressRow {
            deleted_objects: 0,
            ..resumed
        },
        ObjectExpiryProgressRow {
            deleted_objects: 40,
            deleted_bytes: 39,
            ..resumed
        },
    ] {
        assert!(bad.encode().is_err(), "{bad:?}");
    }
    let mut encoded = resumed.encode()?;
    encoded.push(0);
    assert!(
        ObjectExpiryProgressRow::decode(&encoded).is_err(),
        "trailing bytes"
    );
    assert!(validate_state_body(EXPIRY_PROGRESS_ROW_KIND, &[]).is_err());
    // The progress row never decodes as an ownership account, nor the
    // reverse: the kind wrapper binds each body to its own arm.
    let owner = agenc_ircd_storage::e2ee_records::ObjectOwnerRow {
        kind: IrcWireObjectKind::SequencerRecord.value(),
        size: 32,
        retention: agenc_ircd_storage::e2ee_records::RetentionClass::Ordinary,
        accepted_at: 1,
        reconstructed: false,
        retired_at: None,
    }
    .encode()?;
    assert!(ObjectExpiryProgressRow::decode(&owner).is_err());
    assert!(
        validate_state_body(
            agenc_ircd_storage::e2ee_records::OWNER_ROW_KIND,
            &resumed.encode()?
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn recovery_rows_round_trip_and_refuse_inconsistent_outcomes() -> Result<(), Box<dyn Error>> {
    use agenc_ircd_storage::e2ee_records::{
        RECOVERY_RECORD_ROW_KIND, RECOVERY_SUBMISSION_ROW_KIND, RecoveryOutcome, RecoveryRecordRow,
        RecoverySubmissionRow,
    };
    let open = RecoverySubmissionRow {
        account_id: [b'a'; 24],
        device_id: [7; 16],
        element_kind: 1,
        element_object_kind: IrcWireObjectKind::SequencerRecord.value(),
        element_object_id: [2; 32],
        route_sequence: 3,
        predecessor_record_id: [4; 32],
        accepted_at: 1_700_000_000,
        submission_object_id: [5; 32],
        element_retained: false,
        outcome: RecoveryOutcome::Open,
    };
    let extended = RecoverySubmissionRow {
        element_retained: true,
        outcome: RecoveryOutcome::Extended { record_id: [6; 32] },
        ..open
    };
    let closed = RecoverySubmissionRow {
        element_kind: 2,
        element_object_kind: IrcWireObjectKind::CloseAuthorization.value(),
        element_retained: true,
        outcome: RecoveryOutcome::Closed { close_id: [8; 32] },
        ..open
    };
    let conflict = RecoverySubmissionRow {
        element_retained: true,
        outcome: RecoveryOutcome::Conflict {
            installed_record_id: [6; 32],
            conflicting_record_id: [9; 32],
        },
        ..open
    };
    let referenced = RecoverySubmissionRow {
        element_kind: 3,
        element_object_kind: IrcWireObjectKind::Policy.value(),
        element_retained: true,
        outcome: RecoveryOutcome::Referenced,
        ..open
    };
    for row in [&open, &extended, &closed, &conflict, &referenced] {
        let encoded = row.encode().map_err(|e| format!("encode {row:?}: {e:?}"))?;
        assert_eq!(
            &RecoverySubmissionRow::decode(&encoded)
                .map_err(|e| format!("decode {row:?}: {e:?}"))?,
            row
        );
        assert!(validate_state_body(RECOVERY_SUBMISSION_ROW_KIND, &encoded).is_ok());
    }
    // A complete outcome without its retained element, a zero element or
    // acceptance time, and an element kind outside the closed set are refused.
    for broken in [
        RecoverySubmissionRow {
            element_retained: false,
            ..extended
        },
        RecoverySubmissionRow {
            element_object_id: [0; 32],
            ..open
        },
        RecoverySubmissionRow {
            accepted_at: 0,
            ..open
        },
        RecoverySubmissionRow {
            element_kind: 4,
            ..open
        },
    ] {
        assert!(broken.encode().is_err(), "{broken:?}");
    }
    let key = RecoverySubmissionRow::key(&[1; 32], &[2; 32]).map_err(|e| format!("key: {e:?}"))?;
    assert_eq!(RecoverySubmissionRow::parse_key(&key)?, ([1; 32], [2; 32]));
    assert!(key.as_bytes().starts_with(b"recovery-submission/v1/"));
    assert!(RecoverySubmissionRow::range().is_ok());

    let record = RecoveryRecordRow {
        record_id: [1; 32],
        record_object_id: [2; 32],
        predecessor_record_id: [3; 32],
        record_kind: 2,
        submission_id: [4; 32],
    };
    let encoded = record.encode()?;
    assert_eq!(RecoveryRecordRow::decode(&encoded)?, record);
    assert!(validate_state_body(RECOVERY_RECORD_ROW_KIND, &encoded).is_ok());
    assert!(
        RecoveryRecordRow {
            record_kind: 7,
            ..record
        }
        .encode()
        .is_err()
    );
    assert!(
        RecoveryRecordRow {
            record_id: [0; 32],
            ..record
        }
        .encode()
        .is_err()
    );
    let key = RecoveryRecordRow::key(&[1; 32], 9).map_err(|e| format!("key: {e:?}"))?;
    assert_eq!(RecoveryRecordRow::parse_key(&key)?, ([1; 32], 9));
    assert!(key.as_bytes().starts_with(b"recovery-record/v1/"));
    // The submission body cannot be replayed as a record row or vice versa.
    assert!(validate_state_body(RECOVERY_RECORD_ROW_KIND, &open.encode()?).is_err());
    assert!(validate_state_body(RECOVERY_SUBMISSION_ROW_KIND, &record.encode()?).is_err());
    Ok(())
}

#[test]
fn recovery_rows_refuse_zero_kinds_and_identifiers() -> TestResult {
    use agenc_ircd_storage::e2ee_records::{
        RecoveryOutcome, RecoveryRecordRow, RecoverySubmissionRow,
    };
    let submission = RecoverySubmissionRow {
        account_id: [b'a'; 24],
        device_id: [1; 16],
        element_kind: 1,
        element_object_kind: 2,
        element_object_id: [3; 32],
        route_sequence: 4,
        predecessor_record_id: [5; 32],
        accepted_at: 6,
        submission_object_id: [7; 32],
        element_retained: true,
        outcome: RecoveryOutcome::Open,
    };
    assert!(submission.encode().is_ok());
    let mut zero_kind = submission;
    zero_kind.element_object_kind = 0;
    assert!(zero_kind.encode().is_err());
    let mut zero_object = submission;
    zero_object.submission_object_id = [0; 32];
    assert!(zero_object.encode().is_err());
    let record = RecoveryRecordRow {
        record_id: [1; 32],
        record_object_id: [0; 32],
        predecessor_record_id: [2; 32],
        record_kind: 1,
        submission_id: [3; 32],
    };
    assert!(record.encode().is_err());
    Ok(())
}

fn marker(phase: SnapshotPhase, staged: u32) -> SnapshotMarkerRow {
    SnapshotMarkerRow {
        token: [7; 32],
        state_generation: 9,
        delivery_generation: 3,
        total_entries: 65,
        digest: [8; 32],
        staged_entries: staged,
        staged_bytes: 4_096,
        phase,
        opened_at: 120_000,
        switched_through: None,
    }
}

/// The edge's pending snapshot rows: a route body under the generation's
/// key, and the marker with its exact cut and progress (companion 12.5).
#[test]
fn pending_snapshot_rows_round_trip_under_their_generation() -> TestResult {
    let route = RouteRow {
        route_state: vec![1, 2, 3],
        lifecycle: RouteLifecycle::Active,
        binding_id: [4; 32],
        lock_id: [5; 32],
        accepted_state_id: [6; 32],
        sequencer_head_id: [7; 32],
        route_sequence: 8,
        close_id: None,
        predecessor_close_id: None,
        recovery_gate: false,
        stored_bytes: 3,
        sequencer_credential_id: Some([9; 32]),
        blocked_credential_id: None,
    };
    let key = PendingRouteRow::key(3, &[11; 32])?;
    assert!(key.as_bytes().starts_with(b"pending-route/v1/"));
    assert_eq!(PendingRouteRow::parse_key(&key)?, (3, [11; 32]));
    assert_eq!(record_kind_for_key(&key)?, PENDING_ROUTE_ROW_KIND);
    let body = PendingRouteRow::encode_route(&route)?;
    assert_eq!(validate_state_body(PENDING_ROUTE_ROW_KIND, &body), Ok(()));
    assert!(validate_state_body(ROUTE_ROW_KIND, &body).is_err());
    assert_eq!(PendingRouteRow::decode(&body)?, route);
    assert!(PendingRouteRow::decode(&route.encode()?).is_err());
    // Generations sort before conversations, so one generation's rows are
    // one contiguous key range.
    let later = PendingRouteRow::key(4, &[0; 32])?;
    assert!(key.as_bytes() < later.as_bytes());
    assert!(PendingRouteRow::range(3).is_ok());

    let key = SnapshotMarkerRow::key(&[2; 16])?;
    assert!(key.as_bytes().starts_with(b"edge-snapshot/v1/"));
    assert_eq!(SnapshotMarkerRow::parse_key(&key)?, [2; 16]);
    assert_eq!(record_kind_for_key(&key)?, SNAPSHOT_MARKER_ROW_KIND);
    for row in [
        marker(SnapshotPhase::Staging, 32),
        marker(SnapshotPhase::Ready, 65),
        SnapshotMarkerRow {
            switched_through: Some([12; 32]),
            ..marker(SnapshotPhase::Active, 65)
        },
    ] {
        let body = row.encode()?;
        assert_eq!(validate_state_body(SNAPSHOT_MARKER_ROW_KIND, &body), Ok(()));
        assert_eq!(SnapshotMarkerRow::decode(&body)?, row);
    }
    // Staged entries never exceed the total; READY and ACTIVE need every
    // entry; only ACTIVE carries a migration cursor.
    assert!(marker(SnapshotPhase::Staging, 66).encode().is_err());
    assert!(marker(SnapshotPhase::Ready, 64).encode().is_err());
    assert!(
        SnapshotMarkerRow {
            switched_through: Some([12; 32]),
            ..marker(SnapshotPhase::Ready, 65)
        }
        .encode()
        .is_err()
    );
    // The phase is a u16 before the opened-at second, the switched flag
    // and the switched conversation.
    let mut forged = marker(SnapshotPhase::Ready, 65).encode()?;
    let phase_low = forged.len() - 32 - 2 - 8 - 1;
    *forged.get_mut(phase_low).ok_or("phase byte")? = 9;
    assert!(SnapshotMarkerRow::decode(&forged).is_err());
    // A cleared cursor flag with a nonzero cursor does not decode either.
    let mut unflagged = SnapshotMarkerRow {
        switched_through: Some([12; 32]),
        ..marker(SnapshotPhase::Active, 65)
    }
    .encode()?;
    let flag_low = unflagged.len() - 32 - 1;
    *unflagged.get_mut(flag_low).ok_or("flag byte")? = 0;
    assert!(SnapshotMarkerRow::decode(&unflagged).is_err());
    Ok(())
}

/// The canonical body inside one wrapped e2ee state row.
fn inner_of(kind: u16, wrapped: &[u8]) -> Result<Vec<u8>, StorageError> {
    Ok(
        ProtocolRecordBody::decode(TableId::E2eeState, kind, wrapped)?
            .canonical_object()
            .to_vec(),
    )
}

fn rewrap(kind: u16, inner: Vec<u8>) -> Result<Vec<u8>, StorageError> {
    ProtocolRecordBody::new(TableId::E2eeState, kind, 1, inner)?.encode()
}

#[test]
fn crafted_bodies_cannot_smuggle_empty_or_inconsistent_fields_past_the_decoders() -> TestResult {
    // A route row whose route state is empty: the length word is zeroed and
    // the three state bytes removed.
    let inner = inner_of(ROUTE_ROW_KIND, &route_row().encode()?)?;
    let mut empty_route = inner.get(..2).ok_or("version")?.to_vec();
    empty_route.extend_from_slice(&[0; 4]);
    empty_route.extend_from_slice(inner.get(9..).ok_or("tail")?);
    assert_eq!(
        RouteRow::decode(&rewrap(ROUTE_ROW_KIND, empty_route)?).err(),
        Some(StorageError::InvalidEncoding)
    );
    // A key set row that names no credential.
    let inner = inner_of(KEYSET_ROW_KIND, &keyset().encode()?)?;
    let mut no_credentials = inner.get(..42).ok_or("generation and digest")?.to_vec();
    no_credentials.extend_from_slice(&[0; 2]);
    assert_eq!(
        KeySetRow::decode(&rewrap(KEYSET_ROW_KIND, no_credentials)?).err(),
        Some(StorageError::InvalidEncoding)
    );
    // A sequencer history row that carries a retirement generation while
    // claiming it was never retired.
    let history = SequencerHistoryRow {
        key_generation: 1,
        public_key: [1; 32],
        interval: (1, 10),
        previous_key_id: [0; 32],
        introduced_set: 2,
        retired_set: Some(6),
        released: false,
    };
    let wrapped = history.encode()?;
    assert_eq!(SequencerHistoryRow::decode(&wrapped)?, history);
    let mut inner = inner_of(SEQUENCER_HISTORY_ROW_KIND, &wrapped)?;
    for byte in inner.get_mut(98..100).ok_or("retired flag")? {
        *byte = 0;
    }
    assert_eq!(
        SequencerHistoryRow::decode(&rewrap(SEQUENCER_HISTORY_ROW_KIND, inner)?).err(),
        Some(StorageError::InvalidEncoding)
    );
    Ok(())
}
