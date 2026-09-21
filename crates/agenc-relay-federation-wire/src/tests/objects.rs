#![forbid(unsafe_code)]

//! Typed object views: identities, hello, headers, origins, and mappings.

use std::error::Error;

use agenc_relay_types::{
    AccountId, AccountRandomId, ConnectionId, ENUM_REGISTRY, EventId, FederationEventKind,
    FederationOpcode, FederationProjectionKind, FederationResultKind, FederationRole, NetworkId,
    OriginId, RecoveryEpoch, RequestId, ServerId, ServerIncarnation, SessionId, UserId,
};

use super::*;
use crate::codec::{DecodeBudget, SchemaObject, WireValue};
use crate::schema::schema_by_name;

type TestResult = Result<(), Box<dyn Error>>;

fn budget() -> DecodeBudget {
    DecodeBudget::new(1 << 20, 10_000)
}

fn sample_tbs() -> HelloTbs {
    HelloTbs {
        network_id: NetworkId::from_bytes([1; 32]),
        sender_server_id: ServerId::from_bytes([2; 16]),
        expected_peer_server_id: ServerId::from_bytes([3; 16]),
        server_incarnation: ServerIncarnation::from_bytes([4; 16]),
        recovery_epoch: RecoveryEpoch::from_bytes([5; 16]),
        role: FederationRole::Edge,
        hello_nonce: [6; 32],
        profile_hash: crate::BASE_FEDERATION_PROFILE_SHA256,
        tls_exporter: [7; 32],
    }
}

fn sample_replay_key() -> ReplayKey {
    ReplayKey {
        home_server_id: ServerId::from_bytes([2; 16]),
        server_incarnation: ServerIncarnation::from_bytes([4; 16]),
        origin_id: OriginId::from_bytes([8; 16]),
        origin_generation: 1,
        operation_sequence: 7,
    }
}

fn session_close_operation() -> Result<SchemaObject, CodecError> {
    SchemaObject::new(
        "operation.session_close",
        vec![WireValue::Opaque(vec![9; 16]), WireValue::Unsigned(1)],
    )
}

fn committed_result() -> Result<SchemaObject, CodecError> {
    SchemaObject::new("result.committed", vec![WireValue::Unsigned(42)])
}

fn account_id() -> AccountId {
    AccountId::from_random(AccountRandomId::from_bytes([11; 16]))
}

#[test]
fn object_identity_is_domain_separated_sha256() {
    let first = federation_object_id(b"abc");
    let second = federation_object_id(b"abd");
    assert_ne!(first, second);
    let direct = {
        use sha2::{Digest as _, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(FEDERATION_OBJECT_HASH_LABEL);
        hasher.update(b"abc");
        FederationHash32::from_bytes(hasher.finalize().into())
    };
    assert_eq!(first, direct);
}

#[test]
fn hello_signature_input_and_exporter_context_have_exact_shapes() -> TestResult {
    let input = hello_signature_input(b"tbs")?;
    assert!(input.starts_with(FEDERATION_HELLO_SIGNATURE_LABEL));
    assert!(input.ends_with(b"tbs"));
    assert_eq!(input.len(), FEDERATION_HELLO_SIGNATURE_LABEL.len() + 3);

    let network = NetworkId::from_bytes([1; 32]);
    let low = ServerId::from_bytes([2; 16]);
    let high = ServerId::from_bytes([3; 16]);
    let context = exporter_context(&network, &high, &low);
    assert_eq!(context, exporter_context(&network, &low, &high));
    let mut expected = [1_u8; 64];
    expected
        .iter_mut()
        .skip(32)
        .take(16)
        .for_each(|byte| *byte = 2);
    expected.iter_mut().skip(48).for_each(|byte| *byte = 3);
    assert_eq!(context, expected);
    Ok(())
}

#[test]
fn snapshot_digest_binds_epoch_generations_count_and_order() -> TestResult {
    let epoch = RecoveryEpoch::from_bytes([5; 16]);
    let first_id = FederationHash32::from_bytes([1; 32]);
    let second_id = FederationHash32::from_bytes([2; 32]);
    let ids = [first_id, second_id];
    let baseline = snapshot_digest(&epoch, 3, 9, &ids)?;
    assert_ne!(baseline, snapshot_digest(&epoch, 4, 9, &ids)?);
    assert_ne!(baseline, snapshot_digest(&epoch, 3, 10, &ids)?);
    assert_ne!(
        baseline,
        snapshot_digest(&RecoveryEpoch::from_bytes([6; 16]), 3, 9, &ids)?
    );
    let reversed = [second_id, first_id];
    assert_ne!(baseline, snapshot_digest(&epoch, 3, 9, &reversed)?);
    assert_ne!(baseline, snapshot_digest(&epoch, 3, 9, &[first_id])?);
    assert_eq!(baseline, snapshot_digest(&epoch, 3, 9, &ids)?);
    let empty = snapshot_digest(&epoch, 0, 0, &[])?;
    assert_ne!(empty, baseline);
    Ok(())
}

#[test]
fn snapshot_digest_rejects_more_than_the_entry_ceiling() {
    let epoch = RecoveryEpoch::from_bytes([5; 16]);
    let too_many = vec![FederationHash32::from_bytes([0; 32]); 1_000_001];
    assert_eq!(
        snapshot_digest(&epoch, 1, 1, &too_many).err(),
        Some(CodecError::LengthAboveMaximum)
    );
}

#[test]
fn hello_round_trips_through_objects_and_exact_bytes() -> TestResult {
    let hello = FederationHello {
        tbs: sample_tbs(),
        signature: [8; 64],
    };
    let encoded = hello.encode()?;
    assert_eq!(encoded.len(), 260);
    assert_eq!(FederationHello::decode(encoded.as_slice())?, hello);
    assert_eq!(HelloTbs::from_object(&hello.tbs.to_object()?)?, hello.tbs);
    assert_eq!(hello.tbs.encode()?.len(), 196);
    let truncated = encoded.as_slice().get(..259).ok_or("truncate")?;
    assert_eq!(
        FederationHello::decode(truncated).err(),
        Some(CodecError::LengthAboveMaximum)
    );
    let mut wrong_role = encoded.as_slice().to_vec();
    *wrong_role.get_mut(98).ok_or("role high byte")? = 0;
    *wrong_role.get_mut(99).ok_or("role low byte")? = 9;
    assert_eq!(
        FederationHello::decode(&wrong_role).err(),
        Some(CodecError::UnknownDiscriminant)
    );
    Ok(())
}

#[test]
fn typed_readers_reject_other_schemas() -> TestResult {
    let operation = session_close_operation()?;
    assert_eq!(
        HelloTbs::from_object(&operation).err(),
        Some(CodecError::SchemaMismatch)
    );
    assert_eq!(
        FederationHello::from_object(&operation).err(),
        Some(CodecError::SchemaMismatch)
    );
    assert_eq!(
        RequestHeader::from_object(&operation).err(),
        Some(CodecError::SchemaMismatch)
    );
    assert_eq!(
        ResultHeader::from_object(&operation).err(),
        Some(CodecError::SchemaMismatch)
    );
    assert_eq!(
        EventHeader::from_object(&operation).err(),
        Some(CodecError::SchemaMismatch)
    );
    assert_eq!(
        OriginRecord::from_object(&operation).err(),
        Some(CodecError::SchemaMismatch)
    );
    assert_eq!(
        ProjectionEntryHeader::from_object(&operation).err(),
        Some(CodecError::SchemaMismatch)
    );
    Ok(())
}

#[test]
fn replay_key_serializes_in_field_order() {
    let bytes = sample_replay_key().to_bytes();
    let mut expected = Vec::new();
    expected.extend_from_slice(&[2; 16]);
    expected.extend_from_slice(&[4; 16]);
    expected.extend_from_slice(&[8; 16]);
    expected.extend_from_slice(&1_u64.to_be_bytes());
    expected.extend_from_slice(&7_u64.to_be_bytes());
    assert_eq!(bytes.as_slice(), expected.as_slice());
}

#[test]
fn request_header_builds_and_reads_its_operation() -> TestResult {
    let header = RequestHeader {
        network_id: NetworkId::from_bytes([1; 32]),
        replay_key: sample_replay_key(),
        request_id: RequestId::from_bytes([10; 16]),
        opcode: FederationOpcode::SessionClose,
    };
    let operation = session_close_operation()?;
    let request = header.build(&operation)?;
    assert_eq!(RequestHeader::from_object(&request)?, header);
    let decoded = decode_request_operation(&request, &mut budget())?;
    assert_eq!(
        decoded.encode_canonical()?.as_slice(),
        operation.encode_canonical()?.as_slice()
    );
    let wrong = RequestHeader {
        opcode: FederationOpcode::Join,
        ..header
    };
    assert_eq!(
        wrong.build(&operation).err(),
        Some(CodecError::SchemaMismatch)
    );
    Ok(())
}

#[test]
fn result_header_builds_and_reads_arms_and_completion() -> TestResult {
    let header = ResultHeader {
        network_id: NetworkId::from_bytes([1; 32]),
        replay_key: sample_replay_key(),
        request_id: RequestId::from_bytes([10; 16]),
        request_object_id: FederationHash32::from_bytes([12; 32]),
        completion_event_id: Some(EventId::from_bytes([13; 16])),
        result_kind: FederationResultKind::Committed,
    };
    let result = header.build(&committed_result()?, Vec::new())?;
    assert_eq!(ResultHeader::from_object(&result)?, header);
    let arm = decode_result_arm(&result, &mut budget())?;
    assert_eq!(arm.schema().name, "result.committed");

    let no_content = SchemaObject::new("result.no_content", Vec::new())?;
    let mismatched = ResultHeader {
        result_kind: FederationResultKind::NoContent,
        ..header
    };
    assert_eq!(
        mismatched.build(&committed_result()?, Vec::new()).err(),
        Some(CodecError::SchemaMismatch)
    );
    assert_eq!(
        mismatched.build(&no_content, Vec::new()).err(),
        Some(CodecError::CrossReference)
    );
    let without_completion = ResultHeader {
        completion_event_id: None,
        ..mismatched
    };
    let built = without_completion.build(&no_content, Vec::new())?;
    assert_eq!(ResultHeader::from_object(&built)?.completion_event_id, None);
    let stray_reply = committed_result()?;
    assert_eq!(
        header.build(&committed_result()?, vec![stray_reply]).err(),
        Some(CodecError::SchemaMismatch)
    );
    Ok(())
}

#[test]
fn event_header_round_trips_correlation_and_refuses_barriers() -> TestResult {
    let correlation = RequestCorrelation {
        replay_key: sample_replay_key(),
        request_id: RequestId::from_bytes([10; 16]),
    };
    let header = EventHeader {
        network_id: NetworkId::from_bytes([1; 32]),
        target_server_id: ServerId::from_bytes([2; 16]),
        projection_generation: 3,
        coordinator_state_generation: 42,
        delivery_sequence: 5,
        event_id: EventId::from_bytes([13; 16]),
        event_kind: FederationEventKind::RequestCompleted,
        correlation: Some(correlation),
        cross_profile: None,
    };
    let completed = SchemaObject::new("event.request_completed", vec![WireValue::Unsigned(42)])?;
    let event = header.build(&completed)?;
    assert_eq!(EventHeader::from_object(&event)?, header);
    assert_eq!(
        decode_event_arm(&event, &mut budget())?.schema().name,
        "event.request_completed"
    );

    let hidden = SchemaObject::new(
        "event.channel_hidden",
        vec![WireValue::Opaque(vec![14; 16]), WireValue::Unsigned(2)],
    )?;
    let plain = EventHeader {
        event_kind: FederationEventKind::ChannelHidden,
        correlation: None,
        ..header
    };
    let built = plain.build(&hidden)?;
    assert_eq!(EventHeader::from_object(&built)?.correlation, None);
    assert_eq!(
        header.build(&hidden).err(),
        Some(CodecError::SchemaMismatch)
    );

    let part = CrossProfilePart {
        mutation_id: [1; 16],
        part_index: 0,
        part_count: 2,
    };
    let barrier = EventHeader {
        cross_profile: Some(part),
        ..plain
    };
    let built = barrier.build(&hidden)?;
    assert_eq!(EventHeader::from_object(&built)?.cross_profile, Some(part));
    for (part_index, part_count) in [(0, 1), (2, 2), (0, 2_049)] {
        let invalid = EventHeader {
            cross_profile: Some(CrossProfilePart {
                mutation_id: [1; 16],
                part_index,
                part_count,
            }),
            ..plain
        };
        assert_eq!(
            invalid.build(&hidden).err(),
            Some(CodecError::CrossReference)
        );
    }

    let raw_barrier = SchemaObject::new(
        "FederationEvent",
        vec![
            WireValue::Unsigned(1),
            WireValue::Opaque(vec![1; 32]),
            WireValue::Opaque(vec![2; 16]),
            WireValue::Unsigned(3),
            WireValue::Unsigned(42),
            WireValue::Unsigned(5),
            WireValue::Opaque(vec![13; 16]),
            WireValue::Unsigned(5),
            WireValue::Opaque(hidden.encode_canonical()?.as_slice().to_vec()),
            WireValue::Opaque(vec![9; 16]),
            WireValue::Unsigned(1),
            WireValue::Unsigned(2),
            WireValue::Opaque(Vec::new()),
            WireValue::Opaque(Vec::new()),
            WireValue::Opaque(Vec::new()),
            WireValue::Unsigned(0),
            WireValue::Unsigned(0),
            WireValue::Opaque(Vec::new()),
        ],
    )?;
    let parsed = EventHeader::from_object(&raw_barrier)?;
    assert_eq!(
        parsed.cross_profile,
        Some(CrossProfilePart {
            mutation_id: [9; 16],
            part_index: 1,
            part_count: 2,
        })
    );
    Ok(())
}

#[test]
fn origin_records_round_trip_every_principal_shape() -> TestResult {
    let guest = OriginRecord {
        network_id: NetworkId::from_bytes([1; 32]),
        home_server_id: ServerId::from_bytes([2; 16]),
        server_incarnation: ServerIncarnation::from_bytes([4; 16]),
        origin_id: OriginId::from_bytes([8; 16]),
        generation: 0,
        previous_origin_object_id: [0; 32],
        connection_id: ConnectionId::from_bytes([15; 16]),
        session: None,
        account: None,
        connection_nonce: [16; 32],
    };
    assert_eq!(OriginRecord::from_object(&guest.to_object()?)?, guest);

    let registered = OriginRecord {
        generation: 1,
        previous_origin_object_id: [17; 32],
        session: Some(OriginSession {
            session_id: SessionId::from_bytes([18; 16]),
            user_id: UserId::from_bytes([19; 16]),
        }),
        ..guest
    };
    assert_eq!(
        OriginRecord::from_object(&registered.to_object()?)?,
        registered
    );

    let authenticated = OriginRecord {
        generation: 2,
        account: Some(OriginAccount {
            account_id: account_id(),
            account_session_generation: 3,
        }),
        ..registered
    };
    assert_eq!(
        OriginRecord::from_object(&authenticated.to_object()?)?,
        authenticated
    );

    let account_without_session = OriginRecord {
        session: None,
        ..authenticated
    };
    assert_eq!(
        account_without_session.to_object().err(),
        Some(CodecError::CrossReference)
    );
    Ok(())
}

#[test]
fn projection_entries_build_read_and_key_every_kind() -> TestResult {
    let header = ProjectionEntryHeader {
        network_id: NetworkId::from_bytes([1; 32]),
        target_server_id: ServerId::from_bytes([2; 16]),
        projection_generation: 3,
        projection_kind: FederationProjectionKind::Account,
    };
    let account = SchemaObject::new(
        "FederationAccountProjection",
        vec![
            WireValue::Opaque(account_id().to_text().into_bytes()),
            WireValue::Unsigned(1),
            WireValue::Unsigned(1),
        ],
    )?;
    let entry = header.build(&account)?;
    assert_eq!(ProjectionEntryHeader::from_object(&entry)?, header);
    let (arm, key) = decode_projection_arm(&entry, &mut budget())?;
    assert_eq!(arm.schema().name, "FederationAccountProjection");
    assert_eq!(key.kind(), 7);
    assert_eq!(key.primary(), account_id().to_text().as_bytes());
    assert_eq!(key.channel_id(), None);
    assert_eq!(key.invite_id(), None);
    let leading: [u8; 16] = account_id()
        .to_text()
        .as_bytes()
        .get(..16)
        .ok_or("account prefix")?
        .try_into()?;
    assert_eq!(key.leading_id(), Some(leading));

    let membership = SchemaObject::new(
        "FederationMembership",
        vec![
            WireValue::Opaque(vec![20; 16]),
            WireValue::Opaque(vec![21; 16]),
            WireValue::Unsigned(0),
            WireValue::Unsigned(1),
            WireValue::Unsigned(1),
        ],
    )?;
    let key = ProjectionPrimaryKey::of(FederationProjectionKind::Membership, &membership)?;
    assert_eq!(key.kind(), 4);
    assert_eq!(key.channel_id().map(|id| *id.as_bytes()), Some([20; 16]));
    assert_eq!(key.invite_id(), None);
    assert_eq!(
        ProjectionPrimaryKey::of(FederationProjectionKind::Session, &membership).err(),
        Some(CodecError::SchemaMismatch)
    );
    assert_eq!(
        header.build(&membership).err(),
        Some(CodecError::SchemaMismatch)
    );

    let invite = SchemaObject::new(
        "FederationInviteProjection",
        vec![
            WireValue::Opaque(vec![22; 16]),
            WireValue::Opaque(vec![23; 16]),
            WireValue::Structure(SchemaObject::new(
                "PrincipalRef",
                vec![WireValue::Unsigned(2), WireValue::Opaque(vec![24; 16])],
            )?),
            WireValue::Opaque(vec![25; 16]),
            WireValue::Unsigned(1),
            WireValue::Unsigned(1),
        ],
    )?;
    let key = ProjectionPrimaryKey::of(FederationProjectionKind::Invite, &invite)?;
    assert_eq!(key.invite_id().map(|id| *id.as_bytes()), Some([23; 16]));
    assert!(key < ProjectionPrimaryKey::of(FederationProjectionKind::Account, &account)?);
    Ok(())
}

#[test]
fn schema_name_tables_match_the_frozen_registry() -> TestResult {
    let opcodes = ENUM_REGISTRY
        .iter()
        .find(|descriptor| descriptor.name == "FederationOpcode")
        .ok_or("missing opcode registry")?;
    for entry in opcodes.entries {
        let opcode = FederationOpcode::from_wire(entry.value)?;
        let expected = format!("operation.{}", entry.name);
        assert_eq!(operation_schema_name(opcode), expected);
        assert!(schema_by_name(&expected).is_some());
        assert_eq!(opcode_registry_name(opcode)?, entry.name);
        let mapping = result_mapping_value(opcode)?;
        let mut kinds: Vec<&str> = vec!["failed"];
        for kind in permitted_success_results(opcode) {
            kinds.push(result_kind_registry_name(*kind)?);
        }
        assert_eq!(mapping, kinds.join(","));
        assert!(result_kind_permitted(opcode, FederationResultKind::Failed));
    }
    let results = ENUM_REGISTRY
        .iter()
        .find(|descriptor| descriptor.name == "FederationResultKind")
        .ok_or("missing result registry")?;
    for entry in results.entries {
        let kind = FederationResultKind::from_wire(entry.value)?;
        assert_eq!(result_schema_name(kind), format!("result.{}", entry.name));
    }
    let events = ENUM_REGISTRY
        .iter()
        .find(|descriptor| descriptor.name == "FederationEventKind")
        .ok_or("missing event registry")?;
    for entry in events.entries {
        let kind = FederationEventKind::from_wire(entry.value)?;
        assert_eq!(event_schema_name(kind), format!("event.{}", entry.name));
    }
    for kind in [
        FederationProjectionKind::Session,
        FederationProjectionKind::ChannelDetail,
        FederationProjectionKind::Membership,
        FederationProjectionKind::Invite,
        FederationProjectionKind::Account,
    ] {
        assert!(schema_by_name(projection_schema_name(kind)).is_some());
    }
    assert!(!result_kind_permitted(
        FederationOpcode::Join,
        FederationResultKind::ReplyPage
    ));
    Ok(())
}

#[test]
fn barrier_parts_build_for_every_index_below_the_count() -> TestResult {
    let hidden = SchemaObject::new(
        "event.channel_hidden",
        vec![WireValue::Opaque(vec![14; 16]), WireValue::Unsigned(2)],
    )?;
    let header = EventHeader {
        network_id: NetworkId::from_bytes([1; 32]),
        target_server_id: ServerId::from_bytes([2; 16]),
        projection_generation: 1,
        coordinator_state_generation: 3,
        delivery_sequence: 4,
        event_id: EventId::from_bytes([5; 16]),
        event_kind: FederationEventKind::ChannelHidden,
        correlation: None,
        cross_profile: None,
    };
    for (part_index, part_count) in [(0, 3), (1, 3), (2, 3), (2_047, 2_048)] {
        let part = CrossProfilePart {
            mutation_id: [7; 16],
            part_index,
            part_count,
        };
        let built = EventHeader {
            cross_profile: Some(part),
            ..header
        }
        .build(&hidden)?;
        assert_eq!(EventHeader::from_object(&built)?.cross_profile, Some(part));
    }
    Ok(())
}
