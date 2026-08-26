#![forbid(unsafe_code)]

//! Direct tests for private codec guards that public schemas cannot bypass.

use super::*;
use crate::schema::SchemaDescriptor;

const MISSING_SCHEMA: SchemaDescriptor = SchemaDescriptor {
    name: "missing-test-schema",
    fields: &[],
};

fn schema(name: &str) -> &'static SchemaDescriptor {
    schema_by_name(name).unwrap_or(&MISSING_SCHEMA)
}

#[test]
fn primitive_validation_rejects_each_width_and_shape_mismatch() {
    let cases = [
        (FieldKind::Uint8, WireValue::Unsigned(256)),
        (FieldKind::Uint16, WireValue::Unsigned(65_536)),
        (FieldKind::Uint24, WireValue::Unsigned(0x0100_0000)),
        (
            FieldKind::Uint32,
            WireValue::Unsigned(u64::from(u32::MAX) + 1),
        ),
        (
            FieldKind::FixedOpaque { length: 2 },
            WireValue::Opaque(vec![0]),
        ),
    ];
    for (kind, value) in cases {
        assert_eq!(validate_value(kind, &value), Err(CodecError::TypeMismatch));
    }
    assert_eq!(
        validate_value(FieldKind::Uint64, &WireValue::Opaque(Vec::new())),
        Err(CodecError::TypeMismatch)
    );
    assert_eq!(
        validate_bounds(0, 1, 2),
        Err(CodecError::LengthBelowMinimum)
    );
    assert_eq!(
        validate_bounds(3, 1, 2),
        Err(CodecError::LengthAboveMaximum)
    );
    assert_eq!(validate_bounds(1, 1, 2), Ok(()));
}

#[test]
fn enum_nested_projection_and_optional_fixed_guards_fail_closed() -> Result<(), CodecError> {
    assert_eq!(validate_enum("missing", 1), Err(CodecError::UnknownSchema));
    assert_eq!(
        validate_enum("ModeDirection", u64::from(u16::MAX) + 1),
        Err(CodecError::IntegerOutOfRange)
    );
    assert_eq!(
        validate_enum("ModeDirection", 99),
        Err(CodecError::UnknownDiscriminant)
    );

    let nested = SchemaObject::raw_for_test(schema("result.no_content"), Vec::new());
    assert_eq!(
        validate_nested_schema("result.committed", &nested),
        Err(CodecError::SchemaMismatch)
    );
    assert_eq!(
        validate_value(
            FieldKind::ProjectionUnion {
                discriminant: 1,
                schema: "result.no_content",
            },
            &WireValue::ProjectionUnion {
                discriminant: 2,
                value: nested,
            },
        ),
        Err(CodecError::TypeMismatch)
    );

    assert_eq!(
        validate_optional_fixed_field("missing", "field", &WireValue::Opaque(Vec::new())),
        Err(CodecError::UnknownSchema)
    );
    assert_eq!(
        validate_optional_fixed_field(
            "FederationOrigin",
            "missing",
            &WireValue::Opaque(Vec::new())
        ),
        Err(CodecError::SchemaMismatch)
    );
    assert_eq!(
        validate_optional_fixed_field(
            "FederationOrigin",
            "session_id",
            &WireValue::Opaque(vec![0])
        ),
        Err(CodecError::CrossReference)
    );
    assert_eq!(
        validate_optional_fixed_field(
            "FederationOrigin",
            "session_id",
            &WireValue::Opaque(Vec::new())
        ),
        Ok(())
    );
    assert_eq!(
        validate_optional_fixed_field(
            "FederationOrigin",
            "session_id",
            &WireValue::Opaque(vec![0; 16])
        ),
        Ok(())
    );
    Ok(())
}

#[test]
fn explicit_depth_limit_rejects_before_input_or_allocation() {
    let mut budget = DecodeBudget::new(0, 0);
    assert_eq!(
        new_schema_frame(
            schema("result.no_content"),
            MAX_STATIC_SCHEMA_DEPTH + 1,
            SchemaCompletion::Root,
            &mut budget
        )
        .err(),
        Some(CodecError::SchemaDepth)
    );
    assert_eq!(budget.remaining_bytes(), 0);
    assert_eq!(budget.remaining_values(), 0);
}

#[test]
fn iterative_machines_reject_impossible_or_overdeep_states() -> Result<(), CodecError> {
    let empty_schema = schema("result.no_content");
    let spare_frame = SchemaFrame {
        schema: empty_schema,
        fields: Vec::new(),
        next_field: 0,
        depth: 0,
        completion: SchemaCompletion::Structure,
    };
    let root_frame = SchemaFrame {
        schema: empty_schema,
        fields: Vec::new(),
        next_field: 0,
        depth: 0,
        completion: SchemaCompletion::Root,
    };
    assert_eq!(
        complete_schema_frame(root_frame, &[DecodeFrame::Schema(spare_frame)]).err(),
        Some(CodecError::Overflow)
    );

    assert_eq!(
        deliver_completed_value(
            &mut Vec::new(),
            CompletedValue::Wire(WireValue::Unsigned(0))
        ),
        Err(CodecError::Overflow)
    );
    let vector = VectorFrame {
        schema: empty_schema,
        values: Vec::new(),
        remaining: 0,
        element_depth: 0,
    };
    assert_eq!(
        deliver_completed_value(
            &mut vec![DecodeFrame::Vector(vector)],
            CompletedValue::Wire(WireValue::Unsigned(0))
        ),
        Err(CodecError::TypeMismatch)
    );

    let object = SchemaObject::raw_for_test(empty_schema, Vec::new());
    assert_eq!(
        push_object_for_walk(&mut Vec::new(), &object, MAX_STATIC_SCHEMA_DEPTH + 1),
        Err(CodecError::SchemaDepth)
    );

    let mut decoder = Decoder {
        input: &[],
        cursor: usize::MAX,
    };
    assert_eq!(decoder.read(1).err(), Some(CodecError::Overflow));
    Ok(())
}

#[test]
fn iterative_decode_rejects_unknown_schema_and_exhausted_value_budget() {
    let mut budget = DecodeBudget::new(0, 0);
    assert_eq!(
        decode_one_without_embedded("missing", &[], &mut budget, 0).err(),
        Some(CodecError::UnknownSchema)
    );
    assert_eq!(
        new_schema_frame(
            schema("FederationNickname"),
            0,
            SchemaCompletion::Root,
            &mut budget
        )
        .err(),
        Some(CodecError::AllocationBudgetExceeded)
    );
}

#[test]
fn decoded_nested_values_are_directly_owned_and_canonical() -> Result<(), CodecError> {
    let channel_name = SchemaObject::new(
        "FederationChannelName",
        vec![WireValue::Opaque(b"#room".to_vec())],
    )?;
    let join_target = SchemaObject::new(
        "FederationJoinTarget",
        vec![
            WireValue::Structure(channel_name),
            WireValue::Opaque(Vec::new()),
        ],
    )?;
    let encoded_join_target = join_target.encode_canonical()?;
    let mut budget = DecodeBudget::new(4_096, 64);
    let decoded_join_target = SchemaObject::decode_exact(
        "FederationJoinTarget",
        encoded_join_target.as_slice(),
        &mut budget,
    )?;
    assert_eq!(
        decoded_join_target.encode_canonical()?.as_slice(),
        encoded_join_target.as_slice()
    );
    let Some(WireValue::Structure(channel_name)) = decoded_join_target.fields().first() else {
        return Err(CodecError::TypeMismatch);
    };
    assert_eq!(channel_name.schema().name, "FederationChannelName");

    let account_projection = SchemaObject::new(
        "FederationAccountProjection",
        vec![
            WireValue::Opaque(b"a_AAECAwQFBgcICQoLDA0ODw".to_vec()),
            WireValue::Unsigned(1),
            WireValue::Unsigned(1),
        ],
    )?;
    let account_event = SchemaObject::new(
        "event.account_state_changed",
        vec![WireValue::ProjectionUnion {
            discriminant: 7,
            value: account_projection,
        }],
    )?;
    let encoded_account_event = account_event.encode_canonical()?;
    let mut budget = DecodeBudget::new(4_096, 64);
    let decoded_account_event = SchemaObject::decode_exact(
        "event.account_state_changed",
        encoded_account_event.as_slice(),
        &mut budget,
    )?;
    assert_eq!(
        decoded_account_event.encode_canonical()?.as_slice(),
        encoded_account_event.as_slice()
    );
    let Some(WireValue::ProjectionUnion {
        discriminant,
        value: projection,
    }) = decoded_account_event.fields().first()
    else {
        return Err(CodecError::TypeMismatch);
    };
    if *discriminant != 7 {
        return Err(CodecError::UnknownDiscriminant);
    }
    assert_eq!(projection.schema().name, "FederationAccountProjection");
    Ok(())
}

#[test]
fn secret_storage_zeroization_covers_complete_vector_capacity() -> Result<(), CodecError> {
    let mut opaque = Vec::with_capacity(8);
    opaque.extend_from_slice(b"secret");
    let mut value = WireValue::Opaque(opaque);
    value.zeroize_opaque_storage();
    let WireValue::Opaque(bytes) = &value else {
        return Err(CodecError::TypeMismatch);
    };
    assert_eq!(bytes.len(), 8);
    assert!(bytes.iter().all(|byte| *byte == 0));

    let mut encoded = Vec::with_capacity(8);
    encoded.extend_from_slice(b"secret");
    let mut canonical = CanonicalBytes { bytes: encoded };
    canonical.zeroize_storage();
    assert_eq!(canonical.bytes.len(), 8);
    assert!(canonical.bytes.iter().all(|byte| *byte == 0));
    Ok(())
}

#[test]
fn object_storage_capacity_is_bounded_and_exactly_accounted() -> Result<(), CodecError> {
    let mut channel_bytes = Vec::with_capacity(8);
    channel_bytes.extend_from_slice(b"#room");
    let channel_fields = vec![WireValue::Opaque(channel_bytes)];
    let channel = SchemaObject::new("FederationChannelName", channel_fields)?;
    let channel_backing = std::mem::size_of::<WireValue>() + 8;
    assert_eq!(channel.backing_capacity_bytes(), channel_backing);

    let join_key = Vec::with_capacity(12);
    let target_fields = vec![WireValue::Structure(channel), WireValue::Opaque(join_key)];
    let target = SchemaObject::new("FederationJoinTarget", target_fields)?;
    let target_backing = 2 * std::mem::size_of::<WireValue>() + channel_backing + 12;
    assert_eq!(target.backing_capacity_bytes(), target_backing);

    let mut targets = Vec::with_capacity(3);
    targets.push(target);
    let operation_fields = vec![
        WireValue::Opaque(vec![0; 16]),
        WireValue::Unsigned(1),
        WireValue::Vector(targets),
    ];
    let operation = SchemaObject::new("operation.join", operation_fields)?;
    let operation_backing = 3 * std::mem::size_of::<WireValue>()
        + 16
        + 3 * std::mem::size_of::<SchemaObject>()
        + target_backing;
    assert_eq!(operation.backing_capacity_bytes(), operation_backing);

    let fields_with_spare_capacity = Vec::<WireValue>::with_capacity(1);
    assert_eq!(
        SchemaObject::new("result.no_content", fields_with_spare_capacity).err(),
        Some(CodecError::LengthAboveMaximum)
    );

    let mut fixed_with_spare_capacity = Vec::with_capacity(17);
    fixed_with_spare_capacity.resize(16, 0);
    assert_eq!(
        SchemaObject::new(
            "FederationChannelId",
            vec![WireValue::Opaque(fixed_with_spare_capacity)]
        )
        .err(),
        Some(CodecError::LengthAboveMaximum)
    );

    let mut opaque_over_maximum = Vec::with_capacity(65);
    opaque_over_maximum.extend_from_slice(b"#x");
    assert_eq!(
        SchemaObject::new(
            "FederationChannelName",
            vec![WireValue::Opaque(opaque_over_maximum)]
        )
        .err(),
        Some(CodecError::LengthAboveMaximum)
    );

    let channel = SchemaObject::new(
        "FederationChannelName",
        vec![WireValue::Opaque(b"#x".to_vec())],
    )?;
    let target = SchemaObject::new(
        "FederationJoinTarget",
        vec![WireValue::Structure(channel), WireValue::Opaque(Vec::new())],
    )?;
    let mut over_capacity_targets = Vec::with_capacity(21);
    over_capacity_targets.push(target);
    assert_eq!(
        SchemaObject::new(
            "operation.join",
            vec![
                WireValue::Opaque(vec![0; 16]),
                WireValue::Unsigned(1),
                WireValue::Vector(over_capacity_targets),
            ]
        )
        .err(),
        Some(CodecError::LengthAboveMaximum)
    );
    Ok(())
}

#[test]
fn codec_errors_render_closed_messages() {
    let cases = [
        (CodecError::UnknownSchema, "unknown federation schema"),
        (CodecError::FieldCount, "federation field count mismatch"),
        (CodecError::TypeMismatch, "federation field type mismatch"),
        (CodecError::UnexpectedEof, "truncated federation object"),
        (
            CodecError::TrailingBytes,
            "trailing federation object bytes",
        ),
        (
            CodecError::LengthBelowMinimum,
            "federation vector is below its minimum",
        ),
        (
            CodecError::LengthAboveMaximum,
            "federation vector exceeds its maximum",
        ),
        (
            CodecError::IntegerOutOfRange,
            "federation integer is outside its wire width",
        ),
        (
            CodecError::UnknownDiscriminant,
            "unknown federation enum discriminant",
        ),
        (
            CodecError::AllocationBudgetExceeded,
            "federation decode allocation budget exhausted",
        ),
        (
            CodecError::Overflow,
            "federation codec calculation overflowed",
        ),
        (
            CodecError::AllocationFailed,
            "federation codec allocation failed",
        ),
        (
            CodecError::SchemaMismatch,
            "nested federation schema mismatch",
        ),
        (
            CodecError::SchemaDepth,
            "federation schema nesting limit exceeded",
        ),
        (
            CodecError::DuplicateValue,
            "duplicate canonical federation value",
        ),
        (
            CodecError::NonCanonicalOrder,
            "federation values are not canonically ordered",
        ),
        (
            CodecError::CrossReference,
            "federation field presence or cross-reference mismatch",
        ),
        (
            CodecError::NonzeroPadding,
            "federation padding is not all zero",
        ),
    ];
    for (error, message) in cases {
        assert_eq!(error.to_string(), message);
    }
}

#[test]
fn decoded_and_measured_shape_guards_reject_extra_fields() -> Result<(), CodecError> {
    let empty_schema = schema("result.no_content");
    let extra_field = [WireValue::Unsigned(0)];

    assert_eq!(
        validate_fields(empty_schema, &extra_field),
        Err(CodecError::FieldCount)
    );
    assert_eq!(
        validate_decoded_fields(empty_schema, &extra_field),
        Err(CodecError::FieldCount)
    );
    assert_eq!(
        measured_fields_len(empty_schema, &extra_field),
        Err(CodecError::FieldCount)
    );

    assert_eq!(
        validate_value(FieldKind::Uint8, &WireValue::Unsigned(u64::from(u8::MAX))),
        Ok(())
    );

    Ok(())
}

#[test]
fn projection_union_guards_reject_wrong_discriminants() -> Result<(), CodecError> {
    let object_schema = schema("result.no_content");
    let field_kind = FieldKind::ProjectionUnion {
        discriminant: 1,
        schema: object_schema.name,
    };
    let wrong_storage_value = WireValue::ProjectionUnion {
        discriminant: 2,
        value: SchemaObject::raw_for_test(object_schema, Vec::new()),
    };

    assert_eq!(
        validate_value_storage_capacity(field_kind, &wrong_storage_value),
        Err(CodecError::TypeMismatch)
    );

    let wrong_decoded_value = WireValue::ProjectionUnion {
        discriminant: 2,
        value: SchemaObject::raw_for_test(object_schema, Vec::new()),
    };
    assert_eq!(
        validate_decoded_value(field_kind, &wrong_decoded_value),
        Err(CodecError::TypeMismatch)
    );

    let valid_value = WireValue::ProjectionUnion {
        discriminant: 1,
        value: SchemaObject::raw_for_test(object_schema, Vec::new()),
    };
    validate_value_storage_capacity(field_kind, &valid_value)?;
    validate_decoded_value(field_kind, &valid_value)?;

    Ok(())
}

#[test]
fn decode_entry_points_reject_oversize_trailing_and_unknown_projection() -> Result<(), CodecError> {
    let object_limit = base_object_limit()?;
    let oversized = vec![0_u8; object_limit + 1];
    let mut oversized_budget = DecodeBudget::new(object_limit * 2, 64);
    assert_eq!(
        decode_one_without_embedded("result.no_content", &oversized, &mut oversized_budget, 0,)
            .err(),
        Some(CodecError::LengthAboveMaximum)
    );

    let mut trailing_budget = DecodeBudget::new(64, 64);
    assert_eq!(
        decode_one_without_embedded("result.no_content", &[0], &mut trailing_budget, 0,).err(),
        Some(CodecError::TrailingBytes)
    );

    let encoded_discriminant = 2_u16.to_be_bytes();
    let mut decoder = Decoder::new(&encoded_discriminant);
    let mut projection_budget = DecodeBudget::new(64, 64);
    let projection_kind = FieldKind::ProjectionUnion {
        discriminant: 1,
        schema: "result.no_content",
    };
    assert_eq!(
        begin_decode_value(projection_kind, &mut decoder, &mut projection_budget, 0,).err(),
        Some(CodecError::UnknownDiscriminant)
    );

    Ok(())
}

#[test]
fn empty_vectors_complete_without_descending() -> Result<(), CodecError> {
    let mut decode_budget = DecodeBudget::new(0, 0);
    let mut decode_frames = Vec::new();
    let progress = process_vector_frame(
        VectorFrame {
            schema: schema("result.no_content"),
            values: Vec::new(),
            remaining: 0,
            element_depth: 0,
        },
        &mut decode_budget,
        &mut decode_frames,
    )?;
    let DecodeProgress::Value(CompletedValue::Wire(WireValue::Vector(ref values))) = progress
    else {
        return Err(CodecError::TypeMismatch);
    };
    assert!(values.is_empty());
    assert!(decode_frames.is_empty());

    let empty_vector = WireValue::Vector(Vec::new());
    let mut walk_frames = Vec::new();
    push_nested_value_for_walk(&mut walk_frames, &empty_vector, 0)?;
    assert!(walk_frames.is_empty());

    Ok(())
}
