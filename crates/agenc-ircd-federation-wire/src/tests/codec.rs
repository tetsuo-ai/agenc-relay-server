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
fn enum_nested_projection_and_optional_fixed_guards_fail_closed() {
    assert_eq!(validate_enum("missing", 1), Err(CodecError::UnknownSchema));
    assert_eq!(
        validate_enum("ModeDirection", u64::from(u16::MAX) + 1),
        Err(CodecError::IntegerOutOfRange)
    );
    assert_eq!(
        validate_enum("ModeDirection", 99),
        Err(CodecError::UnknownDiscriminant)
    );

    let nested = SchemaObject {
        schema: schema("result.no_content"),
        fields: Vec::new(),
    };
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
                value: Box::new(nested),
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
fn iterative_machines_reject_impossible_or_overdeep_states() {
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
        deliver_completed_value(&mut Vec::new(), WireValue::Unsigned(0)),
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
            WireValue::Unsigned(0)
        ),
        Err(CodecError::TypeMismatch)
    );

    let object = SchemaObject {
        schema: empty_schema,
        fields: Vec::new(),
    };
    assert_eq!(
        push_object_for_walk(&mut Vec::new(), &object, MAX_STATIC_SCHEMA_DEPTH + 1),
        Err(CodecError::SchemaDepth)
    );

    let mut decoder = Decoder {
        input: &[],
        cursor: usize::MAX,
    };
    assert_eq!(decoder.read(1).err(), Some(CodecError::Overflow));
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
