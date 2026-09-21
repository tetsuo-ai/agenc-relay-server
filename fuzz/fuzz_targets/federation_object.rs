#![no_main]
#![forbid(unsafe_code)]

use agenc_relay_federation_wire::{
    CanonicalEncode as _, DecodeBudget, EventHeader, FederationHello, OriginRecord,
    ProjectionEntryHeader, RequestHeader, ResultHeader, SCHEMA_REGISTRY, SchemaObject,
    decode_event_arm, decode_projection_arm, decode_request_operation, decode_result_arm,
    federation_object_id,
};
use libfuzzer_sys::fuzz_target;

const BUDGET_BYTES: usize = 4 * 1024 * 1024;
const BUDGET_VALUES: usize = 1_000_000;

/// Every accepted object re-encodes to exactly the accepted bytes and has one
/// stable identity; typed readers never panic on a schema-valid object.
fn check_schema(name: &str, encoded: &[u8]) {
    let mut budget = DecodeBudget::new(BUDGET_BYTES, BUDGET_VALUES);
    let Ok(object) = SchemaObject::decode_exact(name, encoded, &mut budget) else {
        return;
    };
    let reencoded = object
        .encode_canonical()
        .expect("accepted object must re-encode");
    assert_eq!(
        reencoded.as_slice(),
        encoded,
        "accepted bytes did not re-encode canonically"
    );
    assert_eq!(
        federation_object_id(encoded),
        federation_object_id(reencoded.as_slice())
    );
    let mut arm_budget = DecodeBudget::new(BUDGET_BYTES, BUDGET_VALUES);
    match name {
        "FederationHello" => {
            let hello = FederationHello::from_object(&object).expect("typed hello");
            assert_eq!(FederationHello::decode(encoded), Ok(hello));
        }
        "FederationRequest" => {
            let _ = RequestHeader::from_object(&object).expect("typed request header");
            let _ = decode_request_operation(&object, &mut arm_budget);
        }
        "FederationResult" => {
            let _ = ResultHeader::from_object(&object).expect("typed result header");
            let _ = decode_result_arm(&object, &mut arm_budget);
        }
        "FederationEvent" => {
            let _ = EventHeader::from_object(&object).expect("typed event header");
            let _ = decode_event_arm(&object, &mut arm_budget);
        }
        "FederationOrigin" => {
            let record = OriginRecord::from_object(&object).expect("typed origin");
            let rebuilt = record.to_object().expect("typed origin rebuild");
            assert_eq!(
                rebuilt
                    .encode_canonical()
                    .expect("rebuild encode")
                    .as_slice(),
                encoded
            );
        }
        "FederationProjectionEntry" => {
            let _ = ProjectionEntryHeader::from_object(&object).expect("typed entry header");
            let _ = decode_projection_arm(&object, &mut arm_budget);
        }
        _ => {}
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, encoded)) = data.split_first() else {
        return;
    };
    let schema = &SCHEMA_REGISTRY[usize::from(selector) % SCHEMA_REGISTRY.len()];
    check_schema(schema.name, encoded);
});
