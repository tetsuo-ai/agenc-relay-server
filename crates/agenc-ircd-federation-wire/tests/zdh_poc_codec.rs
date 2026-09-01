//! zeroday-hunter PoC battery: federation codec findings (campaign ircd-2026-09-01).
//!
//! ZDH-D1: five distinct zero-field schemas share the empty canonical encoding —
//!         no schema identity in canonical bytes (signature-confusion primitive
//!         for any future transcript hash over bare canonical bytes).
//! ZDH-D2: FALSIFIED during verification. `operation.part` carries
//!         FederationChannelId (16-byte instance IDs), not channel names, so
//!         raw-byte dedup is correct there. The test now pins the real
//!         invariant: exact duplicate part targets are rejected.

#![forbid(unsafe_code)]

use std::error::Error;

use agenc_ircd_federation_wire::{CanonicalEncode, DecodeBudget, SchemaObject, WireValue};

fn channel_object(value: &str) -> Result<SchemaObject, Box<dyn Error>> {
    Ok(SchemaObject::new(
        "FederationChannelName",
        vec![WireValue::Opaque(value.as_bytes().to_vec())],
    )?)
}

#[test]
fn zdh_d1_zero_field_schemas_share_the_empty_canonical_encoding() -> Result<(), Box<dyn Error>> {
    let schemas = [
        "directory.links",
        "directory.monitor_clear",
        "directory.monitor_list",
        "directory.monitor_status",
        "result.no_content",
    ];
    for schema in schemas {
        let mut budget = DecodeBudget::new(262_144, 1_000_000);
        let object = SchemaObject::decode_exact(schema, b"", &mut budget)
            .map_err(|e| format!("decode {schema} failed: {e:?}"))?;
        let encoded = object.encode_canonical()?;
        assert!(
            encoded.as_slice().is_empty(),
            "ZDH-D1: {schema} must encode to empty canonical bytes"
        );
    }
    Ok(())
}

#[test]
fn zdh_d2_part_rejects_exact_duplicate_channel_ids() -> Result<(), Box<dyn Error>> {
    // operation.part channels are 16-byte FederationChannelId instance IDs.
    let channel_id_object = |value: [u8; 16]| -> Result<SchemaObject, Box<dyn Error>> {
        Ok(SchemaObject::new(
            "FederationChannelId",
            vec![WireValue::Opaque(value.to_vec())],
        )?)
    };
    let part = SchemaObject::new(
        "operation.part",
        vec![
            WireValue::Opaque([7_u8; 16].to_vec()),
            WireValue::Unsigned(1),
            WireValue::Unsigned(0), // Presence::absent
            WireValue::Vector(vec![
                channel_id_object([9_u8; 16])?,
                channel_id_object([9_u8; 16])?,
            ]),
            WireValue::Opaque(Vec::new()), // reason: absent
        ],
    );
    assert!(
        part.is_err(),
        "part must reject exact duplicate channel instance IDs"
    );
    let _ = channel_object("#unused")?;
    Ok(())
}
