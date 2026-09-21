#![forbid(unsafe_code)]

//! COV-01: the maintenance arm of the audit export renderer and the coverage
//! check on the first exported record.
//!
//! The batch is rendered from the independently produced maintenance fixture
//! through `render_export_batch`, so the exported keyword, the signed sequence
//! and the byte-for-byte body are the ones an operator receives.

use super::*;

/// The independently signed encoding-two maintenance body.
const MAINTENANCE_FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-data/stage-ten/maintenance-audit-start-v1.bin"
));

/// A maintenance body exports under its own NOTE keyword, is counted by its own
/// signed sequence, and carries its exact encoded bytes.
#[test]
fn a_maintenance_body_exports_under_its_own_keyword() -> Result<(), AdminError> {
    let event = crate::AuditEvent::decode_exact(MAINTENANCE_FIXTURE)?;
    assert_eq!(event.encoding(), 2);
    let sequence = event.audit_sequence();
    let range = AuditRange::new(sequence, sequence)?;
    let lines = render_export_batch(&[0; 16], range, &[], std::slice::from_ref(&event))?;

    assert_eq!(lines.len(), 3);
    assert_eq!(
        lines.first().map(String::as_str),
        Some(
            format!("BATCH +AAAAAAAAAAAAAAAAAAAAAA agenc.ag/audit {sequence} {sequence} 1 0")
                .as_str()
        )
    );
    let token = crate::encode_base64url(MAINTENANCE_FIXTURE);
    assert_eq!(
        lines.get(1).map(String::as_str),
        Some(
            format!(
                "@batch=AAAAAAAAAAAAAAAAAAAAAA NOTE AUDIT MAINTENANCE {token} \
                 :Maintenance audit event"
            )
            .as_str()
        )
    );
    assert_eq!(
        lines.last().map(String::as_str),
        Some("BATCH -AAAAAAAAAAAAAAAAAAAAAA")
    );
    Ok(())
}

/// A batch whose first record starts after the requested range is refused
/// whole: an export never silently omits the sequences it claims to cover.
#[test]
fn an_export_that_misses_the_start_of_its_range_is_refused() -> Result<(), AdminError> {
    let event = crate::AuditEvent::decode_exact(MAINTENANCE_FIXTURE)?;
    let sequence = event.audit_sequence();
    let start = sequence.checked_sub(1).ok_or(AdminError::Audit)?;
    assert_eq!(
        render_export_batch(
            &[0; 16],
            AuditRange::new(start, sequence)?,
            &[],
            std::slice::from_ref(&event),
        )
        .err(),
        Some(AdminError::Audit)
    );
    // The same records cover a range that begins where they do.
    render_export_batch(
        &[0; 16],
        AuditRange::new(sequence, sequence)?,
        &[],
        std::slice::from_ref(&event),
    )?;
    Ok(())
}
