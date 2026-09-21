#![forbid(unsafe_code)]

//! Stage 06 shared administrative identifiers and permission registry.

use agenc_relay_types::{AdminPermission, AdminPermissionSet, OperatorId, ValidationError};

#[test]
fn operator_id_uses_the_canonical_fixed_identifier_form() -> Result<(), ValidationError> {
    let operator = OperatorId::from_bytes([7_u8; 16]);
    let text = operator.to_base64url();
    assert_eq!(text.len(), 22);
    assert_eq!(OperatorId::parse(&text)?, operator);
    assert_eq!(operator.as_bytes(), &[7_u8; 16]);
    assert_eq!(
        OperatorId::parse("BwcHBwcHBwcHBwcHBwcHBw==").err(),
        Some(ValidationError::IdentifierLength)
    );
    assert_eq!(format!("{operator:?}"), "OperatorId([redacted])");
    Ok(())
}

#[test]
fn permission_registry_is_closed_at_nine_members() -> Result<(), ValidationError> {
    assert_eq!(AdminPermission::ALL.len(), 9);
    let set = AdminPermissionSet::from_names(["audit", "observe"])?;
    assert_eq!(
        set.iter().collect::<Vec<_>>(),
        vec![AdminPermission::Observe, AdminPermission::Audit]
    );
    assert!(!set.contains(AdminPermission::Process));
    Ok(())
}
