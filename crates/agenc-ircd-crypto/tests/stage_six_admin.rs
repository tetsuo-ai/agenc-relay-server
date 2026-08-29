#![forbid(unsafe_code)]

//! Stage 06 administrative signature domains and control-plane hashes.

use agenc_ircd_crypto::{
    CryptoError, Ed25519SecretKey, SignatureDomain, admin_audit_checkpoint_hash,
    admin_audit_event_hash, admin_confirmation_token_hash, audit_signing_key_id,
    backup_signing_key_id, sign_canonical, verify_canonical,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn admin_hashes_pin_their_section_sixteen_and_twenty_two_labels() -> Result<(), CryptoError> {
    let mut token = [0_u8; 16];
    for (index, byte) in token.iter_mut().enumerate() {
        *byte = u8::try_from(index).map_err(|_| CryptoError::Overflow)?;
    }
    assert_eq!(
        hex(admin_confirmation_token_hash(&token)?.as_bytes()),
        "337a34731bd18d13a357709c0a2588a423eda51e9f8665fc497160b058eaab3e"
    );
    let key = [7_u8; 32];
    assert_eq!(
        hex(audit_signing_key_id(&key)?.as_bytes()),
        "4e2efb40d2e138463a7233004d44475e8642f4744ca97597a0ddde80249a9496"
    );
    assert_eq!(
        hex(backup_signing_key_id(&key)?.as_bytes()),
        "13f8de57906b335ff1a4ab2341b86848af210fdd6ae2c2337a4b6ca419432c07"
    );
    assert_ne!(audit_signing_key_id(&key)?, backup_signing_key_id(&key)?);
    assert_eq!(
        hex(admin_audit_event_hash(&[1, 2, 3])?.as_bytes()),
        "21b4bb16f2005db045f284faa4596359e9886851e14a9fc3830d6ee8f9f90933"
    );
    assert_eq!(
        hex(admin_audit_checkpoint_hash(&[9_u8; 194])?.as_bytes()),
        "e08bc34790c9e5144cdefa067ad28040b054430505b174053cb8452ea231a1c3"
    );
    Ok(())
}

#[test]
fn admin_hashes_enforce_their_size_contracts() {
    assert_eq!(admin_audit_event_hash(&[]), Err(CryptoError::LimitExceeded));
    assert!(admin_audit_event_hash(&[0_u8; 4_500]).is_ok());
    assert_eq!(
        admin_audit_event_hash(&[0_u8; 4_501]),
        Err(CryptoError::LimitExceeded)
    );
    assert_eq!(
        admin_audit_checkpoint_hash(&[0_u8; 193]),
        Err(CryptoError::InvalidEncoding)
    );
    assert_eq!(
        admin_audit_checkpoint_hash(&[0_u8; 195]),
        Err(CryptoError::InvalidEncoding)
    );
}

#[test]
fn admin_session_and_command_domains_do_not_cross_verify() -> Result<(), CryptoError> {
    let key = Ed25519SecretKey::from_bytes([21_u8; 32]);
    let content = b"identical canonical bytes";
    let session = sign_canonical(&key, SignatureDomain::AdminSession, content)?;
    let command = sign_canonical(&key, SignatureDomain::AdminCommand, content)?;
    assert_ne!(session, command);
    verify_canonical(
        key.public_key(),
        SignatureDomain::AdminSession,
        content,
        session,
    )?;
    verify_canonical(
        key.public_key(),
        SignatureDomain::AdminCommand,
        content,
        command,
    )?;
    assert_eq!(
        verify_canonical(
            key.public_key(),
            SignatureDomain::AdminCommand,
            content,
            session
        ),
        Err(CryptoError::AuthenticationFailed)
    );
    assert_eq!(
        verify_canonical(
            key.public_key(),
            SignatureDomain::AdminSession,
            content,
            command
        ),
        Err(CryptoError::AuthenticationFailed)
    );
    Ok(())
}
