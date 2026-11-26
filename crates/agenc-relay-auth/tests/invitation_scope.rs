//! Architecture §11.3 and Appendix C. The client and coordinator share one scope check.
use agenc_relay_auth::{AccountCreationInvite, AuthError};
use agenc_relay_crypto::Ed25519SecretKey;
use agenc_relay_types::{InviteId, NetworkId, UtcSecond};

#[test]
fn scope_and_authority_are_independent() -> Result<(), Box<dyn std::error::Error>> {
    let network = NetworkId::from_bytes([1; 32]);
    let authority = Ed25519SecretKey::from_bytes([2; 32]);
    let utc = UtcSecond::from_unix_seconds;
    let issued = AccountCreationInvite::issue(
        network,
        InviteId::from_bytes([3; 16]),
        utc(20),
        utc(20 + 2_592_000),
        &authority,
    )?;
    for (now, valid) in [
        (19, false),
        (20, true),
        (2_592_019, true),
        (2_592_020, false),
    ] {
        assert_eq!(issued.validate_scope(network, utc(now)).is_ok(), valid);
        assert_eq!(
            issued
                .verify(authority.public_key(), network, utc(now))
                .is_ok(),
            valid
        );
    }
    let other = NetworkId::from_bytes([4; 32]);
    assert_eq!(
        issued.validate_scope(other, utc(20)),
        Err(AuthError::InvitationRejected)
    );

    let mut encoded = *issued.expose_for_account_request();
    *encoded.last_mut().ok_or("missing signature")? ^= 1;
    let changed = AccountCreationInvite::parse(&encoded)?;
    changed.validate_scope(network, utc(20))?;
    assert_eq!(
        changed.verify(authority.public_key(), network, utc(20)),
        Err(AuthError::InvitationRejected)
    );

    for expiry in [19_u64, 20, 2_592_021] {
        encoded
            .get_mut(58..66)
            .ok_or("missing expiry")?
            .copy_from_slice(&expiry.to_be_bytes());
        let malformed = AccountCreationInvite::parse(&encoded)?;
        assert_eq!(
            malformed.validate_scope(network, utc(20)),
            Err(AuthError::InvitationRejected)
        );
    }
    Ok(())
}
