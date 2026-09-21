//! Admission owns retained remote carrier memory until cleanup.
#![forbid(unsafe_code)]

use super::*;
use crate::test_support::StateCoreFixture;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn remote_account_authority_rejects_substituted_origin_and_session_facts() -> TestResult {
    use crate::test_support::{seed_account, seed_session};
    use agenc_relay_domain::federation::OriginPrincipal;
    let mut fixture = StateCoreFixture::new(vec![21; 131_072])?;
    let context = fixture.context_mut()?;
    let account = seed_account(context, 31, 1)?;
    let identity = seed_session(context, 41, "CredentialUser", Some(account))?;
    let session = context
        .domain()
        .session(identity.user_id)
        .ok_or("session")?;
    let peer = session.home_server_id();
    let bound = crate::state_core::session::BoundSession {
        session_id: identity.session_id,
        user_id: identity.user_id,
        capability_hash: *session.negotiated_capability_hash(),
    };
    let principal = OriginPrincipal {
        session: Some((bound.session_id, bound.user_id)),
        account: Some(account),
    };
    assert!(validate_remote_principal(context, peer, bound, principal, false).is_ok());
    assert!(
        validate_remote_principal(
            context,
            ServerId::from_bytes([7; 16]),
            bound,
            principal,
            false
        )
        .is_err()
    );
    let bad_principals = [
        OriginPrincipal::UNREGISTERED,
        OriginPrincipal {
            account: None,
            ..principal
        },
        OriginPrincipal {
            account: Some((agenc_relay_testkit::account_id(32), account.1)),
            ..principal
        },
        OriginPrincipal {
            account: Some((account.0, agenc_relay_testkit::generation(2)?)),
            ..principal
        },
        OriginPrincipal {
            session: Some((
                agenc_relay_types::SessionId::from_bytes([9; 16]),
                bound.user_id,
            )),
            ..principal
        },
    ];
    for principal in bad_principals {
        assert!(validate_remote_principal(context, peer, bound, principal, false).is_err());
    }
    let mut wrong_capabilities = bound;
    wrong_capabilities.capability_hash = [0; 32];
    assert!(validate_remote_principal(context, peer, wrong_capabilities, principal, true).is_err());
    let guest = seed_session(context, 42, "GuestCredential", None)?;
    let session = context.domain().session(guest.user_id).ok_or("guest")?;
    let bound = crate::state_core::session::BoundSession {
        session_id: guest.session_id,
        user_id: guest.user_id,
        capability_hash: *session.negotiated_capability_hash(),
    };
    let principal = OriginPrincipal {
        session: Some((guest.session_id, guest.user_id)),
        account: None,
    };
    assert!(validate_remote_principal(context, peer, bound, principal, true).is_ok());
    assert!(validate_remote_principal(context, peer, bound, principal, false).is_err());
    Ok(())
}

#[test]
fn remote_carrier_refusal_leaves_no_origin_or_generation_allocation() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![21; 131_072])?;
    let context = fixture.context_mut()?;
    let budget = context.backing_budget_for_test();
    let mut accounts = RemoteAccounts::default();
    let available = budget.available();
    let exhausted = context.reserve_output_backing(usize::try_from(
        available - crate::budget::ALLOCATION_BOOKKEEPING_BYTES,
    )?)?;
    assert_eq!(budget.available(), 0);
    let peer = ServerId::from_bytes([50; 16]);
    assert!(accounts.carrier_for(context, peer, [51; 16]).is_err());
    drop(exhausted);
    let (owner, created) = accounts
        .carrier_for(context, peer, [51; 16])
        .map_err(|e| format!("carrier: {e:?}"))?;
    assert!(created);
    assert_eq!(owner, ConnectionGeneration::new(VIRTUAL_BASE));
    assert!(budget.available() < available);
    let (_, created) = accounts
        .carrier_for(context, peer, [51; 16])
        .map_err(|e| format!("existing carrier: {e:?}"))?;
    assert!(!created);
    drop(accounts);
    assert_eq!(budget.available(), available);
    Ok(())
}
