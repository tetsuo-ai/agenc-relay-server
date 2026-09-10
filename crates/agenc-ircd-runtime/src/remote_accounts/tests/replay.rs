//! Captured account-service terminal results retain their accepted outcome.
#![forbid(unsafe_code)]

use super::*;
use crate::test_support::StateCoreFixture;

#[tokio::test]
async fn credential_finish_replay_preserves_success_and_sealed_reply()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = StateCoreFixture::new(vec![7; 1_048_576])?;
    let config = crate::test_support::account_service_config(
        &fixture.identity,
        &fixture.opaque,
        fixture.key_state,
    )?;
    let accounts = AccountServiceCoordinator::new(config)?;
    let context = fixture.context_mut()?;
    let generation = ConnectionGeneration::new(1 << 62);
    // Only the trusted owner's terminal NOTE selects success. The payload
    // remains opaque to this adapter and is forwarded byte-for-byte.
    for (terminal, accepted) in [
        ("NOTE ACCTCRED CHANGED :Credentials changed", true),
        ("FAIL ACCTCRED NOT_ALLOWED :Refused", false),
        ("NOTE ACCTCREATE CREATED :Unrelated operation", false),
        ("NOTE ACCTCRED :CHANGED", false),
    ] {
        let lines = vec![
            ":server.example ACCTCRED DATA QUJD".to_owned(),
            format!(":server.example {terminal}"),
        ];
        let (arm, replies) = outcome(
            context,
            &accounts,
            generation,
            FederationOpcode::CredentialChangeFinish,
            &lines,
        );
        assert_eq!(matches!(arm, ResultArm::Committed { .. }), accepted);
        assert_eq!(replies.len(), 1);
        assert_eq!(
            replies.first().ok_or("sealed reply")?,
            &WireMessage::new(context.server_prefix(), "ACCTCRED", &["DATA", "QUJD"], None)?
        );
    }
    Ok(())
}
