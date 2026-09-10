//! An idle node retries a retained session removal after resources recover.
#![forbid(unsafe_code)]

use super::*;
use crate::bridge::crypto::{CHANNEL_KEY_SALT_BYTES, ChannelKeyVerifier, ChannelKeyVerifierRecord};
use crate::test_support::{StateCoreFixture, TestChannelKeyVerifier, remote_session_seed};
use std::sync::Arc;

#[tokio::test]
async fn maintenance_retries_refused_close_and_releases_nickname()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = StateCoreFixture::new(vec![23; 1_048_576])?;
    let verifier: Arc<dyn ChannelKeyVerifier> = Arc::new(TestChannelKeyVerifier);
    let salt = [7; CHANNEL_KEY_SALT_BYTES];
    let hash = verifier.derive(b"dummy", &salt)?;
    let commands = crate::channels::RegisteredCommandExecutor::new(
        verifier,
        ChannelKeyVerifierRecord::new(salt, hash),
    );
    let mut router = RegistrationRouter::new(
        RegistrationRouterConfig {
            network_id: fixture.identity.network_id,
            server_id: fixture.identity.server_id,
            server_prefix: "server.example".to_owned(),
            display_name: "TestNetwork".to_owned(),
            allow_guests: true,
            access_token: None,
            account_service: AccountServiceRole::Advertised {
                creation_policy: AccountCreationPolicy::Closed,
                recovery_epoch: fixture.identity.recovery_epoch,
            },
        },
        commands,
    )?;
    let home = fixture.identity.server_id;
    let context = fixture.context_mut()?;
    let seed = remote_session_seed(context, home, "ClosingUser")?;
    let nickname = agenc_ircd_domain::NicknameValue::parse("ClosingUser")?;
    let bound = BoundSession {
        session_id: seed.session_id,
        user_id: seed.user_id,
        capability_hash: seed.negotiated_capability_hash,
    };
    let opened = context.domain().plan_session_opened(seed)?;
    context
        .stage_durable(
            opened,
            crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())?,
            None,
            0,
        )
        .map_err(|error| format!("session admission: {error:?}"))?;
    fixture.commit_staged_batch().await?;
    let context = fixture.context_mut()?;
    let competing = context
        .domain()
        .plan_account_created(agenc_ircd_domain::AccountState::new(
            agenc_ircd_testkit::account_id(51),
            agenc_ircd_testkit::generation(1)?,
            context.domain().revision(),
        ))?;
    context
        .stage_durable(
            competing,
            crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())?,
            None,
            0,
        )
        .map_err(|error| format!("competing batch: {error:?}"))?;
    assert_eq!(
        context.pending_len(),
        1,
        "competing durable work must own the batch"
    );
    router.queue_session_close(context, bound, "connection closed");
    assert_eq!(
        context.pending_len(),
        1,
        "busy admission retains cleanup outside the competing batch"
    );
    assert_eq!(router.pending_closures.len(), 1);
    assert_eq!(
        context.domain().resolve_nickname(&nickname),
        Some(bound.user_id)
    );
    // Settle the competing owner without a registration callback. This leaves
    // the same retained close an idle node has after a refused cleanup attempt.
    fixture.commit_staged_batch().await?;
    let context = fixture.context_mut()?;
    assert_eq!(context.pending_len(), 0);
    assert!(
        context.domain().session(bound.user_id).is_some(),
        "fixture must retain the original session before the retry"
    );
    router.maintenance(
        context,
        crate::state_core::inbox::MaintenanceEvent::ClockDriftCheck,
    );
    assert_eq!(
        context.pending_len(),
        1,
        "minute maintenance must retry on an otherwise idle node"
    );
    assert!(
        context.domain().session(bound.user_id).is_some(),
        "cleanup waits for storage"
    );
    fixture.commit_staged_batch().await?;
    let context = fixture.context_mut()?;
    router.batch_applied(context, 1);
    assert!(context.domain().session(bound.user_id).is_none());
    assert!(context.domain().resolve_nickname(&nickname).is_none());
    assert!(router.pending_closures.is_empty());
    Ok(())
}
