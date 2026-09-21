//! Account administration advances the same revision in storage and memory.
#![forbid(unsafe_code)]

use super::*;
use crate::state_core::{AdminMutation, AdminMutationAfterImage};
use crate::test_support::seed_account;
use agenc_relay_types::UtcSecond;

#[tokio::test]
async fn account_admin_after_images_match_committed_revisions() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let (account_id, _) = seed_account(fixture.context_mut()?, 31, 1)?;
    let mutations = [
        AdminMutation::SuspendAccount {
            account_id,
            expires_at: UtcSecond::from_unix_seconds(1_800_000_000),
        },
        AdminMutation::RestoreAccount(account_id),
    ];
    for mutation in mutations {
        let state = fixture.state_mut()?;
        let before = state.context.domain.revision();
        let expected = before.checked_add(1)?;
        let after_image = state
            .prepare_admin_after_image(mutation)
            .map_err(|error| format!("prepare: {error:?}"))?;
        let AdminMutationAfterImage::Account(after_image) = after_image else {
            return Err("account administration produced a channel after-image".into());
        };
        assert_eq!(after_image.revision, expected);
        state.apply_admin_mutation(mutation)?;
        let live = state
            .context
            .domain
            .durable_account(account_id)
            .ok_or("account")?;
        assert_eq!(live.revision, expected);
        assert_eq!(live, after_image);
        assert!(state.validate_admin_mutation(mutation, before).is_err());
    }
    Ok(())
}
