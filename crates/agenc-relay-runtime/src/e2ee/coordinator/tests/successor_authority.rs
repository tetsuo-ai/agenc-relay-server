#![forbid(unsafe_code)]

//! Base channel authority remains required after the initial E2EE binding.

use agenc_relay_domain::{
    CanonicalCommand, ChannelCommand, ChannelNameValue, ChannelTarget, DomainState, ExternalInputs,
};
use agenc_relay_testkit::{
    apply_command, apply_plan, channel_id, create_account, open_session, registered_admission,
};
use agenc_relay_types::UtcSecond;

use super::{E2eeReplyCode, binding_plan};

#[test]
fn successor_channel_plan_requires_current_owner_and_exact_account_roster()
-> Result<(), Box<dyn std::error::Error>> {
    let mut domain = DomainState::new()?;
    let owner_account = create_account(&mut domain, 30, 4)?;
    let member_account = create_account(&mut domain, 31, 5)?;
    let owner = open_session(&mut domain, 30, "Owner", Some(owner_account))?;
    let member = open_session(&mut domain, 31, "Member", Some(member_account))?;
    let name = ChannelNameValue::parse("#successor")?;
    let channel = channel_id(40);
    for identity in [owner, member] {
        apply_command(
            &mut domain,
            identity,
            CanonicalCommand::join(vec![ChannelTarget::new(name.clone(), false)])?,
            &registered_admission(identity.user_id)?,
            Some(ExternalInputs {
                utc_now: Some(UtcSecond::from_unix_seconds(1_700_000_000)),
                channel_ids: if identity.user_id == owner.user_id {
                    vec![channel]
                } else {
                    Vec::new()
                },
                ..ExternalInputs::default()
            }),
        )?;
    }
    apply_command(
        &mut domain,
        owner,
        CanonicalCommand::channel(ChannelCommand::Register(channel)),
        &registered_admission(owner.user_id)?,
        None,
    )?;
    let principals = [
        owner_account.0.to_text().as_bytes().try_into()?,
        member_account.0.to_text().as_bytes().try_into()?,
    ];
    let initial = binding_plan(&domain, Some(owner.user_id), channel, &principals)
        .map_err(|error| format!("{error:?}"))?
        .ok_or("initial binding did not produce a base plan")?;
    apply_plan(&mut domain, initial)?;
    assert!(matches!(
        binding_plan(&domain, Some(owner.user_id), channel, &principals),
        Ok(None)
    ));
    assert!(matches!(
        binding_plan(&domain, Some(member.user_id), channel, &principals),
        Err(E2eeReplyCode::BindingAuthInvalid)
    ));
    assert!(matches!(
        binding_plan(&domain, Some(owner.user_id), channel, &principals[..1]),
        Err(E2eeReplyCode::BindingAuthInvalid)
    ));
    assert!(matches!(
        binding_plan(&domain, None, channel, &principals),
        Err(E2eeReplyCode::AccountRequired)
    ));
    Ok(())
}
