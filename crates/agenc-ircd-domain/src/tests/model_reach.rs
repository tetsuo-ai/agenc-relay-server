//! Ceiling, validation and restore outcomes reached only by one field at a
//! time exceeding its bound, by corrupted rows, and by duplicate rows.
#![forbid(unsafe_code)]

use super::*;

#[test]
fn every_usage_ceiling_is_checked_on_its_own() {
    type Exceed = fn(&mut OperationalUsage);
    let exceed: [Exceed; 9] = [
        |usage| usage.sessions_per_account = usize::MAX,
        |usage| usage.channels_per_session = usize::MAX,
        |usage| usage.members_per_channel = usize::MAX,
        |usage| usage.global_channels = usize::MAX,
        |usage| usage.local_channels = usize::MAX,
        |usage| usage.invites_per_channel = usize::MAX,
        |usage| usage.invites_per_principal = usize::MAX,
        |usage| usage.invites_global = usize::MAX,
        |usage| usage.contacts_per_account = usize::MAX,
    ];
    assert!(OperationalLimits::HARD_MAX.admits(OperationalUsage::default()));
    for raise in exceed {
        let mut usage = OperationalUsage::default();
        raise(&mut usage);
        assert!(!OperationalLimits::HARD_MAX.admits(usage));
    }
}

#[test]
fn an_encrypted_channel_needs_registration_and_no_topic() -> Result<(), DomainError> {
    let mut value = channel(1, "#ephemeral")?;
    value.content_policy = ContentPolicy::E2eeBound;
    assert_eq!(value.validate(), Err(DomainError::InvariantViolation));

    let mut value = channel(2, "#topic")?;
    value.content_policy = ContentPolicy::E2eeBound;
    value.persistence = PersistencePolicy::Registered;
    value.role_grants.insert(account(2), Role::Owner);
    value.topic = Some(PlaintextTopic {
        text: TopicText::try_from_str("set", agenc_ircd_types::ControlPolicy::RejectAll)?,
        message_id: MessageId::from_bytes(id(2)),
        setter: UserId::from_bytes(id(66)),
        set_at: UtcSecond::from_unix_seconds(11),
    });
    assert_eq!(value.validate(), Err(DomainError::InvariantViolation));
    Ok(())
}

#[test]
fn an_ephemeral_channel_carries_no_role_grants() -> Result<(), DomainError> {
    let mut value = channel(3, "#grants")?;
    value.role_grants.insert(account(3), Role::Owner);
    assert_eq!(value.validate(), Err(DomainError::InvariantViolation));
    Ok(())
}

#[test]
fn role_grants_beyond_the_channel_limit_are_invalid() -> Result<(), DomainError> {
    let mut value = channel(4, "#many")?;
    value.persistence = PersistencePolicy::Registered;
    for index in 0..=MAX_ROLE_GRANTS_PER_CHANNEL {
        let account_id = AccountId::from_random(AccountRandomId::from_bytes(indexed_id(index)?));
        value.role_grants.insert(account_id, Role::Owner);
    }
    assert!(!value.collection_limits_are_valid());
    Ok(())
}

#[test]
fn memberships_and_invites_ahead_of_the_channel_or_misfiled_are_invalid() -> Result<(), DomainError>
{
    let mut value = channel(5, "#ahead")?;
    for membership in value.memberships.values_mut() {
        membership.membership_revision = Revision::new(9)?;
    }
    assert!(!value.membership_identities_are_valid());

    let mut value = channel(6, "#misfiled")?;
    value.invites.insert(
        InviteId::from_bytes(id(9)),
        Invite {
            invite_id: InviteId::from_bytes(id(8)),
            target: Principal::Guest(UserId::from_bytes(id(70))),
            inviter: UserId::from_bytes(id(70)),
            creation_revision: Revision::new(1)?,
            expires_at: MonotonicTick::from_ticks(100),
            expires_at_utc: UtcSecond::from_unix_seconds(610),
        },
    );
    assert!(!value.invite_identities_are_valid());
    Ok(())
}

#[test]
fn guest_sessions_count_toward_no_account_ceiling() -> Result<(), DomainError> {
    let mut state = DomainState::new()?;
    let guest = session(7, None)?;
    state.sessions.insert(guest.user_id, guest);
    let usage = state.operational_usage()?;
    assert_eq!(usage.sessions_per_account, 0);
    Ok(())
}

#[test]
fn a_channel_is_quarantined_once() -> Result<(), DomainError> {
    let mut state = DomainState::new()?;
    let mut value = channel(8, "#quarantine")?;
    value.persistence = PersistencePolicy::Registered;
    let channel_id = value.channel_id;
    state.channel_names.insert(value.name.clone(), channel_id);
    state.channels.insert(channel_id, value);
    state.admin_quarantine_channel(channel_id)?;
    assert_eq!(
        state.admin_quarantine_channel(channel_id),
        Err(DomainError::NotFound)
    );
    Ok(())
}

/// A registered channel row without members, as a pre-cutover restore holds.
fn durable(seed: u8, name: &str) -> Result<DurableChannel, DomainError> {
    let mut value = channel(seed, name)?;
    value.memberships.clear();
    value.persistence = PersistencePolicy::Registered;
    value.role_grants.insert(account(seed), Role::Owner);
    DurableChannel::from_state(&value).ok_or(DomainError::InvariantViolation)
}

fn account_row(seed: u8) -> Result<DurableAccount, DomainError> {
    Ok(DurableAccount::from_state(&AccountState::new(
        account(seed),
        Generation::new(1)?,
        Revision::new(1)?,
    )))
}

#[test]
fn legacy_restore_refuses_duplicate_accounts_and_channels() -> Result<(), DomainError> {
    let revision = Revision::new(1)?;
    let accounts = || -> Result<Vec<DurableAccount>, DomainError> {
        Ok(vec![account_row(1)?, account_row(2)?])
    };
    assert_eq!(
        DomainState::restore(revision, accounts()?, vec![durable(1, "#a")?], Vec::new()).err(),
        None
    );
    assert!(
        DomainState::restore(
            revision,
            vec![account_row(1)?, account_row(1)?],
            Vec::new(),
            Vec::new()
        )
        .is_err()
    );
    assert!(
        DomainState::restore(
            revision,
            accounts()?,
            vec![durable(1, "#a")?, durable(2, "#a")?],
            Vec::new()
        )
        .is_err()
    );
    assert!(
        DomainState::restore(
            revision,
            accounts()?,
            vec![durable(1, "#a")?, durable(1, "#b")?],
            Vec::new()
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn authoritative_restore_refuses_each_duplicate_session_identity_and_channel_id()
-> Result<(), DomainError> {
    let revision = Revision::new(1)?;
    let first = session(1, None)?;
    let mut same_nickname = session(2, None)?;
    same_nickname.nickname = first.nickname.clone();
    let mut same_cloak = session(3, None)?;
    same_cloak.public_cloak = first.public_cloak;
    let mut same_user = session(4, None)?;
    same_user.user_id = first.user_id;
    for other in [same_nickname, same_cloak, same_user] {
        let sessions = vec![
            crate::DurableSession::from_state(&first),
            crate::DurableSession::from_state(&other),
        ];
        assert!(
            DomainState::restore_authoritative(
                revision,
                Vec::new(),
                sessions,
                Vec::new(),
                Vec::new(),
                MonotonicTick::from_ticks(1),
                UtcSecond::from_unix_seconds(1),
            )
            .is_err()
        );
    }
    assert!(
        DomainState::restore_authoritative(
            revision,
            vec![account_row(1)?],
            Vec::new(),
            vec![durable(1, "#a")?, durable(1, "#b")?],
            Vec::new(),
            MonotonicTick::from_ticks(1),
            UtcSecond::from_unix_seconds(1),
        )
        .is_err()
    );
    Ok(())
}
