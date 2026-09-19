//! Every bound and ordering rule of the live domain record codecs, one
//! violation at a time.
#![forbid(unsafe_code)]

use super::fixtures::{account, channel, session};
use super::{AccountRecordBody, ChannelRecordBody, SessionRecordBody};
use crate::StorageError;
use agenc_ircd_domain::{
    ContentPolicy, DurableChannel, DurableInvite, DurableListEntry, DurableMembership,
    NicknameValue, PersistencePolicy, Principal, Role,
};
use agenc_ircd_domain::{
    MAX_CHANNELS_PER_SESSION, MAX_INVITES_PER_CHANNEL, MAX_MASK_ENTRIES_PER_LIST,
    MAX_MEMBERS_PER_CHANNEL, MAX_ROLE_GRANTS_PER_CHANNEL,
};
use agenc_ircd_types::{
    AccountId, AccountRandomId, ChannelInstanceId, EntryId, Generation, InviteId, Revision, UserId,
    UtcSecond,
};

fn revision(value: u64) -> Result<Revision, StorageError> {
    Revision::new(value).map_err(|_| StorageError::InvalidEncoding)
}

fn nickname(text: &str) -> Result<NicknameValue, StorageError> {
    NicknameValue::parse(text).map_err(|_| StorageError::InvalidEncoding)
}

fn account_id(seed: u8) -> AccountId {
    AccountRandomId::from_bytes([seed; 16]).to_account_id()
}

fn indexed(index: usize) -> [u8; 16] {
    let mut raw = [0_u8; 16];
    raw[..8].copy_from_slice(&(index as u64).to_be_bytes());
    raw
}

fn membership(seed: u8, channel_revision: u64) -> Result<DurableMembership, StorageError> {
    Ok(DurableMembership {
        user_id: UserId::from_bytes([seed; 16]),
        account_id: None,
        session_role: Role::Member,
        effective_role: Role::Member,
        membership_revision: revision(channel_revision)?,
        joined_at: UtcSecond::from_unix_seconds(2),
    })
}

fn invite(seed: u8, creation_revision: u64) -> Result<DurableInvite, StorageError> {
    Ok(DurableInvite {
        invite_id: InviteId::from_bytes([seed; 16]),
        target: Principal::Guest(UserId::from_bytes([seed; 16])),
        inviter: UserId::from_bytes([1; 16]),
        creation_revision: revision(creation_revision)?,
        expires_at_utc: UtcSecond::from_unix_seconds(600),
    })
}

fn entry(seed: u8) -> DurableListEntry {
    DurableListEntry {
        entry_id: EntryId::from_bytes([seed; 16]),
        mask: "$n:blocked".to_owned(),
        setter: Principal::Guest(UserId::from_bytes([1; 16])),
        created_at: UtcSecond::from_unix_seconds(2),
    }
}

/// Swaps the first occurrences of two byte patterns inside an encoded body.
fn swapped(body: &[u8], first: &[u8], second: &[u8]) -> Result<Vec<u8>, StorageError> {
    let find = |needle: &[u8]| {
        body.windows(needle.len())
            .position(|window| window == needle)
            .ok_or(StorageError::InvalidEncoding)
    };
    let (at_first, at_second) = (find(first)?, find(second)?);
    let mut out = body.to_vec();
    out[at_first..at_first + first.len()].copy_from_slice(second);
    out[at_second..at_second + second.len()].copy_from_slice(first);
    Ok(out)
}

#[test]
fn account_bodies_keep_reserved_nicknames_and_contacts_ascending() -> Result<(), StorageError> {
    let mut descending = account(1)?;
    descending.reserved_nicknames = vec![nickname("zed")?, nickname("amy")?];
    assert_eq!(
        AccountRecordBody::encode(&descending).err(),
        Some(StorageError::LimitExceeded)
    );

    let mut sorted = account(1)?;
    sorted.reserved_nicknames = vec![nickname("amy")?, nickname("zed")?];
    let body = AccountRecordBody::encode(&sorted)?;
    assert_eq!(
        AccountRecordBody::decode(&swapped(&body, b"amy", b"zed")?).err(),
        Some(StorageError::InvalidEncoding)
    );

    let mut contacts = account(1)?;
    contacts.contacts = vec![account_id(3), account_id(4)];
    contacts.contacts.sort();
    let body = AccountRecordBody::encode(&contacts)?;
    let (low, high) = (contacts.contacts[0].random(), contacts.contacts[1].random());
    assert_eq!(
        AccountRecordBody::decode(&swapped(&body, low.as_bytes(), high.as_bytes())?).err(),
        Some(StorageError::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn session_bodies_reject_a_zero_generation_and_too_many_channels() -> Result<(), StorageError> {
    let mut zero = session(1)?;
    zero.generation = Generation::new(0).map_err(|_| StorageError::InvalidEncoding)?;
    assert_eq!(
        SessionRecordBody::encode(&zero).err(),
        Some(StorageError::InvalidEncoding)
    );
    let mut crowded = session(1)?;
    crowded.joined_channels = (0..=MAX_CHANNELS_PER_SESSION)
        .map(|index| ChannelInstanceId::from_bytes(indexed(index)))
        .collect();
    assert_eq!(
        SessionRecordBody::encode(&crowded).err(),
        Some(StorageError::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn a_session_display_name_must_already_be_prepared() -> Result<(), StorageError> {
    let mut named = session(1)?;
    named.display_name = agenc_ircd_domain::DisplayNameValue::prepare("Fixtures")
        .map_err(|_| StorageError::InvalidEncoding)?;
    let body = SessionRecordBody::encode(&named)?;
    let unprepared = "Fixtue\u{301}";
    assert_eq!(unprepared.len(), "Fixtures".len());
    let at = body
        .windows(8)
        .position(|window| window == b"Fixtures")
        .ok_or(StorageError::Overflow)?;
    let mut tampered = body.clone();
    tampered[at..at + 8].copy_from_slice(unprepared.as_bytes());
    let decoded = SessionRecordBody::decode(&tampered);
    assert_eq!(decoded.err(), Some(StorageError::InvalidEncoding));
    Ok(())
}

fn refused(channel: &DurableChannel) -> bool {
    ChannelRecordBody::encode(channel).is_err()
}

#[test]
fn ephemeral_channels_need_members_and_carry_no_grants() -> Result<(), StorageError> {
    let mut empty = channel(1)?;
    empty.persistence = PersistencePolicy::Ephemeral;
    empty.role_grants.clear();
    empty.creator = Principal::Guest(UserId::from_bytes([1; 16]));
    assert!(refused(&empty));
    let mut granted = channel(1)?;
    granted.persistence = PersistencePolicy::Ephemeral;
    granted.creator = Principal::Guest(UserId::from_bytes([1; 16]));
    granted.memberships = vec![membership(1, 1)?];
    assert!(refused(&granted));
    Ok(())
}

#[test]
fn channel_collections_are_bounded_and_ordered() -> Result<(), StorageError> {
    let mut members = channel(1)?;
    members.memberships = (0..=MAX_MEMBERS_PER_CHANNEL)
        .map(|index| {
            let mut member = membership(1, 1)?;
            member.user_id = UserId::from_bytes(indexed(index));
            Ok(member)
        })
        .collect::<Result<Vec<_>, StorageError>>()?;
    assert!(refused(&members));

    let mut grants = channel(1)?;
    grants.role_grants = (0..=MAX_ROLE_GRANTS_PER_CHANNEL)
        .map(|index| {
            (
                AccountRandomId::from_bytes(indexed(index)).to_account_id(),
                Role::Owner,
            )
        })
        .collect();
    grants.role_grants.sort_by_key(|(id, _)| *id);
    assert!(refused(&grants));

    let mut invites = channel(1)?;
    invites.invites = (0..=MAX_INVITES_PER_CHANNEL)
        .map(|index| {
            let mut invite = invite(1, 1)?;
            invite.invite_id = InviteId::from_bytes(indexed(index));
            Ok(invite)
        })
        .collect::<Result<Vec<_>, StorageError>>()?;
    assert!(refused(&invites));

    let mut pending = channel(1)?;
    pending.content_policy = ContentPolicy::E2eeBound;
    pending.e2ee_removal_pending = (0..=MAX_MEMBERS_PER_CHANNEL)
        .map(|index| UserId::from_bytes(indexed(index)))
        .collect();
    assert!(refused(&pending));

    let mut unordered_members = channel(1)?;
    unordered_members.memberships = vec![membership(2, 1)?, membership(1, 1)?];
    assert!(refused(&unordered_members));

    let mut unordered_grants = channel(1)?;
    unordered_grants.role_grants = vec![(account_id(2), Role::Owner), (account_id(1), Role::Voice)];
    unordered_grants
        .role_grants
        .sort_by_key(|(id, _)| std::cmp::Reverse(*id));
    assert!(refused(&unordered_grants));

    let mut unordered_invites = channel(1)?;
    unordered_invites.invites = vec![invite(2, 1)?, invite(1, 1)?];
    assert!(refused(&unordered_invites));

    let mut unordered_pending = channel(1)?;
    unordered_pending.content_policy = ContentPolicy::E2eeBound;
    unordered_pending.memberships = vec![membership(1, 1)?, membership(2, 1)?];
    unordered_pending.e2ee_removal_pending =
        vec![UserId::from_bytes([2; 16]), UserId::from_bytes([1; 16])];
    assert!(refused(&unordered_pending));

    let mut masks = channel(1)?;
    masks.bans = (0..=MAX_MASK_ENTRIES_PER_LIST)
        .map(|index| {
            let mut item = entry(1);
            item.entry_id = EntryId::from_bytes(indexed(index));
            item
        })
        .collect();
    assert!(refused(&masks));
    Ok(())
}

#[test]
fn channel_memberships_invites_and_pending_removals_bind_to_the_channel() -> Result<(), StorageError>
{
    let mut zero = channel(1)?;
    zero.memberships = vec![membership(1, 1)?];
    zero.memberships[0].membership_revision = revision(1)?;
    let mut ahead = channel(1)?;
    ahead.memberships = vec![membership(1, 5)?];
    assert!(refused(&ahead));

    let mut demoted = channel(1)?;
    demoted.memberships = vec![membership(1, 1)?];
    demoted.memberships[0].session_role = Role::Operator;
    demoted.memberships[0].effective_role = Role::Member;
    assert!(refused(&demoted));

    let mut invite_ahead = channel(1)?;
    invite_ahead.invites = vec![invite(1, 5)?];
    assert!(refused(&invite_ahead));

    let mut plaintext_pending = channel(1)?;
    plaintext_pending.memberships = vec![membership(1, 1)?];
    plaintext_pending.e2ee_removal_pending = vec![UserId::from_bytes([1; 16])];
    assert!(refused(&plaintext_pending));

    let mut ungranted = channel(1)?;
    let mut member = membership(1, 1)?;
    member.effective_role = Role::Voice;
    ungranted.memberships = vec![member];
    assert!(refused(&ungranted));
    Ok(())
}

#[test]
fn decoded_channel_grants_must_ascend() -> Result<(), StorageError> {
    let mut granted = channel(1)?;
    granted.role_grants = vec![(account_id(3), Role::Owner), (account_id(4), Role::Owner)];
    granted.role_grants.sort_by_key(|(id, _)| *id);
    granted.creator = Principal::Account(granted.role_grants[0].0);
    let body = ChannelRecordBody::encode(&granted)?;
    let (low, high) = (
        granted.role_grants[0].0.random(),
        granted.role_grants[1].0.random(),
    );
    assert_eq!(
        ChannelRecordBody::decode(&swapped(&body, low.as_bytes(), high.as_bytes())?).err(),
        Some(StorageError::InvalidEncoding)
    );
    Ok(())
}
