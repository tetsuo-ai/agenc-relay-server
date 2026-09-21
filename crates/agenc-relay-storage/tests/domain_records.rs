//! Stage 06 persisted-domain body codecs: golden vectors, round trips, and rejections.

#![forbid(unsafe_code)]

use std::error::Error;

use agenc_relay_domain::{
    ChannelKeyVerifier, ChannelModes, ChannelNameValue, ChannelScope, ContentPolicy,
    DirectMessagePolicy, DisplayNameValue, DomainError, DurableAccount, DurableChannel,
    DurableInvite, DurableListEntry, DurableMembership, DurableSanction, DurableSession,
    DurableTopic, GuestDirectMessagePolicy, HistoryPolicy, MAX_CONTACTS_PER_ACCOUNT,
    MAX_MASK_ENTRIES_PER_LIST, MAX_RESERVED_NICKNAMES, ModerationAction, ModerationReasonCode,
    NicknameValue, PersistencePolicy, PresencePolicy, Principal, Role, Visibility,
};
use agenc_relay_storage::{
    AccountRecordBody, ChannelNameRecordBody, ChannelRecordBody, LIVE_RECORD_KIND,
    MAX_ACCOUNT_RECORD_BODY_BYTES, MAX_CHANNEL_NAME_RECORD_BODY_BYTES,
    MAX_CHANNEL_RECORD_BODY_BYTES, MAX_SANCTION_RECORD_BODY_BYTES, MAX_SESSION_RECORD_BODY_BYTES,
    PersistentRecordValue, SanctionRecordBody, SessionRecordBody, StorageError, TableId,
};
use agenc_relay_types::{
    AccountId, AccountRandomId, ChannelInstanceId, EntryId, Generation, InviteId, MessageId,
    PublicCloak, Revision, ServerId, SessionId, UserId, UtcSecond,
};

/// Returns the smallest valid live body for a strict domain table, or an empty body for
/// tables whose live bodies remain opaque to storage.
pub(crate) fn live_body(table: TableId, seed: u8) -> Result<Vec<u8>, StorageError> {
    match table {
        TableId::Account => AccountRecordBody::encode(&minimal_account(seed)?),
        TableId::Session => SessionRecordBody::encode(&minimal_session(seed)?),
        TableId::Channel => ChannelRecordBody::encode(&minimal_channel(seed)?),
        TableId::Sanction => SanctionRecordBody::encode(&minimal_sanction(seed)?),
        _ => Ok(Vec::new()),
    }
}

pub(crate) fn channel_name_body(seed: u8, spelling: &str) -> Result<Vec<u8>, StorageError> {
    let name = ChannelNameValue::parse(spelling).map_err(|_| StorageError::InvalidEncoding)?;
    ChannelNameRecordBody::encode(ChannelInstanceId::from_bytes([seed; 16]), &name)
}

fn minimal_session(seed: u8) -> Result<DurableSession, StorageError> {
    Ok(DurableSession {
        session_id: SessionId::from_bytes([seed; 16]),
        user_id: UserId::from_bytes([seed.wrapping_add(1); 16]),
        home_server_id: ServerId::from_bytes([seed.wrapping_add(2); 16]),
        account_id: Some(account_id(seed)),
        account_session_generation: quantity(Generation::new(1))?,
        generation: quantity(Generation::new(1))?,
        nickname: NicknameValue::parse("fixture").map_err(|_| StorageError::InvalidEncoding)?,
        display_name: DisplayNameValue::prepare("Fixture")
            .map_err(|_| StorageError::InvalidEncoding)?,
        public_cloak: PublicCloak::parse("aaaaaaaaaa", "bbbbbbbbbbbbbbbb")
            .map_err(|_| StorageError::InvalidEncoding)?,
        away: None,
        operator_notices: false,
        connection_nonce: [seed.wrapping_add(3); 32],
        negotiated_capability_hash: [seed.wrapping_add(4); 32],
        joined_channels: Vec::new(),
        created_at_utc: UtcSecond::from_unix_seconds(1),
        revision: quantity(Revision::new(1))?,
    })
}

fn set(bytes: &mut [u8], index: usize, value: u8) -> Result<(), StorageError> {
    *bytes.get_mut(index).ok_or(StorageError::InvalidEncoding)? = value;
    Ok(())
}

fn channel_key_verifier_offset(channel: &DurableChannel) -> usize {
    2 + 16 + 4 + channel.name.presentation().len() + 4 + 17 + 8 + 8 + 1
}

fn channel_membership_offset(channel: &DurableChannel) -> usize {
    let verifier_bytes = 1 + usize::from(channel.key_verifier.is_some()) * 48;
    let member_limit_bytes = 1 + usize::from(channel.member_limit.is_some()) * 2;
    let topic_bytes = 1 + channel
        .topic
        .as_ref()
        .map_or(0, |topic| 4 + topic.text.len() + 16 + 16 + 8);
    channel_key_verifier_offset(channel) + verifier_bytes + member_limit_bytes + topic_bytes
}

fn legacy_channel_body(channel: &DurableChannel, version: u8) -> Result<Vec<u8>, StorageError> {
    let mut encoded = ChannelRecordBody::encode(channel)?;
    let membership_offset = channel_membership_offset(channel);
    encoded.drain(membership_offset..membership_offset + 4);
    let pending_offset = encoded
        .len()
        .checked_sub(5)
        .ok_or(StorageError::InvalidEncoding)?;
    encoded.drain(pending_offset..pending_offset + 4);
    let invite_offset = encoded
        .len()
        .checked_sub(6)
        .ok_or(StorageError::InvalidEncoding)?;
    encoded.drain(invite_offset..invite_offset + 4);
    set(&mut encoded, 1, version)?;
    if version < 3 {
        encoded.pop().ok_or(StorageError::InvalidEncoding)?;
    }
    if version < 2 {
        let verifier_offset = channel_key_verifier_offset(channel);
        let verifier_bytes = 1 + usize::from(channel.key_verifier.is_some()) * 48;
        encoded.drain(verifier_offset..verifier_offset + verifier_bytes);
    }
    Ok(encoded)
}

fn account_id(seed: u8) -> AccountId {
    AccountRandomId::from_bytes([seed; 16]).to_account_id()
}

fn quantity<T>(value: Result<T, agenc_relay_types::ValidationError>) -> Result<T, StorageError> {
    value.map_err(|_| StorageError::InvalidEncoding)
}

fn minimal_account(seed: u8) -> Result<DurableAccount, StorageError> {
    Ok(DurableAccount {
        account_id: account_id(seed),
        label: None,
        presence: PresencePolicy::Private,
        guest_direct_messages: GuestDirectMessagePolicy::Allow,
        direct_messages: DirectMessagePolicy::Allow,
        contacts: Vec::new(),
        reserved_nicknames: Vec::new(),
        session_generation: quantity(Generation::new(1))?,
        revision: quantity(Revision::new(1))?,
        admin_suspension_expires_at: None,
    })
}

fn minimal_channel(seed: u8) -> Result<DurableChannel, StorageError> {
    Ok(DurableChannel {
        channel_id: ChannelInstanceId::from_bytes([seed; 16]),
        name: ChannelNameValue::parse("#fixture").map_err(|_| StorageError::InvalidEncoding)?,
        scope: ChannelScope::Global,
        visibility: Visibility::Listed,
        content_policy: ContentPolicy::Plaintext,
        persistence: PersistencePolicy::Registered,
        creator: Principal::Account(account_id(seed)),
        created_at: UtcSecond::from_unix_seconds(1),
        revision: quantity(Revision::new(1))?,
        modes: ChannelModes::default(),
        key_verifier: None,
        member_limit: None,
        topic: None,
        memberships: Vec::new(),
        role_grants: vec![(account_id(seed), Role::Owner)],
        bans: Vec::new(),
        exceptions: Vec::new(),
        invite_exceptions: Vec::new(),
        invites: Vec::new(),
        history: HistoryPolicy::Off,
        e2ee_removal_pending: Vec::new(),
        admin_quarantined: false,
    })
}

fn minimal_sanction(seed: u8) -> Result<DurableSanction, StorageError> {
    Ok(DurableSanction {
        actor: Principal::Account(account_id(seed)),
        target: Principal::Guest(UserId::from_bytes([seed; 16])),
        channel_id: None,
        action: ModerationAction::Mute,
        reason_code: ModerationReasonCode::Spam,
        reason: None,
        created_at: UtcSecond::from_unix_seconds(1),
        expires_at: None,
        revision: quantity(Revision::new(1))?,
    })
}

fn replace_encoded_text(bytes: &mut [u8], before: &str, after: &str) -> Result<(), StorageError> {
    assert_eq!(before.len(), after.len());
    let offsets = bytes
        .windows(before.len())
        .enumerate()
        .filter_map(|(offset, bytes)| (bytes == before.as_bytes()).then_some(offset))
        .collect::<Vec<_>>();
    assert_eq!(offsets.len(), 1);
    let offset = *offsets.first().ok_or(StorageError::InvalidEncoding)?;
    bytes
        .get_mut(offset..offset + after.len())
        .ok_or(StorageError::InvalidEncoding)?
        .copy_from_slice(after.as_bytes());
    Ok(())
}

#[test]
fn channel_codec_rejects_invalid_topic_text() -> Result<(), StorageError> {
    for invalid in [
        "bad\ntext",
        "bad\rtext",
        "bad\0text",
        "bad\u{1b}text",
        "bad\u{7f}text",
    ] {
        let mut channel = minimal_channel(73)?;
        let placeholder = "x".repeat(invalid.len());
        channel.topic = Some(DurableTopic {
            text: placeholder.clone(),
            message_id: MessageId::from_bytes([74; 16]),
            setter: UserId::from_bytes([75; 16]),
            set_at: UtcSecond::from_unix_seconds(1),
        });
        let mut bytes = ChannelRecordBody::encode(&channel)?;
        replace_encoded_text(&mut bytes, &placeholder, invalid)?;
        assert_eq!(
            ChannelRecordBody::decode(&bytes).map(|_| ()),
            Err(StorageError::InvalidEncoding)
        );
        channel
            .topic
            .as_mut()
            .ok_or(StorageError::InvalidEncoding)?
            .text = invalid.to_owned();
        assert!(ChannelRecordBody::encode(&channel).is_err());
    }
    Ok(())
}

#[test]
fn channel_codec_rejects_invalid_or_noncanonical_masks_in_every_list() -> Result<(), StorageError> {
    for invalid in [
        "$n:a\nb",
        "$n:a\tb",
        "$n:ABC",
        "$n:a**b",
        "$q:$n:ABC",
        "$q:$c:a**b",
        "$q:$q:$n:a",
        "$x:abc",
        "$a:bad",
        "$u:bad",
    ] {
        for list in 0..3 {
            let mut channel = minimal_channel(73)?;
            let placeholder = format!("$n:{}", "x".repeat(invalid.len() - 3));
            let entries = match list {
                0 => &mut channel.bans,
                1 => &mut channel.exceptions,
                _ => &mut channel.invite_exceptions,
            };
            entries.push(DurableListEntry {
                entry_id: EntryId::from_bytes([76; 16]),
                mask: placeholder.clone(),
                setter: channel.creator,
                created_at: channel.created_at,
            });
            let mut bytes = ChannelRecordBody::encode(&channel)?;
            replace_encoded_text(&mut bytes, &placeholder, invalid)?;
            assert_eq!(
                ChannelRecordBody::decode(&bytes).map(|_| ()),
                Err(StorageError::InvalidEncoding)
            );
            let entries = match list {
                0 => &mut channel.bans,
                1 => &mut channel.exceptions,
                _ => &mut channel.invite_exceptions,
            };
            entries
                .first_mut()
                .ok_or(StorageError::InvalidEncoding)?
                .mask = invalid.to_owned();
            assert!(ChannelRecordBody::encode(&channel).is_err());
        }
    }
    Ok(())
}

#[test]
fn channel_codec_preserves_valid_topic_and_mask_forms() -> Result<(), Box<dyn Error>> {
    let masks = [
        format!("$a:{}", account_id(73).random().to_text()),
        format!("$u:{}", UserId::from_bytes([74; 16]).to_base64url()),
        "$n:a*b?".to_owned(),
        "$c:AbC*".to_owned(),
    ];
    for topic in ["", "a\tb", "café"] {
        for mask in masks
            .iter()
            .flat_map(|mask| [mask.clone(), format!("$q:{mask}")])
        {
            let mut channel = minimal_channel(73)?;
            channel.topic = Some(DurableTopic {
                text: topic.to_owned(),
                message_id: MessageId::from_bytes([74; 16]),
                setter: UserId::from_bytes([75; 16]),
                set_at: channel.created_at,
            });
            channel.bans.push(DurableListEntry {
                entry_id: EntryId::from_bytes([76; 16]),
                mask: mask.clone(),
                setter: channel.creator,
                created_at: channel.created_at,
            });
            let encoded = ChannelRecordBody::encode(&channel)?;
            let restored = ChannelRecordBody::decode(&encoded)?;
            assert_eq!(
                restored
                    .topic
                    .as_ref()
                    .ok_or(StorageError::InvalidEncoding)?
                    .text,
                topic
            );
            assert_eq!(
                restored
                    .bans
                    .first()
                    .ok_or(StorageError::InvalidEncoding)?
                    .mask,
                mask
            );
            assert_eq!(ChannelRecordBody::encode(&restored)?, encoded);
        }
    }
    Ok(())
}

fn full_account() -> Result<DurableAccount, Box<dyn Error>> {
    let mut contacts: Vec<AccountId> = (1..=3_u8).map(account_id).collect();
    contacts.sort();
    Ok(DurableAccount {
        account_id: account_id(9),
        label: Some(agenc_relay_domain::AccountLabelValue::parse("Alice.9")?),
        presence: PresencePolicy::Public,
        guest_direct_messages: GuestDirectMessagePolicy::Deny,
        direct_messages: DirectMessagePolicy::Contacts,
        contacts,
        reserved_nicknames: vec![NicknameValue::parse("Alice")?, NicknameValue::parse("bob")?],
        session_generation: Generation::new(7)?,
        revision: Revision::new(42)?,
        admin_suspension_expires_at: Some(UtcSecond::from_unix_seconds(1_700_000_100)),
    })
}

fn full_channel() -> Result<DurableChannel, Box<dyn Error>> {
    let entry = |seed: u8, mask: &str| -> Result<DurableListEntry, Box<dyn Error>> {
        Ok(DurableListEntry {
            entry_id: EntryId::from_bytes([seed; 16]),
            mask: mask.to_owned(),
            setter: Principal::Guest(UserId::from_bytes([seed; 16])),
            created_at: UtcSecond::from_unix_seconds(u64::from(seed)),
        })
    };
    Ok(DurableChannel {
        channel_id: ChannelInstanceId::from_bytes([3; 16]),
        name: ChannelNameValue::parse("#Full-Channel")?,
        scope: ChannelScope::Global,
        visibility: Visibility::Secret,
        content_policy: ContentPolicy::E2eeBound,
        persistence: PersistencePolicy::Registered,
        creator: Principal::Account(account_id(1)),
        created_at: UtcSecond::from_unix_seconds(1_700_000_000),
        revision: Revision::new(99)?,
        modes: ChannelModes {
            invite_only: true,
            moderated: true,
            topic_protected: false,
            join_key: true,
        },
        key_verifier: Some(ChannelKeyVerifier::new([14; 16], [15; 32])),
        member_limit: Some(512),
        topic: Some(DurableTopic {
            text: "topic text".to_owned(),
            message_id: MessageId::from_bytes([5; 16]),
            setter: UserId::from_bytes([6; 16]),
            set_at: UtcSecond::from_unix_seconds(1_700_000_001),
        }),
        memberships: Vec::new(),
        role_grants: vec![(account_id(1), Role::Owner), (account_id(2), Role::Voice)],
        bans: vec![entry(10, "$q:$n:spam*")?, entry(11, "$c:*.example")?],
        exceptions: vec![entry(12, "$u:AAAAAAAAAAAAAAAAAAAAAA")?],
        invite_exceptions: vec![entry(13, "$a:a_AQEBAQEBAQEBAQEBAQEBAQ")?],
        invites: Vec::new(),
        history: HistoryPolicy::Off,
        e2ee_removal_pending: Vec::new(),
        admin_quarantined: true,
    })
}

fn complete_channel() -> Result<DurableChannel, Box<dyn Error>> {
    let mut channel = full_channel()?;
    channel.memberships = vec![
        DurableMembership {
            user_id: UserId::from_bytes([20; 16]),
            account_id: Some(account_id(1)),
            session_role: Role::Member,
            effective_role: Role::Owner,
            membership_revision: Revision::new(80)?,
            joined_at: UtcSecond::from_unix_seconds(1_700_000_010),
        },
        DurableMembership {
            user_id: UserId::from_bytes([21; 16]),
            account_id: Some(account_id(2)),
            session_role: Role::Member,
            effective_role: Role::Voice,
            membership_revision: Revision::new(90)?,
            joined_at: UtcSecond::from_unix_seconds(1_700_000_020),
        },
    ];
    channel.invites = vec![DurableInvite {
        invite_id: InviteId::from_bytes([30; 16]),
        target: Principal::Account(account_id(2)),
        inviter: UserId::from_bytes([20; 16]),
        creation_revision: Revision::new(99)?,
        expires_at_utc: UtcSecond::from_unix_seconds(1_700_000_600),
    }];
    channel.e2ee_removal_pending = vec![UserId::from_bytes([21; 16])];
    Ok(channel)
}

fn full_session() -> Result<DurableSession, Box<dyn Error>> {
    Ok(DurableSession {
        session_id: SessionId::from_bytes([40; 16]),
        user_id: UserId::from_bytes([41; 16]),
        home_server_id: ServerId::from_bytes([42; 16]),
        account_id: Some(account_id(1)),
        account_session_generation: Generation::new(7)?,
        generation: Generation::new(8)?,
        nickname: NicknameValue::parse("Alice")?,
        display_name: DisplayNameValue::prepare("Alice Example")?,
        public_cloak: PublicCloak::parse("abcdefghij", "abcdefghijklmnop")?,
        away: Some("reviewing storage".to_owned()),
        operator_notices: true,
        connection_nonce: [43; 32],
        negotiated_capability_hash: [44; 32],
        joined_channels: vec![
            ChannelInstanceId::from_bytes([3; 16]),
            ChannelInstanceId::from_bytes([4; 16]),
        ],
        created_at_utc: UtcSecond::from_unix_seconds(1_700_000_000),
        revision: Revision::new(99)?,
    })
}

fn full_sanction() -> Result<DurableSanction, Box<dyn Error>> {
    Ok(DurableSanction {
        actor: Principal::Account(account_id(1)),
        target: Principal::Account(account_id(2)),
        channel_id: Some(ChannelInstanceId::from_bytes([3; 16])),
        action: ModerationAction::Suspend,
        reason_code: ModerationReasonCode::Security,
        reason: Some("free text".to_owned()),
        created_at: UtcSecond::from_unix_seconds(10),
        expires_at: Some(UtcSecond::from_unix_seconds(20)),
        revision: Revision::new(5)?,
    })
}

#[test]
fn minimal_bodies_match_their_golden_vectors() -> Result<(), Box<dyn Error>> {
    let account = AccountRecordBody::encode(&minimal_account(7)?)?;
    let mut expected = vec![0, 2];
    expected.extend_from_slice(&[7; 16]);
    expected.extend_from_slice(&[0, 1, 0, 0]);
    expected.extend_from_slice(&[0; 4]);
    expected.extend_from_slice(&[0; 4]);
    expected.extend_from_slice(&1_u64.to_be_bytes());
    expected.extend_from_slice(&1_u64.to_be_bytes());
    expected.push(0);
    assert_eq!(account, expected);
    assert_eq!(account.len(), 47);

    let session = SessionRecordBody::encode(&minimal_session(7)?)?;
    let mut expected = vec![0, 1];
    expected.extend_from_slice(&[7; 16]);
    expected.extend_from_slice(&[8; 16]);
    expected.extend_from_slice(&[9; 16]);
    expected.push(1);
    expected.extend_from_slice(&[7; 16]);
    expected.extend_from_slice(&1_u64.to_be_bytes());
    expected.extend_from_slice(&1_u64.to_be_bytes());
    expected.extend_from_slice(&7_u32.to_be_bytes());
    expected.extend_from_slice(b"fixture");
    expected.extend_from_slice(&7_u32.to_be_bytes());
    expected.extend_from_slice(b"Fixture");
    expected.extend_from_slice(b"aaaaaaaaaa");
    expected.extend_from_slice(b"bbbbbbbbbbbbbbbb");
    expected.extend_from_slice(&[0, 0]);
    expected.extend_from_slice(&[10; 32]);
    expected.extend_from_slice(&[11; 32]);
    expected.extend_from_slice(&0_u32.to_be_bytes());
    expected.extend_from_slice(&1_u64.to_be_bytes());
    expected.extend_from_slice(&1_u64.to_be_bytes());
    assert_eq!(session, expected);
    assert_eq!(session.len(), 217);

    let channel = ChannelRecordBody::encode(&minimal_channel(7)?)?;
    let mut expected = vec![0, 4];
    expected.extend_from_slice(&[7; 16]);
    expected.extend_from_slice(&8_u32.to_be_bytes());
    expected.extend_from_slice(b"#fixture");
    expected.extend_from_slice(&[0, 0, 0, 1]);
    expected.push(1);
    expected.extend_from_slice(&[7; 16]);
    expected.extend_from_slice(&1_u64.to_be_bytes());
    expected.extend_from_slice(&1_u64.to_be_bytes());
    expected.extend_from_slice(&[0b0100, 0, 0, 0]);
    expected.extend_from_slice(&0_u32.to_be_bytes());
    expected.extend_from_slice(&1_u32.to_be_bytes());
    expected.extend_from_slice(&[7; 16]);
    expected.push(5);
    expected.extend_from_slice(&[0; 22]);
    assert_eq!(channel, expected);
    assert_eq!(channel.len(), 118);

    let sanction = SanctionRecordBody::encode(&minimal_sanction(7)?)?;
    let mut expected = vec![0, 1, 1];
    expected.extend_from_slice(&[7; 16]);
    expected.push(0);
    expected.extend_from_slice(&[7; 16]);
    expected.extend_from_slice(&[0, 0, 0, 0]);
    expected.extend_from_slice(&1_u64.to_be_bytes());
    expected.push(0);
    expected.extend_from_slice(&1_u64.to_be_bytes());
    assert_eq!(sanction, expected);
    assert_eq!(sanction.len(), 57);
    Ok(())
}

#[test]
fn full_bodies_round_trip_and_admit_through_the_envelope() -> Result<(), Box<dyn Error>> {
    let account = full_account()?;
    let encoded = AccountRecordBody::encode(&account)?;
    assert!(AccountRecordBody::decode(&encoded)? == account);
    PersistentRecordValue::new(
        TableId::Account,
        LIVE_RECORD_KIND,
        42,
        7,
        None,
        Vec::new(),
        encoded,
    )?;

    let session = full_session()?;
    let encoded = SessionRecordBody::encode(&session)?;
    assert!(SessionRecordBody::decode(&encoded)? == session);
    PersistentRecordValue::new(
        TableId::Session,
        LIVE_RECORD_KIND,
        99,
        8,
        None,
        Vec::new(),
        encoded,
    )?;

    let channel = complete_channel()?;
    let encoded = ChannelRecordBody::encode(&channel)?;
    assert!(ChannelRecordBody::decode(&encoded)? == channel);
    PersistentRecordValue::new(
        TableId::Channel,
        LIVE_RECORD_KIND,
        99,
        0,
        None,
        Vec::new(),
        encoded,
    )?;

    let sanction = full_sanction()?;
    let encoded = SanctionRecordBody::encode(&sanction)?;
    assert!(SanctionRecordBody::decode(&encoded)? == sanction);
    PersistentRecordValue::new(
        TableId::Sanction,
        LIVE_RECORD_KIND,
        5,
        0,
        None,
        Vec::new(),
        encoded,
    )?;
    Ok(())
}

#[test]
fn channel_body_requires_the_complete_current_format() -> Result<(), Box<dyn Error>> {
    for channel in [minimal_channel(7)?, full_channel()?] {
        assert_eq!(
            ChannelRecordBody::decode(&ChannelRecordBody::encode(&channel)?)?,
            channel
        );
        for version in [1, 2, 3] {
            assert_eq!(
                ChannelRecordBody::decode(&legacy_channel_body(&channel, version)?),
                Err(StorageError::UnsupportedVersion)
            );
        }
    }

    let mut missing = full_channel()?;
    missing.key_verifier = None;
    assert_eq!(
        ChannelRecordBody::encode(&missing),
        Err(StorageError::LimitExceeded)
    );
    let mut stray = minimal_channel(7)?;
    stray.key_verifier = Some(ChannelKeyVerifier::new([1; 16], [2; 32]));
    assert_eq!(
        ChannelRecordBody::encode(&stray),
        Err(StorageError::LimitExceeded)
    );
    Ok(())
}

#[test]
fn account_body_rejects_the_obsolete_suspension_free_format() -> Result<(), Box<dyn Error>> {
    let mut legacy = AccountRecordBody::encode(&full_account()?)?;
    set(&mut legacy, 1, 1)?;
    let retained = legacy
        .len()
        .checked_sub(9)
        .ok_or(StorageError::InvalidEncoding)?;
    legacy.truncate(retained);
    assert_eq!(
        AccountRecordBody::decode(&legacy),
        Err(StorageError::UnsupportedVersion)
    );
    Ok(())
}

#[test]
fn channel_name_body_requires_an_explicit_channel_identity() -> Result<(), Box<dyn Error>> {
    let channel_id = ChannelInstanceId::from_bytes([70; 16]);
    let name = ChannelNameValue::parse("#Stable-Name")?;
    let encoded = ChannelNameRecordBody::encode(channel_id, &name)?;
    let decoded = ChannelNameRecordBody::decode(&encoded)?;
    assert_eq!(decoded.channel_id, channel_id);
    assert!(decoded.name == name);

    assert!(ChannelNameRecordBody::decode(b"#Stable-Name").is_err());

    let mut trailing = encoded;
    trailing.push(0);
    assert!(matches!(
        ChannelNameRecordBody::decode(&trailing),
        Err(StorageError::InvalidEncoding)
    ));
    assert!(matches!(
        ChannelNameRecordBody::decode(&[0; MAX_CHANNEL_NAME_RECORD_BODY_BYTES + 1]),
        Err(StorageError::LimitExceeded)
    ));
    Ok(())
}

#[test]
fn every_strict_table_rejects_truncation_trailing_bytes_version_and_opaque_bodies()
-> Result<(), Box<dyn Error>> {
    let bodies = [
        (
            TableId::Account,
            AccountRecordBody::encode(&full_account()?)?,
        ),
        (
            TableId::Session,
            SessionRecordBody::encode(&full_session()?)?,
        ),
        (
            TableId::Channel,
            ChannelRecordBody::encode(&complete_channel()?)?,
        ),
        (
            TableId::Sanction,
            SanctionRecordBody::encode(&full_sanction()?)?,
        ),
    ];
    for (table, encoded) in bodies {
        let admit = |body: Vec<u8>| {
            PersistentRecordValue::new(table, LIVE_RECORD_KIND, 1, 1, None, Vec::new(), body)
                .map(|_| ())
        };
        assert!(admit(encoded.clone()).is_ok());
        for cut in 0..encoded.len() {
            assert_eq!(
                admit(encoded.get(..cut).unwrap_or_default().to_vec()),
                Err(StorageError::InvalidEncoding),
                "truncation at {cut} admitted for {table:?}"
            );
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(admit(trailing), Err(StorageError::InvalidEncoding));
        let mut wrong_version = encoded.clone();
        set(&mut wrong_version, 1, 0xff)?;
        assert_eq!(admit(wrong_version), Err(StorageError::UnsupportedVersion));
        assert_eq!(admit(vec![1]), Err(StorageError::InvalidEncoding));
        assert_eq!(admit(Vec::new()), Err(StorageError::InvalidEncoding));
        PersistentRecordValue::new(table, 2, 1, 0, None, Vec::new(), vec![1])?;
    }
    Ok(())
}

#[test]
fn decoders_reject_each_closed_enum_ordering_and_ceiling_violation() -> Result<(), Box<dyn Error>> {
    let mut account = full_account()?;
    account.contacts.reverse();
    assert_eq!(
        AccountRecordBody::encode(&account),
        Err(StorageError::LimitExceeded)
    );
    let encoded = AccountRecordBody::encode(&full_account()?)?;
    let mut bad_presence = encoded.clone();
    set(&mut bad_presence, 2 + 16 + 1 + 4 + 7, 9)?;
    assert_eq!(
        AccountRecordBody::decode(&bad_presence),
        Err(StorageError::InvalidEncoding)
    );
    let mut oversized = full_account()?;
    oversized.contacts = (0..=MAX_CONTACTS_PER_ACCOUNT)
        .map(|index| {
            let [high, low] = u16::try_from(index).unwrap_or(u16::MAX).to_be_bytes();
            let mut bytes = [0_u8; 16];
            bytes[0] = high;
            bytes[1] = low;
            AccountRandomId::from_bytes(bytes).to_account_id()
        })
        .collect();
    assert_eq!(
        AccountRecordBody::encode(&oversized),
        Err(StorageError::LimitExceeded)
    );
    let mut too_many_nicknames = full_account()?;
    too_many_nicknames.reserved_nicknames = (0..=MAX_RESERVED_NICKNAMES)
        .map(|index| NicknameValue::parse(&format!("nick{index}")))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        AccountRecordBody::encode(&too_many_nicknames),
        Err(StorageError::LimitExceeded)
    );
    assert_eq!(
        AccountRecordBody::decode(&vec![0; MAX_ACCOUNT_RECORD_BODY_BYTES + 1]),
        Err(StorageError::LimitExceeded)
    );

    let mut unsorted_session = full_session()?;
    unsorted_session.joined_channels.reverse();
    assert_eq!(
        SessionRecordBody::encode(&unsorted_session),
        Err(StorageError::InvalidEncoding)
    );
    let mut empty_away = full_session()?;
    empty_away.away = Some(String::new());
    assert_eq!(
        SessionRecordBody::encode(&empty_away),
        Err(StorageError::InvalidEncoding)
    );
    let mut guest_generation = full_session()?;
    guest_generation.account_id = None;
    assert_eq!(
        SessionRecordBody::encode(&guest_generation),
        Err(StorageError::InvalidEncoding)
    );
    let mut zero_revision = full_session()?;
    zero_revision.revision = Revision::new(0)?;
    assert_eq!(
        SessionRecordBody::encode(&zero_revision),
        Err(StorageError::InvalidEncoding)
    );
    assert_eq!(
        SessionRecordBody::decode(&vec![0; MAX_SESSION_RECORD_BODY_BYTES + 1]),
        Err(StorageError::LimitExceeded)
    );

    let mut local_ephemeral = full_channel()?;
    local_ephemeral.name = ChannelNameValue::parse("&ephemeral")?;
    local_ephemeral.scope = ChannelScope::Local;
    local_ephemeral.persistence = PersistencePolicy::Ephemeral;
    assert_eq!(
        ChannelRecordBody::encode(&local_ephemeral),
        Err(StorageError::LimitExceeded)
    );
    let mut global_ephemeral = minimal_channel(7)?;
    global_ephemeral.persistence = PersistencePolicy::Ephemeral;
    global_ephemeral.role_grants.clear();
    global_ephemeral.memberships.push(DurableMembership {
        user_id: UserId::from_bytes([8; 16]),
        account_id: None,
        session_role: Role::Owner,
        effective_role: Role::Owner,
        membership_revision: Revision::new(1)?,
        joined_at: UtcSecond::from_unix_seconds(1),
    });
    assert!(ChannelRecordBody::encode(&global_ephemeral).is_ok());
    let mut too_many_bans = full_channel()?;
    too_many_bans.bans = (0..=MAX_MASK_ENTRIES_PER_LIST)
        .map(|index| DurableListEntry {
            entry_id: EntryId::from_bytes([1; 16]),
            mask: format!("$n:m{index}"),
            setter: Principal::Guest(UserId::from_bytes([1; 16])),
            created_at: UtcSecond::from_unix_seconds(1),
        })
        .collect();
    assert_eq!(
        ChannelRecordBody::encode(&too_many_bans),
        Err(StorageError::LimitExceeded)
    );
    let encoded = ChannelRecordBody::encode(&full_channel()?)?;
    let mut bad_modes = encoded.clone();
    let modes_offset = 2 + 16 + 4 + "#Full-Channel".len() + 4 + 17 + 8 + 8;
    set(&mut bad_modes, modes_offset, 0b1_0000)?;
    assert_eq!(
        ChannelRecordBody::decode(&bad_modes),
        Err(StorageError::InvalidEncoding)
    );
    let mut member_grant = full_channel()?;
    member_grant.role_grants = vec![(account_id(1), Role::Member)];
    let encoded_member = ChannelRecordBody::encode(&member_grant)?;
    assert_eq!(
        ChannelRecordBody::decode(&encoded_member),
        Err(StorageError::InvalidEncoding)
    );
    assert_eq!(
        ChannelRecordBody::decode(&vec![0; MAX_CHANNEL_RECORD_BODY_BYTES + 1]),
        Err(StorageError::LimitExceeded)
    );

    let encoded = SanctionRecordBody::encode(&full_sanction()?)?;
    let mut bad_channel_flag = encoded.clone();
    set(&mut bad_channel_flag, 2 + 17 + 17, 2)?;
    assert_eq!(
        SanctionRecordBody::decode(&bad_channel_flag),
        Err(StorageError::InvalidEncoding)
    );
    let mut bad_action = encoded.clone();
    set(&mut bad_action, 2 + 17 + 17 + 1 + 16, 4)?;
    assert_eq!(
        SanctionRecordBody::decode(&bad_action),
        Err(StorageError::InvalidEncoding)
    );
    assert_eq!(
        SanctionRecordBody::decode(&vec![0; MAX_SANCTION_RECORD_BODY_BYTES + 1]),
        Err(StorageError::LimitExceeded)
    );
    Ok(())
}

#[test]
fn body_ceilings_are_derived_from_the_domain_limits() {
    assert_eq!(MAX_ACCOUNT_RECORD_BODY_BYTES, 16_271);
    assert_eq!(MAX_SESSION_RECORD_BODY_BYTES, 4_655);
    assert_eq!(MAX_CHANNEL_RECORD_BODY_BYTES, 5_824_355);
    assert_eq!(MAX_SANCTION_RECORD_BODY_BYTES, 597);
}

#[test]
fn a_persisted_session_rebuilds_only_from_a_consistent_record() -> Result<(), Box<dyn Error>> {
    assert!(full_session()?.into_state().is_ok());
    let mut unsorted = full_session()?;
    unsorted.joined_channels.reverse();
    assert_eq!(
        unsorted.into_state().err(),
        Some(DomainError::InvalidArgument),
        "unsorted channels"
    );
    let mut guest_with_generation = full_session()?;
    guest_with_generation.account_id = None;
    assert_eq!(
        guest_with_generation.into_state().err(),
        Some(DomainError::InvalidArgument),
        "a guest with an account generation"
    );
    let mut account_without_generation = full_session()?;
    account_without_generation.account_session_generation = Generation::new(0)?;
    assert_eq!(
        account_without_generation.into_state().err(),
        Some(DomainError::InvalidArgument),
        "an account without a generation"
    );
    let mut unborn = full_session()?;
    unborn.generation = Generation::new(0)?;
    assert_eq!(
        unborn.into_state().err(),
        Some(DomainError::InvalidArgument),
        "a zero session generation"
    );
    Ok(())
}

#[test]
fn a_channel_record_needs_live_membership_and_invite_revisions() -> Result<(), Box<dyn Error>> {
    assert!(ChannelRecordBody::encode(&complete_channel()?).is_ok());
    let mut unborn_membership = complete_channel()?;
    if let Some(membership) = unborn_membership.memberships.first_mut() {
        membership.membership_revision = Revision::new(0)?;
    }
    assert_eq!(
        ChannelRecordBody::encode(&unborn_membership),
        Err(StorageError::LimitExceeded),
        "a membership at revision zero"
    );
    let mut unborn_invite = complete_channel()?;
    if let Some(invite) = unborn_invite.invites.first_mut() {
        invite.creation_revision = Revision::new(0)?;
    }
    assert_eq!(
        ChannelRecordBody::encode(&unborn_invite),
        Err(StorageError::LimitExceeded),
        "an invite created at revision zero"
    );
    Ok(())
}
