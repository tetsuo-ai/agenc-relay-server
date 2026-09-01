//! Stage 06 persisted-domain body codecs: golden vectors, round trips, and rejections.

#![forbid(unsafe_code)]

use std::error::Error;

use agenc_ircd_domain::{
    ChannelKeyVerifier, ChannelModes, ChannelNameValue, ChannelScope, ContentPolicy,
    DirectMessagePolicy, DurableAccount, DurableChannel, DurableListEntry, DurableSanction,
    DurableTopic, GuestDirectMessagePolicy, HistoryPolicy, MAX_CONTACTS_PER_ACCOUNT,
    MAX_MASK_ENTRIES_PER_LIST, MAX_RESERVED_NICKNAMES, ModerationAction, ModerationReasonCode,
    NicknameValue, PersistencePolicy, PresencePolicy, Principal, Role, Visibility,
};
use agenc_ircd_storage::{
    AccountRecordBody, ChannelRecordBody, LIVE_RECORD_KIND, MAX_ACCOUNT_RECORD_BODY_BYTES,
    MAX_CHANNEL_RECORD_BODY_BYTES, MAX_SANCTION_RECORD_BODY_BYTES, PersistentRecordValue,
    SanctionRecordBody, StorageError, TableId,
};
use agenc_ircd_types::{
    AccountId, AccountRandomId, ChannelInstanceId, EntryId, Generation, MessageId, Revision,
    UserId, UtcSecond,
};

/// Returns the smallest valid live body for a strict domain table, or an empty body for
/// tables whose live bodies remain opaque to storage.
pub(crate) fn live_body(table: TableId, seed: u8) -> Result<Vec<u8>, StorageError> {
    match table {
        TableId::Account => AccountRecordBody::encode(&minimal_account(seed)?),
        TableId::Channel => ChannelRecordBody::encode(&minimal_channel(seed)?),
        TableId::Sanction => SanctionRecordBody::encode(&minimal_sanction(seed)?),
        _ => Ok(Vec::new()),
    }
}

fn set(bytes: &mut [u8], index: usize, value: u8) -> Result<(), StorageError> {
    *bytes.get_mut(index).ok_or(StorageError::InvalidEncoding)? = value;
    Ok(())
}

fn channel_key_verifier_offset(channel: &DurableChannel) -> usize {
    2 + 16 + 4 + channel.name.presentation().len() + 4 + 17 + 8 + 8 + 1
}

fn account_id(seed: u8) -> AccountId {
    AccountRandomId::from_bytes([seed; 16]).to_account_id()
}

fn quantity<T>(value: Result<T, agenc_ircd_types::ValidationError>) -> Result<T, StorageError> {
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
        role_grants: vec![(account_id(seed), Role::Owner)],
        bans: Vec::new(),
        exceptions: Vec::new(),
        invite_exceptions: Vec::new(),
        history: HistoryPolicy::Off,
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

fn full_account() -> Result<DurableAccount, Box<dyn Error>> {
    let mut contacts: Vec<AccountId> = (1..=3_u8).map(account_id).collect();
    contacts.sort();
    Ok(DurableAccount {
        account_id: account_id(9),
        label: Some(agenc_ircd_domain::AccountLabelValue::parse("Alice.9")?),
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
        creator: Principal::Guest(UserId::from_bytes([4; 16])),
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
        role_grants: vec![(account_id(1), Role::Owner), (account_id(2), Role::Voice)],
        bans: vec![entry(10, "$q:$n:spam*")?, entry(11, "$c:*.example")?],
        exceptions: vec![entry(12, "$u:AAAAAAAAAAAAAAAAAAAAAA")?],
        invite_exceptions: vec![entry(13, "$a:a_AQEBAQEBAQEBAQEBAQEBAQ")?],
        history: HistoryPolicy::Off,
        admin_quarantined: true,
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

    let channel = ChannelRecordBody::encode(&minimal_channel(7)?)?;
    let mut expected = vec![0, 3];
    expected.extend_from_slice(&[7; 16]);
    expected.extend_from_slice(&8_u32.to_be_bytes());
    expected.extend_from_slice(b"#fixture");
    expected.extend_from_slice(&[0, 0, 0, 1]);
    expected.push(1);
    expected.extend_from_slice(&[7; 16]);
    expected.extend_from_slice(&1_u64.to_be_bytes());
    expected.extend_from_slice(&1_u64.to_be_bytes());
    expected.extend_from_slice(&[0b0100, 0, 0, 0]);
    expected.extend_from_slice(&1_u32.to_be_bytes());
    expected.extend_from_slice(&[7; 16]);
    expected.push(5);
    expected.extend_from_slice(&[0; 12]);
    expected.extend_from_slice(&[0, 0]);
    assert_eq!(channel, expected);
    assert_eq!(channel.len(), 106);

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

    let channel = full_channel()?;
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
fn channel_body_v1_compatibility_is_limited_to_unkeyed_rows() -> Result<(), Box<dyn Error>> {
    let unkeyed = minimal_channel(7)?;
    let mut legacy_unkeyed = ChannelRecordBody::encode(&unkeyed)?;
    set(&mut legacy_unkeyed, 1, 1)?;
    legacy_unkeyed.pop();
    let verifier_offset = channel_key_verifier_offset(&unkeyed);
    legacy_unkeyed
        .drain(verifier_offset..verifier_offset + 1)
        .for_each(drop);
    assert!(ChannelRecordBody::decode(&legacy_unkeyed)? == unkeyed);

    let keyed = full_channel()?;
    let mut legacy_keyed = ChannelRecordBody::encode(&keyed)?;
    set(&mut legacy_keyed, 1, 1)?;
    legacy_keyed.pop();
    let verifier_offset = channel_key_verifier_offset(&keyed);
    legacy_keyed
        .drain(verifier_offset..verifier_offset + 49)
        .for_each(drop);
    assert_eq!(
        ChannelRecordBody::decode(&legacy_keyed),
        Err(StorageError::InvalidEncoding)
    );

    let mut version_two = ChannelRecordBody::encode(&keyed)?;
    set(&mut version_two, 1, 2)?;
    version_two.pop();
    let mut expected_version_two = keyed.clone();
    expected_version_two.admin_quarantined = false;
    assert!(ChannelRecordBody::decode(&version_two)? == expected_version_two);

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
fn account_body_v1_defaults_the_durable_admin_suspension() -> Result<(), Box<dyn Error>> {
    let mut legacy = AccountRecordBody::encode(&full_account()?)?;
    set(&mut legacy, 1, 1)?;
    let retained = legacy
        .len()
        .checked_sub(9)
        .ok_or(StorageError::InvalidEncoding)?;
    legacy.truncate(retained);
    let mut expected = full_account()?;
    expected.admin_suspension_expires_at = None;
    assert!(AccountRecordBody::decode(&legacy)? == expected);
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
            TableId::Channel,
            ChannelRecordBody::encode(&full_channel()?)?,
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

    let mut ephemeral = full_channel()?;
    ephemeral.persistence = PersistencePolicy::Ephemeral;
    assert_eq!(
        ChannelRecordBody::encode(&ephemeral),
        Err(StorageError::LimitExceeded)
    );
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
    assert_eq!(MAX_CHANNEL_RECORD_BODY_BYTES, 1_167_258);
    assert_eq!(MAX_SANCTION_RECORD_BODY_BYTES, 597);
}
