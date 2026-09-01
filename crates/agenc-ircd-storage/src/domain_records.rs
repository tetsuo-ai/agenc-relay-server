//! Canonical body codecs for the persisted domain entities.
//!
//! Each body is a versioned, full-consumption, network-order encoding of one
//! domain projection. The envelope around it (`PersistentRecordValue`) carries
//! the table, record kind, revision, generation, expiry, and references; these
//! codecs own only the table-specific bytes and reject any body a live record
//! could not have produced.

use agenc_ircd_domain::{
    AccountLabelValue, ChannelKeyVerifier, ChannelModes, ChannelNameValue, ChannelScope,
    ContentPolicy, DirectMessagePolicy, DurableAccount, DurableChannel, DurableListEntry,
    DurableSanction, DurableTopic, GuestDirectMessagePolicy, HistoryPolicy,
    MAX_CONTACTS_PER_ACCOUNT, MAX_MASK_ENTRIES_PER_LIST, MAX_RESERVED_NICKNAMES,
    MAX_ROLE_GRANTS_PER_CHANNEL, ModerationAction, ModerationReasonCode, NicknameValue,
    PersistencePolicy, PresencePolicy, Principal, Role, Visibility,
};
use agenc_ircd_types::{
    AccountId, AccountRandomId, ChannelInstanceId, EntryId, Generation, MAX_TYPED_MASK_BYTES,
    MessageId, Revision, UserId, UtcSecond,
};

use crate::StorageError;
use crate::codec::{Decoder, Encoder};

/// Version prefix shared by every domain body codec.
const DOMAIN_BODY_VERSION: u16 = 1;
/// Account bodies gained durable administrative suspension state in version two.
const ACCOUNT_BODY_VERSION: u16 = 2;
/// Channel bodies gained persisted join-key verifier material in version two.
const CHANNEL_KEY_BODY_VERSION: u16 = 2;
/// Channel bodies gained durable administrative quarantine state in version three.
const CHANNEL_BODY_VERSION: u16 = 3;
/// Record kind of a live (non-tombstone) domain row.
pub const LIVE_RECORD_KIND: u16 = 1;

const IDENTIFIER_BYTES: usize = 16;
const PRINCIPAL_BYTES: usize = 1 + IDENTIFIER_BYTES;
const MAX_LABEL_BYTES: usize = 32;
const MAX_NICKNAME_BYTES: usize = 32;
const MAX_CHANNEL_NAME_BYTES: usize = 64;
const MAX_TOPIC_BYTES: usize = 1_024;
const MAX_REASON_BYTES: usize = 512;
const VECTOR_PREFIX_BYTES: usize = 4;
const LIST_ENTRY_BYTES: usize =
    IDENTIFIER_BYTES + VECTOR_PREFIX_BYTES + MAX_TYPED_MASK_BYTES + PRINCIPAL_BYTES + 8;

/// Exact ceiling of one encoded account body at every domain limit.
pub const MAX_ACCOUNT_RECORD_BODY_BYTES: usize = 2
    + IDENTIFIER_BYTES
    + 1
    + VECTOR_PREFIX_BYTES
    + MAX_LABEL_BYTES
    + 3
    + VECTOR_PREFIX_BYTES
    + MAX_CONTACTS_PER_ACCOUNT * IDENTIFIER_BYTES
    + VECTOR_PREFIX_BYTES
    + MAX_RESERVED_NICKNAMES * (VECTOR_PREFIX_BYTES + MAX_NICKNAME_BYTES)
    + 8
    + 8
    + 1
    + 8;
/// Exact ceiling of one encoded channel body at every domain limit.
pub const MAX_CHANNEL_RECORD_BODY_BYTES: usize = 2
    + IDENTIFIER_BYTES
    + VECTOR_PREFIX_BYTES
    + MAX_CHANNEL_NAME_BYTES
    + 4
    + PRINCIPAL_BYTES
    + 8
    + 8
    + 1
    + 1
    + 16
    + 32
    + 3
    + 1
    + VECTOR_PREFIX_BYTES
    + MAX_TOPIC_BYTES
    + IDENTIFIER_BYTES
    + IDENTIFIER_BYTES
    + 8
    + VECTOR_PREFIX_BYTES
    + MAX_ROLE_GRANTS_PER_CHANNEL * (IDENTIFIER_BYTES + 1)
    + 3 * (VECTOR_PREFIX_BYTES + MAX_MASK_ENTRIES_PER_LIST * LIST_ENTRY_BYTES)
    + 2;
/// Exact ceiling of one encoded sanction body at every domain limit.
pub const MAX_SANCTION_RECORD_BODY_BYTES: usize = 2
    + PRINCIPAL_BYTES
    + PRINCIPAL_BYTES
    + 1
    + IDENTIFIER_BYTES
    + 1
    + 1
    + 1
    + VECTOR_PREFIX_BYTES
    + MAX_REASON_BYTES
    + 8
    + 1
    + 8
    + 8;

/// Codec for live `account` rows.
pub struct AccountRecordBody;

impl AccountRecordBody {
    /// Encodes one account projection.
    pub fn encode(account: &DurableAccount) -> Result<Vec<u8>, StorageError> {
        if account.contacts.len() > MAX_CONTACTS_PER_ACCOUNT
            || account.reserved_nicknames.len() > MAX_RESERVED_NICKNAMES
            || !ascending(&account.contacts)
            || !ascending(&account.reserved_nicknames)
        {
            return Err(StorageError::LimitExceeded);
        }
        let mut encoder = Encoder::with_capacity(0, MAX_ACCOUNT_RECORD_BODY_BYTES)?;
        encoder.put_u16(ACCOUNT_BODY_VERSION)?;
        encoder.put_fixed(account.account_id.random().as_bytes())?;
        put_optional_text(
            &mut encoder,
            account.label.as_ref().map(AccountLabelValue::as_str),
        )?;
        encoder.put_fixed(&[
            presence_byte(account.presence),
            guest_policy_byte(account.guest_direct_messages),
            direct_policy_byte(account.direct_messages),
        ])?;
        put_count(&mut encoder, account.contacts.len())?;
        for contact in &account.contacts {
            encoder.put_fixed(contact.random().as_bytes())?;
        }
        put_count(&mut encoder, account.reserved_nicknames.len())?;
        for nickname in &account.reserved_nicknames {
            encoder.put_vector_u32(nickname.presentation().as_bytes())?;
        }
        encoder.put_u64(account.session_generation.get())?;
        encoder.put_u64(account.revision.get())?;
        put_optional_second(&mut encoder, account.admin_suspension_expires_at)?;
        Ok(encoder.finish())
    }

    /// Parses one full-consumption account body.
    pub fn decode(encoded: &[u8]) -> Result<DurableAccount, StorageError> {
        if encoded.len() > MAX_ACCOUNT_RECORD_BODY_BYTES {
            return Err(StorageError::LimitExceeded);
        }
        let mut decoder = Decoder::new(encoded);
        let version = decoder.u16()?;
        if !matches!(version, DOMAIN_BODY_VERSION | ACCOUNT_BODY_VERSION) {
            return Err(StorageError::UnsupportedVersion);
        }
        let account_id = read_account_id(&mut decoder)?;
        let label = optional_text(&mut decoder, MAX_LABEL_BYTES)?
            .map(|text| AccountLabelValue::parse(text).map_err(|_| StorageError::InvalidEncoding))
            .transpose()?;
        let presence = presence_from(byte(&mut decoder)?)?;
        let guest_direct_messages = guest_policy_from(byte(&mut decoder)?)?;
        let direct_messages = direct_policy_from(byte(&mut decoder)?)?;
        let contact_count = count(&mut decoder, MAX_CONTACTS_PER_ACCOUNT)?;
        let mut contacts = Vec::new();
        contacts
            .try_reserve_exact(contact_count)
            .map_err(|_| StorageError::AllocationFailed)?;
        for _ in 0..contact_count {
            contacts.push(read_account_id(&mut decoder)?);
        }
        let nickname_count = count(&mut decoder, MAX_RESERVED_NICKNAMES)?;
        let mut reserved_nicknames = Vec::new();
        reserved_nicknames
            .try_reserve_exact(nickname_count)
            .map_err(|_| StorageError::AllocationFailed)?;
        for _ in 0..nickname_count {
            let text = text(&mut decoder, MAX_NICKNAME_BYTES)?;
            reserved_nicknames
                .push(NicknameValue::parse(text).map_err(|_| StorageError::InvalidEncoding)?);
        }
        let session_generation = generation(&mut decoder)?;
        let revision = revision(&mut decoder)?;
        let admin_suspension_expires_at = if version == ACCOUNT_BODY_VERSION {
            optional_second(&mut decoder)?
        } else {
            None
        };
        decoder.finish()?;
        if !ascending(&contacts) || !ascending(&reserved_nicknames) {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(DurableAccount {
            account_id,
            label,
            presence,
            guest_direct_messages,
            direct_messages,
            contacts,
            reserved_nicknames,
            session_generation,
            revision,
            admin_suspension_expires_at,
        })
    }
}

/// Codec for live `channel` rows.
pub struct ChannelRecordBody;

impl ChannelRecordBody {
    /// Encodes one registered channel projection.
    pub fn encode(channel: &DurableChannel) -> Result<Vec<u8>, StorageError> {
        if channel.persistence != PersistencePolicy::Registered
            || channel.modes.join_key != channel.key_verifier.is_some()
            || channel.role_grants.len() > MAX_ROLE_GRANTS_PER_CHANNEL
            || !ascending(
                &channel
                    .role_grants
                    .iter()
                    .map(|(id, _)| *id)
                    .collect::<Vec<_>>(),
            )
            || [
                &channel.bans,
                &channel.exceptions,
                &channel.invite_exceptions,
            ]
            .iter()
            .any(|entries| entries.len() > MAX_MASK_ENTRIES_PER_LIST)
        {
            return Err(StorageError::LimitExceeded);
        }
        let mut encoder = Encoder::with_capacity(0, MAX_CHANNEL_RECORD_BODY_BYTES)?;
        encoder.put_u16(CHANNEL_BODY_VERSION)?;
        encoder.put_fixed(channel.channel_id.as_bytes())?;
        encoder.put_vector_u32(channel.name.presentation().as_bytes())?;
        encoder.put_fixed(&[
            scope_byte(channel.scope),
            visibility_byte(channel.visibility),
            content_policy_byte(channel.content_policy),
            persistence_byte(channel.persistence),
        ])?;
        put_principal(&mut encoder, channel.creator)?;
        encoder.put_u64(channel.created_at.get())?;
        encoder.put_u64(channel.revision.get())?;
        encoder.put_fixed(&[modes_byte(channel.modes)])?;
        put_key_verifier(&mut encoder, channel.key_verifier.as_ref())?;
        put_member_limit(&mut encoder, channel.member_limit)?;
        put_topic(&mut encoder, channel.topic.as_ref())?;
        put_count(&mut encoder, channel.role_grants.len())?;
        for (account_id, role) in &channel.role_grants {
            encoder.put_fixed(account_id.random().as_bytes())?;
            encoder.put_fixed(&[role_byte(*role)])?;
        }
        put_entries(&mut encoder, &channel.bans)?;
        put_entries(&mut encoder, &channel.exceptions)?;
        put_entries(&mut encoder, &channel.invite_exceptions)?;
        encoder.put_fixed(&[history_byte(channel.history)])?;
        encoder.put_fixed(&[bool_byte(channel.admin_quarantined)])?;
        Ok(encoder.finish())
    }

    /// Parses one full-consumption channel body.
    pub fn decode(encoded: &[u8]) -> Result<DurableChannel, StorageError> {
        if encoded.len() > MAX_CHANNEL_RECORD_BODY_BYTES {
            return Err(StorageError::LimitExceeded);
        }
        let mut decoder = Decoder::new(encoded);
        let version = decoder.u16()?;
        if !matches!(
            version,
            DOMAIN_BODY_VERSION | CHANNEL_KEY_BODY_VERSION | CHANNEL_BODY_VERSION
        ) {
            return Err(StorageError::UnsupportedVersion);
        }
        let channel = decode_channel(&mut decoder, version)?;
        decoder.finish()?;
        if channel.persistence != PersistencePolicy::Registered
            || channel.modes.join_key != channel.key_verifier.is_some()
        {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(channel)
    }
}

fn decode_channel(decoder: &mut Decoder<'_>, version: u16) -> Result<DurableChannel, StorageError> {
    let channel_id = ChannelInstanceId::from_bytes(decoder.array()?);
    let name = ChannelNameValue::parse(text(decoder, MAX_CHANNEL_NAME_BYTES)?)
        .map_err(|_| StorageError::InvalidEncoding)?;
    let scope = scope_from(byte(decoder)?)?;
    let visibility = visibility_from(byte(decoder)?)?;
    let content_policy = content_policy_from(byte(decoder)?)?;
    let persistence = persistence_from(byte(decoder)?)?;
    let creator = principal(decoder)?;
    let created_at = UtcSecond::from_unix_seconds(decoder.u64()?);
    let revision = revision(decoder)?;
    let modes = modes_from(byte(decoder)?)?;
    let key_verifier = if matches!(version, CHANNEL_KEY_BODY_VERSION | CHANNEL_BODY_VERSION) {
        key_verifier(decoder)?
    } else {
        None
    };
    let member_limit = member_limit(decoder)?;
    let topic = topic(decoder)?;
    let role_grants = role_grants(decoder)?;
    let bans = entries(decoder)?;
    let exceptions = entries(decoder)?;
    let invite_exceptions = entries(decoder)?;
    let history = history_from(byte(decoder)?)?;
    let admin_quarantined = if version == CHANNEL_BODY_VERSION {
        bool_from(byte(decoder)?)?
    } else {
        false
    };
    Ok(DurableChannel {
        channel_id,
        name,
        scope,
        visibility,
        content_policy,
        persistence,
        creator,
        created_at,
        revision,
        modes,
        key_verifier,
        member_limit,
        topic,
        role_grants,
        bans,
        exceptions,
        invite_exceptions,
        history,
        admin_quarantined,
    })
}

/// Codec for live `sanction` rows.
pub struct SanctionRecordBody;

impl SanctionRecordBody {
    /// Encodes one sanction projection.
    pub fn encode(sanction: &DurableSanction) -> Result<Vec<u8>, StorageError> {
        let mut encoder = Encoder::with_capacity(0, MAX_SANCTION_RECORD_BODY_BYTES)?;
        encoder.put_u16(DOMAIN_BODY_VERSION)?;
        put_principal(&mut encoder, sanction.actor)?;
        put_principal(&mut encoder, sanction.target)?;
        match sanction.channel_id {
            Some(channel_id) => {
                encoder.put_fixed(&[1])?;
                encoder.put_fixed(channel_id.as_bytes())?;
            }
            None => encoder.put_fixed(&[0])?,
        }
        encoder.put_fixed(&[
            action_byte(sanction.action),
            reason_code_byte(sanction.reason_code),
        ])?;
        put_optional_text(&mut encoder, sanction.reason.as_deref())?;
        encoder.put_u64(sanction.created_at.get())?;
        match sanction.expires_at {
            Some(expires_at) => {
                encoder.put_fixed(&[1])?;
                encoder.put_u64(expires_at.get())?;
            }
            None => encoder.put_fixed(&[0])?,
        }
        encoder.put_u64(sanction.revision.get())?;
        Ok(encoder.finish())
    }

    /// Parses one full-consumption sanction body.
    pub fn decode(encoded: &[u8]) -> Result<DurableSanction, StorageError> {
        if encoded.len() > MAX_SANCTION_RECORD_BODY_BYTES {
            return Err(StorageError::LimitExceeded);
        }
        let mut decoder = Decoder::new(encoded);
        expect_version(&mut decoder)?;
        let actor = principal(&mut decoder)?;
        let target = principal(&mut decoder)?;
        let channel_id = match byte(&mut decoder)? {
            0 => None,
            1 => Some(ChannelInstanceId::from_bytes(decoder.array()?)),
            _ => return Err(StorageError::InvalidEncoding),
        };
        let action = action_from(byte(&mut decoder)?)?;
        let reason_code = reason_code_from(byte(&mut decoder)?)?;
        let reason = optional_text(&mut decoder, MAX_REASON_BYTES)?.map(str::to_owned);
        let created_at = UtcSecond::from_unix_seconds(decoder.u64()?);
        let expires_at = match byte(&mut decoder)? {
            0 => None,
            1 => Some(UtcSecond::from_unix_seconds(decoder.u64()?)),
            _ => return Err(StorageError::InvalidEncoding),
        };
        let revision = revision(&mut decoder)?;
        decoder.finish()?;
        Ok(DurableSanction {
            actor,
            target,
            channel_id,
            action,
            reason_code,
            reason,
            created_at,
            expires_at,
            revision,
        })
    }
}

fn expect_version(decoder: &mut Decoder<'_>) -> Result<(), StorageError> {
    if decoder.u16()? != DOMAIN_BODY_VERSION {
        return Err(StorageError::UnsupportedVersion);
    }
    Ok(())
}

fn byte(decoder: &mut Decoder<'_>) -> Result<u8, StorageError> {
    let [value] = decoder.array::<1>()?;
    Ok(value)
}

fn text<'a>(decoder: &mut Decoder<'a>, maximum: usize) -> Result<&'a str, StorageError> {
    std::str::from_utf8(decoder.vector_u32(maximum)?).map_err(|_| StorageError::InvalidEncoding)
}

fn optional_text<'a>(
    decoder: &mut Decoder<'a>,
    maximum: usize,
) -> Result<Option<&'a str>, StorageError> {
    match byte(decoder)? {
        0 => Ok(None),
        1 => text(decoder, maximum).map(Some),
        _ => Err(StorageError::InvalidEncoding),
    }
}

fn put_optional_text(encoder: &mut Encoder, text: Option<&str>) -> Result<(), StorageError> {
    match text {
        Some(text) => {
            encoder.put_fixed(&[1])?;
            encoder.put_vector_u32(text.as_bytes())
        }
        None => encoder.put_fixed(&[0]),
    }
}

fn put_optional_second(
    encoder: &mut Encoder,
    second: Option<UtcSecond>,
) -> Result<(), StorageError> {
    match second {
        Some(second) => {
            encoder.put_fixed(&[1])?;
            encoder.put_u64(second.get())
        }
        None => encoder.put_fixed(&[0]),
    }
}

fn optional_second(decoder: &mut Decoder<'_>) -> Result<Option<UtcSecond>, StorageError> {
    match byte(decoder)? {
        0 => Ok(None),
        1 => Ok(Some(UtcSecond::from_unix_seconds(decoder.u64()?))),
        _ => Err(StorageError::InvalidEncoding),
    }
}

const fn bool_byte(value: bool) -> u8 {
    if value { 1 } else { 0 }
}

fn bool_from(value: u8) -> Result<bool, StorageError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(StorageError::InvalidEncoding),
    }
}

fn put_count(encoder: &mut Encoder, count: usize) -> Result<(), StorageError> {
    encoder.put_u32(u32::try_from(count).map_err(|_| StorageError::LimitExceeded)?)
}

fn count(decoder: &mut Decoder<'_>, maximum: usize) -> Result<usize, StorageError> {
    let count = usize::try_from(decoder.u32()?).map_err(|_| StorageError::Overflow)?;
    if count > maximum {
        return Err(StorageError::LimitExceeded);
    }
    Ok(count)
}

fn read_account_id(decoder: &mut Decoder<'_>) -> Result<AccountId, StorageError> {
    Ok(AccountRandomId::from_bytes(decoder.array()?).to_account_id())
}

fn generation(decoder: &mut Decoder<'_>) -> Result<Generation, StorageError> {
    Generation::new(decoder.u64()?).map_err(|_| StorageError::InvalidEncoding)
}

fn revision(decoder: &mut Decoder<'_>) -> Result<Revision, StorageError> {
    Revision::new(decoder.u64()?).map_err(|_| StorageError::InvalidEncoding)
}

fn put_principal(encoder: &mut Encoder, principal: Principal) -> Result<(), StorageError> {
    match principal {
        Principal::Guest(user_id) => {
            encoder.put_fixed(&[0])?;
            encoder.put_fixed(user_id.as_bytes())
        }
        Principal::Account(account_id) => {
            encoder.put_fixed(&[1])?;
            encoder.put_fixed(account_id.random().as_bytes())
        }
    }
}

fn principal(decoder: &mut Decoder<'_>) -> Result<Principal, StorageError> {
    match byte(decoder)? {
        0 => Ok(Principal::Guest(UserId::from_bytes(decoder.array()?))),
        1 => read_account_id(decoder).map(Principal::Account),
        _ => Err(StorageError::InvalidEncoding),
    }
}

fn put_key_verifier(
    encoder: &mut Encoder,
    verifier: Option<&ChannelKeyVerifier>,
) -> Result<(), StorageError> {
    match verifier {
        Some(verifier) => {
            encoder.put_fixed(&[1])?;
            encoder.put_fixed(verifier.salt())?;
            encoder.put_fixed(verifier.hash())
        }
        None => encoder.put_fixed(&[0]),
    }
}

fn key_verifier(decoder: &mut Decoder<'_>) -> Result<Option<ChannelKeyVerifier>, StorageError> {
    match byte(decoder)? {
        0 => Ok(None),
        1 => Ok(Some(ChannelKeyVerifier::new(
            decoder.array()?,
            decoder.array()?,
        ))),
        _ => Err(StorageError::InvalidEncoding),
    }
}

fn put_member_limit(encoder: &mut Encoder, limit: Option<u16>) -> Result<(), StorageError> {
    match limit {
        Some(limit) => {
            encoder.put_fixed(&[1])?;
            encoder.put_u16(limit)
        }
        None => encoder.put_fixed(&[0]),
    }
}

fn member_limit(decoder: &mut Decoder<'_>) -> Result<Option<u16>, StorageError> {
    match byte(decoder)? {
        0 => Ok(None),
        1 => decoder.u16().map(Some),
        _ => Err(StorageError::InvalidEncoding),
    }
}

fn put_topic(encoder: &mut Encoder, topic: Option<&DurableTopic>) -> Result<(), StorageError> {
    let Some(topic) = topic else {
        return encoder.put_fixed(&[0]);
    };
    encoder.put_fixed(&[1])?;
    encoder.put_vector_u32(topic.text.as_bytes())?;
    encoder.put_fixed(topic.message_id.as_bytes())?;
    encoder.put_fixed(topic.setter.as_bytes())?;
    encoder.put_u64(topic.set_at.get())
}

fn topic(decoder: &mut Decoder<'_>) -> Result<Option<DurableTopic>, StorageError> {
    match byte(decoder)? {
        0 => Ok(None),
        1 => Ok(Some(DurableTopic {
            text: text(decoder, MAX_TOPIC_BYTES)?.to_owned(),
            message_id: MessageId::from_bytes(decoder.array()?),
            setter: UserId::from_bytes(decoder.array()?),
            set_at: UtcSecond::from_unix_seconds(decoder.u64()?),
        })),
        _ => Err(StorageError::InvalidEncoding),
    }
}

fn role_grants(decoder: &mut Decoder<'_>) -> Result<Vec<(AccountId, Role)>, StorageError> {
    let grant_count = count(decoder, MAX_ROLE_GRANTS_PER_CHANNEL)?;
    let mut grants = Vec::new();
    grants
        .try_reserve_exact(grant_count)
        .map_err(|_| StorageError::AllocationFailed)?;
    for _ in 0..grant_count {
        let account_id = read_account_id(decoder)?;
        let role = role_from(byte(decoder)?)?;
        if role == Role::Member {
            return Err(StorageError::InvalidEncoding);
        }
        grants.push((account_id, role));
    }
    if !ascending(&grants.iter().map(|(id, _)| *id).collect::<Vec<_>>()) {
        return Err(StorageError::InvalidEncoding);
    }
    Ok(grants)
}

fn put_entries(encoder: &mut Encoder, entries: &[DurableListEntry]) -> Result<(), StorageError> {
    put_count(encoder, entries.len())?;
    for entry in entries {
        encoder.put_fixed(entry.entry_id.as_bytes())?;
        encoder.put_vector_u32(entry.mask.as_bytes())?;
        put_principal(encoder, entry.setter)?;
        encoder.put_u64(entry.created_at.get())?;
    }
    Ok(())
}

fn entries(decoder: &mut Decoder<'_>) -> Result<Vec<DurableListEntry>, StorageError> {
    let entry_count = count(decoder, MAX_MASK_ENTRIES_PER_LIST)?;
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(entry_count)
        .map_err(|_| StorageError::AllocationFailed)?;
    for _ in 0..entry_count {
        entries.push(DurableListEntry {
            entry_id: EntryId::from_bytes(decoder.array()?),
            mask: text(decoder, MAX_TYPED_MASK_BYTES)?.to_owned(),
            setter: principal(decoder)?,
            created_at: UtcSecond::from_unix_seconds(decoder.u64()?),
        });
    }
    Ok(entries)
}

fn ascending<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| match pair {
        [first, second] => first < second,
        _ => true,
    })
}

const fn presence_byte(policy: PresencePolicy) -> u8 {
    match policy {
        PresencePolicy::Public => 0,
        PresencePolicy::Private => 1,
    }
}

fn presence_from(byte: u8) -> Result<PresencePolicy, StorageError> {
    match byte {
        0 => Ok(PresencePolicy::Public),
        1 => Ok(PresencePolicy::Private),
        _ => Err(StorageError::InvalidEncoding),
    }
}

const fn guest_policy_byte(policy: GuestDirectMessagePolicy) -> u8 {
    match policy {
        GuestDirectMessagePolicy::Allow => 0,
        GuestDirectMessagePolicy::Deny => 1,
    }
}

fn guest_policy_from(byte: u8) -> Result<GuestDirectMessagePolicy, StorageError> {
    match byte {
        0 => Ok(GuestDirectMessagePolicy::Allow),
        1 => Ok(GuestDirectMessagePolicy::Deny),
        _ => Err(StorageError::InvalidEncoding),
    }
}

const fn direct_policy_byte(policy: DirectMessagePolicy) -> u8 {
    match policy {
        DirectMessagePolicy::Allow => 0,
        DirectMessagePolicy::Contacts => 1,
        DirectMessagePolicy::Deny => 2,
    }
}

fn direct_policy_from(byte: u8) -> Result<DirectMessagePolicy, StorageError> {
    match byte {
        0 => Ok(DirectMessagePolicy::Allow),
        1 => Ok(DirectMessagePolicy::Contacts),
        2 => Ok(DirectMessagePolicy::Deny),
        _ => Err(StorageError::InvalidEncoding),
    }
}

const fn scope_byte(scope: ChannelScope) -> u8 {
    match scope {
        ChannelScope::Global => 0,
        ChannelScope::Local => 1,
    }
}

fn scope_from(byte: u8) -> Result<ChannelScope, StorageError> {
    match byte {
        0 => Ok(ChannelScope::Global),
        1 => Ok(ChannelScope::Local),
        _ => Err(StorageError::InvalidEncoding),
    }
}

const fn visibility_byte(visibility: Visibility) -> u8 {
    match visibility {
        Visibility::Listed => 0,
        Visibility::Unlisted => 1,
        Visibility::Secret => 2,
    }
}

fn visibility_from(byte: u8) -> Result<Visibility, StorageError> {
    match byte {
        0 => Ok(Visibility::Listed),
        1 => Ok(Visibility::Unlisted),
        2 => Ok(Visibility::Secret),
        _ => Err(StorageError::InvalidEncoding),
    }
}

const fn content_policy_byte(policy: ContentPolicy) -> u8 {
    match policy {
        ContentPolicy::Plaintext => 0,
        ContentPolicy::E2eeBound => 1,
    }
}

fn content_policy_from(byte: u8) -> Result<ContentPolicy, StorageError> {
    match byte {
        0 => Ok(ContentPolicy::Plaintext),
        1 => Ok(ContentPolicy::E2eeBound),
        _ => Err(StorageError::InvalidEncoding),
    }
}

const fn persistence_byte(policy: PersistencePolicy) -> u8 {
    match policy {
        PersistencePolicy::Ephemeral => 0,
        PersistencePolicy::Registered => 1,
    }
}

fn persistence_from(byte: u8) -> Result<PersistencePolicy, StorageError> {
    match byte {
        0 => Ok(PersistencePolicy::Ephemeral),
        1 => Ok(PersistencePolicy::Registered),
        _ => Err(StorageError::InvalidEncoding),
    }
}

const fn modes_byte(modes: ChannelModes) -> u8 {
    (modes.invite_only as u8)
        | ((modes.moderated as u8) << 1)
        | ((modes.topic_protected as u8) << 2)
        | ((modes.join_key as u8) << 3)
}

fn modes_from(byte: u8) -> Result<ChannelModes, StorageError> {
    if byte > 0b1111 {
        return Err(StorageError::InvalidEncoding);
    }
    Ok(ChannelModes {
        invite_only: byte & 0b0001 != 0,
        moderated: byte & 0b0010 != 0,
        topic_protected: byte & 0b0100 != 0,
        join_key: byte & 0b1000 != 0,
    })
}

const fn role_byte(role: Role) -> u8 {
    match role {
        Role::Member => 0,
        Role::Voice => 1,
        Role::HalfOperator => 2,
        Role::Operator => 3,
        Role::Administrator => 4,
        Role::Owner => 5,
    }
}

fn role_from(byte: u8) -> Result<Role, StorageError> {
    match byte {
        0 => Ok(Role::Member),
        1 => Ok(Role::Voice),
        2 => Ok(Role::HalfOperator),
        3 => Ok(Role::Operator),
        4 => Ok(Role::Administrator),
        5 => Ok(Role::Owner),
        _ => Err(StorageError::InvalidEncoding),
    }
}

const fn history_byte(policy: HistoryPolicy) -> u8 {
    match policy {
        HistoryPolicy::Off => 0,
        HistoryPolicy::OneHour => 1,
        HistoryPolicy::TwentyFourHours => 2,
        HistoryPolicy::SevenDays => 3,
    }
}

fn history_from(byte: u8) -> Result<HistoryPolicy, StorageError> {
    match byte {
        0 => Ok(HistoryPolicy::Off),
        1 => Ok(HistoryPolicy::OneHour),
        2 => Ok(HistoryPolicy::TwentyFourHours),
        3 => Ok(HistoryPolicy::SevenDays),
        _ => Err(StorageError::InvalidEncoding),
    }
}

const fn action_byte(action: ModerationAction) -> u8 {
    match action {
        ModerationAction::Mute => 0,
        ModerationAction::Ban => 1,
        ModerationAction::Kick => 2,
        ModerationAction::Suspend => 3,
    }
}

fn action_from(byte: u8) -> Result<ModerationAction, StorageError> {
    match byte {
        0 => Ok(ModerationAction::Mute),
        1 => Ok(ModerationAction::Ban),
        2 => Ok(ModerationAction::Kick),
        3 => Ok(ModerationAction::Suspend),
        _ => Err(StorageError::InvalidEncoding),
    }
}

const fn reason_code_byte(code: ModerationReasonCode) -> u8 {
    match code {
        ModerationReasonCode::Spam => 0,
        ModerationReasonCode::Harassment => 1,
        ModerationReasonCode::ChannelPolicy => 2,
        ModerationReasonCode::Security => 3,
    }
}

fn reason_code_from(byte: u8) -> Result<ModerationReasonCode, StorageError> {
    match byte {
        0 => Ok(ModerationReasonCode::Spam),
        1 => Ok(ModerationReasonCode::Harassment),
        2 => Ok(ModerationReasonCode::ChannelPolicy),
        3 => Ok(ModerationReasonCode::Security),
        _ => Err(StorageError::InvalidEncoding),
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! Smallest valid live bodies for tests that need a real domain row.

    use agenc_ircd_domain::{
        ChannelModes, ChannelNameValue, ChannelScope, ContentPolicy, DirectMessagePolicy,
        DurableAccount, DurableChannel, DurableSanction, GuestDirectMessagePolicy, HistoryPolicy,
        ModerationAction, ModerationReasonCode, PersistencePolicy, PresencePolicy, Principal, Role,
        Visibility,
    };
    use agenc_ircd_types::{
        AccountId, AccountRandomId, ChannelInstanceId, Generation, Revision, UserId, UtcSecond,
    };

    use super::{AccountRecordBody, ChannelRecordBody, SanctionRecordBody};
    use crate::{StorageError, TableId};

    /// Returns the smallest valid live body for a domain table, or an empty body for
    /// tables whose live bodies remain opaque to storage.
    pub(crate) fn live_body(table: TableId, seed: u8) -> Result<Vec<u8>, StorageError> {
        match table {
            TableId::Account => AccountRecordBody::encode(&account(seed)?),
            TableId::Channel => ChannelRecordBody::encode(&channel(seed)?),
            TableId::Sanction => SanctionRecordBody::encode(&sanction(seed)?),
            _ => Ok(Vec::new()),
        }
    }

    fn account_id(seed: u8) -> AccountId {
        AccountRandomId::from_bytes([seed; 16]).to_account_id()
    }

    fn one() -> Result<(Generation, Revision), StorageError> {
        Ok((
            Generation::new(1).map_err(|_| StorageError::InvalidEncoding)?,
            Revision::new(1).map_err(|_| StorageError::InvalidEncoding)?,
        ))
    }

    pub(crate) fn account(seed: u8) -> Result<DurableAccount, StorageError> {
        let (session_generation, revision) = one()?;
        Ok(DurableAccount {
            account_id: account_id(seed),
            label: None,
            presence: PresencePolicy::Private,
            guest_direct_messages: GuestDirectMessagePolicy::Allow,
            direct_messages: DirectMessagePolicy::Allow,
            contacts: Vec::new(),
            reserved_nicknames: Vec::new(),
            session_generation,
            revision,
            admin_suspension_expires_at: None,
        })
    }

    pub(crate) fn channel(seed: u8) -> Result<DurableChannel, StorageError> {
        let (_, revision) = one()?;
        Ok(DurableChannel {
            channel_id: ChannelInstanceId::from_bytes([seed; 16]),
            name: ChannelNameValue::parse("#fixture").map_err(|_| StorageError::InvalidEncoding)?,
            scope: ChannelScope::Global,
            visibility: Visibility::Listed,
            content_policy: ContentPolicy::Plaintext,
            persistence: PersistencePolicy::Registered,
            creator: Principal::Account(account_id(seed)),
            created_at: UtcSecond::from_unix_seconds(1),
            revision,
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

    pub(crate) fn sanction(seed: u8) -> Result<DurableSanction, StorageError> {
        let (_, revision) = one()?;
        Ok(DurableSanction {
            actor: Principal::Account(account_id(seed)),
            target: Principal::Guest(UserId::from_bytes([seed; 16])),
            channel_id: None,
            action: ModerationAction::Mute,
            reason_code: ModerationReasonCode::Spam,
            reason: None,
            created_at: UtcSecond::from_unix_seconds(1),
            expires_at: None,
            revision,
        })
    }
}
