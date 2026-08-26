#![forbid(unsafe_code)]

//! Boundary and registry tests for Stage-01 foundational values.

use std::error::Error;

use agenc_ircd_types::{
    AccountDeletionToken, AccountId, AccountLabel, AccountRandomId, AuthGrantId, BoundedBytes,
    BoundedUtf8, ByteCount, CAPABILITIES, CLIENT_COMMANDS, CONSTANT_REGISTRY, ChannelInstanceId,
    ChannelName, ClockError, ConnectionId, ControlPolicy, DatabaseId, DisplayName,
    DurationMilliseconds, ENUM_REGISTRY, EntropyError, EntropySource, EntryId, EventId,
    FEDERATION_WIRE_FORMS, Generation, InviteId, MAX_GLOB_BYTES, MAX_TYPED_MASK_BYTES, MessageId,
    MonotonicTick, NetworkId, Nickname, NormalizedLogin, ObjectCount, OriginId, PublicCloak,
    PublicErrorCode, QueueDemand, Quota, RecoveryEpoch, RequestId, Revision, SERVER_COMMANDS,
    SERVER_NUMERICS, STANDARD_REPLY_CODES, SafeContext, SequenceNumber, ServerId,
    ServerIncarnation, ServerName, SessionId, TransactionId, TypedMask, UnixMilliseconds, UserId,
    UtcSecond, ValidationError,
};

#[test]
fn capability_port_errors_have_closed_descriptions() {
    assert_eq!(
        EntropyError::Unavailable.to_string(),
        "entropy source is unavailable"
    );
    assert_eq!(
        ClockError::Unavailable.to_string(),
        "wall clock is unavailable"
    );
    assert_eq!(
        ClockError::OutOfRange.to_string(),
        "wall clock value is outside its UTC domain"
    );
}

#[test]
fn account_deletion_tokens_match_only_the_exact_candidate() {
    let token = AccountDeletionToken::from_bytes([7; 16]);
    assert!(token.matches(&[7; 16]));
    assert!(!token.matches(&[8; 16]));
}

struct IncrementingEntropy(u8);

impl EntropySource for IncrementingEntropy {
    fn fill_exact(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        for byte in destination {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

macro_rules! round_trip_identifier {
    ($type:ty, $size:expr) => {{
        let value = <$type>::from_bytes([$size; std::mem::size_of::<$type>()]);
        let encoded = value.to_base64url();
        assert_eq!(<$type>::parse(&encoded)?, value);
    }};
}

#[test]
fn generated_registries_cover_the_frozen_source() -> Result<(), Box<dyn Error>> {
    let registry = include_str!("../../../docs/federation-v1-profile.registry");
    assert_eq!(CONSTANT_REGISTRY.len(), 53);
    assert_eq!(ENUM_REGISTRY.len(), 29);
    assert_eq!(FEDERATION_WIRE_FORMS.len(), 23);
    for constant in CONSTANT_REGISTRY {
        let line = format!("constant|{}|{}", constant.name, constant.value);
        assert!(registry.lines().any(|candidate| candidate == line));
    }
    for descriptor in ENUM_REGISTRY {
        let prefix = format!("enum|{}|", descriptor.name);
        let line = registry
            .lines()
            .find(|candidate| candidate.starts_with(&prefix))
            .ok_or("missing enum registry line")?;
        for entry in descriptor.entries {
            let rendered = format!("{}={}", entry.name, entry.value);
            assert!(
                line.split('|')
                    .next_back()
                    .is_some_and(|value| value.split(',').any(|item| item == rendered))
            );
        }
    }
    assert!(CLIENT_COMMANDS.contains(&"JOIN"));
    assert!(SERVER_COMMANDS.contains(&"FAIL"));
    assert!(SERVER_NUMERICS.contains(&1));
    assert!(CAPABILITIES.contains(&"agenc.ag/e2ee-mls"));
    Ok(())
}

#[test]
fn public_error_codes_map_exhaustively_without_input_context() -> Result<(), Box<dyn Error>> {
    for token in STANDARD_REPLY_CODES {
        let code = PublicErrorCode::parse(token)?;
        assert_eq!(code.as_str(), *token);
    }
    assert!(PublicErrorCode::parse("invalid_argument").is_err());
    assert!(PublicErrorCode::parse("UNKNOWN").is_err());
    Ok(())
}

#[test]
fn quantity_families_reject_bounds_and_overflow() -> Result<(), ValidationError> {
    macro_rules! zero_based_quantity {
        ($quantity:ty) => {{
            assert_eq!(<$quantity>::new(0)?.get(), 0);
            assert_eq!(<$quantity>::new(1)?.get(), 1);
            assert_eq!(<$quantity>::new(<$quantity>::MAX)?.get(), <$quantity>::MAX);
            assert_eq!(
                <$quantity>::new(<$quantity>::MAX)?.checked_add(1),
                Err(if <$quantity>::MAX == u64::MAX {
                    ValidationError::Overflow
                } else {
                    ValidationError::OutOfRange
                })
            );
            assert_eq!(
                <$quantity>::new(0)?.checked_sub(1),
                Err(ValidationError::Underflow)
            );
        }};
    }

    zero_based_quantity!(ByteCount);
    zero_based_quantity!(ObjectCount);
    zero_based_quantity!(QueueDemand);
    zero_based_quantity!(UnixMilliseconds);
    zero_based_quantity!(UtcSecond);
    zero_based_quantity!(MonotonicTick);
    zero_based_quantity!(DurationMilliseconds);
    zero_based_quantity!(Revision);
    zero_based_quantity!(Generation);
    zero_based_quantity!(SequenceNumber);

    assert_eq!(Quota::new(0), Err(ValidationError::OutOfRange));
    assert_eq!(Quota::new(1)?.get(), 1);
    assert_eq!(Quota::new(Quota::MAX)?.get(), Quota::MAX);
    assert_eq!(
        Quota::new(Quota::MAX)?.checked_add(1),
        Err(ValidationError::Overflow)
    );
    assert_eq!(
        Quota::new(1)?.checked_sub(1),
        Err(ValidationError::OutOfRange)
    );
    assert_eq!(
        Quota::new(1)?.checked_sub(2),
        Err(ValidationError::Underflow)
    );
    Ok(())
}

#[test]
fn every_identifier_domain_round_trips_only_its_canonical_text() -> Result<(), Box<dyn Error>> {
    round_trip_identifier!(NetworkId, 1_u8);
    round_trip_identifier!(ServerId, 2_u8);
    round_trip_identifier!(ServerIncarnation, 3_u8);
    round_trip_identifier!(RecoveryEpoch, 4_u8);
    round_trip_identifier!(SessionId, 5_u8);
    round_trip_identifier!(UserId, 6_u8);
    round_trip_identifier!(ChannelInstanceId, 7_u8);
    round_trip_identifier!(MessageId, 8_u8);
    round_trip_identifier!(RequestId, 9_u8);
    round_trip_identifier!(EventId, 10_u8);
    round_trip_identifier!(OriginId, 11_u8);
    round_trip_identifier!(TransactionId, 12_u8);
    round_trip_identifier!(DatabaseId, 13_u8);
    round_trip_identifier!(ConnectionId, 14_u8);
    round_trip_identifier!(InviteId, 15_u8);
    round_trip_identifier!(EntryId, 16_u8);
    let account = AccountRandomId::from_bytes([19_u8; 16]);
    assert_eq!(AccountRandomId::parse(&account.to_text())?, account);
    assert_eq!(
        AccountRandomId::parse("a_AAAAAAAAAAAAAAAAAAAAAA="),
        Err(ValidationError::IdentifierLength)
    );
    let account_id = AccountId::from_random(account);
    assert_eq!(AccountId::parse(&account_id.to_text())?, account_id);
    assert_eq!(
        AccountId::parse_wire_bytes(account_id.to_text().as_bytes())?,
        account_id
    );
    assert!(AccountId::parse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_err());

    let mut entropy = IncrementingEntropy(1);
    let generated = NetworkId::generate(&mut entropy)?;
    assert_ne!(generated.as_bytes(), &[0_u8; 32]);
    let grant = AuthGrantId::generate(&mut entropy)?;
    assert_ne!(grant.expose_for_session_open(), &[0_u8; 32]);
    let fixed_grant = AuthGrantId::from_bytes([17_u8; 32]);
    assert_eq!(fixed_grant.expose_for_session_open(), &[17_u8; 32]);
    Ok(())
}

#[test]
fn bounded_values_validate_before_copying() -> Result<(), ValidationError> {
    assert_eq!(
        BoundedBytes::<2, 1>::try_from_slice(b"x").err(),
        Some(ValidationError::OutOfRange)
    );
    assert!(matches!(
        BoundedBytes::<1, 3>::try_from_slice(&[]),
        Err(ValidationError::Empty)
    ));
    assert_eq!(
        BoundedBytes::<2, 3>::try_from_slice(b"x").err(),
        Some(ValidationError::TooShort)
    );
    assert!(matches!(
        BoundedBytes::<1, 3>::try_from_slice(b"four"),
        Err(ValidationError::TooLong)
    ));
    assert_eq!(
        BoundedBytes::<1, 3>::try_from_slice(b"ok")?.as_slice(),
        b"ok"
    );
    let mut bytes_with_spare_capacity = Vec::with_capacity(3);
    bytes_with_spare_capacity.extend_from_slice(b"ok");
    assert_eq!(
        BoundedBytes::<1, 3>::try_from_vec(bytes_with_spare_capacity).err(),
        Some(ValidationError::TooLong)
    );
    let exactly_sized = BoundedBytes::<1, 3>::try_from_vec(b"ok".to_vec())?.into_vec();
    assert_eq!(exactly_sized.capacity(), exactly_sized.len());

    assert!(matches!(
        BoundedUtf8::<0, 8>::try_from_bytes(&[0xff], ControlPolicy::RejectAll),
        Err(ValidationError::InvalidUtf8)
    ));
    assert!(matches!(
        BoundedUtf8::<0, 8>::try_from_str("a\0b", ControlPolicy::RejectAll),
        Err(ValidationError::Nul)
    ));
    assert!(matches!(
        BoundedUtf8::<0, 8>::try_from_str("a\nb", ControlPolicy::RejectAll),
        Err(ValidationError::Control)
    ));
    assert_eq!(
        BoundedUtf8::<0, 8>::try_from_str("a\tb", ControlPolicy::PermitHorizontalTab)?.as_str(),
        "a\tb"
    );
    assert_eq!(
        BoundedUtf8::<0, 8>::try_from_str("a\nb", ControlPolicy::PermitHorizontalTab).err(),
        Some(ValidationError::Control)
    );
    Ok(())
}

#[test]
fn names_preserve_presentation_but_compare_by_identity() -> Result<(), ValidationError> {
    let upper = Nickname::parse("Alice")?;
    let lower = Nickname::parse("alice")?;
    assert!(upper == lower);
    assert_eq!(upper.presentation(), "Alice");
    assert_eq!(
        Nickname::parse("9alice").err(),
        Some(ValidationError::InvalidCharacter)
    );

    let channel = ChannelName::parse("#Rust.Chat")?;
    assert_eq!(channel.canonical(), "#rust.chat");
    assert!(channel.is_global());
    assert_eq!(
        ChannelName::parse("+legacy").err(),
        Some(ValidationError::InvalidPrefix)
    );

    assert_eq!(NormalizedLogin::prepare("UsEr")?.as_str(), "user");
    assert_eq!(AccountLabel::parse("Public.Name")?.as_str(), "Public.Name");
    assert_eq!(
        DisplayName::prepare("  Élodie\u{00a0}  Example  ")?.as_str(),
        "Élodie Example"
    );
    assert_eq!(DisplayName::prepare("é ")?.as_str(), "é");
    assert_eq!(
        ServerName::parse("irc.example.invalid")?.as_str(),
        "irc.example.invalid"
    );
    assert!(ServerName::parse("IRC.example.invalid").is_err());
    Ok(())
}

#[test]
fn name_profiles_reject_every_length_and_grammar_boundary() -> Result<(), ValidationError> {
    assert_eq!(Nickname::parse("").err(), Some(ValidationError::Empty));
    assert_eq!(
        Nickname::parse(&"a".repeat(33)).err(),
        Some(ValidationError::TooLong)
    );
    assert_eq!(Nickname::parse("_valid")?.canonical(), "_valid");
    assert_eq!(
        Nickname::parse("a!").err(),
        Some(ValidationError::InvalidCharacter)
    );

    assert_eq!(ChannelName::parse("").err(), Some(ValidationError::Empty));
    assert_eq!(
        ChannelName::parse("#").err(),
        Some(ValidationError::TooShort)
    );
    assert_eq!(
        ChannelName::parse(&format!("#{}", "a".repeat(64))).err(),
        Some(ValidationError::TooLong)
    );
    assert_eq!(
        ChannelName::parse("#bad!").err(),
        Some(ValidationError::InvalidCharacter)
    );

    assert_eq!(
        NormalizedLogin::prepare("ab").err(),
        Some(ValidationError::TooShort)
    );
    assert_eq!(
        NormalizedLogin::prepare(&"a".repeat(65)).err(),
        Some(ValidationError::TooLong)
    );
    assert_eq!(
        NormalizedLogin::prepare(&"a".repeat(257)).err(),
        Some(ValidationError::TooLong)
    );

    assert_eq!(AccountLabel::parse("").err(), Some(ValidationError::Empty));
    assert_eq!(
        AccountLabel::parse(&"a".repeat(33)).err(),
        Some(ValidationError::TooLong)
    );
    assert_eq!(
        AccountLabel::parse("a!").err(),
        Some(ValidationError::InvalidCharacter)
    );
    assert_eq!(
        DisplayName::prepare(&"a".repeat(65)).err(),
        Some(ValidationError::TooLong)
    );
    assert_eq!(
        DisplayName::prepare(&"a".repeat(257)).err(),
        Some(ValidationError::TooLong)
    );

    assert_eq!(ServerName::parse("").err(), Some(ValidationError::Empty));
    assert_eq!(
        ServerName::parse(&format!("{}.invalid", "a".repeat(246))).err(),
        Some(ValidationError::TooLong)
    );
    for invalid in [
        "localhost",
        ".invalid",
        "bad-.invalid",
        "-bad.invalid",
        "BAD.invalid",
    ] {
        assert_eq!(
            ServerName::parse(invalid).err(),
            Some(ValidationError::InvalidCharacter)
        );
    }
    assert_eq!(ServerName::parse("123.example")?.as_str(), "123.example");

    assert_eq!(
        PublicCloak::parse("short", "abcdefghijklmnop").err(),
        Some(ValidationError::IdentifierLength)
    );
    assert_eq!(
        PublicCloak::parse("abcdefghij", "short").err(),
        Some(ValidationError::IdentifierLength)
    );
    assert_eq!(
        PublicCloak::parse("abcdefghi0", "abcdefghijklmnop").err(),
        Some(ValidationError::InvalidCharacter)
    );
    Ok(())
}

#[test]
fn validation_errors_render_only_closed_public_messages() {
    let cases = [
        (ValidationError::Empty, "value is empty"),
        (ValidationError::TooShort, "value is too short"),
        (ValidationError::TooLong, "value is too long"),
        (ValidationError::InvalidUtf8, "value is not valid UTF-8"),
        (ValidationError::Nul, "value contains NUL"),
        (
            ValidationError::Control,
            "value contains a forbidden control character",
        ),
        (
            ValidationError::InvalidCharacter,
            "value contains an invalid character",
        ),
        (ValidationError::NonCanonical, "value is not canonical"),
        (ValidationError::Overflow, "checked calculation overflowed"),
        (
            ValidationError::Underflow,
            "checked calculation underflowed",
        ),
        (ValidationError::OutOfRange, "value is outside its domain"),
        (
            ValidationError::AllocationFailed,
            "bounded allocation failed",
        ),
        (
            ValidationError::PrecisRejected,
            "value is rejected by its PRECIS profile",
        ),
        (
            ValidationError::InvalidPrefix,
            "value has an invalid type prefix",
        ),
        (ValidationError::InvalidMask, "typed mask is invalid"),
        (
            ValidationError::IdentifierLength,
            "identifier has an invalid decoded length",
        ),
    ];
    for (error, expected) in cases {
        assert_eq!(error.to_string(), expected);
    }
    assert_eq!(SafeContext::None, SafeContext::None);
    assert_eq!(SafeContext::TargetIndex(2), SafeContext::TargetIndex(2));
    assert_eq!(
        SafeContext::RetryAfterSeconds(3),
        SafeContext::RetryAfterSeconds(3)
    );
    assert_eq!(SafeContext::Maximum(4), SafeContext::Maximum(4));
}

#[test]
fn server_names_enforce_dns_label_and_total_boundaries() -> Result<(), ValidationError> {
    let maximum_label = "a".repeat(63);
    let valid = format!("{maximum_label}.invalid");
    assert_eq!(ServerName::parse(&valid)?.as_str(), valid);

    let oversized_label = format!("{}.invalid", "a".repeat(64));
    assert_eq!(
        ServerName::parse(&oversized_label).err(),
        Some(ValidationError::InvalidCharacter)
    );

    let maximum_name = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(maximum_name.len(), 253);
    assert_eq!(ServerName::parse(&maximum_name)?.as_str(), maximum_name);
    Ok(())
}

#[test]
fn cloaks_and_masks_use_closed_nonrecursive_grammars() -> Result<(), ValidationError> {
    let cloak = PublicCloak::parse("abcdefghij", "abcdefghijklmnop")?;
    assert_eq!(cloak.user_component(), b"abcdefghij");
    assert_eq!(cloak.host_component(), b"abcdefghijklmnop");

    let nickname_mask = TypedMask::parse("$n:A**?ce")?;
    assert!(nickname_mask.matches_nickname(&Nickname::parse("alice")?));
    let quiet = TypedMask::parse("$q:$c:abc*")?;
    assert!(quiet.is_quiet());
    assert!(quiet.matches_cloak("abcdef"));
    assert!(!quiet.matches_cloak("é"));
    assert_eq!(TypedMask::parse("$n:").err(), Some(ValidationError::Empty));
    assert_eq!(
        TypedMask::parse("$x:value").err(),
        Some(ValidationError::InvalidPrefix)
    );
    assert_eq!(
        TypedMask::parse("$q:$q:$n:a").err(),
        Some(ValidationError::InvalidMask)
    );
    assert_eq!(
        TypedMask::parse(&format!("$n:{}", "a".repeat(MAX_GLOB_BYTES + 1))).err(),
        Some(ValidationError::TooLong)
    );
    assert_eq!(
        TypedMask::parse(&"x".repeat(MAX_TYPED_MASK_BYTES + 1)).err(),
        Some(ValidationError::TooLong)
    );
    Ok(())
}
