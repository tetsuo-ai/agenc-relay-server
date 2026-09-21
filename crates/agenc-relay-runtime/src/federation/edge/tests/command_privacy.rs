//! PRV-01: local edge lookup cannot distinguish missing and hidden channels.

#![forbid(unsafe_code)]

use super::*;
use agenc_relay_client_wire::{PostRegistrationCommandKind, RegisteredCommandKind};
use agenc_relay_domain::{DomainError, federation::ModeDirection};

fn mode_edge(context: &mut StateCoreContext) -> TestResult<EdgeFederation> {
    let mut edge = resync_edge();
    let generation = ConnectionGeneration::new(1);
    edge.connection_opened(context, generation);
    let origin = edge.origins.get_mut(&generation).ok_or("origin absent")?;
    origin.session = Some((
        SessionId::from_bytes([45; 16]),
        UserId::from_bytes([46; 16]),
    ));
    origin.pending_updates.clear();
    edge.phase = Phase::Active;
    Ok(edge)
}

#[test]
fn missing_edge_mode_targets_have_the_secret_unavailable_refusal() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let mut edge = mode_edge(fixture.context_mut()?)?;
    for modes in ["-b $n:absent", "-e $n:absent", "-I $n:absent", "+m"] {
        let line = format!("MODE #absent {modes}");
        let message = parse_message(FramedLine::new(&line)?)?.ok_or("empty mode")?;
        let result = request::send_command(
            &mut edge,
            fixture.context_mut()?,
            ConnectionGeneration::new(1),
            RegisteredCommandKind::Public(PostRegistrationCommandKind::ModeChange),
            Box::new(message),
        );
        assert_eq!(
            result.map_err(|(_, error)| error),
            Err(DomainError::SecretUnavailable)
        );
        assert!(edge.pending.is_empty());
        assert_eq!(
            edge.origins
                .get(&ConnectionGeneration::new(1))
                .map(|origin| origin.sequence),
            Some(0)
        );
    }
    Ok(())
}

#[test]
fn guest_edge_controls_require_an_account_before_resolving_the_channel() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let mut edge = mode_edge(fixture.context_mut()?)?;
    install_secret_channel(&mut edge)?;
    for channel in ["#known", "#absent"] {
        let line = format!("CHANCTL HISTORY {channel} ON");
        let message = parse_message(FramedLine::new(&line)?)?.ok_or("empty control")?;
        let proof = agenc_relay_client_wire::validate_post_registration_command(&message)?;
        let result = request::send_command(
            &mut edge,
            fixture.context_mut()?,
            ConnectionGeneration::new(1),
            RegisteredCommandKind::Public(proof.kind()),
            Box::new(message),
        );
        assert_eq!(
            result.map_err(|(_, error)| error),
            Err(DomainError::RegistrationRequired)
        );
        assert!(edge.pending.is_empty());
    }
    Ok(())
}

fn install_secret_channel(edge: &mut EdgeFederation) -> TestResult<ChannelInstanceId> {
    let channel_id = ChannelInstanceId::from_bytes([63; 16]);
    edge.replica.apply(
        &ProjectedEvent::ChannelVisible(ChannelDetailRecord {
            channel_id,
            name: ChannelNameValue::parse("#known")?,
            channel_revision: Revision::new(3)?,
            visibility: Visibility::Secret,
            content_policy: ContentPolicy::Plaintext,
            persistence: PersistencePolicy::Ephemeral,
            simple_mode_bits: 4,
            history: HistoryPolicy::Off,
            e2ee_route_binding: None,
        }),
        3,
    )?;
    Ok(channel_id)
}

#[test]
fn edge_mask_removal_preserves_the_mask_and_list_for_coordinator_authorization() -> TestResult {
    for (mode, expected_code, argument) in [
        ("b", 1, "$n:absent"),
        ("e", 2, "$n:absent"),
        ("I", 3, "$n:absent"),
        ("b", 1, ":$n:absent"),
        ("e", 2, ":$n:absent"),
        ("I", 3, ":$n:absent"),
    ] {
        let mut fixture = StateCoreFixture::new(entropy_script())?;
        let mut edge = mode_edge(fixture.context_mut()?)?;
        let channel_id = install_secret_channel(&mut edge)?;
        let line = format!("MODE #known -{mode} {argument}");
        let message = parse_message(FramedLine::new(&line)?)?.ok_or("empty mode")?;
        request::send_command(
            &mut edge,
            fixture.context_mut()?,
            ConnectionGeneration::new(1),
            RegisteredCommandKind::Public(PostRegistrationCommandKind::ModeChange),
            Box::new(message),
        )
        .map_err(|(_, error)| format!("mask forwarding failed: {error:?}"))?;
        let pending = edge.pending.values().next().ok_or("mode not pending")?;
        let mut budget = DecodeBudget::new(1 << 20, 4096);
        let object = SchemaObject::decode_exact("FederationRequest", &pending.bytes, &mut budget)?;
        let arm = decode_request_operation(&object, &mut budget)?;
        let FederatedOperation::ChannelMode {
            channel_id: actual_channel,
            expected_channel_revision,
            changes,
            ..
        } = FederatedOperation::from_object(pending.header.opcode, &arm)?
        else {
            return Err("wrong mode operation".into());
        };
        assert_eq!(actual_channel, channel_id);
        assert_eq!(expected_channel_revision, 3);
        assert_eq!(changes.len(), 1);
        let change = changes.first().ok_or("missing mask removal")?;
        assert_eq!(
            (change.direction, change.mode_code),
            (ModeDirection::Remove, expected_code)
        );
        assert_eq!(change.argument.as_slice(), b"$n:absent");
    }
    Ok(())
}

// STA-10: exercise the complete edge request encoder, including trailing IRC
// arguments, against the existing binary MODE schema.
#[test]
fn edge_key_and_limit_modes_cross_the_existing_binary_wire_schema() -> TestResult {
    for (modes, code, expected) in [
        ("+k password", 4, &b"password"[..]),
        ("+k :password", 4, &b"password"[..]),
        ("-k", 4, &b""[..]),
        ("+l 65535", 5, &b"65535"[..]),
        ("+l :1", 5, &b"1"[..]),
        ("-l", 5, &b""[..]),
    ] {
        let change = encoded_mode(modes, None)?;
        assert_eq!(change.mode_code, code);
        assert_eq!(change.argument.as_slice(), expected);
    }
    Ok(())
}

#[test]
fn edge_role_modes_forward_the_known_user_id_instead_of_nickname_bytes() -> TestResult {
    let target = UserId::from_bytes([0xff; 16]);
    for (letter, code) in [("q", 12), ("a", 13), ("o", 14), ("h", 15), ("v", 16)] {
        for direction in ["+", "-"] {
            let change = encoded_mode(&format!("{direction}{letter} :alice"), Some(target))?;
            assert_eq!(change.mode_code, code);
            assert_eq!(change.argument.as_slice(), target.as_bytes());
        }
    }
    assert!(encoded_mode("+v unknown", None).is_err());
    Ok(())
}

fn encoded_mode(
    modes: &str,
    target: Option<UserId>,
) -> TestResult<crate::federation::codec::operations::ModeChangeArg> {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let mut edge = mode_edge(fixture.context_mut()?)?;
    install_secret_channel(&mut edge)?;
    if let Some(target) = target {
        edge.nicknames
            .insert(target, NicknameValue::parse("alice")?);
    }
    let line = format!("MODE #known {modes}");
    let message = parse_message(FramedLine::new(&line)?)?.ok_or("empty mode")?;
    request::send_command(
        &mut edge,
        fixture.context_mut()?,
        ConnectionGeneration::new(1),
        RegisteredCommandKind::Public(PostRegistrationCommandKind::ModeChange),
        Box::new(message),
    )
    .map_err(|(_, error)| format!("MODE {modes} forwarding failed: {error:?}"))?;
    let pending = edge.pending.values().next().ok_or("mode not pending")?;
    let mut budget = DecodeBudget::new(1 << 20, 4096);
    let object = SchemaObject::decode_exact("FederationRequest", &pending.bytes, &mut budget)?;
    let arm = decode_request_operation(&object, &mut budget)?;
    let FederatedOperation::ChannelMode { mut changes, .. } =
        FederatedOperation::from_object(pending.header.opcode, &arm)?
    else {
        return Err("wrong mode operation".into());
    };
    changes.pop().ok_or_else(|| "missing mode change".into())
}
