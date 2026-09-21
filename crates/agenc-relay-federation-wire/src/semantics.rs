//! Context-independent Appendix-B semantic and cross-field validation.

use agenc_relay_types::{
    AccountId, AccountLabel, BoundedUtf8, ChannelName, ControlPolicy, DisplayName,
    MAPPING_DESCRIPTORS, Nickname, NormalizedLogin, PublicCloak, SERVER_COMMANDS, SERVER_NUMERICS,
    TypedMask,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::codec::{
    CodecError, DecodeBudget, FederationSemanticValidator, SchemaObject, SemanticValidator,
    WireValue, decode_one_without_embedded, measured_fields_len,
};
use crate::schema::SchemaDescriptor;

const ACCOUNT_ID_BYTES: usize = 24;
const CHANNEL_INSTANCE_ID_BYTES: usize = 16;
const SERVER_ID_BYTES: usize = 16;
const SESSION_ID_BYTES: usize = 16;
const USER_ID_BYTES: usize = 16;
const SESSION_PROJECTION_HOME_SERVER_OFFSET: usize = SESSION_ID_BYTES + USER_ID_BYTES;
const SESSION_PROJECTION_HOME_SERVER_END: usize =
    SESSION_PROJECTION_HOME_SERVER_OFFSET + SERVER_ID_BYTES;

impl SemanticValidator for FederationSemanticValidator {
    fn validate_schema(schema: &SchemaDescriptor, fields: &[WireValue]) -> Result<(), CodecError> {
        validate_schema_semantics(schema, fields)
    }

    fn validate_embedded(
        schema: &SchemaDescriptor,
        fields: &[WireValue],
        budget: &mut DecodeBudget,
        depth: usize,
        pending: &mut Vec<(SchemaObject, usize)>,
    ) -> Result<(), CodecError> {
        validate_embedded_semantics(schema, fields, budget, depth, pending)
    }
}

pub(crate) fn validate_schema_semantics(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    if schema.name.starts_with("event.") {
        return validate_event_schema(schema, fields);
    }
    if schema.name.starts_with("operation.") {
        return validate_operation_schema(schema, fields);
    }
    if schema.name.starts_with("result.") {
        return validate_result_schema(schema, fields);
    }
    match schema.name {
        "AccountCreateStart" | "AuthStart" => validate_normalized_login(schema, fields),
        "AccountCreationInviteTBS" => validate_creation_invite(schema, fields),
        "AccountServiceChallenge" => validate_account_challenge(schema, fields),
        "AccountServiceCompletion" => validate_account_completion(schema, fields),
        "AccountServiceRequestPlaintext" => {
            validate_padding_shape(schema, fields, "inner_payload", 4_586)
        }
        "AccountServiceResponsePlaintext" => {
            validate_padding_shape(schema, fields, "payload", 4_202)
        }
        "AccountSettingsChange" => validate_account_setting(schema, fields),
        "CredentialChangeStart" => validate_credential_change_start(schema, fields),
        "DirectoryQuery" => validate_directory_cursor(schema, fields),
        "FederationActorView" => {
            validate_presence_payload(schema, fields, "user_present", "source")
        }
        "FederationAccountProjection" => validate_account_projection(schema, fields),
        "FederationChannelDetail" => validate_channel_detail(schema, fields),
        "FederationChannelName" => validate_channel_name(schema, fields),
        "FederationClientTag" => validate_client_tag(schema, fields),
        "FederationDeliveredMessage" => validate_delivered_message(schema, fields),
        "FederationDepartedChannel" => validate_nonzero_field(schema, fields, "resulting_revision"),
        "FederationEvent" => validate_event_tuples(schema, fields),
        "FederationHistoryReference" => validate_history_reference(schema, fields),
        "FederationHistoryMessage" => validate_history_message(schema, fields),
        "FederationHistoryAuthorization" => validate_history_authorization(schema, fields),
        "FederationInviteProjection" => validate_invite_projection(schema, fields),
        "FederationJoinTarget" => validate_join_target(schema, fields),
        "FederationMessageTarget" => validate_message_target(schema, fields),
        "FederationMembership" => validate_membership(schema, fields),
        "FederationMembershipView" => validate_membership_view(schema, fields),
        "FederationModeChange" => validate_mode_change(schema, fields),
        "FederationModeListEntry" => validate_mode_list_entry(schema, fields),
        "FederationNickname" => validate_nickname(schema, fields),
        "FederationOrigin" => validate_origin(schema, fields),
        "FederationParameter" => validate_parameter(schema, fields),
        "FederationPublicCloak" => validate_public_cloak(schema, fields),
        "FederationProjectedModeChange" => validate_projected_mode_change(schema, fields),
        "FederationQueryTarget" => validate_query_target(schema, fields),
        "FederationReply" => validate_reply(schema, fields),
        "FederationResult" => validate_result_envelope(schema, fields),
        "FederationSessionProjection" => validate_session_projection(schema, fields),
        "FederationSourceView" => validate_source_view(schema, fields),
        "FederationTypedMask" => validate_typed_mask(schema, fields),
        "HistorySelector" => validate_history_selector(schema, fields),
        "PrincipalRef" => validate_principal(schema, fields),
        "directory.channel_mode_list" => validate_directory_mode_code(schema, fields),
        "directory.whowas" => validate_whowas_count(schema, fields),
        _ => Ok(()),
    }
}

fn validate_event_schema(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    match schema.name {
        "event.away_changed" => validate_away_fields(schema, fields),
        "event.channel_destroyed" => validate_nonzero_field(schema, fields, "final_revision"),
        "event.channel_hidden" => validate_nonzero_field(schema, fields, "last_revision"),
        "event.channel_memberships_recomputed" => validate_membership_recompute(schema, fields),
        "event.channel_modes_changed" | "event.invite_removed" => {
            validate_nonzero_field(schema, fields, "resulting_revision")
        }
        "event.display_name_changed" => {
            validate_optional_display_name(schema, fields, "display_name")
        }
        "event.member_joined" => validate_member_joined_event(schema, fields),
        "event.kicked" => validate_kicked_event(schema, fields),
        "event.member_parted" => validate_member_parted_event(schema, fields),
        "event.network_notice" => validate_network_notice(schema, fields),
        "event.request_completed" => {
            validate_nonzero_field(schema, fields, "resulting_state_generation")
        }
        "event.session_hidden" => validate_session_hidden(schema, fields),
        "event.topic_changed" => validate_topic_change(schema, fields),
        _ => Ok(()),
    }
}

fn validate_operation_schema(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    match schema.name {
        "operation.account_settings" => {
            validate_nonzero_field(schema, fields, "expected_account_revision")
        }
        "operation.account_create_finish"
        | "operation.account_create_start"
        | "operation.credential_change_finish"
        | "operation.credential_change_start"
        | "operation.opaque_auth_finish"
        | "operation.opaque_auth_start" => validate_account_service_operation(schema, fields),
        "operation.away" => validate_away_operation(schema, fields),
        "operation.channel_mode" => validate_channel_mode_operation(schema, fields),
        "operation.channel_register"
        | "operation.channel_settings"
        | "operation.channel_unregister" => {
            validate_nonzero_field(schema, fields, "expected_channel_revision")
        }
        "operation.history_query" => validate_query_limit(schema, fields),
        "operation.invite" => validate_nonzero_field(schema, fields, "expected_channel_revision"),
        "operation.join" => validate_nonzero_field(schema, fields, "expected_session_revision"),
        "operation.kick" => validate_kick_targets(schema, fields),
        "operation.message" => validate_message_operation(schema, fields),
        "operation.nick_change" => validate_nick_change(schema, fields),
        "operation.part" => validate_part_operation(schema, fields),
        "operation.session_open" => validate_session_open(schema, fields),
        "operation.setname" => validate_setname_operation(schema, fields),
        "operation.topic" => validate_topic_operation(schema, fields),
        "operation.user_mode" => validate_user_mode_operation(schema, fields),
        _ => Ok(()),
    }
}

fn validate_result_schema(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    match schema.name {
        "result.account_created" => validate_created_result(schema, fields),
        "result.auth_challenge" => validate_auth_challenge_result(schema, fields),
        "result.authenticated" => validate_authenticated_result(schema, fields),
        "result.committed" => validate_nonzero_field(schema, fields, "resulting_state_generation"),
        "result.failed" => validate_failed_result(schema, fields),
        "result.reply_page" => validate_reply_page(schema, fields),
        "result.history_page" => validate_history_page(schema, fields),
        "result.session_registered" => validate_registered_result(schema, fields),
        _ => Ok(()),
    }
}

pub(crate) fn validate_embedded_semantics(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
    budget: &mut DecodeBudget,
    depth: usize,
    pending: &mut Vec<(SchemaObject, usize)>,
) -> Result<(), CodecError> {
    match schema.name {
        "AccountCreateStart" | "FederationActorView" | "FederationSessionEventView" => {
            validate_optional_schema_embedded(schema, fields, budget, depth, pending)
        }
        "DirectoryQuery"
        | "FederationEvent"
        | "FederationProjectionValue"
        | "FederationRequest"
        | "FederationResult" => {
            validate_discriminated_embedded(schema, fields, budget, depth, pending)
        }
        "FederationModeChange" => {
            validate_mode_change_embedded(schema, fields, budget, depth, pending)
        }
        "FederationInviteEventView" => {
            validate_invite_event_embedded(schema, fields, budget, depth, pending)
        }
        "FederationProjectedModeChange" => {
            validate_projected_mode_embedded(schema, fields, budget, depth, pending)
        }
        _ => Ok(()),
    }
}

fn validate_optional_schema_embedded(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
    budget: &mut DecodeBudget,
    depth: usize,
    pending: &mut Vec<(SchemaObject, usize)>,
) -> Result<(), CodecError> {
    if schema.name == "FederationSessionEventView" {
        return validate_session_event_embedded(schema, fields, budget, depth, pending);
    }
    let (field_name, nested_schema) = match schema.name {
        "AccountCreateStart" => ("creation_invite", "AccountCreationInvite"),
        "FederationActorView" => ("source", "FederationSourceView"),
        _ => return Err(CodecError::SchemaMismatch),
    };
    validate_optional_embedded(
        schema,
        fields,
        field_name,
        nested_schema,
        budget,
        depth,
        pending,
    )
}

fn validate_session_event_embedded(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
    budget: &mut DecodeBudget,
    depth: usize,
    pending: &mut Vec<(SchemaObject, usize)>,
) -> Result<(), CodecError> {
    let bytes = opaque_field(schema, fields, "home_session_projection")?;
    if bytes.is_empty() {
        return Ok(());
    }
    let child_depth = depth.checked_add(1).ok_or(CodecError::Overflow)?;
    let projection =
        decode_one_without_embedded("FederationSessionProjection", bytes, budget, child_depth)?;
    let source = structure_field(schema, fields, "source")?;
    validate_session_event_identity(source, &projection)?;
    retain_embedded(pending, projection, child_depth)
}

fn validate_session_event_identity(
    source: &SchemaObject,
    projection: &SchemaObject,
) -> Result<(), CodecError> {
    semantic(
        opaque_field(source.schema, &source.fields, "user_id")?
            == opaque_field(projection.schema, &projection.fields, "user_id")?,
    )?;
    semantic(
        opaque_field(source.schema, &source.fields, "account_label")?
            == opaque_field(projection.schema, &projection.fields, "account_label")?,
    )?;
    validate_matching_structure_fields(source, projection, "nickname", &["value"])?;
    validate_matching_structure_fields(
        source,
        projection,
        "public_cloak",
        &["user_component", "host_component"],
    )
}

fn validate_matching_structure_fields(
    first: &SchemaObject,
    second: &SchemaObject,
    field_name: &str,
    child_fields: &[&str],
) -> Result<(), CodecError> {
    let first = structure_field(first.schema, &first.fields, field_name)?;
    let second = structure_field(second.schema, &second.fields, field_name)?;
    for child_field in child_fields {
        semantic(
            opaque_field(first.schema, &first.fields, child_field)?
                == opaque_field(second.schema, &second.fields, child_field)?,
        )?;
    }
    Ok(())
}

fn validate_discriminated_embedded(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
    budget: &mut DecodeBudget,
    depth: usize,
    pending: &mut Vec<(SchemaObject, usize)>,
) -> Result<(), CodecError> {
    let (kind_field, value_field) = match schema.name {
        "DirectoryQuery" => ("query_kind", "query"),
        "FederationEvent" => ("event_kind", "event"),
        "FederationProjectionValue" => ("projection_kind", "value"),
        "FederationRequest" => ("opcode", "operation"),
        "FederationResult" => ("result_kind", "result"),
        _ => return Err(CodecError::SchemaMismatch),
    };
    let kind = unsigned_field(schema, fields, kind_field)?;
    let nested_schema = discriminated_arm(schema.name, kind)?;
    if schema.name != "FederationEvent" {
        return validate_embedded(
            schema,
            fields,
            value_field,
            nested_schema,
            budget,
            depth,
            pending,
        );
    }
    let (object, child_depth) =
        decode_embedded(schema, fields, value_field, nested_schema, budget, depth)?;
    validate_event_target_binding(schema, fields, &object)?;
    validate_event_projection_consistency(&object, budget, child_depth)?;
    retain_embedded(pending, object, child_depth)
}

fn validate_event_target_binding(
    envelope_schema: &SchemaDescriptor,
    envelope_fields: &[WireValue],
    event: &SchemaObject,
) -> Result<(), CodecError> {
    let target_server_id = opaque_field(envelope_schema, envelope_fields, "target_server_id")?;
    for value in &event.fields {
        let Some(home_server_id) = event_projection_home_server(value)? else {
            continue;
        };
        semantic(home_server_id == target_server_id)?;
    }
    Ok(())
}

fn event_projection_home_server(value: &WireValue) -> Result<Option<&[u8]>, CodecError> {
    match value {
        WireValue::Structure(session_view)
            if session_view.schema.name == "FederationSessionEventView" =>
        {
            let projection = opaque_field(
                session_view.schema,
                &session_view.fields,
                "home_session_projection",
            )?;
            if projection.is_empty() {
                return Ok(None);
            }
            projection
                .get(SESSION_PROJECTION_HOME_SERVER_OFFSET..SESSION_PROJECTION_HOME_SERVER_END)
                .ok_or(CodecError::CrossReference)
                .map(Some)
        }
        WireValue::ProjectionUnion { value, .. }
            if value.schema.name == "FederationSessionProjection" =>
        {
            opaque_field(value.schema, &value.fields, "home_server_id").map(Some)
        }
        _ => Ok(None),
    }
}

fn validate_event_projection_consistency(
    event: &SchemaObject,
    budget: &mut DecodeBudget,
    depth: usize,
) -> Result<(), CodecError> {
    match event.schema.name {
        "event.away_changed" => {
            let Some(projection) = decode_event_home_projection(event, budget, depth)? else {
                return Ok(());
            };
            semantic(
                unsigned_field(event.schema, &event.fields, "away_kind")?
                    == unsigned_field(projection.schema, &projection.fields, "away_kind")?,
            )?;
            semantic(
                opaque_field(event.schema, &event.fields, "away_text")?
                    == opaque_field(projection.schema, &projection.fields, "away_text")?,
            )
        }
        "event.display_name_changed" => {
            let Some(projection) = decode_event_home_projection(event, budget, depth)? else {
                return Ok(());
            };
            semantic(
                opaque_field(event.schema, &event.fields, "display_name")?
                    == opaque_field(projection.schema, &projection.fields, "display_name")?,
            )
        }
        "event.channel_modes_changed" => validate_projected_mode_channels(event),
        _ => Ok(()),
    }
}

fn decode_event_home_projection(
    event: &SchemaObject,
    budget: &mut DecodeBudget,
    depth: usize,
) -> Result<Option<SchemaObject>, CodecError> {
    let session = structure_field(event.schema, &event.fields, "session")?;
    let bytes = opaque_field(session.schema, &session.fields, "home_session_projection")?;
    if bytes.is_empty() {
        return Ok(None);
    }
    let projection_depth = depth.checked_add(2).ok_or(CodecError::Overflow)?;
    decode_one_without_embedded(
        "FederationSessionProjection",
        bytes,
        budget,
        projection_depth,
    )
    .map(Some)
}

fn validate_projected_mode_channels(event: &SchemaObject) -> Result<(), CodecError> {
    let event_channel = opaque_field(event.schema, &event.fields, "channel_instance_id")?;
    let changes = vector_field(event.schema, &event.fields, "changes")?;
    for change in changes {
        let mode_code = unsigned_field(change.schema, &change.fields, "mode_code")?;
        if !matches!(mode_code, 1..=3 | 12..=16) {
            continue;
        }
        let argument = opaque_field(change.schema, &change.fields, "argument")?;
        let projected_channel = argument
            .get(..CHANNEL_INSTANCE_ID_BYTES)
            .ok_or(CodecError::CrossReference)?;
        semantic(projected_channel == event_channel)?;
    }
    Ok(())
}

fn discriminated_arm(owner_schema: &str, kind: u64) -> Result<&'static str, CodecError> {
    match owner_schema {
        "DirectoryQuery" => directory_arm(kind),
        "FederationEvent" => event_arm(kind),
        "FederationProjectionValue" => projection_arm(kind),
        "FederationRequest" => operation_arm(kind),
        "FederationResult" => result_arm(kind),
        _ => Err(CodecError::SchemaMismatch),
    }
}

fn validate_mode_change_embedded(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
    budget: &mut DecodeBudget,
    depth: usize,
    pending: &mut Vec<(SchemaObject, usize)>,
) -> Result<(), CodecError> {
    let mode_code = unsigned_field(schema, fields, "mode_code")?;
    if !(1..=3).contains(&mode_code) {
        return Ok(());
    }
    let (mask, child_depth) = decode_embedded(
        schema,
        fields,
        "argument",
        "FederationTypedMask",
        budget,
        depth,
    )?;
    let quiet = unsigned_field(mask.schema, &mask.fields, "quiet")?;
    semantic(mode_code == 1 || quiet == 0)?;
    retain_embedded(pending, mask, child_depth)
}

fn field<'a>(
    schema: &SchemaDescriptor,
    fields: &'a [WireValue],
    name: &str,
) -> Result<&'a WireValue, CodecError> {
    schema
        .fields
        .iter()
        .zip(fields)
        .find_map(|(descriptor, value)| (descriptor.name == name).then_some(value))
        .ok_or(CodecError::SchemaMismatch)
}

fn unsigned_field(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
    name: &str,
) -> Result<u64, CodecError> {
    match field(schema, fields, name)? {
        WireValue::Unsigned(value) => Ok(*value),
        _ => Err(CodecError::TypeMismatch),
    }
}

fn opaque_field<'a>(
    schema: &SchemaDescriptor,
    fields: &'a [WireValue],
    name: &str,
) -> Result<&'a [u8], CodecError> {
    match field(schema, fields, name)? {
        WireValue::Opaque(value) => Ok(value),
        _ => Err(CodecError::TypeMismatch),
    }
}

fn structure_field<'a>(
    schema: &SchemaDescriptor,
    fields: &'a [WireValue],
    name: &str,
) -> Result<&'a SchemaObject, CodecError> {
    match field(schema, fields, name)? {
        WireValue::Structure(value) => Ok(value),
        _ => Err(CodecError::TypeMismatch),
    }
}

fn vector_field<'a>(
    schema: &SchemaDescriptor,
    fields: &'a [WireValue],
    name: &str,
) -> Result<&'a [SchemaObject], CodecError> {
    match field(schema, fields, name)? {
        WireValue::Vector(value) => Ok(value),
        _ => Err(CodecError::TypeMismatch),
    }
}

fn semantic(condition: bool) -> Result<(), CodecError> {
    if condition {
        return Ok(());
    }
    Err(CodecError::CrossReference)
}

fn validate_normalized_login(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    let bytes = opaque_field(schema, fields, "normalized_login")?;
    let text = std::str::from_utf8(bytes).map_err(|_| CodecError::CrossReference)?;
    let normalized = NormalizedLogin::prepare(text).map_err(|_| CodecError::CrossReference)?;
    semantic(normalized.as_str() == text)
}

fn validate_credential_change_start(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    validate_required_account(schema, fields, "account_id")
}

fn validate_creation_invite(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    let not_before = unsigned_field(schema, fields, "not_before")?;
    let expires_at = unsigned_field(schema, fields, "expires_at")?;
    let use_limit = unsigned_field(schema, fields, "use_limit")?;
    let lifetime = expires_at
        .checked_sub(not_before)
        .ok_or(CodecError::CrossReference)?;
    semantic((1..=2_592_000).contains(&lifetime) && use_limit == 1)
}

fn validate_account_challenge(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    let message = opaque_field(schema, fields, "opaque_message")?;
    semantic(matches!(message.len(), 64 | 320))
}

fn validate_account_completion(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    let status = unsigned_field(schema, fields, "status")?;
    let account_id = opaque_field(schema, fields, "account_id")?;
    let generation = unsigned_field(schema, fields, "account_session_generation")?;
    if status == 1 {
        return semantic(account_id.iter().all(|byte| *byte == 0) && generation == 0);
    }
    AccountId::parse_wire_bytes(account_id).map_err(|_| CodecError::CrossReference)?;
    Ok(())
}

fn validate_account_projection(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    validate_required_account(schema, fields, "account_id")?;
    semantic(unsigned_field(schema, fields, "account_session_generation")? != 0)?;
    semantic(unsigned_field(schema, fields, "account_revision")? != 0)
}

fn validate_padding_shape(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
    payload_name: &str,
    combined_length: usize,
) -> Result<(), CodecError> {
    let payload = opaque_field(schema, fields, payload_name)?;
    let padding = opaque_field(schema, fields, "zero_padding")?;
    let total = payload
        .len()
        .checked_add(padding.len())
        .ok_or(CodecError::Overflow)?;
    semantic(total == combined_length)
}

fn validate_account_setting(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    let kind = unsigned_field(schema, fields, "setting_kind")?;
    let value = opaque_field(schema, fields, "value")?;
    match kind {
        1 => {
            let text = std::str::from_utf8(value).map_err(|_| CodecError::CrossReference)?;
            AccountLabel::parse(text).map_err(|_| CodecError::CrossReference)?;
            Ok(())
        }
        2..=6 | 11 | 13..=15 => semantic(value.is_empty()),
        7 | 8 => {
            AccountId::parse_wire_bytes(value).map_err(|_| CodecError::CrossReference)?;
            Ok(())
        }
        9 | 10 => validate_nickname_bytes(value, false),
        12 => semantic(value.len() == USER_ID_BYTES),
        _ => Err(CodecError::UnknownDiscriminant),
    }
}

fn validate_account_service_operation(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    let expected = match schema.name {
        "operation.account_create_start" => 1,
        "operation.account_create_finish" => 2,
        "operation.opaque_auth_start" => 3,
        "operation.opaque_auth_finish" => 4,
        "operation.credential_change_start" => 5,
        "operation.credential_change_finish" => 6,
        _ => return Err(CodecError::SchemaMismatch),
    };
    let envelope = structure_field(schema, fields, "account_service_envelope")?;
    let header = structure_field(envelope.schema, &envelope.fields, "header")?;
    semantic(unsigned_field(header.schema, &header.fields, "message_kind")? == expected)
}

fn validate_directory_cursor(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    let kind = unsigned_field(schema, fields, "query_kind")?;
    let cursor = opaque_field(schema, fields, "cursor")?;
    let cursor_permitted = matches!(kind, 1 | 2 | 3 | 8 | 12 | 16);
    semantic(cursor.is_empty() || (cursor_permitted && cursor.len() == 32))
}

fn validate_presence_payload(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
    presence_name: &str,
    payload_name: &str,
) -> Result<(), CodecError> {
    let presence = unsigned_field(schema, fields, presence_name)?;
    let payload = opaque_field(schema, fields, payload_name)?;
    semantic(matches!(
        (presence, payload.is_empty()),
        (0, true) | (1, false)
    ))
}

fn validate_channel_detail(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    validate_channel_detail_names(schema, fields)?;
    validate_nonzero_field(schema, fields, "channel_revision")?;
    let bits = unsigned_field(schema, fields, "simple_mode_bits")?;
    let content_policy = unsigned_field(schema, fields, "content_policy")?;
    let binding = opaque_field(schema, fields, "e2ee_route_binding")?;
    let bits_valid = bits & !0x3f == 0 && bits & 0x04 != 0 && bits & 0x18 != 0x18;
    let binding_valid = matches!((content_policy, binding.len()), (1, 0) | (2, 32));
    semantic(bits_valid && binding_valid)
}

fn validate_channel_detail_names(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    let canonical = structure_field(schema, fields, "canonical_name")?;
    let display = structure_field(schema, fields, "display_name")?;
    let canonical = parsed_channel_name(canonical)?;
    let display = parsed_channel_name(display)?;
    semantic(
        canonical.presentation() == canonical.canonical()
            && canonical.canonical() == display.canonical()
            && canonical.is_global()
            && display.is_global(),
    )
}

fn parsed_channel_name(object: &SchemaObject) -> Result<ChannelName, CodecError> {
    let value = opaque_field(object.schema, &object.fields, "value")?;
    let text = std::str::from_utf8(value).map_err(|_| CodecError::CrossReference)?;
    ChannelName::parse(text).map_err(|_| CodecError::CrossReference)
}

fn validate_channel_name(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    let value = opaque_field(schema, fields, "value")?;
    let text = std::str::from_utf8(value).map_err(|_| CodecError::CrossReference)?;
    let name = ChannelName::parse(text).map_err(|_| CodecError::CrossReference)?;
    semantic(name.is_global())
}

fn validate_client_tag(schema: &SchemaDescriptor, fields: &[WireValue]) -> Result<(), CodecError> {
    let key = opaque_field(schema, fields, "key")?;
    let value = opaque_field(schema, fields, "value")?;
    std::str::from_utf8(key).map_err(|_| CodecError::CrossReference)?;
    std::str::from_utf8(value).map_err(|_| CodecError::CrossReference)?;
    let key_valid = key.first() == Some(&b'+')
        && key
            .iter()
            .all(|byte| !matches!(byte, 0 | b'\r' | b'\n' | b' ' | b';' | b'='));
    semantic(key_valid)?;
    semantic(!value.contains(&0))
}

fn validate_delivered_message(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    let message_kind = unsigned_field(schema, fields, "message_kind")?;
    let target_kind = unsigned_field(schema, fields, "target_kind")?;
    let channel_sequence = unsigned_field(schema, fields, "channel_event_sequence")?;
    let tags = vector_field(schema, fields, "tags")?;
    let body = opaque_field(schema, fields, "body")?;
    validate_nonzero_field(schema, fields, "target_revision")?;
    validate_message_shape(message_kind, tags.len(), body)?;
    validate_utf8_text(body)?;
    semantic(matches!(target_kind, 1) == (channel_sequence != 0))
}

fn validate_history_message(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    let kind = unsigned_field(schema, fields, "message_kind")?;
    let received = unsigned_field(schema, fields, "received_unix_milliseconds")?;
    let expires = unsigned_field(schema, fields, "expires_unix_milliseconds")?;
    let tags = vector_field(schema, fields, "tags")?;
    let body = opaque_field(schema, fields, "body")?;
    semantic(matches!(kind, 1 | 2) && received != 0 && expires > received)?;
    validate_nonzero_field(schema, fields, "channel_event_sequence")?;
    validate_message_shape(kind, tags.len(), body)?;
    validate_utf8_text(body)?;
    let mut previous: Option<&[u8]> = None;
    for tag in tags {
        let key = opaque_field(tag.schema, &tag.fields, "key")?;
        semantic(previous.is_none_or(|previous| previous < key))?;
        previous = Some(key);
    }
    Ok(())
}

fn validate_history_authorization(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    validate_nonzero_field(schema, fields, "session_generation")?;
    validate_nonzero_field(schema, fields, "membership_revision")?;
    validate_nonzero_field(schema, fields, "history_authorization_generation")?;
    validate_optional_account(
        opaque_field(schema, fields, "account_id")?,
        unsigned_field(schema, fields, "account_session_generation")?,
    )
}

fn validate_history_page(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    validate_reply_page(schema, fields)?;
    let authorization = structure_field(schema, fields, "authorization")?;
    semantic(
        opaque_field(schema, fields, "session_id")?
            == opaque_field(authorization.schema, &authorization.fields, "session_id")?,
    )?;
    let rows = vector_field(schema, fields, "messages")?;
    let cursor = opaque_field(schema, fields, "next_cursor")?;
    let cut = unsigned_field(schema, fields, "snapshot_state_generation")?;
    semantic(cut != 0)?;
    semantic(cursor.is_empty() || !rows.is_empty())?;
    let mut previous: Option<(u64, &[u8])> = None;
    for row in rows {
        let sequence = unsigned_field(row.schema, &row.fields, "channel_event_sequence")?;
        semantic(sequence <= cut)?;
        let message_id = opaque_field(row.schema, &row.fields, "message_id")?;
        let position = (sequence, message_id);
        semantic(previous.is_none_or(|previous| previous < position))?;
        previous = Some(position);
    }
    Ok(())
}

fn validate_event_tuples(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    validate_nonzero_field(schema, fields, "coordinator_state_generation")?;
    validate_cross_profile_tuple(schema, fields)?;
    validate_request_tuple(schema, fields)
}

fn validate_cross_profile_tuple(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    let mutation = opaque_field(schema, fields, "cross_profile_mutation_id")?;
    let part = unsigned_field(schema, fields, "cross_profile_part_index")?;
    let count = unsigned_field(schema, fields, "cross_profile_part_count")?;
    let mutation_valid = if mutation.is_empty() {
        part == 0 && count == 0
    } else {
        mutation.len() == 16 && (2..=2_048).contains(&count) && part < count
    };
    semantic(mutation_valid)
}

fn validate_request_tuple(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    let request_ids = [
        opaque_field(schema, fields, "request_home_server_id")?,
        opaque_field(schema, fields, "request_server_incarnation")?,
        opaque_field(schema, fields, "request_origin_id")?,
        opaque_field(schema, fields, "request_id")?,
    ];
    let generation = unsigned_field(schema, fields, "request_origin_generation")?;
    let sequence = unsigned_field(schema, fields, "request_operation_sequence")?;
    let event_kind = unsigned_field(schema, fields, "event_kind")?;
    let empty = request_ids.iter().all(|value| value.is_empty());
    let present = request_ids.iter().all(|value| value.len() == 16);
    let tuple_valid = (empty && generation == 0 && sequence == 0 && event_kind != 22)
        || (present && event_kind == 22);
    semantic(tuple_valid)
}

fn validate_history_reference(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    let kind = unsigned_field(schema, fields, "reference_kind")?;
    let message_id = opaque_field(schema, fields, "message_id")?;
    let timestamp = unsigned_field(schema, fields, "unix_milliseconds")?;
    semantic(matches!(
        (kind, message_id.len(), timestamp),
        (0, 0, 0) | (1, 16, 0) | (2, 0, 1..=u64::MAX)
    ))
}

fn validate_join_target(schema: &SchemaDescriptor, fields: &[WireValue]) -> Result<(), CodecError> {
    let join_key = opaque_field(schema, fields, "join_key")?;
    if join_key.is_empty() {
        return Ok(());
    }
    validate_utf8_text(join_key)
}

fn validate_invite_projection(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    validate_nonzero_field(schema, fields, "creation_revision")?;
    validate_nonzero_field(schema, fields, "expires_at")
}

fn validate_message_target(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    let kind = unsigned_field(schema, fields, "target_kind")?;
    let value = opaque_field(schema, fields, "value")?;
    let revision = unsigned_field(schema, fields, "expected_target_revision")?;
    match kind {
        1 => semantic(value.len() == 16 && revision != 0),
        2 => {
            semantic(revision == 0)?;
            validate_nickname_bytes(value, true)
        }
        _ => Err(CodecError::UnknownDiscriminant),
    }
}

fn validate_mode_change(schema: &SchemaDescriptor, fields: &[WireValue]) -> Result<(), CodecError> {
    let direction = unsigned_field(schema, fields, "direction")?;
    let code = unsigned_field(schema, fields, "mode_code")?;
    let argument = opaque_field(schema, fields, "argument")?;
    if !(1..=18).contains(&code) {
        return Err(CodecError::CrossReference);
    }
    match code {
        1..=3 => semantic(!argument.is_empty()),
        4 => validate_key_mode_argument(direction, argument),
        5 => validate_limit_mode_argument(direction, argument),
        6..=11 => semantic(argument.is_empty() && !(direction == 2 && code == 8)),
        12..=16 => semantic(argument.len() == 16),
        17..=18 => semantic(argument.is_empty() && !(direction == 2 && code == 17)),
        _ => Err(CodecError::CrossReference),
    }
}

fn validate_projected_mode_change(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    semantic((1..=16).contains(&unsigned_field(schema, fields, "mode_code")?))
}

fn validate_key_mode_argument(direction: u64, argument: &[u8]) -> Result<(), CodecError> {
    if direction == 2 {
        return semantic(argument.is_empty());
    }
    let mut bytes = argument.iter();
    let high = u16::from(*bytes.next().ok_or(CodecError::CrossReference)?);
    let low = u16::from(*bytes.next().ok_or(CodecError::CrossReference)?);
    let length = usize::from((high << 8) | low);
    semantic((8..=256).contains(&length) && bytes.len() == length)?;
    validate_utf8_text(bytes.as_slice())
}

fn validate_limit_mode_argument(direction: u64, argument: &[u8]) -> Result<(), CodecError> {
    if direction == 2 {
        return semantic(argument.is_empty());
    }
    let value = argument.iter().try_fold(0_u32, |current, byte| {
        current
            .checked_shl(8)
            .map(|shifted| shifted | u32::from(*byte))
            .ok_or(CodecError::Overflow)
    })?;
    semantic(argument.len() == 4 && (1..=65_535).contains(&value))
}

fn validate_mode_list_entry(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    let code = unsigned_field(schema, fields, "mode_code")?;
    let created = unsigned_field(schema, fields, "created_at")?;
    let expires = unsigned_field(schema, fields, "expires_at")?;
    let mask = structure_field(schema, fields, "mask")?;
    let quiet = unsigned_field(mask.schema, &mask.fields, "quiet")?;
    semantic((1..=3).contains(&code) && (expires == 0 || expires > created))?;
    semantic(code == 1 || quiet == 0)
}

fn validate_membership_view(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    let membership = structure_field(schema, fields, "membership")?;
    let source = structure_field(schema, fields, "source")?;
    let member_user = opaque_field(membership.schema, &membership.fields, "user_id")?;
    let source_user = opaque_field(source.schema, &source.fields, "user_id")?;
    semantic(member_user == source_user)
}

fn validate_membership(schema: &SchemaDescriptor, fields: &[WireValue]) -> Result<(), CodecError> {
    validate_nonzero_field(schema, fields, "membership_revision")
}

fn validate_nickname(schema: &SchemaDescriptor, fields: &[WireValue]) -> Result<(), CodecError> {
    validate_nickname_bytes(opaque_field(schema, fields, "value")?, false)
}

fn validate_nickname_bytes(bytes: &[u8], require_canonical: bool) -> Result<(), CodecError> {
    let text = std::str::from_utf8(bytes).map_err(|_| CodecError::CrossReference)?;
    let nickname = Nickname::parse(text).map_err(|_| CodecError::CrossReference)?;
    semantic(!require_canonical || nickname.presentation() == nickname.canonical())
}

fn validate_origin(schema: &SchemaDescriptor, fields: &[WireValue]) -> Result<(), CodecError> {
    let generation = unsigned_field(schema, fields, "generation")?;
    let predecessor = opaque_field(schema, fields, "previous_origin_object_id")?;
    let session = opaque_field(schema, fields, "session_id")?;
    let user = opaque_field(schema, fields, "user_id")?;
    let account = opaque_field(schema, fields, "account_id")?;
    let account_generation = unsigned_field(schema, fields, "account_session_generation")?;
    semantic((session.is_empty() && user.is_empty()) || (session.len() == 16 && user.len() == 16))?;
    validate_optional_account(account, account_generation)?;
    semantic(account.is_empty() || !session.is_empty())?;
    if generation == 0 {
        return semantic(
            predecessor.iter().all(|byte| *byte == 0)
                && session.is_empty()
                && user.is_empty()
                && account.is_empty(),
        );
    }
    semantic(predecessor.iter().any(|byte| *byte != 0))
}

fn validate_parameter(schema: &SchemaDescriptor, fields: &[WireValue]) -> Result<(), CodecError> {
    let value = opaque_field(schema, fields, "value")?;
    std::str::from_utf8(value).map_err(|_| CodecError::CrossReference)?;
    semantic(
        value.first() != Some(&b':')
            && !value
                .iter()
                .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n' | b' ')),
    )
}

fn validate_public_cloak(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    let user = opaque_field(schema, fields, "user_component")?;
    let host = opaque_field(schema, fields, "host_component")?;
    let user = std::str::from_utf8(user).map_err(|_| CodecError::CrossReference)?;
    let host = std::str::from_utf8(host).map_err(|_| CodecError::CrossReference)?;
    PublicCloak::parse(user, host).map_err(|_| CodecError::CrossReference)?;
    Ok(())
}

fn validate_query_target(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    let kind = unsigned_field(schema, fields, "target_kind")?;
    let value = opaque_field(schema, fields, "value")?;
    match kind {
        0 => semantic(value.is_empty()),
        1 => validate_nickname_bytes(value, false),
        2 => {
            let text = std::str::from_utf8(value).map_err(|_| CodecError::CrossReference)?;
            let channel = ChannelName::parse(text).map_err(|_| CodecError::CrossReference)?;
            semantic(channel.is_global())
        }
        _ => Err(CodecError::UnknownDiscriminant),
    }
}

fn validate_reply(schema: &SchemaDescriptor, fields: &[WireValue]) -> Result<(), CodecError> {
    let command = opaque_field(schema, fields, "command")?;
    let command_text = std::str::from_utf8(command).map_err(|_| CodecError::CrossReference)?;
    let registered = if command.len() == 3 && command.iter().all(u8::is_ascii_digit) {
        command_text
            .parse::<u16>()
            .is_ok_and(|numeric| SERVER_NUMERICS.contains(&numeric))
    } else {
        SERVER_COMMANDS.contains(&command_text)
    };
    semantic(registered)?;
    let trailing_presence = unsigned_field(schema, fields, "trailing_presence")?;
    let trailing = opaque_field(schema, fields, "trailing")?;
    semantic(trailing_presence == 1 || trailing.is_empty())?;
    BoundedUtf8::<0, 4096>::try_from_bytes(trailing, ControlPolicy::RejectAll)
        .map_err(|_| CodecError::CrossReference)?;
    Ok(())
}

fn validate_result_envelope(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    let kind = unsigned_field(schema, fields, "result_kind")?;
    let completion = opaque_field(schema, fields, "completion_event_id")?;
    let replies = vector_field(schema, fields, "replies")?;
    let completion_valid = matches!((kind, completion.len()), (2 | 3, 16) | (1 | 4..=10, 0));
    let replies_valid = match kind {
        7 => !replies.is_empty(),
        9 | 10 => replies.is_empty(),
        _ => replies.len() <= 64,
    };
    let page_size_valid =
        !matches!(kind, 7 | 9 | 10) || measured_fields_len(schema, fields)? <= 65_536;
    semantic(completion_valid && replies_valid && page_size_valid)
}

fn validate_session_projection(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    validate_nonzero_field(schema, fields, "session_revision")?;
    let account = opaque_field(schema, fields, "account_id")?;
    let generation = unsigned_field(schema, fields, "account_session_generation")?;
    let label = opaque_field(schema, fields, "account_label")?;
    let display_name = opaque_field(schema, fields, "display_name")?;
    validate_optional_account(account, generation)?;
    validate_optional_display_name_bytes(display_name)?;
    if account.is_empty() {
        semantic(label.is_empty())?;
    } else if !label.is_empty() {
        let label = std::str::from_utf8(label).map_err(|_| CodecError::CrossReference)?;
        AccountLabel::parse(label).map_err(|_| CodecError::CrossReference)?;
    }
    let bits = unsigned_field(schema, fields, "user_mode_bits")?;
    semantic(bits & !0x03 == 0 && bits & 0x01 != 0)?;
    let away = unsigned_field(schema, fields, "away_kind")?;
    let away_text = opaque_field(schema, fields, "away_text")?;
    validate_utf8_text(away_text)?;
    semantic(matches!(
        (away, away_text.is_empty()),
        (0, true) | (1, false)
    ))
}

fn validate_source_view(schema: &SchemaDescriptor, fields: &[WireValue]) -> Result<(), CodecError> {
    validate_optional_account_label(opaque_field(schema, fields, "account_label")?)
}

fn validate_typed_mask(schema: &SchemaDescriptor, fields: &[WireValue]) -> Result<(), CodecError> {
    let kind = unsigned_field(schema, fields, "kind")?;
    let quiet = unsigned_field(schema, fields, "quiet")?;
    let value = opaque_field(schema, fields, "value")?;
    let prefix = match kind {
        1 => "$a:",
        2 => "$u:",
        3 => "$n:",
        4 => "$c:",
        _ => return Err(CodecError::UnknownDiscriminant),
    };
    let encoded_value_length = if kind == 2 {
        base64url_encoded_length(value.len())?
    } else {
        std::str::from_utf8(value).map_err(|_| CodecError::CrossReference)?;
        value.len()
    };
    let wrapper = if quiet == 1 { "$q:" } else { "" };
    let rendered_length = wrapper
        .len()
        .checked_add(prefix.len())
        .and_then(|length| length.checked_add(encoded_value_length))
        .ok_or(CodecError::Overflow)?;
    let mut rendered = String::new();
    rendered
        .try_reserve_exact(rendered_length)
        .map_err(|_| CodecError::AllocationFailed)?;
    rendered.push_str(wrapper);
    rendered.push_str(prefix);
    if kind == 2 {
        URL_SAFE_NO_PAD.encode_string(value, &mut rendered);
    } else {
        rendered.push_str(std::str::from_utf8(value).map_err(|_| CodecError::CrossReference)?);
    }
    if rendered.len() != rendered_length {
        return Err(CodecError::Overflow);
    }
    TypedMask::parse(&rendered).map_err(|_| CodecError::CrossReference)?;
    Ok(())
}

fn base64url_encoded_length(decoded: usize) -> Result<usize, CodecError> {
    let complete = decoded
        .checked_div(3)
        .and_then(|value| value.checked_mul(4))
        .ok_or(CodecError::Overflow)?;
    let remainder = match decoded % 3 {
        0 => 0,
        1 => 2,
        2 => 3,
        _ => return Err(CodecError::Overflow),
    };
    complete.checked_add(remainder).ok_or(CodecError::Overflow)
}

fn validate_history_selector(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    let kind = unsigned_field(schema, fields, "selector_kind")?;
    let first = structure_field(schema, fields, "first")?;
    let second = structure_field(schema, fields, "second")?;
    let first_kind = unsigned_field(first.schema, &first.fields, "reference_kind")?;
    let second_kind = unsigned_field(second.schema, &second.fields, "reference_kind")?;
    match kind {
        1 => semantic(second_kind == 0),
        2..=4 => semantic(first_kind != 0 && second_kind == 0),
        5 => semantic(first_kind != 0 && second_kind != 0),
        _ => Err(CodecError::UnknownDiscriminant),
    }
}

fn validate_principal(schema: &SchemaDescriptor, fields: &[WireValue]) -> Result<(), CodecError> {
    let kind = unsigned_field(schema, fields, "kind")?;
    let identifier = opaque_field(schema, fields, "identifier")?;
    match kind {
        1 => {
            AccountId::parse_wire_bytes(identifier).map_err(|_| CodecError::CrossReference)?;
            Ok(())
        }
        2 => semantic(identifier.len() == USER_ID_BYTES),
        _ => Err(CodecError::UnknownDiscriminant),
    }
}

fn validate_directory_mode_code(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    semantic((1..=3).contains(&unsigned_field(schema, fields, "mode_code")?))
}

fn validate_whowas_count(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    semantic((1..=10).contains(&unsigned_field(schema, fields, "count")?))
}

fn validate_away_fields(schema: &SchemaDescriptor, fields: &[WireValue]) -> Result<(), CodecError> {
    let kind = unsigned_field(schema, fields, "away_kind")?;
    let text = opaque_field(schema, fields, "away_text")?;
    validate_utf8_text(text)?;
    semantic(matches!((kind, text.is_empty()), (0, true) | (1, false)))
}

fn validate_membership_recompute(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    let channel = opaque_field(schema, fields, "channel_instance_id")?;
    let revision = unsigned_field(schema, fields, "resulting_revision")?;
    semantic(revision != 0)?;
    for view in vector_field(schema, fields, "memberships")? {
        let membership = structure_field(view.schema, &view.fields, "membership")?;
        let member_channel =
            opaque_field(membership.schema, &membership.fields, "channel_instance_id")?;
        let member_revision =
            unsigned_field(membership.schema, &membership.fields, "membership_revision")?;
        semantic(member_channel == channel && member_revision == revision)?;
    }
    Ok(())
}

fn validate_member_joined_event(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    validate_optional_display_name(schema, fields, "display_name")
}

fn validate_kicked_event(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    validate_nonzero_field(schema, fields, "resulting_revision")?;
    validate_utf8_text(opaque_field(schema, fields, "reason")?)
}

fn validate_member_parted_event(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    validate_nonzero_field(schema, fields, "resulting_revision")?;
    validate_utf8_text(opaque_field(schema, fields, "reason")?)
}

fn validate_optional_display_name(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
    name: &str,
) -> Result<(), CodecError> {
    validate_optional_display_name_bytes(opaque_field(schema, fields, name)?)
}

fn validate_network_notice(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    let code = opaque_field(schema, fields, "code")?;
    let code_valid = code.iter().all(|byte| {
        byte.is_ascii_uppercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
    });
    semantic(code_valid)?;
    validate_utf8_text(opaque_field(schema, fields, "safe_text")?)
}

fn validate_session_hidden(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    validate_nonzero_field(schema, fields, "last_revision")?;
    let hide_kind = unsigned_field(schema, fields, "hide_kind")?;
    let reason = opaque_field(schema, fields, "reason")?;
    validate_utf8_text(reason)?;
    semantic(hide_kind != 6 || reason == b"connection closed")
}

fn validate_topic_change(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    validate_nonzero_field(schema, fields, "resulting_revision")?;
    let actor = structure_field(schema, fields, "actor")?;
    semantic(unsigned_field(actor.schema, &actor.fields, "user_present")? == 1)?;
    let presence = unsigned_field(schema, fields, "topic_presence")?;
    let topic = opaque_field(schema, fields, "topic")?;
    let set_at = unsigned_field(schema, fields, "set_at")?;
    let message_id = opaque_field(schema, fields, "message_id")?;
    validate_utf8_text(topic)?;
    semantic(matches!(
        (presence, topic.is_empty(), set_at, message_id.len()),
        (0, true, 0, 0) | (1, false, 1..=u64::MAX, 16)
    ))
}

fn validate_query_limit(schema: &SchemaDescriptor, fields: &[WireValue]) -> Result<(), CodecError> {
    semantic((1..=100).contains(&unsigned_field(schema, fields, "limit")?))
}

fn validate_away_operation(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    validate_nonzero_field(schema, fields, "expected_session_revision")?;
    validate_utf8_text(opaque_field(schema, fields, "away_text")?)
}

fn validate_channel_mode_operation(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    validate_nonzero_field(schema, fields, "expected_channel_revision")?;
    validate_mode_vector(schema, fields, "changes", 1, 16)
}

fn validate_kick_targets(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    validate_nonzero_field(schema, fields, "expected_channel_revision")?;
    let targets = opaque_field(schema, fields, "target_user_ids")?;
    semantic(targets.len().is_multiple_of(USER_ID_BYTES))?;
    validate_fixed_chunks_ordered_unique(targets, USER_ID_BYTES)?;
    validate_utf8_text(opaque_field(schema, fields, "reason")?)
}

fn validate_message_operation(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    let kind = unsigned_field(schema, fields, "message_kind")?;
    let targets = vector_field(schema, fields, "targets")?;
    let tags = vector_field(schema, fields, "tags")?;
    let body = opaque_field(schema, fields, "body")?;
    validate_message_shape(kind, tags.len(), body)?;
    semantic(kind != 3 || targets.len() == 1)?;
    validate_utf8_text(body)
}

fn validate_nick_change(schema: &SchemaDescriptor, fields: &[WireValue]) -> Result<(), CodecError> {
    validate_nonzero_field(schema, fields, "expected_session_revision")?;
    validate_nickname_bytes(opaque_field(schema, fields, "nickname")?, false)
}

fn validate_session_open(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    validate_nickname_bytes(opaque_field(schema, fields, "nickname")?, false)?;
    validate_utf8_text(opaque_field(schema, fields, "realname")?)
}

fn validate_setname_operation(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    validate_nonzero_field(schema, fields, "expected_session_revision")?;
    validate_optional_display_name(schema, fields, "display_name")
}

fn validate_topic_operation(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    validate_nonzero_field(schema, fields, "expected_channel_revision")?;
    validate_utf8_text(opaque_field(schema, fields, "topic")?)
}

fn validate_user_mode_operation(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    validate_nonzero_field(schema, fields, "expected_session_revision")?;
    validate_mode_vector(schema, fields, "changes", 17, 18)
}

fn validate_message_shape(kind: u64, tag_count: usize, body: &[u8]) -> Result<(), CodecError> {
    match kind {
        1 => semantic(!body.is_empty()),
        2 => Ok(()),
        3 => semantic(body.is_empty() && tag_count != 0),
        _ => Err(CodecError::UnknownDiscriminant),
    }
}

fn validate_fixed_chunks_ordered_unique(bytes: &[u8], width: usize) -> Result<(), CodecError> {
    let mut previous: Option<&[u8]> = None;
    for chunk in bytes.chunks_exact(width) {
        if let Some(prior) = previous {
            semantic(prior < chunk)?;
        }
        previous = Some(chunk);
    }
    Ok(())
}

fn validate_mode_vector(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
    name: &str,
    minimum: u64,
    maximum: u64,
) -> Result<(), CodecError> {
    let changes = vector_field(schema, fields, name)?;
    for (position, change) in changes.iter().enumerate() {
        let code = unsigned_field(change.schema, &change.fields, "mode_code")?;
        if !(minimum..=maximum).contains(&code) {
            return Err(CodecError::CrossReference);
        }
        let direction = unsigned_field(change.schema, &change.fields, "direction")?;
        let argument = opaque_field(change.schema, &change.fields, "argument")?;
        let argument_identifies_target = matches!(code, 1..=3 | 12..=16);
        for prior in changes.iter().take(position) {
            let same_direction =
                unsigned_field(prior.schema, &prior.fields, "direction")? == direction;
            let same_code = unsigned_field(prior.schema, &prior.fields, "mode_code")? == code;
            let same_target_or_mask = !argument_identifies_target
                || opaque_field(prior.schema, &prior.fields, "argument")? == argument;
            if same_direction && same_code && same_target_or_mask {
                return Err(CodecError::DuplicateValue);
            }
        }
    }
    Ok(())
}

fn validate_part_operation(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    validate_nonzero_field(schema, fields, "expected_session_revision")?;
    let all = unsigned_field(schema, fields, "all_channels")?;
    let channels = vector_field(schema, fields, "channels")?;
    let reason = opaque_field(schema, fields, "reason")?;
    validate_utf8_text(reason)?;
    match all {
        0 => semantic((1..=20).contains(&channels.len())),
        1 => semantic(reason.is_empty()),
        _ => Err(CodecError::UnknownDiscriminant),
    }
}

fn validate_required_account(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
    name: &str,
) -> Result<(), CodecError> {
    AccountId::parse_wire_bytes(opaque_field(schema, fields, name)?)
        .map_err(|_| CodecError::CrossReference)?;
    Ok(())
}

fn validate_created_result(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    validate_required_account(schema, fields, "account_id")?;
    validate_nonzero_field(schema, fields, "account_revision")
}

fn validate_auth_challenge_result(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    let response = structure_field(schema, fields, "account_service_response")?;
    let header = structure_field(response.schema, &response.fields, "header")?;
    let kind = unsigned_field(header.schema, &header.fields, "response_kind")?;
    semantic(matches!(kind, 1 | 2 | 5))
}

fn validate_nonzero_field(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
    name: &str,
) -> Result<(), CodecError> {
    semantic(unsigned_field(schema, fields, name)? != 0)
}

fn validate_authenticated_result(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    validate_required_account(schema, fields, "account_id")?;
    semantic(unsigned_field(schema, fields, "account_session_generation")? != 0)
}

fn validate_failed_result(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    let code = opaque_field(schema, fields, "reply_code")?;
    let code = std::str::from_utf8(code).map_err(|_| CodecError::CrossReference)?;
    let descriptor = MAPPING_DESCRIPTORS
        .iter()
        .find(|descriptor| descriptor.name == "federation-failed-reply-codes")
        .ok_or(CodecError::UnknownSchema)?;
    semantic(
        descriptor
            .value
            .split(',')
            .any(|candidate| candidate == code),
    )?;
    validate_utf8_text(opaque_field(schema, fields, "safe_context")?)
}

fn validate_registered_result(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    let account = opaque_field(schema, fields, "account_id")?;
    let generation = unsigned_field(schema, fields, "account_session_generation")?;
    let revision = unsigned_field(schema, fields, "account_revision")?;
    validate_optional_account(account, generation)?;
    semantic((account.is_empty() && revision == 0) || (!account.is_empty() && revision != 0))?;
    validate_nonzero_field(schema, fields, "session_revision")?;
    validate_nonzero_field(schema, fields, "resulting_state_generation")
}

fn validate_reply_page(schema: &SchemaDescriptor, fields: &[WireValue]) -> Result<(), CodecError> {
    let snapshot = opaque_field(schema, fields, "snapshot_token")?;
    semantic(snapshot.iter().any(|byte| *byte != 0))
}

fn validate_optional_account(account: &[u8], generation: u64) -> Result<(), CodecError> {
    if account.is_empty() {
        return semantic(generation == 0);
    }
    semantic(account.len() == ACCOUNT_ID_BYTES && generation != 0)?;
    AccountId::parse_wire_bytes(account).map_err(|_| CodecError::CrossReference)?;
    Ok(())
}

fn validate_optional_account_label(bytes: &[u8]) -> Result<(), CodecError> {
    if bytes.is_empty() {
        return Ok(());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| CodecError::CrossReference)?;
    AccountLabel::parse(text).map_err(|_| CodecError::CrossReference)?;
    Ok(())
}

fn validate_optional_display_name_bytes(bytes: &[u8]) -> Result<(), CodecError> {
    if bytes.is_empty() {
        return Ok(());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| CodecError::CrossReference)?;
    let prepared = DisplayName::prepare(text).map_err(|_| CodecError::CrossReference)?;
    semantic(prepared.as_str() == text)
}

fn validate_utf8_text(bytes: &[u8]) -> Result<(), CodecError> {
    BoundedUtf8::<0, 4096>::try_from_bytes(bytes, ControlPolicy::RejectAll)
        .map_err(|_| CodecError::CrossReference)?;
    Ok(())
}

fn validate_embedded(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
    field_name: &str,
    nested_schema: &str,
    budget: &mut DecodeBudget,
    depth: usize,
    pending: &mut Vec<(SchemaObject, usize)>,
) -> Result<(), CodecError> {
    let (object, child_depth) =
        decode_embedded(schema, fields, field_name, nested_schema, budget, depth)?;
    retain_embedded(pending, object, child_depth)
}

fn decode_embedded(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
    field_name: &str,
    nested_schema: &str,
    budget: &mut DecodeBudget,
    depth: usize,
) -> Result<(SchemaObject, usize), CodecError> {
    let bytes = opaque_field(schema, fields, field_name)?;
    let child_depth = depth.checked_add(1).ok_or(CodecError::Overflow)?;
    let object = decode_one_without_embedded(nested_schema, bytes, budget, child_depth)?;
    Ok((object, child_depth))
}

fn retain_embedded(
    pending: &mut Vec<(SchemaObject, usize)>,
    object: SchemaObject,
    depth: usize,
) -> Result<(), CodecError> {
    pending
        .try_reserve(1)
        .map_err(|_| CodecError::AllocationFailed)?;
    pending.push((object, depth));
    Ok(())
}

fn validate_optional_embedded(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
    field_name: &str,
    nested_schema: &str,
    budget: &mut DecodeBudget,
    depth: usize,
    pending: &mut Vec<(SchemaObject, usize)>,
) -> Result<(), CodecError> {
    let bytes = opaque_field(schema, fields, field_name)?;
    if bytes.is_empty() {
        return Ok(());
    }
    let child_depth = depth.checked_add(1).ok_or(CodecError::Overflow)?;
    let object = decode_one_without_embedded(nested_schema, bytes, budget, child_depth)?;
    retain_embedded(pending, object, child_depth)
}

fn validate_invite_event_embedded(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
    budget: &mut DecodeBudget,
    depth: usize,
    pending: &mut Vec<(SchemaObject, usize)>,
) -> Result<(), CodecError> {
    let bytes = opaque_field(schema, fields, "local_invite_projection")?;
    if bytes.is_empty() {
        return Ok(());
    }
    let child_depth = depth.checked_add(1).ok_or(CodecError::Overflow)?;
    let invite =
        decode_one_without_embedded("FederationInviteProjection", bytes, budget, child_depth)?;
    let outer_channel = opaque_field(schema, fields, "channel_instance_id")?;
    let outer_invite = opaque_field(schema, fields, "invite_id")?;
    let outer_revision = unsigned_field(schema, fields, "resulting_revision")?;
    let inner_channel = opaque_field(invite.schema, &invite.fields, "channel_instance_id")?;
    let inner_invite = opaque_field(invite.schema, &invite.fields, "invite_id")?;
    let inner_revision = unsigned_field(invite.schema, &invite.fields, "creation_revision")?;
    semantic(
        outer_channel == inner_channel
            && outer_invite == inner_invite
            && outer_revision == inner_revision,
    )?;
    validate_invite_event_identity(schema, fields, &invite)?;
    retain_embedded(pending, invite, child_depth)
}

fn validate_invite_event_identity(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
    invite: &SchemaObject,
) -> Result<(), CodecError> {
    let inviter = structure_field(schema, fields, "inviter")?;
    let inviter_user = opaque_field(inviter.schema, &inviter.fields, "user_id")?;
    let recorded_inviter = opaque_field(invite.schema, &invite.fields, "inviter_user_id")?;
    semantic(inviter_user == recorded_inviter)?;

    let target = structure_field(invite.schema, &invite.fields, "target_principal")?;
    if unsigned_field(target.schema, &target.fields, "kind")? != 2 {
        return Ok(());
    }
    let target_user = opaque_field(target.schema, &target.fields, "identifier")?;
    let named_target = structure_field(schema, fields, "named_target")?;
    let named_user = opaque_field(named_target.schema, &named_target.fields, "user_id")?;
    semantic(target_user == named_user)
}

fn validate_projected_mode_embedded(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
    budget: &mut DecodeBudget,
    depth: usize,
    pending: &mut Vec<(SchemaObject, usize)>,
) -> Result<(), CodecError> {
    let code = unsigned_field(schema, fields, "mode_code")?;
    let argument = opaque_field(schema, fields, "argument")?;
    match code {
        1..=3 => {
            let child_depth = depth.checked_add(1).ok_or(CodecError::Overflow)?;
            let object = decode_one_without_embedded(
                "FederationModeListEntry",
                argument,
                budget,
                child_depth,
            )?;
            semantic(unsigned_field(object.schema, &object.fields, "mode_code")? == code)?;
            retain_embedded(pending, object, child_depth)
        }
        4 => semantic(matches!(argument, [0, 0] | [0, 1])),
        5 => validate_projected_limit(argument),
        6..=11 => semantic(argument.is_empty()),
        12..=16 => {
            let child_depth = depth.checked_add(1).ok_or(CodecError::Overflow)?;
            let object = decode_one_without_embedded(
                "FederationMembershipView",
                argument,
                budget,
                child_depth,
            )?;
            retain_embedded(pending, object, child_depth)
        }
        _ => Err(CodecError::UnknownDiscriminant),
    }
}

fn validate_projected_limit(argument: &[u8]) -> Result<(), CodecError> {
    let value = argument.iter().try_fold(0_u32, |current, byte| {
        current
            .checked_shl(8)
            .map(|shifted| shifted | u32::from(*byte))
            .ok_or(CodecError::Overflow)
    })?;
    semantic(argument.len() == 4 && value <= 65_535)
}

fn projection_arm(kind: u64) -> Result<&'static str, CodecError> {
    match kind {
        1 => Ok("FederationSessionProjection"),
        3 => Ok("FederationChannelDetail"),
        4 => Ok("FederationMembership"),
        6 => Ok("FederationInviteProjection"),
        7 => Ok("FederationAccountProjection"),
        _ => Err(CodecError::UnknownDiscriminant),
    }
}

fn directory_arm(kind: u64) -> Result<&'static str, CodecError> {
    match kind {
        1 => Ok("directory.list"),
        2 => Ok("directory.names"),
        3 => Ok("directory.who"),
        4 => Ok("directory.whois"),
        5 => Ok("directory.whowas"),
        6 => Ok("directory.ison"),
        7 => Ok("directory.userhost"),
        8 => Ok("directory.links"),
        9 => Ok("directory.monitor_add"),
        10 => Ok("directory.monitor_remove"),
        11 => Ok("directory.monitor_clear"),
        12 => Ok("directory.monitor_list"),
        13 => Ok("directory.monitor_status"),
        14 => Ok("directory.channel_topic"),
        15 => Ok("directory.channel_modes"),
        16 => Ok("directory.channel_mode_list"),
        _ => Err(CodecError::UnknownDiscriminant),
    }
}

fn operation_arm(opcode: u64) -> Result<&'static str, CodecError> {
    match opcode {
        1 => Ok("operation.session_open"),
        2 => Ok("operation.session_close"),
        3 => Ok("operation.nick_change"),
        4 => Ok("operation.join"),
        5 => Ok("operation.part"),
        6 => Ok("operation.channel_mode"),
        7 => Ok("operation.user_mode"),
        8 => Ok("operation.topic"),
        9 => Ok("operation.invite"),
        10 => Ok("operation.kick"),
        11 => Ok("operation.message"),
        12 => Ok("operation.away"),
        13 => Ok("operation.setname"),
        14 => Ok("operation.channel_register"),
        15 => Ok("operation.channel_unregister"),
        16 => Ok("operation.account_settings"),
        17 => Ok("operation.history_query"),
        18 => Ok("operation.directory_query"),
        19 => Ok("operation.account_create_start"),
        20 => Ok("operation.account_create_finish"),
        21 => Ok("operation.opaque_auth_start"),
        22 => Ok("operation.opaque_auth_finish"),
        24 => Ok("operation.channel_settings"),
        25 => Ok("operation.credential_change_start"),
        26 => Ok("operation.credential_change_finish"),
        _ => Err(CodecError::UnknownDiscriminant),
    }
}

fn result_arm(kind: u64) -> Result<&'static str, CodecError> {
    match kind {
        1 => Ok("result.failed"),
        2 => Ok("result.committed"),
        3 => Ok("result.session_registered"),
        4 => Ok("result.auth_challenge"),
        5 => Ok("result.authenticated"),
        6 => Ok("result.account_created"),
        7 => Ok("result.reply_page"),
        8 => Ok("result.no_content"),
        9 => Ok("result.history_page"),
        10 => Ok("result.history_expired"),
        _ => Err(CodecError::UnknownDiscriminant),
    }
}

fn event_arm(kind: u64) -> Result<&'static str, CodecError> {
    match kind {
        1 => Ok("event.session_visible"),
        2 => Ok("event.session_hidden"),
        3 => Ok("event.nickname_changed"),
        4 => Ok("event.channel_visible"),
        5 => Ok("event.channel_hidden"),
        6 => Ok("event.member_joined"),
        7 => Ok("event.member_parted"),
        8 => Ok("event.channel_modes_changed"),
        9 => Ok("event.topic_changed"),
        10 => Ok("event.invited"),
        11 => Ok("event.kicked"),
        12 => Ok("event.away_changed"),
        13 => Ok("event.display_name_changed"),
        14 => Ok("event.message_delivered"),
        15 => Ok("event.channel_destroyed"),
        16 => Ok("event.account_label_changed"),
        17 => Ok("event.network_notice"),
        18 => Ok("event.user_modes_changed"),
        19 => Ok("event.channel_policy_changed"),
        20 => Ok("event.channel_memberships_recomputed"),
        21 => Ok("event.account_state_changed"),
        22 => Ok("event.request_completed"),
        23 => Ok("event.invite_removed"),
        _ => Err(CodecError::UnknownDiscriminant),
    }
}

#[cfg(test)]
#[path = "tests/semantics.rs"]
mod tests;
