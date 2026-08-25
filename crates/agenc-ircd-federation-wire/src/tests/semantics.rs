#![forbid(unsafe_code)]

//! Focused alternatives and malformed cases for Appendix-B semantics.

use super::*;
use crate::codec::CanonicalEncode;
use crate::schema::{FieldDescriptor, FieldKind, schema_by_name};

const ACCOUNT: &[u8] = b"a_AAECAwQFBgcICQoLDA0ODw";
const MISSING_SCHEMA: SchemaDescriptor = SchemaDescriptor {
    name: "missing-test-schema",
    fields: &[],
};

fn schema(name: &str) -> &'static SchemaDescriptor {
    schema_by_name(name).unwrap_or(&MISSING_SCHEMA)
}

fn fields(
    schema: &'static SchemaDescriptor,
    mut value_for: impl FnMut(&str) -> Option<WireValue>,
) -> Vec<WireValue> {
    schema
        .fields
        .iter()
        .map(|descriptor| value_for(descriptor.name).unwrap_or(WireValue::Unsigned(0)))
        .collect()
}

fn validate(
    schema_name: &str,
    value_for: impl FnMut(&str) -> Option<WireValue>,
) -> Result<(), CodecError> {
    let descriptor = schema(schema_name);
    let values = fields(descriptor, value_for);
    validate_schema_semantics(descriptor, &values)
}

fn opaque(value: impl AsRef<[u8]>) -> WireValue {
    WireValue::Opaque(value.as_ref().to_vec())
}

fn unsigned(value: u64) -> WireValue {
    WireValue::Unsigned(value)
}

fn raw_object(schema_name: &str, values: Vec<WireValue>) -> SchemaObject {
    SchemaObject {
        schema: schema(schema_name),
        fields: values,
    }
}

fn history_reference(kind: u64, value: u8) -> SchemaObject {
    let descriptor = schema("FederationHistoryReference");
    raw_object(
        descriptor.name,
        fields(descriptor, |name| match name {
            "reference_kind" => Some(unsigned(kind)),
            "message_id" if kind == 1 => Some(opaque([value; 16])),
            "message_id" => Some(opaque([])),
            "unix_milliseconds" if kind == 2 => Some(unsigned(u64::from(value))),
            "unix_milliseconds" => Some(unsigned(0)),
            _ => None,
        }),
    )
}

fn typed_mask(quiet: u64) -> SchemaObject {
    let descriptor = schema("FederationTypedMask");
    raw_object(
        descriptor.name,
        fields(descriptor, |name| match name {
            "kind" => Some(unsigned(3)),
            "quiet" => Some(unsigned(quiet)),
            "value" => Some(opaque("nick*")),
            _ => None,
        }),
    )
}

fn channel_name(value: &[u8]) -> SchemaObject {
    let descriptor = schema("FederationChannelName");
    raw_object(
        descriptor.name,
        fields(descriptor, |name| (name == "value").then(|| opaque(value))),
    )
}

fn nickname(value: &[u8]) -> SchemaObject {
    let descriptor = schema("FederationNickname");
    raw_object(
        descriptor.name,
        fields(descriptor, |name| (name == "value").then(|| opaque(value))),
    )
}

fn public_cloak() -> SchemaObject {
    let descriptor = schema("FederationPublicCloak");
    raw_object(
        descriptor.name,
        fields(descriptor, |name| match name {
            "user_component" => Some(opaque("abcdefghij")),
            "host_component" => Some(opaque("abcdefghijklmnop")),
            _ => None,
        }),
    )
}

fn source_view(user: u8, nickname_value: &[u8], label: &[u8]) -> SchemaObject {
    let descriptor = schema("FederationSourceView");
    raw_object(
        descriptor.name,
        fields(descriptor, |name| match name {
            "user_id" => Some(opaque([user; 16])),
            "nickname" => Some(WireValue::Structure(Box::new(nickname(nickname_value)))),
            "public_cloak" => Some(WireValue::Structure(Box::new(public_cloak()))),
            "account_label" => Some(opaque(label)),
            _ => None,
        }),
    )
}

fn session_projection(user: u8, nickname_value: &[u8], label: &[u8]) -> SchemaObject {
    let descriptor = schema("FederationSessionProjection");
    raw_object(
        descriptor.name,
        fields(descriptor, |name| match name {
            "session_id" | "home_server_id" => Some(opaque([1; 16])),
            "user_id" => Some(opaque([user; 16])),
            "session_revision" => Some(unsigned(1)),
            "account_id" if label.is_empty() => Some(opaque([])),
            "account_id" => Some(opaque(ACCOUNT)),
            "account_session_generation" if label.is_empty() => Some(unsigned(0)),
            "account_session_generation" => Some(unsigned(1)),
            "nickname" => Some(WireValue::Structure(Box::new(nickname(nickname_value)))),
            "display_name" => Some(opaque([])),
            "public_cloak" => Some(WireValue::Structure(Box::new(public_cloak()))),
            "account_label" => Some(opaque(label)),
            "user_mode_bits" => Some(unsigned(1)),
            "away_kind" => Some(unsigned(0)),
            "away_text" => Some(opaque([])),
            _ => None,
        }),
    )
}

fn membership_view(channel: u8, user: u8, revision: u64) -> SchemaObject {
    let membership_schema = schema("FederationMembership");
    let membership = raw_object(
        membership_schema.name,
        fields(membership_schema, |name| match name {
            "channel_instance_id" => Some(opaque([channel; 16])),
            "user_id" => Some(opaque([user; 16])),
            "role" => Some(unsigned(0)),
            "membership_revision" => Some(unsigned(revision)),
            "joined_at" => Some(unsigned(1)),
            _ => None,
        }),
    );
    raw_object(
        "FederationMembershipView",
        vec![
            WireValue::Structure(Box::new(membership)),
            WireValue::Structure(Box::new(source_view(user, b"alice", b""))),
        ],
    )
}

fn mode_list_entry(code: u64) -> SchemaObject {
    let descriptor = schema("FederationModeListEntry");
    raw_object(
        descriptor.name,
        fields(descriptor, |name| match name {
            "channel_instance_id" | "entry_id" => Some(opaque([1; 16])),
            "mode_code" => Some(unsigned(code)),
            "mask" => Some(WireValue::Structure(Box::new(typed_mask(0)))),
            "setter" => Some(WireValue::Structure(Box::new(source_view(
                1, b"alice", b"",
            )))),
            "created_at" => Some(unsigned(1)),
            "expires_at" => Some(unsigned(0)),
            _ => None,
        }),
    )
}

#[test]
fn field_accessors_fail_closed_on_missing_or_wrong_types() {
    static ONLY: &[FieldDescriptor] = &[FieldDescriptor {
        name: "only",
        kind: FieldKind::Uint8,
    }];
    let descriptor = SchemaDescriptor {
        name: "test",
        fields: ONLY,
    };
    let unsigned_values = [unsigned(1)];
    let opaque_values = [opaque([])];

    assert_eq!(
        field(&descriptor, &unsigned_values, "missing").err(),
        Some(CodecError::SchemaMismatch)
    );
    assert_eq!(
        unsigned_field(&descriptor, &opaque_values, "only").err(),
        Some(CodecError::TypeMismatch)
    );
    assert_eq!(
        opaque_field(&descriptor, &unsigned_values, "only").err(),
        Some(CodecError::TypeMismatch)
    );
    assert_eq!(
        structure_field(&descriptor, &unsigned_values, "only").err(),
        Some(CodecError::TypeMismatch)
    );
    assert_eq!(
        vector_field(&descriptor, &unsigned_values, "only").err(),
        Some(CodecError::TypeMismatch)
    );
    assert_eq!(semantic(true), Ok(()));
    assert_eq!(semantic(false), Err(CodecError::CrossReference));
}

#[test]
fn account_invite_completion_padding_and_settings_cover_alternatives() {
    let invite = |not_before, expires_at, use_limit| {
        validate("AccountCreationInviteTBS", |name| match name {
            "not_before" => Some(unsigned(not_before)),
            "expires_at" => Some(unsigned(expires_at)),
            "use_limit" => Some(unsigned(use_limit)),
            _ => None,
        })
    };
    assert_eq!(invite(10, 11, 1), Ok(()));
    assert_eq!(invite(11, 10, 1), Err(CodecError::CrossReference));
    assert_eq!(invite(0, 2_592_001, 1), Err(CodecError::CrossReference));
    assert_eq!(invite(0, 1, 2), Err(CodecError::CrossReference));

    let completion = |status, account: &[u8], generation| {
        validate("AccountServiceCompletion", |name| match name {
            "status" => Some(unsigned(status)),
            "account_id" => Some(opaque(account)),
            "account_session_generation" => Some(unsigned(generation)),
            _ => None,
        })
    };
    assert_eq!(completion(1, &[0; 24], 0), Ok(()));
    assert_eq!(completion(1, &[1; 24], 0), Err(CodecError::CrossReference));
    assert_eq!(completion(1, &[0; 24], 1), Err(CodecError::CrossReference));
    assert_eq!(completion(2, ACCOUNT, 1), Ok(()));
    assert_eq!(completion(2, &[0; 24], 1), Err(CodecError::CrossReference));

    let padding = |payload: usize, padding: usize| {
        validate("AccountServiceResponsePlaintext", |name| match name {
            "payload" => Some(opaque(vec![0; payload])),
            "zero_padding" => Some(opaque(vec![0; padding])),
            _ => None,
        })
    };
    assert_eq!(padding(1, 4_201), Ok(()));
    assert_eq!(padding(1, 4_200), Err(CodecError::CrossReference));

    let setting = |kind, value: &[u8]| {
        validate("AccountSettingsChange", |name| match name {
            "setting_kind" => Some(unsigned(kind)),
            "value" => Some(opaque(value)),
            _ => None,
        })
    };
    assert_eq!(setting(1, b"Label"), Ok(()));
    assert_eq!(setting(1, b"-bad"), Err(CodecError::CrossReference));
    assert_eq!(setting(2, b""), Ok(()));
    assert_eq!(setting(11, b"x"), Err(CodecError::CrossReference));
    assert_eq!(setting(7, ACCOUNT), Ok(()));
    assert_eq!(setting(8, b"bad"), Err(CodecError::CrossReference));
    assert_eq!(setting(9, b"Nick"), Ok(()));
    assert_eq!(setting(10, b"9bad"), Err(CodecError::CrossReference));
    assert_eq!(setting(12, &[0; 16]), Ok(()));
    assert_eq!(setting(12, &[0; 15]), Err(CodecError::CrossReference));
    assert_eq!(setting(99, b""), Err(CodecError::UnknownDiscriminant));
}

#[test]
fn account_inputs_require_canonical_private_identifiers() {
    for schema_name in ["AccountCreateStart", "AuthStart"] {
        let login = |value: &[u8]| {
            validate(schema_name, |name| {
                (name == "normalized_login").then(|| opaque(value))
            })
        };
        assert_eq!(login(b"user"), Ok(()));
        assert_eq!(login(b"UsEr"), Err(CodecError::CrossReference));
        assert_eq!(login(&[0xff, 0xff, 0xff]), Err(CodecError::CrossReference));
    }

    let credential = |account: &[u8]| {
        validate("CredentialChangeStart", |name| {
            (name == "account_id").then(|| opaque(account))
        })
    };
    assert_eq!(credential(ACCOUNT), Ok(()));
    assert_eq!(credential(&[0; 24]), Err(CodecError::CrossReference));
}

#[test]
fn account_service_envelope_kinds_match_their_selected_arms() {
    let operation = |schema_name: &str, message_kind| {
        let header_schema = schema("AccountServiceRequestHeader");
        let header = raw_object(
            header_schema.name,
            fields(header_schema, |name| {
                (name == "message_kind").then(|| unsigned(message_kind))
            }),
        );
        let envelope_schema = schema("AccountServiceEnvelope");
        let mut header = Some(header);
        let envelope = raw_object(
            envelope_schema.name,
            fields(envelope_schema, |name| {
                (name == "header")
                    .then(|| {
                        header
                            .take()
                            .map(|value| WireValue::Structure(Box::new(value)))
                    })
                    .flatten()
            }),
        );
        let mut envelope = Some(envelope);
        validate(schema_name, |name| {
            (name == "account_service_envelope")
                .then(|| {
                    envelope
                        .take()
                        .map(|value| WireValue::Structure(Box::new(value)))
                })
                .flatten()
        })
    };

    assert_eq!(operation("operation.account_create_start", 1), Ok(()));
    assert_eq!(
        operation("operation.account_create_start", 3),
        Err(CodecError::CrossReference)
    );
    assert_eq!(operation("operation.credential_change_finish", 6), Ok(()));

    let challenge_result = |response_kind| {
        let header_schema = schema("AccountServiceResponseHeader");
        let header = raw_object(
            header_schema.name,
            fields(header_schema, |name| {
                (name == "response_kind").then(|| unsigned(response_kind))
            }),
        );
        let response_schema = schema("AccountServiceResponse");
        let mut header = Some(header);
        let response = raw_object(
            response_schema.name,
            fields(response_schema, |name| {
                (name == "header")
                    .then(|| {
                        header
                            .take()
                            .map(|value| WireValue::Structure(Box::new(value)))
                    })
                    .flatten()
            }),
        );
        let mut response = Some(response);
        validate("result.auth_challenge", |name| {
            (name == "account_service_response")
                .then(|| {
                    response
                        .take()
                        .map(|value| WireValue::Structure(Box::new(value)))
                })
                .flatten()
        })
    };
    assert_eq!(challenge_result(2), Ok(()));
    assert_eq!(challenge_result(4), Err(CodecError::CrossReference));
}

#[test]
fn operation_text_and_revision_fields_are_validated_at_ingress() {
    let nick_change = |revision, nickname: &[u8]| {
        validate("operation.nick_change", |name| match name {
            "expected_session_revision" => Some(unsigned(revision)),
            "nickname" => Some(opaque(nickname)),
            _ => None,
        })
    };
    assert_eq!(nick_change(1, b"Alice"), Ok(()));
    assert_eq!(nick_change(0, b"Alice"), Err(CodecError::CrossReference));
    assert_eq!(nick_change(1, b"9alice"), Err(CodecError::CrossReference));

    let session_open = |nickname: &[u8], realname: &[u8]| {
        validate("operation.session_open", |name| match name {
            "nickname" => Some(opaque(nickname)),
            "realname" => Some(opaque(realname)),
            _ => None,
        })
    };
    assert_eq!(session_open(b"Alice", "Alice Smith".as_bytes()), Ok(()));
    assert_eq!(
        session_open(b"Alice", &[0xff]),
        Err(CodecError::CrossReference)
    );

    let topic = |revision, value: &[u8]| {
        validate("operation.topic", |name| match name {
            "expected_channel_revision" => Some(unsigned(revision)),
            "topic" => Some(opaque(value)),
            _ => None,
        })
    };
    assert_eq!(topic(1, b"topic"), Ok(()));
    assert_eq!(topic(0, b"topic"), Err(CodecError::CrossReference));
    assert_eq!(topic(1, &[0]), Err(CodecError::CrossReference));
}

#[test]
fn directory_presence_channel_and_tag_rules_cover_alternatives() {
    let directory = |kind, cursor: &[u8]| {
        validate("DirectoryQuery", |name| match name {
            "query_kind" => Some(unsigned(kind)),
            "cursor" => Some(opaque(cursor)),
            _ => None,
        })
    };
    assert_eq!(directory(4, b""), Ok(()));
    assert_eq!(directory(1, &[0; 32]), Ok(()));
    assert_eq!(directory(4, &[0; 32]), Err(CodecError::CrossReference));
    assert_eq!(directory(1, &[0; 31]), Err(CodecError::CrossReference));

    let actor = |presence, source: &[u8]| {
        validate("FederationActorView", |name| match name {
            "user_present" => Some(unsigned(presence)),
            "source" => Some(opaque(source)),
            _ => None,
        })
    };
    assert_eq!(actor(0, b""), Ok(()));
    assert_eq!(actor(1, b"x"), Ok(()));
    assert_eq!(actor(0, b"x"), Err(CodecError::CrossReference));
    assert_eq!(actor(1, b""), Err(CodecError::CrossReference));

    let channel = |bits, policy, binding: &[u8]| {
        validate("FederationChannelDetail", |name| match name {
            "canonical_name" => Some(WireValue::Structure(Box::new(channel_name(b"#room")))),
            "display_name" => Some(WireValue::Structure(Box::new(channel_name(b"#Room")))),
            "channel_revision" => Some(unsigned(1)),
            "simple_mode_bits" => Some(unsigned(bits)),
            "content_policy" => Some(unsigned(policy)),
            "e2ee_route_binding" => Some(opaque(binding)),
            _ => None,
        })
    };
    assert_eq!(channel(0x04, 1, b""), Ok(()));
    assert_eq!(channel(0x04, 2, &[0; 32]), Ok(()));
    assert_eq!(channel(0, 1, b""), Err(CodecError::CrossReference));
    assert_eq!(channel(0x40, 1, b""), Err(CodecError::CrossReference));
    assert_eq!(channel(0x1c, 1, b""), Err(CodecError::CrossReference));
    assert_eq!(channel(0x04, 2, b""), Err(CodecError::CrossReference));

    let channel_identity = |canonical: &[u8], display: &[u8], revision| {
        validate("FederationChannelDetail", |name| match name {
            "canonical_name" => Some(WireValue::Structure(Box::new(channel_name(canonical)))),
            "display_name" => Some(WireValue::Structure(Box::new(channel_name(display)))),
            "channel_revision" => Some(unsigned(revision)),
            "simple_mode_bits" => Some(unsigned(0x04)),
            "content_policy" => Some(unsigned(1)),
            "e2ee_route_binding" => Some(opaque([])),
            _ => None,
        })
    };
    assert_eq!(channel_identity(b"#room", b"#Room", 1), Ok(()));
    assert_eq!(
        channel_identity(b"#Room", b"#Room", 1),
        Err(CodecError::CrossReference)
    );
    assert_eq!(
        channel_identity(b"#room", b"#other", 1),
        Err(CodecError::CrossReference)
    );
    assert_eq!(
        channel_identity(b"#room", b"#room", 0),
        Err(CodecError::CrossReference)
    );

    let channel_name = |value: &[u8]| {
        validate("FederationChannelName", |name| {
            (name == "value").then(|| opaque(value))
        })
    };
    assert_eq!(channel_name(b"#global"), Ok(()));
    assert_eq!(channel_name(b"&local"), Err(CodecError::CrossReference));
    assert_eq!(channel_name(&[0xff]), Err(CodecError::CrossReference));

    let tag = |key: &[u8], value: &[u8]| {
        validate("FederationClientTag", |name| match name {
            "key" => Some(opaque(key)),
            "value" => Some(opaque(value)),
            _ => None,
        })
    };
    assert_eq!(tag(b"+vendor/key-name", b"value"), Ok(()));
    assert_eq!(
        tag(b"vendor/key", b"value"),
        Err(CodecError::CrossReference)
    );
    assert_eq!(tag(b"+bad:key", b"value"), Err(CodecError::CrossReference));
    assert_eq!(tag(b"+key", &[0]), Err(CodecError::CrossReference));
}

#[test]
fn event_correlation_tuples_cover_empty_present_and_multipart_cases() {
    let event = |mutation: &[u8], part, count, event_kind, request: &[u8], generation, sequence| {
        validate("FederationEvent", |name| match name {
            "coordinator_state_generation" => Some(unsigned(1)),
            "cross_profile_mutation_id" => Some(opaque(mutation)),
            "cross_profile_part_index" => Some(unsigned(part)),
            "cross_profile_part_count" => Some(unsigned(count)),
            "event_kind" => Some(unsigned(event_kind)),
            "request_home_server_id"
            | "request_server_incarnation"
            | "request_origin_id"
            | "request_id" => Some(opaque(request)),
            "request_origin_generation" => Some(unsigned(generation)),
            "request_operation_sequence" => Some(unsigned(sequence)),
            _ => None,
        })
    };
    assert_eq!(event(b"", 0, 0, 1, b"", 0, 0), Ok(()));
    assert_eq!(
        event(b"", 1, 0, 1, b"", 0, 0),
        Err(CodecError::CrossReference)
    );
    assert_eq!(
        event(b"", 0, 1, 1, b"", 0, 0),
        Err(CodecError::CrossReference)
    );
    assert_eq!(event(&[1; 16], 0, 2, 1, b"", 0, 0), Ok(()));
    assert_eq!(
        event(&[1; 15], 0, 2, 1, b"", 0, 0),
        Err(CodecError::CrossReference)
    );
    assert_eq!(
        event(&[1; 16], 2, 2, 1, b"", 0, 0),
        Err(CodecError::CrossReference)
    );
    assert_eq!(
        event(&[1; 16], 0, 1, 1, b"", 0, 0),
        Err(CodecError::CrossReference)
    );
    assert_eq!(event(b"", 0, 0, 22, &[1; 16], 1, 1), Ok(()));
    assert_eq!(
        event(b"", 0, 0, 22, &[1; 16], 1, 0),
        Err(CodecError::CrossReference)
    );
    assert_eq!(
        event(b"", 0, 0, 22, &[1; 16], 0, 1),
        Err(CodecError::CrossReference)
    );
    assert_eq!(
        event(b"", 0, 0, 22, b"", 0, 0),
        Err(CodecError::CrossReference)
    );
    assert_eq!(
        event(b"", 0, 0, 1, b"", 1, 0),
        Err(CodecError::CrossReference)
    );
    assert_eq!(
        event(b"", 0, 0, 1, b"", 0, 1),
        Err(CodecError::CrossReference)
    );
    assert_eq!(
        event(b"", 0, 0, 1, &[1; 16], 1, 1),
        Err(CodecError::CrossReference)
    );
}

#[test]
fn history_target_and_mode_rules_cover_every_shape() {
    let history = |kind, id: &[u8], time| {
        validate("FederationHistoryReference", |name| match name {
            "reference_kind" => Some(unsigned(kind)),
            "message_id" => Some(opaque(id)),
            "unix_milliseconds" => Some(unsigned(time)),
            _ => None,
        })
    };
    assert_eq!(history(0, b"", 0), Ok(()));
    assert_eq!(history(1, &[0; 16], 0), Ok(()));
    assert_eq!(history(2, b"", 1), Ok(()));
    assert_eq!(history(2, b"", 0), Err(CodecError::CrossReference));
    assert_eq!(history(3, b"", 0), Err(CodecError::CrossReference));

    let target = |kind, value: &[u8], revision| {
        validate("FederationMessageTarget", |name| match name {
            "target_kind" => Some(unsigned(kind)),
            "value" => Some(opaque(value)),
            "expected_target_revision" => Some(unsigned(revision)),
            _ => None,
        })
    };
    assert_eq!(target(1, &[0; 16], 1), Ok(()));
    assert_eq!(target(1, &[0; 15], 1), Err(CodecError::CrossReference));
    assert_eq!(target(2, b"alice", 0), Ok(()));
    assert_eq!(target(2, b"Alice", 0), Err(CodecError::CrossReference));
    assert_eq!(target(2, b"alice", 1), Err(CodecError::CrossReference));
    assert_eq!(target(3, b"", 0), Err(CodecError::UnknownDiscriminant));

    let mode = |direction, code, argument: &[u8]| {
        validate("FederationModeChange", |name| match name {
            "direction" => Some(unsigned(direction)),
            "mode_code" => Some(unsigned(code)),
            "argument" => Some(opaque(argument)),
            _ => None,
        })
    };
    assert_eq!(mode(1, 1, b"mask"), Ok(()));
    assert_eq!(mode(1, 1, b""), Err(CodecError::CrossReference));
    let mut key = vec![0, 8];
    key.extend_from_slice(b"password");
    assert_eq!(mode(1, 4, &key), Ok(()));
    assert_eq!(mode(1, 4, &[0]), Err(CodecError::CrossReference));
    assert_eq!(mode(2, 4, b""), Ok(()));
    assert_eq!(mode(2, 4, b"x"), Err(CodecError::CrossReference));
    assert_eq!(mode(1, 5, &[0, 0, 0, 1]), Ok(()));
    assert_eq!(mode(1, 5, &[0, 0, 0, 0]), Err(CodecError::CrossReference));
    assert_eq!(mode(2, 5, b""), Ok(()));
    assert_eq!(mode(1, 6, b""), Ok(()));
    assert_eq!(mode(1, 6, b"x"), Err(CodecError::CrossReference));
    assert_eq!(mode(2, 6, b""), Ok(()));
    assert_eq!(mode(1, 8, b""), Ok(()));
    assert_eq!(mode(2, 8, b""), Err(CodecError::CrossReference));
    assert_eq!(mode(1, 12, &[0; 16]), Ok(()));
    assert_eq!(mode(1, 17, b""), Ok(()));
    assert_eq!(mode(1, 17, &[0; 16]), Err(CodecError::CrossReference));
    assert_eq!(mode(2, 17, b""), Err(CodecError::CrossReference));
    assert_eq!(mode(2, 18, b""), Ok(()));
    assert_eq!(mode(1, 19, b""), Err(CodecError::CrossReference));

    let mut short_key = vec![0, 7];
    short_key.extend_from_slice(&[b'x'; 7]);
    assert_eq!(mode(1, 4, &short_key), Err(CodecError::CrossReference));
    let mut truncated_key = vec![0, 8];
    truncated_key.extend_from_slice(&[b'x'; 7]);
    assert_eq!(mode(1, 4, &truncated_key), Err(CodecError::CrossReference));
    assert_eq!(mode(1, 5, &[1]), Err(CodecError::CrossReference));
}

#[test]
fn mode_lists_names_origins_parameters_and_cloaks_cover_alternatives() {
    let mode_list = |code, created, expires, quiet| {
        validate("FederationModeListEntry", |name| match name {
            "mode_code" => Some(unsigned(code)),
            "created_at" => Some(unsigned(created)),
            "expires_at" => Some(unsigned(expires)),
            "mask" => Some(WireValue::Structure(Box::new(typed_mask(quiet)))),
            _ => None,
        })
    };
    assert_eq!(mode_list(1, 10, 0, 1), Ok(()));
    assert_eq!(mode_list(2, 10, 11, 0), Ok(()));
    assert_eq!(mode_list(4, 10, 0, 0), Err(CodecError::CrossReference));
    assert_eq!(mode_list(2, 10, 9, 0), Err(CodecError::CrossReference));
    assert_eq!(mode_list(2, 10, 0, 1), Err(CodecError::CrossReference));

    assert_eq!(validate_nickname_bytes(b"Alice", false), Ok(()));
    assert_eq!(validate_nickname_bytes(b"alice", true), Ok(()));
    assert_eq!(
        validate_nickname_bytes(b"Alice", true),
        Err(CodecError::CrossReference)
    );
    assert_eq!(
        validate_nickname_bytes(&[0xff], false),
        Err(CodecError::CrossReference)
    );

    let origin = |generation,
                  predecessor: &[u8],
                  session: &[u8],
                  user: &[u8],
                  account: &[u8],
                  account_generation| {
        validate("FederationOrigin", |name| match name {
            "generation" => Some(unsigned(generation)),
            "previous_origin_object_id" => Some(opaque(predecessor)),
            "session_id" => Some(opaque(session)),
            "user_id" => Some(opaque(user)),
            "account_id" => Some(opaque(account)),
            "account_session_generation" => Some(unsigned(account_generation)),
            _ => None,
        })
    };
    assert_eq!(origin(0, &[0; 32], b"", b"", b"", 0), Ok(()));
    assert_eq!(origin(1, &[1; 32], &[1; 16], &[2; 16], ACCOUNT, 1), Ok(()));
    assert_eq!(
        origin(1, &[0; 32], b"", b"", b"", 0),
        Err(CodecError::CrossReference)
    );
    assert_eq!(
        origin(0, &[0; 32], &[1; 16], &[2; 16], b"", 0),
        Err(CodecError::CrossReference)
    );
    assert_eq!(
        origin(1, &[1; 32], &[1; 16], b"", b"", 0),
        Err(CodecError::CrossReference)
    );
    assert_eq!(
        origin(1, &[1; 32], b"", &[1; 16], b"", 0),
        Err(CodecError::CrossReference)
    );
    assert_eq!(
        origin(0, &[1; 32], b"", b"", b"", 0),
        Err(CodecError::CrossReference)
    );

    for valid in [b"value".as_slice(), b"a:b", b"a-b"] {
        assert_eq!(
            validate("FederationParameter", |name| (name == "value")
                .then(|| opaque(valid))),
            Ok(())
        );
    }
    for invalid in [b":bad".as_slice(), b"a b", b"a\n", &[0xff]] {
        assert_eq!(
            validate("FederationParameter", |name| (name == "value")
                .then(|| opaque(invalid))),
            Err(CodecError::CrossReference)
        );
    }

    let cloak = |user: &[u8], host: &[u8]| {
        validate("FederationPublicCloak", |name| match name {
            "user_component" => Some(opaque(user)),
            "host_component" => Some(opaque(host)),
            _ => None,
        })
    };
    assert_eq!(cloak(b"abcdefghij", b"abcdefghijklmnop"), Ok(()));
    assert_eq!(
        cloak(&[0xff; 10], b"abcdefghijklmnop"),
        Err(CodecError::CrossReference)
    );
    assert_eq!(
        cloak(b"abcdefghij", b"ABCDEFGHIJKLMNOQ"),
        Err(CodecError::CrossReference)
    );
}

#[test]
fn query_reply_result_and_session_rules_cover_alternatives() {
    let query = |kind, value: &[u8]| {
        validate("FederationQueryTarget", |name| match name {
            "target_kind" => Some(unsigned(kind)),
            "value" => Some(opaque(value)),
            _ => None,
        })
    };
    assert_eq!(query(0, b""), Ok(()));
    assert_eq!(query(0, b"x"), Err(CodecError::CrossReference));
    assert_eq!(query(1, b"Alice"), Ok(()));
    assert_eq!(query(2, b"#rust"), Ok(()));
    assert_eq!(query(2, &[0xff]), Err(CodecError::CrossReference));
    assert_eq!(query(3, b""), Err(CodecError::UnknownDiscriminant));

    let reply = |command: &[u8], presence, trailing: &[u8]| {
        validate("FederationReply", |name| match name {
            "command" => Some(opaque(command)),
            "trailing_presence" => Some(unsigned(presence)),
            "trailing" => Some(opaque(trailing)),
            _ => None,
        })
    };
    assert_eq!(reply(b"FAIL", 0, b""), Ok(()));
    assert_eq!(reply(b"001", 1, b"welcome"), Ok(()));
    assert_eq!(reply(b"999", 0, b""), Err(CodecError::CrossReference));
    assert_eq!(reply(b"FOO", 0, b""), Err(CodecError::CrossReference));
    assert_eq!(reply(b"fail", 0, b""), Err(CodecError::CrossReference));
    assert_eq!(reply(b"FAIL", 0, b"text"), Err(CodecError::CrossReference));
    assert_eq!(reply(b"FAIL", 1, &[0]), Err(CodecError::CrossReference));

    let result = |kind, completion: &[u8], reply_count| {
        let mut replies = Some(
            (0..reply_count)
                .map(|_| raw_object("FederationReply", Vec::new()))
                .collect(),
        );
        validate("FederationResult", |name| match name {
            "result_kind" => Some(unsigned(kind)),
            "completion_event_id" => Some(opaque(completion)),
            "replies" => Some(WireValue::Vector(replies.take().unwrap_or_default())),
            _ => None,
        })
    };
    assert_eq!(result(2, &[0; 16], 0), Ok(()));
    assert_eq!(result(1, b"", 0), Ok(()));
    assert_eq!(result(7, b"", 1), Ok(()));
    assert_eq!(result(7, b"", 0), Err(CodecError::CrossReference));
    assert_eq!(result(2, b"", 0), Err(CodecError::CrossReference));
    assert_eq!(result(1, b"", 65), Err(CodecError::CrossReference));

    let session = |account: &[u8], generation, label: &[u8], bits, away, away_text: &[u8]| {
        validate("FederationSessionProjection", |name| match name {
            "session_revision" => Some(unsigned(1)),
            "account_id" => Some(opaque(account)),
            "account_session_generation" => Some(unsigned(generation)),
            "account_label" => Some(opaque(label)),
            "display_name" => Some(opaque([])),
            "user_mode_bits" => Some(unsigned(bits)),
            "away_kind" => Some(unsigned(away)),
            "away_text" => Some(opaque(away_text)),
            _ => None,
        })
    };
    assert_eq!(session(b"", 0, b"", 1, 0, b""), Ok(()));
    assert_eq!(session(ACCOUNT, 1, b"Label", 1, 1, b"away"), Ok(()));
    assert_eq!(
        session(b"", 0, b"Label", 1, 0, b""),
        Err(CodecError::CrossReference)
    );
    assert_eq!(
        session(ACCOUNT, 1, b"-bad", 1, 0, b""),
        Err(CodecError::CrossReference)
    );
    assert_eq!(
        session(ACCOUNT, 1, b"", 0, 0, b""),
        Err(CodecError::CrossReference)
    );
    assert_eq!(
        session(ACCOUNT, 1, b"", 2, 0, b""),
        Err(CodecError::CrossReference)
    );
    assert_eq!(
        session(ACCOUNT, 1, b"", 5, 0, b""),
        Err(CodecError::CrossReference)
    );
    assert_eq!(
        session(ACCOUNT, 1, b"", 1, 1, b""),
        Err(CodecError::CrossReference)
    );
}

#[test]
fn masks_history_selectors_topics_parts_and_results_cover_alternatives() {
    let mask = |kind, quiet, value: &[u8]| {
        validate("FederationTypedMask", |name| match name {
            "kind" => Some(unsigned(kind)),
            "quiet" => Some(unsigned(quiet)),
            "value" => Some(opaque(value)),
            _ => None,
        })
    };
    assert_eq!(mask(1, 0, ACCOUNT), Ok(()));
    assert_eq!(mask(2, 0, &[0; 16]), Ok(()));
    assert_eq!(mask(3, 1, b"nick*"), Ok(()));
    assert_eq!(mask(4, 0, b"cloak*"), Ok(()));
    assert_eq!(mask(5, 0, b"x"), Err(CodecError::UnknownDiscriminant));
    assert_eq!(mask(3, 2, b"nick"), Ok(()));
    assert_eq!(mask(3, 0, b"bad!"), Err(CodecError::CrossReference));

    let selector = |kind, first: SchemaObject, second: SchemaObject| {
        let descriptor = schema("HistorySelector");
        validate_schema_semantics(
            descriptor,
            &[
                unsigned(kind),
                WireValue::Structure(Box::new(first)),
                WireValue::Structure(Box::new(second)),
            ],
        )
    };
    assert_eq!(
        selector(1, history_reference(0, 0), history_reference(0, 0)),
        Ok(())
    );
    assert_eq!(
        selector(2, history_reference(1, 1), history_reference(0, 0)),
        Ok(())
    );
    assert_eq!(
        selector(1, history_reference(1, 1), history_reference(0, 0)),
        Err(CodecError::CrossReference)
    );
    assert_eq!(
        selector(1, history_reference(0, 0), history_reference(1, 1)),
        Err(CodecError::CrossReference)
    );
    assert_eq!(
        selector(2, history_reference(0, 0), history_reference(0, 0)),
        Err(CodecError::CrossReference)
    );
    assert_eq!(
        selector(2, history_reference(1, 1), history_reference(1, 2)),
        Err(CodecError::CrossReference)
    );
    assert_eq!(
        selector(5, history_reference(1, 1), history_reference(1, 2)),
        Ok(())
    );
    assert_eq!(
        selector(5, history_reference(2, 1), history_reference(2, 2)),
        Ok(())
    );
    assert_eq!(
        selector(5, history_reference(1, 2), history_reference(1, 1)),
        Err(CodecError::CrossReference)
    );
    assert_eq!(
        selector(6, history_reference(0, 0), history_reference(0, 0)),
        Err(CodecError::UnknownDiscriminant)
    );

    let principal = |kind, identifier: &[u8]| {
        validate("PrincipalRef", |name| match name {
            "kind" => Some(unsigned(kind)),
            "identifier" => Some(opaque(identifier)),
            _ => None,
        })
    };
    assert_eq!(principal(1, ACCOUNT), Ok(()));
    assert_eq!(principal(1, b"bad"), Err(CodecError::CrossReference));
    assert_eq!(principal(2, &[0; 16]), Ok(()));
    assert_eq!(principal(2, &[0; 15]), Err(CodecError::CrossReference));
    assert_eq!(principal(3, b""), Err(CodecError::UnknownDiscriminant));

    let topic = |presence, topic: &[u8], set_at, message: &[u8]| {
        validate("event.topic_changed", |name| match name {
            "resulting_revision" => Some(unsigned(1)),
            "topic_presence" => Some(unsigned(presence)),
            "topic" => Some(opaque(topic)),
            "set_at" => Some(unsigned(set_at)),
            "message_id" => Some(opaque(message)),
            _ => None,
        })
    };
    assert_eq!(topic(0, b"", 0, b""), Ok(()));
    assert_eq!(topic(1, b"topic", 1, &[0; 16]), Ok(()));
    assert_eq!(topic(1, b"", 1, &[0; 16]), Err(CodecError::CrossReference));

    let part = |all, channel_count, reason: &[u8]| {
        let mut channels = Some(
            (0..channel_count)
                .map(|_| raw_object("FederationChannelName", Vec::new()))
                .collect(),
        );
        validate("operation.part", |name| match name {
            "expected_session_revision" => Some(unsigned(1)),
            "all_channels" => Some(unsigned(all)),
            "channels" => Some(WireValue::Vector(channels.take().unwrap_or_default())),
            "reason" => Some(opaque(reason)),
            _ => None,
        })
    };
    assert_eq!(part(0, 1, b"reason"), Ok(()));
    assert_eq!(part(0, 0, b"reason"), Err(CodecError::CrossReference));
    assert_eq!(part(1, 0, b""), Ok(()));
    assert_eq!(part(1, 0, b"reason"), Err(CodecError::CrossReference));
    assert_eq!(part(2, 0, b""), Err(CodecError::UnknownDiscriminant));

    assert_eq!(
        validate_required_account(
            schema("result.account_created"),
            &fields(schema("result.account_created"), |name| (name
                == "account_id")
                .then(|| opaque(ACCOUNT))),
            "account_id"
        ),
        Ok(())
    );
    assert_eq!(validate_optional_account(b"", 0), Ok(()));
    assert_eq!(
        validate_optional_account(b"", 1),
        Err(CodecError::CrossReference)
    );
    assert_eq!(validate_optional_account(ACCOUNT, 1), Ok(()));
    assert_eq!(
        validate_optional_account(b"short", 1),
        Err(CodecError::CrossReference)
    );
    assert_eq!(
        validate_optional_account(ACCOUNT, 0),
        Err(CodecError::CrossReference)
    );

    let registered = |account: &[u8], generation, revision| {
        validate("result.session_registered", |name| match name {
            "account_id" => Some(opaque(account)),
            "account_session_generation" => Some(unsigned(generation)),
            "account_revision" => Some(unsigned(revision)),
            "session_revision" | "resulting_state_generation" => Some(unsigned(1)),
            _ => None,
        })
    };
    assert_eq!(registered(b"", 0, 0), Ok(()));
    assert_eq!(registered(ACCOUNT, 1, 1), Ok(()));
    assert_eq!(registered(ACCOUNT, 1, 0), Err(CodecError::CrossReference));
}

#[test]
fn all_closed_embedded_arm_mappings_are_explicit() {
    let projections = [
        (1, "FederationSessionProjection"),
        (3, "FederationChannelDetail"),
        (4, "FederationMembership"),
        (6, "FederationInviteProjection"),
        (7, "FederationAccountProjection"),
    ];
    for (kind, expected) in projections {
        assert_eq!(projection_arm(kind), Ok(expected));
    }
    assert_eq!(projection_arm(0), Err(CodecError::UnknownDiscriminant));

    let directories = [
        "directory.list",
        "directory.names",
        "directory.who",
        "directory.whois",
        "directory.whowas",
        "directory.ison",
        "directory.userhost",
        "directory.links",
        "directory.monitor_add",
        "directory.monitor_remove",
        "directory.monitor_clear",
        "directory.monitor_list",
        "directory.monitor_status",
        "directory.channel_topic",
        "directory.channel_modes",
        "directory.channel_mode_list",
    ];
    for (offset, expected) in directories.iter().enumerate() {
        assert_eq!(
            directory_arm(u64::try_from(offset + 1).unwrap_or(u64::MAX)),
            Ok(*expected)
        );
    }
    assert_eq!(directory_arm(17), Err(CodecError::UnknownDiscriminant));

    let operations = [
        (1, "operation.session_open"),
        (2, "operation.session_close"),
        (3, "operation.nick_change"),
        (4, "operation.join"),
        (5, "operation.part"),
        (6, "operation.channel_mode"),
        (7, "operation.user_mode"),
        (8, "operation.topic"),
        (9, "operation.invite"),
        (10, "operation.kick"),
        (11, "operation.message"),
        (12, "operation.away"),
        (13, "operation.setname"),
        (14, "operation.channel_register"),
        (15, "operation.channel_unregister"),
        (16, "operation.account_settings"),
        (17, "operation.history_query"),
        (18, "operation.directory_query"),
        (19, "operation.account_create_start"),
        (20, "operation.account_create_finish"),
        (21, "operation.opaque_auth_start"),
        (22, "operation.opaque_auth_finish"),
        (24, "operation.channel_settings"),
        (25, "operation.credential_change_start"),
        (26, "operation.credential_change_finish"),
    ];
    for (kind, expected) in operations {
        assert_eq!(operation_arm(kind), Ok(expected));
    }
    assert_eq!(operation_arm(23), Err(CodecError::UnknownDiscriminant));

    let results = [
        "result.failed",
        "result.committed",
        "result.session_registered",
        "result.auth_challenge",
        "result.authenticated",
        "result.account_created",
        "result.reply_page",
        "result.no_content",
    ];
    for (offset, expected) in results.iter().enumerate() {
        assert_eq!(
            result_arm(u64::try_from(offset + 1).unwrap_or(u64::MAX)),
            Ok(*expected)
        );
    }
    assert_eq!(result_arm(9), Err(CodecError::UnknownDiscriminant));

    let events = [
        "event.session_visible",
        "event.session_hidden",
        "event.nickname_changed",
        "event.channel_visible",
        "event.channel_hidden",
        "event.member_joined",
        "event.member_parted",
        "event.channel_modes_changed",
        "event.topic_changed",
        "event.invited",
        "event.kicked",
        "event.away_changed",
        "event.display_name_changed",
        "event.message_delivered",
        "event.channel_destroyed",
        "event.account_label_changed",
        "event.network_notice",
        "event.user_modes_changed",
        "event.channel_policy_changed",
        "event.channel_memberships_recomputed",
        "event.account_state_changed",
        "event.request_completed",
        "event.invite_removed",
    ];
    for (offset, expected) in events.iter().enumerate() {
        assert_eq!(
            event_arm(u64::try_from(offset + 1).unwrap_or(u64::MAX)),
            Ok(*expected)
        );
    }
    assert_eq!(event_arm(24), Err(CodecError::UnknownDiscriminant));
}

#[test]
fn embedded_dispatch_is_iterative_bounded_and_fail_closed() -> Result<(), CodecError> {
    let mut budget = DecodeBudget::new(4_096, 256);
    let mut pending = Vec::new();
    assert_eq!(
        validate_optional_schema_embedded(&MISSING_SCHEMA, &[], &mut budget, 0, &mut pending),
        Err(CodecError::SchemaMismatch)
    );
    assert_eq!(
        validate_discriminated_embedded(&MISSING_SCHEMA, &[], &mut budget, 0, &mut pending),
        Err(CodecError::SchemaMismatch)
    );
    assert_eq!(
        discriminated_arm("missing", 1),
        Err(CodecError::SchemaMismatch)
    );

    let optional_schema = schema("AccountCreateStart");
    let optional_fields = fields(optional_schema, |name| {
        (name == "creation_invite").then(|| opaque([]))
    });
    assert_eq!(
        validate_optional_schema_embedded(
            optional_schema,
            &optional_fields,
            &mut budget,
            0,
            &mut pending
        ),
        Ok(())
    );

    let invite_schema = schema("FederationInviteEventView");
    let invite_fields = fields(invite_schema, |name| {
        (name == "local_invite_projection").then(|| opaque([]))
    });
    assert_eq!(
        validate_invite_event_embedded(invite_schema, &invite_fields, &mut budget, 0, &mut pending),
        Ok(())
    );

    let mode_schema = schema("FederationModeChange");
    let skipped_fields = fields(mode_schema, |name| match name {
        "mode_code" => Some(unsigned(4)),
        "argument" => Some(opaque([])),
        _ => None,
    });
    assert_eq!(
        validate_mode_change_embedded(mode_schema, &skipped_fields, &mut budget, 0, &mut pending),
        Ok(())
    );

    for (quiet, expected) in [(0, Ok(())), (1, Err(CodecError::CrossReference))] {
        let argument = typed_mask(quiet).encode_canonical().unwrap_or_default();
        let mode_fields = fields(mode_schema, |name| match name {
            "mode_code" => Some(unsigned(2)),
            "argument" => Some(opaque(&argument)),
            _ => None,
        });
        assert_eq!(
            validate_mode_change_embedded(mode_schema, &mode_fields, &mut budget, 0, &mut pending),
            expected
        );
    }

    let projected_schema = schema("FederationProjectedModeChange");
    for (argument, expected) in [
        (vec![0, 1], Ok(())),
        (vec![0, 2], Err(CodecError::CrossReference)),
    ] {
        let projected_fields = fields(projected_schema, |name| match name {
            "mode_code" => Some(unsigned(4)),
            "argument" => Some(opaque(&argument)),
            _ => None,
        });
        assert_eq!(
            validate_projected_mode_embedded(
                projected_schema,
                &projected_fields,
                &mut budget,
                0,
                &mut pending
            ),
            expected
        );
    }

    for (argument, expected) in [
        (vec![0, 0, 0, 0], Ok(())),
        (vec![0, 0, 0xff, 0xff], Ok(())),
        (vec![0, 1, 0, 0], Err(CodecError::CrossReference)),
        (vec![0, 0, 1], Err(CodecError::CrossReference)),
    ] {
        let projected_fields = fields(projected_schema, |name| match name {
            "mode_code" => Some(unsigned(5)),
            "argument" => Some(opaque(&argument)),
            _ => None,
        });
        assert_eq!(
            validate_projected_mode_embedded(
                projected_schema,
                &projected_fields,
                &mut budget,
                0,
                &mut pending
            ),
            expected
        );
    }

    let entry = mode_list_entry(1).encode_canonical()?;
    for (outer_code, expected) in [(1, Ok(())), (2, Err(CodecError::CrossReference))] {
        let projected_fields = fields(projected_schema, |name| match name {
            "mode_code" => Some(unsigned(outer_code)),
            "argument" => Some(opaque(&entry)),
            _ => None,
        });
        assert_eq!(
            validate_projected_mode_embedded(
                projected_schema,
                &projected_fields,
                &mut budget,
                0,
                &mut pending
            ),
            expected
        );
    }
    Ok(())
}

#[test]
fn home_session_projection_matches_its_event_source_identity() {
    let validate_view =
        |source_user, source_nick: &[u8], source_label: &[u8], projection: SchemaObject| {
            let encoded = projection.encode_canonical().unwrap_or_default();
            let descriptor = schema("FederationSessionEventView");
            let mut source = Some(source_view(source_user, source_nick, source_label));
            let values = fields(descriptor, |name| match name {
                "source" => source
                    .take()
                    .map(|value| WireValue::Structure(Box::new(value))),
                "home_session_projection" => Some(opaque(&encoded)),
                _ => None,
            });
            let mut budget = DecodeBudget::new(4_096, 256);
            validate_session_event_embedded(descriptor, &values, &mut budget, 0, &mut Vec::new())
        };

    assert_eq!(
        validate_view(1, b"alice", b"", session_projection(1, b"alice", b"")),
        Ok(())
    );
    assert_eq!(
        validate_view(2, b"alice", b"", session_projection(1, b"alice", b"")),
        Err(CodecError::CrossReference)
    );
    assert_eq!(
        validate_view(1, b"other", b"", session_projection(1, b"alice", b"")),
        Err(CodecError::CrossReference)
    );
    assert_eq!(
        validate_view(
            1,
            b"alice",
            b"Other",
            session_projection(1, b"alice", b"Label")
        ),
        Err(CodecError::CrossReference)
    );
}

#[test]
fn appendix_b_cross_field_regressions_fail_closed() {
    let challenge = |length| {
        validate("AccountServiceChallenge", |name| {
            (name == "opaque_message").then(|| opaque(vec![0; length]))
        })
    };
    assert_eq!(challenge(64), Ok(()));
    assert_eq!(challenge(288), Ok(()));
    assert_eq!(challenge(65), Err(CodecError::CrossReference));

    let account_projection = |generation, revision| {
        validate("FederationAccountProjection", |name| match name {
            "account_id" => Some(opaque(ACCOUNT)),
            "account_session_generation" => Some(unsigned(generation)),
            "account_revision" => Some(unsigned(revision)),
            _ => None,
        })
    };
    assert_eq!(account_projection(1, 1), Ok(()));
    assert_eq!(account_projection(0, 1), Err(CodecError::CrossReference));
    assert_eq!(account_projection(1, 0), Err(CodecError::CrossReference));

    let delivered = |message_kind, target_kind, sequence, tag_count, body: &[u8]| {
        let mut tags = Some(
            (0..tag_count)
                .map(|_| raw_object("FederationClientTag", Vec::new()))
                .collect(),
        );
        validate("FederationDeliveredMessage", |name| match name {
            "target_revision" => Some(unsigned(1)),
            "message_kind" => Some(unsigned(message_kind)),
            "target_kind" => Some(unsigned(target_kind)),
            "channel_event_sequence" => Some(unsigned(sequence)),
            "tags" => Some(WireValue::Vector(tags.take().unwrap_or_default())),
            "body" => Some(opaque(body)),
            _ => None,
        })
    };
    assert_eq!(delivered(1, 1, 1, 0, b"body"), Ok(()));
    assert_eq!(delivered(1, 2, 0, 0, b"body"), Ok(()));
    assert_eq!(
        delivered(1, 1, 0, 0, b"body"),
        Err(CodecError::CrossReference)
    );
    assert_eq!(delivered(3, 2, 0, 1, b""), Ok(()));
    assert_eq!(delivered(3, 2, 0, 0, b""), Err(CodecError::CrossReference));
    assert_eq!(
        delivered(1, 2, 0, 0, &[0xff]),
        Err(CodecError::CrossReference)
    );

    let membership = |member: u8, source: u8| {
        let membership = raw_object(
            "FederationMembership",
            fields(schema("FederationMembership"), |name| {
                (name == "user_id").then(|| opaque([member; 16]))
            }),
        );
        let source = raw_object(
            "FederationSourceView",
            fields(schema("FederationSourceView"), |name| {
                (name == "user_id").then(|| opaque([source; 16]))
            }),
        );
        validate_schema_semantics(
            schema("FederationMembershipView"),
            &[
                WireValue::Structure(Box::new(membership)),
                WireValue::Structure(Box::new(source)),
            ],
        )
    };
    assert_eq!(membership(1, 1), Ok(()));
    assert_eq!(membership(1, 2), Err(CodecError::CrossReference));

    assert_eq!(
        validate("directory.whowas", |name| (name == "count")
            .then(|| unsigned(0))),
        Err(CodecError::CrossReference)
    );
    assert_eq!(
        validate("directory.channel_mode_list", |name| {
            (name == "mode_code").then(|| unsigned(4))
        }),
        Err(CodecError::CrossReference)
    );
    assert_eq!(
        validate("event.session_hidden", |name| match name {
            "last_revision" => Some(unsigned(1)),
            "hide_kind" => Some(unsigned(6)),
            "reason" => Some(opaque("connection closed")),
            _ => None,
        }),
        Ok(())
    );
    assert_eq!(
        validate("event.session_hidden", |name| match name {
            "last_revision" => Some(unsigned(1)),
            "hide_kind" => Some(unsigned(6)),
            "reason" => Some(opaque("secret reason")),
            _ => None,
        }),
        Err(CodecError::CrossReference)
    );
    assert_eq!(
        validate("event.session_hidden", |name| match name {
            "last_revision" => Some(unsigned(1)),
            "hide_kind" => Some(unsigned(1)),
            "reason" => Some(opaque("ordinary reason")),
            _ => None,
        }),
        Ok(())
    );

    for code in [b"NOTICE_1".as_slice(), b"NOTICE-2"] {
        assert_eq!(
            validate("event.network_notice", |name| match name {
                "code" => Some(opaque(code)),
                "safe_text" => Some(opaque("safe")),
                _ => None,
            }),
            Ok(())
        );
    }
    assert_eq!(
        validate("event.network_notice", |name| match name {
            "code" => Some(opaque("bad")),
            "safe_text" => Some(opaque("safe")),
            _ => None,
        }),
        Err(CodecError::CrossReference)
    );

    assert_eq!(
        validate_message_shape(3, 1, b"unexpected"),
        Err(CodecError::CrossReference)
    );
}

#[test]
fn recomputed_memberships_bind_the_outer_channel_and_revision() {
    let recompute = |outer_channel, outer_revision, member_channel, member_revision| {
        let mut memberships = Some(vec![membership_view(member_channel, 1, member_revision)]);
        validate("event.channel_memberships_recomputed", |name| match name {
            "channel_instance_id" => Some(opaque([outer_channel; 16])),
            "resulting_revision" => Some(unsigned(outer_revision)),
            "memberships" => Some(WireValue::Vector(memberships.take().unwrap_or_default())),
            _ => None,
        })
    };

    assert_eq!(recompute(1, 2, 1, 2), Ok(()));
    assert_eq!(recompute(1, 0, 1, 0), Err(CodecError::CrossReference));
    assert_eq!(recompute(1, 2, 2, 2), Err(CodecError::CrossReference));
    assert_eq!(recompute(1, 2, 1, 3), Err(CodecError::CrossReference));
}
