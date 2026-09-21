#![forbid(unsafe_code)]
//! Every simple operation arm encodes to its Appendix-B object and decodes
//! back to the same value.

use std::error::Error;

use agenc_relay_domain::MessageKind;
use agenc_relay_domain::federation::ModeDirection;
use agenc_relay_types::{ChannelInstanceId, ConnectionId, FederationOpcode, SessionId, UserId};
use zeroize::Zeroizing;

use crate::federation::codec::operations::{
    FederatedOperation, JoinTarget, MessageTargetArg, ModeChangeArg,
};

type TestResult = Result<(), Box<dyn Error>>;

const SESSION: SessionId = SessionId::from_bytes([3; 16]);
const CHANNEL: ChannelInstanceId = ChannelInstanceId::from_bytes([4; 16]);

#[test]
fn projected_key_changes_carry_only_the_two_byte_presence_value() -> TestResult {
    use crate::federation::codec::{projected_mode_change_object, projected_mode_change_of};
    use agenc_relay_domain::federation::ProjectedModeChange;
    use agenc_relay_federation_wire::{DecodeBudget, access::opaque_field};
    for (direction, present, expected) in [
        (ModeDirection::Add, true, [0, 1]),
        (ModeDirection::Remove, false, [0, 0]),
    ] {
        let object =
            projected_mode_change_object(&ProjectedModeChange::Key { direction, present })?;
        assert_eq!(opaque_field(&object, "argument")?, expected);
        let decoded = projected_mode_change_of(&object, &mut DecodeBudget::new(4096, 64))?;
        assert!(
            matches!(decoded, ProjectedModeChange::Key { direction: actual_direction, present: actual_present }
            if actual_direction == direction && actual_present == present)
        );
    }
    Ok(())
}

// Appendix B.4: keys have a uint16 prefix and limits are uint32 big endian.
#[test]
fn key_and_limit_modes_use_exact_binary_arguments_and_restore_client_values() -> TestResult {
    use agenc_relay_federation_wire::access::{opaque_field, vector};
    for (mode_code, input, expected) in [
        (4, b"password".to_vec(), b"\0\x08password".to_vec()),
        (4, vec![b'x'; 256], [vec![1, 0], vec![b'x'; 256]].concat()),
        (5, b"1".to_vec(), vec![0, 0, 0, 1]),
        (5, b"65535".to_vec(), vec![0, 0, 255, 255]),
    ] {
        for direction in [ModeDirection::Add, ModeDirection::Remove] {
            let argument = if direction == ModeDirection::Add {
                input.clone()
            } else {
                Vec::new()
            };
            let operation = FederatedOperation::ChannelMode {
                session_id: SESSION,
                channel_id: CHANNEL,
                expected_channel_revision: 9,
                changes: vec![ModeChangeArg {
                    direction,
                    mode_code,
                    argument: Zeroizing::new(argument),
                }],
            };
            let object = operation.to_object()?;
            let change = vector(&object, "changes")?
                .first()
                .ok_or("missing encoded mode")?;
            let wire = opaque_field(change, "argument")?;
            assert_eq!(
                wire,
                if direction == ModeDirection::Add {
                    expected.as_slice()
                } else {
                    &[]
                }
            );
            assert!(operation == FederatedOperation::from_object(operation.opcode(), &object)?);
        }
    }
    Ok(())
}

#[test]
fn malformed_keys_and_noncanonical_or_out_of_range_limits_are_refused() {
    for (mode_code, argument) in [
        (4, vec![]),
        (4, vec![b'x'; 7]),
        (4, vec![b'x'; 257]),
        (4, vec![255; 8]),
        (5, b"0".to_vec()),
        (5, b"65536".to_vec()),
        (5, b"01".to_vec()),
        (5, b"+1".to_vec()),
        (5, b"1x".to_vec()),
        (5, b"4294967296".to_vec()),
        (5, vec![255]),
    ] {
        let operation = FederatedOperation::ChannelMode {
            session_id: SESSION,
            channel_id: CHANNEL,
            expected_channel_revision: 9,
            changes: vec![ModeChangeArg {
                direction: ModeDirection::Add,
                mode_code,
                argument: Zeroizing::new(argument),
            }],
        };
        assert!(operation.to_object().is_err());
    }
}

// STA-10: typed mask arguments must survive the real federation schema boundary.
#[test]
fn mask_modes_round_trip_through_typed_wire_arguments() -> TestResult {
    for direction in [ModeDirection::Add, ModeDirection::Remove] {
        for (mode_code, mask) in [
            (1, "$n:alice"),
            (1, "$q:$n:alice"),
            (2, "$n:bob"),
            (3, "$n:carol"),
        ] {
            let operation = FederatedOperation::ChannelMode {
                session_id: SESSION,
                channel_id: CHANNEL,
                expected_channel_revision: 9,
                changes: vec![ModeChangeArg {
                    direction,
                    mode_code,
                    argument: Zeroizing::new(mask.as_bytes().to_vec()),
                }],
            };
            let object = operation.to_object()?;
            assert!(operation == FederatedOperation::from_object(operation.opcode(), &object)?);
        }
    }
    Ok(())
}

#[test]
fn malformed_and_wrong_list_mask_arguments_are_refused_before_transmission() {
    for (mode_code, mask) in [(1, &[0xff][..]), (1, b"not-a-mask"), (2, b"$q:$n:alice")] {
        let operation = FederatedOperation::ChannelMode {
            session_id: SESSION,
            channel_id: CHANNEL,
            expected_channel_revision: 9,
            changes: vec![ModeChangeArg {
                direction: ModeDirection::Remove,
                mode_code,
                argument: Zeroizing::new(mask.to_vec()),
            }],
        };
        assert!(operation.to_object().is_err());
    }
}

fn operations() -> Vec<FederatedOperation> {
    vec![
        FederatedOperation::SessionOpen {
            connection_id: ConnectionId::from_bytes([1; 16]),
            auth_grant_id: Some([2; 32]),
            nickname: "sam".to_owned(),
            realname: "Sam Person".to_owned(),
            capability_hash: [5; 32],
            connection_nonce: [6; 32],
        },
        FederatedOperation::SessionClose {
            session_id: SESSION,
            reason_code: 1,
        },
        FederatedOperation::NickChange {
            session_id: SESSION,
            expected_session_revision: 4,
            nickname: "samuel".to_owned(),
        },
        FederatedOperation::Join {
            session_id: SESSION,
            expected_session_revision: 4,
            targets: vec![JoinTarget {
                channel_name: "#one".to_owned(),
                join_key: Zeroizing::new(b"key".to_vec()),
            }],
        },
        FederatedOperation::Part {
            session_id: SESSION,
            expected_session_revision: 4,
            all_channels: false,
            channels: vec![CHANNEL],
            reason: "bye".to_owned(),
        },
        FederatedOperation::ChannelMode {
            session_id: SESSION,
            channel_id: CHANNEL,
            expected_channel_revision: 9,
            changes: vec![ModeChangeArg {
                direction: ModeDirection::Add,
                mode_code: 6,
                argument: Zeroizing::new(Vec::new()),
            }],
        },
        FederatedOperation::UserMode {
            session_id: SESSION,
            expected_session_revision: 4,
            changes: vec![ModeChangeArg {
                direction: ModeDirection::Add,
                mode_code: 18,
                argument: Zeroizing::new(Vec::new()),
            }],
        },
        FederatedOperation::Topic {
            session_id: SESSION,
            channel_id: CHANNEL,
            expected_channel_revision: 9,
            topic: "topic".to_owned(),
        },
        FederatedOperation::Invite {
            session_id: SESSION,
            channel_id: CHANNEL,
            target_nickname: "tess".to_owned(),
            expected_channel_revision: 9,
        },
        FederatedOperation::Kick {
            session_id: SESSION,
            channel_id: CHANNEL,
            targets: vec![UserId::from_bytes([7; 16])],
            expected_channel_revision: 9,
            reason: "out".to_owned(),
        },
        FederatedOperation::Message {
            session_id: SESSION,
            kind: MessageKind::Notice,
            targets: vec![
                MessageTargetArg::Channel {
                    channel_id: CHANNEL,
                    expected_revision: 9,
                },
                MessageTargetArg::User {
                    nickname: "tess".to_owned(),
                },
            ],
            tags: vec![("+draft/reply".to_owned(), "abc".to_owned())],
            body: "hello".to_owned(),
        },
        FederatedOperation::Away {
            session_id: SESSION,
            expected_session_revision: 4,
            away_text: "away".to_owned(),
        },
        FederatedOperation::Setname {
            session_id: SESSION,
            expected_session_revision: 4,
            display_name: "Sam Renamed".to_owned(),
        },
        FederatedOperation::ChannelRegister {
            session_id: SESSION,
            channel_id: CHANNEL,
            expected_channel_revision: 9,
        },
        FederatedOperation::ChannelUnregister {
            session_id: SESSION,
            channel_id: CHANNEL,
            expected_channel_revision: 9,
        },
        FederatedOperation::ChannelSettings {
            session_id: SESSION,
            channel_id: CHANNEL,
            expected_channel_revision: 9,
            setting_kind: 2,
        },
        FederatedOperation::AccountSettings {
            session_id: SESSION,
            expected_account_revision: 3,
            setting_kind: 2,
            value: Vec::new(),
        },
    ]
}

#[test]
fn every_simple_operation_arm_round_trips() -> TestResult {
    for operation in operations() {
        let opcode = operation.opcode();
        let object = operation
            .to_object()
            .map_err(|error| format!("{opcode:?} encode: {error:?}"))?;
        let decoded = FederatedOperation::from_object(opcode, &object)
            .map_err(|error| format!("{opcode:?} decode: {error:?}"))?;
        assert!(decoded == operation, "{opcode:?} did not round trip");
        assert_eq!(decoded.opcode(), opcode);
    }
    Ok(())
}

#[test]
fn an_object_under_the_wrong_opcode_is_refused() -> TestResult {
    let object = FederatedOperation::SessionClose {
        session_id: SESSION,
        reason_code: 1,
    }
    .to_object()?;
    assert!(FederatedOperation::from_object(FederationOpcode::Topic, &object).is_err());
    Ok(())
}
