#![forbid(unsafe_code)]
//! Every simple operation arm encodes to its Appendix-B object and decodes
//! back to the same value.

use std::error::Error;

use agenc_ircd_domain::MessageKind;
use agenc_ircd_domain::federation::ModeDirection;
use agenc_ircd_types::{ChannelInstanceId, ConnectionId, FederationOpcode, SessionId, UserId};
use zeroize::Zeroizing;

use crate::federation::codec::operations::{
    FederatedOperation, JoinTarget, MessageTargetArg, ModeChangeArg,
};

type TestResult = Result<(), Box<dyn Error>>;

const SESSION: SessionId = SessionId::from_bytes([3; 16]);
const CHANNEL: ChannelInstanceId = ChannelInstanceId::from_bytes([4; 16]);

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
