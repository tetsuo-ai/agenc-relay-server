#![forbid(unsafe_code)]

//! The carrier matrix.

use super::*;
use crate::limits::{
    MAX_APPLICATION_MLS_OBJECT, MAX_BINDING_OBJECT, MAX_LIVE_OBJECT, MAX_WELCOME_MAILBOX_OBJECT,
};

const CLIENT_CARRIERS: [CarrierCommand; 20] = [
    CarrierCommand::Tagmsg,
    CarrierCommand::Edirect,
    CarrierCommand::SubmitCandidate,
    CarrierCommand::SubmitAuthorization,
    CarrierCommand::SubmitAck,
    CarrierCommand::SubmitFinalization,
    CarrierCommand::SubmitAbort,
    CarrierCommand::SubmitReinitAttempt,
    CarrierCommand::SubmitReinitAck,
    CarrierCommand::SubmitReinitActivate,
    CarrierCommand::SubmitReinitAbort,
    CarrierCommand::Bind,
    CarrierCommand::Close,
    CarrierCommand::PublishIdentity,
    CarrierCommand::PublishRoster,
    CarrierCommand::PublishCapabilities,
    CarrierCommand::PublishPackage,
    CarrierCommand::DeliverBinding,
    CarrierCommand::DeliverWelcome,
    CarrierCommand::AttachFinish,
];

#[test]
fn every_client_carrier_accepts_exactly_its_matrix_kinds() {
    for carrier in CLIENT_CARRIERS {
        let accepted = carrier.accepted_kinds();
        assert!(!accepted.is_empty(), "{carrier:?}");
        for kind in IrcWireObjectKind::ALL.iter().copied() {
            assert_eq!(
                carrier.accepts(kind),
                accepted.contains(&kind),
                "{carrier:?} {kind:?}"
            );
            assert!(
                !(carrier.accepts(kind) && kind.is_server_only()),
                "{carrier:?} must not accept {kind:?}"
            );
        }
    }
    assert_eq!(
        CarrierCommand::DeliverWelcome.accepted_kinds(),
        &[
            IrcWireObjectKind::WelcomeMls,
            IrcWireObjectKind::StagedReinit
        ]
    );
    assert!(CarrierCommand::Tagmsg.accepts(IrcWireObjectKind::ApplicationMls));
    assert!(!CarrierCommand::Tagmsg.accepts(IrcWireObjectKind::CommitMls));
    assert!(!CarrierCommand::Edirect.accepts(IrcWireObjectKind::CommitMls));
    assert!(CarrierCommand::SubmitCandidate.accepts(IrcWireObjectKind::CommitMls));
}

#[test]
fn response_and_federation_carriers_accept_one_kind() {
    for kind in IrcWireObjectKind::ALL.iter().copied() {
        assert_eq!(CarrierCommand::Response(kind).accepted_kinds(), &[kind]);
        assert_eq!(CarrierCommand::Federation(kind).accepted_kinds(), &[kind]);
        assert_eq!(
            CarrierCommand::Federation(kind).limit().max_bytes,
            kind.maximum_object_bytes().min(MAX_WELCOME_MAILBOX_OBJECT)
        );
    }
}

#[test]
fn limits_follow_the_kind_and_the_deadline_class() {
    let live = CarrierCommand::Tagmsg.limit();
    assert_eq!(live.max_bytes, MAX_APPLICATION_MLS_OBJECT);
    assert_eq!(live.max_fragments, 90);
    assert_eq!(live.deadline, DeadlineClass::Live);
    assert_eq!(DeadlineClass::Live.seconds(), (120, 15));
    let candidate = CarrierCommand::SubmitCandidate.limit();
    assert_eq!(candidate.max_bytes, MAX_LIVE_OBJECT);
    assert!(CarrierCommand::SubmitCandidate.is_live());
    let welcome = CarrierCommand::DeliverWelcome.limit();
    assert_eq!(welcome.max_bytes, MAX_WELCOME_MAILBOX_OBJECT);
    assert_eq!(welcome.max_fragments, 1_427);
    assert_eq!(welcome.deadline, DeadlineClass::Mailbox);
    assert_eq!(DeadlineClass::Mailbox.seconds(), (600, 30));
    assert!(!CarrierCommand::DeliverWelcome.is_live());
    assert_eq!(CarrierCommand::Bind.limit().max_bytes, MAX_BINDING_OBJECT);
    assert_eq!(
        CarrierCommand::DeliverBinding.limit().max_bytes,
        MAX_BINDING_OBJECT
    );
}
