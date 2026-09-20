//! Request and payload fragments on the wire name this coordinator, and a
//! payload fragment is accepted only for the object its request declared.

#![forbid(unsafe_code)]

use super::*;

#[test]
fn request_and_payload_fragments_must_address_this_coordinator_and_their_object() -> TestResult {
    use agenc_ircd_e2ee::objects::federation::IrcFederationOpcode as Op;
    // The channel is bound through the executing harness first; the frame
    // layer then wraps that committed state.
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let mut sync = Sync {
        harness,
        host: FakeHost::default(),
        entropy: Counter(0),
    };
    let policy = wire(IrcWireObjectKind::Policy, &sync.harness.operational_policy)?;
    let complete = sync
        .harness
        .request(Op::SubmitPolicy, &conversation, Some(&policy))?;
    let request_object = object_id(&complete.request);
    let payload_object = object_id(&policy);
    let elsewhere = agenc_ircd_e2ee::federation::frames::Correlation {
        peer_server_id: [9; 16],
        ..complete.correlation
    };
    let wire_correlation = agenc_ircd_e2ee::federation::frames::Correlation {
        peer_server_id: COORDINATOR,
        ..complete.correlation
    };
    let request_fragments = fragment_object(&complete.request)?;
    let first = request_fragments.first().cloned().ok_or("a fragment")?;
    assert_eq!(
        sync.frame(CompanionFrame::Request {
            correlation: elsewhere,
            object_id: request_object,
            fragment: first.clone(),
        })
        .err(),
        Some(CompanionFault::Protocol),
        "a request addressed elsewhere"
    );
    // A payload before its request has nothing to attach to.
    let payload_fragments = fragment_object(&policy)?;
    let payload_first = payload_fragments.first().cloned().ok_or("a fragment")?;
    assert_eq!(
        sync.frame(CompanionFrame::Payload {
            correlation: wire_correlation,
            object_id: payload_object,
            fragment: payload_first.clone(),
        })
        .err(),
        Some(CompanionFault::Protocol),
        "a payload without an open request"
    );
    let mut actions = Vec::new();
    for fragment in request_fragments {
        actions.extend(sync.frame(CompanionFrame::Request {
            correlation: wire_correlation,
            object_id: request_object,
            fragment,
        })?);
    }
    assert!(actions.is_empty(), "the request waits for its payload");
    assert_eq!(
        sync.frame(CompanionFrame::Payload {
            correlation: elsewhere,
            object_id: payload_object,
            fragment: payload_first.clone(),
        })
        .err(),
        Some(CompanionFault::Protocol),
        "a payload addressed elsewhere"
    );
    assert_eq!(
        sync.frame(CompanionFrame::Payload {
            correlation: wire_correlation,
            object_id: [7; 32],
            fragment: payload_first,
        })
        .err(),
        Some(CompanionFault::Protocol),
        "a payload that is not the declared object"
    );
    let mut executed = Vec::new();
    for fragment in payload_fragments {
        executed.extend(sync.frame(CompanionFrame::Payload {
            correlation: wire_correlation,
            object_id: payload_object,
            fragment,
        })?);
    }
    assert!(matches!(executed.as_slice(), [Action::Execute(_)]));
    Ok(())
}
