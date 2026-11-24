//! Companion 11.6 and 12.5. A live direct event captures one local attachment
//! while its base and companion declarations reach the coordinator.

#![forbid(unsafe_code)]

use super::*;

#[test]
fn a_captured_attachment_waits_for_its_own_declaration_and_never_follows_a_replacement()
-> Result<(), Box<dyn std::error::Error>> {
    let connection = ConnectionGeneration::new(1);
    let user = UserId::from_bytes([11; 16]);
    let account = [12; 24];
    let mut base = BaseOriginFacts {
        origin_id: [13; 16],
        generation: 2,
        acked_generation: Some(2),
        connection_id: [14; 16],
        connection_nonce: [15; 32],
        session: Some(([16; 16], *user.as_bytes())),
        account: Some((account, 1)),
    };
    let mut origin = LocalOrigin {
        ingress: None,
        origin_id: base.origin_id,
        declared: Some(2),
        acked: Some(2),
        predates_device: Some(2),
        next_sequence: 0,
        sequenced: Some(2),
        state_id: [17; 32],
        declaration: None,
        user_id: Some(user),
        account: Some(account),
        device: Some(([18; 16], 9)),
        device_principal: Some((Some(user), Some(account))),
    };
    let sink = Sink::capture(connection, &origin, &base)
        .ok_or("a candidate exists before the base acknowledgement")?;
    assert_eq!(
        sink.origin_status(&origin, &base),
        OriginStatus::AwaitingAck
    );
    base.generation = 3;
    base.acked_generation = Some(3);
    origin.declared = Some(3);
    assert_eq!(
        sink.origin_status(&origin, &base),
        OriginStatus::AwaitingAck
    );
    origin.acked = Some(3);
    origin.predates_device = None;
    assert_eq!(sink.origin_status(&origin, &base), OriginStatus::Ready);
    // After a successful WHOAMI the publication check still pins the same
    // base generation, device, session and account.
    let authorized = Sink {
        verified: Some(true),
        ..sink
    };
    for attachment in [None, Some(([18; 16], 10)), Some(([19; 16], 9))] {
        origin.device = attachment;
        assert_eq!(authorized.origin_status(&origin, &base), OriginStatus::Gone);
    }
    origin.device = Some(sink.attachment);
    base.generation = 4;
    assert_eq!(authorized.origin_status(&origin, &base), OriginStatus::Gone);
    base.generation = 3;
    base.account = Some(([20; 24], 1));
    assert_eq!(authorized.origin_status(&origin, &base), OriginStatus::Gone);
    base.account = Some((account, 1));
    base.session = Some(([16; 16], [21; 16]));
    assert_eq!(authorized.origin_status(&origin, &base), OriginStatus::Gone);
    Ok(())
}
