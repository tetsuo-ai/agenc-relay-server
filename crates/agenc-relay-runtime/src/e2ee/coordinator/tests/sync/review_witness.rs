//! Review regression (ENC-11): companion 12.5.1 makes the coordinator the
//! only party that can answer a blocked edge's `EWITNESS REQUEST`.

#![forbid(unsafe_code)]

use super::*;

/// An edge holding a durable `witness/v1` row sends `EWITNESS REQUEST`
/// right after `ERESUME OK` and reads nothing else (companion 12.5.1). The
/// coordinator must answer with a resolution set (an empty one when it holds
/// no record beyond the expected position); treating the request as a
/// protocol violation closes the link on every reconnect.
#[test]
fn a_witness_request_from_an_active_edge_is_answered_not_refused() -> TestResult {
    let mut sync = Sync::new()?;
    let page = frames(&sync.resume(0, None).map_err(|fault| format!("{fault:?}"))?)?;
    let (cut, _, _) = begin_cut(&page)?;
    sync.ready(cut)?;
    let answer = sync.frame(CompanionFrame::WitnessRequest {
        coordinator_server_id: super::super::COORDINATOR,
        conversation_id: [9; 32],
        expected_sequence: 1,
        expected_head_id: [8; 32],
    });
    let answer =
        answer.map_err(|fault| format!("the coordinator refused EWITNESS REQUEST: {fault:?}"))?;
    // It retains nothing for that conversation: one empty resolution set.
    let sent = frames(&answer)?;
    assert!(matches!(
        sent.first(),
        Some(CompanionFrame::WitnessBegin { .. })
    ));
    assert!(matches!(
        sent.last(),
        Some(CompanionFrame::WitnessEnd {
            record_count: 0,
            ..
        })
    ));
    Ok(())
}

#[test]
fn a_witness_resolved_without_an_open_resolution_is_a_violation() -> TestResult {
    let mut sync = Sync::new()?;
    let page = frames(&sync.resume(0, None).map_err(|fault| format!("{fault:?}"))?)?;
    let (cut, _, _) = begin_cut(&page)?;
    sync.ready(cut)?;
    let result = sync.frame(CompanionFrame::WitnessResolved {
        coordinator_server_id: super::super::COORDINATOR,
        conversation_id: [9; 32],
        resolution_token: [3; 16],
        new_head_sequence: 1,
        new_head_id: [8; 32],
    });
    assert_eq!(result.err(), Some(CompanionFault::Protocol));
    Ok(())
}
