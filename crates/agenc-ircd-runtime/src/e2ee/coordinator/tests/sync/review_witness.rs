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
    assert!(
        answer.is_ok(),
        "the coordinator refused EWITNESS REQUEST as {:?}",
        answer.err(),
    );
    Ok(())
}
