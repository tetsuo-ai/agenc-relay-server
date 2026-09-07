#![forbid(unsafe_code)]

//! Requester response association and retained output memory boundaries.

use super::*;
use crate::budget::{BoundedMemoryCharges, MemoryBudget, MemoryBudgetPort, MemoryCharge};
use crate::federation::codec::results::ResultArm;
use crate::test_support::TestResult;
use agenc_ircd_types::{OriginId, ServerId, ServerIncarnation};

fn echo(
    budget: &MemoryBudget,
    name: &str,
    seed: u8,
) -> Result<JoinEcho, Box<dyn core::error::Error>> {
    let charge = MemoryCharge::allocation(u64::try_from(ECHO_BACKING_BYTES)?)?;
    let permit = budget
        .try_acquire_batch(BoundedMemoryCharges::new(&[charge])?)?
        .split_exact(charge.bytes())
        .ok_or("echo permit")?;
    let mut frame = WireMessage::new(
        "sam!public@cloak",
        "JOIN",
        &[name, "sam-account"],
        Some("Sam Real"),
    )?;
    frame.add_server_tag("account", Some("sam-account"))?;
    Ok(JoinEcho {
        request: RequestId::from_bytes([1; 16]),
        replay_key: ReplayKey {
            home_server_id: ServerId::from_bytes([2; 16]),
            server_incarnation: ServerIncarnation::from_bytes([3; 16]),
            origin_id: OriginId::from_bytes([4; 16]),
            origin_generation: 5,
            operation_sequence: 6,
        },
        state_generation: 7,
        channel: ChannelInstanceId::from_bytes([seed; 16]),
        frame,
        permit,
    })
}

fn topic(name: &str) -> Result<WireMessage, Box<dyn core::error::Error>> {
    Ok(agenc_ircd_client_wire::numeric_reply(
        "edge.test",
        331,
        "sam",
        &[name],
        Some("No topic is set"),
    )?)
}

#[test]
fn exact_echoes_and_their_backing_survive_until_response_delivery() -> TestResult {
    let budget = MemoryBudget::new(1 << 20);
    let echoes = vec![echo(&budget, "#one", 1)?, echo(&budget, "#two", 2)?];
    let mut expected = Vec::new();
    for name in ["#one", "#two"] {
        let mut frame = WireMessage::new(
            "sam!public@cloak",
            "JOIN",
            &[name, "sam-account"],
            Some("Sam Real"),
        )?;
        frame.add_server_tag("account", Some("sam-account"))?;
        expected.push(frame);
    }
    let charge = budget.charged();
    assert!(charge >= 2 * u64::try_from(ECHO_BACKING_BYTES)?);
    let (frames, permits) = into_frames(7, echoes, vec![topic("#ONE")?, topic("#two")?])
        .map_err(|error| format!("{error:?}"))?;
    assert_eq!(
        frames.get(..2).ok_or("missing JOIN echoes")?,
        expected.as_slice()
    );
    assert_eq!(
        frames.iter().map(WireMessage::command).collect::<Vec<_>>(),
        ["JOIN", "JOIN", "331", "331"]
    );
    assert_eq!(permits.len(), 2);
    assert_eq!(budget.charged(), charge);
    drop(frames);
    drop(permits);
    assert_eq!(budget.charged(), 0);
    Ok(())
}

#[test]
fn inconsistent_echo_targets_and_generations_release_all_backing() -> TestResult {
    let budget = MemoryBudget::new(1 << 20);
    for names in [["#one", "#wrong"], ["#one", "#one"]] {
        let echoes = vec![echo(&budget, "#one", 1)?, echo(&budget, "#two", 2)?];
        assert!(into_frames(7, echoes, vec![topic(names[0])?, topic(names[1])?]).is_err());
        assert_eq!(budget.charged(), 0);
    }
    assert!(into_frames(8, vec![echo(&budget, "#one", 1)?], vec![topic("#one")?]).is_err());
    assert_eq!(budget.charged(), 0);
    assert!(into_frames(7, Vec::new(), vec![topic("#one")?]).is_err());
    assert!(into_frames(7, vec![echo(&budget, "#one", 1)?], Vec::new()).is_err());
    assert_eq!(budget.charged(), 0);
    Ok(())
}

#[test]
fn an_echo_cannot_be_covered_by_a_failure_or_another_generation() -> TestResult {
    let budget = MemoryBudget::new(1 << 20);
    let echo = echo(&budget, "#one", 1)?;
    let request = echo.request;
    assert!(
        check_result(
            &echo,
            request,
            &ResultArm::Committed {
                resulting_state_generation: 7
            }
        )
        .is_ok()
    );
    assert!(
        check_result(
            &echo,
            request,
            &ResultArm::Committed {
                resulting_state_generation: 8
            }
        )
        .is_err()
    );
    assert!(
        check_result(
            &echo,
            request,
            &ResultArm::Failed {
                code: "UNAVAILABLE".to_owned(),
                context: String::new()
            }
        )
        .is_err()
    );
    assert!(check_result(&echo, request, &ResultArm::NoContent).is_err());
    assert!(
        check_result(
            &echo,
            RequestId::from_bytes([9; 16]),
            &ResultArm::Committed {
                resulting_state_generation: 8
            }
        )
        .is_ok()
    );
    Ok(())
}
