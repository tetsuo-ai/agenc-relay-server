//! Companion Section 12.5 on a running link: an `ECAP` line that is not
//! this node's exact profile tuple, such as the OFFER of a peer of the
//! previous profile revision, is answered with
//! `ERROR :ARC-MLS profile mismatch` before the link closes.
#![forbid(unsafe_code)]
#![cfg(test)]

use super::*;
use crate::test_support::TestResult;
use agenc_relay_crypto::OsEntropy;
use agenc_relay_e2ee::profile::EcapTuple;

/// The E2EE profile token of release candidate 3, before the ReInit target
/// revision moved the profile hash.
const RC3_PROFILE_TOKEN: &str = "wbUxP4p_GWzaMO6nl_satlsASlXXHPmoEHGScEbl05U";
const HASH_TOKEN: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const ID_TOKEN: &str = "AAAAAAAAAAAAAAAAAAAAAQ";

/// The OFFER line `profile` would send from `peer.example`.
fn offer_line(profile: &str) -> TestResult<String> {
    let mut parameters = EcapTuple::local(HASH_TOKEN, ID_TOKEN, 0, HASH_TOKEN)?.render();
    if let Some(slot) = parameters.get_mut(1) {
        *slot = profile.to_owned();
    }
    Ok(format!(
        ":peer.example ECAP ARCMLS OFFER {}\r\n",
        parameters.join(" ")
    ))
}

/// Runs one link as `core.example` against `peer.example`, sends `line` from
/// the peer, and returns what the peer reads back and why the link closed.
async fn answer_to(line: &str) -> TestResult<(String, LinkCloseReason)> {
    let (local, mut remote) = tokio::io::duplex(1 << 16);
    let (reader, writer) = FrameReader::new(local, "peer.example")?.split();
    let (_handle, queue) = link_queue(1 << 20);
    let (inbound, _receiver) = mpsc::channel(4);
    let context = LinkContext {
        link: LinkId::new(81),
        peer: ServerId::from_bytes([81; 16]),
        local_name: "core.example".to_owned(),
        inbound,
        budget: ingress_budget(),
        token: CancellationToken::root(),
        timing: LinkTiming::SPEC,
        observer: None,
    };
    let task = tokio::spawn(async move {
        let mut entropy = OsEntropy;
        run_link(reader, writer, queue, context, &mut entropy).await
    });
    remote.write_all(line.as_bytes()).await?;
    let reason = tokio::time::timeout(std::time::Duration::from_secs(5), task).await??;
    let mut answer = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        remote.read_to_string(&mut answer),
    )
    .await??;
    Ok((answer, reason))
}

#[test]
fn an_offer_of_another_profile_is_a_profile_line_failure() -> TestResult {
    let current = offer_line(agenc_relay_federation_wire::E2EE_PROFILE_TOKEN)?;
    assert!(matches!(
        parse_line(current.trim_end(), "peer.example"),
        Ok(ParsedLine::Companion(CompanionFrame::EcapOffer(_)))
    ));
    let previous = offer_line(RC3_PROFILE_TOKEN)?;
    assert!(matches!(
        parse_line(previous.trim_end(), "peer.example"),
        Err(ReadFailure::Profile)
    ));
    let short = ":peer.example ECAP ARCMLS OFFER 1";
    assert!(matches!(
        parse_line(short, "peer.example"),
        Err(ReadFailure::Profile)
    ));
    let unknown = ":peer.example ECAP ARCMLS HELLO 1";
    assert!(matches!(
        parse_line(unknown, "peer.example"),
        Err(ReadFailure::Profile)
    ));
    Ok(())
}

#[tokio::test]
async fn a_previous_profile_offer_is_answered_with_the_mismatch_line_and_closes() -> TestResult {
    let (answer, reason) = answer_to(&offer_line(RC3_PROFILE_TOKEN)?).await?;
    assert_eq!(answer, ":core.example ERROR :ARC-MLS profile mismatch\r\n");
    assert_eq!(reason, LinkCloseReason::Framing);
    Ok(())
}

#[tokio::test]
async fn a_malformed_base_line_still_closes_without_a_profile_line() -> TestResult {
    let (answer, reason) = answer_to(":peer.example FPING\r\n").await?;
    assert_eq!(answer, "");
    assert_eq!(reason, LinkCloseReason::Framing);
    Ok(())
}
