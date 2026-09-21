#![forbid(unsafe_code)]

//! A council seat is pinned to one certificate: a device the current roster
//! no longer holds, and a device that re-enrolled under a new certificate,
//! both fail to vote although the policy still names them.

use super::*;
use crate::identity::{verify_root_identity, verify_roster};
use crate::objects::identity::ArcDeviceRoster;
use crate::route::PrincipalRosters;

type RosterFenceResult = Result<(), Box<dyn Error>>;

/// Publishes `replacement` as the only roster of `principal`'s root, so the
/// caller can present a council device that the roster no longer admits.
fn republished(
    principal: &Principal,
    replacement: &ArcDeviceRoster,
) -> Result<PrincipalRosters, Box<dyn Error>> {
    let mut map = PrincipalRosters::new();
    let root = verify_root_identity(&NETWORK, &principal.root, None)?;
    let roster = verify_roster(&root, replacement, None)?;
    map.insert(root.account_id, (root, roster));
    Ok(map)
}

fn council_of_one() -> Result<(Vec<Principal>, PrincipalRosters, VerifiedPolicy), Box<dyn Error>> {
    let principals = vec![principal(43, &ACCOUNT, &[7])?];
    let rosters = principal_rosters(&principals)?;
    let verified = verify_policy(
        &NETWORK,
        &CONVERSATION,
        &policy(&PolicySpec::moderated(&principals, CONVERSATION))?,
        &rosters,
        None,
    )?;
    Ok((principals, rosters, verified))
}

#[test]
fn a_council_device_the_roster_dropped_cannot_vote() -> RosterFenceResult {
    let (principals, rosters, verified) = council_of_one()?;
    let first = principals.first().ok_or("principal")?;
    let terminal = Terminal::finalize([58; 32]);
    let tbs = vote_tbs(&slot(), [52; 32], terminal);
    let vote = finality_vote(first, 7, &tbs)?;

    let mut accepted = QuorumLedger::new();
    accepted.record(&verified, &rosters, &tbs, &vote)?;
    assert_eq!(accepted.count(&terminal), 1);

    // The root republished a roster that holds another device instead.
    let successor = roster(
        &first.root_secret,
        &first.root,
        0,
        [0; 32],
        (100, 100 + 6 * 24 * 3600),
        vec![certificate(
            &first.root_secret,
            &first.root,
            &DeviceSpec::new(8),
        )?],
        Vec::new(),
    )?;
    let dropped = republished(first, &successor)?;
    let mut ledger = QuorumLedger::new();
    assert_eq!(
        ledger.record(&verified, &dropped, &tbs, &vote),
        Err(E2eeError::InvalidValue),
        "the policy still names the seat, but the roster no longer holds it"
    );
    assert_eq!(ledger.count(&terminal), 0);
    assert!(
        verified
            .council_member(&vote.signer_root_fingerprint, &[7; 16])
            .is_some()
    );
    Ok(())
}

#[test]
fn a_re_enrolled_council_device_does_not_inherit_the_pinned_seat() -> RosterFenceResult {
    let (principals, rosters, verified) = council_of_one()?;
    let first = principals.first().ok_or("principal")?;
    let terminal = Terminal::finalize([59; 32]);
    let tbs = vote_tbs(&slot(), [52; 32], terminal);
    let vote = finality_vote(first, 7, &tbs)?;

    let mut accepted = QuorumLedger::new();
    accepted.record(&verified, &rosters, &tbs, &vote)?;
    assert_eq!(accepted.count(&terminal), 1);

    // The same device, the same key, a new certificate serial: the roster
    // admits it and the pinned certificate identifier no longer matches.
    let reissued = certificate(
        &first.root_secret,
        &first.root,
        &DeviceSpec {
            serial: 2,
            ..DeviceSpec::new(7)
        },
    )?;
    let renewed = roster(
        &first.root_secret,
        &first.root,
        0,
        [0; 32],
        (100, 100 + 6 * 24 * 3600),
        vec![reissued],
        Vec::new(),
    )?;
    let rotated = republished(first, &renewed)?;
    let mut ledger = QuorumLedger::new();
    assert_eq!(
        ledger.record(&verified, &rotated, &tbs, &vote),
        Err(E2eeError::InvalidValue),
        "a re-enrolled device does not inherit the certificate the policy pinned"
    );
    assert_eq!(ledger.count(&terminal), 0);
    Ok(())
}
