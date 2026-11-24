//! Each active device is either served by a current edge or retained in its own mailbox.
#![forbid(unsafe_code)]
use super::*;
use crate::e2ee::coordinator::{CompanionOrigin, CompanionOriginKey};
use agenc_relay_domain::e2ee::directory::{AccountEntry, Attachment, RosterHead};

fn account(state: &mut CompanionState, id: u8, devices: &[u8]) {
    let mut entry = AccountEntry {
        roster: Some(RosterHead {
            generation: 0,
            object_id: [0; 32],
            roster_id: [1; 32],
            root_fingerprint: [2; 32],
            active_devices: devices.iter().map(|d| [*d; 16]).collect(),
        }),
        ..AccountEntry::default()
    };
    for device in devices {
        entry.attachments.insert(
            [*device; 16],
            Attachment {
                session_generation: 2,
                challenge: None,
            },
        );
    }
    state.directory.restore_account([id; 32], entry);
}

fn origin(
    state: &mut CompanionState,
    edge: u8,
    id: u8,
    account: u8,
    device: Option<(u8, u64)>,
    fenced: bool,
    suspended: bool,
) {
    let key = CompanionOriginKey {
        home_server_id: [edge; 16],
        server_incarnation: [1; 16],
        origin_id: [id; 16],
    };
    state.origins.insert(
        key,
        CompanionOrigin {
            home_server_id: key.home_server_id,
            server_incarnation: key.server_incarnation,
            origin_id: key.origin_id,
            generation: 1,
            next_sequence: 0,
            account_id: Some([account; 24]),
            account_digest: Some([account; 32]),
            device: device.map(|(d, g)| ([d; 16], g)),
            connection_nonce: [0; 32],
            connection_id: [id; 16],
            object_id: [0; 32],
            state_id: [0; 32],
            previous_state_id: [0; 32],
            fenced,
            suspended,
        },
    );
}

#[test]
fn one_committed_cut_distinguishes_devices_sessions_roster_and_edge_state() {
    let mut state = CompanionState::default();
    account(&mut state, 1, &[11, 12, 13]);
    account(&mut state, 2, &[21, 22, 23, 24]);
    account(&mut state, 3, &[31]);
    origin(&mut state, 1, 1, 1, Some((11, 2)), false, false); // submitting device
    origin(&mut state, 2, 2, 1, Some((12, 2)), false, false); // sender's other live device
    origin(&mut state, 3, 3, 1, Some((12, 1)), false, false); // superseded session
    origin(&mut state, 2, 4, 2, Some((21, 2)), false, false); // another recipient at same edge
    origin(&mut state, 3, 5, 2, Some((22, 2)), true, false);
    origin(&mut state, 3, 6, 2, Some((23, 2)), false, true);
    origin(&mut state, 3, 7, 2, Some((29, 2)), false, false); // revoked
    origin(&mut state, 4, 8, 2, None, false, false);
    origin(&mut state, 4, 9, 3, Some((31, 2)), false, false); // unrelated
    let target = |a, d| Target {
        account_digest: [a; 32],
        device_id: [d; 16],
    };
    let (edges, offline) = recipients(&state, [[1; 32], [2; 32]]);
    assert_eq!(
        edges,
        BTreeSet::from([ServerId::from_bytes([1; 16]), ServerId::from_bytes([2; 16])])
    );
    assert_eq!(
        offline,
        BTreeSet::from([target(1, 13), target(2, 22), target(2, 23), target(2, 24)])
    );
}
