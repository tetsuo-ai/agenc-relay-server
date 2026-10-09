//! The validation time every root and roster a finalization uses must cover
//! (companion 8.2 to 8.4 and 9.3).
//!
//! A root used for a candidate must cover its canonical validation time, and
//! every later use of a device certificate checks the certificate and roster
//! intervals against that time (companion 8.2 and 8.3). A finalization uses
//! the roots and rosters of the principals that sign in it: the controllers
//! whose approvals its authorization carries, the council devices whose
//! votes its request carries, and the devices whose processing ACKs the
//! caller's leaf-membership facts identify. A policy or binding transition
//! names every principal's roster head (companion 9.3, 9.4 and 13.7.2), so it
//! uses every principal. A principal that signs nothing in the record is not
//! used by it, so its expired roster does not block the record.
//!
//! Every root and roster the record installs, or carries as a reaffirmation,
//! covers the time too: a transition never installs an expired roster.
//!
//! An expired roster authorizes nothing, with one narrow exception
//! (companion 8.4): its devices may sign a `roster_recovery` candidate that
//! installs the account's continuous, unexpired successor under the same,
//! still valid root and changes nothing else. Such a device is checked
//! against both rosters, so it must be unchanged in the successor; it may
//! vote and acknowledge but never approve, since expired controller
//! credentials gain no approval authority. The quorum is still counted from
//! the complete old council.
//!
//! Endpoint-only, never claimed here: which leaf committed the candidate, and
//! the Removes and UpdatePath inside the encrypted Commit.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use super::{HistoricalChain, Transitions};
use crate::authorization::VerifiedAuthorization;
use crate::error::E2eeError;
use crate::identity::{AccountIdBytes, ValidationTime, VerifiedRoot, VerifiedRoster};
use crate::ids::SemanticId;
use crate::objects::conversation::{ArcCommitAuthorizationRule, action_bits};
use crate::objects::sequencing::ArcFinalizationRequest;
use crate::route::PrincipalRosters;

/// The devices one record identifies as signers: `(account, device)`.
pub(super) type SigningDevices = BTreeSet<(AccountIdBytes, [u8; 16])>;

/// What one principal signs in a finalization.
#[derive(Debug, Default)]
struct Acts {
    /// Whether one of its devices approved the authorization.
    approved: bool,
    /// Its devices that voted or acknowledged.
    devices: BTreeSet<[u8; 16]>,
}

/// Whether `root` and `roster` both cover `time`.
fn live(root: &VerifiedRoot, roster: &VerifiedRoster, time: ValidationTime) -> bool {
    root.interval.covers(time) && roster.interval.covers(time)
}

/// The account whose root at the record's position is `fingerprint`.
fn account_of(
    held: &PrincipalRosters,
    fingerprint: &SemanticId,
) -> Result<AccountIdBytes, E2eeError> {
    held.iter()
        .find(|(_, (root, _))| root.fingerprint == *fingerprint)
        .map(|(account, _)| *account)
        .ok_or(E2eeError::InvalidValue)
}

/// The principals a finalization uses, by account, with what each signs.
/// `held` is the principals' state before the record.
fn uses(
    held: &PrincipalRosters,
    authorization: &VerifiedAuthorization,
    request: &ArcFinalizationRequest,
    acknowledged: &SigningDevices,
) -> Result<BTreeMap<AccountIdBytes, Acts>, E2eeError> {
    let mut uses: BTreeMap<AccountIdBytes, Acts> = BTreeMap::new();
    if authorization.action_bits & (action_bits::POLICY | action_bits::BINDING) != 0 {
        uses.extend(held.keys().map(|account| (*account, Acts::default())));
    }
    for approval in request.proof.authorization.approvals.as_slice() {
        let account = account_of(held, &approval.signer_root_fingerprint)?;
        uses.entry(account).or_default().approved = true;
    }
    for vote in request.votes.as_slice() {
        let account = account_of(held, &vote.signer_root_fingerprint)?;
        let acts = uses.entry(account).or_default();
        acts.devices.insert(vote.signer_device_id);
    }
    for (account, device) in acknowledged {
        // A device of an account that is no binding principal holds no
        // roster here; its activity is the caller's check.
        if held.contains_key(account) {
            uses.entry(*account).or_default().devices.insert(*device);
        }
    }
    Ok(uses)
}

impl HistoricalChain {
    /// Requires every root and roster the finalization just applied uses or
    /// installs to cover its canonical validation time, apart from the
    /// narrow recovery exception. `held` is the principals' state before
    /// the record; `self` already holds the transitions' result, and the
    /// caller discards it on error.
    pub(super) fn check_liveness(
        &self,
        held: &PrincipalRosters,
        authorization: &VerifiedAuthorization,
        request: &ArcFinalizationRequest,
        acknowledged: &SigningDevices,
        transitions: &Transitions,
    ) -> Result<(), E2eeError> {
        let time = ValidationTime(authorization.validation_time);
        let installed = transitions
            .roster_heads
            .iter()
            .chain(transitions.roots.iter())
            .all(|(account, _)| {
                self.principals
                    .get(account)
                    .is_some_and(|(root, roster)| live(root, roster, time))
            });
        if !installed {
            return Err(E2eeError::InvalidValue);
        }
        let recovery = Self::recovery_candidate(authorization, transitions);
        for (account, acts) in uses(held, authorization, request, acknowledged)? {
            let (root, roster) = held.get(&account).ok_or(E2eeError::InvalidValue)?;
            let recovered = recovery && self.recovers(&account, &acts, roster, time);
            if !live(root, roster, time) && !recovered {
                return Err(E2eeError::InvalidValue);
            }
        }
        Ok(())
    }

    /// Whether the record is a `roster_recovery` candidate the exception can
    /// serve: labelled so, which the authorization's shape check holds to
    /// exactly the roster bit and the Removes its successor requires
    /// (`rule_matches_bits`), and continuing no root.
    fn recovery_candidate(
        authorization: &VerifiedAuthorization,
        transitions: &Transitions,
    ) -> bool {
        authorization.rule == ArcCommitAuthorizationRule::RosterRecovery
            && transitions.roots.is_empty()
    }

    /// Whether `account`, which held the `expired` roster, signs within the
    /// recovery exception: it approves nothing, it now holds a roster that
    /// covers `time` under a root that does, and every device it signed with
    /// is unchanged in that roster. A recovery continues no root, so only a
    /// roster this record installed can cover the time the expired one no
    /// longer covers, and `apply_rosters` holds that roster to the next
    /// generation naming the expired one (companion 8.4).
    fn recovers(
        &self,
        account: &AccountIdBytes,
        acts: &Acts,
        expired: &VerifiedRoster,
        time: ValidationTime,
    ) -> bool {
        let unchanged = |successor: &VerifiedRoster| {
            acts.devices.iter().all(|device| {
                expired
                    .device(device)
                    .is_some_and(|certificate| successor.device(device) == Some(certificate))
            })
        };
        !acts.approved
            && self
                .principals
                .get(account)
                .is_some_and(|(root, successor)| {
                    unchanged(successor) && live(root, successor, time)
                })
    }
}
