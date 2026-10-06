//! Retained roster snapshots by roster identifier (companion 13.7.3).
//!
//! A device-signed statement names the root and the exact roster its
//! credential was authorized under, and that roster stops being the
//! account's current one at the first rotation. A roster object is owned
//! while it is the account's current roster; once superseded it stays
//! resident only until object expiry collects it. The snapshot a statement
//! names is resolved from the roster objects still resident and
//! re-verified under the account's re-verified root chain, and a snapshot
//! that is no longer resident resolves to nothing. Those are the roots and
//! roster objects startup reconstruction consumes, so live admission and a
//! reload decide alike.
//! Whether the device is still roster-active now is the caller's separate
//! check: a named snapshot proves who held the key, never who holds it now.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use agenc_relay_crypto::SemanticHashDomain;
use agenc_relay_e2ee::identity::{VerifiedRoot, VerifiedRoster, restore_roster};
use agenc_relay_e2ee::ids::{account_id_digest, semantic_id_of};
use agenc_relay_e2ee::limits::MAX_ROSTER_OBJECT;
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::identity::ArcDeviceRoster;
use agenc_relay_e2ee::tls::{DecodeBudget, TlsDecode};

use super::CompanionState;

/// Retained `device_roster` object identifiers by roster identifier.
pub(crate) type Index = BTreeMap<[u8; 32], [u8; 32]>;

/// The transient work one resolution may hold: the decoded roster object,
/// its verified view, and the re-verified root chain.
pub(super) const RESOLUTION_WORK_BYTES: usize = MAX_ROSTER_OBJECT * 4 + 16_384;

/// The root and the roster one device-signed statement names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Named {
    /// The fingerprint of the signing root.
    pub(super) root_fingerprint: [u8; 32],
    /// The generation of the signing root.
    pub(super) root_generation: u64,
    /// The roster identifier.
    pub(super) roster_id: [u8; 32],
}

impl Named {
    fn root(&self, root: &VerifiedRoot) -> bool {
        (root.fingerprint, root.generation) == (self.root_fingerprint, self.root_generation)
    }
}

fn decode(bytes: &[u8]) -> Option<ArcDeviceRoster> {
    let mut budget = DecodeBudget::new(MAX_ROSTER_OBJECT, 1 << 16);
    let kind = Some(ArcWireObjectKind::DeviceRoster);
    let object = ArcWireObject::decode_kind(bytes, kind, &mut budget).ok()?;
    ArcDeviceRoster::decode_exact(object.body(), &mut budget).ok()
}

/// Rebuilds the index from every retained roster object, as startup does
/// once the durable objects are resident.
pub(super) fn rebuild(state: &mut CompanionState) {
    let rosters = state.objects.iter().filter_map(|(object_id, bytes)| {
        let (kind, _) = ArcWireObject::peek(bytes).ok()?;
        let roster = (kind == ArcWireObjectKind::DeviceRoster).then(|| decode(bytes))??;
        let roster_id = semantic_id_of(SemanticHashDomain::RosterId, &roster.tbs).ok()?;
        Some((roster_id, *object_id))
    });
    state.roster_snapshots = rosters.collect();
}

/// Resolves the root and the retained roster snapshot `named` states for
/// `account`, re-verified under that account's own root chain. A roster
/// that was never retained, that another account's root signed, or that
/// does not re-verify resolves nothing.
pub(super) fn resolve(
    state: &CompanionState,
    network_id: &[u8; 32],
    account: &[u8; 24],
    named: &Named,
) -> Option<(VerifiedRoot, VerifiedRoster)> {
    let digest = account_id_digest(network_id, account).ok()?;
    let head = state.principals.get(&digest);
    // The head is already verified; a statement naming it needs no work.
    let current =
        head.filter(|(root, roster)| named.root(root) && roster.roster_id == named.roster_id);
    if let Some((root, roster)) = current {
        return Some((*root, roster.clone()));
    }
    let root = match head.map(|(root, _)| *root).filter(|root| named.root(root)) {
        Some(root) => root,
        None => super::startup::principal_roots(state, network_id, account)?
            .into_iter()
            .find(|root| named.root(root))?,
    };
    let object_id = state.roster_snapshots.get(&named.roster_id)?;
    let roster = decode(state.objects.get(object_id)?)?;
    let verified = restore_roster(&root, &roster).ok()?;
    (verified.roster_id == named.roster_id).then_some((root, verified))
}
