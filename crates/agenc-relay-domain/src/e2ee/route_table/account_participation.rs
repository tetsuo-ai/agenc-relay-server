//! Account participation in the current fixed Direct route (architecture §14.6).

use super::{AccountId, RecoveryState, RouteLifecycle, RouteTable, RouteTarget};
use agenc_relay_types::AccountRandomId;

impl RouteTable {
    /// Whether this account still participates in any unclosed fixed Direct pair.
    #[must_use]
    pub fn has_unclosed_direct(&self, account: AccountId) -> bool {
        const FIRST: AccountId = AccountRandomId::from_bytes([0; 16]).to_account_id();
        self.unclosed_direct
            .range((account, FIRST)..)
            .next()
            .is_some_and(|(owner, _)| *owner == account)
    }

    /// Derive both directions from the holder of the pair index. A superseded ReInit
    /// predecessor can still be retained for history when its successor has already closed.
    pub(super) fn refresh_account_participation(&mut self, target: RouteTarget) {
        let RouteTarget::Direct(pair) = target else {
            return;
        };
        let held = self.direct_route(&pair).is_some_and(|entry| {
            !matches!(
                (entry.lifecycle, entry.recovery),
                (
                    RouteLifecycle::Tombstone { .. },
                    RecoveryState::Normal | RecoveryState::Closed
                )
            )
        });
        for relation in [
            (pair.smaller(), pair.larger()),
            (pair.larger(), pair.smaller()),
        ] {
            if held {
                self.unclosed_direct.insert(relation);
            } else {
                self.unclosed_direct.remove(&relation);
            }
        }
    }
}
