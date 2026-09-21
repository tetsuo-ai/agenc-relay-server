//! Base entitlement of a route the coordinator projects outside the live
//! event stream (companion 12.5): an ESTATE cut may name only routes this
//! edge is entitled to, and the edge verifies that itself before READY.
//!
//! A channel route follows the base channel-detail entitlement exactly: the
//! hosted channel detail, in the active projection or in the base snapshot
//! generation still being installed, whose cut pairs with the transfer. A
//! direct route is never projected merely because a coordinator says so: one
//! of its two accounts must be hosted here, as a base account projection, a
//! declared base origin, or an attached companion device. Hosting is read
//! when the entry arrives and as it stood when the transfer opened, because
//! a paired base resynchronization closes the sessions the cut counted while
//! its pages are still being fetched. A cut may also restate a direct route
//! this edge already projects for the same pair, which discloses nothing.

#![forbid(unsafe_code)]

use agenc_relay_e2ee::wire::reply::E2eeReplyCode;
use agenc_relay_types::AccountId;

use super::events::Conversation;
use super::router::Refusal;
use super::{E2eeEdge, snapshot::HostedAccounts};
use crate::budget::BackingReservationPort;
use crate::federation::edge::EdgeFederation;

/// The 24-byte wire form of one Account ID.
fn wire_account(account: AccountId) -> Option<[u8; 24]> {
    account.to_text().as_bytes().try_into().ok()
}

impl E2eeEdge {
    /// Whether the base profile entitles this edge to the route `facts`
    /// describes, named by a coordinator cut for `conversation_id`.
    pub(super) fn cut_route_entitled(
        &self,
        edge: &EdgeFederation,
        conversation_id: &[u8; 32],
        facts: &Conversation,
        opened: &HostedAccounts,
    ) -> bool {
        match (facts.channel, facts.direct) {
            (Some(channel), _) => edge.holds_channel(channel),
            (None, Some((first, second))) => {
                self.hosts_direct_account(edge, opened, &first)
                    || self.hosts_direct_account(edge, opened, &second)
                    || self
                        .conversations
                        .get(conversation_id)
                        .is_some_and(|known| known.direct == Some((first, second)))
            }
            (None, None) => false,
        }
    }

    /// Whether the base profile still entitles this edge to a route it
    /// already projects, before an installer rewrites its head: a channel
    /// route needs its hosted channel detail; a direct route it already
    /// holds gains no pair and no account from a new head.
    pub(super) fn projected_route_entitled(
        &self,
        edge: &EdgeFederation,
        facts: &Conversation,
    ) -> bool {
        facts
            .channel
            .is_none_or(|channel| edge.holds_channel(channel))
    }

    /// Whether this edge hosts `account`, now or when the transfer opened.
    fn hosts_direct_account(
        &self,
        edge: &EdgeFederation,
        opened: &HostedAccounts,
        account: &[u8; 24],
    ) -> bool {
        opened.contains(account)
            || self.attached_account(account)
            || AccountId::parse_wire_bytes(account).is_ok_and(|id| edge.hosts_account(id))
    }

    /// Whether a local companion origin with an attached device is
    /// authenticated as `account`.
    fn attached_account(&self, account: &[u8; 24]) -> bool {
        self.origins
            .values()
            .any(|origin| origin.device.is_some() && origin.account.as_ref() == Some(account))
    }

    /// The accounts this edge hosts as a transfer opens, charged against the
    /// snapshot backing port before they are retained.
    pub(super) fn hosted_accounts_now(
        &self,
        edge: &EdgeFederation,
    ) -> Result<HostedAccounts, Refusal> {
        let attached = || {
            self.origins
                .values()
                .filter(|origin| origin.device.is_some())
                .filter_map(|origin| origin.account)
        };
        let count = edge
            .hosted_accounts()
            .count()
            .saturating_add(attached().count());
        if count == 0 {
            return Ok(HostedAccounts::default());
        }
        let port: BackingReservationPort = self
            .snapshot_backing
            .clone()
            .ok_or(E2eeReplyCode::RateLimited)?;
        let permit = port
            .reserve(count.saturating_mul(std::mem::size_of::<[u8; 24]>()))
            .map_err(|_| E2eeReplyCode::RateLimited)?;
        let mut accounts = Vec::new();
        accounts
            .try_reserve_exact(count)
            .map_err(|_| E2eeReplyCode::RateLimited)?;
        accounts.extend(edge.hosted_accounts().filter_map(wire_account));
        accounts.extend(attached());
        accounts.sort_unstable();
        accounts.dedup();
        Ok(HostedAccounts::new(accounts, permit))
    }
}
