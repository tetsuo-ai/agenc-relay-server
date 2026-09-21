//! Per-link companion state (companion Section 12.5): the ECAP negotiation
//! started after both FREADY, the `profile_active` gate on every later
//! companion frame, and the bounded queue of admitted frames the companion
//! routers drain.
//!
//! A node without a companion profile refuses every companion frame, which
//! closes the link exactly as an unknown command did before.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;

use agenc_relay_e2ee::federation::ecap::{EcapNegotiation, EcapViolation, violation_line};
use agenc_relay_e2ee::federation::frames::CompanionFrame;
use agenc_relay_e2ee::profile::EcapTuple;
use agenc_relay_federation_wire::FederationLineText;

use crate::federation::LinkId;

/// The millisecond value of a monotonic tick (the runtime clock counts
/// milliseconds).
#[must_use]
pub const fn tick_millis(tick: agenc_relay_types::MonotonicTick) -> u64 {
    tick.get()
}

/// Admitted companion frames one link may hold before its router drains
/// them.
pub const MAX_PENDING_COMPANION_FRAMES: usize = 256;

/// The local companion profile of a node: the immutable ECAP tuple.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompanionProfile {
    /// The local OFFER tuple.
    pub local: EcapTuple,
}

/// Why a companion frame closed the link.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompanionViolation {
    /// This node has no companion profile.
    Unsupported,
    /// The ECAP negotiation failed.
    Profile(EcapViolation),
    /// The router did not drain admitted frames in time.
    Backlog,
    /// A rendered line did not fit the link.
    Render,
    /// A companion request violated the federation grammar, order, or
    /// replay rules.
    Request,
    /// The executor could not stage or answer the request.
    Executor,
    /// The ESTATE token expired before READY.
    SnapshotExpired,
    /// A candidate or terminal event did not extend the witnessed sequencer
    /// record chain (companion 12.5).
    Witness,
}

impl fmt::Display for CompanionViolation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => formatter.write_str("companion frames are not supported here"),
            Self::Profile(violation) => violation.fmt(formatter),
            Self::Backlog => formatter.write_str("companion frame backlog exceeded"),
            Self::Request => formatter.write_str("companion request violated the profile"),
            Self::Executor => formatter.write_str("companion executor unavailable"),
            Self::SnapshotExpired => formatter.write_str("companion state transfer expired"),
            Self::Witness => formatter.write_str("sequencer record chain did not extend"),
            Self::Render => formatter.write_str("companion line could not be rendered"),
        }
    }
}

impl std::error::Error for CompanionViolation {}

/// What the owner does after one companion frame.
pub enum CompanionAction {
    /// Nothing to send; the negotiation advanced or a frame was queued.
    Quiet,
    /// Send this line (an ECAP ACK).
    Send(FederationLineText),
}

struct CompanionLinkState {
    negotiation: EcapNegotiation,
    pending: VecDeque<CompanionFrame>,
}

/// The companion state of every live link of one owner.
pub struct CompanionLinks {
    profile: Option<CompanionProfile>,
    local_name: String,
    links: BTreeMap<LinkId, CompanionLinkState>,
}

impl CompanionLinks {
    /// Companion links under `profile` (none disables the profile).
    #[must_use]
    pub fn new(profile: Option<CompanionProfile>, local_name: String) -> Self {
        Self {
            profile,
            local_name,
            links: BTreeMap::new(),
        }
    }

    /// Whether this node negotiates the companion profile.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.profile.is_some()
    }

    /// Starts negotiating on a newly established link; returns the OFFER
    /// line to send, or nothing when the profile is disabled.
    pub fn link_established(
        &mut self,
        link: LinkId,
        now_millis: u64,
    ) -> Result<Option<FederationLineText>, CompanionViolation> {
        let Some(profile) = &self.profile else {
            return Ok(None);
        };
        let (negotiation, offer) = EcapNegotiation::start(profile.local.clone(), now_millis);
        self.links.insert(
            link,
            CompanionLinkState {
                negotiation,
                pending: VecDeque::new(),
            },
        );
        self.render(&offer).map(Some)
    }

    /// Forgets a closed link.
    pub fn link_closed(&mut self, link: LinkId) {
        self.links.remove(&link);
    }

    /// The deadline instant of a negotiating link, in milliseconds.
    #[must_use]
    pub fn deadline(&self, link: LinkId) -> Option<u64> {
        self.links
            .get(&link)
            .map(|state| state.negotiation.deadline())
    }

    /// Whether a companion profile is installed at all.
    #[must_use]
    pub fn has_profile(&self) -> bool {
        self.profile.is_some()
    }

    /// Whether the profile is active on `link`.
    #[must_use]
    pub fn profile_active(&self, link: LinkId) -> bool {
        self.links
            .get(&link)
            .is_some_and(|state| state.negotiation.profile_active())
    }

    /// Handles one companion frame from `link`, whose prefix the transport
    /// already matched to the authenticated peer.
    pub fn on_frame(
        &mut self,
        link: LinkId,
        frame: CompanionFrame,
    ) -> Result<CompanionAction, CompanionViolation> {
        let Some(state) = self.links.get_mut(&link) else {
            return Err(CompanionViolation::Unsupported);
        };
        match frame {
            CompanionFrame::EcapOffer(tuple) => {
                let ack = state
                    .negotiation
                    .on_offer(true, &tuple)
                    .map_err(CompanionViolation::Profile)?;
                let line = render_line(&self.local_name, &ack)?;
                Ok(CompanionAction::Send(line))
            }
            CompanionFrame::EcapAck(tuple) => {
                state
                    .negotiation
                    .on_ack(true, &tuple)
                    .map_err(CompanionViolation::Profile)?;
                Ok(CompanionAction::Quiet)
            }
            other => {
                state
                    .negotiation
                    .admit(&other)
                    .map_err(CompanionViolation::Profile)?;
                if state.pending.len() >= MAX_PENDING_COMPANION_FRAMES {
                    return Err(CompanionViolation::Backlog);
                }
                state.pending.push_back(other);
                Ok(CompanionAction::Quiet)
            }
        }
    }

    /// Checks the negotiation deadline of `link` at `now_millis`.
    pub fn deadline_fired(&self, link: LinkId, now_millis: u64) -> Result<(), CompanionViolation> {
        match self.links.get(&link) {
            Some(state) => state
                .negotiation
                .on_tick(now_millis)
                .map_err(CompanionViolation::Profile),
            None => Ok(()),
        }
    }

    /// Drains the admitted frames of `link` in arrival order.
    pub fn drain(&mut self, link: LinkId) -> Vec<CompanionFrame> {
        self.links
            .get_mut(&link)
            .map(|state| state.pending.drain(..).collect())
            .unwrap_or_default()
    }

    /// Admitted frames waiting on `link`.
    #[must_use]
    pub fn pending(&self, link: LinkId) -> usize {
        self.links.get(&link).map_or(0, |state| state.pending.len())
    }

    /// The line a violation sends before the link closes.
    pub fn violation_line(&self) -> Result<FederationLineText, CompanionViolation> {
        FederationLineText::from_rendered(violation_line(&self.local_name))
            .map_err(|_| CompanionViolation::Render)
    }

    fn render(&self, frame: &CompanionFrame) -> Result<FederationLineText, CompanionViolation> {
        render_line(&self.local_name, frame)
    }
}

fn render_line(
    local_name: &str,
    frame: &CompanionFrame,
) -> Result<FederationLineText, CompanionViolation> {
    let text = frame
        .render(local_name)
        .map_err(|_| CompanionViolation::Render)?;
    FederationLineText::from_rendered(text).map_err(|_| CompanionViolation::Render)
}

#[cfg(test)]
mod tests {
    use agenc_relay_e2ee::wire::tokens::base64url_encode;

    use super::*;

    fn profile() -> Result<CompanionProfile, agenc_relay_e2ee::E2eeError> {
        Ok(CompanionProfile {
            local: EcapTuple::local(
                &base64url_encode(&[1; 32]),
                &base64url_encode(&[2; 16]),
                0,
                &base64url_encode(&[3; 32]),
            )?,
        })
    }

    fn ack_frame() -> CompanionFrame {
        CompanionFrame::Ack(agenc_relay_e2ee::federation::frames::DeliveryPosition {
            server_id: [1; 16],
            delivery_generation: 0,
            delivery_sequence: 0,
            event_id: [0; 16],
        })
    }

    #[test]
    fn a_disabled_node_refuses_every_companion_frame() -> Result<(), Box<dyn std::error::Error>> {
        let mut links = CompanionLinks::new(None, "edge.example".to_owned());
        assert!(!links.enabled());
        assert!(links.link_established(LinkId::new(1), 0)?.is_none());
        assert!(matches!(
            links.on_frame(LinkId::new(1), ack_frame()),
            Err(CompanionViolation::Unsupported)
        ));
        assert!(!links.profile_active(LinkId::new(1)));
        assert_eq!(links.deadline(LinkId::new(1)), None);
        assert_eq!(links.deadline_fired(LinkId::new(1), 9_999), Ok(()));
        assert!(
            links
                .violation_line()?
                .as_str()
                .ends_with("ARC-MLS profile mismatch\r\n")
        );
        Ok(())
    }

    #[test]
    fn an_enabled_node_negotiates_then_queues_admitted_frames()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut links = CompanionLinks::new(Some(profile()?), "coord.example".to_owned());
        let offer = links
            .link_established(LinkId::new(1), 100)?
            .ok_or("offer")?;
        assert!(
            offer
                .as_str()
                .starts_with(":coord.example ECAP ARCMLS OFFER 1 ")
        );
        assert_eq!(links.deadline(LinkId::new(1)), Some(5_100));
        assert!(matches!(
            links.on_frame(LinkId::new(1), ack_frame()),
            Err(CompanionViolation::Profile(EcapViolation::NotActive))
        ));
        let local = profile()?.local;
        let CompanionAction::Send(ack) =
            links.on_frame(LinkId::new(1), CompanionFrame::EcapOffer(local.clone()))?
        else {
            return Err("ack expected".into());
        };
        assert!(
            ack.as_str()
                .starts_with(":coord.example ECAP ARCMLS ACK 1 ")
        );
        assert!(matches!(
            links.on_frame(LinkId::new(1), CompanionFrame::EcapAck(local.clone())),
            Ok(CompanionAction::Quiet)
        ));
        assert!(links.profile_active(LinkId::new(1)));
        assert_eq!(links.deadline_fired(LinkId::new(1), 9_999), Ok(()));
        assert!(matches!(
            links.on_frame(LinkId::new(1), ack_frame()),
            Ok(CompanionAction::Quiet)
        ));
        assert_eq!(links.pending(LinkId::new(1)), 1);
        assert_eq!(links.drain(LinkId::new(1)).len(), 1);
        assert_eq!(links.pending(LinkId::new(1)), 0);
        for _ in 0..MAX_PENDING_COMPANION_FRAMES {
            links.on_frame(LinkId::new(1), ack_frame())?;
        }
        assert!(matches!(
            links.on_frame(LinkId::new(1), ack_frame()),
            Err(CompanionViolation::Backlog)
        ));
        assert!(matches!(
            links.on_frame(LinkId::new(1), CompanionFrame::EcapOffer(local)),
            Err(CompanionViolation::Profile(EcapViolation::Duplicate))
        ));
        links.link_closed(LinkId::new(1));
        assert!(!links.profile_active(LinkId::new(1)));
        let mut slow = CompanionLinks::new(Some(profile()?), "coord.example".to_owned());
        slow.link_established(LinkId::new(2), 0)?;
        assert!(matches!(
            slow.deadline_fired(LinkId::new(2), 5_000),
            Err(CompanionViolation::Profile(EcapViolation::Timeout))
        ));
        assert!(!CompanionViolation::Backlog.to_string().is_empty());
        Ok(())
    }
}
