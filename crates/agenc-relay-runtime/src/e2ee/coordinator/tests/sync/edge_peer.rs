#![forbid(unsafe_code)]

//! The real companion coordinator as the peer of an edge test: the lines
//! the edge queues are delivered as they would arrive on the link, and the
//! coordinator's answers come back as frames.

use super::*;
use crate::federation::edge::BaseOriginFacts;

/// One companion coordinator that accepted the edge's EORIGIN RESET and
/// whose base host holds the edge's one origin.
pub(crate) struct EdgePeer(Sync);

/// What the coordinator holds for the edge's one origin.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Held {
    /// The generation in force.
    pub(crate) generation: u64,
    /// The next operation sequence, or the sequence a deletion fenced.
    pub(crate) next_sequence: u64,
    /// Whether a deletion fenced the origin.
    pub(crate) fenced: bool,
}

impl EdgePeer {
    /// A coordinator that has accepted EORIGIN RESET for the edge.
    pub(crate) fn reset() -> TestResult<Self> {
        let mut sync = Sync::new()?;
        sync.reset()?;
        Ok(Self(sync))
    }

    /// The base facts of the origin the host holds at `generation`, for the
    /// edge to mirror.
    pub(crate) fn facts(generation: u64) -> BaseOriginFacts {
        BaseOriginFacts {
            origin_id: ORIGIN,
            generation,
            acked_generation: Some(generation),
            connection_id: CONNECTION,
            connection_nonce: NONCE,
            session: Some(([21; 16], [22; 16])),
            account: None,
        }
    }

    /// The base origin advances to `generation`: its FORIGIN UPDATE was
    /// acknowledged, so the companion declaration of that generation is
    /// accepted.
    pub(crate) fn base_generation(&mut self, generation: u64) -> TestResult {
        self.0.host.origin.as_mut().ok_or("base origin")?.generation = generation;
        Ok(())
    }

    /// The link closes and comes back: the coordinator suspends the origin
    /// and accepts the edge's next EORIGIN RESET.
    pub(crate) fn relink(&mut self) -> TestResult {
        self.0.harness.coordinator.link_closed(home());
        self.0.reset()?;
        Ok(())
    }

    /// Records `count` committed requests under the generation the
    /// coordinator holds, as their batches would.
    pub(crate) fn committed_requests(&mut self, count: u64) -> TestResult {
        self.held_origin()?.next_sequence = count;
        Ok(())
    }

    /// Delivers one line the edge `sender` queued and returns the
    /// coordinator's answers, or the fault it refuses the line with.
    pub(crate) fn deliver(
        &mut self,
        line: &str,
        sender: &str,
    ) -> Result<Vec<CompanionFrame>, CompanionFault> {
        let Ok(ParsedLine::Companion(frame)) = parse_line(line.trim_end_matches("\r\n"), sender)
        else {
            return Err(CompanionFault::Protocol);
        };
        let actions = self.0.frame(frame)?;
        frames(&actions).map_err(|_| CompanionFault::Protocol)
    }

    /// What the coordinator holds for the origin.
    pub(crate) fn held(&mut self) -> TestResult<Held> {
        let origin = self.held_origin()?;
        Ok(Held {
            generation: origin.generation,
            next_sequence: origin.next_sequence,
            fenced: origin.fenced,
        })
    }

    fn held_origin(&mut self) -> TestResult<&mut crate::e2ee::coordinator::CompanionOrigin> {
        Ok(self
            .0
            .harness
            .coordinator
            .state
            .origins
            .get_mut(&CompanionOriginKey {
                home_server_id: HOME,
                server_incarnation: INCARNATION,
                origin_id: ORIGIN,
            })
            .ok_or("held origin")?)
    }
}
