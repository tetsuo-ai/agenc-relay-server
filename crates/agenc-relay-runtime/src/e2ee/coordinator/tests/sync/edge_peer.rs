#![forbid(unsafe_code)]

//! The real companion coordinator as the peer of an edge test: the lines
//! the edge queues are delivered as they would arrive on the link, and the
//! coordinator's answers come back as frames.

use super::*;
use crate::e2ee::coordinator::CompleteRequest;
use crate::e2ee::coordinator::request::{self, Classified, Decoded};
use crate::federation::edge::BaseOriginFacts;

/// One companion coordinator that accepted the edge's EORIGIN RESET and
/// whose base host holds the edge's origins.
pub(crate) struct EdgePeer {
    sync: Sync,
}

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
        Ok(Self { sync })
    }

    /// The base facts of the origin the host holds at `generation`, for the
    /// edge to mirror.
    pub(crate) fn facts(generation: u64) -> BaseOriginFacts {
        Self::facts_of(ORIGIN, generation)
    }

    /// The base facts of another origin of the same base connection at
    /// `generation`: the host mirrors one base origin for every Origin ID.
    pub(crate) fn facts_of(origin_id: [u8; 16], generation: u64) -> BaseOriginFacts {
        BaseOriginFacts {
            origin_id,
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
        self.sync
            .host
            .origin
            .as_mut()
            .ok_or("base origin")?
            .generation = generation;
        Ok(())
    }

    /// The link closes and comes back: the coordinator suspends the origin
    /// and accepts the edge's next EORIGIN RESET.
    pub(crate) fn relink(&mut self) -> TestResult {
        self.sync.harness.coordinator.link_closed(home());
        self.sync.reset()?;
        Ok(())
    }

    /// The link closes: the coordinator suspends the origin until the
    /// edge's next EORIGIN RESET arrives, which it answers with READY at
    /// once when the base origin set is `base_ready`.
    pub(crate) fn link_lost(&mut self, base_ready: bool) {
        self.sync.harness.coordinator.link_closed(home());
        self.sync.host.ready = base_ready;
    }

    /// The base origin set becomes ready: the coordinator sends the
    /// EORIGIN READY the accepted RESET awaited.
    pub(crate) fn base_ready(&mut self) -> TestResult<Vec<CompanionFrame>> {
        self.sync.host.ready = true;
        self.sync
            .harness
            .coordinator
            .origins_ready(home(), INCARNATION)
            .map_err(|fault| format!("{fault:?}"))?
            .iter()
            .map(parse)
            .collect()
    }

    /// Records `count` committed requests under the generation the
    /// coordinator holds, as their batches would.
    pub(crate) fn committed_requests(&mut self, count: u64) -> TestResult {
        self.held_origin(ORIGIN)?.next_sequence = count;
        Ok(())
    }

    /// Delivers one line the edge `sender` queued and returns the
    /// coordinator's answers, or the fault it refuses the line with. A
    /// complete request is classified as the executor classifies it: a
    /// fresh one at the next sequence commits as its batch would, with its
    /// replay row and stored result, an executed one is answered from the
    /// replay table, and any other is refused.
    pub(crate) fn deliver(
        &mut self,
        line: &str,
        sender: &str,
    ) -> Result<Vec<CompanionFrame>, CompanionFault> {
        let Ok(ParsedLine::Companion(frame)) = parse_line(line.trim_end_matches("\r\n"), sender)
        else {
            return Err(CompanionFault::Protocol);
        };
        let actions = self.sync.frame(frame)?;
        let mut answers = frames(&actions).map_err(|_| CompanionFault::Protocol)?;
        for action in &actions {
            if let Action::Execute(complete) = action {
                answers.extend(self.execute(complete)?);
            }
        }
        Ok(answers)
    }

    /// Delivers one line the edge `sender` queued without running the
    /// request it completes: the request was waiting for its payload or for
    /// the executor when its link closed.
    pub(crate) fn deliver_unexecuted(
        &mut self,
        line: &str,
        sender: &str,
    ) -> Result<(), CompanionFault> {
        let Ok(ParsedLine::Companion(frame)) = parse_line(line.trim_end_matches("\r\n"), sender)
        else {
            return Err(CompanionFault::Protocol);
        };
        let _not_run = self.sync.frame(frame)?;
        Ok(())
    }

    fn execute(
        &mut self,
        complete: &CompleteRequest,
    ) -> Result<Vec<CompanionFrame>, CompanionFault> {
        let coordinator = &self.sync.harness.coordinator;
        let decoded =
            request::decode(coordinator, complete).map_err(|_| CompanionFault::Protocol)?;
        match request::classify(&coordinator.state, HOME, &decoded) {
            Classified::Fresh => {
                let origin = self
                    .held_origin(decoded.request.origin_id)
                    .map_err(|_| CompanionFault::Protocol)?;
                origin.next_sequence = origin
                    .next_sequence
                    .checked_add(1)
                    .ok_or(CompanionFault::Protocol)?;
                self.commit(&decoded)?;
                Ok(Vec::new())
            }
            Classified::Replay(result, responses) => {
                let lines = crate::e2ee::coordinator::execute::replay_lines(
                    &self.sync.harness.coordinator,
                    &complete.correlation,
                    HOME,
                    &result,
                    &responses,
                )
                .map_err(|_| CompanionFault::Protocol)?;
                lines
                    .iter()
                    .map(parse)
                    .collect::<TestResult<Vec<_>>>()
                    .map_err(|_| CompanionFault::Protocol)
            }
            Classified::Violation => Err(CompanionFault::Protocol),
        }
    }

    /// Records the replay row and the stored result that a fresh request's
    /// batch commits, so a copy carried again is answered from them.
    fn commit(&mut self, decoded: &Decoded) -> Result<(), CompanionFault> {
        let result = origin_object(0, [0; 32], None, None)
            .and_then(|(origin, _)| wire(ArcWireObjectKind::FederationResult, &origin))
            .map_err(|_| CompanionFault::Protocol)?;
        let harness = &mut self.sync.harness;
        harness.coordinator.state.replays.insert(
            request::replay_key(HOME, &decoded.request),
            ReplayRow {
                request_id: decoded.request.request_id,
                request_object_id: decoded.request_object_id,
                result_object_id: Some(object_id(&result)),
                response_object_ids: Vec::new(),
                security_mutation: false,
                retain_until: u64::MAX,
            },
        );
        crate::e2ee::coordinator::results::Prepared::capture(
            &result,
            std::iter::empty(),
            &harness.backing,
        )?
        .apply(
            &mut harness.coordinator.state.results,
            decoded.request_object_id,
        );
        Ok(())
    }

    /// What the coordinator holds for the origin.
    pub(crate) fn held(&mut self) -> TestResult<Held> {
        self.held_of(ORIGIN)
    }

    /// What the coordinator holds for the origin `origin_id`.
    pub(crate) fn held_of(&mut self, origin_id: [u8; 16]) -> TestResult<Held> {
        let origin = self.held_origin(origin_id)?;
        Ok(Held {
            generation: origin.generation,
            next_sequence: origin.next_sequence,
            fenced: origin.fenced,
        })
    }

    fn held_origin(
        &mut self,
        origin_id: [u8; 16],
    ) -> TestResult<&mut crate::e2ee::coordinator::CompanionOrigin> {
        Ok(self
            .sync
            .harness
            .coordinator
            .state
            .origins
            .get_mut(&CompanionOriginKey {
                home_server_id: HOME,
                server_incarnation: INCARNATION,
                origin_id,
            })
            .ok_or("held origin")?)
    }
}
