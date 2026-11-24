#![forbid(unsafe_code)]

//! The configured secret-lookup response floor (architecture 13.5).
//!
//! A JOIN, NAMES, TOPIC, or MODE that fails because the target does not
//! exist or is concealed must not answer before
//! `privacy.secret_lookup_floor_milliseconds` have passed since the
//! command's processing began, so that a missing channel and a concealed
//! one are not separated by the time the answer takes. This is a
//! best-effort response floor, not a constant-time or anonymity guarantee.
//!
//! One connection holds at most one floored response. The frames are
//! rendered when the command fails, charged against the output budget, and
//! published by the state owner's timer heap; the router defers that
//! connection's later commands until then, so a delayed answer never loses
//! its place in the connection's order.

use std::collections::BTreeMap;

use agenc_relay_client_wire::{MAX_COMMAND_BYTES, WireMessage};
use agenc_relay_types::MonotonicTick;

use crate::budget::MemoryPermit;
use crate::connection::sink::{ClientQueueDemand, ConnectionGeneration, SinkReserveError};
use crate::e2ee::edge::{ClientBatch, ClientOutput};

/// Floored responses are one per connection, so the hard client ceiling
/// bounds the owner (architecture 28.7).
const MAX_HOLDS: usize = 524_288;

/// One rendered response waiting for its floor, with everything the
/// connection was told afterwards queued behind it so the order it sees is
/// the order the server produced.
struct Hold {
    deadline: MonotonicTick,
    groups: Vec<HeldOutput>,
    _permit: MemoryPermit,
}

enum HeldOutput {
    Frames(Vec<WireMessage>),
    Companion(Box<ClientBatch>),
}

/// Frame groups one connection may queue behind its floored response. A
/// connection's own later commands are deferred, so this bounds only the
/// control and event traffic that continues meanwhile.
pub(crate) const MAX_QUEUED_GROUPS: usize = 64;

/// The floor owner: the configured floor, the current command's start, and
/// the retained responses.
pub(crate) struct SecretFloor {
    millis: u64,
    started: Option<(ConnectionGeneration, MonotonicTick)>,
    holds: BTreeMap<ConnectionGeneration, Hold>,
}

impl SecretFloor {
    /// The owner for a configured floor in milliseconds; zero disables it.
    pub(crate) const fn new(millis: u64) -> Self {
        Self {
            millis,
            started: None,
            holds: BTreeMap::new(),
        }
    }

    /// Records the instant one registered command's processing began.
    pub(crate) fn begin(&mut self, generation: ConnectionGeneration, now: MonotonicTick) {
        self.started = Some((generation, now));
    }

    /// The deadline a response of `generation` must not precede, or `None`
    /// when the floor has already passed (or is not configured).
    fn deadline(
        &self,
        generation: ConnectionGeneration,
        now: MonotonicTick,
    ) -> Option<MonotonicTick> {
        let start = match self.started {
            Some((started, at)) if started == generation => at,
            _ => now,
        };
        let deadline = start.get().checked_add(self.millis)?;
        (self.millis != 0 && deadline > now.get()).then(|| MonotonicTick::from_ticks(deadline))
    }

    /// Whether `generation` still owes a floored response.
    pub(crate) fn pending(&self, generation: ConnectionGeneration) -> bool {
        self.holds.contains_key(&generation)
    }

    /// Retains `frames` until `deadline`, charging their backing.
    fn hold(
        &mut self,
        generation: ConnectionGeneration,
        deadline: MonotonicTick,
        frames: Vec<WireMessage>,
        permit: MemoryPermit,
    ) -> Result<(), ()> {
        // One hold per connection, so the hard client ceiling bounds the
        // owner; the check is structural.
        (self.holds.len() < MAX_HOLDS).then_some(()).ok_or(())?;
        let replaced = self.holds.insert(
            generation,
            Hold {
                deadline,
                groups: vec![HeldOutput::Frames(frames)],
                _permit: permit,
            },
        );
        // One connection owes one response: an existing hold is refused
        // before this point.
        replaced.map_or(Ok(()), |_| Err(()))
    }

    /// Takes the response of `generation`, and everything queued behind
    /// it, once its deadline passed.
    fn take_due(
        &mut self,
        generation: ConnectionGeneration,
        now: MonotonicTick,
    ) -> Option<Vec<HeldOutput>> {
        let due = self
            .holds
            .get(&generation)
            .is_some_and(|hold| hold.deadline <= now);
        due.then(|| self.holds.remove(&generation))
            .flatten()
            .map(|hold| hold.groups)
    }

    fn room(&mut self, generation: ConnectionGeneration) -> Option<&mut Hold> {
        let hold = self.holds.get_mut(&generation)?;
        (hold.groups.len() < MAX_QUEUED_GROUPS && hold.groups.try_reserve(1).is_ok())
            .then_some(hold)
    }

    /// Drops the response of a closed connection and its charge.
    pub(crate) fn discard(&mut self, generation: ConnectionGeneration) {
        let _dropped = self.holds.remove(&generation);
        if self
            .started
            .is_some_and(|(started, _)| started == generation)
        {
            self.started = None;
        }
    }
}

impl super::StateCoreContext {
    /// Records the start of one registered command's processing, from which
    /// its response floor is measured.
    pub(crate) fn begin_secret_floor(&mut self, generation: ConnectionGeneration) {
        let now = self.now();
        self.secret_floor.begin(generation, now);
    }

    /// Whether `generation` still owes a floored response, so its later
    /// commands must wait.
    #[must_use]
    pub(crate) fn secret_floor_pending(&self, generation: ConnectionGeneration) -> bool {
        self.secret_floor.pending(generation)
    }

    /// Retains a concealment response until its floor passes, or reports
    /// that it may go out now. An exhausted budget or timer heap answers
    /// immediately rather than dropping the response.
    pub(crate) fn hold_secret_floor(
        &mut self,
        generation: ConnectionGeneration,
        frames: Vec<WireMessage>,
    ) -> Result<(), Vec<WireMessage>> {
        let now = self.now();
        let held = self
            .secret_floor
            .deadline(generation, now)
            .filter(|_| !self.secret_floor.pending(generation))
            .and_then(|deadline| {
                // Every retained frame is charged its physical line
                // ceiling; publication charges the exact bytes again.
                let bytes = frames.len().checked_mul(MAX_COMMAND_BYTES)?;
                let permit = self.reserve_output_backing(bytes).ok()?;
                self.timers
                    .schedule(
                        deadline,
                        super::timers::TimerKind::SecretChannelFloor,
                        super::timers::TimedId::Connection(generation),
                    )
                    .ok()?;
                Some((deadline, permit))
            });
        let Some((deadline, permit)) = held else {
            return Err(frames);
        };
        self.secret_floor
            .hold(generation, deadline, frames, permit)
            .map_err(|()| Vec::new())
    }

    /// Publishes the floored response of `generation`, and everything
    /// queued behind it, when its deadline has passed; reports whether one
    /// was released.
    pub(crate) fn release_secret_floor(&mut self, generation: ConnectionGeneration) -> bool {
        let now = self.now();
        let Some(groups) = self.secret_floor.take_due(generation, now) else {
            return false;
        };
        for group in groups {
            match group {
                HeldOutput::Frames(frames) => {
                    let _sent = self.send_to(generation, frames);
                }
                HeldOutput::Companion(batch) => self.send_companion_batch_now(generation, batch),
            }
        }
        true
    }

    /// Publishes no part of a later group while this generation owes its
    /// floored response. Reports the normal slow-consumer close on saturation.
    pub(crate) fn queue_behind_secret_floor(
        &mut self,
        generation: ConnectionGeneration,
        frames: Vec<WireMessage>,
    ) -> Result<super::fanout::FanoutCommitReport, Vec<WireMessage>> {
        if !self.secret_floor.pending(generation) {
            return Err(frames);
        }
        Ok(self.retain_behind_floor(generation, HeldOutput::Frames(frames)))
    }

    fn retain_behind_floor(
        &mut self,
        generation: ConnectionGeneration,
        output: HeldOutput,
    ) -> super::fanout::FanoutCommitReport {
        if let Some(hold) = self.secret_floor.room(generation) {
            hold.groups.push(output);
            return super::fanout::FanoutCommitReport::retained();
        }
        // An exhausted hold cannot publish later traffic ahead of earlier
        // groups. Drop every held source and close only this connection.
        self.secret_floor.discard(generation);
        let sink = self.sessions.sink_for_generation(generation);
        self.commit_fanout(super::fanout::FanoutReservation::saturated(
            generation, sink,
        ))
    }

    /// Publishes ordinary replies and single-window bulk batches in the same
    /// order, including behind a pending privacy response floor.
    pub(crate) fn send_companion_output(&mut self, output: ClientOutput) {
        let generation = output.generation;
        let Some(batch) = output.batch else {
            let _sent = self.send_to(generation, output.frames);
            return;
        };
        if self.secret_floor.pending(generation) {
            let _report = self.retain_behind_floor(generation, HeldOutput::Companion(batch));
        } else {
            self.send_companion_batch_now(generation, batch);
        }
    }

    fn send_companion_batch_now(
        &mut self,
        generation: ConnectionGeneration,
        batch: Box<ClientBatch>,
    ) {
        let Some(sink) = self.sessions.sink_for_generation(generation) else {
            return;
        };
        let send = (|| {
            let demand =
                ClientQueueDemand::new(vec![batch.window()]).map_err(|_| SinkReserveError::Full)?;
            let tentative = sink.try_reserve(demand)?;
            let charge = tentative.backing_charge();
            let backing = if charge == 0 {
                None
            } else {
                Some(
                    self.reserve_kept_output(charge)
                        .ok()
                        .and_then(|mut held| held.split_exact(charge))
                        .ok_or(SinkReserveError::Full)?,
                )
            };
            let reservation = sink
                .prepare(tentative, backing)
                .map_err(|error| match error {
                    crate::connection::QueueAllocationError::Closed => SinkReserveError::Closed,
                    _ => SinkReserveError::Full,
                })?;
            sink.commit_companion(reservation, batch)
        })();
        if let Err(refusal) = send {
            if refusal == SinkReserveError::Full {
                sink.begin_slow_consumer_close();
            }
            self.sessions.mark_sink_gone(generation);
        }
    }

    /// Drops the retained response of a closed or replaced connection.
    pub(crate) fn discard_secret_floor(&mut self, generation: ConnectionGeneration) {
        self.secret_floor.discard(generation);
    }
}

#[cfg(test)]
#[path = "tests/secret_floor.rs"]
mod tests;
