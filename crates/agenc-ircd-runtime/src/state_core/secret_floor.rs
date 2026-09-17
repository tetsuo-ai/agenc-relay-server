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

use agenc_ircd_client_wire::{MAX_COMMAND_BYTES, WireMessage};
use agenc_ircd_types::MonotonicTick;

use crate::budget::MemoryPermit;
use crate::connection::sink::ConnectionGeneration;

/// Floored responses are one per connection, so the hard client ceiling
/// bounds the owner (architecture 28.7).
const MAX_HOLDS: usize = 524_288;

/// One rendered response waiting for its floor, with everything the
/// connection was told afterwards queued behind it so the order it sees is
/// the order the server produced.
struct Hold {
    deadline: MonotonicTick,
    groups: Vec<Vec<WireMessage>>,
    _permit: MemoryPermit,
}

/// Frame groups one connection may queue behind its floored response. A
/// connection's own later commands are deferred, so this bounds only the
/// control and event traffic that continues meanwhile.
const MAX_QUEUED_GROUPS: usize = 64;

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
                groups: vec![frames],
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
    ) -> Option<Vec<Vec<WireMessage>>> {
        let due = self
            .holds
            .get(&generation)
            .is_some_and(|hold| hold.deadline <= now);
        due.then(|| self.holds.remove(&generation))
            .flatten()
            .map(|hold| hold.groups)
    }

    /// Queues one later frame group behind a floored response; reports
    /// whether it was retained rather than published now.
    fn queue_behind(
        &mut self,
        generation: ConnectionGeneration,
        frames: Vec<WireMessage>,
    ) -> Result<(), Vec<WireMessage>> {
        let Some(hold) = self.holds.get_mut(&generation) else {
            return Err(frames);
        };
        if hold.groups.len() >= MAX_QUEUED_GROUPS || hold.groups.try_reserve(1).is_err() {
            return Err(frames);
        }
        hold.groups.push(frames);
        Ok(())
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
        for frames in groups {
            let _sent = self.send_to(generation, frames);
        }
        true
    }

    /// Retains one later frame group behind a floored response so the
    /// connection sees the two in the order the server produced them.
    pub(crate) fn queue_behind_secret_floor(
        &mut self,
        generation: ConnectionGeneration,
        frames: Vec<WireMessage>,
    ) -> Result<(), Vec<WireMessage>> {
        self.secret_floor.queue_behind(generation, frames)
    }

    /// Drops the retained response of a closed or replaced connection.
    pub(crate) fn discard_secret_floor(&mut self, generation: ConnectionGeneration) {
        self.secret_floor.discard(generation);
    }
}

#[cfg(test)]
#[path = "tests/secret_floor.rs"]
mod tests;
