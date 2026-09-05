//! The per-conversation sequencer log (companion 12.1, 12.2, 12.4, 13.8):
//! one active candidate per epoch, contiguous route sequences with exact
//! predecessor identifiers, candidate-sequence reset and increment rules,
//! bounded attempts per epoch, ReInit attempt slots, and the terminal
//! transitions that advance the accepted state.
//!
//! The log records positions and identifiers only. Signature checks, quorum
//! counting, and object validation happen in the e2ee crate before a
//! transition is offered here.

use std::fmt;

use super::limits::MAX_CANDIDATE_ATTEMPTS_PER_EPOCH;

/// A 32-byte semantic identifier.
pub type Id = [u8; 32];

/// Why a log transition was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogError {
    /// The epoch already has an unfinalized candidate.
    CandidateActive,
    /// No candidate is active for the named identifier.
    NoSuchCandidate,
    /// The prior epoch or prior state does not match the accepted state.
    EpochStale,
    /// The epoch consumed every permitted attempt.
    AttemptsExhausted,
    /// The log is closed to the requested record class.
    Closed,
    /// A ReInit operation was offered outside a ReInit phase.
    NotReinit,
    /// Arithmetic overflow.
    Overflow,
}

impl fmt::Display for LogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::CandidateActive => "the epoch already has an unfinalized candidate",
            Self::NoSuchCandidate => "no active candidate matches",
            Self::EpochStale => "the prior epoch or state is stale",
            Self::AttemptsExhausted => "the epoch attempt budget is exhausted",
            Self::Closed => "the log is closed to that record",
            Self::NotReinit => "the log is not in a reinit phase",
            Self::Overflow => "sequence arithmetic overflowed",
        };
        formatter.write_str(text)
    }
}

impl std::error::Error for LogError {}

/// The current head of the log.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Head {
    /// Route sequence of the head record; zero names the external anchor.
    pub sequence: u64,
    /// Semantic identifier of the head record or anchor.
    pub record_id: Id,
    /// Whether a real record occupies the head (false at the anchor).
    pub recorded: bool,
}

/// The fields a candidate receipt must carry for the next position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidatePosition {
    /// Route sequence.
    pub route_sequence: u64,
    /// Prior epoch.
    pub prior_epoch: u64,
    /// Prior state identifier.
    pub prior_state_id: Id,
    /// Candidate sequence within the epoch.
    pub candidate_sequence: u32,
    /// Predecessor record identifier.
    pub predecessor_record_id: Id,
}

/// The active candidate slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidateSlot {
    /// Candidate identifier.
    pub candidate_id: Id,
    /// The position it occupies.
    pub position: CandidatePosition,
    /// The Commit object identifier.
    pub commit_object_id: Id,
}

/// The fields a terminal wrapper must carry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalPosition {
    /// Route sequence: the candidate's plus one.
    pub route_sequence: u64,
    /// Predecessor: the candidate identifier.
    pub predecessor_record_id: Id,
}

/// The active ReInit attempt slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttemptSlot {
    /// ReInit attempt identifier.
    pub attempt_id: Id,
    /// Route sequence of the receipt.
    pub route_sequence: u64,
    /// Attempt sequence.
    pub attempt_sequence: u32,
    /// Predecessor record identifier.
    pub predecessor_record_id: Id,
}

/// The phase of the log.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Ordinary epochs.
    Open,
    /// The old group is closed by a finalized ReInit; attempts proceed.
    Reinit {
        /// The finalization identifier of the ReInit Commit.
        old_reinit_state_id: Id,
    },
    /// Activated into a successor conversation.
    Migrated {
        /// The activation identifier.
        activation_id: Id,
        /// The successor conversation.
        new_conversation_id: Id,
    },
    /// Closed by an authorized close.
    Closed {
        /// The close identifier.
        close_id: Id,
    },
}

/// The log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SequencerLog {
    conversation_id: Id,
    head: Head,
    accepted_state_id: Id,
    accepted_epoch: u64,
    candidate: Option<CandidateSlot>,
    next_candidate_sequence: u32,
    next_predecessor: Id,
    attempts: u32,
    reinit_attempt: Option<AttemptSlot>,
    next_attempt_sequence: u32,
    phase: Phase,
}

impl SequencerLog {
    /// Whether one Commit candidate is open for the accepted epoch.
    #[must_use]
    pub fn has_candidate(&self) -> bool {
        self.candidate.is_some()
    }

    /// A log anchored at the genesis state of a new conversation.
    #[must_use]
    pub fn genesis(conversation_id: Id, genesis_state_id: Id) -> Self {
        Self::anchored(conversation_id, genesis_state_id, 0)
    }

    /// A log anchored at a ReInit activation, at epoch one.
    #[must_use]
    pub fn from_activation(conversation_id: Id, activation_id: Id) -> Self {
        Self::anchored(conversation_id, activation_id, 1)
    }

    fn anchored(conversation_id: Id, anchor: Id, epoch: u64) -> Self {
        Self {
            conversation_id,
            head: Head {
                sequence: 0,
                record_id: anchor,
                recorded: false,
            },
            accepted_state_id: anchor,
            accepted_epoch: epoch,
            candidate: None,
            next_candidate_sequence: 0,
            next_predecessor: anchor,
            attempts: 0,
            reinit_attempt: None,
            next_attempt_sequence: 0,
            phase: Phase::Open,
        }
    }

    /// Restores a log from durable fields.
    #[must_use]
    pub fn restore(
        conversation_id: Id,
        head: Head,
        accepted_state_id: Id,
        accepted_epoch: u64,
        phase: Phase,
    ) -> Self {
        Self {
            conversation_id,
            head,
            accepted_state_id,
            accepted_epoch,
            candidate: None,
            next_candidate_sequence: 0,
            next_predecessor: accepted_state_id,
            attempts: 0,
            reinit_attempt: None,
            next_attempt_sequence: 0,
            phase,
        }
    }

    /// Restores the epoch position of a reloaded log: the active candidate,
    /// if the head record is one, and the attempts the epoch consumed. With
    /// no active candidate the next candidate follows the head record.
    pub fn restore_epoch(&mut self, candidate: Option<CandidateSlot>, attempts: u32) {
        self.attempts = attempts;
        match candidate {
            Some(slot) => {
                self.next_candidate_sequence = slot.position.candidate_sequence;
                self.candidate = Some(slot);
            }
            None if attempts > 0 => {
                self.next_candidate_sequence = attempts;
                self.next_predecessor = self.head.record_id;
            }
            None => {}
        }
    }

    /// Restores the attempt position of a log whose durable phase is
    /// [`Phase::Reinit`]. An active receipt keeps its original predecessor;
    /// after an abort the next attempt follows the terminal head.
    pub fn restore_reinit(
        &mut self,
        attempt: Option<AttemptSlot>,
        next_attempt_sequence: u32,
    ) -> Result<(), LogError> {
        let Phase::Reinit {
            old_reinit_state_id,
        } = self.phase
        else {
            return Err(LogError::NotReinit);
        };
        if self.candidate.is_some() || old_reinit_state_id != self.accepted_state_id {
            return Err(LogError::EpochStale);
        }
        if next_attempt_sequence > MAX_CANDIDATE_ATTEMPTS_PER_EPOCH {
            return Err(LogError::AttemptsExhausted);
        }
        if let Some(slot) = attempt {
            if !self.head.recorded
                || slot.attempt_id != self.head.record_id
                || slot.route_sequence != self.head.sequence
                || slot.attempt_sequence != next_attempt_sequence
            {
                return Err(LogError::EpochStale);
            }
            if next_attempt_sequence == MAX_CANDIDATE_ATTEMPTS_PER_EPOCH {
                return Err(LogError::AttemptsExhausted);
            }
        }
        self.reinit_attempt = attempt;
        self.next_attempt_sequence = next_attempt_sequence;
        self.next_predecessor =
            attempt.map_or(self.head.record_id, |slot| slot.predecessor_record_id);
        Ok(())
    }

    /// Conversation identifier.
    #[must_use]
    pub const fn conversation_id(&self) -> &Id {
        &self.conversation_id
    }

    /// The head.
    #[must_use]
    pub const fn head(&self) -> Head {
        self.head
    }

    /// The accepted state identifier.
    #[must_use]
    pub const fn accepted_state_id(&self) -> &Id {
        &self.accepted_state_id
    }

    /// The accepted epoch.
    #[must_use]
    pub const fn accepted_epoch(&self) -> u64 {
        self.accepted_epoch
    }

    /// The active candidate, if any.
    #[must_use]
    pub const fn candidate(&self) -> Option<&CandidateSlot> {
        self.candidate.as_ref()
    }

    /// The active ReInit attempt, if any.
    #[must_use]
    pub const fn reinit_attempt(&self) -> Option<&AttemptSlot> {
        self.reinit_attempt.as_ref()
    }

    /// The phase.
    #[must_use]
    pub const fn phase(&self) -> Phase {
        self.phase
    }

    /// Whether the log accepts application traffic.
    #[must_use]
    pub const fn accepts_application(&self) -> bool {
        matches!(self.phase, Phase::Open)
    }

    fn next_sequence(&self) -> Result<u64, LogError> {
        if !self.head.recorded {
            return Ok(0);
        }
        self.head.sequence.checked_add(1).ok_or(LogError::Overflow)
    }

    /// The position the next candidate must occupy; the caller signs the
    /// receipt and then calls [`Self::record_candidate`].
    pub fn candidate_position(&self, prior_epoch: u64) -> Result<CandidatePosition, LogError> {
        if !matches!(self.phase, Phase::Open) {
            return Err(LogError::Closed);
        }
        if self.candidate.is_some() {
            return Err(LogError::CandidateActive);
        }
        if prior_epoch != self.accepted_epoch {
            return Err(LogError::EpochStale);
        }
        if self.attempts >= MAX_CANDIDATE_ATTEMPTS_PER_EPOCH {
            return Err(LogError::AttemptsExhausted);
        }
        Ok(CandidatePosition {
            route_sequence: self.next_sequence()?,
            prior_epoch,
            prior_state_id: self.accepted_state_id,
            candidate_sequence: self.next_candidate_sequence,
            predecessor_record_id: self.next_predecessor,
        })
    }

    /// Records a signed candidate at the position returned by
    /// [`Self::candidate_position`]; the head advances to it.
    pub fn record_candidate(
        &mut self,
        candidate_id: Id,
        commit_object_id: Id,
        position: CandidatePosition,
    ) -> Result<(), LogError> {
        let expected = self.candidate_position(position.prior_epoch)?;
        if expected != position {
            return Err(LogError::EpochStale);
        }
        self.candidate = Some(CandidateSlot {
            candidate_id,
            position,
            commit_object_id,
        });
        self.attempts = self.attempts.saturating_add(1);
        self.head = Head {
            sequence: position.route_sequence,
            record_id: candidate_id,
            recorded: true,
        };
        Ok(())
    }

    /// The position a finalization or abort of `candidate_id` must occupy.
    pub fn terminal_position(&self, candidate_id: &Id) -> Result<TerminalPosition, LogError> {
        let slot = self.candidate.ok_or(LogError::NoSuchCandidate)?;
        if slot.candidate_id != *candidate_id {
            return Err(LogError::NoSuchCandidate);
        }
        Ok(TerminalPosition {
            route_sequence: slot
                .position
                .route_sequence
                .checked_add(1)
                .ok_or(LogError::Overflow)?,
            predecessor_record_id: slot.candidate_id,
        })
    }

    /// Finalizes the active candidate: the finalization becomes the accepted
    /// state, the epoch advances, and the candidate sequence resets.
    pub fn finalize(
        &mut self,
        candidate_id: &Id,
        finalization_id: Id,
        resulting_epoch: u64,
    ) -> Result<TerminalPosition, LogError> {
        let position = self.terminal_position(candidate_id)?;
        if resulting_epoch
            != self
                .accepted_epoch
                .checked_add(1)
                .ok_or(LogError::Overflow)?
        {
            return Err(LogError::EpochStale);
        }
        self.head = Head {
            sequence: position.route_sequence,
            record_id: finalization_id,
            recorded: true,
        };
        self.accepted_state_id = finalization_id;
        self.accepted_epoch = resulting_epoch;
        self.candidate = None;
        self.next_candidate_sequence = 0;
        self.next_predecessor = finalization_id;
        self.attempts = 0;
        Ok(position)
    }

    /// Aborts the active candidate: the next candidate increments the
    /// candidate sequence and names the abort as predecessor.
    pub fn abort(&mut self, candidate_id: &Id, abort_id: Id) -> Result<TerminalPosition, LogError> {
        let position = self.terminal_position(candidate_id)?;
        let slot = self.candidate.ok_or(LogError::NoSuchCandidate)?;
        self.head = Head {
            sequence: position.route_sequence,
            record_id: abort_id,
            recorded: true,
        };
        self.candidate = None;
        self.next_candidate_sequence = slot
            .position
            .candidate_sequence
            .checked_add(1)
            .ok_or(LogError::Overflow)?;
        self.next_predecessor = abort_id;
        Ok(position)
    }

    /// Whether `terminal_id` is the head record, so that a grown proof
    /// snapshot may replace the retained one without a new record.
    #[must_use]
    pub fn proof_snapshot_allowed(&self, terminal_id: &Id) -> bool {
        self.head.recorded && self.head.record_id == *terminal_id && self.candidate.is_none()
    }

    /// Closes the old group after a finalized ReInit Commit whose
    /// finalization identifier is `old_reinit_state_id`.
    pub fn enter_reinit(&mut self, old_reinit_state_id: Id) -> Result<(), LogError> {
        if !matches!(self.phase, Phase::Open) || self.candidate.is_some() {
            return Err(LogError::Closed);
        }
        if self.accepted_state_id != old_reinit_state_id {
            return Err(LogError::EpochStale);
        }
        self.phase = Phase::Reinit {
            old_reinit_state_id,
        };
        self.next_attempt_sequence = 0;
        self.next_predecessor = old_reinit_state_id;
        Ok(())
    }

    /// The position the next ReInit attempt receipt must occupy.
    pub fn attempt_position(&self) -> Result<AttemptSlot, LogError> {
        if !matches!(self.phase, Phase::Reinit { .. }) {
            return Err(LogError::NotReinit);
        }
        if self.reinit_attempt.is_some() {
            return Err(LogError::CandidateActive);
        }
        if self.next_attempt_sequence >= MAX_CANDIDATE_ATTEMPTS_PER_EPOCH {
            return Err(LogError::AttemptsExhausted);
        }
        Ok(AttemptSlot {
            attempt_id: [0; 32],
            route_sequence: self.next_sequence()?,
            attempt_sequence: self.next_attempt_sequence,
            predecessor_record_id: self.next_predecessor,
        })
    }

    /// Records a signed attempt receipt.
    pub fn record_attempt(&mut self, attempt_id: Id) -> Result<AttemptSlot, LogError> {
        let slot = AttemptSlot {
            attempt_id,
            ..self.attempt_position()?
        };
        self.reinit_attempt = Some(slot);
        self.head = Head {
            sequence: slot.route_sequence,
            record_id: attempt_id,
            recorded: true,
        };
        Ok(slot)
    }

    /// The position an activation or attempt abort must occupy.
    pub fn attempt_terminal_position(&self, attempt_id: &Id) -> Result<TerminalPosition, LogError> {
        let slot = self.reinit_attempt.ok_or(LogError::NoSuchCandidate)?;
        if slot.attempt_id != *attempt_id {
            return Err(LogError::NoSuchCandidate);
        }
        Ok(TerminalPosition {
            route_sequence: slot
                .route_sequence
                .checked_add(1)
                .ok_or(LogError::Overflow)?,
            predecessor_record_id: slot.attempt_id,
        })
    }

    /// Activates the attempt: this log migrates and the caller creates the
    /// successor log with [`Self::from_activation`].
    pub fn activate(
        &mut self,
        attempt_id: &Id,
        activation_id: Id,
        new_conversation_id: Id,
    ) -> Result<TerminalPosition, LogError> {
        let position = self.attempt_terminal_position(attempt_id)?;
        self.head = Head {
            sequence: position.route_sequence,
            record_id: activation_id,
            recorded: true,
        };
        self.reinit_attempt = None;
        self.phase = Phase::Migrated {
            activation_id,
            new_conversation_id,
        };
        Ok(position)
    }

    /// Aborts the attempt; the next attempt increments its sequence and
    /// names the abort as predecessor.
    pub fn abort_attempt(
        &mut self,
        attempt_id: &Id,
        abort_id: Id,
    ) -> Result<TerminalPosition, LogError> {
        let position = self.attempt_terminal_position(attempt_id)?;
        let slot = self.reinit_attempt.ok_or(LogError::NoSuchCandidate)?;
        self.head = Head {
            sequence: position.route_sequence,
            record_id: abort_id,
            recorded: true,
        };
        self.reinit_attempt = None;
        self.next_attempt_sequence = slot
            .attempt_sequence
            .checked_add(1)
            .ok_or(LogError::Overflow)?;
        self.next_predecessor = abort_id;
        Ok(position)
    }

    /// Closes the conversation after an authorized close; the close is the
    /// last record.
    pub fn close(&mut self, close_id: Id) -> Result<TerminalPosition, LogError> {
        if !matches!(self.phase, Phase::Open) || self.candidate.is_some() {
            return Err(LogError::Closed);
        }
        let route_sequence = self.next_sequence()?;
        let predecessor_record_id = self.head.record_id;
        self.head = Head {
            sequence: route_sequence,
            record_id: close_id,
            recorded: true,
        };
        self.phase = Phase::Closed { close_id };
        Ok(TerminalPosition {
            route_sequence,
            predecessor_record_id,
        })
    }

    /// Checks that a fetched or federated record claims a legal position:
    /// contiguous with the head and naming it as predecessor.
    pub fn check_incoming_position(
        &self,
        route_sequence: u64,
        predecessor_record_id: &Id,
    ) -> Result<(), LogError> {
        if route_sequence != self.next_sequence()? || *predecessor_record_id != self.head.record_id
        {
            return Err(LogError::EpochStale);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/sequencer_log.rs"]
mod tests;
