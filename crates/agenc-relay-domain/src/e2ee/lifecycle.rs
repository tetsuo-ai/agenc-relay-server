//! Server-visible group lifecycle (companion 13.2 to 13.8, 13.7.1, 18.4):
//! bootstrap and pending-join bookkeeping, join confirmation deadlines,
//! pending removals, the recovery gate transitions, and the close
//! tombstone. The daemon consults these before accepting each carrier.

use std::fmt;

use super::limits::JOIN_CONFIRMATION_TIMEOUT_SECONDS;
use super::sequencer_log::{Phase, SequencerLog};

/// A 32-byte identifier.
pub type Id = [u8; 32];

/// The server-side recovery gate state (13.7.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryGate {
    /// An ordinary live route.
    Normal,
    /// Restored under a new recovery epoch; mutation is refused.
    Pending,
    /// Two valid successors were proven for one position.
    Conflict,
    /// A continuous chain to a finalized close was installed.
    Closed,
}

/// Why a lifecycle transition was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleError {
    /// The recovery gate refuses mutation.
    RecoveryPending,
    /// The recovery gate transition is not permitted.
    GateTransition,
    /// A pending join already exists.
    JoinPending,
    /// No pending join matches.
    NoPendingJoin,
    /// The conversation is closed or migrated.
    Closed,
    /// A required removal is pending.
    RemovalPending,
    /// The bootstrap has not completed.
    BootstrapPending,
    /// Arithmetic overflow.
    Overflow,
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::RecoveryPending => "the recovery gate refuses mutation",
            Self::GateTransition => "the recovery gate transition is not permitted",
            Self::JoinPending => "a join is already pending",
            Self::NoPendingJoin => "no pending join matches",
            Self::Closed => "the conversation is closed",
            Self::RemovalPending => "a removal is pending",
            Self::BootstrapPending => "the bootstrap has not completed",
            Self::Overflow => "counter overflow",
        };
        formatter.write_str(text)
    }
}

impl std::error::Error for LifecycleError {}

/// A pending join awaiting its confirmation Commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingJoin {
    /// The added leaf index.
    pub leaf_index: u32,
    /// The consumed KeyPackage reference.
    pub key_package_ref: Vec<u8>,
    /// The finalization that added the leaf.
    pub finalization_id: Id,
    /// The confirmation deadline.
    pub deadline: u64,
}

/// The lifecycle of one conversation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lifecycle {
    gate: RecoveryGate,
    bootstrap_pending: bool,
    pending_join: Option<PendingJoin>,
    removal_pending: bool,
}

impl Lifecycle {
    /// A fresh generation-zero conversation with its bootstrap pending.
    #[must_use]
    pub const fn bootstrap() -> Self {
        Self {
            gate: RecoveryGate::Normal,
            bootstrap_pending: true,
            pending_join: None,
            removal_pending: false,
        }
    }

    /// A ReInit successor: activation is its barrier, no bootstrap.
    #[must_use]
    pub const fn successor() -> Self {
        Self {
            gate: RecoveryGate::Normal,
            bootstrap_pending: false,
            pending_join: None,
            removal_pending: false,
        }
    }

    /// Restores a lifecycle from durable fields.
    #[must_use]
    pub const fn restore(
        gate: RecoveryGate,
        bootstrap_pending: bool,
        removal_pending: bool,
    ) -> Self {
        Self {
            gate,
            bootstrap_pending,
            pending_join: None,
            removal_pending,
        }
    }

    /// The recovery gate.
    #[must_use]
    pub const fn gate(&self) -> RecoveryGate {
        self.gate
    }

    /// Whether the bootstrap is pending.
    #[must_use]
    pub const fn bootstrap_pending(&self) -> bool {
        self.bootstrap_pending
    }

    /// The pending join.
    #[must_use]
    pub const fn pending_join(&self) -> Option<&PendingJoin> {
        self.pending_join.as_ref()
    }

    /// Whether a removal is pending.
    #[must_use]
    pub const fn removal_pending(&self) -> bool {
        self.removal_pending
    }

    fn check_mutable(&self) -> Result<(), LifecycleError> {
        match self.gate {
            RecoveryGate::Normal => Ok(()),
            RecoveryGate::Pending | RecoveryGate::Conflict | RecoveryGate::Closed => {
                Err(LifecycleError::RecoveryPending)
            }
        }
    }

    /// Whether application ciphertext may be accepted now.
    pub fn check_application(&self, log: &SequencerLog) -> Result<(), LifecycleError> {
        self.check_mutable()?;
        if !log.accepts_application() {
            return Err(LifecycleError::Closed);
        }
        if self.bootstrap_pending {
            return Err(LifecycleError::BootstrapPending);
        }
        if self.removal_pending {
            return Err(LifecycleError::RemovalPending);
        }
        Ok(())
    }

    /// Whether a new Commit candidate may be sequenced now.
    pub fn check_candidate(&self, log: &SequencerLog) -> Result<(), LifecycleError> {
        self.check_mutable()?;
        if !matches!(log.phase(), Phase::Open) {
            return Err(LifecycleError::Closed);
        }
        Ok(())
    }

    /// Whether a security-state mutation (route, policy, roster, close) may
    /// proceed now.
    pub fn check_security_mutation(&self) -> Result<(), LifecycleError> {
        self.check_mutable()
    }

    /// Records the finalized Add of a leaf whose join must be confirmed.
    pub fn add_finalized(
        &mut self,
        leaf_index: u32,
        key_package_ref: Vec<u8>,
        finalization_id: Id,
        now: u64,
    ) -> Result<(), LifecycleError> {
        self.check_mutable()?;
        if self.pending_join.is_some() {
            return Err(LifecycleError::JoinPending);
        }
        self.pending_join = Some(PendingJoin {
            leaf_index,
            key_package_ref,
            finalization_id,
            deadline: now
                .checked_add(JOIN_CONFIRMATION_TIMEOUT_SECONDS)
                .ok_or(LifecycleError::Overflow)?,
        });
        Ok(())
    }

    /// Clears the pending join after its confirmation Commit finalized.
    pub fn join_confirmed(&mut self, leaf_index: u32) -> Result<PendingJoin, LifecycleError> {
        match self.pending_join.take() {
            Some(join) if join.leaf_index == leaf_index => Ok(join),
            Some(join) => {
                self.pending_join = Some(join);
                Err(LifecycleError::NoPendingJoin)
            }
            None => Err(LifecycleError::NoPendingJoin),
        }
    }

    /// Whether the pending join missed its deadline, so that only a
    /// quorum-finalized removal of that leaf is permitted.
    #[must_use]
    pub fn join_overdue(&self, now: u64) -> bool {
        self.pending_join
            .as_ref()
            .is_some_and(|join| now >= join.deadline)
    }

    /// Removes the overdue pending leaf after its finalized removal.
    pub fn pending_leaf_removed(&mut self, leaf_index: u32) -> Result<(), LifecycleError> {
        self.join_confirmed(leaf_index).map(|_| ())
    }

    /// Completes the bootstrap activation.
    pub fn bootstrap_activated(&mut self) -> Result<(), LifecycleError> {
        self.check_mutable()?;
        if !self.bootstrap_pending {
            return Err(LifecycleError::GateTransition);
        }
        if self.pending_join.is_some() {
            return Err(LifecycleError::JoinPending);
        }
        self.bootstrap_pending = false;
        Ok(())
    }

    /// Marks a removal pending; application sending pauses.
    pub fn removal_requested(&mut self) -> Result<(), LifecycleError> {
        self.check_mutable()?;
        self.removal_pending = true;
        Ok(())
    }

    /// Clears the pending removal after its Commit finalized.
    pub fn removal_finalized(&mut self) {
        self.removal_pending = false;
    }

    /// Enters the restored state under a new recovery epoch.
    pub fn restore_pending(&mut self) -> Result<(), LifecycleError> {
        if self.gate != RecoveryGate::Normal {
            return Err(LifecycleError::GateTransition);
        }
        self.gate = RecoveryGate::Pending;
        Ok(())
    }

    /// Resolves a pending gate: only closed or conflict are reachable, and
    /// neither returns to normal.
    pub fn resolve_recovery(&mut self, to: RecoveryGate) -> Result<(), LifecycleError> {
        let permitted = self.gate == RecoveryGate::Pending
            && matches!(to, RecoveryGate::Closed | RecoveryGate::Conflict);
        if !permitted {
            return Err(LifecycleError::GateTransition);
        }
        self.gate = to;
        Ok(())
    }

    /// Whether the route is a tombstone for plaintext purposes.
    #[must_use]
    pub fn is_tombstone(&self, log: &SequencerLog) -> bool {
        matches!(
            log.phase(),
            Phase::Closed { .. } | Phase::Migrated { .. } | Phase::Retired
        ) || matches!(self.gate, RecoveryGate::Closed | RecoveryGate::Conflict)
    }
}

#[cfg(test)]
#[path = "tests/lifecycle.rs"]
mod tests;
