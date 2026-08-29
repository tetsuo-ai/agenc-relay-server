#![forbid(unsafe_code)]

//! Deterministic capabilities for tests and conformance harnesses.
//!
//! This crate is test-only. Production crates and the release binary are
//! forbidden from depending on it.

use std::collections::{BTreeMap, VecDeque};
use std::error::Error;
use std::fmt;

use agenc_ircd_types::{
    ClockError, EntropyError, EntropySource, MonotonicClock, MonotonicTick, UtcSecond, WallClock,
};

mod client_transcript;
mod domain_fixture;
mod domain_reference;
mod reference_codec;
mod tls_fixture;

pub use client_transcript::{
    ClientTranscript, ClientTranscriptError, ClientTranscriptHandoff, ClientTranscriptHarness,
    ClientTranscriptMessage, ClientTranscriptOperation, ClientTranscriptStep, TranscriptEncoding,
    parse_client_transcript,
};

pub use domain_fixture::{
    DomainTestIdentity, account_id, apply_command, apply_plan, authorize, bytes, channel_id,
    create_account, deterministic_cloak, generation, message_admission, open_session, plan,
    registered_admission, revision,
};

pub use domain_reference::{
    ALL_REFERENCE_COMMAND_KINDS, ReferenceChannelSnapshot, ReferenceCommand, ReferenceCommandKind,
    ReferenceDomainError, ReferenceDomainModel, ReferenceDomainSnapshot, ReferenceDomainStep,
    ReferenceInviteSnapshot, ReferenceMessageTarget, ReferenceModeChange, ReferenceModeOperation,
    ReferencePrincipal, ReferenceRole, ReferenceSessionSnapshot, ReferenceVisibility,
    ReferenceVisibilityMode,
};

pub use reference_codec::{
    MAX_REFERENCE_VECTOR_BYTES, MAX_REFERENCE_VECTORS, ReferenceCodecError, ReferenceEncoder,
    ReferenceVector, parse_reference_vectors,
};

pub use tls_fixture::{MAX_FIXTURE_DNS_NAME_BYTES, TlsFixture, TlsFixtureError};

/// Maximum bytes accepted by one scripted entropy source.
pub const MAX_SCRIPTED_ENTROPY_BYTES: usize = 1_048_576;

/// Maximum records held by a deterministic fault store.
pub const MAX_FAULT_STORE_RECORDS: usize = 1_000_000;

/// Maximum canonical record bytes held by a deterministic fault store.
pub const MAX_FAULT_STORE_BYTES: u64 = 1_073_741_824;

/// Maximum expected steps in one transcript.
pub const MAX_TRANSCRIPT_STEPS: usize = 16_384;

/// Maximum bytes in one transcript step.
pub const MAX_TRANSCRIPT_STEP_BYTES: usize = 65_536;

/// Errors raised by deterministic clock and entropy capabilities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityError {
    /// Advancing a clock would exceed its representable tick range.
    ClockOverflow,
    /// A scripted source cannot satisfy the complete request.
    EntropyExhausted,
    /// A scripted entropy input exceeds its test-only ceiling.
    EntropyScriptTooLarge,
}

impl fmt::Display for CapabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ClockOverflow => "deterministic clock overflow",
            Self::EntropyExhausted => "scripted entropy exhausted",
            Self::EntropyScriptTooLarge => "scripted entropy exceeds its byte ceiling",
        };
        formatter.write_str(message)
    }
}

impl Error for CapabilityError {}

/// A monotonic test clock advanced explicitly by its owner.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeterministicMonotonicClock {
    ticks: u64,
}

impl DeterministicMonotonicClock {
    /// Creates a clock at an explicit tick.
    #[must_use]
    pub const fn at(ticks: u64) -> Self {
        Self { ticks }
    }

    /// Returns the current monotonic tick.
    #[must_use]
    pub const fn now(&self) -> u64 {
        self.ticks
    }

    /// Advances the clock atomically, leaving it unchanged on overflow.
    pub fn advance(&mut self, ticks: u64) -> Result<u64, CapabilityError> {
        let next = self
            .ticks
            .checked_add(ticks)
            .ok_or(CapabilityError::ClockOverflow)?;
        self.ticks = next;
        Ok(next)
    }
}

impl MonotonicClock for DeterministicMonotonicClock {
    fn now(&self) -> MonotonicTick {
        MonotonicTick::from_ticks(self.ticks)
    }
}

/// A wall clock whose whole-second UTC value is advanced explicitly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeterministicWallClock {
    unix_seconds: u64,
    available: bool,
}

impl DeterministicWallClock {
    /// Creates an available wall clock at an explicit Unix timestamp.
    #[must_use]
    pub const fn at(unix_seconds: u64) -> Self {
        Self {
            unix_seconds,
            available: true,
        }
    }

    /// Creates a clock that deterministically fails UTC reads.
    #[must_use]
    pub const fn unavailable_at(unix_seconds: u64) -> Self {
        Self {
            unix_seconds,
            available: false,
        }
    }

    /// Returns the scripted whole-second Unix timestamp.
    #[must_use]
    pub const fn now(&self) -> u64 {
        self.unix_seconds
    }

    /// Advances wall time atomically, leaving it unchanged on overflow.
    pub fn advance(&mut self, seconds: u64) -> Result<u64, CapabilityError> {
        let next = self
            .unix_seconds
            .checked_add(seconds)
            .ok_or(CapabilityError::ClockOverflow)?;
        self.unix_seconds = next;
        Ok(next)
    }
}

impl Default for DeterministicWallClock {
    fn default() -> Self {
        Self::at(0)
    }
}

impl WallClock for DeterministicWallClock {
    fn utc_now(&self) -> Result<UtcSecond, ClockError> {
        if !self.available {
            return Err(ClockError::Unavailable);
        }
        Ok(UtcSecond::from_unix_seconds(self.unix_seconds))
    }
}

/// A deterministic entropy source backed by explicit fixture bytes.
///
/// This is a byte script, not a pseudorandom-number generator. A failed fill
/// consumes no bytes.
#[derive(Debug, Eq, PartialEq)]
pub struct ScriptedEntropy {
    bytes: VecDeque<u8>,
}

impl ScriptedEntropy {
    /// Creates a bounded byte script.
    pub fn new(bytes: Vec<u8>) -> Result<Self, CapabilityError> {
        if bytes.len() > MAX_SCRIPTED_ENTROPY_BYTES || bytes.capacity() > MAX_SCRIPTED_ENTROPY_BYTES
        {
            return Err(CapabilityError::EntropyScriptTooLarge);
        }
        Ok(Self {
            bytes: VecDeque::from(bytes),
        })
    }

    /// Returns the number of unconsumed bytes.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.bytes.len()
    }

    /// Fills the entire destination or returns without consuming the script.
    pub fn fill_exact(&mut self, destination: &mut [u8]) -> Result<(), CapabilityError> {
        if destination.len() > self.bytes.len() {
            return Err(CapabilityError::EntropyExhausted);
        }

        for slot in destination {
            let Some(byte) = self.bytes.pop_front() else {
                return Err(CapabilityError::EntropyExhausted);
            };
            *slot = byte;
        }
        Ok(())
    }
}

impl EntropySource for ScriptedEntropy {
    fn fill_exact(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        ScriptedEntropy::fill_exact(self, destination).map_err(|_| EntropyError::Unavailable)
    }
}

/// Failure from a pure reference-model transition.
#[derive(Debug, Eq, PartialEq)]
pub enum ReferenceTransitionError<TransitionError> {
    /// The supplied pure transition rejected its input.
    Rejected(TransitionError),
    /// The model revision cannot advance further.
    RevisionExhausted,
}

/// A revisioned harness for independently supplied pure transition functions.
#[derive(Debug, Eq, PartialEq)]
pub struct ReferenceModel<State> {
    state: State,
    revision: u64,
}

impl<State> ReferenceModel<State> {
    /// Creates a reference model at revision zero.
    #[must_use]
    pub const fn new(state: State) -> Self {
        Self { state, revision: 0 }
    }

    /// Creates a model at an explicit revision for boundary tests.
    #[must_use]
    pub const fn at_revision(state: State, revision: u64) -> Self {
        Self { state, revision }
    }

    /// Borrows the current model state.
    #[must_use]
    pub const fn state(&self) -> &State {
        &self.state
    }

    /// Returns the current model revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Applies one pure transition and advances only after it succeeds.
    pub fn apply<Input, Output, TransitionError>(
        &mut self,
        input: Input,
        transition: impl FnOnce(&State, Input) -> Result<(State, Output), TransitionError>,
    ) -> Result<Output, ReferenceTransitionError<TransitionError>> {
        let next_revision = self
            .revision
            .checked_add(1)
            .ok_or(ReferenceTransitionError::RevisionExhausted)?;
        let (next_state, output) =
            transition(&self.state, input).map_err(ReferenceTransitionError::Rejected)?;
        self.state = next_state;
        self.revision = next_revision;
        Ok(output)
    }
}

/// Operations at which a fault store can fail deterministically.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum StoreOperation {
    /// A record lookup.
    Read,
    /// A record insertion or replacement.
    Write,
    /// A record removal.
    Delete,
}

/// Errors returned by a deterministic fault store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultStoreError {
    /// A configured record or byte capacity is zero or above its test ceiling.
    InvalidCapacity,
    /// A configured fault fired at this operation.
    Injected(StoreOperation),
    /// Inserting a new key would exceed the configured record capacity.
    CapacityExhausted,
    /// A record charge or total byte count exceeds its configured bound.
    ByteCapacityExhausted,
}

impl fmt::Display for FaultStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCapacity => formatter.write_str("invalid fault-store capacity"),
            Self::Injected(operation) => write!(formatter, "injected {operation:?} fault"),
            Self::CapacityExhausted => formatter.write_str("fault-store capacity exhausted"),
            Self::ByteCapacityExhausted => {
                formatter.write_str("fault-store byte capacity exhausted")
            }
        }
    }
}

impl Error for FaultStoreError {}

/// A bounded in-memory store with per-operation fault schedules.
#[derive(Debug)]
pub struct FaultStore<Key, Value> {
    records: BTreeMap<Key, FaultRecord<Value>>,
    failures: BTreeMap<StoreOperation, u32>,
    record_capacity: usize,
    byte_capacity: u64,
    stored_bytes: u64,
}

#[derive(Debug)]
struct FaultRecord<Value> {
    value: Value,
    encoded_bytes: u64,
}

impl<Key: Ord, Value> FaultStore<Key, Value> {
    /// Creates an empty store with a finite record capacity.
    pub fn new(record_capacity: usize, byte_capacity: u64) -> Result<Self, FaultStoreError> {
        if record_capacity == 0
            || record_capacity > MAX_FAULT_STORE_RECORDS
            || byte_capacity == 0
            || byte_capacity > MAX_FAULT_STORE_BYTES
        {
            return Err(FaultStoreError::InvalidCapacity);
        }
        Ok(Self {
            records: BTreeMap::new(),
            failures: BTreeMap::new(),
            record_capacity,
            byte_capacity,
            stored_bytes: 0,
        })
    }

    /// Configures the next `count` matching operations to fail.
    pub fn fail_next(&mut self, operation: StoreOperation, count: u32) {
        if count == 0 {
            self.failures.remove(&operation);
            return;
        }
        self.failures.insert(operation, count);
    }

    /// Returns the number of stored records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Reports whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Returns the exact caller-declared canonical bytes currently stored.
    #[must_use]
    pub const fn stored_bytes(&self) -> u64 {
        self.stored_bytes
    }

    /// Reads a record, subject to the configured read fault schedule.
    pub fn get(&mut self, key: &Key) -> Result<Option<&Value>, FaultStoreError> {
        self.maybe_fail(StoreOperation::Read)?;
        Ok(self.records.get(key).map(|record| &record.value))
    }

    /// Inserts or replaces a record, subject to bounds and write faults.
    pub fn insert(
        &mut self,
        key: Key,
        value: Value,
        encoded_bytes: u64,
    ) -> Result<Option<Value>, FaultStoreError> {
        self.maybe_fail(StoreOperation::Write)?;
        if !self.records.contains_key(&key) && self.records.len() == self.record_capacity {
            return Err(FaultStoreError::CapacityExhausted);
        }
        let prior_bytes = self
            .records
            .get(&key)
            .map_or(0, |record| record.encoded_bytes);
        let without_prior = self
            .stored_bytes
            .checked_sub(prior_bytes)
            .ok_or(FaultStoreError::ByteCapacityExhausted)?;
        let next_bytes = without_prior
            .checked_add(encoded_bytes)
            .ok_or(FaultStoreError::ByteCapacityExhausted)?;
        if next_bytes > self.byte_capacity {
            return Err(FaultStoreError::ByteCapacityExhausted);
        }
        let previous = self.records.insert(
            key,
            FaultRecord {
                value,
                encoded_bytes,
            },
        );
        self.stored_bytes = next_bytes;
        Ok(previous.map(|record| record.value))
    }

    /// Removes a record, subject to the configured delete fault schedule.
    pub fn remove(&mut self, key: &Key) -> Result<Option<Value>, FaultStoreError> {
        self.maybe_fail(StoreOperation::Delete)?;
        let removed = self.records.remove(key);
        if let Some(record) = removed {
            self.stored_bytes = self
                .stored_bytes
                .checked_sub(record.encoded_bytes)
                .ok_or(FaultStoreError::ByteCapacityExhausted)?;
            return Ok(Some(record.value));
        }
        Ok(None)
    }

    fn maybe_fail(&mut self, operation: StoreOperation) -> Result<(), FaultStoreError> {
        let Some(remaining) = self.failures.get_mut(&operation) else {
            return Ok(());
        };
        *remaining -= 1;
        if *remaining == 0 {
            self.failures.remove(&operation);
        }
        Err(FaultStoreError::Injected(operation))
    }
}

/// The origin of one transcript step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TranscriptActor {
    /// A client endpoint.
    Client,
    /// The daemon under test.
    Server,
    /// A federation edge.
    Edge,
    /// The federation coordinator.
    Coordinator,
    /// An administrative endpoint.
    Administrator,
}

/// One bounded expected transcript step.
#[derive(Debug, Eq, PartialEq)]
pub struct TranscriptStep {
    actor: TranscriptActor,
    bytes: Vec<u8>,
}

impl TranscriptStep {
    /// Creates a bounded transcript step.
    pub fn new(actor: TranscriptActor, bytes: Vec<u8>) -> Result<Self, TranscriptError> {
        if bytes.len() > MAX_TRANSCRIPT_STEP_BYTES {
            return Err(TranscriptError::StepTooLarge);
        }
        if bytes.capacity() > MAX_TRANSCRIPT_STEP_BYTES {
            return Err(TranscriptError::StepCapacityTooLarge);
        }
        Ok(Self { actor, bytes })
    }
}

/// Errors raised while constructing or replaying a transcript.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TranscriptError {
    /// The expected-step count reached its fixed ceiling.
    TooManySteps,
    /// One step exceeds its fixed byte ceiling.
    StepTooLarge,
    /// One owned step hides spare allocation beyond its fixed byte ceiling.
    StepCapacityTooLarge,
    /// A bounded transcript queue allocation failed.
    AllocationFailed,
    /// An observation arrived after all expected steps were consumed.
    UnexpectedStep,
    /// An observation differs from the next expected actor or bytes.
    Mismatch {
        /// Zero-based index of the rejected observation.
        index: usize,
    },
    /// Replay ended before every expected step was consumed.
    Incomplete {
        /// Number of expected steps that were not observed.
        remaining: usize,
    },
}

impl fmt::Display for TranscriptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManySteps => formatter.write_str("transcript step ceiling reached"),
            Self::StepTooLarge => formatter.write_str("transcript step exceeds its byte ceiling"),
            Self::StepCapacityTooLarge => {
                formatter.write_str("transcript step backing capacity exceeds its byte ceiling")
            }
            Self::AllocationFailed => formatter.write_str("transcript queue allocation failed"),
            Self::UnexpectedStep => formatter.write_str("unexpected transcript step"),
            Self::Mismatch { index } => write!(formatter, "transcript mismatch at step {index}"),
            Self::Incomplete { remaining } => {
                write!(formatter, "transcript has {remaining} unconsumed steps")
            }
        }
    }
}

impl Error for TranscriptError {}

/// A bounded, deterministic transcript comparison driver.
#[derive(Debug, Default)]
pub struct TranscriptDriver {
    expected: VecDeque<TranscriptStep>,
    observed: usize,
    scheduled: usize,
    observation_attempts: usize,
}

impl TranscriptDriver {
    /// Creates an empty transcript driver.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            expected: VecDeque::new(),
            observed: 0,
            scheduled: 0,
            observation_attempts: 0,
        }
    }

    /// Appends one already-bounded expected step.
    pub fn push_expected(&mut self, step: TranscriptStep) -> Result<(), TranscriptError> {
        if self.scheduled == MAX_TRANSCRIPT_STEPS {
            return Err(TranscriptError::TooManySteps);
        }
        self.expected
            .try_reserve(1)
            .map_err(|_| TranscriptError::AllocationFailed)?;
        self.expected.push_back(step);
        self.scheduled += 1;
        Ok(())
    }

    /// Compares one observed step and consumes the expectation only on match.
    pub fn observe(&mut self, actor: TranscriptActor, bytes: &[u8]) -> Result<(), TranscriptError> {
        if bytes.len() > MAX_TRANSCRIPT_STEP_BYTES {
            return Err(TranscriptError::StepTooLarge);
        }
        if self.observation_attempts == MAX_TRANSCRIPT_STEPS {
            return Err(TranscriptError::TooManySteps);
        }
        self.observation_attempts += 1;
        let Some(expected) = self.expected.front() else {
            return Err(TranscriptError::UnexpectedStep);
        };
        if expected.actor != actor || expected.bytes != bytes {
            return Err(TranscriptError::Mismatch {
                index: self.observed,
            });
        }
        self.expected.pop_front();
        self.observed += 1;
        Ok(())
    }

    /// Succeeds only when every expected step was observed.
    pub fn finish(self) -> Result<(), TranscriptError> {
        if self.expected.is_empty() {
            return Ok(());
        }
        Err(TranscriptError::Incomplete {
            remaining: self.expected.len(),
        })
    }
}
