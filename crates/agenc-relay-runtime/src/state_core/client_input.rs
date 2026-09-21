//! Independently bounded reader queues with one round-robin ready entry per connection.
//!
//! An idle connection's queue owns no backing allocation: one message waits
//! in the queue state itself, which the client connection base charge
//! covers. Only a second outstanding message brings charged overflow
//! storage, acquired from the memory budget before it is allocated, grown by
//! replacement to the per-connection request maximum and released with its
//! allocation once the overflow drains (spec 19.2).

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::fmt;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

use super::inbox::{MAX_REQUESTS_PER_CONNECTION, StateCoreMessage};
use super::session::MAX_TRACKED_CONNECTIONS;
use crate::RuntimeError;
use crate::budget::{
    ALLOCATION_BOOKKEEPING_BYTES, BackingReservationPort, MEMORY_QUANTUM_BYTES, MemoryPermit,
};
use crate::connection::sink::ConnectionGeneration;
use crate::sync::{Arc, Mutex, lock};

// Covers Arc, mutex, notify and container headers in addition to reserved slots.
const OWNER_BACKING_BYTES: usize = 4096;
/// Overflow slots in one allocation quantum: the first charged growth.
pub(crate) const FIRST_OVERFLOW_SLOTS: usize =
    (MEMORY_QUANTUM_BYTES - ALLOCATION_BOOKKEEPING_BYTES) as usize / size_of::<StateCoreMessage>();
/// Overflow slots beside the inline message at the request maximum.
pub(crate) const MAX_OVERFLOW_SLOTS: usize = MAX_REQUESTS_PER_CONNECTION - 1;

/// Charged overflow storage of one connection's queue.
struct Overflow {
    // Fields drop in declaration order: free the storage before its permit.
    messages: VecDeque<StateCoreMessage>,
    _backing: MemoryPermit,
}

impl Overflow {
    fn reserve(backing: &BackingReservationPort, slots: usize) -> Result<Self, RuntimeError> {
        let bytes = slots
            .checked_mul(size_of::<StateCoreMessage>())
            .ok_or(RuntimeError::Overflow)?;
        let permit = backing.reserve(bytes)?;
        let mut messages = VecDeque::new();
        messages
            .try_reserve_exact(slots)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        Ok(Self {
            messages,
            _backing: permit,
        })
    }

    fn has_room(&self) -> bool {
        self.messages.len() < self.messages.capacity()
    }
}

struct QueueState {
    // The oldest message when present: filled only while overflow is empty.
    inline: Option<StateCoreMessage>,
    overflow: Option<Overflow>,
    scheduled: bool,
}

impl QueueState {
    fn len(&self) -> usize {
        usize::from(self.inline.is_some())
            + self
                .overflow
                .as_ref()
                .map_or(0, |overflow| overflow.messages.len())
    }

    fn is_empty(&self) -> bool {
        self.inline.is_none() && self.overflow.is_none()
    }

    /// The overflow slots one more message needs, if it needs new storage.
    /// A queue at the request maximum refuses before any storage is sought.
    fn growth(&self) -> Option<usize> {
        if self.len() >= MAX_REQUESTS_PER_CONNECTION {
            return None;
        }
        let Some(overflow) = &self.overflow else {
            return self.inline.is_some().then_some(FIRST_OVERFLOW_SLOTS);
        };
        (!overflow.has_room()).then_some(MAX_OVERFLOW_SLOTS)
    }

    /// Replaces the overflow with larger prepared storage when one more
    /// message still needs it; otherwise the prepared storage is released.
    fn install(&mut self, mut prepared: Overflow) {
        if self.growth().is_none() {
            return;
        }
        if let Some(mut current) = self.overflow.take() {
            prepared.messages.extend(current.messages.drain(..));
        }
        self.overflow = Some(prepared);
    }

    /// Appends in arrival order, or returns the message when no prepared
    /// room exists.
    fn push(&mut self, message: StateCoreMessage) -> Result<(), StateCoreMessage> {
        if self.is_empty() {
            self.inline = Some(message);
            return Ok(());
        }
        match self.overflow.as_mut() {
            Some(overflow) if overflow.has_room() => {
                overflow.messages.push_back(message);
                Ok(())
            }
            _ => Err(message),
        }
    }

    fn pop(&mut self) -> Option<StateCoreMessage> {
        if let Some(message) = self.inline.take() {
            return Some(message);
        }
        let message = self.overflow.as_mut()?.messages.pop_front();
        if self
            .overflow
            .as_ref()
            .is_some_and(|overflow| overflow.messages.is_empty())
        {
            self.overflow = None;
        }
        message
    }

    fn clear(&mut self) {
        self.inline = None;
        self.overflow = None;
    }
}

struct Queue {
    generation: ConnectionGeneration,
    state: Mutex<QueueState>,
    _slot: OwnedSemaphorePermit,
}

struct ReadyState {
    queues: VecDeque<Arc<Queue>>,
    messages: usize,
    closed: bool,
}

struct Shared {
    state: Mutex<ReadyState>,
    available: Notify,
    closed: Notify,
    backing: BackingReservationPort,
    _backing: MemoryPermit,
}

/// Why a connection's input refused one parsed line.
pub(crate) enum InputRefusal {
    /// The consumer is gone, the generation is wrong, or the line exceeds
    /// the request maximum.
    Closed,
    /// Overflow storage could not be charged now; the line is returned so the
    /// reader can pause and retry within its stall budget.
    MemoryExhausted(StateCoreMessage),
}

impl fmt::Debug for InputRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => formatter.write_str("Closed"),
            Self::MemoryExhausted(_) => formatter.write_str("MemoryExhausted"),
        }
    }
}

impl fmt::Display for InputRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => formatter.write_str("client input is closed"),
            Self::MemoryExhausted(_) => formatter.write_str("client input storage exhausted"),
        }
    }
}

impl std::error::Error for InputRefusal {}

/// One connection's input authority, issued only after bounded queue preparation.
/// The reader retains its existing per-connection request and byte ledger.
pub struct ClientInputPort {
    queue: Arc<Queue>,
    shared: Arc<Shared>,
}

impl fmt::Debug for ClientInputPort {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientInputPort")
            .finish_non_exhaustive()
    }
}

impl ClientInputPort {
    pub(crate) fn send(&self, message: StateCoreMessage) -> Result<(), InputRefusal> {
        let generation = match &message {
            StateCoreMessage::Line { generation, .. }
            | StateCoreMessage::QueuedLine { generation, .. } => *generation,
            _ => return Err(InputRefusal::Closed),
        };
        if generation != self.queue.generation {
            return Err(InputRefusal::Closed);
        }
        // Only this port's reader grows its queue, so storage prepared before
        // publication still suffices when the consumer drains meanwhile.
        let growth = lock(&self.queue.state).growth();
        let prepared = match growth {
            Some(slots) => match Overflow::reserve(&self.shared.backing, slots) {
                Ok(prepared) => Some(prepared),
                Err(_) => return Err(InputRefusal::MemoryExhausted(message)),
            },
            None => None,
        };
        // Always acquire the shared lock before the connection lock. Publication
        // and readiness change together, including on the last dequeue.
        let mut ready = lock(&self.shared.state);
        let mut queue = lock(&self.queue.state);
        if ready.closed || queue.len() >= MAX_REQUESTS_PER_CONNECTION {
            return Err(InputRefusal::Closed);
        }
        let messages = ready.messages.checked_add(1).ok_or(InputRefusal::Closed)?;
        if let Some(prepared) = prepared {
            queue.install(prepared);
        }
        // Growth was computed for this line, so the push always has room.
        queue.push(message).map_err(|_| InputRefusal::Closed)?;
        if !queue.scheduled {
            queue.scheduled = true;
            ready.queues.push_back(Arc::clone(&self.queue));
        }
        ready.messages = messages;
        drop(queue);
        drop(ready);
        self.shared.available.notify_one();
        Ok(())
    }

    pub(crate) async fn closed(&self) {
        let closed = self.shared.closed.notified();
        tokio::pin!(closed);
        closed.as_mut().enable();
        if !lock(&self.shared.state).closed {
            closed.await;
        }
    }
}

pub(crate) struct ClientInputs {
    shared: Arc<Shared>,
    slots: Arc<Semaphore>,
}

impl ClientInputs {
    pub(crate) fn new(
        capacity: usize,
        backing: BackingReservationPort,
    ) -> Result<Self, RuntimeError> {
        if !(1..=MAX_TRACKED_CONNECTIONS).contains(&capacity) {
            return Err(RuntimeError::InvalidValue);
        }
        let bytes = capacity
            .checked_mul(size_of::<Arc<Queue>>())
            .and_then(|bytes| bytes.checked_add(OWNER_BACKING_BYTES))
            .ok_or(RuntimeError::Overflow)?;
        let permit = backing.reserve(bytes)?;
        let mut queues = VecDeque::new();
        queues
            .try_reserve_exact(capacity)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        if queues.capacity() != capacity {
            return Err(RuntimeError::MemoryExhausted);
        }
        Ok(Self {
            shared: Arc::new(Shared {
                state: Mutex::new(ReadyState {
                    queues,
                    messages: 0,
                    closed: false,
                }),
                available: Notify::new(),
                closed: Notify::new(),
                backing,
                _backing: permit,
            }),
            slots: Arc::new(Semaphore::new(capacity)),
        })
    }

    /// Opens one connection's queue. It holds only a count slot; storage
    /// beyond the inline message is charged when a line needs it.
    pub(crate) fn open(
        &self,
        generation: ConnectionGeneration,
    ) -> Result<ClientInputPort, RuntimeError> {
        let slot = Arc::clone(&self.slots)
            .try_acquire_owned()
            .map_err(|_| RuntimeError::LimitExceeded)?;
        Ok(ClientInputPort {
            queue: Arc::new(Queue {
                generation,
                state: Mutex::new(QueueState {
                    inline: None,
                    overflow: None,
                    scheduled: false,
                }),
                _slot: slot,
            }),
            shared: Arc::clone(&self.shared),
        })
    }

    pub(crate) fn len(&self) -> usize {
        lock(&self.shared.state).messages
    }

    fn take(&self) -> Option<StateCoreMessage> {
        let mut ready = lock(&self.shared.state);
        let connection = ready.queues.pop_front()?;
        let mut queue = lock(&connection.state);
        let message = queue.pop()?;
        if queue.is_empty() {
            queue.scheduled = false;
        } else {
            ready.queues.push_back(Arc::clone(&connection));
        }
        ready.messages -= 1;
        Some(message)
    }

    pub(crate) async fn recv(&self) -> StateCoreMessage {
        // This custom queue must yield like Tokio's bounded channels when a
        // producer continuously replenishes it on another runtime worker.
        tokio::task::coop::consume_budget().await;
        loop {
            let available = self.shared.available.notified();
            if let Some(message) = self.take() {
                return message;
            }
            available.await;
        }
    }
}

impl Drop for ClientInputs {
    fn drop(&mut self) {
        let pending = {
            let mut ready = lock(&self.shared.state);
            ready.closed = true;
            ready.messages = 0;
            std::mem::take(&mut ready.queues)
        };
        // Ports may outlive their consumer. Clear their buffers as well as
        // readiness so every abandoned line returns its admission reservation.
        for queue in pending {
            lock(&queue.state).clear();
        }
        self.shared.closed.notify_waiters();
    }
}

#[cfg(test)]
mod tests;
