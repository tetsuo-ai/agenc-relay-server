//! Independently bounded reader queues with one round-robin ready entry per connection.

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::fmt;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

use super::inbox::{MAX_REQUESTS_PER_CONNECTION, StateCoreMessage};
use super::session::MAX_TRACKED_CONNECTIONS;
use crate::RuntimeError;
use crate::budget::{BackingReservationPort, MemoryPermit};
use crate::connection::sink::ConnectionGeneration;
use crate::sync::{Arc, Mutex, lock};

// Covers Arc, mutex, notify and container headers in addition to reserved slots.
const OWNER_BACKING_BYTES: usize = 4096;

struct QueueState {
    messages: VecDeque<StateCoreMessage>,
    scheduled: bool,
}

struct Queue {
    generation: ConnectionGeneration,
    state: Mutex<QueueState>,
    _slot: OwnedSemaphorePermit,
    _backing: MemoryPermit,
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
    _backing: MemoryPermit,
}

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
    pub(crate) fn send(&self, message: StateCoreMessage) -> Result<(), RuntimeError> {
        let generation = match &message {
            StateCoreMessage::Line { generation, .. }
            | StateCoreMessage::QueuedLine { generation, .. } => *generation,
            _ => return Err(RuntimeError::InvalidValue),
        };
        if generation != self.queue.generation {
            return Err(RuntimeError::InvalidValue);
        }
        // Always acquire the shared lock before the connection lock. Publication
        // and readiness change together, including on the last dequeue.
        let mut ready = lock(&self.shared.state);
        let mut queue = lock(&self.queue.state);
        if ready.closed || queue.messages.len() >= MAX_REQUESTS_PER_CONNECTION {
            return Err(RuntimeError::LimitExceeded);
        }
        let messages = ready
            .messages
            .checked_add(1)
            .ok_or(RuntimeError::Overflow)?;
        queue.messages.push_back(message);
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
    backing: BackingReservationPort,
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
                _backing: permit,
            }),
            slots: Arc::new(Semaphore::new(capacity)),
            backing,
        })
    }

    pub(crate) fn open(
        &self,
        generation: ConnectionGeneration,
    ) -> Result<ClientInputPort, RuntimeError> {
        let slot = Arc::clone(&self.slots)
            .try_acquire_owned()
            .map_err(|_| RuntimeError::LimitExceeded)?;
        let bytes = MAX_REQUESTS_PER_CONNECTION
            .checked_mul(size_of::<StateCoreMessage>())
            .and_then(|bytes| bytes.checked_add(OWNER_BACKING_BYTES))
            .ok_or(RuntimeError::Overflow)?;
        let permit = self.backing.reserve(bytes)?;
        let mut messages = VecDeque::new();
        messages
            .try_reserve_exact(MAX_REQUESTS_PER_CONNECTION)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        if messages.capacity() != MAX_REQUESTS_PER_CONNECTION {
            return Err(RuntimeError::MemoryExhausted);
        }
        Ok(ClientInputPort {
            queue: Arc::new(Queue {
                generation,
                state: Mutex::new(QueueState {
                    messages,
                    scheduled: false,
                }),
                _slot: slot,
                _backing: permit,
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
        let message = queue.messages.pop_front()?;
        if queue.messages.is_empty() {
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
            lock(&queue.state).messages.clear();
        }
        self.shared.closed.notify_waiters();
    }
}

#[cfg(test)]
mod tests;
