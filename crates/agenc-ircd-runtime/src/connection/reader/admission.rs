//! Per-connection charges retained until StateCore consumes a parsed line.

use tokio::sync::Notify;

use super::ReaderLimits;
use crate::sync::{Arc, Mutex, lock};

#[derive(Default)]
struct Usage {
    requests: usize,
    bytes: usize,
}

#[derive(Default)]
pub(super) struct Admission {
    usage: Mutex<Usage>,
    released: Notify,
}

impl Admission {
    pub(super) async fn reserve(
        self: &Arc<Self>,
        bytes: usize,
        limits: ReaderLimits,
    ) -> ClientLinePermit {
        loop {
            // There is one reader per admission ledger. notify_one retains a
            // wakeup if StateCore releases a charge before this future polls.
            let released = self.released.notified();
            if let Some(permit) = self.try_reserve(bytes, limits) {
                return permit;
            }
            released.await;
        }
    }

    fn try_reserve(
        self: &Arc<Self>,
        bytes: usize,
        limits: ReaderLimits,
    ) -> Option<ClientLinePermit> {
        let mut usage = lock(&self.usage);
        if usage.requests >= limits.requests()
            || bytes > limits.arena_bytes().saturating_sub(usage.bytes)
        {
            return None;
        }
        usage.requests += 1;
        usage.bytes += bytes;
        Some(ClientLinePermit {
            admission: Arc::clone(self),
            bytes,
        })
    }
}

/// A reader's request and wire-byte reservation, released after dispatch.
/// Dropping an abandoned inbox also releases every queued reservation.
pub struct ClientLinePermit {
    admission: Arc<Admission>,
    bytes: usize,
}

impl Drop for ClientLinePermit {
    fn drop(&mut self) {
        {
            let mut usage = lock(&self.admission.usage);
            usage.requests -= 1;
            usage.bytes -= self.bytes;
        }
        self.admission.released.notify_one();
    }
}
