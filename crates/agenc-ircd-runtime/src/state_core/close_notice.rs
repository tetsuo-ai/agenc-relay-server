#![forbid(unsafe_code)]

//! The `ERROR` line a slow-consumer close sends first (architecture 1.2 and
//! 19.3).
//!
//! `Close` means one bounded `ERROR` before the transport closes. A
//! slow-consumer close destroys the whole normal queue, so its line cannot
//! take the ordinary fanout path: it is rendered once, charged once, shared
//! by every connection, and armed on each sink when the connection opens.
//! The close itself then only moves the armed frame into the reserved control
//! slot, which allocates nothing and cannot fail for lack of memory.

use agenc_ircd_client_wire::WireMessage;

use crate::budget::{BoundedMemoryCharges, MemoryBudgetPort, MemoryCharge, PermitCursor};
use crate::connection::sink::{ClientSink, SharedClientFrame};
use crate::sync::Arc;

/// The public reason of a slow-consumer close.
pub(crate) const SLOW_CONSUMER_REASON: &str = "Closing connection: output queue exceeded";

/// The shared slow-consumer line, rendered on first use.
#[derive(Default)]
pub(crate) struct CloseNotice {
    frame: Option<SharedClientFrame>,
}

impl CloseNotice {
    /// Arms `sink` with the shared line. A budget too exhausted to render it
    /// leaves the sink unarmed, and the next open tries again.
    pub(crate) fn arm(
        &mut self,
        sink: &dyn ClientSink,
        prefix: &str,
        budget: &dyn MemoryBudgetPort,
    ) {
        if self.frame.is_none() {
            self.frame = render(prefix, budget);
        }
        if let Some(frame) = &self.frame {
            sink.arm_slow_consumer_notice(Arc::clone(frame));
        }
    }
}

fn render(prefix: &str, budget: &dyn MemoryBudgetPort) -> Option<SharedClientFrame> {
    let message = WireMessage::new(prefix, "ERROR", &[], Some(SLOW_CONSUMER_REASON)).ok()?;
    let measured = message.measure().ok()?;
    let bytes = u64::try_from(measured.bytes()).ok()?;
    let charge = MemoryCharge::allocation(bytes).ok()?;
    let charges = BoundedMemoryCharges::new(&[charge]).ok()?;
    let mut permits = budget.try_acquire_batch(charges).ok()?;
    let rendered = measured.encode(&mut PermitCursor::new(&mut permits)).ok()?;
    Some(Arc::new(rendered))
}
