//! Connection owners: the client sink contract, the owner-side writer queue,
//! the reader and writer tasks, and the per-connection supervisor (spec
//! 21.2 and 21.3, lines 4048-4113).

pub mod queue;
pub mod reader;
pub mod sink;
pub mod supervisor;
pub mod writer;

pub use queue::{
    CONTROL_ITEM_SLOTS, ClosePolicy, DEFAULT_CONTROL_OUTPUT_BYTES, DEFAULT_OUTPUT_BYTES,
    DEFAULT_QUEUE_ITEMS, MAX_CONTROL_OUTPUT_BYTES, MAX_OUTPUT_BYTES, MAX_QUEUE_ITEMS,
    QUEUE_WARNING_PERCENT, QueueLimits, QueuePop, WriterQueue,
};
pub use reader::{
    DEFAULT_PARSED_ARENA_BYTES, DEFAULT_REQUESTS_PER_CONNECTION, READ_CHUNK_BYTES,
    READ_STALL_BUDGET, ReaderLimits, run_reader,
};
pub use sink::{
    BoundedSharedClientFrames, ClientQueueDemand, ClientQueueReservation, ClientQueueSnapshot,
    ClientSink, ConnectionGeneration, FlushAcknowledgement, MAX_DEMAND_BYTES, MAX_DEMAND_FRAMES,
    QueueAllocationError, QueueReservationLedger, QueueTransfer, ReservationToken,
    SinkReserveError, TentativeClientQueueReservation,
};
pub(crate) use supervisor::run_connection;
pub use supervisor::{
    AdmittedConnection, ConnectionExit, ConnectionLimits, ConnectionResources, PeerIdentity,
};
pub use writer::run_writer;
