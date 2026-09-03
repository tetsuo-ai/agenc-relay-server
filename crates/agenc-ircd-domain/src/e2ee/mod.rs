//! Pure server-side E2EE state: route lineages, semantic locks, the
//! downgrade decisions the base daemon consults before routing plaintext,
//! the per-conversation sequencer log, the account directory, device
//! mailboxes, the group lifecycle, and companion event projection.
//!
//! Nothing here reads a clock, random source, or key. Companion object
//! validation lives in the e2ee crate; this module holds the state that
//! outlives one object and the rules that relate routes to base channels
//! and account pairs.

pub mod directory;
pub mod lifecycle;
pub mod limits;
pub mod mailbox;
pub mod projection;
mod route_table;
pub mod sequencer_log;

pub use route_table::{
    BindingSummary, ConversationId, DirectPair, RecoveryState, ReservationId, RouteConflict,
    RouteEntry, RouteLifecycle, RouteReservation, RouteTable, RouteTarget, SemanticLockId,
};
