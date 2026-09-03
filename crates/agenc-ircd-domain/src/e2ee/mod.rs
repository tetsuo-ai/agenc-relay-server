//! Pure server-side E2EE state: route lineages, semantic locks, and the
//! downgrade decisions the base daemon consults before routing plaintext.
//!
//! Nothing here reads a clock, random source, or key. Companion object
//! validation lives in the e2ee crate; this module holds the state that
//! outlives one object and the rules that relate routes to base channels
//! and account pairs.

mod route_table;

pub use route_table::{
    BindingSummary, ConversationId, DirectPair, RecoveryState, ReservationId, RouteConflict,
    RouteEntry, RouteLifecycle, RouteReservation, RouteTable, RouteTarget, SemanticLockId,
};
