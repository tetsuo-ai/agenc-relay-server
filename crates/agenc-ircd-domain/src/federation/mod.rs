//! Pure base-federation state logic (spec 20, Appendix B).
//!
//! Everything here is deterministic and free of I/O: origin lifecycle and
//! replay classification, least-information projection derivation, the
//! edge's committed replica, and query-cursor bindings. The runtime supplies
//! clocks, entropy, storage, and wire encoding.

pub mod origin;
pub mod projection;
pub mod query_cursor;
pub mod record;
pub mod replica;
