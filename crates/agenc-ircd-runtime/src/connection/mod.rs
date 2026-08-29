//! Per-connection owners: sockets, transport metadata, and the output queue.
//!
//! The connection supervisor owns queue storage and the socket generation
//! (spec 21.1, lines 3995-3998); StateCore holds only the rollback-capable
//! queue reservations defined in [`sink`].

pub mod sink;
