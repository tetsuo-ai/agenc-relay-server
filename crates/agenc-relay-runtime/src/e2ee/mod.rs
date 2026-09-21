//! The runtime side of the ARC-MLS companion profile: link negotiation now,
//! the coordinator execution, origins, snapshots, and edge routing in the
//! slices that follow. Nothing here holds an MLS client, an epoch secret,
//! or a private key; objects pass through as validated bytes.

pub mod barrier;
pub mod coordinator;
pub mod edge;
pub mod link;
