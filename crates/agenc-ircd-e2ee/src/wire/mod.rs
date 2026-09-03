//! The client and server wire surface of the extension (companion Section
//! 11): canonical tokens, the fragment tag, the carrier matrix, fragment
//! reassembly, command productions, response productions, and the reply
//! code registry.

pub mod assembly;
pub mod carrier;
pub mod command;
pub mod fragment;
pub mod reply;
pub mod response;
pub mod tokens;
