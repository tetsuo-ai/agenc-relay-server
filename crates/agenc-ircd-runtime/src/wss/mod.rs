//! Optional WSS transport owners. Public HTTP and frame codecs live in
//! client-wire; this module owns admission, deadlines, and socket operations.

mod stream;
mod upgrade;

pub(crate) use stream::WssStream;
pub(crate) use upgrade::upgrade;
