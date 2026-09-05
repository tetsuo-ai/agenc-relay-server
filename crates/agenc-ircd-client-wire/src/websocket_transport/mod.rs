//! Bounded HTTP upgrade and RFC 6455 frame codecs. Socket and Origin policy
//! decisions remain with the runtime.

mod frame;
mod upgrade;

pub use frame::{
    ClientFrameHeader, FrameHeaderError, client_header_bytes, decode_client_header,
    server_frame_header,
};
pub use upgrade::{
    HTTP_UPGRADE_BYTES, UpgradeError, UpgradeRequest, UpgradeResponse, parse_upgrade,
    upgrade_response,
};
