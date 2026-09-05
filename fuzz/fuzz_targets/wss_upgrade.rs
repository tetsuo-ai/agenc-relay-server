#![forbid(unsafe_code)]
#![no_main]

use agenc_ircd_client_wire::websocket_transport::{
    HTTP_UPGRADE_BYTES, parse_upgrade, upgrade_response,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > HTTP_UPGRADE_BYTES {
        return;
    }
    if let Ok(Some(request)) = parse_upgrade(data) {
        let response = upgrade_response(&[0; 20], request.subprotocol());
        assert!(response.is_ok());
    }
    let middle = data.len() / 2;
    if let Some(prefix) = data.get(..middle) {
        let _parsed = parse_upgrade(prefix);
    }
});
