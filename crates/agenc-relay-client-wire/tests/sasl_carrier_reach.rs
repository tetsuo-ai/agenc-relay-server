#![forbid(unsafe_code)]

//! SASL carrier boundaries beyond the Stage 02 vectors: logout transitions need the
//! waiting-logout phase, and a complete request must decode to exactly one account request.

use std::error::Error;

use agenc_relay_client_wire::{
    ACCOUNT_REQUEST_BYTES, AUTH_CHUNK_CHARACTERS, AuthTransportError, SASL_REQUEST_CHARACTERS,
    SaslTransport,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn logout_transitions_need_the_waiting_logout_phase() -> TestResult {
    let mut sasl = SaslTransport::new()?;
    assert_eq!(
        sasl.reject_logout().err(),
        Some(AuthTransportError::BadState)
    );
    assert_eq!(
        sasl.complete_logout().err(),
        Some(AuthTransportError::BadState)
    );
    sasl.client("AGENC-OPAQUE", 0)?;
    assert_eq!(
        sasl.reject_logout().err(),
        Some(AuthTransportError::BadState)
    );
    assert_eq!(
        sasl.complete_logout().err(),
        Some(AuthTransportError::BadState)
    );
    Ok(())
}

/// Feeds `encoded` as exact chunks and returns the outcome of the final chunk.
fn feed(sasl: &mut SaslTransport, encoded: &str) -> Result<(), AuthTransportError> {
    let mut rest = encoded;
    while !rest.is_empty() {
        let take = rest.len().min(AUTH_CHUNK_CHARACTERS);
        let (chunk, remaining) = rest.split_at(take);
        sasl.client(chunk, 1)?;
        rest = remaining;
    }
    Ok(())
}

#[test]
fn a_complete_request_must_decode_to_exactly_one_account_request() -> TestResult {
    let longer = STANDARD.encode(vec![3_u8; ACCOUNT_REQUEST_BYTES + 1]);
    assert_eq!(longer.len(), SASL_REQUEST_CHARACTERS);
    let mut sasl = SaslTransport::new()?;
    sasl.client("AGENC-OPAQUE", 0)?;
    assert_eq!(
        feed(&mut sasl, &longer).err(),
        Some(AuthTransportError::InvalidChunk),
        "the same character count carrying one byte too many"
    );
    let exact = STANDARD.encode(vec![3_u8; ACCOUNT_REQUEST_BYTES]);
    assert_eq!(exact.len(), SASL_REQUEST_CHARACTERS);
    let mut sasl = SaslTransport::new()?;
    sasl.client("AGENC-OPAQUE", 0)?;
    feed(&mut sasl, &exact)?;
    Ok(())
}
