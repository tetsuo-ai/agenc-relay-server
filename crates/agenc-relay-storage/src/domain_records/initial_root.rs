//! Every guarded account reserves the complete terminal receipt at creation.
#![forbid(unsafe_code)]

use std::sync::Arc;

use agenc_relay_domain::InitialRootState;

use super::{Decoder, Encoder, StorageError, byte};

pub(super) fn encode(out: &mut Encoder, state: &InitialRootState) -> Result<(), StorageError> {
    let empty = [0; 32];
    let (tag, fingerprint, object_id) = match state {
        InitialRootState::Reserved => (0, &empty, &empty),
        InitialRootState::Chosen(fingerprint) => (1, fingerprint, &empty),
        InitialRootState::Published {
            fingerprint,
            object_id,
        } => (2, fingerprint, object_id),
    };
    out.put_fixed(&[tag])?;
    out.put_fixed(fingerprint)?;
    out.put_fixed(object_id)
}

pub(super) fn decode(input: &mut Decoder<'_>) -> Result<Arc<InitialRootState>, StorageError> {
    let tag = byte(input)?;
    let fingerprint = input.array()?;
    let object_id = input.array()?;
    let state = match tag {
        0 if fingerprint == [0; 32] && object_id == [0; 32] => InitialRootState::Reserved,
        1 if object_id == [0; 32] => InitialRootState::Chosen(fingerprint),
        2 => InitialRootState::Published {
            fingerprint,
            object_id,
        },
        _ => return Err(StorageError::InvalidEncoding),
    };
    Ok(Arc::new(state))
}
