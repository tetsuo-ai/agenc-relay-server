//! The fixed private account wrappers shared by the two negotiated profiles.

use core::ops::RangeInclusive;
use zeroize::Zeroizing;

use super::{AuthError, Cursor, PADDING_VERSION, Writer};

pub(super) fn encode<const SIZE: usize>(
    fields: &[u8],
    valid: RangeInclusive<usize>,
) -> Result<Zeroizing<[u8; SIZE]>, AuthError> {
    if !valid.contains(&fields.len()) {
        return Err(AuthError::InvalidEncoding);
    }
    let padding = SIZE
        .checked_sub(6)
        .and_then(|space| space.checked_sub(fields.len()))
        .ok_or(AuthError::InvalidEncoding)?;
    let field_length = u16::try_from(fields.len()).map_err(|_| AuthError::Overflow)?;
    let padding_length = u16::try_from(padding).map_err(|_| AuthError::Overflow)?;
    let mut plaintext = Zeroizing::new([0; SIZE]);
    let mut writer = Writer::new(plaintext.as_mut());
    writer.write(&PADDING_VERSION.to_be_bytes())?;
    writer.write(&field_length.to_be_bytes())?;
    writer.write(fields)?;
    writer.write(&padding_length.to_be_bytes())?;
    writer.write_zeros(padding)?;
    if !writer.is_finished() {
        return Err(AuthError::InvalidEncoding);
    }
    Ok(plaintext)
}

pub(super) fn decode<const SIZE: usize>(
    plaintext: &[u8; SIZE],
    valid: RangeInclusive<usize>,
) -> Result<&[u8], AuthError> {
    let mut cursor = Cursor::new(plaintext);
    if cursor.read_u16()? != PADDING_VERSION {
        return Err(AuthError::InvalidEncoding);
    }
    let length = usize::from(cursor.read_u16()?);
    if !valid.contains(&length) {
        return Err(AuthError::InvalidEncoding);
    }
    let fields = cursor.read_slice(length)?;
    let padding_length = usize::from(cursor.read_u16()?);
    let padding = cursor.read_slice(padding_length)?;
    if !cursor.is_finished() || padding.iter().any(|byte| *byte != 0) {
        return Err(AuthError::InvalidEncoding);
    }
    Ok(fields)
}
