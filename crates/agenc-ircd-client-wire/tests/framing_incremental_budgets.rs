//! Incremental rejection tests for client-side stream budgets.

#![forbid(unsafe_code)]

use std::error::Error;

use agenc_ircd_client_wire::{FramingError, StreamFramer};

#[test]
fn fragmented_tag_input_fails_at_the_client_side_limit() -> Result<(), Box<dyn Error>> {
    let mut framer = StreamFramer::new()?;
    framer.feed(b"@", |_| {})?;
    framer.feed(&vec![b'a'; 4_094], |_| {})?;

    assert_eq!(
        framer.feed(b"a", |_| {}).err(),
        Some(FramingError::ClientTagsTooLong)
    );

    let mut emitted = 0;
    framer.feed(b"PING\r\n", |_| emitted += 1)?;
    assert_eq!(emitted, 1);
    Ok(())
}

#[test]
fn fragmented_tagged_command_fails_at_the_command_limit() -> Result<(), Box<dyn Error>> {
    let mut framer = StreamFramer::new()?;
    framer.feed(b"@a=b ", |_| {})?;
    framer.feed(&vec![b'A'; 8_696], |_| {})?;

    assert_eq!(
        framer.feed(b"A", |_| {}).err(),
        Some(FramingError::LineTooLong)
    );
    Ok(())
}

#[test]
fn fragmented_maximal_tagged_line_is_admitted() -> Result<(), Box<dyn Error>> {
    let mut framer = StreamFramer::new()?;
    let mut emitted = 0;
    framer.feed(b"@", |_| emitted += 1)?;
    framer.feed(&vec![b'a'; 4_094], |_| emitted += 1)?;
    framer.feed(b" ", |_| emitted += 1)?;
    framer.feed(&vec![b'A'; 4_605], |_| emitted += 1)?;
    framer.feed(b"\r\n", |_| emitted += 1)?;

    assert_eq!(emitted, 1);
    Ok(())
}
