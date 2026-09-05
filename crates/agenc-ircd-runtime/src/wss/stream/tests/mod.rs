#![forbid(unsafe_code)]
//! Socket framing, control ordering, and permit lifetime regressions.

use super::*;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn frame(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut result = vec![if fin { 0x80 | opcode } else { opcode }];
    if payload.len() < 126 {
        result.push(0x80 | payload.len() as u8);
    } else {
        result.push(0xfe);
        result.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    }
    let mask = [11, 22, 33, 44];
    result.extend_from_slice(&mask);
    result.extend(
        payload
            .iter()
            .zip(mask.iter().cycle())
            .map(|(byte, mask)| byte ^ mask),
    );
    result
}

#[tokio::test]
async fn both_subprotocols_preserve_irc_line_boundaries_and_release_buffers() -> TestResult {
    for (protocol, opcode) in [
        (WebSocketSubprotocol::TextIrcv3, 1),
        (WebSocketSubprotocol::BinaryIrcv3, 2),
    ] {
        let budget = MemoryBudget::new(1_048_576);
        let (mut peer, transport) = tokio::io::duplex(32_768);
        let mut stream = WssStream::new(transport, protocol, &budget)?;
        let charge = budget.charged();
        assert_eq!(charge, 61_440);
        for line in [b"CAP LS 302".as_slice(), b"NICK name", b"USER u 0 * :Name"] {
            peer.write_all(&frame(true, opcode, line)).await?;
        }
        let expected = b"CAP LS 302\r\nNICK name\r\nUSER u 0 * :Name\r\n";
        let mut received = vec![0; expected.len()];
        stream.read_exact(&mut received).await?;
        assert_eq!(received, expected);
        stream.write_all(b":server NOTICE * :hello\r\n").await?;
        stream.flush().await?;
        let mut output = [0_u8; 25];
        peer.read_exact(&mut output).await?;
        assert_eq!(&output[..2], &[0x80 | opcode, 23]);
        assert_eq!(&output[2..], b":server NOTICE * :hello");
        drop(stream);
        assert_eq!(budget.charged(), 0);
    }
    Ok(())
}

#[tokio::test]
async fn fragmented_utf8_and_interleaved_ping_use_one_ordered_writer() -> TestResult {
    let budget = MemoryBudget::new(1_048_576);
    let (mut peer, transport) = tokio::io::duplex(32_768);
    let mut stream = WssStream::new(transport, WebSocketSubprotocol::TextIrcv3, &budget)?;
    peer.write_all(&frame(false, 1, b"PRIVMSG #c :\xe2"))
        .await?;
    peer.write_all(&frame(true, 9, b"ping")).await?;
    peer.write_all(&frame(true, 0, b"\x82\xac")).await?;
    let mut output = [0_u8; 17];
    stream.read_exact(&mut output).await?;
    assert_eq!(&output, b"PRIVMSG #c :\xe2\x82\xac\r\n");
    let mut pong = [0_u8; 6];
    peer.read_exact(&mut pong).await?;
    assert_eq!(&pong, b"\x8a\x04ping");
    Ok(())
}

#[tokio::test]
async fn malformed_utf8_masking_and_size_send_exact_close_codes() -> TestResult {
    for (bytes, code) in [
        (vec![0x81, 0], 1002_u16),
        (frame(true, 1, b"\xff"), 1007),
        (vec![0x81, 0xfe, 0x21, 0xfe, 0, 0, 0, 0], 1009),
    ] {
        let budget = MemoryBudget::new(1_048_576);
        let (mut peer, transport) = tokio::io::duplex(32_768);
        let mut stream = WssStream::new(transport, WebSocketSubprotocol::TextIrcv3, &budget)?;
        peer.write_all(&bytes).await?;
        let mut byte = [0];
        assert_eq!(stream.read(&mut byte).await?, 0);
        let mut close = [0_u8; 4];
        peer.read_exact(&mut close).await?;
        assert_eq!(&close[..2], &[0x88, 2]);
        assert_eq!(&close[2..], &code.to_be_bytes());
    }
    Ok(())
}

#[tokio::test]
async fn peer_close_finishes_the_control_exchange_before_eof() -> TestResult {
    let budget = MemoryBudget::new(1_048_576);
    let (mut peer, transport) = tokio::io::duplex(32_768);
    let mut stream = WssStream::new(transport, WebSocketSubprotocol::TextIrcv3, &budget)?;
    peer.write_all(&frame(true, 8, b"\x03\xe8bye")).await?;
    assert_eq!(stream.read(&mut [0]).await?, 0);
    let mut reply = [0_u8; 7];
    peer.read_exact(&mut reply).await?;
    assert_eq!(&reply, b"\x88\x05\x03\xe8bye");
    Ok(())
}

#[tokio::test]
async fn framing_refusal_and_cancellation_return_every_permit() -> TestResult {
    let insufficient = MemoryBudget::new(1);
    let (_peer, transport) = tokio::io::duplex(1);
    assert!(matches!(
        WssStream::new(transport, WebSocketSubprotocol::TextIrcv3, &insufficient),
        Err(RuntimeError::MemoryExhausted)
    ));
    assert_eq!(insufficient.charged(), 0);
    let budget = MemoryBudget::new(1_048_576);
    let (_peer, transport) = tokio::io::duplex(1);
    let mut stream = WssStream::new(transport, WebSocketSubprotocol::TextIrcv3, &budget)?;
    let task = tokio::spawn(async move { stream.read(&mut [0]).await });
    task.abort();
    assert!(task.await.is_err());
    assert_eq!(budget.charged(), 0);
    Ok(())
}

struct FlushStall;
impl AsyncRead for FlushStall {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}
impl AsyncWrite for FlushStall {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

#[tokio::test]
async fn a_control_flush_stall_obeys_its_deadline_after_bytes_are_written() -> TestResult {
    let budget = MemoryBudget::new(1_048_576);
    let mut stream = WssStream::new(FlushStall, WebSocketSubprotocol::TextIrcv3, &budget)?;
    stream.close(1002)?;
    stream
        .control_timer
        .as_mut()
        .reset(Instant::now() + std::time::Duration::from_millis(1));
    let result =
        tokio::time::timeout(std::time::Duration::from_secs(1), stream.read(&mut [0])).await?;
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    Ok(())
}
