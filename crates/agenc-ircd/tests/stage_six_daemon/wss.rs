//! Independent RFC 6455 client exercising the production daemon.
#![forbid(unsafe_code)]

use super::*;

#[path = "wss/equivalence/mod.rs"]
mod equivalence;

pub(super) struct WebSocketClient {
    stream: TlsClient,
    opcode: u8,
    pending: Vec<u8>,
    received: io::Cursor<Vec<u8>>,
}

impl WebSocketClient {
    pub(super) fn upgrade(mut stream: TlsClient, transport: ClientTransport) -> TestResult<Self> {
        let (protocol, opcode) = match transport {
            ClientTransport::TextWebSocket => ("text.ircv3.net", 1),
            ClientTransport::BinaryWebSocket => ("binary.ircv3.net", 2),
            ClientTransport::Tcp => {
                return Err(failure("WebSocket constructor requires its profile"));
            }
        };
        stream.write_all(format!("GET /irc HTTP/1.1\r\nHost: {DNS_NAME}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: {protocol}\r\nOrigin: https://chat.example\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n").as_bytes())?;
        stream.flush()?;
        let mut response = Vec::new();
        while !response.ends_with(b"\r\n\r\n") && response.len() < 1024 {
            let mut byte = [0];
            stream.read_exact(&mut byte)?;
            response.push(byte[0]);
        }
        let response = String::from_utf8(response)?;
        assert!(response.starts_with("HTTP/1.1 101 "), "{response}");
        assert!(response.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
        assert!(response.contains(&format!("Sec-WebSocket-Protocol: {protocol}\r\n")));
        assert!(
            !response
                .to_ascii_lowercase()
                .contains("sec-websocket-extensions")
        );
        Ok(Self {
            stream,
            opcode,
            pending: Vec::new(),
            received: io::Cursor::new(Vec::new()),
        })
    }

    fn send_frame(&mut self, opcode: u8, payload: &[u8]) -> io::Result<()> {
        let mut frame = vec![0x80 | opcode];
        if payload.len() < 126 {
            frame.push(0x80 | payload.len() as u8);
        } else {
            frame.push(0xfe);
            frame.extend_from_slice(
                &u16::try_from(payload.len())
                    .map_err(io::Error::other)?
                    .to_be_bytes(),
            );
        }
        let mask = [11, 22, 33, 44];
        frame.extend_from_slice(&mask);
        frame.extend(
            payload
                .iter()
                .zip(mask.iter().cycle())
                .map(|(byte, mask)| byte ^ mask),
        );
        self.stream.write_all(&frame)?;
        self.stream.flush()
    }
}

impl io::Write for WebSocketClient {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.pending.len().saturating_add(bytes.len()) > 8703 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.pending.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        let pending = std::mem::take(&mut self.pending);
        let payload = pending
            .strip_suffix(b"\r\n")
            .ok_or(io::ErrorKind::InvalidData)?;
        self.send_frame(self.opcode, payload)
    }
}

impl io::Read for WebSocketClient {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let count = self.received.read(bytes)?;
        if count > 0 {
            return Ok(count);
        }
        for _ in 0..64 {
            let mut header = [0; 2];
            self.stream.read_exact(&mut header)?;
            if header[0] & 0xf0 != 0x80 || header[1] & 0x80 != 0 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let length = match header[1] {
                126 => {
                    let mut length = [0; 2];
                    self.stream.read_exact(&mut length)?;
                    usize::from(u16::from_be_bytes(length))
                }
                127 => return Err(io::ErrorKind::InvalidData.into()),
                length => usize::from(length),
            };
            if length > 8701 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let mut payload = vec![0; length];
            self.stream.read_exact(&mut payload)?;
            match header[0] & 15 {
                8 => return Ok(0),
                9 => {
                    self.send_frame(10, &payload)?;
                    continue;
                }
                10 => continue,
                opcode if opcode == self.opcode => {}
                _ => return Err(io::ErrorKind::InvalidData.into()),
            }
            if std::str::from_utf8(&payload).is_err() {
                return Err(io::ErrorKind::InvalidData.into());
            }
            payload.extend_from_slice(b"\r\n");
            self.received = io::Cursor::new(payload);
            return self.received.read(bytes);
        }
        Err(io::ErrorKind::InvalidData.into())
    }
}

pub(super) fn configure(fixture: &LiveFixture) -> TestResult {
    let mut text = fs::read_to_string(&fixture.config_path)?;
    replace_once(
        &mut text,
        "purpose = \"client_tls\"",
        "purpose = \"client_wss\"\nallowed_origins = [\"https://chat.example\"]",
    )?;
    fs::write(&fixture.config_path, text)?;
    Ok(())
}

fn tls_stream(fixture: &LiveFixture) -> TestResult<TlsClient> {
    let socket = TcpStream::connect(fixture.public_address)?;
    socket.set_read_timeout(Some(IO_TIMEOUT))?;
    socket.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut config = (*fixture.client_config()?).clone();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connection =
        ClientConnection::new(Arc::new(config), ServerName::try_from(DNS_NAME.to_owned())?)?;
    Ok(StreamOwned::new(connection, socket))
}

fn upgrade_status(fixture: &LiveFixture, origin: Option<&str>) -> TestResult<String> {
    let mut stream = tls_stream(fixture)?;
    let origin = origin.map_or(String::new(), |value| format!("Origin: {value}\r\n"));
    stream.write_all(format!("GET /irc HTTP/1.1\r\nHost: {DNS_NAME}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: binary.ircv3.net\r\n{origin}\r\n").as_bytes())?;
    stream.flush()?;
    read_line(&mut BufReader::new(stream))
}

#[test]
fn wss_origin_reload_and_alpn_are_enforced_by_the_live_listener() -> TestResult {
    let fixture = LiveFixture::create()?;
    configure(&fixture)?;
    let mut process = DaemonProcess::start(&fixture.config_path)?;
    let mut admin = AdminClient::connect(&fixture)?;
    assert!(IrcClient::connect(&fixture).is_err());
    for origin in [
        None,
        Some("null"),
        Some("https://CHAT.example"),
        Some("https://chat.example:443"),
    ] {
        assert!(upgrade_status(&fixture, origin)?.starts_with("HTTP/1.1 403"));
    }
    let mut accepted = IrcClient::connect_transport(&fixture, ClientTransport::TextWebSocket)?;
    let mut config = fs::read_to_string(&fixture.config_path)?;
    replace_once(
        &mut config,
        "allowed_origins = [\"https://chat.example\"]",
        "allowed_origins = [\"https://new.example\"]",
    )?;
    fs::write(&fixture.config_path, config)?;
    assert!(
        admin
            .command_line("REHASH :origin allowlist change")?
            .contains("NOTE REHASH OK")
    );
    assert!(upgrade_status(&fixture, Some("https://chat.example"))?.starts_with("HTTP/1.1 403"));
    assert!(upgrade_status(&fixture, Some("https://new.example"))?.starts_with("HTTP/1.1 101"));
    accepted.send("CAP LS 302")?;
    let caps = read_until(&mut accepted.reader, |line| {
        line.contains(" CAP * LS ") && !line.contains(" CAP * LS * :")
    })?;
    assert_contains(&caps, "sasl=AGENC-OPAQUE")?;
    admin.confirm_process("DIE :WSS Origin test complete")?;
    assert!(process.wait()?.success());
    Ok(())
}
