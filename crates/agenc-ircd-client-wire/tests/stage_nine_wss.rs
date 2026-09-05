#![forbid(unsafe_code)]
//! HTTP upgrade and raw WebSocket frame boundary regressions.

#[cfg(feature = "wss")]
mod tests {
    use agenc_ircd_client_wire::websocket_transport::{
        FrameHeaderError, UpgradeError, decode_client_header, parse_upgrade, server_frame_header,
        upgrade_response,
    };
    use agenc_ircd_client_wire::{WebSocketOpcode, WebSocketSubprotocol};

    const BASE: &str = "GET /irc HTTP/1.1\r\nHost: chat.example\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: text.ircv3.net\r\nOrigin: https://chat.example\r\n";
    fn request(extra: &str) -> String {
        format!("{BASE}{extra}\r\n")
    }

    #[test]
    fn upgrade_selects_client_preference_and_ignores_extension_offers()
    -> Result<(), Box<dyn std::error::Error>> {
        let input =
            request("Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n")
                .replace(
                    "text.ircv3.net",
                    "unknown, binary.ircv3.net, text.ircv3.net",
                );
        let parsed = parse_upgrade(input.as_bytes())?.ok_or("incomplete")?;
        assert_eq!(parsed.subprotocol(), WebSocketSubprotocol::BinaryIrcv3);
        assert_eq!(parsed.origin(), Some("https://chat.example"));
        assert_eq!(parsed.key(), b"dGhlIHNhbXBsZSBub25jZQ==");
        Ok(())
    }

    #[test]
    fn upgrade_accepts_every_partial_read_until_the_final_delimiter()
    -> Result<(), Box<dyn std::error::Error>> {
        let input = request("");
        for end in 0..input.len() {
            assert!(parse_upgrade(input.as_bytes().get(..end).ok_or("prefix")?)?.is_none());
        }
        assert!(parse_upgrade(input.as_bytes())?.is_some());
        Ok(())
    }

    #[test]
    fn upgrade_rejects_ambiguous_headers_bodies_and_http_authentication() {
        for extra in [
            "Host: other.example\r\n",
            "Origin: https://other.example\r\n",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
            "Sec-WebSocket-Version: 13\r\n",
            "Content-Length: 1\r\n",
            "Content-Length: 0\r\nContent-Length: 0\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Cookie: session=canary\r\n",
            "Authorization: Basic canary\r\n",
            "Proxy-Authorization: Basic canary\r\n",
            " folded\r\n",
            "Bad Header: value\r\n",
        ] {
            assert_eq!(
                parse_upgrade(request(extra).as_bytes()).err(),
                Some(UpgradeError::Malformed),
                "{extra}"
            );
        }
        assert_eq!(
            parse_upgrade(format!("{}GET /irc HTTP/1.1\r\n", request("")).as_bytes()).err(),
            Some(UpgradeError::Malformed)
        );
        assert_eq!(
            parse_upgrade(request("").replace("\r\n", "\n").as_bytes()).err(),
            Some(UpgradeError::Malformed)
        );
    }

    #[test]
    fn upgrade_errors_do_not_echo_request_values() {
        let original = request("");
        for (from, to, expected) in [
            ("GET", "POST", UpgradeError::Method),
            ("/irc", "/irc?canary=1", UpgradeError::Endpoint),
            ("HTTP/1.1", "HTTP/1.0", UpgradeError::Malformed),
            ("Version: 13", "Version: 12", UpgradeError::Version),
            ("text.ircv3.net", "unknown", UpgradeError::Malformed),
            (
                "dGhlIHNhbXBsZSBub25jZQ==",
                "dGhlIHNhbXBsZSBub25jZQ__",
                UpgradeError::Malformed,
            ),
        ] {
            let error = parse_upgrade(original.replace(from, to).as_bytes()).err();
            assert_eq!(error, Some(expected));
            assert!(
                !expected
                    .response()
                    .windows(6)
                    .any(|window| window == b"canary")
            );
        }
    }

    #[test]
    fn upgrade_enforces_request_header_line_count_and_total_bounds() {
        let long_request = format!("GET /{} HTTP/1.1", "a".repeat(2_048));
        assert_eq!(
            parse_upgrade(long_request.as_bytes()).err(),
            Some(UpgradeError::RequestLine)
        );
        let exact_line = format!("X:{}\r\n", "a".repeat(4_094));
        assert!(parse_upgrade(request(&exact_line).as_bytes()).is_ok());
        let over_line = format!("X:{}\r\n", "a".repeat(4_095));
        assert_eq!(
            parse_upgrade(request(&over_line).as_bytes()).err(),
            Some(UpgradeError::Headers)
        );
        assert!(parse_upgrade(request(&"X: a\r\n".repeat(57)).as_bytes()).is_ok());
        assert_eq!(
            parse_upgrade(request(&"X: a\r\n".repeat(58)).as_bytes()).err(),
            Some(UpgradeError::Headers)
        );
        assert_eq!(
            parse_upgrade(request(&exact_line.repeat(4)).as_bytes()).err(),
            Some(UpgradeError::Headers)
        );
    }

    #[test]
    fn upgrade_response_matches_rfc6455_accept_value() -> Result<(), Box<dyn std::error::Error>> {
        let digest = [
            0xb3, 0x7a, 0x4f, 0x2c, 0xc0, 0x62, 0x4f, 0x16, 0x90, 0xf6, 0x46, 0x06, 0xcf, 0x38,
            0x59, 0x45, 0xb2, 0xbe, 0xc4, 0xea,
        ];
        let response = upgrade_response(&digest, WebSocketSubprotocol::TextIrcv3)?;
        assert_eq!(response.as_bytes(), b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Protocol: text.ircv3.net\r\n\r\n");
        Ok(())
    }

    #[test]
    fn raw_headers_reject_mask_reserved_opcode_and_nonminimal_lengths() {
        for input in [
            vec![0x81, 0],
            vec![0xc1, 0x80],
            vec![0x83, 0x80],
            vec![0x09, 0x80],
            vec![0x89, 0xfe],
            vec![0x81, 0xfe, 0, 125],
            vec![0x81, 0xff, 0, 0, 0, 0, 0, 0, 0xff, 0xff],
            vec![0x81, 0xff, 0x80, 0, 0, 0, 0, 0, 0, 0],
        ] {
            assert_eq!(
                decode_client_header(&input).err(),
                Some(FrameHeaderError::Protocol)
            );
        }
        assert_eq!(
            decode_client_header(&[0x81, 0xfe, 0x21, 0xfe]).err(),
            Some(FrameHeaderError::TooLarge)
        );
    }

    #[test]
    fn raw_headers_bound_payloads_before_body_allocation() -> Result<(), Box<dyn std::error::Error>>
    {
        for length in [0_usize, 1, 125, 126, 8_701] {
            let (server, count) = server_frame_header(WebSocketOpcode::Text, length)?;
            let mut client = server.get(..count).ok_or("header")?.to_vec();
            *client.get_mut(1).ok_or("mask bit")? |= 0x80;
            client.extend_from_slice(&[1, 2, 3, 4]);
            for end in 0..client.len() {
                assert!(decode_client_header(client.get(..end).ok_or("prefix")?)?.is_none());
            }
            let header = decode_client_header(&client)?.ok_or("missing header")?;
            assert_eq!(header.payload_bytes(), length);
            assert_eq!(header.header_bytes(), count + 4);
        }
        assert_eq!(
            server_frame_header(WebSocketOpcode::Binary, 8_702).err(),
            Some(FrameHeaderError::TooLarge)
        );
        assert_eq!(
            server_frame_header(WebSocketOpcode::Pong, 126).err(),
            Some(FrameHeaderError::TooLarge)
        );
        Ok(())
    }

    #[test]
    fn host_is_a_single_bounded_authority_without_user_info_or_paths() {
        let base = request("");
        for host in [
            "chat.example",
            "chat.example:443",
            "127.0.0.1:443",
            "[::1]:443",
        ] {
            assert!(
                parse_upgrade(
                    base.replace("Host: chat.example", &format!("Host: {host}"))
                        .as_bytes()
                )
                .is_ok()
            );
        }
        for host in [
            "",
            "user@chat.example",
            "chat.example/path",
            "chat.example:",
            "chat.example:65536",
            "::1",
            "[no-ipv6]",
            "-bad.example",
            "chat..example",
        ] {
            assert_eq!(
                parse_upgrade(
                    base.replace("Host: chat.example", &format!("Host: {host}"))
                        .as_bytes()
                )
                .err(),
                Some(UpgradeError::Malformed)
            );
        }
    }
    #[test]
    fn public_upgrade_fixture_round_trips_exact_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = include_str!("../../../test-data/vectors/stage-nine-wss.vectors");
        let decode = |name: &str| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            let prefix = format!("{name}|hex|");
            let value = fixture
                .lines()
                .find_map(|line| line.strip_prefix(&prefix))
                .ok_or("fixture field")?;
            let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
            if !remainder.is_empty() {
                return Err("odd fixture hex length".into());
            }
            pairs
                .iter()
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair)?, 16).map_err(Into::into))
                .collect()
        };
        let request = decode("request")?;
        let parsed = parse_upgrade(&request)?.ok_or("incomplete fixture")?;
        let digest: [u8; 20] = decode("digest")?.try_into().map_err(|_| "digest length")?;
        assert_eq!(
            upgrade_response(&digest, parsed.subprotocol())?.as_bytes(),
            decode("response")?
        );
        Ok(())
    }
}
