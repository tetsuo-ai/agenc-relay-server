#![forbid(unsafe_code)]
//! History correlation uses live batch ownership and the existing label validator.

use agenc_relay_client_wire::{
    BatchStack, CapRequestReply, CapabilityProfile, CapabilitySpec, CapabilityState, RenderError,
    WireMessage, labeled_response,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn capabilities() -> Result<CapabilityState, Box<dyn std::error::Error>> {
    let names = [
        "message-tags",
        "batch",
        "server-time",
        "message-ids",
        "draft/chathistory",
        "labeled-response",
    ];
    let profile = CapabilityProfile::new(
        names
            .iter()
            .map(|name| CapabilitySpec::new(name, None))
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    let mut state = CapabilityState::default();
    assert!(matches!(
        state.request(&names.join(" "), &profile)?,
        CapRequestReply::Ack(_)
    ));
    Ok(state)
}

#[test]
fn history_batches_require_capability_unique_ids_and_owned_correlation() -> TestResult {
    let mut stack = BatchStack::default();
    let caps = capabilities()?;
    assert_eq!(
        stack.open_history(&CapabilityState::default(), "node.test", "h1", "#history"),
        Err(RenderError::CapabilityRequired)
    );
    let opening = stack.open_history(&caps, "node.test", "h1", "#history")?;
    let labeled = labeled_response(&caps, "node.test", Some("original"), None, vec![opening])?;
    assert_eq!(labeled.messages().len(), 1);
    assert_eq!(
        stack.open_history(&caps, "node.test", "h1", "#history"),
        Err(RenderError::InvalidBatch)
    );
    let mut message = WireMessage::new("sender!user@host", "PRIVMSG", &["#history"], Some("body"))?;
    assert_eq!(
        message.add_server_tag("batch", Some("h1")),
        Err(RenderError::InvalidSyntax)
    );
    stack.attach("h1", &mut message)?;
    message.measure()?;
    let _close = stack.close("node.test", "h1")?;
    assert_eq!(
        stack.attach("h1", &mut message),
        Err(RenderError::InvalidBatch)
    );
    assert_eq!(stack.depth(), 0);
    Ok(())
}

#[cfg(feature = "wss")]
#[test]
fn upgrade_errors_map_to_fixed_nonreflective_http_responses() {
    use agenc_relay_client_wire::websocket_transport::UpgradeError;
    for (error, status) in [
        (UpgradeError::Malformed, "400"),
        (UpgradeError::Origin, "403"),
        (UpgradeError::Endpoint, "404"),
        (UpgradeError::Method, "405"),
        (UpgradeError::Version, "426"),
        (UpgradeError::Headers, "431"),
        (UpgradeError::RequestLine, "414"),
        (UpgradeError::Timeout, "408"),
    ] {
        let bytes = error.response();
        assert!(bytes.starts_with(format!("HTTP/1.1 {status} ").as_bytes()));
        assert!(bytes.ends_with(b"Content-Length: 0\r\n\r\n"));
        assert!(
            bytes
                .windows(b"Connection: close".len())
                .any(|part| part == b"Connection: close")
        );
    }
}
