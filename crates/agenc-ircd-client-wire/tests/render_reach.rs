#![forbid(unsafe_code)]

//! Renderer parameter, tag, batch and capability rules reached one at a time.

use std::error::Error;

use agenc_ircd_client_wire::{
    BatchStack, CapRequestReply, CapabilityProfile, CapabilitySpec, CapabilityState,
    MAX_BATCH_NESTING, MAX_COMMAND_BYTES, MAX_PARAMETERS, MAX_SERVER_TAG_DATA_BYTES, RenderError,
    WireMessage, isupport_messages, labeled_response,
};

type TestResult = Result<(), Box<dyn Error>>;

/// Advertises every batch-related capability and requests only `names`.
fn capabilities(names: &[&str]) -> Result<(CapabilityState, CapRequestReply), Box<dyn Error>> {
    let advertised = CapabilityProfile::new(vec![
        CapabilitySpec::new("batch", None)?,
        CapabilitySpec::new("labeled-response", None)?,
        CapabilitySpec::new("server-time", None)?,
        CapabilitySpec::new("message-ids", None)?,
        CapabilitySpec::new("draft/chathistory", None)?,
    ])?;
    let mut state = CapabilityState::default();
    state.ls(Some("302"), &advertised)?;
    let reply = state.request(&names.join(" "), &advertised)?;
    Ok((state, reply))
}

#[test]
fn parameters_are_counted_and_shaped() {
    let many: Vec<&str> = vec!["p"; MAX_PARAMETERS + 1];
    assert_eq!(
        WireMessage::new("s", "NOTICE", &many, None).err(),
        Some(RenderError::InvalidSyntax)
    );
    for middle in [[""], [":x"], ["a b"]] {
        assert_eq!(
            WireMessage::new("s", "NOTICE", &middle, None).err(),
            Some(RenderError::InvalidSyntax),
            "{middle:?}"
        );
    }
    assert_eq!(
        WireMessage::new("s", "NOTICE", &["t"], Some("a\nb")).err(),
        Some(RenderError::InvalidSyntax)
    );
}

#[test]
fn oversized_tag_keys_and_values_exceed_the_line_budget() -> TestResult {
    let mut message = WireMessage::new("s", "NOTICE", &["t"], Some("x"))?;
    let long = "k".repeat(5_000);
    assert_eq!(
        message.add_server_tag(&long, None).err(),
        Some(RenderError::LineBudget)
    );
    assert_eq!(
        message.add_server_tag("time", Some(&long)).err(),
        Some(RenderError::LineBudget)
    );
    Ok(())
}

#[test]
fn isupport_display_names_are_bounded() -> TestResult {
    let network = agenc_ircd_types::NetworkId::from_bytes([1; 32]);
    let long = "n".repeat(9_000);
    assert_eq!(
        isupport_messages("s", "nick", &long, &network).err(),
        Some(RenderError::InvalidSyntax)
    );
    Ok(())
}

#[test]
fn a_multi_message_labeled_response_needs_the_batch_capability() -> TestResult {
    let (labeled, reply) = capabilities(&["labeled-response"])?;
    let one = vec![WireMessage::new("s", "NOTICE", &["t"], Some("x"))?];
    assert_eq!(
        labeled_response(&labeled, "s", Some("l"), None, one)?
            .messages()
            .len(),
        1
    );
    let two = vec![
        WireMessage::new("s", "NOTICE", &["t"], Some("x"))?,
        WireMessage::new("s", "NOTICE", &["t"], Some("y"))?,
    ];
    let outcome = labeled_response(&labeled, "s", Some("l"), Some("b"), two);
    match reply {
        CapRequestReply::Ack(_) => {
            assert_eq!(outcome.err(), Some(RenderError::CapabilityRequired));
        }
        _ => assert_eq!(outcome?.messages().len(), 2),
    }
    Ok(())
}

#[test]
fn batches_need_their_capabilities_unique_bounded_ids_and_nest_under_a_parent() -> TestResult {
    let none = CapabilityState::default();
    let (batch_only, _) = capabilities(&["batch"])?;
    let (full, reply) = capabilities(&[
        "batch",
        "labeled-response",
        "server-time",
        "message-ids",
        "draft/chathistory",
    ])?;
    assert!(matches!(reply, CapRequestReply::Ack(_)));
    let mut stack = BatchStack::default();
    assert_eq!(
        stack.open_history(&none, "s", "h", "#c").err(),
        Some(RenderError::CapabilityRequired)
    );
    assert_eq!(
        stack.open_history(&batch_only, "s", "h", "#c").err(),
        Some(RenderError::CapabilityRequired)
    );
    assert_eq!(
        stack.open(&batch_only, "s", "b", "label").err(),
        Some(RenderError::CapabilityRequired)
    );
    let long = "i".repeat(65);
    assert!(stack.open(&full, "s", &long, "label").is_err());

    let mut stack = BatchStack::default();
    stack.open(&full, "s", "outer", "label")?;
    let nested = stack.open_history(&full, "s", "inner", "#c")?;
    assert_eq!(nested.command(), "BATCH");
    assert_eq!(
        stack.open_history(&full, "s", "inner", "#c").err(),
        Some(RenderError::InvalidBatch)
    );

    let mut stack = BatchStack::default();
    for index in 0..MAX_BATCH_NESTING {
        stack.open(&full, "s", &format!("b{index}"), "label")?;
    }
    assert_eq!(
        stack.open(&full, "s", "overflow", "label").err(),
        Some(RenderError::InvalidBatch)
    );
    Ok(())
}

#[test]
fn a_command_over_its_byte_budget_is_refused_before_it_is_built() {
    let long = "x".repeat(MAX_COMMAND_BYTES);
    assert_eq!(
        WireMessage::new("s", "NOTICE", &[long.as_str()], None).err(),
        Some(RenderError::LineBudget)
    );
}

#[test]
fn tag_budgets_bound_a_server_tag_and_the_whole_physical_line() -> TestResult {
    let mut message = WireMessage::new("s", "NOTICE", &["#chan"], Some("hello"))?;
    let oversized = "v".repeat(MAX_SERVER_TAG_DATA_BYTES);
    assert_eq!(
        message
            .add_server_tag("big", Some(oversized.as_str()))
            .err(),
        Some(RenderError::LineBudget)
    );
    // A near-maximal command plus one small tag crosses the physical line.
    let body = "b".repeat(MAX_COMMAND_BYTES - ":s NOTICE #chan :".len());
    let mut full = WireMessage::new("s", "NOTICE", &["#chan"], Some(body.as_str()))?;
    assert!(full.measure().is_ok());
    full.add_server_tag("a", Some("bc"))?;
    assert_eq!(full.measure().err(), Some(RenderError::LineBudget));
    Ok(())
}

#[test]
fn a_history_batch_cannot_repeat_an_open_id_or_nest_beyond_the_ceiling() -> TestResult {
    let (state, _) = capabilities(&[
        "batch",
        "labeled-response",
        "server-time",
        "message-ids",
        "draft/chathistory",
    ])?;
    let mut stack = BatchStack::default();
    let _first = stack.open_history(&state, "s", "h0", "#chan")?;
    assert_eq!(
        stack.open_history(&state, "s", "h0", "#chan").err(),
        Some(RenderError::InvalidBatch)
    );
    for depth in 1..MAX_BATCH_NESTING {
        let id = format!("h{depth}");
        let _opened = stack.open_history(&state, "s", &id, "#chan")?;
    }
    assert_eq!(stack.depth(), MAX_BATCH_NESTING);
    assert_eq!(
        stack.open_history(&state, "s", "deep", "#chan").err(),
        Some(RenderError::InvalidBatch)
    );
    Ok(())
}
