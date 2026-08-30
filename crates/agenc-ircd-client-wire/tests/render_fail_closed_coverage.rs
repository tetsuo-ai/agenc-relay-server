#![forbid(unsafe_code)]

//! Public renderer boundary and fail-closed behavior.

use std::error::Error;

use agenc_ircd_client_wire::{
    CapRequestReply, CapabilityProfile, CapabilitySpec, CapabilityState, MAX_COMMAND_BYTES,
    OutputBudget, RenderError, ReplyKind, SafeReplyDescription, WireMessage, labeled_response,
    numeric_reply, standard_reply,
};
use agenc_ircd_types::PublicErrorCode;

struct ExactBudget(usize);

impl OutputBudget for ExactBudget {
    type Permit = usize;

    fn try_reserve_exact(&mut self, bytes: usize) -> Result<Self::Permit, RenderError> {
        if bytes != self.0 {
            return Err(RenderError::ReservationFailed);
        }
        Ok(bytes)
    }
}

#[test]
fn command_budget_accepts_the_exact_boundary_and_rejects_the_next_byte()
-> Result<(), Box<dyn Error>> {
    let fixed_bytes = 1 + "s".len() + 1 + "NOTICE".len() + 2;
    let exact_trailing = "x".repeat(MAX_COMMAND_BYTES - fixed_bytes);
    let message = WireMessage::new("s", "NOTICE", &[], Some(&exact_trailing))?;
    let measured = message.measure()?;
    let measured_bytes = measured.bytes();
    let mut budget = ExactBudget(measured_bytes);
    let rendered = measured.encode(&mut budget)?;

    assert_eq!(rendered.as_bytes().len(), MAX_COMMAND_BYTES + 2);
    assert_eq!(*rendered.permit(), measured_bytes);

    let oversized = format!("{exact_trailing}x");
    assert_eq!(
        WireMessage::new("s", "NOTICE", &[], Some(&oversized)).err(),
        Some(RenderError::LineBudget)
    );
    Ok(())
}

#[test]
fn notice_standard_reply_allows_syntax_errors_and_suppresses_delivery_errors()
-> Result<(), Box<dyn Error>> {
    let advertised = CapabilityProfile::new(vec![CapabilitySpec::new("standard-replies", None)?])?;
    let mut capabilities = CapabilityState::default();
    capabilities.ls(Some("302"), &advertised)?;
    assert!(matches!(
        capabilities.request("standard-replies", &advertised)?,
        CapRequestReply::Ack(_)
    ));

    let syntax_failure = standard_reply(
        &capabilities,
        "server",
        ReplyKind::Fail,
        "NOTICE",
        PublicErrorCode::INVALIDARGUMENT,
        &[],
        SafeReplyDescription::new("Invalid NOTICE syntax")?,
    )?;
    let measured = syntax_failure.measure()?;
    let mut budget = ExactBudget(measured.bytes());
    let rendered = measured.encode(&mut budget)?;
    assert_eq!(
        rendered.as_bytes(),
        b":server FAIL NOTICE INVALID_ARGUMENT :Invalid NOTICE syntax\r\n"
    );

    for suppressed in [
        PublicErrorCode::NETWORKUNAVAILABLE,
        PublicErrorCode::SERVERBUSY,
        PublicErrorCode::E2EEREQUIRED,
    ] {
        assert_eq!(
            standard_reply(
                &capabilities,
                "server",
                ReplyKind::Fail,
                "NOTICE",
                suppressed,
                &[],
                SafeReplyDescription::new("Suppressed delivery error")?,
            )
            .err(),
            Some(RenderError::InapplicableReply)
        );
    }
    Ok(())
}

#[test]
fn stage_two_numerics_reject_noncanonical_middle_and_trailing_shapes() -> Result<(), Box<dyn Error>>
{
    assert!(
        numeric_reply(
            "server",
            4,
            "nick",
            &["server", "version", "io", "io"],
            None
        )
        .is_ok()
    );
    assert_eq!(
        numeric_reply(
            "server",
            4,
            "nick",
            &["server", "version", "io", "io"],
            Some("not permitted"),
        )
        .err(),
        Some(RenderError::InapplicableReply)
    );
    assert_eq!(
        numeric_reply("server", 4, "nick", &["server", "version", "io"], None).err(),
        Some(RenderError::InapplicableReply)
    );

    let one_isupport = ["NETWORK=AgenC"];
    assert!(numeric_reply("server", 5, "nick", &one_isupport, Some("are supported"),).is_ok());
    let thirteen_isupport = ["TOKEN"; 13];
    assert!(
        numeric_reply(
            "server",
            5,
            "nick",
            &thirteen_isupport,
            Some("are supported"),
        )
        .is_ok()
    );
    for invalid in [
        Vec::new(),
        vec!["TOKEN"; 14],
        vec!["lowercase"],
        vec!["TOKEN="],
        vec!["TOKEN=bad value"],
    ] {
        assert_eq!(
            numeric_reply("server", 5, "nick", &invalid, Some("are supported")).err(),
            Some(RenderError::InapplicableReply),
            "invalid ISUPPORT token list: {invalid:?}"
        );
    }

    assert!(numeric_reply("server", 265, "nick", &["1", "2"], Some("users")).is_ok());
    for invalid in [["", "2"], ["1x", "2"], ["1", "2x"]] {
        assert_eq!(
            numeric_reply("server", 265, "nick", &invalid, Some("users")).err(),
            Some(RenderError::InapplicableReply)
        );
    }
    Ok(())
}

#[test]
fn stage_six_numerics_accept_only_their_registered_parameter_shapes() {
    for (code, middle, trailing) in [
        (221, vec!["+i"], None),
        (303, vec![], Some("")),
        (311, vec!["nick", "user", "host", "*"], Some("Real Name")),
        (322, vec!["#chat", "5"], Some("topic")),
        (324, vec!["#chat", "+im"], None),
        (329, vec!["#chat", "1700000000"], None),
        (333, vec!["#chat", "setter", "1700000000"], None),
        (
            352,
            vec!["#chat", "user", "host", "server", "nick", "H"],
            Some("0 Real Name"),
        ),
        (367, vec!["#chat", "*!*@host", "setter", "1700000000"], None),
        (401, vec!["missing"], Some("No such nick")),
        (
            441,
            vec!["nick", "#chat"],
            Some("They are not on that channel"),
        ),
        (472, vec!["x"], Some("Unknown mode")),
        (482, vec!["#chat"], Some("Permission denied for channel")),
    ] {
        assert!(
            numeric_reply("server", code, "requester", &middle, trailing).is_ok(),
            "registered numeric {code} rejected its canonical shape"
        );
    }

    for (code, middle, trailing) in [
        (221, vec!["i"], None),
        (303, vec![], None),
        (311, vec!["nick", "user", "host"], Some("Real Name")),
        (322, vec!["#chat", "exact"], Some("topic")),
        (324, vec!["#chat"], None),
        (329, vec!["#chat", "not-a-time"], None),
        (333, vec!["#chat", "setter", "not-a-time"], None),
        (
            352,
            vec!["#chat", "user", "host", "server", "nick"],
            Some("0 Real Name"),
        ),
        (367, vec!["#chat", "*!*@host", "setter", "not-a-time"], None),
        (401, vec![], Some("No such nick")),
        (441, vec!["nick"], Some("They are not on that channel")),
        (472, vec!["xx"], Some("Unknown mode")),
        (482, vec!["#chat"], None),
    ] {
        assert_eq!(
            numeric_reply("server", code, "requester", &middle, trailing).err(),
            Some(RenderError::InapplicableReply),
            "registered numeric {code} accepted a noncanonical shape"
        );
    }
}

#[test]
fn numeric_counts_and_isupport_names_use_their_exact_grammars() {
    assert_eq!(
        numeric_reply(
            "server",
            252,
            "nick",
            &["not-decimal"],
            Some("operator count"),
        )
        .err(),
        Some(RenderError::InapplicableReply)
    );
    assert_eq!(
        numeric_reply("server", 5, "nick", &["=value"], Some("are supported")).err(),
        Some(RenderError::InapplicableReply)
    );
}

#[test]
fn labeled_response_validates_correlation_before_rendering_wrappers() -> Result<(), Box<dyn Error>>
{
    let advertised = CapabilityProfile::new(vec![
        CapabilitySpec::new("batch", None)?,
        CapabilitySpec::new("cap-notify", None)?,
        CapabilitySpec::new("labeled-response", None)?,
        CapabilitySpec::new("message-tags", None)?,
    ])?;
    let mut capabilities = CapabilityState::default();
    capabilities.ls(Some("302"), &advertised)?;
    assert!(matches!(
        capabilities.request("message-tags batch labeled-response", &advertised)?,
        CapRequestReply::Ack(_)
    ));

    let message = || WireMessage::new("server", "NOTICE", &["nick"], Some("reply"));
    assert_eq!(
        labeled_response(
            &capabilities,
            "server",
            Some("request-1"),
            None,
            vec![message()?],
        )?
        .messages()
        .len(),
        1
    );
    assert_eq!(
        labeled_response(
            &capabilities,
            "server",
            Some("request-2"),
            None,
            vec![message()?, message()?],
        )
        .err(),
        Some(RenderError::InvalidCorrelation)
    );
    assert_eq!(
        labeled_response(
            &capabilities,
            "server",
            Some("request-2"),
            Some("batch-2"),
            vec![message()?, message()?],
        )?
        .messages()
        .len(),
        4
    );

    for invalid_label in [
        "x".repeat(65),
        "contains space".to_owned(),
        "semi;colon".to_owned(),
    ] {
        assert_eq!(
            labeled_response(
                &capabilities,
                "server",
                Some(&invalid_label),
                None,
                vec![message()?],
            )
            .err(),
            Some(RenderError::InvalidCorrelation)
        );
    }
    Ok(())
}
