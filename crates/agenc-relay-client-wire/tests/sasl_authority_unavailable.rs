#![forbid(unsafe_code)]

//! RUN-09 (issue #152): an unavailable account authority and a refused
//! credential leave the SASL carrier through different doors, and only the
//! first carries the Section 9.5 failure line ahead of the shared numeric.

use std::error::Error;

use agenc_relay_client_wire::{
    ACCOUNT_REQUEST_BYTES, ACCOUNT_RESPONSE_BYTES, AUTH_CHUNK_CHARACTERS, CapRequestReply,
    CapabilityProfile, CapabilitySpec, CapabilityState, OutputBudget, RenderError, ReplyKind,
    SafeReplyContext, SafeReplyDescription, SaslAction, SaslNumeric, SaslTransport, standard_reply,
};
use agenc_relay_types::{ChannelName, PublicErrorCode};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

struct ExactBudget(usize);

impl OutputBudget for ExactBudget {
    type Permit = ();

    fn try_reserve_exact(&mut self, bytes: usize) -> Result<Self::Permit, RenderError> {
        (bytes == self.0)
            .then_some(())
            .ok_or(RenderError::ReservationFailed)
    }
}

fn feed_request(sasl: &mut SaslTransport, now: u64) -> Result<(), Box<dyn Error>> {
    let encoded = STANDARD.encode(vec![7_u8; ACCOUNT_REQUEST_BYTES]);
    for chunk in encoded.as_bytes().chunks(AUTH_CHUNK_CHARACTERS) {
        sasl.client(std::str::from_utf8(chunk)?, now)?;
    }
    Ok(())
}

/// A carrier that has sent its finish envelope and is waiting for the
/// account service to answer it.
fn awaiting_outcome() -> Result<SaslTransport, Box<dyn Error>> {
    let mut sasl = SaslTransport::new()?;
    sasl.client("AGENC-OPAQUE", 0)?;
    feed_request(&mut sasl, 1)?;
    sasl.server_response(&[9_u8; ACCOUNT_RESPONSE_BYTES], 1)?;
    feed_request(&mut sasl, 2)?;
    sasl.server_response(&[9_u8; ACCOUNT_RESPONSE_BYTES], 2)?;
    Ok(sasl)
}

fn negotiated(names: &[&str]) -> Result<CapabilityState, Box<dyn Error>> {
    let advertised = CapabilityProfile::new(
        names
            .iter()
            .map(|name| CapabilitySpec::new(name, None))
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    let mut capabilities = CapabilityState::default();
    capabilities.ls(Some("302"), &advertised)?;
    for name in names {
        assert!(matches!(
            capabilities.request(name, &advertised)?,
            CapRequestReply::Ack(_)
        ));
    }
    Ok(capabilities)
}

#[test]
fn an_unavailable_authority_reports_itself_before_the_shared_numeric() -> Result<(), Box<dyn Error>>
{
    // The waiting phases are exactly the ones an account-service request can
    // be abandoned in, and each reports the authority before the numeric.
    for stage in 0..3_u8 {
        let mut sasl = SaslTransport::new()?;
        sasl.client("AGENC-OPAQUE", 0)?;
        feed_request(&mut sasl, 1)?;
        if stage > 0 {
            sasl.server_response(&[9_u8; ACCOUNT_RESPONSE_BYTES], 1)?;
            feed_request(&mut sasl, 2)?;
        }
        if stage > 1 {
            sasl.server_response(&[9_u8; ACCOUNT_RESPONSE_BYTES], 2)?;
        }
        assert!(
            matches!(
                sasl.unavailable(3)?.as_slice(),
                [
                    SaslAction::AuthorityUnavailable,
                    SaslAction::Numeric(SaslNumeric::Failed),
                ]
            ),
            "stage {stage}"
        );
    }
    Ok(())
}

#[test]
fn a_refused_credential_carries_the_numeric_alone() -> Result<(), Box<dyn Error>> {
    let mut rejected = awaiting_outcome()?;
    assert!(matches!(
        rejected.complete(false, 3)?.as_slice(),
        [SaslAction::Numeric(SaslNumeric::Failed)]
    ));

    // An accepted authentication never reports the authority either, so the
    // new line cannot be confused with a success.
    let mut accepted = awaiting_outcome()?;
    assert!(matches!(
        accepted.complete(true, 3)?.as_slice(),
        [SaslAction::Numeric(SaslNumeric::Success)]
    ));
    Ok(())
}

#[test]
fn every_other_refusal_keeps_the_numeric_it_has_today() -> Result<(), Box<dyn Error>> {
    let mut aborted = SaslTransport::new()?;
    aborted.client("AGENC-OPAQUE", 0)?;
    assert!(matches!(
        aborted.client("*", 1)?.as_slice(),
        [SaslAction::Numeric(SaslNumeric::Aborted)]
    ));

    let mut expired = SaslTransport::new()?;
    expired.client("AGENC-OPAQUE", 0)?;
    assert!(matches!(
        expired.tick(30_000)?.as_slice(),
        [SaslAction::Numeric(SaslNumeric::Failed)]
    ));

    let mut logout = awaiting_outcome()?;
    logout.complete(true, 3)?;
    logout.client("*", 4)?;
    assert!(matches!(
        logout.reject_logout()?.as_slice(),
        [SaslAction::Numeric(SaslNumeric::Failed)]
    ));
    Ok(())
}

#[test]
fn the_failure_line_is_a_recognized_shape_that_carries_no_account_context()
-> Result<(), Box<dyn Error>> {
    let capabilities = negotiated(&["standard-replies"])?;
    let frame = standard_reply(
        &capabilities,
        "server",
        ReplyKind::Fail,
        "AUTHENTICATE",
        PublicErrorCode::UNAVAILABLE,
        &[],
        SafeReplyDescription::new("Account authority unavailable")?,
    )?;
    let measured = frame.measure()?;
    let mut budget = ExactBudget(measured.bytes());
    assert_eq!(
        measured.encode(&mut budget)?.as_bytes(),
        b":server FAIL AUTHENTICATE UNAVAILABLE :Account authority unavailable\r\n"
    );

    // The row's public context is empty, so no context the renderer knows how
    // to carry can be attached to it.
    let channel = ChannelName::parse("#authority")?;
    assert_eq!(
        standard_reply(
            &capabilities,
            "server",
            ReplyKind::Fail,
            "AUTHENTICATE",
            PublicErrorCode::UNAVAILABLE,
            &[SafeReplyContext::Channel(&channel)],
            SafeReplyDescription::new("Account authority unavailable")?,
        )
        .err(),
        Some(RenderError::InapplicableReply)
    );

    // A client that negotiated nothing gets no standard reply at all.
    assert_eq!(
        standard_reply(
            &CapabilityState::default(),
            "server",
            ReplyKind::Fail,
            "AUTHENTICATE",
            PublicErrorCode::UNAVAILABLE,
            &[],
            SafeReplyDescription::new("Account authority unavailable")?,
        )
        .err(),
        Some(RenderError::CapabilityRequired)
    );
    Ok(())
}
