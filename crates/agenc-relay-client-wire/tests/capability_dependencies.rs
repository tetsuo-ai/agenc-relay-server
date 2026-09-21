#![forbid(unsafe_code)]

//! Appendix A.3 capability dependency coverage.

use std::error::Error;

use agenc_relay_client_wire::{
    CapError, CapRequestReply, CapabilityProfile, CapabilitySpec, CapabilityState,
};

const E2EE_VALUE: &str = concat!(
    "v1,profile=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,",
    "seg=2940,obj=262144,parts=90,welcome=4194304"
);
const PARSER_BACKED_CAPABILITIES: &[&str] = &["account-tag", "server-time", "message-ids", "batch"];

#[test]
fn parser_backed_capabilities_negotiate_independently() -> Result<(), Box<dyn Error>> {
    for capability in PARSER_BACKED_CAPABILITIES {
        let advertised = profile(&[capability])?;
        let mut state = CapabilityState::default();
        assert!(matches!(
            state.request(capability, &advertised)?,
            CapRequestReply::Ack(_)
        ));
        assert_eq!(state.list()?, [capability.to_string()]);
    }
    Ok(())
}

#[test]
fn composed_dependencies_match_appendix_a3_and_the_e2ee_companion() -> Result<(), Box<dyn Error>> {
    assert_invalid(&["message-tags", "labeled-response"])?;
    profile(&["message-tags", "batch", "labeled-response"])?;

    assert_invalid(&["extended-join"])?;
    profile(&["account-notify", "extended-join"])?;

    assert_invalid(&[
        "message-tags",
        "server-time",
        "message-ids",
        "draft/chathistory",
    ])?;
    assert_invalid(&["message-tags", "batch", "message-ids", "draft/chathistory"])?;
    assert_invalid(&["message-tags", "batch", "server-time", "draft/chathistory"])?;
    profile(&[
        "message-tags",
        "batch",
        "server-time",
        "message-ids",
        "draft/chathistory",
    ])?;

    let e2ee_dependencies = [
        "message-tags",
        "echo-message",
        "batch",
        "labeled-response",
        "standard-replies",
        "account-tag",
    ];
    for omitted in e2ee_dependencies {
        let mut incomplete = Vec::new();
        incomplete.try_reserve_exact(e2ee_dependencies.len())?;
        incomplete.extend(
            e2ee_dependencies
                .iter()
                .copied()
                .filter(|dependency| *dependency != omitted),
        );
        incomplete.push("agenc.ag/e2ee-mls");
        assert_invalid(&incomplete)?;
    }
    let mut complete = e2ee_dependencies.to_vec();
    complete.push("agenc.ag/e2ee-mls");
    profile(&complete)?;
    Ok(())
}

#[test]
fn appendix_a3_standalone_capabilities_have_no_graph_dependencies() -> Result<(), Box<dyn Error>> {
    for capability in [
        "account-notify",
        "away-notify",
        "cap-notify",
        "echo-message",
        "invite-notify",
        "message-tags",
        "monitor",
        "multi-prefix",
        "sasl",
        "setname",
        "standard-replies",
        "userhost-in-names",
        "utf8only",
        "agenc.ag/privacy",
        "agenc.ag/account-controls",
        "agenc.ag/account-credentials",
        "agenc.ag/channel-controls",
        "agenc.ag/recovery",
        "sts",
        "agenc.ag/account-create",
    ] {
        profile(&[capability])?;
    }
    Ok(())
}

fn assert_invalid(names: &[&str]) -> Result<(), Box<dyn Error>> {
    assert_eq!(profile(names).err(), Some(CapError::InvalidAdvertisement));
    Ok(())
}

fn profile(names: &[&str]) -> Result<CapabilityProfile, CapError> {
    let mut capabilities = Vec::new();
    capabilities
        .try_reserve_exact(names.len())
        .map_err(|_| CapError::AllocationFailed)?;
    for name in names {
        capabilities.push(spec(name)?);
    }
    CapabilityProfile::new(capabilities)
}

fn spec(name: &str) -> Result<CapabilitySpec, CapError> {
    let value = match name {
        "agenc.ag/privacy"
        | "agenc.ag/account-controls"
        | "agenc.ag/account-credentials"
        | "agenc.ag/channel-controls"
        | "agenc.ag/account-create" => Some("v1"),
        "agenc.ag/recovery" => Some("v1.AAAAAAAAAAAAAAAAAAAAAA"),
        "agenc.ag/e2ee-mls" => Some(E2EE_VALUE),
        "sasl" => Some("AGENC-OPAQUE"),
        "sts" => Some("duration=31536000"),
        _ => None,
    };
    CapabilitySpec::new(name, value)
}
