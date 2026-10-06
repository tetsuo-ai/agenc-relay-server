#![forbid(unsafe_code)]

//! AUD-18 (SDK program B-12): the one formatter for a public cloak's visible
//! spelling. Architecture 7.4 frames the two random components as
//! `u-<10 base32>` and `h-<16 base32>.invalid`, and a user mask as
//! `<nickname>!<user field>@<host field>`.

use std::error::Error;

use agenc_relay_client_wire::{
    MAX_USER_MASK_BYTES, OutputBudget, RenderError, VISIBLE_CLOAK_HOST_BYTES,
    VISIBLE_CLOAK_USER_BYTES, VisibleCloak, WireMessage, numeric_reply, user_mask,
};
use agenc_relay_types::PublicCloak;

struct AnyBudget;

impl OutputBudget for AnyBudget {
    type Permit = ();

    fn try_reserve_exact(&mut self, _bytes: usize) -> Result<Self::Permit, RenderError> {
        Ok(())
    }
}

fn wire(message: &WireMessage) -> Result<String, Box<dyn Error>> {
    let rendered = message.measure()?.encode(&mut AnyBudget)?;
    Ok(String::from_utf8(rendered.as_bytes().to_vec())?)
}

fn cloak() -> Result<PublicCloak, Box<dyn Error>> {
    Ok(PublicCloak::parse("abcdefgh23", "ijklmnopqrstuv67")?)
}

#[test]
fn the_visible_fields_frame_both_random_components() -> Result<(), Box<dyn Error>> {
    let visible = VisibleCloak::new(&cloak()?)?;
    assert_eq!(visible.user(), "u-abcdefgh23");
    assert_eq!(visible.host(), "h-ijklmnopqrstuv67.invalid");
    assert_eq!(visible.user().len(), VISIBLE_CLOAK_USER_BYTES);
    assert_eq!(visible.host().len(), VISIBLE_CLOAK_HOST_BYTES);
    assert_eq!(
        (VISIBLE_CLOAK_USER_BYTES, VISIBLE_CLOAK_HOST_BYTES),
        (12, 26)
    );
    Ok(())
}

#[test]
fn a_user_mask_is_the_specified_source_form() -> Result<(), Box<dyn Error>> {
    let expected = "kestrel!u-abcdefgh23@h-ijklmnopqrstuv67.invalid";
    assert_eq!(user_mask("kestrel", &cloak()?)?, expected);
    assert_eq!(VisibleCloak::new(&cloak()?)?.mask("kestrel")?, expected);
    let line = WireMessage::new(expected, "PRIVMSG", &["#garden"], Some("hello"))?;
    assert_eq!(
        wire(&line)?,
        ":kestrel!u-abcdefgh23@h-ijklmnopqrstuv67.invalid PRIVMSG #garden :hello\r\n"
    );
    Ok(())
}

#[test]
fn the_separate_fields_fill_the_whois_user_and_host_parameters() -> Result<(), Box<dyn Error>> {
    let visible = VisibleCloak::new(&cloak()?)?;
    let whois = numeric_reply(
        "server.example",
        311,
        "viewer",
        &["kestrel", visible.user(), visible.host(), "*"],
        Some("Kestrel"),
    )?;
    assert_eq!(
        wire(&whois)?,
        ":server.example 311 viewer kestrel u-abcdefgh23 h-ijklmnopqrstuv67.invalid * :Kestrel\r\n"
    );
    Ok(())
}

#[test]
fn the_longest_nickname_fills_the_mask_bound_exactly() -> Result<(), Box<dyn Error>> {
    let nickname = format!("_{}", "n".repeat(31));
    let mask = user_mask(&nickname, &cloak()?)?;
    assert_eq!(nickname.len(), 32);
    assert_eq!(mask.len(), MAX_USER_MASK_BYTES);
    assert_eq!(MAX_USER_MASK_BYTES, 32 + 1 + 12 + 1 + 26);
    Ok(())
}

#[test]
fn a_nickname_outside_the_grammar_renders_no_mask() -> Result<(), Box<dyn Error>> {
    let visible = VisibleCloak::new(&cloak()?)?;
    let too_long = format!("_{}", "n".repeat(32));
    for nickname in [
        "",
        too_long.as_str(),
        "9lives",
        "-dash",
        "bad!nick",
        "bad@nick",
        "bad nick",
        "bad.nick",
        "bad:nick",
        "caf\u{e9}",
    ] {
        assert_eq!(
            visible.mask(nickname).err(),
            Some(RenderError::InvalidSyntax),
            "{nickname:?}"
        );
        assert_eq!(
            user_mask(nickname, &cloak()?).err(),
            Some(RenderError::InvalidSyntax),
            "{nickname:?}"
        );
    }
    Ok(())
}
