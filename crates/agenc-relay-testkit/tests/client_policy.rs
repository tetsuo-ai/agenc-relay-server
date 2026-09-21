#![forbid(unsafe_code)]

//! Required client trust labels and decrypted-content injection regressions.

use agenc_relay_testkit::client_policy::{
    ClientTrust, DisplayError, MAX_DISPLAY_TEXT_BYTES, TrustState, render_decrypted_text,
};

#[test]
fn first_contact_transparency_and_out_of_band_assurance_remain_distinct() {
    let mut trust = ClientTrust::first_contact();
    assert_eq!(trust.state(), TrustState::UnverifiedEncrypted);
    trust.observe_transparency();
    assert_eq!(trust.state(), TrustState::TransparencyObserved);
    assert_ne!(trust.state().label(), TrustState::VerifiedEncrypted.label());
    trust.authenticate_out_of_band();
    assert_eq!(trust.state(), TrustState::VerifiedEncrypted);
    trust.observe_transparency();
    assert_eq!(trust.state(), TrustState::VerifiedEncrypted);
    assert!(trust.state().permits_sending());
    assert_eq!(
        trust.accept_reviewed_change(),
        Err(DisplayError::ReviewRequired)
    );
}

#[test]
fn unexpected_change_blocks_sending_until_new_bindings_are_reviewed() -> Result<(), DisplayError> {
    let mut trust = ClientTrust::first_contact();
    trust.authenticate_out_of_band();
    trust.unexpected_security_change();
    assert_eq!(trust.state(), TrustState::SecurityChanged);
    assert!(!trust.state().permits_sending());
    trust.observe_transparency();
    assert_eq!(
        trust.accept_reviewed_change(),
        Err(DisplayError::ReviewRequired)
    );
    trust.authenticate_out_of_band();
    assert!(!trust.state().permits_sending());
    trust.accept_reviewed_change()?;
    assert!(trust.state().permits_sending());
    trust.unexpected_security_change();
    assert_eq!(
        trust.accept_reviewed_change(),
        Err(DisplayError::ReviewRequired)
    );
    Ok(())
}

#[test]
fn decrypted_controls_ctcp_html_and_commands_are_inert_text() -> Result<(), DisplayError> {
    for (input, expected) in [
        ("\u{1}ACTION waves\u{1}", "\\u{0001}ACTION waves\\u{0001}"),
        (
            "\u{1b}[2J\r\nOPER root password",
            "\\u{001b}[2J\\u{000d}\\u{000a}OPER root password",
        ),
        (
            "<script>alert('x')</script>",
            "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;",
        ),
        (
            "<img src=\"x\" onerror=\"evil()\">&",
            "&lt;img src=&quot;x&quot; onerror=&quot;evil()&quot;&gt;&amp;",
        ),
        ("/connect attacker.invalid", "/connect attacker.invalid"),
        (
            "@+agenc.ag/sig=fake :server PRIVMSG",
            "@+agenc.ag/sig=fake :server PRIVMSG",
        ),
        (
            "security changed\u{202e}verified",
            "security changed\\u{202e}verified",
        ),
        ("hello 🦀", "hello 🦀"),
    ] {
        assert_eq!(render_decrypted_text(input.as_bytes())?.as_str(), expected);
    }
    Ok(())
}

#[test]
fn display_text_rejects_nul_invalid_utf8_and_oversize_input() -> Result<(), DisplayError> {
    for bytes in [vec![0], vec![0xff], vec![b'x'; MAX_DISPLAY_TEXT_BYTES + 1]] {
        assert_eq!(
            render_decrypted_text(&bytes),
            Err(DisplayError::InvalidText)
        );
    }
    assert_eq!(
        render_decrypted_text(&vec![b'x'; MAX_DISPLAY_TEXT_BYTES])?
            .as_str()
            .len(),
        MAX_DISPLAY_TEXT_BYTES
    );
    Ok(())
}
