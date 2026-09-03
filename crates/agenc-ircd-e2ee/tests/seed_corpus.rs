#![forbid(unsafe_code)]

//! The fuzz seed corpora are written by an independent Python encoder
//! (`scripts/generate-e2ee-fuzz-seeds.py`); every seed must decode under
//! the production codec, which pins the two encoders to each other.

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use agenc_ircd_e2ee::mls_outer::{MlsOuterMessage, parse_mls_message};
use agenc_ircd_e2ee::objects::{TypedBody, decode_body};
use agenc_ircd_e2ee::{DecodeBudget, IrcWireObject, IrcWireObjectKind, TlsDecode as _};

type TestResult = Result<(), Box<dyn Error>>;

fn corpus(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-data/fuzz-corpus")
        .join(name)
}

fn budget() -> DecodeBudget {
    DecodeBudget::new(1 << 22, 1 << 16)
}

#[test]
fn every_object_seed_decodes_to_its_declared_kind() -> TestResult {
    let expected = [
        ("root-identity", IrcWireObjectKind::RootIdentity),
        (
            "sequencer-record-candidate",
            IrcWireObjectKind::SequencerRecord,
        ),
        (
            "device-attach-challenge",
            IrcWireObjectKind::DeviceAttachChallenge,
        ),
        ("commit-ack", IrcWireObjectKind::CommitAck),
        ("federation-origin", IrcWireObjectKind::FederationOrigin),
        ("application-mls", IrcWireObjectKind::ApplicationMls),
        ("commit-mls", IrcWireObjectKind::CommitMls),
        ("key-package-mls", IrcWireObjectKind::KeyPackageMls),
    ];
    for (name, kind) in expected {
        let bytes = fs::read(corpus("e2ee-object").join(name))?;
        assert_eq!(IrcWireObject::peek(&bytes)?.0, kind, "{name}");
        let object = IrcWireObject::decode_exact(&bytes, &mut budget())?;
        let body = decode_body(&object, &mut budget())?;
        assert_eq!(body.kind(), kind, "{name}");
        if let TypedBody::FederationOrigin(origin) = &body {
            assert_eq!(origin.account_id.len(), 24);
        }
    }
    let entries = fs::read_dir(corpus("e2ee-object"))?.count();
    assert_eq!(entries, expected.len());
    Ok(())
}

#[test]
fn every_mls_seed_parses() -> TestResult {
    for (name, private) in [
        ("private-application", true),
        ("private-commit", true),
        ("welcome", false),
        ("key-package", false),
    ] {
        let bytes = fs::read(corpus("e2ee-mls-outer").join(name))?;
        let parsed = parse_mls_message(&bytes, &mut budget())?;
        assert_eq!(
            matches!(parsed, MlsOuterMessage::Private(_)),
            private,
            "{name}"
        );
    }
    Ok(())
}

#[test]
fn every_fragment_seed_parses_as_its_kind() -> TestResult {
    use agenc_ircd_e2ee::wire::command::parse_command;
    use agenc_ircd_e2ee::wire::fragment::{FragmentTag, ReceiptTag};
    for name in ["fragment-single", "fragment-zero", "fragment-last"] {
        let text = fs::read_to_string(corpus("e2ee-fragment").join(name))?;
        let tag = FragmentTag::parse(&text)?;
        assert_eq!(tag.render(), text, "{name}");
    }
    let receipt = fs::read_to_string(corpus("e2ee-fragment").join("receipt"))?;
    assert_eq!(ReceiptTag::parse(&receipt)?.render(), receipt);
    for name in ["command-bind", "command-binding-locks", "command-edirect"] {
        let text = fs::read_to_string(corpus("e2ee-fragment").join(name))?;
        let mut words = text.split(' ');
        let command = words.next().ok_or("command")?;
        let params: Vec<&str> = words.collect();
        parse_command(command, &params)?;
    }
    Ok(())
}
