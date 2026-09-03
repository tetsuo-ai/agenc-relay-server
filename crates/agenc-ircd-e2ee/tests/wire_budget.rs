#![forbid(unsafe_code)]

//! The wire budget (S08-032): the production renderers produce exactly the
//! byte counts the independent generator computed from the grammar, and
//! every plus-one form is refused before allocation.

use std::collections::BTreeMap;
use std::error::Error;

use agenc_ircd_e2ee::limits::MAX_E2EE_SERVER_PREFIX_BYTES;
use agenc_ircd_e2ee::objects::sequencing::{IrcCandidateReceipt, IrcCandidateReceiptTbs};
use agenc_ircd_e2ee::tls::TlsEncode;
use agenc_ircd_e2ee::wire::fragment::{
    CLIENT_FRAGMENT_TAG, FragmentTag, RECEIPT_TAG, ReceiptTag, SERVER_FRAGMENT_TAG, fragment_object,
};
use agenc_ircd_e2ee::wire::response::{
    BatchChild, LiveLine, LiveTags, SuccessLine, render_eobject, render_labeled, render_live,
};
use agenc_ircd_e2ee::wire::tokens::{base64url_encode, parse_u16};
use agenc_ircd_e2ee::{IrcWireObjectKind, ObjectId};

type TestResult = Result<(), Box<dyn Error>>;

const BUDGET_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../conformance/e2ee-wire-budget.toml"
);

fn budget() -> Result<BTreeMap<String, usize>, Box<dyn Error>> {
    let text = std::fs::read_to_string(BUDGET_PATH)?;
    let mut values = BTreeMap::new();
    let mut section = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            section = line.trim_matches(|c| c == '[' || c == ']').to_owned();
            continue;
        }
        let Some((key, value)) = line.split_once(" = ") else {
            continue;
        };
        values.insert(format!("{section}.{key}"), value.parse::<usize>()?);
    }
    Ok(values)
}

fn expect(values: &BTreeMap<String, usize>, key: &str) -> Result<usize, Box<dyn Error>> {
    values
        .get(&format!("budget.{key}"))
        .copied()
        .ok_or_else(|| format!("missing budget key {key}").into())
}

fn object(length: usize) -> Vec<u8> {
    (0..length).map(|index| (index % 241) as u8).collect()
}

fn fragment_zero(length: usize) -> Result<FragmentTag, Box<dyn Error>> {
    Ok(fragment_object(&object(length))?
        .into_iter()
        .next()
        .ok_or("fragment zero")?)
}

/// The widest fragment of a maximal object: a full segment behind a
/// four-digit index, one before the shorter final fragment.
fn widest_fragment(length: usize) -> Result<FragmentTag, Box<dyn Error>> {
    let fragments = fragment_object(&object(length))?;
    let index = fragments.len().checked_sub(2).ok_or("two fragments")?;
    Ok(fragments.into_iter().nth(index).ok_or("widest fragment")?)
}

fn client_tag_with_label(fragment: &FragmentTag) -> String {
    format!(
        "{CLIENT_FRAGMENT_TAG}={};label={}",
        fragment.render(),
        "L".repeat(64)
    )
}

fn receipt() -> Result<ReceiptTag, Box<dyn Error>> {
    let receipt = IrcCandidateReceipt {
        tbs: IrcCandidateReceiptTbs {
            profile_version: 1,
            network_id: [1; 32],
            conversation_id: [2; 32],
            route_sequence: u64::MAX,
            prior_epoch: u64::MAX,
            resulting_epoch: u64::MAX,
            candidate_sequence: u32::MAX,
            commit_object_id: [3; 32],
            prior_state_id: [4; 32],
            predecessor_record_id: [5; 32],
            sequenced_at: u64::MAX,
            sequencer_key_id: [6; 32],
        },
        sequencer_signature: [7; 64],
    };
    Ok(ReceiptTag {
        candidate_id: [8; 32],
        receipt: receipt.encode()?,
    })
}

#[test]
fn the_generator_and_the_renderers_agree_on_every_tag_form() -> TestResult {
    let values = budget()?;
    assert_eq!(
        client_tag_with_label(&fragment_zero(65_536)?).len(),
        expect(&values, "application_fragment_zero_tag")?
    );
    assert_eq!(
        client_tag_with_label(&fragment_zero(262_144)?).len(),
        expect(&values, "live_control_fragment_zero_tag")?
    );
    assert_eq!(
        client_tag_with_label(&fragment_zero(4_194_304)?).len(),
        expect(&values, "control_fragment_zero_tag")?
    );
    let mailbox = format!(
        "{SERVER_FRAGMENT_TAG}={};batch={}",
        widest_fragment(4_194_304)?.render(),
        "B".repeat(64)
    );
    assert_eq!(
        mailbox.len(),
        expect(&values, "mailbox_fragment_tag_with_batch")?
    );
    let receipt = receipt()?;
    assert_eq!(
        receipt.receipt.len(),
        expect(&values, "candidate_receipt_bytes")?
    );
    assert_eq!(
        format!(";{RECEIPT_TAG}={}", receipt.render()).len(),
        expect(&values, "receipt_tag_with_separator")?
    );
    let account = "A".repeat(512 - "account=".len());
    let echo = render_live(
        "n!u@h",
        &LiveTags {
            label: Some(&"L".repeat(64)),
            account: Some(&account),
            receipt: Some(&receipt),
        },
        &fragment_zero(262_144)?,
        &LiveLine::Candidate([1; 32], [2; 32], [8; 32]),
    )?;
    let tag_section = echo.split(' ').next().ok_or("tags")?;
    assert_eq!(
        tag_section.len(),
        expect(&values, "candidate_echo_combined_tags")?
    );
    assert!(tag_section.len() <= expect(&values, "max_combined_tags")?);
    Ok(())
}

#[test]
fn the_longest_lines_fit_the_traditional_budget() -> TestResult {
    let values = budget()?;
    let prefix = "p".repeat(MAX_E2EE_SERVER_PREFIX_BYTES);
    let success = render_labeled(
        "x",
        &prefix,
        &SuccessLine::ReinitActivated([1; 32], [2; 32], [3; 32], [4; 32]),
    )?;
    let non_tag = success.len() - "@label=x ".len();
    assert_eq!(non_tag, expect(&values, "longest_success_non_tag")?);
    assert!(non_tag <= expect(&values, "max_non_tag_line")?);
    let child = BatchChild::Claimed([1; 16], vec![9; 32], [2; 32]).render(&prefix, "b")?;
    assert_eq!(
        child.len() - "@batch=b ".len(),
        expect(&values, "longest_batch_child_non_tag")?
    );
    let fragment = widest_fragment(4_194_304)?;
    let eobject = render_eobject(
        &prefix,
        &"B".repeat(64),
        &fragment,
        IrcWireObjectKind::ReinitActivationCertificate,
        &[1; 16],
    )?;
    let (tags, rest) = eobject.split_once(' ').ok_or("tags")?;
    assert_eq!(tags.len() - 1, expect(&values, "eobject_tags")?);
    assert_eq!(rest.len(), expect(&values, "longest_eobject_non_tag")?);
    let longest_command = format!(
        "EKEY FETCH BINDING-LOCKS {} {} {} {}\r\n",
        base64url_encode(&[1; 24]),
        base64url_encode(&[2; 32]),
        u64::MAX,
        base64url_encode(&[3; 32])
    );
    assert_eq!(
        longest_command.len(),
        expect(&values, "longest_client_command_non_tag")?
    );
    assert_eq!(
        expect(&values, "max_client_physical_line")?,
        1 + 4_094 + 1 + 512
    );
    assert_eq!(expect(&values, "max_server_physical_line")?, 8_703);
    Ok(())
}

#[test]
fn plus_one_forms_are_refused_before_allocation() -> TestResult {
    let fragment = fragment_zero(65_536)?;
    let rendered = fragment.render();
    let oversized = format!("{rendered}A");
    assert!(
        FragmentTag::parse(&oversized).is_err(),
        "one extra segment character"
    );
    let mut long_total = fragment.clone();
    long_total.total = 4_194_305;
    long_total.count = 1_428;
    assert!(
        FragmentTag::parse(&long_total.render()).is_err(),
        "an eight-digit total is rejected by width"
    );
    assert!(parse_u16("65536").is_err());
    let prefix = "p".repeat(MAX_E2EE_SERVER_PREFIX_BYTES + 1);
    assert!(render_labeled("x", &prefix, &SuccessLine::Bound([1; 32], [2; 32])).is_err());
    let mut wrong_id = fragment;
    wrong_id.object_id = ObjectId::from_bytes([0; 32]);
    assert_eq!(wrong_id.render().len(), rendered.len());
    Ok(())
}
