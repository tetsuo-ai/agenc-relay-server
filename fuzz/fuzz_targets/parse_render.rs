#![forbid(unsafe_code)]
#![no_main]

use agenc_ircd_client_wire::{
    CapabilityProfile, CapabilitySpec, CapabilityState, FramedLine, MAX_CLIENT_TAG_DATA_BYTES,
    MAX_COMMAND_BYTES, MAX_PHYSICAL_LINE_BYTES, MAX_SERVER_TAG_DATA_BYTES,
    MAX_TRADITIONAL_LINE_BYTES, OutputBudget, RenderError, WireMessage, parse_client_tags,
    parse_message, render_tags,
};
use libfuzzer_sys::fuzz_target;

const MAX_RENDER_TAG_OPERATIONS: usize = 20;
const E2EE_TAG: &str = "+agenc.ag/e2ee";
const EXACT_TAGMSG_FIXED_BYTES: usize = 13;

struct Permit;

struct FuzzBudget {
    maximum: usize,
    requested: Option<usize>,
}

impl FuzzBudget {
    const fn new(maximum: usize) -> Self {
        Self {
            maximum,
            requested: None,
        }
    }
}

impl OutputBudget for FuzzBudget {
    type Permit = Permit;

    fn try_reserve_exact(&mut self, bytes: usize) -> Result<Self::Permit, RenderError> {
        self.requested = Some(bytes);
        if bytes > self.maximum {
            return Err(RenderError::ReservationFailed);
        }
        Ok(Permit)
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 16_384 {
        return;
    }

    let raw = corpus_payload(data);
    if let Ok(text) = std::str::from_utf8(raw)
        && let Ok(line) = FramedLine::new(text)
        && let Ok(Some(parsed)) = parse_message(line)
        && !parsed.tags().is_empty()
        && let Ok(canonical) = render_tags(parsed.tags())
    {
        assert_eq!(parsed.wire_bytes(), text.len());
        assert!(parsed.tags().len() <= MAX_CLIENT_TAG_DATA_BYTES.div_ceil(2));
        let reparsed = parse_client_tags(&canonical);
        assert_eq!(reparsed.as_ref(), Ok(parsed.tags()));
        assert_eq!(reparsed.and_then(|tags| render_tags(&tags)), Ok(canonical),);
    }

    let Ok(capabilities) = message_tag_capabilities() else {
        return;
    };

    exercise_exact_tag_parse_boundaries();
    exercise_boundary_render_plan(data, &capabilities);
    exercise_exact_render_boundaries(&capabilities);

    let safe = safe_text(data, 256);
    let Ok(message) = WireMessage::new("server.invalid", "NOTICE", &["target"], Some(&safe)) else {
        return;
    };
    exercise_render_oracle(message, None);

    let mut tagged = match WireMessage::new("server.invalid", "NOTICE", &["target"], Some("tags")) {
        Ok(message) => message,
        Err(_) => return,
    };
    let tag_value = safe_text(data, 64);
    let tag_value = (!tag_value.is_empty()).then_some(tag_value.as_str());
    if tagged
        .add_client_only_tag(&capabilities, "+z", tag_value)
        .is_err()
        || tagged.add_server_tag("z", Some("two")).is_err()
        || tagged.add_server_tag("a", Some("one")).is_err()
        || tagged
            .add_client_only_tag(&capabilities, "+a", Some("first"))
            .is_err()
    {
        return;
    }
    exercise_render_oracle(tagged, Some("a=one;z=two;+a=first;+z"));
});

fn exercise_exact_tag_parse_boundaries() {
    let maximum_value = "v".repeat(MAX_CLIENT_TAG_DATA_BYTES.saturating_sub(2));
    let maximum = format!("a={maximum_value}");
    let Ok(tags) = parse_client_tags(&maximum) else {
        panic!("exact client tag budget was rejected");
    };
    assert_eq!(render_tags(&tags), Ok(maximum));

    let oversized_value = "v".repeat(MAX_CLIENT_TAG_DATA_BYTES.saturating_sub(1));
    let oversized = format!("a={oversized_value}");
    assert!(parse_client_tags(&oversized).is_err());
}

fn exercise_boundary_render_plan(data: &[u8], capabilities: &CapabilityState) {
    let prefix = render_prefix(data.first().copied().unwrap_or_default());
    let command = render_command(data.get(1).copied().unwrap_or_default());
    let middle = render_middle(data);
    let middle_refs: Vec<&str> = middle.iter().map(String::as_str).collect();
    let trailing = render_trailing(data.get(3).copied().unwrap_or_default());
    let Ok(mut message) = WireMessage::new(&prefix, command, &middle_refs, trailing.as_deref())
    else {
        return;
    };

    assert_render_invariants(&message);
    let operation_count = usize::from(data.get(4).copied().unwrap_or_default())
        % MAX_RENDER_TAG_OPERATIONS.saturating_add(1);
    for index in 0..operation_count {
        let offset = 5usize.saturating_add(index.saturating_mul(3));
        let key_selector = data.get(offset).copied().unwrap_or_default();
        let value_selector = data
            .get(offset.saturating_add(1))
            .copied()
            .unwrap_or_default();
        let content = data
            .get(offset.saturating_add(2))
            .copied()
            .unwrap_or_default();
        let client_only = key_selector & 1 != 0;
        let key = render_tag_key(key_selector >> 1, index, client_only);
        let value = render_tag_value(value_selector, content);
        let before = rendered_snapshot(&message);
        let result = if client_only {
            message.add_client_only_tag(capabilities, &key, value.as_deref())
        } else {
            message.add_server_tag(&key, value.as_deref())
        };
        if result.is_err() {
            assert_eq!(rendered_snapshot(&message), before);
        } else {
            assert_render_invariants(&message);
        }
    }
    exercise_render_oracle(message, None);
}

fn exercise_exact_render_boundaries(capabilities: &CapabilityState) {
    let traditional_command_bytes = MAX_TRADITIONAL_LINE_BYTES.saturating_sub(2);
    let exact_trailing_bytes = traditional_command_bytes.saturating_sub(EXACT_TAGMSG_FIXED_BYTES);
    let trailing = "x".repeat(exact_trailing_bytes);
    let Ok(mut message) = WireMessage::new("s", "TAGMSG", &["t"], Some(&trailing)) else {
        panic!("exact command budget was rejected");
    };
    let Ok(untagged) = rendered_snapshot(&message) else {
        panic!("exact traditional frame could not render");
    };
    assert_eq!(untagged.len(), MAX_TRADITIONAL_LINE_BYTES);

    let server_value = "s".repeat(MAX_SERVER_TAG_DATA_BYTES.saturating_sub(2));
    assert!(message.add_server_tag("s", Some(&server_value)).is_ok());
    let client_value =
        "c".repeat(MAX_CLIENT_TAG_DATA_BYTES.saturating_sub(E2EE_TAG.len().saturating_add(1)));
    assert!(
        message
            .add_client_only_tag(capabilities, E2EE_TAG, Some(&client_value))
            .is_ok()
    );
    let Ok(tagged) = rendered_snapshot(&message) else {
        panic!("exact physical frame could not render");
    };
    assert_eq!(tagged.len(), MAX_PHYSICAL_LINE_BYTES);

    let before = tagged;
    assert!(
        message
            .add_client_only_tag(capabilities, "+overflow", None)
            .is_err()
    );
    assert_eq!(rendered_snapshot(&message), Ok(before));

    let oversized_trailing =
        "x".repeat(MAX_COMMAND_BYTES.saturating_sub(EXACT_TAGMSG_FIXED_BYTES) + 1);
    assert!(WireMessage::new("s", "TAGMSG", &["t"], Some(&oversized_trailing)).is_err());
}

fn render_prefix(selector: u8) -> String {
    match selector % 8 {
        0 => "server.invalid".to_owned(),
        1 => String::new(),
        2 => ":server".to_owned(),
        3 => "bad prefix".to_owned(),
        4 => "bad\nserver".to_owned(),
        5 => "p".repeat(MAX_COMMAND_BYTES),
        6 => "serveé".to_owned(),
        _ => "s".repeat(usize::from(selector).max(1)),
    }
}

const fn render_command(selector: u8) -> &'static str {
    const COMMANDS: &[&str] = &[
        "NOTICE", "PRIVMSG", "TAGMSG", "PING", "BATCH", "FAIL", "001", "005", "notice", "999",
        "UNKNOWN",
    ];
    COMMANDS[selector as usize % COMMANDS.len()]
}

fn render_middle(data: &[u8]) -> Vec<String> {
    const COUNTS: &[usize] = &[0, 1, 2, 14, 15, 16];
    let count_selector = usize::from(data.get(2).copied().unwrap_or_default());
    let count = COUNTS[count_selector % COUNTS.len()];
    let mut middle = Vec::new();
    for index in 0..count {
        let selector = data
            .get(5usize.saturating_add(index))
            .copied()
            .unwrap_or_default();
        middle.push(render_parameter(selector));
    }
    middle
}

fn render_parameter(selector: u8) -> String {
    match selector % 9 {
        0 => "target".to_owned(),
        1 => String::new(),
        2 => ":target".to_owned(),
        3 => "two words".to_owned(),
        4 => "line\rbreak".to_owned(),
        5 => "line\nbreak".to_owned(),
        6 => "nul\0byte".to_owned(),
        7 => "m".repeat(usize::from(selector).max(1)),
        _ => "m".repeat(MAX_COMMAND_BYTES.saturating_add(1)),
    }
}

fn render_trailing(selector: u8) -> Option<String> {
    const LENGTHS: &[usize] = &[0, 1, 64, 256, 497, MAX_COMMAND_BYTES, MAX_COMMAND_BYTES + 1];
    match selector % 10 {
        0 => None,
        1 => Some(String::new()),
        2..=8 => {
            let index = usize::from(selector.saturating_sub(2)) % LENGTHS.len();
            Some("t".repeat(LENGTHS[index]))
        }
        _ => Some("bad\ntrailing\0".to_owned()),
    }
}

fn render_tag_key(selector: u8, index: usize, client_only: bool) -> String {
    let valid = || {
        if client_only {
            format!("+c{index}")
        } else {
            format!("s{index}")
        }
    };
    match selector % 10 {
        0 => valid(),
        1 => {
            if client_only {
                "+duplicate".to_owned()
            } else {
                "duplicate".to_owned()
            }
        }
        2 => String::new(),
        3 => "bad;key".to_owned(),
        4 => {
            if client_only {
                "server-key".to_owned()
            } else {
                "+client-key".to_owned()
            }
        }
        5 => {
            if index & 1 == 0 {
                "label".to_owned()
            } else {
                "batch".to_owned()
            }
        }
        6 if client_only => E2EE_TAG.to_owned(),
        6 => "agenc.ag/e2ee".to_owned(),
        7 => "k".repeat(MAX_SERVER_TAG_DATA_BYTES.saturating_add(1)),
        8 => "unicode-é".to_owned(),
        _ => valid(),
    }
}

fn render_tag_value(selector: u8, content: u8) -> Option<String> {
    const LENGTHS: &[usize] = &[
        0,
        1,
        64,
        65,
        256,
        257,
        1_024,
        MAX_SERVER_TAG_DATA_BYTES.saturating_sub(1),
        MAX_SERVER_TAG_DATA_BYTES,
        MAX_SERVER_TAG_DATA_BYTES.saturating_add(1),
    ];
    match selector % 13 {
        0 => None,
        1..=10 => {
            let index = usize::from(selector.saturating_sub(1)) % LENGTHS.len();
            let byte = b'a'.saturating_add(content % 26);
            Some(char::from(byte).to_string().repeat(LENGTHS[index]))
        }
        11 => Some("; \\\r\n".repeat(512)),
        _ => Some("value\0after".to_owned()),
    }
}

fn rendered_snapshot(message: &WireMessage) -> Result<Vec<u8>, RenderError> {
    let measured = message.measure()?;
    let bytes = measured.bytes();
    let mut budget = FuzzBudget::new(bytes);
    let rendered = measured.encode(&mut budget)?;
    let mut snapshot = Vec::new();
    snapshot
        .try_reserve_exact(rendered.as_bytes().len())
        .map_err(|_| RenderError::AllocationFailed)?;
    snapshot.extend_from_slice(rendered.as_bytes());
    Ok(snapshot)
}

fn assert_render_invariants(message: &WireMessage) {
    let Ok(rendered) = rendered_snapshot(message) else {
        panic!("an admitted render plan stopped measuring or encoding");
    };
    assert!(rendered.len() <= MAX_PHYSICAL_LINE_BYTES);
    assert!(rendered.ends_with(b"\r\n"));
    assert!(!rendered[..rendered.len().saturating_sub(2)].contains(&0));
}

fn exercise_render_oracle(message: WireMessage, tag_prefix: Option<&str>) {
    let Ok(measured) = message.measure() else {
        return;
    };
    let bytes = measured.bytes();
    if bytes > 0 {
        let mut insufficient = FuzzBudget::new(bytes - 1);
        let rejected = message
            .measure()
            .and_then(|value| value.encode(&mut insufficient))
            .err();
        assert_eq!(rejected, Some(RenderError::ReservationFailed),);
        assert_eq!(insufficient.requested, Some(bytes));
    }
    let mut exact = FuzzBudget::new(bytes);
    let rendered = measured.encode(&mut exact);
    let Ok(rendered) = rendered else {
        return;
    };
    assert_eq!(rendered.as_bytes().len(), bytes);
    assert!(rendered.as_bytes().ends_with(b"\r\n"));
    if let Some(prefix) = tag_prefix {
        let Ok(text) = std::str::from_utf8(rendered.as_bytes()) else {
            return;
        };
        let section = text
            .strip_prefix('@')
            .and_then(|value| value.split_once(' '));
        assert!(
            section.is_some(),
            "tagged rendering omitted its tag section"
        );
        let Some(section) = section else {
            return;
        };
        assert!(section.0.starts_with(prefix));
        let tags = parse_client_tags(section.0);
        assert!(tags.is_ok(), "rendered canonical tags did not parse");
        let Ok(tags) = tags else {
            return;
        };
        assert_eq!(render_tags(&tags), Ok(section.0.to_owned()));
    }
}

fn corpus_payload(data: &[u8]) -> &[u8] {
    match data.strip_suffix(b"\n") {
        Some(without_newline) => match without_newline.strip_suffix(b"\r") {
            Some(without_carriage_return) => without_carriage_return,
            None => without_newline,
        },
        None => data,
    }
}

fn safe_text(data: &[u8], maximum: usize) -> String {
    data.iter()
        .take(maximum)
        .map(|byte| char::from(b'a'.saturating_add(*byte % 26)))
        .collect()
}

fn message_tag_capabilities() -> Result<CapabilityState, agenc_ircd_client_wire::CapError> {
    let profile = CapabilityProfile::new(vec![CapabilitySpec::new("message-tags", None)?])?;
    let mut capabilities = CapabilityState::default();
    capabilities.ls(Some("302"), &profile)?;
    capabilities.request("message-tags", &profile)?;
    Ok(capabilities)
}
