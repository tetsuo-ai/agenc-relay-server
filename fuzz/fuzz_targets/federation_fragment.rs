#![no_main]
#![forbid(unsafe_code)]

use agenc_ircd_federation_wire::{
    AssemblyProgress, FederationCommandTag, FederationFragment, FederationFrame, FederationLine,
    FragmentAssembler, FragmentDescriptorKey, federation_object_id, split_fragments,
};
use libfuzzer_sys::fuzz_target;

const PEER: &str = "core.example";

/// A parsed line renders to a line that parses to the same rendering.
fn fuzz_line(text: &str) {
    let mut tokens = text.split(' ');
    let Some(mut first) = tokens.next() else {
        return;
    };
    let mut tag = None;
    if let Some(rest) = first.strip_prefix('@') {
        let Some((name, value)) = rest.split_once('=') else {
            return;
        };
        tag = Some(FederationCommandTag::new(name, Some(value)));
        let Some(next) = tokens.next() else {
            return;
        };
        first = next;
    }
    let (prefix, command) = match first.strip_prefix(':') {
        Some(prefix) => {
            let Some(command) = tokens.next() else {
                return;
            };
            (Some(prefix), command)
        }
        None => (None, first),
    };
    let parameters: Vec<&str> = tokens.collect();
    let tags: Vec<FederationCommandTag<'_>> = tag.into_iter().collect();
    let line = FederationLine::new(prefix, &tags, command, &parameters);
    let Ok(frame) = FederationFrame::parse(line, PEER) else {
        return;
    };
    let rendered = frame.render(PEER).expect("accepted frame must render");
    assert!(rendered.as_str().ends_with("\r\n"));
    let body = rendered.as_str().trim_end_matches("\r\n");
    let mut again = body.split(' ');
    let mut again_first = again.next().expect("rendered line has a first token");
    let mut again_tag = None;
    if let Some(rest) = again_first.strip_prefix('@') {
        let (name, value) = rest.split_once('=').expect("rendered tag has a value");
        again_tag = Some(FederationCommandTag::new(name, Some(value)));
        again_first = again.next().expect("rendered line has a prefix");
    }
    let again_prefix = again_first.strip_prefix(':').expect("rendered prefix");
    let again_command = again.next().expect("rendered command");
    let again_parameters: Vec<&str> = again.collect();
    let again_tags: Vec<FederationCommandTag<'_>> = again_tag.into_iter().collect();
    let reparsed = FederationFrame::parse(
        FederationLine::new(
            Some(again_prefix),
            &again_tags,
            again_command,
            &again_parameters,
        ),
        PEER,
    )
    .expect("rendered line must parse");
    assert_eq!(reparsed.kind(), frame.kind());
    assert_eq!(
        reparsed
            .render(PEER)
            .expect("reparsed frame renders")
            .as_str(),
        rendered.as_str()
    );
}

/// Any object splits into fragments that reassemble to the same bytes, and
/// arbitrary fragment tags never break the assembler's accounting.
fn fuzz_assembly(data: &[u8]) {
    let mut assembler = FragmentAssembler::new();
    let key = FragmentDescriptorKey::derive("FREQUEST", &["x"]);
    if !data.is_empty() && data.len() <= 262_144 {
        let object_id = federation_object_id(data);
        let fragments = split_fragments(object_id, data).expect("bounded object splits");
        let mut completed = None;
        for (index, fragment) in fragments.iter().enumerate() {
            match assembler.admit(key, fragment, index as u64) {
                Ok(AssemblyProgress::Complete(object)) => completed = Some(object),
                Ok(AssemblyProgress::Incomplete { .. }) => {}
                Err(error) => panic!("canonical fragments rejected: {error}"),
            }
        }
        let object = completed.expect("canonical fragments complete");
        assert_eq!(object.as_slice(), data);
        assert_eq!(assembler.reserved_bytes(), 0);
    }
    if let Ok(text) = std::str::from_utf8(data)
        && let Ok(fragment) = FederationFragment::parse(text)
    {
        let _ = assembler.admit(key, &fragment, 0);
        let _ = assembler.expire(u64::MAX);
        assert_eq!(assembler.incomplete_objects(), 0);
        assert_eq!(assembler.reserved_bytes(), 0);
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, input)) = data.split_first() else {
        return;
    };
    if selector % 2 == 0 {
        if let Ok(text) = std::str::from_utf8(input) {
            fuzz_line(text);
        }
    } else {
        fuzz_assembly(input);
    }
});
