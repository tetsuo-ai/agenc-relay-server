#![forbid(unsafe_code)]
//! The bounded encrypted load harness (companion Section 21 gate 11): the
//! maximum mailbox object reassembled from its 1,427 fragments, the
//! authenticated fragment flood held at the global reassembly ceiling and
//! released after quiescence, and the padding arithmetic across the whole
//! size table. It records latency and high-water numbers under
//! `target/stage-eight-load.json` and fails only when a ceiling is crossed.

use std::error::Error;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use agenc_ircd_e2ee::ObjectId;
use agenc_ircd_e2ee::envelope::{padding_bytes, padding_target};
use agenc_ircd_e2ee::limits::{
    MAX_APPLICATION_PLAINTEXT, MAX_MAILBOX_FRAGMENT_COUNT, MAX_OPEN_REASSEMBLIES_GLOBAL,
    MAX_WELCOME_MAILBOX_OBJECT,
};
use agenc_ircd_e2ee::object::IrcWireObjectKind;
use agenc_ircd_e2ee::wire::assembly::{
    AssemblyKey, Direction, E2eeAssembler, Ingest, QuotaLimits, QuotaScopes, Sender,
};
use agenc_ircd_e2ee::wire::carrier::CarrierCommand;
use agenc_ircd_e2ee::wire::fragment::fragment_object;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// Generous ceilings: a debug build is far slower than the release build
/// the gate script uses, so the bounds only catch a regression by an order
/// of magnitude.
const REASSEMBLY_CEILING: Duration = Duration::from_secs(20);
const FLOOD_CEILING: Duration = Duration::from_secs(20);

fn key(sender: [u8; 16], object_id: ObjectId) -> AssemblyKey {
    AssemblyKey {
        direction: Direction::Remote,
        sender: Sender::Peer(sender),
        command: CarrierCommand::Federation(IrcWireObjectKind::WelcomeMls),
        route: [0; 32],
        scope: None,
        object_id,
    }
}

fn scopes(sender: [u8; 16]) -> QuotaScopes {
    QuotaScopes {
        peer: Some(sender),
        ..QuotaScopes::default()
    }
}

struct Report {
    reassembly_fragments: usize,
    reassembly_bytes: usize,
    reassembly: Duration,
    flood_open_high_water: usize,
    flood_refusals: usize,
    flood: Duration,
    flood_released: usize,
    padding_points: usize,
}

fn write_report(report: &Report) -> TestResult {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/stage-eight-load.json");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let text = format!(
        concat!(
            "{{\n",
            "  \"reassembly_fragments\": {},\n",
            "  \"reassembly_bytes\": {},\n",
            "  \"reassembly_millis\": {},\n",
            "  \"flood_open_high_water\": {},\n",
            "  \"flood_refusals\": {},\n",
            "  \"flood_millis\": {},\n",
            "  \"flood_released\": {},\n",
            "  \"padding_points\": {}\n",
            "}}\n"
        ),
        report.reassembly_fragments,
        report.reassembly_bytes,
        report.reassembly.as_millis(),
        report.flood_open_high_water,
        report.flood_refusals,
        report.flood.as_millis(),
        report.flood_released,
        report.padding_points,
    );
    fs::write(path, text)?;
    Ok(())
}

/// The largest mailbox object, split into its maximum fragment count and
/// reassembled in reverse order under the remote direction.
fn reassemble_maximum(report: &mut Report) -> TestResult {
    let object: Vec<u8> = (0..MAX_WELCOME_MAILBOX_OBJECT)
        .map(|index| u8::try_from(index % 251).unwrap_or(0))
        .collect();
    let tags = fragment_object(&object)?;
    assert_eq!(
        u32::try_from(tags.len())?,
        MAX_MAILBOX_FRAGMENT_COUNT,
        "the maximum object splits into the maximum fragment count"
    );
    let object_id = ObjectId::compute(&object);
    let sender = [1; 16];
    let limit = CarrierCommand::Federation(IrcWireObjectKind::WelcomeMls).limit();
    let mut assembler = E2eeAssembler::new(QuotaLimits::default());
    let started = Instant::now();
    let mut complete = None;
    for tag in tags.iter().rev() {
        match assembler.ingest(key(sender, object_id), scopes(sender), limit, tag, 0)? {
            Ingest::Complete(bytes) => complete = Some(bytes),
            Ingest::Incomplete => {}
            Ingest::Duplicate | Ingest::Recent => return Err("fragment repeated".into()),
        }
    }
    report.reassembly = started.elapsed();
    report.reassembly_fragments = tags.len();
    report.reassembly_bytes = object.len();
    assert_eq!(complete.as_deref(), Some(object.as_slice()));
    assert!(
        report.reassembly <= REASSEMBLY_CEILING,
        "reassembly took {:?}",
        report.reassembly
    );
    Ok(())
}

/// Distinct senders each open one object until the global ceiling holds;
/// every further open is refused before any byte is kept, and discarding
/// the senders releases every slot.
fn flood(report: &mut Report) -> TestResult {
    let mut assembler = E2eeAssembler::new(QuotaLimits::default());
    let limit = CarrierCommand::Federation(IrcWireObjectKind::WelcomeMls).limit();
    let attempts = MAX_OPEN_REASSEMBLIES_GLOBAL.saturating_add(64);
    let started = Instant::now();
    let mut refusals = 0_usize;
    let mut high_water = 0_usize;
    for index in 0..attempts {
        let mut object = vec![0_u8; 6_000];
        for (slot, byte) in object.iter_mut().zip(index.to_be_bytes().iter().cycle()) {
            *slot = *byte;
        }
        let object_id = ObjectId::compute(&object);
        let first = fragment_object(&object)?
            .into_iter()
            .next()
            .ok_or("no fragment")?;
        let mut sender = [0_u8; 16];
        for (slot, byte) in sender.iter_mut().zip(index.to_be_bytes().iter()) {
            *slot = *byte;
        }
        match assembler.ingest(key(sender, object_id), scopes(sender), limit, &first, 0) {
            Ok(Ingest::Incomplete) => {}
            Ok(_) => return Err("a first fragment completed an object".into()),
            Err(_) => refusals = refusals.saturating_add(1),
        }
        high_water = high_water.max(assembler.open_count());
    }
    report.flood = started.elapsed();
    report.flood_refusals = refusals;
    report.flood_open_high_water = high_water;
    assert_eq!(
        high_water, MAX_OPEN_REASSEMBLIES_GLOBAL,
        "the global ceiling holds"
    );
    assert_eq!(refusals, 64, "every attempt past the ceiling is refused");
    let mut released = 0_usize;
    for index in 0..attempts {
        let mut sender = [0_u8; 16];
        for (slot, byte) in sender.iter_mut().zip(index.to_be_bytes().iter()) {
            *slot = *byte;
        }
        released = released.saturating_add(assembler.discard_sender(&Sender::Peer(sender)));
    }
    report.flood_released = released;
    assert_eq!(released, MAX_OPEN_REASSEMBLIES_GLOBAL);
    assert_eq!(assembler.open_count(), 0, "quiescence releases every slot");
    assert!(
        report.flood <= FLOOD_CEILING,
        "flood took {:?}",
        report.flood
    );
    Ok(())
}

/// The padding arithmetic across the whole table: every target is at
/// least the content, the padded size never shrinks as content grows, and
/// the maximum content still fits its target.
fn padding(report: &mut Report) -> TestResult {
    let mut previous = 0_usize;
    let mut points = 0_usize;
    for content in (0..=MAX_APPLICATION_PLAINTEXT).step_by(37) {
        let target = padding_target(content)?;
        let pad = padding_bytes(content)?;
        assert!(target >= content);
        assert_eq!(content.saturating_add(pad), target);
        assert!(target >= previous, "padding target shrank at {content}");
        previous = target;
        points = points.saturating_add(1);
    }
    report.padding_points = points;
    Ok(())
}

#[test]
fn maximum_encrypted_shapes_stay_within_their_ceilings() -> TestResult {
    let mut report = Report {
        reassembly_fragments: 0,
        reassembly_bytes: 0,
        reassembly: Duration::ZERO,
        flood_open_high_water: 0,
        flood_refusals: 0,
        flood: Duration::ZERO,
        flood_released: 0,
        padding_points: 0,
    };
    reassemble_maximum(&mut report)?;
    flood(&mut report)?;
    padding(&mut report)?;
    write_report(&report)?;
    Ok(())
}
