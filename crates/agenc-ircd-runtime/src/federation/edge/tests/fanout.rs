#![forbid(unsafe_code)]

//! Shared event frames must preserve every recipient's complete ordered stream.

use super::*;
use crate::budget::MemoryBudget;
use crate::connection::ClientSink;
use crate::purpose::ListenerPurpose;
use crate::state_core::fanout;
use crate::state_core::inbox::SourceAddressKey;
use crate::sync::Arc;
use crate::test_support::{FrameSink, StateCoreFixture, TestResult};

fn open_sink(context: &mut StateCoreContext, sequence: usize) -> TestResult<Arc<FrameSink>> {
    let generation = ConnectionGeneration::new(u64::try_from(sequence)?);
    let sink = FrameSink::new(generation, true);
    let now = context.now();
    context.sessions_mut().open(
        generation,
        ListenerPurpose::ClientTls,
        SourceAddressKey::onion_listener(),
        Arc::clone(&sink) as Arc<dyn crate::connection::ClientSink>,
        now,
    )?;
    Ok(sink)
}

fn message(body: &str) -> TestResult<WireMessage> {
    Ok(WireMessage::new(
        "sender!public@cloak",
        "PRIVMSG",
        &["#wide"],
        Some(body),
    )?)
}

#[tokio::test]
async fn a_shared_event_reaches_the_full_channel_recipient_ceiling() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![1; 256])?;
    let context = fixture.context_mut()?;
    let mut collected = EventFanout::default();
    let mut sinks = Vec::new();
    for sequence in 1..=MAX_FANOUT_TARGETS {
        let sink = open_sink(context, sequence)?;
        collected.append(context, sink.generation(), vec![message("one event")?])?;
        sinks.push(sink);
    }
    let request = collected.finish()?;
    assert_eq!(request.target_count(), MAX_FANOUT_TARGETS);
    assert_eq!(request.frame_count(), 1);
    let budget = MemoryBudget::new(512 * 1_024 * 1_024);
    let reserved = fanout::reserve(&request, &budget)?;
    assert_eq!(reserved.reserved_sinks(), MAX_FANOUT_TARGETS);
    assert!(sinks.iter().all(|sink| sink.lines().is_empty()));
    let report = reserved.commit();
    assert_eq!(report.committed_sinks, MAX_FANOUT_TARGETS);
    for sink in sinks {
        assert_eq!(
            sink.lines(),
            [":sender!public@cloak PRIVMSG #wide :one event"]
        );
    }
    Ok(())
}

#[tokio::test]
async fn shared_frames_preserve_repeated_events_and_each_recipients_order() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![1; 256])?;
    let context = fixture.context_mut()?;
    let first = open_sink(context, 1)?;
    let second = open_sink(context, 2)?;
    let mut collected = EventFanout::default();
    collected.append(
        context,
        first.generation(),
        vec![message("A")?, message("B")?],
    )?;
    collected.append(
        context,
        second.generation(),
        vec![message("B")?, message("A")?],
    )?;
    collected.append(context, first.generation(), vec![message("A")?])?;
    collected.append(context, second.generation(), vec![message("A")?])?;
    let request = collected.finish()?;
    let budget = MemoryBudget::new(1_024 * 1_024);
    fanout::reserve(&request, &budget)?.commit();
    assert_eq!(
        first.lines(),
        [
            ":sender!public@cloak PRIVMSG #wide :A",
            ":sender!public@cloak PRIVMSG #wide :B",
            ":sender!public@cloak PRIVMSG #wide :A",
        ]
    );
    assert_eq!(
        second.lines(),
        [
            ":sender!public@cloak PRIVMSG #wide :B",
            ":sender!public@cloak PRIVMSG #wide :A",
            ":sender!public@cloak PRIVMSG #wide :A",
        ]
    );
    Ok(())
}

#[tokio::test]
async fn shared_frames_keep_recipient_specific_tags_separate() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![1; 256])?;
    let context = fixture.context_mut()?;
    let tagged = open_sink(context, 1)?;
    let untagged = open_sink(context, 2)?;
    let mut tagged_message = message("one event")?;
    tagged_message.add_server_tag("account", Some("public-label"))?;
    let mut collected = EventFanout::default();
    collected.append(context, tagged.generation(), vec![tagged_message])?;
    collected.append(context, untagged.generation(), vec![message("one event")?])?;
    let request = collected.finish()?;
    assert_eq!(request.frame_count(), 2);
    let budget = MemoryBudget::new(1_024 * 1_024);
    fanout::reserve(&request, &budget)?.commit();
    assert_eq!(
        tagged.lines(),
        ["@account=public-label :sender!public@cloak PRIVMSG #wide :one event"]
    );
    assert_eq!(
        untagged.lines(),
        [":sender!public@cloak PRIVMSG #wide :one event"]
    );
    Ok(())
}
