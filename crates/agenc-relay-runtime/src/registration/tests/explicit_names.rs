//! Explicit NAMES replies larger than one response batch, through the state
//! core and the production registration router at the response batch
//! ceiling a configured node uses by default (Appendix C, 65,536 bytes).
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use agenc_relay_domain::{
    CanonicalCommand, ChannelNameValue, ChannelTarget, DisplayNameValue, NicknameValue,
    PlanDecision, SessionSeed,
};
use agenc_relay_testkit::DomainTestIdentity;
use agenc_relay_types::{Generation, PublicCloak, ServerId, SessionId, UserId, UtcSecond};

use super::test_harness::{TestResult, entropy_script, parsed, saw};
use super::*;
use crate::connection::sink::ClientSink;
use crate::state_core::StateCoreContext;
use crate::state_core::inbox::{SourceAddressKey, StateCoreMessage};
use crate::test_support::{FrameSink, StateCoreFixture, apply_live_plan, plan_live};

/// The instant every test in this file starts at; timers fire only when a
/// test moves the clock.
const FROZEN_TICKS: u64 = 10;
/// The interval at which an open NAMES continuation checks its queue.
const QUEUE_CHECK_MILLIS: u64 = 50;

/// The production router over a state core stepped by hand on a frozen
/// clock, as `core_lines` drives it, with the default response batch.
struct Node {
    fixture: StateCoreFixture,
    sequences: BTreeMap<u64, u64>,
}

impl Node {
    fn new() -> TestResult<Self> {
        let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
        let context = fixture.context_mut()?;
        context.set_monotonic_for_test(FROZEN_TICKS);
        let default = agenc_relay_config::LimitValues::defaults()
            .get(agenc_relay_config::LimitKey::ResponseBatchBytes);
        context.set_response_batch_bytes_for_test(usize::try_from(default)?);
        assert_eq!(context.response_batch_bytes(), 65_536);
        Ok(Self {
            fixture,
            sequences: BTreeMap::new(),
        })
    }

    fn context(&mut self) -> TestResult<&mut StateCoreContext> {
        Ok(self.fixture.context_mut()?)
    }

    /// Settles the batch the routed lines staged.
    async fn settle(&mut self) -> TestResult {
        let context = self.context()?;
        if context.pending_len() == 0 || context.in_flight() {
            return Err("no batch is gathering for the test to settle".into());
        }
        self.fixture.commit_staged_batch().await
    }

    fn open(&mut self, number: u64) -> TestResult<Arc<FrameSink>> {
        let generation = ConnectionGeneration::new(number);
        let sink = FrameSink::new(generation, true);
        let (acknowledgement, _accepted) = tokio::sync::oneshot::channel();
        let exit = self
            .fixture
            .state_mut()?
            .step_message(StateCoreMessage::Opened {
                generation,
                purpose: ListenerPurpose::ClientOnion,
                source: SourceAddressKey::onion_listener(),
                sink: Arc::clone(&sink) as Arc<dyn ClientSink>,
                acknowledgement,
            });
        assert!(exit.is_none());
        Ok(sink)
    }

    fn line(&mut self, number: u64, line: &str) -> TestResult {
        let sequence = self.sequences.entry(number).or_insert(0);
        *sequence = sequence.saturating_add(1);
        let message = StateCoreMessage::Line {
            generation: ConnectionGeneration::new(number),
            sequence: *sequence,
            message: Box::new(parsed(line)?),
        };
        let exit = self.fixture.state_mut()?.step_message(message);
        assert!(exit.is_none());
        Ok(())
    }

    /// Fires the timers due `millis` from now.
    fn advance(&mut self, millis: u64) -> TestResult {
        let now = self.context()?.now().get();
        self.context()?.set_monotonic_for_test(now + millis);
        assert!(self.fixture.state_mut()?.step_wake().is_none());
        Ok(())
    }

    /// Moves the clock one queue check at a time until `sink` holds a line
    /// containing `needle`: each check delivers at most one NAMES page.
    fn deliver_until(&mut self, sink: &FrameSink, needle: &str) -> TestResult {
        for _ in 0..32 {
            if saw(sink, needle) {
                return Ok(());
            }
            self.advance(QUEUE_CHECK_MILLIS)?;
        }
        if saw(sink, needle) {
            return Ok(());
        }
        Err(format!("never saw {needle:?}: {:?}", sink.lines()).into())
    }

    fn holds_seed(&mut self, number: u64) -> TestResult<bool> {
        Ok(self
            .context()?
            .has_local_join_seed(ConnectionGeneration::new(number)))
    }

    fn is_open(&mut self, number: u64) -> TestResult<bool> {
        Ok(self
            .context()?
            .sessions()
            .sink_for_generation(ConnectionGeneration::new(number))
            .is_some())
    }

    /// Registers connection 1 as `alice` with `capabilities` and joins it to
    /// each of `channels`, waiting for every JOIN's NAMES to end.
    async fn register_and_join(
        &mut self,
        capabilities: &str,
        channels: &[&str],
    ) -> TestResult<Arc<FrameSink>> {
        let sink = self.open(1)?;
        self.line(1, "CAP LS 302")?;
        self.line(1, &format!("CAP REQ :{capabilities}"))?;
        self.line(1, "NICK alice")?;
        self.line(1, "USER alice 0 * :Alice")?;
        self.line(1, "CAP END")?;
        self.settle().await?;
        assert!(saw(&sink, " 001 alice "), "lines: {:?}", sink.lines());
        self.line(1, &format!("JOIN {}", channels.join(",")))?;
        self.settle().await?;
        for channel in channels {
            self.deliver_until(&sink, &format!(" 366 alice {channel} "))?;
        }
        Ok(sink)
    }
}

/// Opens member `index`, nickname `n` and seven digits, directly in the
/// domain and joins it to each of `channels`, so a NAMES can outgrow one
/// response batch without one connection per member.
fn seed_member(
    context: &mut StateCoreContext,
    index: u16,
    channels: &[ChannelNameValue],
) -> TestResult {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let letter = |value: u16| -> TestResult<char> {
        Ok(char::from(
            *ALPHABET
                .get(usize::from(value % 32))
                .ok_or("cloak letter")?,
        ))
    };
    let mut identity_bytes = [0; 16];
    identity_bytes[..2].copy_from_slice(&index.to_be_bytes());
    identity_bytes[15] = 0xa5;
    let identity = DomainTestIdentity {
        session_id: SessionId::from_bytes(identity_bytes),
        user_id: UserId::from_bytes(identity_bytes),
        generation: Generation::new(1)?,
        account_id: None,
    };
    let nickname = format!("n{index:07}");
    let user = format!(
        "paaaaaa{}{}{}",
        letter(index / 1_024)?,
        letter(index / 32)?,
        letter(index)?
    );
    let plan = context.domain().plan_session_opened(SessionSeed {
        session_id: identity.session_id,
        user_id: identity.user_id,
        home_server_id: ServerId::from_bytes([240; 16]),
        account_id: None,
        account_session_generation: Generation::new(0)?,
        generation: identity.generation,
        nickname: NicknameValue::parse(&nickname)?,
        display_name: DisplayNameValue::prepare(&nickname)?,
        public_cloak: PublicCloak::parse(&user, "qqqqqqqqqqqqqqqq")?,
        connection_nonce: [1; 32],
        negotiated_capability_hash: [2; 32],
        created_at_utc: UtcSecond::from_unix_seconds(1_720_000_000),
        revision: context.domain().revision(),
    })?;
    apply_live_plan(context, plan)?;
    for channel in channels {
        let join = || CanonicalCommand::join(vec![ChannelTarget::new(channel.clone(), false)]);
        let PlanDecision::Mutation(plan) = plan_live(context, identity, &join)? else {
            return Err("member JOIN plan".into());
        };
        apply_live_plan(context, plan)?;
    }
    Ok(())
}

fn seed_channels(node: &mut Node, names: &[&str], members: u16) -> TestResult {
    let channels = names
        .iter()
        .map(|name| ChannelNameValue::parse(name))
        .collect::<Result<Vec<_>, _>>()?;
    let context = node.context()?;
    for index in 1..=members {
        seed_member(context, index, &channels)?;
    }
    Ok(())
}

/// The channel and the tokens of a 353 line, after any tag section.
fn names_line(line: &str) -> TestResult<(&str, Vec<&str>)> {
    let line = line
        .strip_prefix('@')
        .and_then(|tagged| tagged.split_once(' '))
        .map_or(line, |(_, rest)| rest);
    let (head, text) = line.split_once(" :").ok_or("a NAMES line without tokens")?;
    let channel = head
        .split(' ')
        .nth(4)
        .ok_or("a NAMES line without its channel")?;
    Ok((channel, text.split(' ').collect()))
}

/// The lines after `from` up to and including the first that contains `last`.
fn lines_through(lines: &[String], from: usize, last: &str) -> TestResult<Vec<String>> {
    let tail = lines.get(from..).ok_or("too few lines")?;
    let end = tail
        .iter()
        .position(|line| line.contains(last))
        .ok_or_else(|| format!("no {last:?} after line {from}: {lines:?}"))?;
    Ok(tail.get(..=end).ok_or("too few lines")?.to_vec())
}

/// Every NAMES token of `reply` is a framed mask that its channel lists
/// once, and no line lists more than 512; returns how many there are.
fn framed_tokens(reply: &[String]) -> TestResult<usize> {
    let mut seen = BTreeSet::new();
    for line in reply.iter().filter(|line| line.contains(" 353 ")) {
        let (channel, tokens) = names_line(line)?;
        assert!(tokens.len() <= 512, "{} tokens in one line", tokens.len());
        for token in tokens {
            assert!(
                token.contains("!u-") && token.ends_with(".invalid"),
                "{token}"
            );
            assert!(
                seen.insert((channel.to_owned(), token.to_owned())),
                "{channel} lists {token} twice"
            );
        }
    }
    Ok(seen.len())
}

/// B12-R0-1. With `userhost-in-names` a framed NAMES token is 12 bytes longer
/// than the bare one, so the explicit NAMES of a channel of 1,400 members with
/// 8-byte nicknames is about 69 KB, more than the default response batch. It
/// was refused and its connection closed; it now arrives in pages, every
/// member once and one 366, and the command sent behind it runs afterwards.
#[tokio::test]
async fn an_explicit_names_beyond_one_response_batch_arrives_in_pages() -> TestResult {
    let mut node = Node::new()?;
    seed_channels(&mut node, &["#paged"], 1_399)?;
    let sink = node
        .register_and_join("userhost-in-names", &["#paged"])
        .await?;
    let before = sink.lines().len();
    node.line(1, "NAMES #paged")?;
    node.line(1, "TIME")?;
    assert!(
        node.is_open(1)?,
        "a NAMES beyond one response batch keeps its connection"
    );
    node.deliver_until(&sink, " 391 alice ")?;
    let reply = lines_through(&sink.lines(), before, " 391 alice ")?;
    let (time, names) = reply.split_last().ok_or("no reply")?;
    assert!(time.contains(" 391 alice "), "{time}");
    let (end, chunks) = names.split_last().ok_or("no NAMES reply")?;
    assert!(end.contains(" 366 alice #paged "), "{end}");
    assert!(
        chunks
            .iter()
            .all(|line| line.contains(" 353 alice = #paged :")),
        "lines: {reply:?}"
    );
    assert_eq!(framed_tokens(chunks)?, 1_400);
    let rendered: usize = chunks.iter().map(|line| line.len() + 2).sum();
    assert!(rendered > 65_536, "the reply is only {rendered} bytes");
    assert!(node.is_open(1)?);
    assert!(!node.holds_seed(1)?);
    Ok(())
}

/// A labeled explicit NAMES in pages keeps one `labeled-response` batch from
/// its first page to its last, opened with the request's label; a NAMES that
/// fits one response batch is still sent whole, in a batch named by its
/// label, exactly as before.
#[tokio::test]
async fn a_labeled_names_in_pages_keeps_one_batch_and_a_small_one_is_sent_whole() -> TestResult {
    let mut node = Node::new()?;
    seed_channels(&mut node, &["#paged"], 1_399)?;
    let sink = node
        .register_and_join(
            "message-tags batch labeled-response userhost-in-names",
            &["#paged", "#small"],
        )
        .await?;
    let before = sink.lines().len();
    node.line(1, "@label=whole NAMES #small")?;
    let whole = lines_through(&sink.lines(), before, "BATCH -whole")?;
    assert_eq!(whole.len(), 4, "lines: {whole:?}");
    assert!(
        whole
            .first()
            .is_some_and(|line| line.starts_with("@label=whole ")
                && line.ends_with(" BATCH +whole labeled-response")),
        "lines: {whole:?}"
    );
    let before = sink.lines().len();
    node.line(1, "@label=paged NAMES #paged")?;
    node.line(1, "TIME")?;
    node.deliver_until(&sink, " 391 alice ")?;
    let reply = lines_through(&sink.lines(), before, " 391 alice ")?;
    let opening = reply.first().ok_or("no reply")?;
    let id = opening
        .strip_prefix("@label=paged :server.example BATCH +")
        .and_then(|rest| rest.strip_suffix(" labeled-response"))
        .ok_or_else(|| format!("not a labeled batch: {opening}"))?;
    assert!(id.starts_with("fq"), "{id}");
    let closing = format!(":server.example BATCH -{id}");
    let close = reply
        .iter()
        .position(|line| *line == closing)
        .ok_or_else(|| format!("no {closing:?}: {reply:?}"))?;
    let inside = reply.get(1..close).ok_or("an empty batch")?;
    let tag = format!("@batch={id} ");
    assert!(
        inside.iter().all(|line| line.starts_with(&tag)),
        "lines: {reply:?}"
    );
    let (end, chunks) = inside.split_last().ok_or("no NAMES reply")?;
    assert!(end.contains(" 366 alice #paged "), "{end}");
    assert_eq!(framed_tokens(chunks)?, 1_400);
    assert_eq!(close + 2, reply.len(), "lines: {reply:?}");
    Ok(())
}

/// A bare `NAMES` lists every joined channel in one reply. Twenty channels of
/// 71 seeded members and the requester exceed one response batch together;
/// every 366 follows every 353, on the last page.
#[tokio::test]
async fn a_bare_names_across_joined_channels_arrives_in_pages() -> TestResult {
    let names: Vec<String> = (0..20).map(|index| format!("#p{index:02}")).collect();
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    let mut node = Node::new()?;
    seed_channels(&mut node, &names, 71)?;
    let sink = node.register_and_join("userhost-in-names", &names).await?;
    let before = sink.lines().len();
    node.line(1, "NAMES")?;
    node.line(1, "TIME")?;
    node.deliver_until(&sink, " 391 alice ")?;
    let reply = lines_through(&sink.lines(), before, " 391 alice ")?;
    let first_end = reply
        .iter()
        .position(|line| line.contains(" 366 alice "))
        .ok_or("no 366")?;
    let (chunks, rest) = reply.split_at_checked(first_end).ok_or("no 366")?;
    let (time, endings) = rest.split_last().ok_or("no 391")?;
    assert!(time.contains(" 391 alice "), "{time}");
    assert!(chunks.iter().all(|line| line.contains(" 353 alice = #p")));
    let ended: BTreeSet<&str> = endings
        .iter()
        .filter_map(|line| line.split(' ').nth(3))
        .collect();
    assert_eq!(endings.len(), 20, "lines: {endings:?}");
    assert_eq!(ended, names.iter().copied().collect());
    assert_eq!(framed_tokens(chunks)?, 20 * 72, "lines: {chunks:?}");
    let rendered: usize = reply.iter().map(|line| line.len() + 2).sum();
    assert!(rendered > 65_536, "the reply is only {rendered} bytes");
    Ok(())
}

/// A NAMES deferred behind a refusal held by the secret-lookup response floor
/// runs when the floor's timer resumes its connection, and its snapshot opens
/// in that same step: no later line or commit is needed to answer it or the
/// command behind it.
#[tokio::test]
async fn a_paged_names_released_by_a_response_floor_opens_in_that_step() -> TestResult {
    let mut node = Node::new()?;
    seed_channels(&mut node, &["#paged"], 1_399)?;
    let sink = node
        .register_and_join("userhost-in-names", &["#paged"])
        .await?;
    let before = sink.lines().len();
    node.line(1, "TOPIC #missing")?;
    node.line(1, "NAMES #paged")?;
    node.line(1, "TIME")?;
    assert_eq!(sink.lines().len(), before, "lines: {:?}", sink.lines());
    node.advance(crate::state_core::timers::SECRET_CHANNEL_FLOOR_MILLIS)?;
    let lines = sink.lines();
    let after = lines.get(before..).ok_or("too few lines")?;
    let refused = after
        .iter()
        .position(|line| line.contains(" 403 alice #missing "));
    let first = after
        .iter()
        .position(|line| line.contains(" 353 alice = #paged "));
    assert!(
        refused.is_some() && refused < first,
        "the refusal, then the first page in the same step: {after:?}"
    );
    assert!(!node.holds_seed(1)?, "the NAMES snapshot opened");
    node.deliver_until(&sink, " 391 alice ")?;
    let reply = lines_through(&sink.lines(), before, " 391 alice ")?;
    assert_eq!(
        reply
            .iter()
            .filter(|line| line.contains(" 366 alice #paged "))
            .count(),
        1
    );
    Ok(())
}
