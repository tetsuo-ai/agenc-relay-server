//! The pre-authentication command budget at the template default
//! (Architecture Section 19.1 and Appendix C.6; AUD-07): a client that paces
//! its lines to the connection's `preauth_command` bucket, one line per
//! token, finishes account creation followed by registration, and a login
//! before registration followed by registration, within the 30-second
//! registration limit of Section 8.3 at a 3-second round trip, through the
//! production binary at the rates `arcd init` writes. A client that sends
//! more lines than the bucket holds is still told to wait with `263` and
//! stays connected.
#![forbid(unsafe_code)]

use super::*;

use agenc_relay_config::RateSpec;

/// The `preauth_command` default of Section 19.1 and Appendix C.6: one token
/// per second, a burst of 24.
const PREAUTH_DEFAULT: RateSpec = RateSpec::new(1, 1, 24);
/// The registration limit of Architecture Section 8.3.
const REGISTRATION_LIMIT: Duration = Duration::from_secs(30);
/// The round trip the paced client adds before acting on each reply it read:
/// the daemon receives the client's next line this long after it sent the
/// reply. Appendix C.6 sizes the default for round trips of up to 3 seconds.
const SIMULATED_ROUND_TRIP: Duration = Duration::from_secs(3);
/// Slack added to every refill the paced client waits for, so that its clock,
/// which starts when the first line leaves, never runs ahead of the bucket the
/// daemon creates when that line arrives.
const REFILL_MARGIN: Duration = Duration::from_millis(250);
/// The block `LiveFixture` adds to raise three buckets above their defaults.
const RAISED_RATES: &str = "\n[limits.rate.preauth_command]\nrefill_tokens = 10\nrefill_seconds = 1\nburst = 50\n\n[limits.rate.registered_command]\nrefill_tokens = 40\nrefill_seconds = 1\nburst = 200\n\n[limits.rate.expensive_query]\nrefill_tokens = 2\nrefill_seconds = 1\nburst = 10\n";

/// A live fixture whose daemon runs with the template's rate table: the
/// raised buckets `LiveFixture` adds for its other tests are removed, so no
/// `[limits.rate]` table remains and every rate takes its Appendix C.6
/// default.
fn template_rate_fixture() -> TestResult<LiveFixture> {
    let fixture = LiveFixture::create()?;
    let mut config = fs::read_to_string(&fixture.config_path)?;
    replace_once(&mut config, RAISED_RATES, "\n")?;
    if config.contains("[limits.rate") {
        return Err(failure("the fixture still configures a rate table"));
    }
    fs::write(&fixture.config_path, config)?;
    Ok(fixture)
}

/// The client's side of the network a paced client talks through.
///
/// Every line the client writes is charged to a model of the connection's
/// `preauth_command` bucket that applies the daemon's own refill rule, whole
/// refill periods counted from the first charge and capped at the burst, on
/// the client's clock: a line leaves once the model holds a token for it.
/// Lines for which no reply has been read stay in flight and reach the daemon
/// together, at the instant the last of them left, when the client next
/// reads: network delay can deliver such a run at once, which is the case the
/// burst must cover. The first line after a reply leaves no earlier than one
/// simulated round trip after the reply was read.
struct PacedStream {
    inner: Box<dyn ClientIo>,
    rate: RateSpec,
    round_trip: Duration,
    tokens: u64,
    last_refill: Option<Instant>,
    /// Bytes of the line being written, before its CRLF.
    partial: Vec<u8>,
    /// Complete lines that have left but have not reached the daemon.
    in_flight: Vec<u8>,
    /// When the last in-flight line left.
    run_leaves: Option<Instant>,
    /// When the client last read reply bytes.
    replied: Option<Instant>,
    /// When the previous line left.
    previous: Option<Instant>,
}

impl PacedStream {
    fn new(inner: Box<dyn ClientIo>, rate: RateSpec, round_trip: Duration) -> Self {
        Self {
            inner,
            rate,
            round_trip,
            tokens: rate.burst,
            last_refill: None,
            partial: Vec::new(),
            in_flight: Vec::new(),
            run_leaves: None,
            replied: None,
            previous: None,
        }
    }

    fn period(&self) -> Duration {
        Duration::from_secs(self.rate.refill_seconds)
    }

    /// Adds every whole refill period elapsed by `now`, as the daemon does.
    fn refill(&mut self, now: Instant) {
        let Some(last) = self.last_refill else {
            return;
        };
        let period = self.period();
        let mut cursor = last;
        while cursor + period <= now {
            cursor += period;
            self.tokens = self
                .tokens
                .saturating_add(self.rate.refill_tokens)
                .min(self.rate.burst);
        }
        self.last_refill = Some(cursor);
    }

    /// Charges one line and returns when it leaves: no earlier than the
    /// previous line, one round trip after the last reply, and the moment the
    /// model holds a token for it.
    fn charge(&mut self) -> Instant {
        let mut leaves = Instant::now();
        if let Some(previous) = self.previous {
            leaves = leaves.max(previous);
        }
        if let Some(replied) = self.replied.take() {
            leaves = leaves.max(replied + self.round_trip);
        }
        if self.last_refill.is_none() {
            self.last_refill = Some(leaves);
        }
        self.refill(leaves);
        while self.tokens == 0 {
            let next = self.last_refill.unwrap_or(leaves) + self.period();
            leaves = leaves.max(next + REFILL_MARGIN);
            self.refill(leaves);
        }
        self.tokens -= 1;
        self.previous = Some(leaves);
        leaves
    }

    /// Delivers the lines in flight at once, when the last of them leaves.
    fn deliver(&mut self) -> io::Result<()> {
        if self.in_flight.is_empty() {
            return Ok(());
        }
        if let Some(leaves) = self.run_leaves.take() {
            let now = Instant::now();
            if leaves > now {
                thread::sleep(leaves - now);
            }
        }
        let run = std::mem::take(&mut self.in_flight);
        self.inner.write_all(&run)?;
        self.inner.flush()
    }
}

impl io::Write for PacedStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        for &byte in bytes {
            self.partial.push(byte);
            if self.partial.ends_with(b"\r\n") {
                let leaves = self.charge();
                self.run_leaves = Some(leaves);
                self.in_flight.append(&mut self.partial);
            }
        }
        Ok(bytes.len())
    }

    /// A line the client flushes is in flight; it reaches the daemon with
    /// the rest of its run.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl io::Read for PacedStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.deliver()?;
        let read = self.inner.read(buffer)?;
        if read > 0 {
            self.replied = Some(Instant::now());
        }
        Ok(read)
    }
}

/// Connects a client whose lines are paced to `rate` and delayed by
/// `round_trip`, as described on [`PacedStream`].
fn paced_client(
    fixture: &LiveFixture,
    rate: RateSpec,
    round_trip: Duration,
) -> TestResult<ArcClient> {
    let ArcClient {
        reader,
        logged_in,
        registered,
        account_state,
    } = ArcClient::connect(fixture)?;
    if !reader.buffer().is_empty() {
        return Err(failure("the daemon spoke before the client"));
    }
    let paced: Box<dyn ClientIo> =
        Box::new(PacedStream::new(reader.into_inner(), rate, round_trip));
    Ok(ArcClient {
        reader: BufReader::new(paced),
        logged_in,
        registered,
        account_state,
    })
}

/// Requires `elapsed` to be within the registration limit and `welcome` to
/// hold `nickname`'s `001`.
fn require_registered_in_time(
    label: &str,
    elapsed: Duration,
    welcome: &[String],
    nickname: &str,
) -> TestResult {
    assert_contains(welcome, &format!(" 001 {nickname} "))?;
    if elapsed >= REGISTRATION_LIMIT {
        return Err(failure(format!(
            "{label} took {elapsed:?}, not within the registration limit"
        )));
    }
    Ok(())
}

#[test]
fn paced_account_creation_and_login_register_within_the_limit_at_the_template_rate() -> TestResult {
    let rate = PREAUTH_DEFAULT;
    let fixture = template_rate_fixture()?;
    let mut daemon = DaemonProcess::start(&fixture.config_path)?;

    // Account creation, then registration as a guest: 41 lines, with the
    // two 17-line ACCTCREATE runs (16 DATA lines and END) delivered at once.
    let started = Instant::now();
    let mut creation = paced_client(&fixture, rate, SIMULATED_ROUND_TRIP)?;
    creation.negotiate_sasl()?;
    let account_id = create_live_account(&mut creation, &fixture)?;
    let welcome = creation.complete_registration("PacedNew")?;
    let created_in = started.elapsed();
    require_registered_in_time("account creation", created_in, &welcome, "PacedNew")?;

    // A login before registration, then registration: 38 lines, with the
    // two 16-chunk AUTHENTICATE runs delivered at once.
    let started = Instant::now();
    let mut login = paced_client(&fixture, rate, SIMULATED_ROUND_TRIP)?;
    login.negotiate_sasl()?;
    authenticate_live_account(&mut login, &fixture, ACCOUNT_PASSWORD, 60, account_id)?;
    let welcome = login.complete_registration("PacedOld")?;
    let logged_in = started.elapsed();
    require_registered_in_time("login", logged_in, &welcome, "PacedOld")?;
    if login.account_state.is_none() {
        return Err(failure(
            "the login's welcome did not end with its account state",
        ));
    }
    fixture.phase(&format!(
        "account creation registered after {created_in:?}, login after {logged_in:?}"
    ));
    eprintln!(
        "preauth budget: account creation registered after {created_in:?}, \
         login after {logged_in:?} (round trip {SIMULATED_ROUND_TRIP:?})"
    );

    let mut admin = AdminClient::connect(&fixture)?;
    admin.confirm_process("DIE :pre-authentication budget complete")?;
    assert!(daemon.wait()?.success(), "{}", fixture.log_excerpt());
    Ok(())
}

#[test]
fn a_client_beyond_its_preauth_burst_is_told_to_wait_and_stays_connected() -> TestResult {
    let rate = PREAUTH_DEFAULT;
    let burst = usize::try_from(rate.burst)?;
    let fixture = template_rate_fixture()?;
    let mut daemon = DaemonProcess::start(&fixture.config_path)?;

    // One more PING than the burst, in one write: the burst is answered and
    // the line beyond it is refused, before registration.
    let mut client = ArcClient::connect(&fixture)?;
    let mut bytes = Vec::new();
    for index in 0..=burst {
        bytes.extend_from_slice(format!("PING :over-{index:02}\r\n").as_bytes());
    }
    client.reader.get_mut().write_all(&bytes)?;
    client.reader.get_mut().flush()?;
    let refusal = " 263 * PING :Please wait a while and try again.";
    let replies = read_until(&mut client.reader, |line| line.ends_with(refusal))?;
    let answered: Vec<&String> = replies
        .iter()
        .filter(|line| line.contains(" PONG "))
        .collect();
    assert_eq!(answered.len(), burst, "{replies:?}");
    assert_eq!(replies.len(), burst + 1, "{replies:?}");
    for (index, line) in answered.iter().enumerate() {
        assert!(line.ends_with(&format!(" :over-{index:02}")), "{replies:?}");
    }

    // The connection stays open, and the next refill admits the next line.
    thread::sleep(Duration::from_secs(rate.refill_seconds) + REFILL_MARGIN);
    let after = client.send_until("PING :refilled", "PONG")?;
    assert_eq!(after.len(), 1, "{after:?}");
    assert!(
        after.iter().all(|line| line.ends_with(" :refilled")),
        "{after:?}"
    );

    let mut admin = AdminClient::connect(&fixture)?;
    admin.confirm_process("DIE :pre-authentication refusal complete")?;
    assert!(daemon.wait()?.success(), "{}", fixture.log_excerpt());
    Ok(())
}
