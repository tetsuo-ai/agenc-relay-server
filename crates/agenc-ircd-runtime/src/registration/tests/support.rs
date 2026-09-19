//! A registration router owned by the test beside a live state-core context,
//! so a test can drive client lines, timers, and edge completions directly.
#![forbid(unsafe_code)]

use agenc_ircd_client_wire::{FramedLine, parse_message};

use super::*;
use crate::bridge::crypto::{CHANNEL_KEY_SALT_BYTES, ChannelKeyVerifier, ChannelKeyVerifierRecord};
use crate::connection::sink::ClientSink;
use crate::state_core::inbox::SourceAddressKey;
use crate::test_support::{FrameSink, StateCoreFixture, TestChannelKeyVerifier};

pub(super) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Which account-service and federation roles the router under test holds.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Role {
    /// Advertised policy only: no account service and no federation role.
    Plain,
    /// The account service is hosted on this node.
    Hosted,
    /// An edge whose coordinator link is down.
    Edge,
}

/// Router inputs a test overrides.
pub(super) struct Options {
    pub(super) role: Role,
    pub(super) allow_guests: bool,
    pub(super) access_token: Option<[u8; 32]>,
}

impl Options {
    pub(super) const fn role(role: Role) -> Self {
        Self {
            role,
            allow_guests: true,
            access_token: None,
        }
    }
}

/// The router under test and the state core whose context it borrows.
pub(super) struct Harness {
    pub(super) fixture: StateCoreFixture,
    pub(super) router: RegistrationRouter,
}

/// A xorshift stream, so scripted identifiers never repeat in one test.
pub(super) fn entropy_script() -> Vec<u8> {
    let mut state: u32 = 0x9e37_79b9;
    (0..262_144)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            u8::try_from(state & 0xff).unwrap_or(0)
        })
        .collect()
}

pub(super) fn executor() -> TestResult<crate::channels::RegisteredCommandExecutor> {
    let verifier: Arc<dyn ChannelKeyVerifier> = Arc::new(TestChannelKeyVerifier);
    let salt = [7; CHANNEL_KEY_SALT_BYTES];
    let hash = verifier.derive(b"dummy", &salt)?;
    Ok(crate::channels::RegisteredCommandExecutor::new(
        verifier,
        ChannelKeyVerifierRecord::new(salt, hash),
    ))
}

pub(super) fn coordinator_identity() -> crate::federation::PeerIdentity {
    crate::federation::PeerIdentity::new(
        ServerId::from_bytes([90; 16]),
        "hub.example",
        agenc_ircd_types::FederationRole::Coordinator,
        RecoveryEpoch::from_bytes([91; 16]),
        agenc_ircd_crypto::Ed25519SecretKey::from_bytes([12; 32]).public_key(),
        [13; 32],
    )
}

pub(super) fn edge_role(fixture: &StateCoreFixture) -> EdgeFederation {
    EdgeFederation::new(crate::federation::edge::EdgeConfig {
        network_id: fixture.identity.network_id,
        server_id: fixture.identity.server_id,
        server_name: "server.example".to_owned(),
        incarnation: fixture.identity.server_incarnation,
        coordinator: coordinator_identity(),
    })
}

pub(super) fn parsed(line: &str) -> TestResult<agenc_ircd_client_wire::ParsedMessage> {
    parse_message(FramedLine::new(line)?)?.ok_or_else(|| "empty test line".into())
}

impl Harness {
    pub(super) fn new(role: Role) -> TestResult<Self> {
        Self::with(Options::role(role))
    }

    pub(super) fn with(options: Options) -> TestResult<Self> {
        let fixture = StateCoreFixture::new(entropy_script())?;
        let account_service = if options.role == Role::Hosted {
            AccountServiceRole::Hosted(Box::new(crate::test_support::account_service_config(
                &fixture.identity,
                &fixture.opaque,
                fixture.key_state,
            )?))
        } else {
            AccountServiceRole::Advertised {
                creation_policy: AccountCreationPolicy::Open,
                recovery_epoch: fixture.identity.recovery_epoch,
            }
        };
        let router = RegistrationRouter::new(
            RegistrationRouterConfig {
                network_id: fixture.identity.network_id,
                server_id: fixture.identity.server_id,
                server_prefix: "server.example".to_owned(),
                display_name: "TestNetwork".to_owned(),
                allow_guests: options.allow_guests,
                access_token: options.access_token.map(Zeroizing::new),
                account_service,
            },
            executor()?,
        )?;
        let router = if options.role == Role::Edge {
            router.with_edge(edge_role(&fixture))
        } else {
            router
        };
        Ok(Self { fixture, router })
    }

    /// Opens one onion client whose sink admits or refuses every frame.
    pub(super) fn open(&mut self, number: u64, admit: bool) -> TestResult<Arc<FrameSink>> {
        let generation = ConnectionGeneration::new(number);
        let sink = FrameSink::new(generation, admit);
        let context = self.fixture.context_mut()?;
        let now = context.now();
        context.sessions_mut().open(
            generation,
            ListenerPurpose::ClientOnion,
            SourceAddressKey::onion_listener(),
            Arc::clone(&sink) as Arc<dyn ClientSink>,
            now,
        )?;
        self.router.connection_opened(context, generation);
        Ok(sink)
    }

    /// Runs one client line through the registration state machine and the
    /// router's action loop, as `route_message` does after admission.
    pub(super) fn line(&mut self, number: u64, line: &str) -> TestResult<RouteOutcome> {
        let generation = ConnectionGeneration::new(number);
        let message = parsed(line)?;
        let command = message.command().to_owned();
        let context = self.fixture.context_mut()?;
        let mut state = self
            .router
            .connections
            .remove(&generation)
            .ok_or("the connection is not registered with the router")?;
        let actions =
            state
                .registration
                .message(message, context.now().get(), state.advertised.as_ref());
        let mut observation = None;
        let outcome = match actions {
            Ok(actions) => self.router.drive_actions(
                context,
                generation,
                &mut state,
                actions,
                &mut observation,
            ),
            Err(error) => self
                .router
                .render_registration_error(context, generation, &state, &command, error),
        };
        if matches!(outcome, RouteOutcome::Close(_)) {
            self.router.release_lease(generation, &mut state);
        }
        self.router
            .refresh_deadline(context, generation, &mut state, outcome);
        self.router.connections.insert(generation, state);
        Ok(outcome)
    }

    /// The actions the registration state machine produces for one line,
    /// without running them.
    pub(super) fn actions(
        &mut self,
        number: u64,
        line: &str,
    ) -> TestResult<Vec<RegistrationAction>> {
        let generation = ConnectionGeneration::new(number);
        let message = parsed(line)?;
        let now = self.fixture.context_mut()?.now().get();
        let state = self
            .router
            .connections
            .get_mut(&generation)
            .ok_or("the connection is not registered with the router")?;
        let advertised = Arc::clone(&state.advertised);
        state
            .registration
            .message(message, now, advertised.as_ref())
            .map_err(|error| format!("registration refused the line: {error:?}").into())
    }

    /// Runs already produced actions through the router's action loop.
    pub(super) fn drive(
        &mut self,
        number: u64,
        actions: Vec<RegistrationAction>,
    ) -> TestResult<RouteOutcome> {
        let generation = ConnectionGeneration::new(number);
        let context = self.fixture.context_mut()?;
        let mut state = self
            .router
            .connections
            .remove(&generation)
            .ok_or("the connection is not registered with the router")?;
        let mut observation = None;
        let outcome =
            self.router
                .drive_actions(context, generation, &mut state, actions, &mut observation);
        self.router.connections.insert(generation, state);
        Ok(outcome)
    }

    /// Whether the router closed the transport of one connection.
    pub(super) fn sink_gone(&mut self, number: u64) -> TestResult<bool> {
        let generation = ConnectionGeneration::new(number);
        Ok(self
            .fixture
            .context_mut()?
            .sessions()
            .sink_for_generation(generation)
            .is_none())
    }

    /// Marks one transport gone, so every later send to it is refused.
    pub(super) fn drop_transport(&mut self, number: u64) -> TestResult {
        let generation = ConnectionGeneration::new(number);
        self.fixture
            .context_mut()?
            .sessions_mut()
            .mark_sink_gone(generation);
        Ok(())
    }

    /// Settles the staged batch and reports it to the router.
    pub(super) async fn settle(&mut self) -> TestResult {
        self.fixture.commit_staged_batch().await?;
        let context = self.fixture.context_mut()?;
        self.router.batch_applied(context, 1);
        Ok(())
    }

    /// Registers one guest and returns its sink after the welcome burst.
    pub(super) async fn register(&mut self, number: u64, nick: &str) -> TestResult<Arc<FrameSink>> {
        let sink = self.open(number, true)?;
        self.line(number, &format!("NICK {nick}"))?;
        self.line(number, &format!("USER {nick} 0 * :Real {nick}"))?;
        self.settle().await?;
        Ok(sink)
    }

    /// Advances the monotonic clock and fires every due timer at the router.
    pub(super) fn fire_timers_at(&mut self, ticks: u64) -> TestResult<usize> {
        let context = self.fixture.context_mut()?;
        context.set_monotonic_for_test(ticks);
        let mut fired = 0_usize;
        while let Some(entry) = {
            let now = context.now();
            context.timers_mut().pop_due(now)
        } {
            self.router.timer_fired(context, entry);
            fired = fired.saturating_add(1);
        }
        Ok(fired)
    }

    pub(super) fn state(&self, number: u64) -> TestResult<&ConnectionState> {
        self.router
            .connections
            .get(&ConnectionGeneration::new(number))
            .ok_or_else(|| "the connection is not registered with the router".into())
    }
}

pub(super) fn saw(sink: &FrameSink, needle: &str) -> bool {
    sink.lines().iter().any(|line| line.contains(needle))
}
