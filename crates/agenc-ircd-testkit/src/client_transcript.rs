//! Independent pipe-delimited client transcript fixtures and framing harness.

use std::collections::VecDeque;
use std::error::Error;
use std::fmt;

use agenc_ircd_client_wire::{
    AccessTokenPolicy, CapRequestReply, CapabilityProfile, CapabilitySpec, MAX_COMMAND_BYTES,
    OutputBudget, RegisteredCommandKind, RegistrationAction, RegistrationAuthCarrier,
    RegistrationError, RegistrationEvent, RegistrationPhase, RegistrationState, RenderedMessage,
    SecretBytes, StreamFramer, WelcomeStep, WireMessage, isupport_messages, numeric_reply,
    parse_message, split_capability_lines,
};
use agenc_ircd_types::NetworkId;
use subtle::ConstantTimeEq as _;

use crate::{DeterministicMonotonicClock, MAX_TRANSCRIPT_STEP_BYTES, MAX_TRANSCRIPT_STEPS};

const TRANSCRIPT_SERVER: &str = "server.example";
const TRANSCRIPT_NETWORK_ID: NetworkId = NetworkId::from_bytes([0; 32]);
const TRANSCRIPT_PING_TOKEN: &str = "AAAAAAAAAAAAAAAAAAAAAA";
const TRANSCRIPT_CONFIGURED_ACCESS_TOKEN: [u8; 32] = [0; 32];

/// Direction or deterministic-time operation in one fixture step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientTranscriptOperation {
    /// Raw bytes delivered to the client-wire stream framer.
    ClientBytes,
    /// Exact expected server bytes retained for caller comparison.
    ServerBytes,
    /// Advance a deterministic monotonic clock by the ASCII decimal payload.
    AdvanceMillis,
}

/// Payload representation in one fixture step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TranscriptEncoding {
    /// Literal printable ASCII bytes.
    Ascii,
    /// Lowercase hexadecimal bytes.
    Hex,
}

/// One bounded transcript step tied to a conformance evidence ID.
#[derive(Debug, Eq, PartialEq)]
pub struct ClientTranscriptStep {
    evidence_id: String,
    operation: ClientTranscriptOperation,
    encoding: TranscriptEncoding,
    payload: Vec<u8>,
}

impl ClientTranscriptStep {
    /// Returns the stable conformance evidence ID.
    #[must_use]
    pub fn evidence_id(&self) -> &str {
        &self.evidence_id
    }

    /// Returns the step operation.
    #[must_use]
    pub const fn operation(&self) -> ClientTranscriptOperation {
        self.operation
    }

    /// Returns the source encoding.
    #[must_use]
    pub const fn encoding(&self) -> TranscriptEncoding {
        self.encoding
    }

    /// Returns independently decoded bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// One complete checked client transcript.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct ClientTranscript {
    steps: Vec<ClientTranscriptStep>,
}

impl ClientTranscript {
    /// Returns steps in exact file order.
    #[must_use]
    pub fn steps(&self) -> &[ClientTranscriptStep] {
        &self.steps
    }
}

/// Closed transcript fixture/harness failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientTranscriptError {
    /// A non-comment line did not have four pipe-delimited fields.
    Shape,
    /// Evidence ID, operation, encoding, ASCII, hex, or decimal was invalid.
    Value,
    /// Step count or decoded payload exceeded a checked fixture bound.
    Limit,
    /// Raw stream framing failed.
    Framing,
    /// Syntax parsing failed.
    Parsing,
    /// A checked fixture calculation overflowed.
    Overflow,
    /// A bounded fixture or observation allocation failed.
    AllocationFailed,
    /// Capability or registration state rejected a transcript operation.
    Registration,
    /// A deterministic server response could not be rendered.
    Rendering,
    /// The fixture supplied server bytes when no response was pending.
    UnexpectedServerBytes,
    /// The fixture's server bytes differed from the rendered response.
    ServerBytesMismatch,
    /// The transcript ended before all rendered responses were asserted.
    MissingServerBytes,
}

impl fmt::Display for ClientTranscriptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Shape => "client transcript line must have four fields",
            Self::Value => "client transcript field is invalid",
            Self::Limit => "client transcript exceeds a checked fixture bound",
            Self::Framing => "client transcript stream framing failed",
            Self::Parsing => "client transcript syntax parsing failed",
            Self::Overflow => "client transcript calculation overflowed",
            Self::AllocationFailed => "client transcript allocation failed",
            Self::Registration => "client transcript registration state rejected an operation",
            Self::Rendering => "client transcript server response rendering failed",
            Self::UnexpectedServerBytes => "client transcript has unexpected server bytes",
            Self::ServerBytesMismatch => "client transcript server bytes do not match",
            Self::MissingServerBytes => "client transcript omitted expected server bytes",
        };
        formatter.write_str(message)
    }
}

impl Error for ClientTranscriptError {}

/// Parses `evidence-id|operation|encoding|payload` fixture lines.
pub fn parse_client_transcript(input: &str) -> Result<ClientTranscript, ClientTranscriptError> {
    let mut steps = Vec::new();
    for line in input.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if steps.len() >= MAX_TRANSCRIPT_STEPS {
            return Err(ClientTranscriptError::Limit);
        }
        let mut fields = line.split('|');
        let (Some(evidence_id), Some(operation), Some(encoding), Some(payload)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(ClientTranscriptError::Shape);
        };
        if fields.next().is_some() {
            return Err(ClientTranscriptError::Shape);
        }
        validate_evidence_id(evidence_id)?;
        let operation = parse_operation(operation)?;
        let encoding = parse_encoding(encoding)?;
        let payload = decode_payload(payload, operation, encoding)?;
        if payload.len() > MAX_TRANSCRIPT_STEP_BYTES {
            return Err(ClientTranscriptError::Limit);
        }
        steps
            .try_reserve(1)
            .map_err(|_| ClientTranscriptError::AllocationFailed)?;
        steps.push(ClientTranscriptStep {
            evidence_id: copy_string(evidence_id)?,
            operation,
            encoding,
            payload,
        });
    }
    Ok(ClientTranscript { steps })
}

/// Deterministic framing, registration, time, rendering, and byte-exact harness.
pub struct ClientTranscriptHarness {
    framer: StreamFramer,
    parsed: Vec<ClientTranscriptMessage>,
    empty_lines: usize,
    clock: DeterministicMonotonicClock,
    registration: RegistrationState,
    advertised: CapabilityProfile,
    configured_access_token: Option<SecretBytes>,
    registration_authenticated: bool,
    nickname: Option<String>,
    handoffs: Vec<ClientTranscriptHandoff>,
    welcome_steps: Vec<WelcomeStep>,
    expected_server: VecDeque<RenderedMessage<TranscriptOutputPermit>>,
}

/// A secret-free observation of an owned state-machine handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientTranscriptHandoff {
    /// One account-service carrier was transferred and immediately completed.
    Authentication(RegistrationAuthCarrier),
    /// One registered command was transferred to the next-stage owner.
    Registered(RegisteredCommandKind),
}

/// Non-secret observation retained after a parsed client message is consumed.
#[derive(Debug, Eq, PartialEq)]
pub struct ClientTranscriptMessage {
    command: String,
    parameter_count: usize,
    trailing_present: bool,
}

impl ClientTranscriptMessage {
    /// Returns the canonical command observed by the harness.
    #[must_use]
    pub fn command(&self) -> &str {
        &self.command
    }

    /// Returns the total number of middle and trailing parameters.
    #[must_use]
    pub const fn parameter_count(&self) -> usize {
        self.parameter_count
    }

    /// Returns whether the input carried an explicit trailing parameter.
    #[must_use]
    pub const fn trailing_present(&self) -> bool {
        self.trailing_present
    }
}

impl ClientTranscriptHarness {
    /// Creates one empty reusable stream harness.
    pub fn new() -> Result<Self, ClientTranscriptError> {
        let names = [
            "batch",
            "cap-notify",
            "labeled-response",
            "message-tags",
            "standard-replies",
        ];
        let mut advertised = Vec::new();
        advertised
            .try_reserve_exact(names.len())
            .map_err(|_| ClientTranscriptError::AllocationFailed)?;
        for name in names {
            advertised.push(
                CapabilitySpec::new(name, None).map_err(|_| ClientTranscriptError::Registration)?,
            );
        }
        let advertised =
            CapabilityProfile::new(advertised).map_err(|_| ClientTranscriptError::Registration)?;
        Self::with_profile_and_policy(advertised, AccessTokenPolicy::IgnoreCompatibilityPass)
    }

    /// Creates a harness with an explicit listener policy and advertised profile.
    pub fn with_profile_and_policy(
        advertised: CapabilityProfile,
        access_policy: AccessTokenPolicy,
    ) -> Result<Self, ClientTranscriptError> {
        let configured_access_token = match access_policy {
            AccessTokenPolicy::IgnoreCompatibilityPass => None,
            AccessTokenPolicy::RequireConfiguredToken => Some(&TRANSCRIPT_CONFIGURED_ACCESS_TOKEN),
        };
        Self::with_registration_scenario(advertised, access_policy, configured_access_token, false)
    }

    /// Creates a harness with explicit external registration outcomes.
    ///
    /// The configured token must be present exactly when the listener requires
    /// one. The authenticated flag models the result of the atomic external
    /// registration commit.
    pub fn with_registration_scenario(
        advertised: CapabilityProfile,
        access_policy: AccessTokenPolicy,
        configured_access_token: Option<&[u8; 32]>,
        registration_authenticated: bool,
    ) -> Result<Self, ClientTranscriptError> {
        let configured_access_token = match (access_policy, configured_access_token) {
            (AccessTokenPolicy::IgnoreCompatibilityPass, None) => None,
            (AccessTokenPolicy::RequireConfiguredToken, Some(token)) => {
                Some(SecretBytes::new(token).map_err(|_| ClientTranscriptError::Registration)?)
            }
            _ => return Err(ClientTranscriptError::Value),
        };
        Ok(Self {
            framer: StreamFramer::new().map_err(|_| ClientTranscriptError::Framing)?,
            parsed: Vec::new(),
            empty_lines: 0,
            clock: DeterministicMonotonicClock::at(0),
            registration: RegistrationState::new(0, access_policy)
                .map_err(|_| ClientTranscriptError::Registration)?,
            advertised,
            configured_access_token,
            registration_authenticated,
            nickname: None,
            handoffs: Vec::new(),
            welcome_steps: Vec::new(),
            expected_server: VecDeque::new(),
        })
    }

    /// Drives every fixture step and checks server bytes in exact response order.
    pub fn drive(&mut self, transcript: &ClientTranscript) -> Result<(), ClientTranscriptError> {
        for step in transcript.steps() {
            match step.operation {
                ClientTranscriptOperation::ClientBytes => self.drive_client(step.payload())?,
                ClientTranscriptOperation::ServerBytes => {
                    self.assert_server_bytes(step.payload())?;
                }
                ClientTranscriptOperation::AdvanceMillis => {
                    self.advance_time(step.payload())?;
                }
            }
        }
        Ok(())
    }

    /// Validates complete framing and that every response was byte-asserted.
    pub fn finish(&mut self) -> Result<(), ClientTranscriptError> {
        self.framer
            .finish()
            .map_err(|_| ClientTranscriptError::Framing)?;
        if self.expected_server.is_empty() {
            Ok(())
        } else {
            Err(ClientTranscriptError::MissingServerBytes)
        }
    }

    /// Returns parsed messages in receive order.
    #[must_use]
    pub fn messages(&self) -> &[ClientTranscriptMessage] {
        &self.parsed
    }

    /// Returns empty lines that consumed flood budget.
    #[must_use]
    pub const fn empty_lines(&self) -> usize {
        self.empty_lines
    }

    /// Returns the deterministic monotonic millisecond tick.
    #[must_use]
    pub const fn now(&self) -> u64 {
        self.clock.now()
    }

    /// Returns the registration phase reached by the transcript.
    #[must_use]
    pub const fn registration_phase(&self) -> RegistrationPhase {
        self.registration.phase()
    }

    /// Returns secret-free handoff observations in exact receive order.
    #[must_use]
    pub fn handoffs(&self) -> &[ClientTranscriptHandoff] {
        &self.handoffs
    }

    /// Returns welcome groups in the order requested by registration state.
    ///
    /// Groups owned by later stages are observed even when this Stage-02
    /// harness has no account or batch payload to render for them.
    #[must_use]
    pub fn welcome_steps(&self) -> &[WelcomeStep] {
        &self.welcome_steps
    }

    /// Returns rendered frames still awaiting byte-exact fixture assertions.
    #[must_use]
    pub fn pending_server_frame_count(&self) -> usize {
        self.expected_server.len()
    }

    /// Borrows one rendered frame that still awaits a fixture assertion.
    #[must_use]
    pub fn pending_server_frame_bytes(&self, index: usize) -> Option<&[u8]> {
        self.expected_server
            .get(index)
            .map(RenderedMessage::as_bytes)
    }

    fn drive_client(&mut self, bytes: &[u8]) -> Result<(), ClientTranscriptError> {
        let mut parsed_lines = Vec::new();
        let remaining = MAX_TRANSCRIPT_STEPS.saturating_sub(self.parsed.len());
        let possible_lines = bytes.len().div_ceil(2);
        parsed_lines
            .try_reserve_exact(possible_lines.min(remaining))
            .map_err(|_| ClientTranscriptError::AllocationFailed)?;
        let mut too_many_lines = false;
        let progress = self
            .framer
            .feed(bytes, |line| {
                if parsed_lines.len() == remaining {
                    too_many_lines = true;
                } else {
                    parsed_lines.push(parse_message(line));
                }
            })
            .map_err(|_| ClientTranscriptError::Framing)?;
        if too_many_lines {
            return Err(ClientTranscriptError::Limit);
        }
        self.empty_lines = self
            .empty_lines
            .checked_add(progress.empty_lines)
            .ok_or(ClientTranscriptError::Overflow)?;
        for parsed in parsed_lines {
            if self.parsed.len() >= MAX_TRANSCRIPT_STEPS {
                return Err(ClientTranscriptError::Limit);
            }
            let Some(message) = parsed.map_err(|_| ClientTranscriptError::Parsing)? else {
                continue;
            };
            self.parsed
                .try_reserve(1)
                .map_err(|_| ClientTranscriptError::AllocationFailed)?;
            let observation = ClientTranscriptMessage {
                command: copy_string(message.command())?,
                parameter_count: message.parameter_count(),
                trailing_present: message.trailing().is_some(),
            };
            let actions = self
                .registration
                .message(message, self.clock.now(), &self.advertised)
                .map_err(|_| ClientTranscriptError::Registration)?;
            self.parsed.push(observation);
            self.apply_actions(actions)?;
        }
        Ok(())
    }

    fn advance_time(&mut self, payload: &[u8]) -> Result<(), ClientTranscriptError> {
        let milliseconds = std::str::from_utf8(payload)
            .map_err(|_| ClientTranscriptError::Value)?
            .parse::<u64>()
            .map_err(|_| ClientTranscriptError::Value)?;
        let now = self
            .clock
            .advance(milliseconds)
            .map_err(|_| ClientTranscriptError::Overflow)?;
        let actions = self
            .registration
            .tick(now, Some(TRANSCRIPT_PING_TOKEN))
            .map_err(|_| ClientTranscriptError::Registration)?;
        self.apply_actions(actions)
    }

    fn assert_server_bytes(&mut self, bytes: &[u8]) -> Result<(), ClientTranscriptError> {
        let expected = self
            .expected_server
            .pop_front()
            .ok_or(ClientTranscriptError::UnexpectedServerBytes)?;
        if expected.as_bytes() == bytes {
            Ok(())
        } else {
            Err(ClientTranscriptError::ServerBytesMismatch)
        }
    }

    fn apply_actions(
        &mut self,
        actions: Vec<RegistrationAction>,
    ) -> Result<(), ClientTranscriptError> {
        for action in actions {
            self.apply_action(action)?;
        }
        Ok(())
    }

    fn apply_action(&mut self, action: RegistrationAction) -> Result<(), ClientTranscriptError> {
        let follow_up = match action {
            RegistrationAction::ReserveNickname {
                generation,
                nickname,
            }
            | RegistrationAction::ReplaceNickname {
                generation,
                nickname,
                ..
            } => self.accept_nickname_reservation(generation, nickname),
            RegistrationAction::CancelNicknameReservation { .. }
            | RegistrationAction::ReleaseNickname { .. } => return Ok(()),
            RegistrationAction::CheckAccessToken { generation, token } => {
                let accepted = self
                    .configured_access_token
                    .as_ref()
                    .is_some_and(|configured| {
                        bool::from(token.expose().ct_eq(configured.expose()))
                    });
                self.registration.event(
                    RegistrationEvent::AccessTokenChecked {
                        generation,
                        accepted,
                    },
                    self.clock.now(),
                )
            }
            RegistrationAction::CommitRegistration { generation, .. } => self.registration.event(
                RegistrationEvent::RegistrationCommitted {
                    generation,
                    accepted: true,
                    authenticated: self.registration_authenticated,
                },
                self.clock.now(),
            ),
            RegistrationAction::ForwardAuthCarrier {
                generation,
                carrier,
                ..
            } => {
                self.record_handoff(ClientTranscriptHandoff::Authentication(carrier))?;
                self.registration.event(
                    RegistrationEvent::AuthCarrierFinished { generation },
                    self.clock.now(),
                )
            }
            RegistrationAction::ForwardRegisteredCommand(command) => {
                self.record_handoff(ClientTranscriptHandoff::Registered(command.kind()))?;
                return Ok(());
            }
            RegistrationAction::InputDeferred => return Ok(()),
            RegistrationAction::ResumeDeferredInput(messages) => {
                for message in messages.into_messages() {
                    let actions = self
                        .registration
                        .message(message, self.clock.now(), &self.advertised)
                        .map_err(|_| ClientTranscriptError::Registration)?;
                    self.apply_actions(actions)?;
                }
                return Ok(());
            }
            other => return self.render_action(other),
        }
        .map_err(|_| ClientTranscriptError::Registration)?;
        self.apply_actions(follow_up)
    }

    fn accept_nickname_reservation(
        &mut self,
        generation: u64,
        nickname: String,
    ) -> Result<Vec<RegistrationAction>, RegistrationError> {
        self.nickname = Some(nickname);
        self.registration.event(
            RegistrationEvent::NicknameReserved {
                generation,
                accepted: true,
            },
            self.clock.now(),
        )
    }

    fn render_action(&mut self, action: RegistrationAction) -> Result<(), ClientTranscriptError> {
        let target = copy_string(self.nickname.as_deref().unwrap_or("*"))?;
        match action {
            RegistrationAction::CapabilityLs(tokens) => {
                self.queue_capability_tokens(&target, "LS", &tokens)?;
            }
            RegistrationAction::CapabilityRequest(reply) => match reply {
                CapRequestReply::Ack(tokens) => {
                    self.queue_capability_tokens(&target, "ACK", &tokens)?;
                }
                CapRequestReply::Nak(tokens) => {
                    self.queue_capability_tokens(&target, "NAK", &tokens)?;
                }
            },
            RegistrationAction::CapabilityList(tokens) => {
                self.queue_capability_tokens(&target, "LIST", &tokens)?;
            }
            RegistrationAction::CapabilityNew(token) => {
                self.queue_capability(&target, "NEW", false, &token)?;
            }
            RegistrationAction::CapabilityDel(name) => {
                self.queue_capability(&target, "DEL", false, &name)?;
            }
            RegistrationAction::CapabilityReconnectRequired(_) => {
                return Err(ClientTranscriptError::Registration);
            }
            other => return self.render_non_capability_action(&target, other),
        }
        Ok(())
    }

    fn render_non_capability_action(
        &mut self,
        target: &str,
        action: RegistrationAction,
    ) -> Result<(), ClientTranscriptError> {
        match action {
            RegistrationAction::WelcomeBurst(steps) => self.queue_welcome(target, &steps)?,
            RegistrationAction::NotRegistered => {
                self.queue_wire(numeric_reply(
                    TRANSCRIPT_SERVER,
                    451,
                    target,
                    &[],
                    Some("You have not registered"),
                )?)?;
            }
            RegistrationAction::AlreadyRegistered => {
                self.queue_wire(numeric_reply(
                    TRANSCRIPT_SERVER,
                    462,
                    target,
                    &[],
                    Some("You may not reregister"),
                )?)?;
            }
            RegistrationAction::Pong(token) => {
                self.queue_wire(WireMessage::new(
                    TRANSCRIPT_SERVER,
                    "PONG",
                    &[],
                    Some(&token),
                )?)?;
            }
            RegistrationAction::Ping(token) => {
                self.queue_wire(WireMessage::new(
                    TRANSCRIPT_SERVER,
                    "PING",
                    &[],
                    Some(&token),
                )?)?;
            }
            RegistrationAction::Close(reason) => {
                self.queue_wire(WireMessage::new(
                    TRANSCRIPT_SERVER,
                    "ERROR",
                    &[],
                    Some(&reason),
                )?)?;
            }
            RegistrationAction::CapabilityLs(_)
            | RegistrationAction::CapabilityRequest(_)
            | RegistrationAction::CapabilityList(_)
            | RegistrationAction::CapabilityNew(_)
            | RegistrationAction::CapabilityDel(_)
            | RegistrationAction::CapabilityReconnectRequired(_)
            | RegistrationAction::ReserveNickname { .. }
            | RegistrationAction::CancelNicknameReservation { .. }
            | RegistrationAction::ReplaceNickname { .. }
            | RegistrationAction::ReleaseNickname { .. }
            | RegistrationAction::CheckAccessToken { .. }
            | RegistrationAction::CommitRegistration { .. }
            | RegistrationAction::ForwardAuthCarrier { .. }
            | RegistrationAction::ForwardRegisteredCommand(_)
            | RegistrationAction::InputDeferred
            | RegistrationAction::ResumeDeferredInput(_) => {
                return Err(ClientTranscriptError::Registration);
            }
        }
        Ok(())
    }

    fn queue_capability_tokens(
        &mut self,
        target: &str,
        subcommand: &str,
        tokens: &[String],
    ) -> Result<(), ClientTranscriptError> {
        if subcommand != "LS" {
            let capabilities = join_tokens(tokens)?;
            return self.queue_capability(target, subcommand, false, &capabilities);
        }
        let budget = capability_trailing_budget(target, subcommand)?;
        let lines =
            split_capability_lines(tokens, budget).map_err(|_| ClientTranscriptError::Rendering)?;
        for line in lines {
            self.queue_capability(target, subcommand, line.continuation, &line.capabilities)?;
        }
        Ok(())
    }

    fn queue_capability(
        &mut self,
        target: &str,
        subcommand: &str,
        continuation: bool,
        capabilities: &str,
    ) -> Result<(), ClientTranscriptError> {
        let message = if continuation {
            WireMessage::new(
                TRANSCRIPT_SERVER,
                "CAP",
                &[target, subcommand, "*"],
                Some(capabilities),
            )?
        } else {
            WireMessage::new(
                TRANSCRIPT_SERVER,
                "CAP",
                &[target, subcommand],
                Some(capabilities),
            )?
        };
        self.queue_wire(message)
    }

    fn record_handoff(
        &mut self,
        handoff: ClientTranscriptHandoff,
    ) -> Result<(), ClientTranscriptError> {
        if self.handoffs.len() >= MAX_TRANSCRIPT_STEPS {
            return Err(ClientTranscriptError::Limit);
        }
        self.handoffs
            .try_reserve(1)
            .map_err(|_| ClientTranscriptError::AllocationFailed)?;
        self.handoffs.push(handoff);
        Ok(())
    }

    fn queue_welcome(
        &mut self,
        target: &str,
        steps: &[WelcomeStep],
    ) -> Result<(), ClientTranscriptError> {
        for step in steps {
            self.queue_welcome_step(target, *step)?;
            self.record_welcome_step(*step)?;
        }
        Ok(())
    }

    fn queue_welcome_step(
        &mut self,
        target: &str,
        step: WelcomeStep,
    ) -> Result<(), ClientTranscriptError> {
        match step {
            WelcomeStep::WelcomeThroughMyInfo => {
                for message in welcome_numerics(target)? {
                    self.queue_wire(message)?;
                }
            }
            WelcomeStep::Isupport => {
                for message in
                    isupport_messages(TRANSCRIPT_SERVER, target, "AgenC", &TRANSCRIPT_NETWORK_ID)?
                {
                    self.queue_wire(message)?;
                }
            }
            WelcomeStep::LuserCounters => {
                self.queue_wire(numeric_reply(
                    TRANSCRIPT_SERVER,
                    251,
                    target,
                    &[],
                    Some("There are 1 users and 0 services on 1 servers"),
                )?)?;
            }
            WelcomeStep::Motd => {
                self.queue_wire(numeric_reply(
                    TRANSCRIPT_SERVER,
                    422,
                    target,
                    &[],
                    Some("MOTD File is missing"),
                )?)?;
            }
            WelcomeStep::RecoveryEpoch => {
                let epoch = recovery_epoch(&self.advertised)?;
                self.queue_wire(WireMessage::new(
                    TRANSCRIPT_SERVER,
                    "NOTE",
                    &["*", "RECOVERY_EPOCH", &epoch],
                    Some("Current server recovery identity"),
                )?)?;
            }
            WelcomeStep::AccountState | WelcomeStep::RegistrationBatches => {}
        }
        Ok(())
    }

    fn record_welcome_step(&mut self, step: WelcomeStep) -> Result<(), ClientTranscriptError> {
        if self.welcome_steps.len() >= MAX_TRANSCRIPT_STEPS {
            return Err(ClientTranscriptError::Limit);
        }
        self.welcome_steps
            .try_reserve(1)
            .map_err(|_| ClientTranscriptError::AllocationFailed)?;
        self.welcome_steps.push(step);
        Ok(())
    }

    fn queue_wire(&mut self, message: WireMessage) -> Result<(), ClientTranscriptError> {
        if self.expected_server.len() >= MAX_TRANSCRIPT_STEPS {
            return Err(ClientTranscriptError::Limit);
        }
        self.expected_server
            .try_reserve(1)
            .map_err(|_| ClientTranscriptError::AllocationFailed)?;
        let measured = message
            .measure()
            .map_err(|_| ClientTranscriptError::Rendering)?;
        let bytes = measured.bytes();
        let mut budget = TranscriptOutputBudget(Some(bytes));
        let rendered = measured
            .encode(&mut budget)
            .map_err(|_| ClientTranscriptError::Rendering)?;
        self.expected_server.push_back(rendered);
        Ok(())
    }
}

fn recovery_epoch(profile: &CapabilityProfile) -> Result<String, ClientTranscriptError> {
    let epoch = profile
        .capabilities()
        .iter()
        .find(|capability| capability.name() == "agenc.ag/recovery")
        .and_then(CapabilitySpec::value)
        .and_then(|value| value.strip_prefix("v1."))
        .ok_or(ClientTranscriptError::Registration)?;
    copy_string(epoch)
}

fn welcome_numerics(target: &str) -> Result<[WireMessage; 4], ClientTranscriptError> {
    Ok([
        numeric_reply(TRANSCRIPT_SERVER, 1, target, &[], Some("Welcome to AgenC"))?,
        numeric_reply(
            TRANSCRIPT_SERVER,
            2,
            target,
            &[],
            Some("Your host is server.example"),
        )?,
        numeric_reply(
            TRANSCRIPT_SERVER,
            3,
            target,
            &[],
            Some("This server was created at build time"),
        )?,
        numeric_reply(
            TRANSCRIPT_SERVER,
            4,
            target,
            &[TRANSCRIPT_SERVER, "agenc-ircd", "io", "io"],
            None,
        )?,
    ])
}

struct TranscriptOutputPermit;

struct TranscriptOutputBudget(Option<usize>);

impl OutputBudget for TranscriptOutputBudget {
    type Permit = TranscriptOutputPermit;

    fn try_reserve_exact(
        &mut self,
        bytes: usize,
    ) -> Result<Self::Permit, agenc_ircd_client_wire::RenderError> {
        if self.0 != Some(bytes) {
            return Err(agenc_ircd_client_wire::RenderError::ReservationFailed);
        }
        self.0 = None;
        Ok(TranscriptOutputPermit)
    }
}

impl From<agenc_ircd_client_wire::RenderError> for ClientTranscriptError {
    fn from(_error: agenc_ircd_client_wire::RenderError) -> Self {
        Self::Rendering
    }
}

fn parse_operation(value: &str) -> Result<ClientTranscriptOperation, ClientTranscriptError> {
    match value {
        "client" => Ok(ClientTranscriptOperation::ClientBytes),
        "server" => Ok(ClientTranscriptOperation::ServerBytes),
        "advance" => Ok(ClientTranscriptOperation::AdvanceMillis),
        _ => Err(ClientTranscriptError::Value),
    }
}

fn parse_encoding(value: &str) -> Result<TranscriptEncoding, ClientTranscriptError> {
    match value {
        "ascii" => Ok(TranscriptEncoding::Ascii),
        "hex" => Ok(TranscriptEncoding::Hex),
        _ => Err(ClientTranscriptError::Value),
    }
}

fn decode_payload(
    value: &str,
    operation: ClientTranscriptOperation,
    encoding: TranscriptEncoding,
) -> Result<Vec<u8>, ClientTranscriptError> {
    if operation == ClientTranscriptOperation::AdvanceMillis {
        return decode_advance_payload(value, encoding);
    }
    match encoding {
        TranscriptEncoding::Ascii => {
            if value.len() > MAX_TRANSCRIPT_STEP_BYTES {
                return Err(ClientTranscriptError::Limit);
            }
            if !value
                .bytes()
                .all(|byte| byte.is_ascii() && !byte.is_ascii_control())
            {
                return Err(ClientTranscriptError::Value);
            }
            copy_bytes(value.as_bytes())
        }
        TranscriptEncoding::Hex => {
            validate_hex_payload_length(value)?;
            decode_hex(value)
        }
    }
}

fn decode_advance_payload(
    value: &str,
    encoding: TranscriptEncoding,
) -> Result<Vec<u8>, ClientTranscriptError> {
    if encoding != TranscriptEncoding::Ascii
        || value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || value.parse::<u64>().is_err()
    {
        return Err(ClientTranscriptError::Value);
    }
    copy_bytes(value.as_bytes())
}

fn validate_hex_payload_length(value: &str) -> Result<(), ClientTranscriptError> {
    let encoded_limit = MAX_TRANSCRIPT_STEP_BYTES
        .checked_mul(2)
        .ok_or(ClientTranscriptError::Overflow)?;
    if value.len() > encoded_limit {
        return Err(ClientTranscriptError::Limit);
    }
    Ok(())
}

fn decode_hex(value: &str) -> Result<Vec<u8>, ClientTranscriptError> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ClientTranscriptError::Value);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(value.len() / 2)
        .map_err(|_| ClientTranscriptError::AllocationFailed)?;
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(ClientTranscriptError::Value);
    }
    for pair in pairs {
        let text = std::str::from_utf8(pair).map_err(|_| ClientTranscriptError::Value)?;
        bytes.push(u8::from_str_radix(text, 16).map_err(|_| ClientTranscriptError::Value)?);
    }
    Ok(bytes)
}

fn validate_evidence_id(value: &str) -> Result<(), ClientTranscriptError> {
    if !value.starts_with("EVID-S02-")
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(ClientTranscriptError::Value);
    }
    Ok(())
}

fn copy_string(value: &str) -> Result<String, ClientTranscriptError> {
    let mut copy = String::new();
    copy.try_reserve_exact(value.len())
        .map_err(|_| ClientTranscriptError::AllocationFailed)?;
    copy.push_str(value);
    Ok(copy)
}

fn copy_bytes(value: &[u8]) -> Result<Vec<u8>, ClientTranscriptError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(value.len())
        .map_err(|_| ClientTranscriptError::AllocationFailed)?;
    copy.extend_from_slice(value);
    Ok(copy)
}

fn join_tokens(tokens: &[String]) -> Result<String, ClientTranscriptError> {
    let separators = tokens.len().saturating_sub(1);
    let length = tokens.iter().try_fold(separators, |length, token| {
        length
            .checked_add(token.len())
            .ok_or(ClientTranscriptError::Overflow)
    })?;
    let mut joined = String::new();
    joined
        .try_reserve_exact(length)
        .map_err(|_| ClientTranscriptError::AllocationFailed)?;
    for (index, token) in tokens.iter().enumerate() {
        if index != 0 {
            joined.push(' ');
        }
        joined.push_str(token);
    }
    Ok(joined)
}

fn capability_trailing_budget(
    target: &str,
    subcommand: &str,
) -> Result<usize, ClientTranscriptError> {
    let fixed = 1usize
        .checked_add(TRANSCRIPT_SERVER.len())
        .and_then(|bytes| bytes.checked_add(1 + "CAP".len()))
        .and_then(|bytes| bytes.checked_add(1 + target.len()))
        .and_then(|bytes| bytes.checked_add(1 + subcommand.len()))
        .and_then(|bytes| bytes.checked_add(2))
        .and_then(|bytes| bytes.checked_add(2))
        .ok_or(ClientTranscriptError::Overflow)?;
    MAX_COMMAND_BYTES
        .checked_sub(fixed)
        .ok_or(ClientTranscriptError::Rendering)
}
