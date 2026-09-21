//! Pure, generation-bound client registration and keepalive coordination.

use std::error::Error;
use std::fmt;

use agenc_relay_types::{CAPABILITIES, Nickname};
use zeroize::Zeroize as _;

use crate::{
    CapError, CapRequestReply, CapabilityProfile, CapabilityState, ParsedMessage,
    PostRegistrationCommandKind, RegistrationCapCommand, RegistrationCommand,
    RegistrationGrammarError, TextCarrierError, parse_registration_command,
};

/// Registration deadline after TLS completion, in monotonic milliseconds.
pub const REGISTRATION_TIMEOUT_MILLIS: u64 = 30_000;
/// Complete-message idle interval before a server PING.
pub const KEEPALIVE_IDLE_MILLIS: u64 = 120_000;
/// Exact matching-PONG deadline after a server PING.
pub const KEEPALIVE_PONG_MILLIS: u64 = 30_000;
/// Maximum messages awaiting the state owner.
pub const MAX_PENDING_MESSAGES: usize = 16;
/// Maximum bytes awaiting the state owner.
pub const MAX_PENDING_BYTES: usize = 32 * 1_024;

/// Whether the listener requires a 32-byte connection-admission token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessTokenPolicy {
    /// Accept and ignore one compatibility PASS of 1 through 256 bytes.
    IgnoreCompatibilityPass,
    /// Require an externally checked canonical 32-byte token.
    RequireConfiguredToken,
}

/// Secret bytes that zeroize on drop and do not implement [`fmt::Debug`].
///
/// ```compile_fail
/// use agenc_relay_client_wire::SecretBytes;
///
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<SecretBytes>();
/// ```
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Copies bytes into an independently owned zeroizing buffer.
    pub fn new(bytes: &[u8]) -> Result<Self, RegistrationError> {
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| RegistrationError::AllocationFailed)?;
        owned.extend_from_slice(bytes);
        Ok(Self(owned))
    }

    /// Borrows the secret only for an immediate external comparison.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Observable connection phase owned by the wire coordinator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationPhase {
    /// Registration inputs and external results are accepted.
    Negotiating,
    /// The generation-bound registration commit completed.
    Registered,
    /// A single close action has been issued.
    Closing,
    /// The transport confirmed closure.
    Closed,
}

/// Ordered logical groups in the successful welcome burst.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WelcomeStep {
    /// Numerics 001 through 004.
    WelcomeThroughMyInfo,
    /// One or more 005 lines.
    Isupport,
    /// Privacy-safe RPL_LUSER aggregate numerics.
    LuserCounters,
    /// MOTD numerics or ERR_NOMOTD.
    Motd,
    /// Recovery epoch NOTE when negotiated.
    RecoveryEpoch,
    /// Authenticated account tag/numeric state when present.
    AccountState,
    /// Negotiated registration-time batches.
    RegistrationBatches,
}

/// The one account-service carrier currently owned by a connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationAuthCarrier {
    /// IRCv3 SASL `AUTHENTICATE` carrying AGENC-OPAQUE.
    Sasl,
    /// Pre-registration `ACCTCREATE` transfer.
    AccountCreate,
    /// Registered-session `ACCTCRED` transfer.
    AccountCredentials,
}

/// The registered-session command class admitted at the wire boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegisteredCommandKind {
    /// A syntactically valid nickname change for Stage 03 resolution.
    Nickname,
    /// One exact Appendix-A public command grammar alternative.
    Public(PostRegistrationCommandKind),
}

/// Owned proof passed from the wire coordinator to the Stage 03 domain owner.
///
/// Private fields keep the command kind paired with the exact parsed message
/// that established it. The handoff does not perform target lookup,
/// authorization, policy, or domain mutation.
pub struct RegisteredCommandHandoff {
    kind: RegisteredCommandKind,
    message: ParsedMessage,
}

impl RegisteredCommandHandoff {
    fn new(kind: RegisteredCommandKind, message: ParsedMessage) -> Self {
        Self { kind, message }
    }

    /// Returns the state-independent grammar alternative proved by Stage 02.
    #[must_use]
    pub const fn kind(&self) -> RegisteredCommandKind {
        self.kind
    }

    /// Borrows the exact parsed message retained for domain conversion.
    #[must_use]
    pub const fn message(&self) -> &ParsedMessage {
        &self.message
    }

    /// Consumes the proof into its kind and exact parsed message.
    #[must_use]
    pub fn into_parts(self) -> (RegisteredCommandKind, ParsedMessage) {
        (self.kind, self.message)
    }
}

impl fmt::Debug for RegisteredCommandHandoff {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegisteredCommandHandoff")
            .field("kind", &self.kind)
            .field("parameter_count", &self.message.parameter_count())
            .field("tag_count", &self.message.tags().len())
            .finish()
    }
}

/// External effects requested by the pure registration coordinator.
pub enum RegistrationAction {
    /// Send CAP LS tokens, with values, in registry order.
    CapabilityLs(Vec<String>),
    /// Send one atomic CAP ACK or NAK.
    CapabilityRequest(CapRequestReply),
    /// Send enabled bare names for CAP LIST.
    CapabilityList {
        /// Enabled bare capability names in negotiation order.
        tokens: Vec<String>,
        /// Whether CAP 302 permits continuation lines.
        multiline: bool,
    },
    /// Send one complete capability token through CAP NEW.
    CapabilityNew(String),
    /// Send one bare capability name through CAP DEL.
    CapabilityDel(String),
    /// Require the connection owner to reconnect after a security-profile change.
    CapabilityReconnectRequired(String),
    /// Reserve a validated nickname under the supplied generation.
    ReserveNickname {
        /// Generation that must match the later result.
        generation: u64,
        /// Validated first wire spelling.
        nickname: String,
    },
    /// Cancel one in-flight reservation transaction idempotently.
    ///
    /// If acceptance won the race, an initial reservation is released and a
    /// replacement is rolled back to the prior generation recorded by its
    /// external owner.
    CancelNicknameReservation {
        /// In-flight reservation generation to cancel idempotently.
        generation: u64,
    },
    /// Atomically replace one held reservation with a newly validated nickname.
    ReplaceNickname {
        /// Generation that must match the later replacement result.
        generation: u64,
        /// Held reservation generation that must still own the nickname slot.
        previous_generation: u64,
        /// Validated replacement wire spelling.
        nickname: String,
    },
    /// Release one held reservation unless ownership was already transferred.
    ReleaseNickname {
        /// Held reservation generation to release idempotently.
        generation: u64,
    },
    /// Compare the configured access token outside this crate.
    CheckAccessToken {
        /// Generation that must match the later result.
        generation: u64,
        /// Zeroizing decoded token bytes.
        token: SecretBytes,
    },
    /// Commit the complete registration atomically outside this crate.
    CommitRegistration {
        /// Generation that must match the later result.
        generation: u64,
        /// Held nickname reservation transferred by the atomic commit.
        nickname_reservation_generation: u64,
        /// Globally reserved nickname.
        nickname: String,
        /// Control-stripped bounded realname.
        realname: String,
    },
    /// Emit the fixed successful welcome groups in this exact order.
    WelcomeBurst(Vec<WelcomeStep>),
    /// Forward one auth-carrier command without interpreting secret contents.
    ForwardAuthCarrier {
        /// Generation shared by every command in this one live transfer.
        generation: u64,
        /// Exact carrier class holding the per-connection ownership slot.
        carrier: RegistrationAuthCarrier,
        /// Consumed, bounded message whose drop path erases carrier contents.
        message: ParsedMessage,
    },
    /// Transfer one validated registered-session command to the domain owner.
    ForwardRegisteredCommand(RegisteredCommandHandoff),
    /// Confirm that one complete message is retained behind an in-flight commit.
    InputDeferred,
    /// Return deferred messages in receive order after the commit completes.
    ResumeDeferredInput(PendingInputQueue),
    /// Emit ERR_NICKNAMEINUSE (433) for the nickname whose reservation was refused.
    NicknameInUse(String),
    /// Emit ERR_NOTREGISTERED (451).
    NotRegistered,
    /// Emit ERR_ALREADYREGISTRED (462).
    AlreadyRegistered,
    /// Emit a fixed PONG payload.
    Pong(String),
    /// Emit a server keepalive PING.
    Ping(String),
    /// Begin idempotent authoritative closure after nickname cleanup actions.
    Close(String),
}

impl fmt::Debug for RegistrationAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::CapabilityLs(_) => "CapabilityLs",
            Self::CapabilityRequest(_) => "CapabilityRequest",
            Self::CapabilityList { .. } => "CapabilityList",
            Self::CapabilityNew(_) => "CapabilityNew",
            Self::CapabilityDel(_) => "CapabilityDel",
            Self::CapabilityReconnectRequired(_) => "CapabilityReconnectRequired",
            Self::ReserveNickname { .. } => "ReserveNickname",
            Self::CancelNicknameReservation { .. } => "CancelNicknameReservation",
            Self::ReplaceNickname { .. } => "ReplaceNickname",
            Self::ReleaseNickname { .. } => "ReleaseNickname",
            Self::CheckAccessToken { .. } => "CheckAccessToken",
            Self::CommitRegistration { .. } => "CommitRegistration",
            Self::WelcomeBurst(_) => "WelcomeBurst",
            Self::ForwardAuthCarrier { .. } => "ForwardAuthCarrier",
            Self::ForwardRegisteredCommand(_) => "ForwardRegisteredCommand",
            Self::InputDeferred => "InputDeferred",
            Self::ResumeDeferredInput(_) => "ResumeDeferredInput",
            Self::NicknameInUse(_) => "NicknameInUse",
            Self::NotRegistered => "NotRegistered",
            Self::AlreadyRegistered => "AlreadyRegistered",
            Self::Pong(_) => "Pong",
            Self::Ping(_) => "Ping",
            Self::Close(_) => "Close",
        };
        formatter
            .debug_tuple("RegistrationAction")
            .field(&name)
            .finish()
    }
}

/// Generation-bound outcomes returned by external owners.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationEvent {
    /// Nickname reservation finished.
    NicknameReserved {
        /// Original reservation generation.
        generation: u64,
        /// Whether the global owner accepted it.
        accepted: bool,
    },
    /// Configured access-token comparison finished.
    AccessTokenChecked {
        /// Original token-check generation.
        generation: u64,
        /// Whether constant-time comparison succeeded.
        accepted: bool,
    },
    /// Atomic registration commit finished.
    RegistrationCommitted {
        /// Original commit generation.
        generation: u64,
        /// Whether the owner committed the complete registration.
        accepted: bool,
        /// Whether an account is bound for welcome rendering.
        authenticated: bool,
    },
    /// The external carrier owner reached a terminal outcome.
    AuthCarrierFinished {
        /// Generation from the forwarded carrier action.
        generation: u64,
    },
    /// Transport destruction completed.
    TransportClosed,
}

/// Closed registration-wire failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationError {
    /// A command or parameter shape is invalid for the current state.
    InvalidCommand,
    /// NICK validation failed.
    InvalidNickname,
    /// USER or PASS ordering/shape was invalid.
    InvalidRegistrationField,
    /// A configured access token was not canonical or had the wrong length.
    InvalidAccessToken,
    /// CAP negotiation failed locally.
    Capability(CapError),
    /// State-independent Appendix-A registration grammar failed.
    Grammar(RegistrationGrammarError),
    /// Another account-service carrier already owns the connection slot.
    AuthenticationInProgress,
    /// The required capability is not negotiated in this state.
    AuthenticationUnavailable,
    /// A checked deadline calculation overflowed.
    Overflow,
    /// One bounded allocation failed.
    AllocationFailed,
    /// Pending input exceeded 16 messages or 32 KiB.
    PendingInputExceeded,
}

impl fmt::Display for RegistrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidCommand => "command is invalid during registration",
            Self::InvalidNickname => "nickname is invalid",
            Self::InvalidRegistrationField => "registration field or ordering is invalid",
            Self::InvalidAccessToken => "connection access token is invalid",
            Self::Capability(_) => "capability negotiation is invalid",
            Self::Grammar(_) => "registration command grammar is invalid",
            Self::AuthenticationInProgress => "another authentication carrier is active",
            Self::AuthenticationUnavailable => "authentication carrier is unavailable",
            Self::Overflow => "registration deadline calculation overflowed",
            Self::AllocationFailed => "registration allocation failed",
            Self::PendingInputExceeded => "pending registration input exceeds its bound",
        };
        formatter.write_str(message)
    }
}

impl Error for RegistrationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Capability(error) => Some(error),
            Self::Grammar(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CapError> for RegistrationError {
    fn from(error: CapError) -> Self {
        Self::Capability(error)
    }
}

impl From<RegistrationGrammarError> for RegistrationError {
    fn from(error: RegistrationGrammarError) -> Self {
        Self::Grammar(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActiveAuthCarrier {
    generation: u64,
    carrier: RegistrationAuthCarrier,
}

/// One connection-scoped nickname lease or in-flight lease request.
struct NicknameReservation {
    generation: u64,
    nickname: String,
}

impl NicknameReservation {
    fn new(generation: u64, nickname: String) -> Self {
        Self {
            generation,
            nickname,
        }
    }
}

impl Drop for NicknameReservation {
    fn drop(&mut self) {
        self.nickname.zeroize();
    }
}

/// Bounded owner of complete parsed messages waiting behind an external commit.
pub struct PendingInputQueue {
    messages: Vec<ParsedMessage>,
    backing_bytes: usize,
}

impl PendingInputQueue {
    /// Allocates the fixed queue slots before any message can be admitted.
    pub fn new() -> Result<Self, RegistrationError> {
        let mut messages = Vec::new();
        messages
            .try_reserve_exact(MAX_PENDING_MESSAGES)
            .map_err(|_| RegistrationError::AllocationFailed)?;
        Ok(Self {
            messages,
            backing_bytes: 0,
        })
    }

    /// Transfers ownership of one complete parsed message into the queue.
    pub fn admit(&mut self, message: ParsedMessage) -> Result<(), RegistrationError> {
        let total = self.checked_total(&message)?;
        self.push_admitted(message, total);
        Ok(())
    }

    /// Returns the number of messages currently owned by the queue.
    #[must_use]
    pub fn message_count(&self) -> usize {
        self.messages.len()
    }

    /// Returns the exact retained backing request currently owned by the queue.
    #[must_use]
    pub const fn backing_bytes(&self) -> usize {
        self.backing_bytes
    }

    /// Returns whether the queue owns no messages.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// Consumes the queue into its messages in original receive order.
    #[must_use]
    pub fn into_messages(self) -> std::vec::IntoIter<ParsedMessage> {
        self.messages.into_iter()
    }

    fn checked_total(&self, message: &ParsedMessage) -> Result<usize, RegistrationError> {
        let messages = self
            .messages
            .len()
            .checked_add(1)
            .ok_or(RegistrationError::Overflow)?;
        let total = self
            .backing_bytes
            .checked_add(message.requested_backing_bytes())
            .ok_or(RegistrationError::Overflow)?;
        if messages > MAX_PENDING_MESSAGES || total > MAX_PENDING_BYTES {
            return Err(RegistrationError::PendingInputExceeded);
        }
        Ok(total)
    }

    fn push_admitted(&mut self, message: ParsedMessage, total: usize) {
        self.messages.push(message);
        self.backing_bytes = total;
    }

    fn take_all(&mut self) -> Result<Self, RegistrationError> {
        let replacement = Self::new()?;
        Ok(std::mem::replace(self, replacement))
    }

    fn clear(&mut self) {
        self.messages.clear();
        self.backing_bytes = 0;
    }
}

impl fmt::Debug for PendingInputQueue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingInputQueue")
            .field("message_count", &self.message_count())
            .field("backing_bytes", &self.backing_bytes)
            .finish()
    }
}

/// Pure connection-registration wire state with no socket or domain access.
pub struct RegistrationState {
    phase: RegistrationPhase,
    access_policy: AccessTokenPolicy,
    cap: CapabilityState,
    deadline: u64,
    last_complete_message: u64,
    next_generation: u64,
    token_generation: Option<u64>,
    commit_generation: Option<u64>,
    active_auth: Option<ActiveAuthCarrier>,
    pass_seen: bool,
    access_token_accepted: bool,
    user_seen: bool,
    realname: Option<String>,
    pending_nickname: Option<NicknameReservation>,
    reserved_nickname: Option<NicknameReservation>,
    commit_pending: bool,
    pending_input: PendingInputQueue,
    outstanding_ping: Option<(String, u64)>,
}

impl RegistrationState {
    /// Starts NEGOTIATING at a caller-supplied monotonic millisecond tick.
    pub fn new(
        started_at: u64,
        access_policy: AccessTokenPolicy,
    ) -> Result<Self, RegistrationError> {
        let deadline = started_at
            .checked_add(REGISTRATION_TIMEOUT_MILLIS)
            .ok_or(RegistrationError::Overflow)?;
        Ok(Self {
            phase: RegistrationPhase::Negotiating,
            access_policy,
            cap: CapabilityState::default(),
            deadline,
            last_complete_message: started_at,
            next_generation: 0,
            token_generation: None,
            commit_generation: None,
            active_auth: None,
            pass_seen: false,
            access_token_accepted: access_policy == AccessTokenPolicy::IgnoreCompatibilityPass,
            user_seen: false,
            realname: None,
            pending_nickname: None,
            reserved_nickname: None,
            commit_pending: false,
            pending_input: PendingInputQueue::new()?,
            outstanding_ping: None,
        })
    }

    /// Returns the current monotonic phase.
    #[must_use]
    pub const fn phase(&self) -> RegistrationPhase {
        self.phase
    }

    /// Reports whether the keepalive coordinator is waiting for the exact
    /// PONG token issued by [`Self::tick`].
    #[must_use]
    pub const fn has_outstanding_ping(&self) -> bool {
        self.outstanding_ping.is_some()
    }

    /// Borrows negotiated bare capabilities for the registered-session handoff.
    #[must_use]
    pub fn enabled_capabilities(&self) -> &[String] {
        self.cap.enabled_names()
    }

    /// Borrows the negotiated capability state for registered-session
    /// rendering. The wire owner remains the only authority that can mutate
    /// this state.
    #[must_use]
    pub const fn capability_state(&self) -> &CapabilityState {
        &self.cap
    }

    /// Applies one live capability-profile transition to this connection.
    ///
    /// NEW and DEL actions are observable only when `cap-notify` was enabled
    /// before the transition. Reconnect-only security changes are always
    /// returned to the connection owner.
    pub fn apply_capability_profile(
        &mut self,
        current: &CapabilityProfile,
    ) -> Result<Vec<RegistrationAction>, RegistrationError> {
        if matches!(
            self.phase,
            RegistrationPhase::Closing | RegistrationPhase::Closed
        ) {
            return Ok(Vec::new());
        }
        // Both profiles are duplicate-free subsets of the same closed registry,
        // so each registry name can produce at most one diff action.
        let mut actions = action_buffer(CAPABILITIES.len())?;
        let cap_notify_enabled = self.cap.enabled("cap-notify");
        for change in self.cap.apply_profile(current)? {
            match change {
                crate::CapabilityChange::New(token) if cap_notify_enabled => {
                    actions.push(RegistrationAction::CapabilityNew(token));
                }
                crate::CapabilityChange::Del(name) if cap_notify_enabled => {
                    actions.push(RegistrationAction::CapabilityDel(name));
                }
                crate::CapabilityChange::ReconnectRequired(name) => {
                    actions.push(RegistrationAction::CapabilityReconnectRequired(name));
                }
                crate::CapabilityChange::New(_) | crate::CapabilityChange::Del(_) => {}
            }
        }
        Ok(actions)
    }

    /// Processes one syntax-validated message at a monotonic millisecond tick.
    pub fn message(
        &mut self,
        message: ParsedMessage,
        now: u64,
        advertised: &CapabilityProfile,
    ) -> Result<Vec<RegistrationAction>, RegistrationError> {
        if self.phase == RegistrationPhase::Closing || self.phase == RegistrationPhase::Closed {
            return Ok(Vec::new());
        }
        if let Some(actions) = self.expire_before_input(now, None)? {
            return Ok(actions);
        }
        self.last_complete_message = now;
        if self.commit_pending {
            return self.defer_input(message, now);
        }
        if self.phase == RegistrationPhase::Negotiating
            && !is_negotiating_command(message.command())
        {
            let actions = one_action(RegistrationAction::NotRegistered)?;
            return Ok(actions);
        }
        let command = parse_registration_command(&message, self.access_policy)?;
        if command == RegistrationCommand::Quit {
            return self.begin_close(quit_reason(&message)?);
        }
        if self.phase == RegistrationPhase::Registered {
            return self.registered_message(message, command, advertised);
        }
        self.negotiating_message(message, command, advertised)
    }

    fn defer_input(
        &mut self,
        message: ParsedMessage,
        now: u64,
    ) -> Result<Vec<RegistrationAction>, RegistrationError> {
        let total = match self.pending_input.checked_total(&message) {
            Ok(total) => total,
            Err(RegistrationError::PendingInputExceeded) => {
                return self.begin_close(copy_string("Pending input limit exceeded")?);
            }
            Err(error) => return Err(error),
        };
        let actions = one_action(RegistrationAction::InputDeferred)?;
        self.pending_input.push_admitted(message, total);
        self.last_complete_message = now;
        Ok(actions)
    }

    /// Applies current external results and releases accepted stale nickname leases.
    pub fn event(
        &mut self,
        event: RegistrationEvent,
        now: u64,
    ) -> Result<Vec<RegistrationAction>, RegistrationError> {
        if event == RegistrationEvent::TransportClosed {
            return self.finish_transport_close();
        }
        if self.ignore_event_after_close(event) {
            return Ok(Vec::new());
        }
        let stale_accepted_nickname = match event {
            RegistrationEvent::NicknameReserved {
                generation,
                accepted: true,
            } if !self.owns_nickname_generation(generation) => Some(generation),
            _ => None,
        };
        if let Some(actions) = self.expire_before_input(now, stale_accepted_nickname)? {
            return Ok(actions);
        }
        match event {
            RegistrationEvent::NicknameReserved {
                generation,
                accepted,
            } => self.nickname_reserved(generation, accepted),
            RegistrationEvent::AccessTokenChecked {
                generation,
                accepted,
            } => self.access_token_checked(generation, accepted),
            RegistrationEvent::RegistrationCommitted {
                generation,
                accepted,
                authenticated,
            } => self.registration_committed(generation, accepted, authenticated),
            RegistrationEvent::AuthCarrierFinished { generation } => {
                self.auth_carrier_finished(generation)
            }
            RegistrationEvent::TransportClosed => {
                self.phase = RegistrationPhase::Closed;
                Ok(Vec::new())
            }
        }
    }

    fn nickname_reserved(
        &mut self,
        generation: u64,
        accepted: bool,
    ) -> Result<Vec<RegistrationAction>, RegistrationError> {
        if self.phase == RegistrationPhase::Registered {
            return Ok(Vec::new());
        }
        if !self
            .pending_nickname
            .as_ref()
            .is_some_and(|reservation| reservation.generation == generation)
        {
            if accepted && !self.owns_nickname_generation(generation) {
                return one_action(RegistrationAction::ReleaseNickname { generation });
            }
            return Ok(Vec::new());
        }
        if !accepted {
            // A client chooses its next nickname from this reply; silence leaves it waiting
            // for the registration deadline.
            let refused = self.pending_nickname.take();
            let mut actions = self.try_commit()?;
            if let Some(refused) = refused {
                actions
                    .try_reserve(1)
                    .map_err(|_| RegistrationError::AllocationFailed)?;
                actions.insert(
                    0,
                    RegistrationAction::NicknameInUse(refused.nickname.clone()),
                );
            }
            return Ok(actions);
        }
        let reservation = self
            .pending_nickname
            .take()
            .ok_or(RegistrationError::InvalidNickname)?;
        self.reserved_nickname = Some(reservation);
        self.try_commit()
    }

    fn access_token_checked(
        &mut self,
        generation: u64,
        accepted: bool,
    ) -> Result<Vec<RegistrationAction>, RegistrationError> {
        if Some(generation) != self.token_generation {
            return Ok(Vec::new());
        }
        if !accepted {
            return self.begin_close(copy_string("Access token rejected")?);
        }
        self.access_token_accepted = true;
        match self.try_commit() {
            Ok(actions) => {
                self.token_generation = None;
                Ok(actions)
            }
            Err(error) => {
                self.access_token_accepted = false;
                Err(error)
            }
        }
    }

    fn registration_committed(
        &mut self,
        generation: u64,
        accepted: bool,
        authenticated: bool,
    ) -> Result<Vec<RegistrationAction>, RegistrationError> {
        if Some(generation) != self.commit_generation || !self.commit_pending {
            return Ok(Vec::new());
        }
        if !accepted {
            return self.begin_close(copy_string("Registration rejected")?);
        }
        let steps = welcome_steps(self.cap.enabled("agenc.ag/recovery"), authenticated)?;
        let resume_input = !self.pending_input.is_empty();
        let mut actions = action_buffer(1 + usize::from(resume_input))?;
        actions.push(RegistrationAction::WelcomeBurst(steps));
        if resume_input {
            actions.push(RegistrationAction::ResumeDeferredInput(
                self.pending_input.take_all()?,
            ));
        }
        let transferred_nickname = self
            .reserved_nickname
            .take()
            .ok_or(RegistrationError::InvalidNickname)?;
        drop(transferred_nickname);
        self.commit_pending = false;
        self.commit_generation = None;
        self.phase = RegistrationPhase::Registered;
        Ok(actions)
    }

    fn auth_carrier_finished(
        &mut self,
        generation: u64,
    ) -> Result<Vec<RegistrationAction>, RegistrationError> {
        if !self
            .active_auth
            .is_some_and(|active| active.generation == generation)
        {
            return Ok(Vec::new());
        }
        let active = self.active_auth.take();
        let result = if self.phase == RegistrationPhase::Negotiating {
            self.try_commit()
        } else {
            Ok(Vec::new())
        };
        if result.is_err() {
            self.active_auth = active;
        }
        result
    }

    /// Applies registration and keepalive deadlines.
    pub fn tick(
        &mut self,
        now: u64,
        ping_token: Option<&str>,
    ) -> Result<Vec<RegistrationAction>, RegistrationError> {
        if self.phase == RegistrationPhase::Negotiating && now >= self.deadline {
            return self.begin_close(copy_string("Registration timed out")?);
        }
        if self.phase != RegistrationPhase::Registered {
            return Ok(Vec::new());
        }
        if self
            .outstanding_ping
            .as_ref()
            .is_some_and(|(_, deadline)| now >= *deadline)
        {
            return self.begin_close(copy_string("Ping timeout")?);
        }
        let idle_deadline = self
            .last_complete_message
            .checked_add(KEEPALIVE_IDLE_MILLIS)
            .ok_or(RegistrationError::Overflow)?;
        if self.outstanding_ping.is_none() && now >= idle_deadline {
            let token = validate_ping_token(ping_token)?;
            let deadline = now
                .checked_add(KEEPALIVE_PONG_MILLIS)
                .ok_or(RegistrationError::Overflow)?;
            let stored_token = copy_string(&token)?;
            let mut actions = action_buffer(1)?;
            self.outstanding_ping = Some((stored_token, deadline));
            actions.push(RegistrationAction::Ping(token));
            return Ok(actions);
        }
        Ok(Vec::new())
    }

    fn negotiating_message(
        &mut self,
        mut message: ParsedMessage,
        command: RegistrationCommand,
        advertised: &CapabilityProfile,
    ) -> Result<Vec<RegistrationAction>, RegistrationError> {
        match command {
            RegistrationCommand::Cap(command) => self.cap_message(command, &message, advertised),
            RegistrationCommand::Pass => self.pass_message(&mut message),
            RegistrationCommand::Nick => self.nick_message(&message),
            RegistrationCommand::User => self.user_message(&message),
            RegistrationCommand::Ping => {
                one_action(RegistrationAction::Pong(reflected_payload(&message)?))
            }
            RegistrationCommand::Pong => {
                self.accept_pong(&message);
                Ok(Vec::new())
            }
            RegistrationCommand::Authenticate => {
                self.auth_message(RegistrationAuthCarrier::Sasl, message)
            }
            RegistrationCommand::AccountCreate(_) => {
                self.auth_message(RegistrationAuthCarrier::AccountCreate, message)
            }
            RegistrationCommand::AccountCredentials(_)
            | RegistrationCommand::PostRegistration(_) => {
                one_action(RegistrationAction::NotRegistered)
            }
            RegistrationCommand::Quit => Ok(Vec::new()),
        }
    }

    fn registered_message(
        &mut self,
        message: ParsedMessage,
        command: RegistrationCommand,
        advertised: &CapabilityProfile,
    ) -> Result<Vec<RegistrationAction>, RegistrationError> {
        match command {
            RegistrationCommand::Cap(command) => self.cap_message(command, &message, advertised),
            RegistrationCommand::Ping => {
                one_action(RegistrationAction::Pong(reflected_payload(&message)?))
            }
            RegistrationCommand::Pong => {
                self.accept_pong(&message);
                Ok(Vec::new())
            }
            RegistrationCommand::Pass | RegistrationCommand::User => {
                one_action(RegistrationAction::AlreadyRegistered)
            }
            RegistrationCommand::Authenticate => {
                self.auth_message(RegistrationAuthCarrier::Sasl, message)
            }
            RegistrationCommand::AccountCredentials(_) => {
                self.auth_message(RegistrationAuthCarrier::AccountCredentials, message)
            }
            RegistrationCommand::AccountCreate(_) => Err(RegistrationError::InvalidCommand),
            RegistrationCommand::Nick => one_action(RegistrationAction::ForwardRegisteredCommand(
                RegisteredCommandHandoff::new(RegisteredCommandKind::Nickname, message),
            )),
            RegistrationCommand::PostRegistration(kind) => {
                self.require_command_capabilities(kind)?;
                one_action(RegistrationAction::ForwardRegisteredCommand(
                    RegisteredCommandHandoff::new(RegisteredCommandKind::Public(kind), message),
                ))
            }
            RegistrationCommand::Quit => Ok(Vec::new()),
        }
    }

    fn require_command_capabilities(
        &self,
        kind: PostRegistrationCommandKind,
    ) -> Result<(), RegistrationError> {
        let required: &[&str] = match kind {
            PostRegistrationCommandKind::Account(_) => {
                &["agenc.ag/account-controls", "standard-replies"]
            }
            PostRegistrationCommandKind::ChannelControl(_) => {
                &["agenc.ag/channel-controls", "standard-replies"]
            }
            PostRegistrationCommandKind::ChatHistory(_) => &["draft/chathistory"],
            _ => &[],
        };
        if required.iter().all(|name| self.cap.enabled(name)) {
            Ok(())
        } else {
            Err(RegistrationError::Grammar(
                RegistrationGrammarError::NoPrivileges,
            ))
        }
    }

    fn expire_before_input(
        &mut self,
        now: u64,
        stale_accepted_nickname: Option<u64>,
    ) -> Result<Option<Vec<RegistrationAction>>, RegistrationError> {
        let reason = if self.phase == RegistrationPhase::Negotiating && now >= self.deadline {
            Some("Registration timed out")
        } else if self.phase == RegistrationPhase::Registered
            && self
                .outstanding_ping
                .as_ref()
                .is_some_and(|(_, deadline)| now >= *deadline)
        {
            Some("Ping timeout")
        } else {
            None
        };
        match reason {
            Some(reason) => self
                .begin_close_with_stale_reservation(copy_string(reason)?, stale_accepted_nickname)
                .map(Some),
            None => Ok(None),
        }
    }

    fn auth_message(
        &mut self,
        carrier: RegistrationAuthCarrier,
        message: ParsedMessage,
    ) -> Result<Vec<RegistrationAction>, RegistrationError> {
        if self
            .active_auth
            .is_some_and(|active| active.carrier != carrier)
        {
            return Err(RegistrationError::AuthenticationInProgress);
        }
        let required_capability = match carrier {
            RegistrationAuthCarrier::Sasl => "sasl",
            RegistrationAuthCarrier::AccountCreate => "agenc.ag/account-create",
            RegistrationAuthCarrier::AccountCredentials => "agenc.ag/account-credentials",
        };
        if !self.cap.enabled(required_capability)
            || (self.phase == RegistrationPhase::Negotiating && !self.cap.blocks_registration())
        {
            return Err(RegistrationError::AuthenticationUnavailable);
        }
        let active = match self.active_auth {
            Some(active) if active.carrier == carrier => active,
            Some(_) => return Err(RegistrationError::AuthenticationInProgress),
            None => ActiveAuthCarrier {
                generation: self.fresh_generation()?,
                carrier,
            },
        };
        let mut actions = action_buffer(1)?;
        self.active_auth = Some(active);
        actions.push(RegistrationAction::ForwardAuthCarrier {
            generation: active.generation,
            carrier,
            message,
        });
        Ok(actions)
    }

    fn cap_message(
        &mut self,
        command: RegistrationCapCommand,
        message: &ParsedMessage,
        advertised: &CapabilityProfile,
    ) -> Result<Vec<RegistrationAction>, RegistrationError> {
        match command {
            RegistrationCapCommand::ListSupported => self.cap_ls_message(message, advertised),
            RegistrationCapCommand::Request => self.cap_request_message(message, advertised),
            RegistrationCapCommand::ListEnabled => one_action(RegistrationAction::CapabilityList {
                tokens: self.cap.list()?,
                multiline: self.cap.supports_multiline(),
            }),
            RegistrationCapCommand::End => self.cap_end_message(),
        }
    }

    fn cap_ls_message(
        &mut self,
        message: &ParsedMessage,
        advertised: &CapabilityProfile,
    ) -> Result<Vec<RegistrationAction>, RegistrationError> {
        let mut actions = action_buffer(1)?;
        let version = message.middle().get(1).map(String::as_str);
        let tokens = self.cap.ls(version, advertised)?;
        actions.push(RegistrationAction::CapabilityLs(tokens));
        Ok(actions)
    }

    fn cap_request_message(
        &mut self,
        message: &ParsedMessage,
        advertised: &CapabilityProfile,
    ) -> Result<Vec<RegistrationAction>, RegistrationError> {
        let request = message
            .trailing()
            .ok_or(RegistrationError::InvalidCommand)?;
        if self
            .active_auth
            .is_some_and(|active| request_disables_carrier(request, active.carrier))
        {
            return Err(RegistrationError::AuthenticationInProgress);
        }
        let mut actions = action_buffer(1)?;
        let reply = self.cap.request(request, advertised)?;
        actions.push(RegistrationAction::CapabilityRequest(reply));
        Ok(actions)
    }

    fn cap_end_message(&mut self) -> Result<Vec<RegistrationAction>, RegistrationError> {
        if self.phase == RegistrationPhase::Registered {
            return Ok(Vec::new());
        }
        if self.active_auth.is_some() {
            return Err(RegistrationError::AuthenticationInProgress);
        }
        self.cap.end()?;
        if self.phase == RegistrationPhase::Negotiating {
            self.try_commit()
        } else {
            Ok(Vec::new())
        }
    }

    fn pass_message(
        &mut self,
        message: &mut ParsedMessage,
    ) -> Result<Vec<RegistrationAction>, RegistrationError> {
        if self.pass_seen || self.user_seen {
            return one_action(RegistrationAction::AlreadyRegistered);
        }
        let token = message
            .take_single_parameter()
            .ok_or(RegistrationError::InvalidRegistrationField)?;
        let token = zeroize::Zeroizing::new(token);
        match self.access_policy {
            AccessTokenPolicy::IgnoreCompatibilityPass => {
                if token.is_empty() || token.len() > 256 {
                    return Err(RegistrationError::InvalidRegistrationField);
                }
                self.pass_seen = true;
                let result = self.try_commit();
                if result.is_err() {
                    self.pass_seen = false;
                }
                result
            }
            AccessTokenPolicy::RequireConfiguredToken => {
                let decoded = crate::CanonicalBase64Url::parse(token.as_str(), 32, 32)
                    .map_err(map_access_token_error)?;
                let token = SecretBytes::new(decoded.as_bytes())?;
                let mut actions = action_buffer(1)?;
                let generation = self.fresh_generation()?;
                self.pass_seen = true;
                self.token_generation = Some(generation);
                actions.push(RegistrationAction::CheckAccessToken { generation, token });
                Ok(actions)
            }
        }
    }

    fn nick_message(
        &mut self,
        message: &ParsedMessage,
    ) -> Result<Vec<RegistrationAction>, RegistrationError> {
        let nickname = single_parameter(message).ok_or(RegistrationError::InvalidNickname)?;
        let parsed = Nickname::parse(nickname).map_err(|_| RegistrationError::InvalidNickname)?;
        let pending_nickname = copy_string(parsed.presentation())?;
        let action_nickname = copy_string(parsed.presentation())?;
        let pending_generation = self
            .pending_nickname
            .as_ref()
            .map(|reservation| reservation.generation);
        let previous_generation = self
            .reserved_nickname
            .as_ref()
            .map(|reservation| reservation.generation);
        let action_count = 1_usize
            .checked_add(usize::from(pending_generation.is_some()))
            .ok_or(RegistrationError::Overflow)?;
        let mut actions = action_buffer(action_count)?;
        let generation = self.fresh_generation()?;
        if let Some(generation) = pending_generation {
            actions.push(RegistrationAction::CancelNicknameReservation { generation });
        }
        match previous_generation {
            Some(previous_generation) => actions.push(RegistrationAction::ReplaceNickname {
                generation,
                previous_generation,
                nickname: action_nickname,
            }),
            None => actions.push(RegistrationAction::ReserveNickname {
                generation,
                nickname: action_nickname,
            }),
        }
        self.pending_nickname = Some(NicknameReservation::new(generation, pending_nickname));
        Ok(actions)
    }

    fn user_message(
        &mut self,
        message: &ParsedMessage,
    ) -> Result<Vec<RegistrationAction>, RegistrationError> {
        if self.user_seen {
            return one_action(RegistrationAction::AlreadyRegistered);
        }
        if message.middle().len() != 3 || message.trailing().is_none() {
            return Err(RegistrationError::InvalidRegistrationField);
        }
        let realname = strip_controls(message.trailing().unwrap_or_default())?;
        if realname.len() > 64 {
            return Err(RegistrationError::InvalidRegistrationField);
        }
        self.user_seen = true;
        self.realname = Some(realname);
        let result = self.try_commit();
        if result.is_err() {
            self.user_seen = false;
            zeroize_option(&mut self.realname);
        }
        result
    }

    fn try_commit(&mut self) -> Result<Vec<RegistrationAction>, RegistrationError> {
        let ready = self.user_seen
            && self.access_token_accepted
            && self.pending_nickname.is_none()
            && self.reserved_nickname.is_some()
            && self.active_auth.is_none()
            && !self.cap.blocks_registration();
        if !ready || self.commit_pending {
            return Ok(Vec::new());
        }
        let reservation = self
            .reserved_nickname
            .as_ref()
            .ok_or(RegistrationError::InvalidNickname)?;
        let nickname_reservation_generation = reservation.generation;
        let nickname = copy_string(&reservation.nickname)?;
        let realname = copy_string(
            self.realname
                .as_deref()
                .ok_or(RegistrationError::InvalidRegistrationField)?,
        )?;
        let mut actions = action_buffer(1)?;
        let generation = self.fresh_generation()?;
        self.commit_generation = Some(generation);
        self.commit_pending = true;
        actions.push(RegistrationAction::CommitRegistration {
            generation,
            nickname_reservation_generation,
            nickname,
            realname,
        });
        Ok(actions)
    }

    fn fresh_generation(&mut self) -> Result<u64, RegistrationError> {
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or(RegistrationError::Overflow)?;
        Ok(self.next_generation)
    }

    fn accept_pong(&mut self, message: &ParsedMessage) {
        let received = single_parameter(message);
        if self
            .outstanding_ping
            .as_ref()
            .is_some_and(|(expected, _)| received == Some(expected.as_str()))
        {
            self.outstanding_ping = None;
        }
    }

    fn owns_nickname_generation(&self, generation: u64) -> bool {
        self.pending_nickname
            .as_ref()
            .is_some_and(|reservation| reservation.generation == generation)
            || self
                .reserved_nickname
                .as_ref()
                .is_some_and(|reservation| reservation.generation == generation)
    }

    fn begin_close(
        &mut self,
        reason: String,
    ) -> Result<Vec<RegistrationAction>, RegistrationError> {
        self.begin_close_with_stale_reservation(reason, None)
    }

    fn begin_close_with_stale_reservation(
        &mut self,
        reason: String,
        stale_accepted_nickname: Option<u64>,
    ) -> Result<Vec<RegistrationAction>, RegistrationError> {
        if self.phase == RegistrationPhase::Closing || self.phase == RegistrationPhase::Closed {
            return Ok(Vec::new());
        }
        let stale_accepted_nickname = stale_accepted_nickname
            .filter(|generation| !self.owns_nickname_generation(*generation));
        let action_count = 1_usize
            .checked_add(usize::from(self.pending_nickname.is_some()))
            .and_then(|count| count.checked_add(usize::from(self.reserved_nickname.is_some())))
            .and_then(|count| count.checked_add(usize::from(stale_accepted_nickname.is_some())))
            .ok_or(RegistrationError::Overflow)?;
        let mut actions = action_buffer(action_count)?;
        self.push_nickname_cleanup_actions(&mut actions);
        if let Some(generation) = stale_accepted_nickname {
            actions.push(RegistrationAction::ReleaseNickname { generation });
        }
        actions.push(RegistrationAction::Close(reason));
        self.token_generation = None;
        self.commit_generation = None;
        self.active_auth = None;
        self.commit_pending = false;
        self.pending_input.clear();
        self.pending_nickname = None;
        self.reserved_nickname = None;
        zeroize_option(&mut self.realname);
        self.outstanding_ping = None;
        self.phase = RegistrationPhase::Closing;
        Ok(actions)
    }

    fn push_nickname_cleanup_actions(&self, actions: &mut Vec<RegistrationAction>) {
        if let Some(reservation) = &self.pending_nickname {
            actions.push(RegistrationAction::CancelNicknameReservation {
                generation: reservation.generation,
            });
        }
        if let Some(reservation) = &self.reserved_nickname {
            actions.push(RegistrationAction::ReleaseNickname {
                generation: reservation.generation,
            });
        }
    }

    fn ignore_event_after_close(&mut self, event: RegistrationEvent) -> bool {
        match self.phase {
            RegistrationPhase::Closed => true,
            RegistrationPhase::Closing => {
                if event == RegistrationEvent::TransportClosed {
                    self.phase = RegistrationPhase::Closed;
                }
                true
            }
            RegistrationPhase::Negotiating | RegistrationPhase::Registered => false,
        }
    }

    fn finish_transport_close(&mut self) -> Result<Vec<RegistrationAction>, RegistrationError> {
        if self.phase == RegistrationPhase::Closed {
            return Ok(Vec::new());
        }
        let action_count = usize::from(self.pending_nickname.is_some())
            .checked_add(usize::from(self.reserved_nickname.is_some()))
            .ok_or(RegistrationError::Overflow)?;
        let mut actions = action_buffer(action_count)?;
        self.push_nickname_cleanup_actions(&mut actions);
        self.token_generation = None;
        self.commit_generation = None;
        self.active_auth = None;
        self.commit_pending = false;
        self.pending_input.clear();
        self.pending_nickname = None;
        self.reserved_nickname = None;
        zeroize_option(&mut self.realname);
        if let Some((mut token, _)) = self.outstanding_ping.take() {
            token.zeroize();
        }
        self.phase = RegistrationPhase::Closed;
        Ok(actions)
    }
}

impl Drop for RegistrationState {
    fn drop(&mut self) {
        zeroize_option(&mut self.realname);
        self.pending_nickname = None;
        self.reserved_nickname = None;
        if let Some((token, _)) = &mut self.outstanding_ping {
            token.zeroize();
        }
    }
}

fn zeroize_option(value: &mut Option<String>) {
    if let Some(mut owned) = value.take() {
        owned.zeroize();
    }
}

fn single_parameter(message: &ParsedMessage) -> Option<&str> {
    match (message.middle(), message.trailing()) {
        ([only], None) => Some(only),
        ([], Some(only)) => Some(only),
        _ => None,
    }
}

fn is_negotiating_command(command: &str) -> bool {
    matches!(
        command,
        "CAP" | "AUTHENTICATE" | "PASS" | "NICK" | "USER" | "PING" | "PONG" | "QUIT" | "ACCTCREATE"
    )
}

fn strip_controls(value: &str) -> Result<String, RegistrationError> {
    let mut stripped = String::new();
    stripped
        .try_reserve_exact(value.len())
        .map_err(|_| RegistrationError::AllocationFailed)?;
    stripped.extend(value.chars().filter(|character| !character.is_control()));
    Ok(stripped)
}

fn reflected_payload(message: &ParsedMessage) -> Result<String, RegistrationError> {
    copy_string(single_parameter(message).unwrap_or_default())
}

fn quit_reason(message: &ParsedMessage) -> Result<String, RegistrationError> {
    copy_string(single_parameter(message).unwrap_or("Client Quit"))
}

fn validate_ping_token(token: Option<&str>) -> Result<String, RegistrationError> {
    let token = token.ok_or(RegistrationError::InvalidRegistrationField)?;
    if token.len() != 22
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(RegistrationError::InvalidRegistrationField);
    }
    copy_string(token)
}

fn request_disables_carrier(request: &str, carrier: RegistrationAuthCarrier) -> bool {
    let capability = match carrier {
        RegistrationAuthCarrier::Sasl => "sasl",
        RegistrationAuthCarrier::AccountCreate => "agenc.ag/account-create",
        RegistrationAuthCarrier::AccountCredentials => "agenc.ag/account-credentials",
    };
    request
        .split_ascii_whitespace()
        .any(|token| token.strip_prefix('-') == Some(capability))
}

fn copy_string(value: &str) -> Result<String, RegistrationError> {
    let mut owned = String::new();
    owned
        .try_reserve_exact(value.len())
        .map_err(|_| RegistrationError::AllocationFailed)?;
    owned.push_str(value);
    Ok(owned)
}

fn action_buffer(capacity: usize) -> Result<Vec<RegistrationAction>, RegistrationError> {
    let mut actions = Vec::new();
    actions
        .try_reserve_exact(capacity)
        .map_err(|_| RegistrationError::AllocationFailed)?;
    Ok(actions)
}

fn one_action(action: RegistrationAction) -> Result<Vec<RegistrationAction>, RegistrationError> {
    let mut actions = action_buffer(1)?;
    actions.push(action);
    Ok(actions)
}

fn welcome_steps(
    recovery: bool,
    authenticated: bool,
) -> Result<Vec<WelcomeStep>, RegistrationError> {
    let mut steps = Vec::new();
    steps
        .try_reserve_exact(7)
        .map_err(|_| RegistrationError::AllocationFailed)?;
    steps.push(WelcomeStep::WelcomeThroughMyInfo);
    steps.push(WelcomeStep::Isupport);
    steps.push(WelcomeStep::LuserCounters);
    steps.push(WelcomeStep::Motd);
    if recovery {
        steps.push(WelcomeStep::RecoveryEpoch);
    }
    if authenticated {
        steps.push(WelcomeStep::AccountState);
    }
    steps.push(WelcomeStep::RegistrationBatches);
    Ok(steps)
}

fn map_access_token_error(_error: TextCarrierError) -> RegistrationError {
    RegistrationError::InvalidAccessToken
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::io;

    use super::{
        AccessTokenPolicy, KEEPALIVE_IDLE_MILLIS, MAX_PENDING_MESSAGES, PendingInputQueue,
        RegistrationAction, RegistrationError, RegistrationPhase, RegistrationState,
    };
    use crate::{
        CapabilityProfile, FramedLine, ParsedMessage, RegistrationGrammarError, parse_message,
    };

    #[test]
    fn grammar_rejection_refreshes_complete_message_activity() -> Result<(), Box<dyn Error>> {
        let advertised = CapabilityProfile::new(Vec::new())?;
        let mut state = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;
        state.phase = RegistrationPhase::Registered;
        let received_at = 7;
        let malformed = parse_message(FramedLine::new("CAP")?)?
            .ok_or_else(|| io::Error::other("missing parsed message"))?;

        assert_eq!(
            state.message(malformed, received_at, &advertised).err(),
            Some(RegistrationError::Grammar(
                RegistrationGrammarError::NeedMoreParameters
            ))
        );
        assert!(
            state
                .tick(received_at + KEEPALIVE_IDLE_MILLIS - 1, None)?
                .is_empty()
        );
        assert!(matches!(
            state
                .tick(
                    received_at + KEEPALIVE_IDLE_MILLIS,
                    Some("ABCDEFGHIJKLMNOPQRSTUV")
                )?
                .as_slice(),
            [RegistrationAction::Ping(token)] if token == "ABCDEFGHIJKLMNOPQRSTUV"
        ));
        Ok(())
    }

    #[test]
    fn repeated_queue_handoffs_preserve_preallocated_admission_slots() -> Result<(), Box<dyn Error>>
    {
        let mut queue = PendingInputQueue::new()?;
        for _ in 0..3 {
            let reserved_capacity = queue.messages.capacity();
            for _ in 0..MAX_PENDING_MESSAGES {
                queue.admit(parsed_ping()?)?;
            }
            assert_eq!(queue.messages.capacity(), reserved_capacity);
            let resumed = queue.take_all()?;
            assert_eq!(resumed.message_count(), MAX_PENDING_MESSAGES);
            assert_eq!(queue.message_count(), 0);
            assert!(queue.messages.capacity() >= MAX_PENDING_MESSAGES);
        }
        Ok(())
    }

    fn parsed_ping() -> Result<ParsedMessage, Box<dyn Error>> {
        parse_message(FramedLine::new("PING token")?)?
            .ok_or_else(|| io::Error::other("missing parsed message").into())
    }
}

#[cfg(test)]
mod display_tests {
    use super::RegistrationError;

    #[test]
    fn every_discriminant_renders_a_distinct_message() {
        let variants = [
            RegistrationError::InvalidCommand,
            RegistrationError::InvalidNickname,
            RegistrationError::InvalidRegistrationField,
            RegistrationError::InvalidAccessToken,
            RegistrationError::Capability(super::CapError::InvalidState),
            RegistrationError::Grammar(super::RegistrationGrammarError::UnknownCommand),
            RegistrationError::AuthenticationInProgress,
            RegistrationError::AuthenticationUnavailable,
            RegistrationError::Overflow,
            RegistrationError::AllocationFailed,
            RegistrationError::PendingInputExceeded,
        ];
        let rendered: Vec<String> = variants.iter().map(ToString::to_string).collect();
        assert!(rendered.iter().all(|text| !text.is_empty()));
        let mut unique = rendered.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), rendered.len(), "{rendered:?}");
    }
}
