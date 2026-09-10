//! Fixed-shape SASL and account-service transport carriers.

use std::error::Error;
use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use zeroize::{Zeroize as _, Zeroizing};

use crate::SecretBytes;

/// Fixed account-service request envelope bytes.
pub const ACCOUNT_REQUEST_BYTES: usize = 4_726;
/// Fixed account-service response bytes.
pub const ACCOUNT_RESPONSE_BYTES: usize = 4_342;
/// IRCv3 SASL and account-service chunk characters.
pub const AUTH_CHUNK_CHARACTERS: usize = 400;
/// Canonical padded Base64 request characters.
pub const SASL_REQUEST_CHARACTERS: usize = 6_304;
/// Canonical padded Base64 response characters.
pub const SASL_RESPONSE_CHARACTERS: usize = 5_792;
/// Canonical unpadded Base64url request characters.
pub const ACCOUNT_REQUEST_CHARACTERS: usize = 6_302;
/// Canonical unpadded Base64url response characters.
pub const ACCOUNT_RESPONSE_CHARACTERS: usize = 5_790;
/// SASL authentication attempt deadline in monotonic milliseconds.
pub const SASL_TIMEOUT_MILLIS: u64 = 30_000;
/// Account carrier idle deadline in monotonic milliseconds.
pub const ACCOUNT_IDLE_TIMEOUT_MILLIS: u64 = 15_000;
/// Account carrier absolute deadline in monotonic milliseconds.
pub const ACCOUNT_TOTAL_TIMEOUT_MILLIS: u64 = 60_000;

/// Move-only authentication text that zeroizes its full allocation on drop.
///
/// Values are bounded to one carrier chunk and expose bytes explicitly so
/// response material cannot be cloned or converted into an ordinary string by
/// accident.
///
/// ```compile_fail
/// use agenc_ircd_client_wire::SecretText;
///
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<SecretText>();
/// ```
pub struct SecretText {
    storage: Zeroizing<Vec<u8>>,
    length: usize,
}

impl SecretText {
    fn copy_from(value: &str) -> Result<Self, AuthTransportError> {
        if value.is_empty()
            || value.len() > AUTH_CHUNK_CHARACTERS
            || !value.bytes().all(is_auth_response_character)
        {
            return Err(AuthTransportError::InvalidChunk);
        }
        let mut storage = Zeroizing::new(Vec::new());
        storage
            .try_reserve_exact(AUTH_CHUNK_CHARACTERS)
            .map_err(|_| AuthTransportError::AllocationFailed)?;
        let allocation = storage.capacity();
        storage.resize(allocation, 0);
        let destination = storage
            .get_mut(..value.len())
            .ok_or(AuthTransportError::AllocationFailed)?;
        destination.copy_from_slice(value.as_bytes());
        Ok(Self {
            storage,
            length: value.len(),
        })
    }

    /// Borrows the exact ASCII carrier bytes.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.storage.get(..self.length).unwrap_or_default()
    }

    /// Returns the exact number of carrier characters.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.length
    }

    /// Returns whether the carrier text has been cleared.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    fn zeroize_storage(&mut self) {
        self.storage.as_mut_slice().zeroize();
        self.length = 0;
    }
}

impl Drop for SecretText {
    fn drop(&mut self) {
        self.zeroize_storage();
    }
}

/// Fixed IRCv3 SASL numeric outcomes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum SaslNumeric {
    /// RPL_SASLSUCCESS.
    Success = 903,
    /// ERR_SASLFAIL.
    Failed = 904,
    /// ERR_SASLTOOLONG.
    TooLong = 905,
    /// ERR_SASLABORTED.
    Aborted = 906,
    /// ERR_SASLALREADY.
    AlreadyAuthenticated = 907,
    /// RPL_SASLMECHS.
    Mechanisms = 908,
}

/// External actions from the pure SASL carrier.
pub enum SaslAction {
    /// Send `AUTHENTICATE +` after mechanism selection.
    SendPlus,
    /// Forward one fixed request envelope to the account service.
    RequestEnvelope {
        /// `false` for AuthStart and `true` for AuthFinish.
        finish: bool,
        /// Zeroizing exact 4,726 decoded bytes.
        bytes: SecretBytes,
    },
    /// Send one 1..=400-character AUTHENTICATE payload.
    SendChunk(SecretText),
    /// Send one fixed terminal numeric.
    Numeric(SaslNumeric),
    /// Request logout of the current account binding.
    Logout,
}

impl fmt::Debug for SaslAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::SendPlus => "SendPlus",
            Self::RequestEnvelope { .. } => "RequestEnvelope",
            Self::SendChunk(_) => "SendChunk",
            Self::Numeric(_) => "Numeric",
            Self::Logout => "Logout",
        };
        formatter.debug_tuple("SaslAction").field(&name).finish()
    }
}

/// Closed auth-carrier failures. Errors never contain carrier contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthTransportError {
    /// A command arrived in the wrong carrier state.
    BadState,
    /// A mechanism name other than exact `AGENC-OPAQUE` was requested.
    UnsupportedMechanism,
    /// A chunk violated width, count, alphabet, padding, or canonical encoding.
    InvalidChunk,
    /// A decoded or supplied envelope had the wrong exact length.
    WrongLength,
    /// An account carrier line contained any client tag.
    TagsForbidden,
    /// The per-connection attempt/transfer limit was exhausted.
    LimitExceeded,
    /// An idle or total transfer deadline expired.
    TimedOut,
    /// A checked deadline or length calculation overflowed.
    Overflow,
    /// A bounded allocation failed.
    AllocationFailed,
}

impl fmt::Display for AuthTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::BadState => "authentication carrier is in the wrong state",
            Self::UnsupportedMechanism => "SASL mechanism is unsupported",
            Self::InvalidChunk => "authentication carrier chunk is invalid",
            Self::WrongLength => "authentication envelope has the wrong exact length",
            Self::TagsForbidden => "account carrier commands may not contain tags",
            Self::LimitExceeded => "authentication carrier connection limit is exhausted",
            Self::TimedOut => "authentication carrier deadline expired",
            Self::Overflow => "authentication carrier calculation overflowed",
            Self::AllocationFailed => "authentication carrier allocation failed",
        };
        formatter.write_str(message)
    }
}

impl Error for AuthTransportError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SaslPhase {
    Idle,
    ReceivingStart,
    WaitingStartResponse,
    ReceivingFinish,
    WaitingFinishResponse,
    AwaitingOutcome,
    Authenticated,
    WaitingLogout,
}

/// Fixed `AGENC-OPAQUE` SASL transport state, without OPAQUE or HPKE logic.
pub struct SaslTransport {
    phase: SaslPhase,
    authenticated: bool,
    attempts: u8,
    deadline: Option<u64>,
    encoded: String,
}

impl SaslTransport {
    /// Creates an idle per-connection carrier with storage for one request.
    pub fn new() -> Result<Self, AuthTransportError> {
        let mut encoded = String::new();
        encoded
            .try_reserve_exact(SASL_REQUEST_CHARACTERS)
            .map_err(|_| AuthTransportError::AllocationFailed)?;
        Ok(Self {
            phase: SaslPhase::Idle,
            authenticated: false,
            attempts: 0,
            deadline: None,
            encoded,
        })
    }

    /// Accepts one AUTHENTICATE parameter at a monotonic millisecond tick.
    pub fn client(
        &mut self,
        parameter: &str,
        now: u64,
    ) -> Result<Vec<SaslAction>, AuthTransportError> {
        self.check_deadline(now)?;
        if parameter.len() > AUTH_CHUNK_CHARACTERS && self.phase != SaslPhase::Authenticated {
            let actions = one_action(SaslAction::Numeric(SaslNumeric::TooLong))?;
            self.reset_attempt();
            return Ok(actions);
        }
        if parameter == "*" {
            return self.abort_or_logout();
        }
        match self.phase {
            SaslPhase::Idle => self.select_mechanism(parameter, now),
            SaslPhase::ReceivingStart | SaslPhase::ReceivingFinish => self.receive_chunk(parameter),
            SaslPhase::Authenticated if parameter == "AGENC-OPAQUE" => {
                self.select_mechanism(parameter, now)
            }
            SaslPhase::Authenticated => {
                one_action(SaslAction::Numeric(SaslNumeric::AlreadyAuthenticated))
            }
            SaslPhase::WaitingStartResponse
            | SaslPhase::WaitingFinishResponse
            | SaslPhase::AwaitingOutcome
            | SaslPhase::WaitingLogout => Err(AuthTransportError::BadState),
        }
    }

    /// Supplies a fixed account-service response and returns exact chunks.
    pub fn server_response(
        &mut self,
        bytes: &[u8],
        now: u64,
    ) -> Result<Vec<SaslAction>, AuthTransportError> {
        self.check_deadline(now)?;
        let next = match self.phase {
            SaslPhase::WaitingStartResponse => SaslPhase::ReceivingFinish,
            SaslPhase::WaitingFinishResponse => SaslPhase::AwaitingOutcome,
            _ => return Err(AuthTransportError::BadState),
        };
        if bytes.len() != ACCOUNT_RESPONSE_BYTES {
            return self.fail(AuthTransportError::WrongLength);
        }
        let mut encoded = Zeroizing::new([0_u8; SASL_RESPONSE_CHARACTERS]);
        let written = STANDARD
            .encode_slice(bytes, encoded.as_mut_slice())
            .map_err(|_| AuthTransportError::WrongLength)?;
        if written != SASL_RESPONSE_CHARACTERS {
            return self.fail(AuthTransportError::WrongLength);
        }
        let text = std::str::from_utf8(encoded.as_slice())
            .map_err(|_| AuthTransportError::InvalidChunk)?;
        let actions = match chunk_actions(text, SaslAction::SendChunk) {
            Ok(actions) => actions,
            Err(error) => return self.fail(error),
        };
        self.phase = next;
        Ok(actions)
    }

    /// Emits the terminal 903/904 only after the completion response chunks.
    pub fn complete(
        &mut self,
        accepted: bool,
        now: u64,
    ) -> Result<Vec<SaslAction>, AuthTransportError> {
        self.check_deadline(now)?;
        if self.phase != SaslPhase::AwaitingOutcome {
            return Err(AuthTransportError::BadState);
        }
        let mut actions = action_buffer(1)?;
        self.deadline = None;
        if accepted {
            self.authenticated = true;
            self.phase = SaslPhase::Authenticated;
            actions.push(SaslAction::Numeric(SaslNumeric::Success));
        } else {
            self.reset_attempt();
            actions.push(SaslAction::Numeric(SaslNumeric::Failed));
        }
        Ok(actions)
    }

    /// Ends an in-flight exchange whose account-service request could not
    /// produce an authenticated response. This preserves the connection-wide
    /// attempt count while returning the carrier to its idle state.
    pub fn unavailable(&mut self, now: u64) -> Result<Vec<SaslAction>, AuthTransportError> {
        if matches!(self.check_deadline(now), Err(AuthTransportError::TimedOut)) {
            return one_action(SaslAction::Numeric(SaslNumeric::Failed));
        }
        if !matches!(
            self.phase,
            SaslPhase::WaitingStartResponse
                | SaslPhase::WaitingFinishResponse
                | SaslPhase::AwaitingOutcome
        ) {
            return Err(AuthTransportError::BadState);
        }
        self.reset_attempt();
        one_action(SaslAction::Numeric(SaslNumeric::Failed))
    }

    /// Restores the authenticated idle state when the domain refuses logout.
    pub fn reject_logout(&mut self) -> Result<Vec<SaslAction>, AuthTransportError> {
        if self.phase != SaslPhase::WaitingLogout || !self.authenticated {
            return Err(AuthTransportError::BadState);
        }
        self.phase = SaslPhase::Authenticated;
        one_action(SaslAction::Numeric(SaslNumeric::Failed))
    }

    /// Clears the carrier's account binding only after logout commits.
    pub fn complete_logout(&mut self) -> Result<(), AuthTransportError> {
        if self.phase != SaslPhase::WaitingLogout || !self.authenticated {
            return Err(AuthTransportError::BadState);
        }
        self.authenticated = false;
        self.phase = SaslPhase::Idle;
        Ok(())
    }

    /// Applies the nonextendable 30-second attempt deadline.
    pub fn tick(&mut self, now: u64) -> Result<Vec<SaslAction>, AuthTransportError> {
        match self.check_deadline(now) {
            Ok(()) => Ok(Vec::new()),
            Err(AuthTransportError::TimedOut) => {
                one_action(SaslAction::Numeric(SaslNumeric::Failed))
            }
            Err(error) => Err(error),
        }
    }

    fn select_mechanism(
        &mut self,
        mechanism: &str,
        now: u64,
    ) -> Result<Vec<SaslAction>, AuthTransportError> {
        if mechanism != "AGENC-OPAQUE" {
            return one_action(SaslAction::Numeric(SaslNumeric::Mechanisms));
        }
        if self.attempts >= 2 {
            return Err(AuthTransportError::LimitExceeded);
        }
        let deadline = now
            .checked_add(SASL_TIMEOUT_MILLIS)
            .ok_or(AuthTransportError::Overflow)?;
        let mut actions = action_buffer(1)?;
        let attempts = self
            .attempts
            .checked_add(1)
            .ok_or(AuthTransportError::Overflow)?;
        self.attempts = attempts;
        self.deadline = Some(deadline);
        self.phase = SaslPhase::ReceivingStart;
        actions.push(SaslAction::SendPlus);
        Ok(actions)
    }

    fn receive_chunk(&mut self, chunk: &str) -> Result<Vec<SaslAction>, AuthTransportError> {
        if chunk == "+" {
            return self.fail(AuthTransportError::WrongLength);
        }
        if chunk.is_empty() || chunk.len() > AUTH_CHUNK_CHARACTERS {
            return self.fail(if chunk.len() > AUTH_CHUNK_CHARACTERS {
                AuthTransportError::InvalidChunk
            } else {
                AuthTransportError::WrongLength
            });
        }
        let next_length = self
            .encoded
            .len()
            .checked_add(chunk.len())
            .ok_or(AuthTransportError::Overflow)?;
        if next_length > SASL_REQUEST_CHARACTERS {
            return self.fail(AuthTransportError::InvalidChunk);
        }
        if next_length < SASL_REQUEST_CHARACTERS && chunk.len() != AUTH_CHUNK_CHARACTERS {
            return self.fail(AuthTransportError::InvalidChunk);
        }
        if next_length != SASL_REQUEST_CHARACTERS {
            self.encoded.push_str(chunk);
            return Ok(Vec::new());
        }
        let actions = action_buffer(1)?;
        self.encoded.push_str(chunk);
        self.finish_request(actions)
    }

    fn finish_request(
        &mut self,
        mut actions: Vec<SaslAction>,
    ) -> Result<Vec<SaslAction>, AuthTransportError> {
        let mut decoded = Zeroizing::new([0_u8; ACCOUNT_REQUEST_BYTES]);
        let Ok(decoded_bytes) =
            STANDARD.decode_slice(self.encoded.as_bytes(), decoded.as_mut_slice())
        else {
            return self.fail(AuthTransportError::InvalidChunk);
        };
        if decoded_bytes != ACCOUNT_REQUEST_BYTES {
            return self.fail(AuthTransportError::InvalidChunk);
        }
        let mut canonical = Zeroizing::new([0_u8; SASL_REQUEST_CHARACTERS]);
        let Ok(encoded_bytes) = STANDARD.encode_slice(decoded.as_slice(), canonical.as_mut_slice())
        else {
            return self.fail(AuthTransportError::InvalidChunk);
        };
        if encoded_bytes != SASL_REQUEST_CHARACTERS
            || canonical.as_slice() != self.encoded.as_bytes()
        {
            return self.fail(AuthTransportError::InvalidChunk);
        }
        let Ok(bytes) = SecretBytes::new(decoded.as_slice()) else {
            return self.fail(AuthTransportError::AllocationFailed);
        };
        let finish = self.phase == SaslPhase::ReceivingFinish;
        self.phase = if finish {
            SaslPhase::WaitingFinishResponse
        } else {
            SaslPhase::WaitingStartResponse
        };
        self.clear_encoded();
        actions.push(SaslAction::RequestEnvelope { finish, bytes });
        Ok(actions)
    }

    fn abort_or_logout(&mut self) -> Result<Vec<SaslAction>, AuthTransportError> {
        if self.phase == SaslPhase::Authenticated {
            let mut actions = action_buffer(1)?;
            self.phase = SaslPhase::WaitingLogout;
            self.deadline = None;
            actions.push(SaslAction::Logout);
            return Ok(actions);
        }
        if self.phase == SaslPhase::Idle {
            return Err(AuthTransportError::BadState);
        }
        let mut actions = action_buffer(1)?;
        self.reset_attempt();
        actions.push(SaslAction::Numeric(SaslNumeric::Aborted));
        Ok(actions)
    }

    fn fail<T>(&mut self, error: AuthTransportError) -> Result<T, AuthTransportError> {
        self.reset_attempt();
        Err(error)
    }

    fn reset_attempt(&mut self) {
        self.clear_encoded();
        self.phase = if self.authenticated {
            SaslPhase::Authenticated
        } else {
            SaslPhase::Idle
        };
        self.deadline = None;
    }

    fn check_deadline(&mut self, now: u64) -> Result<(), AuthTransportError> {
        if self.deadline.is_some_and(|deadline| now >= deadline)
            && !matches!(self.phase, SaslPhase::Idle | SaslPhase::Authenticated)
        {
            self.reset_attempt();
            return Err(AuthTransportError::TimedOut);
        }
        Ok(())
    }

    fn clear_encoded(&mut self) {
        self.encoded.zeroize();
        self.encoded.clear();
    }
}

impl Drop for SaslTransport {
    fn drop(&mut self) {
        self.clear_encoded();
    }
}

/// Account-service IRC command family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountCarrierKind {
    /// Pre-registration account creation.
    Create,
    /// Registered-account credential replacement.
    Credentials,
}

impl AccountCarrierKind {
    /// Returns the exact IRC command.
    #[must_use]
    pub const fn command(self) -> &'static str {
        match self {
            Self::Create => "ACCTCREATE",
            Self::Credentials => "ACCTCRED",
        }
    }
}

/// Start or finish half of an account-service exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountCarrierPhase {
    /// Initial request/challenge half.
    Start,
    /// Finish/completion half.
    Finish,
}

/// External actions from an account-service text carrier.
pub enum AccountCarrierAction {
    /// Send `READY <START|FINISH> 4726`.
    Ready(AccountCarrierPhase),
    /// Forward one exact request envelope.
    RequestEnvelope {
        /// Which exchange half supplied the bytes.
        phase: AccountCarrierPhase,
        /// Zeroizing exact 4,726 decoded bytes.
        bytes: SecretBytes,
    },
    /// Send `CHALLENGE 4342` or `COMPLETE 4342`.
    ResponseStart(AccountCarrierPhase),
    /// Send one canonical unpadded Base64url DATA chunk.
    Data(SecretText),
    /// Send END after the final response chunk.
    End,
}

impl fmt::Debug for AccountCarrierAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Ready(_) => "Ready",
            Self::RequestEnvelope { .. } => "RequestEnvelope",
            Self::ResponseStart(_) => "ResponseStart",
            Self::Data(_) => "Data",
            Self::End => "End",
        };
        formatter
            .debug_tuple("AccountCarrierAction")
            .field(&name)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AccountState {
    Idle,
    Receiving(AccountCarrierPhase),
    WaitingResponse(AccountCarrierPhase),
    AwaitingFinish,
    Complete,
    Failed,
}

/// One-transfer-per-connection ACCTCREATE or ACCTCRED carrier.
pub struct AccountTransfer {
    kind: AccountCarrierKind,
    state: AccountState,
    encoded: String,
    chunks: usize,
    total_deadline: Option<u64>,
    idle_deadline: Option<u64>,
}

impl AccountTransfer {
    /// Creates an unused carrier for one exact command family.
    pub fn new(kind: AccountCarrierKind) -> Result<Self, AuthTransportError> {
        let mut encoded = String::new();
        encoded
            .try_reserve_exact(ACCOUNT_REQUEST_CHARACTERS)
            .map_err(|_| AuthTransportError::AllocationFailed)?;
        Ok(Self {
            kind,
            state: AccountState::Idle,
            encoded,
            chunks: 0,
            total_deadline: None,
            idle_deadline: None,
        })
    }

    /// Returns the exact command owned by this carrier.
    #[must_use]
    pub const fn command(&self) -> &'static str {
        self.kind.command()
    }

    /// Accepts one exact subcommand/parameter pair.
    pub fn client(
        &mut self,
        subcommand: &str,
        parameter: Option<&str>,
        has_tags: bool,
        now: u64,
    ) -> Result<Vec<AccountCarrierAction>, AuthTransportError> {
        self.check_deadlines(now)?;
        if has_tags {
            return self.fail(AuthTransportError::TagsForbidden);
        }
        let actions = match subcommand {
            "START" => self.begin(AccountCarrierPhase::Start, parameter, now),
            "FINISH" => self.begin(AccountCarrierPhase::Finish, parameter, now),
            "DATA" => self.data(parameter, now),
            "END" if parameter.is_none() => self.end(now),
            _ => self.fail(AuthTransportError::BadState),
        }?;
        Ok(actions)
    }

    /// Supplies a fixed response after an externally processed request.
    pub fn server_response(
        &mut self,
        phase: AccountCarrierPhase,
        bytes: &[u8],
        now: u64,
    ) -> Result<Vec<AccountCarrierAction>, AuthTransportError> {
        self.check_deadlines(now)?;
        if self.state != AccountState::WaitingResponse(phase) {
            return self.fail(AuthTransportError::BadState);
        }
        if bytes.len() != ACCOUNT_RESPONSE_BYTES {
            return self.fail(AuthTransportError::WrongLength);
        }
        let next_idle = match phase {
            AccountCarrierPhase::Start => {
                let Some(deadline) = now.checked_add(ACCOUNT_IDLE_TIMEOUT_MILLIS) else {
                    return self.fail(AuthTransportError::Overflow);
                };
                Some(deadline)
            }
            AccountCarrierPhase::Finish => None,
        };
        let mut encoded = Zeroizing::new([0_u8; ACCOUNT_RESPONSE_CHARACTERS]);
        let written = URL_SAFE_NO_PAD
            .encode_slice(bytes, encoded.as_mut_slice())
            .map_err(|_| AuthTransportError::WrongLength)?;
        if written != ACCOUNT_RESPONSE_CHARACTERS {
            return self.fail(AuthTransportError::WrongLength);
        }
        let text = std::str::from_utf8(encoded.as_slice())
            .map_err(|_| AuthTransportError::InvalidChunk)?;
        let chunks = match chunk_actions(text, AccountCarrierAction::Data) {
            Ok(chunks) => chunks,
            Err(error) => return self.fail(error),
        };
        let action_count = chunks
            .len()
            .checked_add(2)
            .ok_or(AuthTransportError::Overflow)?;
        let mut actions = action_buffer(action_count)?;
        actions.push(AccountCarrierAction::ResponseStart(phase));
        actions.extend(chunks);
        actions.push(AccountCarrierAction::End);
        self.state = match phase {
            AccountCarrierPhase::Start => AccountState::AwaitingFinish,
            AccountCarrierPhase::Finish => AccountState::Complete,
        };
        self.idle_deadline = next_idle;
        Ok(actions)
    }

    /// Applies the 15-second idle and 60-second absolute deadlines.
    pub fn tick(&mut self, now: u64) -> Result<(), AuthTransportError> {
        self.check_deadlines(now)
    }

    /// Irreversibly fails this one-use transfer after an external refusal.
    pub fn reject(&mut self) {
        self.clear_encoded();
        self.state = AccountState::Failed;
        self.total_deadline = None;
        self.idle_deadline = None;
    }

    fn begin(
        &mut self,
        phase: AccountCarrierPhase,
        declared: Option<&str>,
        now: u64,
    ) -> Result<Vec<AccountCarrierAction>, AuthTransportError> {
        let allowed = matches!(
            (self.state, phase),
            (AccountState::Idle, AccountCarrierPhase::Start)
                | (AccountState::AwaitingFinish, AccountCarrierPhase::Finish)
        );
        if !allowed || declared != Some("4726") {
            return self.fail(AuthTransportError::BadState);
        }
        let Some(idle_deadline) = now.checked_add(ACCOUNT_IDLE_TIMEOUT_MILLIS) else {
            return self.fail(AuthTransportError::Overflow);
        };
        let total_deadline = if phase == AccountCarrierPhase::Start {
            let Some(deadline) = now.checked_add(ACCOUNT_TOTAL_TIMEOUT_MILLIS) else {
                return self.fail(AuthTransportError::Overflow);
            };
            Some(deadline)
        } else {
            self.total_deadline
        };
        let mut actions = action_buffer(1)?;
        if phase == AccountCarrierPhase::Start {
            self.total_deadline = total_deadline;
        }
        self.idle_deadline = Some(idle_deadline);
        self.state = AccountState::Receiving(phase);
        self.chunks = 0;
        self.clear_encoded();
        actions.push(AccountCarrierAction::Ready(phase));
        Ok(actions)
    }

    fn data(
        &mut self,
        chunk: Option<&str>,
        now: u64,
    ) -> Result<Vec<AccountCarrierAction>, AuthTransportError> {
        let AccountState::Receiving(_) = self.state else {
            return self.fail(AuthTransportError::BadState);
        };
        let Some(chunk) = chunk else {
            return self.fail(AuthTransportError::InvalidChunk);
        };
        let Some(idle_deadline) = now.checked_add(ACCOUNT_IDLE_TIMEOUT_MILLIS) else {
            return self.fail(AuthTransportError::Overflow);
        };
        let expected = if self.chunks < 15 { 400 } else { 302 };
        if self.chunks >= 16 || chunk.len() != expected || !chunk.bytes().all(is_base64url) {
            return self.fail(AuthTransportError::InvalidChunk);
        }
        let Some(chunks) = self.chunks.checked_add(1) else {
            return self.fail(AuthTransportError::Overflow);
        };
        self.encoded.push_str(chunk);
        self.chunks = chunks;
        self.idle_deadline = Some(idle_deadline);
        Ok(Vec::new())
    }

    fn end(&mut self, now: u64) -> Result<Vec<AccountCarrierAction>, AuthTransportError> {
        let AccountState::Receiving(phase) = self.state else {
            return self.fail(AuthTransportError::BadState);
        };
        if self.chunks != 16 || self.encoded.len() != ACCOUNT_REQUEST_CHARACTERS {
            return self.fail(AuthTransportError::WrongLength);
        }
        let Some(idle_deadline) = now.checked_add(ACCOUNT_IDLE_TIMEOUT_MILLIS) else {
            return self.fail(AuthTransportError::Overflow);
        };
        let mut decoded = Zeroizing::new([0_u8; ACCOUNT_REQUEST_BYTES]);
        let Ok(decoded_bytes) =
            URL_SAFE_NO_PAD.decode_slice(self.encoded.as_bytes(), decoded.as_mut_slice())
        else {
            return self.fail(AuthTransportError::InvalidChunk);
        };
        if decoded_bytes != ACCOUNT_REQUEST_BYTES {
            return self.fail(AuthTransportError::InvalidChunk);
        }
        let mut canonical = Zeroizing::new([0_u8; ACCOUNT_REQUEST_CHARACTERS]);
        let Ok(encoded_bytes) =
            URL_SAFE_NO_PAD.encode_slice(decoded.as_slice(), canonical.as_mut_slice())
        else {
            return self.fail(AuthTransportError::InvalidChunk);
        };
        if encoded_bytes != ACCOUNT_REQUEST_CHARACTERS
            || canonical.as_slice() != self.encoded.as_bytes()
        {
            return self.fail(AuthTransportError::InvalidChunk);
        }
        let Ok(bytes) = SecretBytes::new(decoded.as_slice()) else {
            return self.fail(AuthTransportError::AllocationFailed);
        };
        let mut actions = action_buffer(1)?;
        self.state = AccountState::WaitingResponse(phase);
        self.idle_deadline = Some(idle_deadline);
        self.clear_encoded();
        actions.push(AccountCarrierAction::RequestEnvelope { phase, bytes });
        Ok(actions)
    }

    fn check_deadlines(&mut self, now: u64) -> Result<(), AuthTransportError> {
        let total_expired = self.total_deadline.is_some_and(|deadline| now >= deadline);
        let idle_expired = self.idle_deadline.is_some_and(|deadline| now >= deadline);
        if !matches!(
            self.state,
            AccountState::Idle | AccountState::Complete | AccountState::Failed
        ) && (total_expired || idle_expired)
        {
            return self.fail(AuthTransportError::TimedOut);
        }
        Ok(())
    }

    fn fail<T>(&mut self, error: AuthTransportError) -> Result<T, AuthTransportError> {
        self.clear_encoded();
        self.state = AccountState::Failed;
        self.total_deadline = None;
        self.idle_deadline = None;
        Err(error)
    }

    fn clear_encoded(&mut self) {
        self.encoded.zeroize();
        self.encoded.clear();
        self.chunks = 0;
    }
}

impl Drop for AccountTransfer {
    fn drop(&mut self) {
        self.clear_encoded();
    }
}

fn action_buffer<T>(capacity: usize) -> Result<Vec<T>, AuthTransportError> {
    let mut actions = Vec::new();
    actions
        .try_reserve_exact(capacity)
        .map_err(|_| AuthTransportError::AllocationFailed)?;
    Ok(actions)
}

fn one_action<T>(action: T) -> Result<Vec<T>, AuthTransportError> {
    let mut actions = action_buffer(1)?;
    actions.push(action);
    Ok(actions)
}

fn chunk_actions<T>(
    encoded: &str,
    mut action: impl FnMut(SecretText) -> T,
) -> Result<Vec<T>, AuthTransportError> {
    let count = encoded
        .len()
        .checked_add(AUTH_CHUNK_CHARACTERS - 1)
        .and_then(|value| value.checked_div(AUTH_CHUNK_CHARACTERS))
        .ok_or(AuthTransportError::Overflow)?;
    let mut actions = action_buffer(count)?;
    for chunk in encoded.as_bytes().chunks(AUTH_CHUNK_CHARACTERS) {
        let text = std::str::from_utf8(chunk).map_err(|_| AuthTransportError::InvalidChunk)?;
        actions.push(action(SecretText::copy_from(text)?));
    }
    Ok(actions)
}

const fn is_auth_response_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_')
}

const fn is_base64url(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
}

/// Encodes one carrier payload the way the SASL carrier does: standard
/// Base64 with padding.
#[must_use]
pub fn encode_sasl_payload(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Decodes the concatenated SASL carrier chunks back to bytes.
#[must_use]
pub fn decode_sasl_payload(text: &str) -> Option<Vec<u8>> {
    STANDARD.decode(text).ok()
}

/// Encodes one carrier payload the way the account carriers do: unpadded
/// Base64url.
#[must_use]
pub fn encode_account_payload(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes the concatenated account carrier chunks back to bytes.
#[must_use]
pub fn decode_account_payload(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text).ok()
}

#[cfg(test)]
mod tests {
    use super::{
        ACCOUNT_RESPONSE_BYTES, AUTH_CHUNK_CHARACTERS, AccountCarrierPhase, AccountState,
        AccountTransfer, AuthTransportError, SaslAction, SaslPhase, SaslTransport, SecretText,
        chunk_actions,
    };

    #[test]
    fn secret_text_zeroizes_its_full_allocation() -> Result<(), AuthTransportError> {
        const CANARY: &str = "AUDIT_SECRET_CANARY";
        let mut text = SecretText::copy_from(CANARY)?;
        let allocation = text.storage.capacity();

        assert!(allocation >= AUTH_CHUNK_CHARACTERS);
        assert_eq!(text.storage.len(), allocation);
        assert_eq!(text.expose(), CANARY.as_bytes());

        text.zeroize_storage();

        assert!(text.is_empty());
        assert_eq!(text.storage.len(), allocation);
        assert!(text.storage.iter().all(|byte| *byte == 0));
        Ok(())
    }

    #[test]
    fn partial_chunk_construction_returns_a_clean_error() {
        let mut encoded = "A".repeat(AUTH_CHUNK_CHARACTERS);
        encoded.push('!');

        assert_eq!(
            chunk_actions(&encoded, SaslAction::SendChunk).err(),
            Some(AuthTransportError::InvalidChunk)
        );
    }

    #[test]
    fn secret_text_rejects_empty_and_oversized_chunks() {
        assert_eq!(
            SecretText::copy_from("").err(),
            Some(AuthTransportError::InvalidChunk)
        );
        assert_eq!(
            SecretText::copy_from(&"A".repeat(AUTH_CHUNK_CHARACTERS + 1)).err(),
            Some(AuthTransportError::InvalidChunk)
        );
    }

    #[test]
    fn sasl_server_response_rejects_the_wrong_exact_length() -> Result<(), AuthTransportError> {
        let mut transport = SaslTransport::new()?;
        transport.phase = SaslPhase::WaitingStartResponse;

        assert_eq!(
            transport.server_response(&[], 0).err(),
            Some(AuthTransportError::WrongLength)
        );
        assert_eq!(transport.phase, SaslPhase::Idle);
        Ok(())
    }

    #[test]
    fn sasl_unavailable_preserves_attempt_budget_and_resets_the_exchange()
    -> Result<(), AuthTransportError> {
        let mut transport = SaslTransport::new()?;
        let _selected = transport.client("AGENC-OPAQUE", 10)?;
        transport.phase = SaslPhase::WaitingStartResponse;

        assert!(matches!(
            transport.unavailable(11)?.as_slice(),
            [SaslAction::Numeric(super::SaslNumeric::Failed)]
        ));
        assert_eq!(transport.phase, SaslPhase::Idle);
        assert_eq!(transport.attempts, 1);

        let _selected_again = transport.client("AGENC-OPAQUE", 12)?;
        assert_eq!(transport.attempts, 2);
        Ok(())
    }

    #[test]
    fn failed_reauthentication_preserves_the_existing_account_binding()
    -> Result<(), AuthTransportError> {
        let mut transport = SaslTransport::new()?;
        transport.authenticated = true;
        transport.phase = SaslPhase::AwaitingOutcome;

        assert!(matches!(
            transport.complete(false, 10)?.as_slice(),
            [SaslAction::Numeric(super::SaslNumeric::Failed)]
        ));
        assert_eq!(transport.phase, SaslPhase::Authenticated);
        assert!(matches!(
            transport.client("AGENC-OPAQUE", 11)?.as_slice(),
            [SaslAction::SendPlus]
        ));
        assert!(matches!(
            transport.client("*", 12)?.as_slice(),
            [SaslAction::Numeric(super::SaslNumeric::Aborted)]
        ));
        assert_eq!(transport.phase, SaslPhase::Authenticated);
        assert!(matches!(
            transport.client("*", 13)?.as_slice(),
            [SaslAction::Logout]
        ));
        Ok(())
    }

    #[test]
    fn refused_logout_restores_the_authenticated_carrier() -> Result<(), AuthTransportError> {
        let mut transport = SaslTransport::new()?;
        transport.authenticated = true;
        transport.phase = SaslPhase::Authenticated;
        assert!(matches!(
            transport.client("*", 10)?.as_slice(),
            [SaslAction::Logout]
        ));

        assert!(matches!(
            transport.reject_logout()?.as_slice(),
            [SaslAction::Numeric(super::SaslNumeric::Failed)]
        ));
        assert_eq!(transport.phase, SaslPhase::Authenticated);
        assert!(matches!(
            transport.client("*", 11)?.as_slice(),
            [SaslAction::Logout]
        ));
        transport.complete_logout()?;
        assert_eq!(transport.phase, SaslPhase::Idle);
        Ok(())
    }

    #[test]
    fn oversized_authenticate_does_not_clear_an_authenticated_session()
    -> Result<(), AuthTransportError> {
        let mut transport = SaslTransport::new()?;
        transport.phase = SaslPhase::Authenticated;

        let actions = transport.client(&"A".repeat(AUTH_CHUNK_CHARACTERS + 1), 0)?;

        assert!(matches!(
            actions.as_slice(),
            [SaslAction::Numeric(
                super::SaslNumeric::AlreadyAuthenticated
            )]
        ));
        assert_eq!(transport.phase, SaslPhase::Authenticated);
        Ok(())
    }

    #[test]
    fn account_server_response_rejects_length_and_deadline_overflow()
    -> Result<(), AuthTransportError> {
        let mut wrong_length = AccountTransfer::new(super::AccountCarrierKind::Create)?;
        wrong_length.state = AccountState::WaitingResponse(AccountCarrierPhase::Start);
        assert_eq!(
            wrong_length
                .server_response(AccountCarrierPhase::Start, &[], 0)
                .err(),
            Some(AuthTransportError::WrongLength)
        );

        let mut overflow = AccountTransfer::new(super::AccountCarrierKind::Create)?;
        overflow.state = AccountState::WaitingResponse(AccountCarrierPhase::Start);
        assert_eq!(
            overflow
                .server_response(
                    AccountCarrierPhase::Start,
                    &[0; ACCOUNT_RESPONSE_BYTES],
                    u64::MAX,
                )
                .err(),
            Some(AuthTransportError::Overflow)
        );

        let mut finish = AccountTransfer::new(super::AccountCarrierKind::Create)?;
        finish.state = AccountState::WaitingResponse(AccountCarrierPhase::Finish);
        let actions = finish.server_response(
            AccountCarrierPhase::Finish,
            &[0; ACCOUNT_RESPONSE_BYTES],
            u64::MAX,
        )?;
        assert!(matches!(
            actions.last(),
            Some(super::AccountCarrierAction::End)
        ));
        assert_eq!(finish.state, AccountState::Complete);
        assert_eq!(finish.idle_deadline, None);
        Ok(())
    }

    #[test]
    fn rejected_account_transfer_erases_state_and_cannot_restart() -> Result<(), AuthTransportError>
    {
        let mut transfer = AccountTransfer::new(super::AccountCarrierKind::Create)?;
        transfer.state = AccountState::WaitingResponse(AccountCarrierPhase::Start);
        transfer.encoded.push_str("secret-carrier-text");
        transfer.total_deadline = Some(60_000);
        transfer.idle_deadline = Some(15_000);

        transfer.reject();

        assert_eq!(transfer.state, AccountState::Failed);
        assert!(transfer.encoded.is_empty());
        assert_eq!(transfer.total_deadline, None);
        assert_eq!(transfer.idle_deadline, None);
        assert_eq!(
            transfer.client("START", Some("4726"), false, 1).err(),
            Some(AuthTransportError::BadState)
        );
        Ok(())
    }

    #[test]
    fn account_data_rejects_missing_and_misshapen_chunks() -> Result<(), AuthTransportError> {
        let mut missing = AccountTransfer::new(super::AccountCarrierKind::Create)?;
        missing.state = AccountState::Receiving(AccountCarrierPhase::Start);
        assert_eq!(
            missing.data(None, 0).err(),
            Some(AuthTransportError::InvalidChunk)
        );

        let mut short = AccountTransfer::new(super::AccountCarrierKind::Create)?;
        short.state = AccountState::Receiving(AccountCarrierPhase::Start);
        assert_eq!(
            short.data(Some("A"), 0).err(),
            Some(AuthTransportError::InvalidChunk)
        );

        let mut too_many = AccountTransfer::new(super::AccountCarrierKind::Create)?;
        too_many.state = AccountState::Receiving(AccountCarrierPhase::Start);
        too_many.chunks = 16;
        assert_eq!(
            too_many.data(Some(&"A".repeat(302)), 0).err(),
            Some(AuthTransportError::InvalidChunk)
        );

        let mut overflow = AccountTransfer::new(super::AccountCarrierKind::Create)?;
        overflow.state = AccountState::Receiving(AccountCarrierPhase::Start);
        assert_eq!(
            overflow
                .data(Some(&"A".repeat(AUTH_CHUNK_CHARACTERS)), u64::MAX)
                .err(),
            Some(AuthTransportError::Overflow)
        );
        Ok(())
    }
}

#[cfg(test)]
mod display_tests {
    use super::AuthTransportError;

    #[test]
    fn every_discriminant_renders_a_distinct_message() {
        let variants = [
            AuthTransportError::BadState,
            AuthTransportError::UnsupportedMechanism,
            AuthTransportError::InvalidChunk,
            AuthTransportError::WrongLength,
            AuthTransportError::TagsForbidden,
            AuthTransportError::LimitExceeded,
            AuthTransportError::TimedOut,
            AuthTransportError::Overflow,
            AuthTransportError::AllocationFailed,
        ];
        let rendered: Vec<String> = variants.iter().map(ToString::to_string).collect();
        assert!(rendered.iter().all(|text| !text.is_empty()));
        let mut unique = rendered.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), rendered.len(), "{rendered:?}");
    }
}
