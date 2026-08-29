//! The administrative session state machine (spec 4372-4432, 4575-4581).

use agenc_ircd_crypto::{Ed25519PublicKey, Ed25519Signature};
use agenc_ircd_types::{AdminPermissionSet, MonotonicTick, NetworkId, OperatorId, Revision};

use crate::challenge::parse_signature_token;
use crate::tag::parse_admin_line;
use crate::{
    AdminChallenge, AdminCloseReason, AdminCommand, AdminCommandTbs, AdminError, CanonicalCommand,
    ConfirmationCheck, ConfirmationToken, MAX_ADMIN_COMMAND_BYTES, MAX_PRE_AUTH_PINGS,
    OperatorRegistry, PeerIdentity, PendingConfirmation, PingToken,
};
use agenc_ircd_types::ServerId;

/// The two identities every proof and command is bound to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdminSessionBinding {
    /// Network identity.
    pub network_id: NetworkId,
    /// Server identity.
    pub server_id: ServerId,
}

/// The visible phase of a session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminSessionState {
    /// The challenge was sent; only PING, PONG, QUIT, and one OPER are allowed.
    AwaitingOper,
    /// The operator proved possession; every line carries the signed tag.
    Authenticated,
    /// The session is closed and accepts nothing further.
    Closed(AdminCloseReason),
}

/// How a command relates to the two-step confirmation rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfirmationState {
    /// The command is not subject to confirmation.
    NotRequired,
    /// The first step: the runtime must issue a token and change no state.
    Required,
    /// The repeat bound to the pending token; carries its target revision.
    Satisfied {
        /// The revision the runtime must still observe before acting.
        target_revision: Revision,
    },
}

/// One accepted line, ready for the runtime admin owner.
pub enum AdminEvent {
    /// A pre-authentication PING to answer with PONG.
    PreAuthPing(PingToken),
    /// A pre-authentication PONG.
    PreAuthPong(PingToken),
    /// The client closed the session; the session is now closed.
    Quit,
    /// The operator proof verified.
    Authenticated {
        /// The selected operator.
        operator_id: OperatorId,
        /// Its granted permissions.
        permissions: AdminPermissionSet,
    },
    /// A signed, counter-checked, permission-checked command.
    Command(Box<AdminCommandEvent>),
    /// A signed command the operator lacks permission for.
    PermissionDenied {
        /// The command verb for the FAIL reply.
        verb: &'static str,
        /// The command counter the tag carried.
        counter: u64,
    },
}

/// The payload of an accepted signed command.
pub struct AdminCommandEvent {
    /// The parsed command.
    pub command: AdminCommand,
    /// The command counter the tag carried.
    pub counter: u64,
    /// The exact signed structure, for the audit event.
    pub tbs: AdminCommandTbs,
    /// The operator signature that verified, for the audit event.
    pub operator_signature: Ed25519Signature,
    /// Confirmation status.
    pub confirmation: ConfirmationState,
}

struct Authenticated {
    operator_id: OperatorId,
    key: Ed25519PublicKey,
    permissions: AdminPermissionSet,
    next_counter: u64,
    pending: Option<PendingConfirmation>,
}

enum State {
    AwaitingOper { pings: u8 },
    Authenticated(Authenticated),
    Closed(AdminCloseReason),
}

/// One administrative session from challenge to close.
pub struct AdminSession {
    binding: AdminSessionBinding,
    challenge: AdminChallenge,
    peer: PeerIdentity,
    state: State,
}

impl AdminSession {
    /// Starts a session after the runtime rendered `challenge.render_note()`.
    #[must_use]
    pub const fn new(
        binding: AdminSessionBinding,
        challenge: AdminChallenge,
        peer: PeerIdentity,
    ) -> Self {
        Self {
            binding,
            challenge,
            peer,
            state: State::AwaitingOper { pings: 0 },
        }
    }

    /// Returns the visible phase.
    #[must_use]
    pub const fn state(&self) -> AdminSessionState {
        match &self.state {
            State::AwaitingOper { .. } => AdminSessionState::AwaitingOper,
            State::Authenticated(_) => AdminSessionState::Authenticated,
            State::Closed(reason) => AdminSessionState::Closed(*reason),
        }
    }

    /// Returns the authenticated operator and permissions, if any.
    #[must_use]
    pub const fn operator(&self) -> Option<(OperatorId, AdminPermissionSet)> {
        match &self.state {
            State::Authenticated(auth) => Some((auth.operator_id, auth.permissions)),
            State::AwaitingOper { .. } | State::Closed(_) => None,
        }
    }

    /// Closes the session from the runtime side.
    pub fn terminate(&mut self, reason: AdminCloseReason) {
        self.state = State::Closed(reason);
    }

    /// Consumes any pending confirmation (disconnect, authority reload, expiry).
    pub fn consume_confirmation(&mut self) {
        if let State::Authenticated(auth) = &mut self.state {
            auth.pending = None;
        }
    }

    /// Records the token the runtime drew for a `Required` command.
    pub fn issue_confirmation(
        &mut self,
        token: ConfirmationToken,
        now: MonotonicTick,
        canonical_command: &[u8],
        target_revision: Revision,
    ) -> Result<&ConfirmationToken, AdminError> {
        let State::Authenticated(auth) = &mut self.state else {
            return Err(AdminError::Confirmation);
        };
        let pending = PendingConfirmation::issue(
            token,
            now,
            canonical_command,
            target_revision,
            auth.permissions,
        )?;
        Ok(auth.pending.insert(pending).token())
    }

    /// Accepts one CRLF-terminated line; an error closes the session.
    pub fn accept_line(
        &mut self,
        line: &[u8],
        now: MonotonicTick,
        registry: &OperatorRegistry,
    ) -> Result<AdminEvent, AdminCloseReason> {
        let result = match &mut self.state {
            State::Closed(reason) => Err(*reason),
            State::AwaitingOper { pings } => {
                let mut budget = *pings;
                let outcome = Self::pre_auth_line(
                    &self.binding,
                    &self.challenge,
                    &self.peer,
                    registry,
                    &mut budget,
                    line,
                );
                *pings = budget;
                outcome
            }
            State::Authenticated(auth) => {
                Self::authenticated_line(&self.binding, &self.challenge, auth, line, now)
            }
        };
        match result {
            Ok(PreAuthOutcome::Event(event)) => Ok(event),
            Ok(PreAuthOutcome::Authenticated(auth)) => {
                let event = AdminEvent::Authenticated {
                    operator_id: auth.operator_id,
                    permissions: auth.permissions,
                };
                self.state = State::Authenticated(auth);
                Ok(event)
            }
            Ok(PreAuthOutcome::Quit) => {
                self.state = State::Closed(AdminCloseReason::Quit);
                Ok(AdminEvent::Quit)
            }
            Err(reason) => {
                self.state = State::Closed(reason);
                Err(reason)
            }
        }
    }

    fn pre_auth_line(
        binding: &AdminSessionBinding,
        challenge: &AdminChallenge,
        peer: &PeerIdentity,
        registry: &OperatorRegistry,
        pings: &mut u8,
        line: &[u8],
    ) -> Result<PreAuthOutcome, AdminCloseReason> {
        let content = line
            .strip_suffix(b"\r\n")
            .ok_or(AdminCloseReason::MalformedLine)?;
        if content.first() == Some(&b'@') || content.len() > MAX_ADMIN_COMMAND_BYTES {
            return Err(AdminCloseReason::MalformedLine);
        }
        let command =
            CanonicalCommand::check(content).map_err(|_| AdminCloseReason::MalformedLine)?;
        let parameters = command.parameters();
        match (command.verb(), parameters.as_slice()) {
            ("PING", [token]) => {
                Self::charge_ping(pings)?;
                let token =
                    PingToken::try_from_str(token, agenc_ircd_types::ControlPolicy::RejectAll)
                        .map_err(|_| AdminCloseReason::MalformedLine)?;
                Ok(PreAuthOutcome::Event(AdminEvent::PreAuthPing(token)))
            }
            ("PONG", [token]) => {
                Self::charge_ping(pings)?;
                let token =
                    PingToken::try_from_str(token, agenc_ircd_types::ControlPolicy::RejectAll)
                        .map_err(|_| AdminCloseReason::MalformedLine)?;
                Ok(PreAuthOutcome::Event(AdminEvent::PreAuthPong(token)))
            }
            ("QUIT", []) => Ok(PreAuthOutcome::Quit),
            ("OPER", [operator, signature]) => {
                Self::prove_operator(binding, challenge, peer, registry, operator, signature)
            }
            _ => Err(AdminCloseReason::MalformedLine),
        }
    }

    fn charge_ping(pings: &mut u8) -> Result<(), AdminCloseReason> {
        if *pings >= MAX_PRE_AUTH_PINGS {
            return Err(AdminCloseReason::PingBudget);
        }
        *pings = pings.saturating_add(1);
        Ok(())
    }

    fn prove_operator(
        binding: &AdminSessionBinding,
        challenge: &AdminChallenge,
        peer: &PeerIdentity,
        registry: &OperatorRegistry,
        operator: &str,
        signature: &str,
    ) -> Result<PreAuthOutcome, AdminCloseReason> {
        let operator_id =
            OperatorId::parse(operator).map_err(|_| AdminCloseReason::MalformedLine)?;
        let signature = parse_signature_token(signature.as_bytes())
            .map_err(|_| AdminCloseReason::MalformedLine)?;
        let record = registry
            .select(operator_id, peer)
            .map_err(|_| AdminCloseReason::OperatorMismatch)?;
        challenge
            .verify_oper(
                binding.network_id,
                binding.server_id,
                record.signing_key(),
                signature,
            )
            .map_err(|_| AdminCloseReason::ProofFailed)?;
        Ok(PreAuthOutcome::Authenticated(Authenticated {
            operator_id,
            key: record.signing_key(),
            permissions: record.permissions(),
            next_counter: 0,
            pending: None,
        }))
    }

    fn authenticated_line(
        binding: &AdminSessionBinding,
        challenge: &AdminChallenge,
        auth: &mut Authenticated,
        line: &[u8],
        now: MonotonicTick,
    ) -> Result<PreAuthOutcome, AdminCloseReason> {
        let mut parsed = parse_admin_line(line).map_err(|error| match error {
            AdminError::Counter => AdminCloseReason::BadCounter,
            _ => AdminCloseReason::MalformedLine,
        })?;
        if parsed.counter() != auth.next_counter {
            return Err(AdminCloseReason::BadCounter);
        }
        let canonical = CanonicalCommand::check(parsed.command())
            .map_err(|_| AdminCloseReason::MalformedLine)?;
        let command =
            AdminCommand::parse(canonical).map_err(|_| AdminCloseReason::MalformedLine)?;
        let presented = parsed.take_confirmation();
        let token_hash = match &presented {
            Some(token) => Some(token.hash().map_err(|_| AdminCloseReason::MalformedLine)?),
            None => None,
        };
        let tbs = AdminCommandTbs::new(
            binding.network_id,
            binding.server_id,
            challenge.session_id(),
            parsed.counter(),
            token_hash,
            canonical.as_bytes(),
        )
        .map_err(|_| AdminCloseReason::MalformedLine)?;
        tbs.verify(auth.key, parsed.signature())
            .map_err(|_| AdminCloseReason::BadSignature)?;
        auth.next_counter = auth
            .next_counter
            .checked_add(1)
            .ok_or(AdminCloseReason::BadCounter)?;
        Self::dispatch(auth, command, tbs, parsed.signature(), presented, now)
    }

    fn dispatch(
        auth: &mut Authenticated,
        command: AdminCommand,
        tbs: AdminCommandTbs,
        operator_signature: Ed25519Signature,
        presented: Option<ConfirmationToken>,
        now: MonotonicTick,
    ) -> Result<PreAuthOutcome, AdminCloseReason> {
        let counter = tbs.command_counter();
        if matches!(command, AdminCommand::Quit) {
            return Ok(PreAuthOutcome::Quit);
        }
        if let Some(permission) = command.required_permission()
            && !auth.permissions.contains(permission)
        {
            return Ok(PreAuthOutcome::Event(AdminEvent::PermissionDenied {
                verb: command.verb(),
                counter,
            }));
        }
        let confirmation =
            Self::confirmation_state(auth, &command, tbs.canonical_command(), presented, now)?;
        Ok(PreAuthOutcome::Event(AdminEvent::Command(Box::new(
            AdminCommandEvent {
                command,
                counter,
                tbs,
                operator_signature,
                confirmation,
            },
        ))))
    }

    fn confirmation_state(
        auth: &mut Authenticated,
        command: &AdminCommand,
        canonical_command: &[u8],
        presented: Option<ConfirmationToken>,
        now: MonotonicTick,
    ) -> Result<ConfirmationState, AdminCloseReason> {
        match (command.needs_confirmation(), presented) {
            (false, None) => Ok(ConfirmationState::NotRequired),
            (false, Some(_)) => Err(AdminCloseReason::ConfirmationBinding),
            (true, None) => {
                // A fresh first step consumes any earlier token (spec 4580).
                auth.pending = None;
                Ok(ConfirmationState::Required)
            }
            (true, Some(token)) => Self::check_repeat(auth, &token, canonical_command, now),
        }
    }

    /// The second step: the presented token must bind to the one pending
    /// confirmation, which is consumed whatever the outcome (spec 4579-4581).
    fn check_repeat(
        auth: &mut Authenticated,
        token: &ConfirmationToken,
        canonical_command: &[u8],
        now: MonotonicTick,
    ) -> Result<ConfirmationState, AdminCloseReason> {
        let pending = auth
            .pending
            .take()
            .ok_or(AdminCloseReason::ConfirmationBinding)?;
        let check = pending
            .check(now, token, canonical_command, auth.permissions)
            .map_err(|_| AdminCloseReason::ConfirmationBinding)?;
        match check {
            ConfirmationCheck::Satisfied => Ok(ConfirmationState::Satisfied {
                target_revision: pending.target_revision(),
            }),
            ConfirmationCheck::Expired | ConfirmationCheck::Mismatch => {
                Err(AdminCloseReason::ConfirmationBinding)
            }
        }
    }
}

enum PreAuthOutcome {
    Event(AdminEvent),
    Authenticated(Authenticated),
    Quit,
}

#[cfg(test)]
mod tests {
    use agenc_ircd_crypto::Ed25519SecretKey;
    use agenc_ircd_types::{
        AdminPermission, AdminPermissionSet, MonotonicTick, NetworkId, OperatorId, Revision,
        ServerId,
    };

    use super::{
        AdminEvent, AdminSession, AdminSessionBinding, AdminSessionState, ConfirmationState,
    };
    use crate::{
        AdminChallenge, AdminCloseReason, AdminCommand, AdminCommandTbs, AdminError,
        AdminSessionId, Challenge, ConfirmationToken, OperatorRecord, OperatorRegistry,
        PeerIdentity, TransportBinding, TransportKind, encode_base64url, render_admin_tag,
    };

    const OPERATOR_KEY: [u8; 32] = [21; 32];

    fn binding() -> AdminSessionBinding {
        AdminSessionBinding {
            network_id: NetworkId::from_bytes([1; 32]),
            server_id: ServerId::from_bytes([2; 16]),
        }
    }

    fn challenge() -> AdminChallenge {
        AdminChallenge::new(
            AdminSessionId::from_bytes([3; 16]),
            Challenge::from_bytes([4; 32]),
            TransportKind::Local,
            TransportBinding::from_bytes([5; 32]),
        )
    }

    fn operator_id() -> OperatorId {
        OperatorId::from_bytes([6; 16])
    }

    fn registry(permissions: &[AdminPermission]) -> Result<OperatorRegistry, AdminError> {
        let mut set = AdminPermissionSet::EMPTY;
        for permission in permissions {
            set.insert(*permission);
        }
        OperatorRegistry::from_records(vec![OperatorRecord::new(
            operator_id(),
            Ed25519SecretKey::from_bytes(OPERATOR_KEY).public_key(),
            None,
            vec![1000],
            vec![],
            set,
            true,
        )?])
    }

    fn peer() -> PeerIdentity {
        PeerIdentity::Local {
            uid: 1000,
            gid: 1000,
        }
    }

    fn tick(value: u64) -> Result<MonotonicTick, AdminError> {
        MonotonicTick::new(value).map_err(|_| AdminError::Overflow)
    }

    fn oper_line() -> Result<Vec<u8>, AdminError> {
        let signature = challenge().sign_oper(
            binding().network_id,
            binding().server_id,
            &Ed25519SecretKey::from_bytes(OPERATOR_KEY),
        )?;
        Ok(format!(
            "OPER {} {}\r\n",
            operator_id().to_base64url(),
            encode_base64url(signature.as_bytes())
        )
        .into_bytes())
    }

    fn signed_line(
        counter: u64,
        command: &str,
        token: Option<&ConfirmationToken>,
    ) -> Result<Vec<u8>, AdminError> {
        let hash = match token {
            Some(token) => Some(token.hash()?),
            None => None,
        };
        let tbs = AdminCommandTbs::new(
            binding().network_id,
            binding().server_id,
            AdminSessionId::from_bytes([3; 16]),
            counter,
            hash,
            command.as_bytes(),
        )?;
        let signature = tbs.sign(&Ed25519SecretKey::from_bytes(OPERATOR_KEY))?;
        Ok(format!(
            "{} {command}\r\n",
            render_admin_tag(counter, &signature, token)
        )
        .into_bytes())
    }

    fn authenticated(
        permissions: &[AdminPermission],
    ) -> Result<(AdminSession, OperatorRegistry), AdminError> {
        let registry = registry(permissions)?;
        let mut session = AdminSession::new(binding(), challenge(), peer());
        let event = session.accept_line(&oper_line()?, tick(0)?, &registry);
        assert!(matches!(event, Ok(AdminEvent::Authenticated { .. })));
        assert_eq!(session.state(), AdminSessionState::Authenticated);
        Ok((session, registry))
    }

    #[test]
    fn pre_authentication_allows_only_bounded_liveness_quit_and_one_oper() -> Result<(), AdminError>
    {
        let registry = registry(&[AdminPermission::Observe])?;
        let mut session = AdminSession::new(binding(), challenge(), peer());
        assert_eq!(session.state(), AdminSessionState::AwaitingOper);
        assert!(session.operator().is_none());
        for _ in 0..4 {
            assert!(matches!(
                session.accept_line(b"PING abc\r\n", tick(0)?, &registry),
                Ok(AdminEvent::PreAuthPing(_))
            ));
            assert!(matches!(
                session.accept_line(b"PONG abc\r\n", tick(0)?, &registry),
                Ok(AdminEvent::PreAuthPong(_))
            ));
        }
        assert_eq!(
            session
                .accept_line(b"PING abc\r\n", tick(0)?, &registry)
                .err(),
            Some(AdminCloseReason::PingBudget)
        );
        assert_eq!(
            session.state(),
            AdminSessionState::Closed(AdminCloseReason::PingBudget)
        );
        assert_eq!(
            session.accept_line(b"QUIT\r\n", tick(0)?, &registry).err(),
            Some(AdminCloseReason::PingBudget)
        );

        for (line, reason) in [
            (&b"STATS RUNTIME\r\n"[..], AdminCloseReason::MalformedLine),
            (b"PING\r\n", AdminCloseReason::MalformedLine),
            (b"ping abc\r\n", AdminCloseReason::MalformedLine),
            (b"OPER x y\r\n", AdminCloseReason::MalformedLine),
            (b"QUIT", AdminCloseReason::MalformedLine),
            (
                b"@+agenc.ag/admin=v1.0.x QUIT\r\n",
                AdminCloseReason::MalformedLine,
            ),
        ] {
            let mut fresh = AdminSession::new(binding(), challenge(), peer());
            assert_eq!(
                fresh.accept_line(line, tick(0)?, &registry).err(),
                Some(reason)
            );
        }
        let mut quitting = AdminSession::new(binding(), challenge(), peer());
        assert!(matches!(
            quitting.accept_line(b"QUIT\r\n", tick(0)?, &registry),
            Ok(AdminEvent::Quit)
        ));
        assert_eq!(
            quitting.state(),
            AdminSessionState::Closed(AdminCloseReason::Quit)
        );
        Ok(())
    }

    #[test]
    fn oper_requires_matching_record_and_valid_proof_once() -> Result<(), AdminError> {
        let (mut session, registry) = authenticated(&[AdminPermission::Observe])?;
        assert_eq!(session.operator().map(|(id, _)| id), Some(operator_id()));
        let second = signed_line(0, "OPER x y", None)?;
        assert_eq!(
            session.accept_line(&second, tick(0)?, &registry).err(),
            Some(AdminCloseReason::MalformedLine)
        );

        let wrong_peer = PeerIdentity::Local { uid: 1, gid: 1 };
        let mut mismatched = AdminSession::new(binding(), challenge(), wrong_peer);
        assert_eq!(
            mismatched
                .accept_line(&oper_line()?, tick(0)?, &registry)
                .err(),
            Some(AdminCloseReason::OperatorMismatch)
        );
        let other_key = registry_with_key([22; 32])?;
        let mut failed = AdminSession::new(binding(), challenge(), peer());
        assert_eq!(
            failed
                .accept_line(&oper_line()?, tick(0)?, &other_key)
                .err(),
            Some(AdminCloseReason::ProofFailed)
        );
        let other_challenge = AdminChallenge::new(
            AdminSessionId::from_bytes([9; 16]),
            Challenge::from_bytes([4; 32]),
            TransportKind::Tls,
            TransportBinding::from_bytes([5; 32]),
        );
        let mut replayed = AdminSession::new(binding(), other_challenge, peer());
        assert_eq!(
            replayed
                .accept_line(&oper_line()?, tick(0)?, &registry)
                .err(),
            Some(AdminCloseReason::ProofFailed)
        );
        Ok(())
    }

    fn registry_with_key(seed: [u8; 32]) -> Result<OperatorRegistry, AdminError> {
        let mut set = AdminPermissionSet::EMPTY;
        set.insert(AdminPermission::Observe);
        OperatorRegistry::from_records(vec![OperatorRecord::new(
            operator_id(),
            Ed25519SecretKey::from_bytes(seed).public_key(),
            None,
            vec![1000],
            vec![],
            set,
            true,
        )?])
    }

    #[test]
    fn authenticated_lines_enforce_counter_signature_form_and_permission() -> Result<(), AdminError>
    {
        let (mut session, registry) = authenticated(&[AdminPermission::Observe])?;
        let event =
            session.accept_line(&signed_line(0, "STATS RUNTIME", None)?, tick(0)?, &registry);
        match event {
            Ok(AdminEvent::Command(accepted)) => {
                assert!(accepted.command == AdminCommand::Stats(crate::StatsSelector::Runtime));
                assert_eq!(accepted.counter, 0);
                assert_eq!(accepted.confirmation, ConfirmationState::NotRequired);
                assert_eq!(accepted.tbs.canonical_command(), b"STATS RUNTIME");
            }
            _ => return Err(AdminError::Command),
        }
        assert!(matches!(
            session.accept_line(&signed_line(1, "PING x", None)?, tick(0)?, &registry),
            Ok(AdminEvent::Command(accepted))
                if matches!(accepted.command, AdminCommand::Ping(_)) && accepted.counter == 1
        ));
        assert!(matches!(
            session.accept_line(
                &signed_line(2, "REHASH :now please", None)?,
                tick(0)?,
                &registry
            ),
            Ok(AdminEvent::PermissionDenied {
                verb: "REHASH",
                counter: 2
            })
        ));
        assert!(matches!(
            session.accept_line(&signed_line(3, "QUIT", None)?, tick(0)?, &registry),
            Ok(AdminEvent::Quit)
        ));
        assert_eq!(
            session.state(),
            AdminSessionState::Closed(AdminCloseReason::Quit)
        );

        let cases: [(u64, &str, AdminCloseReason); 3] = [
            (1, "STATS RUNTIME", AdminCloseReason::BadCounter),
            (0, "stats RUNTIME", AdminCloseReason::MalformedLine),
            (0, "FROBNICATE", AdminCloseReason::MalformedLine),
        ];
        for (counter, command, reason) in cases {
            let (mut fresh, registry) = authenticated(&[AdminPermission::Observe])?;
            assert_eq!(
                fresh
                    .accept_line(&signed_line(counter, command, None)?, tick(0)?, &registry)
                    .err(),
                Some(reason),
                "{command}"
            );
        }
        let (mut fresh, registry) = authenticated(&[AdminPermission::Observe])?;
        let mut forged = signed_line(0, "STATS RUNTIME", None)?;
        if let Some(byte) = forged.get_mut(25) {
            *byte = if *byte == b'A' { b'B' } else { b'A' };
        }
        assert_eq!(
            fresh.accept_line(&forged, tick(0)?, &registry).err(),
            Some(AdminCloseReason::BadSignature)
        );
        let (mut fresh, registry) = authenticated(&[AdminPermission::Observe])?;
        let leading_zero = signed_line(0, "STATS RUNTIME", None)?;
        let leading_zero = String::from_utf8_lossy(&leading_zero).replace("v1.0.", "v1.00.");
        assert_eq!(
            fresh
                .accept_line(leading_zero.as_bytes(), tick(0)?, &registry)
                .err(),
            Some(AdminCloseReason::BadCounter)
        );
        let (mut fresh, registry) = authenticated(&[AdminPermission::Observe])?;
        assert_eq!(
            fresh
                .accept_line(b"STATS RUNTIME\r\n", tick(0)?, &registry)
                .err(),
            Some(AdminCloseReason::MalformedLine)
        );
        let (mut replay, registry) = authenticated(&[AdminPermission::Observe])?;
        let first = signed_line(0, "STATS RUNTIME", None)?;
        assert!(replay.accept_line(&first, tick(0)?, &registry).is_ok());
        assert_eq!(
            replay.accept_line(&first, tick(0)?, &registry).err(),
            Some(AdminCloseReason::BadCounter)
        );
        Ok(())
    }

    #[test]
    fn two_step_confirmation_binds_token_command_permissions_and_time() -> Result<(), AdminError> {
        let (mut session, registry) = authenticated(&[AdminPermission::Process])?;
        let first = session.accept_line(
            &signed_line(0, "DIE :planned maintenance", None)?,
            tick(1_000)?,
            &registry,
        );
        assert!(matches!(
            first,
            Ok(AdminEvent::Command(accepted))
                if accepted.confirmation == ConfirmationState::Required
        ));
        let token_bytes = [7_u8; 16];
        let revision = Revision::new(5).map_err(|_| AdminError::Overflow)?;
        session.issue_confirmation(
            ConfirmationToken::from_bytes(token_bytes),
            tick(1_000)?,
            b"DIE :planned maintenance",
            revision,
        )?;
        let repeat = signed_line(
            1,
            "DIE :planned maintenance",
            Some(&ConfirmationToken::from_bytes(token_bytes)),
        )?;
        assert!(matches!(
            session.accept_line(&repeat, tick(30_000)?, &registry),
            Ok(AdminEvent::Command(accepted))
                if accepted.confirmation == ConfirmationState::Satisfied { target_revision: revision }
        ));

        // A second repeat has nothing pending: the token was consumed.
        let again = signed_line(
            2,
            "DIE :planned maintenance",
            Some(&ConfirmationToken::from_bytes(token_bytes)),
        )?;
        assert_eq!(
            session.accept_line(&again, tick(31_000)?, &registry).err(),
            Some(AdminCloseReason::ConfirmationBinding)
        );

        let (mut expired, registry) = authenticated(&[AdminPermission::Process])?;
        expired
            .accept_line(&signed_line(0, "DIE :x y", None)?, tick(1_000)?, &registry)
            .map_err(|_| AdminError::Confirmation)?;
        expired.issue_confirmation(
            ConfirmationToken::from_bytes(token_bytes),
            tick(1_000)?,
            b"DIE :x y",
            revision,
        )?;
        let late = signed_line(
            1,
            "DIE :x y",
            Some(&ConfirmationToken::from_bytes(token_bytes)),
        )?;
        assert_eq!(
            expired.accept_line(&late, tick(61_000)?, &registry).err(),
            Some(AdminCloseReason::ConfirmationBinding)
        );

        let (mut mismatch, registry) = authenticated(&[AdminPermission::Process])?;
        mismatch
            .accept_line(&signed_line(0, "DIE :x y", None)?, tick(0)?, &registry)
            .map_err(|_| AdminError::Confirmation)?;
        mismatch.issue_confirmation(
            ConfirmationToken::from_bytes(token_bytes),
            tick(0)?,
            b"DIE :x y",
            revision,
        )?;
        let other_command = signed_line(
            1,
            "DIE :y z",
            Some(&ConfirmationToken::from_bytes(token_bytes)),
        )?;
        assert_eq!(
            mismatch
                .accept_line(&other_command, tick(1)?, &registry)
                .err(),
            Some(AdminCloseReason::ConfirmationBinding)
        );

        let (mut wrong_token, registry) = authenticated(&[AdminPermission::Process])?;
        wrong_token
            .accept_line(&signed_line(0, "DIE :x y", None)?, tick(0)?, &registry)
            .map_err(|_| AdminError::Confirmation)?;
        wrong_token.issue_confirmation(
            ConfirmationToken::from_bytes(token_bytes),
            tick(0)?,
            b"DIE :x y",
            revision,
        )?;
        let other_token =
            signed_line(1, "DIE :x y", Some(&ConfirmationToken::from_bytes([8; 16])))?;
        assert_eq!(
            wrong_token
                .accept_line(&other_token, tick(1)?, &registry)
                .err(),
            Some(AdminCloseReason::ConfirmationBinding)
        );

        let (mut unrequested, registry) = authenticated(&[AdminPermission::Observe])?;
        let stray = signed_line(
            0,
            "STATS RUNTIME",
            Some(&ConfirmationToken::from_bytes(token_bytes)),
        )?;
        assert_eq!(
            unrequested.accept_line(&stray, tick(0)?, &registry).err(),
            Some(AdminCloseReason::ConfirmationBinding)
        );

        let (mut replaced, registry) = authenticated(&[AdminPermission::Process])?;
        replaced
            .accept_line(&signed_line(0, "DIE :x y", None)?, tick(0)?, &registry)
            .map_err(|_| AdminError::Confirmation)?;
        replaced.issue_confirmation(
            ConfirmationToken::from_bytes(token_bytes),
            tick(0)?,
            b"DIE :x y",
            revision,
        )?;
        // A fresh first step consumes the earlier token.
        assert!(matches!(
            replaced.accept_line(&signed_line(1, "RESTART :x y", None)?, tick(0)?, &registry),
            Ok(AdminEvent::Command(accepted))
                if accepted.confirmation == ConfirmationState::Required
        ));
        let stale = signed_line(
            2,
            "DIE :x y",
            Some(&ConfirmationToken::from_bytes(token_bytes)),
        )?;
        assert_eq!(
            replaced.accept_line(&stale, tick(1)?, &registry).err(),
            Some(AdminCloseReason::ConfirmationBinding)
        );

        let (mut consumed, registry) = authenticated(&[AdminPermission::Process])?;
        consumed
            .accept_line(&signed_line(0, "DIE :x y", None)?, tick(0)?, &registry)
            .map_err(|_| AdminError::Confirmation)?;
        consumed.issue_confirmation(
            ConfirmationToken::from_bytes(token_bytes),
            tick(0)?,
            b"DIE :x y",
            revision,
        )?;
        consumed.consume_confirmation();
        let after_consume = signed_line(
            1,
            "DIE :x y",
            Some(&ConfirmationToken::from_bytes(token_bytes)),
        )?;
        assert_eq!(
            consumed
                .accept_line(&after_consume, tick(1)?, &registry)
                .err(),
            Some(AdminCloseReason::ConfirmationBinding)
        );

        let mut unauthenticated = AdminSession::new(binding(), challenge(), peer());
        assert_eq!(
            unauthenticated
                .issue_confirmation(
                    ConfirmationToken::from_bytes(token_bytes),
                    tick(0)?,
                    b"DIE :x y",
                    revision
                )
                .err(),
            Some(AdminError::Confirmation)
        );
        unauthenticated.terminate(AdminCloseReason::Terminated);
        assert_eq!(
            unauthenticated.state(),
            AdminSessionState::Closed(AdminCloseReason::Terminated)
        );
        unauthenticated.consume_confirmation();
        Ok(())
    }
}
