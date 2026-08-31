//! Isolated administrative transport ownership (spec 22.4 and 22.5).
//!
//! This module is the only runtime boundary that accepts administrative
//! plaintext. Listener tasks hand complete bounded CRLF records to the
//! private admin-owner channel; neither credentials nor lines are converted
//! into public client messages or sent to `StateCore`'s client inbox.

mod audit;

use std::collections::BTreeMap;
use std::time::Duration;

use agenc_ircd_admin::{
    AdminAuditPhase, AdminChallenge, AdminCommand, AdminCommandEvent, AdminSession,
    AdminSessionBinding, MAX_ADMIN_LINE_BYTES, MAX_ADMIN_OUTPUT_LINE_BYTES, OperatorRegistry,
    PeerIdentity,
};
use agenc_ircd_types::{MonotonicClock, WallClock};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::mpsc;

use crate::budget::MemoryPermitBatch;
use crate::cancel::CancellationToken;
use crate::connection::{ConnectionExit, ConnectionGeneration, ConnectionResources};
use crate::purpose::ListenerPurpose;
use crate::state_core::inbox::CloseReason;
use crate::state_core::{AdminCoreFailure, AdminCorePort};

pub(crate) use audit::AuditAuthority;

/// RFC 9846 exporter label for the remote administrative session binding.
pub(crate) const ADMIN_EXPORTER_LABEL: &[u8] = b"EXPORTER-agenc-chat-admin-v1";
/// Admin messages waiting for the single owner.
const ADMIN_OWNER_CAPACITY: usize = 64;
/// Complete ordered response batches waiting for one writer.
const ADMIN_OUTPUT_CAPACITY: usize = 4;
/// Owner notification stall budget, matching the public connection boundary.
const ADMIN_NOTICE_BUDGET: Duration = Duration::from_secs(30);
/// Largest ordinary response batch. Audit export has a separately charged
/// path and will raise this through a typed constructor in its composition
/// slice.
const MAX_ORDINARY_BATCH_LINES: usize = 32;

/// Opaque listener-side handle for the private admin-owner inbox.
///
/// The fields and construction path stay crate-private. Embedders can place
/// `None` in [`crate::listener::ListenerContext`] when no admin endpoint is
/// present, but cannot inject administrative events.
#[derive(Clone)]
pub struct AdminTransportPort {
    binding: AdminSessionBinding,
    sender: mpsc::Sender<AdminOwnerMessage>,
}

impl AdminTransportPort {
    pub(crate) const fn binding(&self) -> AdminSessionBinding {
        self.binding
    }

    async fn opened(
        &self,
        generation: ConnectionGeneration,
        challenge: AdminChallenge,
        peer: PeerIdentity,
        output: AdminOutput,
        token: &CancellationToken,
    ) -> Result<(), CloseReason> {
        self.send(
            AdminOwnerMessage::Opened {
                generation,
                challenge,
                peer,
                output,
            },
            token,
        )
        .await
    }

    async fn line(
        &self,
        generation: ConnectionGeneration,
        line: Vec<u8>,
        token: &CancellationToken,
    ) -> Result<(), CloseReason> {
        self.send(AdminOwnerMessage::Line { generation, line }, token)
            .await
    }

    async fn closed(&self, generation: ConnectionGeneration, reason: CloseReason) {
        let message = AdminOwnerMessage::Closed { generation, reason };
        let _ = tokio::time::timeout(ADMIN_NOTICE_BUDGET, self.sender.send(message)).await;
    }

    async fn send(
        &self,
        message: AdminOwnerMessage,
        token: &CancellationToken,
    ) -> Result<(), CloseReason> {
        tokio::select! {
            () = token.cancelled() => Err(CloseReason::Shutdown),
            sent = tokio::time::timeout(ADMIN_NOTICE_BUDGET, self.sender.send(message)) => {
                match sent {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(_)) => Err(CloseReason::Shutdown),
                    Err(_) => Err(CloseReason::ReadStall),
                }
            }
        }
    }
}

enum AdminOwnerMessage {
    Opened {
        generation: ConnectionGeneration,
        challenge: AdminChallenge,
        peer: PeerIdentity,
        output: AdminOutput,
    },
    Line {
        generation: ConnectionGeneration,
        line: Vec<u8>,
    },
    Closed {
        generation: ConnectionGeneration,
        reason: CloseReason,
    },
}

struct AdminOutput {
    sender: mpsc::Sender<AdminWrite>,
}

impl AdminOutput {
    fn try_line(&self, line: String) -> Result<(), CloseReason> {
        self.try_batch(vec![line], None)
    }

    fn try_close(&self, reason: CloseReason) -> Result<(), CloseReason> {
        self.try_batch(Vec::new(), Some(reason))
    }

    fn try_batch(&self, lines: Vec<String>, close: Option<CloseReason>) -> Result<(), CloseReason> {
        let batch = AdminWrite::ordinary(lines, close)?;
        self.sender.try_send(batch).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => CloseReason::SlowConsumer,
            mpsc::error::TrySendError::Closed(_) => CloseReason::TransportLoss,
        })
    }
}

struct AdminWrite {
    lines: Vec<Vec<u8>>,
    close: Option<CloseReason>,
    _memory: Option<MemoryPermitBatch>,
}

impl AdminWrite {
    fn ordinary(lines: Vec<String>, close: Option<CloseReason>) -> Result<Self, CloseReason> {
        if lines.len() > MAX_ORDINARY_BATCH_LINES {
            return Err(CloseReason::Overload);
        }
        let mut encoded = Vec::with_capacity(lines.len());
        for line in lines {
            let bytes = line.into_bytes();
            if bytes.is_empty()
                || bytes.len() > MAX_ADMIN_OUTPUT_LINE_BYTES
                || bytes.iter().any(|byte| matches!(byte, b'\r' | b'\n'))
            {
                return Err(CloseReason::ProtocolError);
            }
            encoded.push(bytes);
        }
        Ok(Self {
            lines: encoded,
            close,
            _memory: None,
        })
    }
}

/// Creates the one private transport port and receiver owned by
/// `AdminOwner`.
pub(crate) fn admin_transport_channel(
    binding: AdminSessionBinding,
) -> (AdminTransportPort, AdminOwnerInbox) {
    let (sender, receiver) = mpsc::channel(ADMIN_OWNER_CAPACITY);
    (
        AdminTransportPort { binding, sender },
        AdminOwnerInbox { receiver },
    )
}

pub(crate) struct AdminOwnerInbox {
    receiver: mpsc::Receiver<AdminOwnerMessage>,
}

/// Private owner of every live administrative session and its response order.
///
/// Command execution and durable audit composition are added on top of this
/// owner boundary; until then, authenticated commands fail closed instead of
/// crossing into the public protocol owner.
pub(crate) struct AdminOwner {
    binding: AdminSessionBinding,
    registry: OperatorRegistry,
    admission: AdminAdmissionSnapshot,
    audit: AuditAuthority,
    core: AdminCorePort,
    monotonic: Box<dyn MonotonicClock + Send>,
    wall: Box<dyn WallClock + Send>,
    sessions: BTreeMap<ConnectionGeneration, OwnedAdminSession>,
}

pub(crate) struct AdminOwnerClocks {
    pub(crate) monotonic: Box<dyn MonotonicClock + Send>,
    pub(crate) wall: Box<dyn WallClock + Send>,
}

/// Exact enabled-operator transport identities accepted before a challenge.
pub(crate) struct AdminAdmissionSnapshot {
    uids: Vec<u32>,
    gids: Vec<u32>,
    pins: Vec<[u8; 32]>,
}

impl AdminAdmissionSnapshot {
    pub(crate) fn new(mut uids: Vec<u32>, mut gids: Vec<u32>, mut pins: Vec<[u8; 32]>) -> Self {
        uids.sort_unstable();
        uids.dedup();
        gids.sort_unstable();
        gids.dedup();
        pins.sort_unstable();
        pins.dedup();
        Self { uids, gids, pins }
    }

    fn admits(&self, peer: PeerIdentity) -> bool {
        match peer {
            PeerIdentity::Local { uid, gid } => {
                self.uids.binary_search(&uid).is_ok() || self.gids.binary_search(&gid).is_ok()
            }
            PeerIdentity::Pin(pin) => self.pins.binary_search(&pin).is_ok(),
        }
    }
}

struct OwnedAdminSession {
    session: AdminSession,
    output: AdminOutput,
}

impl AdminOwner {
    pub(crate) fn new(
        binding: AdminSessionBinding,
        registry: OperatorRegistry,
        admission: AdminAdmissionSnapshot,
        audit: AuditAuthority,
        core: AdminCorePort,
        clocks: AdminOwnerClocks,
    ) -> Self {
        Self {
            binding,
            registry,
            admission,
            audit,
            core,
            monotonic: clocks.monotonic,
            wall: clocks.wall,
            sessions: BTreeMap::new(),
        }
    }

    pub(crate) async fn run(mut self, mut inbox: AdminOwnerInbox, token: CancellationToken) {
        loop {
            let message = tokio::select! {
                () = token.cancelled() => break,
                message = inbox.receiver.recv() => match message {
                    Some(message) => message,
                    None => break,
                },
            };
            self.handle(message, &token).await;
        }
        for (_, owned) in self.sessions {
            let _ = owned.output.try_close(CloseReason::Shutdown);
        }
    }

    async fn handle(&mut self, message: AdminOwnerMessage, token: &CancellationToken) {
        match message {
            AdminOwnerMessage::Opened {
                generation,
                challenge,
                peer,
                output,
            } => self.open(generation, challenge, peer, output),
            AdminOwnerMessage::Line { generation, line } => {
                self.line(generation, &line, token).await;
            }
            AdminOwnerMessage::Closed { generation, reason } => {
                let _ = reason;
                self.sessions.remove(&generation);
            }
        }
    }

    fn open(
        &mut self,
        generation: ConnectionGeneration,
        challenge: AdminChallenge,
        peer: PeerIdentity,
        output: AdminOutput,
    ) {
        if self.sessions.contains_key(&generation)
            || !self.admission.admits(peer)
            || !self.audit.is_reconciled()
        {
            let _ = output.try_close(CloseReason::ProtocolError);
            return;
        }
        let note = challenge.render_note();
        let session = AdminSession::new(self.binding, challenge, peer);
        if output.try_line(note).is_err() {
            let _ = output.try_close(CloseReason::SlowConsumer);
            return;
        }
        self.sessions
            .insert(generation, OwnedAdminSession { session, output });
    }

    async fn line(
        &mut self,
        generation: ConnectionGeneration,
        line: &[u8],
        token: &CancellationToken,
    ) {
        let now = self.monotonic.now();
        let outcome = {
            let Some(owned) = self.sessions.get_mut(&generation) else {
                return;
            };
            owned.session.accept_line(line, now, &self.registry)
        };
        match outcome {
            Ok(agenc_ircd_admin::AdminEvent::PreAuthPing(ping)) => {
                self.output_line(generation, format!("PONG :{}", ping.as_str()));
            }
            Ok(agenc_ircd_admin::AdminEvent::PreAuthPong(_)) => {}
            Ok(agenc_ircd_admin::AdminEvent::Quit) => {
                self.close(generation, CloseReason::ClientQuit);
            }
            Ok(agenc_ircd_admin::AdminEvent::Authenticated { .. }) => {}
            Ok(agenc_ircd_admin::AdminEvent::Command(event)) => {
                self.command(generation, *event, token).await;
            }
            Ok(agenc_ircd_admin::AdminEvent::PermissionDenied { verb, .. }) => {
                self.output_line(
                    generation,
                    format!("FAIL {verb} PRIVILEGES :Insufficient privileges"),
                );
            }
            Err(_reason) => {
                self.close(generation, CloseReason::ProtocolError);
            }
        }
    }

    async fn command(
        &mut self,
        generation: ConnectionGeneration,
        event: AdminCommandEvent,
        token: &CancellationToken,
    ) {
        match &event.command {
            AdminCommand::Ping(ping) => {
                self.output_line(generation, format!("PONG :{}", ping.as_str()));
                return;
            }
            AdminCommand::Pong(_) => return,
            _ => {}
        }
        let verb = event.command.verb();
        let Some(lines) = self.prepare_read_only(&event.command) else {
            self.output_line(
                generation,
                format!("FAIL {verb} UNAVAILABLE :Command unavailable"),
            );
            return;
        };
        let Some((operator_id, _permissions)) = self
            .sessions
            .get(&generation)
            .and_then(|owned| owned.session.operator())
        else {
            self.close(generation, CloseReason::ProtocolError);
            return;
        };
        let created_at = match self.wall.utc_now() {
            Ok(now) => now.get(),
            Err(_) => {
                self.output_storage_unavailable(generation, verb);
                return;
            }
        };
        let Ok(audit) = self.audit.prepare_event(
            self.binding,
            operator_id,
            &event,
            AdminAuditPhase::Observed,
            created_at,
        ) else {
            self.output_storage_unavailable(generation, verb);
            return;
        };
        match self.core.commit_audit(audit.clone(), token).await {
            Ok(()) => {
                if self.audit.commit_event(&audit).is_err() {
                    self.close(generation, CloseReason::ProtocolError);
                    return;
                }
                self.output_batch(generation, lines);
            }
            Err(AdminCoreFailure::Busy | AdminCoreFailure::Quiescing) => self.output_line(
                generation,
                format!("FAIL {verb} BUSY :Administrative action busy"),
            ),
            Err(AdminCoreFailure::StorageUnavailable) => {
                self.output_storage_unavailable(generation, verb);
            }
        }
    }

    fn prepare_read_only(&self, command: &AdminCommand) -> Option<Vec<String>> {
        match command {
            AdminCommand::Motd => Some(vec!["422 * :MOTD File is missing".to_owned()]),
            AdminCommand::Version => Some(vec![
                format!(
                    ":agenc-ircd 371 * :agenc-ircd-{}",
                    env!("CARGO_PKG_VERSION")
                ),
                ":agenc-ircd 374 * :End of INFO".to_owned(),
            ]),
            AdminCommand::Time => self
                .wall
                .utc_now()
                .ok()
                .map(|now| vec![format!(":agenc-ircd 391 * agenc-ircd :{}", now.get())]),
            AdminCommand::Links => Some(vec![
                ":agenc-ircd 371 * :Server topology is not exposed".to_owned(),
                ":agenc-ircd 374 * :End of INFO".to_owned(),
            ]),
            AdminCommand::Info
            | AdminCommand::Stats(_)
            | AdminCommand::AuditExport(_)
            | AdminCommand::Ping(_)
            | AdminCommand::Pong(_)
            | AdminCommand::Quit
            | AdminCommand::Rehash(_)
            | AdminCommand::Kill { .. }
            | AdminCommand::AccountSuspend { .. }
            | AdminCommand::AccountRestore { .. }
            | AdminCommand::ChannelQuarantine { .. }
            | AdminCommand::Connect { .. }
            | AdminCommand::Squit { .. }
            | AdminCommand::PeerQuarantine { .. }
            | AdminCommand::BackupCreate(_)
            | AdminCommand::Restart(_)
            | AdminCommand::Die(_) => None,
        }
    }

    fn output_storage_unavailable(&self, generation: ConnectionGeneration, verb: &str) {
        self.output_line(
            generation,
            format!("FAIL {verb} STORAGE_UNAVAILABLE :Administrative audit unavailable"),
        );
    }

    fn output_line(&self, generation: ConnectionGeneration, line: String) {
        self.output_batch(generation, vec![line]);
    }

    fn output_batch(&self, generation: ConnectionGeneration, lines: Vec<String>) {
        if let Some(owned) = self.sessions.get(&generation)
            && owned.output.try_batch(lines, None).is_err()
        {
            let _ = owned.output.try_close(CloseReason::SlowConsumer);
        }
    }

    fn close(&self, generation: ConnectionGeneration, reason: CloseReason) {
        if let Some(owned) = self.sessions.get(&generation) {
            let _ = owned.output.try_close(reason);
        }
    }
}

/// Inputs transferred into one administrative connection owner.
pub(crate) struct AdminConnectionStart {
    pub(crate) generation: ConnectionGeneration,
    pub(crate) purpose: ListenerPurpose,
    pub(crate) resources: ConnectionResources,
    pub(crate) challenge: AdminChallenge,
    pub(crate) peer: PeerIdentity,
    pub(crate) port: AdminTransportPort,
    pub(crate) token: CancellationToken,
}

/// Runs one bounded administrative reader/writer pair to completion.
// agenc-review: focus owner=runtime reviewed=2026-08-30 reason=one connection scope owns paired bounded reader writer cancellation and all resource permits
pub(crate) async fn run_admin_connection<T>(
    transport: T,
    start: AdminConnectionStart,
) -> ConnectionExit
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let AdminConnectionStart {
        generation,
        purpose,
        resources,
        challenge,
        peer,
        port,
        token,
    } = start;
    let ConnectionResources {
        permits,
        global_slot,
        listener_slot,
        queue_backing,
    } = resources;
    let (output_sender, output_receiver) = mpsc::channel(ADMIN_OUTPUT_CAPACITY);
    let output = AdminOutput {
        sender: output_sender,
    };
    if let Err(reason) = port
        .opened(generation, challenge, peer, output, &token)
        .await
    {
        drop((permits, global_slot, listener_slot, queue_backing));
        return ConnectionExit {
            generation,
            purpose,
            reason,
        };
    }

    let (read_half, write_half) = tokio::io::split(transport);
    let reader_token = token.child();
    let writer_token = token.child();
    let reason = match (reader_token, writer_token) {
        (Ok(reader_token), Ok(writer_token)) => {
            let mut reader = tokio::spawn(run_admin_reader(
                read_half,
                generation,
                port.clone(),
                reader_token.clone(),
            ));
            let mut writer = tokio::spawn(run_admin_writer(
                write_half,
                output_receiver,
                writer_token.clone(),
            ));
            tokio::select! {
                read = &mut reader => {
                    let reason = read.unwrap_or(CloseReason::TransportLoss);
                    writer_token.cancel();
                    let _ = writer.await;
                    reason
                }
                written = &mut writer => {
                    let reason = written.unwrap_or(CloseReason::TransportLoss);
                    reader_token.cancel();
                    let _ = reader.await;
                    reason
                }
            }
        }
        _ => CloseReason::Overload,
    };
    port.closed(generation, reason).await;
    drop((permits, global_slot, listener_slot, queue_backing));
    ConnectionExit {
        generation,
        purpose,
        reason,
    }
}

async fn run_admin_reader<R>(
    mut reader: R,
    generation: ConnectionGeneration,
    port: AdminTransportPort,
    token: CancellationToken,
) -> CloseReason
where
    R: AsyncRead + Unpin,
{
    let mut frame = [0_u8; MAX_ADMIN_LINE_BYTES];
    let mut used = 0_usize;
    loop {
        if used == frame.len() {
            return CloseReason::ProtocolError;
        }
        let Some(remaining) = frame.get_mut(used..) else {
            return CloseReason::ProtocolError;
        };
        let read = tokio::select! {
            () = token.cancelled() => return CloseReason::Shutdown,
            read = reader.read(remaining) => match read {
                Ok(read) => read,
                Err(_) => return CloseReason::TransportLoss,
            },
        };
        if read == 0 {
            return if used == 0 {
                CloseReason::TransportLoss
            } else {
                CloseReason::ProtocolError
            };
        }
        used = used.saturating_add(read);
        while let Some(end) = frame
            .get(..used)
            .and_then(|buffered| buffered.iter().position(|byte| *byte == b'\n'))
        {
            let line_len = end.saturating_add(1);
            if line_len < 2 || frame.get(line_len - 2) != Some(&b'\r') {
                return CloseReason::ProtocolError;
            }
            let Some(line) = frame.get(..line_len).map(<[u8]>::to_vec) else {
                return CloseReason::ProtocolError;
            };
            frame.copy_within(line_len..used, 0);
            used -= line_len;
            if let Err(reason) = port.line(generation, line, &token).await {
                return reason;
            }
        }
    }
}

async fn run_admin_writer<W>(
    mut writer: W,
    mut output: mpsc::Receiver<AdminWrite>,
    token: CancellationToken,
) -> CloseReason
where
    W: AsyncWrite + Unpin,
{
    loop {
        let batch = tokio::select! {
            () = token.cancelled() => return CloseReason::Shutdown,
            batch = output.recv() => match batch {
                Some(batch) => batch,
                None => return CloseReason::TransportLoss,
            },
        };
        for line in batch.lines {
            if writer.write_all(&line).await.is_err() || writer.write_all(b"\r\n").await.is_err() {
                return CloseReason::TransportLoss;
            }
        }
        if writer.flush().await.is_err() {
            return CloseReason::TransportLoss;
        }
        if let Some(reason) = batch.close {
            let _ = writer.shutdown().await;
            return reason;
        }
    }
}

#[cfg(test)]
mod tests {
    use agenc_ircd_admin::{
        AdminChallenge, AdminCommandTbs, AdminSessionBinding, AdminSessionId, Challenge,
        OperatorRecord, OperatorRegistry, PeerIdentity, TransportBinding, TransportKind,
        encode_base64url, render_admin_tag,
    };
    use agenc_ircd_crypto::Ed25519SecretKey;
    use agenc_ircd_types::{AdminPermission, AdminPermissionSet, NetworkId, OperatorId, ServerId};

    use super::*;
    use crate::RuntimeError;
    use crate::clock::{SystemMonotonicClock, SystemWallClock};
    use crate::state_core::admin_core_channel;

    fn registry() -> Result<OperatorRegistry, RuntimeError> {
        let mut permissions = AdminPermissionSet::EMPTY;
        permissions.insert(AdminPermission::Observe);
        let record = OperatorRecord::new(
            OperatorId::from_bytes([7; 16]),
            Ed25519SecretKey::from_bytes([8; 32]).public_key(),
            None,
            vec![1000],
            Vec::new(),
            permissions,
            true,
        )
        .map_err(|_| RuntimeError::InvalidValue)?;
        OperatorRegistry::from_records(vec![record]).map_err(|_| RuntimeError::InvalidValue)
    }

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

    fn oper_line() -> Result<Vec<u8>, RuntimeError> {
        let operator = OperatorId::from_bytes([7; 16]);
        let signature = challenge()
            .sign_oper(
                binding().network_id,
                binding().server_id,
                &Ed25519SecretKey::from_bytes([8; 32]),
            )
            .map_err(|_| RuntimeError::InvalidValue)?;
        Ok(format!(
            "OPER {} {}\r\n",
            operator.to_base64url(),
            encode_base64url(signature.as_bytes())
        )
        .into_bytes())
    }

    fn signed_line(counter: u64, command: &str) -> Result<Vec<u8>, RuntimeError> {
        let tbs = AdminCommandTbs::new(
            binding().network_id,
            binding().server_id,
            challenge().session_id(),
            counter,
            None,
            command.as_bytes(),
        )
        .map_err(|_| RuntimeError::InvalidValue)?;
        let signature = tbs
            .sign(&Ed25519SecretKey::from_bytes([8; 32]))
            .map_err(|_| RuntimeError::InvalidValue)?;
        Ok(format!(
            "{} {command}\r\n",
            render_admin_tag(counter, &signature, None)
        )
        .into_bytes())
    }

    #[tokio::test]
    async fn owner_answers_only_bounded_pre_auth_liveness() -> Result<(), RuntimeError> {
        let (port, inbox) = admin_transport_channel(binding());
        let root = CancellationToken::root();
        let admission = AdminAdmissionSnapshot::new(vec![1000], Vec::new(), Vec::new());
        let (core, _core_inbox) = admin_core_channel();
        let owner = tokio::spawn(
            AdminOwner::new(
                binding(),
                registry()?,
                admission,
                AuditAuthority::empty_for_test()?,
                core,
                AdminOwnerClocks {
                    monotonic: Box::new(SystemMonotonicClock::start()),
                    wall: Box::new(SystemWallClock),
                },
            )
            .run(inbox, root.clone()),
        );
        let (sender, mut output) = mpsc::channel(ADMIN_OUTPUT_CAPACITY);
        port.opened(
            ConnectionGeneration::new(1),
            challenge(),
            PeerIdentity::Local {
                uid: 1000,
                gid: 1000,
            },
            AdminOutput { sender },
            &root,
        )
        .await
        .map_err(|_| RuntimeError::InvalidValue)?;
        let challenge = output.recv().await.ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(challenge.lines.len(), 1);
        assert!(
            challenge
                .lines
                .first()
                .is_some_and(|line| line.starts_with(b"NOTE OPER CHALLENGE "))
        );
        port.line(
            ConnectionGeneration::new(1),
            b"PING token\r\n".to_vec(),
            &root,
        )
        .await
        .map_err(|_| RuntimeError::InvalidValue)?;
        let pong = output.recv().await.ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(pong.lines, vec![b"PONG :token".to_vec()]);
        root.cancel();
        owner.await.map_err(|_| RuntimeError::Cancelled)?;
        Ok(())
    }

    #[tokio::test]
    async fn reader_rejects_lf_only_and_overlong_frames() {
        let (port, _inbox) = admin_transport_channel(binding());
        let root = CancellationToken::root();
        let reason = run_admin_reader(
            &b"PING x\n"[..],
            ConnectionGeneration::new(1),
            port.clone(),
            root.clone(),
        )
        .await;
        assert_eq!(reason, CloseReason::ProtocolError);
        let oversized = vec![b'a'; MAX_ADMIN_LINE_BYTES];
        let reason = run_admin_reader(
            oversized.as_slice(),
            ConnectionGeneration::new(2),
            port,
            root,
        )
        .await;
        assert_eq!(reason, CloseReason::ProtocolError);
    }

    #[tokio::test]
    async fn observed_output_waits_for_the_durable_audit_reply() -> Result<(), RuntimeError> {
        let (port, inbox) = admin_transport_channel(binding());
        let (core, mut core_inbox) = admin_core_channel();
        let root = CancellationToken::root();
        let owner = tokio::spawn(
            AdminOwner::new(
                binding(),
                registry()?,
                AdminAdmissionSnapshot::new(vec![1000], Vec::new(), Vec::new()),
                AuditAuthority::empty_for_test()?,
                core,
                AdminOwnerClocks {
                    monotonic: Box::new(SystemMonotonicClock::start()),
                    wall: Box::new(SystemWallClock),
                },
            )
            .run(inbox, root.clone()),
        );
        let (sender, mut output) = mpsc::channel(ADMIN_OUTPUT_CAPACITY);
        port.opened(
            ConnectionGeneration::new(9),
            challenge(),
            PeerIdentity::Local {
                uid: 1000,
                gid: 1000,
            },
            AdminOutput { sender },
            &root,
        )
        .await
        .map_err(|_| RuntimeError::InvalidValue)?;
        let _challenge = output.recv().await.ok_or(RuntimeError::InvalidValue)?;
        port.line(ConnectionGeneration::new(9), oper_line()?, &root)
            .await
            .map_err(|_| RuntimeError::InvalidValue)?;
        port.line(ConnectionGeneration::new(9), signed_line(0, "MOTD")?, &root)
            .await
            .map_err(|_| RuntimeError::InvalidValue)?;
        tokio::task::yield_now().await;
        assert!(output.try_recv().is_err());

        let event = core_inbox
            .complete_next_for_test(Ok(()))
            .await
            .ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(event.tbs().phase, AdminAuditPhase::Observed);
        assert_eq!(event.tbs().command_tbs.canonical_command(), b"MOTD");
        let reply = output.recv().await.ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(reply.lines, vec![b"422 * :MOTD File is missing".to_vec()]);
        root.cancel();
        owner.await.map_err(|_| RuntimeError::Cancelled)?;
        Ok(())
    }
}
