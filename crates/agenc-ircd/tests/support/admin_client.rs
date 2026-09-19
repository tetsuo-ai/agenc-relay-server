//! Signed local administrative session shared by the Stage 10 campaign and
//! drill tests. Every command is signed with the operator key, so a test can
//! read STATS batches, reload configuration, and stop a node exactly as an
//! operator would over the local admin socket.

#![forbid(unsafe_code)]

use std::io::{self, BufRead, BufReader, Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use agenc_ircd_admin::{
    AdminChallenge, AdminCommandTbs, AdminSessionId, Challenge, ConfirmationToken,
    TransportBinding, TransportKind, decode_fixed_base64url, encode_base64url, render_admin_tag,
};
use agenc_ircd_crypto::Ed25519SecretKey;
use agenc_ircd_types::{NetworkId, OperatorId, ServerId};

type AdminError = Box<dyn std::error::Error + Send + Sync>;
type AdminResult<T = ()> = Result<T, AdminError>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_TRANSCRIPT_LINES: usize = 256;
const BUSY_RETRY: Duration = Duration::from_millis(50);

fn failure(message: impl Into<String>) -> AdminError {
    message.into().into()
}

/// Everything a signed admin session needs about one node.
pub(crate) struct AdminIdentity {
    pub(crate) socket: PathBuf,
    pub(crate) network_id: NetworkId,
    pub(crate) server_id: ServerId,
    pub(crate) operator_id: OperatorId,
    pub(crate) operator_key: Ed25519SecretKey,
}

/// One authenticated local admin session.
pub(crate) struct AdminSession<'a> {
    reader: BufReader<UnixStream>,
    identity: &'a AdminIdentity,
    session_id: AdminSessionId,
    counter: u64,
}

fn connect_socket(path: &Path) -> AdminResult<UnixStream> {
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    loop {
        match UnixStream::connect(path) {
            Ok(stream) => return Ok(stream),
            Err(error) if Instant::now() < deadline => {
                let _transient = error;
                thread::sleep(Duration::from_millis(25));
            }
            Err(error) => return Err(failure(format!("admin listener did not start: {error}"))),
        }
    }
}

fn read_line(reader: &mut BufReader<UnixStream>) -> AdminResult<String> {
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Err(failure("admin transport closed"));
    }
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}

fn read_until(
    reader: &mut BufReader<UnixStream>,
    mut complete: impl FnMut(&str) -> bool,
) -> AdminResult<Vec<String>> {
    let mut lines = Vec::new();
    for _ in 0..MAX_TRANSCRIPT_LINES {
        let line = read_line(reader)?;
        let done = complete(&line);
        lines.push(line);
        if done {
            return Ok(lines);
        }
    }
    Err(failure("admin reply exceeded its transcript bound"))
}

impl<'a> AdminSession<'a> {
    pub(crate) fn connect(identity: &'a AdminIdentity) -> AdminResult<Self> {
        let stream = connect_socket(&identity.socket)?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        let mut reader = BufReader::new(stream);
        let challenge_line = read_line(&mut reader)?;
        let tokens = challenge_line.split_ascii_whitespace().collect::<Vec<_>>();
        if tokens.get(..7).is_none_or(|prefix| {
            prefix.first() != Some(&"NOTE")
                || prefix.get(1) != Some(&"OPER")
                || prefix.get(2) != Some(&"CHALLENGE")
                || prefix.get(5) != Some(&"local")
        }) {
            return Err(failure(format!(
                "unexpected administrative challenge: {challenge_line}"
            )));
        }
        let field = |index: usize, label: &str| -> AdminResult<&str> {
            tokens
                .get(index)
                .copied()
                .ok_or_else(|| failure(format!("challenge {label} missing")))
        };
        let session_id = AdminSessionId::from_bytes(decode_fixed_base64url::<16>(
            field(3, "session")?.as_bytes(),
        )?);
        let challenge =
            Challenge::from_bytes(decode_fixed_base64url::<32>(field(4, "nonce")?.as_bytes())?);
        let binding = TransportBinding::from_bytes(decode_fixed_base64url::<32>(
            field(6, "binding")?.as_bytes(),
        )?);
        let challenge = AdminChallenge::new(session_id, challenge, TransportKind::Local, binding);
        let proof = challenge.sign_oper(
            identity.network_id,
            identity.server_id,
            &identity.operator_key,
        )?;
        let oper = format!(
            "OPER {} {}\r\n",
            identity.operator_id.to_base64url(),
            encode_base64url(proof.as_bytes())
        );
        reader.get_mut().write_all(oper.as_bytes())?;
        reader.get_mut().flush()?;
        Ok(Self {
            reader,
            identity,
            session_id,
            counter: 0,
        })
    }

    fn send(&mut self, command: &str, confirmation: Option<&ConfirmationToken>) -> AdminResult {
        let confirmation_hash = confirmation.map(ConfirmationToken::hash).transpose()?;
        let tbs = AdminCommandTbs::new(
            self.identity.network_id,
            self.identity.server_id,
            self.session_id,
            self.counter,
            confirmation_hash,
            command.as_bytes(),
        )?;
        let signature = tbs.sign(&self.identity.operator_key)?;
        let tag = render_admin_tag(self.counter, &signature, confirmation);
        let line = format!("{tag} {command}\r\n");
        self.reader.get_mut().write_all(line.as_bytes())?;
        self.reader.get_mut().flush()?;
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or_else(|| failure("admin command counter overflow"))?;
        Ok(())
    }

    /// Sends VERSION and returns the numeric 371 line; the reply ends with
    /// the 374 terminator, which is consumed so the session stays in sync.
    pub(crate) fn version(&mut self) -> AdminResult<String> {
        self.send("VERSION", None)?;
        let lines = read_until(&mut self.reader, |line| line.contains(" 374 "))?;
        lines
            .into_iter()
            .find(|line| line.contains(" 371 "))
            .ok_or_else(|| failure("VERSION reply lacks the 371 line"))
    }

    /// Sends one command and returns every line up to and including the first
    /// one `complete` accepts.
    pub(crate) fn command_until(
        &mut self,
        command: &str,
        complete: impl FnMut(&str) -> bool,
    ) -> AdminResult<Vec<String>> {
        self.send(command, None)?;
        read_until(&mut self.reader, complete)
    }

    /// Sends one command and returns every line through the batch end.
    pub(crate) fn command_batch(&mut self, command: &str) -> AdminResult<Vec<String>> {
        // A refused command answers one FAIL line and no batch, so a reader that waits only
        // for the batch end sits until its socket deadline. `FAIL <verb> BUSY` is the
        // daemon's transient refusal, which it gives while its audit commit cannot be
        // admitted; the command is repeated until it is served or the deadline passes.
        let deadline = Instant::now() + IO_TIMEOUT;
        loop {
            self.send(command, None)?;
            let mut in_batch = false;
            let lines = read_until(&mut self.reader, |line| {
                in_batch |= line.starts_with("BATCH +");
                line.starts_with("BATCH -") || (!in_batch && line.starts_with("FAIL "))
            })?;
            let busy = lines.last().is_some_and(|line| {
                let mut words = line.split_ascii_whitespace();
                words.next() == Some("FAIL") && words.nth(1) == Some("BUSY")
            });
            if !busy || Instant::now() >= deadline {
                return Ok(lines);
            }
            thread::sleep(BUSY_RETRY);
        }
    }

    /// Reads one STATS selector into ordered field and value pairs.
    pub(crate) fn stats(&mut self, selector: &str) -> AdminResult<Vec<(String, u64)>> {
        let lines = self.command_batch(&format!("STATS {selector}"))?;
        let mut values = Vec::new();
        for line in &lines {
            let Some((head, _)) = line.split_once(" :") else {
                continue;
            };
            let tokens = head.split_ascii_whitespace().collect::<Vec<_>>();
            let (Some(value), Some(name)) = (
                tokens.last().and_then(|text| text.parse::<u64>().ok()),
                tokens
                    .len()
                    .checked_sub(2)
                    .and_then(|index| tokens.get(index)),
            ) else {
                continue;
            };
            if name
                .chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
            {
                values.push(((*name).to_owned(), value));
            }
        }
        if values.is_empty() {
            return Err(failure(format!(
                "STATS {selector} returned no fields: {lines:?}"
            )));
        }
        Ok(values)
    }

    /// Runs a confirmation-gated command such as DIE.
    pub(crate) fn confirm_process(&mut self, command: &str) -> AdminResult {
        self.send(command, None)?;
        let challenge = read_line(&mut self.reader)?;
        let verb = command.split_ascii_whitespace().next().unwrap_or_default();
        if !challenge.starts_with(&format!("NOTE {verb} CONFIRM ")) {
            return Err(failure(format!(
                "{verb} was not offered for confirmation: {challenge}"
            )));
        }
        let token_text = challenge
            .split_ascii_whitespace()
            .nth(3)
            .ok_or_else(|| failure(format!("confirmation token missing: {challenge}")))?;
        let token = ConfirmationToken::parse(token_text.as_bytes())?;
        self.send(command, Some(&token))?;
        // A committed process action closes the transport; a refusal answers.
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) => Ok(()),
            Ok(_) if line.starts_with("FAIL") => Err(failure(line.trim_end().to_owned())),
            Ok(_) => Ok(()),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::BrokenPipe
                        | io::ErrorKind::UnexpectedEof
                ) =>
            {
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) fn quit(mut self) -> AdminResult {
        self.send("QUIT", None)?;
        let mut byte = [0_u8; 1];
        match self.reader.read(&mut byte) {
            Ok(0) => Ok(()),
            Ok(_) => Err(failure("admin QUIT returned unexpected output")),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
                ) =>
            {
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }
}
