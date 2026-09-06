//! Router glue for remote account carriers (spec 22.2): the coordinator's
//! account service serves an edge client through a virtual connection that
//! speaks the exact carrier grammar, and the captured frames become the
//! federated result the edge relays.

use agenc_ircd_client_wire::{
    FramedLine, ParsedMessage, WireMessage, decode_account_payload, decode_sasl_payload,
    encode_account_payload, encode_sasl_payload, parse_message,
};
use agenc_ircd_types::{AccountId, FederationOpcode};

use crate::account_service::{AccountServiceCoordinator, CarrierCompletion, CarrierRoute};
use crate::connection::ConnectionGeneration;
use crate::federation::codec::results::ResultArm;
use crate::federation::coordinator::{
    FederationCoordinator, InFlightCarrier, RemoteAccountWork, challenge_object,
};
use crate::purpose::ListenerPurpose;
use crate::state_core::StateCoreContext;
use crate::state_core::inbox::SourceAddressKey;

/// The characters of one carrier line's payload (spec 11.4).
const CHUNK_CHARACTERS: usize = 400;
/// The account carrier START and FINISH length token.
const ENVELOPE_LENGTH_TOKEN: &str = "4726";

/// Runs the queued remote account work: opens virtual connections, feeds
/// the carrier lines, and stages grant-backed session opens.
pub(crate) fn drive(
    context: &mut StateCoreContext,
    accounts: &mut AccountServiceCoordinator,
    federation: &mut FederationCoordinator,
) {
    for generation in federation.take_closed_remote_carriers() {
        close_virtual(context, accounts, federation, generation);
    }
    for work in federation.take_remote_account_work() {
        match work {
            RemoteAccountWork::Carrier {
                generation,
                opcode,
                envelope,
                in_flight,
            } => carrier(
                context, accounts, federation, generation, opcode, &envelope, in_flight,
            ),
            RemoteAccountWork::SessionOpen {
                peer,
                link,
                fresh,
                seed,
                grant_id,
            } => session_open(
                context,
                accounts,
                federation,
                (peer, link),
                fresh,
                seed,
                grant_id,
            ),
        }
    }
}

/// Stages a session open whose account a remote grant proves: the grant
/// must belong to a virtual connection of the same edge and still be live.
fn session_open(
    context: &mut StateCoreContext,
    accounts: &mut AccountServiceCoordinator,
    federation: &mut FederationCoordinator,
    origin: (agenc_ircd_types::ServerId, crate::federation::LinkId),
    fresh: Box<crate::federation::coordinator::FreshRequest>,
    seed: Box<agenc_ircd_domain::SessionSeed>,
    grant_id: [u8; 32],
) {
    let (peer, link) = origin;
    let owner = accounts
        .grant_owner(&grant_id)
        .filter(|owner| federation.remote_carrier_peer(*owner) == Some(peer));
    let binding = owner.and_then(|owner| {
        accounts
            .authenticated_binding(owner, context.now())
            .ok()
            .flatten()
            .map(|binding| (owner, binding))
    });
    let Some((owner, (account_id, session_generation))) = binding else {
        federation.refuse_remote_session(context, link, peer, fresh);
        return;
    };
    let mut seed = *seed;
    seed.account_id = Some(account_id);
    seed.account_session_generation = session_generation;
    let consumption = accounts
        .registration_grant_write(owner, context.now())
        .and_then(|write| {
            accounts
                .begin_registration_grant_consumption(context, owner)
                .map(|()| vec![write])
        });
    let Ok(writes) = consumption else {
        federation.refuse_remote_session(context, link, peer, fresh);
        return;
    };
    if federation
        .open_remote_session(context, link, peer, fresh, seed, writes, owner)
        .is_err()
    {
        let _cancelled = accounts.cancel_registration_grant_consumption(context, owner);
        federation.remote_carrier_violation(context, link, peer);
    }
}

/// Applies the batch outcome of a grant-backed session open.
pub(crate) fn batch_settled(
    context: &mut StateCoreContext,
    accounts: &mut AccountServiceCoordinator,
    federation: &mut FederationCoordinator,
) {
    if let Some((generation, user_id)) = federation.take_committed_grant() {
        let _committed = accounts.registration_committed(
            context,
            generation,
            user_id,
            crate::account_service::SessionHome::RemoteEdge,
        );
    }
    if let Some(generation) = federation.take_rejected_grant() {
        let _rejected = accounts.registration_rejected(context, generation);
    }
    for generation in federation.take_closed_remote_carriers() {
        close_virtual(context, accounts, federation, generation);
    }
}

/// Whether `completion` belongs to a virtual connection; when it does, the
/// captured frames become the federated result.
pub(crate) fn completion(
    context: &mut StateCoreContext,
    accounts: &mut AccountServiceCoordinator,
    federation: &mut FederationCoordinator,
    completion: &CarrierCompletion,
) -> bool {
    let generation = completion.generation;
    let Some(opcode) = federation.remote_carrier_opcode(generation) else {
        return federation.remote_carrier_peer(generation).is_some();
    };
    let lines = federation
        .remote_carrier_sink(generation)
        .map(|sink| sink.take_lines())
        .unwrap_or_default();
    let (arm, replies) = if completion.close {
        (busy(), Vec::new())
    } else {
        outcome(context, accounts, generation, opcode, &lines)
    };
    let _answered = federation.finish_remote_carrier(context, generation, arm, replies);
    if completion.close {
        close_virtual(context, accounts, federation, generation);
    }
    true
}

fn close_virtual(
    context: &mut StateCoreContext,
    accounts: &mut AccountServiceCoordinator,
    federation: &mut FederationCoordinator,
    generation: ConnectionGeneration,
) {
    context.forget_remote_account_result(generation);
    accounts.connection_closed(context, generation);
    let _closed = context.sessions_mut().close(generation);
    federation.remote_carrier_closed(generation);
}

// agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one function opens the virtual connection on first use and feeds the exact carrier lines the edge client spoke so every refusal path stays next to the line that caused it
fn carrier(
    context: &mut StateCoreContext,
    accounts: &mut AccountServiceCoordinator,
    federation: &mut FederationCoordinator,
    generation: ConnectionGeneration,
    opcode: FederationOpcode,
    envelope: &[u8],
    in_flight: Box<InFlightCarrier>,
) {
    let carrier_generation = in_flight.carrier_generation;
    if federation
        .remote_carrier_started(context, generation, in_flight)
        .is_err()
    {
        close_virtual(context, accounts, federation, generation);
        return;
    }
    if context.sessions().connection(generation).is_none() {
        let opened = federation
            .remote_carrier_sink(generation)
            .ok_or(())
            .and_then(|sink| {
                let now = context.now();
                context
                    .sessions_mut()
                    .open(
                        generation,
                        ListenerPurpose::ClientTls,
                        SourceAddressKey::onion_listener(),
                        sink,
                        now,
                    )
                    .map_err(|_| ())
            })
            .and_then(|()| {
                accounts
                    .connection_opened(context, generation)
                    .map_err(|_| ())
            });
        if opened.is_err() {
            let _answered =
                federation.finish_remote_carrier(context, generation, busy(), Vec::new());
            let _closed = context.sessions_mut().close(generation);
            federation.remote_carrier_closed(generation);
            return;
        }
    }
    let Some(lines) = carrier_lines(federation, generation, opcode, envelope) else {
        let _answered = federation.finish_remote_carrier(context, generation, busy(), Vec::new());
        return;
    };
    for line in lines {
        let Some(message) = parse_line(&line) else {
            let _answered =
                federation.finish_remote_carrier(context, generation, busy(), Vec::new());
            return;
        };
        let route = match opcode {
            FederationOpcode::OpaqueAuthStart | FederationOpcode::OpaqueAuthFinish => {
                accounts.route_sasl(context, generation, carrier_generation, "*", message)
            }
            _ => accounts.route_account(
                context,
                generation,
                carrier_generation,
                "*",
                agenc_ircd_client_wire::AccountCarrierKind::Create,
                message,
            ),
        };
        match route {
            CarrierRoute::Finished { frames, .. } => {
                let _sent = context.send_to(generation, frames);
            }
            CarrierRoute::Pending => return,
            CarrierRoute::Close => {
                let _answered =
                    federation.finish_remote_carrier(context, generation, busy(), Vec::new());
                close_virtual(context, accounts, federation, generation);
                return;
            }
        }
    }
    // Every line finished synchronously: the transport refused the transfer
    // and its frames are the answer.
    let lines = federation
        .remote_carrier_sink(generation)
        .map(|sink| sink.take_lines())
        .unwrap_or_default();
    let (arm, replies) = outcome(context, accounts, generation, opcode, &lines);
    let _answered = federation.finish_remote_carrier(context, generation, arm, replies);
}

/// The exact carrier lines the edge client spoke, rebuilt from the
/// envelope: the SASL mechanism selection once per virtual connection, or
/// the account carrier START or FINISH header, then the payload chunks and
/// the terminator.
fn carrier_lines(
    federation: &mut FederationCoordinator,
    generation: ConnectionGeneration,
    opcode: FederationOpcode,
    envelope: &[u8],
) -> Option<Vec<String>> {
    let mut lines = Vec::new();
    match opcode {
        FederationOpcode::OpaqueAuthStart | FederationOpcode::OpaqueAuthFinish => {
            if !federation.remote_sasl_started(generation) {
                lines.push("AUTHENTICATE AGENC-OPAQUE".to_owned());
            }
            let encoded = encode_sasl_payload(envelope);
            for chunk in encoded.as_bytes().chunks(CHUNK_CHARACTERS) {
                lines.push(format!("AUTHENTICATE {}", std::str::from_utf8(chunk).ok()?));
            }
            if encoded.len().is_multiple_of(CHUNK_CHARACTERS) {
                lines.push("AUTHENTICATE +".to_owned());
            }
        }
        FederationOpcode::AccountCreateStart | FederationOpcode::AccountCreateFinish => {
            let phase = if opcode == FederationOpcode::AccountCreateStart {
                "START"
            } else {
                "FINISH"
            };
            lines.push(format!("ACCTCREATE {phase} {ENVELOPE_LENGTH_TOKEN}"));
            let encoded = encode_account_payload(envelope);
            for chunk in encoded.as_bytes().chunks(CHUNK_CHARACTERS) {
                lines.push(format!(
                    "ACCTCREATE DATA {}",
                    std::str::from_utf8(chunk).ok()?
                ));
            }
            lines.push("ACCTCREATE END".to_owned());
        }
        _ => return None,
    }
    Some(lines)
}

/// The result of one finished remote carrier, from the frames the account
/// service delivered to the virtual connection.
fn outcome(
    context: &StateCoreContext,
    accounts: &AccountServiceCoordinator,
    generation: ConnectionGeneration,
    opcode: FederationOpcode,
    lines: &[String],
) -> (ResultArm, Vec<WireMessage>) {
    let sasl = matches!(
        opcode,
        FederationOpcode::OpaqueAuthStart | FederationOpcode::OpaqueAuthFinish
    );
    let chunks = payload_chunks(lines, sasl);
    let bytes = if sasl {
        decode_sasl_payload(&chunks.concat())
    } else {
        decode_account_payload(&chunks.concat())
    };
    let replies: Vec<WireMessage> = chunks
        .iter()
        .filter_map(|chunk| chunk_frame(context.server_prefix(), sasl, chunk).ok())
        .collect();
    match opcode {
        FederationOpcode::OpaqueAuthStart | FederationOpcode::AccountCreateStart => {
            match bytes.as_deref().and_then(challenge_object) {
                Some(object) => (ResultArm::AuthChallenge(object), Vec::new()),
                None => (not_allowed(), replies),
            }
        }
        FederationOpcode::OpaqueAuthFinish => match authenticated(context, accounts, generation) {
            Some(arm) => (arm, replies),
            None => (not_allowed(), replies),
        },
        _ => match created(context, lines) {
            Some(arm) => (arm, replies),
            None => (not_allowed(), replies),
        },
    }
}

/// The `authenticated` arm of a virtual connection holding a live grant.
fn authenticated(
    context: &StateCoreContext,
    accounts: &AccountServiceCoordinator,
    generation: ConnectionGeneration,
) -> Option<ResultArm> {
    let (account_id, session_generation, auth_grant_id) =
        accounts.preregistration_grant(generation, context.now())?;
    Some(ResultArm::Authenticated {
        account_id,
        account_session_generation: session_generation.get(),
        auth_grant_id,
    })
}

/// The `account_created` arm when the captured frames name the account.
fn created(context: &StateCoreContext, lines: &[String]) -> Option<ResultArm> {
    let account_id = created_account(lines)?;
    let account_revision = context
        .domain()
        .account(account_id)
        .map_or(0, |account| account.revision().get());
    Some(ResultArm::AccountCreated {
        account_id,
        account_revision,
    })
}

/// The command and middle parameters of one captured line; the virtual
/// connection's lines carry the coordinator's own prefix.
fn captured_parts(line: &str) -> Option<(String, Vec<String>)> {
    let rest = match line.strip_prefix(':') {
        Some(prefixed) => prefixed.split_once(' ')?.1,
        None => line,
    };
    let mut parts = rest.split(' ').filter(|part| !part.is_empty());
    let command = parts.next()?.to_owned();
    let mut middle = Vec::new();
    for part in parts {
        if part.starts_with(':') {
            break;
        }
        middle.push(part.to_owned());
    }
    Some((command, middle))
}

/// The payload chunks of the captured carrier lines, in order.
fn payload_chunks(lines: &[String], sasl: bool) -> Vec<String> {
    lines
        .iter()
        .filter_map(|line| {
            let (command, middle) = captured_parts(line)?;
            if sasl {
                let chunk = middle.first().filter(|_| command == "AUTHENTICATE")?;
                return (chunk.as_str() != "+").then(|| chunk.clone());
            }
            let data =
                command == "ACCTCREATE" && middle.first().map(String::as_str) == Some("DATA");
            data.then(|| middle.get(1).cloned())?
        })
        .collect()
}

fn chunk_frame(prefix: &str, sasl: bool, chunk: &str) -> Result<WireMessage, ()> {
    let frame = if sasl {
        WireMessage::new(prefix, "AUTHENTICATE", &[chunk], None)
    } else {
        WireMessage::new(prefix, "ACCTCREATE", &["DATA", chunk], None)
    };
    frame.map_err(|_| ())
}

/// The account the captured `NOTE ACCTCREATE CREATED` line names.
fn created_account(lines: &[String]) -> Option<AccountId> {
    lines.iter().find_map(|line| {
        let (command, middle) = captured_parts(line)?;
        if command != "NOTE"
            || middle.first().map(String::as_str) != Some("ACCTCREATE")
            || middle.get(1).map(String::as_str) != Some("CREATED")
        {
            return None;
        }
        AccountId::parse(middle.get(2)?).ok()
    })
}

fn busy() -> ResultArm {
    ResultArm::Failed {
        code: "SERVER_BUSY".to_owned(),
        context: String::new(),
    }
}

fn not_allowed() -> ResultArm {
    ResultArm::Failed {
        code: "NOT_ALLOWED".to_owned(),
        context: String::new(),
    }
}

/// Parses one captured or synthesized carrier line.
fn parse_line(line: &str) -> Option<ParsedMessage> {
    let framed = FramedLine::new(line).ok()?;
    parse_message(framed).ok().flatten()
}

/// Builds the same exact arm and payload replies before the account transaction commits.
pub(crate) fn sealed_result(
    prefix: &str,
    opcode: FederationOpcode,
    response: &[u8],
    semantic: Option<ResultArm>,
) -> Result<(ResultArm, Vec<agenc_ircd_federation_wire::SchemaObject>), crate::RuntimeError> {
    if matches!(
        opcode,
        FederationOpcode::OpaqueAuthStart | FederationOpcode::AccountCreateStart
    ) {
        let object = challenge_object(response).ok_or(crate::RuntimeError::InvalidValue)?;
        return Ok((ResultArm::AuthChallenge(object), Vec::new()));
    }
    let sasl = opcode == FederationOpcode::OpaqueAuthFinish;
    let encoded = if sasl {
        encode_sasl_payload(response)
    } else {
        encode_account_payload(response)
    };
    let mut replies = Vec::new();
    for chunk in encoded.as_bytes().chunks(CHUNK_CHARACTERS) {
        let text = std::str::from_utf8(chunk).map_err(|_| crate::RuntimeError::InvalidValue)?;
        let frame =
            chunk_frame(prefix, sasl, text).map_err(|_| crate::RuntimeError::InvalidValue)?;
        replies.push(
            crate::federation::codec::results::reply_object(&frame)
                .map_err(|_| crate::RuntimeError::InvalidValue)?,
        );
    }
    Ok((semantic.unwrap_or_else(not_allowed), replies))
}
