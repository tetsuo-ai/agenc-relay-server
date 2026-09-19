#![forbid(unsafe_code)]

//! Requests the edge refuses to build, defer or transmit, and what each refusal leaves behind.

use super::super::request::PendingKind;
use super::*;
use agenc_ircd_client_wire::ParsedMessage;
use agenc_ircd_domain::DomainError;
use agenc_ircd_types::FederationOpcode;

pub(super) const CONNECTION: ConnectionGeneration = ConnectionGeneration::new(1);

fn sealed_envelope_of(kind: agenc_ircd_types::AccountServiceMessageKind) -> TestResult<Vec<u8>> {
    let private = agenc_ircd_crypto::AccountHpkePrivateKey::from_bytes([40; 32])?;
    let public = private.public_key()?;
    let binding = agenc_ircd_crypto::AccountRequestBinding::new(
        NETWORK,
        COORDINATOR_EPOCH,
        public.key_id(),
        RequestId::from_bytes([61; 16]),
        kind,
    );
    let (sealed, _) = agenc_ircd_crypto::seal_account_request(
        public,
        binding,
        &[0; agenc_ircd_crypto::ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES],
    )?;
    Ok(
        agenc_ircd_auth::AccountServiceEnvelope::from_sealed(sealed)?
            .as_bytes()
            .to_vec(),
    )
}

pub(super) fn sealed_envelope() -> TestResult<Vec<u8>> {
    sealed_envelope_of(agenc_ircd_types::AccountServiceMessageKind::OpaqueAuthStart)
}

/// An active edge whose one connection holds an acknowledged, registered origin.
pub(super) fn registered_edge(context: &mut StateCoreContext) -> TestResult<EdgeFederation> {
    let mut edge = resync_edge();
    edge.phase = Phase::Active;
    edge.connection_opened(context, CONNECTION);
    let origin = edge.origins.get_mut(&CONNECTION).ok_or("origin")?;
    origin.generation = 1;
    origin.previous_object_id = [40; 32];
    origin.acked_generation = Some(1);
    origin.ever_acked = true;
    origin.session = Some((
        SessionId::from_bytes([41; 16]),
        UserId::from_bytes([42; 16]),
    ));
    origin.pending_updates.clear();
    Ok(edge)
}

fn parsed(line: &str) -> TestResult<Box<ParsedMessage>> {
    Ok(Box::new(
        parse_message(FramedLine::new(line)?)?.ok_or("empty line")?,
    ))
}

pub(super) fn command(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    line: &str,
) -> TestResult<Result<(), DomainError>> {
    let message = parsed(line)?;
    let proof = agenc_ircd_client_wire::validate_post_registration_command(&message)?;
    Ok(request::send_command(
        edge,
        context,
        CONNECTION,
        agenc_ircd_client_wire::RegisteredCommandKind::Public(proof.kind()),
        message,
    )
    .map_err(|(_, error)| error))
}

fn carrier(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    opcode: FederationOpcode,
    envelope: &[u8],
) -> Result<(), Violation> {
    request::send_account_carrier(edge, context, CONNECTION, opcode, envelope, false, 3)
}

#[tokio::test]
async fn a_carrier_is_refused_unless_the_link_is_active_and_the_journal_is_settled() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let context = fixture.context_mut()?;
    let envelope = sealed_envelope()?;
    let mut edge = registered_edge(context)?;
    edge.phase = Phase::Origins;
    assert_eq!(
        carrier(
            &mut edge,
            context,
            FederationOpcode::OpaqueAuthStart,
            &envelope
        ),
        Err(Violation::Phase)
    );
    edge.phase = Phase::Active;
    edge.journal.retry.recovering = true;
    assert_eq!(
        carrier(
            &mut edge,
            context,
            FederationOpcode::OpaqueAuthStart,
            &envelope
        ),
        Err(Violation::Phase)
    );
    assert!(edge.pending.is_empty());
    assert!(edge.deferred_carriers.is_empty());
    assert_eq!(edge.origins.get(&CONNECTION).ok_or("origin")?.sequence, 0);
    Ok(())
}

#[tokio::test]
async fn a_carrier_that_is_not_an_account_envelope_is_a_codec_violation() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut edge = registered_edge(context)?;
    assert_eq!(
        carrier(
            &mut edge,
            context,
            FederationOpcode::OpaqueAuthStart,
            &[0xff; 9]
        ),
        Err(Violation::Codec)
    );
    assert!(edge.pending.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_credential_change_needs_an_authenticated_live_session() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let context = fixture.context_mut()?;
    let envelope =
        sealed_envelope_of(agenc_ircd_types::AccountServiceMessageKind::CredentialChangeStart)?;
    let mut edge = registered_edge(context)?;
    let opcode = FederationOpcode::CredentialChangeStart;
    assert_eq!(
        carrier(&mut edge, context, opcode, &envelope),
        Err(Violation::Phase),
        "the session has no account"
    );
    let origin = edge.origins.get_mut(&CONNECTION).ok_or("origin")?;
    origin.account = Some((
        agenc_ircd_types::AccountId::from_random(agenc_ircd_types::AccountRandomId::from_bytes(
            [43; 16],
        )),
        1,
    ));
    origin.deleted = true;
    assert_eq!(
        carrier(&mut edge, context, opcode, &envelope),
        Err(Violation::Phase),
        "the origin is already deleted"
    );
    assert!(edge.pending.is_empty());
    let origin = edge.origins.get_mut(&CONNECTION).ok_or("origin")?;
    origin.deleted = false;
    assert_eq!(carrier(&mut edge, context, opcode, &envelope), Ok(()));
    let pending = edge.pending.values().next().ok_or("pending")?;
    assert!(matches!(
        pending.kind,
        PendingKind::AccountCarrier {
            sasl: false,
            finish: false,
            carrier_generation: 3,
        }
    ));
    Ok(())
}

#[tokio::test]
async fn a_carrier_for_a_deleted_origin_is_refused_instead_of_held() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut edge = registered_edge(context)?;
    edge.session_bound(context, CONNECTION);
    let origin = edge.origins.get_mut(&CONNECTION).ok_or("origin")?;
    assert_eq!(origin.pending_updates.len(), 1);
    origin.deleted = true;
    assert_eq!(
        carrier(
            &mut edge,
            context,
            FederationOpcode::OpaqueAuthStart,
            &sealed_envelope()?
        ),
        Err(Violation::Phase)
    );
    assert!(edge.deferred_carriers.is_empty());
    assert!(edge.pending.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_session_open_names_its_refusal_and_consumes_no_sequence() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut edge = registered_edge(context)?;
    let mut open = |edge: &mut EdgeFederation, connection, nickname| {
        request::send_session_open(
            edge, context, connection, 1, nickname, "Real", [1; 32], None,
        )
    };
    assert_eq!(
        open(&mut edge, ConnectionGeneration::new(9), "nick"),
        Err(Violation::Phase)
    );
    assert_eq!(
        open(&mut edge, CONNECTION, "not a nick"),
        Err(Violation::Codec)
    );
    edge.journal.retry.recovering = true;
    assert_eq!(open(&mut edge, CONNECTION, "nick"), Err(Violation::Ceiling));
    assert!(edge.pending.is_empty());
    assert_eq!(edge.origins.get(&CONNECTION).ok_or("origin")?.sequence, 0);
    assert_eq!(edge.counters.requests_sent, 0);
    Ok(())
}

#[tokio::test]
async fn an_exhausted_operation_sequence_refuses_the_request() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut edge = registered_edge(context)?;
    edge.origins.get_mut(&CONNECTION).ok_or("origin")?.sequence = u64::MAX;
    assert_eq!(
        command(&mut edge, context, "WHO #bridge")?,
        Err(DomainError::ServerBusy)
    );
    assert!(edge.pending.is_empty());
    assert_eq!(
        edge.origins.get(&CONNECTION).ok_or("origin")?.sequence,
        u64::MAX
    );
    let names = parsed("NAMES #bridge")?;
    assert!(!request::continue_query(
        &mut edge, context, CONNECTION, names, [7; 32]
    ));
    Ok(())
}

#[tokio::test]
async fn a_command_from_an_unregistered_connection_requires_registration() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut edge = registered_edge(context)?;
    edge.origins.get_mut(&CONNECTION).ok_or("origin")?.session = None;
    assert_eq!(
        command(&mut edge, context, "WHO #bridge")?,
        Err(DomainError::RegistrationRequired)
    );
    edge.phase = Phase::Down;
    assert_eq!(
        command(&mut edge, context, "WHO #bridge")?,
        Err(DomainError::ServerBusy)
    );
    assert_eq!(
        command(&mut edge, context, "MODE someone")?,
        Err(DomainError::RegistrationRequired),
        "the local mode read is admitted while down, then needs a session"
    );
    Ok(())
}

#[tokio::test]
async fn a_full_deferred_queue_answers_server_busy() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut edge = registered_edge(context)?;
    edge.origins
        .get_mut(&CONNECTION)
        .ok_or("origin")?
        .join_names_pending = true;
    fill_deferred_query_queue(&mut edge, context, CONNECTION)?;
    assert!(matches!(
        queue_deferred_query(&mut edge, context, CONNECTION)?,
        Err(DomainError::ServerBusy)
    ));
    assert_eq!(
        edge.deferred
            .get(&CONNECTION)
            .map(crate::budget::RetainedQueue::len),
        Some(MAX_DEFERRED_COMMANDS)
    );
    Ok(())
}

#[test]
fn only_a_bare_nickname_mode_line_is_the_local_mode_query() -> TestResult {
    for (line, local) in [
        ("MODE someone", true),
        ("MODE #channel", false),
        ("MODE someone +i", false),
        ("MODE someone :+i", false),
        ("WHO someone", false),
    ] {
        assert_eq!(
            request::is_local_user_mode_query(&*parsed(line)?),
            local,
            "{line}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_directory_query_needs_a_session_and_a_directory_command() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut edge = registered_edge(context)?;
    let cursor = [7; 32];
    let away = parsed("AWAY :gone")?;
    assert!(!request::continue_query(
        &mut edge, context, CONNECTION, away, cursor
    ));
    let unknown = parsed("FROBNICATE now")?;
    assert!(!request::continue_query(
        &mut edge, context, CONNECTION, unknown, cursor
    ));
    let malformed = parsed("NAMES not-a-channel")?;
    assert!(!request::continue_query(
        &mut edge, context, CONNECTION, malformed, cursor
    ));
    edge.origins.get_mut(&CONNECTION).ok_or("origin")?.session = None;
    let names = parsed("NAMES #bridge")?;
    assert!(!request::continue_query(
        &mut edge, context, CONNECTION, names, cursor
    ));
    request::send_names(&mut edge, context, CONNECTION, "#bridge", None);
    assert!(edge.pending.is_empty());
    assert_eq!(edge.counters.requests_sent, 0);
    Ok(())
}

#[tokio::test]
async fn a_join_names_continuation_needs_an_active_link_and_an_unfinished_join() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut edge = registered_edge(context)?;
    let channels = [agenc_ircd_domain::ChannelNameValue::parse("#bridge")?];
    let mut resume = |edge: &mut EdgeFederation| -> TestResult<bool> {
        Ok(request::continue_join_names(
            edge,
            context,
            CONNECTION,
            &channels,
            parsed("JOIN #bridge")?,
            None,
        ))
    };
    assert!(!resume(&mut edge)?, "no join is unfinished");
    let origin = edge.origins.get_mut(&CONNECTION).ok_or("origin")?;
    origin.join_names_pending = true;
    edge.phase = Phase::Origins;
    assert!(!resume(&mut edge)?, "the link is not active");
    edge.phase = Phase::Active;
    let origin = edge.origins.get_mut(&CONNECTION).ok_or("origin")?;
    let session = origin.session.take();
    assert!(!resume(&mut edge)?, "the connection has no session");
    let origin = edge.origins.get_mut(&CONNECTION).ok_or("origin")?;
    origin.session = session;
    origin.sequence = u64::MAX;
    assert!(!resume(&mut edge)?, "the sequence is exhausted");
    assert!(edge.pending.is_empty());
    edge.origins.get_mut(&CONNECTION).ok_or("origin")?.sequence = 4;
    assert!(resume(&mut edge)?);
    assert_eq!(edge.pending.len(), 1);
    Ok(())
}

async fn quiet(queue: &mut LinkQueue) -> bool {
    tokio::time::timeout(std::time::Duration::from_millis(50), queue.recv())
        .await
        .is_err()
}

async fn drain(queue: &mut LinkQueue) -> usize {
    let mut lines = 0_usize;
    while tokio::time::timeout(std::time::Duration::from_millis(20), queue.recv())
        .await
        .is_ok_and(|line| line.is_some())
    {
        lines = lines.saturating_add(1);
    }
    lines
}

#[tokio::test]
async fn origin_traffic_for_a_connection_the_edge_never_opened_sends_nothing() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let mut edge = registered_edge(fixture.context_mut()?)?;
    let mut queue = resync_snapshot_link(&mut edge);
    edge.phase = Phase::Origins;
    commit_edge_batches(&mut edge, &mut fixture).await?;
    drain(&mut queue).await;
    let context = fixture.context_mut()?;
    let stranger = ConnectionGeneration::new(9);
    request::replay_origin(&mut edge, context, stranger);
    request::delete_origin(&mut edge, context, stranger);
    assert!(
        edge.commit.is_none(),
        "nothing was journaled for a stranger"
    );
    assert_eq!(edge.origins.len(), 1);
    assert!(quiet(&mut queue).await);
    Ok(())
}

#[tokio::test]
async fn a_deleted_origin_is_never_declared_again() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let mut edge = registered_edge(fixture.context_mut()?)?;
    let mut queue = resync_snapshot_link(&mut edge);
    edge.phase = Phase::Origins;
    commit_edge_batches(&mut edge, &mut fixture).await?;
    assert!(
        drain(&mut queue).await > 0,
        "the durable origin was declared"
    );
    let context = fixture.context_mut()?;
    request::declare_origin(&mut edge, context, CONNECTION, true);
    assert_eq!(drain(&mut queue).await, 1, "a live origin declares again");
    edge.origins.get_mut(&CONNECTION).ok_or("origin")?.deleted = true;
    request::declare_origin(&mut edge, context, CONNECTION, true);
    assert!(quiet(&mut queue).await);
    Ok(())
}

#[tokio::test]
async fn a_durable_origin_is_not_declared_while_the_link_is_down() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let mut edge = registered_edge(fixture.context_mut()?)?;
    edge.phase = Phase::Down;
    commit_edge_batches(&mut edge, &mut fixture).await?;
    let mut queue = resync_snapshot_link(&mut edge);
    edge.phase = Phase::Down;
    request::declare_origin(&mut edge, fixture.context_mut()?, CONNECTION, true);
    assert!(quiet(&mut queue).await);
    assert!(edge.commit.is_none());
    Ok(())
}

#[tokio::test]
async fn transmit_skips_unknown_answered_and_orphaned_requests() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let mut edge = registered_edge(fixture.context_mut()?)?;
    let mut queue = resync_snapshot_link(&mut edge);
    edge.phase = Phase::Active;
    assert_eq!(
        command(&mut edge, fixture.context_mut()?, "WHO #bridge")?,
        Ok(())
    );
    commit_edge_batches(&mut edge, &mut fixture).await?;
    let request_id = *edge.pending.keys().next().ok_or("request")?;
    assert!(edge.pending.get(&request_id).ok_or("pending")?.sent);
    drain(&mut queue).await;
    let context = fixture.context_mut()?;
    request::transmit(&mut edge, context, RequestId::from_bytes([9; 16]));
    let pending = edge.pending.get_mut(&request_id).ok_or("pending")?;
    pending.sent = false;
    pending.result = Some(ResultArm::NoContent);
    request::transmit(&mut edge, context, request_id);
    let pending = edge.pending.get_mut(&request_id).ok_or("pending")?;
    pending.result = None;
    edge.origins.get_mut(&CONNECTION).ok_or("origin")?.deleted = true;
    request::resend_pending(&mut edge, context);
    assert!(!edge.pending.get(&request_id).ok_or("pending")?.sent);
    assert!(
        quiet(&mut queue).await,
        "none of the three was written to the link"
    );
    Ok(())
}
