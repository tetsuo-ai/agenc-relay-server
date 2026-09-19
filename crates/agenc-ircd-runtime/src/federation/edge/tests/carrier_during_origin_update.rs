#![forbid(unsafe_code)]

//! A client is welcomed as soon as its session is bound, before the coordinator acknowledges
//! the origin update that carries the binding. An account carrier sent in that window waits
//! for the acknowledgement; it is neither built under the stale origin nor failed.

use super::super::request::PendingKind;
use super::*;
use agenc_ircd_types::FederationOpcode;

fn sasl_envelope() -> TestResult<Vec<u8>> {
    // The edge forwards this sealed envelope as opaque bytes.
    let private = agenc_ircd_crypto::AccountHpkePrivateKey::from_bytes([40; 32])?;
    let public = private.public_key()?;
    let binding = agenc_ircd_crypto::AccountRequestBinding::new(
        NETWORK,
        COORDINATOR_EPOCH,
        public.key_id(),
        RequestId::from_bytes([61; 16]),
        agenc_ircd_types::AccountServiceMessageKind::OpaqueAuthStart,
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

/// An active edge whose one connection has just been bound to a session.
fn bound_edge(
    context: &mut StateCoreContext,
    connection: ConnectionGeneration,
) -> TestResult<EdgeFederation> {
    let mut edge = resync_edge();
    edge.phase = Phase::Active;
    edge.connection_opened(context, connection);
    let origin = edge.origins.get_mut(&connection).ok_or("origin")?;
    origin.acked_generation = Some(0);
    origin.ever_acked = true;
    origin.object_id = [40; 32];
    origin.session = Some((
        SessionId::from_bytes([41; 16]),
        UserId::from_bytes([42; 16]),
    ));
    edge.session_bound(context, connection);
    assert_eq!(
        edge.origins
            .get(&connection)
            .ok_or("origin")?
            .pending_updates
            .len(),
        1
    );
    Ok(edge)
}

fn acknowledge_update(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    connection: ConnectionGeneration,
) -> TestResult<Vec<EdgeCompletion>> {
    let origin = edge.origins.get(&connection).ok_or("origin")?;
    let update = origin.pending_updates.front().copied().ok_or("update")?;
    let encoded = update.to_object()?.encode_canonical()?;
    let frame = FederationFrame::OriginAck {
        edge_server_id: EDGE,
        server_incarnation: EDGE_INCARNATION,
        origin_id: origin.origin_id,
        generation: update.generation,
        object_id: Some(federation_object_id(encoded.as_slice())),
    };
    edge.handle_frame(context, frame)
        .map_err(|violation| format!("the acknowledgement was refused: {violation:?}").into())
}

#[tokio::test]
async fn a_carrier_sent_during_an_origin_update_waits_for_its_acknowledgement() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let context = fixture.context_mut()?;
    let connection = ConnectionGeneration::new(1);
    let mut edge = bound_edge(context, connection)?;
    let envelope = sasl_envelope()?;

    request::send_account_carrier(
        &mut edge,
        context,
        connection,
        FederationOpcode::OpaqueAuthStart,
        &envelope,
        false,
        3,
    )
    .map_err(|violation| format!("the carrier must be held, not refused: {violation:?}"))?;
    assert!(
        edge.pending.is_empty(),
        "no request is built under the stale origin"
    );
    assert!(edge.deferred_carriers.contains_key(&connection));
    assert!(
        request::send_account_carrier(
            &mut edge,
            context,
            connection,
            FederationOpcode::OpaqueAuthStart,
            &envelope,
            false,
            4,
        )
        .is_err(),
        "one carrier exchange per connection"
    );

    let completions = acknowledge_update(&mut edge, context, connection)?;
    assert!(
        completions.is_empty(),
        "the held carrier is forwarded, not failed to the client"
    );
    assert!(edge.deferred_carriers.is_empty());
    let pending = edge.pending.values().next().ok_or("forwarded carrier")?;
    assert_eq!(edge.pending.len(), 1);
    assert_eq!(pending.header.opcode, FederationOpcode::OpaqueAuthStart);
    assert_eq!(
        pending.header.replay_key.origin_generation, 1,
        "the carrier travels under the acknowledged origin generation"
    );
    assert!(matches!(
        pending.kind,
        PendingKind::AccountCarrier {
            sasl: true,
            finish: false,
            carrier_generation: 3,
        }
    ));
    Ok(())
}

#[tokio::test]
async fn a_closed_connection_drops_its_held_carrier() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let context = fixture.context_mut()?;
    let connection = ConnectionGeneration::new(1);
    let mut edge = bound_edge(context, connection)?;
    request::send_account_carrier(
        &mut edge,
        context,
        connection,
        FederationOpcode::OpaqueAuthStart,
        &sasl_envelope()?,
        false,
        3,
    )
    .map_err(|violation| format!("{violation:?}"))?;
    edge.connection_closed(context, connection, "client quit");
    assert!(edge.deferred_carriers.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_carrier_outside_an_origin_update_is_forwarded_at_once() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let context = fixture.context_mut()?;
    let connection = ConnectionGeneration::new(1);
    let mut edge = bound_edge(context, connection)?;
    assert!(acknowledge_update(&mut edge, context, connection)?.is_empty());
    request::send_account_carrier(
        &mut edge,
        context,
        connection,
        FederationOpcode::OpaqueAuthStart,
        &sasl_envelope()?,
        false,
        3,
    )
    .map_err(|violation| format!("{violation:?}"))?;
    assert!(edge.deferred_carriers.is_empty());
    assert_eq!(edge.pending.len(), 1);
    Ok(())
}
