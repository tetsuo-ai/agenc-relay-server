//! Current base authority and old physical-channel guards during a binding handoff.
#![forbid(unsafe_code)]

use super::*;
use crate::e2ee::coordinator::ops::BindingChannel;
use agenc_relay_types::ServerId;

fn facts(protected: bool, owner: bool) -> TestResult<BindingChannel> {
    Ok(BindingChannel {
        name_hash: agenc_relay_e2ee::route::channel_name_hash(b"#room")?,
        protected,
        owner,
    })
}

fn channel() -> TestResult<(Harness, Group)> {
    let mut h = Harness::new()?;
    let id = h.bind_channel()?;
    operate(&mut h, id, Some(INSTANCE))?;
    let group = h
        .coordinator
        .state
        .conversations
        .get(&id)
        .ok_or("conversation")?;
    let bytes = h
        .coordinator
        .state
        .objects
        .get(&group.binding_object_id)
        .ok_or("package")?
        .to_vec();
    let original = Group {
        conversation: id,
        bytes,
        policies: [h.initial_policy.clone(), h.operational_policy.clone()],
    };
    Ok((h, original))
}

#[tokio::test]
async fn protected_channel_owner_can_renew_at_the_same_instance() -> TestResult {
    let (mut h, original) = channel()?;
    let id = original.conversation;
    let old = ChannelInstanceId::from_bytes(INSTANCE);
    for denied in [facts(true, false)?, facts(false, true)?] {
        h.binding_channels = vec![(old, denied)];
        assert_eq!(
            refusal(reserve_channel(&mut h, INSTANCE)?),
            Some(E2eeReplyCode::GroupConflict)
        );
    }
    h.binding_channels = vec![(old, facts(true, true)?)];
    let grant = ok_reservation(reserve_channel(&mut h, INSTANCE)?)?;
    let (next, target) = advance_to(&original, |_| Ok(()))?;
    approve(&mut h, id, 2, target)?;
    h.binding_channels = vec![(old, facts(true, false)?)];
    assert_eq!(
        code(bind(&mut h, grant, &next)?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    h.binding_channels = vec![(old, facts(true, true)?)];
    install(&mut h, grant, &next, target)?;
    let mut h = sealed_restart(&h).await?;
    traffic(&mut h, id, Some(INSTANCE), 3)?;
    Ok(())
}

#[tokio::test]
async fn retired_channel_keeps_its_guard_and_loses_only_its_former_host() -> TestResult {
    let (mut h, original) = channel()?;
    let id = original.conversation;
    let old = ChannelInstanceId::from_bytes(INSTANCE);
    let new = ChannelInstanceId::from_bytes(SECOND_INSTANCE);
    let losing = ServerId::from_bytes([12; 16]);
    let grant = ok_reservation(reserve_channel(&mut h, SECOND_INSTANCE)?)?;
    let (next, target) = advance_to(&original, |tbs| {
        tbs.channel_instance_id = Opaque::from_slice(&SECOND_INSTANCE)?;
        tbs.route_binding = channel_route_binding(&NETWORK, &SECOND_INSTANCE)?;
        Ok(())
    })?;
    approve(&mut h, id, 2, target)?;
    h.binding_channels = vec![(new, facts(false, true)?), (old, facts(true, true)?)];
    assert_eq!(
        code(bind(&mut h, grant, &next)?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    let mut wrong_name = facts(false, true)?;
    wrong_name.name_hash = agenc_relay_e2ee::route::channel_name_hash(b"#else")?;
    for denied in [facts(false, false)?, facts(true, true)?, wrong_name] {
        h.binding_channels = vec![(new, denied)];
        assert_eq!(
            code(bind(&mut h, grant, &next)?),
            Some(E2eeReplyCode::BindingAuthInvalid)
        );
    }
    h.binding_channels = vec![(new, facts(false, true)?)];
    h.missing_host = Some((losing, new));
    h.coordinator
        .state
        .entitlements
        .set_channel(losing, id, true);
    let out = ok(bind(&mut h, grant, &next)?)?;
    let on_losing: Vec<_> = out
        .events
        .iter()
        .filter(|event| event.planned.target == losing)
        .collect();
    assert!(
        matches!(on_losing.as_slice(), [event] if event.planned.kind == EventKind::RouteStateHidden && event.planned.payload_object_id.is_none())
    );
    assert!(out.events.iter().any(|event| event.planned.target != losing
        && event.planned.kind == EventKind::RouteStateChanged));
    assert!(!h.coordinator.state.entitlements.entitled(losing, &id));
    let mut h = sealed_restart(&h).await?;
    let routes = &h.coordinator.state.routes;
    assert!(routes.channel_route(&old).is_none());
    assert!(!routes.channel_plaintext_allowed(&old));
    assert_eq!(
        routes.channel_route(&new).ok_or("new route")?.binding_id,
        target
    );
    traffic(&mut h, id, Some(SECOND_INSTANCE), 3)?;
    Ok(())
}

#[test]
fn finalized_reinit_retires_the_outstanding_binding_grant_in_its_receipt() -> TestResult {
    let (mut h, old_group) = channel()?;
    let id = old_group.conversation;
    let instance = ChannelInstanceId::from_bytes(INSTANCE);
    h.binding_channels = vec![(instance, facts(true, true)?)];
    let grant = ok_reservation(reserve_channel(&mut h, INSTANCE)?)?;
    let binding = route_of(&h, id)?.binding_id;
    h.finalize_reinit(id)?;
    assert!(
        h.coordinator
            .state
            .reservations
            .for_predecessor(&binding)
            .is_none()
    );
    assert!(
        !h.coordinator
            .state
            .routes
            .reservations()
            .any(|lease| lease.reservation_id.0 == grant)
    );
    let mut reopened = h.reloaded()?;
    assert_eq!(
        refusal(reserve_channel(&mut reopened, INSTANCE)?),
        Some(E2eeReplyCode::GroupConflict)
    );
    Ok(())
}
