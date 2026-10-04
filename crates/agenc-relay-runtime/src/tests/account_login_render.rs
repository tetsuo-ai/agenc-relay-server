//! A post-registration login (architecture 11.4): the requester reads its
//! carrier's frames, `903`, then `900`; a guest that gained an account is
//! named to every `account-notify` recipient of the switch with
//! `ACCOUNT <label-or-*>`; a reauthentication repeats `900` alone; and a
//! coordinator's internal carrier for an edge client gets no `900`.
#![forbid(unsafe_code)]

use std::sync::Arc;

use super::*;
use crate::connection::ConnectionGeneration;
use crate::connection::sink::ClientSink;
use crate::test_support::{
    FrameSink, StateCoreFixture, apply_live_plan, bind_live_session, bound,
    negotiated_capabilities, plan_live, seed_account, seed_session,
};
use agenc_relay_domain::{AccountLabelValue, ChannelTarget, PlanDecision};
use agenc_relay_testkit::DomainTestIdentity;

type TestResult<T = ()> = Result<T, Box<dyn core::error::Error>>;

const SERVER: &str = "server.example";

fn mutation(decision: PlanDecision) -> TestResult<MutationPlan> {
    match decision {
        PlanDecision::Mutation(plan) => Ok(plan),
        _ => Err("command was not planned as a mutation".into()),
    }
}

fn join(context: &mut StateCoreContext, identity: DomainTestIdentity) -> TestResult {
    let name = ChannelNameValue::parse("#room")?;
    let plan = mutation(plan_live(context, identity, &|| {
        CanonicalCommand::join(vec![ChannelTarget::new(name.clone(), false)])
    })?)?;
    apply_live_plan(context, plan)
}

/// The prefix this node renders on every line of `user`'s session, which
/// its `900` and `ACCOUNT` lines repeat. It comes from the renderer itself,
/// so the expected lines hold whatever the cloak's visible spelling, and it
/// is checked against the session's deterministic cloak of fixture `seed`:
/// the nickname, then a user field holding the cloak's user component and a
/// host field holding its host component.
fn mask(context: &StateCoreContext, user_id: UserId, nick: &str, seed: u8) -> TestResult<String> {
    let session = context.domain().session(user_id).ok_or("no session")?;
    let mask = session_prefix(session)?;
    let cloak = agenc_relay_testkit::deterministic_cloak(seed)?;
    let (nickname, fields) = mask.split_once('!').ok_or("a mask without a nickname")?;
    let (user, host) = fields.split_once('@').ok_or("a mask without a host")?;
    assert_eq!(nickname, nick);
    assert!(
        user.contains(std::str::from_utf8(cloak.user_component())?),
        "user field {user}"
    );
    assert!(
        host.contains(std::str::from_utf8(cloak.host_component())?),
        "host field {host}"
    );
    Ok(mask)
}

/// The carrier's own last frames: one response chunk and `903`.
fn carrier_frames(target: &str) -> TestResult<Vec<WireMessage>> {
    Ok(vec![
        WireMessage::new(SERVER, "AUTHENTICATE", &["Y2h1bms="], None)?,
        numeric_reply(
            SERVER,
            903,
            target,
            &[],
            Some("SASL authentication successful"),
        )?,
    ])
}

fn carrier_lines(target: &str) -> [String; 2] {
    [
        format!(":{SERVER} AUTHENTICATE Y2h1bms="),
        format!(":{SERVER} 903 {target} :SASL authentication successful"),
    ]
}

/// One account labeled `Kestrel` by a session that already holds it, a guest
/// and two peers in `#room`; the guest (connection 1) and the first peer
/// (connection 2) negotiated `account-notify`, the second peer (connection 3)
/// did not.
struct Room {
    fixture: StateCoreFixture,
    account: (AccountId, agenc_relay_types::Generation),
    guest: DomainTestIdentity,
    sinks: [Arc<FrameSink>; 3],
}

fn room() -> TestResult<Room> {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let context = fixture.context_mut()?;
    let account = seed_account(context, 7, 1)?;
    let holder = seed_session(context, 5, "Holder", Some(account))?;
    let label = mutation(plan_live(context, holder, &|| {
        Ok(CanonicalCommand::account(AccountCommand::Label(Some(
            AccountLabelValue::parse("Kestrel")?,
        ))))
    })?)?;
    apply_live_plan(context, label)?;
    let guest = seed_session(context, 6, "Guest", None)?;
    let notified = seed_session(context, 8, "Notified", None)?;
    let quiet = seed_session(context, 9, "Quiet", None)?;
    for member in [holder, guest, notified, quiet] {
        join(context, member)?;
    }
    let notify = || negotiated_capabilities(&["account-notify"]);
    let sinks = [
        bind_live_session(context, 1, guest, notify()?, true)?,
        bind_live_session(context, 2, notified, notify()?, true)?,
        bind_live_session(context, 3, quiet, negotiated_capabilities(&[])?, true)?,
    ];
    Ok(Room {
        fixture,
        account,
        guest,
        sinks,
    })
}

#[test]
fn a_guest_login_answers_903_then_900_and_names_its_account_to_notify_peers() -> TestResult {
    let mut room = room()?;
    let context = room.fixture.context_mut()?;
    let generation = context
        .domain()
        .session(room.guest.user_id)
        .ok_or("guest")?
        .generation();
    let plan = context.domain().plan_session_account_switch(
        room.guest.user_id,
        generation,
        Some(room.account),
    )?;
    let request = render_account_login(
        context,
        ConnectionGeneration::new(1),
        bound(room.guest),
        room.account.0,
        &plan,
        carrier_frames("Guest")?,
        "Guest",
    )?;
    context.fanout_now(request)?;
    let guest = mask(context, room.guest.user_id, "Guest", 6)?;
    let [chunk, success] = carrier_lines("Guest");
    // The requester negotiated account-notify, so it is named as well.
    assert_eq!(
        room.sinks[0].lines(),
        [
            chunk,
            success,
            format!(":{SERVER} 900 Guest {guest} Kestrel :You are now logged in"),
            format!(":{guest} ACCOUNT Kestrel"),
        ]
    );
    assert_eq!(room.sinks[1].lines(), [format!(":{guest} ACCOUNT Kestrel")]);
    assert!(room.sinks[2].lines().is_empty());
    Ok(())
}

#[test]
fn a_reauthentication_repeats_900_alone() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let context = fixture.context_mut()?;
    let account = seed_account(context, 7, 1)?;
    let owner = seed_session(context, 6, "Owner", Some(account))?;
    let peer = seed_session(context, 8, "Peer", None)?;
    for member in [owner, peer] {
        join(context, member)?;
    }
    let notify = || negotiated_capabilities(&["account-notify"]);
    let owner_sink = bind_live_session(context, 1, owner, notify()?, true)?;
    let peer_sink = bind_live_session(context, 2, peer, notify()?, true)?;
    let plan = context.domain().plan_account_service_checkpoint()?;
    let request = render_account_login(
        context,
        ConnectionGeneration::new(1),
        bound(owner),
        account.0,
        &plan,
        carrier_frames("Owner")?,
        "Owner",
    )?;
    context.fanout_now(request)?;
    let [chunk, success] = carrier_lines("Owner");
    // An account without a public label is named `*`.
    assert_eq!(
        owner_sink.lines(),
        [
            chunk,
            success,
            format!(
                ":{SERVER} 900 Owner {} * :You are now logged in",
                mask(context, owner.user_id, "Owner", 6)?
            ),
        ]
    );
    assert!(peer_sink.lines().is_empty());
    Ok(())
}

#[test]
fn an_internal_carrier_gets_no_900_while_local_peers_learn_the_account() -> TestResult {
    let mut room = room()?;
    let context = room.fixture.context_mut()?;
    // The coordinator's virtual connection for a session an edge homes.
    let carrier = ConnectionGeneration::new(4);
    let carrier_sink = FrameSink::new(carrier, true);
    let now = context.now();
    context
        .sessions_mut()
        .unbind_session(ConnectionGeneration::new(1), bound(room.guest))?;
    context.sessions_mut().open_virtual(
        carrier,
        Arc::clone(&carrier_sink) as Arc<dyn ClientSink>,
        now,
    )?;
    context
        .sessions_mut()
        .bind_virtual_session(carrier, bound(room.guest))?;
    let generation = context
        .domain()
        .session(room.guest.user_id)
        .ok_or("guest")?
        .generation();
    let plan = context.domain().plan_session_account_switch(
        room.guest.user_id,
        generation,
        Some(room.account),
    )?;
    let request = render_account_login(
        context,
        carrier,
        bound(room.guest),
        room.account.0,
        &plan,
        carrier_frames("*")?,
        "*",
    )?;
    context.fanout_now(request)?;
    assert_eq!(carrier_sink.lines(), carrier_lines("*"));
    assert_eq!(
        room.sinks[1].lines(),
        [format!(
            ":{} ACCOUNT Kestrel",
            mask(context, room.guest.user_id, "Guest", 6)?
        )]
    );
    assert!(room.sinks[0].lines().is_empty());
    assert!(room.sinks[2].lines().is_empty());
    Ok(())
}

#[test]
fn a_login_rendering_refuses_a_stale_plan_or_an_absent_account() -> TestResult {
    let mut room = room()?;
    let context = room.fixture.context_mut()?;
    let generation = context
        .domain()
        .session(room.guest.user_id)
        .ok_or("guest")?
        .generation();
    let plan = context.domain().plan_session_account_switch(
        room.guest.user_id,
        generation,
        Some(room.account),
    )?;
    let absent = agenc_relay_testkit::account_id(99);
    assert!(matches!(
        render_account_login(
            context,
            ConnectionGeneration::new(1),
            bound(room.guest),
            absent,
            &plan,
            carrier_frames("Guest")?,
            "Guest",
        ),
        Err(RuntimeError::InvalidValue)
    ));
    let stale = context.domain().plan_account_service_checkpoint()?;
    apply_live_plan(context, plan)?;
    assert!(matches!(
        render_account_login(
            context,
            ConnectionGeneration::new(1),
            bound(room.guest),
            room.account.0,
            &stale,
            carrier_frames("Guest")?,
            "Guest",
        ),
        Err(RuntimeError::InvalidValue)
    ));
    Ok(())
}
