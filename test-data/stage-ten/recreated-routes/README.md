# Route stores written before recreated routes

These files are the restore evidence of plan item G-08 for the server topic
`sdk/b-routes` (SDK program item B-14, outside master #35), recorded in
[the recreated routes record](../../../docs/stage-10-recreated-routes.md).
Governing evidence: G-08 and decision D-06 (storage generation 5); the
rules they exercise are companion Sections 9.4 and 11.4. They support no
conformance claim by themselves.

Each `.rows` file holds the durable rows that a coordinator stored for one
state, as its test harness's logical store held them: one row per line,
`<table id> <key hex> <value hex>`, the value being the plaintext persistent
record before sealing. The tests in
`crates/agenc-relay-runtime/src/e2ee/coordinator/tests/sequence/recreated_routes/earlier_stores.rs`
seal them into a storage fixture of this tree and restore them through the
storage reads a restart uses, and reload them into the coordinator harness
for the requests that follow.

| File | State |
| --- | --- |
| `closed-channel.rows` | The harness channel `#room` bound, its bootstrap activated, its closing transition finalized and the route closed |
| `live-direct.rows` | A direct pair of the harness account and a peer bound at incarnation zero, its bootstrap activated, one application object and one routine Commit |
| `closed-direct.rows` | That pair's closing transition finalized and the route closed |

All three were written by `0825eea8910884fe29a010c2c77cfd1e4ac649cf`, the
server's `main` this topic starts from.

## How the files were written

`git archive 0825eea8910884fe29a010c2c77cfd1e4ac649cf` was extracted into a
scratch directory (not a checkout), where two test-only edits were made: the
module below was added as
`crates/agenc-relay-runtime/src/e2ee/coordinator/tests/sequence/g08_routes.rs`
and declared with `mod g08_routes;` at the end of `tests/sequence.rs`, and
that file's test Commit builder `commit_bytes` takes the conversation's
retained group and concrete route instead of the harness channel's, as this
topic's second commit has it, so the direct conversation's Commits verify.
No production source of that commit changed. The module ran with that
tree's own lockfile and toolchain:

```sh
G08_OUT=<directory> cargo nextest run -p agenc-relay-runtime --lib \
  --all-features --locked --run-ignored only -E 'test(write_g08_route_fixtures)'
```

The output is deterministic: two runs wrote byte-identical files. The
module:

```rust
//! Test-only generator of the G-08 restore fixtures of the recreated routes
//! topic: writes the durable rows this (0825eea) coordinator holds after a
//! direct pair is bound and bootstrapped, after that pair is closed, and
//! after the harness channel is closed. Each file holds one row per line,
//! `<table> <key hex> <value hex>`, in the harness's store order. `G08_OUT`
//! names the output directory.

use std::fmt::Write as _;

use agenc_relay_e2ee::ids::conversation_id;
use agenc_relay_e2ee::objects::aad::ArcApplicationAad;
use agenc_relay_e2ee::objects::conversation::{
    ArcCloseAuthorization, ArcCloseAuthorizationTbs, ArcCloseIntent, ArcMembershipPolicy,
    ArcReservation, ArcSemanticRouteTbs,
};
use agenc_relay_e2ee::tls::{Opaque, TlsDecode, TlsVec};

use super::super::support::{
    BindingSpec, PolicySpec, binding_package, commit_approval, policy, policy_id_of, principal,
    private_message_bytes, root_fingerprint,
};
use super::recovery_pending::close_authorization::finish;
use super::*;
use crate::e2ee::coordinator::tests::{ROOT_SEED, account_bytes, account_param, origin_key};
use crate::state_core::durable::AccountServiceDurableWrite as Write;

const DIRECT_GROUP: [u8; 32] = [35; 32];
const PEER_ROOT_SEED: u8 = 41;
const PEER_DEVICE: u8 = 11;

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn dump(harness: &Harness, name: &str) -> TestResult {
    let dir = std::env::var("G08_OUT")?;
    let mut text = String::new();
    for write in &harness.writes {
        let Write::Put {
            table,
            key,
            plaintext,
        } = write
        else {
            return Err("a delete in the logical store".into());
        };
        let _ = writeln!(
            text,
            "{} {} {}",
            *table as u16,
            hex(key.as_bytes()),
            hex(plaintext)
        );
    }
    std::fs::write(format!("{dir}/{name}.rows"), text)?;
    Ok(())
}

/// Closes `conversation` at `epoch` with its controller's approval.
fn close(harness: &mut Harness, conversation: [u8; 32], epoch: u64) -> TestResult {
    let intent = ArcCloseIntent {
        reason_code: 1,
        validation_time: 30,
    };
    let intent_id = semantic_id_of(SemanticHashDomain::CloseIntentId, &intent)?;
    let terminal = finish(harness, conversation, epoch, Some(intent_id))?;
    let binding = harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("conversation")?
        .binding;
    let tbs = ArcCloseAuthorizationTbs {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: conversation,
        binding_id: binding,
        authorizing_terminal_id: terminal,
        close_intent: intent,
        close_intent_id: intent_id,
    };
    let close = ArcCloseAuthorization {
        approvals: TlsVec::new(vec![commit_approval(
            &harness.principal,
            DEVICE,
            &tbs,
            SignatureDomain::CloseAuthorization,
        )?])?,
        tbs,
    };
    let bytes = wire(ArcWireObjectKind::CloseAuthorization, &close)?;
    let mut parameters = conversation.to_vec();
    parameters.extend_from_slice(&1_u16.to_be_bytes());
    ok(harness.run(Op::CloseGroup, &parameters, Some(&bytes))?)?;
    Ok(())
}

/// The harness account and a peer whose root and roster the origin
/// publishes declared under the peer's account, then back.
fn publish_peer(harness: &mut Harness) -> TestResult<[u8; 24]> {
    let peer_account = account_bytes(10)?;
    let peer = principal(PEER_ROOT_SEED, &peer_account, &[PEER_DEVICE])?;
    let saved = harness
        .coordinator
        .state
        .origins
        .get(&origin_key())
        .cloned()
        .ok_or("origin")?;
    if let Some(origin) = harness.coordinator.state.origins.get_mut(&origin_key()) {
        origin.account_id = Some(peer_account);
        origin.account_digest = Some(agenc_relay_e2ee::ids::account_id_digest(
            &NETWORK,
            &peer_account,
        )?);
        origin.device = None;
    }
    let root = wire(ArcWireObjectKind::RootIdentity, &peer.root)?;
    ok(harness.run(Op::PublishIdentity, &[], Some(&root))?)?;
    let roster = wire(ArcWireObjectKind::DeviceRoster, &peer.roster)?;
    ok(harness.run(Op::PublishRoster, &[], Some(&roster))?)?;
    if let Some(origin) = harness.coordinator.state.origins.get_mut(&origin_key()) {
        origin.account_id = saved.account_id;
        origin.account_digest = saved.account_digest;
        origin.device = saved.device;
    }
    Ok(peer_account)
}

/// Reserves the pair with the peer, binds its incarnation-zero direct group
/// with creator-only policies, publishes them and the leaf proof, and
/// activates the bootstrap; returns the conversation.
fn bind_direct(harness: &mut Harness, peer_account: &[u8; 24]) -> TestResult<[u8; 32]> {
    let reserved = ok(harness.run(Op::ReserveDirect, &account_param(peer_account), None)?)?;
    let ResultBody::Reserved(reservation, _) = reserved.result else {
        return Err("a direct reservation".into());
    };
    let response = reserved.responses.first().ok_or("reservation object")?;
    let mut budget = DecodeBudget::new(1 << 16, 1 << 10);
    let object = agenc_relay_e2ee::object::ArcWireObject::decode_kind(
        &response.bytes,
        Some(ArcWireObjectKind::Reservation),
        &mut budget,
    )?;
    let nonce: [u8; 32] = ArcReservation::decode_exact(object.body(), &mut budget)?
        .tbs
        .conversation_nonce
        .as_slice()
        .try_into()?;
    let principals = [
        principal(ROOT_SEED, &harness.account, &harness.devices)?,
        principal(PEER_ROOT_SEED, peer_account, &[PEER_DEVICE])?,
    ];
    let conversation = conversation_id(&NETWORK, &DIRECT_GROUP)?;
    let mut bootstrap =
        PolicySpec::bootstrap(&principals, conversation, ArcConversationKind::Direct);
    bootstrap.membership = ArcMembershipPolicy::Moderated;
    bootstrap.controllers = vec![0];
    bootstrap.council = vec![(0, DEVICE)];
    bootstrap.approvers = vec![(0, DEVICE)];
    let initial = policy(&bootstrap)?;
    let operational = policy(&bootstrap.successor(policy_id_of(&initial)?))?;
    let route = ArcSemanticRouteTbs {
        profile_version: 1,
        network_id: NETWORK,
        kind: ArcConversationKind::Direct,
        direct_account_a: Opaque::from_slice(&harness.account)?,
        direct_account_b: Opaque::from_slice(peer_account)?,
        canonical_channel_name: Opaque::new(Vec::new())?,
        channel_authority_root_fingerprint: [0; 32],
        semantic_incarnation: 0,
        predecessor_close_id: [0; 32],
    };
    let package = binding_package(&BindingSpec {
        principals: &principals,
        route,
        channel_instance_id: None,
        conversation_nonce: Some(nonce),
        group_id: DIRECT_GROUP,
        generation: 0,
        previous_binding_id: [0; 32],
        lock_sequence: 0,
        plan_devices: vec![
            (&harness.account, root_fingerprint(&principals[0].root)?, DEVICE),
            (peer_account, root_fingerprint(&principals[1].root)?, PEER_DEVICE),
        ],
        initial_policy_id: policy_id_of(&initial)?,
        required_operational_policy_id: policy_id_of(&operational)?,
        sequencer_credential_id: harness.pinned_credential(),
    })?;
    let bytes = wire(ArcWireObjectKind::ConversationBinding, &package)?;
    let mut parameters = reservation.to_vec();
    parameters.extend_from_slice(&conversation);
    parameters.extend_from_slice(&[44; 32]);
    ok(harness.run(Op::BindGroup, &parameters, Some(&bytes))?)?;
    harness.publish_policy(conversation, &initial)?;
    harness.publish_policy(conversation, &operational)?;
    harness.publish_leaf_zero(conversation)?;
    finish(harness, conversation, 0, None)?;
    Ok(conversation)
}

/// One application object on the direct conversation.
fn application(harness: &mut Harness, conversation: [u8; 32]) -> TestResult {
    let state = harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("conversation")?;
    let latest = *harness
        .coordinator
        .state
        .logs
        .get(&conversation)
        .ok_or("log")?
        .accepted_state_id();
    let aad = ArcApplicationAad {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: conversation,
        route_binding: state.route_binding,
        latest_state_id: latest,
    }
    .encode()?;
    let message = wire_raw(
        ArcWireObjectKind::ApplicationMls,
        private_message_bytes(&state.group_id, 1, &aad)?,
    )?;
    ok(harness.run(Op::ApplicationDirect, &conversation, Some(&message))?)?;
    Ok(())
}

#[test]
#[ignore = "writes the G-08 fixtures of sdk/b-routes to G08_OUT"]
fn write_g08_route_fixtures() -> TestResult {
    let mut harness = Harness::new()?;
    let channel = harness.bind_channel()?;
    finish(&mut harness, channel, 0, None)?;
    close(&mut harness, channel, 1)?;
    dump(&harness, "closed-channel")?;

    let mut harness = Harness::new()?;
    harness.publish_identity_and_roster()?;
    harness.attach()?;
    let peer = publish_peer(&mut harness)?;
    let direct = bind_direct(&mut harness, &peer)?;
    application(&mut harness, direct)?;
    finish(&mut harness, direct, 1, None)?;
    dump(&harness, "live-direct")?;
    close(&mut harness, direct, 2)?;
    dump(&harness, "closed-direct")?;
    Ok(())
}
```
