//! Companion 11.6 through the production daemons: the coordinator maps
//! `(claiming_account_id, operation_id)` to the exact claim parameters and
//! result, and the mapping survives a coordinator restart. A client that
//! lost the reply to its claim of another account's device asks
//! `CLAIM STATUS` or retries the identical claim and receives the stored
//! result: that device, its package reference and the same object.
#![forbid(unsafe_code)]

use mls_rs::client_builder::MlsConfig;
use mls_rs::time::MlsTime;

use super::real_clients::{self, LEAF_LIFETIME, SUITE};
use super::recovery_submission::{attach_when_active, settle};
use super::stage_ten_drills::wait_for_account_authority;
use super::*;

/// The operation under which alice claims bob's published package.
const CLAIMED: [u8; 16] = [0xC1; 16];
const EMPTY: [u8; 16] = [0xC2; 16];
const FRESH: [u8; 16] = [0xC3; 16];

/// Sends `command` under a fresh label and returns the reply. A refusal
/// while the edge's route state is still syncing changes nothing and is
/// retried; every other reply, a `FAIL` included, is returned.
fn answered(
    client: &mut ArcClient,
    claimant: &mut Principal,
    command: &str,
) -> TestResult<Vec<String>> {
    settle(command, || {
        let label = claimant.label();
        client.send(&format!("@label={label} {command}"))?;
        let reply = labeled_reply(client, &label)?;
        if reply
            .iter()
            .any(|line| line.contains(" FAIL ") && line.contains(" E2EE_SYNCING "))
        {
            return Err(failure(format!("still syncing: {reply:?}")));
        }
        Ok(reply)
    })
}

/// Sends one `EKEY CLAIM PACKAGE` for `target`'s device and returns the
/// reply.
fn claim(
    client: &mut ArcClient,
    claimant: &mut Principal,
    target: &Principal,
    suite: u16,
    operation: [u8; 16],
) -> TestResult<Vec<String>> {
    let command = format!(
        "EKEY CLAIM PACKAGE {} {} {suite} {}",
        base64url_encode(&target.account),
        target.device_token(),
        base64url_encode(&operation)
    );
    answered(client, claimant, &command)
}

/// Sends one `EKEY CLAIM STATUS` for `operation` and returns the reply.
fn status(
    client: &mut ArcClient,
    claimant: &mut Principal,
    operation: [u8; 16],
) -> TestResult<Vec<String>> {
    let command = format!("EKEY CLAIM STATUS {}", base64url_encode(&operation));
    answered(client, claimant, &command)
}

/// One fresh real mls-rs KeyPackage whose leaf opens at `interval.0`.
fn key_package<C: MlsConfig>(
    client: &mls_rs::Client<C>,
    interval: (u64, u64),
) -> TestResult<Vec<u8>> {
    Ok(client
        .generate_key_package_message(
            Default::default(),
            Default::default(),
            Some(MlsTime::from(interval.0)),
        )?
        .to_bytes()?)
}

/// Stops and restarts the coordinator, waits for both edges to link again,
/// and re-attaches both devices; the client sessions stay on their edges.
fn restart_coordinator(
    network: &Network,
    coordinator: &mut DaemonProcess,
    alice: (&mut ArcClient, &mut Principal),
    bob: (&mut ArcClient, &mut Principal),
) -> TestResult {
    let before_a = links_established(&network.edge_a);
    let before_b = links_established(&network.edge_b);
    let status = coordinator.stop()?;
    assert!(
        status.success(),
        "coordinator stopped for the restart: {status}"
    );
    *coordinator = DaemonProcess::start(&network.coordinator.config_path)?;
    wait_for_link(&network.edge_a, before_a)?;
    wait_for_link(&network.edge_b, before_b)?;
    step("alice re-attach", attach_when_active(alice.0, alice.1))?;
    step("bob re-attach", attach_when_active(bob.0, bob.1))
}

#[test]
fn a_claim_keeps_its_target_and_result_across_a_coordinator_restart() -> TestResult {
    super::encrypted_clients::run_network(claims_across_a_restart)
}

fn require_empty(reply: &[String]) -> TestResult {
    let result = result_words(completion_line(reply)?)
        .ok_or_else(|| failure("missing claim completion words"))?;
    assert_eq!(result, ["EKEY", "EMPTY", "PACKAGE"]);
    Ok(())
}

fn claims_across_a_restart(
    network: &Network,
    coordinator: &mut DaemonProcess,
    _edge_a: &mut DaemonProcess,
    _edge_b: &mut DaemonProcess,
) -> TestResult {
    wait_for_link(&network.edge_a, 0)?;
    wait_for_link(&network.edge_b, 0)?;
    wait_for_account_authority(&network.edge_a)?;
    wait_for_account_authority(&network.edge_b)?;
    let now = real_clients::wall_clock_seconds()?;
    let (mut alice, alice_account) =
        authenticated_client(&network.edge_a, "alice", "alice-account", 41)?;
    let (mut bob, bob_account) = authenticated_client(&network.edge_b, "bob", "bob-account", 51)?;
    let mut alice_keys = Principal::new_valid_at(ALICE_ROOT, ALICE_DEVICE, alice_account, now)?;
    let mut bob_keys = Principal::new_valid_at(BOB_ROOT, BOB_DEVICE, bob_account, now)?;
    step(
        "alice attach",
        publish_and_attach(&mut alice, &mut alice_keys),
    )?;
    step("bob attach", publish_and_attach(&mut bob, &mut bob_keys))?;

    let initial_empty = claim(&mut alice, &mut alice_keys, &bob_keys, SUITE, EMPTY)?;
    require_empty(&initial_empty)?;

    // bob publishes one real KeyPackage; alice, another account on another
    // edge, claims it, and the reply names bob's device.
    let interval = (now - 60, now - 60 + LEAF_LIFETIME);
    let joiner = real_clients::mls_rs_client(&bob_keys, interval)?;
    let package = key_package(&joiner, interval)?;
    settle("bob's package", || {
        real_clients::publish_package(&mut bob, &mut bob_keys, &package, interval.1)
    })?;
    let retry = claim(&mut alice, &mut alice_keys, &bob_keys, SUITE, EMPTY)?;
    require_empty(&retry)?;
    let claimed = claim(&mut alice, &mut alice_keys, &bob_keys, SUITE, CLAIMED)?;
    let words = real_clients::claimed_words(&claimed)?;
    assert_eq!(words.get(3), Some(&bob_keys.device_token()), "{claimed:?}");
    let object = batch_object(&claimed)?;
    assert_eq!(
        real_clients::mls_body(&object, ArcWireObjectKind::KeyPackageMls)?,
        package
    );

    step(
        "coordinator restart",
        restart_coordinator(
            network,
            coordinator,
            (&mut alice, &mut alice_keys),
            (&mut bob, &mut bob_keys),
        ),
    )?;

    // alice lost the reply: STATUS and the identical retry both return the
    // stored claim, naming bob's device rather than alice's own.
    let asked = status(&mut alice, &mut alice_keys, CLAIMED)?;
    let retried = claim(&mut alice, &mut alice_keys, &bob_keys, SUITE, CLAIMED)?;
    for (what, reply) in [("status", &asked), ("identical retry", &retried)] {
        assert_eq!(
            real_clients::claimed_words(reply)?,
            words,
            "{what}: {reply:?}"
        );
        assert_eq!(batch_object(reply)?, object, "{what}: {reply:?}");
    }
    let next = key_package(&joiner, interval)?;
    assert_ne!(next, package);
    settle("bob refills his stock", || {
        real_clients::publish_package(&mut bob, &mut bob_keys, &next, interval.1)
    })?;
    let checked = status(&mut alice, &mut alice_keys, EMPTY)?;
    require_empty(&checked)?;
    let retry = claim(&mut alice, &mut alice_keys, &bob_keys, SUITE, EMPTY)?;
    require_empty(&retry)?;
    let conflict = claim(&mut alice, &mut alice_keys, &bob_keys, 3, EMPTY)?;
    let refusal = result_words(completion_line(&conflict)?)
        .ok_or_else(|| failure("missing conflict completion words"))?;
    assert_eq!(
        refusal.join(" "),
        e2ee::wire::reply::E2eeReplyCode::OperationConflict
            .render_fail("EKEY", Some(&base64url_encode(&EMPTY)))
    );
    let new = claim(&mut alice, &mut alice_keys, &bob_keys, SUITE, FRESH)?;
    assert_eq!(
        real_clients::mls_body(&batch_object(&new)?, ArcWireObjectKind::KeyPackageMls)?,
        next
    );
    Ok(())
}
