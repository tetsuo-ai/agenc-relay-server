//! Companion 8.2, 8.4, 8.5, 11.6 and 14 through the production daemons: an
//! account renews its roster under its root and then rotates its root, and
//! the coordinator admits and refuses its publications alike before and
//! after a restart at each step. A same-root roster and capability
//! statement advance their lineages by exactly one, and a restart keeps the
//! device's capability head that names the replaced roster, so its next
//! statement continues it. A continued root starts both lineages at
//! generation zero, and while it awaits its first roster the account keeps
//! its roster and device, a restart included.
#![forbid(unsafe_code)]

use agenc_relay_testkit::e2ee::objects::identity::{ArcDeviceRoster, ArcRootIdentity};

use super::recovery_submission::{attach_when_active, settle};
use super::stage_ten_drills::wait_for_account_authority;
use super::*;

/// The signing seed of the account's first root.
const ROOT: u8 = 0x71;
/// The signing seed of the account's continued root.
const NEXT_ROOT: u8 = 0x72;
/// The account's device.
const DEVICE: u8 = 0x73;
/// The refusal of a publication that does not continue its lineage.
const REFUSED: &str = "FAIL EKEY E2EE_BINDING_AUTH_INVALID";
/// The interval of every roster, opening inside each certificate's
/// enrollment window.
const ROSTER_INTERVAL: (u64, u64) = (100, 100 + 6 * 24 * 3600);

/// The account's client session on edge A and its keys.
struct Account {
    client: ArcClient,
    keys: Principal,
}

impl Account {
    /// Sends `command`, with `object` attached when given, under a fresh
    /// label and returns the labeled reply. A transitional refusal after a
    /// restart is retried, and any refusal other than a lineage break fails
    /// the test.
    fn request(&mut self, command: &str, object: Option<&[u8]>) -> TestResult<Vec<String>> {
        let Self { client, keys } = self;
        settle(command, || {
            let label = keys.label();
            match object {
                Some(object) => send_object(client, &label, command, object)?,
                None => client.send(&format!("@label={label} {command}"))?,
            }
            let reply = labeled_reply(client, &label)?;
            if reply
                .iter()
                .any(|line| line.contains(" FAIL ") && !line.contains(REFUSED))
            {
                return Err(failure(format!("{command}: {reply:?}")));
            }
            Ok(reply)
        })
    }

    /// Publishes `object` under `command` and requires it stored as `kind`.
    fn stored(&mut self, command: &str, kind: &str, object: &[u8]) -> TestResult {
        let reply = self.request(command, Some(object))?;
        assert_contains(&reply, &format!(" EKEY STORED {kind} "))
    }

    /// Publishes `object` under `command` and requires the lineage refusal.
    fn refused(&mut self, command: &str, object: &[u8]) -> TestResult {
        let reply = self.request(command, Some(object))?;
        assert_contains(&reply, REFUSED)
    }

    /// The command that publishes the device's capability statement.
    fn capabilities_command(&self) -> String {
        format!("EKEY PUBLISH CAPABILITIES {}", self.keys.device_token())
    }

    /// Publishes the roster `roster`, required stored or refused.
    fn roster(&mut self, roster: &ArcDeviceRoster, admitted: bool) -> TestResult {
        let object = wire_object(ArcWireObjectKind::DeviceRoster, roster)?;
        if admitted {
            return self.stored("EKEY PUBLISH ROSTER", "ROSTER", &object);
        }
        self.refused("EKEY PUBLISH ROSTER", &object)
    }

    /// Publishes the device's statement `object`, required stored or
    /// refused.
    fn statement(&mut self, object: &[u8], admitted: bool) -> TestResult {
        let command = self.capabilities_command();
        if admitted {
            return self.stored(&command, "CAPABILITIES", object);
        }
        self.refused(&command, object)
    }

    /// The account's current roster object, as `EKEY FETCH ROSTER` returns
    /// it.
    fn current_roster(&mut self) -> TestResult<Vec<u8>> {
        let account = base64url_encode(&self.keys.account);
        let reply = self.request(&format!("EKEY FETCH ROSTER {account}"), None)?;
        batch_object(&reply)
    }

    /// The reply to `EKEY FETCH CAPABILITIES` from the first page.
    fn page(&mut self) -> TestResult<Vec<String>> {
        let account = base64url_encode(&self.keys.account);
        self.request(&format!("EKEY FETCH CAPABILITIES {account} *"), None)
    }

    /// The objects of the account's current capability page.
    fn current_page(&mut self) -> TestResult<Vec<u8>> {
        let reply = self.page()?;
        batch_object(&reply)
    }
}

/// The device's capability statement of `generation` naming `roster` and
/// the statement `previous`, with its identifier; `suites` tells two
/// statements of one generation apart.
fn statement(
    roster: &ArcDeviceRoster,
    generation: u64,
    previous: [u8; 32],
    suites: Vec<u16>,
) -> TestResult<(Vec<u8>, [u8; 32])> {
    let capabilities =
        builders::capabilities(DEVICE, roster, generation, previous, (200, 3_600), suites)?;
    let identifier = semantic_id_of(SemanticHashDomain::CapabilityId, &capabilities.tbs)?;
    Ok((
        wire_object(ArcWireObjectKind::DeviceCapabilities, &capabilities)?,
        identifier,
    ))
}

/// The roster of `generation` naming `previous` under `root`, signed with
/// the key of `seed`, certifying the device anew for that generation.
fn roster_under(
    seed: u8,
    root: &ArcRootIdentity,
    generation: u64,
    previous: [u8; 32],
) -> TestResult<ArcDeviceRoster> {
    let secret = builders::key(seed);
    let spec = builders::DeviceSpec {
        target_roster_generation: generation,
        ..builders::DeviceSpec::new(DEVICE)
    };
    let certificate = builders::certificate(&secret, root, &spec)?;
    Ok(builders::roster(
        &secret,
        root,
        generation,
        previous,
        ROSTER_INTERVAL,
        vec![certificate],
        Vec::new(),
    )?)
}

/// The next roster under the account's first root, keeping the device's
/// certificate.
fn renewal(keys: &Principal, previous: &ArcDeviceRoster) -> TestResult<ArcDeviceRoster> {
    let certificates = previous
        .tbs
        .active_devices
        .as_slice()
        .iter()
        .map(|entry| entry.certificate.clone())
        .collect();
    Ok(builders::roster(
        &keys.keys.root_secret,
        &keys.keys.root,
        previous.tbs.roster_generation + 1,
        builders::roster_id(previous)?,
        ROSTER_INTERVAL,
        certificates,
        Vec::new(),
    )?)
}

/// Stops and restarts the coordinator, waits for both edges to link again,
/// and re-attaches the device; the client session stays on its edge.
fn restart_coordinator(
    network: &Network,
    coordinator: &mut DaemonProcess,
    account: &mut Account,
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
    attach_when_active(&mut account.client, &mut account.keys)
}

#[test]
fn a_root_rotation_keeps_its_lineages_across_coordinator_restarts() -> TestResult {
    super::encrypted_clients::run_network(rotation_across_restarts)
}

fn rotation_across_restarts(
    network: &Network,
    coordinator: &mut DaemonProcess,
    _edge_a: &mut DaemonProcess,
    _edge_b: &mut DaemonProcess,
) -> TestResult {
    wait_for_link(&network.edge_a, 0)?;
    wait_for_link(&network.edge_b, 0)?;
    wait_for_account_authority(&network.edge_a)?;
    let (client, account_id) = step(
        "session",
        authenticated_client(&network.edge_a, "rotator", "rotator-account", 71),
    )?;
    let mut account = Account {
        client,
        keys: Principal::new(ROOT, DEVICE, account_id)?,
    };
    // The edge answers for the account once its session is the
    // coordinator's.
    let ready = account.request("EKEY WHOAMI", None)?;
    assert_contains(&ready, " EKEY ACCOUNT ")?;
    step(
        "attach",
        publish_and_attach(&mut account.client, &mut account.keys),
    )?;
    let renewed = step(
        "renewal",
        renewal_across_a_restart(network, coordinator, &mut account),
    )?;
    step(
        "rotation",
        rotation_after_a_restart(network, coordinator, &mut account, &renewed),
    )
}

/// The device's statement for the first roster, the roster's same-root
/// renewal and a restart: the head names the replaced roster, the page
/// lists nothing, a reset is refused and the next statement continues the
/// head. Returns the renewed roster and the device's head identifier.
fn renewal_across_a_restart(
    network: &Network,
    coordinator: &mut DaemonProcess,
    account: &mut Account,
) -> TestResult<(ArcDeviceRoster, [u8; 32])> {
    let first_roster = account.keys.keys.roster.clone();
    let (object, first) = statement(&first_roster, 0, [0; 32], vec![1])?;
    account.statement(&object, true)?;
    let renewed = renewal(&account.keys, &first_roster)?;
    account.roster(&renewed, true)?;
    restart_coordinator(network, coordinator, account)?;
    assert_contains(&account.page()?, " EKEY EMPTY CAPABILITIES")?;
    let (reset, _) = statement(&renewed, 0, [0; 32], vec![1])?;
    account.statement(&reset, false)?;
    let (gap, _) = statement(&renewed, 2, first, vec![1])?;
    account.statement(&gap, false)?;
    let (next, second) = statement(&renewed, 1, first, vec![1])?;
    account.statement(&next, true)?;
    assert_eq!(account.current_page()?, next);
    Ok((renewed, second))
}

/// A continued root, a restart while it awaits its first roster, then its
/// first roster and statement at generation zero and a restart that keeps
/// both lineages.
fn rotation_after_a_restart(
    network: &Network,
    coordinator: &mut DaemonProcess,
    account: &mut Account,
    (renewed, head): &(ArcDeviceRoster, [u8; 32]),
) -> TestResult {
    let keys = &account.keys.keys;
    let next_root = builders::root(
        &builders::key(NEXT_ROOT),
        &account.keys.account,
        1,
        (0, 2_000_000),
        Some((&keys.root_secret, &keys.root)),
    )?;
    let object = wire_object(ArcWireObjectKind::RootIdentity, &next_root)?;
    account.stored("EKEY PUBLISH IDENTITY", "IDENTITY", &object)?;
    // The device stays active under the account's roster across a restart.
    restart_coordinator(network, coordinator, account)?;
    assert_eq!(
        account.current_roster()?,
        wire_object(ArcWireObjectKind::DeviceRoster, renewed)?
    );
    let carried = roster_under(NEXT_ROOT, &next_root, 2, builders::roster_id(renewed)?)?;
    account.roster(&carried, false)?;
    let rotated = roster_under(NEXT_ROOT, &next_root, 0, [0; 32])?;
    account.roster(&rotated, true)?;
    let (carried, _) = statement(&rotated, 2, *head, vec![1])?;
    account.statement(&carried, false)?;
    let (object, first) = statement(&rotated, 0, [0; 32], vec![1])?;
    account.statement(&object, true)?;
    restart_coordinator(network, coordinator, account)?;
    let (fork, _) = statement(&rotated, 0, [0; 32], vec![1, 3])?;
    account.statement(&fork, false)?;
    let (next, _) = statement(&rotated, 1, first, vec![1])?;
    account.statement(&next, true)?;
    assert_eq!(account.current_page()?, next);
    Ok(())
}
