//! Original account confirmations around committed root and roster publications.
#![forbid(unsafe_code)]

use super::*;
use crate::stage_ten_drills::{
    acct_reply, issue_deletion_challenge, quit_and_drain, read_deleted_connection_closure,
};

fn confirm(client: &mut ArcClient) -> TestResult {
    let token = issue_deletion_challenge(client)?;
    client.send(&format!("ACCT DELETE CONFIRM {token}"))
}

fn pending_root_refusal(client: &mut ArcClient) -> TestResult {
    confirm(client)?;
    assert!(acct_reply(client)?.contains(" FAIL ACCT BAD_STATE "));
    Ok(())
}

#[test]
fn the_root_publisher_can_delete_after_its_first_valid_successor_roster() -> TestResult {
    crate::encrypted_clients::run_network(|network, coordinator, _, _| {
        wait_for_link(&network.edge_a, 0)?;
        wait_for_link(&network.edge_b, 0)?;
        wait_for_account_authority(&network.edge_a)?;
        let login = "root-publisher";
        let (client, id) = authenticated_client(&network.edge_a, "publisher", login, 60)?;
        let mut account = Account {
            client,
            keys: Principal::new(ROOT, DEVICE, id)?,
        };
        let initial = wire_object(ArcWireObjectKind::RootIdentity, &account.keys.keys.root)?;
        account.stored("EKEY PUBLISH IDENTITY", "IDENTITY", &initial)?;
        step(
            "first published root",
            pending_root_refusal(&mut account.client),
        )?;
        quit_and_drain(&mut account.client, "renewing the original login")?;

        account.client = authenticated_session(&network.edge_a, "publisher", login, 70, id)?;
        let original_roster = account.keys.keys.roster.clone();
        account.roster(&original_roster, true)?;
        let next = builders::root(
            &builders::key(NEXT_ROOT),
            &account.keys.account,
            1,
            (0, 2_000_000),
            Some((&account.keys.keys.root_secret, &account.keys.keys.root)),
        )?;
        account.stored(
            "EKEY PUBLISH IDENTITY",
            "IDENTITY",
            &wire_object(ArcWireObjectKind::RootIdentity, &next)?,
        )?;
        step(
            "rotated root with its older roster",
            pending_root_refusal(&mut account.client),
        )?;
        quit_and_drain(&mut account.client, "checking the restored issuer")?;

        let (mut independent, _) =
            authenticated_client(&network.edge_b, "unrelated", "unrelated-login", 80)?;
        confirm(&mut independent)?;
        read_deleted_connection_closure(&mut independent.reader)?;

        let before = links_established(&network.edge_a);
        assert!(coordinator.stop()?.success());
        *coordinator = DaemonProcess::start(&network.coordinator.config_path)?;
        wait_for_link(&network.edge_a, before)?;
        let mut local = ArcClient::connect(&network.coordinator)?;
        local.negotiate_sasl()?;
        local.send_until(
            "CAP REQ :standard-replies agenc.ag/account-controls",
            " CAP * ACK ",
        )?;
        authenticate_live_account(
            &mut local,
            &network.coordinator,
            login,
            ACCOUNT_PASSWORD,
            90,
            id,
        )?;
        local.complete_registration("localroot")?;
        step(
            "restored pending identity",
            pending_root_refusal(&mut local),
        )?;
        quit_and_drain(&mut local, "finishing the original transition")?;

        wait_for_account_authority(&network.edge_a)?;
        account.client = authenticated_session(&network.edge_a, "publisher", login, 100, id)?;
        crate::initial_root_registered::await_directory_account(&mut account.client, id)?;
        step(
            "roster signed by the previous root",
            account.roster(&original_roster, false),
        )?;
        let accepted = roster_under(NEXT_ROOT, &next, 0, [0; 32])?;
        step(
            "first roster signed by the current root",
            account.roster(&accepted, true),
        )?;
        confirm(&mut account.client)?;
        read_deleted_connection_closure(&mut account.client.reader)?;
        Ok(())
    })
}
