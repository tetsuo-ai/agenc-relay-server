#![forbid(unsafe_code)]

//! Architecture §14.6 against two original, independently authenticated accounts.

use super::*;
use crate::stage_ten_drills::{
    acct_reply, issue_deletion_challenge, quit_and_drain, read_deleted_connection_closure,
};

fn confirm(client: &mut ArcClient) -> TestResult {
    let token = issue_deletion_challenge(client)?;
    client.send(&format!("ACCT DELETE CONFIRM {token}"))
}

fn refuse(client: &mut ArcClient) -> TestResult {
    confirm(client)?;
    let reply = acct_reply(client)?;
    if !reply.contains(" FAIL ACCT BAD_STATE ") {
        return Err(failure(
            "the fixed Direct participant did not receive BAD_STATE",
        ));
    }
    Ok(())
}

fn local_session(network: &Network, party: &Party) -> TestResult<ArcClient> {
    let mut client = ArcClient::connect(&network.coordinator)?;
    client.negotiate_sasl()?;
    client.send_until(
        "CAP REQ :standard-replies agenc.ag/account-controls",
        " CAP * ACK ",
    )?;
    authenticate_live_account(
        &mut client,
        &network.coordinator,
        party.login,
        ACCOUNT_PASSWORD,
        72,
        party.account,
    )?;
    client.complete_registration("direct-local")?;
    Ok(client)
}

#[test]
fn bound_direct_participants_can_delete_only_after_authorized_close() -> TestResult {
    super::super::encrypted_clients::run_network(|network, coordinator, _, _| {
        let (mut creator, mut peer) = attached_pair(network)?;
        let bound = bind_direct(&mut creator, &peer, (0, [0; 32]), None, DIRECT_GROUP)?;
        let terminal = activate_bootstrap_with(
            &mut creator.client,
            &mut creator.keys,
            &bound,
            &[&peer.keys],
        )?;
        step("creator on the bound route", refuse(&mut creator.client))?;
        step("peer on the bound route", refuse(&mut peer.client))?;
        quit_and_drain(&mut creator.client, "reopening the original account")?;
        quit_and_drain(&mut peer.client, "reopening the original account")?;

        let before = links_established(&network.edge_a);
        if !coordinator.stop()?.success() {
            return Err(failure("the coordinator did not stop cleanly"));
        }
        *coordinator = DaemonProcess::start(&network.coordinator.config_path)?;
        wait_for_link(&network.edge_a, before)?;
        let mut local = local_session(network, &peer)?;
        step("peer on the restored fixed pair", refuse(&mut local))?;
        quit_and_drain(&mut local, "returning to the original edge")?;
        step("creator reattaches", rejoin(network, &mut creator))?;
        step("peer reattaches", rejoin(network, &mut peer))?;
        step(
            "both original parties authorize the close",
            close_direct(&mut creator, &mut peer, &bound, (1, terminal)),
        )?;
        for party in [&mut peer, &mut creator] {
            confirm(&mut party.client)?;
            read_deleted_connection_closure(&mut party.client.reader)?;
        }
        Ok(())
    })
}
