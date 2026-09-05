#![forbid(unsafe_code)]

//! The same public object can be submitted for distinct mailbox recipients.

use agenc_ircd_e2ee::ObjectId;
use agenc_ircd_e2ee::wire::assembly::{
    AssemblyKey, Direction, E2eeAssembler, Ingest, QuotaScopes, Sender,
};
use agenc_ircd_e2ee::wire::command::EkeyCommand;
use agenc_ircd_e2ee::wire::fragment::fragment_object;
use agenc_ircd_types::{AccountId, AccountRandomId};

use super::super::router::request_scope;
use super::*;

fn delivery(account: u8, device: u8) -> TestResult<Resolved> {
    let text = AccountId::from_random(AccountRandomId::from_bytes([account; 16])).to_text();
    Ok(Resolved::Command(ClientCommand::Ekey(
        EkeyCommand::DeliverBinding {
            account: text.as_bytes().try_into()?,
            device_id: [device; 16],
        },
    )))
}

#[test]
fn mailbox_recipient_parameters_separate_recent_object_submissions() -> TestResult {
    let bytes = vec![5; 100];
    let fragments = fragment_object(&bytes)?;
    let fragment = fragments.first().ok_or("fragment")?;
    let mut assembler = E2eeAssembler::default();
    for command in [delivery(1, 1)?, delivery(1, 2)?, delivery(2, 1)?] {
        let carrier = command.carrier().ok_or("carrier")?;
        let key = AssemblyKey {
            direction: Direction::LocalIngress,
            sender: Sender::Connection {
                connection: 1,
                session_generation: 1,
            },
            command: carrier,
            route: request_scope(&command).map_err(|error| error.code.to_string())?,
            scope: None,
            object_id: ObjectId::compute(&bytes),
        };
        assert_eq!(
            assembler.ingest(
                key.clone(),
                QuotaScopes::default(),
                carrier.limit(),
                fragment,
                1
            )?,
            Ingest::Complete(bytes.clone())
        );
        assert_eq!(
            assembler.ingest(key, QuotaScopes::default(), carrier.limit(), fragment, 2)?,
            Ingest::Recent
        );
    }
    Ok(())
}

#[test]
fn local_request_scope_includes_the_opcode_and_authorization() -> TestResult {
    let scope = |command| {
        request_scope(&Resolved::Command(ClientCommand::Ekey(command)))
            .map_err(|error| error.code.to_string())
    };
    assert_ne!(
        scope(EkeyCommand::PublishIdentity)?,
        scope(EkeyCommand::PublishRoster)?
    );
    let text = AccountId::from_random(AccountRandomId::from_bytes([1; 16])).to_text();
    let account: [u8; 24] = text.as_bytes().try_into()?;
    let welcome = |authorization| EkeyCommand::DeliverWelcome {
        account,
        device_id: [1; 16],
        conversation_id: [2; 32],
        authorization_id: [authorization; 32],
    };
    assert_ne!(scope(welcome(3))?, scope(welcome(4))?);
    Ok(())
}
