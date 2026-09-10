//! Binding mailbox ingress requires verified participant authority.

#![forbid(unsafe_code)]

use agenc_ircd_e2ee::ObjectId;
use agenc_ircd_e2ee::limits::MAX_BINDING_OBJECT;
use agenc_ircd_e2ee::object::IrcWireObject;
use agenc_ircd_e2ee::objects::conversation::IrcConversationBindingPackage;
use agenc_ircd_e2ee::route::verify_binding_package;
use agenc_ircd_e2ee::tls::{DecodeBudget, TlsDecode};
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;

use super::{Exec, Fail, route};

pub(super) fn admit(
    exec: &Exec<'_>,
    conversation: &[u8; 32],
    object: &IrcWireObject,
    bytes: &[u8],
) -> Result<(), Fail> {
    let account = exec.account_id()?;
    let object_id = ObjectId::compute(bytes);
    if let Some(bound) = exec.coordinator.state.conversations.get(conversation) {
        // BIND verified this exact artifact. A later roster change cannot
        // erase its retained participant approval or authorize a new sender.
        if bound.binding_object_id == *object_id.as_bytes() {
            return participant(bound.principal_accounts.contains(&account));
        }
    }
    let mut budget = DecodeBudget::new(MAX_BINDING_OBJECT, 1 << 16);
    let package = IrcConversationBindingPackage::decode_exact(object.body(), &mut budget)
        .map_err(|_| Fail::from(E2eeReplyCode::BindingAuthInvalid))?;
    let accounts = route::principal_accounts(&package)?;
    participant(accounts.contains(&account))?;
    let rosters = route::rosters_of(exec, &accounts)?;
    let verified = verify_binding_package(&exec.coordinator.network_id, &package, &rosters)
        .map_err(|_| Fail::from(E2eeReplyCode::BindingAuthInvalid))?;
    participant(verified.conversation_id == *conversation && verified.principals.contains(&account))
}

fn participant(approved: bool) -> Result<(), Fail> {
    if !approved {
        return Err(E2eeReplyCode::BindingAuthInvalid.into());
    }
    Ok(())
}
