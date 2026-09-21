//! Local connection closure follows the durable removal of its session.

use agenc_relay_domain::federation::ProjectedEvent;
use agenc_relay_types::FederationOpcode;

use super::{EdgeCompletion, EdgeFederation};
use crate::connection::ConnectionGeneration;
use crate::state_core::StateCoreContext;

pub(super) fn prepare(
    context: &StateCoreContext,
    event: &ProjectedEvent,
) -> Option<ConnectionGeneration> {
    let ProjectedEvent::SessionHidden { source, .. } = event else {
        return None;
    };
    context.sessions().generation_for_user(source.user_id)
}

pub(super) fn committed(
    edge: &mut EdgeFederation,
    generations: impl IntoIterator<Item = ConnectionGeneration>,
) -> Vec<EdgeCompletion> {
    let mut completions = Vec::new();
    for generation in generations {
        let Some(origin) = edge.origins.get_mut(&generation) else {
            continue;
        };
        origin.revoked = true;
        // The initiating client must receive its sealed or account deletion
        // result after the ordered completion covers it, then close.
        let awaiting_result = edge.pending.values().any(|pending| {
            pending.generation == generation
                && matches!(
                    pending.header.opcode,
                    FederationOpcode::CredentialChangeFinish | FederationOpcode::AccountSettings
                )
        });
        if !awaiting_result {
            completions.push(EdgeCompletion::SessionRevoked { generation });
        }
    }
    completions
}
