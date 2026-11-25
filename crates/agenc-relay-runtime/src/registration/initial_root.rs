//! Connection-private discovery and withdrawal of guarded account authority.

use super::*;
use crate::federation::LinkId;
use agenc_relay_types::INITIAL_ROOT_CAPABILITY;

impl ConnectionState {
    pub(super) fn lost_initial_root_link(&self, current: Option<LinkId>) -> bool {
        self.initial_root_edge
            .is_some_and(|link| Some(link) != current)
    }
}

impl RegistrationRouter {
    pub(super) fn initial_root_link(&self) -> Option<LinkId> {
        self.edge
            .as_ref()
            .and_then(EdgeFederation::initial_root_link)
    }

    /// A different authenticated link needs a fresh client connection and explicit opt-in.
    /// An ordinary client never discovers this private capability from a topology change.
    pub(super) fn withdraw_stale_initial_root_clients(&mut self, context: &mut StateCoreContext) {
        let link = self.initial_root_link();
        if self.last_initial_root_link == link {
            return;
        }
        self.last_initial_root_link = link;
        for (&generation, state) in &self.connections {
            if state.lost_initial_root_link(link) {
                if state.registration.capability_state().enabled("cap-notify") {
                    let _queued = self.send_capabilities(
                        context,
                        generation,
                        state,
                        "DEL",
                        false,
                        &[INITIAL_ROOT_CAPABILITY.to_owned()],
                    );
                }
                close_transport(context, generation);
            }
        }
    }

    pub(super) fn registration_message(
        &self,
        context: &StateCoreContext,
        generation: ConnectionGeneration,
        state: &mut ConnectionState,
        message: agenc_relay_client_wire::ParsedMessage,
    ) -> Result<Vec<RegistrationAction>, RegistrationError> {
        let link = self.initial_root_link();
        // If an edge is attached, every carrier routes through it, even on a mixed-role fixture.
        let available = if self.edge.is_some() {
            link.is_some()
        } else {
            self.accounts.is_some()
        };
        let probe = available
            && !state.advertised.contains(INITIAL_ROOT_CAPABILITY)
            && state.registration.capability_state().supports_multiline()
            && message.command() == "CAP"
            && matches!(message.middle(), [verb] if verb == "REQ")
            && message.trailing() == Some(INITIAL_ROOT_CAPABILITY);
        if !probe {
            return state
                .registration
                .message(message, context.now().get(), &state.advertised);
        }
        let profile = context
            .sessions()
            .connection(generation)
            .and_then(|entry| self.initial_root_profiles.for_purpose(entry.purpose()))
            .ok_or(RegistrationError::InvalidCommand)?;
        let mut actions = state.registration.apply_capability_profile(&profile)?;
        state.advertised = profile;
        state.initial_root_edge = link;
        // CAP NEW carries the value under the same link that authorizes the ordinary ACK.
        let mut request =
            state
                .registration
                .message(message, context.now().get(), &state.advertised)?;
        actions
            .try_reserve(request.len())
            .map_err(|_| RegistrationError::AllocationFailed)?;
        actions.append(&mut request);
        Ok(actions)
    }
}
