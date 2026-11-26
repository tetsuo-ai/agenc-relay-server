//! Connection-private discovery and withdrawal of guarded account authority.

use super::*;
use crate::federation::LinkId;
use agenc_relay_types::{
    INITIAL_ROOT_CAPABILITY, INITIAL_ROOT_PROFILE_TOKEN, TERMINAL_ROOT_CAPABILITY,
    TERMINAL_ROOT_PROFILE_TOKEN,
};

impl ConnectionState {
    pub(super) fn lost_initial_root_link(&self, current: Option<LinkId>) -> bool {
        self.initial_root_edge.is_some() && self.initial_root_edge != current
    }
    pub(super) fn lost_terminal_root_link(&self, current: Option<LinkId>) -> bool {
        self.terminal_root_edge.is_some() && self.terminal_root_edge != current
    }
}

impl RegistrationRouter {
    pub(super) fn initial_root_link(&self) -> Option<LinkId> {
        self.edge
            .as_ref()
            .and_then(EdgeFederation::initial_root_link)
    }

    pub(super) fn terminal_root_link(&self) -> Option<LinkId> {
        self.e2ee.as_ref()?;
        self.edge.as_ref()?.terminal_root_link()
    }

    /// A different authenticated link needs a fresh client connection and explicit opt-in.
    /// An ordinary client never discovers this private capability from a topology change.
    pub(super) fn withdraw_stale_initial_root_clients(&mut self, context: &mut StateCoreContext) {
        let link = self.initial_root_link();
        let terminal = self.terminal_root_link();
        if self.last_initial_root_link == link && self.last_terminal_root_link == terminal {
            return;
        }
        self.last_initial_root_link = link;
        self.last_terminal_root_link = terminal;
        for (&generation, state) in &self.connections {
            let lost_initial = state.lost_initial_root_link(link);
            let lost_terminal = state.lost_terminal_root_link(terminal);
            if lost_initial || lost_terminal {
                if state.registration.capability_state().enabled("cap-notify") {
                    let names: Vec<_> = [
                        (lost_initial, INITIAL_ROOT_CAPABILITY),
                        (lost_terminal, TERMINAL_ROOT_CAPABILITY),
                    ]
                    .into_iter()
                    .filter(|(lost, _)| *lost)
                    .map(|(_, name)| name.to_owned())
                    .collect();
                    let _queued =
                        self.send_capabilities(context, generation, state, "DEL", false, &names);
                }
                close_transport(context, generation);
            }
        }
    }

    fn private_root_capability(
        &self,
        state: &ConnectionState,
        requested: Option<&str>,
        link: Option<LinkId>,
        terminal: Option<LinkId>,
    ) -> Option<(&'static str, &'static str)> {
        // If an edge is attached, every carrier routes through it, even on a mixed-role fixture.
        let available = if self.edge.is_some() {
            link.is_some()
        } else {
            self.accounts.is_some()
        };
        match requested {
            Some(INITIAL_ROOT_CAPABILITY) if available => {
                Some((INITIAL_ROOT_CAPABILITY, INITIAL_ROOT_PROFILE_TOKEN))
            }
            Some(TERMINAL_ROOT_CAPABILITY)
                if terminal.is_some()
                    && state
                        .registration
                        .capability_state()
                        .enabled("agenc.ag/e2ee-mls") =>
            {
                Some((TERMINAL_ROOT_CAPABILITY, TERMINAL_ROOT_PROFILE_TOKEN))
            }
            _ => None,
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
        let terminal = self.terminal_root_link();
        let requested = self.private_root_capability(state, message.trailing(), link, terminal);
        let probe = state.registration.capability_state().supports_multiline()
            && message.command() == "CAP"
            && matches!(message.middle(), [verb] if verb == "REQ");
        let Some((name, token)) =
            requested.filter(|(name, _)| probe && !state.advertised.contains(name))
        else {
            return state
                .registration
                .message(message, context.now().get(), &state.advertised);
        };
        let profile = if name == INITIAL_ROOT_CAPABILITY
            && !state.advertised.contains(TERMINAL_ROOT_CAPABILITY)
        {
            context
                .sessions()
                .connection(generation)
                .and_then(|entry| self.initial_root_profiles.for_purpose(entry.purpose()))
                .ok_or(RegistrationError::InvalidCommand)?
        } else {
            let mut specs = state.advertised.capabilities().to_vec();
            specs.push(CapabilitySpec::new(name, Some(&format!("v1.{token}")))?);
            Arc::new(CapabilityProfile::new(specs)?)
        };
        let mut actions = state.registration.apply_capability_profile(&profile)?;
        state.advertised = profile;
        if name == INITIAL_ROOT_CAPABILITY {
            state.initial_root_edge = link;
        } else {
            state.terminal_root_edge = terminal;
        }
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
