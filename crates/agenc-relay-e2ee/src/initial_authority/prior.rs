//! The terminal of the semantic incarnation a recreated ordinary route
//! follows (companion 9.4: "A later incarnation increments by one and names
//! the semantic close ID of the prior incarnation").

#![forbid(unsafe_code)]

use crate::ids::SemanticId;
use crate::route::{SemanticRoute, is_next_incarnation};

/// The terminal of one closed semantic incarnation: the close that ended
/// it, the binding and conversation it closed, and that binding's semantic
/// route.
///
/// Only [`crate::history::HistoricalChain::prior_terminal`] produces one,
/// from a chain whose lineage a close ended. A chain adopts a close only
/// through [`crate::history::HistoricalChain::close`]: the close must name
/// the chain's network, conversation and binding, reference the
/// finalization of the exact active-to-closing transition at the chain's
/// head, carry the committed close intent, and carry approvals that satisfy
/// the last finalized policy's controller rule (companion 11.5). A chain
/// resumed from retained state ([`crate::history::HistoricalChain::resume`])
/// is trusted exactly as that state is; resumed at its closing state, it
/// verifies a retained close as an opened chain does.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PriorTerminal {
    network_id: [u8; 32],
    conversation_id: SemanticId,
    binding_id: SemanticId,
    route: SemanticRoute,
    close_id: SemanticId,
}

impl PriorTerminal {
    /// The terminal a validated closed chain reached.
    pub(crate) const fn closed(
        network_id: [u8; 32],
        conversation_id: SemanticId,
        binding_id: SemanticId,
        route: SemanticRoute,
        close_id: SemanticId,
    ) -> Self {
        Self {
            network_id,
            conversation_id,
            binding_id,
            route,
            close_id,
        }
    }

    /// Whether `next`, the semantic route of a new group with conversation
    /// `conversation_id` on `network_id`, is the next incarnation of the
    /// route this terminal closed: the same route key, the incarnation after
    /// it, naming exactly this close, in another conversation.
    #[must_use]
    pub fn precedes(
        &self,
        network_id: &[u8; 32],
        conversation_id: &SemanticId,
        next: &SemanticRoute,
    ) -> bool {
        self.network_id == *network_id
            && self.conversation_id != *conversation_id
            && is_next_incarnation(&self.route, self.close_id, next)
    }

    /// The semantic close identifier.
    #[must_use]
    pub const fn close_id(&self) -> &SemanticId {
        &self.close_id
    }

    /// The closed conversation.
    #[must_use]
    pub const fn conversation_id(&self) -> &SemanticId {
        &self.conversation_id
    }

    /// The binding the close named.
    #[must_use]
    pub const fn binding_id(&self) -> &SemanticId {
        &self.binding_id
    }

    /// The semantic route the close ended.
    #[must_use]
    pub const fn route(&self) -> &SemanticRoute {
        &self.route
    }
}
