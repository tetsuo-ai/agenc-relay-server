#![forbid(unsafe_code)]

//! Retain one projection preimage until its durable transaction commits.

use std::collections::BTreeMap;

use agenc_ircd_domain::e2ee::RouteTable;
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;
use agenc_ircd_types::ChannelInstanceId;

use super::{E2eeEdge, events::Conversation, router::Refusal};
use crate::federation::edge::EdgeFederation;

pub(super) struct ProjectionBefore {
    barrier: Option<[u8; 16]>,
    routes: RouteTable,
    conversations: BTreeMap<[u8; 32], Conversation>,
    route_objects: BTreeMap<[u8; 32], Vec<u8>>,
    channel_names: BTreeMap<ChannelInstanceId, String>,
    echoes: BTreeMap<[u8; 16], Vec<String>>,
}

impl E2eeEdge {
    pub(super) fn begin_projection(&mut self, barrier: Option<[u8; 16]>) -> Result<(), Refusal> {
        if self.projection_before.is_some() {
            return Err(E2eeReplyCode::Syncing.into());
        }
        self.projection_before = Some(ProjectionBefore {
            barrier,
            routes: self.routes.clone(),
            conversations: self.conversations.clone(),
            route_objects: self.route_objects.clone(),
            channel_names: self.channel_names.clone(),
            echoes: self
                .pending
                .iter()
                .map(|(id, pending)| (*id, pending.echo_lines.clone()))
                .collect(),
        });
        Ok(())
    }

    /// Restores speculative changes while preserving recorded witness evidence.
    pub(crate) fn rollback_projection(&mut self) -> bool {
        let Some(before) = self.projection_before.take() else {
            return false;
        };
        self.routes = before.routes;
        self.conversations = before.conversations;
        self.route_objects = before.route_objects;
        self.channel_names = before.channel_names;
        for (id, echoes) in before.echoes {
            if let Some(pending) = self.pending.get_mut(&id) {
                pending.echo_lines = echoes;
            }
        }
        self.barrier_completions.clear();
        self.barrier_pending = None;
        true
    }

    pub(super) fn commit_projection(&mut self) {
        self.projection_before = None;
    }

    /// A link failure may discard pending output while storage still commits.
    pub(super) fn commit_barrier_projection(&mut self, edge: &EdgeFederation) {
        let committed = self
            .projection_before
            .as_ref()
            .and_then(|before| before.barrier)
            .is_some_and(|id| edge.barrier_applied(&id));
        if committed {
            self.commit_projection();
        }
    }
}
