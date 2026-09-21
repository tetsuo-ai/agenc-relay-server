//! Reauthorization of completed channel-key work against unchanged targets.
#![forbid(unsafe_code)]

use super::*;
use agenc_relay_domain::{ChannelNameValue, ModeCommand};
use agenc_relay_types::{Generation, Revision};

struct ChannelRevision {
    name: ChannelNameValue,
    revision: Option<(ChannelInstanceId, Revision)>,
}

pub(super) struct DeferredAuthority {
    bound: BoundSession,
    session_generation: Generation,
    channels: Vec<ChannelRevision>,
}

impl DeferredAuthority {
    pub(super) fn capture(
        context: &StateCoreContext,
        bound: BoundSession,
        command: &CanonicalCommand,
    ) -> Result<Self, RuntimeError> {
        let session_generation = context
            .domain()
            .session(bound.user_id)
            .ok_or(RuntimeError::InvalidValue)?
            .generation();
        let mut channels = Vec::new();
        match command.view() {
            CanonicalCommandView::Join(targets) => {
                channels
                    .try_reserve_exact(targets.len())
                    .map_err(|_| RuntimeError::MemoryExhausted)?;
                for target in targets {
                    channels.push(ChannelRevision::capture(context.domain(), target.name()));
                }
            }
            CanonicalCommandView::Mode(ModeCommand::ChannelChange(name, _)) => {
                channels
                    .try_reserve_exact(1)
                    .map_err(|_| RuntimeError::MemoryExhausted)?;
                channels.push(ChannelRevision::capture(context.domain(), name));
            }
            _ => return Err(RuntimeError::InvalidValue),
        }
        Ok(Self {
            bound,
            session_generation,
            channels,
        })
    }

    pub(super) fn finish(
        self,
        context: &StateCoreContext,
        authorized: AuthorizedCommand,
        mut external: ExternalInputs,
    ) -> Result<PlanDecision, SessionCommandError> {
        let session = context
            .domain()
            .session(self.bound.user_id)
            .ok_or_else(|| domain_plan_error(DomainError::NotFound))?;
        if session.generation() != self.session_generation
            || self
                .channels
                .iter()
                .any(|channel| channel.current(context.domain()) != channel.revision)
        {
            return Err(domain_plan_error(DomainError::StaleRevision));
        }
        let (authorized, _) =
            authorize_unmetered_command(context, self.bound, authorized.into_command())?;
        if external.utc_now.is_some() {
            external.utc_now = Some(context.utc_now().map_err(|_| RuntimeError::InvalidValue)?);
        }
        if external.monotonic_now.is_some() {
            external.monotonic_now = Some(context.now());
        }
        context
            .domain()
            .plan_authorized(authorized, Some(external))
            .map_err(domain_plan_error)
    }
}

impl ChannelRevision {
    fn capture(domain: &DomainState, name: &ChannelNameValue) -> Self {
        let mut snapshot = Self {
            name: name.clone(),
            revision: None,
        };
        snapshot.revision = snapshot.current(domain);
        snapshot
    }

    fn current(&self, domain: &DomainState) -> Option<(ChannelInstanceId, Revision)> {
        let id = domain.resolve_channel(&self.name)?;
        Some((id, domain.channel(id)?.revision()))
    }
}
