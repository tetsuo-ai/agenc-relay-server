//! Ordered tentative application and exact final checkpoint assembly.

use super::super::{EdgeFederation, PendingCommit, Violation, events, join_echo, journal, render};
use super::{EventReceipt, Pending, Refused, backing};
use crate::RuntimeError;
use crate::federation::link::{ReservedFrames, SendRefusal};
use crate::state_core::{StateCoreContext, durable::AccountServiceDurableWrite};
use agenc_ircd_domain::federation::{ProjectedEvent, ProjectionKey};
use agenc_ircd_federation_wire::FederationFrame;
use agenc_ircd_types::RequestId;
use std::collections::{BTreeMap, BTreeSet};

struct Draft {
    receipts: Vec<EventReceipt>,
    coverage: Vec<journal::Version>,
    echoes: Vec<join_echo::JoinEcho>,
    writes: Vec<AccountServiceDurableWrite>,
    keys: BTreeMap<ProjectionKey, bool>,
    completed: BTreeSet<RequestId>,
    fanout: render::EventFanout,
}

pub(super) fn stage(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    count: usize,
) -> Result<(), Refused> {
    if !context.edge_checkpoint_ready() || edge.commit.is_some() {
        return Err(Refused::Busy);
    }
    if edge.event_before.is_some() || edge.barrier.is_open() {
        return Err(Violation::Phase.into());
    }
    let link = edge.live.as_ref().ok_or(Violation::Phase)?.link;
    let permit = backing::reserve(edge, context, count)?;
    let mut selected = Vec::new();
    selected
        .try_reserve_exact(count)
        .map_err(|_| Refused::Resource)?;
    for _ in 0..count {
        selected.push(
            edge.queued_events
                .pop_front()
                .ok_or(Violation::Consistency)?,
        );
    }
    edge.event_before = Some(events::ProjectionBefore {
        replica: edge.replica.clone(),
        nicknames: edge.nicknames.clone(),
    });
    let result = prepare_and_stage(edge, context, &selected);
    match result {
        Ok((draft, acknowledgements)) => {
            drop(selected);
            edge.commit = Some(PendingCommit::OrdinaryBatch(Box::new(Pending {
                staged_after: context.head().storage_commit_sequence,
                link,
                receipts: draft.receipts,
                coverage: draft.coverage,
                echoes: draft.echoes,
                acknowledgements: Some(acknowledgements),
                _backing: permit,
            })));
            Ok(())
        }
        Err(error) => {
            events::restore_projection(edge);
            for event in selected.drain(..).rev() {
                edge.queued_events.push_front(event);
            }
            Err(error)
        }
    }
}

fn prepare_and_stage(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    selected: &[events::QueuedEvent],
) -> Result<(Draft, ReservedFrames), Refused> {
    let revision = context
        .domain()
        .plan_account_service_checkpoint()
        .map_err(|_| Violation::Consistency)?
        .resulting_revision()
        .get();
    let mut draft = Draft {
        receipts: Vec::new(),
        coverage: Vec::new(),
        echoes: Vec::new(),
        writes: Vec::new(),
        keys: BTreeMap::new(),
        completed: BTreeSet::new(),
        fanout: render::EventFanout::default(),
    };
    draft
        .receipts
        .try_reserve_exact(selected.len())
        .map_err(|_| Refused::Resource)?;
    draft
        .coverage
        .try_reserve_exact(selected.len())
        .map_err(|_| Refused::Resource)?;
    draft
        .echoes
        .try_reserve_exact(selected.len())
        .map_err(|_| Refused::Resource)?;
    for selected in selected {
        draft.apply(edge, context, selected, revision)?;
    }
    draft.final_rows(edge, context, revision)?;
    let acknowledgements = reserve_acks(edge, context, &draft.receipts)?;
    let fanout = std::mem::take(&mut draft.fanout).finish()?;
    let writes = std::mem::take(&mut draft.writes);
    context.stage_edge_checkpoint(revision, fanout, writes)?;
    Ok((draft, acknowledgements))
}

impl Draft {
    fn apply(
        &mut self,
        edge: &mut EdgeFederation,
        context: &mut StateCoreContext,
        selected: &events::QueuedEvent,
        revision: u64,
    ) -> Result<(), Refused> {
        let events::QueuedEvent::Base {
            header, projected, ..
        } = selected
        else {
            return Err(Violation::Consistency.into());
        };
        let previous = self
            .receipts
            .last()
            .map(|receipt| receipt.header.delivery_sequence)
            .or_else(|| edge.cursor.map(|cursor| cursor.0));
        let expected = previous.map_or(Some(0), |sequence| sequence.checked_add(1));
        if Some(header.delivery_sequence) != expected
            || header.cross_profile.is_some()
            || header.projection_generation != edge.replica.projection_generation()
        {
            return Err(Violation::Consistency.into());
        }
        let label = render::event_channel_label(edge, projected);
        let outcome = edge
            .replica
            .apply(projected, header.coordinator_state_generation)
            .map_err(|_| Violation::Consistency)?;
        render::remember_nicknames(edge, projected);
        let echo = render::render_event_strict(
            edge,
            context,
            header,
            projected,
            &outcome,
            label.as_deref(),
            &mut self.fanout,
        )
        .map_err(render_refusal)?;
        if let Some(echo) = echo {
            join_echo::validate_tentative(edge, &self.echoes, &echo, &self.completed)?;
            self.echoes.push(echo);
        }
        for key in outcome.upserted {
            self.keys.insert(key, true);
        }
        for key in outcome.removed {
            self.keys.insert(key, false);
        }
        let completion = self.completion(edge, header, projected, revision)?;
        self.receipts.push(EventReceipt {
            header: *header,
            completion,
        });
        Ok(())
    }

    fn completion(
        &mut self,
        edge: &EdgeFederation,
        header: &agenc_ircd_federation_wire::EventHeader,
        projected: &ProjectedEvent,
        revision: u64,
    ) -> Result<Option<RequestId>, Refused> {
        let ProjectedEvent::RequestCompleted {
            resulting_state_generation,
        } = projected
        else {
            return Ok(None);
        };
        let request = events::completion_of(edge, header, *resulting_state_generation)?;
        let Some(request) = request else {
            return Ok(None);
        };
        join_echo::validate_completion(edge, &self.echoes, header)?;
        if !self.completed.insert(request) {
            return Err(Violation::Consistency.into());
        }
        let (coverage, write) = journal::completion_write(edge, header, projected, revision)?;
        self.coverage.push(coverage);
        self.writes.push(write);
        Ok(Some(request))
    }

    fn final_rows(
        &mut self,
        edge: &EdgeFederation,
        context: &StateCoreContext,
        revision: u64,
    ) -> Result<(), Refused> {
        self.writes
            .try_reserve(
                self.keys
                    .len()
                    .checked_add(1)
                    .ok_or(RuntimeError::Overflow)?,
            )
            .map_err(|_| Refused::Resource)?;
        for (key, present) in &self.keys {
            if *present {
                self.writes.push(events::entry_row(edge, key, revision)?);
            } else if let Some(write) = events::removal_write(edge, context, key)? {
                self.writes.push(write);
            }
        }
        let last = self.receipts.last().ok_or(Violation::Consistency)?;
        self.writes.push(edge.peer_row(
            Some((last.header.delivery_sequence, last.header.event_id)),
            revision,
        )?);
        Ok(())
    }
}

fn render_refusal(error: render::EventRenderRefused) -> Refused {
    match error {
        render::EventRenderRefused::Runtime(error) => error.into(),
        render::EventRenderRefused::Protocol(violation) => violation.into(),
    }
}

fn reserve_acks(
    edge: &EdgeFederation,
    context: &StateCoreContext,
    receipts: &[EventReceipt],
) -> Result<ReservedFrames, Refused> {
    let bytes = ReservedFrames::backing_bytes(receipts.len()).map_err(|_| Refused::Resource)?;
    let backing = context.reserve_output_backing(bytes)?;
    let mut lines = Vec::new();
    lines
        .try_reserve_exact(receipts.len())
        .map_err(|_| Refused::Resource)?;
    for receipt in receipts {
        lines.push(
            FederationFrame::Ack {
                coordinator_server_id: edge.config.coordinator.server_id(),
                delivery_sequence: receipt.header.delivery_sequence,
                event_id: receipt.header.event_id,
            }
            .render(&edge.config.server_name)
            .map_err(|_| Violation::Codec)?,
        );
    }
    edge.live
        .as_ref()
        .ok_or(Violation::Phase)?
        .handle
        .reserve_frames(lines, backing)
        .map_err(|error| match error {
            SendRefusal::QueueFull => Refused::Resource,
            SendRefusal::Closed => Refused::Protocol(Violation::Phase),
        })
}
