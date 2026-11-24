//! Prepare reply frames before admission; publish request completion after commit.

use agenc_relay_e2ee::objects::federation::{ArcFederationEvent, ArcFederationResultKind};
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;

use super::router::Refusal;
use super::{ClientOutput, E2eeEdge, PendingRequest, ResultValue};
use crate::state_core::StateCoreContext;

pub(crate) struct PreparedCompletion(Option<LocalCompletion>);

struct LocalCompletion {
    event_id: [u8; 16],
    request_id: [u8; 16],
    generation: crate::connection::ConnectionGeneration,
    request_object_id: [u8; 32],
    answer: Option<PreparedAnswer>,
}

pub(super) enum PreparedAnswer {
    Frames(Vec<String>),
    Stream(Box<super::ClientBatch>),
}

impl E2eeEdge {
    pub(super) fn prepare_completion(
        &self,
        context: &mut StateCoreContext,
        event: &ArcFederationEvent,
    ) -> Result<(PreparedCompletion, Vec<ClientOutput>), Refusal> {
        let request_id = <[u8; 16]>::try_from(event.request_id.as_slice()).ok();
        let pending = request_id
            .and_then(|id| self.pending.get(&id).map(|p| (id, p)))
            .filter(|(_, p)| {
                event.request_home_server_id.as_slice() == self.config.server_id.as_bytes()
                    && event.request_server_incarnation.as_slice() == self.config.incarnation
                    && event.request_origin_generation == p.origin_generation
                    && event.request_operation_sequence == p.sequence
                    && p.transfer.as_ref().is_none_or(|t| {
                        event.request_origin_id.as_slice() == t.correlation.origin_id
                    })
            });
        let Some((request_id, pending)) = pending else {
            return Ok((PreparedCompletion(None), Vec::new()));
        };
        if pending
            .early_completion
            .is_some_and(|id| id != event.event_id)
            || pending
                .result
                .as_ref()
                .is_some_and(|r| r.completion_event_id != Some(event.event_id))
        {
            return Err(E2eeReplyCode::InvalidFragment.into());
        }
        let mut local = LocalCompletion {
            event_id: event.event_id,
            request_id,
            generation: pending.generation,
            request_object_id: pending.request_object_id,
            answer: None,
        };
        let mut outputs = Vec::new();
        if let Some(result) = pending.result.as_ref().filter(|r| {
            r.completion_event_id == Some(event.event_id)
                && !pending.rendered
                && super::result::complete_descriptors(pending, r)
        }) {
            let (answer, eager) = self.prepare_answer(context, pending, result)?;
            local.answer = Some(answer);
            outputs.extend(eager);
        }
        Ok((PreparedCompletion(Some(local)), outputs))
    }

    pub(super) fn commit_completion(
        &mut self,
        context: &mut StateCoreContext,
        completion: PreparedCompletion,
    ) -> Vec<ClientOutput> {
        let Some(local) = completion.0 else {
            return Vec::new();
        };
        let Some(pending) = self.pending.get_mut(&local.request_id).filter(|p| {
            p.generation == local.generation && p.request_object_id == local.request_object_id
        }) else {
            return Vec::new();
        };
        let Some(result) = &pending.result else {
            if pending
                .early_completion
                .is_some_and(|event| event != local.event_id)
            {
                self.link_down();
            } else {
                pending.early_completion = Some(local.event_id);
            }
            return Vec::new();
        };
        if result.completion_event_id != Some(local.event_id) {
            return Vec::new();
        }
        pending.completion_seen = true;
        let released = match local.answer {
            Some(answer) => {
                let Some(mut pending) = self.pending.remove(&local.request_id) else {
                    return Vec::new();
                };
                // Eager frames belong to the admitted event/barrier fanout.
                // A stream is moved only now, after its durable cursor advanced.
                self.release_answer(context, &mut pending, answer, None)
            }
            None => self.render_ready(context, local.request_id),
        };
        released.unwrap_or_else(|_| {
            self.link_down();
            Vec::new()
        })
    }

    pub(super) fn release_answer(
        &mut self,
        context: &StateCoreContext,
        pending: &mut PendingRequest,
        answer: PreparedAnswer,
        eager: Option<ClientOutput>,
    ) -> Result<Vec<ClientOutput>, Refusal> {
        let (lines, output) = match answer {
            PreparedAnswer::Frames(lines) => (lines, eager),
            PreparedAnswer::Stream(batch) => (
                Vec::new(),
                Some(ClientOutput {
                    generation: pending.generation,
                    frames: Vec::new(),
                    batch: Some(batch),
                }),
            ),
        };
        let mut outputs = self.publish_reply(context, pending, &lines)?;
        if let Some(output) = output {
            outputs.insert(0, output);
        }
        Ok(outputs)
    }

    pub(super) fn publish_reply(
        &mut self,
        context: &StateCoreContext,
        pending: &mut PendingRequest,
        lines: &[String],
    ) -> Result<Vec<ClientOutput>, Refusal> {
        let result = pending
            .result
            .as_ref()
            .ok_or(E2eeReplyCode::InvalidFragment)?;
        if let ResultValue::Attached(device, session_generation) = result.value {
            self.attachments
                .push((pending.generation, device, session_generation));
        }
        let reply_lines = if result.kind == ArcFederationResultKind::AcceptedEvent {
            pending.echo_lines.clone()
        } else {
            lines.to_vec()
        };
        self.replies
            .remember(pending, reply_lines, context.now().get() / 1_000)?;
        // The answered submission's reply answers its retries from now on:
        // its recent-object tuple is released (companion 11.8, 16).
        if let (Some(key), Some(carrier)) = (pending.reply_key, pending.command.carrier()) {
            self.assembler
                .forget(&super::router::submission_key(key, carrier));
        }
        self.counters.results_rendered = self.counters.results_rendered.saturating_add(1);
        if let (Some(key), Some(label)) = (pending.reply_key, &pending.retry_label) {
            return Ok(self
                .replies
                .replay(key, &pending.command, label.as_deref())?
                .into_iter()
                .collect());
        }
        Ok(Vec::new())
    }
}
