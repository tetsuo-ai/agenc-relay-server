//! Prepare reply frames before admission; publish request completion after commit.

use agenc_relay_client_wire::WireMessage;
use agenc_relay_e2ee::objects::federation::{ArcFederationEvent, ArcFederationResultKind};
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;

use super::router::Refusal;
use super::{ClientOutput, E2eeEdge, PendingRequest, ResultValue};
use crate::state_core::StateCoreContext;

pub(crate) struct PreparedCompletion {
    event_id: Option<[u8; 16]>,
    reply: Option<([u8; 16], Vec<String>)>,
}

impl E2eeEdge {
    pub(super) fn prepare_completion(
        &mut self,
        context: &mut StateCoreContext,
        event: &ArcFederationEvent,
    ) -> Result<(PreparedCompletion, Vec<ClientOutput>), Refusal> {
        let event_id = event.event_id;
        let mut completion = PreparedCompletion {
            event_id: None,
            reply: None,
        };
        let local = event.request_home_server_id.as_slice() == self.config.server_id.as_bytes()
            && event.request_server_incarnation.as_slice() == self.config.incarnation
            && <[u8; 16]>::try_from(event.request_id.as_slice())
                .ok()
                .is_some_and(|request| self.pending.contains_key(&request));
        if !local {
            return Ok((completion, Vec::new()));
        }
        completion.event_id = Some(event_id);
        let Some(request_id) = self.by_completion.get(&event_id).copied() else {
            return Ok((completion, Vec::new()));
        };
        let Some(pending) = self.pending.remove(&request_id) else {
            return Ok((completion, Vec::new()));
        };
        let prepared = pending
            .result
            .as_ref()
            .filter(|result| {
                !pending.rendered
                    && result.descriptors.iter().all(|descriptor| {
                        pending.responses.contains_key(&descriptor.response_index)
                    })
            })
            .map(|result| self.render_answer(context, &pending, result))
            .transpose();
        let generation = pending.generation;
        self.pending.insert(request_id, pending);
        let Some(lines) = prepared? else {
            return Ok((completion, Vec::new()));
        };
        let frames = lines
            .iter()
            .map(|line| WireMessage::extension_line(line))
            .collect::<Result<_, _>>()
            .map_err(|_| E2eeReplyCode::InvalidFragment)?;
        completion.reply = Some((request_id, lines));
        Ok((completion, vec![ClientOutput { generation, frames }]))
    }

    pub(super) fn commit_completion(
        &mut self,
        context: &mut StateCoreContext,
        completion: PreparedCompletion,
    ) -> Vec<ClientOutput> {
        let request_id = completion
            .event_id
            .and_then(|event_id| self.completion_arrived(event_id));
        if completion.reply.is_none() {
            let Some(request_id) = request_id else {
                return Vec::new();
            };
            return match self.render_ready(context, request_id) {
                Ok(outputs) => outputs,
                Err(_) => {
                    self.link_down();
                    Vec::new()
                }
            };
        }
        if let Some((request_id, lines)) = completion.reply
            && let Some(mut pending) = self.pending.remove(&request_id)
        {
            // The same bounded lines were validated before durable admission.
            match self.publish_reply(context, &mut pending, &lines) {
                Ok(outputs) => return outputs,
                Err(_) => self.link_down(),
            }
        }
        Vec::new()
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
